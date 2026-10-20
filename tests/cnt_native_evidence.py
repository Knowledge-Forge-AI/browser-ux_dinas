#!/usr/bin/env python3
"""Read only captured CNT packages; reproduce the original capture-side digest.

This does not discover or access browser profiles. The digest stream is byte-for-
byte compatible with BUX5B0B-CAPTURE-STATIC-CNT-PACKAGES.py's tree_digest.
Safety checks are additional refusals, not changes to the hashed representation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


class VerificationError(RuntimeError):
    """`code` and `changed` are optional fixed tokens; the message is unchanged.

    Messages may contain paths and are never a machine protocol. Callers export
    only allowlisted `code` values and `changed` names from STAMP_FIELDS.
    """
    def __init__(self, *args: Any, code: str | None = None,
                 changed: list[str] | None = None) -> None:
        super().__init__(*args)
        self.code = code
        self.changed = changed


def require(condition: bool, message: str, code: str | None = None,
            changed: list[str] | None = None) -> None:
    if not condition:
        raise VerificationError(message, code=code, changed=changed)


# Names of the stamp() components, in order. Values are never exported.
STAMP_FIELDS = ("device", "inode", "size", "mtime", "ctime")
# Last operation a measurement reached; recorded in a caller-owned trace.
MEASUREMENT_OPERATIONS = frozenset((
    "root-validation", "enumeration", "entry-lstat", "link-read", "link-admission",
    "link-chain", "leaf-lstat", "leaf-open", "leaf-stability-before", "leaf-read",
    "leaf-stability-after", "leaf-path-identity", "entry-admission", "root-stability",
    "entry-set-stability", "entry-stability"))
# Codes attached at the refusal sites below. Observations, never causes.
MEASUREMENT_CODES = frozenset((
    "ROOT_NOT_DIRECTORY", "LEAF_NOT_REGULAR", "LEAF_CHANGED_BEFORE_READ",
    "LEAF_CHANGED_DURING_READ", "LEAF_REPLACED_AFTER_READ", "LINK_ESCAPES",
    "LINK_CHAIN_EXCESSIVE", "LINK_CHAIN_ESCAPES", "UNSUPPORTED_ENTRY", "ROOT_CHANGED",
    "ENTRY_SET_CHANGED", "ENTRY_CHANGED"))


def stamp(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def changed_fields(before: os.stat_result, after: os.stat_result) -> list[str]:
    """Names of differing stamp fields, never their values."""
    return [name for name, old, new in zip(STAMP_FIELDS, stamp(before), stamp(after)) if old != new]


def _reached(trace: dict | None, operation: str, **facts: Any) -> None:
    # Caller-owned: after any exception the trace names the last operation reached.
    if trace is not None:
        trace["operation"] = operation
        trace.update(facts)


def file_sha256(path: Path, trace: dict | None = None) -> str:
    """Refuse symlink/nonregular leaves and concurrent changes while hashing.

    A trace records only `operation`; tree_digest owns its `relative` entry.
    """
    _reached(trace, "leaf-lstat")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), f"Not a regular file: {path}", "LEAF_NOT_REGULAR")
    _reached(trace, "leaf-open")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        _reached(trace, "leaf-stability-before")
        opened = os.fstat(handle.fileno())
        require(stamp(opened) == stamp(before), f"File changed before hashing: {path}",
                "LEAF_CHANGED_BEFORE_READ", changed_fields(before, opened))
        _reached(trace, "leaf-read")
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        _reached(trace, "leaf-stability-after")
        read = os.fstat(handle.fileno())
        require(stamp(read) == stamp(before), f"File changed during hashing: {path}",
                "LEAF_CHANGED_DURING_READ", changed_fields(before, read))
    _reached(trace, "leaf-path-identity")
    after = path.lstat()
    require(stamp(after) == stamp(before), f"File replaced while hashing: {path}",
            "LEAF_REPLACED_AFTER_READ", changed_fields(before, after))
    return digest.hexdigest()


def descendants(root: Path) -> list[Path]:
    """Capture traversal: include links, never descend through directory links."""
    result = []
    def visit(directory):
        for path in directory.iterdir():
            result.append(path)
            if stat.S_ISDIR(path.lstat().st_mode):
                visit(path)
    visit(root)
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def tree_digest(root: Path, trace: dict | None = None) -> str:
    """browser-ux-static-tree-sha256-v1, not a NAR or a flat checksum list.

    Root excluded. All descendants, including directories and _metadata, sorted
    by relative POSIX path. Each record is:
      kind UTF-8 + NUL + relative path UTF-8 + NUL + payload + NUL
    kind=dir: empty payload; kind=file: 32 binary SHA256 bytes;
    kind=symlink: UTF-8 link text (never target contents).
    Modes, owners, timestamps, and sizes are NOT included.

    An optional caller-owned trace receives the last operation reached, the
    lexical `relative` entry (None at root level) and entry counts. It never
    holds digest state, link text, stamps or messages, and does not change the
    digest or any refusal.
    """
    root = Path(os.path.abspath(root))
    _reached(trace, "root-validation", relative=None, entries_enumerated=None, entries_measured=0)
    require(stat.S_ISDIR(root.lstat().st_mode), f"Package root not a plain directory: {root}",
            "ROOT_NOT_DIRECTORY")
    digest = hashlib.sha256()
    before_root = root.lstat()
    _reached(trace, "enumeration")
    entries = descendants(root)
    _reached(trace, "enumeration", entries_enumerated=len(entries))
    observations: list[tuple[Path, os.stat_result]] = []
    for measured, path in enumerate(entries):
        relative = path.relative_to(root).as_posix()
        _reached(trace, "entry-lstat", relative=relative, entries_measured=measured)
        before = path.lstat()
        observations.append((path, before))
        if stat.S_ISLNK(before.st_mode):
            kind = "symlink"
            _reached(trace, "link-read")
            link_text = os.readlink(path)
            # Do not dereference links, especially links to the original profile.
            _reached(trace, "link-admission")
            target = Path(os.path.normpath(os.path.join(str(path.parent), link_text)))
            require(target.is_relative_to(root), f"Symlink escapes copied package: {relative}",
                    "LINK_ESCAPES")
            # Resolve only in-package link metadata, never target contents.
            _reached(trace, "link-chain")
            pending = list(target.relative_to(root).parts)
            current = root
            hops = 0
            while pending:
                current /= pending.pop(0)
                if current.is_symlink():
                    hops += 1
                    require(hops <= 40, "Symlink cycle or excessive chain", "LINK_CHAIN_EXCESSIVE")
                    destination = Path(os.path.normpath(os.path.join(
                        str(current.parent), os.readlink(current))))
                    require(destination.is_relative_to(root), "Symlink chain escapes copied package",
                            "LINK_CHAIN_ESCAPES")
                    pending = list(destination.relative_to(root).parts) + pending
                    current = root
            payload = link_text.encode("utf-8")
        elif stat.S_ISDIR(before.st_mode):
            kind, payload = "dir", b""
        elif stat.S_ISREG(before.st_mode):
            kind, payload = "file", bytes.fromhex(file_sha256(path, trace))
        else:
            _reached(trace, "entry-admission")
            raise VerificationError(f"Unsupported package entry: {relative}", code="UNSUPPORTED_ENTRY")
        digest.update(kind.encode("utf-8") + b"\0" + relative.encode("utf-8")
                      + b"\0" + payload + b"\0")
    _reached(trace, "root-stability", relative=None, entries_measured=len(entries))
    after_root = root.lstat()
    require(stamp(after_root) == stamp(before_root), "Package directory changed during hashing",
            "ROOT_CHANGED", changed_fields(before_root, after_root))
    _reached(trace, "entry-set-stability")
    require([p.relative_to(root).as_posix() for p in entries] ==
            [p.relative_to(root).as_posix() for p in descendants(root)],
            "Package entry set changed during hashing", "ENTRY_SET_CHANGED")
    for path, before in observations:
        _reached(trace, "entry-stability", relative=path.relative_to(root).as_posix())
        after = path.lstat()
        require(stamp(after) == stamp(before), f"Package entry changed: {path}",
                "ENTRY_CHANGED", changed_fields(before, after))
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    require(stat.S_ISREG(path.lstat().st_mode), f"Not a regular JSON file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def plain_descendant(root: Path, relative: str, directory: bool = False) -> Path:
    parts = PurePosixPath(relative).parts
    require(bool(parts) and not PurePosixPath(relative).is_absolute()
            and all(p not in ("..", ".", "") for p in parts), "Unsafe relative evidence path")
    current = root
    for part in parts:
        current = current / part
        require(not current.is_symlink(), f"Symlink evidence path component: {current}")
    mode = current.lstat().st_mode
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode),
            f"Unexpected evidence path type: {current}")
    return current


def verify_evidence(evidence_root: Path, binding: dict[str, Any]) -> dict[str, Any]:
    evidence_root = Path(os.path.abspath(evidence_root))
    require(stat.S_ISDIR(evidence_root.lstat().st_mode), "Evidence root must be a plain directory")
    provenance = read_json(plain_descendant(evidence_root, "provenance.json"))
    require(provenance.get("schema") == binding["provenance_schema"], "Provenance schema mismatch")
    for field in ("synthetic_or_static_only", "live_cnt_runtime_storage_read",
                  "live_cnt_runtime_storage_written"):
        require(provenance.get(field) is binding[field], f"Provenance flag mismatch: {field}")
    for engine in ("chrome", "firefox"):
        for field in ("extension_id", "version", "manifest_version", "package_kind",
                      "digest_algorithm", "digest"):
            require(provenance.get(engine, {}).get(field) == binding[engine][field],
                    f"Provenance binding mismatch: {engine}.{field}")

    chrome = plain_descendant(evidence_root, binding["chrome"]["relative_path"], directory=True)
    chrome_digest = tree_digest(chrome)
    require(chrome_digest == binding["chrome"]["digest"],
            "Chrome tree digest mismatch using capture encoding: "
            f"expected {binding['chrome']['digest']}; actual {chrome_digest}. "
            "Preserve evidence; do not recapture, guess another encoding, or change the binding.")
    chrome_manifest = read_json(plain_descendant(chrome, "manifest.json"))
    require(chrome_manifest.get("version") == binding["chrome"]["version"]
            and chrome_manifest.get("manifest_version") == binding["chrome"]["manifest_version"],
            "Chrome manifest version mismatch")
    key = chrome_manifest.get("key")
    require(isinstance(key, str) and bool(key), "Chrome manifest lacks its ID-derivation key")
    key_bytes = base64.b64decode("".join(key.split()), validate=True)
    chrome_id = "".join(chr(ord("a") + int(c, 16))
                        for c in hashlib.sha256(key_bytes).hexdigest()[:32])
    require(chrome_id == binding["chrome"]["extension_id"], "Chrome derived extension ID mismatch")

    firefox = plain_descendant(evidence_root, binding["firefox"]["relative_path"])
    firefox_digest = file_sha256(firefox)
    require(firefox_digest == binding["firefox"]["digest"], "Firefox XPI SHA256 mismatch")
    with zipfile.ZipFile(firefox) as archive:
        names: set[str] = set()
        for member in archive.infolist():
            name = member.filename
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name,
                    "Unsafe XPI member path")
            require(name not in names, "Duplicate XPI member name")
            names.add(name)
            require(not stat.S_ISLNK(member.external_attr >> 16), "XPI symlink member refused")
        info = archive.getinfo("manifest.json")
        require(info.file_size < 2 * 1024 * 1024, "Unreasonably large XPI manifest")
        firefox_manifest = json.loads(archive.read("manifest.json"))
    gecko = firefox_manifest.get("browser_specific_settings", {}).get("gecko", {})
    require(gecko.get("id") == binding["firefox"]["extension_id"], "Firefox extension ID mismatch")
    require(firefox_manifest.get("version") == binding["firefox"]["version"]
            and firefox_manifest.get("manifest_version") == binding["firefox"]["manifest_version"],
            "Firefox manifest version mismatch")
    require(file_sha256(firefox) == firefox_digest, "Firefox XPI changed during verification")
    require(tree_digest(chrome) == chrome_digest, "Chrome package changed during verification")
    return {
        "schema": "bux5b0b-r1-static-verification-v1",
        "status": "VERIFIED_CAPTURED_STATIC_INPUTS",
        "read_scope": "provided copied packages and their provenance only; no live discovery",
        "capture_safety_flags": {k: provenance[k] for k in (
            "synthetic_or_static_only", "live_cnt_runtime_storage_read", "live_cnt_runtime_storage_written")},
        "capture_flags_basis": "operator provenance, not an independent audit of the capture process",
        "chrome": {"version": chrome_manifest["version"], "manifest_version": 3,
                   "extension_id": chrome_id, "digest_algorithm": "browser-ux-static-tree-sha256-v1",
                   "digest": chrome_digest},
        "firefox": {"version": firefox_manifest["version"], "manifest_version": 3,
                    "extension_id": gecko["id"], "digest_algorithm": "sha256-file",
                    "digest": firefox_digest},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_evidence(args.evidence_root, read_json(args.binding)),
                         indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, VerificationError) as error:
        parser.exit(1, f"STOP: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
