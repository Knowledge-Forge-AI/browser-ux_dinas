"""Transport reviewed source entries without dereferencing directory symlinks."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile


def safe_name(name):
    path = PurePosixPath(name)
    parts = path.parts
    if not parts or str(path) != name or name.startswith("/") or ".." in parts or "\\" in name or any(ord(c) < 32 for c in name):
        raise ValueError("Unsafe transport member")
    return parts


def entry(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raw, kind = os.readlink(path).encode(), "symlink"
    elif stat.S_ISREG(info.st_mode):
        raw, kind = path.read_bytes(), "file"
    else:
        raise ValueError("Special transport entry")
    return {"kind": kind, "mode": stat.S_IMODE(info.st_mode),
            "sha256": hashlib.sha256(raw).hexdigest()}, raw


def names_under(root):
    names = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                names.append(path.relative_to(root).as_posix())
                dirs.remove(name)
        names.extend((Path(directory) / n).relative_to(root).as_posix() for n in files)
    return sorted(names)


def validate_links(records, contents):
    for name, record in records.items():
        safe_name(name)
        if any(records.get("/".join(safe_name(name)[:i]), {}).get("kind") == "symlink"
               for i in range(1, len(safe_name(name)))):
            raise ValueError("Transport member beneath a symlink")
        if record["kind"] != "symlink":
            continue
        target = contents[name].decode()
        if target.startswith("/"):
            raise ValueError("Absolute transport link")
        pending = list(PurePosixPath(name).parent.parts) + target.split("/")
        current, hops = [], 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not current:
                    raise ValueError("Escaping transport link")
                current.pop()
                continue
            current.append(part)
            key = "/".join(current)
            if records.get(key, {}).get("kind") == "symlink":
                hops += 1
                if hops > 40:
                    raise ValueError("Transport link cycle")
                current.pop()
                pending = contents[key].decode().split("/") + pending
        key = "/".join(current)
        if key not in records and not any(n.startswith(key + "/") for n in records):
            raise ValueError("Transport link target absent")


def pack(root, destination):
    entries = {name: entry(root / name) for name in names_under(root)}
    records = {name: value[0] for name, value in entries.items()}
    contents = {name: value[1] for name, value in entries.items()}
    validate_links(records, contents)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("TRANSPORT-MANIFEST.json", json.dumps(records, sort_keys=True))
        for name, (record, raw) in entries.items():
            item = zipfile.ZipInfo("payload/" + name)
            item.create_system = 3
            kind = stat.S_IFLNK if record["kind"] == "symlink" else stat.S_IFREG
            item.external_attr = (kind | record["mode"]) << 16
            archive.writestr(item, raw)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def unpack(archive_path, destination):
    if destination.exists() or destination.parent.resolve() != destination.parent.absolute():
        raise ValueError("Extraction needs a new physical destination")
    with zipfile.ZipFile(archive_path) as archive:
        records = json.loads(archive.read("TRANSPORT-MANIFEST.json"))
        expected = {"TRANSPORT-MANIFEST.json"} | {"payload/" + n for n in records}
        if len(archive.namelist()) != len(expected) or set(archive.namelist()) != expected:
            raise ValueError("Transport member mismatch")
        contents = {name: archive.read("payload/" + name) for name in records}
    validate_links(records, contents)
    for name, record in records.items():
        if record["kind"] not in ("file", "symlink"):
            raise ValueError("Unknown transport kind")
        if hashlib.sha256(contents[name]).hexdigest() != record["sha256"]:
            raise ValueError("Transport checksum mismatch")
    destination.mkdir(mode=0o700)
    for kind in ("file", "symlink"):
        for name, record in records.items():
            if record["kind"] != kind:
                continue
            path = destination.joinpath(*safe_name(name))
            path.parent.mkdir(parents=True, exist_ok=True)
            if kind == "symlink":
                path.symlink_to(contents[name].decode())
                if os.chmod in os.supports_follow_symlinks:
                    os.chmod(path, record["mode"], follow_symlinks=False)
            else:
                path.write_bytes(contents[name])
                path.chmod(record["mode"])
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["pack", "unpack"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--sha256", help="Expected reviewed archive digest; required for unpack")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "pack":
            result = {"status": "PACKED", "sha256": pack(args.source, args.destination)}
        else:
            if not args.sha256 or hashlib.sha256(args.source.read_bytes()).hexdigest() != args.sha256:
                raise ValueError("Archive digest mismatch")
            records = unpack(args.source, args.destination)
            result = {"status": "VERIFIED_EXTRACTED", "entries": len(records), "sha256": args.sha256}
        code = 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        result, code = {"status": "FAILED", "mode": args.mode, "category": type(error).__name__}, 1
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
