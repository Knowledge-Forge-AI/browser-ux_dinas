"""Independent capture-byte vectors; no extension package required."""
import hashlib
import importlib.util
import os
import base64
import json
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("cnt_evidence", Path(__file__).with_name("cnt_native_evidence.py"))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def test_capture_vector(tmp_path):
    (tmp_path / "_metadata").mkdir()
    (tmp_path / "_metadata" / ".hidden").write_bytes(b"abc")
    (tmp_path / "empty").mkdir()
    (tmp_path / "é").write_bytes(b"image")
    (tmp_path / "link").symlink_to("empty", target_is_directory=True)
    expected = (b"dir\0_metadata\0\0"
                b"file\0_metadata/.hidden\0" + hashlib.sha256(b"abc").digest() + b"\0"
                b"dir\0empty\0\0symlink\0link\0empty\0"
                b"file\0" + "é".encode() + b"\0" + hashlib.sha256(b"image").digest() + b"\0")
    assert evidence.tree_digest(tmp_path) == hashlib.sha256(expected).hexdigest()
    assert [p.relative_to(tmp_path).as_posix() for p in evidence.descendants(tmp_path)] == [
        "_metadata", "_metadata/.hidden", "empty", "link", "é"]
    original = evidence.tree_digest(tmp_path)
    (tmp_path / "é").chmod(0o700)
    os.utime(tmp_path / "é", (100, 100))
    assert evidence.tree_digest(tmp_path) == original
    renamed = tmp_path.with_name(tmp_path.name + "-renamed")
    tmp_path.rename(renamed)
    assert evidence.tree_digest(renamed) == original


@pytest.mark.parametrize("mutation", ["content", "name", "directory", "link"])
def test_identity_changes(tmp_path, mutation):
    (tmp_path / "a").write_bytes(b"a")
    (tmp_path / "b").write_bytes(b"a")
    (tmp_path / "link").symlink_to("a")
    original = evidence.tree_digest(tmp_path)
    if mutation == "content":
        (tmp_path / "a").write_bytes(b"b")
    elif mutation == "name":
        (tmp_path / "b").rename(tmp_path / "c")
    elif mutation == "directory":
        (tmp_path / "empty").mkdir()
    else:
        (tmp_path / "link").unlink()
        (tmp_path / "link").symlink_to("b")
    assert evidence.tree_digest(tmp_path) != original


@pytest.mark.parametrize("target", ["../outside", "/outside"])
def test_escaping_links(tmp_path, target):
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(evidence.VerificationError, match="escapes"):
        evidence.tree_digest(tmp_path)


def test_directory_link_not_traversed(tmp_path):
    (tmp_path / "directory").mkdir()
    (tmp_path / "directory" / "file").write_bytes(b"x")
    (tmp_path / "link").symlink_to("directory", target_is_directory=True)
    assert len(evidence.descendants(tmp_path)) == 3


def test_chained_escape_and_cycle(tmp_path):
    (tmp_path / "a").symlink_to("z")
    (tmp_path / "z").symlink_to("../outside")
    with pytest.raises(evidence.VerificationError, match="escapes"):
        evidence.tree_digest(tmp_path)
    (tmp_path / "z").unlink()
    (tmp_path / "z").symlink_to("a")
    with pytest.raises(evidence.VerificationError, match="cycle"):
        evidence.tree_digest(tmp_path)


def test_unsupported_entry(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(evidence.VerificationError, match="Unsupported"):
        evidence.tree_digest(tmp_path)


def test_empty_tree(tmp_path):
    assert evidence.tree_digest(tmp_path) == hashlib.sha256(b"").hexdigest()


def synthetic_capture(root, archive_member=None):
    chrome = root / "chrome/package"
    chrome.mkdir(parents=True)
    key = b"synthetic manifest key"
    identity = "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(key).hexdigest()[:32])
    (chrome / "manifest.json").write_text(json.dumps({"key": base64.b64encode(key).decode(),
                                                   "version": "1", "manifest_version": 3}))
    firefox = root / "firefox.xpi"
    with zipfile.ZipFile(firefox, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"version": "2", "manifest_version": 3,
                           "browser_specific_settings": {"gecko": {"id": "synthetic@example.invalid"}}}))
        if archive_member:
            archive.writestr(archive_member, "synthetic")
    binding = {"provenance_schema": "synthetic", "synthetic_or_static_only": True,
               "live_cnt_runtime_storage_read": False, "live_cnt_runtime_storage_written": False,
               "chrome": {"extension_id": identity, "version": "1", "manifest_version": 3,
                          "package_kind": "directory", "digest_algorithm": "browser-ux-static-tree-sha256-v1",
                          "relative_path": "chrome/package", "digest": evidence.tree_digest(chrome)},
               "firefox": {"extension_id": "synthetic@example.invalid", "version": "2", "manifest_version": 3,
                           "package_kind": "xpi", "digest_algorithm": "sha256-file",
                           "relative_path": "firefox.xpi", "digest": evidence.file_sha256(firefox)}}
    provenance = dict(binding, schema="synthetic")
    (root / "provenance.json").write_text(json.dumps(provenance))
    return binding


def test_synthetic_capture(tmp_path):
    binding = synthetic_capture(tmp_path)
    assert evidence.verify_evidence(tmp_path, binding)["status"] == "VERIFIED_CAPTURED_STATIC_INPUTS"


@pytest.mark.parametrize("member", ["../escape", "/absolute", "back\\slash"])
def test_unsafe_archive(tmp_path, member):
    binding = synthetic_capture(tmp_path, member)
    with pytest.raises(evidence.VerificationError, match="Unsafe XPI"):
        evidence.verify_evidence(tmp_path, binding)


@pytest.mark.parametrize("engine,field,value", [("chrome", "version", "wrong"),
                                               ("firefox", "extension_id", "wrong")])
def test_manifest_binding(tmp_path, engine, field, value):
    binding = synthetic_capture(tmp_path)
    binding[engine][field] = value
    provenance = dict(binding, schema="synthetic")
    (tmp_path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(evidence.VerificationError, match="manifest version|extension ID"):
        evidence.verify_evidence(tmp_path, binding)


def test_provenance_mismatch(tmp_path):
    binding = synthetic_capture(tmp_path)
    binding["synthetic_or_static_only"] = False
    with pytest.raises(evidence.VerificationError, match="flag mismatch"):
        evidence.verify_evidence(tmp_path, binding)


def test_content_drift(tmp_path):
    binding = synthetic_capture(tmp_path)
    (tmp_path / "chrome/package/added").write_bytes(b"new")
    with pytest.raises(evidence.VerificationError, match="tree digest mismatch"):
        evidence.verify_evidence(tmp_path, binding)


# R4-CONT9: structured refusal context. The digest bytes and every refusal are unchanged;
# these tests only prove that the refusing operation, code and stamp-field names survive.
import errno


def bundle(root):
    (root / "Contents/MacOS").mkdir(parents=True)
    (root / "Contents/MacOS/firefox").write_bytes(b"synthetic executable")
    (root / "Contents/Info.plist").write_bytes(b"synthetic plist")
    (root / "Contents/link").symlink_to("MacOS/firefox")
    return root


def refused(root, **kw):
    trace = {}
    with pytest.raises(evidence.VerificationError) as caught:
        evidence.tree_digest(root, trace=trace, **kw)
    return caught.value, trace


def second_enumeration(monkeypatch, action):
    """Run `action` when tree_digest re-enumerates for its end-of-tree checks."""
    original, calls = evidence.descendants, []
    def hooked(root):
        calls.append(root)
        if len(calls) == 2:
            action()
        return original(root)
    monkeypatch.setattr(evidence, "descendants", hooked)


def test_trace_is_digest_neutral_and_holds_no_digest_material(tmp_path):
    root = bundle(tmp_path / "Firefox.app")
    trace = {}
    plain = evidence.tree_digest(root)
    assert evidence.tree_digest(root, trace=trace) == plain
    assert trace == {"operation": "entry-stability", "relative": "Contents/link",
                     "entries_enumerated": 5, "entries_measured": 5}
    assert plain not in json.dumps(trace)


def test_messages_are_unchanged_and_codes_are_allowlisted(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    second_enumeration(monkeypatch, lambda: os.utime(target, ns=(1, 1)))
    error, trace = refused(root)
    assert str(error) == f"Package entry changed: {target}" and error.args == (str(error),)
    assert error.code == "ENTRY_CHANGED" and error.code in evidence.MEASUREMENT_CODES
    assert trace["operation"] in evidence.MEASUREMENT_OPERATIONS
    assert evidence.VerificationError("plain").code is None


def test_refusal_before_leaf_read(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    real_open = os.open
    def changing_open(path, *a, **kw):
        if Path(path) == target:
            with open(target, "ab") as stream:
                stream.write(b"+")
        return real_open(path, *a, **kw)
    monkeypatch.setattr(os, "open", changing_open)
    error, trace = refused(root)
    assert error.code == "LEAF_CHANGED_BEFORE_READ" and "size" in error.changed
    assert trace["operation"] == "leaf-stability-before" and trace["relative"] == "Contents/Info.plist"


class Handle:
    """Real read handle with a deterministic hook; everything else delegates."""
    def __init__(self, handle, on_read=None, on_exit=None):
        self.handle, self.on_read, self.on_exit = handle, on_read, on_exit
    def __enter__(self): return self
    def __exit__(self, *exc):
        self.handle.close()
        if self.on_exit and exc[0] is None:
            self.on_exit()
    def fileno(self): return self.handle.fileno()
    def read(self, size):
        if self.on_read:
            hook, self.on_read = self.on_read, None
            hook()
        return self.handle.read(size)


def hook_leaf(monkeypatch, **hooks):
    real = os.fdopen
    monkeypatch.setattr(os, "fdopen", lambda fd, mode: Handle(real(fd, mode), **hooks))


def test_refusal_during_leaf_read(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    def grow():
        with open(root / "Contents/Info.plist", "ab") as stream:
            stream.write(b"+")
    hook_leaf(monkeypatch, on_read=grow)
    error, trace = refused(root)
    assert error.code == "LEAF_CHANGED_DURING_READ" and "size" in error.changed
    assert trace["operation"] == "leaf-stability-after" and trace["relative"] == "Contents/Info.plist"


def test_refusal_after_leaf_read_replacement(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    def replace():
        (tmp_path / "replacement").write_bytes(target.read_bytes())
        os.replace(tmp_path / "replacement", target)
    hook_leaf(monkeypatch, on_exit=replace)
    error, trace = refused(root)
    assert error.code == "LEAF_REPLACED_AFTER_READ" and "inode" in error.changed
    assert trace["operation"] == "leaf-path-identity"


def test_leaf_removed_after_read_keeps_errno(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    hook_leaf(monkeypatch, on_exit=(root / "Contents/Info.plist").unlink)
    trace = {}
    with pytest.raises(FileNotFoundError) as caught:
        evidence.tree_digest(root, trace=trace)
    assert caught.value.errno == errno.ENOENT and trace["operation"] == "leaf-path-identity"


@pytest.mark.parametrize("change,code,operation", [
    ("mtime", "ENTRY_CHANGED", "entry-stability"),
    ("added", "ENTRY_SET_CHANGED", "entry-set-stability")])
def test_end_of_tree_changes(tmp_path, monkeypatch, change, code, operation):
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    action = {"mtime": lambda: os.utime(target, ns=(1, 1)),
              "added": lambda: (root / "Contents/MacOS/added").write_bytes(b"")}[change]
    second_enumeration(monkeypatch, action)
    error, trace = refused(root)
    assert (error.code, trace["operation"]) == (code, operation)
    if change == "mtime":
        assert "mtime" in error.changed and trace["relative"] == "Contents/Info.plist"
    else:
        assert trace["relative"] is None and error.changed is None


def test_root_change_is_root_level(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    hook_leaf(monkeypatch, on_exit=lambda: (root / "added").write_bytes(b""))
    error, trace = refused(root)
    assert error.code == "ROOT_CHANGED" and "mtime" in error.changed
    assert trace["operation"] == "root-stability" and trace["relative"] is None


def test_os_error_during_reenumeration(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    def fail():
        raise OSError(errno.EIO, "synthetic")
    second_enumeration(monkeypatch, fail)
    trace = {}
    with pytest.raises(OSError) as caught:
        evidence.tree_digest(root, trace=trace)
    assert caught.value.errno == errno.EIO
    assert trace["operation"] == "entry-set-stability" and trace["entries_measured"] == 5


class CtimeOnly:
    def __init__(self, info): self.info = info
    def __getattr__(self, name):
        value = getattr(self.info, name)
        return value + 1 if name == "st_ctime_ns" else value


def test_modelled_ctime_only_change_still_refuses(tmp_path, monkeypatch):
    """MODELLED: an injected stamp with only ctime bumped. Guards against ignoring ctime."""
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    armed = []
    second_enumeration(monkeypatch, lambda: armed.append(True))
    real_lstat = Path.lstat
    def lstat(path):
        info = real_lstat(path)
        return CtimeOnly(info) if armed and path == target else info
    monkeypatch.setattr(Path, "lstat", lstat)
    error, trace = refused(root)
    assert error.code == "ENTRY_CHANGED" and error.changed == ["ctime"]
    assert trace["relative"] == "Contents/Info.plist"


def chmod_and_restore(path):
    """Real metadata-only change: mode flipped then restored until ctime moves (bounded)."""
    original = path.lstat()
    for _ in range(1000):
        path.chmod(0o600)
        path.chmod(original.st_mode & 0o7777)
        if path.lstat().st_ctime_ns != original.st_ctime_ns:
            return
    raise AssertionError("ctime did not advance")


def test_real_mode_restore_refuses_then_later_digest_is_equal(tmp_path, monkeypatch):
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    original = evidence.tree_digest(root)
    second_enumeration(monkeypatch, lambda: chmod_and_restore(target))
    error, trace = refused(root)
    assert error.code == "ENTRY_CHANGED" and error.changed == ["ctime"]
    monkeypatch.undo()
    assert evidence.tree_digest(root) == original


@pytest.mark.parametrize("persistent", [False, True])
def test_restored_versus_persistent_bytes_have_same_refusal(tmp_path, monkeypatch, persistent):
    """Outward evidence is identical; only a later measurement differs. Not a cause finding."""
    root = bundle(tmp_path / "Firefox.app")
    target = root / "Contents/Info.plist"
    original_bytes, original = target.read_bytes(), evidence.tree_digest(root)
    def rewrite():
        target.write_bytes(b"X" * len(original_bytes))
        if not persistent:
            target.write_bytes(original_bytes)
    second_enumeration(monkeypatch, rewrite)
    error, trace = refused(root)
    assert (error.code, trace["operation"], trace["relative"]) == (
        "ENTRY_CHANGED", "entry-stability", "Contents/Info.plist")
    monkeypatch.undo()
    assert (evidence.tree_digest(root) == original) is not persistent


def test_nonregular_and_root_refusals(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    error, trace = refused(tmp_path)
    assert (error.code, trace["operation"], trace["relative"]) == ("UNSUPPORTED_ENTRY", "entry-admission", "fifo")
    for leaf in (tmp_path / "fifo", tmp_path / "link"):
        if leaf.name == "link":
            leaf.symlink_to("fifo")
        trace = {}
        with pytest.raises(evidence.VerificationError) as caught:
            evidence.file_sha256(leaf, trace=trace)
        assert caught.value.code == "LEAF_NOT_REGULAR" and trace == {"operation": "leaf-lstat"}
    (tmp_path / "file").write_bytes(b"")
    error, trace = refused(tmp_path / "file")
    assert error.code == "ROOT_NOT_DIRECTORY" and trace["operation"] == "root-validation"
    trace = {}
    with pytest.raises(FileNotFoundError):
        evidence.tree_digest(tmp_path / "missing", trace=trace)
    assert trace["operation"] == "root-validation" and trace["relative"] is None


@pytest.mark.parametrize("links,code,relative", [
    ({"link": "../private-outside"}, "LINK_ESCAPES", "link"),
    ({"link": "/private-outside"}, "LINK_ESCAPES", "link"),
    ({"a": "z", "z": "../private-outside"}, "LINK_CHAIN_ESCAPES", "a"),
    ({"a": "z", "z": "a"}, "LINK_CHAIN_EXCESSIVE", "a")])
def test_link_refusals_name_the_entry_never_its_text(tmp_path, links, code, relative):
    root = tmp_path / "Firefox.app"
    root.mkdir()
    for name, text in links.items():
        (root / name).symlink_to(text)
    error, trace = refused(root)
    assert error.code == code and trace["relative"] == relative
    assert trace["operation"] == ("link-admission" if code == "LINK_ESCAPES" else "link-chain")
    assert "private-outside" not in json.dumps(trace)


def test_internal_link_passes(tmp_path):
    root = bundle(tmp_path / "Firefox.app")
    (root / "Contents/chain").symlink_to("link")
    trace = {}
    evidence.tree_digest(root, trace=trace)
    assert trace["entries_measured"] == 6


@pytest.mark.parametrize("site,error,operation", [
    ("open", OSError(errno.EIO, "synthetic"), "leaf-open"),
    ("readlink", RuntimeError("/private/raw text"), "link-read"),
    ("read", KeyboardInterrupt(), "leaf-read")])
def test_os_unknown_and_interrupt_keep_last_operation(tmp_path, monkeypatch, site, error, operation):
    root = bundle(tmp_path / "Firefox.app")
    def fail(*a, **kw):
        raise error
    if site == "read":
        hook_leaf(monkeypatch, on_read=fail)
    else:
        monkeypatch.setattr(os, site, fail)
    trace = {}
    with pytest.raises(type(error)) as caught:
        evidence.tree_digest(root, trace=trace)
    assert caught.value is error and trace["operation"] == operation
    assert "/private" not in json.dumps(trace)
