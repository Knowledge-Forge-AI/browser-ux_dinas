"""Identity readback and source safety contracts for replacement candidates."""

import hashlib
import importlib.util
import plistlib
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("replacement_identity", ROOT / "tests/replacement_app_identity.py")
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)


def bundle(tmp_path, identifier="app.floorp.Floorp", executable="floorp"):
    app = tmp_path / "Floorp.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/MacOS/floorp").write_bytes(b"synthetic executable: must never run")
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
        "CFBundleShortVersionString": "fixture",
    }))
    return app


def digest(app):
    return {str(p.relative_to(app)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in app.rglob("*") if p.is_file()}


def runner(app, *, verify=0, team="DV2U35YBHT", signature=0, diagnostic=""):
    def run(argv, **kwargs):
        assert kwargs == dict(capture_output=True, text=True, check=False, timeout=30)
        assert argv in (["/usr/bin/codesign", "-dv", "--verbose=2", str(app)],
                        ["/usr/bin/codesign", "--verify", "--strict", str(app)])
        if "-dv" in argv:
            return subprocess.CompletedProcess(argv, signature, "",
                "Executable=/private/fixture\nIdentifier=app.floorp.Floorp\nTeamIdentifier=" + team)
        return subprocess.CompletedProcess(argv, verify, "", diagnostic)
    return run


def test_match_is_read_only_and_sanitized(tmp_path):
    app = bundle(tmp_path)
    before = digest(app)
    result = IDENTITY.probe(app, "app.floorp.Floorp", "DV2U35YBHT", runner(app))
    assert result["verdict"] == "MATCH"
    assert result["version"] == "fixture"
    assert digest(app) == before
    assert "/private/fixture" not in str(result)
    assert result["signatureDiagnostic"] == "VERIFIED"
    assert result["signatureVerifyExitCode"] == 0


@pytest.mark.parametrize("diagnostic,category", [
    ("/private/operator/app: invalid signature (code or signature have been modified)\n"
     "In architecture: arm64\n", "INVALID_SIGNATURE"),
    ("/private/operator/app: Operation not permitted", "ACCESS_DENIED"),
    ("/private/operator/app: code object is not signed at all", "UNSIGNED"),
    ("/private/operator/app: unclassified failure", "VERIFY_FAILED"),
    ("/private/operator/app: a sealed resource is missing or invalid", "SEALED_RESOURCE_INVALID"),
    ("/private/operator/app: resource fork, Finder information, or similar detritus not allowed", "RESOURCE_DETRITUS"),
])
def test_signature_failure_evidence_is_sanitized(tmp_path, diagnostic, category):
    app = bundle(tmp_path)
    result = IDENTITY.probe(app, "app.floorp.Floorp", "DV2U35YBHT",
                            runner(app, verify=1, diagnostic=diagnostic))
    assert result["verdict"] == "MISMATCH"
    assert result["signatureDiagnostic"] == category
    assert result["signatureVerifyExitCode"] == 1
    assert result["signatureArchitecture"] == ("arm64" if "arm64" in diagnostic else None)
    assert "/private/operator" not in str(result)


@pytest.mark.parametrize("identifier,team,verify", [
    ("one.ablaze.floorp", "DV2U35YBHT", 0),
    ("app.floorp.Floorp", "OTHER", 0),
    ("app.floorp.Floorp", "DV2U35YBHT", 1),
])
def test_identity_mismatch(tmp_path, identifier, team, verify):
    app = bundle(tmp_path, identifier)
    assert IDENTITY.probe(app, "app.floorp.Floorp", "DV2U35YBHT",
                          runner(app, team=team, verify=verify))["verdict"] == "MISMATCH"


def test_absent_and_unreadable_are_unknown(tmp_path):
    assert IDENTITY.probe(tmp_path / "absent", "id", "team")["verdict"] == "UNKNOWN"
    app = bundle(tmp_path)
    assert IDENTITY.probe(app, "app.floorp.Floorp", "DV2U35YBHT",
                          runner(app, signature=1))["verdict"] == "UNKNOWN"
    (app / "Contents/Info.plist").write_bytes(b"invalid plist")
    assert IDENTITY.probe(app, "id", "team")["verdict"] == "UNKNOWN"
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(["wrong root type"]))
    assert IDENTITY.probe(app, "id", "team")["verdict"] == "UNKNOWN"


def test_executable_path_cannot_escape_bundle(tmp_path):
    app = bundle(tmp_path, executable="../../outside")
    def forbidden(*args, **kwargs):
        pytest.fail("codesign invoked for invalid bundle")
    assert IDENTITY.probe(app, "id", "team", forbidden)["verdict"] == "UNKNOWN"


def test_probe_has_only_read_only_process_surface():
    source = (ROOT / "tests/replacement_app_identity.py").read_text()
    for token in ("Popen", "launch", "osascript", "--force", "shutil", "write_bytes", "write_text"):
        assert token not in source
    assert '"/usr/bin/codesign", "-dv", "--verbose=2"' in source
    assert '"/usr/bin/codesign", "--verify", "--strict"' in source


def test_no_sensitive_profile_copy_surface():
    paths = [ROOT / "modules/default.nix", ROOT / "config/browser/chrome-policy-defaults.nix",
             ROOT / "config/browser/firefox-policy-defaults.nix"]
    paths += list((ROOT / "config/browser/families").glob("*.nix"))
    paths += list((ROOT / "config/browser/replacements").glob("*.nix"))
    forbidden_stores = ("logins.json", "key4.db", "Login Data", "cookies.sqlite", "places.sqlite",
                        "sessionstore", "formhistory.sqlite", "profiles.ini", "IndexedDB",
                        "Local Storage", "Local Extension Settings", "Web Data", "Cookies")
    for path in paths:
        source = path.read_text()
        assert not re.search(r"\b(cp|rsync|copytree|copyfile|copy2|shutil)\b", source), path
        # Cookie policy names are expected; storage filenames are not.
        for token in forbidden_stores[:-1]:
            assert token not in source, (path, token)
