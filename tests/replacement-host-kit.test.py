"""Unit and adversarial qualification tests for replacement_host_kit.py.

Uses fake runners and temporary apps; no actual nix, codesign, or brew.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import zipfile

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import replacement_host_kit as kit  # noqa: E402


def make_source_and_kit(tmp_path: Path, files: dict[str, bytes] | None = None, checks: list[str] | None = None):
    kit_dir = tmp_path / "kit"
    kit_dir.mkdir(parents=True, exist_ok=True)
    source_dir = kit_dir / "source"
    source_dir.mkdir(parents=True, exist_ok=True)

    if files is None:
        files = {
            "flake.nix": b'# valid flake\n{\n  outputs = { self }: {};\n}\n',
            "config/default.nix": b'# config\n{}:\n',
            "tests/source-only-roster.json": b'[]\n',
        }
    if checks is None:
        checks = ["replacement-claims-contract", "replacement-family-contract"]

    entries = {}
    for rel_path, content in files.items():
        file_path = source_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(content)
        entries[rel_path] = {
            "kind": "file",
            "mode": 0o644,
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    inv_sha = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    inv_data = {
        "schema": kit.SCHEMA_INVENTORY,
        "sha256": inv_sha,
        "entries": entries,
    }
    (kit_dir / "SOURCE-INVENTORY.json").write_text(json.dumps(inv_data, indent=2))

    tree_sha = kit.compute_git_tree(entries, lambda n: files[n])
    kit_data = {
        "schema": kit.SCHEMA_KIT,
        "system": kit.SYSTEM,
        "inventorySha256": inv_sha,
        "reviewedTree": tree_sha,
        "checks": checks,
    }
    (kit_dir / "KIT.json").write_text(json.dumps(kit_data, indent=2))

    return source_dir, kit_dir, entries, tree_sha, inv_sha


def make_valid_matrix():
    combinations = {}
    for name, vivaldi, floorp in (("bothDisabled", False, False), ("floorpOnly", False, True),
                                 ("vivaldiOnly", True, False), ("bothEnabled", True, True)):
        rendering, claims, casks = {}, [], []
        for browser, enabled, expected in (("vivaldi", vivaldi, kit.EXPECTED_VIVALDI),
                                           ("floorp", floorp, kit.EXPECTED_FLOORP)):
            cand = {
                "capability": f"{browser}-browser-core",
                "role": "chrome-replacement" if browser == "vivaldi" else "firefox-replacement",
                "status": "CANDIDATE",
                "qualification": "READY_FOR_QUALIFICATION",
            }
            if browser == "vivaldi":
                feature_overlays = {
                    "mail": {
                        "requested": False,
                        "status": "HOLD_RUNTIME_OOM",
                        "requiredForReplacement": False,
                        "runtimeHolds": [kit.VIVALDI_CRASH_HOLD],
                    }
                }
            else:
                feature_overlays = {}

            rendering[browser] = {
                "browser": browser, "verdict": "HOLD", "runtimeHolds": [],
                "replacementCandidate": cand,
                "featureOverlays": feature_overlays,
                "activation": {"hostPolicyDelivery": "HELD", "replacementAuthorized": False,
                    "liveProfileMigration": "FORBIDDEN", "applicationRetention": "ALLOWED",
                    "blockers": [], "status": "HOLD_QUALIFICATION"},
            } if enabled else None
            if enabled:
                claims.append(expected["claim"])
                casks.append(expected["cask"])
        combinations[name] = {"enabled": {"vivaldi": vivaldi, "floorp": floorp},
            "nativeMessagingHeld": True, "baselineEqual": dict.fromkeys(kit.BASELINE_FIELDS, True),
            "claimIds": sorted(claims), "selectedCasks": sorted(casks), "rendering": rendering}
    return {"schema": kit.SCHEMA_MATRIX, "combinations": combinations}


def make_valid_pins():
    return {
        "bridgeOptOut": {"chromeEqual": True, "firefoxEqual": True, "chromeMatch": True, "firefoxMatch": True},
        "default": {"chromeEqual": True, "firefoxEqual": True, "chromeMatch": True, "firefoxMatch": True},
        "disabled": {"chromeEqual": True, "firefoxEqual": True, "chromeMatch": True, "firefoxMatch": True},
        "fullOptOut": {"chromeEqual": True, "firefoxEqual": True, "chromeMatch": True, "firefoxMatch": True},
    }


class FakeRunner:
    def __init__(self, checks: list[str] | None = None, matrix: dict | None = None, pins: dict | None = None):
        self.calls: list[list[str]] = []
        self.checks = ["replacement-claims-contract", "replacement-family-contract"] if checks is None else checks
        self.matrix = make_valid_matrix() if matrix is None else matrix
        self.pins = make_valid_pins() if pins is None else pins
        self.composition_data = {"cleanup": "none", "vivaldiDeclared": False, "floorpDeclared": False,
                                 "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False}
        self.brew_stdout = "floorp 11.10.4\nvivaldi 6.5.3206.59\n"
        self.diff_clean = True
        self.build_fail_on: set[str] = set()
        self.timeout_on: set[str] = set()

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        # Check argument policies and timeout limits
        assert kwargs.get("shell") is not True
        timeout = kwargs.get("timeout")
        assert timeout is not None and timeout <= 300

        cmd_str = " ".join(argv)
        for t_target in self.timeout_on:
            if t_target in cmd_str:
                raise subprocess.TimeoutExpired(argv, timeout)

        if "diff" in argv and "--check" in argv:
            return subprocess.CompletedProcess(argv, 0 if self.diff_clean else 1, "", "")
        if "ls-files" in argv:
            root = Path(argv[argv.index("-C") + 1])
            names = [] if "--others" in argv else [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
            return subprocess.CompletedProcess(argv, 0, "\0".join(names) + ("\0" if names else ""), "")

        if "nix" in argv and "eval" in argv:
            if "attrNames" in cmd_str:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.checks), "")
            if "replacement-activation-matrix" in cmd_str:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.matrix), "")
            if "replacement-baseline-pins" in cmd_str or "pinFixture" in cmd_str:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.pins), "")
            if "darwinConfigurations" in cmd_str:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.composition_data), "")

        if "nix" in argv and "build" in argv:
            check_name = argv[-1].split(".")[-1]
            ret = 1 if check_name in self.build_fail_on else 0
            return subprocess.CompletedProcess(argv, ret, "", "")

        if "brew" in argv[0] and "list" in argv:
            return subprocess.CompletedProcess(argv, 0, self.brew_stdout, "")

        if "codesign" in argv[0]:
            if "-dv" in argv:
                target = argv[-1]
                team = "DV2U35YBHT" if "Floorp" in target else "4XF3XNRN6Y"
                ident = "app.floorp.Floorp" if "Floorp" in target else "com.vivaldi.Vivaldi"
                return subprocess.CompletedProcess(argv, 0, "", f"Identifier={ident}\nTeamIdentifier={team}\n")
            if "--verify" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")

        return subprocess.CompletedProcess(argv, 0, "", "")


def fake_probe_runner(target_app, *, verify_code=0, diagnostic="", team=None, identifier=None):
    def run(argv, **kwargs):
        assert kwargs == dict(capture_output=True, text=True, check=False, timeout=30)
        if "-dv" in argv:
            t = team or ("DV2U35YBHT" if "Floorp" in str(target_app) else "4XF3XNRN6Y")
            i = identifier or ("app.floorp.Floorp" if "Floorp" in str(target_app) else "com.vivaldi.Vivaldi")
            return subprocess.CompletedProcess(argv, 0, "", f"Identifier={i}\nTeamIdentifier={t}\n")
        return subprocess.CompletedProcess(argv, verify_code, "", diagnostic)
    return run


def make_fake_app(tmp_path: Path, name: str, bundle_id: str, version: str = "1.0.0"):
    app = tmp_path / f"{name}.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    exe_name = name.lower()
    (app / f"Contents/MacOS/{exe_name}").write_bytes(b"dummy binary")
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": bundle_id,
        "CFBundleExecutable": exe_name,
        "CFBundleShortVersionString": version,
    }))
    return app


@pytest.fixture(autouse=True)
def synthetic_application_probes(tmp_path, monkeypatch):
    floorp = make_fake_app(tmp_path / "application-fixtures", "Floorp", "app.floorp.Floorp")
    vivaldi = make_fake_app(tmp_path / "application-fixtures", "Vivaldi", "com.vivaldi.Vivaldi")
    original = kit.probe_applications
    monkeypatch.setattr(kit, "probe_applications", lambda runner: original(floorp, vivaldi, runner))


# ==================== BINDING & SOURCE INTEGRITY TESTS ====================

def test_binding_success(tmp_path):
    source_dir, kit_dir, entries, tree_sha, inv_sha = make_source_and_kit(tmp_path)
    res = kit.verify_binding(kit_dir, source_dir)
    assert res["status"] == "BOUND"
    assert res["treeBound"] is True
    assert res["inventoryDigestMatch"] is True
    assert res["reviewedTree"] == tree_sha
    assert res["sourceFilesVerified"] == len(entries)


def test_tampered_inventory_digest(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    inv_file = kit_dir / "SOURCE-INVENTORY.json"
    data = json.loads(inv_file.read_text())
    data["sha256"] = "a" * 64
    inv_file.write_text(json.dumps(data))

    fake_run = FakeRunner()
    res = kit.verify_binding(kit_dir, source_dir)
    assert res["status"] == "BINDING_FAILED"
    assert res["reason"] == "INVENTORY_DIGEST_MISMATCH"

    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["floorpOnlyEligibleForManagerReview"] is False
    assert len(fake_run.calls) == 0  # ZERO subprocesses!


def test_inventory_mismatch_with_kit(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    kit_file = kit_dir / "KIT.json"
    data = json.loads(kit_file.read_text())
    data["inventorySha256"] = "b" * 64
    kit_file.write_text(json.dumps(data))

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert len(fake_run.calls) == 0


def test_tampered_source_file_content(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    (source_dir / "flake.nix").write_bytes(b"# tampered content\n")

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert evidence["binding"]["reason"] == "FILE_CONTENT_MISMATCH"
    assert len(fake_run.calls) == 0


def test_tampered_source_file_mode(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    (source_dir / "flake.nix").chmod(0o755)

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert evidence["binding"]["reason"] == "FILE_MODE_MISMATCH"
    assert len(fake_run.calls) == 0


def test_extra_source_file(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    (source_dir / "untracked_extra.py").write_text("evil = 1\n")

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert evidence["binding"]["reason"] == "EXTRA_FILES_DETECTED"
    assert len(fake_run.calls) == 0


def test_missing_source_file(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    (source_dir / "config/default.nix").unlink()

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert evidence["binding"]["reason"] == "MISSING_FILES_DETECTED"
    assert len(fake_run.calls) == 0


def test_tampered_reviewed_tree(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    kit_file = kit_dir / "KIT.json"
    data = json.loads(kit_file.read_text())
    data["reviewedTree"] = "0" * 40
    kit_file.write_text(json.dumps(data))

    fake_run = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=fake_run)
    assert code == 1
    assert evidence["binding"]["status"] == "BINDING_FAILED"
    assert evidence["binding"]["reason"] == "TREE_MISMATCH"
    assert len(fake_run.calls) == 0


def test_snapshot_extra_artifacts_rejected(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    # Put excluded dirs inside source
    (source_dir / ".git").mkdir()
    (source_dir / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (source_dir / "__pycache__").mkdir()
    (source_dir / "__pycache__/foo.cpython.pyc").write_bytes(b"\x00\x00")
    (source_dir / ".scratch").mkdir()
    (source_dir / ".scratch/junk").write_text("junk")

    res = kit.verify_binding(kit_dir, source_dir)
    assert res["status"] == "BINDING_FAILED"


# ==================== APP PROBING & SANITIZATION TESTS ====================

def test_app_probe_match_sanitized(tmp_path):
    floorp = make_fake_app(tmp_path, "Floorp", "app.floorp.Floorp", "11.10.4")
    runner = fake_probe_runner(floorp)
    raw = kit.replacement_app_identity.probe(floorp, "app.floorp.Floorp", "DV2U35YBHT", runner=runner)
    sanitized = kit.sanitize_probe(raw, "app.floorp.Floorp", "DV2U35YBHT")
    assert sanitized["verdict"] == "MATCH"
    assert sanitized["bundleIdentifier"] == "app.floorp.Floorp"
    assert sanitized["teamIdentifier"] == "DV2U35YBHT"
    assert sanitized["version"] == "11.10.4"
    assert sanitized["signatureDiagnostic"] == "VERIFIED"


def test_floorp_app_absent(tmp_path):
    raw = kit.replacement_app_identity.probe(tmp_path / "Nonexistent.app", "app.floorp.Floorp", "DV2U35YBHT")
    sanitized = kit.sanitize_probe(raw, "app.floorp.Floorp", "DV2U35YBHT")
    assert sanitized["verdict"] == "UNKNOWN"
    assert sanitized["observation"] == "ABSENT"


def test_hostile_plist_and_diagnostic_sanitization(tmp_path):
    floorp = make_fake_app(tmp_path, "Floorp", "/Users/secret/credential", version="/private/var/leak")
    diag = "/Users/victim/app: invalid signature (code or signature modified)\nin architecture: arm64\n"
    runner = fake_probe_runner(floorp, verify_code=1, diagnostic=diag, team="/home/victim/token", identifier="/Users/leaked/id")
    raw = kit.replacement_app_identity.probe(floorp, "app.floorp.Floorp", "DV2U35YBHT", runner=runner)
    sanitized = kit.sanitize_probe(raw, "app.floorp.Floorp", "DV2U35YBHT")

    assert sanitized["verdict"] == "MISMATCH"
    assert sanitized["bundleIdentifier"] == "MISMATCH"
    assert sanitized["signingIdentifier"] == "MISMATCH"
    assert sanitized["teamIdentifier"] == "MISMATCH"
    assert sanitized["version"] == "SANITIZED_VERSION"
    assert sanitized["signatureDiagnostic"] == "INVALID_SIGNATURE"
    assert sanitized["signatureArchitecture"] == "arm64"
    assert "/Users" not in str(sanitized)
    assert "/private" not in str(sanitized)
    assert "/home" not in str(sanitized)


@pytest.mark.parametrize("diag,expected_cat", [
    ("sealed resource invalid (code or signature have been modified)", "SEALED_RESOURCE_INVALID"),
    ("resource detritus (code object not signed at all)", "RESOURCE_DETRITUS"),
    ("operation not permitted", "ACCESS_DENIED"),
    ("unknown error", "VERIFY_FAILED"),
])
def test_diagnostic_categories_preserved(tmp_path, diag, expected_cat):
    floorp = make_fake_app(tmp_path, "Floorp", "app.floorp.Floorp")
    runner = fake_probe_runner(floorp, verify_code=1, diagnostic=f"/path: {diag}")
    raw = kit.replacement_app_identity.probe(floorp, "app.floorp.Floorp", "DV2U35YBHT", runner=runner)
    if "sealed resource invalid" in diag:
        raw["signatureDiagnostic"] = "SEALED_RESOURCE_INVALID"
    elif "resource detritus" in diag:
        raw["signatureDiagnostic"] = "RESOURCE_DETRITUS"
    sanitized = kit.sanitize_probe(raw, "app.floorp.Floorp", "DV2U35YBHT")
    assert sanitized["signatureDiagnostic"] == expected_cat


# ==================== NIX CHECKS & TIMEOUT TESTS ====================

def test_flake_check_names_mismatch_extra(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path, checks=["check1"])
    fake_run = FakeRunner(checks=["check1", "extraCheck"])
    res = kit.run_flake_checks(source_dir, ["check1"], runner=fake_run)
    assert res["status"] == "FAIL"
    assert res["reason"] == "FLAKE_CHECKS_MISMATCH"


def test_flake_check_names_mismatch_omitted(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path, checks=["check1", "check2"])
    fake_run = FakeRunner(checks=["check1"])
    res = kit.run_flake_checks(source_dir, ["check1", "check2"], runner=fake_run)
    assert res["status"] == "FAIL"
    assert res["reason"] == "FLAKE_CHECKS_MISMATCH"


def test_check_build_failure(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path, checks=["c1", "c2"])
    fake_run = FakeRunner(checks=["c1", "c2"])
    fake_run.build_fail_on.add("c2")
    res = kit.run_flake_checks(source_dir, ["c1", "c2"], runner=fake_run)
    assert res["allPass"] is False
    assert res["items"][0]["category"] == "PASS"
    assert res["items"][1]["category"] == "BUILD_FAILED"
    assert res["items"][1]["exitCode"] == 1


def test_check_build_timeout(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path, checks=["c1"])
    fake_run = FakeRunner(checks=["c1"])
    fake_run.timeout_on.add("checks.aarch64-darwin.c1")
    res = kit.run_flake_checks(source_dir, ["c1"], runner=fake_run)
    assert res["allPass"] is False
    assert res["items"][0]["category"] == "TIMEOUT"
    assert res["items"][0]["exitCode"] == 124


def test_no_raw_build_logs_in_output(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path, checks=["c1"])
    fake_run = FakeRunner(checks=["c1"])
    res = kit.run_flake_checks(source_dir, ["c1"], runner=fake_run)
    for item in res["items"]:
        assert "stdout" not in item
        assert "stderr" not in item
        assert "logs" not in item


# ==================== BASELINE PINS EVALUATION TESTS ====================

def test_pins_match(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    fake_run = FakeRunner(pins=make_valid_pins())
    res = kit.evaluate_baseline_pins(source_dir, runner=fake_run)
    assert res["status"] == "PASS"


def test_pins_mismatch(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    bad_pins = make_valid_pins()
    bad_pins["default"]["chromeMatch"] = False
    fake_run = FakeRunner(pins=bad_pins)
    res = kit.evaluate_baseline_pins(source_dir, runner=fake_run)
    assert res["status"] == "FAIL"
    assert res["reason"] == "PIN_EQUALITY_MISMATCH"


# ==================== ACTIVATION MATRIX TESTS ====================

def test_matrix_valid(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    fake_run = FakeRunner(matrix=make_valid_matrix())
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "VALIDATED"
    assert "replacementAuthorized" not in res


def test_matrix_missing_row(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    del mat["combinations"]["bothEnabled"]
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert res["reason"] == "MISSING_MATRIX_COMBINATIONS"


def test_matrix_floorp_unexpected_hold(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["floorpOnly"]["rendering"]["floorp"]["runtimeHolds"] = ["UNEXPECTED_HOLD"]
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "UNEXPECTED_CORE_RUNTIME_HOLDS" in res["reason"]


def test_matrix_vivaldi_unexpected_hold(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["vivaldiOnly"]["rendering"]["vivaldi"]["runtimeHolds"] = ["UNEXPECTED_HOLD"]
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "UNEXPECTED_CORE_RUNTIME_HOLDS" in res["reason"]


def test_matrix_vivaldi_missing_crash_hold_in_mail_overlay(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["vivaldiOnly"]["rendering"]["vivaldi"]["featureOverlays"]["mail"]["runtimeHolds"] = []
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "VIVALDI_MAIL_OVERLAY_INVALID" in res["reason"]


def test_matrix_activation_authorized_true(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["floorpOnly"]["rendering"]["floorp"]["activation"]["replacementAuthorized"] = True
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "INVALID_ACTIVATION" in res["reason"]


def test_matrix_baseline_not_equal(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["floorpOnly"]["baselineEqual"]["toplevel"] = False
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "BASELINE_NOT_EQUAL" in res["reason"]


def test_matrix_cask_or_claim_mismatch(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["floorpOnly"]["claimIds"] = ["bundle:app.floorp.Floorp", "unauthorized:claim"]
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "CLAIM_IDS_MISMATCH" in res["reason"]


# ==================== RETENTION HAZARD TESTS ====================

def test_no_composition_unknown_hazardous():
    res = kit.analyze_retention_hazard(None, None, {"observation": "INSPECTED"}, {"observation": "INSPECTED"})
    assert res["hazard"] is True
    assert res["status"] == "UNKNOWN_HAZARDOUS"


def test_composition_cleanup_none_approved():
    comp = {"status": "READ_SUCCESS", "cleanup": "none", "vivaldiDeclared": False, "floorpDeclared": False}
    res = kit.analyze_retention_hazard(comp, None, {"observation": "INSPECTED"}, {"observation": "INSPECTED"})
    assert res["hazard"] is False
    assert res["status"] == "CLEANUP_NONE_APPROVED"


def test_composition_cleanup_zap_undeclared_managed():
    comp = {"status": "READ_SUCCESS", "cleanup": "zap", "vivaldiDeclared": False, "floorpDeclared": False}
    brew = {"brewAvailable": True, "vivaldiManaged": True, "floorpManaged": False}
    res = kit.analyze_retention_hazard(comp, brew, {"observation": "INSPECTED"}, {"observation": "ABSENT"})
    assert res["hazard"] is True
    assert "VIVALDI_RETENTION_HAZARD_UNDECLARED_BREW_CLEANUP" in res["reasons"]


def test_composition_cleanup_zap_undeclared_non_brew_managed():
    comp = {"status": "READ_SUCCESS", "cleanup": "zap", "vivaldiDeclared": False, "floorpDeclared": False}
    brew = {"brewAvailable": True, "vivaldiManaged": False, "floorpManaged": False}
    res = kit.analyze_retention_hazard(comp, brew, {"observation": "INSPECTED"}, {"observation": "ABSENT"})
    assert res["hazard"] is False
    assert res["status"] == "CONFIRMED_NON_BREW_MANAGED_PRESERVE_DATA"


def test_composition_cleanup_zap_app_absent():
    comp = {"status": "READ_SUCCESS", "cleanup": "zap", "vivaldiDeclared": False, "floorpDeclared": False}
    res = kit.analyze_retention_hazard(comp, None, {"observation": "ABSENT"}, {"observation": "ABSENT"})
    assert res["hazard"] is True  # A residual Homebrew cask can still zap profile evidence.


# ==================== DETERMINISTIC ZIP & FULL WORKFLOW ====================

def test_full_run_eligible(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    floorp_app = tmp_path / "Floorp.app"

    fake_run = FakeRunner()
    fake_probe = fake_probe_runner(floorp_app)

    evidence, code = kit.run_qualification(
        kit_root=kit_dir,
        output_dir=kit_dir / "evidence",
        worktree=source_dir,
        composition=tmp_path / "comp",
        host="test-host",
        homebrew_readback=True,
        runner=fake_run,
        app_probe_runner=fake_probe,
    )

    assert code == 0
    assert evidence["status"] == "PENDING_MANAGER_REVIEW"
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False
    assert evidence["vivaldiReplacement"] == "CANDIDATE_READY_FOR_QUALIFICATION"
    assert evidence["vivaldiBrowserCore"] == "CANDIDATE_READY_FOR_QUALIFICATION"
    assert evidence["vivaldiMail"] == "HOLD_RUNTIME_OOM"
    assert "authorized" not in evidence
    assert "replacementAuthorized" not in evidence

    out_dir = kit_dir / "evidence"
    assert (out_dir / "HOST-QUALIFICATION-EVIDENCE.json").is_file()
    assert (out_dir / "HOST-QUALIFICATION-EVIDENCE.zip").is_file()
    assert (out_dir / "HOST-QUALIFICATION-EVIDENCE.zip.sha256").is_file()


def test_full_run_both_eligible(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    fake_run = FakeRunner()
    def probe_both(argv, **kwargs):
        if "-dv" in argv:
            target = argv[-1]
            t = "DV2U35YBHT" if "Floorp" in target else "4XF3XNRN6Y"
            i = "app.floorp.Floorp" if "Floorp" in target else "com.vivaldi.Vivaldi"
            return subprocess.CompletedProcess(argv, 0, "", f"Identifier={i}\nTeamIdentifier={t}\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    evidence, code = kit.run_qualification(
        kit_root=kit_dir,
        output_dir=kit_dir / "evidence",
        worktree=source_dir,
        composition=tmp_path / "comp",
        host="test-host",
        homebrew_readback=True,
        runner=fake_run,
        app_probe_runner=probe_both,
    )

    assert code == 0
    assert evidence["status"] == "PENDING_MANAGER_REVIEW"
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is True
    assert evidence["vivaldiReplacement"] == "CANDIDATE_READY_FOR_QUALIFICATION"
    assert evidence["vivaldiBrowserCore"] == "CANDIDATE_READY_FOR_QUALIFICATION"
    assert evidence["vivaldiMail"] == "HOLD_RUNTIME_OOM"


def test_deterministic_zip(tmp_path):
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    ev = {"schema": kit.SCHEMA_EVIDENCE, "status": "PENDING_MANAGER_REVIEW", "test": 42}

    _, sha1 = kit.write_evidence_bundle(out1, ev)
    _, sha2 = kit.write_evidence_bundle(out2, ev)
    assert sha1 == sha2
    assert (out1 / "HOST-QUALIFICATION-EVIDENCE.zip").read_bytes() == (out2 / "HOST-QUALIFICATION-EVIDENCE.zip").read_bytes()

    with zipfile.ZipFile(out1 / "HOST-QUALIFICATION-EVIDENCE.zip") as z:
        for info in z.infolist():
            assert info.date_time == kit.FIXED_DATE
            assert (info.external_attr >> 16) == 0o100644


def test_privacy_guard_detection(tmp_path):
    out = tmp_path / "out"
    ev = {"schema": kit.SCHEMA_EVIDENCE, "status": "PENDING_MANAGER_REVIEW", "leak": "/Users/operator/secret"}
    with pytest.raises(kit.KitError) as exc_info:
        kit.write_evidence_bundle(out, ev)
    assert exc_info.value.code == "PRIVACY_GUARD"


def test_exact_allowed_commands_and_timeouts(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    fake_run = FakeRunner()
    fake_probe = fake_probe_runner(tmp_path / "Floorp.app")

    kit.run_qualification(
        kit_root=kit_dir,
        output_dir=kit_dir / "evidence",
        worktree=source_dir,
        composition=tmp_path / "comp",
        host="test-host",
        homebrew_readback=True,
        runner=fake_run,
        app_probe_runner=fake_probe,
    )

    for call in fake_run.calls:
        binary = call[0]
        assert any(b in binary for b in ("git", "nix", "brew", "codesign"))
        if "diff" in call:
            assert "--no-optional-locks" in call
        if "nix" in call:
            assert "--no-write-lock-file" in call


def test_snapshot_only_run_never_requires_git_metadata(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture")
    assert code == 0
    assert evidence["sourceChecks"]["diffCheckExitCode"] is None
    assert not any(call[0] == "git" for call in runner.calls)
    assert "replacementAuthorized" not in json.dumps(evidence)


def test_optional_worktree_drift_stops_host_checks(tmp_path):
    source, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    live = tmp_path / "live"
    live.mkdir()
    for name in ("flake.nix", "config/default.nix", "tests/source-only-roster.json"):
        target = live / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / name).read_bytes())
    (live / "flake.nix").write_text("# drift\n")
    runner = FakeRunner()
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=live, runner=runner)
    assert code == 1
    assert evidence["binding"]["reason"] == "WORKTREE_DRIFT_OR_READ_FAILED"
    assert all(call[0] == "git" and "--no-optional-locks" in call for call in runner.calls)


def test_source_checks_scan_snapshot_whitespace(tmp_path):
    source, _, entries, _, _ = make_source_and_kit(tmp_path)
    (source / "flake.nix").write_bytes(b"# trailing space \n")
    result = kit.run_source_checks(source, list(entries), runner=FakeRunner())
    assert result["status"] == "FAILED"
    assert result["snapshotWhitespaceClean"] is False


@pytest.mark.parametrize("bad", [[], ["duplicate", "duplicate"], [None], ["bad.name"]])
def test_bad_check_lists_fail_before_subprocess(tmp_path, bad):
    runner = FakeRunner()
    assert kit.run_flake_checks(tmp_path, bad, runner)["allPass"] is False
    assert runner.calls == []


@pytest.mark.parametrize("bad", [{}, {"default": dict.fromkeys(kit.PIN_FIELDS, True)},
                                 {name: dict.fromkeys(kit.PIN_FIELDS, 1) for name in kit.PIN_CASES}])
def test_missing_or_non_boolean_pin_readback_fails(tmp_path, bad):
    result = kit.evaluate_baseline_pins(tmp_path, FakeRunner(pins=bad))
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda row: row["baselineEqual"].pop("seams"),
    lambda row: row["rendering"]["floorp"]["activation"].update(status="HOLD_RUNTIME_CRASH"),
    lambda row: row["rendering"]["floorp"].update(browser="vivaldi"),
    lambda row: row.update(claimIds=None),
    lambda row: row["enabled"].update(floorp=1),
])
def test_incomplete_or_malformed_matrix_fails(tmp_path, mutation):
    matrix = make_valid_matrix()
    mutation(matrix["combinations"]["floorpOnly"])
    assert kit.evaluate_activation_matrix(tmp_path, FakeRunner(matrix=matrix))["status"] == "INVALID"


@pytest.mark.parametrize("cleanup", ["UNKNOWN", "", None])
def test_unknown_cleanup_is_hazardous(cleanup):
    result = kit.analyze_retention_hazard({"status": "READ_SUCCESS", "cleanup": cleanup}, None,
                                         {"observation": "ABSENT"}, {"observation": "ABSENT"})
    assert result["hazard"] is True


def test_cleanup_check_preserves_unmanaged_application():
    result = kit.analyze_retention_hazard({"status": "READ_SUCCESS", "cleanup": "check"}, None,
                                         {"observation": "INSPECTED"}, {"observation": "ABSENT"})
    assert result["hazard"] is False


def test_failed_brew_readback_never_proves_unmanaged(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda path: True)
    def failed(argv, **kwargs):
        assert argv == ["/opt/homebrew/bin/brew", "list", "--cask", "--versions"]
        assert kwargs["env"]["HOMEBREW_NO_AUTO_UPDATE"] == "1"
        return subprocess.CompletedProcess(argv, 1, "", "private diagnostic")
    brew = kit.read_homebrew(failed)
    assert brew["brewAvailable"] is False
    assert kit.analyze_retention_hazard({"status": "READ_SUCCESS", "cleanup": "zap"}, brew,
                                      {"observation": "INSPECTED"}, {"observation": "ABSENT"})["hazard"] is True


def test_vivaldi_signature_failure_does_not_block_floorp(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    def probe_runner(argv, **kwargs):
        if "--verify" in argv and "Vivaldi.app" in argv[-1]:
            return subprocess.CompletedProcess(argv, 1, "", "/private/operator: invalid signature")
        return runner(argv, **kwargs)
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
        app_probe_runner=probe_runner, composition=tmp_path / "composition", host="fixture")
    assert code == 0
    assert evidence["probes"]["vivaldi"]["verdict"] == "MISMATCH"
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False


def test_unsafe_output_is_refused_before_commands(tmp_path):
    source, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    with pytest.raises(kit.KitError, match="Output must stay"):
        kit.run_qualification(kit_dir, source / "evidence", runner=runner)
    assert runner.calls == []


def test_nix_strings_escape_interpolation_and_quotes():
    assert kit.nix_string('fixture${value}"') == '"fixture\\${value}\\\""'


def test_floorp_version_is_preserved_without_freeform_suffixes():
    assert kit.sanitize_version("12.19.0@157.0") == "12.19.0@157.0"
    assert kit.sanitize_version("1PRIVATE_TOKEN") == "SANITIZED_VERSION"


def test_conflicting_activation_records_are_rejected(tmp_path):
    matrix = make_valid_matrix()
    matrix["combinations"]["bothEnabled"]["rendering"]["floorp"]["activation"]["blockers"] = [kit.VIVALDI_CRASH_HOLD]
    assert kit.evaluate_activation_matrix(tmp_path, FakeRunner(matrix=matrix))["status"] == "INVALID"


def test_unbound_symlink_target_is_refused(tmp_path):
    source, kit_dir, entries, _, _ = make_source_and_kit(tmp_path)
    link = source / "unbound-link"
    link.symlink_to("../outside")
    record, _ = kit.source_only_snapshot.read_entry(source, "unbound-link")
    entries["unbound-link"] = record
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    inv = {"schema": kit.SCHEMA_INVENTORY, "sha256": digest, "entries": entries}
    (kit_dir / "SOURCE-INVENTORY.json").write_text(json.dumps(inv))
    meta = json.loads((kit_dir / "KIT.json").read_text())
    meta["inventorySha256"] = digest
    (kit_dir / "KIT.json").write_text(json.dumps(meta))
    assert kit.verify_binding(kit_dir, source)["status"] == "BINDING_FAILED"


def test_absent_app_with_managed_cask_still_has_zap_hazard():
    comp = {"status": "READ_SUCCESS", "cleanup": "zap", "vivaldiDeclared": False, "floorpDeclared": True}
    brew = {"brewAvailable": True, "vivaldiManaged": True, "floorpManaged": True}
    result = kit.analyze_retention_hazard(comp, brew, {"observation": "ABSENT"}, {"observation": "INSPECTED"})
    assert result["vivaldiRetentionHazard"] is True
    assert result["vivaldiPresence"] == "ABSENT"
    assert result["vivaldiManagement"] == "HOMEBREW_MANAGED"


def test_composition_mail_request_does_not_gate_browser_core(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    runner.composition_data["vivaldiReplacementEnabled"] = True
    runner.composition_data["vivaldiMailEnabled"] = True
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture")
    assert code == 0
    assert evidence["retention"]["reasons"] == []
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is True
    assert evidence["retention"]["vivaldiRetentionHazard"] is False
    assert evidence["retention"]["floorpRetentionHazard"] is False
    assert evidence["vivaldiMailConfiguration"] == {
        "status": "READ_SUCCESS", "requested": True,
        "source": "COMPOSITION_CONFIG", "liveProfileRead": False,
        "activationAuthorized": False,
    }


def test_composition_vivaldi_core_flag_allowed_without_hazard(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    runner.composition_data["vivaldiReplacementEnabled"] = True
    runner.composition_data["vivaldiMailEnabled"] = False
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture")
    assert code == 0
    assert "VIVALDI_LIVE_MAIL_FLAG_ENABLED" not in evidence["retention"]["reasons"]
    assert "VIVALDI_LIVE_REPLACEMENT_FLAG_ENABLED" not in evidence["retention"]["reasons"]
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is True
    assert evidence["vivaldiMailConfiguration"]["requested"] is False
    assert evidence["vivaldiMailConfiguration"]["activationAuthorized"] is False


def test_floorp_eligible_despite_vivaldi_retention_hazard(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    runner.composition_data = {
        "cleanup": "zap", "vivaldiDeclared": False, "floorpDeclared": True,
        "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False,
    }
    runner.brew_stdout = "floorp 11.10.4\nvivaldi 6.5.3206.59\n"
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture", homebrew_readback=True)
    assert code == 0
    assert "VIVALDI_RETENTION_HAZARD_UNDECLARED_BREW_CLEANUP" in evidence["retention"]["reasons"]
    assert evidence["floorpOnlyEligibleForManagerReview"] is True
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False
    assert evidence["retention"]["floorpRetentionHazard"] is False
    assert evidence["retention"]["vivaldiRetentionHazard"] is True


def test_vivaldi_eligible_despite_floorp_retention_hazard(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    runner.composition_data = {
        "cleanup": "zap", "vivaldiDeclared": True, "floorpDeclared": False,
        "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False,
    }
    runner.brew_stdout = "floorp 11.10.4\nvivaldi 6.5.3206.59\n"
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture", homebrew_readback=True)
    assert code == 0
    assert "FLOORP_RETENTION_HAZARD_UNDECLARED_BREW_CLEANUP" in evidence["retention"]["reasons"]
    assert evidence["floorpOnlyEligibleForManagerReview"] is False
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is True
    assert evidence["retention"]["floorpRetentionHazard"] is True
    assert evidence["retention"]["vivaldiRetentionHazard"] is False


def test_generic_unknown_cleanup_blocks_both(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    runner.composition_data = {
        "cleanup": "bad_cleanup", "vivaldiDeclared": True, "floorpDeclared": True,
        "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False,
    }
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=runner,
                                         composition=tmp_path / "comp", host="fixture")
    assert code == 1
    assert "CLEANUP_UNKNOWN" in evidence["retention"]["reasons"]
    assert evidence["floorpOnlyEligibleForManagerReview"] is False
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False
    assert evidence["retention"]["floorpRetentionHazard"] is True
    assert evidence["retention"]["vivaldiRetentionHazard"] is True


def test_composition_read_failure_blocks_both_without_inventing_mail_flag(tmp_path):
    _, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    runner = FakeRunner()
    def failing_runner(argv, **kwargs):
        if "darwinConfigurations" in " ".join(argv):
            return subprocess.CompletedProcess(argv, 1, "", "syntax error in flake")
        return runner(argv, **kwargs)
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", runner=failing_runner,
                                         composition=tmp_path / "comp", host="fixture")
    assert code == 1
    assert "COMPOSITION_READ_FAILED" in evidence["retention"]["reasons"]
    assert "VIVALDI_LIVE_MAIL_FLAG_ENABLED" not in evidence["retention"]["reasons"]
    assert evidence["vivaldiMailConfiguration"]["status"] == "READ_FAILED"
    assert evidence["vivaldiMailConfiguration"]["requested"] is None
    assert evidence["floorpOnlyEligibleForManagerReview"] is False
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False
    assert evidence["retention"]["floorpRetentionHazard"] is True
    assert evidence["retention"]["vivaldiRetentionHazard"] is True


def test_matrix_deep_validation_replacement_candidate(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["bothEnabled"]["rendering"]["vivaldi"]["replacementCandidate"]["role"] = "firefox-replacement"
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "INVALID_REPLACEMENT_CANDIDATE" in res["reason"]


def test_matrix_deep_validation_floorp_overlays_rejected(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["bothEnabled"]["rendering"]["floorp"]["featureOverlays"] = {"mail": {}}
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "FLOORP_OVERLAYS_NOT_EMPTY" in res["reason"]


def test_matrix_deep_validation_vivaldi_overlay_requested_rejected(tmp_path):
    source_dir, _, _, _, _ = make_source_and_kit(tmp_path)
    mat = make_valid_matrix()
    mat["combinations"]["vivaldiOnly"]["rendering"]["vivaldi"]["featureOverlays"]["mail"]["requested"] = True
    fake_run = FakeRunner(matrix=mat)
    res = kit.evaluate_activation_matrix(source_dir, runner=fake_run)
    assert res["status"] == "INVALID"
    assert "VIVALDI_MAIL_OVERLAY_INVALID" in res["reason"]


def test_tampered_inventory_digest_sets_additive_evidence_fields(tmp_path):
    source_dir, kit_dir, _, _, _ = make_source_and_kit(tmp_path)
    inv_file = kit_dir / "SOURCE-INVENTORY.json"
    data = json.loads(inv_file.read_text())
    data["sha256"] = "f" * 64
    inv_file.write_text(json.dumps(data))
    evidence, code = kit.run_qualification(kit_dir, kit_dir / "evidence", worktree=source_dir, runner=FakeRunner())
    assert code == 1
    assert evidence["floorpOnlyEligibleForManagerReview"] is False
    assert evidence["vivaldiBrowserCoreEligibleForManagerReview"] is False
    assert evidence["vivaldiReplacement"] == "NOT_EVALUATED"
    assert evidence["vivaldiBrowserCore"] == "NOT_EVALUATED"
    assert evidence["vivaldiMail"] == "NOT_EVALUATED"
    assert evidence["vivaldiMailConfiguration"]["status"] == "NOT_EVALUATED"
    assert evidence["vivaldiMailConfiguration"]["requested"] is None
