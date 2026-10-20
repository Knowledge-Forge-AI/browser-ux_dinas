#!/usr/bin/env python3
"""Host qualification kit for browser UX replacement candidates (Floorp and Vivaldi).

Read-only and derivation-only host qualification runner. Python stdlib only.
CLI: python3 -B source/tests/replacement_host_kit.py run --kit-root DIR --output DIR [--worktree PATH] [--composition PATH --host NAME] [--homebrew-readback]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import replacement_app_identity  # noqa: E402
import source_only_snapshot  # noqa: E402

SCHEMA_KIT = "browser-ux-replacement-host-kit-v1"
SCHEMA_INVENTORY = "browser-ux-source-inventory-v1"
SCHEMA_MATRIX = "browser-ux-replacement-activation-matrix-v1"
SCHEMA_EVIDENCE = "browser-ux-host-qualification-evidence-v1"
SYSTEM = "aarch64-darwin"
VIVALDI_CRASH_HOLD = "VIVALDI_MAIL_STARTUP_CRASH_8_2_4133_83"

FLOORP_APP = Path("/Applications/Floorp.app")
VIVALDI_APP = Path("/Applications/Vivaldi.app")

EXPECTED_FLOORP = {
    "bundle": "app.floorp.Floorp", "team": "DV2U35YBHT",
    "cask": "floorp", "claim": "bundle:app.floorp.Floorp",
}
EXPECTED_VIVALDI = {
    "bundle": "com.vivaldi.Vivaldi", "team": "4XF3XNRN6Y",
    "cask": "vivaldi", "claim": "bundle:com.vivaldi.Vivaldi",
}

EXCLUDED_NAMES = {
    ".git", ".scratch", "scratch", "__pycache__", ".pytest_cache",
    "reports", "outbox", "node_modules", ".venv",
}
PRIVATE_MARKERS = ("/Users/", "/home/", "/nix/store/", "/private/var/", "/var/folders/")
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
TIMEOUTS = {"diff": 30, "eval": 60, "build": 180, "comp": 30, "brew": 15}
BASELINE_FIELDS = {"toplevel", "applications", "homebrew", "seams", "activationScripts", "etc"}
PIN_CASES = {"bridgeOptOut", "default", "disabled", "fullOptOut"}
PIN_FIELDS = {"chromeEqual", "firefoxEqual", "chromeMatch", "firefoxMatch"}
# Preserve the one pre-existing MIRROR1 whitespace line by exact bytes/location.
BASELINE_WHITESPACE = {
    ("tests/cnt-synthetic-firefox.test.py", 65): "bd6d7e70cab31c56cf1458436976107e58281dfc7c12bcdbc3a71b4d8191a2e7",
}


def nix_string(value: str) -> str:
    return json.dumps(value).replace("${", "\\${")


class KitError(Exception):
    def __init__(self, message: str, code: str = "ERROR"):
        super().__init__(message)
        self.code = code


def require(cond: bool, msg: str, code: str = "ERROR") -> None:
    if not cond:
        raise KitError(msg, code=code)


def compute_git_tree(entries: dict[str, dict], file_reader) -> str:
    """Reconstruct pure-Python Git tree SHA1 from entries and file bytes."""
    root: dict = {}
    for path, record in entries.items():
        curr = root
        parts = path.split("/")
        for part in parts[:-1]:
            curr = curr.setdefault(part, {})
        raw = file_reader(path)
        blob = b"blob " + str(len(raw)).encode() + b"\x00" + raw
        blob_sha = hashlib.sha1(blob).digest()
        mode_str = "120000" if record.get("kind") == "symlink" else (
            "100755" if (record.get("mode", 0) & 0o111) else "100644"
        )
        curr[parts[-1]] = (mode_str, blob_sha)

    def _tree_sha(tree_dict: dict) -> str:
        items = []
        for name, val in tree_dict.items():
            if isinstance(val, dict):
                items.append((name, "40000", bytes.fromhex(_tree_sha(val)), True))
            else:
                items.append((name, val[0], val[1], False))
        items.sort(key=lambda x: x[0].encode() + (b"/" if x[3] else b""))
        raw_tree = b"".join(f"{m} {n}".encode() + b"\x00" + s for n, m, s, _ in items)
        return hashlib.sha1(f"tree {len(raw_tree)}".encode() + b"\x00" + raw_tree).hexdigest()

    return _tree_sha(root)


def fail_binding(reason: str, verified: int = 0, inv_match: bool = False, **extra) -> dict:
    return {
        "status": "BINDING_FAILED", "reason": reason, "sourceFilesVerified": verified,
        "treeBound": False, "inventoryDigestMatch": inv_match, **extra,
    }


def snapshot_paths(source_root: Path) -> set[str]:
    def walk_error(error):
        raise error
    actual_paths = set()
    for root_dir, dirnames, filenames in os.walk(source_root, followlinks=False, onerror=walk_error):
        for d in [d for d in dirnames if os.path.islink(os.path.join(root_dir, d))]:
            actual_paths.add(os.path.relpath(os.path.join(root_dir, d), source_root))
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(root_dir, d))]
        actual_paths.update(os.path.relpath(os.path.join(root_dir, f), source_root) for f in filenames)
    return actual_paths


def verify_binding(kit_root: Path, source_root: Path) -> dict:
    """Verify inventory digest, files, and tree SHA1. Zero subprocesses allowed."""
    kit_path, inv_path = Path(kit_root) / "KIT.json", Path(kit_root) / "SOURCE-INVENTORY.json"
    if not kit_path.is_file() or not inv_path.is_file():
        return fail_binding("MISSING_KIT_OR_INVENTORY")

    try:
        kit, inventory = json.loads(kit_path.read_text()), json.loads(inv_path.read_text())
    except (OSError, ValueError):
        return fail_binding("MALFORMED_JSON")

    if not isinstance(kit, dict) or kit.get("schema") != SCHEMA_KIT or kit.get("system") != SYSTEM:
        return fail_binding("INVALID_KIT_SCHEMA_OR_SYSTEM")
    if not isinstance(inventory, dict) or inventory.get("schema") != SCHEMA_INVENTORY or not isinstance(inventory.get("entries"), dict):
        return fail_binding("INVALID_INVENTORY_SCHEMA")
    if not valid_check_names(kit.get("checks")):
        return fail_binding("INVALID_CHECK_LIST")

    entries = inventory["entries"]
    computed_inv_sha = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if computed_inv_sha != inventory.get("sha256") or kit.get("inventorySha256") != computed_inv_sha:
        return fail_binding("INVENTORY_DIGEST_MISMATCH")

    source_root = Path(source_root).absolute()
    if source_root.resolve() != source_root:
        return fail_binding("SOURCE_ROOT_SUBSTITUTED", inv_match=True)
    try:
        actual_paths = snapshot_paths(source_root)
    except OSError:
        return fail_binding("SOURCE_READ_FAILED", inv_match=True)

    if actual_paths != set(entries.keys()):
        return fail_binding("EXTRA_FILES_DETECTED" if actual_paths - set(entries.keys()) else "MISSING_FILES_DETECTED",
                            inv_match=True)

    file_bytes_cache: dict[str, bytes] = {}
    for name, exp in entries.items():
        if not isinstance(exp, dict) or set(exp) != {"kind", "mode", "sha256"}:
            return fail_binding("INVALID_ENTRY_SCHEMA", len(file_bytes_cache), inv_match=True)
        try:
            act, raw = source_only_snapshot.read_entry(source_root, name)
        except Exception:
            return fail_binding("FILE_READ_FAILED", len(file_bytes_cache), inv_match=True)
        if act.get("kind") != exp.get("kind"):
            return fail_binding("FILE_KIND_MISMATCH", len(file_bytes_cache), inv_match=True)
        if act.get("mode") != exp.get("mode"):
            return fail_binding("FILE_MODE_MISMATCH", len(file_bytes_cache), inv_match=True)
        if act.get("sha256") != exp.get("sha256"):
            return fail_binding("FILE_CONTENT_MISMATCH", len(file_bytes_cache), inv_match=True)
        file_bytes_cache[name] = raw

    try:
        for name, exp in entries.items():
            if exp["kind"] == "symlink":
                source_only_snapshot.validate_link(name, file_bytes_cache[name], set(entries),
                    {n: (r, file_bytes_cache[n]) for n, r in entries.items()})
            else:
                source_only_snapshot.reject_capture(name, file_bytes_cache[name])
        reconstructed_tree = compute_git_tree(entries, lambda n: file_bytes_cache[n])
    except Exception:
        return fail_binding("TREE_RECONSTRUCTION_FAILED", len(file_bytes_cache), inv_match=True)

    if kit.get("reviewedTree") != reconstructed_tree:
        return fail_binding("TREE_MISMATCH", len(file_bytes_cache), inv_match=True, reconstructedTree=reconstructed_tree)

    return {
        "status": "BOUND", "reason": None, "sourceFilesVerified": len(file_bytes_cache),
        "treeBound": True, "inventoryDigestMatch": True,
        "reviewedTree": reconstructed_tree, "inventorySha256": computed_inv_sha,
    }


def sanitize_version(val: object) -> str | None:
    if isinstance(val, str) and len(val) <= 32 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*(?:@[0-9]+(?:\.[0-9]+)*)?", val):
        return val
    return "SANITIZED_VERSION" if isinstance(val, str) else None


def verify_worktree(kit_root: Path, worktree: Path, runner=subprocess.run) -> dict:
    try:
        def paths(*flags):
            result = runner(["git", "--no-optional-locks", "-C", str(worktree), "ls-files", "-z", *flags],
                            capture_output=True, text=True, check=False, timeout=TIMEOUTS["diff"])
            require(result.returncode == 0, "Git read failed")
            return {n for n in result.stdout.split("\0") if n}
        _, roster_raw = source_only_snapshot.read_entry(worktree, source_only_snapshot.ROSTER)
        roster = json.loads(roster_raw)
        require(isinstance(roster, list) and all(isinstance(n, str) for n in roster), "Invalid roster")
        selected = paths("--cached") | set(roster) | {source_only_snapshot.ROSTER}
        others = paths("--others", "--exclude-standard")
        require(not {n for n in others - selected if not EXCLUDED_NAMES.intersection(Path(n).parts)}, "Unexpected source")
        expected = json.loads((kit_root / "SOURCE-INVENTORY.json").read_text())["entries"]
        require(selected == set(expected), "Source selection changed")
        require(all(source_only_snapshot.read_entry(worktree, n)[0] == record
                    for n, record in expected.items()), "Source drift")
        return {"status": "MATCH", "sourceFilesVerified": len(expected)}
    except (OSError, ValueError, KeyError, TypeError, KitError, subprocess.TimeoutExpired):
        return {"status": "DRIFT_OR_READ_FAILED"}


def sanitize_probe(probe_res: dict, expect_bundle: str, expect_team: str) -> dict:
    verdict = probe_res.get("verdict") if probe_res.get("verdict") in ("MATCH", "MISMATCH") else "UNKNOWN"
    obs = probe_res.get("observation")
    allowed_obs = {"ABSENT", "INVALID_PLIST", "INVALID_EXECUTABLE", "EXECUTABLE_ABSENT",
                   "READ_OR_SIGNATURE_ERROR", "SIGNATURE_UNREADABLE", "INSPECTED"}
    obs = obs if obs in allowed_obs else "UNKNOWN"

    bundle_id = expect_bundle if probe_res.get("bundleIdentifier") == expect_bundle else "MISMATCH"
    signing_id = expect_bundle if probe_res.get("signingIdentifier") == expect_bundle else "MISMATCH"
    team_id = expect_team if probe_res.get("teamIdentifier") == expect_team else "MISMATCH"

    allowed_diags = {"VERIFIED", "ACCESS_DENIED", "INVALID_SIGNATURE", "UNSIGNED", "VERIFY_FAILED",
                     "SEALED_RESOURCE_INVALID", "RESOURCE_DETRITUS", "SIGNATURE_UNREADABLE"}
    sig_diag = probe_res.get("signatureDiagnostic")
    if sig_diag not in allowed_diags:
        sig_diag = "VERIFY_FAILED" if not probe_res.get("signatureVerified") else "VERIFIED"

    arch = probe_res.get("signatureArchitecture") if probe_res.get("signatureArchitecture") in ("arm64", "x86_64") else None
    exit_code = probe_res.get("signatureVerifyExitCode") if isinstance(probe_res.get("signatureVerifyExitCode"), int) else None

    if verdict == "MATCH" and (bundle_id != expect_bundle or signing_id != expect_bundle
            or team_id != expect_team or probe_res.get("signatureVerified") is not True
            or exit_code != 0 or obs != "INSPECTED"):
        verdict = "UNKNOWN"
    return {
        "schema": "browser-ux-app-identity-v1", "verdict": verdict, "observation": obs,
        "bundleIdentifier": bundle_id, "signingIdentifier": signing_id, "teamIdentifier": team_id,
        "version": sanitize_version(probe_res.get("version")),
        "buildVersion": sanitize_version(probe_res.get("buildVersion")),
        "signatureVerified": probe_res.get("signatureVerified") is True,
        "signatureVerifyExitCode": exit_code, "signatureDiagnostic": sig_diag,
        "signatureArchitecture": arch, "executablePresent": bool(probe_res.get("executablePresent", False)),
    }


def probe_applications(floorp_app: Path = FLOORP_APP, vivaldi_app: Path = VIVALDI_APP, runner=subprocess.run) -> dict:
    f_raw = replacement_app_identity.probe(floorp_app, EXPECTED_FLOORP["bundle"], EXPECTED_FLOORP["team"], runner=runner)
    v_raw = replacement_app_identity.probe(vivaldi_app, EXPECTED_VIVALDI["bundle"], EXPECTED_VIVALDI["team"], runner=runner)
    return {
        "floorp": sanitize_probe(f_raw, EXPECTED_FLOORP["bundle"], EXPECTED_FLOORP["team"]),
        "vivaldi": sanitize_probe(v_raw, EXPECTED_VIVALDI["bundle"], EXPECTED_VIVALDI["team"]),
    }


def check_conflict_markers(source_root: Path, file_names: list[str]) -> bool:
    for name in file_names:
        p = Path(source_root) / name
        if not p.is_file() or p.is_symlink():
            continue
        try:
            raw = p.read_bytes()
            if b"\x00" in raw:
                continue
            for line in raw.decode("utf-8", errors="ignore").splitlines():
                if line.startswith("<<<<<<< ") or line.startswith(">>>>>>> ") or line == "=======":
                    return True
        except Exception:
            continue
    return False


def run_source_checks(source_root: Path, file_names: list[str], runner=subprocess.run, worktree=None) -> dict:
    diff_code = None
    if worktree is not None:
        try:
            res = runner(["git", "--no-optional-locks", "-C", str(worktree), "diff", "--check"],
                         capture_output=True, text=True, check=False, timeout=TIMEOUTS["diff"])
            diff_code = res.returncode
        except (subprocess.TimeoutExpired, OSError):
            diff_code = 124
    whitespace_clean = True
    for name in file_names:
        record, raw = source_only_snapshot.read_entry(source_root, name)
        if record["kind"] == "file" and b"\x00" not in raw:
            whitespace_clean &= not any(line.endswith((b" ", b"\t"))
                and BASELINE_WHITESPACE.get((name, number)) != hashlib.sha256(line).hexdigest()
                for number, line in enumerate(raw.splitlines(), 1))
    conflict_found = check_conflict_markers(source_root, file_names)
    clean = diff_code in (None, 0) and not conflict_found and whitespace_clean
    return {"diffCheckExitCode": diff_code, "conflictMarkersFound": conflict_found,
            "snapshotWhitespaceClean": whitespace_clean, "status": "CLEAN" if clean else "FAILED"}


def valid_check_names(names) -> bool:
    return isinstance(names, list) and bool(names) and all(
        isinstance(n, str) and re.fullmatch(r"[a-z][a-z0-9-]*", n) for n in names
    ) and len(names) == len(set(names))


def run_flake_checks(source_root: Path, sealed_checks: list[str], runner=subprocess.run) -> dict:
    if not valid_check_names(sealed_checks):
        return {"allPass": False, "status": "FAIL", "reason": "INVALID_CHECK_LIST", "items": []}
    cmd_eval = ["nix", "eval", "--json", "--no-write-lock-file",
                f"path:{source_root}#checks.aarch64-darwin", "--apply", "c: builtins.attrNames c"]
    try:
        res_eval = runner(cmd_eval, capture_output=True, text=True, check=False, timeout=TIMEOUTS["eval"])
        if res_eval.returncode != 0:
            return {"allPass": False, "status": "FAIL", "reason": "FLAKE_CHECKS_EVAL_FAILED", "items": []}
        flake_names = json.loads(res_eval.stdout)
        if not valid_check_names(flake_names) or sorted(flake_names) != sorted(sealed_checks):
            return {"allPass": False, "status": "FAIL", "reason": "FLAKE_CHECKS_MISMATCH", "items": []}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError):
        return {"allPass": False, "status": "FAIL", "reason": "FLAKE_CHECKS_EVAL_ERROR", "items": []}

    items, all_pass = [], True
    for name in sealed_checks:
        cmd_build = ["nix", "build", "--no-link", "--no-write-lock-file", f"path:{source_root}#checks.aarch64-darwin.{name}"]
        try:
            res_b = runner(cmd_build, capture_output=True, text=True, check=False, timeout=TIMEOUTS["build"])
            code = res_b.returncode
            category = "PASS" if code == 0 else "BUILD_FAILED"
        except subprocess.TimeoutExpired:
            code, category = 124, "TIMEOUT"
        except FileNotFoundError:
            code, category = 127, "TOOL_NOT_FOUND"
        except Exception:
            code, category = 1, "BUILD_FAILED"
        if category != "PASS":
            all_pass = False
        items.append({"name": name, "category": category, "exitCode": code})

    return {"allPass": all_pass, "status": "PASS" if all_pass else "FAIL", "items": items,
            "reason": None if all_pass else "CHECKS_FAILED"}


def evaluate_baseline_pins(source_root: Path, runner=subprocess.run) -> dict:
    expr = f"""
let
  flake = builtins.getFlake {nix_string('path:' + str(source_root))};
  root = flake.outPath;
  pinFixture = builtins.fromJSON (builtins.readFile (root + "/tests/fixtures/replacement-baseline-pins.json"));
  chromiumBaseline = import (root + "/config/browser/families/chromium.nix");
  geckoBaseline = import (root + "/config/browser/families/gecko.nix");
  chromeLegacyWrapper = import (root + "/config/browser/chrome-policy-defaults.nix");
  firefoxLegacyWrapper = import (root + "/config/browser/firefox-policy-defaults.nix");
  cases = pinFixture.cases;
in
builtins.mapAttrs (caseName: c:
  let
    cChrome = chromiumBaseline c.args; cFirefox = geckoBaseline c.args;
    wChrome = chromeLegacyWrapper c.args; wFirefox = firefoxLegacyWrapper c.args;
    hChrome = builtins.hashString "sha256" (builtins.toJSON cChrome);
    hFirefox = builtins.hashString "sha256" (builtins.toJSON cFirefox);
    hwChrome = builtins.hashString "sha256" (builtins.toJSON wChrome);
    hwFirefox = builtins.hashString "sha256" (builtins.toJSON wFirefox);
  in {{
    chromeEqual = (cChrome == wChrome); firefoxEqual = (cFirefox == wFirefox);
    chromeMatch = (hChrome == c.chrome && hwChrome == c.chrome);
    firefoxMatch = (hFirefox == c.firefox && hwFirefox == c.firefox);
  }}
) cases
"""
    cmd = ["nix", "eval", "--json", "--no-write-lock-file", "--impure", "--expr", expr]
    try:
        res = runner(cmd, capture_output=True, text=True, check=False, timeout=TIMEOUTS["eval"])
        if res.returncode != 0:
            return {"status": "FAIL", "reason": "PINS_EVAL_FAILED", "cases": {}}
        cases = json.loads(res.stdout)
        shaped = isinstance(cases, dict) and set(cases) == PIN_CASES and all(
            isinstance(c, dict) and set(c) == PIN_FIELDS and all(type(v) is bool for v in c.values())
            for c in cases.values())
        all_ok = shaped and all(all(c.values()) for c in cases.values())
        return {"status": "PASS" if all_ok else "FAIL", "reason": None if all_ok else "PIN_EQUALITY_MISMATCH",
                "cases": cases if shaped else {}}
    except Exception:
        return {"status": "FAIL", "reason": "PINS_EXECUTION_ERROR", "cases": {}}


def evaluate_activation_matrix(source_root: Path, runner=subprocess.run) -> dict:
    cmd = ["nix", "eval", "--json", "--no-write-lock-file",
           f"path:{source_root}#checks.aarch64-darwin.replacement-activation-matrix.passthru.readback"]
    try:
        res = runner(cmd, capture_output=True, text=True, check=False, timeout=TIMEOUTS["eval"])
        if res.returncode != 0:
            return {"status": "INVALID", "reason": "MATRIX_EVAL_FAILED"}
        matrix = json.loads(res.stdout)
    except Exception:
        return {"status": "INVALID", "reason": "MATRIX_EXECUTION_ERROR"}

    if not isinstance(matrix, dict) or matrix.get("schema") != SCHEMA_MATRIX:
        return {"status": "INVALID", "reason": "INVALID_MATRIX_SCHEMA"}

    combos = matrix.get("combinations")
    req_keys = ("bothDisabled", "floorpOnly", "vivaldiOnly", "bothEnabled")
    if not isinstance(combos, dict) or set(combos) != set(req_keys) or set(matrix) != {"schema", "combinations"}:
        return {"status": "INVALID", "reason": "MISSING_MATRIX_COMBINATIONS"}

    specs = {
        "bothDisabled": (False, False, [], []),
        "floorpOnly": (False, True, [EXPECTED_FLOORP["cask"]], [EXPECTED_FLOORP["claim"]]),
        "vivaldiOnly": (True, False, [EXPECTED_VIVALDI["cask"]], [EXPECTED_VIVALDI["claim"]]),
        "bothEnabled": (True, True, sorted([EXPECTED_FLOORP["cask"], EXPECTED_VIVALDI["cask"]]),
                        sorted([EXPECTED_FLOORP["claim"], EXPECTED_VIVALDI["claim"]])),
    }

    for name, (v_en, f_en, exp_casks, exp_claims) in specs.items():
        row = combos[name]
        if not isinstance(row, dict) or row.get("enabled") != {"vivaldi": v_en, "floorp": f_en} or any(
                type(v) is not bool for v in row.get("enabled", {}).values()):
            return {"status": "INVALID", "reason": f"ENABLED_MISMATCH_{name}"}
        if row.get("nativeMessagingHeld") is not True:
            return {"status": "INVALID", "reason": f"NATIVE_MESSAGING_NOT_HELD_{name}"}
        b_eq = row.get("baselineEqual")
        if not isinstance(b_eq, dict) or set(b_eq) != BASELINE_FIELDS or not all(v is True for v in b_eq.values()):
            return {"status": "INVALID", "reason": f"BASELINE_NOT_EQUAL_{name}"}
        if not isinstance(row.get("claimIds"), list) or any(type(v) is not str for v in row["claimIds"]) or sorted(row["claimIds"]) != exp_claims:
            return {"status": "INVALID", "reason": f"CLAIM_IDS_MISMATCH_{name}"}
        if not isinstance(row.get("selectedCasks"), list) or any(type(v) is not str for v in row["selectedCasks"]) or sorted(row["selectedCasks"]) != exp_casks:
            return {"status": "INVALID", "reason": f"CASKS_MISMATCH_{name}"}

        rend = row.get("rendering")
        if not isinstance(rend, dict) or set(rend) != {"floorp", "vivaldi"}:
            return {"status": "INVALID", "reason": f"RENDERING_MISSING_{name}"}

        for b, en in (("floorp", f_en), ("vivaldi", v_en)):
            b_rend = rend.get(b)
            if not en:
                if b_rend is not None:
                    return {"status": "INVALID", "reason": f"UNEXPECTED_RENDERING_{name}_{b}"}
            else:
                if not isinstance(b_rend, dict) or b_rend.get("browser") != b or b_rend.get("verdict") != "HOLD":
                    return {"status": "INVALID", "reason": f"MISSING_RENDERING_{name}_{b}"}
                act = b_rend.get("activation", {})
                if (not isinstance(act, dict) or act.get("hostPolicyDelivery") != "HELD" or act.get("replacementAuthorized") is not False
                        or act.get("liveProfileMigration") != "FORBIDDEN"):
                    return {"status": "INVALID", "reason": f"INVALID_ACTIVATION_FIELDS_{name}_{b}"}
                if act.get("status") != "HOLD_QUALIFICATION" or act.get("blockers") != []:
                    return {"status": "INVALID", "reason": f"INVALID_ACTIVATION_STATUS_OR_BLOCKERS_{name}_{b}"}
                if b_rend.get("runtimeHolds") != []:
                    return {"status": "INVALID", "reason": f"UNEXPECTED_CORE_RUNTIME_HOLDS_{name}_{b}"}

                cand = b_rend.get("replacementCandidate")
                exp_role = "chrome-replacement" if b == "vivaldi" else "firefox-replacement"
                if (not isinstance(cand, dict)
                        or cand.get("capability") != f"{b}-browser-core"
                        or cand.get("role") != exp_role
                        or cand.get("status") != "CANDIDATE"
                        or cand.get("qualification") != "READY_FOR_QUALIFICATION"):
                    return {"status": "INVALID", "reason": f"INVALID_REPLACEMENT_CANDIDATE_{name}_{b}"}

                overlays = b_rend.get("featureOverlays")
                if not isinstance(overlays, dict):
                    return {"status": "INVALID", "reason": f"INVALID_FEATURE_OVERLAYS_{name}_{b}"}

                if b == "floorp":
                    if overlays != {}:
                        return {"status": "INVALID", "reason": f"FLOORP_OVERLAYS_NOT_EMPTY_{name}"}
                elif b == "vivaldi":
                    mail_ov = overlays.get("mail")
                    if (not isinstance(mail_ov, dict)
                            or mail_ov.get("requested") is not False
                            or mail_ov.get("status") != "HOLD_RUNTIME_OOM"
                            or mail_ov.get("requiredForReplacement") is not False
                            or mail_ov.get("runtimeHolds") != [VIVALDI_CRASH_HOLD]
                            or set(overlays.keys()) != {"mail"}):
                        return {"status": "INVALID", "reason": f"VIVALDI_MAIL_OVERLAY_INVALID_{name}"}

    if any(combos[only]["rendering"][browser] != combos["bothEnabled"]["rendering"][browser]
           for browser, only in (("floorp", "floorpOnly"), ("vivaldi", "vivaldiOnly"))):
        return {"status": "INVALID", "reason": "COUPLED_BROWSER_RECORDS"}
    return {
        "status": "VALIDATED", "combinations": list(req_keys), "nativeMessagingHeld": True,
        "runtimeHolds": {"floorp": [], "vivaldi": []},
        "activationStatus": {"floorp": "HOLD_QUALIFICATION", "vivaldi": "HOLD_QUALIFICATION"},
        "featureOverlays": {
            "floorp": {},
            "vivaldi": {
                "mail": {
                    "requested": False,
                    "status": "HOLD_RUNTIME_OOM",
                    "requiredForReplacement": False,
                    "runtimeHolds": [VIVALDI_CRASH_HOLD],
                }
            },
        },
    }


def read_composition(composition_path: Path, host: str, runner=subprocess.run) -> dict:
    comp_resolved = Path(composition_path).resolve()
    expr = f"""
let
  comp = builtins.getFlake {nix_string('path:' + str(comp_resolved))};
  hostName = {nix_string(host)};
  hostConfig = comp.darwinConfigurations.${{hostName}}.config;
  cfg = hostConfig.homebrew;
  cleanup = cfg.onActivation.cleanup or "none";
  casks = cfg.casks or [];
  caskNames = builtins.map (c: if builtins.isAttrs c then c.name else c) casks;
  vivaldiCfg = hostConfig."browser-ux".configuration.replacements.vivaldi or {{}};
in {{
  cleanup = cleanup;
  vivaldiDeclared = builtins.elem "vivaldi" caskNames;
  floorpDeclared = builtins.elem "floorp" caskNames;
  vivaldiReplacementEnabled = vivaldiCfg.enable or false;
  vivaldiMailEnabled = vivaldiCfg.mail.enable or false;
}}
"""
    cmd = ["nix", "eval", "--json", "--no-write-lock-file", "--impure", "--expr", expr]
    try:
        res = runner(cmd, capture_output=True, text=True, check=False, timeout=TIMEOUTS["comp"])
        if res.returncode != 0:
            return {"status": "READ_FAILED", "cleanup": "UNKNOWN", "vivaldiDeclared": False, "floorpDeclared": False,
                    "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False}
        data = json.loads(res.stdout)
        if not isinstance(data, dict):
            raise ValueError("Invalid composition readback")
        required_keys = {"cleanup", "vivaldiDeclared", "floorpDeclared", "vivaldiReplacementEnabled"}
        if not required_keys.issubset(set(data)):
            raise ValueError("Missing keys in composition readback")
        if any(type(data.get(k)) is not bool for k in ("vivaldiDeclared", "floorpDeclared", "vivaldiReplacementEnabled")):
            raise ValueError("Invalid composition boolean")
        mail_en = data.get("vivaldiMailEnabled", False)
        if type(mail_en) is not bool:
            raise ValueError("Invalid vivaldiMailEnabled boolean")
        cleanup = data.get("cleanup") if data.get("cleanup") in ("none", "check", "uninstall", "zap") else "UNKNOWN"
        return {"status": "READ_SUCCESS", "cleanup": cleanup,
                "vivaldiDeclared": data["vivaldiDeclared"], "floorpDeclared": data["floorpDeclared"],
                "vivaldiReplacementEnabled": data["vivaldiReplacementEnabled"],
                "vivaldiMailEnabled": mail_en}
    except Exception:
        return {"status": "READ_ERROR", "cleanup": "UNKNOWN", "vivaldiDeclared": False, "floorpDeclared": False,
                "vivaldiReplacementEnabled": False, "vivaldiMailEnabled": False}


def read_homebrew(runner=subprocess.run) -> dict:
    brew_bin = "/opt/homebrew/bin/brew" if Path("/opt/homebrew/bin/brew").exists() else "/usr/local/bin/brew"
    if not Path(brew_bin).exists():
        return {"brewAvailable": False, "brewPath": None, "vivaldiManaged": False,
                "floorpManaged": False, "vivaldiVersion": None, "floorpVersion": None}

    # A complete successful listing proves absence. Named queries can return
    # nonzero for a missing cask and must never be mistaken for non-management.
    cmd = [brew_bin, "list", "--cask", "--versions"]
    try:
        res = runner(cmd, env=dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1"),
                     capture_output=True, text=True, check=False, timeout=TIMEOUTS["brew"])
        if res.returncode != 0:
            raise OSError("Homebrew readback failed")
        v_man, f_man, v_ver, f_ver = False, False, None, None
        for line in res.stdout.splitlines():
            toks = line.strip().split()
            if toks and toks[0] == "vivaldi":
                v_man, v_ver = True, sanitize_version(toks[1]) if len(toks) > 1 else None
            elif toks and toks[0] == "floorp":
                f_man, f_ver = True, sanitize_version(toks[1]) if len(toks) > 1 else None
        return {"brewAvailable": True, "brewPath": brew_bin, "vivaldiManaged": v_man,
                "floorpManaged": f_man, "vivaldiVersion": v_ver, "floorpVersion": f_ver}
    except Exception:
        return {"brewAvailable": False, "brewPath": brew_bin, "vivaldiManaged": False,
                "floorpManaged": False, "vivaldiVersion": None, "floorpVersion": None}


def analyze_retention_hazard(composition: dict | None, brew: dict | None, vivaldi_probe: dict, floorp_probe: dict) -> dict:
    v_absent = (vivaldi_probe.get("observation") == "ABSENT") if isinstance(vivaldi_probe, dict) else False
    f_absent = (floorp_probe.get("observation") == "ABSENT") if isinstance(floorp_probe, dict) else False

    if composition is None:
        return {
            "hazard": True, "status": "UNKNOWN_HAZARDOUS", "cleanup": "UNKNOWN",
            "vivaldiDeclared": False, "floorpDeclared": False,
            "reasons": ["NO_COMPOSITION_SPECIFIED"],
            "vivaldiRetentionHazard": True, "floorpRetentionHazard": True,
            "vivaldiPresence": "ABSENT" if v_absent else "PRESENT_OR_UNREADABLE",
            "floorpPresence": "ABSENT" if f_absent else "PRESENT_OR_UNREADABLE",
            "vivaldiManagement": "UNKNOWN", "floorpManagement": "UNKNOWN",
        }

    if composition.get("status") != "READ_SUCCESS":
        return {
            "hazard": True, "status": "UNKNOWN_HAZARDOUS", "cleanup": "UNKNOWN",
            "vivaldiDeclared": False, "floorpDeclared": False,
            "reasons": ["COMPOSITION_READ_FAILED"],
            "vivaldiRetentionHazard": True, "floorpRetentionHazard": True,
            "vivaldiPresence": "ABSENT" if v_absent else "PRESENT_OR_UNREADABLE",
            "floorpPresence": "ABSENT" if f_absent else "PRESENT_OR_UNREADABLE",
            "vivaldiManagement": "UNKNOWN", "floorpManagement": "UNKNOWN",
        }

    cleanup = composition.get("cleanup", "UNKNOWN")
    if cleanup not in ("none", "check", "uninstall", "zap"):
        return {
            "hazard": True, "status": "UNKNOWN_HAZARDOUS", "cleanup": "UNKNOWN",
            "vivaldiDeclared": False, "floorpDeclared": False,
            "reasons": ["CLEANUP_UNKNOWN"],
            "vivaldiRetentionHazard": True, "floorpRetentionHazard": True,
            "vivaldiPresence": "ABSENT" if v_absent else "PRESENT_OR_UNREADABLE",
            "floorpPresence": "ABSENT" if f_absent else "PRESENT_OR_UNREADABLE",
            "vivaldiManagement": "UNKNOWN", "floorpManagement": "UNKNOWN",
        }

    v_declared = composition.get("vivaldiDeclared", False)
    f_declared = composition.get("floorpDeclared", False)

    brew_checked = bool(brew and brew.get("brewAvailable"))
    v_brew = brew.get("vivaldiManaged", False) if brew_checked else None
    f_brew = brew.get("floorpManaged", False) if brew_checked else None

    hazards = []
    if cleanup in ("uninstall", "zap"):
        if not v_declared:
            if not (brew_checked and v_brew is False):
                hazards.append("VIVALDI_RETENTION_HAZARD_UNDECLARED_BREW_CLEANUP")
        if not f_declared:
            if not (brew_checked and f_brew is False):
                hazards.append("FLOORP_RETENTION_HAZARD_UNDECLARED_BREW_CLEANUP")

    has_hazard = len(hazards) > 0
    if has_hazard:
        status = "RETENTION_HAZARD_DETECTED"
    elif cleanup in ("uninstall", "zap") and not v_absent and not v_brew:
        status = "CONFIRMED_NON_BREW_MANAGED_PRESERVE_DATA"
    elif cleanup in ("none", "check"):
        status = "CLEANUP_NONE_APPROVED"
    else:
        status = "RETAINED_NO_HAZARD"

    has_vivaldi_hazard = any(r.startswith("VIVALDI_") or (not r.startswith("FLOORP_")) for r in hazards)
    has_floorp_hazard = any(r.startswith("FLOORP_") or (not r.startswith("VIVALDI_")) for r in hazards)

    return {
        "hazard": has_hazard, "status": status, "cleanup": cleanup,
        "vivaldiDeclared": v_declared, "floorpDeclared": f_declared, "reasons": hazards,
        "vivaldiRetentionHazard": has_vivaldi_hazard,
        "floorpRetentionHazard": has_floorp_hazard,
        "vivaldiPresence": "ABSENT" if v_absent else "PRESENT_OR_UNREADABLE",
        "floorpPresence": "ABSENT" if f_absent else "PRESENT_OR_UNREADABLE",
        "vivaldiManagement": "UNKNOWN" if v_brew is None else "HOMEBREW_MANAGED" if v_brew else "NON_HOMEBREW",
        "floorpManagement": "UNKNOWN" if f_brew is None else "HOMEBREW_MANAGED" if f_brew else "NON_HOMEBREW",
    }


def check_privacy_leaks(data_bytes: bytes, extra_forbidden: tuple[str, ...] = (), user: str = "") -> None:
    tokens = [t.encode() for t in (*PRIVATE_MARKERS, *extra_forbidden) if t]
    segment = re.compile(rb"/" + re.escape(user.encode()) + rb'(?=[/"\s\\]|$)') if user else None
    for t in tokens:
        if t in data_bytes:
            raise KitError("Private marker detected", code="PRIVACY_GUARD")
    if segment and segment.search(data_bytes):
        raise KitError("Private user segment detected", code="PRIVACY_GUARD")


def write_evidence_bundle(output_dir: Path, evidence: dict, extra_forbidden: tuple[str, ...] = (), user: str = "") -> tuple[str, str]:
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    json_raw = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    check_privacy_leaks(json_raw, extra_forbidden, user)
    (out_path / "HOST-QUALIFICATION-EVIDENCE.json").write_bytes(json_raw)

    members = {"HOST-QUALIFICATION-EVIDENCE.json": json_raw}
    manifest = "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(members.items())).encode("utf-8")
    check_privacy_leaks(manifest, extra_forbidden, user)
    members["MEMBERS.sha256"] = manifest

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name])

    zip_bytes = stream.getvalue()
    check_privacy_leaks(zip_bytes, extra_forbidden, user)
    (out_path / "HOST-QUALIFICATION-EVIDENCE.zip").write_bytes(zip_bytes)
    zip_sha = hashlib.sha256(zip_bytes).hexdigest()
    (out_path / "HOST-QUALIFICATION-EVIDENCE.zip.sha256").write_text(f"{zip_sha}  HOST-QUALIFICATION-EVIDENCE.zip\n")
    return "HOST-QUALIFICATION-EVIDENCE.json", zip_sha


def run_qualification(
    kit_root: Path,
    output_dir: Path,
    worktree: Path | None = None,
    composition: Path | None = None,
    host: str | None = None,
    homebrew_readback: bool = False,
    runner=subprocess.run,
    app_probe_runner=None,
    forbidden: tuple[str, ...] = (),
    user: str = "",
) -> tuple[dict, int]:
    kit_root = Path(kit_root).resolve()
    source_root = kit_root / "source"
    output_dir = Path(output_dir).resolve()
    require(output_dir.is_relative_to(kit_root / "evidence"), "Output must stay inside kit evidence directory", "UNSAFE_OUTPUT")
    require(not worktree or not output_dir.is_relative_to(Path(worktree).resolve()),
            "Output cannot modify the worktree", "UNSAFE_OUTPUT")
    probe_runner = app_probe_runner if app_probe_runner is not None else runner

    # 1. VERIFY BINDING (fail closed; zero subprocesses on mismatch)
    binding = verify_binding(kit_root, source_root)
    if binding["status"] == "BOUND" and worktree is not None:
        binding["worktree"] = verify_worktree(kit_root, Path(worktree), runner)
        if binding["worktree"]["status"] != "MATCH":
            binding["status"] = "BINDING_FAILED"
            binding["reason"] = "WORKTREE_DRIFT_OR_READ_FAILED"
    if binding["status"] != "BOUND":
        evidence = {
            "schema": SCHEMA_EVIDENCE, "status": "PENDING_MANAGER_REVIEW",
            "floorpOnlyEligibleForManagerReview": False,
            "vivaldiBrowserCoreEligibleForManagerReview": False,
            "vivaldiReplacement": "NOT_EVALUATED",
            "vivaldiBrowserCore": "NOT_EVALUATED",
            "vivaldiMail": "NOT_EVALUATED",
            "vivaldiMailConfiguration": {
                "status": "NOT_EVALUATED", "requested": None,
                "source": "COMPOSITION_CONFIG", "liveProfileRead": False,
                "activationAuthorized": False,
            },
            "binding": binding, "probes": {"floorp": None, "vivaldi": None},
            "checks": {"status": "NOT_RUN", "allPass": False, "items": []},
            "pins": {"status": "NOT_RUN", "cases": {}}, "matrix": {"status": "NOT_RUN"},
            "retention": {
                "hazard": True, "status": "NOT_RUN", "reasons": ["BINDING_FAILED"],
                "vivaldiRetentionHazard": True, "floorpRetentionHazard": True,
                "vivaldiPresence": "UNKNOWN", "floorpPresence": "UNKNOWN",
                "vivaldiManagement": "UNKNOWN", "floorpManagement": "UNKNOWN",
            },
            "sourceChecks": {"status": "NOT_RUN"},
        }
        write_evidence_bundle(output_dir, evidence, extra_forbidden=forbidden, user=user)
        return evidence, 1

    kit_data = json.loads((Path(kit_root) / "KIT.json").read_text())
    sealed_checks = kit_data.get("checks", [])
    inventory_data = json.loads((Path(kit_root) / "SOURCE-INVENTORY.json").read_text())
    file_names = list(inventory_data.get("entries", {}).keys())

    probes = probe_applications(runner=probe_runner)
    source_checks = run_source_checks(source_root, file_names, runner=runner, worktree=worktree)
    flake_checks = run_flake_checks(source_root, sealed_checks, runner=runner)
    pins_result = evaluate_baseline_pins(source_root, runner=runner)
    matrix_result = evaluate_activation_matrix(source_root, runner=runner)

    comp_info = read_composition(composition, host, runner=runner) if (composition and host) else None
    brew_info = read_homebrew(runner=runner) if homebrew_readback else None
    retention_result = analyze_retention_hazard(comp_info, brew_info, probes["vivaldi"], probes["floorp"])
    # Rebind after the host checks: evaluation/builds must not mutate source.
    final_binding = verify_binding(kit_root, source_root)
    source_stable = final_binding["status"] == "BOUND" and (
        worktree is None or verify_worktree(kit_root, Path(worktree), runner)["status"] == "MATCH")

    shared_retention_hazard = any(
        not r.startswith("VIVALDI_") and not r.startswith("FLOORP_")
        for r in retention_result.get("reasons", [])
    )
    shared_prerequisites = bool(
        source_stable and
        (flake_checks.get("allPass") is True) and
        (pins_result.get("status") == "PASS") and
        (matrix_result.get("status") == "VALIDATED") and
        (source_checks.get("status") == "CLEAN") and
        not shared_retention_hazard
    )

    floorp_eligible = bool(
        shared_prerequisites and
        (probes["floorp"].get("verdict") == "MATCH") and
        (retention_result.get("floorpRetentionHazard") is False)
    )

    vivaldi_core_eligible = bool(
        shared_prerequisites and
        (probes["vivaldi"].get("verdict") == "MATCH") and
        (retention_result.get("vivaldiRetentionHazard") is False)
    )

    eligible_for_exit0 = bool(shared_prerequisites and (floorp_eligible or vivaldi_core_eligible))

    evidence = {
        "schema": SCHEMA_EVIDENCE, "status": "PENDING_MANAGER_REVIEW",
        "floorpOnlyEligibleForManagerReview": floorp_eligible,
        "vivaldiBrowserCoreEligibleForManagerReview": vivaldi_core_eligible,
        "vivaldiReplacement": "CANDIDATE_READY_FOR_QUALIFICATION",
        "vivaldiBrowserCore": "CANDIDATE_READY_FOR_QUALIFICATION",
        "vivaldiMail": "HOLD_RUNTIME_OOM",
        # Composition configuration is not a live-profile observation or an
        # application-retention hazard. Mail never gates core eligibility and
        # this runner cannot authorize its separate qualification/activation.
        "vivaldiMailConfiguration": {
            "status": comp_info["status"] if comp_info else "NOT_EVALUATED",
            "requested": comp_info["vivaldiMailEnabled"]
                if comp_info and comp_info["status"] == "READ_SUCCESS" else None,
            "source": "COMPOSITION_CONFIG", "liveProfileRead": False,
            "activationAuthorized": False,
        },
        "binding": binding, "probes": probes, "checks": flake_checks,
        "pins": pins_result, "matrix": matrix_result, "retention": retention_result,
        "sourceChecks": source_checks,
        "sourceStableAfterChecks": source_stable,
    }

    write_evidence_bundle(output_dir, evidence, extra_forbidden=forbidden, user=user)
    return evidence, 0 if eligible_for_exit0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_p = subparsers.add_parser("run")
    run_p.add_argument("--kit-root", type=Path, required=True, help="Directory with KIT.json & SOURCE-INVENTORY.json")
    run_p.add_argument("--output", type=Path, required=True, help="Output evidence directory")
    run_p.add_argument("--worktree", type=Path, default=None, help="Path to source root/worktree")
    run_p.add_argument("--composition", type=Path, default=None, help="Path to composition flake/nix")
    run_p.add_argument("--host", type=str, default=None, help="Host name in darwinConfigurations")
    run_p.add_argument("--homebrew-readback", action="store_true", help="Perform read-only Homebrew readback")
    return parser


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
        sys.argv.insert(1, "run")
    args = build_parser().parse_args()
    try:
        if bool(args.composition) != bool(args.host):
            raise KitError("Composition and host must be provided together", "INVALID_ARGUMENTS")
        if args.command == "run":
            _, code = run_qualification(
                kit_root=args.kit_root, output_dir=args.output, worktree=args.worktree,
                composition=args.composition, host=args.host, homebrew_readback=args.homebrew_readback,
            )
            return code
    except (KitError, OSError, ValueError) as error:
        print(json.dumps({"status": "FAILED", "reason": error.code if isinstance(error, KitError) else "READ_OR_OUTPUT_ERROR"}))
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
