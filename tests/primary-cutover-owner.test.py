"""Portable Nix evaluator and disposable writer fixtures; never applies host policy or touches live paths."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "delivery"))
import rollout


def require(condition: bool, message: str = "requirement failed") -> None:
    if not condition:
        raise AssertionError(message)


def nix_eval(expr: str):
    proc = subprocess.run(
        ["nix", "eval", "--impure", "--offline", "--json", "--expr", expr],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr or proc.stdout)
    return json.loads(proc.stdout)


def nix_eval_failure(expr: str) -> str:
    proc = subprocess.run(
        ["nix", "eval", "--impure", "--offline", "--json", "--expr", expr],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        proc.returncode != 0,
        f"expected nix eval to fail, but it succeeded with stdout: {proc.stdout!r}",
    )
    return proc.stderr


# Self-consistency only: the preimage is reconstructed from the patch's own hunks
# with placeholder lines for elided context, so this does not authenticate historical
# upstream flake.nix bytes against delivery/composition/SOURCE.json.
def synthesize_preimage_from_patch(patch_text: str, target_relpath: str) -> str:
    lines: list[str] = []
    in_file = False
    for raw_line in patch_text.splitlines():
        if raw_line.startswith("+++ "):
            in_file = raw_line == f"+++ b/{target_relpath}"
            continue
        if raw_line.startswith("--- "):
            in_file = False
            continue
        if not in_file:
            continue
        hunk_match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", raw_line)
        if hunk_match:
            old_start = int(hunk_match.group(1))
            while len(lines) < old_start - 1:
                lines.append(f"# context placeholder line {len(lines) + 1}")
            continue
        if raw_line.startswith(("-", " ")):
            lines.append(raw_line[1:])
    lines.extend(["# trailing context line 1", "# trailing context line 2", "# trailing context line 3"])
    return "\n".join(lines) + "\n"


def _verify_fixture_root(root: Path) -> Path:
    resolved_root = root.resolve()
    require(
        resolved_root == root and resolved_root.is_absolute(),
        f"fixture root must be a resolved absolute path: {root}",
    )
    for forbidden_live_prefix in ("/Library/", "/Applications/", str(Path.home().resolve()) + "/"):
        require(
            not str(resolved_root).startswith(forbidden_live_prefix),
            f"fixture root must not point into live host path: {resolved_root}",
        )
    if os.environ.get("TMPDIR"):
        tmpdir_resolved = Path(os.environ["TMPDIR"]).resolve()
        require(
            resolved_root.is_relative_to(tmpdir_resolved),
            f"fixture root {resolved_root} is not inside TMPDIR {tmpdir_resolved}",
        )
    return resolved_root


def _substitute_primary_home_before_library(text: str, resolved_root: Path) -> str:
    return (
        text.replace("/__PRIMARY_HOME__/Library/", "/__PRIMARY_HOME_LIB__/")
        .replace("/Library/", f"{resolved_root}/Library/")
        .replace("/Applications/", f"{resolved_root}/Applications/")
        .replace("/__PRIMARY_HOME_LIB__/", f"{resolved_root}/Users/fixture/Library/")
        .replace("/__PRIMARY_HOME__", str(resolved_root / "Users/fixture"))
    )


def rewrite_target_hermetic(target_path: str, root: Path) -> str:
    resolved_root = _verify_fixture_root(root)
    rewritten = _substitute_primary_home_before_library(target_path, resolved_root)
    rewritten_path = Path(rewritten)
    require(
        rewritten_path.is_absolute()
        and rewritten.startswith(str(resolved_root) + "/")
        and rewritten_path.resolve().is_relative_to(resolved_root),
        f"rewritten target escaped fixture root {resolved_root}: {rewritten}",
    )
    return rewritten


def rewrite_hermetic(script: str, root: Path) -> str:
    resolved_root = _verify_fixture_root(root)
    rewritten = (
        _substitute_primary_home_before_library(script, resolved_root)
        .replace('test "$(id -u)" -eq 0', "true")
        .replace("install -o root -g wheel ", "install ")
    )
    filtered_lines = []
    for line in rewritten.splitlines():
        stripped = line.strip()
        if stripped.startswith(("chown ", "killall ", "defaults ")):
            continue
        filtered_lines.append(line)
    final_script = "\n".join(filtered_lines) + "\n"
    for forbidden in ("sudo", "launchctl", "defaults", "killall", "profiles", "chown", "chgrp"):
        require(
            re.search(rf"\b{forbidden}\b", final_script) is None,
            f"un-stubbed host command {forbidden} in script",
        )
    for raw_path in re.findall(r"(?<![A-Za-z0-9_./-])/(?:Library|Applications|Users)/[^\s\"';]+", final_script):
        require(
            raw_path.startswith(str(resolved_root) + "/"),
            f"escaped absolute path in script: {raw_path}",
        )
    return final_script


def evaluate_core_fixture(root: Path, payloads: Path):
    ext_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "a"
    nmh_name = "org.keepassxc.keepassxc_browser"
    stage = root / "stage"
    (stage / "modules").mkdir(parents=True, exist_ok=True)
    if not (stage / "config").exists():
        shutil.copytree(ROOT / "config", stage / "config")
    (stage / "config/browser/chrome-policy.plist").write_text(
        '<plist version="1.0"><dict/></plist>\n'
    )
    shutil.copy2(ROOT / "delivery/core/modules-browsers.nix", stage / "modules/browsers.nix")

    payloads.mkdir(parents=True, exist_ok=True)
    ext_file = payloads / "ext.json"
    ext_file.write_text('{"external_update_url":"https://clients2.google.com/service/update2/crx"}\n')
    nmh_file = payloads / "nmh.json"
    nmh_file.write_text('{"name":"org.keepassxc.keepassxc_browser"}\n')

    evaluated = nix_eval(
        f"""
        let
          flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
          lib = flake.inputs.nixpkgs.lib;
          coreModule = import {json.dumps(str(stage / "modules/browsers.nix"))};
          payloadDir = {json.dumps(str(payloads))};
          stubPkgs = {{
            inherit lib;
            writeText = name: text:
              let p = "${{payloadDir}}/${{name}}";
              in {{ inherit text; __toString = _: p; }};
            writeShellScript = name: text: {{ inherit name text; __toString = _: name; }};
            google-chrome = "/nix/store/stub-google-chrome";
          }};
          stubModule = {{
            options = {{
              system.primaryUser = lib.mkOption {{ type = lib.types.str; default = "fixture"; }};
              users.users = lib.mkOption {{
                type = lib.types.attrsOf lib.types.anything;
                default.fixture.home = "/__PRIMARY_HOME__";
              }};
              assertions = lib.mkOption {{ type = lib.types.listOf lib.types.anything; default = []; }};
              environment.systemPackages = lib.mkOption {{ type = lib.types.listOf lib.types.anything; default = []; }};
              homebrew.casks = lib.mkOption {{ type = lib.types.listOf lib.types.str; default = []; }};
              system.build = lib.mkOption {{ type = lib.types.attrsOf lib.types.anything; default = {{}}; }};
              system.activationScripts = lib.mkOption {{
                type = lib.types.attrsOf (lib.types.submodule {{
                  options.text = lib.mkOption {{ type = lib.types.lines; default = ""; }};
                }});
                default = {{}};
              }};
            }};
          }};
          evalWith = extra: (lib.evalModules {{
            specialArgs = {{ pkgs = stubPkgs; }};
            modules = [ coreModule stubModule extra ];
          }}).config;
          configured = evalWith {{
            programs.browserBaseline = {{
              legacyPolicyDefaults.enable = false;
              replacementPolicyOwnership = true;
              chrome.managedPreferences = {{ BlockThirdPartyCookies = true; }};
              chrome.externalExtensions."{ext_id}" = /. + {json.dumps(str(ext_file))};
              chrome.nativeMessagingHosts."{nmh_name}" = /. + {json.dumps(str(nmh_file))};
              firefox.policyDelivery = "macos-preferences";
              firefox.policies = {{ DisableTelemetry = true; }};
              firefox.nativeMessagingHosts."{nmh_name}" = /. + {json.dumps(str(nmh_file))};
              vivaldi.managedPreferences = {{ BlockThirdPartyCookies = true; }};
              vivaldi.externalExtensions."{ext_id}" = /. + {json.dumps(str(ext_file))};
              vivaldi.nativeMessagingHosts."{nmh_name}" = /. + {json.dumps(str(nmh_file))};
              floorp.policies = {{ DisableTelemetry = true; }};
            }};
          }};
          retracted = evalWith {{
            programs.browserBaseline = {{
              legacyPolicyDefaults.enable = false;
              replacementPolicyOwnership = true;
            }};
          }};
          bb = configured.system.build.browserBaseline;
        in {{
          guardViolations = bb.guardViolations;
          plists = {{
            "com.google.Chrome.plist" = bb.chromeManagedPlist.text;
            "org.mozilla.firefox.plist" = bb.firefoxManagedPlist.text;
            "com.vivaldi.Vivaldi.plist" = bb.vivaldiManagedPlist.text;
            "app.floorp.Floorp.plist" = bb.floorpManagedPlist.text;
          }};
          attendedTargets = map (r: {{
            inherit (r) target;
            source = toString r.source;
            perUser = r.perUser or false;
          }}) bb.attendedTargets;
          targetsByBrowser = lib.mapAttrs (_: rows: map (r: r.target) rows) bb.attendedTargetsByBrowser;
          scriptsByBrowser = lib.mapAttrs (_: v: v.text) bb.attendedApplyByBrowser;
          attendedApply = bb.attendedApply.text;
          retractedPostActivation = retracted.system.activationScripts.postActivation.text;
        }}
        """
    )
    require(evaluated["guardViolations"] == [])
    for name, text in evaluated["plists"].items():
        (payloads / name).write_text(text)
    return evaluated, ext_id, nmh_name


class OwnerContracts(unittest.TestCase):
    def test_patch_artifacts_apply_cleanly_to_staged_fixtures(self):
        core_source_meta = json.loads((ROOT / "delivery/core/SOURCE.json").read_text())
        comp_source_meta = json.loads((ROOT / "delivery/composition/SOURCE.json").read_text())

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ceiling_env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(base)}

            # 1. delivery/core/browsers.patch against delivery/core/modules-browsers.nix
            core_stage = base / "core"
            (core_stage / "modules").mkdir(parents=True)
            core_patch = (ROOT / "delivery/core/browsers.patch").resolve()
            core_post_bytes = (ROOT / "delivery/core/modules-browsers.nix").read_bytes()
            require(
                hashlib.sha256(core_post_bytes).hexdigest()
                == core_source_meta["candidate"]["moduleSha256"],
                "core candidate moduleSha256 mismatch",
            )
            require(
                hashlib.sha256(core_patch.read_bytes()).hexdigest()
                == core_source_meta["candidate"]["patchSha256"],
                "core candidate patchSha256 mismatch",
            )
            staged_core = core_stage / "modules/browsers.nix"
            staged_core.write_bytes(core_post_bytes)

            numstat = subprocess.run(
                ["git", "apply", "--numstat", str(core_patch)],
                cwd=core_stage,
                env=ceiling_env,
                text=True,
                capture_output=True,
                check=True,
            )
            require(
                [line.split("\t")[-1] for line in numstat.stdout.strip().splitlines()]
                == ["modules/browsers.nix"],
                f"unexpected browsers.patch target paths: {numstat.stdout!r}",
            )
            subprocess.run(
                ["git", "apply", "-R", "--check", str(core_patch)],
                cwd=core_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", "-R", str(core_patch)],
                cwd=core_stage,
                env=ceiling_env,
                check=True,
            )
            core_pre_bytes = staged_core.read_bytes()
            require(core_pre_bytes != core_post_bytes, "reverse patch did not change modules/browsers.nix")
            require(
                hashlib.sha256(core_pre_bytes).hexdigest()
                == core_source_meta["original"]["sha256"],
                "reverse-patched modules/browsers.nix sha256 mismatch with core SOURCE.json",
            )
            core_pre_text = core_pre_bytes.decode("utf-8")
            require("vivaldi =" not in core_pre_text and "floorp =" not in core_pre_text)

            subprocess.run(
                ["git", "apply", "--check", str(core_patch)],
                cwd=core_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", str(core_patch)],
                cwd=core_stage,
                env=ceiling_env,
                check=True,
            )
            require(staged_core.read_bytes() == core_post_bytes, "forward patch did not reproduce modules-browsers.nix")

            # 2. delivery/composition/browser-ux.toml.patch against browser-ux.toml preimage
            toml_stage = base / "toml"
            toml_stage.mkdir(parents=True)
            toml_patch = (ROOT / "delivery/composition/browser-ux.toml.patch").resolve()
            toml_pre_bytes = b"[browser-ux]\nschema = 1\n\n[browser-ux.keepassxc]\nenable = true\n"
            toml_post_bytes = (ROOT / "delivery/composition/browser-ux.toml").read_bytes()
            require(
                hashlib.sha256(toml_pre_bytes).hexdigest()
                == comp_source_meta["originalFiles"]["localConfig/browser-ux.toml"],
                "preimage localConfig/browser-ux.toml hash mismatch",
            )
            require(
                hashlib.sha256(toml_post_bytes).hexdigest()
                == comp_source_meta["candidateLocalConfigSha256"],
                "postimage delivery/composition/browser-ux.toml hash mismatch",
            )
            require(
                hashlib.sha256(toml_patch.read_bytes()).hexdigest()
                == comp_source_meta["patches"]["browser-ux.toml.patch"],
                "browser-ux.toml.patch hash mismatch",
            )
            require(toml_pre_bytes != toml_post_bytes)
            staged_toml = toml_stage / "browser-ux.toml"
            staged_toml.write_bytes(toml_pre_bytes)

            toml_numstat = subprocess.run(
                ["git", "apply", "--numstat", str(toml_patch)],
                cwd=toml_stage,
                env=ceiling_env,
                text=True,
                capture_output=True,
                check=True,
            )
            require(
                [line.split("\t")[-1] for line in toml_numstat.stdout.strip().splitlines()]
                == ["browser-ux.toml"],
                f"unexpected browser-ux.toml.patch target paths: {toml_numstat.stdout!r}",
            )
            subprocess.run(
                ["git", "apply", "--check", str(toml_patch)],
                cwd=toml_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", str(toml_patch)],
                cwd=toml_stage,
                env=ceiling_env,
                check=True,
            )
            require(staged_toml.read_bytes() == toml_post_bytes, "toml patch did not produce delivery/composition/browser-ux.toml")
            subprocess.run(
                ["git", "apply", "-R", "--check", str(toml_patch)],
                cwd=toml_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", "-R", str(toml_patch)],
                cwd=toml_stage,
                env=ceiling_env,
                check=True,
            )
            require(staged_toml.read_bytes() == toml_pre_bytes, "reverse toml patch did not restore preimage")

            # 3. delivery/composition/composition.patch against synthetic composition preimage
            comp_stage = base / "composition"
            comp_stage.mkdir(parents=True)
            comp_patch = (ROOT / "delivery/composition/composition.patch").resolve()
            require(
                hashlib.sha256(comp_patch.read_bytes()).hexdigest()
                == comp_source_meta["patches"]["composition.patch"],
                "composition.patch hash mismatch",
            )
            comp_patch_text = comp_patch.read_text()
            # Self-consistency only: reconstructed from patch hunks with placeholder lines,
            # not an authentication of historical upstream flake.nix bytes.
            flake_pre = synthesize_preimage_from_patch(comp_patch_text, "flake.nix")
            (comp_stage / "flake.nix").write_text(flake_pre)
            require("browser-ux-host-selection.nix" not in flake_pre)
            require(not (comp_stage / "lib/browser-ux-host-selection.nix").exists())

            comp_numstat = subprocess.run(
                ["git", "apply", "--numstat", str(comp_patch)],
                cwd=comp_stage,
                env=ceiling_env,
                text=True,
                capture_output=True,
                check=True,
            )
            require(
                [line.split("\t")[-1] for line in comp_numstat.stdout.strip().splitlines()]
                == ["flake.nix", "lib/browser-ux-host-selection.nix"],
                f"unexpected composition.patch target paths: {comp_numstat.stdout!r}",
            )
            subprocess.run(
                ["git", "apply", "--check", str(comp_patch)],
                cwd=comp_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", str(comp_patch)],
                cwd=comp_stage,
                env=ceiling_env,
                check=True,
            )
            flake_post = (comp_stage / "flake.nix").read_text()
            selector_post_bytes = (comp_stage / "lib/browser-ux-host-selection.nix").read_bytes()
            require("browser-ux-host-selection.nix" in flake_post)
            require("browserHostSelection.moduleForHost hostName moduleConfiguration" in flake_post)
            require("browserHostSelection.casksForHost hostName moduleConfiguration" in flake_post)
            require("browserHostSelection.claimAppliesToHost host" in flake_post)
            require(
                selector_post_bytes == (ROOT / "delivery/composition/browser-ux-host-selection.nix").read_bytes(),
                "patched lib/browser-ux-host-selection.nix differs from committed selector",
            )
            require(
                hashlib.sha256(selector_post_bytes).hexdigest()
                == comp_source_meta["candidateFiles"]["lib/browser-ux-host-selection.nix"],
                "patched lib/browser-ux-host-selection.nix sha256 mismatch",
            )
            subprocess.run(
                ["git", "apply", "-R", "--check", str(comp_patch)],
                cwd=comp_stage,
                env=ceiling_env,
                check=True,
            )
            subprocess.run(
                ["git", "apply", "-R", str(comp_patch)],
                cwd=comp_stage,
                env=ceiling_env,
                check=True,
            )
            require((comp_stage / "flake.nix").read_text() == flake_pre)
            require(not (comp_stage / "lib/browser-ux-host-selection.nix").exists())

    def test_core_delivery_and_matched_contracts_evaluate_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ceiling_env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(base)}
            core_stage = base / "core"
            cand_stage = base / "cand"
            matched_stage = base / "matched"
            for stage in (core_stage, cand_stage, matched_stage):
                (stage / "modules").mkdir(parents=True)
                shutil.copytree(ROOT / "config", stage / "config")
                (stage / "config/browser/chrome-policy.plist").write_text(
                    '<plist version="1.0"><dict/></plist>\n'
                )
                shutil.copy2(ROOT / "delivery/core/modules-browsers.nix", stage / "modules/browsers.nix")

            subprocess.run(
                ["git", "apply", "-R", str((ROOT / "delivery/core/browsers.patch").resolve())],
                cwd=core_stage,
                env=ceiling_env,
                check=True,
            )

            # Bridge the 3 primary-cutover seam options set by modules/default.nix onto the pre-cutover core snapshot
            (matched_stage / "modules/real-browsers.nix").write_bytes(
                (ROOT / "delivery/core/modules-browsers.nix").read_bytes()
            )
            (matched_stage / "modules/browsers.nix").write_text(
                """{ config, lib, pkgs, ... }@args:
let base = import ./real-browsers.nix args;
in base // {
  options = base.options // {
    programs = base.options.programs // {
      browserBaseline = base.options.programs.browserBaseline // {
        vivaldiPolicyOwnership = lib.mkOption { type = lib.types.bool; default = false; };
        chrome = base.options.programs.browserBaseline.chrome // {
          enable = lib.mkOption { type = lib.types.bool; default = true; };
        };
        firefox = base.options.programs.browserBaseline.firefox // {
          enable = lib.mkOption { type = lib.types.bool; default = true; };
        };
      };
    };
  };
}
"""
            )

            result = nix_eval(
                f"""
                let
                  flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
                  pkgs = flake.inputs.nixpkgs.legacyPackages.${{builtins.currentSystem}};
                  coreContracts = import {json.dumps(str(ROOT / "tests/core-delivery-contracts.nix"))} {{
                    lib = pkgs.lib;
                    coreRoot = /. + {json.dumps(str(core_stage))};
                    candidateRoot = /. + {json.dumps(str(cand_stage))};
                  }};
                  coreTests = pkgs.lib.filterAttrs (n: _: pkgs.lib.hasPrefix "test" n) coreContracts;
                  matched = import {json.dumps(str(ROOT / "tests/matched-delivery-contracts.nix"))} {{
                    lib = pkgs.lib;
                    candidateRoot = /. + {json.dumps(str(matched_stage))};
                  }};
                in {{
                  coreTests = pkgs.lib.mapAttrs (_: v: builtins.deepSeq v v) coreTests;
                  matchedStatus = builtins.deepSeq matched matched.status;
                  matchedTargetCount = matched.targetCount;
                  matchedBrowsers = builtins.attrNames matched.browserPolicies;
                }}
                """
            )
            require(len(result["coreTests"]) == 15, f"expected 15 core test attrs, got {len(result['coreTests'])}")
            for name, passed in result["coreTests"].items():
                require(passed is True, f"core-delivery-contracts {name} failed")
            require(result["matchedStatus"] == "MATCHED_SOURCE_FIXTURES_PASS")
            require(result["matchedTargetCount"] == 8)
            require(result["matchedBrowsers"] == ["chrome", "firefox", "floorp", "vivaldi"])

    def test_composition_host_selection_and_shared_toml_contracts(self):
        result = nix_eval(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              selection = import {json.dumps(str(ROOT / "delivery/composition/browser-ux-host-selection.nix"))} {{ inherit lib; }};
              shared = {{
                browser-ux.configuration = (builtins.fromTOML (builtins.readFile {json.dumps(str(ROOT / "delivery/composition/browser-ux.toml"))})).browser-ux;
              }};
              extraSeam = {{ lib, ... }}: {{
                options.networking.hostName = lib.mkOption {{ type = lib.types.str; }};
                options.programs.browserBaseline.replacementPolicyOwnership = lib.mkOption {{ type = lib.types.bool; default = false; }};
                options.programs.browserBaseline.vivaldi = lib.mkOption {{ type = lib.types.attrsOf lib.types.anything; default = {{}}; }};
                options.programs.browserBaseline.floorp = lib.mkOption {{ type = lib.types.attrsOf lib.types.anything; default = {{}}; }};
              }};
              evalHost = host: (lib.evalModules {{
                modules = [
                  {json.dumps(str(ROOT / "tests/seam-fixture.nix"))}
                  extraSeam
                  {json.dumps(str(ROOT / "modules/default.nix"))}
                  (selection.moduleForHost host shared)
                  {{ networking.hostName = host; }}
                ];
              }}).config;
              current = evalHost "example-current-mac";
              previous = evalHost "example-previous-mac";
              other = evalHost "unselected-mac";
              previousProjection = selection.moduleForHost "example-previous-mac" shared;
              cutoverKeepass = (lib.evalModules {{
                modules = [
                  {json.dumps(str(ROOT / "tests/seam-fixture.nix"))}
                  extraSeam
                  {json.dumps(str(ROOT / "modules/default.nix"))}
                  {{
                    networking.hostName = "example-current-mac";
                    "browser-ux".configuration = {{
                      schema = 1;
                      keepassxc.enable = true;
                      replacements = {{
                        vivaldi.enable = true;
                        floorp.enable = true;
                      }};
                      primaryCutover = {{
                        enable = true;
                        activeBrowsers = [ "vivaldi" "floorp" "safari" ];
                        retiredBrowsers = [ "chrome" "firefox" ];
                        credentialProvider = "keepassxc";
                        productivityIntent = "feeds-only";
                        protonVpnEnabled = true;
                      }};
                    }};
                  }}
                ];
              }}).config;
            in {{
              currentCasks = selection.casksForHost "example-current-mac" shared;
              previousCasks = selection.casksForHost "example-previous-mac" shared;
              otherCasks = selection.casksForHost "unselected-mac" shared;
              previousProjectedConfig = previousProjection."browser-ux".configuration;
              currentOwnership = current.programs.browserBaseline.replacementPolicyOwnership;
              previousOwnership = previous.programs.browserBaseline.replacementPolicyOwnership;
              otherOwnership = other.programs.browserBaseline.replacementPolicyOwnership;
              currentMail = current.browser-ux.configuration.replacements.vivaldi.mail.enable;
              previousMail = previous.browser-ux.configuration.replacements.vivaldi.mail.enable;
              currentTrial = current.browser-ux.configuration.extensions.apple-proton-trial.enable;
              previousTrial = previous.browser-ux.configuration.extensions.apple-proton-trial.enable;
              currentClaimsCount = builtins.length current.browser-ux.replacementApplicationClaims;
              previousClaimsCount = builtins.length previous.browser-ux.replacementApplicationClaims;
              otherClaimsCount = builtins.length other.browser-ux.replacementApplicationClaims;
              claimChecks = {{
                vivaldiOnCurrent = selection.claimAppliesToHost "example-current-mac" {{ owner = "browser-ux"; claim.id = "bundle:com.vivaldi.Vivaldi"; }};
                floorpOnCurrent = selection.claimAppliesToHost "example-current-mac" {{ owner = "browser-ux"; claim.id = "bundle:app.floorp.Floorp"; }};
                vivaldiOnPrevious = selection.claimAppliesToHost "example-previous-mac" {{ owner = "browser-ux"; claim.id = "bundle:com.vivaldi.Vivaldi"; }};
                floorpOnPrevious = selection.claimAppliesToHost "example-previous-mac" {{ owner = "browser-ux"; claim.id = "bundle:app.floorp.Floorp"; }};
                otherOwnerOnPrevious = selection.claimAppliesToHost "example-previous-mac" {{ owner = "core"; claim.id = "bundle:com.vivaldi.Vivaldi"; }};
              }};
              cutoverKeepassRetirement = {{
                chromeEnable = cutoverKeepass.programs.browserBaseline.chrome.enable;
                firefoxEnable = cutoverKeepass.programs.browserBaseline.firefox.enable;
                firefoxNmhKeys = builtins.attrNames cutoverKeepass.programs.browserBaseline.firefox.nativeMessagingHosts;
                floorpRendered = cutoverKeepass."browser-ux".replacementRendering.floorp != null;
              }};
            }}
            """
        )
        require(result["currentCasks"] == ["vivaldi", "floorp"])
        require(result["previousCasks"] == [])
        require(result["otherCasks"] == [])
        prev_proj = result["previousProjectedConfig"]
        require("primaryCutover" not in prev_proj)
        require("replacements" not in prev_proj)
        require("apple-proton-trial" not in prev_proj.get("extensions", {}))
        require(prev_proj["keepassxc"]["enable"] is True)
        require(result["currentOwnership"] is True)
        require(result["previousOwnership"] is False)
        require(result["otherOwnership"] is False)
        require(result["currentMail"] is True and result["previousMail"] is False)
        require(result["currentTrial"] is True and result["previousTrial"] is False)
        require(result["currentClaimsCount"] == 2)
        require(result["previousClaimsCount"] == 0 and result["otherClaimsCount"] == 0)
        require(
            result["claimChecks"]
            == {
                "vivaldiOnCurrent": True,
                "floorpOnCurrent": True,
                "vivaldiOnPrevious": False,
                "floorpOnPrevious": False,
                "otherOwnerOnPrevious": True,
            }
        )
        require(
            result["cutoverKeepassRetirement"]
            == {
                "chromeEnable": False,
                "firefoxEnable": False,
                "firefoxNmhKeys": ["org.keepassxc.keepassxc_browser"],
                "floorpRendered": True,
            }
        )

    def test_attended_apply_and_retraction_fixture_hermetic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            payloads = root / "payloads"
            evaluated, ext_id, nmh_name = evaluate_core_fixture(root, payloads)

            attended_script = rewrite_hermetic(evaluated["attendedApply"], root)
            retracted_script = rewrite_hermetic(evaluated["retractedPostActivation"], root)

            subprocess.run(["/bin/sh", "-eu", "-c", attended_script], cwd=root, check=True)
            expected_targets = [
                root / "Library/Managed Preferences/com.google.Chrome.plist",
                root / "Library/Preferences/org.mozilla.firefox.plist",
                root / "Library/Managed Preferences/com.vivaldi.Vivaldi.plist",
                root / "Library/Preferences/app.floorp.Floorp.plist",
                root / f"Library/Application Support/Google/Chrome/External Extensions/{ext_id}.json",
                root / f"Library/Application Support/Vivaldi/External Extensions/{ext_id}.json",
                root / f"Library/Google/Chrome/NativeMessagingHosts/{nmh_name}.json",
                root / f"Library/Application Support/Mozilla/NativeMessagingHosts/{nmh_name}.json",
                root / f"Users/fixture/Library/Application Support/Vivaldi/NativeMessagingHosts/{nmh_name}.json",
            ]
            for target in expected_targets:
                require(target.is_file(), f"missing attended target: {target}")

            # Re-run attended apply to prove idempotence
            subprocess.run(["/bin/sh", "-eu", "-c", attended_script], cwd=root, check=True)
            for target in expected_targets:
                require(target.is_file(), f"missing attended target after idempotent rerun: {target}")

            # Seed seam-owned external extension IDs for retraction check
            seam_ext = "felphkbfjadmcejnibcmcncimlappdde"
            chrome_seam_ext = root / f"Library/Application Support/Google/Chrome/External Extensions/{seam_ext}.json"
            vivaldi_seam_ext = root / f"Library/Application Support/Vivaldi/External Extensions/{seam_ext}.json"
            chrome_seam_ext.write_text("{}\n")
            vivaldi_seam_ext.write_text("{}\n")

            retracted_targets = (
                root / "Library/Managed Preferences/com.google.Chrome.plist",
                root / "Library/Preferences/org.mozilla.firefox.plist",
                root / "Library/Managed Preferences/com.vivaldi.Vivaldi.plist",
                root / "Library/Preferences/app.floorp.Floorp.plist",
                chrome_seam_ext,
                vivaldi_seam_ext,
            )
            vivaldi_user_nmh = (
                root / f"Users/fixture/Library/Application Support/Vivaldi/NativeMessagingHosts/{nmh_name}.json"
            )

            subprocess.run(["/bin/sh", "-eu", "-c", retracted_script], cwd=root, check=True)
            for retracted_target in retracted_targets:
                require(not retracted_target.exists(), f"expected retracted target to be removed: {retracted_target}")
            # Vivaldi per-user KeePassXC native host registration is outside replacementPolicyOwnership retraction
            require(vivaldi_user_nmh.is_file())

            # Re-run retracted postActivation a second time to prove idempotent removal
            subprocess.run(["/bin/sh", "-eu", "-c", retracted_script], cwd=root, check=True)
            for retracted_target in retracted_targets:
                require(
                    not retracted_target.exists(),
                    f"expected retracted target to remain absent on idempotent rerun: {retracted_target}",
                )
            require(vivaldi_user_nmh.is_file())

    def test_per_browser_writers_share_mozilla_host_and_back_up_in_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            payloads = root / "payloads"
            evaluated, ext_id, nmh_name = evaluate_core_fixture(root, payloads)

            # 1. Syntax check all generated per-browser and aggregate writer scripts
            scripts_by_browser = evaluated["scriptsByBrowser"]
            require(set(scripts_by_browser) == {"chrome", "firefox", "vivaldi", "floorp"})
            for browser, script in scripts_by_browser.items():
                syntax_proc = subprocess.run(
                    ["/bin/sh", "-n"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                require(
                    syntax_proc.returncode == 0,
                    f"per-browser writer syntax check failed for {browser}: {syntax_proc.stderr}",
                )

            # 2. Shared Mozilla NMH placement and per-browser lane target selection
            targets_by_browser = evaluated["targetsByBrowser"]
            mozilla_target = f"/Library/Application Support/Mozilla/NativeMessagingHosts/{nmh_name}.json"
            chrome_plist = "/Library/Managed Preferences/com.google.Chrome.plist"
            firefox_plist = "/Library/Preferences/org.mozilla.firefox.plist"
            vivaldi_plist = "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"
            floorp_plist = "/Library/Preferences/app.floorp.Floorp.plist"
            chrome_ext = f"/Library/Application Support/Google/Chrome/External Extensions/{ext_id}.json"
            vivaldi_ext = f"/Library/Application Support/Vivaldi/External Extensions/{ext_id}.json"
            chrome_nmh = f"/Library/Google/Chrome/NativeMessagingHosts/{nmh_name}.json"
            vivaldi_user_nmh = f"/__PRIMARY_HOME__/Library/Application Support/Vivaldi/NativeMessagingHosts/{nmh_name}.json"

            require(mozilla_target in targets_by_browser["firefox"])
            require(mozilla_target in targets_by_browser["floorp"])
            require(mozilla_target not in targets_by_browser["chrome"])
            require(mozilla_target not in targets_by_browser["vivaldi"])
            for chrome_only in (chrome_plist, chrome_ext, chrome_nmh):
                require(chrome_only in targets_by_browser["chrome"])
                for other_browser in ("firefox", "vivaldi", "floorp"):
                    require(chrome_only not in targets_by_browser[other_browser])

            require(rollout.target_consumers(mozilla_target) == {"firefox", "floorp"})
            attended_rows = evaluated["attendedTargets"]
            selected_vf = rollout.selected_targets(attended_rows, ["vivaldi", "floorp"])
            selected_vf_targets = {row["target"] for row in selected_vf}
            require(mozilla_target in selected_vf_targets)
            require(vivaldi_plist in selected_vf_targets)
            require(floorp_plist in selected_vf_targets)
            require(vivaldi_ext in selected_vf_targets)
            require(vivaldi_user_nmh in selected_vf_targets)
            require(chrome_plist not in selected_vf_targets)
            require(firefox_plist not in selected_vf_targets)
            require(chrome_ext not in selected_vf_targets)
            require(chrome_nmh not in selected_vf_targets)

            # 3. Rewrite backup targets into the verified disposable fixture and run rollout.backup()
            rewritten_vf_rows = []
            seeded_prior_bytes: dict[str, bytes] = {}
            for idx, row in enumerate(selected_vf):
                rewritten_target = rewrite_target_hermetic(row["target"], root)
                require(
                    rewritten_target.startswith(str(root) + "/"),
                    f"rewritten backup target must start with fixture root {root}: {rewritten_target}",
                )
                target_path = Path(rewritten_target)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                prior_content = f"prior-fixture-content-{idx}-{target_path.name}\n".encode("utf-8")
                target_path.write_bytes(prior_content)
                seeded_prior_bytes[rewritten_target] = prior_content
                rewritten_vf_rows.append(
                    {
                        "target": rewritten_target,
                        "source": row["source"],
                        "perUser": row["perUser"],
                    }
                )

            backup_dir = root / "backup"
            backup_records = rollout.backup(rewritten_vf_rows, backup_dir)
            backup_manifest = json.loads((backup_dir / "BACKUP.json").read_text())
            require(backup_records == backup_manifest)
            require(len(backup_manifest) == len(rewritten_vf_rows))
            for record in backup_manifest:
                expected_prior = seeded_prior_bytes[record["target"]]
                expected_sha = hashlib.sha256(expected_prior).hexdigest()
                require(record["kind"] == "file")
                require(record["sha256"] == expected_sha)
                entry_bytes = (backup_dir / record["entry"]).read_bytes()
                require(entry_bytes == expected_prior)

            # 4. Run hermetically rewritten vivaldi and floorp per-browser scripts twice (idempotence
            #    plus per-lane script isolation and Floorp independently writing the shared Mozilla NMH)
            vivaldi_script = rewrite_hermetic(scripts_by_browser["vivaldi"], root)
            floorp_script = rewrite_hermetic(scripts_by_browser["floorp"], root)
            for _ in range(2):
                subprocess.run(["/bin/sh", "-eu", "-c", vivaldi_script], cwd=root, check=True)
                subprocess.run(["/bin/sh", "-eu", "-c", floorp_script], cwd=root, check=True)

            for row in rewritten_vf_rows:
                target_path = Path(row["target"])
                source_path = Path(row["source"])
                require(target_path.is_file(), f"missing per-browser written target: {target_path}")
                require(
                    target_path.read_bytes() == source_path.read_bytes(),
                    f"per-browser written target payload mismatch: {target_path}",
                )

            # Because only the vivaldi and floorp lane scripts ran, chrome and firefox lane-only targets remain absent
            require(not Path(rewrite_target_hermetic(chrome_plist, root)).exists())
            require(not Path(rewrite_target_hermetic(firefox_plist, root)).exists())

            # 5. Held rollback: rollout.rollback() refuses immediately with R3_LEGACY_ROLLBACK_HELD_...
            #    before reading BACKUP.json or modifying target files; restorable backup entries remain intact.
            rollback_args = type("Args", (), {"backup": backup_dir, "attended": True})()
            try:
                rollout.rollback(rollback_args)
            except ValueError as exc:
                require(
                    str(exc) == "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED",
                    f"unexpected rollback refusal message: {exc!r}",
                )
            else:
                raise AssertionError("expected rollout.rollback() to raise ValueError under R3 hold")

            for row in rewritten_vf_rows:
                require(Path(row["target"]).read_bytes() == Path(row["source"]).read_bytes())
            for record in json.loads((backup_dir / "BACKUP.json").read_text()):
                require((backup_dir / record["entry"]).read_bytes() == seeded_prior_bytes[record["target"]])

    def test_declared_undefined_browser_configuration_readback_stays_lazy(self):
        eval_inputs_path = ROOT / "delivery/evaluate-installed-inputs.nix"
        lazy = nix_eval(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              evalInstalled = import {json.dumps(str(eval_inputs_path))};
              roots = {{
                core = "/nix/store/00000000000000000000000000000000-core-source";
                "browser-ux" = "/nix/store/11111111111111111111111111111111-browser-ux-source";
              }};
              outputs = {{
                darwinConfigurations."example-previous-mac" = {{
                  pkgs = {{ inherit lib; }};
                  options = {{
                    "browser-ux".configuration.isDefined = false;
                    system.build.isDefined = false;
                  }};
                  config = {{
                    networking.hostName = "example-previous-mac";
                    "browser-ux".configuration = throw "LAZY_BROWSER_CONFIGURATION_FORCED";
                    system = {{
                      primaryUser = "fixture";
                      build = throw "LAZY_SYSTEM_BUILD_FORCED";
                    }};
                    users.users.fixture.home = "/Users/fixture";
                  }};
                }};
              }};
              result = evalInstalled {{
                flakeOutputs = outputs;
                sourceRoots = roots;
                host = "example-previous-mac";
              }};
            in builtins.deepSeq result result
            """
        )
        require(lazy["optionMetadata"] == {"isTargetHost": False, "browserDefined": False})
        require(lazy["requiredPosture"]["activeBrowsers"] == ["chrome", "firefox"])
        require(lazy["requiredPosture"]["credentialProvider"] == "legacy")
        require(lazy["applyScript"] is None)
        require(lazy["applyScripts"] == {})
        require(lazy["targets"] == [])
        require(lazy["requiredDerivations"] == [])
        require(lazy["primaryHome"] == "/Users/fixture")

        # Negative controls: when isDefined = true, forcing the readback triggers the throw
        forced_browser_stderr = nix_eval_failure(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              evalInstalled = import {json.dumps(str(eval_inputs_path))};
              roots = {{
                core = "/nix/store/00000000000000000000000000000000-core-source";
                "browser-ux" = "/nix/store/11111111111111111111111111111111-browser-ux-source";
              }};
              outputs = {{
                darwinConfigurations."example-previous-mac" = {{
                  pkgs = {{ inherit lib; }};
                  options = {{
                    "browser-ux".configuration.isDefined = true;
                    system.build.isDefined = false;
                  }};
                  config = {{
                    networking.hostName = "example-previous-mac";
                    "browser-ux".configuration = throw "LAZY_BROWSER_CONFIGURATION_FORCED";
                    system = {{
                      primaryUser = "fixture";
                      build = throw "LAZY_SYSTEM_BUILD_FORCED";
                    }};
                    users.users.fixture.home = "/Users/fixture";
                  }};
                }};
              }};
              result = evalInstalled {{
                flakeOutputs = outputs;
                sourceRoots = roots;
                host = "example-previous-mac";
              }};
            in builtins.deepSeq result result
            """
        )
        require(
            "LAZY_BROWSER_CONFIGURATION_FORCED" in forced_browser_stderr,
            f"expected LAZY_BROWSER_CONFIGURATION_FORCED in stderr, got: {forced_browser_stderr!r}",
        )

        forced_build_stderr = nix_eval_failure(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              evalInstalled = import {json.dumps(str(eval_inputs_path))};
              roots = {{
                core = "/nix/store/00000000000000000000000000000000-core-source";
                "browser-ux" = "/nix/store/11111111111111111111111111111111-browser-ux-source";
              }};
              outputs = {{
                darwinConfigurations."example-previous-mac" = {{
                  pkgs = {{ inherit lib; }};
                  options = {{
                    "browser-ux".configuration.isDefined = false;
                    system.build.isDefined = true;
                  }};
                  config = {{
                    networking.hostName = "example-previous-mac";
                    "browser-ux".configuration = throw "LAZY_BROWSER_CONFIGURATION_FORCED";
                    system = {{
                      primaryUser = "fixture";
                      build = throw "LAZY_SYSTEM_BUILD_FORCED";
                    }};
                    users.users.fixture.home = "/Users/fixture";
                  }};
                }};
              }};
              result = evalInstalled {{
                flakeOutputs = outputs;
                sourceRoots = roots;
                host = "example-previous-mac";
              }};
            in builtins.deepSeq result result
            """
        )
        require(
            "LAZY_SYSTEM_BUILD_FORCED" in forced_build_stderr,
            f"expected LAZY_SYSTEM_BUILD_FORCED in stderr, got: {forced_build_stderr!r}",
        )

    def test_evaluate_installed_inputs_handles_explicit_roots_and_legacy_cutover_refusal(self):
        eval_inputs_path = ROOT / "delivery/evaluate-installed-inputs.nix"
        require("builtins.getFlake" not in eval_inputs_path.read_text())

        result = nix_eval(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              evalInstalled = import {json.dumps(str(eval_inputs_path))};
              roots = {{
                core = "/nix/store/00000000000000000000000000000000-core-source";
                "browser-ux" = "/nix/store/11111111111111111111111111111111-browser-ux-source";
              }};
              mkHost = host: roleDefined: roleEnable: cutoverEnable: {{
                pkgs = {{ inherit lib; }};
                options = {{
                  "browser-ux" = {{
                    configuration.isDefined = true;
                    rolesR3.isDefined = roleDefined;
                  }};
                  system.build.isDefined = false;
                }};
                config = {{
                  networking.hostName = host;
                  "browser-ux" = {{
                    rolesR3 = {{ enable = roleEnable; }};
                    configuration = {{
                      extensions.apple-proton-trial.enable = host == "example-current-mac";
                      replacements = {{
                        vivaldi = {{ enable = host == "example-current-mac"; mail.enable = host == "example-current-mac"; }};
                        floorp.enable = host == "example-current-mac";
                      }};
                      primaryCutover = {{
                        enable = cutoverEnable;
                        activeBrowsers = [ "vivaldi" "floorp" "safari" ];
                        retiredBrowsers = [ "chrome" "firefox" ];
                        credentialProvider = "apple";
                        productivityIntent = "feeds-only";
                        protonVpnEnabled = true;
                      }};
                    }};
                  }};
                }};
              }};
              outputs = {{
                darwinConfigurations = {{
                  "example-current-mac" = mkHost "example-current-mac" false false true;
                  "example-previous-mac" = mkHost "example-previous-mac" false false false;
                  "roles-r3-active-mac" = mkHost "example-current-mac" true true true;
                }};
              }};
              current = evalInstalled {{ flakeOutputs = outputs; sourceRoots = roots; host = "example-current-mac"; }};
              previous = evalInstalled {{ flakeOutputs = outputs; sourceRoots = roots; host = "example-previous-mac"; }};
              held = builtins.tryEval (evalInstalled {{ flakeOutputs = outputs; sourceRoots = roots; host = "roles-r3-active-mac"; }});
            in {{
              currentSourceRoots = current.sourceRoots;
              currentOptionMetadata = current.optionMetadata;
              currentPosture = current.requiredPosture;
              previousOptionMetadata = previous.optionMetadata;
              previousPosture = previous.requiredPosture;
              heldRefused = !held.success;
            }}
            """
        )
        require(
            result["currentSourceRoots"]
            == {
                "core": "/nix/store/00000000000000000000000000000000-core-source",
                "browser-ux": "/nix/store/11111111111111111111111111111111-browser-ux-source",
            }
        )
        require(result["currentOptionMetadata"] == {"isTargetHost": True, "browserDefined": True})
        require(result["currentPosture"]["activeBrowsers"] == ["vivaldi", "floorp", "safari"])
        require(result["currentPosture"]["retiredBrowsers"] == ["chrome", "firefox"])
        require(result["currentPosture"]["appleProton"] is True)
        require(result["previousOptionMetadata"] == {"isTargetHost": False, "browserDefined": True})
        require(result["previousPosture"]["retiredBrowsers"] == [])
        require(result["previousPosture"]["appleProton"] is False)
        require(result["heldRefused"] is True)

        held_stderr = nix_eval_failure(
            f"""
            let
              flake = builtins.getFlake (toString {json.dumps(str(ROOT))});
              lib = flake.inputs.nixpkgs.lib;
              evalInstalled = import {json.dumps(str(eval_inputs_path))};
              roots = {{
                core = "/nix/store/00000000000000000000000000000000-core-source";
                "browser-ux" = "/nix/store/11111111111111111111111111111111-browser-ux-source";
              }};
              outputs = {{
                darwinConfigurations."roles-r3-active-mac" = {{
                  pkgs = {{ inherit lib; }};
                  options = {{
                    "browser-ux" = {{
                      configuration.isDefined = true;
                      rolesR3.isDefined = true;
                    }};
                    system.build.isDefined = false;
                  }};
                  config = {{
                    networking.hostName = "example-current-mac";
                    "browser-ux" = {{
                      rolesR3 = {{ enable = true; }};
                      configuration = {{
                        primaryCutover = {{
                          enable = true;
                          activeBrowsers = [ "vivaldi" "floorp" "safari" ];
                          retiredBrowsers = [ "chrome" "firefox" ];
                          credentialProvider = "apple";
                          productivityIntent = "feeds-only";
                          protonVpnEnabled = true;
                        }};
                      }};
                    }};
                  }};
                }};
              }};
              held = evalInstalled {{
                flakeOutputs = outputs;
                sourceRoots = roots;
                host = "roles-r3-active-mac";
              }};
            in builtins.deepSeq held held
            """
        )
        require(
            "R3_LEGACY_CUTOVER_HELD: selected Browser UX roles supersede primary cutover" in held_stderr,
            f"expected R3_LEGACY_CUTOVER_HELD message in stderr, got: {held_stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
