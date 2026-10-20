#!/usr/bin/env python3
"""Attended orchestration of the matched core-owned browser policy writer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

from observations import APPS, app_metadata, helper, installed, vivaldi_vpn_source

TARGETS = {
    "/Library/Managed Preferences/com.google.Chrome.plist",
    "/Library/Preferences/org.mozilla.firefox.plist",
    "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist",
    "/Library/Preferences/app.floorp.Floorp.plist",
    "/Library/Application Support/Google/Chrome/External Extensions/felphkbfjadmcejnibcmcncimlappdde.json",
    "/Library/Application Support/Vivaldi/External Extensions/felphkbfjadmcejnibcmcncimlappdde.json",
    "/Library/Google/Chrome/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json",
    "/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json",
}


def digest(path):
    raw = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
    return hashlib.sha256(raw).hexdigest()


def require(condition, category):
    if not condition:
        raise ValueError(category)


def validate_build(build):
    targets = build["targets"]
    names = [row["target"] for row in targets]
    home = Path(build["primaryHome"])
    require(home.is_absolute() and home.parent == Path("/Users") and home.resolve() == home, "PRIMARY_HOME_INVALID")
    require(len(names) == len(set(names)) and set(names) == TARGETS, "TARGET_OWNERSHIP_MISMATCH")
    require(build["owner"] == "core/programs.browserBaseline", "WRITER_OWNER_MISMATCH")
    writer = Path(build["applyScript"])
    require(str(writer).startswith("/nix/store/") and writer.is_file(), "CORE_WRITER_NOT_BUILT")
    require(set(build["applyScripts"]) == set(APPS), "BROWSER_WRITERS_MISMATCH")
    for script in build["applyScripts"].values():
        require(str(script).startswith("/nix/store/") and Path(script).is_file(), "CORE_WRITER_NOT_BUILT")
    for row in targets:
        require(str(row["source"]).startswith("/nix/store/") and Path(row["source"]).is_file(), "PAYLOAD_NOT_BUILT")
        require(all(not parent.is_symlink() for parent in Path(row["target"]).parents), "TARGET_ANCESTOR_SYMLINK")
    return targets, writer


def target_consumers(target):
    if target == "/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json":
        return {"firefox", "floorp"}
    if "com.google.Chrome.plist" in target or "/Google/Chrome/" in target:
        return {"chrome"}
    if "org.mozilla.firefox.plist" in target:
        return {"firefox"}
    if "Vivaldi" in target:
        return {"vivaldi"}
    if "app.floorp.Floorp.plist" in target:
        return {"floorp"}
    return set()


def selected_targets(targets, browsers):
    return [row for row in targets if target_consumers(row["target"]).intersection(browsers)]


def selected_browsers(args):
    browsers = getattr(args, "browsers", None) or list(APPS)
    require(len(browsers) == len(set(browsers)) and set(browsers) <= set(APPS), "BROWSER_SELECTION_INVALID")
    return browsers


def source_check(bindings, roots):
    for owner, records in bindings["candidateFiles"].items():
        for name, expected in records.items():
            path = roots[owner] / name
            require(path.exists() or path.is_symlink(), "MATCHED_SOURCE_ABSENT")
            require(digest(path) == expected, "MATCHED_SOURCE_CHANGED")


def check(args):
    require(all((args.bindings, args.browser_ux, args.core, args.composition, args.build_manifest)), "MATCHED_INPUT_ARGUMENTS_REQUIRED")
    bindings = json.loads(args.bindings.read_text())
    roots = {"browser-ux": args.browser_ux, "core": args.core, "composition": args.composition}
    source_check(bindings, roots)
    host = subprocess.run(["/usr/sbin/scutil", "--get", "LocalHostName"],
                          capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    require(host == "example-current-mac", "HOST_SCOPE_MISMATCH")
    apps = {}
    for browser in APPS:
        try:
            apps[browser] = app_metadata(browser)
        except (OSError, ValueError, subprocess.SubprocessError):
            apps[browser] = {"status": "UNVERIFIED_LOCAL_GAP"}
    readiness = {browser: {"canApplyConfiguration": bool(row.get("signingIdentityMatches") and row.get("signatureVerified")),
                           "prerequisite": "MET" if row.get("signingIdentityMatches") and row.get("signatureVerified") else "APP_IDENTITY_OR_SIGNATURE_PENDING"}
                 for browser, row in apps.items()}
    build = json.loads(args.build_manifest.read_text())
    targets, writer = validate_build(build)
    # Bind the evaluated input bytes, not just the caller-supplied checkout paths.
    require(build["candidateFiles"] == bindings["candidateFiles"], "EVALUATED_INPUT_BINDING_MISMATCH")
    require(build["requiredPosture"] == bindings["requiredPosture"], "EVALUATED_POSTURE_MISMATCH")
    try:
        vpn = vivaldi_vpn_source()
    except (OSError, ValueError):
        vpn = {"sourceCapability": "UNVERIFIED_LOCAL_GAP", "installedInstance": "UNVERIFIED"}
    require(bindings["vivaldiVpn"]["route"] in ("standalone", "integrated"), "VPN_ROUTE_UNKNOWN")
    # Source diagnostics never establish a usable instance or admit another ID.
    # Vivaldi execute requires an attended confirmation of its actual single route.
    os_version = subprocess.run(["/usr/bin/sw_vers", "-productVersion"], capture_output=True,
                                text=True, timeout=10, check=True).stdout.strip()
    helpers, extensions = {}, {}
    for browser, identities in bindings["extensionIds"].items():
        try:
            helpers[browser] = helper(browser, identities["icloud-passwords"], home=build["primaryHome"])
            extensions[browser] = {product: installed(browser, identity, home=Path(build["primaryHome"]))
                                   for product, identity in identities.items()}
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            helpers[browser], extensions[browser] = {"status": "UNVERIFIED_LOCAL_GAP"}, {"status": "UNVERIFIED_LOCAL_GAP"}
    apple_requirement = "MET" if os_version.split(".")[0].isdigit() and int(os_version.split(".")[0]) >= 14 else "UNSUPPORTED_OR_UNVERIFIED_LOCAL_GAP"
    return {"status": "CHECKED_NOT_ACTIVATED", "apps": apps, "vpnSource": vpn,
            "browserReadiness": readiness, "selectedBrowsers": selected_browsers(args),
            "vpnRouteReadback": "ATTENDED_INSTANCE_CONFIRMATION_PENDING",
            "macOS": os_version, "applePlatformRequirement": apple_requirement,
            "appleHelpers": helpers, "observedExtensionFiles": extensions,
            "targetCount": len(targets), "selectedTargetCount": len(selected_targets(targets, selected_browsers(args))),
            "effective": "READBACK_PENDING", "behavior": "UNVERIFIED",
            "deliberateOptOuts": build.get("deliberateOptOuts", []),
            "buildManifestSha256": digest(args.build_manifest), "writerSha256": digest(writer),
            "extensionData": "NOT_BACKED_UP_POLICY_REMOVAL_MAY_UNINSTALL"}


def backup(targets, destination):
    require(not destination.exists() and destination.parent.resolve() == destination.parent.absolute(), "BACKUP_DESTINATION_UNSAFE")
    destination.mkdir(mode=0o700)
    records = []
    for index, row in enumerate(targets):
        target, name = Path(row["target"]), str(index)
        record = {"target": row["target"], "entry": name, "kind": "absent"}
        if target.is_symlink():
            record.update(kind="symlink", link=os.readlink(target))
        elif target.exists():
            require(target.is_file(), "TARGET_NOT_REGULAR")
            shutil.copyfile(target, destination / name)
            (destination / name).chmod(0o600)
            record.update(kind="file", sha256=digest(destination / name), mode=target.stat().st_mode & 0o777)
        if record["kind"] != "absent":
            info = target.lstat()
            record.update(uid=info.st_uid, gid=info.st_gid)
        records.append(record)
    (destination / "BACKUP.json").write_text(json.dumps(records, indent=2) + "\n")
    return records


def execute(args):
    require(False, "R3_DEPLOYMENT_HELD_SOURCE_RELEASE_REQUIRED")
    require(args.backup is not None, "BACKUP_ARGUMENT_REQUIRED")
    require(args.attended, "ATTENDED_CONFIRMATIONS_REQUIRED")
    browsers = selected_browsers(args)
    require("vivaldi" not in browsers or args.vpn_instance_confirmed, "VIVALDI_INSTANCE_CONFIRMATION_REQUIRED")
    require(args.mail_calendar_feeds_on, "MAIL_PRESERVATION_CONFIRMATION_REQUIRED")
    result = check(args)
    require(all(result["browserReadiness"][browser]["canApplyConfiguration"] for browser in browsers), "SELECTED_BROWSER_PREREQUISITE_PENDING")
    build = json.loads(args.build_manifest.read_text())
    targets, _ = validate_build(build)
    targets = selected_targets(targets, browsers)
    # Actual target backups require root; this orchestration runs under the normal sudo prompt.
    require(os.geteuid() == 0, "ATTENDED_ADMINISTRATIVE_PROMPT_REQUIRED")
    backup(targets, args.backup)
    for browser in browsers:
        subprocess.run([build["applyScripts"][browser]], check=True, timeout=120, capture_output=True)
    require(all(Path(row["target"]).is_file() and Path(row["target"]).read_bytes() == Path(row["source"]).read_bytes()
                for row in targets), "CONFIGURATION_FILE_READBACK_FAILED")
    return result | {"status": "CONFIGURATION_WRITTEN_EFFECTIVE_READBACK_PENDING",
                     "mail": "PRESERVED_NO_PROFILE_WRITER", "extensions": "INSTALL_READBACK_PENDING"}


def rollback(args):
    require(False, "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED")
    require(args.backup is not None, "BACKUP_ARGUMENT_REQUIRED")
    require(args.attended and os.geteuid() == 0, "ATTENDED_ADMINISTRATIVE_PROMPT_REQUIRED")
    records = json.loads((args.backup / "BACKUP.json").read_text())
    require(len({row["target"] for row in records}) == len(records), "DUPLICATE_ROLLBACK_TARGET")
    for row in records:
        target = Path(row["target"])
        require(row["target"] in TARGETS, "ROLLBACK_SCOPE_MISMATCH")
        require(row["kind"] in ("file", "symlink", "absent"), "BACKUP_KIND_INVALID")
        require(all(not parent.is_symlink() for parent in Path(row["target"]).parents), "TARGET_ANCESTOR_SYMLINK")
        if row["kind"] == "file":
            require(row["entry"].isdigit() and digest(args.backup / row["entry"]) == row["sha256"], "BACKUP_CHECKSUM_MISMATCH")
    for row in records:
        path = Path(row["target"])
        if path.is_symlink():
            path.unlink()
        if row["kind"] == "absent":
            path.unlink(missing_ok=True)
        elif row["kind"] == "symlink":
            path.unlink(missing_ok=True)
            path.symlink_to(row["link"])
        else:
            shutil.copyfile(args.backup / row["entry"], path)
            path.chmod(row["mode"])
        if row["kind"] != "absent":
            os.chown(path, row["uid"], row["gid"], follow_symlinks=False)
    return {"status": "AFFECTED_CONFIGURATION_RESTORED", "profilesAndMail": "UNTOUCHED",
            "extensionData": "NOT_BACKED_UP_POLICY_REMOVAL_MAY_UNINSTALL",
            "extensionNextStep": "Inspect extension presence/settings after restoration; use official onboarding if reinstallation or pairing is needed."}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("mode", choices=["check", "execute", "rollback"])
    result.add_argument("--browsers", nargs="+", choices=list(APPS), help="Apply only selected browser lanes; defaults to all four")
    for name in ("bindings", "browser-ux", "core", "composition", "build-manifest", "report", "backup"):
        result.add_argument("--" + name, type=Path, required=name == "report")
    for name in ("attended", "vpn-instance-confirmed", "mail-calendar-feeds-on"):
        result.add_argument("--" + name, action="store_true")
    return result


def main():
    args = parser().parse_args()
    try:
        result = {"check": check, "execute": execute, "rollback": rollback}[args.mode](args)
        code = 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, ValueError) and str(error).replace("_", "").isupper() else type(error).__name__
        result, code = {"status": "FAILED", "mode": args.mode, "automaticRollback": False,
                        "category": category,
                        "nextStep": "Inspect prerequisites or restore the exact affected-target backup; no profile rollback."}, 1
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
