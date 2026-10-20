"""Read only public app metadata and requested extension/helper manifests."""
import json
from pathlib import Path
import plistlib
import re
import subprocess
import zipfile

APPS = {
    "chrome": ("/Applications/Nix Apps/Google Chrome.app", "com.google.Chrome", "EQHXZ8M8AV"),
    "firefox": ("/Applications/Firefox.app", "org.mozilla.firefox", "43AQ936H96"),
    "vivaldi": ("/Applications/Vivaldi.app", "com.vivaldi.Vivaldi", "4XF3XNRN6Y"),
    "floorp": ("/Applications/Floorp.app", "app.floorp.Floorp", "DV2U35YBHT"),
}
NATIVE_USER_RELATIVE = {
    "chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "firefox": "Library/Application Support/Mozilla/NativeMessagingHosts",
    "vivaldi": "Library/Application Support/Vivaldi/NativeMessagingHosts",
    "floorp": "Library/Application Support/Mozilla/NativeMessagingHosts",
}
NATIVE_SYSTEM_RELATIVE = {
    "chrome": "Google/Chrome/NativeMessagingHosts",
    "firefox": "Application Support/Mozilla/NativeMessagingHosts",
    "vivaldi": "Application Support/Vivaldi/NativeMessagingHosts",
    "floorp": "Application Support/Mozilla/NativeMessagingHosts",
}


def app_metadata(browser):
    app, expected_bundle, expected_team = APPS[browser]
    path = Path(app)
    if not path.exists():
        return {"status": "ABSENT"}
    data = plistlib.loads((path / "Contents/Info.plist").read_bytes())
    result = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=2", str(path)],
                            capture_output=True, text=True, timeout=30, check=False)
    fields = dict(line.split("=", 1) for line in result.stderr.splitlines()
                  if line.startswith(("Identifier=", "TeamIdentifier=")))
    verify = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)],
                            capture_output=True, timeout=30, check=False)
    return {"status": "OBSERVED", "version": data.get("CFBundleShortVersionString"),
            "bundleId": data.get("CFBundleIdentifier"),
            "signingIdentityMatches": fields.get("Identifier") == expected_bundle
            and fields.get("TeamIdentifier") == expected_team,
            "signatureVerified": verify.returncode == 0,
            "signatureDiagnostic": "VERIFIED" if verify.returncode == 0 else "VERIFY_FAILED_IN_EXECUTION_ENVIRONMENT"}


def helper(browser, extension_id, home=None, system_root=Path("/Library")):
    roots = [("per-user", Path(home or Path.home()) / NATIVE_USER_RELATIVE[browser]),
             ("system", Path(system_root) / NATIVE_SYSTEM_RELATIVE[browser])]
    registrations = []
    for scope, root in roots:
        path = root / "com.apple.passwordmanager.json"
        if not (path.exists() or path.is_symlink()):
            continue
        try:
            data = json.loads(path.read_text())
            identity = "chrome-extension://" + extension_id + "/"
            allowed = identity in data.get("allowed_origins", []) or extension_id in data.get("allowed_extensions", [])
            present = Path(data.get("path", "/NONEXISTENT")).is_file()
            registrations.append({"scope": scope, "allowedIdentity": allowed, "executablePresent": present})
        except (OSError, ValueError, TypeError, AttributeError):
            registrations.append({"scope": scope, "allowedIdentity": False, "executablePresent": False,
                                  "status": "REGISTRATION_UNVERIFIED_LOCAL_GAP"})
    # A per-user registration can shadow the system registration; do not promote
    # the latter's presence to proof the browser reaches it.
    selected = registrations[0] if registrations else {}
    available = selected.get("allowedIdentity") and selected.get("executablePresent")
    status = ("NATIVE_HELPER_AVAILABLE" if available else "NATIVE_HELPER_UNVERIFIED") if registrations else "NATIVE_REGISTRATION_NOT_OBSERVED"
    return {"status": status,
            "registrationOwner": "Apple/OS", "allowedIdentity": selected.get("allowedIdentity", False),
            "registrations": registrations, "searchedRoots": [scope for scope, _ in roots],
            "selectedRegistration": selected.get("scope"),
            "availabilityMeaning": "Registration and executable present; native handshake untested",
            "callerAcceptance": "UNVERIFIED",
            "sharedReader": "firefox" if browser == "floorp" else None,
            "pairing": "PAIRING_PENDING", "authenticatedUsability": "UNVERIFIED"}


def manifest_summary(data):
    return {"version": data.get("version"), "updateUrl": data.get("update_url"),
            "permissions": data.get("permissions", []), "hostPermissions": data.get("host_permissions", []),
            "enabled": "UNVERIFIED", "signedIn": "UNVERIFIED", "behavior": "UNVERIFIED"}


def installed(browser, extension_id, home=None):
    home = home or Path.home()
    if browser in ("chrome", "vivaldi"):
        relative = "Google/Chrome" if browser == "chrome" else "Vivaldi"
        root = home / "Library/Application Support" / relative
        paths = root.glob("*/Extensions/" + extension_id + "/*/manifest.json")
        return [manifest_summary(json.loads(p.read_text())) for p in paths]
    relative = "Firefox" if browser == "firefox" else "Floorp"
    root = home / "Library/Application Support" / relative / "Profiles"
    found = []
    for path in root.glob("*/extensions/" + extension_id + ".xpi"):
        with zipfile.ZipFile(path) as package:
            data = json.loads(package.read("manifest.json"))
            identity = data.get("browser_specific_settings", data.get("applications", {})).get("gecko", {}).get("id")
            if identity == extension_id:
                found.append(manifest_summary(data))
    return found


def vivaldi_vpn_source():
    root = Path(APPS["vivaldi"][0]) / "Contents/Frameworks/Vivaldi Framework.framework/Resources/vivaldi"
    path = root / "background-common-bundle.js"
    if not path.exists():
        return {"sourceCapability": "NOT_OBSERVED", "installedInstance": "UNVERIFIED"}
    # A store-ID literal is diagnostic evidence, not a stable UI export contract
    # or proof of an installed instance. Minified export names change on updates.
    text = path.read_text()
    store_id = "jplgfhpmjnbigmhklmmbgecoobifkmpa"
    referenced = re.search(r"[\"']" + store_id + r"[\"']", text) is not None
    return {"sourceCapability": "STORE_ID_REFERENCE_OBSERVED" if referenced else "UNVERIFIED",
            "referencedStoreId": store_id if referenced else None, "route": "UNVERIFIED_REQUIRES_ATTENDED_INSTANCE",
            "ownership": "Vivaldi app resources; installed-instance vendor/store route requires attended confirmation",
            "installedInstance": "UNVERIFIED", "available": "UNVERIFIED",
            "source": "https://protonvpn.com/support/vivaldi"}
