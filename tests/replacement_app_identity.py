#!/usr/bin/env python3
"""Read-only macOS replacement application identity qualification; never runs a browser."""

import argparse
import json
import plistlib
import subprocess
from pathlib import Path


def probe(app, expect_bundle, expect_team, runner=subprocess.run):
    app = Path(app).absolute()
    result = {"schema": "browser-ux-app-identity-v1", "verdict": "UNKNOWN"}
    if not app.exists():
        return result | {"observation": "ABSENT"}
    try:
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if not isinstance(info, dict):
            return result | {"observation": "INVALID_PLIST"}
        executable = info.get("CFBundleExecutable")
        if (not isinstance(executable, str) or not executable
                or Path(executable).name != executable or executable in (".", "..")):
            return result | {"observation": "INVALID_EXECUTABLE"}
        if not (app / "Contents/MacOS" / executable).is_file():
            return result | {"observation": "EXECUTABLE_ABSENT"}
        signature = runner(["/usr/bin/codesign", "-dv", "--verbose=2", str(app)],
                           capture_output=True, text=True, check=False, timeout=30)
        verify = runner(["/usr/bin/codesign", "--verify", "--strict", str(app)],
                        capture_output=True, text=True, check=False, timeout=30)
    except (OSError, ValueError, plistlib.InvalidFileException, subprocess.TimeoutExpired):
        return result | {"observation": "READ_OR_SIGNATURE_ERROR"}
    # Diagnostics can contain private paths. Retain only closed categories and
    # architecture names; a failure in this environment is not a host diagnosis.
    diagnostic = verify.stderr.lower()
    signature_diagnostic = "VERIFIED" if verify.returncode == 0 else "VERIFY_FAILED"
    if verify.returncode != 0:
        for token, category in (("operation not permitted", "ACCESS_DENIED"),
                                ("permission denied", "ACCESS_DENIED"),
                                ("resource fork, finder information, or similar detritus", "RESOURCE_DETRITUS"),
                                ("sealed resource is missing or invalid", "SEALED_RESOURCE_INVALID"),
                                ("invalid signature", "INVALID_SIGNATURE"),
                                ("not signed at all", "UNSIGNED")):
            if token in diagnostic:
                signature_diagnostic = category
                break
    architecture = next((arch for arch in ("arm64", "x86_64")
                         if f"in architecture: {arch}" in diagnostic), None)
    fields = {}
    for line in signature.stderr.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("Identifier", "TeamIdentifier"):
            fields[key] = value
    result |= {
        "bundleIdentifier": info.get("CFBundleIdentifier"),
        "signingIdentifier": fields.get("Identifier"),
        "teamIdentifier": fields.get("TeamIdentifier"),
        "version": info.get("CFBundleShortVersionString"),
        "buildVersion": info.get("CFBundleVersion"),
        "signatureVerified": verify.returncode == 0,
        "signatureVerifyExitCode": verify.returncode,
        "signatureDiagnostic": signature_diagnostic,
        "signatureArchitecture": architecture,
        "executablePresent": True,
    }
    if signature.returncode != 0 or not fields.get("Identifier") or not fields.get("TeamIdentifier"):
        return result | {"observation": "SIGNATURE_UNREADABLE"}
    match = (result["bundleIdentifier"] == expect_bundle
             and result["signingIdentifier"] == expect_bundle
             and result["teamIdentifier"] == expect_team
             and result["signatureVerified"])
    return result | {"verdict": "MATCH" if match else "MISMATCH", "observation": "INSPECTED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--expect-bundle", required=True)
    parser.add_argument("--expect-team", required=True)
    args = parser.parse_args()
    result = probe(args.app, args.expect_bundle, args.expect_team)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
