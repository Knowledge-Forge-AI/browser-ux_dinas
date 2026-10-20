#!/usr/bin/env python3
import plistlib
import sys
from pathlib import Path


def launch_plist(label, program, log_file):
    return {
        "Label": label,
        "ProgramArguments": [program, "daemon"],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": log_file,
        "StandardErrorPath": log_file,
    }


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: write-launch-plist.py OUTPUT LABEL PROGRAM LOG_FILE")

    output_file = Path(sys.argv[1])
    plist = launch_plist(sys.argv[2], sys.argv[3], sys.argv[4])
    with output_file.open("wb") as output:
        plistlib.dump(plist, output, sort_keys=False)


if __name__ == "__main__":
    main()
