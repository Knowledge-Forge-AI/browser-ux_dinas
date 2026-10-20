#!/usr/bin/env python3
import os
import re
import sys


def version_key(path):
    name = os.path.basename(path)
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", name)]


def main():
    root = sys.argv[1]
    versions = [
        os.path.join(root, name)
        for name in os.listdir(root)
        if os.path.isdir(os.path.join(root, name))
    ]
    if not versions:
        raise SystemExit(1)
    print(sorted(versions, key=version_key)[-1])


if __name__ == "__main__":
    main()
