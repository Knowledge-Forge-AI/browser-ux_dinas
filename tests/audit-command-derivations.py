"""Dispatch-time full derivation metadata audit, without realizing build sources.

Run with the standalone command package .drv path. Runtime closure and exact
direct build-input contexts are separately checked by package-provenance.nix.
No browser, network tool, host build, or profile read is performed.
"""
import json
import re
import subprocess
import sys

def audit(graph, root):
    for path, derivation in graph.items():
        members = [path, *derivation.get("inputSrcs", [])]
        for member in members:
            if "darwin-is-not-a-snowflake" in member.lower():
                raise ValueError("forbidden core source")
            # FFmpeg has a chromium-named compatibility patch; it is not a browser.
            name = member.rsplit("/", 1)[-1].split("-", 1)[-1]
            if re.match(r"(?:google-chrome|chromium)(?:[-.]|$)", name):
                raise ValueError("forbidden browser derivation")
    for value in graph[root].get("env", {}).values():
        if any(word in value for word in
               ("/run/current-system", "/Users/", "/home/", "darwin-is-not-a-snowflake")):
            raise ValueError("forbidden package build authority")


if __name__ == "__main__":
    result = subprocess.run(["nix", "derivation", "show", "--recursive", sys.argv[1]],
                            text=True, capture_output=True, check=True)
    graph = json.loads(result.stdout)
    audit(graph, sys.argv[1])
    print(f"PASS: recursive derivation metadata ({len(graph)} derivations); no forbidden core/browser source or package build authority")
