#!/usr/bin/env python3
"""Bind a normal composed Nix evaluation to the reviewed browser handoff."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def prepare(args):
    evaluation = json.loads(args.evaluation.read_text())
    bindings = json.loads(args.bindings.read_text())
    observed = {}
    for owner, files in bindings["candidateFiles"].items():
        root = Path(evaluation["sourceRoots"][owner])
        if not str(root).startswith("/nix/store/"):
            raise ValueError("Normal selected Nix input required")
        observed[owner] = {}
        for name in files:
            path = root / name
            raw = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            observed[owner][name] = hashlib.sha256(raw).hexdigest()
    if observed != bindings["candidateFiles"]:
        raise ValueError("Selected inputs differ from reviewed source")
    if evaluation["requiredPosture"] != bindings["requiredPosture"]:
        raise ValueError("Selected host trial posture differs from the handoff")
    # Realize only the core writer and its exact payloads; no activation or full system build.
    subprocess.run(["nix-store", "--realise", *sorted(set(evaluation["requiredDerivations"]))],
                   check=True, capture_output=True)
    result = {key: evaluation[key] for key in ("owner", "applyScript", "applyScripts", "targets", "primaryHome", "requiredPosture", "deliberateOptOuts")}
    result["candidateFiles"] = observed
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return {"status": "MATCHED_PAYLOADS_BUILT_NOT_APPLIED", "targetCount": len(result["targets"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result, code = prepare(args), 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result, code = {"status": "FAILED", "category": type(error).__name__, "activated": False}, 1
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
