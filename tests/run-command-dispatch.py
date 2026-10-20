"""macOS-only migrated suites and confined session helper harness.

Run under the command-tests dev shell; --scratch must be a task-owned directory.
"""
import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--scratch", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
args.scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="commands-", dir=args.scratch) as temporary:
    home = Path(temporary)
    (home / ".bux-fixture").touch()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("BRAVE_YOUTUBE_", "YOUTUBE_", "CLEAR_NEW_TAB_", "SHARED_IMAGES_"))}
    env.update(HOME=str(home), BUX_TEST_HOME=str(home), XDG_STATE_HOME=str(home / "state"),
               TMPDIR=str(home), PYTHONDONTWRITEBYTECODE="1")
    recorder = home / "record"
    recorder.write_text("#!" + shutil.which("bash") + '\nprintf "%s\\n" "$*" >> "$HOME/record.log"\n')
    recorder.chmod(0o700)
    for name in ("PMSET", "SUDO", "CAFFEINATE", "OPEN", "LAUNCHCTL", "PS", "KILL"):
        env["BRAVE_YOUTUBE_" + name] = str(recorder)
    subprocess.run(["bats", "tests/migrated/unit/bash", "tests/migrated/unit/awk",
                    "tests/migrated/unit/applescript", "tests/migrated/int/bash"],
                   cwd=root, env=env, check=True)
    subprocess.run(["bash", "tests/migrated/support/bash/brave-youtube-session-coverage-harness"],
                   cwd=root, env=env, check=True)
    assert not (home / "Library/LaunchAgents").exists()
    print("PASS: macOS suites and fixture-only session helper harness; external tool calls recorded")
