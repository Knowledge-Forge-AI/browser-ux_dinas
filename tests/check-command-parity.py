"""Dispatch-time source byte/mode inventory; maintained flake tests need no core."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--core", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "tests/fixtures/command-source-manifest.json").read_text())
# Recorded destination adaptations of core commands. BUX5B1 CONSUMER-ADAPT1 repoints the sync
# command to verified Browser UX durable state; core keeps the Chrome-profile copy until BUX6.
ADAPTED = {"bin/clear-new-tab-sync": "durable-authority-consumer",
           "bin/cnt-wallpaper-gallery": "tracked-runtime-selection"}
# Core helpers deliberately not packaged here: the retired Chrome extension-version selector.
RETIRED_CORE_HELPERS = {"libexec/clear-new-tab/latest-source-extension-dir.py"}
differences = []
origins = []
for relative, record in manifest.items():
    source, destination = args.core / relative, root / relative
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == record["destination_sha256"], relative
    if record["adaptation"] == "destination-origin":
        # BUX5B0C/BUX5B1 destination-only libraries and consumer helper: no core source exists.
        assert record["source_sha256"] is None and not source.exists(), relative
        assert destination.stat().st_mode & 0o777 == int(record["mode"], 8), relative
        origins.append(relative)
        continue
    assert hashlib.sha256(source.read_bytes()).hexdigest() == record["source_sha256"], relative
    assert source.stat().st_mode & 0o777 == destination.stat().st_mode & 0o777 == int(record["mode"], 8), relative
    if source.read_bytes() != destination.read_bytes():
        differences.append(relative)
        assert record["adaptation"] == ADAPTED[relative], relative
    else:
        assert record["adaptation"] == "byte-identical"
assert differences == ["bin/clear-new-tab-sync", "bin/cnt-wallpaper-gallery"]
assert origins == ["libexec/clear-new-tab/brave-youtube-consumer.py", "libexec/clear-new-tab/durable_state.py",
                   "libexec/clear-new-tab/guarded_recovery.py"]
helpers = {str(path.relative_to(args.core)) for folder in ("brave-youtube", "clear-new-tab", "shared-images")
           for path in (args.core / "libexec" / folder).iterdir() if path.is_file()}
packaged = {path for path in manifest if path.startswith("libexec/") and path not in origins}
assert not RETIRED_CORE_HELPERS & set(manifest)
assert helpers == packaged | RETIRED_CORE_HELPERS
print("PASS: 29 source entries, 24 byte/mode-identical, two recorded adaptations (runtime-only gallery, "
      "durable-authority sync consumer); 16 of 17 core helpers packaged, one retired "
      "(latest-source-extension-dir.py), no additions; three destination-origin files "
      "(brave-youtube-consumer.py, durable_state.py, guarded_recovery.py)")
