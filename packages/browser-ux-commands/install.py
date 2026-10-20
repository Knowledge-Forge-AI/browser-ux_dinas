"""Asserted runtime-only installation rewrites; bin contains no hidden wrappers."""
import json
import sys
from pathlib import Path

root, bash, python, gallery_python, rclone, magick, chrome = sys.argv[1:]
root = Path(root)


def replace(text, old, new, count):
    assert text.count(old) == count, (old, text.count(old), count)
    return text.replace(old, new)


for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    text = path.read_text()
    if text.startswith("#!/usr/bin/env bash\n"):
        text = replace(text, "#!/usr/bin/env bash", f"#!{bash}", 1)
    if text.startswith("#!/usr/bin/env python3\n"):
        interpreter = gallery_python if path.name == "cnt-wallpaper-gallery" else python
        text = replace(text, "#!/usr/bin/env python3", f"#!{interpreter}", 1)
    if path.name in ("brave-youtube-session", "clear-new-tab-sync"):
        count = 3 if path.name == "brave-youtube-session" else 1
        text = replace(text, "/usr/bin/python3", python, count)
        text = replace(text, "  cat <<", "  /bin/cat <<", 1)
    if path.name == "shared-images-rclone-sync":
        text = replace(text, '${RCLONE:-rclone}', '${RCLONE:-' + rclone + '}', 1)
        text = replace(text, "  cat <<", "  /bin/cat <<", 1)
        text = replace(text, '    mkdir -p', '    /bin/mkdir -p', 2)
    if path.name == "cnt-wallpaper-gallery":
        text = replace(text, 'PACKAGED_CHROME_EXECUTABLE = ""',
                       'PACKAGED_CHROME_EXECUTABLE = ' + json.dumps(chrome), 1)
        text = replace(text, '["magick",', '[' + json.dumps(magick) + ',', 2)
        text = replace(text, '["sips",', '["/usr/bin/sips",', 1)
        text = replace(text, '["ps",', '["/bin/ps",', 1)
    path.write_text(text)
