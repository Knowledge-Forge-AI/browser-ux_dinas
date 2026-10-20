#!/usr/bin/env python3
import json
import os
import sys


MAIN_CHROME_IDS = {
    "ddkjiahejlhfcafbddmgiahcphecmpfh",
    "oboonakemofpalcgghocfoadofidjkkk",
    "hlkenndednhfkekhgcdicdfddnkalmdm",
    "hoombieeljmmljlkjmnheibnpciblicm",
    "efaidnbmnnnibpcajpcglclefindmkaj",
    "lmjnegcaeklhafolokijcfjliaokphfk",
    "ckkdlimhmcjmikdlpkmbgfkaikojcbjk",
    "efknglbfhoddmmfabeihlemgekhhnabb",
}


def load_secure_preferences(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        print("profile_not_created")
        raise SystemExit(0)
    except Exception as error:
        print(f"unknown reason={type(error).__name__}")
        raise SystemExit(0)


def normalized_location(value):
    return int(value) if str(value).isdigit() else value


def main():
    secure_preferences = sys.argv[1]
    theme_extension_dir = os.path.realpath(sys.argv[2])
    clear_new_tab_extension_dir = os.path.realpath(sys.argv[3])
    clear_new_tab_extension_id = sys.argv[4]

    data = load_secure_preferences(secure_preferences)
    settings = data.get("extensions", {}).get("settings", {})
    main_present = sorted(extension_id for extension_id in settings if extension_id in MAIN_CHROME_IDS)
    non_theme = []
    theme_present = False
    clear_new_tab_present = False

    for extension_id, value in settings.items():
        path = str(value.get("path", ""))
        real_path = os.path.realpath(path) if path else ""
        location = normalized_location(value.get("location", -1))
        if real_path == theme_extension_dir:
            theme_present = True
        elif extension_id == clear_new_tab_extension_id or real_path == clear_new_tab_extension_dir:
            clear_new_tab_present = True
        elif extension_id in MAIN_CHROME_IDS:
            continue
        elif (
            path
            and "Brave YouTube/brave-youtube-theme" not in path
            and "Brave YouTube/clear-new-tab-extension" not in path
            and location not in (5, 8)
        ):
            non_theme.append(extension_id)

    print(
        "theme="
        + ("present" if theme_present else "missing")
        + " clear_new_tab="
        + ("present" if clear_new_tab_present else "missing")
        + " main_chrome_ids="
        + (",".join(main_present) if main_present else "none")
        + " non_theme_extensions="
        + (",".join(sorted(non_theme)) if non_theme else "none")
    )


if __name__ == "__main__":
    main()
