#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 15 ]; then
  printf 'Brave YouTube activation: expected fifteen fixed arguments\n' >&2
  exit 1
fi

common=$1
target_user=$2
user_home=$3
source_app=$4
launcher_template=$5
theme_manifest=$6
generate_icon=$7
generate_theme_assets=$8
python_bin=$9
iconutil_bin=${10}
plist_buddy=${11}
codesign_bin=${12}
lsregister_bin=${13}
qlmanage_bin=${14}
bundle_id=${15}

# shellcheck source=/dev/null
source "$common"
uh_initialize "$target_user" "$user_home"

if [ ! -d "$source_app" ] || [ -L "$source_app" ]; then
  uh_fail "the Nix-store Brave source app is not an ordinary directory"
fi

applications_dir="$user_home/Applications"
library_dir="$user_home/Library"
application_support_dir="$library_dir/Application Support"
profile_dir="$application_support_dir/Brave YouTube"
old_profile_dir="$application_support_dir/YouTube Brave"
theme_dir="$profile_dir/brave-youtube-theme"
app_bundle="$applications_dir/Brave YouTube.app"
chrome_apps_dir="$applications_dir/Chrome Apps.localized"
old_chrome_app="$chrome_apps_dir/YouTube.app"

uh_ensure_directory "$applications_dir" "user Applications root" "$user_home" 0755
uh_ensure_directory "$library_dir" "user Library root" "$user_home" 0700
uh_ensure_directory "$application_support_dir" "user Application Support root" "$library_dir" 0700

plist_set_or_add() {
  local plist=$1 key=$2 type=$3 value=$4
  if "$plist_buddy" -c "Print :$key" "$plist" >/dev/null 2>&1; then
    "$plist_buddy" -c "Set :$key $value" "$plist"
  else
    "$plist_buddy" -c "Add :$key $type $value" "$plist"
  fi
}

plist_delete_if_present() {
  local plist=$1 key=$2
  "$plist_buddy" -c "Delete :$key" "$plist" >/dev/null 2>&1 || true
}

remove_or_backup_app() {
  local target=$1 expected_bundle_id=$2 actual_bundle_id=
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi
  if [ -L "$target" ] || [ ! -d "$target" ]; then
    uh_preserve_path "$target" "Brave YouTube app conflict"
    return 0
  fi
  uh_require_owned_directory "$target" "existing Brave YouTube app"
  actual_bundle_id=$("$plist_buddy" -c 'Print :CFBundleIdentifier' "$target/Contents/Info.plist" 2>/dev/null || true)
  if [ "$actual_bundle_id" = "$expected_bundle_id" ]; then
    /bin/rm -rf "$target" \
      || uh_fail "could not replace the existing managed Brave YouTube app"
  else
    uh_preserve_path "$target" "wrong-identity Brave YouTube app"
  fi
}

if [ -e "$chrome_apps_dir" ] || [ -L "$chrome_apps_dir" ]; then
  uh_require_owned_directory "$chrome_apps_dir" "legacy Chrome Apps root"
  if [ -L "$old_chrome_app" ]; then
    uh_preserve_path "$old_chrome_app" "legacy Chrome YouTube app link"
  elif [ -d "$old_chrome_app" ]; then
    uh_require_owned_directory "$old_chrome_app" "legacy Chrome YouTube app"
    old_shortcut_id=$("$plist_buddy" -c 'Print :CrAppModeShortcutID' "$old_chrome_app/Contents/Info.plist" 2>/dev/null || true)
    if [ "$old_shortcut_id" = agimnkijcaahngcdmfeangaknmldooml ]; then
      /bin/rm -rf "$old_chrome_app"
    fi
  fi
fi

# Public-preview migration boundary: historical private pre-curation app bundle cleanup is omitted.
remove_or_backup_app "$app_bundle" "$bundle_id"

if [ ! -e "$profile_dir" ] && [ ! -L "$profile_dir" ] && { [ -e "$old_profile_dir" ] || [ -L "$old_profile_dir" ]; }; then
  uh_require_owned_directory "$old_profile_dir" "legacy Brave YouTube profile"
  /bin/mv "$old_profile_dir" "$profile_dir"
fi
uh_ensure_directory "$profile_dir" "Brave YouTube profile" "$application_support_dir" 0700
uh_ensure_directory "$theme_dir" "Brave YouTube theme root" "$profile_dir" 0700

if ! /bin/cp -cR "$source_app" "$app_bundle"; then
  /bin/rm -rf "$app_bundle"
  /bin/cp -R "$source_app" "$app_bundle"
fi
/usr/bin/find -P "$app_bundle" -type d -exec /bin/chmod u+rwx {} +
/usr/bin/find -P "$app_bundle" -type f -exec /bin/chmod u+rw {} +

contents="$app_bundle/Contents"
macos="$contents/MacOS"
resources="$contents/Resources"
launcher="$macos/Brave YouTube"
browser_bin="$macos/Brave YouTube.bin"
source_plist="$source_app/Contents/Info.plist"

if [ -f "$macos/Brave Browser" ]; then
  /bin/mv "$macos/Brave Browser" "$browser_bin"
fi
source_short_version=$("$plist_buddy" -c 'Print :CFBundleShortVersionString' "$source_plist" 2>/dev/null || true)
source_bundle_version=$("$plist_buddy" -c 'Print :CFBundleVersion' "$source_plist" 2>/dev/null || true)
[ -n "$source_short_version" ] || source_short_version=1.0
[ -n "$source_bundle_version" ] || source_bundle_version=$source_short_version

/usr/bin/sed -e "s|@USER_NAME@|$target_user|g" "$launcher_template" >"$launcher"
/bin/chmod 0755 "$launcher" "$browser_bin"

plist="$contents/Info.plist"
plist_set_or_add "$plist" CFBundleDisplayName string "Brave YouTube"
plist_set_or_add "$plist" CFBundleExecutable string "Brave YouTube"
plist_set_or_add "$plist" CFBundleIconFile string brave-youtube.icns
plist_set_or_add "$plist" CFBundleIdentifier string "$bundle_id"
plist_set_or_add "$plist" CFBundleName string "Brave YouTube"
plist_set_or_add "$plist" CFBundlePackageType string APPL
plist_set_or_add "$plist" CFBundleShortVersionString string "$source_short_version"
plist_set_or_add "$plist" CFBundleVersion string "$source_bundle_version"
for key in \
  CFBundleIconName CFBundleDocumentTypes CFBundleURLTypes \
  ASWebAuthenticationSessionWebBrowserSupportCapabilities CrProductDirName \
  KSProductID KSVersion SMPrivilegedExecutables SUEnableSystemProfiling SUPublicEDKey; do
  plist_delete_if_present "$plist" "$key"
done

/bin/rm -f "$contents/Library/LaunchServices/com.brave.Browser.UpdaterPrivilegedHelper"
/usr/bin/find "$contents/Frameworks/Brave Browser Framework.framework/Versions" \
  -path '*/Helpers/BraveUpdater.app' -type d -prune -exec /bin/rm -rf {} +
/usr/bin/find "$contents/Frameworks/Brave Browser Framework.framework/Versions" \
  -path '*/Frameworks/Sparkle.framework' -type d -prune -exec /bin/rm -rf {} +
printf 'APPL????\n' >"$contents/PkgInfo"

iconset=$(/usr/bin/mktemp -d /private/tmp/brave-youtube-icon.XXXXXX.iconset)
"$python_bin" "$generate_icon" "$iconset"
"$iconutil_bin" -c icns "$iconset" -o "$resources/brave-youtube.icns" >/dev/null
/bin/cp "$resources/brave-youtube.icns" "$resources/app.icns"
/bin/rm -rf "$iconset"

for generated_theme_path in manifest.json theme_frame.png theme_toolbar.png theme_ntp_background.png; do
  if [ -e "$theme_dir/$generated_theme_path" ] || [ -L "$theme_dir/$generated_theme_path" ]; then
    /bin/rm -rf "${theme_dir:?}/$generated_theme_path"
  fi
done
/usr/bin/install -m 0644 "$theme_manifest" "$theme_dir/manifest.json"
"$python_bin" "$generate_theme_assets" "$theme_dir"

"$codesign_bin" --force --deep --sign - "$app_bundle" >/dev/null 2>&1 || true
/usr/bin/touch "$app_bundle" "$contents/Info.plist" "$resources/brave-youtube.icns"
"$lsregister_bin" -u "$app_bundle" || true
"$lsregister_bin" -f "$app_bundle" || true
"$qlmanage_bin" -r cache >/dev/null 2>&1 || true
