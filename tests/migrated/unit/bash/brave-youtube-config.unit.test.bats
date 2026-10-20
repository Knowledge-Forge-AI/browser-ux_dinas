#!/usr/bin/env bats

@test "brave-youtube-config.unit.test" {
set -euo pipefail

script_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
repo_dir="$(cd "$script_dir/../../../.." && pwd)"

fail() {
  echo "test-brave-youtube-config: $*" >&2
  exit 1
}

module_source_file="$repo_dir/modules/brave-youtube.nix"
writer_file="$repo_dir/modules/brave-youtube-app-writer.sh"
module_file="$BATS_TEST_TMPDIR/brave-youtube-implementation"
cat "$module_source_file" "$writer_file" >"$module_file"
session_file="$repo_dir/bin/brave-youtube-session"
launcher_template="$repo_dir/config/brave-youtube/launcher.sh.template"
theme_manifest="$repo_dir/config/brave-youtube/theme-manifest.json"
icon_generator="$repo_dir/libexec/brave-youtube/generate-icon.py"
theme_asset_generator="$repo_dir/libexec/brave-youtube/generate-theme-assets.py"

[ -f "$module_file" ] || fail "missing modules/brave-youtube.nix"
[ -f "$session_file" ] || fail "missing bin/brave-youtube-session"
[ -f "$launcher_template" ] || fail "missing config/brave-youtube/launcher.sh.template"
[ -f "$theme_manifest" ] || fail "missing config/brave-youtube/theme-manifest.json"
[ -f "$icon_generator" ] || fail "missing libexec/brave-youtube/generate-icon.py"
[ -f "$theme_asset_generator" ] || fail "missing libexec/brave-youtube/generate-theme-assets.py"

bash -n "$launcher_template" || fail "Brave YouTube launcher template must be valid Bash"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$icon_generator" \
  || fail "Brave YouTube icon generator must compile"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$theme_asset_generator" \
  || fail "Brave YouTube theme asset generator must compile"
jq empty "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme manifest config must be valid JSON"

rg -F -q 'braveYoutubeLauncherTemplate = ../config/brave-youtube/launcher.sh.template;' "$module_file" \
  || fail "Brave YouTube module must source config/brave-youtube/launcher.sh.template"
rg -F -q 'braveYoutubeThemeManifest = ../config/brave-youtube/theme-manifest.json;' "$module_file" \
  || fail "Brave YouTube module must source config/brave-youtube/theme-manifest.json"
rg -F -q 'braveYoutubeGenerateIcon = ../libexec/brave-youtube/generate-icon.py;' "$module_file" \
  || fail "Brave YouTube module must source libexec/brave-youtube/generate-icon.py"
rg -F -q 'braveYoutubeGenerateThemeAssets = ../libexec/brave-youtube/generate-theme-assets.py;' "$module_file" \
  || fail "Brave YouTube module must source libexec/brave-youtube/generate-theme-assets.py"
rg -F -q '/usr/bin/sed -e "s|@USER_NAME@|$target_user|g" "$launcher_template" >"$launcher"' "$module_file" \
  || fail "Brave YouTube launcher must be rendered from its template"
rg -F -q '/usr/bin/install -m 0644 "$theme_manifest" "$theme_dir/manifest.json"' "$module_file" \
  || fail "Brave YouTube theme manifest must be installed from its config file"
rg -F -q '"$python_bin" "$generate_icon" "$iconset"' "$module_file" \
  || fail "Brave YouTube icon generator must be invoked from its source file"
rg -F -q '"$python_bin" "$generate_theme_assets" "$theme_dir"' "$module_file" \
  || fail "Brave YouTube theme asset generator must be invoked from its source file"
if rg -F -q 'cat >"$launcher" <<'\''APP'\''' "$module_file"; then
  fail "Brave YouTube module must not embed the launcher Bash heredoc"
fi
if rg -F -q 'cat >"$themeDir/manifest.json" <<'\''JSON'\''' "$module_file"; then
  fail "Brave YouTube module must not embed the theme manifest JSON heredoc"
fi
if rg -F -q '/usr/bin/python3 - "$iconset" <<'\''PY'\''' "$module_file"; then
  fail "Brave YouTube module must not embed the icon generator Python heredoc"
fi
if rg -F -q '/usr/bin/python3 - "$themeDir" <<'\''PY'\''' "$module_file"; then
  fail "Brave YouTube module must not embed the theme asset generator Python heredoc"
fi

rg -F -q '"${pkgs.brave}/Applications/Brave Browser.app"' "$module_file" \
  || fail "Brave YouTube must be built from the Nix Brave app"
rg -F -q 'app_bundle="$applications_dir/Brave YouTube.app"' "$module_file" \
  || fail "Brave YouTube app bundle path must stay stable"
rg -F -q 'profile_dir="$application_support_dir/Brave YouTube"' "$module_file" \
  || fail "Brave YouTube profile path must stay stable"
rg -F -q 'theme_dir="$profile_dir/brave-youtube-theme"' "$module_file" \
  || fail "Brave YouTube theme path must stay profile-local"

for legacy_path in \
  'old_chrome_app="$chrome_apps_dir/YouTube.app"' \
  'old_profile_dir="$application_support_dir/YouTube Brave"'
do
  rg -F -q "$legacy_path" "$module_file" \
    || fail "Brave YouTube migration must know legacy path: $legacy_path"
done

rg -F -q 'remove_or_backup_app "$app_bundle" "$bundle_id"' "$module_file" \
  || fail "Brave YouTube must safely remove or back up current app bundle"
[ "$(rg -c 'remove_or_backup_app' "$writer_file")" -eq 2 ] \
  || fail "Brave YouTube writer must only invoke remove_or_backup_app for the current app bundle"
for omitted_legacy in \
  'old_renamed_app' \
  'old_managed_app'
do
  if rg -F -q "$omitted_legacy" "$module_file"; then
    fail "Brave YouTube public preview must not reference omitted legacy app cleanup variable: $omitted_legacy"
  fi
done

rg -F -q 'old_shortcut_id=$("$plist_buddy" -c '\''Print :CrAppModeShortcutID'\''' "$module_file" \
  || fail "Brave YouTube must identify the old Chrome app by shortcut id"
rg -F -q 'agimnkijcaahngcdmfeangaknmldooml' "$module_file" \
  || fail "Brave YouTube must know the old YouTube Chrome shortcut id"
rg -F -q '/bin/mv "$old_profile_dir" "$profile_dir"' "$module_file" \
  || fail "Brave YouTube must migrate the old Brave YouTube profile directory"

rg -F -q '/bin/cp -cR "$source_app" "$app_bundle"' "$module_file" \
  || fail "Brave YouTube should use clonefile copy when available"
rg -F -q '/bin/cp -R "$source_app" "$app_bundle"' "$module_file" \
  || fail "Brave YouTube must fall back to recursive copy"
rg -F -q '/bin/mv "$macos/Brave Browser" "$browser_bin"' "$module_file" \
  || fail "Brave YouTube must move the real Brave binary behind the wrapper"

rg -F -q 'session="/Users/@USER_NAME@/.local/nbin/dinas/brave-youtube-session"' "$launcher_template" \
  || fail "launcher must delegate session management to brave-youtube-session"
rg -F -q -- '--brave-youtube-internal' "$launcher_template" \
  || fail "launcher must support internal launch mode"
rg -F -q 'exec "$self_dir/Brave YouTube.bin"' "$launcher_template" \
  || fail "launcher internal mode must exec the real Brave binary"
rg -F -q 'args[@]' "$launcher_template" \
  || fail "launcher internal mode must forward user arguments"
rg -F -q '"$session" start >/dev/null 2>&1' "$launcher_template" \
  || fail "launcher normal mode must start the managed video session"

for plist_set in \
  'plist_set_or_add "$plist" CFBundleDisplayName string "Brave YouTube"' \
  'plist_set_or_add "$plist" CFBundleExecutable string "Brave YouTube"' \
  'plist_set_or_add "$plist" CFBundleIconFile string brave-youtube.icns' \
  'plist_set_or_add "$plist" CFBundleIdentifier string "$bundle_id"' \
  'plist_set_or_add "$plist" CFBundleName string "Brave YouTube"' \
  'plist_set_or_add "$plist" CFBundlePackageType string APPL' \
  'plist_set_or_add "$plist" CFBundleShortVersionString string "$source_short_version"' \
  'plist_set_or_add "$plist" CFBundleVersion string "$source_bundle_version"'
do
  rg -F -q "$plist_set" "$module_file" \
    || fail "Brave YouTube Info.plist must set: $plist_set"
done

for deleted_key in \
  CFBundleIconName \
  CFBundleDocumentTypes \
  CFBundleURLTypes \
  ASWebAuthenticationSessionWebBrowserSupportCapabilities \
  CrProductDirName \
  KSProductID \
  KSVersion \
  SMPrivilegedExecutables \
  SUEnableSystemProfiling \
  SUPublicEDKey
do
  rg -F -q "$deleted_key" "$module_file" \
    || fail "Brave YouTube inherited-key list must include $deleted_key"
done
rg -F -q 'plist_delete_if_present "$plist" "$key"' "$module_file" \
  || fail "Brave YouTube must delete every inherited key through the bounded helper"

for updater_cleanup in \
  '/bin/rm -f "$contents/Library/LaunchServices/com.brave.Browser.UpdaterPrivilegedHelper"' \
  "-path '*/Helpers/BraveUpdater.app' -type d -prune -exec /bin/rm -rf {} +" \
  "-path '*/Frameworks/Sparkle.framework' -type d -prune -exec /bin/rm -rf {} +"
do
  rg -F -q -- "$updater_cleanup" "$module_file" \
    || fail "Brave YouTube must strip updater component: $updater_cleanup"
done

jq -e '.manifest_version == 3' "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme manifest must use Manifest V3"
jq -e '.name == "Brave YouTube Theme"' "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme manifest must have the expected name"
for image_key in theme_frame theme_toolbar theme_ntp_background; do
  jq -e --arg image_key "$image_key" '.theme.images[$image_key] | type == "string"' "$theme_manifest" >/dev/null \
    || fail "Brave YouTube theme manifest must define image $image_key"
done
jq -e '.theme.colors.frame == [0, 0, 0]' "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme must keep a black frame"
jq -e '.theme.colors.toolbar_button_icon == [255, 0, 0]' "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme must keep red toolbar icons"
jq -e '.theme.properties.ntp_background_repeat == "no-repeat"' "$theme_manifest" >/dev/null \
  || fail "Brave YouTube theme must not tile the NTP background"

rg -F -q 'write_png(os.path.join(iconset, name), size)' "$icon_generator" \
  || fail "Brave YouTube icon generator must render each iconset size"

for generated_asset in \
  'write_png(os.path.join(theme_dir, "theme_frame.png"), 3000, 220, frame_pixel)' \
  'write_png(os.path.join(theme_dir, "theme_toolbar.png"), 3000, 120, toolbar_pixel)' \
  'write_png(os.path.join(theme_dir, "theme_ntp_background.png"), 1600, 1000, ntp_pixel)'
do
  rg -F -q "$generated_asset" "$theme_asset_generator" \
    || fail "Brave YouTube theme asset generator must generate expected asset: $generated_asset"
done

for generated_asset in \
  '"$iconutil_bin" -c icns "$iconset" -o "$resources/brave-youtube.icns"' \
  '/bin/cp "$resources/brave-youtube.icns" "$resources/app.icns"'
do
  rg -F -q "$generated_asset" "$module_file" \
    || fail "Brave YouTube must generate expected asset: $generated_asset"
done

if rg -q '\b(chown|chgrp|sudo)\b' "$writer_file"; then
  fail "Brave YouTube writer must construct ownership as the target user"
fi
rg -F -q '"$codesign_bin" --force --deep --sign - "$app_bundle"' "$module_file" \
  || fail "Brave YouTube must ad-hoc sign the generated app bundle"
rg -F -q '"$lsregister_bin" -u "$app_bundle"' "$module_file" \
  || fail "Brave YouTube must unregister stale LaunchServices records"
rg -F -q '"$lsregister_bin" -f "$app_bundle"' "$module_file" \
  || fail "Brave YouTube must register the generated app bundle"
rg -F -q '"$qlmanage_bin" -r cache' "$module_file" \
  || fail "Brave YouTube must refresh Quick Look icon cache"
rg -F -q '/usr/bin/sudo -n -H -u "$target_user" --' "$module_source_file" \
  || fail "Brave YouTube module must cross the privilege boundary before invoking its writer"

echo "Brave YouTube config tests passed"

}
