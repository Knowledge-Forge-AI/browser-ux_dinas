#!/usr/bin/env bats

@test "brave-youtube-session.unit.test" {
set -euo pipefail

script_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
repo_dir="$(cd "$script_dir/../../../.." && pwd)"

fail() {
  echo "test-brave-youtube-session: $*" >&2
  exit 1
}

session_file="$repo_dir/bin/brave-youtube-session"
audit_helper="$repo_dir/libexec/brave-youtube/profile-extension-audit.py"
debug_port_helper="$repo_dir/libexec/brave-youtube/allocate-debug-port.py"
plist_helper="$repo_dir/libexec/brave-youtube/write-launch-plist.py"
notification_helper="$repo_dir/libexec/brave-youtube/display-notification.applescript"
sleep_disabled_helper="$repo_dir/libexec/brave-youtube/pmset-sleep-disabled.awk"
power_source_helper="$repo_dir/libexec/brave-youtube/pmset-power-source.awk"
battery_percent_helper="$repo_dir/libexec/brave-youtube/pmset-battery-percent.awk"

[ -f "$session_file" ] || fail "missing bin/brave-youtube-session"
[ -f "$audit_helper" ] || fail "missing libexec/brave-youtube/profile-extension-audit.py"
[ -f "$debug_port_helper" ] || fail "missing libexec/brave-youtube/allocate-debug-port.py"
[ -f "$plist_helper" ] || fail "missing libexec/brave-youtube/write-launch-plist.py"
[ -f "$notification_helper" ] || fail "missing libexec/brave-youtube/display-notification.applescript"
[ -f "$sleep_disabled_helper" ] || fail "missing libexec/brave-youtube/pmset-sleep-disabled.awk"
[ -f "$power_source_helper" ] || fail "missing libexec/brave-youtube/pmset-power-source.awk"
[ -f "$battery_percent_helper" ] || fail "missing libexec/brave-youtube/pmset-battery-percent.awk"

bash -n "$session_file"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$audit_helper" \
  || fail "Brave YouTube profile extension audit helper must compile"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$debug_port_helper" \
  || fail "Brave YouTube debug port helper must compile"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$plist_helper" \
  || fail "Brave YouTube launchd plist helper must compile"

for command_name in start open stop status is-active daemon; do
  rg -F -q "$command_name" "$session_file" \
    || fail "usage and command dispatch must mention $command_name"
done

for default_chain in \
  'BRAVE_YOUTUBE_URL:-${YOUTUBE_BRAVE_URL:-${YOUTUBE_CHROME_URL:-https://www.youtube.com/}}' \
  'BRAVE_YOUTUBE_APP_BUNDLE:-${YOUTUBE_BRAVE_APP_BUNDLE:-$HOME/Applications/Brave YouTube.app}' \
  'BRAVE_YOUTUBE_BIN:-${YOUTUBE_BRAVE_BIN:-$browser_app_bundle/Contents/MacOS/Brave YouTube.bin}' \
  'BRAVE_YOUTUBE_USER_DATA_DIR:-${YOUTUBE_BRAVE_USER_DATA_DIR:-$HOME/Library/Application Support/Brave YouTube}' \
  'BRAVE_YOUTUBE_LOW_BATTERY_PERCENT:-${YOUTUBE_BRAVE_LOW_BATTERY_PERCENT:-${YOUTUBE_CHROME_LOW_BATTERY_PERCENT:-20}}' \
  'BRAVE_YOUTUBE_CHECK_INTERVAL:-${YOUTUBE_BRAVE_CHECK_INTERVAL:-${YOUTUBE_CHROME_CHECK_INTERVAL:-15}}'
do
  rg -F -q "$default_chain" "$session_file" \
    || fail "session script must preserve environment fallback: $default_chain"
done

for state_file in \
  'session.pid' \
  'caffeinate.pid' \
  'previous-sleep-disabled' \
  'power-active' \
  'debug-port' \
  'media-state' \
  'session.log'
do
  rg -F -q "$state_file" "$session_file" \
    || fail "session state must include $state_file"
done

plist_tmp="$(mktemp)"
cleanup() {
  rm -f "$plist_tmp"
}
trap cleanup EXIT

rg -F -q '/usr/bin/python3 "$(script_dir)/../libexec/brave-youtube/write-launch-plist.py" "$launch_plist_file" "$launch_label" "$self" "$log_file"' "$session_file" \
  || fail "session script must delegate launchd plist writing to the Python helper"
if rg -F -q 'cat >"$launch_plist_file" <<PLIST' "$session_file"; then
  fail "session script must not embed launchd XML plist heredocs"
fi

python3 "$plist_helper" "$plist_tmp" "local.test.brave-youtube" "/tmp/Brave YouTube Session" "/tmp/brave-youtube-session.log"
/usr/bin/plutil -lint "$plist_tmp" >/dev/null \
  || fail "launchd plist helper must write valid XML/plist syntax"
for plist_key in Label ProgramArguments RunAtLoad KeepAlive StandardOutPath StandardErrorPath; do
  rg -F -q "<key>$plist_key</key>" "$plist_tmp" \
    || fail "launchd plist must include $plist_key"
done

rg -F -q 'usage: display-notification.applescript TITLE MESSAGE' "$notification_helper" \
  || fail "Brave YouTube notification helper must document its title/message arguments"
rg -F -q '/usr/bin/osascript "$(script_dir)/../libexec/brave-youtube/display-notification.applescript" "$app_name" "$message"' "$session_file" \
  || fail "session script must delegate notifications to the AppleScript helper"
if rg -F -q '/usr/bin/osascript -e "display notification' "$session_file"; then
  fail "session script must not embed AppleScript notification source"
fi

rg -F -q '/usr/bin/awk -f "$(script_dir)/../libexec/brave-youtube/pmset-sleep-disabled.awk"' "$session_file" \
  || fail "session script must delegate SleepDisabled parsing to the libexec awk helper"
rg -F -q '/usr/bin/awk -f "$(script_dir)/../libexec/brave-youtube/pmset-power-source.awk"' "$session_file" \
  || fail "session script must delegate power source parsing to the libexec awk helper"
rg -F -q '/usr/bin/awk -f "$(script_dir)/../libexec/brave-youtube/pmset-battery-percent.awk"' "$session_file" \
  || fail "session script must delegate battery percent parsing to the libexec awk helper"
if rg -F -q "/SleepDisabled/ { print \$2; found=1; exit } END { if (!found) print 0 }" "$session_file"; then
  fail "session script must not embed the SleepDisabled awk program"
fi
if rg -F -q "/Now drawing from/ { print \$2; exit }" "$session_file"; then
  fail "session script must not embed the power source awk program"
fi
if rg -F -q 'match($0, /[0-9]+%;/)' "$session_file"; then
  fail "session script must not embed the battery percent awk program"
fi

rg -F -q '/usr/bin/python3 "$(script_dir)/../libexec/brave-youtube/profile-extension-audit.py" "$secure_preferences" "$theme_extension_dir" "$clear_new_tab_extension_dir" "$clear_new_tab_extension_id"' "$session_file" \
  || fail "session script must delegate extension audit to the Python helper"
if rg -F -q '/usr/bin/python3 - "$secure_preferences"' "$session_file"; then
  fail "session script must not embed the extension audit Python heredoc"
fi
rg -F -q '/usr/bin/python3 "$(script_dir)/../libexec/brave-youtube/allocate-debug-port.py"' "$session_file" \
  || fail "session script must delegate debug port allocation to the Python helper"
if rg -F -q "/usr/bin/python3 -c 'import socket;" "$session_file"; then
  fail "session script must not embed debug port Python code"
fi

debug_port="$(python3 "$debug_port_helper")"
case "$debug_port" in
  *[!0-9]*|'')
    fail "debug port helper must print a numeric port; got $debug_port"
    ;;
esac

sleep_sample='System-wide power settings:
 SleepDisabled          1'
sleep_output="$(printf '%s\n' "$sleep_sample" | /usr/bin/awk -f "$sleep_disabled_helper")"
[ "$sleep_output" = "1" ] \
  || fail "SleepDisabled parser must print the configured value; got $sleep_output"
sleep_default_output="$(printf '%s\n' 'System-wide power settings:' | /usr/bin/awk -f "$sleep_disabled_helper")"
[ "$sleep_default_output" = "0" ] \
  || fail "SleepDisabled parser must default to 0 when the setting is absent; got $sleep_default_output"

power_source_sample="Now drawing from 'Battery Power'"
power_source_output="$(printf '%s\n' "$power_source_sample" | /usr/bin/awk -f "$power_source_helper")"
[ "$power_source_output" = "Battery Power" ] \
  || fail "power source parser must print the quoted power source; got $power_source_output"

battery_sample="Now drawing from 'Battery Power'
 -InternalBattery-0 (id=1234567)	84%; discharging; 4:01 remaining present: true"
battery_output="$(printf '%s\n' "$battery_sample" | /usr/bin/awk -f "$battery_percent_helper")"
[ "$battery_output" = "84" ] \
  || fail "battery parser must print the numeric percent; got $battery_output"

for allowed_extension in \
  'brave-youtube-theme' \
  'clear-new-tab-extension' \
  'location not in (5, 8)' \
  'main_chrome_ids'
do
  rg -F -q "$allowed_extension" "$audit_helper" \
    || fail "extension audit must preserve rule: $allowed_extension"
done

for power_command in \
  '"$sudo_bin" -n "$pmset_bin" -a disablesleep 1' \
  '"$sudo_bin" -n "$pmset_bin" -a disablesleep 0'
do
  rg -F -q "$power_command" "$session_file" \
    || fail "video session power management must use non-interactive sudo command: $power_command"
done

rg -F -q '"$caffeinate_bin" -d -i -m -u &' "$session_file" \
  || fail "video session must run caffeinate with display, idle, disk, and user activity assertions"
rg -F -q 'trap cleanup EXIT' "$session_file" \
  || fail "daemon must restore power state on exit"
rg -F -q 'trap request_stop INT TERM HUP' "$session_file" \
  || fail "daemon must request browser shutdown on termination signals"
rg -F -q 'sleep_disabled >"$previous_sleep_file"' "$session_file" \
  || fail "daemon must preserve previous SleepDisabled state"

for browser_flag in \
  '--brave-youtube-internal' \
  '--user-data-dir=$browser_user_data_dir' \
  '--profile-directory=Default' \
  '--no-first-run' \
  '--no-default-browser-check' \
  '--disable-sync' \
  '--disable-extensions-except=$extension_dirs' \
  '--load-extension=$extension_dirs' \
  '--disable-component-extensions-with-background-pages' \
  '--remote-debugging-address=127.0.0.1' \
  '--remote-debugging-port=$debug_port' \
  '--new-window'
do
  rg -F -q -- "$browser_flag" "$session_file" \
    || fail "browser launch must include flag $browser_flag"
done

rg -F -q 'if [ "$current_source" = "Battery Power" ]' "$session_file" \
  || fail "session must check battery power source"
rg -F -q '[ "$current_battery" -le "$low_battery_percent" ]' "$session_file" \
  || fail "session must stop or refuse startup at low battery"
rg -F -q 'if [ "$media_kind" = "not_playing" ]; then' "$session_file" \
  || fail "session must disable video power assertions when media is not playing"
rg -F -q 'enable_video_session_power' "$session_file" \
  || fail "session must enable video power assertions while media is active"
rg -F -q 'clear_new_tab_present' "$audit_helper" \
  || fail "status audit must report Clear New Tab presence"

echo "Brave YouTube session tests passed"

}
