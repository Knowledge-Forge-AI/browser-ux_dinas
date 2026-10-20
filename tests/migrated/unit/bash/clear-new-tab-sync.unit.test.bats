#!/usr/bin/env bats

@test "clear-new-tab-sync.unit.test" {
set -euo pipefail

script_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
repo_dir="$(cd "$script_dir/../../../.." && pwd)"

fail() {
  echo "test-clear-new-tab-sync: $*" >&2
  exit 1
}

sync_script="$repo_dir/bin/clear-new-tab-sync"
consumer_helper="$repo_dir/libexec/clear-new-tab/brave-youtube-consumer.py"
extension_id="felphkbfjadmcejnibcmcncimlappdde"

[ -f "$sync_script" ] || fail "missing bin/clear-new-tab-sync"
[ -f "$consumer_helper" ] || fail "missing libexec/clear-new-tab/brave-youtube-consumer.py"

bash -n "$sync_script" || fail "clear-new-tab-sync must be valid Bash"
python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], "exec")' "$consumer_helper" \
  || fail "Clear New Tab durable-state consumer helper must compile"

rg -F -q 'exec /usr/bin/python3 -I -B "$(clear_new_tab_libexec_dir)/brave-youtube-consumer.py" "$@"' "$sync_script" \
  || fail "clear-new-tab-sync must delegate to the durable-state consumer helper"
if rg -F -q "<<'PY'" "$sync_script"; then
  fail "clear-new-tab-sync must not embed Python heredocs"
fi

# BUX5B1 CONSUMER-ADAPT1: the normal Chrome profile is no longer an authority or a fallback.
for forbidden in \
  'Google/Chrome' \
  'IndexedDB' \
  'Local Extension Settings' \
  'sync_dir' \
  'CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE' \
  'latest-source-extension-dir' \
  "$extension_id" \
  '/bin/cp' \
  '/bin/mv' \
  '/bin/rm'
do
  if rg -F -q -- "$forbidden" "$sync_script"; then
    fail "clear-new-tab-sync must not reference retired Chrome authority: $forbidden"
  fi
done

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

home="$tmp_dir/home"
profile="$home/Library/Application Support/Google/Chrome/Default"
target="$tmp_dir/brave"
mkdir -p "$profile/Extensions/$extension_id/1.10.0" "$target/Default"
printf '{}' > "$target/Default/Preferences"
before="$(cd "$tmp_dir" && find . -print | LC_ALL=C sort)"

output="$(env -i HOME="$home" PATH=/usr/bin:/bin CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE="$profile" \
  BRAVE_YOUTUBE_USER_DATA_DIR="$target" "$sync_script" status)" \
  || fail "status must succeed read-only"
[[ "$output" == *"authority: browser-ux-durable-state"* ]] || fail "status must name durable state as authority"
[[ "$output" == *"state_root_present: absent"* ]] || fail "status must not create the default root"
[[ "$output" == *"brave_youtube_consumer: REFUSED MANIFEST_SELECTION_REQUIRED"* ]] \
  || fail "status must report the bounded consumer verdict"
[[ "$output" != *"1.10.0"* ]] || fail "status must not consult the legacy Chrome profile"

set +e
refusal="$(env -i HOME="$home" PATH=/usr/bin:/bin BRAVE_YOUTUBE_USER_DATA_DIR="$target" \
  "$sync_script" brave-youtube 2>&1 >/dev/null)"
status=$?
set -e
[ "$status" -eq 3 ] || fail "brave-youtube without a selected manifest must refuse with status 3; got $status"
[ "$refusal" = "clear-new-tab-sync: refused: MANIFEST_SELECTION_REQUIRED" ] \
  || fail "unexpected brave-youtube refusal: $refusal"

after="$(cd "$tmp_dir" && find . -print | LC_ALL=C sort)"
[ "$before" = "$after" ] || fail "status and refused brave-youtube must not create, copy or remove anything"

echo "Clear New Tab sync tests passed"

}
