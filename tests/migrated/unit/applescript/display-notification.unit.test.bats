#!/usr/bin/env bats

@test "display-notification AppleScript compiles and keeps notification contract" {
  set -euo pipefail

  script_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
  repo_dir="$(cd "$script_dir/../../../.." && pwd)"
  source_file="$repo_dir/libexec/brave-youtube/display-notification.applescript"
  compiled_file="$BATS_TEST_TMPDIR/display-notification.scpt"

  [ -f "$source_file" ]
  osacompile -o "$compiled_file" "$source_file"
  [ -s "$compiled_file" ]

  rg -F -q 'use scripting additions' "$source_file"
  rg -F -q 'if (count of argv) is not 2 then' "$source_file"
  rg -F -q 'error "usage: display-notification.applescript TITLE MESSAGE"' "$source_file"
  rg -F -q 'display notification notificationMessage with title appTitle' "$source_file"
}
