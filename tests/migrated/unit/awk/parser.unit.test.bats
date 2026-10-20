#!/usr/bin/env bats

repo_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../../../.." && pwd)"

run_awk_file() {
  local awk_file="$1"
  local input="$2"
  shift 2

  printf '%s' "$input" | awk "$@" -f "$awk_file"
}
@test "pmset power source parser extracts the active source" {
  run run_awk_file \
    "$repo_dir/libexec/brave-youtube/pmset-power-source.awk" \
    "Now drawing from 'Battery Power'
 -InternalBattery-0 (id=1234567)	82%; discharging; 3:12 remaining present: true"

  [ "$status" -eq 0 ]
  [ "$output" = "Battery Power" ]
}

# nix-darwin-test-source-target: libexec/brave-youtube/first-field.awk
@test "first field parser extracts the leading token" {
  run run_awk_file \
    "$repo_dir/libexec/brave-youtube/first-field.awk" \
    "pages count=1
ignored"

  [ "$status" -eq 0 ]
  [ "$output" = "pages" ]
}

@test "pmset battery percent parser extracts the numeric percent" {
  run run_awk_file \
    "$repo_dir/libexec/brave-youtube/pmset-battery-percent.awk" \
    "Now drawing from 'AC Power'
 -InternalBattery-0 (id=1234567)	100%; charged; 0:00 remaining present: true"

  [ "$status" -eq 0 ]
  [ "$output" = "100" ]
}

@test "pmset sleep disabled parser defaults to 0 when assertion is absent" {
  run run_awk_file \
    "$repo_dir/libexec/brave-youtube/pmset-sleep-disabled.awk" \
    "Assertion status system-wide:
   PreventUserIdleDisplaySleep    0"

  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
}

@test "pmset sleep disabled parser reports the assertion value" {
  run run_awk_file \
    "$repo_dir/libexec/brave-youtube/pmset-sleep-disabled.awk" \
    "Assertion status system-wide:
   SleepDisabled                  1"

  [ "$status" -eq 0 ]
  [ "$output" = "1" ]
}
