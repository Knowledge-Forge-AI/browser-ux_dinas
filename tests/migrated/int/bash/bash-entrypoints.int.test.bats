#!/usr/bin/env bats
# Browser UX cases adapted from core's bash-entrypoints.int.test.bats.
setup() {
  repo_dir="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../../../.." && pwd)"
}

@test "Browser UX bash entrypoints expose safe help paths" {
  for name in brave-youtube-session clear-new-tab-sync shared-images-rclone-sync; do
    run "$repo_dir/bin/$name" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
  done
}

@test "Shared Images dry-run dispatch uses configured recording rclone" {
  recorder="$BATS_TEST_TMPDIR/rclone"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" > "$RCLONE_TEST_LOG"' > "$recorder"
  chmod +x "$recorder"
  run env RCLONE="$recorder" RCLONE_TEST_LOG="$BATS_TEST_TMPDIR/log" \
    SHARED_IMAGES_LOCAL_DIR="$BATS_TEST_TMPDIR" SHARED_IMAGES_CRYPT_REMOTE="fixture:" \
    "$repo_dir/bin/shared-images-rclone-sync" dry-run-push
  [ "$status" -eq 0 ]
  grep -Fq 'sync --dry-run' "$BATS_TEST_TMPDIR/log"
}
