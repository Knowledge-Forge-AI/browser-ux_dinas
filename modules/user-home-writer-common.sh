#!/bin/sh

uh_fail() {
  printf 'user-home activation: %s\n' "$*" >&2
  exit 1
}

uh_initialize() {
  [ "$#" -eq 2 ] || uh_fail "expected target user and resolved home"
  uh_target_user=$1
  uh_user_home=$2
  uh_effective_uid=$(/usr/bin/id -u) || exit 1

  [ "$uh_effective_uid" -ne 0 ] || uh_fail "refusing to mutate user-home state as root"
  [ "$(/usr/bin/id -un)" = "$uh_target_user" ] \
    || uh_fail "effective user does not match target user"
  case "$uh_user_home" in
    /*) ;;
    *) uh_fail "resolved user home is not absolute" ;;
  esac
  case "$uh_user_home" in
    /|*//*|*/./*|*/.|*/../*|*/..) uh_fail "resolved user home is not a safe canonical path" ;;
  esac

  umask 022
  uh_require_owned_directory "$uh_user_home" "resolved user home"
}

uh_require_owned_directory() {
  uh_required_directory=$1
  uh_required_description=$2

  if [ -L "$uh_required_directory" ] || [ ! -d "$uh_required_directory" ]; then
    uh_fail "$uh_required_description is not an ordinary directory; ownership/type repair is required before retry"
  fi
  if [ "$(/usr/bin/stat -f '%u' "$uh_required_directory")" != "$uh_effective_uid" ]; then
    uh_fail "$uh_required_description is not owned by the target user; ownership repair is required before retry"
  fi
  if [ ! -w "$uh_required_directory" ] || [ ! -x "$uh_required_directory" ]; then
    uh_fail "$uh_required_description is not writable and searchable by the target user; mode repair is required before retry"
  fi
}

uh_ensure_directory() {
  uh_ensure_directory_path=$1
  uh_ensure_description=$2
  uh_ensure_parent=$3
  uh_ensure_mode=${4:-0755}

  uh_require_owned_directory "$uh_ensure_parent" "parent of $uh_ensure_description"
  if [ ! -e "$uh_ensure_directory_path" ] && [ ! -L "$uh_ensure_directory_path" ]; then
    /bin/mkdir -m "$uh_ensure_mode" "$uh_ensure_directory_path" \
      || uh_fail "could not create $uh_ensure_description"
  fi
  uh_require_owned_directory "$uh_ensure_directory_path" "$uh_ensure_description"
}

uh_unique_backup_path() {
  uh_backup_source=$1
  uh_backup_base="$uh_backup_source.before-nix-darwin"
  uh_backup_candidate=$uh_backup_base

  if [ -e "$uh_backup_candidate" ] || [ -L "$uh_backup_candidate" ]; then
    uh_backup_timestamp=$(/bin/date +%Y%m%d%H%M%S) \
      || uh_fail "could not timestamp a managed-path backup"
    uh_backup_candidate="$uh_backup_base.$uh_backup_timestamp"
  fi
  uh_backup_suffix=0
  while [ -e "$uh_backup_candidate" ] || [ -L "$uh_backup_candidate" ]; do
    uh_backup_suffix=$((uh_backup_suffix + 1))
    uh_backup_candidate="$uh_backup_base.${uh_backup_timestamp:-existing}.$uh_backup_suffix"
  done
  printf '%s\n' "$uh_backup_candidate"
}

uh_preserve_path() {
  uh_preserve_source=$1
  uh_preserve_description=$2
  uh_preserve_backup=$(uh_unique_backup_path "$uh_preserve_source") || exit 1
  /bin/mv "$uh_preserve_source" "$uh_preserve_backup" \
    || uh_fail "could not preserve $uh_preserve_description"
}

uh_link_managed_path() {
  uh_link_target=$1
  uh_link_source=$2
  uh_link_parent=$3
  uh_link_description=$4

  uh_require_owned_directory "$uh_link_parent" "parent of $uh_link_description"
  if [ -L "$uh_link_target" ]; then
    uh_link_current=$(/usr/bin/readlink "$uh_link_target") \
      || uh_fail "could not inspect $uh_link_description"
    if [ "$uh_link_current" = "$uh_link_source" ]; then
      return 0
    fi
    /bin/rm "$uh_link_target" || uh_fail "could not remove the old $uh_link_description link"
  elif [ -e "$uh_link_target" ]; then
    uh_preserve_path "$uh_link_target" "$uh_link_description conflict"
  fi

  /bin/ln -s "$uh_link_source" "$uh_link_target" \
    || uh_fail "could not create $uh_link_description"
}
