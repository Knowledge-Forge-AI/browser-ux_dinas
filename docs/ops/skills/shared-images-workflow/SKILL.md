---
name: shared-images-workflow
description: Maintain the shared anime image archive under $HOME/Pictures/shared-images. Use when triaging images, moving wallpapers or portraits, editing shared-images SQLite records, refreshing by-artist symlinks, promoting originals, rehashing edited files, loading Clear New Tab backgrounds, auditing the shared-images DB, or syncing the encrypted shared-images remote.
---

# Shared Images Workflow

## Overview

Use this skill to keep the shared-images archive consistent across files, SQLite rows, derived symlinks, browser imports, and encrypted sync.

## Required Context

Confirm operator-supplied archive guidance before moving files, changing DB rows, or running archive scripts.

Canonical roots:

- Archive: `$HOME/Pictures/shared-images`
- Collection: `$HOME/Pictures/shared-images/anime/women`
- Raw inbox: `$HOME/Pictures/shared-images/anime/women/inbox`
- Wallpaper workflow: `$HOME/Pictures/shared-images/anime/women/wallpapers/workflow`
- Portrait workflow: `$HOME/Pictures/shared-images/anime/women/portraits/workflow`
- DB: `$HOME/Pictures/shared-images/shared-images-db.sqlite`
- Scripts: `selected core command namespace`

## Operating Rules

1. Treat SQLite as the source of truth for canonical image metadata.
2. Treat `by-artist` directories as derived symlink views, not authoritative data.
3. Use `unknown` for unclear artists. Do not guess attribution.
4. Use dry-run modes before destructive file moves or symlink refreshes.
5. Use transactions for DB writes.
6. Use `sqlite3 -readonly` for inspection.
7. Rehash edited files immediately.
8. Run an audit before claiming completion.
9. Put newly found images in the unified raw inbox first, then classify them into portrait or wallpaper workflow lanes by visual/contextual judgment.
10. Treat low-res determination as a post-classification workflow step under `<image-type>/workflow/low-res/`.

## Core Commands

```sh
shared-images-db-audit --check-hashes
shared-images-db-audit --check-hashes --check-symlinks
shared-images-rehash <prod-path>
shared-images-workflow-layout check
shared-images-workflow-layout migrate --dry-run
shared-images-promote-original --dry-run <original-path>
shared-images-refresh-artist-links --dry-run --artist <artist>
shared-images-rclone-sync dry-run-push
```

## Visual Work

When classifying wallpaper versus portrait, SFW versus NSFW, or transparency quality, use visual inspection. Conservative image-shape heuristics can help, but user judgment wins.

## BUX5A authority boundary

Browser UX owns these sources; core remains the selected command owner until BUX6.
The destination command package is unregistered. Explicit BUX5A trials are limited
to help, status, and fixture-only dry runs. Starting a destination Brave session
would reuse core's launchd label and mutate CNT state; it requires separate operator
authorization and is not a qualification step. Normal activation and promotion
never authorize CNT imports/clears or Shared Images mutation/sync. Generic rclone
and storage authority remain external to Browser UX. Even rclone dry runs contact
a remote; use recording stubs for qualification.
