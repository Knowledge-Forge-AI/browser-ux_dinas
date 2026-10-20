# Shared Images Command Notes

Use the selected core command namespace until BUX6. Browser UX's dormant
package is available for explicitly authorized fixture trials only. The managed
command namespace root is `~/.local/nbin`; no global skill exposure changes here.
The commands below document operator workflows, not activation actions.
Mutation and real remote operations require separate operator authorization.

Audit before completion:

```sh
shared-images-db-audit --check-hashes
```

Stronger audit:

```sh
shared-images-db-audit --check-hashes --check-symlinks
```

Check or migrate intake/workflow layout:

```sh
shared-images-workflow-layout check
shared-images-workflow-layout migrate --dry-run
shared-images-workflow-layout migrate
```

Promote original:

```sh
shared-images-promote-original --dry-run <original-path>
shared-images-promote-original <original-path>
```

Refresh artist symlinks:

```sh
shared-images-refresh-artist-links --dry-run --artist <artist>
shared-images-refresh-artist-links --artist <artist>
```

Sync:

```sh
shared-images-rclone-sync dry-run-push
shared-images-rclone-sync push
```

Use dry-run first for file-moving and sync operations.
