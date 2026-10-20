# Clear New Tab durable authority: BUX5B design

Current BUX5B1 consumer status: the dormant `clear-new-tab-sync` is repointed (source only).
Its only authority is one operator-selected stored manifest in Browser UX durable state,
verified by the accepted libraries through `libexec/clear-new-tab/brave-youtube-consumer.py`.
The normal Chrome profile is never read or copied. `brave-youtube` refuses before the Brave
target is opened, because Chromium/Brave CNT import is uncharacterized; that refusal is the
BUX5C boundary. See [the CONSUMER-ADAPT1 addendum in command-package.md](command-package.md).

Current BUX5B1 status: guarded capture/recovery source exists in
`libexec/clear-new-tab/guarded_recovery.py` (adapter seam, fake-adapter tests only). Live
recovery is NOT IMPLEMENTED and NOT QUALIFIED; no reset-evidence kind is accepted, so automatic
recovery is unreachable; consumers are not repointed. See
[the RECOVERY-PREP1 addendum in command-package.md](command-package.md). A test-owned disposable-Firefox
adapter and host harness with an UNEXECUTED native qualification handoff is included in `tests/` as a
source-only candidate.

BUX5B0C status (accepted foundation): a non-mutating, engine/version-labelled foundation
library exists (manifest, fingerprint, references, journal schema). It projects
only Firefox CNT 6.12.1 on Firefox 156.0.1. No canonical root has been created,
and recovery is NOT_IMPLEMENTED. See
[the BUX5B0C addendum in command-package.md](command-package.md). The design below is
unchanged.

Current R2 status: **BLOCKED**. Corrected empty-browser confinement has not
qualified either engine. R1 evidence remains dated historical evidence; its
unsafe launch entrypoints now refuse and original harness bytes are retained
as text provenance in `history/r1/`.

Status: BUX5A code-and-fixture inventory and implementation design. No durable
authority exists yet, and no live browser collection was inspected or changed.
BUX5B must characterize native exports before implementing recovery. BUX5C and
BUX6 remain separate qualification and ownership-transfer milestones.

BUX5B0's [characterization record](cnt-native-format-characterization.md)
records the 2026-09-27 R1 capture verification: both exact digests match.
Firefox has a small native UI round-trip fixture; its complete semantic matrix
and the Chrome lane remain blocked. Historical prefix probes remain limited
control-flow evidence. Neither lane is CHARACTERIZED; manifest, fingerprint and journal implementations remain
deferred to **BUX5B0C**, after the native-evidence gate. Backup coverage of the frozen default
root is `BACKUP_COVERAGE_NOT_CONFIRMED`. No canonical directory, recovery
implementation or command registration was added.

## Evidence and current semantics

The evidence is `bin/cnt-wallpaper-gallery`, `bin/clear-new-tab-sync`, the
Shared Images helpers, `tests/test_commands.py`, and migrated tests under
`tests/migrated/unit/python`. These fixtures characterize generated backups;
they are not native exports of an installed CNT version.

| Concern | Observed contract |
| --- | --- |
| Membership | `db_rows` reads `anime_women_images`, joining `image_types` and `res_type`. `row_matches_filters` selects safety, wallpaper/portrait, series, artist and optionally `high_res`; series/artist comparison is case-insensitive. `discover_images` excludes missing files and unsupported suffixes. `dedupe_images` keeps the first readable file for each SHA-256 digest. |
| Ordering | SQL orders by image type, safety, series, artist, title, relative path, then absolute path, all `COLLATE NOCASE`. `write_backup_files` enumerates from 1 **before** `make_chunk` may skip an image. `data.i` is a decimal string rank and may contain gaps; it is not a dense index. |
| Identity | `make_chunk` uses UUIDv5 in `NAMESPACE_URL` over `cnt-wallpaper-gallery:<sha256>`. If a digest was not supplied, it falls back to the resolved path. Normal load deduplicates first and supplies a digest. Moving unchanged content preserves the digest identity; editing, rehashing changed bytes, or promoting an edited original produces a new CNT identity. A rehash of unchanged bytes does not. |
| Source mapping | `db_image_path` prefers an existing absolute path, then a DB-relative path. `Wallpaper` retains path, rating, series, artist, image type, resolution flag and digest. Backup chunks retain filename and bytes but lose archive-relative path, filters and attribution. |
| Chunk | `make_chunk` emits `data`, `thumbnail`, `file`, `tasks`. `data` includes ID, rank, `img_file`, dimensions/thumbnail dimensions, and global presentation settings. `file` has name, MIME type, millisecond modification time and a data URL. `thumbnail.background` is another data URL; `tasks` is empty. |
| Preferences | `make_backup_payload` adds only to part 1: `settings.prefs.mode = multiple_backgrounds`, `id_of_last_installed_theme = ""`, and empty `custom_code.html/css/js`. It does not export existing preferences or preserve arbitrary custom code. |
| Multipart | JSON is split at a configured approximate byte budget. A single oversized chunk is not split. Rank order continues across parts; later parts omit settings/custom code. |
| Chromium import | `apply_chrome_import` invokes this script using the same Python interpreter. `chrome_import_worker` clones user data, clears only CNT IndexedDB in the clone, drives CNT's native Restore/Upload backup UI, then calls `replace_chrome_cnt_storage` to replace real CNT IndexedDB after preserving displaced directories. Completion is storage growth/settling, not semantic equality. |
| Firefox import | Generated JSON plus manual restore instructions only. No automated native import or cross-engine database conversion is implemented. |
| Chrome → Brave | Historical (BUX5A evidence; core still behaves this way): `clear-new-tab-sync` selects the numerically latest extension directory, then copies the extension bundle, IndexedDB leveldb/blob directories and Local Extension Settings opaquely. `sync_dir` removes its temporary displaced backup after replacement; it is not durable recovery. Since BUX5B1 CONSUMER-ADAPT1 the destination command reads only verified durable state and refuses Brave writes until BUX5C. |

`image_dimensions` uses ImageMagick with a macOS `sips` fallback. Thumbnail
generation can fall back to the original data URL. These are presentation
operations, not additional canonical image identities.

## Native acquisition and storage boundaries

Current tools can read archive metadata/content, produce CNT-compatible backup
JSON for that selection, locate storage directories, and perform the native
Chromium upload workflow. **No inspected command exports live collection
membership/order, complete settings, arbitrary collections, or unknown native
fields.** A generated backup must never be described as a lossless live export.

Chromium runtime state comprises CNT's `IndexedDB` leveldb and blob directories
and its `Local Extension Settings` directory for extension ID
`felphkbfjadmcejnibcmcncimlappdde`. Gallery clear/replacement targets only the
two IndexedDB directories; sync additionally copies Local Extension Settings.
Firefox uses profile-local `storage/default/moz-extension+++<uuid>` storage,
including a possible user-context suffix. `firefox_extension_uuid` first reads
extension settings, but its arbitrary-storage fallback is insufficient evidence
for recovery targeting. BUX5B must resolve extension identity explicitly and
reject ambiguous profiles/UUIDs.

Reading live rows from opaque storage would require characterizing Chromium
IndexedDB/LevelDB key encoding, blobs, local settings and Firefox's distinct
storage format. None is implemented or inferred here. Prefer native backup
export/import. First obtain operator-authorized, sanitized, version-labelled
native export fixtures for both engines and prove membership, rank, settings,
custom-code and unknown-field round trips. If native export cannot preserve a
required semantic, stop that recovery path for further characterization; do not
synthesize databases or silently discard fields. No Chromium DB enters Firefox.

## Chosen Browser UX representation

Use `$HOME/.local/state/browser-ux/clear-new-tab` as the canonical root, outside
profiles and the Nix store. This is a design choice, not a directory created by
BUX5A. Host-backup coverage is **unverified**; BUX5B must explicitly confirm
coverage or arrange owner-approved coverage before calling the state durable.

The representation has four distinct components:

1. `manifest.json`: a versioned Browser UX envelope with an ordered `images`
   array. Each image records SHA-256, the observed CNT ID and rank when known,
   and an archive-relative content reference when known. Preserve gaps and
   order explicitly. The existing `Wallpaper` metadata may accompany known
   archive sources; do not manufacture missing attribution. Do not invent
   CNT collection IDs or flatten uncharacterized native collections.
2. Content references rooted at `$HOME/Pictures/shared-images`, validated by
   digest. Native-export-only content may be retained under a digest-addressed
   `content/` directory. Reject traversal and references outside authorized
   roots. Never put the archive database or image bytes in the Nix store.
3. `native/`: original engine/extension-version-labelled backup artifacts and
   their digests. Retain exact unknown fields and settings in these artifacts.
   Only proven portable semantics enter the neutral manifest. A native backup
   is not automatically portable to another engine/version.
4. `recovery/`: Browser UX transaction metadata: source-artifact digest,
   target engine/profile identity, before/after fingerprints, validation
   results, authorization basis and displaced-state location. These are newly
   designed control fields, not claimed CNT-native keys. Do not store secrets
   or full profile payloads in public reports.

Freeze the manifest envelope and native preference projection only after native
fixtures pass characterization. Unknown or partial collection semantics remain
in preserved native artifacts and block an engine-neutral recovery claim.
Distinguish an image's content identity from its historical occurrence/order:
content edits produce a new digest and CNT ID, and require a recorded manifest
revision rather than silently reassigning an old ID. Path-only moves preserve
identity after digest verification. Do not rerun current SQL ordering to recover
a captured collection; replay the captured order.

## Recovery and authority invariants

1. Normal nix-darwin activation never clears, rebuilds, imports or recovers CNT.
2. Preserve displaced state durably before replacement; failure to preserve it
   prevents replacement. Retain a verified rollback reference.
3. Automatic recovery requires positive, versioned evidence of missing/reset
   state. Empty directory heuristics alone are insufficient if identity or
   browser shutdown is uncertain.
4. Nonempty, changed, ambiguous or unknown state requires explicit operator
   authorization; elapsed time and prior activation never confer it.
5. Recovery is idempotent: an already-matching semantic fingerprint is a no-op.
6. Brave YouTube derives from canonical Browser UX state, not mutable normal
   Chrome state. Repoint consumers only in BUX5B's authorized implementation.
7. Firefox and Chromium storage and import adapters remain distinct.
8. Shared Images content/database and runtime browser databases stay outside
   the Nix store. Only code and synthetic tests are build inputs.
9. Destructive commands remain operator-only. Ordinary promotion grants no
   import, clear, rehash, promotion, layout mutation or cloud-sync authority.

Capture must establish browser quiescence, complete export and compatible
engine/version identity. Recovery stages and verifies native import in a
disposable profile, captures displaced state, checks the live fingerprint has
not changed, and only then replaces through the characterized engine adapter.
An interrupted transaction resumes or rolls back from its recorded state;
it never guesses which directory is authoritative. Semantic verification must
replace the current storage-growth heuristic as acceptance evidence.

## Concrete BUX5B implementation and tests

| Step | Implementation boundary | Required fixture evidence |
| --- | --- | --- |
| 1 | Characterize native export UI/API and version compatibility per engine. | Multiple collections if supported, settings/custom code, unknown fields, multipart order/rank gaps, partial or corrupt exports; exact preserved native artifact. |
| 2 | Implement capture/validation and manifest/content references. | Duplicate bytes, missing content, digest mismatch, path relocation, traversal refusal, edited originals, promote/rehash identity changes, unknown attribution. |
| 3 | Implement per-engine identity and fingerprint adapter. | Explicit Chromium extension/profile, Firefox UUID/container identity, ambiguous-profile refusal, missing/reset versus legitimate empty state. |
| 4 | Implement journaled, guarded recovery and rollback. | Nonempty-state refusal, explicit authorization, positive reset evidence, failed preservation, concurrent change, interrupted import/replacement, rollback, repeated recovery as no-op. |
| 5 | Repoint Brave/CNT consumers to canonical state. | Chrome-independent Brave derivation, no Chromium-to-Firefox DB copy, preserved policy and singleton writer boundary. |
| 6 | Qualify durability and operators' recovery procedure. | Confirm backup coverage, restore canonical artifacts from backup in a fixture, verify versions/digests, and document manual recovery for unsupported versions. |

All early tests use synthetic content and isolated profiles. Live acquisition,
browser launch/import, backup configuration and ownership transfer require the
separately authorized BUX5B/BUX6 work. BUX5A's tests prove generated-format and
runtime-package contracts only; BUX5 is not complete.

## Synthetic Firefox 156.0.1 runtime requalification handoff template

When running an operator-reviewed runtime requalification in zsh, `<OUTBOX>` is `~/Documents/agent/outbox/browser-ux_dinas/<HOST_PHASE>/` and `<ROOT>` is a fresh claim root under managed scratch:

```zsh
setopt pipefail
mkdir -m 700 <ROOT>
python3 -B tests/source_only_snapshot.py --source-root <SOURCE_ROOT> --destination <SNAP>
<PY> -B <SNAP>/tests/cnt_host_firefox_runtime_requal.py bind --snapshot <SNAP> \
  --inventory <SNAP>-inventory.json --expected-inventory-sha256 <TERMINAL_INVENTORY> \
  --runtime /Applications/Firefox.app --python <PY> --nix-bin <NIXBIN> --claim-root <ROOT> \
  2> <ROOT>/BIND-STDERR.log | tee <OUTBOX>/BIND-STDOUT.json
<PY> -B <SNAP>/tests/cnt_host_firefox_runtime_requal.py run --snapshot <SNAP> \
  --inventory <SNAP>-inventory.json --expected-inventory-sha256 <TERMINAL_INVENTORY> \
  --runtime /Applications/Firefox.app --python <PY> --nix-bin <NIXBIN> --claim-root <ROOT> \
  --bind-record <ROOT>/BIND-001.json --bind-record-sha256 <sha256 printed by bind> \
  2> <ROOT>/RUN-STDERR.log | tee <OUTBOX>/RUN-STDOUT.json
print -r -- "run_exit=$?" | tee <OUTBOX>/RUN-EXIT.txt
<PY> -B <SNAP>/tests/cnt_host_firefox_runtime_requal.py collect --claim-root <ROOT> \
  2> <ROOT>/COLLECT-STDERR.log | tee <OUTBOX>/COLLECT-STDOUT.json
cp <ROOT>/<summary printed by collect> <OUTBOX>/
```
