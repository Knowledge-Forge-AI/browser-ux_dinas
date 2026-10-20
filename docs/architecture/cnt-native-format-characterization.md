# CNT native characterization: BUX5B0B

Current R2 status: **BLOCKED**. Corrected empty-browser confinement has not
qualified either engine. R1 evidence remains dated historical evidence; its
unsafe launch entrypoints now refuse and original harness bytes are retained
as text provenance in `history/r1/`.

## Historical R1 status — 2026-09-27

This section records R1 observations, not current executable behavior. R2
entrypoints refuse; fixture provenance binds to `history/r1/*.txt`.

Both static captures are **VERIFIED** using the capture helper's exact encoding and
independently maintained verifier. Both native lanes remain **BLOCKED**; neither
is CHARACTERIZED. The R1 implementation repairs capture verification and adds
maintained synthetic regression tests; it records a small Firefox round trip, without accepting either full lane.

Chrome's `browser-ux-static-tree-sha256-v1` matches
`fe6261cba7b97fcbbde9a1287ca6094bb3e95d73a0cdfd8493f9e3a6dcddd739`.
Firefox's XPI SHA-256 matches
`bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f`.
Manifest public-key and Gecko identities and exact versions/MV3 also match.
The supplied helper and `tests/cnt_native_evidence.py` were each run against
only the supplied copies. Capture safety flags remain provenance-input metadata.
The missing-digest-definition blocker below is superseded. The NAR mismatch
was a different serialization, not evidence of capture corruption.

The maintained algorithm excludes the root, includes all descendants and
_metadata, sorts relative POSIX paths by Python string order, and hashes NUL
framed kind/path/payload records. File payloads are binary SHA-256; directories
have empty payloads; links retain UTF-8 text. Directory links are never descended.
Escaping links, escaping chains, cycles and unsupported filesystem entries fail.
R1 registered 19 synthetic cases as `cnt-static-evidence-tests`; private
packages never entered that check. The historical prefix entrypoint verified
the Chrome tree and emitted `VERIFIED_STATIC_INPUT_ONLY`. The current prefix
entrypoint refuses execution; that historical result is not native PASS.

### Native execution and remaining limits

Both engines' `internal3.mjs` members were independently hashed and their
export/import slices located without body edits. Chrome's member SHA-256 is
`c3a88f213b3404afbdb517e0fa1608ecce1957207de06c60f5e535d2c0bceb3b`;
Firefox's is `a751464b910f968d1514b6e4eb2438be44a0c59b81067efee063f8726ca73efa`.
Chrome slices were not executed. Firefox execution ultimately used the complete
unmodified captured XPI, including its actual Dexie/IndexedDB and native helpers.
No extracted native bodies or package code are tracked.

Chrome remains **BLOCKED: INCOMPLETE_IMPLEMENTATION**, not blocked by an
unavailable offline dependency.
During R1, no Chrome launch, mock-keychain qualification, branded-Chrome
unpacked-extension loading test or CDP `Extensions.loadUnpacked` attempt was
performed. R2 subsequently attempted an empty confined launch; it aborted.
Upstream documentation identifies `--use-mock-keychain` as an available mechanism; its behavior
remains unqualified for this delivery path. No dependency was downloaded. Completing
this lane requires faithful execution and the remaining semantic matrix, not
another runtime-absence claim.

The historical R1 Firefox fixture was recorded on Firefox 155.0.1 using the
maintained [Marionette protocol](https://firefox-source-docs.mozilla.org/remote/marionette/Protocol.html)
against a fresh isolated HOME/profile (`CFFIXED_USER_HOME`) and a temporary copy
of the captured XPI. No GeckoDriver installation, live profile seed, outbound
network access, TCC grant, app-bundle edit, or existing-browser mutation was
used. Unqualified module-import probes that altered the initialized settings
graph were rejected as acceptance evidence.

The historical `history/r1/cnt-native-firefox-ui.py.txt` and `.js.txt` sources
executed the retained small experiment
through the initialized native UI. DataTransfer/File/change events supply tiny
synthetic images and the native restore file input. Native CodeMirror changes
supply harmless HTML/CSS/JS, allowing native debounce between edits. The supported
background-size option is `cover_screen`. No native semantic helper is replaced.
The only download adapters delegate URL creation, capture the native Blob and
filename, and omit the OS anchor save action. Native serialization, conversion,
storage transactions, ordering, settings and custom-code logic execute unchanged.

The maintained seed and import runs each use a new private profile. Native export
and native re-export bytes are **exactly equal**: four ordered occurrences with
three distinct image contents and a duplicate-content occurrence, distinct
native IDs, ranks 1–4, original image bytes/File timestamps, non-default settings
and custom HTML/CSS/JS. No clock/RNG was replaced. Original download filenames
are retained separately; their locale/date is volatile. No emitted JSON was
rewritten or excluded from comparison.

Small untouched artifacts, input images and metadata live under
`tests/fixtures/cnt-native/firefox/6.12.1/`. Metadata binds package/member and
harness hashes, every artifact digest, adapters and limitations. Maintained fixture tests enforce artifact and historical `.txt` harness hashes,
identity, order, content and custom-code/settings preservation. These tests
validate evidence, not a fresh private-package replay. The historical harness
reported `OBSERVED_UI_SUBSET_NOT_CHARACTERIZED`, never native lane PASS.
The current Python entrypoint refuses. The redundant `tests/cnt-native-firefox-ui.js`
copy is retained unchanged, is not qualified for execution, and is not the
fixture provenance authority.

The full Firefox lane is still **BLOCKED**: tasks, theme behavior, supported-UI
multipart boundaries/order/missing parts, unknown fields, rank gaps and completed
malformed-import destructive behavior remain unexercised. This is incomplete
implementation, not an offline Firefox prerequisite. Historical scheduling
probes do not fill these gaps. No cross-engine compatibility claim is made.

### Prefix adapter fidelity inventory (historical probe only)

| Binding | Classification | Acceptance consequence |
| --- | --- | --- |
| n | Native semantic predicate replaced | Equivalence unproven; cannot support full import. |
| err, err_async | Native control/error helpers replaced | Propagated test errors are not native UI behavior. |
| XH | Omitted progress/protection UI | Completion effects unqualified. |
| Gq | Omitted UI transition | Storage-deletion completion not proven. |
| h.Error.print_error_code | Omitted diagnostic UI | No native user-visible error claim. |
| Ae.BackUp.read | Host file-read adapter | Native conversion helper omitted; limited text-prefix probe only. |
| Zt, Wq | Incomplete native object wrappers | Only two fields present; actual dependencies absent. |
| files | Synthetic host input | No real File/IndexedDB semantics. |

Large supported-UI multipart artifacts are excluded from source; only small
digests and projections belong in tracked fixtures. Reduced-threshold probes cannot
count as supported-UI evidence. Cross-engine portability remains UNKNOWN.

### Source boundary and remaining gates

Nix qualification uses an enumerated source-only snapshot
(`tests/source_only_snapshot.py`) preserving tracked symlinks and excluding
untracked local captures.

foundation: **DEFERRED_TO_BUX5B0C**. live recovery: **NOT_IMPLEMENTED**.
backup: **BACKUP_COVERAGE_NOT_CONFIRMED**. No canonical root was created.
Native characterization acceptance remains incomplete.

## Historical BUX5B0B pre-R1 observations — 2026-09-27

The following retained record describes the preceding unpublished attempt.
Its missing-digest statements are superseded above; its partial probes remain
historical evidence, not fresh R1 native execution or current acceptance.

Status: `BUX5B0B_PARTIAL_CHARACTERIZATION`. Neither engine is `CHARACTERIZED`,
and both lanes remain blocked.
Firefox has verified static source and a partial executable importer probe;
Chrome's required tree digest remains unverifiable without its encoding
definition. Full synthetic export/import/re-export and foundation are deferred.
This supersedes BUX5B0's current access-blocked status, not its historical record.

### Historical pre-R1 (2026-09-27): Authority and provenance

Only static extension package captures were used as extension evidence. No live
browser profile was accessed, enumerated, copied or launched.

`provenance.json` declares schema `browser-ux-cnt-static-package-evidence-v1`,
`synthetic_or_static_only = true`, `live_cnt_runtime_storage_read = false`, and
`live_cnt_runtime_storage_written = false`. All were checked.

| Evidence | Chrome | Firefox |
| --- | --- | --- |
| Version / manifest | 6.12.0 / MV3 | 6.12.1 / MV3 |
| Extension ID | `felphkbfjadmcejnibcmcncimlappdde` | `clear-new-tab@loftyshaky` |
| Path within static evidence root | `chrome/package` | `firefox/clear-new-tab.xpi` |
| Declared digest | `fe6261cba7b97fcbbde9a1287ca6094bb3e95d73a0cdfd8493f9e3a6dcddd739` | `bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f` |
| Verification | Required tree encoding undefined; NOT VERIFIED | Recomputed SHA-256 matches |
| Derived identity | Decoded manifest key SHA-256, first 32 hex digits mapped to a–p; matches | `browser_specific_settings.gecko.id`; matches |
| Acceptance | `BLOCKED_DIGEST_DEFINITION` | `BLOCKED_FULL_NATIVE_ROUND_TRIP` |

Chrome's `browser-ux-static-tree-sha256-v1` is not defined by supplied provenance.
No substitute digest is accepted. Supplemental SHA-256 checks of blocks listed
in `_metadata/computed_hashes.json` match all 57 listed files. This does not
authenticate that metadata, verify its Web Store signature, prove coverage of
unlisted files, or replace the required tree digest. `_metadata` is integrity
metadata, not characterized application code.

These diagnostic encodings were recomputed over sorted relative POSIX file
paths; none matches:

| Per-file encoding | Include `_metadata` | Exclude `_metadata` |
| --- | --- | --- |
| hex SHA-256 + two spaces + path + LF | `3cacf78d691622592249677575b94661edf9c5c2f1cb902a639f99ed05eedaf4` | `6eadb1270184fcfff6ecbe54a93dd2c87045818375c6b75bd5b6772bd4895ac1` |
| path + NUL + content bytes | `013fa6b62e9ca88ff9f2fa9841cdd0888e5a5dc101382a720d9febf82f6990c0` | `6df16d30e987c55d004401d04e9f5ded5b855e4c1e14f93b898331527c28054d` |
| path + NUL + hex SHA-256 + NUL | `03a7a4513149210ef719d53eca220ab749073cf5c9bed26b038768ac07c90cac` | `0bdeccb7d5a256c6f60ab7a59f59b92b856e531719c0f7765fa5d356f1abb0a7` |

Verification also ran `nix hash path --type sha256 --base16` on the captured Chrome
package directory. Its NAR digest is
`38d14a262424ac402ce1ab166c5dae58edd0924d8c6dd2f44839436834b495fb`,
which does not match. NAR covers directory entries and the executable bit of
regular files; this check does not exhaust arbitrary file-mode encodings.

This established an unresolved encoding contract rather than corruption; R1
subsequently verified the exact `browser-ux-static-tree-sha256-v1` encoding
algorithm described in the R1 section above.

### Historical pre-R1 (2026-09-27): Firefox 6.12.1 static call chains

The verified XPI has no duplicate, absolute, traversal or symlink members.
Analysis reads members in memory, without extracting an archive into a profile.
Relevant source-member SHA-256 values:

| Member | SHA-256 |
| --- | --- |
| `chunks/internal3.mjs` | `a751464b910f968d1514b6e4eb2438be44a0c59b81067efee063f8726ca73efa` |
| `chunks/internal2.mjs` | `bfdeae22b717bc4d4fa02d05c6417f748e85b9e605a175b5192f90943c4a5a29` |
| `chunks/internal.mjs` | `53b7a1cbe81b0c3263c5f250afc2a152dc55244b88e54480f3b0bb183f2def8c` |
| `background.mjs` | `596f6e50361cd28d505a2e0b165e44f9e58c63c27b3d8ef49c46fec7e8d8aef2` |

The options page is `settings.html`. Its bundle wires
`xe.Sections.make_shared_sections` to `Wq.download_back_up` and
`Wq.restore_back_up` in `internal3.mjs`. The shared section in `internal2.mjs`
creates download/upload buttons and a multiple-file JSON input.

Export: `Wq.download_back_up` reads `O.get_custom_code`,
`O.get_background_files`, `O.get_background_thumbnails`, `mn.backgrounds` and
`Fq.tasks`; serializes JSON chunks using native `JSON.stringify`; converts
Blob/File data with `x.convert_blob_to_base64` (FileReader data URL); then calls
`Ae.BackUp.download`. That helper creates an octet-stream Blob and temporary
DOM anchor/object URL, naming files with locale/date text and `Part N.json`.
It does not require a manifest `downloads` permission.

Import: `Wq.restore_back_up` requests background deletion, sorts filenames by
`Part (\d+)`, requires a filename containing `Part 1.json`, calls
`Ae.BackUp.read` (FileReader text) and native `JSON.parse`, then transforms
backgrounds via `mn.transform_background` / `Ne.Schema.transform`. Data URLs
are converted by `x.convert_base64_to_blob` (`fetch(dataURL).blob()`) and rebuilt
as Files. `O.save_backgrounds` uses Dexie transactions and bulkAdd;
`mn.get_missing_*` filters existing IDs and `mn.merge_backgrounds` merges,
deduplicates by theme identity and optionally sorts. Tasks pass through
`O.save_tasks` and `Fq.merge_tasks`. Custom code uses `IH.save_custom_code` and
`O.save_custom_code`. Settings use `u.send_msg_to_update_settings` and the
background `update_settings_background` handler, including a final forced
transformation/load pass. These chains do not prove losslessness.

Storage permissions: `storage`, `alarms`; optional `clipboardRead`; empty host
permissions. Shared code uses `we.storage.local` and `we.storage.sync`, including
fallback/migration logic. Dexie defines `backgrounds` (`id, i`),
`background_thumbnails`, `background_files`, `tasks`, `alarm_data`, `custom_code`.
Database version 2 adds `video_speed = global` to backgrounds. No live DB was read.

### Historical pre-R1 (2026-09-27): Firefox semantic inventory (static evidence unless marked executed)

| Feature | Native representation and qualification limit |
| --- | --- |
| Top-level schema | First part: `settings: {prefs}`, `custom_code`, `chunks`. Later parts: `chunks` only. Explicit artifact schema/version discriminator: **NOT PRESENT** in this serializer. |
| Occurrences | Each chunk has `data`, `thumbnail`, `file`, `tasks`. `data` is the complete background object; file/thumbnail records are projected. |
| Content | Image/video Files carry `name`, `type`, `last_modified`, data URL `background`. Color records carry `background`; image links retain links. Content SHA-256: **NOT PRESENT**. |
| Identity/order | Background `id` retained; decimal-string `i` sorted through arbitrary-precision subtraction. Gaps representable; no export densification visible. Duplicate-ID/theme effects need round-trip tests. |
| Preferences | Whole `prefs` cloned/serialized; `id_of_last_installed_theme` reset to empty string. `apply_unchanged_prefs` retains target `current_section`, `color_help_is_visible`, `clipboard_read_permission`, `install_help_is_visible`; final transformations unexecuted. |
| Presentation | Per-background size, position, repeat, surrounding color, video speed/volume; `global` inherits preferences. Slideshow/scheduling settings exist. |
| Custom code | `html`, `css`, `js`; object exported/restored through save/cache/message chain. No custom code executed here. |
| Tasks | Filtered by `background_id`, stored per chunk; task IDs/ranks and year/month/day/time scheduling fields. Alarm cache is not a top-level backup member. |
| Collections | Separate collection envelope/table: **NOT PRESENT** in inspected backup schema/database declaration. Broader UI grouping and portability unproven. |
| Themes | Real `theme_id` and deduplication semantics. Chrome/Edge theme-upload controls are gated out for Firefox. Not equated to a portable collection model. |
| Multipart | Real byte threshold and filename-sorted import. First-part settings/code. Part-count/digest/completeness envelope: **NOT PRESENT**. UI threshold range 50–400 MiB; boundary behavior untested. |
| Unknown fields | Export stringifies complete prefs/background/task/code objects. Top-level extras are not emitted; file/thumbnail extras are not projected. Full import preservation and normalization unproven. |
| Volatility | Download filename includes current locale/date. File `last_modified` is explicitly restored source metadata, **not** proven disposable volatility. IDs/ranks not classified volatile. |
| Engine/version | MV3 background scripts include background/offscreen modules. Manifest includes `strict_min_version: 153.0.0` under `browser_specific_settings`; enforcement untested. No compatibility range beyond this inspected build asserted. |

### Historical pre-R1 (2026-09-27): Executed partial importer probe

`tests/cnt-native-static-probe.py` verifies provenance, identities, archive
safety, Firefox archive digest and executed member digest before invoking an
explicit Nix-store Node executable. `tests/cnt-native-import-prefix.mjs` takes
exact contiguous slices for `restore_back_up` and `delete_all_backgrounds` and
wraps them as class fields. Function bodies are unchanged; no extension code is
vendored. Executed slice SHA-256:

- Importer: `575f531c7ae3179f5699a2f1618f8fefb73a4e9d1eb0be9a76b673ed07243e3d`.
- Deletion scheduling: `d12a36f5a7a67a69a9a254696e9ee45886c0242e880e078eb5f8de06b7c95838`.

Four cases pass: empty selection, missing Part 1, malformed JSON and missing
`chunks`. All schedule deletion before parse/shape failure. Missing Part 1
returns without reading the supplied part. The deletion method sets a reason
and hides the UI section; its transition-end callback performs database clearing.
**The probe proves scheduling, not actual deletion.** Future recovery must
validate artifacts before invoking native restore.

Adapters record UI/diagnostic calls, supply text instead of FileReader and
propagate errors instead of rendering native ribbons. No IndexedDB, structured
clone, transaction, DOM transition or background messaging implementation is
supplied. No network, browser, profile, clock or RNG is used. This is **not** a
faithful complete serializer/importer graph or a native acceptance test.

Every substituted free identifier is listed here: `n` is a non-null/undefined
predicate; `err` and `err_async` execute callbacks and propagate failures;
`XH` records show/hide; `Gq` records background-section visibility; `h` replaces
error-code reporting with a no-op; `Ae` supplies synthetic file text. `Zt` and
`Wq` are instances of wrappers containing only the two extracted class fields.
The native definitions of these substitute helpers, including `n`, were not
extracted or proven equivalent. The reported `SyntaxError` and `TypeError` are
probe outcomes, not evidence of native user-visible error behavior.

Native export and successful restore/re-export are **NOT EXECUTED**. Three-image
seeds, rank gaps, settings, custom code, tasks/themes, multipart restoration,
normalization, unknown fields and identity comparisons remain unexercised.
The missing faithful dependency closure includes schema/settings transforms,
merge/custom-code helpers, UI transition sequencing and IndexedDB transactions.
Replacing domain helpers with copies/no-ops would invalidate round-trip claims.

The static probe requires external package inputs and fails closed when those
inputs are absent. At the pre-R1 stage, no accepted fixture or foundation tests
were registered in flake checks, and no browser runtime was launched. Exercising
`Wq.download_back_up`, restore, and re-export required a disposable isolated
profile loading only the captured XPI with network disabled and synthetic data.

### Historical pre-R1 (2026-09-27): Comparison, artifacts, foundation and prerequisites

Chrome application analysis is withheld pending its required digest. The
serializer/importer comparison, byte identity and cross-engine equivalence are
**UNKNOWN**. Nearby version numbers do not establish portability. Firefox engine
branches do not prove Chrome behavior.

Native fixture roster: **none**. No native artifact digests, accepted fixture
metadata or seed/export/round-trip semantic fingerprints are published. BUX5A
generated backups remain generator evidence only.

Foundation: **DEFERRED**. No `durable_state.py`, manifest schema, fingerprint,
journal validator, canonical-root creation, recovery executor or command
registration. Foundation tests are not applicable.

Remaining prerequisites:

1. Obtain the Chrome capture script and digest definition, verify the bound digest,
   then characterize that lane.
2. Complete faithful synthetic export/import/re-export independently per engine,
   including all supported semantics, malformed/partial artifacts and multipart
   boundaries; publish sanitized accepted native fixtures and metadata.
3. Decide the bounded foundation only after native unknown-field, identity and
   normalization contracts are established; test manifest/fingerprint/journal.
4. BUX5B1 additionally requires guarded capture/recovery, consumer migration,
   and confirmed backup coverage before durability claims. BUX5C requires full
   milestone State C qualification after those prerequisites; current dormant
   State C checks alone do not complete BUX5C.

### Historical pre-R1 (2026-09-27): Backup coverage

`BACKUP_COVERAGE_NOT_CONFIRMED`, bound to the frozen default
`$HOME/.local/state/browser-ux/clear-new-tab`. This directory was not created.

Host-backup coverage for this state root must be verified separately by a
downstream workstation composition before treating captured state as durable
(checking that the default root's volume and ancestors are included, wildcard
exclusions permit it, and a synthetic coverage probe can be backed up and
restored). Any alternate `XDG_STATE_HOME` requires a separately path-bound
coverage verdict; default-root evidence must not be reused after relocation.
Root resolution remains unimplemented and BUX5A's frozen path is unchanged.

BUX5B1 additionally requires accepted per-engine/version native fixtures,
manifest/fingerprint/journal contracts with adversarial tests, confirmed backup
coverage before durability claims, and guarded recovery/consumer migration.
BUX5B remains incomplete.

## Native preflight D1 and production adoption boundary

The synthetic D1 preflight invocation exercises the empty workload under Seatbelt confinement with shutdown tracing enabled:

```
tests/cnt-native-preflight.py --engine firefox --runtime /Applications/Firefox.app \
  --scratch <fresh-attempt> --workload empty --shutdown-trace \
  --service com.apple.windowserver.active --service com.apple.coreservices.launchservicesd \
  --nested-sandbox-exception content --nested-sandbox-exception socket \
  --nested-sandbox-exception utility-generic
```

Production adoption of the Firefox runtime identity keeps the `malformed-D` claim withheld and introduces no captured-code shell handoff.
