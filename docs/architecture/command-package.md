# BUX5A dormant command package

Status: destination-owned source/package; unregistered and not selected. Core
copies and selected command resolution remain unchanged. This package retains
operator-only behavior and must not be invoked by activation or promotion.

## Exact command and runtime roster

| `$out/bin` entry | Interpreter/runtime |
| --- | --- |
| `brave-youtube-cdp` | Nix Python, standard library |
| `brave-youtube-session` | Nix Bash; Nix Python for three sibling helpers |
| `clear-new-tab-sync` | Nix Bash; Nix Python for the sibling durable-state consumer helper (BUX5B1 CONSUMER-ADAPT1) |
| `cnt-wallpaper-gallery` | Nix Python with Playwright, including import subprocess |
| `shared-images-db-audit` | Nix Python, standard library |
| `shared-images-promote-original` | Nix Python, standard library |
| `shared-images-rclone-sync` | Nix Bash; explicit Nix rclone fallback |
| `shared-images-refresh-artist-links` | Nix Python, standard library |
| `shared-images-rehash` | Nix Python, standard library |
| `shared-images-workflow-layout` | Nix Python, standard library |

## Exact helper roster

The local-core reference/import inventory found no additions beyond the frozen
fifteen helpers plus two existing BUX4 asset generators. Until BUX5B1
CONSUMER-ADAPT1 all seventeen were installed at the following sibling paths, with
no duplicate asset implementation. CONSUMER-ADAPT1 retires
`latest-source-extension-dir.py` from the package (see the addendum below); the
other sixteen are unchanged:

```text
libexec/brave-youtube/allocate-debug-port.py
libexec/brave-youtube/display-notification.applescript
libexec/brave-youtube/first-field.awk
libexec/brave-youtube/generate-icon.py
libexec/brave-youtube/generate-theme-assets.py
libexec/brave-youtube/pmset-battery-percent.awk
libexec/brave-youtube/pmset-power-source.awk
libexec/brave-youtube/pmset-sleep-disabled.awk
libexec/brave-youtube/profile-extension-audit.py
libexec/brave-youtube/write-launch-plist.py
libexec/clear-new-tab/latest-source-extension-dir.py
libexec/shared-images/artist_links.py
libexec/shared-images/db_audit.py
libexec/shared-images/promote_original.py
libexec/shared-images/rehash.py
libexec/shared-images/shared_images_lib.py
libexec/shared-images/workflow_layout.py
```

Session references account for the notification/awk/three Python helpers; sync
accounted for the version selector until CONSUMER-ADAPT1 and now delegates only to
the destination-origin consumer helper. The five Shared Images Python entrypoints
import their matching helper, which imports `shared_images_lib`. CDP and gallery
are standalone apart from standard-library/Playwright and external executables.
BUX4's dormant writer still owns the two existing generator references.

## Source parity and precise adaptations

`tests/fixtures/command-source-manifest.json` records all 27 source paths, local
core hashes, destination hashes, modes and classification. It sits alongside
the unchanged BUX4 `dormant-source-sha256.json`; shared asset hashes agree.
Nine commands and all seventeen helpers are byte/mode-identical to local core.
Only the gallery has a tracked source difference. Core source is never edited.
(BUX5A baseline. Since BUX5B1 CONSUMER-ADAPT1: eight commands and sixteen packaged
helpers are byte/mode-identical; the sync command is a second recorded adaptation;
one core helper is retired; see the addendum.)

| Path/surface | Reason | Old behavior | New behavior | Scope evidence |
| --- | --- | --- | --- | --- |
| `bin/cnt-wallpaper-gallery`, tracked `chrome_executable` | Remove mutable ordered runtime discovery and pin mismatch risk | Override, then ordered application copies including current-system Chrome; invalid override could fall through | CLI override, environment override, injected immutable core executable; fail closed if unset or invalid | Precedence/failure tests; native import worker, backup format and replace logic unchanged |
| Same file, tracked `playwright_python` | Keep entrypoint and subprocess in one Python closure | Current-system Python path and existence check | `sys.executable` | Interpreter test and installed Playwright import; worker semantics unchanged |
| Three Bash command shebangs, install only | Deterministic interpreter | `/usr/bin/env bash` | `${pkgs.bash}/bin/bash` | Exact shebang and hostile-PATH entrypoint tests |
| Seven Python command shebangs and executable Python helper shebangs, install only | Deterministic interpreter | `/usr/bin/env python3` | Nix Python; gallery alone uses Playwright closure | Exact installed shebang checks; no mutable Python in any runtime file |
| `bin/brave-youtube-session`, install only | Hermetic helper execution | Three `/usr/bin/python3` calls | Nix Python; unchanged `$(script_dir)/../libexec/brave-youtube` paths | Asserted count=3 rewrite; fixture plist self-reexecution target; existing session tests |
| `bin/clear-new-tab-sync`, install only | Hermetic helper execution | `/usr/bin/python3` | Nix Python with the sibling durable-state consumer helper (BUX5A: version helper) | Asserted count=1 rewrite; installed status/plan/refusal fixtures |
| `bin/clear-new-tab-sync`, tracked (`durable-authority-consumer`, BUX5B1 CONSUMER-ADAPT1) | Remove the mutable normal Chrome profile as Brave YouTube authority | Copy latest Chrome extension bundle, CNT IndexedDB leveldb/blob and Local Extension Settings into the Brave YouTube profile | Delegate `status`/`plan`/`brave-youtube` to the verified durable-state consumer; `brave-youtube` refuses before the target is opened | Consumer tests (normal and `-O`), rewritten Bats test, installed-package contract |
| Gallery `PACKAGED_CHROME_EXECUTABLE`, install only | Optional core-owner injection | Empty fail-closed default | Exact immutable caller argument, or still empty | Package rejects non-store defaults; no standalone Chrome dependency |
| Gallery utility calls, install only | Eliminate ambient lookup | Bare `magick`, `sips`, `ps` | Pinned ImageMagick, `/usr/bin/sips`, `/bin/ps` | Asserted 2/1/1 replacements; no change to utility arguments or fallback behavior |
| `bin/shared-images-rclone-sync`, install only | External storage runtime binding | Ambient `rclone` fallback | `${pkgs.rclone}/bin/rclone`; existing `RCLONE` override retained | Exact fallback check; five dispatch verbs through recording override |
| Three Bash commands' help `cat`; rclone `mkdir`, install only | Hostile-PATH independence | Bare platform utilities | `/bin/cat`, `/bin/mkdir` | Asserted replacement counts; unchanged arguments, outputs and workflow |

`packages/browser-ux-commands/install.py` asserts every substitution count so
source drift fails the build. It installs direct scripts, not wrappers that
break `Path(__file__).resolve().parents[1]`, sibling lookup or launchd
self-reexecution. The package contains exactly ten executable `bin` names,
with no hidden entries, and all seventeen helpers (sixteen plus three
destination-origin files since CONSUMER-ADAPT1). No core checkout is a runtime
dependency.

## Chrome and runtime authority

Standalone Browser UX and selected core may pin different Chrome versions.
The standalone output therefore fails closed for automatic Chrome import until
the operator supplies a verified compatible executable. A separately authorized
integration may import the package expression with `chromeExecutable` bound to
the selected core's `google-chrome` store executable. This replaces the old
mutable `/Applications/Nix Apps` copy with an explicit immutable path when
configured; the caller must prove that it is exactly selected core's build.
BUX5A installs no Chrome, adds no unfree exception and claims no application.
Chrome closure cost is zero for the fail-closed standalone output; a configured
variant would add the selected Chrome closure and must measure that separately.

Generic rclone ownership stays external. Supplying its existing pinned package
as a runtime dependency does not move storage configuration or authorize cloud
operations. Platform utilities and existing bounded test/operator overrides
remain intentional interfaces; the hermetic claim concerns Bash/Python,
ImageMagick/rclone defaults and helper layout, not replacement of macOS APIs.

## Dependency and compatibility record

BUX5A uses only these existing nixpkgs dependency classes. No input,
lockfile or Python project dependency was added. The alternatives were ambient
PATH/current-system lookup (rejected as mutable), wrappers (unsuitable for
sibling/self paths), and asserted installation rewrites (selected). Gallery's
multi-line selector correction is tracked source so source tests cannot exercise
obsolete current-system Python/Chrome authority.

The unchanged destination pin supplies Bash 5.3p3 (GPL-3.0-or-later), Python
3.13.12 (Python-2.0), Playwright 1.56.0 (Apache-2.0), rclone 1.72.1 (MIT), and
ImageMagick 7.1.2-23 (Apache-2.0), as declared by evaluated nixpkgs metadata.
Tests use Bats 1.12.0 (MIT), ripgrep 15.1.0 (MIT/Unlicense), and pytest 8.4.2
(MIT). This is a package metadata/license review, not a new upstream security
audit. Supply provenance is the existing locked nixpkgs inputs and their Nix
fetch/build verification; no pip install or Playwright browser download occurs.
No additional parser/database/framework dependency is introduced.

The explicit operator override remains capable of selecting an incompatible
Chrome; separate import authorization must include version qualification.
Removing the exported dormant package is the rollback: selected host state,
command namespace and policies do not change. Runtime closure size and actual
test results are recorded in the qualification report. The large migrated
gallery remains a preserved legacy implementation with narrowly bounded runtime
edits; a behavioral redesign is deferred, not folded into this migration.

## Test ownership

### BUX5B0 package advisories

`command-package-provenance` builds standalone and a test-only variant with a
tiny immutable `writeShellScript` fixture. The variant is not a `packages`
output or module input. It loads the installed gallery selector, verifies the
exact fixture path and standalone failure without an override, and runs the
full installed-package contract against the variant. No browser or fixture
executable is invoked. The ten-command/seventeen-helper roster is unchanged.

Nix `closureInfo` supplies actual recursive runtime reference sets. Standalone
must equal the union of declared Bash, Python, Playwright Python, rclone and
ImageMagick closures plus the package. Every member, including allowed
transitives, is scanned for Chrome/Chromium and recognizable core checkout
names. Name scans alone cannot identify anonymous `<hash>-source` flake inputs;
exact runtime-set equality and the direct-context allowlist below carry the
undeclared-source guard. The
injected closure differs only by its output and the fixture closure. Store
hashes are not hard-coded.

At evaluation, the complete package derivation-attribute string context must
be contained in the baseline `runCommand` builder context, declared runtimes,
and exact source-manifest files plus installer. Even a renamed undeclared
source/build input fails. The existing installed-file contract rejects mutable
current-system, home and core authority. This is bounded package provenance,
not a generic upstream supply-chain attestation.

Dispatch qualification also runs
`python3 tests/audit-command-derivations.py <standalone-package.drv>`. It uses
`nix derivation show --recursive` to inspect build metadata without realizing
upstream source archives. It rejects recognizable core source/derivation names and browser
package derivations, and scans package-owned build environment values for
home/current-system authority. A Chromium-named FFmpeg compatibility patch is
not a browser derivation. The metadata audit complements the sandbox check;
the maintained flake guarantee covers the runtime closure and top-level direct
build inputs, not exhaustive transitive source provenance. Anonymous transitive
source origins are not established by this metadata name scan. Negative tests
cover recognizable forbidden allowed transitives, renamed extras, missing
runtimes, build authority and recognizably named transitive sources. Synthetic
core-name cases exercise only the supplementary name scan.

The runtime substring scan is deliberately stricter than the build-metadata
package-name regex: a Chromium compatibility patch may occur in build metadata
without being a browser or a runtime dependency. The Nix negative test asserts
evaluation refusal, not a specific assertion message; the independent positive
package check must also pass. Python assertions require the normal, unoptimized
interpreter used by these Nix checks.

Flake checks run the migrated Python helper suites, selected unit/integration
entrypoint cases, generated CNT format/membership tests, source manifest and
local skill checks, and installed package contract. Existing BUX4 asset tests
are reused rather than duplicating generators.

Dispatch-time `run-command-dispatch.py` runs migrated Brave config/session,
CNT-sync, five Browser UX AWK cases, AppleScript compilation, Bash help/rclone
cases and the bounded session coverage harness. macOS utilities are deliberately
outside Nix sandbox checks. The harness now refuses to run without a marked
disposable HOME and fixture-local external-tool overrides. Existing BUX4 writer
tests remain a separate macOS runner. No coverage percentage is claimed.

`command-dormancy.nix` checks evaluated default and direct dormant-enabled
activation text plus the corresponding module sources. None invokes any of the
ten commands, so no destructive subcommand can run there. Generated launcher
content is checked separately and retains the core DINAS session path.

## BUX5B0C addendum: one destination-origin library helper

BUX5B0C adds `libexec/clear-new-tab/durable_state.py` (mode `0644`, no shebang,
standard library only). It is a library imported by future Browser UX code, not
a command: `bin/` stays exactly the ten entries above, and nothing registers or
selects the package. It has no core source, so its source-manifest record uses
the new `destination-origin` adaptation with `source_sha256: null`. The manifest
now has 28 entries: ten commands, the seventeen core helpers and this library.
`check-command-parity.py` checks that the library is absent from core. The
installed-package contract checks that it is non-executable, has no shebang and
loads with Nix Python. See
[clear-new-tab-durable-authority.md](clear-new-tab-durable-authority.md).

## BUX5B1 addendum: second destination-origin library helper

BUX5B1-RECOVERY-PREP1 adds `libexec/clear-new-tab/guarded_recovery.py` (mode `0644`, no shebang,
standard library only). It loads `durable_state.py` from its own directory as a private module
and is not a command: `bin/` stays exactly ten entries and nothing registers or selects the
package. Its manifest record is also `destination-origin` with `source_sha256: null`. The
manifest now has 29 entries: ten commands, seventeen core helpers and two libraries.
`check-command-parity.py` checks that both are absent from core. The installed-package contract
checks that both are non-executable with no shebang, and that the installed recovery library
resolves its installed sibling foundation. See
[clear-new-tab-durable-authority.md](clear-new-tab-durable-authority.md).

## BUX5B1 CONSUMER-ADAPT1 addendum: durable-state consumer, retired Chrome selector

BUX5B1 CONSUMER-ADAPT1 repoints the dormant `bin/clear-new-tab-sync` from the mutable normal
Chrome profile to verified Browser UX durable state. Its manifest record keeps the core
`source_sha256` and records the new `durable-authority-consumer` adaptation. It adds
`libexec/clear-new-tab/brave-youtube-consumer.py` (mode `0644`, no shebang, standard library
only), a CLI helper invoked by the sync command, not a command. It loads `guarded_recovery.py`
(and through it `durable_state.py`) from its own directory as private modules. Its record is
`destination-origin` with `source_sha256: null`.

`libexec/clear-new-tab/latest-source-extension-dir.py` is removed from the source manifest and
therefore from the package. The tracked file and its migrated unit test remain until the
publication commit can delete them; `check-command-parity.py` lists it in
`RETIRED_CORE_HELPERS`.

The manifest still has 29 entries: ten commands, sixteen core helpers and three
destination-origin files. `bin/` stays exactly ten entries, and nothing registers or selects the
package. The installed-package contract checks:

- the helper is non-executable and resolves its installed siblings;
- `status` creates nothing and never reports the legacy profile;
- `brave-youtube` without a selected manifest refuses with exit 3;
- an end-to-end `plan`, against a state root captured with the installed library, refuses with
  `BRAVE_CNT_IMPORT_UNQUALIFIED`;
- the dormant session's implicit sync call leaves a Brave-style target unchanged.

See [clear-new-tab-durable-authority.md](clear-new-tab-durable-authority.md).
