# Matched adoption and attended rollout

Status: source-only reference documentation for the committed `delivery/core` and
`delivery/composition` patch artifacts in the v0.0.1 public preview. No patch
application to external owners, system switch or host policy write occurs when
evaluating or testing this repository.

## Owner changes and committed source metadata

Each owner directory records its pre-patch file hashes, patch hashes and matched
candidate file hashes in [`delivery/core/SOURCE.json`](../core/SOURCE.json) and
[`delivery/composition/SOURCE.json`](SOURCE.json). Hashes bind the committed
patch fixtures ([`tests/primary-cutover-owner.test.py`](../../tests/primary-cutover-owner.test.py));
reconcile any changed downstream owner file before applying a patch in a
compatible composition.

- Browser UX: contributes the declarative module, replacement rendering models
  and extension catalog from this repository.
- Core ([`delivery/core/browsers.patch`](../core/browsers.patch),
  [`delivery/core/modules-browsers.nix`](../core/modules-browsers.nix)): extends
  `modules/browsers.nix` so the physical policy seam owns eight
  policy/external-extension/native-host targets, including the shared Mozilla
  registration. KeePassXC's supported installer owns Vivaldi's per-user native
  registration; the Browser UX contribution leaves the generic core Vivaldi
  native endpoint absent. Explicit `replacementPolicyOwnership = true` on the
  selected target host permits activation to retract Vivaldi/Floorp plists and
  known external manifests when endpoints are disabled, while unselected hosts
  retain the default `false` and remain untouched. Retraction never removes
  KeePassXC-owned registrations or browser profiles.
- Public composition ([`delivery/composition/composition.patch`](composition.patch),
  [`delivery/composition/browser-ux-host-selection.nix`](browser-ux-host-selection.nix)):
  gates shared local configuration and replacement casks/claims to the synthetic
  target host fixture `example-current-mac` while leaving the synthetic
  predecessor host fixture `example-previous-mac` and unselected hosts unchanged.
- Local configuration ([`delivery/composition/browser-ux.toml.patch`](browser-ux.toml.patch),
  [`delivery/composition/browser-ux.toml`](browser-ux.toml)): enables Vivaldi
  Mail preservation (`preserve-resolved = true`) and the three-product
  Apple/Proton extension trial (`apple-proton-trial.enable = true`) on the
  selected target host while preserving existing opt-outs.

## Offline verification and rollout helpers

In-tree verification exercises these artifacts hermetically without live external
checkouts or host writes:

- [`delivery/evaluate-installed-inputs.nix`](../evaluate-installed-inputs.nix)
  evaluates explicit source roots and host posture readback without calling
  `builtins.getFlake` internally.
- [`delivery/build-manifest.py`](../build-manifest.py) and
  [`delivery/rollout.py`](../rollout.py) implement preflight `check`, attended
  `execute` and checksum-verified `rollback` over the eight physical policy,
  external-extension and native-host targets, tested against synthetic fixtures
  in [`tests/delivery-rollout.test.py`](../../tests/delivery-rollout.test.py) and
  [`tests/primary-cutover-owner.test.py`](../../tests/primary-cutover-owner.test.py).

Before any future attended execution in a downstream composition, follow
[ONBOARDING.md](../ONBOARDING.md): inspect the Vivaldi VPN extension route,
confirm Mail/Calendar/Feeds remain enabled, and verify only the eight planned
policy targets. If a browser's prerequisites remain unresolved, `--browsers`
restricts `check`/`execute` to healthy lanes (`chrome`, `firefox`, `floorp`,
`vivaldi`).

## Assisted readback and rollback boundaries

- Reload `chrome://policy` / `vivaldi://policy` and inspect `about:policies`
  (`Active` and `Errors`) in Firefox/Floorp after any downstream policy apply.
- Verify KeePassXC with a synthetic local fixture and normal attended native
  consent; check the content blocker (uBOL for Vivaldi, uBO for Floorp),
  HTTPS/permissions/DoH, scrolling and fullscreen behavior separately.
- `delivery/rollout.py rollback` validates recorded backup checksums before
  restoring prior file, symlink or absent state for the eight managed policy
  targets. Configuration backups do not include browser profile or extension
  storage; releasing managed extension policy can cause a browser to remove
  managed extension state. Prefer the browser's extension disable toggle when
  pausing a trial without releasing policy.
