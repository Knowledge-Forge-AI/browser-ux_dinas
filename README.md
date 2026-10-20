# DINAS Browser UX

DINAS Browser UX develops browser policy contributions, convenience commands and
scrollbar presentation for DINAS and nix-darwin compositions.

**v0.0.1 is the first public source preview.** Interfaces and integration remain
experimental. This preview publishes source and documentation; it does not publish
installable browser-extension packages, binary release assets or registry packages.

## Included source

- Declarative Chrome and Firefox baseline policies and extension classifications.
- Vivaldi and Floorp replacement-policy models, with explicit capability limits.
- Browser-role and credential-provider configuration contracts.
- Browser UX Scrollbar Visibility source, currently version 0.4.0, with local
  scroll controls and bounded presentation work.
- Convenience-command sources, synthetic fixtures and source-level checks.

The repository preview version and the scrollbar extension version are separate.
The dormant command package is not automatically selected as a workstation command
owner. The dormant Brave YouTube app writer (`modules/brave-youtube-app-writer.sh`)
manages only the current public app identity (`ai.knowledge-forge.dinas.brave-youtube`
at `~/Applications/Brave YouTube.app`), the legacy Chrome Web App shortcut
(`agimnkijcaahngcdmfeangaknmldooml`), and the legacy `~/Library/Application Support/YouTube Brave`
profile directory rename; historical pre-curation private app bundle names and
identities are omitted from this public preview.

## Integration boundary

The default module contributes semantic configuration through the DINAS
programs.browserBaseline contract. A compatible composition provides the option
definitions and physical policy writers. This is not a standalone workstation
installer.

Policy declarations and source checks do not prove effective browser behavior.
Native installation, browser policy readback, credential-provider compatibility
and attended user-interface qualification remain distinct integration steps.
Host-selection examples use synthetic current and predecessor machine names and
must be adapted deliberately in a private composition.

Keep personal browser profiles, credentials, managed-policy snapshots and
operator evidence outside public source. Loading this repository does not grant
authority to alter existing profiles or activate a workstation configuration.

## Development

The current flake provides checks for aarch64-darwin with pinned Nix inputs.
From a checkout, evaluate the flake without building or activating it (add
`--offline` when evaluating against a pre-populated local Nix store):

    nix flake check --no-build
    nix flake check --offline --no-build

Build an individual existing source contract when appropriate:

    nix build --no-link .#checks.aarch64-darwin.browser-operator-preferences-contract

These commands do not install a browser extension or switch a host configuration.
Native and attended browser harnesses have additional operational prerequisites;
a source preview does not claim that every such lane is portable or qualified.

## Documentation

- [Preview scope](docs/releases/v0.0.1.md)
- [Operator preference contracts](docs/architecture/browser-operator-preferences.md)
- [Clear New Tab durable authority](docs/architecture/clear-new-tab-durable-authority.md)
- [Clear New Tab native characterization](docs/architecture/cnt-native-format-characterization.md)
- [Dormant command package](docs/architecture/command-package.md)
- [Four-browser onboarding notes](delivery/ONBOARDING.md)
- [Matched composition adoption notes](delivery/composition/ADOPTION.md)
- [Example configuration](config/default/browser-ux.toml)
- [Scrollbar privacy policy](PRIVACY.md)
- [Contribution terms](CONTRIBUTING.md)

## License and contributions

DINAS Browser UX is licensed under [AGPL-3.0-or-later](LICENSE), with
[commercial licensing](COMMERCIAL-LICENSE.md) available for proprietary terms.
AGPL permits commercial use subject to its terms. Referenced browsers, extensions
and other third-party material retain their own rights and notices; see [NOTICE](NOTICE).

Contributors retain copyright and grant the project steward the rights described
in [CLA.md](CLA.md), including project sublicensing and relicensing. Every outside
pull request must include the explicit CLA acknowledgment in the
[PR template](.github/pull_request_template.md). A Signed-off-by line does not
replace it.

Project steward and contact: Samuel Leighton Lair,
sam.lair@knowledge-forge.ai.
