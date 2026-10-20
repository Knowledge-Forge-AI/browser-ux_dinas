# Four-browser attended onboarding

This public-preview delivery kit models a synthetic host-selection trial targeting the synthetic host fixture `example-current-mac` in Chrome, Firefox,
Vivaldi and Floorp (as reference documentation for a compatible private composition). It does not claim runtime parity. Brave, Brave YouTube, Safari
and the synthetic predecessor host fixture `example-previous-mac` are outside the additions. Mail, Calendar and Feeds stay on;
no Mail test campaign, profile reset, default-browser change or credential migration is needed.

The shared family catalog ([`config/browser/apple-proton-extensions.json`](../config/browser/apple-proton-extensions.json)) records official publisher identities, permissions,
observed versions and update routes for Proton Pass, Proton VPN and iCloud Passwords.
The matched core policy writer requests actual default-on `normal_installed`
installation, with a browser disable toggle and the existing deliberate policy
opt-out mechanism. Existing required/default-on baseline entries retain their modes.
Versions are observations, not update pins.

1. Inspect existing extension settings and preserve them. For a first install,
   leave Pass signed out and iCloud unpaired until choosing coexistence settings.
   KeePassXC remains primary; built-in browser stores stay off. Use supported
   per-extension autofill/save controls where available. If no manual mode exists,
   retain the unpaired/signed-out stage or make an explicit user-controlled toggle
   decision; do not claim that three simultaneously active providers have an OS
   priority mechanism. Nothing exports/imports passwords, passkeys or TOTP seeds.
2. Confirm Vivaldi's VPN UI/extension manager before apply. The installed app's
   integrated UI source references `jplgfhpmjnbigmhklmmbgecoobifkmpa`; source presence
   does not prove an installed usable instance. Reuse that official instance if
   present. Otherwise the policy requests the same official store identity, so it
   cannot create a second identity. If an update reveals a different integrated
   ID, defer Vivaldi's lane and reconcile its route before applying that lane.
   Chrome, Firefox and Floorp can proceed independently with `--browsers`.
3. After policy delivery, verify the three identities in each browser's extension
   manager and pin their buttons through its toolbar/extension menu. Chrome supports
   `ExtensionSettings.toolbar_pin=default_pinned`; Firefox supports
   `ExtensionSettings.default_area=navbar`. This rollout uses attended pinning to
   preserve existing toolbar choices; fork policy support remains readback-dependent.
   If a browser
   cannot install a build through policy, label it `AWAITING_USER_INSTALL`, open
   that product's official CWS listing in Chrome/Vivaldi or AMO listing in
   Firefox/Floorp from [`config/browser/apple-proton-extensions.json`](../config/browser/apple-proton-extensions.json), choose Add, and accept the vendor's
   normal permissions prompt. Then read back the actual identity/version. A
   rendered entry alone is never `INSTALLED`.
4. Pair/sign in only through official consent, Touch ID/MFA and vendor onboarding.
   Preserve any existing iCloud Passwords extension installation, pairing and
   settings on macOS Sonoma or later. Apple Chrome and Mozilla registrations
   point to the system helper, and reachability/authenticated usability require
   attended verification. The probe checks per-user and system roots
   and reports a shadowing per-user registration separately; it does not assume a
   fixed Apple-helper location. Vivaldi helper reachability and Floorp's
   Mozilla-registration caller acceptance remain unverified until attended testing.
   Never copy/re-sign helpers, impersonate browsers or keep a forced
   browser process alive to bypass pairing. A fork helper gap leaves unrelated
   extensions and ordinary browsing available.
5. Leave Proton VPN disconnected unless the user deliberately chooses otherwise;
   preserve an existing connection and its settings. Do not introduce auto-connect,
   a kill switch, host VPN/system proxy changes or DNS edits. Proton documents a
   Firefox `network.trr.mode=3` caveat; the maintained DoH posture stays unchanged
   and connection/DNS qualification is `RECONCILIATION_PENDING`. Installation does
   not prove leak-free operation. The extension covers only its browser traffic,
   not the other browsers/apps, Proton Bridge or Vivaldi Mail's raw IMAP/SMTP.
   Any optional connection test checks localhost/LAN/development access and
   restores the previous connection state.

Record each feature separately: source prepared, installed, native helper available,
pairing pending, signed in, and USER_VERIFIED_WORKING. Use only a synthetic password,
verification code or alias fixture; never collect live vault/account content or
pairing codes in reports. Visually confirm Mail/Calendar/Feeds remain on without
inspecting account identities or repeating the closed Mail campaign.

Pass TOTP is plan-dependent; iCloud Passwords supports verification codes. Proton
Authenticator is a separate native app, not a fourth auto-installed extension.
Do not move an account's only second factor into a vault that needs that factor.
The catalog's NOT_FOUND_IN_OFFICIAL_CATALOG findings for other Proton/iCloud services
are limited official-catalog research, not a claim about all third-party tools.
SimpleLogin is an optional alias candidate; iCloud Bookmarks is a Windows companion.
Neither is automatically installed here.

Custom scrollbar permanent distribution and Vivaldi fullscreen-hover behavior remain
local gaps. Do not disable signing to close them. For Vivaldi's KeePassXC bridge,
retain existing settings/registration. If absent, use KeePassXC Settings → Browser
Integration → enable Vivaldi, then verify the extension with a synthetic local
fixture and normal native consent. KeePassXC alone owns that per-user registration;
the rollout never overwrites or removes it. Do not turn on extra browser integrations
or change existing vault settings. This setup/readback is pending attended action.

Rollback restores only affected configuration targets and leaves Mail/account
repair untouched. Configuration backups exclude extension data and pairing.
Browser policy removal can uninstall managed extensions, including a pre-existing
extension subsequently taken under management; reinstallation can require pairing
again. `normal_installed` supports disabling for a trial, but is not a guarantee
that releasing policy retains installation or data. Prefer the browser's disable
toggle while keeping trial policy if the user wants a reversible pause.

For a deliberate policy opt-out, retain all existing tokens and add the official
browser-qualified ID under `[browser-ux.extensions]`, for example:

```toml
default-on-opt-out = [
  "chrome:ghmbeldphafepmbegfdlkpapadhbakde",
  "firefox:78272b6fa58f4a1abaac99321d503a20@proton.me",
]
```

These family tokens affect Chrome/Vivaldi and Firefox/Floorp respectively. They
release default-on installation to `allowed`. Inspect extension presence/settings
after that policy change; do not promise data or sign-in preservation. Required
KeePassXC remains managed while its bridge is enabled.

Policy references: [Chrome ExtensionSettings](https://support.google.com/chrome/a/answer/9867568?hl=en),
[Chromium force-install removal semantics](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/Extensions/ExtensionInstallForcelist.yaml),
[Firefox ExtensionSettings](https://firefox-admin-docs.mozilla.org/reference/policies/extensionsettings/),
[KeePassXC native installer](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/NativeMessageInstaller.cpp).
