# Browser UX operator preference contract

Status: source-prepared. Every behavior below marked **GUI-pending** needs an
attended observation before it can be called qualified.

This contract covers the managed Chrome and Firefox baselines. Vivaldi and Floorp
inherit their declared settings through the source-only
[replacement candidate mapping](../../config/browser/replacements/default.nix),
with delivery and runtime parity held for SYSTEM1. Mullvad Browser and Tor Browser require separate
mapping before adoption. Tor Browser must never be
customized in a way that weakens its anti-fingerprinting model, so this contract
does not apply to it by default.

## A. Always-visible scrollbars

### Host setting (external handoff)

The macOS "Show scroll bars: Always" setting (`NSGlobalDomain AppleShowScrollBars =
"Always"`) is the only authority for the system-wide setting. The desktop/composition
owner applies it; Browser UX never writes it. Browser-specific overlay-scrollbar
preferences (for example Firefox `ui.useOverlayScrollbars`) are deliberately not set,
so the host and the browsers cannot disagree.

### Top-layer enforcement (R5 source candidate)

The MV3 extension in `extensions/browser-ux-scrollbars/` (introduced at version
`0.3.0` in R5; updated to `0.4.0` in R6/R7 below) places
rails for eligible visible vertical scrollers in one extension-owned manual
popover. It uses a closed shadow root after DOMContentLoaded and only after the
background confirms USER-origin insertion of the native and host stylesheets.
The shell is pointer-transparent; individual narrow tracks accept pointer drag,
track clicks and wheel input. Native page keyboard scrolling remains available.

The existing native sheet remains `scrollbar-width: auto !important` and
`scrollbar-color: GrayText Canvas !important` on `*`. The additional USER-origin
host sheet pins the hidden and open states separately, disables animation and
transitions, neutralizes author presentation and generated content, and makes
the backdrop transparent and non-intercepting. No ordinary-document fallback
is used if Popover API support is absent.

Every eligible visible scroller receives a rail regardless of native suppression
or ordinary overlay hit-test evidence. The extension does not change page
layout, overflow, class, style or attributes. Root/body hidden or clip overflow,
inert targets, offscreen strips and layout-clipped strips remain excluded. The
host suspends for element fullscreen, page modal/popover UI, and document
lifecycle inactivity; recovery occurs through bounded normal reevaluation.
Persistent manual page popovers therefore suspend all extension rails.

Progressive discovery has fixed node/time, candidate, rail and backoff limits.
System-derived Canvas and GrayText colors are used. No page text is copied and
no network, storage or console output is needed. Permissions and frame matching
remain unchanged: scripting with http/https host permission, all_frames,
match_about_blank and match_origin_as_fallback. Browser floors remain Chrome 121
and Firefox 140.0.

Source models do not prove rendering. Attended qualification must separately
observe root-gutter painting/pointer routing in Chrome and Firefox, ordinary
overlays, root generated paint/masks/clips, nested scrollers, top-layer
suspension and recovery, and layout preservation.

### Remaining limits and attended holds

- Classic scrollbar thickness must be measured within the supported range;
  macOS `AppleShowScrollBars=Always` remains the host prerequisite.
- Root-gutter paintability is engine-dependent and unresolved until attended
  observation. An ambiguous hit-test failure hides the entire custom shell as
  `HIT_TEST_UNCONFIRMED` and retries with bounded backoff; attended
  `ROOT_GUTTER_UNPAINTABLE` or native-only visibility fails R5 qualification; no broad rail width is invented.
- Closed page shadow roots are inaccessible to discovery and top-layer checks.
  Their modal/popover/scroller coverage, and top-layer UI in open roots attached
  after discovery without a light-tree mutation, remain material contract gaps.
  R5 source acceptance and accepted GUI-kit sealing are deferred.
- Transformed/zoomed nested geometry and arbitrary nested clip paths are
  refused when placement cannot be established. Horizontal bars and cross-frame
  occlusion are outside this implementation.
- Author JavaScript can locate/remove/hide the host. Structural selectors and
  page event observers can see the host; CSS resistance does not defeat a
  JavaScript adversary.
- Browser-internal/restricted pages, file pages, direct opaque URLs and
  incognito/private contexts remain outside the manifest's default coverage.
  Related-frame and shadow reach remain separately observed as in R3.
- Rails are aria-hidden and non-focusable. Accessible custom-scrollbar keyboard
  semantics require a separate reviewed design.

R4's ordinary-document counterexamples remain historical fixtures. No permanent
registration, signing, publication or default-profile mutation is enabled in this
source release; always-visible scrollbar closure still requires attended GUI
qualification.

### Distribution (prepared; not performed)

The extension is source-prepared, tested and deterministically packaged, but it is
**not registered** in `ExtensionSettings`. In summary:

- **Firefox release** requires Mozilla signing. The selected route is AMO **unlisted**
  (self-distribution) signing of the exact package under the permanent Gecko id, with
  signing credentials kept outside the repository. The signed XPI is then
  force-installed from a hash-pinned local `file:///` `install_url`. That avoids a
  public listing and a local web service, and operation stays offline.
- **Chrome on macOS** force-installs extensions from outside the Web Store only on
  MDM-, MCX- or Chrome Enterprise Core-managed machines. The selected route is an
  **Unlisted** Chrome Web Store item. Once the store assigns its id, it is registered
  through the existing `force_installed` plus Web Store `update_url` shape. Network is
  used only for install and update.

Registration later goes through `config/browser/extension-policy.nix` as a
`required` entry. The gecko id `scrollbar-visibility@browser-ux` becomes permanent
at first signing.

## B. Full-screen browser UI

Wanted: in ordinary interactive full screen, the toolbars, tabs and address bar
hide. Moving the pointer to the top edge reveals them, and moving away lets them
hide again. This is not kiosk mode.

**Firefox.** The policy sets `Preferences."browser.fullscreen.autohide" = { Value
= true; Status = "locked"; }`.

- `browser.` is an allowed `Preferences` prefix.
- Upstream `firefox.js` defaults this pref to `false` on macOS (bug 1702563) and
  `true` elsewhere, so the policy is load-bearing.
- `FullScreen.hideNavToolbox` returns early when the pref is false, and the
  top-edge toggler's `mouseover` reveals the toolbox again.
- `locked` is chosen over `default`, because `default` would leave an earlier user
  toggle-off in place. The cost is that the "Hide Toolbars" context-menu toggle has
  no effect while the pref is locked. `user` would re-apply the value at every
  startup and keep the toggle usable within a session.
- **GUI-pending.**

**Chrome.** "View › Always Show Toolbar in Full Screen" is the per-profile pref
`browser.show_fullscreen_toolbar`. No enterprise policy maps to it, so Browser UX
renders nothing for it. During attended qualification the operator unchecks it in
each profile. That setting is per profile and is not made durable by Browser UX.
**GUI-pending.**

Nothing kiosk-like is rendered:

- no kiosk keys;
- no `full-screen-api.*` prefs;
- no `userChrome`/`userContent` files;
- no `toolkit.legacyUserProfileCustomizations.stylesheets`.

The contract asserts all of these are absent.

**Host setting (external handoff).** The macOS menu bar should hide in full screen
and show at the top edge. That is the Control Center "Automatically hide and show
the menu bar" option set to hide in full screen. The desktop/composition owner
verifies the exact defaults key for the target macOS release and applies it.
Browser UX never writes it.

## C. KeePassXC as password authority

These parts are unchanged:

- the KeePassXC-Browser semantic identities: Chrome `oboonakemofpalcgghocfoadofidjkkk`
  and Firefox `keepassxc-browser@keepassxc.org`;
- `force_installed` while `keepassxc.enable = true`, which is the default;
- the native-messaging host `org.keepassxc.keepassxc_browser` and its pinned
  manifests.

New in BUX5C0: while `keepassxc.enable = true`, both browsers render
`PasswordManagerEnabled = false`. With `keepassxc.enable = false` the key is omitted
(never rendered `true`), so an operator who opts out of KeePassXC gets the browser
defaults back rather than having no password manager. KeePassXC-Browser itself stays
force-installed in that case unless it is also opted out (see the README opt-out
rules).

Effects, quoted from upstream sources and **GUI-pending**:

- **Chrome.** Users cannot save new passwords, but previously saved passwords still
  work. With `PasswordManagerEnabled` disabled, passkey saving is also disabled
  (`PasswordManagerPasskeysEnabled` does not apply). KeePassXC is therefore the
  authority for *new* credentials. Removing existing Chrome entries is an
  operator-only decision.
- **Firefox.** The policy locks `signon.rememberSignons` to the policy value. When
  disabled, it also blocks `about:logins` and locks the "Saved logins" button and
  the contextual password manager. Existing logins remain on disk but are
  unreachable in the UI. **Operator handoff:** export any Firefox logins intended
  for KeePassXC *before* the activation that first applies this policy. Current
  `releaseCandidate.deployPreconditions` in `flake.nix` records the held seven-role
  cutover and Apple Passwords compatibility preconditions while preserving
  credential stores and recovery vaults.

Firefox `OfferToSaveLoginsDefault = false`, `AutofillAddressEnabled = false` and
`AutofillCreditCardEnabled = false` are unchanged. Chrome gains no `Autofill*` key,
so the address/payment asymmetry between the browsers is recorded, not broadened.
No code deletes, reads or migrates credential stores.

## D. uBlock baseline

The browser-family split is unchanged:

- **Firefox:** full uBlock Origin, `uBlock0@raymondhill.net`, `required`.
- **Chrome/Chromium:** uBlock Origin Lite, `ddkjiahejlhfcafbddmgiahcphecmpfh`,
  `required`.

The obsolete Chrome Web Store id for full uBO, `cjpalhdlnbpafiamejdnhcphjbkeiagm`,
must never appear.

No managed settings are added. The upstream defaults already express the requested
baseline:

- uBO's own filters, EasyList, EasyPrivacy, Peter Lowe's list and the Online
  Malicious URL Blocklist;
- uBOL's default rulesets in its default filtering mode.

Concretely, Browser UX adds no Firefox `3rdparty` key and no Chrome per-extension
managed storage. The latter would need a separate `com.google.Chrome.extensions.<id>`
domain that the core seam does not offer.

The uBO/uBOL default list selection is GUI-pending: confirm it in the dashboard.

**No-stacking rule (future browsers).** Do not stack a second content blocker with
uBO/uBOL, such as Brave Shields alongside uBO, without an explicit compatibility
reason recorded with that browser's mapping.

## What would make this contract wrong

- Upstream changes `scripting.insertCSS` so that `origin: "USER"` is ignored or
  author-overridable, or browsers stop treating user `!important` as outranking
  author `!important`.
- A GUI observation shows the shipped sheet making a non-scrollable or
  `overflow: hidden` box scroll, or changing layout.
- Blink or Gecko still applies author `::-webkit-scrollbar*` rules to an element whose
  computed `scrollbar-color` is not `auto`, or takes the viewport's scrollbar style from
  an element that `*` does not reach.
- `GrayText` on `Canvas` is unreadable or invisible in some color scheme (fixture c26),
  or on a dark page that declares no color scheme (fixture c27).
- A non-auto `scrollbar-color` changes scrollbar width or layout on macOS.
- Firefox removes `browser.` from the allowed `Preferences` prefixes, or the
  macOS full-screen toolbox stops honoring `browser.fullscreen.autohide`.
- Chrome adds a policy for the full-screen toolbar: Browser UX should then render
  it instead of relying on a per-profile toggle.
- `PasswordManagerEnabled = false` turns out to delete or migrate stored
  credentials, or stops covering passkeys.
- uBO/uBOL upstream defaults diverge from the baseline listed in D. The baseline
  would then need explicit managed settings.

## R7 coverage recovery source candidate

The R7 candidate repairs the isolated cooldown path and retains unfinished
incremental light/shadow coverage across epochs. Local overload retries a full
walk after cooldown; a structural walk over 60,000 nodes requires a later page
addition/removal and 1–30 second backoff. Permanent authority loss stays latched.
Large documents under continuous mutation can remain suspended until a quiet
coverage interval; this is an availability residual. Attended Chrome/Firefox
qualification and distribution signing remain pending.

## R6 closed-shadow source candidate

The 0.4.0 candidate adds a document-start MAIN sentinel and an explicit handshake.
The isolated runtime begins UNKNOWN and opens its existing manual top-layer shell
only after current-document CLEAR and exact-host binding. ACTIVE, missing/stale
messages, invalid bridge messages, lost instrumentation and coverage limits hide
rails and cancel dragging. Native scrollbars remain underneath.

The sentinel captures future open and closed roots through attachShadow, observes
root-local transitions, and retains at most 256 author roots. A separate bounded
privileged coverage traversal includes closed roots; parser-created or adopted
uncaptured closed roots permanently suspend that document. Coverage does not
depend on rail discovery's bounded queues. Pointermove, drag and placement no
longer query document-wide modal/popover state. Chromium custom rails require
working :open semantics (133+); earlier supported extension versions retain USER
native styling and suspend custom rails.

The R6 attended fixture records early inline closed-root capture separately for
Chrome and Firefox. Empty Firefox frames, late install, MAIN-world JavaScript
interference, wrapper integrity checks and cross-realm calls remain qualification
limits. Source model tests do not establish engine paint or earliest-load behavior.
Ordinary content updates use incremental coverage and preserve drag when verified
in the same observer checkpoint. Work overruns suspend during cooldown and require
a full coverage recheck; actual loss of root authority remains permanent. Attended
GUI qualification, extension signing and permanent policy registration remain
separate integration steps.
