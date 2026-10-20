# Floorp Proton VPN attended installation

Status: source prepared; installation held pending separate approved release,
fresh Gecko identity and attended authorization. Browser UX installs Floorp and
owns its Proton VPN add-on `vpn@proton.ch`. Core defines no Floorp VPN entry.
Browser UX contributes per-ID data to core's single combined plan renderer;
this creates no competing policy or profile writer.

1. Use the installed Floorp app and the intended existing profile. Record an
   anonymous local profile label, browser version, all existing extension IDs
   and enabled states, forced extension IDs, policy equality baseline, CNT
   wallpaper and credential behavior. Preserve uBO, Clear New Tab, the existing
   Firefox-family convenience suite and Apple Passwords compatibility intent.
   Do not suppress native password storage or remove competing existing state.
   If Proton is already present, skip Add actions and observe it without
   reinstalling. Record OBSERVED_EXISTING rather than ADDED_THIS_SESSION.
   Confirm complete inventories and explicitly confirm any empty baseline.
2. Run core's R3R3 read-only HTTPS identity kit. Require a fresh official AMO
   `guid=vpn@proton.ch`, current XPI manifest ID/version and AMO SHA256 agreement.
   Require browser signing verification on install. A `latest.xpi` URL or the
   pinned upstream builder alone does not attest a current signed package.
3. In that Floorp profile, open the official
   [Proton VPN AMO listing](https://addons.mozilla.org/en-US/firefox/addon/proton-vpn-firefox-extension/).
   Check Proton AG, click **Add to Firefox**, inspect the permissions, then
   approve **Add**. This is an actual per-profile installation procedure.
   If unavailable, blocked or incompatible, stop and retain held status.
   Do not overwrite managed settings or `policies.json`, disable signing, load
   an unpacked/temporary XPI or edit profile databases. Allow normal official
   signed AMO updates; never downgrade or disable updates.
4. Do not log in or connect. Do not enable private browsing or auto-connect.
   Record auto-connect as OFF if visible or UNOBSERVABLE_LOGGED_OUT if not.
5. Read `about:addons` and `about:support` for ID, version, enabled state and
   signing; compare existing extensions, forced IDs, policy values, wallpaper,
   credentials, hardening and DNS settings with the baseline. Feed sanitized
   observations to core's R3R3 presence validator with semanticOwner=browser-ux.
   Pass the fresh identity kit JSON as --identity-evidence and copy its XPI
   SHA256 into identitySha256. Match the installed version to that receipt,
   refreshed during this session (within 24 hours). If AMO updates between
   readback and Add, refresh and compare again without downgrading/reinstalling.
   The receipt binds observed version to a fetched package; installed bytes
   still require browser signing readback. A boolean identity flag is insufficient.
   Presence is distinct from an enabled, authenticated and protected tunnel.
6. Stop on preservation failure. If newly installed here, an attended disable
   of this one add-on is the bounded rollback. Do not delete data or reset an
   already present add-on. Uninstall needs a separate preservation decision.

Floorp compatibility and Firefox DNS/DoH behavior need a later separately
authorized connection canary. Do not set `network.trr.mode`. Record only route
change outcomes; keep IPs, resolvers and raw account/profile data local.
Proton's [official Firefox-family guide](https://protonvpn.com/support/browser-extensions)
supports attended add-on installation; it does not establish this Floorp
version's working tunnel. Mozilla's
[policy reference](https://mozilla.github.io/policy-templates/#extensionsettings)
distinguishes `allowed` from automatic installation. No automatic policy is
selected in this source candidate.
