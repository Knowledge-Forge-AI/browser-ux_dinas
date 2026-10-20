# Primary Browser UX cutover executable contracts.
# Evaluates source contracts (runtime behavior requires attended observation):
#   1. Target lifecycle yields Vivaldi/Floorp/Safari active, Chrome/Firefox retired delivery
#      with inherited baseline intact.
#   2. Apple credential choice removes BOTH KeepassXC and Proton Pass install sources for
#      Vivaldi/Floorp, installs iCloud Passwords, preserves Proton VPN, and suppresses
#      built-in password management independent of keepassxcEnabled.
#   3. WebAuthn is unaffected, native passkeys are retained, and KeePass native app/vault is not deleted.
#   4. Safari five Wipr component states and supported attended adapters are represented honestly.
#   5. Vivaldi feeds-only is expressed as supported UI intent with data retention (no raw pref invented).
#   6. Decoupled bookmark intent (shallow supported API, imported trees untouched).
#   7. Legacy default behavior unchanged (compatibility defaults true, provider parameter default legacy).

{ lib
, pkgs ? {
    runCommandLocal = name: _: text: {
      inherit name text;
      __toString = _: "/nix/store/test-${name}";
    };
  }
}:

let
  cutover = import ../config/browser/primary-cutover.nix;
  safari = import ../config/browser/safari.nix;
  extensionPolicy = import ../config/browser/extension-policy.nix;
  chromiumBaseline = import ../config/browser/families/chromium.nix;
  geckoBaseline = import ../config/browser/families/gecko.nix;
  replacements = import ../config/browser/replacements;
  claims = import ../lib/application-claims.nix;

  # Seam fixture evaluator
  evaluateModule = override: (lib.evalModules {
    modules = [
      ./seam-fixture.nix
      ({ lib, ... }: {
        options.networking.hostName = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };
        options.programs.browserBaseline.replacementPolicyOwnership = lib.mkOption {
          type = lib.types.bool;
          default = false;
        };
        options.programs.browserBaseline.vivaldi = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
        };
        options.programs.browserBaseline.floorp = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
        };
      })
      ../modules/default.nix
      override
    ];
  }).config;

  check = name: predicate: assert predicate; pkgs.runCommandLocal name { } ''touch "$out"'';

  cIds = cutover.appleExtensionIds.chrome;
  gIds = cutover.appleExtensionIds.gecko;

  resDefault = cutover.evaluateCutover { };
  resKeepassFalse = cutover.evaluateCutover { keepassxcEnabled = false; };
  resKeepassTrue = cutover.evaluateCutover { keepassxcEnabled = true; };

  # Module-level evaluations
  legacyModuleConfig = evaluateModule { };
  cutoverModuleConfig = evaluateModule {
    networking.hostName = "example-current-mac";
    "browser-ux".configuration = {
      schema = 1;
      primaryCutover = {
        enable = true;
        activeBrowsers = [ "vivaldi" "floorp" "safari" ];
        retiredBrowsers = [ "chrome" "firefox" ];
        credentialProvider = "apple";
        productivityIntent = "feeds-only";
        protonVpnEnabled = true;
      };
      replacements = {
        vivaldi = {
          enable = true;
          inherit-from = "chrome";
          mail = { enable = false; preserve-resolved = false; };
        };
        floorp = {
          enable = true;
          inherit-from = "firefox";
        };
      };
    };
  };
  omittedVpnConfig = evaluateModule {
    networking.hostName = "example-current-mac";
    "browser-ux".configuration.primaryCutover.enable = true;
  };
in
{
  primary-cutover-vpn-posture-required = check "primary-cutover-vpn-posture-required" (
    !(builtins.tryEval omittedVpnConfig."browser-ux".configuration.primaryCutover.enable).success
    && cutoverModuleConfig."browser-ux".configuration.primaryCutover.protonVpnEnabled
    && (legacyModuleConfig."browser-ux".configuration.primaryCutover or null) == null
  );

  primary-cutover-floorp-search-classification = check "primary-cutover-floorp-search-classification" (
    let
      rendered = replacements.render "floorp" {
        credentialProvider = "apple";
        keepassxcEnabled = false;
        searchProvider = "Startpage";
      };
      target = cutoverModuleConfig."browser-ux".replacementRendering.floorp;
    in
    rendered.baselineKeys == builtins.attrNames rendered.policyCapabilities
    && rendered.policyCapabilities.SearchEngines.capability == "UNVERIFIED"
    && rendered.policyCapabilities.SearchSuggestEnabled.staticEvidence.symbolPresent
    && !rendered.policyCapabilities.SearchSuggestEnabled.runtimeQualified
    && rendered.held.SearchEngines.Default == "Startpage"
    && rendered.held.SearchSuggestEnabled == false
    && !(rendered.deliverable ? SearchEngines)
    && target.deliverable.SearchEngines.DefaultPrivate == "Startpage"
    && target.deliverable.SearchSuggestEnabled == false
    && !((replacements.render "floorp" { }).desired ? SearchEngines)
  );

  # 1. Target lifecycle: Vivaldi/Floorp/Safari active, Chrome/Firefox retired delivery with baseline intact
  primary-cutover-browser-lifecycle = check "primary-cutover-browser-lifecycle" (
    # Intent declarations
    resDefault.lifecycle.activeBrowsers == [ "vivaldi" "floorp" "safari" ]
    && resDefault.lifecycle.retiredBrowsers == [ "chrome" "firefox" ]
    && resDefault.lifecycle.chromeDelivery == false
    && resDefault.lifecycle.firefoxDelivery == false
    # Inherited baseline intact
    && resDefault.lifecycle.chromeBaselineIntact
    && resDefault.lifecycle.firefoxBaselineIntact
    && resDefault.chromeBaseline ? BlockThirdPartyCookies
    && resDefault.firefoxBaseline ? Cookies
    # Chrome/Firefox retired delivery does NOT suppress Vivaldi/Floorp family data
    && resDefault.vivaldiRender.deliverable != { }
    && resDefault.floorpRender.deliverable != { }
    && resDefault.vivaldiRender.deliverable ? BlockThirdPartyCookies
    && resDefault.floorpRender.deliverable ? Cookies
    # Module evaluation confirms chrome and firefox disabled in delivery but baselines intact
    && cutoverModuleConfig.programs.browserBaseline.chrome.enable == false
    && cutoverModuleConfig.programs.browserBaseline.firefox.enable == false
    && cutoverModuleConfig.programs.browserBaseline.chrome.managedPreferences != { }
    && cutoverModuleConfig.programs.browserBaseline.firefox.policies != { }
    && cutoverModuleConfig.programs.browserBaseline.vivaldi.managedPreferences != { }
    && cutoverModuleConfig.programs.browserBaseline.floorp.policies != { }
    # Compatibility defaults: chrome.enable and firefox.enable default to true
    && legacyModuleConfig.programs.browserBaseline.chrome.enable == true
    && legacyModuleConfig.programs.browserBaseline.firefox.enable == true
  );

  # 2. Apple credential provider: removes BOTH KeepassXC and Proton Pass for Vivaldi/Floorp
  #    Installs iCloud Passwords, preserves Proton VPN, suppresses built-in password management
  #    independent of keepassxcEnabled, retains native passkeys/WebAuthn, preserves KeePass vault
  primary-cutover-apple-credential-provider = check "primary-cutover-apple-credential-provider" (
    # KeepassXC removed from BOTH Vivaldi and Floorp
    resKeepassFalse.credentials.keepassxcRemovedFromVivaldi
    && resKeepassFalse.credentials.keepassxcRemovedFromFloorp
    && resKeepassTrue.credentials.keepassxcRemovedFromVivaldi
    && resKeepassTrue.credentials.keepassxcRemovedFromFloorp
    # Proton Pass removed from BOTH Vivaldi and Floorp
    && resKeepassFalse.credentials.protonPassRemovedFromVivaldi
    && resKeepassFalse.credentials.protonPassRemovedFromFloorp
    && resKeepassTrue.credentials.protonPassRemovedFromVivaldi
    && resKeepassTrue.credentials.protonPassRemovedFromFloorp
    # iCloud Passwords installed in BOTH Vivaldi and Floorp
    && resDefault.credentials.iCloudPasswordsInstalledInVivaldi
    && resDefault.credentials.iCloudPasswordsInstalledInFloorp
    # Proton VPN preserved independently
    && resDefault.credentials.protonVpnPreservedInVivaldi
    && resDefault.credentials.protonVpnPreservedInFloorp
    # Built-in password management suppressed independent of keepassxcEnabled
    && resKeepassFalse.credentials.passwordManagerSuppressedInVivaldi
    && resKeepassFalse.credentials.passwordManagerSuppressedInFloorp
    && resKeepassTrue.credentials.passwordManagerSuppressedInVivaldi
    && resKeepassTrue.credentials.passwordManagerSuppressedInFloorp
    && cutoverModuleConfig.programs.browserBaseline.chrome.managedPreferences.PasswordManagerEnabled == false
    && cutoverModuleConfig.programs.browserBaseline.firefox.policies.PasswordManagerEnabled == false
    # WebAuthn unaffected, native passkeys retained, KeePass vault not deleted
    && resDefault.credentials.webAuthnUnaffected
    && resDefault.credentials.keepassAppVaultNotDeleted
    && cutover.targetIntent.credentials.nativePasskeysRetained
    && cutover.targetIntent.credentials.webAuthnUnaffected
    && cutoverModuleConfig.programs.browserBaseline.floorp.policies.Preferences."signon.autofillForms".Value == false
    && !(cutoverModuleConfig.programs.browserBaseline.floorp.policies.Preferences ? "security.webauth.webauthn")
    && cutoverModuleConfig.programs.browserBaseline.floorp.policies.SearchEngines.Default == "Startpage"
    && cutoverModuleConfig.programs.browserBaseline.floorp.policies.SearchEngines.DefaultPrivate == "Startpage"
    && (builtins.head cutoverModuleConfig.programs.browserBaseline.floorp.policies.SearchEngines.Add).URLTemplate == "https://www.startpage.com/sp/search?query={searchTerms}"
    && !(builtins.hasAttr cIds.protonPass cutoverModuleConfig.programs.browserBaseline.vivaldi.managedPreferences.ExtensionSettings)
    && builtins.hasAttr cIds.protonVpn cutoverModuleConfig.programs.browserBaseline.vivaldi.managedPreferences.ExtensionSettings
  );

  # 3. Safari: exactly five Wipr component states and supported attended adapters represented honestly
  primary-cutover-safari-wipr-components = check "primary-cutover-safari-wipr-components" (
    let
      w = safari.contentBlocking;
      comps = w.components;
    in
    # Exactly five components
    w.componentCount == 5
    && builtins.length (builtins.attrNames comps) == 5
    # Component 1: WiprBlocker1
    && comps.wiprBlocker1.bundleId == "site.kaylees.Wipr2.WiprBlocker1"
    && comps.wiprBlocker1.appex == "WiprBlocker1.appex"
    && comps.wiprBlocker1.kind == "content-blocker"
    && comps.wiprBlocker1.state == "ATTENDED_ENABLE_REQUIRED"
    # Component 2: WiprBlocker2
    && comps.wiprBlocker2.bundleId == "site.kaylees.Wipr2.WiprBlocker2"
    && comps.wiprBlocker2.appex == "WiprBlocker2.appex"
    && comps.wiprBlocker2.kind == "content-blocker"
    && comps.wiprBlocker2.state == "ATTENDED_ENABLE_REQUIRED"
    # Component 3: WiprBlocker3
    && comps.wiprBlocker3.bundleId == "site.kaylees.Wipr2.WiprBlocker3"
    && comps.wiprBlocker3.appex == "WiprBlocker3.appex"
    && comps.wiprBlocker3.kind == "content-blocker"
    && comps.wiprBlocker3.state == "ATTENDED_ENABLE_REQUIRED"
    # Component 4: WiprBlocker4
    && comps.wiprBlocker4.bundleId == "site.kaylees.Wipr2.WiprBlocker4"
    && comps.wiprBlocker4.appex == "WiprBlocker4.appex"
    && comps.wiprBlocker4.kind == "content-blocker"
    && comps.wiprBlocker4.state == "ATTENDED_ENABLE_REQUIRED"
    # Component 5: WiprBlockerExtra
    && comps.wiprBlockerExtra.bundleId == "site.kaylees.Wipr2.WiprBlockerExtra"
    && comps.wiprBlockerExtra.appex == "WiprBlockerExtra.appex"
    && comps.wiprBlockerExtra.kind == "web-extension"
    && comps.wiprBlockerExtra.state == "ATTENDED_ENABLE_REQUIRED"
    # Honest representation of supported attended adapters
    && w.supportedAttendedAdapters == [ "safari-settings-extensions" "attended-ui-verification" ]
    # Honest representation of platform absence of unattended policy deployment
    && w.unattendedPolicySupport == false
    && w.unattendedPolicyStatus == "UNSUPPORTED_BY_APPLE_PLATFORM"
  );

  # 4. Vivaldi feeds-only: expressed as supported UI intent with data retention (no raw pref invented)
  primary-cutover-vivaldi-productivity-feeds-only = check "primary-cutover-vivaldi-productivity-feeds-only" (
    # Expressed as UI intent feeds-only with data retention
    resDefault.productivity.vivaldiUiIntent == "feeds-only"
    && resDefault.productivity.vivaldiDataRetention == true
    && resDefault.productivity.mailEnabledInOverlay == false
    # Zero raw preference invented
    && resDefault.productivity.rawPrefInvented == false
    && !(resDefault.vivaldiRender.deliverable ? "vivaldi.features.feeds")
    && !(resDefault.vivaldiRender.deliverable ? "vivaldi.features.mail")
    # Live Mail/Calendar/Feeds selection preserved
    && resDefault.vivaldiRender.featureOverlays.mail.selection == "FEEDS_ONLY_PRESERVE_DATA"
    && resDefault.vivaldiRender.featureOverlays.mail.settingWriter == false
    # Claims never deliver Mail and allow productivity/feeds intent
    && claims.replacementApplicationClaims {
      vivaldi = {
        enable = true;
        inherit-from = "chrome";
        mail = { enable = true; preserve-resolved = true; ui-intent = "feeds-only"; };
        productivity = { intent = "feeds-only"; data-retention = true; };
      };
      floorp = { enable = true; inherit-from = "firefox"; };
    } != [ ]
  );

  # 5. Bookmarks: decoupled bookmark intent with shallow adapter and untouched imported trees
  primary-cutover-bookmarks = check "primary-cutover-bookmarks" (
    let
      b = cutover.targetIntent.bookmarks;
      shortcuts = map (s: s.title) b.shortcuts;
    in
    builtins.elem "Google Search AI Mode" shortcuts
    && builtins.elem "ChatGPT" shortcuts
    && b.folder == "Browser UX"
    && b.locations.vivaldi == "Bookmarks Bar"
    && b.locations.floorp == "Bookmarks Toolbar"
    && b.locations.safari == "Favorites"
    && b.shallowAdapterOnly == true
    && b.profileParser == false
    && b.importedTreesUntouched == true
  );

  # 6. Legacy default behavior unchanged: compatibility defaults true, provider render default legacy
  primary-cutover-legacy-compatibility = check "primary-cutover-legacy-compatibility" (
    let
      legacyChrome = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; };
      legacyFirefox = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; };
      legacyChromeNoKeepass = chromiumBaseline { keepassxcEnabled = false; optOut = [ ]; };
    in
    # Baseline render parameter defaults to legacy
    legacyChrome.PasswordManagerEnabled == false
    && builtins.hasAttr cIds.keepassxc legacyChrome.ExtensionSettings
    && !(builtins.hasAttr "PasswordManagerEnabled" legacyChromeNoKeepass)
    && builtins.hasAttr gIds.keepassxc legacyFirefox.ExtensionSettings
    # Module evaluation with empty override retains exact legacy configuration
    && legacyModuleConfig.programs.browserBaseline.chrome.enable == true
    && legacyModuleConfig.programs.browserBaseline.firefox.enable == true
    && legacyModuleConfig."browser-ux".primaryCutover.enable == false
    # Old assumption of trial 4 active browsers removed from primary cutover path
    && cutover.targetIntent.browsers.active == [ "vivaldi" "floorp" "safari" ]
    && cutover.targetIntent.browsers.retired == [ "chrome" "firefox" ]
  );
}
