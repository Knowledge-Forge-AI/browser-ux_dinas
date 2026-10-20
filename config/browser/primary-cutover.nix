# Primary Browser UX cutover contract, decoupled intents, and lifecycle semantics.
# Captures target intent:
#   - Active browsers: Vivaldi, Floorp, Safari
#   - Retired delivery: Chrome, Firefox (delivery retired, inherited baseline intact)
#   - Decoupled credential provider: Apple (iCloud only credential extension, VPN preserved,
#     native suppression independent of keepassxcEnabled, WebAuthn unaffected, KeePass vault not deleted)
#   - Decoupled productivity: Vivaldi UI intent feeds-only with data retention (no raw pref invented)
#   - Decoupled search and bookmarks (shallow supported adapter, imported trees untouched)
#   - Safari: five Wipr component states and supported attended adapters represented honestly

let
  safari = import ./safari.nix;
  replacements = import ./replacements;
  extensionPolicy = import ./extension-policy.nix;
  chromiumBaseline = import ./families/chromium.nix;
  geckoBaseline = import ./families/gecko.nix;

  appleExtensionIds = {
    chrome = {
      icloudPasswords = "pejdijmoenmkgeppbflobdenhhabjlaj";
      protonPass = "ghmbeldphafepmbegfdlkpapadhbakde";
      protonVpn = "jplgfhpmjnbigmhklmmbgecoobifkmpa";
      keepassxc = "oboonakemofpalcgghocfoadofidjkkk";
    };
    gecko = {
      icloudPasswords = "password-manager-firefox-extension@apple.com";
      protonPass = "78272b6fa58f4a1abaac99321d503a20@proton.me";
      protonVpn = "vpn@proton.ch";
      keepassxc = "keepassxc-browser@keepassxc.org";
    };
  };

  targetIntent = {
    schema = "browser-ux-primary-cutover-v1";

    # Decoupled browser lifecycle intent
    browsers = {
      active = [ "vivaldi" "floorp" "safari" ];
      retired = [ "chrome" "firefox" ];
    };

    lifecycle = {
      chrome = {
        state = "retired";
        delivery = false;
        baselineIntact = true;
        inheritableFamily = "chromium";
      };
      firefox = {
        state = "retired";
        delivery = false;
        baselineIntact = true;
        inheritableFamily = "gecko";
      };
      vivaldi = {
        state = "active";
        delivery = true;
        inheritFrom = "chrome";
      };
      floorp = {
        state = "active";
        delivery = true;
        inheritFrom = "firefox";
      };
      safari = {
        state = "active";
        delivery = "system";
      };
    };

    # Decoupled credential provider intent
    credentials = {
      provider = "apple";
      installedExtensions = {
        vivaldi = [ appleExtensionIds.chrome.icloudPasswords ];
        floorp = [ appleExtensionIds.gecko.icloudPasswords ];
      };
      removedExtensions = {
        vivaldi = [
          appleExtensionIds.chrome.keepassxc
          appleExtensionIds.chrome.protonPass
        ];
        floorp = [
          appleExtensionIds.gecko.keepassxc
          appleExtensionIds.gecko.protonPass
        ];
      };
      vpnPreserved = {
        vivaldi = appleExtensionIds.chrome.protonVpn;
        floorp = appleExtensionIds.gecko.protonVpn;
      };
      nativeSuppressionIndependentOfKeepass = true;
      webAuthnUnaffected = true;
      nativePasskeysRetained = true;
      keepassAppVaultNotDeleted = true;
    };

    # Decoupled productivity intent
    productivity = {
      vivaldi = {
        intent = "feeds-only";
        dataRetention = true;
        settingWriter = false;
        rawPrefInvented = false;
        selection = "FEEDS_ONLY_PRESERVE_DATA";
      };
    };

    # Decoupled search intent
    search = {
      vivaldi = { provider = "Startpage"; ordinary = true; private = true; adapter = "supported-search-settings"; observed = "PENDING"; };
      floorp = { provider = "Startpage"; ordinary = true; private = true; adapter = "installed-SearchEngines-schema-plus-attended-readback"; observed = "PENDING"; };
      safari = {
        provider = "Startpage";
        mechanism = "attended-safari-settings";
        status = "PENDING_SUPPORTED_MECHANISM";
      };
    };

    # Decoupled bookmark intent
    bookmarks = {
      folder = "Browser UX";
      shortcuts = [
        { title = "Google Search AI Mode"; url = "https://www.google.com/aimode"; }
        { title = "ChatGPT"; url = "https://chatgpt.com/"; }
      ];
      locations = {
        vivaldi = "Bookmarks Bar";
        floorp = "Bookmarks Toolbar";
        safari = "Favorites";
      };
      shallowAdapterOnly = true;
      profileParser = false;
      importedTreesUntouched = true;
    };

    inherit safari;
  };

  # Evaluates desired source semantics; this is not installed/effective runtime proof.
  evaluateCutover =
    { keepassxcEnabled ? false
    , optOut ? [ ]
    , personalHostTrial ? true
    , currentHostResolved ? true
    , preserveResolved ? true
    , omitAppleProtonVpn ? false
    }:
    let
      # Render Vivaldi with Apple credential provider and feeds-only productivity intent
      vivaldiRender = replacements.render "vivaldi" {
        inherit keepassxcEnabled optOut personalHostTrial;
        inherit currentHostResolved preserveResolved omitAppleProtonVpn;
        mailEnabled = false;
        credentialProvider = "apple";
        productivityIntent = "feeds-only";
        appleProtonEnabled = true;
      };

      # Render Floorp with Apple credential provider
      floorpRender = replacements.render "floorp" {
        inherit keepassxcEnabled optOut personalHostTrial;
        credentialProvider = "apple";
        appleProtonEnabled = true;
        searchProvider = "Startpage";
      };

      # Chrome and Firefox baselines evaluated with Apple credential choice
      chromeBaseline = chromiumBaseline {
        inherit keepassxcEnabled optOut omitAppleProtonVpn;
        appleProtonEnabled = true;
        credentialProvider = "apple";
      };

      firefoxBaseline = geckoBaseline {
        inherit keepassxcEnabled optOut;
        appleProtonEnabled = true;
        credentialProvider = "apple";
      };

      vExts = vivaldiRender.desired.ExtensionSettings;
      fExts = floorpRender.desired.ExtensionSettings;

      cIds = appleExtensionIds.chrome;
      gIds = appleExtensionIds.gecko;
    in
    {
      inherit targetIntent safari;
      inherit vivaldiRender floorpRender;
      inherit chromeBaseline firefoxBaseline;

      # Source lifecycle states
      lifecycle = {
        activeBrowsers = targetIntent.browsers.active;
        retiredBrowsers = targetIntent.browsers.retired;
        chromeDelivery = false; # retired delivery
        firefoxDelivery = false; # retired delivery
        chromeBaselineIntact = chromeBaseline != { };
        firefoxBaselineIntact = firefoxBaseline != { };
      };

      # Source credential provider semantics
      credentials = {
        provider = "apple";
        # KeepassXC removed from both
        keepassxcRemovedFromVivaldi = !(vExts ? ${cIds.keepassxc});
        keepassxcRemovedFromFloorp = !(fExts ? ${gIds.keepassxc});
        # Proton Pass removed from both
        protonPassRemovedFromVivaldi = !(vExts ? ${cIds.protonPass});
        protonPassRemovedFromFloorp = !(fExts ? ${gIds.protonPass});
        # iCloud Passwords installed in both
        iCloudPasswordsInstalledInVivaldi =
          (vExts ? ${cIds.icloudPasswords})
          && vExts.${cIds.icloudPasswords}.installation_mode == "normal_installed";
        iCloudPasswordsInstalledInFloorp =
          (fExts ? ${gIds.icloudPasswords})
          && fExts.${gIds.icloudPasswords}.installation_mode == "normal_installed";
        # Proton VPN preserved in both
        protonVpnPreservedInVivaldi =
          (vExts ? ${cIds.protonVpn})
          && vExts.${cIds.protonVpn}.installation_mode == "normal_installed";
        protonVpnPreservedInFloorp =
          (fExts ? ${gIds.protonVpn})
          && fExts.${gIds.protonVpn}.installation_mode == "normal_installed";
        # PasswordManagerEnabled suppressed independent of keepassxcEnabled
        passwordManagerSuppressedInVivaldi =
          vivaldiRender.desired.PasswordManagerEnabled == false;
        passwordManagerSuppressedInFloorp =
          floorpRender.desired.PasswordManagerEnabled == false;
        # KeePass native app and vault retained
        keepassAppVaultNotDeleted = true;
        webAuthnUnaffected = true;
      };

      # Source productivity semantics
      productivity = {
        vivaldiUiIntent = vivaldiRender.featureOverlays.mail.uiIntent or null;
        vivaldiDataRetention = vivaldiRender.featureOverlays.mail.dataRetention or false;
        rawPrefInvented = vivaldiRender.featureOverlays.mail.rawPrefInvented or true;
        mailEnabledInOverlay = vivaldiRender.featureOverlays.mail.requested;
      };

      # Source Safari Wipr component states
      safariComponents = {
        componentCount = safari.contentBlocking.componentCount;
        components = safari.contentBlocking.components;
        supportedAttendedAdapters = safari.contentBlocking.supportedAttendedAdapters;
        unattendedPolicySupport = safari.contentBlocking.unattendedPolicySupport;
      };
    };
in
{
  inherit targetIntent safari appleExtensionIds evaluateCutover;
}
