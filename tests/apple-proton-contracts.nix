# Apple and Proton extension catalog and policy delta contract checks.
# Covers official CWS/Gecko IDs, AMO and package evidence, default-on installation semantics,
# opt-out recognition without baseline drift, source delta allowlist removal invariants,
# Vivaldi integrated VPN deduplication, and password authority preservation.

{ lib, pkgs }:

let
  appleProton = import ../config/browser/apple-proton.nix;
  extensionPolicy = import ../config/browser/extension-policy.nix;
  chromiumBaseline = import ../config/browser/families/chromium.nix;
  geckoBaseline = import ../config/browser/families/gecko.nix;

  catalog = appleProton.catalog;

  # Expected official CWS extension IDs
  expectedChromeIds = {
    protonPass = "ghmbeldphafepmbegfdlkpapadhbakde";
    protonVpn = "jplgfhpmjnbigmhklmmbgecoobifkmpa";
    iCloudPasswords = "pejdijmoenmkgeppbflobdenhhabjlaj";
  };

  # Expected official AMO Gecko extension IDs (resolved from AMO API v5 & signed XPI manifests)
  expectedGeckoIds = {
    protonPass = "78272b6fa58f4a1abaac99321d503a20@proton.me";
    protonVpn = "vpn@proton.ch";
    iCloudPasswords = "password-manager-firefox-extension@apple.com";
  };

  chromeDeltaKeys = [
    expectedChromeIds.protonPass
    expectedChromeIds.protonVpn
    expectedChromeIds.iCloudPasswords
  ];

  geckoDeltaKeys = [
    expectedGeckoIds.protonPass
    expectedGeckoIds.protonVpn
    expectedGeckoIds.iCloudPasswords
  ];
in
{
  # 1. Catalog schema, official IDs, primary evidence hashes, and caveats
  apple-proton-catalog-contract =
    let
      c = catalog;
      exts = c.extensions;

      # Proton Pass evidence validation
      pass = exts."proton-pass";
      passChromeValid = pass.chrome.id == expectedChromeIds.protonPass
        && builtins.match "[0-9]+.*" pass.chrome.observedVersion != null
        && pass.chrome.updateRoute == "https://clients2.google.com/service/update2/crx"
        && lib.hasPrefix "sha256:" pass.chrome.evidenceHash
        && builtins.elem "storage" pass.chrome.permissions
        && builtins.elem "nativeMessaging" pass.chrome.optionalPermissions;
      passGeckoValid = pass.gecko.id == expectedGeckoIds.protonPass
        && builtins.match "[0-9]+.*" pass.gecko.observedVersion != null
        && pass.gecko.strictMinVersion == "109.0"
        && pass.gecko.installRoute == "https://addons.mozilla.org/firefox/downloads/latest/proton-pass/latest.xpi"
        && lib.hasPrefix "sha256:" pass.gecko.evidenceHash
        && builtins.elem "storage" pass.gecko.permissions
        && builtins.elem "nativeMessaging" pass.gecko.optionalPermissions;

      # Proton VPN evidence validation
      vpn = exts."proton-vpn";
      vpnChromeValid = vpn.chrome.id == expectedChromeIds.protonVpn
        && builtins.match "[0-9]+.*" vpn.chrome.observedVersion != null
        && vpn.chrome.updateRoute == "https://clients2.google.com/service/update2/crx"
        && lib.hasPrefix "sha256:" vpn.chrome.evidenceHash
        && builtins.elem "proxy" vpn.chrome.permissions
        && builtins.elem "privacy" vpn.chrome.permissions;
      vpnGeckoValid = vpn.gecko.id == expectedGeckoIds.protonVpn
        && builtins.match "[0-9]+.*" vpn.gecko.observedVersion != null
        && vpn.gecko.strictMinVersion == "109.0"
        && vpn.gecko.installRoute == "https://addons.mozilla.org/firefox/downloads/latest/proton-vpn-firefox-extension/latest.xpi"
        && lib.hasPrefix "sha256:" vpn.gecko.evidenceHash
        && builtins.elem "privacy" vpn.gecko.permissions
        && builtins.elem "proxy" vpn.gecko.optionalPermissions;

      # iCloud Passwords evidence validation
      icloud = exts."icloud-passwords";
      icloudChromeValid = icloud.chrome.id == expectedChromeIds.iCloudPasswords
        && builtins.match "[0-9]+.*" icloud.chrome.observedVersion != null
        && icloud.chrome.updateRoute == "https://clients2.google.com/service/update2/crx"
        && lib.hasPrefix "sha256:" icloud.chrome.evidenceHash
        && builtins.elem "nativeMessaging" icloud.chrome.permissions;
      icloudGeckoValid = icloud.gecko.id == expectedGeckoIds.iCloudPasswords
        && builtins.match "[0-9]+.*" icloud.gecko.observedVersion != null
        && icloud.gecko.strictMinVersion == "128.0"
        && icloud.gecko.installRoute == "https://addons.mozilla.org/firefox/downloads/latest/icloud-passwords/latest.xpi"
        && lib.hasPrefix "sha256:" icloud.gecko.evidenceHash
        && builtins.elem "nativeMessaging" icloud.gecko.permissions;

      # Slugs must never be used as gecko IDs
      noSlugsAsGeckoKeys = !builtins.elem "proton-pass" geckoDeltaKeys
        && !builtins.elem "proton-vpn" geckoDeltaKeys
        && !builtins.elem "proton-vpn-firefox-extension" geckoDeltaKeys
        && !builtins.elem "icloud-passwords" geckoDeltaKeys;

      # Caveats integrity
      caveatsComplete = pass ? caveats && vpn ? caveats && icloud ? caveats
        && pass.caveats ? nativeHelper && pass.caveats ? attendedGaps
        && vpn.caveats ? vpn && vpn.caveats ? attendedGaps
        && icloud.caveats ? nativeHelper && icloud.caveats ? attendedGaps;
    in
    assert c.schema == "browser-ux-apple-proton-catalog-v1";
    assert c.catalogMetadata.targetHost == "example-current-mac";
    assert c.catalogMetadata.targetBrowsers == [ "chrome" "firefox" "vivaldi" "floorp" ];
    assert c.catalogMetadata.excludedTargets == [ "brave" "brave-youtube" "safari" ];
    assert passChromeValid;
    assert passGeckoValid;
    assert vpnChromeValid;
    assert vpnGeckoValid;
    assert icloudChromeValid;
    assert icloudGeckoValid;
    assert noSlugsAsGeckoKeys;
    assert caveatsComplete;
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-catalog-contract" { } ''
      touch "$out"
    '';

  # 2. No baseline drift when appleProtonEnabled is disabled or omitted
  apple-proton-no-baseline-drift-contract =
    let
      chromeBaseDefault = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; };
      chromeBaseExplicitOff = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = false; };

      firefoxBaseDefault = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; };
      firefoxBaseExplicitOff = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = false; };

      chromeSettingsDefault = extensionPolicy.renderChromeExtensionSettings { keepassxcEnabled = true; optOut = [ ]; };
      chromeSettingsExplicitOff = extensionPolicy.renderChromeExtensionSettings { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = false; };

      firefoxSettingsDefault = extensionPolicy.renderFirefoxExtensionSettings { keepassxcEnabled = true; optOut = [ ]; };
      firefoxSettingsExplicitOff = extensionPolicy.renderFirefoxExtensionSettings { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = false; };

      # Verify none of the trial IDs exist in baseline outputs
      chromeHasNoTrial = lib.all (id: !builtins.hasAttr id chromeBaseDefault.ExtensionSettings) chromeDeltaKeys;
      firefoxHasNoTrial = lib.all (id: !builtins.hasAttr id firefoxBaseDefault.ExtensionSettings) geckoDeltaKeys;
    in
    assert chromeBaseDefault == chromeBaseExplicitOff;
    assert firefoxBaseDefault == firefoxBaseExplicitOff;
    assert chromeSettingsDefault == chromeSettingsExplicitOff;
    assert firefoxSettingsDefault == firefoxSettingsExplicitOff;
    assert chromeHasNoTrial;
    assert firefoxHasNoTrial;
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-no-baseline-drift-contract" { } ''
      touch "$out"
    '';

  # 3. Remove only the authorized delta and compare with pre-request output pins.
  apple-proton-delta-allowlist-removal-contract =
    let
      chromeBase = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; };
      chromeTrial = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };

      firefoxBase = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; };
      firefoxTrial = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };

      # Stripping trial delta keys from trial settings yields base settings
      chromeStrippedSettings = builtins.removeAttrs chromeTrial.ExtensionSettings chromeDeltaKeys;
      firefoxStrippedSettings = builtins.removeAttrs firefoxTrial.ExtensionSettings geckoDeltaKeys;

      # Non-ExtensionSettings policy keys are strictly identical
      chromeNonSettingsBase = builtins.removeAttrs chromeBase [ "ExtensionSettings" ];
      chromeNonSettingsTrial = builtins.removeAttrs chromeTrial [ "ExtensionSettings" ];
      firefoxNonSettingsBase = builtins.removeAttrs firefoxBase [ "ExtensionSettings" ];
      firefoxNonSettingsTrial = builtins.removeAttrs firefoxTrial [ "ExtensionSettings" ];
      pins = (builtins.fromJSON (builtins.readFile ./fixtures/replacement-baseline-pins.json)).cases;
      oldEquivalent = case:
        let
          chromeNew = chromiumBaseline (case.args // { appleProtonEnabled = true; });
          firefoxNew = geckoBaseline (case.args // { appleProtonEnabled = true; });
          strip = output: keys: output // { ExtensionSettings = builtins.removeAttrs output.ExtensionSettings keys; };
        in
          builtins.hashString "sha256" (builtins.toJSON (strip chromeNew chromeDeltaKeys)) == case.chrome
          && builtins.hashString "sha256" (builtins.toJSON (strip firefoxNew geckoDeltaKeys)) == case.firefox;
    in
    assert chromeStrippedSettings == chromeBase.ExtensionSettings;
    assert firefoxStrippedSettings == firefoxBase.ExtensionSettings;
    assert chromeNonSettingsBase == chromeNonSettingsTrial;
    assert firefoxNonSettingsBase == firefoxNonSettingsTrial;
    assert builtins.all oldEquivalent (builtins.attrValues pins);
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-delta-allowlist-removal-contract" { } ''
      touch "$out"
    '';

  # 4. Default-on, user-disableable installation semantics when enabled
  apple-proton-default-on-semantics-contract =
    let
      chromeTrial = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };
      firefoxTrial = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };

      cSettings = chromeTrial.ExtensionSettings;
      fSettings = firefoxTrial.ExtensionSettings;

      cUpdateUrl = "https://clients2.google.com/service/update2/crx";
    in
    # Chrome trial entries are normal_installed with update_url
    assert cSettings.${expectedChromeIds.protonPass} == {
      installation_mode = "normal_installed";
      update_url = cUpdateUrl;
    };
    assert cSettings.${expectedChromeIds.protonVpn} == {
      installation_mode = "normal_installed";
      update_url = cUpdateUrl;
    };
    assert cSettings.${expectedChromeIds.iCloudPasswords} == {
      installation_mode = "normal_installed";
      update_url = cUpdateUrl;
    };
    # Firefox trial entries are normal_installed with respective install_url
    assert fSettings.${expectedGeckoIds.protonPass} == {
      installation_mode = "normal_installed";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/proton-pass/latest.xpi";
    };
    assert fSettings.${expectedGeckoIds.protonVpn} == {
      installation_mode = "normal_installed";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/proton-vpn-firefox-extension/latest.xpi";
    };
    assert fSettings.${expectedGeckoIds.iCloudPasswords} == {
      installation_mode = "normal_installed";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/icloud-passwords/latest.xpi";
    };
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-default-on-semantics-contract" { } ''
      touch "$out"
    '';

  # 5. Opt-out semantics transition trial extensions to allowed mode
  apple-proton-opt-out-semantics-contract =
    let
      # Opt out single Chrome extension (Proton Pass)
      chromeOptOutPass = chromiumBaseline {
        keepassxcEnabled = true;
        optOut = [ "chrome:${expectedChromeIds.protonPass}" ];
        appleProtonEnabled = true;
      };
      cSettingsPass = chromeOptOutPass.ExtensionSettings;

      # Opt out all Chrome trial extensions
      chromeOptOutAll = chromiumBaseline {
        keepassxcEnabled = true;
        optOut = map (id: "chrome:${id}") chromeDeltaKeys;
        appleProtonEnabled = true;
      };
      cSettingsAll = chromeOptOutAll.ExtensionSettings;

      # Opt out single Firefox extension (iCloud Passwords)
      firefoxOptOutICloud = geckoBaseline {
        keepassxcEnabled = true;
        optOut = [ "firefox:${expectedGeckoIds.iCloudPasswords}" ];
        appleProtonEnabled = true;
      };
      fSettingsICloud = firefoxOptOutICloud.ExtensionSettings;

      # Opt out all Firefox trial extensions
      firefoxOptOutAll = geckoBaseline {
        keepassxcEnabled = true;
        optOut = map (id: "firefox:${id}") geckoDeltaKeys;
        appleProtonEnabled = true;
      };
      fSettingsAll = firefoxOptOutAll.ExtensionSettings;
    in
    # Single opt-out converts only that extension to allowed
    assert cSettingsPass.${expectedChromeIds.protonPass} == { installation_mode = "allowed"; };
    assert cSettingsPass.${expectedChromeIds.protonVpn}.installation_mode == "normal_installed";
    assert cSettingsPass.${expectedChromeIds.iCloudPasswords}.installation_mode == "normal_installed";

    # Full opt-out converts all trial extensions to allowed
    assert cSettingsAll.${expectedChromeIds.protonPass} == { installation_mode = "allowed"; };
    assert cSettingsAll.${expectedChromeIds.protonVpn} == { installation_mode = "allowed"; };
    assert cSettingsAll.${expectedChromeIds.iCloudPasswords} == { installation_mode = "allowed"; };

    # Firefox single opt-out
    assert fSettingsICloud.${expectedGeckoIds.iCloudPasswords} == { installation_mode = "allowed"; };
    assert fSettingsICloud.${expectedGeckoIds.protonPass}.installation_mode == "normal_installed";
    assert fSettingsICloud.${expectedGeckoIds.protonVpn}.installation_mode == "normal_installed";

    # Firefox full opt-out
    assert fSettingsAll.${expectedGeckoIds.protonPass} == { installation_mode = "allowed"; };
    assert fSettingsAll.${expectedGeckoIds.protonVpn} == { installation_mode = "allowed"; };
    assert fSettingsAll.${expectedGeckoIds.iCloudPasswords} == { installation_mode = "allowed"; };
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-opt-out-semantics-contract" { } ''
      touch "$out"
    '';

  # 6. Opt-out validation recognizes trial extensions regardless of enablement
  apple-proton-validation-contract =
    let
      v = extensionPolicy.validateConfiguration;

      # Each trial extension opt-out is recognized (returns null = valid)
      passChromeRes = v { extensions."default-on-opt-out" = [ "chrome:${expectedChromeIds.protonPass}" ]; };
      vpnChromeRes = v { extensions."default-on-opt-out" = [ "chrome:${expectedChromeIds.protonVpn}" ]; };
      icloudChromeRes = v { extensions."default-on-opt-out" = [ "chrome:${expectedChromeIds.iCloudPasswords}" ]; };

      passGeckoRes = v { extensions."default-on-opt-out" = [ "firefox:${expectedGeckoIds.protonPass}" ]; };
      vpnGeckoRes = v { extensions."default-on-opt-out" = [ "firefox:${expectedGeckoIds.protonVpn}" ]; };
      icloudGeckoRes = v { extensions."default-on-opt-out" = [ "firefox:${expectedGeckoIds.iCloudPasswords}" ]; };

      # All combined
      allTrialRes = v {
        extensions."default-on-opt-out" =
          (map (id: "chrome:${id}") chromeDeltaKeys)
          ++ (map (id: "firefox:${id}") geckoDeltaKeys);
      };

      # Required extensions CANNOT be opted out
      reqChromeRes = v { extensions."default-on-opt-out" = [ "chrome:felphkbfjadmcejnibcmcncimlappdde" ]; };
      reqFirefoxRes = v { extensions."default-on-opt-out" = [ "firefox:clear-new-tab@loftyshaky" ]; };

      # Unknown extensions fail
      unknownChromeRes = v { extensions."default-on-opt-out" = [ "chrome:unknownextensionident" ]; };
      unknownFirefoxRes = v { extensions."default-on-opt-out" = [ "firefox:unknown@extension.org" ]; };

      # Duplicates fail
      duplicateRes = v {
        extensions."default-on-opt-out" = [
          "chrome:${expectedChromeIds.protonPass}"
          "chrome:${expectedChromeIds.protonPass}"
        ];
      };
    in
    assert passChromeRes == null;
    assert vpnChromeRes == null;
    assert icloudChromeRes == null;
    assert passGeckoRes == null;
    assert vpnGeckoRes == null;
    assert icloudGeckoRes == null;
    assert allTrialRes == null;
    assert reqChromeRes == "Cannot opt out required Chrome extension 'felphkbfjadmcejnibcmcncimlappdde'";
    assert reqFirefoxRes == "Cannot opt out required Firefox extension 'clear-new-tab@loftyshaky'";
    assert unknownChromeRes == "Unknown Chrome extension opt-out 'unknownextensionident'";
    assert unknownFirefoxRes == "Unknown Firefox extension opt-out 'unknown@extension.org'";
    assert duplicateRes == "Duplicate extension opt-out detected in default-on-opt-out";
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-validation-contract" { } ''
      touch "$out"
    '';

  # 7. Vivaldi integrated VPN deduplication route
  apple-proton-vivaldi-dedup-contract =
    let
      # Standalone fallback: omitAppleProtonVpn = false -> VPN included
      standaloneChrome = chromiumBaseline {
        keepassxcEnabled = true;
        optOut = [ ];
        appleProtonEnabled = true;
        omitAppleProtonVpn = false;
      };
      # Integrated route: omitAppleProtonVpn = true -> VPN omitted
      integratedChrome = chromiumBaseline {
        keepassxcEnabled = true;
        optOut = [ ];
        appleProtonEnabled = true;
        omitAppleProtonVpn = true;
      };
    in
    # Standalone includes Proton VPN
    assert builtins.hasAttr expectedChromeIds.protonVpn standaloneChrome.ExtensionSettings;
    assert builtins.hasAttr expectedChromeIds.protonPass standaloneChrome.ExtensionSettings;
    assert builtins.hasAttr expectedChromeIds.iCloudPasswords standaloneChrome.ExtensionSettings;

    # Integrated omits Proton VPN but retains Pass and iCloud
    assert !builtins.hasAttr expectedChromeIds.protonVpn integratedChrome.ExtensionSettings;
    assert builtins.hasAttr expectedChromeIds.protonPass integratedChrome.ExtensionSettings;
    assert builtins.hasAttr expectedChromeIds.iCloudPasswords integratedChrome.ExtensionSettings;
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-vivaldi-dedup-contract" { } ''
      touch "$out"
    '';

  # 8. Password authority and KeePassXC invariants are strictly preserved
  apple-proton-password-authority-invariants-contract =
    let
      # With KeePassXC enabled
      chromeKeepass = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };
      firefoxKeepass = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; appleProtonEnabled = true; };

      # With KeePassXC disabled
      chromeNoKeepass = chromiumBaseline { keepassxcEnabled = false; optOut = [ ]; appleProtonEnabled = true; };
      firefoxNoKeepass = geckoBaseline { keepassxcEnabled = false; optOut = [ ]; appleProtonEnabled = true; };
    in
    # PasswordManagerEnabled = false only when KeePassXC is enabled
    assert chromeKeepass.PasswordManagerEnabled == false;
    assert firefoxKeepass.PasswordManagerEnabled == false;
    assert !builtins.hasAttr "PasswordManagerEnabled" chromeNoKeepass;
    assert !builtins.hasAttr "PasswordManagerEnabled" firefoxNoKeepass;

    # KeePassXC extension presence is strictly preserved
    assert chromeKeepass.ExtensionSettings.${extensionPolicy.chromeExtensions.keepassxc.id}.installation_mode == "force_installed";
    assert firefoxKeepass.ExtensionSettings.${extensionPolicy.firefoxExtensions.keepassxc.id}.installation_mode == "force_installed";
    pkgs.runCommandLocal "browser-ux-dinas-apple-proton-password-authority-invariants-contract" { } ''
      touch "$out"
    '';
}
