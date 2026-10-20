# Destination-owned structured representation of Chrome managed policy.
# Semantically validated to match legacy chrome-policy.plist via AST comparison.
# Modernized in BUX3B2B to consume semantic extension durability renderer.
# Contributed to programs.browserBaseline.chrome.managedPreferences.
# BUX5C0 adds PasswordManagerEnabled = false only while KeePassXC is the configured
# password authority (docs/architecture/browser-operator-preferences.md).
{ keepassxcEnabled
, optOut
, appleProtonEnabled ? false
, omitAppleProtonVpn ? false
, credentialProvider ? "legacy"
, protonVpnEnabled ? appleProtonEnabled
, ...
}:
let
  extensionPolicy = import ../extension-policy.nix;
  passwordAuthority =
    if credentialProvider == "apple" then
      { PasswordManagerEnabled = false; }
    else if keepassxcEnabled then
      { PasswordManagerEnabled = false; }
    else
      { };
in
passwordAuthority
// {
  AudioCaptureAllowedUrls = [
    "https://meet.google.com/"
    "https://[*.]zoom.us/"
    "https://[*.]zoomgov.com/"
    "https://teams.microsoft.com/"
    "https://[*.]teams.microsoft.com/"
    "https://teams.live.com/"
    "https://teams.cloud.microsoft/"
    "https://[*.]webex.com/"
    "https://[*.]goto.com/"
    "https://[*.]gotomeeting.com/"
    "https://[*.]ringcentral.com/"
    "https://[*.]whereby.com/"
    "https://meet.jit.si/"
    "https://doxy.me/"
    "https://[*.]doxy.me/"
    "https://[*.]simplepractice.com/"
    "https://[*.]therapynotes.com/"
    "https://[*.]mdlive.com/"
    "https://[*.]amwell.com/"
    "https://[*.]teladoc.com/"
    "https://[*.]teladochealth.com/"
  ];
  BlockThirdPartyCookies = true;
  DefaultAutomaticDownloadsSetting = 3;
  DefaultGeolocationSetting = 3;
  DefaultMediaStreamSetting = 3;
  DefaultNotificationsSetting = 3;
  DnsOverHttpsMode = "off";
  ExtensionInstallForcelist = [
    "felphkbfjadmcejnibcmcncimlappdde;https://clients2.google.com/service/update2/crx"
  ];
  ExtensionSettings = extensionPolicy.renderChromeExtensionSettings {
    inherit keepassxcEnabled optOut appleProtonEnabled omitAppleProtonVpn credentialProvider protonVpnEnabled;
  };
  HttpsOnlyMode = "force_balanced_enabled";
  VideoCaptureAllowedUrls = [
    "https://meet.google.com/"
    "https://[*.]zoom.us/"
    "https://[*.]zoomgov.com/"
    "https://teams.microsoft.com/"
    "https://[*.]teams.microsoft.com/"
    "https://teams.live.com/"
    "https://teams.cloud.microsoft/"
    "https://[*.]webex.com/"
    "https://[*.]goto.com/"
    "https://[*.]gotomeeting.com/"
    "https://[*.]ringcentral.com/"
    "https://[*.]whereby.com/"
    "https://meet.jit.si/"
    "https://doxy.me/"
    "https://[*.]doxy.me/"
    "https://[*.]simplepractice.com/"
    "https://[*.]therapynotes.com/"
    "https://[*.]mdlive.com/"
    "https://[*.]amwell.com/"
    "https://[*.]teladoc.com/"
    "https://[*.]teladochealth.com/"
  ];
}
