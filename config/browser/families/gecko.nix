# Destination-owned structured representation of Firefox enterprise policies.
# Semantically validated to match legacy firefox-policies.json["policies"].
# Modernized in BUX3B2B to consume semantic extension durability renderer.
# Contributed to programs.browserBaseline.firefox.policies in BUX3B2A/BUX3B2B.
# BUX5C0 adds PasswordManagerEnabled = false only while KeePassXC is the configured
# password authority, and locks full-screen toolbar autohide (macOS default is false).
# See docs/architecture/browser-operator-preferences.md.
{ keepassxcEnabled
, optOut
, appleProtonEnabled ? false
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
  AutofillAddressEnabled = false;
  AutofillCreditCardEnabled = false;
  Cookies = {
    Behavior = "reject-tracker-and-partition-foreign";
    BehaviorPrivateBrowsing = "reject-tracker-and-partition-foreign";
    Locked = false;
  };
  DisableFirefoxStudies = true;
  DisableTelemetry = true;
  DNSOverHTTPS = {
    Enabled = false;
    Locked = false;
  };
  EnableTrackingProtection = {
    Category = "strict";
    Cryptomining = true;
    EmailTracking = true;
    Fingerprinting = true;
    Locked = false;
    SuspectedFingerprinting = true;
    Value = true;
  };
  ExtensionSettings = extensionPolicy.renderFirefoxExtensionSettings {
    inherit keepassxcEnabled optOut appleProtonEnabled credentialProvider protonVpnEnabled;
  };
  HttpsOnlyMode = "enabled";
  OfferToSaveLoginsDefault = false;
  Preferences = {
    "browser.fullscreen.autohide" = {
      Value = true;
      Status = "locked";
    };
  } // (if credentialProvider == "apple" then {
    "signon.autofillForms" = { Value = false; Status = "locked"; };
    "signon.rememberSignons" = { Value = false; Status = "locked"; };
  } else { });
}
