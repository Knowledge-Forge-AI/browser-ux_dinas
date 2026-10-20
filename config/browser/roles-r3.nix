let
  catalog = import ./extension-policy.nix;
  chrome = catalog.chromeExtensions.defaultOn // {
    felphkbfjadmcejnibcmcncimlappdde = catalog.chromeExtensions.required.felphkbfjadmcejnibcmcncimlappdde;
  };
  gecko = catalog.firefoxExtensions.defaultOn // catalog.firefoxExtensions.required;
  held = entries: builtins.mapAttrs (_: item: item // {
    status = "ATTENDED_OR_UNSUPPORTED";
    automaticInstallation = false;
    effectiveReadbackRequired = true;
  }) entries;
in {
  schema = "browser-ux-role-ownership-r3-v1";
  enable = true;
  deployment = "HELD_SOURCE_RELEASE_REQUIRED";
  floorp = {
    package = "floorp";
    bundleId = "app.floorp.Floorp";
    searchDefault = "Brave Search";
    extensions = held (gecko // {
      # Core owns Proton VPN for core-installed browsers; Floorp alone is ours.
      "vpn@proton.ch" = catalog.firefoxExtensions.trial."vpn@proton.ch" // {
        extensionOwner = "browser-ux";
        installationIntent = "per-profile attended official AMO add";
        installationProcedure = ../../delivery/proton-vpn-floorp.md;
        sourceDelivery = "ATTENDED_INSTALLATION_PREPARED_NOT_INSTALLED";
        autoConnectDefault = false;
        autoConnectEnforcement = "NONE; attended UI readback required";
        automaticSignIn = false;
        dnsPolicy = "UNCHANGED; compatibility and DNS/DoH leak check pending";
      };
    });
    credentialExtension = "password-manager-firefox-extension@apple.com";
    credentialCompatibility = "PASSWORD_TOTP_PASSKEY_PROOF_REQUIRED_BEFORE_NATIVE_SUPPRESSION";
    deliveredPolicies = {};
  };
  librewolf = {
    extensions = held { "clear-new-tab@loftyshaky" = catalog.firefoxExtensions.required."clear-new-tab@loftyshaky"; };
    privacyAndCredentialsOwner = "core";
    deliveredPolicies = {};
  };
  braveDaily = {
    extensions = held chrome;
    delivery = "per-profile attended only; no global forced policy";
    widevine = { enabled = false; delivery = "attended opt-in only"; };
    privacyAndCredentialsOwner = "core";
  };
  orion = {
    extensions = held chrome;
    delivery = "each Chrome-family extension requires actual Orion API/functionality attestation";
    privacyBlockerAndCredentialsOwner = "core";
  };
  braveAutomation = { extensions = {}; credentialManagers = []; sync = false; };
  braveYoutube = { physicalWriter = "core retained"; ownershipCut = "HELD"; destinationWriterEnabled = false; };
  vivaldi = {
    state = "VIVALDI_VISUAL_REFERENCE_RETAINED_DECOMMISSION_HELD";
    primaryRole = false;
    package = "vivaldi";
    profileWriter = false;
    mailOAuthTroubleshooting = false;
    preserve = [ "app/executable" "settings/extensions" "Mail/Calendar/Feeds/OAuth"
      "unsent/local data" "credentials" "imported bookmarks/preferences" ];
    retirement = "EXPLICIT_OPERATOR_APPROVAL_REQUIRED";
    visualMigration = "DEFERRED_DISPOSABLE_FLOORP_PROFILE_FIRST";
  };
  retiredR1Cutover = "configuration retained for continuity; target runtime selects R3 rather than primaryCutover/replacements";
}
