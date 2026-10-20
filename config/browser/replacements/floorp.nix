# Floorp replacement browser metadata and capability contract.
let
  extensionPolicy = import ../extension-policy.nix;
in
{
  browser = "floorp";
  family = "gecko";
  source = "firefox";
  inheritFrom = "firefox";

  coreCapability = "floorp-browser-core";
  featureOverlays = { };

  # Expected signed application identity
  identity = {
    bundleId = "app.floorp.Floorp";
    teamId = "DV2U35YBHT";
    qualification = "UNKNOWN";
    observed = (builtins.fromJSON (builtins.readFile ./static-evidence.json)).browsers.floorp.identityProbe;
    status = "UNKNOWN";
  };

  # Observed versions (informational evidence, not restrictive version pins)
  versionObservations = [
    "12.19.0@157.0"
  ];

  # Profile directory contract (isolated from Firefox, no data copying)
  profile = {
    path = "$HOME/Library/Application Support/Floorp";
    symbolic = "$HOME/Library/Application Support/Floorp";
    isolatedFrom = "Firefox";
    dataCopying = false;
  };

  # Policy delivery transport specification
  policyDelivery = {
    status = "PREPARED_CORE_OWNED_TRIAL";
    domain = "app.floorp.Floorp";
    candidate = "app.floorp.Floorp";
    candidates = [
      "app.floorp.Floorp"
      "org.mozilla.firefox"
    ];
    qualified = false;
  };

  # Closed per-key policy capability set exactly equals union of baseline keys keepass=true/false
  policyCapabilities = {
    AutofillAddressEnabled = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    AutofillCreditCardEnabled = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    Cookies = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DNSOverHTTPS = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DisableFirefoxStudies = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DisableTelemetry = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    EnableTrackingProtection = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    ExtensionSettings = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    HttpsOnlyMode = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    OfferToSaveLoginsDefault = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    PasswordManagerEnabled = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    Preferences = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
  };

  # Derived semantic extension capabilities from extension-policy.nix
  extensionCapabilities =
    let
      exts = extensionPolicy.firefoxExtensions;
      mkCap = class: id: meta: {
        id = id;
        inherit (meta) name;
        inherit class;
        installSource = meta.install_url;
        capability = "UNVERIFIED";
        status = "UNVERIFIED";
        runtimeQualified = false;
      };
      req = builtins.mapAttrs (mkCap "required") exts.required;
      def = builtins.mapAttrs (mkCap "defaultOn") exts.defaultOn;
      kpx = {
        ${exts.keepassxc.id} = mkCap "keepassxc" exts.keepassxc.id exts.keepassxc;
      };
    in
    req // def // kpx;

  # Native messaging template
  nativeMessaging = {
    candidate = "/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json";
    path = "/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json";
    sharedWith = "firefox";
    target = "UNVERIFIED";
    status = "UNVERIFIED";
    dependsOn = "firefox native host active";
    newWriter = false;
    staticEvidence = "Floorp NativeManifests.sys.mjs rewrites Floorp native-manifest roots to Mozilla";
    manifestReferTo = "config/browser/keepassxc-firefox-native-messaging.json";
    browserSpecificPathSupported = false;
    sharedReaderSupported = true;
    qualified = false;
    gaps = [
      "depends on firefox native host active"
    ];
  };

  # Custom extension state
  customExtension = {
    status = "INHERITED_UNREGISTERED_DISTRIBUTION_BLOCKED";
    scrollbarInPolicyConfig = false;
    qualified = false;
    sourceDirectory = "extensions/browser-ux-scrollbars";
  };

  # Clear New Tab state
  cnt = {
    status = "HELD";
    authorityExpansion = false;
    qualified = false;
  };
}
