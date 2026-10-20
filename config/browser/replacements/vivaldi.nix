# Vivaldi replacement browser metadata and capability contract.
let
  extensionPolicy = import ../extension-policy.nix;
in
{
  browser = "vivaldi";
  family = "chromium";
  source = "chrome";
  inheritFrom = "chrome";

  coreCapability = "vivaldi-browser-core";
  featureOverlays.mail = {
    capability = "vivaldi-mail";
    role = "optional-vivaldi-overlay";
    requiredForReplacement = false;
    chromeCounterpart = false;
    chromeParityFeature = false;
    safePosture = "DISABLED";
    preservedPosture = "PRESERVE_CURRENT_HOST_ENABLED_SEPARATE_SYNTHETIC_LAB";
    delivery = "NOT_DELIVERED_BY_BROWSER_UX";
    qualificationSuite = "vivaldi-mail";
  };

  # Expected signed application identity
  identity = {
    bundleId = "com.vivaldi.Vivaldi";
    teamId = "4XF3XNRN6Y";
    qualification = "UNKNOWN";
    observed = (builtins.fromJSON (builtins.readFile ./static-evidence.json)).browsers.vivaldi.identityProbe;
    status = "UNKNOWN";
  };

  # Observed versions (informational evidence, not restrictive version pins)
  versionObservations = [
    "8.2.4133.83"
    "8.2.4133.84"
  ];

  # Profile directory contract (isolated from Google/Chrome, no data copying)
  profile = {
    path = "$HOME/Library/Application Support/Vivaldi";
    symbolic = "$HOME/Library/Application Support/Vivaldi";
    isolatedFrom = "Google/Chrome";
    dataCopying = false;
  };

  # Policy delivery transport specification
  policyDelivery = {
    status = "PREPARED_CORE_OWNED_TRIAL";
    candidate = "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist";
    candidates = [
      "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"
    ];
    qualified = false;
  };

  # Closed per-key policy capability set exactly equals union of baseline keys keepass=true/false
  policyCapabilities = {
    AudioCaptureAllowedUrls = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    BlockThirdPartyCookies = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DefaultAutomaticDownloadsSetting = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DefaultGeolocationSetting = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DefaultMediaStreamSetting = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DefaultNotificationsSetting = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    DnsOverHttpsMode = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    ExtensionInstallForcelist = {
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
    PasswordManagerEnabled = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
    VideoCaptureAllowedUrls = {
      capability = "UNVERIFIED";
      status = "UNVERIFIED";
      runtimeQualified = false;
    };
  };

  # Derived semantic extension capabilities from extension-policy.nix
  extensionCapabilities =
    let
      exts = extensionPolicy.chromeExtensions;
      mkCap = class: id: meta: {
        id = id;
        inherit (meta) name;
        inherit class;
        installSource = exts.updateUrl;
        capability = "UNVERIFIED";
        status = "UNVERIFIED";
        runtimeQualified = false;
        cwsSupport = "VENDOR_DOCUMENTED";
        provenance = "https://help.vivaldi.com/desktop/appearance-customization/extensions/";
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
    candidate = "$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json";
    targetScope = "per-user";
    provenance = "https://github.com/keepassxreboot/keepassxc-browser/wiki/Troubleshooting-guide";
    manifestReferTo = "config/browser/keepassxc-chrome-native-messaging.json";
    target = "UNVERIFIED";
    status = "UNVERIFIED";
    profileSharing = false;
    systemTarget = "NOT_REQUESTED_SUPPORTED_PER_USER_ROUTE";
    delivery = "PRESERVE_KEEPASSXC_OWNED_ATTENDED_SETUP";
    qualified = false;
    gaps = [
      "KeePassXC installer owns per-user registration; preserve it or enable Vivaldi through supported attended settings if absent; effective handshake pending"
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
