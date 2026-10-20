# Safari platform browser contract, Wipr component states, and attended adapters.
# Honestly captures Safari's five Wipr components, attended enablement requirements,
# and platform-level absence of unattended Web Extension / Content Blocker policy delivery.

{
  browser = "safari";
  name = "Safari";
  bundleId = "com.apple.Safari";
  appPath = "/Applications/Safari.app";
  provider = "apple-system";

  lifecycle = {
    state = "active";
    delivery = "system-managed";
    retired = false;
  };

  # Content blocker specification and five Wipr component states
  contentBlocking = {
    provider = "wipr";
    product = "Wipr 2";
    appBundleId = "site.kaylees.Wipr2";
    appPath = "/Applications/Wipr.app";
    componentCount = 5;
    components = {
      wiprBlocker1 = {
        name = "Blocklist 1";
        componentName = "WiprBlocker1";
        bundleId = "site.kaylees.Wipr2.WiprBlocker1";
        appex = "WiprBlocker1.appex";
        kind = "content-blocker";
        state = "ATTENDED_ENABLE_REQUIRED";
        desiredEnabled = true;
        installed = "READBACK_REQUIRED";
        enabled = "ATTENDED_PENDING";
        permissioned = "ATTENDED_PENDING";
        attendedAdapter = "safari-settings-extensions";
      };
      wiprBlocker2 = {
        name = "Blocklist 2";
        componentName = "WiprBlocker2";
        bundleId = "site.kaylees.Wipr2.WiprBlocker2";
        appex = "WiprBlocker2.appex";
        kind = "content-blocker";
        state = "ATTENDED_ENABLE_REQUIRED";
        desiredEnabled = true;
        installed = "READBACK_REQUIRED";
        enabled = "ATTENDED_PENDING";
        permissioned = "ATTENDED_PENDING";
        attendedAdapter = "safari-settings-extensions";
      };
      wiprBlocker3 = {
        name = "Blocklist 3";
        componentName = "WiprBlocker3";
        bundleId = "site.kaylees.Wipr2.WiprBlocker3";
        appex = "WiprBlocker3.appex";
        kind = "content-blocker";
        state = "ATTENDED_ENABLE_REQUIRED";
        desiredEnabled = true;
        installed = "READBACK_REQUIRED";
        enabled = "ATTENDED_PENDING";
        permissioned = "ATTENDED_PENDING";
        attendedAdapter = "safari-settings-extensions";
      };
      wiprBlocker4 = {
        name = "Blocklist 4";
        componentName = "WiprBlocker4";
        bundleId = "site.kaylees.Wipr2.WiprBlocker4";
        appex = "WiprBlocker4.appex";
        kind = "content-blocker";
        state = "ATTENDED_ENABLE_REQUIRED";
        desiredEnabled = true;
        installed = "READBACK_REQUIRED";
        enabled = "ATTENDED_PENDING";
        permissioned = "ATTENDED_PENDING";
        attendedAdapter = "safari-settings-extensions";
      };
      wiprBlockerExtra = {
        name = "Wipr Extra";
        componentName = "WiprBlockerExtra";
        bundleId = "site.kaylees.Wipr2.WiprBlockerExtra";
        appex = "WiprBlockerExtra.appex";
        kind = "web-extension";
        state = "ATTENDED_ENABLE_REQUIRED";
        desiredEnabled = true;
        installed = "READBACK_REQUIRED";
        enabled = "ATTENDED_PENDING";
        permissioned = "ATTENDED_PENDING";
        attendedAdapter = "safari-settings-extensions";
      };
    };
    supportedAttendedAdapters = [
      "safari-settings-extensions"
      "attended-ui-verification"
    ];
    unattendedPolicySupport = false;
    unattendedPolicyStatus = "UNSUPPORTED_BY_APPLE_PLATFORM";
  };

  credentials = {
    provider = "apple";
    mechanism = "native-keychain";
    passkeys = "native-supported";
    webAuthn = "native-supported";
    nativeSuppression = "not-applicable";
  };

  search = {
    mechanism = "attended-safari-settings";
    status = "PENDING_SUPPORTED_MECHANISM";
  };

  bookmarks = {
    folder = "Browser UX";
    location = "Favorites";
    adapter = "shallow-supported-api";
    profileParser = false;
    importedTreesUntouched = true;
  };
}
