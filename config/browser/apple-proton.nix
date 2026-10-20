# Apple and Proton trial extension catalog and policy bindings.
# Provides structured metadata, Gecko/CWS IDs, installation semantics,
# caveats, and attended gap descriptions for Proton Pass, Proton VPN, and iCloud Passwords.
# Covers Chrome, Firefox, Vivaldi, and Floorp targets on macOS.

let
  catalog = builtins.fromJSON (builtins.readFile ./apple-proton-extensions.json);
in
rec {
  inherit catalog;

  # Chrome Web Store extension entries
  chromeExtensions = {
    updateUrl = "https://clients2.google.com/service/update2/crx";
    extensions = builtins.listToAttrs (map (entry: {
      name = entry.chrome.id;
      value = { inherit (entry) name product publisher; cwsId = entry.chrome.id; };
    }) (builtins.attrValues catalog.extensions));
  };

  # Firefox AMO extension entries
  firefoxExtensions = {
    extensions = builtins.listToAttrs (map (entry: {
      name = entry.gecko.id;
      value = { inherit (entry) name product publisher; geckoId = entry.gecko.id;
        install_url = entry.gecko.installRoute; };
    }) (builtins.attrValues catalog.extensions));
  };

  # Trial extension maps exported alongside base maps
  trialChromeExtensions = chromeExtensions.extensions;
  trialFirefoxExtensions = firefoxExtensions.extensions;

  # Attended gaps and caveats
  caveats = {
    protonPass = catalog.extensions."proton-pass".caveats;
    protonVpn = catalog.extensions."proton-vpn".caveats;
    iCloudPasswords = catalog.extensions."icloud-passwords".caveats;
  };
}
