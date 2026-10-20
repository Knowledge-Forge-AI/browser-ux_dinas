# Semantic inputs only. Core renders one combined attended delivery plan.
let
  roles = import ./roles-r3.nix;
  rows = role: entries: builtins.map (id: {
    inherit role id;
    owner = "browser-ux";
    purpose = if id == "vpn@proton.ch" then "security"
      else if id == "uBlock0@raymondhill.net" then "blocker" else "convenience";
    name = entries.${id}.name;
    method = if id == "vpn@proton.ch" then "ATTENDED_OFFICIAL_STORE" else "PRESERVED_CONVENIENCE_INTENT";
    automaticInstallation = false;
    automaticSignIn = false;
    autoConnect = false;
    policy = {};
  } // (if id == "vpn@proton.ch" then {
    procedure = ../../delivery/proton-vpn-floorp.md;
    storeUrl = "https://addons.mozilla.org/en-US/firefox/addon/proton-vpn-firefox-extension/";
    updateUrl = entries.${id}.install_url;
    status = "ATTENDED_INSTALLATION_HELD_PENDING_IDENTITY_RELEASE_AND_READBACK";
  } else {})) (builtins.attrNames entries);
in rows "brave-daily" roles.braveDaily.extensions
  ++ rows "librewolf" roles.librewolf.extensions
  ++ rows "orion" roles.orion.extensions
  ++ rows "floorp" roles.floorp.extensions
  ++ [{
    role = "floorp";
    id = roles.floorp.credentialExtension;
    owner = "browser-ux";
    purpose = "credentials";
    name = "Apple Passwords";
    method = "PRESERVED_COMPATIBILITY_HELD_INTENT";
    automaticInstallation = false; automaticSignIn = false; autoConnect = false;
    policy = {};
  }]
