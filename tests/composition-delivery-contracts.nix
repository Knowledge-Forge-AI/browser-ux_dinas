# Evaluate the actual composition-owned selector against one shared local config.
{ lib, pkgs, oldBrowser ? null }:
let
  selection = import ../delivery/composition/browser-ux-host-selection.nix { inherit lib; };
  shared = { browser-ux.configuration = (builtins.fromTOML
    (builtins.readFile ../delivery/composition/browser-ux.toml)).browser-ux; };
  extraSeam = { lib, ... }: {
    options.networking.hostName = lib.mkOption { type = lib.types.str; };
    options.programs.browserBaseline.replacementPolicyOwnership = lib.mkOption { type = lib.types.bool; default = false; };
    options.programs.browserBaseline.vivaldi = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = {}; };
    options.programs.browserBaseline.floorp = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = {}; };
  };
  evaluate = host: projection: (lib.evalModules {
    modules = [ ./seam-fixture.nix extraSeam ../modules/default.nix
      (selection.moduleForHost host projection) { networking.hostName = host; } ];
  }).config;
  current = evaluate "example-current-mac" shared;
  predecessor = evaluate "example-previous-mac" shared;
  # Same-version rendering baseline. Actual old-schema coverage is separate below.
  baselinePredecessor = evaluate "example-previous-mac" { browser-ux.configuration = { schema = 1; keepassxc.enable = true; }; };
  cIds = map (row: row.chrome.id) (builtins.attrValues (import ../config/browser/apple-proton.nix).catalog.extensions);
  gIds = map (row: row.gecko.id) (builtins.attrValues (import ../config/browser/apple-proton.nix).catalog.extensions);
  stripChrome = value: value // { ExtensionSettings = builtins.removeAttrs value.ExtensionSettings cIds; };
  stripGecko = value: value // { ExtensionSettings = builtins.removeAttrs value.ExtensionSettings gIds; };
  chrome = current.programs.browserBaseline.chrome.managedPreferences;
  firefox = current.programs.browserBaseline.firefox.policies;
  oldChrome = baselinePredecessor.programs.browserBaseline.chrome.managedPreferences;
  oldFirefox = baselinePredecessor.programs.browserBaseline.firefox.policies;
  oldFirefoxSeam = builtins.removeAttrs baselinePredecessor.programs.browserBaseline.firefox [ "policiesJsonPayload" ];
  claims = import ../lib/application-claims.nix;
  attached = map (claim: { owner = "browser-ux"; inherit claim; })
    (claims.applicationClaimsFor shared.browser-ux.configuration.replacements);
  check = name: predicate: assert predicate; pkgs.runCommandLocal name {} ''touch "$out"'';
in {
  current-host-delivery = check "current-host-delivery" (
    current.browser-ux.configuration.replacements.vivaldi.mail.enable
    && current.browser-ux.replacementRendering.vivaldi.featureOverlays.mail.status == "OPERATOR_REPORTED_RESOLVED"
    && current.programs.browserBaseline.vivaldi.managedPreferences == chrome
    && current.programs.browserBaseline.floorp.policies == firefox
    && builtins.all (id: chrome.ExtensionSettings.${id}.installation_mode == "normal_installed") cIds
    && builtins.all (id: firefox.ExtensionSettings.${id}.installation_mode == "normal_installed") gIds
    && builtins.all (id: current.browser-ux.replacementRendering.vivaldi.extensionCapabilities.${id}.effectiveClass == "default-on") cIds
    && builtins.all (id: current.browser-ux.replacementRendering.floorp.extensionCapabilities.${id}.effectiveClass == "default-on") gIds
    && chrome.PasswordManagerEnabled == false && firefox.PasswordManagerEnabled == false
    && !(current.programs.browserBaseline.vivaldi ? nativeMessagingHosts)
    && current.programs.browserBaseline.replacementPolicyOwnership
    && current.browser-ux.replacementRendering.vivaldi.verdict == "HOLD"
    && current.browser-ux.replacementRendering.floorp.verdict == "HOLD"
  );
  predecessor-same-shared-config = check "predecessor-same-shared-config" (
    predecessor.programs.browserBaseline.chrome == baselinePredecessor.programs.browserBaseline.chrome
    && builtins.removeAttrs predecessor.programs.browserBaseline.firefox [ "policiesJsonPayload" ] == oldFirefoxSeam
    && predecessor.programs.browserBaseline.vivaldi == {}
    && predecessor.programs.browserBaseline.floorp == {}
    && predecessor.browser-ux.replacementApplicationClaims == []
    && !predecessor.browser-ux.configuration.replacements.vivaldi.mail.enable
    && !predecessor.browser-ux.configuration.extensions.apple-proton-trial.enable
    && !predecessor.programs.browserBaseline.replacementPolicyOwnership
  );
  exact-allowlisted-delta = check "exact-allowlisted-delta" (
    stripChrome chrome == oldChrome && stripGecko firefox == oldFirefox
    && current.programs.browserBaseline.chrome.nativeMessagingHosts == baselinePredecessor.programs.browserBaseline.chrome.nativeMessagingHosts
    && current.programs.browserBaseline.firefox.nativeMessagingHosts == baselinePredecessor.programs.browserBaseline.firefox.nativeMessagingHosts
    && current.programs.browserBaseline.chrome.externalExtensions == baselinePredecessor.programs.browserBaseline.chrome.externalExtensions
  );
  single-host-cask-claims = check "single-host-cask-claims" (
    selection.casksForHost "example-current-mac" shared == [ "vivaldi" "floorp" ]
    && selection.casksForHost "example-previous-mac" shared == []
    && # Under R3, core retains Brave YouTube writer/claim (inventory is empty);
    # predecessor receives 0 attached claims from browser-ux (1 in legacy R1).
    builtins.length (builtins.filter (selection.claimAppliesToHost "example-previous-mac") attached) == (if claims.applicationClaims == [] then 0 else 1)
    && builtins.filter (selection.claimAppliesToHost "example-current-mac") attached == attached
    && selection.claimAppliesToHost "example-previous-mac" { owner = "other"; claim.id = "bundle:com.vivaldi.Vivaldi"; }
  );
} // lib.optionalAttrs (oldBrowser != null) {
  actual-old-closed-schema = check "actual-old-closed-schema" (
    let
      legacy = { browser-ux.configuration = { schema = 1; keepassxc.enable = true; }; };
      evaluateOld = projection: (lib.evalModules {
        modules = [ ./seam-fixture.nix extraSeam (oldBrowser + "/modules/default.nix")
          projection { networking.hostName = "example-previous-mac"; } ];
      }).config;
      plain = evaluateOld legacy;
      projected = evaluateOld (selection.moduleForHost "example-previous-mac" legacy);
    in
    builtins.deepSeq projected.browser-ux.configuration (
      projected.browser-ux.configuration == plain.browser-ux.configuration
      && projected.programs.browserBaseline.chrome == plain.programs.browserBaseline.chrome
      && builtins.removeAttrs projected.programs.browserBaseline.firefox [ "policiesJsonPayload" ]
        == builtins.removeAttrs plain.programs.browserBaseline.firefox [ "policiesJsonPayload" ])
  );
}
