# Integration against the actual externally owned core candidate snapshot.
{ lib, candidateRoot }:
let
  selection = import ../delivery/composition/browser-ux-host-selection.nix { inherit lib; };
  shared = { browser-ux.configuration = (builtins.fromTOML
    (builtins.readFile ../delivery/composition/browser-ux.toml)).browser-ux; };
  pkgs = {
    inherit lib;
    writeText = name: text: { inherit text; __toString = _: "/nix/store/fixture-${name}"; };
    writeShellScript = name: text: { inherit text; __toString = _: "/nix/store/fixture-${name}"; };
    google-chrome = "/nix/store/fixture-google-chrome";
  };
  stub = {
    options = {
      networking.hostName = lib.mkOption { type = lib.types.str; };
      system.primaryUser = lib.mkOption { type = lib.types.str; default = "browser-probe"; };
      users.users = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default.browser-probe.home = "/Users/browser-probe"; };
      assertions = lib.mkOption { type = lib.types.listOf lib.types.anything; default = []; };
      environment.systemPackages = lib.mkOption { type = lib.types.listOf lib.types.anything; default = []; };
      homebrew.casks = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; };
      system.build = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = {}; };
      system.activationScripts = lib.mkOption { type = lib.types.attrsOf (lib.types.submodule {
        options.text = lib.mkOption { type = lib.types.lines; default = ""; };
      }); default = {}; };
    };
  };
  evaluate = host: projection: (lib.evalModules {
    specialArgs = { inherit pkgs; };
    modules = [ (candidateRoot + "/modules/browsers.nix") ../modules/default.nix stub
      (selection.moduleForHost host projection)
      { networking.hostName = host; homebrew.casks = selection.casksForHost host projection; } ];
  }).config;
  current = evaluate "example-current-mac" shared;
  predecessor = evaluate "example-previous-mac" shared;
  oldPredecessor = evaluate "example-previous-mac" { browser-ux.configuration = { schema = 1; keepassxc.enable = true; }; };
  build = current.system.build.browserBaseline;
  targets = map (row: row.target) build.attendedTargets;
  payload = artifact: if builtins.isAttrs artifact then artifact.text else builtins.readFile artifact;
  sources = map (row: payload row.source) build.attendedTargets;
  chromium = builtins.fromJSON (builtins.readFile ../config/browser/apple-proton-extensions.json);
in
assert build.guardViolations == [];
assert lib.all (row: row.assertion) current.assertions;
assert builtins.length targets == 8;
assert builtins.length (lib.unique targets) == 8;
assert build.vivaldiNativeMessagingHosts == {};
assert current.programs.browserBaseline.replacementPolicyOwnership;
assert !predecessor.programs.browserBaseline.replacementPolicyOwnership;
assert !(lib.hasInfix "/Users/browser-probe/Library/Application Support/Vivaldi/NativeMessagingHosts" build.attendedApply.text);
assert builtins.length build.attendedTargetsByBrowser.chrome == 3;
assert builtins.length build.attendedTargetsByBrowser.firefox == 2;
assert builtins.length build.attendedTargetsByBrowser.vivaldi == 2;
assert builtins.length build.attendedTargetsByBrowser.floorp == 2;
assert lib.sort builtins.lessThan current.homebrew.casks == lib.sort builtins.lessThan (oldPredecessor.homebrew.casks ++ [ "vivaldi" "floorp" ]);
assert predecessor.homebrew.casks == oldPredecessor.homebrew.casks;
assert build.attendedOwner == "core/programs.browserBaseline";
assert build.floorpPreferences.EnterprisePoliciesEnabled;
assert build.firefoxPreferences.EnterprisePoliciesEnabled;
assert build.chromeManagedPlist.text == build.vivaldiManagedPlist.text;
assert build.firefoxManagedPlist.text == lib.replaceStrings [ "org.mozilla.firefox" ] [ "app.floorp.Floorp" ] build.floorpManagedPlist.text;
assert builtins.all (source: !(lib.hasInfix "MailEnabled" source)) sources;
assert lib.hasInfix "org.keepassxc.keepassxc_browser" (builtins.concatStringsSep "\n" sources);
assert !(lib.hasInfix "network.trr.mode" (builtins.concatStringsSep "\n" sources));
assert !(lib.hasInfix "/Applications/" build.attendedApply.text);
assert !(lib.hasInfix "killall" build.attendedApply.text);
assert !(lib.hasInfix "defaults delete" build.attendedApply.text);
assert !(lib.hasInfix "defaults delete \"/Library/Managed Preferences/com.google.Chrome\" PasswordManagerEnabled" current.system.activationScripts.postActivation.text);
assert predecessor.system.activationScripts == oldPredecessor.system.activationScripts;
assert predecessor.system.build.browserBaseline.attendedApply.text == oldPredecessor.system.build.browserBaseline.attendedApply.text;
{
  status = "MATCHED_SOURCE_FIXTURES_PASS";
  targetCount = builtins.length targets;
  targets = map (row: if row.perUser or false then "$PRIMARY_HOME/Library/Application Support/Vivaldi/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json" else row.target) build.attendedTargets;
  payloadHashes = map (row: builtins.hashString "sha256" (payload row.source)) build.attendedTargets;
  writerHash = builtins.hashString "sha256" build.attendedApply.text;
  browserPolicies = {
    chrome = current.programs.browserBaseline.chrome.managedPreferences;
    firefox = current.programs.browserBaseline.firefox.policies;
    vivaldi = current.programs.browserBaseline.vivaldi.managedPreferences;
    floorp = current.programs.browserBaseline.floorp.policies;
  };
  runtimeParity = "UNVERIFIED";
}
