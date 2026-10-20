# Full default-module coverage for the inactive R3 option seam. Active R3 is
# qualified only in a disposable source projection with the matched core.
{ lib, pkgs, nix-darwin, defaultModule }:
let
  probe = extraModules: nix-darwin.lib.darwinSystem {
    inherit pkgs;
    modules = [
      ./seam-fixture.nix
      defaultModule
      {
        nixpkgs.pkgs = pkgs;
        system.primaryUser = "browser-probe";
        system.stateVersion = 6;
        users.users.browser-probe.home = "/Users/browser-probe";
      }
    ] ++ extraModules;
  };
  # The matched core's optional selectors and replacement policy dictionaries.
  # No physical policy writer is included in standalone evaluation.
  ownershipSeam = { lib, ... }: {
    options.programs.browserBaseline = {
      rolesR3 = lib.mkOption { type = lib.types.bool; default = false; };
      replacementPolicyOwnership = lib.mkOption { type = lib.types.bool; default = false; };
      vivaldi = {
        managedPreferences = lib.mkOption { type = lib.types.attrsOf lib.types.anything; };
        externalExtensions = lib.mkOption {
          type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        };
        nativeMessagingHosts = lib.mkOption {
          type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        };
      };
      floorp.policies = lib.mkOption { type = lib.types.attrsOf lib.types.anything; };
    };
  };
  standalone = probe [ ];
  nonTarget = probe [ { networking.hostName = "browser-probe-other"; } ];
  namedHost = hostName: probe [ ownershipSeam {
    networking.hostName = hostName;
    programs.browserBaseline.rolesR3 = false;
    "browser-ux".configuration.replacements = {
      vivaldi.enable = true;
      floorp.enable = true;
    };
  } ];
  predecessor = namedHost "example-previous-mac";
  target = namedHost "example-current-mac";
  explicitFalse = probe [ ownershipSeam {
    networking.hostName = "browser-probe-other";
    programs.browserBaseline = { rolesR3 = false; replacementPolicyOwnership = false; };
  } ];
  targetDisabled = probe [ ownershipSeam {
    networking.hostName = "example-current-mac";
    programs.browserBaseline.rolesR3 = false;
  } ];
  inactive = sys:
    !sys.config."browser-ux".rolesR3.enable
    && !sys.config.programs.browserBaseline.vivaldiPolicyOwnership
    && sys.config.programs.browserBaseline.chrome.enable
    && sys.config.programs.browserBaseline.firefox.enable;
  baselinePolicies = sys: {
    chrome = sys.config.programs.browserBaseline.chrome;
    firefox = builtins.removeAttrs sys.config.programs.browserBaseline.firefox [ "policiesJsonPayload" ];
  };
  check = name: predicate:
    assert predicate;
    pkgs.runCommandLocal name { } ''touch "$out"'';
in {
  r3r4-schema-standalone = check "r3r4-schema-standalone" (
    inactive standalone && inactive nonTarget
    # The missing legacy ownership path must stay unforced with R3 inactive.
    && !(standalone.options.programs.browserBaseline ? replacementPolicyOwnership)
    && !(nonTarget.options.programs.browserBaseline ? replacementPolicyOwnership)
    && baselinePolicies standalone == baselinePolicies nonTarget
  );
  r3r4-schema-inactive-hosts = check "r3r4-schema-inactive-hosts" (
    inactive predecessor && inactive target && inactive explicitFalse && inactive targetDisabled
    && !predecessor.config.programs.browserBaseline.replacementPolicyOwnership
    && !explicitFalse.config.programs.browserBaseline.replacementPolicyOwnership
    && target.config.programs.browserBaseline.replacementPolicyOwnership
    && targetDisabled.config.programs.browserBaseline.replacementPolicyOwnership
    && !targetDisabled.options.programs.browserBaseline.vivaldi.managedPreferences.isDefined
    && !targetDisabled.options.programs.browserBaseline.floorp.policies.isDefined
    && !predecessor.options.programs.browserBaseline.vivaldi.managedPreferences.isDefined
    && !predecessor.options.programs.browserBaseline.floorp.policies.isDefined
    && target.config.programs.browserBaseline.vivaldi.managedPreferences
      == target.config."browser-ux".replacementRendering.vivaldi.deliverable
    && target.config.programs.browserBaseline.floorp.policies
      == target.config."browser-ux".replacementRendering.floorp.deliverable
    && baselinePolicies predecessor == baselinePolicies standalone
    && baselinePolicies target == baselinePolicies standalone
  );
}
