# Closed-schema evaluations against the caller's actual old/new Browser UX trees.
{ lib, oldBrowser, newBrowser, selector, originalSelector, sharedConfiguration ? null,
  oldCore ? null, newCore ? null, selectedOldCore ? oldCore, legacyConfiguration ? null,
  failureProbe ? null }:
let
  oldModule = oldBrowser + "/modules/default.nix";
  newModule = newBrowser + "/modules/default.nix";
  select = import selector { inherit lib; };
  original = import originalSelector { inherit lib; };
  target = "example-current-mac";
  predecessor = "example-previous-mac";
  legacy = { browser-ux.configuration = if legacyConfiguration != null then legacyConfiguration else {
    schema = 1;
    keepassxc.enable = true;
    extensions.default-on-opt-out = [ ];
  }; };
  shared = if sharedConfiguration == null then {
    browser-ux.configuration = (builtins.fromTOML
      (builtins.readFile (newBrowser + "/delivery/composition/browser-ux.toml"))).browser-ux;
  } else { browser-ux.configuration = sharedConfiguration; };
  # Only the core's contribution seam is declared here. Browser UX's closed
  # configuration schema comes exclusively from the selected real module.
  seam = { lib, ... }: {
    imports = [ (newBrowser + "/tests/seam-fixture.nix") ];
    options.networking.hostName = lib.mkOption { type = lib.types.str; };
    options.programs.browserBaseline.chrome.nativeMessagingHosts = lib.mkOption { default = { }; };
    options.programs.browserBaseline.firefox.nativeMessagingHosts = lib.mkOption { default = { }; };
    options.programs.browserBaseline.replacementPolicyOwnership = lib.mkOption {
      type = lib.types.bool; default = false;
    };
    options.programs.browserBaseline.vivaldi = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything; default = { };
    };
    options.programs.browserBaseline.floorp = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything; default = { };
    };
  };
  evaluate = module: host: projection: (lib.evalModules {
    modules = [ seam module projection { networking.hostName = host; } ];
  }).config;
  run = module: host: projection: evaluate module host (select.moduleForHost host projection);
  accepts = module: host: projection:
    (builtins.tryEval (builtins.deepSeq (run module host projection).browser-ux.configuration true)).success;
  oldPlain = evaluate oldModule predecessor legacy;
  oldSelected = run oldModule predecessor legacy;
  sharedLegacy = { browser-ux.configuration = {
    schema = shared.browser-ux.configuration.schema or 1;
    keepassxc.enable = shared.browser-ux.configuration.keepassxc.enable or true;
    extensions.default-on-opt-out = shared.browser-ux.configuration.extensions.default-on-opt-out or [ ];
  }; };
  newPlain = evaluate newModule predecessor sharedLegacy;
  current = run newModule target shared;
  nonTarget = run newModule predecessor shared;
  off = value:
    !value.browser-ux.configuration.replacements.vivaldi.enable
    && !value.browser-ux.configuration.replacements.vivaldi.mail.enable
    && !value.browser-ux.configuration.replacements.vivaldi.mail.preserve-resolved
    && !value.browser-ux.configuration.replacements.floorp.enable
    && !value.browser-ux.configuration.extensions.apple-proton-trial.enable
    && value.browser-ux.replacementApplicationClaims == [ ]
    && value.programs.browserBaseline.vivaldi == { }
    && value.programs.browserBaseline.floorp == { };
  # Committed trees live at different fixture paths; compare manifest bytes,
  # not temporary extraction directory names.
  normalize = value:
    if builtins.isPath value then builtins.hashString "sha256" (builtins.readFile value)
    else if builtins.isAttrs value then builtins.mapAttrs (_: normalize) value
    else if builtins.isList value then map normalize value
    else value;
  chrome = value: normalize value.programs.browserBaseline.chrome;
  firefox = value: normalize (builtins.removeAttrs value.programs.browserBaseline.firefox [ "policiesJsonPayload" ]);
  catalog = (import (newBrowser + "/config/browser/apple-proton.nix")).catalog.extensions;
  chromeIds = map (row: row.chrome.id) (builtins.attrValues catalog);
  geckoIds = map (row: row.gecko.id) (builtins.attrValues catalog);
  additions = value: ids: builtins.all
    (id: value.ExtensionSettings.${id}.installation_mode == "normal_installed") ids;
  absent = value: ids: builtins.all (id: !(value.ExtensionSettings ? ${id})) ids;
  without = projection: select.moduleForHost predecessor projection;
  optoutId = "chrome:hlkenndednhfkekhgcdicdfddnkalmdm";
  optouts = { browser-ux.configuration = {
    keepassxc.enable = false;
    extensions.default-on-opt-out = [ optoutId ];
  }; };
  opted = run newModule predecessor optouts;
  oldOpted = run oldModule predecessor optouts;
  newOptedPlain = evaluate newModule predecessor optouts;
  oldOptedPlain = evaluate oldModule predecessor optouts;
  # Use the real core option declarations for the coupled transition. Physical
  # writers and package realization belong to the separate composed-host check.
  withCore = coreSource: browserModule: host: projection:
    let
      coreOptions = args: {
        options.programs.browserBaseline = ((import (coreSource + "/modules/browsers.nix"))
          (args // { pkgs = { }; })).options.programs.browserBaseline;
      };
      evaluated = (lib.evalModules {
        modules = [ coreOptions browserModule
          ({ lib, ... }: { options.networking.hostName = lib.mkOption { type = lib.types.str; }; })
          (select.moduleForHost host projection) { networking.hostName = host; } ];
      }).config;
    in builtins.deepSeq evaluated.browser-ux.configuration true;
  failureProbes = {
    coreFirstPrivateCurrentRejects = withCore newCore oldModule target shared;
    browserFirstPublicCurrentRejects = withCore oldCore newModule target legacy;
    browserFirstPrivateCurrentRejects = withCore selectedOldCore newModule target shared;
  };
in if failureProbe != null then failureProbes.${failureProbe} else {
  originalOldFailure = !(builtins.tryEval (builtins.deepSeq
    (evaluate oldModule predecessor (original.moduleForHost predecessor legacy)).browser-ux.configuration true)).success;
  actualOldModuleAccepts = builtins.deepSeq oldSelected.browser-ux.configuration true;
  oldSettingsPreserved = oldSelected.browser-ux.configuration == oldPlain.browser-ux.configuration;
  oldPoliciesAndExtensionsPreserved = chrome oldSelected == chrome oldPlain && firefox oldSelected == firefox oldPlain;
  oldApplicationClaimsPreserved =
    let attached = map (claim: { owner = "browser-ux"; inherit claim; })
      (import (oldBrowser + "/lib/application-claims.nix")).applicationClaims;
    in builtins.filter (select.claimAppliesToHost predecessor) attached == attached
      && select.casksForHost predecessor legacy == [ ];
  nonTargetNewDefaultsOff = off nonTarget;
  nonTargetKeepsSelectedModuleBaseline = chrome nonTarget == chrome newPlain && firefox nonTarget == firefox newPlain;
  nonTargetAllThreeAdditionsAbsent = absent (chrome nonTarget).managedPreferences chromeIds
    && absent (firefox nonTarget).policies geckoIds;
  targetProjectionUnchanged = select.moduleForHost target shared == shared;
  targetReplacementsAndMailPreserved = current.browser-ux.configuration.replacements.vivaldi.enable
    && current.browser-ux.configuration.replacements.floorp.enable
    && current.browser-ux.configuration.replacements.vivaldi.mail.enable
    && current.browser-ux.configuration.replacements.vivaldi.mail.preserve-resolved
    && current.browser-ux.replacementRendering.vivaldi.featureOverlays.mail.status == "OPERATOR_REPORTED_RESOLVED";
  targetAllThreeAdditionsPresent = builtins.length chromeIds == 3 && builtins.length geckoIds == 3
    && additions (chrome current).managedPreferences chromeIds
    && additions (firefox current).policies geckoIds
    && additions current.programs.browserBaseline.vivaldi.managedPreferences chromeIds
    && additions current.programs.browserBaseline.floorp.policies geckoIds;
  targetKeePassXCAndBlockersPreserved = current.browser-ux.configuration.keepassxc.enable
    && (chrome current).managedPreferences.PasswordManagerEnabled == false
    && (firefox current).policies.PasswordManagerEnabled == false
    && current.programs.browserBaseline.vivaldi.managedPreferences.ExtensionSettings.ddkjiahejlhfcafbddmgiahcphecmpfh.installation_mode == "force_installed"
    && current.programs.browserBaseline.floorp.policies.ExtensionSettings."uBlock0@raymondhill.net".installation_mode == "force_installed";
  missingOwnerRemainsMissing = without { unrelated = true; } == { unrelated = true; };
  missingConfigurationRemainsMissing = without { browser-ux = { }; } == { browser-ux = { }; };
  missingOwnerUsesNewDisabledDefaults = off (run newModule predecessor { });
  emptyOwnerOldAndNew = accepts oldModule predecessor { browser-ux = { }; }
    && off (run newModule predecessor { browser-ux = { }; });
  emptyConfigurationOldAndNew = accepts oldModule predecessor { browser-ux.configuration = { }; }
    && off (run newModule predecessor { browser-ux.configuration = { }; });
  emptyExtensionsPreserved = without { browser-ux.configuration.extensions = { }; }
    == { browser-ux.configuration.extensions = { }; };
  extensionsOnlyOldAndNew =
    let extensionsOnly = { browser-ux.configuration.extensions.default-on-opt-out = [ optoutId ]; };
    in accepts oldModule predecessor extensionsOnly && accepts newModule predecessor extensionsOnly
      && (run newModule predecessor extensionsOnly).browser-ux.configuration.extensions.default-on-opt-out == [ optoutId ];
  oneReplacementOldAndNew = builtins.all (projection:
    accepts oldModule predecessor projection && off (run newModule predecessor projection)) [
      { browser-ux.configuration.replacements.vivaldi.enable = true; }
      { browser-ux.configuration.replacements.floorp.enable = true; }
    ];
  targetSingleReplacementDefaultsOtherOff =
    let onlyFloorp = run newModule target { browser-ux.configuration.replacements.floorp.enable = true; };
    in onlyFloorp.browser-ux.configuration.replacements.floorp.enable
      && !onlyFloorp.browser-ux.configuration.replacements.vivaldi.enable
      && !onlyFloorp.browser-ux.configuration.extensions.apple-proton-trial.enable;
  optoutsPreserved = opted.browser-ux.configuration.extensions.default-on-opt-out == [ optoutId ]
    && !opted.browser-ux.configuration.keepassxc.enable
    && chrome opted == chrome newOptedPlain && firefox opted == firefox newOptedPlain
    && chrome oldOpted == chrome oldOptedPlain && firefox oldOpted == firefox oldOptedPlain
    && (chrome opted).managedPreferences.ExtensionSettings.hlkenndednhfkekhgcdicdfddnkalmdm.installation_mode == "allowed";
  targetOldRejectsNewRequestedSettings = !accepts oldModule target shared;
  unrelatedOptionStillRejectedOldAndNew = !accepts oldModule predecessor { browser-ux.configuration.unrelated-invalid = true; }
    && !accepts newModule predecessor { browser-ux.configuration.unrelated-invalid = true; };
  globalUnrelatedOptionStillRejected = !accepts oldModule predecessor { unrelated-invalid.enable = true; }
    && !accepts newModule predecessor { unrelated-invalid.enable = true; };
  invalidLegacyValueStillRejected = !accepts oldModule predecessor { browser-ux.configuration.keepassxc.enable = "invalid"; }
    && !accepts newModule predecessor { browser-ux.configuration.keepassxc.enable = "invalid"; };
  invalidExtensionStillRejected = !accepts oldModule predecessor { browser-ux.configuration.extensions.unrelated-invalid = true; }
    && !accepts newModule predecessor { browser-ux.configuration.extensions.unrelated-invalid = true; };
  casksAndHostClaimsRemainScoped = select.casksForHost target shared == [ "vivaldi" "floorp" ]
    && select.casksForHost predecessor shared == [ ]
    && !select.claimAppliesToHost predecessor { owner = "browser-ux"; claim.id = "bundle:com.vivaldi.Vivaldi"; }
    && select.claimAppliesToHost target { owner = "browser-ux"; claim.id = "bundle:app.floorp.Floorp"; }
    && select.claimAppliesToHost predecessor { owner = "other"; claim.id = "bundle:com.vivaldi.Vivaldi"; };
} // lib.optionalAttrs (oldCore != null && newCore != null) {
  actualOldPairPredecessorAccepts = withCore oldCore oldModule predecessor legacy;
  coreFirstPublicPortableBothHostsAccept = withCore newCore oldModule predecessor legacy
    && withCore newCore oldModule target legacy;
  matchedNewPairPrivateCurrentAccepts = withCore newCore newModule target shared;
  matchedNewPairPredecessorAccepts = withCore newCore newModule predecessor shared;
}
