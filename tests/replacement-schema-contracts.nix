# Pure option-system contracts; runnable without builds or a Nix daemon.
{ lib }:
let
  evaluateSystem = override: lib.evalModules {
    modules = [ ./seam-fixture.nix ../modules/default.nix override ];
  };
  evaluate = override: (evaluateSystem override).config;
  # The seam intentionally declares this option without a value. Nixpkgs 25.11
  # retains its throwing thunk in config; compare defined values and absence.
  seamValues = cfg: cfg.programs.browserBaseline // {
    firefox = builtins.removeAttrs cfg.programs.browserBaseline.firefox [ "policiesJsonPayload" ];
  };
  cfg = evaluate { };
  enabled = evaluate {
    "browser-ux".configuration.replacements = { vivaldi.enable = true; floorp.enable = true; };
  };
  combinations = [
    { vivaldi.enable = false; floorp.enable = false; }
    { vivaldi.enable = false; floorp.enable = true; }
    { vivaldi.enable = true; floorp.enable = false; }
    { vivaldi.enable = true; floorp.enable = true; }
  ];
  claims = import ../lib/application-claims.nix;
  matrixValid = lib.all (replacements:
    let
      evaluated = evaluateSystem { "browser-ux".configuration = { inherit replacements; }; };
      candidate = evaluated.config;
      rendered = candidate."browser-ux".replacementRendering;
      expectedNames = lib.filter (name: replacements.${name}.enable) [ "vivaldi" "floorp" ];
      selected = candidate."browser-ux".replacementApplicationClaims;
    in
    builtins.deepSeq rendered (
      lib.all (name: (rendered.${name} != null) == replacements.${name}.enable) [ "vivaldi" "floorp" ]
      && selected == claims.replacementApplicationClaims replacements
      && map (claim: claim.package) selected == expectedNames
      && claims.applicationClaimsFor replacements == claims.applicationClaims ++ selected
      && seamValues candidate == seamValues cfg
      && !(evaluated.options.programs.browserBaseline.firefox.policiesJsonPayload.isDefined)
      && builtins.attrNames candidate == [ "browser-ux" "programs" ]
      && (rendered.floorp == null || (rendered.floorp == enabled."browser-ux".replacementRendering.floorp
        && rendered.floorp.runtimeHolds == [ ] && rendered.floorp.activation.status == "HOLD_QUALIFICATION"))
      && (rendered.vivaldi == null || (rendered.vivaldi == enabled."browser-ux".replacementRendering.vivaldi
        && rendered.vivaldi.runtimeHolds == [ ]
        && rendered.vivaldi.featureOverlays.mail.status == "HOLD_RUNTIME_OOM"
        && !rendered.vivaldi.featureOverlays.mail.requested
        && !candidate."browser-ux".configuration.replacements.vivaldi.mail.enable
        && rendered.vivaldi.replacementCandidate.qualification == "READY_FOR_QUALIFICATION"
        && rendered.vivaldi.activation.status == "HOLD_QUALIFICATION"))
      && lib.all (name: rendered.${name} == null || (!rendered.${name}.nativeMessaging.qualified
        && !rendered.${name}.nativeMessaging.deliveredByBrowserUX)) [ "vivaldi" "floorp" ]
    )
  ) combinations;
  probe = replacements: builtins.tryEval (builtins.deepSeq (evaluate {
    "browser-ux".configuration = { inherit replacements; };
  })."browser-ux".configuration true);
  missingBridge = builtins.tryEval (builtins.deepSeq (evaluate {
    "browser-ux".configuration.replacements.floorp.enable = true;
    programs.browserBaseline.firefox.nativeMessagingHosts = lib.mkForce { };
  })."browser-ux".replacementRendering true);
in
assert cfg."browser-ux".configuration == (builtins.fromTOML (builtins.readFile ../config/default/browser-ux.toml)).browser-ux;
assert cfg."browser-ux".replacementRendering == { vivaldi = null; floorp = null; };
assert enabled."browser-ux".replacementRendering.vivaldi.inheritFrom == "chrome";
assert enabled."browser-ux".replacementRendering.floorp.inheritFrom == "firefox";
assert enabled."browser-ux".replacementRendering.vivaldi.verdict == "HOLD";
assert enabled."browser-ux".replacementRendering.floorp.verdict == "HOLD";
assert seamValues enabled == seamValues cfg;
assert !(evaluateSystem { }).options.programs.browserBaseline.firefox.policiesJsonPayload.isDefined;
assert !(evaluateSystem {
  "browser-ux".configuration.replacements = { vivaldi.enable = true; floorp.enable = true; };
}).options.programs.browserBaseline.firefox.policiesJsonPayload.isDefined;
assert cfg."browser-ux".replacementApplicationClaims == [ ];
assert matrixValid;
assert enabled."browser-ux".replacementApplicationClaims ==
  (import ../lib/application-claims.nix).replacementApplicationClaims {
    vivaldi.enable = true; floorp.enable = true;
  };
assert builtins.attrNames enabled == [ "browser-ux" "programs" ];
assert !(probe { unknown.enable = true; }).success;
assert !(probe { vivaldi.unknown = true; }).success;
assert !(probe { floorp.unknown = true; }).success;
assert !(probe { vivaldi.enable = "true"; }).success;
assert !(probe { floorp.enable = 1; }).success;
assert !(probe { vivaldi.inherit-from = "firefox"; }).success;
assert !(probe { floorp.inherit-from = "chrome"; }).success;
assert (probe { }).success;
assert !cfg."browser-ux".configuration.replacements.vivaldi.mail.enable;
assert (probe { vivaldi.enable = true; }).success;
assert !(probe { vivaldi.enable = true; vivaldi.mail.enable = true; }).success;
assert !(probe { vivaldi.mail.enable = true; }).success;
assert !(probe { floorp.enable = true; floorp.mail.enable = true; }).success;
assert !(probe { vivaldi.mail.enable = "true"; }).success;
assert !(probe { vivaldi.mail.unknown = true; }).success;
assert !missingBridge.success;
true
