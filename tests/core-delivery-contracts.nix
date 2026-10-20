# Focused pure lib.evalModules stub test for core seam extension (Vivaldi/Floorp).
# Exercises option definitions, default absence, guard violations, effective state resolution,
# plist/manifest generators, activation script paths, and byte-level parity with core baseline.

{
  lib,
  pkgs ? null,
  coreRoot,
  candidateRoot,
}:

let
  testPkgs = if pkgs != null then pkgs else {
    inherit lib;
    writeText = name: text: { inherit text; __toString = _: "/nix/store/stub-${name}"; };
    writeShellScript = name: text: "/nix/store/stub-${name}";
    google-chrome = "/nix/store/stub-google-chrome";
  };

  candidateModule = import (candidateRoot + "/modules/browsers.nix");

  originalModule = import (coreRoot + "/modules/browsers.nix");

  stubModule = {
    options.system.primaryUser = lib.mkOption { type = lib.types.str; default = "browser-probe"; };
    options.users.users = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default.browser-probe.home = "/Users/browser-probe"; };
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.environment.systemPackages = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.homebrew.casks = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.system.build = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.system.activationScripts = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.text = lib.mkOption {
          type = lib.types.lines;
          default = "";
        };
      });
      default = {};
    };
  };

  evalCandidate = extraModules: lib.evalModules {
    specialArgs = { pkgs = testPkgs; };
    modules = [ candidateModule stubModule ] ++ extraModules;
  };

  evalOriginal = extraModules: lib.evalModules {
    specialArgs = { pkgs = testPkgs; };
    modules = [ originalModule stubModule ] ++ extraModules;
  };

  payload = artifact: if builtins.isAttrs artifact then artifact.text else builtins.readFile artifact;

  # Helper to inspect violations
  violationsOf = evalResult: evalResult.config.system.build.browserBaseline.guardViolations;
  hasViolationType = evalResult: vType:
    builtins.any (v: v.type == vType) (violationsOf evalResult);

  # 1. Legacy defaults evaluation: compares original and candidate
  origLegacy = evalOriginal [];
  candLegacy = evalCandidate [];
  origLegacyBB = origLegacy.config.system.build.browserBaseline;
  candLegacyBB = candLegacy.config.system.build.browserBaseline;

  # 2. Unconfigured evaluation: new endpoints default absent, legacyPolicyDefaults disabled
  unconfigured = evalCandidate [
    { programs.browserBaseline.legacyPolicyDefaults.enable = false; }
  ];
  unconfBB = unconfigured.config.system.build.browserBaseline;
  unconfOpt = unconfigured.options.programs.browserBaseline;

  # 3. Vivaldi configured evaluation
  vivaldiConfigured = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences = {
        BlockThirdPartyCookies = true;
        DefaultGeolocationSetting = 2;
      };
      programs.browserBaseline.vivaldi.externalExtensions = {
        felphkbfjadmcejnibcmcncimlappdde = {
          external_update_url = "https://clients2.google.com/service/update2/crx";
        };
      };
      programs.browserBaseline.vivaldi.nativeMessagingHosts = {
        "org.keepassxc.keepassxc_browser" = {
          name = "org.keepassxc.keepassxc_browser";
        };
      };
    }
  ];
  vConfBB = vivaldiConfigured.config.system.build.browserBaseline;

  # 4. Floorp configured evaluation
  floorpConfigured = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.floorp.policies = {
        DisableTelemetry = true;
        AutofillAddressEnabled = false;
      };
    }
  ];
  fConfBB = floorpConfigured.config.system.build.browserBaseline;

  # 5. Both Vivaldi and Floorp configured simultaneously
  bothConfigured = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences = {
        BlockThirdPartyCookies = true;
      };
      programs.browserBaseline.vivaldi.externalExtensions = {
        felphkbfjadmcejnibcmcncimlappdde = {
          external_update_url = "https://clients2.google.com/service/update2/crx";
        };
      };
      programs.browserBaseline.vivaldi.nativeMessagingHosts = {
        "org.keepassxc.keepassxc_browser" = {
          name = "org.keepassxc.keepassxc_browser";
        };
      };
      programs.browserBaseline.floorp.policies = {
        DisableTelemetry = true;
      };
    }
  ];
  bothBB = bothConfigured.config.system.build.browserBaseline;
  bothScript = bothConfigured.config.system.activationScripts.postActivation.text;

  # 6. Negative tests: Priority overrides
  priorityVivaldiPref = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences = lib.mkForce {
        BlockThirdPartyCookies = true;
      };
    }
  ];
  priorityVivaldiExt = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.externalExtensions = lib.mkForce {
        felphkbfjadmcejnibcmcncimlappdde = { external_update_url = "https://clients2.google.com/service/update2/crx"; };
      };
    }
  ];
  priorityVivaldiNMH = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.nativeMessagingHosts = lib.mkForce {
        "org.keepassxc.keepassxc_browser" = { name = "org.keepassxc.keepassxc_browser"; };
      };
    }
  ];
  priorityFloorp = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.floorp.policies = lib.mkForce {
        DisableTelemetry = true;
      };
    }
  ];
  priorityNestedKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences.BlockThirdPartyCookies = lib.mkOverride 50 true;
    }
  ];

  # 7. Negative tests: Duplicate keys across modules
  duplicateVivaldiKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences.BlockThirdPartyCookies = true;
    }
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences.BlockThirdPartyCookies = false;
    }
  ];
  duplicateFloorpKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.floorp.policies.DisableTelemetry = true;
    }
    {
      programs.browserBaseline.floorp.policies.DisableTelemetry = false;
    }
  ];
  duplicateVivaldiExtKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.externalExtensions.felphkbfjadmcejnibcmcncimlappdde = {
        external_update_url = "https://clients2.google.com/service/update2/crx";
      };
    }
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.externalExtensions.felphkbfjadmcejnibcmcncimlappdde = {
        external_update_url = "https://clients2.google.com/service/update2/crx";
      };
    }
  ];
  duplicateVivaldiNMHKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.nativeMessagingHosts."org.keepassxc.keepassxc_browser" = {
        name = "org.keepassxc.keepassxc_browser";
      };
    }
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.nativeMessagingHosts."org.keepassxc.keepassxc_browser" = {
        name = "org.keepassxc.keepassxc_browser";
      };
    }
  ];

  # 8. Negative tests: Identifier validation
  invalidVivaldiExtId = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.externalExtensions = {
        "NOT_A_VALID_EXTENSION_ID" = {
          external_update_url = "https://clients2.google.com/service/update2/crx";
        };
      };
    }
  ];
  invalidVivaldiNMHName = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.nativeMessagingHosts = {
        "bad host name with spaces" = { name = "test"; };
      };
    }
  ];

  # 9. Negative tests: Legacy exclusivity
  legacyExclusivityVivaldi = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = true;
      programs.browserBaseline.vivaldi.managedPreferences = {
        BlockThirdPartyCookies = true;
      };
    }
  ];
  legacyExclusivityFloorp = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = true;
      programs.browserBaseline.floorp.policies = {
        DisableTelemetry = true;
      };
    }
  ];

  # 10. Negative tests: Floorp reserved key
  floorpReservedKey = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.floorp.policies = {
        EnterprisePoliciesEnabled = true;
      };
    }
  ];

  # 11. Negative tests: Null value checks for plist generators
  floorpNullValue = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.floorp.policies = {
        DisableTelemetry = null;
      };
    }
  ];
  vivaldiNullValue = evalCandidate [
    {
      programs.browserBaseline.legacyPolicyDefaults.enable = false;
      programs.browserBaseline.vivaldi.managedPreferences = {
        BlockThirdPartyCookies = null;
      };
    }
  ];
  ownedAbsent = evalCandidate [{
    programs.browserBaseline.legacyPolicyDefaults.enable = false;
    programs.browserBaseline.replacementPolicyOwnership = true;
  }];
in
{
  # 1. Legacy defaults parity: candidate behavior identical to original core module
  testLegacyDefaultsParityWithOriginal =
    assert candLegacyBB.guardViolations == origLegacyBB.guardViolations;
    assert candLegacyBB.firefoxPolicyDelivery == origLegacyBB.firefoxPolicyDelivery;
    assert builtins.attrNames candLegacyBB.chromeExternalExtensions == builtins.attrNames origLegacyBB.chromeExternalExtensions;
    assert builtins.attrNames candLegacyBB.chromeNativeMessagingHosts == builtins.attrNames origLegacyBB.chromeNativeMessagingHosts;
    assert builtins.attrNames candLegacyBB.firefoxNativeMessagingHosts == builtins.attrNames origLegacyBB.firefoxNativeMessagingHosts;
    assert (payload candLegacyBB.chromeExternalExtensions."felphkbfjadmcejnibcmcncimlappdde")
      == (payload origLegacyBB.chromeExternalExtensions."felphkbfjadmcejnibcmcncimlappdde");
    assert (payload candLegacyBB.chromeNativeMessagingHosts."org.keepassxc.keepassxc_browser")
      == (payload origLegacyBB.chromeNativeMessagingHosts."org.keepassxc.keepassxc_browser");
    assert (payload candLegacyBB.firefoxNativeMessagingHosts."org.keepassxc.keepassxc_browser")
      == (payload origLegacyBB.firefoxNativeMessagingHosts."org.keepassxc.keepassxc_browser");
    assert (payload candLegacyBB.firefoxPolicies) == (payload origLegacyBB.firefoxPolicies);
    assert lib.hasPrefix origLegacy.config.system.activationScripts.postActivation.text
      candLegacy.config.system.activationScripts.postActivation.text;
    assert lib.trim (lib.removePrefix origLegacy.config.system.activationScripts.postActivation.text
      candLegacy.config.system.activationScripts.postActivation.text) == "";
    assert candLegacyBB.vivaldiManagedPlist == null;
    assert candLegacyBB.vivaldiExternalExtensions == {};
    assert candLegacyBB.vivaldiNativeMessagingHosts == {};
    assert candLegacyBB.floorpManagedPlist == null;
    assert candLegacyBB.floorpPreferences == {};
    true;

  # 2. Unconfigured checks
  testUnconfiguredViolationsClean =
    assert unconfBB.guardViolations == [];
    true;

  testUnconfiguredEndpointsDefaultAbsent =
    assert !unconfOpt.vivaldi.managedPreferences.isDefined;
    assert !unconfOpt.vivaldi.externalExtensions.isDefined;
    assert !unconfOpt.vivaldi.nativeMessagingHosts.isDefined;
    assert !unconfOpt.floorp.policies.isDefined;
    true;

  testUnconfiguredBuildOutputsNullOrEmpty =
    assert unconfBB.vivaldiManagedPlist == null;
    assert unconfBB.vivaldiExternalExtensions == {};
    assert unconfBB.vivaldiNativeMessagingHosts == {};
    assert unconfBB.floorpManagedPlist == null;
    assert unconfBB.floorpPreferences == {};
    assert !unconfBB.effectiveState.hasVivaldiPreferences;
    assert !unconfBB.effectiveState.hasFloorpPolicies;
    assert !unconfBB.effectiveState.hasFloorpPlist;
    true;

  # 3. Vivaldi configured checks
  testVivaldiConfiguredBuildOutputs =
    assert vConfBB.guardViolations == [];
    assert vConfBB.vivaldiManagedPlist != null;
    assert vConfBB.vivaldiExternalExtensions ? "felphkbfjadmcejnibcmcncimlappdde";
    assert vConfBB.vivaldiNativeMessagingHosts ? "org.keepassxc.keepassxc_browser";
    assert vConfBB.effectiveState.hasVivaldiPreferences;
    assert vConfBB.effectiveState.vivaldiPreferenceCount == 2;
    assert vConfBB.effectiveState.vivaldiExternalExtensionIds == [ "felphkbfjadmcejnibcmcncimlappdde" ];
    assert vConfBB.effectiveState.vivaldiNativeMessagingHostNames == [ "org.keepassxc.keepassxc_browser" ];
    true;

  # 4. Floorp configured checks
  testFloorpConfiguredBuildOutputs =
    assert fConfBB.guardViolations == [];
    assert fConfBB.floorpManagedPlist != null;
    assert fConfBB.floorpPreferences.EnterprisePoliciesEnabled == true;
    assert fConfBB.floorpPreferences.DisableTelemetry == true;
    assert fConfBB.floorpPreferences.AutofillAddressEnabled == false;
    assert fConfBB.effectiveState.hasFloorpPolicies;
    assert fConfBB.effectiveState.hasFloorpPlist;
    assert fConfBB.effectiveState.floorpPolicyCount == 2;
    true;

  # 5. Both configured simultaneously
  testBothConfiguredSimultaneously =
    assert bothBB.guardViolations == [];
    assert bothBB.vivaldiManagedPlist != null;
    assert bothBB.floorpManagedPlist != null;
    assert bothBB.effectiveState.hasVivaldiPreferences;
    assert bothBB.effectiveState.hasFloorpPolicies;
    true;

  # 6. Activation script paths verification
  testActivationScriptPaths =
    assert lib.hasInfix "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist" bothScript;
    assert lib.hasInfix "/Library/Application Support/Vivaldi/External Extensions" bothScript;
    assert lib.hasInfix "/Users/browser-probe/Library/Application Support/Vivaldi/NativeMessagingHosts" bothScript;
    assert !(lib.hasInfix "/Library/Vivaldi/NativeMessagingHosts" bothScript);
    assert lib.hasInfix "/Library/Preferences/app.floorp.Floorp.plist" bothScript;
    # No signed bundle edits for Floorp:
    assert !(lib.hasInfix "/Applications/Floorp.app" bothScript);
    # No second native writer for Floorp (shares Mozilla path):
    assert !(lib.hasInfix "/Library/Floorp/NativeMessagingHosts" bothScript);
    # Seam does not own casks:
    assert !(lib.elem "vivaldi" bothConfigured.config.homebrew.casks);
    assert !(lib.elem "floorp" bothConfigured.config.homebrew.casks);
    true;

  # 7. Negative tests: Priority overrides
  testPriorityOverridesRejected =
    assert hasViolationType priorityVivaldiPref "priority-override";
    assert hasViolationType priorityVivaldiExt "priority-override";
    assert hasViolationType priorityVivaldiNMH "priority-override";
    assert hasViolationType priorityFloorp "priority-override";
    assert hasViolationType priorityNestedKey "priority-override";
    true;

  # 8. Negative tests: Duplicate keys
  testDuplicateKeysRejected =
    assert hasViolationType duplicateVivaldiKey "duplicate-key";
    assert hasViolationType duplicateFloorpKey "duplicate-key";
    assert hasViolationType duplicateVivaldiExtKey "duplicate-key";
    assert hasViolationType duplicateVivaldiNMHKey "duplicate-key";
    true;

  # 9. Negative tests: Identifier validation
  testInvalidIdentifiersRejected =
    assert hasViolationType invalidVivaldiExtId "invalid-identifier";
    assert hasViolationType invalidVivaldiNMHName "invalid-identifier";
    true;

  # 10. Negative tests: Legacy exclusivity
  testLegacyExclusivityViolations =
    assert hasViolationType legacyExclusivityVivaldi "legacy-exclusivity";
    assert hasViolationType legacyExclusivityFloorp "legacy-exclusivity";
    true;

  # 11. Negative tests: Floorp reserved key
  testFloorpReservedKeyRejected =
    assert hasViolationType floorpReservedKey "reserved-key";
    true;

  # 12. Negative tests: Null values rejected for plist generation
  testNullValuesRejected =
    assert hasViolationType floorpNullValue "unsupported-null-value";
    assert hasViolationType vivaldiNullValue "unsupported-null-value";
    true;

  testOwnedAbsentReplacementPoliciesRetracted =
    let script = ownedAbsent.config.system.activationScripts.postActivation.text;
    in
    assert lib.hasInfix ''rm -f "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"'' script;
    assert lib.hasInfix ''rm -f "/Library/Preferences/app.floorp.Floorp.plist"'' script;
    assert lib.hasInfix ''rm -f "$vivaldiExternalExtensionsDir/felphkbfjadmcejnibcmcncimlappdde.json"'' script;
    assert !(lib.hasInfix "/Users/browser-probe" script);
    true;

  summary = {
    contractStatus = "PASSED";
    testedEndpoints = [
      "programs.browserBaseline.vivaldi.managedPreferences"
      "programs.browserBaseline.vivaldi.externalExtensions"
      "programs.browserBaseline.vivaldi.nativeMessagingHosts"
      "programs.browserBaseline.floorp.policies"
    ];
    guardsVerified = [
      "priority-override"
      "duplicate-key"
      "invalid-identifier"
      "legacy-exclusivity"
      "reserved-key"
      "unsupported-null-value"
    ];
    exposedBuildOutputs = [
      "vivaldiManagedPlist"
      "vivaldiExternalExtensions"
      "vivaldiNativeMessagingHosts"
      "floorpManagedPlist"
      "floorpPreferences"
      "effectiveState"
    ];
  };
}
