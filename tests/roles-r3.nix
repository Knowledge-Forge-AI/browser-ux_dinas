{ lib, pkgs ? { runCommandLocal = name: _: text: { inherit name text; }; } }:
let
  roles = import ../config/browser/roles-r3.nix;
  provenance = import ../lib/application-claims.nix;
  target = import ../modules/roles-r3.nix {
    inherit lib;
    config = { networking.hostName = "example-current-mac";
      programs.browserBaseline = { rolesR3 = true; corePolicyOwnership = true; };
      homebrew.onActivation.cleanup = "none";
      "browser-ux".configuration.replacements.vivaldi.enable = true;
    };
  };
  referenceRefusal = configuration: cleanup: let rejected = import ../modules/roles-r3.nix {
    inherit lib;
    config = { programs.browserBaseline = { rolesR3 = true; corePolicyOwnership = true; };
      "browser-ux" = { inherit configuration; }; homebrew.onActivation.cleanup = cleanup; };
  }; in !lib.all (a: a.assertion) rejected.assertions && rejected.homebrew.casks == [ "vivaldi" "floorp" ];
  check = name: predicate: assert predicate; pkgs.runCommandLocal name {} ''touch "$out"'';
  chromeIds = builtins.attrNames roles.braveDaily.extensions;
  # Retained primaryCutover input is historical once the selected module owns R3.
  # Exercise the real readback boundary without a store copy or policy writer.
  readbackForHost = host: roleDefined: roleValue: cutoverEnabled: import ../delivery/evaluate-installed-inputs.nix {
    sourceRoots = {};
    inherit host;
    flakeOutputs.darwinConfigurations.${host} = {
      pkgs = { inherit lib; };
      options = {
        "browser-ux" = {
          configuration.isDefined = true;
          rolesR3.isDefined = roleDefined;
        };
        system.build.isDefined = false;
      };
      config = {
        networking.hostName = host;
        "browser-ux" = {
          rolesR3 = roleValue;
          configuration.extensions.apple-proton-trial.enable = true;
          configuration.replacements = {
            vivaldi = { enable = true; mail.enable = true; };
            floorp.enable = true;
          };
          configuration.primaryCutover = {
            enable = cutoverEnabled;
            activeBrowsers = [ "vivaldi" "floorp" "safari" ];
            retiredBrowsers = [ "chrome" "firefox" ];
            credentialProvider = "apple";
            productivityIntent = "feeds-only";
            protonVpnEnabled = true;
          };
        };
        system.build = throw "Undefined policy writer must remain lazy";
      };
    };
  };
  readback = roleDefined: roleValue: readbackForHost "example-current-mac" roleDefined roleValue true;
in {
  roles-r3-readback-host-trial-scope = check "roles-r3-readback-host-trial-scope" (
    let
      current = (readback true { enable = false; }).requiredPosture;
      replacementsOnly = (readbackForHost "example-current-mac" true { enable = false; } false).requiredPosture;
      other = (readbackForHost "example-previous-mac" false
        (throw "Undefined secondary role must remain lazy") true);
    in
    current.appleProton && current.protonVpnEnabled
    && current.vivaldi && current.floorp && current.safariManaged
    && replacementsOnly.activeBrowsers == [ "chrome" "firefox" "vivaldi" "floorp" ]
    && replacementsOnly.vivaldi && replacementsOnly.floorp
    && replacementsOnly.mailClient && replacementsOnly.calendarClient
    && !replacementsOnly.safariManaged
    && !other.requiredPosture.appleProton && !other.requiredPosture.protonVpnEnabled
    && !other.requiredPosture.vivaldi && !other.requiredPosture.floorp
    && !other.requiredPosture.mailClient && !other.requiredPosture.calendarClient
    && !other.requiredPosture.safariManaged
    && other.requiredPosture.credentialProvider == "legacy"
    && other.requiredPosture.activeBrowsers == [ "chrome" "firefox" ]
    && other.targetIntent.activeBrowsers == [ "chrome" "firefox" ]
    && other.targetIntent.activeBrowserCount == 2
    && other.targetIntent.safariIntent == "unselected"
  );
  roles-r3-legacy-cutover-readback-held = check "roles-r3-legacy-cutover-readback-held" (
    !(builtins.tryEval (readback true roles).requiredPosture).success
    && !(builtins.tryEval (readback true roles).applyScripts).success
  );
  roles-r3-legacy-readback-compatible = check "roles-r3-legacy-readback-compatible" (
    let
      disabled = readback true { enable = false; };
      undefined = readback false (throw "Undefined R3 option must remain lazy");
    in
    disabled.requiredPosture.activeBrowsers == [ "vivaldi" "floorp" "safari" ]
    && disabled.requiredPosture.credentialProvider == "apple"
    && undefined.requiredPosture == disabled.requiredPosture
    && disabled.applyScripts == {} && undefined.applyScript == null
  );
  roles-r3-owner-cut = check "roles-r3-owner-cut" (
    target.homebrew.casks == ["vivaldi" "floorp"]
    && target.programs.browserBaseline ? extensionContributions && !(target ? system)
    && lib.all (row: row.owner == "browser-ux" && row.policy == {}
      && !row.automaticInstallation && !row.autoConnect)
      target.programs.browserBaseline.extensionContributions
    && provenance.inventory == [] && provenance.applicationClaims == []
    && map (c: c.id) (provenance.applicationClaimsForHost { hostName = "example-current-mac"; }) == ["bundle:com.vivaldi.Vivaldi" "bundle:app.floorp.Floorp"]
    && provenance.applicationClaimsForHost { hostName = "example-previous-mac"; } == []
    && lib.all (a: a.assertion) target.assertions
    && !target."browser-ux".primaryCutover.enable
    && target."browser-ux".replacementRendering == { floorp = null; }
  );
  roles-r3-reference-retirement-refused = check "roles-r3-reference-retirement-refused" (
    referenceRefusal { replacements.vivaldi.enable = false; } "none"
    && referenceRefusal { replacements.vivaldi.enable = true; primaryCutover.retiredBrowsers = [ "vivaldi" ]; } "none"
    && referenceRefusal { replacements.vivaldi.enable = true; } "zap"
  );
  roles-r3-convenience-boundary = check "roles-r3-convenience-boundary" (
    builtins.length chromeIds == 7
    && !(builtins.elem "ddkjiahejlhfcafbddmgiahcphecmpfh" chromeIds)
    && !(builtins.elem "oboonakemofpalcgghocfoadofidjkkk" chromeIds)
    && !(builtins.elem "pejdijmoenmkgeppbflobdenhhabjlaj" chromeIds)
    && builtins.attrNames roles.librewolf.extensions == ["clear-new-tab@loftyshaky"]
    && roles.braveAutomation.extensions == {}
    && roles.braveAutomation.credentialManagers == []
    && roles.orion.extensions == roles.braveDaily.extensions
    && !roles.braveDaily.widevine.enabled
    && lib.all (item: !item.automaticInstallation) (builtins.attrValues roles.braveDaily.extensions)
    && roles.vivaldi.state == "VIVALDI_VISUAL_REFERENCE_RETAINED_DECOMMISSION_HELD"
    && !roles.vivaldi.primaryRole && roles.vivaldi.retirement == "EXPLICIT_OPERATOR_APPROVAL_REQUIRED"
    && !roles.braveYoutube.destinationWriterEnabled
  );
}
