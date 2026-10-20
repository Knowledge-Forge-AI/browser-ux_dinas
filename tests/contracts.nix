{
  self,
  lib,
  pkgs,
  nixpkgs,
  nix-darwin,
  defaultModule,
  applicationClaims,
  packageSetIdentity,
  configAllowlist,
  releaseCandidate,
  system,
}:

let
  seamFixture = import ./seam-fixture.nix;

  probeUser = "browser-probe";
  probeHome = "/Users/browser-probe";
  probeBase = {
    imports = [ seamFixture ];
    nixpkgs.pkgs = pkgs;
    system.primaryUser = probeUser;
    system.stateVersion = 6;
    users.users.${probeUser}.home = probeHome;
  };

  probeSystem =
    modules:
    nix-darwin.lib.darwinSystem {
      inherit pkgs;
      modules = [ probeBase ] ++ modules;
    };

  probe = modules: (probeSystem modules).config;

  baselineSys = probeSystem [ ];
  baseline = baselineSys.config;

  declaredSys = probeSystem [ defaultModule ];
  declared = declaredSys.config;
  declaredOptions = declaredSys.options;

  configuredSys = probeSystem [
    defaultModule
    {
      "browser-ux".configuration = {
        schema = 1;
        keepassxc.enable = true;
      };
    }
  ];
  configured = configuredSys.config;
  configuredOptions = configuredSys.options;

  replacementsEnabledSys = probeSystem [ defaultModule {
    "browser-ux".configuration.replacements = {
      vivaldi.enable = true;
      floorp.enable = true;
    };
  } ];
  replacementsEnabled = replacementsEnabledSys.config;
  replacementCombinations = {
    bothDisabled = { vivaldi = false; floorp = false; };
    floorpOnly = { vivaldi = false; floorp = true; };
    vivaldiOnly = { vivaldi = true; floorp = false; };
    bothEnabled = { vivaldi = true; floorp = true; };
  };
  replacementMatrix = lib.mapAttrs (_: enabled:
    let
      selection = lib.mapAttrs (_: enable: { inherit enable; }) enabled;
      sys = probeSystem [ defaultModule { "browser-ux".configuration.replacements = selection; } ];
      cfg = sys.config;
      rendering = cfg."browser-ux".replacementRendering;
      claims = cfg."browser-ux".replacementApplicationClaims;
      projected = lib.mapAttrs (_: record: if record == null then null else {
        inherit (record) browser verdict runtimeHolds activation replacementCandidate featureOverlays;
      }) rendering;
    in {
      inherit enabled;
      rendering = projected;
      claimIds = map (claim: claim.id) claims;
      selectedCasks = map (claim: claim.package) claims;
      baselineEqual = {
        toplevel = cfg.system.build.toplevel.drvPath == baseline.system.build.toplevel.drvPath;
        applications = cfg.system.build.applications.drvPath == baseline.system.build.applications.drvPath;
        homebrew = cfg.homebrew == baseline.homebrew;
        seams = replacementSeamValues cfg == replacementSeamValues declared;
        activationScripts = cfg.system.activationScripts == baseline.system.activationScripts;
        etc = cfg.environment.etc == baseline.environment.etc;
      };
      nativeMessagingHeld = lib.all (name: rendering.${name} == null ||
        (!rendering.${name}.nativeMessaging.qualified && !rendering.${name}.nativeMessaging.deliveredByBrowserUX))
        [ "vivaldi" "floorp" ];
      claimsEqual = claims == (import ../lib/application-claims.nix).replacementApplicationClaims selection
        && (import ../lib/application-claims.nix).applicationClaimsFor selection == applicationClaims ++ claims;
      policyPayloadUndefined = !sys.options.programs.browserBaseline.firefox.policiesJsonPayload.isDefined;
      hostSurfacesSafe = lib.all (surface:
        lib.all (fragment: !lib.hasInfix fragment surface)
          (rootWriterTargetPrefixes ++ profileMutablePathFragments)
      ) (allHostScriptSurfaces cfg);
    }
  ) replacementCombinations;
  replacementMatrixValid = lib.all (name:
    let row = replacementMatrix.${name}; in
    lib.all (value: value) (builtins.attrValues row.baselineEqual)
    && row.nativeMessagingHeld && row.claimsEqual && row.policyPayloadUndefined && row.hostSurfacesSafe
    && row.selectedCasks == lib.filter (browser: row.enabled.${browser}) [ "vivaldi" "floorp" ]
    && lib.all (browser: (row.rendering.${browser} != null) == row.enabled.${browser}) [ "vivaldi" "floorp" ]
  ) (builtins.attrNames replacementMatrix)
    && replacementMatrix.floorpOnly.rendering.floorp == replacementMatrix.bothEnabled.rendering.floorp
    && replacementMatrix.vivaldiOnly.rendering.vivaldi == replacementMatrix.bothEnabled.rendering.vivaldi
    && replacementMatrix.floorpOnly.rendering.floorp.runtimeHolds == [ ]
    && replacementMatrix.vivaldiOnly.rendering.vivaldi.runtimeHolds == [ ]
    && replacementMatrix.vivaldiOnly.rendering.vivaldi.replacementCandidate.qualification == "READY_FOR_QUALIFICATION"
    && replacementMatrix.vivaldiOnly.rendering.vivaldi.featureOverlays.mail.status == "HOLD_RUNTIME_OOM"
    && !replacementMatrix.vivaldiOnly.rendering.vivaldi.featureOverlays.mail.requested;
  replacementSeamValues = cfg: cfg.programs.browserBaseline // {
    firefox = builtins.removeAttrs cfg.programs.browserBaseline.firefox [ "policiesJsonPayload" ];
  };
  replacementConfigProbe = replacements: evalProbeConfig {
    "browser-ux".configuration = { inherit replacements; };
  };
  missingGeckoBridge = builtins.tryEval (builtins.deepSeq (probe [ defaultModule {
    "browser-ux".configuration.replacements.floorp.enable = true;
    programs.browserBaseline.firefox.nativeMessagingHosts = lib.mkForce { };
  } ])."browser-ux".replacementRendering true);

  explicitFalseSys = probeSystem [
    defaultModule
    {
      "browser-ux".configuration = {
        schema = 1;
        keepassxc.enable = false;
      };
    }
  ];
  explicitFalseConfig = explicitFalseSys.config;
  explicitFalseOptions = explicitFalseSys.options;

  chromeOptOutSys = probeSystem [
    defaultModule
    {
      "browser-ux".configuration = {
        schema = 1;
        keepassxc.enable = false;
        extensions."default-on-opt-out" = [
          "chrome:oboonakemofpalcgghocfoadofidjkkk"
        ];
      };
    }
  ];
  chromeOptOutConfig = chromeOptOutSys.config;

  firefoxOptOutSys = probeSystem [
    defaultModule
    {
      "browser-ux".configuration = {
        schema = 1;
        keepassxc.enable = false;
        extensions."default-on-opt-out" = [
          "firefox:keepassxc-browser@keepassxc.org"
        ];
      };
    }
  ];
  firefoxOptOutConfig = firefoxOptOutSys.config;

  optOutSys = probeSystem [
    defaultModule
    {
      "browser-ux".configuration = {
        schema = 1;
        keepassxc.enable = false;
        extensions."default-on-opt-out" = [
          "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
          "chrome:oboonakemofpalcgghocfoadofidjkkk"
          "firefox:markdown-viewer@outofindex.com"
          "firefox:keepassxc-browser@keepassxc.org"
        ];
      };
    }
  ];
  optOutConfig = optOutSys.config;
  optOutChromeExt = optOutConfig.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings;
  optOutFirefoxExt = optOutConfig.programs.browserBaseline.firefox.policies.ExtensionSettings;

  shippedConfig = builtins.fromTOML (builtins.readFile ../config/default/browser-ux.toml);
  shippedInjected = probe [
    defaultModule
    {
      "browser-ux".configuration = shippedConfig."browser-ux";
    }
  ];

  evalProbeConfig =
    configOverride:
    builtins.tryEval (
      builtins.deepSeq (probe [ defaultModule configOverride ])."browser-ux".configuration true
    );

  validPositive = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      keepassxc.enable = true;
    };
  };
  validOptOutPositive = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
        "firefox:markdown-viewer@outofindex.com"
      ];
    };
  };
  validKeePassXCOptOutWhenDisabledPositive = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      keepassxc.enable = false;
      extensions."default-on-opt-out" = [
        "chrome:oboonakemofpalcgghocfoadofidjkkk"
        "firefox:keepassxc-browser@keepassxc.org"
      ];
    };
  };

  invalidSchemaProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 2;
    };
  };
  invalidTypeProbe = evalProbeConfig {
    "browser-ux".configuration = {
      keepassxc.enable = "not-a-bool";
    };
  };
  unknownTopKeyProbe = evalProbeConfig {
    "browser-ux".configuration = {
      unknownKey = true;
    };
  };
  unknownChildKeyProbe = evalProbeConfig {
    "browser-ux".configuration = {
      keepassxc.unknownChild = true;
    };
  };
  unknownOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "chrome:unknown123" ];
    };
  };
  requiredOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "chrome:felphkbfjadmcejnibcmcncimlappdde" ];
    };
  };
  duplicateOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
      ];
    };
  };
  keepassxcOptOutWhenEnabledProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    };
  };
  firefoxRequiredOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "firefox:clear-new-tab@loftyshaky" ];
    };
  };
  firefoxKeePassXCOptOutWhenEnabledProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    };
  };
  defaultChromeKeePassXCOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    };
  };
  defaultFirefoxKeePassXCOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    };
  };
  crossBrowserBleedProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "chrome:{c3c10168-4186-445c-9c5b-63f12b8e2c87}" ];
    };
  };
  firefoxCrossBrowserBleedProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "firefox:hlkenndednhfkekhgcdicdfddnkalmdm" ];
    };
  };
  invalidFormatOptOutProbe = evalProbeConfig {
    "browser-ux".configuration = {
      schema = 1;
      extensions."default-on-opt-out" = [ "not-qualified-id" ];
    };
  };

  safeStr = v: if builtins.isString v || builtins.isPath v then builtins.toString v else "";
  activationScriptTexts =
    cfg: lib.mapAttrsToList (name: script: safeStr (script.text or null)) cfg.system.activationScripts;
  launchdTexts =
    cfg:
    let
      extractDef = d: [
        (safeStr (d.command or null))
        (safeStr (d.script or null))
        (safeStr (d.serviceConfig.Program or null))
        (builtins.concatStringsSep " " (map safeStr (d.serviceConfig.ProgramArguments or [ ])))
      ];
      allDefs =
        (builtins.attrValues (cfg.launchd.agents or { }))
        ++ (builtins.attrValues (cfg.launchd.daemons or { }))
        ++ (builtins.attrValues (cfg.launchd.user.agents or { }));
    in
    lib.concatMap extractDef allDefs;
  allHostScriptSurfaces = cfg: (activationScriptTexts cfg) ++ (launchdTexts cfg);

  rootWriterTargetPrefixes = [
    "/Library/Managed Preferences"
    "/Library/Preferences/org.mozilla.firefox.plist"
    "/Library/Application Support/Google/Chrome"
    "/Library/Google/Chrome"
    "/Library/Application Support/Mozilla"
    "/Applications/Firefox.app"
    "/Applications/Vivaldi.app"
    "/Applications/Floorp.app"
    "/Library/Preferences/app.floorp.Floorp.plist"
    "/Library/Application Support/Vivaldi"
    "/Library/Application Support/Floorp"
  ];

  profileMutablePathFragments = [
    "Google/Chrome"
    "Mozilla/Firefox"
    "Default"
    "Profiles"
    "IndexedDB"
    "Local Extension Settings"
    "Vivaldi"
    "Floorp"
    "com.vivaldi.Vivaldi"
    "app.floorp.Floorp"
  ];

  flakeSource = builtins.readFile ../flake.nix;
  defaultModuleSource = builtins.readFile ../modules/default.nix;
  candidateJson = builtins.toJSON releaseCandidate;
  seamFixtureSource = builtins.readFile ./seam-fixture.nix;
  chromeDefaultsSource = builtins.readFile ../config/browser/chrome-policy-defaults.nix;
  firefoxDefaultsSource = builtins.readFile ../config/browser/firefox-policy-defaults.nix;
  extensionPolicySource = builtins.readFile ../config/browser/extension-policy.nix;
  replacementSources = [
    "config/browser/families/chromium.nix"
    "config/browser/families/gecko.nix"
    "config/browser/replacements/default.nix"
    "config/browser/replacements/capabilities.nix"
    "config/browser/replacements/vivaldi.nix"
    "config/browser/replacements/floorp.nix"
    "config/browser/replacements/static-evidence.json"
    "config/browser/replacements/runtime-issues.json"
    "config/browser/replacements/system1-catalog.json"
    "tests/replacement-contracts.nix"
    "tests/replacement-schema-contracts.nix"
    "tests/replacement_app_identity.py"
    "tests/replacement-app-identity.test.py"
    "tests/replacement_host_kit.py"
    "tests/replacement-host-kit.test.py"
    "tests/fixtures/replacement-baseline-pins.json"
  ];
  cntJsonSource = builtins.readFile ../config/browser/chrome-clear-new-tab-external-extension.json;
  firefoxPoliciesSource = builtins.readFile ../config/browser/firefox-policies.json;
  chromeNmhSource = builtins.readFile ../config/browser/keepassxc-chrome-native-messaging.json;
  firefoxNmhSource = builtins.readFile ../config/browser/keepassxc-firefox-native-messaging.json;

  # Generalized structural public-source boundary check (embeds zero private literals).
  # Bounded structural heuristic (not complete personal-data detection; the parent
  # independently scans all exported files):
  # - Home paths: case-sensitive `(/Users|/home)/<seg>(/<nextSeg>)?` split; requires
  #   exact membership of `<seg>` in `allowedSyntheticHomeSegments`, or `seg == "Shared"`
  #   with `nextSeg == "agent-scratch"` (which exempts the entire `/Users/Shared/agent-scratch`
  #   subtree). Lowercase `/users/` prefixes are not matched by this regex.
  # - GitHub owners: case-insensitive `(github:|github\.com/|raw\.githubusercontent\.com/)<owner>`
  #   checked against the fixed `allowedGithubOwners` allowlist.
  # - Host labels: matches only the lowercased possessive `<name>s[-_](laptop|macbook(-pro|-air)?|imac|mac-mini|mac-studio|mac-pro)`
  #   shape, not arbitrary non-possessive hostnames.
  allowedSyntheticHomeSegments = [
    "browser-probe"
    "operator"
    "x"
    "someone"
    "other"
    "fixture"
    "example"
    "@USER_NAME@"
    "observer"
    "secret"
    "victim"
    "leaked"
  ];
  allowedGithubOwners = [
    "knowledge-forge-ai"
    "nixos"
    "nix-darwin"
    "keepassxreboot"
    "chromium"
  ];
  hasPublicBoundaryViolation =
    text:
    let
      lowerText = lib.toLower text;
      homeMatches =
        builtins.filter builtins.isList
          (builtins.split "(/Users|/home)/([A-Za-z0-9._@-]+)(/([A-Za-z0-9._@-]+))?" text);
      isAllowedHomeMatch =
        m:
        let
          seg = builtins.elemAt m 1;
          nextSeg = builtins.elemAt m 3;
        in
        if seg == "Shared" then
          nextSeg == "agent-scratch"
        else
          builtins.elem seg allowedSyntheticHomeSegments;
      hasConcreteHomePath = builtins.any (m: !(isAllowedHomeMatch m)) homeMatches;
      githubMatches =
        builtins.filter builtins.isList
          (builtins.split "(github:|github\\.com/|raw\\.githubusercontent\\.com/)([a-z0-9._-]+)" lowerText);
      hasUnallowedGithubOwner =
        builtins.any (m: !(builtins.elem (builtins.elemAt m 1) allowedGithubOwners)) githubMatches;
      hasHostLabel =
        builtins.match ".*(^|[^a-z0-9])[a-z0-9]+s[-_](laptop|macbook(-pro|-air)?|imac|mac-mini|mac-studio|mac-pro)($|[^a-z0-9]).*" lowerText != null;
      hasPrivateWorktreeMarker =
        builtins.match ".*(~|/)[.]local/nix-[A-Za-z0-9_-]+.*" text != null
        || builtins.match ".*(~|/)[.]fla[k]es.*" text != null
        || lib.hasInfix "forbidden-worktree-canary" text;
      hasPersonalBundlePrefix =
        builtins.match ".*bundle:com\\.[a-z0-9_-]+\\.(brave-youtube|youtube-chrome|youtube-brave).*" lowerText != null
        || builtins.match ".*remove_or_backup_app [^\n]* (com\\.[a-z0-9_-]+|ai\\.knowledge-forge\\.dinas)\\.youtube-(chrome|brave).*" lowerText != null;
    in
    hasConcreteHomePath
    || hasUnallowedGithubOwner
    || hasHostLabel
    || hasPrivateWorktreeMarker
    || hasPersonalBundlePrefix;

  checkRecursiveTypeEquality =
    a: b:
    if builtins.typeOf a != builtins.typeOf b then
      false
    else if builtins.isAttrs a then
      (lib.sort builtins.lessThan (builtins.attrNames a)) == (lib.sort builtins.lessThan (builtins.attrNames b))
      && builtins.all (k: checkRecursiveTypeEquality a.${k} b.${k}) (builtins.attrNames a)
    else if builtins.isList a then
      builtins.length a == builtins.length b
      && builtins.all (idx: checkRecursiveTypeEquality (builtins.elemAt a idx) (builtins.elemAt b idx)) (
        builtins.genList (i: i) (builtins.length a)
      )
    else
      a == b;

  hasNullValues =
    val:
    if val == null then
      true
    else if builtins.isAttrs val then
      builtins.any hasNullValues (builtins.attrValues val)
    else if builtins.isList val then
      builtins.any hasNullValues val
    else
      false;

  extensionPolicy = import ../config/browser/extension-policy.nix;
  chromePolicyFunc = import ../config/browser/chrome-policy-defaults.nix;
  firefoxPolicyFunc = import ../config/browser/firefox-policy-defaults.nix;

  expectedChromeRequiredIds = [
    "felphkbfjadmcejnibcmcncimlappdde"
    "ddkjiahejlhfcafbddmgiahcphecmpfh"
  ];
  expectedChromeDefaultOnIds = [
    "hlkenndednhfkekhgcdicdfddnkalmdm"
    "hoombieeljmmljlkjmnheibnpciblicm"
    "efaidnbmnnnibpcajpcglclefindmkaj"
    "lmjnegcaeklhafolokijcfjliaokphfk"
    "ckkdlimhmcjmikdlpkmbgfkaikojcbjk"
    "efknglbfhoddmmfabeihlemgekhhnabb"
  ];
  expectedChromeKeePassXCId = "oboonakemofpalcgghocfoadofidjkkk";
  expectedAllChromeExtIds =
    expectedChromeRequiredIds ++ expectedChromeDefaultOnIds ++ [ expectedChromeKeePassXCId ];

  expectedFirefoxRequiredIds = [
    "clear-new-tab@loftyshaky"
    "uBlock0@raymondhill.net"
  ];
  expectedFirefoxDefaultOnIds = [
    "{c3c10168-4186-445c-9c5b-63f12b8e2c87}"
    "markdown-viewer@outofindex.com"
    "{b9db16a4-6edc-47ec-a1f4-b86292ed211d}"
  ];
  expectedFirefoxKeePassXCId = "keepassxc-browser@keepassxc.org";
  expectedAllFirefoxExtIds =
    expectedFirefoxRequiredIds ++ expectedFirefoxDefaultOnIds ++ [ expectedFirefoxKeePassXCId ];

  # Pre-parsed payloads and policy keys for structural contract verification
  chromePrefs = declared.programs.browserBaseline.chrome.managedPreferences;
  chromeExtSettings = chromePrefs.ExtensionSettings;
  expectedChromePolicyKeys = [
    "AudioCaptureAllowedUrls"
    "BlockThirdPartyCookies"
    "DefaultAutomaticDownloadsSetting"
    "DefaultGeolocationSetting"
    "DefaultMediaStreamSetting"
    "DefaultNotificationsSetting"
    "DnsOverHttpsMode"
    "ExtensionInstallForcelist"
    "ExtensionSettings"
    "HttpsOnlyMode"
    "PasswordManagerEnabled"
    "VideoCaptureAllowedUrls"
  ];
  expectedChromeNonExtensionKeys = [
    "AudioCaptureAllowedUrls"
    "BlockThirdPartyCookies"
    "DefaultAutomaticDownloadsSetting"
    "DefaultGeolocationSetting"
    "DefaultMediaStreamSetting"
    "DefaultNotificationsSetting"
    "DnsOverHttpsMode"
    "HttpsOnlyMode"
    "VideoCaptureAllowedUrls"
  ];

  firefoxRaw = builtins.fromJSON firefoxPoliciesSource;
  firefoxStructuredDeclared = firefoxPolicyFunc {
    keepassxcEnabled = true;
    optOut = [ ];
  };
  firefoxStructuredConfigured = firefoxPolicyFunc {
    keepassxcEnabled = true;
    optOut = [ ];
  };
  firefoxExtSettings = declared.programs.browserBaseline.firefox.policies.ExtensionSettings;
  expectedFirefoxNonExtensionKeys = [
    "AutofillAddressEnabled"
    "AutofillCreditCardEnabled"
    "Cookies"
    "DisableFirefoxStudies"
    "DisableTelemetry"
    "DNSOverHTTPS"
    "EnableTrackingProtection"
    "HttpsOnlyMode"
    "OfferToSaveLoginsDefault"
  ];

  # BUX5C0 operator preference sources scanned by the public-source boundary.
  operatorPreferenceSources = [
    "extensions/browser-ux-scrollbars/manifest.json"
    "extensions/browser-ux-scrollbars/background.js"
    "extensions/browser-ux-scrollbars/content.js"
    "extensions/browser-ux-scrollbars/scrollbars.css"
    "tests/browser_preferences.py"
    "tests/browser-preferences.test.py"
    "tests/browser-preferences-harness.mjs"
    "tests/fixtures/browser-preferences/scrollbar-matrix.html"
    "tests/scrollbar_gui_kit.py"
    "tests/scrollbar-gui-kit.test.py"
    "docs/architecture/browser-operator-preferences.md"
    "tests/scrollbar_gui_runtime.py"
    "tests/scrollbar-gui-runtime.test.py"
    "tests/scrollbar_gui_observer.py"
    "tests/scrollbar-gui-observer.test.py"
    "tests/fixtures/browser-preferences/scrollbar-rail-boundary.html"
    "extensions/browser-ux-scrollbars/rail-core.js"
    "extensions/browser-ux-scrollbars/rail-host.css"
    "tests/scrollbar-rail-fakedom.mjs"
    "tests/scrollbar-rail-harness.mjs"
    "tests/scrollbar-rail.test.py"
    "tests/fixtures/browser-preferences/scrollbar-toplayer-matrix.html"
    "extensions/browser-ux-scrollbars/toplayer-sentinel-main.js"
    "tests/fixtures/browser-preferences/scrollbar-shadow-sentinel-matrix.html"
    "tests/bux5c0-r14-chrome-carry-forward-authority.json"
  ];

  cntJson = builtins.fromJSON cntJsonSource;
  chromeNmhJson = builtins.fromJSON chromeNmhSource;
  firefoxNmhJson = builtins.fromJSON firefoxNmhSource;
in
{
  replacement-module-contract =
    assert import ./replacement-schema-contracts.nix { inherit lib; };
    assert replacementMatrixValid;
    assert baseline.system.build.toplevel.drvPath == replacementsEnabled.system.build.toplevel.drvPath;
    assert baseline.system.build.applications.drvPath == replacementsEnabled.system.build.applications.drvPath;
    assert baseline.homebrew == replacementsEnabled.homebrew;
    assert baseline.environment.etc == replacementsEnabled.environment.etc;
    assert baseline.system.activationScripts == replacementsEnabled.system.activationScripts;
    assert lib.all (surface:
      lib.all (fragment: !lib.hasInfix fragment surface)
        (rootWriterTargetPrefixes ++ profileMutablePathFragments)
    ) (allHostScriptSurfaces replacementsEnabled);
    assert declared."browser-ux".replacementRendering == { vivaldi = null; floorp = null; };
    assert declared."browser-ux".replacementApplicationClaims == [ ];
    assert replacementsEnabled."browser-ux".replacementApplicationClaims ==
      (import ../lib/application-claims.nix).replacementApplicationClaims {
        vivaldi.enable = true; floorp.enable = true;
      };
    assert replacementsEnabled."browser-ux".replacementRendering.vivaldi.inheritFrom == "chrome";
    assert replacementsEnabled."browser-ux".replacementRendering.floorp.inheritFrom == "firefox";
    assert replacementSeamValues replacementsEnabled == replacementSeamValues declared;
    assert !replacementsEnabledSys.options.programs.browserBaseline.firefox.policiesJsonPayload.isDefined;
    assert missingGeckoBridge.success == false;
    assert (replacementConfigProbe { }).success;
    assert (replacementConfigProbe { vivaldi.enable = true; }).success;
    assert !(replacementConfigProbe { vivaldi.enable = true; vivaldi.mail.enable = true; }).success;
    assert !(replacementConfigProbe { vivaldi.mail.enable = true; }).success;
    assert !(replacementConfigProbe { floorp.mail.enable = true; }).success;
    assert !(replacementConfigProbe { brave.enable = true; }).success;
    assert !(replacementConfigProbe { vivaldi.unknown = true; }).success;
    assert !(replacementConfigProbe { vivaldi.enable = "true"; }).success;
    assert !(replacementConfigProbe { vivaldi."inherit-from" = "firefox"; }).success;
    assert !(replacementConfigProbe { floorp."inherit-from" = "chrome"; }).success;
    pkgs.runCommandLocal "browser-ux-replacement-module-contract" { } ''touch "$out"'';

  replacement-activation-matrix =
    assert replacementMatrixValid;
    pkgs.runCommandLocal "browser-ux-replacement-activation-matrix" {
      passthru.readback = {
        schema = "browser-ux-replacement-activation-matrix-v1";
        combinations = lib.mapAttrs (_: row: builtins.removeAttrs row
          [ "claimsEqual" "policyPayloadUndefined" "hostSurfacesSafe" ]) replacementMatrix;
      };
    } ''touch "$out"'';

  replacement-host-kit-tests = pkgs.runCommand "browser-ux-replacement-host-kit-tests" {
    nativeBuildInputs = [ pkgs.python3Packages.pytest ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    pytest --import-mode=importlib -q -p no:cacheprovider ${../.}/tests/replacement-host-kit.test.py
    touch "$out"
  '';

  replacement-app-identity-tests = pkgs.runCommand "browser-ux-replacement-app-identity-tests" {
    nativeBuildInputs = [ pkgs.python3Packages.pytest ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    pytest --import-mode=importlib -q -p no:cacheprovider ${../.}/tests/replacement-app-identity.test.py
    touch "$out"
  '';
  command-dormancy = import ./command-dormancy.nix {
    inherit lib pkgs releaseCandidate;
    defaultActivation = lib.concatStringsSep "\n" (activationScriptTexts declared);
  };
  module-inertness-contract =
    # Prove defaultModule and configured probes contribute zero changes to host generation baseline
    assert baseline.environment.systemPackages == declared.environment.systemPackages;
    assert baseline.homebrew.brews == declared.homebrew.brews;
    assert baseline.homebrew.casks == declared.homebrew.casks;
    assert baseline.homebrew.taps == declared.homebrew.taps;
    assert baseline.homebrew.masApps == declared.homebrew.masApps;
    assert baseline.system.activationScripts == declared.system.activationScripts;
    assert baseline.launchd.agents == declared.launchd.agents;
    assert baseline.launchd.daemons == declared.launchd.daemons;
    assert baseline.launchd.user.agents == declared.launchd.user.agents;
    assert baseline.environment.variables == declared.environment.variables;
    assert baseline.environment.shellInit == declared.environment.shellInit;
    assert baseline.environment.loginShellInit == declared.environment.loginShellInit;
    assert baseline.environment.interactiveShellInit == declared.environment.interactiveShellInit;
    assert baseline.environment.etc == declared.environment.etc;

    # Explicitly configured probe contributes zero changes
    assert baseline.environment.systemPackages == configured.environment.systemPackages;
    assert baseline.homebrew.brews == configured.homebrew.brews;
    assert baseline.homebrew.casks == configured.homebrew.casks;
    assert baseline.homebrew.taps == configured.homebrew.taps;
    assert baseline.homebrew.masApps == configured.homebrew.masApps;
    assert baseline.system.activationScripts == configured.system.activationScripts;
    assert baseline.launchd.agents == configured.launchd.agents;
    assert baseline.launchd.daemons == configured.launchd.daemons;
    assert baseline.launchd.user.agents == configured.launchd.user.agents;
    assert baseline.environment.variables == configured.environment.variables;
    assert baseline.environment.shellInit == configured.environment.shellInit;
    assert baseline.environment.loginShellInit == configured.environment.loginShellInit;
    assert baseline.environment.interactiveShellInit == configured.environment.interactiveShellInit;
    assert baseline.environment.etc == configured.environment.etc;

    # Shipped-injected probe contributes zero changes
    assert baseline.environment.systemPackages == shippedInjected.environment.systemPackages;
    assert baseline.homebrew.brews == shippedInjected.homebrew.brews;
    assert baseline.homebrew.casks == shippedInjected.homebrew.casks;
    assert baseline.homebrew.taps == shippedInjected.homebrew.taps;
    assert baseline.homebrew.masApps == shippedInjected.homebrew.masApps;
    assert baseline.system.activationScripts == shippedInjected.system.activationScripts;
    assert baseline.launchd.agents == shippedInjected.launchd.agents;
    assert baseline.launchd.daemons == shippedInjected.launchd.daemons;
    assert baseline.launchd.user.agents == shippedInjected.launchd.user.agents;
    assert baseline.environment.variables == shippedInjected.environment.variables;
    assert baseline.environment.shellInit == shippedInjected.environment.shellInit;
    assert baseline.environment.loginShellInit == shippedInjected.environment.loginShellInit;
    assert baseline.environment.interactiveShellInit == shippedInjected.environment.interactiveShellInit;
    assert baseline.environment.etc == shippedInjected.environment.etc;

    # Strongest safe total-generation equality
    assert baseline.system.build.toplevel.drvPath == declared.system.build.toplevel.drvPath;
    assert baseline.system.build.toplevel.drvPath == configured.system.build.toplevel.drvPath;
    assert baseline.system.build.toplevel.drvPath == shippedInjected.system.build.toplevel.drvPath;
    assert baseline.system.build.toplevel.drvPath == optOutConfig.system.build.toplevel.drvPath;

    # Verify zero root writer text in activation script surfaces across declared and configured
    assert lib.all (
      surface: lib.all (prefix: !lib.hasInfix prefix surface) rootWriterTargetPrefixes
    ) (activationScriptTexts declared);
    assert lib.all (
      surface: lib.all (prefix: !lib.hasInfix prefix surface) rootWriterTargetPrefixes
    ) (activationScriptTexts configured);

    # Verify zero mutable profile path fragments in activation scripts or launchd surfaces (Test 25)
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces declared);
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces configured);
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces shippedInjected);
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces optOutConfig);

    pkgs.runCommandLocal "browser-ux-dinas-module-inertness-contract" { } ''
      touch "$out"
    '';

  generated-applications-inert =
    assert baseline.system.build.applications.drvPath == declared.system.build.applications.drvPath;
    assert baseline.system.build.applications.drvPath == configured.system.build.applications.drvPath;
    assert baseline.system.build.applications.drvPath == shippedInjected.system.build.applications.drvPath;
    assert baseline.system.build.applications.drvPath == optOutConfig.system.build.applications.drvPath;
    pkgs.runCommandLocal "browser-ux-dinas-generated-applications-inert"
      {
        baselineApplications = baseline.system.build.applications;
        declaredApplications = declared.system.build.applications;
      }
      ''
        diff -ru "$baselineApplications" "$declaredApplications"
        touch "$out"
      '';

  typed-configuration-contract =
    # 1. Typed default
    assert declared."browser-ux".configuration.schema == 1;
    assert declared."browser-ux".configuration.keepassxc.enable == true;
    assert declared."browser-ux".configuration.extensions."default-on-opt-out" == [ ];
    assert declared."browser-ux".configuration == shippedConfig."browser-ux";

    # 2. Explicit projected configuration
    assert configured."browser-ux".configuration.schema == 1;
    assert configured."browser-ux".configuration.keepassxc.enable == true;
    assert configured."browser-ux".configuration.extensions."default-on-opt-out" == [ ];

    # Positive controls: valid configurations evaluate successfully
    assert validPositive.success == true;
    assert validOptOutPositive.success == true;
    assert validKeePassXCOptOutWhenDisabledPositive.success == true;

    # 3. Closed schema and semantic validations: invalid values fail evaluation
    assert invalidSchemaProbe.success == false;
    assert invalidTypeProbe.success == false;
    assert unknownTopKeyProbe.success == false;
    assert unknownChildKeyProbe.success == false;
    assert unknownOptOutProbe.success == false;
    assert requiredOptOutProbe.success == false;
    assert duplicateOptOutProbe.success == false;
    assert defaultChromeKeePassXCOptOutProbe.success == false;
    assert defaultFirefoxKeePassXCOptOutProbe.success == false;
    assert keepassxcOptOutWhenEnabledProbe.success == false;
    assert firefoxRequiredOptOutProbe.success == false;
    assert firefoxKeePassXCOptOutWhenEnabledProbe.success == false;
    assert crossBrowserBleedProbe.success == false;
    assert firefoxCrossBrowserBleedProbe.success == false;
    assert invalidFormatOptOutProbe.success == false;

    # Exact error strings from extensionPolicy.validateConfiguration
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:felphkbfjadmcejnibcmcncimlappdde" ];
    } == "Cannot opt out required Chrome extension 'felphkbfjadmcejnibcmcncimlappdde'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:clear-new-tab@loftyshaky" ];
    } == "Cannot opt out required Firefox extension 'clear-new-tab@loftyshaky'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:unknown123" ];
    } == "Unknown Chrome extension opt-out 'unknown123'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:unknown123" ];
    } == "Unknown Firefox extension opt-out 'unknown123'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
      ];
    } == "Duplicate extension opt-out detected in default-on-opt-out";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";
    # Standalone validation without keepassxc explicitly configured defaults to keepassxcEnabled = true
    assert extensionPolicy.validateConfiguration {
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";
    assert extensionPolicy.validateConfiguration {
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";
    # Standalone validation with explicit keepassxc.enable = false permits KeePassXC opt-out
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = false;
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    } == null;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = false;
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    } == null;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:{c3c10168-4186-445c-9c5b-63f12b8e2c87}" ];
    } == "Unknown Chrome extension opt-out '{c3c10168-4186-445c-9c5b-63f12b8e2c87}'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:hlkenndednhfkekhgcdicdfddnkalmdm" ];
    } == "Unknown Firefox extension opt-out 'hlkenndednhfkekhgcdicdfddnkalmdm'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "not-qualified-id" ];
    } == "Invalid extension opt-out format 'not-qualified-id': must be prefixed with 'chrome:' or 'firefox:'";
    pkgs.runCommandLocal "browser-ux-dinas-typed-configuration-contract" { } ''
      touch "$out"
    '';

  browser-policy-structure-contract =
    # 1. Destination evaluates with public default config
    assert declared."browser-ux".configuration.schema == 1;

    # 2. Default config remains schema = 1, keepassxc.enable = true, default-on-opt-out = []
    assert shippedConfig."browser-ux".schema == 1;
    assert shippedConfig."browser-ux".keepassxc.enable == true;
    assert shippedConfig."browser-ux".extensions."default-on-opt-out" == [ ];

    # 3. Destination sets legacy defaults false
    assert declared.programs.browserBaseline.legacyPolicyDefaults.enable == false;
    assert configured.programs.browserBaseline.legacyPolicyDefaults.enable == false;
    assert shippedInjected.programs.browserBaseline.legacyPolicyDefaults.enable == false;
    assert optOutConfig.programs.browserBaseline.legacyPolicyDefaults.enable == false;

    # 4. Chrome managed preferences are non-empty and have expected structural policy keys
    assert (lib.sort builtins.lessThan (builtins.attrNames chromePrefs)) == expectedChromePolicyKeys;
    assert chromePrefs.BlockThirdPartyCookies == true;
    assert chromePrefs.DefaultAutomaticDownloadsSetting == 3;
    assert chromePrefs.DefaultGeolocationSetting == 3;
    assert chromePrefs.DefaultMediaStreamSetting == 3;
    assert chromePrefs.DefaultNotificationsSetting == 3;
    assert chromePrefs.DnsOverHttpsMode == "off";
    assert chromePrefs.HttpsOnlyMode == "force_balanced_enabled";
    assert builtins.length chromePrefs.AudioCaptureAllowedUrls == 21;
    assert builtins.length chromePrefs.VideoCaptureAllowedUrls == 21;

    # Non-extension Chrome policy values are invariant between declared and configured
    assert lib.all (
      k:
      declared.programs.browserBaseline.chrome.managedPreferences.${k}
      == configured.programs.browserBaseline.chrome.managedPreferences.${k}
    ) expectedChromeNonExtensionKeys;

    # 5. Chrome extension IDs exist exactly once across classes and render force_installed by default
    assert (lib.sort builtins.lessThan (builtins.attrNames extensionPolicy.chromeExtensions.required))
      == (lib.sort builtins.lessThan expectedChromeRequiredIds);
    assert (lib.sort builtins.lessThan (builtins.attrNames extensionPolicy.chromeExtensions.defaultOn))
      == (lib.sort builtins.lessThan expectedChromeDefaultOnIds);
    assert extensionPolicy.chromeExtensions.keepassxc.id == expectedChromeKeePassXCId;
    assert builtins.length (lib.unique expectedAllChromeExtIds) == builtins.length expectedAllChromeExtIds;
    assert lib.intersectLists (builtins.attrNames extensionPolicy.chromeExtensions.required) (builtins.attrNames extensionPolicy.chromeExtensions.defaultOn) == [ ];
    assert !(builtins.elem extensionPolicy.chromeExtensions.keepassxc.id (builtins.attrNames extensionPolicy.chromeExtensions.required));
    assert !(builtins.elem extensionPolicy.chromeExtensions.keepassxc.id (builtins.attrNames extensionPolicy.chromeExtensions.defaultOn));
    assert (lib.sort builtins.lessThan (builtins.filter (k: k != "*") (builtins.attrNames chromeExtSettings)))
      == (lib.sort builtins.lessThan expectedAllChromeExtIds);
    assert lib.all (
      id:
      (chromeExtSettings.${id}.installation_mode == "force_installed")
      && (chromeExtSettings.${id}.update_url == "https://clients2.google.com/service/update2/crx")
    ) expectedAllChromeExtIds;
    assert chromePrefs.ExtensionInstallForcelist == [
      "felphkbfjadmcejnibcmcncimlappdde;https://clients2.google.com/service/update2/crx"
    ];

    # 6. Firefox extension IDs exist exactly once across classes and render force_installed by default
    assert (lib.sort builtins.lessThan (builtins.attrNames extensionPolicy.firefoxExtensions.required))
      == (lib.sort builtins.lessThan expectedFirefoxRequiredIds);
    assert (lib.sort builtins.lessThan (builtins.attrNames extensionPolicy.firefoxExtensions.defaultOn))
      == (lib.sort builtins.lessThan expectedFirefoxDefaultOnIds);
    assert extensionPolicy.firefoxExtensions.keepassxc.id == expectedFirefoxKeePassXCId;
    assert builtins.length (lib.unique expectedAllFirefoxExtIds) == builtins.length expectedAllFirefoxExtIds;
    assert lib.intersectLists (builtins.attrNames extensionPolicy.firefoxExtensions.required) (builtins.attrNames extensionPolicy.firefoxExtensions.defaultOn) == [ ];
    assert !(builtins.elem extensionPolicy.firefoxExtensions.keepassxc.id (builtins.attrNames extensionPolicy.firefoxExtensions.required));
    assert !(builtins.elem extensionPolicy.firefoxExtensions.keepassxc.id (builtins.attrNames extensionPolicy.firefoxExtensions.defaultOn));
    assert (lib.sort builtins.lessThan (builtins.filter (k: k != "*") (builtins.attrNames firefoxExtSettings)))
      == (lib.sort builtins.lessThan expectedAllFirefoxExtIds);
    assert lib.all (
      id:
      (firefoxExtSettings.${id}.installation_mode == "force_installed")
      && (firefoxExtSettings.${id}.install_url == firefoxRaw.policies.ExtensionSettings.${id}.install_url)
    ) expectedAllFirefoxExtIds;

    # 7. Wildcard extension setting remains allowed in both browsers
    assert chromeExtSettings."*".installation_mode == "allowed";
    assert configured.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings."*".installation_mode == "allowed";
    assert optOutChromeExt."*".installation_mode == "allowed";
    assert firefoxExtSettings."*".installation_mode == "allowed";
    assert configured.programs.browserBaseline.firefox.policies.ExtensionSettings."*".installation_mode == "allowed";
    assert optOutFirefoxExt."*".installation_mode == "allowed";

    # 8. Chrome default-on opt-out renders allowed with no auto-install-only fields
    assert optOutChromeExt."hlkenndednhfkekhgcdicdfddnkalmdm" == {
      installation_mode = "allowed";
    };
    # Non-opted-out Chrome extensions remain force_installed with update_url
    assert optOutChromeExt."felphkbfjadmcejnibcmcncimlappdde" == {
      installation_mode = "force_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };
    assert optOutChromeExt."ddkjiahejlhfcafbddmgiahcphecmpfh" == {
      installation_mode = "force_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };
    assert optOutChromeExt."hoombieeljmmljlkjmnheibnpciblicm" == {
      installation_mode = "force_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };

    # 9. Firefox default-on opt-out renders allowed with no auto-install-only fields
    assert optOutFirefoxExt."markdown-viewer@outofindex.com" == {
      installation_mode = "allowed";
    };
    # Non-opted-out Firefox extensions remain force_installed with install_url
    assert optOutFirefoxExt."clear-new-tab@loftyshaky" == {
      installation_mode = "force_installed";
      install_url = firefoxRaw.policies.ExtensionSettings."clear-new-tab@loftyshaky".install_url;
    };
    assert optOutFirefoxExt."uBlock0@raymondhill.net" == {
      installation_mode = "force_installed";
      install_url = firefoxRaw.policies.ExtensionSettings."uBlock0@raymondhill.net".install_url;
    };
    assert optOutFirefoxExt."{c3c10168-4186-445c-9c5b-63f12b8e2c87}" == {
      installation_mode = "force_installed";
      install_url = firefoxRaw.policies.ExtensionSettings."{c3c10168-4186-445c-9c5b-63f12b8e2c87}".install_url;
    };

    # 10. Required opt-out is rejected (asserted via probes in typed-configuration-contract)
    assert requiredOptOutProbe.success == false;
    assert firefoxRequiredOptOutProbe.success == false;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:felphkbfjadmcejnibcmcncimlappdde" ];
    } == "Cannot opt out required Chrome extension 'felphkbfjadmcejnibcmcncimlappdde'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:clear-new-tab@loftyshaky" ];
    } == "Cannot opt out required Firefox extension 'clear-new-tab@loftyshaky'";

    # 11. Unknown opt-out is rejected (asserted via probes in typed-configuration-contract)
    assert unknownOptOutProbe.success == false;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:unknown123" ];
    } == "Unknown Chrome extension opt-out 'unknown123'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:unknown123" ];
    } == "Unknown Firefox extension opt-out 'unknown123'";

    # 12. Duplicate opt-outs are rejected (asserted via probes in typed-configuration-contract)
    assert duplicateOptOutProbe.success == false;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
        "chrome:hlkenndednhfkekhgcdicdfddnkalmdm"
      ];
    } == "Duplicate extension opt-out detected in default-on-opt-out";

    # 13. Browser-qualified identities cannot bleed across browsers (asserted via probe)
    assert crossBrowserBleedProbe.success == false;
    assert firefoxCrossBrowserBleedProbe.success == false;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:{c3c10168-4186-445c-9c5b-63f12b8e2c87}" ];
    } == "Unknown Chrome extension opt-out '{c3c10168-4186-445c-9c5b-63f12b8e2c87}'";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:hlkenndednhfkekhgcdicdfddnkalmdm" ];
    } == "Unknown Firefox extension opt-out 'hlkenndednhfkekhgcdicdfddnkalmdm'";

    # 14. keepassxc.enable = true makes KeePassXC required in both browsers (both default and explicit)
    assert declared.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${expectedChromeKeePassXCId}.installation_mode == "force_installed";
    assert declared.programs.browserBaseline.firefox.policies.ExtensionSettings.${expectedFirefoxKeePassXCId}.installation_mode == "force_installed";
    assert configured.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${expectedChromeKeePassXCId}.installation_mode == "force_installed";
    assert configured.programs.browserBaseline.firefox.policies.ExtensionSettings.${expectedFirefoxKeePassXCId}.installation_mode == "force_installed";

    # 15. KeePassXC opt-out is rejected while integration is enabled
    assert defaultChromeKeePassXCOptOutProbe.success == false;
    assert defaultFirefoxKeePassXCOptOutProbe.success == false;
    assert keepassxcOptOutWhenEnabledProbe.success == false;
    assert firefoxKeePassXCOptOutWhenEnabledProbe.success == false;
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "chrome:oboonakemofpalcgghocfoadofidjkkk" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";
    assert extensionPolicy.validateConfiguration {
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ "firefox:keepassxc-browser@keepassxc.org" ];
    } == "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true";

    # 16. keepassxc.enable = false leaves KeePassXC default-on (renders force_installed without opt-out)
    assert explicitFalseConfig.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${expectedChromeKeePassXCId} == {
      installation_mode = "force_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };
    assert explicitFalseConfig.programs.browserBaseline.firefox.policies.ExtensionSettings.${expectedFirefoxKeePassXCId} == {
      installation_mode = "force_installed";
      install_url = firefoxRaw.policies.ExtensionSettings.${expectedFirefoxKeePassXCId}.install_url;
    };

    # 17. KeePassXC may then be explicitly opted out when keepassxc.enable = false
    # 17a. Browser-qualified Chrome-only opt-out renders only Chrome extension allowed; Firefox remains force_installed
    assert chromeOptOutConfig.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${expectedChromeKeePassXCId} == {
      installation_mode = "allowed";
    };
    assert chromeOptOutConfig.programs.browserBaseline.firefox.policies.ExtensionSettings.${expectedFirefoxKeePassXCId} == {
      installation_mode = "force_installed";
      install_url = firefoxRaw.policies.ExtensionSettings.${expectedFirefoxKeePassXCId}.install_url;
    };
    # 17b. Browser-qualified Firefox-only opt-out renders only Firefox extension allowed; Chrome remains force_installed
    assert firefoxOptOutConfig.programs.browserBaseline.firefox.policies.ExtensionSettings.${expectedFirefoxKeePassXCId} == {
      installation_mode = "allowed";
    };
    assert firefoxOptOutConfig.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${expectedChromeKeePassXCId} == {
      installation_mode = "force_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };
    # 17c. Both opted out
    assert optOutChromeExt.${expectedChromeKeePassXCId} == {
      installation_mode = "allowed";
    };
    assert optOutFirefoxExt.${expectedFirefoxKeePassXCId} == {
      installation_mode = "allowed";
    };

    # 18. Existing install/update URLs for non-opted-out extensions are unchanged
    assert lib.all (
      id:
      declared.programs.browserBaseline.chrome.managedPreferences.ExtensionSettings.${id}.update_url
      == "https://clients2.google.com/service/update2/crx"
    ) expectedAllChromeExtIds;
    assert lib.all (
      id:
      declared.programs.browserBaseline.firefox.policies.ExtensionSettings.${id}.install_url
      == firefoxRaw.policies.ExtensionSettings.${id}.install_url
    ) expectedAllFirefoxExtIds;

    # 19. Current Chrome Clear New Tab forcelist remains exact
    assert chromePrefs.ExtensionInstallForcelist == [
      "felphkbfjadmcejnibcmcncimlappdde;https://clients2.google.com/service/update2/crx"
    ];

    # 20. Firefox policyDelivery remains macos-preferences
    assert declared.programs.browserBaseline.firefox.policyDelivery == "macos-preferences";
    assert configured.programs.browserBaseline.firefox.policyDelivery == "macos-preferences";
    assert shippedInjected.programs.browserBaseline.firefox.policyDelivery == "macos-preferences";
    assert optOutConfig.programs.browserBaseline.firefox.policyDelivery == "macos-preferences";

    # 21. All non-extension Chrome policy values are unchanged
    assert (lib.sort builtins.lessThan (builtins.attrNames chromePrefs)) == expectedChromePolicyKeys;

    # 22. All non-extension Firefox policy values are unchanged
    assert lib.all (
      k: declared.programs.browserBaseline.firefox.policies.${k} == firefoxRaw.policies.${k}
    ) expectedFirefoxNonExtensionKeys;
    assert lib.all (
      k: configured.programs.browserBaseline.firefox.policies.${k} == firefoxRaw.policies.${k}
    ) expectedFirefoxNonExtensionKeys;
    assert lib.all (
      k: explicitFalseConfig.programs.browserBaseline.firefox.policies.${k} == firefoxRaw.policies.${k}
    ) expectedFirefoxNonExtensionKeys;
    assert lib.all (
      k: optOutConfig.programs.browserBaseline.firefox.policies.${k} == firefoxRaw.policies.${k}
    ) expectedFirefoxNonExtensionKeys;

    # 23. NativeMessagingHosts default enabled; explicit-false absent
    # Default has both NativeMessagingHosts present
    assert declaredOptions.programs.browserBaseline.chrome.nativeMessagingHosts.isDefined == true;
    assert declaredOptions.programs.browserBaseline.firefox.nativeMessagingHosts.isDefined == true;
    assert (builtins.attrNames declared.programs.browserBaseline.chrome.nativeMessagingHosts)
      == [ "org.keepassxc.keepassxc_browser" ];
    assert (builtins.attrNames declared.programs.browserBaseline.firefox.nativeMessagingHosts)
      == [ "org.keepassxc.keepassxc_browser" ];
    assert declared.programs.browserBaseline.chrome.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-chrome-native-messaging.json;
    assert declared.programs.browserBaseline.firefox.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-firefox-native-messaging.json;

    # Explicit configured true has both NativeMessagingHosts present
    assert configuredOptions.programs.browserBaseline.chrome.nativeMessagingHosts.isDefined == true;
    assert configuredOptions.programs.browserBaseline.firefox.nativeMessagingHosts.isDefined == true;
    assert (builtins.attrNames configured.programs.browserBaseline.chrome.nativeMessagingHosts)
      == [ "org.keepassxc.keepassxc_browser" ];
    assert (builtins.attrNames configured.programs.browserBaseline.firefox.nativeMessagingHosts)
      == [ "org.keepassxc.keepassxc_browser" ];

    # Explicit false removes both NativeMessagingHosts
    assert explicitFalseOptions.programs.browserBaseline.chrome.nativeMessagingHosts.isDefined == false;
    assert explicitFalseOptions.programs.browserBaseline.chrome.nativeMessagingHosts.definitionsWithLocations == [ ];
    assert explicitFalseOptions.programs.browserBaseline.firefox.nativeMessagingHosts.isDefined == false;
    assert explicitFalseOptions.programs.browserBaseline.firefox.nativeMessagingHosts.definitionsWithLocations == [ ];
    assert optOutSys.options.programs.browserBaseline.chrome.nativeMessagingHosts.isDefined == false;
    assert optOutSys.options.programs.browserBaseline.chrome.nativeMessagingHosts.definitionsWithLocations == [ ];
    assert optOutSys.options.programs.browserBaseline.firefox.nativeMessagingHosts.isDefined == false;
    assert optOutSys.options.programs.browserBaseline.firefox.nativeMessagingHosts.definitionsWithLocations == [ ];

    assert chromeNmhJson.name == "org.keepassxc.keepassxc_browser";
    assert chromeNmhJson.allowed_origins == [ "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/" ];
    assert chromeNmhJson.path == "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-proxy";
    assert firefoxNmhJson.name == "org.keepassxc.keepassxc_browser";
    assert firefoxNmhJson.allowed_extensions == [ "keepassxc-browser@keepassxc.org" ];
    assert firefoxNmhJson.path == "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-proxy";

    # External extension payload exists and ID is exact
    assert (builtins.attrNames declared.programs.browserBaseline.chrome.externalExtensions)
      == [ "felphkbfjadmcejnibcmcncimlappdde" ];
    assert cntJson.external_update_url == "https://clients2.google.com/service/update2/crx";

    # JSON payloads parse cleanly
    assert builtins.isAttrs cntJson;
    assert builtins.isAttrs firefoxRaw;
    assert builtins.isAttrs chromeNmhJson;
    assert builtins.isAttrs firefoxNmhJson;

    # Firefox policies structured representation matches function evaluations
    assert declaredOptions.programs.browserBaseline.firefox.policies.isDefined == true;
    assert configuredOptions.programs.browserBaseline.firefox.policies.isDefined == true;
    assert declared.programs.browserBaseline.firefox.policies != { };
    assert declared.programs.browserBaseline.firefox.policies == firefoxStructuredDeclared;
    assert configured.programs.browserBaseline.firefox.policies == firefoxStructuredConfigured;
    assert !(firefoxStructuredDeclared ? EnterprisePoliciesEnabled);
    assert !hasNullValues firefoxStructuredDeclared;

    assert declaredOptions.programs.browserBaseline.firefox.policiesJsonPayload.isDefined == false;
    assert declaredOptions.programs.browserBaseline.firefox.policiesJsonPayload.definitionsWithLocations == [ ];
    assert configuredOptions.programs.browserBaseline.firefox.policiesJsonPayload.isDefined == false;
    assert configuredOptions.programs.browserBaseline.firefox.policiesJsonPayload.definitionsWithLocations == [ ];

    # Option payload path wiring asserts exact destination-owned sources
    assert declared.programs.browserBaseline.firefox.policies
      == firefoxPolicyFunc {
        keepassxcEnabled = true;
        optOut = [ ];
      };
    assert declared.programs.browserBaseline.chrome.managedPreferences
      == chromePolicyFunc {
        keepassxcEnabled = true;
        optOut = [ ];
      };
    assert explicitFalseConfig.programs.browserBaseline.firefox.policies
      == firefoxPolicyFunc {
        keepassxcEnabled = false;
        optOut = [ ];
      };
    assert explicitFalseConfig.programs.browserBaseline.chrome.managedPreferences
      == chromePolicyFunc {
        keepassxcEnabled = false;
        optOut = [ ];
      };
    assert declared.programs.browserBaseline.chrome.externalExtensions."felphkbfjadmcejnibcmcncimlappdde"
      == ../config/browser/chrome-clear-new-tab-external-extension.json;
    assert declared.programs.browserBaseline.chrome.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-chrome-native-messaging.json;
    assert declared.programs.browserBaseline.firefox.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-firefox-native-messaging.json;
    assert declared.programs.browserBaseline.chrome.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      != declared.programs.browserBaseline.firefox.nativeMessagingHosts."org.keepassxc.keepassxc_browser";
    assert configured.programs.browserBaseline.chrome.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-chrome-native-messaging.json;
    assert configured.programs.browserBaseline.firefox.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      == ../config/browser/keepassxc-firefox-native-messaging.json;
    assert configured.programs.browserBaseline.chrome.nativeMessagingHosts."org.keepassxc.keepassxc_browser"
      != configured.programs.browserBaseline.firefox.nativeMessagingHosts."org.keepassxc.keepassxc_browser";

    # 24. No Browser UX activation/root writer appears
    assert lib.all (
      surface: lib.all (prefix: !lib.hasInfix prefix surface) rootWriterTargetPrefixes
    ) (activationScriptTexts declared);
    assert lib.all (
      surface: lib.all (prefix: !lib.hasInfix prefix surface) rootWriterTargetPrefixes
    ) (activationScriptTexts configured);

    # 25. No profile/CNT mutable path appears
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces declared);
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces configured);
    assert lib.all (
      surface: lib.all (frag: !lib.hasInfix frag surface) profileMutablePathFragments
    ) (allHostScriptSurfaces optOutConfig);

    # 26. Application claims remain declarative; no host contribution appears
    assert baseline.environment.systemPackages == declared.environment.systemPackages;
    assert baseline.homebrew.casks == declared.homebrew.casks;
    assert baseline.launchd.agents == declared.launchd.agents;
    assert applicationClaims == (import ./dormant-contracts.nix { inherit lib pkgs; }).expectedClaims;

    pkgs.runCommandLocal "browser-ux-dinas-browser-policy-structure-contract" { } ''
      touch "$out"
    '';

  chrome-plist-ast-parity-contract =
    let
      renderedPlist = pkgs.writeText "rendered-chrome-policy.plist" (
        lib.generators.toPlist { escape = true; } declared.programs.browserBaseline.chrome.managedPreferences
      );
      fixturePlist = ./fixtures/chrome-policy.plist;
    in
    pkgs.runCommandLocal "browser-ux-dinas-chrome-plist-ast-parity-contract"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        python3 -c '
        import plistlib, sys

        def assert_strict_equal(v1, v2, path="root"):
            if type(v1) is not type(v2):
                print(f"Type mismatch at {path}: {type(v1).__name__} vs {type(v2).__name__} ({v1!r} vs {v2!r})", file=sys.stderr)
                sys.exit(1)
            if isinstance(v1, dict):
                k1 = set(v1.keys())
                k2 = set(v2.keys())
                if k1 != k2:
                    print(f"Key mismatch at {path}: {k1 ^ k2}", file=sys.stderr)
                    sys.exit(1)
                for k in sorted(k1):
                    assert_strict_equal(v1[k], v2[k], f"{path}.{k}")
            elif isinstance(v1, list):
                if len(v1) != len(v2):
                    print(f"Length mismatch at {path}: {len(v1)} vs {len(v2)}", file=sys.stderr)
                    sys.exit(1)
                for idx, (elem1, elem2) in enumerate(zip(v1, v2)):
                    assert_strict_equal(elem1, elem2, f"{path}[{idx}]")
            else:
                if v1 != v2:
                    print(f"Value mismatch at {path}: {v1!r} vs {v2!r}", file=sys.stderr)
                    sys.exit(1)

        with open("${fixturePlist}", "rb") as f1, open("${renderedPlist}", "rb") as f2:
            d1 = plistlib.load(f1)
            d2 = plistlib.load(f2)

        # 1. Non-extension keys match fixture strictly
        non_ext_keys = [k for k in d1.keys() if k != "ExtensionSettings"]
        for k in non_ext_keys:
            assert_strict_equal(d1[k], d2[k], f"root.{k}")

        # 1b. BUX5C0: the only rendered key beyond the legacy fixture is the password authority
        added = set(d2) - set(d1)
        if added != {"PasswordManagerEnabled"} or d2["PasswordManagerEnabled"] is not False:
            print(f"Unexpected Chrome policy delta: {sorted(added)}", file=sys.stderr)
            sys.exit(1)

        # 2. ExtensionSettings renders modernized force_installed modes
        ext_settings = d2["ExtensionSettings"]
        assert ext_settings["*"] == {"installation_mode": "allowed"}
        expected_chrome_ids = [
            "ckkdlimhmcjmikdlpkmbgfkaikojcbjk",
            "ddkjiahejlhfcafbddmgiahcphecmpfh",
            "efaidnbmnnnibpcajpcglclefindmkaj",
            "efknglbfhoddmmfabeihlemgekhhnabb",
            "felphkbfjadmcejnibcmcncimlappdde",
            "hlkenndednhfkekhgcdicdfddnkalmdm",
            "hoombieeljmmljlkjmnheibnpciblicm",
            "lmjnegcaeklhafolokijcfjliaokphfk",
            "oboonakemofpalcgghocfoadofidjkkk",
        ]
        assert sorted([k for k in ext_settings.keys() if k != "*"]) == sorted(expected_chrome_ids)
        for ext_id in expected_chrome_ids:
            assert ext_settings[ext_id] == {
                "installation_mode": "force_installed",
                "update_url": "https://clients2.google.com/service/update2/crx"
            }

        print("Chrome plist AST semantic and strict-type equality verified!")
        '
        touch "$out"
      '';

  firefox-plist-ast-parity-contract =
    let
      firefoxPrefs =
        { EnterprisePoliciesEnabled = true; } // declared.programs.browserBaseline.firefox.policies;
      renderedPlist = pkgs.writeText "rendered-firefox-policy.plist" (
        lib.generators.toPlist { escape = true; } firefoxPrefs
      );
      rawJsonFile = ../config/browser/firefox-policies.json;
    in
    pkgs.runCommandLocal "browser-ux-dinas-firefox-plist-ast-parity-contract"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        python3 -c '
        import json, plistlib, sys

        def assert_strict_equal(v1, v2, path="root"):
            if type(v1) is not type(v2):
                print(f"Type mismatch at {path}: {type(v1).__name__} vs {type(v2).__name__} ({v1!r} vs {v2!r})", file=sys.stderr)
                sys.exit(1)
            if isinstance(v1, dict):
                k1 = set(v1.keys())
                k2 = set(v2.keys())
                if k1 != k2:
                    print(f"Key mismatch at {path}: {k1 ^ k2}", file=sys.stderr)
                    sys.exit(1)
                for k in sorted(k1):
                    assert_strict_equal(v1[k], v2[k], f"{path}.{k}")
            elif isinstance(v1, list):
                if len(v1) != len(v2):
                    print(f"Length mismatch at {path}: {len(v1)} vs {len(v2)}", file=sys.stderr)
                    sys.exit(1)
                for idx, (elem1, elem2) in enumerate(zip(v1, v2)):
                    assert_strict_equal(elem1, elem2, f"{path}[{idx}]")
            else:
                if v1 != v2:
                    print(f"Value mismatch at {path}: {v1!r} vs {v2!r}", file=sys.stderr)
                    sys.exit(1)

        with open("${renderedPlist}", "rb") as fp:
            rendered = plistlib.load(fp)

        with open("${rawJsonFile}", "r", encoding="utf-8") as fj:
            expected_json = json.load(fj)

        expected_policies = expected_json["policies"]

        if rendered.get("EnterprisePoliciesEnabled") is not True:
            print("EnterprisePoliciesEnabled is not True in rendered plist", file=sys.stderr)
            sys.exit(1)

        rendered_without_reserved = {k: v for k, v in rendered.items() if k != "EnterprisePoliciesEnabled"}

        # 1. Non-extension keys match expected_policies strictly
        non_ext_keys = [k for k in expected_policies.keys() if k != "ExtensionSettings"]
        for k in non_ext_keys:
            assert_strict_equal(rendered_without_reserved[k], expected_policies[k], f"policies.{k}")

        # 1b. BUX5C0: only the password authority and full-screen preference are added
        added = set(rendered_without_reserved) - set(expected_policies)
        expected_preferences = {"browser.fullscreen.autohide": {"Status": "locked", "Value": True}}
        if (added != {"PasswordManagerEnabled", "Preferences"}
                or rendered_without_reserved["PasswordManagerEnabled"] is not False
                or rendered_without_reserved["Preferences"] != expected_preferences
                or rendered_without_reserved["Preferences"]["browser.fullscreen.autohide"]["Value"] is not True):
            print(f"Unexpected Firefox policy delta: {sorted(added)}", file=sys.stderr)
            sys.exit(1)

        # 2. ExtensionSettings renders modernized force_installed modes
        ext_settings = rendered_without_reserved["ExtensionSettings"]
        assert ext_settings["*"] == {"installation_mode": "allowed"}
        expected_ff_ids = [
            "clear-new-tab@loftyshaky",
            "keepassxc-browser@keepassxc.org",
            "markdown-viewer@outofindex.com",
            "uBlock0@raymondhill.net",
            "{b9db16a4-6edc-47ec-a1f4-b86292ed211d}",
            "{c3c10168-4186-445c-9c5b-63f12b8e2c87}",
        ]
        assert sorted([k for k in ext_settings.keys() if k != "*"]) == sorted(expected_ff_ids)
        for ext_id in expected_ff_ids:
            expected_install_url = expected_policies["ExtensionSettings"][ext_id]["install_url"]
            assert ext_settings[ext_id] == {
                "installation_mode": "force_installed",
                "install_url": expected_install_url
            }

        print("Firefox plist AST semantic and strict-type equality verified!")
        '
        touch "$out"
      '';

  browser-operator-preferences-contract =
    let
      chromeOf = c: c.programs.browserBaseline.chrome.managedPreferences;
      firefoxOf = c: c.programs.browserBaseline.firefox.policies;
      enabledConfigs = [ declared configured shippedInjected ];
      disabledConfigs = [ explicitFalseConfig chromeOptOutConfig firefoxOptOutConfig optOutConfig ];
      allConfigs = enabledConfigs ++ disabledConfigs;
      sorted = lib.sort builtins.lessThan;
      allKeys =
        v:
        if builtins.isAttrs v then
          lib.concatMap (k: [ k ] ++ allKeys v.${k}) (builtins.attrNames v)
        else if builtins.isList v then
          lib.concatMap allKeys v
        else
          [ ];
      expectedFirefoxPolicyKeys = sorted (
        expectedFirefoxNonExtensionKeys ++ [ "ExtensionSettings" "PasswordManagerEnabled" "Preferences" ]
      );
      expectedFirefoxPreferences = {
        "browser.fullscreen.autohide" = {
          Value = true;
          Status = "locked";
        };
      };
      chromeWebStore = "https://clients2.google.com/service/update2/crx";
      fullUBlockChromeId = "cjpalhdlnbpafiamejdnhcphjbkeiagm";
      scrollbarGeckoId = "scrollbar-visibility@browser-ux";
    in
    # C. Password authority: built-in managers off exactly while KeePassXC is the authority
    assert lib.all (c: (chromeOf c).PasswordManagerEnabled == false && builtins.isBool (chromeOf c).PasswordManagerEnabled) enabledConfigs;
    assert lib.all (c: (firefoxOf c).PasswordManagerEnabled == false && builtins.isBool (firefoxOf c).PasswordManagerEnabled) enabledConfigs;
    assert lib.all (c: !((chromeOf c) ? PasswordManagerEnabled)) disabledConfigs;
    assert lib.all (c: !((firefoxOf c) ? PasswordManagerEnabled)) disabledConfigs;
    assert lib.all (c: sorted (builtins.attrNames (chromeOf c)) == expectedChromePolicyKeys) enabledConfigs;
    assert lib.all (c: sorted (builtins.attrNames (chromeOf c)) == lib.remove "PasswordManagerEnabled" expectedChromePolicyKeys) disabledConfigs;
    assert lib.all (c: sorted (builtins.attrNames (firefoxOf c)) == expectedFirefoxPolicyKeys) enabledConfigs;
    assert lib.all (c: sorted (builtins.attrNames (firefoxOf c)) == lib.remove "PasswordManagerEnabled" expectedFirefoxPolicyKeys) disabledConfigs;
    assert lib.all (c: (chromeOf c).ExtensionSettings.${expectedChromeKeePassXCId} == {
      installation_mode = "force_installed";
      update_url = chromeWebStore;
    }) enabledConfigs;
    assert lib.all (c: (firefoxOf c).ExtensionSettings.${expectedFirefoxKeePassXCId} == {
      installation_mode = "force_installed";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/keepassxc-browser/latest.xpi";
    }) enabledConfigs;
    assert lib.all (c: builtins.attrNames c.programs.browserBaseline.chrome.nativeMessagingHosts == [ "org.keepassxc.keepassxc_browser" ]) enabledConfigs;
    assert lib.all (c: builtins.attrNames c.programs.browserBaseline.firefox.nativeMessagingHosts == [ "org.keepassxc.keepassxc_browser" ]) enabledConfigs;
    # Address/payment autofill is not broadened: Chrome gains no Autofill* key, Firefox keeps its values
    assert lib.all (c: builtins.filter (lib.hasPrefix "Autofill") (builtins.attrNames (chromeOf c)) == [ ]) allConfigs;
    assert lib.all (c:
      (firefoxOf c).AutofillAddressEnabled == false
      && (firefoxOf c).AutofillCreditCardEnabled == false
      && (firefoxOf c).OfferToSaveLoginsDefault == false
    ) allConfigs;

    # B. Full screen: Firefox toolbar autohide is locked on; nothing kiosk-like is rendered
    assert lib.all (c: (firefoxOf c).Preferences == expectedFirefoxPreferences) allConfigs;
    assert lib.all (c: builtins.isBool (firefoxOf c).Preferences."browser.fullscreen.autohide".Value) allConfigs;
    assert lib.all (c:
      !(lib.any (k: lib.hasInfix "kiosk" (lib.toLower k)) (allKeys (chromeOf c) ++ allKeys (firefoxOf c)))
    ) allConfigs;
    assert lib.all (c: !(lib.any (k: lib.hasPrefix "full-screen-api." k || lib.hasInfix "userChrome" k
      || lib.hasInfix "legacyUserProfileCustomizations" k) (allKeys (firefoxOf c)))) allConfigs;

    # D. uBlock family split stays exact; no obsolete full-uBO Chrome install, no managed list settings
    assert lib.all (c: (chromeOf c).ExtensionSettings.ddkjiahejlhfcafbddmgiahcphecmpfh == {
      installation_mode = "force_installed";
      update_url = chromeWebStore;
    }) allConfigs;
    assert lib.all (c: (firefoxOf c).ExtensionSettings."uBlock0@raymondhill.net" == {
      installation_mode = "force_installed";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi";
    }) allConfigs;
    assert lib.all (c:
      !((chromeOf c).ExtensionSettings ? ${fullUBlockChromeId})
      && !(lib.any (lib.hasPrefix fullUBlockChromeId) (chromeOf c).ExtensionInstallForcelist)
    ) allConfigs;
    assert lib.all (c: !(builtins.elem "3rdparty" (allKeys (firefoxOf c)))) allConfigs;
    assert lib.all (c: lib.all (id: lib.subtractLists [ "installation_mode" "update_url" ]
      (builtins.attrNames (chromeOf c).ExtensionSettings.${id}) == [ ])
      (builtins.attrNames (chromeOf c).ExtensionSettings)) allConfigs;
    assert lib.all (c: lib.all (id: lib.subtractLists [ "installation_mode" "install_url" ]
      (builtins.attrNames (firefoxOf c).ExtensionSettings.${id}) == [ ])
      (builtins.attrNames (firefoxOf c).ExtensionSettings)) allConfigs;

    # A. The prepared scrollbar extension is not registered: distribution is blocked
    assert lib.all (c: !((firefoxOf c).ExtensionSettings ? ${scrollbarGeckoId})) allConfigs;
    assert lib.all (c: builtins.length (builtins.attrNames (chromeOf c).ExtensionSettings) == 10) allConfigs;
    assert lib.all (c: builtins.length (builtins.attrNames (firefoxOf c).ExtensionSettings) == 7) allConfigs;

    # Regression anchors: tracking protection, HTTPS-only, DNS-over-HTTPS choice
    assert lib.all (c:
      (firefoxOf c).EnableTrackingProtection.Category == "strict"
      && (firefoxOf c).HttpsOnlyMode == "enabled"
      && (firefoxOf c).DNSOverHTTPS == { Enabled = false; Locked = false; }
      && (chromeOf c).HttpsOnlyMode == "force_balanced_enabled"
      && (chromeOf c).DnsOverHttpsMode == "off"
    ) allConfigs;
    assert lib.all (c: c.programs.browserBaseline.firefox.policyDelivery == "macos-preferences") allConfigs;
    pkgs.runCommandLocal "browser-ux-dinas-browser-operator-preferences-contract" { } ''
      touch "$out"
    '';

  browser-preferences-tests = pkgs.runCommand "browser-ux-browser-preferences-tests" {
    nativeBuildInputs = [ pkgs.python3Packages.pytest pkgs.nodejs ];
  } ''
    export HOME="$TMPDIR/home" PYTHONDONTWRITEBYTECODE=1
    mkdir -p "$HOME"
    pytest --import-mode=importlib -q -p no:cacheprovider -o python_files='*.test.py' \
      ${../.}/tests/browser-preferences.test.py ${../.}/tests/scrollbar-gui-kit.test.py \
      ${../.}/tests/scrollbar-gui-runtime.test.py ${../.}/tests/scrollbar-gui-observer.test.py \
      ${../.}/tests/scrollbar-rail.test.py
    touch "$out"
  '';

  json-payload-parity-contract =
    let
      cntJsonFile = ../config/browser/chrome-clear-new-tab-external-extension.json;
      ffJsonFile = ../config/browser/firefox-policies.json;
      kChromeJsonFile = ../config/browser/keepassxc-chrome-native-messaging.json;
      kFfJsonFile = ../config/browser/keepassxc-firefox-native-messaging.json;
    in
    pkgs.runCommandLocal "browser-ux-dinas-json-payload-parity-contract"
      {
        nativeBuildInputs = [ pkgs.coreutils ];
      }
      ''
        check_hash() {
          local file="$1"
          local expected="$2"
          local actual
          actual=$(sha256sum "$file" | cut -d" " -f1)
          if [ "$actual" != "$expected" ]; then
            echo "Hash mismatch for $file: expected $expected, got $actual" >&2
            exit 1
          fi
        }
        check_hash "${cntJsonFile}" "5bcd92f712b450ecb20eb390f957216d488e5dc0c4abbb2cbf4dd6b570b11edc"
        check_hash "${ffJsonFile}" "575427106192c45e17c2b6766f1b88cfbf6b70372d5e481990035ad31c6eb9b7"
        check_hash "${kChromeJsonFile}" "caeb4e3cb79acacbce541a44bd8845cab31986dbb41ef9108b1bc38dc60ce1fc"
        check_hash "${kFfJsonFile}" "71644e9a2a157449b44ea929fce6443ed97a0f3a63309075f136942cbfe0185e"
        touch "$out"
      '';

  claims-contract =
    assert builtins.isList applicationClaims;
    assert applicationClaims == (import ./dormant-contracts.nix { inherit lib pkgs; }).expectedClaims;
    assert lib.all (key:
      builtins.length (lib.unique (map (claim: claim.${key}) applicationClaims)) == builtins.length applicationClaims
    ) [ "id" "artifact" "package" ];
    assert lib.all (claim: builtins.attrNames claim == [ "artifact" "id" "package" "provider" ])
      applicationClaims;
    pkgs.runCommandLocal "browser-ux-dinas-claims-contract" { } ''
      touch "$out"
    '';

  package-set-contract =
    assert packageSetIdentity == {
      schema = "nix-darwin-package-set-v1";
      revision = nixpkgs.rev;
      outPath = builtins.toString nixpkgs.outPath;
    };
    assert nix-darwin.inputs.nixpkgs.rev == nixpkgs.rev;
    assert builtins.toString nix-darwin.inputs.nixpkgs.outPath == builtins.toString nixpkgs.outPath;
    pkgs.runCommandLocal "browser-ux-dinas-package-set-contract" { } ''
      touch "$out"
    '';

  config-contract =
    assert configAllowlist == {
      "browser-ux.toml" = [
        "browser-ux.schema"
        "browser-ux.keepassxc"
        "browser-ux.extensions"
        "browser-ux.replacements"
        "browser-ux.primaryCutover"
      ];
    };
    assert shippedConfig.browser-ux.schema == 1;
    assert shippedConfig.browser-ux.keepassxc.enable == true;
    assert shippedConfig.browser-ux.extensions."default-on-opt-out" == [ ];
    assert builtins.isInt shippedConfig.browser-ux.schema;
    assert builtins.isAttrs shippedConfig.browser-ux.keepassxc;
    assert builtins.isBool shippedConfig.browser-ux.keepassxc.enable;
    assert builtins.isAttrs shippedConfig.browser-ux.extensions;
    assert builtins.isList shippedConfig.browser-ux.extensions."default-on-opt-out";
    assert (builtins.attrNames shippedConfig) == [ "browser-ux" ];
    assert (lib.sort builtins.lessThan (builtins.attrNames shippedConfig.browser-ux)) == [
      "extensions"
      "keepassxc"
      "replacements"
      "schema"
    ];
    assert (builtins.attrNames shippedConfig.browser-ux.keepassxc) == [ "enable" ];
    assert (builtins.attrNames shippedConfig.browser-ux.extensions) == [ "apple-proton-trial" "default-on-opt-out" ];
    assert builtins.attrNames shippedConfig.browser-ux.replacements == [ "floorp" "vivaldi" ];
    assert shippedConfig.browser-ux.replacements.vivaldi == { enable = false; inherit-from = "chrome"; mail = { enable = false; preserve-resolved = false; }; };
    assert shippedConfig.browser-ux.replacements.floorp == { enable = false; inherit-from = "firefox"; };
    pkgs.runCommandLocal "browser-ux-dinas-config-contract" { } ''
      touch "$out"
    '';

  release-candidate-contract =
    assert releaseCandidate.schema == "browser-ux-release-candidate-v1";
    assert releaseCandidate.intendedChannel == "refs/heads/deploy";
    assert releaseCandidate.hostGeneration.systemPackages == [ ];
    assert releaseCandidate.hostGeneration.homebrewCasks == [ ];
    assert releaseCandidate.hostGeneration.activationScripts == [ ];
    assert releaseCandidate.hostGeneration.launchdDefinitions == [ ];
    assert lib.any (text: lib.hasInfix "mechanically held in core" text) releaseCandidate.deployPreconditions;
    assert lib.any (text: lib.hasInfix "Vivaldi remains installed and unchanged" text) releaseCandidate.deployPreconditions;
    assert lib.any (text: lib.hasInfix "Apple Passwords password/TOTP/passkey" text) releaseCandidate.deployPreconditions;
    assert lib.any (text: lib.hasInfix "no convenience or credential extensions" text) releaseCandidate.deployPreconditions;
    assert lib.any (text: lib.hasInfix "Real composed graph" text) releaseCandidate.qualificationNotes;
    assert (map (op: op.id) releaseCandidate.operatorOnlyOperations) == [
      "clear-new-tab-profile-mutation"
      "clear-new-tab-playwright-import"
      "shared-images-content-mutation"
      "shared-images-rclone-push-pull"
    ];
    assert lib.all (op: op.authorizedByRecord == false) releaseCandidate.operatorOnlyOperations;
    # Ensure module activation scripts and launchd surfaces do not invoke or reference any operator-only operation
    assert lib.all (
      op: lib.all (surface: !lib.hasInfix op.id surface) (allHostScriptSurfaces declared)
    ) releaseCandidate.operatorOnlyOperations;
    assert lib.all (
      op: lib.all (surface: !lib.hasInfix op.id surface) (allHostScriptSurfaces configured)
    ) releaseCandidate.operatorOnlyOperations;
    pkgs.runCommandLocal "browser-ux-dinas-release-candidate-contract" { } ''
      touch "$out"
    '';

  public-source-boundary-contract =
    # Evaluation-time positive and negative controls for the structural boundary verifier
    assert !(hasPublicBoundaryViolation "synthetic fixture /Users/browser-probe and /Users/Shared/agent-scratch/work and bundle:ai.knowledge-forge.dinas.brave-youtube and github:Knowledge-Forge-AI/browser-ux_dinas");
    assert hasPublicBoundaryViolation "operator home path /Users/example-operator/project";
    assert hasPublicBoundaryViolation "prefix collision /Users/operator-real/project";
    assert hasPublicBoundaryViolation "unallowlisted shared path /Users/Shared/other";
    assert hasPublicBoundaryViolation "bare shared path /Users/Shared";
    assert hasPublicBoundaryViolation "linux home path /home/alice/work";
    assert hasPublicBoundaryViolation "host label AliceS-MacBook-Pro in config";
    assert hasPublicBoundaryViolation "unapproved github owner github:example-personal/private-repo";
    assert hasPublicBoundaryViolation "personal claim bundle:com.example-owner.brave-youtube";
    assert hasPublicBoundaryViolation "private worktree ~/.local/nix-private/work";
    # Prohibit private boundary violations across the bounded scan set:
    # the 9 dormant-source-sha256.json keys, flake.nix, modules/default.nix,
    # serialized releaseCandidate JSON, tests/seam-fixture.nix, chrome/firefox
    # policy defaults, extension-policy.nix, the 16 replacementSources, the 4
    # config/browser/*.json payloads, and the 25 operatorPreferenceSources
    # (not every public document or test file in the repository).
    assert lib.all (path:
      !(hasPublicBoundaryViolation (builtins.readFile (../. + "/${path}")))
    ) (builtins.attrNames (builtins.fromJSON
      (builtins.readFile ./fixtures/dormant-source-sha256.json)));
    assert !(hasPublicBoundaryViolation flakeSource);
    assert !(hasPublicBoundaryViolation defaultModuleSource);
    assert !(hasPublicBoundaryViolation candidateJson);
    assert !(hasPublicBoundaryViolation seamFixtureSource);
    assert !(hasPublicBoundaryViolation chromeDefaultsSource);
    assert !(hasPublicBoundaryViolation firefoxDefaultsSource);
    assert !(hasPublicBoundaryViolation extensionPolicySource);
    assert lib.all (path:
      !(hasPublicBoundaryViolation (builtins.readFile (../. + "/${path}")))
    ) replacementSources;
    assert !(hasPublicBoundaryViolation cntJsonSource);
    assert !(hasPublicBoundaryViolation firefoxPoliciesSource);
    assert !(hasPublicBoundaryViolation chromeNmhSource);
    assert !(hasPublicBoundaryViolation firefoxNmhSource);
    assert lib.all (path:
      !(hasPublicBoundaryViolation (builtins.readFile (../. + "/${path}")))
    ) operatorPreferenceSources;
    pkgs.runCommandLocal "browser-ux-dinas-public-source-boundary-contract" { } ''
      touch "$out"
    '';

  anchor-removal-contract =
    assert !(builtins.pathExists ../.dispatcher-bootstrap-anchor);
    pkgs.runCommandLocal "browser-ux-dinas-anchor-removal-contract" { } ''
      touch "$out"
    '';
} // (import ./dormant-contracts.nix { inherit lib pkgs; }).checks {
  inherit applicationClaims;
  defaultActivation = lib.concatStringsSep "\n" (activationScriptTexts declared);
} // (import ./replacement-contracts.nix { inherit lib pkgs; })
