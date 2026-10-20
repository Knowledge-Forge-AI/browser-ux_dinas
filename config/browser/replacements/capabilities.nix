# Closed runtime-capability and SYSTEM1 contracts, independent of policy rendering.
let
  vivaldiMeta = import ./vivaldi.nix;
  floorpMeta = import ./floorp.nix;
  metaFor = browser: if browser == "vivaldi" then vivaldiMeta else floorpMeta;
  # Validate only the requested browser's issue list. A malformed Vivaldi issue
  # cannot couple Floorp qualification to Vivaldi; disabled renders stay lazy.
  exactFields = value: names: builtins.isAttrs value
    && builtins.attrNames value == builtins.sort builtins.lessThan names;
  nonempty = value: builtins.isString value && value != "";
  natural = value: builtins.isInt value && value >= 0;
  publicText = value:
    builtins.all (token: builtins.match ".*${token}.*" (builtins.toJSON value) == null)
      [ "@" "/Users/" "/private/" ];
  commonIssueFields = [
    "blocks"
    "capability"
    "doesNotBlock"
    "evidenceRetention"
    "feature"
    "id"
    "interpretation"
    "replacementBrowser"
    "scope"
    "signature"
    "sourceBrowser"
    "sourceRelationship"
    "status"
    "trigger"
  ];
  mailExtraFields = [
    "configurationSupport"
    "evidencePreservation"
    "forensics"
    "livePosture"
    "operatorStrategies"
    "prohibitedRemediations"
    "systemTest"
  ];
  genericSignatureFields = [
    "absoluteAddressStable"
    "architecture"
    "breakpointSubcode"
    "dumpCount"
    "exceptionName"
    "exceptionType"
    "module"
    "moduleRelativeOffsetDecimal"
    "moduleRelativeOffsetHex"
    "operatingSystem"
    "process"
    "product"
    "symbolicated"
    "version"
    "windowLocal"
  ];
  mailSignatureFields = genericSignatureFields ++ [
    "failureClass"
    "rendererHeapBeforeFailure"
  ];
  validateForensics = f:
    exactFields f [ "classification" "scope" "limitation" "thresholdClaimed"
      "configuredAccounts" "highVolumeAccount" "prefetchSemantics" "matrix" ]
    && f.classification == "NECESSARY_AND_SUFFICIENT" && f.thresholdClaimed == false
    && natural f.configuredAccounts
    && builtins.all (field: nonempty f.${field}) [ "scope" "limitation" "prefetchSemantics" ]
    && exactFields f.highVolumeAccount [ "label" "preFetch" "logicalHeaderMemberships"
      "olderThanOneYear" "olderThanOneYearPercent" "indexedDateRangeBegins"
      "fullServerHistoryBackTo2004Downloaded" "cachedBodies" "cachedBodiesOlderThanOneYear" ]
    && builtins.match "A[0-9]+" f.highVolumeAccount.label != null
    && builtins.all (field: natural f.highVolumeAccount.${field}) [ "logicalHeaderMemberships"
      "olderThanOneYear" "cachedBodies" "cachedBodiesOlderThanOneYear" ]
    && builtins.all (field: nonempty f.highVolumeAccount.${field}) [ "preFetch"
      "olderThanOneYearPercent" "indexedDateRangeBegins" ]
    && f.highVolumeAccount.fullServerHistoryBackTo2004Downloaded == "UNPROVEN"
    && builtins.isList f.matrix && builtins.length f.matrix == 4
    && (let rows = f.matrix; control = builtins.elemAt rows 0; isolated = builtins.elemAt rows 1;
            bodies = builtins.elemAt rows 2; configOnly = builtins.elemAt rows 3; in
      exactFields control [ "case" "configuredAccounts" "indexedRecords" "offlineSeconds"
        "outcome" "peakRendererRssKiB" "peakV8GcUsedMB" ]
      && control.case == "all-except-A4" && control.outcome == "STABLE_NO_V8_OOM"
      && builtins.all (field: natural control.${field}) [ "configuredAccounts" "indexedRecords" "peakRendererRssKiB" ]
      && nonempty control.offlineSeconds && nonempty control.peakV8GcUsedMB
      && exactFields isolated [ "case" "indexedRecords" "secondsToOom" "outcome"
        "peakRendererRssKiB" "peakV8GcUsedMB" ]
      && isolated.case == "A4-only" && isolated.outcome == "V8_OOM"
      && natural isolated.indexedRecords && natural isolated.peakRendererRssKiB
      && nonempty isolated.secondsToOom && nonempty isolated.peakV8GcUsedMB
      && exactFields bodies [ "case" "indexedRecords" "secondsToOom" "outcome"
        "cachedBodiesRemaining" "indexedMetadataUnchanged" "conclusion" ]
      && bodies.case == "A4-only-cached-bodies-removed" && bodies.outcome == "V8_OOM"
      && natural bodies.indexedRecords && bodies.cachedBodiesRemaining == 0
      && bodies.indexedMetadataUnchanged == true && nonempty bodies.secondsToOom && nonempty bodies.conclusion
      && exactFields configOnly [ "case" "outcome" "indexedMetadataRetained"
        "accountConfigurationPresent" "conclusion" ]
      && configOnly.case == "A4-configuration-removed-metadata-retained" && configOnly.outcome == "V8_OOM"
      && configOnly.indexedMetadataRetained == true && configOnly.accountConfigurationPresent == false
      && nonempty configOnly.conclusion);
  validateMailExtras = issue:
    validateForensics issue.forensics
    && exactFields issue.evidencePreservation [ "status" "authority" "privateMaterialInSource" ]
    && issue.evidencePreservation.status == "COMPLETED_HOST_FORENSICS"
    && nonempty issue.evidencePreservation.authority && issue.evidencePreservation.privateMaterialInSource == false
    && exactFields issue.livePosture [ "mailFeature" "preference" "appliedBy" "browserUxWrites"
      "cleanLaunchExitCycles" "mailAccountDefinitionsRetained" "reenable" "permanentMailRejection"
      "observationScope" "currentHostResolution" ]
    && issue.livePosture.observationScope == "HISTORICAL_INCIDENT_POSTURE_SUPERSEDED_FOR_CURRENT_HOST"
    && issue.livePosture.currentHostResolution == "mail-resolution.json"
    && issue.livePosture.mailFeature == "DISABLED"
    && issue.livePosture.preference == "vivaldi.features.mail = false"
    && issue.livePosture.appliedBy == "operator-incident-response" && issue.livePosture.browserUxWrites == false
    && natural issue.livePosture.cleanLaunchExitCycles && natural issue.livePosture.mailAccountDefinitionsRetained
    && issue.livePosture.reenable == "SEPARATE_QUALIFIED_OPERATOR_ACTION"
    && issue.livePosture.permanentMailRejection == false
    && builtins.isList issue.operatorStrategies && map (strategy: strategy.id) issue.operatorStrategies == [
      "browser-core-mail-disabled" "mail-smaller-accounts-only" "separate-reduced-mail-profile"
      "revisit-after-vendor-fix" "bounded-reduced-corpus-experiment" ]
    && builtins.all (strategy: exactFields strategy [ "id" "description" "appliedByBrowserUx" ]
      && nonempty strategy.description && strategy.appliedByBrowserUx == false) issue.operatorStrategies
    && exactFields issue.configurationSupport [ "status" "url" ]
    && issue.configurationSupport.status == "VENDOR_DOCUMENTED"
    && nonempty issue.configurationSupport.url
    && builtins.match "https://help[.]vivaldi[.]com/.*" issue.configurationSupport.url != null
    && issue.prohibitedRemediations == [ "mail-database-copy" "mail-database-modification"
      "mail-database-deletion" "application-removal" "crash-or-profile-evidence-deletion"
      "live-mail-reenable-without-qualification" ]
    && exactFields issue.systemTest [ "lane" "automatedBaseline" "multipleAccounts" "disposableProfile"
      "realProtonCredentials" "managedPolicyCharacterization" "realProtonBridge" "tartImageCredentials" "suite" ]
    && issue.systemTest == {
      lane = "SYSTEM1"; automatedBaseline = "synthetic-local-tls-imap-smtp";
      multipleAccounts = true; disposableProfile = true; realProtonCredentials = false;
      managedPolicyCharacterization = "off-host-tart-only";
      realProtonBridge = "credentialed-manual-separate-safe-test-account-approval";
      tartImageCredentials = "FORBIDDEN";
      suite = "vivaldi-mail";
    };
  validateSignature = isMail: sig:
    builtins.isAttrs sig
    && exactFields sig (if isMail then mailSignatureFields else genericSignatureFields)
    && builtins.all (field: nonempty sig.${field}) [ "product" "version" "process"
      "operatingSystem" "exceptionName" "module" "windowLocal" ]
    && builtins.elem sig.architecture [ "arm64" "x86_64" ]
    && nonempty sig.moduleRelativeOffsetHex
    && builtins.match "0x[0-9a-fA-F]+" sig.moduleRelativeOffsetHex != null
    && builtins.all (field: builtins.isInt sig.${field} && sig.${field} >= 0)
      [ "exceptionType" "breakpointSubcode" "moduleRelativeOffsetDecimal" "dumpCount" ]
    && sig.dumpCount > 0
    && builtins.isBool sig.absoluteAddressStable && builtins.isBool sig.symbolicated
    && (!isMail || (sig.failureClass == "V8_JAVASCRIPT_OOM" && nonempty sig.rendererHeapBeforeFailure));
  validateRuntimeIssues = browser: document:
    let
      source = if browser == "vivaldi" then "chrome" else "firefox";
      validIssue = issue:
        let
          isMail = (issue.capability or "") == "vivaldi-mail";
          expectedFields = (if isMail then commonIssueFields ++ mailExtraFields else commonIssueFields)
            ++ (if (issue.status or "") == "CLEARED" then [ "clearance" ] else [ ]);
        in
        builtins.isAttrs issue
        && exactFields issue expectedFields
        && builtins.all (field: nonempty issue.${field}) [ "id" "feature"
          "sourceRelationship" "trigger" "interpretation" "evidenceRetention" ]
        && builtins.match "[A-Z][A-Z0-9_]+" issue.id != null
        && issue.replacementBrowser == browser && issue.sourceBrowser == source
        && builtins.elem issue.status [ "HOLD_RUNTIME_OOM" "HOLD_RUNTIME_CRASH" "CLEARED" ]
        && publicText issue
        && builtins.elem issue.capability
          ([ (metaFor browser).coreCapability ] ++ map (overlay: overlay.capability)
            (builtins.attrValues (metaFor browser).featureOverlays))
        && (if isMail then
          browser == "vivaldi" && issue.feature == "mail" && issue.scope == "optional_overlay"
        else
          issue.feature != "mail" && issue.capability != "vivaldi-mail")
        && builtins.isList issue.blocks && builtins.isList issue.doesNotBlock
        && builtins.all nonempty (issue.blocks ++ issue.doesNotBlock)
        && !builtins.any (capability: builtins.elem capability issue.doesNotBlock) issue.blocks
        && (if issue.scope == "optional_overlay" then
          issue.capability != (metaFor browser).coreCapability && issue.blocks == [ issue.capability ]
          && builtins.elem (metaFor browser).coreCapability issue.doesNotBlock
          && builtins.elem "${source}-replacement-parity" issue.doesNotBlock
        else issue.scope == "browser_core" && issue.capability == (metaFor browser).coreCapability
          && builtins.elem (metaFor browser).coreCapability issue.blocks)
        && (issue.status != "CLEARED" || (exactFields issue.clearance [ "reviewedIn" "evidence" "clearedOn" ]
          && builtins.all (field: nonempty issue.clearance.${field}) [ "reviewedIn" "evidence" "clearedOn" ]))
        && validateSignature isMail issue.signature
        && (!isMail || validateMailExtras issue);
      issues = document.issues.${browser};
      ids = map (issue: issue.id) issues;
      unique = builtins.foldl' (acc: id: if builtins.elem id acc then acc else acc ++ [ id ]) [ ] ids;
    in
    if !(builtins.elem browser [ "vivaldi" "floorp" ])
      || !(exactFields document [ "schema" "issues" ])
      || document.schema != "browser-ux-replacement-runtime-issues-v2"
      || !(exactFields document.issues [ "vivaldi" "floorp" ])
      || !(builtins.isList issues) || !(builtins.all validIssue issues)
      || builtins.length ids != builtins.length unique then
      throw "Replacement runtime issues violate the closed per-browser schema"
    else true;

  holdsFor = browser: capability: document:
    builtins.seq (validateRuntimeIssues browser document)
      (map (issue: issue.id) (builtins.filter (issue: issue.status != "CLEARED"
        && builtins.elem capability issue.blocks) document.issues.${browser}));

  coreHoldsFor = browser: overlays: document:
    let
      capabilities = [ (metaFor browser).coreCapability ]
        ++ map (overlay: overlay.capability) (builtins.filter (overlay: overlay.requiredForReplacement)
          (builtins.attrValues overlays));
    in builtins.seq (validateRuntimeIssues browser document)
      (map (issue: issue.id) (builtins.filter (issue: issue.status != "CLEARED"
        && builtins.any (capability: builtins.elem capability issue.blocks) capabilities) document.issues.${browser}));

  # Existing consumers read core holds. Optional overlays have their own holds.
  runtimeHoldsFor = browser: coreHoldsFor browser (metaFor browser).featureOverlays;

  mailResolution = builtins.fromJSON (builtins.readFile ./mail-resolution.json);

  validateMailRequest = browser: { replacementEnabled ? true, mailEnabled ? false, currentHostResolved ? false, preserveResolved ? false }: document:
    let
      resolved = currentHostResolved;
    in
    if !builtins.isBool mailEnabled || !builtins.isBool replacementEnabled
      || !builtins.isBool currentHostResolved || !builtins.isBool preserveResolved then
      throw "Mail enablement requires boolean flags"
    else if !mailEnabled then true
    else if browser != "vivaldi" then throw "Mail is a Vivaldi-only optional overlay"
    else if !replacementEnabled then throw "Mail request requires the Vivaldi replacement candidate"
    else if !resolved && holdsFor browser "vivaldi-mail" document != [ ] then
      throw "Vivaldi Mail is held; enabling requires reviewed runtime-issue clearance and separate Mail qualification"
    else true;

  mailOverlayFor = args: document:
    let
      isAttrs = builtins.isAttrs args;
      requested = if isAttrs then args.requested or (args.mailEnabled or false) else args;
      resolved = if isAttrs then args.currentHostResolved or false else false;
      runtimeHolds = holdsFor "vivaldi" "vivaldi-mail" document;
      active = builtins.filter (issue: builtins.elem issue.id runtimeHolds) document.issues.vivaldi;
      baseOverlay = vivaldiMeta.featureOverlays.mail;
    in builtins.seq (validateMailRequest "vivaldi" { mailEnabled = requested; currentHostResolved = resolved; } document)
      (baseOverlay // {
        inherit requested runtimeHolds;
        currentHostResolved = resolved;
        status =
          if resolved && requested then "OPERATOR_REPORTED_RESOLVED"
          else if active != [ ] then (builtins.head active).status
          else "HOLD_QUALIFICATION";
        resolution = if resolved then mailResolution else null;
        preservation = if resolved then {
          mail = true;
          calendar = true;
          feeds = true;
          selection = "PRESERVE_LIVE_SELECTION";
          settingWriter = false;
        } else null;
      });

  validateSystem1Catalog = browser: document:
    let
      core = (metaFor browser).coreCapability;
      commonCoreCases = [ "launch" "policy-readback" "extension-parity" "keepassxc"
        "cnt-where-compatible" "scrollbar" "https-doh-content-permissions"
        "password-manager-posture" "fullscreen-ui" "profile-isolation" "normal-browsing" ];
      vivaldiCoreCases = commonCoreCases ++ [ "ubol" "extension-coexistence" ];
      floorpCoreCases = commonCoreCases ++ [ "ubo" "extension-coexistence" ];
      histVivaldiCoreCases = commonCoreCases ++ [ "ubol" ];
      histFloorpCoreCases = commonCoreCases ++ [ "ubo" ];
      coreCases = if browser == "vivaldi" then vivaldiCoreCases else floorpCoreCases;
      histCoreCases = if browser == "vivaldi" then histVivaldiCoreCases else histFloorpCoreCases;
      suites = document.suites.${browser};
      validCore = suite:
        exactFields suite ([ "capability" "requiredForReplacement" "runsRegardlessOf"
          "cases" "credentials" "managedPolicyCharacterization" ]
          ++ (if suite ? routeScope then [ "routeScope" ] else [ ])
          ++ (if browser == "vivaldi" then [ "mailPosture" ] else [ ]))
        && suite.capability == core && suite.requiredForReplacement == true
        && (suite.cases == coreCases || suite.cases == histCoreCases)
        && suite.credentials == "NONE"
        && (builtins.elem suite.managedPolicyCharacterization [
          "personal-host-attended"
          "personal-host-attended-or-tart"
          "personal-host-attended-or-off-host-tart"
          "off-host-tart-only"
        ])
        && (if suite ? routeScope then suite.routeScope == "personal-host-attended" else true)
        && suite.runsRegardlessOf == (if browser == "vivaldi"
          then [ "VIVALDI_MAIL_STARTUP_CRASH_8_2_4133_83" ] else [ ])
        && (browser != "vivaldi"
          || suite.mailPosture == "PRESERVE_CURRENT_HOST_ENABLED_SEPARATE_SYNTHETIC_LAB"
          || suite.mailPosture == "DISABLED");
      validMail = suite:
        exactFields suite [ "capability" "requiredForReplacement" "chromeParity" "cases"
          "accounts" "disposableProfile" "realCredentials" "realMail" "tartImageCredentials"
          "realProtonBridge" "regressionFixture" ]
        && suite.capability == "vivaldi-mail" && suite.requiredForReplacement == false
        && suite.chromeParity == false
        && suite.cases == [ "disabled-by-default-while-held" "synthetic-tls-imap-smtp-account"
          "small-corpus-control" "high-cardinality-synthetic-corpus" "startup-memory-renderer-stability"
          "body-prefetch-vs-header-cardinality" ]
        && suite.accounts == "synthetic-local-tls-imap-smtp" && suite.disposableProfile == true
        && suite.realCredentials == false && suite.realMail == false && suite.tartImageCredentials == "FORBIDDEN"
        && suite.realProtonBridge == "credentialed-manual-separate-safe-test-account-approval"
        && exactFields suite.regressionFixture [ "version" "stableControlMetadataRecords" "oomMetadataRecords"
          "source" "universalThreshold" "countVsPathology" "syntheticOnly" ]
        && suite.regressionFixture.version == "8.2.4133.83"
        && natural suite.regressionFixture.stableControlMetadataRecords && natural suite.regressionFixture.oomMetadataRecords
        && suite.regressionFixture.source == "single-affected-profile-retained-shared-state"
        && suite.regressionFixture.universalThreshold == false && suite.regressionFixture.syntheticOnly == true
        && suite.regressionFixture.countVsPathology == "UNRESOLVED";
    in if !(builtins.elem browser [ "vivaldi" "floorp" ])
      || !(exactFields document [ "schema" "suites" "extensionTrials" ])
      || !(exactFields document.extensionTrials [ "browsers" "products" "catalogSource" "fixtures" "realSecrets" "requiredForPersonalHost" "labRoute" ])
      || document.extensionTrials.browsers != [ "chrome" "firefox" "vivaldi" "floorp" ]
      || document.extensionTrials.products != [ "Proton Pass" "Proton VPN" "iCloud Passwords" ]
      || document.extensionTrials.catalogSource != "config/browser/apple-proton-extensions.json"
      || document.extensionTrials.fixtures != [ "synthetic-password" "synthetic-totp" "synthetic-alias" "coexistence-opt-outs" "vpn-single-instance-disconnected" "optional-helper-blocked" "localhost-native-bridge" ]
      || document.extensionTrials.realSecrets != false
      || document.extensionTrials.requiredForPersonalHost != false
      || document.extensionTrials.labRoute != "off-host-tart"
      || document.schema != "browser-ux-replacement-system1-catalog-v1"
      || !(exactFields document.suites [ "vivaldi" "floorp" ])
      || !(exactFields suites ([ core ] ++ (if browser == "vivaldi" then [ "vivaldi-mail" ] else [ ])))
      || !(publicText suites) || !(validCore suites.${core})
      || (browser == "vivaldi" && !(validMail suites.vivaldi-mail)) then
      throw "Replacement SYSTEM1 catalog violates the closed per-browser schema"
    else true;

in
{
  inherit validateRuntimeIssues
    runtimeHoldsFor
    holdsFor
    coreHoldsFor
    validateMailRequest
    mailOverlayFor
    mailResolution
    validateSystem1Catalog;
}
