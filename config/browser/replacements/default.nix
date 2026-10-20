# Replacements library for alternative browser evaluations (Vivaldi, Floorp).
# Implements render, applyOverlay, parityVerdict, and records.

let
  vivaldiMeta = import ./vivaldi.nix;
  floorpMeta = import ./floorp.nix;

  chromiumBaseline = import ../families/chromium.nix;
  geckoBaseline = import ../families/gecko.nix;
  extensionPolicy = import ../extension-policy.nix;
  staticEvidence = builtins.fromJSON (builtins.readFile ./static-evidence.json);
  runtimeIssues = builtins.fromJSON (builtins.readFile ./runtime-issues.json);
  system1Catalog = builtins.fromJSON (builtins.readFile ./system1-catalog.json);
  supportedStatuses = [ "SUPPORTED_SAME_SEMANTICS" "SUPPORTED_TRANSLATED" ];
  capabilityStatuses = supportedStatuses ++ [ "UNSUPPORTED" "UNVERIFIED" ];

  inherit (import ./capabilities.nix)
    validateRuntimeIssues
    runtimeHoldsFor
    holdsFor
    coreHoldsFor
    validateMailRequest
    mailOverlayFor
    mailResolution
    validateSystem1Catalog;

  # Compare the complete union, including conditional settings, on every render.
  validateCapabilities = keys: capabilities:
    if builtins.attrNames capabilities != keys then
      throw "Replacement has unclassified or extraneous baseline policy capabilities"
    else if !builtins.all (cap: builtins.elem (cap.capability or "") capabilityStatuses
      && (cap.status or "") == cap.capability) (builtins.attrValues capabilities) then
      throw "Replacement has invalid or inconsistent capability status"
    else true;

  chromeNmhManifest = builtins.fromJSON (builtins.readFile ../keepassxc-chrome-native-messaging.json);
  firefoxNmhManifest = builtins.fromJSON (builtins.readFile ../keepassxc-firefox-native-messaging.json);

  # Helper to validate reviewed exception metadata
  isValidException = exc:
    builtins.isAttrs exc
    && exc ? reason
    && builtins.isString exc.reason
    && exc.reason != ""
    && exc ? reviewedIn
    && builtins.isString exc.reviewedIn
    && exc.reviewedIn != "";

  qualifiedCapability = cap:
    builtins.isAttrs cap
    && builtins.elem (cap.capability or "") supportedStatuses
    && (cap.status or "") == cap.capability
    && (cap.runtimeQualified or false) == true
    && (cap.capability != "SUPPORTED_TRANSLATED" || (
      cap ? translation && isValidException cap.translation
      && (cap.translation.kind or "") == "rename"
      && builtins.isString (cap.translation.targetKey or null)
      && cap.translation.targetKey != ""));

  # Translations require an explicit reviewed target; no invented policy names.
  partitionPolicies = { desired, capabilities, runtimeHolds ? [ ] }:
    let
      keys = builtins.attrNames desired;
      accepted = builtins.filter (key: qualifiedCapability (capabilities.${key} or { })) keys;
      entries = map (key: {
        name = if capabilities.${key}.capability == "SUPPORTED_TRANSLATED"
          then capabilities.${key}.translation.targetKey else key;
        value = desired.${key};
      }) accepted;
      targetNames = map (entry: entry.name) entries;
      uniqueNames = builtins.foldl' (names: name: if builtins.elem name names then names else names ++ [ name ]) [ ] targetNames;
    in
    if runtimeHolds != [ ] then { deliverable = { }; held = desired; }
    else if builtins.length targetNames != builtins.length uniqueNames then
      throw "Replacement translation has colliding policy targets"
    else {
      deliverable = builtins.listToAttrs entries;
      held = builtins.removeAttrs desired accepted;
    };

  # Overlay engine: strict review metadata requirement on ANY added or overridden policy key
  applyOverlay =
    { baseline, overlay ? { } }:
    if !builtins.isAttrs overlay
      || !builtins.all (key: builtins.elem key [ "policies" "reviewedExceptions" ]) (builtins.attrNames overlay)
      || !builtins.isAttrs (overlay.policies or { })
      || !builtins.isAttrs (overlay.reviewedExceptions or { }) then
      throw "Replacement overlay must use the closed policies/reviewedExceptions schema"
    else
      let
        policies = overlay.policies or { };
        reviewedExceptions = overlay.reviewedExceptions or { };
        exceptionKeys = key: if key == "ExtensionSettings"
          then [ "extensions" "reason" "reviewedIn" ] else [ "reason" "reviewedIn" ];

        # Validate each top-level key in policies
        validateTopKey =
          k:
          if !builtins.hasAttr k reviewedExceptions then
            throw "applyOverlay rejected: policy key '${k}' added or overridden without reviewedExceptions metadata"
          else if !isValidException reviewedExceptions.${k} then
            throw "applyOverlay rejected: reviewedExceptions for key '${k}' must contain nonempty 'reason' and 'reviewedIn'"
          else if !builtins.all (field: builtins.elem field (exceptionKeys k))
            (builtins.attrNames reviewedExceptions.${k}) then
            throw "applyOverlay rejected: unknown exception metadata for policy '${k}'"
          else
            null;

        # Validate nested ExtensionSettings if present
        validateExtensionSettings =
          if policies ? ExtensionSettings then
            let
              entries = policies.ExtensionSettings;
              exceptions = reviewedExceptions.ExtensionSettings.extensions or { };
            in
            if !builtins.isAttrs entries || !builtins.isAttrs exceptions then
              throw "applyOverlay rejected: extension settings and exceptions must be attribute sets"
            else if builtins.attrNames entries != builtins.attrNames exceptions then
              throw "applyOverlay rejected: extension exceptions must exactly cover changed extension entries"
            else builtins.map (extId:
              let exc = exceptions.${extId}; in
              if !isValidException exc || builtins.attrNames exc != [ "reason" "reviewedIn" ] then
                throw "applyOverlay rejected: invalid reviewed exception for extension '${extId}'"
              else null
            ) (builtins.attrNames entries)
          else
            [ ];

        # Enforce validations
        checked = if builtins.attrNames policies != builtins.attrNames reviewedExceptions then
          throw "applyOverlay rejected: exceptions must exactly cover changed policy keys"
        else builtins.deepSeq [
          (builtins.map validateTopKey (builtins.attrNames policies)) validateExtensionSettings
        ];

        # Merge policies into baseline with proper nested ExtensionSettings handling
        mergedExtensionSettings =
          if baseline ? ExtensionSettings && policies ? ExtensionSettings && builtins.isAttrs policies.ExtensionSettings then
            { ExtensionSettings = baseline.ExtensionSettings // policies.ExtensionSettings; }
          else
            { };
      in
      checked (baseline // policies // mergedExtensionSettings);

  # Strict fail-closed parity verdict evaluator
  parityVerdict =
    record:
    let
      # Identity must match expected code-signing requirements
      identityMatch =
        record ? identity
        && (record.identity.status or "") == "MATCH"
        && (record.identity.qualification or "") == "MATCH";

      # Policy delivery must be proven supported and qualified
      policyDeliverySupported =
        record ? policyDelivery
        && (record.policyDelivery.status or "") == "SUPPORTED"
        && (record.policyDelivery.qualified or false) == true;

      # Every policy requires qualified same semantics or a reviewed translation.
      allPoliciesQualified =
        record ? policyCapabilities
        && builtins.isAttrs record.policyCapabilities
        && record.policyCapabilities != { }
        && builtins.all (k:
          let
            cap = record.policyCapabilities.${k};
          in
          qualifiedCapability cap
        ) (builtins.attrNames record.policyCapabilities);

      # Every extension requires qualified same semantics or a reviewed translation.
      allExtensionsQualified =
        record ? extensionCapabilities
        && builtins.isAttrs record.extensionCapabilities
        && record.extensionCapabilities != { }
        && builtins.all (id:
          let
            cap = record.extensionCapabilities.${id};
          in
          qualifiedCapability cap
        ) (builtins.attrNames record.extensionCapabilities);

      # Native messaging host must be qualified with no unresolved gaps
      nativeMessagingQualified =
        record ? nativeMessaging
        && (record.nativeMessaging.qualified or false) == true
        && (record.nativeMessaging.status or "") == "QUALIFIED"
        && builtins.elem (record.nativeMessaging.target or "") supportedStatuses
        && (!(record.nativeMessaging ? sharedWith)
          || (record.nativeMessaging.browserSpecificPathSupported or false)
          || (record.nativeMessaging.sharedReaderSupported or false))
        && (record.nativeMessaging.gaps or [ ]) == [ ];

      # Custom extension must be qualified
      customExtensionQualified =
        record ? customExtension
        && (record.customExtension.qualified or false) == true
        && (record.customExtension.status or "") == "QUALIFIED";

      # Gaps list must be completely empty
      gapsEmpty = (record ? gaps) && record.gaps == [ ];
      runtimeClear = record ? runtimeHolds && record.runtimeHolds == [ ];
      profileQualified = record ? profileIsolation
        && (record.profileIsolation.qualification or "") == "QUALIFIED"
        && (record.profileIsolation.dataCopying or true) == false
        && record.profileIsolation ? path && record.profileIsolation ? sourcePath
        && record.profileIsolation.path != record.profileIsolation.sourcePath
        && (record.profileIsolation.migrationOperations or [ "UNKNOWN" ]) == [ ];
      cntQualified = record ? cnt && (record.cnt.status or "") == "QUALIFIED"
        && (record.cnt.qualified or false) && (record.cnt.authorityExpansion or true) == false;
      coverageComplete = record ? baselineKeys && record ? desired
        && record ? desiredExtensions
        && builtins.attrNames (record.policyCapabilities or { }) == record.baselineKeys
        && builtins.all (key: builtins.hasAttr key (record.policyCapabilities or { }))
          (builtins.attrNames record.desired)
        && builtins.attrNames (record.extensionCapabilities or { }) ==
          builtins.attrNames record.desiredExtensions;

      isPass =
        identityMatch
        && policyDeliverySupported
        && allPoliciesQualified
        && allExtensionsQualified
        && nativeMessagingQualified
        && customExtensionQualified
        && coverageComplete
        && profileQualified
        && cntQualified
        && runtimeClear
        && gapsEmpty;
    in
    if isPass then "PASS" else "HOLD";

  # Render function for replacement browser evaluation
  render =
    browser: args:
    let
      browserNorm =
        if browser == "vivaldi" || browser == "Vivaldi" then
          "vivaldi"
        else if browser == "floorp" || browser == "Floorp" then
          "floorp"
        else
          throw "Unknown replacement browser '${browser}'";

      meta = if browserNorm == "vivaldi" then vivaldiMeta else floorpMeta;
      baselineFunc = if browserNorm == "vivaldi" then chromiumBaseline else geckoBaseline;
      baseManifest = if browserNorm == "vivaldi" then chromeNmhManifest else firefoxNmhManifest;

      keepassxcEnabled = args.keepassxcEnabled or true;
      optOut = args.optOut or [ ];
      mailEnabled = args.mailEnabled or false;
      overlay = args.overlay or { policies = { }; reviewedExceptions = { }; };
      personalHostTrial = args.personalHostTrial or false;
      appleProtonEnabled = args.appleProtonEnabled or false;
      omitAppleProtonVpn = args.omitAppleProtonVpn or false;
      preserveResolved = args.preserveResolved or (args.currentHostResolved or (args."preserve-resolved" or false));
      currentHostResolved = args.currentHostResolved or false;
      credentialProvider = args.credentialProvider or "legacy";
      productivityIntent = args.productivityIntent or "default";
      protonVpnEnabled = args.protonVpnEnabled or appleProtonEnabled;

      familyArgs = { inherit keepassxcEnabled optOut appleProtonEnabled credentialProvider protonVpnEnabled; }
        // (if browserNorm == "vivaldi" then { inherit omitAppleProtonVpn; } else { });
      baseline = baselineFunc familyArgs;
      search = if browserNorm == "floorp" && (args.searchProvider or "legacy") == "Startpage"
        then import ./floorp-search.nix else { policies = { }; reviewedExceptions = { }; capabilities = { }; };
      classifiedCapabilities = meta.policyCapabilities // search.capabilities;

      # Closed per-key capability check: any key in baseline missing from capabilities throws
      baselineKeys = builtins.attrNames (baselineFunc { keepassxcEnabled = true; optOut = [ ]; }
        // baselineFunc { keepassxcEnabled = false; optOut = [ ]; } // search.policies);
      _checkCoverage = validateCapabilities baselineKeys classifiedCapabilities;
      validationError = extensionPolicy.validateConfiguration {
        keepassxc.enable = keepassxcEnabled;
        extensions.default-on-opt-out = optOut;
      };
      policyCapabilities = builtins.mapAttrs (key: cap: cap // {
        staticEvidence = cap.staticEvidence or
          (staticEvidence.browsers.${browserNorm}.policyEvidence.${key} or { kind = "UNKNOWN"; });
      }) classifiedCapabilities;

      # Apply overlay if specified
      desired = if validationError != null then throw validationError
        else applyOverlay {
          baseline = applyOverlay { inherit baseline; overlay = {
            inherit (search) policies reviewedExceptions;
          }; };
          inherit overlay;
        };
      desiredExtensions = builtins.removeAttrs desired.ExtensionSettings [ "*" ];
      deriveExtensionCap = id:
        let
          baseCap = meta.extensionCapabilities.${id} or {
            inherit id;
            name = let catalog = (import ../apple-proton.nix).catalog;
              entries = builtins.filter (entry:
                (if browserNorm == "vivaldi" then entry.chrome.id else entry.gecko.id) == id)
                (builtins.attrValues catalog.extensions);
              in if entries == [] then id else (builtins.head entries).name;
            class = if builtins.elem desiredExtensions.${id}.installation_mode [ "force_installed" "normal_installed" ]
              then "default-on" else "allowed";
            installSource =
              if browserNorm == "vivaldi"
              then (desiredExtensions.${id}.update_url or "https://clients2.google.com/service/update2/crx")
              else (desiredExtensions.${id}.install_url or "https://addons.mozilla.org/");
            capability = "UNVERIFIED";
            status = "UNVERIFIED";
            runtimeQualified = false;
          } // (if browserNorm == "vivaldi" then {
            cwsSupport = "VENDOR_DOCUMENTED";
            provenance = "https://help.vivaldi.com/desktop/appearance-customization/extensions/";
          } else { });
          effectiveClass =
            if desiredExtensions.${id}.installation_mode == "allowed" then "allowed"
            else if (baseCap.class or "") == "required" || ((baseCap.class or "") == "keepassxc" && keepassxcEnabled)
            then "required"
            else (baseCap.class or "default-on");
        in
        baseCap // {
          inherit effectiveClass;
          desired = desiredExtensions.${id};
        };
      extensionCapabilities = builtins.mapAttrs (id: _: deriveExtensionCap id) desiredExtensions;

      runtimeHolds = runtimeHoldsFor browserNorm runtimeIssues;
      featureOverlays = if browserNorm == "vivaldi" then {
        mail =
          let
            baseMail = mailOverlayFor {
              requested = mailEnabled;
              inherit currentHostResolved preserveResolved;
            } runtimeIssues;
          in
          if productivityIntent == "feeds-only" then
            baseMail // {
              uiIntent = "feeds-only";
              dataRetention = true;
              settingWriter = false;
              rawPrefInvented = false;
              selection = "FEEDS_ONLY_PRESERVE_DATA";
            }
          else
            baseMail;
      } else builtins.seq (validateMailRequest browserNorm {
        inherit mailEnabled currentHostResolved preserveResolved;
      } runtimeIssues) { };
      replacementCandidate = {
        capability = meta.coreCapability;
        role = "${meta.source}-replacement";
        status = "CANDIDATE";
        qualification = if runtimeHolds == [ ] then "READY_FOR_QUALIFICATION" else "HOLD_RUNTIME";
      };
      system1 = builtins.seq (validateSystem1Catalog browserNorm system1Catalog) {
        core = meta.coreCapability;
        optional = map (overlay: overlay.qualificationSuite) (builtins.attrValues meta.featureOverlays);
      };
      partitioned = partitionPolicies { inherit desired runtimeHolds; capabilities = policyCapabilities; };
      partitionedDeliverable = partitioned.deliverable;
      partitionedHeld = partitioned.held;

      deliverable =
        if !personalHostTrial then partitionedDeliverable
        else if runtimeHolds != [ ] then { }
        else desired;

      held =
        if !personalHostTrial then partitionedHeld
        else if runtimeHolds != [ ] then desired
        else builtins.removeAttrs desired (builtins.attrNames deliverable);

      trialCandidate = {
        deliverable = if runtimeHolds != [ ] then { } else desired;
        held = if runtimeHolds != [ ] then desired else { };
        trialReady = runtimeHolds == [ ];
        qualification = "PENDING";
        readback = "PENDING";
        status = if runtimeHolds != [ ] then "HOLD_RUNTIME_CRASH" else "READY_FOR_TRIAL";
      };

      activation = {
        replacementAuthorized = false;
        applicationRetention = "ALLOWED";
        liveProfileMigration = "FORBIDDEN";
        hostPolicyDelivery = if personalHostTrial && runtimeHolds == [ ] then "TRIAL_CANDIDATE" else "HELD";
        status = if runtimeHolds != [ ] then "HOLD_RUNTIME_CRASH" else "HOLD_QUALIFICATION";
        blockers = runtimeHolds;
        trial = personalHostTrial;
      };

      qualificationCandidate = desired;

      nativeMessaging = meta.nativeMessaging // {
        inherit keepassxcEnabled;
        requested = keepassxcEnabled;
        deliveredByBrowserUX = false;
        manifest = if keepassxcEnabled then baseManifest else null;
        baseManifest = baseManifest;
      };

      gaps =
        (if (meta.identity.qualification or "") != "MATCH" then [ "identity qualification pending attended or SYSTEM1 readback" ] else [ ])
        ++ (if (meta.identity.observed.verdict or "UNKNOWN") == "MISMATCH"
            then [ "installed app strict signature verification MISMATCH observed in semantic-dispatch sandbox on 2026-10-04" ] else [ ])
        ++ (if (meta.policyDelivery.status or "") != "SUPPORTED" then [ "core-owned policy trial prepared; effective readback pending" ] else [ ])
        ++ (if held != { } && !personalHostTrial then [ "policy capabilities unverified / held" ] else [ ])
        ++ (if personalHostTrial && held != { } then [ "unsupported trial policies held" ] else [ ])
        ++ [ "extension installation/enforcement unverified" "composition cask/config adoption pending"
          "first-run imports must be declined; no profile state migration"
          "profile isolation runtime readback unverified"
          "inherited family opt-outs have no replacement-specific override" ]
        ++ (meta.nativeMessaging.gaps or [ ])
        ++ (if (meta.customExtension.status or "") != "QUALIFIED" then [ "customExtension INHERITED_UNREGISTERED_DISTRIBUTION_BLOCKED" ] else [ ])
        ++ (if (meta.cnt.status or "") != "QUALIFIED" then [ "CNT status held" ] else [ ])
        ++ runtimeHolds;

      recordWithoutVerdict = builtins.seq _checkCoverage {
        browser = browserNorm;
        inherit (meta)
          family
          source
          inheritFrom
          identity
          versionObservations
          profile
          policyDelivery
          customExtension
          cnt
          ;
        application = {
          claimId = "bundle:${meta.identity.bundleId}";
          provider = "homebrew-cask";
          cask = browserNorm;
          artifact = if browserNorm == "vivaldi" then "Vivaldi.app" else "Floorp.app";
          observedIdentity = meta.identity.observed;
        };
        profileIsolation = meta.profile // {
          sourcePath = if browserNorm == "vivaldi" then "$HOME/Library/Application Support/Google/Chrome"
            else "$HOME/Library/Application Support/Firefox";
          qualification = "UNVERIFIED";
          migrationOperations = [ ];
        };
        qualificationScope =
          if personalHostTrial then "personal-host attended trial; core-owned delivery prepared; effective readback pending; no CNT authority expansion"
          else "SYSTEM1 lab-only; no delivery, activation or CNT authority";
        inherit
          desired
          deliverable
          held
          qualificationCandidate
          nativeMessaging
          baselineKeys
          policyCapabilities
          extensionCapabilities
          desiredExtensions
          overlay
          gaps
          runtimeHolds
          activation
          replacementCandidate
          featureOverlays
          system1
          personalHostTrial
          appleProtonEnabled
          trialCandidate
          ;
      };

      verdict = parityVerdict recordWithoutVerdict;
    in
    builtins.seq (if productivityIntent == "feeds-only" then true else validateMailRequest browserNorm {
      inherit mailEnabled currentHostResolved preserveResolved;
    } runtimeIssues)
      (recordWithoutVerdict // { inherit verdict; });

  records = {
    vivaldi = render "vivaldi" {
      keepassxcEnabled = true;
      optOut = [ ];
    };
    floorp = render "floorp" {
      keepassxcEnabled = true;
      optOut = [ ];
    };
  };
in
{
  inherit
    render
    applyOverlay
    parityVerdict
    records
    validateCapabilities
    partitionPolicies
    runtimeIssues
    validateRuntimeIssues
    runtimeHoldsFor
    holdsFor
    coreHoldsFor
    validateMailRequest
    mailOverlayFor
    mailResolution
    system1Catalog
    validateSystem1Catalog
    ;
}
