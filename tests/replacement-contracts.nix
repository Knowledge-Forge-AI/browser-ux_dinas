# Replacement browser family and evaluation contract checks.
# Covers Vivaldi and Floorp metadata, baseline family pins, capability coverage,
# extension parity, overlay security, isolation invariants, and fail-closed verdict.

{ lib, pkgs }:

let
  replacements = import ../config/browser/replacements;
  extensionPolicy = import ../config/browser/extension-policy.nix;

  chromiumBaseline = import ../config/browser/families/chromium.nix;
  geckoBaseline = import ../config/browser/families/gecko.nix;

  chromeLegacyWrapper = import ../config/browser/chrome-policy-defaults.nix;
  firefoxLegacyWrapper = import ../config/browser/firefox-policy-defaults.nix;

  pinFixture = builtins.fromJSON (builtins.readFile ./fixtures/replacement-baseline-pins.json);

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

  # Common baseline for overlay tests
  chromeTestBaseline = chromiumBaseline {
    keepassxcEnabled = true;
    optOut = [ ];
  };
  claims = import ../lib/application-claims.nix;
in
{
  replacement-runtime-hold-contract =
    let
      document = replacements.runtimeIssues;
      issue = builtins.head document.issues.vivaldi;
      changed = entry: document // { issues = document.issues // { vivaldi = [ entry ]; }; };
      rejected = candidate: !(builtins.tryEval (builtins.deepSeq
        (replacements.holdsFor "vivaldi" "vivaldi-mail" candidate) true)).success;
      cleared = issue // { status = "CLEARED"; clearance = {
        reviewedIn = "synthetic-review"; evidence = "synthetic-clearance"; clearedOn = "2026-10-05";
      }; };
      vRec = replacements.records.vivaldi;
      fRec = replacements.records.floorp;
      qualify = record: record // {
        identity = { status = "MATCH"; qualification = "MATCH"; };
        policyDelivery = { status = "SUPPORTED"; qualified = true; };
        policyCapabilities = builtins.mapAttrs (_: _: { capability = "SUPPORTED_SAME_SEMANTICS";
          status = "SUPPORTED_SAME_SEMANTICS"; runtimeQualified = true; }) record.policyCapabilities;
        extensionCapabilities = builtins.mapAttrs (_: _: { capability = "SUPPORTED_SAME_SEMANTICS";
          status = "SUPPORTED_SAME_SEMANTICS"; runtimeQualified = true; }) record.extensionCapabilities;
        nativeMessaging = { status = "QUALIFIED"; target = "SUPPORTED_SAME_SEMANTICS"; qualified = true; gaps = [ ]; };
        customExtension = { status = "QUALIFIED"; qualified = true; };
        profileIsolation = record.profileIsolation // { qualification = "QUALIFIED"; };
        cnt = { status = "QUALIFIED"; qualified = true; authorityExpansion = false; };
        gaps = [ ];
      };
      changedFloorp = entry: document // { issues = document.issues // { floorp = [ entry ]; }; };
      rejectedCore = candidate: !(builtins.tryEval (builtins.deepSeq
        (replacements.holdsFor "vivaldi" "vivaldi-browser-core" candidate) true)).success;
      rejectedFloorp = candidate: !(builtins.tryEval (builtins.deepSeq
        (replacements.holdsFor "floorp" "floorp-browser-core" candidate) true)).success;
      supported = (qualify vRec).policyCapabilities;
      vivaldiCoreCrash = {
        id = "VIVALDI_CORE_STARTUP_CRASH_TEST";
        replacementBrowser = "vivaldi";
        sourceBrowser = "chrome";
        feature = "browser_core";
        capability = "vivaldi-browser-core";
        scope = "browser_core";
        sourceRelationship = "Vivaldi browser core replacing Chrome.";
        status = "HOLD_RUNTIME_CRASH";
        trigger = "Reproducible startup crash during browser window initialization.";
        interpretation = "Unsymbolicated native crash in Vivaldi Framework main thread.";
        evidenceRetention = "Crash log preserved in test diagnostic store; no private material.";
        blocks = [ "vivaldi-browser-core" ];
        doesNotBlock = [ "vivaldi-mail" "vivaldi-application-claim" "floorp-qualification" ];
        signature = {
          product = "Vivaldi_Mac";
          version = "8.2.4133.83";
          process = "Vivaldi";
          operatingSystem = "macOS 27.0.1";
          architecture = "arm64";
          exceptionType = 1;
          exceptionName = "EXC_BAD_ACCESS";
          breakpointSubcode = 0;
          module = "Vivaldi Framework";
          moduleRelativeOffsetHex = "0x123456";
          moduleRelativeOffsetDecimal = 1193046;
          absoluteAddressStable = false;
          symbolicated = false;
          dumpCount = 1;
          windowLocal = "approximately 2026-10-05 00:00:00";
        };
      };
      vivaldiCoreCleared = vivaldiCoreCrash // {
        status = "CLEARED";
        clearance = {
          reviewedIn = "synthetic-core-review";
          evidence = "synthetic-core-clearance";
          clearedOn = "2026-10-05";
        };
      };
      floorpCoreCrash = {
        id = "FLOORP_CORE_STARTUP_CRASH_TEST";
        replacementBrowser = "floorp";
        sourceBrowser = "firefox";
        feature = "browser_core";
        capability = "floorp-browser-core";
        scope = "browser_core";
        sourceRelationship = "Floorp browser core replacing Firefox.";
        status = "HOLD_RUNTIME_CRASH";
        trigger = "Reproducible crash in Floorp Gecko child process during tab restore.";
        interpretation = "Unsymbolicated native crash in libxul.dylib during session restore.";
        evidenceRetention = "Crash log preserved in test diagnostic store; no private material.";
        blocks = [ "floorp-browser-core" ];
        doesNotBlock = [ "floorp-application-claim" "vivaldi-qualification" ];
        signature = {
          product = "Floorp_Mac";
          version = "11.20.0";
          process = "floorp";
          operatingSystem = "macOS 27.0.1";
          architecture = "arm64";
          exceptionType = 11;
          exceptionName = "SIGSEGV";
          breakpointSubcode = 0;
          module = "libxul.dylib";
          moduleRelativeOffsetHex = "0xabcdef";
          moduleRelativeOffsetDecimal = 11259375;
          absoluteAddressStable = false;
          symbolicated = false;
          dumpCount = 2;
          windowLocal = "approximately 2026-10-05 01:00:00";
        };
      };
      floorpCoreCleared = floorpCoreCrash // {
        status = "CLEARED";
        clearance = {
          reviewedIn = "synthetic-floorp-review";
          evidence = "synthetic-floorp-clearance";
          clearedOn = "2026-10-05";
        };
      };
      requiredMail = (import ../config/browser/replacements/vivaldi.nix).featureOverlays // {
        mail = vRec.featureOverlays.mail // { requiredForReplacement = true; };
      };
    in
    assert replacements.validateRuntimeIssues "vivaldi" document;
    assert replacements.validateRuntimeIssues "floorp" document;
    assert issue.capability == "vivaldi-mail" && issue.scope == "optional_overlay";
    assert issue.blocks == [ "vivaldi-mail" ];
    assert lib.all (cap: builtins.elem cap issue.doesNotBlock)
      [ "vivaldi-browser-core" "chrome-replacement-parity" "vivaldi-application-claim" ];
    assert vRec.runtimeHolds == [ ] && fRec.runtimeHolds == [ ];
    assert replacements.holdsFor "vivaldi" "vivaldi-mail" (changed (issue // {
      signature = issue.signature // { version = "999.0"; };
    })) == [ issue.id ];
    assert replacements.runtimeHoldsFor "floorp" (changed { malformed = true; }) == [ ];
    assert !(builtins.elem issue.id vRec.gaps) && !(builtins.elem issue.id fRec.gaps);
    assert vRec.activation.status == "HOLD_QUALIFICATION" && fRec.activation.status == "HOLD_QUALIFICATION";
    assert !vRec.activation.replacementAuthorized && !fRec.activation.replacementAuthorized;
    assert vRec.activation.hostPolicyDelivery == "HELD" && vRec.activation.liveProfileMigration == "FORBIDDEN";
    assert vRec.activation.applicationRetention == "ALLOWED";
    assert vRec.deliverable == { } && vRec.held == vRec.desired;
    assert (replacements.partitionPolicies { desired = vRec.desired; capabilities = supported;
      runtimeHolds = vRec.runtimeHolds; }) == { deliverable = vRec.desired; held = { }; };
    assert replacements.parityVerdict (qualify fRec) == "PASS";
    # Real held Mail overlay remains in this fully qualified synthetic core record.
    assert (qualify vRec).featureOverlays.mail.status == "HOLD_RUNTIME_OOM";
    assert replacements.parityVerdict (qualify vRec) == "PASS";
    assert replacements.parityVerdict ((qualify vRec) // { runtimeHolds = [ issue.id ]; }) == "HOLD";
    assert replacements.validateRuntimeIssues "vivaldi" (changed vivaldiCoreCrash);
    assert replacements.runtimeHoldsFor "vivaldi" (changed vivaldiCoreCrash) == [ vivaldiCoreCrash.id ];
    assert replacements.holdsFor "vivaldi" "vivaldi-browser-core" (changed vivaldiCoreCrash) == [ vivaldiCoreCrash.id ];
    assert replacements.holdsFor "vivaldi" "vivaldi-mail" (changed vivaldiCoreCrash) == [ ];
    assert replacements.runtimeHoldsFor "floorp" (changed vivaldiCoreCrash) == [ ];
    assert replacements.holdsFor "floorp" "floorp-browser-core" (changed vivaldiCoreCrash) == [ ];
    assert replacements.parityVerdict ((qualify vRec) // { runtimeHolds = [ vivaldiCoreCrash.id ]; }) == "HOLD";
    assert replacements.holdsFor "vivaldi" "vivaldi-browser-core" (changed vivaldiCoreCleared) == [ ];
    assert replacements.runtimeHoldsFor "vivaldi" (changed vivaldiCoreCleared) == [ ];

    assert replacements.validateRuntimeIssues "floorp" (changedFloorp floorpCoreCrash);
    assert replacements.runtimeHoldsFor "floorp" (changedFloorp floorpCoreCrash) == [ floorpCoreCrash.id ];
    assert replacements.holdsFor "floorp" "floorp-browser-core" (changedFloorp floorpCoreCrash) == [ floorpCoreCrash.id ];
    assert replacements.runtimeHoldsFor "vivaldi" (changedFloorp floorpCoreCrash) == [ ];
    assert replacements.holdsFor "vivaldi" "vivaldi-browser-core" (changedFloorp floorpCoreCrash) == [ ];
    assert replacements.holdsFor "vivaldi" "vivaldi-mail" (changedFloorp floorpCoreCrash) == [ issue.id ];
    assert replacements.parityVerdict ((qualify fRec) // { runtimeHolds = [ floorpCoreCrash.id ]; }) == "HOLD";
    assert replacements.holdsFor "floorp" "floorp-browser-core" (changedFloorp floorpCoreCleared) == [ ];
    assert replacements.runtimeHoldsFor "floorp" (changedFloorp floorpCoreCleared) == [ ];

    assert replacements.coreHoldsFor "vivaldi" requiredMail document == [ issue.id ];
    assert replacements.holdsFor "vivaldi" "vivaldi-mail" (changed cleared) == [ ];
    assert replacements.parityVerdict vRec == "HOLD";
    assert rejected (document // { extra = true; });
    assert rejected (document // { schema = "unknown"; });
    assert rejected (document // { issues = document.issues // { brave = [ ]; }; });
    assert rejected (changed (issue // { status = "PASS"; }));
    assert rejected (changed (issue // { status = "CLEARED"; }));
    assert rejected (changed (cleared // { clearance = cleared.clearance // { evidence = ""; }; }));
    assert rejected (changed (cleared // { clearance = cleared.clearance // { extra = true; }; }));
    assert rejected (changed (issue // { clearance = cleared.clearance; }));
    assert rejected (changed (issue // { account = "forbidden-field"; }));
    assert rejected (changed (issue // { replacementBrowser = "floorp"; }));
    assert rejected (changed (issue // { sourceBrowser = "firefox"; }));
    assert rejected (document // { issues = document.issues // { vivaldi = [ issue issue ]; }; });
    assert rejected (changed (issue // { capability = "unknown"; }));
    assert rejected (changed (issue // { blocks = [ "vivaldi-browser-core" ]; }));
    assert rejected (changed (issue // { doesNotBlock = [ ]; }));
    assert rejected (changed (issue // { doesNotBlock = issue.doesNotBlock ++ [ "vivaldi-mail" ]; }));
    assert rejected (changed (issue // { signature = issue.signature // { privatePath = "forbidden-field"; }; }));
    assert rejected (changed (issue // { signature = issue.signature // { dumpCount = 0; }; }));
    assert rejected (changed (issue // { signature = issue.signature // { absoluteAddressStable = "false"; }; }));
    assert rejected (changed (issue // { systemTest = issue.systemTest // { automatedBaseline = "real-proton"; }; }));
    assert rejected (changed (issue // { systemTest = issue.systemTest // { realProtonCredentials = true; }; }));
    assert rejected (changed (issue // { systemTest = issue.systemTest // { tartImageCredentials = "ALLOWED"; }; }));
    assert rejected (changed (issue // { systemTest = issue.systemTest // { disposableProfile = false; }; }));
    assert rejected (changed (issue // { systemTest = issue.systemTest // { managedPolicyCharacterization = "live-host"; }; }));
    assert rejected (changed (issue // { forensics = issue.forensics // { thresholdClaimed = true; }; }));
    assert rejected (changed (issue // { forensics = issue.forensics // {
      highVolumeAccount = issue.forensics.highVolumeAccount // { label = "private-account"; };
    }; }));
    assert rejected (changed (issue // { trigger = "synthetic@private.invalid"; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { forensics = issue.forensics; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { livePosture = issue.livePosture; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { operatorStrategies = issue.operatorStrategies; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { configurationSupport = issue.configurationSupport; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { systemTest = issue.systemTest; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { prohibitedRemediations = issue.prohibitedRemediations; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { evidencePreservation = issue.evidencePreservation; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { signature = vivaldiCoreCrash.signature // { failureClass = "V8_JAVASCRIPT_OOM"; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { signature = vivaldiCoreCrash.signature // { rendererHeapBeforeFailure = "3.6 GiB"; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { feature = "mail"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { forensics = issue.forensics; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { livePosture = issue.livePosture; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { operatorStrategies = issue.operatorStrategies; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { configurationSupport = issue.configurationSupport; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { systemTest = issue.systemTest; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { prohibitedRemediations = issue.prohibitedRemediations; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { evidencePreservation = issue.evidencePreservation; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { signature = floorpCoreCrash.signature // { failureClass = "V8_JAVASCRIPT_OOM"; }; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { signature = floorpCoreCrash.signature // { rendererHeapBeforeFailure = "3.6 GiB"; }; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { feature = "mail"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { capability = "vivaldi-mail"; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { signature = vivaldiCoreCrash.signature // { dumpCount = 0; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { signature = vivaldiCoreCrash.signature // { moduleRelativeOffsetHex = "123456"; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { signature = vivaldiCoreCrash.signature // { architecture = "x86"; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { blocks = [ "chrome-replacement-parity" ]; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { doesNotBlock = [ "vivaldi-browser-core" ]; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { trigger = "crash@private.invalid"; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { clearance = { reviewedIn = "r"; evidence = "e"; clearedOn = "c"; }; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { status = "CLEARED"; }));
    assert rejectedCore (changed (vivaldiCoreCrash // { extra = true; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { replacementBrowser = "vivaldi"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { sourceBrowser = "chrome"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { scope = "optional_overlay"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { status = "PASS"; }));
    assert rejectedFloorp (changedFloorp (floorpCoreCrash // { signature = floorpCoreCrash.signature // { dumpCount = 0; }; }));
    assert issue.feature == "mail" && issue.sourceBrowser == "chrome";
    assert issue.signature.failureClass == "V8_JAVASCRIPT_OOM";
    assert issue.signature.moduleRelativeOffsetHex == "0x9017364" && issue.signature.moduleRelativeOffsetDecimal == 151090020;
    assert issue.signature.exceptionType == 6 && issue.signature.breakpointSubcode == 1;
    assert issue.signature.dumpCount == 9 && !issue.signature.absoluteAddressStable && !issue.signature.symbolicated;
    assert issue.forensics.classification == "NECESSARY_AND_SUFFICIENT" && !issue.forensics.thresholdClaimed;
    assert issue.forensics.configuredAccounts == 5;
    assert issue.forensics.highVolumeAccount == {
      label = "A4"; preFetch = "year"; logicalHeaderMemberships = 205133;
      olderThanOneYear = 171843; olderThanOneYearPercent = "83.77";
      indexedDateRangeBegins = "2018-07-19"; fullServerHistoryBackTo2004Downloaded = "UNPROVEN";
      cachedBodies = 2386; cachedBodiesOlderThanOneYear = 1958;
    };
    assert (builtins.elemAt issue.forensics.matrix 0).indexedRecords == 2680;
    assert (builtins.elemAt issue.forensics.matrix 0).offlineSeconds == "90.008";
    assert (builtins.elemAt issue.forensics.matrix 0).peakRendererRssKiB == 407792;
    assert (builtins.elemAt issue.forensics.matrix 0).peakV8GcUsedMB == "36.3";
    assert (builtins.elemAt issue.forensics.matrix 1).indexedRecords == 205133;
    assert (builtins.elemAt issue.forensics.matrix 1).secondsToOom == "7.164";
    assert (builtins.elemAt issue.forensics.matrix 1).peakRendererRssKiB == 5029664;
    assert (builtins.elemAt issue.forensics.matrix 1).peakV8GcUsedMB == "3677.5";
    assert (builtins.elemAt issue.forensics.matrix 2).secondsToOom == "7.18";
    assert (builtins.elemAt issue.forensics.matrix 2).indexedMetadataUnchanged;
    assert (builtins.elemAt issue.forensics.matrix 3).indexedMetadataRetained;
    assert !issue.livePosture.browserUxWrites && issue.livePosture.cleanLaunchExitCycles == 3;
    assert issue.livePosture.mailAccountDefinitionsRetained == 5 && !issue.livePosture.permanentMailRejection;
    assert issue.evidencePreservation.status == "COMPLETED_HOST_FORENSICS";
    assert lib.all (token: !lib.hasInfix token (builtins.toJSON document)) [ "/Users/" "/private/" "@" ];
    pkgs.runCommandLocal "browser-ux-dinas-replacement-runtime-hold-contract" { } ''touch "$out"'';

  replacement-mail-overlay-contract =
    let
      record = replacements.records.vivaldi;
      document = replacements.runtimeIssues;
      issue = builtins.head document.issues.vivaldi;
      cleared = document // { issues = document.issues // { vivaldi = [ (issue // {
        status = "CLEARED"; clearance = { reviewedIn = "synthetic-review";
          evidence = "synthetic-clearance"; clearedOn = "2026-10-05"; };
      }) ]; }; };
      rejected = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
      resolvedMail = replacements.render "vivaldi" { mailEnabled = true; preserveResolved = true; currentHostResolved = true; };
    in
    assert record.replacementCandidate == { capability = "vivaldi-browser-core";
      role = "chrome-replacement"; status = "CANDIDATE"; qualification = "READY_FOR_QUALIFICATION"; };
    assert record.featureOverlays.mail.status == "HOLD_RUNTIME_OOM";
    assert record.featureOverlays.mail.runtimeHolds == [ issue.id ];
    assert !record.featureOverlays.mail.requested && !record.featureOverlays.mail.requiredForReplacement;
    assert !record.featureOverlays.mail.chromeCounterpart && !record.featureOverlays.mail.chromeParityFeature;
    assert record.featureOverlays.mail.safePosture == "DISABLED";
    assert record.featureOverlays.mail.delivery == "NOT_DELIVERED_BY_BROWSER_UX";
    assert !(record.desired ? mail) && !(record.policyCapabilities ? mail);
    assert !(builtins.elem "mail" record.baselineKeys);
    assert (replacements.render "vivaldi" { }).featureOverlays.mail.requested == false;
    assert rejected (replacements.render "vivaldi" { mailEnabled = true; });
    assert rejected (replacements.render "floorp" { mailEnabled = true; });
    assert rejected (replacements.validateMailRequest "vivaldi" {
      replacementEnabled = false; mailEnabled = true;
    } cleared);
    assert (replacements.mailOverlayFor true cleared).status == "HOLD_QUALIFICATION";
    assert (replacements.mailOverlayFor true cleared).requested;
    assert resolvedMail.featureOverlays.mail.status == "OPERATOR_REPORTED_RESOLVED";
    assert resolvedMail.featureOverlays.mail.currentHostResolved;
    assert resolvedMail.featureOverlays.mail.resolution.accountStatus == "OPERATOR_REPORTED_RESOLVED";
    assert resolvedMail.verdict == "HOLD";
    assert (replacements.mailOverlayFor { requested = true; currentHostResolved = true; } document).status == "OPERATOR_REPORTED_RESOLVED";
    assert replacements.records.floorp.featureOverlays == { };
    assert replacements.records.floorp.system1.optional == [ ];
    pkgs.runCommandLocal "browser-ux-dinas-replacement-mail-overlay-contract" { } ''touch "$out"'';

  replacement-system1-catalog-contract =
    let
      catalog = replacements.system1Catalog;
      mail = catalog.suites.vivaldi.vivaldi-mail;
      vCases = catalog.suites.vivaldi.vivaldi-browser-core.cases;
      fCases = catalog.suites.floorp.floorp-browser-core.cases;
      expectedCommonCases = [ "launch" "policy-readback" "extension-parity" "keepassxc"
        "cnt-where-compatible" "scrollbar" "https-doh-content-permissions"
        "password-manager-posture" "fullscreen-ui" "profile-isolation" "normal-browsing"
        "extension-coexistence" ];
      changedCoreCases = browser: cases:
        let core = "${browser}-browser-core";
        in catalog // { suites = catalog.suites // {
          ${browser} = catalog.suites.${browser} // {
            ${core} = catalog.suites.${browser}.${core} // { inherit cases; };
          };
        }; };
      rejectedCore = browser: cases: !(builtins.tryEval (builtins.deepSeq
        (replacements.validateSystem1Catalog browser (changedCoreCases browser cases)) true)).success;
      changed = suite: catalog // { suites = catalog.suites // {
        vivaldi = catalog.suites.vivaldi // { vivaldi-mail = suite; };
      }; };
      rejected = candidate: !(builtins.tryEval (builtins.deepSeq
        (replacements.validateSystem1Catalog "vivaldi" candidate) true)).success;
    in
    assert replacements.validateSystem1Catalog "vivaldi" catalog;
    assert replacements.validateSystem1Catalog "floorp" catalog;
    assert replacements.validateSystem1Catalog "floorp" (changed { malformed = true; });
    assert builtins.elem "ubol" vCases && !(builtins.elem "ubo" vCases);
    assert builtins.elem "ubo" fCases && !(builtins.elem "ubol" fCases);
    assert builtins.elem "extension-parity" vCases && builtins.elem "extension-parity" fCases;
    assert builtins.elem "extension-coexistence" vCases && builtins.elem "extension-coexistence" fCases;
    assert lib.remove "ubol" vCases == expectedCommonCases;
    assert lib.remove "ubo" fCases == expectedCommonCases;
    assert rejectedCore "vivaldi" fCases;
    assert rejectedCore "vivaldi" (vCases ++ [ "ubo" ]);
    assert rejectedCore "floorp" vCases;
    assert rejectedCore "floorp" (fCases ++ [ "ubol" ]);
    assert catalog.suites.floorp.floorp-browser-core.runsRegardlessOf == [ ];
    assert catalog.suites.vivaldi.vivaldi-browser-core.requiredForReplacement;
    assert catalog.suites.vivaldi.vivaldi-browser-core.mailPosture == "PRESERVE_CURRENT_HOST_ENABLED_SEPARATE_SYNTHETIC_LAB";
    assert catalog.suites.vivaldi.vivaldi-browser-core.managedPolicyCharacterization == "personal-host-attended-or-off-host-tart";
    assert catalog.suites.floorp.floorp-browser-core.managedPolicyCharacterization == "personal-host-attended-or-off-host-tart";
    assert catalog.suites.vivaldi.vivaldi-browser-core.runsRegardlessOf == [ "VIVALDI_MAIL_STARTUP_CRASH_8_2_4133_83" ];
    assert !mail.requiredForReplacement && !mail.chromeParity;
    assert !mail.realCredentials && !mail.realMail && mail.tartImageCredentials == "FORBIDDEN";
    assert mail.regressionFixture.stableControlMetadataRecords == 2680 && mail.regressionFixture.oomMetadataRecords == 205133;
    assert !mail.regressionFixture.universalThreshold && mail.regressionFixture.syntheticOnly;
    assert lib.intersectLists catalog.suites.vivaldi.vivaldi-browser-core.cases mail.cases == [ ];
    assert rejected (changed (mail // { realCredentials = true; }));
    assert rejected (changed (mail // { realMail = true; }));
    assert rejected (changed (mail // { tartImageCredentials = "ALLOWED"; }));
    assert rejected (changed (mail // { requiredForReplacement = true; }));
    assert rejected (changed (mail // { regressionFixture = mail.regressionFixture // { universalThreshold = true; }; }));
    assert rejected (changed (mail // { accounts = "real-user-mail"; }));
    assert lib.all (token: !lib.hasInfix token (builtins.toJSON catalog)) [ "@" "/Users/" "/private/" ];
    pkgs.runCommandLocal "browser-ux-dinas-replacement-system1-catalog-contract" { } ''touch "$out"'';

  replacement-claims-contract =
    let
      vivaldi = { id = "bundle:com.vivaldi.Vivaldi"; artifact = "Vivaldi.app";
        provider = "homebrew-cask"; package = "vivaldi"; };
      floorp = { id = "bundle:app.floorp.Floorp"; artifact = "Floorp.app";
        provider = "homebrew-cask"; package = "floorp"; };
      both = { vivaldi.enable = true; floorp.enable = true; };
      rejected = cfg: !(builtins.tryEval (builtins.deepSeq
        (claims.applicationClaimsFor cfg) true)).success;
      active = claims.applicationClaimsFor both;
    in
    assert claims.replacementApplicationClaims { } == [ ];
    assert claims.applicationClaimsFor { } == claims.applicationClaims;
    assert claims.applicationClaimsFor { vivaldi.enable = false; floorp.enable = false; }
      == claims.applicationClaims;
    assert claims.replacementApplicationClaims { vivaldi.enable = true; } == [ vivaldi ];
    assert claims.replacementApplicationClaims { floorp.enable = true; } == [ floorp ];
    assert claims.replacementApplicationClaims both == [ vivaldi floorp ];
    # Claims ignore Mail on purpose; configuration/rendering enforce its hold.
    assert claims.applicationClaimsFor (both // { vivaldi = { enable = true; mail.enable = true; }; })
      == claims.applicationClaimsFor (both // { vivaldi = { enable = true; mail.enable = false; }; });
    assert rejected { floorp.mail.enable = true; };
    assert rejected { vivaldi.mail.enable = "true"; };
    assert rejected { vivaldi.mail.extra = true; };
    assert lib.all (key: builtins.length (lib.unique (map (claim: claim.${key}) active))
      == builtins.length active) [ "id" "artifact" "package" ];
    assert rejected { brave.enable = true; };
    assert rejected { vivaldi.enable = "true"; };
    assert rejected { floorp.unknown = true; };
    assert rejected { vivaldi.inherit-from = "firefox"; };
    assert rejected { floorp.inherit-from = "chrome"; };
    pkgs.runCommandLocal "browser-ux-dinas-replacement-claims-contract" { } ''touch "$out"'';

  # 1. Family contract: preserves all eight captured pins and guarantees wrapper equality across four cases
  replacement-family-contract =
    let
      cases = pinFixture.cases;
      verifyCase =
        caseName: c:
        let
          cChrome = chromiumBaseline c.args;
          cFirefox = geckoBaseline c.args;
          wChrome = chromeLegacyWrapper c.args;
          wFirefox = firefoxLegacyWrapper c.args;

          hChrome = builtins.hashString "sha256" (builtins.toJSON cChrome);
          hFirefox = builtins.hashString "sha256" (builtins.toJSON cFirefox);
          hwChrome = builtins.hashString "sha256" (builtins.toJSON wChrome);
          hwFirefox = builtins.hashString "sha256" (builtins.toJSON wFirefox);
        in
        cChrome == wChrome
        && cFirefox == wFirefox
        && hChrome == c.chrome
        && hwChrome == c.chrome
        && hFirefox == c.firefox
        && hwFirefox == c.firefox
        && (replacements.render "vivaldi" c.args).desired == cChrome
        && (replacements.render "floorp" c.args).desired == cFirefox
        && builtins.deepSeq [ (replacements.render "vivaldi" c.args)
          (replacements.render "floorp" c.args) ] true;

      allCasesVerified = builtins.all (name: verifyCase name cases.${name}) (builtins.attrNames cases);

      # Trial rendering behavior: delivers candidate policies for personalHostTrial
      vTrial = replacements.render "vivaldi" { personalHostTrial = true; };
      fTrial = replacements.render "floorp" { personalHostTrial = true; };

      # Apple/Proton allowlisted trial delta tests:
      # baseline pins continue valid disabled; enabled remove exactly new ExtensionSettings and Chromium forcelist entries before compare
      appleAllowlistedChromeSettings = {
        "pejdijmoenmkgeppbflobdenhhabjlaj" = { installation_mode = "force_installed"; update_url = "https://clients2.google.com/service/update2/crx"; };
      };
      appleAllowlistedChromeForcelist = [
        "pejdijmoenmkgeppbflobdenhhabjlaj;https://clients2.google.com/service/update2/crx"
      ];
      appleAllowlistedFirefoxSettings = {
        "password-manager-firefox-extension@apple.com" = { installation_mode = "force_installed"; install_url = "https://addons.mozilla.org/firefox/downloads/latest/icloud-passwords/latest.xpi"; };
      };

      # Test candidate with Apple delta added
      chromeBaselineDefault = chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; };
      chromeWithApple = chromeBaselineDefault // {
        ExtensionInstallForcelist = chromeBaselineDefault.ExtensionInstallForcelist ++ appleAllowlistedChromeForcelist;
        ExtensionSettings = chromeBaselineDefault.ExtensionSettings // appleAllowlistedChromeSettings;
      };
      chromeRecovered = chromeWithApple // {
        ExtensionInstallForcelist = builtins.filter (e: !builtins.elem e appleAllowlistedChromeForcelist) chromeWithApple.ExtensionInstallForcelist;
        ExtensionSettings = builtins.removeAttrs chromeWithApple.ExtensionSettings (builtins.attrNames appleAllowlistedChromeSettings);
      };

      firefoxBaselineDefault = geckoBaseline { keepassxcEnabled = true; optOut = [ ]; };
      firefoxWithApple = firefoxBaselineDefault // {
        ExtensionSettings = firefoxBaselineDefault.ExtensionSettings // appleAllowlistedFirefoxSettings;
      };
      firefoxRecovered = firefoxWithApple // {
        ExtensionSettings = builtins.removeAttrs firefoxWithApple.ExtensionSettings (builtins.attrNames appleAllowlistedFirefoxSettings);
      };

      # Also test rendering with personalHostTrial and appleProtonEnabled
      vTrialApple = replacements.render "vivaldi" { personalHostTrial = true; appleProtonEnabled = true; };
      fTrialApple = replacements.render "floorp" { personalHostTrial = true; appleProtonEnabled = true; };
    in
    assert allCasesVerified;
    assert vTrial.deliverable == vTrial.desired;
    assert fTrial.deliverable == fTrial.desired;
    assert vTrial.held == { };
    assert fTrial.held == { };
    assert vTrial.trialCandidate.trialReady;
    assert fTrial.trialCandidate.trialReady;
    assert vTrial.trialCandidate.qualification == "PENDING";
    assert vTrial.trialCandidate.readback == "PENDING";
    assert vTrial.verdict == "HOLD";
    assert fTrial.verdict == "HOLD";
    assert chromeRecovered == chromeBaselineDefault;
    assert firefoxRecovered == firefoxBaselineDefault;
    assert vTrialApple.verdict == "HOLD";
    assert fTrialApple.verdict == "HOLD";
    pkgs.runCommandLocal "browser-ux-dinas-replacement-family-contract" { } ''
      touch "$out"
    '';

  # 2. Capabilities coverage: closed per-key policy capability set exactly equals union of baseline keys keepass=true/false
  replacement-capabilities-contract =
    let
      vRec = replacements.records.vivaldi;
      fRec = replacements.records.floorp;

      # Chromium union
      cTrueKeys = builtins.attrNames (chromiumBaseline { keepassxcEnabled = true; optOut = [ ]; });
      cFalseKeys = builtins.attrNames (chromiumBaseline { keepassxcEnabled = false; optOut = [ ]; });
      cUnion = lib.sort builtins.lessThan (lib.unique (cTrueKeys ++ cFalseKeys));
      vCapKeys = lib.sort builtins.lessThan (builtins.attrNames vRec.policyCapabilities);

      # Gecko union
      gTrueKeys = builtins.attrNames (geckoBaseline { keepassxcEnabled = true; optOut = [ ]; });
      gFalseKeys = builtins.attrNames (geckoBaseline { keepassxcEnabled = false; optOut = [ ]; });
      gUnion = lib.sort builtins.lessThan (lib.unique (gTrueKeys ++ gFalseKeys));
      fCapKeys = lib.sort builtins.lessThan (builtins.attrNames fRec.policyCapabilities);

      # Initial state is UNVERIFIED
      vAllUnverified = builtins.all (k:
        vRec.policyCapabilities.${k}.capability == "UNVERIFIED"
        && vRec.policyCapabilities.${k}.status == "UNVERIFIED"
        && !vRec.policyCapabilities.${k}.runtimeQualified
      ) (builtins.attrNames vRec.policyCapabilities);

      fAllUnverified = builtins.all (k:
        fRec.policyCapabilities.${k}.capability == "UNVERIFIED"
        && fRec.policyCapabilities.${k}.status == "UNVERIFIED"
        && !fRec.policyCapabilities.${k}.runtimeQualified
      ) (builtins.attrNames fRec.policyCapabilities);

      # Deliverables empty and held equals desired
      vDeliverableEmpty = vRec.deliverable == { };
      vHeldEqualsDesired = vRec.held == vRec.desired;
      fDeliverableEmpty = fRec.deliverable == { };
      fHeldEqualsDesired = fRec.held == fRec.desired;
    in
    assert cUnion == vCapKeys;
    assert gUnion == fCapKeys;
    assert !(builtins.tryEval (replacements.validateCapabilities (cUnion ++ [ "FuturePolicy" ]) vRec.policyCapabilities)).success;
    assert !(builtins.tryEval (replacements.validateCapabilities cUnion (vRec.policyCapabilities // {
      FuturePolicy = { capability = "UNVERIFIED"; status = "UNVERIFIED"; };
    }))).success;
    assert vAllUnverified;
    assert fAllUnverified;
    assert vDeliverableEmpty;
    assert vHeldEqualsDesired;
    assert fDeliverableEmpty;
    assert fHeldEqualsDesired;
    pkgs.runCommandLocal "browser-ux-dinas-replacement-capabilities-contract" { } ''
      touch "$out"
    '';

  # 3. Extension parity: all expected IDs/classes inherited and unverified; scrollbar absent from config
  replacement-extension-parity-contract =
    let
      vExtCaps = replacements.records.vivaldi.extensionCapabilities;
      fExtCaps = replacements.records.floorp.extensionCapabilities;

      # Vivaldi extension ID and class checks
      vReqOk = builtins.all (id: (vExtCaps.${id}.class or "") == "required") expectedChromeRequiredIds;
      vDefOk = builtins.all (id: (vExtCaps.${id}.class or "") == "defaultOn") expectedChromeDefaultOnIds;
      vKpxOk = (vExtCaps.${expectedChromeKeePassXCId}.class or "") == "keepassxc";

      # Floorp extension ID and class checks
      fReqOk = builtins.all (id: (fExtCaps.${id}.class or "") == "required") expectedFirefoxRequiredIds;
      fDefOk = builtins.all (id: (fExtCaps.${id}.class or "") == "defaultOn") expectedFirefoxDefaultOnIds;
      fKpxOk = (fExtCaps.${expectedFirefoxKeePassXCId}.class or "") == "keepassxc";

      # Initial state UNVERIFIED
      vExtUnverified = builtins.all (id:
        vExtCaps.${id}.capability == "UNVERIFIED"
        && vExtCaps.${id}.status == "UNVERIFIED"
        && !vExtCaps.${id}.runtimeQualified
      ) (builtins.attrNames vExtCaps);

      fExtUnverified = builtins.all (id:
        fExtCaps.${id}.capability == "UNVERIFIED"
        && fExtCaps.${id}.status == "UNVERIFIED"
        && !fExtCaps.${id}.runtimeQualified
      ) (builtins.attrNames fExtCaps);

      # Custom extension and scrollbar isolation
      vNoScrollbarInPolicies =
        !(replacements.records.vivaldi.desired ? "browser-ux-scrollbars")
        && !(builtins.hasAttr "browser-ux-scrollbars" (replacements.records.vivaldi.desired.ExtensionSettings or { }));
      fNoScrollbarInPolicies =
        !(replacements.records.floorp.desired ? "browser-ux-scrollbars")
        && !(builtins.hasAttr "browser-ux-scrollbars" (replacements.records.floorp.desired.ExtensionSettings or { }));

      customExtBlocked =
        replacements.records.vivaldi.customExtension.status == "INHERITED_UNREGISTERED_DISTRIBUTION_BLOCKED"
        && replacements.records.floorp.customExtension.status == "INHERITED_UNREGISTERED_DISTRIBUTION_BLOCKED";
    in
    assert vReqOk;
    assert vDefOk;
    assert vKpxOk;
    assert fReqOk;
    assert fDefOk;
    assert fKpxOk;
    assert builtins.attrNames vExtCaps == lib.sort builtins.lessThan
      (expectedChromeRequiredIds ++ expectedChromeDefaultOnIds ++ [ expectedChromeKeePassXCId ]);
    assert builtins.attrNames fExtCaps == lib.sort builtins.lessThan
      (expectedFirefoxRequiredIds ++ expectedFirefoxDefaultOnIds ++ [ expectedFirefoxKeePassXCId ]);
    assert lib.all (id: vExtCaps.${id}.installSource == extensionPolicy.chromeExtensions.updateUrl)
      (builtins.attrNames vExtCaps);
    assert lib.all (id: lib.hasPrefix "https://addons.mozilla.org/" fExtCaps.${id}.installSource)
      (builtins.attrNames fExtCaps);
    assert !builtins.hasAttr "cjpalhdlnbpafiamejdnhcphjbkeiagm" vExtCaps;
    assert lib.all (name:
      let args = pinFixture.cases.${name}.args;
          v = replacements.render "vivaldi" args; f = replacements.render "floorp" args;
      in v.desired.ExtensionSettings == extensionPolicy.renderChromeExtensionSettings args
        && f.desired.ExtensionSettings == extensionPolicy.renderFirefoxExtensionSettings args
        && v.nativeMessaging.requested == args.keepassxcEnabled
        && f.nativeMessaging.requested == args.keepassxcEnabled
    ) (builtins.attrNames pinFixture.cases);
    assert vExtUnverified;
    assert fExtUnverified;
    assert vNoScrollbarInPolicies;
    assert fNoScrollbarInPolicies;
    assert customExtBlocked;
    pkgs.runCommandLocal "browser-ux-dinas-replacement-extension-parity-contract" { } ''
      touch "$out"
    '';

  # 4. Overlay security: rejects unreviewed additions and modifications; succeeds with valid review metadata
  replacement-overlay-contract =
    let
      # Empty overlay returns baseline unchanged
      emptyPass = (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = { };
      }) == chromeTestBaseline;

      emptyPoliciesPass = (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = { policies = { }; reviewedExceptions = { }; };
      }) == chromeTestBaseline;

      # Added policy without metadata rejected
      unreviewedAddRejected = !(builtins.tryEval (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = { policies = { SomeNewPolicy = true; }; };
      })).success;

      # Added policy with empty reason rejected
      emptyReasonRejected = !(builtins.tryEval (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = {
          policies = { SomeNewPolicy = true; };
          reviewedExceptions = { SomeNewPolicy = { reason = ""; reviewedIn = "BUX-TEST-1"; }; };
        };
      })).success;

      # Added policy with empty reviewedIn rejected
      emptyReviewedInRejected = !(builtins.tryEval (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = {
          policies = { SomeNewPolicy = true; };
          reviewedExceptions = { SomeNewPolicy = { reason = "intentional addition"; reviewedIn = ""; }; };
        };
      })).success;

      # Weakened/overridden baseline policy without metadata rejected
      unreviewedWeakenedRejected = !(builtins.tryEval (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = { policies = { BlockThirdPartyCookies = false; }; };
      })).success;

      # Nested ExtensionSettings addition without metadata rejected
      unreviewedNestedExtRejected = !(builtins.tryEval (replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = {
          policies = {
            ExtensionSettings = {
              "unreviewed-ext-id" = { installation_mode = "allowed"; };
            };
          };
          reviewedExceptions = {
            ExtensionSettings = { reason = "extension container"; reviewedIn = "BUX-TEST-2"; };
          };
        };
      })).success;

      # Valid reviewed top-level policy succeeds
      validReviewedOverlay = replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = {
          policies = { BlockThirdPartyCookies = false; };
          reviewedExceptions = {
            BlockThirdPartyCookies = { reason = "exception reviewed for testing"; reviewedIn = "BUX-REVIEW-1"; };
          };
        };
      };
      validReviewedPass = validReviewedOverlay.BlockThirdPartyCookies == false;

      # Valid reviewed nested ExtensionSettings succeeds
      validReviewedExtOverlay = replacements.applyOverlay {
        baseline = chromeTestBaseline;
        overlay = {
          policies = {
            ExtensionSettings = {
              "reviewed-ext-id" = { installation_mode = "force_installed"; };
            };
          };
          reviewedExceptions = {
            ExtensionSettings = {
              reason = "extension settings wrapper"; reviewedIn = "BUX-REVIEW-2";
              extensions."reviewed-ext-id" = { reason = "extension reviewed"; reviewedIn = "BUX-REVIEW-3"; };
            };
          };
        };
      };
      validReviewedExtPass =
        validReviewedExtOverlay.ExtensionSettings."reviewed-ext-id".installation_mode == "force_installed";
    in
    assert emptyPass;
    assert emptyPoliciesPass;
    assert unreviewedAddRejected;
    assert emptyReasonRejected;
    assert emptyReviewedInRejected;
    assert unreviewedWeakenedRejected;
    assert unreviewedNestedExtRejected;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline;
      overlay.policies.ExtensionSettings."ddkjiahejlhfcafbddmgiahcphecmpfh".installation_mode = "allowed";
    })).success;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline; overlay.extensions = { };
    })).success;
    assert validReviewedPass;
    assert validReviewedExtPass;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline;
      overlay.reviewedExceptions.Unused = { reason = "unused"; reviewedIn = "fixture-review"; };
    })).success;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline;
      overlay = {
        policies.ExtensionSettings."reviewed-ext-id".installation_mode = "allowed";
        reviewedExceptions = {
          ExtensionSettings = { reason = "container"; reviewedIn = "fixture-review"; };
          "reviewed-ext-id" = { reason = "ambiguous top-level namespace"; reviewedIn = "fixture-review"; };
        };
      };
    })).success;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline;
      overlay = {
        policies.BlockThirdPartyCookies = false;
        reviewedExceptions.BlockThirdPartyCookies = {
          reason = "typo"; reviewedIn = "fixture-review"; unused = true;
        };
      };
    })).success;
    assert !(builtins.tryEval (replacements.applyOverlay {
      baseline = chromeTestBaseline;
      overlay = {
        policies.ExtensionSettings."reviewed-ext-id".installation_mode = "allowed";
        reviewedExceptions.ExtensionSettings = {
          reason = "container"; reviewedIn = "fixture-review";
          extensions = {
            "reviewed-ext-id" = { reason = "used"; reviewedIn = "fixture-review"; };
            "unused-ext-id" = { reason = "unused"; reviewedIn = "fixture-review"; };
          };
        };
      };
    })).success;
    pkgs.runCommandLocal "browser-ux-dinas-replacement-overlay-contract" { } ''
      touch "$out"
    '';

  # 5. Isolation: profiles use symbolic paths isolated from Chrome/Firefox; native messaging candidates verified
  replacement-isolation-contract =
    let
      vRec = replacements.records.vivaldi;
      fRec = replacements.records.floorp;

      vProfileOk =
        vRec.profile.symbolic == "$HOME/Library/Application Support/Vivaldi"
        && vRec.profile.isolatedFrom == "Google/Chrome"
        && !vRec.profile.dataCopying;

      fProfileOk =
        fRec.profile.symbolic == "$HOME/Library/Application Support/Floorp"
        && fRec.profile.isolatedFrom == "Firefox"
        && !fRec.profile.dataCopying;

      vNmhOk =
        vRec.nativeMessaging.candidate == "$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json"
        && vRec.nativeMessaging.targetScope == "per-user"
        && !vRec.nativeMessaging.profileSharing
        && vRec.nativeMessaging.systemTarget == "NOT_REQUESTED_SUPPORTED_PER_USER_ROUTE"
        && !vRec.nativeMessaging.qualified;

      fNmhOk =
        fRec.nativeMessaging.candidate == "/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json"
        && fRec.nativeMessaging.sharedWith == "firefox"
        && fRec.nativeMessaging.dependsOn == "firefox native host active"
        && !fRec.nativeMessaging.newWriter
        && !fRec.nativeMessaging.browserSpecificPathSupported
        && fRec.nativeMessaging.sharedReaderSupported
        && !fRec.nativeMessaging.qualified;
      profilePaths = [ vRec.profile.path fRec.profile.path
        "$HOME/Library/Application Support/Google/Chrome" "$HOME/Library/Application Support/Firefox" ];
    in
    assert vProfileOk;
    assert fProfileOk;
    assert vNmhOk;
    assert fNmhOk;
    assert vRec.nativeMessaging.manifest.allowed_origins == [ "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/" ];
    assert fRec.nativeMessaging.manifest.allowed_extensions == [ "keepassxc-browser@keepassxc.org" ];
    assert builtins.length (lib.unique profilePaths) == 4;
    assert lib.all (a: lib.all (b: a == b || (!lib.hasPrefix (a + "/") b && !lib.hasPrefix (b + "/") a)) profilePaths) profilePaths;
    pkgs.runCommandLocal "browser-ux-dinas-replacement-isolation-contract" { } ''
      touch "$out"
    '';

  # 6. Strict fail-closed verdict: HOLD on unknowns/unverified/gaps; rejects false qualifications
  replacement-verdict-strictness-contract =
    let
      vRec = replacements.records.vivaldi;
      fRec = replacements.records.floorp;

      vHold = vRec.verdict == "HOLD";
      fHold = fRec.verdict == "HOLD";

      # Missing fields fail closed
      emptyHold = replacements.parityVerdict { } == "HOLD";
      partialHold = replacements.parityVerdict {
        identity = { status = "MATCH"; qualification = "MATCH"; };
      } == "HOLD";

      # False qualification fails closed: identity & delivery falsely marked qualified, but capabilities unverified
      falseQualHold = replacements.parityVerdict (vRec // {
        identity = { status = "MATCH"; qualification = "MATCH"; };
        policyDelivery = { status = "SUPPORTED"; qualified = true; };
      }) == "HOLD";

      # Floorp native dependency gap keeps Floorp at HOLD even if delivery and identity match
      floorpDepGapHold = replacements.parityVerdict (fRec // {
        identity = { status = "MATCH"; qualification = "MATCH"; };
        policyDelivery = { status = "SUPPORTED"; qualified = true; };
        nativeMessaging = fRec.nativeMessaging // { qualified = true; status = "QUALIFIED"; gaps = [ "depends on firefox native host active" ]; };
      }) == "HOLD";
      qualified = vRec // {
        runtimeHolds = [ ];
        identity = { status = "MATCH"; qualification = "MATCH"; };
        policyDelivery = { status = "SUPPORTED"; qualified = true; };
        policyCapabilities = builtins.mapAttrs (_: _: { capability = "SUPPORTED_SAME_SEMANTICS";
          status = "SUPPORTED_SAME_SEMANTICS"; runtimeQualified = true; }) vRec.policyCapabilities;
        extensionCapabilities = builtins.mapAttrs (_: _: { capability = "SUPPORTED_SAME_SEMANTICS";
          status = "SUPPORTED_SAME_SEMANTICS"; runtimeQualified = true; }) vRec.extensionCapabilities;
        nativeMessaging = { status = "QUALIFIED"; target = "SUPPORTED_SAME_SEMANTICS"; qualified = true; gaps = [ ]; };
        customExtension = { status = "QUALIFIED"; qualified = true; };
        profileIsolation = vRec.profileIsolation // { qualification = "QUALIFIED"; };
        cnt = { status = "QUALIFIED"; qualified = true; authorityExpansion = false; };
        gaps = [ ];
      };
      translatedCap = {
        capability = "SUPPORTED_TRANSLATED"; status = "SUPPORTED_TRANSLATED"; runtimeQualified = true;
        translation = { kind = "rename"; targetKey = "TranslatedHTTPS";
          reason = "synthetic reviewed translation"; reviewedIn = "fixture-review"; };
      };
    in
    assert vHold;
    assert fHold;
    assert emptyHold;
    assert partialHold;
    assert falseQualHold;
    assert floorpDepGapHold;
    assert replacements.parityVerdict qualified == "PASS";
    assert replacements.parityVerdict (builtins.removeAttrs qualified [ "runtimeHolds" ]) == "HOLD";
    assert replacements.parityVerdict (qualified // { runtimeHolds = [ "synthetic-core-hold" ]; }) == "HOLD";
    assert replacements.parityVerdict (qualified // {
      profileIsolation = qualified.profileIsolation // { qualification = "UNKNOWN"; };
    }) == "HOLD";
    assert replacements.parityVerdict (qualified // {
      nativeMessaging = qualified.nativeMessaging // { target = "UNVERIFIED"; };
    }) == "HOLD";
    assert replacements.parityVerdict (qualified // {
      nativeMessaging = qualified.nativeMessaging // { sharedWith = "firefox"; browserSpecificPathSupported = false; };
    }) == "HOLD";
    assert replacements.parityVerdict (qualified // {
      nativeMessaging = qualified.nativeMessaging // {
        sharedWith = "firefox"; browserSpecificPathSupported = false; sharedReaderSupported = true;
      };
    }) == "PASS";
    assert lib.all (status: replacements.parityVerdict (qualified // {
      policyCapabilities = qualified.policyCapabilities // {
        HttpsOnlyMode = { capability = status; inherit status; runtimeQualified = true; };
      };
    }) == "HOLD") [ "UNVERIFIED" "UNKNOWN" "UNSUPPORTED" ];
    assert replacements.parityVerdict (qualified // {
      policyCapabilities = builtins.removeAttrs qualified.policyCapabilities [ "HttpsOnlyMode" ];
    }) == "HOLD";
    assert replacements.parityVerdict (qualified // {
      policyCapabilities = qualified.policyCapabilities // {
        HttpsOnlyMode = builtins.removeAttrs translatedCap [ "translation" ];
      };
    }) == "HOLD";
    assert (replacements.partitionPolicies {
      desired.HttpsOnlyMode = "fixture"; capabilities.HttpsOnlyMode = translatedCap;
    }) == { deliverable.TranslatedHTTPS = "fixture"; held = { }; };
    assert replacements.parityVerdict (qualified // {
      policyCapabilities = qualified.policyCapabilities // {
        HttpsOnlyMode = { capability = "SUPPORTED_SAME_SEMANTICS"; status = "UNSUPPORTED"; runtimeQualified = true; };
      };
    }) == "HOLD";
    pkgs.runCommandLocal "browser-ux-dinas-replacement-verdict-strictness-contract" { } ''
      touch "$out"
    '';
}
