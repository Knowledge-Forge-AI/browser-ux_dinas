# Target-host search overlay. Schema presence is evidence, not runtime qualification.
let
  capability = evidence: {
    capability = "UNVERIFIED";
    status = "UNVERIFIED";
    runtimeQualified = false;
    staticEvidence = evidence;
  };
in {
  policies = {
    SearchEngines = {
      Default = "Startpage";
      DefaultPrivate = "Startpage";
      Add = [{ Name = "Startpage"; URLTemplate = "https://www.startpage.com/sp/search?query={searchTerms}"; Method = "GET"; }];
    };
    SearchSuggestEnabled = false;
  };
  reviewedExceptions = {
    SearchEngines = {
      reason = "Explicit target-host ordinary/private Startpage selection; installed schema observed; UI acceptance pending";
      reviewedIn = "PRIMARY-CUTOVER1 revise_close finding 3";
    };
    SearchSuggestEnabled = {
      reason = "Prevent typed queries reaching the previous provider; installed schema evidence and UI readback recorded separately";
      reviewedIn = "PRIMARY-CUTOVER1 revise_close finding 3";
    };
  };
  capabilities = {
    SearchEngines = capability {
      kind = "installed-policy-schema-only";
      source = "HOST-OBSERVATIONS.json floorpInstalledSchema";
      symbolPresent = true;
      supportsPolicy = false;
    };
    SearchSuggestEnabled = capability {
      kind = "installed-policy-schema-only";
      source = "HOST-OBSERVATIONS.json floorpInstalledSchema";
      symbolPresent = true;
      supportsPolicy = false;
    };
  };
}
