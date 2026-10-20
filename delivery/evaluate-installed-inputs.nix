# Normal selected composition + its locked, allowlisted localConfig context only.
{ activeFlake ? null, flakeOutputs ? null, host ? "example-current-mac", sourceRoots ? null }:
let
  outputs = if flakeOutputs != null then flakeOutputs else assert activeFlake != null; activeFlake;
  hasInputs = activeFlake != null && activeFlake ? inputs;
  hasComposition = hasInputs && (activeFlake.inputs ? composition-nd);
  public = if hasComposition then activeFlake.inputs.composition-nd else activeFlake;
  selected = outputs.darwinConfigurations.${host};
  configuration = selected.config;
  options = selected.options;
  lib = selected.pkgs.lib or public.inputs.core.inputs.nixpkgs.lib;
  # Attribute existence alone does not make a declared-but-undefined option readable.
  defined = path: lib.hasAttrByPath path options && (lib.getAttrFromPath path options).isDefined;
  read = path: fallback: if defined path then lib.getAttrFromPath path configuration else fallback;
  browser = read [ "browser-ux" "configuration" ] {};
  rolesR3 = read [ "browser-ux" "rolesR3" ] {};
  baseline = if defined [ "system" "build" ] then configuration.system.build.browserBaseline or {} else {};
  primary = browser.primaryCutover or null;
  isTargetHost = (configuration.networking.hostName or host) == "example-current-mac";
  primaryEnabled = isTargetHost && primary != null && primary.enable;
  vivaldi = if isTargetHost then browser.replacements.vivaldi or {} else {};
  floorp = if isTargetHost then browser.replacements.floorp or {} else {};
  trial = browser.extensions.apple-proton-trial or {};
  scripts = baseline.attendedApplyByBrowser or {};
  targets = baseline.attendedTargets or [];
  sources = builtins.filter (value: value != null) (map (row: row.source or null) targets);
  active = if primaryEnabled then primary.activeBrowsers else
    [ "chrome" "firefox" ] ++ lib.optional (vivaldi.enable or false) "vivaldi" ++ lib.optional (floorp.enable or false) "floorp";
  resolvedSourceRoots =
    if sourceRoots != null then sourceRoots
    else if hasInputs then {
      core = toString public.inputs.core.outPath;
      composition = toString public.outPath;
      browser-ux = toString public.inputs.browser-ux_dinas.outPath;
      private = toString activeFlake.outPath;
    } else throw "Explicit sourceRoots required for CLI flake outputs";
in
# R3 retains the old input for continuity but supersedes its delivery intent.
# Refuse before this readback exposes a legacy posture or writer. Retained kits
# use their embedded readback; this guard reaches rebuilt kits or checkout fallback.
if rolesR3.enable or false then
  throw "R3_LEGACY_CUTOVER_HELD: selected Browser UX roles supersede primary cutover; qualify the current role source"
else {
  sourceRoots = resolvedSourceRoots;
  owner = baseline.attendedOwner or "core/programs.browserBaseline";
  applyScript = if baseline ? attendedApply then toString baseline.attendedApply else null;
  applyScripts = builtins.mapAttrs (_: value: toString value) scripts;
  requiredDerivations = map (value: value.drvPath)
    (builtins.filter (value: builtins.isAttrs value && value ? drvPath)
      ((lib.optional (baseline ? attendedApply) baseline.attendedApply) ++ builtins.attrValues scripts ++ sources));
  targets = map (row: row // { source = if (row.source or null) == null then null else toString row.source; }) targets;
  primaryHome = configuration.users.users.${configuration.system.primaryUser}.home or null;
  requiredPosture = {
    host = configuration.networking.hostName or host;
    activeBrowsers = active;
    retiredBrowsers = if primaryEnabled then primary.retiredBrowsers else [];
    keepassxc = browser.keepassxc.enable or true;
    credentialProvider = if primaryEnabled then primary.credentialProvider else "legacy";
    vivaldi = vivaldi.enable or false;
    floorp = floorp.enable or false;
    productivityIntent = if primaryEnabled then primary.productivityIntent else "legacy";
    mailClient = if primaryEnabled then primary.productivityIntent == "full" else vivaldi.mail.enable or false;
    calendarClient = if primaryEnabled then primary.productivityIntent == "full" else vivaldi.mail.enable or false;
    appleProton = isTargetHost && (trial.enable or false);
    protonVpnEnabled = if primaryEnabled then primary.protonVpnEnabled else isTargetHost && (trial.enable or false);
    vivaldiVpnRoute = trial.vivaldi-vpn-route or "standalone";
    integratedVpnId = trial.integrated-vpn-id or "";
    safariManaged = builtins.elem "safari" active;
    searchProvider = if primaryEnabled then "Startpage" else "legacy";
  };
  deliberateOptOuts = browser.extensions.default-on-opt-out or [];
  optionMetadata = { inherit isTargetHost; browserDefined = defined [ "browser-ux" "configuration" ]; };
  targetIntent = {
    activeBrowsers = active;
    activeBrowserCount = builtins.length active;
    retiredBrowsers = if primaryEnabled then primary.retiredBrowsers else [];
    familyRetention = { vivaldi = "chromium-data"; floorp = "gecko-data"; };
    safariIntent = if builtins.elem "safari" active then "os-provided-attended-settings" else "unselected";
    effectiveState = "ATTENDED_READBACK_PENDING";
  };
}
