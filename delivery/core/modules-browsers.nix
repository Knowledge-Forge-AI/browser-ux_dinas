{ config, options, lib, pkgs, ... }:

let
  legacyChromePolicyFile = ../config/browser/chrome-policy.plist;
  legacyChromePolicyDefaults = import ../config/browser/chrome-policy-defaults.nix;
  legacyClearNewTabExternalExtension = ../config/browser/chrome-clear-new-tab-external-extension.json;
  legacyFirefoxPolicies = ../config/browser/firefox-policies.json;
  legacyKeepassxcChromeNativeMessaging = ../config/browser/keepassxc-chrome-native-messaging.json;
  legacyKeepassxcFirefoxNativeMessaging = ../config/browser/keepassxc-firefox-native-messaging.json;

  cfg = config.programs.browserBaseline;
  options_ = options.programs.browserBaseline;

  optChromePreferences = options_.chrome.managedPreferences;
  optChromeExtensions = options_.chrome.externalExtensions;
  optChromeNMH = options_.chrome.nativeMessagingHosts;
  optFirefoxPolicies = options_.firefox.policies;
  optFirefoxPoliciesPayload = options_.firefox.policiesJsonPayload;
  optFirefoxPolicyDelivery = options_.firefox.policyDelivery;
  optFirefoxNMH = options_.firefox.nativeMessagingHosts;
  optVivaldiPreferences = options_.vivaldi.managedPreferences;
  optVivaldiExtensions = options_.vivaldi.externalExtensions;
  optVivaldiNMH = options_.vivaldi.nativeMessagingHosts;
  optFloorpPolicies = options_.floorp.policies;

  # Architecture and Seam Representation Rationale (Roadmap BUX2 / §3 & §5):
  # - Option 2 Payload Model: For Firefox policies and external manifests, BUX2 provides
  #   both generic structured Nix attrsets (e.g. firefox.policies, structured records)
  #   and immutable JSON payload files (firefox.policiesJsonPayload, path inputs) to guarantee
  #   exact byte parity with baseline files without sacrificing structured key validation.
  # - Physical Writer Ownership: modules/browsers.nix is the sole physical writer of root
  #   browser paths. Destination modules contribute data only.
  # - Duplicate Leaf Granularity: Collision detection operates at the top-level policy leaf
  #   (e.g. BlockThirdPartyCookies, ExtensionSettings). Defining the same top-level key across
  #   modules—even with identical values—is strictly rejected. Sub-key merging for complex
  #   dictionaries like ExtensionSettings is deferred to BUX3.
  # - Priority Wrapper Invariant (§4.2): Seam definitions must carry default priority (100).
  #   Wrappers with _type == "override" (mkForce, mkOverride, mkDefault, mkOptionDefault)
  #   are rejected at both the option level and nested definition/key levels.
  # - Order Wrappers Assessment (§4.2): mkBefore / mkAfter (_type == "order") do not bypass
  #   duplicate detection because top-level keys remain visible in raw definition attrsets.
  # - Priority Shadowing Boundary: Under Nix's lib.modules.filterOverrides, if Module A uses
  #   mkDefault and Module B uses default priority (100) on the same option, Nix prunes Module A
  #   prior to definition inspection. Module B wins.
  # - Bounded Cleanup Ownership (§6): Host cleanup of absent contributions is strictly bounded
  #   to known seam-managed identities (knownExternalExtensionIdentities and knownNativeMessagingHosts).
  #   Symlinks are checked against store/legacy paths before unlinking. Dynamic destination-declared
  #   identity registries are deferred to BUX3.

  # Known seam-managed identities for bounded cleanup
  knownExternalExtensionIdentities = [
    "felphkbfjadmcejnibcmcncimlappdde"
  ];
  knownNativeMessagingHosts = [
    "org.keepassxc.keepassxc_browser"
  ];

  # Helper to recognize Nix override wrappers without false-positives on legitimate policy
  # attributes that happen to be named "priority".
  isOverrideWrapper = v:
    builtins.isAttrs v && (v._type or "" == "override");

  # Guard violation detection
  # 1. Non-default priority detection:
  #    - Whole option priority check (when defined, highestPrio must be 100)
  #    - Definition-level override check (scanning raw definitions for _type == "override")
  #    - Nested key override check (scanning attrs for per-key override wrappers)
  checkPriorityViolations = opt:
    let
      wholeOptionViolation =
        if opt.isDefined && opt.highestPrio != 100 then
          [{
            type = "priority-override";
            option = lib.showOption opt.loc;
            loc = opt.loc;
            priority = opt.highestPrio;
            message = "Option ${lib.showOption opt.loc} defined with non-default priority ${toString opt.highestPrio}";
          }]
        else [];

      defs = opt.definitionsWithLocations or [];

      nestedViolations = lib.concatMap (d:
        if builtins.isAttrs d.value then
          (if isOverrideWrapper d.value then
            [{
              type = "priority-override";
              option = lib.showOption opt.loc;
              loc = opt.loc;
              file = d.file;
              priority = d.value.priority or 100;
              message = "Option ${lib.showOption opt.loc} defined with override wrapper in ${d.file}";
            }]
          else [])
          ++
          (lib.concatMap (k:
            let v = d.value.${k}; in
            if isOverrideWrapper v then
              [{
                type = "priority-override";
                option = lib.showOption (opt.loc ++ [ k ]);
                loc = opt.loc ++ [ k ];
                key = k;
                file = d.file;
                priority = v.priority or 100;
                message = "Key ${lib.showOption (opt.loc ++ [ k ])} defined with override priority in ${d.file}";
              }]
            else []
          ) (builtins.attrNames d.value))
        else []
      ) defs;
    in wholeOptionViolation ++ nestedViolations;

  # Priority check for selector options that carry an option-declaration default (priority 1500).
  # Defends against mkForce, mkOverride, mkDefault, etc. while tolerating unset option default.
  checkSelectorPriorityViolations = opt:
    let
      nonDefaultPriority =
        opt.isDefined && opt.highestPrio != 100 && opt.highestPrio != 1500;
      optionDefaultOverride =
        opt.isDefined && opt.highestPrio == 1500 && (
          builtins.length (opt.definitionsWithLocations or []) > 1
          || builtins.any (f: f != "<unknown-file>") (opt.files or [])
        );
    in
      if nonDefaultPriority || optionDefaultOverride then
        [{
          type = "priority-override";
          option = lib.showOption opt.loc;
          loc = opt.loc;
          priority = opt.highestPrio;
          message = "Option ${lib.showOption opt.loc} defined with non-default priority ${toString opt.highestPrio}";
        }]
      else [];

  # 2. Duplicate key detection:
  #    - Across modules, each leaf key must have at most 1 definition.
  #    - Identical values across multiple modules remain duplicate collisions.
  checkDuplicateKeyViolations = opt:
    let
      defs = opt.definitionsWithLocations or [];
      keysWithFiles = lib.foldl (acc: d:
        if builtins.isAttrs d.value then
          lib.foldl (accInner: k:
            accInner // { ${k} = (accInner.${k} or []) ++ [ d.file ]; }
          ) acc (builtins.attrNames d.value)
        else acc
      ) {} defs;
    in
      lib.concatMap (k:
        let files = keysWithFiles.${k}; in
        if builtins.length files > 1 then
          [{
            type = "duplicate-key";
            option = lib.showOption opt.loc;
            loc = opt.loc ++ [ k ];
            key = k;
            files = files;
            message = "Duplicate definition for seam key ${lib.showOption (opt.loc ++ [ k ])} in files: ${builtins.concatStringsSep ", " files}";
          }]
        else []
      ) (builtins.attrNames keysWithFiles);

  checkDuplicatePayloadViolations = opt:
    let defs = opt.definitionsWithLocations or []; in
    if builtins.length defs > 1 then
      [{
        type = "duplicate-key";
        option = lib.showOption opt.loc;
        loc = opt.loc;
        files = map (d: d.file) defs;
        message = "Duplicate definition for seam payload ${lib.showOption opt.loc} in files: ${builtins.concatStringsSep ", " (map (d: d.file) defs)}";
      }]
    else [];

  # 3. Identifier format validation:
  #    Ensures extension IDs and host names match strict safe character sets,
  #    preventing shell escaping or path traversal when interpolated into activation scripts.
  checkKeyFormatViolations = opt: pattern: desc:
    let defs = opt.definitionsWithLocations or []; in
    lib.concatMap (d:
      if builtins.isAttrs d.value then
        lib.concatMap (k:
          if builtins.match pattern k == null then
            [{
              type = "invalid-identifier";
              option = lib.showOption (opt.loc ++ [ k ]);
              loc = opt.loc ++ [ k ];
              key = k;
              file = d.file;
              message = "Invalid ${desc} '${k}' in ${d.file}. Identifier must match pattern '${pattern}'.";
            }]
          else []
        ) (builtins.attrNames d.value)
      else []
    ) defs;

  allPriorityViolations =
    checkPriorityViolations optChromePreferences
    ++ checkPriorityViolations optChromeExtensions
    ++ checkPriorityViolations optChromeNMH
    ++ checkPriorityViolations optFirefoxPolicies
    ++ checkPriorityViolations optFirefoxPoliciesPayload
    ++ checkPriorityViolations optFirefoxNMH
    ++ checkSelectorPriorityViolations optFirefoxPolicyDelivery
    ++ checkPriorityViolations optVivaldiPreferences
    ++ checkPriorityViolations optVivaldiExtensions
    ++ checkPriorityViolations optVivaldiNMH
    ++ checkPriorityViolations optFloorpPolicies;

  allDuplicateViolations =
    checkDuplicateKeyViolations optChromePreferences
    ++ checkDuplicateKeyViolations optChromeExtensions
    ++ checkDuplicateKeyViolations optChromeNMH
    ++ checkDuplicateKeyViolations optFirefoxPolicies
    ++ checkDuplicatePayloadViolations optFirefoxPoliciesPayload
    ++ checkDuplicateKeyViolations optFirefoxNMH
    ++ checkDuplicateKeyViolations optVivaldiPreferences
    ++ checkDuplicateKeyViolations optVivaldiExtensions
    ++ checkDuplicateKeyViolations optVivaldiNMH
    ++ checkDuplicateKeyViolations optFloorpPolicies;

  allIdentifierViolations =
    checkKeyFormatViolations optChromeExtensions "[a-p]{32}" "Chrome extension ID"
    ++ checkKeyFormatViolations optChromeNMH "[a-zA-Z0-9_.-]+" "Chrome NativeMessagingHosts name"
    ++ checkKeyFormatViolations optFirefoxNMH "[a-zA-Z0-9_.-]+" "Firefox NativeMessagingHosts name"
    ++ checkKeyFormatViolations optVivaldiExtensions "[a-p]{32}" "Vivaldi extension ID"
    ++ checkKeyFormatViolations optVivaldiNMH "[a-zA-Z0-9_.-]+" "Vivaldi NativeMessagingHosts name";

  # 4. Legacy-vs-destination exclusivity check:
  hasDefs = opt:
    opt.isDefined && builtins.any (d:
      if builtins.isAttrs d.value then
        d.value != {}
      else
        d.value != null
    ) (opt.definitionsWithLocations or []);

  hasExternalChromePrefs = hasDefs optChromePreferences;
  hasExternalChromeExts = hasDefs optChromeExtensions;
  hasExternalChromeNMH = hasDefs optChromeNMH;
  hasExternalFirefoxPolicies = hasDefs optFirefoxPolicies;
  hasExternalFirefoxPayload = hasDefs optFirefoxPoliciesPayload;
  hasExternalFirefoxNMH = hasDefs optFirefoxNMH;
  hasExternalFirefoxDelivery =
    optFirefoxPolicyDelivery.isDefined && (cfg.firefox.policyDelivery != "bundle");
  hasExternalVivaldiPrefs = hasDefs optVivaldiPreferences;
  hasExternalVivaldiExts = hasDefs optVivaldiExtensions;
  hasExternalVivaldiNMH = hasDefs optVivaldiNMH;
  hasExternalFloorpPolicies = hasDefs optFloorpPolicies;

  hasExternalContribution =
    hasExternalChromePrefs || hasExternalChromeExts || hasExternalChromeNMH
    || hasExternalFirefoxPolicies || hasExternalFirefoxPayload || hasExternalFirefoxNMH
    || hasExternalFirefoxDelivery
    || hasExternalVivaldiPrefs || hasExternalVivaldiExts || hasExternalVivaldiNMH
    || hasExternalFloorpPolicies;

  legacyExclusivityViolations =
    if cfg.legacyPolicyDefaults.enable && hasExternalContribution then
      [{
        type = "legacy-exclusivity";
        option = "programs.browserBaseline.legacyPolicyDefaults.enable";
        loc = [ "programs" "browserBaseline" "legacyPolicyDefaults" "enable" ];
        message = "programs.browserBaseline.legacyPolicyDefaults.enable is true, but external browser baseline contributions are present. Legacy defaults and destination contributions must never merge.";
      }]
    else [];

  # 5. Firefox payload vs structured exclusivity check:
  firefoxPayloadConflictViolations =
    let
      hasPayload = optFirefoxPoliciesPayload.isDefined && (cfg.firefox.policiesJsonPayload != null);
      hasPolicies = optFirefoxPolicies.isDefined && (cfg.firefox.policies != {});
    in
      if hasPayload && hasPolicies then
        [{
          type = "conflicting-definitions";
          option = "programs.browserBaseline.firefox";
          loc = [ "programs" "browserBaseline" "firefox" ];
          message = "Both programs.browserBaseline.firefox.policies and programs.browserBaseline.firefox.policiesJsonPayload are defined. Destinations must contribute either structured policies or an immutable payload, not both.";
        }]
      else [];

  # 6. Firefox macOS preferences vs opaque payload exclusivity check:
  firefoxDeliveryPayloadViolations =
    let
      hasPayload = optFirefoxPoliciesPayload.isDefined && (cfg.firefox.policiesJsonPayload != null);
    in
      if cfg.firefox.policyDelivery == "macos-preferences" && hasPayload then
        [{
          type = "unsupported-delivery-payload";
          option = "programs.browserBaseline.firefox.policiesJsonPayload";
          loc = [ "programs" "browserBaseline" "firefox" "policiesJsonPayload" ];
          message = "programs.browserBaseline.firefox.policiesJsonPayload cannot be used with policyDelivery = \"macos-preferences\". macOS preferences delivery requires structured firefox.policies.";
        }]
      else [];

  # 7. Firefox reserved key check (EnterprisePoliciesEnabled is managed automatically by core):
  firefoxReservedKeyViolations =
    let
      defs = optFirefoxPolicies.definitionsWithLocations or [];
      hasReserved = builtins.any (d:
        builtins.isAttrs d.value && (d.value ? EnterprisePoliciesEnabled)
      ) defs;
    in
      if hasReserved then
        [{
          type = "reserved-key";
          option = "programs.browserBaseline.firefox.policies.EnterprisePoliciesEnabled";
          loc = [ "programs" "browserBaseline" "firefox" "policies" "EnterprisePoliciesEnabled" ];
          message = "Key EnterprisePoliciesEnabled is reserved and managed automatically by the seam. It must not be set in programs.browserBaseline.firefox.policies.";
        }]
      else [];

  # 8. Floorp reserved key check (EnterprisePoliciesEnabled is managed automatically by core):
  floorpReservedKeyViolations =
    let
      defs = optFloorpPolicies.definitionsWithLocations or [];
      hasReserved = builtins.any (d:
        builtins.isAttrs d.value && (d.value ? EnterprisePoliciesEnabled)
      ) defs;
    in
      if hasReserved then
        [{
          type = "reserved-key";
          option = "programs.browserBaseline.floorp.policies.EnterprisePoliciesEnabled";
          loc = [ "programs" "browserBaseline" "floorp" "policies" "EnterprisePoliciesEnabled" ];
          message = "Key EnterprisePoliciesEnabled is reserved and managed automatically by the seam. It must not be set in programs.browserBaseline.floorp.policies.";
        }]
      else [];

  # 9. Null value checks for macOS preference plist generators:
  hasNullValues = val:
    if val == null then
      true
    else if builtins.isAttrs val then
      builtins.any hasNullValues (builtins.attrValues val)
    else if builtins.isList val then
      builtins.any hasNullValues val
    else
      false;

  firefoxNullValueViolations =
    let
      defs = optFirefoxPolicies.definitionsWithLocations or [];
      hasNull = builtins.any (d:
        builtins.isAttrs d.value && hasNullValues d.value
      ) defs;
    in
      if cfg.firefox.policyDelivery == "macos-preferences" && hasNull then
        [{
          type = "unsupported-null-value";
          option = "programs.browserBaseline.firefox.policies";
          loc = [ "programs" "browserBaseline" "firefox" "policies" ];
          message = "programs.browserBaseline.firefox.policies contains null values, which are not supported by the macOS plist generator. Omit attributes or use explicit empty structures instead.";
        }]
      else [];

  floorpNullValueViolations =
    let
      defs = optFloorpPolicies.definitionsWithLocations or [];
      hasNull = builtins.any (d:
        builtins.isAttrs d.value && hasNullValues d.value
      ) defs;
    in
      if hasNull then
        [{
          type = "unsupported-null-value";
          option = "programs.browserBaseline.floorp.policies";
          loc = [ "programs" "browserBaseline" "floorp" "policies" ];
          message = "programs.browserBaseline.floorp.policies contains null values, which are not supported by the macOS plist generator. Omit attributes or use explicit empty structures instead.";
        }]
      else [];

  vivaldiNullValueViolations =
    let
      defs = optVivaldiPreferences.definitionsWithLocations or [];
      hasNull = builtins.any (d:
        builtins.isAttrs d.value && hasNullValues d.value
      ) defs;
    in
      if hasNull then
        [{
          type = "unsupported-null-value";
          option = "programs.browserBaseline.vivaldi.managedPreferences";
          loc = [ "programs" "browserBaseline" "vivaldi" "managedPreferences" ];
          message = "programs.browserBaseline.vivaldi.managedPreferences contains null values, which are not supported by the macOS plist generator. Omit attributes or use explicit empty structures instead.";
        }]
      else [];

  guardViolations =
    allPriorityViolations
    ++ allDuplicateViolations
    ++ allIdentifierViolations
    ++ legacyExclusivityViolations
    ++ firefoxPayloadConflictViolations
    ++ firefoxDeliveryPayloadViolations
    ++ firefoxReservedKeyViolations
    ++ firefoxNullValueViolations
    ++ floorpReservedKeyViolations
    ++ floorpNullValueViolations
    ++ vivaldiNullValueViolations;

  # Effective contribution resolution
  effectiveChromePreferences =
    if guardViolations != [] then
      {}
    else if cfg.legacyPolicyDefaults.enable then
      legacyChromePolicyDefaults
    else if optChromePreferences.isDefined then
      cfg.chrome.managedPreferences
    else
      {};

  effectiveChromeExtensions =
    if guardViolations != [] then
      {}
    else if cfg.legacyPolicyDefaults.enable then
      { "felphkbfjadmcejnibcmcncimlappdde" = legacyClearNewTabExternalExtension; }
    else if optChromeExtensions.isDefined then
      cfg.chrome.externalExtensions
    else
      {};

  effectiveChromeNMH =
    if guardViolations != [] then
      {}
    else if cfg.legacyPolicyDefaults.enable then
      { "org.keepassxc.keepassxc_browser" = legacyKeepassxcChromeNativeMessaging; }
    else if optChromeNMH.isDefined then
      cfg.chrome.nativeMessagingHosts
    else
      {};

  effectiveFirefoxPolicies =
    if guardViolations != [] then
      {}
    else if optFirefoxPolicies.isDefined then
      cfg.firefox.policies
    else
      {};

  effectiveFirefoxPreferences =
    if guardViolations != [] then
      {}
    else if cfg.firefox.policyDelivery != "macos-preferences" then
      {}
    else if effectiveFirefoxPolicies != {} then
      { EnterprisePoliciesEnabled = true; } // (builtins.removeAttrs effectiveFirefoxPolicies [ "EnterprisePoliciesEnabled" ])
    else
      {};

  effectiveFirefoxPoliciesFile =
    if guardViolations != [] then
      null
    else if cfg.firefox.policyDelivery == "macos-preferences" then
      null
    else if cfg.legacyPolicyDefaults.enable then
      legacyFirefoxPolicies
    else if optFirefoxPoliciesPayload.isDefined && (cfg.firefox.policiesJsonPayload != null) then
      cfg.firefox.policiesJsonPayload
    else if effectiveFirefoxPolicies != {} then
      pkgs.writeText "policies.json" (builtins.toJSON { policies = effectiveFirefoxPolicies; })
    else
      null;

  effectiveFirefoxNMH =
    if guardViolations != [] then
      {}
    else if cfg.legacyPolicyDefaults.enable then
      { "org.keepassxc.keepassxc_browser" = legacyKeepassxcFirefoxNativeMessaging; }
    else if optFirefoxNMH.isDefined then
      cfg.firefox.nativeMessagingHosts
    else
      {};

  effectiveVivaldiPreferences =
    if guardViolations != [] then
      {}
    else if optVivaldiPreferences.isDefined then
      cfg.vivaldi.managedPreferences
    else
      {};

  effectiveVivaldiExtensions =
    if guardViolations != [] then
      {}
    else if optVivaldiExtensions.isDefined then
      cfg.vivaldi.externalExtensions
    else
      {};

  effectiveVivaldiNMH =
    if guardViolations != [] then
      {}
    else if optVivaldiNMH.isDefined then
      cfg.vivaldi.nativeMessagingHosts
    else
      {};

  effectiveFloorpPolicies =
    if guardViolations != [] then
      {}
    else if optFloorpPolicies.isDefined then
      cfg.floorp.policies
    else
      {};

  effectiveFloorpPreferences =
    if guardViolations != [] then
      {}
    else if effectiveFloorpPolicies != {} then
      { EnterprisePoliciesEnabled = true; } // (builtins.removeAttrs effectiveFloorpPolicies [ "EnterprisePoliciesEnabled" ])
    else
      {};

  resolveArtifactFile = name: value:
    if builtins.isPath value then
      value
    else if builtins.isAttrs value && (value ? payload) then
      value.payload
    else if builtins.isAttrs value then
      pkgs.writeText "${name}.json" (builtins.toJSON value)
    else
      throw "Invalid artifact value for ${name}";

  effectiveChromeExtensionFiles =
    lib.mapAttrs resolveArtifactFile effectiveChromeExtensions;

  effectiveChromeNMHFiles =
    lib.mapAttrs resolveArtifactFile effectiveChromeNMH;

  effectiveFirefoxNMHFiles =
    lib.mapAttrs resolveArtifactFile effectiveFirefoxNMH;

  effectiveVivaldiExtensionFiles =
    lib.mapAttrs resolveArtifactFile effectiveVivaldiExtensions;

  effectiveVivaldiNMHFiles =
    lib.mapAttrs resolveArtifactFile effectiveVivaldiNMH;

  chromeManagedPlist =
    if effectiveChromePreferences != {} then
      pkgs.writeText "com.google.Chrome.plist" (lib.generators.toPlist { escape = true; } effectiveChromePreferences)
    else
      null;

  firefoxManagedPlist =
    if guardViolations != [] then
      null
    else if cfg.firefox.policyDelivery == "macos-preferences" && effectiveFirefoxPreferences != {} then
      pkgs.writeText "org.mozilla.firefox.plist" (lib.generators.toPlist { escape = true; } effectiveFirefoxPreferences)
    else
      null;

  vivaldiManagedPlist =
    if guardViolations != [] then
      null
    else if effectiveVivaldiPreferences != {} then
      pkgs.writeText "com.vivaldi.Vivaldi.plist" (lib.generators.toPlist { escape = true; } effectiveVivaldiPreferences)
    else
      null;

  floorpManagedPlist =
    if guardViolations != [] then
      null
    else if effectiveFloorpPreferences != {} then
      pkgs.writeText "app.floorp.Floorp.plist" (lib.generators.toPlist { escape = true; } effectiveFloorpPreferences)
    else
      null;

  # KeePassXC's supported Vivaldi installer uses the primary user's Library.
  # Do not invent a second system root from Chromium family membership.
  primaryUser = config.system.primaryUser or null;
  primaryHome = if primaryUser == null then null else config.users.users.${primaryUser}.home;
  vivaldiNativeRoot = if effectiveVivaldiNMHFiles == {} then null
    else if primaryHome == null then throw "Vivaldi native delivery requires the configured primary user's home"
    else "${primaryHome}/Library/Application Support/Vivaldi/NativeMessagingHosts";

  attendedTargets =
    lib.optional (chromeManagedPlist != null) { target = "/Library/Managed Preferences/com.google.Chrome.plist"; source = chromeManagedPlist; }
    ++ lib.optional (firefoxManagedPlist != null) { target = "/Library/Preferences/org.mozilla.firefox.plist"; source = firefoxManagedPlist; }
    ++ lib.optional (vivaldiManagedPlist != null) { target = "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"; source = vivaldiManagedPlist; }
    ++ lib.optional (floorpManagedPlist != null) { target = "/Library/Preferences/app.floorp.Floorp.plist"; source = floorpManagedPlist; }
    ++ lib.mapAttrsToList (id: source: { target = "/Library/Application Support/Google/Chrome/External Extensions/${id}.json"; inherit source; }) effectiveChromeExtensionFiles
    ++ lib.mapAttrsToList (id: source: { target = "/Library/Application Support/Vivaldi/External Extensions/${id}.json"; inherit source; }) effectiveVivaldiExtensionFiles
    ++ lib.mapAttrsToList (name: source: { target = "/Library/Google/Chrome/NativeMessagingHosts/${name}.json"; inherit source; }) effectiveChromeNMHFiles
    ++ lib.mapAttrsToList (name: source: { target = "/Library/Application Support/Mozilla/NativeMessagingHosts/${name}.json"; inherit source; }) effectiveFirefoxNMHFiles
    ++ lib.mapAttrsToList (name: source: { target = "${vivaldiNativeRoot}/${name}.json"; inherit source; perUser = true; }) effectiveVivaldiNMHFiles;
  makeAttendedApply = name: targets: pkgs.writeShellScript name ''
    set -eu
    test "$(id -u)" -eq 0
    ${lib.concatMapStrings (row: ''
      parent=${lib.escapeShellArg (builtins.dirOf row.target)}
      if [ ! -d "$parent" ]; then
        install -d -m 0755 "$parent"
        ${lib.optionalString (row.perUser or false) "chown ${lib.escapeShellArg primaryUser} \"$parent\""}
      fi
      target=${lib.escapeShellArg row.target}
      # Break an existing manifest symlink before replacing its link entry.
      if [ -L "$target" ]; then rm "$target"; fi
      install -m 0644 ${lib.escapeShellArg (toString row.source)} "$target"
      ${lib.optionalString (row.perUser or false) "chown ${lib.escapeShellArg primaryUser} \"$target\""}
    '') targets}
  '';
  attendedApply = makeAttendedApply "browser-baseline-attended-apply" attendedTargets;
  attendedTargetsByBrowser = {
    chrome = builtins.filter (row: lib.hasInfix "com.google.Chrome.plist" row.target || lib.hasInfix "/Google/Chrome/" row.target) attendedTargets;
    firefox = builtins.filter (row: lib.hasInfix "org.mozilla.firefox.plist" row.target || lib.hasInfix "/Mozilla/NativeMessagingHosts/" row.target) attendedTargets;
    vivaldi = builtins.filter (row: lib.hasInfix "Vivaldi" row.target) attendedTargets;
    floorp = builtins.filter (row: lib.hasInfix "app.floorp.Floorp.plist" row.target || lib.hasInfix "/Mozilla/NativeMessagingHosts/" row.target) attendedTargets;
  };
  attendedApplyByBrowser = lib.mapAttrs (browser: targets:
    makeAttendedApply "browser-baseline-attended-${browser}" targets) attendedTargetsByBrowser;
in
{
  options.programs.browserBaseline = {
    replacementPolicyOwnership = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicit ownership of Vivaldi/Floorp policy targets, including retraction
        when those endpoints become absent. Leave false on unselected hosts.
        Native registrations owned by KeePassXC are outside this retraction.
      '';
    };
    legacyPolicyDefaults.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to render current legacy browser policies and extension configurations
        from config/browser/*. Declared with option-declaration default of true.
        Must be set to false when external or domain contributions are provided.
      '';
    };

    chrome = {
      managedPreferences = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Chrome managed policy values written to /Library/Managed Preferences/com.google.Chrome.plist.
          Each attribute name is a top-level policy key (e.g. BlockThirdPartyCookies, ExtensionSettings).
        '';
      };

      externalExtensions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Chrome external extensions mapping extension IDs to either a manifest path, a payload record,
          or a structured attribute set. Extension IDs must be 32-character identifiers matching [a-p]{32}.
        '';
      };

      nativeMessagingHosts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Chrome NativeMessagingHosts mapping host names to JSON manifest paths or attribute sets.
          Host names must match [a-zA-Z0-9_.-]+.
        '';
      };
    };

    firefox = {
      policyDelivery = lib.mkOption {
        type = lib.types.enum [ "bundle" "macos-preferences" ];
        default = "bundle";
        description = ''
          Delivery mechanism for Firefox enterprise policies.
          - "bundle": writes /Applications/Firefox.app/Contents/Resources/distribution/policies.json
          - "macos-preferences": writes /Library/Preferences/org.mozilla.firefox.plist
        '';
      };

      policies = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Firefox enterprise policy values. When rendered without policiesJsonPayload,
          the physical writer places these under the top-level 'policies' JSON object.
        '';
      };

      policiesJsonPayload = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        description = ''
          Immutable policies.json payload file (containing the full JSON with top-level 'policies' key)
          used to preserve exact byte parity. Mutually exclusive with firefox.policies.
        '';
      };

      nativeMessagingHosts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Firefox NativeMessagingHosts mapping host names to JSON manifest paths or attribute sets.
          Host names must match [a-zA-Z0-9_.-]+.
        '';
      };
    };

    vivaldi = {
      managedPreferences = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Vivaldi managed policy values written to /Library/Managed Preferences/com.vivaldi.Vivaldi.plist.
          Each attribute name is a top-level policy key.
        '';
      };

      externalExtensions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Vivaldi external extensions mapping extension IDs to either a manifest path, a payload record,
          or a structured attribute set. Extension IDs must be 32-character identifiers matching [a-p]{32}.
        '';
      };

      nativeMessagingHosts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Vivaldi NativeMessagingHosts mapping host names to JSON manifest paths or attribute sets.
          Host names must match [a-zA-Z0-9_.-]+.
        '';
      };
    };

    floorp = {
      policies = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Floorp enterprise policy values written to /Library/Preferences/app.floorp.Floorp.plist.
        '';
      };
    };
  };

  config = {
    environment.systemPackages = [
      pkgs.google-chrome
    ];

    homebrew.casks = [
      "firefox"
    ];

    assertions = [
      {
        assertion = guardViolations == [];
        message = "Browser baseline seam guard violations:\n"
          + lib.concatMapStringsSep "\n" (v: "  - [${v.type}] ${v.message}") guardViolations;
      }
    ];

    system.build.browserBaseline = {
      inherit attendedTargets attendedApply attendedTargetsByBrowser attendedApplyByBrowser;
      attendedOwner = "core/programs.browserBaseline";
      inherit guardViolations;
      inherit chromeManagedPlist;
      chromeExternalExtensions = effectiveChromeExtensionFiles;
      chromeNativeMessagingHosts = effectiveChromeNMHFiles;
      firefoxPolicyDelivery = cfg.firefox.policyDelivery;
      firefoxPolicies = effectiveFirefoxPoliciesFile;
      firefoxManagedPlist = firefoxManagedPlist;
      firefoxPreferences = effectiveFirefoxPreferences;
      firefoxNativeMessagingHosts = effectiveFirefoxNMHFiles;
      vivaldiManagedPlist = vivaldiManagedPlist;
      vivaldiExternalExtensions = effectiveVivaldiExtensionFiles;
      vivaldiNativeMessagingHosts = effectiveVivaldiNMHFiles;
      floorpManagedPlist = floorpManagedPlist;
      floorpPreferences = effectiveFloorpPreferences;
      effectiveState = {
        legacyDefaultsEnabled = cfg.legacyPolicyDefaults.enable;
        hasChromePreferences = effectiveChromePreferences != {};
        chromePreferenceCount = builtins.length (builtins.attrNames effectiveChromePreferences);
        externalExtensionIds = builtins.attrNames effectiveChromeExtensions;
        chromeNativeMessagingHostNames = builtins.attrNames effectiveChromeNMH;
        firefoxPolicyDelivery = cfg.firefox.policyDelivery;
        hasFirefoxPolicies = (effectiveFirefoxPoliciesFile != null) || (firefoxManagedPlist != null);
        hasFirefoxPlist = firefoxManagedPlist != null;
        firefoxNativeMessagingHostNames = builtins.attrNames effectiveFirefoxNMH;
        hasVivaldiPreferences = effectiveVivaldiPreferences != {};
        vivaldiPreferenceCount = builtins.length (builtins.attrNames effectiveVivaldiPreferences);
        vivaldiExternalExtensionIds = builtins.attrNames effectiveVivaldiExtensions;
        vivaldiNativeMessagingHostNames = builtins.attrNames effectiveVivaldiNMH;
        hasFloorpPolicies = effectiveFloorpPreferences != {};
        hasFloorpPlist = floorpManagedPlist != null;
        floorpPolicyCount = builtins.length (builtins.attrNames effectiveFloorpPolicies);
      };
    };

    system.activationScripts.postActivation.text = ''
      echo "setting up browser policies..."

      # Chrome Managed Preferences
      ${if chromeManagedPlist != null then ''
        install -d -m 0755 "/Library/Managed Preferences"
        install -m 0644 "${chromeManagedPlist}" "/Library/Managed Preferences/com.google.Chrome.plist"
      '' else ''
        if [ -f "/Library/Managed Preferences/com.google.Chrome.plist" ]; then
          rm -f "/Library/Managed Preferences/com.google.Chrome.plist"
        fi
      ''}

      # Stale Chrome preference cleanup
      ${lib.optionalString (!(effectiveChromePreferences ? PasswordManagerEnabled)) ''defaults delete "/Library/Managed Preferences/com.google.Chrome" PasswordManagerEnabled >/dev/null 2>&1 || true''}
      defaults delete "/Library/Preferences/com.google.Chrome" PasswordManagerEnabled >/dev/null 2>&1 || true
      ${lib.optionalString (!(effectiveChromePreferences ? AutofillCreditCardEnabled)) ''defaults delete "/Library/Managed Preferences/com.google.Chrome" AutofillCreditCardEnabled >/dev/null 2>&1 || true''}
      defaults delete "/Library/Preferences/com.google.Chrome" AutofillCreditCardEnabled >/dev/null 2>&1 || true
      ${lib.optionalString (!(effectiveChromePreferences ? AutofillAddressEnabled)) ''defaults delete "/Library/Managed Preferences/com.google.Chrome" AutofillAddressEnabled >/dev/null 2>&1 || true''}
      defaults delete "/Library/Preferences/com.google.Chrome" AutofillAddressEnabled >/dev/null 2>&1 || true
      killall cfprefsd >/dev/null 2>&1 || true

      recommendedChromePolicy="/Library/Preferences/com.google.Chrome.plist"
      if [ -f "$recommendedChromePolicy" ] && cmp -s "${legacyChromePolicyFile}" "$recommendedChromePolicy"; then
        rm "$recommendedChromePolicy"
      fi

      # Chrome External Extensions
      chromeExternalRoot="/Library/Application Support/Google"
      chromeExternalProfileRoot="$chromeExternalRoot/Chrome"
      chromeExternalExtensionsDir="/Library/Application Support/Google/Chrome/External Extensions"
      ${if effectiveChromeExtensionFiles != {} then ''
        install -d -m 0755 "$chromeExternalExtensionsDir"
        chown root:wheel "$chromeExternalRoot" "$chromeExternalProfileRoot" "$chromeExternalExtensionsDir"
        chmod 0755 "$chromeExternalRoot" "$chromeExternalProfileRoot" "$chromeExternalExtensionsDir"
        ${lib.concatStrings (lib.mapAttrsToList (id: file: ''
          install -m 0644 "${file}" "$chromeExternalExtensionsDir/${id}.json"
          chown root:wheel "$chromeExternalExtensionsDir/${id}.json"
          chmod 0644 "$chromeExternalExtensionsDir/${id}.json"
        '') effectiveChromeExtensionFiles)}
      '' else ""}
      # Bounded cleanup for seam-owned external extensions
      ${lib.concatMapStrings (id: ''
        ${if ! (effectiveChromeExtensions ? "${id}") then ''
          if [ -f "$chromeExternalExtensionsDir/${id}.json" ]; then
            rm -f "$chromeExternalExtensionsDir/${id}.json"
          fi
        '' else ""}
      '') knownExternalExtensionIdentities}

      # Chrome Native Messaging Hosts
      ${if effectiveChromeNMHFiles != {} then ''
        install -d -m 0755 "/Library/Google/Chrome/NativeMessagingHosts"
        ${lib.concatStrings (lib.mapAttrsToList (name: file: ''
          ln -sfn "${file}" "/Library/Google/Chrome/NativeMessagingHosts/${name}.json"
        '') effectiveChromeNMHFiles)}
      '' else ""}
      # Bounded cleanup for seam-owned Chrome NativeMessagingHosts symlinks
      ${lib.concatMapStrings (name: ''
        ${if ! (effectiveChromeNMH ? "${name}") then ''
          chromeNMH="/Library/Google/Chrome/NativeMessagingHosts/${name}.json"
          if [ -L "$chromeNMH" ] || [ -f "$chromeNMH" ]; then
            target="$(readlink "$chromeNMH" || true)"
            case "$target" in
              /nix/store/*|*/config/browser/keepassxc-*)
                rm -f "$chromeNMH"
                ;;
            esac
          fi
        '' else ""}
      '') knownNativeMessagingHosts}

      # Mozilla Native Messaging Hosts
      ${if effectiveFirefoxNMHFiles != {} then ''
        install -d -m 0755 "/Library/Application Support/Mozilla/NativeMessagingHosts"
        ${lib.concatStrings (lib.mapAttrsToList (name: file: ''
          ln -sfn "${file}" "/Library/Application Support/Mozilla/NativeMessagingHosts/${name}.json"
        '') effectiveFirefoxNMHFiles)}
      '' else ""}
      # Bounded cleanup for seam-owned Mozilla NativeMessagingHosts symlinks
      ${lib.concatMapStrings (name: ''
        ${if ! (effectiveFirefoxNMH ? "${name}") then ''
          mozillaNMH="/Library/Application Support/Mozilla/NativeMessagingHosts/${name}.json"
          if [ -L "$mozillaNMH" ] || [ -f "$mozillaNMH" ]; then
            target="$(readlink "$mozillaNMH" || true)"
            case "$target" in
              /nix/store/*|*/config/browser/keepassxc-*)
                rm -f "$mozillaNMH"
                ;;
            esac
          fi
        '' else ""}
      '') knownNativeMessagingHosts}

      # Firefox Policies
      firefoxPolicyDir="/Applications/Firefox.app/Contents/Resources/distribution"
      ${if cfg.firefox.policyDelivery == "macos-preferences" then ''
        ${if firefoxManagedPlist != null then ''
          install -d -m 0755 "/Library/Preferences"
          install -o root -g wheel -m 0644 "${firefoxManagedPlist}" "/Library/Preferences/org.mozilla.firefox.plist.tmp.$$"
          mv -f "/Library/Preferences/org.mozilla.firefox.plist.tmp.$$" "/Library/Preferences/org.mozilla.firefox.plist"
          killall cfprefsd >/dev/null 2>&1 || true
        '' else ''
          if [ -f "/Library/Preferences/org.mozilla.firefox.plist" ]; then
            rm -f "/Library/Preferences/org.mozilla.firefox.plist"
            killall cfprefsd >/dev/null 2>&1 || true
          fi
        ''}
        if [ -f "$firefoxPolicyDir/policies.json" ]; then
          rm -f "$firefoxPolicyDir/policies.json"
        fi
      '' else ''
        ${if effectiveFirefoxPoliciesFile != null then ''
          if [ -d "/Applications/Firefox.app" ]; then
            install -d -m 0755 "$firefoxPolicyDir"
            install -m 0644 "${effectiveFirefoxPoliciesFile}" "$firefoxPolicyDir/policies.json"
          else
            echo "WARNING: [browserBaseline] Firefox policy is configured but /Applications/Firefox.app was not found; policies.json not installed" >&2
          fi
        '' else ''
          if [ -f "$firefoxPolicyDir/policies.json" ]; then
            rm -f "$firefoxPolicyDir/policies.json"
          fi
        ''}
        if [ -f "/Library/Preferences/org.mozilla.firefox.plist" ]; then
          rm -f "/Library/Preferences/org.mozilla.firefox.plist"
          killall cfprefsd >/dev/null 2>&1 || true
        fi
      ''}

      ${lib.optionalString (cfg.replacementPolicyOwnership || vivaldiManagedPlist != null || effectiveVivaldiExtensionFiles != {} || effectiveVivaldiNMHFiles != {}) ''
      # Vivaldi Managed Preferences (only an explicitly selected endpoint)
      ${if vivaldiManagedPlist != null then ''
        install -d -m 0755 "/Library/Managed Preferences"
        install -m 0644 "${vivaldiManagedPlist}" "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"
      '' else lib.optionalString cfg.replacementPolicyOwnership ''
        rm -f "/Library/Managed Preferences/com.vivaldi.Vivaldi.plist"
      ''}

      # Vivaldi External Extensions
      vivaldiExternalRoot="/Library/Application Support/Vivaldi"
      vivaldiExternalExtensionsDir="/Library/Application Support/Vivaldi/External Extensions"
      ${if effectiveVivaldiExtensionFiles != {} then ''
        install -d -m 0755 "$vivaldiExternalExtensionsDir"
        chown root:wheel "$vivaldiExternalRoot" "$vivaldiExternalExtensionsDir"
        chmod 0755 "$vivaldiExternalRoot" "$vivaldiExternalExtensionsDir"
        ${lib.concatStrings (lib.mapAttrsToList (id: file: ''
          install -m 0644 "${file}" "$vivaldiExternalExtensionsDir/${id}.json"
          chown root:wheel "$vivaldiExternalExtensionsDir/${id}.json"
          chmod 0644 "$vivaldiExternalExtensionsDir/${id}.json"
        '') effectiveVivaldiExtensionFiles)}
      '' else ""}
      # Only explicitly owned, known external manifests are retracted.
      ${lib.optionalString cfg.replacementPolicyOwnership (lib.concatMapStrings (id:
        lib.optionalString (!(effectiveVivaldiExtensions ? "${id}")) ''
          rm -f "$vivaldiExternalExtensionsDir/${id}.json"
        '') knownExternalExtensionIdentities)}

      # Vivaldi Native Messaging Hosts
      ${if effectiveVivaldiNMHFiles != {} then ''
        if [ ! -d ${lib.escapeShellArg vivaldiNativeRoot} ]; then
          install -d -m 0755 ${lib.escapeShellArg vivaldiNativeRoot}
          chown ${lib.escapeShellArg primaryUser} ${lib.escapeShellArg vivaldiNativeRoot}
        fi
        ${lib.concatStrings (lib.mapAttrsToList (name: file: ''
          ln -sfn "${file}" ${lib.escapeShellArg "${vivaldiNativeRoot}/${name}.json"}
          chown -h ${lib.escapeShellArg primaryUser} ${lib.escapeShellArg "${vivaldiNativeRoot}/${name}.json"}
        '') effectiveVivaldiNMHFiles)}
      '' else ""}
      ''}

      ${if floorpManagedPlist != null then ''
        # Floorp Policies (macOS preferences)
        install -d -m 0755 "/Library/Preferences"
        install -o root -g wheel -m 0644 "${floorpManagedPlist}" "/Library/Preferences/app.floorp.Floorp.plist.tmp.$$"
        mv -f "/Library/Preferences/app.floorp.Floorp.plist.tmp.$$" "/Library/Preferences/app.floorp.Floorp.plist"
        killall cfprefsd >/dev/null 2>&1 || true
      '' else lib.optionalString cfg.replacementPolicyOwnership ''
        rm -f "/Library/Preferences/app.floorp.Floorp.plist"
        killall cfprefsd >/dev/null 2>&1 || true
      ''}
    '';
  };
}
