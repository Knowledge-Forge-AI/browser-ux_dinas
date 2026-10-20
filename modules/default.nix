{ config, options ? {}, lib, ... }:
let
  extensionPolicy = import ../config/browser/extension-policy.nix;
  keepassxcEnabled = config."browser-ux".configuration.keepassxc.enable;
  optOut = config."browser-ux".configuration.extensions."default-on-opt-out";
  replacements = import ../config/browser/replacements;
  replacementConfig = config."browser-ux".configuration.replacements;
  trial = config."browser-ux".configuration.extensions."apple-proton-trial";
  currentHost = (config.networking.hostName or "") == "example-current-mac";
  appleProtonEnabled = trial.enable && currentHost;
  omitAppleProtonVpn = trial."vivaldi-vpn-route" == "integrated";
  rendering = config."browser-ux".replacementRendering;
  replacementOption = source: lib.mkOption {
    description = "Shared family replacement candidate; the current personal host selects core-owned attended delivery.";
    default = { };
    type = lib.types.submodule {
      options = {
        enable = lib.mkOption { type = lib.types.bool; default = false; };
        "inherit-from" = lib.mkOption { type = lib.types.enum [ source ]; default = source; };
      } // lib.optionalAttrs (source == "chrome") {
        mail = lib.mkOption {
          description = "Optional Mail request; separately qualified and never delivered by Browser UX.";
          default = { };
          type = lib.types.submodule {
            options = {
              enable = lib.mkOption { type = lib.types.bool; default = false; };
              "preserve-resolved" = lib.mkOption {
                type = lib.types.bool; default = false;
                description = "Preserve this host's operator-resolved Mail, Calendar and Feeds selection; no profile writer.";
              };
            };
          };
        };
      };
    };
  };
in
{
  # BUX3B2B destination module: contributes durable browser policy values to programs.browserBaseline
  # through the generic core seam, selecting durable macOS preferences delivery for Firefox
  # while core remains the sole physical root-path writer.
  # System packages, casks, activation scripts, launchd agents, sudoers,
  # and command namespaces are deferred to later migration milestones.

  options."browser-ux".configuration = lib.mkOption {
    description = "Public-capable browser UX destination configuration schema.";
    default = {
      schema = 1;
      keepassxc.enable = true;
      extensions."default-on-opt-out" = [ ];
    };
    type = lib.types.submodule {
      options = {
        schema = lib.mkOption {
          description = "Browser UX configuration schema version.";
          type = lib.types.enum [ 1 ];
          default = 1;
        };
        keepassxc = lib.mkOption {
          description = "KeePassXC browser integration configuration.";
          default = { };
          type = lib.types.submodule {
            options.enable = lib.mkOption {
              description = "Whether KeePassXC browser integration is enabled.";
              type = lib.types.bool;
              default = true;
            };
          };
        };
        extensions = lib.mkOption {
          description = "Browser UX extension configuration.";
          default = { };
          type = lib.types.submodule {
            # Note: The kebab-case option name `default-on-opt-out` directly matches the TOML
            # key in [browser-ux.extensions], preserving 1:1 projection from builtins.fromTOML.
            options."default-on-opt-out" = lib.mkOption {
              description = "List of browser-qualified extension identities to opt out from default-on management.";
              type = lib.types.listOf lib.types.str;
              default = [ ];
            };
            options."apple-proton-trial" = lib.mkOption {
              default = { };
              description = "Explicit three-product trial, effective only on the current personal host and four selected browsers.";
              type = lib.types.submodule {
                options = {
                  enable = lib.mkOption { type = lib.types.bool; default = false; };
                  host = lib.mkOption { type = lib.types.enum [ "example-current-mac" ]; default = "example-current-mac"; };
                  "vivaldi-vpn-route" = lib.mkOption { type = lib.types.enum [ "standalone" "integrated" ]; default = "standalone"; };
                  "integrated-vpn-id" = lib.mkOption { type = lib.types.str; default = ""; };
                };
              };
            };
          };
        };
        replacements = lib.mkOption {
          description = "Closed family inheritance configuration for replacement candidates.";
          default = { };
          type = lib.types.submodule {
            options = {
              vivaldi = (replacementOption "chrome") // {
                type = lib.types.submodule {
                  options = {
                    enable = lib.mkOption { type = lib.types.bool; default = false; };
                    "inherit-from" = lib.mkOption { type = lib.types.enum [ "chrome" ]; default = "chrome"; };
                    mail = lib.mkOption {
                      description = "Optional Mail request; separately qualified and never delivered by Browser UX.";
                      default = { };
                      type = lib.types.submodule {
                        options = {
                          enable = lib.mkOption { type = lib.types.bool; default = false; };
                          "preserve-resolved" = lib.mkOption {
                            type = lib.types.bool; default = false;
                            description = "Preserve this host's operator-resolved Mail, Calendar and Feeds selection; no profile writer.";
                          };
                          "ui-intent" = lib.mkOption {
                            type = lib.types.nullOr (lib.types.enum [ "feeds-only" "full" "disabled" ]);
                            default = null;
                            description = "Expressed UI intent without raw preference invention.";
                          };
                        };
                      };
                    };
                    productivity = lib.mkOption {
                      description = "Supported UI intent for Vivaldi Mail, Calendar and Feeds with data retention.";
                      default = null;
                      type = lib.types.nullOr (lib.types.submodule {
                        options = {
                          intent = lib.mkOption { type = lib.types.enum [ "feeds-only" "full" "disabled" ]; default = "feeds-only"; };
                          "data-retention" = lib.mkOption { type = lib.types.bool; default = true; };
                        };
                      });
                    };
                  };
                };
              };
              floorp = replacementOption "firefox";
            };
          };
        };
        primaryCutover = lib.mkOption {
          description = "Primary Browser UX cutover intent and decoupled provider/lifecycle configuration.";
          default = null;
          type = lib.types.nullOr (lib.types.submodule {
            options = {
              enable = lib.mkOption { type = lib.types.bool; default = false; };
              activeBrowsers = lib.mkOption {
                type = lib.types.listOf (lib.types.enum [ "chrome" "firefox" "vivaldi" "floorp" "safari" ]);
                default = [ "vivaldi" "floorp" "safari" ];
              };
              retiredBrowsers = lib.mkOption {
                type = lib.types.listOf (lib.types.enum [ "chrome" "firefox" "vivaldi" "floorp" "safari" ]);
                default = [ "chrome" "firefox" ];
              };
              credentialProvider = lib.mkOption {
                type = lib.types.enum [ "apple" "keepassxc" "legacy" ];
                default = "apple";
              };
              productivityIntent = lib.mkOption {
                type = lib.types.enum [ "feeds-only" "full" "disabled" ];
                default = "feeds-only";
              };
              protonVpnEnabled = lib.mkOption {
                type = lib.types.nullOr lib.types.bool; default = null;
                description = "Independent Proton VPN source; an enabled cutover must explicitly preserve the selected posture.";
              };
            };
          });
        };
      };
    };
    apply =
      cfg:
      let
        validationError = extensionPolicy.validateConfiguration cfg;
        baseReplacements = {
          floorp = cfg.replacements.floorp;
          vivaldi = {
            inherit (cfg.replacements.vivaldi) enable;
            inherit (cfg.replacements.vivaldi) inherit-from;
            mail = {
              inherit (cfg.replacements.vivaldi.mail) enable;
              inherit (cfg.replacements.vivaldi.mail) preserve-resolved;
            } // lib.optionalAttrs (cfg.replacements.vivaldi.mail ? ui-intent && cfg.replacements.vivaldi.mail.ui-intent != null) {
              inherit (cfg.replacements.vivaldi.mail) ui-intent;
            };
          } // lib.optionalAttrs (cfg.replacements.vivaldi ? productivity && cfg.replacements.vivaldi.productivity != null) {
            inherit (cfg.replacements.vivaldi) productivity;
          };
        };
        baseCfg = {
          inherit (cfg) schema keepassxc extensions;
          replacements = baseReplacements;
        };
        extraKeys = lib.optionalAttrs (cfg.primaryCutover != null) {
          inherit (cfg) primaryCutover;
        };
      in
      if cfg.primaryCutover != null && cfg.primaryCutover.enable && cfg.primaryCutover.protonVpnEnabled == null then
        throw "Enabled primaryCutover requires explicit protonVpnEnabled; never infer VPN removal from credential choice"
      else if cfg.primaryCutover != null && cfg.primaryCutover.enable &&
        (lib.unique cfg.primaryCutover.activeBrowsers != cfg.primaryCutover.activeBrowsers
        || lib.unique cfg.primaryCutover.retiredBrowsers != cfg.primaryCutover.retiredBrowsers
        || builtins.any (name: builtins.elem name cfg.primaryCutover.retiredBrowsers) cfg.primaryCutover.activeBrowsers) then
        builtins.throw "Browser lifecycle selections must be unique and active/retired selections disjoint"
      else if cfg.extensions."apple-proton-trial"."vivaldi-vpn-route" == "integrated"
        && builtins.match "[a-p]{32}" cfg.extensions."apple-proton-trial"."integrated-vpn-id" == null then
        builtins.throw "Integrated Vivaldi VPN reuse requires the observed actual extension identity; attended check must verify its instance"
      else if validationError != null then builtins.throw validationError
      else builtins.seq (if cfg.primaryCutover != null && cfg.primaryCutover.enable && cfg.primaryCutover.productivityIntent == "feeds-only"
        then true else replacements.validateMailRequest "vivaldi" {
        replacementEnabled = cfg.replacements.vivaldi.enable;
        mailEnabled = cfg.replacements.vivaldi.mail.enable;
        currentHostResolved = currentHost && cfg.replacements.vivaldi.mail."preserve-resolved";
        preserveResolved = currentHost && cfg.replacements.vivaldi.mail."preserve-resolved";
      } replacements.runtimeIssues) (baseCfg // extraKeys);
  };

  options."browser-ux".replacementRendering = lib.mkOption {
    description = "Trial delivery candidates and separate fail-closed effective parity records.";
    type = lib.types.attrsOf (lib.types.nullOr lib.types.attrs);
    readOnly = true;
  };
  options."browser-ux".replacementApplicationClaims = lib.mkOption {
    description = "Enabled replacement claims for explicit composition adoption; no cask writer.";
    type = lib.types.listOf lib.types.attrs;
    readOnly = true;
  };
  options."browser-ux".primaryCutover = lib.mkOption {
    description = "Target primary cutover intent, lifecycle semantics, and decoupled provider state.";
    type = lib.types.attrsOf lib.types.anything;
    readOnly = true;
  };

  options."browser-ux".rolesR3 = lib.mkOption {
    description = "R3 per-role convenience intent with automatic deployment held.";
    type = lib.types.attrsOf lib.types.anything;
    readOnly = true;
  };

  config = let
    hasRolesR3Option = options ? programs && options.programs ? browserBaseline && options.programs.browserBaseline ? rolesR3;
    rolesR3Active = currentHost && hasRolesR3Option && (config.programs.browserBaseline.rolesR3 or false);
    r3Config = import ./roles-r3.nix { inherit config lib options; };
    legacyConfig = let
      primaryCutoverCfg = config."browser-ux".configuration.primaryCutover or null;
      primaryCutoverActive = currentHost && primaryCutoverCfg != null && primaryCutoverCfg.enable;
      credentialProvider =
        if primaryCutoverActive then primaryCutoverCfg.credentialProvider
        else "legacy";
      chromeDelivery =
        if primaryCutoverActive then builtins.elem "chrome" primaryCutoverCfg.activeBrowsers && !(builtins.elem "chrome" primaryCutoverCfg.retiredBrowsers)
        else true;
      firefoxDelivery =
        if primaryCutoverActive then builtins.elem "firefox" primaryCutoverCfg.activeBrowsers && !(builtins.elem "firefox" primaryCutoverCfg.retiredBrowsers)
        else true;
      replacementConfig = if primaryCutoverActive then lib.mapAttrs (name: value:
        value // { enable = value.enable && builtins.elem name primaryCutoverCfg.activeBrowsers
          && !(builtins.elem name primaryCutoverCfg.retiredBrowsers); })
        config."browser-ux".configuration.replacements else config."browser-ux".configuration.replacements;
      productivityIntent =
        if primaryCutoverActive then primaryCutoverCfg.productivityIntent
        else (replacementConfig.vivaldi.productivity.intent or "default");
      protonVpnEnabled = if primaryCutoverActive then primaryCutoverCfg.protonVpnEnabled else appleProtonEnabled;
    in
    {
    "browser-ux".primaryCutover = if primaryCutoverActive then
      (import ../config/browser/primary-cutover.nix).targetIntent // {
        enable = true;
        browsers = { active = primaryCutoverCfg.activeBrowsers; retired = primaryCutoverCfg.retiredBrowsers; };
        credentials = if credentialProvider == "apple" then
          (import ../config/browser/primary-cutover.nix).targetIntent.credentials
          else { provider = credentialProvider; effectiveState = "ATTENDED_READBACK_PENDING"; };
        productivity.vivaldi = { intent = productivityIntent; dataRetention = true; settingWriter = false; };
      } else { enable = false; };
    "browser-ux".replacementApplicationClaims =
      (import ../lib/application-claims.nix).replacementApplicationClaims replacementConfig;
    "browser-ux".replacementRendering = {
      vivaldi = if replacementConfig.vivaldi.enable then
        replacements.render "vivaldi" {
          inherit keepassxcEnabled optOut;
          mailEnabled = replacementConfig.vivaldi.mail.enable;
          personalHostTrial = currentHost;
          currentHostResolved = currentHost && replacementConfig.vivaldi.mail."preserve-resolved";
          preserveResolved = currentHost && replacementConfig.vivaldi.mail."preserve-resolved";
          inherit appleProtonEnabled omitAppleProtonVpn;
          inherit credentialProvider productivityIntent protonVpnEnabled;
        }
      else null;
      floorp = if replacementConfig.floorp.enable then
        # Sharing is a qualification hold and remains dependent on the source bridge.
        # Retiring that declaration must not silently break a replacement candidate.
        if keepassxcEnabled && credentialProvider != "apple" && !(builtins.hasAttr "org.keepassxc.keepassxc_browser"
          config.programs.browserBaseline.firefox.nativeMessagingHosts) then
          builtins.throw "Floorp candidate depends on the Firefox-owned Gecko native-messaging registration"
        else replacements.render "floorp" {
          inherit keepassxcEnabled optOut appleProtonEnabled;
          inherit credentialProvider protonVpnEnabled;
          personalHostTrial = currentHost;
          searchProvider = if primaryCutoverActive then "Startpage" else "legacy";
        }
      else null;
    };
    programs.browserBaseline = {
      legacyPolicyDefaults.enable = false;

      chrome = {
        enable = chromeDelivery;
        managedPreferences = (import ../config/browser/chrome-policy-defaults.nix) {
          inherit keepassxcEnabled optOut;
          inherit appleProtonEnabled;
          inherit credentialProvider protonVpnEnabled;
        };
        externalExtensions = {
          "felphkbfjadmcejnibcmcncimlappdde" = ../config/browser/chrome-clear-new-tab-external-extension.json;
        };
        nativeMessagingHosts = lib.mkIf (keepassxcEnabled && credentialProvider != "apple") {
          "org.keepassxc.keepassxc_browser" = ../config/browser/keepassxc-chrome-native-messaging.json;
        };
      };

      firefox = {
        enable = firefoxDelivery;
        policyDelivery = "macos-preferences";
        policies = (import ../config/browser/firefox-policy-defaults.nix) {
          inherit keepassxcEnabled optOut;
          inherit appleProtonEnabled;
          inherit credentialProvider protonVpnEnabled;
        };
        nativeMessagingHosts = lib.mkIf (keepassxcEnabled && credentialProvider != "apple") {
          "org.keepassxc.keepassxc_browser" = ../config/browser/keepassxc-firefox-native-messaging.json;
        };
      };
    } // lib.optionalAttrs currentHost {
      # Retain target ownership after disabling the trial so normal activation
      # retracts owned replacement policies instead of leaving enforced orphans.
      replacementPolicyOwnership = true;
    } // lib.optionalAttrs (currentHost && replacementConfig.vivaldi.enable) {
      vivaldi = {
        managedPreferences = rendering.vivaldi.deliverable;
        externalExtensions = {
          "felphkbfjadmcejnibcmcncimlappdde" = ../config/browser/chrome-clear-new-tab-external-extension.json;
        };
        # KeePassXC's supported installer owns this per-user Vivaldi registration.
        # Preserve its file and settings; attended setup/readback remains required.
      };
    } // lib.optionalAttrs (currentHost && replacementConfig.floorp.enable) {
      floorp.policies = rendering.floorp.deliverable;
    };
  };
  in lib.mkMerge [
    {
      "browser-ux" = {
        rolesR3 = if rolesR3Active then r3Config."browser-ux".rolesR3 else { enable = false; };
        primaryCutover = if rolesR3Active then r3Config."browser-ux".primaryCutover else legacyConfig."browser-ux".primaryCutover;
        replacementRendering = if rolesR3Active then r3Config."browser-ux".replacementRendering // {
          vivaldi = legacyConfig."browser-ux".replacementRendering.vivaldi;
        } else legacyConfig."browser-ux".replacementRendering;
        replacementApplicationClaims = if rolesR3Active then r3Config."browser-ux".replacementApplicationClaims else legacyConfig."browser-ux".replacementApplicationClaims;
      };
    }
    (lib.mkIf rolesR3Active (builtins.removeAttrs r3Config [ "browser-ux" ]))
    (lib.mkIf rolesR3Active {
      # Preserve the existing Vivaldi policy/convenience selection through core's
      # sole physical writer. No profile or productivity preference transition.
      programs.browserBaseline = {
        vivaldiPolicyOwnership = legacyConfig.programs.browserBaseline.replacementPolicyOwnership;
      } // lib.optionalAttrs (legacyConfig.programs.browserBaseline ? vivaldi) {
        vivaldi = legacyConfig.programs.browserBaseline.vivaldi;
      };
    })
    (lib.mkIf (!rolesR3Active) (builtins.removeAttrs legacyConfig [ "browser-ux" ]))
  ];
}
