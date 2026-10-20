{ lib, ... }:
{
  # Minimal test-only option declaration fixture for programs.browserBaseline.
  # Enables standalone destination module evaluation and contract testing without
  # depending on external core modules at evaluation or build time.
  # Option shapes and absence of defaults mirror the core seam definitions.
  options.programs.browserBaseline = {
    vivaldiPolicyOwnership = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Ownership of Vivaldi policy and known external-extension retraction only.
        Retained references do not select Floorp policy retraction.
      '';
    };

    legacyPolicyDefaults.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether legacy policy defaults are enabled.
      '';
    };

    chrome = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Whether Chrome browser delivery is enabled.
          Compatibility default is true; retired delivery sets false while
          retaining inherited baseline configurations for family consumers.
        '';
      };

      managedPreferences = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Chrome managed policy dictionary written to com.google.Chrome.plist.
        '';
      };

      externalExtensions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Chrome external extensions mapping extension IDs to manifests.
        '';
      };

      nativeMessagingHosts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Chrome NativeMessagingHosts mapping host names to manifests.
        '';
      };
    };

    firefox = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Whether Firefox browser delivery is enabled.
          Compatibility default is true; retired delivery sets false while
          retaining inherited baseline configurations for family consumers.
        '';
      };

      policyDelivery = lib.mkOption {
        type = lib.types.enum [ "bundle" "macos-preferences" ];
        default = "bundle";
        description = ''
          Delivery mechanism for Firefox enterprise policies.
        '';
      };

      policies = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        description = ''
          Firefox enterprise policy dictionary.
        '';
      };

      policiesJsonPayload = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        description = ''
          Firefox policies.json payload file.
        '';
      };

      nativeMessagingHosts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.either lib.types.path (lib.types.attrsOf lib.types.anything));
        description = ''
          Firefox NativeMessagingHosts mapping host names to manifests.
        '';
      };
    };
  };
}
