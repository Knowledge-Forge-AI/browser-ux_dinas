{
  description = "Public-capable browser UX destination module for nix-darwin compositions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-25.11-darwin";
    nix-darwin.url = "github:nix-darwin/nix-darwin/nix-darwin-25.11";
    nix-darwin.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-darwin,
      ...
    }:
    let
      system = "aarch64-darwin";
      inherit (nixpkgs) lib;
      pkgs = nixpkgs.legacyPackages.${system};
      commands = import ./packages/browser-ux-commands { inherit pkgs; };

      defaultModule = import ./modules/default.nix;

      packageSetIdentity = {
        schema = "nix-darwin-package-set-v1";
        revision = nixpkgs.rev;
        outPath = builtins.toString nixpkgs.outPath;
      };

      inherit (import ./lib/application-claims.nix) applicationClaims applicationClaimsFor applicationClaimsForHost;

      configAllowlist = {
        "browser-ux.toml" = [
          "browser-ux.schema"
          "browser-ux.keepassxc"
          "browser-ux.extensions"
          "browser-ux.replacements"
          "browser-ux.primaryCutover"
        ];
      };

      releaseCandidate = {
        milestone = "R3: held browser role and physical owner source candidate";
        commandPackageRegistered = false;
        commandTrialBoundary = "Help/status and fixture-only dry runs. Physical command ownership and native integration remain downstream composition responsibilities.";
        schema = "browser-ux-release-candidate-v1";
        intendedChannel = "refs/heads/deploy";
        assertionType = "self-asserted-destination-metadata";
        enforcementBoundary = "none";
        note = "Self-asserted destination metadata; not an enforcement boundary consumed by core or composition.";
        deployPreconditions = [
          "Primary browser-role cutover and external owner patches remain mechanically held in core until downstream composition adoption."
          "Core owns stock Brave, LibreWolf, Orion and Safari privacy. Browser UX owns Floorp and per-profile convenience intent; Brave automation receives no convenience or credential extensions."
          "Preserve Chrome/Clear New Tab storage and Brave YouTube writer data, profiles, artwork and wallpaper source. Vivaldi remains installed and unchanged as a runnable visual reference outside the seven primary roles."
          "Apple Passwords password/TOTP/passkey compatibility precedes native-manager suppression. Unsupported fork integration stays held; preserve credential stores and recovery vaults."
        ];
        qualificationNotes = [
          "Real composed graph, package acquisition, effective per-profile search/privacy/blockers/extensions and representative Brave automation remain native/attended qualification. No source declaration proves effectiveness."
        ];
        targetHostGeneration = {
          homebrewCasks = [ "vivaldi" "floorp" ];
          effectiveQualification = "HELD";
        };
        # Legacy/non-target baseline; target package ownership is declared above.
        hostGeneration = {
          systemPackages = [ ];
          homebrewCasks = [ ];
          activationScripts = [ ];
          launchdDefinitions = [ ];
        };
        operatorOnlyOperations = [
          {
            id = "clear-new-tab-profile-mutation";
            authorizedByRecord = false;
          }
          {
            id = "clear-new-tab-playwright-import";
            authorizedByRecord = false;
          }
          {
            id = "shared-images-content-mutation";
            authorizedByRecord = false;
          }
          {
            id = "shared-images-rclone-push-pull";
            authorizedByRecord = false;
          }
        ];
        authority = {
          ordinaryActivationAuthorizesOperatorOperations = false;
          ordinaryPromotionAuthorizesOperatorOperations = false;
        };
      };
    in
    {
      darwinModules.default = defaultModule;
      browserRolesR3 = import ./config/browser/roles-r3.nix;
      replacementParity = {
        schema = "browser-ux-replacement-parity-v1";
        system1 = (import ./config/browser/replacements).system1Catalog;
        browsers = builtins.listToAttrs (map (name: {
          inherit name;
          value = (import ./config/browser/replacements).render name {
            keepassxcEnabled = true;
            optOut = [ ];
          };
        }) [ "vivaldi" "floorp" ]);
      };
      packages.${system}.browser-ux-commands = commands;
      devShells.${system}.command-tests = pkgs.mkShell {
        packages = [ pkgs.bash pkgs.bats pkgs.ripgrep pkgs.python3Packages.pytest ];
      };

      inherit
        applicationClaims
        applicationClaimsFor
        applicationClaimsForHost
        packageSetIdentity
        configAllowlist
        releaseCandidate
        ;

      checks.${system} = (import ./tests/contracts.nix {
        inherit
          self
          lib
          pkgs
          nixpkgs
          nix-darwin
          defaultModule
          applicationClaims
          packageSetIdentity
          configAllowlist
          releaseCandidate
          system
          ;
      }) // (import ./tests/command-checks.nix { inherit pkgs commands; })
        // (import ./tests/apple-proton-contracts.nix { inherit lib pkgs; })
        // (import ./tests/composition-delivery-contracts.nix { inherit lib pkgs; })
        // (import ./tests/primary-cutover-contracts.nix { inherit lib pkgs; })
        // (import ./tests/roles-r3.nix { inherit lib pkgs; })
        // (import ./tests/r3r4-schema-regression.nix { inherit lib pkgs nix-darwin defaultModule; });
    };
}
