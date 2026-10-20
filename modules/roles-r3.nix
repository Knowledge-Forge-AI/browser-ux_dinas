{ config, lib, options ? null }:
let
  intent = import ../config/browser/roles-r3.nix;
  claims = import ../lib/application-claims.nix;
  hasHomebrew = options == null || options ? homebrew;
  hasAssertions = options == null || options ? assertions;
  hasExtensionSeam = options == null || (options ? programs
    && options.programs ? browserBaseline
    && options.programs.browserBaseline ? extensionContributions);
in {
} // lib.optionalAttrs hasExtensionSeam {
  programs.browserBaseline.extensionContributions =
    import ../config/browser/extension-contributions-r3r3.nix;
} // lib.optionalAttrs hasHomebrew {
  homebrew.casks = [ "vivaldi" "floorp" ];
} // lib.optionalAttrs hasAssertions {
  assertions = [
    {
      assertion = (config.programs.browserBaseline.rolesR3 or false)
        && (config.programs.browserBaseline.corePolicyOwnership or false);
      message = "Browser UX R3 requires the matched held core role source.";
    }
    {
      assertion = (config.homebrew.onActivation.cleanup or "none") == "none";
      message = "Vivaldi visual reference retention preserves installed apps and profiles; Homebrew cleanup must remain none.";
    }
    {
      assertion = (config."browser-ux".configuration.replacements.vivaldi.enable or false)
        && !(builtins.elem "vivaldi" (config."browser-ux".configuration.primaryCutover.retiredBrowsers or []));
      message = "Vivaldi visual reference must remain selected; any retirement requires explicit operator approval and a separate source release.";
    }
  ];
} // {
  "browser-ux" = {
    rolesR3 = intent;
    replacementRendering = { floorp = null; }; # default module carries the existing Vivaldi rendering.
    replacementApplicationClaims = claims.applicationClaimsForHost { hostName = "example-current-mac"; };
    primaryCutover = { enable = false; supersededBy = intent.schema; };
  };
  # No global Firefox policy suite, Brave force-install policy, Chrome/Safari
  # contribution or profile writer. Core retains its legacy CNT/Chrome bridge.
}
