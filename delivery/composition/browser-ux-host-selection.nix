{ lib }:
let
  targetHost = "example-current-mac";
  replacementsOf = projection: projection.browser-ux.configuration.replacements or { };
in
{
  moduleForHost = host: projection:
    if host == targetHost || !(projection ? browser-ux)
      || !(projection.browser-ux ? configuration) then projection
    else projection // {
      browser-ux = projection.browser-ux // {
        # These sections belong only to the target host. Omit them so both
        # legacy closed schemas and current disabled defaults remain valid.
        configuration = builtins.removeAttrs projection.browser-ux.configuration [ "replacements" ]
          // lib.optionalAttrs (projection.browser-ux.configuration ? extensions) {
            extensions = builtins.removeAttrs projection.browser-ux.configuration.extensions [ "apple-proton-trial" ];
          };
      };
    };

  casksForHost = host: projection:
    if host != targetHost then [ ]
    else (lib.optional ((replacementsOf projection).vivaldi.enable or false) "vivaldi")
      ++ (lib.optional ((replacementsOf projection).floorp.enable or false) "floorp");

  claimAppliesToHost = host: entry:
    if entry.owner == "browser-ux"
      && builtins.elem entry.claim.id [ "bundle:com.vivaldi.Vivaldi" "bundle:app.floorp.Floorp" ]
    then host == targetHost else true;
}
