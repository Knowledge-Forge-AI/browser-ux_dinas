# Destination-owned migration provenance; the public claim schema excludes location fields.
let
  # Core retains the existing Brave YouTube physical writer and active claim.
  inventory = [ ];
  replacementInventory = {
    vivaldi = {
      id = "bundle:com.vivaldi.Vivaldi"; artifact = "Vivaldi.app";
      provider = "homebrew-cask"; package = "vivaldi";
      surface = "homebrew.casks"; declaration = "composition-handoff";
    };
    floorp = {
      id = "bundle:app.floorp.Floorp"; artifact = "Floorp.app";
      provider = "homebrew-cask"; package = "floorp";
      surface = "homebrew.casks"; declaration = "composition-handoff";
    };
  };
  project = records: map (record: builtins.removeAttrs record [ "surface" "declaration" ]) records;
  applicationClaims = project inventory;
  # Static flake claims preserve legacy consumers. Composition explicitly selects
  # replacement claims from the same closed, per-host enable configuration.
  replacementApplicationClaims = replacements:
    let
      sources = { vivaldi = "chrome"; floorp = "firefox"; };
      valid = builtins.isAttrs replacements
        && builtins.all (name: builtins.hasAttr name sources) (builtins.attrNames replacements)
        && builtins.all (name:
          let cfg = replacements.${name}; in
          builtins.isAttrs cfg
          && builtins.all (key: builtins.elem key
            ([ "enable" "inherit-from" ] ++ (if name == "vivaldi" then [ "mail" "productivity" ] else [ ])))
            (builtins.attrNames cfg)
          && builtins.isBool (cfg.enable or false)
          && (cfg.inherit-from or sources.${name}) == sources.${name}
          # Application retention is independent of optional Mail qualification.
          # Configuration and rendering enforce the hold; claims never deliver Mail.
          && (!(cfg ? mail) || (builtins.isAttrs cfg.mail
            && builtins.all (key: builtins.elem key [ "enable" "preserve-resolved" "ui-intent" "intent" "feeds-only" "data-retention" ]) (builtins.attrNames cfg.mail)
            && builtins.isBool (cfg.mail.enable or false)
            && builtins.isBool (cfg.mail."preserve-resolved" or false)))
          && (!(cfg ? productivity) || (builtins.isAttrs cfg.productivity
            && builtins.all (key: builtins.elem key [ "enable" "intent" "ui-intent" "feeds-only" "data-retention" ]) (builtins.attrNames cfg.productivity)))
        ) (builtins.attrNames replacements);
    in
    if !valid then throw "Replacement application claims require the closed family inheritance configuration"
    else project (map (name: replacementInventory.${name})
      (builtins.filter (name: replacements.${name}.enable or false) [ "vivaldi" "floorp" ]));
in
{
  inherit inventory replacementInventory applicationClaims replacementApplicationClaims;
  applicationClaimsForHost = { hostName, ... }:
    if hostName == "example-current-mac" then project [ replacementInventory.vivaldi replacementInventory.floorp ] else [ ];
  applicationClaimsFor = replacements: applicationClaims ++ replacementApplicationClaims replacements;
}
