# Dispatch-time only: caller supplies selected validator and canonical local source.
{ candidate, core, localCore, pkgs }:
let
  lib = pkgs.lib;
  validator = core.lib.applicationClaims;
  claim = builtins.head candidate.applicationClaims;
  source = validator.attachOwner "core" core.applicationClaims;
  destination = claims: validator.attachOwner "browser-ux" claims;
  result = claims: validator.validate (source ++ destination claims);
  rejects = rule: claims:
    let checked = result claims;
    in !checked.ok && lib.any (lib.hasInfix "(${rule})") checked.errors;
  handoff = fields: claim // { handoff = fields; };
  hashes = builtins.fromJSON (builtins.readFile ./fixtures/dormant-source-sha256.json);
  arguments = {
    inherit lib pkgs;
    config = {
      system.primaryUser = "dormant-probe";
      users.users.dormant-probe.home = "/disposable/dormant-probe";
    };
  };
  brave = root: ((import (root + "/modules/brave-youtube.nix") {
    userName = "unused-outer-user";
  }) arguments).system.activationScripts.postActivation.text;
  video = root: (import (root + "/modules/video-session.nix") { }).system.activationScripts.postActivation.text;
  # Exact comparison first: identical copied files have identical content-addressed paths.
  projectionsEqual = brave candidate.outPath == brave localCore
    && video candidate.outPath == video localCore
    && brave candidate.outPath == brave core.outPath
    && video candidate.outPath == video core.outPath;
  parity = lib.mapAttrs (path: expected:
    builtins.readFile (candidate.outPath + "/${path}") == builtins.readFile (localCore + "/${path}")
    && builtins.hashFile "sha256" (localCore + "/${path}") == expected
    && builtins.readFile (localCore + "/${path}") == builtins.readFile (core.outPath + "/${path}")
  ) hashes;
  matrix = {
    compatibleOverlap = (result [ claim ]).ok;
    missingHandoff = rejects "duplicate-claim" [ (builtins.removeAttrs claim [ "handoff" ]) ];
    duplicateDestination = rejects "too-many-claims" [ claim claim ];
    surfaceLeak = rejects "unknown-keys" [ (claim // { surface = "system.activationScripts"; }) ];
    declarationLeak = rejects "unknown-keys" [ (claim // { declaration = "modules/brave-youtube.nix"; }) ];
    wrongOwner = rejects "handoff-source-mismatch" [ (handoff (claim.handoff // { from = "other"; })) ];
    wildcardOwner = rejects "handoff-from-wildcard" [ (handoff (claim.handoff // { from = "*"; })) ];
    absoluteAdr = rejects "handoff-adr-not-tracked" [ (handoff (claim.handoff // { adr = "/absolute.md"; })) ];
    homeAdr = rejects "handoff-adr-not-tracked" [ (handoff (claim.handoff // { adr = "~/relative.md"; })) ];
    missingField = rejects "handoff-keys" [ (handoff { from = "core"; }) ];
    emptyOwner = rejects "handoff-from-empty" [ (handoff (claim.handoff // { from = ""; })) ];
    emptyAdr = rejects "handoff-adr-empty" [ (handoff (claim.handoff // { adr = ""; })) ];
  };
in
assert lib.all (value: value) (builtins.attrValues matrix);
assert lib.all (value: value) (builtins.attrValues parity);
assert projectionsEqual;
{
  inherit matrix parity projectionsEqual;
  braveProjection = builtins.unsafeDiscardStringContext (brave candidate.outPath);
  videoProjection = builtins.unsafeDiscardStringContext (video candidate.outPath);
}
