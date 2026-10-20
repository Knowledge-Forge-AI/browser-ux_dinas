{ lib, pkgs, defaultActivation, releaseCandidate }:
let
  manifest = builtins.fromJSON (builtins.readFile ./fixtures/command-source-manifest.json);
  names = map (path: lib.removePrefix "bin/" path)
    (builtins.filter (lib.hasPrefix "bin/") (builtins.attrNames manifest));
  brave = ((import ../modules/brave-youtube.nix { userName = "unused"; }) {
    inherit lib pkgs;
    config = {
      system.primaryUser = "probe";
      users.users.probe.home = "/disposable/probe";
    };
  }).system.activationScripts.postActivation.text;
  video = (import ../modules/video-session.nix { }).system.activationScripts.postActivation.text;
  # Direct dormant-enabled module projections are inspected, never executed or
  # interpolated into a builder. Generated launcher content is a distinct surface.
  activations = [ defaultActivation brave video ];
  sources = map builtins.readFile [ ../modules/default.nix ../modules/brave-youtube.nix ../modules/video-session.nix ];
in
assert builtins.length names == 10;
assert lib.all (text: lib.all (name: !lib.hasInfix name text) names) (activations ++ sources);
assert lib.all (value: value == [ ]) (builtins.attrValues releaseCandidate.hostGeneration);
assert !releaseCandidate.commandPackageRegistered;
assert !releaseCandidate.authority.ordinaryActivationAuthorizesOperatorOperations;
assert !releaseCandidate.authority.ordinaryPromotionAuthorizesOperatorOperations;
assert lib.hasInfix "/.local/nbin/dinas/brave-youtube-session"
  (builtins.readFile ../config/brave-youtube/launcher.sh.template);
pkgs.runCommandLocal "browser-ux-command-dormancy" { } ''touch "$out"''
