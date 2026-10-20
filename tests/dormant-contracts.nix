{ lib, pkgs }:
let
  expectedClaim = {
    id = "bundle:ai.knowledge-forge.dinas.brave-youtube";
    artifact = "Brave YouTube.app";
    provider = "nix";
    package = "brave";
    handoff = {
      from = "core";
      adr = "docs/adr/2026/08/0002-domain-ownership-application-claims-and-migration-sequencing.md";
    };
  };
  expectedClaims = [ ];
  provenance = import ../lib/application-claims.nix;
  hashes = builtins.fromJSON (builtins.readFile ./fixtures/dormant-source-sha256.json);
  # Direct application supplies the preserved outer argument. Configuration owns identity.
  brave = (import ../modules/brave-youtube.nix { userName = "unused-outer-user"; }) {
    inherit lib pkgs;
    config = {
      system.primaryUser = "dormant-probe";
      users.users.dormant-probe.home = "/disposable/dormant-probe";
    };
  };
  braveText = brave.system.activationScripts.postActivation.text;
  videoText = (import ../modules/video-session.nix { }).system.activationScripts.postActivation.text;
  forbidden = [
    "setting up Brave YouTube app" "ai.knowledge-forge.dinas.brave-youtube" "Brave YouTube.app"
    "brave-youtube-app-writer.sh" "setting up video session power controls"
    "video_session_pmset" "amphetamine_PowerProtect"
  ];
  containsAll = text: fragments: lib.all (fragment:
    lib.hasInfix (builtins.unsafeDiscardStringContext fragment)
      (builtins.unsafeDiscardStringContext text)) fragments;
in
{
  inherit expectedClaims;
  checks = { applicationClaims, defaultActivation }: {
    dormant-handoff-contract =
      assert applicationClaims == expectedClaims;
      assert provenance.inventory == [ ];
      assert lib.all (token: !lib.hasInfix token defaultActivation) forbidden;
      assert lib.all (path: builtins.hashFile "sha256" (../. + "/${path}") == hashes.${path})
        (builtins.attrNames hashes);
      assert containsAll braveText [
        "target_user=${lib.escapeShellArg "dormant-probe"}"
        "user_home=${lib.escapeShellArg "/disposable/dormant-probe"}"
        ''/usr/bin/sudo -n -H -u "$target_user" --''
        "${pkgs.brave}/Applications/Brave Browser.app"
        "${pkgs.bash}/bin/bash" "ai.knowledge-forge.dinas.brave-youtube"
        "brave-youtube-app-writer.sh" "user-home-writer-common.sh"
        "generate-icon.py" "generate-theme-assets.py"
        "/usr/bin/python3 /usr/bin/iconutil /usr/libexec/PlistBuddy"
        "/usr/bin/codesign" "/usr/bin/qlmanage"
      ];
      assert !lib.hasInfix "unused-outer-user" braveText;
      assert containsAll videoText [
        "install -d -m 0755 /private/etc/sudoers.d"
        ''install -m 0440 "'' ''/usr/sbin/visudo -cf "$sudoersTmp"''
        ''install -m 0440 "$sudoersTmp" /private/etc/sudoers.d/video_session_pmset''
        "rm -f /private/etc/sudoers.d/amphetamine_PowerProtect"
      ];
      # Assertions consume context-bearing strings only during evaluation. No activation
      # text or Brave derivation is passed to this builder, even as a discarded fixture.
      pkgs.runCommandLocal "browser-ux-dormant-handoff-contract" { } ''touch "$out"'';

    dormant-assets = pkgs.runCommandLocal "browser-ux-dormant-assets" {
      nativeBuildInputs = [ pkgs.python3 ];
    } ''
      python3 ${./test-dormant-assets.py} ${../libexec/brave-youtube}
      touch "$out"
    '';
  };
}
