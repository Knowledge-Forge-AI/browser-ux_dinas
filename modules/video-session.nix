{ ... }:

let
  videoSessionSudoers = ../config/power/video-session-pmset.sudoers;
in
{
  system.activationScripts.postActivation.text = ''
    echo "setting up video session power controls..."

    install -d -m 0755 /private/etc/sudoers.d
    sudoersTmp="$(/usr/bin/mktemp /private/tmp/video-session-pmset-sudoers.XXXXXX)"
    install -m 0440 "${videoSessionSudoers}" "$sudoersTmp"
    /usr/sbin/visudo -cf "$sudoersTmp"
    install -m 0440 "$sudoersTmp" /private/etc/sudoers.d/video_session_pmset
    rm -f "$sudoersTmp"

    rm -f /private/etc/sudoers.d/amphetamine_PowerProtect
  '';
}
