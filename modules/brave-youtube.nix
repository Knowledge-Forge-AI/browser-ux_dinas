{ userName }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  primaryUser = config.system.primaryUser;
  userHome = config.users.users.${primaryUser}.home;
  braveYoutubeLauncherTemplate = ../config/brave-youtube/launcher.sh.template;
  braveYoutubeThemeManifest = ../config/brave-youtube/theme-manifest.json;
  braveYoutubeGenerateIcon = ../libexec/brave-youtube/generate-icon.py;
  braveYoutubeGenerateThemeAssets = ../libexec/brave-youtube/generate-theme-assets.py;
in
{
  system.activationScripts.postActivation.text = ''
    echo "setting up Brave YouTube app..."
    target_user=${lib.escapeShellArg primaryUser}
    user_home=${lib.escapeShellArg userHome}
    brave_youtube_bundle_id="ai.knowledge-forge.dinas.brave-youtube"
    /usr/bin/sudo -n -H -u "$target_user" -- \
      ${pkgs.bash}/bin/bash ${./brave-youtube-app-writer.sh} \
      ${./user-home-writer-common.sh} \
      "$target_user" "$user_home" \
      "${pkgs.brave}/Applications/Brave Browser.app" \
      ${braveYoutubeLauncherTemplate} ${braveYoutubeThemeManifest} \
      ${braveYoutubeGenerateIcon} ${braveYoutubeGenerateThemeAssets} \
      /usr/bin/python3 /usr/bin/iconutil /usr/libexec/PlistBuddy \
      /usr/bin/codesign \
      /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
      /usr/bin/qlmanage "$brave_youtube_bundle_id" || exit 1
  '';
}
