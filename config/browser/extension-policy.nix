# Destination-owned semantic extension policy classification, opt-out validation,
# and policy rendering for Chrome and Firefox.
# Introduced in BUX3B2B to provide durable baseline extension management.

let
  unique = values:
    builtins.foldl' (result: value: if builtins.elem value result then result else result ++ [ value ]) [ ] values;

  hasPrefix = pref: str:
    builtins.substring 0 (builtins.stringLength pref) str == pref;

  removePrefix = pref: str:
    builtins.substring (builtins.stringLength pref) (builtins.stringLength str) str;
in
rec {
  appleProton = import ./apple-proton.nix;
  appleProtonChromeExtensions = appleProton.trialChromeExtensions;
  appleProtonFirefoxExtensions = appleProton.trialFirefoxExtensions;
  trialChromeExtensions = appleProtonChromeExtensions;
  trialFirefoxExtensions = appleProtonFirefoxExtensions;

  chromeExtensions = {
    updateUrl = "https://clients2.google.com/service/update2/crx";
    required = {
      "felphkbfjadmcejnibcmcncimlappdde" = {
        name = "Clear New Tab";
      };
      "ddkjiahejlhfcafbddmgiahcphecmpfh" = {
        name = "uBlock Origin Lite";
      };
    };
    defaultOn = {
      "hlkenndednhfkekhgcdicdfddnkalmdm" = {
        name = "Cookie-Editor";
      };
      "hoombieeljmmljlkjmnheibnpciblicm" = {
        name = "Language Reactor";
      };
      "efaidnbmnnnibpcajpcglclefindmkaj" = {
        name = "Adobe Acrobat";
      };
      "lmjnegcaeklhafolokijcfjliaokphfk" = {
        name = "Video DownloadHelper";
      };
      "ckkdlimhmcjmikdlpkmbgfkaikojcbjk" = {
        name = "Markdown Viewer";
      };
      "efknglbfhoddmmfabeihlemgekhhnabb" = {
        name = "JSON Viewer";
      };
    };
    trial = appleProtonChromeExtensions;
    keepassxc = {
      id = "oboonakemofpalcgghocfoadofidjkkk";
      name = "KeePassXC-Browser";
    };
  };

  firefoxExtensions = {
    required = {
      "clear-new-tab@loftyshaky" = {
        name = "Clear New Tab";
        install_url = "https://addons.mozilla.org/firefox/downloads/latest/clear-new-tab/latest.xpi";
      };
      "uBlock0@raymondhill.net" = {
        name = "uBlock Origin";
        install_url = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi";
      };
    };
    defaultOn = {
      "{c3c10168-4186-445c-9c5b-63f12b8e2c87}" = {
        name = "Cookie-Editor";
        install_url = "https://addons.mozilla.org/firefox/downloads/latest/cookie-editor/latest.xpi";
      };
      "markdown-viewer@outofindex.com" = {
        name = "Markdown Viewer";
        install_url = "https://addons.mozilla.org/firefox/downloads/latest/markdown-viewer-chrome/latest.xpi";
      };
      "{b9db16a4-6edc-47ec-a1f4-b86292ed211d}" = {
        name = "Video DownloadHelper";
        install_url = "https://addons.mozilla.org/firefox/downloads/latest/video-downloadhelper/latest.xpi";
      };
    };
    trial = appleProtonFirefoxExtensions;
    keepassxc = {
      id = "keepassxc-browser@keepassxc.org";
      name = "KeePassXC-Browser";
      install_url = "https://addons.mozilla.org/firefox/downloads/latest/keepassxc-browser/latest.xpi";
    };
  };

  validateConfiguration =
    cfg:
    let
      keepassxcEnabled = cfg.keepassxc.enable or true;
      optOutList = cfg.extensions."default-on-opt-out" or [ ];

      uniqueList = unique optOutList;
      hasDuplicates = builtins.length optOutList != builtins.length uniqueList;

      validateItem =
        item:
        if !builtins.isString item then
          "Opt-out item must be a string: ${builtins.toJSON item}"
        else if hasPrefix "chrome:" item then
          let
            id = removePrefix "chrome:" item;
          in
          if id == "" then
            "Invalid extension opt-out format '${item}': extension ID cannot be empty"
          else if builtins.hasAttr id chromeExtensions.required then
            "Cannot opt out required Chrome extension '${id}'"
          else if id == chromeExtensions.keepassxc.id then
            if keepassxcEnabled then
              "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true"
            else
              null
          else if builtins.hasAttr id chromeExtensions.defaultOn || builtins.hasAttr id appleProtonChromeExtensions then
            null
          else
            "Unknown Chrome extension opt-out '${id}'"
        else if hasPrefix "firefox:" item then
          let
            id = removePrefix "firefox:" item;
          in
          if id == "" then
            "Invalid extension opt-out format '${item}': extension ID cannot be empty"
          else if builtins.hasAttr id firefoxExtensions.required then
            "Cannot opt out required Firefox extension '${id}'"
          else if id == firefoxExtensions.keepassxc.id then
            if keepassxcEnabled then
              "Cannot opt out KeePassXC-Browser extension while keepassxc.enable = true"
            else
              null
          else if builtins.hasAttr id firefoxExtensions.defaultOn || builtins.hasAttr id appleProtonFirefoxExtensions then
            null
          else
            "Unknown Firefox extension opt-out '${id}'"
        else
          "Invalid extension opt-out format '${item}': must be prefixed with 'chrome:' or 'firefox:'";

      errors =
        (if hasDuplicates then [ "Duplicate extension opt-out detected in default-on-opt-out" ] else [ ])
        ++ builtins.filter (e: e != null) (builtins.map validateItem optOutList);
    in
    if errors != [ ] then builtins.head errors else null;

  renderChromeExtensionSettings =
    { keepassxcEnabled
    , optOut
    , appleProtonEnabled ? false
    , omitAppleProtonVpn ? false
    , credentialProvider ? "legacy"
    , protonVpnEnabled ? appleProtonEnabled
    , ...
    }:
    let
      isOptedOut = id: builtins.elem "chrome:${id}" optOut;
      updateUrl = chromeExtensions.updateUrl;

      requiredEntries = builtins.mapAttrs (_id: _meta: {
        installation_mode = "force_installed";
        update_url = updateUrl;
      }) chromeExtensions.required;

      defaultOnEntries = builtins.mapAttrs (
        id: _meta:
        if isOptedOut id then
          {
            installation_mode = "allowed";
          }
        else
          {
            installation_mode = "force_installed";
            update_url = updateUrl;
          }
      ) chromeExtensions.defaultOn;

      keepassxcEntry =
        if credentialProvider == "apple" then
          { }
        else if keepassxcEnabled then
          {
            ${chromeExtensions.keepassxc.id} = {
              installation_mode = "force_installed";
              update_url = updateUrl;
            };
          }
        else
          {
            ${chromeExtensions.keepassxc.id} =
              if isOptedOut chromeExtensions.keepassxc.id then
                {
                  installation_mode = "allowed";
                }
              else
                {
                  installation_mode = "force_installed";
                  update_url = updateUrl;
                };
          };

      appleProtonCandidates =
        if credentialProvider == "apple" then
          let
            icloud = {
              "pejdijmoenmkgeppbflobdenhhabjlaj" = appleProtonChromeExtensions."pejdijmoenmkgeppbflobdenhhabjlaj";
            };
            vpn = if omitAppleProtonVpn || !protonVpnEnabled then { } else {
              "jplgfhpmjnbigmhklmmbgecoobifkmpa" = appleProtonChromeExtensions."jplgfhpmjnbigmhklmmbgecoobifkmpa";
            };
          in
          icloud // vpn
        else if omitAppleProtonVpn then
          builtins.removeAttrs appleProtonChromeExtensions [ "jplgfhpmjnbigmhklmmbgecoobifkmpa" ]
        else
          appleProtonChromeExtensions;

      appleProtonEntries =
        if credentialProvider == "apple" || appleProtonEnabled then
          builtins.mapAttrs (
            id: _meta:
            if isOptedOut id then
              {
                installation_mode = "allowed";
              }
            else
              {
                # Supported default-on installation with a user-controlled disable toggle.
                installation_mode = "normal_installed";
                update_url = updateUrl;
              }
          ) appleProtonCandidates
        else
          { };
    in
    {
      "*" = {
        installation_mode = "allowed";
      };
    }
    // requiredEntries
    // defaultOnEntries
    // keepassxcEntry
    // appleProtonEntries;

  renderFirefoxExtensionSettings =
    { keepassxcEnabled
    , optOut
    , appleProtonEnabled ? false
    , credentialProvider ? "legacy"
    , protonVpnEnabled ? appleProtonEnabled
    , ...
    }:
    let
      isOptedOut = id: builtins.elem "firefox:${id}" optOut;

      requiredEntries = builtins.mapAttrs (_id: meta: {
        installation_mode = "force_installed";
        install_url = meta.install_url;
      }) firefoxExtensions.required;

      defaultOnEntries = builtins.mapAttrs (
        id: meta:
        if isOptedOut id then
          {
            installation_mode = "allowed";
          }
        else
          {
            installation_mode = "force_installed";
            install_url = meta.install_url;
          }
      ) firefoxExtensions.defaultOn;

      keepassxcEntry =
        if credentialProvider == "apple" then
          { }
        else if keepassxcEnabled then
          {
            ${firefoxExtensions.keepassxc.id} = {
              installation_mode = "force_installed";
              install_url = firefoxExtensions.keepassxc.install_url;
            };
          }
        else
          {
            ${firefoxExtensions.keepassxc.id} =
              if isOptedOut firefoxExtensions.keepassxc.id then
                {
                  installation_mode = "allowed";
                }
              else
                {
                  installation_mode = "force_installed";
                  install_url = firefoxExtensions.keepassxc.install_url;
                };
          };

      appleCandidates =
        if credentialProvider == "apple" then
          {
            "password-manager-firefox-extension@apple.com" =
              appleProtonFirefoxExtensions."password-manager-firefox-extension@apple.com";
          } // (if protonVpnEnabled then {
            "vpn@proton.ch" =
              appleProtonFirefoxExtensions."vpn@proton.ch";
          } else { })
        else
          appleProtonFirefoxExtensions;

      appleProtonEntries =
        if credentialProvider == "apple" || appleProtonEnabled then
          builtins.mapAttrs (
            id: meta:
            if isOptedOut id then
              {
                installation_mode = "allowed";
              }
            else
              {
                installation_mode = "normal_installed";
                install_url = meta.install_url;
              }
          ) appleCandidates
        else
          { };
    in
    {
      "*" = {
        installation_mode = "allowed";
      };
    }
    // requiredEntries
    // defaultOnEntries
    // keepassxcEntry
    // appleProtonEntries;
}
