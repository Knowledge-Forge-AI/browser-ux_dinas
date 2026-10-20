# Read-only dispatch projection. Hash private host values rather than emitting them.
{ coreSource }:
configurations:
let
  hash = value: builtins.hashString "sha256" (builtins.unsafeDiscardStringContext (builtins.toJSON value));
  project = system:
    let
      c = system.config;
      lib = system.pkgs.lib;
      activation = c.system.activationScripts.postActivation.text;
      count = token: builtins.length (lib.splitString token activation) - 1;
      coreArguments = { config = c; inherit lib; pkgs = system.pkgs; };
      coreBrave = ((import (coreSource + "/modules/brave-youtube.nix") {
        userName = "unused-outer-probe";
      }) coreArguments).system.activationScripts.postActivation.text;
      coreVideo = (import (coreSource + "/modules/video-session.nix") { }).system.activationScripts.postActivation.text;
      includes = text: lib.hasInfix (builtins.unsafeDiscardStringContext text)
        (builtins.unsafeDiscardStringContext activation);
      definitions = system.options.system.activationScripts.definitionsWithLocations;
      textValue = value:
        if builtins.isString value then value
        else if (value._type or "") == "order" then textValue value.content
        else "";
      writerFiles = token: builtins.map (definition: definition.file)
        (builtins.filter (definition:
          lib.hasInfix token (textValue (definition.value.postActivation.text or ""))) definitions);
    in {
      braveWriters = count "setting up Brave YouTube app";
      videoWriters = count "setting up video session power controls";
      coreBraveProjectionPresent = includes coreBrave;
      coreVideoProjectionPresent = includes coreVideo;
      braveWriterFiles = writerFiles "setting up Brave YouTube app";
      videoWriterFiles = writerFiles "setting up video session power controls";
      activationHash = hash c.system.activationScripts;
      # Optional seam inputs may intentionally have no value. Compare the core's
      # effective rendering projection, including NativeMessagingHosts, instead.
      policyHash = hash c.system.build.browserBaseline;
      packagesHash = hash (map toString c.environment.systemPackages);
      casksHash = hash c.homebrew.casks;
      launchdHash = hash { inherit (c.launchd) agents daemons; };
      namespacesHash = hash c.dinas.commandNamespaces;
      browserNamespaceAbsent = !(c.dinas.commandNamespaces ? browser-ux);
      braveSystemPackageAbsent = !(lib.any (p: (p.pname or "") == "brave") c.environment.systemPackages);
    };
in
# Host names are intentionally not serialized.
map (name: project configurations.${name}) (builtins.attrNames configurations)
