{ pkgs, chromeExecutable ? null }:
let
  roster = builtins.attrNames (builtins.fromJSON
    (builtins.readFile ../../tests/fixtures/command-source-manifest.json));
  galleryPython = pkgs.python3.withPackages (ps: [ ps.playwright ]);
in
# Callers may inject only an immutable executable from their selected core package
# set. Standalone output intentionally has no Chrome default (pins can differ).
assert chromeExecutable == null || pkgs.lib.hasPrefix "/nix/store/" (toString chromeExecutable);
pkgs.runCommand "browser-ux-commands" {
  nativeBuildInputs = [ pkgs.python3 ];
  passthru = { inherit galleryPython chromeExecutable; };
} ''
  mkdir -p "$out"
  ${pkgs.lib.concatMapStringsSep "\n" (path: ''
    mkdir -p "$out/$(dirname '${path}')"
    cp ${../../. + "/${path}"} "$out/${path}"
    chmod u+w "$out/${path}"
  '') roster}
  python3 ${./install.py} "$out" \
    ${pkgs.bash}/bin/bash ${pkgs.python3}/bin/python3 \
    ${galleryPython}/bin/python3 ${pkgs.rclone}/bin/rclone \
    ${pkgs.imagemagick}/bin/magick \
    ${pkgs.lib.escapeShellArg (if chromeExecutable == null then "" else toString chromeExecutable)}
''
