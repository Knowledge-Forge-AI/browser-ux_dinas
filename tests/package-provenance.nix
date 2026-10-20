{ pkgs, commands }:
let
  runtimes = [ pkgs.bash pkgs.python3 commands.galleryPython pkgs.rclone pkgs.imagemagick ];
  fixture = pkgs.writeShellScript "cnt-chrome-fixture" "exit 97";
  injected = import ../packages/browser-ux-commands { inherit pkgs; chromeExecutable = fixture; };
  closure = roots: pkgs.closureInfo { rootPaths = roots; };
  baseline = pkgs.runCommand "browser-ux-build-baseline" {
    nativeBuildInputs = [ pkgs.python3 ];
  } "touch $out";
  roster = builtins.attrNames (builtins.fromJSON
    (builtins.readFile ./fixtures/command-source-manifest.json));
  sources = map (path: ../. + "/${path}") roster ++ [ ../packages/browser-ux-commands/install.py ];
  # Check every derivation attribute, not just buildCommand. Exact context
  # membership rejects even a renamed extra source/build dependency.
  context = value: builtins.attrNames (builtins.getContext (builtins.toJSON value.drvAttrs));
  allowedContext = map builtins.unsafeDiscardStringContext
    (context baseline ++ map (p: "${p}") sources ++ map (p: p.drvPath) runtimes);
in
assert pkgs.lib.all (p: builtins.elem p allowedContext) (context commands);
pkgs.runCommand "browser-ux-package-provenance" {
  nativeBuildInputs = [ pkgs.python3 ];
} ''
  export HOME="$TMPDIR/home" PYTHONDONTWRITEBYTECODE=1
  mkdir -p "$HOME"
  python3 ${./package-provenance.py} \
    ${commands} ${injected} ${fixture} \
    ${closure [ commands ]}/store-paths \
    ${closure runtimes}/store-paths \
    ${closure [ injected ]}/store-paths \
    ${closure [ fixture ]}/store-paths \
    ${pkgs.writeText "browser-ux-build-context.json" (builtins.toJSON (context commands))} \
    ${pkgs.writeText "browser-ux-allowed-context.json" (builtins.toJSON allowedContext)}
  python3 ${./package-contract.py} ${injected} ${../.} \
    ${pkgs.python3}/bin/python3 ${commands.galleryPython}/bin/python3 \
    ${pkgs.bash}/bin/bash ${pkgs.rclone}/bin/rclone
  touch "$out"
''
