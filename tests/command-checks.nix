{ pkgs, commands }:
let
  undeclaredSource = commands.overrideAttrs (_: {
    unexpectedSource = ./test_package_provenance.py;
  });
  rejectedSource = builtins.tryEval (import ./package-provenance.nix {
    inherit pkgs;
    commands = undeclaredSource;
  });
in
{
  cnt-static-evidence-tests = pkgs.runCommand "browser-ux-cnt-static-evidence-tests" {
    nativeBuildInputs = [ pkgs.python3Packages.pytest ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    pytest --import-mode=importlib -q -p no:cacheprovider ${../.}/tests/cnt-native-preflight.test.py ${../.}/tests/cnt-native-evidence.test.py ${../.}/tests/cnt-native-fixtures.test.py ${../.}/tests/qualify-command-compositions.test.py ${../.}/tests/source-only-snapshot.test.py ${../.}/tests/cnt-confinement.test.py ${../.}/tests/cnt-owned-process.test.py ${../.}/tests/cnt-protocol.test.py ${../.}/tests/cnt-synthetic-firefox.test.py ${../.}/tests/cnt-firefox-observation.test.py ${../.}/tests/cnt-host-d2.test.py ${../.}/tests/cnt-synthetic-chrome.test.py ${../.}/tests/cnt-host-chrome.test.py ${../.}/tests/cnt-chrome-rendezvous.test.py ${../.}/tests/cnt-firefox-matrix.test.py ${../.}/tests/cnt-firefox-matrix-session.test.py ${../.}/tests/cnt-host-firefox-matrix.test.py ${../.}/tests/cnt-host-firefox-runtime-requal.test.py ${../.}/tests/cnt-firefox-production.test.py ${../.}/tests/cnt-firefox-recovery.test.py ${../.}/tests/cnt-host-firefox-recovery.test.py
    touch "$out"
  '';
  command-package-provenance = import ./package-provenance.nix { inherit pkgs commands; };
  command-provenance-negative-tests = assert !rejectedSource.success;
    pkgs.runCommand "browser-ux-provenance-negative-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${../.}/tests/test_package_provenance.py
    touch "$out"
  '';
  command-unit-tests = pkgs.runCommand "browser-ux-command-unit-tests" {
    nativeBuildInputs = [ pkgs.python3Packages.pytest ];
  } ''
    export HOME="$TMPDIR/home" PYTHONDONTWRITEBYTECODE=1
    mkdir -p "$HOME"
    pytest --import-mode=importlib -q -p no:cacheprovider -o python_files='*.test.py test_commands.py' \
      ${../.}/tests/migrated/unit/python ${../.}/tests/migrated/int/python ${../.}/tests/test_commands.py \
      ${../.}/tests/clear-new-tab-durable-state.test.py ${../.}/tests/clear-new-tab-guarded-recovery.test.py \
      ${../.}/tests/clear-new-tab-consumer.test.py
    touch "$out"
  '';
  command-package-contract = pkgs.runCommand "browser-ux-command-package-contract" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    export HOME="$TMPDIR/home" PYTHONDONTWRITEBYTECODE=1
    mkdir -p "$HOME"
    python3 ${./package-contract.py} ${commands} ${../.} \
      ${pkgs.python3}/bin/python3 ${commands.galleryPython}/bin/python3 \
      ${pkgs.bash}/bin/bash ${pkgs.rclone}/bin/rclone
    touch "$out"
  '';
}
