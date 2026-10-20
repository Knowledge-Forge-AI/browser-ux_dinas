"""Actual Nix reference graphs; no daemon or browser invocation in the check."""
import argparse
import json
import os
import runpy
from pathlib import Path


def verify_graph(actual, allowed, required=()):
    # Scan even allowed transitive members: a future Playwright browser dependency
    # must not become silently permissible just because Playwright is declared.
    forbidden = ("google-chrome", "chromium", "darwin-is-not-a-snowflake")
    if any(any(word in path.lower() for word in forbidden) for path in actual):
        raise ValueError("forbidden browser/core graph member")
    if not actual <= allowed:
        raise ValueError("undeclared graph member")
    if not set(required) <= actual:
        raise ValueError("missing declared runtime")


def paths(filename):
    return set(Path(filename).read_text().splitlines())


def main():
    parser = argparse.ArgumentParser()
    for name in ("standalone", "injected", "fixture", "runtime", "allowed_runtime",
                 "configured_runtime", "fixture_runtime", "build_context"):
        parser.add_argument(name)
    parser.add_argument("allowed_context", nargs="?")
    args = parser.parse_args()
    runtime, allowed = paths(args.runtime), paths(args.allowed_runtime)
    verify_graph(runtime, allowed | {args.standalone}, allowed)
    fixture_runtime = paths(args.fixture_runtime)
    assert fixture_runtime - runtime == {args.fixture}, "fixture adds an unexpected runtime"
    configured = paths(args.configured_runtime)
    verify_graph(configured, (runtime - {args.standalone}) | fixture_runtime | {args.injected})
    assert configured - {args.injected} == (runtime - {args.standalone}) | fixture_runtime
    context = set(json.loads(Path(args.build_context).read_text()))
    allowed_context = (
        set(json.loads(Path(args.allowed_context).read_text()))
        if args.allowed_context
        else context
    )
    verify_graph(context, allowed_context)
    assert {p.name for p in (Path(args.standalone) / "bin").iterdir()} == {
        p.name for p in (Path(args.injected) / "bin").iterdir()}
    os.environ.pop("CNT_CHROME_EXECUTABLE", None)
    for package, expected in ((args.standalone, ""), (args.injected, args.fixture)):
        module = runpy.run_path(str(Path(package) / "bin/cnt-wallpaper-gallery"), run_name="bux_fixture")
        assert module["PACKAGED_CHROME_EXECUTABLE"] == expected
        try:
            selected = module["chrome_executable"](argparse.Namespace(chrome_executable=None))
        except SystemExit as error:
            assert not expected and "supply --chrome-executable" in str(error)
        else:
            assert expected and str(selected) == expected
    print("PASS: runtime/build provenance, exact injected closure/selector, standalone fail-closed; no browser invoked")


if __name__ == "__main__":
    main()
