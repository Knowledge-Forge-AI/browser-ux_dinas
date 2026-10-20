"""Dispatch-only State C qualification; no real lock writes or host builds.

Requires explicit public/private/core paths and task-owned scratch. Outputs only
sanitized projections and summaries; raw Nix diagnostics stay in scratch.
"""
import argparse
import atexit
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
for name in ("public", "private", "core", "scratch"):
    parser.add_argument("--" + name, type=Path, required=True)
parser.add_argument("--source-root", type=Path, required=True,
                    help="Real Browser UX source for independent lock measurement only")
parser.add_argument("--policy-baseline", type=Path, required=True,
                    help="Source-only accepted BUX3/B4 Browser UX snapshot")
for name in ("public-live", "private-live"):
    parser.add_argument("--" + name, type=Path, required=True,
                        help="Live source used only for independent lock readback")
parser.add_argument('--graph', choices=('public', 'private'),
                    help='Qualify one graph independently; default runs both')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
if (root / ".scratch").exists():
    raise SystemExit("Use a source-only snapshot: qualification root contains .scratch")
args.scratch.mkdir(parents=True, exist_ok=True)
counter = 0


def require(condition, message):
    """Keep qualification failures active under Python optimization."""
    if not condition:
        raise RuntimeError(message)


def run(command, decode=True):
    global counter
    counter += 1
    if command[0] == "nix":
        flags = ['--no-write-lock-file']
        if '--override-input' not in command:
            flags.append('--no-update-lock-file')
        if command[1] == 'build':
            flags += ['--max-jobs', '1', '--cores', '2']
        for flag in flags:
            if flag not in command:
                command.append(flag)
    labels = [(str(value.resolve()), '<' + name + '>') for name, value in vars(args).items()
              if isinstance(value, Path)] + [(str(root), '<browser-snapshot>')]
    recorded = list(command)
    for value, label in sorted(labels, key=lambda item: -len(item[0])):
        recorded = [part.replace(value, label) for part in recorded]
    record = {'command': recorded, 'timeout_seconds': 1800}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        record['status'] = 'TIMEOUT'
        (args.scratch / f'command-{counter}.json').write_text(json.dumps(record, indent=2))
        raise RuntimeError(f'qualification command {counter}: TIMEOUT (1800 seconds)') from None
    record.update(status='PASS' if result.returncode == 0 else 'FAILED', returncode=result.returncode)
    (args.scratch / f'command-{counter}.json').write_text(json.dumps(record, indent=2))
    (args.scratch / f"nix-{counter}.log").write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f"qualification command {counter}: FAILED exit {result.returncode}")
    return json.loads(result.stdout) if decode else result.stdout.strip()


def lock_hash(path):
    return hashlib.sha256((path / "flake.lock").read_bytes()).hexdigest()


def identities(metadata):
    """Resolve lock graph by input routes, including follows, not node labels."""
    lock = metadata["locks"]
    nodes = lock["nodes"]
    def resolve(reference):
        if isinstance(reference, str):
            return reference
        current = lock["root"]
        for part in reference:
            current = resolve(nodes[current]["inputs"][part])
        return current
    result = {}
    def visit(node, route, ancestors):
        if node in ancestors:
            return
        result[route] = nodes[node].get("locked", {})
        for key, ref in nodes[node].get("inputs", {}).items():
            visit(resolve(ref), route + "/" + key, ancestors | {node})
    visit(lock["root"], "", set())
    return result


def browser_override(metadata, label, source):
    """Resolve aliases through follows; override only this graph's Browser node."""
    lock = metadata['locks']
    nodes = lock['nodes']
    def resolve(reference, seen=()):
        require(str(reference) not in seen, 'Cyclic follows')
        if isinstance(reference, str):
            require(reference in nodes, 'Missing lock node')
            return reference
        current = lock['root']
        for part in reference:
            current = resolve(nodes[current]['inputs'][part], seen + (str(reference),))
        return current
    routes = {}
    def visit(node, route, ancestors):
        require(node not in ancestors, 'Cyclic lock graph')
        routes[route] = node
        for name, reference in nodes[node].get('inputs', {}).items():
            visit(resolve(reference), route + '/' + name, ancestors | {node})
    visit(lock['root'], '', set())
    route = '/browser-ux_dinas' if label == 'public' else '/composition-nd/browser-ux_dinas'
    require(label in ('public', 'private') and route in routes, 'Unexpected Browser topology')
    target = routes[route]
    require(target != lock['root'], 'Browser override resolves to root')
    require(all(node == target for key, node in routes.items()
                if key.rsplit('/', 1)[-1] == 'browser-ux_dinas'),
            'Unexpected Browser topology: multiple Browser nodes')
    aliases = {key for key, node in routes.items() if node == target}
    require('' not in aliases and '/composition-nd' not in aliases, 'Browser aliases an ancestor')
    return ['--override-input', route[1:], 'path:' + str(source)], aliases


def compare_graph(label, before, after, allowed, projections, systems, claims, accepted):
    changed = {route for route in before.keys() | after.keys() if before.get(route) != after.get(route)}
    require(changed <= allowed, (label, 'unrelated input drift', changed - allowed))
    require(projections[0] == projections[1], (label, 'projection drift'))
    require(systems[0] == systems[1], (label, 'selected closure derivation drift'))
    require(claims[0] == claims[1], (label, 'claim drift'))
    require([p['policyHash'] for p in accepted] == [p['policyHash'] for p in projections[1]],
            'accepted baseline policy drift')
    for projection in projections[1]:
        require(projection['braveWriters'] == projection['videoWriters'] == 1,
                (label, 'writer count drift'))


before = {label: lock_hash(path) for label, path in
          (("destination", args.source_root), ("public", args.public_live), ("private", args.private_live))}
summary = {"locks_before": before, "compositions": {}}

def record_real_locks():
    after = {label: lock_hash(path) for label, path in
             (("destination", args.source_root), ("public", args.public_live), ("private", args.private_live))}
    (args.scratch / "source-lock-preservation.json").write_text(json.dumps({
        "before": before, "after": after, "unchanged": before == after}, indent=2) + "\n")

atexit.register(record_real_locks)

for label, path in (("public", args.public), ("private", args.private)):
    if args.graph and label != args.graph:
        continue
    ref = "path:" + str(path.resolve())
    baseline_metadata = run(["nix", "flake", "metadata", ref, "--json"])
    candidate_override, allowed = browser_override(baseline_metadata, label, root)
    core_route = '.inputs.core' if label == 'public' else '.inputs."composition-nd".inputs.core'
    selected_core = run(["nix", "eval", "--impure", "--raw", "--expr",
                         f'(builtins.getFlake {json.dumps(ref)}){core_route}.outPath'], False)
    metadata = []
    projections = []
    systems = []
    claims = []
    for overrides in ([], candidate_override):
        flags = ["--no-write-lock-file", *overrides]
        metadata.append(identities(run(["nix", "flake", "metadata", ref, "--json", *flags])))
        projection = f'import {root}/tests/composition-projection.nix {{ coreSource = builtins.toPath {json.dumps(selected_core)}; }}'
        projections.append(run(["nix", "eval", "--impure", ref + "#darwinConfigurations", "--json", "--apply", projection, *flags]))
        systems.append(run(["nix", "eval", "--impure", ref + "#darwinConfigurations", "--json", "--apply",
                            'systems: map (n: { out = toString systems.${n}.system; drv = systems.${n}.system.drvPath; }) (builtins.attrNames systems)', *flags]))
        claims.append(run(["nix", "eval", ref + "#applicationClaims", "--json", *flags]))
    baseline_override = ["path:" + str(args.policy_baseline.resolve())
                         if value == "path:" + str(root) else value for value in candidate_override]
    baseline_policies = run(["nix", "eval", "--impure", ref + "#darwinConfigurations", "--json",
                             "--apply", projection, "--no-write-lock-file", *baseline_override])
    compare_graph(label, metadata[0], metadata[1], allowed, projections, systems, claims, baseline_policies)
    brave = [c for c in claims[1] if c.get("claim", {}).get("id") == "bundle:ai.knowledge-forge.dinas.brave-youtube"]
    require(len(brave) == 2 and {c["owner"] for c in brave} == {"core", "browser-ux"}, 'State C condition failed: len(brave) == 2 and {c["owner"] for c in brave} == {"core", "browser-ux"}')
    for projection in projections[1]:
        require(projection["coreBraveProjectionPresent"] and projection["coreVideoProjectionPresent"], 'State C condition failed: projection["coreBraveProjectionPresent"] and projection["coreVideoProjectionPresent"]')
        require(projection["browserNamespaceAbsent"], 'State C condition failed: projection["browserNamespaceAbsent"]')
    # Derivation requisites also prove the dormant command cannot enter a selected
    # output: its derivation is not even in the host's build dependency graph.
    closure_counts = []
    for system in systems[1]:
        dependencies = run(["nix-store", "--query", "--requisites", system["drv"]], False).splitlines()
        require(not any("-browser-ux-commands" in p for p in dependencies), 'State C condition failed: not any("-browser-ux-commands" in p for p in dependencies)')
        closure_counts.append(len(dependencies))
    checks = ["application-claims", "contracts",
              "registered-input-checks" if label == "public" else "public-checks"]
    for check in checks:
        run(["nix", "build", "--no-link", ref + "#checks.aarch64-darwin." + check,
             "--no-write-lock-file", *candidate_override], False)
        print(f"{label}: {check} PASS", flush=True)
    summary["compositions"][label] = {
        "direct_accepted_baseline_policy_equality": True,
        "hosts": len(projections[1]), "projection_equality": True,
        "selected_toplevel_output_and_derivation_equality": True,
        "claims_equality": True, "unrelated_inputs_unchanged": True,
        "command_package_absent_from_host_dependency_graph": True,
        "host_dependency_counts": closure_counts, "checks": checks,
        "projections": projections[1],
    }
    # Selected validator and BUX4 local/selected source parity, independent of the
    # new command package's standalone dependency pin.
    expression = f'''let candidate = builtins.getFlake "path:{root}";
      core = builtins.getFlake {json.dumps(selected_core)};
      in import {root}/tests/qualify-dormant.nix {{ inherit candidate core;
        localCore = builtins.toPath {json.dumps(str(args.core.resolve()))};
        pkgs = core.legacyPackages.aarch64-darwin; }}'''
    qualification = run(["nix", "eval", "--impure", "--json", "--expr", expression])
    summary["compositions"][label]["validator_matrix"] = qualification["matrix"]
    summary["compositions"][label]["dormant_source_parity"] = qualification["parity"]
    print(f"{label}: State C projections, closure exclusion and validator PASS", flush=True)
after = {label: lock_hash(path) for label, path in
         (("destination", args.source_root), ("public", args.public_live), ("private", args.private_live))}
require(before == after, 'State C condition failed: before == after')
summary["locks_after"] = after
(args.scratch / "composition-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("PASS: " + (args.graph or "public/private") + " State C and unchanged real locks")
