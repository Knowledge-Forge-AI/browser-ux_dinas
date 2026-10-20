"""HOST-D2: one operator-terminal configd one-factor diagnostic. Never agent-executed.

`run` binds the exported snapshot, retained D1 result, runtime, launch interpreter
and Nix store bin (nix-store or nix closure-query frontend); predicts the launch
policy template and checks that the launch interpreter imports pytest BEFORE claiming; takes one host-wide execution
claim (independent of the operator-chosen claim root) plus the per-root claim; runs the owned-process prerequisite; launches the preflight
exactly once; then collects. `collect` never launches and never overwrites an
earlier summary. Children are waited for, never killed: cleanup belongs to the
preflight supervisor. Diagnostic-only even on exit zero; never Firefox qualification.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from cnt_confinement import CONFIGD, CONFIGD_RULE, REVIEWED_SERVICES, policy, policy_evidence  # noqa: E402
from cnt_native_evidence import require, tree_digest  # noqa: E402
from source_only_snapshot import collect as collect_entries  # noqa: E402

SCRATCH = Path('/Users/Shared/agent-scratch/r')
STORE = Path('/nix/store')
RUNNER = Path(__file__).resolve()
# Consumed D1 baseline (CONT6 HOST-D1): read back from its retained result.json.
D1_TEMPLATE = '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'
D1_RUNTIME = '6555cd15eb85f2be816fede570f252d5e7154c1c4ecfda372f00f19cc0596f7d'
D1_EXECUTABLE = 'ca4f2108d1000fce089d4c5ace30565f489dfce8d2d98c89b355e7c3ebc40462'
D1_EXCEPTIONS = ['content', 'socket', 'utility-generic']
D2_SERVICES = (*REVIEWED_SERVICES, CONFIGD)
PREREQUISITE_SUITES = ('tests/cnt-confinement-process.test.py',)
PREREQUISITE_PASSED = 15
PREDICTION_PORT = 49152
EVIDENCE_LIMIT = 8 * 1024 * 1024
SUPPORTS = 'D2_DIAGNOSTIC_EXIT_ZERO_SUPPORTS_HYPOTHESIS_NOT_QUALIFICATION'
FAILURE_FIELDS = ('primary_failure', 'cleanup_failure', 'runtime_failure', 'evidence_io_failure')
# One D2 execution per host, whichever claim root the operator chooses.
HOST_CLAIM_NAME = 'bux-c7-host-d2.claim'
# HOSTPREP1-NIX-CLI-COMPAT1: cnt-native-preflight CLOSURE_FRONTENDS names, in preference order.
NIX_FRONTENDS = ('nix-store', 'nix')
NIX_BIN_REFUSED = 'Nix bin must be a resolved /nix/store bin with an executable nix-store or nix'


def d1_options(runtime, attempt):
    """The CONT6 D1 command (docs/architecture/cnt-native-format-characterization.md), argument for argument."""
    return ['--engine', 'firefox', '--runtime', str(runtime), '--scratch', str(attempt),
            '--workload', 'empty', '--shutdown-trace',
            '--service', REVIEWED_SERVICES[0], '--service', REVIEWED_SERVICES[1],
            *[a for e in D1_EXCEPTIONS for a in ('--nested-sandbox-exception', e)]]


def d2_options(runtime, attempt):
    options = d1_options(runtime, attempt)
    at = options.index(REVIEWED_SERVICES[1]) + 1
    return options[:at] + ['--service', CONFIGD] + options[at:]


def spawn(argv, **kwargs):
    return subprocess.Popen(argv, **kwargs)


def wait_retained(process):
    """Keep waiting through operator interrupts; never kill or terminate."""
    interrupted = False
    while True:
        try:
            return process.wait(), interrupted
        except KeyboardInterrupt:
            interrupted = True


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def read_bounded(path, limit=EVIDENCE_LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Non-regular evidence refused')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'Oversized evidence refused')
    return raw


def managed(path, label):
    path = Path(path).absolute()
    require(path.is_relative_to(SCRATCH) and path.resolve() == path,
            label + ' must be a link-free path under managed scratch')
    return path


def verify_snapshot(snapshot, inventory_path, expected):
    raw = read_bounded(inventory_path)
    inventory = json.loads(raw)
    entries = inventory.get('entries') if isinstance(inventory, dict) else None
    require(isinstance(entries, dict) and bool(entries), 'Invalid snapshot inventory')
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(digest == inventory.get('sha256') == expected, 'Snapshot inventory is not the approved candidate')
    require(RUNNER == snapshot / 'tests/cnt_host_d2.py', 'Runner must execute from the approved snapshot')
    require(not os.path.lexists(snapshot / '.git'), 'Snapshot must not be a Git worktree')
    present = set()
    for directory, directories, files in os.walk(snapshot):
        for name in directories + files:
            path = Path(directory, name)
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                present.add(path.relative_to(snapshot).as_posix())
    # An extra conftest, module or bytecode file would be loaded by pytest or imports.
    require(present == set(entries), 'Snapshot has missing or extra entries')
    observed = collect_entries(snapshot, sorted(entries))
    require({n: record for n, (record, _) in observed.items()} == entries, 'Snapshot bytes/modes/links differ')
    return digest


def bind_d1(path, expected):
    raw = read_bounded(path)
    require(hashlib.sha256(raw).hexdigest() == expected, 'D1 result is not the bound baseline')
    r = json.loads(raw)
    p = r.get('preflight') or {}
    checks = {'engine': r.get('engine') == 'firefox', 'workload': r.get('workload') == 'empty',
              'shutdown_trace': r.get('shutdown_trace') is True, 'abnormal': r.get('abnormal') is False,
              'crash_force_enable': r.get('crash_force_enable') is False,
              'crash_readback': r.get('crash_readback') is False, 'parent_probes': r.get('parent_probes') is False,
              'shutdown_observer': r.get('shutdown_observer') is False,
              'sandbox_disables': r.get('sandbox_disables') == D1_EXCEPTIONS,
              'policy_template': p.get('policy_template_sha256') == D1_TEMPLATE,
              'firefox_child_ipc': p.get('firefox_child_ipc') is True,
              'configd_absent': r.get('configd_compatibility') in (None, False),
              'runtime': r.get('runtime_snapshot_sha256') == D1_RUNTIME,
              'executable': r.get('executable_sha256') == D1_EXECUTABLE,
              'signature': r.get('signature') == {'original': True, 'frozen': True},
              'consumed_exit': r.get('exit_before_cleanup') == -11}
    failed = sorted(k for k, v in checks.items() if not v)
    require(not failed, 'D1 baseline mismatch: ' + ', '.join(failed))
    return expected


def bind_runtime(runtime):
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.name == 'Firefox.app' and runtime.resolve() == runtime,
            'Runtime must be the link-free installed Firefox.app')
    require(tree_digest(runtime) == D1_RUNTIME, 'Runtime differs from the D1 runtime')
    executable = read_bounded(runtime / 'Contents/MacOS/firefox', 1 << 30)
    require(hashlib.sha256(executable).hexdigest() == D1_EXECUTABLE, 'Executable differs from D1')


def nix_frontend(nix_bin):
    """The closure-query frontend the preflight selects from nix_bin, its first PATH entry."""
    usable = [nix_bin / name for name in NIX_FRONTENDS
              if (nix_bin / name).is_file() and os.access(nix_bin / name, os.X_OK)]
    return usable[0] if usable else None


def launch_environment(python, nix_bin, root):
    """Minimal parent environment. The preflight builds its own browser environment."""
    python, nix_bin = Path(python), Path(nix_bin)
    require(python.is_absolute() and python.resolve(strict=True) == python and python.is_relative_to(STORE),
            'Launch Python must be a resolved /nix/store interpreter')
    require(nix_bin.is_absolute() and nix_bin.resolve(strict=True) == nix_bin and nix_bin.is_relative_to(STORE)
            and nix_bin.is_dir(), NIX_BIN_REFUSED)
    # A store bin's frontend may be a multi-call link (nix-store -> nix); it must stay in the store.
    frontend = nix_frontend(nix_bin)
    require(frontend is not None and frontend.resolve(strict=True).is_relative_to(STORE), NIX_BIN_REFUSED)
    return {'PATH': f'{nix_bin}:/usr/bin:/bin', 'HOME': str(root / 'home'), 'LANG': 'en_US.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1'}


def predict(root):
    """Internal: run under the exact launch interpreter and environment. Writes empty dirs only.

    Also imports pytest, so an interpreter that cannot run the prerequisite refuses
    before the claim instead of consuming it as PREREQUISITE_FAILED."""
    import pytest
    spec = importlib.util.spec_from_file_location('cnt_native_preflight_d2', HERE / 'cnt-native-preflight.py')
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    run = Path(root).absolute()
    run.mkdir()
    predicted = predicted_policy(run, preflight.runtime_roots(Path(sys.executable).resolve(strict=True)))
    print(json.dumps({**predicted, 'pytest_version': pytest.__version__}))
    return 0


def predicted_policy(run, interpreter_roots):
    """Same roots, services and lane as the preflight's D2 launch; the port is normalized away."""
    bundle = run / 'runtime/Firefox.app'
    bundle.mkdir(parents=True)
    roots = sorted(set([bundle] + list(interpreter_roots)))
    text = policy(run, roots, D2_SERVICES, PREDICTION_PORT, firefox_child_ipc=True,
                  firefox_executable=bundle / 'Contents/MacOS/firefox')
    evidence = policy_evidence(text, run, PREDICTION_PORT, True, D2_SERVICES)
    return {k: evidence[k] for k in ('policy_template_sha256', 'policy_template_without_configd_sha256')}


def predicted_template(python, env, root):
    work = root / ('prediction-' + os.urandom(6).hex())
    work.mkdir(mode=0o700)
    with (work / 'stdout.json').open('w') as out, (work / 'stderr.log').open('w') as err:
        process = spawn([str(python), '-B', str(RUNNER), 'predict', '--root', str(work / 'run')],
                        env=env, cwd=work, stdout=out, stderr=err)
        code, interrupted = wait_retained(process)
    require(code == 0 and not interrupted, 'Policy prediction failed')
    return json.loads(read_bounded(work / 'stdout.json', 4096))


def save_state(root, state):
    temporary = root / 'D2-state.json.tmp'
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(root / 'D2-state.json')


def prerequisite(python, env, snapshot, root, optimized):
    mode = 'optimized' if optimized else 'normal'
    argv = [str(python), '-B', *(['-O'] if optimized else []), '-m', 'pytest', '--import-mode=importlib',
            '-q', '-p', 'no:cacheprovider', '--basetemp', str(root / ('pytest-' + mode)),
            *[str(snapshot / s) for s in PREREQUISITE_SUITES]]
    log = root / ('pytest-' + mode + '.log')
    with log.open('w') as out:
        code, interrupted = wait_retained(spawn(argv, env=env, cwd=snapshot, stdout=out, stderr=subprocess.STDOUT))
    tail = read_bounded(log).decode('utf-8', 'replace').strip().splitlines()[-1:] or ['']
    passed = re.search(r'\b(\d+) passed\b', tail[0])
    counts = {'mode': mode, 'returncode': code, 'interrupted': interrupted,
              'passed': int(passed.group(1)) if passed else 0,
              'other_outcomes': bool(re.search(r'\b(failed|error|errors|skipped|xfailed)\b', tail[0])),
              'log_sha256': hashlib.sha256(read_bounded(log)).hexdigest()}
    counts['ok'] = (code == 0 and not interrupted and counts['passed'] == PREREQUISITE_PASSED
                    and not counts['other_outcomes'])
    return counts


def exclusive(path, record):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(json.dumps(record) + '\n')


def run(args):
    root = managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    claim, attempt, host_claim = root / 'D2.claim', root / 'attempt', SCRATCH / HOST_CLAIM_NAME
    require(not os.path.lexists(host_claim), 'D2 already claimed on this host: collect from its claim root; never rerun')
    require(not os.path.lexists(claim), 'D2 already claimed: use collect; never rerun')
    require(not os.path.lexists(attempt), 'Attempt directory already present')
    snapshot = managed(args.snapshot, 'Snapshot')
    runtime = Path(args.runtime)
    # Pre-claim steps launch no browser and do not consume the claim. They read the
    # bindings and write only root/home (reused if a refused run is retried) and a
    # fresh root/prediction-* directory; the browser gets fresh roots from the preflight.
    inventory = verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    d1 = bind_d1(args.d1_result, args.d1_result_sha256)
    bind_runtime(runtime)
    env = launch_environment(args.python, args.nix_bin, root)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    prediction = predicted_template(args.python, env, root)
    require(prediction.get('policy_template_without_configd_sha256') == D1_TEMPLATE,
            'Predicted launch policy is not D1 plus exactly the configd rule')
    require(isinstance(prediction.get('pytest_version'), str), 'Launch interpreter cannot import pytest')
    state = {'schema': 'bux-r4c7-host-d2-state-v1', 'phase': 'CLAIMED', 'claimed_utc': utc(),
             'inventory_sha256': inventory, 'd1_result_sha256': d1,
             'predicted_template_sha256': prediction.get('policy_template_sha256'),
             'predicted_template_without_configd_sha256': prediction['policy_template_without_configd_sha256'],
             'launch_pytest_version': prediction['pytest_version'],
             'launch_environment_names': sorted(env), 'interrupted': False, 'prerequisites': [],
             'launch_options': d2_options('<RUNTIME>', '<ATTEMPT>')}
    record = {'schema': 'bux-r4c7-host-d2-claim-v1', 'claimed_utc': state['claimed_utc'],
              'inventory_sha256': inventory, 'd1_result_sha256': d1}
    # Host claim first: a failure between the two leaves D2 claimed and unlaunched, never twice.
    exclusive(host_claim, {**record, 'claim_root_name': root.name})
    exclusive(claim, record)
    save_state(root, state)
    try:
        claimed(args, env, snapshot, runtime, attempt, root, state)
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        state.update(phase='INTERRUPTED_RETAINED' if interrupted else 'RUNNER_REFUSED',
                     interrupted=state['interrupted'] or interrupted,
                     runner_failure={'type': type(error).__name__,
                                     'message': str(error) if type(error).__name__ == 'VerificationError' else None})
        if not isinstance(error, Exception):
            save_state(root, state)
            raise
    save_state(root, state)
    return collect(root)


def claimed(args, env, snapshot, runtime, attempt, root, state):
    """After the claim: nothing here is retried, and nothing kills a child."""
    for optimized in (False, True):
        counts = prerequisite(args.python, env, snapshot, root, optimized)
        state['prerequisites'].append(counts)
        if counts['interrupted']:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        if not counts['ok']:
            state['phase'] = 'PREREQUISITE_FAILED'
            return
    # Re-verify after pytest (bytecode/cache writes) and immediately before the one launch.
    verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    state.update(phase='LAUNCHING', launched_utc=utc())
    save_state(root, state)
    argv = [str(args.python), '-B', str(snapshot / 'tests/cnt-native-preflight.py'),
            *d2_options(runtime, attempt)]
    with (root / 'preflight-stdout.json').open('w') as out, (root / 'preflight-stderr.log').open('w') as err:
        code, interrupted = wait_retained(spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
    state.update(phase='INTERRUPTED_RETAINED' if interrupted else 'LAUNCH_RETURNED',
                 preflight_exit=code, interrupted=interrupted, returned_utc=utc())


def failure(value):
    if not isinstance(value, dict):
        return None if value is None else {'present': True}
    return {k: value[k] for k in ('stage', 'type', 'classification') if isinstance(value.get(k), str)}


def policy_delta(attempt, preflight):
    port = preflight.get('automation_port')
    try:
        raw = read_bounded(attempt / 'confinement.sb', 1 << 20)
    except (OSError, RuntimeError) as error:
        return {'status': 'UNREADABLE', 'type': type(error).__name__, 'd1_template_match': False,
                'launch_policy_matches_preflight': False}
    text = raw.decode('utf-8', 'replace')
    count = text.count(CONFIGD_RULE)
    stripped = text.replace(CONFIGD_RULE, '', 1)
    template = policy_evidence(stripped, attempt, port if type(port) is int else None, True)['policy_template_sha256']
    match = count == 1 and template == D1_TEMPLATE
    return {'status': 'READ', 'launch_policy_matches_preflight':
                hashlib.sha256(raw).hexdigest() == preflight.get('policy_sha256'),
            'configd_rule_count': count, 'added_rule': CONFIGD_RULE.strip(),
            'template_sha256': preflight.get('policy_template_sha256'),
            'template_without_configd_sha256': template, 'd1_template_sha256': D1_TEMPLATE,
            'd1_template_match': match,
            'attribution': 'ONLY_CONFIGD_RULE' if match else 'UNATTRIBUTED_POLICY_DIFFERENCE'}


def listeners(result, port):
    samples = [s for s in result.get('listener_samples') or [] if isinstance(s, dict)]
    expected = {f'127.0.0.1:{port}', f'[::1]:{port}'}
    addresses = [a for s in samples for a in (s.get('tcp_listeners') or [])]
    canaries = (result.get('preflight') or {}).get('canaries') or {}
    return {'listener_sample_count': len(result.get('listener_samples') or []),
            'samples_with_tcp_listener': sum(bool(s.get('tcp_listeners')) for s in samples),
            'all_owned': bool(samples) and all(s.get('owned') is True for s in samples),
            'loopback_only': all(a in expected for a in addresses),
            # Copied exactly as the preflight canary recorded them; never relabelled.
            'same_port_wildcard_bind': canaries.get('same_port_wildcard_bind'),
            'public_bind_refused': canaries.get('public_bind_refused')}


def summarize(state, attempt):
    summary = {'schema': 'bux-r4c7-host-d2-summary-v1', 'diagnostic_only': True,
               'qualification_accepted': False,
               'scope': 'One-factor configd diagnostic; exit zero supports the hypothesis only.',
               'claim': {k: state.get(k) for k in ('phase', 'claimed_utc', 'inventory_sha256', 'd1_result_sha256',
                                                   'predicted_template_sha256',
                                                   'predicted_template_without_configd_sha256',
                                                   'launch_pytest_version',
                                                   'preflight_exit', 'interrupted', 'runner_failure',
                                                   'launch_environment_names', 'launch_options')},
               'prerequisites': state.get('prerequisites', [])}
    interrupted = state.get('interrupted') is True
    if not os.path.lexists(attempt / 'result.json'):
        launched = state.get('phase') in ('LAUNCHING', 'LAUNCH_RETURNED', 'INTERRUPTED_RETAINED') \
            and 'launched_utc' in state
        summary['label'] = ('D2_INCOMPLETE_INTERRUPTED' if interrupted
                            else 'D2_DIAGNOSTIC_FAILED' if launched else 'D2_PREREQUISITE_FAILED')
        summary['result'] = 'ABSENT'
        return summary
    r = json.loads(read_bounded(attempt / 'result.json'))
    p = r.get('preflight') or {}
    s = r.get('settlement') or {}
    port = p.get('automation_port')
    methods = [m.get('method') for m in r.get('protocol') or [] if isinstance(m, dict)]
    delta = policy_delta(attempt, p)
    observed = listeners(r, port)
    summary.update(
        outcome={'status': r.get('status'), 'exit_before_cleanup': r.get('exit_before_cleanup'),
                 'quit_observed': r.get('quit_observed'), 'marionette_quit_requested': 'Marionette:Quit' in methods,
                 'protocol': [{'method': m.get('method'), 'outcome': m.get('outcome')}
                              for m in r.get('protocol') or [] if isinstance(m, dict)],
                 'settlement': {k: s.get(k) for k in ('exit_code', 'zero_survivors', 'unsettled', 'workload_status')},
                 'settlement_failure_count': len(s.get('failures') or []) if isinstance(s.get('failures'), list) else None,
                 **{k: failure(r.get(k)) for k in FAILURE_FIELDS}},
        runtime={k: r.get(k) for k in ('runtime_source_sha256', 'runtime_snapshot_sha256', 'runtime_observed_sha256',
                                       'runtime_unchanged', 'executable_sha256', 'browser_version', 'signature')},
        choices={k: r.get(k) for k in ('engine', 'workload', 'abnormal', 'shutdown_trace', 'crash_force_enable',
                                       'crash_readback', 'parent_probes', 'shutdown_observer', 'sandbox_disables',
                                       'mach_services', 'configd_compatibility', 'environment_names')},
        listeners=observed, policy_delta=delta,
        shutdown_trace_summary=r.get('shutdown_trace_summary'),
        owned_crash_artifacts={k: {f: v.get(f) for f in ('status', 'counts', 'provenance')}
                               for k, v in (r.get('owned_crash_artifacts') or {}).items() if isinstance(v, dict)})
    conjuncts = {
        'status_diagnostic_completed': r.get('status') == 'DIAGNOSTIC_COMPLETED',
        'exit_zero_before_cleanup': type(r.get('exit_before_cleanup')) is int and r['exit_before_cleanup'] == 0,
        'quit_requested': 'Marionette:Quit' in methods and r.get('quit_observed') in ('reply', 'qualified-eof'),
        'clean_settlement': (type(s.get('exit_code')) is int and s['exit_code'] == 0
                             and s.get('zero_survivors') is True and s.get('unsettled') is False
                             and s.get('failures') == [] and s.get('workload_status') == 'exited'),
        'no_recorded_failure': not any(r.get(k) for k in FAILURE_FIELDS),
        'runtime_identity': (r.get('runtime_unchanged') is True
                             and r.get('runtime_snapshot_sha256') == r.get('runtime_observed_sha256') == D1_RUNTIME
                             and r.get('executable_sha256') == D1_EXECUTABLE),
        'configuration': (r.get('engine') == 'firefox' and r.get('workload') == 'empty'
                          and r.get('abnormal') is False and r.get('shutdown_trace') is True
                          and r.get('crash_force_enable') is False and r.get('crash_readback') is False
                          and r.get('parent_probes') is False and r.get('shutdown_observer') is False
                          and r.get('sandbox_disables') == D1_EXCEPTIONS
                          and r.get('mach_services') == list(D2_SERVICES)
                          and r.get('configd_compatibility') is True),
        'listeners_owned_loopback': (observed['all_owned'] and observed['loopback_only']
                                     and observed['samples_with_tcp_listener'] > 0),
        'policy_one_factor': delta['d1_template_match'] is True and delta['launch_policy_matches_preflight'] is True,
        'not_interrupted': not interrupted}
    summary['failed_conjuncts'] = sorted(k for k, v in conjuncts.items() if v is not True)
    summary['label'] = (SUPPORTS if not summary['failed_conjuncts']
                        else 'D2_INCOMPLETE_INTERRUPTED' if interrupted else 'D2_DIAGNOSTIC_FAILED')
    return summary


def collect(root):
    root = managed(root, 'Claim root')
    require(os.path.lexists(root / 'D2.claim'), 'No D2 claim to collect')
    state = json.loads(read_bounded(root / 'D2-state.json'))
    summary = summarize(state, root / 'attempt')
    for index in range(1, 1000):
        name = f'D2-SUMMARY-{index:03d}.json'
        try:
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({'label': summary['label'], 'summary': name,
                          'failed_conjuncts': summary.get('failed_conjuncts')}))
        return 0
    raise RuntimeError('Summary slots exhausted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    execute = commands.add_parser('run')
    for name in ('snapshot', 'inventory', 'd1-result', 'runtime', 'python', 'nix-bin', 'claim-root'):
        execute.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-inventory-sha256', 'd1-result-sha256'):
        execute.add_argument('--' + name, required=True)
    commands.add_parser('collect').add_argument('--claim-root', type=Path, required=True)
    commands.add_parser('predict').add_argument('--root', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'predict':
        return predict(args.root)
    return run(args) if args.command == 'run' else collect(args.claim_root)


if __name__ == '__main__':
    raise SystemExit(main())
