"""HOST Chrome recipe runner (R5-CHROME-PREP2). UNEXECUTED; never agent-executed.

`bind` launches no browser and consumes no claim. It verifies the exported snapshot,
requires the operator's selection path to resolve to the explicit store Google Chrome.app,
measures that app (tree digest, executable, bundle identity, codesign) and predicts the
Chrome closure and launch policy template under the launch interpreter. It writes the next
exclusive BIND-NNN.json. With --reference-bind it also refuses unless the fresh identity equals
that earlier record's identity; the reference is only read and only its SHA-256 is recorded.

`run --operation startup` launches one empty diagnostic. `run --operation pair` launches
NORMAL full, then ABNORMAL full only after NORMAL passed, and requires a completed startup
summary for the same bind record, read from the claim root that consumed this host's startup
claim. A failed startup also consumes that claim. Each operation re-binds and requires equality with the bind
record, takes its host-wide claim plus a per-root claim, runs the owned-process prerequisite
in both Python modes and re-checks snapshot and selection immediately before and after each
launch. There is no default operation, retry or kill: children are waited for and cleanup
belongs to the preflight supervisor. `collect` never launches and never overwrites a summary.

No output contains a raw path; the runtime path is bound by its SHA-256 only.

R5-CHROME-C1A lane (`--chrome-rendezvous own-workload-pid` on bind and run; absent keeps every
baseline behaviour above). Its bind requires the baseline reference record and refuses unless
the runtime identity equals it and removing exactly the one rendezvous rule from the new
predicted template reproduces the reference template; the reference is never rewritten. Its
own claims are `bux-r5-chrome-c1a-{startup,pair}.claim`; the baseline claims are never read,
created or checked by it. After the prerequisites and before any launch it runs `pid-check`:
the existing Python canary through the rendezvous helper and `sandbox-exec -D` under its own
PID (no Chrome execution, no Mach call, no other service), then the same policy without the
parameter, which must refuse before its program runs. Any failure stops before a launch.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402
from cnt_chrome_rendezvous import RULE, matched, project  # noqa: E402
from cnt_confinement import REVIEWED_SERVICES, policy, policy_evidence  # noqa: E402
from cnt_native_evidence import require, tree_digest  # noqa: E402
from cnt_synthetic_chrome import (QUALIFIED_CLOSE_ENTRY, USEFUL_FLAGS, close_count, collapsed,  # noqa: E402
                                  expected_sequence, protocol_passed)

RUNNER = Path(__file__).resolve()
SERVICES = list(REVIEWED_SERVICES)
# Other names under which a Chrome may appear. Classified by link metadata only; never read.
ALIASES = {'nix_apps': Path('/Applications/Nix Apps/Google Chrome.app')}
DAILY_APP = Path('/Applications/Google Chrome.app')
HOST_CLAIMS = {'startup': 'bux-r5-chrome-startup.claim', 'pair': 'bux-r5-chrome-pair.claim'}
ROLES = {'startup': ('startup',), 'pair': ('normal', 'abnormal')}
STARTUP_LABEL = 'CHROME_STARTUP_DIAGNOSTIC_COMPLETED'
PAIR_LABEL = 'CHROME_USEFUL_PAIR_PASSED_PENDING_MANAGER_REVIEW'
IDENTITY = ('runtime_path_sha256', 'bundle_id', 'bundle_version', 'runtime_sha256', 'executable_sha256',
            'signature_original', 'closure_count', 'closure_sha256', 'policy_template_sha256', 'services')
FAILURE_FIELDS = d2.FAILURE_FIELDS
FIREFOX_OPTIONS = ('crash_force_enable', 'crash_readback', 'parent_probes', 'shutdown_trace')
# R5-CHROME-C1A: explicit own-workload-PID rendezvous lane. Never the default.
C1A = 'own-workload-pid'
C1A_LANE = 'C1A_OWN_WORKLOAD_PID'
C1A_CLAIMS = {'startup': 'bux-r5-chrome-c1a-startup.claim', 'pair': 'bux-r5-chrome-c1a-pair.claim'}
BIND_SCHEMA, C1A_BIND_SCHEMA = 'bux-r5-chrome-bind-v1', 'bux-r5-chrome-c1a-bind-v1'
DELTA_KIND = 'CHROME_RENDEZVOUS_OWN_WORKLOAD_PID_RULE'
CANARY_PASSED = 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION'
# Names the C1A lane creates beside each attempt; any leftover refuses before the claim.
C1A_SIBLINGS = ('-outside-canary', '-rendezvous')
UNDEFINED_PROGRAM = "open('undefined-parameter-ran','x').close()"
HELPER_FAILURES = {'HELPER_REFUSED', 'EXEC_FAILED', 'RECORD_ABSENT', 'RECORD_INVALID', 'ARGV_MISMATCH'}
CDP_UNSUPPORTED = {'CDP_METHOD_UNAVAILABLE', 'CDP_PROTOCOL_ERROR', 'CDP_SESSION_NOT_FOUND'}


def load_preflight():
    spec = importlib.util.spec_from_file_location('cnt_native_preflight_chrome', HERE / 'cnt-native-preflight.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def classify(alias, runtime):
    if not os.path.lexists(alias):
        return 'ABSENT'
    if stat.S_ISLNK(os.lstat(alias).st_mode):
        return 'LINK_SAME' if Path(alias).resolve() == runtime else 'LINK_DIFFERENT'
    return 'NOT_LINK_CONTENT_UNREAD'


def select(selection, runtime):
    """The operator's selection must resolve to the explicit runtime; no alias may disagree."""
    selection, runtime = Path(selection), Path(runtime)
    require(selection.is_absolute() and os.path.lexists(selection), 'Chrome selection missing')
    require(selection.resolve(strict=True) == runtime, 'Chrome selection differs from the explicit runtime')
    aliases = {name: classify(path, runtime) for name, path in ALIASES.items()}
    require('LINK_DIFFERENT' not in aliases.values(), 'Chrome selection ambiguous')
    return {'selection_resolves_to_runtime': True, 'aliases': aliases,
            'daily_app_present_unread': os.path.lexists(DAILY_APP)}


def measure(preflight, runtime):
    """Identity of the selected app. The digest is repeated after codesign to catch drift."""
    executable, version = preflight.chrome_bundle(runtime)
    digest = tree_digest(runtime)
    executable_sha = hashlib.sha256(d2.read_bounded(executable, 1 << 30)).hexdigest()
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(runtime)],
                              capture_output=True, timeout=120)
    require(verified.returncode == 0, 'Chrome original signature invalid')
    require(tree_digest(runtime) == digest, 'Chrome runtime changed during binding')
    return {'runtime_path_sha256': hashlib.sha256(str(runtime).encode()).hexdigest(),
            'bundle_id': preflight.CHROME_BUNDLE_ID, 'bundle_version': version, 'runtime_sha256': digest,
            'executable_sha256': executable_sha, 'signature_original': True}


def predicted(run, chrome_roots, interpreter_roots):
    """Same roots, services and portless lane as the preflight Chrome launch."""
    roots = sorted(set(list(chrome_roots) + list(interpreter_roots)))
    text = policy(run, roots, SERVICES, None, firefox_child_ipc=False)
    return policy_evidence(text, run, None, False, SERVICES)['policy_template_sha256']


def predicted_c1a(run, chrome_roots, interpreter_roots, executable, baseline):
    """The C1A template, and proof that removing exactly its one rule gives the baseline template."""
    roots = sorted(set(list(chrome_roots) + list(interpreter_roots)))
    text = policy(run, roots, SERVICES, None, firefox_child_ipc=False, chrome_rendezvous=True,
                  chrome_executable=Path(executable))
    evidence = policy_evidence(text, run, None, False, SERVICES, chrome_rendezvous=True)
    require(evidence['policy_template_without_rendezvous_sha256'] == baseline,
            'Rendezvous policy is not the baseline plus exactly the one rule')
    return {'policy_template_sha256': evidence['policy_template_sha256'],
            'baseline_policy_template_sha256': baseline}


def predict(root, runtime, c1a=False):
    """Internal: runs under the exact launch interpreter and PATH. Writes an empty directory only."""
    import pytest
    preflight = load_preflight()
    run = Path(root).absolute()
    run.mkdir()
    chrome = preflight.runtime_roots(Path(runtime) / preflight.CHROME_EXECUTABLE)
    count, closure = preflight.closure_identity(chrome)
    interpreter = preflight.runtime_roots(Path(sys.executable).resolve(strict=True))
    template = predicted(run, chrome, interpreter)
    value = {'policy_template_sha256': template, 'closure_count': count, 'closure_sha256': closure,
             'pytest_version': pytest.__version__}
    if c1a:
        value.update(predicted_c1a(run, chrome, interpreter, Path(runtime) / preflight.CHROME_EXECUTABLE, template))
    print(json.dumps(value))
    return 0


def prediction(python, env, root, runtime, c1a=False):
    work = root / ('prediction-' + os.urandom(6).hex())
    work.mkdir(mode=0o700)
    with (work / 'stdout.json').open('w') as out, (work / 'stderr.log').open('w') as err:
        process = d2.spawn([str(python), '-B', str(RUNNER), 'predict', '--root', str(work / 'run'),
                            '--runtime', str(runtime), *(['--chrome-rendezvous', C1A] if c1a else [])],
                           env=env, cwd=work, stdout=out, stderr=err)
        code, interrupted = d2.wait_retained(process)
    require(code == 0 and not interrupted, 'Policy prediction failed')
    value = json.loads(d2.read_bounded(work / 'stdout.json', 4096))
    require(isinstance(value, dict) and isinstance(value.get('pytest_version'), str),
            'Launch interpreter cannot import pytest')
    require(not c1a or isinstance(value.get('baseline_policy_template_sha256'), str),
            'Rendezvous policy prediction incomplete')
    return value


def lane(args):
    """True only for exactly one explicit C1A selection; absence is the baseline lane."""
    selected = list(getattr(args, 'chrome_rendezvous', None) or [])
    require(len(selected) <= 1, 'Duplicate rendezvous selection')
    require(all(choice == C1A for choice in selected), 'Chrome rendezvous option invalid')
    return bool(selected)


def binding(args, root):
    """Everything a launch depends on, recomputed from the host. Launches no browser."""
    snapshot = d2.managed(args.snapshot, 'Snapshot')
    require(RUNNER == snapshot / 'tests/cnt_host_chrome.py', 'Runner must execute from the approved snapshot')
    inventory = d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    runtime = Path(args.runtime)
    preflight = load_preflight()
    selection = select(args.selection, runtime)
    identity = measure(preflight, runtime)
    env = d2.launch_environment(args.python, args.nix_bin, root)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    c1a = lane(args)
    predicted_values = prediction(args.python, env, root, runtime, c1a)
    identity.update(closure_count=predicted_values['closure_count'],
                    closure_sha256=predicted_values['closure_sha256'],
                    policy_template_sha256=predicted_values['policy_template_sha256'], services=SERVICES)
    if c1a:
        identity.update(baseline_policy_template_sha256=predicted_values['baseline_policy_template_sha256'],
                        chrome_rendezvous='OWN_WORKLOAD_PID')
    return {'schema': C1A_BIND_SCHEMA if c1a else BIND_SCHEMA, 'bound_utc': d2.utc(), 'inventory_sha256': inventory,
            'identity': identity, 'selection': selection, 'launch_pytest_version': predicted_values['pytest_version'],
            'launch_environment_names': sorted(env), 'scope': 'Binding only; no browser launched, no claim.'}, env


def next_slot(root, prefix, value):
    for index in range(1, 1000):
        name = f'{prefix}-{index:03d}.json'
        try:
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        raw = (json.dumps(value, indent=2) + '\n').encode()
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
        return name, hashlib.sha256(raw).hexdigest()
    raise RuntimeError('Record slots exhausted')


def authorized_delta(reference, identity):
    """C1A only: the manager-authorized one-rule policy delta against a baseline bind record.

    Dedicated, not the generic equality: the reference must be a baseline record, every other
    identity field must equal it, the new template minus exactly the one rule must equal its
    template, and the new template must differ from it. Anything else refuses.
    """
    message = 'Current runtime or policy differs from the reference bind record beyond the rendezvous rule'
    old = reference.get('identity') if isinstance(reference, dict) else None
    require(isinstance(old, dict) and reference.get('schema') == BIND_SCHEMA and set(old) == set(IDENTITY), message)
    require(all(identity.get(k) == old.get(k) for k in IDENTITY if k != 'policy_template_sha256'), message)
    require(identity.get('baseline_policy_template_sha256') == old.get('policy_template_sha256')
            != identity.get('policy_template_sha256'), message)
    return {'kind': DELTA_KIND, 'rule_sha256': hashlib.sha256(RULE.encode()).hexdigest(),
            'baseline_equals_reference': True, 'other_identity_equal': True}


def bind(args):
    root = d2.managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    c1a = lane(args)
    require(not c1a or args.reference_bind is not None, 'The C1A bind requires the baseline reference bind record')
    reference = None
    if args.reference_bind is not None:
        reference = bound_record(args.reference_bind, args.reference_bind_sha256, 'Reference bind record')
    record, _ = binding(args, root)
    if c1a:
        record['reference_delta'] = authorized_delta(reference, record['identity'])
        record['reference_bind_sha256'] = args.reference_bind_sha256
    elif reference is not None:
        # Same selected build and predicted policy as the earlier record; the source may differ.
        require(isinstance(reference, dict) and record['identity'] == reference.get('identity'),
                'Current runtime or policy differs from the reference bind record')
        record['reference_bind_sha256'] = args.reference_bind_sha256
    name, digest = next_slot(root, 'BIND', record)
    print(json.dumps({'label': 'CHROME_BOUND_NO_LAUNCH', 'bind': name, 'sha256': digest}))
    return 0


def bound_record(path, expected, label):
    raw = d2.read_bounded(path)
    require(hashlib.sha256(raw).hexdigest() == expected, label + ' is not the supplied record')
    return json.loads(raw)


def startup_claimed(path, bind_sha256, c1a=False):
    """The startup summary must sit in the claim root that consumed this host's startup claim."""
    message = 'Pair requires a completed startup diagnostic for the same bind record'
    root = d2.managed(path, 'Startup summary').parent
    try:
        claim = json.loads(d2.read_bounded(root / 'CHROME.claim'))
        host = json.loads(d2.read_bounded(d2.SCRATCH / (C1A_CLAIMS if c1a else HOST_CLAIMS)['startup']))
    except (OSError, ValueError):
        require(False, message)
    require(isinstance(claim, dict) and isinstance(host, dict)
            and claim.get('operation') == host.get('operation') == 'startup'
            and claim.get('bind_sha256') == host.get('bind_sha256') == bind_sha256
            and host.get('claim_root_name') == root.name, message)


def options(role, runtime, attempt, c1a=False):
    base = ['--engine', 'chrome', '--runtime', str(runtime), '--scratch', str(attempt),
            *[a for s in SERVICES for a in ('--service', s)]]
    return base + {'startup': ['--workload', 'empty'], 'normal': ['--workload', 'full'],
                   'abnormal': ['--workload', 'full', '--abnormal']}[role] + (['--chrome-rendezvous', C1A] if c1a else [])


def lane_label(label, c1a):
    return label.replace('CHROME_', 'CHROME_C1A_', 1) if c1a else label


def bound_lane(bound, c1a):
    """The bind record must belong to the selected lane; baseline and C1A records never mix."""
    identity = bound.get('identity') if isinstance(bound, dict) else None
    if not isinstance(identity, dict):
        return False
    if not c1a:
        return bound.get('schema') == BIND_SCHEMA and 'chrome_rendezvous' not in identity
    delta = bound.get('reference_delta')
    return (bound.get('schema') == C1A_BIND_SCHEMA and identity.get('chrome_rendezvous') == 'OWN_WORKLOAD_PID'
            and isinstance(delta, dict) and delta.get('kind') == DELTA_KIND
            and delta.get('rule_sha256') == hashlib.sha256(RULE.encode()).hexdigest()
            and isinstance(bound.get('reference_bind_sha256'), str))


def save_state(root, state):
    temporary = root / 'CHROME-state.json.tmp'
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(root / 'CHROME-state.json')


def run(args):
    root = d2.managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    operation, c1a = args.operation, lane(args)
    host_claim, claim = d2.SCRATCH / (C1A_CLAIMS if c1a else HOST_CLAIMS)[operation], root / 'CHROME.claim'
    require(not os.path.lexists(host_claim), 'Operation already claimed on this host: collect; never rerun')
    require(not os.path.lexists(claim), 'Claim root already used: collect; never rerun')
    require(not any(os.path.lexists(root / r) for rs in ROLES.values() for r in rs), 'Attempt directory present')
    if c1a:
        names = ['pid-check', *[r for rs in ROLES.values() for r in rs]]
        require(not any(os.path.lexists(root / (n + suffix)) for n in names for suffix in ('', *C1A_SIBLINGS)),
                'Attempt directory present')
    bound = bound_record(args.bind_record, args.bind_record_sha256, 'Bind record')
    require(bound_lane(bound, c1a), 'Bind record lane differs from the selected lane')
    startup = None
    if operation == 'pair':
        startup = bound_record(args.startup_summary, args.startup_summary_sha256, 'Startup summary')
        require(startup.get('label') == lane_label(STARTUP_LABEL, c1a) and startup.get('operation') == 'startup'
                and startup.get('bind_sha256') == args.bind_record_sha256,
                'Pair requires a completed startup diagnostic for the same bind record')
        startup_claimed(args.startup_summary, args.bind_record_sha256, c1a)
    # Pre-claim: launches no browser and consumes nothing.
    current, env = binding(args, root)
    require(current['inventory_sha256'] == bound.get('inventory_sha256')
            and current['identity'] == bound.get('identity'),
            'Current snapshot, runtime or policy differs from the bind record')
    state = {'schema': 'bux-r5-chrome-state-v1', 'operation': operation, 'phase': 'CLAIMED',
             'claimed_utc': d2.utc(), 'bind_sha256': args.bind_record_sha256,
             'startup_summary_sha256': args.startup_summary_sha256 if startup else None,
             'inventory_sha256': current['inventory_sha256'], 'identity': current['identity'],
             'selection': current['selection'], 'launch_environment_names': current['launch_environment_names'],
             'launch_pytest_version': current['launch_pytest_version'], 'interrupted': False,
             'prerequisites': [], 'launches': [],
             'launch_options': {r: options(r, '<RUNTIME>', '<ATTEMPT>', c1a) for r in ROLES[operation]}}
    record = {'schema': 'bux-r5-chrome-claim-v1', 'operation': operation, 'claimed_utc': state['claimed_utc'],
              'bind_sha256': args.bind_record_sha256, 'inventory_sha256': state['inventory_sha256']}
    if c1a:
        state.update(lane=C1A_LANE, reference_bind_sha256=bound['reference_bind_sha256'],
                     reference_delta=bound['reference_delta'])
        record['lane'] = C1A_LANE
    # Host claim first: a failure between the two leaves the operation claimed and unlaunched.
    d2.exclusive(host_claim, {**record, 'claim_root_name': root.name})
    d2.exclusive(claim, record)
    save_state(root, state)
    try:
        claimed(args, env, root, state)
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        state.update(phase='INTERRUPTED_RETAINED' if interrupted else 'RUNNER_REFUSED',
                     interrupted=state['interrupted'] or interrupted,
                     runner_failure={'type': type(error).__name__,
                                     'message': str(error) if type(error).__name__ == 'VerificationError'
                                     and '/' not in str(error) else None})
        if not isinstance(error, Exception):
            save_state(root, state)
            raise
    save_state(root, state)
    return collect(root)


def claimed(args, env, root, state):
    """After the claim: nothing is retried and nothing kills a child."""
    snapshot, runtime = d2.managed(args.snapshot, 'Snapshot'), Path(args.runtime)
    for optimized in (False, True):
        counts = d2.prerequisite(args.python, env, snapshot, root, optimized)
        state['prerequisites'].append(counts)
        if counts['interrupted']:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        if not counts['ok']:
            state['phase'] = 'PREREQUISITE_FAILED'
            return
    c1a = state.get('lane') == C1A_LANE
    if c1a:
        # Before any launch: the bounded non-browser PID/parameter check. No Chrome runs.
        d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
        state['phase'] = 'PID_CHECK'
        save_state(root, state)
        state['pid_check'] = check = pid_check_run(args, env, root, runtime, state['identity'])
        if check['interrupted']:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        if not check['passed']:
            state['phase'] = 'PID_CHECK_FAILED'
            return
    for role in ROLES[state['operation']]:
        entry = {'role': role}
        state['launches'].append(entry)
        # Immediately before the launch: bytes/modes/links and the selection are unchanged.
        d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
        select(args.selection, runtime)
        entry.update(selection_before='MATCH', launched_utc=d2.utc())
        state['phase'] = 'LAUNCHING'
        save_state(root, state)
        argv = [str(args.python), '-B', str(snapshot / 'tests/cnt-native-preflight.py'),
                *options(role, runtime, root / role, c1a)]
        with (root / (role + '-stdout.json')).open('w') as out, (root / (role + '-stderr.log')).open('w') as err:
            code, interrupted = d2.wait_retained(d2.spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
        entry.update(returncode=code, interrupted=interrupted, returned_utc=d2.utc())
        try:
            select(args.selection, runtime)
            entry['selection_after'] = 'UNCHANGED'
        except Exception:
            entry['selection_after'] = 'CHANGED_OR_UNRESOLVED'
        if interrupted:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        if role == 'normal' and not attempt_summary(root, role, state['identity'], entry, c1a)['passed']:
            # Normal-before-abnormal: ABNORMAL never starts after a failed NORMAL.
            state['abnormal'] = 'NOT_STARTED_NORMAL_FAILED'
            break
    state['phase'] = 'LAUNCHES_RETURNED'


def pid_check_run(args, env, root, runtime, identity):
    """Parent side of pid-check: waits, never kills, and judges only fixed fields it can verify."""
    argv = [str(args.python), '-B', str(RUNNER), 'pid-check', '--root', str(root / 'pid-check'),
            '--runtime', str(runtime)]
    entry = {'launched_utc': d2.utc()}
    with (root / 'pid-check-stdout.json').open('w') as out, (root / 'pid-check-stderr.log').open('w') as err:
        code, interrupted = d2.wait_retained(d2.spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
    entry.update(returncode=code, interrupted=interrupted, returned_utc=d2.utc())
    raw = value = None
    try:
        raw = d2.read_bounded(root / 'pid-check-stdout.json', 16384)
        value = json.loads(raw)
    except (OSError, ValueError, RuntimeError):
        pass
    value = value if isinstance(value, dict) else {}
    settlement = value.get('settlement') if isinstance(value.get('settlement'), dict) else {}
    undefined = value.get('undefined_parameter') if isinstance(value.get('undefined_parameter'), dict) else {}
    checks = {
        'returned_zero': code == 0 and not interrupted,
        'canaries_passed': value.get('status') == CANARY_PASSED,
        'settled': (settlement.get('exit_code') == 0 and settlement.get('zero_survivors') is True
                    and settlement.get('unsettled') is False and settlement.get('failures') == []),
        'own_pid_parameter': matched(value.get('rendezvous_canary'), canary=True),
        'template_matches_bind': value.get('policy_template_sha256') == identity.get('policy_template_sha256'),
        'baseline_matches_bind': (value.get('policy_template_without_rendezvous_sha256')
                                  == identity.get('baseline_policy_template_sha256')),
        'undefined_parameter_refused': undefined.get('state') == 'REFUSED_BEFORE_PROGRAM'}
    entry.update(checks=checks, failed_checks=sorted(k for k, v in checks.items() if v is not True),
                 rendezvous_canary=project(value.get('rendezvous_canary')),
                 undefined_parameter=project_undefined(undefined),
                 stdout_sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None)
    entry['passed'] = not entry['failed_checks']
    return entry


UNDEFINED_STATES = ('REFUSED_BEFORE_PROGRAM', 'PROGRAM_RAN_WITHOUT_PARAMETER', 'UNCLASSIFIED', 'NOT_RUN_CANARY_FAILED')


def project_undefined(value):
    """Fixed-key export of the undefined-parameter result; anything unexpected becomes None."""
    digest = value.get('log_sha256')
    return {'state': value.get('state') if value.get('state') in UNDEFINED_STATES else None,
            'exit_code': value.get('exit_code') if type(value.get('exit_code')) is int else None,
            'log_sha256': digest if type(digest) is str and len(digest) == 64
            and all(c in '0123456789abcdef' for c in digest) else None,
            'log_bytes': value.get('log_bytes') if type(value.get('log_bytes')) is int else None}


def undefined_parameter(run, python):
    """Same policy file, no -D parameter, a trivial marker program. Expected: refused before it runs."""
    from cnt_confinement import environment
    from cnt_owned_process import OwnedProcess
    command = ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb'), str(python), '-B', '-c',
               UNDEFINED_PROGRAM]
    evidence = {}
    with (run / 'undefined-parameter.log').open('w') as log:
        process = OwnedProcess(command, run, environment(run), log, evidence=evidence)
        try:
            process.until(lambda: process.returncode is not None, 15)
        except Exception as error:
            evidence['wait_failure'] = type(error).__name__
        finally:
            try:
                settlement = process.settle()
            except Exception as cleanup:
                settlement = process.result or {}
                evidence['cleanup_failure'] = type(cleanup).__name__
    code = settlement.get('exit_code')
    clean = (settlement.get('zero_survivors') is True and settlement.get('unsettled') is False
             and 'cleanup_failure' not in evidence and 'wait_failure' not in evidence)
    # The classification rests on the marker and exit code only; sandbox-exec's refusal text is
    # host-unobserved, so it is not a gate. The private log stays in the run; its digest and
    # size are exported so a reviewer can tell a sandbox-exec refusal from an early program error.
    try:
        raw = d2.read_bounded(run / 'undefined-parameter.log', 16384)
    except (OSError, RuntimeError):
        raw = None
    if os.path.lexists(run / 'undefined-parameter-ran'):
        state = 'PROGRAM_RAN_WITHOUT_PARAMETER'
    elif type(code) is int and code != 0 and clean:
        state = 'REFUSED_BEFORE_PROGRAM'
    else:
        state = 'UNCLASSIFIED'
    return {'state': state, 'exit_code': code if type(code) is int else None, 'clean_settlement': clean,
            'log_sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None,
            'log_bytes': len(raw) if raw is not None else None}


def pid_check(root, runtime):
    """Internal, under the launch interpreter: the bounded non-browser PID/parameter check.

    Reads the selected app's plist and layout and queries its store closure; never runs Chrome.
    The canary is the existing Python probe through the helper under its own PID.
    """
    import socket
    from cnt_confinement import fresh_attempt, run_probe
    preflight = load_preflight()
    executable, _ = preflight.chrome_bundle(runtime)
    python = Path(sys.executable).resolve(strict=True)
    roots = sorted(set(preflight.runtime_roots(executable) + preflight.runtime_roots(python)))
    run = fresh_attempt(Path(root))
    outside = run.parent / (run.name + '-outside-canary')
    with outside.open('x') as stream:
        stream.write('synthetic private canary')
    evidence = run.parent / (run.name + '-rendezvous')
    evidence.mkdir(mode=0o700)
    evidence.chmod(0o700)
    result = {}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        run_probe(run, python, roots, outside, listener.getsockname()[1], SERVICES, automation_port=None,
                  firefox_child_ipc=False, firefox_executable=executable, evidence=result,
                  chrome_rendezvous=True, chrome_executable=executable, rendezvous_evidence=evidence)
    settlement = result.get('settlement') or {}
    undefined = (undefined_parameter(run, python) if result.get('status') == CANARY_PASSED
                 else {'state': 'NOT_RUN_CANARY_FAILED'})
    print(json.dumps({
        'status': result.get('status'),
        'settlement': {k: settlement.get(k) for k in ('exit_code', 'zero_survivors', 'unsettled', 'failures')},
        'rendezvous_canary': project(result.get('rendezvous_canary')),
        'policy_template_sha256': result.get('policy_template_sha256'),
        'policy_template_without_rendezvous_sha256': result.get('policy_template_without_rendezvous_sha256'),
        'undefined_parameter': undefined}))
    return 0


def failure(value):
    if not isinstance(value, dict):
        return None if value is None else {'present': True}
    return {k: value[k] for k in ('stage', 'type', 'classification', 'code') if isinstance(value.get(k), str)}


def policy_check(attempt, preflight, identity, c1a=False):
    try:
        raw = d2.read_bounded(attempt / 'confinement.sb', 1 << 20)
    except (OSError, RuntimeError) as error:
        return {'status': 'UNREADABLE', 'type': type(error).__name__, 'matches': False}
    evidence = policy_evidence(raw.decode('utf-8', 'replace'), attempt, None, False,
                               **({'chrome_rendezvous': True} if c1a else {}))
    template = evidence['policy_template_sha256']
    result = {'status': 'READ',
              'launch_policy_matches_preflight': hashlib.sha256(raw).hexdigest() == preflight.get('policy_sha256'),
              'preflight_template_matches_bind': preflight.get('policy_template_sha256')
              == identity.get('policy_template_sha256'),
              'launch_template_matches_bind': template == identity.get('policy_template_sha256')}
    if c1a:
        # Only the one authorized rule, and only its explicit parameter, separate it from the baseline.
        result['launch_template_without_rendezvous_matches_baseline'] = (
            evidence['policy_template_without_rendezvous_sha256'] is not None
            and evidence['policy_template_without_rendezvous_sha256']
            == identity.get('baseline_policy_template_sha256'))
    result['matches'] = all(result[k] is True for k in result if k not in ('status',))
    return result


def cdp_unsupported(r, methods):
    code = (r.get('primary_failure') or {}).get('code') if isinstance(r.get('primary_failure'), dict) else None
    return code in CDP_UNSUPPORTED or any('protocol_error' in m for m in methods)


def cleanup_failed(r, settlement):
    return bool(r.get('cleanup_failure') or settlement.get('zero_survivors') is not True
                or settlement.get('unsettled') is not False or settlement.get('observed_escapes') not in (0, None))


def c1a_outcome(role, r, p, methods, passed):
    """One fixed label per C1A attempt, first match wins. Failure fields stay separate facts."""
    if r.get('chrome_rendezvous') != 'OWN_WORKLOAD_PID':
        return 'RENDEZVOUS_NOT_SELECTED'
    canary, launch = p.get('rendezvous_canary'), r.get('rendezvous_parameter')
    states = {v.get('state') for v in (canary, launch) if isinstance(v, dict)}
    settlement = r.get('settlement') or {}
    if 'INVALID_PARAMETER' in states:
        return 'RENDEZVOUS_INVALID_PARAMETER'
    if states & HELPER_FAILURES:
        return 'RENDEZVOUS_HELPER_OR_EXEC_FAILED'
    if 'PID_MISMATCH' in states:
        return 'RENDEZVOUS_PID_MISMATCH'
    if not isinstance(canary, dict):
        return 'OTHER_FAILURE'
    if not matched(canary, canary=True) or p.get('status') != CANARY_PASSED:
        return 'RENDEZVOUS_CANARY_REFUSED'
    if r.get('browser_launched') is not True:
        return 'OTHER_FAILURE'
    if r.get('ready') is not True and r.get('cdp_stage') in (None, 'startup') and not cdp_unsupported(r, methods):
        return 'PRE_CDP_FAILURE'
    if not matched(launch):
        return 'RENDEZVOUS_UNOBSERVED'
    if cdp_unsupported(r, methods):
        return 'CDP_UNSUPPORTED'
    if cleanup_failed(r, settlement):
        return 'OWNED_CLEANUP_FAILED'
    if passed:
        return 'INTENDED_ABNORMAL_TIMEOUT' if role == 'abnormal' else 'NORMAL_CLOSE'
    return 'OTHER_FAILURE'


def attempt_summary(root, role, identity, entry, c1a=False):
    """Fixed facts and conjuncts for one attempt. Never raw paths, argv or messages."""
    attempt = root / role
    if not os.path.lexists(attempt / 'result.json'):
        return {'role': role, 'result': 'ABSENT', 'passed': False, 'failed_checks': ['result_present']}
    r = json.loads(d2.read_bounded(attempt / 'result.json'))
    p, s = r.get('preflight') or {}, r.get('settlement') or {}
    methods = [m for m in r.get('protocol') or [] if isinstance(m, dict)]
    measurement = r.get('runtime_measurement') or {}
    startup, abnormal = role == 'startup', role == 'abnormal'
    workload = 'empty' if startup else 'full'
    exited_zero = (type(r.get('exit_before_cleanup')) is int and r['exit_before_cleanup'] == 0
                   and type(s.get('exit_code')) is int and s['exit_code'] == 0 and s.get('workload_status') == 'exited')
    closes = close_count(methods)
    # The sole final Browser.close may be the truthful failed/CDPEOF record only when the close
    # was requested, the adapter classified the EOF, the owned exit before cleanup and the
    # settled exit were both 0, and no failure-path EOF observation exists. Every other
    # conjunct below stays independent: earlier calls, runtime, policy, settlement, selection.
    qualified_close = (not abnormal and closes == 1 and r.get('quit_observed') == 'qualified-eof'
                       and r.get('close_reply') is False and r.get('browser_close_requested') is True
                       and exited_zero and 'eof_exit_observation' not in r)
    policy_facts = policy_check(attempt, p, identity, c1a)
    checks = {
        'runner_transport': entry.get('interrupted') is False and entry.get('returncode') == (2 if startup else 0),
        'native_predicate': r.get('status') == ('DIAGNOSTIC_COMPLETED' if startup else 'SYNTHETIC_ATTEMPT_PASSED'),
        'selected_configuration': (r.get('engine') == 'chrome' and r.get('workload') == workload
                                   and r.get('abnormal') is abnormal and r.get('diagnostic_only') is startup
                                   and all(r.get(k) is False for k in FIREFOX_OPTIONS)
                                   and r.get('shutdown_observer') is False and r.get('sandbox_disables') == []
                                   and r.get('mach_services') == SERVICES and r.get('configd_compatibility') is False
                                   and 'automation_port' in p and p.get('automation_port') is None
                                   and p.get('firefox_child_ipc') is False
                                   and (r.get('chrome_rendezvous') == 'OWN_WORKLOAD_PID'
                                        and p.get('chrome_rendezvous') == 'OWN_WORKLOAD_PID' if c1a else
                                        r.get('chrome_rendezvous') == 'NOT_SELECTED'
                                        and 'chrome_rendezvous' not in p and 'rendezvous_canary' not in p
                                        and 'rendezvous_parameter' not in r)),
        'useful_work': all(r.get(k) is True for k in (('ready',) if startup else USEFUL_FLAGS)),
        'protocol_work': (collapsed(methods) == expected_sequence(workload, abnormal)
                          and closes == (0 if abnormal else 1) and protocol_passed(methods, qualified_close)),
        'runtime_identity': (r.get('runtime_preparation_complete') is True and r.get('runtime_unchanged') is True
                             and measurement.get('state') == 'MATCH' and measurement.get('digest_complete') is True
                             and r.get('runtime_measurement_root') == 'SELECTED_STORE_APP'
                             and r.get('runtime_source_sha256') == r.get('runtime_snapshot_sha256')
                             == r.get('runtime_observed_sha256') == identity.get('runtime_sha256')
                             and r.get('executable_sha256') == identity.get('executable_sha256')
                             and r.get('runtime_closure_sha256') == identity.get('closure_sha256')
                             and r.get('runtime_closure_count') == identity.get('closure_count')
                             and r.get('runtime_bundle_id') == identity.get('bundle_id')
                             and r.get('runtime_bundle_version') == identity.get('bundle_version')
                             and r.get('signature') == {'original': True}),
        'session_version': (r.get('version_matches') is True
                            and r.get('browser_version') == identity.get('bundle_version')),
        'policy': policy_facts['matches'],
        'settlement': (s.get('zero_survivors') is True and s.get('unsettled') is False and s.get('failures') == []
                       and (abnormal or exited_zero)),
        'no_failures': not any(r.get(k) for k in FAILURE_FIELDS),
        'termination': ((r.get('intended_timeout') is True and r.get('browser_close_requested') is False
                         and 'quit_observed' not in r) if abnormal else
                        (r.get('browser_close_requested') is True and exited_zero
                         and r.get('quit_observed') in ('reply', 'qualified-eof')
                         and r.get('close_reply') is (r.get('quit_observed') == 'reply')
                         and r.get('intended_timeout') is not True)),
        'selection_stable': entry.get('selection_before') == 'MATCH' and entry.get('selection_after') == 'UNCHANGED'}
    if c1a:
        checks['rendezvous_parameter'] = (p.get('status') == CANARY_PASSED
                                          and matched(p.get('rendezvous_canary'), canary=True)
                                          and matched(r.get('rendezvous_parameter')))
    failed = sorted(k for k, v in checks.items() if v is not True)
    if not closes:
        transport = 'ABSENT'
    elif qualified_close and methods[-1] == QUALIFIED_CLOSE_ENTRY:
        transport = 'QUALIFIED_EOF'
    elif (closes == 1 and methods[-1].get('method') == 'Browser.close' and methods[-1].get('outcome') == 'passed'
          and r.get('quit_observed') == 'reply'):
        transport = 'REPLY'
    else:
        transport = 'UNQUALIFIED'
    crash = (r.get('owned_crash_artifacts') or {}).get('profile/Crashpad')
    extra = {}
    if c1a:
        extra = {'c1a_outcome': c1a_outcome(role, r, p, methods, not failed),
                 'rendezvous': {'canary': project(p.get('rendezvous_canary')),
                                'launch': project(r.get('rendezvous_parameter'))}}
    return {'role': role, 'result': 'PRESENT', 'passed': not failed, 'failed_checks': failed, 'checks': checks,
            **extra,
            'raw_result_sha256': hashlib.sha256(d2.read_bounded(attempt / 'result.json')).hexdigest(),
            'status': r.get('status'), 'cdp_stage': r.get('cdp_stage'), 'browser_version': r.get('browser_version'),
            'protocol_version': r.get('protocol_version'), 'exit_before_cleanup': r.get('exit_before_cleanup'),
            'quit_observed': r.get('quit_observed'), 'close_reply': r.get('close_reply'),
            'close_transport': transport, 'intended_timeout': r.get('intended_timeout'),
            'eof_exit_observation': r.get('eof_exit_observation'),
            # Queried registry evidence and the uninstall acknowledgement stay separate facts.
            'extension_registry': [r.get('extension_registry_before'), r.get('extension_registry_after')],
            'extension_uninstall_replied': r.get('extension_uninstall_replied'),
            'extension_registry_absent': r.get('extension_registry_absent'),
            'extension_worker_absent': r.get('extension_worker_absent'),
            'extension_worker_to_absence_seconds': r.get('extension_worker_to_absence_seconds'),
            'protocol': [{k: m[k] for k in ('method', 'outcome', 'optional', 'scope', 'protocol_error', 'error')
                          if k in m} for m in methods],
            'runtime_measurement': {k: measurement.get(k) for k in ('state', 'digest_complete', 'operation', 'code',
                                                                   'entries_enumerated', 'entries_measured')},
            'settlement': {k: s.get(k) for k in ('exit_code', 'workload_status', 'zero_survivors', 'unsettled',
                                                 'observed_escapes')},
            'crashpad': {k: crash.get(k) for k in ('status', 'counts')} if isinstance(crash, dict) else None,
            'policy': policy_facts, 'failures': {k: failure(r.get(k)) for k in FAILURE_FIELDS}}


def summarize(root, state):
    operation = state.get('operation')
    c1a = state.get('lane') == C1A_LANE
    summary = {'schema': 'bux-r5-chrome-c1a-summary-v1' if c1a else 'bux-r5-chrome-summary-v1', 'operation': operation,
               'qualification_accepted': False, 'native_acceptance': 'PENDING_MANAGER_REVIEW',
               'captured_cnt_executed': False, 'bind_sha256': state.get('bind_sha256'),
               'claim': {k: state.get(k) for k in ('phase', 'claimed_utc', 'inventory_sha256', 'identity',
                                                   'startup_summary_sha256', 'launch_pytest_version',
                                                   'launch_environment_names', 'launch_options', 'interrupted',
                                                   'runner_failure', 'abnormal')},
               'prerequisites': state.get('prerequisites', [])}
    if c1a:
        summary.update(lane=C1A_LANE, reference_bind_sha256=state.get('reference_bind_sha256'),
                       reference_delta=state.get('reference_delta'), pid_check=state.get('pid_check'))
    launches = {e.get('role'): e for e in state.get('launches', []) if isinstance(e, dict)}
    attempts = {role: attempt_summary(root, role, state.get('identity') or {}, launches.get(role, {}), c1a)
                for role in ROLES.get(operation, ())}
    summary['attempts'] = attempts
    interrupted = state.get('interrupted') is True
    prerequisites = state.get('prerequisites') or []
    if interrupted:
        label = 'CHROME_INCOMPLETE_INTERRUPTED'
    elif state.get('phase') == 'RUNNER_REFUSED':
        label = 'CHROME_RUNNER_REFUSED'
    elif len(prerequisites) < 2 or not all(p.get('ok') for p in prerequisites):
        label = 'CHROME_PREREQUISITE_FAILED'
    elif c1a and not (isinstance(state.get('pid_check'), dict) and state['pid_check'].get('passed') is True):
        label = 'CHROME_PID_CHECK_FAILED'
    elif all(a['passed'] for a in attempts.values()) and state.get('phase') == 'LAUNCHES_RETURNED':
        label = STARTUP_LABEL if operation == 'startup' else PAIR_LABEL
    else:
        label = 'CHROME_STARTUP_DIAGNOSTIC_FAILED' if operation == 'startup' else 'CHROME_PAIR_FAILED'
    summary['label'] = lane_label(label, c1a)
    return summary


def collect(root):
    root = d2.managed(root, 'Claim root')
    require(os.path.lexists(root / 'CHROME.claim'), 'No Chrome claim to collect')
    state = json.loads(d2.read_bounded(root / 'CHROME-state.json'))
    summary = summarize(root, state)
    name, digest = next_slot(root, 'SUMMARY', summary)
    print(json.dumps({'label': summary['label'], 'summary': name, 'sha256': digest,
                      'failed_checks': {r: a.get('failed_checks') for r, a in summary['attempts'].items()}}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    common = ('snapshot', 'inventory', 'runtime', 'selection', 'python', 'nix-bin', 'claim-root')
    for name in ('bind', 'run'):
        command = commands.add_parser(name)
        for option in common:
            command.add_argument('--' + option, type=Path, required=True)
        command.add_argument('--expected-inventory-sha256', required=True)
        command.add_argument('--chrome-rendezvous', action='append', default=[], choices=[C1A])
    bind_command = commands.choices['bind']
    bind_command.add_argument('--reference-bind', type=Path)
    bind_command.add_argument('--reference-bind-sha256')
    execute = commands.choices['run']
    execute.add_argument('--operation', choices=tuple(ROLES), required=True)
    execute.add_argument('--bind-record', type=Path, required=True)
    execute.add_argument('--bind-record-sha256', required=True)
    execute.add_argument('--startup-summary', type=Path)
    execute.add_argument('--startup-summary-sha256')
    commands.add_parser('collect').add_argument('--claim-root', type=Path, required=True)
    internal = commands.add_parser('predict')
    internal.add_argument('--root', type=Path, required=True)
    internal.add_argument('--runtime', type=Path, required=True)
    internal.add_argument('--chrome-rendezvous', action='append', default=[], choices=[C1A])
    check = commands.add_parser('pid-check')
    check.add_argument('--root', type=Path, required=True)
    check.add_argument('--runtime', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'predict':
        return predict(args.root, args.runtime, lane(args))
    if args.command == 'pid-check':
        return pid_check(args.root, args.runtime)
    if args.command == 'bind':
        require((args.reference_bind is None) == (args.reference_bind_sha256 is None),
                'A reference bind record needs its SHA-256, and only with one')
        return bind(args)
    if args.command == 'run':
        require((args.operation == 'pair') == (args.startup_summary is not None)
                == (args.startup_summary_sha256 is not None),
                'A startup summary is required for, and only for, the pair operation')
        return run(args)
    return collect(args.claim_root)


if __name__ == '__main__':
    raise SystemExit(main())
