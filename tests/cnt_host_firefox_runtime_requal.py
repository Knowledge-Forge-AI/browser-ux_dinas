"""R6 Firefox 156.0.1 runtime requalification pair: accepted, adopted, historical. Never agent-executed.

The one-shot NORMAL+ABNORMAL pair ran on the host under `bux-r6-firefox-15601-requal.claim`, the
manager accepted it, and PRODUCTION-ADOPTION1 adopted its exact identity as the production Firefox
(`cnt_firefox_production`, the sole owner). That claim is consumed and immutable: `bind` and `run`
refuse on that host before anything else, and `collect` only reads. The lane is kept as historical
and maintenance authority for the requalification evidence; it is not a production binder.

It accepts only the exact candidate identity from RUNTIME-ID1 (version, bundle identifier and
version, application.ini build ID, app-tree and executable digests, valid signature); there is no
version family, prefix or pattern. Every entry point cross-checks, and never writes, that production
binds exactly this identity from its sole owner, that the superseded 155.0.1 identity survives only
as the historical CONT6 D1 baseline (`cnt_host_d2.D1_*`, unchanged), and that the accepted R4 policy
templates, services and sandbox exceptions are shared.

`bind` launches no browser and takes no claim. It verifies the exported snapshot and that this
runner executes from it, the adopted production binding, the candidate runtime (Info.plist,
application.ini, tree and executable digests, codesign) and the predicted launch policy (one spawn
of the launch interpreter), and writes the next exclusive BIND-NNN.json. The malformed-D claim is
only tested for existence.

`run` re-binds and requires equality with a bind record, checks free space and runs the 15+15
owned-process prerequisites before any claim; a failed or interrupted prerequisite refuses and
consumes nothing. It re-verifies the snapshot and the installed candidate, then takes `bux-r6-firefox-15601-requal.claim` and the per-root REQUAL.claim,
re-binds the candidate runtime and launches the maintained preflight with the full trusted-synthetic
workload: NORMAL once; ABNORMAL (`--abnormal`, its own fresh attempt root and profile) only if the
complete NORMAL predicate held and the installed candidate still matched afterwards. The source is
re-verified before each launch and the installed candidate after each. Unless interrupted, the run
ends with a source, candidate-runtime and production-binding recheck, also after a refusal. There
is no retry, no fallback and no kill: children are waited for and cleanup belongs to the preflight
supervisor. No captured CNT/XPI, matrix option or diagnostic flag is ever passed.

`collect` only reads state and attempt results and writes the next exclusive REQUAL-SUMMARY-NNN.json
of privacy projections. It launches nothing, binds nothing and mutates no claim. A passing label is
pending manager review; it never changes production constants or authorizes malformed-D.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402
import cnt_firefox_production as firefox  # noqa: E402  (constants read only)
import cnt_host_firefox_matrix as production  # noqa: E402  (constants read only)
from cnt_native_evidence import VerificationError, plain_descendant, require  # noqa: E402

RUNNER = Path(__file__).resolve()
# RUNTIME-ID1 candidate, as this lane bound it. Manager-accepted from this lane's pair and adopted
# as production; the literals stay here as the historical record and are cross-checked against the
# owner (`cnt_firefox_production`), never its source.
CANDIDATE_VERSION = '156.0.1'
CANDIDATE_BUNDLE_ID = 'org.mozilla.firefox'
CANDIDATE_BUNDLE_VERSION = '15626.9.21'
CANDIDATE_BUILD_ID = '20260921121718'
CANDIDATE_RUNTIME = '35172d4e392575860ed48cd7e7a45a6eb1a59eacdfef277aced6c5610bbcdab3'
CANDIDATE_EXECUTABLE = 'f2559282d3ef1ceeb0083700e57092c905f043eddb02a9b8ac09009ec9719ac3'
# Superseded production identity (R4 HOST-PAIR3, Firefox 155.0.1). It survives only as the
# historical CONT6 D1 baseline, copied as literals so a change to the live constants is detected
# rather than inherited.
SUPERSEDED_VERSION = '155.0.1'
HISTORICAL_D1 = {'d2.D1_RUNTIME': '6555cd15eb85f2be816fede570f252d5e7154c1c4ecfda372f00f19cc0596f7d',
                 'd2.D1_EXECUTABLE': 'ca4f2108d1000fce089d4c5ace30565f489dfce8d2d98c89b355e7c3ebc40462',
                 'd2.D1_TEMPLATE': '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'}
# The accepted R4 lane, deliberately shared with production (checked equal, never aliased away).
# Unchanged by the adoption.
ACCEPTED_TEMPLATE = 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'
ACCEPTED_TEMPLATE_WITHOUT_CONFIGD = '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'
SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd',
            'com.apple.SystemConfiguration.configd']
EXCEPTIONS = ['content', 'socket', 'utility-generic']
HOST_CLAIM = 'bux-r6-firefox-15601-requal.claim'
ROOT_CLAIM, STATE = 'REQUAL.claim', 'REQUAL-state.json'
MALFORMED_D_CLAIM = 'bux-r6-firefox-native-matrix-malformed-d.claim'
# Every historical host claim named in source (COMPAT-E is consumed lineage since MULTIPART-B-PREP1),
# plus the production matrix's current budget claim (MULTIPART-B-PREP1), which is refused by name only.
# None is created, opened or reused here; only the malformed-D claim is tested for existence. The
# REPAIR1 name was never created and is never touched.
REFUSED_CLAIMS = ('bux-c7-host-d2.claim', 'bux-c8-host-pair2.claim', 'bux-c9-host-pair3.claim',
                  'bux-r5-chrome-startup.claim', 'bux-r5-chrome-pair.claim',
                  'bux-r5-chrome-c1a-startup.claim', 'bux-r5-chrome-c1a-pair.claim',
                  'bux-r6-firefox-native-matrix.claim', 'bux-r6-firefox-native-matrix-srich-repair1.claim',
                  'bux-r6-firefox-native-matrix-srich-repair2.claim',
                  'bux-r6-firefox-native-matrix-rich-valid.claim', MALFORMED_D_CLAIM,
                  'bux-r6-firefox-native-matrix-compat-e.claim',
                  'bux-r6-firefox-native-matrix-multipart-b.claim')
ROLES = ('normal', 'abnormal')
MIN_FREE_BYTES = 48 * 1024 ** 3
PLIST_LIMIT = 4 * 1024 * 1024
INI_LIMIT = 1024 * 1024
BIND_SCHEMA = 'bux-r6-firefox-15601-requal-bind-v1'
PREREQUISITES_SCHEMA = 'bux-r6-firefox-15601-requal-prerequisites-v1'
CLAIM_SCHEMA = 'bux-r6-firefox-15601-requal-claim-v1'
STATE_SCHEMA = 'bux-r6-firefox-15601-requal-state-v1'
SUMMARY_SCHEMA = 'bux-r6-firefox-15601-requal-summary-v1'
PASSED = 'SYNTHETIC_ATTEMPT_PASSED'
USEFUL_WORK = ('ready', 'page_nonce', 'extension_installed', 'extension_origin_verified',
               'extension_nonce', 'extension_unloaded')
# Matrix, capture and Chrome-lane result keys: none may appear in a requalification attempt.
FORBIDDEN_KEYS = ('matrix', 'matrix_case', 'capture_identity', 'capture_copy', 'matrix_inputs',
                  'matrix_materialized', 'matrix_completed', 'chrome_rendezvous', 'rendezvous_parameter',
                  'parent_probes_completed', 'crash_readback_completed', 'shutdown_trace_summary')
MATCH, MISMATCH = 'MATCH', 'MISMATCH_OR_UNREADABLE'
LABELS = {'passed': 'R6_FIREFOX_15601_REQUAL_PAIR_PASSED_PENDING_MANAGER_REVIEW',
          'normal': 'R6_FIREFOX_15601_REQUAL_NORMAL_FAILED',
          'after_normal': 'R6_FIREFOX_15601_REQUAL_RUNTIME_AFTER_NORMAL_FAILED',
          'abnormal': 'R6_FIREFOX_15601_REQUAL_ABNORMAL_FAILED',
          'after_abnormal': 'R6_FIREFOX_15601_REQUAL_RUNTIME_AFTER_ABNORMAL_FAILED',
          'end': 'R6_FIREFOX_15601_REQUAL_END_RECHECK_FAILED',
          'refused': 'R6_FIREFOX_15601_REQUAL_RUNNER_REFUSED',
          'interrupted': 'R6_FIREFOX_15601_REQUAL_INCOMPLETE_INTERRUPTED',
          'claimed': 'R6_FIREFOX_15601_REQUAL_CLAIMED_NOT_LAUNCHED'}
# Fixed refusal codes; a runner failure records a code, never message text or a path.
REQUAL_CODES = {
    'Historical D1 binding changed': 'HISTORICAL_D1_BINDING_CHANGED',
    'Production runtime binding is not the adopted identity': 'PRODUCTION_NOT_ADOPTED_IDENTITY',
    'Accepted R4 policy binding changed': 'ACCEPTED_POLICY_BINDING_CHANGED',
    'Requalification claim is not distinct': 'CLAIM_NOT_DISTINCT',
    'Candidate runtime must be the link-free installed Firefox.app': 'CANDIDATE_PATH_REFUSED',
    'Candidate bundle metadata unreadable': 'CANDIDATE_PLIST_UNREADABLE',
    'Candidate bundle identity differs': 'CANDIDATE_BUNDLE_ID_DIFFERS',
    'Candidate bundle version differs': 'CANDIDATE_VERSION_DIFFERS',
    'Candidate bundle build version differs': 'CANDIDATE_BUNDLE_VERSION_DIFFERS',
    'Candidate application.ini unreadable': 'CANDIDATE_INI_UNREADABLE',
    'Candidate application.ini version differs': 'CANDIDATE_INI_VERSION_DIFFERS',
    'Candidate application.ini build differs': 'CANDIDATE_BUILD_ID_DIFFERS',
    'Candidate runtime tree differs': 'CANDIDATE_TREE_DIFFERS',
    'Candidate executable differs': 'CANDIDATE_EXECUTABLE_DIFFERS',
    'Candidate signature invalid': 'CANDIDATE_SIGNATURE_INVALID',
    'Snapshot inventory is not the approved candidate': 'SNAPSHOT_INVENTORY_DIFFERS',
    'Snapshot has missing or extra entries': 'SNAPSHOT_ENTRIES_DIFFER',
    'Snapshot bytes/modes/links differ': 'SNAPSHOT_BYTES_DIFFER',
    'Runner must execute from the approved snapshot': 'RUNNER_NOT_FROM_SNAPSHOT'}


def owned(path, label):
    """Managed, link-free scratch that is never an inbox: host outputs go to the outbox by copy."""
    path = d2.managed(path, label)
    require('inbox' not in path.parts, label + ' must not be under an inbox')
    return path


def production_adopted():
    """Production binds exactly the adopted candidate from its sole owner, the superseded 155.0.1
    identity is unchanged history only, and the requal claim is distinct."""
    live = {'d2.D1_RUNTIME': d2.D1_RUNTIME, 'd2.D1_EXECUTABLE': d2.D1_EXECUTABLE,
            'd2.D1_TEMPLATE': d2.D1_TEMPLATE}
    require(production.d2 is d2 and live == HISTORICAL_D1, 'Historical D1 binding changed')
    candidate = {'version': CANDIDATE_VERSION, 'bundle_identifier': CANDIDATE_BUNDLE_ID,
                 'bundle_version': CANDIDATE_BUNDLE_VERSION, 'build_id': CANDIDATE_BUILD_ID,
                 'runtime_sha256': CANDIDATE_RUNTIME, 'executable_sha256': CANDIDATE_EXECUTABLE}
    owner = {'version': firefox.VERSION, 'bundle_identifier': firefox.BUNDLE_ID,
             'bundle_version': firefox.BUNDLE_VERSION, 'build_id': firefox.BUILD_ID,
             'runtime_sha256': firefox.RUNTIME, 'executable_sha256': firefox.EXECUTABLE}
    # Exactly the adopted identity, every field, in the owner and in what the matrix binds.
    require(production.firefox is firefox and owner == candidate and firefox.IDENTITY == candidate
            and production.ACCEPTED_RUNTIME == CANDIDATE_RUNTIME
            and production.ACCEPTED_EXECUTABLE == CANDIDATE_EXECUTABLE,
            'Production runtime binding is not the adopted identity')
    # The superseded identity is history only: never the production runtime, executable or version.
    require(production.ACCEPTED_RUNTIME != HISTORICAL_D1['d2.D1_RUNTIME']
            and production.ACCEPTED_EXECUTABLE != HISTORICAL_D1['d2.D1_EXECUTABLE']
            and firefox.VERSION != SUPERSEDED_VERSION, 'Production runtime binding is not the adopted identity')
    # Shared: the accepted R4 templates, services and exceptions must equal production.
    require(ACCEPTED_TEMPLATE == production.ACCEPTED_TEMPLATE
            and ACCEPTED_TEMPLATE_WITHOUT_CONFIGD == production.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD == d2.D1_TEMPLATE
            and SERVICES == list(d2.D2_SERVICES) == list(production.SERVICES)
            and EXCEPTIONS == list(d2.D1_EXCEPTIONS) == list(production.EXCEPTIONS),
            'Accepted R4 policy binding changed')
    historical = {d2.HOST_CLAIM_NAME, *production.CONSUMED_HOST_CLAIMS, *production.UNCREATED_PROPOSED_CLAIMS,
                  *(b['claim'] for b in production.BUDGETS.values())}
    require(HOST_CLAIM not in REFUSED_CLAIMS and historical <= set(REFUSED_CLAIMS)
            and len(set(REFUSED_CLAIMS)) == len(REFUSED_CLAIMS), 'Requalification claim is not distinct')
    return {'binding': {'firefox': dict(candidate), 'historical_d1': dict(HISTORICAL_D1)},
            'version': CANDIDATE_VERSION, 'superseded_version': SUPERSEDED_VERSION, 'status': 'ADOPTED'}


def signature(runtime):
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(runtime)],
                              capture_output=True, timeout=120)
    require(verified.returncode == 0, 'Candidate signature invalid')
    return True


def exact(value, expected):
    return type(value) is str and value == expected


def bundle_info(runtime):
    try:
        info = plistlib.loads(d2.read_bounded(plain_descendant(runtime, 'Contents/Info.plist'), PLIST_LIMIT))
    except Exception:
        info = None
    require(isinstance(info, dict), 'Candidate bundle metadata unreadable')
    return info


def application_ini(runtime):
    try:
        raw = d2.read_bounded(plain_descendant(runtime, 'Contents/Resources/application.ini'), INI_LIMIT)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(raw.decode('utf-8'))
        app = {'version': parser.get('App', 'Version', fallback=None),
               'build_id': parser.get('App', 'BuildID', fallback=None)}
    except Exception:
        app = None
    require(isinstance(app, dict), 'Candidate application.ini unreadable')
    return app


def executable_digest(runtime):
    try:
        raw = d2.read_bounded(plain_descendant(runtime, 'Contents/MacOS/firefox'), 1 << 30)
    except (OSError, VerificationError):
        return None
    return hashlib.sha256(raw).hexdigest()


def bind_candidate(runtime):
    """Read-only identity of the installed candidate; never launches. Exact values only."""
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.name == 'Firefox.app' and runtime.resolve() == runtime,
            'Candidate runtime must be the link-free installed Firefox.app')
    info = bundle_info(runtime)
    require(exact(info.get('CFBundleIdentifier'), CANDIDATE_BUNDLE_ID), 'Candidate bundle identity differs')
    require(exact(info.get('CFBundleShortVersionString'), CANDIDATE_VERSION), 'Candidate bundle version differs')
    require(exact(info.get('CFBundleVersion'), CANDIDATE_BUNDLE_VERSION), 'Candidate bundle build version differs')
    app = application_ini(runtime)
    require(exact(app['version'], CANDIDATE_VERSION), 'Candidate application.ini version differs')
    require(exact(app['build_id'], CANDIDATE_BUILD_ID), 'Candidate application.ini build differs')
    require(d2.tree_digest(runtime) == CANDIDATE_RUNTIME, 'Candidate runtime tree differs')
    require(executable_digest(runtime) == CANDIDATE_EXECUTABLE, 'Candidate executable differs')
    signed = signature(runtime)
    return {'version': CANDIDATE_VERSION, 'bundle_identifier': CANDIDATE_BUNDLE_ID,
            'bundle_version': CANDIDATE_BUNDLE_VERSION, 'build_id': CANDIDATE_BUILD_ID,
            'runtime_sha256': CANDIDATE_RUNTIME, 'executable_sha256': CANDIDATE_EXECUTABLE,
            'signature_original': signed}


def runtime_check(runtime):
    try:
        bind_candidate(runtime)
        return MATCH
    except Exception:
        return MISMATCH


def options(role, runtime, attempt):
    """The accepted full, uninstrumented R4 lane; ABNORMAL adds exactly `--abnormal`."""
    require(role in ROLES, 'Unknown requalification role')
    return ['--engine', 'firefox', '--runtime', str(runtime), '--scratch', str(attempt), '--workload', 'full',
            *[a for s in SERVICES for a in ('--service', s)],
            *[a for e in EXCEPTIONS for a in ('--nested-sandbox-exception', e)],
            *(['--abnormal'] if role == 'abnormal' else [])]


def binding(args, root):
    """Everything a run depends on, recomputed from the host. Launches no browser, takes no claim."""
    snapshot = owned(args.snapshot, 'Snapshot')
    require(RUNNER == snapshot / 'tests/cnt_host_firefox_runtime_requal.py',
            'Runner must execute from the approved snapshot')
    inventory = d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    preserved = production_adopted()
    candidate = bind_candidate(Path(args.runtime))
    env = d2.launch_environment(args.python, args.nix_bin, root)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    prediction = d2.predicted_template(args.python, env, root)
    require(prediction.get('policy_template_sha256') == ACCEPTED_TEMPLATE
            and prediction.get('policy_template_without_configd_sha256') == ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
            'Predicted launch policy is not the accepted R4 template')
    require(isinstance(prediction.get('pytest_version'), str), 'Launch interpreter cannot import pytest')
    # launch_environment already required both to be resolved /nix/store paths (immutable tools).
    identity = {'candidate': candidate, 'policy_template_sha256': ACCEPTED_TEMPLATE,
                'policy_template_without_configd_sha256': ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
                'services': SERVICES, 'sandbox_disables': EXCEPTIONS, 'workload': 'full',
                'shutdown_trace': False, 'shutdown_observer': False, 'crash_force_enable': False,
                'crash_readback': False, 'parent_probes': False, 'captured_code': False,
                'launch_tools': {'python': str(Path(args.python)), 'nix_bin': str(Path(args.nix_bin))}}
    return {'schema': BIND_SCHEMA, 'bound_utc': d2.utc(), 'inventory_sha256': inventory, 'identity': identity,
            'production': preserved, 'host_claim': HOST_CLAIM,
            'malformed_d_claim_present': os.path.lexists(d2.SCRATCH / MALFORMED_D_CLAIM),
            'launch_pytest_version': prediction['pytest_version'], 'launch_environment_names': sorted(env),
            'launch_options': {role: options(role, '<RUNTIME>', '<ATTEMPT>') for role in ROLES},
            'scope': 'Binding only; no browser launched, no claim. Spawned the launch interpreter, codesign.'}, env


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


def bind(args):
    root = owned(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    require(not os.path.lexists(d2.SCRATCH / HOST_CLAIM), 'Requalification already claimed on this host; never rerun')
    record, _ = binding(args, root)
    name, digest = next_slot(root, 'BIND', record)
    print(json.dumps({'label': 'R6_FIREFOX_15601_REQUAL_BOUND_NO_LAUNCH', 'bind': name, 'sha256': digest}))
    return 0


def save_state(root, state):
    temporary = root / (STATE + '.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(root / STATE)


def free_bytes(root):
    return shutil.disk_usage(root).free


def run(args):
    root = owned(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    host_claim, claim = d2.SCRATCH / HOST_CLAIM, root / ROOT_CLAIM
    require(not os.path.lexists(host_claim), 'Requalification already claimed on this host; never rerun')
    require(not os.path.lexists(claim), 'Claim root already used: collect; never rerun')
    require(not any(os.path.lexists(root / name) for role in ROLES for name in (role, role + '-outside-canary')),
            'Attempt directory present')
    raw = d2.read_bounded(args.bind_record)
    require(hashlib.sha256(raw).hexdigest() == args.bind_record_sha256, 'Bind record is not the supplied record')
    bound = json.loads(raw)
    require(isinstance(bound, dict) and bound.get('schema') == BIND_SCHEMA, 'Bind record schema differs')
    # Pre-claim: launches no browser and consumes nothing.
    current, env = binding(args, root)
    require(all(current[k] == bound.get(k) for k in ('inventory_sha256', 'identity', 'production', 'host_claim',
                                                      'launch_options')),
            'Current snapshot, candidate runtime, tools or policy differ from the bind record')
    available = free_bytes(root)
    require(available >= MIN_FREE_BYTES, 'Insufficient free space before claim')
    prerequisites = prerequisites_before_claim(args, env, root)
    # Immediately before the claim: drift during the long prerequisites refuses and consumes nothing.
    d2.verify_snapshot(owned(args.snapshot, 'Snapshot'), args.inventory, args.expected_inventory_sha256)
    bind_candidate(Path(args.runtime))
    state = {'schema': STATE_SCHEMA, 'phase': 'CLAIMED', 'claimed_utc': d2.utc(),
             'bind_sha256': args.bind_record_sha256, 'inventory_sha256': current['inventory_sha256'],
             'host_claim': HOST_CLAIM, 'root_claim': ROOT_CLAIM, 'identity': current['identity'],
             'production': current['production'], 'malformed_d_claim_present': current['malformed_d_claim_present'],
             'free_bytes_before': available, 'launch_environment_names': current['launch_environment_names'],
             'launch_pytest_version': current['launch_pytest_version'], 'launch_options': current['launch_options'],
             'interrupted': False, 'prerequisites': prerequisites, 'attempts': {}}
    record = {'schema': CLAIM_SCHEMA, 'claimed_utc': state['claimed_utc'], 'bind_sha256': args.bind_record_sha256,
              'inventory_sha256': state['inventory_sha256'], 'candidate_runtime_sha256': CANDIDATE_RUNTIME}
    # Host claim first: a failure between the two leaves the pair claimed and unlaunched, never twice.
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
                                     'code': REQUAL_CODES.get(str(error)) if isinstance(error, VerificationError)
                                     else None})
        if not isinstance(error, Exception):
            save_state(root, state)
            raise
    save_state(root, state)
    return collect(root)


def prerequisites_before_claim(args, env, root):
    """Pre-claim 15+15 owned-process prerequisites; any failure refuses before a claim exists."""
    snapshot, counts = owned(args.snapshot, 'Snapshot'), []
    for optimized in (False, True):
        counts.append(d2.prerequisite(args.python, env, snapshot, root, optimized))
        if counts[-1]['interrupted'] or not counts[-1]['ok']:
            break
    ok = len(counts) == 2 and all(c['ok'] and not c['interrupted'] for c in counts)
    name, digest = next_slot(root, 'PREREQUISITES', {'schema': PREREQUISITES_SCHEMA, 'recorded_utc': d2.utc(),
                                                     'claims_consumed': False, 'ok': ok, 'prerequisites': counts})
    require(ok, 'Prerequisites failed or were interrupted before claim; nothing consumed')
    return {'record': name, 'sha256': digest, 'counts': counts}


def claimed(args, env, root, state):
    """After the claim: nothing is retried and nothing kills a child."""
    snapshot, runtime = owned(args.snapshot, 'Snapshot'), Path(args.runtime)
    try:
        bind_candidate(runtime)
        state['runtime_before_normal'] = MATCH
        state['abnormal'] = 'NOT_STARTED'
        normal = launch(args, env, root, state, snapshot, runtime, 'normal')
        if normal['interrupted']:
            return
        state['runtime_after_normal'] = runtime_check(runtime)
        checks = role_checks(read_result(root / 'normal'), 'normal', root / 'normal', normal)
        if not all(checks.values()):
            state.update(phase='NORMAL_FAILED', abnormal='NOT_STARTED_NORMAL_FAILED')
        elif state['runtime_after_normal'] != MATCH:
            state.update(phase='RUNTIME_AFTER_NORMAL_FAILED', abnormal='NOT_STARTED_RUNTIME_AFTER_NORMAL_FAILED')
        else:
            state['abnormal'] = 'LAUNCHING'
            abnormal = launch(args, env, root, state, snapshot, runtime, 'abnormal')
            state['abnormal'] = 'LAUNCHED'
            if abnormal['interrupted']:
                return
            state['runtime_after_abnormal'] = runtime_check(runtime)
            state['phase'] = 'PAIR_RETURNED'
    except Exception:
        # A refusal after the claim still ends with the recheck; an interrupt does not.
        if state.get('abnormal') == 'LAUNCHING':
            state['abnormal'] = 'NOT_STARTED_RUNNER_REFUSED'
        end_recheck(args, snapshot, runtime, state)
        raise
    end_recheck(args, snapshot, runtime, state)


def launch(args, env, root, state, snapshot, runtime, role):
    """One launch of the maintained preflight in its own fresh attempt root; waited for, never killed."""
    # Immediately before each launch: source bytes/modes/links are unchanged.
    d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    attempt = root / role
    argv = [str(args.python), '-B', str(snapshot / 'tests/cnt-native-preflight.py'), *options(role, runtime, attempt)]
    entry = state['attempts'][role] = {'launched_utc': d2.utc()}
    state['phase'] = 'LAUNCHING_' + role.upper()
    save_state(root, state)
    with (root / (role + '-stdout.json')).open('w') as out, (root / (role + '-stderr.log')).open('w') as err:
        code, interrupted = d2.wait_retained(d2.spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
    entry.update(returncode=code, interrupted=interrupted, returned_utc=d2.utc())
    if interrupted:
        state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
    save_state(root, state)
    return entry


def end_recheck(args, snapshot, runtime, state):
    checks = {}
    for name, action in (('source', lambda: d2.verify_snapshot(snapshot, args.inventory,
                                                                 args.expected_inventory_sha256)),
                         ('runtime', lambda: bind_candidate(runtime)), ('production', production_adopted)):
        try:
            action()
            checks[name] = MATCH
        except Exception:
            checks[name] = MISMATCH
    state['end_recheck'] = checks


def read_result(attempt):
    try:
        raw = d2.read_bounded(attempt / 'result.json')
        value = json.loads(raw)
    except (OSError, ValueError, VerificationError):
        return None
    return (value, hashlib.sha256(raw).hexdigest()) if isinstance(value, dict) else None


def role_checks(loaded, role, attempt, entry):
    """The complete accepted R4 predicate for one role, as named conjuncts. Never raises."""
    if loaded is None:
        return {'result_readable': False}
    r = loaded[0]
    try:
        return predicate(r, role, attempt, entry)
    except Exception:
        return {'result_readable': True, 'predicate_evaluable': False}


def predicate(r, role, attempt, entry):
    p = r.get('preflight') if isinstance(r.get('preflight'), dict) else {}
    s = r.get('settlement') if isinstance(r.get('settlement'), dict) else {}
    m = r.get('runtime_measurement') if isinstance(r.get('runtime_measurement'), dict) else {}
    methods = [x.get('method') for x in r.get('protocol') or [] if isinstance(x, dict)]
    delta = d2.policy_delta(attempt, p)
    heard = d2.listeners(r, p.get('automation_port'))
    checks = {
        'transport': entry.get('interrupted') is False and type(entry.get('returncode')) is int
        and entry['returncode'] == 0,
        'status': r.get('status') == PASSED,
        'configuration': (r.get('engine') == 'firefox' and r.get('workload') == 'full'
                          and r.get('diagnostic_only') is False and r.get('browser_launched') is True
                          and all(r.get(k) is False for k in ('shutdown_trace', 'shutdown_observer',
                                                              'crash_force_enable', 'crash_readback',
                                                              'parent_probes', 'captured_code_loaded'))
                          and r.get('sandbox_disables') == EXCEPTIONS and r.get('mach_services') == SERVICES
                          and r.get('configd_compatibility') is True and r.get('native_semantics') == 'NOT_EXECUTED'),
        'no_forbidden_keys': not any(k in r for k in FORBIDDEN_KEYS),
        'useful_work': all(r.get(k) is True for k in USEFUL_WORK),
        'runtime': (r.get('runtime_preparation_complete') is True and r.get('runtime_unchanged') is True
                    and m.get('state') == MATCH and m.get('digest_complete') is True
                    and r.get('runtime_source_sha256') == r.get('runtime_snapshot_sha256')
                    == r.get('runtime_observed_sha256') == CANDIDATE_RUNTIME
                    and r.get('executable_sha256') == CANDIDATE_EXECUTABLE
                    and r.get('signature') == {'original': True, 'frozen': True}
                    and r.get('browser_version') == CANDIDATE_VERSION),
        'policy': (p.get('policy_template_sha256') == ACCEPTED_TEMPLATE
                   and p.get('status') == 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION'
                   and delta.get('d1_template_match') is True and delta.get('launch_policy_matches_preflight') is True),
        'listeners_owned_loopback': (heard['all_owned'] is True and heard['loopback_only'] is True
                                     and heard['samples_with_tcp_listener'] > 0),
        'no_recorded_failure': not any(r.get(k) for k in d2.FAILURE_FIELDS),
        'settled': (s.get('zero_survivors') is True and s.get('unsettled') is False and s.get('failures') == []
                    and s.get('workload_status') == 'exited')}
    if role == 'normal':
        checks.update(
            normal_mode=r.get('abnormal') is False and 'intended_timeout' not in r,
            quit_reply=r.get('quit_observed') == 'reply' and methods.count('Marionette:Quit') == 1,
            exit_zero=(type(r.get('exit_before_cleanup')) is int and r['exit_before_cleanup'] == 0
                       and type(s.get('exit_code')) is int and s['exit_code'] == 0))
    else:
        checks.update(
            abnormal_mode=r.get('abnormal') is True and r.get('intended_timeout') is True,
            no_quit='quit_observed' not in r and 'Marionette:Quit' not in methods,
            live_timeout_exit=('exit_before_cleanup' in r and r['exit_before_cleanup'] is None
                               and type(s.get('exit_code')) is int and s['exit_code'] == -15))
    return checks


def hexdigest(value):
    return value if type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value) else None


def token(value, allowed=None):
    if type(value) is not str or not 0 < len(value) <= 64:
        return None
    if allowed is not None:
        return value if value in allowed else 'OTHER'
    return value if all(c.isascii() and (c.isalnum() or c in '_-.:') for c in value) else 'UNSAFE'


def failure(value):
    if not isinstance(value, dict):
        return None if not value else {'present': True}
    return {k: token(value.get(k)) for k in ('stage', 'type', 'code')}


def integer(value):
    return value if type(value) is int else None


def role_summary(root, role, entry):
    """Privacy projection of one attempt: fixed keys, digests, enums, counts; never paths, PIDs or text."""
    attempt = root / role
    loaded = read_result(attempt)
    checks = role_checks(loaded, role, attempt, entry)
    summary = {'returncode': integer(entry.get('returncode')), 'interrupted': entry.get('interrupted') is True,
               'checks': checks, 'failed_checks': sorted(k for k, v in checks.items() if v is not True),
               'passed': bool(checks) and all(v is True for v in checks.values())}
    if loaded is None:
        summary['result'] = 'ABSENT_OR_UNREADABLE'
        return summary
    r, digest = loaded
    s = r.get('settlement') if isinstance(r.get('settlement'), dict) else {}
    m = r.get('runtime_measurement') if isinstance(r.get('runtime_measurement'), dict) else {}
    p = r.get('preflight') if isinstance(r.get('preflight'), dict) else {}
    methods = [x.get('method') for x in r.get('protocol') or [] if isinstance(x, dict)]
    delta = d2.policy_delta(attempt, p)
    heard = d2.listeners(r, p.get('automation_port'))
    summary.update(
        result='READ', raw_result_sha256=digest, status=token(r.get('status')),
        useful_work={k: r.get(k) is True for k in USEFUL_WORK},
        quit_observed=token(r.get('quit_observed'), ('reply', 'qualified-eof')),
        marionette_quit_count=methods.count('Marionette:Quit'),
        exit_before_cleanup=integer(r.get('exit_before_cleanup')),
        intended_timeout=r.get('intended_timeout') is True, abnormal=r.get('abnormal') is True,
        captured_code_loaded=r.get('captured_code_loaded') is True,
        settlement={'exit_code': integer(s.get('exit_code')),
                    'workload_status': token(s.get('workload_status'), ('exited', 'unknown-before-kill')),
                    'zero_survivors': s.get('zero_survivors') is True, 'unsettled': s.get('unsettled') is True,
                    'observed_escapes': integer(s.get('observed_escapes')),
                    'failure_count': len(s['failures']) if isinstance(s.get('failures'), list) else None},
        runtime_measurement={'state': token(m.get('state'), ('MATCH', 'MISMATCH', 'INCOMPLETE', 'NOT_STARTED')),
                             'digest_complete': m.get('digest_complete') is True, 'code': token(m.get('code')),
                             'entries_measured': integer(m.get('entries_measured'))},
        frozen_identity={'runtime_source_sha256': hexdigest(r.get('runtime_source_sha256')),
                         'runtime_snapshot_sha256': hexdigest(r.get('runtime_snapshot_sha256')),
                         'runtime_observed_sha256': hexdigest(r.get('runtime_observed_sha256')),
                         'executable_sha256': hexdigest(r.get('executable_sha256')),
                         'browser_version': token(r.get('browser_version')),
                         'signature': {k: (r.get('signature') or {}).get(k) is True for k in ('original', 'frozen')}
                         if isinstance(r.get('signature'), dict) else None},
        policy={'template_sha256': hexdigest(p.get('policy_template_sha256')),
                'd1_template_match': delta.get('d1_template_match') is True,
                'launch_policy_matches_preflight': delta.get('launch_policy_matches_preflight') is True,
                'configd_rule_count': integer(delta.get('configd_rule_count'))},
        listeners={'listener_sample_count': integer(heard['listener_sample_count']),
                   'samples_with_tcp_listener': integer(heard['samples_with_tcp_listener']),
                   'all_owned': heard['all_owned'] is True, 'loopback_only': heard['loopback_only'] is True},
        failures={k: failure(r.get(k)) for k in d2.FAILURE_FIELDS})
    return summary


def label(state, roles):
    phase = state.get('phase')
    if state.get('interrupted'):
        return LABELS['interrupted']
    if phase == 'RUNNER_REFUSED':
        return LABELS['refused']
    if 'normal' not in roles:
        return LABELS['claimed']
    if not roles['normal']['passed']:
        return LABELS['normal']
    if state.get('runtime_after_normal') != MATCH:
        return LABELS['after_normal']
    if 'abnormal' not in roles:
        return LABELS['refused']
    if not roles['abnormal']['passed']:
        return LABELS['abnormal']
    if state.get('runtime_after_abnormal') != MATCH:
        return LABELS['after_abnormal']
    recheck = state.get('end_recheck')
    if not (isinstance(recheck, dict) and set(recheck) == {'source', 'runtime', 'production'}
            and all(v == MATCH for v in recheck.values())):
        return LABELS['end']
    if phase == 'PAIR_RETURNED' and state.get('runtime_before_normal') == MATCH:
        return LABELS['passed']
    return LABELS['refused']


def summarize(state, root):
    roles = {role: role_summary(root, role, entry) for role, entry in (state.get('attempts') or {}).items()
             if role in ROLES and isinstance(entry, dict)}
    prerequisites = state.get('prerequisites') if isinstance(state.get('prerequisites'), dict) else {}
    identity = state.get('identity') if isinstance(state.get('identity'), dict) else {}
    # Tool paths stay in the private bind record and state; the summary binds them by digest.
    tools = json.dumps(identity.get('launch_tools'), sort_keys=True, separators=(',', ':')).encode()
    summary = {
        'schema': SUMMARY_SCHEMA, 'qualification_accepted': False, 'production_binding_changed': False,
        'native_acceptance': 'PENDING_MANAGER_REVIEW', 'semantic_success_claimed': False,
        'malformed_d_authorized': False,
        'captured_cnt_executed': any(r.get('captured_code_loaded') is True for r in roles.values()),
        'scope': 'Firefox 156.0.1 trusted-synthetic NORMAL+ABNORMAL requalification observations for manager '
                 'review; never a production binding change.',
        'candidate': identity.get('candidate'),
        'policy': {**{k: identity.get(k) for k in ('policy_template_sha256', 'policy_template_without_configd_sha256',
                                                   'services', 'sandbox_disables', 'workload')},
                   'launch_tools_sha256': hashlib.sha256(tools).hexdigest()},
        'production': state.get('production'),
        'claim': {'host_claim': state.get('host_claim'), 'root_claim': state.get('root_claim'),
                  **{k: state.get(k) for k in ('phase', 'claimed_utc', 'bind_sha256', 'inventory_sha256',
                                               'malformed_d_claim_present', 'interrupted', 'runner_failure',
                                               'launch_pytest_version', 'launch_environment_names',
                                               'free_bytes_before')}},
        'prerequisites': {'record': prerequisites.get('record'), 'sha256': prerequisites.get('sha256'),
                          'counts': prerequisites.get('counts')},
        'runtime_before_normal': state.get('runtime_before_normal'),
        'runtime_after_normal': state.get('runtime_after_normal'),
        'runtime_after_abnormal': state.get('runtime_after_abnormal'),
        'abnormal': state.get('abnormal'), 'end_recheck': state.get('end_recheck'), 'roles': roles}
    summary['label'] = label(state, roles)
    return summary


def collect(root):
    """Read-only: no launch, provider, Nix, runtime bind or claim mutation."""
    root = owned(root, 'Claim root')
    require(os.path.lexists(root / ROOT_CLAIM), 'No requalification claim to collect')
    state = json.loads(d2.read_bounded(root / STATE))
    summary = summarize(state, root)
    name, _ = next_slot(root, 'REQUAL-SUMMARY', summary)
    print(json.dumps({'label': summary['label'], 'summary': name,
                      'failed_checks': {k: v['failed_checks'] for k, v in summary['roles'].items()}}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('bind', 'run'):
        sub = commands.add_parser(command)
        for name in ('snapshot', 'inventory', 'runtime', 'python', 'nix-bin', 'claim-root'):
            sub.add_argument('--' + name, type=Path, required=True)
        sub.add_argument('--expected-inventory-sha256', required=True)
        if command == 'run':
            sub.add_argument('--bind-record', type=Path, required=True)
            sub.add_argument('--bind-record-sha256', required=True)
    commands.add_parser('collect').add_argument('--claim-root', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'collect':
        return collect(args.claim_root)
    return bind(args) if args.command == 'bind' else run(args)


if __name__ == '__main__':
    raise SystemExit(main())
