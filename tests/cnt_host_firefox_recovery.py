"""BUX5B1 RECOVERY-HOSTPREP1 disposable Firefox recovery qualification host runner. UNEXECUTED.

Never agent-executed. One one-shot run per host under the global claim
`bux5b1-firefox-recovery-qual.claim`; the manager must review the sealed HOSTPREP1 payload first.

`bind` launches no browser and takes no claim. It spawns the launch interpreter once (policy
template prediction, which runs nix-store --query and imports pytest), runs codesign on the
installed Firefox.app and digests it. It verifies the exported snapshot (the supplied terminal
HOSTPREP inventory) and that this runner executes from it, the two accepted library digests in that
snapshot, the retained CNT 6.12.1 XPI, the production Firefox 156.0.1 identity from its sole owner
`cnt_firefox_production`, the accepted R4 policy template (D1 plus exactly the configd rule) with
the accepted services and sandbox exceptions, the exact scenario roster, the 18-launch plan and the
launch-option templates. It records historical claims by existence only and writes the next
exclusive BIND-NNN.json.

`run` re-binds and requires equality with the bind record, checks free space, runs the 15+15
owned-process prerequisites (exclusive PREREQUISITES-NNN.json; a failure or interrupt consumes
nothing), then immediately re-binds once more (source, runtime, capture and policy) and requires
equality again. Only then does it create the global claim and the run-root RECOVERY-QUAL.claim
(exclusive, no-follow), issue one single-use caller token per recover() journal, and launch each
role once through the maintained preflight (`--workload cnt-recovery`): the source, then each
scenario's staging attempt before its target, every attempt in its own fresh attempt root and so a
fresh disposable profile. Before each launch the snapshot and capture are re-verified, the attempt
path is seen absent, and an exclusive digest-bound plan is written. The runtime is verified before
the first launch and after the last launched attempt, also when a refusal is raised after a launch.
It stops at the first attempt that is not RECOVERY_ATTEMPT_COMPLETED or (for a target) whose own
recorded expectation is not MATCHED; expected scenario refusals are observations inside a matched
target. There is no retry, fallback, kill or claim deletion; an operator interrupt waits for the
child and retains state. Historical claims are provenance, never a gate in either direction.

`collect` only reads state and attempt results and writes the next exclusive
RECOVERY-SUMMARY-NNN.json of privacy projections plus the run-level ZERO_LIVE_CONTACT facts. It
launches nothing, calls no provider or Nix, does no runtime bind and mutates no claim. No Chrome
option or Chrome-lane path exists here; no live or default profile is ever named.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402
import cnt_firefox_matrix as matrix  # noqa: E402
import cnt_firefox_production as firefox  # noqa: E402
import cnt_firefox_recovery as recovery  # noqa: E402
import cnt_host_firefox_matrix as host_matrix  # noqa: E402  (accepted lane constants and helpers)
import cnt_host_firefox_runtime_requal as requal  # noqa: E402  (its claim name only)
from cnt_native_evidence import VerificationError, require  # noqa: E402

RUNNER = Path(__file__).resolve()
GLOBAL_CLAIM = 'bux5b1-firefox-recovery-qual.claim'
RUN_ROOT_CLAIM, STATE = 'RECOVERY-QUAL.claim', 'RECOVERY-QUAL-state.json'
# Historical claims, imported from their owners: existence is recorded, nothing else.
HISTORICAL_CLAIMS = (*host_matrix.CONSUMED_HOST_CLAIMS, host_matrix.BUDGETS['multipart-b']['claim'],
                     requal.HOST_CLAIM)
ACCEPTED_TEMPLATE = host_matrix.ACCEPTED_TEMPLATE
ACCEPTED_TEMPLATE_WITHOUT_CONFIGD = host_matrix.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD
SERVICES = list(host_matrix.SERVICES)
EXCEPTIONS = list(host_matrix.EXCEPTIONS)
MIN_FREE_BYTES = 48 * 1024 ** 3
BIND_SCHEMA = 'bux5b1-firefox-recovery-qual-bind-v1'
STATE_SCHEMA = 'bux5b1-firefox-recovery-qual-state-v1'
CLAIM_SCHEMA = 'bux5b1-firefox-recovery-qual-claim-v1'
SUMMARY_SCHEMA = 'bux5b1-firefox-recovery-qual-summary-v1'
COMPLETED = 'RECOVERY_ATTEMPT_COMPLETED'
LABELS = {'all': 'BUX5B1_RECOVERY_QUAL_RECORDED_PENDING_MANAGER_REVIEW',
          'stopped': 'BUX5B1_RECOVERY_QUAL_STOPPED_AT_ATTEMPT',
          'prerequisite': 'BUX5B1_RECOVERY_QUAL_PREREQUISITE_FAILED',
          'interrupted': 'BUX5B1_RECOVERY_QUAL_INCOMPLETE_INTERRUPTED',
          'refused': 'BUX5B1_RECOVERY_QUAL_RUNNER_REFUSED',
          'claimed': 'BUX5B1_RECOVERY_QUAL_CLAIMED_NOT_LAUNCHED'}
DIRECTORIES = ('cases', 'plans', 'tokens', 'staging')


def launches():
    """The exact ordered launch plan: the source, then per scenario its staging attempt (if any)
    before its target. 18 launches for the 10-scenario roster."""
    plan = [('source', None)]
    for scenario in recovery.SCENARIOS:
        if scenario in recovery.STAGED_SCENARIOS:
            plan.append(('staging', scenario))
        plan.append(('target', scenario))
    return plan


def attempt_name(index, role, scenario):
    slug = '' if scenario is None else '-' + scenario.lower().replace('_', '-')
    name = f'{index:02d}-{role}{slug}'
    require(recovery.SAFE_NAME.fullmatch(name) is not None, 'Recovery plan invalid')
    return name


def options(runtime, attempt, capture, plan, plan_sha256):
    """The accepted full, uninstrumented R4 lane plus exactly the cnt-recovery workload options."""
    return ['--engine', 'firefox', '--runtime', str(runtime), '--scratch', str(attempt),
            '--workload', 'cnt-recovery', *[a for s in SERVICES for a in ('--service', s)],
            *[a for e in EXCEPTIONS for a in ('--nested-sandbox-exception', e)],
            '--capture', str(capture), '--capture-sha256', matrix.XPI_SHA256,
            '--recovery-plan', str(plan), '--recovery-plan-sha256', str(plan_sha256)]


def historical_claims_present():
    """Recorded, never required present or absent."""
    return {name: os.path.lexists(d2.SCRATCH / name) for name in HISTORICAL_CLAIMS}


def library_digests(snapshot):
    names = {'guarded_recovery': 'libexec/clear-new-tab/guarded_recovery.py',
             'durable_state': 'libexec/clear-new-tab/durable_state.py'}
    observed = {k: hashlib.sha256(d2.read_bounded(snapshot / v)).hexdigest() for k, v in names.items()}
    require(observed == {'guarded_recovery': recovery.GUARDED_RECOVERY_SHA256,
                         'durable_state': recovery.DURABLE_STATE_SHA256}, 'Recovery library digest mismatch')
    return observed


def binding(args, root):
    """Everything a run depends on, recomputed from the host. Launches no browser, takes no claim."""
    snapshot = d2.managed(args.snapshot, 'Snapshot')
    require(RUNNER == snapshot / 'tests/cnt_host_firefox_recovery.py', 'Runner must execute from the approved snapshot')
    inventory = d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    libraries = library_digests(snapshot)
    capture = host_matrix.capture_identity(args.capture)
    runtime = Path(args.runtime)
    production = firefox.bind_runtime(runtime)
    signed = host_matrix.signature(runtime)
    env = d2.launch_environment(args.python, args.nix_bin, root)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    prediction = d2.predicted_template(args.python, env, root)
    require(prediction.get('policy_template_sha256') == ACCEPTED_TEMPLATE
            and prediction.get('policy_template_without_configd_sha256') == ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
            'Predicted launch policy is not the accepted R4 template')
    require(isinstance(prediction.get('pytest_version'), str), 'Launch interpreter cannot import pytest')
    identity = {'runtime_sha256': firefox.RUNTIME, 'executable_sha256': firefox.EXECUTABLE,
                'firefox': {k: production[k] for k in ('version', 'bundle_identifier', 'bundle_version', 'build_id')},
                'signature_original': signed, 'policy_template_sha256': ACCEPTED_TEMPLATE,
                'policy_template_without_configd_sha256': ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
                'services': SERVICES, 'sandbox_disables': EXCEPTIONS, 'shutdown_trace': False,
                'crash_force_enable': False, 'workload': 'cnt-recovery', 'capture': capture,
                'libraries': libraries, 'recovery_prep1': dict(recovery.RECOVERY_PREP1),
                'provenance_sha256': hashlib.sha256(matrix.PROVENANCE.read_bytes()).hexdigest()}
    plan = launches()
    return {'schema': BIND_SCHEMA, 'bound_utc': d2.utc(), 'inventory_sha256': inventory, 'identity': identity,
            'global_claim': GLOBAL_CLAIM, 'historical_claims_present': historical_claims_present(),
            'roster': list(recovery.ROSTER), 'launches': [list(entry) for entry in plan],
            'journals': {k: list(v) for k, v in recovery.JOURNALS.items()}, 'token_kinds': dict(recovery.TOKEN_KIND),
            'launch_pytest_version': prediction['pytest_version'], 'launch_environment_names': sorted(env),
            'launch_options': options('<RUNTIME>', '<ATTEMPT>', '<CAPTURE>', '<PLAN>', '<PLAN_SHA256>'),
            'scope': 'Binding only; no browser launched, no claim. Spawned the launch interpreter, codesign.'}, env


BOUND_KEYS = ('inventory_sha256', 'identity', 'global_claim', 'roster', 'launches', 'journals', 'token_kinds')


def bind(args):
    root = d2.managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    record, _ = binding(args, root)
    name, digest = host_matrix.next_slot(root, 'BIND', record)
    print(json.dumps({'label': 'BUX5B1_RECOVERY_QUAL_BOUND_NO_LAUNCH', 'bind': name, 'sha256': digest,
                      'launches': len(record['launches'])}))
    return 0


def save_state(root, state):
    temporary = root / (STATE + '.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(root / STATE)


def free_bytes(root):
    return shutil.disk_usage(root).free


def run(args):
    root = d2.managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    global_claim, claim = d2.SCRATCH / GLOBAL_CLAIM, root / RUN_ROOT_CLAIM
    require(not os.path.lexists(global_claim), 'Recovery qualification already claimed on this host: collect; never rerun')
    require(not os.path.lexists(claim), 'Claim root already used: collect; never rerun')
    require(not any(os.path.lexists(root / name) for name in DIRECTORIES), 'Attempt directory present')
    raw = d2.read_bounded(args.bind_record)
    require(hashlib.sha256(raw).hexdigest() == args.bind_record_sha256, 'Bind record is not the supplied record')
    bound = json.loads(raw)
    require(isinstance(bound, dict) and bound.get('schema') == BIND_SCHEMA, 'Bind record schema differs')
    # Pre-claim: launches no browser and consumes nothing.
    current, env = binding(args, root)
    require(all(current[k] == bound.get(k) for k in BOUND_KEYS),
            'Current snapshot, capture, runtime, policy or roster differ from the bind record')
    available = free_bytes(root)
    require(available >= MIN_FREE_BYTES, 'Insufficient free space before claim')
    prerequisites = prerequisites_before_claim(args, env, root)
    # Immediately before the claim: source, runtime, capture and policy once more.
    recheck, env = binding(args, root)
    require(all(recheck[k] == bound.get(k) for k in BOUND_KEYS),
            'Immediate pre-claim recheck differs from the bind record')
    state = {'schema': STATE_SCHEMA, 'phase': 'CLAIMED', 'claimed_utc': d2.utc(),
             'bind_sha256': args.bind_record_sha256, 'inventory_sha256': current['inventory_sha256'],
             'global_claim': GLOBAL_CLAIM, 'historical_claims_present': historical_claims_present(),
             'identity': current['identity'], 'roster': current['roster'], 'launches': current['launches'],
             'free_bytes_before': available, 'launch_environment_names': current['launch_environment_names'],
             'launch_pytest_version': current['launch_pytest_version'], 'interrupted': False,
             'prerequisites': prerequisites, 'recheck_before_claim': 'MATCH', 'attempts': [],
             'plan_nonce': secrets.token_hex(32), 'tokens': {}}
    record = {'schema': CLAIM_SCHEMA, 'claimed_utc': state['claimed_utc'], 'bind_sha256': args.bind_record_sha256,
              'inventory_sha256': state['inventory_sha256']}
    # Global claim first: a failure between the two leaves the qualification claimed and unlaunched.
    d2.exclusive(global_claim, {**record, 'claim_root_name': root.name})
    state['global_claim_sha256'] = hashlib.sha256(d2.read_bounded(global_claim)).hexdigest()
    d2.exclusive(claim, record)
    save_state(root, state)
    try:
        for name in DIRECTORIES:
            (root / name).mkdir(mode=0o700)
        for scenario, journals in recovery.JOURNALS.items():
            for journal_id in journals:
                state['tokens'][journal_id] = recovery.issue_token(
                    root / 'tokens', scenario, journal_id, state['global_claim_sha256'], recovery.TOKEN_KIND[journal_id])
        save_state(root, state)
        claimed(args, env, root, state)
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        state.update(phase='INTERRUPTED_RETAINED' if interrupted else 'RUNNER_REFUSED',
                     interrupted=state['interrupted'] or interrupted,
                     runner_failure={'type': type(error).__name__,
                                     'code': recovery.code_of(error) if isinstance(error, VerificationError) else None})
        if not isinstance(error, Exception):
            save_state(root, state)
            raise
    save_state(root, state)
    return collect(root)


def prerequisites_before_claim(args, env, root):
    """Pre-claim 15+15 owned-process prerequisites; any failure refuses before a claim exists."""
    snapshot, counts = d2.managed(args.snapshot, 'Snapshot'), []
    for optimized in (False, True):
        counts.append(d2.prerequisite(args.python, env, snapshot, root, optimized))
        if counts[-1]['interrupted'] or not counts[-1]['ok']:
            break
    ok = len(counts) == 2 and all(c['ok'] and not c['interrupted'] for c in counts)
    host_matrix.next_slot(root, 'PREREQUISITES', {'schema': 'bux5b1-firefox-recovery-qual-prerequisites-v1',
                                                  'recorded_utc': d2.utc(), 'claims_consumed': False,
                                                  'ok': ok, 'prerequisites': counts})
    require(ok, 'Prerequisites failed or were interrupted before claim; nothing consumed')
    return counts


def claimed(args, env, root, state):
    """After the claim: nothing is retried and nothing kills a child."""
    snapshot, runtime = d2.managed(args.snapshot, 'Snapshot'), Path(args.runtime)
    firefox.bind_runtime(runtime)
    state['runtime_before_first'] = 'MATCH'
    try:
        launch_all(args, env, root, state, snapshot, runtime)
    except Exception:
        if state['attempts'] and 'launched_utc' not in state['attempts'][-1]:
            state['attempts'][-1]['status'] = 'NOT_LAUNCHED_RUNNER_REFUSED'
        if any('launched_utc' in e for e in state['attempts']):
            runtime_after(runtime, state)
        raise
    if state['interrupted']:
        return
    runtime_after(runtime, state)
    if state['phase'] not in ('STOPPED', 'RUNNER_REFUSED'):
        state['phase'] = 'ATTEMPTS_RETURNED'


def runtime_after(runtime, state):
    try:
        firefox.bind_runtime(runtime)
        state['runtime_after_last'] = 'MATCH'
    except Exception as error:
        state['runtime_after_last'] = 'MISMATCH_OR_UNREADABLE'
        state['runtime_after_failure'] = type(error).__name__


def plan_for(root, state, index, role, scenario):
    name = attempt_name(index, role, scenario)
    source = None if role == 'source' else str(root / 'cases' / attempt_name(1, 'source', None))
    tokens = ([state['tokens'][j] for j in recovery.JOURNALS[scenario]] if role == 'target' else [])
    return {'schema': recovery.PLAN_SCHEMA, 'role': role, 'scenario': scenario, 'plan_nonce': state['plan_nonce'],
            'claim_root': str(root), 'attempt': str(root / 'cases' / name), 'attempt_name': name,
            'source_attempt': source, 'tokens': tokens, 'global_claim_sha256': state['global_claim_sha256']}


def write_plan(root, plan):
    raw = (json.dumps(plan, indent=2, sort_keys=True) + '\n').encode()
    path = root / 'plans' / (plan['attempt_name'] + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
    return path, hashlib.sha256(raw).hexdigest()


def launch_all(args, env, root, state, snapshot, runtime):
    """Each attempt once, in order; returns at the first unmatched, unlaunched or interrupted one."""
    for index, (role, scenario) in enumerate(launches(), 1):
        name = attempt_name(index, role, scenario)
        entry = {'attempt': name, 'role': role, 'scenario': scenario}
        state['attempts'].append(entry)
        d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
        require(host_matrix.capture_identity(args.capture) == state['identity']['capture'], 'Capture digest mismatch')
        attempt = root / 'cases' / name
        require(not any(os.path.lexists(attempt.parent / (name + suffix))
                        for suffix in ('', '-state', '-state-missing', '-state-substituted')),
                'Attempt directory present')
        entry['absent_before_spawn'] = True
        plan_path, plan_sha256 = write_plan(root, plan_for(root, state, index, role, scenario))
        entry['plan_sha256'] = plan_sha256
        argv = [str(args.python), '-B', str(snapshot / 'tests/cnt-native-preflight.py'),
                *options(runtime, attempt, args.capture, plan_path, plan_sha256)]
        entry['launched_utc'] = d2.utc()
        state['phase'] = 'LAUNCHING'
        save_state(root, state)
        with (root / (name + '-stdout.json')).open('w') as out, (root / (name + '-stderr.log')).open('w') as err:
            code, interrupted = d2.wait_retained(d2.spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
        status, expectation = attempt_outcome(attempt)
        entry.update(returncode=code, interrupted=interrupted, returned_utc=d2.utc(), status=status,
                     expectation=expectation)
        save_state(root, state)
        if interrupted:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        # The exit code is advisory; the attempt's own result.json status and expectation decide.
        if not matched(entry):
            state.update(phase='STOPPED', stopped_at=name)
            break


def matched(entry):
    return entry.get('status') == COMPLETED and (entry.get('role') != 'target' or entry.get('expectation') == 'MATCHED')


def attempt_outcome(attempt):
    try:
        value = json.loads(d2.read_bounded(attempt / 'result.json'))
    except (OSError, ValueError, VerificationError):
        return 'RESULT_ABSENT_OR_UNREADABLE', None
    status = value.get('status') if isinstance(value, dict) else None
    status = status if status in (COMPLETED, 'BLOCKED') else 'RESULT_STATUS_INVALID'
    facts = value.get('recovery') if isinstance(value, dict) and isinstance(value.get('recovery'), dict) else {}
    expectation = facts.get('expectation')
    return status, expectation if expectation in ('MATCHED', 'MISMATCHED') else None


def zero_live_contact(state, attempts):
    """Run-level ZERO_LIVE_CONTACT from each launched attempt's own facts (no launch of its own)."""
    launched = [a for a in state.get('attempts') or [] if 'launched_utc' in a]
    projected = [attempts.get(a['attempt']) or {} for a in launched]
    def every(predicate):
        return bool(projected) and all(predicate(p) for p in projected)
    facts = {'scenario': recovery.RUN_LEVEL, 'launched_attempts': len(launched),
             'fresh_contained_profiles': every(lambda p: (p.get('freshness') or {}).get('proven') is True
                                               and (p.get('freshness') or {}).get('home_is_run_home') is True),
             'policy_template_accepted': every(lambda p: p.get('policy_template_sha256') == ACCEPTED_TEMPLATE),
             'zero_survivors': every(lambda p: (p.get('settlement') or {}).get('zero_survivors') is True),
             'zero_escapes': every(lambda p: (p.get('settlement') or {}).get('observed_escapes') == 0),
             # Structural, not observed: neither module has a route that names a live or default
             # profile; the observed facts above are what ZERO_LIVE_CONTACT's status rests on.
             'live_profile_named': False, 'default_profile_selected': False,
             'live_default_profile_basis': 'STRUCTURAL_NO_ROUTE_NOT_OBSERVED'}
    facts['status'] = 'MATCHED' if all(facts[k] is True for k in ('fresh_contained_profiles',
                                                                  'policy_template_accepted', 'zero_survivors',
                                                                  'zero_escapes')) else 'NOT_PROVEN'
    return facts


def summarize(state, root):
    summary = {'schema': SUMMARY_SCHEMA, 'qualification_accepted': False, 'semantic_success_claimed': False,
               'scope': 'Disposable Firefox 6.12.1 recovery qualification observations for manager review; '
                        'not live-data safety evidence, not a canonical root, not consumer adoption.',
               'claim': {k: state.get(k) for k in ('phase', 'claimed_utc', 'bind_sha256', 'inventory_sha256',
                                                   'global_claim', 'historical_claims_present', 'identity',
                                                   'interrupted', 'runner_failure', 'stopped_at',
                                                   'recheck_before_claim', 'runtime_before_first',
                                                   'runtime_after_last', 'launch_pytest_version',
                                                   'launch_environment_names')},
               'tokens': {j: {'kind': t.get('kind'), 'state': 'CONSUMED' if recovery.token_consumed(t) else 'ISSUED'}
                          for j, t in (state.get('tokens') or {}).items()},
               'prerequisites': state.get('prerequisites', []), 'attempts': {}}
    for entry in state.get('attempts') or []:
        try:
            result = json.loads(d2.read_bounded(root / 'cases' / entry['attempt'] / 'result.json'))
            projected = recovery.projected_attempt(result)
        except (OSError, ValueError, VerificationError):
            projected = {'result': 'ABSENT_OR_UNREADABLE'}
        summary['attempts'][entry['attempt']] = {
            **{k: entry.get(k) for k in ('role', 'scenario', 'returncode', 'status', 'expectation', 'interrupted',
                                          'absent_before_spawn', 'plan_sha256')}, **projected}
    summary['zero_live_contact'] = zero_live_contact(state, summary['attempts'])
    phase = state.get('phase')
    if state.get('interrupted'):
        label = LABELS['interrupted']
    elif phase == 'RUNNER_REFUSED':
        label = LABELS['refused']
    elif phase == 'STOPPED':
        label = LABELS['stopped']
    elif (phase == 'ATTEMPTS_RETURNED' and state.get('runtime_after_last') == 'MATCH'
          and len(state.get('attempts') or []) == len(state.get('launches') or [])
          and all(matched(e) for e in state['attempts'])
          and summary['zero_live_contact']['status'] == 'MATCHED'):
        label = LABELS['all']
    elif not state.get('attempts'):
        label = LABELS['claimed']
    else:
        label = LABELS['stopped']
    summary['label'] = label
    # As the R6 host summary: every attempt-derived value is projected (projected_attempt); the
    # envelope holds only host-owned enums, digests, counts, UTC stamps and fixed claim names.
    return summary


def collect(root):
    """Read-only: no launch, provider, Nix, runtime bind or claim mutation."""
    root = d2.managed(root, 'Claim root')
    require(os.path.lexists(root / RUN_ROOT_CLAIM), 'No recovery qualification claim to collect')
    state = json.loads(d2.read_bounded(root / STATE))
    summary = summarize(state, root)
    name, _ = host_matrix.next_slot(root, 'RECOVERY-SUMMARY', summary)
    print(json.dumps({'label': summary['label'], 'summary': name, 'attempts': len(summary.get('attempts') or {})}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('bind', 'run'):
        sub = commands.add_parser(command)
        for name in ('snapshot', 'inventory', 'runtime', 'python', 'nix-bin', 'claim-root', 'capture'):
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
