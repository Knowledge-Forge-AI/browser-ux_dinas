"""R6 Firefox native semantic matrix host recipe runner. UNEXECUTED; never agent-executed.

Budgets are fixed here, each with its own host claim and declared categories; the only runnable
budget is `multipart-b` (S-MULTI, T-MULTI-ORDERED, T-MULTI-REVERSED, T-MULTI-NO-P1, T-MULTI-NO-MIDDLE,
T-MULTI-DUP, T-MULTI-TRUNC, T-MULTI-BADDATA under its own new claim). The HOST1, S-RICH REPAIR2,
RICH-VALID, MALFORMED-D and COMPAT-E claims are consumed: none is created, opened, written, renamed,
deleted or reused, only its existence is recorded (provenance, never a gate in either direction), and
the consumed `srich-repair2`, `rich-valid`, `malformed-d` and `compat-e` budgets are refused by name.
The REPAIR1 proposed claim was never created; its name is refused and the runner never creates, opens,
stats or retires it. No category is withheld any longer; D-EMPTY-SELECTION is not runnable (NOT_DRIVEN)
and so is refused in any budget. There is no free-form case list.

`bind` launches no browser and takes no claim. It does spawn the launch interpreter once
(policy-template prediction, which runs nix-store --query and imports pytest), runs codesign
on the installed Firefox.app and digests it. It verifies the exported snapshot and that this
runner executes from it, the retained captured XPI (digest, archive safety, manifest identity,
21 member digests), the accepted production Firefox 156.0.1 identity from its sole owner
`cnt_firefox_production` (bundle, application.ini, tree and executable; codesign here), the accepted
policy template (D1 plus exactly the configd rule), the accepted option set and the budget's
ordered, dependency-closed case list. It writes the next exclusive BIND-NNN.json.

`run` re-binds and requires equality with a bind record, checks free space and runs the 15+15
owned-process prerequisites before any claim: their counts go to an exclusive
PREREQUISITES-NNN.json and a failed or interrupted prerequisite refuses without consuming a
claim. Only then does it take the budget's distinct host claim and the per-root MATRIX.claim
(no other claim is read or reused), and then runs each case
once through the maintained preflight (`--workload cnt-matrix`), each in its own fresh attempt
root and therefore a fresh disposable profile. The only claim the run gates on is the current
budget's host claim (and the per-root MATRIX.claim); historical claim names are lineage, not
filesystem gates. The snapshot and capture are re-verified before
every attempt and the runtime before the first and after the last launched case, also when a
drift or refusal is raised after a launch; an operator interrupt waits for the child, retains
state and does no further runtime work (`runtime_after_last` absent). A dependent case is launched
only when its source attempt (S-RICH or S-MULTI) of this same claim root completed with its own recorded
readiness true; otherwise the run is refused before that launch (MATRIX_INPUT_SOURCE_INVALID) and the
runtime is still verified after the last launched case. No raw artifact of another claim is
ever an input. It stops at the first attempt whose result.json is not MATRIX_ATTEMPT_COMPLETED,
on any drift, refusal or interrupt.
There is no retry and no kill: children are waited for and cleanup belongs to the preflight
supervisor. Large native artifacts stay in the attempt directories.

`collect` only reads state and attempt results and writes the next exclusive
MATRIX-SUMMARY-NNN.json of privacy projections, including each case's fixed S-RICH source
readiness (`rich_source_ready`, `rich_source_missing`) and coverage enums, never row or task ids,
each dependent's fixed `restore_evidence` or `malformed_evidence` (each projected on its own, so a
refusal is contained to that field), each restore's completion with the restore_error tri-state and
allowlisted report codes only, and a `source_binding` to the same-root S-RICH artifact that also
binds a declared mutation to the unmutated source digests. For a runnable D or E case (decided from
the state's own case id) each restore carries the observability-aware tri-state and
`report_observability`, and the case carries `pre_restore_error_ribbon` and marks its legacy
classifications and predictions as computed on the recorded restore_error. Each E case also carries
its fixed `compat_evidence` and recorded pre-restore `compat_input` proof, each projected on its own.
A D or E restore refused for a pre-existing error ribbon, or an E restore refused for an unproven
input, is an ordinary non-completed attempt: the run stops there and the runtime is verified after
it, as S-RICH was launched. A B dependent is handled like D and E (tri-state, pre-restore ribbon,
legacy labels) and carries its fixed `multipart_evidence` and recorded pre-selection `multipart_input`
proof; S-MULTI carries its `multipart_evidence` source block and `multi_source_ready` /
`multi_source_missing`, each projected on its own. A B restore refused for an unproven selection is an
ordinary non-completed attempt too. It launches nothing, calls no
provider or Nix, does no runtime bind and mutates no claim. No Chrome option, CDP or rendezvous
path exists here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402
import cnt_firefox_matrix as matrix  # noqa: E402
import cnt_firefox_production as firefox  # noqa: E402
from cnt_native_evidence import VerificationError, require  # noqa: E402

RUNNER = Path(__file__).resolve()
# Manager-approved budgets. Each owns a distinct host claim; no budget may reuse one. `categories`
# declares every catalogue category a budget may run; none may be withheld.
BUDGETS = {'multipart-b': {'claim': 'bux-r6-firefox-native-matrix-multipart-b.claim',
                           'cases': ('S-MULTI', 'T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1',
                                     'T-MULTI-NO-MIDDLE', 'T-MULTI-DUP', 'T-MULTI-TRUNC', 'T-MULTI-BADDATA'),
                           'categories': ('B',)}}
# Consumed by HOST1, S-RICH REPAIR2, RICH-VALID HOST1, MALFORMED-D HOST2 and COMPAT-E HOST1 and retained
# as immutable evidence: existence is recorded, nothing else. Lineage only: never a filesystem gate.
CONSUMED_HOST_CLAIMS = ('bux-r6-firefox-native-matrix.claim',
                        'bux-r6-firefox-native-matrix-srich-repair2.claim',
                        'bux-r6-firefox-native-matrix-rich-valid.claim',
                        'bux-r6-firefox-native-matrix-malformed-d.claim',
                        'bux-r6-firefox-native-matrix-compat-e.claim')
# Proposed by REPAIR1 and never created: refused by name only, never touched on the host.
UNCREATED_PROPOSED_CLAIMS = ('bux-r6-firefox-native-matrix-srich-repair1.claim',)
# Consumed budgets, refused by name even if reintroduced.
RETIRED_BUDGETS = ('srich-repair2', 'rich-valid', 'malformed-d', 'compat-e')
# No category is withheld since MULTIPART-B-PREP1; the mechanism stays for any future withholding.
WITHHELD_CATEGORIES = ()
SUMMARY_SCHEMA = 'bux-r6-firefox-matrix-summary-v8'
ROOT_CLAIM, STATE = 'MATRIX.claim', 'MATRIX-state.json'
# Accepted production Firefox (cnt_firefox_production; 156.0.1 adopted by PRODUCTION-ADOPTION1),
# aliased from its sole owner. The R4 policy below is the accepted HOST-PAIR3 lane, unchanged
# (docs/architecture/cnt-native-format-characterization.md).
ACCEPTED_RUNTIME = firefox.RUNTIME
ACCEPTED_EXECUTABLE = firefox.EXECUTABLE
ACCEPTED_TEMPLATE = 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'
ACCEPTED_TEMPLATE_WITHOUT_CONFIGD = d2.D1_TEMPLATE
EXCEPTIONS = list(d2.D1_EXCEPTIONS)
SERVICES = list(d2.D2_SERVICES)
MIN_FREE_BYTES = 48 * 1024 ** 3
BIND_SCHEMA = 'bux-r6-firefox-matrix-bind-v3'
COMPLETED = 'MATRIX_ATTEMPT_COMPLETED'
LABELS = {'all': 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW',
          'stopped': 'R6_MATRIX_STOPPED_AT_CASE', 'prerequisite': 'R6_MATRIX_PREREQUISITE_FAILED',
          'interrupted': 'R6_MATRIX_INCOMPLETE_INTERRUPTED', 'refused': 'R6_MATRIX_RUNNER_REFUSED',
          'claimed': 'R6_MATRIX_CLAIMED_NOT_LAUNCHED'}


def case_order(selected=None):
    """Ordered runnable case ids; a subset must include every dependency before its dependent."""
    catalogue = matrix.validate_catalogue()
    chosen = list(catalogue) if not selected else list(selected)
    require(len(chosen) == len(set(chosen)) and all(c in catalogue for c in chosen), 'Unknown matrix case')
    position = {c: n for n, c in enumerate(chosen)}
    require([c for c in catalogue if c in position] == chosen, 'Matrix case order differs from the catalogue')
    for case_id in chosen:
        source = matrix.case(case_id)['source']
        require(source is None or source in position, 'Matrix input undeclared')
    return chosen


def options(case_id, runtime, attempt, capture, source=None):
    """The accepted full, uninstrumented R4 lane plus exactly the cnt-matrix workload options."""
    return ['--engine', 'firefox', '--runtime', str(runtime), '--scratch', str(attempt),
            '--workload', 'cnt-matrix', *[a for s in SERVICES for a in ('--service', s)],
            *[a for e in EXCEPTIONS for a in ('--nested-sandbox-exception', e)],
            '--capture', str(capture), '--capture-sha256', matrix.XPI_SHA256, '--matrix-case', case_id,
            *(['--matrix-input', str(source)] if source is not None else [])]


def signature(runtime):
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(runtime)],
                              capture_output=True, timeout=120)
    require(verified.returncode == 0, 'Firefox original signature invalid')
    return True


def budget(name):
    require(isinstance(name, str) and name in BUDGETS and name not in RETIRED_BUDGETS, 'Unknown matrix budget')
    chosen = BUDGETS[name]
    require(chosen['claim'] not in CONSUMED_HOST_CLAIMS and chosen['claim'] not in UNCREATED_PROPOSED_CLAIMS
            and sum(b['claim'] == chosen['claim'] for b in BUDGETS.values()) == 1, 'Unknown matrix budget')
    declared = chosen.get('categories')
    require(isinstance(declared, tuple) and declared and not set(declared) & set(WITHHELD_CATEGORIES)
            and all(matrix.case(c)['category'] in declared for c in chosen['cases']), 'Unknown matrix budget')
    return chosen


def consumed_claims_present():
    """Historical claim sentinels: recorded, never required present or absent."""
    return {name: os.path.lexists(d2.SCRATCH / name) for name in CONSUMED_HOST_CLAIMS}


def capture_identity(path):
    capture = Path(path)
    require(capture.is_absolute() and capture.resolve() == capture, 'Capture absent or not a regular file')
    return matrix.verify_capture(capture)


def binding(args, root):
    """Everything a run depends on, recomputed from the host. Launches no browser, takes no claim."""
    snapshot = d2.managed(args.snapshot, 'Snapshot')
    require(RUNNER == snapshot / 'tests/cnt_host_firefox_matrix.py', 'Runner must execute from the approved snapshot')
    inventory = d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
    capture = capture_identity(args.capture)
    runtime = Path(args.runtime)
    production = firefox.bind_runtime(runtime)
    signed = signature(runtime)
    env = d2.launch_environment(args.python, args.nix_bin, root)
    (root / 'home').mkdir(mode=0o700, exist_ok=True)
    prediction = d2.predicted_template(args.python, env, root)
    require(prediction.get('policy_template_sha256') == ACCEPTED_TEMPLATE
            and prediction.get('policy_template_without_configd_sha256') == ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
            'Predicted launch policy is not the accepted R4 template')
    require(isinstance(prediction.get('pytest_version'), str), 'Launch interpreter cannot import pytest')
    cases = case_order(budget(args.budget)['cases'])
    identity = {'runtime_sha256': ACCEPTED_RUNTIME, 'executable_sha256': ACCEPTED_EXECUTABLE,
                'firefox': {k: production[k] for k in ('version', 'bundle_identifier', 'bundle_version',
                                                       'build_id')},
                'signature_original': signed, 'policy_template_sha256': ACCEPTED_TEMPLATE,
                'policy_template_without_configd_sha256': ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
                'services': SERVICES, 'sandbox_disables': EXCEPTIONS, 'shutdown_trace': False,
                'crash_force_enable': False, 'workload': 'cnt-matrix', 'capture': capture,
                'provenance_sha256': hashlib.sha256(matrix.PROVENANCE.read_bytes()).hexdigest()}
    return {'schema': BIND_SCHEMA, 'bound_utc': d2.utc(), 'inventory_sha256': inventory, 'identity': identity,
            'budget': args.budget, 'host_claim': budget(args.budget)['claim'],
            'consumed_claims_present': consumed_claims_present(),
            'cases': cases, 'launch_pytest_version': prediction['pytest_version'],
            'launch_environment_names': sorted(env),
            'launch_options': {c: options(c, '<RUNTIME>', '<ATTEMPT>', '<CAPTURE>',
                                          '<SOURCE>' if matrix.case(c)['source'] else None) for c in cases},
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
    root = d2.managed(args.claim_root, 'Claim root')
    require(root.is_dir(), 'Claim root must exist')
    record, _ = binding(args, root)
    name, digest = next_slot(root, 'BIND', record)
    print(json.dumps({'label': 'R6_MATRIX_BOUND_NO_LAUNCH', 'bind': name, 'sha256': digest,
                      'budget': record['budget'], 'cases': len(record['cases'])}))
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
    host_claim, claim = d2.SCRATCH / budget(args.budget)['claim'], root / ROOT_CLAIM
    require(not os.path.lexists(host_claim), 'Matrix already claimed on this host: collect; never rerun')
    require(not os.path.lexists(claim), 'Claim root already used: collect; never rerun')
    require(not os.path.lexists(root / 'cases'), 'Attempt directory present')
    raw = d2.read_bounded(args.bind_record)
    require(hashlib.sha256(raw).hexdigest() == args.bind_record_sha256, 'Bind record is not the supplied record')
    bound = json.loads(raw)
    require(isinstance(bound, dict) and bound.get('schema') == BIND_SCHEMA, 'Bind record schema differs')
    # Pre-claim: launches no browser and consumes nothing.
    current, env = binding(args, root)
    require(all(current[k] == bound.get(k) for k in ('inventory_sha256', 'identity', 'budget', 'host_claim',
                                                      'cases')),
            'Current snapshot, capture, runtime, policy or cases differ from the bind record')
    available = free_bytes(root)
    require(available >= MIN_FREE_BYTES, 'Insufficient free space before claim')
    # The 15+15 prerequisites precede the claims: a failed or interrupted prerequisite leaves an
    # exclusive PREREQUISITES-NNN.json and consumes nothing.
    prerequisites = prerequisites_before_claim(args, env, root)
    state = {'schema': 'bux-r6-firefox-matrix-state-v2', 'phase': 'CLAIMED', 'claimed_utc': d2.utc(),
             'bind_sha256': args.bind_record_sha256, 'inventory_sha256': current['inventory_sha256'],
             'budget': current['budget'], 'host_claim': current['host_claim'],
             'consumed_claims_present': consumed_claims_present(),
             'identity': current['identity'], 'cases': current['cases'], 'free_bytes_before': available,
             'launch_environment_names': current['launch_environment_names'],
             'launch_pytest_version': current['launch_pytest_version'], 'interrupted': False,
             'prerequisites': prerequisites, 'attempts': [], 'launch_options': current['launch_options']}
    record = {'schema': 'bux-r6-firefox-matrix-claim-v2', 'claimed_utc': state['claimed_utc'],
              'bind_sha256': args.bind_record_sha256, 'inventory_sha256': state['inventory_sha256'],
              'budget': state['budget']}
    # Host claim first: a failure between the two leaves the matrix claimed and unlaunched.
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
                                     'code': (matrix.MATRIX_CODES.get(str(error))
                                              or firefox.CODES.get(str(error)))
                                     if isinstance(error, VerificationError) else None})
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
    next_slot(root, 'PREREQUISITES', {'schema': 'bux-r6-firefox-matrix-prerequisites-v1',
                                      'recorded_utc': d2.utc(), 'claims_consumed': False,
                                      'ok': ok, 'prerequisites': counts})
    require(ok, 'Prerequisites failed or were interrupted before claim; nothing consumed')
    return counts


def claimed(args, env, root, state):
    """After the claim: nothing is retried and nothing kills a child."""
    snapshot, runtime = d2.managed(args.snapshot, 'Snapshot'), Path(args.runtime)
    firefox.bind_runtime(runtime)
    state['runtime_before_first'] = 'MATCH'
    cases_root = root / 'cases'
    cases_root.mkdir(mode=0o700)
    try:
        launch_cases(args, env, root, state, snapshot, runtime, cases_root)
    except Exception:
        # A drift or refusal raised after a launch still verifies the runtime after the last
        # launched case before run() records the refusal; an unlaunched entry says so.
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


def launch_cases(args, env, root, state, snapshot, runtime, cases_root):
    """Each case once, in order; returns at the first non-completed, unlaunched or interrupted one."""
    for case_id in state['cases']:
        entry = {'case': case_id}
        state['attempts'].append(entry)
        # Immediately before each launch: source bytes/modes/links and the capture are unchanged.
        d2.verify_snapshot(snapshot, args.inventory, args.expected_inventory_sha256)
        require(capture_identity(args.capture) == state['identity']['capture'], 'Capture digest mismatch')
        source = matrix.case(case_id)['source']
        if not source_gate(cases_root, case_id):
            # Recorded as a refusal, not raised, so the runtime is still verified after the last
            # launched case. Nothing is spawned for this case.
            entry.update(status='NOT_LAUNCHED_SOURCE_INVALID')
            state.update(phase='RUNNER_REFUSED', stopped_at=case_id,
                         runner_failure={'type': 'VerificationError',
                                         'code': matrix.MATRIX_CODES['Matrix input source invalid']})
            break
        attempt = cases_root / case_id
        argv = [str(args.python), '-B', str(snapshot / 'tests/cnt-native-preflight.py'),
                *options(case_id, runtime, attempt, args.capture, cases_root / source if source else None)]
        entry['launched_utc'] = d2.utc()
        state['phase'] = 'LAUNCHING'
        save_state(root, state)
        with (root / (case_id + '-stdout.json')).open('w') as out, \
                (root / (case_id + '-stderr.log')).open('w') as err:
            code, interrupted = d2.wait_retained(d2.spawn(argv, env=env, cwd=root, stdout=out, stderr=err))
        entry.update(returncode=code, interrupted=interrupted, returned_utc=d2.utc(),
                     status=attempt_status(attempt))
        save_state(root, state)
        if interrupted:
            state.update(phase='INTERRUPTED_RETAINED', interrupted=True)
            return
        # The exit code is advisory; the attempt's own result.json status decides.
        if entry['status'] != COMPLETED:
            state.update(phase='STOPPED', stopped_at=case_id)
            break


def source_gate(cases_root, case_id):
    """Host duplicate of the preflight consumer gate: a dependent case runs only on the source
    attempt (S-RICH or S-MULTI) of this same claim root, completed with its own recorded readiness
    true (cnt_firefox_matrix.source_ready)."""
    entry = matrix.case(case_id)
    if entry['source'] is None:
        return True
    try:
        result = json.loads(d2.read_bounded(cases_root / entry['source'] / 'result.json'))
        facts = result.get('matrix') if isinstance(result, dict) else None
        return bool(isinstance(facts, dict) and result.get('status') == COMPLETED
                    and facts.get('case') == entry['source'] and facts.get('completed') is True
                    and matrix.source_ready(facts, entry))
    except (OSError, ValueError, TypeError, AttributeError, VerificationError):
        return False


def attempt_status(attempt):
    try:
        value = json.loads(d2.read_bounded(attempt / 'result.json'))
    except (OSError, ValueError, VerificationError):
        return 'RESULT_ABSENT_OR_UNREADABLE'
    status = value.get('status') if isinstance(value, dict) else None
    return status if status in (COMPLETED, 'BLOCKED') else 'RESULT_STATUS_INVALID'


def failure(value):
    if not isinstance(value, dict):
        return None if value is None else {'present': True}
    return {k: value[k] for k in ('stage', 'type', 'code') if isinstance(value.get(k), str)}


def case_summary(attempt, case_id=None):
    """Projection of one attempt; raw artifacts, paths, PIDs and messages never leave it.

    `case_id` is the host's own state entry, never the attempt's result: for a runnable D or E case or a
    B dependent the restores carry the observability-aware tri-state and the pre-restore ribbon
    reading, and the legacy classifications and predictions are labelled as computed on the recorded
    restore_error."""
    try:
        r = json.loads(d2.read_bounded(attempt / 'result.json'))
    except (OSError, ValueError, VerificationError):
        return {'result': 'ABSENT_OR_UNREADABLE'}
    facts = r.get('matrix') if isinstance(r.get('matrix'), dict) else {}
    classes = facts.get('classifications') if isinstance(facts.get('classifications'), dict) else {}
    settlement = r.get('settlement') or {}
    entry = matrix.CASE_INDEX.get(case_id) if isinstance(case_id, str) else None
    observed = isinstance(entry, dict) and entry['runnable'] is True and (
        entry['category'] in ('D', 'E') or (entry['category'] == 'B' and entry['source'] is not None))
    ribbon = facts.get('pre_restore_error_ribbon')
    ribbon = ribbon if isinstance(ribbon, str) and ribbon in matrix.PRE_RESTORE_RIBBONS else None
    restores = (matrix.restore_outcomes(facts.get('restores'), matrix.REPORT_OBSERVABILITY, ribbon) if observed
                else matrix.restore_outcomes(facts.get('restores')))
    summary = {
        'status': r.get('status'), 'native_semantics': r.get('native_semantics'),
        'captured_code_loaded': r.get('captured_code_loaded'),
        'browser_version': r.get('browser_version'),
        'runtime_unchanged': r.get('runtime_unchanged'),
        'exit_before_cleanup': r.get('exit_before_cleanup'), 'quit_observed': r.get('quit_observed'),
        'settlement': {k: settlement.get(k) for k in ('exit_code', 'zero_survivors', 'unsettled', 'workload_status')},
        **{k: failure(r.get(k)) for k in d2.FAILURE_FIELDS},
        'steps': [{k: s.get(k) for k in ('step', 'status', 'error_type')} for s in facts.get('steps') or []
                  if isinstance(s, dict)],
        'artifacts': {label: {'parts': [{k: p.get(k) for k in ('name_class', 'bytes', 'sha256')}
                                        for p in a.get('parts') or []],
                              'semantic_sha256': a.get('semantic_sha256'), 'derived': a.get('derived'),
                              'native_template': a.get('native_template'), 'source_ready': a.get('source_ready'),
                              'closure': a.get('closure'), 'complete': a.get('complete')}
                      for label, a in (facts.get('artifacts') or {}).items() if isinstance(a, dict)},
        'rich_source_ready': classes.get('rich_source_ready'),
        'rich_source_missing': classes.get('rich_source_missing'),
        'multi_source_ready': contained(classes.get('multi_source_ready')),
        'multi_source_missing': contained(classes.get('multi_source_missing')),
        'restores': restores,
        'classifications': facts.get('classifications'),
        'predictions': facts.get('predictions'), 'boundary_prediction': facts.get('boundary_prediction'),
        'partition': facts.get('partition'), 'blocked_facts': facts.get('blocked_facts'),
        'seed_trace': facts.get('seed_trace'), 'seed_failed_action': facts.get('seed_failed_action'),
        'inputs': inputs_summary(r.get('matrix_inputs')),
        'restore_evidence': contained(facts.get('restore_evidence')),
        'malformed_evidence': contained(facts.get('malformed_evidence')),
        'compat_evidence': contained(facts.get('compat_evidence')),
        'compat_input': contained(facts.get('compat_input')),
        'multipart_evidence': contained(facts.get('multipart_evidence')),
        'multipart_input': contained(facts.get('multipart_input'))}
    if observed:
        summary.update(pre_restore_error_ribbon=ribbon, report_observability=matrix.REPORT_OBSERVABILITY,
                       legacy_basis=matrix.PREDICTION_BASIS)
    try:
        return matrix.project(summary)
    except VerificationError:
        return {'status': r.get('status'), 'projection': 'REFUSED'}


MUTATION_RECORD = ('mutation', 'edit', 'target', 'part_number', 'parseable', 'before_sha256', 'after_sha256')


def inputs_summary(inputs):
    """Input part digests, the unmutated source digests of a mutated input and the fixed-key
    mutation record; never names, paths or bytes."""
    inputs = inputs if isinstance(inputs, dict) else {}
    digests = lambda key: [p.get('sha256') for p in inputs.get(key) or [] if isinstance(p, dict)]
    mutation = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else None
    return {'source_sha256': digests('source'), 'original_sha256': digests('original') or None,
            'mutation': mutation.get('mutation') if mutation else None,
            'mutation_record': {k: mutation.get(k) for k in MUTATION_RECORD} if mutation else None}


def contained(value):
    """Projected on its own: an unsafe restore-evidence value refuses only this field."""
    try:
        return matrix.project(value)
    except VerificationError:
        return {'projection': 'REFUSED'}


def source_binding(summaries, case_id):
    """A dependent's link to the same-root source artifact (S-RICH, or S-MULTI minimum), from values
    already projected in this summary: its input part digests and given semantic digest against the
    source's own record, and for a declared mutation the unmutated source digests, the mutation's
    before/after digests and the malformed, compat or multipart evidence's source semantic digest. A B
    selection transform (reversed, omitted or duplicated parts) leaves the input parts the exact source
    and is disclosed beside it. A mismatch reads false or MISMATCH, never raises."""
    entry = matrix.case(case_id)
    if entry['source'] is None:
        return None
    source = summaries.get(entry['source'])
    source = source if isinstance(source, dict) else {}
    artifacts = source.get('artifacts') if isinstance(source.get('artifacts'), dict) else {}
    artifact = artifacts.get(entry['artifact']) if isinstance(artifacts.get(entry['artifact']), dict) else {}
    dependent = summaries.get(case_id) if isinstance(summaries.get(case_id), dict) else {}
    projected = dependent.get('inputs') if isinstance(dependent.get('inputs'), dict) else {}
    inputs, original = projected.get('source_sha256'), projected.get('original_sha256')
    record = projected.get('mutation_record') if isinstance(projected.get('mutation_record'), dict) else None
    recorded = [p.get('sha256') for p in artifact.get('parts') or [] if isinstance(p, dict)]
    evidence = dependent.get('restore_evidence') if isinstance(dependent.get('restore_evidence'), dict) else {}
    malformed = dependent.get('malformed_evidence') if isinstance(dependent.get('malformed_evidence'), dict) else {}
    compat = dependent.get('compat_evidence') if isinstance(dependent.get('compat_evidence'), dict) else {}
    multipart = dependent.get('multipart_evidence') if isinstance(dependent.get('multipart_evidence'), dict) else {}
    mutated_source = (malformed.get('source') if isinstance(malformed.get('source'), dict) else
                      compat.get('source') if isinstance(compat.get('source'), dict) else
                      multipart.get('source') if isinstance(multipart.get('source'), dict) else {})
    given = evidence.get('given_semantic_sha256') or mutated_source.get('given_semantic_sha256')
    semantic = artifact.get('semantic_sha256')
    exact = bool(recorded) and inputs == recorded
    mutated = record is not None
    n = record.get('part_number') if mutated else None
    at = n - 1 if type(n) is int and bool(recorded) and 1 <= n <= len(recorded) else None
    listed = isinstance(inputs, list) and at is not None and len(inputs) == len(recorded)
    binding = {
        'source_case': entry['source'], 'artifact': entry['artifact'], 'source_status': source.get('status'),
        'source_rich_source_ready': source.get('rich_source_ready'),
        'source_artifact_ready': artifact.get('source_ready'),
        'input_parts_match_source': exact,
        'given_semantic_matches_source': isinstance(given, str) and given == semantic,
        'input_mutated': mutated,
        'original_parts_match_source': bool(recorded) and original == recorded if mutated else None,
        'mutation_before_matches_source': at is not None and record.get('before_sha256') == recorded[at]
        if mutated else None,
        'mutation_after_matches_input': listed and record.get('after_sha256') == inputs[at] if mutated else None,
        'unmutated_parts_match_source': listed and all(a == b for i, (a, b) in enumerate(zip(inputs, recorded))
                                                       if i != at) if mutated else None,
        'original_semantic_matches_source': (isinstance(mutated_source.get('original_semantic_sha256'), str)
                                             and mutated_source['original_semantic_sha256'] == semantic)
        if mutated_source else None}
    if entry['source'] == 'S-MULTI':
        # B only (D, E and rich-valid bindings keep their accepted shape): the S-MULTI readiness and the
        # selection transform, which leaves the input parts the exact source.
        binding.update(source_multi_source_ready=source.get('multi_source_ready'), selection_kind=entry['selection'])
    if not mutated:
        binding['binding_class'] = 'EXACT_SOURCE_INPUT' if exact else 'MISMATCH'
    else:
        held = [binding[k] for k in ('original_parts_match_source', 'mutation_before_matches_source',
                                     'mutation_after_matches_input', 'unmutated_parts_match_source')]
        if mutated_source:
            held.append(binding['original_semantic_matches_source'])
        binding['binding_class'] = 'DECLARED_MUTATION_OF_SOURCE' if all(v is True for v in held) else 'MISMATCH'
    return binding


def summarize(state, root):
    summary = {'schema': SUMMARY_SCHEMA, 'qualification_accepted': False,
               'semantic_success_claimed': False, 'budget': state.get('budget'),
               'scope': 'Native Firefox 6.12.1 matrix observations for manager review; not a lane pass.',
               'claim': {k: state.get(k) for k in ('phase', 'claimed_utc', 'bind_sha256', 'inventory_sha256',
                                                   'budget', 'host_claim', 'consumed_claims_present',
                                                   'identity', 'interrupted', 'runner_failure', 'stopped_at',
                                                   'runtime_before_first', 'runtime_after_last',
                                                   'launch_pytest_version', 'launch_environment_names')},
               'prerequisites': state.get('prerequisites', []), 'cases': {}}
    for entry in state.get('attempts') or []:
        summary['cases'][entry['case']] = {'returncode': entry.get('returncode'), 'status': entry.get('status'),
                                           'interrupted': entry.get('interrupted'),
                                           **case_summary(root / 'cases' / entry['case'], entry['case'])}
    for case_id, projected in summary['cases'].items():
        binding = source_binding(summary['cases'], case_id)
        if binding is not None:
            projected['source_binding'] = contained(binding)
    phase = state.get('phase')
    if state.get('interrupted'):
        label = LABELS['interrupted']
    elif phase == 'PREREQUISITE_FAILED':
        label = LABELS['prerequisite']
    elif phase == 'RUNNER_REFUSED':
        label = LABELS['refused']
    elif phase == 'STOPPED':
        label = LABELS['stopped']
    elif (phase == 'ATTEMPTS_RETURNED' and state.get('runtime_after_last') == 'MATCH'
          and len(state.get('attempts') or []) == len(state.get('cases') or [])
          and all(e.get('status') == COMPLETED for e in state['attempts'])):
        label = LABELS['all']
    elif not state.get('attempts'):
        label = LABELS['claimed']
    else:
        label = LABELS['stopped']
    summary['label'] = label
    return summary


def collect(root):
    """Read-only: no launch, provider, Nix, runtime bind or claim mutation."""
    root = d2.managed(root, 'Claim root')
    require(os.path.lexists(root / ROOT_CLAIM), 'No matrix claim to collect')
    state = json.loads(d2.read_bounded(root / STATE))
    summary = summarize(state, root)
    name, _ = next_slot(root, 'MATRIX-SUMMARY', summary)
    print(json.dumps({'label': summary['label'], 'summary': name, 'cases': len(summary['cases'])}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('bind', 'run'):
        sub = commands.add_parser(command)
        for name in ('snapshot', 'inventory', 'runtime', 'python', 'nix-bin', 'claim-root', 'capture'):
            sub.add_argument('--' + name, type=Path, required=True)
        sub.add_argument('--expected-inventory-sha256', required=True)
        sub.add_argument('--budget', required=True, choices=sorted(BUDGETS),
                         help='Manager-approved budget; it fixes the cases and the host claim')
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
