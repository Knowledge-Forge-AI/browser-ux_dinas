"""BUX5B1 RECOVERY-HOSTPREP1 host runner contracts: every subprocess is faked.

No browser, codesign, Nix, pytest child, captured code, claim on the real host or live profile.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

GLOBAL_CLAIM = 'bux5b1-firefox-recovery-qual.claim'
HISTORICAL = ('bux-r6-firefox-native-matrix.claim', 'bux-r6-firefox-native-matrix-srich-repair2.claim',
              'bux-r6-firefox-native-matrix-rich-valid.claim', 'bux-r6-firefox-native-matrix-malformed-d.claim',
              'bux-r6-firefox-native-matrix-compat-e.claim', 'bux-r6-firefox-native-matrix-multipart-b.claim',
              'bux-r6-firefox-15601-requal.claim')
ATTEMPTS = ['01-source', '02-target-noop-match', '03-staging-synthetic-reset-completed',
            '04-target-synthetic-reset-completed', '05-staging-operator-auth-completed',
            '06-target-operator-auth-completed', '07-staging-concurrent-change', '08-target-concurrent-change',
            '09-staging-post-apply-mismatch-rollback', '10-target-post-apply-mismatch-rollback',
            '11-staging-rollback-failure', '12-target-rollback-failure', '13-staging-interrupted-rollback-resume',
            '14-target-interrupted-rollback-resume', '15-target-target-identity-refusal',
            '16-target-requested-part-refusal', '17-staging-idempotent-repeat', '18-target-idempotent-repeat']
SYNC_SHA256 = 'e24566ca833ef447cc849de4a4694bce22f53c32d58e7e85eeab13dfc91c0fc6'


class Proc:
    def __init__(self, code, interrupts=0):
        self.code, self.interrupts = code, interrupts

    def wait(self):
        if self.interrupts:
            self.interrupts -= 1
            raise KeyboardInterrupt
        return self.code


class World:
    def __init__(self, h, tmp_path, monkeypatch, repo_root, library_edit=None):
        import cnt_host_d2 as d2
        from source_only_snapshot import collect
        self.h, self.d2, self.tmp = h, d2, tmp_path
        scratch = tmp_path / 'scratch'
        scratch.mkdir()
        monkeypatch.setattr(d2, 'SCRATCH', scratch)
        import cnt_confinement
        monkeypatch.setattr(cnt_confinement, 'SCRATCH', scratch)
        self.scratch = scratch
        self.snapshot = scratch / 'snapshot'
        (self.snapshot / 'tests').mkdir(parents=True)
        (self.snapshot / 'libexec/clear-new-tab').mkdir(parents=True)
        names = ['tests/cnt_host_firefox_recovery.py', 'tests/cnt_host_d2.py', 'tests/cnt-native-preflight.py']
        for name in names:
            (self.snapshot / name).write_text('synthetic ' + name + '\n')
        for name in ('guarded_recovery.py', 'durable_state.py'):
            raw = (repo_root / 'libexec/clear-new-tab' / name).read_bytes()
            if library_edit == name:
                raw += b'\n# edited\n'
            (self.snapshot / 'libexec/clear-new-tab' / name).write_bytes(raw)
            names.append('libexec/clear-new-tab/' + name)
        entries = {n: rec for n, (rec, _) in collect(self.snapshot, names).items()}
        self.inventory_sha = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'))
                                            .encode()).hexdigest()
        self.inventory = scratch / 'snapshot-inventory.json'
        self.inventory.write_text(json.dumps({'sha256': self.inventory_sha, 'entries': entries}))
        monkeypatch.setattr(h, 'RUNNER', self.snapshot / 'tests/cnt_host_firefox_recovery.py')
        monkeypatch.setattr(d2, 'RUNNER', self.snapshot / 'tests/cnt_host_d2.py')
        self.runtime_calls = []
        monkeypatch.setattr(h.firefox, 'bind_runtime', self.bind_runtime)
        monkeypatch.setattr(d2, 'bind_runtime', self.historical_binder)
        monkeypatch.setattr(h.host_matrix, 'signature', lambda runtime: True)
        self.capture = {'xpi_sha256': h.matrix.XPI_SHA256, 'extension_id': 'clear-new-tab@loftyshaky',
                        'version': '6.12.1', 'manifest_version': 3, 'member_count': 129, 'verified_member_digests': 21}
        monkeypatch.setattr(h.matrix, 'verify_capture', lambda path: dict(self.capture))
        self.predictions = []
        self.prediction = {'policy_template_sha256': h.ACCEPTED_TEMPLATE,
                           'policy_template_without_configd_sha256': h.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
                           'pytest_version': '9.0.0'}
        monkeypatch.setattr(d2, 'predicted_template', self.predict)
        monkeypatch.setattr(h, 'free_bytes', lambda root: h.MIN_FREE_BYTES)
        self.python = tmp_path / 'store/python-env/bin/python3'
        self.nix_bin = tmp_path / 'store/nix/bin'
        self.nix_bin.mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text('')
        (self.nix_bin / 'nix-store').write_text('')
        (self.nix_bin / 'nix-store').chmod(0o755)
        monkeypatch.setattr(d2, 'STORE', tmp_path / 'store')
        self.root = scratch / 'claim'
        self.root.mkdir()
        self.xpi = scratch / 'retained/clear-new-tab.xpi'
        self.xpi.parent.mkdir()
        self.xpi.write_bytes(b'synthetic capture')
        self.spawned, self.statuses, self.expectations, self.interrupts, self.before_spawn = [], {}, {}, {}, {}
        self.pytest_ok = True
        self.events = []
        real_exclusive = d2.exclusive
        def exclusive(path, record):
            self.events.append(('claim', Path(path).name))
            return real_exclusive(path, record)
        monkeypatch.setattr(d2, 'exclusive', exclusive)
        monkeypatch.setattr(d2, 'spawn', self.spawn)

    def predict(self, python, env, root):
        self.events.append(('predict',))
        self.predictions.append(dict(env))
        return dict(self.prediction)

    def bind_runtime(self, runtime):
        self.runtime_calls.append(str(runtime))
        return dict(self.h.firefox.IDENTITY)

    @staticmethod
    def historical_binder(runtime):
        raise AssertionError('the historical D1 binder must not bind production')

    def spawn(self, argv, **kw):
        if '-m' in argv and 'pytest' in argv:
            self.spawned.append('pytest')
            self.events.append(('pytest',))
            kw['stdout'].write('15 passed in 1.0s\n' if self.pytest_ok else '1 failed in 1.0s\n')
            kw['stdout'].flush()
            return Proc(0 if self.pytest_ok else 1)
        attempt = Path(argv[argv.index('--scratch') + 1])
        self.spawned.append(attempt.name)
        self.events.append(('launch', attempt.name))
        self.before_spawn.get(attempt.name, lambda: None)()
        plan_path = Path(argv[argv.index('--recovery-plan') + 1])
        raw = plan_path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == argv[argv.index('--recovery-plan-sha256') + 1]
        plan = json.loads(raw)
        assert plan['attempt'] == str(attempt) and argv[argv.index('--workload') + 1] == 'cnt-recovery'
        attempt.mkdir()
        status = self.statuses.get(attempt.name, 'RECOVERY_ATTEMPT_COMPLETED')
        recovery = {'role': plan['role'], 'scenario': plan['scenario'], 'completed': True}
        if plan['role'] == 'target':
            recovery['expectation'] = self.expectations.get(attempt.name, 'MATCHED')
            for token in plan['tokens']:
                self.h.recovery.consume_token(token, plan['scenario'], plan['global_claim_sha256'], token['kind'],
                                              None if token['kind'] == 'NONE' else 'e' * 64)
        result = {'status': status, 'recovery_role': plan['role'], 'recovery_scenario': plan['scenario'],
                  'browser_version': '156.0.1', 'captured_code_loaded': True, 'runtime_unchanged': True,
                  'preflight': {'policy_template_sha256': self.h.ACCEPTED_TEMPLATE},
                  'recovery_freshness': {'proven': True, 'home_is_run_home': True, 'role': plan['role']},
                  'settlement': {'exit_code': 0, 'zero_survivors': True, 'unsettled': False,
                                 'workload_status': 'exited', 'observed_escapes': 0, 'survivors': [31337]},
                  'recovery': recovery}
        (attempt / 'result.json').write_text(json.dumps(result))
        return Proc(0 if status == 'RECOVERY_ATTEMPT_COMPLETED' else 2, self.interrupts.get(attempt.name, 0))

    def argv(self, command, **extra):
        values = ['--snapshot', str(self.snapshot), '--inventory', str(self.inventory),
                  '--runtime', str(self.tmp / 'Firefox.app'), '--python', str(self.python),
                  '--nix-bin', str(self.nix_bin), '--claim-root', str(self.root), '--capture', str(self.xpi),
                  '--expected-inventory-sha256', self.inventory_sha]
        for key, value in extra.items():
            values += ['--' + key.replace('_', '-'), value]
        return [command] + values

    def bind(self):
        assert self.h.main(self.argv('bind')) == 0
        path = sorted(self.root.glob('BIND-*.json'))[-1]
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def run(self):
        path, digest = self.bind()
        return self.h.main(self.argv('run', bind_record=str(path), bind_record_sha256=digest))

    def state(self):
        return json.loads((self.root / 'RECOVERY-QUAL-state.json').read_text())

    def summary(self):
        return json.loads(sorted(self.root.glob('RECOVERY-SUMMARY-*.json'))[-1].read_text())

    def launched(self):
        return [s for s in self.spawned if s != 'pytest']

    def claims(self):
        return (self.scratch / GLOBAL_CLAIM).exists(), (self.root / 'RECOVERY-QUAL.claim').exists()

    def nix_layout(self, frontends, mode=0o755):
        """NIX-CLI-COMPAT1: the synthetic store bin holds exactly these closure-query frontends."""
        for name in ('nix-store', 'nix'):
            if os.path.lexists(self.nix_bin / name):
                (self.nix_bin / name).unlink()
        for name in frontends:
            (self.nix_bin / name).write_text('')
            (self.nix_bin / name).chmod(mode)


@pytest.fixture
def h(monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_host_firefox_recovery
    return cnt_host_firefox_recovery


@pytest.fixture
def w(h, tmp_path, monkeypatch, repo_root):
    return World(h, tmp_path, monkeypatch, repo_root)


def test_roster_and_launch_plan_are_exact(h):
    assert h.recovery.ROSTER == ('NOOP_MATCH', 'SYNTHETIC_RESET_COMPLETED', 'OPERATOR_AUTH_COMPLETED',
                                 'CONCURRENT_CHANGE', 'POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE',
                                 'INTERRUPTED_ROLLBACK_RESUME', 'TARGET_IDENTITY_REFUSAL', 'REQUESTED_PART_REFUSAL',
                                 'IDEMPOTENT_REPEAT', 'ZERO_LIVE_CONTACT')
    plan = h.launches()
    assert len(plan) == 18 and [h.attempt_name(i, r, s) for i, (r, s) in enumerate(plan, 1)] == ATTEMPTS
    # Every staging attempt immediately precedes its own target.
    for i, (role, scenario) in enumerate(plan):
        if role == 'staging':
            assert plan[i + 1] == ('target', scenario)
    assert h.GLOBAL_CLAIM == GLOBAL_CLAIM and h.HISTORICAL_CLAIMS == HISTORICAL


def test_options_are_the_accepted_lane_plus_the_recovery_workload(h):
    argv = h.options('/R/Firefox.app', '/A', '/C.xpi', '/P.json', 'f' * 64)
    assert argv[:8] == ['--engine', 'firefox', '--runtime', '/R/Firefox.app', '--scratch', '/A',
                        '--workload', 'cnt-recovery']
    assert [argv[i + 1] for i, a in enumerate(argv) if a == '--service'] == h.host_matrix.SERVICES
    assert [argv[i + 1] for i, a in enumerate(argv) if a == '--nested-sandbox-exception'] == h.host_matrix.EXCEPTIONS
    assert argv[argv.index('--capture-sha256') + 1] == 'bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f'
    assert not {'--matrix-case', '--matrix-input', '--chrome-rendezvous', '--abnormal', '--shutdown-trace',
                '--parent-probes', '--crash-readback', '--crash-force-enable'} & set(argv)
    assert h.ACCEPTED_TEMPLATE == 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'


def test_bind_launches_nothing_and_claims_nothing(w):
    path, _ = w.bind()
    record = json.loads(path.read_text())
    assert record['schema'] == 'bux5b1-firefox-recovery-qual-bind-v1' and len(record['launches']) == 18
    assert record['identity']['libraries'] == {'guarded_recovery': w.h.recovery.GUARDED_RECOVERY_SHA256,
                                               'durable_state': w.h.recovery.DURABLE_STATE_SHA256}
    assert record['identity']['recovery_prep1']['tree'] == '622154aa87074f394f0f0baca3879a58bb4d9a76'
    assert record['identity']['firefox']['version'] == '156.0.1'
    assert record['historical_claims_present'] == dict.fromkeys(HISTORICAL, False)
    assert w.spawned == [] and w.claims() == (False, False)
    assert not any((w.root / d).exists() for d in ('cases', 'tokens', 'plans', 'staging'))


@pytest.mark.parametrize('name', ['guarded_recovery.py', 'durable_state.py'])
def test_bind_refuses_a_snapshot_library_other_than_the_accepted_one(h, tmp_path, monkeypatch, repo_root, name):
    world = World(h, tmp_path, monkeypatch, repo_root, library_edit=name)
    with pytest.raises(h.VerificationError, match='^Recovery library digest mismatch$'):
        world.bind()
    assert world.claims() == (False, False)


NIX_ENV = ('HOME', 'LANG', 'PATH', 'PYTHONDONTWRITEBYTECODE')


@pytest.mark.parametrize('layout', [('nix-store',), ('nix',)])
def test_bind_accepts_legacy_or_modern_nix_bin_with_an_identical_record(h, tmp_path, monkeypatch, repo_root,
                                                                         layout):
    records = []
    for name, frontends in (('legacy', ('nix-store',)), ('selected', layout)):
        (tmp_path / name).mkdir()
        world = World(h, tmp_path / name, monkeypatch, repo_root)
        world.nix_layout(frontends)
        path, _ = world.bind()
        records.append(json.loads(path.read_text()))
        assert world.predictions == [{'PATH': f'{world.nix_bin}:/usr/bin:/bin', 'HOME': str(world.root / 'home'),
                                      'LANG': 'en_US.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}]
        assert world.spawned == [] and world.claims() == (False, False)
    # nix_bin is not part of the bound identity; only the synthetic per-world paths differ.
    for key in ('identity', 'roster', 'launches', 'journals', 'token_kinds', 'global_claim', 'launch_options'):
        assert records[0][key] == records[1][key], key
    assert records[0]['launch_environment_names'] == records[1]['launch_environment_names'] == list(NIX_ENV)


def test_full_run_with_a_modern_only_nix_bin(w):
    w.nix_layout(('nix',))
    assert w.run() == 0
    assert w.spawned == ['pytest', 'pytest'] + ATTEMPTS
    assert w.summary()['label'] == 'BUX5B1_RECOVERY_QUAL_RECORDED_PENDING_MANAGER_REVIEW'
    assert all(env['PATH'] == f'{w.nix_bin}:/usr/bin:/bin' for env in w.predictions)


@pytest.mark.parametrize('case', ['neither', 'legacy-not-executable', 'modern-not-executable',
                                  'nix-bin-outside-store', 'nix-bin-link'])
def test_bind_refuses_an_unsupported_nix_bin_before_prediction(w, tmp_path, case):
    if case == 'neither': w.nix_layout(())
    if case == 'legacy-not-executable': w.nix_layout(('nix-store',), 0o644)
    if case == 'modern-not-executable': w.nix_layout(('nix',), 0o644)
    if case == 'nix-bin-outside-store':
        other = tmp_path / 'elsewhere/bin'; other.mkdir(parents=True)
        (other / 'nix').write_text(''); (other / 'nix').chmod(0o755); w.nix_bin = other
    if case == 'nix-bin-link':
        link = tmp_path / 'store/nix-link'; link.symlink_to(w.nix_bin); w.nix_bin = link
    with pytest.raises(w.h.VerificationError, match='^Nix bin must be a resolved /nix/store bin with an executable '
                                                    'nix-store or nix$'):
        w.bind()
    assert w.predictions == [] and w.spawned == [] and w.claims() == (False, False)
    assert list(w.root.glob('BIND-*.json')) == []


def test_full_run_launches_each_role_once_in_order_under_new_claims(w):
    assert w.run() == 0
    assert w.spawned == ['pytest', 'pytest'] + ATTEMPTS
    state, summary = w.state(), w.summary()
    assert w.claims() == (True, True) and state['phase'] == 'ATTEMPTS_RETURNED'
    assert state['runtime_before_first'] == 'MATCH' and state['runtime_after_last'] == 'MATCH'
    assert summary['label'] == 'BUX5B1_RECOVERY_QUAL_RECORDED_PENDING_MANAGER_REVIEW'
    assert summary['semantic_success_claimed'] is False and summary['qualification_accepted'] is False
    assert summary['zero_live_contact']['status'] == 'MATCHED'
    assert summary['zero_live_contact']['launched_attempts'] == 18
    assert summary['zero_live_contact']['live_default_profile_basis'] == 'STRUCTURAL_NO_ROUTE_NOT_OBSERVED'
    assert {j: t['state'] for j, t in summary['tokens'].items()} == dict.fromkeys(w.h.recovery.TOKEN_KIND, 'CONSUMED')
    for entry in state['attempts']:
        plan = w.root / 'plans' / (entry['attempt'] + '.json')
        assert hashlib.sha256(plan.read_bytes()).hexdigest() == entry['plan_sha256'] and entry['absent_before_spawn']
    claim = json.loads((w.scratch / GLOBAL_CLAIM).read_text())
    assert claim['claim_root_name'] == 'claim' and claim['schema'] == 'bux5b1-firefox-recovery-qual-claim-v1'
    tokens = json.loads((w.root / 'tokens/s03-operator.token').read_text())
    assert tokens['global_claim_sha256'] == hashlib.sha256((w.scratch / GLOBAL_CLAIM).read_bytes()).hexdigest()


def test_claims_follow_both_prerequisites_and_the_immediate_recheck(w):
    assert w.run() == 0
    claim_at = w.events.index(('claim', GLOBAL_CLAIM))
    before = w.events[:claim_at]
    # bind, run binding, then 15+15, then the immediate recheck, then the claims.
    assert before == [('predict',), ('predict',), ('pytest',), ('pytest',), ('predict',)]
    assert w.events[claim_at + 1] == ('claim', 'RECOVERY-QUAL.claim')
    assert w.events[claim_at + 2:claim_at + 3] == [('launch', '01-source')]


def test_prerequisite_failure_consumes_nothing(w):
    w.pytest_ok = False
    with pytest.raises(w.h.VerificationError):
        w.run()
    assert w.claims() == (False, False) and w.launched() == []
    record = json.loads(sorted(w.root.glob('PREREQUISITES-*.json'))[-1].read_text())
    assert record['claims_consumed'] is False and record['ok'] is False


@pytest.mark.parametrize('drift', ['policy', 'runtime', 'capture'])
def test_immediate_recheck_drift_refuses_before_any_claim(w, monkeypatch, drift):
    real_predict, real_bind = w.predict, w.bind_runtime
    count = {'predict': 0, 'runtime': 0}
    def predict(*a):
        count['predict'] += 1
        value = real_predict(*a)
        if drift == 'policy' and count['predict'] == 3:
            value['policy_template_sha256'] = '0' * 64
        return value
    def bind_runtime(runtime):
        count['runtime'] += 1
        if drift == 'runtime' and count['runtime'] == 3:
            raise w.h.VerificationError('Firefox runtime differs from the production runtime')
        return real_bind(runtime)
    monkeypatch.setattr(w.d2, 'predicted_template', predict)
    monkeypatch.setattr(w.h.firefox, 'bind_runtime', bind_runtime)
    if drift == 'capture':
        def verify(path, n=[0]):
            n[0] += 1
            return dict(w.capture, member_count=1) if n[0] == 3 else dict(w.capture)
        monkeypatch.setattr(w.h.matrix, 'verify_capture', verify)
    with pytest.raises(w.h.VerificationError):
        w.run()
    assert w.claims() == (False, False) and w.launched() == []
    assert json.loads(sorted(w.root.glob('PREREQUISITES-*.json'))[-1].read_text())['ok'] is True


@pytest.mark.parametrize('which', ['global', 'root'])
def test_existing_claim_refuses_collect_never_rerun(w, which):
    if which == 'global':
        (w.scratch / GLOBAL_CLAIM).write_text('{}\n')
    else:
        (w.root / 'RECOVERY-QUAL.claim').write_text('{}\n')
    with pytest.raises(w.h.VerificationError, match='never rerun'):
        w.run()
    assert w.launched() == [] and w.spawned == []


@pytest.mark.parametrize('present', [True, False])
def test_historical_claims_are_provenance_never_gates(w, present):
    stats = {}
    if present:
        for name in HISTORICAL:
            path = w.scratch / name
            path.write_text('{"consumed": true}\n')
            stats[name] = path.stat()
            path.chmod(0)
    assert w.run() == 0 and w.launched() == ATTEMPTS
    assert w.state()['historical_claims_present'] == dict.fromkeys(HISTORICAL, present)
    for name, before in stats.items():
        path = w.scratch / name
        info = path.stat()
        assert (info.st_ino, info.st_size, info.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
        path.chmod(0o600)
        assert path.read_text() == '{"consumed": true}\n'


@pytest.mark.parametrize('at,how', [('01-source', 'blocked'), ('03-staging-synthetic-reset-completed', 'blocked'),
                                    ('06-target-operator-auth-completed', 'mismatched'),
                                    ('16-target-requested-part-refusal', 'mismatched'),
                                    ('18-target-idempotent-repeat', 'blocked')])
def test_stops_at_the_first_unmatched_attempt(w, at, how):
    if how == 'blocked':
        w.statuses[at] = 'BLOCKED'
    else:
        w.expectations[at] = 'MISMATCHED'
    assert w.run() == 0
    state = w.state()
    assert w.launched() == ATTEMPTS[:ATTEMPTS.index(at) + 1]
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at and state['runtime_after_last'] == 'MATCH'
    assert w.summary()['label'] == 'BUX5B1_RECOVERY_QUAL_STOPPED_AT_ATTEMPT' and w.claims() == (True, True)


def test_runtime_is_verified_after_a_refusal_raised_after_a_launch(w, monkeypatch):
    calls = {'n': 0}
    real = w.h.host_matrix.capture_identity
    def capture(path):
        calls['n'] += 1
        # bind, run, recheck, then before launch 1 and 2: the third launch sees drift.
        return dict(real(path), member_count=0) if calls['n'] == 6 else real(path)
    monkeypatch.setattr(w.h.host_matrix, 'capture_identity', capture)
    assert w.run() == 0
    state = w.state()
    assert w.launched() == ATTEMPTS[:2] and state['phase'] == 'RUNNER_REFUSED'
    assert state['attempts'][-1]['status'] == 'NOT_LAUNCHED_RUNNER_REFUSED'
    assert state['runtime_after_last'] == 'MATCH' and w.summary()['label'] == 'BUX5B1_RECOVERY_QUAL_RUNNER_REFUSED'


def test_operator_interrupt_waits_retains_state_and_does_no_further_work(w):
    w.interrupts['02-target-noop-match'] = 1
    assert w.run() == 0
    state = w.state()
    assert w.launched() == ATTEMPTS[:2] and state['phase'] == 'INTERRUPTED_RETAINED' and state['interrupted']
    assert 'runtime_after_last' not in state and w.claims() == (True, True)
    assert w.summary()['label'] == 'BUX5B1_RECOVERY_QUAL_INCOMPLETE_INTERRUPTED'


def test_existing_attempt_path_refuses_before_spawn(w):
    w.before_spawn['01-source'] = lambda: (w.root / 'cases/02-target-noop-match-state').mkdir()
    assert w.run() == 0
    assert w.launched() == ['01-source'] and w.state()['phase'] == 'RUNNER_REFUSED'


def test_collect_is_read_only(w, monkeypatch):
    assert w.run() == 0
    before = {p: (p.stat().st_ino, p.read_bytes()) for p in (w.scratch / GLOBAL_CLAIM, w.root / 'RECOVERY-QUAL.claim')}
    import subprocess
    def refuse(*a, **kw):
        raise AssertionError('collect must not launch, bind, claim or call a provider')
    for owner, name in ((w.d2, 'spawn'), (w.d2, 'exclusive'), (w.d2, 'predicted_template'),
                        (w.h.firefox, 'bind_runtime'), (subprocess, 'run'), (subprocess, 'Popen'),
                        (w.h.recovery, 'issue_token'), (w.h.recovery, 'consume_token')):
        monkeypatch.setattr(owner, name, refuse)
    assert w.h.main(['collect', '--claim-root', str(w.root)]) == 0
    assert len(list(w.root.glob('RECOVERY-SUMMARY-*.json'))) == 2
    assert {p: (p.stat().st_ino, p.read_bytes()) for p in before} == before


def pid_exposures(value, pid, private, path='$'):
    """Structural PID/path leaks. A path-dependent sha256 may contain the PID's digits by chance."""
    if isinstance(value, dict):
        return [f'{path}.{k}: pid key' for k in value if k == 'survivors' or k.lower().startswith('pid')] + [
            v for k, item in value.items() for v in pid_exposures(item, pid, private, f'{path}.{k}')]
    if isinstance(value, list):
        return [v for i, item in enumerate(value) for v in pid_exposures(item, pid, private, f'{path}[{i}]')]
    if isinstance(value, str):
        digest = len(value) == 64 and set(value) <= set('0123456789abcdef')
        return [f'{path}: private text'] if private in value or (str(pid) in value and not digest) else []
    return [f'{path}: pid value'] if type(value) is int and value == pid else []


def test_summary_is_privacy_safe(w):
    assert w.run() == 0
    assert pid_exposures(w.summary(), 31337, str(w.tmp)) == []
    # HOSTPREP1-FIX1: no substring scan over path-dependent digests; real leaks are still caught.
    assert pid_exposures({'plan_sha256': '31337'.ljust(64, 'a')}, 31337, str(w.tmp)) == []
    for leak in ({'survivors': [1]}, {'pid': 1}, {'n': 31337}, {'s': 'pid 31337'}, {'s': str(w.tmp / 'x')}):
        assert pid_exposures(leak, 31337, str(w.tmp)), leak
    for attempt in w.summary()['attempts'].values():
        assert set(attempt['settlement']) == {'exit_code', 'zero_survivors', 'unsettled', 'workload_status',
                                              'observed_escapes'}


def test_zero_live_contact_needs_every_launched_attempt(w):
    real = w.spawn
    def spawn(argv, **kw):
        proc = real(argv, **kw)
        if '--scratch' in argv and argv[argv.index('--scratch') + 1].endswith('07-staging-concurrent-change'):
            path = Path(argv[argv.index('--scratch') + 1]) / 'result.json'
            result = json.loads(path.read_text())
            result['preflight']['policy_template_sha256'] = '0' * 64
            path.write_text(json.dumps(result))
        return proc
    w.d2.spawn = spawn
    assert w.run() == 0
    summary = w.summary()
    assert summary['zero_live_contact']['status'] == 'NOT_PROVEN'
    assert summary['label'] != 'BUX5B1_RECOVERY_QUAL_RECORDED_PENDING_MANAGER_REVIEW'


# --- static package, command and consumer boundaries ------------------------------------------------

def test_exactly_ten_commands_and_clear_new_tab_sync_pinned(repo_root):
    assert len([p for p in (repo_root / 'bin').iterdir()]) == 10
    assert hashlib.sha256((repo_root / 'bin/clear-new-tab-sync').read_bytes()).hexdigest() == SYNC_SHA256
    for path in (repo_root / 'bin').iterdir():
        text = path.read_bytes()
        assert b'cnt_firefox_recovery' not in text and b'guarded_recovery' not in text


def test_harness_is_test_owned_and_unpackaged(repo_root):
    roster = json.loads((repo_root / 'tests/source-only-roster.json').read_text())
    new = ['tests/cnt_firefox_recovery.py', 'tests/cnt_host_firefox_recovery.py', 'tests/cnt-firefox-recovery.test.py',
           'tests/cnt-host-firefox-recovery.test.py', 'docs/architecture/clear-new-tab-durable-authority.md']
    assert all(name in roster for name in new) and len(roster) == len(set(roster))
    for nix in [p for p in repo_root.rglob('*.nix') if '.scratch' not in p.parts and 'tests' not in p.parts]:
        assert 'cnt_firefox_recovery' not in nix.read_text() and 'host_firefox_recovery' not in nix.read_text()
    assert not (repo_root / 'libexec/clear-new-tab/cnt_firefox_recovery.py').exists()


def test_host_runner_has_no_chrome_cdp_rendezvous_owned_process_or_assert(h):
    tree = ast.parse(Path(h.__file__).read_text())
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    text = Path(h.__file__).read_text()
    for forbidden in ('cnt_synthetic_chrome', 'cnt_protocol', 'rendezvous', 'CDP', 'OwnedProcess', 'cnt_supervisor',
                      "'--engine', 'chrome'", 'canonical_root('):
        assert forbidden not in text
