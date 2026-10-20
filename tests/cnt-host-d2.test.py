"""HOST-D2 runner contracts: every subprocess is faked; no browser, Nix or host scratch."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

CONFIGD = 'com.apple.SystemConfiguration.configd'
SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd']
PORT = 23456
# D1-shaped synthetic template from the pre-edit source (see cnt-confinement.test.py).
DEFAULT_TEMPLATE = 'fab8c31ce797f36a63fc7ae1e4f08f406e363add0a6a7dbc8844cc0f024e048a'


class World:
    def __init__(self, m, tmp_path):
        import cnt_confinement
        from source_only_snapshot import collect
        self.m, self.tmp = m, tmp_path
        self.snapshot = tmp_path / 'snapshot'
        (self.snapshot / 'tests').mkdir(parents=True)
        (self.snapshot / 'tests/cnt_host_d2.py').write_text('synthetic runner\n')
        (self.snapshot / 'tests/cnt-native-preflight.py').write_text('synthetic preflight\n')
        names = ['tests/cnt-native-preflight.py', 'tests/cnt_host_d2.py']
        entries = {n: r for n, (r, _) in collect(self.snapshot, names).items()}
        self.inventory_sha = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'))
                                            .encode()).hexdigest()
        self.inventory = tmp_path / 'snapshot-inventory.json'
        self.inventory.write_text(json.dumps({'sha256': self.inventory_sha, 'entries': entries}))
        m.RUNNER = self.snapshot / 'tests/cnt_host_d2.py'
        self.runtime = tmp_path / 'Firefox.app'
        (self.runtime / 'Contents/MacOS').mkdir(parents=True)
        (self.runtime / 'Contents/MacOS/firefox').write_bytes(b'synthetic firefox')
        m.D1_EXECUTABLE = hashlib.sha256(b'synthetic firefox').hexdigest()
        m.D1_RUNTIME = 'synthetic-runtime-digest'
        m.tree_digest = lambda path: m.D1_RUNTIME
        self.python = tmp_path / 'store/python-env/bin/python3'
        self.nix_bin = tmp_path / 'store/nix/bin'
        self.nix_bin.mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text('')
        (self.nix_bin / 'nix-store').write_text('')
        (self.nix_bin / 'nix-store').chmod(0o755)
        self.root = tmp_path / 'claim'
        self.root.mkdir()
        self.attempt = self.root / 'attempt'
        # The consumed D1 baseline shape and a D2 policy that differs by exactly the configd rule.
        base = self.policy(SERVICES)
        m.D1_TEMPLATE = cnt_confinement.policy_evidence(base, self.attempt, PORT, True)['policy_template_sha256']
        self.sb = self.policy([*SERVICES, CONFIGD])
        shutil.rmtree(self.attempt)  # policy() needs the bundle; the runner needs a fresh attempt
        d1 ={'engine': 'firefox', 'workload': 'empty', 'shutdown_trace': True, 'abnormal': False,
              'crash_force_enable': False, 'crash_readback': False, 'parent_probes': False,
              'shutdown_observer': False, 'sandbox_disables': ['content', 'socket', 'utility-generic'],
              'preflight': {'policy_template_sha256': m.D1_TEMPLATE, 'firefox_child_ipc': True},
              'runtime_snapshot_sha256': m.D1_RUNTIME, 'executable_sha256': m.D1_EXECUTABLE,
              'signature': {'original': True, 'frozen': True}, 'exit_before_cleanup': -11}
        self.d1 = tmp_path / 'd1-result.json'
        self.d1.write_text(json.dumps(d1))
        self.d1_sha = hashlib.sha256(self.d1.read_bytes()).hexdigest()
        self.result = self.good_result()
        self.prediction, self.pytest_version = m.D1_TEMPLATE, '8.4.2'
        self.pytest_line, self.pytest_code, self.launch_code = '15 passed in 3.00s', 0, 0
        self.interrupts, self.launches, self.kills, self.spawned, self.on_pytest = {}, [], [], [], None

    def policy(self, services):
        import cnt_confinement
        bundle = self.attempt / 'runtime/Firefox.app'
        bundle.mkdir(parents=True, exist_ok=True)
        return cnt_confinement.policy(self.attempt, [bundle], services, PORT, firefox_child_ipc=True,
                                      firefox_executable=bundle / 'Contents/MacOS/firefox')

    def good_result(self):
        m = self.m
        return {'status': 'DIAGNOSTIC_COMPLETED', 'engine': 'firefox', 'workload': 'empty', 'abnormal': False,
                'shutdown_trace': True, 'crash_force_enable': False, 'crash_readback': False,
                'parent_probes': False, 'shutdown_observer': False,
                'sandbox_disables': ['content', 'socket', 'utility-generic'],
                'mach_services': [*SERVICES, CONFIGD], 'configd_compatibility': True,
                'exit_before_cleanup': 0, 'quit_observed': 'reply',
                'protocol': [{'method': 'WebDriver:NewSession', 'outcome': 'passed'},
                             {'method': 'Marionette:Quit', 'outcome': 'passed'}],
                'settlement': {'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': [],
                               'workload_status': 'exited'},
                'runtime_snapshot_sha256': m.D1_RUNTIME, 'runtime_observed_sha256': m.D1_RUNTIME,
                'runtime_unchanged': True, 'executable_sha256': m.D1_EXECUTABLE, 'browser_version': '155.0.1',
                'listener_samples': [{'tcp_listeners': [], 'owned': True, 'stage': 'startup'},
                                     {'tcp_listeners': [f'127.0.0.1:{PORT}'], 'owned': True, 'stage': 'quit'}],
                'preflight': {'automation_port': PORT,
                              'policy_sha256': hashlib.sha256(self.sb.encode()).hexdigest(),
                              'policy_template_sha256': 'synthetic',
                              'canaries': {'same_port_wildcard_bind': 'ALLOWED', 'public_bind_refused': False}},
                'shutdown_trace_summary': {'status': 'SUMMARIZED', 'parent_last': {'op': 'NotifyObservers',
                                                                                  'topic': 'xpcom-shutdown'}}}

    def spawn(self, argv, **kw):
        world = self
        kind = ('predict' if 'predict' in argv else 'pytest' if 'pytest' in argv else 'launch')
        self.spawned.append(kind)
        out = kw.get('stdout')
        code = 0
        if kind == 'predict':
            out.write(json.dumps({'policy_template_sha256': 'x',
                                  'policy_template_without_configd_sha256': self.prediction,
                                  **({'pytest_version': self.pytest_version} if self.pytest_version else {})}))
        elif kind == 'pytest':
            out.write('...............\n' + self.pytest_line + '\n')
            code = self.pytest_code
            if self.on_pytest:
                self.on_pytest()
        else:
            self.launches.append((argv, kw['env'], kw['cwd']))
            if self.result is not None:
                self.attempt.mkdir(exist_ok=True)
                (self.attempt / 'confinement.sb').write_text(self.sb)
                (self.attempt / 'result.json').write_text(json.dumps(self.result))
            code = self.launch_code
        out.flush()

        class Child:
            def wait(self):
                if world.interrupts.get(kind, 0):
                    world.interrupts[kind] -= 1
                    raise KeyboardInterrupt()
                return code

            def kill(self):
                world.kills.append(kind)
            terminate = send_signal = kill
        return Child()

    def args(self, **overrides):
        from types import SimpleNamespace
        values = dict(snapshot=self.snapshot, inventory=self.inventory,
                      expected_inventory_sha256=self.inventory_sha, d1_result=self.d1,
                      d1_result_sha256=self.d1_sha, runtime=self.runtime, python=self.python,
                      nix_bin=self.nix_bin, claim_root=self.root)
        values.update(overrides)
        return SimpleNamespace(**values)

    def summary(self, index=1):
        return json.loads((self.root / f'D2-SUMMARY-{index:03d}.json').read_text())


@pytest.fixture
def world(load_module, monkeypatch, repo_root, tmp_path):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    m = load_module('tests/cnt_host_d2.py')
    import cnt_confinement
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    monkeypatch.setattr(m, 'SCRATCH', tmp_path)
    monkeypatch.setattr(m, 'STORE', tmp_path / 'store')
    w = World(m, tmp_path)
    monkeypatch.setattr(m, 'spawn', w.spawn)
    return m, w


def test_d1_options_match_cont6_document(world, repo_root):
    m, w = world
    text = (repo_root / 'docs/architecture/cnt-native-format-characterization.md').read_text()
    block = text.split('tests/cnt-native-preflight.py', 1)[1].split('```', 1)[0]
    tokens = block.replace('\\\n', ' ').split()
    assert tokens == m.d1_options('/Applications/Firefox.app', '<fresh-attempt>')


def test_d2_options_add_exactly_one_service_pair(world):
    m, w = world
    d1, d2 = m.d1_options('R', 'A'), m.d2_options('R', 'A')
    assert len(d2) == len(d1) + 2 and d2.count(CONFIGD) == 1
    at = d2.index(CONFIGD)
    assert d2[at - 1] == '--service' and d2[:at - 1] + d2[at + 1:] == d1
    assert m.D2_SERVICES == (*SERVICES, CONFIGD)


def test_predicted_policy_is_d1_shape_plus_configd(world, tmp_path):
    m, w = world
    run = tmp_path / 'prediction'
    run.mkdir()
    predicted = m.predicted_policy(run, [])
    assert predicted['policy_template_without_configd_sha256'] == DEFAULT_TEMPLATE
    assert predicted['policy_template_sha256'] != DEFAULT_TEMPLATE


def test_supported_run_launches_once_and_never_overwrites(world, capsys):
    m, w = world
    assert m.run(w.args()) == 0
    s = w.summary()
    assert s['label'] == m.SUPPORTS and s['failed_conjuncts'] == []
    assert s['diagnostic_only'] is True and s['qualification_accepted'] is False
    assert w.spawned == ['predict', 'pytest', 'pytest', 'launch'] and w.kills == []
    argv, env, cwd = w.launches[0]
    assert argv[:3] == [str(w.python), '-B', str(w.snapshot / 'tests/cnt-native-preflight.py')]
    assert argv[3:] == m.d2_options(w.runtime, w.attempt)
    frontend = m.nix_frontend(w.nix_bin)
    assert frontend.parent == w.nix_bin and shutil.which(frontend.name, path=env['PATH']) == str(frontend)
    assert sorted(env) == ['HOME', 'LANG', 'PATH', 'PYTHONDONTWRITEBYTECODE'] and cwd == w.root
    assert s['policy_delta']['attribution'] == 'ONLY_CONFIGD_RULE'
    assert s['policy_delta']['added_rule'] == '(allow mach-lookup (global-name "' + CONFIGD + '"))'
    assert [p['passed'] for p in s['prerequisites']] == [15, 15]
    assert s['claim']['phase'] == 'LAUNCH_RETURNED' and s['claim']['preflight_exit'] == 0
    assert s['claim']['launch_pytest_version'] == '8.4.2'
    with pytest.raises(RuntimeError, match='already claimed'):
        m.run(w.args())
    assert len(w.launches) == 1
    first = (w.root / 'D2-SUMMARY-001.json').read_bytes()
    assert m.collect(w.root) == 0 and len(w.launches) == 1
    assert (w.root / 'D2-SUMMARY-001.json').read_bytes() == first and w.summary(2)['label'] == m.SUPPORTS
    capsys.readouterr()


@pytest.mark.parametrize('case', ['inventory-sha', 'extra-conftest', 'bytecode', 'modified-byte', 'runner-outside',
                                  'git-dir', 'd1-sha', 'd1-config', 'runtime', 'executable', 'python-outside-store',
                                  'prediction-mismatch', 'prediction-failed', 'existing-claim',
                                  'existing-host-claim', 'launch-python-without-pytest', 'snapshot-outside-scratch'])
def test_refusals_before_claim_never_launch(world, tmp_path, case):
    m, w = world
    overrides = {}
    if case == 'inventory-sha': overrides['expected_inventory_sha256'] = '0' * 64
    if case == 'extra-conftest': (w.snapshot / 'tests/conftest.py').write_text('import os\n')
    if case == 'bytecode':
        (w.snapshot / 'tests/__pycache__').mkdir()
        (w.snapshot / 'tests/__pycache__/x.pyc').write_bytes(b'')
    if case == 'modified-byte': (w.snapshot / 'tests/cnt-native-preflight.py').write_text('synthetic preflighT\n')
    if case == 'runner-outside': m.RUNNER = tmp_path / 'elsewhere/tests/cnt_host_d2.py'
    if case == 'git-dir': (w.snapshot / '.git').mkdir()
    if case == 'd1-sha': overrides['d1_result_sha256'] = '0' * 64
    if case == 'd1-config':
        r = json.loads(w.d1.read_text()); r['crash_force_enable'] = True
        w.d1.write_text(json.dumps(r)); overrides['d1_result_sha256'] = hashlib.sha256(w.d1.read_bytes()).hexdigest()
    if case == 'runtime': m.tree_digest = lambda path: 'changed'
    if case == 'executable': (w.runtime / 'Contents/MacOS/firefox').write_bytes(b'changed')
    if case == 'python-outside-store':
        other = tmp_path / 'python3'; other.write_text(''); overrides['python'] = other
    if case == 'prediction-mismatch': w.prediction = 'f' * 64
    if case == 'prediction-failed': w.interrupts['predict'] = 1
    if case == 'existing-claim': (w.root / 'D2.claim').write_text('{}')
    if case == 'existing-host-claim': (tmp_path / m.HOST_CLAIM_NAME).write_text('{}')
    if case == 'launch-python-without-pytest': w.pytest_version = None
    if case == 'snapshot-outside-scratch': overrides['snapshot'] = Path('/nonexistent-outside-scratch')
    with pytest.raises(Exception):
        m.run(w.args(**overrides))
    assert w.launches == [] and 'pytest' not in w.spawned and w.kills == []
    assert os_exists(w.root / 'D2.claim') is (case == 'existing-claim')
    assert os_exists(tmp_path / m.HOST_CLAIM_NAME) is (case == 'existing-host-claim')


def nix_layout(w, frontends, mode=0o755):
    """HOSTPREP1-NIX-CLI-COMPAT1: rewrite the synthetic store bin with exactly these frontends."""
    for name in ('nix-store', 'nix'):
        if os_exists(w.nix_bin / name):
            (w.nix_bin / name).unlink()
    for name in frontends:
        (w.nix_bin / name).write_text('')
        (w.nix_bin / name).chmod(mode)


@pytest.mark.parametrize('layout', [('nix-store',), ('nix',), ('nix-store', 'nix')])
def test_launch_environment_accepts_either_supported_frontend(world, layout):
    m, w = world
    nix_layout(w, layout)
    env = m.launch_environment(w.python, w.nix_bin, w.root)
    assert env == {'PATH': f'{w.nix_bin}:/usr/bin:/bin', 'HOME': str(w.root / 'home'), 'LANG': 'en_US.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1'}
    # nix-store is preferred within the bin, matching cnt-native-preflight closure_frontend.
    assert m.nix_frontend(w.nix_bin) == w.nix_bin / layout[0]
    assert shutil.which(layout[0], path=env['PATH']) == str(w.nix_bin / layout[0])


def test_modern_only_nix_bin_runs_once(world, capsys):
    m, w = world
    nix_layout(w, ('nix',))
    assert m.run(w.args()) == 0
    assert w.spawned == ['predict', 'pytest', 'pytest', 'launch'] and len(w.launches) == 1
    assert w.summary()['label'] == m.SUPPORTS
    capsys.readouterr()


@pytest.mark.parametrize('case', ['neither', 'legacy-not-executable', 'modern-not-executable', 'nix-bin-outside-store',
                                  'nix-bin-link', 'nix-bin-not-dir', 'frontend-link-outside-store'])
def test_unsupported_nix_bin_refuses_before_prediction(world, tmp_path, case):
    m, w = world
    overrides = {}
    if case == 'neither': nix_layout(w, ())
    if case == 'legacy-not-executable': nix_layout(w, ('nix-store',), 0o644)
    if case == 'modern-not-executable': nix_layout(w, ('nix',), 0o644)
    if case == 'nix-bin-outside-store':
        other = tmp_path / 'elsewhere/bin'; other.mkdir(parents=True)
        (other / 'nix').write_text(''); (other / 'nix').chmod(0o755); overrides['nix_bin'] = other
    if case == 'nix-bin-link':
        link = tmp_path / 'store/nix-link'; link.symlink_to(w.nix_bin); overrides['nix_bin'] = link
    if case == 'nix-bin-not-dir':
        overrides['nix_bin'] = w.nix_bin / 'nix-store'
    if case == 'frontend-link-outside-store':
        wrapper = tmp_path / 'home-wrapper/nix'; wrapper.parent.mkdir(); wrapper.write_text(''); wrapper.chmod(0o755)
        nix_layout(w, ()); (w.nix_bin / 'nix').symlink_to(wrapper)
    with pytest.raises(RuntimeError, match='Nix bin must be a resolved /nix/store bin with an executable nix-store or nix'):
        m.run(w.args(**overrides))
    assert w.spawned == [] and w.launches == [] and w.kills == []
    assert not os_exists(w.root / 'D2.claim') and not os_exists(tmp_path / m.HOST_CLAIM_NAME)


def test_launch_interpreter_without_pytest_refuses_before_claim(world, tmp_path):
    m, w = world
    w.pytest_version = None
    with pytest.raises(RuntimeError, match='cannot import pytest'):
        m.run(w.args())
    assert w.spawned == ['predict'] and not os_exists(tmp_path / m.HOST_CLAIM_NAME)


def test_fresh_claim_root_cannot_launch_a_second_d2(world, tmp_path, capsys):
    m, w = world
    assert m.run(w.args()) == 0 and len(w.launches) == 1
    host = json.loads((tmp_path / m.HOST_CLAIM_NAME).read_text())
    assert host['claim_root_name'] == w.root.name and host['inventory_sha256'] == w.inventory_sha
    other = tmp_path / 'claim-2'
    other.mkdir()
    with pytest.raises(RuntimeError, match='already claimed on this host'):
        m.run(w.args(claim_root=other))
    assert len(w.launches) == 1 and not os_exists(other / 'D2.claim') and list(other.iterdir()) == []
    capsys.readouterr()


def os_exists(path):
    import os
    return os.path.lexists(path)


@pytest.mark.parametrize('line,code', [('13 failed, 2 passed in 3.00s', 1), ('14 passed in 3.00s', 0),
                                       ('15 passed, 1 skipped in 3.00s', 0), ('no tests ran', 5)])
def test_prerequisite_failure_prevents_launch_and_consumes_claim(world, capsys, line, code):
    m, w = world
    w.pytest_line, w.pytest_code = line, code
    assert m.run(w.args()) == 0
    s = w.summary()
    assert s['label'] == 'D2_PREREQUISITE_FAILED' and s['result'] == 'ABSENT'
    assert w.launches == [] and s['claim']['phase'] == 'PREREQUISITE_FAILED'
    with pytest.raises(RuntimeError, match='already claimed'):
        m.run(w.args())
    capsys.readouterr()


def test_snapshot_change_after_prerequisite_refuses_launch(world, capsys):
    m, w = world
    def plant():
        (w.snapshot / 'tests/__pycache__').mkdir(exist_ok=True)
        (w.snapshot / 'tests/__pycache__/conftest.cpython-313.pyc').write_bytes(b'')
    w.on_pytest = plant
    assert m.run(w.args()) == 0
    s = w.summary()
    assert w.launches == [] and s['claim']['phase'] == 'RUNNER_REFUSED'
    assert s['claim']['runner_failure']['message'] == 'Snapshot has missing or extra entries'
    assert s['label'] == 'D2_PREREQUISITE_FAILED'
    capsys.readouterr()


@pytest.mark.parametrize('stage', ['pytest', 'launch'])
def test_interrupt_is_retained_without_kill_or_retry(world, capsys, stage):
    m, w = world
    w.interrupts[stage] = 2
    if stage == 'launch':
        w.launch_code = 2
    assert m.run(w.args()) == 0
    s = w.summary()
    assert w.kills == [] and s['label'] == 'D2_INCOMPLETE_INTERRUPTED'
    assert s['claim']['phase'] == 'INTERRUPTED_RETAINED' and s['claim']['interrupted'] is True
    assert len(w.launches) == (1 if stage == 'launch' else 0)
    if stage == 'launch':
        assert s['claim']['preflight_exit'] == 2 and 'not_interrupted' in s['failed_conjuncts']
    with pytest.raises(RuntimeError, match='already claimed'):
        m.run(w.args())
    capsys.readouterr()


def test_wait_retained_waits_through_interrupts(world):
    m, w = world
    calls = []
    class Child:
        def wait(self):
            calls.append('wait')
            if len(calls) < 3: raise KeyboardInterrupt()
            return 5
        def kill(self): calls.append('kill')
        terminate = send_signal = kill
    assert m.wait_retained(Child()) == (5, True) and calls == ['wait'] * 3


def mutate(result, sb, case, w):
    if case == 'crash-exit': result['exit_before_cleanup'] = -11; result['status'] = 'DIAGNOSTIC_FAILED'
    if case == 'status': result['status'] = 'DIAGNOSTIC_FAILED'
    if case == 'no-quit': result['protocol'] = result['protocol'][:1]
    if case == 'survivors': result['settlement']['zero_survivors'] = False
    if case == 'cleanup-failure': result['cleanup_failure'] = {'stage': 'cleanup', 'type': 'OSError'}
    if case == 'runtime-drift': result['runtime_unchanged'] = False
    if case == 'crash-force': result['crash_force_enable'] = True
    if case == 'no-configd-recorded': result['mach_services'] = list(SERVICES)
    if case == 'unowned': result['listener_samples'][1]['owned'] = False
    if case == 'public-listener': result['listener_samples'][1]['tcp_listeners'] = [f'0.0.0.0:{PORT}']
    if case == 'no-listener': result['listener_samples'] = result['listener_samples'][:1]
    if case in ('policy-byte', 'policy-extra-rule', 'policy-configd-twice'):
        sb = (sb + ' ' if case == 'policy-byte' else
              sb + '(allow mach-lookup (global-name "com.apple.securityd"))\n' if case == 'policy-extra-rule'
              else sb + w.m.CONFIGD_RULE)
        if case != 'policy-byte':
            result['preflight']['policy_sha256'] = hashlib.sha256(sb.encode()).hexdigest()
    return sb


@pytest.mark.parametrize('case,conjunct', [
    ('crash-exit', 'exit_zero_before_cleanup'), ('status', 'status_diagnostic_completed'),
    ('no-quit', 'quit_requested'), ('survivors', 'clean_settlement'), ('cleanup-failure', 'no_recorded_failure'),
    ('runtime-drift', 'runtime_identity'), ('crash-force', 'configuration'),
    ('no-configd-recorded', 'configuration'), ('unowned', 'listeners_owned_loopback'),
    ('public-listener', 'listeners_owned_loopback'), ('no-listener', 'listeners_owned_loopback'),
    ('policy-byte', 'policy_one_factor'), ('policy-extra-rule', 'policy_one_factor'),
    ('policy-configd-twice', 'policy_one_factor')])
def test_each_negated_conjunct_fails_the_label(world, capsys, case, conjunct):
    m, w = world
    w.sb = mutate(w.result, w.sb, case, w)
    assert m.run(w.args()) == 0
    s = w.summary()
    assert s['label'] == 'D2_DIAGNOSTIC_FAILED' and conjunct in s['failed_conjuncts']
    if case in ('policy-extra-rule', 'policy-configd-twice'):
        assert s['policy_delta']['attribution'] == 'UNATTRIBUTED_POLICY_DIFFERENCE'
    capsys.readouterr()


def test_listener_count_uses_listener_samples_not_obsolete_key(world, capsys):
    m, w = world
    w.result['listener_samples'] = [dict(w.result['listener_samples'][1]) for _ in range(27)]
    w.result['listener_observations'] = []
    assert m.run(w.args()) == 0
    assert w.summary()['listeners']['listener_sample_count'] == 27
    capsys.readouterr()


@pytest.mark.parametrize('wildcard,refused', [('ALLOWED', False), ('DENIED', True), ('ERROR_22', False)])
def test_wildcard_bind_residual_copied_verbatim(world, capsys, wildcard, refused):
    m, w = world
    w.result['preflight']['canaries'] = {'same_port_wildcard_bind': wildcard, 'public_bind_refused': refused}
    assert m.run(w.args()) == 0
    listeners = w.summary()['listeners']
    assert listeners['same_port_wildcard_bind'] == wildcard and listeners['public_bind_refused'] is refused
    capsys.readouterr()


def test_summary_excludes_raw_logs_paths_pids_and_environment(world, capsys):
    m, w = world
    secret = '/private/SECRET-PATH 987654'
    w.result.update(browser_log_tail=secret, environment={'HOME': secret}, workload_pid=987654,
                    primary_failure={'stage': 'browser', 'type': 'X', 'classification': 'browser',
                                     'detail': secret})
    w.result['settlement']['observed_pids'] = [987654]
    w.result['listener_samples'][1]['pid'] = 987654
    w.result['owned_crash_artifacts'] = {'crash-data': {'status': 'INSPECTED', 'counts': {'dmp': 1},
                                                        'provenance': 'x', 'path': secret}}
    w.result['preflight']['canaries']['raw'] = secret
    assert m.run(w.args()) == 0
    (w.attempt / 'browser.log').write_text(secret)
    (w.root / 'preflight-stdout.json').write_text(secret)
    assert m.collect(w.root) == 0
    for index in (1, 2):
        exported = (w.root / f'D2-SUMMARY-{index:03d}.json').read_text()
        assert 'SECRET' not in exported and '987654' not in exported
        assert str(w.tmp) not in exported
    assert w.summary()['owned_crash_artifacts'] == {'crash-data': {'status': 'INSPECTED', 'counts': {'dmp': 1},
                                                                   'provenance': 'x'}}
    capsys.readouterr()


def test_collect_requires_claim_and_never_launches(world):
    m, w = world
    with pytest.raises(RuntimeError, match='No D2 claim'):
        m.collect(w.root)
    assert w.spawned == []
