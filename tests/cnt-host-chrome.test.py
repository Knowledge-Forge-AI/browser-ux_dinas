"""HOST Chrome runner contracts: every subprocess is faked; no browser, Nix, codesign or host scratch.

Live-mode attempts run the real preflight launch_empty Chrome branch, CDPPipe and adapter over
real in-process pipes against the scripted peer (tests/cnt_chrome_peer.py); only the owned
process is a stand-in. Their transcript reaches attempt_summary unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sys
import threading
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from cnt_chrome_peer import Browser, Owner  # noqa: E402

SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd']
VERSION = '140.0.7339.80'
STORE_NAME = '0123456789abcdfghijklmnpqrsvwxyz-google-chrome-' + VERSION
POLICY = '(version 1)\n(deny default)\n(allow file-read* (subpath "{run}"))\n'
FULL = ['Browser.getVersion', 'Target.createTarget', 'Target.attachToTarget', 'Target.getTargets',
        'Runtime.evaluate', 'Extensions.loadUnpacked', 'Target.getTargets', 'Extensions.getExtensions',
        'Target.attachToTarget', 'Extensions.getStorageItems', 'Target.detachFromTarget', 'Extensions.uninstall',
        'Extensions.getExtensions', 'Target.getTargets']
SCOPES = {'Runtime.evaluate': 'page', 'Extensions.getStorageItems': 'extension-worker'}
USEFUL = ('page_nonce', 'extension_installed', 'extension_worker_observed', 'extension_registry_listed',
          'extension_session_attached', 'extension_nonce', 'extension_uninstall_replied',
          'extension_registry_absent', 'extension_worker_absent', 'extension_unloaded')
QUALIFIED = {'method': 'Browser.close', 'outcome': 'failed', 'error': 'CDPEOF'}
RULE = ('(allow mach-register mach-lookup (global-name (string-append '
        '"com.google.Chrome.MachPortRendezvousServer." (param "CHROME_RENDEZVOUS_PID"))))\n')
C1A = ['--chrome-rendezvous', 'own-workload-pid']
MATCHED = {'state': 'MATCHED_WORKLOAD', 'workload_pid_matches': True, 'argv_template_matches': True,
           'sandboxed_pid_matches': None, 'record_sha256': 'a' * 64, 'helper_code': None, 'exec_errno': None}


class Process:
    def __init__(self, code, interrupt=False):
        self.code, self.interrupt, self.waits = code, interrupt, 0
        self.pid = 4242

    def wait(self):
        self.waits += 1
        if self.interrupt and self.waits == 1:
            raise KeyboardInterrupt
        return self.code

    def kill(self): raise AssertionError('runner must never kill')
    terminate = send_signal = kill


class World:
    def __init__(self, m, tmp_path, monkeypatch, load_module):
        from source_only_snapshot import collect
        d2 = m.d2
        self.m, self.d2, self.tmp = m, d2, tmp_path
        self.snapshot = tmp_path / 'snapshot'
        (self.snapshot / 'tests').mkdir(parents=True)
        names = ['tests/cnt-native-preflight.py', 'tests/cnt_host_chrome.py', 'tests/cnt_host_d2.py']
        for name in names:
            (self.snapshot / name).write_text('synthetic ' + name + '\n')
        entries = {n: r for n, (r, _) in collect(self.snapshot, names).items()}
        self.inventory_sha = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'))
                                            .encode()).hexdigest()
        self.inventory = tmp_path / 'snapshot-inventory.json'
        self.inventory.write_text(json.dumps({'sha256': self.inventory_sha, 'entries': entries}))
        monkeypatch.setattr(m, 'RUNNER', self.snapshot / 'tests/cnt_host_chrome.py')
        monkeypatch.setattr(d2, 'RUNNER', self.snapshot / 'tests/cnt_host_d2.py')
        monkeypatch.setattr(d2, 'SCRATCH', tmp_path)
        monkeypatch.setattr(d2, 'STORE', tmp_path / 'store')
        store = (tmp_path / 'store').resolve()
        self.runtime = store / STORE_NAME / 'Applications/Google Chrome.app'
        (self.runtime / 'Contents/MacOS').mkdir(parents=True)
        (self.runtime / 'Contents/MacOS/Google Chrome').write_bytes(b'synthetic chrome')
        (self.runtime / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'com.google.Chrome', 'CFBundleExecutable': 'Google Chrome',
            'CFBundleShortVersionString': VERSION}))
        preflight = load_module('tests/cnt-native-preflight.py')
        monkeypatch.setattr(preflight, 'CHROME_STORE', store)
        monkeypatch.setattr(m, 'load_preflight', lambda: preflight)
        self.selection = tmp_path / 'current-system/Applications/Google Chrome.app'
        self.selection.parent.mkdir(parents=True)
        self.selection.symlink_to(self.runtime)
        self.alias = tmp_path / 'Nix Apps/Google Chrome.app'
        monkeypatch.setattr(m, 'ALIASES', {'nix_apps': self.alias})
        monkeypatch.setattr(m, 'DAILY_APP', tmp_path / 'Applications/Google Chrome.app')
        self.python = tmp_path / 'store/python-env/bin/python3'
        self.nix_bin = tmp_path / 'store/nix/bin'
        self.python.parent.mkdir(parents=True)
        self.nix_bin.mkdir(parents=True)
        self.python.write_text('')
        (self.nix_bin / 'nix-store').write_text('')
        (self.nix_bin / 'nix-store').chmod(0o755)
        self.root = tmp_path / 'claim'
        self.root.mkdir()
        self.template = hashlib.sha256(POLICY.format(run='<RUN>').encode()).hexdigest()
        self.c1a_template = hashlib.sha256((POLICY.format(run='<RUN>') + RULE).encode()).hexdigest()
        self.c1a_baseline = self.template
        self.pid_check_code, self.pid_check_interrupt, self.pid_check_mutation = 0, False, None
        self.closure = hashlib.sha256(b'/nix/store/x').hexdigest()
        self.codesign, self.launches, self.spawned, self.results = [], [], [], {}
        self.pytest_line, self.pytest_code, self.interrupt_role, self.after_launch = '15 passed in 3.00s', 0, None, None
        self.preflight, self.monkeypatch = preflight, monkeypatch
        self.live, self.settle, self.mutations, self.peers = {}, {}, {}, []
        monkeypatch.setattr(m.subprocess, 'run', self.run_codesign)
        monkeypatch.setattr(d2, 'spawn', self.spawn)
        for name in ('Popen', 'check_output', 'call'):
            monkeypatch.setattr(m.subprocess, name, lambda *a, **kw: pytest.fail('unfaked subprocess'))

    def run_codesign(self, argv, **kw):
        self.codesign.append(argv)
        return SimpleNamespace(returncode=0)

    def spawn(self, argv, env=None, cwd=None, stdout=None, stderr=None):
        self.spawned.append(argv)
        if 'predict' in argv:
            value = {'policy_template_sha256': self.template, 'closure_count': 3,
                     'closure_sha256': self.closure, 'pytest_version': '8.4.2'}
            if '--chrome-rendezvous' in argv:
                value.update(policy_template_sha256=self.c1a_template,
                             baseline_policy_template_sha256=self.c1a_baseline)
            stdout.write(json.dumps(value))
            stdout.flush()
            return Process(0)
        if 'pid-check' in argv:
            value = self.pid_check_good()
            if self.pid_check_mutation:
                value = self.pid_check_mutation(value)
            stdout.write(value if isinstance(value, str) else json.dumps(value))
            stdout.flush()
            return Process(self.pid_check_code, interrupt=self.pid_check_interrupt)
        if '-m' in argv:
            stdout.write(self.pytest_line + '\n')
            stdout.flush()
            return Process(self.pytest_code)
        role = Path(argv[argv.index('--scratch') + 1]).name
        attempt = Path(argv[argv.index('--scratch') + 1])
        self.launches.append((role, argv))
        attempt.mkdir()
        record = self.results.get(role, self.good(role))
        if role in self.live:
            record = self.live_record(role, attempt)
        policy = POLICY.format(run=attempt) + (RULE if '--chrome-rendezvous' in argv else '')
        (attempt / 'confinement.sb').write_text(policy)
        if record is not None:
            record = json.loads(json.dumps(record))
            if '--chrome-rendezvous' in argv and role not in self.live and role not in self.results:
                self.c1a_facts(record)
            if role in self.mutations:
                self.mutations[role](record)
                record['status'] = self.preflight.outcome(record)
            record['preflight'].setdefault('policy_sha256', hashlib.sha256(policy.encode()).hexdigest())
            (attempt / 'result.json').write_text(json.dumps(record))
        if self.after_launch:
            self.after_launch(role)
        return Process(0 if role != 'startup' and record and record['status'] == 'SYNTHETIC_ATTEMPT_PASSED' else 2,
                       interrupt=role == self.interrupt_role)

    def live_record(self, role, attempt):
        """The real launch_empty Chrome branch; only the owned process is a stand-in."""
        import cnt_owned_process, cnt_synthetic_chrome as canonical
        for name, value in (('STARTUP_DEADLINE', 1), ('CALL_TIMEOUT', 1), ('PAGE_DEADLINE', .5),
                            ('EXTENSION_DEADLINE', .5), ('REMOVAL_DEADLINE', .5), ('CLOSE_DEADLINE', .5),
                            ('EXIT_DEADLINE', .5), ('ABNORMAL_WAIT', .05), ('EOF_EXIT_OBSERVATION', .2),
                            ('POLL_INTERVAL', .001)):
            self.monkeypatch.setattr(canonical, name, value)
        knobs, settle, peers = self.live[role], self.settle.get(role, {}), self.peers

        class Owned:
            def __init__(self, command, run, env, log, pipe_fds=(), evidence=None, markers=()):
                self.returncode, self.workload_pid, self.result, self.received = None, 4242, {}, 0
                reader, writer = (os.dup(fd) for fd in pipe_fds)  # launch_empty closes its copies
                self.browser = Browser(self, reader, writer, **{k: v for k, v in knobs.items()
                                                                if k not in ('c1a', 'pid')})
                peers.append((reader, self.browser))
                if knobs.get('startup_eof') is not None:
                    self.browser.close_writer()
                    threading.Timer(.02, lambda: setattr(self, 'returncode', knobs['startup_eof'])).start()
            receive = Owner.receive
            until = Owner.until

            def settle(self):
                if settle.get('raise'):
                    raise RuntimeError('synthetic cleanup failure')
                exited = self.returncode is not None
                return {'exit_code': self.returncode, 'workload_status': 'exited' if exited else 'unknown-before-kill',
                        'zero_survivors': settle.get('zero_survivors', True), 'unsettled': False,
                        'failures': [], 'observed_escapes': 0}
        self.monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owned)
        for name in ('profile', 'home', 'tmp'):
            (attempt / name).mkdir()
        record = self.good(role)
        for key in (*USEFUL, 'quit_observed', 'intended_timeout', 'close_reply', 'protocol', 'settlement',
                    'exit_before_cleanup', 'browser_close_requested'):
            record.pop(key, None)
        record['browser_launched'] = True
        rendezvous = {}
        if knobs.get('c1a'):
            # The helper's own record, written as the real helper would under the given PID.
            import cnt_chrome_rendezvous as rv
            self.c1a_facts(record)
            record.pop('rendezvous_parameter')
            evidence = attempt.parent / (attempt.name + '-rendezvous')
            evidence.mkdir(mode=0o700)
            evidence.chmod(0o700)
            self.monkeypatch.setattr(rv, 'STORE', str(self.tmp / 'store'))
            sandboxed = ['/usr/bin/sandbox-exec', '-f', str(attempt / 'confinement.sb'),
                         str(self.runtime / 'Contents/MacOS/Google Chrome'), '--remote-debugging-pipe']
            def execv(path, argv):
                raise KeyboardInterrupt  # stands in for a successful exec
            try:
                rv.main([str(evidence), 'browser', '--', *sandboxed], {}, getpid=lambda: knobs.get('pid', 4242),
                        execv=execv)
            except KeyboardInterrupt:
                pass
            rendezvous = {'rendezvous': {'evidence': evidence, 'argv': sandboxed}}
        self.preflight.launch_empty(['sandboxed-chrome'], attempt, 'chrome', abnormal=role == 'abnormal',
                                    result=record, workload=record['workload'], expected_version=VERSION,
                                    **rendezvous)
        record['status'] = self.preflight.outcome(record)
        return record

    def c1a_facts(self, record):
        record['chrome_rendezvous'] = 'OWN_WORKLOAD_PID'
        record['preflight'].update(chrome_rendezvous='OWN_WORKLOAD_PID',
                                   status='CANARIES_PASSED_NOT_BROWSER_QUALIFICATION',
                                   policy_template_sha256=self.c1a_template,
                                   rendezvous_canary=dict(MATCHED, sandboxed_pid_matches=True))
        record['rendezvous_parameter'] = dict(MATCHED)

    def pid_check_good(self):
        return {'status': 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION',
                'settlement': {'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': []},
                'rendezvous_canary': dict(MATCHED, sandboxed_pid_matches=True),
                'policy_template_sha256': self.c1a_template,
                'policy_template_without_rendezvous_sha256': self.c1a_baseline,
                'undefined_parameter': {'state': 'REFUSED_BEFORE_PROGRAM', 'exit_code': 65,
                                        'clean_settlement': True, 'log_sha256': 'a' * 64, 'log_bytes': 40}}

    def close_peers(self):
        for reader, browser in self.peers:
            browser.thread.join(2)
            assert not browser.thread.is_alive()
            os.close(reader)
            browser.close_writer()

    def good(self, role):
        startup, abnormal = role == 'startup', role == 'abnormal'
        methods = ['Browser.getVersion'] if startup else list(FULL)
        if not abnormal:
            methods.append('Browser.close')
        digest = self.m.tree_digest(self.runtime)
        record = {'status': 'DIAGNOSTIC_COMPLETED' if startup else 'SYNTHETIC_ATTEMPT_PASSED',
                  'engine': 'chrome', 'workload': 'empty' if startup else 'full', 'abnormal': abnormal,
                  'diagnostic_only': startup, 'crash_force_enable': False, 'crash_readback': False,
                  'parent_probes': False, 'shutdown_trace': False, 'shutdown_observer': False,
                  'sandbox_disables': [], 'mach_services': SERVICES, 'configd_compatibility': False,
                  'chrome_rendezvous': 'NOT_SELECTED', 'browser_launched': True,
                  'preflight': {'automation_port': None, 'firefox_child_ipc': False,
                                'policy_template_sha256': self.template},
                  'ready': True, 'browser_version': VERSION, 'protocol_version': '1.3', 'version_matches': True,
                  'protocol': [{'method': name, 'outcome': 'passed', **({'scope': SCOPES[name]}
                                                                         if name in SCOPES else {})}
                               for name in methods],
                  'runtime_preparation_complete': True, 'runtime_unchanged': True,
                  'runtime_measurement': {'state': 'MATCH', 'digest_complete': True},
                  'runtime_measurement_root': 'SELECTED_STORE_APP', 'runtime_source_sha256': digest,
                  'runtime_snapshot_sha256': digest, 'runtime_observed_sha256': digest,
                  'executable_sha256': hashlib.sha256(b'synthetic chrome').hexdigest(),
                  'runtime_closure_sha256': self.closure, 'runtime_closure_count': 3,
                  'runtime_bundle_id': 'com.google.Chrome', 'runtime_bundle_version': VERSION,
                  'signature': {'original': True}, 'browser_close_requested': not abnormal,
                  'settlement': {'exit_code': None if abnormal else 0, 'zero_survivors': True, 'unsettled': False,
                                 'failures': [], 'workload_status': 'unknown-before-kill' if abnormal else 'exited'},
                  'exit_before_cleanup': None if abnormal else 0,
                  'owned_crash_artifacts': {'profile/Crashpad': {'status': 'ABSENT_DIRECTORY', 'errno': 2}}}
        if not startup:
            record.update({k: True for k in USEFUL})
            record.update(extension_registry_before='LISTED_ENABLED', extension_registry_after='ABSENT')
        if abnormal:
            record['intended_timeout'] = True
        else:
            record.update(quit_observed='reply', close_reply=True)
        return record

    def common(self):
        return ['--snapshot', str(self.snapshot), '--inventory', str(self.inventory),
                '--expected-inventory-sha256', self.inventory_sha, '--runtime', str(self.runtime),
                '--selection', str(self.selection), '--python', str(self.python), '--nix-bin', str(self.nix_bin),
                '--claim-root', str(self.root)]

    def bind(self, capsys, extra=()):
        assert self.m.main(['bind', *self.common(), *extra]) == 0
        out = json.loads(capsys.readouterr().out)
        return self.root / out['bind'], out['sha256']

    def c1a_bind(self, capsys):
        """A baseline reference record (read only), then the C1A bind against it."""
        reference = self.bind(capsys)
        copy = self.tmp / 'BIND-001-reference.json'
        copy.write_bytes(reference[0].read_bytes())
        self.reference = (copy, reference[1])
        return self.bind(capsys, [*C1A, '--reference-bind', str(copy), '--reference-bind-sha256', reference[1]])

    def run(self, operation, bind, extra=()):
        return self.m.main(['run', *self.common(), '--operation', operation, '--bind-record', str(bind[0]),
                            '--bind-record-sha256', bind[1], *extra])

    def summary(self, name='SUMMARY-001.json'):
        return json.loads((self.root / name).read_text())

    def claims(self):
        return sorted(p.name for p in self.tmp.glob('bux-r5-chrome-*.claim'))


@pytest.fixture
def world(load_module, monkeypatch, repo_root, tmp_path):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    m = load_module('tests/cnt_host_chrome.py')
    world = World(m, tmp_path, monkeypatch, load_module)
    yield world
    world.close_peers()


def startup_summary(world, capsys):
    bind = world.bind(capsys)
    assert world.run('startup', bind) == 0
    out = json.loads(capsys.readouterr().out)
    path = world.root / out['summary']
    return bind, path, out['sha256']


def pair_root(world):
    world.root = world.tmp / 'pair-claim'
    world.root.mkdir()


def test_bind_launches_nothing_claims_nothing_and_leaks_no_path(world, capsys):
    path, digest = world.bind(capsys)
    record = json.loads(path.read_text())
    assert path.name == 'BIND-001.json' and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert world.launches == [] and world.claims() == [] and not (world.root / 'CHROME.claim').exists()
    identity = record['identity']
    assert identity['bundle_version'] == VERSION and identity['bundle_id'] == 'com.google.Chrome'
    assert identity['policy_template_sha256'] == world.template and identity['services'] == SERVICES
    assert identity['runtime_path_sha256'] == hashlib.sha256(str(world.runtime).encode()).hexdigest()
    assert record['selection'] == {'selection_resolves_to_runtime': True, 'aliases': {'nix_apps': 'ABSENT'},
                                   'daily_app_present_unread': False}
    assert world.codesign == [['/usr/bin/codesign', '--verify', '--deep', '--strict', str(world.runtime)]]
    assert str(world.tmp) not in path.read_text()
    world.bind(capsys)
    assert (world.root / 'BIND-002.json').exists() and path.read_bytes() == path.read_bytes()


@pytest.mark.parametrize('case,message', [
    ('extra-file', 'Snapshot has missing or extra entries'),
    ('wrong-inventory', 'Snapshot inventory is not the approved candidate'),
    ('selection-missing', 'Chrome selection missing'),
    ('selection-differs', 'Chrome selection differs from the explicit runtime'),
    ('alias-differs', 'Chrome selection ambiguous'),
    ('codesign', 'Chrome original signature invalid'),
    ('chromium', 'Chrome bundle identity refused'),
    ('runner-outside-snapshot', 'Runner must execute from the approved snapshot')])
def test_bind_refusals(world, capsys, monkeypatch, case, message):
    if case == 'extra-file':
        (world.snapshot / 'tests/conftest.py').write_text('')
    elif case == 'wrong-inventory':
        world.inventory_sha = '0' * 64
    elif case == 'selection-missing':
        world.selection.unlink()
    elif case == 'selection-differs':
        world.selection.unlink()
        world.selection.symlink_to(world.tmp)
    elif case == 'alias-differs':
        world.alias.parent.mkdir()
        world.alias.symlink_to(world.tmp)
    elif case == 'codesign':
        monkeypatch.setattr(world.m.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1))
    elif case == 'chromium':
        (world.runtime / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'org.chromium.Chromium', 'CFBundleExecutable': 'Google Chrome',
            'CFBundleShortVersionString': VERSION}))
    elif case == 'runner-outside-snapshot':
        monkeypatch.setattr(world.m, 'RUNNER', world.tmp / 'cnt_host_chrome.py')
    with pytest.raises(Exception, match=message):
        world.m.main(['bind', *world.common()])
    assert world.launches == [] and not list(world.root.glob('BIND-*'))


@pytest.mark.parametrize('kind,expected', [('same', 'LINK_SAME'), ('copy', 'NOT_LINK_CONTENT_UNREAD')])
def test_alias_classification_never_reads_content(world, capsys, kind, expected):
    world.alias.parent.mkdir()
    if kind == 'same':
        world.alias.symlink_to(world.runtime)
    else:
        world.alias.mkdir()
        (world.alias / 'unreadable').write_text('x')
        (world.alias / 'unreadable').chmod(0)
    record = json.loads(world.bind(capsys)[0].read_text())
    assert record['selection']['aliases'] == {'nix_apps': expected}


def test_runtime_drift_during_binding_refuses(world, monkeypatch):
    digests = iter(['first', 'second'])
    monkeypatch.setattr(world.m, 'tree_digest', lambda path: next(digests))
    with pytest.raises(Exception, match='Chrome runtime changed during binding'):
        world.m.main(['bind', *world.common()])


def test_startup_launches_exactly_once_and_completes(world, capsys):
    bind = world.bind(capsys)
    assert world.claims() == []
    assert world.run('startup', bind) == 0
    out = json.loads(capsys.readouterr().out)
    summary = world.summary()
    assert out['label'] == summary['label'] == 'CHROME_STARTUP_DIAGNOSTIC_COMPLETED'
    assert [role for role, _ in world.launches] == ['startup']
    argv = world.launches[0][1]
    assert argv[:3] == [str(world.python), '-B', str(world.snapshot / 'tests/cnt-native-preflight.py')]
    assert argv[3:7] == ['--engine', 'chrome', '--runtime', str(world.runtime)]
    assert argv[argv.index('--workload') + 1] == 'empty' and '--abnormal' not in argv
    assert [argv[i + 1] for i, a in enumerate(argv) if a == '--service'] == SERVICES
    assert not any(a.startswith(('--nested', '--crash', '--parent', '--shutdown')) for a in argv)
    assert world.claims() == ['bux-r5-chrome-startup.claim']
    assert summary['attempts']['startup']['passed'] and summary['qualification_accepted'] is False
    assert [p['mode'] for p in summary['prerequisites']] == ['normal', 'optimized']
    assert str(world.tmp) not in (world.root / 'SUMMARY-001.json').read_text()
    # Never twice on this host, whatever claim root is chosen.
    world.root = world.tmp / 'second'
    world.root.mkdir()
    with pytest.raises(Exception, match='Operation already claimed on this host'):
        world.run('startup', bind)
    assert len(world.launches) == 1


@pytest.mark.parametrize('case', ['bind-sha', 'identity-changed', 'selection-changed'])
def test_run_refuses_before_claim_when_binding_differs(world, capsys, case):
    bind = world.bind(capsys)
    if case == 'bind-sha':
        bind = (bind[0], '0' * 64)
    elif case == 'identity-changed':
        (world.runtime / 'Contents/MacOS/Google Chrome').write_bytes(b'changed')
    elif case == 'selection-changed':
        world.selection.unlink()
        world.selection.symlink_to(world.tmp)
    with pytest.raises(Exception):
        world.run('startup', bind)
    assert world.launches == [] and world.claims() == [] and not (world.root / 'CHROME.claim').exists()


def test_pair_requires_completed_startup_for_same_bind(world, capsys):
    bind = world.bind(capsys)
    with pytest.raises(Exception, match='startup summary is required'):
        world.run('pair', bind)
    with pytest.raises(Exception, match='startup summary is required'):
        world.run('startup', bind, ['--startup-summary', 'x', '--startup-summary-sha256', 'y'])
    world.results['startup'] = dict(world.good('startup'), exit_before_cleanup=-11)
    assert world.run('startup', bind) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['label'] == 'CHROME_STARTUP_DIAGNOSTIC_FAILED'
    pair_root(world)
    with pytest.raises(Exception, match='completed startup diagnostic'):
        world.run('pair', bind, ['--startup-summary', str(world.tmp / 'claim' / out['summary']),
                                 '--startup-summary-sha256', out['sha256']])
    assert [r for r, _ in world.launches] == ['startup'] and 'bux-r5-chrome-pair.claim' not in world.claims()


@pytest.mark.parametrize('copied', [(), ('CHROME.claim',)])
def test_pair_refuses_a_summary_outside_the_startup_claim_root(world, capsys, copied):
    bind, path, digest = startup_summary(world, capsys)
    forged = world.tmp / 'forged'
    forged.mkdir()
    for name in (path.name, *copied):
        (forged / name).write_bytes((path.parent / name).read_bytes())
    pair_root(world)
    with pytest.raises(Exception, match='completed startup diagnostic'):
        world.run('pair', bind, ['--startup-summary', str(forged / path.name), '--startup-summary-sha256', digest])
    assert [r for r, _ in world.launches] == ['startup'] and world.claims() == ['bux-r5-chrome-startup.claim']
    assert not (world.root / 'CHROME.claim').exists()


def test_pair_runs_normal_then_abnormal(world, capsys):
    bind, path, digest = startup_summary(world, capsys)
    pair_root(world)
    assert world.run('pair', bind, ['--startup-summary', str(path), '--startup-summary-sha256', digest]) == 0
    summary = world.summary()
    assert summary['label'] == 'CHROME_USEFUL_PAIR_PASSED_PENDING_MANAGER_REVIEW'
    assert [r for r, _ in world.launches] == ['startup', 'normal', 'abnormal']
    abnormal = world.launches[2][1]
    assert '--abnormal' in abnormal and abnormal[abnormal.index('--workload') + 1] == 'full'
    assert summary['attempts']['normal']['quit_observed'] == 'reply'
    assert summary['attempts']['abnormal']['intended_timeout'] is True
    assert world.claims() == ['bux-r5-chrome-pair.claim', 'bux-r5-chrome-startup.claim']


def test_failed_normal_never_starts_abnormal(world, capsys):
    bind, path, digest = startup_summary(world, capsys)
    pair_root(world)
    world.results['normal'] = dict(world.good('normal'), exit_before_cleanup=-11,
                                   status='BLOCKED', quit_observed=None)
    assert world.run('pair', bind, ['--startup-summary', str(path), '--startup-summary-sha256', digest]) == 0
    summary = world.summary()
    assert [r for r, _ in world.launches] == ['startup', 'normal']
    assert summary['label'] == 'CHROME_PAIR_FAILED' and summary['claim']['abnormal'] == 'NOT_STARTED_NORMAL_FAILED'
    assert summary['attempts']['abnormal']['result'] == 'ABSENT'


def test_prerequisite_failure_never_launches(world, capsys):
    bind = world.bind(capsys)
    world.pytest_line = '14 passed, 1 failed in 3.00s'
    world.run('startup', bind)
    assert world.launches == [] and world.summary()['label'] == 'CHROME_PREREQUISITE_FAILED'
    assert world.claims() == ['bux-r5-chrome-startup.claim']


def test_interrupt_is_waited_through_and_retained(world, capsys):
    bind = world.bind(capsys)
    world.interrupt_role = 'startup'
    world.run('startup', bind)
    summary = world.summary()
    assert summary['label'] == 'CHROME_INCOMPLETE_INTERRUPTED' and summary['claim']['interrupted'] is True
    assert summary['claim']['phase'] == 'INTERRUPTED_RETAINED' and len(world.launches) == 1


def test_selection_change_after_launch_fails_the_attempt(world, capsys):
    bind = world.bind(capsys)
    def change(role):
        world.selection.unlink()
        world.selection.symlink_to(world.tmp)
    world.after_launch = change
    world.run('startup', bind)
    attempt = world.summary()['attempts']['startup']
    assert attempt['failed_checks'] == ['selection_stable']


def mutate(record, path, value):
    target = record
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        target.pop(path[-1], None)
    else:
        target[path[-1]] = value


@pytest.mark.parametrize('role,path,value,check', [
    ('normal', ('status',), 'BLOCKED', 'native_predicate'),
    ('normal', ('preflight', 'automation_port'), 12345, 'selected_configuration'),
    ('normal', ('preflight', 'automation_port'), KeyError, 'selected_configuration'),
    ('normal', ('mach_services',), [*SERVICES, 'com.apple.SystemConfiguration.configd'], 'selected_configuration'),
    ('normal', ('shutdown_trace',), True, 'selected_configuration'),
    ('normal', ('sandbox_disables',), ['content'], 'selected_configuration'),
    ('normal', ('extension_worker_observed',), KeyError, 'useful_work'),
    ('normal', ('extension_unloaded',), KeyError, 'useful_work'),
    ('normal', ('protocol', 9, 'outcome'), 'failed', 'protocol_work'),
    ('normal', ('protocol', 12, 'method'), 'Extensions.setStorageItems', 'protocol_work'),
    ('normal', ('runtime_measurement', 'state'), 'MISMATCH', 'runtime_identity'),
    ('normal', ('runtime_measurement', 'state'), 'INCOMPLETE', 'runtime_identity'),
    ('normal', ('runtime_observed_sha256',), '0' * 64, 'runtime_identity'),
    ('normal', ('runtime_closure_sha256',), '0' * 64, 'runtime_identity'),
    ('normal', ('signature',), {'original': True, 'frozen': True}, 'runtime_identity'),
    ('normal', ('browser_version',), '139.0.0.1', 'session_version'),
    ('normal', ('preflight', 'policy_template_sha256'), '0' * 64, 'policy'),
    ('normal', ('preflight', 'policy_sha256'), '0' * 64, 'policy'),
    ('normal', ('settlement', 'unsettled'), True, 'settlement'),
    ('normal', ('primary_failure',), {'stage': 'browser', 'code': 'CDP_EOF'}, 'no_failures'),
    ('normal', ('browser_close_requested',), False, 'termination'),
    ('normal', ('quit_observed',), 'eof', 'termination'),
    ('normal', ('close_reply',), False, 'termination'),
    ('normal', ('close_reply',), KeyError, 'termination'),
    ('normal', ('protocol', 9, 'scope'), KeyError, 'protocol_work'),
    ('normal', ('protocol', 7, 'scope'), 'extension-worker', 'protocol_work'),
    ('normal', ('protocol', 4, 'scope'), 'extension-worker', 'protocol_work'),
    ('normal', ('extension_registry_absent',), KeyError, 'useful_work'),
    ('normal', ('extension_session_attached',), KeyError, 'useful_work'),
    ('normal', ('exit_before_cleanup',), -11, 'termination'),
    ('abnormal', ('quit_observed',), 'reply', 'termination'),
    ('abnormal', ('intended_timeout',), KeyError, 'termination'),
    ('abnormal', ('browser_close_requested',), True, 'termination')])
def test_each_conjunct_has_a_negative(world, capsys, role, path, value, check):
    bind, summary_path, digest = startup_summary(world, capsys)
    pair_root(world)
    record = world.good(role)
    mutate(record, path, value)
    world.results[role] = record
    world.run('pair', bind, ['--startup-summary', str(summary_path), '--startup-summary-sha256', digest])
    attempt = world.summary()['attempts'][role]
    assert check in attempt['failed_checks'] and attempt['passed'] is False
    assert world.summary()['label'] == 'CHROME_PAIR_FAILED'


def test_listing_unavailable_is_not_excused(world, capsys):
    bind, path, digest = startup_summary(world, capsys)
    pair_root(world)
    record = world.good('normal')
    for index in (7, 12):
        record['protocol'][index] = {'method': 'Extensions.getExtensions', 'outcome': 'failed',
                                     'optional': True, 'protocol_error': 'method-unavailable'}
    world.results['normal'] = record
    world.run('pair', bind, ['--startup-summary', str(path), '--startup-summary-sha256', digest])
    assert world.summary()['label'] == 'CHROME_PAIR_FAILED'
    assert 'protocol_work' in world.summary()['attempts']['normal']['failed_checks']


def live_pair(world, capsys, normal=None, abnormal=None, startup=None, mutate_normal=None, settle=None):
    world.live['startup'] = startup or {}
    bind, path, digest = startup_summary(world, capsys)
    startup_attempt = world.summary()['attempts']['startup']
    pair_root(world)
    world.live.update(normal=normal or {}, abnormal=abnormal or {})
    if mutate_normal:
        world.mutations['normal'] = mutate_normal
    if settle:
        world.settle['normal'] = settle
    world.run('pair', bind, ['--startup-summary', str(path), '--startup-summary-sha256', digest])
    return startup_attempt, world.summary()


@pytest.mark.parametrize('close', ['reply', 'eof'])
def test_live_adapter_transcript_reaches_the_summary(world, capsys, close):
    startup, summary = live_pair(world, capsys, normal={'close': close}, startup={'close': close})
    assert startup['passed'] and startup['close_transport'] == ('REPLY' if close == 'reply' else 'QUALIFIED_EOF')
    assert summary['label'] == 'CHROME_USEFUL_PAIR_PASSED_PENDING_MANAGER_REVIEW', summary['attempts']
    normal, abnormal = summary['attempts']['normal'], summary['attempts']['abnormal']
    assert normal['passed'] and abnormal['passed']
    expected_close = {'method': 'Browser.close', 'outcome': 'passed'} if close == 'reply' else QUALIFIED
    # The truthful raw record is exported unchanged; the summary carries the qualification.
    assert normal['protocol'][-1] == expected_close
    assert normal['close_transport'] == ('REPLY' if close == 'reply' else 'QUALIFIED_EOF')
    assert normal['quit_observed'] == ('reply' if close == 'reply' else 'qualified-eof')
    assert normal['close_reply'] is (close == 'reply') and normal['exit_before_cleanup'] == 0
    assert normal['extension_registry'] == ['LISTED_ENABLED', 'ABSENT']
    assert normal['extension_uninstall_replied'] is True and normal['extension_worker_absent'] is True
    assert [m.get('scope') for m in normal['protocol'] if 'scope' in m][-1] == 'extension-worker'
    assert abnormal['close_transport'] == 'ABSENT' and abnormal['intended_timeout'] is True
    raw = (world.root / 'SUMMARY-001.json').read_text()
    for secret in ('B' * 32, 'D' * 32, 'abcdefghijklmnopabcdefghijklmnop', '/private/fixture', str(world.tmp)):
        assert secret not in raw


def test_live_empty_startup_is_diagnostic_never_a_pair(world, capsys):
    world.live['startup'] = {'close': 'eof'}
    bind = world.bind(capsys)
    world.run('startup', bind)
    summary = world.summary()
    assert summary['label'] == 'CHROME_STARTUP_DIAGNOSTIC_COMPLETED'
    assert summary['attempts']['startup']['protocol'] == [
        {'method': 'Browser.getVersion', 'outcome': 'passed'}, QUALIFIED]


@pytest.mark.parametrize('knobs,check', [
    ({'startup_eof': 0}, 'protocol_work'),                         # EOF during startup
    ({'eof_on': 'Browser.getVersion'}, 'protocol_work'),           # EOF on another method
    ({'close': 'eof', 'exit_code': -11}, 'termination'),           # nonzero owned exit
    ({'close': 'eof', 'exit_code': None}, 'termination')])         # absent owned exit
def test_live_startup_eof_negatives(world, capsys, knobs, check):
    world.live['startup'] = knobs
    bind = world.bind(capsys)
    world.run('startup', bind)
    attempt = world.summary()['attempts']['startup']
    assert world.summary()['label'] == 'CHROME_STARTUP_DIAGNOSTIC_FAILED'
    assert check in attempt['failed_checks'] and not attempt['passed']
    assert attempt['close_transport'] != 'QUALIFIED_EOF'


def earlier_failed(record):
    record['protocol'][3] = {**record['protocol'][3], 'outcome': 'failed', 'error': 'CDPEOF'}


def duplicate_close(record):
    record['protocol'].append(dict(record['protocol'][-1]))


def incomplete_runtime(record):
    record['runtime_measurement'] = {'state': 'INCOMPLETE', 'digest_complete': False}


def mismatched_runtime(record):
    record['runtime_measurement'] = {'state': 'MISMATCH', 'digest_complete': True}


def failure_path_observation(record):
    record['eof_exit_observation'] = 'EXITED'


def reply_claimed(record):
    record['close_reply'] = True


def nonzero_exit_recorded(record):
    record['exit_before_cleanup'] = -11


def settled_nonzero(record):
    record['settlement']['exit_code'] = 1


def duplicate_reply_close(record):
    record['protocol'].append({'method': 'Browser.close', 'outcome': 'passed'})


@pytest.mark.parametrize('normal,mutation,settle,check', [
    ({'close': 'eof', 'eof_on': 'Extensions.uninstall'}, None, None, 'protocol_work'),
    ({'close': 'eof'}, earlier_failed, None, 'protocol_work'),
    ({'close': 'eof'}, duplicate_close, None, 'protocol_work'),
    ({'close': 'eof', 'exit_code': -11}, None, None, 'termination'),
    ({'close': 'eof', 'exit_code': None}, None, None, 'termination'),
    ({'close': 'eof'}, incomplete_runtime, None, 'runtime_identity'),
    ({'close': 'eof'}, mismatched_runtime, None, 'runtime_identity'),
    ({'close': 'eof'}, failure_path_observation, None, 'protocol_work'),
    ({'close': 'eof'}, reply_claimed, None, 'termination'),
    ({'close': 'eof'}, nonzero_exit_recorded, None, 'protocol_work'),
    ({'close': 'eof'}, settled_nonzero, None, 'protocol_work'),
    ({'close': 'reply'}, duplicate_reply_close, None, 'protocol_work'),
    ({'close': 'eof'}, None, {'raise': True}, 'no_failures'),
    ({'close': 'eof'}, None, {'zero_survivors': False}, 'settlement')])
def test_live_qualified_eof_negatives(world, capsys, normal, mutation, settle, check):
    _, summary = live_pair(world, capsys, normal=normal, mutate_normal=mutation, settle=settle)
    attempt = summary['attempts']['normal']
    assert check in attempt['failed_checks'] and not attempt['passed'], attempt['failed_checks']
    assert summary['label'] == 'CHROME_PAIR_FAILED' and summary['attempts']['abnormal']['result'] == 'ABSENT'
    # The raw transport record is never rewritten into a pass.
    assert all(m.get('outcome') != 'passed' or m.get('method') != 'Browser.close' or 'error' not in m
               for m in attempt['protocol'])


def test_live_storage_scope_and_registry_failures_fail_the_pair(world, capsys):
    _, summary = live_pair(world, capsys, normal={'registry_retained': 'disabled'})
    attempt = summary['attempts']['normal']
    assert {'native_predicate', 'useful_work', 'no_failures'} <= set(attempt['failed_checks'])
    assert attempt['extension_registry'] == ['LISTED_ENABLED', 'LISTED_DISABLED']
    assert attempt['extension_uninstall_replied'] is True and attempt['extension_registry_absent'] is None
    assert attempt['failures']['primary_failure']['code'] == 'EXTENSION_REGISTRY_RETAINED'


def test_abnormal_eof_close_is_never_qualified(world, capsys):
    bind, path, digest = startup_summary(world, capsys)
    pair_root(world)
    record = world.good('abnormal')
    record['protocol'].append(dict(QUALIFIED))
    record.update(quit_observed='qualified-eof', close_reply=False, exit_before_cleanup=0,
                  browser_close_requested=True,
                  settlement={'exit_code': 0, 'workload_status': 'exited', 'zero_survivors': True,
                              'unsettled': False, 'failures': []})
    world.results['abnormal'] = record
    world.run('pair', bind, ['--startup-summary', str(path), '--startup-summary-sha256', digest])
    attempt = world.summary()['attempts']['abnormal']
    assert {'protocol_work', 'termination'} <= set(attempt['failed_checks'])
    assert attempt['close_transport'] == 'UNQUALIFIED'


def test_reference_bind_requires_identity_equality(world, capsys, tmp_path):
    first, digest = world.bind(capsys)
    reference = tmp_path / 'reference-bind.json'
    reference.write_bytes(first.read_bytes())
    assert world.m.main(['bind', *world.common(), '--reference-bind', str(reference),
                         '--reference-bind-sha256', digest]) == 0
    out = json.loads(capsys.readouterr().out)
    record = json.loads((world.root / out['bind']).read_text())
    assert record['reference_bind_sha256'] == digest and str(reference) not in json.dumps(record)
    assert reference.read_bytes() == first.read_bytes()
    with pytest.raises(Exception, match='is not the supplied record'):
        world.m.main(['bind', *world.common(), '--reference-bind', str(reference),
                      '--reference-bind-sha256', '0' * 64])
    with pytest.raises(Exception, match='needs its SHA-256'):
        world.m.main(['bind', *world.common(), '--reference-bind', str(reference)])
    changed = json.loads(reference.read_text())
    changed['identity']['policy_template_sha256'] = '0' * 64
    raw = json.dumps(changed).encode()
    reference.write_bytes(raw)
    with pytest.raises(Exception, match='differs from the reference bind record'):
        world.m.main(['bind', *world.common(), '--reference-bind', str(reference),
                      '--reference-bind-sha256', hashlib.sha256(raw).hexdigest()])
    assert sorted(p.name for p in world.root.glob('BIND-*')) == ['BIND-001.json', 'BIND-002.json']
    assert world.launches == [] and world.claims() == []


def test_collect_never_launches_or_overwrites(world, capsys):
    bind = world.bind(capsys)
    world.run('startup', bind)
    first = (world.root / 'SUMMARY-001.json').read_bytes()
    launches = len(world.launches)
    assert world.m.main(['collect', '--claim-root', str(world.root)]) == 0
    assert (world.root / 'SUMMARY-001.json').read_bytes() == first
    assert (world.root / 'SUMMARY-002.json').exists() and len(world.launches) == launches


def test_collect_requires_a_claim(world):
    with pytest.raises(Exception, match='No Chrome claim to collect'):
        world.m.main(['collect', '--claim-root', str(world.root)])


def test_no_default_operation(world, capsys):
    with pytest.raises(SystemExit):
        world.m.main(['run', *world.common(), '--bind-record', 'x', '--bind-record-sha256', 'y'])
    capsys.readouterr()


def test_predicted_template_is_portless_chrome_policy(world, monkeypatch, tmp_path):
    import cnt_confinement
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    run = tmp_path / 'predicted-run'
    run.mkdir()
    captured = {}
    def fake_policy(run_, roots, services, port, **kw):
        captured.update(roots=roots, services=services, port=port, **kw)
        return POLICY.format(run=run_)
    monkeypatch.setattr(world.m, 'policy', fake_policy)
    template = world.m.predicted(run, [Path('/nix/store/b-chrome')], [Path('/nix/store/a-python'),
                                                                     Path('/nix/store/b-chrome')])
    assert template == world.template
    assert captured == {'roots': [Path('/nix/store/a-python'), Path('/nix/store/b-chrome')],
                        'services': SERVICES, 'port': None, 'firefox_child_ipc': False}



# ---- R5-CHROME-C1A lane ---------------------------------------------------------------------

def c1a_startup(world, capsys):
    bind = world.c1a_bind(capsys)
    assert world.run('startup', bind, C1A) == 0
    out = json.loads(capsys.readouterr().out)
    return bind, world.root / out['summary'], out['sha256']


def test_c1a_bind_records_the_single_authorized_delta(world, capsys):
    with pytest.raises(Exception, match='requires the baseline reference bind record'):
        world.m.main(['bind', *world.common(), *C1A])
    path, digest = world.c1a_bind(capsys)
    record = json.loads(path.read_text())
    reference = json.loads(world.reference[0].read_text())
    assert record['schema'] == 'bux-r5-chrome-c1a-bind-v1' and reference['schema'] == 'bux-r5-chrome-bind-v1'
    identity = record['identity']
    assert identity['policy_template_sha256'] == world.c1a_template != reference['identity']['policy_template_sha256']
    assert identity['baseline_policy_template_sha256'] == reference['identity']['policy_template_sha256']
    assert identity['chrome_rendezvous'] == 'OWN_WORKLOAD_PID'
    assert {k: v for k, v in identity.items() if k in world.m.IDENTITY and k != 'policy_template_sha256'} == {
        k: v for k, v in reference['identity'].items() if k != 'policy_template_sha256'}
    assert record['reference_bind_sha256'] == world.reference[1]
    assert record['reference_delta'] == {'kind': 'CHROME_RENDEZVOUS_OWN_WORKLOAD_PID_RULE',
                                         'rule_sha256': hashlib.sha256(RULE.encode()).hexdigest(),
                                         'baseline_equals_reference': True, 'other_identity_equal': True}
    assert hashlib.sha256(world.reference[0].read_bytes()).hexdigest() == world.reference[1]
    assert world.launches == [] and world.claims() == [] and str(world.tmp) not in path.read_text()
    predict = [a for a in world.spawned if 'predict' in a]
    assert '--chrome-rendezvous' not in predict[0] and predict[1][-2:] == C1A


def rewrite(path, change):
    value = json.loads(path.read_text())
    change(value)
    raw = json.dumps(value).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('case', ['executable-drift', 'closure-drift', 'services-drift', 'reference-template',
                                  'reference-is-c1a', 'reference-extra-key', 'reference-schema',
                                  'new-equals-reference', 'baseline-differs'])
def test_c1a_bind_refuses_everything_but_the_one_rule(world, capsys, case):
    reference, digest = world.bind(capsys)
    copy = world.tmp / 'reference.json'
    copy.write_bytes(reference.read_bytes())
    if case == 'executable-drift':
        digest = rewrite(copy, lambda v: v['identity'].update(executable_sha256='0' * 64))
    elif case == 'closure-drift':
        digest = rewrite(copy, lambda v: v['identity'].update(closure_count=4))
    elif case == 'services-drift':
        digest = rewrite(copy, lambda v: v['identity'].update(services=SERVICES[:1]))
    elif case == 'reference-template':
        digest = rewrite(copy, lambda v: v['identity'].update(policy_template_sha256='0' * 64))
    elif case == 'reference-is-c1a':
        digest = rewrite(copy, lambda v: (v.update(schema='bux-r5-chrome-c1a-bind-v1'),
                                         v['identity'].update(chrome_rendezvous='OWN_WORKLOAD_PID')))
    elif case == 'reference-extra-key':
        digest = rewrite(copy, lambda v: v['identity'].update(chrome_rendezvous='NOT_SELECTED'))
    elif case == 'reference-schema':
        digest = rewrite(copy, lambda v: v.update(schema='bux-r5-chrome-bind-v0'))
    elif case == 'new-equals-reference':
        world.c1a_template = world.template
    elif case == 'baseline-differs':
        world.c1a_baseline = '1' * 64
    with pytest.raises(Exception, match='beyond the rendezvous rule'):
        world.m.main(['bind', *world.common(), *C1A, '--reference-bind', str(copy), '--reference-bind-sha256', digest])
    assert sorted(p.name for p in world.root.glob('BIND-*')) == ['BIND-001.json']
    assert world.launches == [] and world.claims() == []


def test_generic_reference_still_refuses_the_c1a_policy(world, capsys):
    path, digest = world.c1a_bind(capsys)
    # A C1A record used as a generic baseline reference is an ordinary policy/identity difference.
    with pytest.raises(Exception, match='differs from the reference bind record'):
        world.m.main(['bind', *world.common(), '--reference-bind', str(path), '--reference-bind-sha256', digest])


@pytest.mark.parametrize('bound,selected', [('baseline', True), ('c1a', False)])
def test_lanes_never_mix_before_the_claim(world, capsys, bound, selected):
    bind = world.bind(capsys) if bound == 'baseline' else world.c1a_bind(capsys)
    with pytest.raises(Exception, match='lane differs'):
        world.run('startup', bind, C1A if selected else ())
    assert world.launches == [] and world.claims() == [] and not (world.root / 'CHROME.claim').exists()


def test_c1a_startup_runs_prerequisites_pid_check_then_one_launch(world, capsys):
    old = world.tmp / 'bux-r5-chrome-startup.claim'
    old.write_text('{"consumed": "elsewhere"}\n')
    bind = world.c1a_bind(capsys)
    world.spawned.clear()
    assert world.run('startup', bind, C1A) == 0
    summary = world.summary()
    kinds = ['pytest' if '-m' in a else 'pid-check' if 'pid-check' in a else 'predict' if 'predict' in a
             else 'launch' for a in world.spawned]
    assert kinds == ['predict', 'pytest', 'pytest', 'pid-check', 'launch']
    assert world.spawned[3][3:] == ['pid-check', '--root', str(world.root / 'pid-check'), '--runtime',
                                    str(world.runtime)]
    argv = world.launches[0][1]
    assert argv[-2:] == C1A and argv[argv.index('--workload') + 1] == 'empty'
    assert summary['label'] == 'CHROME_C1A_STARTUP_DIAGNOSTIC_COMPLETED' and summary['lane'] == 'C1A_OWN_WORKLOAD_PID'
    assert summary['schema'] == 'bux-r5-chrome-c1a-summary-v1' and summary['pid_check']['passed'] is True
    assert summary['pid_check']['undefined_parameter'] == {'state': 'REFUSED_BEFORE_PROGRAM', 'exit_code': 65,
                                                           'log_sha256': 'a' * 64, 'log_bytes': 40}
    attempt = summary['attempts']['startup']
    assert attempt['passed'] and attempt['c1a_outcome'] == 'NORMAL_CLOSE'
    assert attempt['policy']['launch_template_without_rendezvous_matches_baseline'] is True
    assert attempt['rendezvous']['launch']['state'] == 'MATCHED_WORKLOAD'
    assert world.claims() == ['bux-r5-chrome-c1a-startup.claim', 'bux-r5-chrome-startup.claim']
    assert old.read_text() == '{"consumed": "elsewhere"}\n'
    assert summary['claim']['launch_options']['startup'][-2:] == C1A
    raw = (world.root / 'SUMMARY-001.json').read_text()
    assert '4242' not in raw and str(world.tmp) not in raw
    world.root = world.tmp / 'second'
    world.root.mkdir()
    with pytest.raises(Exception, match='Operation already claimed on this host'):
        world.run('startup', bind, C1A)
    assert len(world.launches) == 1


def drop(key):
    def change(value):
        value.pop(key)
        return value
    return change


@pytest.mark.parametrize('mutation,check', [
    (lambda v: dict(v, status='BLOCKED'), 'canaries_passed'),
    (lambda v: dict(v, rendezvous_canary=dict(MATCHED, state='PID_MISMATCH', workload_pid_matches=False)),
     'own_pid_parameter'),
    (lambda v: dict(v, rendezvous_canary=dict(MATCHED)), 'own_pid_parameter'),  # sandboxed report absent
    (lambda v: dict(v, policy_template_sha256='0' * 64), 'template_matches_bind'),
    (lambda v: dict(v, policy_template_without_rendezvous_sha256=None), 'baseline_matches_bind'),
    (lambda v: dict(v, undefined_parameter={'state': 'PROGRAM_RAN_WITHOUT_PARAMETER'}), 'undefined_parameter_refused'),
    (lambda v: dict(v, undefined_parameter={'state': 'NOT_RUN_CANARY_FAILED'}), 'undefined_parameter_refused'),
    (lambda v: dict(v, settlement=dict(v['settlement'], zero_survivors=False)), 'settled'),
    (drop('rendezvous_canary'), 'own_pid_parameter'),
    (lambda v: 'not json', 'canaries_passed'),
    (lambda v: ' ' * 20000, 'canaries_passed')])  # oversized output is a failed check, not a runner error
def test_c1a_pid_check_failure_never_launches(world, capsys, mutation, check):
    bind = world.c1a_bind(capsys)
    world.pid_check_mutation = mutation
    world.run('startup', bind, C1A)
    summary = world.summary()
    assert world.launches == [] and summary['label'] == 'CHROME_C1A_PID_CHECK_FAILED'
    assert summary['claim']['phase'] == 'PID_CHECK_FAILED' and check in summary['pid_check']['failed_checks']
    assert summary['attempts']['startup']['result'] == 'ABSENT'
    assert world.claims() == ['bux-r5-chrome-c1a-startup.claim']


def test_c1a_pid_check_nonzero_exit_never_launches(world, capsys):
    bind = world.c1a_bind(capsys)
    world.pid_check_code = 1
    world.run('startup', bind, C1A)
    assert world.launches == [] and 'returned_zero' in world.summary()['pid_check']['failed_checks']


def test_c1a_pid_check_interrupt_is_retained_without_launch(world, capsys):
    bind = world.c1a_bind(capsys)
    world.pid_check_interrupt = True
    world.run('startup', bind, C1A)
    summary = world.summary()
    assert world.launches == [] and summary['label'] == 'CHROME_C1A_INCOMPLETE_INTERRUPTED'
    assert summary['claim']['phase'] == 'INTERRUPTED_RETAINED' and summary['claim']['interrupted'] is True


def test_c1a_prerequisite_failure_precedes_pid_check(world, capsys):
    bind = world.c1a_bind(capsys)
    world.pytest_line = '14 passed, 1 failed in 3.00s'
    world.run('startup', bind, C1A)
    assert not any('pid-check' in a for a in world.spawned) and world.launches == []
    assert world.summary()['label'] == 'CHROME_C1A_PREREQUISITE_FAILED'


@pytest.mark.parametrize('name', ['pid-check', 'pid-check-rendezvous', 'pid-check-outside-canary',
                                  'startup-rendezvous', 'startup-outside-canary', 'normal-rendezvous'])
def test_c1a_leftovers_refuse_before_the_claim(world, capsys, name):
    bind = world.c1a_bind(capsys)
    (world.root / name).mkdir()
    with pytest.raises(Exception, match='Attempt directory present'):
        world.run('startup', bind, C1A)
    assert world.claims() == [] and not (world.root / 'CHROME.claim').exists()


def set_state(section, key, value):
    def change(record):
        target = record['preflight'] if section == 'preflight' else record
        if value is KeyError:
            target.pop(key, None)
        else:
            target[key] = value
    return change


def rendezvous_state(section, state, **facts):
    key = 'rendezvous_canary' if section == 'preflight' else 'rendezvous_parameter'
    base = dict(MATCHED, sandboxed_pid_matches=True) if section == 'preflight' else dict(MATCHED)
    return set_state(section, key, dict(base, state=state, **facts))


@pytest.mark.parametrize('mutation,checks,outcome', [
    (None, [], 'NORMAL_CLOSE'),
    (set_state('record', 'chrome_rendezvous', 'NOT_SELECTED'), ['selected_configuration'], 'RENDEZVOUS_NOT_SELECTED'),
    (set_state('preflight', 'chrome_rendezvous', KeyError), ['selected_configuration'], 'OTHER_FAILURE'),
    (rendezvous_state('preflight', 'INVALID_PARAMETER'), ['rendezvous_parameter'], 'RENDEZVOUS_INVALID_PARAMETER'),
    (rendezvous_state('record', 'HELPER_REFUSED'), ['rendezvous_parameter'], 'RENDEZVOUS_HELPER_OR_EXEC_FAILED'),
    (rendezvous_state('record', 'EXEC_FAILED'), ['rendezvous_parameter'], 'RENDEZVOUS_HELPER_OR_EXEC_FAILED'),
    (rendezvous_state('record', 'RECORD_ABSENT'), ['rendezvous_parameter'], 'RENDEZVOUS_HELPER_OR_EXEC_FAILED'),
    (rendezvous_state('record', 'PID_MISMATCH', workload_pid_matches=False), ['rendezvous_parameter'],
     'RENDEZVOUS_PID_MISMATCH'),
    (rendezvous_state('preflight', 'SANDBOXED_PID_UNOBSERVED', sandboxed_pid_matches=None),
     ['rendezvous_parameter'], 'RENDEZVOUS_CANARY_REFUSED'),
    (set_state('preflight', 'status', 'BLOCKED'), ['rendezvous_parameter'], 'RENDEZVOUS_CANARY_REFUSED'),
    (set_state('preflight', 'rendezvous_canary', KeyError), ['rendezvous_parameter'], 'OTHER_FAILURE'),
    (rendezvous_state('record', 'WORKLOAD_UNOBSERVED', workload_pid_matches=None), ['rendezvous_parameter'],
     'RENDEZVOUS_UNOBSERVED'),
    (lambda r: r.update(ready=False, cdp_stage='startup', status='DIAGNOSTIC_FAILED',
                        primary_failure={'stage': 'browser', 'code': 'CDP_EOF'}),
     ['native_predicate', 'no_failures', 'useful_work'], 'PRE_CDP_FAILURE'),
    (lambda r: r.update(ready=False, cdp_stage='startup', status='DIAGNOSTIC_FAILED',
                        primary_failure={'stage': 'browser', 'code': 'CDP_METHOD_UNAVAILABLE'}),
     ['native_predicate', 'no_failures', 'useful_work'], 'CDP_UNSUPPORTED'),
    (lambda r: r['settlement'].update(zero_survivors=False), ['settlement'], 'OWNED_CLEANUP_FAILED'),
    (lambda r: r['settlement'].update(observed_escapes=1, zero_survivors=False, unsettled=True), ['settlement'],
     'OWNED_CLEANUP_FAILED'),
    (lambda r: r.update(cleanup_failure={'stage': 'cleanup', 'type': 'TimeoutExpired'}), ['no_failures'],
     'OWNED_CLEANUP_FAILED')])
def test_c1a_conjuncts_and_outcome_labels(world, capsys, mutation, checks, outcome):
    bind = world.c1a_bind(capsys)
    record = world.good('startup')
    world.c1a_facts(record)
    if mutation:
        mutation(record)
    world.results['startup'] = record
    world.run('startup', bind, C1A)
    attempt = world.summary()['attempts']['startup']
    assert attempt['c1a_outcome'] == outcome
    assert set(checks) <= set(attempt['failed_checks']) and attempt['passed'] is (not checks and outcome == 'NORMAL_CLOSE')


def test_c1a_launch_policy_must_be_the_baseline_plus_the_rule(world, capsys):
    bind = world.c1a_bind(capsys)
    def strip(role):
        path = world.root / role / 'confinement.sb'
        path.write_text(path.read_text().replace(RULE, ''))
    world.after_launch = strip
    world.run('startup', bind, C1A)
    attempt = world.summary()['attempts']['startup']
    assert 'policy' in attempt['failed_checks']
    assert attempt['policy']['launch_template_without_rendezvous_matches_baseline'] is False


@pytest.mark.parametrize('mutation', [set_state('record', 'chrome_rendezvous', KeyError),
                                      set_state('record', 'chrome_rendezvous', 'OWN_WORKLOAD_PID'),
                                      set_state('record', 'rendezvous_parameter', dict(MATCHED)),
                                      set_state('preflight', 'rendezvous_canary', dict(MATCHED))])
def test_baseline_summary_refuses_rendezvous_or_pre_c1a_records(world, capsys, mutation):
    bind = world.bind(capsys)
    record = world.good('startup')
    mutation(record)
    world.results['startup'] = record
    world.run('startup', bind)
    attempt = world.summary()['attempts']['startup']
    assert 'selected_configuration' in attempt['failed_checks'] and 'c1a_outcome' not in attempt


def test_c1a_pair_requires_a_c1a_startup(world, capsys):
    bind, path, digest = startup_summary(world, capsys)
    # A baseline startup summary never admits a C1A pair (its bind is not a C1A record either).
    c1a = world.c1a_bind(capsys)
    pair_root(world)
    with pytest.raises(Exception, match='completed startup diagnostic'):
        world.run('pair', c1a, [*C1A, '--startup-summary', str(path), '--startup-summary-sha256', digest])
    assert 'bux-r5-chrome-c1a-pair.claim' not in world.claims()


def test_c1a_pair_runs_pid_check_then_normal_then_abnormal(world, capsys):
    bind, path, digest = c1a_startup(world, capsys)
    pair_root(world)
    world.spawned.clear()
    assert world.run('pair', bind, [*C1A, '--startup-summary', str(path), '--startup-summary-sha256', digest]) == 0
    summary = world.summary()
    assert summary['label'] == 'CHROME_C1A_USEFUL_PAIR_PASSED_PENDING_MANAGER_REVIEW'
    assert [r for r, _ in world.launches] == ['startup', 'normal', 'abnormal']
    assert summary['attempts']['abnormal']['c1a_outcome'] == 'INTENDED_ABNORMAL_TIMEOUT'
    assert summary['attempts']['normal']['c1a_outcome'] == 'NORMAL_CLOSE'
    assert world.claims() == ['bux-r5-chrome-c1a-pair.claim', 'bux-r5-chrome-c1a-startup.claim']
    assert sum('pid-check' in a for a in world.spawned) == 1


def test_c1a_collect_never_launches(world, capsys):
    c1a_startup(world, capsys)
    launches, spawned = len(world.launches), len(world.spawned)
    assert world.m.main(['collect', '--claim-root', str(world.root)]) == 0
    assert len(world.launches) == launches and len(world.spawned) == spawned
    assert world.summary('SUMMARY-002.json')['label'] == 'CHROME_C1A_STARTUP_DIAGNOSTIC_COMPLETED'


@pytest.mark.parametrize('pid,outcome', [(4242, 'NORMAL_CLOSE'), (4343, 'RENDEZVOUS_PID_MISMATCH')])
def test_c1a_live_launch_observes_the_helper_record(world, capsys, pid, outcome):
    world.live['startup'] = {'close': 'eof', 'c1a': True, 'pid': pid}
    bind = world.c1a_bind(capsys)
    world.run('startup', bind, C1A)
    attempt = world.summary()['attempts']['startup']
    assert attempt['c1a_outcome'] == outcome
    assert attempt['rendezvous']['launch']['state'] == ('MATCHED_WORKLOAD' if pid == 4242 else 'PID_MISMATCH')
    assert attempt['passed'] is (pid == 4242)


def test_predicted_c1a_is_the_baseline_plus_one_rule(world, monkeypatch, tmp_path):
    import cnt_confinement, cnt_chrome_rendezvous as rv
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    run = tmp_path / 'predicted-run'
    root = run / 'runtime'
    (root / 'Applications/Google Chrome.app/Contents/MacOS').mkdir(parents=True)
    monkeypatch.setattr(rv, 'STORE', str(run))
    executable = root / 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    baseline = world.m.predicted(run, [root], [])
    value = world.m.predicted_c1a(run, [root], [], executable, baseline)
    assert value['baseline_policy_template_sha256'] == baseline != value['policy_template_sha256']
    with pytest.raises(Exception, match='baseline plus exactly the one rule'):
        world.m.predicted_c1a(run, [root], [], executable, '0' * 64)


def test_pid_check_child_runs_only_the_canary_and_the_undefined_parameter_check(world, monkeypatch, capsys):
    import cnt_confinement
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', world.tmp)
    monkeypatch.setattr(world.preflight, 'runtime_roots', lambda path: [Path('/nix/store/x-' + path.name)])
    calls, negative = [], []
    def probe(run, python, roots, outside, port, services, **kw):
        calls.append(dict(kw, services=services, outside=outside))
        kw['evidence'].update(status='CANARIES_PASSED_NOT_BROWSER_QUALIFICATION', policy_template_sha256='t',
                              policy_template_without_rendezvous_sha256='b',
                              settlement={'exit_code': 0, 'zero_survivors': True, 'unsettled': False,
                                          'failures': []},
                              rendezvous_canary=dict(MATCHED, sandboxed_pid_matches=True, private='/x'))
    monkeypatch.setattr(cnt_confinement, 'run_probe', probe)
    monkeypatch.setattr(world.m, 'undefined_parameter', lambda run, python: negative.append(run) or
                        {'state': 'REFUSED_BEFORE_PROGRAM', 'exit_code': 65, 'clean_settlement': True})
    root = world.root / 'pid-check'
    assert world.m.main(['pid-check', '--root', str(root), '--runtime', str(world.runtime)]) == 0
    out = json.loads(capsys.readouterr().out)
    kw = calls[0]
    assert kw['chrome_rendezvous'] is True and kw['automation_port'] is None and kw['firefox_child_ipc'] is False
    assert kw['chrome_executable'] == world.runtime / 'Contents/MacOS/Google Chrome' == kw['firefox_executable']
    evidence = world.root / 'pid-check-rendezvous'
    assert kw['rendezvous_evidence'] == evidence and evidence.stat().st_mode & 0o777 == 0o700
    assert kw['services'] == SERVICES and kw['outside'] == world.root / 'pid-check-outside-canary'
    assert negative == [root] and out['undefined_parameter']['state'] == 'REFUSED_BEFORE_PROGRAM'
    assert set(out) == {'status', 'settlement', 'rendezvous_canary', 'policy_template_sha256',
                        'policy_template_without_rendezvous_sha256', 'undefined_parameter'}
    assert 'private' not in out['rendezvous_canary'] and world.launches == []


REFUSAL_LOG = 'sandbox-exec: synthetic refusal text\n'


def test_undefined_parameter_unreadable_log_is_recorded_as_absent(world, monkeypatch, tmp_path):
    import cnt_owned_process
    class Owner:
        def __init__(self, command, run, env, log, evidence=None):
            self.returncode, self.result = 65, None
            log.write('x' * 16385)
        def until(self, predicate, timeout):
            pass
        def settle(self):
            return {'exit_code': 65, 'zero_survivors': True, 'unsettled': False}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    value = world.m.undefined_parameter(tmp_path, Path('/nix/store/p-python/bin/python3'))
    assert value['log_sha256'] is None and value['log_bytes'] is None


@pytest.mark.parametrize('bad', [{'state': 'MAYBE', 'exit_code': True, 'log_sha256': 'A' * 64, 'log_bytes': '4'},
                                 {'state': 7, 'exit_code': '65', 'log_sha256': 'a' * 63, 'log_bytes': None},
                                 {'log_sha256': '/private/path/' + 'a' * 50}])
def test_undefined_parameter_projection_is_fixed_keys_only(world, bad):
    assert world.m.project_undefined(dict(bad, private='x')) == {
        'state': None, 'exit_code': None, 'log_sha256': None, 'log_bytes': None}


@pytest.mark.parametrize('case,state', [('refused', 'REFUSED_BEFORE_PROGRAM'), ('ran', 'PROGRAM_RAN_WITHOUT_PARAMETER'),
                                        ('zero', 'UNCLASSIFIED'), ('timeout', 'UNCLASSIFIED'),
                                        ('unsettled', 'UNCLASSIFIED')])
def test_undefined_parameter_classification(world, monkeypatch, tmp_path, case, state):
    import cnt_owned_process
    commands = []
    class Owner:
        def __init__(self, command, run, env, log, evidence=None):
            commands.append(command)
            self.returncode = {'refused': 65, 'ran': 0, 'zero': 0, 'timeout': None, 'unsettled': 65}[case]
            self.result = None
            if case == 'ran':
                (run / 'undefined-parameter-ran').write_text('')
            log.write(REFUSAL_LOG)
            log.flush()
        def until(self, predicate, timeout):
            if case == 'timeout':
                raise RuntimeError('Owned workload timeout')
        def settle(self):
            return {'exit_code': self.returncode, 'zero_survivors': case != 'unsettled', 'unsettled': case == 'unsettled'}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    value = world.m.undefined_parameter(tmp_path, Path('/nix/store/p-python/bin/python3'))
    assert value['state'] == state
    # The private log stays in the run; only its digest and size leave it, never as a gate.
    assert value['log_sha256'] == hashlib.sha256(REFUSAL_LOG.encode()).hexdigest()
    assert value['log_bytes'] == len(REFUSAL_LOG)
    assert commands[0][:3] == ['/usr/bin/sandbox-exec', '-f', str(tmp_path / 'confinement.sb')]
    assert '-D' not in commands[0] and not any('RENDEZVOUS' in a for a in commands[0])
