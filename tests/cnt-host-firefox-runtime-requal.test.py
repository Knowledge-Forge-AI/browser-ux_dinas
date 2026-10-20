"""R6 Firefox 156.0.1 requalification runner contracts: every subprocess is faked.

No browser, codesign, Nix, pytest child, captured code, installed runtime or host scratch is used.
"""
import ast
import hashlib
import json
from pathlib import Path
import plistlib
import re

import pytest

CANDIDATE = {'version': '156.0.1', 'bundle_identifier': 'org.mozilla.firefox', 'bundle_version': '15626.9.21',
             'build_id': '20260921121718',
             'runtime_sha256': '35172d4e392575860ed48cd7e7a45a6eb1a59eacdfef277aced6c5610bbcdab3',
             'executable_sha256': 'f2559282d3ef1ceeb0083700e57092c905f043eddb02a9b8ac09009ec9719ac3',
             'signature_original': True}
D1_RUNTIME = '6555cd15eb85f2be816fede570f252d5e7154c1c4ecfda372f00f19cc0596f7d'
D1_EXECUTABLE = 'ca4f2108d1000fce089d4c5ace30565f489dfce8d2d98c89b355e7c3ebc40462'
TEMPLATE = 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'
WITHOUT_CONFIGD = '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'
SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd',
            'com.apple.SystemConfiguration.configd']
EXCEPTIONS = ['content', 'socket', 'utility-generic']
HOST_CLAIM = 'bux-r6-firefox-15601-requal.claim'
MALFORMED_D = 'bux-r6-firefox-native-matrix-malformed-d.claim'
COMPAT_E = 'bux-r6-firefox-native-matrix-compat-e.claim'
MULTIPART_B = 'bux-r6-firefox-native-matrix-multipart-b.claim'
LABEL = 'R6_FIREFOX_15601_REQUAL_'
PORT = 50123
RUNNER = 'tests/cnt_host_firefox_runtime_requal.py'
DOC = 'docs/architecture/clear-new-tab-durable-authority.md'
PLIST = {'CFBundleIdentifier': 'org.mozilla.firefox', 'CFBundleShortVersionString': '156.0.1',
         'CFBundleVersion': '15626.9.21', 'CFBundleExecutable': 'firefox'}
INI = '[App]\nVendor=Mozilla\nName=Firefox\nVersion=156.0.1\nBuildID=20260921121718\n'


def result(role):
    """A synthetic result.json as the preflight records a passing full trusted-synthetic attempt."""
    normal = role == 'normal'
    methods = ['WebDriver:NewSession', 'WebDriver:Navigate', 'Addon:Install', 'Addon:Uninstall']
    r = {'status': 'SYNTHETIC_ATTEMPT_PASSED', 'engine': 'firefox', 'workload': 'full', 'abnormal': not normal,
         'diagnostic_only': False, 'browser_launched': True, 'captured_code_loaded': False,
         'shutdown_trace': False, 'shutdown_observer': False, 'crash_force_enable': False,
         'crash_readback': False, 'parent_probes': False, 'native_semantics': 'NOT_EXECUTED',
         'sandbox_disables': list(EXCEPTIONS), 'mach_services': list(SERVICES), 'configd_compatibility': True,
         'ready': True, 'page_nonce': True, 'extension_installed': True, 'extension_origin_verified': True,
         'extension_nonce': True, 'extension_unloaded': True,
         'runtime_preparation_complete': True, 'runtime_unchanged': True,
         'runtime_measurement': {'state': 'MATCH', 'digest_complete': True, 'operation': 'digest-comparison',
                                 'code': None, 'entries_enumerated': 9, 'entries_measured': 9},
         'runtime_source_sha256': CANDIDATE['runtime_sha256'], 'runtime_snapshot_sha256': CANDIDATE['runtime_sha256'],
         'runtime_observed_sha256': CANDIDATE['runtime_sha256'],
         'executable_sha256': CANDIDATE['executable_sha256'], 'signature': {'original': True, 'frozen': True},
         'browser_version': '156.0.1', 'environment_names': ['HOME', 'TMPDIR'],
         'preflight': {'status': 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION', 'policy_template_sha256': TEMPLATE,
                       'policy_sha256': 'c' * 64, 'automation_port': PORT},
         'listener_samples': [{'owned': True, 'tcp_listeners': [f'127.0.0.1:{PORT}']}],
         'protocol': [{'method': m, 'outcome': 'reply'} for m in methods],
         'settlement': {'exit_code': 0 if normal else -15, 'workload_status': 'exited', 'observed_process_count': 2,
                        'observed_escapes': 0, 'survivors': [], 'zero_survivors': True, 'unsettled': False,
                        'failures': []}}
    if normal:
        r.update(quit_observed='reply', exit_before_cleanup=0)
        r['protocol'].append({'method': 'Marionette:Quit', 'outcome': 'reply'})
    else:
        r.update(intended_timeout=True, exit_before_cleanup=None)
    return r


class Proc:
    def __init__(self, code, interrupts=0):
        self.code, self.interrupts = code, interrupts

    def wait(self):
        if self.interrupts:
            self.interrupts -= 1
            raise KeyboardInterrupt
        return self.code

    def kill(self):
        raise AssertionError('never killed')

    terminate = kill


class World:
    def __init__(self, m, tmp_path, monkeypatch):
        import cnt_host_d2 as d2
        from source_only_snapshot import collect
        self.m, self.d2, self.tmp, self.mp = m, d2, tmp_path, monkeypatch
        self.production = m.production
        self.scratch = tmp_path / 'scratch'
        self.scratch.mkdir()
        monkeypatch.setattr(d2, 'SCRATCH', self.scratch)
        self.snapshot = self.scratch / 'snapshot'
        (self.snapshot / 'tests').mkdir(parents=True)
        names = [RUNNER, 'tests/cnt_host_d2.py', 'tests/cnt-native-preflight.py', 'tests/cnt_host_firefox_matrix.py']
        for name in names:
            (self.snapshot / name).write_text('synthetic ' + name + '\n')
        entries = {n: r for n, (r, _) in collect(self.snapshot, names).items()}
        self.inventory_sha = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'))
                                            .encode()).hexdigest()
        self.inventory = self.scratch / 'snapshot-inventory.json'
        self.inventory.write_text(json.dumps({'sha256': self.inventory_sha, 'entries': entries}))
        monkeypatch.setattr(m, 'RUNNER', self.snapshot / RUNNER)
        monkeypatch.setattr(d2, 'RUNNER', self.snapshot / 'tests/cnt_host_d2.py')
        monkeypatch.setattr(self.production, 'RUNNER', self.snapshot / 'tests/cnt_host_firefox_matrix.py')
        # A synthetic installed candidate: real Info.plist and application.ini, synthetic executable.
        self.app = tmp_path / 'Applications/Firefox.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        (self.app / 'Contents/Resources').mkdir()
        (self.app / 'Contents/MacOS/firefox').write_bytes(b'synthetic executable')
        self.write_plist(PLIST)
        self.write_ini(INI)
        self.tree, self.executable, self.events = CANDIDATE['runtime_sha256'], CANDIDATE['executable_sha256'], []
        monkeypatch.setattr(d2, 'tree_digest', self.tree_digest)
        monkeypatch.setattr(m, 'executable_digest', lambda runtime: self.executable)
        self.real_signature = m.signature
        monkeypatch.setattr(m, 'signature', lambda runtime: True)
        self.prediction = {'policy_template_sha256': TEMPLATE, 'policy_template_without_configd_sha256': WITHOUT_CONFIGD,
                           'pytest_version': '9.0.0'}
        monkeypatch.setattr(d2, 'predicted_template', lambda python, env, root: dict(self.prediction))
        self.delta = {'status': 'READ', 'd1_template_match': True, 'launch_policy_matches_preflight': True,
                      'configd_rule_count': 1}
        monkeypatch.setattr(d2, 'policy_delta', lambda attempt, preflight: dict(self.delta))
        monkeypatch.setattr(m, 'free_bytes', lambda root: m.MIN_FREE_BYTES)
        self.python = tmp_path / 'store/python-env/bin/python3'
        self.nix_bin = tmp_path / 'store/nix/bin'
        self.nix_bin.mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text('')
        (self.nix_bin / 'nix-store').write_text('')
        (self.nix_bin / 'nix-store').chmod(0o755)
        monkeypatch.setattr(d2, 'STORE', tmp_path / 'store')
        self.root = self.scratch / 'claim'
        self.root.mkdir()
        self.spawned, self.edits, self.after, self.interrupts, self.codes = [], {}, {}, {}, {}
        self.pytest_tail = {False: '15 passed in 1.0s', True: '15 passed in 1.0s'}
        self.pytest_codes = {False: 0, True: 0}
        self.pytest_interrupts = {False: 0, True: 0}
        monkeypatch.setattr(d2, 'spawn', self.spawn)
        real_exclusive = d2.exclusive

        def exclusive(path, record):
            self.events.append('claim:' + ('host' if Path(path).name == HOST_CLAIM else Path(path).name))
            return real_exclusive(path, record)
        monkeypatch.setattr(d2, 'exclusive', exclusive)

    def write_plist(self, values):
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(values))

    def write_ini(self, text):
        (self.app / 'Contents/Resources/application.ini').write_text(text)

    def tree_digest(self, root, trace=None):
        self.events.append('tree')
        return self.tree

    def spawn(self, argv, **kw):
        self.spawned.append(argv)
        if '-m' in argv and 'pytest' in argv:
            optimized = '-O' in argv
            self.events.append('pytest-O' if optimized else 'pytest')
            kw['stdout'].write(self.pytest_tail[optimized] + '\n')
            kw['stdout'].flush()
            return Proc(self.pytest_codes[optimized], self.pytest_interrupts[optimized])
        role = 'abnormal' if '--abnormal' in argv else 'normal'
        self.events.append(role)
        attempt = Path(argv[argv.index('--scratch') + 1])
        attempt.mkdir()
        value = result(role)
        self.edits.get(role, lambda r: None)(value)
        if value is not None:
            (attempt / 'result.json').write_text(json.dumps(value))
        self.after.get(role, lambda: None)()
        return Proc(self.codes.get(role, 0), self.interrupts.get(role, 0))

    def argv(self, command, root=None, **extra):
        values = ['--snapshot', str(self.snapshot), '--inventory', str(self.inventory),
                  '--runtime', str(self.app), '--python', str(self.python), '--nix-bin', str(self.nix_bin),
                  '--claim-root', str(root or self.root), '--expected-inventory-sha256', self.inventory_sha]
        for key, value in extra.items():
            values += ['--' + key.replace('_', '-'), value]
        return [command] + values

    def bind(self, root=None):
        assert self.m.main(self.argv('bind', root)) == 0
        path = sorted((root or self.root).glob('BIND-*.json'))[-1]
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def run(self, root=None):
        path, digest = self.bind(root)
        self.events.clear()
        return self.m.main(self.argv('run', root, bind_record=str(path), bind_record_sha256=digest))

    def launched(self):
        return [e for e in self.events if e in ('pytest', 'pytest-O', 'normal', 'abnormal')]

    def state(self):
        return json.loads((self.root / 'REQUAL-state.json').read_text())

    def summary(self, root=None):
        return json.loads(sorted((root or self.root).glob('REQUAL-SUMMARY-*.json'))[-1].read_text())

    def no_side_effects(self):
        assert self.spawned == [] and not list(self.root.glob('BIND-*.json'))
        assert not (self.scratch / HOST_CLAIM).exists() and not (self.root / 'REQUAL.claim').exists()


@pytest.fixture
def w(load_module, monkeypatch, tmp_path, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_host_firefox_runtime_requal as m
    return World(m, tmp_path, monkeypatch)


def refused(w, message, *argv):
    from cnt_native_evidence import VerificationError
    with pytest.raises(VerificationError) as error:
        w.m.main(list(argv) or w.argv('bind'))
    assert str(error.value) == message
    return error


# Adopted production binding ------------------------------------------------------------------

ADOPTED = {k: v for k, v in CANDIDATE.items() if k != 'signature_original'}


def test_production_is_the_adopted_156_identity_and_d1_stays_155_history(w):
    d2, production, firefox = w.d2, w.production, w.m.firefox
    assert (d2.D1_RUNTIME, d2.D1_EXECUTABLE, d2.D1_TEMPLATE) == (D1_RUNTIME, D1_EXECUTABLE, WITHOUT_CONFIGD)
    assert firefox.IDENTITY == ADOPTED and production.firefox is firefox
    assert (production.ACCEPTED_RUNTIME, production.ACCEPTED_EXECUTABLE) == (CANDIDATE['runtime_sha256'],
                                                                             CANDIDATE['executable_sha256'])
    assert (production.ACCEPTED_TEMPLATE, production.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD) == (TEMPLATE, WITHOUT_CONFIGD)
    assert w.m.production_adopted() == {
        'binding': {'firefox': ADOPTED, 'historical_d1': {'d2.D1_RUNTIME': D1_RUNTIME, 'd2.D1_EXECUTABLE': D1_EXECUTABLE,
                                                          'd2.D1_TEMPLATE': WITHOUT_CONFIGD}},
        'version': '156.0.1', 'superseded_version': '155.0.1', 'status': 'ADOPTED'}
    assert w.m.SUPERSEDED_VERSION == '155.0.1' and set(w.m.HISTORICAL_D1.values()) == {D1_RUNTIME, D1_EXECUTABLE,
                                                                                         WITHOUT_CONFIGD}


@pytest.mark.parametrize('name', ['D1_RUNTIME', 'D1_EXECUTABLE', 'D1_TEMPLATE'])
@pytest.mark.parametrize('value', ['candidate', 'f' * 64])
def test_changed_historical_d1_constant_refuses_before_anything(w, monkeypatch, name, value):
    monkeypatch.setattr(w.d2, name, CANDIDATE['runtime_sha256'] if value == 'candidate' else value)
    refused(w, 'Historical D1 binding changed')
    w.no_side_effects()


@pytest.mark.parametrize('owner,name,value', [
    ('firefox', 'VERSION', '155.0.1'), ('firefox', 'VERSION', '156.0.2'), ('firefox', 'BUNDLE_ID', 'org.mozilla.nightly'),
    ('firefox', 'BUNDLE_VERSION', '15626.9.20'), ('firefox', 'BUILD_ID', '20260921121719'),
    ('firefox', 'RUNTIME', D1_RUNTIME), ('firefox', 'RUNTIME', 'f' * 64),
    ('firefox', 'EXECUTABLE', D1_EXECUTABLE), ('firefox', 'EXECUTABLE', 'f' * 64),
    ('firefox', 'IDENTITY', {**ADOPTED, 'version': '155.0.1'}),
    ('production', 'ACCEPTED_RUNTIME', D1_RUNTIME), ('production', 'ACCEPTED_RUNTIME', 'f' * 64),
    ('production', 'ACCEPTED_EXECUTABLE', D1_EXECUTABLE), ('production', 'ACCEPTED_EXECUTABLE', 'f' * 64),
    ('candidate', 'CANDIDATE_RUNTIME', D1_RUNTIME), ('candidate', 'CANDIDATE_EXECUTABLE', 'f' * 64),
    ('candidate', 'CANDIDATE_VERSION', '155.0.1'), ('candidate', 'CANDIDATE_BUILD_ID', '20260921121719')])
def test_production_not_exactly_the_adopted_identity_refuses(w, monkeypatch, owner, name, value):
    target = {'firefox': w.m.firefox, 'production': w.production, 'candidate': w.m}[owner]
    monkeypatch.setattr(target, name, value)
    refused(w, 'Production runtime binding is not the adopted identity')
    w.no_side_effects()


def test_production_must_alias_the_single_owner(w, monkeypatch):
    import types
    impostor = types.SimpleNamespace(**{k: getattr(w.m.firefox, k) for k in (
        'VERSION', 'BUNDLE_ID', 'BUNDLE_VERSION', 'BUILD_ID', 'RUNTIME', 'EXECUTABLE', 'IDENTITY')})
    monkeypatch.setattr(w.production, 'firefox', impostor)
    refused(w, 'Production runtime binding is not the adopted identity')
    w.no_side_effects()


def test_superseded_version_alias_refuses(w, monkeypatch):
    monkeypatch.setattr(w.m, 'SUPERSEDED_VERSION', '156.0.1')
    refused(w, 'Production runtime binding is not the adopted identity')
    w.no_side_effects()


@pytest.mark.parametrize('name,value', [('ACCEPTED_TEMPLATE', 'f' * 64), ('ACCEPTED_TEMPLATE_WITHOUT_CONFIGD', 'f' * 64),
                                        ('SERVICES', SERVICES[:2]), ('EXCEPTIONS', ['content', 'socket'])])
def test_shared_r4_policy_binding_must_equal_production(w, monkeypatch, name, value):
    monkeypatch.setattr(w.m, name, value)
    refused(w, 'Accepted R4 policy binding changed')
    w.no_side_effects()


@pytest.mark.parametrize('name,value', [('ACCEPTED_TEMPLATE', 'f' * 64), ('ACCEPTED_TEMPLATE_WITHOUT_CONFIGD', 'f' * 64),
                                        ('SERVICES', SERVICES[:2]), ('EXCEPTIONS', ['content', 'socket'])])
def test_changed_production_r4_policy_refuses(w, monkeypatch, name, value):
    monkeypatch.setattr(w.production, name, value)
    refused(w, 'Accepted R4 policy binding changed')
    w.no_side_effects()


@pytest.mark.parametrize('claim', ['bux-c9-host-pair3.claim', MALFORMED_D, 'bux-c7-host-d2.claim'])
def test_requal_claim_must_be_distinct(w, monkeypatch, claim):
    monkeypatch.setattr(w.m, 'HOST_CLAIM', claim)
    refused(w, 'Requalification claim is not distinct')
    w.no_side_effects()


def test_refused_claims_cover_every_production_claim(w, monkeypatch):
    import cnt_host_chrome as chrome
    known = {w.d2.HOST_CLAIM_NAME, *w.production.CONSUMED_HOST_CLAIMS, *w.production.UNCREATED_PROPOSED_CLAIMS,
             *(b['claim'] for b in w.production.BUDGETS.values()), *chrome.HOST_CLAIMS.values(),
             *chrome.C1A_CLAIMS.values(), 'bux-c8-host-pair2.claim', 'bux-c9-host-pair3.claim'}
    assert set(w.m.REFUSED_CLAIMS) == known and HOST_CLAIM not in known
    monkeypatch.setattr(w.production, 'UNCREATED_PROPOSED_CLAIMS', ('bux-r6-new-unlisted.claim',))
    refused(w, 'Requalification claim is not distinct')


def test_historical_d1_binder_still_binds_only_155(w):
    from cnt_native_evidence import VerificationError
    # d2.tree_digest is the World fake returning the adopted tree: the D1 binder refuses it.
    with pytest.raises(VerificationError, match='Runtime differs from the D1 runtime'):
        w.d2.bind_runtime(w.app)
    w.tree = D1_RUNTIME
    with pytest.raises(VerificationError, match='Executable differs from D1'):
        w.d2.bind_runtime(w.app)
    w.no_side_effects()


def test_consumed_requal_claim_refuses_bind_and_run_and_is_never_touched(w):
    """The host state after the accepted pair: the retained claim is unreadable here, so any open fails."""
    path, digest = w.bind()
    claim = w.scratch / HOST_CLAIM
    claim.write_text('{"consumed": "REQUAL-HOST1"}\n')
    before = claim.stat()
    claim.chmod(0)
    try:
        refused(w, 'Requalification already claimed on this host; never rerun')
        refused(w, 'Requalification already claimed on this host; never rerun',
                *w.argv('run', bind_record=str(path), bind_record_sha256=digest))
        after = claim.stat()
        assert (after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
        assert after.st_mode & 0o777 == 0
    finally:
        claim.chmod(0o600)
    assert claim.read_text() == '{"consumed": "REQUAL-HOST1"}\n'
    assert w.spawned == [] and not (w.root / 'REQUAL.claim').exists() and not (w.scratch / MALFORMED_D).exists()


# Exact candidate binding ----------------------------------------------------------------------

def test_bind_accepts_only_the_exact_candidate_and_launches_nothing(w):
    path, _ = w.bind()
    record = json.loads(path.read_text())
    assert w.spawned == [] and not (w.root / 'REQUAL.claim').exists() and not (w.scratch / HOST_CLAIM).exists()
    assert record['schema'] == 'bux-r6-firefox-15601-requal-bind-v1' and record['host_claim'] == HOST_CLAIM
    identity = record['identity']
    assert identity['candidate'] == CANDIDATE
    assert identity['policy_template_sha256'] == TEMPLATE
    assert identity['policy_template_without_configd_sha256'] == WITHOUT_CONFIGD
    assert identity['services'] == SERVICES and identity['sandbox_disables'] == EXCEPTIONS
    assert identity['workload'] == 'full' and identity['captured_code'] is False
    assert identity['launch_tools'] == {'python': str(w.python), 'nix_bin': str(w.nix_bin)}
    assert record['production']['status'] == 'ADOPTED' and record['malformed_d_claim_present'] is False
    base = ['--engine', 'firefox', '--runtime', '<RUNTIME>', '--scratch', '<ATTEMPT>', '--workload', 'full',
            '--service', SERVICES[0], '--service', SERVICES[1], '--service', SERVICES[2],
            '--nested-sandbox-exception', 'content', '--nested-sandbox-exception', 'socket',
            '--nested-sandbox-exception', 'utility-generic']
    assert record['launch_options'] == {'normal': base, 'abnormal': base + ['--abnormal']}


def drift_plist(key, value):
    return lambda w: w.write_plist({**PLIST, key: value})


def drift_ini(old, new):
    return lambda w: w.write_ini(INI.replace(old, new))


def set_attr(name, value):
    return lambda w: setattr(w, name, value)


def bad_signature(w):
    class Completed:
        returncode = 1
    w.mp.setattr(w.m, 'signature', w.real_signature)
    w.mp.setattr(w.m.subprocess, 'run', lambda *a, **k: Completed())


DRIFT = {
    **{f'short-{v}': (drift_plist('CFBundleShortVersionString', v), 'Candidate bundle version differs')
       for v in ('156.0', '156.0.2', '156.0.10', '156.0.1esr', '155.0.1', ' 156.0.1', '156.0.1.0')},
    'short-not-string': (drift_plist('CFBundleShortVersionString', 156), 'Candidate bundle version differs'),
    'bundle-id': (drift_plist('CFBundleIdentifier', 'org.mozilla.nightly'), 'Candidate bundle identity differs'),
    'bundle-version': (drift_plist('CFBundleVersion', '15626.9.20'), 'Candidate bundle build version differs'),
    'plist-missing': (lambda w: (w.app / 'Contents/Info.plist').unlink(), 'Candidate bundle metadata unreadable'),
    'plist-garbage': (lambda w: (w.app / 'Contents/Info.plist').write_bytes(b'<plist'),
                      'Candidate bundle metadata unreadable'),
    'plist-link': (lambda w: ((w.app / 'Contents/Info.plist').unlink(),
                              (w.app / 'Contents/Info.plist').symlink_to(w.tmp / 'elsewhere.plist')),
                   'Candidate bundle metadata unreadable'),
    'ini-version': (drift_ini('Version=156.0.1', 'Version=156.0'), 'Candidate application.ini version differs'),
    'ini-version-suffix': (drift_ini('Version=156.0.1', 'Version=156.0.1esr'),
                           'Candidate application.ini version differs'),
    'ini-build': (drift_ini('BuildID=20260921121718', 'BuildID=20260921121719'),
                  'Candidate application.ini build differs'),
    'ini-no-build': (drift_ini('BuildID=20260921121718\n', ''), 'Candidate application.ini build differs'),
    'ini-duplicate-option': (drift_ini('Vendor=Mozilla', 'Version=156.0.1'), 'Candidate application.ini unreadable'),
    'ini-duplicate-section': (lambda w: w.write_ini(INI + '[App]\nVersion=156.0.1\n'),
                              'Candidate application.ini unreadable'),
    'ini-no-section': (lambda w: w.write_ini('Version=156.0.1\n'), 'Candidate application.ini unreadable'),
    'ini-missing': (lambda w: (w.app / 'Contents/Resources/application.ini').unlink(),
                    'Candidate application.ini unreadable'),
    'tree-other': (set_attr('tree', 'f' * 64), 'Candidate runtime tree differs'),
    'tree-production': (set_attr('tree', D1_RUNTIME), 'Candidate runtime tree differs'),
    'executable-other': (set_attr('executable', 'f' * 64), 'Candidate executable differs'),
    'executable-production': (set_attr('executable', D1_EXECUTABLE), 'Candidate executable differs'),
    'executable-unreadable': (set_attr('executable', None), 'Candidate executable differs'),
    'signature': (bad_signature, 'Candidate signature invalid')}


@pytest.mark.parametrize('case', sorted(DRIFT))
def test_candidate_drift_refuses_with_the_tree_still_matching(w, case):
    damage, message = DRIFT[case]
    damage(w)
    refused(w, message)
    w.no_side_effects()


def test_candidate_path_must_be_the_link_free_firefox_app(w):
    other = w.tmp / 'Applications/Nightly.app'
    w.app.rename(other)
    refused(w, 'Candidate runtime must be the link-free installed Firefox.app',
            *w.argv('bind')[:5], '--runtime', str(other), *w.argv('bind')[7:])
    link = w.tmp / 'link/Firefox.app'
    link.parent.mkdir()
    link.symlink_to(other)
    refused(w, 'Candidate runtime must be the link-free installed Firefox.app',
            *w.argv('bind')[:5], '--runtime', str(link), *w.argv('bind')[7:])
    w.no_side_effects()


def test_executable_digest_reads_the_real_bytes(w, load_module, repo_root):
    real = load_module(RUNNER)
    assert real.executable_digest(w.app) == hashlib.sha256(b'synthetic executable').hexdigest()
    (w.app / 'Contents/MacOS/firefox').unlink()
    assert real.executable_digest(w.app) is None


def test_runner_has_no_version_pattern_or_prefix_acceptance(repo_root):
    source = (repo_root / RUNNER).read_text()
    tree = ast.parse(source)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not {'re', 'fnmatch', 'glob'} & imported
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not {'startswith', 'endswith', 'fullmatch', 'match', 'search', 'split', 'partition'} & calls
    assert not re.search(r'\bassert\b', source)


def test_runner_reads_only_production_constants(repo_root):
    tree = ast.parse((repo_root / RUNNER).read_text())
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == 'production'}
    assert used == {'d2', 'firefox', 'ACCEPTED_RUNTIME', 'ACCEPTED_EXECUTABLE', 'ACCEPTED_TEMPLATE',
                    'ACCEPTED_TEMPLATE_WITHOUT_CONFIGD', 'SERVICES', 'EXCEPTIONS', 'CONSUMED_HOST_CLAIMS',
                    'UNCREATED_PROPOSED_CLAIMS', 'BUDGETS'}
    owner = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and isinstance(n.value, ast.Name) and n.value.id == 'firefox'}
    assert owner == {'VERSION', 'BUNDLE_ID', 'BUNDLE_VERSION', 'BUILD_ID', 'RUNTIME', 'EXECUTABLE', 'IDENTITY'}
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and isinstance(n.func.value, ast.Name) and n.func.value.id in ('production', 'firefox')}
    assert called == set()


# Source and policy drift ----------------------------------------------------------------------

def test_snapshot_drift_refuses(w):
    (w.snapshot / 'tests/cnt-native-preflight.py').write_text('changed\n')
    refused(w, 'Snapshot bytes/modes/links differ')
    w.no_side_effects()


def test_runner_must_execute_from_the_snapshot(w, monkeypatch):
    monkeypatch.setattr(w.m, 'RUNNER', w.tmp / RUNNER)
    refused(w, 'Runner must execute from the approved snapshot')
    w.no_side_effects()


@pytest.mark.parametrize('key,value', [('policy_template_sha256', 'f' * 64),
                                       ('policy_template_without_configd_sha256', 'f' * 64),
                                       ('policy_template_sha256', None)])
def test_policy_prediction_drift_refuses(w, key, value):
    w.prediction[key] = value
    refused(w, 'Predicted launch policy is not the accepted R4 template')
    w.no_side_effects()


def test_launch_interpreter_without_pytest_refuses(w):
    del w.prediction['pytest_version']
    refused(w, 'Launch interpreter cannot import pytest')
    w.no_side_effects()


# The pair -------------------------------------------------------------------------------------

def test_passing_pair_order_argv_and_summary(w):
    assert w.run() == 0
    assert w.events == ['tree', 'pytest', 'pytest-O', 'tree', 'claim:host', 'claim:REQUAL.claim', 'tree', 'normal',
                        'tree', 'abnormal', 'tree', 'tree']
    python, preflight = str(w.python), str(w.snapshot / 'tests/cnt-native-preflight.py')
    base = [python, '-B', preflight, '--engine', 'firefox', '--runtime', str(w.app)]
    tail = ['--workload', 'full', '--service', SERVICES[0], '--service', SERVICES[1], '--service', SERVICES[2],
            '--nested-sandbox-exception', 'content', '--nested-sandbox-exception', 'socket',
            '--nested-sandbox-exception', 'utility-generic']
    assert w.spawned[2] == base + ['--scratch', str(w.root / 'normal')] + tail
    assert w.spawned[3] == base + ['--scratch', str(w.root / 'abnormal')] + tail + ['--abnormal']
    state = w.state()
    assert state['phase'] == 'PAIR_RETURNED' and state['abnormal'] == 'LAUNCHED'
    summary = w.summary()
    assert summary['label'] == LABEL + 'PAIR_PASSED_PENDING_MANAGER_REVIEW'
    assert (summary['qualification_accepted'], summary['production_binding_changed'], summary['malformed_d_authorized'],
            summary['captured_cnt_executed'], summary['semantic_success_claimed']) == (False,) * 5
    assert summary['native_acceptance'] == 'PENDING_MANAGER_REVIEW'
    assert summary['candidate'] == CANDIDATE and summary['production']['status'] == 'ADOPTED'
    assert summary['policy']['policy_template_sha256'] == TEMPLATE
    assert (summary['runtime_before_normal'], summary['runtime_after_normal'],
            summary['runtime_after_abnormal']) == ('MATCH',) * 3
    assert summary['end_recheck'] == {'source': 'MATCH', 'runtime': 'MATCH', 'production': 'MATCH'}
    normal, abnormal = summary['roles']['normal'], summary['roles']['abnormal']
    assert normal['passed'] and abnormal['passed'] and normal['failed_checks'] == abnormal['failed_checks'] == []
    assert normal['quit_observed'] == 'reply' and normal['marionette_quit_count'] == 1
    assert normal['exit_before_cleanup'] == 0 and normal['settlement']['exit_code'] == 0
    assert abnormal['intended_timeout'] and abnormal['exit_before_cleanup'] is None
    assert abnormal['settlement']['exit_code'] == -15 and abnormal['marionette_quit_count'] == 0
    for role in (normal, abnormal):
        assert role['useful_work'] == {k: True for k in w.m.USEFUL_WORK}
        assert role['frozen_identity']['runtime_observed_sha256'] == CANDIDATE['runtime_sha256']
        assert role['frozen_identity']['browser_version'] == '156.0.1'
        assert role['runtime_measurement']['state'] == 'MATCH' and role['settlement']['zero_survivors']
    lineage = summary['claim']
    assert lineage['host_claim'] == HOST_CLAIM and lineage['root_claim'] == 'REQUAL.claim'
    assert lineage['inventory_sha256'] == w.inventory_sha and lineage['malformed_d_claim_present'] is False
    prerequisites = summary['prerequisites']
    assert prerequisites['record'] == 'PREREQUISITES-001.json' and len(prerequisites['counts']) == 2
    assert [c['mode'] for c in prerequisites['counts']] == ['normal', 'optimized']
    assert all(c['passed'] == 15 and c['ok'] for c in prerequisites['counts'])
    host = json.loads((w.scratch / HOST_CLAIM).read_text())
    assert host['candidate_runtime_sha256'] == CANDIDATE['runtime_sha256'] and host['claim_root_name'] == 'claim'
    assert not (w.scratch / MALFORMED_D).exists()


@pytest.mark.parametrize('optimized,tail,code,interrupts', [
    (False, '14 passed in 1.0s', 0, 0), (True, '15 passed, 1 skipped in 1.0s', 0, 0),
    (False, '15 passed in 1.0s', 1, 0), (True, '15 passed in 1.0s', 0, 1), (False, '1 failed, 14 passed', 1, 0)])
def test_prerequisite_failure_refuses_before_any_claim(w, optimized, tail, code, interrupts):
    from cnt_native_evidence import VerificationError
    path, digest = w.bind()
    w.pytest_tail[optimized], w.pytest_codes[optimized] = tail, code
    w.pytest_interrupts[optimized] = interrupts
    with pytest.raises(VerificationError, match='Prerequisites failed'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert not (w.scratch / HOST_CLAIM).exists() and not (w.root / 'REQUAL.claim').exists()
    assert 'normal' not in w.events and 'abnormal' not in w.events
    record = json.loads((w.root / 'PREREQUISITES-001.json').read_text())
    assert record['ok'] is False and record['claims_consumed'] is False


@pytest.mark.parametrize('drift,message', [
    ('source', 'Snapshot bytes/modes/links differ'), ('tree', 'Candidate runtime tree differs'),
    ('executable', 'Candidate executable differs'), ('plist', 'Candidate bundle version differs')])
def test_drift_during_prerequisites_refuses_before_any_claim(w, drift, message):
    from cnt_native_evidence import VerificationError
    path, digest = w.bind()
    real = w.d2.prerequisite
    damage = {'source': lambda: (w.snapshot / 'tests/cnt-native-preflight.py').write_text('changed\n'),
              'tree': lambda: setattr(w, 'tree', 'f' * 64),
              'executable': lambda: setattr(w, 'executable', 'f' * 64),
              'plist': lambda: w.write_plist({**PLIST, 'CFBundleShortVersionString': '156.0.2'})}[drift]

    def prerequisite(python, env, snapshot, root, optimized):
        counts = real(python, env, snapshot, root, optimized)
        if optimized:
            damage()
        return counts
    w.mp.setattr(w.d2, 'prerequisite', prerequisite)
    with pytest.raises(VerificationError) as error:
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert str(error.value) == message
    assert not (w.scratch / HOST_CLAIM).exists() and not (w.root / 'REQUAL.claim').exists()
    assert not any(e.startswith('claim:') for e in w.events) and w.launched() == ['pytest', 'pytest-O']
    assert json.loads((w.root / 'PREREQUISITES-001.json').read_text())['ok'] is True


def not_passed(key, value):
    return lambda r: r.update({key: value})


def nested(outer, key, value):
    return lambda r: r[outer].update({key: value})


def removed(key):
    return lambda r: r.pop(key)


COMMON_DAMAGE = {
    'status-blocked': not_passed('status', 'BLOCKED'),
    'workload-empty': not_passed('workload', 'empty'),
    'diagnostic': not_passed('diagnostic_only', True),
    'shutdown-trace': not_passed('shutdown_trace', True),
    'observer': not_passed('shutdown_observer', True),
    'crash-force': not_passed('crash_force_enable', True),
    'crash-readback': not_passed('crash_readback', True),
    'parent-probes': not_passed('parent_probes', True),
    'captured-code': not_passed('captured_code_loaded', True),
    'native-semantics': not_passed('native_semantics', 'EXECUTED_CASE_RECORDED'),
    'not-launched': not_passed('browser_launched', False),
    'no-configd': not_passed('mach_services', SERVICES[:2]),
    'configd-flag': not_passed('configd_compatibility', False),
    'exceptions': not_passed('sandbox_disables', ['content', 'socket']),
    'forbidden-matrix-case': not_passed('matrix_case', 'S-RICH'),
    'forbidden-capture': not_passed('capture_identity', {}),
    'forbidden-rendezvous': not_passed('chrome_rendezvous', 'NOT_SELECTED'),
    **{f'useful-{k}': not_passed(k, False) for k in ('ready', 'page_nonce', 'extension_installed',
                                                      'extension_origin_verified', 'extension_nonce',
                                                      'extension_unloaded')},
    'measurement-incomplete': not_passed('runtime_measurement', {'state': 'INCOMPLETE', 'digest_complete': False}),
    'measurement-mismatch': nested('runtime_measurement', 'state', 'MISMATCH'),
    'runtime-unchanged-false': not_passed('runtime_unchanged', False),
    'observed-other': not_passed('runtime_observed_sha256', 'f' * 64),
    'source-production': not_passed('runtime_source_sha256', D1_RUNTIME),
    'executable-production': not_passed('executable_sha256', D1_EXECUTABLE),
    'frozen-signature': not_passed('signature', {'original': True, 'frozen': False}),
    'browser-version': not_passed('browser_version', '156.0'),
    'policy-template': nested('preflight', 'policy_template_sha256', WITHOUT_CONFIGD),
    'canaries': nested('preflight', 'status', 'CANARIES_FAILED'),
    'listener-not-owned': not_passed('listener_samples', [{'owned': False, 'tcp_listeners': [f'127.0.0.1:{PORT}']}]),
    'listener-public': not_passed('listener_samples', [{'owned': True, 'tcp_listeners': [f'0.0.0.0:{PORT}']}]),
    'listener-absent': not_passed('listener_samples', []),
    'primary-failure': not_passed('primary_failure', {'stage': 'browser', 'type': 'X', 'code': 'UNKNOWN'}),
    'survivors': nested('settlement', 'zero_survivors', False),
    'unsettled': nested('settlement', 'unsettled', True),
    'settlement-failures': nested('settlement', 'failures', [{'type': 'X'}]),
    'unknown-before-kill': nested('settlement', 'workload_status', 'unknown-before-kill'),
    'unparseable': lambda r: r.clear()}
NORMAL_DAMAGE = {
    **COMMON_DAMAGE,
    'qualified-eof': not_passed('quit_observed', 'qualified-eof'),
    'no-quit': removed('quit_observed'),
    'two-quits': lambda r: r['protocol'].append({'method': 'Marionette:Quit', 'outcome': 'reply'}),
    'exit-before-cleanup-1': not_passed('exit_before_cleanup', 1),
    'exit-before-cleanup-none': not_passed('exit_before_cleanup', None),
    'settlement-exit': nested('settlement', 'exit_code', 1),
    'abnormal-flag': not_passed('abnormal', True),
    'intended-timeout': not_passed('intended_timeout', True)}


@pytest.mark.parametrize('case', sorted(NORMAL_DAMAGE))
def test_normal_failure_prevents_abnormal(w, case):
    w.edits['normal'] = NORMAL_DAMAGE[case]
    assert w.run() == 0
    assert w.launched() == ['pytest', 'pytest-O', 'normal']
    state = w.state()
    assert state['abnormal'] == 'NOT_STARTED_NORMAL_FAILED' and state['phase'] == 'NORMAL_FAILED'
    summary = w.summary()
    assert summary['label'] == LABEL + 'NORMAL_FAILED' and 'abnormal' not in summary['roles']
    assert summary['roles']['normal']['failed_checks']
    assert summary['end_recheck'] == {'source': 'MATCH', 'runtime': 'MATCH', 'production': 'MATCH'}


@pytest.mark.parametrize('code,result_present', [(2, True), (0, False)])
def test_normal_transport_or_missing_result_prevents_abnormal(w, code, result_present):
    w.codes['normal'] = code
    if not result_present:
        w.edits['normal'] = lambda r: None
        w.after['normal'] = lambda: (w.root / 'normal/result.json').unlink()
    assert w.run() == 0
    assert w.launched() == ['pytest', 'pytest-O', 'normal']
    summary = w.summary()
    assert summary['label'] == LABEL + 'NORMAL_FAILED'
    failed = summary['roles']['normal']['failed_checks']
    assert failed == (['transport'] if result_present else ['result_readable'])


def test_policy_delta_mismatch_fails_the_role(w):
    w.delta['d1_template_match'] = False
    assert w.run() == 0
    assert w.summary()['roles']['normal']['failed_checks'] == ['policy']
    assert w.launched() == ['pytest', 'pytest-O', 'normal']


def test_installed_runtime_drift_after_normal_prevents_abnormal(w):
    w.after['normal'] = lambda: setattr(w, 'tree', 'f' * 64)
    assert w.run() == 0
    assert w.launched() == ['pytest', 'pytest-O', 'normal']
    state = w.state()
    assert state['abnormal'] == 'NOT_STARTED_RUNTIME_AFTER_NORMAL_FAILED'
    summary = w.summary()
    assert summary['roles']['normal']['passed'] is True
    assert summary['label'] == LABEL + 'RUNTIME_AFTER_NORMAL_FAILED'
    assert summary['runtime_after_normal'] == 'MISMATCH_OR_UNREADABLE'
    assert summary['end_recheck']['runtime'] == 'MISMATCH_OR_UNREADABLE'


ABNORMAL_DAMAGE = {
    **COMMON_DAMAGE,
    'no-intended-timeout': removed('intended_timeout'),
    'exit-minus-9': nested('settlement', 'exit_code', -9),
    'exit-zero': nested('settlement', 'exit_code', 0),
    'exit-before-cleanup-0': not_passed('exit_before_cleanup', 0),
    'exit-before-cleanup-absent': removed('exit_before_cleanup'),
    'quit-observed': not_passed('quit_observed', 'reply'),
    'quit-requested': lambda r: r['protocol'].append({'method': 'Marionette:Quit', 'outcome': 'reply'}),
    'abnormal-flag': not_passed('abnormal', False)}


@pytest.mark.parametrize('case', sorted(ABNORMAL_DAMAGE))
def test_abnormal_predicate(w, case):
    w.edits['abnormal'] = ABNORMAL_DAMAGE[case]
    assert w.run() == 0
    assert w.launched() == ['pytest', 'pytest-O', 'normal', 'abnormal']
    summary = w.summary()
    assert summary['label'] == LABEL + 'ABNORMAL_FAILED'
    assert summary['roles']['normal']['passed'] and summary['roles']['abnormal']['failed_checks']


def test_installed_runtime_drift_after_abnormal(w):
    w.after['abnormal'] = lambda: setattr(w, 'tree', 'f' * 64)
    assert w.run() == 0
    summary = w.summary()
    assert summary['label'] == LABEL + 'RUNTIME_AFTER_ABNORMAL_FAILED'
    assert summary['runtime_after_abnormal'] == 'MISMATCH_OR_UNREADABLE'


@pytest.mark.parametrize('drift,failed', [('source', 'source'), ('production', 'production'), ('d1', 'production')])
def test_end_recheck_detects_drift_after_the_pair(w, monkeypatch, drift, failed):
    if drift == 'source':
        w.after['abnormal'] = lambda: (w.snapshot / 'tests/cnt-native-preflight.py').write_text('changed\n')
    elif drift == 'd1':
        w.after['abnormal'] = lambda: monkeypatch.setattr(w.d2, 'D1_RUNTIME', CANDIDATE['runtime_sha256'])
    else:
        w.after['abnormal'] = lambda: monkeypatch.setattr(w.production, 'ACCEPTED_RUNTIME', D1_RUNTIME)
    assert w.run() == 0
    summary = w.summary()
    assert summary['label'] == LABEL + 'END_RECHECK_FAILED'
    assert summary['end_recheck'][failed] == 'MISMATCH_OR_UNREADABLE'
    assert summary['roles']['normal']['passed'] and summary['roles']['abnormal']['passed']


def test_refusal_after_normal_still_rechecks_and_never_launches_abnormal(w):
    w.after['normal'] = lambda: (w.snapshot / 'tests/cnt-native-preflight.py').write_text('changed\n')
    assert w.run() == 0
    assert w.launched() == ['pytest', 'pytest-O', 'normal']
    state = w.state()
    assert state['phase'] == 'RUNNER_REFUSED' and state['abnormal'] == 'NOT_STARTED_RUNNER_REFUSED'
    assert state['runner_failure'] == {'type': 'VerificationError', 'code': 'SNAPSHOT_BYTES_DIFFER'}
    assert state['end_recheck'] == {'source': 'MISMATCH_OR_UNREADABLE', 'runtime': 'MATCH', 'production': 'MATCH'}
    assert w.summary()['label'] == LABEL + 'RUNNER_REFUSED'


def test_candidate_drift_after_claim_refuses_before_launch(w):
    path, digest = w.bind()
    recording = w.d2.exclusive

    def exclusive(p, record):
        # The claimed phase re-binds the candidate first; make that post-claim bind fail.
        recording(p, record)
        if Path(p).name == 'REQUAL.claim':
            w.tree = 'f' * 64
    w.mp.setattr(w.d2, 'exclusive', exclusive)
    assert w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest)) == 0
    assert 'normal' not in w.events
    state = w.state()
    assert state['runner_failure'] == {'type': 'VerificationError', 'code': 'CANDIDATE_TREE_DIFFERS'}
    assert state['end_recheck']['runtime'] == 'MISMATCH_OR_UNREADABLE'
    assert w.summary()['label'] == LABEL + 'RUNNER_REFUSED'


@pytest.mark.parametrize('role', ['normal', 'abnormal'])
def test_interrupt_waits_for_the_child_and_does_no_runtime_work(w, role):
    w.interrupts[role] = 1
    assert w.run() == 0
    expected = ['pytest', 'pytest-O', 'normal'] + (['abnormal'] if role == 'abnormal' else [])
    assert w.launched() == expected
    assert w.events[-1] == role
    state = w.state()
    assert state['interrupted'] is True and state['phase'] == 'INTERRUPTED_RETAINED'
    assert 'end_recheck' not in state and f'runtime_after_{role}' not in state
    assert state['attempts'][role]['interrupted'] is True
    assert w.summary()['label'] == LABEL + 'INCOMPLETE_INTERRUPTED'


def test_no_retry_on_this_host_or_this_root(w):
    assert w.run() == 0
    spawned = len(w.spawned)
    other = w.scratch / 'fresh-root'
    other.mkdir()
    from cnt_native_evidence import VerificationError
    with pytest.raises(VerificationError, match='already claimed on this host'):
        w.run(other)
    (w.scratch / HOST_CLAIM).unlink()  # synthetic only: the per-root claim still refuses
    path, digest = w.bind()
    with pytest.raises(VerificationError, match='Claim root already used'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert len(w.spawned) == spawned


@pytest.mark.parametrize('name', ['normal', 'abnormal', 'normal-outside-canary', 'abnormal-outside-canary'])
def test_existing_attempt_directory_refuses(w, name):
    from cnt_native_evidence import VerificationError
    path, digest = w.bind()
    (w.root / name).mkdir()
    with pytest.raises(VerificationError, match='Attempt directory present'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert w.spawned == [] and not (w.scratch / HOST_CLAIM).exists()


def test_bind_record_must_match(w):
    from cnt_native_evidence import VerificationError
    path, digest = w.bind()
    with pytest.raises(VerificationError, match='Bind record is not the supplied record'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256='0' * 64))
    record = json.loads(path.read_text())
    record['identity']['candidate']['version'] = '156.0.2'
    forged = w.root / 'BIND-forged.json'
    forged.write_text(json.dumps(record))
    with pytest.raises(VerificationError, match='differ from the bind record'):
        w.m.main(w.argv('run', bind_record=str(forged),
                        bind_record_sha256=hashlib.sha256(forged.read_bytes()).hexdigest()))
    assert w.spawned == [] and not (w.scratch / HOST_CLAIM).exists()


def test_insufficient_free_space_refuses_before_claim(w, monkeypatch):
    from cnt_native_evidence import VerificationError
    path, digest = w.bind()
    monkeypatch.setattr(w.m, 'free_bytes', lambda root: w.m.MIN_FREE_BYTES - 1)
    with pytest.raises(VerificationError, match='Insufficient free space'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert w.spawned == [] and not (w.scratch / HOST_CLAIM).exists()


def test_bind_refuses_once_claimed(w):
    (w.scratch / HOST_CLAIM).write_text('{}\n')
    refused(w, 'Requalification already claimed on this host; never rerun')
    assert w.spawned == [] and not list(w.root.glob('BIND-*.json'))


def test_collect_launches_nothing_and_mutates_no_claim(w, monkeypatch):
    assert w.run() == 0
    claims = {p: p.read_bytes() for p in (w.scratch / HOST_CLAIM, w.root / 'REQUAL.claim')}

    def forbidden(*args, **kwargs):
        raise AssertionError('collect must not call this')
    for owner, name in ((w.d2, 'spawn'), (w.d2, 'predicted_template'), (w.d2, 'exclusive'), (w.d2, 'tree_digest'),
                        (w.d2, 'prerequisite'), (w.m, 'bind_candidate'), (w.m, 'signature'),
                        (w.m, 'executable_digest'), (w.m, 'production_adopted'), (w.m.subprocess, 'run'),
                        (w.m.subprocess, 'Popen')):
        monkeypatch.setattr(owner, name, forbidden)
    assert w.m.main(['collect', '--claim-root', str(w.root)]) == 0
    assert sorted(p.name for p in w.root.glob('REQUAL-SUMMARY-*.json')) == ['REQUAL-SUMMARY-001.json',
                                                                            'REQUAL-SUMMARY-002.json']
    assert {p: p.read_bytes() for p in claims} == claims
    assert w.summary()['label'] == LABEL + 'PAIR_PASSED_PENDING_MANAGER_REVIEW'


def test_launches_carry_no_capture_matrix_or_diagnostic_option(w, repo_root):
    assert w.run() == 0
    forbidden = {'--capture', '--capture-sha256', '--matrix-case', '--matrix-input', 'cnt-matrix', '--shutdown-trace',
                 '--crash-readback', '--crash-force-enable', '--parent-probes', '--chrome-rendezvous', 'chrome'}
    for argv in w.spawned:
        assert not forbidden & set(argv)
    assert '--abnormal' not in w.spawned[2] and w.spawned[3][-1] == '--abnormal'
    source = (repo_root / RUNNER).read_text()
    for token in ('--capture', '--matrix', 'cnt-matrix', 'verify_capture', 'XPI_SHA256', 'cnt_firefox_matrix_session',
                  'cnt_host_chrome', 'cnt_synthetic_chrome', 'CDPPipe', 'OwnedProcess', 'sandbox-exec', '.kill(',
                  '.terminate(', 'killpg', '--shutdown-trace', '--crash-', '--parent-probes', 'while True'):
        assert token not in source, token


@pytest.mark.parametrize('which', ['claim-root', 'snapshot', 'collect'])
def test_inbox_paths_are_refused(w, which):
    from cnt_native_evidence import VerificationError
    inbox = w.scratch / 'agent/inbox/kit'
    inbox.mkdir(parents=True)
    if which == 'collect':
        argv = ['collect', '--claim-root', str(inbox)]
    else:
        argv = w.argv('bind', inbox if which == 'claim-root' else None)
        if which == 'snapshot':
            argv[argv.index('--snapshot') + 1] = str(inbox)
    with pytest.raises(VerificationError, match='must not be under an inbox'):
        w.m.main(argv)
    assert w.spawned == [] and not list(inbox.iterdir())


def test_handoff_writes_only_to_the_outbox(repo_root):
    text = (repo_root / DOC).read_text()
    blocks = re.findall(r'```zsh\n(.*?)```', text, re.S)
    handoff = [b for b in blocks if 'cnt_host_firefox_runtime_requal.py' in b]
    assert len(handoff) == 1
    commands = handoff[0].replace('\\\n', ' ')
    assert [c for c in ('bind', 'run', 'collect') if f'cnt_host_firefox_runtime_requal.py {c} ' in commands] == \
        ['bind', 'run', 'collect']
    destinations = re.findall(r'\btee\s+(\S+)', commands) + [line.split()[-1] for line in commands.splitlines()
                                                             if line.strip().startswith('cp ')]
    assert destinations == ['<OUTBOX>/BIND-STDOUT.json', '<OUTBOX>/RUN-STDOUT.json', '<OUTBOX>/RUN-EXIT.txt',
                            '<OUTBOX>/COLLECT-STDOUT.json', '<OUTBOX>/']
    # Raw stderr stays private in the claim root; pipefail keeps the runner's exit status visible.
    assert re.findall(r'2>\s*(\S+)', commands) == ['<ROOT>/BIND-STDERR.log', '<ROOT>/RUN-STDERR.log',
                                                    '<ROOT>/COLLECT-STDERR.log']
    lines = [line.strip() for line in commands.splitlines()]
    assert lines[:2] == ['setopt pipefail', 'mkdir -m 700 <ROOT>']
    assert 'inbox' not in handoff[0] and '--capture' not in handoff[0] and '--budget' not in handoff[0]
    assert re.search(r'`<OUTBOX>` is `~/Documents/agent/outbox/browser-ux_dinas/[^`]*`', text)


def test_chrome_unchanged_and_the_production_budget_is_multipart_b(w):
    import cnt_host_chrome as chrome
    assert w.production.BUDGETS == {'multipart-b': {
        'claim': MULTIPART_B,
        'cases': ('S-MULTI', 'T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1', 'T-MULTI-NO-MIDDLE',
                  'T-MULTI-DUP', 'T-MULTI-TRUNC', 'T-MULTI-BADDATA'),
        'categories': ('B',)}}
    assert MALFORMED_D in w.production.CONSUMED_HOST_CLAIMS and w.production.CONSUMED_HOST_CLAIMS[-1] == COMPAT_E
    assert chrome.HOST_CLAIMS == {'startup': 'bux-r5-chrome-startup.claim', 'pair': 'bux-r5-chrome-pair.claim'}
    assert chrome.C1A_CLAIMS == {'startup': 'bux-r5-chrome-c1a-startup.claim', 'pair': 'bux-r5-chrome-c1a-pair.claim'}
    assert HOST_CLAIM not in (*chrome.HOST_CLAIMS.values(), *chrome.C1A_CLAIMS.values(), MALFORMED_D, COMPAT_E,
                              MULTIPART_B)


@pytest.mark.parametrize('claim', [COMPAT_E, MULTIPART_B], ids=['consumed-compat-e', 'current-multipart-b'])
def test_matrix_claims_are_refused_by_name_only(w, monkeypatch, repo_root, claim):
    # COMPAT-E is consumed lineage; MULTIPART-B-PREP1's new production claim is refused by name too.
    assert claim in w.m.REFUSED_CLAIMS and w.m.REFUSED_CLAIMS[-2:] == (COMPAT_E, MULTIPART_B)
    source = (repo_root / RUNNER).read_text()
    assert source.count(claim) == 1 and 'lexists(d2.SCRATCH / MALFORMED_D_CLAIM)' in source
    # Mutant: without the literal the lane refuses before any side effect.
    monkeypatch.setattr(w.m, 'REFUSED_CLAIMS', tuple(c for c in w.m.REFUSED_CLAIMS if c != claim))
    refused(w, 'Requalification claim is not distinct')
    w.no_side_effects()


def test_existing_malformed_d_claim_is_only_tested_for_existence(w):
    claim = w.scratch / MALFORMED_D
    claim.write_text('{"retained": true}\n')
    before = claim.stat()
    claim.chmod(0)
    try:
        path, _ = w.bind()
        assert json.loads(path.read_text())['malformed_d_claim_present'] is True
        after = claim.stat()
        assert (after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
    finally:
        claim.chmod(0o600)
    assert claim.read_text() == '{"retained": true}\n'


def test_summary_is_a_privacy_projection(w):
    secret = str(w.tmp)

    def leak(r):
        r['primary_failure'] = {'stage': 'browser', 'type': 'OSError', 'code': 'UNKNOWN',
                                'message': 'open ' + secret + '/Users/someone/profile'}
        r['settlement'].update(survivors=[987654], zero_survivors=False)
        r['browser_version'] = '/Users/x'
        r['listener_samples'] = [{'owned': True, 'pid': 987654, 'tcp_listeners': [f'127.0.0.1:{PORT}'],
                                  'command': secret}]
    w.edits['normal'] = leak
    assert w.run() == 0
    raw = sorted(w.root.glob('REQUAL-SUMMARY-*.json'))[-1].read_text()
    for text in (secret, '/Users/', '987654', 'someone', 'message'):
        assert text not in raw
    summary = json.loads(raw)
    assert summary['roles']['normal']['failures']['primary_failure'] == {'stage': 'browser', 'type': 'OSError',
                                                                         'code': 'UNKNOWN'}
    assert summary['roles']['normal']['frozen_identity']['browser_version'] == 'UNSAFE'
