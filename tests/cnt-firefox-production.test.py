"""Adopted production Firefox identity (`cnt_firefox_production`): exact owner and single authority.

No browser, codesign, installed runtime, Nix, subprocess, captured code or host scratch is used; the
app is synthetic and its tree and executable digests are faked on the owner module.
"""
import ast
import hashlib
import json
from pathlib import Path
import plistlib
import re

import pytest

OWNER = 'tests/cnt_firefox_production.py'
MATRIX = 'tests/cnt_host_firefox_matrix.py'
REQUAL = 'tests/cnt_host_firefox_runtime_requal.py'
D2 = 'tests/cnt_host_d2.py'
DOC = 'docs/architecture/cnt-native-format-characterization.md'
ADOPTED = {'version': '156.0.1', 'bundle_identifier': 'org.mozilla.firefox', 'bundle_version': '15626.9.21',
           'build_id': '20260921121718',
           'runtime_sha256': '35172d4e392575860ed48cd7e7a45a6eb1a59eacdfef277aced6c5610bbcdab3',
           'executable_sha256': 'f2559282d3ef1ceeb0083700e57092c905f043eddb02a9b8ac09009ec9719ac3'}
SUPERSEDED_RUNTIME = '6555cd15eb85f2be816fede570f252d5e7154c1c4ecfda372f00f19cc0596f7d'
SUPERSEDED_EXECUTABLE = 'ca4f2108d1000fce089d4c5ace30565f489dfce8d2d98c89b355e7c3ebc40462'
TEMPLATE = 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'
WITHOUT_CONFIGD = '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'
SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd',
            'com.apple.SystemConfiguration.configd']
EXCEPTIONS = ['content', 'socket', 'utility-generic']
MALFORMED_D = 'bux-r6-firefox-native-matrix-malformed-d.claim'
PLIST = {'CFBundleIdentifier': 'org.mozilla.firefox', 'CFBundleShortVersionString': '156.0.1',
         'CFBundleVersion': '15626.9.21', 'CFBundleExecutable': 'firefox'}
INI = '[App]\nVendor=Mozilla\nName=Firefox\nVersion=156.0.1\nBuildID=20260921121718\n'


class App:
    def __init__(self, firefox, tmp_path, monkeypatch):
        self.f, self.tmp = firefox, tmp_path
        self.path = tmp_path / 'Applications/Firefox.app'
        (self.path / 'Contents/MacOS').mkdir(parents=True)
        (self.path / 'Contents/Resources').mkdir()
        (self.path / 'Contents/MacOS/firefox').write_bytes(b'synthetic executable')
        self.plist(PLIST)
        self.ini(INI)
        self.tree, self.executable = ADOPTED['runtime_sha256'], ADOPTED['executable_sha256']
        monkeypatch.setattr(firefox, 'tree_digest', lambda root, trace=None: self.tree)
        monkeypatch.setattr(firefox, 'executable_digest', lambda runtime: self.executable)

    def plist(self, values):
        (self.path / 'Contents/Info.plist').write_bytes(plistlib.dumps(values))

    def ini(self, text):
        (self.path / 'Contents/Resources/application.ini').write_text(text)


@pytest.fixture
def firefox(monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_production
    return cnt_firefox_production


@pytest.fixture
def app(firefox, tmp_path, monkeypatch):
    return App(firefox, tmp_path, monkeypatch)


def refuses(firefox, runtime, message):
    with pytest.raises(firefox.VerificationError) as error:
        firefox.bind_runtime(runtime)
    assert str(error.value) == message
    assert message in firefox.CODES


# 1. Exact constants ------------------------------------------------------------------------------

def test_owner_constants_are_exactly_the_accepted_156_identity(firefox):
    assert (firefox.VERSION, firefox.BUNDLE_ID, firefox.BUNDLE_VERSION, firefox.BUILD_ID, firefox.RUNTIME,
            firefox.EXECUTABLE) == tuple(ADOPTED.values())
    assert firefox.IDENTITY == ADOPTED


def test_owner_constants_match_the_requal_lane_record(firefox):
    """The accepted requalification identity, as the requal lane's historical literals carry it."""
    import cnt_host_firefox_runtime_requal as requal
    assert (requal.CANDIDATE_VERSION, requal.CANDIDATE_BUNDLE_ID, requal.CANDIDATE_BUNDLE_VERSION,
            requal.CANDIDATE_BUILD_ID, requal.CANDIDATE_RUNTIME, requal.CANDIDATE_EXECUTABLE) == tuple(ADOPTED.values())


# 2. Exact binder accepts ------------------------------------------------------------------------

def test_binder_accepts_the_exact_adopted_identity(firefox, app):
    bound = firefox.bind_runtime(app.path)
    assert bound == ADOPTED and bound is not firefox.IDENTITY
    bound['version'] = 'mutated'
    assert firefox.IDENTITY['version'] == '156.0.1'


def test_real_digest_helpers_read_the_real_bytes(firefox, tmp_path, monkeypatch):
    real = App(firefox, tmp_path, monkeypatch)
    monkeypatch.undo()
    assert firefox.executable_digest(real.path) == hashlib.sha256(b'synthetic executable').hexdigest()
    assert firefox.runtime_digest(real.path) == firefox.tree_digest(real.path)
    (real.path / 'Contents/MacOS/firefox').unlink()
    assert firefox.executable_digest(real.path) is None
    assert firefox.runtime_digest(tmp_path / 'absent/Firefox.app') is None


# 3 and 4. Drift and the superseded 155.0.1 identity refuse -------------------------------------

def plist(key, value):
    return lambda a: a.plist({**PLIST, key: value})


def ini(old, new):
    return lambda a: a.ini(INI.replace(old, new))


def attr(name, value):
    return lambda a: setattr(a, name, value)


DRIFT = {
    **{f'short-{v}': (plist('CFBundleShortVersionString', v), 'Firefox bundle version differs')
       for v in ('156.0', '156.0.2', '156.0.10', '156.0.1esr', '155.0.1', ' 156.0.1', '156.0.1.0', '156')},
    'short-not-string': (plist('CFBundleShortVersionString', 156), 'Firefox bundle version differs'),
    'short-absent': (lambda a: a.plist({k: v for k, v in PLIST.items() if k != 'CFBundleShortVersionString'}),
                     'Firefox bundle version differs'),
    'bundle-id': (plist('CFBundleIdentifier', 'org.mozilla.nightly'), 'Firefox bundle identity differs'),
    'bundle-version': (plist('CFBundleVersion', '15626.9.20'), 'Firefox bundle build version differs'),
    'plist-missing': (lambda a: (a.path / 'Contents/Info.plist').unlink(), 'Firefox bundle metadata unreadable'),
    'plist-garbage': (lambda a: (a.path / 'Contents/Info.plist').write_bytes(b'<plist'),
                      'Firefox bundle metadata unreadable'),
    'plist-list': (lambda a: (a.path / 'Contents/Info.plist').write_bytes(plistlib.dumps([1])),
                   'Firefox bundle metadata unreadable'),
    'plist-link': (lambda a: ((a.path / 'Contents/Info.plist').unlink(),
                              (a.path / 'Contents/Info.plist').symlink_to(a.tmp / 'elsewhere.plist')),
                   'Firefox bundle metadata unreadable'),
    'ini-version': (ini('Version=156.0.1', 'Version=156.0'), 'Firefox application.ini version differs'),
    'ini-version-155': (ini('Version=156.0.1', 'Version=155.0.1'), 'Firefox application.ini version differs'),
    'ini-version-suffix': (ini('Version=156.0.1', 'Version=156.0.1esr'), 'Firefox application.ini version differs'),
    'ini-build': (ini('BuildID=20260921121718', 'BuildID=20260921121719'), 'Firefox application.ini build differs'),
    'ini-no-build': (ini('BuildID=20260921121718\n', ''), 'Firefox application.ini build differs'),
    'ini-duplicate-option': (ini('Vendor=Mozilla', 'Version=156.0.1'), 'Firefox application.ini unreadable'),
    'ini-duplicate-section': (lambda a: a.ini(INI + '[App]\nVersion=156.0.1\n'), 'Firefox application.ini unreadable'),
    'ini-no-section': (lambda a: a.ini('Version=156.0.1\n'), 'Firefox application.ini unreadable'),
    'ini-missing': (lambda a: (a.path / 'Contents/Resources/application.ini').unlink(),
                    'Firefox application.ini unreadable'),
    'tree-other': (attr('tree', 'f' * 64), 'Firefox runtime differs from the production runtime'),
    'tree-superseded': (attr('tree', SUPERSEDED_RUNTIME), 'Firefox runtime differs from the production runtime'),
    'tree-unreadable': (attr('tree', None), 'Firefox runtime differs from the production runtime'),
    'executable-other': (attr('executable', 'f' * 64), 'Firefox executable differs from the production executable'),
    'executable-superseded': (attr('executable', SUPERSEDED_EXECUTABLE),
                              'Firefox executable differs from the production executable'),
    'executable-unreadable': (attr('executable', None), 'Firefox executable differs from the production executable'),
    'whole-155': (lambda a: (a.plist({**PLIST, 'CFBundleShortVersionString': '155.0.1'}),
                             a.ini(INI.replace('Version=156.0.1', 'Version=155.0.1')),
                             setattr(a, 'tree', SUPERSEDED_RUNTIME), setattr(a, 'executable', SUPERSEDED_EXECUTABLE)),
                  'Firefox bundle version differs')}


@pytest.mark.parametrize('case', sorted(DRIFT))
def test_drift_refuses_with_a_fixed_code(firefox, app, case):
    damage, message = DRIFT[case]
    damage(app)
    refuses(firefox, app.path, message)


def test_superseded_155_tree_and_executable_refuse_even_with_156_metadata(firefox, app):
    app.tree = SUPERSEDED_RUNTIME
    refuses(firefox, app.path, 'Firefox runtime differs from the production runtime')
    app.tree, app.executable = ADOPTED['runtime_sha256'], SUPERSEDED_EXECUTABLE
    refuses(firefox, app.path, 'Firefox executable differs from the production executable')


def test_path_must_be_the_link_free_installed_firefox_app(firefox, app):
    message = 'Firefox runtime must be the link-free installed Firefox.app'
    refuses(firefox, Path('Applications/Firefox.app'), message)
    other = app.tmp / 'Applications/Nightly.app'
    app.path.rename(other)
    refuses(firefox, other, message)
    link = app.tmp / 'link/Firefox.app'
    link.parent.mkdir()
    link.symlink_to(other)
    refuses(firefox, link, message)


def test_refusals_carry_no_path_and_every_message_has_a_distinct_code(firefox, repo_root):
    import cnt_firefox_matrix as matrix
    tree = ast.parse((repo_root / OWNER).read_text())
    messages = {n.args[1].value for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == 'require'}
    assert messages == set(firefox.CODES) and len(set(firefox.CODES.values())) == len(firefox.CODES)
    assert all('/' not in m and '{' not in m for m in messages)
    # Merged into the matrix runner's failure codes: no message may collide.
    assert not set(firefox.CODES) & set(matrix.MATRIX_CODES)
    assert not set(firefox.CODES.values()) & set(matrix.MATRIX_CODES.values())


def test_owner_has_no_pattern_family_or_fallback(repo_root):
    source = (repo_root / OWNER).read_text()
    tree = ast.parse(source)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not {'re', 'fnmatch', 'glob', 'subprocess', 'cnt_host_firefox_matrix', 'cnt_firefox_matrix',
                'cnt_host_firefox_runtime_requal', 'os'} & imported
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not {'startswith', 'endswith', 'fullmatch', 'match', 'search', 'split', 'partition', 'lower',
                'strip', 'kill', 'terminate', 'Popen', 'run', 'spawn'} & calls
    assert not re.search(r'\bassert\b', source)  # every check survives -O
    assert not any(isinstance(n, ast.While) for n in ast.walk(tree))
    binder = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'bind_runtime')
    # No alternative: no `or`, no membership test against a set of accepted values.
    assert not any(isinstance(n, (ast.Or, ast.In, ast.NotIn)) for n in ast.walk(binder))
    hexes = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and re.fullmatch(r'[0-9a-f]{64}', n.value)]
    assert hexes == [ADOPTED['runtime_sha256'], ADOPTED['executable_sha256']]
    for token in ('--capture', 'XPI', 'sandbox-exec', 'codesign', 'malformed'):
        assert token not in source, token


def test_owner_uses_only_the_bounded_reader_of_the_historical_module(repo_root):
    tree = ast.parse((repo_root / OWNER).read_text())
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == 'd2'}
    assert used == {'read_bounded'}


# 5. Historical 155.0.1 remains readable as history ----------------------------------------------

def test_d1_baseline_stays_the_historical_155_identity(repo_root):
    import cnt_host_d2 as d2
    assert (d2.D1_RUNTIME, d2.D1_EXECUTABLE, d2.D1_TEMPLATE) == (SUPERSEDED_RUNTIME, SUPERSEDED_EXECUTABLE,
                                                                  WITHOUT_CONFIGD)
    assert d2.D1_EXCEPTIONS == EXCEPTIONS and list(d2.D2_SERVICES) == SERVICES
    source = (repo_root / D2).read_text()
    assert '# Consumed D1 baseline (CONT6 HOST-D1): read back from its retained result.json.' in source


# 6. Accepted R4 policy unchanged -----------------------------------------------------------------

def test_matrix_r4_policy_is_unchanged(repo_root, monkeypatch):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_host_firefox_matrix as m
    import cnt_confinement
    assert (m.ACCEPTED_TEMPLATE, m.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD) == (TEMPLATE, WITHOUT_CONFIGD)
    assert m.SERVICES == SERVICES and m.EXCEPTIONS == EXCEPTIONS
    assert [*cnt_confinement.REVIEWED_SERVICES, cnt_confinement.CONFIGD] == SERVICES
    assert m.options('S-RICH', '<R>', '<A>', '<C>') == [
        '--engine', 'firefox', '--runtime', '<R>', '--scratch', '<A>', '--workload', 'cnt-matrix',
        '--service', SERVICES[0], '--service', SERVICES[1], '--service', SERVICES[2],
        '--nested-sandbox-exception', 'content', '--nested-sandbox-exception', 'socket',
        '--nested-sandbox-exception', 'utility-generic',
        '--capture', '<C>', '--capture-sha256', m.matrix.XPI_SHA256, '--matrix-case', 'S-RICH']


# 8. One authority --------------------------------------------------------------------------------

def modules(repo_root):
    """Every non-test Python module under tests/."""
    return {p.relative_to(repo_root).as_posix(): p.read_text() for p in sorted((repo_root / 'tests').glob('*.py'))
            if not p.name.endswith('.test.py') and not p.name.startswith('test_') and p.name != 'conftest.py'}


def test_identity_literals_live_only_in_their_owners(repo_root):
    found = {digest: sorted(name for name, text in modules(repo_root).items() if digest in text)
             for digest in (ADOPTED['runtime_sha256'], ADOPTED['executable_sha256'], SUPERSEDED_RUNTIME,
                            SUPERSEDED_EXECUTABLE)}
    # The owner holds the production identity; the requal lane keeps its historical candidate record
    # (cross-checked equal to the owner). The superseded identity is D1 history and its requal copy.
    assert found == {ADOPTED['runtime_sha256']: [OWNER, REQUAL], ADOPTED['executable_sha256']: [OWNER, REQUAL],
                     SUPERSEDED_RUNTIME: [D2, REQUAL], SUPERSEDED_EXECUTABLE: [D2, REQUAL]}
    for name, text in modules(repo_root).items():
        if name not in (OWNER, REQUAL):
            assert "'156.0.1'" not in text and '"156.0.1"' not in text, name
            assert '15626.9.21' not in text and '20260921121718' not in text, name


def test_matrix_aliases_the_owner_and_never_the_historical_binder(repo_root, monkeypatch):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_production as firefox
    import cnt_host_firefox_matrix as m
    assert m.firefox is firefox
    assert (m.ACCEPTED_RUNTIME, m.ACCEPTED_EXECUTABLE) == (firefox.RUNTIME, firefox.EXECUTABLE)
    tree = ast.parse((repo_root / MATRIX).read_text())
    assigned = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
                if isinstance(t, ast.Name)}
    # `is` cannot tell an alias from an interned same-valued literal; the syntax can.
    for name, attribute in (('ACCEPTED_RUNTIME', 'RUNTIME'), ('ACCEPTED_EXECUTABLE', 'EXECUTABLE')):
        value = assigned[name]
        assert isinstance(value, ast.Attribute) and value.attr == attribute
        assert isinstance(value.value, ast.Name) and value.value.id == 'firefox'
    d2_used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
               and isinstance(n.value, ast.Name) and n.value.id == 'd2'}
    assert not {'D1_RUNTIME', 'D1_EXECUTABLE', 'bind_runtime', 'tree_digest'} & d2_used
    owner_used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                  and isinstance(n.value, ast.Name) and n.value.id == 'firefox'}
    assert owner_used == {'RUNTIME', 'EXECUTABLE', 'bind_runtime', 'CODES'}
    binds = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == 'bind_runtime']
    assert len(binds) == 3 and all(n.func.value.id == 'firefox' for n in binds)
    hexes = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and re.fullmatch(r'[0-9a-f]{64}', n.value)}
    assert hexes == {TEMPLATE}


# 10 and 11. Malformed-D withheld; no captured-code path introduced --------------------------------

def test_adoption_introduces_no_malformed_d_handoff(repo_root):
    doc = (repo_root / DOC).read_text()
    readme = (repo_root / 'README.md').read_text()
    assert not re.findall(r'```(?:zsh|sh|bash)\n', doc)
    for text in (doc, readme):
        assert not re.search(r'cnt_host_firefox_matrix\.py\s+(bind|run)\b', text)
    assert 'malformed-D' in doc and 'withheld' in doc


def test_owner_and_requal_lane_never_call_into_the_matrix(repo_root):
    for name in (OWNER, REQUAL):
        tree = ast.parse((repo_root / name).read_text())
        called = {n.func.value.id for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)}
        assert not {'production', 'matrix', 'firefox'} & called, name


def test_matrix_budget_is_multipart_b_and_compat_e_is_consumed(repo_root, monkeypatch):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_host_firefox_matrix as m
    assert m.BUDGETS == {'multipart-b': {
        'claim': 'bux-r6-firefox-native-matrix-multipart-b.claim',
        'cases': ('S-MULTI', 'T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1', 'T-MULTI-NO-MIDDLE',
                  'T-MULTI-DUP', 'T-MULTI-TRUNC', 'T-MULTI-BADDATA'),
        'categories': ('B',)}}
    assert m.WITHHELD_CATEGORIES == ()
    assert m.RETIRED_BUDGETS == ('srich-repair2', 'rich-valid', 'malformed-d', 'compat-e')
    assert m.CONSUMED_HOST_CLAIMS[-2:] == (MALFORMED_D, 'bux-r6-firefox-native-matrix-compat-e.claim')
    # The matrix still aliases the one production owner; no identity is restated there.
    assert (m.ACCEPTED_RUNTIME, m.ACCEPTED_EXECUTABLE) == (m.firefox.RUNTIME, m.firefox.EXECUTABLE)


# 12. No retry, fallback or kill ------------------------------------------------------------------

def test_no_kill_or_retry_in_the_owner_or_matrix(repo_root):
    for name in (OWNER, MATRIX):
        source = (repo_root / name).read_text()
        for token in ('.kill(', '.terminate(', 'killpg', 'while True', 'retry('):
            assert token not in source, (name, token)


# Bookkeeping -------------------------------------------------------------------------------------

def test_new_sources_are_rostered_and_in_the_static_suite(repo_root):
    roster = json.loads((repo_root / 'tests/source-only-roster.json').read_text())
    for name in (OWNER, 'tests/cnt-firefox-production.test.py', DOC):
        assert name in roster
    checks = (repo_root / 'tests/command-checks.nix').read_text()
    assert '${../.}/tests/cnt-firefox-production.test.py' in checks
