"""Source-only tests for the attended scrollbar GUI kit. A fake host is injected:
no browser or live profile is touched; fixture HTTP tests use loopback only."""
import json
import plistlib
import re
import shutil
import stat
import threading
import urllib.request
import zipfile

import pytest


def require(condition, message='requirement failed'):
    if not condition:
        raise AssertionError(message)


def writable_copy(source, destination):
    """copytree keeps read-only store modes inside Nix builds; mutation copies must be writable."""
    shutil.copytree(source, destination, copy_function=shutil.copyfile)
    for path in [destination, *destination.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)


@pytest.fixture
def kit(load_module):
    return load_module('tests/scrollbar_gui_kit.py')


IDENTITY = {
    'chrome': {'selection': 'RUN_CURRENT_SYSTEM', 'bundle_id': 'com.google.Chrome', 'version': '149.0.7827.201',
               'executable_sha256': 'a' * 64, 'runtime_sha256': 'b' * 64, 'store_root_sha256': 'c' * 64,
               'signature_valid': True},
    'firefox': {'selection': 'ATTENDED_INSTALLED_FIREFOX_APP', 'version': '157.0',
                'bundle_identifier': 'org.mozilla.firefox', 'bundle_version': '15726.9.24',
                'build_id': '20260924084938',
                'runtime_sha256': 'e8e1a70613e1cc5750514e17f56781c06a07d5f31421cfcbf762a91c3d904407',
                'executable_sha256': '729e0ae83fca74cf143bbef68836c195b340fcc09566461243a075be9e6b959a',
                'signature_valid': True},
}


class FakeHandle:
    def __init__(self, code, on_wait=None):
        self.code, self.on_wait, self.waited = code, on_wait, False

    def poll(self):
        return self.code if self.waited else None

    def wait(self):
        if self.on_wait:
            self.on_wait()
        self.waited = True
        return self.code


@pytest.fixture
def host(kit, tmp_path):
    class FakeHost(kit.Host):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.procs = {'Google Chrome': {}, 'firefox': {}}  # process name -> {pid: command}
            self.pgrep_error = False
            self.mode = 'Always'
            self.exit_code = 0
            self.launched = []
            self.on_launch = None
            self.identity = json.loads(json.dumps(IDENTITY))
            self.unavailable = {}
            self.commands = []

        def run(self, argv, timeout=30):
            self.commands.append(argv)
            if argv[0] == '/usr/bin/pgrep':
                if self.pgrep_error:
                    return 3, ''
                pids = self.procs[argv[-1]]
                return (0, ''.join(f'{pid}\n' for pid in pids)) if pids else (1, '')
            if argv[:3] == ['/bin/ps', '-ww', '-p'] and argv[4:] == ['-o', 'command=']:
                command = {**self.procs['Google Chrome'], **self.procs['firefox']}.get(argv[3])
                return (1, '') if command is None else (0, command + '\n')
            if argv[:3] == ['/usr/bin/defaults', 'read', '-g']:
                return (0, self.mode + '\n') if self.mode else (1, '')
            raise AssertionError(f'unexpected command {argv}')

        def bind(self, browser):
            if browser in self.unavailable:
                raise kit.runtime.Unavailable(f'SELECTED_{browser.upper()}_UNAVAILABLE', self.unavailable[browser])
            app = tmp_path / 'apps' / browser
            return dict(self.identity[browser]), {'app': str(app), 'executable': str(app / 'bin')}

        def start(self, argv, log):
            require(stat.S_IMODE(log.parent.stat().st_mode) == 0o700, 'log outside the private root')
            self.launched.append(argv)
            return FakeHandle(self.exit_code, self.on_launch)

    home = tmp_path / 'home'
    support = home / 'Library/Application Support'
    (support / 'Google/Chrome').mkdir(parents=True)
    (support / 'Firefox').mkdir(parents=True)
    (support / 'Google/Chrome/Local State').write_text('{}')
    (support / 'Firefox/profiles.ini').write_text('[General]\n')
    managed = tmp_path / 'managed'
    managed.mkdir()
    (tmp_path / 'preferences').mkdir()
    return FakeHost(home=home, managed_root=managed, preferences_root=tmp_path / 'preferences',
                    firefox_app=tmp_path / 'apps/Firefox.app', chrome_selection=tmp_path / 'apps/selection',
                    user='observer')


def write_policy(host, domain, policy):
    (host.managed_root / f'{domain}.plist').write_bytes(plistlib.dumps(policy))


LIVE_SHAPE = {
    'com.google.Chrome': {'ExtensionSettings': {
        '*': {'installation_mode': 'allowed'},
        'oboonakemofpalcgghocfoadofidjkkk': {'installation_mode': 'force_installed'},
        'ddkjiahejlhfcafbddmgiahcphecmpfh': {'installation_mode': 'force_installed'}},
        'PasswordManagerEnabled': False},
    'org.mozilla.firefox': {'ExtensionSettings': {
        '*': {'installation_mode': 'allowed'},
        'keepassxc-browser@keepassxc.org': {'installation_mode': 'force_installed'}},
        'PasswordManagerEnabled': False},
}


def prepared(kit, host, tmp_path, name='scratch', work=None, sentinels=None):
    for domain, policy in LIVE_SHAPE.items():
        write_policy(host, domain, policy)
    scratch = tmp_path / name
    kit.prepare(scratch, host, work=work, sentinels=sentinels)
    return scratch


# prepare -------------------------------------------------------------------------------------

def test_prepare_creates_disposable_roots_and_records_only_digests(kit, host, tmp_path, repo_root):
    scratch = prepared(kit, host, tmp_path)
    for name in ('profiles/chrome', 'profiles/firefox', 'extension', 'site', 'private'):
        require((scratch / name).is_dir(), name)
    for name, digest in kit.MEMBER_SHA256.items():
        require(kit.sha256((scratch / 'extension' / name).read_bytes()) == digest, name)
    require((scratch / 'site/scrollbar-matrix.html').read_bytes()
            == (repo_root / kit.FIXTURE).read_bytes())
    require((scratch / 'site/scrollbar-toplayer-matrix.html').read_bytes()
            == (repo_root / kit.TOPLAYER_FIXTURE).read_bytes())
    require((scratch / 'site/scrollbar-shadow-sentinel-matrix.html').read_bytes()
            == (repo_root / kit.SHADOW_SENTINEL_FIXTURE).read_bytes())
    raw = (scratch / 'SESSION.json').read_text()
    session = json.loads(raw)
    require(str(tmp_path) not in raw, 'absolute path leaked into SESSION.json')
    require(session['schema'] == kit.SESSION_SCHEMA)
    require(session['host'] == {'AppleShowScrollBars': 'Always'})
    require(session['runtimes'] == IDENTITY, session['runtimes'])
    require(session['keepassxc_forced'] == list(kit.KEEPASSXC_IDS), session['keepassxc_forced'])
    require(session['policy_keys']['chrome'] == ['ExtensionSettings', 'PasswordManagerEnabled'])
    require(set(session['sentinels'].values()) - {'absent'} and
            all(len(v) == 64 or v == 'absent' for v in session['sentinels'].values()))
    require(len(kit.Session(scratch).entries) == 1)
    require('KeePassXC is reachable' in session['live_policy_scope'], session['live_policy_scope'])
    require([r.split(':')[0] for r in session['residuals']] == [
        'LIVE_POLICY_FORCE_INSTALL', 'FIREFOX_UPDATE_DRIFT', 'LOAD_ROUTE_POLICY_LEVEL_ONLY',
        'PERSISTENT_MANUAL_TOAST_SUSPENSION', 'ROOT_GUTTER_MATERIAL_HOLD', 'EARLY_CLOSED_ROOT_MANAGER_LIMIT',
        'SHADOW_AVAILABILITY_LIMITS'])
    require(any('Structural subtrees exceeding 60000 elements' in r for r in session['residuals']))
    require(any('independent of the CNT production pin' in r and 'no CNT recovery claim' in r for r in session['residuals']))


def test_prepare_splits_evidence_from_work_and_keeps_paths_private(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path, work=tmp_path / 'work')
    work = tmp_path / 'work'
    require(sorted(p.name for p in scratch.iterdir()) == ['SESSION.json', 'journal.jsonl'])
    for name in ('profiles/chrome', 'profiles/firefox', 'extension', 'site', 'private'):
        require((work / name).is_dir(), name)
    local = work / 'private/LOCAL.json'
    require(stat.S_IMODE(local.stat().st_mode) == 0o600)
    require(stat.S_IMODE(work.stat().st_mode) == 0o700 and stat.S_IMODE(scratch.stat().st_mode) == 0o700)
    data = json.loads(local.read_text())
    session = json.loads((scratch / 'SESSION.json').read_text())
    require(data['session_id'] == session['session_id'] and data['work'] == str(work))
    require(data['runtimes']['chrome']['executable'].endswith('chrome/bin'))
    require(str(tmp_path) not in (scratch / 'SESSION.json').read_text())


@pytest.mark.parametrize('layout', ['work-inside-evidence', 'evidence-inside-work'])
def test_prepare_refuses_nested_work_and_evidence(kit, host, tmp_path, layout):
    for domain, policy in LIVE_SHAPE.items():
        write_policy(host, domain, policy)
    scratch, work = ((tmp_path / 's', tmp_path / 's/w') if layout == 'work-inside-evidence'
                     else (tmp_path / 'w/s', tmp_path / 'w'))
    with pytest.raises(kit.KitError):
        kit.prepare(scratch, host, work=work)
    require(not (tmp_path / 's').exists() and not (tmp_path / 'w').exists())


@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_prepare_refuses_unavailable_runtime_and_creates_nothing(kit, host, tmp_path, browser):
    host.unavailable[browser] = 'SELECTION_ABSENT'
    with pytest.raises(kit.KitError, match=f'SELECTED_{browser.upper()}_UNAVAILABLE:SELECTION_ABSENT') as error:
        prepared(kit, host, tmp_path, work=tmp_path / 'work')
    require(error.value.code == f'SELECTED_{browser.upper()}_UNAVAILABLE')
    require(not (tmp_path / 'scratch').exists() and not (tmp_path / 'work').exists())


def test_prepare_records_unset_scrollbar_mode_as_automatic(kit, host, tmp_path):
    host.mode = ''
    scratch = prepared(kit, host, tmp_path)
    require(json.loads((scratch / 'SESSION.json').read_text())['host']['AppleShowScrollBars']
            == 'Automatic (unset)')


def test_prepare_refuses_existing_scratch(kit, host, tmp_path):
    (tmp_path / 'scratch').mkdir()
    with pytest.raises(kit.KitError, match='must not exist'):
        prepared(kit, host, tmp_path)


def test_prepare_refuses_scratch_inside_live_profile_root(kit, host, tmp_path):
    for domain, policy in LIVE_SHAPE.items():
        write_policy(host, domain, policy)
    with pytest.raises(kit.KitError, match='scratch inside'):
        kit.prepare(host.home / 'Library/Application Support/Firefox/kit', host)


def test_prepare_refuses_scratch_inside_repository(kit, host, repo_root):
    with pytest.raises(kit.KitError, match='scratch inside'):
        kit.prepare(repo_root / 'never-created-kit-scratch', host)
    require(not (repo_root / 'never-created-kit-scratch').exists())


def test_prepare_refuses_symlinked_ancestor(kit, host, tmp_path):
    (tmp_path / 'real').mkdir()
    (tmp_path / 'link').symlink_to(tmp_path / 'real')
    with pytest.raises(kit.KitError, match='symlinked ancestor'):
        kit.prepare(tmp_path / 'link/scratch', host)


CHROME = '/Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome'
MCP = {'Google Chrome': {
    '701': 'npm exec @playwright/mcp@latest --executable-path ' + CHROME,
    '702': 'npm exec chrome-devtools-mcp@latest --executablePath ' + CHROME}, 'firefox': {}}


def test_prepare_refuses_running_browsers(kit, host, tmp_path):
    host.procs['firefox']['801'] = '/Applications/Firefox.app/Contents/MacOS/firefox'
    with pytest.raises(kit.KitError, match='quit these browsers'):
        prepared(kit, host, tmp_path)
    require(not (tmp_path / 'scratch').exists())


def test_prepare_fails_closed_when_process_state_is_unknown(kit, host, tmp_path):
    host.pgrep_error = True
    with pytest.raises(kit.KitError, match='chrome:UNKNOWN'):
        prepared(kit, host, tmp_path)
    require(not (tmp_path / 'scratch').exists())


def test_prepare_ignores_mcp_process_name_collisions(kit, host, tmp_path):
    host.procs = json.loads(json.dumps(MCP))
    scratch = prepared(kit, host, tmp_path)
    require((scratch / 'SESSION.json').is_file())
    session = (scratch / 'SESSION.json').read_text()
    require('npm' not in session and not re.search(r'(?<![0-9a-f])701(?![0-9a-f])', session)
            and 'Nix Apps' not in session, 'process identity leaked into public session')
    require(host.procs == MCP, 'the MCP services are left alone')


def test_prepare_with_an_unreadable_candidate_is_unknown(kit, host, tmp_path):
    host.procs = json.loads(json.dumps(MCP))
    host.procs['Google Chrome']['703'] = None
    with pytest.raises(kit.KitError, match=r"\['chrome:UNKNOWN'\]"):
        prepared(kit, host, tmp_path)
    require(not (tmp_path / 'scratch').exists())


def test_begin_launch_refuses_a_real_chrome_but_not_mcp_collisions(kit, host, tmp_path):
    host.procs = json.loads(json.dumps(MCP))
    scratch = prepared(kit, host, tmp_path)
    host.procs['Google Chrome']['704'] = CHROME + ' --flag'
    with pytest.raises(kit.KitError, match=r"before a disposable launch: \['chrome'\]"):
        kit.begin_launch(scratch, 'chrome', host, 8123)
    require(host.launched == [])
    del host.procs['Google Chrome']['704']
    kit.begin_launch(scratch, 'chrome', host, 8123)
    require(len(host.launched) == 1 and host.procs == MCP)


STOP_POLICIES = {
    'scrollbar-registered': ('org.mozilla.firefox', {'ExtensionSettings': {
        'scrollbar-visibility@browser-ux': {'installation_mode': 'force_installed'}}}),
    'star-blocked': ('com.google.Chrome', {'ExtensionSettings': {'*': {'installation_mode': 'blocked'}}}),
    'blocklist-star': ('com.google.Chrome', {'ExtensionInstallBlocklist': ['*']}),
    'chrome-devtools-off': ('com.google.Chrome', {'DeveloperToolsAvailability': 2}),
    'chrome-devmode-off': ('com.google.Chrome', {'ExtensionDeveloperModeSettings': 1}),
    'chrome-types': ('com.google.Chrome', {'ExtensionAllowedTypes': ['theme']}),
    'firefox-devtools-off': ('org.mozilla.firefox', {'DisableDeveloperTools': True}),
    'firefox-addons-blocked': ('org.mozilla.firefox', {'BlockAboutAddons': True}),
}


@pytest.mark.parametrize('name', sorted(STOP_POLICIES))
def test_prepare_stops_on_unsafe_policy(kit, host, tmp_path, name):
    domain, policy = STOP_POLICIES[name]
    write_policy(host, domain, policy)
    with pytest.raises(kit.KitError, match='STOP'):
        kit.prepare(tmp_path / 'scratch', host)
    require(not (tmp_path / 'scratch').exists(), 'nothing is created after a STOP')


@pytest.mark.parametrize('policy,match', [
    ({'EnterprisePoliciesEnabled': True, 'BlockAboutAddons': True}, 'about:addons is blocked'),
    ({'EnterprisePoliciesEnabled': True, 'ExtensionSettings': {
        'scrollbar-visibility@browser-ux': {'installation_mode': 'force_installed'}}}, 'registered in live policy'),
])
def test_prepare_reads_firefox_macos_preferences_delivery(kit, host, tmp_path, policy, match):
    (host.preferences_root / 'org.mozilla.firefox.plist').write_bytes(plistlib.dumps(policy))
    with pytest.raises(kit.KitError, match=match):
        kit.prepare(tmp_path / 'scratch', host)
    require(not (tmp_path / 'scratch').exists())


def test_firefox_macos_preferences_force_installs_are_recorded(kit, host, tmp_path):
    (host.preferences_root / 'org.mozilla.firefox.plist').write_bytes(plistlib.dumps({
        'EnterprisePoliciesEnabled': True, 'ExtensionSettings': {
            '*': {'installation_mode': 'allowed'},
            'keepassxc-browser@keepassxc.org': {'installation_mode': 'force_installed'},
            'uBlock0@raymondhill.net': {'installation_mode': 'force_installed'}}}))
    stops, keys, forced = kit.classify_policy(host)
    require(stops == [] and forced == ['keepassxc-browser@keepassxc.org', 'uBlock0@raymondhill.net'], forced)
    require(keys['firefox'] == ['EnterprisePoliciesEnabled', 'ExtensionSettings'] and keys['chrome'] == [])


def test_managed_preferences_win_over_the_preferences_delivery(kit, host):
    (host.preferences_root / 'com.google.Chrome.plist').write_bytes(plistlib.dumps({'ExtensionDeveloperModeSettings': 1}))
    require(kit.classify_policy(host)[0] == ['chrome: extension developer mode is disabled'])
    write_policy(host, 'com.google.Chrome', {'ExtensionDeveloperModeSettings': 0})
    require(kit.classify_policy(host)[0] == [])


def test_prepare_reads_per_user_managed_policy(kit, host, tmp_path):
    (host.managed_root / 'observer').mkdir()
    (host.managed_root / 'observer/com.google.Chrome.plist').write_bytes(
        plistlib.dumps({'DeveloperToolsAvailability': 2}))
    with pytest.raises(kit.KitError, match='developer tools'):
        kit.prepare(tmp_path / 'scratch', host)


# launch ---------------------------------------------------------------------------------------

def test_launch_argv_is_isolated_and_exact(kit, tmp_path):
    work = tmp_path / 's'
    require(kit.launch_argv('chrome', work, '/sel/chrome', 8123) == [
        '/sel/chrome', f'--user-data-dir={work}/profiles/chrome', '--no-first-run',
        '--no-default-browser-check', '--use-mock-keychain', 'about:blank'])
    require(kit.launch_argv('firefox', work, '/sel/firefox', 8123) == [
        '/sel/firefox', '-profile', f'{work}/profiles/firefox', '-no-remote', '-new-instance', 'about:blank'])
    for argv in (kit.launch_argv(b, work, '/x', 8123) for b in kit.BROWSERS):
        require(not any('load-extension' in a or 'Default' in a for a in argv), argv)
        require(not any('scrollbar' in a for a in argv), argv)
        require(argv[-1] == 'about:blank', argv)


def test_launch_uses_the_bound_executable_and_journals_exit(kit, host, tmp_path, capsys):
    scratch = prepared(kit, host, tmp_path, work=tmp_path / 'work')
    work = tmp_path / 'work'
    require(kit.launch(scratch, 'firefox', host, 8123, work) == 0)
    host.exit_code = 3
    kit.launch(scratch, 'chrome', host, 8123, work)
    require([argv[0] for argv in host.launched] == [str(tmp_path / 'apps/firefox/bin'),
                                                     str(tmp_path / 'apps/chrome/bin')])
    require(all(f'{work}/profiles/' in ' '.join(argv) for argv in host.launched))
    entries = kit.Session(scratch).entries
    exits = {(e['browser'], e['result']) for e in entries if e.get('gate') == 'normal-exit'}
    require(exits == {('firefox', 'pass'), ('chrome', 'fail')}, exits)
    journal = (scratch / 'journal.jsonl').read_text()
    require(str(tmp_path) not in journal and '<work>/profiles/chrome' in journal, journal)
    out = capsys.readouterr().out
    require('Load Temporary Add-on' in out and 'deny every association prompt' in out, out)


def test_one_launch_per_browser_per_session(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.launch(scratch, 'chrome', host, 8123)
    with pytest.raises(kit.KitError, match='already launched'):
        kit.launch(scratch, 'chrome', host, 8123)
    require(len(host.launched) == 1)


@pytest.mark.parametrize('tamper', ['member', 'extra-member', 'fixture', 'toplayer-fixture', 'shadow-sentinel-fixture'])
def test_launch_and_serve_stop_when_scratch_copy_is_not_r8(kit, host, tmp_path, tamper):
    scratch = prepared(kit, host, tmp_path)
    if tamper == 'member':
        css = scratch / 'extension/scrollbars.css'
        css.write_text(css.read_text().replace('GrayText', 'CanvasText'))
    elif tamper == 'extra-member':
        (scratch / 'extension/extra.js').write_text('')
    elif tamper == 'fixture':
        site = scratch / 'site/scrollbar-matrix.html'
        site.write_text(site.read_text() + '<!-- edited -->')
    elif tamper == 'toplayer-fixture':
        site = scratch / 'site/scrollbar-toplayer-matrix.html'
        site.write_text(site.read_text() + '<!-- edited -->')
    else:
        site = scratch / 'site/scrollbar-shadow-sentinel-matrix.html'
        site.write_text(site.read_text() + '<!-- edited -->')
    with pytest.raises(kit.KitError, match='STOP: scratch copy changed'):
        kit.launch(scratch, 'chrome', host, 8123)
    require(host.launched == [], 'no browser starts on changed bytes')
    require(kit.Session(scratch).stopped)
    with pytest.raises(kit.KitError, match='stopped'):
        kit.serve(scratch, 0)
    require(kit.bundle(scratch)[0] == 'INCOMPLETE')


def test_serve_stops_when_fixture_copy_is_not_r8(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    site = scratch / 'site/scrollbar-matrix.html'
    site.write_text(site.read_text() + '<!-- edited -->')
    with pytest.raises(kit.KitError, match='served fixture is not R8'):
        kit.serve(scratch, 0)
    require(kit.Session(scratch).stopped)


def test_launch_stops_when_the_selected_runtime_becomes_unavailable(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    host.unavailable['chrome'] = 'CHROME_RUNTIME_NOT_STORE_APP'
    with pytest.raises(kit.KitError, match='SELECTED_CHROME_UNAVAILABLE:CHROME_RUNTIME_NOT_STORE_APP'):
        kit.launch(scratch, 'chrome', host, 8123)
    require(host.launched == [] and kit.Session(scratch).stopped)


@pytest.mark.parametrize('field', ['version', 'executable_sha256', 'runtime_sha256', 'store_root_sha256'])
def test_launch_stops_when_the_runtime_changed_since_prepare(kit, host, tmp_path, field):
    scratch = prepared(kit, host, tmp_path)
    host.identity['chrome'][field] = 'changed'
    with pytest.raises(kit.KitError, match='RUNTIME_CHANGED'):
        kit.launch(scratch, 'chrome', host, 8123)
    require(host.launched == [])


def test_launch_stops_when_host_scrollbar_mode_changed(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    host.mode = 'WhenScrolling'
    with pytest.raises(kit.KitError, match='HOST_SCROLLBAR_MODE_CHANGED'):
        kit.launch(scratch, 'firefox', host, 8123)
    require(host.launched == [])


def test_runtime_change_during_the_session_stops_after_exit(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    host.on_launch = lambda: host.identity['firefox'].update(version='158.0')
    with pytest.raises(kit.KitError, match='firefox RUNTIME_CHANGED during the session'):
        kit.launch(scratch, 'firefox', host, 8123)
    state = kit.Session(scratch)
    require(state.stopped and any(e.get('gate') == 'normal-exit' for e in state.entries))


@pytest.mark.parametrize('field', ['version', 'bundle_version', 'build_id', 'runtime_sha256', 'executable_sha256'])
def test_firefox_launch_stops_when_runtime_changed_since_prepare(kit, host, tmp_path, field):
    scratch = prepared(kit, host, tmp_path)
    host.identity['firefox'][field] = 'drifted_' + field
    with pytest.raises(kit.KitError, match='RUNTIME_CHANGED'):
        kit.launch(scratch, 'firefox', host, 8123)
    require(host.launched == [])


@pytest.mark.parametrize('field', ['version', 'bundle_version', 'build_id', 'runtime_sha256', 'executable_sha256'])
def test_firefox_runtime_drift_during_session_stops_after_exit(kit, host, tmp_path, field):
    scratch = prepared(kit, host, tmp_path)
    host.on_launch = lambda: host.identity['firefox'].update({field: 'drifted_' + field})
    with pytest.raises(kit.KitError, match='firefox RUNTIME_CHANGED during the session'):
        kit.launch(scratch, 'firefox', host, 8123)
    state = kit.Session(scratch)
    require(state.stopped and any(e.get('gate') == 'normal-exit' for e in state.entries))


def test_live_sentinel_change_stops_the_session(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    profiles = host.home / 'Library/Application Support/Firefox/profiles.ini'
    host.on_launch = lambda: profiles.write_text('[Profile9]\n')
    with pytest.raises(kit.KitError, match='STOP'):
        kit.launch(scratch, 'firefox', host, 8123)
    require(kit.Session(scratch).stopped)
    for call in (lambda: kit.record(scratch, 'firefox', 'c1', 'pass'),
                 lambda: kit.launch(scratch, 'chrome', host, 8123),
                 lambda: kit.serve(scratch, 0)):
        with pytest.raises(kit.KitError, match='stopped'):
            call()
    result, _ = kit.bundle(scratch)
    require(result == 'INCOMPLETE')


def test_wait_retained_never_signals_on_interrupt(kit):
    class Handle:
        calls = 0

        def wait(self):
            Handle.calls += 1
            if Handle.calls == 1:
                raise KeyboardInterrupt
            return 0
    printed = []
    require(kit.wait_retained(Handle(), printed.append) == 0 and Handle.calls == 2)
    require('never signals' in printed[0])


# record / journal -----------------------------------------------------------------------------

@pytest.mark.parametrize('args', [
    ('safari', 'c1', 'pass', ''), ('chrome', 'c99', 'pass', ''), ('chrome', 'normal-exit', 'pass', ''),
    ('chrome', 'c1', 'ok', ''), ('chrome', 'c1', 'pass', 'see <script>'), ('chrome', 'c1', 'pass', 'x' * 201),
    ('chrome', 'c1', 'pass', 'see /Users/observer/x'), ('chrome', 'c1', 'pass', 'see ~ home'),
])
def test_record_refuses_bad_input(kit, host, tmp_path, args):
    scratch = prepared(kit, host, tmp_path)
    with pytest.raises(kit.KitError):
        kit.record(scratch, *args[:3], note=args[3])


def advance_to_freshness(kit, scratch, host, browser='chrome', work=None):
    handle = kit.begin_launch(scratch, browser, host, 8123, work=work)
    kit.record(scratch, browser, 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, browser, request_barrier=0)
    token = kit.present_fixtures(scratch, browser)
    requests = [
        {'seq': i + 1, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
        for i, name in enumerate(kit.FIXTURE_NAMES)
    ]
    kit.prove_postload(scratch, browser, requests)
    return handle, token


def complete_rail_steps(kit, scratch, browser, token, barrier=10):
    kit.begin_rail_step(scratch, browser, 'disabled-reload', request_barrier=barrier)
    dis_reqs = [
        {'seq': barrier + 1, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [token]},
        {'seq': barrier + 2, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [token]},
    ]
    kit.prove_rail_step(scratch, browser, 'disabled-reload', dis_reqs)

    kit.begin_rail_step(scratch, browser, 'reenabled-reload', request_barrier=barrier + 10)
    reen_reqs = [
        {'seq': barrier + 11, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [token]},
        {'seq': barrier + 12, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [token]},
        {'seq': barrier + 13, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [token]},
    ]
    kit.prove_rail_step(scratch, browser, 'reenabled-reload', reen_reqs)


def advance_to_custom(kit, scratch, host, browser='chrome', work=None):
    handle, token = advance_to_freshness(kit, scratch, host, browser, work=work)
    complete_rail_steps(kit, scratch, browser, token)
    kit.record(scratch, browser, 'custom-rail-discriminator', 'pass')
    return handle, token


def exit_all(kit, scratch, host, code=0):
    for b in kit.BROWSERS:
        kit.end_launch(scratch, b, host, code)


def test_journal_chain_detects_tampering(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c1', 'pass')
    journal = scratch / 'journal.jsonl'
    journal.write_text(journal.read_text().replace('"result":"pass"', '"result":"fail"'))
    with pytest.raises(kit.KitError, match='chain broken'):
        kit.Session(scratch)


@pytest.mark.parametrize('first,second', [('pass', 'pass'), ('not-run', 'pass'), ('fail', 'pass'),
                                          ('fail', 'not-run'), ('fail', 'fail')])
def test_a_recorded_result_is_final_except_correction_to_fail(kit, host, tmp_path, first, second):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c11', first)
    with pytest.raises(kit.KitError, match='already recorded'):
        kit.record(scratch, 'chrome', 'c11', second)


@pytest.mark.parametrize('first', ['pass', 'not-run'])
def test_a_result_can_be_corrected_to_fail_and_then_never_back(kit, host, tmp_path, first):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c11', first)
    kit.record(scratch, 'chrome', 'c11', 'fail', note='second look')
    with pytest.raises(kit.KitError, match='already recorded as fail'):
        kit.record(scratch, 'chrome', 'c11', 'pass')
    require(kit.latest(kit.Session(scratch).entries)[('chrome', 'c11')] == 'fail')


def test_latest_keeps_a_fail_even_if_a_later_line_says_pass(kit):
    entries = [{'kind': 'observation', 'browser': 'chrome', 'gate': 'c1', 'result': r}
               for r in ('fail', 'pass', 'not-run')]
    require(kit.latest(entries) == {('chrome', 'c1'): 'fail'})


def record_all(kit, scratch, host, result='pass', skip=()):
    session = json.loads((scratch / 'SESSION.json').read_text())
    for browser in kit.BROWSERS:
        state = kit.Session(scratch)
        if not any(e['kind'] == 'launch' and e.get('browser') == browser for e in state.entries):
            advance_to_custom(kit, scratch, host, browser)
        if ('custom-rail-discriminator' in kit.required_gates(session)
            and (browser, 'custom-rail-discriminator') not in skip
            and result == 'pass'):
            if kit.latest(kit.Session(scratch).entries).get((browser, 'custom-rail-discriminator')) != 'pass':
                kit.record(scratch, browser, 'custom-rail-discriminator', 'pass')

        for gate in kit.required_gates(session) + kit._cases(session, 'related'):
            if gate in kit.AUTO_GATES or (browser, gate) in skip:
                continue
            if gate in kit.PRE_FIXTURE_GATES:
                if kit.latest(kit.Session(scratch).entries).get((browser, gate)) is not None:
                    continue
            if gate == 'custom-rail-discriminator':
                continue
            branch = ('RAIL_VISIBLE_USABLE' if result == 'pass' else 'FAIL' if result == 'fail' else 'NOT_RUN') if gate == 'root-gutter' else None
            early_branch = ('CAPTURED' if result == 'pass' else 'FAIL' if result == 'fail' else 'NOT_RUN') if gate == 'early-closed-root' else None
            kit.record(scratch, browser, gate, result, root_gutter=branch, early_closed_root=early_branch)


def test_verdict_pass_requires_every_core_gate_both_exits_and_always(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries)[0] == 'INCOMPLETE', 'exits not journaled')
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('PASS', []))
    require(kit.related_coverage(state.session, state.entries) == ('FULL', []))


def test_new_required_gates_gate_the_verdict(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    session = json.loads((scratch / 'SESSION.json').read_text())
    gates = kit.required_gates(session)
    attended_gates = {'fixed-bottom', 'visual-pointer-none', 'root-after', 'root-mask-clip',
                      'nested-overlay', 'pointer-priority', 'outside-click-escape',
                      'drag-track-wheel-budget', 'modal-popover-recovery', 'popover-stacks',
                      'fullscreen', 'host-css-attacks', 'lazy-parser-hydration',
                      'no-severe-layout-changes', 'root-gutter', 'system-colors-usable',
                      'handshake', 'closed-shadow-modal', 'closed-shadow-popover',
                      'late-shadow', 'dsd-fail-closed', 'budget-fail-closed', 'early-closed-root',
                      'coverage-throttle-recovery', 'detached-root-reattach',
                      'custom-rail-discriminator'}
    require(attended_gates <= set(gates), gates)
    record_all(kit, scratch, host, skip={('firefox', 'system-colors-usable')})
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('INCOMPLETE', ['firefox:system-colors-usable']))


def test_detached_root_reattach_gates_the_verdict(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'detached-root-reattach')})
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('INCOMPLETE', ['chrome:detached-root-reattach']))
    kit.record(scratch, 'chrome', 'detached-root-reattach', 'fail', note='popover did not recover on reattach')
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('FAIL', ['chrome:detached-root-reattach']))


def test_coverage_throttle_recovery_gates_the_verdict(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'coverage-throttle-recovery')})
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('INCOMPLETE', ['chrome:coverage-throttle-recovery']))
    kit.record(scratch, 'chrome', 'coverage-throttle-recovery', 'fail', note='batch did not recover')
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('FAIL', ['chrome:coverage-throttle-recovery']))


def test_verdict_incomplete_under_overlay_scrollbars(kit, host, tmp_path):
    host.mode = 'WhenScrolling'
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    result, reasons = kit.verdict(state.session, state.entries)
    require(result == 'INCOMPLETE' and any('not Always' in r for r in reasons), reasons)


def test_verdict_fail_and_related_gap_are_separate(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'c21'), ('firefox', 'c9')})
    kit.record(scratch, 'chrome', 'c21', 'fail')
    kit.record(scratch, 'firefox', 'c9', 'not-run')
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('INCOMPLETE', ['firefox:c9']))
    require(kit.related_coverage(state.session, state.entries) == ('PARTIAL', ['chrome:c21']))
    kit.record(scratch, 'firefox', 'c9', 'fail')
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('FAIL', ['firefox:c9']))
    require(kit.related_coverage(state.session, state.entries) == ('PARTIAL', ['chrome:c21']))


def test_fail_outranks_a_later_stop(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c11', 'fail')
    kit.stop(scratch, 'operator stopped')
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('FAIL', ['chrome:c11', 'stopped: operator stopped']))
    require(kit.bundle(scratch)[0] == 'FAIL')


def test_a_stop_without_a_fail_is_incomplete(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c11', 'pass')
    kit.stop(scratch, 'operator stopped')
    state = kit.Session(scratch)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict == 'INCOMPLETE')
    require(reasons[:2] == ['session stopped; no qualification claim', 'operator stopped'])
    require('firefox:FIXTURE_NOT_POSTLOAD_FRESH' in reasons)


def test_record_only_cases_never_gate(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    session = json.loads((scratch / 'SESSION.json').read_text())
    gates = kit.required_gates(session)
    require('c14' not in gates and 'c25' not in gates and 'c21' not in gates and
            'closed-shadow-top-layer' in gates and 'public-observation-chatgpt' not in gates and
            'foreign-realm-attempt' not in gates, gates)
    require({'c1', 'c9', 'c24', 'c26', 'c27', 'fixed-bottom', 'root-gutter', 'detached-root-reattach', 'custom-rail-discriminator'} <= set(gates), gates)
    kit.record(scratch, 'chrome', 'c14', 'fail', note='observed only')
    kit.record(scratch, 'chrome', 'public-observation-chatgpt', 'fail', note='chatgpt observation')
    kit.record(scratch, 'chrome', 'foreign-realm-attempt', 'fail', note='foreign realm attempt')


def test_root_gutter_unpaintable_fails_gate_as_material_hold(kit, host, tmp_path, repo_root, monkeypatch):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'root-gutter')})
    kit.record(scratch, 'chrome', 'root-gutter', 'fail', note='material hold', root_gutter='ROOT_GUTTER_UNPAINTABLE')
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict == 'FAIL', verdict)
    require('chrome:root-gutter' in reasons, reasons)
    summary = kit.summary_of(state)
    require(summary['root_gutter']['chrome'] == 'ROOT_GUTTER_UNPAINTABLE')



# bundle ---------------------------------------------------------------------------------------

def test_bundle_is_deterministic_and_privacy_safe(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    kit.record(scratch, 'chrome', 'c1', 'pass', note='bar visible')
    copy = tmp_path / 'copy'
    shutil.copytree(scratch, copy)
    first, second = kit.bundle(scratch), kit.bundle(copy)
    require(first == second, (first, second))
    out = scratch / f'bundle/{kit.EVIDENCE}'
    require(kit.sha256(out.read_bytes()) == first[1])
    require((out.parent / (out.name + '.sha256')).read_text().split()[0] == first[1])
    with zipfile.ZipFile(out) as archive:
        require(archive.namelist() == ['MEMBERS.sha256', 'SESSION.json', 'SUMMARY.json', 'journal.jsonl'])
        for info in archive.infolist():
            require(info.date_time == (1980, 1, 1, 0, 0, 0))
            require(str(tmp_path).encode() not in archive.read(info), info.filename)
            require(b'LOCAL' not in archive.read(info) and b'executable"' not in archive.read(info))
        summary = json.loads(archive.read('SUMMARY.json'))
    require(summary['verdict'] == 'INCOMPLETE' and summary['related_frames'] == 'PARTIAL')
    with pytest.raises(kit.KitError, match='already written'):
        kit.bundle(scratch)


@pytest.mark.parametrize('planted', ['home', 'store', 'users', 'work', 'user-segment'])
def test_bundle_privacy_guard_refuses_planted_paths(kit, host, tmp_path, planted):
    scratch = prepared(kit, host, tmp_path, work=tmp_path / 'work')
    session = json.loads((scratch / 'SESSION.json').read_text())
    session['planted'] = {'home': str(kit.Path.home()) + '/x', 'store': '/nix/store/abc-chrome',
                          'users': '/Users/someone', 'work': str(tmp_path / 'work'),
                          'user-segment': 'C:/observer/'}[planted]
    (scratch / 'SESSION.json').write_text(json.dumps(session))
    with pytest.raises(kit.KitError, match='PRIVACY_GUARD') as error:
        kit.bundle(scratch, (str(tmp_path / 'work'),), 'observer')
    require(error.value.code == 'PRIVACY_GUARD')
    require(not (scratch / 'bundle').exists(), 'nothing is written after a privacy refusal')


def test_privacy_guard_matches_the_user_only_as_a_path_segment(kit):
    require(kit.privacy_problems({'a': b'observers observed'}, (), 'observer') == [])
    require(kit.privacy_problems({'a': b'"x/observer"'}, (), 'observer') == ['a'])
    require(kit.privacy_problems({'a': b'x/observer/y'}, (), 'observer') == ['a'])
    require(kit.privacy_problems({'a': b'/var/folders/q'}, (), '') == ['a'])


def test_kit_verifies_r8_source_identity(kit, repo_root, tmp_path):
    kit.verify_sources(repo_root)
    fake = tmp_path / 'repo'
    writable_copy(repo_root / kit.EXTENSION_DIR, fake / kit.EXTENSION_DIR)
    (fake / 'tests/fixtures/browser-preferences').mkdir(parents=True)
    shutil.copyfile(repo_root / 'tests/browser_preferences.py', fake / 'tests/browser_preferences.py')
    shutil.copyfile(repo_root / kit.FIXTURE, fake / kit.FIXTURE)
    shutil.copyfile(repo_root / kit.TOPLAYER_FIXTURE, fake / kit.TOPLAYER_FIXTURE)
    shutil.copyfile(repo_root / kit.SHADOW_SENTINEL_FIXTURE, fake / kit.SHADOW_SENTINEL_FIXTURE)
    kit.verify_sources(fake)
    css = fake / kit.EXTENSION_DIR / 'scrollbars.css'
    css.write_text(css.read_text().replace('GrayText', 'CanvasText'))
    with pytest.raises(kit.KitError, match='not R8'):
        kit.verify_sources(fake)


def test_early_closed_root_requires_explicit_consistent_observation(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    for branch, result in ((None, 'pass'), ('CAPTURED', 'fail'),
                           ('NOT_CAPTURED_FAIL_CLOSED', 'pass'),
                           ('FAIL', 'pass'), ('NOT_RUN', 'pass')):
        with pytest.raises(kit.KitError):
            kit.record(scratch, 'chrome', 'early-closed-root', result, early_closed_root=branch)


def test_early_closed_root_not_captured_fail_closed_fails_gate_with_manager_limit(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'early-closed-root')})
    kit.record(scratch, 'chrome', 'early-closed-root', 'fail', note='manager limit', early_closed_root='NOT_CAPTURED_FAIL_CLOSED')
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict == 'FAIL', verdict)
    require('chrome:early-closed-root' in reasons, reasons)
    require(any('NOT_CAPTURED_FAIL_CLOSED' in r for r in reasons), reasons)
    summary = kit.summary_of(state)
    require(summary['early_closed_root']['chrome'] == 'NOT_CAPTURED_FAIL_CLOSED')


def test_early_closed_root_captured_passes_gate(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict == 'PASS', (verdict, reasons))
    summary = kit.summary_of(state)
    require(summary['early_closed_root'] == {'chrome': 'CAPTURED', 'firefox': 'CAPTURED'})


def test_kit_has_no_live_mutation_surface(repo_root):
    source = (repo_root / 'tests/scrollbar_gui_kit.py').read_text()
    for token in ('defaults write', "'write'", 'rmtree', 'unlink(', 'Managed Preferences/com',
                  'load-extension', 'web-ext', 'sign(', 'killall', 'pkill', 'sudo', '0.0.0.0',
                  '.kill(', '.terminate(', 'send_signal', 'os.kill', '/Applications/Google Chrome.app'):
        require(token not in source, token)
    require("('127.0.0.1', port)" in source)
    require('start_new_session=True' in source and 'stdin=subprocess.DEVNULL' in source)


def test_root_gutter_requires_explicit_consistent_observation(kit, host, tmp_path, repo_root, monkeypatch):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    for branch, result in ((None, 'pass'), ('ROOT_GUTTER_UNPAINTABLE', 'pass'),
                           ('NATIVE_UNOCCLUDED', 'pass'),
                           ('RAIL_VISIBLE_USABLE', 'fail'), ('NOT_RUN', 'pass')):
        with pytest.raises(kit.KitError):
            kit.record(scratch, 'chrome', 'root-gutter', result, root_gutter=branch)


def test_root_gutter_native_unoccluded_fails_gate_as_disqualification(kit, host, tmp_path, repo_root, monkeypatch):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'root-gutter')})
    kit.record(scratch, 'chrome', 'root-gutter', 'fail', note='native only', root_gutter='NATIVE_UNOCCLUDED')
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict == 'FAIL', verdict)
    require('chrome:root-gutter' in reasons, reasons)
    require(any('NATIVE_UNOCCLUDED' in r for r in reasons), reasons)
    summary = kit.summary_of(state)
    require(summary['root_gutter']['chrome'] == 'NATIVE_UNOCCLUDED')


def test_root_challenge_scene_linkage_to_root_gutter_branch(kit, host, tmp_path, repo_root, monkeypatch):
    scratch = prepared(kit, host, tmp_path)
    advance_to_custom(kit, scratch, host, 'chrome')
    # 1. Challenge scenes cannot pass if root-gutter already failed as NATIVE_UNOCCLUDED
    kit.record(scratch, 'chrome', 'root-gutter', 'fail', root_gutter='NATIVE_UNOCCLUDED')
    with pytest.raises(kit.KitError, match='root-gutter branch is NATIVE_UNOCCLUDED'):
        kit.record(scratch, 'chrome', 'root-after', 'pass')
    with pytest.raises(kit.KitError, match='root-gutter branch is NATIVE_UNOCCLUDED'):
        kit.record(scratch, 'chrome', 'root-mask-clip', 'pass')

    # 2. A rail observation never overrides an already failed challenge scene.
    scratch2 = prepared(kit, host, tmp_path, name='scratch2')
    advance_to_custom(kit, scratch2, host, 'chrome')
    kit.record(scratch2, 'chrome', 'root-after', 'fail')
    kit.record(scratch2, 'chrome', 'root-gutter', 'pass', root_gutter='RAIL_VISIBLE_USABLE')
    state2 = kit.Session(scratch2)
    require(kit.verdict(state2.session, state2.entries)[0] == 'FAIL')

    # 3. verdict linkage: if challenge scenes were passed but root-gutter is not RAIL_VISIBLE_USABLE, verdict flags linkage
    scratch3 = prepared(kit, host, tmp_path, name='scratch3')
    record_all(kit, scratch3, host, skip={('chrome', 'root-gutter')})
    kit.record(scratch3, 'chrome', 'root-gutter', 'fail', root_gutter='ROOT_GUTTER_UNPAINTABLE')
    exit_all(kit, scratch3, host, 0)
    state3 = kit.Session(scratch3)
    verdict, reasons = kit.verdict(state3.session, state3.entries)
    require(verdict == 'FAIL', verdict)
    require(any('challenge scene cannot qualify without root-gutter RAIL_VISIBLE_USABLE' in r for r in reasons), reasons)


def test_root_challenges_pending_without_root_gutter_are_incomplete(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host, skip={('chrome', 'root-gutter')})
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries)[0] == 'INCOMPLETE')


# R9 attended freshness and custom rail tests --------------------------------------------------

def test_r9_neutral_argv_chrome_and_firefox(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    for browser in kit.BROWSERS:
        for port in (0, 8123):
            argv = kit.launch_argv(browser, scratch, f'/bin/{browser}', port=port)
            require(argv[-1] == 'about:blank', (browser, port, argv))
            for arg in argv:
                require('scrollbar-matrix.html' not in arg, arg)
                require('scrollbar-toplayer-matrix.html' not in arg, arg)
                require('scrollbar-shadow-sentinel-matrix.html' not in arg, arg)
                require('http://' not in arg, arg)


def test_r9_phase_order_and_token_session_binding(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    state = kit.Session(scratch)
    # Before launch, phase is None
    require(kit.browser_phase(state.entries, 'chrome') is None)

    # Cannot mark extension loaded or present fixtures before launch
    with pytest.raises(kit.KitError, match='must be launched'):
        kit.mark_extension_loaded(scratch, 'chrome', request_barrier=0)
    with pytest.raises(kit.KitError, match='present_fixtures requires EXTENSION_LOADED phase'):
        kit.present_fixtures(scratch, 'chrome')

    # Launch browser
    kit.begin_launch(scratch, 'chrome', host, 8123)
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'LAUNCHED')

    # Cannot mark extension loaded without extension-loaded pass recorded
    with pytest.raises(kit.KitError, match='extension-loaded must pass'):
        kit.mark_extension_loaded(scratch, 'chrome', request_barrier=0)

    # Record extension-loaded pass and mark phase
    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, 'chrome', request_barrier=5)
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'EXTENSION_LOADED')

    # Exactly one EXTENSION_LOADED phase allowed
    with pytest.raises(kit.KitError, match='EXTENSION_LOADED phase allowed only once'):
        kit.mark_extension_loaded(scratch, 'chrome', request_barrier=5)

    # Cannot prove postload before fixtures-presented
    with pytest.raises(kit.KitError, match='prove_postload requires fixtures-presented phase'):
        kit.prove_postload(scratch, 'chrome', [])

    # Present fixtures generates hex16 token bound to session
    token = kit.present_fixtures(scratch, 'chrome')
    require(isinstance(token, str) and len(token) == 32 and re.fullmatch(r'[0-9a-f]{32}', token))
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'fixtures-presented')
    pres = [e for e in state.entries if e.get('kind') == 'fixtures-presented' and e.get('browser') == 'chrome']
    require(len(pres) == 1)
    require(pres[0]['session_id'] == state.session['session_id'])
    require(pres[0]['token'] == token)

    # Proving postload transitions through FIXTURES_OPENED_POSTLOAD to VISUAL_GATES
    reqs = [
        {'seq': 6 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
        for i, name in enumerate(kit.FIXTURE_NAMES)
    ]
    kit.prove_postload(scratch, 'chrome', reqs)
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'VISUAL_GATES')
    kinds = [e.get('kind') for e in state.entries]
    require('FIXTURES_OPENED_POSTLOAD' in kinds and 'VISUAL_GATES' in kinds)


def test_r9_prove_postload_failures_and_stop(kit, host, tmp_path):
    scenarios = [
        ('missing_matrix', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('missing_toplayer', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [tok]},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('missing_shadow_sentinel', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [tok]},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
        ]),
        ('preload_barrier', lambda tok: [
            {'seq': 4, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [tok]},
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('stale_token', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': ['0123456789abcdef0123456789abcdef']},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 12, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('no_token', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': []},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 12, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('multiple_tokens', lambda tok: [
            {'seq': 10, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [tok, 'extra']},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 12, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
        ('head_rejected', lambda tok: [
            {'seq': 10, 'method': 'HEAD', 'path': '/scrollbar-matrix.html', 'qual': [tok]},
            {'seq': 11, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [tok]},
            {'seq': 12, 'method': 'GET', 'path': '/scrollbar-shadow-sentinel-matrix.html', 'qual': [tok]},
        ]),
    ]

    for name, req_fn in scenarios:
        scratch = prepared(kit, host, tmp_path, name=f'scratch_{name}')
        kit.begin_launch(scratch, 'chrome', host, 8123)
        kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
        kit.mark_extension_loaded(scratch, 'chrome', request_barrier=5)
        token = kit.present_fixtures(scratch, 'chrome')
        bad_reqs = req_fn(token)
        with pytest.raises(kit.KitError, match='FIXTURE_NOT_POSTLOAD_FRESH') as err:
            kit.prove_postload(scratch, 'chrome', bad_reqs)
        require(err.value.code == 'FIXTURE_NOT_POSTLOAD_FRESH')
        state = kit.Session(scratch)
        stops = [e for e in state.entries if e.get('kind') == 'stop']
        require(len(stops) == 1 and stops[0]['reason'] == 'FIXTURE_NOT_POSTLOAD_FRESH')
        verdict, reasons = kit.verdict(state.session, state.entries)
        require(verdict == 'INCOMPLETE')
        require(any('session stopped' in r for r in reasons))


def test_r9_visual_recording_refused_before_freshness(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.begin_launch(scratch, 'chrome', host, 8123)

    # In LAUNCHED phase: PRE_FIXTURE_GATES are permitted
    kit.record(scratch, 'chrome', 'manifest-known-warnings-only', 'pass')
    # But visual gates (fixture cases, challenge scenes, record-only) are prohibited
    for gate in ('c1', 'c27', 'fixed-bottom', 'root-gutter', 'public-observation-chatgpt', 'nested-overlay'):
        with pytest.raises(kit.KitError, match='cannot be recorded before VISUAL_GATES phase'):
            kit.record(scratch, 'chrome', gate, 'pass')

    # Transition to EXTENSION_LOADED
    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, 'chrome', 0)
    with pytest.raises(kit.KitError, match='cannot be recorded before VISUAL_GATES phase'):
        kit.record(scratch, 'chrome', 'c1', 'pass')

    # Transition to fixtures-presented
    token = kit.present_fixtures(scratch, 'chrome')
    with pytest.raises(kit.KitError, match='cannot be recorded before VISUAL_GATES phase'):
        kit.record(scratch, 'chrome', 'c1', 'pass')

    # Prove postload enters VISUAL_GATES
    reqs = [{'seq': i + 1, 'method': 'GET', 'path': f'/{n}', 'qual': [token]} for i, n in enumerate(kit.FIXTURE_NAMES)]
    kit.prove_postload(scratch, 'chrome', reqs)
    # Now in VISUAL_GATES phase
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'VISUAL_GATES')
    # Record-only gates like public-observation-chatgpt are now allowed
    kit.record(scratch, 'chrome', 'public-observation-chatgpt', 'not-reproduced', note='visual inspection confirmed')


def test_r9_chrome_and_firefox_independent_barriers(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.begin_launch(scratch, 'chrome', host, 8123)
    kit.begin_launch(scratch, 'firefox', host, 8123)

    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.record(scratch, 'firefox', 'extension-loaded', 'pass')

    # Chrome gets barrier 10; Firefox gets barrier 20
    kit.mark_extension_loaded(scratch, 'chrome', request_barrier=10)
    kit.mark_extension_loaded(scratch, 'firefox', request_barrier=20)

    tok_c = kit.present_fixtures(scratch, 'chrome')
    tok_f = kit.present_fixtures(scratch, 'firefox')
    require(tok_c != tok_f)

    # Requests at seq 15 with Chrome's token satisfy Chrome (15 > 10)
    c_reqs = [{'seq': 15 + i, 'method': 'GET', 'path': f'/{n}', 'qual': [tok_c]} for i, n in enumerate(kit.FIXTURE_NAMES)]
    kit.prove_postload(scratch, 'chrome', c_reqs)
    require(kit.browser_phase(kit.Session(scratch).entries, 'chrome') == 'VISUAL_GATES')

    # But seq 15 with Firefox's token fails Firefox (15 <= 20)
    f_stale_reqs = [{'seq': 15 + i, 'method': 'GET', 'path': f'/{n}', 'qual': [tok_f]} for i, n in enumerate(kit.FIXTURE_NAMES)]
    with pytest.raises(kit.KitError, match='FIXTURE_NOT_POSTLOAD_FRESH'):
        kit.prove_postload(scratch, 'firefox', f_stale_reqs)


def test_r9_fixture_server_banner_and_cache_byte_identity(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    server = kit.fixture_server(scratch, 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        orig_matrix = (scratch / 'site/scrollbar-matrix.html').read_bytes()
        orig_toplayer = (scratch / 'site/scrollbar-toplayer-matrix.html').read_bytes()
        orig_shadow = (scratch / 'site/scrollbar-shadow-sentinel-matrix.html').read_bytes()

        # 1. Bare GET without qual returns byte-identical original and Cache-Control: no-store
        req = urllib.request.Request(f'{base_url}/scrollbar-matrix.html')
        with urllib.request.urlopen(req) as resp:
            require(resp.status == 200)
            require(resp.headers.get('Cache-Control') == 'no-store')
            body = resp.read()
            require(body == orig_matrix)

        # 2. Bypasses If-Modified-Since (returns 200, not 304)
        req_ims = urllib.request.Request(f'{base_url}/scrollbar-matrix.html',
                                         headers={'If-Modified-Since': 'Wed, 21 Oct 2015 07:28:00 GMT'})
        with urllib.request.urlopen(req_ims) as resp:
            require(resp.status == 200)
            require(resp.read() == orig_matrix)

        # 3. Stale token returns byte-identical original
        server.set_qualification('abcdef0123456789abcdef0123456789')
        with urllib.request.urlopen(f'{base_url}/scrollbar-matrix.html?qual=wrongtoken') as resp:
            require(resp.read() == orig_matrix)

        # 4. Subframe with qualifying token returns byte-identical original (no banner)
        with urllib.request.urlopen(f'{base_url}/scrollbar-matrix.html?qual=abcdef0123456789abcdef0123456789&frame=same') as resp:
            require(resp.read() == orig_matrix)

        # 5. Other fixtures with qualifying token return byte-identical original
        with urllib.request.urlopen(f'{base_url}/scrollbar-toplayer-matrix.html?qual=abcdef0123456789abcdef0123456789') as resp:
            require(resp.read() == orig_toplayer.replace(kit.SCENE_MENU_ASSIGNMENT,
                b"location.search = '?qual=abcdef0123456789abcdef0123456789&scene=' + encodeURIComponent(menu.value);"))
        with urllib.request.urlopen(f'{base_url}/scrollbar-shadow-sentinel-matrix.html?qual=abcdef0123456789abcdef0123456789') as resp:
            require(resp.read() == orig_shadow.replace(kit.SCENE_MENU_ASSIGNMENT,
                b"location.search = '?qual=abcdef0123456789abcdef0123456789&scene=' + encodeURIComponent(menu.value);"))

        # 6. Qualifying matrix (no frame) receives POST-EXTENSION QUALIFICATION PAGE banner
        with urllib.request.urlopen(f'{base_url}/scrollbar-matrix.html?qual=abcdef0123456789abcdef0123456789') as resp:
            qualified_body = resp.read()
            require(b'POST-EXTENSION QUALIFICATION PAGE' in qualified_body)
            require(kit.POST_EXTENSION_QUALIFICATION_BANNER in qualified_body)
            # On-disk file is preserved byte-identically
            require((scratch / 'site/scrollbar-matrix.html').read_bytes() == orig_matrix)

        # 7. Server snapshot records request sequence and qual list
        snaps = server.snapshot_requests()
        require(len(snaps) >= 6)
        for s in snaps:
            require(set(s.keys()) == {'seq', 'method', 'path', 'qual'})
            require(isinstance(s['qual'], list))
            require('header' not in s and 'headers' not in s and 'url' not in s)
        require(server.request_barrier() == len(snaps))
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize('defect', ['matrix-only', 'toplayer-only', 'stale-seq', None])
def test_r9_ordered_dual_page_comparison_requirement(kit, host, tmp_path, defect):
    scratch = prepared(kit, host, tmp_path)
    _, token = advance_to_freshness(kit, scratch, host, 'chrome')
    with pytest.raises(kit.KitError, match='requires prior DISABLED_COMPARISON_FRESH'):
        kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 10)
    kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 10)
    with pytest.raises(kit.KitError, match='requires prior VISUAL_GATES'):
        kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 10)
    valid_dis = [
        {'seq': 11, 'method': 'GET', 'path': '/scrollbar-matrix.html', 'qual': [token]},
        {'seq': 12, 'method': 'GET', 'path': '/scrollbar-toplayer-matrix.html', 'qual': [token]},
    ]
    if defect is not None:
        requests = valid_dis[:1] if defect == 'matrix-only' else valid_dis[1:] if defect == 'toplayer-only' else [dict(valid_dis[0], seq=10), valid_dis[1]]
        with pytest.raises(kit.KitError) as error:
            kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', requests)
        require(error.value.code == 'RAIL_COMPARISON_NOT_PROVEN')
        require(kit.Session(scratch).stopped)
        return
    kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', valid_dis)
    state = kit.Session(scratch)
    proof = next(e for e in state.entries if e['kind'] == 'DISABLED_COMPARISON_FRESH')
    require(proof['token'] == token and proof['barrier'] == 10)
    require(proof['basenames'] == list(kit.FIXTURE_NAMES[:2]))
    require(proof['seqs'] == {'scrollbar-matrix.html': 11, 'scrollbar-toplayer-matrix.html': 12})
    with pytest.raises(kit.KitError, match='requires EXTENSION_DISABLED'):
        kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', valid_dis)
    kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 15)
    valid_reen = [{'seq': 16 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
                  for i, name in enumerate(kit.FIXTURE_NAMES)]
    kit.prove_rail_step(scratch, 'chrome', 'reenabled-reload', valid_reen)
    require(kit.browser_phase(kit.Session(scratch).entries, 'chrome') == 'SENTINEL_VISUAL_GATES')


def test_r9_custom_gate_prerequisite_and_native_only_failure(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    handle, token = advance_to_freshness(kit, scratch, host, 'chrome')

    # 1. custom-rail-discriminator cannot pass without completed rail steps
    with pytest.raises(kit.KitError, match='FIXTURE_NOT_POSTREENABLE_FRESH'):
        kit.record(scratch, 'chrome', 'custom-rail-discriminator', 'pass')

    # Complete the rail steps
    complete_rail_steps(kit, scratch, 'chrome', token)

    # 2. CUSTOM_RAIL_GATES cannot pass without prior custom-rail-discriminator pass
    for gate in ('c1', 'root-after', 'fixed-bottom', 'root-gutter'):
        with pytest.raises(kit.KitError, match='cannot pass without prior custom-rail-discriminator pass'):
            kit.record(scratch, 'chrome', gate, 'pass', root_gutter='RAIL_VISIBLE_USABLE' if gate == 'root-gutter' else None)

    # Now pass custom-rail-discriminator
    kit.record(scratch, 'chrome', 'custom-rail-discriminator', 'pass')
    # Custom gate pass now succeeds
    kit.record(scratch, 'chrome', 'c1', 'pass')

    # 3. Handwritten journal laundering detection in verdict:
    # If a custom gate pass is planted before custom-rail-discriminator in entries, verdict flags it as FAIL
    state = kit.Session(scratch)
    entries_tampered = list(state.entries)
    # Move c1 pass before custom-rail-discriminator
    c1_entry = [e for e in entries_tampered if e.get('gate') == 'c1'][0]
    entries_tampered.remove(c1_entry)
    disc_idx = next(i for i, e in enumerate(entries_tampered) if e.get('gate') == 'custom-rail-discriminator')
    entries_tampered.insert(disc_idx, c1_entry)
    v, reasons = kit.verdict(state.session, entries_tampered)
    require(v == 'FAIL')
    require(any('passed before custom-rail-discriminator pass' in r for r in reasons))

    # 4. Native-only remains failure
    scratch_nat = prepared(kit, host, tmp_path, name='scratch_nat')
    advance_to_custom(kit, scratch_nat, host, 'chrome')
    kit.record(scratch_nat, 'chrome', 'root-gutter', 'fail', note='native scrollbar only', root_gutter='NATIVE_UNOCCLUDED')
    state_nat = kit.Session(scratch_nat)
    v_nat, reasons_nat = kit.verdict(state_nat.session, state_nat.entries)
    require(v_nat == 'FAIL')
    require('chrome:root-gutter' in reasons_nat)
    require(any('NATIVE_UNOCCLUDED' in r for r in reasons_nat))


def test_r9_old_schema_no_resume(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    session_file = scratch / 'SESSION.json'
    session = json.loads(session_file.read_text())
    session['schema'] = 'bux5c0-r8-session-v1'
    session_file.write_text(json.dumps(session))

    state = kit.Session(scratch)
    with pytest.raises(kit.KitError, match='unsupported session schema'):
        state.active()

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.mark_extension_loaded(scratch, 'chrome', 0)

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.present_fixtures(scratch, 'chrome')

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.prove_postload(scratch, 'chrome', [])

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 0)

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', [])

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.record(scratch, 'chrome', 'c1', 'pass')

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.begin_launch(scratch, 'chrome', host, 8123)

    with pytest.raises(kit.KitError, match='unsupported session schema'):
        kit.stop(scratch, 'manual stop')


def test_r9_postload_journal_persists_current_session_get_evidence(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    _, token = advance_to_freshness(kit, scratch, host, 'chrome')
    state = kit.Session(scratch)
    proof = next(e for e in state.entries if e['kind'] == 'FIXTURES_OPENED_POSTLOAD')
    barrier = next(e['barrier'] for e in state.entries if e['kind'] == 'EXTENSION_LOADED')
    require(proof['token'] == token and proof['session_id'] == state.session['session_id'])
    require(proof['method'] == 'GET' and set(proof['seqs']) == set(kit.FIXTURE_NAMES))
    require(all(seq > barrier for seq in proof['seqs'].values()))
    require(proof['seq'] > next(e['seq'] for e in state.entries if e.get('gate') == 'extension-loaded'))
    for field in ('url', 'headers', 'port', 'path'):
        require(field not in proof)


@pytest.mark.parametrize('defect', ['missing', 'stale-token', 'foreign-session', 'preload',
                                  'head', 'repeated-seq', 'rail-stale-token', 'rail-foreign-session'])
def test_r9_phase_names_without_valid_request_evidence_never_qualify(kit, host, tmp_path, defect):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    exit_all(kit, scratch, host, 0)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('PASS', []))
    entries = json.loads(json.dumps(state.entries))
    kind = 'DISABLED_COMPARISON_FRESH' if defect.startswith('rail-') else 'FIXTURES_OPENED_POSTLOAD'
    proof = next(e for e in entries if e['kind'] == kind)
    if defect == 'missing':
        proof.pop('seqs')
    elif defect.endswith('stale-token'):
        proof['token'] = 'f' * 32 if proof['token'] != 'f' * 32 else 'e' * 32
    elif defect.endswith('foreign-session'):
        proof['session_id'] = '0' * 32
    elif defect == 'preload':
        barrier = next(e['barrier'] for e in entries if e['kind'] == 'EXTENSION_LOADED')
        proof['seqs'][kit.FIXTURE_NAMES[0]] = barrier
    elif defect == 'head':
        proof['method'] = 'HEAD'
    else:
        proof['seqs'] = dict.fromkeys(kit.FIXTURE_NAMES, 100)
    verdict, reasons = kit.verdict(state.session, entries)
    require(verdict != 'PASS' and any('FIXTURE_NOT_POSTLOAD_FRESH' in r for r in reasons), reasons)
    with pytest.raises(kit.KitError):
        kit.browser_phase(entries, 'chrome')


def test_r9_old_journal_cannot_be_attached_to_a_new_session(kit, host, tmp_path):
    old = prepared(kit, host, tmp_path, name='old')
    advance_to_custom(kit, old, host, 'chrome')
    new = prepared(kit, host, tmp_path, name='new')
    (new / 'journal.jsonl').write_bytes((old / 'journal.jsonl').read_bytes())
    with pytest.raises(kit.KitError, match='journal belongs to another session'):
        kit.record(new, 'chrome', 'c1', 'pass')
    state = kit.Session(new)
    verdict, reasons = kit.verdict(state.session, state.entries)
    require(verdict != 'PASS' and any('foreign session journal' in r for r in reasons))


def test_r9_comparison_barriers_cannot_reuse_previous_reload_requests(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    _, token = advance_to_freshness(kit, scratch, host, 'chrome')
    with pytest.raises(kit.KitError, match='barrier regressed'):
        kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 0)
    kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 10)
    requests = [{'seq': 11 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
                for i, name in enumerate(kit.FIXTURE_NAMES[:2])]
    kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', requests)
    with pytest.raises(kit.KitError, match='barrier regressed'):
        kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 10)
    kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 12)
    with pytest.raises(kit.KitError) as error:
        kit.prove_rail_step(scratch, 'chrome', 'reenabled-reload', requests)
    require(error.value.code == 'FIXTURE_NOT_POSTREENABLE_FRESH')


def test_r9_visual_pre_freshness_has_fixed_refusal_code(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    for gate in ('c1', 'nested-overlay', 'public-observation-chatgpt'):
        with pytest.raises(kit.KitError) as error:
            kit.record(scratch, 'chrome', gate, 'pass')
        require(error.value.code == 'FIXTURE_NOT_POSTLOAD_FRESH')


def await_reenable(kit, scratch, host, browser='chrome'):
    _, token = advance_to_freshness(kit, scratch, host, browser)
    kit.begin_rail_step(scratch, browser, 'disabled-reload', 10)
    requests = [{'seq': 11 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
                for i, name in enumerate(kit.FIXTURE_NAMES[:2])]
    kit.prove_rail_step(scratch, browser, 'disabled-reload', requests)
    kit.begin_rail_step(scratch, browser, 'reenabled-reload', 20)
    return token


@pytest.mark.parametrize('defect', ['matrix-only', 'two-pages', 'initial-sentinel',
                                  'before-reenable', 'head', 'wrong-token', 'two-tokens',
                                  'repeated-seq'])
def test_r10_reenable_requires_all_three_fresh_current_gets(kit, host, tmp_path, defect):
    scratch = prepared(kit, host, tmp_path)
    token = await_reenable(kit, scratch, host)
    requests = [{'seq': 21 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
                for i, name in enumerate(kit.FIXTURE_NAMES)]
    if defect == 'matrix-only':
        requests = requests[:1]
    elif defect == 'two-pages':
        requests = requests[:2]
    elif defect == 'initial-sentinel':
        requests[-1]['seq'] = 3
    elif defect == 'before-reenable':
        requests[-1]['seq'] = 19
    elif defect == 'head':
        requests[-1]['method'] = 'HEAD'
    elif defect == 'wrong-token':
        requests[-1]['qual'] = ['f' * 32 if token != 'f' * 32 else 'e' * 32]
    elif defect == 'two-tokens':
        requests[-1]['qual'].append(token)
    else:
        requests[-1]['seq'] = requests[0]['seq']
    with pytest.raises(kit.KitError) as error:
        kit.prove_rail_step(scratch, 'chrome', 'reenabled-reload', requests)
    require(error.value.code == 'FIXTURE_NOT_POSTREENABLE_FRESH')
    state = kit.Session(scratch)
    require(state.stopped)
    require(state.entries[-1]['reason'] == 'FIXTURE_NOT_POSTREENABLE_FRESH')
    require(kit.verdict(state.session, state.entries)[0] == 'INCOMPLETE')


@pytest.mark.parametrize('phase', ['VISUAL_GATES', 'EXTENSION_DISABLED',
                                  'DISABLED_COMPARISON_FRESH', 'EXTENSION_REENABLED'])
@pytest.mark.parametrize('result', ['pass', 'fail', 'not-run'])
def test_r10_every_sentinel_gate_refused_before_reenable_freshness(kit, host, tmp_path, phase, result):
    scratch = prepared(kit, host, tmp_path)
    _, token = advance_to_freshness(kit, scratch, host)
    if phase != 'VISUAL_GATES':
        kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 10)
    if phase in ('DISABLED_COMPARISON_FRESH', 'EXTENSION_REENABLED'):
        requests = [{'seq': 11 + i, 'method': 'GET', 'path': f'/{name}', 'qual': [token]}
                    for i, name in enumerate(kit.FIXTURE_NAMES[:2])]
        kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', requests)
    if phase == 'EXTENSION_REENABLED':
        kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 20)
    require(kit.browser_phase(kit.Session(scratch).entries, 'chrome') == phase)
    for gate in kit.SENTINEL_FIXTURE_GATES:
        before = (scratch / 'journal.jsonl').read_bytes()
        kwargs = {'early_closed_root': {'pass': 'CAPTURED', 'fail': 'FAIL', 'not-run': 'NOT_RUN'}[result]} if gate == 'early-closed-root' else {}
        with pytest.raises(kit.KitError) as error:
            kit.record(scratch, 'chrome', gate, result, **kwargs)
        require(error.value.code == 'FIXTURE_NOT_POSTREENABLE_FRESH', gate)
        require((scratch / 'journal.jsonl').read_bytes() == before, gate)


@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_r10_ledger_fresh_flow_and_journal_replay(kit, host, tmp_path, browser):
    scratch = prepared(kit, host, tmp_path)
    ledger = kit.RequestLedger()
    site = scratch / 'site'
    # Earlier and bare requests are real ledger entries but never current postload evidence.
    for name in kit.FIXTURE_NAMES:
        kit.fixture_response(ledger, site, 'GET', '/' + name)
    kit.begin_launch(scratch, browser, host, 8123)
    kit.record(scratch, browser, 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, browser, ledger.request_barrier())
    token = kit.present_fixtures(scratch, browser)
    ledger.set_qualification(token)
    for name in kit.FIXTURE_NAMES:
        status, _ = kit.fixture_response(ledger, site, 'GET', '/' + name + '?qual=' + token)
        require(status == 200)
    kit.prove_postload(scratch, browser, ledger.snapshot_requests())
    for step, names in [('disabled-reload', kit.FIXTURE_NAMES[:2]),
                        ('reenabled-reload', kit.FIXTURE_NAMES)]:
        kit.begin_rail_step(scratch, browser, step, ledger.request_barrier())
        for name in names:
            kit.fixture_response(ledger, site, 'GET', '/' + name + '?qual=' + token)
        kit.prove_rail_step(scratch, browser, step, ledger.snapshot_requests())
    # Reopening the session reconstructs the enabled gates from durable facts.
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, browser) == 'SENTINEL_VISUAL_GATES')
    phase_kinds = [e['kind'] for e in state.entries if e.get('browser') == browser
                   and e['kind'] in kit.PHASES]
    require(phase_kinds == list(kit.PHASES[1:]))
    kit.record(scratch, browser, 'custom-rail-discriminator', 'pass')
    kit.record(scratch, browser, 'handshake', 'pass')
    proof = next(e for e in state.entries if e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
    toggle = next(e for e in state.entries if e['kind'] == 'EXTENSION_REENABLED')
    require(proof['barrier'] == toggle['barrier'])
    require(proof['token'] == token and proof['session_id'] == state.session['session_id'])
    require(set(proof['seqs']) == set(kit.FIXTURE_NAMES))
    require(all(seq > toggle['barrier'] for seq in proof['seqs'].values()))


@pytest.mark.parametrize('defect', ['missing-sentinel', 'missing-proof', 'at-barrier',
                                  'initial-sentinel', 'truncated', 'lowered-barrier',
                                  'toggle-out-of-order', 'missing-toggle', 'missing-gates-enabled'])
def test_r10_tampered_reenable_journal_cannot_pass(kit, host, tmp_path, defect):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    exit_all(kit, scratch, host)
    state = kit.Session(scratch)
    require(kit.verdict(state.session, state.entries) == ('PASS', []))
    entries = json.loads(json.dumps(state.entries))
    proof = next(e for e in entries if e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
    toggle = next(e for e in entries if e['kind'] == 'EXTENSION_REENABLED')
    if defect == 'missing-sentinel':
        proof['seqs'].pop(kit.FIXTURE_NAMES[2])
    elif defect == 'missing-proof':
        entries.remove(proof)
    elif defect == 'at-barrier':
        proof['seqs'][kit.FIXTURE_NAMES[2]] = toggle['barrier']
    elif defect == 'initial-sentinel':
        initial = next(e for e in entries if e['kind'] == 'FIXTURES_OPENED_POSTLOAD')
        proof['seqs'][kit.FIXTURE_NAMES[2]] = initial['seqs'][kit.FIXTURE_NAMES[2]]
    elif defect == 'truncated':
        entries = entries[:entries.index(proof)]
    elif defect == 'lowered-barrier':
        # Still above disabled GETs: the freshness proof must match the actual toggle barrier.
        toggle['barrier'] -= 1
    elif defect == 'toggle-out-of-order':
        entries.remove(toggle)
        disabled = next(e for e in entries if e['kind'] == 'DISABLED_COMPARISON_FRESH')
        entries.insert(entries.index(disabled), toggle)
    elif defect == 'missing-toggle':
        entries.remove(toggle)
    else:
        entries.remove(next(e for e in entries if e['kind'] == 'SENTINEL_VISUAL_GATES'))
    verdict, reasons = kit.verdict(state.session, entries)
    require(verdict == 'INCOMPLETE', (verdict, reasons))
    require(any('FIXTURE_NOT_POSTREENABLE_FRESH' in reason for reason in reasons))
    if defect != 'truncated':
        with pytest.raises(kit.KitError):
            kit.browser_phase(entries, 'chrome')
    else:
        require(kit.browser_phase(entries, 'chrome') == 'EXTENSION_REENABLED')
    # A valid unkeyed chain cannot hide invalid semantic facts from recording commands.
    previous = '0' * 64
    lines = []
    for i, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k != 'hash'}
        body.update(seq=i, prev=previous)
        previous = kit.sha256(kit._canonical(body))
        lines.append(kit._canonical(dict(body, hash=previous)))
    (scratch / 'journal.jsonl').write_bytes(b'\n'.join(lines) + b'\n')
    with pytest.raises(kit.KitError):
        kit.record(scratch, 'chrome', 'foreign-realm-attempt', 'not-run')


def test_r10_premature_sentinel_evidence_is_incomplete_and_required_failure_stays_fail(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    record_all(kit, scratch, host)
    exit_all(kit, scratch, host)
    state = kit.Session(scratch)
    entries = json.loads(json.dumps(state.entries))
    handshake = next(e for e in entries if e.get('gate') == 'handshake')
    entries.remove(handshake)
    visual = next(e for e in entries if e['kind'] == 'VISUAL_GATES')
    entries.insert(entries.index(visual) + 1, handshake)
    require(kit.verdict(state.session, entries)[0] == 'INCOMPLETE')
    next(e for e in entries if e.get('gate') == 'c1')['result'] = 'fail'
    require(kit.verdict(state.session, entries)[0] == 'FAIL')


@pytest.mark.parametrize('fixture', ['scrollbar-toplayer-matrix.html', 'scrollbar-shadow-sentinel-matrix.html'])
def test_r10_scene_menu_and_generated_urls_preserve_current_qual(kit, host, tmp_path, fixture):
    scratch = prepared(kit, host, tmp_path)
    ledger = kit.RequestLedger()
    token = 'abcdef0123456789abcdef0123456789'
    ledger.set_qualification(token)
    original = (scratch / 'site' / fixture).read_bytes()
    require(original.count(kit.SCENE_MENU_ASSIGNMENT) == 1)
    allowed = re.search(rb'const allowed = \[(.*?)\];', original, flags=re.S).group(1)
    require(tuple(value.decode() for value in re.findall(rb"'([^']+)'", allowed)) == kit.SCENES[fixture])
    status, served = kit.fixture_response(ledger, scratch / 'site', 'GET', '/' + fixture + '?qual=' + token)
    require(status == 200 and kit.SCENE_MENU_ASSIGNMENT not in served)
    rewritten = ("location.search = '?qual=" + token + "&scene=' + encodeURIComponent(menu.value);").encode()
    require(served == original.replace(kit.SCENE_MENU_ASSIGNMENT, rewritten, 1))
    # Deterministic Python substitution evaluates the assignment for these ASCII scene names.
    prefix = re.search(rb"location.search = '([^']*)' \+ encodeURIComponent\(menu.value\);", served).group(1).decode()
    for scene in kit.SCENES[fixture]:
        query = prefix + urllib.parse.quote(scene, safe="~()*!.'-")
        require(urllib.parse.parse_qs(query.removeprefix('?')) == {'qual': [token], 'scene': [scene]})
        url = kit.qualification_url(8123, fixture, token, scene)
        require(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query) == {'qual': [token], 'scene': [scene]})
    for query in ('', '?qual=stale', '?qual=' + token + '&frame=child', '?qual=' + token + '&qual=' + token):
        _, served = kit.fixture_response(ledger, scratch / 'site', 'GET', '/' + fixture + query)
        require(served == original)
    require((scratch / 'site' / fixture).read_bytes() == original)


def test_r10_qualification_helpers_refuse_invalid_binding(kit):
    ledger = kit.RequestLedger()
    for token in ('validtoken1234567890abcdef123456', 'f' * 31, 'F' * 32, "x'", 123):
        with pytest.raises(kit.KitError):
            ledger.set_qualification(token)
        with pytest.raises(kit.KitError):
            kit.qualification_url(8123, kit.FIXTURE_NAMES[0], token)
    for port, fixture, scene in ((0, kit.FIXTURE_NAMES[0], None), (8123, '../x', None),
                                 (8123, kit.FIXTURE_NAMES[1], 'unknown')):
        with pytest.raises(kit.KitError):
            kit.qualification_url(port, fixture, 'f' * 32, scene)


# R13 freshness retry and quiescent sentinel regressions --------------------------------------

def test_r13_fixture_proof_status_pure_and_rules(kit):
    names = list(kit.FIXTURE_NAMES)
    token = 'a' * 32
    barrier = 10
    valid_reqs = [
        {'seq': 11, 'method': 'GET', 'path': f'/{names[0]}', 'qual': [token]},
        {'seq': 12, 'method': 'GET', 'path': f'/{names[1]}', 'qual': [token]},
        {'seq': 13, 'method': 'GET', 'path': f'/{names[2]}', 'qual': [token]},
    ]
    # 1. Pure: inputs are not modified
    reqs_copy = json.loads(json.dumps(valid_reqs))
    status = kit.fixture_proof_status(valid_reqs, names, token, barrier)
    require(valid_reqs == reqs_copy, 'requests input was mutated')
    require(status['missing'] == [], status)
    require(status['seqs'] == {names[0]: 11, names[1]: 12, names[2]: 13}, status)
    require(kit.fixture_proof_status(tuple(valid_reqs), names, token, barrier) == status)
    for invalid_barrier in (True, '10', 10.0, None):
        with pytest.raises(kit.KitError):
            kit.fixture_proof_status(valid_reqs, names, token, invalid_barrier)

    # 2. Malformed requests: non-dict items, non-list requests, missing seq, string seq, bool seq
    malformed = [
        None, 'not-a-dict', 123, [], {},
        {'seq': '11', 'method': 'GET', 'path': f'/{names[0]}', 'qual': [token]},
        {'seq': True, 'method': 'GET', 'path': f'/{names[0]}', 'qual': [token]},
        {'seq': 11, 'method': 'GET', 'path': f'/{names[0]}'},  # missing qual
    ]
    status_malformed = kit.fixture_proof_status(malformed, names, token, barrier)
    require(status_malformed['missing'] == names)
    require(kit.fixture_proof_status('not-a-list', names, token, barrier)['missing'] == names)

    # 3. Stale token
    stale_reqs = [
        {'seq': 11, 'method': 'GET', 'path': f'/{names[0]}', 'qual': ['b' * 32]},
        {'seq': 12, 'method': 'GET', 'path': f'/{names[1]}', 'qual': [token]},
        {'seq': 13, 'method': 'GET', 'path': f'/{names[2]}', 'qual': [token, 'extra']},
    ]
    status_stale = kit.fixture_proof_status(stale_reqs, names, token, barrier)
    require(status_stale['missing'] == [names[0], names[2]])

    # 4. HEAD method never counts
    head_reqs = [
        {'seq': 11, 'method': 'HEAD', 'path': f'/{names[0]}', 'qual': [token]},
        {'seq': 12, 'method': 'GET', 'path': f'/{names[1]}', 'qual': [token]},
        {'seq': 13, 'method': 'GET', 'path': f'/{names[2]}', 'qual': [token]},
    ]
    status_head = kit.fixture_proof_status(head_reqs, names, token, barrier)
    require(status_head['missing'] == [names[0]])

    # 5. Pre-barrier requests never count (seq <= barrier)
    prebarrier_reqs = [
        {'seq': 10, 'method': 'GET', 'path': f'/{names[0]}', 'qual': [token]},  # seq == barrier
        {'seq': 9, 'method': 'GET', 'path': f'/{names[1]}', 'qual': [token]},   # seq < barrier
        {'seq': 11, 'method': 'GET', 'path': f'/{names[2]}', 'qual': [token]},
    ]
    status_pre = kit.fixture_proof_status(prebarrier_reqs, names, token, barrier)
    require(status_pre['missing'] == [names[0], names[1]])

    # 6. Duplicate sequence: all fixtures reported missing when distinct seq rule is violated
    dup_reqs = [
        {'seq': 11, 'method': 'GET', 'path': f'/{names[0]}', 'qual': [token]},
        {'seq': 11, 'method': 'GET', 'path': f'/{names[1]}', 'qual': [token]},
        {'seq': 12, 'method': 'GET', 'path': f'/{names[2]}', 'qual': [token]},
    ]
    status_dup = kit.fixture_proof_status(dup_reqs, names, token, barrier)
    require(status_dup['missing'] == names, 'duplicate seq must report all names as missing')


def test_r13_pending_fixture_proof_read_only_across_phases(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.begin_launch(scratch, 'chrome', host, 8123)

    # In LAUNCHED phase: no pending fixture proof
    with pytest.raises(kit.KitError) as err:
        kit.pending_fixture_proof(scratch, 'chrome')
    require(err.value.code == 'FIXTURE_NOT_POSTLOAD_FRESH')

    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, 'chrome', 5)

    # In EXTENSION_LOADED phase: no pending fixture proof
    with pytest.raises(kit.KitError) as err:
        kit.pending_fixture_proof(scratch, 'chrome')
    require(err.value.code == 'FIXTURE_NOT_POSTLOAD_FRESH')

    # Present fixtures -> fixtures-presented phase
    token = kit.present_fixtures(scratch, 'chrome')
    journal_before = (scratch / 'journal.jsonl').read_bytes()
    pending = kit.pending_fixture_proof(scratch, 'chrome')
    journal_after = (scratch / 'journal.jsonl').read_bytes()
    require(journal_before == journal_after, 'pending_fixture_proof must be strictly read-only')
    require(pending['proof'] == 'FIXTURES_OPENED_POSTLOAD')
    require(pending['names'] == list(kit.FIXTURE_NAMES))
    require(pending['token'] == token)
    require(pending['barrier'] == 5)
    require(pending['code'] == 'FIXTURE_NOT_POSTLOAD_FRESH')

    # Prove postload -> enters VISUAL_GATES
    reqs = [{'seq': 6 + i, 'method': 'GET', 'path': f'/{n}', 'qual': [token]} for i, n in enumerate(kit.FIXTURE_NAMES)]
    kit.prove_postload(scratch, 'chrome', reqs)
    with pytest.raises(kit.KitError):
        kit.pending_fixture_proof(scratch, 'chrome')

    # begin_rail_step disabled-reload -> EXTENSION_DISABLED phase
    kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 10)
    journal_before = (scratch / 'journal.jsonl').read_bytes()
    pending_dis = kit.pending_fixture_proof(scratch, 'chrome')
    require((scratch / 'journal.jsonl').read_bytes() == journal_before)
    require(pending_dis['proof'] == 'DISABLED_COMPARISON_FRESH')
    require(pending_dis['names'] == list(kit.RAIL_STEPS['disabled-reload']['fixtures']))
    require(pending_dis['token'] == token)
    require(pending_dis['barrier'] == 10)
    require(pending_dis['code'] == 'RAIL_COMPARISON_NOT_PROVEN')

    # Complete disabled-reload
    dis_reqs = [{'seq': 11 + i, 'method': 'GET', 'path': f'/{n}', 'qual': [token]}
                for i, n in enumerate(kit.RAIL_STEPS['disabled-reload']['fixtures'])]
    kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', dis_reqs)

    # begin_rail_step reenabled-reload -> EXTENSION_REENABLED phase
    kit.begin_rail_step(scratch, 'chrome', 'reenabled-reload', 20)
    journal_before = (scratch / 'journal.jsonl').read_bytes()
    pending_reen = kit.pending_fixture_proof(scratch, 'chrome')
    require((scratch / 'journal.jsonl').read_bytes() == journal_before)
    require(pending_reen['proof'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
    require(pending_reen['names'] == list(kit.FIXTURE_NAMES))
    require(pending_reen['token'] == token)
    require(pending_reen['barrier'] == 20)
    require(pending_reen['code'] == 'FIXTURE_NOT_POSTREENABLE_FRESH')


def test_r13_note_freshness_retry_entries_no_phase_and_invariants(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.begin_launch(scratch, 'chrome', host, 8123)
    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, 'chrome', 5)
    token = kit.present_fixtures(scratch, 'chrome')

    # Note retry 1 with missing subset
    missing = [kit.FIXTURE_NAMES[0], kit.FIXTURE_NAMES[2]]
    before = kit.Session(scratch)
    verdict_before = kit.verdict(before.session, before.entries)
    entry = kit.note_freshness_retry(scratch, 'chrome', 1, missing)
    require(entry['kind'] == 'freshness-retry')
    require(entry['browser'] == 'chrome')
    require(entry['proof'] == 'FIXTURES_OPENED_POSTLOAD')
    require('phase' not in entry, 'retry entry must NOT contain a phase field')
    require(entry['retry'] == 1)
    require(entry['missing'] == missing)

    # Phase is preserved unchanged
    state = kit.Session(scratch)
    require(kit.browser_phase(state.entries, 'chrome') == 'fixtures-presented')
    require(kit.verdict(state.session, state.entries) == verdict_before)

    # Multiple retries up to FRESHNESS_RETRIES=3
    entry2 = kit.note_freshness_retry(scratch, 'chrome', 2, [kit.FIXTURE_NAMES[1]])
    require(entry2['retry'] == 2 and 'phase' not in entry2)
    entry3 = kit.note_freshness_retry(scratch, 'chrome', 3, [kit.FIXTURE_NAMES[0]])
    require(entry3['retry'] == 3 and 'phase' not in entry3)
    require(kit.browser_phase(kit.Session(scratch).entries, 'chrome') == 'fixtures-presented')


def test_r13_note_freshness_retry_invalid_inputs(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    kit.begin_launch(scratch, 'chrome', host, 8123)
    kit.record(scratch, 'chrome', 'extension-loaded', 'pass')
    kit.mark_extension_loaded(scratch, 'chrome', 5)

    # In EXTENSION_LOADED phase: active phase check fails
    with pytest.raises(kit.KitError):
        kit.note_freshness_retry(scratch, 'chrome', 1, [kit.FIXTURE_NAMES[0]])

    kit.present_fixtures(scratch, 'chrome')

    # Invalid retry integer
    for bad_retry in (0, 4, -1, '1', 1.0, None, True):
        with pytest.raises(kit.KitError):
            kit.note_freshness_retry(scratch, 'chrome', bad_retry, [kit.FIXTURE_NAMES[0]])

    # Invalid missing: empty, non-sequence, foreign names, out of order, duplicates
    for bad_missing in (
        [], None, 'scrollbar-matrix.html', 123,
        ['nonexistent-fixture.html'],
        [kit.FIXTURE_NAMES[2], kit.FIXTURE_NAMES[0]],  # out of order
        [kit.FIXTURE_NAMES[0], kit.FIXTURE_NAMES[0]],  # duplicate
    ):
        with pytest.raises(kit.KitError):
            kit.note_freshness_retry(scratch, 'chrome', 1, bad_missing)
    kit.Session(scratch).append('stop', reason='OPERATOR_STOPPED')
    with pytest.raises(kit.KitError):
        kit.note_freshness_retry(scratch, 'chrome', 1, [kit.FIXTURE_NAMES[0]])


def test_r13_quiescent_sentinel_digests_contract_and_behavior(kit, host, tmp_path):
    # 1. Bounds checks
    for bad_samples in (0, 1, 2, '3', None):
        with pytest.raises(kit.KitError):
            kit.quiescent_sentinel_digests(host, samples=bad_samples, sleeper=lambda s: None)
    for bad_interval in (0, -0.1, 1.6, '1.0', None, True):
        with pytest.raises(kit.KitError):
            kit.quiescent_sentinel_digests(host, interval=bad_interval, sleeper=lambda s: None)
    # Total duration > 3.0s: (4 - 1) * 1.1 = 3.3s > 3s
    with pytest.raises(kit.KitError, match='total sample duration'):
        kit.quiescent_sentinel_digests(host, samples=4, interval=1.1, sleeper=lambda s: None)

    # 2. Stable sentinels: returns digests map, invokes sleeper
    slept = []
    baseline = kit.quiescent_sentinel_digests(host, samples=3, interval=1.0, sleeper=slept.append)
    require(slept == [1.0, 1.0], slept)
    require(baseline == kit.sentinel_digests(host))

    # 3. Drift detection: sentinel file modified during sampling
    profiles = host.home / 'Library/Application Support/Firefox/profiles.ini'
    call_count = [0]
    def drift_sleeper(s):
        call_count[0] += 1
        profiles.write_text(f'[Profile_drift_{call_count[0]}]\n')

    with pytest.raises(kit.KitError) as exc:
        kit.quiescent_sentinel_digests(host, samples=3, interval=1.0, sleeper=drift_sleeper)
    require(exc.value.code == 'LIVE_SENTINEL_NOT_QUIESCENT')
    msg = str(exc.value)
    for private in (str(host.home), 'observer', 'profiles.ini'):
        require(private not in msg, f'private detail {private} in failure message: {msg}')

    # 4. Absent sentinels: all absent files stay absent -> stable
    for p in host.sentinels().values():
        if p.exists():
            p.unlink()
    absent_map = kit.quiescent_sentinel_digests(host, samples=3, interval=0.1, sleeper=lambda s: None)
    require(all(v == 'absent' for v in absent_map.values()))

    # 5. Transitions: absent -> created during sampling -> drift detected
    def transition_sleeper(s):
        profiles.write_text('[General]\n')
    with pytest.raises(kit.KitError) as exc:
        kit.quiescent_sentinel_digests(host, samples=3, interval=0.1, sleeper=transition_sleeper)
    require(exc.value.code == 'LIVE_SENTINEL_NOT_QUIESCENT')

    # 6. OSError during sampling fails closed
    class ErrPath:
        def exists(self):
            return True
        def read_bytes(self):
            raise OSError('Permission denied')
    orig_sentinels = host.sentinels
    host.sentinels = lambda: {'chrome-local-state': ErrPath(), 'firefox-profiles-ini': ErrPath(), 'firefox-installs-ini': ErrPath()}
    try:
        with pytest.raises(kit.KitError) as exc:
            kit.quiescent_sentinel_digests(host, samples=3, interval=0.1, sleeper=lambda s: None)
        require(exc.value.code == 'LIVE_SENTINEL_NOT_QUIESCENT')
        require('Permission denied' not in str(exc.value))
    finally:
        host.sentinels = orig_sentinels


def test_r13_sentinel_contract_and_prepare_baseline_validation(kit, host, tmp_path, monkeypatch):
    # SENTINEL_CONTRACT constant check
    contract = kit.SENTINEL_CONTRACT
    require(contract['count'] == 3)
    require(contract['sentinels'] == ['chrome-local-state', 'firefox-profiles-ini', 'firefox-installs-ini'])
    require('quiescent' in contract['execution_baseline'].lower())
    require('prelaunch' in contract['prelaunch'].lower())
    require('after-exit' in contract['after_exit'].lower() or 'post-exit' in contract['after_exit'].lower())

    # FRESHNESS_CONTRACT retry_rule check
    require('retry_rule' in kit.FRESHNESS_CONTRACT)
    require('first attempt + 3 retries = four confirmations' in kit.FRESHNESS_CONTRACT['retry_rule'].lower())

    # Validation before directory creation
    bad_baselines = [
        'not-a-dict',
        {'chrome-local-state': 'absent'},  # missing keys
        {'chrome-local-state': 'absent', 'firefox-profiles-ini': 'absent', 'firefox-installs-ini': 'absent', 'extra': 'absent'},  # extra keys
        {k: 'A' * 64 for k in host.sentinels()},  # uppercase hex
        {k: 'short' for k in host.sentinels()},    # short value
        {k: 'g' * 64 for k in host.sentinels()},    # non-hex chars
    ]
    for idx, bad in enumerate(bad_baselines):
        scratch = tmp_path / f'scratch_bad_{idx}'
        with pytest.raises(kit.KitError):
            prepared(kit, host, tmp_path, name=f'scratch_bad_{idx}', sentinels=bad)
        require(not scratch.exists(), f'scratch {scratch} was created despite invalid baseline')

    # Valid baseline stored exactly with QUIESCENT_3_SAMPLES label without reading live sentinels
    good_baseline = {
        'chrome-local-state': '1' * 64,
        'firefox-profiles-ini': '2' * 64,
        'firefox-installs-ini': 'absent',
    }
    def forbidden_read(*args):
        raise AssertionError('prepare reread a supplied baseline')
    with monkeypatch.context() as isolated:
        isolated.setattr(kit, 'sentinel_digests', forbidden_read)
        scratch_good = prepared(kit, host, tmp_path, name='scratch_good', sentinels=good_baseline)
    session = json.loads((scratch_good / 'SESSION.json').read_text())
    require(session['sentinels'] == good_baseline)
    require(session['sentinel_baseline'] == 'QUIESCENT_3_SAMPLES')

    # None sentinels produces SINGLE_SAMPLE_DIAGNOSTIC
    scratch_diag = prepared(kit, host, tmp_path, name='scratch_diag', sentinels=None)
    session_diag = json.loads((scratch_diag / 'SESSION.json').read_text())
    require(session_diag['sentinel_baseline'] == 'SINGLE_SAMPLE_DIAGNOSTIC')
    require(session_diag['sentinels'] == kit.sentinel_digests(host))


@pytest.mark.parametrize('initial_present', [False, True])
@pytest.mark.parametrize('sample', [2, 3])
def test_r13_sentinel_presence_transition_refuses(kit, host, initial_present, sample):
    path = host.sentinels()['firefox-installs-ini']
    if initial_present:
        path.write_text('[Install]\n')
    sleeps = []
    def sleeper(interval):
        sleeps.append(interval)
        if len(sleeps) == sample - 1:
            if initial_present:
                path.unlink()
            else:
                path.write_text('[Install]\n')
    with pytest.raises(kit.KitError) as error:
        kit.quiescent_sentinel_digests(host, sleeper=sleeper)
    require(error.value.code == 'LIVE_SENTINEL_NOT_QUIESCENT')
    require(sleeps == [1.0] * (sample - 1))


def test_r13_prelaunch_sentinel_refusal_allowed_and_after_exit_regression(kit, host, tmp_path):
    # 1. Prelaunch allowed when baseline is unchanged
    scratch = prepared(kit, host, tmp_path, name='s_allow')
    kit.begin_launch(scratch, 'chrome', host, 8123)
    require(len(host.launched) == 1)

    # 2. Prelaunch refusal on first browser when live sentinel changed
    scratch_refuse1 = prepared(kit, host, tmp_path, name='s_refuse1')
    chrome_local_state = host.home / 'Library/Application Support/Google/Chrome/Local State'
    chrome_local_state.write_text('{"tampered": true}')
    with pytest.raises(kit.KitError) as exc:
        kit.begin_launch(scratch_refuse1, 'chrome', host, 8123)
    require(exc.value.code == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
    msg = str(exc.value)
    require(str(host.home) not in msg and 'Local State' not in msg)
    require('chrome-local-state' in msg)
    state = kit.Session(scratch_refuse1)
    require(state.stopped)
    stop_entry = state.entries[-1]
    require(stop_entry['kind'] == 'stop')
    require(stop_entry['reason'] == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
    require(stop_entry['browser'] == 'chrome')
    require(stop_entry['changed'] == ['chrome-local-state'])
    require(stop_entry['baseline'] == 'SESSION_BASELINE_UNCHANGED')
    require(stop_entry['prior_browser_exit_checked'] is False)

    # 3. Prelaunch refusal on second browser derives prior_browser_exit_checked=True
    chrome_local_state.write_text('{}')  # restore to match initial
    scratch_seq = prepared(kit, host, tmp_path, name='s_seq')
    # Launch Chrome and exit normally
    kit.begin_launch(scratch_seq, 'chrome', host, 8123)
    kit.end_launch(scratch_seq, 'chrome', host, 0)
    # Now tamper Firefox profiles.ini before Firefox launch
    firefox_profiles = host.home / 'Library/Application Support/Firefox/profiles.ini'
    firefox_profiles.write_text('[TamperedProfile]\n')
    with pytest.raises(kit.KitError) as exc:
        kit.begin_launch(scratch_seq, 'firefox', host, 8123)
    require(exc.value.code == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
    state_seq = kit.Session(scratch_seq)
    stop_entry2 = state_seq.entries[-1]
    require(stop_entry2['prior_browser_exit_checked'] is True)
    require(stop_entry2['changed'] == ['firefox-profiles-ini'])

    # 4. Prelaunch fail closed on OSError
    firefox_profiles.write_text('[General]\n')  # restore
    scratch_err = prepared(kit, host, tmp_path, name='s_err')
    class FailingHost(type(host)):
        pass
    class ErrPath:
        def exists(self):
            return True
        def read_bytes(self):
            raise OSError('Disk read error')
    orig_sentinels = host.sentinels
    host.sentinels = lambda: {'chrome-local-state': ErrPath(), 'firefox-profiles-ini': ErrPath(), 'firefox-installs-ini': ErrPath()}
    try:
        with pytest.raises(kit.KitError) as exc:
            kit.begin_launch(scratch_err, 'chrome', host, 8123)
        require(exc.value.code == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
        require('Disk read error' not in str(exc.value))
    finally:
        host.sentinels = orig_sentinels

    # 5. After-exit strict regression preserved: change during session caught by end_launch
    scratch_exit = prepared(kit, host, tmp_path, name='s_exit')
    host.on_launch = lambda: (host.home / 'Library/Application Support/Firefox/profiles.ini').write_text('[ExitedChanged]\n')
    with pytest.raises(kit.KitError, match='STOP: firefox after exit: live browser state changed'):
        kit.launch(scratch_exit, 'firefox', host, 8123)


# R14 Firefox-only session machinery regressions ---------------------------------------------

def prepared_firefox_only(kit, host, tmp_path, name='scratch_ff', work=None, sentinels=None):
    for domain, policy in LIVE_SHAPE.items():
        write_policy(host, domain, policy)
    scratch = tmp_path / name
    if sentinels is None:
        sentinels = kit.sentinel_digests(host, names=kit.FIREFOX_SENTINELS)
    kit.prepare(scratch, host, work=work, sentinels=sentinels, browsers=('firefox',),
                chrome_authority_sha256=kit.CHROME_AUTHORITY_SHA256)
    return scratch


def record_all_firefox(kit, scratch, host, result='pass', skip=()):
    session = json.loads((scratch / 'SESSION.json').read_text())
    browser = 'firefox'
    state = kit.Session(scratch)
    if not any(e['kind'] == 'launch' and e.get('browser') == browser for e in state.entries):
        advance_to_custom(kit, scratch, host, browser)
    if ('custom-rail-discriminator' in kit.required_gates(session)
        and (browser, 'custom-rail-discriminator') not in skip
        and result == 'pass'):
        if kit.latest(kit.Session(scratch).entries).get((browser, 'custom-rail-discriminator')) != 'pass':
            kit.record(scratch, browser, 'custom-rail-discriminator', 'pass')

    for gate in kit.required_gates(session) + kit._cases(session, 'related'):
        if gate in kit.AUTO_GATES or (browser, gate) in skip:
            continue
        if gate in kit.PRE_FIXTURE_GATES:
            if kit.latest(kit.Session(scratch).entries).get((browser, gate)) is not None:
                continue
        if gate == 'custom-rail-discriminator':
            continue
        branch = ('RAIL_VISIBLE_USABLE' if result == 'pass' else 'FAIL' if result == 'fail' else 'NOT_RUN') if gate == 'root-gutter' else None
        early_branch = ('CAPTURED' if result == 'pass' else 'FAIL' if result == 'fail' else 'NOT_RUN') if gate == 'early-closed-root' else None
        kit.record(scratch, browser, gate, result, root_gutter=branch, early_closed_root=early_branch)


def test_r14_chrome_authority_status_pin_and_field_validation(kit, repo_root, tmp_path):
    # Real file positive check
    doc = kit.chrome_authority_status(repo_root)
    require(doc['disposition'] == 'MANAGER_ACCEPTED_PRIOR_ATTENDED')
    require(doc['browser'] == 'chrome')
    require(doc['version'] == '149.0.7827.201')
    require(doc['source_session'] == '20261004T193451Z-ae8e8bf7')
    require(doc['fresh_launch_in_r14'] is False)
    require(doc['not_a_pass_journal'] is True)

    # Missing file
    with pytest.raises(kit.KitError) as exc:
        kit.chrome_authority_status(tmp_path / 'nonexistent')
    require(exc.value.code == 'CHROME_AUTHORITY_INVALID')

    # Symlink refusal
    fake_auth = tmp_path / 'fake_auth.json'
    fake_auth.write_text(json.dumps(doc))
    symlink_auth = tmp_path / 'sym_auth.json'
    symlink_auth.symlink_to(fake_auth)
    with pytest.raises(kit.KitError) as exc:
        kit.chrome_authority_status(symlink_auth)
    require(exc.value.code == 'CHROME_AUTHORITY_INVALID')

    # Hash mismatch
    fake_auth.write_text(json.dumps({**doc, 'version': '150.0'}))
    with pytest.raises(kit.KitError) as exc:
        kit.chrome_authority_status(fake_auth)
    require(exc.value.code == 'CHROME_AUTHORITY_INVALID')

    # Field mismatch even if forced sha check bypassed by monkeypatch
    orig_sha = kit.CHROME_AUTHORITY_SHA256
    try:
        kit.CHROME_AUTHORITY_SHA256 = kit.sha256(fake_auth.read_bytes())
        with pytest.raises(kit.KitError) as exc:
            kit.chrome_authority_status(fake_auth)
        require(exc.value.code == 'CHROME_AUTHORITY_INVALID')
    finally:
        kit.CHROME_AUTHORITY_SHA256 = orig_sha


def test_r14_sentinel_digests_filter_before_read(kit, host):
    class ExplodingPath:
        def exists(self):
            raise AssertionError('Chrome Local State should never be accessed in Firefox-only sentinel checks')
        def read_bytes(self):
            raise AssertionError('Chrome Local State should never be accessed in Firefox-only sentinel checks')

    orig_sentinels = host.sentinels
    host.sentinels = lambda: {
        'chrome-local-state': ExplodingPath(),
        'firefox-profiles-ini': host.home / 'Library/Application Support/Firefox/profiles.ini',
        'firefox-installs-ini': host.home / 'Library/Application Support/Firefox/installs.ini',
    }
    try:
        # names=FIREFOX_SENTINELS filters before reading, so ExplodingPath is never accessed
        digests = kit.sentinel_digests(host, names=kit.FIREFOX_SENTINELS)
        require(set(digests.keys()) == set(kit.FIREFOX_SENTINELS))
        quiescent = kit.quiescent_sentinel_digests(host, names=kit.FIREFOX_SENTINELS,
                                                 sleeper=lambda _: None)
        require(set(quiescent.keys()) == set(kit.FIREFOX_SENTINELS))

        # Without names, ExplodingPath is accessed and raises AssertionError
        with pytest.raises(AssertionError, match='Chrome Local State should never be accessed'):
            kit.sentinel_digests(host)
    finally:
        host.sentinels = orig_sentinels


def test_r14_browser_scope_helpers(kit, host):
    require(kit._normalize_browser_scope(None) == kit.BROWSERS)
    require(kit._normalize_browser_scope(('firefox',)) == ('firefox',))
    require(kit._normalize_browser_scope(('chrome', 'firefox')) == ('chrome', 'firefox'))
    with pytest.raises(kit.KitError, match='unsupported browser scope'):
        kit._normalize_browser_scope(('chrome',))
    with pytest.raises(kit.KitError, match='unsupported browser scope'):
        kit._normalize_browser_scope(('safari',))

    # running(host, browsers=('firefox',)) checks only Firefox
    host.procs['Google Chrome']['1111'] = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    require(kit.running(host, browsers=('firefox',)) == [])
    require('chrome' in kit.running(host, browsers=kit.BROWSERS))
    host.procs['Google Chrome'].clear()

    # classify_policy and bind_all scoped
    stops, keys, forced = kit.classify_policy(host, browsers=('firefox',))
    require('chrome' not in keys)
    require('firefox' in keys)
    bindings = kit.bind_all(host, browsers=('firefox',))
    require(set(bindings.keys()) == {'firefox'})


def test_r14_prepare_firefox_only(kit, host, tmp_path, repo_root):
    # Authority pin mismatch refused before mkdir
    bad_scratch = tmp_path / 'bad_scratch'
    with pytest.raises(kit.KitError) as exc:
        kit.prepare(bad_scratch, host, repo_root=repo_root, browsers=('firefox',), chrome_authority_sha256='0' * 64)
    require(exc.value.code == 'CHROME_AUTHORITY_INVALID')
    require(not bad_scratch.exists())

    # Combined prepare rejects chrome_authority_sha256
    with pytest.raises(kit.KitError, match='chrome_authority_sha256 only valid for firefox-only'):
        kit.prepare(bad_scratch, host, repo_root=repo_root, browsers=kit.BROWSERS, chrome_authority_sha256=kit.CHROME_AUTHORITY_SHA256)

    # Valid Firefox-only prepare
    scratch = prepared_firefox_only(kit, host, tmp_path)
    require((scratch / 'profiles/firefox').is_dir())
    require(not (scratch / 'profiles/chrome').exists())

    # CHROME-AUTHORITY.json in scratch
    auth_copy = scratch / 'CHROME-AUTHORITY.json'
    require(auth_copy.is_file() and not auth_copy.is_symlink())
    require(stat.S_IMODE(auth_copy.stat().st_mode) == 0o600)
    require(kit.sha256(auth_copy.read_bytes()) == kit.CHROME_AUTHORITY_SHA256)

    # Scope and schema in session and journal
    session = json.loads((scratch / 'SESSION.json').read_text())
    require(session['schema'] == kit.FIREFOX_ONLY_SESSION_SCHEMA)
    require(session['scope'] == {
        'mode': 'FIREFOX_ONLY',
        'browsers': ['firefox'],
        'sentinels': list(kit.FIREFOX_SENTINELS),
        'chrome_authority_sha256': kit.CHROME_AUTHORITY_SHA256,
    })
    state = kit.Session(scratch)
    require(state.entries[0]['kind'] == 'prepared')
    require(state.entries[0]['schema'] == kit.FIREFOX_ONLY_SESSION_SCHEMA)
    require(state.entries[0]['scope'] == session['scope'])


def test_r14_session_scope_validation(kit, host, tmp_path):
    scratch = prepared_firefox_only(kit, host, tmp_path)
    state = kit.Session(scratch)
    browsers, sentinels = kit.session_scope(state.session, state.entries)
    require(browsers == ('firefox',))
    require(sentinels == kit.FIREFOX_SENTINELS)

    # Prepared scope mismatch
    tampered_entries = [dict(state.entries[0], scope={**state.entries[0]['scope'], 'mode': 'COMBINED'})]
    with pytest.raises(kit.KitError, match='scope mismatch'):
        kit.session_scope(state.session, tampered_entries)

    # Illegal chrome runtime key in Firefox-only session
    tampered_session = dict(state.session, runtimes={'firefox': state.session['runtimes']['firefox'], 'chrome': {}})
    with pytest.raises(kit.KitError, match='Firefox-only session runtimes'):
        kit.session_scope(tampered_session, state.entries)


def test_r14_session_active_rejects_chrome_helpers_immediately(kit, host, tmp_path):
    scratch = prepared_firefox_only(kit, host, tmp_path)
    state = kit.Session(scratch)

    with pytest.raises(kit.KitError) as exc:
        state.active(browser='chrome')
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    # All browser helpers reject chrome immediately
    with pytest.raises(kit.KitError) as exc:
        kit.begin_launch(scratch, 'chrome', host, 8123)
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.launch(scratch, 'chrome', host, 8123)
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.end_launch(scratch, 'chrome', host, 0)
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.mark_extension_loaded(scratch, 'chrome', 0)
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.present_fixtures(scratch, 'chrome')
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.pending_fixture_proof(scratch, 'chrome')
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.note_freshness_retry(scratch, 'chrome', 1, ['scrollbar-matrix.html'])
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.prove_postload(scratch, 'chrome', [])
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.begin_rail_step(scratch, 'chrome', 'disabled-reload', 0)
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.prove_rail_step(scratch, 'chrome', 'disabled-reload', [])
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')

    with pytest.raises(kit.KitError) as exc:
        kit.record(scratch, 'chrome', 'c1', 'pass')
    require(exc.value.code == 'FOREIGN_BROWSER_ENTRY')


def test_r14_verdict_scoped_and_requires_verified_after_exit(kit, host, tmp_path):
    scratch = prepared_firefox_only(kit, host, tmp_path)
    state = kit.Session(scratch)

    # Advance Firefox through custom rail and record all gates
    record_all_firefox(kit, scratch, host)
    state = kit.Session(scratch)

    # 1. Normal-exit alone without verified after-exit cannot PASS
    state.append('observation', browser='firefox', gate='normal-exit', result='pass')
    v, reasons = kit.verdict(state.session, state.entries)
    require(v == 'INCOMPLETE')
    require(any('verified after-exit check required' in r for r in reasons))

    # An arbitrary verification flag with different sentinels is insufficient.
    state.append('after-exit', browser='firefox', verified=True, status='VERIFIED_MATCH',
                 sentinels={k: 'a' * 64 for k in kit.FIREFOX_SENTINELS},
                 runtime=state.session['runtimes']['firefox'])
    v, reasons = kit.verdict(state.session, state.entries)
    require(v == 'INCOMPLETE')

    # 2. Actual exact after-exit comparisons -> PASS
    kit.end_launch(scratch, 'firefox', host, 0)
    state = kit.Session(scratch)
    v, reasons = kit.verdict(state.session, state.entries)
    require((v, reasons) == ('PASS', []))
    cov, gaps = kit.related_coverage(state.session, state.entries)
    require((cov, gaps) == ('FULL', []))

    # 3. Forged foreign browser entry forces non-PASS
    forged_entries = list(state.entries)
    forged_entries.append({'kind': 'observation', 'browser': 'chrome', 'gate': 'c1', 'result': 'pass',
                           'hash': '0' * 64, 'prev': '0' * 64, 'seq': 999, 'time': 0})
    v, reasons = kit.verdict(state.session, forged_entries)
    require(v == 'FAIL')
    require('chrome:FOREIGN_BROWSER_ENTRY' in reasons)
    cov, gaps = kit.related_coverage(state.session, forged_entries)
    require((cov, gaps) == ('PARTIAL', ['chrome:FOREIGN_BROWSER_ENTRY']))


def test_r14_summary_of_and_bundle_firefox_only(kit, host, tmp_path, repo_root):
    scratch = prepared_firefox_only(kit, host, tmp_path)
    record_all_firefox(kit, scratch, host)
    kit.end_launch(scratch, 'firefox', host, 0)
    state = kit.Session(scratch)

    # Summary
    summary = kit.summary_of(state)
    require(summary['verdict'] == 'PASS')
    require(summary['verdict_scope'] == 'FRESH_FIREFOX_ONLY')
    require(summary['provenance_chrome_authority'] == {
        'member': kit.CHROME_AUTHORITY_MEMBER,
        'sha256': kit.CHROME_AUTHORITY_SHA256,
        'disposition': 'MANAGER_ACCEPTED_PRIOR_ATTENDED',
        'combined_qualification': False,
    })

    # Tampered authority copy in scratch is rejected by bundle
    auth_file = scratch / 'CHROME-AUTHORITY.json'
    auth_file.write_text('{}')
    with pytest.raises(kit.KitError) as exc:
        kit.bundle(scratch)
    require(exc.value.code == 'CHROME_AUTHORITY_INVALID')

    # Restore authority copy
    auth_file.write_bytes((kit.Path(repo_root) / kit.CHROME_AUTHORITY_MEMBER).read_bytes())

    # Bundle creates FIREFOX_ONLY_EVIDENCE
    v, digest = kit.bundle(scratch)
    require(v == 'PASS')
    evidence_path = scratch / 'bundle' / kit.FIREFOX_ONLY_EVIDENCE
    require(evidence_path.is_file())
    require(kit.sha256(evidence_path.read_bytes()) == digest)

    with zipfile.ZipFile(evidence_path) as archive:
        names = archive.namelist()
        require('CHROME-AUTHORITY.json' in names)
        require('SESSION.json' in names)
        require('journal.jsonl' in names)
        require('SUMMARY.json' in names)
        require('MEMBERS.sha256' in names)
        require(kit.sha256(archive.read('CHROME-AUTHORITY.json')) == kit.CHROME_AUTHORITY_SHA256)
        bundled_summary = json.loads(archive.read('SUMMARY.json'))
        require(bundled_summary['verdict_scope'] == 'FRESH_FIREFOX_ONLY')


def test_r14_scoped_baseline_rejects_chrome_before_mkdir(kit, host, tmp_path):
    scratch = tmp_path / 'bad-baseline'
    with pytest.raises(kit.KitError, match='sentinel baseline keys'):
        kit.prepare(scratch, host, browsers=('firefox',),
                    chrome_authority_sha256=kit.CHROME_AUTHORITY_SHA256,
                    sentinels=kit.sentinel_digests(host))
    require(not scratch.exists() and not host.launched)


def test_r14_combined_default_keeps_three_sentinels_and_no_scope(kit, host, tmp_path):
    scratch = prepared(kit, host, tmp_path)
    state = kit.Session(scratch)
    require('scope' not in state.session and 'scope' not in state.entries[0])
    require(set(state.session['sentinels']) == set(kit.SENTINEL_CONTRACT['sentinels']))
    require((scratch / 'profiles/chrome').is_dir() and (scratch / 'profiles/firefox').is_dir())
    require(kit.session_scope(state.session, state.entries)[0] == kit.BROWSERS)


def test_r14_firefox_launch_is_once_and_policy_never_reads_chrome(kit, host, tmp_path, monkeypatch):
    original = kit.managed_policy
    observed = []
    def policy(current, domain):
        observed.append(domain)
        require(domain == 'org.mozilla.firefox')
        return original(current, domain)
    monkeypatch.setattr(kit, 'managed_policy', policy)
    scratch = prepared_firefox_only(kit, host, tmp_path)
    kit.begin_launch(scratch, 'firefox', host, 8123)
    with pytest.raises(kit.KitError, match='already launched'):
        kit.begin_launch(scratch, 'firefox', host, 8123)
    require(len(host.launched) == 1 and observed == ['org.mozilla.firefox'])


def test_r14_authority_read_error_is_fixed_refusal(kit, repo_root, monkeypatch):
    original = kit.Path.read_bytes
    def unreadable(path):
        if path.name == 'bux5c0-r14-chrome-carry-forward-authority.json':
            raise OSError('private operational message')
        return original(path)
    monkeypatch.setattr(kit.Path, 'read_bytes', unreadable)
    with pytest.raises(kit.KitError) as error:
        kit.chrome_authority_status(repo_root)
    require(error.value.code == 'CHROME_AUTHORITY_INVALID')
    require('private operational message' not in str(error.value))


@pytest.mark.parametrize('field,value', [('mode', 'COMBINED'), ('browsers', ['chrome']),
                                        ('sentinels', ['chrome-local-state']),
                                        ('chrome_authority_sha256', '0' * 64)])
def test_r14_scope_cannot_be_downgraded_even_with_matching_prepared(kit, host, tmp_path, field, value):
    scratch = prepared_firefox_only(kit, host, tmp_path)
    state = kit.Session(scratch)
    state.session['scope'][field] = value
    entries = [{**state.entries[0], 'scope': dict(state.session['scope'])}]
    with pytest.raises(kit.KitError):
        kit.session_scope(state.session, entries)
