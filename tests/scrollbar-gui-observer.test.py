"""Source-only tests for the guided scrollbar GUI observer and its sealed operator kit.

A fake host binds synthetic runtimes, models the process table that pgrep and ps would read,
and returns fake browser handles: no browser, codesign, pgrep, ps, defaults or live profile is
used. The fixture server is real but loopback-only and is
proven closed after every session.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import types
import urllib.parse
import urllib.request
import zipfile

import pytest


def require(condition, message='requirement failed'):
    if not condition:
        raise AssertionError(message)


@pytest.fixture
def obs(load_module, monkeypatch):
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)  # an extracted kit must stay exact
    return load_module('tests/scrollbar_gui_observer.py')


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
LIVE_SHAPE = {
    'com.google.Chrome': {'ExtensionSettings': {
        '*': {'installation_mode': 'allowed'},
        'oboonakemofpalcgghocfoadofidjkkk': {'installation_mode': 'force_installed'}}},
    'org.mozilla.firefox': {'ExtensionSettings': {
        '*': {'installation_mode': 'allowed'},
        'keepassxc-browser@keepassxc.org': {'installation_mode': 'force_installed'}}},
}


# The two long-lived MCP launchers the operator observed under `pgrep -x "Google Chrome"` (R3).
MCP = ('npm exec @playwright/mcp@latest --executable-path /Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome',
       'npm exec chrome-devtools-mcp@latest --executablePath /Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome')
NORMAL = {'chrome': '/Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome',
          'firefox': '/Applications/Firefox.app/Contents/MacOS/firefox'}
PROCESS = {'chrome': 'Google Chrome', 'firefox': 'firefox'}
# Tokens that would reveal a PID-bearing or command-line process record if exported.
PROCESS_TOKENS = ('npm exec', 'playwright', 'chrome-devtools-mcp', 'Nix Apps', 'MacOS/', 'executable-path',
                  'executablePath', 'pid')


class FakeHandle:
    def __init__(self, host, browser, pid):
        self.host, self.browser, self.pid, self.done = host, browser, pid, False

    def poll(self):
        if self.done or self.browser in self.host.exit_early:
            return self.host.exit_code
        return None

    def wait(self):
        hook = self.host.on_wait.get(self.browser)
        if hook:
            hook()
        self.done = True
        if self.browser not in self.host.linger:  # the disposable main process is gone after exit
            self.host.procs[PROCESS[self.browser]].pop(self.pid, None)
        return self.host.exit_code


@pytest.fixture
def host(obs, tmp_path):
    kit = obs.kit

    class FakeHost(kit.Host):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.pgrep_error, self.mode, self.exit_code = False, 'Always', 0
            self.identity = json.loads(json.dumps(IDENTITY))
            self.unavailable, self.launched, self.on_wait, self.exit_early = {}, [], {}, set()
            self.served, self.linger, self.next_pid = [], set(), 4000
            self.procs = {name: {} for name in PROCESS.values()}  # process name -> {pid: command}
            self.slept, self.on_sleep = [], []

        def sleep(self, seconds):
            self.slept.append(seconds)
            if self.on_sleep:
                hook = self.on_sleep.pop(0)
                if hook:
                    hook()

        def spawn(self, browser, command):
            """One process holding `browser`'s process name; command None is unreadable to ps."""
            self.next_pid += 1
            self.procs[PROCESS[browser]][str(self.next_pid)] = command
            return str(self.next_pid)

        def run(self, argv, timeout=30):
            if argv[0] == '/usr/bin/pgrep':
                require(argv[1] == '-x' and len(argv) == 3, argv)
                if self.pgrep_error:
                    return 3, ''
                pids = self.procs[argv[2]]
                return (0, ''.join(f'{pid}\n' for pid in pids)) if pids else (1, '')
            if argv[:3] == ['/bin/ps', '-ww', '-p']:
                require(argv[4:] == ['-o', 'command='] and len(argv) == 6, argv)
                for procs in self.procs.values():
                    if procs.get(argv[3]) is not None:
                        return 0, procs[argv[3]] + '\n'
                return 1, ''
            if argv[:3] == ['/usr/bin/defaults', 'read', '-g']:
                return (0, self.mode + '\n') if self.mode else (1, '')
            raise AssertionError(f'unexpected command {argv}')

        def bind(self, browser):
            if browser in self.unavailable:
                raise obs.runtime.Unavailable(f'SELECTED_{browser.upper()}_UNAVAILABLE', self.unavailable[browser])
            return dict(self.identity[browser]), {'app': str(APPS[browser]), 'executable': executable(browser)}

        def start(self, argv, log):
            self.launched.append(argv)
            require(argv[-1] == 'about:blank', argv)
            require(not any('127.0.0.1' in arg or 'scrollbar-matrix' in arg or
                            'scrollbar-toplayer' in arg or 'scrollbar-shadow' in arg for arg in argv), argv)
            browser = 'chrome' if '--use-mock-keychain' in argv else 'firefox'
            return FakeHandle(self, browser, self.spawn(browser, ' '.join(argv)))  # as ps prints it

    store = tmp_path / 'store' / '0123456789abcdfghijklmnpqrsvwxyz-google-chrome-149.0.7827.201'
    APPS = {'chrome': store / 'Applications/Google Chrome.app', 'firefox': tmp_path / 'apps/Firefox.app'}

    def executable(browser):
        return str(APPS[browser] / ('Contents/MacOS/Google Chrome' if browser == 'chrome' else 'Contents/MacOS/firefox'))

    home = tmp_path / 'home'
    support = home / 'Library/Application Support'
    (support / 'Google/Chrome').mkdir(parents=True)
    (support / 'Firefox').mkdir(parents=True)
    (support / 'Google/Chrome/Local State').write_text('{}')
    (support / 'Firefox/profiles.ini').write_text('[General]\n')
    managed = tmp_path / 'managed'
    managed.mkdir()
    for domain, policy in LIVE_SHAPE.items():
        (managed / f'{domain}.plist').write_bytes(plistlib.dumps(policy))
    outbox = home.joinpath(*obs.OUTBOX)
    outbox.mkdir(parents=True, mode=0o700)
    for path in (home, *outbox.parents):
        if path.is_relative_to(home):
            path.chmod(0o700)
    (tmp_path / 'tmp').mkdir(mode=0o700)
    (tmp_path / 'preferences').mkdir()
    return FakeHost(home=home, managed_root=managed, preferences_root=tmp_path / 'preferences',
                    firefox_app=tmp_path / 'apps/Firefox.app', chrome_selection=tmp_path / 'apps/selection',
                    user='observer')


@pytest.fixture
def sealed(obs, repo_root, tmp_path, monkeypatch):
    out = tmp_path / 'sealed'
    out.mkdir()
    digest = obs.seal(repo_root, out)
    root = tmp_path / 'kit'
    with zipfile.ZipFile(out / obs.KIT_ZIP) as archive:
        archive.extractall(root)
    return root, digest


SESSION_ROOT = 'BUX5C0-PREFERENCES1-R10-REENABLE-FRESHNESS1-SCROLLBAR-GUI'
EVIDENCE = 'BUX5C0-R10-REENABLE-FRESHNESS1-SCROLLBAR-GUI-EVIDENCE.zip'


def destinations(host, tmp_path):
    return {'outbox': host.home.joinpath(*('Documents', 'agent', 'outbox', 'browser-ux_dinas')),
            'work_parent': tmp_path / 'tmp', 'uid': os.getuid()}


def session_paths(outbox):
    root = Path(outbox) / SESSION_ROOT
    return frozenset(root.iterdir()) if root.exists() else frozenset()


def unique_new_session(before, after):
    diff = frozenset(after) - frozenset(before)
    require(len(diff) == 1, f'expected exactly one new session, got {diff}')
    return next(iter(diff))


def snapshot(root):
    return {str(p): (p.read_bytes() if p.is_file() and not p.is_symlink() else None)
            for p in sorted(Path(root).rglob('*'))}


class Script:
    """Scripted operator. Items are answers or exceptions; every call records journal length."""

    def __init__(self, items, outbox, port=None, host=None, before=frozenset()):
        self.items, self.outbox, self.lengths, self.prompts = list(items), Path(outbox), [], []
        self.port, self.host = port, host
        self.before = frozenset(before)

    def fetch(self, names=None, token=None):
        session = unique_new_session(self.before, session_paths(self.outbox))
        entries = [json.loads(line) for line in (session / 'journal.jsonl').read_text().splitlines()]
        presented = [e for e in entries if e['kind'] == 'fixtures-presented'][-1]
        token = presented['token'] if token is None else token
        names = names or ('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html',
                          'scrollbar-shadow-sentinel-matrix.html')
        for name in names:
            with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/{name}?qual={token}', timeout=10) as response:
                raw = response.read()
            if self.host is not None:
                self.host.served.append((name, raw))

    def journal_lines(self):
        return sum(len(p.read_text().splitlines())
                   for p in self.outbox.glob(f'{SESSION_ROOT}/*/journal.jsonl'))

    def __call__(self, prompt):
        self.prompts.append(prompt)
        self.lengths.append(self.journal_lines())
        require(self.items, f'unscripted prompt: {prompt}')
        item = self.items.pop(0)
        if item == '@fixtures':
            self.fetch()
            return ''
        if item in ('@reload-both', '@reload-disabled'):
            self.fetch(('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html'))
            return ''
        if item in ('@reload-all-three', '@reload-reenabled'):
            self.fetch(('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html',
                        'scrollbar-shadow-sentinel-matrix.html'))
            return ''
        if isinstance(item, BaseException) or (isinstance(item, type) and issubclass(item, BaseException)):
            raise item
        if callable(item):  # an operator action at this prompt; returns the answer
            return item(prompt)
        return item


def answers(obs, overrides=None, stop_after=None):
    """Answers for one browser: per group key, 'p' unless overridden; notes empty."""
    flat = []
    for key, _, _, _ in obs.GROUPS:
        if key == 'rail-discriminator':
            flat += ['@fixtures', '', '@reload-both', '', '@reload-all-three']
        answer = (overrides or {}).get(key, 'RAIL_VISIBLE_USABLE' if key == 'root-gutter' else ('CAPTURED' if key == 'early-closed-root' else 'p'))
        if isinstance(answer, list):
            flat += answer
            if key == stop_after:
                return flat
            continue
        flat.append(answer)
        if answer.startswith(('f', 'native')) or answer.upper() in ('ROOT_GUTTER_UNPAINTABLE', 'FAIL', 'NATIVE_UNOCCLUDED', 'NOT_CAPTURED_FAIL_CLOSED'):
            flat.append('yes')
        if answer not in ('q', 'blocked'):
            flat.append('')
        if key == stop_after or answer in ('q', 'blocked'):
            return flat
    return flat


def execute(obs, host, kit_root, tmp_path, items, port=0, ack=True, firefox_only=False):
    """LIVE_SHAPE force-installs, so the first answer accepts that residual unless ack=False."""
    printed = []
    where = destinations(host, tmp_path)
    if not port:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
    host.fixture_port = port
    before = session_paths(where['outbox'])
    script = Script(([obs.FORCE_INSTALL_ACK] if ack else []) + list(items), where['outbox'], port, host,
                    before=before)
    code = obs.execute(host, script, printed.append, kit_root, where['outbox'], where['work_parent'],
                       where['uid'], port, firefox_only=firefox_only)
    root = where['outbox'] / (obs.FIREFOX_ONLY_SESSION_ROOT if firefox_only else obs.SESSION_ROOT)
    sessions = sorted(root.glob('*')) if root.exists() else []
    return code, printed, script, sessions


def evidence(session):
    with zipfile.ZipFile(session / 'bundle' / EVIDENCE) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def port_of(host):
    return host.fixture_port


def closed(port):
    with socket.socket() as probe:
        return probe.connect_ex(('127.0.0.1', port)) != 0


# Groups and answers ------------------------------------------------------------------------------

def test_groups_cover_every_case_and_browser_gate_exactly_once(obs):
    items = [item for _, _, _, group in obs.GROUPS for item in group]
    cases = obs.kit._fixture_cases()
    require(len(items) == len(set(items)), items)
    expected = set(cases) | set(obs.kit.BROWSER_GATES) | set(obs.kit.RECORD_ONLY_GATES)
    require(set(items) == expected, set(items) ^ expected)
    require('normal-exit' not in items, 'normal-exit stays automatic')
    color = dict((k, t) for k, _, t, _ in obs.GROUPS)['color']
    require('NOT a failure unless rendering is severe' in color, color)
    labels = obs.case_labels()
    require(set(labels) >= set(cases) and all(labels.values()))


@pytest.mark.parametrize('raw,items,expected', [
    ('p', ('c1', 'c2'), ('p', ())),
    ('P', ('c1', 'c2'), ('p', ())),
    ('n', ('c1', 'c2'), ('n', ())),
    ('q', ('c1', 'c2'), ('q', ())),
    ('f', ('c1', 'c2'), ('f', ('c1', 'c2'))),
    ('f c2', ('c1', 'c2'), ('f', ('c2',))),
    ('f c2,c1', ('c1', 'c2'), ('f', ('c2', 'c1'))),
    ('f c2, c2', ('c1', 'c2'), ('f', ('c2',))),
    ('blocked', ('c1', 'c2'), None),
    ('f c9', ('c1', 'c2'), None),
    ('pass', ('c1', 'c2'), None),
    ('', ('c1', 'c2'), None),
    ('p c1', ('c1', 'c2'), None),
    ('RAIL_VISIBLE_USABLE', ('root-gutter',), ('p', ())),
    ('NATIVE_UNOCCLUDED', ('root-gutter',), ('f', ('root-gutter',))),
    ('ROOT_GUTTER_UNPAINTABLE', ('root-gutter',), ('f', ('root-gutter',))),
    ('CAPTURED', ('early-closed-root',), ('p', ())),
    ('NOT_CAPTURED_FAIL_CLOSED', ('early-closed-root',), ('f', ('early-closed-root',))),
    ('FAIL', ('early-closed-root',), ('f', ('early-closed-root',))),
    ('NOT_RUN', ('early-closed-root',), ('n', ())),
    ('not-reproduced', ('public-observation-chatgpt',), ('nr', ())),
])
def test_parse_answer(obs, raw, items, expected):
    require(obs.parse_answer(raw, items, False) == expected, obs.parse_answer(raw, items, False))


def test_blocked_is_only_an_answer_to_the_load_group(obs):
    require(obs.parse_answer('blocked', ('extension-loaded',), True) == ('blocked', ()))


# Seal ---------------------------------------------------------------------------------------------

def test_seal_is_deterministic_exact_and_hash_bound(obs, repo_root, tmp_path, sealed):
    root, digest = sealed
    again = tmp_path / 'again'
    again.mkdir()
    require(obs.seal(repo_root, again) == digest)
    first = (tmp_path / 'sealed' / obs.KIT_ZIP).read_bytes()
    require(first == (again / obs.KIT_ZIP).read_bytes() and hashlib.sha256(first).hexdigest() == digest)
    require((again / f'{obs.KIT_ZIP}.sha256').read_text() == f'{digest}  {obs.KIT_ZIP}\n')
    expected = set(obs.SOURCE_MEMBERS) | {obs.WRAPPER, obs.README, obs.MANIFEST, obs.MEMBERS_FILE}
    with zipfile.ZipFile(again / obs.KIT_ZIP) as archive:
        infos = {i.filename: i for i in archive.infolist()}
        require(set(infos) == expected, set(infos) ^ expected)
        for name, info in infos.items():
            require(info.date_time == (1980, 1, 1, 0, 0, 0))
            require(stat.S_IMODE(info.external_attr >> 16) == (0o755 if name == obs.WRAPPER else 0o644), name)
            raw = archive.read(name)
            require(str(Path.home()).encode() not in raw, name)
            if not name.startswith('tests/cnt'):  # reused helpers are byte-identical to the repository
                require(f'/{pwd.getpwuid(os.getuid()).pw_name}/'.encode() not in raw, name)
        require(not any(n.startswith(('tests/cnt-', 'docs/', 'config/', 'modules/', 'bin/', 'flake'))
                        and n != 'tests/cnt-native-preflight.py' for n in infos), 'no repository extras')
    manifest = json.loads((root / obs.MANIFEST).read_text())
    require(manifest['r1_entry_tree'] == '75bfc971e2b81ca89039fa5dcbb97c089f6b0323')
    require(manifest['package_sha256'] == obs.kit.PACKAGE_SHA256)
    require(manifest['fixture_sha256'] == obs.kit.FIXTURE_SHA256)
    require(manifest['toplayer_fixture_sha256'] == obs.kit.TOPLAYER_FIXTURE_SHA256)
    require(manifest['shadow_sentinel_fixture_sha256'] == obs.kit.SHADOW_SENTINEL_FIXTURE_SHA256)
    for name, meta in manifest['members'].items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == meta['sha256'], name)
        if name != obs.WRAPPER and name != obs.README:
            require((root / name).read_bytes() == (repo_root / name).read_bytes(), name)
    for line in (root / obs.MEMBERS_FILE).read_text().splitlines():
        sha, name = line.split('  ', 1)
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == sha, name)
    require(obs.manifest_problems(root)[0] == [])
    with pytest.raises(obs.Refused, match='already exists'):
        obs.seal(repo_root, again)


def test_seal_binds_frozen_source_identity(obs, repo_root, tmp_path):
    tree, inventory = 'a' * 40, 'b' * 64
    obs.seal(repo_root, tmp_path, source_tree=tree, inventory_sha256=inventory)
    with zipfile.ZipFile(tmp_path / obs.KIT_ZIP) as archive:
        manifest = json.loads(archive.read(obs.MANIFEST))
    require(manifest['source_binding'] == {'tree': tree, 'inventory_sha256': inventory})


@pytest.mark.parametrize('tree,inventory', [('a' * 40, None), (None, 'b' * 64), ('bad', 'b' * 64)])
def test_seal_rejects_partial_source_binding(obs, repo_root, tmp_path, tree, inventory):
    with pytest.raises(obs.Refused, match='supplied together'):
        obs.seal(repo_root, tmp_path, source_tree=tree, inventory_sha256=inventory)
    require(not (tmp_path / obs.KIT_ZIP).exists())


def test_r10_seal_identity_preserves_r8_product_and_process_contract(obs, sealed):
    root, _ = sealed
    manifest = json.loads((root / obs.MANIFEST).read_text())
    require(obs.KIT_ZIP == 'BUX5C0-R13-SCROLLBAR-GUIDED-GUI-KIT.zip' and obs.SESSION_ROOT == SESSION_ROOT)
    require(manifest['phase'] == 'DINAS-BROWSER-UX5C0-PREFERENCES1-R10-REENABLE-FRESHNESS1', manifest['phase'])
    require(manifest['schema'] == 'bux5c0-r10-reenable-freshness1-scrollbar-guided-gui-kit-manifest-v1')
    require(manifest['process_contract'] == obs.runtime.PROCESS_CONTRACT)
    require(manifest['freshness_contract'] == obs.kit.FRESHNESS_CONTRACT)
    require(manifest['sentinel_contract'] == obs.kit.SENTINEL_CONTRACT)
    require(obs.kit.EVIDENCE == EVIDENCE, 'R10 evidence never overwrites historical evidence')
    require(manifest['package_sha256'] == 'fc5cd1e97c0e8fa708896815cd84e1061ca6e483508d0918d08d7f8c702cd0e4')
    require('tests/cnt_firefox_production.py' not in manifest['members'])
    require(not (root / 'tests/cnt_firefox_production.py').exists())
    require(manifest['resolver_contract'] == obs.RESOLVER_CONTRACT)
    ff_contract = manifest['resolver_contract']['firefox']
    require('ATTENDED_INSTALLED_FIREFOX_APP' in ff_contract)
    require('ChannelPrefs' in ff_contract)
    require('release NUL' in ff_contract)
    require('strict_min_version' in ff_contract)
    readme = (root / obs.README).read_text()
    require('attended installed Firefox' in readme and 'no CNT recovery claim' in readme, readme)
    require('156' not in readme, readme)
    require('Playwright MCP, Chrome DevTools MCP' in readme and 'must still be closed' in readme, readme)
    require('R2' not in readme and 'R3' not in readme and 'R5' not in readme and 'R2' not in (root / obs.WRAPPER).read_text() and 'R3' not in (root / obs.WRAPPER).read_text())


def test_no_kit_path_can_signal_a_process(obs, sealed):
    """The kit's own members never signal; the reused CNT helpers are byte-identical repository
    files and the kit reaches only their read-only identity readers."""
    root, _ = sealed
    own = ('tests/scrollbar_gui_observer.py', 'tests/scrollbar_gui_kit.py', 'tests/scrollbar_gui_runtime.py',
           obs.WRAPPER, obs.README)
    for name in own:
        text = (root / name).read_text()
        for token in ('kill', '.terminate(', '.send_signal', 'import signal', 'from signal',
                      'SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP'):
            require(token not in text, (name, token))
    reached = set()
    for name in own[:3]:
        reached |= set(re.findall(r'\b(d2|reader|firefox_production)\.([A-Za-z_]+)', (root / name).read_text()))
    require(reached == {('d2', 'read_bounded'), ('reader', 'chrome_bundle'), ('reader', 'CHROME_BUNDLE_ID'),
                        ('reader', 'CHROME_PREPARATION_CODES'), ('reader', 'CHROME_STORE')}, reached)


def test_wrapper_accepts_only_check_or_execute(obs, sealed):
    root, _ = sealed
    text = (root / obs.WRAPPER).read_text()
    require(text.startswith('#!/bin/zsh\n') and 'shasum -a 256 -s -c MEMBERS.sha256' in text)
    require(text.rstrip().endswith('exec python3 -I -B tests/scrollbar_gui_observer.py "$1"'))
    if not os.access('/bin/zsh', os.X_OK):
        pytest.skip('zsh unavailable; static wrapper checks only')
    for args in ([], ['--seal', 'x'], ['--check', '--execute'], ['check']):
        try:
            done = subprocess.run(['/bin/zsh', str(root / obs.WRAPPER), *args], capture_output=True, text=True,
                                  timeout=30, env={'PATH': '/usr/bin:/bin'})
        except OSError:
            pytest.skip('zsh not executable here; static wrapper checks only')
        require(done.returncode == 2 and 'usage' in done.stderr, (args, done.returncode, done.stderr))


def test_seal_refuses_inside_a_sealed_kit(load_module, sealed, tmp_path, monkeypatch):
    root, _ = sealed
    monkeypatch.setattr(sys, 'path', list(sys.path))
    inner = load_module(str(root / 'tests/scrollbar_gui_observer.py'))
    require(inner.KIT_ROOT == root)
    printed = []
    require(inner.main(['--seal', str(tmp_path)], host=object(), out=printed.append) == 2)
    require(printed == ['refused: seal runs only from a source checkout'], printed)
    require(not (tmp_path / inner.KIT_ZIP).exists())


# Check --------------------------------------------------------------------------------------------

def test_check_is_ready_read_only_and_privacy_safe(obs, host, tmp_path, sealed):
    root, _ = sealed
    before = snapshot(tmp_path)
    report, bindings = obs.check(host, root, **destinations(host, tmp_path))
    require(snapshot(tmp_path) == before, 'check created or changed nothing')
    require(report['status'] == 'READY' and report['codes'] == [], report)
    require(report['kit'] == 'SEALED_MANIFEST_MATCH' and report['sources'] == 'R8_PINS_MATCH')
    require(report['runtimes'] == IDENTITY and set(bindings) == {'chrome', 'firefox'})
    require(report['policy']['keepassxc_forced'] == list(obs.kit.KEEPASSXC_IDS), report['policy'])
    printed = []
    obs.render(report, printed.append)
    text = '\n'.join(printed) + json.dumps(report)
    require(str(tmp_path) not in text and '/observer' not in text, text)
    require(printed[-1] == 'READY')


def test_main_check_from_source_checkout(obs, host, tmp_path, monkeypatch):
    monkeypatch.setattr(obs.tempfile, 'tempdir', str(tmp_path / 'tmp'))
    printed = []
    require(obs.main(['--check'], host=host, out=printed.append) == 0, printed)
    require(any('UNSEALED_SOURCE_CHECKOUT' in line for line in printed) and printed[-1] == 'READY', printed)


def not_ready(obs, host, tmp_path, root):
    report, _ = obs.check(host, root, **destinations(host, tmp_path))
    printed = []
    obs.render(report, printed.append)
    require(report['status'] == 'NOT_READY', report)
    return report, '\n'.join(printed)


@pytest.mark.parametrize('case,code', [
    ('chrome', 'SELECTED_CHROME_UNAVAILABLE'), ('firefox', 'SELECTED_FIREFOX_UNAVAILABLE'),
    ('running', 'BROWSER_RUNNING'), ('pgrep', 'BROWSER_STATE_UNKNOWN'),
    ('policy', 'POLICY_STOP'), ('devmode', 'POLICY_STOP'), ('firefox-preferences', 'POLICY_STOP'),
    ('policy-unreadable', 'POLICY_UNREADABLE'), ('kit-member', 'KIT_IDENTITY_MISMATCH'),
    ('kit-extra', 'KIT_IDENTITY_MISMATCH'), ('extension', 'KIT_IDENTITY_MISMATCH'),
    ('outbox-absent', 'OUTBOX_UNSAFE'), ('outbox-shared', 'OUTBOX_UNSAFE'), ('outbox-link', 'OUTBOX_UNSAFE'),
    ('work-shared', 'WORK_ROOT_UNSAFE'), ('work-in-kit', 'WORK_ROOT_UNSAFE'),
])
def test_check_not_ready_codes(obs, host, tmp_path, sealed, case, code):
    root, _ = sealed
    where = destinations(host, tmp_path)
    if case == 'chrome':
        host.unavailable['chrome'] = 'SELECTION_ABSENT'
    elif case == 'firefox':
        host.unavailable['firefox'] = 'FIREFOX_VERSION_DIFFERS'
    elif case == 'running':
        host.spawn('firefox', NORMAL['firefox'])
    elif case == 'pgrep':
        host.pgrep_error = True
    elif case == 'policy':
        (host.managed_root / 'com.google.Chrome.plist').write_bytes(plistlib.dumps({'ExtensionSettings': {
            'scrollbar-visibility@browser-ux': {'installation_mode': 'force_installed'}}}))
    elif case == 'devmode':
        (host.managed_root / 'com.google.Chrome.plist').write_bytes(plistlib.dumps({'ExtensionDeveloperModeSettings': 1}))
    elif case == 'firefox-preferences':
        (host.preferences_root / 'org.mozilla.firefox.plist').write_bytes(plistlib.dumps(
            {'EnterprisePoliciesEnabled': True, 'DisableDeveloperTools': True}))
    elif case == 'policy-unreadable':
        (host.preferences_root / 'org.mozilla.firefox.plist').write_bytes(b'not a plist')
    elif case == 'kit-member':
        path = root / 'tests/scrollbar_gui_runtime.py'
        path.write_text(path.read_text() + '\n# edited\n')
    elif case == 'kit-extra':
        (root / 'tests/extra.py').write_text('')
    elif case == 'extension':
        path = root / 'extensions/browser-ux-scrollbars/scrollbars.css'
        path.write_text(path.read_text().replace('GrayText', 'CanvasText'))
    elif case == 'outbox-absent':
        shutil.rmtree(where['outbox'])
    elif case == 'outbox-shared':
        where['outbox'].chmod(0o777)
    elif case == 'outbox-link':
        real = tmp_path / 'real-outbox'
        real.mkdir(mode=0o700)
        where['outbox'].rmdir()
        where['outbox'].symlink_to(real)
    elif case == 'work-shared':
        where['work_parent'].chmod(0o777)
    else:
        (root / 'tmp').mkdir(mode=0o700)
        where['work_parent'] = root / 'tmp'
    report, _ = obs.check(host, root, **where)
    require(report['status'] == 'NOT_READY' and code in report['codes'], report['codes'])
    if case in ('chrome', 'firefox'):
        require(report['runtimes'][case] == {'result': code, 'code': host.unavailable[case]})


@pytest.mark.parametrize('mode', ['WhenScrolling', 'Automatic', ''])
def test_check_explains_the_host_scrollbar_prerequisite_without_writing(obs, host, tmp_path, sealed, mode):
    host.mode = mode
    report, text = not_ready(obs, host, tmp_path, sealed[0])
    require(report['codes'] == ['HOST_SCROLLBAR_MODE_NOT_ALWAYS'], report['codes'])
    require('HOST_SCROLLBAR_MODE_NOT_ALWAYS' in text and 'System Settings > Appearance' in text
            and 'defaults write -g AppleShowScrollBars -string Always' in text, text)


def mcp_services(host):
    return [host.spawn('chrome', command) for command in MCP]


def require_no_process_record(text, host, where):
    for name, procs in host.procs.items():
        for pid, command in procs.items():
            require(re.search(rf'\b{pid}\b', text) is None, (where, pid))
            require(command is None or command not in text, (where, command))
    for token in PROCESS_TOKENS:
        require(token not in text, (where, token))


def test_operator_mcp_collisions_alone_are_ready(obs, host, tmp_path, sealed):
    """The R2 false positive: closed browsers, only the two MCP launchers hold the Chrome name."""
    pids = mcp_services(host)
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    require(report['status'] == 'READY' and report['codes'] == [], report['codes'])
    require(report['browser_processes'] == {'chrome': 'NOT_RUNNING', 'firefox': 'NOT_RUNNING'}, report)
    require(report['browser_candidates'] == {
        'chrome': {'candidates': 2, 'real_browser': 0, 'name_collision': 2, 'unreadable': 0},
        'firefox': {'candidates': 0, 'real_browser': 0, 'name_collision': 0, 'unreadable': 0}}, report)
    printed = []
    obs.render(report, printed.append)
    require('  normal browsers: chrome NOT_RUNNING, firefox NOT_RUNNING' in printed, printed)
    require('  process-name collisions ignored (not browsers): chrome 2' in printed, printed)
    require(not any('could not be read' in line for line in printed), printed)
    require_no_process_record('\n'.join(printed) + json.dumps(report), host, 'check')
    require(set(host.procs['Google Chrome']) == set(pids), 'the MCP services are left alone')


@pytest.mark.parametrize('extra,status,code,line', [
    ('chrome', 'RUNNING', 'BROWSER_RUNNING', None),
    ('unreadable', 'UNKNOWN', 'BROWSER_STATE_UNKNOWN', '  candidates whose command line could not be read: chrome 1'),
    ('collision', 'NOT_RUNNING', None, '  process-name collisions ignored (not browsers): chrome 3'),
])
def test_mcp_collisions_do_not_hide_a_real_or_unreadable_chrome(obs, host, tmp_path, sealed, extra, status, code, line):
    mcp_services(host)
    host.spawn('chrome', {'chrome': NORMAL['chrome'], 'unreadable': None,
                          'collision': 'node tool.js --chrome ' + NORMAL['chrome']}[extra])
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    require(report['browser_processes']['chrome'] == status, report)
    require(report['codes'] == ([code] if code else []), report['codes'])
    printed = []
    obs.render(report, printed.append)
    require(line is None or line in printed, printed)
    require_no_process_record('\n'.join(printed) + json.dumps(report), host, extra)


def test_real_normal_firefox_with_mcp_services_is_running(obs, host, tmp_path, sealed):
    mcp_services(host)
    host.spawn('firefox', NORMAL['firefox'])
    host.spawn('firefox', 'node x.js --firefox ' + NORMAL['firefox'])
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    require(report['browser_processes'] == {'chrome': 'NOT_RUNNING', 'firefox': 'RUNNING'}, report)
    require(report['codes'] == ['BROWSER_RUNNING'], report['codes'])


# Execute ------------------------------------------------------------------------------------------

def test_execute_full_pass(obs, host, tmp_path, sealed):
    root, kit_digest = sealed
    code, printed, script, sessions = execute(obs, host, root, tmp_path, answers(obs) + answers(obs))
    require(code == 0, printed)
    require(len(sessions) == 1 and not script.items)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS' and result['related_frames'] == 'FULL', result)
    zipped = (session / 'bundle' / EVIDENCE).read_bytes()
    require(result['evidence_sha256'] == hashlib.sha256(zipped).hexdigest())
    require(result['kit_manifest_sha256'] == hashlib.sha256((root / obs.MANIFEST).read_bytes()).hexdigest())
    require(f'Evidence SHA-256: {result["evidence_sha256"]}' in printed, printed)
    require(any(line.startswith('Evidence: ') and str(session) in line for line in printed))
    require([name for name, _ in host.served] == [*obs.kit.FIXTURE_NAMES,
            'scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html',
            *obs.kit.FIXTURE_NAMES] * 2)
    for name, raw in host.served:
        if name == 'scrollbar-matrix.html':
            require(b'POST-EXTENSION QUALIFICATION PAGE' in raw)
        else:
            require(b"location.search = '?qual=" in raw and b"&scene=' + encodeURIComponent(menu.value);" in raw)
    require([argv[0] for argv in host.launched] == [host.bind(b)[1]['executable'] for b in ('chrome', 'firefox')])
    require(host.procs == {'Google Chrome': {}, 'firefox': {}}, 'both disposable browsers exited')
    require(closed(port_of(host)), 'fixture server closed')
    entries = obs.kit.Session(session).entries
    session_id = obs.kit.Session(session).session['session_id']
    for browser in ('chrome', 'firefox'):
        per_browser = [e for e in entries if e.get('browser') == browser]
        kinds = [e['kind'] for e in per_browser]
        phases = ['launch', 'EXTENSION_LOADED', 'fixtures-presented',
                  'FIXTURES_OPENED_POSTLOAD', 'VISUAL_GATES',
                  'EXTENSION_DISABLED', 'DISABLED_COMPARISON_FRESH',
                  'EXTENSION_REENABLED', 'ALL_FIXTURES_FRESH_POSTREENABLE',
                  'SENTINEL_VISUAL_GATES']
        require([kinds.index(p) for p in phases] == sorted(kinds.index(p) for p in phases))
        presented = per_browser[kinds.index('fixtures-presented')]
        require(presented['session_id'] == session_id and re.fullmatch('[0-9a-f]{32}', presented['token']))
        load_pass = next(e for e in per_browser if e.get('gate') == 'extension-loaded')
        require(load_pass['seq'] < presented['seq'])

        disabled_prompt = next(e for e in per_browser if e['kind'] == 'EXTENSION_DISABLED')
        disabled_proof = next(e for e in per_browser if e['kind'] == 'DISABLED_COMPARISON_FRESH')
        require(set(disabled_proof['seqs']) == set(obs.kit.RAIL_STEPS['disabled-reload']['fixtures']))
        require(all(seq > disabled_prompt['barrier'] for seq in disabled_proof['seqs'].values()))
        require(disabled_proof['token'] == presented['token'])

        reenabled_prompt = next(e for e in per_browser if e['kind'] == 'EXTENSION_REENABLED')
        reenabled_proof = next(e for e in per_browser if e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
        require(set(reenabled_proof['seqs']) == set(obs.kit.FIXTURE_NAMES))
        require(all(seq > reenabled_prompt['barrier'] for seq in reenabled_proof['seqs'].values()))
        require(reenabled_proof['token'] == presented['token'])
    observed = {(e['browser'], e['gate']) for e in entries if e['kind'] == 'observation'}
    cases = obs.kit._fixture_cases()
    expected_gates = set(cases) | set(obs.kit.BROWSER_GATES) | set(obs.kit.RECORD_ONLY_GATES) | {'normal-exit'}
    require(observed == {(b, g) for b in ('chrome', 'firefox')
                         for g in expected_gates}, 'every case ID journaled')
    # journal persistence across every prompt: each group prompt sees the previous group's entries
    group_prompts = [n for p, n in zip(script.prompts, script.lengths) if p.startswith('[')]
    require(len(group_prompts) == 2 * (len(obs.GROUPS) + 5))
    require(all(b > a for a, b in zip(group_prompts, group_prompts[1:])), group_prompts)
    require(stat.S_IMODE(session.stat().st_mode) == 0o700)
    require(not (session / 'private').exists() and not (session / 'profiles').exists(), 'work stays out of the outbox')


def test_execute_fail_is_final_and_shown(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'core-webkit': ['f c11,c12', 'no', 'f c11,c12', 'yes', 'two bars hidden']})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL' and result['reasons'] == ['chrome:c11', 'chrome:c12'], result)
    require(any(line.startswith('FAILED so far (final): chrome:c11, chrome:c12') for line in printed), printed)
    banners = [line for line in printed if line.startswith('FAILED so far')]
    require(len(banners) >= len(obs.GROUPS), 'the failure stays visible after every later group')
    entries = obs.kit.Session(sessions[0]).entries
    c11 = [e for e in entries if e.get('gate') == 'c11' and e['browser'] == 'chrome']
    require([e['result'] for e in c11] == ['fail'] and c11[0]['note'] == 'two bars hidden', c11)


def test_execute_not_run_is_incomplete_not_fail(obs, host, tmp_path, sealed):
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path,
                                         answers(obs, {'core-author': 'n'}) + answers(obs))
    require(code == 5, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'INCOMPLETE' and 'chrome:c1' in result['reasons'], result)


def test_related_frame_fail_narrows_coverage_only(obs, host, tmp_path, sealed):
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path,
                                         answers(obs, {'related': 'f c21'}) + answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 0 and result['verdict'] == 'PASS', result)
    require(result['related_frames'] == 'PARTIAL' and result['related_gaps'] == ['chrome:c21'], result)
    require(not any(line.startswith('FAILED so far') for line in printed), 'no core-fail banner')
    require('Related or record-only fails (final; never decide the core verdict): chrome:c21' in printed, printed)


@pytest.mark.parametrize('error,reason', [(EOFError, 'OBSERVER_INPUT_CLOSED'),
                                          (KeyboardInterrupt, 'OBSERVER_INTERRUPTED')])
@pytest.mark.parametrize('earlier', ['p', 'f c11'])
def test_end_of_input_or_interrupt_keeps_answers_and_still_bundles(obs, host, tmp_path, sealed, error, reason, earlier):
    items = answers(obs, {'core-webkit': earlier}, stop_after='core-webkit') + [error]
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, items)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    entries = obs.kit.Session(session).entries
    stops = [e['reason'] for e in entries if e['kind'] == 'stop']
    require(stops == [f'{reason} while chrome was open'], stops)
    require(any(e.get('gate') == 'c23' for e in entries), 'earlier answers retained')
    require(any(e.get('gate') == 'normal-exit' for e in entries), 'the browser was waited for, not signalled')
    require(len(host.launched) == 1, 'firefox never launched')
    require(result['verdict'] == ('FAIL' if earlier.startswith('f') else 'INCOMPLETE'), result)
    require(code == (4 if earlier.startswith('f') else 5))
    require(closed(port_of(host)))


@pytest.mark.parametrize('browser,reason', [('chrome', 'CHROME_LOAD_UNPACKED_ROUTE_BLOCKED'),
                                            ('firefox', 'FIREFOX_TEMPORARY_ADDON_ROUTE_BLOCKED')])
def test_load_route_blocked_is_a_bounded_stop(obs, host, tmp_path, sealed, browser, reason):
    items = ['blocked'] if browser == 'chrome' else answers(obs) + ['blocked']
    code, _, script, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE' and reason in result['reasons'], result)
    require(len(host.launched) == (1 if browser == 'chrome' else 2) and not script.items)


def test_operator_quit_stops_the_session(obs, host, tmp_path, sealed):
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs, {'layout': 'q'}))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and 'OPERATOR_STOPPED during chrome layout' in result['reasons'], result)


def test_browser_exiting_early_stops_without_asking_more(obs, host, tmp_path, sealed):
    host.exit_early.add('chrome')
    code, _, script, sessions = execute(obs, host, sealed[0], tmp_path, [])
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and 'chrome exited before every group was observed' in result['reasons'], result)
    require(len(script.prompts) == 1 and obs.FORCE_INSTALL_ACK in script.prompts[0], script.prompts)
    require(len(host.launched) == 1)


def test_execute_passes_with_mcp_services_running_throughout(obs, host, tmp_path, sealed):
    """MCP services never stop; the disposable Chrome counts as running only while it lives."""
    mcp = mcp_services(host)
    states = []

    def observe(answer):
        def at(prompt):
            states.append((prompt.split(']')[0] + ']', len(host.launched),
                           obs.runtime.browser_processes(host.run)))
            return answer
        return at
    chrome, firefox = answers(obs), answers(obs)
    chrome[0], firefox[0] = observe(chrome[0]), observe(firefox[0])
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, chrome + firefox)
    require(code == 0, printed)
    require(states == [('[chrome load]', 1, {'chrome': 'RUNNING', 'firefox': 'NOT_RUNNING'}),
                       ('[firefox load]', 2, {'chrome': 'NOT_RUNNING', 'firefox': 'RUNNING'})], states)
    require(not any(p.startswith('Still not proven closed') for p in script.prompts), script.prompts)
    require(set(host.procs['Google Chrome']) == set(mcp) and host.procs['firefox'] == {},
            'MCP services untouched; both disposable browsers exited')
    session = sessions[0]
    result = (session / 'RESULT.json').read_bytes()
    require(json.loads(result)['verdict'] == 'PASS')
    for name, raw in [*evidence(session).items(), ('RESULT.json', result)]:
        require_no_process_record(raw.decode(), host, name)
        for pid in mcp:
            require(re.search(rf'\b{pid}\b', raw.decode()) is None, (name, pid))


def test_next_browser_waits_until_the_first_is_proven_closed(obs, host, tmp_path, sealed):
    """The disposable Chrome main process outlives its handle: Firefox waits until it is gone."""
    host.linger.add('chrome')
    seen = []

    def finally_gone(prompt):
        seen.append((len(host.launched), obs.runtime.browser_processes(host.run)['chrome']))
        host.procs['Google Chrome'].clear()
        return ''
    code, printed, script, _ = execute(obs, host, sealed[0], tmp_path, answers(obs) + [finally_gone] + answers(obs))
    require(code == 0, printed)
    require(seen == [(1, 'RUNNING')], seen)
    require([p for p in script.prompts if p.startswith('Still not proven closed')]
            == ["Still not proven closed: ['chrome']. Quit it, then press Enter (q stops the session): "], script.prompts)
    require(len(host.launched) == 2)


def test_still_running_browser_can_only_stop_the_session(obs, host, tmp_path, sealed):
    host.linger.add('chrome')
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + ['q'])
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and 'BROWSER_STILL_RUNNING after chrome' in result['reasons'], result)
    require(len(host.launched) == 1, 'firefox never launched while chrome may still run')


def test_sentinel_change_after_chrome_stops_before_firefox(obs, host, tmp_path, sealed):
    profiles = host.home / 'Library/Application Support/Firefox/profiles.ini'
    host.on_wait['chrome'] = lambda: profiles.write_text('[Profile9]\n')
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and any('live browser state changed: firefox-profiles-ini' in r for r in result['reasons']), result)
    require(len(host.launched) == 1)


def test_scratch_tamper_between_browsers_stops_before_firefox(obs, host, tmp_path, sealed):
    def tamper():
        work = next((tmp_path / 'tmp').glob(f'{obs.WORK_PREFIX}*/work'))
        css = work / 'extension/scrollbars.css'
        css.write_text(css.read_text().replace('GrayText', 'CanvasText'))
    host.on_wait['chrome'] = tamper
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and any('scrollbars.css is not R8' in r for r in result['reasons']), result)
    require(len(host.launched) == 1)


@pytest.mark.parametrize('field,drifted_val', [
    ('version', '158.0'),
    ('build_id', '20261001000000'),
    ('executable_sha256', 'f' * 64),
])
def test_runtime_drift_during_firefox_stops(obs, host, tmp_path, sealed, field, drifted_val):
    host.on_wait['firefox'] = lambda: host.identity['firefox'].update({field: drifted_val})
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and any('firefox RUNTIME_CHANGED during the session' in r for r in result['reasons']), result)


def test_execute_refuses_unsealed_and_not_ready_without_creating_anything(obs, host, tmp_path, repo_root, sealed):
    where = destinations(host, tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(obs.Refused, match='KIT_NOT_SEALED'):
        obs.execute(host, lambda p: 'p', lambda line: None, repo_root, where['outbox'], where['work_parent'], where['uid'])
    host.mode = 'WhenScrolling'
    require(obs.execute(host, lambda p: 'p', lambda line: None, sealed[0], where['outbox'],
                        where['work_parent'], where['uid']) == 3)
    require(snapshot(tmp_path) == before and host.launched == [])
    host.mode = 'Always'
    path = sealed[0] / 'tests/scrollbar_gui_kit.py'
    path.write_text(path.read_text() + '\n')
    with pytest.raises(obs.Refused, match='KIT_IDENTITY_MISMATCH'):
        obs.execute(host, lambda p: 'p', lambda line: None, sealed[0], where['outbox'], where['work_parent'], where['uid'])


@pytest.mark.parametrize('reply', ['', 'yes', 'p', EOFError, KeyboardInterrupt])
def test_force_install_residual_must_be_accepted_before_any_session(obs, host, tmp_path, sealed, reply):
    before = snapshot(tmp_path)
    with pytest.raises(obs.Refused, match=obs.FORCE_INSTALL_DECLINED):
        execute(obs, host, sealed[0], tmp_path, [reply], ack=False)
    require(snapshot(tmp_path) == before and host.launched == [], 'nothing created or launched')


def test_force_install_acceptance_is_journaled_before_launch(obs, host, tmp_path, sealed):
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs))
    require(code == 0, printed)
    require(any(line.startswith('LIVE_POLICY_FORCE_INSTALL: ') and 'keepassxc-browser@keepassxc.org' in line
                for line in printed), printed)
    entries = obs.kit.Session(sessions[0]).entries
    kinds = [e['kind'] for e in entries]
    require(kinds.index('acknowledged') < kinds.index('launch'), kinds)
    ack = entries[kinds.index('acknowledged')]
    require(ack['residual'] == 'LIVE_POLICY_FORCE_INSTALL'
            and ack['force_installed'] == ['keepassxc-browser@keepassxc.org', 'oboonakemofpalcgghocfoadofidjkkk'], ack)
    require(b'"acknowledged"' in evidence(sessions[0])['journal.jsonl'])


def test_no_force_install_means_no_acknowledgement_prompt(obs, host, tmp_path, sealed):
    for domain in LIVE_SHAPE:
        (host.managed_root / f'{domain}.plist').write_bytes(plistlib.dumps({'ExtensionSettings': {
            '*': {'installation_mode': 'allowed'}}}))
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs), ack=False)
    require(code == 0 and not any(obs.FORCE_INSTALL_ACK in p for p in script.prompts), printed)
    require('acknowledged' not in [e['kind'] for e in obs.kit.Session(sessions[0]).entries])


def test_policy_change_after_acknowledgement_stops_before_launch(obs, host, tmp_path, sealed, monkeypatch):
    original, calls = obs.kit.classify_policy, []

    def classify(h):
        calls.append(1)
        stops, keys, forced = original(h)
        return stops, keys, forced + (['late@example.invalid'] if len(calls) > 1 else [])
    monkeypatch.setattr(obs.kit, 'classify_policy', classify)
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, [])
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and 'LIVE_POLICY_CHANGED after the force-install acknowledgement' in result['reasons'], result)
    require(host.launched == [])


@pytest.mark.parametrize('failure', ['timeout', 'missing'])
def test_host_command_timeout_or_missing_binary_is_bounded(obs, tmp_path, monkeypatch, failure):
    if failure == 'timeout':
        def run(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs.get('timeout'))
        monkeypatch.setattr(obs.kit.subprocess, 'run', run)
        argv, code = ['/usr/bin/true'], 124
    else:
        argv, code = [str(tmp_path / 'absent-binary')], 127
    real = obs.kit.Host(home=tmp_path)
    require(real.run(argv) == (code, ''))
    if failure == 'timeout':
        require(set(obs.runtime.browser_processes(real.run).values()) == {obs.runtime.UNKNOWN})
        require(obs.runtime.host_scrollbar_mode(real.run) != obs.runtime.SCROLLBAR_ALWAYS)


def test_a_new_execution_never_resumes_or_changes_an_old_session(obs, host, tmp_path, sealed):
    _, _, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs, {'layout': 'f c9'}) + answers(obs))
    old = snapshot(sessions[0])
    code, _, _, sessions_after = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs))
    require(code == 0 and len(sessions_after) == 2 and snapshot(sessions[0]) == old)
    new = next(s for s in sessions_after if s != sessions[0])
    require(json.loads((new / 'RESULT.json').read_text())['verdict'] == 'PASS')
    require(json.loads((sessions[0] / 'RESULT.json').read_text())['verdict'] == 'FAIL')


def test_evidence_is_deterministic_and_privacy_safe(obs, host, tmp_path, sealed, monkeypatch):
    monkeypatch.setattr(obs.kit.time, 'time', lambda: 1790000000.0)
    monkeypatch.setattr(obs.secrets, 'token_hex', lambda n: '5' * (2 * n))
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    outputs = []
    for run in ('one', 'two'):
        home = host.home
        outbox = tmp_path / run / 'outbox'
        outbox.mkdir(parents=True, mode=0o700)
        (tmp_path / run).chmod(0o700)
        work_parent = tmp_path / run / 'tmp'
        work_parent.mkdir(mode=0o700)
        printed = []
        code = obs.execute(host, Script([obs.FORCE_INSTALL_ACK] + answers(obs) + answers(obs), outbox, port, host),
                           printed.append, sealed[0],
                           outbox, work_parent, os.getuid(), port)
        require(code == 0 and home == host.home, printed)
        session = next((outbox / obs.SESSION_ROOT).glob('*'))
        outputs.append((evidence(session), (session / 'RESULT.json').read_bytes(), printed))
    (first, result_one, printed), (second, result_two, _) = outputs
    require(first == second and result_one == result_two, 'same answers give the same evidence bytes')
    for name, raw in [*first.items(), ('RESULT.json', result_one)]:
        for token in (str(tmp_path), str(Path.home()), '/observer', '/nix/store/', '/Users/', '/var/folders/'):
            require(token.encode() not in raw, (name, token))
    session = json.loads(first['SESSION.json'])
    require(session['runtimes'] == IDENTITY and session['work'] == '<work>')
    require(any(str(tmp_path) in line for line in printed), 'paths are printed locally only')


def test_observer_pins_match_the_preferences_suite(obs, load_module):
    prefs_test = (Path(obs.__file__).parent / 'browser-preferences.test.py').read_text()
    for name, pin in obs.kit.MEMBER_SHA256.items():
        require(pin in prefs_test, pin)
    require(obs.kit.FIXTURE_SHA256 in prefs_test, obs.kit.FIXTURE_SHA256)
    require(obs.kit.PACKAGE_SHA256 in prefs_test, obs.kit.PACKAGE_SHA256)


def test_execute_root_gutter_unpaintable_fails_gate_with_material_hold(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'root-gutter': 'ROOT_GUTTER_UNPAINTABLE'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL', result)
    require('chrome:root-gutter' in result['reasons'], result['reasons'])
    require(result['root_gutter']['chrome'] == 'ROOT_GUTTER_UNPAINTABLE')
    require(result['root_gutter']['firefox'] == 'RAIL_VISIBLE_USABLE')
    entries = obs.kit.Session(session).entries
    rg_entry = next(e for e in entries if e.get('gate') == 'root-gutter' and e['browser'] == 'chrome')
    require(rg_entry['result'] == 'fail')
    require(rg_entry['root_gutter'] == 'ROOT_GUTTER_UNPAINTABLE')
    require('material hold' in rg_entry['note'])


def test_execute_root_gutter_native_unoccluded_fails_gate(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'root-gutter': 'NATIVE_UNOCCLUDED'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL', result)
    require('chrome:root-gutter' in result['reasons'], result['reasons'])
    require(result['root_gutter']['chrome'] == 'NATIVE_UNOCCLUDED')
    require(result['root_gutter']['firefox'] == 'RAIL_VISIBLE_USABLE')
    entries = obs.kit.Session(session).entries
    rg_entry = next(e for e in entries if e.get('gate') == 'root-gutter' and e['browser'] == 'chrome')
    require(rg_entry['result'] == 'fail')
    require(rg_entry['root_gutter'] == 'NATIVE_UNOCCLUDED')
    require('native-only visibility does not qualify' in rg_entry['note'])


def test_execute_root_gutter_rail_visible_usable_passes(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'root-gutter': 'RAIL_VISIBLE_USABLE'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 0, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS', result)
    require(result['root_gutter']['chrome'] == 'RAIL_VISIBLE_USABLE')
    require(result['root_gutter']['firefox'] == 'RAIL_VISIBLE_USABLE')
    entries = obs.kit.Session(session).entries
    rg_entry = next(e for e in entries if e.get('gate') == 'root-gutter' and e['browser'] == 'chrome')
    require(rg_entry['result'] == 'pass')
    require(rg_entry['root_gutter'] == 'RAIL_VISIBLE_USABLE')


def test_execute_root_gutter_failure_disqualifies_earlier_challenge_scenes(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'root-gutter': 'NATIVE_UNOCCLUDED'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    session = sessions[0]
    entries = obs.kit.Session(session).entries
    after_entry = next(e for e in entries if e.get('gate') == 'root-after' and e['browser'] == 'chrome' and e['result'] == 'fail')
    require('disqualified by root-gutter NATIVE_UNOCCLUDED' in after_entry['note'])
    mask_entry = next(e for e in entries if e.get('gate') == 'root-mask-clip' and e['browser'] == 'chrome' and e['result'] == 'fail')
    require('disqualified by root-gutter NATIVE_UNOCCLUDED' in mask_entry['note'])


def test_generic_pass_selects_only_rail_visible_root_gutter_branch(obs):
    require(obs.parse_answer('p', ('root-gutter',), False) == ('p', ()))
    require(obs.parse_answer('RAIL_VISIBLE_USABLE', ('root-gutter',), False) == ('p', ()))
    require(obs.parse_answer('NATIVE_UNOCCLUDED', ('root-gutter',), False) == ('f', ('root-gutter',)))
    require(obs.parse_answer('ROOT_GUTTER_UNPAINTABLE', ('root-gutter',), False) == ('f', ('root-gutter',)))


def test_optional_public_observation_has_its_own_non_gating_group(obs):
    groups = [g for g in obs.GROUPS if 'public-observation-chatgpt' in g[3]]
    require(len(groups) == 1 and groups[0][3] == ('public-observation-chatgpt',))
    require(obs.parse_answer('not-reproduced', groups[0][3], False) == ('nr', ()))


def test_execute_early_closed_root_not_captured_fails_gate_with_manager_limit(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'early-closed-root': 'NOT_CAPTURED_FAIL_CLOSED'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL', result)
    require('chrome:early-closed-root' in result['reasons'], result['reasons'])
    require(result['early_closed_root']['chrome'] == 'NOT_CAPTURED_FAIL_CLOSED')
    require(result['early_closed_root']['firefox'] == 'CAPTURED')
    entries = obs.kit.Session(session).entries
    early_entry = next(e for e in entries if e.get('gate') == 'early-closed-root' and e['browser'] == 'chrome')
    require(early_entry['result'] == 'fail')
    require(early_entry['early_closed_root'] == 'NOT_CAPTURED_FAIL_CLOSED')
    require('manager limit' in early_entry['note'])


def test_execute_early_closed_root_captured_passes(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'early-closed-root': 'CAPTURED'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 0, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS', result)
    require(result['early_closed_root']['chrome'] == 'CAPTURED')
    require(result['early_closed_root']['firefox'] == 'CAPTURED')
    entries = obs.kit.Session(session).entries
    early_entry = next(e for e in entries if e.get('gate') == 'early-closed-root' and e['browser'] == 'chrome')
    require(early_entry['result'] == 'pass')
    require(early_entry['early_closed_root'] == 'CAPTURED')


def test_generic_pass_cannot_invent_early_closed_root_branch(obs):
    require(obs.parse_answer('p', ('early-closed-root',), False) is None)
    require(obs.parse_answer('CAPTURED', ('early-closed-root',), False) == ('p', ()))
    require(obs.parse_answer('NOT_CAPTURED_FAIL_CLOSED', ('early-closed-root',), False) == ('f', ('early-closed-root',)))
    require(obs.parse_answer('FAIL', ('early-closed-root',), False) == ('f', ('early-closed-root',)))
    require(obs.parse_answer('NOT_RUN', ('early-closed-root',), False) == ('n', ()))


def test_representative_prompts_require_custom_rail_and_native_diagnostics(obs):
    required = ('A 1–2 px border is not a scrollbar.',
                'Native scrollbar visibility alone does not prove the custom top-layer rail.',
                'Gray box borders do not qualify.',
                'Pass requires the custom Canvas/GrayText rail and working drag/track/wheel behavior',
                'GrayText/Canvas coloring alone can come from native restoration')
    for gate in ('c1', 'c16', 'c23', 'c5', 'root-gutter', 'nested-overlay', 'handshake'):
        group = next(g for g in obs.GROUPS if gate in g[3])
        for text in required:
            require(text in group[2], (gate, text))
    for gate in ('c1', 'c16', 'c23', 'c5'):
        instruction = next(g[2] for g in obs.GROUPS if gate in g[3])
        require('native/computed-style diagnostics' in instruction and 'must be noted' in instruction
                and 'reloaded before observation' in instruction)
    compare = next(g[2] for g in obs.GROUPS if g[0] == 'rail-discriminator')
    require(all(x in compare for x in ('t3', 't7', 't8', 't5', 'ABOVE the covers')))
    require('The served Scene menu preserves the qualification token' in compare)
    require('do not use the fixture Scene menu' not in compare)


@pytest.mark.parametrize('raw,items,expected', [
    ('native c1', ('c1', 'c2'), ('native', ('c1',))),
    ('native', ('c1', 'c2'), ('native', ('c1', 'c2'))),
    ('native', ('custom-rail-discriminator',), ('native', ('custom-rail-discriminator',))),
    ('native', ('extension-loaded',), None),
    ('native', ('public-observation-chatgpt',), None),
])
def test_native_answer_is_never_a_pass(obs, raw, items, expected):
    require(obs.parse_answer(raw, items, False) == expected)
    require(expected is None or expected[0] != 'p')


def test_native_only_first_tab_answer_records_sticky_failure(obs, host, tmp_path, sealed):
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path,
        answers(obs, {'core-author': 'native c1'}) + answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 4 and result['verdict'] == 'FAIL' and 'chrome:c1' in result['reasons'])
    entry = next(e for e in obs.kit.Session(sessions[0]).entries if e.get('gate') == 'c1')
    require(entry['result'] == 'fail' and 'NATIVE_ONLY' in entry['note'])


def test_native_only_discriminator_cannot_be_converted_to_visual_pass(obs, host, tmp_path, sealed):
    overrides = {key: 'n' for key, _, _, items in obs.GROUPS
                 if any(item in obs.kit.CUSTOM_RAIL_GATES for item in items)}
    overrides['rail-discriminator'] = 'native'
    overrides['core-frames'] = ['p', 'n', '']
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path,
        answers(obs, overrides) + answers(obs))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 4 and 'chrome:custom-rail-discriminator' in result['reasons'], result)
    require(any('These items cannot pass' in line for line in printed))
    entries = obs.kit.Session(sessions[0]).entries
    require(not any(e.get('browser') == 'chrome' and e.get('gate') in obs.kit.CUSTOM_RAIL_GATES
                    and e.get('result') == 'pass' for e in entries))


@pytest.mark.parametrize('missing', ['scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html',
                                   'scrollbar-shadow-sentinel-matrix.html', 'all', 'stale'])
@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_observer_freshness_failure_stops_before_visual_prompt(obs, host, tmp_path, sealed, missing, browser):
    def open_incomplete(prompt):
        script = Script([], destinations(host, tmp_path)['outbox'], host.fixture_port, host)
        if missing != 'all':
            names = tuple(n for n in obs.kit.FIXTURE_NAMES if n != missing)
            script.fetch(names, token='stale' if missing == 'stale' else None)
        return ''
    items = (answers(obs) if browser == 'firefox' else []) + ['p', '', open_incomplete] + [''] * obs.kit.FRESHNESS_RETRIES
    code, _, script, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE', result)
    require(any('FIXTURE_NOT_POSTLOAD_FRESH' in r for r in result['reasons']), result)
    require(not any(p.startswith(f'[{browser} rail-discriminator]') or p.startswith(f'[{browser} core-')
                    for p in script.prompts))
    require(closed(port_of(host)))


@pytest.mark.parametrize('step,expected_code', [
    ('disabled-reload', 'RAIL_COMPARISON_NOT_PROVEN'),
    ('reenabled-reload', 'FIXTURE_NOT_POSTREENABLE_FRESH'),
])
@pytest.mark.parametrize('only', ['scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html'])
def test_each_comparison_step_requires_both_pages_after_prompt(obs, host, tmp_path, sealed, step, expected_code, only):
    def one_page(prompt):
        Script([], destinations(host, tmp_path)['outbox'], host.fixture_port, host).fetch((only,))
        return ''
    items = ['p', '', '@fixtures']
    if step == 'disabled-reload':
        items += ['', one_page]
    else:
        items += ['', '@reload-both', '', one_page]
    items += [''] * obs.kit.FRESHNESS_RETRIES
    code, _, script, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE', result)
    require(any(expected_code in r for r in result['reasons']), result)
    require(not any('rail-discriminator]' in p for p in script.prompts))


@pytest.mark.parametrize('at', ['fixtures', 'extension-disabled', 'disabled-reload',
                                'extension-reenabled', 'reenabled-reload', 'rail-discriminator'])
@pytest.mark.parametrize('error,reason', [(KeyboardInterrupt, 'OBSERVER_INTERRUPTED'),
                                          (EOFError, 'OBSERVER_INPUT_CLOSED')])
def test_interrupt_at_postload_or_discriminator_remains_incomplete(obs, host, tmp_path, sealed, at, error, reason):
    actions = {
        'fixtures': [],
        'extension-disabled': ['@fixtures'],
        'disabled-reload': ['@fixtures', ''],
        'extension-reenabled': ['@fixtures', '', '@reload-both'],
        'reenabled-reload': ['@fixtures', '', '@reload-both', ''],
        'rail-discriminator': ['@fixtures', '', '@reload-both', '', '@reload-all-three'],
    }
    items = ['p', ''] + actions[at] + [error]
    code, _, _, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE', result)
    require(f'{reason} while chrome was open' in result['reasons'])
    entries = obs.kit.Session(sessions[0]).entries
    require(any(e.get('gate') == 'normal-exit' for e in entries))
    require(len(host.launched) == 1 and closed(port_of(host)))


def test_firefox_comparison_has_in_profile_temporary_reload_fallback(obs, host, tmp_path, sealed):
    code, printed, _, _ = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs))
    require(code == 0, printed)
    text = '\n'.join(printed)
    require('about:addons' in text and 'about:debugging > this add-on > Remove' in text
            and 'Load Temporary Add-on' in text and 'same extension/manifest.json' in text)
    scene_urls = [line for line in printed if line.startswith('http://127.0.0.1:') and '&scene=' in line]
    require(len(scene_urls) > 0 and all('?qual=' in line for line in scene_urls))
    for url in scene_urls:
        require(url.count('?qual=') == 1 and '&qual=' not in url)
    scenes_present = {line.rsplit('&scene=', 1)[1] for line in scene_urls}
    require({'overlays', 'visual-overlay', 'root-after'}.issubset(scenes_present))


@pytest.mark.parametrize('reply', ['n', 'f'])
def test_extension_not_loaded_cannot_present_qualification_urls(obs, host, tmp_path, sealed, reply):
    items = [reply] + (['yes'] if reply == 'f' else []) + ['']
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == (4 if reply == 'f' else 5), result)
    require('EXTENSION_NOT_LOADED chrome' in result['reasons'] or
            'stopped: EXTENSION_NOT_LOADED chrome' in result['reasons'], result)
    require(not any('?qual=' in line and line.startswith('http') for line in printed))
    require(not any('fixtures]' in p for p in script.prompts))


def test_execute_coverage_throttle_recovery_fails_gate(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'coverage-throttle': 'f'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL', result)
    require('chrome:coverage-throttle-recovery' in result['reasons'], result['reasons'])
    entries = obs.kit.Session(session).entries
    cov_entry = next(e for e in entries if e.get('gate') == 'coverage-throttle-recovery' and e['browser'] == 'chrome')
    require(cov_entry['result'] == 'fail')


def test_execute_coverage_throttle_recovery_passes(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'coverage-throttle': 'p'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 0, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS', result)
    entries = obs.kit.Session(session).entries
    cov_entry = next(e for e in entries if e.get('gate') == 'coverage-throttle-recovery' and e['browser'] == 'chrome')
    require(cov_entry['result'] == 'pass')


def test_execute_detached_root_reattach_fails_gate(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'detached-root': 'f'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 4, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL', result)
    require('chrome:detached-root-reattach' in result['reasons'], result['reasons'])
    entries = obs.kit.Session(session).entries
    detached_entry = next(e for e in entries if e.get('gate') == 'detached-root-reattach' and e['browser'] == 'chrome')
    require(detached_entry['result'] == 'fail')


def test_execute_detached_root_reattach_passes(obs, host, tmp_path, sealed):
    chrome = answers(obs, {'detached-root': 'p'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs))
    require(code == 0, printed)
    session = sessions[0]
    result = json.loads((session / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS', result)
    entries = obs.kit.Session(session).entries
    detached_entry = next(e for e in entries if e.get('gate') == 'detached-root-reattach' and e['browser'] == 'chrome')
    require(detached_entry['result'] == 'pass')


def test_f13_post_toggle_barrier_capture_and_dual_prompt_flow(obs, host, tmp_path, sealed):
    """Barrier is captured ONLY after operator toggle acknowledgment at [browser extension-disabled];
    requests made before the toggle acknowledgment (<= barrier) are rejected."""
    def premature_request_before_toggle_ack(prompt):
        Script([], destinations(host, tmp_path)['outbox'], host.fixture_port, host).fetch(
            ('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html'))
        return ''

    def do_nothing_at_reload(prompt):
        return ''

    items = ['p', '', '@fixtures', premature_request_before_toggle_ack, do_nothing_at_reload] + [''] * obs.kit.FRESHNESS_RETRIES
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE', result)
    require(any('RAIL_COMPARISON_NOT_PROVEN' in r for r in result['reasons']), result)
    entries = obs.kit.Session(sessions[0]).entries
    toggle_entry = next(e for e in entries if e['kind'] == 'EXTENSION_DISABLED')
    require(toggle_entry['barrier'] >= 5)


def _f14_two_sessions(obs, host, tmp_path, sealed):
    def only_matrix_and_toplayer_at_reenabled(prompt):
        Script([], destinations(host, tmp_path)['outbox'], host.fixture_port, host).fetch(
            ('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html'))
        return ''

    items_missing_sentinel = ['p', '', '@fixtures', '', '@reload-both', '', only_matrix_and_toplayer_at_reenabled] + [''] * obs.kit.FRESHNESS_RETRIES
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items_missing_sentinel)
    require(len(sessions) == 1, sessions)
    first = sessions[0]
    result = json.loads((first / 'RESULT.json').read_text())
    require(code == 5 and result['verdict'] == 'INCOMPLETE', result)
    require(any('FIXTURE_NOT_POSTREENABLE_FRESH' in r for r in result['reasons']), result)
    entries = obs.kit.Session(first).entries
    require(not any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in entries))
    old = snapshot(first)

    outbox = destinations(host, tmp_path)['outbox']
    before_second = session_paths(outbox)
    items_complete = answers(obs, stop_after='rail-discriminator') + ['q']
    code2, _, _, sessions2 = execute(obs, host, sealed[0], tmp_path, items_complete)
    second = unique_new_session(before_second, session_paths(outbox))
    require(second != first, (first, second))

    require(snapshot(first) == old, 'first session changed across second execute')
    first_result = json.loads((first / 'RESULT.json').read_text())
    require(first_result['verdict'] == 'INCOMPLETE', first_result)
    require(any('FIXTURE_NOT_POSTREENABLE_FRESH' in r for r in first_result['reasons']), first_result)
    first_entries = obs.kit.Session(first).entries
    require(not any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in first_entries))

    entries2 = obs.kit.Session(second).entries
    require(any(e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE' for e in entries2))
    require(any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in entries2))
    sentinel_entry = next(e for e in entries2 if e['kind'] == 'SENTINEL_VISUAL_GATES')
    proof_entry = next(e for e in entries2 if e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
    require(sentinel_entry['seq'] > proof_entry['seq'])
    require(set(proof_entry['seqs'].keys()) == set(obs.kit.FIXTURE_NAMES), proof_entry)
    return first, second, entries2


def test_f14_reenabled_reload_requires_all_three_fixtures(obs, host, tmp_path, sealed):
    """Reenabled reload requires all three fixtures including sentinel post-barrier.
    Missing sentinel stops with FIXTURE_NOT_POSTREENABLE_FRESH; reloading all three emits SENTINEL_VISUAL_GATES."""
    _f14_two_sessions(obs, host, tmp_path, sealed)


def test_f14_same_timestamp_reversed_suffix_selects_new_session(obs, host, tmp_path, sealed, monkeypatch):
    suffixes = iter(['ffffffff', '00000000'])
    fake_time = types.SimpleNamespace(
        strftime=lambda fmt, *args: '20261003T000000Z',
        gmtime=lambda *args: None,
    )
    fake_secrets = types.SimpleNamespace(
        token_hex=lambda n=4: next(suffixes),
    )
    monkeypatch.setattr(obs, 'time', fake_time)
    monkeypatch.setattr(obs, 'secrets', fake_secrets)

    first, second, entries2 = _f14_two_sessions(obs, host, tmp_path, sealed)

    require(first.name == '20261003T000000Z-ffffffff', first.name)
    require(second.name == '20261003T000000Z-00000000', second.name)
    outbox = destinations(host, tmp_path)['outbox']
    trap = sorted(session_paths(outbox))[-1]
    require(trap == first, f'lexical trap: sorted()[-1] was {trap}, expected {first}')
    require(any(e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE' for e in entries2))
    require(any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in entries2))
    require(next(suffixes, None) is None, 'expected exactly two suffixes to be consumed')


def test_f15_generated_urls_group_coverage_and_binding_callable(obs, host, tmp_path, sealed):
    """Every group receives plain fixture links appropriate for matrix and shadow record-only cases;
    binding link callable prints no URLs at load before extension-loaded; every scene URL has current token once."""
    token = '1234567890abcdef1234567890abcdef'
    port = 8123

    fake_scratch = tmp_path / 'fake-scratch'
    fake_scratch.mkdir()
    (fake_scratch / 'SESSION.json').write_text(json.dumps({
        'schema': obs.kit.SESSION_SCHEMA, 'session_id': 'a' * 32, 'host': {'AppleShowScrollBars': 'Always'},
        'cases': {}, 'runtimes': {b: {} for b in obs.kit.BROWSERS}, 'residuals': []
    }))
    (fake_scratch / 'journal.jsonl').write_text('')
    fake_server = type('FakeServer', (), {'server_address': ('127.0.0.1', port)})()

    link_fn = obs.binding_link_callable(fake_scratch, 'chrome', fake_server, out=lambda u: None)
    require(link_fn('load') == [], 'load group must not produce links before extension-loaded')

    core_urls = obs.group_urls(port, token, 'core-frames')
    require(core_urls == [f'http://127.0.0.1:{port}/scrollbar-matrix.html?qual={token}'])

    record_urls = obs.group_urls(port, token, 'record-only')
    require(f'http://127.0.0.1:{port}/scrollbar-matrix.html?qual={token}' in record_urls)
    require(f'http://127.0.0.1:{port}/scrollbar-shadow-sentinel-matrix.html?qual={token}' in record_urls)

    toplayer_urls = obs.group_urls(port, token, 'toplayer-occlusion')
    require(f'http://127.0.0.1:{port}/scrollbar-toplayer-matrix.html?qual={token}' in toplayer_urls)
    for scene in obs.GROUP_SCENES['toplayer-occlusion']:
        expected_scene_url = f'http://127.0.0.1:{port}/scrollbar-toplayer-matrix.html?qual={token}&scene={scene}'
        require(expected_scene_url in toplayer_urls)

    for key, scenes in obs.GROUP_SCENES.items():
        urls = obs.group_urls(port, token, key)
        for u in urls:
            require(u.count('?qual=') == 1 and '&qual=' not in u, u)
            require(f'?qual={token}' in u, u)
    for key, scene in (('sentinel-handshake', 'control'), ('sentinel-handshake', 'early-closed'),
                       ('coverage-throttle', 'throttle-recovery'), ('detached-root', 'detached-root'),
                       ('record-only', 'detached-root')):
        url = obs.kit.qualification_url(port, 'scrollbar-shadow-sentinel-matrix.html', token, scene)
        require(url in obs.group_urls(port, token, key), (key, scene))


def test_f16_review_evidence_classification(obs, host, tmp_path, sealed):
    """Pre-initial visual journal evidence remains FAIL;
    premature sentinel after initial before reenable is invalid evidence INCOMPLETE (unless real fail)."""
    scratch = tmp_path / 'scratch-f16'
    session = obs.kit.prepare(scratch, host)
    obs.kit.begin_launch(scratch, 'chrome', host, 8123)
    s = obs.kit.Session(scratch)
    s.append('observation', browser='chrome', gate='c1', result='pass', note='')
    s.append('stop', reason='OPERATOR_STOPPED')
    verdict, reasons = obs.kit.verdict(s.session, s.entries)
    require(verdict == 'FAIL', (verdict, reasons))
    require(any('without valid VISUAL_GATES chain' in r for r in reasons), reasons)
    host.procs['Google Chrome'].clear()

    scratch2 = tmp_path / 'scratch-f16-sentinel'
    session2 = obs.kit.prepare(scratch2, host)
    obs.kit.begin_launch(scratch2, 'chrome', host, 8123)
    obs.kit.record(scratch2, 'chrome', 'extension-loaded', 'pass')
    obs.kit.mark_extension_loaded(scratch2, 'chrome', 0)
    tok = obs.kit.present_fixtures(scratch2, 'chrome')
    seqs = {name: i + 1 for i, name in enumerate(obs.kit.FIXTURE_NAMES)}
    reqs = [{'seq': seqs[name], 'method': 'GET', 'path': f'/{name}', 'qual': [tok]} for name in obs.kit.FIXTURE_NAMES]
    obs.kit.prove_postload(scratch2, 'chrome', reqs)

    with pytest.raises(obs.kit.KitError) as exc_info:
        obs.kit.record(scratch2, 'chrome', 'handshake', 'pass')
    require(exc_info.value.code == 'FIXTURE_NOT_POSTREENABLE_FRESH')

    s2 = obs.kit.Session(scratch2)
    s2.append('observation', browser='chrome', gate='handshake', result='pass', note='')
    s2.append('stop', reason='TEST_STOP')
    v2, r2 = obs.kit.verdict(s2.session, s2.entries)
    require(v2 == 'INCOMPLETE', (v2, r2))
    require(any('FIXTURE_NOT_POSTREENABLE_FRESH' in r for r in r2), r2)

    s2.append('observation', browser='chrome', gate='c1', result='fail', note='')
    v3, r3 = obs.kit.verdict(s2.session, s2.entries)
    require(v3 == 'FAIL', (v3, r3))
    host.procs['Google Chrome'].clear()


def test_f17_deterministic_python_substitution_parse_no_node(obs, host, tmp_path, sealed):
    """Pure deterministic Python substitution parse; verifies response rewrite and scene preservation
    without node dependency."""
    scratch = tmp_path / 'scratch-f17'
    session = obs.kit.prepare(scratch, host)
    site_dir = scratch / 'site'
    ledger = obs.kit.RequestLedger()
    token = '0123456789abcdef0123456789abcdef'
    ledger.set_qualification(token)

    status, matrix_content = obs.kit.fixture_response(ledger, site_dir, 'GET', f'/scrollbar-matrix.html?qual={token}')
    require(status == 200)
    require(obs.kit.POST_EXTENSION_QUALIFICATION_BANNER in matrix_content)

    for fix_name in ('scrollbar-toplayer-matrix.html', 'scrollbar-shadow-sentinel-matrix.html'):
        orig_bytes = (site_dir / fix_name).read_bytes()
        require(orig_bytes.count(obs.kit.SCENE_MENU_ASSIGNMENT) == 1)
        status, fix_content = obs.kit.fixture_response(ledger, site_dir, 'GET', f'/{fix_name}?qual={token}')
        require(status == 200)
        require(obs.kit.SCENE_MENU_ASSIGNMENT not in fix_content)
        expected_assignment = ("location.search = '?qual=" + token + "&scene=' + encodeURIComponent(menu.value);").encode()
        require(expected_assignment in fix_content)

        match = re.search(rb"location.search = '([^']*)' \+ encodeURIComponent\(menu.value\);", fix_content)
        require(match is not None)
        prefix = match.group(1).decode()
        for scene in obs.kit.SCENES[fix_name]:
            simulated_query = prefix + urllib.parse.quote(scene, safe="~()*!.'-")
            parsed_qs = urllib.parse.parse_qs(simulated_query.removeprefix('?'))
            require(parsed_qs == {'qual': [token], 'scene': [scene]})

    status, unqual = obs.kit.fixture_response(ledger, site_dir, 'GET', '/scrollbar-toplayer-matrix.html')
    require(unqual == (site_dir / 'scrollbar-toplayer-matrix.html').read_bytes())

    status, frame_req = obs.kit.fixture_response(ledger, site_dir, 'GET', f'/scrollbar-toplayer-matrix.html?qual={token}&frame=1')
    require(frame_req == (site_dir / 'scrollbar-toplayer-matrix.html').read_bytes())


def test_socket_denied_classified_as_environment_denied_failure(obs, host, tmp_path, sealed, monkeypatch):
    """Socket denied during fixture_server stops with FIXTURE_SERVER_UNAVAILABLE (INCOMPLETE, not pass)."""
    def socket_denied(work, port):
        raise OSError('Permission denied (socket creation blocked in sandbox)')
    monkeypatch.setattr(obs.kit, 'fixture_server', socket_denied)
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs), port=8123)
    require(code == 5, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'INCOMPLETE', result)
    require('FIXTURE_SERVER_UNAVAILABLE' in result['reasons'], result['reasons'])


class FakeFixtureServer:
    """Non-network fake server using RequestLedger for deterministic socket-free testing."""
    def __init__(self, work, kit):
        self.site_dir = Path(work) / 'site'
        self.kit = kit
        self.ledger = kit.RequestLedger()
        self.server_address = ('127.0.0.1', 8123)
        self.stop_event = threading.Event()

    def snapshot_requests(self):
        return self.ledger.snapshot_requests()

    def request_barrier(self):
        return self.ledger.request_barrier()

    def set_qualification(self, token):
        self.ledger.set_qualification(token)

    def fetch(self, name, token):
        status, body = self.kit.fixture_response(self.ledger, self.site_dir, 'GET', f'/{name}?qual={token}')
        return status, body

    def serve_forever(self):
        self.stop_event.wait()

    def shutdown(self):
        self.stop_event.set()

    def server_close(self):
        pass


def install_ledger_transport(obs, monkeypatch):
    """Explicit fake HTTP transport; real loopback tests remain separate integration evidence."""
    servers = []

    def make_server(work, port):
        server = FakeFixtureServer(work, obs.kit)
        servers.append(server)
        return server

    def fetch(script, names=None, token=None):
        session = unique_new_session(script.before, session_paths(script.outbox))
        entries = [json.loads(line) for line in (session / 'journal.jsonl').read_text().splitlines()]
        presented = next(e for e in reversed(entries) if e['kind'] == 'fixtures-presented')
        token = presented['token'] if token is None else token
        for name in names or obs.kit.FIXTURE_NAMES:
            status, body = servers[-1].fetch(name, token)
            require(status == 200)
            if script.host is not None:
                script.host.served.append((name, body))

    monkeypatch.setattr(obs.kit, 'fixture_server', make_server)
    monkeypatch.setattr(Script, 'fetch', fetch)
    return servers


def test_fake_server_request_ledger_non_network_flow(obs, host, tmp_path, sealed, monkeypatch):
    servers = install_ledger_transport(obs, monkeypatch)
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path,
                                            answers(obs) + answers(obs), port=8123)
    require(code == 0, printed)
    require(not script.items)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'PASS', result)
    entries = obs.kit.Session(sessions[0]).entries
    require([name for name, _ in host.served] == [*obs.kit.FIXTURE_NAMES,
            *obs.kit.FIXTURE_NAMES[:2], *obs.kit.FIXTURE_NAMES] * 2)
    tokens = [e['token'] for e in entries if e['kind'] == 'fixtures-presented']
    require(len(set(tokens)) == 2)
    for browser in obs.kit.BROWSERS:
        per_browser = [e for e in entries if e.get('browser') == browser]
        require(obs.kit.browser_phase(entries, browser) == 'SENTINEL_VISUAL_GATES')
        proof = next(e for e in per_browser if e['kind'] == 'ALL_FIXTURES_FRESH_POSTREENABLE')
        require(set(proof['seqs']) == set(obs.kit.FIXTURE_NAMES))
    scene_urls = [line for line in printed if line.startswith('http://') and '&scene=' in line]
    require(scene_urls)
    for url in scene_urls:
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        require(qs['qual'] in [[token] for token in tokens] and len(qs['scene']) == 1, url)
    require('Remove' in '\n'.join(printed) and 'Load Temporary Add-on' in '\n'.join(printed))
    require(len(servers) == 1 and servers[0].stop_event.is_set())
    require(host.procs == {'Google Chrome': {}, 'firefox': {}})


@pytest.mark.parametrize('step', ['extension-disabled', 'extension-reenabled'])
@pytest.mark.parametrize('interrupt', [EOFError, KeyboardInterrupt])
def test_r10_ledger_interrupt_at_toggle_stays_incomplete(obs, host, tmp_path, sealed, monkeypatch, step, interrupt):
    servers = install_ledger_transport(obs, monkeypatch)
    items = ['p', '', '@fixtures']
    if step == 'extension-reenabled':
        items += ['', '@reload-both']
    items += [interrupt]
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    require(code == 5, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'INCOMPLETE')
    require(any(step in prompt for prompt in script.prompts))
    entries = obs.kit.Session(sessions[0]).entries
    require(any(e.get('gate') == 'normal-exit' and e['result'] == 'pass' for e in entries))
    require(not any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in entries))
    require(servers[0].stop_event.is_set())


@pytest.mark.parametrize('step', ['extension-disabled', 'extension-reenabled'])
def test_r10_ledger_gets_before_toggle_acknowledgement_do_not_count(obs, host, tmp_path, sealed, monkeypatch, step):
    install_ledger_transport(obs, monkeypatch)
    def premature_gets(prompt):
        Script([], destinations(host, tmp_path)['outbox'], 8123, host).fetch()
        return ''
    items = ['p', '', '@fixtures']
    if step == 'extension-reenabled':
        items += ['', '@reload-both']
    items += [premature_gets, ''] + [''] * obs.kit.FRESHNESS_RETRIES
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    require(code == 5, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    code = 'FIXTURE_NOT_POSTREENABLE_FRESH' if step == 'extension-reenabled' else 'RAIL_COMPARISON_NOT_PROVEN'
    require(result['verdict'] == 'INCOMPLETE' and any(code in reason for reason in result['reasons']))


@pytest.mark.parametrize('phase,missing', [
    ('initial', ('scrollbar-matrix.html',)),
    ('disabled', ('scrollbar-matrix.html',)),
    ('disabled', ('scrollbar-toplayer-matrix.html',)),
    ('disabled', ('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html')),
    ('reenabled', ('scrollbar-shadow-sentinel-matrix.html',)),
])
def test_r13_missing_fixture_recovers_without_rebasing(obs, host, tmp_path, sealed, monkeypatch, phase, missing):
    servers = install_ledger_transport(obs, monkeypatch)
    outbox = destinations(host, tmp_path)['outbox']
    observed = {}
    printed = []

    def first_attempt(prompt):
        session = next(iter(session_paths(outbox)))
        target = obs.kit.pending_fixture_proof(session, 'chrome')
        observed['target'] = target
        for name in target['names']:
            if name not in missing:
                servers[-1].fetch(name, target['token'])
        observed['seqs'] = obs.kit.fixture_proof_status(
            servers[-1].snapshot_requests(), target['names'], target['token'], target['barrier'])['seqs']
        return ''

    def retry(prompt):
        require('retry 1/3' in prompt)
        session = next(iter(session_paths(outbox)))
        state = obs.kit.Session(session)
        before = (session / 'journal.jsonl').read_bytes()
        target = obs.kit.pending_fixture_proof(session, 'chrome')
        require(target == observed['target'])
        require(not state.stopped)
        fresh = {'initial': 'FIXTURES_OPENED_POSTLOAD', 'disabled': 'DISABLED_COMPARISON_FRESH',
                 'reenabled': 'ALL_FIXTURES_FRESH_POSTREENABLE'}[phase]
        require(not any(e['kind'] == fresh for e in state.entries))
        for gate, code in [('no-extension-console-errors', 'FIXTURE_NOT_POSTLOAD_FRESH'),
                           ('handshake', 'FIXTURE_NOT_POSTREENABLE_FRESH'),
                           ('custom-rail-discriminator', 'FIXTURE_NOT_POSTREENABLE_FRESH')]:
            with pytest.raises(obs.kit.KitError) as error:
                obs.kit.record(session, 'chrome', gate, 'pass')
            require(error.value.code == code)
        require((session / 'journal.jsonl').read_bytes() == before)
        marker = next(i for i, line in enumerate(printed) if line.startswith('Still missing a fresh GET for:'))
        retry_urls = [line for line in printed[marker:] if line.startswith('http://')]
        require(retry_urls == [obs.kit.qualification_url(8123, name, target['token']) for name in missing])
        require('Still missing a fresh GET for: ' + ', '.join(missing) in printed)
        for name in missing:
            servers[-1].fetch(name, target['token'])
        return ''

    chrome = answers(obs)
    index = {'initial': 2, 'disabled': 4, 'reenabled': 6}[phase]
    chrome[index:index + 1] = [first_attempt, retry]
    script = Script([obs.FORCE_INSTALL_ACK] + chrome + answers(obs), outbox, 8123, host)
    where = destinations(host, tmp_path)
    code = obs.execute(host, script, printed.append, sealed[0], outbox, where['work_parent'], where['uid'], 8123)
    require(code == 0, printed)
    require(not script.items)
    state = obs.kit.Session(next(iter(session_paths(outbox))))
    target = observed['target']
    proof = next(e for e in state.entries if e.get('browser') == 'chrome' and e['kind'] == {
        'initial': 'FIXTURES_OPENED_POSTLOAD', 'disabled': 'DISABLED_COMPARISON_FRESH',
        'reenabled': 'ALL_FIXTURES_FRESH_POSTREENABLE'}[phase])
    require(proof['barrier'] == target['barrier'] and proof['token'] == target['token'])
    require(all(proof['seqs'][name] == seq for name, seq in observed['seqs'].items()))
    require(len([e for e in state.entries if e['kind'] == 'fixtures-presented' and e['browser'] == 'chrome']) == 1)
    retries = [e for e in state.entries if e['kind'] == 'freshness-retry']
    require(len(retries) == 1 and retries[0]['missing'] == list(missing) and 'phase' not in retries[0])
    require(not any(e['kind'] == 'stop' for e in state.entries))
    require(servers[0].stop_event.is_set())


@pytest.mark.parametrize('invalid', ['HEAD', 'wrong-token', 'stale-token', 'pre-barrier'])
def test_r13_invalid_reload_remains_missing_through_exhaustion(obs, host, tmp_path, sealed, monkeypatch, invalid):
    servers = install_ledger_transport(obs, monkeypatch)
    outbox = destinations(host, tmp_path)['outbox']
    target = {}

    def reload_invalid(prompt):
        session = next(iter(session_paths(outbox)))
        current = obs.kit.pending_fixture_proof(session, 'chrome')
        if target:
            require(current == target)
        else:
            target.update(current)
        token = current['token'] if invalid in ('HEAD', 'pre-barrier') else ('a' * 32 if invalid == 'stale-token' else 'wrong')
        if invalid != 'pre-barrier':
            servers[-1].ledger.record('HEAD' if invalid == 'HEAD' else 'GET', '/scrollbar-matrix.html', [token])
        servers[-1].fetch('scrollbar-toplayer-matrix.html', current['token'])
        return ''

    items = ['p', '', '@fixtures', '', reload_invalid] + [reload_invalid] * obs.kit.FRESHNESS_RETRIES
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    state = obs.kit.Session(sessions[0])
    stops = [e for e in state.entries if e['kind'] == 'stop']
    require(code == 5 and obs.kit.verdict(state.session, state.entries)[0] == 'INCOMPLETE', printed)
    require(len(stops) == 1 and stops[0]['reason'] == 'RAIL_COMPARISON_NOT_PROVEN')
    require(stops[0]['missing'] == ['scrollbar-matrix.html'])
    require(len([e for e in state.entries if e['kind'] == 'freshness-retry']) == 3)
    require(not any(e['kind'] == 'DISABLED_COMPARISON_FRESH' for e in state.entries))
    require(not any('rail-discriminator]' in p for p in script.prompts))
    require(servers[0].stop_event.is_set())


@pytest.mark.parametrize('phase', ['initial', 'disabled', 'reenabled'])
@pytest.mark.parametrize('retry', [False, True])
def test_r13_q_records_one_stop_with_original_reason(obs, host, tmp_path, sealed, monkeypatch, phase, retry):
    servers = install_ledger_transport(obs, monkeypatch)
    items = ['p', '']
    if phase != 'initial':
        items += ['@fixtures', '']
    if phase == 'reenabled':
        items += ['@reload-both', '']
    items += (['', 'q'] if retry else ['q'])
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    stops = [e for e in obs.kit.Session(sessions[0]).entries if e['kind'] == 'stop']
    label = {'initial': 'fixtures', 'disabled': 'disabled-reload', 'reenabled': 'reenabled-reload'}[phase]
    require(code == 5 and len(stops) == 1, printed)
    require(stops[0]['reason'] == f'OPERATOR_STOPPED during chrome {label}')
    require(('missing' in stops[0]) == retry)
    require(servers[0].stop_event.is_set())


@pytest.mark.parametrize('phase,code_name', [('initial', 'FIXTURE_NOT_POSTLOAD_FRESH'),
                                           ('reenabled', 'FIXTURE_NOT_POSTREENABLE_FRESH')])
def test_r13_all_three_exhaustion_stays_incomplete(obs, host, tmp_path, sealed, monkeypatch, phase, code_name):
    servers = install_ledger_transport(obs, monkeypatch)
    items = ['p', '']
    if phase == 'reenabled':
        items += ['@fixtures', '', '@reload-both', '']
    items += [''] * (obs.kit.FRESHNESS_RETRIES + 1)
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    state = obs.kit.Session(sessions[0])
    stops = [e for e in state.entries if e['kind'] == 'stop']
    require(code == 5 and len(stops) == 1 and stops[0]['reason'] == code_name, printed)
    require(stops[0]['missing'] == list(obs.kit.FIXTURE_NAMES))
    require(not any(e['kind'] == 'SENTINEL_VISUAL_GATES' for e in state.entries))
    require(servers[0].stop_event.is_set())


def test_r13_readiness_quiescence_is_read_only_and_private(obs, host, tmp_path, sealed):
    before = snapshot(tmp_path)
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    printed = []
    obs.render(report, printed.append)
    require(report['status'] == 'READY' and report['live_sentinels'] == 'QUIESCENT')
    require(host.slept == [1.0, 1.0] and snapshot(tmp_path) == before)
    text = json.dumps(report) + '\n'.join(printed)
    require('live sentinels: QUIESCENT' in '\n'.join(printed))
    for value in [str(host.home), str(tmp_path), 'Local State', 'profiles.ini', 'installs.ini',
                  *[v for v in obs.kit.sentinel_digests(host).values() if v != 'absent']]:
        require(value not in text, value)


@pytest.mark.parametrize('state,code_name', [('RUNNING', 'BROWSER_RUNNING'), ('UNKNOWN', 'BROWSER_STATE_UNKNOWN')])
def test_r13_busy_readiness_skips_sentinels(obs, host, tmp_path, sealed, monkeypatch, state, code_name):
    host.spawn('chrome', NORMAL['chrome'] if state == 'RUNNING' else None)
    def forbidden(*args, **kwargs):
        raise AssertionError('sentinels sampled while browser busy')
    monkeypatch.setattr(obs.kit, 'quiescent_sentinel_digests', forbidden)
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    require(report['status'] == 'NOT_READY' and report['live_sentinels'] == 'NOT_SAMPLED')
    require(report['codes'] == [code_name] and not host.slept)


@pytest.mark.parametrize('drift_sample', [2, 3])
def test_r13_readiness_drift_refuses_privately(obs, host, tmp_path, sealed, drift_sample):
    sentinel = host.sentinels()['chrome-local-state']
    host.on_sleep = [None] * (drift_sample - 2) + [lambda: sentinel.write_text('changed')]
    report, _ = obs.check(host, sealed[0], **destinations(host, tmp_path))
    printed = []
    obs.render(report, printed.append)
    require(report['status'] == 'NOT_READY' and report['codes'] == ['LIVE_SENTINEL_NOT_QUIESCENT'])
    require(report['live_sentinels'] == 'LIVE_SENTINEL_NOT_QUIESCENT')
    require(host.slept == [1.0] * (drift_sample - 1))
    require(str(sentinel) not in '\n'.join(printed))


@pytest.mark.parametrize('change', ['sentinel', 'browser'])
def test_r13_execute_refuses_before_creating_any_session(obs, host, tmp_path, sealed, change):
    where = destinations(host, tmp_path)
    def acknowledge(prompt):
        require(host.slept == [1.0, 1.0], 'readiness sampling changed')
        if change == 'sentinel':
            host.on_sleep = [lambda: host.sentinels()['chrome-local-state'].write_text('delayed-write')]
        else:
            host.spawn('chrome', NORMAL['chrome'])
        return obs.FORCE_INSTALL_ACK
    with pytest.raises(obs.Refused) as error:
        obs.execute(host, acknowledge, lambda line: None, sealed[0], **where)
    require(('LIVE_SENTINEL_NOT_QUIESCENT' if change == 'sentinel' else 'BROWSER_RUNNING') in str(error.value))
    require(not (where['outbox'] / obs.SESSION_ROOT).exists())
    require(not list(where['work_parent'].iterdir()) and not host.launched)


@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_r13_prelaunch_drift_stops_before_start(obs, host, tmp_path, sealed, monkeypatch, browser):
    servers = install_ledger_transport(obs, monkeypatch)
    original = obs.kit.print_guide
    def guide(current, work, out):
        original(current, work, out)
        if current == browser:
            host.sentinels()['chrome-local-state'].write_text('changed-before-launch')
    monkeypatch.setattr(obs.kit, 'print_guide', guide)
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, answers(obs) + answers(obs), port=8123)
    state = obs.kit.Session(sessions[0])
    stops = [e for e in state.entries if e['kind'] == 'stop']
    require(code == 5 and len(stops) == 1, printed)
    require(stops[0]['reason'] == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
    require(stops[0]['changed'] == ['chrome-local-state'])
    require(stops[0]['baseline'] == 'SESSION_BASELINE_UNCHANGED')
    require(stops[0]['prior_browser_exit_checked'] == (browser == 'firefox'))
    require(len(host.launched) == (1 if browser == 'firefox' else 0))
    require(not any(e['kind'] == 'launch' and e['browser'] == browser for e in state.entries))
    require(servers[0].stop_event.is_set())


@pytest.mark.parametrize('reversed_suffix', [False, True])
def test_r13_socket_free_r11_session_selection(obs, host, tmp_path, sealed, monkeypatch, reversed_suffix):
    servers = install_ledger_transport(obs, monkeypatch)
    original_execute = execute
    def ledger_execute(*args, **kwargs):
        kwargs.setdefault('port', 8123)
        return original_execute(*args, **kwargs)
    monkeypatch.setitem(globals(), 'execute', ledger_execute)
    if reversed_suffix:
        test_f14_same_timestamp_reversed_suffix_selects_new_session(obs, host, tmp_path, sealed, monkeypatch)
    else:
        test_f14_reenabled_reload_requires_all_three_fixtures(obs, host, tmp_path, sealed)
    require(len(servers) == 2 and all(server.stop_event.is_set() for server in servers))


def test_r13_retry_browser_exit_stops_once(obs, host, tmp_path, sealed, monkeypatch):
    servers = install_ledger_transport(obs, monkeypatch)
    def incomplete_then_exit(prompt):
        host.exit_early.add('chrome')
        return ''
    items = ['p', '', '@fixtures', '', incomplete_then_exit]
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path, items, port=8123)
    stops = [e for e in obs.kit.Session(sessions[0]).entries if e['kind'] == 'stop']
    require(code == 5 and len(stops) == 1, printed)
    require(stops[0]['reason'] == 'chrome exited during disabled-reload')
    require(not any('retry' in prompt for prompt in script.prompts))
    require(servers[0].stop_event.is_set())


def test_r10_ledger_native_only_stays_fail(obs, host, tmp_path, sealed, monkeypatch):
    install_ledger_transport(obs, monkeypatch)
    chrome = answers(obs, {'rail-discriminator': 'native', 'core-frames': 'n', 'core-author': 'n',
                          'core-webkit': 'n', 'related': 'n', 'color': 'n', 'toplayer-occlusion': 'n',
                          'interaction-priority': 'n', 'popover-lifecycle': 'n', 'resilience-integrity': 'n',
                          'eligibility-dynamics': 'n', 'root-gutter': 'NOT_RUN', 'sentinel-handshake': 'n',
                          'shadow-lifecycle': 'n', 'shadow-bounds': 'n', 'early-closed-root': 'NOT_RUN',
                          'coverage-throttle': 'n', 'detached-root': 'n'})
    code, printed, _, sessions = execute(obs, host, sealed[0], tmp_path, chrome + answers(obs), port=8123)
    require(code == 4, printed)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == 'FAIL' and 'chrome:custom-rail-discriminator' in result['reasons'])


@pytest.fixture
def r14_kit(obs, repo_root, tmp_path, monkeypatch):
    out = tmp_path / 'firefox-only-seal'
    out.mkdir()
    obs.seal(repo_root, out, firefox_only=True)
    root = tmp_path / 'firefox-only-kit'
    with zipfile.ZipFile(out / obs.FIREFOX_ONLY_KIT_ZIP) as archive:
        archive.extractall(root)
    # The scripted operator enumerates the mode-specific session directory.
    monkeypatch.setitem(globals(), 'SESSION_ROOT', obs.FIREFOX_ONLY_SESSION_ROOT)
    return root


def run_r14(obs, host, tmp_path, r14_kit, monkeypatch, overrides=None):
    install_ledger_transport(obs, monkeypatch)
    return execute(obs, host, r14_kit, tmp_path,
                   answers(obs, {'root-gutter': 'p', **(overrides or {})}),
                   port=8123, firefox_only=True)


@pytest.mark.parametrize('raw,expected', [
    ('p', ('p', ())), ('P', ('p', ())),
    ('rail_visible_usable', ('p', ())), ('RAIL_VISIBLE_USABLE', ('p', ())),
    ('f', ('f', ('root-gutter',))), ('FAIL', ('f', ('root-gutter',))),
    ('native_unoccluded', ('f', ('root-gutter',))),
    ('ROOT_GUTTER_UNPAINTABLE', ('f', ('root-gutter',))),
    ('n', ('n', ())), ('NOT_RUN', ('n', ())), ('Q', ('q', ())),
    ('invalid', None), ('p x', None), ('', None),
])
def test_r14_root_gutter_parser_table(obs, raw, expected):
    require(obs.parse_answer(raw, ('root-gutter',), False) == expected)


@pytest.mark.parametrize('answer,branch,verdict,code', [
    ('p', 'RAIL_VISIBLE_USABLE', 'PASS', 0),
    ('RAIL_VISIBLE_USABLE', 'RAIL_VISIBLE_USABLE', 'PASS', 0),
    ('f', 'FAIL', 'FAIL', 4), ('FAIL', 'FAIL', 'FAIL', 4),
    ('NATIVE_UNOCCLUDED', 'NATIVE_UNOCCLUDED', 'FAIL', 4),
    ('ROOT_GUTTER_UNPAINTABLE', 'ROOT_GUTTER_UNPAINTABLE', 'FAIL', 4),
    ('n', 'NOT_RUN', 'INCOMPLETE', 5), ('NOT_RUN', 'NOT_RUN', 'INCOMPLETE', 5),
])
def test_r14_prior_success_then_root_answer_advances_once(obs, host, tmp_path, r14_kit,
                                                        monkeypatch, answer, branch, verdict, code):
    got, printed, script, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch,
                                            {'root-gutter': answer})
    require(got == code, printed)
    prompts = script.prompts
    indices = [i for i, p in enumerate(prompts) if p.startswith('[firefox root-gutter]')]
    require(len(indices) == 1 and not script.items)
    root_index = indices[0]
    require(sum(p.startswith('[firefox ') for p in prompts[:root_index]) > 10)
    next_gate = next(p for p in prompts[root_index + 1:] if p.startswith('[firefox '))
    require(next_gate.startswith('[firefox sentinel-handshake]'))
    state = obs.kit.Session(sessions[0])
    gate = next(e for e in state.entries if e.get('gate') == 'root-gutter')
    require(gate['root_gutter'] == branch)
    require(gate['result'] == ('pass' if verdict == 'PASS' else 'not-run' if branch == 'NOT_RUN' else 'fail'))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['verdict'] == verdict)
    if branch == 'ROOT_GUTTER_UNPAINTABLE':
        require(any('material hold' in r for r in result['reasons']))


def test_r14_combined_prior_success_then_one_p_advances(obs, host, tmp_path, sealed, monkeypatch):
    install_ledger_transport(obs, monkeypatch)
    code, printed, script, sessions = execute(obs, host, sealed[0], tmp_path,
        answers(obs, {'root-gutter': 'p'}) + answers(obs, {'root-gutter': 'p'}), port=8123)
    require(code == 0 and not script.items, printed)
    for browser in obs.kit.BROWSERS:
        require(sum(p.startswith(f'[{browser} root-gutter]') for p in script.prompts) == 1)
    require(json.loads((sessions[0] / 'RESULT.json').read_text())['verdict'] == 'PASS')


def test_r14_invalid_reprompts_then_one_p_returns(obs, host, tmp_path, r14_kit, monkeypatch):
    code, printed, script, _ = run_r14(obs, host, tmp_path, r14_kit, monkeypatch,
                                     {'root-gutter': ['invalid', 'p', '']})
    require(code == 0 and not script.items, printed)
    require(sum(p.startswith('[firefox root-gutter]') for p in script.prompts) == 2)
    require(any('p = RAIL_VISIBLE_USABLE' in line for line in printed))


def test_r14_root_q_stops_once(obs, host, tmp_path, r14_kit, monkeypatch):
    code, printed, script, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch,
                                             {'root-gutter': 'q'})
    stops = [e for e in obs.kit.Session(sessions[0]).entries if e['kind'] == 'stop']
    require(code == 5 and len(stops) == 1, printed)
    require(not any(p.startswith('[firefox sentinel-handshake]') for p in script.prompts))


@pytest.mark.parametrize('chrome', ['RUNNING', 'UNKNOWN', 'NOT_RUNNING'])
def test_r14_readiness_ignores_chrome_process_and_binding(obs, host, tmp_path, r14_kit, chrome):
    if chrome != 'NOT_RUNNING':
        host.spawn('chrome', NORMAL['chrome'] if chrome == 'RUNNING' else None)
    host.unavailable['chrome'] = 'NO_CHROME_BIND_ALLOWED'
    before = snapshot(tmp_path)
    report, bindings = obs.check(host, r14_kit, **destinations(host, tmp_path), firefox_only=True)
    printed = []
    obs.render(report, printed.append)
    require(report['status'] == 'READY' and set(bindings) == {'firefox'})
    require(snapshot(tmp_path) == before)
    require('chrome: OUT_OF_SCOPE (may remain running)' in '\n'.join(printed))
    require(set(report['browser_processes']) == {'firefox'})
    require(not any(token in json.dumps(report) + '\n'.join(printed) for token in PROCESS_TOKENS))


@pytest.mark.parametrize('command,code', [(NORMAL['firefox'], 'BROWSER_RUNNING'),
                                        (None, 'BROWSER_STATE_UNKNOWN')])
def test_r14_firefox_busy_skips_sampling(obs, host, tmp_path, r14_kit, monkeypatch, command, code):
    host.spawn('firefox', command)
    def forbidden(*args, **kwargs):
        raise AssertionError('sampling while Firefox busy')
    monkeypatch.setattr(obs.kit, 'quiescent_sentinel_digests', forbidden)
    report, _ = obs.check(host, r14_kit, **destinations(host, tmp_path), firefox_only=True)
    require(report['status'] == 'NOT_READY' and report['codes'] == [code])


def test_r14_full_firefox_flow_provenance_and_no_chrome(obs, host, tmp_path, r14_kit, monkeypatch):
    host.spawn('chrome', NORMAL['chrome'])
    host.unavailable['chrome'] = 'FORBIDDEN'
    # An unreadable Chrome sentinel cannot be opened in any Firefox-only phase.
    chrome = host.sentinels()['chrome-local-state']
    chrome.unlink()
    chrome.mkdir()
    host.on_wait['firefox'] = lambda: (chrome / 'changed').write_text('out of scope')
    code, printed, script, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
    require(code == 0 and not script.items, printed)
    require(len(host.launched) == 1 and '--use-mock-keychain' not in host.launched[0])
    work = next((tmp_path / 'tmp').iterdir()) / 'work'
    require(not (work / 'profiles/chrome').exists())
    local = json.loads((work / 'private/LOCAL.json').read_text())
    state = obs.kit.Session(sessions[0])
    require(set(local['runtimes']) == set(state.session['runtimes']) == {'firefox'})
    require(set(state.session['sentinels']) == set(obs.kit.FIREFOX_SENTINELS))
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(result['chrome']['fresh_launch'] is False)
    require(result['chrome']['authority_sha256'] == obs.kit.CHROME_AUTHORITY_SHA256)
    require(result['firefox']['fresh_launch'] is True)
    require(result['firefox']['version'] == IDENTITY['firefox']['version'])
    require(result['firefox']['runtime_sha256'] == IDENTITY['firefox']['runtime_sha256'])
    require(result['verdict'] == result['firefox_verdict'] == 'PASS')
    require(obs.kit.browser_phase(state.entries, 'firefox') == 'SENTINEL_VISUAL_GATES')
    require([g[3] for g in obs.FIREFOX_ONLY_GROUPS] == [g[3] for g in obs.GROUPS])
    text = '\n'.join(printed + script.prompts)
    for excluded in ('######## Google Chrome', '== Google Chrome', '[chrome ', 'chrome://',
                     'Load unpacked', 'Developer mode'):
        require(excluded not in text, excluded)
    with zipfile.ZipFile(sessions[0] / 'bundle' / obs.kit.FIREFOX_ONLY_EVIDENCE) as archive:
        summary = json.loads(archive.read('SUMMARY.json'))
        require(summary['verdict_scope'] == 'FRESH_FIREFOX_ONLY')
        require(obs.sha256(archive.read('CHROME-AUTHORITY.json')) == obs.kit.CHROME_AUTHORITY_SHA256)


@pytest.mark.parametrize('sentinel', ['firefox-profiles-ini', 'firefox-installs-ini'])
@pytest.mark.parametrize('when', ['readiness', 'execute', 'prelaunch', 'exit'])
def test_r14_firefox_sentinel_drift_fails_closed(obs, host, tmp_path, r14_kit, monkeypatch, sentinel, when):
    change = lambda: host.sentinels()[sentinel].write_text('drift')
    if when == 'readiness':
        host.on_sleep = [change]
        report, _ = obs.check(host, r14_kit, **destinations(host, tmp_path), firefox_only=True)
        require(report['status'] == 'NOT_READY' and 'LIVE_SENTINEL_NOT_QUIESCENT' in report['codes'])
        return
    if when == 'execute':
        def acknowledge(prompt):
            host.on_sleep = [change]
            return obs.FORCE_INSTALL_ACK
        with pytest.raises(obs.Refused, match='LIVE_SENTINEL_NOT_QUIESCENT'):
            obs.execute(host, acknowledge, lambda _: None, r14_kit,
                        **destinations(host, tmp_path), firefox_only=True)
        require(not (destinations(host, tmp_path)['outbox'] / obs.FIREFOX_ONLY_SESSION_ROOT).exists())
        require(not list((tmp_path / 'tmp').iterdir()))
        return
    if when == 'prelaunch':
        original = obs.kit.print_guide
        def guide(browser, work, out):
            original(browser, work, out)
            change()
        monkeypatch.setattr(obs.kit, 'print_guide', guide)
    else:
        host.on_wait['firefox'] = change
    code, printed, _, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
    require(code != 0, printed)
    if when == 'prelaunch':
        require(not host.launched)
        stops = [e for e in obs.kit.Session(sessions[0]).entries if e['kind'] == 'stop']
        require(stops[0]['reason'] == 'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
        require(stops[0]['changed'] == [sentinel])
    require(json.loads((sessions[0] / 'RESULT.json').read_text())['verdict'] != 'PASS')


@pytest.mark.parametrize('when', ['readiness', 'execute', 'prelaunch', 'exit'])
def test_r14_chrome_sentinel_drift_never_blocks(obs, host, tmp_path, r14_kit, monkeypatch, when):
    change = lambda: host.sentinels()['chrome-local-state'].write_text('out of scope')
    if when == 'readiness':
        host.on_sleep = [change]
    elif when == 'execute':
        host.on_sleep = [None, None, change]
    elif when == 'prelaunch':
        original = obs.kit.print_guide
        def guide(browser, work, out):
            original(browser, work, out)
            change()
        monkeypatch.setattr(obs.kit, 'print_guide', guide)
    else:
        host.on_wait['firefox'] = change
    code, printed, _, _ = run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
    require(code == 0, printed)


@pytest.mark.parametrize('attack', ['missing', 'tampered', 'rehashed', 'symlink'])
def test_r14_authority_refuses_even_rehashed_manifest(obs, host, tmp_path, r14_kit, attack):
    path = r14_kit / obs.kit.CHROME_AUTHORITY_MEMBER
    original = path.read_bytes()
    if attack == 'missing':
        path.unlink()
    elif attack == 'symlink':
        path.unlink()
        target = tmp_path / 'authority-copy'
        target.write_bytes(original)
        path.symlink_to(target)
    else:
        value = json.loads(original)
        value['version'] = '149.0.0.0'
        path.write_text(json.dumps(value))
    if attack == 'rehashed':
        manifest = json.loads((r14_kit / obs.MANIFEST).read_text())
        manifest['members'][obs.kit.CHROME_AUTHORITY_MEMBER]['sha256'] = obs.sha256(path.read_bytes())
        manifest['chrome_authority']['sha256'] = obs.sha256(path.read_bytes())
        (r14_kit / obs.MANIFEST).write_text(json.dumps(manifest))
        hashes = {n: m['sha256'] for n, m in manifest['members'].items()}
        hashes[obs.MANIFEST] = obs.sha256((r14_kit / obs.MANIFEST).read_bytes())
        (r14_kit / obs.MEMBERS_FILE).write_text(obs.members_listing(hashes))
    report, _ = obs.check(host, r14_kit, **destinations(host, tmp_path), firefox_only=True)
    require(report['status'] == 'NOT_READY' and 'CHROME_AUTHORITY_INVALID' in report['codes'])
    require(not host.launched)


def test_r14_mid_session_authority_tamper_cannot_leave_pass_evidence(obs, host, tmp_path, r14_kit, monkeypatch):
    host.on_wait['firefox'] = lambda: (r14_kit / obs.kit.CHROME_AUTHORITY_MEMBER).write_text('{}')
    code, printed, _, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
    result = json.loads((sessions[0] / 'RESULT.json').read_text())
    require(code != 0 and result['verdict'] != 'PASS', printed)
    require('CHROME_AUTHORITY_INVALID' in result['reasons'])
    with zipfile.ZipFile(sessions[0] / 'bundle' / obs.kit.FIREFOX_ONLY_EVIDENCE) as archive:
        require(json.loads(archive.read('SUMMARY.json'))['verdict'] != 'PASS')


@pytest.mark.parametrize('bind_number', [2, 3, 4])
def test_r14_runtime_drift_refuses_at_each_binding(obs, host, tmp_path, r14_kit, monkeypatch, bind_number):
    original, calls = host.bind, []
    def bind(browser):
        require(browser == 'firefox')
        calls.append(browser)
        if len(calls) == bind_number:
            host.identity['firefox']['runtime_sha256'] = '0' * 64
        return original(browser)
    monkeypatch.setattr(host, 'bind', bind)
    if bind_number == 2:
        with pytest.raises(obs.Refused, match='RUNTIME_CHANGED'):
            run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
        require(not (destinations(host, tmp_path)['outbox'] / obs.FIREFOX_ONLY_SESSION_ROOT).exists())
    else:
        code, printed, _, sessions = run_r14(obs, host, tmp_path, r14_kit, monkeypatch)
        require(code != 0, printed)
        require(json.loads((sessions[0] / 'RESULT.json').read_text())['verdict'] != 'PASS')
    require(len(host.launched) == (1 if bind_number == 4 else 0))


def test_r14_mode_mismatch_refuses_before_writes(obs, host, tmp_path, r14_kit, sealed):
    before = snapshot(tmp_path)
    for root, firefox_only in [(r14_kit, False), (sealed[0], True)]:
        with pytest.raises(obs.Refused, match='KIT_MODE_MISMATCH'):
            obs.execute(host, lambda _: '', lambda _: None, root,
                        **destinations(host, tmp_path), firefox_only=firefox_only)
    require(snapshot(tmp_path) == before and not host.launched)


def test_r14_destinations_use_firefox_only_root(obs, host, tmp_path, r14_kit):
    where = destinations(host, tmp_path)
    (where['outbox'] / obs.FIREFOX_ONLY_SESSION_ROOT).write_text('not a directory')
    report, _ = obs.check(host, r14_kit, **where, firefox_only=True)
    require(report['schema'] == obs.mode_contract(True)['check_schema'])
    require(report['status'] == 'NOT_READY' and 'OUTBOX_UNSAFE' in report['codes'])


def test_r14_seal_deterministic_and_dedicated(obs, repo_root, tmp_path, r14_kit):
    second = tmp_path / 'second-firefox-seal'
    second.mkdir()
    digest = obs.seal(repo_root, second, firefox_only=True)
    first = tmp_path / 'firefox-only-seal' / obs.FIREFOX_ONLY_KIT_ZIP
    require(first.read_bytes() == (second / obs.FIREFOX_ONLY_KIT_ZIP).read_bytes())
    require(obs.sha256(first.read_bytes()) == digest)
    with zipfile.ZipFile(first) as archive:
        expected = set(obs.SOURCE_MEMBERS) | {obs.kit.CHROME_AUTHORITY_MEMBER,
                    obs.FIREFOX_ONLY_WRAPPER, obs.README, obs.MANIFEST, obs.MEMBERS_FILE}
        require(set(archive.namelist()) == expected and obs.WRAPPER not in archive.namelist())
        require('tests/cnt_firefox_production.py' not in archive.namelist())
        wrapper = archive.read(obs.FIREFOX_ONLY_WRAPPER).decode()
        require('scrollbar_gui_observer.py --firefox-only "$1"' in wrapper)
        require('$1 != --check && $1 != --execute' in wrapper)
        manifest = json.loads(archive.read(obs.MANIFEST))
        require(manifest['sentinel_contract']['count'] == 2)
        require(manifest['chrome_authority']['sha256'] == obs.kit.CHROME_AUTHORITY_SHA256)
    require(obs.manifest_problems(r14_kit, True)[0] == [])


def test_r14_authority_rechecked_after_ack_before_session(obs, host, tmp_path, r14_kit):
    def acknowledge(prompt):
        (r14_kit / obs.kit.CHROME_AUTHORITY_MEMBER).write_text('{}')
        return obs.FORCE_INSTALL_ACK
    with pytest.raises(obs.Refused, match='CHROME_AUTHORITY_INVALID'):
        obs.execute(host, acknowledge, lambda _: None, r14_kit,
                    **destinations(host, tmp_path), firefox_only=True)
    require(not (destinations(host, tmp_path)['outbox'] / obs.FIREFOX_ONLY_SESSION_ROOT).exists())
    require(not list((tmp_path / 'tmp').iterdir()) and not host.launched)


@pytest.mark.parametrize('phase,index', [('initial', 2), ('disabled', 4), ('reenabled', 6)])
def test_r14_firefox_retry_retains_original_token_and_barrier(obs, host, tmp_path, r14_kit,
                                                           monkeypatch, phase, index):
    servers = install_ledger_transport(obs, monkeypatch)
    target = {}
    outbox = destinations(host, tmp_path)['outbox']
    def partial(prompt):
        session = next(iter(session_paths(outbox)))
        target.update(obs.kit.pending_fixture_proof(session, 'firefox'))
        for name in target['names'][1:]:
            servers[-1].fetch(name, target['token'])
        return ''
    def retry(prompt):
        require('retry 1/3' in prompt)
        session = next(iter(session_paths(outbox)))
        require(obs.kit.pending_fixture_proof(session, 'firefox') == target)
        servers[-1].fetch(target['names'][0], target['token'])
        return ''
    items = answers(obs, {'root-gutter': 'p'})
    items[index:index + 1] = [partial, retry]
    code, printed, _, sessions = execute(obs, host, r14_kit, tmp_path, items,
                                        port=8123, firefox_only=True)
    require(code == 0, printed)
    entries = obs.kit.Session(sessions[0]).entries
    kind = {'initial': 'FIXTURES_OPENED_POSTLOAD', 'disabled': 'DISABLED_COMPARISON_FRESH',
            'reenabled': 'ALL_FIXTURES_FRESH_POSTREENABLE'}[phase]
    proof = next(e for e in entries if e['kind'] == kind)
    require(proof['token'] == target['token'] and proof['barrier'] == target['barrier'])
    retries = [e for e in entries if e['kind'] == 'freshness-retry']
    require(len(retries) == 1 and retries[0]['browser'] == 'firefox')


@pytest.mark.parametrize('phase,index', [('initial', 2), ('disabled', 4), ('reenabled', 6)])
@pytest.mark.parametrize('terminal', ['exhaustion', 'q', 'interrupt'])
def test_r14_firefox_missing_freshness_never_passes(obs, host, tmp_path, r14_kit, monkeypatch,
                                                 phase, index, terminal):
    install_ledger_transport(obs, monkeypatch)
    items = answers(obs, {'root-gutter': 'p'})[:index]
    items += ([''] * (obs.kit.FRESHNESS_RETRIES + 1) if terminal == 'exhaustion'
              else ['q'] if terminal == 'q' else [KeyboardInterrupt])
    code, printed, _, sessions = execute(obs, host, r14_kit, tmp_path, items,
                                        port=8123, firefox_only=True)
    require(code == 5, printed)
    state = obs.kit.Session(sessions[0])
    require(len([e for e in state.entries if e['kind'] == 'stop']) == 1)
    require(json.loads((sessions[0] / 'RESULT.json').read_text())['verdict'] == 'INCOMPLETE')


def test_r14_combined_policy_change_keeps_existing_stop_contract(obs, host, tmp_path, sealed, monkeypatch):
    install_ledger_transport(obs, monkeypatch)
    original = execute
    def ledger_execute(*args, **kwargs):
        kwargs.setdefault('port', 8123)
        return original(*args, **kwargs)
    monkeypatch.setitem(globals(), 'execute', ledger_execute)
    test_policy_change_after_acknowledgement_stops_before_launch(obs, host, tmp_path, sealed, monkeypatch)
