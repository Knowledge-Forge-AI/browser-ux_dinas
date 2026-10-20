"""Source-only tests for the attended scrollbar kit's runtime and host binding.

Chrome and Firefox apps are synthetic; codesign, defaults, pgrep and ps are a recording fake. No
browser, installed runtime, Nix store, process or host preference is read or written.
"""
import ast
import hashlib
from pathlib import Path
import json
import plistlib
import re
import shutil
import struct

import pytest

STORE_HASH = '0123456789abcdfghijklmnpqrsvwxyz'
CHROME_PLIST = {'CFBundleIdentifier': 'com.google.Chrome', 'CFBundleExecutable': 'Google Chrome',
                'CFBundleShortVersionString': '149.0.7827.201'}
FIREFOX_PLIST = {'CFBundleIdentifier': 'org.mozilla.firefox', 'CFBundleShortVersionString': '157.0',
                 'CFBundleVersion': '15726.9.24', 'CFBundleExecutable': 'firefox'}
FIREFOX_INI = '[App]\nVendor=Mozilla\nName=Firefox\nVersion=157.0\nBuildID=20260924084938\n'
READ_ONLY = (('/usr/bin/codesign', '--verify', '--deep', '--strict'),
             ('/usr/bin/defaults', 'read', '-g', 'AppleShowScrollBars'), ('/usr/bin/pgrep', '-x'),
             ('/bin/ps', '-ww', '-p'))
# The two long-lived MCP launchers the operator observed under `pgrep -x "Google Chrome"` (R3).
MCP = ('npm exec @playwright/mcp@latest --executable-path /Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome',
       'npm exec chrome-devtools-mcp@latest --executablePath /Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome')
CHROME = '/Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome'
FIREFOX = '/Applications/Firefox.app/Contents/MacOS/firefox'


def require(condition, message='requirement failed'):
    if not condition:
        raise AssertionError(message)


@pytest.fixture
def rt(load_module):
    return load_module('tests/scrollbar_gui_runtime.py')


class Run:
    """Recording fake for host.run; only read-only argv are accepted."""

    def __init__(self):
        self.calls, self.codes, self.outputs, self.during = [], {}, {}, None
        self.pgrep, self.ps = {}, {}  # name -> (code, out); pid -> (code, out)

    def __call__(self, argv, timeout=30):
        require(any(tuple(argv[:len(p)]) == p for p in READ_ONLY), f'not read-only: {argv}')
        self.calls.append((list(argv), timeout))
        if argv[0] == '/usr/bin/codesign' and self.during:
            self.during()
        if argv[0] == '/usr/bin/pgrep' and argv[-1] in self.pgrep:
            return self.pgrep[argv[-1]]
        if argv[0] == '/bin/ps':
            require(argv[4:] == ['-o', 'command='] and len(argv) == 6, argv)
            return self.ps.get(argv[3], (1, ''))
        return self.codes.get(argv[0], 0), self.outputs.get(argv[0], '')

    def processes(self, name, *commands):
        """`commands` become the candidates for `name`; None is a PID ps cannot read."""
        base = 100 * (len(self.pgrep) + 1)
        pids = [str(base + i) for i in range(len(commands))]
        self.pgrep[name] = (0, ''.join(f'{pid}\n' for pid in pids)) if pids else (1, '')
        for pid, command in zip(pids, commands):
            self.ps[pid] = (1, '') if command is None else (0, command + '\n')
        return pids


@pytest.fixture
def run():
    return Run()


@pytest.fixture
def store(rt, tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'store'
    root.mkdir()
    monkeypatch.setattr(rt.preflight(), 'CHROME_STORE', root)
    return root


def chrome_app(base, plist=None, package=f'{STORE_HASH}-google-chrome-149.0.7827.201'):
    app = base / package / 'Applications/Google Chrome.app'
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/MacOS/Google Chrome').write_bytes(b'synthetic chrome')
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(plist or CHROME_PLIST))
    return app


@pytest.fixture
def selection(tmp_path):
    path = tmp_path.resolve() / 'run/current-system/Applications/Google Chrome.app'
    path.parent.mkdir(parents=True)
    return path


def refused(rt, call, result, code):
    with pytest.raises(rt.Unavailable) as error:
        call()
    require((error.value.result, error.value.code) == (result, code), (error.value.result, error.value.code))
    require(str(error.value) == f'{result}:{code}', 'refusals carry no path')


# Chrome ----------------------------------------------------------------------------------------

def test_selected_chrome_binds_through_the_maintained_identity_reader(rt, run, store, selection):
    app = chrome_app(store)
    selection.symlink_to(app)
    public, private = rt.bind_chrome(run, selection)
    require(public == {
        'selection': 'RUN_CURRENT_SYSTEM', 'bundle_id': 'com.google.Chrome', 'version': '149.0.7827.201',
        'executable_sha256': hashlib.sha256(b'synthetic chrome').hexdigest(),
        'runtime_sha256': rt.tree_digest(app),
        'store_root_sha256': hashlib.sha256(str(store / app.relative_to(store).parts[0]).encode()).hexdigest(),
        'signature_valid': True}, public)
    require(private == {'app': str(app), 'executable': str(app / 'Contents/MacOS/Google Chrome')})
    require(run.calls == [(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], 120)], run.calls)
    require(str(store) not in repr(public), 'public identity carries no path')


def test_daily_app_is_never_a_fallback(rt, run, store, selection, tmp_path):
    """False /Applications negative control: a valid-looking daily app and a Nix Apps copy exist,
    the selected-generation app does not."""
    daily = tmp_path / 'Applications'
    chrome_app(daily, package='.')
    chrome_app(daily / 'Nix Apps', package='.')
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE', 'SELECTION_ABSENT')
    require(run.calls == [], 'nothing else is inspected')


def test_daily_app_selected_by_link_is_not_a_store_app(rt, run, store, selection, tmp_path):
    selection.symlink_to(chrome_app(tmp_path / 'Applications', package='.'))
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE',
            'CHROME_RUNTIME_NOT_STORE_APP')


def test_dangling_selection_is_absent(rt, run, store, selection):
    selection.symlink_to(store / 'missing')
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE', 'SELECTION_ABSENT')


@pytest.mark.parametrize('case,code', [
    ('chromium-package', 'CHROME_RUNTIME_NOT_STORE_APP'),
    ('wrong-bundle', 'CHROME_BUNDLE_IDENTITY_REFUSED'),
    ('renamed-executable', 'CHROME_BUNDLE_IDENTITY_REFUSED'),
    ('bad-version', 'CHROME_BUNDLE_VERSION_INVALID'),
    ('unreadable-plist', 'CHROME_BUNDLE_METADATA_UNREADABLE'),
    ('missing-executable', 'CHROME_APP_LAYOUT_REFUSED'),
    ('linked-executable', 'CHROME_APP_LAYOUT_REFUSED'),
])
def test_selected_chrome_refusals(rt, run, store, selection, case, code):
    if case == 'chromium-package':
        app = chrome_app(store, package=f'{STORE_HASH}-chromium-149.0.7827.201')
    elif case == 'wrong-bundle':
        app = chrome_app(store, {**CHROME_PLIST, 'CFBundleIdentifier': 'org.chromium.Chromium'})
    elif case == 'renamed-executable':
        app = chrome_app(store, {**CHROME_PLIST, 'CFBundleExecutable': 'Chromium'})
    elif case == 'bad-version':
        app = chrome_app(store, {**CHROME_PLIST, 'CFBundleShortVersionString': '149.0'})
    else:
        app = chrome_app(store)
        if case == 'unreadable-plist':
            (app / 'Contents/Info.plist').write_bytes(b'not a plist')
        elif case == 'missing-executable':
            (app / 'Contents/MacOS/Google Chrome').unlink()
        else:
            target = app / 'Contents/MacOS/real'
            (app / 'Contents/MacOS/Google Chrome').rename(target)
            (app / 'Contents/MacOS/Google Chrome').symlink_to(target)
    selection.symlink_to(app)
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE', code)
    require(run.calls == [], 'no codesign before identity')


def test_selected_chrome_signature_must_verify(rt, run, store, selection):
    selection.symlink_to(chrome_app(store))
    run.codes['/usr/bin/codesign'] = 1
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE', 'ORIGINAL_SIGNATURE_INVALID')


def test_selected_chrome_change_during_binding_is_refused(rt, run, store, selection):
    app = chrome_app(store)
    selection.symlink_to(app)
    run.during = lambda: (app / 'Contents/Resources').mkdir()
    refused(rt, lambda: rt.bind_chrome(run, selection), 'SELECTED_CHROME_UNAVAILABLE', 'CHROME_RUNTIME_CHANGED')


# Firefox ---------------------------------------------------------------------------------------

FIREFOX_RUNTIME = 'e8e1a70613e1cc5750514e17f56781c06a07d5f31421cfcbf762a91c3d904407'
FIREFOX_EXECUTABLE_SHA = '729e0ae83fca74cf143bbef68836c195b340fcc09566461243a075be9e6b959a'


def channel_binary(channel=b'release\0', cpu=0x100000c):
    """Minimal data-only Mach-O fixture with one __TEXT,__cstring section."""
    header = struct.pack('<IIIIIIII', 0xfeedfacf, cpu, 0, 6, 1, 152, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 152, b'__TEXT', 0, 0, 0, 0, 0, 0, 1, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__cstring', b'__TEXT', 0, len(channel),
                          184, 0, 0, 0, 2, 0, 0, 0)
    return header + segment + section + channel


def universal_channel(*channels):
    slices = [channel_binary(channel, cpu) for cpu, channel in
              zip((0x1000007, 0x100000c), channels)]
    offset = 8 + 20 * len(slices)
    header = struct.pack('>II', 0xcafebabe, len(slices))
    for cpu, data in zip((0x1000007, 0x100000c), slices):
        header += struct.pack('>IIIII', cpu, 0, offset, len(data), 0)
        offset += len(data)
    return header + b''.join(slices)


@pytest.fixture
def firefox(rt, tmp_path, monkeypatch):
    app = tmp_path.resolve() / 'Applications/Firefox.app'
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Resources').mkdir()
    (app / rt.CHANNEL_FRAMEWORK).parent.mkdir(parents=True)
    (app / rt.CHANNEL_FRAMEWORK).write_bytes(channel_binary())
    (app / 'Contents/MacOS/firefox').write_bytes(b'synthetic firefox')
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(FIREFOX_PLIST))
    (app / 'Contents/Resources/application.ini').write_text(FIREFOX_INI)
    state = {'tree': FIREFOX_RUNTIME, 'executable_reader': rt.firefox_executable_sha256}
    # Synthetic roots replace the one constant, never bypass the exact-path or layout checks.
    monkeypatch.setattr(rt, 'FIREFOX_APP', app)
    monkeypatch.setattr(rt, 'tree_digest', lambda root, trace=None: state['tree'])
    monkeypatch.setattr(rt, 'firefox_executable_sha256', lambda executable: FIREFOX_EXECUTABLE_SHA)
    return app, state


def set_version(app, version, ini_version=None):
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({**FIREFOX_PLIST,
                                                           'CFBundleShortVersionString': version}))
    (app / 'Contents/Resources/application.ini').write_text(
        FIREFOX_INI.replace('Version=157.0', 'Version=' + (ini_version or str(version))))


def test_attended_firefox_exact_operator_target(rt, run, firefox):
    app, _ = firefox
    public, private = rt.bind_firefox(run, app)
    require(public == {'selection': 'ATTENDED_INSTALLED_FIREFOX_APP', 'version': '157.0',
                       'bundle_identifier': 'org.mozilla.firefox', 'bundle_version': '15726.9.24',
                       'build_id': '20260924084938', 'runtime_sha256': FIREFOX_RUNTIME,
                       'executable_sha256': FIREFOX_EXECUTABLE_SHA, 'signature_valid': True}, public)
    require(private == {'app': str(app), 'executable': str(app / 'Contents/MacOS/firefox')})
    require(str(app) not in repr(public), 'public identity carries no path')
    require(run.calls == [(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], 120)])


def test_firefox_default_authority_and_manifest_floor(rt, load_module):
    kit = load_module('tests/scrollbar_gui_kit.py')
    require(str(rt.FIREFOX_APP) == '/Applications/Firefox.app')
    require(rt.bind_firefox.__defaults__ == (rt.FIREFOX_APP,))
    require(kit.Host(home=Path('/synthetic-home')).firefox_app == rt.FIREFOX_APP)
    require(str(rt.CHROME_SELECTION) == '/run/current-system/Applications/Google Chrome.app')
    require(rt.EXTENSION_MANIFEST == rt.HERE.parent / kit.EXTENSION_DIR / 'manifest.json')
    require(rt.gecko_floor() == (140, 0, 0))


@pytest.mark.parametrize('version', ['140.0', '157.0', '163.0.2', '200.0'])
def test_normal_version_family_is_eligible_not_qualified(rt, run, firefox, version):
    app, _ = firefox
    set_version(app, version)
    require(rt.bind_firefox(run, app)[0]['version'] == version)


@pytest.mark.parametrize('version', ['157', '157.0b3', '159.0a1', '140.3.0esr', '0157.0',
                                     '157.00', '157.0.1.2', '157.0\n', 157, True, [],
                                     '１５７.０', ''])
def test_malformed_version_refused(rt, run, firefox, version):
    app, _ = firefox
    set_version(app, version)
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_VERSION_INVALID')
    require(run.calls == [])


@pytest.mark.parametrize('version', ['139.0', '139.9.9'])
def test_version_below_manifest_floor_refused(rt, run, firefox, version):
    app, _ = firefox
    set_version(app, version)
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_VERSION_BELOW_FLOOR')
    require(run.calls == [])


@pytest.mark.parametrize('manifest', [{}, [], None, {'browser_specific_settings': None},
                                     {'browser_specific_settings': {'gecko': {'strict_min_version': 140}}},
                                     {'browser_specific_settings': {'gecko': {'strict_min_version': '140.*'}}}])
def test_bad_floor_contract_is_fixed_refusal(rt, run, firefox, tmp_path, monkeypatch, manifest):
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(rt, 'EXTENSION_MANIFEST', path)
    refused(rt, lambda: rt.bind_firefox(run, firefox[0]), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_FLOOR_UNREADABLE')
    require(run.calls == [])


@pytest.mark.parametrize('raw', [b'not JSON', b'\xff', b' ' * ((64 << 10) + 1)],
                         ids=['non-json', 'non-utf8', 'oversize'])
def test_unreadable_floor_contract(rt, tmp_path, monkeypatch, raw):
    path = tmp_path / 'manifest.json'
    path.write_bytes(raw)
    monkeypatch.setattr(rt, 'EXTENSION_MANIFEST', path)
    refused(rt, rt.gecko_floor, rt.FIREFOX_UNAVAILABLE, 'FIREFOX_FLOOR_UNREADABLE')
    path.unlink()
    refused(rt, rt.gecko_floor, rt.FIREFOX_UNAVAILABLE, 'FIREFOX_FLOOR_UNREADABLE')


@pytest.mark.parametrize('field,value,code', [
    ('CFBundleIdentifier', 'org.mozilla.other', 'FIREFOX_BUNDLE_ID_DIFFERS'),
    ('CFBundleIdentifier', 123, 'FIREFOX_BUNDLE_ID_DIFFERS'),
    ('CFBundleIdentifier', [], 'FIREFOX_BUNDLE_ID_DIFFERS'),
    ('CFBundleExecutable', 'firefox-bin', 'FIREFOX_APP_LAYOUT_REFUSED'),
    ('CFBundleExecutable', 123, 'FIREFOX_APP_LAYOUT_REFUSED'),
    ('CFBundleExecutable', {}, 'FIREFOX_APP_LAYOUT_REFUSED'),
    ('CFBundleVersion', '', 'FIREFOX_BUNDLE_VERSION_INVALID'),
    ('CFBundleVersion', 'x' * 129, 'FIREFOX_BUNDLE_VERSION_INVALID'),
    ('CFBundleVersion', 'bad\nvalue', 'FIREFOX_BUNDLE_VERSION_INVALID'),
    ('CFBundleVersion', 123, 'FIREFOX_BUNDLE_VERSION_INVALID'),
    ('CFBundleVersion', [], 'FIREFOX_BUNDLE_VERSION_INVALID'),
])
def test_plist_identity_types_and_values_refused(rt, run, firefox, field, value, code):
    app, _ = firefox
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({**FIREFOX_PLIST, field: value}))
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, code)
    require(run.calls == [])


def test_bundle_version_is_recorded_without_build_id_derivation(rt, run, firefox):
    app, _ = firefox
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({**FIREFOX_PLIST, 'CFBundleVersion': '1.2.3'}))
    public, _ = rt.bind_firefox(run, app)
    require(public['bundle_version'] == '1.2.3' and public['build_id'] == '20260924084938')


@pytest.mark.parametrize('raw,code', [
    (FIREFOX_INI.replace('Version=157.0', 'Version=157.0.1'), 'FIREFOX_INI_VERSION_DIFFERS'),
    (FIREFOX_INI.replace('Version=157.0\n', ''), 'FIREFOX_INI_UNREADABLE'),
    (FIREFOX_INI.replace('BuildID=20260924084938\n', ''), 'FIREFOX_INI_UNREADABLE'),
    ('[DEFAULT]\nVersion=157.0\nBuildID=20260924084938\n[App]\n', 'FIREFOX_INI_UNREADABLE'),
    (FIREFOX_INI + 'Version=157.0\n', 'FIREFOX_INI_UNREADABLE'),
    (FIREFOX_INI.replace('20260924084938', '2026092408493'), 'FIREFOX_BUILD_ID_INVALID'),
    (FIREFOX_INI.replace('20260924084938', '20261399000000'), 'FIREFOX_BUILD_ID_INVALID'),
    (FIREFOX_INI.replace('20260924084938', 'abcdefghijklmn'), 'FIREFOX_BUILD_ID_INVALID'),
])
def test_ini_version_and_build_refusals(rt, run, firefox, raw, code):
    app, _ = firefox
    (app / 'Contents/Resources/application.ini').write_text(raw)
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, code)
    require(run.calls == [])


@pytest.mark.parametrize('case,code', [
    ('absent', 'FIREFOX_APP_ABSENT'), ('linked-app', 'FIREFOX_RUNTIME_PATH_REFUSED'),
    ('linked-ancestor', 'FIREFOX_RUNTIME_PATH_REFUSED'), ('relative', 'FIREFOX_RUNTIME_PATH_REFUSED'),
    ('alternate', 'FIREFOX_RUNTIME_PATH_REFUSED'), ('not-directory', 'FIREFOX_RUNTIME_PATH_REFUSED'),
    ('missing-executable', 'FIREFOX_APP_LAYOUT_REFUSED'), ('linked-executable', 'FIREFOX_APP_LAYOUT_REFUSED'),
    ('bad-plist', 'FIREFOX_PLIST_UNREADABLE'), ('non-dict-plist', 'FIREFOX_PLIST_UNREADABLE'),
    ('malformed-xml', 'FIREFOX_PLIST_UNREADABLE'),
    ('missing-ini', 'FIREFOX_INI_UNREADABLE'), ('bad-ini', 'FIREFOX_INI_UNREADABLE'),
    ('signature', 'ORIGINAL_SIGNATURE_INVALID'), ('changed', 'FIREFOX_RUNTIME_CHANGED'),
    ('unreadable-executable', 'FIREFOX_EXECUTABLE_UNREADABLE'), ('unreadable-tree', 'FIREFOX_RUNTIME_UNREADABLE'),
    ('unreadable-after-tree', 'FIREFOX_RUNTIME_CHANGED'), ('missing-channel', 'FIREFOX_CHANNEL_UNREADABLE'),
])
def test_attended_firefox_refusals(rt, run, firefox, tmp_path, monkeypatch, case, code):
    app, state = firefox
    target = app
    def unreadable(*args):
        raise OSError('private path must not escape')
    if case == 'absent':
        shutil.rmtree(app)
    elif case in ('linked-app', 'not-directory'):
        app.rename(app.with_name('saved'))
        if case == 'linked-app':
            app.symlink_to(app.with_name('saved'))
        else:
            app.write_bytes(b'file')
    elif case == 'linked-ancestor':
        app.parent.rename(app.parent.with_name('saved'))
        app.parent.symlink_to(app.parent.with_name('saved'))
    elif case == 'relative':
        target = Path('Applications/Firefox.app')
    elif case == 'alternate':
        target = tmp_path / 'Other/Firefox.app'
        shutil.copytree(app, target)
    elif case == 'missing-executable':
        (app / rt.FIREFOX_EXECUTABLE).unlink()
    elif case == 'linked-executable':
        executable = app / rt.FIREFOX_EXECUTABLE
        executable.rename(executable.with_name('saved'))
        executable.symlink_to(executable.with_name('saved'))
    elif case == 'malformed-xml':
        (app / 'Contents/Info.plist').write_bytes(b'<?xml version="1.0"?><plist><dict><key>broken</dict>')
    elif case in ('bad-plist', 'non-dict-plist'):
        (app / 'Contents/Info.plist').write_bytes(b'bad' if case == 'bad-plist' else plistlib.dumps([]))
    elif case == 'missing-ini':
        (app / 'Contents/Resources/application.ini').unlink()
    elif case == 'bad-ini':
        (app / 'Contents/Resources/application.ini').write_bytes(b'\xff')
    elif case == 'signature':
        run.codes['/usr/bin/codesign'] = 1
    elif case == 'changed':
        run.during = lambda: state.update(tree='1' * 64)
    elif case == 'unreadable-executable':
        monkeypatch.setattr(rt, 'firefox_executable_sha256', unreadable)
    elif case == 'unreadable-tree':
        monkeypatch.setattr(rt, 'tree_digest', unreadable)
    elif case == 'unreadable-after-tree':
        run.during = lambda: monkeypatch.setattr(rt, 'tree_digest', unreadable)
    else:
        (app / rt.CHANNEL_FRAMEWORK).unlink()
    refused(rt, lambda: rt.bind_firefox(run, target), rt.FIREFOX_UNAVAILABLE, code)
    if case not in ('signature', 'changed', 'unreadable-after-tree'):
        require(run.calls == [])


@pytest.mark.parametrize('raw', [channel_binary(b'esr\0'), channel_binary(b'beta\0'),
    channel_binary(b'nightly\0'), channel_binary(b'release-candidate\0'), b'release\0',
    channel_binary(b'esr\0') + b'release\0', channel_binary()[:100],
    universal_channel(b'release\0', b'esr\0'), b'\xca\xfe\xba\xbe' + b'\0' * 4,
    channel_binary()[:48] + b'\xff' * 4 + channel_binary()[52:],
], ids=['esr', 'beta', 'nightly', 'unknown', 'not-macho', 'decoy-release', 'truncated',
        'mixed-channels', 'empty-universal', 'bad-segment'])
def test_channel_refuses_esr_prerelease_unknown_and_malformed(rt, run, firefox, raw):
    app, _ = firefox
    (app / rt.CHANNEL_FRAMEWORK).write_bytes(raw)
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_CHANNEL_REFUSED')
    require(run.calls == [])


def test_universal_release_channel_is_eligible(rt, run, firefox):
    app, _ = firefox
    (app / rt.CHANNEL_FRAMEWORK).write_bytes(universal_channel(b'release\0', b'release\0'))
    require(rt.bind_firefox(run, app)[0]['version'] == '157.0')


def test_real_tree_and_executable_read_and_runtime_mutation(rt, run, firefox, monkeypatch):
    app, state = firefox
    from cnt_native_evidence import tree_digest
    monkeypatch.setattr(rt, 'tree_digest', tree_digest)
    monkeypatch.setattr(rt, 'firefox_executable_sha256', state['executable_reader'])
    public, _ = rt.bind_firefox(run, app)
    require(public['runtime_sha256'] == tree_digest(app))
    require(public['executable_sha256'] == hashlib.sha256(b'synthetic firefox').hexdigest())
    run.during = lambda: (app / 'Contents/update').write_bytes(b'changed during codesign')
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_RUNTIME_CHANGED')


def test_oversize_executable_is_fixed_refusal(rt, run, firefox, monkeypatch):
    app, state = firefox
    monkeypatch.setattr(rt, 'firefox_executable_sha256', state['executable_reader'])
    monkeypatch.setattr(rt, 'EXECUTABLE_LIMIT', 1)
    refused(rt, lambda: rt.bind_firefox(run, app), rt.FIREFOX_UNAVAILABLE, 'FIREFOX_EXECUTABLE_UNREADABLE')
    require(run.calls == [])


def test_firefox_has_no_cnt_production_dependency_or_pinned_identity(rt):
    for name in ('scrollbar_gui_runtime.py', 'scrollbar_gui_kit.py', 'scrollbar_gui_observer.py'):
        raw = (rt.HERE / name).read_text()
        parsed = ast.parse(raw)
        imports = [alias.name for node in ast.walk(parsed) if isinstance(node, ast.Import) for alias in node.names]
        imports += [node.module for node in ast.walk(parsed) if isinstance(node, ast.ImportFrom)]
        require('cnt_firefox_production' not in imports and 'cnt_firefox_production' not in raw)
        require('firefox_production' not in raw)
    require(not hasattr(rt, 'firefox_production'))
    raw = Path(rt.__file__).read_text()
    require('156.0.1' not in raw and '157.0' not in raw, 'no forever version pin')


# Host ------------------------------------------------------------------------------------------

@pytest.mark.parametrize('code,output,mode', [
    (0, 'Always\n', 'Always'), (0, 'WhenScrolling\n', 'WhenScrolling'), (0, 'Automatic\n', 'Automatic'),
    (1, '', 'Automatic (unset)'), (0, '', 'Automatic (unset)'), (0, 'Always; x\n', 'UNRECOGNIZED'),
])
def test_host_scrollbar_mode_is_read_only(rt, run, code, output, mode):
    run.codes['/usr/bin/defaults'], run.outputs['/usr/bin/defaults'] = code, output
    require(rt.host_scrollbar_mode(run) == mode)
    require(run.calls == [(['/usr/bin/defaults', 'read', '-g', 'AppleShowScrollBars'], 30)])


@pytest.mark.parametrize('code,state', [(1, 'NOT_RUNNING'), (2, 'UNKNOWN'), (3, 'UNKNOWN'),
                                        (124, 'UNKNOWN'), (127, 'UNKNOWN')])
def test_pgrep_exit_other_than_zero_never_reads_a_command_line(rt, run, code, state):
    run.codes['/usr/bin/pgrep'] = code
    require(rt.browser_processes(run) == {'chrome': state, 'firefox': state})
    require([c[0] for c in run.calls] == [['/usr/bin/pgrep', '-x', 'Google Chrome'], ['/usr/bin/pgrep', '-x', 'firefox']])


def test_pgrep_exit_zero_alone_is_not_proof_of_a_browser(rt, run):
    """R2 treated exit 0 as RUNNING. Now every candidate must be read; one ps-less PID is UNKNOWN."""
    run.outputs['/usr/bin/pgrep'] = '1\n'
    require(rt.browser_processes(run) == {'chrome': 'UNKNOWN', 'firefox': 'UNKNOWN'})


# Process identity (R3) ------------------------------------------------------------------------

@pytest.mark.parametrize('command', [
    CHROME,
    CHROME + ' --user-data-dir=/tmp/example',
    '/nix/store/example-google-chrome/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --flag',
    # the kit's own disposable launch shape (store executable, then a profile option)
    f'/nix/store/{STORE_HASH}-google-chrome-149.0.7827.201/Applications/Google Chrome.app/Contents/MacOS/'
    'Google Chrome --user-data-dir=/private/var/folders/x/T/bux5c0-r3-scrollbar-1/work/profiles/chrome '
    '--no-first-run --no-default-browser-check --use-mock-keychain http://127.0.0.1:5/scrollbar-matrix.html',
    '/Google Chrome.app/Contents/MacOS/Google Chrome',
    CHROME + ' --flag=' + CHROME,
    '  ' + CHROME + '\n',
])
def test_chrome_main_executable_is_a_real_browser(rt, command):
    require(rt.classify_command('chrome', command) == 'REAL_BROWSER', command)


@pytest.mark.parametrize('command', [
    *MCP,
    'node tool.js --chrome ' + CHROME,
    '/bin/zsh -c /Applications/Nix\\ Apps/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome',
    '/bin/zsh -c ' + CHROME,
    '/bin/sh ' + CHROME,
    '/usr/bin/env /nix/store/example/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/env FOO=1 ' + CHROME,
    '/usr/local/bin/npx @playwright/mcp@latest --executable-path=' + CHROME,
    '/opt/node/bin/node /opt/mcp/cli.js --executable-path=' + CHROME,
    '/bin/zsh -c x' + CHROME,
    'Applications/Nix Apps/Google Chrome.app/Contents/MacOS/Google Chrome',
    'Google Chrome',
    CHROME + 'ium',
    CHROME + '.bak --flag',
    CHROME + '\t--flag',
    CHROME + '_Helper',
    FIREFOX,
])
def test_chrome_name_collisions_are_not_browsers(rt, command):
    require(rt.classify_command('chrome', command) == 'NON_BROWSER_NAME_COLLISION', command)


@pytest.mark.parametrize('command,expected', [
    (FIREFOX, 'REAL_BROWSER'),
    (FIREFOX + ' -profile /private/var/folders/x/T/bux5c0-r3-scrollbar-1/work/profiles/firefox '
     '-no-remote -new-instance http://127.0.0.1:5/scrollbar-matrix.html', 'REAL_BROWSER'),
    ('node x.js --firefox ' + FIREFOX, 'NON_BROWSER_NAME_COLLISION'),
    ('/bin/sh ' + FIREFOX, 'NON_BROWSER_NAME_COLLISION'),
    ('/opt/tool --firefox-path=' + FIREFOX, 'NON_BROWSER_NAME_COLLISION'),
    (FIREFOX + '-bin', 'NON_BROWSER_NAME_COLLISION'),
    (CHROME, 'NON_BROWSER_NAME_COLLISION'),
])
def test_firefox_main_executable_classification(rt, command, expected):
    require(rt.classify_command('firefox', command) == expected, command)


@pytest.mark.parametrize('command', ['', '   ', '\n', CHROME + '\n' + CHROME, '(Google Chrome)', '(firefox)\n'])
def test_unreadable_command_identity(rt, command):
    for browser in ('chrome', 'firefox'):
        require(rt.classify_command(browser, command) == 'UNREADABLE', (browser, command))


def test_disposable_launch_argv_classifies_as_a_real_browser(rt, load_module, tmp_path):
    """The kit's real launch argv, as ps prints it, still counts while the disposable browser lives."""
    kit = load_module('tests/scrollbar_gui_kit.py')
    work = tmp_path / 'bux5c0-r3-scrollbar-x' / 'work'
    chrome = f'/nix/store/{STORE_HASH}-google-chrome-149.0.7827.201/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    for browser, executable in (('chrome', chrome), ('firefox', str(rt.FIREFOX_APP / rt.FIREFOX_EXECUTABLE))):
        command = ' '.join(kit.launch_argv(browser, work, executable, 5))
        require(rt.classify_command(browser, command) == 'REAL_BROWSER', command)


def test_operator_mcp_regression_is_not_running(rt, run):
    """The exact R2 false positive: only the two MCP launchers hold the Google Chrome name."""
    run.processes('Google Chrome', *MCP)
    run.processes('firefox')
    census = rt.browser_census(run)
    require(census == {
        'chrome': {'state': 'NOT_RUNNING', 'candidates': 2, 'real_browser': 0, 'name_collision': 2, 'unreadable': 0},
        'firefox': {'state': 'NOT_RUNNING', 'candidates': 0, 'real_browser': 0, 'name_collision': 0, 'unreadable': 0},
    }, census)
    require(rt.browser_processes(run) == {'chrome': 'NOT_RUNNING', 'firefox': 'NOT_RUNNING'})


@pytest.mark.parametrize('commands,state,counts', [
    ((CHROME,), 'RUNNING', (1, 1, 0, 0)),
    ((*MCP, CHROME), 'RUNNING', (3, 1, 2, 0)),
    ((MCP[0], None), 'UNKNOWN', (2, 0, 1, 1)),
    ((MCP[0], ''), 'UNKNOWN', (2, 0, 1, 1)),
    ((None, CHROME), 'RUNNING', (2, 1, 0, 1)),
    ((MCP[0], '(Google Chrome)'), 'UNKNOWN', (2, 0, 1, 1)),
    ((*MCP, 'node tool.js --chrome ' + CHROME), 'NOT_RUNNING', (3, 0, 3, 0)),
    ((), 'NOT_RUNNING', (0, 0, 0, 0)),
])
def test_census_aggregation(rt, run, commands, state, counts):
    run.processes('Google Chrome', *commands)
    run.processes('firefox')
    chrome = rt.browser_census(run)['chrome']
    require(chrome == dict(zip(('state', 'candidates', 'real_browser', 'name_collision', 'unreadable'),
                               (state, *counts))), chrome)


@pytest.mark.parametrize('code', [1, 124, 127])
def test_ps_failure_is_unknown(rt, run, code):
    pid, = run.processes('Google Chrome', MCP[0])
    run.ps[pid] = (code, '')
    run.processes('firefox')
    require(rt.browser_processes(run) == {'chrome': 'UNKNOWN', 'firefox': 'NOT_RUNNING'})


@pytest.mark.parametrize('out', ['', '\n', 'abc\n', '12 34\n', '0\n', '-1\n', '1\n\n2\n', '01\n', '12345678901\n'])
def test_malformed_pgrep_output_is_unknown_without_reading_any_pid(rt, run, out):
    run.pgrep['Google Chrome'] = (0, out)
    run.processes('firefox')
    require(rt.browser_processes(run)['chrome'] == 'UNKNOWN', out)
    require(not any(c[0][0] == '/bin/ps' for c in run.calls), 'nothing read for an unproven list')


def test_more_candidates_than_the_limit_is_unknown(rt, run):
    run.processes('Google Chrome', *[MCP[0]] * (rt.CANDIDATE_LIMIT + 1))
    run.processes('firefox')
    require(rt.browser_processes(run)['chrome'] == 'UNKNOWN')
    require(not any(c[0][0] == '/bin/ps' for c in run.calls))


def test_every_distinct_candidate_is_read_once_with_the_exact_argv(rt, run):
    run.processes('Google Chrome', MCP[0], MCP[1])
    run.pgrep['Google Chrome'] = (0, '100\n101\n100\n')
    run.processes('firefox', FIREFOX)
    require(rt.browser_processes(run) == {'chrome': 'NOT_RUNNING', 'firefox': 'RUNNING'})
    require(run.calls == [
        (['/usr/bin/pgrep', '-x', 'Google Chrome'], 30),
        (['/bin/ps', '-ww', '-p', '100', '-o', 'command='], 30),
        (['/bin/ps', '-ww', '-p', '101', '-o', 'command='], 30),
        (['/usr/bin/pgrep', '-x', 'firefox'], 30),
        (['/bin/ps', '-ww', '-p', '200', '-o', 'command='], 30)], run.calls)


def test_census_exports_counts_only(rt, run):
    run.processes('Google Chrome', *MCP, CHROME, None)
    run.processes('firefox', FIREFOX, 'node x.js --firefox ' + FIREFOX)
    text = json.dumps(rt.browser_census(run))
    for pid in run.ps:
        require(re.search(rf'\b{pid}\b', text) is None, pid)
    for token in ('npm', 'Nix Apps', 'playwright', 'devtools', '/Applications', 'node', 'MacOS'):
        require(token not in text, token)
    require(set(re.findall(r'"([a-z_]+)":', text)) == {'chrome', 'firefox', 'state', 'candidates', 'real_browser',
                                                        'name_collision', 'unreadable'}, text)


def test_process_contract_matches_the_constants(rt):
    for text in (*rt.MAIN_EXECUTABLES.values(), '/bin/ps -ww -p <pid> -o command=', str(rt.CANDIDATE_LIMIT),
                 rt.REAL_BROWSER, rt.NAME_COLLISION, rt.UNREADABLE):
        require(text in rt.PROCESS_CONTRACT, text)
    require(rt.MAIN_EXECUTABLES['firefox'] == '/Firefox.app/Contents/MacOS/firefox')


def test_guidance_names_both_operator_options_and_is_the_only_write(rt, repo_root):
    require('System Settings > Appearance' in rt.HOST_SCROLLBAR_GUIDANCE)
    require('defaults write -g AppleShowScrollBars -string Always' in rt.HOST_SCROLLBAR_GUIDANCE)
    for name in ('scrollbar_gui_runtime.py', 'scrollbar_gui_kit.py', 'scrollbar_gui_observer.py'):
        source = (repo_root / 'tests' / name).read_text()
        require(source.count('defaults write') == (1 if name == 'scrollbar_gui_runtime.py' else 0), name)
        # Only the selected-generation path may name a Chrome app; no daily or Nix Apps fallback.
        require(re.search(r'(?<!/run/current-system)/Applications/Google Chrome\.app', source) is None, name)
        for token in ('Nix Apps/', 'kill', 'pkill', '.terminate(', 'send_signal', 'rmtree', 'import signal',
                      'from signal', 'SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP'):
            require(token not in source, (name, token))
        # Process identity is classification only: no anchored or substring Chrome app path test.
        require("'Google Chrome.app' in" not in source and '"Google Chrome.app" in' not in source, name)
    runtime_source = (repo_root / 'tests/scrollbar_gui_runtime.py').read_text()
    require('import subprocess' not in runtime_source, 'all host commands go through the injected run')
    binaries = set(re.findall(r"'(/(?:usr/)?bin/[a-z]+)'", runtime_source))
    require(binaries == {'/usr/bin/codesign', '/usr/bin/defaults', '/usr/bin/pgrep', '/bin/ps'}, binaries)
