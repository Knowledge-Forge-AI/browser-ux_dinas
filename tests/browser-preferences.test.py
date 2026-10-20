"""BUX5C0 operator preference contract: scrollbar extension source, package and
static boundaries. Policy projections are asserted in tests/contracts.nix.

Every check raises explicitly (``require``), so results do not depend on
Python ``assert`` and stay meaningful under ``python -O``. The cascade model in
tests/browser_preferences.py is a specification model, not browser evidence.
"""
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
import io

import pytest

EXT = 'extensions/browser-ux-scrollbars'
FIXTURE = 'tests/fixtures/browser-preferences/scrollbar-matrix.html'
PACKAGE_SHA256 = 'fc5cd1e97c0e8fa708896815cd84e1061ca6e483508d0918d08d7f8c702cd0e4'
MEMBER_SHA256 = {
    'background.js': 'e9af249a96f825e6219d4d1dbb3a0a5399cc45ecb29dd78137e361484f02d68a',
    'content.js': '19fe94a2078aa281050aa3c93f850126684759b2957716e83a3ee87f5afb57d2',
    'manifest.json': '9f50bd3d2f04fd15e9617d49a52f9089dfc19953a66098c6dcdcac52f4ed84eb',
    'rail-core.js': '7477ea6c4abbb9bd4ff223dba7fb21c5a903bb85547149703e98dad8ec023a32',
    'rail-host.css': 'c67f8696b588aa4622acc70edf9b09506747ba5db542cd43437a98c8a43b1ebe',
    'scrollbars.css': '95dcb31fa6b2711cde503d2de6b82214add49aef78fc53e9adcd7a61a76b73db',
    'toplayer-sentinel-main.js': '5a6cdb16d08e127eaa206aeb7d4a61892451bf9c2883c53a6b027e855ede5e08',
}
FIXTURE_SHA256 = 'be06f524c6e8a91427d759290fcbdfd7298d465a92df4df5a44d2fc1d37d766c'
EXPECTED_MANIFEST = {
    'manifest_version': 3,
    'name': 'Browser UX Scrollbar Visibility',
    'version': '0.4.0',
    'description': 'Keeps scrollbars visible with user-origin styling and a manual top-layer rail runtime.',
    'minimum_chrome_version': '121',
    'permissions': ['scripting'],
    'host_permissions': ['http://*/*', 'https://*/*'],
    'background': {'service_worker': 'background.js', 'scripts': ['background.js']},
    'content_scripts': [{
        'matches': ['http://*/*', 'https://*/*'],
        'js': ['toplayer-sentinel-main.js'],
        'world': 'MAIN',
        'run_at': 'document_start',
        'all_frames': True,
        'match_about_blank': True,
        'match_origin_as_fallback': True,
    }, {
        'world': 'ISOLATED',
        'matches': ['http://*/*', 'https://*/*'],
        'js': ['rail-core.js', 'content.js'],
        'run_at': 'document_start',
        'all_frames': True,
        'match_about_blank': True,
        'match_origin_as_fallback': True,
    }],
    'browser_specific_settings': {'gecko': {
        'id': 'scrollbar-visibility@browser-ux',
        'strict_min_version': '140.0',
        'data_collection_permissions': {'required': ['none']},
    }},
}
GECKO_ID = 'scrollbar-visibility@browser-ux'
SHIPPED_SHEET = [('*', [('scrollbar-width', 'auto', True),
                        ('scrollbar-color', 'GrayText Canvas', True)])]


@pytest.fixture
def prefs(load_module):
    return load_module('tests/browser_preferences.py')


def require(condition, message='requirement failed'):
    if not condition:
        raise AssertionError(message)


def writable_copy(source, destination):
    """copytree keeps read-only store modes inside Nix builds; mutation copies must be writable."""
    shutil.copytree(source, destination, copy_function=shutil.copyfile)
    for path in [destination, *destination.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)


def walk_keys(value):
    if isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from walk_keys(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from walk_keys(inner)


# Manifest and permissions ---------------------------------------------------------------

def test_manifest_is_exact_and_minimal(prefs, repo_root):
    manifest = json.loads((repo_root / EXT / 'manifest.json').read_text())
    require(manifest == EXPECTED_MANIFEST, manifest)
    require(prefs.check_manifest(manifest) == [], prefs.check_manifest(manifest))
    keys = set(walk_keys(manifest))
    for forbidden in ('key', 'web_accessible_resources', 'externally_connectable', 'css',
                      'optional_permissions', 'optional_host_permissions', 'update_url',
                      'content_security_policy', 'commands', 'action', 'incognito'):
        require(forbidden not in keys, forbidden)
    for permission in ('tabs', 'webNavigation', 'storage', 'activeTab', 'webRequest',
                       'declarativeNetRequest', 'nativeMessaging', '<all_urls>'):
        require(permission not in manifest['permissions'] + manifest['host_permissions'], permission)
    # Only web schemes: privileged/browser-internal pages are out of scope by design.
    for pattern in manifest['host_permissions'] + manifest['content_scripts'][0]['matches']:
        require(re.fullmatch(r'https?://\*/\*', pattern), pattern)


def test_manifest_cross_browser_contract(repo_root):
    """MV3 dual background (Chrome >=121 uses service_worker, Firefox >=121 uses
    scripts) and related-frame coverage (match_origin_as_fallback needs a wildcard
    path; Firefox 128 is the floor that added it)."""
    manifest = json.loads((repo_root / EXT / 'manifest.json').read_text())
    background = manifest['background']
    require(background == {'service_worker': 'background.js', 'scripts': ['background.js']})
    require(int(manifest['minimum_chrome_version']) >= 121)
    require(tuple(map(int, manifest['browser_specific_settings']['gecko']['strict_min_version']
                      .split('.'))) >= (140, 0))
    script = manifest['content_scripts'][0]
    require(script['all_frames'] is True and script['match_about_blank'] is True
            and script['match_origin_as_fallback'] is True, script)
    require(all(p.endswith('/*') for p in script['matches']), 'wildcard path required')


def test_manifest_passes_source_snapshot_capture_refusal(load_module, repo_root):
    snapshot = load_module('tests/source_only_snapshot.py')
    raw = (repo_root / EXT / 'manifest.json').read_bytes()
    snapshot.reject_capture(f'{EXT}/manifest.json', raw)


# Stylesheet and cascade -----------------------------------------------------------------

def test_stylesheet_declares_only_user_important_standard_properties(prefs, repo_root):
    text = (repo_root / EXT / 'scrollbars.css').read_text()
    require(prefs.css_rules(text) == SHIPPED_SHEET, prefs.css_rules(text))
    require(prefs.check_sheet(text) == [], prefs.check_sheet(text))
    stripped = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    for token in ('overflow', 'display', 'height', 'gutter', 'webkit', 'position', 'contain',
                  'thin', 'none', 'transparent', '#', 'rgb', 'hsl', '@'):
        require(token not in stripped, token)


def test_extension_checker_accepts_source(prefs, repo_root):
    require(prefs.check_extension(repo_root / EXT) == [], prefs.check_extension(repo_root / EXT))


def test_variant_sheets_are_retired(repo_root):
    require(not (repo_root / 'tests/fixtures/browser-preferences/scrollbar-variants').exists())


SHIPPED = {'origin': 'user', 'important': True, 'specificity': (0, 0, 0), 'order': 0}
AUTHOR_HIDES = {
    'normal': {'origin': 'author', 'important': False, 'specificity': (1, 1, 0), 'order': 9},
    'important': {'origin': 'author', 'important': True, 'specificity': (1, 1, 0), 'order': 9},
    'layered-important': {'origin': 'author', 'important': True, 'layer': 0, 'specificity': (1, 0, 0)},
    'inline-important': {'origin': 'author', 'important': True, 'inline': True},
    'root-normal': {'origin': 'author', 'important': False, 'specificity': (0, 0, 1)},
}


@pytest.mark.parametrize('case', sorted(AUTHOR_HIDES))
def test_spec_model_user_important_beats_author_hiding(prefs, case):
    require(prefs.winner(SHIPPED, AUTHOR_HIDES[case]) is SHIPPED, case)
    require(prefs.winner(AUTHOR_HIDES[case], SHIPPED) is SHIPPED, case)


@pytest.mark.parametrize('case', ['important', 'layered-important', 'inline-important'])
def test_spec_model_negative_control_author_origin_would_lose(prefs, case):
    # insertCSS's default AUTHOR origin behaves like a late unlayered author sheet.
    as_author = {**SHIPPED, 'origin': 'author', 'order': 100}
    require(prefs.winner(as_author, AUTHOR_HIDES[case]) is AUTHOR_HIDES[case], case)


def test_spec_model_layer_and_inline_ordering_sanity(prefs):
    early = {'origin': 'author', 'important': True, 'layer': 0}
    late = {'origin': 'author', 'important': True, 'layer': 1}
    unlayered = {'origin': 'author', 'important': True}
    require(prefs.winner(early, late) is early)
    require(prefs.winner(late, unlayered) is late)
    normal_late = {'origin': 'author', 'important': False, 'layer': 1}
    normal_unlayered = {'origin': 'author', 'important': False}
    require(prefs.winner(normal_late, normal_unlayered) is normal_unlayered)
    require(prefs.winner({'origin': 'user', 'important': False}, AUTHOR_HIDES['normal'])
            is AUTHOR_HIDES['normal'])


def shipped_sheet(prefs, repo_root, origin='user'):
    return prefs.sheet_declarations(prefs.css_rules((repo_root / EXT / 'scrollbars.css').read_text()),
                                    origin)


def test_case_model_matches_fixture_ids_and_expectations(prefs, repo_root):
    html = (repo_root / FIXTURE).read_text()
    fixture = dict(re.findall(r'id="(c\d+)" data-expect="(visible|absent|related|record)"', html))
    model = {case['id']: case['expect'] for case in prefs.SCROLLBAR_CASES}
    require(fixture == model, (fixture, model))
    related = sorted(i for i, e in model.items() if e == 'related')
    require(related == ['c19', 'c20', 'c21', 'c22', 'c8'], related)
    require(sorted(int(i[1:]) for i in model) == list(range(1, 28)), sorted(model))
    require(len(re.findall(r'id="c\d+"', html)) == 27, 'duplicate or untagged case ids')


def test_case_model_resolves_shipped_sheet(prefs, repo_root):
    sheet = shipped_sheet(prefs, repo_root)
    manifest = json.loads((repo_root / EXT / 'manifest.json').read_text())
    for case in prefs.SCROLLBAR_CASES:
        state = prefs.declared_state(case, sheet)
        if case['expect'] in ('visible', 'related'):
            require(state == {'scroll_container': True, 'width': 'auto', 'color': 'GrayText Canvas',
                              'webkit_path': False, 'outcome': 'visible'}, (case['id'], state))
            require(prefs.frame_reached(case, manifest), case['id'])
        if case['expect'] == 'absent':
            require(state['outcome'] == 'absent' and not state['scroll_container'], case['id'])
            require(case['overflow'] in ('hidden', 'visible') or not case['overflows'], case['id'])


def test_case_model_negative_controls(prefs, repo_root):
    by_id = {case['id']: case for case in prefs.SCROLLBAR_CASES}
    # The PREFERENCES1 sheet (width only) leaves the WebKit path and transparent colors live.
    old = prefs.sheet_declarations([('*', [('scrollbar-width', 'auto', True)])], 'user')
    for case_id in ('c5', 'c11', 'c12', 'c13', 'c16', 'c17', 'c23'):
        require(prefs.declared_state(by_id[case_id], old)['outcome'] == 'hidden', case_id)
    # The same sheet at AUTHOR origin loses to author !important, layered and inline hiding.
    as_author = shipped_sheet(prefs, repo_root, origin='author')
    for case_id in ('c2', 'c3', 'c4'):
        require(prefs.declared_state(by_id[case_id], as_author)['outcome'] == 'hidden', case_id)
    # Without any sheet every hiding case hides; absent cases stay absent.
    for case in prefs.SCROLLBAR_CASES:
        state = prefs.declared_state(case, [])
        if case['expect'] in ('visible', 'related') and case['id'] not in ('c15', 'c26', 'c27'):
            require(state['outcome'] == 'hidden', case['id'])
        if case['expect'] == 'absent':
            require(state['outcome'] == 'absent', case['id'])


# Mutations: each copy of the extension must be rejected by the checker -----------------

def _replace(name, old, new):
    def apply(directory):
        path = directory / name
        text = path.read_text()
        require(old in text, (name, old))
        path.write_text(text.replace(old, new, 1))
    return apply


def _manifest(edit):
    def apply(directory):
        path = directory / 'manifest.json'
        manifest = json.loads(path.read_text())
        edit(manifest)
        path.write_text(json.dumps(manifest))
    return apply


def _script(key, value):
    return _manifest(lambda m: m['content_scripts'][0].__setitem__(key, value))


def _drop_script_key(key):
    return _manifest(lambda m: m['content_scripts'][0].pop(key))


COLOR = 'scrollbar-color: GrayText Canvas !important;'
WIDTH = 'scrollbar-width: auto !important;'
MUTATIONS = {
    'origin-author': _replace('background.js', 'origin: "USER"', 'origin: "AUTHOR"'),
    'origin-dropped': _replace('background.js', 'origin: "USER",', ''),
    'overflow-in-rule': _replace('scrollbars.css', COLOR, COLOR + ' overflow: auto !important;'),
    'overflow-new-rule': _replace('scrollbars.css', '}', '}\nhtml { overflow-y: scroll; }'),
    'color-removed': _replace('scrollbars.css', COLOR, ''),
    'color-not-important': _replace('scrollbars.css', COLOR, 'scrollbar-color: GrayText Canvas;'),
    'color-auto': _replace('scrollbars.css', COLOR, 'scrollbar-color: auto !important;'),
    'color-transparent': _replace('scrollbars.css', COLOR,
                                  'scrollbar-color: transparent transparent !important;'),
    'color-hex': _replace('scrollbars.css', COLOR, 'scrollbar-color: #777 #fff !important;'),
    'color-same': _replace('scrollbars.css', COLOR, 'scrollbar-color: Canvas Canvas !important;'),
    'width-removed': _replace('scrollbars.css', WIDTH, ''),
    'width-thin': _replace('scrollbars.css', WIDTH, 'scrollbar-width: thin !important;'),
    'width-not-important': _replace('scrollbars.css', WIDTH, 'scrollbar-width: auto;'),
    'webkit-rule': _replace('scrollbars.css', '}', '}\n*::-webkit-scrollbar { width: 12px; }'),
    'origin-fallback-removed': _drop_script_key('match_origin_as_fallback'),
    'origin-fallback-false': _script('match_origin_as_fallback', False),
    'about-blank-removed': _drop_script_key('match_about_blank'),
    'all-frames-false': _script('all_frames', False),
    'all-urls-host': _manifest(lambda m: m.__setitem__('host_permissions', ['<all_urls>'])),
    'all-urls-match': _script('matches', ['<all_urls>']),
    'main-world-dropped': _drop_script_key('world'),
    'main-world-isolated': _script('world', 'ISOLATED'),
    'main-idle': _script('run_at', 'document_idle'),
    'main-script-missing': _script('js', ['content.js']),
    'isolated-world-main': _manifest(lambda m: m['content_scripts'][1].__setitem__('world', 'MAIN')),
    'isolated-frames-false': _manifest(lambda m: m['content_scripts'][1].__setitem__('all_frames', False)),
    'service-worker-removed': _manifest(lambda m: m['background'].pop('service_worker')),
    'scripts-removed': _manifest(lambda m: m['background'].pop('scripts')),
    'sender-guard-removed': _replace('background.js', ' || sender.id !== chrome.runtime.id', ''),
}


@pytest.mark.parametrize('name', sorted(MUTATIONS))
def test_mutation_is_rejected(prefs, repo_root, tmp_path, name):
    copy = tmp_path / 'ext'
    writable_copy(repo_root / EXT, copy)
    require(prefs.check_extension(copy) == [], 'unmutated copy must pass')
    MUTATIONS[name](copy)
    require(prefs.check_extension(copy) != [], f'{name} was not detected')


# Scripts ---------------------------------------------------------------------------------

def run_harness(repo_root, extension=None):
    node = shutil.which('node')
    require(node is not None, 'node is required for the extension harness')
    completed = subprocess.run(
        [node, str(repo_root / 'tests/browser-preferences-harness.mjs'),
         str(extension or repo_root / EXT)],
        capture_output=True, text=True, timeout=60, check=False)
    require(completed.returncode == 0, completed.stderr)
    require(completed.stderr == '', completed.stderr)
    return json.loads(completed.stdout)


INSERT = {'api': 'scripting.insertCSS', 'args': [{
    'target': {'tabId': 7, 'frameIds': [3]}, 'files': ['scrollbars.css', 'rail-host.css'], 'origin': 'USER'}]}


def clean(calls, returned=('undefined',), responses=()):
    return {'listeners': 1, 'returned': list(returned), 'calls': calls, 'error': None,
            'unhandled': [], 'responses': list(responses)}


def test_background_injects_user_origin_css_only_for_exact_sender(repo_root):
    result = run_harness(repo_root)['background']
    require(result['valid'] == clean([INSERT], ('true',), ({'ok': True},)), result['valid'])
    top = dict(INSERT, args=[dict(INSERT['args'][0], target={'tabId': 7, 'frameIds': [0]})])
    require(result['top-frame'] == clean([top], ('true',), ({'ok': True},)), result['top-frame'])
    for name in ('wrong-message', 'object-message', 'foreign-sender', 'missing-tab', 'missing-frame'):
        require(result[name] == clean([]), name)


@pytest.mark.parametrize('mode', ['resolves', 'rejects', 'undefined', 'object', 'throws'])
def test_background_is_silent_for_every_insert_return_shape(repo_root, mode):
    result = run_harness(repo_root)['background-returns'][mode]
    require(result == clean([INSERT], ('true',), ({'ok': mode == 'resolves'},)), result)


def test_scripts_use_no_network_dynamic_code_or_page_exports(repo_root):
    for name in ('background.js', 'content.js', 'rail-core.js', 'toplayer-sentinel-main.js'):
        source = (repo_root / EXT / name).read_text()
        for token in ('fetch(', 'XMLHttpRequest', 'eval(', 'Function(', 'executeScript',
                      'registerContentScripts', 'storage', 'tabs.', 'innerHTML',
                      'insertAdjacentHTML', 'outerHTML', 'console.', 'exportparts', '::part',
                      'chatgpt', 'openai'):
            require(token not in source.lower() if token in ('chatgpt', 'openai') else token not in source,
                    (name, token))
        require(re.search(r'\bimport(?:\s|\()', source) is None, name)
        require(re.search(r'mode\s*:\s*["\']open', source) is None, name)
    source = (repo_root / EXT / 'background.js').read_text()
    require('document' not in source and 'window' not in source)


def test_closed_background_response_channel_is_silent(repo_root):
    result = run_harness(repo_root)['closed-response-channel']
    require(result == clean([INSERT], ('true',)), result)


def test_background_unhandled_return_mutation_is_observable(repo_root, tmp_path):
    copy = tmp_path / 'ext'
    writable_copy(repo_root / EXT, copy)
    p = copy / 'background.js'
    source = p.read_text()
    require('return;' in source)
    p.write_text(source.replace('return;', 'return true;', 1))
    require(run_harness(repo_root, copy)['background']['wrong-message']['returned'] != ['undefined'])


# Package ---------------------------------------------------------------------------------

def test_package_is_deterministic_and_pinned(prefs, repo_root):
    first, second = prefs.package_bytes(repo_root), prefs.package_bytes(repo_root)
    require(first == second, 'package bytes differ between builds')
    require(hashlib.sha256(first).hexdigest() == PACKAGE_SHA256, hashlib.sha256(first).hexdigest())
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        infos = archive.infolist()
        require([i.filename for i in infos] == sorted(MEMBER_SHA256), [i.filename for i in infos])
        for info in infos:
            require(info.compress_type == zipfile.ZIP_STORED and info.date_time == (1980, 1, 1, 0, 0, 0))
            require(info.external_attr >> 16 == 0o100644, info.filename)
            require(hashlib.sha256(archive.read(info)).hexdigest() == MEMBER_SHA256[info.filename],
                    info.filename)


def test_gui_kit_pins_match_this_suite(load_module, repo_root):
    kit = load_module('tests/scrollbar_gui_kit.py')
    require(kit.PACKAGE_SHA256 == PACKAGE_SHA256, kit.PACKAGE_SHA256)
    require(kit.MEMBER_SHA256 == MEMBER_SHA256, kit.MEMBER_SHA256)
    require(kit.FIXTURE_SHA256 == FIXTURE_SHA256, kit.FIXTURE_SHA256)
    fixture = hashlib.sha256((repo_root / FIXTURE).read_bytes()).hexdigest()
    require(fixture == FIXTURE_SHA256, fixture)
    require(kit.VERSION == EXPECTED_MANIFEST['version'])


# Boundaries ------------------------------------------------------------------------------

def test_extension_is_not_a_command_and_not_registered_in_policy(repo_root):
    manifest = json.loads((repo_root / 'tests/fixtures/command-source-manifest.json').read_text())
    require(not any('extensions/' in path or 'scrollbar' in path for path in manifest), 'packaged')
    paths = [repo_root / path for path in (
        'config/browser/extension-policy.nix', 'config/browser/chrome-policy-defaults.nix',
        'config/browser/firefox-policy-defaults.nix', 'modules/default.nix', 'flake.nix')]
    paths += list((repo_root / 'config/browser/families').glob('*.nix'))
    paths += list((repo_root / 'config/browser/replacements').glob('*.nix'))
    for path in paths:
        require(GECKO_ID not in path.read_text(), str(path.relative_to(repo_root)))
    require(not any('scrollbar' in p.name for p in (repo_root / 'bin').iterdir()), 'bin')


# These existing declarative policies are not direct credential-store writes.
# Keep this exception limited to the exact Apple-only block in its source owner.
# The source-policy semantics are also exercised by primary-cutover contracts.
# This is a static source guard, not a Nix parser or installed-browser proof.
_APPLE_SIGNON_POLICY = b'''  } // (if credentialProvider == "apple" then {
    "signon.autofillForms" = { Value = false; Status = "locked"; };
    "signon.rememberSignons" = { Value = false; Status = "locked"; };
  } else { });'''
_CREDENTIAL_SOURCE_FORBIDDEN = (
    b'logins.json', b'key4.db', b'Login Data', b'userChrome', b'userContent',
    b'legacyUserProfileCustomizations', b'KioskMode', b'--kiosk',
)
_GECKO_POLICY_SOURCE = 'config/browser/families/gecko.nix'


def _require_credential_source_boundary(relative, raw):
    for token in _CREDENTIAL_SOURCE_FORBIDDEN:
        require(token not in raw, (relative, token))
    # Preserve the existing flake-metadata exception, not an exception for a
    # production directory or for arbitrary occurrences of allowed key names.
    if relative == 'flake.nix':
        return
    if relative == _GECKO_POLICY_SOURCE:
        require(raw.count(_APPLE_SIGNON_POLICY) == 1,
                (relative, 'expected one unchanged Apple-only signon policy block'))
        raw = raw.replace(_APPLE_SIGNON_POLICY, b'', 1)
    require(b'signon.' not in raw, (relative, 'unexpected signon preference'))


def test_no_credential_store_mutation_or_profile_styling_hack(repo_root):
    sources = [p for folder in ('modules', 'config', 'lib', 'extensions')
               for p in (repo_root / folder).rglob('*') if p.is_file()]
    for path in [repo_root / 'flake.nix'] + sources:
        _require_credential_source_boundary(path.relative_to(repo_root).as_posix(),
                                            path.read_bytes())


def test_credential_guard_accepts_existing_apple_block(repo_root):
    _require_credential_source_boundary(
        _GECKO_POLICY_SOURCE, (repo_root / _GECKO_POLICY_SOURCE).read_bytes())


@pytest.mark.parametrize('relative', ['modules/example.nix', _GECKO_POLICY_SOURCE, 'flake.nix'])
@pytest.mark.parametrize('token', _CREDENTIAL_SOURCE_FORBIDDEN)
def test_credential_guard_still_rejects_store_and_styling_tokens(relative, token):
    raw = _APPLE_SIGNON_POLICY if relative == _GECKO_POLICY_SOURCE else b'{}'
    with pytest.raises(AssertionError):
        _require_credential_source_boundary(relative, raw + b'\n' + token)


@pytest.mark.parametrize('relative', [
    'modules/example.nix', 'config/example.nix', 'lib/example.nix',
    'extensions/example.js', 'config/browser/families/other.nix',
])
def test_credential_guard_cannot_move_exception_to_another_source(relative):
    with pytest.raises(AssertionError):
        _require_credential_source_boundary(relative, _APPLE_SIGNON_POLICY)


@pytest.mark.parametrize('mutation', [
    'wrong-provider', 'unconditional', 'autofill-enabled', 'remember-enabled',
    'unlocked', 'missing-block', 'duplicate-block', 'extra-inside', 'extra-outside',
    'allowed-key-outside',
])
def test_credential_guard_rejects_changed_or_extra_signon_policy(mutation):
    raw = _APPLE_SIGNON_POLICY
    mutations = {
        'wrong-provider': raw.replace(b'credentialProvider == "apple"', b'credentialProvider == "legacy"'),
        'unconditional': raw.replace(b'credentialProvider == "apple"', b'true'),
        'autofill-enabled': raw.replace(b'"signon.autofillForms" = { Value = false',
                                       b'"signon.autofillForms" = { Value = true'),
        'remember-enabled': raw.replace(b'"signon.rememberSignons" = { Value = false',
                                       b'"signon.rememberSignons" = { Value = true'),
        'unlocked': raw.replace(b'Status = "locked"', b'Status = "default"'),
        'missing-block': b'{}',
        'duplicate-block': raw + b'\n' + raw,
        'extra-inside': raw.replace(b'  } else', b'    "signon.extra" = false;\n  } else'),
        'extra-outside': raw + b'\n"signon.extra" = false;',
        'allowed-key-outside': raw + b'\n"signon.autofillForms" = false;',
    }
    with pytest.raises(AssertionError):
        _require_credential_source_boundary(_GECKO_POLICY_SOURCE, mutations[mutation])


R1_SOURCES = (
    f'{EXT}/manifest.json', f'{EXT}/background.js', f'{EXT}/content.js', f'{EXT}/scrollbars.css',
    f'{EXT}/rail-core.js', f'{EXT}/rail-host.css',
    'tests/browser_preferences.py', 'tests/browser-preferences.test.py',
    'tests/browser-preferences-harness.mjs', FIXTURE, 'tests/scrollbar_gui_kit.py',
    'tests/scrollbar-gui-kit.test.py', 'docs/architecture/browser-operator-preferences.md',
    'tests/scrollbar_gui_runtime.py', 'tests/scrollbar-gui-runtime.test.py',
    'tests/scrollbar_gui_observer.py', 'tests/scrollbar-gui-observer.test.py',
    'tests/fixtures/browser-preferences/scrollbar-rail-boundary.html',
)
SECRET_PATTERNS = (
    rb'-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----',
    rb'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # JWT-shaped
    rb'(?i)(api[_-]?(key|secret)|jwt[_-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9/+_-]{16,}',
    rb'user:\d{5,}:\d+',  # AMO JWT issuer shape
    rb'AKIA[0-9A-Z]{16}',
)


def test_no_signing_secret_in_r1_sources(repo_root):
    for name in R1_SOURCES:
        raw = (repo_root / name).read_bytes()
        for pattern in SECRET_PATTERNS:
            require(re.search(pattern, raw) is None, (name, pattern))
    manifest = json.loads((repo_root / EXT / 'manifest.json').read_text())
    require('key' not in manifest, 'a manifest key would pin a private-key-derived ID in source')


def test_secret_scan_negative_control():
    # Assembled at runtime so the scanned sources never contain a literal match.
    samples = [b'-----BEGIN ' + b'PRIVATE KEY-----', b'api_' + b'secret = "' + b'a' * 32 + b'"',
               b'user:' + b'12345:67']
    for sample in samples:
        require(any(re.search(p, sample) for p in SECRET_PATTERNS), sample)


GUI_FIXTURES = (
    FIXTURE,
    'tests/fixtures/browser-preferences/scrollbar-rail-boundary.html',
)
OFFLINE_DISALLOWED_TOKENS = (
    'fetch(', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon',
    'import(', 'importScripts(',
)
OFFLINE_RESOURCE_PATTERNS = (
    r'<link\b',
    r'<script\b[^>]*\bsrc\s*=',
    r'<img\b',
    r'<object\b',
    r'<embed\b',
    r'<audio\b',
    r'<video\b',
    r'<iframe\b[^>]*\bsrc\s*=',
    r'@import\b',
    r'\burl\s*\(',
    r'(?:src|href)\s*=\s*["\']?\s*//',
    r'\bfetch\s*\(',
    r'\bsendBeacon\s*\(',
)


def assert_gui_fixture_is_offline(html):
    urls = re.findall(r'(?:https?|wss?|ftp)://[^\s"\'<>`]+', html)
    require(urls == [], urls)
    for token in OFFLINE_DISALLOWED_TOKENS:
        require(token not in html, token)
    for pattern in OFFLINE_RESOURCE_PATTERNS:
        matches = re.findall(pattern, html, flags=re.IGNORECASE)
        require(matches == [], (pattern, matches))


@pytest.mark.parametrize('fixture_path', GUI_FIXTURES)
def test_gui_fixture_is_offline(repo_root, fixture_path):
    html = (repo_root / fixture_path).read_text()
    assert_gui_fixture_is_offline(html)


def test_gui_fixture_offline_negative_control():
    # Assembled at runtime so scanned test sources never contain literal active URLs.
    scheme = 'http' + 's://'
    samples = [
        '<script ' + f'src="{scheme}remote.invalid/bundle.js"></script>',
        '<script defer ' + f'src="{scheme}remote.invalid/bundle.js"></script>',
        '<link rel="stylesheet" ' + f'href="{scheme}remote.invalid/theme.css">',
        f'<img src="{scheme}remote.invalid/pixel.png">',
        f'<iframe src="{scheme}remote.invalid/frame.html"></iframe>',
        '<iframe src="//remote.invalid/frame.html"></iframe>',
        '<script src="//remote.invalid/bundle.js"></script>',
        'window.' + 'fetch("/telemetry")',
        'fetch  ("/telemetry")',
        'new ' + 'XMLHttpRequest()',
        'new ' + 'WebSocket("wss://remote.invalid/socket")',
        'new ' + 'EventSource("/events")',
        'navigator.' + 'sendBeacon("/log")',
        'import(' + f'"{scheme}remote.invalid/mod.js")',
        'importScripts(' + f'"{scheme}remote.invalid/worker.js")',
        '<style>@import ' + f'"{scheme}remote.invalid/theme.css";</style>',
        '<style>div { background: url("/pixel.png"); }</style>',
    ]
    for sample in samples:
        rejected = False
        try:
            assert_gui_fixture_is_offline(sample)
        except AssertionError:
            rejected = True
        require(rejected, f'sample was not rejected: {sample!r}')
