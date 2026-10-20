"""BUX5B1 CONSUMER-ADAPT1 Brave YouTube derived consumer: portable, temporary-root-only tests.

No browser, live profile, operator root, Shared Images archive or cloud is touched. Every
state root is built beneath tmp_path with the accepted capture path from the synthetic
6.12.1 fixture (exported on Firefox 155.0.1: under the projected labels it is a synthetic
test vector only, never accepted 156.0.1 evidence, exactly as in the recovery tests).

Audit limitation: Python audit events cover open/listdir/scandir and mutating os/shutil
calls; os.stat/os.lstat/os.access are wrapped in-process to record their paths too. Calls
made from C code that bypasses those Python entry points are not observable; the static
token checks remain the primary proof that no legacy Chrome path is referenced.
"""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import sys

import pytest

HELPER = 'libexec/clear-new-tab/brave-youtube-consumer.py'
RECOVERY = 'libexec/clear-new-tab/guarded_recovery.py'
FOUNDATION = 'libexec/clear-new-tab/durable_state.py'
SYNC = 'bin/clear-new-tab-sync'
RECOVERY_SHA256 = '1cf34e0edbbaee0ceb5e9ad80284abbb2f84c813b3b853766954254d950b8053'
FOUNDATION_SHA256 = '7a1dd704988088c22d1502b72318183960c8f70e3bde6e9908ec42255c653eea'
FIXTURE = Path('tests/fixtures/cnt-native/firefox/6.12.1')
CHROME_ID = 'felphkbfjadmcejnibcmcncimlappdde'
PROFILE, STORAGE = 'a' * 64, 'b' * 64
CHROME_LABELS = {'engine': 'chrome', 'extension_id': CHROME_ID, 'extension_version': '6.12.1',
                 'browser_version': None}
PLAN_KEYS = {'schema', 'source', 'native_parts_brave_portable', 'derived', 'excluded', 'verdict', 'refusal',
             'bux5c_requirements', 'backup_coverage'}
SOURCE_KEYS = {'authority', 'manifest_sha256', 'fingerprint', 'labels', 'revision', 'projection_status',
               'native_part_sha256'}
DERIVED_KEYS = {'position', 'native_rank', 'content_sha256', 'content_ref_kind', 'content'}


# --- Audit: every open/listdir/scandir/stat path and every mutating call while gated ------------

_EVENTS = []
_GATE = [False]
_MUTATING = {'os.mkdir', 'os.rename', 'os.remove', 'os.rmdir', 'os.symlink', 'os.link', 'os.chmod',
             'os.chown', 'os.truncate', 'os.utime', 'os.chflags', 'os.lchflags', 'os.mkfifo', 'os.mknod',
             'shutil.copyfile', 'shutil.copymode', 'shutil.copystat', 'shutil.copytree', 'shutil.rmtree',
             'shutil.move', 'shutil.unpack_archive', 'shutil.make_archive'}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _hook(event, args):
    if not _GATE[0]:
        return
    if event == 'open':
        flags = args[2] if len(args) > 2 and type(args[2]) is int else 0
        _EVENTS.append(('open-write' if flags & _WRITE_FLAGS else 'open', _text(args[0])))
    elif event in ('os.listdir', 'os.scandir'):
        _EVENTS.append((event, _text(args[0])))
    elif event in _MUTATING:
        _EVENTS.append(('mutate:' + event, _text(args[0]) if args else ''))


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value if isinstance(value, str) else str(value) if isinstance(value, os.PathLike) else repr(value)


sys.addaudithook(_hook)


@pytest.fixture(autouse=True)
def recorded_stats(monkeypatch):
    for name in ('stat', 'lstat', 'access'):
        original = getattr(os, name)

        def wrapper(path, *args, _original=original, _name=name, **kwargs):
            if _GATE[0]:
                _EVENTS.append((_name, _text(path)))
            return _original(path, *args, **kwargs)
        monkeypatch.setattr(os, name, wrapper)


def writes(events):
    return [e for e in events if e[0] == 'open-write' or e[0].startswith('mutate:')]


def test_the_recorder_sees_writes_reads_and_stats(tmp_path):
    """Meta-test: the audit hook and stat wrappers are live, so an empty record means something."""
    _EVENTS.clear()
    _GATE[0] = True
    try:
        (tmp_path / 'made').mkdir()
        with open(tmp_path / 'made/file', 'wb') as stream:
            stream.write(b'x')
        os.lstat(tmp_path / 'made')
        os.listdir(tmp_path)
        os.close(os.open(tmp_path / 'made/file', os.O_RDONLY))
        os.rename(tmp_path / 'made/file', tmp_path / 'made/moved')
    finally:
        _GATE[0] = False
    kinds = [kind for kind, _path in _EVENTS]
    assert {'mutate:os.mkdir', 'open-write', 'lstat', 'os.listdir', 'open', 'mutate:os.rename'} <= set(kinds)
    assert len(writes(_EVENTS)) == 3


# --- Fixtures ----------------------------------------------------------------------------------

@pytest.fixture
def consumer(load_module):
    return load_module(HELPER)


@pytest.fixture
def gr(load_module):
    # An independent writer: the consumer's own private library objects are never shared.
    return load_module(RECOVERY)


@pytest.fixture
def native(repo_root):
    return json.loads((repo_root / FIXTURE / 'export.json').read_bytes())


@pytest.fixture
def labels(gr):
    return dict(gr.ds.PROJECTED_LABELS)


@pytest.fixture
def home(tmp_path):
    path = tmp_path / 'home'
    path.mkdir()
    return path


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'state'
    path.mkdir()
    return path


@pytest.fixture
def target(tmp_path):
    """A disposable Brave-style user-data tree that must never change."""
    path = tmp_path / 'brave'
    for relative, raw in (('Default/IndexedDB/chrome-extension_x_0.indexeddb.leveldb/000003.log', b'target-db'),
                          ('Default/Local Extension Settings/x/000003.log', b'target-settings'),
                          ('clear-new-tab-extension/manifest.json', b'{"target": true}'),
                          ('Default/Preferences', b'{}')):
        (path / relative).parent.mkdir(parents=True, exist_ok=True)
        (path / relative).write_bytes(raw)
    return path


@pytest.fixture
def env(home, target):
    return {'HOME': str(home), 'BRAVE_YOUTUBE_USER_DATA_DIR': str(target)}


@pytest.fixture(autouse=True)
def roots_stay_temporary(consumer, tmp_path, monkeypatch):
    """Guard: no resolved state root may be the real operator root or leave tmp_path."""
    real = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.local' / 'state' / 'browser-ux'
    original = consumer.resolve_state_root

    def guarded(explicit, environ):
        resolved = original(explicit, environ)
        text = str(resolved[0])
        assert text.startswith(str(tmp_path) + '/') or text.startswith('/nonexistent'), text
        assert not text.startswith(str(real)), text
        return resolved
    monkeypatch.setattr(consumer, 'resolve_state_root', guarded)


def dump(value):
    return json.dumps(value).encode()


def with_ranks(native, ranks):
    value = copy.deepcopy(native)
    for chunk, rank in zip(value['chunks'], ranks):
        chunk['data']['i'] = rank
    return [dump(value)]


def store(gr, root, labels, parts, **kwargs):
    target = gr.bind_target({'labels': dict(labels), 'profile_token': PROFILE, 'storage_token': STORAGE})
    export = {'labels': dict(labels), 'part_count': len(parts), 'parts': list(parts)}
    return gr.capture_export(root, gr.verify_export(export, target), **kwargs)


def snapshot(path):
    """Paths, kinds, modes, bytes and link targets of a whole tree (taken outside the audit gate)."""
    result = {}
    if not os.path.lexists(path):
        return None
    for directory, folders, files in os.walk(path, followlinks=False):
        for name in folders + files:
            full = os.path.join(directory, name)
            info = os.lstat(full)
            relative = os.path.relpath(full, path)
            if os.path.islink(full):
                result[relative] = ('link', os.readlink(full))
            elif os.path.isdir(full):
                result[relative] = ('dir', info.st_mode)
            elif os.path.isfile(full):
                result[relative] = ('file', info.st_mode, Path(full).read_bytes())
            else:
                result[relative] = ('other', info.st_mode)
    return result


def run(consumer, argv, environ):
    out, err = io.StringIO(), io.StringIO()
    _EVENTS.clear()
    _GATE[0] = True
    try:
        code = consumer.main(list(argv), dict(environ), out, err)
    finally:
        _GATE[0] = False
    return code, out.getvalue(), err.getvalue(), list(_EVENTS)


def plan_of(consumer, root, digest, environ, *extra):
    code, out, err, events = run(consumer, ['plan', '--state-root', str(root), '--manifest', digest, *extra],
                                 environ)
    assert (code, err) == (0, ''), err
    assert writes(events) == []
    return json.loads(out), out, events


def refused(consumer, argv, environ, code, target=None):
    before = snapshot(target) if target is not None else None
    status, out, err, events = run(consumer, argv, environ)
    assert (status, out, err) == (3, '', 'clear-new-tab-sync: refused: %s\n' % code)
    assert writes(events) == []
    if target is not None:
        assert snapshot(target) == before
        assert not any(str(target) in path for _kind, path in events)
    return events


# --- Static source discipline -------------------------------------------------------------------

LEGACY_TOKENS = ('Google/Chrome', 'IndexedDB', 'Local Extension Settings', 'CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE',
                 'latest-source-extension-dir', CHROME_ID, 'Extensions/')


def test_helper_source_discipline(repo_root):
    text = (repo_root / HELPER).read_text()
    assert not text.startswith('#!')
    assert (repo_root / HELPER).stat().st_mode & 0o111 == 0
    for forbidden in LEGACY_TOKENS + (
            'shutil', 'os.replace', 'os.rename', 'mkdir', 'makedirs', 'os.remove', 'unlink', 'rmdir',
            'atomic_write', 'capture_export', 'gr.recover', 'gr.resume', 'adapter', 'write_bytes',
            'write_text', 'open(', 'symlink(', 'chmod', 'subprocess', 'assert ', 'sys.path', 'sys.modules[',
            '/usr/bin/python3', '/Users/', '/home/', '/run/current-system', '/usr/bin/env python',
            'expanduser', 'Path.home', 'getenv', 'socket'):
        assert forbidden not in text, forbidden
    # The process environment is read once, at the CLI boundary; functions take an injected mapping.
    assert text.count('os.environ') == 1
    assert "sys.exit(main(sys.argv[1:], os.environ, sys.stdout, sys.stderr))" in text
    # The retired legacy zone is named only to refuse overlap with it.
    assert text.count('RETIRED_LEGACY_ZONE') == 2


def test_sync_command_source_discipline(repo_root):
    text = (repo_root / SYNC).read_text()
    for forbidden in LEGACY_TOKENS + ('sync_dir', 'source_chrome_profile', '/bin/cp', '/bin/mv', '/bin/rm',
                                      'mkdir', 'guarded_recovery', 'durable_state', 'Default/'):
        assert forbidden not in text, forbidden
    # install.py rewrites exactly one interpreter and one cat; the helper is the only delegate.
    assert text.count('/usr/bin/python3') == 1 and text.count('  cat <<') == 1
    assert ('exec /usr/bin/python3 -I -B "$(clear_new_tab_libexec_dir)/brave-youtube-consumer.py" "$@"'
            in text)
    assert 'Chrome profile is not an authority' in text


def test_every_refusal_literal_is_bounded(consumer, repo_root):
    tree = ast.parse((repo_root / HELPER).read_text())
    found = set()
    positions = {'_require': 1, 'ConsumerError': 0, '_absolute': 1}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) in positions:
            index = positions[node.func.id]
            if len(node.args) > index and isinstance(node.args[index], ast.Constant):
                found.add(node.args[index].value)
    assert found and found <= set(consumer.REFUSAL_CODES)
    assert len(consumer.REFUSAL_CODES) == len(set(consumer.REFUSAL_CODES))
    assert consumer.REFUSAL_CODES[:len(consumer.gr.REFUSAL_CODES)] == consumer.gr.REFUSAL_CODES
    assert 'TARGET_INVALID' in consumer.gr.REFUSAL_CODES and 'TARGET_INVALID' not in consumer.CONSUMER_CODES
    assert str(consumer.ConsumerError('not-a-code')) == 'RECOVERY_INVALID'


def test_recovery_libraries_are_unchanged_private_siblings(consumer, repo_root):
    assert hashlib.sha256((repo_root / RECOVERY).read_bytes()).hexdigest() == RECOVERY_SHA256
    assert hashlib.sha256((repo_root / FOUNDATION).read_bytes()).hexdigest() == FOUNDATION_SHA256
    assert Path(consumer.gr.__file__) == repo_root / RECOVERY
    assert Path(consumer.ds.__file__) == repo_root / FOUNDATION
    assert 'browser_ux_cnt_guarded_recovery' not in sys.modules
    assert 'browser_ux_cnt_durable_state' not in sys.modules


# --- Root resolution and confinement (pure) -------------------------------------------------------

def test_state_root_resolution_is_explicit_or_frozen_default(consumer, home, tmp_path):
    environ = {'HOME': str(home)}
    explicit = str(tmp_path / 'explicit')
    assert consumer.resolve_state_root(explicit, environ) == (Path(explicit), 'explicit')
    default = home / '.local/state/browser-ux/clear-new-tab'
    assert consumer.resolve_state_root(None, environ) == (default, 'default')
    for same in (str(home / '.local/state'), str(home / '.local/state') + '/', ''):
        assert consumer.resolve_state_root(None, dict(environ, XDG_STATE_HOME=same))[1] == 'default'
    with pytest.raises(consumer.ConsumerError, match='^STATE_ROOT_RELOCATION_UNBOUND$'):
        consumer.resolve_state_root(None, dict(environ, XDG_STATE_HOME=str(tmp_path / 'elsewhere')))
    for bad in ('relative/root', str(tmp_path) + '/a/../b', str(tmp_path) + '/./b', str(tmp_path) + '//b',
                '/', str(tmp_path) + '/a\0b', ''):
        with pytest.raises(consumer.ConsumerError, match='^STATE_ROOT_INVALID$'):
            consumer.resolve_state_root(bad, environ)
    for bad_home in ({}, {'HOME': ''}, {'HOME': 'relative'}, {'HOME': '/a/../b'}):
        with pytest.raises(consumer.ConsumerError, match='^HOME_INVALID$'):
            consumer.resolve_state_root(None, bad_home)
    assert not (home / '.local').exists()


def test_target_resolution(consumer, home, tmp_path):
    assert consumer.resolve_target({'HOME': str(home)}) == home / 'Library/Application Support/Brave YouTube'
    assert consumer.resolve_target({'HOME': str(home), 'BRAVE_YOUTUBE_USER_DATA_DIR': str(tmp_path / 'b')}) \
        == tmp_path / 'b'
    for bad in ('relative', str(tmp_path) + '/../b', '/'):
        with pytest.raises(consumer.ConsumerError, match='^TARGET_INVALID$'):
            consumer.resolve_target({'HOME': str(home), 'BRAVE_YOUTUBE_USER_DATA_DIR': bad})


def test_roots_are_independently_confined(consumer, home, tmp_path):
    environ = {'HOME': str(home)}
    legacy = home / 'Library/Application Support/Google/Chrome'
    p = Path
    ok = (tmp_path / 'state', tmp_path / 'brave', tmp_path / 'images')
    _GATE[0] = True
    _EVENTS.clear()
    try:
        consumer.check_confinement(*ok, environ)
        consumer.check_confinement(ok[0], ok[1], None, environ)
        consumer.check_confinement(tmp_path / 'st', tmp_path / 'state', None, environ)  # prefix, not nested
        for state, brave, images in (
                (ok[0], ok[0], None), (ok[0], ok[0] / 'x', None), (ok[0] / 'x', ok[0], None),
                (ok[0], ok[1], ok[0] / 'images'), (ok[0], ok[1], ok[1]), (ok[0], ok[1], p('/')),
                (legacy / 'Default', ok[1], None), (ok[0], legacy, None), (home / 'Library', ok[1], None),
                (ok[0], ok[1], legacy.parent)):
            with pytest.raises(consumer.ConsumerError, match='^ROOTS_OVERLAP$'):
                consumer.check_confinement(state, brave, images, environ)
        # Source roots stay outside every browser profile zone; the target is a Brave profile by nature.
        support = home / 'Library/Application Support'
        consumer.check_confinement(ok[0], support / 'BraveSoftware/Brave-Browser', ok[2], environ)
        consumer.check_confinement(support / 'Firefoxes', ok[1], support / 'BraveSoftwareX', environ)
        for zone in (support / 'Brave YouTube', support / 'BraveSoftware', support / 'Chromium',
                     support / 'Firefox', support / 'Mozilla', home / 'Library/Caches/Firefox'):
            for state, images in ((zone, None), (zone / 'Profiles/x.default', None), (ok[0], zone / 'images'),
                                  (zone.parent, None)):
                with pytest.raises(consumer.ConsumerError, match='^ROOTS_OVERLAP$'):
                    consumer.check_confinement(state, ok[1], images, environ)
    finally:
        _GATE[0] = False
    assert _EVENTS == []  # pure: no filesystem call at all


# --- Verified consumption and the derived plan ------------------------------------------------------

def test_plan_is_exact_bounded_and_idempotent(consumer, gr, root, native, labels, env, target, tmp_path):
    record = store(gr, root, labels, [dump(native)])
    state_before, target_before = snapshot(root), snapshot(target)
    plan, out, _ = plan_of(consumer, root, record.manifest_sha256, env)
    assert set(plan) == PLAN_KEYS and set(plan['source']) == SOURCE_KEYS
    manifest = record.manifest
    assert plan['schema'] == 'browser-ux-cnt-brave-derived-plan-v1'
    assert plan['source'] == {'authority': 'browser-ux-durable-state', 'manifest_sha256': record.manifest_sha256,
                              'fingerprint': record.fingerprint, 'labels': labels, 'revision': 1,
                              'projection_status': 'PROJECTED_FIREFOX_6_12_1',
                              'native_part_sha256': list(record.part_digests)}
    assert (plan['verdict'], plan['refusal']) == ('REFUSED', 'BRAVE_CNT_IMPORT_UNQUALIFIED')
    assert plan['native_parts_brave_portable'] is False
    assert plan['backup_coverage'] == 'BACKUP_COVERAGE_NOT_CONFIRMED'
    assert plan['bux5c_requirements'] == list(consumer.BUX5C_REQUIREMENTS)
    assert set(plan['excluded']) >= {'settings', 'custom_code', 'presentation', 'thumbnail', 'tasks', 'native_id'}
    derived = plan['derived']
    assert set(derived) == {'order', 'occurrences'}
    assert derived['order'] == {'basis': 'native_rank', 'status': 'RANK_STRICTLY_ASCENDING'}
    assert [set(o) for o in derived['occurrences']] == [DERIVED_KEYS] * len(manifest['occurrences'])
    assert derived['occurrences'] == [
        {'position': o['position'], 'native_rank': o['native_rank'], 'content_sha256': o['content_sha256'],
         'content_ref_kind': 'native_only', 'content': 'NATIVE_PART_ONLY'} for o in manifest['occurrences']]
    # Only digests and ranks: no native IDs, preference values, data URLs or paths.
    for leaked in [o['native_id'] for o in manifest['occurrences']] + ['data:', 'transition_duration',
                                                                       'prefs', str(tmp_path), 'thumbnail_width']:
        assert leaked not in out, leaked
    assert out.encode() == consumer.ds.canonical_bytes(plan) + b'\n'
    # Repeat: byte-identical output; state root and target untouched.
    for _ in range(2):
        assert plan_of(consumer, root, record.manifest_sha256, env)[1] == out
    assert snapshot(root) == state_before and snapshot(target) == target_before


def test_multipart_state_is_part_verified(consumer, gr, root, native, labels, env):
    value = copy.deepcopy(native)
    parts = [dump(dict(value, chunks=value['chunks'][:2])), dump({'chunks': value['chunks'][2:]})]
    record = store(gr, root, labels, parts)
    plan, _, _ = plan_of(consumer, root, record.manifest_sha256, env)
    assert len(plan['source']['native_part_sha256']) == 2
    assert [o['position'] for o in plan['derived']['occurrences']] == [0, 1, 2, 3]


@pytest.mark.parametrize('ranks, status', [
    (['1', '5', '9', '20'], 'RANK_STRICTLY_ASCENDING'),        # gaps are kept verbatim
    (['1', '1.5', '2', '10'], 'RANK_STRICTLY_ASCENDING'),      # numeric, not string, comparison
    (['-2', '0', '0.25', '3'], 'RANK_STRICTLY_ASCENDING'),
    (['3', '1', '2', '4'], 'NOT_PROJECTED'),                   # unordered export rows
    (['1', '1', '2', '3'], 'NOT_PROJECTED'),                   # equal ranks
    (['1', '1.0', '2', '3'], 'NOT_PROJECTED'),
])
def test_order_is_rank_bound_never_position_alone(consumer, gr, root, native, labels, env, ranks, status):
    record = store(gr, root, labels, with_ranks(native, ranks))
    plan, _, _ = plan_of(consumer, root, record.manifest_sha256, env)
    assert plan['derived']['order'] == {'basis': 'native_rank', 'status': status}
    assert [o['native_rank'] for o in plan['derived']['occurrences']] == ranks
    assert plan['refusal'] == 'BRAVE_CNT_IMPORT_UNQUALIFIED'


def test_undecoded_content_is_not_derivable(consumer, gr, root, native, labels, env):
    value = copy.deepcopy(native)
    value['chunks'][1]['file']['background'] = 'not a data url'
    record = store(gr, root, labels, [dump(value)])
    occurrences = plan_of(consumer, root, record.manifest_sha256, env)[0]['derived']['occurrences']
    assert occurrences[1]['content_sha256'] is None and occurrences[1]['content'] == 'NOT_DERIVABLE'
    # Firefox-native-only bytes are digest-proven through the native parts, never neutrally materialized.
    assert all(o['content'] == 'NATIVE_PART_ONLY' and o['content_sha256'] for i, o in enumerate(occurrences) if i != 1)


def content_bytes(native, index=0):
    import base64
    url = native['chunks'][index]['file']['background']
    return base64.b64decode(url.split(',', 1)[1])


def test_shared_images_refs_are_verified_against_an_explicit_root(consumer, gr, root, native, labels, env,
                                                                  target, tmp_path):
    images = tmp_path / 'images'
    (images / 'walls').mkdir(parents=True)
    (images / 'walls/zero.png').write_bytes(content_bytes(native))
    record = store(gr, root, labels, [dump(native)], content_refs={0: {'kind': 'shared_images', 'path': 'walls/zero.png'}},
                   shared_images_root=images)
    digest = record.manifest_sha256
    plan, _, events = plan_of(consumer, root, digest, env, '--shared-images-root', str(images))
    assert plan['derived']['occurrences'][0]['content_ref_kind'] == 'shared_images'
    assert [o['content'] for o in plan['derived']['occurrences']] == ['DIGEST_BOUND'] + ['NATIVE_PART_ONLY'] * 3
    assert any(path == str(images) for _kind, path in events)
    base = ['--state-root', str(root), '--manifest', digest]
    for command in ('plan', 'brave-youtube'):
        refused(consumer, [command, *base], env, 'ROOT_REQUIRED', target)
    (images / 'walls/zero.png').write_bytes(b'edited')
    refused(consumer, ['plan', *base, '--shared-images-root', str(images)], env, 'CONTENT_DIGEST_MISMATCH', target)
    (images / 'walls/zero.png').unlink()
    refused(consumer, ['plan', *base, '--shared-images-root', str(images)], env, 'CONTENT_MISSING', target)
    (tmp_path / 'elsewhere.png').write_bytes(content_bytes(native))
    (images / 'walls/zero.png').symlink_to(tmp_path / 'elsewhere.png')
    refused(consumer, ['plan', *base, '--shared-images-root', str(images)], env, 'REF_SYMLINK', target)
    refused(consumer, ['plan', *base, '--shared-images-root', 'relative'], env, 'ROOT_INVALID', target)


def test_private_content_is_bound_to_the_state_root(consumer, gr, root, native, labels, env, target, tmp_path):
    raw = content_bytes(native)
    digest = hashlib.sha256(raw).hexdigest()
    refs = {0: {'kind': 'private', 'sha256': digest}}
    (root / 'content/sha256').mkdir(parents=True)
    (root / 'content/sha256' / digest).write_bytes(raw)
    record = store(gr, root, labels, [dump(native)], content_refs=refs, private_root=root)
    plan, _, _ = plan_of(consumer, root, record.manifest_sha256, env)
    assert plan['derived']['occurrences'][0]['content_ref_kind'] == 'private'
    assert plan['derived']['occurrences'][0]['content'] == 'DIGEST_BOUND'
    # Content captured against a different private root is not accepted from the state root.
    other_root, separate = tmp_path / 'other-state', tmp_path / 'separate'
    other_root.mkdir()
    (separate / 'content/sha256').mkdir(parents=True)
    (separate / 'content/sha256' / digest).write_bytes(raw)
    other = store(gr, other_root, labels, [dump(native)], content_refs=refs, private_root=separate)
    refused(consumer, ['plan', '--state-root', str(other_root), '--manifest', other.manifest_sha256], env,
            'CONTENT_MISSING', target)


# --- Fail-closed verification before any target access ----------------------------------------------

def _part_path(root, record, index=0):
    return root / 'native/sha256' / record.part_digests[index]


def _stored(root, digest):
    return root / 'content/sha256' / digest


def _crafted(gr, root, record, edit):
    """Store a manifest edited without validation; its parts are the record's verified parts."""
    manifest = record.manifest
    edit(manifest)
    raw = gr.ds.canonical_bytes(manifest)
    digest = hashlib.sha256(raw).hexdigest()
    _stored(root, digest).write_bytes(raw)
    return digest


def _set_ref(path):
    def edit(manifest):
        manifest['occurrences'][0]['content_ref'] = {'kind': 'shared_images', 'path': path}
    return edit


def _tamper_cases():
    def missing_root(root, tmp_path, gr, record):
        return str(tmp_path / 'absent'), record.manifest_sha256

    def symlinked_root(root, tmp_path, gr, record):
        (tmp_path / 'link').symlink_to(root)
        return str(tmp_path / 'link'), record.manifest_sha256

    def file_root(root, tmp_path, gr, record):
        (tmp_path / 'plain').write_bytes(b'')
        return str(tmp_path / 'plain'), record.manifest_sha256

    def manifest_missing(root, tmp_path, gr, record):
        return str(root), 'c' * 64

    def manifest_symlink(root, tmp_path, gr, record):
        stored = _stored(root, record.manifest_sha256)
        stored.rename(tmp_path / 'moved')
        stored.symlink_to(tmp_path / 'moved')
        return str(root), record.manifest_sha256

    def manifest_altered(root, tmp_path, gr, record):
        stored = _stored(root, record.manifest_sha256)
        stored.write_bytes(stored.read_bytes().replace(b'"revision":1', b'"revision":2'))
        return str(root), record.manifest_sha256

    def manifest_directory(root, tmp_path, gr, record):
        stored = _stored(root, record.manifest_sha256)
        stored.unlink()
        stored.mkdir()
        return str(root), record.manifest_sha256

    def part_missing(root, tmp_path, gr, record):
        _part_path(root, record).unlink()
        return str(root), record.manifest_sha256

    def part_size(root, tmp_path, gr, record):
        with _part_path(root, record).open('ab') as stream:
            stream.write(b' ')
        return str(root), record.manifest_sha256

    def part_digest(root, tmp_path, gr, record):
        path = _part_path(root, record)
        raw = bytearray(path.read_bytes())
        raw[-1] = ord(' ') if raw[-1] != ord(' ') else ord('\n')
        path.write_bytes(bytes(raw))
        return str(root), record.manifest_sha256

    def part_symlink(root, tmp_path, gr, record):
        path = _part_path(root, record)
        path.rename(tmp_path / 'part')
        path.symlink_to(tmp_path / 'part')
        return str(root), record.manifest_sha256

    def part_fifo(root, tmp_path, gr, record):
        path = _part_path(root, record)
        path.unlink()
        os.mkfifo(path)
        return str(root), record.manifest_sha256

    def parts_dir_symlink(root, tmp_path, gr, record):
        (root / 'native/sha256').rename(tmp_path / 'parts')
        (root / 'native/sha256').symlink_to(tmp_path / 'parts')
        return str(root), record.manifest_sha256

    def traversal_ref(root, tmp_path, gr, record):
        return str(root), _crafted(gr, root, record, _set_ref('walls/../../outside.png'))

    def absolute_ref(root, tmp_path, gr, record):
        return str(root), _crafted(gr, root, record, _set_ref('/outside.png'))

    def semantic_mismatch(root, tmp_path, gr, record):
        def edit(manifest):
            manifest['native_semantic_sha256'] = 'f' * 64
        return str(root), _crafted(gr, root, record, edit)

    def foreign_part_set(root, tmp_path, gr, record):
        def edit(manifest):
            manifest['native_artifacts'][0]['sha256'] = 'e' * 64
        return str(root), _crafted(gr, root, record, edit)

    def not_canonical(root, tmp_path, gr, record):
        raw = record.manifest_bytes + b' '
        digest = hashlib.sha256(raw).hexdigest()
        _stored(root, digest).write_bytes(raw)
        return str(root), digest

    return [
        (missing_root, 'ROOT_INVALID'), (symlinked_root, 'ROOT_INVALID'), (file_root, 'ROOT_INVALID'),
        (manifest_missing, 'STORED_MANIFEST_MISSING'), (manifest_symlink, 'STORED_MANIFEST_SYMLINK'),
        (manifest_altered, 'STORED_MANIFEST_DIGEST_MISMATCH'), (manifest_directory, 'STORED_MANIFEST_NOT_REGULAR'),
        (part_missing, 'NATIVE_PART_MISSING'), (part_size, 'NATIVE_PART_SIZE_MISMATCH'),
        (part_digest, 'NATIVE_PART_DIGEST_MISMATCH'), (part_symlink, 'NATIVE_PART_SYMLINK'),
        (part_fifo, 'NATIVE_PART_NOT_REGULAR'), (parts_dir_symlink, 'NATIVE_PART_SYMLINK'),
        (traversal_ref, 'REF_TRAVERSAL'), (absolute_ref, 'REF_ABSOLUTE'),
        (semantic_mismatch, 'ARTIFACT_MISMATCH'), (foreign_part_set, 'NATIVE_PART_MISSING'),
        (not_canonical, 'NOT_CANONICAL'),
    ]


@pytest.mark.parametrize('command', ['plan', 'brave-youtube'])
@pytest.mark.parametrize('case, code', _tamper_cases(), ids=lambda v: getattr(v, '__name__', v))
def test_invalid_durable_state_refuses_before_target_access(consumer, gr, root, native, labels, env, target,
                                                            tmp_path, command, case, code):
    record = store(gr, root, labels, [dump(native)])
    state_root, digest = case(root, tmp_path, gr, record)
    state_before = snapshot(state_root)
    refused(consumer, [command, '--state-root', state_root, '--manifest', digest], env, code, target)
    assert snapshot(state_root) == state_before


def test_selection_is_required_before_any_filesystem_access(consumer, env, target):
    for argv in (['brave-youtube'], ['plan'], ['brave-youtube', '--state-root', '/nonexistent/x']):
        events = refused(consumer, argv, env, 'MANIFEST_SELECTION_REQUIRED', target)
        assert events == []
    for bad in ('abc', 'A' * 64, 'g' * 64):
        assert refused(consumer, ['brave-youtube', '--manifest', bad], env, 'DIGEST_MALFORMED', target) == []


def test_relocation_and_overlap_refuse_before_any_filesystem_access(consumer, env, home, target, tmp_path):
    digest = 'c' * 64
    assert refused(consumer, ['brave-youtube', '--manifest', digest], dict(env, XDG_STATE_HOME=str(tmp_path / 'x')),
                   'STATE_ROOT_RELOCATION_UNBOUND', target) == []
    assert refused(consumer, ['brave-youtube', '--manifest', digest, '--state-root', str(target / 'Default')], env,
                   'ROOTS_OVERLAP', target) == []
    chrome = home / 'Library/Application Support/Google/Chrome/Default'
    assert refused(consumer, ['plan', '--manifest', digest, '--state-root', str(chrome)], env, 'ROOTS_OVERLAP',
                   target) == []
    firefox = home / 'Library/Application Support/Firefox/Profiles/x.default'
    assert refused(consumer, ['plan', '--manifest', digest, '--state-root', str(firefox)], env, 'ROOTS_OVERLAP',
                   target) == []
    assert refused(consumer, ['plan', '--manifest', digest, '--state-root', 'relative'], env, 'STATE_ROOT_INVALID',
                   target) == []
    assert refused(consumer, ['plan', '--manifest', digest], dict(env, BRAVE_YOUTUBE_USER_DATA_DIR='rel'),
                   'TARGET_INVALID', target) == []


@pytest.mark.parametrize('argv', [[], ['bogus'], ['status', '--bogus', 'x'], ['plan', '--manifest'],
                                  ['plan', '--manifest', 'a', '--manifest', 'b'], ['--manifest', 'a']])
def test_usage_errors(consumer, env, argv):
    code, out, err, events = run(consumer, argv, env)
    assert (code, out, err, events) == (2, '', 'clear-new-tab-sync: refused: USAGE\n', [])


# --- Engine/label boundaries --------------------------------------------------------------------------

def test_unsupported_labels_and_native_only_state(consumer, gr, root, native, labels, env, target):
    cases = (
        (CHROME_LABELS, [dump(native)], 'NATIVE_ONLY_UNCHARACTERIZED', 'CHROMIUM_NATIVE_UNCHARACTERIZED'),
        (dict(labels, browser_version='155.0.1'), [dump(native)], 'NATIVE_ONLY_UNCHARACTERIZED',
         'NATIVE_ONLY_NO_NEUTRAL_PROJECTION'),
        (dict(labels, extension_version='6.13.0'), [dump(native)], 'NATIVE_ONLY_UNCHARACTERIZED',
         'NATIVE_ONLY_NO_NEUTRAL_PROJECTION'),
        (labels, [b'opaque native bytes'], 'NATIVE_ONLY_UNPROJECTABLE', 'NATIVE_ONLY_NO_NEUTRAL_PROJECTION'),
        (labels, [dump(native)], 'PROJECTED_FIREFOX_6_12_1', 'BRAVE_CNT_IMPORT_UNQUALIFIED'),
    )
    for case_labels, parts, status, refusal in cases:
        record = store(gr, root, case_labels, parts)
        plan, out, _ = plan_of(consumer, root, record.manifest_sha256, env)
        assert plan['source']['projection_status'] == status and plan['refusal'] == refusal
        assert plan['native_parts_brave_portable'] is False
        assert (plan['derived'] is None) == (status != 'PROJECTED_FIREFOX_6_12_1')
        assert b'opaque native bytes'.decode() not in out
        refused(consumer, ['brave-youtube', '--state-root', str(root), '--manifest', record.manifest_sha256], env,
                refusal, target)


def test_firefox_native_parts_never_reach_the_target_or_output(consumer, gr, root, native, labels, env, target):
    record = store(gr, root, labels, [dump(native)])
    part = record.parts[0]
    _plan, out, _ = plan_of(consumer, root, record.manifest_sha256, env)
    assert part.decode() not in out and 'chunks' not in out
    refused(consumer, ['brave-youtube', '--state-root', str(root), '--manifest', record.manifest_sha256], env,
            'BRAVE_CNT_IMPORT_UNQUALIFIED', target)
    for entry in snapshot(target).values():
        assert entry[0] != 'file' or part not in entry[2]


# --- No legacy Chrome authority, fallback or access ----------------------------------------------------

@pytest.fixture
def chrome_profile(home):
    """A populated legacy normal Chrome profile at the historical default location."""
    profile = home / 'Library/Application Support/Google/Chrome/Default'
    for relative in (f'Extensions/{CHROME_ID}/9.9.9/manifest.json',
                     f'IndexedDB/chrome-extension_{CHROME_ID}_0.indexeddb.leveldb/000003.log',
                     f'IndexedDB/chrome-extension_{CHROME_ID}_0.indexeddb.blob/1/00/1',
                     f'Local Extension Settings/{CHROME_ID}/000003.log'):
        (profile / relative).parent.mkdir(parents=True, exist_ok=True)
        (profile / relative).write_bytes(b'LEGACY-CHROME-MARKER ' + relative.encode())
    return profile


def _no_chrome(events):
    for _kind, path in events:
        assert 'Google' not in path and 'Chrome' not in path and 'IndexedDB' not in path, path


def test_no_chrome_fallback_when_durable_state_is_absent(consumer, home, chrome_profile, tmp_path):
    target = home / 'Library/Application Support/Brave YouTube'
    (target / 'Default').mkdir(parents=True)
    (target / 'Default/Preferences').write_bytes(b'{}')
    environ = {'HOME': str(home), 'CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE': str(chrome_profile)}
    chrome_before, target_before = snapshot(chrome_profile), snapshot(target)
    for argv, code in ((['brave-youtube'], 'MANIFEST_SELECTION_REQUIRED'),
                       (['brave-youtube', '--manifest', 'c' * 64], 'ROOT_INVALID'),
                       (['plan', '--manifest', 'c' * 64], 'ROOT_INVALID')):
        _no_chrome(refused(consumer, argv, environ, code, target))
    status, out, err, events = run(consumer, ['status'], environ)
    assert status == 0 and err == '' and writes(events) == []
    _no_chrome(events)
    assert 'state_root_present: absent' in out and 'Chrome' not in out.replace('legacy_chrome', '')
    assert snapshot(chrome_profile) == chrome_before and snapshot(target) == target_before
    assert not (home / '.local').exists()
    for entry in snapshot(target).values():
        assert entry[0] != 'file' or b'LEGACY-CHROME-MARKER' not in entry[2]


def test_valid_durable_state_never_consults_chrome(consumer, gr, root, native, labels, home, chrome_profile,
                                                   target):
    record = store(gr, root, labels, [dump(native)])
    environ = {'HOME': str(home), 'BRAVE_YOUTUBE_USER_DATA_DIR': str(target),
               'CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE': str(chrome_profile)}
    chrome_before = snapshot(chrome_profile)
    _plan, out, events = plan_of(consumer, root, record.manifest_sha256, environ)
    _no_chrome(events)
    assert 'LEGACY-CHROME-MARKER' not in out
    _no_chrome(refused(consumer, ['brave-youtube', '--state-root', str(root), '--manifest', record.manifest_sha256],
                       environ, 'BRAVE_CNT_IMPORT_UNQUALIFIED', target))
    assert snapshot(chrome_profile) == chrome_before


# --- Read-only status -----------------------------------------------------------------------------------

def _status(consumer, argv, environ):
    code, out, err, events = run(consumer, ['status', *argv], environ)
    assert (code, err) == (0, '') and writes(events) == []
    return dict(line.split(': ', 1) for line in out.splitlines()), events


def test_status_is_read_only_and_reports_the_bounded_verdict(consumer, gr, root, native, labels, env, home,
                                                             target, tmp_path):
    record = store(gr, root, labels, [dump(native)])
    state_before, target_before = snapshot(root), snapshot(target)
    report, _ = _status(consumer, [], env)
    assert report == {
        'authority': 'browser-ux-durable-state', 'legacy_chrome_profile_authority': 'retired',
        'state_root': str(home / '.local/state/browser-ux/clear-new-tab'), 'state_root_source': 'default',
        'state_root_present': 'absent', 'backup_coverage': 'BACKUP_COVERAGE_NOT_CONFIRMED',
        'brave_youtube_target': str(target), 'manifest': 'unselected',
        'brave_youtube_consumer': 'REFUSED MANIFEST_SELECTION_REQUIRED', 'brave_extension_bundle': 'NOT_PROVISIONED'}
    report, events = _status(consumer, ['--state-root', str(root), '--manifest', record.manifest_sha256], env)
    assert (report['state_root_source'], report['state_root_present']) == ('explicit', 'directory')
    assert report['manifest'] == 'VERIFIED %s PROJECTED_FIREFOX_6_12_1' % record.manifest_sha256
    assert report['brave_youtube_consumer'] == 'REFUSED BRAVE_CNT_IMPORT_UNQUALIFIED'
    assert not any(str(target) in path for _kind, path in events)
    assert ('lstat', str(root)) in events and ('open', str(root)) in events
    report, _ = _status(consumer, ['--state-root', str(root), '--manifest', 'c' * 64], env)
    assert report['manifest'] == 'REFUSED STORED_MANIFEST_MISSING'
    (tmp_path / 'link').symlink_to(root)
    assert _status(consumer, ['--state-root', str(tmp_path / 'link')], env)[0]['state_root_present'] \
        == 'symlink-refused'
    report, _ = _status(consumer, [], dict(env, XDG_STATE_HOME=str(tmp_path / 'x')))
    assert report['state_root'] == 'REFUSED STATE_ROOT_RELOCATION_UNBOUND' and 'state_root_present' not in report
    assert snapshot(root) == state_before and snapshot(target) == target_before
    assert not (home / '.local').exists()


# --- Optimized-interpreter parity (live assertions) ------------------------------------------------
# pytest does not execute test-module assertions when the runner itself is started with python -O,
# so -O product evidence comes from here: the helper CLI runs under -O in a child process while
# this test's assertions stay live in the parent, and results must equal the in-process run.

def _optimized(repo_root, argv, environ):
    import subprocess
    result = subprocess.run([sys.executable, '-O', '-I', '-B', str(repo_root / HELPER), *argv],
                            env=dict(environ, PYTHONDONTWRITEBYTECODE='1'), capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_optimized_cli_matches_normal_in_process_results(consumer, gr, root, native, labels, env, target,
                                                         repo_root, tmp_path):
    import subprocess
    flags = subprocess.run([sys.executable, '-O', '-c', 'import sys; print(sys.flags.optimize)'],
                           capture_output=True, text=True, check=True).stdout.strip()
    assert flags == '1'
    good = store(gr, root, labels, [dump(native)]).manifest_sha256
    chrome = store(gr, root, CHROME_LABELS, [dump(native)]).manifest_sha256
    other = tmp_path / 'tampered'
    other.mkdir()
    tampered = store(gr, other, labels, [dump(native)])
    part = other / 'native/sha256' / tampered.part_digests[0]
    part.write_bytes(part.read_bytes()[:-1] + b' ')
    crafted = _crafted(gr, root, store(gr, root, labels, with_ranks(native, ['3', '1', '2', '4'])),
                       _set_ref('a/../b'))
    target_before, state_before = snapshot(target), snapshot(root)
    cases = [
        ['status'], ['status', '--state-root', str(root), '--manifest', good],
        ['plan', '--state-root', str(root), '--manifest', good],
        ['plan', '--state-root', str(root), '--manifest', chrome],
        ['brave-youtube', '--state-root', str(root), '--manifest', good],
        ['brave-youtube', '--state-root', str(root), '--manifest', chrome],
        ['brave-youtube', '--state-root', str(other), '--manifest', tampered.manifest_sha256],
        ['plan', '--state-root', str(root), '--manifest', crafted],
        ['brave-youtube'], ['brave-youtube', '--manifest', 'bad'], ['bogus'],
    ]
    seen = set()
    for argv in cases:
        normal = run(consumer, argv, env)[:3]
        assert _optimized(repo_root, argv, env) == normal, argv
        seen.add(normal[0])
    assert seen == {0, 2, 3}
    assert snapshot(target) == target_before and snapshot(root) == state_before


# --- Package, activation and ownership boundaries ---------------------------------------------------------

def test_exactly_ten_commands_and_the_helper_is_packaged_not_a_command(repo_root):
    assert len(list((repo_root / 'bin').iterdir())) == 10
    manifest = json.loads((repo_root / 'tests/fixtures/command-source-manifest.json').read_text())
    record = manifest[HELPER]
    assert record['adaptation'] == 'destination-origin' and record['source_sha256'] is None
    assert record['mode'] == '0o644'
    assert hashlib.sha256((repo_root / HELPER).read_bytes()).hexdigest() == record['destination_sha256']
    sync = manifest[SYNC]
    assert sync['adaptation'] == 'durable-authority-consumer'
    assert hashlib.sha256((repo_root / SYNC).read_bytes()).hexdigest() == sync['destination_sha256']
    assert sync['source_sha256'] != sync['destination_sha256']
    assert 'libexec/clear-new-tab/latest-source-extension-dir.py' not in manifest
    roster = json.loads((repo_root / 'tests/source-only-roster.json').read_text())
    assert {HELPER, 'tests/clear-new-tab-consumer.test.py',
            'docs/architecture/clear-new-tab-durable-authority.md'} <= set(roster)
    assert 'tests/clear-new-tab-consumer.test.py' in (repo_root / 'tests/command-checks.nix').read_text()


def test_no_activation_module_or_composition_reaches_the_consumer(repo_root):
    surfaces = [repo_root / 'flake.nix'] + [p for folder in ('modules', 'config', 'lib')
                                            for p in (repo_root / folder).rglob('*') if p.is_file()]
    for path in surfaces:
        raw = path.read_bytes()
        for token in (b'clear-new-tab-sync', b'brave-youtube-consumer', b'guarded_recovery', b'durable_state'):
            assert token not in raw, (path, token)
    for path in (repo_root / 'packages').rglob('*'):
        if path.is_file():
            assert b'brave-youtube-consumer' not in path.read_bytes(), path
    # The only automatic caller (the dormant core-identical session) passes no selection.
    session = (repo_root / 'bin/brave-youtube-session').read_text()
    body = session[session.index('sync_clear_new_tab() {'):]
    body = body[:body.index('\n}\n')]
    assert re.findall(r'"\$helper" [a-z][^\n]*', body) == ['"$helper" brave-youtube >/dev/null; then']
    assert '--manifest' not in session and '--state-root' not in session
    assert re.findall(r'^[ \t]+sync_clear_new_tab$', session, re.M) == ['  sync_clear_new_tab']
