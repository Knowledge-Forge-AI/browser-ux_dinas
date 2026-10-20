"""BUX5B0C durable-state foundation: portable, temporary-root-only tests.

No browser, profile, native import/export, Shared Images, cloud or operator root is
touched. The 6.12.1 fixture bytes were exported on Firefox 155.0.1 and are NOT accepted
156.0.1 evidence: under their own labels they stay native-only. Projection tests reuse
the same bytes under SYNTHETIC_LABELS purely as synthetic test vectors.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re

import pytest

LIBRARY = 'libexec/clear-new-tab/durable_state.py'
FIXTURE = Path('tests/fixtures/cnt-native/firefox/6.12.1')
D1, D2, D3, D4 = ('1' * 64, '2' * 64, '3' * 64, '4' * 64)


@pytest.fixture
def ds(load_module):
    return load_module(LIBRARY)


@pytest.fixture
def raw(repo_root):
    return (repo_root / FIXTURE / 'export.json').read_bytes()


@pytest.fixture
def native(raw):
    return json.loads(raw)


@pytest.fixture
def labels(ds):
    # Synthetic test vector labels: the fixture is not accepted 156.0.1 evidence.
    return dict(ds.PROJECTED_LABELS)


def dump(value, **kwargs):
    return json.dumps(value, **kwargs).encode()


def refuse(code, function, *args, **kwargs):
    """Every refusal is the bare code: no path, native text or chained cause."""
    with pytest.raises(Exception) as caught:
        function(*args, **kwargs)
    error = caught.value
    assert type(error).__name__ == 'DurableStateError', repr(error)
    assert str(error) == code and error.args == (code,)
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    return error


def fingerprint(ds, parts, labels, **kwargs):
    return ds.semantic_fingerprint(ds.build_manifest(parts, labels, **kwargs))


def decoded(native, row):
    return base64.b64decode(native['chunks'][row]['file']['background'].split(',', 1)[1])


# --- Purity, source discipline and bounded codes ----------------------------------------------

def test_library_source_discipline(repo_root):
    text = (repo_root / LIBRARY).read_text()
    assert not text.startswith('#!')
    for forbidden in ('environ', 'expanduser', 'Path.home', '/Users/', '/home/', 'assert ',
                      'subprocess', 'import cnt_', 'getenv'):
        assert forbidden not in text, forbidden
    assert not re.search(r'\bprint\(', text)
    assert (repo_root / LIBRARY).stat().st_mode & 0o111 == 0


def test_every_refusal_literal_is_bounded(ds, repo_root):
    tree = ast.parse((repo_root / LIBRARY).read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            args = {'_require': node.args[1:2], 'DurableStateError': node.args[:1]}.get(node.func.id, [])
            for arg in args:
                found |= {n.value for n in ast.walk(arg) if isinstance(n, ast.Constant)}
    assert found and found <= set(ds.REFUSAL_CODES)
    assert len(ds.REFUSAL_CODES) == len(set(ds.REFUSAL_CODES))


def test_canonical_root_is_pure_and_never_created(ds, tmp_path):
    root = ds.canonical_root(tmp_path)
    assert str(root) == str(tmp_path) + '/.local/state/browser-ux/clear-new-tab'
    assert not (tmp_path / '.local').exists()
    for bad in ('relative/home', '', '/a/../b', '/a//b', '/a/./b', '/a/', 'C:\\x', '/a\0b', 7):
        refuse('HOME_INVALID', ds.canonical_root, bad)
    assert list(tmp_path.iterdir()) == []


# --- Canonical serialization ------------------------------------------------------------------

def test_canonical_bytes_deterministic_and_typed(ds):
    a = {'b': [1, True, None, 'é'], 'a': {'z': 0, 'y': False}}
    b = {'a': {'y': False, 'z': 0}, 'b': [1, True, None, 'é']}
    assert ds.canonical_bytes(a) == ds.canonical_bytes(b) == \
        b'{"a":{"y":false,"z":0},"b":[1,true,null,"\\u00e9"]}'
    assert ds.canonical_bytes(True) != ds.canonical_bytes(1)
    for bad in (1.5, float('nan'), (1, 2), {1, 2}, {1: 'x'}, {1: 'x', 'a': 'y'}, b'x', 10 ** 5000,
                {'a': [10 ** 5000]}):
        refuse('CANONICAL_UNSUPPORTED_TYPE', ds.canonical_bytes, bad)


def test_parse_canonical_refusals(ds):
    assert ds.parse_canonical(b'{"a":1}') == {'a': 1}
    refuse('NOT_CANONICAL', ds.parse_canonical, b'{"a": 1}')
    refuse('NOT_CANONICAL', ds.parse_canonical, b'{"b":1,"a":2}')
    for bad in (b'{"a":1.5}', b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff', b'[', '{}'):
        refuse('UNPARSEABLE', ds.parse_canonical, bad)


def test_native_number_tokens_kept_exact(ds, native, labels):
    text = dump(native)
    assert text.count(b'"video_speed": 1,') == 1
    projections, fingerprints = {}, set()
    for token in ('1', '1.0', '1.5', '1.50', '1e0'):
        part = text.replace(b'"video_speed": 1,', b'"video_speed": ' + token.encode() + b',')
        manifest = ds.build_manifest([part], labels)
        projections[token] = manifest['projection']['settings']['video_speed']
        fingerprints.add(ds.semantic_fingerprint(manifest))
    assert projections['1'] == ['int', 1]
    assert projections['1.0'] == ['num', '1.0'] and projections['1.5'] == ['num', '1.5']
    assert len(fingerprints) == 5  # no float normalization: tokens never compare silently equal
    string = ds.build_manifest([text.replace(b'"video_speed": 1,', b'"video_speed": "1",')], labels)
    assert string['projection']['settings']['video_speed'] == ['str', '1']


# --- Manifest, occurrences and content identity -------------------------------------------------

def test_fixture_labels_are_not_accepted_evidence(ds, raw, repo_root):
    metadata = json.loads((repo_root / FIXTURE / 'metadata.json').read_text())
    assert metadata['browser_version'] == '155.0.1' and metadata['acceptance'] == 'NOT_CHARACTERIZED'
    own = {'engine': 'firefox', 'extension_id': metadata['extension_id'],
           'extension_version': metadata['version'], 'browser_version': metadata['browser_version']}
    manifest = ds.build_manifest([raw], own)
    assert manifest['projection_status'] == 'NATIVE_ONLY_UNCHARACTERIZED'
    assert manifest['projection'] is None and manifest['occurrences'] == []


def test_duplicate_content_stays_distinct_occurrences(ds, raw, native, labels, repo_root):
    manifest = ds.build_manifest([raw], labels)
    assert manifest['projection_status'] == 'PROJECTED_FIREFOX_6_12_1'
    occurrences = manifest['occurrences']
    metadata = json.loads((repo_root / FIXTURE / 'metadata.json').read_text())
    assert [o['content_sha256'] for o in occurrences] == metadata['content_sha256']
    assert occurrences[0]['content_sha256'] == occurrences[3]['content_sha256']
    assert occurrences[0]['native_id'] != occurrences[3]['native_id']
    assert [o['position'] for o in occurrences] == [0, 1, 2, 3]
    assert [o['native_id'] for o in occurrences] == [c['data']['id'] for c in native['chunks']]
    assert all(o['content_ref'] == {'kind': 'native_only'} for o in occurrences)
    assert hashlib.sha256(decoded(native, 0)).hexdigest() == occurrences[0]['content_sha256']


def test_ranks_preserved_without_densifying(ds, native, labels):
    chunks = native['chunks']
    for chunk, rank in zip(chunks, ('1', '3', '7.5', '-2')):
        chunk['data']['i'] = rank
    manifest = ds.build_manifest([dump(native)], labels)
    assert [o['native_rank'] for o in manifest['occurrences']] == ['1', '3', '7.5', '-2']
    bad = json.loads(ds.serialize_manifest(manifest))
    bad['occurrences'][1]['native_rank'] = '1e3'
    refuse('RANK_MALFORMED', ds.validate_manifest, bad)


def test_occurrence_identity_and_position_refusals(ds, raw, labels):
    base = json.loads(ds.serialize_manifest(ds.build_manifest([raw], labels)))
    dup = json.loads(json.dumps(base))
    dup['occurrences'][3]['native_id'] = dup['occurrences'][0]['native_id']
    refuse('OCCURRENCE_IDENTITY_DUPLICATE', ds.validate_manifest, dup)
    gap = json.loads(json.dumps(base))
    gap['occurrences'][2]['position'] = 5
    refuse('OCCURRENCE_INVALID', ds.validate_manifest, gap)
    swapped = json.loads(json.dumps(base))
    swapped['occurrences'][1]['content_sha256'] = swapped['occurrences'][2]['content_sha256']
    refuse('OCCURRENCE_PROJECTION_MISMATCH', ds.validate_manifest, swapped)


def test_native_duplicate_ids_are_unprojectable_not_equal(ds, native, labels):
    native['chunks'][1]['data']['id'] = native['chunks'][0]['data']['id']
    manifest = ds.build_manifest([dump(native)], labels)
    assert manifest['projection_status'] == 'NATIVE_ONLY_UNPROJECTABLE'
    assert manifest['occurrences'] == []


def test_manifest_schema_refusals(ds, raw, labels):
    manifest = ds.build_manifest([raw], labels)
    serialized = ds.serialize_manifest(manifest)
    assert ds.parse_manifest(serialized, [raw]) == manifest
    assert ds.serialize_manifest(ds.parse_manifest(serialized)) == serialized
    refuse('NOT_CANONICAL', ds.parse_manifest, json.dumps(manifest, indent=1).encode())
    for edit in (lambda m: m.update(schema='browser-ux-cnt-manifest-v2'), lambda m: m.update(extra=1),
                 lambda m: m.pop('labels'), lambda m: m.update(revision=0),
                 lambda m: m.update(projection_status='NATIVE_ONLY_UNCHARACTERIZED')):
        bad = json.loads(serialized)
        edit(bad)
        refuse('MANIFEST_INVALID', ds.validate_manifest, bad)
    unprojected = json.loads(serialized)
    unprojected['projection_status'] = 'NATIVE_ONLY_UNPROJECTABLE'
    refuse('PROJECTION_INVALID', ds.validate_manifest, unprojected)


def test_manifest_proves_derivation_from_native_bytes(ds, raw, native, labels):
    manifest = json.loads(ds.serialize_manifest(ds.build_manifest([raw], labels)))
    manifest['projection']['settings']['slideshow'] = ['bool', True]
    ds.validate_manifest(manifest)  # internally consistent ...
    refuse('PROJECTION_MISMATCH', ds.validate_manifest, manifest, [raw])  # ... but not derived
    native['settings']['prefs']['slideshow'] = True
    refuse('ARTIFACT_MISMATCH', ds.validate_manifest, ds.build_manifest([raw], labels), [dump(native)])
    refuse('ARTIFACT_MISMATCH', ds.validate_manifest, ds.build_manifest([raw], labels), [raw, raw])


def test_manifest_revision_chain(ds, raw, labels):
    first = ds.build_manifest([raw], labels)
    second = ds.build_manifest([raw], labels, revision=2, predecessor_sha256=ds.manifest_sha256(first))
    assert ds.semantic_fingerprint(first) == ds.semantic_fingerprint(second)
    refuse('MANIFEST_INVALID', ds.build_manifest, [raw], labels, revision=2)
    refuse('MANIFEST_INVALID', ds.build_manifest, [raw], labels, predecessor_sha256=D1)
    refuse('DIGEST_MALFORMED', ds.build_manifest, [raw], labels, revision=2, predecessor_sha256='x')


def test_labels_refusals(ds, raw, labels):
    for edit in ({'engine': 'brave'}, {'engine': 'chrome'}, {'extension_id': 'felphkbfjadmcejnibcmcncimlappdde'},
                 {'extension_version': '6.12.1-beta'}, {'extension_version': ''}, {'extension_version': '6..1'},
                 {'extension_version': 6121}, {'browser_version': '156'*3}, {'extra': 1}):
        refuse('LABELS_INVALID', ds.build_manifest, [raw], {**labels, **edit})
    refuse('LABELS_INVALID', ds.build_manifest, [raw], {k: v for k, v in labels.items() if k != 'browser_version'})
    refuse('LABELS_INVALID', ds.build_manifest, [raw], {**labels, 'engine': ['firefox']})
    refuse('LABELS_INVALID', ds.build_manifest, [raw], {**labels, 1: 'x'})
    refuse('MANIFEST_INVALID', ds.validate_manifest, {**ds.build_manifest([raw], labels), 1: 'x'})
    for parts in ([], [raw.decode()], (raw,) * 257):
        refuse('ARTIFACTS_INVALID', ds.build_manifest, list(parts), labels)


# --- Semantic fingerprint -----------------------------------------------------------------------

def variant(native, edit):
    value = json.loads(json.dumps(native))
    edit(value)
    return dump(value)


def with_task(value, **overrides):
    chunk = value['chunks'][0]
    chunk['tasks'] = [{'id': 'task-1', 'background_id': chunk['data']['id'], 'year': '', 'month': '',
                       'day_of_the_month': '', 'day_of_the_week': '', 'time': '08:00:00', 'i': '1',
                       **overrides}]


OTHER_PNG = base64.b64encode(b'\x89PNG\r\n\x1a\nsynthetic-edited').decode()
FINGERPRINT_CASES = {
    # name: (edit, same_fingerprint)
    'reserialized_sorted_indented': (None, True),
    'volatile_change_time': (lambda v: v['settings']['prefs'].update(background_change_time=1), True),
    'volatile_current_background': (lambda v: v['settings']['prefs'].update(current_background_id='x'), True),
    'volatile_future_background': (lambda v: v['settings']['prefs'].update(future_background_id='y'), True),
    'swap_rows': (lambda v: v['chunks'].insert(0, v['chunks'].pop(1)), False),
    'rank_change': (lambda v: v['chunks'][1]['data'].update(i='2.5'), False),
    'content_edit': (lambda v: v['chunks'][1]['file'].update(background='data:image/png;base64,' + OTHER_PNG), False),
    'represented_pref': (lambda v: v['settings']['prefs'].update(slideshow=True), False),
    'custom_code': (lambda v: v['custom_code'].update(css='p { color: red; }'), False),
    'task_added': (lambda v: with_task(v), False),
    'presentation': (lambda v: v['chunks'][2]['data'].update(background_size='contain'), False),
    'file_name': (lambda v: v['chunks'][2]['file'].update(name='renamed.png'), False),
    'unknown_top': (lambda v: v.update(x_bux_top=1), False),
    'unknown_background': (lambda v: v['chunks'][0]['data'].update(x_bux_data=1), False),
    'unknown_pref': (lambda v: v['settings']['prefs'].update(x_bux_pref=1), False),
    'unknown_unlisted_pref': (lambda v: v['settings']['prefs'].update(zz_future_pref=True), False),
    'unknown_custom_code': (lambda v: v['custom_code'].update(x_bux_code='x'), False),
    'unknown_row': (lambda v: v['chunks'][0].update(x_bux_row=[1, 2]), False),
}


@pytest.mark.parametrize('name', sorted(FINGERPRINT_CASES))
def test_fingerprint_cases(ds, raw, native, labels, name):
    edit, same = FINGERPRINT_CASES[name]
    changed = dump(native, sort_keys=True, indent=3) if edit is None else variant(native, edit)
    base, other = ds.build_manifest([raw], labels), ds.build_manifest([changed], labels)
    assert other['projection_status'] == 'PROJECTED_FIREFOX_6_12_1'
    assert other['native_artifacts'] != base['native_artifacts']
    assert (ds.semantic_fingerprint(base) == ds.semantic_fingerprint(other)) is same
    if name.startswith('unknown_'):
        # Not structurally represented: projection equal, native digest distinguishes.
        assert other['projection'] == base['projection']
        assert other['native_semantic_sha256'] != base['native_semantic_sha256']


def test_task_fields_are_represented(ds, native, labels):
    one = ds.build_manifest([variant(native, with_task)], labels)
    two = ds.build_manifest([variant(native, lambda v: with_task(v, time='09:00:00'))], labels)
    assert one['projection']['rows'][0]['tasks'][0]['time'] == ['str', '08:00:00']
    assert one['projection'] != two['projection']
    assert ds.semantic_fingerprint(one) != ds.semantic_fingerprint(two)
    unknown = ds.build_manifest([variant(native, lambda v: with_task(v, x_bux_task=1))], labels)
    assert unknown['projection'] == one['projection']
    assert ds.semantic_fingerprint(unknown) != ds.semantic_fingerprint(one)


def test_unknown_value_change_is_never_silently_equal(ds, native, labels):
    a = ds.build_manifest([variant(native, lambda v: v['chunks'][0]['data'].update(x_bux_data='a'))], labels)
    b = ds.build_manifest([variant(native, lambda v: v['chunks'][0]['data'].update(x_bux_data='b'))], labels)
    assert a['projection'] == b['projection']
    assert ds.semantic_fingerprint(a) != ds.semantic_fingerprint(b)


def test_volatile_download_filename_is_not_an_input(ds, repo_root, labels):
    metadata = json.loads((repo_root / FIXTURE / 'metadata.json').read_text())
    first = (repo_root / FIXTURE / 'export.json').read_bytes()
    second = (repo_root / FIXTURE / 'reexport.json').read_bytes()
    names = [metadata['native_artifacts'][k]['native_filename'] for k in ('export', 'reexport')]
    assert names[0] != names[1]
    one, two = ds.build_manifest([first], labels), ds.build_manifest([second], labels)
    assert ds.semantic_fingerprint(one) == ds.semantic_fingerprint(two)
    assert not any(name.encode() in ds.serialize_manifest(one) for name in names)


def test_path_relocation_preserves_identity(ds, raw, native, labels, tmp_path):
    shared = tmp_path / 'shared-images'
    content = decoded(native, 0)
    for relative in ('wallpapers/a/one.png', 'portraits/moved.png'):
        (shared / relative).parent.mkdir(parents=True)
        (shared / relative).write_bytes(content)
    manifests = [ds.build_manifest([raw], labels, content_refs={0: {'kind': 'shared_images', 'path': p}})
                 for p in ('wallpapers/a/one.png', 'portraits/moved.png')]
    for manifest in manifests:
        assert ds.verify_manifest_content(manifest, shared_images_root=shared)
    assert manifests[0]['occurrences'][0]['content_sha256'] == manifests[1]['occurrences'][0]['content_sha256']
    assert ds.semantic_fingerprint(manifests[0]) == ds.semantic_fingerprint(manifests[1])
    assert ds.semantic_fingerprint(manifests[0]) == fingerprint(ds, [raw], labels)
    (shared / 'portraits/moved.png').write_bytes(b'edited bytes')
    refuse('CONTENT_DIGEST_MISMATCH', ds.verify_manifest_content, manifests[1], shared_images_root=shared)
    refuse('ROOT_REQUIRED', ds.verify_manifest_content, manifests[0])


def test_private_content_refs_are_digest_addressed(ds, raw, native, labels, tmp_path):
    content = decoded(native, 1)
    digest = hashlib.sha256(content).hexdigest()
    assert ds.private_content_relpath(digest) == 'content/sha256/' + digest
    (tmp_path / 'content/sha256').mkdir(parents=True)
    (tmp_path / 'content/sha256' / digest).write_bytes(content)
    manifest = ds.build_manifest([raw], labels, content_refs={1: {'kind': 'private', 'sha256': digest}})
    assert ds.verify_manifest_content(manifest, private_root=tmp_path)
    refuse('CONTENT_REF_INVALID', ds.build_manifest, [raw], labels,
           content_refs={2: {'kind': 'private', 'sha256': digest}})
    refuse('ROOT_REQUIRED', ds.verify_manifest_content, manifest)
    refuse('CONTENT_MISSING', ds.verify_private_content, tmp_path, D1)
    refuse('DIGEST_MALFORMED', ds.private_content_relpath, '../' + digest)


def test_content_ref_kinds(ds, raw, labels):
    for ref in ({'kind': 'url', 'path': 'x'}, {'kind': 'native_only', 'path': 'x'},
                {'kind': 'shared_images'}, {'kind': 'private', 'sha256': D1}):
        refuse('CONTENT_REF_INVALID', ds.build_manifest, [raw], labels, content_refs={0: ref})
    refuse('REF_ABSOLUTE', ds.build_manifest, [raw], labels,
           content_refs={0: {'kind': 'shared_images', 'path': '/etc/hosts'}})
    refuse('OCCURRENCE_INVALID', ds.build_manifest, [raw], labels, content_refs={9: {'kind': 'native_only'}})


def test_undecodable_content_has_no_content_identity(ds, native, labels):
    parts = [variant(native, lambda v: v['chunks'][2]['file'].update(background='https://example.invalid/x'))]
    manifest = ds.build_manifest(parts, labels)
    assert manifest['occurrences'][2]['content_sha256'] is None
    assert manifest['projection']['rows'][2]['file']['content']['status'] == 'NOT_DATA_URL'
    refuse('CONTENT_REF_INVALID', ds.build_manifest, parts, labels,
           content_refs={2: {'kind': 'shared_images', 'path': 'x.png'}})
    broken = ds.build_manifest([variant(native, lambda v: v['chunks'][1]['file'].update(
        background='data:image/png;base64,@@not-base64@@'))], labels)
    assert broken['occurrences'][1]['content_sha256'] is None
    assert broken['projection']['rows'][1]['file']['content']['status'] == 'UNDECODABLE'
    absent = ds.build_manifest([variant(native, lambda v: v['chunks'][0]['file'].pop('background'))], labels)
    assert absent['occurrences'][0]['content_sha256'] is None
    assert absent['projection']['rows'][0]['file']['content'] == {'status': 'ABSENT'}


def test_uncharacterized_labels_fall_back_to_raw_digest(ds, raw, native, labels):
    chrome = {'engine': 'chrome', 'extension_id': 'felphkbfjadmcejnibcmcncimlappdde',
              'extension_version': '6.12.0', 'browser_version': None}
    for other in (chrome, dict(labels, extension_version='6.12.0'), dict(labels, browser_version='156.0.2'),
                  dict(labels, browser_version=None)):
        whitespace = dump(native, indent=5)
        one, two = ds.build_manifest([raw], other), ds.build_manifest([whitespace], other)
        assert one['projection_status'] == 'NATIVE_ONLY_UNCHARACTERIZED' and one['occurrences'] == []
        assert ds.semantic_fingerprint(one) != ds.semantic_fingerprint(two)
        assert ds.semantic_fingerprint(one) == ds.semantic_fingerprint(ds.build_manifest([raw], other))
    assert fingerprint(ds, [raw], labels) != fingerprint(ds, [raw], chrome)


@pytest.mark.parametrize('broken', [b'{', b'{"settings":{"prefs":{}},"custom_code":{},"chunks":[],"chunks":[]}',
                                    b'{"settings":{"prefs":{"a":NaN}},"custom_code":{},"chunks":[]}',
                                    b'{"custom_code":{},"chunks":[]}', b'[]'])
def test_unprojectable_supported_labels_stay_native_only(ds, labels, broken):
    manifest = ds.build_manifest([broken], labels)
    assert manifest['projection_status'] == 'NATIVE_ONLY_UNPROJECTABLE'
    assert manifest['native_semantic_sha256'] != ds.build_manifest([broken + b' '], labels)['native_semantic_sha256']


def test_multipart_order_is_semantic(ds, native, labels):
    first = dict(native, chunks=native['chunks'][:2])
    second = {'chunks': native['chunks'][2:]}
    parts = [dump(first), dump(second)]
    manifest = ds.build_manifest(parts, labels)
    assert [a['part_index'] for a in manifest['native_artifacts']] == [1, 2]
    assert len(manifest['occurrences']) == 4
    assert ds.build_manifest(parts[::-1], labels)['projection_status'] == 'NATIVE_ONLY_UNPROJECTABLE'
    assert ds.build_manifest([parts[1]], labels)['projection_status'] == 'NATIVE_ONLY_UNPROJECTABLE'


def test_parity_with_accepted_r6_view(ds, raw, native, labels, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_matrix as accepted
    for name in ('VOLATILE_PREFS', 'KNOWN_ROW', 'KNOWN_DATA', 'KNOWN_FILE', 'KNOWN_TASK', 'KNOWN_CODE', 'KNOWN_TOP'):
        assert getattr(ds, name) == getattr(accepted, name), name
    assert ds.BOUNDED.pattern == accepted.BOUNDED.pattern and ds.DATA_URL.pattern == accepted.DATA_URL.pattern
    assert set(ds.KNOWN_PREFS) | set(ds.VOLATILE_PREFS) == set(native['settings']['prefs'])
    base_view = accepted.semantic(accepted.fingerprint([raw]))
    base = fingerprint(ds, [raw], labels)
    cases = dict(FINGERPRINT_CASES, unknown_value_only=(
        lambda v: v['chunks'][0]['data'].update(x_bux_data='b'), False))
    reference = dump(json.loads(variant(native, lambda v: v['chunks'][0]['data'].update(x_bux_data='a'))))
    for name, (edit, _) in cases.items():
        changed = dump(native, sort_keys=True, indent=3) if edit is None else variant(native, edit)
        origin = reference if name == 'unknown_value_only' else raw
        accepted_same = accepted.semantic(accepted.fingerprint([changed])) == accepted.semantic(
            accepted.fingerprint([origin]))
        ours_same = fingerprint(ds, [changed], labels) == fingerprint(ds, [origin], labels)
        if name == 'unknown_value_only':
            assert accepted_same and not ours_same  # deliberately stricter than the accepted view
        else:
            assert accepted_same == ours_same, name
    assert base_view == accepted.semantic(accepted.fingerprint([raw])) and base


# --- References and root confinement ------------------------------------------------------------

@pytest.mark.parametrize('ref,code', [
    ('/abs/x.png', 'REF_ABSOLUTE'), ('../x.png', 'REF_TRAVERSAL'), ('a/../../x.png', 'REF_TRAVERSAL'),
    ('a/..', 'REF_TRAVERSAL'), ('', 'REF_NOT_NORMALIZED'), ('a//b', 'REF_NOT_NORMALIZED'),
    ('./a', 'REF_NOT_NORMALIZED'), ('a/./b', 'REF_NOT_NORMALIZED'), ('a/', 'REF_NOT_NORMALIZED'),
    ('a\\b', 'REF_NOT_NORMALIZED'), ('a\nb', 'REF_NOT_NORMALIZED'), ('a\0b', 'REF_NOT_NORMALIZED'),
    ('a' * 4097, 'REF_TOO_LONG'), (7, 'REF_NOT_NORMALIZED'), ('a/\ud800.png', 'REF_NOT_NORMALIZED')])
def test_relative_ref_lexical_refusals(ds, ref, code):
    refuse(code, ds.validate_relative_ref, ref)


def test_shared_images_symlink_and_root_refusals(ds, tmp_path):
    root, outside = tmp_path / 'root', tmp_path / 'outside'
    (root / 'dir').mkdir(parents=True)
    outside.mkdir()
    payload = b'synthetic image'
    digest = hashlib.sha256(payload).hexdigest()
    (outside / 'secret.png').write_bytes(payload)
    (root / 'dir/real.png').write_bytes(payload)
    (root / 'escape.png').symlink_to(outside / 'secret.png')
    (root / 'inside.png').symlink_to('dir/real.png')
    (root / 'linkdir').symlink_to(outside)
    (root / 'alias').symlink_to('dir')
    assert ds.verify_shared_images_ref(root, 'dir/real.png', digest)
    for ref in ('escape.png', 'inside.png', 'linkdir/secret.png', 'alias/real.png'):
        refuse('REF_SYMLINK', ds.verify_shared_images_ref, root, ref, digest)
    refuse('CONTENT_MISSING', ds.verify_shared_images_ref, root, 'dir/missing.png', digest)
    refuse('CONTENT_MISSING', ds.verify_shared_images_ref, root, 'dir', digest)
    refuse('CONTENT_DIGEST_MISMATCH', ds.verify_shared_images_ref, root, 'dir/real.png', D1)
    refuse('DIGEST_MALFORMED', ds.verify_shared_images_ref, root, 'dir/real.png', digest.upper())
    (tmp_path / 'rootlink').symlink_to(root)
    for bad_root in (tmp_path / 'rootlink', tmp_path / 'missing', 'relative/root', root / 'dir/real.png',
                     str(root) + '\0x', None, str(root) + '/\ud800'):
        refuse('ROOT_INVALID', ds.verify_shared_images_ref, bad_root, 'dir/real.png', digest)
    refuse('ROOT_INVALID', ds.atomic_write, str(tmp_path) + '/\udcff', 'x', b'x')


def test_surrogate_ref_from_canonical_manifest_is_bounded(ds, raw, labels, tmp_path):
    manifest = ds.build_manifest([raw], labels)
    edited = json.loads(ds.serialize_manifest(manifest))
    position = next(o['position'] for o in edited['occurrences'] if o['content_sha256'])
    edited['occurrences'][position]['content_ref'] = {'kind': 'shared_images', 'path': 'a/\ud800.png'}
    refuse('REF_NOT_NORMALIZED', ds.verify_manifest_content, edited, shared_images_root=tmp_path)
    reparsed = json.dumps(edited, sort_keys=True, separators=(',', ':')).encode()
    refuse('REF_NOT_NORMALIZED', ds.parse_manifest, reparsed)


def test_confined_read_hashes_in_chunks_and_refuses_swapped_objects(ds, tmp_path, monkeypatch):
    root = tmp_path / 'root'
    root.mkdir()
    payload = bytes(range(256)) * 41
    (root / 'video.webm').write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(ds, 'READ_CHUNK', 7)
    assert ds.verify_shared_images_ref(root, 'video.webm', digest)
    os.mkfifo(root / 'pipe')
    refuse('CONTENT_MISSING', ds.verify_shared_images_ref, root, 'pipe', digest)  # never blocks
    other = os.stat(tmp_path)
    monkeypatch.setattr(ds.os, 'fstat', lambda fd: other)  # opened object is not the lstat'd file
    refuse('CONTENT_MISSING', ds.verify_shared_images_ref, root, 'video.webm', digest)


# --- Recovery journal ---------------------------------------------------------------------------

def journal(ds, *, before=D1, requested=D2, basis='OPERATOR_EXPLICIT', before_state='PRESENT', labels=None):
    return ds.new_journal(journal_id='bux5b0c-test', labels=labels or dict(ds.PROJECTED_LABELS),
                          source_manifest_sha256=D3, source_artifact_sha256=[D4],
                          profile_token=D3, storage_token=D4, basis=basis, evidence_sha256=D3,
                          before_state=before_state, before_fingerprint=before,
                          requested_fingerprint=requested)


def advance(ds, start, path):
    current = start
    for status, kwargs in path:
        current = ds.transition(current, status, **kwargs)
    return current


DISPLACED = {'kind': 'private', 'sha256': D4}
HAPPY = [('STAGED', {'observed_fingerprint': D2}),
         ('PRESERVED', {'observed_fingerprint': D1, 'displaced_state': DISPLACED}),
         ('APPLYING', {'observed_fingerprint': D1})]
PATHS = {
    'PREPARED': [], 'STAGED': HAPPY[:1], 'PRESERVED': HAPPY[:2], 'APPLYING': HAPPY,
    'ROLLBACK_REQUIRED': HAPPY + [('ROLLBACK_REQUIRED', {'failure_code': 'VERIFICATION_MISMATCH',
                                                         'observed_fingerprint': D3})],
    'COMPLETED': HAPPY + [('COMPLETED', {'observed_fingerprint': D2})],
    'FAILED_BEFORE_MUTATION': [('FAILED_BEFORE_MUTATION', {'failure_code': 'OPERATOR_ABORT'})],
    'ROLLED_BACK': HAPPY + [('ROLLBACK_REQUIRED', {'failure_code': 'APPLY_FAILED'}),
                            ('ROLLED_BACK', {'observed_fingerprint': D1})],
    'ROLLBACK_FAILED': HAPPY + [('ROLLBACK_REQUIRED', {'failure_code': 'APPLY_FAILED'}),
                                ('ROLLBACK_FAILED', {'failure_code': 'ROLLBACK_MISMATCH',
                                                     'observed_fingerprint': D3})],
}


def plausible(ds, target):
    """Arguments that would satisfy target's preconditions if the pair were allowed."""
    kwargs = {'observed_fingerprint': D1 if target in ('PRESERVED', 'APPLYING', 'ROLLED_BACK') else D2}
    if target in ds.FAILURE_CODES:
        kwargs['failure_code'] = ds.FAILURE_CODES[target][-1]
    if target == 'PRESERVED':
        kwargs['displaced_state'] = DISPLACED
    return kwargs


def test_journal_paths_and_history(ds):
    start = journal(ds)
    for status, path in PATHS.items():
        result = advance(ds, start, path)
        assert result['status'] == status
        assert [e['status'] for e in result['history']] == ['PREPARED'] + [s for s, _ in path]
        assert ds.validate_journal(result) == result
        raw = ds.serialize_journal(result)
        assert ds.serialize_journal(ds.parse_journal(raw)) == raw
    rolled = advance(ds, start, PATHS['ROLLBACK_REQUIRED'])
    assert rolled['history'][-1]['observed_fingerprint'] == D3  # failed observation retained
    assert rolled['displaced_state'] == DISPLACED
    assert advance(ds, start, PATHS['STAGED'])['displaced_state'] is None


def test_journal_noop_is_the_only_path_for_matching_state(ds):
    same = journal(ds, before=D2, requested=D2)
    assert ds.transition(same, 'NOOP_COMPLETED', observed_fingerprint=D2)['status'] == 'NOOP_COMPLETED'
    refuse('JOURNAL_PRECONDITION_FAILED', ds.transition, same, 'STAGED', observed_fingerprint=D2)
    refuse('JOURNAL_PRECONDITION_FAILED', ds.transition, journal(ds), 'NOOP_COMPLETED', observed_fingerprint=D2)


@pytest.mark.parametrize('source', sorted(PATHS))
@pytest.mark.parametrize('target', ['PREPARED', 'STAGED', 'PRESERVED', 'APPLYING', 'ROLLBACK_REQUIRED',
                                    'COMPLETED', 'NOOP_COMPLETED', 'FAILED_BEFORE_MUTATION', 'ROLLED_BACK',
                                    'ROLLBACK_FAILED'])
def test_journal_transition_matrix(ds, source, target):
    current = advance(ds, journal(ds), PATHS[source])
    snapshot = ds.serialize_journal(current)
    if source in ds.TERMINAL_STATES:
        refuse('JOURNAL_TERMINAL', ds.transition, current, target, **plausible(ds, target))
    elif (source, target) not in ds.TRANSITIONS:
        refuse('JOURNAL_TRANSITION_INVALID', ds.transition, current, target, **plausible(ds, target))
    elif target == 'NOOP_COMPLETED':
        refuse('JOURNAL_PRECONDITION_FAILED', ds.transition, current, target, **plausible(ds, target))
    else:
        assert ds.transition(current, target, **plausible(ds, target))['status'] == target
    assert ds.serialize_journal(current) == snapshot  # input never mutated


def test_journal_preconditions(ds):
    start = journal(ds)
    staged = advance(ds, start, PATHS['STAGED'])
    preserved = advance(ds, start, PATHS['PRESERVED'])
    applying = advance(ds, start, PATHS['APPLYING'])
    rollback = advance(ds, start, PATHS['ROLLBACK_REQUIRED'])
    cases = [
        (start, 'STAGED', {'observed_fingerprint': D3}),                       # staged import mismatch
        (staged, 'PRESERVED', {'observed_fingerprint': D1}),                   # no displaced ref
        (staged, 'PRESERVED', {'observed_fingerprint': D3, 'displaced_state': DISPLACED}),
        (preserved, 'APPLYING', {'observed_fingerprint': D3}),                 # concurrent change
        (preserved, 'APPLYING', {}),                                           # no live re-check
        (applying, 'COMPLETED', {'observed_fingerprint': D3}),                 # verification mismatch
        (applying, 'ROLLBACK_REQUIRED', {}),                                   # no failure code
        (applying, 'ROLLBACK_REQUIRED', {'failure_code': 'OPERATOR_ABORT'}),   # not allowlisted here
        (rollback, 'ROLLED_BACK', {'observed_fingerprint': D2}),
        (start, 'FAILED_BEFORE_MUTATION', {'failure_code': 'Traceback: /private/x'}),
        (start, 'STAGED', {'observed_fingerprint': D2, 'failure_code': 'INTERRUPTED'}),
        (start, 'STAGED', {'observed_fingerprint': D2, 'displaced_state': DISPLACED}),
    ]
    for current, status, kwargs in cases:
        refuse('JOURNAL_PRECONDITION_FAILED', ds.transition, current, status, **kwargs)
    concurrent = ds.transition(preserved, 'FAILED_BEFORE_MUTATION', failure_code='CONCURRENT_CHANGE',
                               observed_fingerprint=D3)
    assert concurrent['history'][-1] == {'seq': 3, 'status': 'FAILED_BEFORE_MUTATION',
                                         'observed_fingerprint': D3, 'failure_code': 'CONCURRENT_CHANGE'}


def test_journal_authorization_and_identity(ds):
    refuse('JOURNAL_PRECONDITION_FAILED', journal, ds, basis='POSITIVE_VERSIONED_RESET_EVIDENCE')
    assert journal(ds, basis='POSITIVE_VERSIONED_RESET_EVIDENCE', before_state='RESET_EVIDENCED')
    for basis in ('ELAPSED_TIME', 'PRIOR_ACTIVATION', None):
        refuse('JOURNAL_INVALID', journal, ds, basis=basis)
    refuse('JOURNAL_INVALID', journal, ds, before_state='EMPTY_DIRECTORY')
    refuse('JOURNAL_INVALID', journal, ds, labels={'engine': 'firefox'})
    for artifacts in (None, 123, []):
        refuse('JOURNAL_INVALID', ds.new_journal, journal_id='x', labels=dict(ds.PROJECTED_LABELS),
               source_manifest_sha256=D3, source_artifact_sha256=artifacts, profile_token=D3,
               storage_token=D4, basis='OPERATOR_EXPLICIT', evidence_sha256=D3, before_state='PRESENT',
               before_fingerprint=D1, requested_fingerprint=D2)
    displaced = dict(DISPLACED)
    preserved = ds.transition(advance(ds, journal(ds), PATHS['STAGED']), 'PRESERVED',
                              observed_fingerprint=D1, displaced_state=displaced)
    displaced['sha256'] = D2  # caller mutation after the call never reaches the journal
    assert preserved['displaced_state'] == DISPLACED
    refuse('DIGEST_MALFORMED', ds.new_journal, journal_id='x', labels=dict(ds.PROJECTED_LABELS),
           source_manifest_sha256=D3, source_artifact_sha256=[D4], profile_token='/private/profile',
           storage_token=D4, basis='OPERATOR_EXPLICIT', evidence_sha256=D3, before_state='PRESENT',
           before_fingerprint=D1, requested_fingerprint=D2)
    refuse('JOURNAL_INVALID', ds.new_journal, journal_id='Has Space', labels=dict(ds.PROJECTED_LABELS),
           source_manifest_sha256=D3, source_artifact_sha256=[D4], profile_token=D3,
           storage_token=D4, basis='OPERATOR_EXPLICIT', evidence_sha256=D3, before_state='PRESENT',
           before_fingerprint=D1, requested_fingerprint=D2)


def test_journal_tampering_refused_by_replay(ds):
    completed = json.loads(ds.serialize_journal(advance(ds, journal(ds), PATHS['COMPLETED'])))
    skipped = json.loads(json.dumps(completed))
    del skipped['history'][2]
    for seq, entry in enumerate(skipped['history']):
        entry['seq'] = seq
    refuse('JOURNAL_TRANSITION_INVALID', ds.validate_journal, skipped)
    status = dict(completed, status='APPLYING')
    refuse('JOURNAL_INVALID', ds.validate_journal, status)
    unpreserved = json.loads(ds.serialize_journal(advance(ds, journal(ds), PATHS['STAGED'])))
    unpreserved['displaced_state'] = DISPLACED
    refuse('JOURNAL_INVALID', ds.validate_journal, unpreserved)
    observed = json.loads(json.dumps(completed))
    observed['history'][-1]['observed_fingerprint'] = D3
    refuse('JOURNAL_PRECONDITION_FAILED', ds.validate_journal, observed)
    refuse('NOT_CANONICAL', ds.parse_journal, json.dumps(completed).encode())


# --- Atomic writes ------------------------------------------------------------------------------

def test_atomic_write_confined_and_durable(ds, tmp_path, monkeypatch):
    root, sibling = tmp_path / 'state', tmp_path / 'sibling'
    root.mkdir()
    sibling.mkdir()
    (sibling / 'keep').write_bytes(b'unchanged')
    flushed = []
    real = ds._flush
    monkeypatch.setattr(ds, '_flush', lambda fd: (flushed.append(fd), real(fd)))
    assert ds.atomic_write(root, 'recovery/journal.json', b'one')
    assert ds.atomic_write(root, 'recovery/journal.json', b'two')
    target = root / 'recovery/journal.json'
    assert target.read_bytes() == b'two' and target.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in (root / 'recovery').iterdir()) == ['journal.json']
    assert len(flushed) >= 4
    assert (sibling / 'keep').read_bytes() == b'unchanged'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['sibling', 'state']


def test_atomic_write_flush_prefers_full_fsync_and_falls_back(ds, tmp_path, monkeypatch):
    root = tmp_path / 'state'
    root.mkdir()
    full = getattr(ds.fcntl, 'F_FULLFSYNC', None)
    calls, synced = [], []
    real_fsync = ds.os.fsync
    monkeypatch.setattr(ds.os, 'fsync', lambda fd: (synced.append(fd), real_fsync(fd)))
    def unsupported(fd, command, *args):
        calls.append(command)
        raise OSError('unsupported at ' + str(tmp_path))
    monkeypatch.setattr(ds.fcntl, 'fcntl', unsupported)
    assert ds.atomic_write(root, 'a/journal.json', b'one')
    assert (root / 'a/journal.json').read_bytes() == b'one'
    if full is None:
        assert calls == [] and len(synced) >= 3
    else:
        assert calls and set(calls) == {full} and len(synced) == len(calls)


def test_atomic_write_refusals(ds, tmp_path):
    root, outside = tmp_path / 'state', tmp_path / 'outside'
    root.mkdir()
    outside.mkdir()
    (outside / 'victim').write_bytes(b'victim')
    (root / 'linkdir').symlink_to(outside)
    (root / 'link.json').symlink_to(outside / 'victim')
    (root / 'directory').mkdir()
    (tmp_path / 'rootlink').symlink_to(root)
    refuse('ROOT_INVALID', ds.atomic_write, tmp_path / 'missing', 'x', b'x')
    assert not (tmp_path / 'missing').exists()
    refuse('ROOT_INVALID', ds.atomic_write, tmp_path / 'rootlink', 'x', b'x')
    refuse('ROOT_INVALID', ds.atomic_write, 'relative', 'x', b'x')
    refuse('REF_SYMLINK', ds.atomic_write, root, 'linkdir/new', b'x')
    refuse('WRITE_TARGET_INVALID', ds.atomic_write, root, 'link.json', b'x')
    refuse('WRITE_TARGET_INVALID', ds.atomic_write, root, 'directory', b'x')
    refuse('REF_TRAVERSAL', ds.atomic_write, root, '../outside/victim', b'x')
    refuse('REF_ABSOLUTE', ds.atomic_write, root, str(outside / 'victim'), b'x')
    refuse('WRITE_FAILED', ds.atomic_write, root, 'x', 'text')
    assert (outside / 'victim').read_bytes() == b'victim'
    assert sorted(p.name for p in outside.iterdir()) == ['victim']


def test_atomic_write_failure_leaves_no_temporary(ds, tmp_path, monkeypatch):
    root = tmp_path / 'state'
    root.mkdir()
    ds.atomic_write(root, 'manifest.json', b'original')
    def broken(*args, **kwargs):
        raise OSError('disk full at ' + str(tmp_path))
    monkeypatch.setattr(ds.os, 'replace', broken)
    error = refuse('WRITE_FAILED', ds.atomic_write, root, 'manifest.json', b'new')
    assert str(tmp_path) not in repr(error)
    assert (root / 'manifest.json').read_bytes() == b'original'
    assert sorted(p.name for p in root.iterdir()) == ['manifest.json']


def test_manifest_round_trip_through_atomic_write(ds, raw, labels, tmp_path):
    manifest = ds.build_manifest([raw], labels)
    ds.atomic_write(tmp_path, 'manifest.json', ds.serialize_manifest(manifest))
    assert ds.parse_manifest((tmp_path / 'manifest.json').read_bytes(), [raw]) == manifest


# --- Source bookkeeping -------------------------------------------------------------------------

def test_source_bookkeeping(repo_root):
    roster = json.loads((repo_root / 'tests/source-only-roster.json').read_text())
    for path in (LIBRARY, 'tests/clear-new-tab-durable-state.test.py',
                 'docs/architecture/clear-new-tab-durable-authority.md'):
        assert path in roster and (repo_root / path).is_file(), path
    assert 'tests/clear-new-tab-durable-state.test.py' in (repo_root / 'tests/command-checks.nix').read_text()
    manifest = json.loads((repo_root / 'tests/fixtures/command-source-manifest.json').read_text())
    record = manifest[LIBRARY]
    assert record['adaptation'] == 'destination-origin' and record['source_sha256'] is None
    assert record['mode'] == '0o644'
    assert hashlib.sha256((repo_root / LIBRARY).read_bytes()).hexdigest() == record['destination_sha256']
