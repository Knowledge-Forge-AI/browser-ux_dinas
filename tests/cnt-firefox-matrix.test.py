"""R6 Firefox matrix portable core: synthetic bytes and the accepted small fixtures only.

No browser, process, socket, Nix or captured-XPI execution. The retained capture is never
read here; capture verification is exercised with synthetic archives.
"""
import base64
import hashlib
import io
import json
from pathlib import Path
import random
import zipfile

import pytest

FIXTURE = Path(__file__).resolve().parent / 'fixtures/cnt-native/firefox/6.12.1'


@pytest.fixture
def m(monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_matrix
    return cnt_firefox_matrix


@pytest.fixture
def export():
    return (FIXTURE / 'export.json').read_bytes()


def with_tasks(raw):
    """Test-only derivative of the accepted export with two synthetic tasks (for mutation tests)."""
    value = json.loads(raw)
    for n, chunk in enumerate(value['chunks'][:2]):
        chunk['tasks'] = [{'id': f'task{n}', 'i': str(n + 1), 'background_id': chunk['data']['id'],
                           'year': '2031', 'day_of_the_week': '', 'month': '', 'day_of_the_month': '',
                           'time': '12:34:56'}]
    return json.dumps(value, separators=(',', ':')).encode()


def native_parts(raw, groups, threshold_header=True):
    """Test-only: regroup the accepted export's chunk bytes into the verified native template."""
    root = json.loads(raw)
    header = raw[:raw.index(b'"chunks":[') + len(b'"chunks":[')]
    chunks = [json.dumps(c, separators=(',', ':')).encode() for c in root['chunks']]
    parts = []
    for n, group in enumerate(groups):
        head = header if n == 0 else b'{"chunks":['
        parts.append(head + b','.join(chunks[i] for i in group) + b']}')
    return parts


# --- provenance binding ----------------------------------------------------------------------

def test_harness_constants_equal_static_provenance(m):
    p = m.load_provenance()
    capture = p['capture']
    assert (capture['xpi_sha256'], capture['extension_id'], capture['version'], capture['manifest_version']) == (
        m.XPI_SHA256, m.EXTENSION_ID, m.EXTENSION_VERSION, m.MANIFEST_VERSION)
    assert m.provenance_value(p, 'backup.threshold_default') == m.THRESHOLD_DEFAULT
    assert m.provenance_value(p, 'backup.threshold_ui_range') == [m.THRESHOLD_MIN, m.THRESHOLD_MAX]
    metadata = json.loads((FIXTURE / 'metadata.json').read_text())
    assert metadata['package_sha256'] == m.XPI_SHA256 and len(metadata['native_member_sha256']) == 21


def test_provenance_records_statuses_offsets_and_no_code(m):
    p = m.load_provenance()
    assert 'Gemini' in p['method']['worker_disclosure'] and 'Parent' in p['method']['binding_authority']
    for key, fact in p['facts'].items():
        assert fact['status'] in ('VERIFIED', 'CORRECTED', 'UNVERIFIED'), key
        assert type(fact['offset']) is int and fact['offset'] >= 0 and fact['member'].endswith('.mjs'), key
        text = json.dumps(fact['value'])
        assert '=>' not in text and 'function(' not in text and len(text) < 600, key
    # The partition and apply_unchanged_prefs readings were corrected, not taken from workers.
    assert p['facts']['backup.partition']['status'] == 'CORRECTED'
    assert p['facts']['schema.unknown_prefs']['status'] == 'UNVERIFIED'


def test_every_step_fact_and_selector_is_bound(m, monkeypatch, repo_root):
    import cnt_firefox_matrix_session as session
    p = m.load_provenance()
    for group, keys in session.STEP_FACTS.items():
        for key in keys:
            assert m.fact_status(p, key) in ('VERIFIED', 'CORRECTED'), (group, key)
    source = Path(session.__file__).read_text()
    used = set(__import__('re').findall(r"selectors\['([a-z_]+)'\]", source))
    assert used and used <= set(p['selectors'])
    # Literal select names driven outside the rich-pref plan must be bound to a verified fact.
    literal = set(__import__('re').findall(r"self\.select\('([a-z_]+)'", source))
    assert literal == {'mode', 'day_of_the_month'}
    # The context switch is an option click on the verified settings_context select.
    assert 'select[name="settings_context"] option[value="global"]' in source
    assert 'ui.settings_context' in session.STEP_FACTS['rich'] and 'mode' in [n for _, n, _ in p['rich_prefs']]
    assert 'day_of_the_month' in m.provenance_value(p, 'ui.scheduler')
    assert 'select[name=settings_context]' in m.provenance_value(p, 'ui.settings_context')
    js = (repo_root / 'tests/cnt_firefox_matrix_page.js').read_text()
    for key in ('ready', 'hidden_roots', 'loading_root', 'error_root', 'protecting', 'background',
                'section', 'task'):
        assert 's.' + key in js and key in p['selectors']


def test_rich_prefs_are_verified_non_defaults(m):
    p = m.load_provenance()
    defaults = m.provenance_value(p, 'defaults.prefs')
    names = [name for _, name, _ in p['rich_prefs']]
    assert names.index('mode') < names.index('slideshow')  # visibility order
    for _, name, value in p['rich_prefs']:
        assert defaults[name] != value, name
        assert name not in p['not_driven']
    for gated in m.provenance_value(p, 'gating.optional_permissions'):
        assert gated not in names and gated in p['not_driven']


# --- capture verification (synthetic archives) --------------------------------------------------

def archive(members, manifest=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('manifest.json', json.dumps(manifest or {
            'manifest_version': 3, 'version': '6.12.1',
            'browser_specific_settings': {'gecko': {'id': 'clear-new-tab@loftyshaky'}}}))
        for name, data in members.items():
            z.writestr(name, data)
    return stream.getvalue()


@pytest.fixture
def capture(m, tmp_path, monkeypatch):
    def make(raw, digests=None):
        path = tmp_path / 'capture.xpi'
        path.write_bytes(raw)
        meta = tmp_path / 'metadata.json'
        meta.write_text(json.dumps({'native_member_sha256': digests if digests is not None else {
            'a.mjs': hashlib.sha256(b'native').hexdigest()}}))
        monkeypatch.setattr(m, 'XPI_SHA256', hashlib.sha256(raw).hexdigest())
        return path, meta
    return make


def test_capture_identity_verified(m, capture):
    path, meta = capture(archive({'a.mjs': b'native'}))
    identity = m.verify_capture(path, expected_sha256=m.XPI_SHA256, metadata_path=meta)
    assert identity['verified_member_digests'] == 1 and identity['extension_id'] == m.EXTENSION_ID


@pytest.mark.parametrize('damage', ['digest', 'expected', 'member-digest', 'manifest', 'traversal', 'missing'])
def test_capture_refusals(m, capture, damage):
    raw = archive({'a.mjs': b'native', **({'../escape': b'x'} if damage == 'traversal' else {})},
                  manifest={'manifest_version': 3, 'version': '6.12.0',
                            'browser_specific_settings': {'gecko': {'id': 'clear-new-tab@loftyshaky'}}}
                  if damage == 'manifest' else None)
    digests = {'a.mjs': '0' * 64} if damage == 'member-digest' else (
        {'absent.mjs': '0' * 64} if damage == 'missing' else None)
    path, meta = capture(raw, digests)
    expected = m.XPI_SHA256
    if damage == 'digest':
        path.write_bytes(raw + b'\0')
    if damage == 'expected':
        expected = '1' * 64
    message = {'digest': 'Capture digest mismatch', 'expected': 'Capture digest mismatch',
               'member-digest': 'Capture member digest mismatch', 'missing': 'Capture member digest mismatch',
               'manifest': 'Capture manifest identity mismatch', 'traversal': 'Capture member unsafe'}[damage]
    with pytest.raises(m.VerificationError, match=message):
        m.verify_capture(path, expected_sha256=expected, metadata_path=meta)
    assert m.MATRIX_CODES[message]


def test_capture_link_and_default_pin_refused(m, capture, tmp_path):
    path, meta = capture(archive({'a.mjs': b'native'}))
    link = tmp_path / 'link.xpi'
    link.symlink_to(path)
    with pytest.raises(m.VerificationError, match='Capture absent or not a regular file'):
        m.verify_capture(link, expected_sha256=m.XPI_SHA256, metadata_path=meta)
    # The pinned constant, not the caller, decides: a caller digest equal to the file but not the pin refuses.
    raw = path.read_bytes()
    m.XPI_SHA256 = 'f' * 64
    with pytest.raises(m.VerificationError, match='Capture digest mismatch'):
        m.verify_capture(path, expected_sha256=hashlib.sha256(raw).hexdigest(), metadata_path=meta)


# --- byte-span locator and partition ---------------------------------------------------------------

def test_layout_of_accepted_export(m, export):
    layout = m.part_layout(export)
    assert layout['native_template'] and layout['settings_header']
    assert len(layout['chunk_core_bytes']) == 4 and layout['footer_bytes'] == 2
    assert layout['header_bytes'] + sum(layout['chunk_core_bytes']) + 3 + 2 == len(export)


def test_partition_simulation_matches_verified_loop(m):
    # All fit: one part.
    assert m.simulate_partition([10, 10, 10], 100, 10**6)['parts'] == [[0, 1, 2]]
    # Double counting: b=20 then 20+20+100+2 >= 140 splits on the second chunk.
    sim = m.simulate_partition([10, 20, 10], 100, 140)
    assert sim['parts'] == [[0], [1, 2]] and all(sim['well_formed'])
    # The last chunk is always appended, even past the threshold.
    assert m.simulate_partition([10, 10, 500], 100, 200)['parts'][-1][-1] == 2
    # A first-chunk split emits an empty Part 1 and predicts a missing separator.
    first = m.simulate_partition([500, 10, 10], 100, 200)
    assert first['parts'][0] == [] and first['empty_parts'] == 1 and False in first['well_formed']
    assert m.simulate_partition([], 100, 200) == {'parts': [[]], 'well_formed': [True], 'empty_parts': 1}


def test_flip_threshold_is_the_exact_boundary(m):
    rng = random.Random(6)
    for _ in range(200):
        cores = [rng.randint(1, 5000) for _ in range(rng.randint(2, 8))]
        header = rng.randint(50, 3000)
        t = m.flip_threshold(cores, header)
        assert len(m.simulate_partition(cores, header, t)['parts']) >= 2
        assert len(m.simulate_partition(cores, header, t + 1)['parts']) == 1


def test_boundary_prediction_uses_calibration_bytes_and_digit_adjustment(m, export):
    prediction = m.boundary_prediction(export)
    layout = m.part_layout(export)
    assert prediction['threshold'] == m.flip_threshold(layout['chunk_core_bytes'], prediction['header_adjusted_bytes'])
    assert prediction['in_ui_range'] is False  # the tiny accepted export cannot reach 50 MiB
    assert m.header_at(1000, 419430400, 52428800) == 999
    assert m.classify_boundary(prediction, 2, 1) == 'BOUNDARY_NOT_SETTABLE'
    ok = dict(prediction, in_ui_range=True)
    header = ok['header_adjusted_bytes']
    assert m.classify_boundary(ok, 2, 1, header) == 'EXACT_BOUNDARY_OBSERVED'
    assert m.classify_boundary(ok, 1, 1, header) == 'BOUNDARY_SHIFTED'
    assert m.classify_boundary(ok, None, 1, header) == 'INCOMPLETE_EVIDENCE'
    # The at-T export's own header decides whether the digit-only premise held.
    assert m.classify_boundary(ok, 1, 1, header + 3) == 'PREDICTION_HEADER_DRIFT'
    assert m.classify_boundary(ok, 2, 1, None) == 'INCOMPLETE_EVIDENCE'


def test_partition_consistency_against_observed_grouping(m, export):
    layout = m.part_layout(export)
    cores, header = layout['chunk_core_bytes'], layout['header_bytes']
    threshold = m.flip_threshold(cores, header)
    expected = m.simulate_partition(cores, header, threshold)['parts']
    parts = native_parts(export, expected)
    assert m.partition_consistency(parts, threshold)['status'] == 'CONSISTENT'
    assert m.partition_consistency(native_parts(export, [[0, 1, 2, 3]]), threshold)['status'] == 'INCONSISTENT'
    assert m.partition_consistency([parts[0][:-5]] + parts[1:], threshold)['status'] == 'NOT_NATIVE_TEMPLATE'


def test_part_selection_order_missing_duplicate_and_rename(m):
    parts = [b'1', b'2', b'3']
    pick = lambda kind: [(n, raw, number, slot) for n, raw, number, slot in m.select_parts(parts, kind)]
    assert [x[0] for x in pick('ordered')] == [1, 2, 3]
    assert [x[0] for x in pick('reversed')] == [3, 2, 1]
    assert [x[0] for x in pick('no_part_1')] == [2, 3]
    assert [x[0] for x in pick('no_middle')] == [1, 3]
    dup = pick('duplicate_middle')
    assert [(x[0], x[3]) for x in dup] == [(1, 0), (2, 0), (3, 0), (2, 1)]
    assert pick('duplicate_middle')[1][1] == dup[3][1] == b'2'
    assert [(x[0], x[2]) for x in m.select_parts([b'1'], 'rename_no_part_1')] == [(2, 1)]
    with pytest.raises(m.VerificationError):
        m.select_parts(parts, 'unknown')


# --- fingerprint -----------------------------------------------------------------------------------

def test_fingerprint_is_deterministic_and_order_sensitive(m, export):
    a, b = m.fingerprint([export]), m.fingerprint([export])
    assert a == b and a['complete']
    swapped = json.loads(export)
    swapped['chunks'][0], swapped['chunks'][1] = swapped['chunks'][1], swapped['chunks'][0]
    c = m.fingerprint([json.dumps(swapped).encode()])
    assert c['semantic_sha256'] != a['semantic_sha256']
    assert [r['id'] for r in c['rows']] != [r['id'] for r in a['rows']]
    # Re-encoding without semantic change keeps the semantic identity but not byte identity.
    same = m.fingerprint([json.dumps(json.loads(export), indent=1).encode()])
    assert same['semantic_sha256'] == a['semantic_sha256'] and same['sha256'] != a['sha256']


def test_duplicate_content_versus_duplicate_identity(m, export):
    fp = m.fingerprint([export])
    assert fp['derived']['duplicate_content_groups'] == [[0, 3]] and fp['derived']['duplicate_id_groups'] == []
    assert fp['derived']['distinct_contents'] == 3 and fp['derived']['distinct_ids'] == 4
    value = json.loads(export)
    value['chunks'].append(value['chunks'][1])
    doubled = m.fingerprint([json.dumps(value).encode()])
    assert doubled['derived']['duplicate_id_groups'] == [[1, 4]] and doubled['derived']['row_count'] == 5


@pytest.mark.parametrize('ranks,expected', [(['1', '2', '3'], 'DENSE_1_N'), (['1', '2', '4'], 'GAPPED'),
                                            (['1', '1.5', '2'], 'FRACTIONAL'), (['2', '1'], 'UNORDERED'),
                                            ([1, 2], 'INVALID'), (['x'], 'INVALID'),
                                            (['1', 'NaN'], 'INVALID'), (['sNaN', '2'], 'INVALID'),
                                            (['1', 'Infinity'], 'INVALID')])
def test_rank_classes(m, ranks, expected):
    assert m.rank_class(ranks) == expected


def test_volatile_prefs_listed_not_silently_dropped(m, export):
    fp = m.fingerprint([export])
    assert fp['settings']['volatile'] == sorted(m.VOLATILE_PREFS)
    assert 'current_background_id' in fp['settings']['prefs']
    assert m.semantic(fp)['excluded_volatile'] == list(m.VOLATILE_PREFS)


def test_unparseable_part_makes_fingerprint_incomplete(m, export):
    fp = m.fingerprint([export[:100]])
    assert fp['complete'] is False and fp['parts'][0]['parse'] == 'UNPARSEABLE'


def test_tasks_fingerprinted_in_order(m, export):
    fp = m.fingerprint([with_tasks(export)])
    assert fp['derived']['task_count'] == 2
    assert [t['year'] for r in fp['rows'] for t in (r['tasks'] or [])] == ['2031', '2031']


# --- mutations ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('mutation', sorted(
    ['unknown_top_level', 'unknown_background_data', 'unknown_pref', 'unknown_custom_code', 'unknown_task',
     'absent_optional_prefs', 'pref_version_older', 'synthetic_theme_id_duplicate',
     'pref_mode_theme_background', 'truncate_json', 'drop_chunks', 'chunks_not_array', 'invalid_data_url',
     'flip_base64_char']))
def test_every_mutation_changes_only_its_declared_edit(m, export, mutation):
    raw = with_tasks(export)
    out, record = m.mutate(raw, mutation)
    assert out != raw and record['before_sha256'] == hashlib.sha256(raw).hexdigest()
    assert record['after_sha256'] == hashlib.sha256(out).hexdigest()
    if mutation == 'truncate_json':
        assert raw.startswith(out) and record['parseable'] is False
        return
    before, after = json.loads(raw), json.loads(out)
    if mutation == 'flip_base64_char':
        after['chunks'][0]['file']['background'] = before['chunks'][0]['file']['background']
        assert after == before
    assert (record['synthetic_label'] == 'SYNTHETIC_INPUT_NOT_UI_CREATABLE') == (
        mutation in ('synthetic_theme_id_duplicate', 'pref_mode_theme_background'))
    m.project(record)


def test_mutation_that_alters_a_known_field_is_refused(m, export, monkeypatch):
    # Inserting an existing key shadows the native value; the re-parse check must refuse it.
    monkeypatch.setitem(m.MUTATIONS, 'unknown_pref', ('insert', ('settings', 'prefs'), 'mode'))
    with pytest.raises(m.VerificationError, match='Mutation altered a known field'):
        m.mutate(export, 'unknown_pref')
    with pytest.raises(m.VerificationError, match='Mutation target absent'):
        m.mutate(export, 'unknown_task')  # the accepted export has no tasks


def test_unknown_field_outcomes(m, export):
    raw = with_tasks(export)
    for mutation in ('unknown_top_level', 'unknown_background_data', 'unknown_pref', 'unknown_custom_code',
                     'unknown_task'):
        mutated, _ = m.mutate(raw, mutation)
        assert m.classify_unknown(m.fingerprint([mutated]), mutation) == 'RETAINED_UNKNOWN'
        assert m.classify_unknown(m.fingerprint([raw]), mutation) == 'IGNORED'
    assert m.classify_unknown(m.fingerprint([raw[:9]]), 'unknown_pref') == 'INCOMPLETE_EVIDENCE'
    optional, record = m.mutate(raw, 'absent_optional_prefs')
    assert record['keys'] == sorted(m.OPTIONAL_PREFS)
    assert not set(m.OPTIONAL_PREFS) & set(json.loads(optional)['settings']['prefs'])


# --- classification ----------------------------------------------------------------------------------

def rows_fp(m, export, indexes, prefs=None, code=None):
    value = json.loads(export)
    value['chunks'] = [value['chunks'][i] for i in indexes]
    if prefs:
        value['settings']['prefs'].update(prefs)
    if code:
        value['custom_code']['html'] = code
    return m.fingerprint([json.dumps(value).encode()])


def test_displacement_classes(m, export):
    pre, given = rows_fp(m, export, [0, 1]), rows_fp(m, export, [2, 3])
    empty = rows_fp(m, export, [])
    assert m.classify_backgrounds(pre, given, given, restore_error=False) == 'DISPLACED'
    assert m.classify_backgrounds(empty, given, given, restore_error=False) == 'RESTORED'
    assert m.classify_backgrounds(pre, given, rows_fp(m, export, [0, 1, 2, 3]), restore_error=False) == 'MERGED'
    assert m.classify_backgrounds(pre, given, pre, restore_error=False) == 'PRESERVED'
    assert m.classify_backgrounds(pre, given, rows_fp(m, export, [2]), restore_error=False) == 'PARTIAL'
    assert m.classify_backgrounds(pre, given, empty, restore_error=False) == 'LOST'
    assert m.classify_backgrounds(pre, given, rows_fp(m, export, [3, 2]), restore_error=False) == 'NORMALIZED'


def test_malformed_restore_is_never_inferred_from_absence(m, export):
    pre, empty = rows_fp(m, export, [0, 1]), rows_fp(m, export, [])
    assert m.classify_backgrounds(pre, None, empty, restore_error=True) == 'REJECTED_STATE_DESTROYED'
    assert m.classify_backgrounds(pre, None, pre, restore_error=True) == 'REJECTED_STATE_PRESERVED'
    # Missing post, missing pre, unknown error state: never a verdict.
    assert m.classify_backgrounds(pre, None, None, restore_error=True) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_backgrounds(None, None, empty, restore_error=True) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_backgrounds(pre, pre, pre, restore_error=None) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_component(pre, None, m.fingerprint([export[:20]]), 'settings',
                                restore_error=True) == 'INCOMPLETE_EVIDENCE'


def test_settings_and_code_components(m, export):
    pre = rows_fp(m, export, [0], prefs={'mode': 'scheduled'}, code='<p>sentinel</p>')
    given = rows_fp(m, export, [1])
    assert m.classify_component(pre, given, given, 'settings', restore_error=False) == 'REPLACED'
    assert m.classify_component(pre, given, pre, 'custom_code', restore_error=False) == 'PRESERVED'
    assert m.classify_component(pre, given, rows_fp(m, export, [1], prefs={'version': '9'}), 'settings',
                                restore_error=False) == 'NORMALIZED'
    assert m.classify_component(pre, None, given, 'custom_code', restore_error=True) == 'REJECTED_STATE_DESTROYED'


def test_task_classes(m, export):
    tasks = m.fingerprint([with_tasks(export)])
    none = m.fingerprint([export])
    assert m.classify_tasks(none, tasks, tasks, restore_error=False) == 'RESTORED'
    assert m.classify_tasks(tasks, none, none, restore_error=True) == 'REJECTED_STATE_DESTROYED'
    assert m.classify_tasks(tasks, none, tasks, restore_error=True) == 'REJECTED_STATE_PRESERVED'
    assert m.classify_tasks(none, tasks, none, restore_error=False) == 'LOST'


def test_rank_preservation_and_normalization(m, export):
    given = m.fingerprint([export])
    value = json.loads(export)
    value['chunks'][2]['data']['i'] = '7'
    assert m.classify_ranks(given, given) == 'RANK_PRESERVED'
    assert m.classify_ranks(given, m.fingerprint([json.dumps(value).encode()])) == 'RANK_NORMALIZED'
    assert m.classify_ranks(given, m.fingerprint([export[:9]])) == 'INCOMPLETE_EVIDENCE'


def test_repeat_import_classes_without_harness_deduplication(m, export):
    once = m.fingerprint([export])
    value = json.loads(export)
    value['chunks'] += value['chunks']
    twice = m.fingerprint([json.dumps(value).encode()])
    assert twice['derived']['row_count'] == 8  # the fingerprint never de-duplicates
    ok = {'restore_errors': (False, False)}
    assert m.classify_repeat(once, once, **ok) == 'IDEMPOTENT'
    assert m.classify_repeat(once, twice, **ok) == 'DUPLICATED'
    assert m.classify_repeat(twice, once, **ok) == 'LOST'
    assert m.classify_repeat(once, None, **ok) == 'INCOMPLETE_EVIDENCE'
    # Matching exports never make a rejected or unknown second import idempotent.
    assert m.classify_repeat(once, once, restore_errors=(False, True)) == 'REJECTED_ON_REPEAT'
    assert m.classify_repeat(once, once, restore_errors=(False, None)) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_repeat(once, once, restore_errors=(None, False)) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_repeat(once, once, restore_errors=(False,)) == 'INCOMPLETE_EVIDENCE'


def test_prediction_status_is_separate_from_failure(m):
    assert m.prediction_status(None, 'RESTORED') == 'NONE'
    assert m.prediction_status('RESTORED', 'RESTORED') == 'MATCH'
    assert m.prediction_status('RESTORED', 'LOST') == 'MISMATCH'
    assert m.prediction_status('RESTORED', 'INCOMPLETE_EVIDENCE') == 'UNOBSERVED'


# --- privacy ------------------------------------------------------------------------------------------

@pytest.mark.parametrize('value', [
    {'where': '/Users/someone/Library/Application Support/Firefox'}, {'pid': 4242},
    {'message': 'x'}, {'note': 'free text with spaces'}, {'image': 'data:image/png;base64,AAAA'},
    {'profile_path': 'x'}, {'k': 1.0e300}, {'Bad-Key': 1}, {'x': list(range(5000))}, {'x': object()}])
def test_privacy_projection_refuses(m, value):
    with pytest.raises(m.VerificationError, match='Privacy projection refused'):
        m.project(value)


def test_projected_fingerprint_contains_no_raw_artifacts(m, export):
    fp = m.fingerprint([export])
    projected = m.projected_fingerprint(fp)
    text = json.dumps(projected)
    assert 'data:' not in text and '/' not in text and 'Synthetic CNT fixture' not in text
    assert 'base64' not in text and len(text) < len(export) * 2
    # Raw data URL content and native file names are never present, only digests.
    assert json.loads(export)['chunks'][0]['file']['name'] not in text


# --- catalogue -------------------------------------------------------------------------------------------

def test_catalogue_counts_and_dependency_closure(m):
    runnable = m.validate_catalogue()
    assert len(m.CASES) == m.CASE_COUNT == 27 and len(runnable) == m.RUNNABLE_COUNT == 26
    assert {c['category'] for c in m.CASES} == set('ABCDEF')
    assert not m.case('D-EMPTY-SELECTION')['runnable'] and 'NOT_DRIVEN' in m.case('D-EMPTY-SELECTION')['reason']
    for entry in m.CASES:
        if entry['category'] == 'D':
            assert entry['profile'] == m.SEEDED_SENTINEL and entry['allow_no_signal']
        if entry['id'].startswith('S-'):
            assert entry['profile'] == m.FRESH_SOURCE and entry['source'] is None
        if entry['category'] == 'E':
            # COMPAT-E-PREP1: a silent E rejection is an observation, never a stop of the budget.
            assert entry['profile'] == m.FRESH_TARGET and entry['allow_no_signal'] is True
    assert not m.case('T-RICH')['allow_no_signal'] and not m.case('T-DISPLACE')['allow_no_signal']
    with pytest.raises(m.VerificationError, match='Unknown matrix case'):
        m.case('T-UNKNOWN')


def test_catalogue_refuses_forward_or_missing_dependencies(m):
    cases = list(m.CASES)
    cases.insert(0, cases.pop(1))  # T-RICH before S-RICH
    with pytest.raises(m.VerificationError, match='Matrix input undeclared'):
        m.validate_catalogue(cases)
    bad = [dict(c) for c in m.CASES]
    bad[1]['artifact'] = 'absent'
    with pytest.raises(m.VerificationError, match='Matrix input undeclared'):
        m.validate_catalogue(bad)


def test_not_representable_categories_are_classified(m):
    assert m.NOT_REPRESENTABLE['theme_background_mode'] == 'NOT_REPRESENTABLE_FIREFOX_6_12_1'
    assert m.NOT_REPRESENTABLE['theme_install'] == 'NOT_REPRESENTABLE_FIREFOX_6_12_1'
    assert m.case('E-MODE-THEME')['mutation'] == 'pref_mode_theme_background'


# --- synthetic inputs ------------------------------------------------------------------------------------

def test_rich_inputs_reuse_the_accepted_fixture_images(m):
    rich = m.synthetic_inputs('rich')
    for n in range(4):
        assert rich[n][1] == (FIXTURE / f'image-{n}.png').read_bytes()
    assert rich[0][1] == rich[3][1] and len({raw for _, raw in rich}) == 5


def test_padded_png_is_deterministic_and_well_formed(m):
    a = m.png((1, 2, 3), 3 * 1024 * 1024 + 7, b'seed')
    assert a == m.png((1, 2, 3), 3 * 1024 * 1024 + 7, b'seed') != m.png((1, 2, 3), 3 * 1024 * 1024 + 7, b'other')
    at, kinds = 8, []
    while at < len(a):
        length = int.from_bytes(a[at:at + 4], 'big')
        kind, data = a[at + 4:at + 8], a[at + 8:at + 8 + length]
        assert int.from_bytes(a[at + 8 + length:at + 12 + length], 'big') == __import__('zlib').crc32(kind + data)
        kinds.append(kind)
        at += 12 + length
    assert kinds[0] == b'IHDR' and kinds[-2:] == [b'IDAT', b'IEND'] and kinds.count(b'bxXf') == 4


def test_multi_design_reaches_the_ui_range(m):
    # Estimate from the verified template: base64 is 4/3 of the file; T ~ sum of chunk cores.
    core = 4 * (m.MULTI_PADDING + 200) // 3 + 400
    estimate = core * m.MULTI_COUNT
    assert m.THRESHOLD_MIN < estimate < m.THRESHOLD_MAX and estimate > 10 ** 8  # same digit count as default
    assert len(m.simulate_partition([core] * m.MULTI_COUNT, 2200, m.THRESHOLD_MIN)['parts']) >= 3


# --- SRICH-REPAIR1: handler facts and the seed trace ---------------------------------------------

HANDLER_FACTS = ('ui.data_global', 'ui.event.select', 'ui.event.checkbox', 'ui.event.text',
                 'ui.validation.threshold', 'ui.validation.year', 'ui.validation.time', 'ui.val_accessor',
                 'ui.override_routing', 'ui.background_click', 'ui.global_return', 'ui.control_wrapper',
                 'ui.visibility_enablement', 'ui.custom_code_open', 'ui.custom_code_gate',
                 'ui.custom_code_close', 'ui.scheduler_store', 'ui.add_task_enablement',
                 'ui.task_background_id')


def test_handler_facts_are_parent_verified_and_bound(m, repo_root, monkeypatch):
    import cnt_firefox_matrix_session as session
    p = m.load_provenance()
    for key in HANDLER_FACTS:
        fact = p['facts'][key]
        assert fact['status'] == 'VERIFIED' and fact['member'] in ('chunks/internal2.mjs', 'chunks/internal3.mjs')
        assert key in session.STEP_FACTS['rich'], key
    for key in ('ui.event.text', 'ui.validation.threshold', 'ui.control_wrapper'):
        assert key in session.STEP_FACTS['threshold']
    assert m.provenance_value(p, 'ui.val_accessor') == ['settings_context', 'background_size',
                                                         'background_position', 'background_repeat']
    # The committed threshold is a number in page state; the session reads it back typed.
    assert 'number' in m.provenance_value(p, 'ui.event.text')
    assert '250 ms' in m.provenance_value(p, 'ui.custom_code_gate')
    assert [n for k, n, v in p['rich_prefs'] if k == 'text'] == ['one_backup_file_size_in_bytes']
    assert type([v for k, n, v in p['rich_prefs'] if k == 'text'][0]) is int
    assert p['selectors']['close_code_editor'] == '.btn_w.close_code_editor'
    disclosure = p['method']['worker_disclosure']
    assert 'r6-static-seams' in disclosure and 'worker-srich-repair1-plan-static-inputs' in disclosure


def test_trace_values_are_allowlisted_or_classed(m):
    allow = m.trace_allowlist(m.load_provenance())
    assert allow['options_page_theme'] >= {'lavender', 'ruby'} and allow['settings_context'] == {
        'global', 'selected_background'}
    assert m.trace_value('ruby', allow['options_page_theme']) == 'ruby'
    assert m.trace_value('419430400209715200') == '419430400209715200'
    assert m.trace_value('07:08:09') == '07:08:09' and m.trace_value(True) is True
    assert m.trace_value(209715200) == 209715200
    for bad in ('/Users/x/secret', 'data:image/png;base64,AA', 'x' * 30, 'ruby', 1.5, 2 ** 60, [1], {'a': 1}):
        value = m.trace_value(bad)
        assert value['value'] is None and value['allowlisted'] is False


def test_trace_observation_drops_unknown_keys_and_bounds_shapes(m):
    allow = m.trace_allowlist(m.load_provenance())
    raw = {'context': 'selected_background', 'backgrounds': 5, 'tasks': -1, 'scheduler': 'yes',
           'pid': 4242, 'path': '/Users/x', 'message': 'secret',
           'add_task': {'present': True, 'shown': False, 'enabled': 1},
           'controls': {'mode': {'present': True, 'pref': 'scheduled', 'dom': '<b>x</b>', 'ui': None,
                                 'length': 9, 'shown': True, 'enabled': True, 'warn': False, 'raw': 'x'},
                        'Bad Name': {'present': True}, 'year': 'not-a-dict',
                        **{f'n{i}': {'present': True} for i in range(20)}},
           'editors': {'open': True, 'count': 3, 'items': [{'ready': True, 'length': 5, 'matches': True,
                                                            'value': 'code'}] * 5}}
    out = m.trace_observation(raw, allow)
    assert set(out) == {'context', 'counts', 'panels', 'add_task', 'controls', 'editors'}
    assert out['counts'] == {'backgrounds': 5, 'tasks': None} and out['panels']['scheduler'] is None
    assert out['add_task'] == {'present': True, 'shown': False, 'enabled': None}
    assert out['controls']['mode']['state'] == 'scheduled' and out['controls']['mode']['dom']['allowlisted'] is False
    assert out['controls']['year'] == {'present': False} and 'Bad Name' not in out['controls']
    assert len(out['controls']) <= 8 and len(out['editors']['items']) == 3
    assert 'value' not in json.dumps(out['editors']) and 'secret' not in json.dumps(out)
    assert m.trace_observation('nope', allow) == {'observation': 'UNAVAILABLE'}
    m.project(out)


def test_validate_trace_refuses_unknown_ids_and_unbounded_traces(m):
    good = [{'n': 1, 'action': 'pref:mode', 'route': 'option_click', 'status': 'DONE', 'expected': 'scheduled'}]
    assert m.validate_trace(good) == good
    for bad in ([dict(good[0], action='pref:mode;drop')], [dict(good[0], route='script')],
                [dict(good[0], status='PASSED')], [dict(good[0], n=2)],
                [dict(good[0], expected='/Users/x')], good * (m.TRACE_LIMIT + 1)):
        with pytest.raises(m.VerificationError):
            m.validate_trace(bad)
    for action in ('upload', 'delete_gap', 'move_fractional', 'context:select_background',
                   'override:background_size', 'invariant:override_global_unchanged', 'context:return_global',
                   'invariant:global_background_size', 'custom_code:open', 'custom_code:js',
                   'custom_code:close', 'scheduler:mode', 'task:2:day_of_the_month', 'threshold:predicted'):
        assert m.TRACE_ACTION.fullmatch(action), action


# --- SRICH-REPAIR2: task/background relation and the fixed source-readiness contract ----------

RICH_ORDER = (0, 5, 1, 3, 4)  # upload index per rendered position after the delete and move


def rich_export(m, change=None):
    """Test-only native-shaped S-RICH export as the verified seed leaves it: five rows in rank
    order 1, 1.5, 2, 4, 5, the override on position 1, task 1 on position 2, task 2 on
    position 4, every rich pref and the three custom-code values. `change(value)` edits it."""
    return m.fingerprint([rich_bytes(m, change)])


def rich_bytes(m, change=None):
    """The raw single-part bytes behind rich_export."""
    p = m.load_provenance()
    value = json.loads((FIXTURE / 'export.json').read_bytes())
    template = value['chunks'][0]
    for _, name, pref in p['rich_prefs']:
        value['settings']['prefs'][name] = pref
    value['custom_code'] = dict(zip(('html', 'css', 'js'), m.RICH_CODE))
    chunks = []
    for n, (upload, rank) in enumerate(zip(RICH_ORDER, p['rich_rows']['ranks'])):
        chunk = json.loads(json.dumps(template))
        chunk['data'].update(id=f'17905335218{n}bux', i=rank)
        chunk['file']['background'] = 'data:image/png;base64,' + base64.b64encode(
            m.png(m.RICH_COLOURS[upload])).decode()
        chunks.append(chunk)
    chunks[0]['data']['background_size'] = 'stretch_browser'
    base = {'day_of_the_week': '', 'month': '', 'day_of_the_month': ''}
    for n, task in enumerate(p['rich_tasks'], 1):
        row = chunks[task['background_position'] - 1]
        fields = {k: v for k, v in task.items() if k != 'background_position'}
        row['tasks'].append({'id': f'task{n}', 'i': str(n), 'background_id': row['data']['id'],
                             **base, **fields})
    value['chunks'] = chunks
    if change:
        change(value)
    return json.dumps(value, separators=(',', ':')).encode()


def move_task(value, number, row):
    """Re-home task `number` natively: new background_id, placed in that row's tasks."""
    chunks = value['chunks']
    task = next(t for c in chunks for t in c['tasks'] if t['id'] == f'task{number}')
    for c in chunks:
        c['tasks'] = [t for t in c['tasks'] if t is not task]
    task['background_id'] = chunks[row]['data']['id']
    chunks[row]['tasks'].append(task)


def delete_row(value, row):
    """A delete-button hit: the row and its tasks are gone (backup.task_placement)."""
    del value['chunks'][row]


def readiness(m, fp):
    p = m.load_provenance()
    return m.rich_readiness(m.rich_coverage(fp, p), p)


def test_rich_requirement_list_is_pinned(m):
    p = m.load_provenance()
    prefs = [f'pref:{n}' for n in ('options_page_theme', 'mode', 'slideshow', 'background_change_effect',
                                   'slide_direction', 'background_size', 'background_position',
                                   'background_repeat', 'home_btn_is_visible', 'home_btn_position',
                                   'one_backup_file_size_in_bytes')]
    assert m.rich_requirements(p) == prefs + [
        'override:background_size', 'rows:count', 'rows:order', 'rows:rank_class', 'rows:duplicate_content',
        'rows:distinct_identity', 'tasks:count', 'task:1:fields', 'task:1:background', 'task:2:fields',
        'task:2:background', 'custom_code:html', 'custom_code:css', 'custom_code:js']
    assert len(m.rich_requirements(p)) == 25 and m.READINESS_SCHEMA == 'bux-r6-rich-readiness-v1'
    rows = p['rich_rows']
    assert rows['ranks'] == ['1', '1.5', '2', '4', '5'] and rows['duplicate_content_groups'] == [[0, 3]]
    for key in rows['facts'] + ['ui.background_identity']:
        assert m.fact_status(p, key) == 'VERIFIED', key


def test_intended_rich_export_is_ready_and_carries_no_ids(m):
    fp = rich_export(m)
    p = m.load_provenance()
    coverage = m.rich_coverage(fp, p, ['REACT_FIBER_READ', 'bogus'])
    assert m.rich_readiness(coverage, p) == {'schema': 'bux-r6-rich-readiness-v1', 'ready': True, 'missing': []}
    assert coverage['task_fields'] == coverage['task_background'] == ['OBSERVED', 'OBSERVED']
    assert coverage['task_target_binding'] == ['REACT_FIBER_READ', 'NOT_BOUND']
    assert coverage['rank_class'] == 'FRACTIONAL' and coverage['row_count'] == 5 and coverage['task_count'] == 2
    text = json.dumps(coverage)
    assert 'bux' not in text and 'task1' not in text  # no row or task id leaves the classifier
    m.project(coverage)


@pytest.mark.parametrize('label,change,missing', [
    ('task1-wrong-existing', lambda v: move_task(v, 1, 2), ['task:1:background']),
    ('task2-wrong-existing', lambda v: move_task(v, 2, 4), ['task:2:background']),
    ('task2-same-content-row', lambda v: move_task(v, 2, 0), ['task:2:background']),
    ('no-op-task-click', lambda v: move_task(v, 2, 1), ['task:2:background']),
    ('delete-button-hit', lambda v: delete_row(v, 1),
     ['rows:count', 'rows:order', 'rows:rank_class', 'tasks:count', 'task:1:fields', 'task:1:background',
      'task:2:background']),
    ('placed-not-bound', lambda v: v['chunks'][3]['tasks'][0].update(background_id=v['chunks'][1]['data']['id']),
     ['task:2:background']),
    ('bound-not-placed', lambda v: v['chunks'][0]['tasks'].append(v['chunks'][3]['tasks'].pop()),
     ['task:2:background']),
    ('missing-custom-code', lambda v: v['custom_code'].pop('js'), ['custom_code:js']),
    ('missing-task-field', lambda v: v['chunks'][1]['tasks'][0].pop('time'),
     ['task:1:fields', 'task:1:background']),
    ('task-field-type', lambda v: v['chunks'][1]['tasks'][0].update(year=2031),
     ['task:1:fields', 'task:1:background']),
    ('duplicate-candidate', lambda v: v['chunks'][2]['tasks'].append(dict(v['chunks'][1]['tasks'][0], id='x')),
     ['tasks:count', 'task:1:fields', 'task:1:background']),
    ('wrong-pref', lambda v: v['settings']['prefs'].update(mode='multiple_backgrounds'), ['pref:mode']),
    ('pref-type', lambda v: v['settings']['prefs'].update(one_backup_file_size_in_bytes='209715200'),
     ['pref:one_backup_file_size_in_bytes']),
    ('missing-override', lambda v: v['chunks'][0]['data'].update(background_size='global'),
     ['override:background_size']),
    ('override-wrong-row', lambda v: (v['chunks'][0]['data'].update(background_size='global'),
                                      v['chunks'][1]['data'].update(background_size='stretch_browser')),
     ['override:background_size']),
    ('override-extra-row', lambda v: v['chunks'][2]['data'].update(background_size='stretch_browser'),
     ['override:background_size']),
    ('dense-ranks', lambda v: [c['data'].update(i=str(n)) for n, c in enumerate(v['chunks'], 1)],
     ['rows:order', 'rows:rank_class']),
    ('unordered-ranks', lambda v: v['chunks'][1]['data'].update(i='3'),
     ['override:background_size', 'rows:order', 'rows:rank_class', 'task:1:background', 'task:2:background']),
    ('numeric-ranks', lambda v: v['chunks'][1]['data'].update(i=1.5),
     ['override:background_size', 'rows:order', 'rows:rank_class', 'task:1:background', 'task:2:background']),
    ('content-order', lambda v: v['chunks'].insert(1, v['chunks'].pop(3)) or [
        c['data'].update(i=r) for c, r in zip(v['chunks'], ('1', '1.5', '2', '4', '5'))],
     ['rows:order', 'task:1:background', 'task:2:background']),
    ('duplicate-id', lambda v: v['chunks'][4]['data'].update(id=v['chunks'][2]['data']['id']),
     ['override:background_size', 'rows:distinct_identity', 'task:1:background', 'task:2:background'])])
def test_readiness_names_exactly_what_is_missing(m, label, change, missing):
    result = readiness(m, rich_export(m, change))
    assert result['ready'] is False and result['missing'] == missing, label


def test_task_relation_is_positional_and_id_bound(m):
    p = m.load_provenance()
    fields, background = m.task_relations(rich_export(m), p['rich_tasks'])
    assert (fields, background) == (['OBSERVED'] * 2, ['OBSERVED'] * 2)
    # Same content at positions 1 and 4: content alone cannot tell them apart; the id does.
    fp = rich_export(m, lambda v: move_task(v, 2, 0))
    assert fp['derived']['duplicate_content_groups'] == [[0, 3]]
    assert m.task_relations(fp, p['rich_tasks']) == (['OBSERVED'] * 2, ['OBSERVED', 'NOT_OBSERVED'])
    incomplete = dict(rich_export(m), complete=False)
    assert m.task_relations(incomplete, p['rich_tasks']) == (['NOT_OBSERVED'] * 2, ['NOT_OBSERVED'] * 2)


@pytest.mark.parametrize('coverage', [None, [], {}, {'custom_code': 'OBSERVED', 'task_fields': 'OBSERVED'}])
def test_malformed_coverage_is_never_ready(m, coverage):
    p = m.load_provenance()
    result = m.rich_readiness(coverage, p)
    assert result['ready'] is False and result['missing'] == m.rich_requirements(p)


def test_consumer_source_gate(m):
    rich, multi = m.case('T-RICH'), m.case('T-MULTI-ORDERED')
    ready = {'classifications': {'rich_source_ready': True, 'rich_source_missing': []},
             'artifacts': {'rich': {'source_ready': True}}}
    # MULTIPART-B-PREP1: an S-MULTI dependent is gated on its own source readiness too.
    assert m.source_ready(ready, rich) is True and m.source_ready({}, multi) is False
    assert m.source_ready(ready, multi) is False  # S-RICH readiness never satisfies S-MULTI
    for damage in ({'classifications': {'rich_source_ready': False, 'rich_source_missing': ['rows:order']}},
                   {'classifications': {'rich_source_ready': True, 'rich_source_missing': ['rows:order']}},
                   {'artifacts': {'rich': {'source_ready': None}}}, {'classifications': None}):
        assert m.source_ready({**ready, **damage}, rich) is False, damage
    assert m.MATRIX_CODES['Matrix rich source incomplete'] == 'MATRIX_RICH_SOURCE_INCOMPLETE'


# --- RICH-VALID-PREP1: restore, displacement and repeat evidence -------------------------------

SENTINEL_CODE = '<p>BUX R6 sentinel</p>'


def sentinel_value(m):
    """Test-only native-shaped sentinel target as seed_sentinel leaves it: two sentinel rows, one
    task on position 1, mode scheduled and the sentinel html."""
    value = json.loads((FIXTURE / 'export.json').read_bytes())
    template = value['chunks'][0]
    value['settings']['prefs']['mode'] = 'scheduled'
    value['custom_code']['html'] = SENTINEL_CODE
    chunks = []
    for n, colour in enumerate(m.SENTINEL_COLOURS):
        chunk = json.loads(json.dumps(template))
        chunk['data'].update(id=f'sentinel{n}', i=str(n + 1))
        chunk['file']['background'] = 'data:image/png;base64,' + base64.b64encode(m.png(colour)).decode()
        chunk['tasks'] = []
        chunks.append(chunk)
    chunks[0]['tasks'] = [{'id': 'stask', 'i': '1', 'background_id': 'sentinel0', 'year': '2033',
                           'time': '01:02:03', 'day_of_the_week': '', 'month': '', 'day_of_the_month': ''}]
    value['chunks'] = chunks
    return value


def sentinel(m):
    return m.fingerprint([json.dumps(sentinel_value(m), separators=(',', ':')).encode()])


def reidentify(value):
    """A consistent native re-identification: every row id changes and tasks follow their row."""
    for n, chunk in enumerate(value['chunks']):
        old, new = chunk['data']['id'], f'renumbered{n}'
        chunk['data']['id'] = new
        for c in value['chunks']:
            for t in c['tasks']:
                if t['background_id'] == old:
                    t['background_id'] = new


def ids_absent(m, value):
    text = json.dumps(value)
    rich_ids = [f'17905335218{n}bux' for n in range(5)]
    return not [i for i in rich_ids + ['sentinel0', 'sentinel1', 'renumbered0', '"task1"', '"task2"', '"stask"']
                if i in text]


MALFORMED = [None, {}, [], 'x', {'complete': True}, {'complete': True, 'rows': [1]},
             {'complete': True, 'rows': [{'file': 'x', 'tasks': 'y'}]},
             {'complete': True, 'rows': [{'tasks': [1]}]},
             {'complete': True, 'rows': [], 'settings': {'prefs': 3}},
             {'complete': True, 'rows': [], 'settings': None, 'custom_code': {'html': 'x'}},
             {'complete': True, 'rows': [{'presentation': 'x', 'id': 'a', 'rank': '1'}], 'settings': None}]


def test_semantic_relation_and_digest(m):
    rich, other = rich_export(m), sentinel(m)
    assert m.semantic_relation(rich, rich_export(m)) == 'SEMANTIC_EQUAL'
    assert m.semantic_relation(rich, other) == 'SEMANTIC_DIFFERENT'
    assert m.semantic_sha256(rich) == rich['semantic_sha256']
    # A volatile pref alone never makes two states semantically different; bytes may differ.
    moved = rich_export(m, lambda v: v['settings']['prefs'].update(current_background_id='x1'))
    assert m.semantic_relation(rich, moved) == 'SEMANTIC_EQUAL' and moved['sha256'] != rich['sha256']
    for bad in MALFORMED:
        assert m.semantic_relation(rich, bad) == m.semantic_relation(bad, rich) == 'INCOMPLETE_EVIDENCE'
        assert m.semantic_sha256(bad) is None


def test_restored_rich_is_met_on_the_intended_export_without_seed_fields(m):
    p = m.load_provenance()
    restored = m.restored_rich(rich_export(m), p)
    assert restored['requirements'] == {'schema': 'bux-r6-rich-readiness-v1', 'met': True, 'missing': []}
    assert restored['evidence'] == 'OBSERVED' and restored['source_seed_custom_code_input'] == 'LIBRARY_ADAPTER'
    assert 'task_target_binding' not in restored and 'custom_code_input' not in restored
    assert 'ready' not in restored['requirements']  # never confused with S-RICH source readiness
    assert ids_absent(m, restored)
    m.project(restored)


@pytest.mark.parametrize('label,change,missing', [
    ('normalized-ranks', lambda v: [c['data'].update(i=str(n)) for n, c in enumerate(v['chunks'], 1)],
     ['rows:order', 'rows:rank_class']),
    ('dropped-override', lambda v: v['chunks'][0]['data'].update(background_size='global'),
     ['override:background_size']),
    ('lost-task-relation', lambda v: move_task(v, 1, 2), ['task:1:background']),
    ('changed-custom-code', lambda v: v['custom_code'].update(js='void 0;'), ['custom_code:js']),
    ('reset-pref', lambda v: v['settings']['prefs'].update(mode='multiple_backgrounds'), ['pref:mode']),
    # A consistent re-identification keeps every relation: coverage is met, yet post differs from given.
    ('consistent-reid', reidentify, [])])
def test_restored_rich_names_exactly_what_the_restore_lost(m, label, change, missing):
    p = m.load_provenance()
    post = rich_export(m, change)
    restored = m.restored_rich(post, p)
    assert restored['requirements']['missing'] == missing, label
    assert restored['requirements']['met'] is (not missing)
    assert m.semantic_relation(post, rich_export(m)) == 'SEMANTIC_DIFFERENT'


def test_restored_rich_on_missing_evidence_misses_everything(m):
    p = m.load_provenance()
    for bad in MALFORMED:
        restored = m.restored_rich(bad, p)
        assert restored['evidence'] == 'INCOMPLETE_EVIDENCE'
        assert restored['requirements']['met'] is False and restored['requirements']['missing'] == m.rich_requirements(p)
        m.project(restored)


def merged(m):
    return rich_export(m, lambda v: v['chunks'].extend(sentinel_value(m)['chunks']))


def test_displacement_classes_follow_the_written_rule_set(m):
    pre, given = sentinel(m), rich_export(m)
    ok = {'restore_error': False}
    assert m.classify_displacement(pre, given, given, **ok) == 'REPLACES'
    # Prior state removed but the input not kept exactly: a changed setting, or re-identified rows.
    changed = rich_export(m, lambda v: v['settings']['prefs'].update(version='9.9.9'))
    reid = rich_export(m, reidentify)
    for post in (changed, reid):
        assert m.prior_state(m.prior_residue(pre, given, post)) == 'REMOVED'
        assert m.classify_displacement(pre, given, post, **ok) == 'TRANSFORMS'
    assert m.classify_backgrounds(pre, given, reid, restore_error=False) == 'NORMALIZED'
    assert m.classify_displacement(pre, given, merged(m), **ok) == 'MERGES'
    assert m.prior_state(m.prior_residue(pre, given, merged(m))) == 'PARTIALLY_RETAINED'
    assert m.classify_displacement(pre, given, pre, **ok) == 'PRESERVES_PRIOR'
    assert m.prior_state(m.prior_residue(pre, given, pre)) == 'RETAINED'
    # Only some of the input arrived and nothing prior remains: not a replacement.
    partial = rich_export(m, lambda v: v['chunks'].pop())
    assert m.classify_displacement(pre, given, partial, **ok) == 'TRANSFORMS'
    assert m.classify_displacement(pre, given, pre, restore_error=True) == 'REJECTED_STATE_PRESERVED'
    empty = m.fingerprint([json.dumps(dict(sentinel_value(m), chunks=[])).encode()])
    assert m.classify_displacement(pre, None, empty, restore_error=True) == 'REJECTED_STATE_ALTERED'
    assert m.classify_displacement(given, given, given, **ok) == 'NOT_DISCRIMINATING'
    assert m.classify_displacement(pre, given, given, restore_error=None) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_displacement(pre, None, given, **ok) == 'INCOMPLETE_EVIDENCE'
    assert m.classify_displacement(None, given, given, **ok) == 'INCOMPLETE_EVIDENCE'
    assert set(m.DISPLACEMENT_CLASSES) == {'REPLACES', 'MERGES', 'PRESERVES_PRIOR', 'TRANSFORMS',
                                           'REJECTED_STATE_PRESERVED', 'REJECTED_STATE_ALTERED',
                                           'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE'}
    # No class asserts losslessness or live-data safety.
    assert not [c for c in m.DISPLACEMENT_CLASSES if 'LOSSLESS' in c or 'SAFE' in c]
    assert m.LIVE_DATA_SCOPE == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'


def test_prior_residue_counts_only_distinguishable_prior_state(m):
    pre, given = sentinel(m), rich_export(m)
    replaced = m.prior_residue(pre, given, given)
    assert replaced == {'prior_rows': 2, 'prior_rows_distinguishable': 2, 'prior_rows_remaining': 0,
                        'prior_contents_distinguishable': 2, 'prior_contents_remaining': 0,
                        'prior_tasks': 1, 'prior_tasks_distinguishable': 1, 'prior_tasks_remaining': 0,
                        'prior_custom_code_remaining': {'html': False, 'css': False, 'js': False}, 'post_rows': 5}
    kept = m.prior_residue(pre, given, merged(m))
    assert (kept['prior_rows_remaining'], kept['prior_contents_remaining'], kept['prior_tasks_remaining']) == (2, 2, 1)
    assert kept['prior_custom_code_remaining'] == {'html': False, 'css': False, 'js': False}
    # A prior value the input also carries is not distinguishable: None, never "remaining".
    same_css = rich_export(m, lambda v: v['custom_code'].update(css=sentinel_value(m)['custom_code']['css']))
    assert m.prior_residue(pre, same_css, same_css)['prior_custom_code_remaining']['css'] is None
    assert ids_absent(m, kept)
    for bad in MALFORMED:
        assert m.prior_residue(pre, given, bad) is None and m.prior_state(m.prior_residue(bad, given, given)) == \
            'INCOMPLETE_EVIDENCE'
    assert m.prior_state({'prior_custom_code_remaining': {}, 'prior_rows_remaining': 3,
                          'prior_rows_distinguishable': 1}) == 'INCOMPLETE_EVIDENCE'


def test_repeat_identity_idempotent_with_disclosed_bytes_and_volatile_prefs(m):
    once = rich_export(m)
    same = m.repeat_identity(once, rich_export(m), restore_errors=(False, False))
    assert same['repeat_class'] == same['idempotence'] == 'IDEMPOTENT'
    assert (same['semantic_equal'], same['part_bytes_equal'], same['volatile_prefs_equal']) == (True, True, True)
    assert same['row_counts'] == [5, 5] and same['task_counts'] == [2, 2]
    assert same['excluded_volatile'] == list(m.VOLATILE_PREFS)
    # Native output differs in bytes and a volatile pref: still IDEMPOTENT, and both are disclosed.
    drift = rich_export(m, lambda v: v['settings']['prefs'].update(background_change_time=123))
    moved = m.repeat_identity(once, drift, restore_errors=(False, False))
    assert moved['idempotence'] == 'IDEMPOTENT' and moved['semantic_equal'] is True
    assert moved['part_bytes_equal'] is False and moved['volatile_prefs_equal'] is False
    assert moved['first_semantic_sha256'] == moved['second_semantic_sha256']
    assert ids_absent(m, moved)
    m.project(moved)


@pytest.mark.parametrize('label,second,errors,repeat,idempotence', [
    ('duplicated', lambda m: rich_export(m, lambda v: v['chunks'].extend(json.loads(json.dumps(v['chunks'])))),
     (False, False), 'DUPLICATED', 'NOT_IDEMPOTENT'),
    ('lost', lambda m: rich_export(m, lambda v: v['chunks'].pop()), (False, False), 'LOST', 'NOT_IDEMPOTENT'),
    ('changed', lambda m: rich_export(m, lambda v: v['settings']['prefs'].update(version='9.9.9')), (False, False),
     'CHANGED', 'NOT_IDEMPOTENT'),
    ('rejected-preserved', lambda m: rich_export(m), (False, True), 'REJECTED_ON_REPEAT',
     'REJECTED_ON_REPEAT_STATE_PRESERVED'),
    ('rejected-altered', lambda m: rich_export(m, lambda v: v['chunks'].pop()), (False, True), 'REJECTED_ON_REPEAT',
     'REJECTED_ON_REPEAT_STATE_ALTERED'),
    ('unknown-second', lambda m: rich_export(m), (False, None), 'INCOMPLETE_EVIDENCE', 'INCOMPLETE_EVIDENCE'),
    ('unknown-first', lambda m: rich_export(m), (None, False), 'INCOMPLETE_EVIDENCE', 'INCOMPLETE_EVIDENCE'),
    ('one-restore', lambda m: rich_export(m), (False,), 'INCOMPLETE_EVIDENCE', 'INCOMPLETE_EVIDENCE'),
    ('no-second', lambda m: None, (False, False), 'INCOMPLETE_EVIDENCE', 'INCOMPLETE_EVIDENCE'),
    ('rejected-no-second', lambda m: None, (False, True), 'REJECTED_ON_REPEAT', 'INCOMPLETE_EVIDENCE')])
def test_repeat_identity_classes(m, label, second, errors, repeat, idempotence):
    result = m.repeat_identity(rich_export(m), second(m), restore_errors=errors)
    assert (result['repeat_class'], result['idempotence']) == (repeat, idempotence), label
    assert result['idempotence'] in m.IDEMPOTENCE_CLASSES
    m.project(result)


def evidence_record(case, errors=(False,), closure='CLOSED'):
    steps = [{'step': 'open_settings', 'status': 'DONE'}, {'step': 'pre_export', 'status': 'DONE'}]
    for _ in errors:
        steps += [{'step': 'restore', 'status': 'DONE'}, {'step': 'reload', 'status': 'DONE'}]
    steps.append({'step': 'post_export', 'status': 'DONE'})
    return {'steps': steps, 'restores': [{'completion': 'COMPLETED', 'restore_error': e, 'start_observed': True,
                                          'error_codes': []} for e in errors],
            'artifacts': {'post': {'closure': closure}, 'repeat': {'closure': closure}},
            'classifications': {'backgrounds': 'DISPLACED', 'tasks': 'DISPLACED', 'settings': 'REPLACED',
                                'custom_code': 'REPLACED'}}


def test_restore_evidence_has_a_fixed_shape_per_case_and_carries_no_ids(m):
    p = m.load_provenance()
    rich, empty = rich_export(m), m.fingerprint([json.dumps(dict(sentinel_value(m), chunks=[])).encode()])
    t_rich = m.restore_evidence(m.case('T-RICH'), {'pre': empty, 'post': rich}, rich, evidence_record('T-RICH'), p)
    assert t_rich['schema'] == 'bux-r6-restore-evidence-v1' and t_rich['case'] == 'T-RICH'
    assert t_rich['given_semantic_sha256'] == rich['semantic_sha256'] == t_rich['post_semantic_sha256']
    assert t_rich['post_vs_given'] == 'SEMANTIC_EQUAL' and t_rich['restored_rich']['requirements']['met'] is True
    assert t_rich['restore_sequence'] == {
        'steps': [{'step': 'restore', 'status': 'DONE'}, {'step': 'reload', 'status': 'DONE'},
                  {'step': 'post_export', 'status': 'DONE'}],
        'restores': [{'completion': 'COMPLETED', 'restore_error': False, 'start_observed': True}],
        'post_closure': 'CLOSED', 'repeat_closure': 'CLOSED'}
    pre = sentinel(m)
    displace = m.restore_evidence(m.case('T-DISPLACE'), {'pre': pre, 'post': rich}, rich,
                                  evidence_record('T-DISPLACE'), p)
    assert displace['sentinel_pre'] == {'contract': 'SEEDED_SENTINEL_V1', 'semantic_sha256': pre['semantic_sha256'],
                                        'row_count': 2, 'task_count': 1}
    assert displace['displacement'] == 'REPLACES' and displace['prior_state'] == 'REMOVED'
    assert displace['components'] == {'backgrounds': 'DISPLACED', 'tasks': 'DISPLACED', 'settings': 'REPLACED',
                                      'custom_code': 'REPLACED'}
    assert displace['live_data_scope'] == m.LIVE_DATA_SCOPE and displace['post_vs_pre'] == 'SEMANTIC_DIFFERENT'
    repeat = m.restore_evidence(m.case('F-REPEAT'), {'pre': empty, 'post': rich, 'repeat': rich}, rich,
                                evidence_record('F-REPEAT', (False, False)), p)
    assert repeat['repeat_identity']['idempotence'] == 'IDEMPOTENT' and repeat['repeat_vs_given'] == 'SEMANTIC_EQUAL'
    assert [s['step'] for s in repeat['restore_sequence']['steps']] == ['restore', 'reload', 'restore', 'reload',
                                                                       'post_export']
    for evidence in (t_rich, displace, repeat):
        assert m.project(evidence) == evidence and ids_absent(m, evidence)
    assert m.restore_evidence(m.case('S-RICH'), {}, None, {}, p) is None
    assert m.restore_evidence(m.case('D-TRUNC-P1'), {}, None, {}, p) is None


@pytest.mark.parametrize('case', ['T-RICH', 'T-DISPLACE', 'F-REPEAT'])
@pytest.mark.parametrize('bad', range(len(MALFORMED)))
def test_restore_evidence_is_total_over_malformed_input(m, case, bad):
    p, value = m.load_provenance(), MALFORMED[bad]
    records = [value, {'restores': 'x', 'steps': [1, {'step': '/Users/x', 'status': 'DONE'}], 'artifacts': []},
               {'restores': [{'completion': '/raw', 'restore_error': 'yes'}], 'classifications': {'tasks': {'id': 'x'}}}]
    for record in records:
        for fps in (value, {'pre': value, 'post': value, 'repeat': value}, {'post': rich_export(m), 'pre': value}):
            evidence = m.restore_evidence(m.case(case), fps, value, record, p)
            assert evidence['case'] == case and m.project(evidence) == evidence


@pytest.mark.parametrize('case', ['T-RICH', 'T-DISPLACE', 'F-REPEAT'])
def test_consumer_source_gate_covers_every_rich_valid_dependent(m, case):
    entry = m.case(case)
    ready = {'classifications': {'rich_source_ready': True, 'rich_source_missing': []},
             'artifacts': {'rich': {'source_ready': True}}}
    assert entry['source'] == 'S-RICH' and entry['artifact'] == 'rich' and m.source_ready(ready, entry) is True
    for damage in ({'classifications': {'rich_source_ready': False, 'rich_source_missing': []}},
                   {'artifacts': {'rich': {'source_ready': False}}}, {'artifacts': {}}):
        assert m.source_ready({**ready, **damage}, entry) is False
    assert m.RICH_VALID_EVIDENCE == ('T-RICH', 'T-DISPLACE', 'F-REPEAT')


# --- MALFORMED-D-PREP1: malformed-input D evidence ---------------------------------------------

D_CASES = ['D-TRUNC-P1', 'D-NO-CHUNKS', 'D-CHUNKS-TYPE', 'D-BAD-DATAURL', 'D-NAME-NO-P1']
D_PREDICTED = {'backgrounds': 'REJECTED_STATE_DESTROYED', 'custom_code': 'REJECTED_STATE_PRESERVED'}
UNRECOGNIZED = 'UNRECOGNIZED_REPORT_PRESENT'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def d_input(m, case):
    """(matrix_inputs, input parts, given fingerprint, original fingerprint) as the preflight and the
    session produce them for one D case on the S-RICH-shaped single-part source."""
    source, entry, mutation = rich_bytes(m), m.case(case), None
    parts = [source]
    if entry['mutation']:
        out, mutation = m.mutate(source, entry['mutation'])
        mutation['part_number'] = 1
        parts = [out]
    selection = m.select_parts(parts, entry['selection'])
    inputs = {'source_case': 'S-RICH', 'artifact': 'rich', 'selection_kind': entry['selection'],
              'source': [{'part_number': 1, 'bytes': len(parts[0]), 'sha256': sha(parts[0])}], 'mutation': mutation,
              'selection': [{'named_part': n, 'slot': s, 'part_number': p, 'sha256': sha(r)}
                            for n, r, p, s in selection]}
    given = m.fingerprint(parts)
    if mutation:
        inputs['original'] = [{'part_number': 1, 'bytes': len(source), 'sha256': sha(source)}]
        return inputs, parts, given, m.fingerprint([source])
    return inputs, parts, given, given


def d_record(completion='ERROR_REPORTED', error=True, started=True, closure='CLOSED', codes=(), silent=(),
             ribbon=None, restores=1, predictions=None, pre='HIDDEN'):
    """`pre` is the session's pre-restore ribbon reading; a recorded restore implies the gate passed."""
    restore = {'completion': completion, 'restore_error': error, 'error_codes': list(codes),
               'silent_codes': list(silent), 'start_observed': started, 'transition_end_observed': started,
               'backgrounds_dom_after': 0, 'selected_files': 1}
    if ribbon is not None:
        restore['error_ribbon_seen'] = ribbon
    record = {'restores': [dict(restore) for _ in range(restores)],
              'artifacts': {'post': {'closure': closure, 'complete': True,
                                     'derived': {'row_count': 0, 'task_count': 0}}},
              'predictions': predictions or {}}
    if pre is not None:
        record['pre_restore_error_ribbon'] = pre
    return record


def d_evidence(m, case, post, record=None, pre=None):
    inputs, parts, given, original = d_input(m, case)
    return m.malformed_evidence(m.case(case), {'pre': pre or sentinel(m), 'post': post}, given, original,
                                d_record() if record is None else record, inputs, m.input_shape(parts))


def sentinel_changed(m, change):
    value = sentinel_value(m)
    change(value)
    return m.fingerprint([json.dumps(value, separators=(',', ':')).encode()])


def emptied(m):
    """The sentinel after its rows and tasks were deleted; settings and custom code untouched."""
    return sentinel_changed(m, lambda v: v.update(chunks=[]))


def test_d_catalogue_cases_predictions_and_not_driven_empty_selection(m):
    runnable = [c['id'] for c in m.CASES if c['category'] == 'D' and c['runnable']]
    assert runnable == D_CASES and sorted(m.MALFORMED_INPUT_CLASSES) == sorted(D_CASES)
    empty = m.case('D-EMPTY-SELECTION')
    assert empty['runnable'] is False and empty['reason'].startswith('NOT_DRIVEN') and empty['source'] is None
    assert [m.case(c)['predictions'] for c in D_CASES] == [D_PREDICTED] * 3 + [{}, {}]
    assert all(m.case(c)['allow_no_signal'] is True and m.case(c)['profile'] == 'SEEDED_SENTINEL' for c in D_CASES)
    assert m.validate_catalogue() == [c['id'] for c in m.CASES if c['runnable']]
    assert (m.CASE_COUNT, m.RUNNABLE_COUNT) == (27, 26)


def test_report_allowlist_equals_verified_provenance(m):
    p = m.load_provenance()
    assert m.REPORT_CODES == m.report_allowlist(p) == frozenset({('cnt_1436', True)})
    for key in ('report.cnt_1436', 'report.local_route', 'restore.report_route', 'ui.error_ribbon',
                'backup.partition_split_notice'):
        assert m.fact_status(p, key) == 'VERIFIED', key
    fact = p['facts']['report.cnt_1436']
    assert fact['value']['route'] == m.REPORT_ROUTE and fact['value']['stage'] == 'export'
    assert fact['member'] == p['facts']['backup.partition_split_notice']['member']
    # The accepted prose fact is not rewritten; the structured fact sits beside it.
    assert isinstance(p['facts']['backup.partition_split_notice']['value'], str)
    assert 'module-local' in p['facts']['report.local_route']['value']
    assert 'no restore-path site calls show_err_ribbon' in p['facts']['restore.report_route']['value']
    for status, route in (('UNVERIFIED', m.REPORT_ROUTE), ('VERIFIED', 'MODULE_LOCAL')):
        changed = json.loads(json.dumps(p))
        changed['facts']['report.cnt_1436'].update(status=status)
        changed['facts']['report.cnt_1436']['value']['route'] = route
        assert m.report_allowlist(changed) == frozenset()
    disclosure = p['method']['worker_disclosure']
    assert 'malformed-d-static-report-codes' in disclosure and 'nothing from it is used' in disclosure


def test_report_projection_passes_only_allowlisted_pairs(m, monkeypatch):
    assert m.report_projection(['cnt_1436'], True) == ['cnt_1436']
    assert m.report_projection(['cnt_1436'], False) == [UNRECOGNIZED]  # the other silent flag
    assert m.report_projection(['OTHER', 'cnt_1556', 'cnt_1999', 7, None], True) == [UNRECOGNIZED]
    assert m.report_projection(['cnt_1436', 'OTHER', 'cnt_1436'], True) == ['cnt_1436', UNRECOGNIZED]
    assert m.report_projection([], False) == [] and m.report_projection(None, False) == []
    assert m.report_projection({'code': 'cnt_1436'}, True) == [UNRECOGNIZED]
    # Only cnt_1436 (silent) is verified, so a loud allowlisted code needs a test-only allowlist.
    monkeypatch.setattr(m, 'REPORT_CODES', frozenset({('cnt_1436', True), ('cnt_1278', False)}))
    assert m.report_projection(['cnt_1278', 'cnt_1556'], False) == ['cnt_1278', UNRECOGNIZED]
    assert m.report_projection(['cnt_1278'], True) == [UNRECOGNIZED]


@pytest.mark.parametrize('restore,state', [
    ({'completion': 'COMPLETED', 'restore_error': False}, ('FALSE', True)),
    ({'completion': 'COMPLETED', 'restore_error': False, 'error_ribbon_seen': False}, ('FALSE', True)),
    ({'completion': 'COMPLETED', 'restore_error': False, 'error_ribbon_seen': True}, ('UNKNOWN', False)),
    ({'completion': 'ERROR_REPORTED', 'restore_error': True}, ('TRUE', True)),
    ({'completion': 'SILENT_REPORTED', 'restore_error': None}, ('UNKNOWN', True)),
    ({'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': None}, ('UNKNOWN', True)),
    ({'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': True}, ('UNKNOWN', True)),
    ({'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': False}, ('UNKNOWN', False)),
    ({'completion': 'COMPLETED', 'restore_error': True}, ('UNKNOWN', False)),
    ({'completion': 'COMPLETED', 'restore_error': None}, ('UNKNOWN', False)),
    ({'completion': 'ERROR_REPORTED', 'restore_error': False}, ('UNKNOWN', False)),
    ({'completion': 'COMPLETED', 'restore_error': 0}, ('UNKNOWN', False)),
    ({'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': 1}, ('UNKNOWN', False)),
    ({}, ('UNKNOWN', False)), (None, ('UNKNOWN', False)), ('x', ('UNKNOWN', False))])
def test_restore_error_tri_state(m, restore, state):
    assert m.restore_error_state(restore) == state
    assert state[0] in m.RESTORE_ERROR_STATES


@pytest.mark.parametrize('case,edit,shape', [
    ('D-TRUNC-P1', 'truncate', {'parse': 'UNPARSEABLE', 'chunks': None, 'row1_content': None}),
    ('D-NO-CHUNKS', 'remove', {'parse': 'PARSED', 'chunks': 'ABSENT', 'row1_content': None}),
    ('D-CHUNKS-TYPE', 'replace', {'parse': 'PARSED', 'chunks': 'NOT_ARRAY', 'row1_content': None}),
    ('D-BAD-DATAURL', 'replace', {'parse': 'PARSED', 'chunks': 'ARRAY', 'row1_content': 'UNDECODABLE'}),
    ('D-NAME-NO-P1', None, {'parse': 'PARSED', 'chunks': 'ARRAY', 'row1_content': 'DECODED'})])
def test_each_d_input_transformation_on_the_rich_source(m, case, edit, shape):
    source = rich_bytes(m)
    inputs, parts, given, original = d_input(m, case)
    assert m.input_shape(parts) == [shape] and (inputs['mutation'] or {}).get('edit') == edit
    if case == 'D-TRUNC-P1':
        assert source.startswith(parts[0]) and len(parts[0]) == len(source) * 2 // 3
    elif case == 'D-NO-CHUNKS':
        assert json.loads(parts[0]) == {k: v for k, v in json.loads(source).items() if k != 'chunks'}
    elif case == 'D-CHUNKS-TYPE':
        assert json.loads(parts[0]) == dict(json.loads(source), chunks={})
    elif case == 'D-BAD-DATAURL':
        value, bad = json.loads(source), json.loads(parts[0])
        assert bad['chunks'][0]['file']['background'] == 'data:image/png;base64,@@@@'
        bad['chunks'][0]['file']['background'] = value['chunks'][0]['file']['background']
        assert bad == value  # only the declared field changed
    else:
        assert parts == [source] and inputs['selection'] == [
            {'named_part': 2, 'slot': 0, 'part_number': 1, 'sha256': sha(source)}]
        with pytest.raises(m.VerificationError):
            m.select_parts([source, source], 'rename_no_part_1')
    evidence = d_evidence(m, case, emptied(m))
    block = evidence['input']
    assert block['input_class'] == m.MALFORMED_INPUT_CLASSES[case] and block['input_class_observed'] is True
    assert block['source_part_count'] == 1 and block['shape'] == [shape]
    assert block['named_parts'] == ([2] if case == 'D-NAME-NO-P1' else [1])
    binding, rich = evidence['source'], rich_export(m)['semantic_sha256']
    assert binding['selection_matches_input'] is True and binding['original_semantic_sha256'] == rich
    if edit:
        assert (binding['input_mutated'], binding['mutation_before_matches_original'],
                binding['mutation_after_matches_input'], binding['unmutated_parts_equal']) == (True,) * 4
        assert block['mutated_part'] == 1 and block['mutation'] == m.case(case)['mutation']
    else:
        assert binding['input_mutated'] is False and binding['given_semantic_sha256'] == rich
        assert binding['mutation_before_matches_original'] is None and block['mutated_part'] is None


def test_input_class_is_observed_on_the_bytes_not_the_catalogue(m):
    inputs, parts, given, _ = d_input(m, 'D-NO-CHUNKS')
    shape = m.input_shape(parts)
    assert m._input_observed('D-NO-CHUNKS', shape, inputs) is True
    assert m._input_observed('D-CHUNKS-TYPE', shape, inputs) is False
    # The fingerprint alone cannot separate them (both chunk counts are None); the bytes do.
    other = d_input(m, 'D-CHUNKS-TYPE')
    assert given['parts'][0]['chunk_count'] is None and other[2]['parts'][0]['chunk_count'] is None
    assert m.input_shape(other[1]) != shape
    inputs, parts, _, _ = d_input(m, 'D-NAME-NO-P1')
    renamed = dict(inputs, selection=[dict(inputs['selection'][0], named_part=1)])
    assert m._input_observed('D-NAME-NO-P1', m.input_shape(parts), renamed) is False
    assert m._input_observed('D-NAME-NO-P1', m.input_shape(parts), dict(inputs, mutation={'edit': 'x'})) is False
    assert m._input_observed('D-TRUNC-P1', [], {}) is False


def test_sentinel_components_and_state_effect_classes(m):
    pre, rich = sentinel(m), rich_export(m)
    bad = m.fingerprint([m.mutate(rich_bytes(m), 'invalid_data_url')[0]])
    comps = lambda post, given=rich, original=rich: m.sentinel_components(pre, given, original, post)
    effect = lambda post, given=rich, original=rich: m.state_effect(comps(post, given, original))
    assert comps(pre) == dict.fromkeys(m.COMPONENTS, 'PRESERVED') and effect(pre) == 'STATE_PRESERVED'
    assert comps(rich) == dict.fromkeys(m.COMPONENTS, 'REPLACED_BY_INPUT') and effect(rich) == 'STATE_REPLACED_BY_INPUT'
    # Rows and tasks gone before any parse; settings and custom code kept (the D prediction shape).
    destroyed = {'backgrounds': 'DESTROYED', 'tasks': 'DESTROYED', 'settings': 'PRESERVED', 'custom_code': 'PRESERVED'}
    assert comps(emptied(m), None) == destroyed and effect(emptied(m), None) == 'SENTINEL_CONTENT_DESTROYED'
    # A malformed input stored faithfully is visible as the input, not hidden as another difference.
    assert comps(bad, bad) == dict.fromkeys(m.COMPONENTS, 'REPLACED_BY_INPUT')
    mixed = comps(rich, bad)
    assert mixed['backgrounds'] == 'REPLACED_BY_UNMUTATED_SOURCE' and mixed['settings'] == 'REPLACED_BY_INPUT'
    assert m.state_effect(mixed) == 'STATE_REPLACED_BY_UNMUTATED_SOURCE'
    partial = sentinel_changed(m, lambda v: v['chunks'].pop())
    assert comps(partial)['backgrounds'] == 'PARTIALLY_RETAINED' and comps(partial)['tasks'] == 'PRESERVED'
    assert effect(partial) == 'STATE_PARTIALLY_RETAINED'
    swapped = sentinel_changed(m, lambda v: v['chunks'].reverse())
    assert comps(swapped)['backgrounds'] == 'REORDERED' and effect(swapped) == 'STATE_PARTIALLY_RETAINED'
    added = sentinel_changed(m, lambda v: v['chunks'].extend(json.loads(rich_bytes(m))['chunks']))
    assert comps(added)['backgrounds'] == comps(added)['tasks'] == 'RETAINED_WITH_ADDITIONS'
    def altered(v):
        other = json.loads(rich_bytes(m))['chunks'][2]
        other['tasks'] = []
        v['chunks'] = [other]
        v['settings']['prefs']['version'] = '9.9.9'
        v['custom_code'] = {'html': '', 'css': '', 'js': ''}
    changed = sentinel_changed(m, altered)
    assert comps(changed) == {'backgrounds': 'REMOVED_OTHER_PRESENT', 'tasks': 'DESTROYED', 'settings': 'NORMALIZED',
                              'custom_code': 'DESTROYED'}
    assert effect(changed) == 'STATE_ALTERED'
    no_settings = sentinel_changed(m, lambda v: v.pop('settings'))
    assert comps(no_settings)['settings'] == 'DESTROYED'
    # A prior value a reference also carries does not discriminate.
    assert m.sentinel_components(rich, rich, rich, rich) == dict.fromkeys(m.COMPONENTS, 'NOT_DISCRIMINATING')
    assert m.state_effect(dict.fromkeys(m.COMPONENTS, 'NOT_DISCRIMINATING')) == 'STATE_PRESERVED'
    for bad_fp in MALFORMED:
        assert m.sentinel_components(pre, rich, rich, bad_fp) == dict.fromkeys(m.COMPONENTS, 'INCOMPLETE_EVIDENCE')
        assert m.sentinel_components(bad_fp, rich, rich, pre) == dict.fromkeys(m.COMPONENTS, 'INCOMPLETE_EVIDENCE')
    for bad_components in (None, {}, dict(destroyed, tasks='bogus'), dict(destroyed, settings='INCOMPLETE_EVIDENCE')):
        assert m.state_effect(bad_components) == 'INCOMPLETE_EVIDENCE'
    assert set(m.STATE_EFFECTS) >= {effect(pre), effect(rich), effect(changed), effect(partial)}
    # No class asserts a safe rejection or losslessness.
    assert not [c for c in m.SENTINEL_EFFECTS + m.STATE_EFFECTS if 'SAFE' in c or 'LOSSLESS' in c or 'REJECT' in c]


def test_retention_counts_duplicates(m):
    rich = rich_export(m)
    pre = sentinel_changed(m, lambda v: v['chunks'].insert(1, json.loads(json.dumps(v['chunks'][0]))))
    def post_change(v):
        v['chunks'].append(json.loads(rich_bytes(m))['chunks'][2])
    post = sentinel_changed(m, post_change)  # [a, b, c] against a pre of [a, a, b]
    assert m.sentinel_components(pre, rich, rich, post)['backgrounds'] == 'PARTIALLY_RETAINED'
    assert m._retained(['a', 'a', 'b'], ['a', 'b', 'c']) == 2


def test_components_never_read_restore_error(m):
    import inspect
    post = emptied(m)
    seen = {json.dumps([d_evidence(m, 'D-NO-CHUNKS', post, r)[k] for k in ('components', 'state_effect')])
            for r in (d_record('ERROR_REPORTED', True), d_record('COMPLETED', False), d_record('DEADLINE_NO_SIGNAL', None),
                      d_record('SILENT_REPORTED', None), d_record('COMPLETED', True))}
    assert len(seen) == 1
    assert list(inspect.signature(m.sentinel_components).parameters) == ['pre', 'given', 'original', 'post']
    assert list(inspect.signature(m.state_effect).parameters) == ['components']


@pytest.mark.parametrize('case', D_CASES)
def test_malformed_evidence_fixed_shape_projects_and_carries_no_ids(m, case):
    record = d_record(codes=['cnt_1556', 'OTHER'], silent=['cnt_1436'], ribbon=True)
    evidence = d_evidence(m, case, emptied(m), record)
    assert set(evidence) == {'schema', 'case', 'evidence', 'live_data_scope', 'input', 'source', 'completion',
                             'reports', 'post', 'semantics', 'sentinel_pre', 'components', 'state_effect',
                             'sentinel_residue', 'ranks', 'predictions', 'prediction_scope'}
    assert (evidence['schema'], evidence['case'], evidence['evidence']) == ('bux-r6-malformed-evidence-v2', case,
                                                                            'OBSERVED')
    assert evidence['live_data_scope'] == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
    assert evidence['completion'] == {'completion': 'ERROR_REPORTED', 'restore_count': 1, 'restore_error': 'TRUE',
                                      'state_consistent': True, 'recorded_restore_error': True,
                                      'start_observed': True, 'transition_end_observed': True, 'selected_files': 1,
                                      'pre_restore_error_ribbon': 'HIDDEN',
                                      'report_observability': 'PARTIAL_SUPPRESSION_UNRESOLVED',
                                      'observability_gaps': ['ERROR_SILENT_PROPERTY', 'PREVENT_SUBSEQUENT_ERRORS',
                                                             'RESTORE_THROW_COVERAGE', 'RIBBON_PERSISTENCE']}
    assert evidence['reports'] == {'loud_present': True, 'silent_present': True, 'error_ribbon_seen': True,
                                   'loud_codes': [UNRECOGNIZED], 'silent_codes': ['cnt_1436'],
                                   'restore_route_codes': 'NOT_OBSERVABLE_MODULE_LOCAL_ROUTE'}
    assert evidence['components'] == {'backgrounds': 'DESTROYED', 'tasks': 'DESTROYED', 'settings': 'PRESERVED',
                                      'custom_code': 'PRESERVED'}
    assert evidence['state_effect'] == 'SENTINEL_CONTENT_DESTROYED'
    assert evidence['sentinel_pre'] == {'contract': 'SEEDED_SENTINEL_V1', 'semantic_sha256': sentinel(m)['semantic_sha256'],
                                        'row_count': 2, 'task_count': 1}
    assert evidence['post'] == {'closure': 'CLOSED', 'complete': True, 'row_count': 0, 'task_count': 0}
    assert evidence['semantics']['post_vs_pre'] == 'SEMANTIC_DIFFERENT'
    assert evidence['semantics']['post_vs_original'] == 'SEMANTIC_DIFFERENT'
    assert evidence['ranks'] == {'post_rank_class': 'EMPTY', 'vs_input': 'NOT_MEANINGFUL'}
    assert evidence['sentinel_residue']['prior_rows_remaining'] == 0
    assert evidence['prediction_scope'] == 'PREDICTION_ONLY_NOT_ASSERTED'
    assert m.project(evidence) == evidence and ids_absent(m, evidence)
    text = json.dumps(evidence)
    assert 'cnt_1556' not in text and '"OTHER"' not in text


def test_malformed_evidence_only_for_runnable_d_cases(m):
    for case in ('S-RICH', 'T-RICH', 'T-DISPLACE', 'F-REPEAT', 'E-TOP', 'T-MULTI-TRUNC', 'D-EMPTY-SELECTION'):
        assert m.malformed_evidence(m.case(case), {}, None, None, {}, {}, []) is None
    assert m.malformed_evidence(None, {}, None, None, {}, {}, []) is None
    assert m.malformed_evidence(dict(m.case('D-TRUNC-P1'), id='D-OTHER'), {}, None, None, {}, {}, []) is None


def test_deadline_no_signal_is_never_a_clean_completion(m):
    for record in (d_record('DEADLINE_NO_SIGNAL', None), d_record('DEADLINE_NO_SIGNAL', True, codes=['cnt_1556'])):
        evidence = d_evidence(m, 'D-TRUNC-P1', emptied(m), record)
        assert evidence['completion']['completion'] == 'DEADLINE_NO_SIGNAL'
        assert evidence['completion']['restore_error'] == 'UNKNOWN'
        # The closed, readable post-export is still observed; it never upgrades the completion.
        assert evidence['post']['closure'] == 'CLOSED' and evidence['state_effect'] == 'SENTINEL_CONTENT_DESTROYED'
    assert evidence['completion']['recorded_restore_error'] is True and evidence['reports']['loud_present'] is True
    silent = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('SILENT_REPORTED', None, silent=['cnt_1436']))
    assert silent['completion']['restore_error'] == 'UNKNOWN' and silent['reports']['silent_codes'] == ['cnt_1436']
    assert silent['reports']['loud_present'] is False
    # REPORT-GATE1: a sticky post-start ribbon (gate HIDDEN) is TRUE, inconsistent with the recorded
    # legacy False; a clean-looking completion is UNKNOWN while observability is partial.
    ribbon = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('COMPLETED', False, ribbon=True))
    assert ribbon['completion']['restore_error'] == 'TRUE' and ribbon['completion']['state_consistent'] is False
    assert ribbon['reports']['loud_present'] is True
    clean = d_evidence(m, 'D-NAME-NO-P1', emptied(m), d_record('COMPLETED', False, ribbon=False))
    assert clean['completion']['restore_error'] == 'UNKNOWN' and clean['reports']['loud_present'] is False
    assert clean['completion']['state_consistent'] is True


@pytest.mark.parametrize('record', [d_record(started=False), d_record(closure='UNCLOSED'), d_record(closure='ROWS_SHORT'),
                                    d_record(restores=2), d_record(restores=0), {}],
                         ids=['unstarted', 'unclosed', 'rows-short', 'two-restores', 'no-restore', 'empty-record'])
def test_unstarted_or_unclosed_restore_is_never_preservation(m, record):
    evidence = d_evidence(m, 'D-NAME-NO-P1', sentinel(m), record)  # post identical to pre
    assert evidence['components'] == dict.fromkeys(m.COMPONENTS, 'INCOMPLETE_EVIDENCE')
    assert evidence['state_effect'] == evidence['evidence'] == 'INCOMPLETE_EVIDENCE'
    semantics = evidence['semantics']
    assert semantics['pre_semantic_sha256'] == semantics['post_semantic_sha256'] is not None  # still disclosed
    assert evidence['sentinel_residue'] is None and evidence['ranks']['vs_input'] == 'INCOMPLETE_EVIDENCE'


def test_predictions_stay_predictions(m):
    recorded = {'backgrounds': {'predicted': 'REJECTED_STATE_DESTROYED', 'status': 'MATCH'},
                'custom_code': {'predicted': 'REJECTED_STATE_PRESERVED', 'status': 'MISMATCH'}}
    basis = 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'
    loud = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('ERROR_REPORTED', True, predictions=recorded))
    assert loud['predictions'] == {
        'backgrounds': {'predicted': 'REJECTED_STATE_DESTROYED', 'legacy_status': 'MATCH', 'status': 'MATCH',
                        'basis': basis},
        'custom_code': {'predicted': 'REJECTED_STATE_PRESERVED', 'legacy_status': 'MISMATCH', 'status': 'MISMATCH',
                        'basis': basis}}
    assert loud['evidence'] == 'OBSERVED'  # a mismatch is a finding, not a failure
    deadline = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('DEADLINE_NO_SIGNAL', True, predictions=recorded))
    assert {k: v['status'] for k, v in deadline['predictions'].items()} == dict.fromkeys(recorded, 'UNOBSERVED')
    assert deadline['predictions']['backgrounds']['legacy_status'] == 'MATCH'
    missing = d_evidence(m, 'D-NO-CHUNKS', emptied(m), d_record('ERROR_REPORTED', True))
    assert {k: v['status'] for k, v in missing['predictions'].items()} == dict.fromkeys(D_PREDICTED, 'UNOBSERVED')
    for case in ('D-BAD-DATAURL', 'D-NAME-NO-P1'):
        assert d_evidence(m, case, emptied(m), d_record(predictions=recorded))['predictions'] == {}
    assert loud['components'] == deadline['components'] and loud['state_effect'] == deadline['state_effect']


@pytest.mark.parametrize('tamper,key', [('before', 'mutation_before_matches_original'),
                                        ('after', 'mutation_after_matches_input'),
                                        ('original', 'mutation_before_matches_original'),
                                        ('selection', 'selection_matches_input'),
                                        ('part', 'mutation_before_matches_original'),
                                        ('no-original', 'unmutated_parts_equal')])
def test_in_attempt_source_binding_discloses_tampering(m, tamper, key):
    inputs, parts, given, original = d_input(m, 'D-BAD-DATAURL')
    if tamper == 'before':
        inputs['mutation']['before_sha256'] = '0' * 64
    elif tamper == 'after':
        inputs['mutation']['after_sha256'] = '0' * 64
    elif tamper == 'original':
        inputs['original'][0]['sha256'] = '0' * 64
    elif tamper == 'selection':
        inputs['selection'][0]['sha256'] = '0' * 64
    elif tamper == 'part':
        inputs['mutation']['part_number'] = 2
    else:
        del inputs['original']
    evidence = m.malformed_evidence(m.case('D-BAD-DATAURL'), {'pre': sentinel(m), 'post': emptied(m)}, given,
                                    original, d_record(), inputs, m.input_shape(parts))
    assert evidence['source'][key] is False and evidence['evidence'] == 'OBSERVED'


def test_malformed_ranks(m):
    rich = rich_export(m)
    assert m.malformed_ranks(rich, rich, rich) == 'RANK_PRESERVED'
    dense = rich_export(m, lambda v: [c['data'].update(i=str(n)) for n, c in enumerate(v['chunks'], 1)])
    assert m.malformed_ranks(None, rich, dense) == 'RANK_NORMALIZED'
    assert m.malformed_ranks(None, rich, emptied(m)) == 'NOT_MEANINGFUL'
    assert m.malformed_ranks(None, None, rich) == 'INCOMPLETE_EVIDENCE'


def test_restore_outcomes_label_the_recorded_flag_and_filter_codes(m):
    outcomes = m.restore_outcomes([
        {'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': True, 'error_codes': ['cnt_1556'],
         'silent_codes': ['cnt_1436'], 'start_observed': True, 'transition_end_observed': True,
         'error_ribbon_seen': True, 'backgrounds_dom_after': 0, 'selected_files': 1, 'message': '/Users/x'},
        'x', {'completion': 'COMPLETED', 'restore_error': False}])
    assert outcomes == [
        {'completion': 'DEADLINE_NO_SIGNAL', 'recorded_restore_error': True, 'restore_error_state': 'UNKNOWN',
         'state_consistent': True, 'start_observed': True, 'transition_end_observed': True,
         'error_ribbon_seen': True, 'selected_files': 1, 'backgrounds_dom_after': 0,
         'error_codes': [UNRECOGNIZED], 'silent_codes': ['cnt_1436']},
        {'completion': 'COMPLETED', 'recorded_restore_error': False, 'restore_error_state': 'FALSE',
         'state_consistent': True, 'start_observed': None, 'transition_end_observed': None,
         'error_ribbon_seen': None, 'selected_files': None, 'backgrounds_dom_after': None,
         'error_codes': [], 'silent_codes': []}]
    assert m.restore_outcomes('x') == [] and m.restore_outcomes(None) == [] and m.project(outcomes) == outcomes


def test_raw_report_text_never_leaves_malformed_evidence(m):
    record = d_record(codes=['cnt_1556', 'OTHER', 'Error: /Users/someone secret'], silent=['cnt_9999'])
    evidence = d_evidence(m, 'D-CHUNKS-TYPE', emptied(m), record)
    text = json.dumps(evidence)
    for leak in ('cnt_1556', 'cnt_9999', '/Users', 'secret', '"OTHER"'):
        assert leak not in text, leak
    assert evidence['reports']['loud_codes'] == evidence['reports']['silent_codes'] == [UNRECOGNIZED]
    assert m.project(evidence) == evidence


@pytest.mark.parametrize('case', D_CASES)
@pytest.mark.parametrize('bad', range(len(MALFORMED)))
def test_malformed_evidence_is_total_over_malformed_input(m, case, bad):
    value = MALFORMED[bad]
    records = [value, {'restores': 'x', 'artifacts': []},
               {'restores': [{'completion': '/raw', 'restore_error': 'yes', 'error_codes': '/Users/x',
                              'silent_codes': [{'a': 1}], 'selected_files': -1}],
                'artifacts': {'post': {'closure': 'CLOSED', 'derived': 'x'}}, 'predictions': {'backgrounds': 'x'}}]
    inputs_list = [value, {'source': value, 'original': value, 'mutation': value, 'selection': value},
                   {'mutation': {'part_number': 'x'}, 'source': [{}], 'original': [{}, {}], 'selection': [1]}]
    for record in records:
        for inputs in inputs_list:
            for shape in (value, [value], [{'parse': '/raw'}]):
                evidence = m.malformed_evidence(m.case(case), {'pre': value, 'post': value}, value, value, record,
                                                inputs, shape)
                assert evidence['case'] == case and m.project(evidence) == evidence


# --- REPORT-GATE1: report observability and the conservative malformed tri-state ---------------

PARTIAL, FULLY = 'PARTIAL_SUPPRESSION_UNRESOLVED', 'FULLY_OBSERVABLE'
OBLIGATIONS = ('ERROR_SILENT_PROPERTY', 'PREVENT_SUBSEQUENT_ERRORS', 'RESTORE_THROW_COVERAGE', 'RIBBON_PERSISTENCE')


def all_closed(m):
    p = json.loads(json.dumps(m.load_provenance()))
    for key in m.OBSERVABILITY_OBLIGATIONS.values():
        p['facts'][key]['value']['resolution'] = 'CLOSED'
    return p


def test_pinned_observability_equals_the_static_audit(m):
    p = m.load_provenance()
    assert m.REPORT_OBSERVABILITIES == (FULLY, PARTIAL) and tuple(m.OBSERVABILITY_OBLIGATIONS) == OBLIGATIONS
    assert (m.REPORT_OBSERVABILITY, m.OBSERVABILITY_GAPS) == m.report_observability(p)
    assert m.report_observability(p) == (PARTIAL, OBLIGATIONS)
    resolutions = {g: p['facts'][k]['value']['resolution'] for g, k in m.OBSERVABILITY_OBLIGATIONS.items()}
    # Closed only on an unproved premise (platform error values; a loaded ribbon root) is a gap.
    assert resolutions == {'ERROR_SILENT_PROPERTY': 'CONDITIONAL', 'PREVENT_SUBSEQUENT_ERRORS': 'CONDITIONAL',
                           'RESTORE_THROW_COVERAGE': 'OPEN', 'RIBBON_PERSISTENCE': 'OPEN'}
    for gap in ('ERROR_SILENT_PROPERTY', 'PREVENT_SUBSEQUENT_ERRORS'):
        assert 'premise, not' in p['facts'][m.OBSERVABILITY_OBLIGATIONS[gap]]['value']['finding'], gap


def test_observability_facts_are_hash_bound_and_leave_the_report_allowlist_unchanged(m):
    p = m.load_provenance()
    native = json.loads((FIXTURE / 'metadata.json').read_text())['native_member_sha256']
    assert p['capture']['xpi_sha256'] == m.XPI_SHA256
    for gap, key in m.OBSERVABILITY_OBLIGATIONS.items():
        fact = p['facts'][key]
        assert fact['status'] == 'VERIFIED' and fact['value']['obligation'] == gap, key
        assert fact['member_sha256'] == native[fact['member']], key
        assert set(fact['related_offsets']) <= set(native), key
        assert not key.startswith('report.') and 'route' not in fact['value'] and 'code' not in fact['value']
    assert m.report_allowlist(p) == m.REPORT_CODES == frozenset({('cnt_1436', True)})
    assert m.report_allowlist(all_closed(m)) == m.REPORT_CODES
    # The accepted facts, including report.ribbon_visibility, are not rewritten.
    assert 'was not audited' in p['facts']['report.ribbon_visibility']['value']
    assert 'REPORT-GATE1' in p['method']['worker_disclosure'] and 'no worker read the capture' in \
        p['method']['worker_disclosure']


@pytest.mark.parametrize('gap', OBLIGATIONS)
@pytest.mark.parametrize('damage', ['open', 'conditional', 'unverified', 'no-member-hash', 'wrong-obligation',
                                    'absent'])
def test_each_unclosed_obligation_is_a_gap(m, gap, damage):
    p = all_closed(m)
    assert m.report_observability(p) == (FULLY, ())
    key = m.OBSERVABILITY_OBLIGATIONS[gap]
    fact = p['facts'][key]
    if damage in ('open', 'conditional'):
        fact['value']['resolution'] = damage.upper()
    elif damage == 'unverified':
        fact['status'] = 'UNVERIFIED'
    elif damage == 'no-member-hash':
        del fact['member_sha256']
    elif damage == 'wrong-obligation':
        fact['value']['obligation'] = 'RIBBON_PERSISTENCE' if gap != 'RIBBON_PERSISTENCE' else 'ERROR_SILENT_PROPERTY'
    else:
        del p['facts'][key]
    assert m.report_observability(p) == (PARTIAL, (gap,))


def test_another_capture_proves_nothing(m):
    p = all_closed(m)
    p['capture']['xpi_sha256'] = '0' * 64
    assert m.report_observability(p) == (PARTIAL, OBLIGATIONS)
    for bad in (None, {}, [], 'x', {'facts': 'x', 'capture': 'x'}):
        assert m.report_observability(bad) == (PARTIAL, OBLIGATIONS)


R = lambda completion, error, ribbon=None, started=True: dict(
    {'completion': completion, 'restore_error': error, 'start_observed': started},
    **({} if ribbon is None else {'error_ribbon_seen': ribbon}))


@pytest.mark.parametrize('restore,partial,fully', [
    # The clean-looking completion: FALSE only with every suppression route closed.
    (R('COMPLETED', False), ('UNKNOWN', True), ('FALSE', True)),
    (R('COMPLETED', False, False), ('UNKNOWN', True), ('FALSE', True)),
    # A ribbon seen after a positively observed start (sticky flash): TRUE, inconsistent with the
    # recorded legacy False, under either observability.
    (R('COMPLETED', False, True), ('TRUE', False), ('TRUE', False)),
    (R('COMPLETED', False, True, started=False), ('UNKNOWN', False), ('UNKNOWN', False)),
    (R('ERROR_REPORTED', True, True), ('TRUE', True), ('TRUE', True)),
    (R('ERROR_REPORTED', True), ('TRUE', True), ('TRUE', True)),
    (R('SILENT_REPORTED', None), ('UNKNOWN', True), ('UNKNOWN', True)),
    (R('DEADLINE_NO_SIGNAL', None), ('UNKNOWN', True), ('UNKNOWN', True)),
    (R('DEADLINE_NO_SIGNAL', True, True), ('UNKNOWN', True), ('UNKNOWN', True)),
    (R('DEADLINE_NO_SIGNAL', False), ('UNKNOWN', False), ('UNKNOWN', False)),
    (R('COMPLETED', True), ('UNKNOWN', False), ('UNKNOWN', False)),
    (R('COMPLETED', None), ('UNKNOWN', False), ('UNKNOWN', False)),
    (R('ERROR_REPORTED', False), ('UNKNOWN', False), ('UNKNOWN', False)),
    (R('COMPLETED', 0), ('UNKNOWN', False), ('UNKNOWN', False)),
    ({}, ('UNKNOWN', False), ('UNKNOWN', False)), (None, ('UNKNOWN', False), ('UNKNOWN', False)),
    ('x', ('UNKNOWN', False), ('UNKNOWN', False))])
def test_malformed_tri_state_table(m, restore, partial, fully):
    assert m.malformed_restore_error_state(restore, PARTIAL, 'HIDDEN') == partial
    assert m.malformed_restore_error_state(restore, FULLY, 'HIDDEN') == fully
    # Any value other than FULLY_OBSERVABLE counts as partial.
    for other in (None, '', 'fully_observable', True, 'OTHER'):
        assert m.malformed_restore_error_state(restore, other, 'HIDDEN') == partial
    # Without the gate's HIDDEN reading no ribbon-based answer is given.
    for pre in ('VISIBLE', 'UNREADABLE', None, True, False, 'hidden'):
        assert m.malformed_restore_error_state(restore, FULLY, pre) == ('UNKNOWN', False)
    assert {partial[0], fully[0]} <= set(m.RESTORE_ERROR_STATES)


def test_legacy_tri_state_is_unchanged_for_non_d_paths(m):
    assert m.restore_error_state(R('COMPLETED', False)) == ('FALSE', True)
    assert m.restore_error_state(R('COMPLETED', False, True)) == ('UNKNOWN', False)
    assert m.restore_outcomes([R('COMPLETED', False)])[0]['restore_error_state'] == 'FALSE'
    assert 'report_observability' not in m.restore_outcomes([R('COMPLETED', False)])[0]


def test_d_restore_outcomes_carry_the_observability_aware_tri_state(m):
    restores = [R('COMPLETED', False, False), R('COMPLETED', False, True), R('DEADLINE_NO_SIGNAL', None)]
    legacy = m.restore_outcomes(restores)
    partial = m.restore_outcomes(restores, PARTIAL, 'HIDDEN')
    fully = m.restore_outcomes(restores, FULLY, 'HIDDEN')
    assert [o['restore_error_state'] for o in legacy] == ['FALSE', 'UNKNOWN', 'UNKNOWN']
    assert [(o['restore_error_state'], o['state_consistent']) for o in partial] == [
        ('UNKNOWN', True), ('TRUE', False), ('UNKNOWN', True)]
    assert [o['restore_error_state'] for o in fully] == ['FALSE', 'TRUE', 'UNKNOWN']
    assert [o['report_observability'] for o in partial] == [PARTIAL] * 3
    assert m.restore_outcomes(restores, 'bogus', 'HIDDEN')[0]['report_observability'] is None
    assert [o['restore_error_state'] for o in m.restore_outcomes(restores, FULLY, 'VISIBLE')] == ['UNKNOWN'] * 3
    # The recorded legacy flag and every other field are unchanged beside the tri-state.
    strip = lambda o: {k: v for k, v in o.items() if k not in ('restore_error_state', 'state_consistent',
                                                               'report_observability')}
    assert [strip(o) for o in partial] == [strip(o) for o in legacy] == [strip(o) for o in fully]
    assert m.project(partial) == partial


@pytest.mark.parametrize('case', D_CASES)
def test_partial_observability_keeps_a_clean_completion_unknown(m, case):
    recorded = {k: {'predicted': v, 'status': 'MATCH'} for k, v in D_PREDICTED.items()}
    record = d_record('COMPLETED', False, ribbon=False, predictions=recorded)
    evidence = d_evidence(m, case, emptied(m), record)
    assert (evidence['completion']['restore_error'], evidence['completion']['state_consistent']) == ('UNKNOWN', True)
    assert evidence['completion']['report_observability'] == PARTIAL
    # A readable post-export and any state effect never upgrade it; predictions are not observed.
    assert evidence['post']['closure'] == 'CLOSED' and evidence['evidence'] == 'OBSERVED'
    assert {v['status'] for v in evidence['predictions'].values()} <= {'UNOBSERVED'}
    assert {v['legacy_status'] for v in evidence['predictions'].values()} <= {'MATCH'}
    replaced = d_evidence(m, case, rich_export(m), record)
    assert replaced['completion']['restore_error'] == 'UNKNOWN'


@pytest.mark.parametrize('case', D_CASES)
def test_full_observability_would_make_the_same_shape_false(m, monkeypatch, case):
    recorded = {k: {'predicted': v, 'status': 'MATCH'} for k, v in D_PREDICTED.items()}
    record = d_record('COMPLETED', False, ribbon=False, predictions=recorded)
    partial = d_evidence(m, case, emptied(m), record)
    monkeypatch.setattr(m, 'REPORT_OBSERVABILITY', FULLY)
    monkeypatch.setattr(m, 'OBSERVABILITY_GAPS', ())
    fully = d_evidence(m, case, emptied(m), record)
    assert (fully['completion']['restore_error'], fully['completion']['state_consistent']) == ('FALSE', True)
    assert fully['completion']['report_observability'] == FULLY and fully['completion']['observability_gaps'] == []
    assert {v['status'] for v in fully['predictions'].values()} <= {'MATCH'}
    # Only the completion tri-state and its labels differ: every other channel is identical.
    assert {k: v for k, v in fully.items() if k not in ('completion', 'predictions')} == \
        {k: v for k, v in partial.items() if k not in ('completion', 'predictions')}
    labels = ('restore_error', 'report_observability', 'observability_gaps')
    assert {k: v for k, v in fully['completion'].items() if k not in labels} == \
        {k: v for k, v in partial['completion'].items() if k not in labels}
    # Without the gate's HIDDEN reading even full observability gives no FALSE.
    ungated = d_evidence(m, case, emptied(m), d_record('COMPLETED', False, ribbon=False, pre=None))
    assert ungated['completion']['restore_error'] == 'UNKNOWN' and ungated['completion']['state_consistent'] is False
    assert ungated['completion']['pre_restore_error_ribbon'] is None


def test_sticky_ribbon_is_true_but_predictions_stay_unobserved(m):
    recorded = {k: {'predicted': v, 'status': 'MATCH'} for k, v in D_PREDICTED.items()}
    evidence = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('COMPLETED', False, ribbon=True, predictions=recorded))
    assert evidence['completion']['restore_error'] == 'TRUE' and evidence['completion']['recorded_restore_error'] is False
    assert {k: v['status'] for k, v in evidence['predictions'].items()} == dict.fromkeys(D_PREDICTED, 'UNOBSERVED')
    loud = d_evidence(m, 'D-TRUNC-P1', emptied(m), d_record('ERROR_REPORTED', True, ribbon=True, predictions=recorded))
    assert {k: v['status'] for k, v in loud['predictions'].items()} == dict.fromkeys(D_PREDICTED, 'MATCH')


def test_state_effects_and_other_channels_are_independent_of_the_tri_state(m):
    shapes = [d_record('COMPLETED', False, ribbon=False), d_record('COMPLETED', False, ribbon=True),
              d_record('ERROR_REPORTED', True), d_record('DEADLINE_NO_SIGNAL', None), d_record('SILENT_REPORTED', None),
              d_record('COMPLETED', False, ribbon=False, pre='VISIBLE')]
    for post in (emptied(m), sentinel(m), rich_export(m)):
        blocks = {json.dumps([d_evidence(m, 'D-NO-CHUNKS', post, r)[k] for k in
                              ('components', 'state_effect', 'input', 'source', 'post', 'semantics',
                               'sentinel_pre', 'sentinel_residue', 'ranks')], sort_keys=True) for r in shapes}
        assert len(blocks) == 1


@pytest.mark.parametrize('pre', ['VISIBLE', 'UNREADABLE', '/Users/x ribbon text', 7, None])
def test_pre_restore_ribbon_is_a_fixed_enum(m, pre):
    evidence = d_evidence(m, 'D-BAD-DATAURL', emptied(m), d_record('ERROR_REPORTED', True, ribbon=True, pre=pre))
    assert evidence['completion']['pre_restore_error_ribbon'] == (pre if pre in ('VISIBLE', 'UNREADABLE') else None)
    assert evidence['completion']['restore_error'] == 'UNKNOWN'
    assert m.project(evidence) == evidence and '/Users' not in json.dumps(evidence)


# --- COMPAT-E-PREP1: exact E input proof and the fixed compatibility evidence ------------------

E_CASES = ['E-TOP', 'E-BG', 'E-PREF', 'E-CODE', 'E-TASK', 'E-ABSENT-OPT', 'E-VERSION', 'E-THEMEID-DUP',
           'E-MODE-THEME']
UNKNOWN_CASES = E_CASES[:5]
E_CHANGED = {'E-ABSENT-OPT': ['settings'], 'E-VERSION': ['settings'], 'E-THEMEID-DUP': ['backgrounds'],
             'E-MODE-THEME': ['settings']}
ARBITRARY = 'x_bux_private_zz'  # regex-shaped like the allowlist, but never allowlisted


def fresh_value(m):
    """Test-only fresh FRESH_TARGET pre-state: verified default prefs, no rows or tasks, fixture code."""
    value = json.loads((FIXTURE / 'export.json').read_bytes())
    value['settings']['prefs'].update(m.provenance_value(m.load_provenance(), 'defaults.prefs'))
    value['chunks'] = []
    return value


def fp_of(m, value):
    return m.fingerprint([json.dumps(value, separators=(',', ':')).encode()])


def fresh(m):
    return fp_of(m, fresh_value(m))


def e_input(m, case, source=None):
    """(matrix_inputs, input bytes, source bytes) as the preflight materializes one E case."""
    source = source or rich_bytes(m)
    out, mutation = m.mutate(source, m.case(case)['mutation'])
    mutation['part_number'] = 1
    inputs = {'source_case': 'S-RICH', 'artifact': 'rich', 'selection_kind': 'single',
              'source': [{'part_number': 1, 'bytes': len(out), 'sha256': sha(out)}], 'mutation': mutation,
              'original': [{'part_number': 1, 'bytes': len(source), 'sha256': sha(source)}],
              'selection': [{'named_part': 1, 'slot': 0, 'part_number': 1, 'sha256': sha(out)}]}
    return inputs, out, source


def e_record(m, case, inputs, out, source, completion='COMPLETED', error=False, ribbon=False, started=True,
             closure='CLOSED', pre_ribbon='HIDDEN', predictions=None, codes=(), silent=()):
    restore = {'completion': completion, 'restore_error': error, 'error_codes': list(codes),
               'silent_codes': list(silent), 'start_observed': started, 'transition_end_observed': started,
               'error_ribbon_seen': ribbon, 'backgrounds_dom_after': 5, 'selected_files': 1}
    return {'restores': [restore], 'predictions': predictions or {}, 'pre_restore_error_ribbon': pre_ribbon,
            'artifacts': {'post': {'closure': closure, 'complete': True, 'derived': {'row_count': 5, 'task_count': 2}}},
            'compat_input': m.compat_input_proof(m.case(case), inputs, [out], [source], [out])}


def post_value(m, which, out, source, change=None):
    value = {'SOURCE': lambda: json.loads(source), 'INPUT': lambda: json.loads(out),
             'PRE': lambda: fresh_value(m)}[which]()
    if change:
        change(value)
    return fp_of(m, value)


def e_evidence(m, case, which='SOURCE', change=None, pre=None, **kw):
    inputs, out, source = e_input(m, case)
    record = e_record(m, case, inputs, out, source, **kw)
    post = post_value(m, which, out, source, change)
    return m.compat_evidence(m.case(case), {'pre': pre or fresh(m), 'post': post}, m.fingerprint([out]),
                             m.fingerprint([source]), record, inputs)


def partial(m):
    """Rows, tasks and custom code applied from the source; settings kept at the fresh pre-state."""
    return lambda v: v.update(settings=fresh_value(m)['settings'])


def test_compat_constants_equal_catalogue_and_provenance(m):
    p = m.load_provenance()
    runnable = [c['id'] for c in m.CASES if c['category'] == 'E' and c['runnable']]
    assert runnable == E_CASES == list(m.COMPAT_CASES)
    assert m.COMPAT_UNKNOWN_KEYS == ('x_bux_top', 'x_bux_background', 'x_bux_pref', 'x_bux_code', 'x_bux_task')
    for case in E_CASES:
        entry = m.case(case)
        assert (entry['source'], entry['artifact'], entry['selection'], entry['mutate_part']) == ('S-RICH', 'rich',
                                                                                                  'single', 1)
        assert entry['profile'] == m.FRESH_TARGET and entry['allow_no_signal'] is True
        assert entry['predictions'] == ({'unknown': 'IGNORED'} if case == 'E-TOP' else {})
        assert m.COMPAT_CASES[case]['changed'] == tuple(E_CHANGED.get(case, ()))
    assert [c for c in E_CASES if m.case(c)['mutation'] in m.SYNTHETIC_ONLY] == ['E-THEMEID-DUP', 'E-MODE-THEME']
    assert list(m.CURRENT_STATE_PREFS) == m.provenance_value(p, 'restore.apply_unchanged_prefs')
    defaults = m.provenance_value(p, 'defaults.prefs')
    assert m.OPTIONAL_PREF_DEFAULTS == {k: defaults[k] for k in m.OPTIONAL_PREFS}
    assert m.MODE_DEFAULT == defaults['mode'] and m.OLDER_VERSION == '6.0.0'


@pytest.mark.parametrize('case', E_CASES)
def test_each_e_input_is_one_proven_bounded_mutation_of_the_rich_source(m, case):
    inputs, out, source = e_input(m, case)
    proof = m.compat_input_proof(m.case(case), inputs, [out], [source], [out])
    assert proof['proven'] is True and proof['case'] == case
    assert (proof['edit_present'], proof['outside_edit_unchanged'], proof['mutation_record_binds'],
            proof['unmutated_parts_byte_identical'], proof['selection_bytes_equal_input']) == (True,) * 5
    assert proof['known_components_changed'] == proof['known_components_expected'] == E_CHANGED.get(case, [])
    assert (proof['selection_class'], proof['source_part_count'], proof['mutated_part']) == ('single', 1, 1)
    synthetic = case in ('E-THEMEID-DUP', 'E-MODE-THEME')
    assert proof['synthetic_input_scope'] == ('SYNTHETIC_INPUT_NOT_UI_CREATABLE' if synthetic
                                              else 'NATIVE_EXPORT_BOUNDED_MUTATION')
    assert m.project(proof) == proof and ids_absent(m, proof)


def replace_bytes(raw, old, new):
    assert raw.count(old) == 1
    return raw.replace(old, new)


@pytest.mark.parametrize('case,tamper,fact', [
    ('E-PREF', 'extra-edit', 'outside_edit_unchanged'), ('E-PREF', 'wrong-value', 'edit_present'),
    ('E-PREF', 'wrong-key', 'edit_present'), ('E-TASK', 'extra-edit', 'outside_edit_unchanged'),
    ('E-VERSION', 'unchanged-value', 'edit_present'), ('E-ABSENT-OPT', 'one-kept', 'edit_present'),
    ('E-THEMEID-DUP', 'one-row', 'edit_present'), ('E-PREF', 'original-tampered', 'mutation_record_binds'),
    ('E-PREF', 'record-name', 'mutation_record_binds'), ('E-PREF', 'record-target', 'mutation_record_binds'),
    ('E-PREF', 'part-number', 'mutated_part'), ('E-PREF', 'selection-bytes', 'selection_bytes_equal_input'),
    ('E-PREF', 'selection-shape', 'selection_class'), ('E-PREF', 'second-part', 'unmutated_parts_byte_identical'),
    ('E-CODE', 'known-change', 'known_components_changed')])
def test_input_proof_refuses_anything_but_the_declared_edit(m, case, tamper, fact):
    inputs, out, source = e_input(m, case)
    record, selected, original = inputs['mutation'], [out], [source]
    key = m.MUTATIONS[m.case(case)['mutation']][2]
    if tamper == 'extra-edit':
        out = replace_bytes(out, b'"options_page_theme":"ruby"', b'"options_page_theme":"lavender"')
    elif tamper == 'wrong-value':
        out = replace_bytes(out, b'"bux-r6-unknown"', b'"bux-r6-other"')
    elif tamper == 'wrong-key':
        out = replace_bytes(out, b'"x_bux_pref"', b'"x_bux_prefx"')
    elif tamper == 'unchanged-value':
        out = source
    elif tamper == 'one-kept':
        value = json.loads(out)
        value['settings']['prefs']['backgrounds_per_page'] = 200
        out = json.dumps(value, separators=(',', ':')).encode()
    elif tamper == 'one-row':
        value = json.loads(out)
        del value['chunks'][1]['data']['theme_id']
        out = json.dumps(value, separators=(',', ':')).encode()
    elif tamper == 'original-tampered':
        original = [source + b' ']
    elif tamper == 'record-name':
        record['mutation'] = 'unknown_top_level'
    elif tamper == 'record-target':
        record['target'] = 'custom_code'
    elif tamper == 'part-number':
        record['part_number'] = 2
    elif tamper == 'selection-bytes':
        selected = [source]
    elif tamper == 'selection-shape':
        inputs['selection'][0]['named_part'] = 2
    elif tamper == 'second-part':
        out, original = [out, b'{"chunks":[]}'], [source, b'{"chunks":[1]}']
    elif tamper == 'known-change':
        value = json.loads(out)
        value['custom_code']['html'] = '<p>other</p>'
        out = json.dumps(value, separators=(',', ':')).encode()
    parts = out if isinstance(out, list) else [out]
    if tamper not in ('record-name', 'record-target', 'part-number', 'original-tampered', 'selection-shape',
                      'second-part'):
        record['after_sha256'] = inputs['source'][0]['sha256'] = sha(parts[0])
        inputs['selection'][0]['sha256'] = sha(parts[0])
    if tamper == 'second-part':
        inputs['source'].append({'part_number': 2, 'sha256': sha(parts[1])})
        inputs['original'].append({'part_number': 2, 'sha256': sha(original[1])})
    selected = parts if tamper not in ('selection-bytes',) else selected
    proof = m.compat_input_proof(m.case(case), inputs, parts, original, selected)
    assert proof['proven'] is False, (tamper, proof)
    expected = {'mutated_part': 2, 'selection_class': 'UNEXPECTED', 'known_components_changed': ['custom_code']}
    assert proof[fact] == expected.get(fact, False), (fact, proof[fact])
    assert (key is None or key not in json.dumps(proof)) and m.project(proof) == proof


def test_input_proof_is_fixed_shape_and_total(m):
    empty = m.compat_input_proof(m.case('T-RICH'), {}, [], [], [])
    assert empty['proven'] is False and empty['case'] is None
    keys = set(empty)
    for case in E_CASES:
        for bad in MALFORMED + [b'{', [b'{'], [1], [b'{}', b'{}']]:
            parts = bad if isinstance(bad, list) else [bad]
            proof = m.compat_input_proof(m.case(case), bad, parts, parts, parts)
            assert proof['proven'] is False and set(proof) == keys and m.project(proof) == proof
    assert m.compat_input_proof(None, None, None, None, None)['proven'] is False
    # Only a runnable E catalogue entry is proven; an E-shaped copy with another selection is not.
    inputs, out, source = e_input(m, 'E-TOP')
    assert m.compat_input_proof(dict(m.case('E-TOP'), selection='ordered'), inputs, [out], [source], [out])[
        'proven'] is False


@pytest.mark.parametrize('case', UNKNOWN_CASES)
@pytest.mark.parametrize('which,change,application,kind,at', [
    ('SOURCE', None, 'APPLIED', 'UNKNOWN_IGNORED', False),
    ('INPUT', None, 'APPLIED', 'UNKNOWN_RETAINED', True),
    ('SOURCE', lambda v: v['settings']['prefs'].update(slide_direction='random'), 'APPLIED',
     'KNOWN_STATE_NORMALIZED', False),
    ('PRE', None, 'RESTORE_REJECTED', 'RESTORE_REJECTED', False),
    ('PARTIAL', None, 'PARTIALLY_APPLIED', 'PARTIALLY_APPLIED', False)],
    ids=['ignored', 'retained', 'normalized', 'rejected', 'partial'])
def test_unknown_key_classes(m, case, which, change, application, kind, at):
    if which == 'PARTIAL':
        which, change = 'SOURCE', partial(m)
    evidence = e_evidence(m, case, which, change)
    assert evidence['evidence'] == 'OBSERVED'
    assert (evidence['application'], evidence['compat_class']) == (application, kind)
    block = evidence['unknown']
    key = m.MUTATIONS[m.case(case)['mutation']][2]
    assert block['declared_key'] == key and block['input_at_declared_object'] is True
    assert block['original_anywhere'] is False and block['post_at_declared_object'] is at
    assert block['allowlisted_keys_in_post'] == ([key] if at else [])
    assert evidence['semantics']['post_view_equals_original'] is (kind in ('UNKNOWN_IGNORED', 'UNKNOWN_RETAINED'))
    assert m.project(evidence) == evidence and ids_absent(m, evidence)


def test_rejected_restore_is_not_ignored_even_where_the_legacy_classifier_says_so(m):
    evidence = e_evidence(m, 'E-TOP', 'PRE')
    assert evidence['compat_class'] == 'RESTORE_REJECTED'
    assert set(evidence['components'].values()) == {'PRE_STATE_RETAINED'}
    # The legacy classifier reads only the post-export: an unapplied restore reads IGNORED there.
    assert m.classify_unknown(fresh(m), 'unknown_top_level') == 'IGNORED'
    assert evidence['predictions']['unknown']['status'] == 'UNOBSERVED'


def test_relocated_and_native_added_unknown_keys(m):
    def moved(v):
        v['chunks'][0]['data'].pop('x_bux_background')
        v['chunks'][2]['data']['x_bux_background'] = 'bux-r6-unknown'
    relocated = e_evidence(m, 'E-BG', 'INPUT', moved)
    assert relocated['compat_class'] == 'UNKNOWN_RELOCATED'
    assert (relocated['unknown']['post_at_declared_object'], relocated['unknown']['post_elsewhere']) == (False, True)
    # A native-added field outside the allowlist is a difference, disclosed only as a boolean.
    added = e_evidence(m, 'E-PREF', 'SOURCE', lambda v: v['settings']['prefs'].update({ARBITRARY: 'secret value'}))
    assert added['compat_class'] == 'KNOWN_STATE_NORMALIZED'
    assert added['semantics']['other_unknown_changed_vs_source'] is True
    assert added['unknown']['allowlisted_keys_in_post'] == []
    text = json.dumps(added)
    assert ARBITRARY not in text and 'secret value' not in text and m.project(added) == added


@pytest.mark.parametrize('site', ['top', 'pref', 'code', 'row', 'file', 'task'])
def test_non_allowlisted_x_bux_names_are_never_stripped_from_the_view(m, site):
    """Only the five allowlisted names are left out; any other regex-shaped name is a difference."""
    def add(v):
        target = {'top': v, 'pref': v['settings']['prefs'], 'code': v['custom_code'], 'row': v['chunks'][0]['data'],
                  'file': v['chunks'][0]['file'], 'task': v['chunks'][1]['tasks'][0]}[site]
        target[ARBITRARY] = 'raw'
    evidence = e_evidence(m, 'E-TOP', 'SOURCE', add)
    assert evidence['compat_class'] == 'KNOWN_STATE_NORMALIZED'
    assert evidence['semantics']['other_unknown_changed_vs_source'] is True
    assert ARBITRARY not in json.dumps(evidence)


def test_unsettled_restore_is_not_called_a_rejection(m):
    evidence = e_evidence(m, 'E-TOP', 'PRE', completion='DEADLINE_NO_SIGNAL', error=None)
    assert evidence['application'] == evidence['compat_class'] == 'UNSETTLED_NO_COMPLETION_SIGNAL'
    assert evidence['completion']['completion_basis'] == 'NO_COMPLETION_SIGNAL'
    assert evidence['completion']['restore_error'] == 'UNKNOWN'
    applied = e_evidence(m, 'E-TOP', 'SOURCE', completion='DEADLINE_NO_SIGNAL', error=None)
    assert applied['application'] == 'APPLIED' and applied['compat_class'] == 'UNKNOWN_IGNORED'
    assert applied['completion']['completion_basis'] == 'NO_COMPLETION_SIGNAL'


def test_current_state_prefs_are_set_apart_and_disclosed(m):
    change = lambda v: v['settings']['prefs'].update(color_help_is_visible=False, current_section='links')
    evidence = e_evidence(m, 'E-TOP', 'SOURCE', change)
    assert evidence['compat_class'] == 'UNKNOWN_IGNORED'
    assert evidence['semantics']['current_state_prefs_equal_to_source'] is False
    assert evidence['semantics']['post_vs_original'] == 'SEMANTIC_DIFFERENT'
    assert e_evidence(m, 'E-TOP')['semantics']['current_state_prefs_equal_to_source'] is True


def without(*names):
    return lambda v: [v['settings']['prefs'].pop(n) for n in names]


def prefs(**values):
    return lambda v: v['settings']['prefs'].update(values)


@pytest.mark.parametrize('which,change,bpp,backup,kind', [
    ('INPUT', None, 'REMAINED_ABSENT', 'REMAINED_ABSENT', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', prefs(backgrounds_per_page=200, one_backup_file_size_in_bytes=419430400),
     'DEFAULT_NOT_DISCRIMINATED', 'DEFAULT_NOT_DISCRIMINATED', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', None, 'DEFAULT_NOT_DISCRIMINATED', 'NORMALIZED', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', without('backgrounds_per_page'), 'REMAINED_ABSENT', 'NORMALIZED', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', prefs(one_backup_file_size_in_bytes=100000000), 'DEFAULT_NOT_DISCRIMINATED', 'NORMALIZED',
     'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('INPUT', prefs(options_page_theme='lavender'), 'REMAINED_ABSENT', 'REMAINED_ABSENT',
     'ACCEPTED_WITH_NORMALIZATION'),
    ('PARTIAL', None, 'SETTINGS_NOT_APPLIED', 'SETTINGS_NOT_APPLIED', 'PARTIALLY_APPLIED'),
    ('PRE', None, 'RESTORE_REJECTED', 'RESTORE_REJECTED', 'RESTORE_REJECTED')],
    ids=['absent', 'defaults', 'source-values', 'independent', 'other-value', 'known-normalized',
         'settings-not-applied', 'rejected'])
def test_absent_optional_prefs_are_classified_independently(m, which, change, bpp, backup, kind):
    if which == 'PARTIAL':
        which, change = 'SOURCE', partial(m)
    evidence = e_evidence(m, 'E-ABSENT-OPT', which, change)
    block = evidence['optional_prefs']
    assert set(block) == set(m.OPTIONAL_PREFS)
    assert (block['backgrounds_per_page']['class'], block['one_backup_file_size_in_bytes']['class']) == (bpp, backup)
    assert evidence['compat_class'] == kind
    # The fresh pre-state holds both defaults, and S-RICH keeps backgrounds_per_page at its default.
    assert block['backgrounds_per_page']['default_equals_pre'] is True
    assert block['backgrounds_per_page']['default_equals_source'] is True
    assert block['one_backup_file_size_in_bytes']['default_equals_source'] is False
    text = json.dumps(evidence)
    assert 'options_page_theme' not in text and 'home_btn_position' not in text and m.project(evidence) == evidence


def test_defaulted_needs_a_default_distinct_from_pre_state_and_source(m, monkeypatch):
    monkeypatch.setattr(m, 'OPTIONAL_PREF_DEFAULTS', {'backgrounds_per_page': 150,
                                                      'one_backup_file_size_in_bytes': 300000000})
    evidence = e_evidence(m, 'E-ABSENT-OPT', 'INPUT',
                          prefs(backgrounds_per_page=150, one_backup_file_size_in_bytes=300000000))
    block = evidence['optional_prefs']
    assert {k: v['class'] for k, v in block.items()} == dict.fromkeys(m.OPTIONAL_PREFS, 'DEFAULTED')
    assert block['one_backup_file_size_in_bytes']['post_value'] == 300000000
    assert block['backgrounds_per_page']['post_value_class'] == 'DEFAULT_VALUE'
    other = e_evidence(m, 'E-ABSENT-OPT', 'INPUT', prefs(backgrounds_per_page=7))['optional_prefs']
    assert (other['backgrounds_per_page']['class'], other['backgrounds_per_page']['post_value_class'],
            other['backgrounds_per_page']['post_value']) == ('NORMALIZED', 'OTHER_VALUE', None)


@pytest.mark.parametrize('which,change,version,kind', [
    ('SOURCE', None, 'SOURCE_VERSION', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('INPUT', None, 'INPUT_OLDER_VERSION', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', without('version'), 'ABSENT', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('SOURCE', prefs(version='9.9.9'), 'OTHER_VERSION', 'ACCEPTED_EQUIVALENT_KNOWN_STATE'),
    ('INPUT', prefs(slideshow=False), 'INPUT_OLDER_VERSION', 'ACCEPTED_WITH_NORMALIZATION'),
    ('PRE', None, 'SOURCE_VERSION', 'RESTORE_REJECTED')],
    ids=['source', 'input', 'absent', 'other', 'normalized', 'rejected'])
def test_older_version_observed_classes(m, which, change, version, kind):
    evidence = e_evidence(m, 'E-VERSION', which, change)
    assert evidence['compat_class'] == kind
    assert evidence['version'] == {'post_version_class': version, 'input_version_class': 'INPUT_OLDER_VERSION',
                                   'scope': 'EXACT_6_12_1_ARTIFACT_WITH_6_0_0_VERSION_ONLY'}


def drop_row(n):
    return lambda v: v['chunks'].pop(n)


@pytest.mark.parametrize('case,which,change,kind,facts', [
    ('E-THEMEID-DUP', 'INPUT', None, 'ACCEPTED_AS_INPUT',
     {'rows_relation': 'ROWS_EQUAL', 'rows_with_theme_id': 2, 'theme_id_value_class': 'INPUT_VALUE'}),
    ('E-THEMEID-DUP', 'SOURCE', None, 'ACCEPTED_AS_SOURCE_EQUIVALENT',
     {'rows_relation': 'ROWS_EQUAL', 'rows_with_theme_id': 0, 'theme_id_value_class': 'ABSENT'}),
    ('E-THEMEID-DUP', 'INPUT', drop_row(1), 'ACCEPTED_WITH_NORMALIZATION',
     {'rows_relation': 'ROWS_REDUCED', 'rows_with_theme_id': 1, 'theme_id_value_class': 'INPUT_VALUE'}),
    ('E-THEMEID-DUP', 'PRE', None, 'RESTORE_REJECTED', {'rows_relation': 'ROWS_REDUCED'}),
    ('E-MODE-THEME', 'INPUT', None, 'ACCEPTED_AS_INPUT', {'post_mode_class': 'INPUT_VALUE'}),
    ('E-MODE-THEME', 'SOURCE', None, 'ACCEPTED_AS_SOURCE_EQUIVALENT', {'post_mode_class': 'SOURCE_VALUE'}),
    ('E-MODE-THEME', 'SOURCE', prefs(mode='one_background'), 'ACCEPTED_WITH_NORMALIZATION',
     {'post_mode_class': 'DEFAULT_VALUE'}),
    ('E-MODE-THEME', 'PRE', None, 'RESTORE_REJECTED', {'post_mode_class': 'DEFAULT_VALUE'})],
    ids=['dup-as-input', 'dup-stripped', 'dup-deduplicated', 'dup-rejected', 'mode-as-input', 'mode-source',
         'mode-default', 'mode-rejected'])
def test_synthetic_theme_inputs_keep_their_label_and_classify_parser_behaviour_only(m, case, which, change, kind,
                                                                                    facts):
    evidence = e_evidence(m, case, which, change)
    assert evidence['compat_class'] == kind
    theme = evidence['theme']
    assert theme['synthetic_input_scope'] == evidence['input']['synthetic_input_scope'] == \
        'SYNTHETIC_INPUT_NOT_UI_CREATABLE'
    assert theme['ui_support_claimed'] is False
    assert theme['not_representable'] == 'NOT_REPRESENTABLE_FIREFOX_6_12_1'
    assert {k: theme[k] for k in facts} == facts
    assert 'bux-r6-theme' not in json.dumps(evidence) and m.project(evidence) == evidence


@pytest.mark.parametrize('case', E_CASES)
def test_partial_observability_keeps_a_clean_e_completion_unknown(m, case):
    evidence = e_evidence(m, case)
    completion = evidence['completion']
    assert (completion['completion'], completion['recorded_restore_error']) == ('COMPLETED', False)
    assert (completion['restore_error'], completion['state_consistent']) == ('UNKNOWN', True)
    assert completion['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
    assert completion['observability_gaps'] == list(m.OBSERVABILITY_GAPS)
    assert completion['pre_restore_error_ribbon'] == 'HIDDEN' and completion['start_observed'] is True
    assert completion['transition_end_observed'] is True and completion['selected_files'] == 1


def test_error_tri_state_never_reaches_the_compat_classes(m, monkeypatch):
    clean = e_evidence(m, 'E-TOP')
    ribbon = e_evidence(m, 'E-TOP', ribbon=True)
    loud = e_evidence(m, 'E-TOP', completion='ERROR_REPORTED', error=True, codes=['cnt_1556'])
    assert (ribbon['completion']['restore_error'], ribbon['completion']['state_consistent']) == ('TRUE', False)
    assert loud['completion']['restore_error'] == 'TRUE' and loud['reports']['loud_codes'] == [UNRECOGNIZED]
    monkeypatch.setattr(m, 'REPORT_OBSERVABILITY', 'FULLY_OBSERVABLE')
    monkeypatch.setattr(m, 'OBSERVABILITY_GAPS', ())
    fully = e_evidence(m, 'E-TOP')
    assert fully['completion']['restore_error'] == 'FALSE'
    for other in (ribbon, loud, fully):
        for key in ('components', 'application', 'compat_class', 'unknown', 'semantics', 'ranks', 'input', 'post'):
            assert other[key] == clean[key], key
    # An unreadable or visible pre-restore reading keeps even a fully observable completion UNKNOWN.
    assert e_evidence(m, 'E-TOP', pre_ribbon='VISIBLE')['completion']['restore_error'] == 'UNKNOWN'


@pytest.mark.parametrize('which,change,status,observed', [
    ('SOURCE', None, 'MATCH', 'IGNORED'), ('INPUT', None, 'MISMATCH', 'RETAINED_UNKNOWN'),
    ('PRE', None, 'UNOBSERVED', None),
    ('SOURCE', lambda v: v['settings']['prefs'].update(slide_direction='random'), 'UNOBSERVED', None),
    ('INPUT', lambda v: v['settings']['prefs'].update(slide_direction='random'), 'MISMATCH', 'RETAINED_UNKNOWN'),
    ('INPUT', lambda v: v['settings']['prefs'].update(x_bux_top=v.pop('x_bux_top')), 'MISMATCH', 'RETAINED_UNKNOWN')],
    ids=['ignored', 'retained', 'rejected', 'normalized-absent', 'normalized-retained', 'relocated'])
def test_e_top_prediction_stays_a_prediction(m, which, change, status, observed):
    legacy = {'unknown': {'predicted': 'IGNORED', 'status': 'MATCH'}}
    evidence = e_evidence(m, 'E-TOP', which, change, predictions=legacy)
    assert evidence['predictions'] == {'unknown': {
        'predicted': 'IGNORED', 'observed': observed, 'status': status,
        'basis': 'COMPAT_UNKNOWN_PRESENCE_ON_APPLIED_STATE', 'legacy_status': 'MATCH',
        'legacy_basis': 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'}}
    assert evidence['prediction_scope'] == 'PREDICTION_ONLY_NOT_ASSERTED'
    for case in E_CASES[1:]:
        assert e_evidence(m, case)['predictions'] == {}


@pytest.mark.parametrize('damage', ['unstarted', 'unclosed', 'two-restores', 'unproven', 'no-completion',
                                    'bad-post'])
def test_every_class_needs_the_evidence_gate(m, damage):
    inputs, out, source = e_input(m, 'E-TOP')
    record = e_record(m, 'E-TOP', inputs, out, source, started=damage != 'unstarted',
                      closure='UNCLOSED' if damage == 'unclosed' else 'CLOSED')
    post = m.fingerprint([source])
    if damage == 'two-restores':
        record['restores'] *= 2
    elif damage == 'unproven':
        record['compat_input'] = dict(record['compat_input'], proven=False)
    elif damage == 'no-completion':
        record['restores'][0]['completion'] = '/raw'
    elif damage == 'bad-post':
        post = m.fingerprint([source[:40]])
    evidence = m.compat_evidence(m.case('E-TOP'), {'pre': fresh(m), 'post': post}, m.fingerprint([out]),
                                 m.fingerprint([source]), record, inputs)
    assert evidence['evidence'] == 'INCOMPLETE_EVIDENCE'
    assert set(evidence['components'].values()) == {'INCOMPLETE_EVIDENCE'}
    assert evidence['application'] == evidence['compat_class'] == 'INCOMPLETE_EVIDENCE'
    assert evidence['source']['original_semantic_sha256'] == m.fingerprint([source])['semantic_sha256']
    assert m.project(evidence) == evidence


def test_a_source_equal_to_the_pre_state_is_not_discriminating(m):
    inputs, out, source = e_input(m, 'E-TOP')
    evidence = e_evidence(m, 'E-TOP', 'SOURCE', pre=m.fingerprint([source]))
    assert set(evidence['components'].values()) == {'NOT_DISCRIMINATING'}
    assert evidence['application'] == evidence['compat_class'] == 'NOT_DISCRIMINATING'


def test_compat_evidence_source_binding_and_fixed_shape(m):
    evidence = e_evidence(m, 'E-TASK')
    source = evidence['source']
    assert (source['source_case'], source['artifact'], source['readiness_gate']) == (
        'S-RICH', 'rich', 'SAME_ROOT_S_RICH_READY_BEFORE_LAUNCH')
    assert source['original_semantic_sha256'] == rich_export(m)['semantic_sha256']
    assert source['given_semantic_sha256'] != source['original_semantic_sha256']
    assert source['given_view_equals_original'] is True and source['input_mutated'] is True
    assert (source['selection_matches_input'], source['mutation_before_matches_original'],
            source['mutation_after_matches_input'], source['unmutated_parts_equal']) == (True,) * 4
    assert evidence['input']['proof']['proven'] is True
    assert evidence['input']['target_class'] == 'FIRST_TASK_OF_FIRST_ROW_WITH_TASKS'
    assert evidence['observation_scope'] == 'EXACT_CNT_6_12_1_ON_BOUND_FIREFOX_OBSERVATION_NOT_CERTIFICATION'
    assert evidence['live_data_scope'] == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
    assert evidence['ranks'] == {'post_rank_class': 'FRACTIONAL', 'vs_source': 'RANK_PRESERVED'}
    assert m.project(evidence) == evidence and ids_absent(m, evidence)


def test_compat_evidence_only_for_runnable_e_cases(m):
    for case in ('S-RICH', 'T-RICH', 'T-DISPLACE', 'F-REPEAT', 'D-TRUNC-P1', 'T-MULTI-TRUNC', 'D-EMPTY-SELECTION'):
        assert m.compat_evidence(m.case(case), {}, None, None, {}, {}) is None
    assert m.compat_evidence(None, {}, None, None, {}, {}) is None
    assert m.compat_evidence(dict(m.case('E-TOP'), id='E-OTHER'), {}, None, None, {}, {}) is None
    assert m.compat_evidence(dict(m.case('E-TOP'), runnable=False), {}, None, None, {}, {}) is None
    # Unhashable identities are refused, never raised (worker finding).
    assert m.compat_evidence({'id': [], 'category': 'E'}, {}, None, None, {}, {}) is None
    assert m.compat_input_proof({'id': []}, {}, [], [], [])['proven'] is False
    assert m.compat_input_proof(dict(m.case('E-TOP'), mutation=[]), {}, [], [], [])['proven'] is False
    # Only the allowlisted prediction key leaves; any other catalogue key is dropped.
    inputs, out, source = e_input(m, 'E-TOP')
    entry = dict(m.case('E-TOP'), predictions={'unknown': 'IGNORED', 'x_bux_private': 'NORMALIZED'})
    evidence = m.compat_evidence(entry, {'pre': fresh(m), 'post': m.fingerprint([source])}, m.fingerprint([out]),
                                 m.fingerprint([source]), e_record(m, 'E-TOP', inputs, out, source), inputs)
    assert list(evidence['predictions']) == ['unknown'] and 'x_bux_private' not in json.dumps(evidence)
    assert m.malformed_evidence(m.case('E-TOP'), {}, None, None, {}, {}, []) is None


def test_raw_values_names_and_report_text_never_leave_compat_evidence(m):
    def adversarial(v):
        v[ARBITRARY] = '/Users/someone/secret'
        v['settings']['prefs']['zz_private_key'] = 'raw pref value'
        v['chunks'][0]['data']['x_bux_background'] = '/Users/someone/other'
        v['custom_code']['x_bux_code'] = 'raw code value'
    evidence = e_evidence(m, 'E-BG', 'INPUT', adversarial, codes=['/Users/x report', 'cnt_1556'],
                          silent=['raw silent'])
    text = json.dumps(evidence) + json.dumps(evidence['input']['proof'])
    for leak in (ARBITRARY, '/Users', 'secret', 'zz_private_key', 'raw pref value', 'raw code value',
                 'raw silent', 'bux-r6-unknown', 'cnt_1556'):
        assert leak not in text, leak
    assert m.project(evidence) == evidence and ids_absent(m, evidence)
    assert evidence['unknown']['allowlisted_keys_in_post'] == ['x_bux_background', 'x_bux_code']
    # A recorded proof is copied only as fixed values: an unsafe recorded value reads None.
    inputs, out, source = e_input(m, 'E-TOP')
    record = e_record(m, 'E-TOP', inputs, out, source)
    record['compat_input'].update(selection_class='/Users/raw', known_components_changed=['/raw'], mutated_part='x')
    proof = m.compat_evidence(m.case('E-TOP'), {'pre': fresh(m), 'post': m.fingerprint([source])},
                              m.fingerprint([out]), m.fingerprint([source]), record, inputs)['input']['proof']
    assert (proof['selection_class'], proof['known_components_changed'], proof['mutated_part']) == (None, None, None)
    assert proof['proven'] is True and '/raw' not in json.dumps(proof)


@pytest.mark.parametrize('case', E_CASES)
@pytest.mark.parametrize('bad', range(len(MALFORMED)))
def test_compat_evidence_is_total_over_malformed_input(m, case, bad):
    value = MALFORMED[bad]
    records = [value, {'restores': 'x', 'artifacts': []}, {'compat_input': value, 'restores': [value]},
               {'restores': [{'completion': '/raw', 'restore_error': 'yes', 'error_codes': '/Users/x',
                              'silent_codes': [{'a': 1}], 'selected_files': -1, 'start_observed': True}],
                'artifacts': {'post': {'closure': 'CLOSED', 'derived': 'x'}}, 'predictions': {'unknown': 'x'},
                'compat_input': {'proven': True}}]
    for record in records:
        for inputs in (value, {'source': value, 'original': value, 'mutation': value, 'selection': value}):
            evidence = m.compat_evidence(m.case(case), {'pre': value, 'post': value}, value, value, record, inputs)
            assert evidence['case'] == case and m.project(evidence) == evidence
            assert evidence['evidence'] == 'INCOMPLETE_EVIDENCE'


# --- MULTIPART-B-PREP1: S-MULTI readiness, B input proofs and multipart evidence ---------------------

B_DEPENDENTS = ['T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1', 'T-MULTI-NO-MIDDLE', 'T-MULTI-DUP',
                'T-MULTI-TRUNC', 'T-MULTI-BADDATA']
MULTI_COLOURS = [(n * 40, 90, 200 - n * 30) for n in range(5)]
# Real-size layout integers: each chunk core is ~4/3 of a 15 MiB padded PNG (+4096 bytes per seed) plus
# row JSON; the Part 1 header carries a 9-digit threshold. Tests never build ~100 MiB of bytes.
CORES = [20973000 + 5462 * n for n in range(5)]
HEADER = 2187


def multi_value(m, threshold, code=None):
    """Test-only native-shaped S-MULTI state: five small rows standing in for the padded seeds."""
    value = json.loads((FIXTURE / 'export.json').read_bytes())
    template = value['chunks'][0]
    value['settings']['prefs']['one_backup_file_size_in_bytes'] = threshold
    if code is not None:
        value['custom_code']['html'] = code
    chunks = []
    for n, colour in enumerate(MULTI_COLOURS):
        chunk = json.loads(json.dumps(template))
        chunk['data'].update(id=f'multi{n}', i=str(n + 1))
        chunk['file']['background'] = 'data:image/png;base64,' + base64.b64encode(m.png(colour)).decode()
        chunk['tasks'] = []
        chunks.append(chunk)
    value['chunks'] = chunks
    return value


def split(value, groups):
    return native_parts(json.dumps(value, separators=(',', ':')).encode(), groups)


def real_layouts(m, threshold, groups, cores=CORES):
    header = m.header_at(HEADER, m.THRESHOLD_DEFAULT, threshold)
    return [{'keys': ['settings', 'custom_code', 'chunks'] if n == 0 else ['chunks'],
             'header_bytes': header if n == 0 else 11, 'chunk_core_bytes': [cores[i] for i in group],
             'footer_bytes': 2, 'native_template': True, 'settings_header': n == 0} for n, group in enumerate(groups)]


def multi_world(m):
    """A complete, ready S-MULTI attempt as the session records it: real-size layouts per export (each
    against the threshold that export read), small same-grouped native parts for the fingerprints, the
    prediction from the calibration layout and the deterministic seed digests."""
    calibration = real_layouts(m, m.THRESHOLD_DEFAULT, [list(range(5))])[0]
    prediction = m.layout_prediction(calibration, m.THRESHOLD_DEFAULT)
    t = prediction['threshold']
    own = {'calibration': m.THRESHOLD_DEFAULT, 'at_t': t, 'at_t_plus_1': t + 1, 'minimum': m.THRESHOLD_MIN}
    steps = [{'step': 'open_settings', 'status': 'DONE'}] + [
        {'step': step, 'status': 'DONE', **({'uploaded': 5, 'backgrounds_dom': 5} if step == 'seed_multi' else {})}
        for step in m.case('S-MULTI')['steps']]
    record = {'steps': steps, 'artifacts': {}, 'boundary_prediction': prediction,
              'thresholds': {'predicted': t, 'predicted_plus_1': t + 1, 'minimum': m.THRESHOLD_MIN}}
    layouts, fps, parts = {}, {}, {}
    for label, threshold in own.items():
        groups = m.simulate_partition(CORES, m.header_at(HEADER, m.THRESHOLD_DEFAULT, threshold), threshold)['parts']
        layouts[label] = real_layouts(m, threshold, groups)
        parts[label] = split(multi_value(m, threshold), groups)
        fps[label] = m.fingerprint(parts[label])
        record['artifacts'][label] = {
            'closure': 'CLOSED', 'threshold': threshold, 'semantic_sha256': fps[label]['semantic_sha256'],
            'parts': [{'index': n, 'name_class': f'NATIVE_PART_{n + 1}',
                       'bytes': l['header_bytes'] + sum(l['chunk_core_bytes']) + len(l['chunk_core_bytes']) + 1,
                       'sha256': sha(raw)} for n, (l, raw) in enumerate(zip(layouts[label], parts[label]))]}
    record['boundary_header_at_t'] = layouts['at_t'][0]['header_bytes']
    return {'record': record, 'layouts': layouts, 'fps': fps, 'parts': parts,
            'seeds': [sha(m.png(c)) for c in MULTI_COLOURS]}


def multi_ready(m, world):
    return m.multi_readiness(world['record'], world['layouts'], world['fps'], world['seeds'])


def test_multipart_constants_equal_the_audited_provenance(m):
    p = m.load_provenance()
    assert m.provenance_value(p, 'backup.threshold_ui_range') == [m.THRESHOLD_MIN, m.THRESHOLD_MAX] == [52428800,
                                                                                                         419430400]
    assert m.provenance_value(p, 'backup.threshold_default') == m.THRESHOLD_DEFAULT == 419430400
    assert m.FOOTER == b']}' and m.THRESHOLD_PREF == 'one_backup_file_size_in_bytes'
    native = json.loads((FIXTURE / 'metadata.json').read_text())['native_member_sha256']
    for key in ('backup.partition_units', 'backup.partition_header', 'ui.upload_limits', 'restore.later_parts'):
        fact = p['facts'][key]
        assert fact['status'] == 'VERIFIED' and fact['member_sha256'] == native[fact['member']], key
        assert set(fact['related_offsets']) <= set(native), key
    assert 'UTF-8 byte length' in p['facts']['backup.partition_units']['value']
    assert 'plain decimal digits' in p['facts']['backup.partition_header']['value']
    assert 'no file-size check' in p['facts']['ui.upload_limits']['value']
    assert 'only a file whose name includes Part 1.json' in p['facts']['restore.later_parts']['value']
    assert 'MULTIPART-B-PREP1' in p['method']['worker_disclosure']
    # The inherited partition reading stays the CORRECTED parent reading.
    assert p['facts']['backup.partition']['status'] == 'CORRECTED'


def test_the_real_size_design_reaches_three_parts_at_the_minimum_and_a_settable_boundary(m):
    world = multi_world(m)
    prediction = world['record']['boundary_prediction']
    assert prediction['converged'] is True and prediction['in_ui_range'] is True
    assert m.THRESHOLD_MIN < prediction['threshold'] < m.THRESHOLD_MAX and prediction['threshold'] > 10 ** 8
    sizes = {label: [len(l['chunk_core_bytes']) for l in layouts] for label, layouts in world['layouts'].items()}
    assert sizes == {'calibration': [5], 'at_t': [3, 2], 'at_t_plus_1': [5], 'minimum': [1, 2, 2]}


def test_s_multi_readiness_holds_on_a_complete_world(m):
    result = multi_ready(m, multi_world(m))
    assert result == {'schema': 'bux-r6-multi-readiness-v1', 'ready': True, 'missing': []}
    assert m.multi_requirements()[0] == 'seed:uploaded' and m.multi_requirements()[-1] == 'steps:all_done'
    assert len(m.multi_requirements()) == len(set(m.multi_requirements())) == 22
    assert 'encoding:ascii' not in m.multi_requirements()  # sizes are UTF-8 bytes (backup.partition_units)


def _part_value(m, world, label, edit):
    value = multi_value(m, world['record']['artifacts'][label]['threshold'])
    edit(value)
    groups = [list(range(a, a + len(l['chunk_core_bytes']))) for a, l in
              zip([0] + list(__import__('itertools').accumulate(len(l['chunk_core_bytes']) for l in world['layouts'][label]))[:-1],
                  world['layouts'][label])]
    world['parts'][label] = split(value, groups)
    world['fps'][label] = m.fingerprint(world['parts'][label])


def _steps(world, step, **changes):
    for entry in world['record']['steps']:
        if entry['step'] == step:
            entry.update(changes)


READINESS_DAMAGE = {
    'seed:uploaded': (lambda m, w: _steps(w, 'seed_multi', uploaded=4), True),
    'seed:rows': (lambda m, w: w['seeds'].__setitem__(0, '0' * 64), True),
    'calibration:closed_single': (lambda m, w: w['record']['artifacts']['calibration'].update(closure='ROWS_SHORT'),
                                  False),
    'calibration:threshold_default': (lambda m, w: w['record']['artifacts']['calibration'].update(
        threshold=m.THRESHOLD_DEFAULT - 1), False),
    'prediction:in_range': (lambda m, w: w['record']['boundary_prediction'].update(converged=False), False),
    'threshold:committed:predicted': (lambda m, w: w['record']['thresholds'].update(
        predicted=w['record']['thresholds']['predicted'] - 1), True),
    'threshold:committed:predicted_plus_1': (lambda m, w: w['record']['artifacts']['at_t_plus_1'].update(
        threshold=w['record']['thresholds']['predicted_plus_1'] + 1), False),
    'threshold:committed:minimum': (lambda m, w: w['record']['thresholds'].update(minimum=m.THRESHOLD_MIN + 1), True),
    'rows:stable': (lambda m, w: w['layouts']['at_t_plus_1'][0]['chunk_core_bytes'].__setitem__(4, CORES[4] + 1),
                    False),
    'at_t:multipart': (lambda m, w: (w['layouts'].__setitem__('at_t', real_layouts(
        m, w['record']['artifacts']['at_t']['threshold'], [list(range(5))])),
        w['record']['artifacts']['at_t'].update(parts=w['record']['artifacts']['at_t']['parts'][:1])), False),
    'at_t:header_premise': (lambda m, w: w['layouts']['at_t'][0].update(
        header_bytes=w['layouts']['at_t'][0]['header_bytes'] + 3), False),
    'at_t_plus_1:single': (lambda m, w: (w['layouts'].__setitem__('at_t_plus_1', real_layouts(
        m, w['record']['artifacts']['at_t_plus_1']['threshold'], [[0, 1, 2, 3], [4]])),
        w['record']['artifacts']['at_t_plus_1'].update(
            parts=w['record']['artifacts']['at_t'][ 'parts'])), False),
    'boundary:exact': (lambda m, w: w['record']['boundary_prediction'].update(header_adjusted_bytes=1), False),
    'partition:minimum': (lambda m, w: w['layouts'].__setitem__('minimum', real_layouts(
        m, m.THRESHOLD_MIN, [[0, 1], [2], [3, 4]])), False),
    'minimum:closed_contiguous': (lambda m, w: w['record']['artifacts']['minimum']['parts'][2].update(
        name_class='NATIVE_PART_4'), True),
    'minimum:part_facts': (lambda m, w: w['record']['artifacts']['minimum']['parts'][1].update(sha256='x'), True),
    'minimum:semantic': (lambda m, w: _part_value(m, w, 'minimum', lambda v: v['custom_code'].update(html='<p>x</p>')),
                         True),
    'minimum:dependent_targets': (lambda m, w: _part_value(m, w, 'minimum', lambda v: v['chunks'][1]['file'].update(
        background='data:image/png;base64,@@@@')), False),
    'steps:all_done': (lambda m, w: _steps(w, 'export:at_t_plus_1', status='SKIPPED_NOT_SETTABLE'), True),
}


@pytest.mark.parametrize('requirement', sorted(READINESS_DAMAGE))
def test_each_s_multi_requirement_refuses_readiness(m, requirement):
    world = multi_world(m)
    damage, alone = READINESS_DAMAGE[requirement]
    damage(m, world)
    result = multi_ready(m, world)
    assert result['ready'] is False and requirement in result['missing']
    if alone:
        assert result['missing'] == [requirement]
    assert result['missing'] == [r for r in m.multi_requirements() if r in result['missing']]  # fixed order


@pytest.mark.parametrize('bad', [None, {}, [], 'x', {'artifacts': 'x', 'steps': 'y'}])
def test_malformed_readiness_inputs_miss_everything(m, bad):
    world = multi_world(m)
    for args in ((bad, world['layouts'], world['fps'], world['seeds']), (world['record'], bad, bad, bad)):
        result = m.multi_readiness(*args)
        assert result['ready'] is False and result['missing']


def test_seed_rows_bind_content_as_a_multiset_not_upload_order(m):
    world = multi_world(m)
    world['seeds'].reverse()
    assert multi_ready(m, world)['ready'] is True
    world['seeds'][0] = world['seeds'][1]
    assert multi_ready(m, world)['missing'] == ['seed:rows']


def test_no_reduced_threshold_can_satisfy_the_minimum_commit(m):
    world = multi_world(m)
    reduced = 1024 * 1024
    world['record']['thresholds']['minimum'] = reduced
    world['record']['artifacts']['minimum']['threshold'] = reduced
    world['layouts']['minimum'] = real_layouts(m, reduced, m.simulate_partition(CORES, HEADER - 2, reduced)['parts'])
    missing = multi_ready(m, world)['missing']
    assert 'threshold:committed:minimum' in missing
    session = (Path(__file__).resolve().parent / 'cnt_firefox_matrix_session.py').read_text()
    assert session.count("value = matrix.THRESHOLD_MIN") == 1 and 'THRESHOLD_MIN //' not in session


def test_first_split_empty_part_is_never_ready_even_when_consistent(m):
    cores = [m.THRESHOLD_MIN, 1000, 1000]
    layouts = real_layouts(m, m.THRESHOLD_MIN, [[], [0, 1, 2]], cores)
    consistency = m.partition_layouts(layouts, m.THRESHOLD_MIN)
    assert consistency['status'] == 'CONSISTENT' and consistency['empty_parts'] == 1
    assert False in consistency['well_formed']


def test_partition_layouts_positive_negative_and_incomplete(m):
    world = multi_world(m)
    minimum = world['layouts']['minimum']
    assert m.partition_layouts(minimum, m.THRESHOLD_MIN) == {
        'status': 'CONSISTENT', 'observed_part_sizes': [1, 2, 2], 'simulated_part_sizes': [1, 2, 2],
        'well_formed': [True, True, True], 'empty_parts': 0}
    assert m.partition_layouts(minimum, m.THRESHOLD_MIN + 30000000)['status'] == 'INCONSISTENT'
    assert m.partition_layouts(minimum, None)['status'] == 'INCOMPLETE_EVIDENCE'
    assert m.partition_layouts(minimum, str(m.THRESHOLD_MIN))['status'] == 'INCOMPLETE_EVIDENCE'
    broken = [dict(minimum[0], native_template=False)] + minimum[1:]
    assert m.partition_layouts(broken, m.THRESHOLD_MIN)['status'] == 'NOT_NATIVE_TEMPLATE'
    assert m.partition_layouts([], m.THRESHOLD_MIN)['status'] == 'NOT_NATIVE_TEMPLATE'
    assert m.partition_layouts([{'native_template': True, 'settings_header': True}], 7)['status'] == \
        'NOT_NATIVE_TEMPLATE'
    # The bytes wrapper agrees with the layout form on real native-template bytes.
    world_small = [p for p in world['parts']['minimum']]
    assert m.partition_consistency(world_small, 10 ** 9)['status'] == 'INCONSISTENT'


def test_partition_simulation_is_exact_in_utf8_bytes_for_non_ascii_content(m, export):
    value = json.loads(export)
    value['chunks'][1]['file']['name'] = 'grüße-é中.png'  # non-ASCII, several UTF-8 bytes each
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    layout = m.part_layout(raw)
    threshold = m.flip_threshold(layout['chunk_core_bytes'], layout['header_bytes'])
    groups = m.simulate_partition(layout['chunk_core_bytes'], layout['header_bytes'], threshold)['parts']
    root = json.loads(raw)
    header = raw[:raw.index(b'"chunks":[') + len(b'"chunks":[')]
    chunks = [json.dumps(c, separators=(',', ':'), ensure_ascii=False).encode() for c in root['chunks']]
    parts = [(header if n == 0 else b'{"chunks":[') + b','.join(chunks[i] for i in g) + b']}'
             for n, g in enumerate(groups)]
    assert m.partition_consistency(parts, threshold)['status'] == 'CONSISTENT'


def test_header_digit_width_fixpoint_edges(m):
    # 9 -> 8 digits: the predicted T falls below 10**8, so the header loses one byte and T one.
    layout = {'native_template': True, 'settings_header': True, 'header_bytes': 2000,
              'chunk_core_bytes': [24999000, 24999000, 24999000, 25000000]}
    flip = m.flip_threshold(layout['chunk_core_bytes'], 2000)
    prediction = m.layout_prediction(layout, m.THRESHOLD_DEFAULT)
    assert flip >= 10 ** 8 or prediction['threshold'] < 10 ** 8
    shrink = {**layout, 'chunk_core_bytes': [24999000, 24999000, 24999000, 24990000]}
    t9 = m.flip_threshold(shrink['chunk_core_bytes'], 2000)
    p = m.layout_prediction(shrink, m.THRESHOLD_DEFAULT)
    assert t9 < 10 ** 8 and p['converged'] is True and p['header_adjusted_bytes'] == 1999 and p['threshold'] == t9 - 1
    # Exactly 10**8 keeps nine digits: no adjustment.
    exact = {**layout, 'header_bytes': 2000 + (10 ** 8 - flip)}
    q = m.layout_prediction(exact, m.THRESHOLD_DEFAULT)
    assert q['threshold'] == 10 ** 8 and q['header_adjusted_bytes'] == exact['header_bytes']
    # An 8-digit calibration threshold adjusting up to 9 digits gains one byte.
    r = m.layout_prediction(exact, m.THRESHOLD_MIN)
    assert r['header_adjusted_bytes'] == exact['header_bytes'] + 1 and r['converged'] is True
    with pytest.raises(m.VerificationError):
        m.layout_prediction(layout, None)
    with pytest.raises(m.VerificationError):
        m.layout_prediction(layout, '419430400')


def test_a_non_converging_fixpoint_is_never_settable(m, monkeypatch):
    values = iter([10 ** 8, 10 ** 8 - 1] * 4)
    monkeypatch.setattr(m, 'flip_threshold', lambda cores, header, footer_bytes=2: next(values))
    layout = {'native_template': True, 'settings_header': True, 'header_bytes': 2000, 'chunk_core_bytes': [1, 2]}
    prediction = m.layout_prediction(layout, m.THRESHOLD_DEFAULT)
    assert prediction['converged'] is False and prediction['in_ui_range'] is False
    assert m.classify_boundary(prediction, 2, 1, prediction['header_adjusted_bytes']) == 'BOUNDARY_NOT_SETTABLE'


def test_same_width_volatile_prefs_do_not_drift_the_header_and_wider_ones_do(m):
    calibration = multi_value(m, m.THRESHOLD_DEFAULT)
    calibration['settings']['prefs'].update(background_change_time=1700000000000, current_background_id='multi0')
    cal = split(calibration, [list(range(5))])[0]
    prediction = dict(m.boundary_prediction(cal, m.THRESHOLD_DEFAULT), in_ui_range=True)
    t = prediction['threshold']
    def at_t(**volatile):
        value = multi_value(m, t)
        value['settings']['prefs'].update(background_change_time=1700000000000, current_background_id='multi0')
        value['settings']['prefs'].update(volatile)
        return m.part_layout(split(value, [[0, 1, 2, 3], [4]])[0])['header_bytes']
    assert m.classify_boundary(prediction, 2, 1, at_t()) == 'EXACT_BOUNDARY_OBSERVED'
    same = at_t(background_change_time=1700000009999, current_background_id='multi4')
    assert m.classify_boundary(prediction, 2, 1, same) == 'EXACT_BOUNDARY_OBSERVED'
    wider = at_t(current_background_id='multi4-renamed')
    assert m.classify_boundary(prediction, 2, 1, wider) == 'PREDICTION_HEADER_DRIFT'


def test_export_threshold_is_the_exports_own_int_pref(m):
    assert m.export_threshold(m.fingerprint([split(multi_value(m, 52428800), [list(range(5))])[0]])) == 52428800
    value = multi_value(m, m.THRESHOLD_MIN)
    value['settings']['prefs']['one_backup_file_size_in_bytes'] = '52428800'
    assert m.export_threshold(m.fingerprint([split(value, [list(range(5))])[0]])) is None
    for bad in (None, {}, {'settings': None}, {'settings': {'prefs': {}}}):
        assert m.export_threshold(bad) is None


# --- B input proofs ---------------------------------------------------------------------------------

def b_input(m, case, parts=None, ready=True, same_root=True):
    """(matrix_inputs, input parts, unmutated parts, selected bytes) as the preflight materializes one B
    dependent from the same-root S-MULTI minimum parts."""
    entry = m.case(case)
    original = list(parts if parts is not None else multi_world(m)['parts']['minimum'])
    source, mutation = list(original), None
    if entry['mutation']:
        at = len(source) - 1 if entry['mutate_part'] == -1 else entry['mutate_part'] - 1
        source[at], mutation = m.mutate(source[at], entry['mutation'])
        mutation['part_number'] = at + 1
    selection = m.select_parts(source, entry['selection'])
    inputs = {'source_case': 'S-MULTI', 'artifact': 'minimum', 'selection_kind': entry['selection'],
              'source': [{'part_number': n, 'bytes': len(r), 'sha256': sha(r)} for n, r in enumerate(source, 1)],
              'mutation': mutation,
              'selection': [{'named_part': named, 'slot': slot, 'part_number': number, 'sha256': sha(raw)}
                            for named, raw, number, slot in selection],
              'source_readiness': {'ready': ready, 'same_root': same_root,
                                   'minimum_part_sha256': [sha(r) for r in original]}}
    if mutation:
        inputs['original'] = [{'part_number': n, 'bytes': len(r), 'sha256': sha(r)} for n, r in enumerate(original, 1)]
    return inputs, source, original, [raw for _, raw, _, _ in selection]


def proof(m, case, inputs, source, original, selected):
    return m.multipart_input_proof(m.case(case), inputs, source, original, selected)


@pytest.mark.parametrize('case', B_DEPENDENTS)
def test_every_b_selection_is_proven_before_file_selection(m, case):
    out = proof(m, case, *b_input(m, case))
    assert out['proven'] is True, out
    entry = m.case(case)
    assert out['selection_class'] == entry['selection'] and out['source_part_count'] == 3
    assert out['declared_relation'] == m.MULTIPART_SELECTIONS[entry['selection']]
    assert out['selected_ordinals'] == {'ordered': [1, 2, 3], 'reversed': [3, 2, 1], 'no_part_1': [2, 3],
                                        'no_middle': [1, 3], 'duplicate_middle': [1, 2, 3, 2],
                                        'truncate_last': [1, 2, 3], 'bad_data_part_2': [1, 2, 3]}[entry['selection']]
    assert out['middle_ordinal'] == (2 if entry['selection'] in ('no_middle', 'duplicate_middle') else None)
    assert out['mutation_proof'] == {'T-MULTI-TRUNC': 'TRUNCATED_PREFIX_PROVEN',
                                     'T-MULTI-BADDATA': 'DATA_URL_REPLACED_PROVEN'}.get(case, 'NOT_APPLICABLE')
    assert out['mutated_part'] == {'T-MULTI-TRUNC': 3, 'T-MULTI-BADDATA': 2}.get(case)
    assert m.project(out) == out and ids_absent(m, out)


def _swap(items):
    items[0], items[1] = items[1], items[0]


PROOF_DAMAGE = {
    'wrong-order': ('T-MULTI-ORDERED', lambda m, i, s, o, sel: (_swap(i['selection']), _swap(sel)),
                    'selection_class'),
    'extra-part': ('T-MULTI-NO-P1', lambda m, i, s, o, sel: (i['selection'].insert(0, {
        'named_part': 1, 'slot': 0, 'part_number': 1, 'sha256': sha(s[0])}), sel.insert(0, s[0])), 'selection_class'),
    'missing-part': ('T-MULTI-REVERSED', lambda m, i, s, o, sel: (i['selection'].pop(), sel.pop()), 'selection_class'),
    'wrong-middle': ('T-MULTI-NO-MIDDLE', lambda m, i, s, o, sel: (
        i['selection'].__setitem__(1, {'named_part': 2, 'slot': 0, 'part_number': 2, 'sha256': sha(s[1])}),
        sel.__setitem__(1, s[1])), 'selection_class'),
    'dup-wrong-part': ('T-MULTI-DUP', lambda m, i, s, o, sel: (
        i['selection'].__setitem__(3, {'named_part': 3, 'slot': 1, 'part_number': 3, 'sha256': sha(s[2])}),
        sel.__setitem__(3, s[2])), 'selection_class'),
    'differing-bytes': ('T-MULTI-ORDERED', lambda m, i, s, o, sel: sel.__setitem__(2, sel[2] + b' '),
                        'selection_bytes_equal_input'),
    'tampered-original': ('T-MULTI-BADDATA', lambda m, i, s, o, sel: o.__setitem__(0, o[0] + b' '),
                          'unmutated_input_equals_ready_source'),
    'untouched-part-changed': ('T-MULTI-TRUNC', lambda m, i, s, o, sel: s.__setitem__(0, s[0] + b' '),
                               'untouched_parts_byte_identical'),
    'wrong-truncation': ('T-MULTI-TRUNC', None, 'mutation_proof'),
    'extra-edit': ('T-MULTI-BADDATA', None, 'mutation_proof'),
    'record-mismatch': ('T-MULTI-BADDATA', lambda m, i, s, o, sel: i['mutation'].update(part_number=1),
                        'mutation_record_binds'),
    'unready-source': ('T-MULTI-ORDERED', lambda m, i, s, o, sel: i['source_readiness'].update(ready=False),
                       'source_binding'),
    'other-root': ('T-MULTI-DUP', lambda m, i, s, o, sel: i['source_readiness'].update(same_root=False),
                   'source_binding'),
    'ready-digests-differ': ('T-MULTI-NO-P1', lambda m, i, s, o, sel: i['source_readiness'].update(
        minimum_part_sha256=['0' * 64] * 3), 'unmutated_input_equals_ready_source'),
    'undeclared-mutation': ('T-MULTI-NO-MIDDLE', lambda m, i, s, o, sel: i.update(mutation={'mutation': 'x'}),
                            'mutation_record_binds'),
}


@pytest.mark.parametrize('damage', sorted(PROOF_DAMAGE))
def test_each_b_proof_refusal(m, damage):
    case, edit, fact = PROOF_DAMAGE[damage]
    inputs, source, original, selected = b_input(m, case)
    if damage == 'wrong-truncation':
        cut = source[-1][:len(original[-1]) // 2]
        source[-1], selected[-1] = cut, cut
        inputs['source'][-1]['sha256'] = inputs['selection'][-1]['sha256'] = inputs['mutation']['after_sha256'] = sha(cut)
    elif damage == 'extra-edit':
        value = json.loads(source[1])
        value['chunks'][0]['data']['i'] = '99'
        raw = json.dumps(value, separators=(',', ':')).encode()
        source[1], selected[1] = raw, raw
        inputs['source'][1]['sha256'] = inputs['selection'][1]['sha256'] = inputs['mutation']['after_sha256'] = sha(raw)
    else:
        edit(m, inputs, source, original, selected)
    out = proof(m, case, inputs, source, original, selected)
    assert out['proven'] is False, damage
    if fact == 'selection_class':
        assert out['selection_class'] == 'UNEXPECTED'
    elif fact == 'mutation_proof':
        assert out['mutation_proof'] == 'UNPROVEN'
    else:
        assert out[fact] is False, (damage, out)


def test_a_two_part_source_is_never_a_b_input(m):
    world = multi_world(m)
    two = split(multi_value(m, m.THRESHOLD_MIN), [[0, 1, 2], [3, 4]])
    for case in B_DEPENDENTS:
        if m.case(case)['selection'] in ('no_middle', 'duplicate_middle'):
            with pytest.raises(m.VerificationError):
                b_input(m, case, two)
            continue
        assert proof(m, case, *b_input(m, case, two))['proven'] is False, case
    assert proof(m, 'T-MULTI-ORDERED', *b_input(m, 'T-MULTI-ORDERED', world['parts']['minimum']))['proven']


@pytest.mark.parametrize('bad', range(len(MALFORMED)))
def test_b_proof_is_total_and_fixed_shape(m, bad):
    value = MALFORMED[bad]
    for case in B_DEPENDENTS + ['S-MULTI', 'E-TOP', 'D-TRUNC-P1']:
        for args in ((value, [], [], []), (value, value or [], [], []), ({}, [b'x'], [b'x'], [b'x'])):
            try:
                out = m.multipart_input_proof(m.case(case), *args)
            except TypeError:
                pytest.fail('not total')
            assert out['proven'] is False and m.project(out) == out
    assert m.multipart_input_proof(m.case('E-TOP'), {}, [], [], [])['case'] is None


# --- multipart evidence -----------------------------------------------------------------------------

def b_record(m, case, post_parts, completion='COMPLETED', recorded=False, ribbon=False, ribbon_gate='HIDDEN',
             codes=(), silent=(), proven=True):
    inputs, source, original, selected = b_input(m, case)
    record = {'restores': [{'completion': completion, 'restore_error': recorded, 'error_codes': list(codes),
                            'silent_codes': list(silent), 'start_observed': True, 'transition_end_observed': True,
                            'error_ribbon_seen': ribbon, 'selected_files': len(selected),
                            'backgrounds_dom_after': 5}],
              'artifacts': {'post': {'closure': 'CLOSED', 'complete': True, 'parts': [{} for _ in post_parts],
                                     'derived': m.fingerprint(post_parts)['derived']}},
              'pre_restore_error_ribbon': ribbon_gate,
              'multipart_input': dict(proof(m, case, inputs, source, original, selected), proven=proven),
              'predictions': {k: {'predicted': v, 'status': 'MATCH'} for k, v in m.case(case)['predictions'].items()}}
    native = sorted(zip([s['named_part'] for s in inputs['selection']], selected), key=lambda pair: pair[0])
    chosen = {'native_order': m.fingerprint([raw for _, raw in native]), 'selection_order': m.fingerprint(selected)}
    return record, inputs, m.fingerprint(source), m.fingerprint(original), chosen


def b_evidence(m, case, pre, post_parts, **kw):
    record, inputs, given, original, chosen = b_record(m, case, post_parts, **kw)
    return m.multipart_evidence(m.case(case), {'pre': pre, 'post': m.fingerprint(post_parts)}, given, original,
                                chosen, record, inputs)


def fresh_b(m):
    return fresh(m)


def minimum_parts(m):
    return multi_world(m)['parts']['minimum']


def test_ordered_full_restore_reads_applied_exact_order_and_a_prediction_only_match(m):
    evidence = b_evidence(m, 'T-MULTI-ORDERED', fresh_b(m), minimum_parts(m))
    assert evidence['evidence'] == 'OBSERVED' and evidence['application'] == 'APPLIED'
    assert evidence['rows']['row_relation'] == 'SOURCE_ROWS_EXACT_ORDER'
    assert evidence['rows']['missing_source_parts'] == [] and evidence['rows']['duplicated_source_parts'] == []
    assert [o['source_part'] for o in evidence['rows']['post_row_origins']] == [1, 2, 2, 3, 3]
    assert evidence['components']['backgrounds'] == 'EQUAL_TO_SOURCE'
    assert evidence['semantics']['post_vs_source'] == 'SEMANTIC_EQUAL'
    assert evidence['settings']['threshold_pref_class'] == 'SOURCE_MINIMUM'
    prediction = evidence['predictions']['backgrounds']
    assert prediction['status'] == 'MATCH' and prediction['basis'] == m.MULTIPART_PREDICTION_BASIS
    assert evidence['prediction_scope'] == 'PREDICTION_ONLY_NOT_ASSERTED'
    # No ribbon after completion is still UNKNOWN under partial suppression.
    assert evidence['completion']['restore_error'] == 'UNKNOWN' and evidence['completion']['state_consistent']
    assert m.project(evidence) == evidence and ids_absent(m, evidence) and 'multi0' not in json.dumps(evidence)
    assert 'data:' not in json.dumps(evidence)


def test_a_restore_split_into_fewer_parts_still_compares_by_content(m):
    post = split(multi_value(m, m.THRESHOLD_MIN), [list(range(5))])
    evidence = b_evidence(m, 'T-MULTI-ORDERED', fresh_b(m), post)
    assert evidence['semantics']['post_vs_source'] == 'SEMANTIC_EQUAL' and evidence['post']['part_count'] == 1


def test_no_signal_or_unproven_or_ungated_ordered_restore_is_never_a_match(m):
    for kw in ({'completion': 'DEADLINE_NO_SIGNAL', 'recorded': None}, {'proven': False}):
        evidence = b_evidence(m, 'T-MULTI-ORDERED', fresh_b(m), minimum_parts(m), **kw)
        assert evidence['predictions']['backgrounds']['status'] == 'UNOBSERVED', kw
    evidence = b_evidence(m, 'T-MULTI-ORDERED', fresh_b(m), minimum_parts(m), proven=False)
    assert evidence['evidence'] == 'INCOMPLETE_EVIDENCE' and evidence['rows']['row_relation'] == 'INCOMPLETE_EVIDENCE'
    assert set(evidence['components'].values()) == {'INCOMPLETE_EVIDENCE'}
    assert evidence['source']['original_semantic_sha256'] is not None  # digests still disclosed


def test_reversed_selection_normalized_or_permuted_is_observed_not_assumed(m):
    same = b_evidence(m, 'T-MULTI-REVERSED', fresh_b(m), minimum_parts(m))
    assert same['rows']['row_relation'] == 'SOURCE_ROWS_EXACT_ORDER'
    assert same['semantics']['post_vs_selection_native_order'] == 'SEMANTIC_EQUAL'
    assert same['semantics']['post_vs_selection_order'] == 'SEMANTIC_DIFFERENT'
    value = multi_value(m, m.THRESHOLD_MIN)
    value['chunks'].reverse()
    permuted = b_evidence(m, 'T-MULTI-REVERSED', fresh_b(m), split(value, [[0], [1, 2], [3, 4]]))
    assert permuted['rows']['row_relation'] == 'SOURCE_ROWS_PERMUTED'
    assert permuted['predictions']['backgrounds']['status'] == 'MISMATCH'


def test_sentinel_effects_are_independent_of_error_reporting(m):
    loud = {'completion': 'ERROR_REPORTED', 'recorded': True, 'ribbon': True}
    kept_post = [json.dumps(sentinel_value(m), separators=(',', ':')).encode()]
    empty = sentinel_value(m)
    empty['chunks'] = []
    gone_post = [json.dumps(empty, separators=(',', ':')).encode()]
    for post in (kept_post, gone_post):
        clean, error = (b_evidence(m, 'T-MULTI-NO-P1', sentinel(m), post, **kw) for kw in ({}, loud))
        # Identical state readings whether or not an error was reported or a ribbon seen.
        for key in ('components', 'state_effect', 'rows', 'prior_residue', 'semantics'):
            assert clean[key] == error[key], key
        assert (clean['completion']['restore_error'], error['completion']['restore_error']) == ('UNKNOWN', 'TRUE')
    kept = b_evidence(m, 'T-MULTI-NO-P1', sentinel(m), kept_post, **loud)
    assert kept['state_effect'] == 'STATE_PRESERVED' and kept['rows']['row_relation'] == 'PRE_STATE_ONLY'
    assert kept['rows']['missing_source_parts'] == [1, 2, 3]
    # An error and a ribbon never imply the sentinel was preserved: here its rows are destroyed.
    gone = b_evidence(m, 'T-MULTI-NO-P1', sentinel(m), gone_post, **loud)
    assert gone['components']['backgrounds'] == 'DESTROYED' and gone['rows']['row_relation'] == 'NO_ROWS'
    assert gone['components']['tasks'] == 'REPLACED_BY_INPUT'  # the selected parts carry no tasks
    assert gone['state_effect'] != 'STATE_PRESERVED'


def test_missing_middle_and_partial_application_are_classified(m):
    value = multi_value(m, m.THRESHOLD_MIN)
    value['chunks'] = [value['chunks'][0]] + value['chunks'][3:]
    evidence = b_evidence(m, 'T-MULTI-NO-MIDDLE', sentinel(m), split(value, [[0], [1, 2]]))
    assert evidence['rows']['row_relation'] == 'SOURCE_SUBSET_IN_ORDER'
    assert evidence['rows']['missing_source_parts'] == [2]
    # Post equals the actual selected input (parts 1 and 3 in native order), not the unmutated source.
    assert evidence['components']['backgrounds'] == 'REPLACED_BY_INPUT'
    assert evidence['semantics']['post_vs_source'] == 'SEMANTIC_DIFFERENT'
    mixed = multi_value(m, m.THRESHOLD_MIN)
    mixed['chunks'] = sentinel_value(m)['chunks'] + mixed['chunks'][:1]
    partial = b_evidence(m, 'T-MULTI-BADDATA', sentinel(m), split(mixed, [[0, 1, 2]]))
    assert partial['rows']['row_relation'] == 'MIXED_SOURCE_AND_PRE_STATE'
    assert partial['state_effect'] in ('STATE_PARTIALLY_RETAINED', 'STATE_ALTERED')


def test_duplicate_selection_reports_duplicated_source_rows_when_present(m):
    value = multi_value(m, m.THRESHOLD_MIN)
    value['chunks'] = value['chunks'] + value['chunks'][1:3]
    evidence = b_evidence(m, 'T-MULTI-DUP', sentinel(m), split(value, [[0], [1, 2], [3, 4, 5, 6]]))
    assert evidence['rows']['row_relation'] == 'SOURCE_ROWS_DUPLICATED'
    assert evidence['rows']['duplicated_source_parts'] == [2]


def test_trunc_inherited_predictions_follow_the_d_rule(m):
    preserved = [json.dumps(sentinel_value(m), separators=(',', ':')).encode()]
    clean = b_evidence(m, 'T-MULTI-TRUNC', sentinel(m), preserved)
    assert {v['status'] for v in clean['predictions'].values()} == {'UNOBSERVED'}  # UNKNOWN tri-state
    loud = b_evidence(m, 'T-MULTI-TRUNC', sentinel(m), preserved, completion='ERROR_REPORTED', recorded=True,
                      ribbon=True)
    assert {v['status'] for v in loud['predictions'].values()} == {'MATCH'}
    assert all(v['basis'] == m.PREDICTION_BASIS for v in loud['predictions'].values())
    assert set(loud['predictions']) == {'backgrounds', 'custom_code'}


def test_a_b_completion_without_a_hidden_gate_reading_is_unknown_and_inconsistent(m):
    for gate in ('VISIBLE', 'UNREADABLE', None):
        evidence = b_evidence(m, 'T-MULTI-ORDERED', fresh_b(m), minimum_parts(m), ribbon_gate=gate)
        assert (evidence['completion']['restore_error'], evidence['completion']['state_consistent']) == (
            'UNKNOWN', False)


def test_s_multi_source_block_projects_readiness_boundary_and_partition(m):
    world = multi_world(m)
    record = world['record']
    record['classifications'] = {'multi_source_ready': True, 'multi_source_missing': [], 'boundary':
                                 'EXACT_BOUNDARY_OBSERVED', 'partition': 'CONSISTENT'}
    record['partition'] = {label: m.partition_layouts(world['layouts'][label], record['artifacts'][label]['threshold'])
                           for label in m.MULTI_LABELS}
    evidence = m.multipart_evidence(m.case('S-MULTI'), {}, None, None, None, record, None)
    block = evidence['source']
    assert evidence['role'] == 'SOURCE' and block['readiness']['ready'] is True
    assert block['supported_threshold'] == {'minimum': 52428800, 'default': 419430400, 'maximum': 419430400}
    assert block['calibration_threshold_class'] == 'DEFAULT' and block['predicted_in_range'] is True
    assert block['header']['relation'] == 'HEADER_MATCH' and block['boundary'] == 'EXACT_BOUNDARY_OBSERVED'
    minimum = block['exports']['minimum']
    assert minimum['part_count'] == 3 and minimum['ordinal_class'] == 'CONTIGUOUS_1_N'
    assert [p['chunk_count'] for p in minimum['parts']] == [1, 2, 2] and minimum['threshold_matches_intended']
    assert [p['sha256'] for p in minimum['parts']] == [sha(r) for r in world['parts']['minimum']]
    assert block['exports']['at_t']['part_count'] == 2 and block['exports']['at_t_plus_1']['part_count'] == 1
    assert m.project(evidence) == evidence and 'data:' not in json.dumps(evidence)
    record['boundary_header_at_t'] += 3
    assert m.multipart_evidence(m.case('S-MULTI'), {}, None, None, None, record, None)['source']['header'][
        'relation'] == 'HEADER_DRIFT'


@pytest.mark.parametrize('case', B_DEPENDENTS + ['S-MULTI'])
@pytest.mark.parametrize('bad', range(len(MALFORMED)))
def test_multipart_evidence_is_total_over_malformed_input(m, case, bad):
    value = MALFORMED[bad]
    records = [value, {'restores': 'x', 'artifacts': []}, {'multipart_input': value, 'restores': [value]},
               {'restores': [{'completion': '/raw', 'restore_error': 'yes', 'error_codes': '/Users/x',
                              'silent_codes': [{'a': 1}], 'selected_files': -1, 'start_observed': True}],
                'artifacts': {'post': {'closure': 'CLOSED', 'derived': 'x', 'parts': 'y'}},
                'multipart_input': {'proven': True, 'selected_ordinals': ['/raw']},
                'classifications': {'multi_source_missing': ['/raw']}, 'partition': {'minimum': value}}]
    for record in records:
        for selected in (value, {'native_order': value, 'selection_order': value}):
            evidence = m.multipart_evidence(m.case(case), {'pre': value, 'post': value}, value, value, selected,
                                            record, {'source': value, 'selection': value})
            assert evidence['case'] == case and m.project(evidence) == evidence
            if case != 'S-MULTI':
                assert evidence['evidence'] == 'INCOMPLETE_EVIDENCE'
    assert m.multipart_evidence(m.case('E-TOP'), {}, None, None, None, {}, {}) is None
    assert m.multipart_evidence(m.case('D-EMPTY-SELECTION'), {}, None, None, None, {}, {}) is None
