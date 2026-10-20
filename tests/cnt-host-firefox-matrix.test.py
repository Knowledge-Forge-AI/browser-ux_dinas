"""R6 Firefox matrix host runner contracts: every subprocess is faked.

No browser, codesign, Nix, pytest child, captured code or host scratch is used.
"""
import hashlib
import json
from pathlib import Path

import pytest

OTHER_CLAIMS = ('bux-c7-host-d2.claim', 'bux-r5-chrome-startup.claim', 'bux-r5-chrome-pair.claim',
                'bux-r5-chrome-c1a-startup.claim', 'bux-r5-chrome-c1a-pair.claim')
CONSUMED = 'bux-r6-firefox-native-matrix.claim'
# Consumed by S-RICH REPAIR2 HOST1 (accepted as the dependency source); retained and refused.
REPAIR2_CLAIM = 'bux-r6-firefox-native-matrix-srich-repair2.claim'
# Consumed by RICH-VALID HOST1 (manager-accepted); retained and refused.
RICH_VALID_CLAIM = 'bux-r6-firefox-native-matrix-rich-valid.claim'
# Consumed by MALFORMED-D HOST2 (manager-accepted characterization); retained and refused.
MALFORMED_D_CLAIM = 'bux-r6-firefox-native-matrix-malformed-d.claim'
# Consumed by COMPAT-E HOST1 (manager-accepted characterization); retained and refused.
COMPAT_E_CLAIM = 'bux-r6-firefox-native-matrix-compat-e.claim'
# MULTIPART-B-PREP1: the one runnable budget and its new claim.
B_BUDGET = 'multipart-b'
B_CLAIM = 'bux-r6-firefox-native-matrix-multipart-b.claim'
B_CASES = ['S-MULTI', 'T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1', 'T-MULTI-NO-MIDDLE', 'T-MULTI-DUP',
           'T-MULTI-TRUNC', 'T-MULTI-BADDATA']
# Proposed by REPAIR1, never created: refused by name and never touched.
REPAIR1_CLAIM = 'bux-r6-firefox-native-matrix-srich-repair1.claim'
# Test-only compat-E-shaped budget (injected by the `w` fixture): keeps the accepted COMPAT-E runner and
# projection behaviour covered after the compat-e budget itself was consumed and retired. Never shipped.
BUDGET = 'synthetic-compat-e-shape'
NEW_CLAIM = 'bux-r6-test-synthetic-compat-e-shape.claim'
CASES = ['S-RICH', 'E-TOP', 'E-BG', 'E-PREF', 'E-CODE', 'E-TASK', 'E-ABSENT-OPT', 'E-VERSION', 'E-THEMEID-DUP',
         'E-MODE-THEME']
# Test-only malformed-D-shaped budget: keeps the accepted D projection covered after the malformed-d
# budget itself was consumed and retired. Never shipped.
D_SHAPE = 'synthetic-malformed-d-shape'
D_SHAPE_CLAIM = 'bux-r6-test-synthetic-malformed-d-shape.claim'
D_CASES = ['S-RICH', 'D-TRUNC-P1', 'D-NO-CHUNKS', 'D-CHUNKS-TYPE', 'D-BAD-DATAURL', 'D-NAME-NO-P1']
# (mutation, edit, target) mutate() records for each E case; E-TASK's row index is fixture-shaped.
E_MUTATED = {'E-TOP': ('unknown_top_level', 'insert', ''),
             'E-BG': ('unknown_background_data', 'insert', 'chunks.0.data'),
             'E-PREF': ('unknown_pref', 'insert', 'settings.prefs'),
             'E-CODE': ('unknown_custom_code', 'insert', 'custom_code'),
             'E-TASK': ('unknown_task', 'insert', 'chunks.1.tasks.0'),
             'E-ABSENT-OPT': ('absent_optional_prefs', 'remove', 'settings.prefs'),
             'E-VERSION': ('pref_version_older', 'replace', 'settings.prefs.version'),
             'E-THEMEID-DUP': ('synthetic_theme_id_duplicate', 'insert', 'chunks.0-1.data'),
             'E-MODE-THEME': ('pref_mode_theme_background', 'replace', 'settings.prefs.mode')}
MUTATED = {'D-TRUNC-P1': ('truncate_json', 'truncate', None, False),
           'D-NO-CHUNKS': ('drop_chunks', 'remove', 'chunks', True),
           'D-CHUNKS-TYPE': ('chunks_not_array', 'replace', 'chunks', True),
           'D-BAD-DATAURL': ('invalid_data_url', 'replace', 'chunks.0.file.background', True)}
CONSUMED_ALL = {CONSUMED: True, REPAIR2_CLAIM: True, RICH_VALID_CLAIM: True, MALFORMED_D_CLAIM: True,
                COMPAT_E_CLAIM: True}
RETAINED = {CONSUMED: '{"consumed": "HOST1"}\n', REPAIR2_CLAIM: '{"consumed": "SRICH-REPAIR2"}\n',
            RICH_VALID_CLAIM: '{"consumed": "RICH-VALID-HOST1"}\n',
            MALFORMED_D_CLAIM: '{"consumed": "MALFORMED-D-HOST2"}\n',
            COMPAT_E_CLAIM: '{"consumed": "COMPAT-E-HOST1"}\n'}
SOURCE_PART = {'index': 0, 'name_class': 'NATIVE_PART_1', 'bytes': 7271, 'sha256': 'a' * 64}
SOURCE_SEMANTIC = 'b' * 64
# Test-only rich-valid-shaped budget: keeps the accepted restore-evidence projection covered after
# the rich-valid budget itself was consumed and retired. Never shipped.
RICH_SHAPE = 'synthetic-rich-shape'
RICH_CASES = ['S-RICH', 'T-RICH', 'T-DISPLACE', 'F-REPEAT']
# Adopted production Firefox 156.0.1 (cnt_firefox_production) and the superseded R4 155.0.1.
PRODUCTION_RUNTIME = '35172d4e392575860ed48cd7e7a45a6eb1a59eacdfef277aced6c5610bbcdab3'
PRODUCTION_EXECUTABLE = 'f2559282d3ef1ceeb0083700e57092c905f043eddb02a9b8ac09009ec9719ac3'
SUPERSEDED_RUNTIME = '6555cd15eb85f2be816fede570f252d5e7154c1c4ecfda372f00f19cc0596f7d'
SUPERSEDED_EXECUTABLE = 'ca4f2108d1000fce089d4c5ace30565f489dfce8d2d98c89b355e7c3ebc40462'


def mutated_sha(case):
    return hashlib.sha256(case.encode()).hexdigest()


def dependent_d(result, case):
    """Synthetic D attempt facts as the preflight and session record them: the (mutated) input, the
    unmutated original for a declared mutation, one restore and a minimal malformed_evidence."""
    source = [{'part_number': 1, 'bytes': SOURCE_PART['bytes'], 'sha256': SOURCE_PART['sha256']}]
    if case in MUTATED:
        mutation, edit, target, parseable = MUTATED[case]
        record = {'mutation': mutation, 'edit': edit, 'part_number': 1, 'parseable': parseable,
                  'before_sha256': SOURCE_PART['sha256'], 'after_sha256': mutated_sha(case),
                  'synthetic_label': None, **({'target': target} if target else {'kept_bytes': 4847})}
        inputs = {'source': [dict(source[0], sha256=mutated_sha(case))], 'original': source, 'mutation': record,
                  'selection': [{'named_part': 1, 'slot': 0, 'part_number': 1, 'sha256': mutated_sha(case)}]}
    else:
        inputs = {'source': source, 'mutation': None,
                  'selection': [{'named_part': 2, 'slot': 0, 'part_number': 1, 'sha256': SOURCE_PART['sha256']}]}
    result['matrix_inputs'] = inputs
    result['matrix']['pre_restore_error_ribbon'] = 'HIDDEN'  # the session gate passed
    result['matrix']['restores'] = [{'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': True,
                                     'error_codes': ['cnt_1556'], 'silent_codes': ['cnt_1436', 'OTHER'],
                                     'start_observed': True, 'transition_end_observed': True,
                                     'error_ribbon_seen': True, 'backgrounds_dom_after': 0, 'selected_files': 1}]
    result['matrix']['malformed_evidence'] = {
        'schema': 'bux-r6-malformed-evidence-v2', 'case': case, 'evidence': 'OBSERVED',
        'source': {'original_semantic_sha256': SOURCE_SEMANTIC,
                   'given_semantic_sha256': None if case in MUTATED and case != 'D-BAD-DATAURL' else
                   (SOURCE_SEMANTIC if case == 'D-NAME-NO-P1' else 'e' * 64)},
        'completion': {'completion': 'DEADLINE_NO_SIGNAL', 'restore_error': 'UNKNOWN'},
        'components': {'backgrounds': 'DESTROYED', 'tasks': 'DESTROYED', 'settings': 'PRESERVED',
                       'custom_code': 'PRESERVED'},
        'state_effect': 'SENTINEL_CONTENT_DESTROYED',
        'live_data_scope': 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'}


def dependent_e(result, case):
    """Synthetic E attempt facts as the preflight and session record them: the mutated input, the
    unmutated original, the recorded pre-restore proof, one clean-looking restore and a minimal
    compat_evidence."""
    mutation, edit, target = E_MUTATED[case]
    source = [{'part_number': 1, 'bytes': SOURCE_PART['bytes'], 'sha256': SOURCE_PART['sha256']}]
    synthetic = case in ('E-THEMEID-DUP', 'E-MODE-THEME')
    record = {'mutation': mutation, 'edit': edit, 'target': target, 'part_number': 1, 'parseable': True,
              'before_sha256': SOURCE_PART['sha256'], 'after_sha256': mutated_sha(case),
              'synthetic_label': 'SYNTHETIC_INPUT_NOT_UI_CREATABLE' if synthetic else None}
    result['matrix_inputs'] = {'source': [dict(source[0], sha256=mutated_sha(case))], 'original': source,
                               'mutation': record,
                               'selection': [{'named_part': 1, 'slot': 0, 'part_number': 1,
                                              'sha256': mutated_sha(case)}]}
    facts = result['matrix']
    facts['pre_restore_error_ribbon'] = 'HIDDEN'  # the session gates passed
    facts['compat_input'] = {'schema': 'bux-r6-compat-input-v1', 'case': case, 'proven': True,
                             'mutation_record_binds': True, 'edit_present': True, 'outside_edit_unchanged': True,
                             'known_components_changed': [], 'unmutated_parts_byte_identical': True,
                             'selection_bytes_equal_input': True, 'selection_class': 'single'}
    facts['restores'] = [{'completion': 'COMPLETED', 'restore_error': False, 'error_codes': [], 'silent_codes': [],
                          'start_observed': True, 'transition_end_observed': True, 'error_ribbon_seen': False,
                          'backgrounds_dom_after': 5, 'selected_files': 1}]
    facts['compat_evidence'] = {
        'schema': 'bux-r6-compat-evidence-v1', 'case': case, 'evidence': 'OBSERVED',
        'input': {'synthetic_input_scope': 'SYNTHETIC_INPUT_NOT_UI_CREATABLE' if synthetic
                  else 'NATIVE_EXPORT_BOUNDED_MUTATION'},
        'source': {'original_semantic_sha256': SOURCE_SEMANTIC, 'given_semantic_sha256': 'e' * 64},
        'completion': {'completion': 'COMPLETED', 'restore_error': 'UNKNOWN'},
        'application': 'APPLIED', 'compat_class': 'UNKNOWN_IGNORED' if case in E_MUTATED and edit == 'insert'
        and not synthetic else 'ACCEPTED_EQUIVALENT_KNOWN_STATE',
        'observation_scope': 'EXACT_CNT_6_12_1_ON_BOUND_FIREFOX_OBSERVATION_NOT_CERTIFICATION'}


MULTI_PARTS = [{'index': n, 'name_class': f'NATIVE_PART_{n + 1}', 'bytes': 41000000 + n, 'sha256': c * 64}
               for n, c in enumerate('123')]
MULTI_SEMANTIC = '9' * 64
B_SLOTS = {'T-MULTI-ORDERED': [(1, 0, 1), (2, 0, 2), (3, 0, 3)], 'T-MULTI-REVERSED': [(3, 0, 3), (2, 0, 2), (1, 0, 1)],
           'T-MULTI-NO-P1': [(2, 0, 2), (3, 0, 3)], 'T-MULTI-NO-MIDDLE': [(1, 0, 1), (3, 0, 3)],
           'T-MULTI-DUP': [(1, 0, 1), (2, 0, 2), (3, 0, 3), (2, 1, 2)],
           'T-MULTI-TRUNC': [(1, 0, 1), (2, 0, 2), (3, 0, 3)], 'T-MULTI-BADDATA': [(1, 0, 1), (2, 0, 2), (3, 0, 3)]}
# (mutation, edit, target, part number, parseable) of the two mutated B cases.
B_MUTATED = {'T-MULTI-TRUNC': ('truncate_json', 'truncate', None, 3, False),
             'T-MULTI-BADDATA': ('invalid_data_url', 'replace', 'chunks.0.file.background', 2, True)}


def source_multi(result):
    """Synthetic S-MULTI facts: readiness true and a closed three-part minimum artifact."""
    facts = result['matrix']
    facts['classifications'].update(multi_source_ready=True, multi_source_missing=[], boundary='EXACT_BOUNDARY_OBSERVED',
                                    partition='CONSISTENT')
    facts['artifacts'] = {'minimum': {'parts': [dict(p) for p in MULTI_PARTS], 'semantic_sha256': MULTI_SEMANTIC,
                                      'source_ready': True, 'closure': 'CLOSED', 'complete': True, 'threshold': 52428800}}
    facts['multipart_evidence'] = {'schema': 'bux-r6-multipart-evidence-v1', 'case': 'S-MULTI', 'role': 'SOURCE',
                                   'evidence': 'OBSERVED',
                                   'source': {'readiness': {'ready': True, 'missing': []},
                                              'boundary': 'EXACT_BOUNDARY_OBSERVED'}}


def dependent_b(result, case):
    """Synthetic B dependent facts as the preflight and session record them: the (mutated) input, the
    unmutated original, the same-root readiness record, the selection, the recorded pre-selection proof,
    one clean-looking restore and a minimal multipart_evidence."""
    source = [{'part_number': n + 1, 'bytes': p['bytes'], 'sha256': p['sha256']} for n, p in enumerate(MULTI_PARTS)]
    inputs = {'source_case': 'S-MULTI', 'artifact': 'minimum', 'source': [dict(s) for s in source], 'mutation': None,
              'source_readiness': {'ready': True, 'same_root': True,
                                   'minimum_part_sha256': [p['sha256'] for p in MULTI_PARTS]}}
    if case in B_MUTATED:
        mutation, edit, target, number, parseable = B_MUTATED[case]
        inputs['original'] = source
        inputs['source'][number - 1]['sha256'] = mutated_sha(case)
        inputs['mutation'] = {'mutation': mutation, 'edit': edit, 'part_number': number, 'parseable': parseable,
                              'before_sha256': source[number - 1]['sha256'], 'after_sha256': mutated_sha(case),
                              'synthetic_label': None, **({'target': target} if target else {'kept_bytes': 7})}
    inputs['selection'] = [{'named_part': named, 'slot': slot, 'part_number': number,
                            'sha256': inputs['source'][number - 1]['sha256']} for named, slot, number in B_SLOTS[case]]
    result['matrix_inputs'] = inputs
    facts = result['matrix']
    facts['pre_restore_error_ribbon'] = 'HIDDEN'  # the session gates passed
    facts['multipart_input'] = {'schema': 'bux-r6-multipart-input-v1', 'case': case, 'proven': True,
                                'source_binding': True, 'selection_class': 'ordered',
                                'selected_ordinals': [n for _, _, n in B_SLOTS[case]]}
    facts['restores'] = [{'completion': 'COMPLETED', 'restore_error': False, 'error_codes': [], 'silent_codes': [],
                          'start_observed': True, 'transition_end_observed': True, 'error_ribbon_seen': False,
                          'backgrounds_dom_after': 5, 'selected_files': len(B_SLOTS[case])}]
    facts['multipart_evidence'] = {
        'schema': 'bux-r6-multipart-evidence-v1', 'case': case, 'role': 'DEPENDENT', 'evidence': 'OBSERVED',
        'source': {'original_semantic_sha256': MULTI_SEMANTIC,
                   'given_semantic_sha256': 'e' * 64 if case in B_MUTATED else MULTI_SEMANTIC},
        'completion': {'completion': 'COMPLETED', 'restore_error': 'UNKNOWN'},
        'rows': {'row_relation': 'SOURCE_ROWS_EXACT_ORDER'}}


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
        self.m, self.d2, self.tmp = m, d2, tmp_path
        scratch = tmp_path / 'scratch'
        scratch.mkdir()
        monkeypatch.setattr(d2, 'SCRATCH', scratch)
        self.scratch = scratch
        self.snapshot = scratch / 'snapshot'
        (self.snapshot / 'tests').mkdir(parents=True)
        names = ['tests/cnt_host_firefox_matrix.py', 'tests/cnt_host_d2.py', 'tests/cnt-native-preflight.py']
        for name in names:
            (self.snapshot / name).write_text('synthetic ' + name + '\n')
        entries = {n: r for n, (r, _) in collect(self.snapshot, names).items()}
        self.inventory_sha = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'))
                                            .encode()).hexdigest()
        self.inventory = scratch / 'snapshot-inventory.json'
        self.inventory.write_text(json.dumps({'sha256': self.inventory_sha, 'entries': entries}))
        monkeypatch.setattr(m, 'RUNNER', self.snapshot / 'tests/cnt_host_firefox_matrix.py')
        monkeypatch.setattr(d2, 'RUNNER', self.snapshot / 'tests/cnt_host_d2.py')
        self.runtime_calls = []
        self.real_bind_runtime = m.firefox.bind_runtime
        monkeypatch.setattr(m.firefox, 'bind_runtime', self.bind_runtime)
        # The historical D1 binder is never a production binder: any call fails loudly.
        monkeypatch.setattr(d2, 'bind_runtime', self.historical_binder)
        monkeypatch.setattr(m, 'signature', lambda runtime: True)
        self.capture = {'xpi_sha256': m.matrix.XPI_SHA256, 'extension_id': 'clear-new-tab@loftyshaky',
                        'version': '6.12.1', 'manifest_version': 3, 'member_count': 129,
                        'verified_member_digests': 21}
        monkeypatch.setattr(m.matrix, 'verify_capture', lambda path: dict(self.capture))
        self.prediction = {'policy_template_sha256': m.ACCEPTED_TEMPLATE,
                           'policy_template_without_configd_sha256': m.ACCEPTED_TEMPLATE_WITHOUT_CONFIGD,
                           'pytest_version': '9.0.0'}
        monkeypatch.setattr(d2, 'predicted_template', lambda python, env, root: dict(self.prediction))
        monkeypatch.setattr(m, 'free_bytes', lambda root: m.MIN_FREE_BYTES)
        self.python = tmp_path / 'store/python-env/bin/python3'
        self.nix_bin = tmp_path / 'store/nix/bin'
        self.nix_bin.mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text('')
        (self.nix_bin / 'nix-store').write_text('')
        (self.nix_bin / 'nix-store').chmod(0o755)
        monkeypatch.setattr(d2, 'STORE', tmp_path / 'store')
        self.root = scratch / 'claim'
        self.root.mkdir()
        self.xpi = scratch / 'retained/clear-new-tab.xpi'
        self.xpi.parent.mkdir()
        self.xpi.write_bytes(b'synthetic capture')
        self.spawned, self.statuses, self.interrupts = [], {}, {}
        # Per-case edits of the synthetic result (the S-RICH source facts, dependent evidence), and
        # hooks run after a case's attempt is written (for example, damaging the S-RICH result).
        self.edits, self.after = {}, {}
        monkeypatch.setattr(d2, 'spawn', self.spawn)
        for name in OTHER_CLAIMS:
            (scratch / name).write_text('{"retained": true}\n')
        # The consumed HOST1 and REPAIR2 claims: unreadable here, so any open would fail loudly.
        self.retained, self.retained_stat = {}, {}
        for name, text in RETAINED.items():
            path = scratch / name
            path.write_text(text)
            self.retained[name], self.retained_stat[name] = path, path.stat()
            path.chmod(0)

    def bind_runtime(self, runtime):
        self.runtime_calls.append(str(runtime))
        return dict(self.m.firefox.IDENTITY)

    @staticmethod
    def historical_binder(runtime):
        raise AssertionError('the historical D1 binder must not bind production')

    def spawn(self, argv, **kw):
        self.spawned.append(argv)
        if '-m' in argv and 'pytest' in argv:
            kw['stdout'].write('15 passed in 1.0s\n')
            kw['stdout'].flush()
            return Proc(0)
        case = argv[argv.index('--matrix-case') + 1]
        attempt = Path(argv[argv.index('--scratch') + 1])
        attempt.mkdir()
        status = self.statuses.get(case, 'MATRIX_ATTEMPT_COMPLETED')
        result = {'status': status, 'native_semantics': 'EXECUTED_CASE_RECORDED', 'captured_code_loaded': True,
                  'matrix': {'case': case, 'completed': True, 'steps': [{'step': 'open_settings', 'status': 'DONE'}],
                             'classifications': {'backgrounds': 'RESTORED'}, 'artifacts': {}}}
        if case == 'S-RICH':
            result['matrix']['classifications'].update(rich_source_ready=True, rich_source_missing=[])
            result['matrix']['artifacts'] = {'rich': {'parts': [dict(SOURCE_PART)], 'semantic_sha256': SOURCE_SEMANTIC,
                                                      'source_ready': True, 'closure': 'CLOSED', 'complete': True}}
        elif case == 'S-MULTI':
            source_multi(result)
        elif case.startswith('T-MULTI-'):
            dependent_b(result, case)
        elif case.startswith('D-'):
            dependent_d(result, case)
        elif case.startswith('E-'):
            dependent_e(result, case)
        else:
            result['matrix_inputs'] = {'source': [{'part_number': 1, 'bytes': SOURCE_PART['bytes'],
                                                   'sha256': SOURCE_PART['sha256']}], 'mutation': None}
            result['matrix']['restore_evidence'] = {'schema': 'bux-r6-restore-evidence-v1', 'case': case,
                                                    'given_semantic_sha256': SOURCE_SEMANTIC}
        self.edits.get(case, lambda r: None)(result)
        (attempt / 'result.json').write_text(json.dumps(result))
        self.after.get(case, lambda: None)()
        return Proc(0 if status == 'MATRIX_ATTEMPT_COMPLETED' else 2, self.interrupts.get(case, 0))

    def argv(self, command, **extra):
        extra.setdefault('budget', BUDGET)
        values = ['--snapshot', str(self.snapshot), '--inventory', str(self.inventory),
                  '--runtime', str(self.tmp / 'Firefox.app'), '--python', str(self.python),
                  '--nix-bin', str(self.nix_bin), '--claim-root', str(self.root), '--capture', str(self.xpi),
                  '--expected-inventory-sha256', self.inventory_sha]
        for key, value in extra.items():
            values += ['--' + key.replace('_', '-'), value]
        return [command] + values

    def bind(self, **extra):
        assert self.m.main(self.argv('bind', **extra)) == 0
        path = sorted(self.root.glob('BIND-*.json'))[-1]
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def run(self, **extra):
        path, digest = self.bind(**{k: v for k, v in extra.items() if k == 'budget'})
        return self.m.main(self.argv('run', bind_record=str(path), bind_record_sha256=digest, **extra))

    def consumed_unchanged(self):
        for name, path in self.retained.items():
            info, before = path.stat(), self.retained_stat[name]
            assert (info.st_ino, info.st_size, info.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
            path.chmod(0o600)
            assert path.read_text() == RETAINED[name]
            path.chmod(0)

    def launched(self):
        return ['pytest' if 'pytest' in argv else argv[argv.index('--matrix-case') + 1] for argv in self.spawned]

    def state(self):
        return json.loads((self.root / 'MATRIX-state.json').read_text())

    def summary(self):
        return json.loads(sorted(self.root.glob('MATRIX-SUMMARY-*.json'))[-1].read_text())


@pytest.fixture
def w(load_module, monkeypatch, tmp_path, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_host_firefox_matrix as m
    world = World(m, tmp_path, monkeypatch)
    # The shipped budgets, before the test-only compat-E-shaped budget is injected.
    world.real_budgets = dict(m.BUDGETS)
    monkeypatch.setitem(m.BUDGETS, BUDGET, {'claim': NEW_CLAIM, 'cases': tuple(CASES), 'categories': ('A', 'E')})
    yield world
    for path in world.retained.values():
        path.chmod(0o600)


# Test-only synthetic subset budget: a second, different bind for mismatch tests. Never shipped.
SUBSET = 'synthetic-subset'


@pytest.fixture
def subset(w, monkeypatch):
    monkeypatch.setitem(w.m.BUDGETS, SUBSET, {'claim': 'bux-r6-test-synthetic-subset.claim',
                                              'cases': ('S-RICH', 'D-TRUNC-P1'), 'categories': ('A', 'D')})
    return w


@pytest.fixture
def d_shape(w, monkeypatch):
    monkeypatch.setitem(w.m.BUDGETS, D_SHAPE, {'claim': D_SHAPE_CLAIM, 'cases': tuple(D_CASES),
                                               'categories': ('A', 'D')})
    return w


@pytest.fixture
def rich_shape(w, monkeypatch):
    monkeypatch.setitem(w.m.BUDGETS, RICH_SHAPE, {'claim': 'bux-r6-test-synthetic-rich-shape.claim',
                                                  'cases': tuple(RICH_CASES), 'categories': ('A', 'C', 'F')})
    return w


def test_bind_launches_nothing_and_claims_nothing(w):
    path, _ = w.bind()
    record = json.loads(path.read_text())
    assert w.spawned == [] and not (w.root / 'MATRIX.claim').exists()
    assert not (w.scratch / NEW_CLAIM).exists()
    assert record['cases'] == CASES and record['budget'] == BUDGET
    assert record['host_claim'] == NEW_CLAIM and record['schema'] == 'bux-r6-firefox-matrix-bind-v3'
    assert record['consumed_claims_present'] == CONSUMED_ALL
    w.consumed_unchanged()
    identity = record['identity']
    assert identity['services'] == w.m.SERVICES and len(identity['services']) == 3
    assert identity['sandbox_disables'] == ['content', 'socket', 'utility-generic']
    assert identity['policy_template_sha256'] == 'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3'
    # The adopted production Firefox 156.0.1, never the superseded 155.0.1.
    assert identity['runtime_sha256'] == PRODUCTION_RUNTIME != SUPERSEDED_RUNTIME
    assert identity['executable_sha256'] == PRODUCTION_EXECUTABLE != SUPERSEDED_EXECUTABLE
    assert identity['firefox'] == {'version': '156.0.1', 'bundle_identifier': 'org.mozilla.firefox',
                                   'bundle_version': '15626.9.21', 'build_id': '20260921121718'}
    assert identity['capture']['xpi_sha256'] == 'bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f'
    assert record['launch_options']['S-RICH'].count('--matrix-input') == 0
    for case in CASES[1:]:
        options = record['launch_options'][case]
        assert options[options.index('--matrix-input') + 1] == '<SOURCE>'
    assert w.runtime_calls  # the runtime identity is checked at bind


@pytest.mark.parametrize('drift', ['runtime', 'template', 'without-configd', 'pytest', 'capture', 'snapshot',
                                   'runner', 'python'])
def test_bind_refuses_drift(w, monkeypatch, drift):
    d2 = w.d2
    if drift == 'runtime':
        monkeypatch.setattr(w.m.firefox, 'bind_runtime',
                            lambda r: d2.require(False, 'Firefox runtime differs from the production runtime'))
    elif drift == 'template':
        w.prediction['policy_template_sha256'] = '0' * 64
    elif drift == 'without-configd':
        w.prediction['policy_template_without_configd_sha256'] = '0' * 64
    elif drift == 'pytest':
        del w.prediction['pytest_version']
    elif drift == 'capture':
        monkeypatch.setattr(w.m.matrix, 'verify_capture',
                            lambda path: w.m.require(False, 'Capture digest mismatch'))
    elif drift == 'snapshot':
        (w.snapshot / 'tests/cnt-native-preflight.py').write_text('changed\n')
    elif drift == 'runner':
        monkeypatch.setattr(w.m, 'RUNNER', w.tmp / 'elsewhere.py')
    else:
        w.python = w.tmp / 'python3'
        w.python.write_text('')
    with pytest.raises(w.m.VerificationError):
        w.m.main(w.argv('bind'))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []


def test_case_subsets_must_be_dependency_closed_and_ordered(w):
    assert w.m.case_order(['S-RICH', 'D-TRUNC-P1']) == ['S-RICH', 'D-TRUNC-P1']
    assert w.m.case_order(CASES) == CASES and w.m.case_order(RICH_CASES) == RICH_CASES
    for bad in (['D-TRUNC-P1'], ['D-TRUNC-P1', 'S-RICH'], ['S-RICH', 'S-RICH'], ['D-EMPTY-SELECTION'],
                ['S-RICH', 'D-EMPTY-SELECTION'], ['S-RICH', 'D-NO-CHUNKS', 'D-TRUNC-P1'],
                ['S-RICH', 'D-NAME-NO-P1', 'D-BAD-DATAURL'], CASES[1:], ['S-RICH', 'D-TRUNC-P1', 'bogus']):
        with pytest.raises(w.m.VerificationError):
            w.m.case_order(bad)


def test_options_are_the_accepted_lane_plus_the_matrix_workload(w):
    plain = w.m.options('S-RICH', 'R', 'A', 'C')
    dependent = w.m.options('T-RICH', 'R', 'A', 'C', 'S')
    for argv in (plain, dependent):
        assert argv[:2] == ['--engine', 'firefox'] and argv.count('--service') == 3
        assert argv.count('--nested-sandbox-exception') == 3
        assert argv[argv.index('--capture-sha256') + 1] == w.m.matrix.XPI_SHA256
        for forbidden in ('--abnormal', '--shutdown-trace', '--parent-probes', '--crash-readback',
                          '--crash-force-enable', '--chrome-rendezvous'):
            assert forbidden not in argv
        assert not [a for a in argv if 'chrome' in a.lower()]
    assert '--matrix-input' not in plain and dependent[dependent.index('--matrix-input') + 1] == 'S'


# --- MULTIPART-B-PREP1: the one runnable budget and claim lineage -------------------------------

def test_multipart_b_is_the_only_shipped_budget_in_exact_order_and_nothing_is_withheld(w):
    assert w.real_budgets == {B_BUDGET: {'claim': B_CLAIM, 'cases': tuple(B_CASES), 'categories': ('B',)}}
    assert w.m.budget(B_BUDGET)['cases'] == tuple(B_CASES) and w.m.case_order(B_CASES) == B_CASES
    entries = [w.m.matrix.case(c) for c in B_CASES]
    assert [e['category'] for e in entries] == ['B'] * 8 and w.m.WITHHELD_CATEGORIES == ()
    # Only S-MULTI is a source; every dependent consumes its same-root minimum artifact.
    assert [e['source'] for e in entries] == [None] + ['S-MULTI'] * 7
    assert {e['artifact'] for e in entries[1:]} == {'minimum'}
    assert [e['profile'] for e in entries] == ['FRESH_SOURCE', 'FRESH_TARGET', 'FRESH_TARGET'] + ['SEEDED_SENTINEL'] * 5
    assert [e['selection'] for e in entries[1:]] == ['ordered', 'reversed', 'no_part_1', 'no_middle',
                                                     'duplicate_middle', 'truncate_last', 'bad_data_part_2']
    assert [e['mutation'] for e in entries[1:]] == [None] * 5 + ['truncate_json', 'invalid_data_url']
    # The complete-set targets stay strict (a no-signal restore fails); the sentinel cases may end silently.
    assert [e['allow_no_signal'] for e in entries[1:]] == [False, False] + [True] * 5
    # No A, C, D, E or F case is in the shipped budget, and the B catalogue is exactly the budget.
    assert [c['id'] for c in w.m.matrix.CASES if c['category'] == 'B'] == B_CASES
    assert not [c for b in w.real_budgets.values() for c in b['cases'] if w.m.matrix.case(c)['category'] != 'B']


@pytest.mark.parametrize('name', ['compat-e', 'malformed-d', 'rich-valid', 'srich-repair2'])
def test_retired_budgets_are_refused_by_argparse_and_by_name(w, monkeypatch, name):
    with pytest.raises(SystemExit):
        w.m.main(w.argv('bind', budget=name))
    monkeypatch.setitem(w.m.BUDGETS, name, {'claim': 'bux-r6-test-fresh-%s.claim' % name, 'cases': ('S-MULTI',),
                                            'categories': ('B',)})
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.main(w.argv('bind', budget=name))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []


def test_preserved_compat_e_shape_budget_exact_order(w):
    assert w.m.budget(BUDGET)['cases'] == tuple(CASES) and w.m.case_order(CASES) == CASES
    categories = [w.m.matrix.case(c)['category'] for c in CASES]
    assert categories == ['A'] + ['E'] * 9 and 'B' not in categories
    # Only S-RICH is a source; every E case consumes its rich artifact on a fresh target.
    entries = [w.m.matrix.case(c) for c in CASES]
    assert [e['source'] for e in entries] == [None] + ['S-RICH'] * 9
    assert {e['artifact'] for e in entries[1:]} == {'rich'}
    assert [e['profile'] for e in entries] == ['FRESH_SOURCE'] + ['FRESH_TARGET'] * 9
    assert [(e['mutation'], e['selection']) for e in entries[1:]] == [(E_MUTATED[c][0], 'single') for c in CASES[1:]]
    assert all(e['allow_no_signal'] is True and e['runnable'] is True for e in entries[1:])
    # The one catalogue prediction (E-TOP) is unchanged and stays a prediction.
    assert [e['predictions'] for e in entries] == [{}, {'unknown': 'IGNORED'}] + [{}] * 8
    e_runnable = [c['id'] for c in w.m.matrix.CASES if c['category'] == 'E' and c['runnable']]
    assert e_runnable == CASES[1:]
    # D is unchanged in the catalogue and has no shipped budget.
    assert [c['id'] for c in w.m.matrix.CASES if c['category'] == 'D' and c['runnable']] == D_CASES[1:]
    assert not [c for b in w.real_budgets.values() for c in b['cases'] if w.m.matrix.case(c)['category'] == 'D']


def test_claim_lineage_consumed_retained_uncreated_refused_new_distinct(w):
    assert w.m.CONSUMED_HOST_CLAIMS == (CONSUMED, REPAIR2_CLAIM, RICH_VALID_CLAIM, MALFORMED_D_CLAIM,
                                        COMPAT_E_CLAIM)
    assert w.m.UNCREATED_PROPOSED_CLAIMS == (REPAIR1_CLAIM,)
    assert w.m.RETIRED_BUDGETS == ('srich-repair2', 'rich-valid', 'malformed-d', 'compat-e')
    assert B_CLAIM not in w.m.CONSUMED_HOST_CLAIMS + w.m.UNCREATED_PROPOSED_CLAIMS
    assert NEW_CLAIM not in w.m.CONSUMED_HOST_CLAIMS + w.m.UNCREATED_PROPOSED_CLAIMS
    assert w.m.consumed_claims_present() == CONSUMED_ALL
    w.consumed_unchanged()


@pytest.mark.parametrize('name,claim', [('compat-e', COMPAT_E_CLAIM), ('malformed-d', MALFORMED_D_CLAIM),
                                        ('rich-valid', RICH_VALID_CLAIM),
                                        ('srich-repair2', REPAIR2_CLAIM), ('srich-repair1', REPAIR1_CLAIM),
                                        ('host1', CONSUMED)])
def test_consumed_and_uncreated_budgets_are_refused(w, monkeypatch, name, claim):
    if name != 'host1':
        with pytest.raises(SystemExit):
            w.m.main(w.argv('bind', budget=name))
    # Reintroduced (or reusing a historical claim) it is still refused by name or claim.
    monkeypatch.setitem(w.m.BUDGETS, name, {'claim': claim, 'cases': ('S-RICH',), 'categories': ('A',)})
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.main(w.argv('bind', budget=name))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []
    assert not (w.scratch / REPAIR1_CLAIM).exists()
    w.consumed_unchanged()


@pytest.mark.parametrize('name', ['srich-repair2', 'rich-valid', 'malformed-d', 'compat-e'])
def test_retired_budget_name_is_refused_even_with_a_fresh_claim(w, monkeypatch, name):
    monkeypatch.setitem(w.m.BUDGETS, name, {'claim': 'bux-r6-test-fresh.claim', 'cases': ('S-RICH',),
                                            'categories': ('A',)})
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.budget(name)


@pytest.mark.parametrize('cases,categories', [
    (('S-MULTI', 'T-MULTI-ORDERED'), ('A',)), (('S-MULTI', 'T-MULTI-ORDERED'), ('A', 'E')),
    (('S-RICH', 'S-MULTI', 'E-TOP', 'T-MULTI-ORDERED'), ('A', 'E')),
    (('S-RICH', 'S-MULTI', 'E-TOP', 'T-MULTI-ORDERED'), ('B',)),
    (('S-RICH', 'D-TRUNC-P1', 'E-TOP'), ('A', 'D')), (('S-RICH', 'E-TOP'), ('A',)),
    (('S-MULTI', 'T-MULTI-ORDERED'), None), (('S-MULTI', 'T-MULTI-ORDERED'), ()),
    (('S-MULTI', 'T-MULTI-ORDERED'), ['B'])],
    ids=['b-undeclared', 'b-with-a-e', 'b-injected-undeclared', 'ae-injected-undeclared',
         'e-injected-undeclared', 'e-undeclared', 'no-categories', 'empty-categories', 'categories-not-tuple'])
def test_withheld_or_undeclared_categories_are_refused_in_any_budget(w, monkeypatch, cases, categories):
    monkeypatch.setitem(w.m.BUDGETS, 'withheld', {'claim': 'bux-r6-test-withheld.claim', 'cases': cases,
                                                  'categories': categories})
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.main(w.argv('bind', budget='withheld'))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []


@pytest.mark.parametrize('withheld', [('B',), ('A',), ('E',)])
def test_the_withholding_mechanism_still_refuses_a_withheld_category(w, monkeypatch, withheld):
    monkeypatch.setattr(w.m, 'WITHHELD_CATEGORIES', withheld)
    budget = B_BUDGET if 'B' in withheld else BUDGET
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.budget(budget)


def test_declared_e_budget_is_accepted_and_e_is_no_longer_withheld(w, monkeypatch):
    monkeypatch.setitem(w.m.BUDGETS, 'e-subset', {'claim': 'bux-r6-test-e-subset.claim',
                                                  'cases': ('S-RICH', 'E-TOP'), 'categories': ('A', 'E')})
    assert w.m.budget('e-subset')['cases'] == ('S-RICH', 'E-TOP')


def test_not_driven_empty_selection_is_refused_in_any_budget(w, monkeypatch):
    monkeypatch.setitem(w.m.BUDGETS, 'empty', {'claim': 'bux-r6-test-empty.claim', 'categories': ('A', 'D'),
                                               'cases': ('S-RICH', 'D-TRUNC-P1', 'D-EMPTY-SELECTION')})
    with pytest.raises(w.m.VerificationError):
        w.m.main(w.argv('bind', budget='empty'))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []


def test_ten_cases_under_the_new_claim_on_the_same_root_source(w):
    before = {n: (w.scratch / n).read_bytes() for n in OTHER_CLAIMS}
    assert w.run() == 0
    assert (w.scratch / NEW_CLAIM).exists() and (w.root / 'MATRIX.claim').exists()
    claim = json.loads((w.scratch / NEW_CLAIM).read_text())
    assert claim['budget'] == BUDGET and claim['claim_root_name'] == 'claim'
    assert {n: (w.scratch / n).read_bytes() for n in OTHER_CLAIMS} == before
    w.consumed_unchanged()
    assert w.launched() == ['pytest', 'pytest', *CASES]
    assert '-O' in w.spawned[1] and '-O' not in w.spawned[0]
    # Every E case consumes S-RICH from this claim root: a fresh source, never another claim's.
    for argv in w.spawned[3:]:
        assert argv[argv.index('--matrix-input') + 1] == str(w.root / 'cases/S-RICH')
    assert w.spawned[2].count('--matrix-input') == 0
    # Each case runs in its own fresh attempt root (fresh disposable profile).
    scratches = [argv[argv.index('--scratch') + 1] for argv in w.spawned[2:]]
    assert scratches == [str(w.root / 'cases' / c) for c in CASES]
    summary = w.summary()
    assert summary['budget'] == BUDGET and list(summary['cases']) == CASES
    assert summary['claim']['consumed_claims_present'] == CONSUMED_ALL
    assert summary['schema'] == 'bux-r6-firefox-matrix-summary-v8'
    assert summary['label'] == 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'
    assert summary['cases']['S-RICH']['rich_source_ready'] is True
    assert summary['cases']['S-RICH']['rich_source_missing'] == []
    assert summary['semantic_success_claimed'] is False and summary['qualification_accepted'] is False
    assert not (w.scratch / REPAIR1_CLAIM).exists()
    assert not any(c in a for argv in w.spawned for a in argv
                   for c in (REPAIR1_CLAIM, REPAIR2_CLAIM, RICH_VALID_CLAIM, MALFORMED_D_CLAIM, CONSUMED))
    assert len(w.runtime_calls) >= 4  # bind, re-bind, before first, after last


@pytest.mark.parametrize('at', CASES)
def test_stops_at_the_first_non_completed_case_in_each_position(w, at):
    w.statuses[at] = 'BLOCKED'
    assert w.run() == 0
    state = w.state()
    ran = CASES[:CASES.index(at) + 1]
    assert [a['case'] for a in state['attempts']] == ran
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at
    assert state['runtime_after_last'] == 'MATCH'
    assert sorted(p.name for p in (w.root / 'cases').iterdir()) == sorted(ran)
    assert w.launched()[2:] == ran  # no retry, no fallback
    assert w.summary()['label'] == 'R6_MATRIX_STOPPED_AT_CASE'
    assert (w.scratch / NEW_CLAIM).exists() and (w.root / 'MATRIX.claim').exists()


@pytest.mark.parametrize('damage', ['unready', 'artifact-unready', 'missing-listed', 'wrong-case', 'not-completed'])
def test_dependent_needs_the_same_root_source_ready_before_launch(w, damage):
    def edit(result):
        facts = result['matrix']
        if damage == 'unready':
            facts['classifications'].update(rich_source_ready=False, rich_source_missing=['rows:order'])
        elif damage == 'artifact-unready':
            facts['artifacts']['rich']['source_ready'] = None
        elif damage == 'missing-listed':
            facts['classifications']['rich_source_missing'] = ['custom_code:js']
        elif damage == 'wrong-case':
            facts['case'] = 'S-MULTI'
        else:
            facts['completed'] = False
    w.edits['S-RICH'] = edit  # the attempt still reports MATRIX_ATTEMPT_COMPLETED
    assert w.run() == 0
    state = w.state()
    assert w.launched()[2:] == ['S-RICH']  # E-TOP is never spawned
    assert state['phase'] == 'RUNNER_REFUSED' and state['stopped_at'] == 'E-TOP'
    assert state['runner_failure'] == {'type': 'VerificationError', 'code': 'MATRIX_INPUT_SOURCE_INVALID'}
    assert [(a['case'], a['status']) for a in state['attempts']] == [
        ('S-RICH', 'MATRIX_ATTEMPT_COMPLETED'), ('E-TOP', 'NOT_LAUNCHED_SOURCE_INVALID')]
    # The refusal is recorded, not raised, so the runtime is still verified after the last launch.
    assert state['runtime_after_last'] == 'MATCH'
    assert not (w.root / 'cases/E-TOP').exists()
    assert w.summary()['label'] == 'R6_MATRIX_RUNNER_REFUSED'
    assert (w.scratch / NEW_CLAIM).exists() and (w.root / 'MATRIX.claim').exists()


@pytest.mark.parametrize('after', CASES[1:-1])
def test_readiness_gate_runs_before_every_e_dependent(w, after):
    """The same-root S-RICH readiness is re-read before each E launch, not only the first."""
    def damage():
        path = w.root / 'cases/S-RICH/result.json'
        result = json.loads(path.read_text())
        result['matrix']['classifications'].update(rich_source_ready=False, rich_source_missing=['rows:order'])
        path.write_text(json.dumps(result))
    w.after[after] = damage
    assert w.run() == 0
    state, following = w.state(), CASES[CASES.index(after) + 1]
    assert w.launched()[2:] == CASES[:CASES.index(after) + 1]
    assert state['phase'] == 'RUNNER_REFUSED' and state['stopped_at'] == following
    assert state['attempts'][-1] == {'case': following, 'status': 'NOT_LAUNCHED_SOURCE_INVALID'}
    assert state['runtime_after_last'] == 'MATCH' and not (w.root / 'cases' / following).exists()


def test_source_gate_is_load_bearing(w, monkeypatch):
    """Mutant check: without the host gate an unready same-root source would feed E-TOP."""
    w.edits['S-RICH'] = lambda r: r['matrix']['classifications'].update(rich_source_ready=False)
    monkeypatch.setattr(w.m, 'source_gate', lambda root, case: True)
    w.run()
    assert 'E-TOP' in w.launched()


@pytest.mark.parametrize('outcome', ['all', 'stopped', 'interrupted', 'refused', 'drift'])
def test_both_claims_remain_after_every_post_claim_outcome(w, monkeypatch, outcome):
    if outcome == 'stopped':
        w.statuses['E-PREF'] = 'BLOCKED'
    elif outcome == 'interrupted':
        w.interrupts['E-TOP'] = 1
    elif outcome == 'refused':
        w.edits['S-RICH'] = lambda r: r['matrix']['classifications'].update(rich_source_ready=False)
    elif outcome == 'drift':
        calls = {'n': 0}
        def drifting(path):
            calls['n'] += 1
            if calls['n'] > 4:
                w.m.require(False, 'Capture digest mismatch')
            return dict(w.capture)
        monkeypatch.setattr(w.m.matrix, 'verify_capture', drifting)
    w.run()
    host, root = json.loads((w.scratch / NEW_CLAIM).read_text()), json.loads((w.root / 'MATRIX.claim').read_text())
    assert host['budget'] == root['budget'] == BUDGET
    assert w.state()['phase'] in ('ATTEMPTS_RETURNED', 'STOPPED', 'INTERRUPTED_RETAINED', 'RUNNER_REFUSED')
    w.consumed_unchanged()


def test_cases_option_unknown_budget_and_claim_reuse_are_refused(w, monkeypatch):
    with pytest.raises(SystemExit):
        w.m.main(w.argv('bind') + ['--cases', 'S-RICH,T-RICH'])
    with pytest.raises(SystemExit):
        w.m.main(w.argv('bind', budget='all'))
    with pytest.raises(SystemExit):
        w.m.main([a for a in w.argv('bind') if a not in ('--budget', BUDGET)])
    monkeypatch.setitem(w.m.BUDGETS, 'reuse', {'claim': NEW_CLAIM, 'cases': ('S-RICH',), 'categories': ('A',)})
    with pytest.raises(w.m.VerificationError, match='Unknown matrix budget'):
        w.m.main(w.argv('bind', budget='reuse'))
    assert not list(w.root.glob('BIND-*.json')) and w.spawned == []
    w.consumed_unchanged()


def test_second_run_refused_on_host_or_root_claim(w):
    assert w.run() == 0
    path = sorted(w.root.glob('BIND-*.json'))[-1]
    with pytest.raises(w.m.VerificationError, match='already claimed on this host'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))


def test_run_refuses_bind_mismatch_and_low_space_before_claim(subset, monkeypatch):
    w = subset
    path, digest = w.bind()
    with pytest.raises(w.m.VerificationError, match='differ from the bind record'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest, budget=SUBSET))
    monkeypatch.setattr(w.m, 'free_bytes', lambda root: w.m.MIN_FREE_BYTES - 1)
    with pytest.raises(w.m.VerificationError, match='Insufficient free space before claim'):
        w.m.main(w.argv('run', bind_record=str(path), bind_record_sha256=digest))
    assert not (w.root / 'MATRIX.claim').exists() and not (w.scratch / NEW_CLAIM).exists()


def test_exit_code_is_advisory_result_status_decides(w, monkeypatch):
    spawn = w.spawn
    def zero_exit(argv, **kw):
        proc = spawn(argv, **kw)
        proc.code = 0
        return proc
    monkeypatch.setattr(w.d2, 'spawn', zero_exit)
    w.statuses['S-RICH'] = 'BLOCKED'
    w.run()
    assert w.state()['stopped_at'] == 'S-RICH' and w.launched()[2:] == ['S-RICH']


def test_prerequisite_failure_launches_no_case(w, monkeypatch):
    spawn = w.spawn
    def failing(argv, **kw):
        if 'pytest' in argv:
            kw['stdout'].write('14 passed, 1 failed in 1.0s\n')
            return Proc(1)
        return spawn(argv, **kw)
    monkeypatch.setattr(w.d2, 'spawn', failing)
    with pytest.raises(w.m.VerificationError, match='before claim; nothing consumed'):
        w.run()
    # A prerequisite failure consumes neither claim, so the one-shot budget is still available.
    assert not (w.scratch / NEW_CLAIM).exists() and not (w.root / 'MATRIX.claim').exists()
    assert not (w.root / 'MATRIX-state.json').exists() and not (w.root / 'cases').exists()
    assert not any('--matrix-case' in argv for argv in w.spawned)
    record = json.loads((w.root / 'PREREQUISITES-001.json').read_text())
    assert record['ok'] is False and record['claims_consumed'] is False
    assert [c['mode'] for c in record['prerequisites']] == ['normal']
    w.consumed_unchanged()


def test_interrupted_prerequisite_refuses_before_claim(w, monkeypatch):
    spawn = w.spawn
    def interrupted(argv, **kw):
        if 'pytest' in argv and '-O' in argv:
            kw['stdout'].write('15 passed in 1.0s\n')
            return Proc(0, interrupts=1)
        return spawn(argv, **kw)
    monkeypatch.setattr(w.d2, 'spawn', interrupted)
    with pytest.raises(w.m.VerificationError, match='before claim; nothing consumed'):
        w.run()
    assert not (w.scratch / NEW_CLAIM).exists() and not (w.root / 'MATRIX.claim').exists()
    record = json.loads((w.root / 'PREREQUISITES-001.json').read_text())
    assert record['ok'] is False and record['prerequisites'][-1]['interrupted'] is True
    assert not any('--matrix-case' in argv for argv in w.spawned)


def test_claims_are_taken_only_after_both_prerequisites_pass(w, monkeypatch):
    exclusive, order = w.d2.exclusive, []
    spawn = w.spawn
    def tracking_spawn(argv, **kw):
        order.append('pytest-O' if 'pytest' in argv and '-O' in argv else 'pytest' if 'pytest' in argv
                     else argv[argv.index('--matrix-case') + 1])
        return spawn(argv, **kw)
    def tracking_exclusive(path, record):
        order.append('claim:' + Path(path).name)
        return exclusive(path, record)
    monkeypatch.setattr(w.d2, 'spawn', tracking_spawn)
    monkeypatch.setattr(w.d2, 'exclusive', tracking_exclusive)
    assert w.run() == 0
    assert order == ['pytest', 'pytest-O', 'claim:' + NEW_CLAIM, 'claim:MATRIX.claim', *CASES]
    record = json.loads((w.root / 'PREREQUISITES-001.json').read_text())
    assert record['ok'] is True and [c['mode'] for c in record['prerequisites']] == ['normal', 'optimized']
    assert w.state()['prerequisites'] == record['prerequisites']


def test_interrupt_waits_and_never_kills(w):
    w.interrupts['S-RICH'] = 2
    w.run()
    state = w.state()
    assert state['interrupted'] is True and state['phase'] == 'INTERRUPTED_RETAINED'
    assert [a['case'] for a in state['attempts']] == ['S-RICH']
    assert state['attempts'][0]['status'] == 'MATRIX_ATTEMPT_COMPLETED'  # waited to completion
    assert 'runtime_after_last' not in state  # an interrupt does no further runtime work


def test_capture_drift_between_attempts_stops_without_launch(w, monkeypatch):
    calls = {'n': 0}
    def drifting(path):
        calls['n'] += 1
        if calls['n'] > 3:  # bind, re-bind, first attempt
            w.m.require(False, 'Capture digest mismatch')
        return dict(w.capture)
    monkeypatch.setattr(w.m.matrix, 'verify_capture', drifting)
    w.run()
    state = w.state()
    assert state['phase'] == 'RUNNER_REFUSED' and state['runner_failure']['code'] == 'CAPTURE_DIGEST_MISMATCH'
    assert [a['case'] for a in state['attempts']] == ['S-RICH', 'E-TOP']
    assert state['attempts'][-1]['status'] == 'NOT_LAUNCHED_RUNNER_REFUSED'
    assert not (w.root / 'cases/E-TOP').exists()
    # The refusal was raised after S-RICH launched: the runtime is still verified after it.
    assert state['runtime_after_last'] == 'MATCH'
    assert w.summary()['claim']['runtime_after_last'] == 'MATCH'


def test_raised_refusal_after_a_launch_records_a_runtime_mismatch(w, monkeypatch):
    calls = {'n': 0}
    def drifting(path):
        calls['n'] += 1
        if calls['n'] > 3:
            w.m.require(False, 'Capture digest mismatch')
        return dict(w.capture)
    runtimes = []
    def runtime(r):
        runtimes.append(r)
        if len(runtimes) >= 4:  # bind, re-bind, before first, after last
            w.d2.require(False, 'Firefox runtime differs from the production runtime')
        return dict(w.m.firefox.IDENTITY)
    monkeypatch.setattr(w.m.matrix, 'verify_capture', drifting)
    monkeypatch.setattr(w.m.firefox, 'bind_runtime', runtime)
    w.run()
    state = w.state()
    assert len(runtimes) == 4 and state['phase'] == 'RUNNER_REFUSED'
    assert state['runtime_after_last'] == 'MISMATCH_OR_UNREADABLE'
    assert state['runner_failure']['code'] == 'CAPTURE_DIGEST_MISMATCH'


def test_refusal_before_the_first_launch_does_no_runtime_after(w, monkeypatch):
    calls = {'n': 0}
    def drifting(path):
        calls['n'] += 1
        if calls['n'] > 2:  # bind, re-bind
            w.m.require(False, 'Capture digest mismatch')
        return dict(w.capture)
    monkeypatch.setattr(w.m.matrix, 'verify_capture', drifting)
    w.run()
    state = w.state()
    assert state['phase'] == 'RUNNER_REFUSED' and 'runtime_after_last' not in state
    assert state['attempts'] == [{'case': 'S-RICH', 'status': 'NOT_LAUNCHED_RUNNER_REFUSED'}]
    assert not any('--matrix-case' in argv for argv in w.spawned)
    assert (w.scratch / NEW_CLAIM).exists() and (w.root / 'MATRIX.claim').exists()


def test_runtime_after_last_mismatch_is_not_a_complete_label(w, monkeypatch):
    calls = []
    def runtime(r):
        calls.append(r)
        if len(calls) >= 4:
            w.d2.require(False, 'Firefox runtime differs from the production runtime')
        return dict(w.m.firefox.IDENTITY)
    monkeypatch.setattr(w.m.firefox, 'bind_runtime', runtime)
    w.run()
    assert w.state()['runtime_after_last'] == 'MISMATCH_OR_UNREADABLE'
    assert w.summary()['label'] != 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'


def test_collect_is_read_only(w, monkeypatch):
    w.run()
    claims = {p.name: p.read_bytes() for p in list(w.scratch.glob('*.claim')) + [w.root / 'MATRIX.claim']
              if p.name not in RETAINED}
    def forbidden(*a, **kw):
        raise AssertionError('collect must not launch, bind or call Nix')
    for target, name in ((w.d2, 'spawn'), (w.m.firefox, 'bind_runtime'), (w.d2, 'predicted_template'),
                         (w.m, 'signature'), (w.m.subprocess, 'run'), (w.d2, 'exclusive')):
        monkeypatch.setattr(target, name, forbidden)
    assert w.m.main(['collect', '--claim-root', str(w.root)]) == 0
    assert sorted(p.name for p in w.root.glob('MATRIX-SUMMARY-*.json')) == [
        'MATRIX-SUMMARY-001.json', 'MATRIX-SUMMARY-002.json']
    assert {p.name: p.read_bytes() for p in list(w.scratch.glob('*.claim')) + [w.root / 'MATRIX.claim']
            if p.name not in RETAINED} == claims
    w.consumed_unchanged()


def test_case_summary_is_a_privacy_projection(w):
    attempt = w.root / 'probe'
    attempt.mkdir()
    (attempt / 'result.json').write_text(json.dumps({
        'status': 'MATRIX_ATTEMPT_COMPLETED', 'primary_failure': {'stage': 'browser', 'type': 'X',
                                                                  'code': 'UNKNOWN', 'message': 'secret /Users/x'},
        'matrix': {'steps': [{'step': 'export:rich', 'status': 'DONE', 'label': 'rich'}],
                   'artifacts': {'rich': {'parts': [{'index': 0, 'name_class': 'NATIVE_PART_1', 'bytes': 5,
                                                     'sha256': '0' * 64}], 'closure': 'CLOSED', 'complete': True,
                                          'expected_rows': 5}}},
        'matrix_inputs': {'source': [{'sha256': '1' * 64}], 'mutation': {'mutation': 'drop_chunks'}},
        'settlement': {'exit_code': 0, 'pid': 99}}))
    summary = w.m.case_summary(attempt)
    text = json.dumps(summary)
    assert '/Users' not in text and 'secret' not in text and '"pid"' not in text
    assert summary['artifacts']['rich']['parts'][0]['name_class'] == 'NATIVE_PART_1'
    assert summary['artifacts']['rich']['closure'] == 'CLOSED' and summary['artifacts']['rich']['complete'] is True
    (attempt / 'result.json').write_text(json.dumps({'status': 'BLOCKED', 'browser_version': '/leak path'}))
    assert w.m.case_summary(attempt) == {'status': 'BLOCKED', 'projection': 'REFUSED'}


def test_runner_has_no_chrome_or_browser_orchestration(w, repo_root):
    import ast
    source = (repo_root / 'tests/cnt_host_firefox_matrix.py').read_text()
    text = source.replace(ast.get_docstring(ast.parse(source), clean=False), '')
    for token in ('cnt_host_chrome', 'cnt_synthetic_chrome', 'cnt_chrome', 'CDP', 'OwnedProcess',
                  'sandbox-exec', 'Marionette', 'kill(', 'terminate('):
        assert token not in text, token


def test_case_summary_carries_the_seed_trace_and_refuses_unsafe_traces(w):
    attempt = w.root / 'probe-trace'
    attempt.mkdir()
    trace = [{'n': 1, 'action': 'pref:one_backup_file_size_in_bytes', 'route': 'keys_replace',
              'status': 'FAILED', 'expected': 209715200,
              'before': {'controls': {'one_backup_file_size_in_bytes': {'present': True, 'state': 419430400,
                                                                        'dom': '419430400'}}},
              'after': {'controls': {'one_backup_file_size_in_bytes': {'present': True,
                                                                       'state': '419430400209715200',
                                                                       'dom': '419430400209715200'}}},
              'elapsed_ms': 10000,
              'failure': {'type': 'VerificationError', 'code': 'MATRIX_UI_VALUE_NOT_APPLIED', 'protocol': None}}]
    result = {'status': 'BLOCKED', 'native_semantics': 'NOT_EXECUTED',
              'matrix': {'steps': [{'step': 'seed_rich', 'status': 'FAILED', 'error_type': 'VerificationError'}],
                         'seed_trace': trace, 'seed_failed_action': 'pref:one_backup_file_size_in_bytes'}}
    (attempt / 'result.json').write_text(json.dumps(result))
    summary = w.m.case_summary(attempt)
    assert summary['seed_failed_action'] == 'pref:one_backup_file_size_in_bytes'
    assert summary['seed_trace'] == trace
    trace[0]['after']['controls']['one_backup_file_size_in_bytes']['dom'] = '/Users/someone/x'
    (attempt / 'result.json').write_text(json.dumps(result))
    assert w.m.case_summary(attempt) == {'status': 'BLOCKED', 'projection': 'REFUSED'}


def test_runner_names_each_historical_claim_exactly_once(repo_root):
    source = (repo_root / 'tests/cnt_host_firefox_matrix.py').read_text()
    for claim in (CONSUMED, REPAIR2_CLAIM, RICH_VALID_CLAIM, MALFORMED_D_CLAIM, COMPAT_E_CLAIM, REPAIR1_CLAIM,
                  B_CLAIM):
        assert source.count(claim) == 1, claim
    assert 'UNCREATED_PROPOSED_CLAIMS' in source.split('def budget', 1)[1]
    assert 'RETIRED_BUDGETS' in source.split('def budget', 1)[1]
    assert 'lexists(d2.SCRATCH / name) for name in CONSUMED_HOST_CLAIMS' in source


@pytest.mark.parametrize('ready,missing', [(True, []), (False, ['task:2:background', 'custom_code:js'])])
def test_summary_projects_readiness_and_coverage_enums_without_ids(w, ready, missing):
    attempt = w.root / ('probe-ready-' + str(ready))
    attempt.mkdir()
    coverage = {'task_fields': ['OBSERVED', 'OBSERVED'],
                'task_background': ['OBSERVED', 'NOT_OBSERVED' if missing else 'OBSERVED'],
                'task_target_binding': ['REACT_FIBER_READ', 'NOT_BOUND'], 'row_order': 'OBSERVED',
                'override_background': 'OBSERVED', 'custom_code_input': 'LIBRARY_ADAPTER',
                'custom_code': {'html': 'OBSERVED', 'css': 'OBSERVED', 'js': 'NOT_OBSERVED' if missing else 'OBSERVED'}}
    result = {'status': 'MATRIX_ATTEMPT_COMPLETED' if ready else 'BLOCKED',
              'native_semantics': 'EXECUTED_CASE_RECORDED' if ready else 'NOT_EXECUTED',
              'primary_failure': None if ready else {'stage': 'browser', 'type': 'VerificationError',
                                                     'code': 'MATRIX_RICH_SOURCE_INCOMPLETE'},
              'matrix': {'steps': [{'step': 'source_readiness', 'status': 'DONE' if ready else 'FAILED'}],
                         'classifications': {'rich_coverage': coverage, 'rich_source_ready': ready,
                                             'rich_source_missing': missing},
                         'artifacts': {'rich': {'parts': [], 'source_ready': ready}}}}
    (attempt / 'result.json').write_text(json.dumps(result))
    summary = w.m.case_summary(attempt)
    assert summary['rich_source_ready'] is ready and summary['rich_source_missing'] == missing
    assert summary['artifacts']['rich']['source_ready'] is ready
    assert summary['classifications']['rich_coverage']['task_background'] == coverage['task_background']
    if not ready:
        assert summary['primary_failure']['code'] == 'MATRIX_RICH_SOURCE_INCOMPLETE'
    # An unsafe value smuggled into the projected classifications is refused, never exported.
    coverage['task_background'][0] = {'id': 'x/raw id'}
    (attempt / 'result.json').write_text(json.dumps(result))
    assert w.m.case_summary(attempt)['projection'] == 'REFUSED'


# --- RICH-VALID-PREP1 (preserved): restore evidence and source binding, rich-shaped budget -----

EVIDENCE = {
    'T-RICH': {'restored_rich': {'requirements': {'schema': 'bux-r6-rich-readiness-v1', 'met': True, 'missing': []},
                                 'source_seed_custom_code_input': 'LIBRARY_ADAPTER'},
               'post_vs_given': 'SEMANTIC_EQUAL'},
    'T-DISPLACE': {'displacement': 'REPLACES', 'prior_state': 'REMOVED',
                   'prior_residue': {'prior_rows': 2, 'prior_rows_remaining': 0},
                   'live_data_scope': 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'},
    'F-REPEAT': {'repeat_identity': {'repeat_class': 'IDEMPOTENT', 'idempotence': 'IDEMPOTENT',
                                     'part_bytes_equal': False, 'volatile_prefs_equal': False}}}


def with_evidence(case):
    def edit(result):
        result['matrix']['restore_evidence'].update(EVIDENCE[case])
    return edit


EXACT_BINDING = {'source_case': 'S-RICH', 'artifact': 'rich', 'source_status': 'MATRIX_ATTEMPT_COMPLETED',
                 'source_rich_source_ready': True, 'source_artifact_ready': True, 'input_parts_match_source': True,
                 'given_semantic_matches_source': True, 'input_mutated': False,
                 'original_parts_match_source': None, 'mutation_before_matches_source': None,
                 'mutation_after_matches_input': None, 'unmutated_parts_match_source': None,
                 'original_semantic_matches_source': None, 'binding_class': 'EXACT_SOURCE_INPUT'}


def test_summary_projects_restore_evidence_and_source_binding(rich_shape):
    w = rich_shape
    for case in RICH_CASES[1:]:
        w.edits[case] = with_evidence(case)
    assert w.run(budget=RICH_SHAPE) == 0
    summary = w.summary()
    assert summary['schema'] == 'bux-r6-firefox-matrix-summary-v8' and list(summary['cases']) == RICH_CASES
    for case in RICH_CASES[1:]:
        projected = summary['cases'][case]
        evidence = projected['restore_evidence']
        assert evidence['case'] == case and evidence['given_semantic_sha256'] == SOURCE_SEMANTIC
        assert {k: evidence[k] for k in EVIDENCE[case]} == EVIDENCE[case]
        assert projected['source_binding'] == EXACT_BINDING
        assert projected['malformed_evidence'] is None and projected['compat_evidence'] is None
        assert projected['compat_input'] is None
        assert projected['inputs'] == {'source_sha256': ['a' * 64], 'original_sha256': None, 'mutation': None,
                                       'mutation_record': None}
    assert 'source_binding' not in summary['cases']['S-RICH']
    assert summary['cases']['S-RICH']['artifacts']['rich']['closure'] == 'CLOSED'
    text = json.dumps(summary)
    for leak in ('part-1.json', 'Part 1.json', str(w.scratch), '/Users', 'inputs/source', 'artifacts/rich'):
        assert leak not in text, leak


@pytest.mark.parametrize('tamper', ['input-digest', 'given-semantic', 'no-evidence'])
def test_source_binding_discloses_a_mismatch_without_raising(rich_shape, tamper):
    w = rich_shape
    def edit(result):
        if tamper == 'input-digest':
            result['matrix_inputs']['source'][0]['sha256'] = 'c' * 64
        elif tamper == 'given-semantic':
            result['matrix']['restore_evidence']['given_semantic_sha256'] = 'd' * 64
        else:
            del result['matrix']['restore_evidence']
    w.edits['T-RICH'] = edit
    assert w.run(budget=RICH_SHAPE) == 0
    binding = w.summary()['cases']['T-RICH']['source_binding']
    assert binding['input_parts_match_source'] is (tamper != 'input-digest')
    assert binding['given_semantic_matches_source'] is (tamper == 'input-digest')
    assert binding['binding_class'] == ('MISMATCH' if tamper == 'input-digest' else 'EXACT_SOURCE_INPUT')
    assert w.summary()['cases']['T-DISPLACE']['source_binding']['given_semantic_matches_source'] is True


def test_unsafe_restore_evidence_is_refused_without_hiding_the_case(rich_shape):
    w = rich_shape
    w.edits['T-DISPLACE'] = lambda r: r['matrix']['restore_evidence'].update(
        prior_residue={'row_id': '/Users/someone/raw id'})
    assert w.run(budget=RICH_SHAPE) == 0
    projected = w.summary()['cases']['T-DISPLACE']
    assert projected['restore_evidence'] == {'projection': 'REFUSED'}
    assert projected['status'] == 'MATRIX_ATTEMPT_COMPLETED' and projected['steps']
    assert projected['source_binding']['given_semantic_matches_source'] is False
    assert '/Users' not in json.dumps(w.summary())


def test_rich_shape_run_sequence_is_preserved(rich_shape):
    w = rich_shape
    assert w.run(budget=RICH_SHAPE) == 0
    assert w.launched() == ['pytest', 'pytest', *RICH_CASES]
    assert w.summary()['label'] == 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'
    assert (w.scratch / 'bux-r6-test-synthetic-rich-shape.claim').exists()
    w.consumed_unchanged()


# --- MALFORMED-D-PREP1 (preserved): malformed evidence and mutation binding, D-shaped budget ---

def test_v5_summary_projects_malformed_evidence_and_declared_mutation_binding(d_shape):
    w = d_shape
    assert w.run(budget=D_SHAPE) == 0
    summary = w.summary()
    for case in D_CASES[1:]:
        projected = summary['cases'][case]
        evidence = projected['malformed_evidence']
        assert evidence['case'] == case and evidence['state_effect'] == 'SENTINEL_CONTENT_DESTROYED'
        assert evidence['live_data_scope'] == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
        assert projected['restore_evidence'] is None
        binding = projected['source_binding']
        if case in MUTATED:
            assert projected['inputs']['original_sha256'] == ['a' * 64]
            assert projected['inputs']['source_sha256'] == [mutated_sha(case)]
            record = projected['inputs']['mutation_record']
            assert record['mutation'] == MUTATED[case][0] and record['part_number'] == 1
            assert set(record) == {'mutation', 'edit', 'target', 'part_number', 'parseable', 'before_sha256',
                                   'after_sha256'}
            # The mutated input is not the source; the declared mutation of the source is bound.
            assert binding['input_parts_match_source'] is False and binding['input_mutated'] is True
            assert (binding['original_parts_match_source'], binding['mutation_before_matches_source'],
                    binding['mutation_after_matches_input'], binding['unmutated_parts_match_source'],
                    binding['original_semantic_matches_source']) == (True,) * 5
            assert binding['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE'
            assert binding['given_semantic_matches_source'] is False
        else:
            assert projected['inputs']['original_sha256'] is None and projected['inputs']['mutation'] is None
            assert binding['binding_class'] == 'EXACT_SOURCE_INPUT' and binding['input_mutated'] is False
            assert binding['given_semantic_matches_source'] is True
            assert binding['original_semantic_matches_source'] is True
        assert binding['source_rich_source_ready'] is True and binding['source_artifact_ready'] is True


def test_v5_restores_carry_the_tri_state_and_only_allowlisted_codes(d_shape):
    w = d_shape
    assert w.run(budget=D_SHAPE) == 0
    summary = w.summary()
    restores = summary['cases']['D-TRUNC-P1']['restores']
    assert restores == [{'completion': 'DEADLINE_NO_SIGNAL', 'recorded_restore_error': True,
                         'restore_error_state': 'UNKNOWN', 'state_consistent': True, 'start_observed': True,
                         'transition_end_observed': True, 'error_ribbon_seen': True, 'selected_files': 1,
                         'backgrounds_dom_after': 0, 'error_codes': ['UNRECOGNIZED_REPORT_PRESENT'],
                         'silent_codes': ['cnt_1436', 'UNRECOGNIZED_REPORT_PRESENT'],
                         'report_observability': 'PARTIAL_SUPPRESSION_UNRESOLVED'}]
    # The recorded loud flag never upgrades DEADLINE_NO_SIGNAL; the raw unknown code never leaves.
    text = json.dumps(summary)
    assert 'cnt_1556' not in text and '"OTHER"' not in text


@pytest.mark.parametrize('tamper', ['original-digest', 'before', 'after', 'part-number', 'original-semantic',
                                    'no-original', 'extra-input-part'])
def test_mutation_binding_discloses_a_mismatch_without_raising(d_shape, tamper):
    w = d_shape
    def edit(result):
        inputs, record = result['matrix_inputs'], result['matrix_inputs']['mutation']
        if tamper == 'original-digest':
            inputs['original'][0]['sha256'] = 'c' * 64
        elif tamper == 'before':
            record['before_sha256'] = 'c' * 64
        elif tamper == 'after':
            record['after_sha256'] = 'c' * 64
        elif tamper == 'part-number':
            record['part_number'] = 2
        elif tamper == 'original-semantic':
            result['matrix']['malformed_evidence']['source']['original_semantic_sha256'] = 'd' * 64
        elif tamper == 'no-original':
            del inputs['original']
        else:
            inputs['source'].append({'part_number': 2, 'bytes': 1, 'sha256': 'f' * 64})
    w.edits['D-NO-CHUNKS'] = edit
    assert w.run(budget=D_SHAPE) == 0
    summary = w.summary()
    binding = summary['cases']['D-NO-CHUNKS']['source_binding']
    assert binding['binding_class'] == 'MISMATCH' and binding['input_mutated'] is True
    assert summary['cases']['D-CHUNKS-TYPE']['source_binding']['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE'
    assert summary['cases']['D-NO-CHUNKS']['status'] == 'MATRIX_ATTEMPT_COMPLETED'


def test_unsafe_malformed_evidence_is_refused_without_hiding_the_case(d_shape):
    w = d_shape
    w.edits['D-BAD-DATAURL'] = lambda r: r['matrix']['malformed_evidence'].update(
        reports={'raw_message': '/Users/someone/raw report text'})
    assert w.run(budget=D_SHAPE) == 0
    projected = w.summary()['cases']['D-BAD-DATAURL']
    assert projected['malformed_evidence'] == {'projection': 'REFUSED'}
    assert projected['status'] == 'MATRIX_ATTEMPT_COMPLETED' and projected['steps']
    # The refused evidence carries no semantic digest, so the binding says so instead of raising.
    assert projected['source_binding']['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE'
    assert projected['source_binding']['original_semantic_matches_source'] is None
    assert '/Users' not in json.dumps(w.summary())


# --- REPORT-GATE1 (preserved): pre-existing ribbon refusal, observability-aware D restores -------

def refused_for_ribbon(result):
    """What the session and preflight record when the D gate refuses: BLOCKED, the restore step
    FAILED, the VISIBLE reading, the fixed code and no restore, classification or evidence."""
    facts = result['matrix']
    facts.update(pre_restore_error_ribbon='VISIBLE', completed=False, classifications={},
                 steps=[{'step': 'open_settings', 'status': 'DONE'}, {'step': 'seed_sentinel', 'status': 'DONE'},
                        {'step': 'pre_export', 'status': 'DONE'},
                        {'step': 'restore', 'status': 'FAILED', 'error_type': 'VerificationError'}])
    for key in ('restores', 'malformed_evidence'):
        facts.pop(key, None)
    result['primary_failure'] = {'stage': 'browser', 'type': 'VerificationError',
                                 'classification': 'Matrix pre-existing error ribbon',
                                 'code': 'MATRIX_PREEXISTING_ERROR_RIBBON', 'message_known': True}


@pytest.mark.parametrize('at', D_CASES[1:])
def test_pre_existing_ribbon_refusal_stops_at_that_d_case(d_shape, at):
    w = d_shape
    w.statuses[at] = 'BLOCKED'
    w.edits[at] = refused_for_ribbon
    assert w.run(budget=D_SHAPE) == 0
    state = w.state()
    ran = D_CASES[:D_CASES.index(at) + 1]
    assert w.launched()[2:] == ran  # no retry, no fallback, nothing after the refused case
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at
    # S-RICH was launched, so the runtime is verified after the last launched case.
    assert state['runtime_after_last'] == 'MATCH'
    summary = w.summary()
    projected = summary['cases'][at]
    assert summary['label'] == 'R6_MATRIX_STOPPED_AT_CASE'
    assert projected['status'] == 'BLOCKED' and projected['primary_failure']['code'] == \
        'MATRIX_PREEXISTING_ERROR_RIBBON'
    assert projected['pre_restore_error_ribbon'] == 'VISIBLE' and projected['restores'] == []
    assert projected['malformed_evidence'] is None
    assert projected['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
    assert (w.scratch / D_SHAPE_CLAIM).exists() and not (w.scratch / REPAIR1_CLAIM).exists()
    w.consumed_unchanged()


def clean_d(result):
    result['matrix']['restores'] = [{'completion': 'COMPLETED', 'restore_error': False, 'error_codes': [],
                                     'silent_codes': [], 'start_observed': True, 'transition_end_observed': True,
                                     'error_ribbon_seen': False, 'backgrounds_dom_after': 2, 'selected_files': 1}]


def test_v6_d_restores_keep_a_clean_completion_unknown(d_shape):
    w = d_shape
    w.edits['D-CHUNKS-TYPE'] = clean_d
    assert w.run(budget=D_SHAPE) == 0
    summary = w.summary()
    projected = summary['cases']['D-CHUNKS-TYPE']
    restore = projected['restores'][0]
    assert (restore['completion'], restore['recorded_restore_error']) == ('COMPLETED', False)
    assert (restore['restore_error_state'], restore['state_consistent']) == ('UNKNOWN', True)
    assert restore['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
    assert projected['pre_restore_error_ribbon'] == 'HIDDEN'
    # The legacy classifications and predictions are labelled as computed on the recorded flag.
    assert projected['legacy_basis'] == 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'
    assert projected['classifications'] == {'backgrounds': 'RESTORED'}
    for case in D_CASES[1:]:
        assert summary['cases'][case]['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
    source = summary['cases']['S-RICH']
    assert not {'pre_restore_error_ribbon', 'report_observability', 'legacy_basis'} & set(source)


@pytest.mark.parametrize('recorded_case', ['T-RICH', None, 'D-OTHER', 7])
def test_runnable_d_decision_comes_from_the_host_state_not_the_result(d_shape, recorded_case):
    w = d_shape
    w.edits['D-CHUNKS-TYPE'] = lambda r: (clean_d(r), r['matrix'].update(case=recorded_case))
    assert w.run(budget=D_SHAPE) == 0
    restore = w.summary()['cases']['D-CHUNKS-TYPE']['restores'][0]
    assert restore['restore_error_state'] == 'UNKNOWN' and 'report_observability' in restore
    # A direct projection without the host case id keeps the legacy (non-D) tri-state.
    attempt = w.root / 'cases/D-CHUNKS-TYPE'
    assert w.m.case_summary(attempt)['restores'][0]['restore_error_state'] == 'FALSE'
    assert w.m.case_summary(attempt, 'D-CHUNKS-TYPE')['restores'][0]['restore_error_state'] == 'UNKNOWN'
    assert w.m.case_summary(attempt, 'D-EMPTY-SELECTION')['restores'][0]['restore_error_state'] == 'FALSE'


@pytest.mark.parametrize('ribbon', ['VISIBLE', 'UNREADABLE', None, '/Users/someone ribbon text'])
def test_d_restores_without_a_hidden_gate_reading_are_unknown(d_shape, ribbon):
    w = d_shape
    def edit(result):
        clean_d(result)
        if ribbon is None:
            del result['matrix']['pre_restore_error_ribbon']
        else:
            result['matrix']['pre_restore_error_ribbon'] = ribbon
    w.edits['D-NAME-NO-P1'] = edit
    assert w.run(budget=D_SHAPE) == 0
    projected = w.summary()['cases']['D-NAME-NO-P1']
    assert projected['restores'][0]['restore_error_state'] == 'UNKNOWN'
    assert projected['restores'][0]['state_consistent'] is False
    assert projected['pre_restore_error_ribbon'] == (ribbon if ribbon in ('VISIBLE', 'UNREADABLE') else None)
    assert '/Users' not in json.dumps(w.summary())


def test_rich_shaped_summary_is_unchanged_apart_from_the_schema_label(rich_shape):
    w = rich_shape
    def edit(result):
        clean_d(result)
        result['matrix']['pre_restore_error_ribbon'] = 'HIDDEN'  # ignored outside runnable D and E
    w.edits['T-RICH'] = edit
    assert w.run(budget=RICH_SHAPE) == 0
    summary = w.summary()
    assert summary['schema'] == 'bux-r6-firefox-matrix-summary-v8'
    for case in RICH_CASES:
        assert not {'pre_restore_error_ribbon', 'report_observability', 'legacy_basis'} & set(summary['cases'][case])
    restore = summary['cases']['T-RICH']['restores'][0]
    assert (restore['restore_error_state'], restore['state_consistent']) == ('FALSE', True)
    assert 'report_observability' not in restore


def test_budget_order_claims_schemas_and_withheld_categories_are_pinned(w):
    m = w.m
    assert w.real_budgets == {B_BUDGET: {'claim': B_CLAIM, 'cases': tuple(B_CASES), 'categories': ('B',)}}
    assert m.RETIRED_BUDGETS == ('srich-repair2', 'rich-valid', 'malformed-d', 'compat-e')
    assert m.WITHHELD_CATEGORIES == ()
    assert m.CONSUMED_HOST_CLAIMS == (CONSUMED, REPAIR2_CLAIM, RICH_VALID_CLAIM, MALFORMED_D_CLAIM, COMPAT_E_CLAIM)
    assert m.UNCREATED_PROPOSED_CLAIMS == (REPAIR1_CLAIM,)
    assert (m.BIND_SCHEMA, m.SUMMARY_SCHEMA) == ('bux-r6-firefox-matrix-bind-v3', 'bux-r6-firefox-matrix-summary-v8')
    assert m.matrix.case('D-EMPTY-SELECTION')['runnable'] is False
    assert not [c for c in CASES if m.matrix.case(c)['category'] in ('B', 'D')]
    # The preserved compat-E-shaped run (test-only budget) is unchanged.
    assert w.run() == 0
    assert w.launched()[2:] == CASES and 'D-EMPTY-SELECTION' not in w.summary()['cases']


# --- COMPAT-E-PREP1: compat evidence, input proof and source binding in the v7 summary ----------

def test_v7_summary_projects_compat_evidence_input_proof_and_binding(w):
    assert w.run() == 0
    summary = w.summary()
    for case in CASES[1:]:
        projected = summary['cases'][case]
        evidence = projected['compat_evidence']
        assert evidence['case'] == case and evidence['application'] == 'APPLIED'
        assert projected['compat_input']['proven'] is True and projected['compat_input']['case'] == case
        assert projected['malformed_evidence'] is None and projected['restore_evidence'] is None
        # A clean-looking E completion stays UNKNOWN under partial observability.
        restore = projected['restores'][0]
        assert (restore['completion'], restore['restore_error_state'], restore['state_consistent']) == (
            'COMPLETED', 'UNKNOWN', True)
        assert restore['report_observability'] == projected['report_observability'] == \
            'PARTIAL_SUPPRESSION_UNRESOLVED'
        assert projected['pre_restore_error_ribbon'] == 'HIDDEN'
        assert projected['legacy_basis'] == 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'
        record = projected['inputs']['mutation_record']
        assert (record['mutation'], record['edit'], record['target']) == E_MUTATED[case]
        binding = projected['source_binding']
        assert binding['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE' and binding['input_mutated'] is True
        assert (binding['original_parts_match_source'], binding['mutation_before_matches_source'],
                binding['mutation_after_matches_input'], binding['unmutated_parts_match_source'],
                binding['original_semantic_matches_source']) == (True,) * 5
        assert binding['given_semantic_matches_source'] is False  # the input is the declared mutation
        assert binding['source_rich_source_ready'] is True and binding['source_artifact_ready'] is True
    source = summary['cases']['S-RICH']
    assert not {'pre_restore_error_ribbon', 'report_observability', 'legacy_basis'} & set(source)
    assert source['compat_evidence'] is None and source['compat_input'] is None
    text = json.dumps(summary)
    for leak in ('part-1.json', str(w.scratch), '/Users', 'bux-r6-unknown', 'x_bux_'):
        assert leak not in text, leak


@pytest.mark.parametrize('tamper', ['original-semantic', 'before', 'no-original'])
def test_compat_mutation_binding_discloses_a_mismatch_without_raising(w, tamper):
    def edit(result):
        inputs = result['matrix_inputs']
        if tamper == 'original-semantic':
            result['matrix']['compat_evidence']['source']['original_semantic_sha256'] = 'd' * 64
        elif tamper == 'before':
            inputs['mutation']['before_sha256'] = 'c' * 64
        else:
            del inputs['original']
    w.edits['E-VERSION'] = edit
    assert w.run() == 0
    summary = w.summary()
    assert summary['cases']['E-VERSION']['source_binding']['binding_class'] == 'MISMATCH'
    assert summary['cases']['E-MODE-THEME']['source_binding']['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE'
    assert summary['cases']['E-VERSION']['status'] == 'MATRIX_ATTEMPT_COMPLETED'


def test_unsafe_compat_evidence_or_proof_is_refused_without_hiding_the_case(w):
    w.edits['E-BG'] = lambda r: r['matrix']['compat_evidence'].update(unknown={'x_bux_raw_key': '/Users/raw value'})
    w.edits['E-PREF'] = lambda r: r['matrix']['compat_input'].update(detail='/Users/someone raw')
    assert w.run() == 0
    summary = w.summary()
    assert summary['cases']['E-BG']['compat_evidence'] == {'projection': 'REFUSED'}
    assert summary['cases']['E-PREF']['compat_input'] == {'projection': 'REFUSED'}
    assert summary['cases']['E-PREF']['compat_evidence']['case'] == 'E-PREF'
    assert summary['cases']['E-BG']['status'] == 'MATRIX_ATTEMPT_COMPLETED' and summary['cases']['E-BG']['steps']
    assert summary['cases']['E-BG']['source_binding']['original_semantic_matches_source'] is None
    assert '/Users' not in json.dumps(summary)


def refused_for_proof(result):
    """What the session and preflight record when the E input proof refuses: BLOCKED, the restore step
    FAILED, the unproven proof and no ribbon read, restore, classification or evidence."""
    facts = result['matrix']
    facts.update(completed=False, classifications={},
                 compat_input=dict(facts['compat_input'], proven=False, outside_edit_unchanged=False),
                 steps=[{'step': 'open_settings', 'status': 'DONE'}, {'step': 'pre_export', 'status': 'DONE'},
                        {'step': 'restore', 'status': 'FAILED', 'error_type': 'VerificationError'}])
    for key in ('restores', 'compat_evidence', 'pre_restore_error_ribbon'):
        facts.pop(key, None)
    result['primary_failure'] = {'stage': 'browser', 'type': 'VerificationError',
                                 'classification': 'Matrix compat input unproven',
                                 'code': 'MATRIX_COMPAT_INPUT_UNPROVEN', 'message_known': True}


def refused_for_ribbon_e(result):
    facts = result['matrix']
    refused_for_proof(result)
    facts['compat_input'] = dict(facts['compat_input'], proven=True, outside_edit_unchanged=True)
    facts['pre_restore_error_ribbon'] = 'VISIBLE'
    result['primary_failure'].update(classification='Matrix pre-existing error ribbon',
                                     code='MATRIX_PREEXISTING_ERROR_RIBBON')


@pytest.mark.parametrize('refusal,code', [(refused_for_proof, 'MATRIX_COMPAT_INPUT_UNPROVEN'),
                                          (refused_for_ribbon_e, 'MATRIX_PREEXISTING_ERROR_RIBBON')],
                         ids=['proof', 'ribbon'])
@pytest.mark.parametrize('at', ['E-TOP', 'E-TASK', 'E-MODE-THEME'])
def test_e_refusal_before_selection_stops_at_that_case(w, at, refusal, code):
    w.statuses[at] = 'BLOCKED'
    w.edits[at] = refusal
    assert w.run() == 0
    state = w.state()
    ran = CASES[:CASES.index(at) + 1]
    assert w.launched()[2:] == ran  # no retry, no fallback, nothing after the refused case
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at
    assert state['runtime_after_last'] == 'MATCH'  # verified after the last launched case
    summary = w.summary()
    projected = summary['cases'][at]
    assert summary['label'] == 'R6_MATRIX_STOPPED_AT_CASE'
    assert projected['status'] == 'BLOCKED' and projected['primary_failure']['code'] == code
    assert projected['restores'] == [] and projected['compat_evidence'] is None
    assert projected['compat_input']['proven'] is (code != 'MATRIX_COMPAT_INPUT_UNPROVEN')
    assert (w.scratch / NEW_CLAIM).exists() and not (w.scratch / REPAIR1_CLAIM).exists()
    w.consumed_unchanged()


@pytest.mark.parametrize('recorded_case', ['T-RICH', None, 'D-TRUNC-P1', 7])
def test_runnable_e_decision_comes_from_the_host_state_not_the_result(w, recorded_case):
    w.edits['E-CODE'] = lambda r: r['matrix'].update(case=recorded_case)
    assert w.run() == 0
    restore = w.summary()['cases']['E-CODE']['restores'][0]
    assert restore['restore_error_state'] == 'UNKNOWN' and 'report_observability' in restore
    attempt = w.root / 'cases/E-CODE'
    assert w.m.case_summary(attempt)['restores'][0]['restore_error_state'] == 'FALSE'
    assert w.m.case_summary(attempt, 'E-CODE')['restores'][0]['restore_error_state'] == 'UNKNOWN'


def test_malformed_d_claim_is_consumed_existence_only_and_never_reused(w):
    assert w.m.consumed_claims_present()[MALFORMED_D_CLAIM] is True
    assert w.run() == 0
    assert not any(MALFORMED_D_CLAIM in a for argv in w.spawned for a in argv)
    assert json.loads((w.scratch / NEW_CLAIM).read_text())['budget'] == BUDGET
    w.consumed_unchanged()
    (w.scratch / MALFORMED_D_CLAIM).chmod(0o600)
    (w.scratch / MALFORMED_D_CLAIM).unlink()
    assert w.m.consumed_claims_present()[MALFORMED_D_CLAIM] is False
    w.retained.pop(MALFORMED_D_CLAIM)


# Adopted production Firefox 156.0.1, end to end through the real owner binder -------------------

PLIST = {'CFBundleIdentifier': 'org.mozilla.firefox', 'CFBundleShortVersionString': '156.0.1',
         'CFBundleVersion': '15626.9.21', 'CFBundleExecutable': 'firefox'}
INI = '[App]\nVendor=Mozilla\nName=Firefox\nVersion=156.0.1\nBuildID=20260921121718\n'


@pytest.fixture
def owner(w, monkeypatch):
    """The real `cnt_firefox_production.bind_runtime` on a synthetic Firefox.app: real Info.plist and
    application.ini; the tree and executable digests are faked on the owner module."""
    import plistlib
    app = w.tmp / 'Firefox.app'
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Resources').mkdir()
    (app / 'Contents/MacOS/firefox').write_bytes(b'synthetic executable')
    w.write_plist = lambda values: (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(values))
    w.write_ini = lambda text: (app / 'Contents/Resources/application.ini').write_text(text)
    w.write_plist(PLIST)
    w.write_ini(INI)
    w.tree, w.executable = PRODUCTION_RUNTIME, PRODUCTION_EXECUTABLE
    monkeypatch.setattr(w.m.firefox, 'bind_runtime', w.real_bind_runtime)
    monkeypatch.setattr(w.m.firefox, 'tree_digest', lambda root, trace=None: w.tree)
    monkeypatch.setattr(w.m.firefox, 'executable_digest', lambda runtime: w.executable)
    return w


def test_matrix_bind_accepts_the_adopted_156_identity_end_to_end(owner):
    path, _ = owner.bind()
    identity = json.loads(path.read_text())['identity']
    assert (identity['runtime_sha256'], identity['executable_sha256']) == (PRODUCTION_RUNTIME, PRODUCTION_EXECUTABLE)
    assert identity['firefox'] == {'version': '156.0.1', 'bundle_identifier': 'org.mozilla.firefox',
                                   'bundle_version': '15626.9.21', 'build_id': '20260921121718'}
    assert owner.spawned == [] and not (owner.scratch / NEW_CLAIM).exists()


SUPERSEDED = {
    'tree': (lambda w: setattr(w, 'tree', SUPERSEDED_RUNTIME), 'Firefox runtime differs from the production runtime'),
    'executable': (lambda w: setattr(w, 'executable', SUPERSEDED_EXECUTABLE),
                   'Firefox executable differs from the production executable'),
    'plist-version': (lambda w: w.write_plist({**PLIST, 'CFBundleShortVersionString': '155.0.1'}),
                      'Firefox bundle version differs'),
    'ini-version': (lambda w: w.write_ini(INI.replace('Version=156.0.1', 'Version=155.0.1')),
                    'Firefox application.ini version differs'),
    'whole-155': (lambda w: (w.write_plist({**PLIST, 'CFBundleShortVersionString': '155.0.1'}),
                             setattr(w, 'tree', SUPERSEDED_RUNTIME), setattr(w, 'executable', SUPERSEDED_EXECUTABLE)),
                  'Firefox bundle version differs')}


@pytest.mark.parametrize('case', sorted(SUPERSEDED))
def test_matrix_bind_refuses_the_superseded_155_identity_end_to_end(owner, case):
    damage, message = SUPERSEDED[case]
    damage(owner)
    with pytest.raises(owner.m.VerificationError) as error:
        owner.m.main(owner.argv('bind'))
    assert str(error.value) == message
    assert not list(owner.root.glob('BIND-*.json')) and owner.spawned == []
    assert not (owner.scratch / NEW_CLAIM).exists() and not (owner.root / 'MATRIX.claim').exists()
    owner.consumed_unchanged()


def test_post_claim_runtime_refusal_records_the_owner_code(owner, monkeypatch):
    real = owner.d2.exclusive

    def exclusive(path, record):
        real(path, record)
        if Path(path).name == 'MATRIX.claim':
            owner.tree = SUPERSEDED_RUNTIME  # the post-claim runtime bind now fails
    monkeypatch.setattr(owner.d2, 'exclusive', exclusive)
    assert owner.run() == 0
    state = owner.state()
    assert state['phase'] == 'RUNNER_REFUSED' and state['attempts'] == []
    assert state['runner_failure'] == {'type': 'VerificationError', 'code': 'FIREFOX_RUNTIME_DIFFERS'}
    assert 'runtime_before_first' not in state and 'runtime_after_last' not in state
    assert not any('--matrix-case' in argv for argv in owner.spawned)


# --- MULTIPART-B-PREP1: the multipart-b run, gates and v8 projections ------------------------------

def test_bind_names_the_eight_case_multipart_budget_and_its_claim(w):
    path, _ = w.bind(budget=B_BUDGET)
    record = json.loads(path.read_text())
    assert record['cases'] == B_CASES and record['budget'] == B_BUDGET and record['host_claim'] == B_CLAIM
    assert record['consumed_claims_present'] == CONSUMED_ALL
    assert record['launch_options']['S-MULTI'].count('--matrix-input') == 0
    for case in B_CASES[1:]:
        options = record['launch_options'][case]
        assert options[options.index('--matrix-input') + 1] == '<SOURCE>'
    assert w.spawned == [] and not (w.scratch / B_CLAIM).exists() and not (w.root / 'MATRIX.claim').exists()
    w.consumed_unchanged()


def test_multipart_b_runs_eight_cases_on_the_same_root_s_multi(w):
    assert w.run(budget=B_BUDGET) == 0
    assert w.launched() == ['pytest', 'pytest', *B_CASES]
    for argv in w.spawned[3:]:
        assert argv[argv.index('--matrix-input') + 1] == str(w.root / 'cases/S-MULTI')
    scratches = [argv[argv.index('--scratch') + 1] for argv in w.spawned[2:]]
    assert scratches == [str(w.root / 'cases' / c) for c in B_CASES]
    claim = json.loads((w.scratch / B_CLAIM).read_text())
    assert claim['budget'] == B_BUDGET and (w.root / 'MATRIX.claim').exists()
    assert not (w.scratch / NEW_CLAIM).exists()
    state = w.state()
    assert state['runtime_before_first'] == state['runtime_after_last'] == 'MATCH'
    summary = w.summary()
    assert summary['schema'] == 'bux-r6-firefox-matrix-summary-v8' and summary['budget'] == B_BUDGET
    assert summary['label'] == 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'
    assert summary['semantic_success_claimed'] is False and summary['qualification_accepted'] is False
    source = summary['cases']['S-MULTI']
    assert source['multi_source_ready'] is True and source['multi_source_missing'] == []
    assert source['multipart_evidence']['role'] == 'SOURCE' and 'source_binding' not in source
    assert not {'pre_restore_error_ribbon', 'report_observability', 'legacy_basis'} & set(source)
    for case in B_CASES[1:]:
        projected = summary['cases'][case]
        assert projected['multipart_evidence']['case'] == case and projected['multipart_input']['proven'] is True
        assert projected['compat_evidence'] is None and projected['malformed_evidence'] is None
        # A clean-looking B completion stays UNKNOWN under partial observability.
        restore = projected['restores'][0]
        assert (restore['completion'], restore['restore_error_state'], restore['state_consistent']) == (
            'COMPLETED', 'UNKNOWN', True)
        assert projected['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
        assert projected['pre_restore_error_ribbon'] == 'HIDDEN'
        assert projected['legacy_basis'] == 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'
        binding = projected['source_binding']
        assert binding['source_case'] == 'S-MULTI' and binding['artifact'] == 'minimum'
        assert binding['source_multi_source_ready'] is True and binding['source_artifact_ready'] is True
        assert binding['selection_kind'] == w.m.matrix.case(case)['selection']
        if case in B_MUTATED:
            assert binding['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE' and binding['input_mutated'] is True
            assert binding['original_semantic_matches_source'] is True
        else:
            # A selection transform leaves the input parts the exact ready source.
            assert binding['binding_class'] == 'EXACT_SOURCE_INPUT' and binding['given_semantic_matches_source']
    text = json.dumps(summary)
    for leak in ('part-1.json', 'Part 1.json', str(w.scratch), '/Users', 'inputs/select', 'artifacts/minimum'):
        assert leak not in text, leak
    w.consumed_unchanged()


@pytest.mark.parametrize('present', [True, False], ids=['all-historical-present', 'all-historical-absent'])
def test_historical_claim_sentinels_are_never_a_gate_in_either_direction(w, present):
    """Only the current budget's claim (and MATRIX.claim) gates a run; historical names are lineage."""
    if not present:
        for name, path in list(w.retained.items()):
            path.chmod(0o600)
            path.unlink()
        w.retained.clear()
    assert w.run(budget=B_BUDGET) == 0
    assert w.launched()[2:] == B_CASES
    assert w.state()['consumed_claims_present'] == dict.fromkeys(CONSUMED_ALL, present)
    assert w.summary()['label'] == 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'
    # The current claim's presence is the one filesystem gate.
    path = sorted(w.root.glob('BIND-*.json'))[-1]
    with pytest.raises(w.m.VerificationError, match='already claimed on this host'):
        w.m.main(w.argv('run', bind_record=str(path), budget=B_BUDGET,
                        bind_record_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))


def test_an_existing_current_multipart_claim_refuses_before_prerequisites(w):
    (w.scratch / B_CLAIM).write_text('{"consumed": "elsewhere"}\n')
    with pytest.raises(w.m.VerificationError, match='already claimed on this host'):
        w.run(budget=B_BUDGET)
    assert not any('pytest' in argv for argv in w.spawned) and not (w.root / 'MATRIX.claim').exists()


@pytest.mark.parametrize('at', B_CASES)
def test_multipart_b_stops_at_the_first_non_completed_case_in_each_position(w, at):
    w.statuses[at] = 'BLOCKED'
    assert w.run(budget=B_BUDGET) == 0
    state, ran = w.state(), B_CASES[:B_CASES.index(at) + 1]
    assert [a['case'] for a in state['attempts']] == ran and w.launched()[2:] == ran  # no retry, no fallback
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at
    assert state['runtime_after_last'] == 'MATCH'
    assert w.summary()['label'] == 'R6_MATRIX_STOPPED_AT_CASE'
    assert (w.scratch / B_CLAIM).exists() and (w.root / 'MATRIX.claim').exists()


@pytest.mark.parametrize('damage', ['unready', 'missing-listed', 'artifact-unready', 'rich-keys-only', 'not-completed'])
def test_b_dependents_need_the_same_root_s_multi_ready_before_launch(w, damage):
    def edit(result):
        facts = result['matrix']
        if damage == 'unready':
            facts['classifications'].update(multi_source_ready=False, multi_source_missing=['boundary:exact'])
        elif damage == 'missing-listed':
            facts['classifications']['multi_source_missing'] = ['at_t:header_premise']
        elif damage == 'artifact-unready':
            facts['artifacts']['minimum']['source_ready'] = None
        elif damage == 'rich-keys-only':
            # An S-RICH-shaped readiness record never satisfies the S-MULTI gate.
            for key in ('multi_source_ready', 'multi_source_missing'):
                facts['classifications'].pop(key)
            facts['classifications'].update(rich_source_ready=True, rich_source_missing=[])
        else:
            facts['completed'] = False
    w.edits['S-MULTI'] = edit  # the attempt still reports MATRIX_ATTEMPT_COMPLETED
    assert w.run(budget=B_BUDGET) == 0
    state = w.state()
    assert w.launched()[2:] == ['S-MULTI']  # no dependent is spawned
    assert state['phase'] == 'RUNNER_REFUSED' and state['stopped_at'] == 'T-MULTI-ORDERED'
    assert state['runner_failure'] == {'type': 'VerificationError', 'code': 'MATRIX_INPUT_SOURCE_INVALID'}
    assert state['attempts'][-1] == {'case': 'T-MULTI-ORDERED', 'status': 'NOT_LAUNCHED_SOURCE_INVALID'}
    assert state['runtime_after_last'] == 'MATCH'  # the source was launched
    assert w.summary()['label'] == 'R6_MATRIX_RUNNER_REFUSED'


@pytest.mark.parametrize('after', B_CASES[1:-1])
def test_s_multi_readiness_is_re_read_before_every_b_dependent(w, after):
    def damage():
        path = w.root / 'cases/S-MULTI/result.json'
        result = json.loads(path.read_text())
        result['matrix']['classifications'].update(multi_source_ready=False, multi_source_missing=['rows:stable'])
        path.write_text(json.dumps(result))
    w.after[after] = damage
    assert w.run(budget=B_BUDGET) == 0
    state, following = w.state(), B_CASES[B_CASES.index(after) + 1]
    assert w.launched()[2:] == B_CASES[:B_CASES.index(after) + 1]
    assert state['phase'] == 'RUNNER_REFUSED' and state['stopped_at'] == following
    assert state['runtime_after_last'] == 'MATCH' and not (w.root / 'cases' / following).exists()


def refused_for_selection(result):
    """What the session and preflight record when the B selection proof refuses: BLOCKED, the restore
    step FAILED, the unproven proof and no ribbon read, restore, classification or evidence."""
    facts = result['matrix']
    facts.update(completed=False, classifications={},
                 multipart_input=dict(facts['multipart_input'], proven=False, selection_class='UNEXPECTED'),
                 steps=[{'step': 'open_settings', 'status': 'DONE'}, {'step': 'pre_export', 'status': 'DONE'},
                        {'step': 'restore', 'status': 'FAILED', 'error_type': 'VerificationError'}])
    for key in ('restores', 'multipart_evidence', 'pre_restore_error_ribbon'):
        facts.pop(key, None)
    result['primary_failure'] = {'stage': 'browser', 'type': 'VerificationError',
                                 'classification': 'Matrix multipart input unproven',
                                 'code': 'MATRIX_MULTIPART_INPUT_UNPROVEN', 'message_known': True}


def refused_for_ribbon_b(result):
    facts = result['matrix']
    refused_for_selection(result)
    facts['multipart_input'] = dict(facts['multipart_input'], proven=True, selection_class='ordered')
    facts['pre_restore_error_ribbon'] = 'VISIBLE'
    result['primary_failure'].update(classification='Matrix pre-existing error ribbon',
                                     code='MATRIX_PREEXISTING_ERROR_RIBBON')


@pytest.mark.parametrize('refusal,code', [(refused_for_selection, 'MATRIX_MULTIPART_INPUT_UNPROVEN'),
                                          (refused_for_ribbon_b, 'MATRIX_PREEXISTING_ERROR_RIBBON')],
                         ids=['proof', 'ribbon'])
@pytest.mark.parametrize('at', ['T-MULTI-ORDERED', 'T-MULTI-DUP', 'T-MULTI-BADDATA'])
def test_b_refusal_before_selection_stops_at_that_case(w, at, refusal, code):
    w.statuses[at] = 'BLOCKED'
    w.edits[at] = refusal
    assert w.run(budget=B_BUDGET) == 0
    state, ran = w.state(), B_CASES[:B_CASES.index(at) + 1]
    assert w.launched()[2:] == ran
    assert state['phase'] == 'STOPPED' and state['stopped_at'] == at
    assert state['runtime_after_last'] == 'MATCH'  # verified after the last launched case
    projected = w.summary()['cases'][at]
    assert projected['status'] == 'BLOCKED' and projected['primary_failure']['code'] == code
    assert projected['restores'] == [] and projected['multipart_evidence'] is None
    assert projected['multipart_input']['proven'] is (code != 'MATRIX_MULTIPART_INPUT_UNPROVEN')
    w.consumed_unchanged()


def test_runtime_drift_after_a_b_launch_is_recorded_after_the_last_launch(w, monkeypatch):
    runtimes = []
    def runtime(r):
        runtimes.append(r)
        if len(runtimes) >= 4:  # bind, re-bind, before first, after last
            w.d2.require(False, 'Firefox runtime differs from the production runtime')
        return dict(w.m.firefox.IDENTITY)
    monkeypatch.setattr(w.m.firefox, 'bind_runtime', runtime)
    w.statuses['T-MULTI-NO-P1'] = 'BLOCKED'
    assert w.run(budget=B_BUDGET) == 0
    state = w.state()
    assert len(runtimes) == 4 and state['stopped_at'] == 'T-MULTI-NO-P1'
    assert state['runtime_after_last'] == 'MISMATCH_OR_UNREADABLE'
    assert w.summary()['label'] != 'R6_MATRIX_CASES_RECORDED_PENDING_MANAGER_REVIEW'


def test_multipart_collect_is_read_only_and_launches_nothing(w, monkeypatch):
    assert w.run(budget=B_BUDGET) == 0
    claims = {p.name: p.read_bytes() for p in list(w.scratch.glob('*.claim')) + [w.root / 'MATRIX.claim']
              if p.name not in RETAINED}
    spawned = list(w.spawned)
    def forbidden(*a, **kw):
        raise AssertionError('collect must not launch, bind or call Nix')
    for target, name in ((w.d2, 'spawn'), (w.m.firefox, 'bind_runtime'), (w.d2, 'predicted_template'),
                         (w.m, 'signature'), (w.m.subprocess, 'run'), (w.d2, 'exclusive')):
        monkeypatch.setattr(target, name, forbidden)
    assert w.m.main(['collect', '--claim-root', str(w.root)]) == 0
    assert w.spawned == spawned
    assert {p.name: p.read_bytes() for p in list(w.scratch.glob('*.claim')) + [w.root / 'MATRIX.claim']
            if p.name not in RETAINED} == claims
    w.consumed_unchanged()


def test_unsafe_multipart_evidence_or_proof_is_refused_without_hiding_the_case(w):
    w.edits['T-MULTI-REVERSED'] = lambda r: r['matrix']['multipart_evidence'].update(
        rows={'raw': '/Users/someone/raw part bytes'})
    w.edits['T-MULTI-NO-P1'] = lambda r: r['matrix']['multipart_input'].update(detail='/Users/someone raw')
    w.edits['S-MULTI'] = lambda r: (source_multi(r), r['matrix']['multipart_evidence'].update(
        source={'part_path': '/Users/someone/artifacts/minimum/part-1.json'}))
    assert w.run(budget=B_BUDGET) == 0
    summary = w.summary()
    assert summary['cases']['T-MULTI-REVERSED']['multipart_evidence'] == {'projection': 'REFUSED'}
    assert summary['cases']['T-MULTI-NO-P1']['multipart_input'] == {'projection': 'REFUSED'}
    assert summary['cases']['S-MULTI']['multipart_evidence'] == {'projection': 'REFUSED'}
    assert summary['cases']['T-MULTI-REVERSED']['status'] == 'MATRIX_ATTEMPT_COMPLETED'
    assert summary['cases']['S-MULTI']['multi_source_ready'] is True
    assert '/Users' not in json.dumps(summary)


@pytest.mark.parametrize('tamper', ['readiness-digest', 'before', 'no-original'])
def test_multipart_mutation_binding_discloses_a_mismatch_without_raising(w, tamper):
    def edit(result):
        inputs = result['matrix_inputs']
        if tamper == 'readiness-digest':
            result['matrix']['multipart_evidence']['source']['original_semantic_sha256'] = 'd' * 64
        elif tamper == 'before':
            inputs['mutation']['before_sha256'] = 'c' * 64
        else:
            del inputs['original']
    w.edits['T-MULTI-TRUNC'] = edit
    assert w.run(budget=B_BUDGET) == 0
    summary = w.summary()
    assert summary['cases']['T-MULTI-TRUNC']['source_binding']['binding_class'] == 'MISMATCH'
    assert summary['cases']['T-MULTI-BADDATA']['source_binding']['binding_class'] == 'DECLARED_MUTATION_OF_SOURCE'
