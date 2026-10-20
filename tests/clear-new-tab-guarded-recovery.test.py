"""BUX5B1 RECOVERY-PREP1 guarded recovery/capture: portable, temporary-root-only tests.

No browser, profile, native import/export, XPI, Shared Images, cloud or operator root is
touched. Adapters are in-memory recording fakes. The 6.12.1 fixture bytes were exported on
Firefox 155.0.1 and are NOT accepted 156.0.1 evidence; under the projected labels they are
synthetic test vectors only, exactly as in the BUX5B0C foundation tests.
"""
import ast
import builtins
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import pytest

LIBRARY = 'libexec/clear-new-tab/guarded_recovery.py'
FOUNDATION = 'libexec/clear-new-tab/durable_state.py'
FOUNDATION_SHA256 = '7a1dd704988088c22d1502b72318183960c8f70e3bde6e9908ec42255c653eea'
SYNC_SHA256 = 'e24566ca833ef447cc849de4a4694bce22f53c32d58e7e85eeab13dfc91c0fc6'
FIXTURE = Path('tests/fixtures/cnt-native/firefox/6.12.1')
PROFILE, STORAGE, STAGE_PROFILE, STAGE_STORAGE, OBSERVATION = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64)
JOURNAL = 'recovery-1'


@pytest.fixture
def gr(load_module):
    return load_module(LIBRARY)


@pytest.fixture
def native(repo_root):
    return json.loads((repo_root / FIXTURE / 'export.json').read_bytes())


@pytest.fixture
def labels(gr):
    # Synthetic test vector labels: the fixture is not accepted 156.0.1 evidence.
    return dict(gr.ds.PROJECTED_LABELS)


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'state'
    path.mkdir()
    return path


def dump(value):
    return json.dumps(value).encode()


def state(native, variant=0, split=False):
    """Ordered native part list; variant changes a known, non-volatile preference."""
    value = copy.deepcopy(native)
    if variant:
        value['settings']['prefs']['transition_duration'] = 200 + variant
    if not split:
        return [dump(value)]
    return [dump(dict(value, chunks=value['chunks'][:2])), dump({'chunks': value['chunks'][2:]})]


def export_of(labels, parts):
    return {'labels': dict(labels), 'part_count': len(parts), 'parts': list(parts)}


def target_record(labels, profile=PROFILE, storage=STORAGE):
    return {'labels': dict(labels), 'profile_token': profile, 'storage_token': storage}


def refuse(code, function, *args, **kwargs):
    """Every refusal is the bare code: no path, native text or chained cause."""
    with pytest.raises(Exception) as caught:
        function(*args, **kwargs)
    error = caught.value
    assert type(error).__name__ == 'RecoveryError', repr(error)
    assert str(error) == code and error.args == (code,)
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    return error


def store(gr, root, labels, parts, **kwargs):
    target = gr.bind_target(target_record(labels))
    return gr.capture_export(root, gr.verify_export(export_of(labels, parts), target), **kwargs)


def disk_journal(root, journal_id=JOURNAL):
    path = root / 'recovery' / journal_id / 'journal.json'
    return json.loads(path.read_bytes()) if path.exists() else None


class Fake:
    """Recording adapter over an in-memory live part list. hooks[name](fake, n, *args) may
    mutate state or raise before the default behavior runs (n counts that call name)."""

    def __init__(self, root, labels, parts, hooks=None):
        self.root, self.labels, self.parts = root, dict(labels), list(parts)
        self.identity_record = target_record(labels)
        self.staging_record = target_record(labels, STAGE_PROFILE, STAGE_STORAGE)
        self.hooks, self.calls, self.counts, self.disk = hooks or {}, [], {}, []
        self.applied, self.rolled = [], []

    def _enter(self, name, *args):
        self.calls.append(name)
        self.counts[name] = self.counts.get(name, 0) + 1
        journal = disk_journal(self.root)
        self.disk.append((name, journal and journal['status']))
        if name in self.hooks:
            self.hooks[name](self, self.counts[name], *args)

    def identity(self):
        self._enter('identity')
        return dict(self.identity_record, labels=dict(self.identity_record['labels']))

    def export_current(self):
        self._enter('export')
        return export_of(self.labels, self.parts)

    def stage(self, parts):
        self._enter('stage', parts)
        return {'identity': dict(self.staging_record), 'export': export_of(self.labels, parts)}

    def apply(self, parts):
        self._enter('apply', parts)
        self.applied.append(tuple(parts))
        self.parts = list(parts)

    def rollback(self, parts):
        self._enter('rollback', parts)
        self.rolled.append(tuple(parts))
        self.parts = list(parts)


@pytest.fixture
def scene(gr, root, native, labels):
    """current = variant 0 (one part); requested = variant 1 (two parts), stored and verified."""
    class Scene:
        pass
    s = Scene()
    s.current_parts = state(native)
    s.requested_parts = state(native, 1, split=True)
    s.other_parts = state(native, 2)
    s.requested = store(gr, root, labels, s.requested_parts)
    s.target = gr.bind_target(target_record(labels))
    s.current = gr.verify_export(export_of(labels, s.current_parts), s.target)
    s.other = gr.verify_export(export_of(labels, s.other_parts), s.target)
    s.adapter = Fake(root, labels, s.current_parts)
    s.authorization = {'schema': gr.AUTHORIZATION_SCHEMA, 'labels': dict(labels), 'profile_token': PROFILE,
                       'storage_token': STORAGE, 'requested_manifest_sha256': s.requested.manifest_sha256,
                       'requested_fingerprint': s.requested.fingerprint,
                       'before_fingerprint': s.current.fingerprint}
    s.evidence = {'schema': gr.RESET_EVIDENCE_SCHEMA, 'kind': gr.QUALIFICATION_SYNTHETIC_RESET,
                  'labels': dict(labels), 'profile_token': PROFILE, 'storage_token': STORAGE,
                  'observed_fingerprint': s.current.fingerprint, 'observation_sha256': OBSERVATION}
    s.policy = gr.qualification_reset_policy(labels, s.current.fingerprint)

    def run(**kwargs):
        kwargs.setdefault('authorization', s.authorization)
        journal_id = kwargs.pop('journal_id', JOURNAL)
        return gr.recover(root, journal_id, s.target, s.requested.manifest_sha256, s.adapter, **kwargs)
    s.run = run
    return s


def statuses(outcome):
    return [entry['status'] for entry in outcome.journal['history']]


def bounded(adapter):
    assert adapter.calls.count('apply') <= 1 and adapter.calls.count('rollback') <= 1


# --- Source discipline, bounded codes and foundation binding --------------------------------------

def test_library_source_discipline(repo_root):
    text = (repo_root / LIBRARY).read_text()
    assert not text.startswith('#!')
    for forbidden in ('environ', 'expanduser', 'Path.home', '/Users/', '/home/', 'assert ', 'subprocess',
                      'import cnt_', 'getenv', 'socket', 'canonical_root(', 'signal', 'sleep', '.kill',
                      'sys.path', 'sys.modules[', 'while True'):
        assert forbidden not in text, forbidden
    assert not re.search(r'\bprint\(', text)
    # Non-executable; the exact 0644 source mode is pinned by the source manifest (store copies are 0444).
    assert (repo_root / LIBRARY).stat().st_mode & 0o111 == 0


def test_every_refusal_literal_is_bounded(gr, repo_root):
    tree = ast.parse((repo_root / LIBRARY).read_text())
    found, failures, keys = set(), set(), set()
    positions = {'_require': slice(1, 2), 'RecoveryError': slice(0, 1), '_bounded': slice(0, 1),
                 '_plan': slice(1, 2)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, 'id', None)
            for arg in node.args[positions[name]] if name in positions else []:
                lookups = [n.slice for n in ast.walk(arg) if isinstance(n, ast.Subscript)]
                for key in lookups:
                    options = [key.body, key.orelse] if isinstance(key, ast.IfExp) else [key]
                    keys |= {o.value for o in options if isinstance(o, ast.Constant)}
                skip = {id(n) for s in lookups for n in ast.walk(s)}
                found |= {n.value for n in ast.walk(arg)
                          if isinstance(n, ast.Constant) and type(n.value) is str and id(n) not in skip}
            for keyword in node.keywords:
                if keyword.arg == 'failure':
                    failures |= {n.value for n in ast.walk(keyword.value) if isinstance(n, ast.Constant)}
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '').endswith('_CODES') for t in node.targets) \
                and isinstance(node.value, ast.Dict):
            found |= {v.value for v in node.value.values}
    found.discard(None)
    assert found and found <= set(gr.REFUSAL_CODES)
    # codes['KEY'] lookups resolve through every per-object code map.
    assert keys and all(keys <= set(table) for table in (gr._PART_CODES, gr._MANIFEST_CODES, gr._JOURNAL_CODES))
    assert failures and failures <= {c for codes in gr.ds.FAILURE_CODES.values() for c in codes}
    assert len(gr.REFUSAL_CODES) == len(set(gr.REFUSAL_CODES))


def test_foundation_is_unchanged_private_sibling(gr, repo_root):
    assert hashlib.sha256((repo_root / FOUNDATION).read_bytes()).hexdigest() == FOUNDATION_SHA256
    manifest = json.loads((repo_root / 'tests/fixtures/command-source-manifest.json').read_text())
    assert manifest[FOUNDATION]['destination_sha256'] == FOUNDATION_SHA256
    assert Path(gr.ds.__file__) == repo_root / FOUNDATION
    assert 'browser_ux_cnt_durable_state' not in sys.modules
    assert gr.REFUSAL_CODES[:len(gr.ds.REFUSAL_CODES)] == gr.ds.REFUSAL_CODES


# --- Prerequisite A: confined native-artifact locator ----------------------------------------

def records(gr, parts):
    return gr.ds.native_artifact_records(list(parts))


def place(root, parts):
    folder = root / 'native' / 'sha256'
    folder.mkdir(parents=True, exist_ok=True)
    for raw in parts:
        (folder / hashlib.sha256(raw).hexdigest()).write_bytes(raw)
    return folder


def test_locator_returns_exact_ordered_bytes(gr, root, native):
    parts = state(native, 1, split=True)
    place(root, parts)
    assert gr.locate_native_parts(root, records(gr, parts)) == tuple(parts)
    assert gr.native_part_relpath(hashlib.sha256(parts[0]).hexdigest()).startswith('native/sha256/')


def test_locator_refuses_bad_order_and_index(gr, root, native):
    parts = state(native, 1, split=True)
    place(root, parts)
    good = records(gr, parts)
    for mutate in (lambda r: r.reverse(), lambda r: r.append(dict(r[0])), lambda r: r.__setitem__(1, dict(r[1], part_index=3)),
                   lambda r: r.__setitem__(0, dict(r[0], part_index=True)), lambda r: r.__setitem__(1, dict(r[1], part_index='2')),
                   lambda r: r.__setitem__(0, dict(r[0], role='other')), lambda r: r.__setitem__(0, dict(r[0], extra=1)),
                   lambda r: r.clear()):
        bad = copy.deepcopy(good)
        mutate(bad)
        refuse('NATIVE_PART_ORDER_INVALID', gr.locate_native_parts, root, bad)
    refuse('NATIVE_PART_ORDER_INVALID', gr.locate_native_parts, root, tuple(good))


def test_locator_missing_symlink_and_root(gr, root, tmp_path, native):
    parts = state(native)
    refuse('NATIVE_PART_MISSING', gr.locate_native_parts, root, records(gr, parts))
    elsewhere = tmp_path / 'elsewhere'
    place(elsewhere, parts)
    (root / 'native').mkdir()
    (root / 'native' / 'sha256').symlink_to(elsewhere / 'native' / 'sha256')
    refuse('NATIVE_PART_SYMLINK', gr.locate_native_parts, root, records(gr, parts))
    (root / 'native' / 'sha256').unlink()
    folder = place(root, [])
    digest = hashlib.sha256(parts[0]).hexdigest()
    (folder / digest).symlink_to(elsewhere / 'native' / 'sha256' / digest)
    refuse('NATIVE_PART_SYMLINK', gr.locate_native_parts, root, records(gr, parts))
    linked = tmp_path / 'linked-root'
    linked.symlink_to(elsewhere)
    refuse('ROOT_INVALID', gr.locate_native_parts, linked, records(gr, parts))
    refuse('ROOT_INVALID', gr.locate_native_parts, 'relative/root', records(gr, parts))


def test_locator_refuses_fifo_and_directory_without_blocking(gr, root, native):
    parts = state(native)
    folder = place(root, [])
    digest = hashlib.sha256(parts[0]).hexdigest()
    os.mkfifo(folder / digest)
    refuse('NATIVE_PART_NOT_REGULAR', gr.locate_native_parts, root, records(gr, parts))
    (folder / digest).unlink()
    (folder / digest).mkdir()
    refuse('NATIVE_PART_NOT_REGULAR', gr.locate_native_parts, root, records(gr, parts))


def test_locator_refuses_object_swapped_after_lstat(gr, root, native, monkeypatch):
    parts = state(native)
    folder = place(root, parts)
    digest = hashlib.sha256(parts[0]).hexdigest()
    (folder / 'swap').write_bytes(parts[0])
    real_open, swapped = os.open, []

    def swapping(path, flags, mode=0o777, *, dir_fd=None):
        if path == digest and not swapped:
            swapped.append(True)
            os.replace(folder / 'swap', folder / digest)
        return real_open(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(gr.os, 'open', swapping)
    refuse('NATIVE_PART_NOT_REGULAR', gr.locate_native_parts, root, records(gr, parts))
    assert swapped


def test_locator_final_open_errors_are_classified(gr, root, native, monkeypatch):
    parts = state(native)
    folder = place(root, parts)
    digest = hashlib.sha256(parts[0]).hexdigest()
    real_open = os.open
    for error, code in ((OSError(errno.EACCES, 'denied'), 'NATIVE_PART_UNREADABLE'),
                        (OSError(errno.ELOOP, 'loop'), 'NATIVE_PART_SYMLINK'),
                        (OSError(errno.ENOENT, 'gone'), 'NATIVE_PART_MISSING')):
        def failing(path, flags, mode=0o777, *, dir_fd=None, error=error):
            if path == digest:
                raise error
            return real_open(path, flags, mode, dir_fd=dir_fd)
        monkeypatch.setattr(gr.os, 'open', failing)
        refuse(code, gr.locate_native_parts, root, records(gr, parts))
    assert (folder / digest).exists()


def test_locator_size_digest_and_caps(gr, root, native, monkeypatch):
    parts = state(native)
    folder = place(root, [])
    digest = hashlib.sha256(parts[0]).hexdigest()
    for wrong in (parts[0] + b' ', parts[0][:-1]):
        (folder / digest).write_bytes(wrong)
        refuse('NATIVE_PART_SIZE_MISMATCH', gr.locate_native_parts, root, records(gr, parts))
    (folder / digest).write_bytes(parts[0][:-1] + b'!')
    refuse('NATIVE_PART_DIGEST_MISMATCH', gr.locate_native_parts, root, records(gr, parts))
    (folder / digest).write_bytes(parts[0])
    assert gr.locate_native_parts(root, records(gr, parts)) == tuple(parts)
    monkeypatch.setattr(gr, 'MAX_PART_SET_BYTES', len(parts[0]) - 1)
    refuse('NATIVE_SET_TOO_LARGE', gr.locate_native_parts, root, records(gr, parts))
    monkeypatch.setattr(gr, 'MAX_NATIVE_PART_BYTES', len(parts[0]) - 1)
    refuse('NATIVE_PART_TOO_LARGE', gr.locate_native_parts, root, records(gr, parts))


# --- Prerequisite B: part-verified manifest type discipline -----------------------------------

def test_verified_types_cannot_be_constructed_or_mutated(gr, scene):
    for cls in (gr.VerifiedManifest, gr.TargetIdentity, gr.Plan, gr.ResetPolicy, gr.Outcome):
        refuse('UNVERIFIED_INPUT', cls)
    refuse('RECOVERY_INVALID', setattr, scene.requested, 'fingerprint', '0' * 64)
    refuse('RECOVERY_INVALID', delattr, scene.requested, 'fingerprint')
    refuse('RECOVERY_INVALID', setattr, scene.target, 'profile_token', '0' * 64)
    labels = scene.requested.labels
    labels['engine'] = 'chrome'
    assert scene.requested.labels['engine'] == 'firefox'
    assert copy.deepcopy(scene.requested) is scene.requested


def test_planner_accepts_only_verified_records(gr, scene):
    value = scene.requested.fingerprint

    class Duck:
        origin, fingerprint, projection_status = 'STATE_ROOT', value, 'PROJECTED_FIREFOX_6_12_1'
    for current, requested in ((value, scene.requested), (scene.current, value),
                               (scene.current, scene.requested.manifest), (Duck(), scene.requested),
                               (scene.current, Duck()), (scene.current, scene.current)):
        refuse('UNVERIFIED_INPUT', gr.plan_recovery, scene.target, current, requested)
    refuse('UNVERIFIED_INPUT', gr.plan_recovery, target_record(scene.requested.labels), scene.current, scene.requested)
    refuse('UNVERIFIED_INPUT', gr.plan_recovery, scene.target, scene.current, scene.requested,
           reset_policy={'entries': ()})


def test_internally_consistent_manifest_without_verified_parts_is_refused(gr, root, scene, native, labels):
    parts = state(native, 3)
    manifest = gr.ds.build_manifest(parts, labels)
    raw = gr.ds.serialize_manifest(manifest)
    digest = hashlib.sha256(raw).hexdigest()
    (root / 'content' / 'sha256' / digest).write_bytes(raw)
    refuse('NATIVE_PART_MISSING', gr.load_verified, root, digest)
    tampered = dict(manifest, native_semantic_sha256='0' * 64)
    raw = gr.ds.canonical_bytes(tampered)
    digest = hashlib.sha256(raw).hexdigest()
    (root / 'content' / 'sha256' / digest).write_bytes(raw)
    place(root, parts)
    refuse('ARTIFACT_MISMATCH', gr.load_verified, root, digest)
    (root / 'content' / 'sha256' / ('f' * 64)).write_bytes(raw)
    refuse('STORED_MANIFEST_DIGEST_MISMATCH', gr.load_verified, root, 'f' * 64)
    refuse('STORED_MANIFEST_MISSING', gr.load_verified, root, '9' * 64)
    refuse('DIGEST_MALFORMED', gr.load_verified, root, '../x')
    assert scene.requested.origin == 'STATE_ROOT' and scene.current.origin == 'EXPORT'


def test_verify_export_closure_and_labels(gr, scene, labels):
    parts = scene.current_parts
    refuse('EXPORT_INVALID', gr.verify_export, dict(export_of(labels, parts), extra=1), scene.target)
    refuse('EXPORT_INVALID', gr.verify_export, export_of(labels, [bytearray(parts[0])]), scene.target)
    refuse('EXPORT_INCOMPLETE', gr.verify_export, dict(export_of(labels, parts), part_count=2), scene.target)
    refuse('EXPORT_INCOMPLETE', gr.verify_export, export_of(labels, []), scene.target)
    refuse('EXPORT_INCOMPLETE', gr.verify_export, dict(export_of(labels, parts), part_count=True), scene.target)
    refuse('LABELS_MISMATCH', gr.verify_export, export_of(dict(labels, browser_version='156.0.2'), parts),
           scene.target)
    refuse('UNVERIFIED_INPUT', gr.verify_export, export_of(labels, parts), target_record(labels))
    refuse('TARGET_INVALID', gr.bind_target, dict(target_record(labels), profile_token='/Users/x'))
    refuse('TARGET_INVALID', gr.bind_target, dict(target_record(labels), extra=1))


# --- Pure authorization planner ----------------------------------------------------------------

def test_planner_noop_ignores_authorization_and_evidence(gr, scene):
    for kwargs in ({}, {'authorization': 'garbage'}, {'reset_evidence': {'kind': 'ELAPSED_TIME'}}):
        plan = gr.plan_recovery(scene.target, scene.requested, scene.requested, **kwargs)
        assert (plan.decision, plan.refusal, plan.basis) == ('NOOP', None, None)


def test_planner_refuses_chrome_and_uncharacterized_labels(gr, scene, labels):
    chrome = {'engine': 'chrome', 'extension_id': 'felphkbfjadmcejnibcmcncimlappdde',
              'extension_version': '1.10.0', 'browser_version': None}
    plan = gr.plan_recovery(gr.bind_target(target_record(chrome)), scene.current, scene.requested,
                            authorization=scene.authorization)
    assert (plan.decision, plan.refusal) == ('REFUSE', 'CHROME_UNCHARACTERIZED')
    for change in ({'browser_version': '156.0.2'}, {'browser_version': '155.0.1'}, {'browser_version': None},
                   {'extension_version': '6.12.2'}):
        plan = gr.plan_recovery(gr.bind_target(target_record(dict(labels, **change))), scene.current,
                                scene.requested, authorization=scene.authorization)
        assert (plan.decision, plan.refusal) == ('REFUSE', 'LABELS_UNCHARACTERIZED')


def test_planner_refuses_conversion_and_unprojected_requests(gr, root, scene, native, labels):
    other = dict(labels, browser_version='155.0.1')
    foreign = store(gr, root, other, state(native, 4))
    assert foreign.projection_status == 'NATIVE_ONLY_UNCHARACTERIZED'
    plan = gr.plan_recovery(scene.target, scene.current, foreign, authorization=scene.authorization)
    assert (plan.decision, plan.refusal) == ('REFUSE', 'LABELS_MISMATCH')
    broken = store(gr, root, labels, [b'{"chunks": "not-a-list"}'])
    assert broken.projection_status == 'NATIVE_ONLY_UNPROJECTABLE'
    plan = gr.plan_recovery(scene.target, scene.current, broken, authorization=scene.authorization)
    assert (plan.decision, plan.refusal) == ('REFUSE', 'REQUESTED_NOT_PROJECTED')


def test_planner_operator_authorization_binding(gr, scene):
    plan = gr.plan_recovery(scene.target, scene.current, scene.requested, authorization=scene.authorization)
    assert (plan.decision, plan.basis, plan.before_state) == ('MUTATE_OPERATOR', 'OPERATOR_EXPLICIT', 'PRESENT')
    assert plan.evidence_sha256 == hashlib.sha256(gr.ds.canonical_bytes(scene.authorization)).hexdigest()
    for key, value in (('labels', dict(scene.authorization['labels'], browser_version='156.0.2')),
                       ('profile_token', '0' * 64), ('storage_token', '0' * 64),
                       ('requested_manifest_sha256', '0' * 64), ('requested_fingerprint', '0' * 64),
                       ('before_fingerprint', '0' * 64)):
        plan = gr.plan_recovery(scene.target, scene.current, scene.requested,
                                authorization=dict(scene.authorization, **{key: value}))
        assert (plan.decision, plan.refusal) == ('REFUSE', 'AUTHORIZATION_MISMATCH'), key
    for bad in (dict(scene.authorization, schema='other'), dict(scene.authorization, extra=1),
                {k: v for k, v in scene.authorization.items() if k != 'before_fingerprint'},
                dict(scene.authorization, profile_token='/Users/x'), 'yes', True, {}):
        plan = gr.plan_recovery(scene.target, scene.current, scene.requested, authorization=bad,
                                reset_evidence=scene.evidence, reset_policy=scene.policy)
        assert (plan.decision, plan.refusal) == ('REFUSE', 'AUTHORIZATION_INVALID')


def test_planner_reset_evidence_classes(gr, scene, labels):
    def plan(evidence, policy=scene.policy):
        return gr.plan_recovery(scene.target, scene.current, scene.requested, reset_evidence=evidence,
                                reset_policy=policy)
    accepted = plan(scene.evidence)
    assert (accepted.decision, accepted.basis, accepted.before_state) == (
        'MUTATE_RESET_EVIDENCE', 'POSITIVE_VERSIONED_RESET_EVIDENCE', 'RESET_EVIDENCED')
    assert accepted.evidence_sha256 == hashlib.sha256(gr.ds.canonical_bytes(scene.evidence)).hexdigest()

    def refused(reason, evidence, policy=scene.policy):
        result = plan(evidence, policy)
        assert (result.decision, result.refusal, result.reasons) == ('REFUSE', 'AUTHORIZATION_REQUIRED', (reason,))
    # The shipped policy accepts nothing: automatic mutation is unreachable.
    assert gr.ACCEPTED_RESET_POLICY.entries == ()
    refused('RESET_KIND_UNACCEPTED', scene.evidence, gr.ACCEPTED_RESET_POLICY)
    refused('RESET_EVIDENCE_ABSENT', None)
    refused('RESET_EVIDENCE_ABSENT', None, gr.ACCEPTED_RESET_POLICY)
    for unreadable in (b'', 'UNREADABLE', [], {}, dict(scene.evidence, extra=1), dict(scene.evidence, kind=7),
                       dict(scene.evidence, schema='x'), dict(scene.evidence, observation_sha256='none')):
        refused('RESET_EVIDENCE_INVALID', unreadable)
    for kind in gr.FORBIDDEN_RESET_KINDS:
        refused('RESET_KIND_FORBIDDEN', dict(scene.evidence, kind=kind))
    refused('RESET_KIND_UNACCEPTED', dict(scene.evidence, kind='FACTORY_RESET'))
    for key, value in (('profile_token', '0' * 64), ('storage_token', '0' * 64),
                       ('observed_fingerprint', scene.other.fingerprint)):
        refused('RESET_EVIDENCE_UNBOUND', dict(scene.evidence, **{key: value}))
    refused('RESET_KIND_UNACCEPTED', scene.evidence,
            gr.qualification_reset_policy(dict(labels, browser_version='156.0.2'), scene.current.fingerprint))
    # Evidence of a reset must match the characterized reset state, not arbitrary user state.
    refused('RESET_STATE_UNCHARACTERIZED', scene.evidence, gr.qualification_reset_policy(labels, scene.other.fingerprint))
    refuse('POLICY_INVALID', gr.qualification_reset_policy, labels, 'nope')
    assert [kind for kind, _, _ in scene.policy.entries] == ['QUALIFICATION_SYNTHETIC_RESET']


def test_planner_operator_precedence(gr, scene):
    plan = gr.plan_recovery(scene.target, scene.current, scene.requested, authorization=scene.authorization,
                            reset_evidence=scene.evidence, reset_policy=scene.policy)
    assert plan.decision == 'MUTATE_OPERATOR'
    plan = gr.plan_recovery(scene.target, scene.current, scene.requested,
                            authorization=dict(scene.authorization, before_fingerprint='0' * 64),
                            reset_evidence=scene.evidence, reset_policy=scene.policy)
    assert (plan.decision, plan.refusal) == ('REFUSE', 'AUTHORIZATION_MISMATCH')  # never falls through


def test_planner_is_pure(gr, scene, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('planner I/O')
    for module, name in ((os, 'open'), (os, 'stat'), (os, 'lstat'), (os, 'listdir'), (builtins, 'open')):
        monkeypatch.setattr(module, name, forbidden)
    for kwargs in ({'authorization': scene.authorization}, {'reset_evidence': scene.evidence, 'reset_policy': scene.policy}, {}):
        gr.plan_recovery(scene.target, scene.current, scene.requested, **kwargs)


# --- Guarded orchestration: transitions and exact call order -----------------------------------

FULL = ['identity', 'export', 'stage', 'identity', 'export', 'apply', 'identity', 'export']


def test_completed_by_operator_with_write_ahead_journal(gr, root, scene, tmp_path):
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code, outcome.journal_id) == ('COMPLETED', None, JOURNAL)
    assert scene.adapter.calls == FULL
    assert statuses(outcome) == ['PREPARED', 'STAGED', 'PRESERVED', 'APPLYING', 'COMPLETED']
    # Write-ahead: each side-effecting call ran with the preceding state already on disk.
    assert dict((name, status) for name, status in scene.adapter.disk if name in ('stage', 'apply')) == {
        'stage': 'PREPARED', 'apply': 'APPLYING'}
    assert scene.adapter.applied == [tuple(scene.requested_parts)]
    assert scene.adapter.parts == scene.requested_parts
    journal = outcome.journal
    assert disk_journal(root) == journal
    assert (journal['authorization']['basis'], journal['before_state']) == ('OPERATOR_EXPLICIT', 'PRESENT')
    assert (journal['before_fingerprint'], journal['requested_fingerprint']) == (
        scene.current.fingerprint, scene.requested.fingerprint)
    assert journal['source'] == {'manifest_sha256': scene.requested.manifest_sha256,
                                 'native_artifact_sha256': list(scene.requested.part_digests)}
    preserved = gr.load_verified(root, journal['displaced_state']['sha256'])
    assert preserved.fingerprint == scene.current.fingerprint and preserved.parts == tuple(scene.current_parts)
    assert not (tmp_path / '.local').exists()
    # The authorization record behind evidence_sha256 is retained, content-addressed.
    stored = root / 'content' / 'sha256' / journal['authorization']['evidence_sha256']
    assert stored.read_bytes() == gr.ds.canonical_bytes(scene.authorization)


def test_completed_by_synthetic_reset_evidence(gr, root, scene):
    outcome = scene.run(authorization=None, reset_evidence=scene.evidence, qualification_policy=scene.policy)
    assert outcome.status == 'COMPLETED' and scene.adapter.calls == FULL
    journal = outcome.journal
    assert (journal['authorization']['basis'], journal['before_state']) == (
        'POSITIVE_VERSIONED_RESET_EVIDENCE', 'RESET_EVIDENCED')
    assert journal['authorization']['evidence_sha256'] == hashlib.sha256(
        gr.ds.canonical_bytes(scene.evidence)).hexdigest()
    # The synthetic kind is recoverable from the retained record, not from the journal basis.
    stored = root / 'content' / 'sha256' / journal['authorization']['evidence_sha256']
    assert json.loads(stored.read_bytes())['kind'] == gr.QUALIFICATION_SYNTHETIC_RESET


def test_shipped_policy_refuses_automatic_mutation(gr, root, scene):
    refuse('AUTHORIZATION_REQUIRED', scene.run, authorization=None, reset_evidence=scene.evidence)
    refuse('POLICY_INVALID', scene.run, qualification_policy={'entries': ()})
    assert scene.adapter.calls == ['identity', 'export'] and not (root / 'recovery').exists()


def test_noop_is_unjournaled_and_repeat_is_idempotent(gr, root, scene):
    first = scene.run()
    assert first.status == 'COMPLETED'
    scene.adapter.calls.clear()
    outcome = scene.run(journal_id='recovery-2', authorization=None)
    assert (outcome.status, outcome.journal_id, outcome.journal) == ('NOOP', None, None)
    assert scene.adapter.calls == ['identity', 'export']
    assert not (root / 'recovery' / 'recovery-2').exists()
    assert scene.adapter.applied == [tuple(scene.requested_parts)]  # still the single original apply
    scene.adapter.calls.clear()
    refuse('JOURNAL_EXISTS', scene.run)
    assert scene.adapter.calls == []
    refuse('JOURNAL_ID_INVALID', scene.run, journal_id='../x')
    (root / 'recovery' / 'linked').mkdir()
    (root / 'recovery' / 'linked' / 'journal.json').symlink_to(root / 'recovery' / JOURNAL / 'journal.json')
    refuse('JOURNAL_UNREADABLE', scene.run, journal_id='linked')
    assert scene.adapter.calls == []


def test_staging_failures_fail_before_mutation(gr, scene, labels):
    variants = {
        'raises': lambda f, n, parts: (_ for _ in ()).throw(RuntimeError('/private/path')),
        'same-target': lambda f, n, parts: setattr(f, 'staging_record', target_record(labels)),
        'wrong-labels': lambda f, n, parts: setattr(f, 'staging_record',
                                                    target_record(dict(labels, browser_version='156.0.2'),
                                                                  STAGE_PROFILE, STAGE_STORAGE)),
    }
    for index, (name, hook) in enumerate(variants.items()):
        scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {'stage': hook})
        outcome = scene.run(journal_id=f'stage-{index}')
        assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'STAGING_MISMATCH'), name
        assert scene.adapter.calls == ['identity', 'export', 'stage'] and scene.adapter.applied == []


def test_staged_fingerprint_mismatch_fails_before_mutation(gr, scene, labels):
    class WrongStage(Fake):
        def stage(self, parts):
            self._enter('stage', parts)
            return {'identity': dict(self.staging_record), 'export': export_of(self.labels, scene.other_parts)}
    scene.adapter = WrongStage(scene.adapter.root, labels, scene.current_parts)
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'STAGING_MISMATCH')
    assert statuses(outcome) == ['PREPARED', 'FAILED_BEFORE_MUTATION'] and 'apply' not in scene.adapter.calls


def test_preservation_failure_fails_before_mutation(gr, root, scene):
    conflict = root / 'native' / 'sha256' / hashlib.sha256(scene.current_parts[0]).hexdigest()
    conflict.write_bytes(b'different bytes')
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'PRESERVATION_FAILED')
    assert statuses(outcome) == ['PREPARED', 'STAGED', 'FAILED_BEFORE_MUTATION']
    assert conflict.read_bytes() == b'different bytes'  # never overwritten
    assert scene.adapter.calls == ['identity', 'export', 'stage']


def test_concurrent_change_is_refused_before_apply(gr, scene, labels):
    def change(f, n):
        if n == 2:
            f.parts = list(scene.other_parts)
    scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {'export': change})
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'CONCURRENT_CHANGE')
    assert outcome.journal['history'][-1]['observed_fingerprint'] == scene.other.fingerprint
    assert statuses(outcome) == ['PREPARED', 'STAGED', 'PRESERVED', 'FAILED_BEFORE_MUTATION']
    assert scene.adapter.calls == FULL[:5] and scene.adapter.applied == []

    def swap(f, n):
        if n == 2:
            f.identity_record = target_record(labels, PROFILE, '0' * 64)
    scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {'identity': swap})
    outcome = scene.run(journal_id='recovery-2')
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'CONCURRENT_CHANGE')
    assert scene.adapter.calls == FULL[:4] and scene.adapter.applied == []


def test_post_apply_mismatch_rolls_back_with_preserved_bytes(gr, root, scene, labels):
    class Partial(Fake):
        def apply(self, parts):
            self._enter('apply', parts)
            self.applied.append(tuple(parts))
            self.parts = list(scene.other_parts)
    scene.adapter = Partial(root, labels, scene.current_parts)
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code) == ('ROLLED_BACK', None)
    assert statuses(outcome) == ['PREPARED', 'STAGED', 'PRESERVED', 'APPLYING', 'ROLLBACK_REQUIRED', 'ROLLED_BACK']
    history = outcome.journal['history']
    assert (history[4]['failure_code'], history[4]['observed_fingerprint']) == (
        'VERIFICATION_MISMATCH', scene.other.fingerprint)
    assert scene.adapter.calls == FULL + ['identity', 'export', 'rollback', 'identity', 'export']
    preserved = gr.load_verified(root, outcome.journal['displaced_state']['sha256'])
    assert scene.adapter.rolled == [preserved.parts] == [tuple(scene.current_parts)]
    assert dict((n, s) for n, s in scene.adapter.disk if n == 'rollback') == {'rollback': 'ROLLBACK_REQUIRED'}
    assert scene.adapter.parts == scene.current_parts
    bounded(scene.adapter)


def test_apply_failure_without_change_needs_no_native_rollback(gr, scene, labels):
    def boom(f, n, parts):
        raise OSError('/private/profile')
    scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {'apply': boom})
    outcome = scene.run()
    assert outcome.status == 'ROLLED_BACK'
    assert outcome.journal['history'][4]['failure_code'] == 'APPLY_FAILED'
    assert scene.adapter.calls == FULL[:6] + ['identity', 'export'] and scene.adapter.rolled == []


def test_apply_failure_after_partial_change_rolls_back(gr, scene, labels):
    def partial(f, n, parts):
        f.parts = list(scene.other_parts)
        raise RuntimeError('half applied')
    scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {'apply': partial})
    outcome = scene.run()
    assert outcome.status == 'ROLLED_BACK' and scene.adapter.rolled == [tuple(scene.current_parts)]
    bounded(scene.adapter)


def mismatching(scene, labels, hooks=None):
    class Partial(Fake):
        def apply(self, parts):
            self._enter('apply', parts)
            self.parts = list(scene.other_parts)
    return Partial(scene.adapter.root, labels, scene.current_parts, hooks)


def test_rollback_failure_classifications(gr, root, scene, labels):
    def boom(f, n, parts):
        raise RuntimeError('rollback failed')
    scene.adapter = mismatching(scene, labels, {'rollback': boom})
    outcome = scene.run(journal_id='rb-raises')
    assert (outcome.status, outcome.failure_code) == ('ROLLBACK_FAILED', 'ROLLBACK_APPLY_FAILED')
    bounded(scene.adapter)

    class Ignores(Fake):
        def apply(self, parts):
            self._enter('apply', parts)
            self.parts = list(scene.other_parts)

        def rollback(self, parts):
            self._enter('rollback', parts)
    scene.adapter = Ignores(root, labels, scene.current_parts)
    outcome = scene.run(journal_id='rb-mismatch')
    assert (outcome.status, outcome.failure_code) == ('ROLLBACK_FAILED', 'ROLLBACK_MISMATCH')
    assert outcome.journal['history'][-1]['observed_fingerprint'] == scene.other.fingerprint
    bounded(scene.adapter)

    def lost_identity(f, n):
        if n == 4:
            f.identity_record = target_record(labels, '0' * 64, STORAGE)
    scene.adapter = mismatching(scene, labels, {'identity': lost_identity})
    outcome = scene.run(journal_id='rb-identity')
    assert (outcome.status, outcome.failure_code) == ('ROLLBACK_FAILED', 'ROLLBACK_APPLY_FAILED')
    assert 'rollback' not in scene.adapter.calls


def test_rollback_refuses_corrupted_preserved_state(gr, root, scene, labels):
    def corrupt(f, n, parts):
        digest = hashlib.sha256(scene.current_parts[0]).hexdigest()
        path = root / 'native' / 'sha256' / digest
        path.write_bytes(path.read_bytes()[:-1] + b'!')
    scene.adapter = mismatching(scene, labels, {'apply': corrupt})
    outcome = scene.run()
    assert (outcome.status, outcome.failure_code) == ('ROLLBACK_FAILED', 'ROLLBACK_APPLY_FAILED')
    assert 'rollback' not in scene.adapter.calls


def test_refusals_before_any_journal(gr, root, scene, labels):
    scene.adapter.identity_record = target_record(labels, PROFILE, '0' * 64)
    refuse('TARGET_IDENTITY_MISMATCH', scene.run)
    assert scene.adapter.calls == ['identity']
    scene.adapter = Fake(root, labels, scene.current_parts)
    refuse('AUTHORIZATION_REQUIRED', scene.run, authorization=None)
    refuse('AUTHORIZATION_MISMATCH', scene.run, authorization=dict(scene.authorization, before_fingerprint='0' * 64))
    assert scene.adapter.calls == ['identity', 'export'] * 2

    def boom(f, n):
        raise RuntimeError('/private')
    for name, expected in (('identity', ['identity']), ('export', ['identity', 'export'])):
        scene.adapter = Fake(root, labels, scene.current_parts, {name: boom})
        refuse('ADAPTER_FAILED', scene.run)
        assert scene.adapter.calls == expected
    assert not (root / 'recovery').exists()


def test_chrome_and_uncharacterized_targets_make_zero_adapter_calls(gr, root, scene, labels):
    chrome = {'engine': 'chrome', 'extension_id': 'felphkbfjadmcejnibcmcncimlappdde',
              'extension_version': '1.10.0', 'browser_version': '140.0.1'}
    for record, code in ((target_record(chrome), 'CHROME_UNCHARACTERIZED'),
                         (target_record(dict(labels, browser_version='156.0.2')), 'LABELS_UNCHARACTERIZED')):
        refuse(code, gr.recover, root, JOURNAL, record, scene.requested.manifest_sha256, scene.adapter,
               authorization=scene.authorization)
    assert scene.adapter.calls == [] and not (root / 'recovery').exists()


def test_corrupt_or_missing_requested_part_refused_before_any_restore(gr, root, scene):
    path = root / 'native' / 'sha256' / scene.requested.part_digests[1]
    original = path.read_bytes()
    path.write_bytes(original[:-1] + b'!')
    refuse('NATIVE_PART_DIGEST_MISMATCH', scene.run)
    path.unlink()
    refuse('NATIVE_PART_MISSING', scene.run)
    assert scene.adapter.calls == ['identity', 'identity']
    assert scene.adapter.applied == scene.adapter.rolled == [] and not (root / 'recovery').exists()


def test_journal_write_failure_stops_before_next_adapter_call(gr, root, scene, monkeypatch):
    real = gr.ds.atomic_write

    def failing(state_root, relative, data):
        if relative.endswith('journal.json') and json.loads(data)['status'] == 'APPLYING':
            raise gr.ds.DurableStateError('WRITE_FAILED')
        return real(state_root, relative, data)
    monkeypatch.setattr(gr.ds, 'atomic_write', failing)
    refuse('JOURNAL_WRITE_FAILED', scene.run)
    assert 'apply' not in scene.adapter.calls and disk_journal(root)['status'] == 'PRESERVED'
    monkeypatch.setattr(gr.ds, 'atomic_write', real)
    outcome = gr.resume(root, JOURNAL, scene.target, scene.adapter)
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'INTERRUPTED')


# --- Interruption, replay and idempotence -----------------------------------------------------

def interrupted(scene, labels, name, nth=1, effect=None):
    def hook(f, n, *args):
        if n == nth:
            if effect:
                effect(f)
            raise KeyboardInterrupt
    scene.adapter = Fake(scene.adapter.root, labels, scene.current_parts, {name: hook})
    with pytest.raises(KeyboardInterrupt):
        scene.run()
    return Fake(scene.adapter.root, labels, scene.adapter.parts)


@pytest.mark.parametrize('name,nth,disk', [('stage', 1, 'PREPARED'), ('identity', 2, 'PRESERVED'),
                                           ('export', 2, 'PRESERVED')])
def test_resume_before_apply_is_failed_before_mutation_with_zero_calls(gr, root, scene, labels, name, nth, disk):
    fresh = interrupted(scene, labels, name, nth)
    assert disk_journal(root)['status'] == disk
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert (outcome.status, outcome.failure_code) == ('FAILED_BEFORE_MUTATION', 'INTERRUPTED')
    assert fresh.calls == [] and disk_journal(root) == outcome.journal


def test_resume_applying_after_full_apply_completes(gr, root, scene, labels):
    fresh = interrupted(scene, labels, 'apply', effect=lambda f: setattr(f, 'parts', list(scene.requested_parts)))
    assert disk_journal(root)['status'] == 'APPLYING'
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert outcome.status == 'COMPLETED' and fresh.calls == ['identity', 'identity', 'export']


def test_resume_applying_before_apply_rolls_back_without_native_call(gr, root, scene, labels):
    fresh = interrupted(scene, labels, 'apply')
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert outcome.status == 'ROLLED_BACK'
    assert outcome.journal['history'][4]['failure_code'] == 'INTERRUPTED'
    assert fresh.calls == ['identity', 'identity', 'export', 'identity', 'export'] and fresh.rolled == []


def test_resume_applying_after_partial_apply_uses_preserved_rollback(gr, root, scene, labels):
    fresh = interrupted(scene, labels, 'apply', effect=lambda f: setattr(f, 'parts', list(scene.other_parts)))
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert outcome.status == 'ROLLED_BACK' and fresh.rolled == [tuple(scene.current_parts)]
    bounded(fresh)


def test_resume_rollback_required_never_reinvokes_rollback(gr, root, scene, labels):
    scene.adapter = mismatching(scene, labels, {'rollback': lambda f, n, parts: (_ for _ in ()).throw(KeyboardInterrupt)})
    with pytest.raises(KeyboardInterrupt):
        scene.run()
    assert disk_journal(root)['status'] == 'ROLLBACK_REQUIRED'
    # Rollback never attempted (or attempted without effect): manual operator rollback required.
    fresh = Fake(root, labels, scene.other_parts)
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert (outcome.status, outcome.failure_code) == ('ROLLBACK_FAILED', 'INTERRUPTED')
    assert 'rollback' not in fresh.calls and fresh.calls == ['identity', 'identity', 'export']


def test_resume_rollback_required_observes_completed_rollback(gr, root, scene, labels):
    def restored_then_interrupted(f, n, parts):
        f.parts = list(parts)
        raise KeyboardInterrupt
    scene.adapter = mismatching(scene, labels, {'rollback': restored_then_interrupted})
    with pytest.raises(KeyboardInterrupt):
        scene.run()
    fresh = Fake(root, labels, scene.current_parts)
    outcome = gr.resume(root, JOURNAL, scene.target, fresh)
    assert outcome.status == 'ROLLED_BACK' and 'rollback' not in fresh.calls


def test_resume_terminal_is_unchanged_with_zero_calls(gr, root, scene, labels):
    done = scene.run()
    before = (root / 'recovery' / JOURNAL / 'journal.json').read_bytes()
    fresh = Fake(root, labels, scene.requested_parts)
    again = gr.resume(root, JOURNAL, scene.target, fresh)
    assert (again.status, again.journal_bytes) == (done.status, done.journal_bytes)
    assert fresh.calls == [] and (root / 'recovery' / JOURNAL / 'journal.json').read_bytes() == before


def test_resume_refuses_unverified_or_foreign_journals(gr, root, scene, labels):
    fresh = interrupted(scene, labels, 'apply', effect=lambda f: setattr(f, 'parts', list(scene.requested_parts)))
    path = root / 'recovery' / JOURNAL / 'journal.json'
    original = path.read_bytes()
    # Internally consistent journal whose requested fingerprint is not the stored manifest's.
    forged = json.loads(original.replace(scene.requested.fingerprint.encode(), scene.other.fingerprint.encode()))
    assert forged['requested_fingerprint'] == scene.other.fingerprint
    path.write_bytes(gr.ds.serialize_journal(forged))
    refuse('JOURNAL_UNVERIFIED', gr.resume, root, JOURNAL, scene.target, fresh)
    forged = json.loads(original)
    forged['displaced_state']['sha256'] = scene.requested.manifest_sha256
    path.write_bytes(gr.ds.serialize_journal(forged))
    refuse('JOURNAL_UNVERIFIED', gr.resume, root, JOURNAL, scene.target, fresh)
    path.write_bytes(original + b' ')
    refuse('JOURNAL_UNREADABLE', gr.resume, root, JOURNAL, scene.target, fresh)
    path.write_bytes(original)
    other = gr.bind_target(target_record(labels, PROFILE, '0' * 64))
    refuse('JOURNAL_TARGET_MISMATCH', gr.resume, root, JOURNAL, other, fresh)
    refuse('JOURNAL_MISSING', gr.resume, root, 'recovery-9', scene.target, fresh)
    assert fresh.calls == []
    fresh.identity_record = target_record(labels, PROFILE, '0' * 64)
    refuse('TARGET_IDENTITY_MISMATCH', gr.resume, root, JOURNAL, scene.target, fresh)
    assert fresh.calls == ['identity'] and json.loads(path.read_bytes())['status'] == 'APPLYING'


# --- Capture preparation ------------------------------------------------------------------------

def test_capture_revision_chain_and_round_trip(gr, root, scene, native, labels):
    first = scene.requested
    assert (first.revision, first.manifest['predecessor_sha256']) == (1, None)
    second = gr.capture_export(root, scene.other, predecessor=first)
    assert (second.revision, second.manifest['predecessor_sha256']) == (2, first.manifest_sha256)
    third = gr.capture_export(root, scene.current, predecessor=second)
    assert (third.revision, third.manifest['predecessor_sha256']) == (3, second.manifest_sha256)
    assert gr.load_verified(root, third.manifest_sha256).fingerprint == scene.current.fingerprint
    repeat = gr.capture_export(root, scene.current, predecessor=second)
    assert repeat.manifest_sha256 == third.manifest_sha256
    refuse('PREDECESSOR_INVALID', gr.capture_export, root, scene.current, predecessor=scene.other)
    refuse('PREDECESSOR_INVALID', gr.capture_export, root, scene.current, predecessor=first.manifest_sha256)
    foreign = store(gr, root, dict(labels, browser_version='155.0.1'), state(native, 5))
    refuse('PREDECESSOR_INVALID', gr.capture_export, root, scene.current, predecessor=foreign)
    refuse('UNVERIFIED_INPUT', gr.capture_export, root, first)
    refuse('UNVERIFIED_INPUT', gr.capture_export, root, export_of(labels, scene.current_parts))


def test_capture_preserves_native_only_states_without_inventing_semantics(gr, root, native, labels):
    chrome = {'engine': 'chrome', 'extension_id': 'felphkbfjadmcejnibcmcncimlappdde',
              'extension_version': '1.10.0', 'browser_version': None}
    for record_labels, parts, status in ((chrome, [b'\x00opaque leveldb bytes'], 'NATIVE_ONLY_UNCHARACTERIZED'),
                                         (dict(labels, browser_version='155.0.1'), state(native), 'NATIVE_ONLY_UNCHARACTERIZED'),
                                         (labels, [b'{"chunks": 1}', b'{}'], 'NATIVE_ONLY_UNPROJECTABLE')):
        captured = store(gr, root, record_labels, parts)
        manifest = captured.manifest
        assert (captured.projection_status, manifest['projection'], manifest['occurrences']) == (status, None, [])
        assert captured.parts == tuple(parts)
    projected = store(gr, root, labels, state(native))
    assert {o['content_ref']['kind'] for o in projected.manifest['occurrences']} == {'native_only'}


def test_capture_never_overwrites_and_verifies_content_refs(gr, root, scene, tmp_path):
    path = root / 'native' / 'sha256' / hashlib.sha256(scene.other_parts[0]).hexdigest()
    path.write_bytes(b'conflict')
    refuse('NATIVE_PART_DIGEST_MISMATCH', gr.capture_export, root, scene.other)
    assert path.read_bytes() == b'conflict'
    path.unlink()
    content = scene.other.manifest['occurrences'][0]['content_sha256']
    refs = {0: {'kind': 'private', 'sha256': content}}
    refuse('ROOT_REQUIRED', gr.capture_export, root, scene.other, content_refs=refs)
    private = tmp_path / 'private'
    refuse('ROOT_INVALID', gr.capture_export, root, scene.other, content_refs=refs, private_root=private)
    private.mkdir()
    refuse('CONTENT_MISSING', gr.capture_export, root, scene.other, content_refs=refs, private_root=private)
    assert not path.exists()  # nothing was stored for a refused capture


def test_capture_refuses_symlinked_destination(gr, root, scene, tmp_path):
    (tmp_path / 'outside').mkdir()
    (root / 'native' / 'sha256').rename(tmp_path / 'moved')
    (root / 'native' / 'sha256').symlink_to(tmp_path / 'outside')
    refuse('NATIVE_PART_SYMLINK', gr.capture_export, root, scene.other)
    assert list((tmp_path / 'outside').iterdir()) == []


# --- Boundaries ----------------------------------------------------------------------------------

def test_product_boundaries_unchanged(repo_root):
    assert hashlib.sha256((repo_root / 'bin/clear-new-tab-sync').read_bytes()).hexdigest() == SYNC_SHA256
    assert len([p for p in (repo_root / 'bin').iterdir()]) == 10
    manifest = json.loads((repo_root / 'tests/fixtures/command-source-manifest.json').read_text())
    assert manifest[LIBRARY]['adaptation'] == 'destination-origin' and manifest[LIBRARY]['source_sha256'] is None
    assert hashlib.sha256((repo_root / LIBRARY).read_bytes()).hexdigest() == manifest[LIBRARY]['destination_sha256']
    roster = json.loads((repo_root / 'tests/source-only-roster.json').read_text())
    assert {LIBRARY, 'tests/clear-new-tab-guarded-recovery.test.py',
            'docs/architecture/clear-new-tab-durable-authority.md'} <= set(roster)
    assert 'tests/clear-new-tab-guarded-recovery.test.py' in (repo_root / 'tests/command-checks.nix').read_text()
    for name in ('flake.nix', 'packages/browser-ux-commands/default.nix'):
        assert 'guarded_recovery' not in (repo_root / name).read_text()
