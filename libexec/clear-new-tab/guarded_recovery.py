"""Clear New Tab guarded recovery and capture (BUX5B1 RECOVERY-PREP1). Library only; not a command.

Source-only machinery on top of the accepted BUX5B0C foundation (durable_state.py, loaded
from this file's directory). It never launches a browser, reads a profile, resolves or
creates the operator state root, or imports/exports native data itself: every browser-side
effect goes through a caller-injected adapter, and every file lives beneath a caller-supplied
state root that must already exist.

- locate_native_parts: confined, digest/size/order-verified native backup parts.
- VerifiedManifest: the only accepted carrier of a part-verified fingerprint. It is minted
  only by load_verified (state root) or verify_export (adapter export). This is type and
  evidence discipline, not authentication: nothing here is secret or unforgeable.
- plan_recovery: pure authorization decision (NOOP / operator / reset evidence / REFUSE).
- recover / resume: guarded orchestration through the foundation journal state machine.
- capture_export: store a verified export plus its manifest beneath a caller root.

Every refusal is RecoveryError(code) whose text is the fixed code alone. Checks are explicit
raises and behave identically under python -O.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import stat


def _load_foundation():
    # A private module object (never registered in sys.modules): no global aliasing and no
    # path search. The foundation is always the sibling file shipped beside this library.
    spec = importlib.util.spec_from_file_location('browser_ux_cnt_durable_state',
                                                  Path(__file__).with_name('durable_state.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ds = _load_foundation()

NEW_REFUSAL_CODES = (
    'RECOVERY_INVALID', 'UNVERIFIED_INPUT', 'TARGET_INVALID', 'TARGET_IDENTITY_MISMATCH',
    'CHROME_UNCHARACTERIZED', 'LABELS_UNCHARACTERIZED', 'LABELS_MISMATCH', 'REQUESTED_NOT_PROJECTED',
    'NATIVE_PART_ORDER_INVALID', 'NATIVE_PART_MISSING', 'NATIVE_PART_SYMLINK', 'NATIVE_PART_NOT_REGULAR',
    'NATIVE_PART_SIZE_MISMATCH', 'NATIVE_PART_DIGEST_MISMATCH', 'NATIVE_PART_TOO_LARGE',
    'NATIVE_PART_UNREADABLE', 'NATIVE_SET_TOO_LARGE',
    'STORED_MANIFEST_MISSING', 'STORED_MANIFEST_SYMLINK', 'STORED_MANIFEST_NOT_REGULAR',
    'STORED_MANIFEST_TOO_LARGE', 'STORED_MANIFEST_UNREADABLE', 'STORED_MANIFEST_DIGEST_MISMATCH',
    'JOURNAL_ID_INVALID', 'JOURNAL_EXISTS', 'JOURNAL_MISSING', 'JOURNAL_UNREADABLE',
    'JOURNAL_WRITE_FAILED', 'JOURNAL_TARGET_MISMATCH', 'JOURNAL_UNVERIFIED',
    'EXPORT_INVALID', 'EXPORT_INCOMPLETE', 'ADAPTER_FAILED',
    'PREDECESSOR_INVALID', 'POLICY_INVALID',
    'AUTHORIZATION_REQUIRED', 'AUTHORIZATION_INVALID', 'AUTHORIZATION_MISMATCH',
)
REFUSAL_CODES = ds.REFUSAL_CODES + NEW_REFUSAL_CODES


class RecoveryError(ValueError):
    """Bounded refusal. str(error) is exactly one REFUSAL_CODES member."""

    def __init__(self, code):
        if code not in REFUSAL_CODES:
            code = 'RECOVERY_INVALID'
        super().__init__(code)
        self.code = code


def _require(condition, code):
    if not condition:
        raise RecoveryError(code)


@contextlib.contextmanager
def _bounded(code=None):
    """Re-raise a foundation refusal as RecoveryError (its own code, or `code`), unchained."""
    try:
        yield
    except ds.DurableStateError as error:
        raise RecoveryError(code or error.code) from None


class _Immutable:
    __slots__ = ()

    def __init__(self, *_args, **_kwargs):
        raise RecoveryError('UNVERIFIED_INPUT')

    def __setattr__(self, _name, _value):
        raise RecoveryError('RECOVERY_INVALID')

    def __delattr__(self, _name):
        raise RecoveryError('RECOVERY_INVALID')

    def __copy__(self):
        return self

    def __deepcopy__(self, _memo):
        return self

    @classmethod
    def _mint(cls, **fields):
        instance = object.__new__(cls)
        for name in cls.__slots__:
            object.__setattr__(instance, name, fields[name])
        return instance


def _labels_key(labels):
    with _bounded('LABELS_INVALID'):
        return ds.canonical_bytes(ds.validate_labels(labels))


# --- Confined reads --------------------------------------------------------------------------

MAX_NATIVE_PART_BYTES = 512 * 1024 * 1024
MAX_PART_SET_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_BYTES = 1024 * 1024
NATIVE_PREFIX = ('native', 'sha256')
RECOVERY_PREFIX = 'recovery'
JOURNAL_NAME = 'journal.json'

_PART_CODES = {'MISSING': 'NATIVE_PART_MISSING', 'SYMLINK': 'NATIVE_PART_SYMLINK',
               'NOT_REGULAR': 'NATIVE_PART_NOT_REGULAR', 'TOO_LARGE': 'NATIVE_PART_TOO_LARGE',
               'SIZE': 'NATIVE_PART_SIZE_MISMATCH', 'UNREADABLE': 'NATIVE_PART_UNREADABLE'}
_MANIFEST_CODES = {'MISSING': 'STORED_MANIFEST_MISSING', 'SYMLINK': 'STORED_MANIFEST_SYMLINK',
                   'NOT_REGULAR': 'STORED_MANIFEST_NOT_REGULAR', 'TOO_LARGE': 'STORED_MANIFEST_TOO_LARGE',
                   'SIZE': 'STORED_MANIFEST_TOO_LARGE', 'UNREADABLE': 'STORED_MANIFEST_UNREADABLE'}
_JOURNAL_CODES = {'MISSING': 'JOURNAL_MISSING', 'SYMLINK': 'JOURNAL_UNREADABLE',
                  'NOT_REGULAR': 'JOURNAL_UNREADABLE', 'TOO_LARGE': 'JOURNAL_UNREADABLE',
                  'SIZE': 'JOURNAL_UNREADABLE', 'UNREADABLE': 'JOURNAL_UNREADABLE'}


def _read_confined(state_root, relative, codes, limit, exact=None):
    """Bytes of a regular file beneath state_root; no symlink is followed at any level.

    lstat must see a regular file (a FIFO or device is refused before open); O_NONBLOCK keeps
    an object swapped in afterwards from blocking the open, and fstat must then match the
    lstat identity. At most limit + 1 bytes are read, in chunks. Returns the bytes read,
    which are the bytes any caller hashes and uses: there is no second read.
    """
    with _bounded():
        parts = ds.validate_relative_ref(relative)
        directory = ds._open_root(state_root)
    try:
        for part in parts[:-1]:
            try:
                child = ds._descend(directory, part, False)
            except ds.DurableStateError as error:
                raise RecoveryError(codes['SYMLINK' if error.code == 'REF_SYMLINK' else 'MISSING']) from None
            os.close(directory)
            directory = child
        try:
            info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            raise RecoveryError(codes['MISSING']) from None
        except OSError:
            raise RecoveryError(codes['UNREADABLE']) from None
        _require(not stat.S_ISLNK(info.st_mode), codes['SYMLINK'])
        _require(stat.S_ISREG(info.st_mode), codes['NOT_REGULAR'])
        _require(info.st_size <= limit, codes['TOO_LARGE'])
        _require(exact is None or info.st_size == exact, codes['SIZE'])
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            raise RecoveryError(codes['MISSING']) from None
        except OSError as error:
            # O_NOFOLLOW reports a symlink swapped in after the lstat as ELOOP; any other
            # open failure (e.g. EACCES) is an unreadable entry, not a symlink.
            raise RecoveryError(codes['SYMLINK' if error.errno == errno.ELOOP else 'UNREADABLE']) from None
        try:
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                _require(stat.S_ISREG(opened.st_mode)
                         and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), codes['NOT_REGULAR'])
                chunks, total = [], 0
                while total <= limit:
                    chunk = stream.read(min(ds.READ_CHUNK, limit + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except OSError:
            raise RecoveryError(codes['UNREADABLE']) from None
        _require(total <= limit, codes['TOO_LARGE'])
        raw = b''.join(chunks)
        _require(exact is None or len(raw) == exact, codes['SIZE'])
        return raw
    finally:
        os.close(directory)


def native_part_relpath(digest):
    with _bounded():
        return '/'.join((*NATIVE_PREFIX, ds.require_digest(digest)))


def locate_native_parts(state_root, records):
    """Prerequisite A: the verified, ordered native part set for manifest native_artifacts.

    Refs are derived (native/sha256/<hex>), never taken from caller path text. Index order,
    size, digest and the per-part and per-set caps are all exact. A verified part set is the
    only artifact input eligible for staging, application or rollback.
    """
    with _bounded('NATIVE_PART_ORDER_INVALID'):
        ds.validate_native_artifacts(records)
    _require(all(type(r['bytes']) is int and r['bytes'] <= MAX_NATIVE_PART_BYTES for r in records),
             'NATIVE_PART_TOO_LARGE')
    _require(sum(r['bytes'] for r in records) <= MAX_PART_SET_BYTES, 'NATIVE_SET_TOO_LARGE')
    parts = []
    for record in records:
        raw = _read_confined(state_root, native_part_relpath(record['sha256']), _PART_CODES,
                             MAX_NATIVE_PART_BYTES, exact=record['bytes'])
        _require(hashlib.sha256(raw).hexdigest() == record['sha256'], 'NATIVE_PART_DIGEST_MISMATCH')
        parts.append(raw)
    return tuple(parts)


# --- Prerequisite B: part-verified manifests --------------------------------------------------

STATE_ROOT, EXPORT = 'STATE_ROOT', 'EXPORT'


class VerifiedManifest(_Immutable):
    """A manifest proven against its exact native parts. Only load_verified/verify_export mint it."""
    __slots__ = ('origin', '_labels', 'manifest_sha256', 'manifest_bytes', 'fingerprint',
                 'projection_status', 'revision', 'part_digests', 'parts')

    @property
    def labels(self):
        return ds.parse_canonical(self._labels)

    @property
    def manifest(self):
        return ds.parse_canonical(self.manifest_bytes)


def _mint_manifest(origin, manifest, parts):
    with _bounded():
        raw = ds.serialize_manifest(manifest)
        fingerprint = ds.semantic_fingerprint(manifest)
    return VerifiedManifest._mint(
        origin=origin, _labels=_labels_key(manifest['labels']), manifest_sha256=ds.sha256_hex(raw),
        manifest_bytes=raw, fingerprint=fingerprint, projection_status=manifest['projection_status'],
        revision=manifest['revision'], part_digests=tuple(r['sha256'] for r in manifest['native_artifacts']),
        parts=tuple(bytes(p) for p in parts))


def stored_manifest_relpath(digest):
    with _bounded():
        return ds.private_content_relpath(digest)


def load_verified(state_root, manifest_sha256):
    """STATE_ROOT record: stored canonical manifest bytes plus every native part, all verified."""
    with _bounded():
        ds.require_digest(manifest_sha256)
    raw = _read_confined(state_root, stored_manifest_relpath(manifest_sha256), _MANIFEST_CODES,
                         MAX_MANIFEST_BYTES)
    _require(ds.sha256_hex(raw) == manifest_sha256, 'STORED_MANIFEST_DIGEST_MISMATCH')
    with _bounded():
        manifest = ds.parse_manifest(raw)
    parts = locate_native_parts(state_root, manifest['native_artifacts'])
    with _bounded():
        ds.validate_manifest(manifest, native_parts=list(parts))
    return _mint_manifest(STATE_ROOT, manifest, parts)


EXPORT_KEYS = ('labels', 'part_count', 'parts')


def verify_export(export, target):
    """EXPORT record from an adapter export {labels, part_count, parts} for an exact target.

    part_count is the export's declared closure: the part list must be complete. The
    manifest is derived from the exact bytes, so its fingerprint is part-verified.
    """
    _require(type(target) is TargetIdentity, 'UNVERIFIED_INPUT')
    _require(type(export) is dict and set(export) == set(EXPORT_KEYS), 'EXPORT_INVALID')
    parts, count = export['parts'], export['part_count']
    _require(type(parts) in (list, tuple) and all(type(p) is bytes for p in parts), 'EXPORT_INVALID')
    _require(type(count) is int and 1 <= count <= ds.MAX_ARTIFACTS and len(parts) == count, 'EXPORT_INCOMPLETE')
    _require(all(len(p) <= MAX_NATIVE_PART_BYTES for p in parts), 'NATIVE_PART_TOO_LARGE')
    _require(sum(len(p) for p in parts) <= MAX_PART_SET_BYTES, 'NATIVE_SET_TOO_LARGE')
    _require(_labels_key(export['labels']) == target._labels, 'LABELS_MISMATCH')
    with _bounded():
        manifest = ds.build_manifest(list(parts), target.labels)
    return _mint_manifest(EXPORT, manifest, parts)


class TargetIdentity(_Immutable):
    """Exact target: engine/extension/browser labels plus opaque profile and storage tokens."""
    __slots__ = ('_labels', 'profile_token', 'storage_token')

    @property
    def labels(self):
        return ds.parse_canonical(self._labels)

    def record(self):
        return {'labels': self.labels, 'profile_token': self.profile_token,
                'storage_token': self.storage_token}


def bind_target(record):
    """TargetIdentity from {labels, profile_token, storage_token}. Tokens are digests, never paths."""
    _require(type(record) is dict and set(record) == {'labels', 'profile_token', 'storage_token'},
             'TARGET_INVALID')
    labels = _labels_key(record['labels'])
    with _bounded('TARGET_INVALID'):
        ds.require_digest(record['profile_token'])
        ds.require_digest(record['storage_token'])
    return TargetIdentity._mint(_labels=labels, profile_token=record['profile_token'],
                                storage_token=record['storage_token'])


def _target_key(target):
    return (target._labels, target.profile_token, target.storage_token)


def _same_target(target, observed):
    """Whether an adapter-reported identity record is exactly the bound target."""
    try:
        return _target_key(bind_target(observed)) == _target_key(target)
    except RecoveryError:
        return False


# --- Pure authorization planner --------------------------------------------------------------

NOOP, MUTATE_OPERATOR, MUTATE_RESET_EVIDENCE, REFUSE = 'NOOP', 'MUTATE_OPERATOR', 'MUTATE_RESET_EVIDENCE', 'REFUSE'
DECISIONS = (NOOP, MUTATE_OPERATOR, MUTATE_RESET_EVIDENCE, REFUSE)
AUTHORIZATION_SCHEMA = 'browser-ux-cnt-operator-authorization-v1'
RESET_EVIDENCE_SCHEMA = 'browser-ux-cnt-reset-evidence-v1'
AUTHORIZATION_KEYS = ('schema', 'labels', 'profile_token', 'storage_token', 'requested_manifest_sha256',
                      'requested_fingerprint', 'before_fingerprint')
RESET_EVIDENCE_KEYS = ('schema', 'kind', 'labels', 'profile_token', 'storage_token',
                       'observed_fingerprint', 'observation_sha256')
REASONS = ('RESET_EVIDENCE_ABSENT', 'RESET_EVIDENCE_INVALID', 'RESET_KIND_FORBIDDEN',
           'RESET_KIND_UNACCEPTED', 'RESET_EVIDENCE_UNBOUND', 'RESET_STATE_UNCHARACTERIZED')
# Never reset evidence, whatever any policy says.
FORBIDDEN_RESET_KINDS = ('ELAPSED_TIME', 'BROWSER_UPDATE', 'EXTENSION_UPDATE', 'PROFILE_AGE',
                         'OBSERVER_ABSENT', 'EVIDENCE_MISSING', 'EVIDENCE_UNREADABLE', 'EMPTY_DIRECTORY',
                         'PRIOR_ACTIVATION')
QUALIFICATION_SYNTHETIC_RESET = 'QUALIFICATION_SYNTHETIC_RESET'


class ResetPolicy(_Immutable):
    """Accepted reset kinds: (kind, exact labels, characterized reset-state fingerprint) entries."""
    __slots__ = ('entries',)


# No reset-evidence kind is characterized: automatic mutation is unreachable with this policy.
ACCEPTED_RESET_POLICY = ResetPolicy._mint(entries=())


def qualification_reset_policy(labels, reset_fingerprint):
    """Explicitly synthetic policy for tests and disposable qualification only.

    Its single kind is QUALIFICATION_SYNTHETIC_RESET; it is not accepted reset evidence. The
    journal basis is still POSITIVE_VERSIONED_RESET_EVIDENCE; the kind is recoverable only from
    the evidence record that recover() stores at content/sha256/<journal evidence_sha256>.
    """
    with _bounded('POLICY_INVALID'):
        ds.require_digest(reset_fingerprint)
    return ResetPolicy._mint(entries=((QUALIFICATION_SYNTHETIC_RESET, _labels_key(labels), reset_fingerprint),))


class Plan(_Immutable):
    __slots__ = ('decision', 'refusal', 'reasons', 'basis', 'before_state', 'evidence_sha256')


def _plan(decision, refusal=None, reasons=(), basis=None, before_state=None, evidence_sha256=None):
    return Plan._mint(decision=decision, refusal=refusal, reasons=tuple(reasons), basis=basis,
                      before_state=before_state, evidence_sha256=evidence_sha256)


def _record_digest(record):
    try:
        return ds.sha256_hex(ds.canonical_bytes(record))
    except (ds.DurableStateError, RecursionError):
        return None


def _well_formed(record, schema, keys, digests):
    if type(record) is not dict or set(record) != set(keys) or record.get('schema') != schema:
        return False
    try:
        _labels_key(record['labels'])
        for key in digests:
            ds.require_digest(record[key])
    except (RecoveryError, ds.DurableStateError):
        return False
    return _record_digest(record) is not None


def _binds_target(record, target):
    return (_labels_key(record['labels']) == target._labels and record['profile_token'] == target.profile_token
            and record['storage_token'] == target.storage_token)


def _authorization_plan(authorization, target, current, requested):
    digests = ('profile_token', 'storage_token', 'requested_manifest_sha256', 'requested_fingerprint',
               'before_fingerprint')
    if not _well_formed(authorization, AUTHORIZATION_SCHEMA, AUTHORIZATION_KEYS, digests):
        return _plan(REFUSE, 'AUTHORIZATION_INVALID')
    if not (_binds_target(authorization, target)
            and authorization['requested_manifest_sha256'] == requested.manifest_sha256
            and authorization['requested_fingerprint'] == requested.fingerprint
            and authorization['before_fingerprint'] == current.fingerprint):
        return _plan(REFUSE, 'AUTHORIZATION_MISMATCH')
    return _plan(MUTATE_OPERATOR, basis='OPERATOR_EXPLICIT', before_state='PRESENT',
                 evidence_sha256=_record_digest(authorization))


def _reset_reason(evidence, target, current, policy):
    if evidence is None:
        return 'RESET_EVIDENCE_ABSENT'
    digests = ('profile_token', 'storage_token', 'observed_fingerprint', 'observation_sha256')
    if not _well_formed(evidence, RESET_EVIDENCE_SCHEMA, RESET_EVIDENCE_KEYS, digests) \
            or type(evidence['kind']) is not str:
        return 'RESET_EVIDENCE_INVALID'
    if evidence['kind'] in FORBIDDEN_RESET_KINDS:
        return 'RESET_KIND_FORBIDDEN'
    accepted = [fp for kind, labels, fp in policy.entries if kind == evidence['kind'] and labels == target._labels]
    if not accepted:
        return 'RESET_KIND_UNACCEPTED'
    if not _binds_target(evidence, target) or evidence['observed_fingerprint'] != current.fingerprint:
        return 'RESET_EVIDENCE_UNBOUND'
    if current.fingerprint not in accepted:
        return 'RESET_STATE_UNCHARACTERIZED'
    return None


def label_gate(target):
    """REFUSE plan for a target this phase may not touch, else None. Pure."""
    _require(type(target) is TargetIdentity, 'UNVERIFIED_INPUT')
    labels = target.labels
    if labels['engine'] == 'chrome':
        return _plan(REFUSE, 'CHROME_UNCHARACTERIZED')
    if labels != ds.PROJECTED_LABELS:
        return _plan(REFUSE, 'LABELS_UNCHARACTERIZED')
    return None


def plan_recovery(target, current, requested, *, authorization=None, reset_evidence=None,
                  reset_policy=ACCEPTED_RESET_POLICY):
    """Pure decision. Malformed/unverified inputs raise; policy outcomes return REFUSE plans.

    Order: label gate, no conversion, projected requested state, NOOP (authorization and
    evidence are ignored), explicit operator authorization, positive reset evidence.
    """
    _require(type(current) is VerifiedManifest and type(requested) is VerifiedManifest
             and requested.origin == STATE_ROOT and type(reset_policy) is ResetPolicy, 'UNVERIFIED_INPUT')
    gate = label_gate(target)
    if gate is not None:
        return gate
    if not (current._labels == requested._labels == target._labels):
        return _plan(REFUSE, 'LABELS_MISMATCH')
    if requested.projection_status != ds.PROJECTED:
        return _plan(REFUSE, 'REQUESTED_NOT_PROJECTED')
    if current.fingerprint == requested.fingerprint:
        return _plan(NOOP)
    if authorization is not None:
        return _authorization_plan(authorization, target, current, requested)
    reason = _reset_reason(reset_evidence, target, current, reset_policy)
    if reason is not None:
        return _plan(REFUSE, 'AUTHORIZATION_REQUIRED', (reason,))
    return _plan(MUTATE_RESET_EVIDENCE, basis='POSITIVE_VERSIONED_RESET_EVIDENCE',
                 before_state='RESET_EVIDENCED', evidence_sha256=_record_digest(reset_evidence))


# --- Capture preparation ---------------------------------------------------------------------

def _store_verified(state_root, relative, raw, codes, limit, mismatch):
    """Write raw at a content-addressed path, or verify and keep an existing identical file."""
    try:
        existing = _read_confined(state_root, relative, codes, limit)
    except RecoveryError as error:
        if error.code != codes['MISSING']:
            raise
        with _bounded('WRITE_FAILED'):
            ds.atomic_write(state_root, relative, raw)
        return
    _require(existing == raw, mismatch)


def capture_export(state_root, export, *, predecessor=None, content_refs=None,
                   shared_images_root=None, private_root=None):
    """Store a verified export (parts + canonical manifest) beneath a caller root; no browser call.

    Parts go to native/sha256/<hex>, the manifest to content/sha256/<manifest sha>. An
    existing different file is refused and never overwritten. Projection, occurrences and
    content identity come only from the foundation; native-only states are kept native-only.
    Returns the STATE_ROOT record re-read from disk.
    """
    _require(type(export) is VerifiedManifest and export.origin == EXPORT, 'UNVERIFIED_INPUT')
    revision, previous = 1, None
    if predecessor is not None:
        _require(type(predecessor) is VerifiedManifest and predecessor.origin == STATE_ROOT
                 and predecessor._labels == export._labels, 'PREDECESSOR_INVALID')
        revision, previous = predecessor.revision + 1, predecessor.manifest_sha256
    with _bounded():
        manifest = ds.build_manifest(list(export.parts), export.labels, revision=revision,
                                     predecessor_sha256=previous, content_refs=content_refs)
        ds.verify_manifest_content(manifest, shared_images_root=shared_images_root, private_root=private_root)
        raw = ds.serialize_manifest(manifest)
    for record, part in zip(manifest['native_artifacts'], export.parts):
        _store_verified(state_root, native_part_relpath(record['sha256']), part, _PART_CODES,
                        MAX_NATIVE_PART_BYTES, 'NATIVE_PART_DIGEST_MISMATCH')
    digest = ds.sha256_hex(raw)
    _store_verified(state_root, stored_manifest_relpath(digest), raw, _MANIFEST_CODES, MAX_MANIFEST_BYTES,
                    'STORED_MANIFEST_DIGEST_MISMATCH')
    return load_verified(state_root, digest)


# --- Guarded orchestration -------------------------------------------------------------------
# Adapter protocol (the only calls made): identity() -> target record; export_current() ->
# export dict; stage(parts) -> {'identity': record, 'export': export} for a disposable target;
# apply(parts); rollback(parts). An adapter Exception becomes a bounded code; a BaseException
# (e.g. KeyboardInterrupt) propagates and leaves the persisted journal for resume().

class Outcome(_Immutable):
    """status: 'NOOP' (no journal) or the terminal journal status reached."""
    __slots__ = ('status', 'failure_code', 'journal_id', 'journal_bytes')

    @property
    def journal(self):
        return None if self.journal_bytes is None else ds.parse_journal(self.journal_bytes)


def journal_relpath(journal_id):
    _require(type(journal_id) is str and ds.JOURNAL_ID.fullmatch(journal_id) is not None, 'JOURNAL_ID_INVALID')
    return '/'.join((RECOVERY_PREFIX, journal_id, JOURNAL_NAME))


def _journal_absent(state_root, journal_id):
    try:
        _read_confined(state_root, journal_relpath(journal_id), _JOURNAL_CODES, MAX_JOURNAL_BYTES)
    except RecoveryError as error:
        if error.code == 'JOURNAL_MISSING':
            return True
        raise
    return False


def _claim_journal(state_root, journal_id):
    """mkdir of recovery/<journal_id> is the atomic per-id claim; EEXIST means already used."""
    journal_relpath(journal_id)
    with _bounded():
        directory = ds._open_root(state_root)
    try:
        try:
            child = ds._descend(directory, RECOVERY_PREFIX, True)
        except ds.DurableStateError:
            raise RecoveryError('JOURNAL_WRITE_FAILED') from None
        try:
            os.mkdir(journal_id, 0o700, dir_fd=child)
        except FileExistsError:
            raise RecoveryError('JOURNAL_EXISTS') from None
        except OSError:
            raise RecoveryError('JOURNAL_WRITE_FAILED') from None
        finally:
            os.close(child)
    finally:
        os.close(directory)


def _persist(state_root, journal):
    with _bounded('JOURNAL_WRITE_FAILED'):
        ds.atomic_write(state_root, journal_relpath(journal['journal_id']), ds.serialize_journal(journal))
    return journal


def _outcome(journal):
    entry = journal['history'][-1]
    return Outcome._mint(status=journal['status'], failure_code=entry['failure_code'],
                         journal_id=journal['journal_id'], journal_bytes=ds.serialize_journal(journal))


class _Run:
    """One orchestration: write-ahead journal persistence around each adapter call."""

    def __init__(self, state_root, target, adapter, journal):
        self.state_root, self.target, self.adapter, self.journal = state_root, target, adapter, journal

    def step(self, status, observed=None, failure=None, displaced=None):
        with _bounded():
            updated = ds.transition(self.journal, status, observed_fingerprint=observed, failure_code=failure,
                                    displaced_state=displaced)
        self.journal = _persist(self.state_root, updated)
        return self.journal

    def observe(self):
        """(identity matches, fingerprint or None) of the live target; never raises for adapter faults."""
        try:
            identity = self.adapter.identity()
        except Exception:
            return False, None
        if not _same_target(self.target, identity):
            return False, None
        try:
            export = self.adapter.export_current()
        except Exception:
            return True, None
        try:
            return True, verify_export(export, self.target).fingerprint
        except RecoveryError:
            return True, None

    def rollback(self):
        """ROLLBACK_REQUIRED -> ROLLED_BACK / ROLLBACK_FAILED using only the verified preserved parts."""
        before = self.journal['before_fingerprint']
        try:
            preserved = load_verified(self.state_root, self.journal['displaced_state']['sha256'])
        except RecoveryError:
            preserved = None
        if preserved is None or preserved.fingerprint != before or preserved._labels != self.target._labels:
            return self.step(ds.ROLLBACK_FAILED, failure='ROLLBACK_APPLY_FAILED')
        matches, observed = self.observe()
        if not matches:
            return self.step(ds.ROLLBACK_FAILED, failure='ROLLBACK_APPLY_FAILED')
        if observed == before:  # nothing was changed: no native rollback is needed
            return self.step(ds.ROLLED_BACK, observed=before)
        try:
            self.adapter.rollback(preserved.parts)
        except Exception:
            return self.step(ds.ROLLBACK_FAILED, failure='ROLLBACK_APPLY_FAILED')
        matches, observed = self.observe()
        if matches and observed == before:
            return self.step(ds.ROLLED_BACK, observed=before)
        return self.step(ds.ROLLBACK_FAILED, observed=observed, failure='ROLLBACK_MISMATCH')


def _adapter_identity(adapter, target):
    try:
        identity = adapter.identity()
    except Exception:
        raise RecoveryError('ADAPTER_FAILED') from None
    _require(_same_target(target, identity), 'TARGET_IDENTITY_MISMATCH')


def recover(state_root, journal_id, target, requested_manifest_sha256, adapter, *, authorization=None,
            reset_evidence=None, qualification_policy=None):
    """Guarded recovery of one exact target to a stored, part-verified requested manifest.

    Refusals before a journal exists raise RecoveryError. A NOOP returns Outcome('NOOP')
    with no journal and no stage/preserve/apply. Every other path returns the terminal
    journal Outcome. Each journal_id is single-use: a repeat needs a fresh id (or resume()).
    qualification_policy, if given, must be a ResetPolicy; only ACCEPTED_RESET_POLICY (empty)
    and qualification_reset_policy() (explicitly synthetic) can produce one.
    """
    target = target if type(target) is TargetIdentity else bind_target(target)
    gate = label_gate(target)
    if gate is not None:
        raise RecoveryError(gate.refusal)
    policy = ACCEPTED_RESET_POLICY if qualification_policy is None else qualification_policy
    _require(type(policy) is ResetPolicy, 'POLICY_INVALID')
    journal_relpath(journal_id)
    _require(_journal_absent(state_root, journal_id), 'JOURNAL_EXISTS')
    # 1. exact target identity
    _adapter_identity(adapter, target)
    # 2. requested manifest and every native part, before anything else touches the target
    requested = load_verified(state_root, requested_manifest_sha256)
    # 3-4. current export -> part-verified current fingerprint
    try:
        export = adapter.export_current()
    except Exception:
        raise RecoveryError('ADAPTER_FAILED') from None
    current = verify_export(export, target)
    # 5. authorization
    plan = plan_recovery(target, current, requested, authorization=authorization,
                         reset_evidence=reset_evidence, reset_policy=policy)
    if plan.decision == REFUSE:
        raise RecoveryError(plan.refusal)
    # 6. NOOP: no journal, no staging, preservation or apply
    if plan.decision == NOOP:
        return Outcome._mint(status=NOOP, failure_code=None, journal_id=None, journal_bytes=None)
    with _bounded():
        journal = ds.new_journal(
            journal_id=journal_id, labels=target.labels, source_manifest_sha256=requested.manifest_sha256,
            source_artifact_sha256=list(requested.part_digests), profile_token=target.profile_token,
            storage_token=target.storage_token, basis=plan.basis, evidence_sha256=plan.evidence_sha256,
            before_state=plan.before_state, before_fingerprint=current.fingerprint,
            requested_fingerprint=requested.fingerprint)
    # Retain the exact authorization/evidence record behind the journal's evidence_sha256
    # (content-addressed, idempotent), so the digest names a stored record and its kind.
    with _bounded():
        record = ds.canonical_bytes(authorization if plan.decision == MUTATE_OPERATOR else reset_evidence)
    _store_verified(state_root, stored_manifest_relpath(plan.evidence_sha256), record, _MANIFEST_CODES,
                    MAX_MANIFEST_BYTES, 'STORED_MANIFEST_DIGEST_MISMATCH')
    _claim_journal(state_root, journal_id)
    run = _Run(state_root, target, adapter, _persist(state_root, journal))
    before = current.fingerprint
    # 7. disposable staging target proves the requested fingerprint
    try:
        staged = adapter.stage(requested.parts)
        _require(type(staged) is dict and set(staged) == {'identity', 'export'}, 'EXPORT_INVALID')
        staging = bind_target(staged['identity'])
        _require(staging._labels == target._labels and staging.profile_token != target.profile_token
                 and staging.storage_token != target.storage_token, 'TARGET_INVALID')
        staged_ok = verify_export(staged['export'], staging).fingerprint == requested.fingerprint
    except Exception:
        staged_ok = False
    if not staged_ok:
        return _outcome(run.step(ds.FAILED_BEFORE_MUTATION, failure='STAGING_MISMATCH'))
    run.step(ds.STAGED, observed=requested.fingerprint)
    # 8. preserve the displaced (current, part-verified) state beneath the caller root, then
    #    re-read it from disk: digest, every part and the before fingerprint must all hold.
    try:
        preserved = capture_export(state_root, current)
        preserved_ok = (preserved.fingerprint == before and preserved._labels == target._labels
                        and ds.verify_private_content(state_root, preserved.manifest_sha256))
    except (RecoveryError, ds.DurableStateError):
        preserved_ok = False
    if not preserved_ok:
        return _outcome(run.step(ds.FAILED_BEFORE_MUTATION, failure='PRESERVATION_FAILED'))
    run.step(ds.PRESERVED, observed=before,
             displaced={'kind': 'private', 'sha256': preserved.manifest_sha256})
    # 9. live re-check immediately before apply
    matches, observed = run.observe()
    if not (matches and observed == before):
        return _outcome(run.step(ds.FAILED_BEFORE_MUTATION, observed=observed, failure='CONCURRENT_CHANGE'))
    run.step(ds.APPLYING, observed=before)
    # 10. the single native apply
    try:
        adapter.apply(requested.parts)
    except Exception:
        run.step(ds.ROLLBACK_REQUIRED, failure='APPLY_FAILED')
        return _outcome(run.rollback())
    # 11-12. verify
    matches, observed = run.observe()
    if matches and observed == requested.fingerprint:
        return _outcome(run.step(ds.COMPLETED, observed=observed))
    # 13-14. rollback from the verified preserved artifacts only
    run.step(ds.ROLLBACK_REQUIRED, observed=observed, failure='VERIFICATION_MISMATCH')
    return _outcome(run.rollback())


def _journal_target_matches(journal, target):
    return (_labels_key(journal['labels']) == target._labels
            and journal['target'] == {'profile_token': target.profile_token, 'storage_token': target.storage_token})


def _reverify_journal(state_root, journal, target):
    """Never trust on-disk fingerprint strings: re-mint the requested and preserved records."""
    try:
        requested = load_verified(state_root, journal['source']['manifest_sha256'])
    except RecoveryError:
        raise RecoveryError('JOURNAL_UNVERIFIED') from None
    _require(requested.fingerprint == journal['requested_fingerprint']
             and list(requested.part_digests) == journal['source']['native_artifact_sha256']
             and requested._labels == target._labels, 'JOURNAL_UNVERIFIED')
    if journal['displaced_state'] is not None:
        try:
            preserved = load_verified(state_root, journal['displaced_state']['sha256'])
        except RecoveryError:
            raise RecoveryError('JOURNAL_UNVERIFIED') from None
        _require(preserved.fingerprint == journal['before_fingerprint']
                 and preserved._labels == target._labels, 'JOURNAL_UNVERIFIED')


def resume(state_root, journal_id, target, adapter):
    """Resolve a persisted journal after interruption. Never re-invokes apply or rollback.

    terminal                      -> returned unchanged, zero adapter calls;
    PREPARED/STAGED/PRESERVED     -> FAILED_BEFORE_MUTATION/INTERRUPTED, zero adapter calls
                                     (write-ahead APPLYING proves apply never ran);
    APPLYING                      -> re-verify, observe: requested -> COMPLETED, else
                                     ROLLBACK_REQUIRED/INTERRUPTED then guarded rollback;
    ROLLBACK_REQUIRED             -> re-verify, observe: before -> ROLLED_BACK, else
                                     ROLLBACK_FAILED/INTERRUPTED (manual operator rollback
                                     from displaced_state is then required).
    """
    target = target if type(target) is TargetIdentity else bind_target(target)
    raw = _read_confined(state_root, journal_relpath(journal_id), _JOURNAL_CODES, MAX_JOURNAL_BYTES)
    with _bounded('JOURNAL_UNREADABLE'):
        journal = ds.parse_journal(raw)
    _require(journal['journal_id'] == journal_id, 'JOURNAL_UNREADABLE')
    _require(_journal_target_matches(journal, target), 'JOURNAL_TARGET_MISMATCH')
    status = journal['status']
    if status in ds.TERMINAL_STATES:
        return _outcome(journal)
    run = _Run(state_root, target, adapter, journal)
    if status in (ds.PREPARED, ds.STAGED, ds.PRESERVED):
        return _outcome(run.step(ds.FAILED_BEFORE_MUTATION, failure='INTERRUPTED'))
    _reverify_journal(state_root, journal, target)
    _adapter_identity(adapter, target)
    matches, observed = run.observe()
    if status == ds.APPLYING:
        if matches and observed == journal['requested_fingerprint']:
            return _outcome(run.step(ds.COMPLETED, observed=observed))
        run.step(ds.ROLLBACK_REQUIRED, observed=observed, failure='INTERRUPTED')
        return _outcome(run.rollback())
    if matches and observed == journal['before_fingerprint']:
        return _outcome(run.step(ds.ROLLED_BACK, observed=observed))
    return _outcome(run.step(ds.ROLLBACK_FAILED, observed=observed, failure='INTERRUPTED'))
