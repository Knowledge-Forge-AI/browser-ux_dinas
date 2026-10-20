"""BUX5B1 RECOVERY-HOSTPREP1: disposable Firefox adapter for guarded-recovery qualification.

Test-owned harness source; not a command and not packaged. UNEXECUTED: nothing here has run
against a browser. It drives the accepted RECOVERY-PREP1 library (libexec/clear-new-tab/
guarded_recovery.py, which loads the accepted durable_state foundation) through the accepted
R4 lifecycle and the R6 native-UI session: one owned Firefox 156.0.1 per fresh attempt root,
the retained CNT 6.12.1 XPI installed temporarily, state changed and observed only through
the extension's own settings UI (cnt_firefox_matrix_session.Session).

The adapter exposes exactly the library protocol: identity(), export_current(), stage(parts),
apply(parts), rollback(parts). Its additions over RECOVERY-PREP1 are caller-side proofs:

- prove_export_closure: an export is complete only by an independent closure proof over one
  attributed export (quiescent empty baseline, one click, positive start and stable end,
  contiguous NATIVE_PART_1..N, no duplicate, parser/partition/projection closure, bounds).
  part_count is len(closed set); it is never taken from anywhere else. EXPORT_INCOMPLETE.
- prove_fresh_profile: before any launch, the attempt root and profile are contained beneath
  the owned claim root, created exclusively, link-free, private and owned, hold only the
  generated user.js and only the retained XPI. STAGING_DISPOSABILITY_UNPROVEN for staging.
- StateRootClaim: per-state-root exclusive execution claim (O_EXCL create plus a held flock),
  re-verified before every recover()/resume(); never deleted; no daemon.
- consume_token: caller-level single-use qualification token wrapping, not replacing, the
  library's state-transition authorization (which stays NOT globally single-use).
- StagingReplay: stage() replays a separate, earlier staging attempt of the same claim root and
  scenario, bound to the requested parts and manifest and consumed once.

Fault injection exists only at the adapter or caller seam, is labelled
QUALIFICATION_FAULT_INJECTION and never replaces a native apply or rollback that a scenario
claims as real. The live/default profile, extension storage, the add-on database and the profile
catalogue are never named, read or written; no CNT serialization is written by hand and no native
artifact is rewritten. This is disposable qualification, not live-data safety evidence.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from cnt_native_evidence import VerificationError, plain_descendant, require
import cnt_firefox_matrix as matrix
import cnt_firefox_matrix_session as session_module
import cnt_firefox_production as firefox

HERE = Path(__file__).resolve().parent
LIBEXEC = HERE.parent / 'libexec/clear-new-tab'

# --- Accepted bindings (provenance constants; exact Git identity is never a runtime gate) ------

RECOVERY_PREP1 = {'tree': '622154aa87074f394f0f0baca3879a58bb4d9a76', 'candidate_paths': 56, 'entries': 201,
                  'inventory_sha256': '24c0faa0008c4cf889ba93fbec47bca4d84e56489bfc37e36ea9ff67a66a1837'}
GUARDED_RECOVERY_SHA256 = '1cf34e0edbbaee0ceb5e9ad80284abbb2f84c813b3b853766954254d950b8053'
DURABLE_STATE_SHA256 = '7a1dd704988088c22d1502b72318183960c8f70e3bde6e9908ec42255c653eea'
# Historical staged-manager value: stale and non-authoritative. Recorded, never used to load.
STALE_DURABLE_STATE_SHA256 = '4a861666aa0ec10b1b1a4946660bc062438b26e9aae7abb298e0433609df8ee3'
# Aliased from their sole owners; never repeated here.
CAPTURE_SHA256 = matrix.XPI_SHA256
EXTENSION_ID = matrix.EXTENSION_ID
EXTENSION_VERSION = matrix.EXTENSION_VERSION
FIREFOX_VERSION = firefox.VERSION
LIBRARY_LIMIT = 4 * 1024 * 1024

RECOVERY_CODES = {
    'Recovery library digest mismatch': 'RECOVERY_LIBRARY_DIGEST_MISMATCH',
    'Recovery export incomplete': 'EXPORT_INCOMPLETE',
    'Recovery target labels unproven': 'TARGET_LABELS_UNPROVEN',
    'Recovery staging disposability unproven': 'STAGING_DISPOSABILITY_UNPROVEN',
    'Recovery profile freshness unproven': 'PROFILE_FRESHNESS_UNPROVEN',
    'Recovery extension set unproven': 'EXTENSION_SET_UNPROVEN',
    'Recovery storage identity unavailable': 'STORAGE_IDENTITY_UNAVAILABLE',
    'Recovery staged input mismatch': 'STAGED_INPUT_MISMATCH',
    'Recovery staging record invalid': 'STAGING_RECORD_INVALID',
    'Recovery staging record reused': 'STAGING_RECORD_REUSED',
    'Recovery native apply not completed': 'NATIVE_APPLY_NOT_COMPLETED',
    'Recovery native rollback not completed': 'NATIVE_ROLLBACK_NOT_COMPLETED',
    'Recovery target setup not completed': 'TARGET_SETUP_NOT_COMPLETED',
    'Recovery pre-existing error ribbon': 'RECOVERY_PREEXISTING_ERROR_RIBBON',
    'Recovery state root invalid': 'STATE_ROOT_INVALID',
    'Recovery state root claim exists': 'ROOT_CLAIM_EXISTS',
    'Recovery state root claim lost': 'ROOT_CLAIM_LOST',
    'Recovery caller token reused': 'CALLER_TOKEN_REUSED',
    'Recovery caller token invalid': 'CALLER_TOKEN_INVALID',
    'Recovery resume without consumed token': 'RESUME_TOKEN_UNCONSUMED',
    'Recovery plan invalid': 'RECOVERY_PLAN_INVALID',
    'Recovery source invalid': 'RECOVERY_SOURCE_INVALID',
    'Recovery source state unprojected': 'RECOVERY_SOURCE_UNPROJECTED',
    'Recovery scenario refused': 'RECOVERY_SCENARIO_REFUSED',
    'Recovery qualification rollback fault': 'QUALIFICATION_ROLLBACK_FAULT',
}


def code_of(error):
    """Fixed code of a harness refusal, the R6 session/matrix code, or the error type class."""
    message = str(error)
    if isinstance(error, VerificationError):
        return (RECOVERY_CODES.get(message) or session_module.SESSION_CODES.get(message)
                or matrix.MATRIX_CODES.get(message) or firefox.CODES.get(message) or 'UNCLASSIFIED')
    return 'UNCLASSIFIED'


def _bounded_file(path, limit, message):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise VerificationError(message) from None
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), message)
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, message)
    return raw


def load_libraries(libexec=LIBEXEC):
    """The accepted guarded_recovery module, and through it its own durable_state sibling.

    Both files are hashed before execution and again after loading, and the foundation the
    library loaded must be that exact sibling file. The module object stays private (never
    registered in sys.modules), as RECOVERY-PREP1 loads its foundation. The harness never loads
    a second durable_state: gr.ds is the only foundation instance it uses.
    """
    libexec = Path(libexec)
    paths = {'gr': libexec / 'guarded_recovery.py', 'ds': libexec / 'durable_state.py'}
    pins = {'gr': GUARDED_RECOVERY_SHA256, 'ds': DURABLE_STATE_SHA256}
    message = 'Recovery library digest mismatch'

    def verified():
        return all(hashlib.sha256(_bounded_file(paths[k], LIBRARY_LIMIT, message)).hexdigest() == pins[k]
                   for k in paths)
    require(verified(), message)
    spec = importlib.util.spec_from_file_location('browser_ux_cnt_guarded_recovery_qualification', paths['gr'])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    origin = getattr(getattr(module.ds, '__spec__', None), 'origin', None)
    require(origin is not None and Path(origin) == paths['ds'] and verified(), message)
    return module


gr = load_libraries()
ds = gr.ds


def digest_record(value):
    return ds.sha256_hex(ds.canonical_bytes(value))


class _Sealed:
    """Immutable value minted only by its owner function (type discipline, not authentication)."""
    __slots__ = ()

    def __init__(self, *_args, **_kwargs):
        raise VerificationError('Recovery export incomplete')

    def __setattr__(self, _name, _value):
        raise VerificationError('Recovery export incomplete')

    @classmethod
    def _mint(cls, **fields):
        instance = object.__new__(cls)
        for name in cls.__slots__:
            object.__setattr__(instance, name, fields[name])
        return instance


# --- Independent native-export closure ----------------------------------------------------------

OBSERVATION_KEYS = ('facts_verified', 'baseline_captured', 'baseline_stable', 'clicks', 'start_observed',
                    'end_observed', 'end_captured', 'dom_backgrounds', 'entries', 'parts')
ENTRY_KEYS = ('index', 'name_class', 'bytes', 'sha256')
EMPTY_SINGLE_PART = 'EMPTY_SINGLE_PART'


class ClosureProof(_Sealed):
    """A closed export: the exact parts, their count and projection-safe closure facts."""
    __slots__ = ('parts', 'part_count', 'facts')


def prove_export_closure(observation, labels):
    """ClosureProof for one attributed native export, else VerificationError(EXPORT_INCOMPLETE).

    Pure over a fixed-key observation. Every condition must hold; nothing is repaired, counted
    from a declaration or inferred from quiescence alone:
    - baseline: the capture list was cleared and read 0, stable and not protecting, before the
      single download click (no in-flight export);
    - attribution: exactly one click; every part was captured after that baseline;
    - positive start (a first part arrived) and positive end (stable, not protecting, no further
      part for SETTLE after the last one read);
    - helper indexes 0..n-1, names NATIVE_PART_1..N, digests unique: no missing, extra or
      duplicate part;
    - parser closure: the R6 fingerprint parses completely, exported rows equal the DOM
      background count, every part is the native template with the settings header on part 1
      only, and the native partition predicate (backup.partition) reproduces the observed
      grouping at the export's own threshold; a state with no chunk closes only as exactly one
      part with 0 rows and 0 DOM backgrounds (EMPTY_SINGLE_PART, the R6 fresh pre-export shape);
    - the accepted foundation projects the set as PROJECTED_FIREFOX_6_12_1 for the exact labels;
    - per-part, per-set and part-count bounds of the accepted library.
    """
    def holds(condition):
        if not condition:
            raise VerificationError('Recovery export incomplete')
    holds(type(observation) is dict and set(observation) == set(OBSERVATION_KEYS))
    holds(observation['facts_verified'] is True)
    holds(observation['baseline_captured'] == 0 and type(observation['baseline_captured']) is int
          and observation['baseline_stable'] is True)
    holds(observation['clicks'] == 1 and type(observation['clicks']) is int)
    holds(observation['start_observed'] is True and observation['end_observed'] is True)
    entries, parts = observation['entries'], observation['parts']
    holds(type(entries) is list and type(parts) is list and all(type(p) is bytes for p in parts))
    count = len(parts)
    holds(1 <= count <= ds.MAX_ARTIFACTS and len(entries) == count
          and observation['end_captured'] == count and type(observation['end_captured']) is int)
    holds(all(len(p) <= gr.MAX_NATIVE_PART_BYTES for p in parts)
          and sum(len(p) for p in parts) <= gr.MAX_PART_SET_BYTES)
    digests = [hashlib.sha256(p).hexdigest() for p in parts]
    for n, (entry, raw) in enumerate(zip(entries, parts)):
        holds(type(entry) is dict and set(entry) == set(ENTRY_KEYS) and type(entry['index']) is int
              and entry['index'] == n and entry['name_class'] == f'NATIVE_PART_{n + 1}'
              and entry['bytes'] == len(raw) and type(entry['bytes']) is int and entry['sha256'] == digests[n])
    holds(len(set(digests)) == count)
    dom = observation['dom_backgrounds']
    holds(type(dom) is int and dom >= 0)
    fp = matrix.fingerprint(parts)
    holds(fp['complete'] is True and fp['derived']['row_count'] == dom)
    try:
        layouts = [matrix.part_layout(p) for p in parts]
    except VerificationError:
        raise VerificationError('Recovery export incomplete') from None
    holds(all(l['native_template'] is True for l in layouts) and layouts[0]['settings_header'] is True
          and not any(l['settings_header'] for l in layouts[1:]))
    chunks = sum(len(l['chunk_core_bytes']) for l in layouts)
    if chunks == 0:
        holds(count == 1 and dom == 0)
        partition = EMPTY_SINGLE_PART
    else:
        partition = matrix.partition_layouts(layouts, matrix.export_threshold(fp))['status']
        holds(partition == 'CONSISTENT')
    try:
        manifest = ds.build_manifest(list(parts), labels)
    except ds.DurableStateError:
        raise VerificationError('Recovery export incomplete') from None
    holds(manifest['projection_status'] == ds.PROJECTED)
    facts = {'proven': True, 'start_observed': True, 'end_observed': True, 'attributed': True,
             'baseline_quiescent': True, 'clicks': 1, 'index_contiguous': True, 'duplicates': 0,
             'partition_status': partition, 'rows_match': True, 'rows': dom,
             'projection_status': manifest['projection_status'], 'part_count': count,
             'part_sha256': digests, 'part_bytes': [len(p) for p in parts]}
    return ClosureProof._mint(parts=tuple(parts), part_count=count, facts=facts)


def export_from_proof(proof, labels):
    """The adapter export dict; part_count comes only from the closed set."""
    require(type(proof) is ClosureProof, 'Recovery export incomplete')
    return {'labels': dict(labels), 'part_count': proof.part_count, 'parts': list(proof.parts)}


# --- Tokens: opaque digests, never paths ----------------------------------------------------------

UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HEX64 = re.compile(r'[0-9a-f]{64}')


def profile_token(nonce, device, inode):
    """Per-run nonce plus the profile directory's (st_dev, st_ino). No role is mixed in, so the
    library's staging != target token check compares real identities, not a constant."""
    require(HEX64.fullmatch(nonce or '') is not None and type(device) is int and type(inode) is int,
            'Recovery plan invalid')
    return hashlib.sha256(b'bux5b1-qual-profile-v1\0' + nonce.encode() + b'\0'
                          + f'{device}:{inode}'.encode()).hexdigest()


def storage_token(nonce, extension_uuid):
    """Per-run nonce plus the profile's own moz-extension UUID (WebExtensionPolicy, chrome context).
    Independent of profile_token, so storage distinctness is checked on its own."""
    require(HEX64.fullmatch(nonce or '') is not None, 'Recovery plan invalid')
    require(type(extension_uuid) is str and UUID.fullmatch(extension_uuid) is not None,
            'Recovery storage identity unavailable')
    return hashlib.sha256(b'bux5b1-qual-storage-v1\0' + nonce.encode() + b'\0'
                          + extension_uuid.encode()).hexdigest()


def proven_labels(result):
    """ds.PROJECTED_LABELS only when Marionette reported the exact Firefox, the temporary install
    returned the CNT id, and the in-run capture copy verified as the retained 6.12.1 XPI."""
    capture = result.get('capture_copy') if isinstance(result.get('capture_copy'), dict) else {}
    session = result.get('recovery_session') if isinstance(result.get('recovery_session'), dict) else {}
    opened = [s for s in session.get('steps') or [] if isinstance(s, dict) and s.get('step') == 'open_settings']
    require(result.get('browser_version') == FIREFOX_VERSION
            and capture.get('xpi_sha256') == CAPTURE_SHA256 and capture.get('extension_id') == EXTENSION_ID
            and capture.get('version') == EXTENSION_VERSION
            and len(opened) == 1 and opened[0].get('status') == 'DONE', 'Recovery target labels unproven')
    return dict(ds.PROJECTED_LABELS)


# --- Pre-launch freshness / staging disposability -------------------------------------------------

ROLES = ('source', 'staging', 'target')
PROFILE_ENTRIES = ('user.js',)
CAPTURE_RELATIVE = 'capture/clear-new-tab.xpi'
RUNTIME_RELATIVE = 'runtime'


def prove_fresh_profile(plan, run, expected_user_js, *, created_exclusive):
    """Run by the preflight after arguments() wrote user.js and immediately before the launch.

    The attempt root is exactly <claim root>/cases/<attempt name>, under managed scratch, created
    by this attempt's exclusive mkdir (and seen absent by the host before spawning), link-free
    from the claim root down to the profile and owned by this user, with cases, attempt and profile
    private (0700); the profile
    holds exactly the user.js arguments() generates; the only XPI anywhere in the attempt is the
    retained capture copy. There is no copy route from HOME or any profile: HOME is run/home and
    the policy denies reads outside run and the runtime. Token difference alone is never proof.
    """
    from cnt_confinement import SCRATCH, environment
    message = ('Recovery staging disposability unproven' if plan.get('role') == 'staging'
               else 'Recovery profile freshness unproven')
    try:
        run = Path(run)
        root = Path(plan['claim_root'])
        cases = root / 'cases'
        uid = os.geteuid()
        require(created_exclusive is True, message)
        require(run.is_absolute() and root.is_absolute() and root.is_relative_to(SCRATCH)
                and run == cases / plan['attempt_name'] and run.resolve() == run, message)
        for path in (root, cases, run, run / 'profile'):
            info = os.lstat(path)
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == uid, message)
        # The operator-supplied claim root is owner- and link-checked only; the host-created cases
        # directory, the attempt and the profile must be private.
        for path in (cases, run, run / 'profile'):
            require(stat.S_IMODE(os.lstat(path).st_mode) == 0o700, message)
        require(tuple(sorted(os.listdir(run / 'profile'))) == PROFILE_ENTRIES, message)
        user_js = run / 'profile/user.js'
        info = os.lstat(user_js)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid, message)
        require(_bounded_file(user_js, 64 * 1024, message) == expected_user_js, message)
        xpis = []
        for directory, directories, files in os.walk(run, followlinks=False):
            if Path(directory) == run:
                # The frozen runtime copy (prepare_runtime) is bound by its own tree digest to the
                # production Firefox and carries the application's built-in feature add-ons; it is
                # application code, never profile or captured input, so it is not scanned here.
                directories[:] = [d for d in directories if d != RUNTIME_RELATIVE]
            for name in directories + files:
                if name.lower().endswith('.xpi'):
                    xpis.append(Path(directory, name).relative_to(run).as_posix())
        require(xpis == [CAPTURE_RELATIVE], message)
        capture = matrix.verify_capture(run / CAPTURE_RELATIVE)
        require(capture['xpi_sha256'] == CAPTURE_SHA256, message)
        require(environment(run)['HOME'] == str(run / 'home'), message)
    except (VerificationError, OSError, KeyError, TypeError, ValueError):
        raise VerificationError(message) from None
    return {'role': plan['role'], 'contained': True, 'created_exclusive': True, 'link_free': True,
            'private_mode': True, 'owner_matches': True, 'profile_entries': list(PROFILE_ENTRIES),
            'user_js_generated': True, 'xpi_only_capture': True, 'home_is_run_home': True,
            'copy_route': 'NONE', 'proven': True}


# --- Per-state-root exclusive execution claim -----------------------------------------------------

STATE_ROOT_CLAIM = 'STATE-ROOT.claim'
STATE_ROOT_SUFFIX = '-state'


def create_state_root(run, suffix=STATE_ROOT_SUFFIX):
    """A fresh caller-owned state root beside the attempt (beneath the owned claim root's cases
    directory, outside the browser's writable run). Exclusive mkdir 0700; never reused."""
    path = Path(run).parent / (Path(run).name + suffix)
    try:
        os.mkdir(path, 0o700)
    except OSError:
        raise VerificationError('Recovery state root invalid') from None
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'Recovery state root invalid')
    return path


class StateRootClaim:
    """Exclusive execution claim on one state root: O_CREAT|O_EXCL|O_NOFOLLOW 0600 plus
    flock(LOCK_EX|LOCK_NB) held on the descriptor for the whole scenario. A second owner fails at
    O_EXCL or flock before any adapter call. The file is never deleted (a released claim still
    refuses a second owner: qualification never re-enters a state root)."""

    def __init__(self, path, descriptor, raw):
        self.path, self.descriptor, self.raw = path, descriptor, raw

    @classmethod
    def acquire(cls, state_root, scenario, attempt):
        path = Path(state_root) / STATE_ROOT_CLAIM
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise VerificationError('Recovery state root claim exists') from None
        except OSError as error:
            code = 'Recovery state root claim exists' if error.errno == errno.ELOOP else 'Recovery state root invalid'
            raise VerificationError(code) from None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(descriptor)
            raise VerificationError('Recovery state root claim exists') from None
        raw = (json.dumps({'schema': 'bux5b1-qual-state-root-claim-v1', 'scenario': scenario,
                           'attempt': attempt, 'owner_nonce': secrets.token_hex(32)},
                          sort_keys=True) + '\n').encode()
        os.write(descriptor, raw)
        os.fsync(descriptor)
        return cls(path, descriptor, raw)

    def verify(self):
        """The held descriptor is still the file at the path, with this owner's bytes."""
        try:
            held, named = os.fstat(self.descriptor), os.lstat(self.path)
            same = ((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                    and stat.S_ISREG(named.st_mode) and os.pread(self.descriptor, len(self.raw) + 1, 0) == self.raw)
        except OSError:
            same = False
        require(same, 'Recovery state root claim lost')
        return True

    def release(self):
        """Close (dropping the lock); the claim file stays."""
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


# --- Caller-level single-use qualification token ----------------------------------------------------

TOKEN_SCHEMA = 'bux5b1-qual-caller-token-v1'
TOKEN_KEYS = ('schema', 'scenario', 'journal_id', 'global_claim_sha256', 'kind', 'nonce')
TOKEN_KINDS = ('OPERATOR_AUTHORIZATION', 'QUALIFICATION_SYNTHETIC_RESET', 'NONE')
CONSUMED_SUFFIX = '.consumed'


def issue_token(tokens, scenario, journal_id, global_claim_sha256, kind):
    """Host side, after the global claim: one exclusive token file per recover() journal."""
    require(kind in TOKEN_KINDS and HEX64.fullmatch(global_claim_sha256 or '') is not None, 'Recovery plan invalid')
    record = {'schema': TOKEN_SCHEMA, 'scenario': scenario, 'journal_id': journal_id,
              'global_claim_sha256': global_claim_sha256, 'kind': kind, 'nonce': secrets.token_hex(32)}
    raw = (json.dumps(record, sort_keys=True) + '\n').encode()
    path = Path(tokens) / f'{journal_id}.token'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'scenario': scenario,
            'journal_id': journal_id, 'kind': kind}


def consume_token(token, scenario, global_claim_sha256, kind, bound_sha256):
    """Consume once, before recover(): an exclusive `<token>.consumed` binds the exact
    authorization/evidence digest (or null) actually passed. Reuse refuses CALLER_TOKEN_REUSED;
    any binding difference refuses CALLER_TOKEN_INVALID. recover() is never called on refusal."""
    path = Path(token['path'])
    raw = _bounded_file(path, 4096, 'Recovery caller token invalid')
    require(hashlib.sha256(raw).hexdigest() == token['sha256'], 'Recovery caller token invalid')
    try:
        record = json.loads(raw)
    except ValueError:
        raise VerificationError('Recovery caller token invalid') from None
    require(isinstance(record, dict) and set(record) == set(TOKEN_KEYS) and record['schema'] == TOKEN_SCHEMA
            and record['scenario'] == scenario == token['scenario'] and record['journal_id'] == token['journal_id']
            and record['global_claim_sha256'] == global_claim_sha256 and record['kind'] == kind == token['kind']
            and (bound_sha256 is None) == (kind == 'NONE')
            and (bound_sha256 is None or HEX64.fullmatch(bound_sha256) is not None),
            'Recovery caller token invalid')
    consumed = {'schema': 'bux5b1-qual-caller-token-consumed-v1', 'token_sha256': token['sha256'],
                'journal_id': record['journal_id'], 'kind': kind, 'bound_sha256': bound_sha256}
    try:
        descriptor = os.open(str(path) + CONSUMED_SUFFIX, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
    except FileExistsError:
        raise VerificationError('Recovery caller token reused') from None
    except OSError:
        raise VerificationError('Recovery caller token invalid') from None
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(json.dumps(consumed, sort_keys=True) + '\n')
    return consumed


def token_consumed(token):
    return os.path.lexists(str(token['path']) + CONSUMED_SUFFIX)


# --- Staging record and replay -------------------------------------------------------------------

STAGING_SCHEMA = 'bux5b1-qual-staging-v1'
STAGING_KEYS = ('schema', 'scenario', 'claim_root_name', 'plan_nonce', 'attempt_name', 'requested_part_sha256',
                'requested_manifest_sha256', 'staged_label', 'staged_part_sha256', 'staged_closure', 'identity',
                'profile_identity', 'disposability', 'extension_set_proven', 'native_restore_completed')


def manifest_digest(parts, labels):
    return ds.sha256_hex(ds.serialize_manifest(ds.build_manifest(list(parts), labels)))


def staging_path(claim_root, scenario):
    return Path(claim_root) / 'staging' / f'{scenario}.json'


def write_staging_record(claim_root, record):
    require(type(record) is dict and set(record) == set(STAGING_KEYS), 'Recovery staging record invalid')
    path = staging_path(claim_root, record['scenario'])
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')
    return path


class StagingReplay:
    """stage(parts) for one scenario: the earlier staging attempt of this claim root, consumed once.

    The record must name this scenario, claim root and run nonce; record disposability (pre-launch
    proof plus the post-launch extension set) and a native-completed restore; its requested input
    must equal the parts the library passes (digests and manifest digest); its staged export must
    re-verify byte for byte from the closed set it recorded; the staging profile must be another
    profile than the target's (device/inode and attempt), with other tokens. Single-use by an
    exclusive `<record>.consumed`."""

    def __init__(self, plan):
        self.plan, self.used = plan, False

    def replay(self, parts, target_identity, target_profile):
        plan = self.plan
        require(not self.used, 'Recovery staging record reused')
        self.used = True
        path = staging_path(plan['claim_root'], plan['scenario'])
        try:
            descriptor = os.open(str(path) + CONSUMED_SUFFIX, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
        except FileExistsError:
            raise VerificationError('Recovery staging record reused') from None
        except OSError:
            raise VerificationError('Recovery staging record invalid') from None
        os.close(descriptor)
        try:
            record = json.loads(_bounded_file(path, 1024 * 1024, 'Recovery staging record invalid'))
        except ValueError:
            raise VerificationError('Recovery staging record invalid') from None
        require(isinstance(record, dict) and set(record) == set(STAGING_KEYS) and record['schema'] == STAGING_SCHEMA
                and record['scenario'] == plan['scenario'] and record['plan_nonce'] == plan['plan_nonce']
                and record['claim_root_name'] == Path(plan['claim_root']).name, 'Recovery staging record invalid')
        require(record['extension_set_proven'] is True and record['native_restore_completed'] is True
                and isinstance(record['disposability'], dict) and record['disposability'].get('proven') is True
                and record['disposability'].get('role') == 'staging', 'Recovery staging disposability unproven')
        labels = dict(ds.PROJECTED_LABELS)
        require([hashlib.sha256(p).hexdigest() for p in parts] == record['requested_part_sha256']
                and manifest_digest(parts, labels) == record['requested_manifest_sha256'],
                'Recovery staged input mismatch')
        closure = record['staged_closure'] if isinstance(record['staged_closure'], dict) else {}
        require(closure.get('proven') is True and closure.get('part_sha256') == record['staged_part_sha256'],
                'Recovery staging record invalid')
        attempt = Path(plan['claim_root']) / 'cases' / record['attempt_name']
        require(record['attempt_name'] != plan['attempt_name'] and attempt.parent == Path(plan['attempt']).parent,
                'Recovery staging disposability unproven')
        staged = []
        try:
            for n, digest in enumerate(record['staged_part_sha256'], 1):
                raw = matrix.file_bytes(plain_descendant(attempt, f'artifacts/{record["staged_label"]}/part-{n}.json'),
                                        gr.MAX_NATIVE_PART_BYTES)
                require(hashlib.sha256(raw).hexdigest() == digest, 'Recovery staging record invalid')
                staged.append(raw)
        except (OSError, VerificationError):
            raise VerificationError('Recovery staging record invalid') from None
        identity = record['identity']
        require(isinstance(identity, dict) and identity.get('labels') == labels
                and identity.get('profile_token') != target_identity['profile_token']
                and identity.get('storage_token') != target_identity['storage_token']
                and record['profile_identity'] != list(target_profile), 'Recovery staging disposability unproven')
        return {'identity': {k: identity[k] for k in ('labels', 'profile_token', 'storage_token')},
                'export': {'labels': labels, 'part_count': len(staged), 'parts': staged}}


# --- The adapter -------------------------------------------------------------------------------------

QUALIFICATION_FAULT_INJECTION = 'QUALIFICATION_FAULT_INJECTION'
QUALIFICATION_TARGET_SETUP = 'QUALIFICATION_TARGET_SETUP'
FAULT_KINDS = ('CONCURRENT_UI_CHANGE', 'POST_APPLY_UI_CHANGE', 'ROLLBACK_FAULT_BEFORE_NATIVE',
               'INTERRUPT_AFTER_NATIVE_ROLLBACK', 'FORGED_TARGET_TOKEN', 'REQUESTED_PART_OMITTED',
               'REQUESTED_PART_SUBSTITUTED')
COUNTERS = ('identity', 'export', 'stage', 'apply', 'rollback', 'native_apply', 'native_rollback')


class QualificationRollbackFault(Exception):
    """Raised by rollback() before any native action (ROLLBACK_FAILURE)."""


class QualificationInterrupt(BaseException):
    """Raised by rollback() after a completed native rollback, at the write-ahead boundary
    (INTERRUPTED_ROLLBACK_RESUME). A BaseException: the library lets it through, leaving the
    persisted ROLLBACK_REQUIRED journal for resume()."""


class FirefoxRecoveryAdapter:
    """The library's adapter. `driver` performs native actions in the owned session (the R6
    Session subclass below, or a portable fake). `hooks` maps a seam to a qualification fault."""

    def __init__(self, driver, staging=None, hooks=None):
        self.driver, self.staging, self.hooks = driver, staging, dict(hooks or {})
        self.counters = dict.fromkeys(COUNTERS, 0)
        self.injections, self.codes, self.rollback_inputs = [], [], []

    def inject(self, kind, seam):
        require(kind in FAULT_KINDS, 'Recovery scenario refused')
        self.injections.append({'label': QUALIFICATION_FAULT_INJECTION, 'kind': kind, 'seam': seam})

    def _hook(self, seam):
        hook = self.hooks.get(seam)
        if hook is not None:
            hook(self)

    def _guard(self, action):
        try:
            return action()
        except Exception as error:
            self.codes.append(code_of(error) if not isinstance(error, QualificationRollbackFault)
                              else 'QUALIFICATION_ROLLBACK_FAULT')
            raise

    def identity(self):
        self.counters['identity'] += 1
        def run():
            self._hook('identity')
            return self.driver.identity()
        return self._guard(run)

    def export_current(self):
        self.counters['export'] += 1
        return self._guard(lambda: export_from_proof(self.driver.closed_export(), self.driver.labels()))

    def stage(self, parts):
        self.counters['stage'] += 1
        def run():
            require(self.staging is not None, 'Recovery staging record invalid')
            return self.staging.replay(parts, self.driver.identity(), self.driver.profile_identity())
        return self._guard(run)

    def apply(self, parts):
        self.counters['apply'] += 1
        def run():
            ok, _ = self.driver.native_restore(list(parts), 'apply')
            require(ok, 'Recovery native apply not completed')
            self.counters['native_apply'] += 1
            self._hook('after_apply')
        return self._guard(run)

    def rollback(self, parts):
        self.counters['rollback'] += 1
        self.rollback_inputs.append([hashlib.sha256(p).hexdigest() for p in parts])
        def run():
            self._hook('before_rollback')
            ok, _ = self.driver.native_restore(list(parts), 'rollback')
            require(ok, 'Recovery native rollback not completed')
            self.counters['native_rollback'] += 1
            self._hook('after_rollback')
        return self._guard(run)


# --- In-session native driver (R6 Session reuse) ------------------------------------------------------

RECOVERY_ENTRY = {'id': 'BUX5B1-RECOVERY', 'category': 'R', 'profile': matrix.FRESH_TARGET, 'source': None,
                  'artifact': None, 'selection': None, 'mutation': None, 'mutate_part': 1, 'steps': (),
                  'predictions': {}, 'runnable': True, 'reason': None, 'allow_no_signal': False}
# The one supported-UI change the qualification uses: a verified select route (ui.event.select) on
# a non-volatile accepted preference whose values are all allowlisted (ui.options_page_theme).
QUAL_UI_PREF = 'options_page_theme'
QUAL_UI_VALUES = {'requested_default': 'lavender', 'setup': 'dark', 'injection': 'clover'}


class RecoverySession(session_module.Session):
    """R6 Session reused for transport, page helper, idle/settle, readout, native restore and
    reload. Adds the attributed closed export, the identity reads and the native restore of an
    exact part set. Facts go to result['recovery_session'] (never result['matrix'])."""

    def __init__(self, client, run, result, provenance, plan, clock=time.monotonic):
        super().__init__(client, run, result, RECOVERY_ENTRY, provenance, clock)
        result['recovery_session'] = result.pop('matrix')
        self.plan, self.pending, self.exports, self.operations, self.last_label = plan, [], 0, 0, None

    def restore_inputs(self):
        return list(self.pending)

    def labels(self):
        return proven_labels(self.result)

    def chrome(self, source, arguments=()):
        from cnt_synthetic_firefox import script
        self.client.call('Marionette:SetContext', {'value': 'chrome'})
        try:
            return script(self.client, source, list(arguments))
        finally:
            self.client.call('Marionette:SetContext', {'value': 'content'})

    def prove_extension_set(self):
        """Exactly one active non-privileged WebExtension, the CNT id. Built-in and system add-ons
        are privileged in Firefox and excluded; nothing reads add-on databases or storage."""
        ids = self.chrome('return WebExtensionPolicy.getActiveExtensions()'
                          '.filter(p => !p.isPrivileged).map(p => String(p.id));')
        require(ids == [EXTENSION_ID], 'Recovery extension set unproven')
        self.record['extension_set'] = {'non_privileged_active': 1, 'cnt_only': True}
        return {'extension_set_proven': True}

    def profile_identity(self):
        info = os.stat(self.run / 'profile', follow_symlinks=False)
        return (info.st_dev, info.st_ino)

    def identity(self):
        labels = self.labels()
        uuid = self.chrome('const p = WebExtensionPolicy.getByID(arguments[0]);'
                           ' return p ? String(p.mozExtensionHostname) : null;', [EXTENSION_ID])
        device, inode = self.profile_identity()
        return {'labels': labels, 'profile_token': profile_token(self.plan['plan_nonce'], device, inode),
                'storage_token': storage_token(self.plan['plan_nonce'], uuid)}

    def closed_export(self):
        """One attributed export, read back and handed to prove_export_closure."""
        self.exports += 1
        label = f'recovery-{self.exports}'
        try:
            self.facts('export')
        except VerificationError:
            raise VerificationError('Recovery export incomplete') from None
        self.page('return window.__buxMatrix.clear();')
        exports = self.record.setdefault('exports', [])
        try:
            baseline = self.idle(lambda s: s['captured'] == 0, session_module.DEADLINES['export'])
        except VerificationError as error:
            if str(error) != 'Matrix step deadline':
                raise
            # A part captured after clear() and before any click (a straggler) is never attributed.
            exports.append({'label': label, 'proven': False, 'baseline_quiescent': False})
            raise VerificationError('Recovery export incomplete') from None
        self.click(self.selectors['download'])
        target = self.run / 'artifacts' / label
        target.mkdir(parents=True, mode=0o700)
        started, deadline = self.clock(), session_module.DEADLINES['export']
        entries, paths, start, end, end_captured, dom = [], [], False, False, None, None
        rows = {'read': 0}

        def settled(s, have):
            # More parts, or (as R6 ROWS_SHORT) a stable set whose parts read so far already hold at
            # least the page's background count; a short set keeps waiting until the deadline.
            return s['captured'] > have or (have >= 1 and s['captured'] == have and rows['read'] >= s['backgrounds'])
        while len(entries) <= ds.MAX_ARTIFACTS:
            try:
                state = self.idle(lambda s, have=len(entries): settled(s, have), deadline - (self.clock() - started))
            except VerificationError as error:
                if str(error) != 'Matrix step deadline':
                    raise
                break
            start = True
            if state['captured'] == len(entries):
                end, end_captured, dom = True, state['captured'], state['backgrounds']
                break
            captured = self.page('return window.__buxMatrix.captured();')
            require(isinstance(captured, list) and len(captured) >= state['captured'], 'Matrix export absent')
            fresh = captured[len(entries):]
            if any(not isinstance(e, dict) or e.get('index') != len(entries) + n for n, e in enumerate(fresh)):
                break
            for entry in fresh:
                part, path = self.read_part(target, entry)
                entries.append(part)
                paths.append(path)
            fp = matrix.fingerprint([matrix.file_bytes(p, session_module.ARTIFACT_LIMIT) for p in paths])
            # An unparseable set never closes; waiting longer cannot repair it.
            rows['read'] = fp['derived']['row_count'] if fp['complete'] else float('inf')
        observation = {'facts_verified': True, 'baseline_captured': baseline.get('captured'),
                       'baseline_stable': True, 'clicks': 1, 'start_observed': start, 'end_observed': end,
                       'end_captured': end_captured, 'dom_backgrounds': dom, 'entries': entries,
                       'parts': [matrix.file_bytes(p, session_module.ARTIFACT_LIMIT) for p in paths]}
        try:
            proof = prove_export_closure(observation, self.labels())
        except VerificationError:
            exports.append({'label': label, 'proven': False, 'start_observed': start, 'end_observed': end,
                            'captured': len(entries)})
            raise
        exports.append({'label': label, **proof.facts})
        self.last_label = label
        return proof

    def native_restore(self, parts, op):
        """The extension's own restore of exact bytes (fresh O_EXCL 0600 files under run/inputs, in
        native order), behind the pre-restore ribbon gate, then reload. Native only when the R6
        restore completed with no error and both start and transition-end signals."""
        self.operations += 1
        folder = self.run / 'inputs' / f'{op}-{self.operations}'
        folder.mkdir(parents=True, mode=0o700)
        paths = []
        for number, raw in enumerate(parts, 1):
            path = folder / matrix.INPUT_NAME.format(number)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
            require(matrix.file_bytes(path, len(raw)) == raw, 'Matrix input digest mismatch')
            paths.append(path)
        require(self.state().get('error_visible') is False, 'Recovery pre-existing error ribbon')
        self.pending = paths
        try:
            outcome = self.restore()
        finally:
            self.pending = []
        self.reload()
        ok = (outcome['completion'] == 'COMPLETED' and outcome['restore_error'] is False
              and outcome['start_observed'] is True and outcome['transition_end_observed'] is True)
        return ok, outcome

    def set_ui_pref(self, value):
        require(value in QUAL_UI_VALUES.values(), 'Recovery scenario refused')
        self.select(QUAL_UI_PREF, value)


# --- Plans and inputs -------------------------------------------------------------------------------

PLAN_SCHEMA = 'bux5b1-qual-plan-v1'
PLAN_KEYS = ('schema', 'role', 'scenario', 'plan_nonce', 'claim_root', 'attempt', 'attempt_name',
             'source_attempt', 'tokens', 'global_claim_sha256')
PLAN_LIMIT = 256 * 1024
SOURCE_RESULT_LIMIT = 8 * 1024 * 1024
SAFE_NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')


def load_plan(path, expected_sha256, scratch):
    """Preflight selection stage, before any attempt root: the host-written plan, digest-bound."""
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'Recovery plan invalid')
    raw = _bounded_file(path, PLAN_LIMIT, 'Recovery plan invalid')
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'Recovery plan invalid')
    try:
        plan = json.loads(raw)
    except ValueError:
        raise VerificationError('Recovery plan invalid') from None
    from cnt_confinement import SCRATCH
    require(isinstance(plan, dict) and set(plan) == set(PLAN_KEYS) and plan['schema'] == PLAN_SCHEMA
            and plan['role'] in ROLES and HEX64.fullmatch(plan['plan_nonce'] or '') is not None
            and HEX64.fullmatch(plan['global_claim_sha256'] or '') is not None
            and isinstance(plan['attempt_name'], str) and SAFE_NAME.fullmatch(plan['attempt_name']) is not None
            and isinstance(plan['claim_root'], str) and Path(plan['claim_root']).is_absolute()
            and Path(plan['claim_root']).is_relative_to(SCRATCH)
            and plan['attempt'] == str(Path(scratch).absolute())
            and Path(plan['attempt']) == Path(plan['claim_root']) / 'cases' / plan['attempt_name'],
            'Recovery plan invalid')
    if plan['role'] == 'source':
        require(plan['scenario'] is None and plan['source_attempt'] is None and plan['tokens'] == [],
                'Recovery plan invalid')
        return plan
    require(plan['scenario'] in SCENARIOS and isinstance(plan['source_attempt'], str)
            and Path(plan['source_attempt']).parent == Path(plan['attempt']).parent
            and Path(plan['source_attempt']).resolve() == Path(plan['source_attempt']), 'Recovery plan invalid')
    if plan['role'] == 'staging':
        require(plan['scenario'] in STAGED_SCENARIOS and plan['tokens'] == [], 'Recovery plan invalid')
    else:
        require(isinstance(plan['tokens'], list)
                and [t.get('journal_id') if isinstance(t, dict) else None for t in plan['tokens']]
                == list(JOURNALS[plan['scenario']])
                and all(set(t) == {'path', 'sha256', 'scenario', 'journal_id', 'kind'}
                        and t['scenario'] == plan['scenario'] and t['kind'] == TOKEN_KIND[t['journal_id']]
                        and Path(t['path']).parent == Path(plan['claim_root']) / 'tokens' for t in plan['tokens']),
                'Recovery plan invalid')
    plan['_inputs'] = source_inputs(Path(plan['source_attempt']))
    return plan


def source_inputs(source):
    """The reset and requested part sets of the completed same-root source attempt, each bound to
    the closure facts its own result.json recorded and re-verified byte for byte."""
    try:
        result = json.loads(_bounded_file(source / 'result.json', SOURCE_RESULT_LIMIT, 'Recovery source invalid'))
    except ValueError:
        raise VerificationError('Recovery source invalid') from None
    facts = result.get('recovery') if isinstance(result, dict) else None
    require(isinstance(facts, dict) and result.get('status') == 'RECOVERY_ATTEMPT_COMPLETED'
            and facts.get('role') == 'source' and facts.get('completed') is True, 'Recovery source invalid')
    inputs = {}
    for name in ('reset', 'requested'):
        export = (facts.get('exports') or {}).get(name)
        require(isinstance(export, dict) and export.get('proven') is True and isinstance(export.get('label'), str)
                and SAFE_NAME.fullmatch(export['label']) is not None
                and isinstance(export.get('part_sha256'), list) and export['part_sha256'], 'Recovery source invalid')
        parts = []
        try:
            for n, digest in enumerate(export['part_sha256'], 1):
                raw = matrix.file_bytes(plain_descendant(source, f'artifacts/{export["label"]}/part-{n}.json'),
                                        gr.MAX_NATIVE_PART_BYTES)
                require(hashlib.sha256(raw).hexdigest() == digest, 'Recovery source invalid')
                parts.append(raw)
        except (OSError, VerificationError):
            raise VerificationError('Recovery source invalid') from None
        inputs[name] = parts
    require(facts.get('requested_manifest_sha256') == manifest_digest(inputs['requested'], ds.PROJECTED_LABELS),
            'Recovery source invalid')
    return inputs


# --- Scenario roster, journals and expectations -------------------------------------------------------

SCENARIOS = ('NOOP_MATCH', 'SYNTHETIC_RESET_COMPLETED', 'OPERATOR_AUTH_COMPLETED', 'CONCURRENT_CHANGE',
             'POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME',
             'TARGET_IDENTITY_REFUSAL', 'REQUESTED_PART_REFUSAL', 'IDEMPOTENT_REPEAT')
RUN_LEVEL = 'ZERO_LIVE_CONTACT'
ROSTER = SCENARIOS + (RUN_LEVEL,)
# Scenarios whose recover() reaches stage(): each has its own earlier staging attempt.
STAGED_SCENARIOS = ('SYNTHETIC_RESET_COMPLETED', 'OPERATOR_AUTH_COMPLETED', 'CONCURRENT_CHANGE',
                    'POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME',
                    'IDEMPOTENT_REPEAT')
JOURNALS = {'NOOP_MATCH': ('s01-noop',), 'SYNTHETIC_RESET_COMPLETED': ('s02-reset',),
            'OPERATOR_AUTH_COMPLETED': ('s03-operator',), 'CONCURRENT_CHANGE': ('s04-concurrent',),
            'POST_APPLY_MISMATCH_ROLLBACK': ('s05-mismatch',), 'ROLLBACK_FAILURE': ('s06-rollback-fault',),
            'INTERRUPTED_ROLLBACK_RESUME': ('s07-interrupted',), 'TARGET_IDENTITY_REFUSAL': ('s08-identity',),
            'REQUESTED_PART_REFUSAL': ('s09-missing', 's09-substituted'),
            'IDEMPOTENT_REPEAT': ('s10-first', 's10-repeat')}
TOKEN_KIND = {'s01-noop': 'NONE', 's02-reset': 'QUALIFICATION_SYNTHETIC_RESET',
              's03-operator': 'OPERATOR_AUTHORIZATION', 's04-concurrent': 'OPERATOR_AUTHORIZATION',
              's05-mismatch': 'OPERATOR_AUTHORIZATION', 's06-rollback-fault': 'OPERATOR_AUTHORIZATION',
              's07-interrupted': 'OPERATOR_AUTHORIZATION', 's08-identity': 'NONE', 's09-missing': 'NONE',
              's09-substituted': 'NONE', 's10-first': 'OPERATOR_AUTHORIZATION', 's10-repeat': 'NONE'}
# Target setup before recover(): NONE (untouched fresh profile), REQUESTED (native restore of the
# requested parts) or REQUESTED_THEN_UI (that restore, then the supported-UI setup value), so every
# preserved before-state that a rollback restores is a non-empty export of a restored state.
SETUP = {'NOOP_MATCH': 'REQUESTED', 'SYNTHETIC_RESET_COMPLETED': 'NONE',
         'OPERATOR_AUTH_COMPLETED': 'REQUESTED_THEN_UI', 'CONCURRENT_CHANGE': 'REQUESTED_THEN_UI',
         'POST_APPLY_MISMATCH_ROLLBACK': 'REQUESTED_THEN_UI', 'ROLLBACK_FAILURE': 'REQUESTED_THEN_UI',
         'INTERRUPTED_ROLLBACK_RESUME': 'REQUESTED_THEN_UI', 'TARGET_IDENTITY_REFUSAL': 'NONE',
         'REQUESTED_PART_REFUSAL': 'NONE', 'IDEMPOTENT_REPEAT': 'REQUESTED_THEN_UI'}
# Declared qualification faults per scenario; injections must match exactly (kinds, in order).
FAULTS = {'NOOP_MATCH': (), 'SYNTHETIC_RESET_COMPLETED': (), 'OPERATOR_AUTH_COMPLETED': (),
          'CONCURRENT_CHANGE': ('CONCURRENT_UI_CHANGE',), 'POST_APPLY_MISMATCH_ROLLBACK': ('POST_APPLY_UI_CHANGE',),
          'ROLLBACK_FAILURE': ('POST_APPLY_UI_CHANGE', 'ROLLBACK_FAULT_BEFORE_NATIVE'),
          'INTERRUPTED_ROLLBACK_RESUME': ('POST_APPLY_UI_CHANGE', 'INTERRUPT_AFTER_NATIVE_ROLLBACK'),
          'TARGET_IDENTITY_REFUSAL': ('FORGED_TARGET_TOKEN',),
          'REQUESTED_PART_REFUSAL': ('REQUESTED_PART_OMITTED', 'REQUESTED_PART_SUBSTITUTED'),
          'IDEMPOTENT_REPEAT': ()}
COMPLETED_HISTORY = (('PREPARED', None), ('STAGED', None), ('PRESERVED', None), ('APPLYING', None),
                     ('COMPLETED', None))
MISMATCH_PREFIX = COMPLETED_HISTORY[:4] + (('ROLLBACK_REQUIRED', 'VERIFICATION_MISMATCH'),)
HISTORIES = {
    'SYNTHETIC_RESET_COMPLETED': COMPLETED_HISTORY,
    'OPERATOR_AUTH_COMPLETED': COMPLETED_HISTORY,
    'CONCURRENT_CHANGE': COMPLETED_HISTORY[:3] + (('FAILED_BEFORE_MUTATION', 'CONCURRENT_CHANGE'),),
    'POST_APPLY_MISMATCH_ROLLBACK': MISMATCH_PREFIX + (('ROLLED_BACK', None),),
    'ROLLBACK_FAILURE': MISMATCH_PREFIX + (('ROLLBACK_FAILED', 'ROLLBACK_APPLY_FAILED'),),
    'INTERRUPTED_ROLLBACK_RESUME': MISMATCH_PREFIX + (('ROLLED_BACK', None),),
    'IDEMPOTENT_REPEAT': COMPLETED_HISTORY}


def history(outcome):
    journal = outcome.journal
    return [] if journal is None else [[e['status'], e['failure_code']] for e in journal['history']]


def observed(journal):
    """Per history entry: whether its observed fingerprint was the before, the requested, another
    real fingerprint, or none (a failed observation). Distinguishes a real change from a fault."""
    if journal is None:
        return []
    return [relation(e['observed_fingerprint'], journal['before_fingerprint'], journal['requested_fingerprint'])
            for e in journal['history']]


def journal_on_disk(state_root, journal_id):
    """The persisted journal through the library's own confined reader, or None when absent."""
    try:
        raw = gr._read_confined(state_root, gr.journal_relpath(journal_id), gr._JOURNAL_CODES, gr.MAX_JOURNAL_BYTES)
    except gr.RecoveryError as error:
        if error.code == 'JOURNAL_MISSING':
            return None
        raise
    return ds.parse_journal(raw)


def journal_dirs(state_root):
    recovery = Path(state_root) / gr.RECOVERY_PREFIX
    return sorted(os.listdir(recovery)) if recovery.is_dir() else []


class Target:
    """Caller context for one target attempt: the state-root claim, tokens and the library calls."""

    def __init__(self, driver, plan, record, adapter):
        self.driver, self.plan, self.record, self.adapter = driver, plan, record, adapter
        self.tokens = {t['journal_id']: t for t in plan['tokens']}
        self.calls = record.setdefault('calls', [])
        self.claims = {}

    def deltas(self, before):
        return {k: self.adapter.counters[k] - before[k] for k in COUNTERS}

    def state_root(self, suffix=STATE_ROOT_SUFFIX):
        root = create_state_root(self.plan['attempt'], suffix)
        self.claims[str(root)] = StateRootClaim.acquire(root, self.plan['scenario'], self.plan['attempt_name'])
        return root

    def requested(self, state_root, target):
        """Capture the source's closed requested export beneath the state root (library capture)."""
        parts = self.plan['_inputs']['requested']
        export = gr.verify_export({'labels': dict(ds.PROJECTED_LABELS), 'part_count': len(parts),
                                   'parts': list(parts)}, target)
        stored = gr.capture_export(state_root, export)
        return stored

    def recover(self, state_root, journal_id, target, requested_sha256, *, authorization=None,
                reset_evidence=None, policy=None):
        """Held state-root claim -> consume the single-use caller token -> library recover()."""
        self.claims[str(state_root)].verify()
        token = self.tokens[journal_id]
        bound = (digest_record(authorization) if authorization is not None
                 else digest_record(reset_evidence) if reset_evidence is not None else None)
        before = dict(self.adapter.counters)
        call = {'call': 'recover', 'journal_id': journal_id, 'token': 'ISSUED'}
        self.calls.append(call)
        try:
            consume_token(token, self.plan['scenario'], self.plan['global_claim_sha256'], token['kind'], bound)
        except VerificationError as error:
            call.update(token='REUSE_REFUSED' if code_of(error) == 'CALLER_TOKEN_REUSED' else 'INVALID',
                        refusal=code_of(error), deltas=self.deltas(before))
            return None
        call['token'] = 'CONSUMED'
        try:
            outcome = gr.recover(state_root, journal_id, target, requested_sha256, self.adapter,
                                 authorization=authorization, reset_evidence=reset_evidence,
                                 qualification_policy=policy)
        except gr.RecoveryError as error:
            call.update(refusal=error.code, deltas=self.deltas(before), journal_present=journal_on_disk(
                state_root, journal_id) is not None)
            return None
        except QualificationInterrupt:
            persisted = journal_on_disk(state_root, journal_id)
            call.update(interrupted=True, deltas=self.deltas(before), observed=observed(persisted),
                        persisted=(persisted or {}).get('status'))
            raise
        call.update(status=outcome.status, failure_code=outcome.failure_code, history=history(outcome),
                    observed=observed(outcome.journal), deltas=self.deltas(before))
        return outcome

    def resume(self, state_root, journal_id, target):
        """Held state-root claim and a journal created under a consumed token -> library resume()."""
        self.claims[str(state_root)].verify()
        require(token_consumed(self.tokens[journal_id]), 'Recovery resume without consumed token')
        before = dict(self.adapter.counters)
        outcome = gr.resume(state_root, journal_id, target, self.adapter)
        self.calls.append({'call': 'resume', 'journal_id': journal_id, 'status': outcome.status,
                           'failure_code': outcome.failure_code, 'history': history(outcome),
                           'observed': observed(outcome.journal), 'deltas': self.deltas(before)})
        return outcome

    def observe(self, target):
        """Caller pre-observation (outside recover): the part-verified current fingerprint and the
        digest of its closure facts. Counted separately as the 'pre' phase."""
        proof = self.driver.closed_export()
        current = gr.verify_export(export_from_proof(proof, self.driver.labels()), target)
        return current, digest_record(proof.facts)


def relation(value, before, requested):
    return ('REQUESTED' if value == requested else 'BEFORE' if value == before
            else 'NONE' if value is None else 'OTHER')


def setup_target(target_ctx, scenario):
    """QUALIFICATION_TARGET_SETUP: never a recovery apply and never counted as one."""
    driver, kind = target_ctx.driver, SETUP[scenario]
    steps = []
    if kind in ('REQUESTED', 'REQUESTED_THEN_UI'):
        ok, _ = driver.native_restore(list(target_ctx.plan['_inputs']['requested']), 'setup')
        require(ok, 'Recovery target setup not completed')
        steps.append('NATIVE_RESTORE_REQUESTED')
    if kind == 'REQUESTED_THEN_UI':
        driver.set_ui_pref(QUAL_UI_VALUES['setup'])
        steps.append('UI_SETUP_VALUE')
    target_ctx.record['setup'] = {'label': QUALIFICATION_TARGET_SETUP, 'kind': kind, 'steps': steps}


def operator_authorization(target, requested, current):
    return {'schema': gr.AUTHORIZATION_SCHEMA, 'labels': target.labels, 'profile_token': target.profile_token,
            'storage_token': target.storage_token, 'requested_manifest_sha256': requested.manifest_sha256,
            'requested_fingerprint': requested.fingerprint, 'before_fingerprint': current.fingerprint}


def fault_hooks(scenario, driver, state_root, journal_id):
    """Adapter-seam qualification faults. Each records QUALIFICATION_FAULT_INJECTION when it fires."""
    hooks = {}
    if scenario == 'CONCURRENT_CHANGE':
        fired = []

        def concurrent(adapter):
            # Sole trigger: the persisted journal is PRESERVED (step 9 live re-check), once.
            journal = journal_on_disk(state_root, journal_id)
            if not fired and journal is not None and journal['status'] == ds.PRESERVED:
                fired.append(True)
                driver.set_ui_pref(QUAL_UI_VALUES['injection'])
                adapter.inject('CONCURRENT_UI_CHANGE', 'ADAPTER_IDENTITY')
        hooks['identity'] = concurrent
    if scenario in ('POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME'):
        def mismatch(adapter):
            # After the real native apply and reload, before the library's verification.
            driver.set_ui_pref(QUAL_UI_VALUES['injection'])
            adapter.inject('POST_APPLY_UI_CHANGE', 'ADAPTER_AFTER_APPLY')
        hooks['after_apply'] = mismatch
    if scenario == 'ROLLBACK_FAILURE':
        def refuse(adapter):
            adapter.inject('ROLLBACK_FAULT_BEFORE_NATIVE', 'ADAPTER_BEFORE_ROLLBACK')
            raise QualificationRollbackFault()
        hooks['before_rollback'] = refuse
    if scenario == 'INTERRUPTED_ROLLBACK_RESUME':
        def interrupt(adapter):
            adapter.inject('INTERRUPT_AFTER_NATIVE_ROLLBACK', 'ADAPTER_AFTER_ROLLBACK')
            raise QualificationInterrupt()
        hooks['after_rollback'] = interrupt
    return hooks


def run_target(driver, plan, record):
    """One target scenario in this attempt's owned profile. Expected refusals are observations."""
    scenario = plan['scenario']
    require(scenario in SCENARIOS, 'Recovery scenario refused')
    labels = driver.labels()
    identity = driver.identity()
    target = gr.bind_target(identity)
    require(gr.label_gate(target) is None, 'Recovery target labels unproven')
    journals = JOURNALS[scenario]
    staging = StagingReplay(plan) if scenario in STAGED_SCENARIOS else None
    adapter = FirefoxRecoveryAdapter(driver, staging)
    ctx = Target(driver, plan, record, adapter)
    record.update(scenario=scenario, labels_proven=labels == ds.PROJECTED_LABELS)
    if scenario == 'REQUESTED_PART_REFUSAL':
        return requested_part_refusal(ctx, target)
    state_root = ctx.state_root()
    requested = ctx.requested(state_root, target)
    record['requested_fingerprint'] = requested.fingerprint
    record['requested_manifest_sha256'] = requested.manifest_sha256
    setup_target(ctx, scenario)
    adapter.hooks = fault_hooks(scenario, driver, state_root, journals[0])
    pre = dict(adapter.counters)
    current, observation_sha256 = ctx.observe(target)
    record['before_fingerprint'] = current.fingerprint
    record['before_relation'] = relation(current.fingerprint, None, requested.fingerprint)
    kind = TOKEN_KIND[journals[0]]
    authorization = evidence = policy = None
    if kind == 'OPERATOR_AUTHORIZATION':
        authorization = operator_authorization(target, requested, current)
    elif kind == 'QUALIFICATION_SYNTHETIC_RESET':
        reset = plan['_inputs']['reset']
        reset_fingerprint = gr.verify_export({'labels': dict(ds.PROJECTED_LABELS), 'part_count': len(reset),
                                              'parts': list(reset)}, target).fingerprint
        record['reset_fingerprint_relation'] = 'EQUAL' if reset_fingerprint == current.fingerprint else 'DIFFERENT'
        policy = gr.qualification_reset_policy(target.labels, reset_fingerprint)
        evidence = {'schema': gr.RESET_EVIDENCE_SCHEMA, 'kind': gr.QUALIFICATION_SYNTHETIC_RESET,
                    'labels': target.labels, 'profile_token': target.profile_token,
                    'storage_token': target.storage_token, 'observed_fingerprint': current.fingerprint,
                    'observation_sha256': observation_sha256}
    record['pre_observation'] = ctx.deltas(pre)
    recover_target = target
    if scenario == 'TARGET_IDENTITY_REFUSAL':
        adapter.inject('FORGED_TARGET_TOKEN', 'CALLER_TARGET_BINDING')
        forged = dict(identity, profile_token=hashlib.sha256(b'bux5b1-qual-forged-v1\0'
                                                             + plan['plan_nonce'].encode()).hexdigest())
        recover_target = gr.bind_target(forged)
    if scenario == 'INTERRUPTED_ROLLBACK_RESUME':
        outcome = interrupted_resume(ctx, state_root, target, journals[0], authorization, requested)
    else:
        outcome = ctx.recover(state_root, journals[0], recover_target, requested.manifest_sha256,
                              authorization=authorization, reset_evidence=evidence, policy=policy)
    if scenario == 'OPERATOR_AUTH_COMPLETED':
        # The same caller token again: refused before recover(), adapter untouched.
        ctx.recover(state_root, journals[0], target, requested.manifest_sha256, authorization=authorization)
    if scenario == 'IDEMPOTENT_REPEAT':
        ctx.recover(state_root, journals[1], target, requested.manifest_sha256)
        ctx.resume(state_root, journals[0], target)
    record['outcome'] = None if outcome is None else outcome.status
    finish_target(ctx, state_root, target, requested, current, journals, scenario)


def interrupted_resume(ctx, state_root, target, journal_id, authorization, requested):
    """INTERRUPTED_ROLLBACK_RESUME driver: recover() is interrupted after the native rollback (the
    write-ahead boundary: ROLLBACK_REQUIRED was persisted before rollback() was invoked); the caller
    catches only QualificationInterrupt, sees ROLLBACK_REQUIRED persisted and resumes under the same
    held state-root claim. resume() never re-invokes apply or rollback."""
    try:
        ctx.recover(state_root, journal_id, target, requested.manifest_sha256, authorization=authorization)
    except QualificationInterrupt:
        persisted = journal_on_disk(state_root, journal_id)
        ctx.record['interrupted_at'] = None if persisted is None else persisted['status']
        ctx.adapter.hooks = {}
        return ctx.resume(state_root, journal_id, target)
    ctx.record['interrupted_at'] = 'NOT_INTERRUPTED'
    return None


def requested_part_refusal(ctx, target):
    """Two state roots, each with its own claim: the requested part omitted, and a genuine,
    unmodified same-root native part (the source's reset export) stored under the requested
    part's content address. No byte is rewritten. Each refuses before any export or mutation."""
    plan, record, adapter = ctx.plan, ctx.record, ctx.adapter
    labels = dict(ds.PROJECTED_LABELS)
    requested_parts, reset_parts = plan['_inputs']['requested'], plan['_inputs']['reset']
    manifest = ds.build_manifest(list(requested_parts), labels)
    raw = ds.serialize_manifest(manifest)
    digest = ds.sha256_hex(raw)
    results = {}
    for journal_id, key, kind in (('s09-missing', 'missing', 'REQUESTED_PART_OMITTED'),
                                  ('s09-substituted', 'substituted', 'REQUESTED_PART_SUBSTITUTED')):
        suffix = '-state-' + key
        state_root = ctx.state_root(suffix)
        ds.atomic_write(state_root, gr.stored_manifest_relpath(digest), raw)
        adapter.inject(kind, 'CALLER_STATE_ROOT')
        for number, (record_part, part) in enumerate(zip(manifest['native_artifacts'], requested_parts)):
            if kind == 'REQUESTED_PART_OMITTED' and number == 0:
                continue
            stored = part if not (kind == 'REQUESTED_PART_SUBSTITUTED' and number == 0) else reset_parts[0]
            ds.atomic_write(state_root, gr.native_part_relpath(record_part['sha256']), stored)
        ctx.recover(state_root, journal_id, target, digest)
        results[key] = {'journal_dirs': len(journal_dirs(state_root))}
    record['roots'] = results
    record['requested_manifest_sha256'] = digest
    record['outcome'] = None
    check_expectation(ctx, 'REQUESTED_PART_REFUSAL', {})


def finish_target(ctx, state_root, target, requested, current, journals, scenario):
    record, adapter = ctx.record, ctx.adapter
    final = {}
    journal = journal_on_disk(state_root, journals[0])
    if journal is not None:
        final['basis'] = journal['authorization']['basis']
        try:
            stored = ds.parse_canonical(gr._read_confined(
                state_root, gr.stored_manifest_relpath(journal['authorization']['evidence_sha256']),
                gr._MANIFEST_CODES, gr.MAX_MANIFEST_BYTES))
            final['stored_evidence_kind'] = stored.get('kind') if 'kind' in stored else stored.get('schema')
        except (gr.RecoveryError, ds.DurableStateError, AttributeError):
            final['stored_evidence_kind'] = None
    if scenario in ('ROLLBACK_FAILURE',):
        journal = journal_on_disk(state_root, journals[0])
        displaced = (journal or {}).get('displaced_state') or {}
        try:
            preserved = gr.load_verified(state_root, displaced.get('sha256'))
            final['preserved_verifiable'] = preserved.fingerprint == journal['before_fingerprint']
        except (gr.RecoveryError, TypeError):
            final['preserved_verifiable'] = False
    if scenario in ('POST_APPLY_MISMATCH_ROLLBACK', 'INTERRUPTED_ROLLBACK_RESUME'):
        journal = journal_on_disk(state_root, journals[0])
        displaced = (journal or {}).get('displaced_state') or {}
        try:
            preserved = gr.load_verified(state_root, displaced.get('sha256'))
            final['rollback_from_preserved'] = (adapter.rollback_inputs == [list(preserved.part_digests)])
        except (gr.RecoveryError, TypeError):
            final['rollback_from_preserved'] = False
    record['journal_dirs'] = len(journal_dirs(state_root))
    record['final'] = final
    record['counters'] = dict(adapter.counters)
    check_expectation(ctx, scenario, final)


def _call(calls, kind, journal_id, index=0):
    found = [c for c in calls if c['call'] == kind and c['journal_id'] == journal_id]
    return found[index] if len(found) > index else {}


def expectation(scenario, record, injections, final):
    """(matched, reasons) for one target scenario from the recorded calls; reasons are fixed tokens."""
    calls, reasons = record.get('calls') or [], []
    def need(condition, reason):
        if not condition:
            reasons.append(reason)
    zero = dict.fromkeys(('stage', 'apply', 'rollback', 'native_apply', 'native_rollback'), 0)
    def counts(call, **expected):
        deltas = call.get('deltas') or {}
        return all(deltas.get(k) == v for k, v in {**zero, **expected}.items())
    need([i['kind'] for i in injections] == list(FAULTS[scenario])
         and all(i['label'] == QUALIFICATION_FAULT_INJECTION for i in injections), 'FAULT_LABELS')
    journals = JOURNALS[scenario]
    first = _call(calls, 'recover', journals[0])
    if scenario == 'NOOP_MATCH':
        need(first.get('status') == 'NOOP' and counts(first) and record.get('journal_dirs') == 0, 'NOOP')
    elif scenario in ('SYNTHETIC_RESET_COMPLETED', 'OPERATOR_AUTH_COMPLETED', 'IDEMPOTENT_REPEAT'):
        need(first.get('history') == [list(e) for e in HISTORIES[scenario]]
             and counts(first, stage=1, apply=1, native_apply=1), 'COMPLETED')
    if scenario == 'SYNTHETIC_RESET_COMPLETED':
        need(final.get('basis') == 'POSITIVE_VERSIONED_RESET_EVIDENCE'
             and final.get('stored_evidence_kind') == gr.QUALIFICATION_SYNTHETIC_RESET, 'SYNTHETIC_EVIDENCE')
    if scenario in ('OPERATOR_AUTH_COMPLETED', 'CONCURRENT_CHANGE', 'POST_APPLY_MISMATCH_ROLLBACK',
                    'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME', 'IDEMPOTENT_REPEAT'):
        need(final.get('basis') == 'OPERATOR_EXPLICIT'
             and final.get('stored_evidence_kind') == gr.AUTHORIZATION_SCHEMA, 'OPERATOR_BASIS')
    if scenario == 'OPERATOR_AUTH_COMPLETED':
        again = _call(calls, 'recover', journals[0], 1)
        need(again.get('refusal') == 'CALLER_TOKEN_REUSED' and again.get('token') == 'REUSE_REFUSED'
             and all(v == 0 for v in (again.get('deltas') or {'x': 1}).values()), 'TOKEN_REUSE')
    if scenario == 'CONCURRENT_CHANGE':
        # The re-check saw a real, different fingerprint (not a failed observation).
        need(first.get('history') == [list(e) for e in HISTORIES[scenario]] and counts(first, stage=1)
             and (first.get('observed') or [None])[-1] == 'OTHER', 'CONCURRENT')
    if scenario in ('POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME'):
        # The verification mismatch was a real, different fingerprint (not a failed observation).
        need(len(first.get('observed') or []) >= 5 and first['observed'][4] == 'OTHER', 'REAL_MISMATCH')
    if scenario == 'POST_APPLY_MISMATCH_ROLLBACK':
        need(first.get('history') == [list(e) for e in HISTORIES[scenario]]
             and counts(first, stage=1, apply=1, native_apply=1, rollback=1, native_rollback=1)
             and final.get('rollback_from_preserved') is True, 'ROLLED_BACK')
    if scenario == 'ROLLBACK_FAILURE':
        need(first.get('history') == [list(e) for e in HISTORIES[scenario]]
             and counts(first, stage=1, apply=1, native_apply=1, rollback=1)
             and final.get('preserved_verifiable') is True, 'ROLLBACK_FAILED')
    if scenario == 'INTERRUPTED_ROLLBACK_RESUME':
        resumed = _call(calls, 'resume', journals[0])
        need(first.get('interrupted') is True and first.get('persisted') == 'ROLLBACK_REQUIRED'
             and counts(first, stage=1, apply=1, native_apply=1, rollback=1, native_rollback=1)
             and resumed.get('history') == [list(e) for e in HISTORIES[scenario]] and counts(resumed)
             and final.get('rollback_from_preserved') is True, 'RESUMED')
    if scenario == 'TARGET_IDENTITY_REFUSAL':
        need(first.get('refusal') == 'TARGET_IDENTITY_MISMATCH' and first.get('journal_present') is False
             and counts(first) and (first.get('deltas') or {}).get('identity') == 1
             and (first.get('deltas') or {}).get('export') == 0 and record.get('journal_dirs') == 0, 'IDENTITY')
    if scenario == 'REQUESTED_PART_REFUSAL':
        missing, substituted = _call(calls, 'recover', 's09-missing'), _call(calls, 'recover', 's09-substituted')
        need(missing.get('refusal') == 'NATIVE_PART_MISSING'
             and substituted.get('refusal') in ('NATIVE_PART_SIZE_MISMATCH', 'NATIVE_PART_DIGEST_MISMATCH')
             and all(counts(c) and (c.get('deltas') or {}).get('identity') == 1
                     and (c.get('deltas') or {}).get('export') == 0 and c.get('journal_present') is False
                     for c in (missing, substituted))
             and all(v.get('journal_dirs') == 0 for v in (record.get('roots') or {}).values()), 'PART_REFUSAL')
    if scenario == 'IDEMPOTENT_REPEAT':
        repeat, resumed = _call(calls, 'recover', journals[1]), _call(calls, 'resume', journals[0])
        need(repeat.get('status') == 'NOOP' and counts(repeat)
             and resumed.get('status') == 'COMPLETED' and resumed.get('history') == first.get('history')
             and all(v == 0 for v in (resumed.get('deltas') or {'x': 1}).values())
             and record.get('counters', {}).get('native_apply') == 1, 'IDEMPOTENT')
    return not reasons, reasons


def check_expectation(ctx, scenario, final):
    matched, reasons = expectation(scenario, ctx.record, ctx.adapter.injections, final)
    ctx.record.update(injections=list(ctx.adapter.injections), adapter_codes=list(ctx.adapter.codes[-16:]),
                      counters=dict(ctx.adapter.counters), expectation='MATCHED' if matched else 'MISMATCHED',
                      expectation_reasons=reasons)
    for claim in ctx.claims.values():
        claim.verify()
    ctx.record['state_root_claims'] = {'held_to_end': True, 'count': len(ctx.claims), 'deleted': False}


def run_source(driver, plan, record):
    """Reset export of the untouched fresh profile, the accepted R6 sentinel seed through the native
    UI, then the requested export. Both exports must close and project."""
    labels = driver.labels()
    identity = driver.identity()
    gr.bind_target(identity)
    exports = {}
    proof = driver.closed_export()
    exports['reset'] = {'label': driver.last_label, **proof.facts}
    driver.seed_sentinel()
    proof = driver.closed_export()
    exports['requested'] = {'label': driver.last_label, **proof.facts}
    record.update(exports=exports, requested_manifest_sha256=manifest_digest(proof.parts, labels))


def run_staging(driver, plan, record):
    """Native restore of the requested parts into this fresh profile, reload, closed export; then the
    exclusive, scenario-bound staging record the target's stage() replays exactly once."""
    labels = driver.labels()
    identity = driver.identity()
    requested = list(plan['_inputs']['requested'])
    ok, _ = driver.native_restore(requested, 'stage')
    require(ok, 'Recovery native apply not completed')
    proof = driver.closed_export()
    staged = {'label': driver.last_label, **proof.facts}
    staging = {'schema': STAGING_SCHEMA, 'scenario': plan['scenario'], 'claim_root_name': Path(plan['claim_root']).name,
               'plan_nonce': plan['plan_nonce'], 'attempt_name': plan['attempt_name'],
               'requested_part_sha256': [hashlib.sha256(p).hexdigest() for p in requested],
               'requested_manifest_sha256': manifest_digest(requested, labels), 'staged_label': driver.last_label,
               'staged_part_sha256': proof.facts['part_sha256'], 'staged_closure': proof.facts,
               'identity': identity, 'profile_identity': list(driver.profile_identity()),
               'disposability': plan.get('_freshness') or {}, 'extension_set_proven': True,
               'native_restore_completed': True}
    write_staging_record(plan['claim_root'], staging)
    record.update(staged=staged, staging_record='WRITTEN',
                  staged_equals_requested_manifest=manifest_digest(proof.parts, labels)
                  == staging['requested_manifest_sha256'])


ROLE_DRIVERS = {'source': run_source, 'staging': run_staging, 'target': run_target}


def exercise(client, run, result, plan, provenance=None, clock=time.monotonic):
    """One role in the owned session. Raises on any unclassified failure; partial facts stay."""
    provenance = provenance or matrix.load_provenance()
    driver = RecoverySession(client, run, result, provenance, plan, clock)
    plan['_freshness'] = result.get('recovery_freshness')
    record = result.setdefault('recovery', {})
    record.update(role=plan['role'], scenario=plan['scenario'], completed=False,
                  scope='DISPOSABLE_QUALIFICATION_NOT_LIVE_DATA_SAFETY')
    driver.step('open_settings', lambda: session_module.open_settings(driver))
    driver.step('extension_set', driver.prove_extension_set)
    def role():
        try:
            return ROLE_DRIVERS[plan['role']](driver, plan, record)
        except QualificationInterrupt:
            # Only interrupted_resume may observe the qualification interrupt; one escaping anywhere
            # else is a classified role failure, never an operator interrupt of the preflight.
            raise VerificationError('Recovery scenario refused') from None
    driver.step('role', role)
    record['completed'] = True
    matrix.project(record)
    result['recovery_completed'] = True
    return driver


# --- Privacy-safe projection ------------------------------------------------------------------------

def projected_attempt(result):
    """Fixed-key review projection of one attempt result.json. Never paths, PIDs, text or bytes."""
    result = result if isinstance(result, dict) else {}
    settlement = result.get('settlement') if isinstance(result.get('settlement'), dict) else {}
    preflight = result.get('preflight') if isinstance(result.get('preflight'), dict) else {}
    def failure(value):
        return ({k: value[k] for k in ('stage', 'type', 'code') if isinstance(value.get(k), str)}
                if isinstance(value, dict) else None)
    def contained(value):
        try:
            return matrix.project(value)
        except VerificationError:
            return {'projection': 'REFUSED'}
    session = result.get('recovery_session') if isinstance(result.get('recovery_session'), dict) else {}
    summary = {'status': result.get('status'), 'role': result.get('recovery_role'),
               'scenario': result.get('recovery_scenario'), 'browser_version': result.get('browser_version'),
               'captured_code_loaded': result.get('captured_code_loaded'),
               'runtime_unchanged': result.get('runtime_unchanged'),
               'policy_template_sha256': preflight.get('policy_template_sha256'),
               'settlement': {k: settlement.get(k) for k in ('exit_code', 'zero_survivors', 'unsettled',
                                                              'workload_status', 'observed_escapes')},
               **{k: failure(result.get(k)) for k in ('primary_failure', 'cleanup_failure', 'runtime_failure',
                                                      'evidence_io_failure')},
               'freshness': contained(result.get('recovery_freshness')),
               'steps': [{k: s.get(k) for k in ('step', 'status', 'error_type')}
                         for s in session.get('steps') or [] if isinstance(s, dict)],
               'exports': contained(session.get('exports')),
               'restores': contained([{k: r.get(k) for k in ('completion', 'restore_error', 'start_observed',
                                                             'transition_end_observed', 'selected_files')}
                                      for r in session.get('restores') or [] if isinstance(r, dict)]),
               'recovery': contained(result.get('recovery'))}
    try:
        return matrix.project(summary)
    except VerificationError:
        return {'status': result.get('status'), 'projection': 'REFUSED'}
