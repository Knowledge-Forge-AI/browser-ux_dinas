"""Clear New Tab durable-state foundation (BUX5B0C). Library only; not a command.

Pure validation, canonical serialization and fingerprinting for Browser UX CNT
state, plus confined reads and atomic writes beneath caller-supplied roots.
Nothing here launches a browser, reads a profile, imports/exports native data,
performs recovery or rollback, or resolves or creates the operator state root.

Every refusal is DurableStateError(code) whose text is the fixed code alone, so
no path, native byte or raw OS error text can leak through an error. Checks are
explicit raises and behave identically under python -O.

Projection is version-bound: only the exact Firefox CNT 6.12.1 on Firefox
156.0.1 label set is projected, from the accepted R6 characterization. Every
other label set (all Chrome labels included) is NATIVE_ONLY_UNCHARACTERIZED and
bound only by raw native-artifact digests. No cross-engine claim is made.
"""
from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
from pathlib import PurePath, PurePosixPath
import re
import secrets
import stat

MANIFEST_SCHEMA = 'browser-ux-cnt-manifest-v1'
FINGERPRINT_SCHEMA = 'browser-ux-cnt-fingerprint-v1'
JOURNAL_SCHEMA = 'browser-ux-cnt-recovery-journal-v1'
CANONICAL_ROOT_SUFFIX = ('.local', 'state', 'browser-ux', 'clear-new-tab')
PRIVATE_CONTENT_PREFIX = ('content', 'sha256')

REFUSAL_CODES = (
    'CANONICAL_UNSUPPORTED_TYPE', 'NOT_CANONICAL', 'UNPARSEABLE',
    'HOME_INVALID', 'DIGEST_MALFORMED', 'LABELS_INVALID', 'ARTIFACTS_INVALID',
    'ARTIFACT_MISMATCH', 'MANIFEST_INVALID', 'PROJECTION_INVALID', 'PROJECTION_MISMATCH',
    'OCCURRENCE_INVALID', 'OCCURRENCE_IDENTITY_DUPLICATE', 'OCCURRENCE_PROJECTION_MISMATCH',
    'RANK_MALFORMED', 'CONTENT_REF_INVALID', 'ROOT_REQUIRED',
    'REF_ABSOLUTE', 'REF_TRAVERSAL', 'REF_NOT_NORMALIZED', 'REF_TOO_LONG', 'REF_SYMLINK',
    'ROOT_INVALID', 'CONTENT_MISSING', 'CONTENT_DIGEST_MISMATCH',
    'JOURNAL_INVALID', 'JOURNAL_TRANSITION_INVALID', 'JOURNAL_PRECONDITION_FAILED',
    'JOURNAL_TERMINAL', 'WRITE_TARGET_INVALID', 'WRITE_FAILED',
)


class DurableStateError(ValueError):
    """Bounded refusal. str(error) is exactly one REFUSAL_CODES member."""

    def __init__(self, code):
        if code not in REFUSAL_CODES:
            code = 'MANIFEST_INVALID'
        super().__init__(code)
        self.code = code


def _require(condition, code):
    if not condition:
        raise DurableStateError(code)


# --- Canonical serialization -----------------------------------------------------------------

class NativeNumber:
    """A non-integer native JSON number kept as its exact source token.

    1 (int) and 1.0 (token) are deliberately unequal; native JS never emits 1.0.
    """
    __slots__ = ('token',)

    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return isinstance(other, NativeNumber) and other.token == self.token

    def __hash__(self):
        return hash(('NativeNumber', self.token))


def _encode(value, out, native):
    # bool before int: True must never encode as 1.
    if value is None:
        out.append('null')
    elif value is True:
        out.append('true')
    elif value is False:
        out.append('false')
    elif type(value) is int:
        try:
            out.append(str(value))
        except ValueError:  # beyond the interpreter's integer string-conversion limit
            raise DurableStateError('CANONICAL_UNSUPPORTED_TYPE') from None
    elif type(value) is str:
        out.append(json.dumps(value, ensure_ascii=True))
    elif native and type(value) is NativeNumber:
        out.append(value.token)
    elif type(value) is list:
        out.append('[')
        for index, item in enumerate(value):
            if index:
                out.append(',')
            _encode(item, out, native)
        out.append(']')
    elif type(value) is dict:
        _require(all(type(key) is str for key in value), 'CANONICAL_UNSUPPORTED_TYPE')
        out.append('{')
        for index, key in enumerate(sorted(value)):
            if index:
                out.append(',')
            out.append(json.dumps(key, ensure_ascii=True))
            out.append(':')
            _encode(value[key], out, native)
        out.append('}')
    else:
        raise DurableStateError('CANONICAL_UNSUPPORTED_TYPE')


def canonical_bytes(value):
    """Sorted keys (code point), ASCII escapes, no whitespace. No floats, no repr."""
    out = []
    _encode(value, out, False)
    return ''.join(out).encode('ascii')


def _native_canonical(value):
    out = []
    _encode(value, out, True)
    return ''.join(out).encode('ascii')


def _refuse_constant(_token):
    raise ValueError('constant')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def _strict_loads(raw, parse_float):
    _require(isinstance(raw, (bytes, bytearray)), 'UNPARSEABLE')
    try:
        return json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_float=parse_float, parse_constant=_refuse_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise DurableStateError('UNPARSEABLE') from None


def _refuse_float(_token):
    raise ValueError('float')


def parse_canonical(raw):
    """Parse bytes that must already be exactly canonical (manifests, journals)."""
    value = _strict_loads(raw, _refuse_float)
    _require(canonical_bytes(value) == bytes(raw), 'NOT_CANONICAL')
    return value


def _parse_native(raw):
    """Native JSON: duplicate keys and NaN/Infinity refused, number tokens kept exact."""
    value = _strict_loads(raw, NativeNumber)
    try:
        _native_canonical(value)
    except RecursionError:
        raise DurableStateError('UNPARSEABLE') from None
    return value


# --- Digests, labels and roots ---------------------------------------------------------------

HEX64 = re.compile(r'[0-9a-f]{64}')
VERSION = re.compile(r'[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}')
EXTENSION_IDS = {'firefox': 'clear-new-tab@loftyshaky', 'chrome': 'felphkbfjadmcejnibcmcncimlappdde'}
LABEL_KEYS = ('engine', 'extension_id', 'extension_version', 'browser_version')
# The one accepted characterization (R6 A-F, FIREFOX_6_12_1_A_TO_F_NATIVE_CHARACTERIZATION_ACCEPTED).
PROJECTED_LABELS = {'engine': 'firefox', 'extension_id': 'clear-new-tab@loftyshaky',
                    'extension_version': '6.12.1', 'browser_version': '156.0.1'}
PROJECTED = 'PROJECTED_FIREFOX_6_12_1'
NATIVE_ONLY_UNCHARACTERIZED = 'NATIVE_ONLY_UNCHARACTERIZED'
NATIVE_ONLY_UNPROJECTABLE = 'NATIVE_ONLY_UNPROJECTABLE'
PROJECTION_STATUSES = (PROJECTED, NATIVE_ONLY_UNCHARACTERIZED, NATIVE_ONLY_UNPROJECTABLE)


def sha256_hex(raw):
    return hashlib.sha256(bytes(raw)).hexdigest()


def require_digest(value):
    _require(type(value) is str and HEX64.fullmatch(value) is not None, 'DIGEST_MALFORMED')
    return value


def validate_labels(labels):
    _require(type(labels) is dict and set(labels) == set(LABEL_KEYS), 'LABELS_INVALID')
    engine = labels['engine']
    _require(type(engine) is str and engine in EXTENSION_IDS and labels['extension_id'] == EXTENSION_IDS[engine], 'LABELS_INVALID')
    _require(type(labels['extension_version']) is str
             and VERSION.fullmatch(labels['extension_version']) is not None, 'LABELS_INVALID')
    browser = labels['browser_version']
    _require(browser is None or (type(browser) is str and VERSION.fullmatch(browser) is not None),
             'LABELS_INVALID')
    return labels


def projection_supported(labels):
    return validate_labels(labels) == PROJECTED_LABELS


def canonical_root(home):
    """Pure path arithmetic for the designed operator root. Never touches the filesystem."""
    _require(isinstance(home, (str, PurePath)), 'HOME_INVALID')
    text = str(home)
    _require(text.startswith('/') and '\0' not in text and '\\' not in text, 'HOME_INVALID')
    parts = text.split('/')[1:]
    _require(text == '/' or all(p not in ('', '.', '..') for p in parts), 'HOME_INVALID')
    return PurePosixPath(text).joinpath(*CANONICAL_ROOT_SUFFIX)


# --- Native artifacts ------------------------------------------------------------------------

MAX_ARTIFACTS = 256


def native_artifact_records(parts):
    """Ordered backup-part records: index 1..n, SHA-256 and size of the exact bytes."""
    _require(type(parts) in (list, tuple) and 1 <= len(parts) <= MAX_ARTIFACTS, 'ARTIFACTS_INVALID')
    _require(all(isinstance(p, (bytes, bytearray)) for p in parts), 'ARTIFACTS_INVALID')
    return [{'role': 'backup_part', 'part_index': n, 'sha256': sha256_hex(raw), 'bytes': len(raw)}
            for n, raw in enumerate(parts, 1)]


def validate_native_artifacts(records):
    _require(type(records) is list and 1 <= len(records) <= MAX_ARTIFACTS, 'ARTIFACTS_INVALID')
    for n, record in enumerate(records, 1):
        _require(type(record) is dict and set(record) == {'bytes', 'part_index', 'role', 'sha256'},
                 'ARTIFACTS_INVALID')
        _require(record['role'] == 'backup_part' and record['part_index'] == n
                 and type(record['part_index']) is int, 'ARTIFACTS_INVALID')
        _require(type(record['bytes']) is int and record['bytes'] >= 0, 'ARTIFACTS_INVALID')
        require_digest(record['sha256'])
    return records


# --- Firefox CNT 6.12.1 projection -----------------------------------------------------------
# Field tuples equal the accepted R6 view (tests/cnt_firefox_matrix.py). KNOWN_PREFS is the
# exact 6.12.1 export preference set; other preference keys remain native-only.

VOLATILE_PREFS = ('background_change_time', 'current_background_id', 'future_background_id')
KNOWN_ROW = ('data', 'thumbnail', 'file', 'tasks')
KNOWN_DATA = ('id', 'i', 'type', 'width', 'height', 'thumbnail_width', 'thumbnail_height',
              'background_size', 'background_position', 'background_repeat',
              'color_of_area_around_background', 'video_speed', 'video_volume', 'theme_id')
KNOWN_FILE = ('name', 'type', 'last_modified', 'background')
KNOWN_TASK = ('id', 'background_id', 'year', 'month', 'day_of_the_month', 'day_of_the_week', 'time', 'i')
KNOWN_CODE = ('html', 'css', 'js')
KNOWN_TOP = ('settings', 'custom_code', 'chunks')
KNOWN_PREFS = (
    'version', 'clipboard_read_permission', 'options_page_theme', 'transition_duration',
    'color_help_is_visible', 'developer_mode', 'enable_cut_features', 'persistent_service_worker',
    'detect_infinite_loops', 'offers_are_visible', 'admin_section_content_is_visible', 'colors',
    'install_help_is_visible', 'mode', 'color_type', 'keep_old_theme_backgrounds',
    'automatically_set_last_uploaded_background_as_current', 'background_change_interval',
    'slideshow', 'background_change_effect', 'shuffle_backgrounds', 'slide_direction',
    'background_size', 'background_position', 'background_repeat',
    'color_of_area_around_background', 'video_speed', 'video_volume',
    'download_img_when_link_given', 'home_btn_is_visible', 'homepage', 'home_btn_position',
    'paste_btn_is_visible', 'year', 'day_of_the_week', 'month', 'day_of_the_month', 'time',
    'install_help_msg_is_visible', 'id_of_last_installed_theme', 'current_random_solid_color',
    'backgrounds_per_page', 'enable_video_repeat',
    'always_use_alarms_api_to_change_background_in_slideshow_mode',
    'show_item_developer_info_in_tooltip', 'update_database_when_dnd_item',
    'one_backup_file_size_in_bytes')
BOUNDED = re.compile(r'[A-Za-z0-9_.:+-]{0,64}')
NATIVE_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')
RANK = re.compile(r'-?[0-9]{1,64}(?:\.[0-9]{1,64})?')
DATA_URL = re.compile(r'data:([a-z]+/[a-z0-9.+-]+);base64,(.*)', re.S)
CONTENT_STATUSES = ('DECODED', 'UNDECODABLE', 'NOT_DATA_URL', 'NOT_STRING', 'ABSENT')
ROW_KEYS = ('native_id', 'native_rank', 'type', 'presentation', 'file', 'thumbnail', 'tasks')


class _Unprojectable(Exception):
    pass


def _shape(condition):
    if not condition:
        raise _Unprojectable()


def _value_digest(value):
    raw = _native_canonical(value)
    return ['digest', sha256_hex(raw), len(raw)]


def typed_value(value):
    """Tagged projection of a native value: bounded scalars verbatim, all else digested."""
    if value is None:
        return ['null']
    if type(value) is bool:
        return ['bool', value]
    if type(value) is int:
        return ['int', value]
    if type(value) is NativeNumber:
        return ['num', value.token]
    if type(value) is str and BOUNDED.fullmatch(value):
        return ['str', value]
    return _value_digest(value)


def _content(holder, key):
    if key not in holder:
        return {'status': 'ABSENT'}
    value = holder[key]
    if type(value) is not str:
        return {'status': 'NOT_STRING', 'sha256': _value_digest(value)[1]}
    match = DATA_URL.fullmatch(value)
    if not match:
        return {'status': 'NOT_DATA_URL', 'sha256': _value_digest(value)[1]}
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        return {'status': 'UNDECODABLE', 'media_type': match.group(1), 'sha256': _value_digest(value)[1]}
    return {'status': 'DECODED', 'media_type': match.group(1), 'sha256': sha256_hex(decoded),
            'bytes': len(decoded)}


def _optional_object(chunk, key):
    if key not in chunk:
        return None
    _shape(type(chunk[key]) is dict)
    return chunk[key]


def _row(chunk):
    _shape(type(chunk) is dict and type(chunk.get('data')) is dict)
    data = chunk['data']
    _shape(type(data.get('id')) is str and NATIVE_ID.fullmatch(data['id']) is not None)
    _shape(type(data.get('i')) is str and RANK.fullmatch(data['i']) is not None)
    file, thumb = _optional_object(chunk, 'file'), _optional_object(chunk, 'thumbnail')
    tasks = chunk.get('tasks')
    _shape(tasks is None and 'tasks' not in chunk or type(tasks) is list)
    projected_tasks = None
    if tasks is not None:
        _shape(all(type(t) is dict for t in tasks))
        projected_tasks = [{k: typed_value(t[k]) for k in KNOWN_TASK if k in t} for t in tasks]
    projected_file = None
    if file is not None:
        projected_file = {k: typed_value(file[k]) for k in ('type', 'last_modified') if k in file}
        if 'name' in file:
            projected_file['name'] = _value_digest(file['name'])
        projected_file['content'] = _content(file, 'background')
    return {'native_id': data['id'], 'native_rank': data['i'],
            'type': typed_value(data['type']) if 'type' in data else ['absent'],
            'presentation': {k: typed_value(data[k]) for k in KNOWN_DATA[3:] if k in data},
            'file': projected_file,
            'thumbnail': None if thumb is None else _content(thumb, 'background'),
            'tasks': projected_tasks}


def _firefox_parsed(parts):
    """Strict structural read of the accepted 6.12.1 backup layout, else _Unprojectable."""
    parsed = []
    for raw in parts:
        try:
            parsed.append(_parse_native(raw))
        except DurableStateError:
            raise _Unprojectable() from None
    for index, value in enumerate(parsed):
        _shape(type(value) is dict and type(value.get('chunks')) is list)
        if index == 0:
            _shape(type(value.get('settings')) is dict and type(value['settings'].get('prefs')) is dict)
            _shape(type(value.get('custom_code')) is dict)
        else:
            _shape('settings' not in value and 'custom_code' not in value)
    return parsed


def _projection_from_parsed(parsed):
    rows = [_row(chunk) for part in parsed for chunk in part['chunks']]
    ids = [r['native_id'] for r in rows]
    _shape(len(ids) == len(set(ids)))
    prefs = parsed[0]['settings']['prefs']
    code = parsed[0]['custom_code']
    return {'rows': rows,
            'settings': {k: typed_value(prefs[k]) for k in KNOWN_PREFS if k in prefs},
            'custom_code': {k: _value_digest(code[k]) for k in KNOWN_CODE if k in code}}


def _semantic_digest(parsed):
    """All parsed native content except the three accepted volatile preferences."""
    first = dict(parsed[0])
    settings = dict(first['settings'])
    settings['prefs'] = {k: v for k, v in settings['prefs'].items() if k not in VOLATILE_PREFS}
    first['settings'] = settings
    return sha256_hex(_native_canonical([first, *parsed[1:]]))


def _raw_digest(parts):
    return sha256_hex(canonical_bytes([sha256_hex(raw) for raw in parts]))


def derive_native(parts, labels):
    """(projection_status, projection, native_semantic_sha256) for an ordered part set."""
    native_artifact_records(parts)
    if not projection_supported(labels):
        return NATIVE_ONLY_UNCHARACTERIZED, None, _raw_digest(parts)
    try:
        parsed = _firefox_parsed(parts)
        projection = _projection_from_parsed(parsed)
        digest = _semantic_digest(parsed)
    except (_Unprojectable, RecursionError):
        return NATIVE_ONLY_UNPROJECTABLE, None, _raw_digest(parts)
    return PROJECTED, projection, digest


def _occurrences_from_projection(projection):
    occurrences = []
    for position, row in enumerate(projection['rows']):
        content = (row.get('file') or {}).get('content') or {}
        digest = content.get('sha256') if content.get('status') == 'DECODED' else None
        occurrences.append({'position': position, 'native_id': row['native_id'],
                            'native_rank': row['native_rank'], 'content_sha256': digest,
                            'content_ref': {'kind': 'native_only'}})
    return occurrences


# --- Content references ------------------------------------------------------------------------

MAX_REF = 4096
CONTENT_REF_KINDS = ('shared_images', 'private', 'native_only')


def _utf8(text):
    """Strict UTF-8 bytes, or None (e.g. a lone surrogate no filesystem call could encode)."""
    try:
        return text.encode('utf-8')
    except UnicodeEncodeError:
        return None


def validate_relative_ref(ref):
    _require(type(ref) is str and ref != '', 'REF_NOT_NORMALIZED')
    encoded = _utf8(ref)
    _require(encoded is not None, 'REF_NOT_NORMALIZED')
    _require(len(encoded) <= MAX_REF, 'REF_TOO_LONG')
    _require(not ref.startswith('/'), 'REF_ABSOLUTE')
    parts = ref.split('/')
    _require('..' not in parts, 'REF_TRAVERSAL')
    _require(all(p not in ('', '.') for p in parts) and '\\' not in ref
             and not any(ord(c) < 32 or ord(c) == 127 for c in ref), 'REF_NOT_NORMALIZED')
    return tuple(parts)


def private_content_relpath(digest):
    return '/'.join((*PRIVATE_CONTENT_PREFIX, require_digest(digest)))


def _open_root(root):
    _require(isinstance(root, (str, PurePath)) and str(root).startswith('/') and '\0' not in str(root)
             and _utf8(str(root)) is not None, 'ROOT_INVALID')
    try:
        return os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (OSError, ValueError):
        raise DurableStateError('ROOT_INVALID') from None


def _descend(directory, part, create):
    """Open one child directory relative to an owned FD; never follows a symlink."""
    try:
        info = os.stat(part, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        if not create:
            raise DurableStateError('CONTENT_MISSING') from None
        try:
            os.mkdir(part, 0o700, dir_fd=directory)
            _flush(directory)
            info = os.stat(part, dir_fd=directory, follow_symlinks=False)
        except OSError:
            raise DurableStateError('WRITE_FAILED') from None
    except OSError:
        raise DurableStateError('WRITE_FAILED' if create else 'CONTENT_MISSING') from None
    _require(not stat.S_ISLNK(info.st_mode), 'REF_SYMLINK')
    _require(stat.S_ISDIR(info.st_mode), 'WRITE_TARGET_INVALID' if create else 'CONTENT_MISSING')
    try:
        return os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except OSError:
        raise DurableStateError('REF_SYMLINK') from None


READ_CHUNK = 1 << 20


def _digest_confined(root, parts):
    """SHA-256 of a confined regular file, hashed in chunks (Shared Images may hold large videos).

    O_NONBLOCK keeps a FIFO swapped in after the lstat from blocking the open; fstat then
    requires the opened object to be the same regular file the lstat saw.
    """
    directory = _open_root(root)
    try:
        for part in parts[:-1]:
            child = _descend(directory, part, False)
            os.close(directory)
            directory = child
        try:
            info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        except OSError:
            raise DurableStateError('CONTENT_MISSING') from None
        _require(not stat.S_ISLNK(info.st_mode), 'REF_SYMLINK')
        _require(stat.S_ISREG(info.st_mode), 'CONTENT_MISSING')
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except OSError:
            raise DurableStateError('REF_SYMLINK') from None
        try:
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                _require(stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino)
                         == (info.st_dev, info.st_ino), 'CONTENT_MISSING')
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(READ_CHUNK), b''):
                    digest.update(chunk)
                return digest.hexdigest()
        except OSError:
            raise DurableStateError('CONTENT_MISSING') from None
    finally:
        os.close(directory)


def verify_shared_images_ref(root, ref, digest):
    """Confined read of a caller-authorized Shared Images relative ref; digest must match."""
    require_digest(digest)
    _require(_digest_confined(root, validate_relative_ref(ref)) == digest, 'CONTENT_DIGEST_MISMATCH')
    return True


def verify_private_content(root, digest):
    found = _digest_confined(root, validate_relative_ref(private_content_relpath(digest)))
    _require(found == digest, 'CONTENT_DIGEST_MISMATCH')
    return True


def validate_content_ref(ref, content_sha256):
    _require(type(ref) is dict and ref.get('kind') in CONTENT_REF_KINDS, 'CONTENT_REF_INVALID')
    kind = ref['kind']
    if kind == 'native_only':
        _require(set(ref) == {'kind'}, 'CONTENT_REF_INVALID')
    elif kind == 'shared_images':
        _require(set(ref) == {'kind', 'path'} and content_sha256 is not None, 'CONTENT_REF_INVALID')
        validate_relative_ref(ref['path'])
    else:
        _require(set(ref) == {'kind', 'sha256'} and content_sha256 is not None, 'CONTENT_REF_INVALID')
        _require(require_digest(ref['sha256']) == content_sha256, 'CONTENT_REF_INVALID')
    return ref


# --- Manifest --------------------------------------------------------------------------------

MANIFEST_KEYS = ('schema', 'revision', 'predecessor_sha256', 'labels', 'native_artifacts',
                 'native_semantic_sha256', 'projection_status', 'projection', 'occurrences')
OCCURRENCE_KEYS = ('position', 'native_id', 'native_rank', 'content_sha256', 'content_ref')
MAX_OCCURRENCES = 100000
MAX_REVISION = 2 ** 31


def build_manifest(parts, labels, *, revision=1, predecessor_sha256=None, content_refs=None):
    """Manifest for an ordered native part set. content_refs maps position -> content ref."""
    validate_labels(labels)
    status, projection, semantic = derive_native(parts, labels)
    occurrences = _occurrences_from_projection(projection) if status == PROJECTED else []
    refs = content_refs or {}
    _require(type(refs) is dict and all(type(k) is int and 0 <= k < len(occurrences) for k in refs),
             'OCCURRENCE_INVALID')
    for position, ref in refs.items():
        occurrences[position]['content_ref'] = dict(ref) if type(ref) is dict else ref
    manifest = {'schema': MANIFEST_SCHEMA, 'revision': revision, 'predecessor_sha256': predecessor_sha256,
                'labels': dict(labels), 'native_artifacts': native_artifact_records(parts),
                'native_semantic_sha256': semantic, 'projection_status': status,
                'projection': projection, 'occurrences': occurrences}
    return validate_manifest(manifest, native_parts=parts)


def _validate_occurrence(occurrence, position):
    _require(type(occurrence) is dict and set(occurrence) == set(OCCURRENCE_KEYS), 'OCCURRENCE_INVALID')
    _require(type(occurrence['position']) is int and occurrence['position'] == position, 'OCCURRENCE_INVALID')
    _require(type(occurrence['native_id']) is str
             and NATIVE_ID.fullmatch(occurrence['native_id']) is not None, 'OCCURRENCE_INVALID')
    _require(type(occurrence['native_rank']) is str
             and RANK.fullmatch(occurrence['native_rank']) is not None, 'RANK_MALFORMED')
    if occurrence['content_sha256'] is not None:
        require_digest(occurrence['content_sha256'])
    validate_content_ref(occurrence['content_ref'], occurrence['content_sha256'])


def _validate_projection(projection, occurrences):
    _require(type(projection) is dict and set(projection) == {'custom_code', 'rows', 'settings'},
             'PROJECTION_INVALID')
    rows = projection['rows']
    _require(type(rows) is list and len(rows) == len(occurrences), 'PROJECTION_INVALID')
    for row in rows:
        _require(type(row) is dict and set(row) == set(ROW_KEYS), 'PROJECTION_INVALID')
        _require(row['file'] is None or type(row['file']) is dict
                 and type(row['file'].get('content')) is dict, 'PROJECTION_INVALID')
    _require(_occurrences_from_projection(projection) == [dict(o, content_ref={'kind': 'native_only'})
                                                          for o in occurrences],
             'OCCURRENCE_PROJECTION_MISMATCH')
    _require(type(projection['settings']) is dict and set(projection['settings']) <= set(KNOWN_PREFS),
             'PROJECTION_INVALID')
    _require(type(projection['custom_code']) is dict and set(projection['custom_code']) <= set(KNOWN_CODE),
             'PROJECTION_INVALID')


def validate_manifest(manifest, native_parts=None):
    """Schema and internal consistency; with native_parts, proves derivation from those bytes."""
    _require(type(manifest) is dict and set(manifest) == set(MANIFEST_KEYS), 'MANIFEST_INVALID')
    _require(manifest['schema'] == MANIFEST_SCHEMA, 'MANIFEST_INVALID')
    revision, predecessor = manifest['revision'], manifest['predecessor_sha256']
    _require(type(revision) is int and 1 <= revision <= MAX_REVISION, 'MANIFEST_INVALID')
    _require((revision == 1) == (predecessor is None), 'MANIFEST_INVALID')
    if predecessor is not None:
        require_digest(predecessor)
    labels = validate_labels(manifest['labels'])
    validate_native_artifacts(manifest['native_artifacts'])
    require_digest(manifest['native_semantic_sha256'])
    status, projection, occurrences = (manifest['projection_status'], manifest['projection'],
                                       manifest['occurrences'])
    allowed = (PROJECTED, NATIVE_ONLY_UNPROJECTABLE) if projection_supported(labels) else (
        NATIVE_ONLY_UNCHARACTERIZED,)
    _require(status in allowed, 'MANIFEST_INVALID')
    _require(type(occurrences) is list and len(occurrences) <= MAX_OCCURRENCES, 'OCCURRENCE_INVALID')
    for position, occurrence in enumerate(occurrences):
        _validate_occurrence(occurrence, position)
    ids = [o['native_id'] for o in occurrences]
    _require(len(ids) == len(set(ids)), 'OCCURRENCE_IDENTITY_DUPLICATE')
    if status == PROJECTED:
        _validate_projection(projection, occurrences)
    else:
        _require(projection is None and occurrences == [], 'PROJECTION_INVALID')
    try:
        canonical_bytes(manifest)
    except RecursionError:
        raise DurableStateError('MANIFEST_INVALID') from None
    if native_parts is not None:
        _require(native_artifact_records(native_parts) == manifest['native_artifacts'], 'ARTIFACT_MISMATCH')
        derived_status, derived_projection, semantic = derive_native(native_parts, labels)
        _require(derived_status == status and semantic == manifest['native_semantic_sha256'],
                 'ARTIFACT_MISMATCH')
        _require(derived_projection == projection, 'PROJECTION_MISMATCH')
    return manifest


def serialize_manifest(manifest):
    return canonical_bytes(validate_manifest(manifest))


def parse_manifest(raw, native_parts=None):
    return validate_manifest(parse_canonical(raw), native_parts)


def manifest_sha256(manifest):
    """Identity of exact canonical manifest bytes (used as a successor's predecessor_sha256)."""
    return sha256_hex(serialize_manifest(manifest))


def verify_manifest_content(manifest, *, shared_images_root=None, private_root=None):
    """Prove every non-native content ref against its caller-authorized root by digest."""
    validate_manifest(manifest)
    for occurrence in manifest['occurrences']:
        ref, digest = occurrence['content_ref'], occurrence['content_sha256']
        if ref['kind'] == 'shared_images':
            _require(shared_images_root is not None, 'ROOT_REQUIRED')
            verify_shared_images_ref(shared_images_root, ref['path'], digest)
        elif ref['kind'] == 'private':
            _require(private_root is not None, 'ROOT_REQUIRED')
            verify_private_content(private_root, digest)
    return True


def semantic_fingerprint(manifest):
    """Labels, projection, native semantic digest and occurrence order/content identity.

    Content locations (content_ref) and the manifest revision chain are deliberately excluded.
    This checks internal consistency only: equal fingerprints prove shared semantics only for
    manifests already proven against their native parts (validate_manifest(..., native_parts)
    or parse_manifest(..., native_parts)). Only such part-verified fingerprints may feed a
    journal's before/requested fingerprints.
    """
    validate_manifest(manifest)
    return sha256_hex(canonical_bytes({
        'schema': FINGERPRINT_SCHEMA,
        'labels': manifest['labels'],
        'projection_status': manifest['projection_status'],
        'native_semantic_sha256': manifest['native_semantic_sha256'],
        'projection': manifest['projection'],
        'occurrences': [[o['position'], o['native_id'], o['native_rank'], o['content_sha256']]
                        for o in manifest['occurrences']],
    }))


# --- Recovery journal (schema and state machine only) -----------------------------------------

PREPARED, STAGED, PRESERVED, APPLYING = 'PREPARED', 'STAGED', 'PRESERVED', 'APPLYING'
ROLLBACK_REQUIRED = 'ROLLBACK_REQUIRED'
COMPLETED, NOOP_COMPLETED = 'COMPLETED', 'NOOP_COMPLETED'
FAILED_BEFORE_MUTATION, ROLLED_BACK, ROLLBACK_FAILED = 'FAILED_BEFORE_MUTATION', 'ROLLED_BACK', 'ROLLBACK_FAILED'
JOURNAL_STATES = (PREPARED, STAGED, PRESERVED, APPLYING, ROLLBACK_REQUIRED, COMPLETED, NOOP_COMPLETED,
                  FAILED_BEFORE_MUTATION, ROLLED_BACK, ROLLBACK_FAILED)
TERMINAL_STATES = (COMPLETED, NOOP_COMPLETED, FAILED_BEFORE_MUTATION, ROLLED_BACK, ROLLBACK_FAILED)
# observed: which fingerprint the transition's observation must equal (None = not required).
TRANSITIONS = {
    (PREPARED, STAGED): 'requested',            # disposable-profile staged import verified
    (PREPARED, NOOP_COMPLETED): 'requested',    # live state already matches: repeat is a no-op
    (PREPARED, FAILED_BEFORE_MUTATION): None,
    (STAGED, PRESERVED): 'before',              # preserved displaced state verified as before-state
    (STAGED, FAILED_BEFORE_MUTATION): None,
    (PRESERVED, APPLYING): 'before',            # live re-check: no concurrent change
    (PRESERVED, FAILED_BEFORE_MUTATION): None,
    (APPLYING, COMPLETED): 'requested',
    (APPLYING, ROLLBACK_REQUIRED): None,
    (ROLLBACK_REQUIRED, ROLLED_BACK): 'before',
    (ROLLBACK_REQUIRED, ROLLBACK_FAILED): None,
}
FAILURE_CODES = {
    FAILED_BEFORE_MUTATION: ('STAGING_MISMATCH', 'PRESERVATION_FAILED', 'CONCURRENT_CHANGE',
                             'OPERATOR_ABORT', 'INTERRUPTED'),
    ROLLBACK_REQUIRED: ('APPLY_FAILED', 'VERIFICATION_MISMATCH', 'INTERRUPTED'),
    ROLLBACK_FAILED: ('ROLLBACK_MISMATCH', 'ROLLBACK_APPLY_FAILED', 'INTERRUPTED'),
}
AUTHORIZATION_BASES = ('OPERATOR_EXPLICIT', 'POSITIVE_VERSIONED_RESET_EVIDENCE')
BEFORE_STATES = ('PRESENT', 'RESET_EVIDENCED')
JOURNAL_KEYS = ('schema', 'journal_id', 'labels', 'source', 'target', 'authorization', 'before_state',
                'before_fingerprint', 'requested_fingerprint', 'displaced_state', 'status', 'history')
HISTORY_KEYS = ('seq', 'status', 'observed_fingerprint', 'failure_code')
JOURNAL_ID = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')
MAX_HISTORY = 16


def new_journal(*, journal_id, labels, source_manifest_sha256, source_artifact_sha256, profile_token,
                storage_token, basis, evidence_sha256, before_state, before_fingerprint,
                requested_fingerprint):
    """PREPARED journal. Tokens are opaque digests, never paths. Labels bind source and target."""
    journal = {
        'schema': JOURNAL_SCHEMA, 'journal_id': journal_id,
        'labels': dict(labels) if type(labels) is dict else labels,
        'source': {'manifest_sha256': source_manifest_sha256,
                   'native_artifact_sha256': list(source_artifact_sha256)
                   if type(source_artifact_sha256) in (list, tuple) else source_artifact_sha256},
        'target': {'profile_token': profile_token, 'storage_token': storage_token},
        'authorization': {'basis': basis, 'evidence_sha256': evidence_sha256},
        'before_state': before_state, 'before_fingerprint': before_fingerprint,
        'requested_fingerprint': requested_fingerprint, 'displaced_state': None, 'status': PREPARED,
        'history': [{'seq': 0, 'status': PREPARED, 'observed_fingerprint': before_fingerprint,
                     'failure_code': None}],
    }
    return validate_journal(journal)


def _check_step(journal, current, entry):
    target = entry['status']
    _require(current not in TERMINAL_STATES, 'JOURNAL_TERMINAL')
    _require((current, target) in TRANSITIONS, 'JOURNAL_TRANSITION_INVALID')
    observed, failure = entry['observed_fingerprint'], entry['failure_code']
    if observed is not None:
        require_digest(observed)
    if target in FAILURE_CODES:
        _require(failure in FAILURE_CODES[target], 'JOURNAL_PRECONDITION_FAILED')
    else:
        _require(failure is None, 'JOURNAL_PRECONDITION_FAILED')
    expected = TRANSITIONS[(current, target)]
    before, requested = journal['before_fingerprint'], journal['requested_fingerprint']
    if expected is not None:
        _require(observed == (before if expected == 'before' else requested), 'JOURNAL_PRECONDITION_FAILED')
    if target == NOOP_COMPLETED:
        _require(before == requested, 'JOURNAL_PRECONDITION_FAILED')
    if target == STAGED:
        # Idempotence: an already-matching state may only complete as a no-op.
        _require(before != requested, 'JOURNAL_PRECONDITION_FAILED')


def validate_journal(journal):
    """Pure, idempotent replay of the whole history from PREPARED."""
    _require(type(journal) is dict and set(journal) == set(JOURNAL_KEYS), 'JOURNAL_INVALID')
    _require(journal['schema'] == JOURNAL_SCHEMA, 'JOURNAL_INVALID')
    _require(type(journal['journal_id']) is str and JOURNAL_ID.fullmatch(journal['journal_id']) is not None,
             'JOURNAL_INVALID')
    try:
        validate_labels(journal['labels'])
    except DurableStateError:
        raise DurableStateError('JOURNAL_INVALID') from None
    source, target, authorization = journal['source'], journal['target'], journal['authorization']
    _require(type(source) is dict and set(source) == {'manifest_sha256', 'native_artifact_sha256'},
             'JOURNAL_INVALID')
    require_digest(source['manifest_sha256'])
    artifacts = source['native_artifact_sha256']
    _require(type(artifacts) is list and 1 <= len(artifacts) <= MAX_ARTIFACTS, 'JOURNAL_INVALID')
    for digest in artifacts:
        require_digest(digest)
    _require(type(target) is dict and set(target) == {'profile_token', 'storage_token'}, 'JOURNAL_INVALID')
    require_digest(target['profile_token'])
    require_digest(target['storage_token'])
    _require(type(authorization) is dict and set(authorization) == {'basis', 'evidence_sha256'}
             and authorization['basis'] in AUTHORIZATION_BASES, 'JOURNAL_INVALID')
    require_digest(authorization['evidence_sha256'])
    _require(journal['before_state'] in BEFORE_STATES, 'JOURNAL_INVALID')
    # Automatic (evidence-based) recovery is only for a positively evidenced reset target.
    _require(authorization['basis'] != 'POSITIVE_VERSIONED_RESET_EVIDENCE'
             or journal['before_state'] == 'RESET_EVIDENCED', 'JOURNAL_PRECONDITION_FAILED')
    require_digest(journal['before_fingerprint'])
    require_digest(journal['requested_fingerprint'])
    history = journal['history']
    _require(type(history) is list and 1 <= len(history) <= MAX_HISTORY, 'JOURNAL_INVALID')
    for seq, entry in enumerate(history):
        _require(type(entry) is dict and set(entry) == set(HISTORY_KEYS) and type(entry['seq']) is int
                 and entry['seq'] == seq and entry['status'] in JOURNAL_STATES, 'JOURNAL_INVALID')
    first = history[0]
    _require(first['status'] == PREPARED and first['failure_code'] is None
             and first['observed_fingerprint'] == journal['before_fingerprint'], 'JOURNAL_INVALID')
    current = PREPARED
    for entry in history[1:]:
        _check_step(journal, current, entry)
        current = entry['status']
    _require(journal['status'] == current, 'JOURNAL_INVALID')
    displaced = journal['displaced_state']
    if any(entry['status'] == PRESERVED for entry in history):
        _require(type(displaced) is dict and set(displaced) == {'kind', 'sha256'}
                 and displaced['kind'] == 'private', 'JOURNAL_INVALID')
        require_digest(displaced['sha256'])
    else:
        _require(displaced is None, 'JOURNAL_INVALID')
    try:
        canonical_bytes(journal)
    except RecursionError:
        raise DurableStateError('JOURNAL_INVALID') from None
    return journal


def transition(journal, status, *, observed_fingerprint=None, failure_code=None, displaced_state=None):
    """New journal with one appended, checked step. The input journal is never modified."""
    validate_journal(journal)
    _require(journal['status'] not in TERMINAL_STATES, 'JOURNAL_TERMINAL')
    _require(status in JOURNAL_STATES and len(journal['history']) < MAX_HISTORY, 'JOURNAL_TRANSITION_INVALID')
    _require((displaced_state is not None) == (status == PRESERVED), 'JOURNAL_PRECONDITION_FAILED')
    entry = {'seq': len(journal['history']), 'status': status,
             'observed_fingerprint': observed_fingerprint, 'failure_code': failure_code}
    _check_step(journal, journal['status'], entry)
    updated = parse_canonical(canonical_bytes(journal))
    updated['history'].append(entry)
    updated['status'] = status
    if displaced_state is not None:
        updated['displaced_state'] = dict(displaced_state) if type(displaced_state) is dict else displaced_state
    return validate_journal(updated)


def serialize_journal(journal):
    return canonical_bytes(validate_journal(journal))


def parse_journal(raw):
    return validate_journal(parse_canonical(raw))


# --- Atomic write beneath an explicit caller root ----------------------------------------------

def _flush(fd):
    """F_FULLFSYNC where available (macOS fsync alone does not reach stable storage), else fsync."""
    full = getattr(fcntl, 'F_FULLFSYNC', None)
    if full is not None:
        try:
            fcntl.fcntl(fd, full)
            return
        except OSError:  # e.g. a filesystem or directory FD without F_FULLFSYNC support
            pass
    os.fsync(fd)


def atomic_write(state_root, relative, data):
    """temp (O_EXCL|O_NOFOLLOW, 0600) + fsync + replace + parent fsync, confined to state_root.

    The root must already exist; it is never created or inferred. Missing intermediate
    directories are created only beneath it, and no symlink is followed at any level.
    """
    _require(isinstance(data, (bytes, bytearray)), 'WRITE_FAILED')
    parts = validate_relative_ref(relative)
    directory = _open_root(state_root)
    try:
        for part in parts[:-1]:
            child = _descend(directory, part, True)
            os.close(directory)
            directory = child
        name = parts[-1]
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _require(stat.S_ISREG(info.st_mode), 'WRITE_TARGET_INVALID')
        except FileNotFoundError:
            pass
        except OSError:
            raise DurableStateError('WRITE_FAILED') from None
        temporary = '.' + name[:64] + '.tmp-' + secrets.token_hex(8)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=directory)
        except OSError:
            raise DurableStateError('WRITE_FAILED') from None
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(bytes(data))
                stream.flush()
                _flush(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            _flush(directory)
        except OSError:
            try:
                os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
            raise DurableStateError('WRITE_FAILED') from None
    finally:
        os.close(directory)
    return True
