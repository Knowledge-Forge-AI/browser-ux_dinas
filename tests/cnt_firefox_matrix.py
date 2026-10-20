"""R6 Firefox native semantic matrix: portable core. No browser, process or network I/O.

The native extension is the only importer and exporter. This module never writes or reads
extension storage, never serializes Clear New Tab state and never repairs native bytes. It
(1) verifies the retained captured XPI read-only in memory, (2) locates byte spans in native
export parts so part accounting and bounded synthetic mutations can be checked against the
original bytes, (3) simulates the verified 6.12.1 partition predicate for boundary
predictions, (4) computes a privacy-safe semantic fingerprint of native parts,
(5) classifies observed pre/input/post fingerprints, (6) derives the fixed rich-valid restore
evidence (restore, displacement, repeat identity), (7) derives the fixed malformed-input D
evidence (completion tri-state, allowlisted report codes, sentinel effects) and (8) proves each E
restore input is one declared bounded mutation of the same-root S-RICH artifact and derives the
fixed E compatibility evidence (application, allowlisted unknown-key fate, optional-pref, version and
synthetic-theme classes) and (9) for multipart B, decides the fixed S-MULTI source readiness, proves
each B restore's part selection (and its one bounded mutation) against the ready same-root S-MULTI
minimum artifact before file selection, and derives the fixed multipart evidence. Missing evidence
is never a verdict.

Static facts come from fixtures/cnt-native/firefox/6.12.1/static-matrix-provenance.json,
re-verified by the parent at member and offset; constants here must equal that file.
"""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import zipfile
import zlib

from cnt_native_evidence import VerificationError, require

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures/cnt-native/firefox/6.12.1'
PROVENANCE = FIXTURES / 'static-matrix-provenance.json'
METADATA = FIXTURES / 'metadata.json'

EXTENSION_ID = 'clear-new-tab@loftyshaky'
EXTENSION_VERSION = '6.12.1'
MANIFEST_VERSION = 3
XPI_SHA256 = 'bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f'
XPI_LIMIT = 8 * 1024 * 1024
# Verified 6.12.1 backup facts (provenance keys backup.*).
THRESHOLD_DEFAULT = 419430400
THRESHOLD_MIN = 52428800
THRESHOLD_MAX = 419430400
FOOTER = b']}'
PART_NAME = re.compile(r'Part (\d+)')
INPUT_NAME = 'bux-matrix Part {}.json'

# Fixed refusal messages mapped to fixed codes. Nothing else is exported.
MATRIX_CODES = {
    'Capture absent or not a regular file': 'CAPTURE_ABSENT',
    'Capture oversized': 'CAPTURE_OVERSIZED',
    'Capture digest mismatch': 'CAPTURE_DIGEST_MISMATCH',
    'Capture archive unreadable': 'CAPTURE_ARCHIVE_UNREADABLE',
    'Capture member unsafe': 'CAPTURE_MEMBER_UNSAFE',
    'Capture manifest identity mismatch': 'CAPTURE_MANIFEST_MISMATCH',
    'Capture member digest mismatch': 'CAPTURE_MEMBER_DIGEST_MISMATCH',
    'Provenance unreadable': 'PROVENANCE_UNREADABLE',
    'Provenance constant mismatch': 'PROVENANCE_CONSTANT_MISMATCH',
    'Native part structure invalid': 'NATIVE_PART_STRUCTURE_INVALID',
    'Mutation target absent': 'MUTATION_TARGET_ABSENT',
    'Mutation altered a known field': 'MUTATION_ALTERED_KNOWN_FIELD',
    'Unknown matrix case': 'MATRIX_CASE_UNKNOWN',
    'Matrix case not drivable': 'MATRIX_CASE_NOT_DRIVABLE',
    'Matrix input undeclared': 'MATRIX_INPUT_UNDECLARED',
    'Matrix input required': 'MATRIX_INPUT_REQUIRED',
    'Matrix input digest mismatch': 'MATRIX_INPUT_DIGEST_MISMATCH',
    'Matrix input source invalid': 'MATRIX_INPUT_SOURCE_INVALID',
    'Privacy projection refused': 'PRIVACY_PROJECTION_REFUSED',
    'Matrix rich source incomplete': 'MATRIX_RICH_SOURCE_INCOMPLETE',
    'Matrix multi source incomplete': 'MATRIX_MULTI_SOURCE_INCOMPLETE',
}


def file_bytes(path, limit):
    """Bounded no-follow regular-file read."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise VerificationError('Capture absent or not a regular file') from None
    with open(descriptor, 'rb', closefd=True) as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                'Capture absent or not a regular file')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'Capture oversized')
    return raw


def load_provenance(path=PROVENANCE):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise VerificationError('Provenance unreadable') from None
    require(isinstance(value, dict) and value.get('schema') == 'bux-r6-firefox-static-matrix-provenance-v1',
            'Provenance unreadable')
    return value


def provenance_value(provenance, key):
    fact = provenance.get('facts', {}).get(key)
    require(isinstance(fact, dict) and 'value' in fact, 'Provenance unreadable')
    return fact['value']


def fact_status(provenance, key):
    fact = provenance.get('facts', {}).get(key)
    return fact.get('status') if isinstance(fact, dict) else None


def verify_capture(path, *, expected_sha256=XPI_SHA256, metadata_path=METADATA):
    """Identity of the retained XPI, read once into memory. Never extracts or executes."""
    raw = file_bytes(path, XPI_LIMIT)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == expected_sha256 == XPI_SHA256, 'Capture digest mismatch')
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError):
        raise VerificationError('Capture archive unreadable') from None
    names = [i.filename for i in infos]
    for info in infos:
        name = info.filename
        parts = PurePosixPath(name).parts
        require(bool(name) and not name.startswith('/') and '\\' not in name and '..' not in parts
                and (info.external_attr >> 16) & 0o170000 != 0o120000, 'Capture member unsafe')
    require(len(names) == len(set(names)), 'Capture member unsafe')
    try:
        manifest = json.loads(archive.read('manifest.json'))
    except (KeyError, ValueError):
        raise VerificationError('Capture manifest identity mismatch') from None
    gecko = ((manifest.get('browser_specific_settings') or {}).get('gecko') or {}) if isinstance(manifest, dict) else {}
    require(gecko.get('id') == EXTENSION_ID and manifest.get('version') == EXTENSION_VERSION
            and manifest.get('manifest_version') == MANIFEST_VERSION, 'Capture manifest identity mismatch')
    expected = json.loads(Path(metadata_path).read_text())['native_member_sha256']
    try:
        observed = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in expected}
    except KeyError:
        raise VerificationError('Capture member digest mismatch') from None
    require(observed == expected, 'Capture member digest mismatch')
    return {'xpi_sha256': digest, 'extension_id': EXTENSION_ID, 'version': EXTENSION_VERSION,
            'manifest_version': MANIFEST_VERSION, 'member_count': len(names),
            'verified_member_digests': len(expected)}


# --- Native byte-span locator -------------------------------------------------------------
# Reads native bytes and records spans; it never produces Clear New Tab JSON.

_WS = b' \t\r\n'
_SCALAR = re.compile(rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null')


class Node:
    __slots__ = ('kind', 'start', 'end', 'members', 'items')

    def __init__(self, kind, start):
        self.kind, self.start, self.end = kind, start, None
        self.members, self.items = [], []


def _skip(raw, at):
    while at < len(raw) and raw[at] in _WS:
        at += 1
    return at


def _string_end(raw, at):
    at += 1
    while True:
        end = raw.find(b'"', at)
        require(end >= 0, 'Native part structure invalid')
        slashes = 0
        while raw[end - 1 - slashes] == 0x5C:
            slashes += 1
        if slashes % 2 == 0:
            return end + 1
        at = end + 1


def _value(raw, at, depth=0):
    require(depth < 64, 'Native part structure invalid')
    at = _skip(raw, at)
    require(at < len(raw), 'Native part structure invalid')
    head = raw[at]
    if head == 0x7B:  # {
        node = Node('object', at)
        at = _skip(raw, at + 1)
        if raw[at:at + 1] == b'}':
            node.end = at + 1
            return node
        while True:
            at = _skip(raw, at)
            require(raw[at:at + 1] == b'"', 'Native part structure invalid')
            key_end = _string_end(raw, at)
            key = json.loads(raw[at:key_end])
            colon = _skip(raw, key_end)
            require(raw[colon:colon + 1] == b':', 'Native part structure invalid')
            child = _value(raw, colon + 1, depth + 1)
            node.members.append((key, at, child))
            at = _skip(raw, child.end)
            if raw[at:at + 1] == b',':
                at += 1
                continue
            require(raw[at:at + 1] == b'}', 'Native part structure invalid')
            node.end = at + 1
            return node
    if head == 0x5B:  # [
        node = Node('array', at)
        at = _skip(raw, at + 1)
        if raw[at:at + 1] == b']':
            node.end = at + 1
            return node
        while True:
            child = _value(raw, at, depth + 1)
            node.items.append(child)
            at = _skip(raw, child.end)
            if raw[at:at + 1] == b',':
                at += 1
                continue
            require(raw[at:at + 1] == b']', 'Native part structure invalid')
            node.end = at + 1
            return node
    node = Node('scalar', at)
    if head == 0x22:
        node.end = _string_end(raw, at)
        return node
    match = _SCALAR.match(raw, at)
    require(match is not None, 'Native part structure invalid')
    node.end = match.end()
    return node


def locate(raw):
    """Root span tree of one native JSON document (bytes)."""
    root = _value(raw, 0)
    require(_skip(raw, root.end) == len(raw), 'Native part structure invalid')
    return root


def member(node, key):
    for name, key_start, child in node.members if node is not None and node.kind == 'object' else ():
        if name == key:
            return key_start, child
    return None, None


def find(root, path):
    """Node at a path of keys and indexes, or None."""
    node = root
    for step in path:
        if node is None:
            return None
        if isinstance(step, int):
            node = node.items[step] if node.kind == 'array' and 0 <= step < len(node.items) else None
        else:
            node = member(node, step)[1]
    return node


def part_layout(raw):
    """Byte accounting of a native part: header length, chunk core lengths, footer.

    A native part is `<header>[` + chunks joined by ',' + `]}` exactly (verified template).
    Anything else is reported as not native-template, never repaired.
    """
    root = locate(raw)
    require(root.kind == 'object', 'Native part structure invalid')
    keys = [k for k, _, _ in root.members]
    chunks = member(root, 'chunks')[1]
    require(chunks is not None and chunks.kind == 'array', 'Native part structure invalid')
    header = chunks.start + 1
    cores = [item.end - item.start for item in chunks.items]
    joined = b','.join(raw[item.start:item.end] for item in chunks.items)
    template = (raw[header:chunks.end - 1] == joined and raw[chunks.end:] == b'}'
                and keys[-1:] == ['chunks'])
    return {'keys': keys, 'header_bytes': header, 'chunk_core_bytes': cores,
            'footer_bytes': len(raw) - (chunks.end - 1), 'native_template': template,
            'settings_header': keys[:2] == ['settings', 'custom_code']}


# --- Verified 6.12.1 partition predicate (provenance backup.partition) ---------------------

def simulate_partition(cores, header_bytes, threshold, footer_bytes=len(FOOTER)):
    """Parts as lists of chunk indexes, reproducing the verified native loop exactly.

    Native: b += g; split when b + g + header + footer >= threshold (the new chunk counted
    twice); on a split the accumulated chunks are emitted without the new one, which is
    carried (leading comma stripped) and b resets to 0 (the carried chunk is not counted);
    the last chunk is always appended to the current part. The leading-comma flag only
    becomes false after a non-split append, so a split on the first chunk leaves the next
    appended chunk without a separator. `well_formed` records that prediction.
    """
    require(all(type(c) is int and c > 0 for c in cores) and type(threshold) is int
            and type(header_bytes) is int, 'Native part structure invalid')
    if not cores:
        return {'parts': [[]], 'well_formed': [True], 'empty_parts': 1}
    parts, current, accumulated, first = [], [], 0, True
    for index, core in enumerate(cores):
        last = index == len(cores) - 1
        comma = not first
        size = core + (1 if comma else 0)
        accumulated += size
        limit = accumulated + size + header_bytes + footer_bytes >= threshold
        if limit or last:
            parts.append(current + [(index, comma)] if last else current)
            current = [(index, False)]
            accumulated = 0
        else:
            current.append((index, comma))
            first = False
    well_formed = [all(c == (i > 0) for i, (_, c) in enumerate(p)) for p in parts]
    return {'parts': [[i for i, _ in p] for p in parts], 'well_formed': well_formed,
            'empty_parts': sum(1 for p in parts if not p)}


def flip_threshold(cores, header_bytes, footer_bytes=len(FOOTER)):
    """Smallest threshold at which the single-part export stays one part is result + 1."""
    require(len(cores) >= 2, 'Native part structure invalid')
    values, accumulated = [], 0
    for index, core in enumerate(cores[:-1]):
        size = core + (1 if index else 0)
        accumulated += size
        values.append(accumulated + size + header_bytes + footer_bytes)
    return max(values)


def header_at(header_bytes, calibration_threshold, threshold):
    """Declared adjustment: the threshold pref is serialized in Part 1 as decimal digits."""
    return header_bytes - len(str(calibration_threshold)) + len(str(threshold))


def boundary_prediction(calibration, calibration_threshold=THRESHOLD_DEFAULT):
    """Predicted flip threshold T from one native single-part calibration export.

    `calibration_threshold` is the threshold the calibration export itself read: the session passes
    the export's own Part 1 pref (backup.partition_header), never an assumed default. The header
    adjustment is a fixpoint over the threshold's decimal digit count; `converged` is False when it
    did not settle, and such a prediction is never settable."""
    return layout_prediction(part_layout(calibration), calibration_threshold)


def layout_prediction(layout, calibration_threshold):
    """boundary_prediction() on the calibration's part layout (real-size integers in tests)."""
    require(type(calibration_threshold) is int and calibration_threshold > 0, 'Native part structure invalid')
    require(layout['native_template'] and layout['settings_header'], 'Native part structure invalid')
    header = layout['header_bytes']
    threshold = flip_threshold(layout['chunk_core_bytes'], header)
    converged = False
    for _ in range(4):  # fixpoint over the digit-count adjustment
        adjusted = header_at(header, calibration_threshold, threshold)
        following = flip_threshold(layout['chunk_core_bytes'], adjusted)
        if following == threshold:
            converged = True
            break
        threshold = following
    in_range = converged and THRESHOLD_MIN <= threshold and threshold + 1 <= THRESHOLD_MAX
    return {'threshold': threshold, 'in_ui_range': in_range, 'converged': converged,
            'calibration_threshold': calibration_threshold,
            'header_adjusted_bytes': header_at(header, calibration_threshold, threshold),
            'chunk_count': len(layout['chunk_core_bytes'])}


def classify_boundary(prediction, parts_at_t, parts_at_t_plus_1, header_at_t=None):
    """`header_at_t` is the at-T export's own Part 1 header length. If it differs from the
    digit-adjusted prediction, the prediction's premise failed and no shift is claimed."""
    if not prediction or parts_at_t is None or parts_at_t_plus_1 is None:
        return 'INCOMPLETE_EVIDENCE'
    if not prediction.get('in_ui_range'):
        return 'BOUNDARY_NOT_SETTABLE'
    if header_at_t is None:
        return 'INCOMPLETE_EVIDENCE'
    if header_at_t != prediction.get('header_adjusted_bytes'):
        return 'PREDICTION_HEADER_DRIFT'
    return 'EXACT_BOUNDARY_OBSERVED' if parts_at_t >= 2 and parts_at_t_plus_1 == 1 else 'BOUNDARY_SHIFTED'


def partition_consistency(parts, threshold):
    """Observed native grouping against the simulated predicate, using the export's own bytes."""
    try:
        layouts = [part_layout(p) for p in parts]
    except VerificationError:
        return {'status': 'NOT_NATIVE_TEMPLATE'}
    return partition_layouts(layouts, threshold)


def partition_layouts(layouts, threshold):
    """partition_consistency() on already computed part layouts. Sizes are UTF-8 byte lengths
    (backup.partition_units), so the byte simulation is exact for any content. `threshold` is the
    threshold the export itself read (its own Part 1 pref); without an int threshold the
    comparison is incomplete, never consistent."""
    if (not isinstance(layouts, list) or not layouts or not all(isinstance(l, dict) for l in layouts)
            or not layouts[0].get('settings_header') or not all(l.get('native_template') is True for l in layouts)):
        return {'status': 'NOT_NATIVE_TEMPLATE'}
    if type(threshold) is not int or threshold <= 0:
        return {'status': 'INCOMPLETE_EVIDENCE'}
    try:
        cores = [c for l in layouts for c in l['chunk_core_bytes']]
        observed, at = [], 0
        for layout in layouts:
            observed.append(list(range(at, at + len(layout['chunk_core_bytes']))))
            at += len(layout['chunk_core_bytes'])
        simulated = simulate_partition(cores, layouts[0]['header_bytes'], threshold) if cores else None
    except (VerificationError, TypeError, KeyError):
        return {'status': 'NOT_NATIVE_TEMPLATE'}
    return {'status': 'CONSISTENT' if simulated and simulated['parts'] == observed else 'INCONSISTENT',
            'observed_part_sizes': [len(p) for p in observed],
            'simulated_part_sizes': [len(p) for p in simulated['parts']] if simulated else None,
            'well_formed': list(simulated['well_formed']) if simulated else None,
            'empty_parts': simulated['empty_parts'] if simulated else None}


# --- Project-authored deterministic inputs -----------------------------------------------

def _chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def png(rgb, padding=0, seed=b''):
    """1x1 RGB PNG; optional private ancillary 'bxXf' chunks (1 MiB each) of PRNG bytes."""
    body = _chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
    counter, remaining = 0, padding
    while remaining > 0:
        size = min(remaining, 1024 * 1024)
        block, stream = bytearray(), 0
        while len(block) < size:
            block += hashlib.sha256(seed + counter.to_bytes(8, 'big') + stream.to_bytes(8, 'big')).digest()
            stream += 1
        body += _chunk(b'bxXf', bytes(block[:size]))
        remaining -= size
        counter += 1
    body += _chunk(b'IDAT', zlib.compress(b'\0' + bytes(rgb))) + _chunk(b'IEND', b'')
    return b'\x89PNG\r\n\x1a\n' + body


# Accepted R1 colours (fixture image-0..3.png are byte-identical), then two extras.
RICH_COLOURS = ((255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 0, 0), (255, 255, 0), (0, 255, 255))
SENTINEL_COLOURS = ((17, 34, 51), (68, 85, 102))
MULTI_COUNT = 5
MULTI_PADDING = 15 * 1024 * 1024  # ~20 MiB base64 per chunk; see boundary design in the doc


def synthetic_inputs(kind):
    """Ordered (filename, bytes) inputs for a seed step; never user or captured data."""
    if kind == 'rich':
        return [(f'bux-rich-{i}.png', png(c)) for i, c in enumerate(RICH_COLOURS)]
    if kind == 'sentinel':
        return [(f'bux-sentinel-{i}.png', png(c)) for i, c in enumerate(SENTINEL_COLOURS)]
    if kind == 'multi':
        return [(f'bux-multi-{i}.png', png((i * 40, 90, 200 - i * 30), MULTI_PADDING + i * 4096,
                                           b'bux-r6-multi-%d' % i)) for i in range(MULTI_COUNT)]
    raise VerificationError('Unknown matrix case')


# --- Bounded synthetic mutations of native artifacts --------------------------------------

UNKNOWN_VALUE = 'bux-r6-unknown'
MUTATIONS = {
    'unknown_top_level': ('insert', (), 'x_bux_top'),
    'unknown_background_data': ('insert', ('chunks', 0, 'data'), 'x_bux_background'),
    'unknown_pref': ('insert', ('settings', 'prefs'), 'x_bux_pref'),
    'unknown_custom_code': ('insert', ('custom_code',), 'x_bux_code'),
    'unknown_task': ('insert', ('chunks', '*task', 'tasks', 0), 'x_bux_task'),
    'absent_optional_prefs': ('remove', ('settings', 'prefs'), None),
    'pref_version_older': ('replace', ('settings', 'prefs', 'version'), '6.0.0'),
    'synthetic_theme_id_duplicate': ('theme', ('chunks',), 'bux-r6-theme'),
    'pref_mode_theme_background': ('replace', ('settings', 'prefs', 'mode'), 'theme_background'),
    'truncate_json': ('truncate', (), None),
    'drop_chunks': ('remove-member', (), 'chunks'),
    'chunks_not_array': ('replace', ('chunks',), {}),
    'invalid_data_url': ('replace', ('chunks', 0, 'file', 'background'), 'data:image/png;base64,@@@@'),
    'flip_base64_char': ('flip', ('chunks', 0, 'file', 'background'), None),
}
# Keys removed by absent_optional_prefs: optional in 6.12.1 schema transforms (provenance
# schema.optional_prefs); the import either restores their defaults or keeps them absent.
OPTIONAL_PREFS = ('backgrounds_per_page', 'one_backup_file_size_in_bytes')
SYNTHETIC_ONLY = {'synthetic_theme_id_duplicate', 'pref_mode_theme_background'}


def _resolve(root, path):
    if '*task' in path:
        at = path.index('*task')
        chunks = find(root, path[:at])
        for index, item in enumerate(chunks.items if chunks is not None and chunks.kind == 'array' else ()):
            node = find(item, path[at + 1:])
            if node is not None:
                return node, path[:at] + (index,) + path[at + 1:]
        return None, path
    return find(root, path), path


def _drop(value, path, key):
    """Parsed value with the declared key removed at path (a copy)."""
    value = json.loads(json.dumps(value))
    target = value
    for step in path:
        target = target[step]
    target.pop(key)
    return value


def _set(value, path, new):
    value = json.loads(json.dumps(value))
    target = value
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = new
    return value


def mutate(raw, mutation):
    """(bytes, record). Only the declared edit changes; everything else is byte-identical.

    Each parseable result is re-parsed and compared with the original after undoing the
    declared edit, so a mutation can never silently alter a known native field.
    """
    require(mutation in MUTATIONS, 'Mutation target absent')
    action, path, value = MUTATIONS[mutation]
    root = locate(raw)
    original = json.loads(raw)
    record = {'mutation': mutation, 'before_sha256': hashlib.sha256(raw).hexdigest(),
              'synthetic_label': 'SYNTHETIC_INPUT_NOT_UI_CREATABLE' if mutation in SYNTHETIC_ONLY else None}
    if action == 'truncate':
        cut = max(1, len(raw) * 2 // 3)
        out = raw[:cut]
        record.update(edit='truncate', kept_bytes=cut, parseable=False)
    elif action == 'insert':
        node, resolved = _resolve(root, path)
        require(node is not None and node.kind == 'object', 'Mutation target absent')
        text = json.dumps(value) + ':' + json.dumps(UNKNOWN_VALUE)
        text += ',' if node.members else ''
        out = raw[:node.start + 1] + text.encode() + raw[node.start + 1:]
        undone = _drop(json.loads(out), resolved, value)
        require(undone == original, 'Mutation altered a known field')
        record.update(edit='insert', target=_path(resolved), key=value, parseable=True)
    elif action == 'remove':
        node = find(root, path)
        require(node is not None and node.kind == 'object', 'Mutation target absent')
        spans = [(k, s, c) for k, s, c in node.members if k in OPTIONAL_PREFS]
        require(len(spans) == len(OPTIONAL_PREFS), 'Mutation target absent')
        out, removed = raw, []
        for key, start, child in sorted(spans, key=lambda s: -s[1]):
            end = _skip(out, child.end)
            if out[end:end + 1] == b',':
                end += 1
            elif out[start - 1:start] == b',':
                start -= 1
            out = out[:start] + out[end:]
            removed.append(key)
        expected = original
        for key in removed:
            expected = _drop(expected, path, key)
        require(json.loads(out) == expected, 'Mutation altered a known field')
        record.update(edit='remove', target=_path(path), keys=sorted(removed), parseable=True)
    elif action == 'remove-member':
        start, child = member(root, value)
        require(child is not None, 'Mutation target absent')
        end = child.end
        if raw[start - 1:start] == b',':
            start -= 1
        out = raw[:start] + raw[end:]
        require(json.loads(out) == _drop(original, (), value), 'Mutation altered a known field')
        record.update(edit='remove', target=_path((value,)), parseable=True)
    elif action == 'replace':
        node = find(root, path)
        require(node is not None, 'Mutation target absent')
        out = raw[:node.start] + json.dumps(value).encode() + raw[node.end:]
        require(json.loads(out) == _set(original, path, value), 'Mutation altered a known field')
        record.update(edit='replace', target=_path(path), parseable=True)
    elif action == 'flip':
        node = find(root, path)
        require(node is not None and node.kind == 'scalar', 'Mutation target absent')
        text = raw[node.start:node.end]
        comma = text.find(b',')
        require(comma > 0 and node.end - node.start > comma + 8, 'Mutation target absent')
        at = node.start + comma + 5
        new = b'B' if raw[at:at + 1] != b'B' else b'C'
        out = raw[:at] + new + raw[at + 1:]
        record.update(edit='flip', target=_path(path), parseable=True)
    elif action == 'theme':
        chunks = find(root, path)
        require(chunks is not None and len(chunks.items) >= 2, 'Mutation target absent')
        out = raw
        for item in sorted(chunks.items[:2], key=lambda n: -n.start):
            data = member(item, 'data')[1]
            require(data is not None and data.kind == 'object' and member(data, 'theme_id')[1] is None,
                    'Mutation target absent')
            text = json.dumps('theme_id') + ':' + json.dumps(value) + ','
            out = out[:data.start + 1] + text.encode() + out[data.start + 1:]
        undone = _drop(_drop(json.loads(out), ('chunks', 0, 'data'), 'theme_id'),
                       ('chunks', 1, 'data'), 'theme_id')
        require(undone == original, 'Mutation altered a known field')
        record.update(edit='insert', target='chunks.0-1.data', key='theme_id', parseable=True)
    record['after_sha256'] = hashlib.sha256(out).hexdigest()
    return out, record


def _path(path):
    return '.'.join(str(p) for p in path)


# --- Part-set selection -------------------------------------------------------------------

SELECTIONS = ('ordered', 'reversed', 'no_part_1', 'no_middle', 'duplicate_middle',
              'truncate_last', 'bad_data_part_2', 'rename_no_part_1', 'single')


def select_parts(parts, selection):
    """[(named-part, bytes, source-part-number, directory-slot)] in file-selection order.

    Input file names are harness-assigned (`bux-matrix Part N.json`, N = named-part) because
    native names contain '/' and ':'; the file bytes are the untouched native (or declared
    mutated) bytes. Duplicate names go to separate directory slots.
    """
    numbered = [(n, raw, n) for n, raw in enumerate(parts, 1)]
    if selection in ('ordered', 'single', 'truncate_last', 'bad_data_part_2'):
        chosen = list(numbered)
    elif selection == 'reversed':
        chosen = list(reversed(numbered))
    elif selection == 'no_part_1':
        chosen = numbered[1:]
    elif selection == 'no_middle':
        require(len(numbered) >= 3, 'Matrix input required')
        chosen = [numbered[0]] + numbered[2:]
    elif selection == 'duplicate_middle':
        require(len(numbered) >= 3, 'Matrix input required')
        chosen = numbered + [numbered[1]]
    elif selection == 'rename_no_part_1':
        require(len(numbered) == 1, 'Matrix input required')
        chosen = [(2, numbered[0][1], 1)]
    else:
        raise VerificationError('Matrix input undeclared')
    seen, result = {}, []
    for name, raw, number in chosen:
        slot = seen.get(name, 0)
        seen[name] = slot + 1
        result.append((name, raw, number, slot))
    return result


# --- Semantic fingerprint ------------------------------------------------------------------

VOLATILE_PREFS = ('background_change_time', 'current_background_id', 'future_background_id')
BOUNDED = re.compile(r'[A-Za-z0-9_.:+-]{0,64}')
DATA_URL = re.compile(r'data:([a-z]+/[a-z0-9.+-]+);base64,(.*)', re.S)
KNOWN_ROW = ('data', 'thumbnail', 'file', 'tasks')
KNOWN_DATA = ('id', 'i', 'type', 'width', 'height', 'thumbnail_width', 'thumbnail_height',
              'background_size', 'background_position', 'background_repeat',
              'color_of_area_around_background', 'video_speed', 'video_volume', 'theme_id')
KNOWN_FILE = ('name', 'type', 'last_modified', 'background')
KNOWN_TASK = ('id', 'background_id', 'year', 'month', 'day_of_the_month', 'day_of_the_week', 'time', 'i')
KNOWN_CODE = ('html', 'css', 'js')
KNOWN_TOP = ('settings', 'custom_code', 'chunks')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scalar(value):
    """Bounded scalar, else a digest with length. Never exports arbitrary text."""
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str) and BOUNDED.fullmatch(value):
        return value
    return {'sha256': digest(value), 'length': len(json.dumps(value))}


def content_digest(value):
    if not isinstance(value, str):
        return {'status': 'NOT_STRING'}
    match = DATA_URL.fullmatch(value)
    if not match:
        return {'status': 'NOT_DATA_URL', 'sha256': digest(value)}
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        return {'status': 'UNDECODABLE', 'media_type': match.group(1), 'sha256': digest(value)}
    return {'status': 'DECODED', 'media_type': match.group(1),
            'sha256': hashlib.sha256(decoded).hexdigest(), 'bytes': len(decoded)}


def unknown(value, known):
    if not isinstance(value, dict):
        return None
    extra = sorted(k for k in value if k not in known)
    literal = [k for k in extra if re.fullmatch(r'x_bux_[a-z_]{1,32}', k)]
    other = [k for k in extra if k not in literal]
    return {'literal': literal, 'other_count': len(other), 'other_sha256': digest(other) if other else None}


def rank_class(ranks):
    try:
        values = [Decimal(r) for r in ranks]
    except (InvalidOperation, TypeError, ValueError):
        return 'INVALID'
    if not all(isinstance(r, str) for r in ranks) or not all(v.is_finite() for v in values):
        return 'INVALID'
    if any(b <= a for a, b in zip(values, values[1:])):
        return 'UNORDERED'
    if any(v != v.to_integral_value() for v in values):
        return 'FRACTIONAL'
    if values == [Decimal(n) for n in range(1, len(values) + 1)]:
        return 'DENSE_1_N'
    return 'GAPPED'


def fingerprint(parts):
    """Canonical semantic fingerprint of an ordered native part set. Order-sensitive.

    Rows are never de-duplicated or re-sorted. Unparseable parts are recorded as such and
    make the fingerprint incomplete; nothing is repaired.
    """
    result = {'schema': 'bux-r6-cnt-fingerprint-v1', 'parts': [], 'complete': True}
    rows, settings, code, top_unknown = [], None, None, []
    for index, raw in enumerate(parts):
        entry = {'index': index, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            value = None
        if not isinstance(value, dict):
            entry['parse'] = 'UNPARSEABLE'
            result['complete'] = False
            result['parts'].append(entry)
            continue
        entry['parse'] = 'PARSED'
        chunks = value.get('chunks')
        entry['chunk_count'] = len(chunks) if isinstance(chunks, list) else None
        entry['has_settings'] = 'settings' in value
        top_unknown.append(unknown(value, KNOWN_TOP))
        if 'settings' in value and settings is None:
            settings = value.get('settings')
            code = value.get('custom_code')
        result['parts'].append(entry)
        if not isinstance(chunks, list):
            result['complete'] = False
            continue
        for chunk in chunks:
            rows.append(row(chunk))
    result['rows'] = rows
    result['top_unknown'] = top_unknown
    result['settings'] = settings_projection(settings)
    result['custom_code'] = ({k: {'sha256': digest(code.get(k)), 'length': len(code.get(k))
                                  if isinstance(code.get(k), str) else None} for k in KNOWN_CODE}
                             | {'unknown': unknown(code, KNOWN_CODE)} if isinstance(code, dict) else None)
    result['derived'] = derived(rows)
    result['sha256'] = digest({k: v for k, v in result.items() if k != 'sha256'})
    result['semantic_sha256'] = digest(semantic(result))
    return result


def row(chunk):
    if not isinstance(chunk, dict):
        return {'shape': 'NOT_OBJECT'}
    data = chunk.get('data') if isinstance(chunk.get('data'), dict) else {}
    file = chunk.get('file') if isinstance(chunk.get('file'), dict) else {}
    thumb = chunk.get('thumbnail') if isinstance(chunk.get('thumbnail'), dict) else {}
    tasks = chunk.get('tasks') if isinstance(chunk.get('tasks'), list) else None
    return {'id': scalar(data.get('id')), 'rank': scalar(data.get('i')), 'type': scalar(data.get('type')),
            'presentation': {k: scalar(data.get(k)) for k in KNOWN_DATA if k not in ('id', 'i', 'type')
                             and k in data},
            'theme_id_present': 'theme_id' in data,
            'file': {'name_sha256': digest(file.get('name')) if 'name' in file else None,
                     'type': scalar(file.get('type')), 'last_modified': scalar(file.get('last_modified')),
                     'content': content_digest(file.get('background'))},
            'thumbnail': content_digest(thumb.get('background')),
            'tasks': None if tasks is None else [task(t) for t in tasks],
            'unknown': {'row': unknown(chunk, KNOWN_ROW), 'data': unknown(data, KNOWN_DATA),
                        'file': unknown(file, KNOWN_FILE)}}


def task(value):
    if not isinstance(value, dict):
        return {'shape': 'NOT_OBJECT'}
    return {**{k: scalar(value.get(k)) for k in KNOWN_TASK if k in value},
            'unknown': unknown(value, KNOWN_TASK)}


def settings_projection(settings):
    if not isinstance(settings, dict) or not isinstance(settings.get('prefs'), dict):
        return None
    prefs = settings['prefs']
    return {'prefs': {k: scalar(v) for k, v in sorted(prefs.items()) if not k.startswith('x_bux_')},
            'volatile': sorted(k for k in VOLATILE_PREFS if k in prefs),
            'unknown_literal': sorted(k for k in prefs if re.fullmatch(r'x_bux_[a-z_]{1,32}', k)),
            'settings_unknown': unknown(settings, ('prefs',))}


def derived(rows):
    ids = [r.get('id') for r in rows]
    contents = [((r.get('file') or {}).get('content') or {}).get('sha256') for r in rows]
    ranks = [r.get('rank') for r in rows]
    return {'row_count': len(rows), 'distinct_ids': len({json.dumps(i) for i in ids}),
            'distinct_contents': len({c for c in contents if c}),
            'duplicate_content_groups': _groups(contents), 'duplicate_id_groups': _groups(ids),
            'rank_class': rank_class(ranks) if rows else 'EMPTY',
            'task_count': sum(len(r.get('tasks') or []) for r in rows)}


def _groups(values):
    buckets = {}
    for index, value in enumerate(values):
        if value is not None:
            buckets.setdefault(json.dumps(value, sort_keys=True), []).append(index)
    return sorted(v for v in buckets.values() if len(v) > 1)


def semantic(fp):
    """Fingerprint without byte identities and volatile prefs, for state comparison only.

    Volatile prefs are listed explicitly in the full fingerprint; they are excluded here and
    only here, and the exclusion list is part of the output.
    """
    settings = fp.get('settings')
    if settings is not None:
        settings = dict(settings, prefs={k: v for k, v in settings['prefs'].items() if k not in VOLATILE_PREFS})
    return {'rows': fp.get('rows'), 'settings': settings, 'custom_code': fp.get('custom_code'),
            'top_unknown': fp.get('top_unknown'), 'excluded_volatile': list(VOLATILE_PREFS)}


# --- Classification -------------------------------------------------------------------------

COMPONENT_CLASSES = ('RESTORED', 'PRESERVED', 'DISPLACED', 'MERGED', 'REPLACED', 'NORMALIZED',
                     'IGNORED', 'RETAINED_UNKNOWN', 'REJECTED_STATE_PRESERVED',
                     'REJECTED_STATE_DESTROYED', 'PARTIAL', 'LOST', 'UNCLASSIFIED_DIFFERENCE',
                     'INCOMPLETE_EVIDENCE')
RANK_CLASSES = ('RANK_PRESERVED', 'RANK_NORMALIZED', 'INCOMPLETE_EVIDENCE')
REPEAT_CLASSES = ('IDEMPOTENT', 'DUPLICATED', 'LOST', 'CHANGED', 'REJECTED_ON_REPEAT', 'INCOMPLETE_EVIDENCE')


def _identity(r):
    return json.dumps({'id': r.get('id'), 'content': ((r.get('file') or {}).get('content') or {}).get('sha256')},
                      sort_keys=True)


def _content(r):
    return json.dumps(((r.get('file') or {}).get('content') or {}).get('sha256'))


def usable(fp):
    return isinstance(fp, dict) and fp.get('complete') is True and isinstance(fp.get('rows'), list)


def classify_backgrounds(pre, given, post, *, restore_error):
    """Pre-target, restore input and persisted post fingerprints. Absence is never a verdict."""
    if not (usable(pre) and usable(post)) or restore_error is None:
        return 'INCOMPLETE_EVIDENCE'
    before = [_identity(r) for r in pre['rows']]
    after = [_identity(r) for r in post['rows']]
    if restore_error:
        if after == before:
            return 'REJECTED_STATE_PRESERVED'
        if before and not set(before) & set(after):
            return 'REJECTED_STATE_DESTROYED'
        return 'PARTIAL'
    if not usable(given):
        return 'INCOMPLETE_EVIDENCE'
    wanted = [_identity(r) for r in given['rows']]
    if after == wanted:
        return 'DISPLACED' if before and not set(before) & set(after) and before != wanted else 'RESTORED'
    if before and after == before:
        return 'PRESERVED' if wanted else 'IGNORED'
    if before and set(before) <= set(after) and set(wanted) <= set(after):
        return 'MERGED'
    if sorted(map(_content, post['rows'])) == sorted(map(_content, given['rows'])):
        return 'NORMALIZED'
    if after and set(after) < set(wanted):
        return 'PARTIAL'
    if not after and (before or wanted):
        return 'LOST'
    return 'UNCLASSIFIED_DIFFERENCE'


def classify_component(pre, given, post, component, *, restore_error):
    """settings or custom_code: compared semantically, volatile prefs excluded."""
    if not (usable(pre) and usable(post)) or restore_error is None:
        return 'INCOMPLETE_EVIDENCE'
    view = lambda fp: semantic(fp).get(component)
    before, after = view(pre), view(post)
    if restore_error:
        return 'REJECTED_STATE_PRESERVED' if after == before else 'REJECTED_STATE_DESTROYED'
    if not usable(given):
        return 'INCOMPLETE_EVIDENCE'
    wanted = view(given)
    if after == wanted:
        return 'REPLACED' if before != wanted else 'RESTORED'
    if after == before:
        return 'PRESERVED'
    return 'NORMALIZED'


def classify_tasks(pre, given, post, *, restore_error):
    if not (usable(pre) and usable(post)) or restore_error is None:
        return 'INCOMPLETE_EVIDENCE'
    flat = lambda fp: [json.dumps(t, sort_keys=True) for r in fp['rows'] for t in (r.get('tasks') or [])]
    before, after = flat(pre), flat(post)
    if restore_error:
        return 'REJECTED_STATE_PRESERVED' if after == before else (
            'REJECTED_STATE_DESTROYED' if before else 'PARTIAL' if after else 'REJECTED_STATE_PRESERVED')
    if not usable(given):
        return 'INCOMPLETE_EVIDENCE'
    wanted = flat(given)
    if after == wanted:
        return 'DISPLACED' if before and not set(before) & set(after) else 'RESTORED'
    if before and set(before) <= set(after) and set(wanted) <= set(after):
        return 'MERGED'
    if not after and (before or wanted):
        return 'LOST'
    return 'NORMALIZED' if len(after) == len(wanted) else 'PARTIAL'


def classify_ranks(given, post):
    if not (usable(given) and usable(post)):
        return 'INCOMPLETE_EVIDENCE'
    ranks = lambda fp: {json.dumps(r.get('id')): r.get('rank') for r in fp['rows']}
    wanted, observed = ranks(given), ranks(post)
    shared = set(wanted) & set(observed)
    if not shared:
        return 'INCOMPLETE_EVIDENCE'
    return 'RANK_PRESERVED' if all(wanted[k] == observed[k] for k in shared) else 'RANK_NORMALIZED'


def classify_repeat(first, second, *, restore_errors):
    """Native repeat import: X1 after the first restore, X2 after the second. No de-duplication.

    Both restores must have ended with an observed no-error completion (False); a loud
    rejection of the second import is its own class, and unknown (None) is never a verdict.
    """
    errors = tuple(restore_errors)
    if len(errors) != 2 or errors[0] is not False or errors[1] is None:
        return 'INCOMPLETE_EVIDENCE'
    if errors[1] is True:
        return 'REJECTED_ON_REPEAT'
    if not (usable(first) and usable(second)):
        return 'INCOMPLETE_EVIDENCE'
    one = [_identity(r) for r in first['rows']]
    two = [_identity(r) for r in second['rows']]
    if semantic(first) == semantic(second):
        return 'IDEMPOTENT'
    if len(two) > len(one) and all(two.count(x) >= one.count(x) for x in set(one)):
        return 'DUPLICATED'
    if len(two) < len(one):
        return 'LOST'
    return 'CHANGED'


def classify_unknown(post, mutation):
    """Whether a bounded x_bux_* key survived the native import at its declared object."""
    if not usable(post) or mutation not in MUTATIONS or MUTATIONS[mutation][0] != 'insert':
        return 'INCOMPLETE_EVIDENCE'
    key = MUTATIONS[mutation][2]
    if mutation == 'unknown_top_level':
        found = any(key in (u or {}).get('literal', []) for u in post['top_unknown'])
    elif mutation == 'unknown_pref':
        found = key in ((post.get('settings') or {}).get('unknown_literal') or [])
    elif mutation == 'unknown_custom_code':
        found = key in (((post.get('custom_code') or {}).get('unknown') or {}).get('literal') or [])
    elif mutation == 'unknown_background_data':
        found = any(key in (((r.get('unknown') or {}).get('data') or {}).get('literal') or [])
                    for r in post['rows'])
    else:
        found = any(key in ((t.get('unknown') or {}).get('literal') or [])
                    for r in post['rows'] for t in (r.get('tasks') or []))
    return 'RETAINED_UNKNOWN' if found else 'IGNORED'


# --- S-RICH source coverage and readiness (bux-r6-rich-readiness-v1) ---------------------------
# Every value is computed from the in-memory fingerprint of the native export. Row and task ids
# are compared here and never returned: the coverage holds fixed enums, counts and booleans.

OBSERVED, NOT_OBSERVED = 'OBSERVED', 'NOT_OBSERVED'
READINESS_SCHEMA = 'bux-r6-rich-readiness-v1'
# Custom code entered through the accepted CodeMirror library adapter (seed setup only).
RICH_CODE = ('<p>BUX R6 rich fixture</p>', 'p { color: rgb(1, 2, 3); }', 'void "bux-r6";')
TARGET_BINDINGS = ('REACT_FIBER_READ', 'NOT_BOUND')


def _same(observed, expected):
    return type(observed) is type(expected) and observed == expected


def _enum(ok):
    return OBSERVED if ok else NOT_OBSERVED


def _rows(fp):
    return fp['rows'] if usable(fp) else []


def row_contract(fp):
    """Export order is the rendered order: chunks follow the in-memory collection unsorted
    (backup.chunk_order), which renders in ascending rank (ui.background_render_order). So a
    rendered position maps to an exported row only when every rank is a string and the ranks
    strictly ascend in export order, and every row id is present and unique."""
    rows = _rows(fp)
    ids = [r.get('id') for r in rows]
    return (bool(rows) and rank_class([r.get('rank') for r in rows]) in ('DENSE_1_N', 'GAPPED', 'FRACTIONAL')
            and all(i is not None for i in ids) and not _groups(ids))


def task_matches(value, expected):
    """Strict type and value match of every non-background field the fixture specifies."""
    return isinstance(value, dict) and all(_same(value.get(k), v) for k, v in expected.items()
                                           if k != 'background_position')


def task_relations(fp, expected_tasks):
    """(fields, background) per expected task, each OBSERVED or NOT_OBSERVED.

    fields: exactly one exported task matches the specified non-background fields.
    background: that task sits in the row at its intended rendered position under the row
    contract, and its background_id equals that row's id (compared here, never exported).
    A task on another existing background, a no-op click (the previous task's background) or
    a deleted row all fail.
    """
    rows, contract = _rows(fp), row_contract(fp)
    tasks = [(n, t) for n, r in enumerate(rows) for t in (r.get('tasks') or []) if isinstance(t, dict)]
    fields, background = [], []
    for expected in expected_tasks:
        found = [(n, t) for n, t in tasks if task_matches(t, expected)]
        at = expected['background_position'] - 1
        fields.append(_enum(len(found) == 1))
        background.append(_enum(
            len(found) == 1 and contract and 0 <= at < len(rows) and found[0][0] == at
            and found[0][1].get('background_id') is not None
            and _same(found[0][1].get('background_id'), rows[at].get('id'))))
    return fields, background


def row_order(fp, expected):
    """The seeded rows in rendered order: string ranks with the verified values (compared as
    decimals) and the expected equal-content positions. Upload bytes are not assumed to be
    preserved; only which positions share content."""
    rows = _rows(fp)
    ranks = [r.get('rank') for r in rows]
    if len(rows) != len(expected['ranks']) or rank_class(ranks) == 'INVALID':
        return NOT_OBSERVED
    contents = [((r.get('file') or {}).get('content') or {}) for r in rows]
    groups = expected['duplicate_content_groups']
    return _enum([Decimal(r) for r in ranks] == [Decimal(r) for r in expected['ranks']]
                 and all(c.get('status') == 'DECODED' for c in contents)
                 and _groups([c.get('sha256') for c in contents]) == groups)


def override_background(fp, provenance):
    """The per-background override is on the row clicked for it (rendered position
    rich_rows.override_position) and on no other row."""
    rows, (name, value) = _rows(fp), provenance['rich_override']
    at = provenance['rich_rows']['override_position'] - 1
    carriers = [n for n, r in enumerate(rows) if _same((r.get('presentation') or {}).get(name), value)]
    return _enum(row_contract(fp) and carriers == [at])


def rich_coverage(fp, provenance, bindings=None):
    """Fixed-shape S-RICH coverage of one fingerprint. `bindings` are the page-side task
    target bindings the seed recorded (never part of readiness)."""
    prefs = ((fp.get('settings') or {}).get('prefs') or {}) if usable(fp) else {}
    coverage = {name: _enum(_same(prefs.get(name), value)) for _, name, value in provenance['rich_prefs']}
    rows = _rows(fp)
    counts = fp['derived'] if usable(fp) else derived([])
    fields, background = task_relations(fp, provenance['rich_tasks'])
    code = (fp.get('custom_code') or {}) if usable(fp) else {}
    ids = [r.get('id') for r in rows]
    coverage.update(
        rank_class=counts['rank_class'], task_count=counts['task_count'], row_count=len(rows),
        duplicate_content=bool(counts['duplicate_content_groups']),
        duplicate_identity=bool(counts['duplicate_id_groups']),
        row_identity=_enum(bool(rows) and all(i is not None for i in ids) and not _groups(ids)),
        row_order=row_order(fp, provenance['rich_rows']),
        per_background_override=any(_same((r.get('presentation') or {}).get(provenance['rich_override'][0]),
                                          provenance['rich_override'][1]) for r in rows),
        override_background=override_background(fp, provenance),
        # Seed setup only (manager-ratified): never evidence of native typing.
        custom_code_input='LIBRARY_ADAPTER',
        custom_code={kind: _enum((code.get(kind) or {}).get('sha256') == digest(value))
                     for kind, value in zip(KNOWN_CODE, RICH_CODE)},
        task_fields=fields, task_background=background,
        task_target_binding=[b if b in TARGET_BINDINGS else 'NOT_BOUND' for b in bindings]
        if bindings is not None else None)
    return coverage


def rich_requirements(provenance):
    """The fixed, ordered S-RICH source-readiness requirement ids (pinned by tests)."""
    ids = [f'pref:{name}' for _, name, _ in provenance['rich_prefs']]
    ids += ['override:' + provenance['rich_override'][0], 'rows:count', 'rows:order', 'rows:rank_class',
            'rows:duplicate_content', 'rows:distinct_identity', 'tasks:count']
    for n in range(1, len(provenance['rich_tasks']) + 1):
        ids += [f'task:{n}:fields', f'task:{n}:background']
    return ids + [f'custom_code:{kind}' for kind in KNOWN_CODE]


def rich_readiness(coverage, provenance):
    """{'schema', 'ready', 'missing'}: ready only when every requirement holds. `missing`
    lists fixed requirement ids in requirement order; malformed coverage misses all."""
    c = coverage if isinstance(coverage, dict) else {}
    rows = provenance['rich_rows']
    def listed(key, n):
        value = c.get(key)
        return value[n] if isinstance(value, list) and len(value) > n else None
    def holds(requirement):
        kind, _, rest = requirement.partition(':')
        if kind == 'pref':
            return c.get(rest) == OBSERVED
        if kind == 'custom_code':
            return isinstance(c.get('custom_code'), dict) and c['custom_code'].get(rest) == OBSERVED
        if kind == 'task':
            number, field = rest.split(':')
            return listed('task_fields' if field == 'fields' else 'task_background', int(number) - 1) == OBSERVED
        return {'override:' + provenance['rich_override'][0]: c.get('override_background') == OBSERVED,
                'rows:count': _same(c.get('row_count'), len(rows['ranks'])),
                'rows:order': c.get('row_order') == OBSERVED,
                'rows:rank_class': c.get('rank_class') == 'FRACTIONAL',
                'rows:duplicate_content': c.get('duplicate_content') is True,
                'rows:distinct_identity': c.get('row_identity') == OBSERVED and c.get('duplicate_identity') is False,
                'tasks:count': _same(c.get('task_count'), len(provenance['rich_tasks']))}[requirement]
    missing = [r for r in rich_requirements(provenance) if not holds(r)]
    return {'schema': READINESS_SCHEMA, 'ready': not missing, 'missing': missing}


SOURCE_READINESS_KEYS = {'S-RICH': ('rich_source_ready', 'rich_source_missing'),
                         'S-MULTI': ('multi_source_ready', 'multi_source_missing')}


def source_ready(facts, entry):
    """Consumer gate: an S-RICH or S-MULTI source is usable only with its own recorded readiness
    true (and nothing missing) on the consumed artifact. Any other source keeps the old gate."""
    if entry.get('source') not in SOURCE_READINESS_KEYS:
        return True
    ready, missing = SOURCE_READINESS_KEYS[entry['source']]
    classes = facts.get('classifications') if isinstance(facts.get('classifications'), dict) else {}
    artifact = ((facts.get('artifacts') or {}).get(entry.get('artifact')) or {})
    return (classes.get(ready) is True and classes.get(missing) == []
            and isinstance(artifact, dict) and artifact.get('source_ready') is True)


def prediction_status(prediction, observed):
    if prediction is None:
        return 'NONE'
    if observed in (None, 'INCOMPLETE_EVIDENCE'):
        return 'UNOBSERVED'
    return 'MATCH' if observed == prediction else 'MISMATCH'


# --- Rich-valid restore evidence (bux-r6-restore-evidence-v1) -----------------------------------
# Observation only, never a gate or a verdict on native success: fixed enums, counts, booleans and
# digests computed from in-memory fingerprints. Row and task ids are compared here and never
# returned. Every function is total: malformed or missing input gives INCOMPLETE_EVIDENCE or None.

RESTORE_EVIDENCE_SCHEMA = 'bux-r6-restore-evidence-v1'
RICH_VALID_EVIDENCE = ('T-RICH', 'T-DISPLACE', 'F-REPEAT')
SEMANTIC_RELATIONS = ('SEMANTIC_EQUAL', 'SEMANTIC_DIFFERENT', 'INCOMPLETE_EVIDENCE')
PRIOR_STATES = ('REMOVED', 'RETAINED', 'PARTIALLY_RETAINED', 'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE')
DISPLACEMENT_CLASSES = ('REPLACES', 'MERGES', 'PRESERVES_PRIOR', 'TRANSFORMS', 'REJECTED_STATE_PRESERVED',
                        'REJECTED_STATE_ALTERED', 'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE')
IDEMPOTENCE_CLASSES = ('IDEMPOTENT', 'NOT_IDEMPOTENT', 'REJECTED_ON_REPEAT_STATE_PRESERVED',
                       'REJECTED_ON_REPEAT_STATE_ALTERED', 'INCOMPLETE_EVIDENCE')
LIVE_DATA_SCOPE = 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
SEQUENCE_STEPS = ('restore', 'reload', 'post_export', 'repeat_export')
STEP_STATUSES = ('STARTED', 'DONE', 'FAILED', 'SKIPPED_NOT_SETTABLE')
COMPLETIONS = ('COMPLETED', 'ERROR_REPORTED', 'SILENT_REPORTED', 'DEADLINE_NO_SIGNAL')
CLOSURES = ('CLOSED', 'UNCLOSED', 'ROWS_SHORT', 'ROWS_EXCESS', 'PART_SEQUENCE_BROKEN', 'UNPARSEABLE_PART')
_MALFORMED = (TypeError, ValueError, AttributeError, KeyError, IndexError, InvalidOperation, RecursionError)


def _fixed(value, allowed):
    return value if isinstance(value, (str, bool)) and value in allowed else None


def _well_formed(fp):
    """A usable fingerprint whose rows, tasks, settings and custom code have the fingerprint shape."""
    if not usable(fp) or not all(isinstance(r, dict) for r in fp['rows']):
        return False
    settings, code = fp.get('settings'), fp.get('custom_code')
    shaped = lambda value, key: key not in value or isinstance(value[key], dict)
    return ((settings is None or (isinstance(settings, dict) and isinstance(settings.get('prefs'), dict)))
            and (code is None or (isinstance(code, dict) and all(shaped(code, k) for k in KNOWN_CODE)))
            and all(shaped(r, 'file') and shaped(r, 'presentation')
                    and (r.get('tasks') is None or (isinstance(r['tasks'], list)
                                                    and all(isinstance(t, dict) for t in r['tasks'])))
                    for r in fp['rows']))


def _content_sha(r):
    file = r.get('file')
    content = file.get('content') if isinstance(file, dict) else None
    return content.get('sha256') if isinstance(content, dict) else None


def _row_key(r):
    return json.dumps({'id': r.get('id'), 'content': _content_sha(r)}, sort_keys=True)


def _task_keys(fp):
    return [json.dumps(t, sort_keys=True) for r in fp['rows'] for t in (r.get('tasks') or [])]


def _code_sha(fp, kind):
    code = fp.get('custom_code')
    value = code.get(kind) if isinstance(code, dict) else None
    return value.get('sha256') if isinstance(value, dict) else None


def semantic_sha256(fp):
    """Digest of the maintained semantic view (volatile prefs excluded), recomputed; or None."""
    try:
        return digest(semantic(fp)) if _well_formed(fp) else None
    except _MALFORMED:
        return None


def semantic_relation(a, b):
    """SEMANTIC_EQUAL / SEMANTIC_DIFFERENT under the maintained semantic view, else incomplete."""
    try:
        if not (_well_formed(a) and _well_formed(b)):
            return 'INCOMPLETE_EVIDENCE'
        return 'SEMANTIC_EQUAL' if semantic(a) == semantic(b) else 'SEMANTIC_DIFFERENT'
    except _MALFORMED:
        return 'INCOMPLETE_EVIDENCE'


def restored_rich(post, provenance):
    """T-RICH: the S-RICH coverage contract applied to the post-restore export. Seed-only fields
    (the custom-code input route and page-side task target binding) are not restore observations;
    the seed route is disclosed instead. `requirements.met` is restored coverage, never S-RICH
    source readiness, and is not a native pass."""
    evidence = 'OBSERVED'
    try:
        coverage = rich_coverage(post if _well_formed(post) else {}, provenance, None)
    except _MALFORMED:
        coverage, evidence = rich_coverage({}, provenance, None), 'INCOMPLETE_EVIDENCE'
    if not _well_formed(post):
        evidence = 'INCOMPLETE_EVIDENCE'
    coverage.pop('task_target_binding', None)
    coverage.pop('custom_code_input', None)
    readiness = rich_readiness(coverage, provenance)
    return {**coverage, 'evidence': evidence, 'source_seed_custom_code_input': 'LIBRARY_ADAPTER',
            'requirements': {'schema': readiness['schema'], 'met': readiness['ready'],
                             'missing': readiness['missing']}}


def prior_residue(pre, given, post):
    """Counts of prior (pre-restore) state still present after the restore. A prior item counts
    only when it is distinguishable: the restore input does not carry the same item. Custom code
    per kind is True (the prior digest remains), False, or None (not distinguishable)."""
    try:
        if not all(_well_formed(fp) for fp in (pre, given, post)):
            return None
        contents = lambda fp: {c for c in (_content_sha(r) for r in fp['rows']) if c}
        wanted_rows, after_rows = {_row_key(r) for r in given['rows']}, {_row_key(r) for r in post['rows']}
        prior_rows = [k for k in (_row_key(r) for r in pre['rows']) if k not in wanted_rows]
        prior_contents = contents(pre) - contents(given)
        wanted_tasks, after_tasks = set(_task_keys(given)), set(_task_keys(post))
        prior_tasks = [k for k in _task_keys(pre) if k not in wanted_tasks]
        code = {}
        for kind in KNOWN_CODE:
            before, wanted, after = (_code_sha(fp, kind) for fp in (pre, given, post))
            code[kind] = None if before is None or before == wanted else after == before
        return {'prior_rows': len(pre['rows']), 'prior_rows_distinguishable': len(prior_rows),
                'prior_rows_remaining': sum(k in after_rows for k in prior_rows),
                'prior_contents_distinguishable': len(prior_contents),
                'prior_contents_remaining': len(prior_contents & contents(post)),
                'prior_tasks': len(_task_keys(pre)), 'prior_tasks_distinguishable': len(prior_tasks),
                'prior_tasks_remaining': sum(k in after_tasks for k in prior_tasks),
                'prior_custom_code_remaining': code, 'post_rows': len(post['rows'])}
    except _MALFORMED:
        return None


def prior_state(residue):
    """Whether distinguishable prior state was removed, kept or partly kept (from prior_residue)."""
    try:
        code = [v for v in residue['prior_custom_code_remaining'].values() if v is not None]
        pairs = [(residue[f'prior_{k}_remaining'], residue[f'prior_{k}_distinguishable'])
                 for k in ('rows', 'contents', 'tasks')] + [(int(v), 1) for v in code]
        if not all(type(a) is int and type(b) is int and 0 <= a <= b for a, b in pairs):
            return 'INCOMPLETE_EVIDENCE'
    except _MALFORMED:
        return 'INCOMPLETE_EVIDENCE'
    if not sum(b for _, b in pairs):
        return 'NOT_DISCRIMINATING'
    if not sum(a for a, _ in pairs):
        return 'REMOVED'
    return 'RETAINED' if all(a == b for a, b in pairs) else 'PARTIALLY_RETAINED'


def classify_displacement(pre, given, post, *, restore_error):
    """T-DISPLACE, a fixed rule set in which the first matching rule wins. `≡` is the maintained
    semantic view (volatile prefs excluded); settings, tasks and custom code enter only through
    `≡` and the prior residue, and the per-component classes are reported beside the result.

    1. restore_error unknown (None), or pre or post not well formed: INCOMPLETE_EVIDENCE.
    2. restore_error True: REJECTED_STATE_PRESERVED if post ≡ pre, else REJECTED_STATE_ALTERED.
    3. given not well formed: INCOMPLETE_EVIDENCE.
    4. pre ≡ given, or no prior item is distinguishable from the input: NOT_DISCRIMINATING.
    5. post ≡ given and prior state REMOVED: REPLACES (the input kept exactly, nothing prior left).
    6. post ≡ pre: PRESERVES_PRIOR.
    7. prior state RETAINED or PARTIALLY_RETAINED and every input content present: MERGES.
    8. otherwise: TRANSFORMS (for example prior state removed but the input not kept exactly:
       re-identified rows, normalized ranks, changed settings or custom code).

    REPLACES describes synthetic sentinel state only; it is never a claim that destructive
    displacement is safe for live user data."""
    try:
        if restore_error is None or not (_well_formed(pre) and _well_formed(post)):
            return 'INCOMPLETE_EVIDENCE'
        if restore_error is True:
            return ('REJECTED_STATE_PRESERVED' if semantic(post) == semantic(pre)
                    else 'REJECTED_STATE_ALTERED')
        if restore_error is not False or not _well_formed(given):
            return 'INCOMPLETE_EVIDENCE'
        state = prior_state(prior_residue(pre, given, post))
        if state == 'INCOMPLETE_EVIDENCE':
            return 'INCOMPLETE_EVIDENCE'
        if semantic(pre) == semantic(given) or state == 'NOT_DISCRIMINATING':
            return 'NOT_DISCRIMINATING'
        if semantic(post) == semantic(given) and state == 'REMOVED':
            return 'REPLACES'
        if semantic(post) == semantic(pre):
            return 'PRESERVES_PRIOR'
        wanted = {c for c in (_content_sha(r) for r in given['rows']) if c}
        present = {_content_sha(r) for r in post['rows']}
        if state in ('RETAINED', 'PARTIALLY_RETAINED') and wanted <= present:
            return 'MERGES'
        return 'TRANSFORMS'
    except _MALFORMED:
        return 'INCOMPLETE_EVIDENCE'


def repeat_identity(first, second, *, restore_errors):
    """F-REPEAT: the maintained repeat class plus an idempotence class. A rejected second restore
    is its own class (state preserved or altered), not NOT_IDEMPOTENT. Byte and volatile-pref
    differences are always disclosed, so the semantic view never hides a normalization."""
    try:
        repeat = classify_repeat(first, second, restore_errors=restore_errors)
    except _MALFORMED:
        repeat = 'INCOMPLETE_EVIDENCE'
    out = {'repeat_class': repeat, 'idempotence': 'INCOMPLETE_EVIDENCE',
           'first_semantic_sha256': semantic_sha256(first), 'second_semantic_sha256': semantic_sha256(second),
           'semantic_equal': None, 'part_bytes_equal': None, 'volatile_prefs_equal': None,
           'excluded_volatile': list(VOLATILE_PREFS), 'row_counts': None, 'task_counts': None}
    try:
        if _well_formed(first) and _well_formed(second):
            parts = lambda fp: [(p.get('bytes'), p.get('sha256')) for p in fp.get('parts') or []]
            volatile = lambda fp: {k: ((fp.get('settings') or {}).get('prefs') or {}).get(k) for k in VOLATILE_PREFS}
            out.update(semantic_equal=semantic(first) == semantic(second),
                       part_bytes_equal=bool(parts(first)) and parts(first) == parts(second),
                       volatile_prefs_equal=volatile(first) == volatile(second),
                       row_counts=[len(first['rows']), len(second['rows'])],
                       task_counts=[len(_task_keys(first)), len(_task_keys(second))])
    except _MALFORMED:
        return out
    if repeat == 'IDEMPOTENT':
        out['idempotence'] = 'IDEMPOTENT'
    elif repeat in ('DUPLICATED', 'LOST', 'CHANGED'):
        out['idempotence'] = 'NOT_IDEMPOTENT'
    elif repeat == 'REJECTED_ON_REPEAT' and out['semantic_equal'] is not None:
        out['idempotence'] = ('REJECTED_ON_REPEAT_STATE_PRESERVED' if out['semantic_equal']
                              else 'REJECTED_ON_REPEAT_STATE_ALTERED')
    return out


def restore_sequence(record):
    """Fixed-shape status of the restore path: steps, each restore's completion, export closure."""
    steps = [s for s in record.get('steps') or [] if isinstance(s, dict)]
    restores = [r for r in record.get('restores') or [] if isinstance(r, dict)]
    artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
    closure = lambda label: _fixed((artifacts.get(label) or {}).get('closure')
                                   if isinstance(artifacts.get(label), dict) else None, CLOSURES)
    return {'steps': [{'step': s['step'], 'status': _fixed(s.get('status'), STEP_STATUSES)}
                      for s in steps if _fixed(s.get('step'), SEQUENCE_STEPS)],
            'restores': [{'completion': _fixed(r.get('completion'), COMPLETIONS),
                          'restore_error': _fixed(r.get('restore_error'), (True, False)),
                          'start_observed': _fixed(r.get('start_observed'), (True, False))} for r in restores],
            'post_closure': closure('post'), 'repeat_closure': closure('repeat')}


def restore_evidence(entry, fingerprints, given, record, provenance):
    """The fixed per-case evidence for T-RICH, T-DISPLACE and F-REPEAT; None for other cases."""
    case_id = entry.get('id') if isinstance(entry, dict) else None
    if case_id not in RICH_VALID_EVIDENCE:
        return None
    try:
        fps = fingerprints if isinstance(fingerprints, dict) else {}
        record = record if isinstance(record, dict) else {}
        pre, post, repeat = fps.get('pre'), fps.get('post'), fps.get('repeat')
        restores = [r for r in record.get('restores') or [] if isinstance(r, dict)]
        errors = [r.get('restore_error') for r in restores]
        classes = record.get('classifications') if isinstance(record.get('classifications'), dict) else {}
        out = {'schema': RESTORE_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'OBSERVED',
               'given_semantic_sha256': semantic_sha256(given), 'pre_semantic_sha256': semantic_sha256(pre),
               'post_semantic_sha256': semantic_sha256(post), 'post_vs_given': semantic_relation(post, given),
               'post_vs_pre': semantic_relation(post, pre), 'restore_sequence': restore_sequence(record)}
        if case_id == 'T-RICH':
            out['restored_rich'] = restored_rich(post, provenance)
        elif case_id == 'T-DISPLACE':
            residue = prior_residue(pre, given, post)
            out.update(sentinel_pre={'contract': 'SEEDED_SENTINEL_V1', 'semantic_sha256': semantic_sha256(pre),
                                     'row_count': len(pre['rows']) if _well_formed(pre) else None,
                                     'task_count': len(_task_keys(pre)) if _well_formed(pre) else None},
                       components={k: _fixed(classes.get(k), COMPONENT_CLASSES)
                                   for k in ('backgrounds', 'tasks', 'settings', 'custom_code')},
                       prior_residue=residue, prior_state=prior_state(residue),
                       displacement=classify_displacement(pre, given, post,
                                                          restore_error=errors[0] if errors else None),
                       live_data_scope=LIVE_DATA_SCOPE)
        else:
            out.update(repeat_semantic_sha256=semantic_sha256(repeat),
                       repeat_vs_given=semantic_relation(repeat, given),
                       repeat_identity=repeat_identity(post, repeat, restore_errors=errors))
        return out
    except _MALFORMED:
        return {'schema': RESTORE_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'INCOMPLETE_EVIDENCE'}


# --- Malformed-input D evidence (bux-r6-malformed-evidence-v2) ----------------------------------
# Observation only, never a gate, a verdict that a rejection is safe, or a live-data claim: fixed
# enums, counts, booleans and digests computed from in-memory fingerprints. Row and task ids are
# compared here and never returned. The sentinel component effects never read restore_error: they
# come from the pre, input, unmutated-source and post exports alone. Every function is total.
# v2 (REPORT-GATE1): restore_error is the observability-aware tri-state and the completion block
# carries report_observability, observability_gaps and pre_restore_error_ribbon.

MALFORMED_EVIDENCE_SCHEMA = 'bux-r6-malformed-evidence-v2'
# The fixed input class of each runnable D case (its catalogue mutation or selection).
MALFORMED_INPUT_CLASSES = {'D-TRUNC-P1': 'PART1_TRUNCATED', 'D-NO-CHUNKS': 'PART1_CHUNKS_ABSENT',
                           'D-CHUNKS-TYPE': 'PART1_CHUNKS_NOT_ARRAY', 'D-BAD-DATAURL': 'PART1_ROW1_DATA_URL_INVALID',
                           'D-NAME-NO-P1': 'VALID_PART_NAMED_PART_2'}
RESTORE_ERROR_STATES = ('TRUE', 'FALSE', 'UNKNOWN')
SENTINEL_EFFECTS = ('PRESERVED', 'REORDERED', 'RETAINED_WITH_ADDITIONS', 'PARTIALLY_RETAINED',
                    'REMOVED_OTHER_PRESENT', 'DESTROYED', 'REPLACED_BY_INPUT', 'REPLACED_BY_UNMUTATED_SOURCE',
                    'NORMALIZED', 'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE')
STATE_EFFECTS = ('STATE_PRESERVED', 'STATE_REPLACED_BY_INPUT', 'STATE_REPLACED_BY_UNMUTATED_SOURCE',
                 'SENTINEL_CONTENT_DESTROYED', 'STATE_PARTIALLY_RETAINED', 'STATE_ALTERED', 'INCOMPLETE_EVIDENCE')
MALFORMED_RANKS = ('RANK_PRESERVED', 'RANK_NORMALIZED', 'NOT_MEANINGFUL', 'INCOMPLETE_EVIDENCE')
RANK_SHAPES = ('INVALID', 'UNORDERED', 'FRACTIONAL', 'DENSE_1_N', 'GAPPED', 'EMPTY')
PREDICTION_SCOPE = 'PREDICTION_ONLY_NOT_ASSERTED'
PREDICTION_BASIS = 'LEGACY_CLASSIFIER_ON_RECORDED_RESTORE_ERROR'
PREDICTION_STATUSES = ('MATCH', 'MISMATCH', 'UNOBSERVED', 'NONE')
INPUT_SHAPES = {'parse': ('PARSED', 'UNPARSEABLE'), 'chunks': ('ARRAY', 'ABSENT', 'NOT_ARRAY'),
                'row1_content': ('DECODED', 'UNDECODABLE', 'NOT_DATA_URL', 'NOT_STRING')}
D_TARGETS = ('chunks', 'chunks.0.file.background')
# Report codes. The page wrapper sees only calls made through the global show_err_ribbon binding
# (ui.error_ribbon). A code leaves verbatim only as a (code, silent) pair of a VERIFIED or CORRECTED
# report.* fact on that route; anything else is UNRECOGNIZED_REPORT_PRESENT, never the raw token.
# Restore-path reports go through the module-local route (restore.report_route, report.local_route):
# they surface only as error-ribbon visibility, never as codes.
REPORT_ROUTE = 'GLOBAL_SHOW_ERR_RIBBON'
REPORT_UNRECOGNIZED = 'UNRECOGNIZED_REPORT_PRESENT'
REPORT_CODE = re.compile(r'[a-z]{2,4}_[0-9]{1,5}')
REPORT_CODES = frozenset({('cnt_1436', True)})
RESTORE_ROUTE_CODES = 'NOT_OBSERVABLE_MODULE_LOCAL_ROUTE'
_ABSENT = object()


def report_allowlist(provenance):
    """(code, silent) pairs of the VERIFIED or CORRECTED report.* facts on the global route."""
    allow = set()
    for key, fact in (provenance.get('facts') or {}).items():
        value = fact.get('value') if isinstance(fact, dict) else None
        if (key.startswith('report.') and fact.get('status') in ('VERIFIED', 'CORRECTED')
                and isinstance(value, dict) and value.get('route') == REPORT_ROUTE
                and isinstance(value.get('code'), str) and REPORT_CODE.fullmatch(value['code'])
                and type(value.get('silent')) is bool):
            allow.add((value['code'], value['silent']))
    return frozenset(allow)


def report_projection(codes, silent, allow=None):
    """Ordered unique tokens: an allowlisted (code, silent) pair verbatim; anything else (OTHER, an
    unknown code, a known code with the other silent flag, a non-string) UNRECOGNIZED_REPORT_PRESENT."""
    allow = REPORT_CODES if allow is None else allow
    if not isinstance(codes, (list, tuple)):
        codes = [] if codes is None or codes == '' else [codes]
    out = []
    for code in codes:
        token = code if isinstance(code, str) and (code, silent) in allow else REPORT_UNRECOGNIZED
        if token not in out:
            out.append(token)
    return out


def restore_error_state(restore):
    """(TRUE | FALSE | UNKNOWN, consistent) of one recorded restore. SILENT_REPORTED and
    DEADLINE_NO_SIGNAL are always UNKNOWN, also beside a loud report; FALSE needs a COMPLETED restore
    recorded without error whose error ribbon was never seen. Any other pairing is UNKNOWN and
    inconsistent: a readable post-export never upgrades it."""
    if not isinstance(restore, dict):
        return 'UNKNOWN', False
    completion, recorded = restore.get('completion'), restore.get('restore_error')
    if completion == 'COMPLETED' and recorded is False and restore.get('error_ribbon_seen') is not True:
        return 'FALSE', True
    if completion == 'ERROR_REPORTED' and recorded is True:
        return 'TRUE', True
    if completion == 'SILENT_REPORTED' and recorded is None:
        return 'UNKNOWN', True
    if completion == 'DEADLINE_NO_SIGNAL' and (recorded is None or recorded is True):
        return 'UNKNOWN', True
    return 'UNKNOWN', False


# Report observability (REPORT-GATE1). A restore-path report reaches the page only as the error
# ribbon, so "no ribbon seen" proves no native error only when the static audit closed every
# suppression route (observability.* facts). The pinned constant must equal report_observability()
# of the provenance; anything short of FULLY_OBSERVABLE keeps a clean-looking restore UNKNOWN.
# Only CLOSED closes an obligation: OPEN and CONDITIONAL (closed on an unproved premise) are gaps.
REPORT_OBSERVABILITIES = ('FULLY_OBSERVABLE', 'PARTIAL_SUPPRESSION_UNRESOLVED')
OBSERVABILITY_OBLIGATIONS = {'ERROR_SILENT_PROPERTY': 'observability.error_silent_property',
                             'PREVENT_SUBSEQUENT_ERRORS': 'observability.prevent_subsequent_errors',
                             'RESTORE_THROW_COVERAGE': 'observability.restore_throw_coverage',
                             'RIBBON_PERSISTENCE': 'observability.ribbon_persistence'}
REPORT_OBSERVABILITY = 'PARTIAL_SUPPRESSION_UNRESOLVED'
OBSERVABILITY_GAPS = ('ERROR_SILENT_PROPERTY', 'PREVENT_SUBSEQUENT_ERRORS', 'RESTORE_THROW_COVERAGE',
                      'RIBBON_PERSISTENCE')
# The error ribbon read immediately before a D restore's file selection (session gate).
PRE_RESTORE_RIBBONS = ('HIDDEN', 'VISIBLE', 'UNREADABLE')
_HEX64 = re.compile(r'[0-9a-f]{64}')


def report_observability(provenance):
    """(enum, gaps). FULLY_OBSERVABLE only when the capture is the pinned XPI and every obligation
    is a VERIFIED or CORRECTED member-hash-bound fact resolved CLOSED; each other one is a gap."""
    p = provenance if isinstance(provenance, dict) else {}
    capture = p.get('capture') if isinstance(p.get('capture'), dict) else {}
    facts = p.get('facts') if isinstance(p.get('facts'), dict) else {}
    gaps = []
    for gap, key in OBSERVABILITY_OBLIGATIONS.items():
        fact = facts.get(key) if isinstance(facts.get(key), dict) else {}
        value = fact.get('value') if isinstance(fact.get('value'), dict) else {}
        if not (capture.get('xpi_sha256') == XPI_SHA256 and fact.get('status') in ('VERIFIED', 'CORRECTED')
                and isinstance(fact.get('member_sha256'), str) and _HEX64.fullmatch(fact['member_sha256'])
                and value.get('obligation') == gap and value.get('resolution') == 'CLOSED'):
            gaps.append(gap)
    return ('PARTIAL_SUPPRESSION_UNRESOLVED' if gaps else 'FULLY_OBSERVABLE'), tuple(gaps)


def malformed_restore_error_state(restore, observability, pre_ribbon):
    """(TRUE | FALSE | UNKNOWN, consistent) of one runnable D restore. Every ribbon-based answer
    needs the pre-restore gate's HIDDEN reading; otherwise UNKNOWN and inconsistent.

    A COMPLETED restore recorded without error whose ribbon was never seen is FALSE only under
    FULLY_OBSERVABLE (any other value counts as partial) and UNKNOWN otherwise. A ribbon seen after a
    positively observed start is TRUE, but inconsistent with the recorded legacy False, so copied
    predictions stay UNOBSERVED. Every other pairing is restore_error_state()."""
    if not isinstance(restore, dict) or pre_ribbon != 'HIDDEN':
        return 'UNKNOWN', False
    if restore.get('completion') == 'COMPLETED' and restore.get('restore_error') is False:
        if restore.get('error_ribbon_seen') is True:
            return ('TRUE', False) if restore.get('start_observed') is True else ('UNKNOWN', False)
        return ('FALSE', True) if observability == 'FULLY_OBSERVABLE' else ('UNKNOWN', True)
    return restore_error_state(restore)


def restore_outcomes(restores, observability=None, pre_ribbon=None):
    """Fixed-key projection of each recorded restore (host summary). The recorded legacy
    restore_error, which feeds the classifiers and predictions, is labelled as recorded beside the
    tri-state; codes pass the allowlist. Without `observability` (every non-D case) the tri-state is
    restore_error_state(); with it (runnable D) it is malformed_restore_error_state() and the
    observability is exported beside it."""
    out = []
    for r in restores if isinstance(restores, list) else []:
        if not isinstance(r, dict):
            continue
        if observability is None:
            state, consistent = restore_error_state(r)
        else:
            state, consistent = malformed_restore_error_state(r, observability, pre_ribbon)
        out.append({'completion': _fixed(r.get('completion'), COMPLETIONS),
                    'recorded_restore_error': _fixed(r.get('restore_error'), (True, False)),
                    'restore_error_state': state, 'state_consistent': consistent,
                    'start_observed': _fixed(r.get('start_observed'), (True, False)),
                    'transition_end_observed': _fixed(r.get('transition_end_observed'), (True, False)),
                    'error_ribbon_seen': _fixed(r.get('error_ribbon_seen'), (True, False)),
                    'selected_files': _count(r.get('selected_files')),
                    'backgrounds_dom_after': _count(r.get('backgrounds_dom_after')),
                    'error_codes': report_projection(r.get('error_codes'), False),
                    'silent_codes': report_projection(r.get('silent_codes'), True)})
        if observability is not None:
            out[-1]['report_observability'] = _fixed(observability, REPORT_OBSERVABILITIES)
    return out


def input_shape(parts):
    """Per restore-input part: parse, chunks shape and the first row's content status (fixed enums).
    Read from the raw input bytes, so an absent and a non-array chunks member stay distinct."""
    out = []
    for raw in parts if isinstance(parts, (list, tuple)) else []:
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError, TypeError):
            value = None
        if not isinstance(value, dict):
            out.append({'parse': 'UNPARSEABLE', 'chunks': None, 'row1_content': None})
            continue
        chunks = value.get('chunks', _ABSENT)
        kind = 'ABSENT' if chunks is _ABSENT else 'ARRAY' if isinstance(chunks, list) else 'NOT_ARRAY'
        first = chunks[0] if kind == 'ARRAY' and chunks and isinstance(chunks[0], dict) else None
        file = first.get('file') if first is not None and isinstance(first.get('file'), dict) else {}
        out.append({'parse': 'PARSED', 'chunks': kind,
                    'row1_content': content_digest(file.get('background'))['status'] if first is not None else None})
    return out


def _digests(items):
    return [i.get('sha256') for i in items] if isinstance(items, list) and all(isinstance(i, dict) for i in items) \
        else None


def _input_binding(inputs):
    """Digest-level link between the restore input and the unmutated source parts of this attempt."""
    source, original = _digests(inputs.get('source')), _digests(inputs.get('original'))
    selection = inputs.get('selection') if isinstance(inputs.get('selection'), list) else []
    mutation = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else None
    selected = bool(source) and bool(selection) and all(
        isinstance(s, dict) and type(s.get('part_number')) is int and 1 <= s['part_number'] <= len(source)
        and s.get('sha256') == source[s['part_number'] - 1] for s in selection)
    out = {'input_mutated': mutation is not None, 'selection_matches_input': selected,
           'mutation_before_matches_original': None, 'mutation_after_matches_input': None,
           'unmutated_parts_equal': None}
    if mutation is not None:
        n = mutation.get('part_number')
        ok = (type(n) is int and bool(source) and original is not None and len(original) == len(source)
              and 1 <= n <= len(source))
        out.update(mutation_before_matches_original=ok and mutation.get('before_sha256') == original[n - 1],
                   mutation_after_matches_input=ok and mutation.get('after_sha256') == source[n - 1],
                   unmutated_parts_equal=ok and all(a == b for i, (a, b) in enumerate(zip(source, original))
                                                    if i != n - 1))
    return out


def _input_observed(case_id, shape, inputs):
    """The declared input class holds on the actual input bytes (never on the catalogue alone)."""
    mutation = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else None
    selection = [s for s in inputs.get('selection') or [] if isinstance(s, dict)] \
        if isinstance(inputs.get('selection'), list) else []
    source = _digests(inputs.get('source')) or []
    if not shape:
        return False
    first = shape[0]
    if case_id == 'D-TRUNC-P1':
        return (first['parse'] == 'UNPARSEABLE' and mutation is not None and mutation.get('edit') == 'truncate'
                and mutation.get('parseable') is False and mutation.get('part_number') == 1)
    if case_id == 'D-NO-CHUNKS':
        return first['chunks'] == 'ABSENT' and mutation is not None and mutation.get('part_number') == 1
    if case_id == 'D-CHUNKS-TYPE':
        return first['chunks'] == 'NOT_ARRAY' and mutation is not None and mutation.get('part_number') == 1
    if case_id == 'D-BAD-DATAURL':
        return (first['chunks'] == 'ARRAY' and first['row1_content'] == 'UNDECODABLE' and mutation is not None
                and mutation.get('part_number') == 1)
    if case_id == 'D-NAME-NO-P1':
        return (mutation is None and len(shape) == 1 and first['chunks'] == 'ARRAY' and len(source) == 1
                and [s.get('named_part') for s in selection] == [2] and selection[0].get('sha256') == source[0])
    return False


def _retained(before, after):
    """How many `before` items remain in `after`, duplicates counted (multiset intersection)."""
    left = {}
    for item in after:
        left[item] = left.get(item, 0) + 1
    kept = 0
    for item in before:
        if left.get(item, 0) > 0:
            left[item] -= 1
            kept += 1
    return kept


def _sequence_effect(before, after, given, original):
    """Rows or tasks. Equality is ordered; retention counts duplicates. First matching rule wins."""
    if after == before:
        return 'NOT_DISCRIMINATING' if not before or before in (given, original) else 'PRESERVED'
    if given is not None and after == given:
        return 'REPLACED_BY_INPUT'
    if original is not None and after == original:
        return 'REPLACED_BY_UNMUTATED_SOURCE'
    if not before:
        return 'NOT_DISCRIMINATING'
    kept = _retained(before, after)
    if not kept:
        return 'REMOVED_OTHER_PRESENT' if after else 'DESTROYED'
    if kept == len(before):
        return 'REORDERED' if len(after) == len(before) else 'RETAINED_WITH_ADDITIONS'
    return 'PARTIALLY_RETAINED'


def _value_effect(before, after, given, original, destroyed):
    """Settings or custom code (semantic view, volatile prefs excluded). First matching rule wins."""
    if after == before:
        return 'NOT_DISCRIMINATING' if before is None or before in (given, original) else 'PRESERVED'
    if given is not _ABSENT and after == given:
        return 'REPLACED_BY_INPUT'
    if original is not _ABSENT and after == original:
        return 'REPLACED_BY_UNMUTATED_SOURCE'
    return 'DESTROYED' if destroyed else 'NORMALIZED'


def _carried(fp, component):
    """A reference's settings or custom-code view, also from an incomplete input whose parsed part
    carried it; _ABSENT when the fingerprint does not carry it."""
    try:
        value = semantic(fp).get(component) if isinstance(fp, dict) else None
    except _MALFORMED:
        value = None
    return _ABSENT if value is None else value


def _code_destroyed(before, after):
    if after is None:
        return before is not None
    kinds = [k for k in KNOWN_CODE if isinstance(before, dict) and isinstance(before.get(k), dict)
             and before[k].get('length')]
    return bool(kinds) and isinstance(after, dict) and all(
        not (isinstance(after.get(k), dict) and after[k].get('length')) for k in kinds)


COMPONENTS = ('backgrounds', 'tasks', 'settings', 'custom_code')


def sentinel_components(pre, given, original, post):
    """What happened to each sentinel component. `given` is the actual restore input, `original` the
    unmutated same-root source; either may be absent or incomplete. Never reads restore_error.

    backgrounds (id+content keys) and tasks (full projection): PRESERVED (post equals pre),
    REPLACED_BY_INPUT, REPLACED_BY_UNMUTATED_SOURCE, DESTROYED (nothing prior left, post empty),
    REMOVED_OTHER_PRESENT, REORDERED, RETAINED_WITH_ADDITIONS, PARTIALLY_RETAINED.
    settings and custom code: PRESERVED, REPLACED_BY_INPUT, REPLACED_BY_UNMUTATED_SOURCE, DESTROYED
    (absent, or every non-empty code kind now empty), NORMALIZED. NOT_DISCRIMINATING when the prior
    value equals a reference or there was none."""
    try:
        if not (_well_formed(pre) and _well_formed(post)):
            return dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE')
        rows = lambda fp: [_row_key(r) for r in fp['rows']] if _well_formed(fp) else None
        tasks = lambda fp: _task_keys(fp) if _well_formed(fp) else None
        before = {c: semantic(pre).get(c) for c in ('settings', 'custom_code')}
        after = {c: semantic(post).get(c) for c in ('settings', 'custom_code')}
        return {'backgrounds': _sequence_effect(rows(pre), rows(post), rows(given), rows(original)),
                'tasks': _sequence_effect(tasks(pre), tasks(post), tasks(given), tasks(original)),
                'settings': _value_effect(before['settings'], after['settings'], _carried(given, 'settings'),
                                          _carried(original, 'settings'), after['settings'] is None),
                'custom_code': _value_effect(before['custom_code'], after['custom_code'],
                                             _carried(given, 'custom_code'), _carried(original, 'custom_code'),
                                             _code_destroyed(before['custom_code'], after['custom_code']))}
    except _MALFORMED:
        return dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE')


def state_effect(components):
    """Aggregate derived only from the component effects (never from restore_error or a desired
    result); the components stay beside it. First matching rule wins:
    1. any component incomplete or not a known effect: INCOMPLETE_EVIDENCE;
    2. every component PRESERVED or NOT_DISCRIMINATING: STATE_PRESERVED;
    3. every component REPLACED_BY_INPUT or NOT_DISCRIMINATING: STATE_REPLACED_BY_INPUT;
    4. every component replaced (input or unmutated source) or NOT_DISCRIMINATING:
       STATE_REPLACED_BY_UNMUTATED_SOURCE;
    5. backgrounds and tasks DESTROYED: SENTINEL_CONTENT_DESTROYED (settings and custom code are read
       from the components);
    6. a background or task kept in any form, or settings or custom code PRESERVED:
       STATE_PARTIALLY_RETAINED;
    7. otherwise STATE_ALTERED."""
    c = components if isinstance(components, dict) else {}
    values = [c.get(k) for k in COMPONENTS]
    if any(v not in SENTINEL_EFFECTS or v == 'INCOMPLETE_EVIDENCE' for v in values):
        return 'INCOMPLETE_EVIDENCE'
    if set(values) <= {'PRESERVED', 'NOT_DISCRIMINATING'}:
        return 'STATE_PRESERVED'
    if set(values) <= {'REPLACED_BY_INPUT', 'NOT_DISCRIMINATING'}:
        return 'STATE_REPLACED_BY_INPUT'
    if set(values) <= {'REPLACED_BY_INPUT', 'REPLACED_BY_UNMUTATED_SOURCE', 'NOT_DISCRIMINATING'}:
        return 'STATE_REPLACED_BY_UNMUTATED_SOURCE'
    if c['backgrounds'] == c['tasks'] == 'DESTROYED':
        return 'SENTINEL_CONTENT_DESTROYED'
    kept = ('PRESERVED', 'REORDERED', 'RETAINED_WITH_ADDITIONS', 'PARTIALLY_RETAINED')
    if c['backgrounds'] in kept or c['tasks'] in kept or 'PRESERVED' in (c['settings'], c['custom_code']):
        return 'STATE_PARTIALLY_RETAINED'
    return 'STATE_ALTERED'


def malformed_ranks(given, original, post):
    """Ranks of the post rows against the input (else the unmutated source) on shared ids;
    NOT_MEANINGFUL when no row id is shared."""
    try:
        reference = given if _well_formed(given) else original
        if not (_well_formed(reference) and _well_formed(post)):
            return 'INCOMPLETE_EVIDENCE'
        ranks = lambda fp: {json.dumps(r.get('id')): r.get('rank') for r in fp['rows']}
        wanted, observed = ranks(reference), ranks(post)
        shared = set(wanted) & set(observed)
        if not shared:
            return 'NOT_MEANINGFUL'
        return 'RANK_PRESERVED' if all(wanted[k] == observed[k] for k in shared) else 'RANK_NORMALIZED'
    except _MALFORMED:
        return 'INCOMPLETE_EVIDENCE'


def malformed_evidence(entry, fingerprints, given, original, record, inputs, shape):
    """The fixed per-case malformed evidence for a runnable D case; None for any other case.

    `given` is the fingerprint of the actual restore input, `original` that of the unmutated
    same-root S-RICH parts, `inputs` the attempt's digest-level matrix_inputs record and `shape`
    input_shape() of the input bytes. The sentinel effects are computed only when the one restore was
    positively observed to start and the post-export closed; otherwise every component is
    INCOMPLETE_EVIDENCE and the digests are still disclosed. Predictions are copied as predictions
    (PREDICTION_ONLY_NOT_ASSERTED) and are UNOBSERVED whenever the restore_error tri-state is not a
    consistent TRUE or FALSE. The tri-state is malformed_restore_error_state() under the pinned
    REPORT_OBSERVABILITY and the record's pre-restore ribbon reading; neither reaches the components,
    state effect, input binding or post facts."""
    case_id = entry.get('id') if isinstance(entry, dict) else None
    if not (isinstance(entry, dict) and entry.get('category') == 'D' and entry.get('runnable') is True
            and case_id in MALFORMED_INPUT_CLASSES):
        return None
    try:
        fps = fingerprints if isinstance(fingerprints, dict) else {}
        record = record if isinstance(record, dict) else {}
        inputs = inputs if isinstance(inputs, dict) else {}
        shape = [{k: _fixed(s.get(k), v) for k, v in INPUT_SHAPES.items()} for s in shape
                 if isinstance(s, dict)] if isinstance(shape, list) else []
        pre, post = fps.get('pre'), fps.get('post')
        restores = [r for r in record.get('restores') or [] if isinstance(r, dict)] \
            if isinstance(record.get('restores'), list) else []
        restore = restores[0] if len(restores) == 1 else {}
        pre_ribbon = _fixed(record.get('pre_restore_error_ribbon'), PRE_RESTORE_RIBBONS)
        state, consistent = (malformed_restore_error_state(restore, REPORT_OBSERVABILITY, pre_ribbon)
                             if len(restores) == 1 else ('UNKNOWN', False))
        artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
        post_record = artifacts.get('post') if isinstance(artifacts.get('post'), dict) else {}
        post_derived = post_record.get('derived') if isinstance(post_record.get('derived'), dict) else {}
        closure = _fixed(post_record.get('closure'), CLOSURES)
        gate = (restore.get('start_observed') is True and closure == 'CLOSED'
                and _well_formed(pre) and _well_formed(post))
        components = (sentinel_components(pre, given, original, post) if gate
                      else dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE'))
        effect = state_effect(components)
        mutation = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else {}
        selection = inputs.get('selection') if isinstance(inputs.get('selection'), list) else []
        codes, silent = restore.get('error_codes'), restore.get('silent_codes')
        recorded = record.get('predictions') if isinstance(record.get('predictions'), dict) else {}
        predictions = {}
        for key, predicted in (entry.get('predictions') or {}).items():
            item = recorded.get(key) if isinstance(recorded.get(key), dict) else {}
            legacy = _fixed(item.get('status'), PREDICTION_STATUSES)
            predictions[key] = {'predicted': _fixed(predicted, COMPONENT_CLASSES), 'legacy_status': legacy,
                                'status': legacy if state in ('TRUE', 'FALSE') and consistent and legacy
                                else 'UNOBSERVED', 'basis': PREDICTION_BASIS}
        completion = _fixed(restore.get('completion'), COMPLETIONS)
        return {
            'schema': MALFORMED_EVIDENCE_SCHEMA, 'case': case_id,
            'evidence': 'OBSERVED' if effect != 'INCOMPLETE_EVIDENCE' and completion else 'INCOMPLETE_EVIDENCE',
            'live_data_scope': LIVE_DATA_SCOPE,
            'input': {'input_class': MALFORMED_INPUT_CLASSES[case_id],
                      'mutation': _fixed(entry.get('mutation'), tuple(MUTATIONS)),
                      'edit': _fixed(mutation.get('edit'), ('truncate', 'remove', 'replace')),
                      'target': _fixed(mutation.get('target'), D_TARGETS),
                      'mutated_part': _count(mutation.get('part_number')),
                      'selection': _fixed(entry.get('selection'), SELECTIONS),
                      'named_parts': [_count(s.get('named_part')) for s in selection if isinstance(s, dict)],
                      'source_part_count': len(inputs['source']) if isinstance(inputs.get('source'), list) else None,
                      'shape': shape, 'input_class_observed': _input_observed(case_id, shape, inputs)},
            'source': {'source_case': _fixed(entry.get('source'), ('S-RICH',)),
                       'artifact': _fixed(entry.get('artifact'), ('rich',)),
                       'original_semantic_sha256': semantic_sha256(original),
                       'given_semantic_sha256': semantic_sha256(given), **_input_binding(inputs)},
            'completion': {'completion': completion, 'restore_count': len(restores), 'restore_error': state,
                           'state_consistent': consistent,
                           'recorded_restore_error': _fixed(restore.get('restore_error'), (True, False)),
                           'start_observed': _fixed(restore.get('start_observed'), (True, False)),
                           'transition_end_observed': _fixed(restore.get('transition_end_observed'), (True, False)),
                           'selected_files': _count(restore.get('selected_files')),
                           'pre_restore_error_ribbon': pre_ribbon,
                           'report_observability': _fixed(REPORT_OBSERVABILITY, REPORT_OBSERVABILITIES),
                           'observability_gaps': [g for g in OBSERVABILITY_GAPS if g in OBSERVABILITY_OBLIGATIONS]},
            'reports': {'loud_present': bool(codes) or restore.get('restore_error') is True
                        or restore.get('error_ribbon_seen') is True,
                        'silent_present': bool(silent),
                        'error_ribbon_seen': _fixed(restore.get('error_ribbon_seen'), (True, False)),
                        'loud_codes': report_projection(codes, False), 'silent_codes': report_projection(silent, True),
                        'restore_route_codes': RESTORE_ROUTE_CODES},
            'post': {'closure': closure, 'complete': _fixed(post_record.get('complete'), (True, False)),
                     'row_count': _count(post_derived.get('row_count')),
                     'task_count': _count(post_derived.get('task_count'))},
            'semantics': {'pre_semantic_sha256': semantic_sha256(pre), 'post_semantic_sha256': semantic_sha256(post),
                          'post_vs_pre': semantic_relation(post, pre), 'post_vs_given': semantic_relation(post, given),
                          'post_vs_original': semantic_relation(post, original)},
            'sentinel_pre': {'contract': 'SEEDED_SENTINEL_V1', 'semantic_sha256': semantic_sha256(pre),
                             'row_count': len(pre['rows']) if _well_formed(pre) else None,
                             'task_count': len(_task_keys(pre)) if _well_formed(pre) else None},
            'components': components, 'state_effect': effect,
            'sentinel_residue': prior_residue(pre, original, post) if gate else None,
            'ranks': {'post_rank_class': _fixed(post['derived'].get('rank_class'), RANK_SHAPES)
                      if gate and isinstance(post.get('derived'), dict) else None,
                      'vs_input': malformed_ranks(given, original, post) if gate else 'INCOMPLETE_EVIDENCE'},
            'predictions': predictions, 'prediction_scope': PREDICTION_SCOPE}
    except _MALFORMED:
        return {'schema': MALFORMED_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'INCOMPLETE_EVIDENCE'}


# --- Compatibility E evidence (bux-r6-compat-evidence-v1) ---------------------------------------
# Observation of exact CNT 6.12.1 on the bound Firefox only: never a gate, a compatibility
# certification, a UI-support claim or a live-data claim. Fixed enums, counts, booleans and digests
# computed from in-memory fingerprints of the fresh pre-state, the actual restore input, the unmutated
# same-root S-RICH source and the post-export. Unknown keys are named only from the fixed
# COMPAT_UNKNOWN_KEYS allowlist; arbitrary key names, values, report text and ids never leave. The
# classes never read restore_error; the observability-aware tri-state is reported beside them.
# Every function is total.

COMPAT_EVIDENCE_SCHEMA = 'bux-r6-compat-evidence-v1'
COMPAT_INPUT_SCHEMA = 'bux-r6-compat-input-v1'
# Exactly the insert keys of the declared unknown-field mutations, in MUTATIONS order.
COMPAT_UNKNOWN_KEYS = tuple(v[2] for v in MUTATIONS.values() if v[0] == 'insert')
# restore.apply_unchanged_prefs (CORRECTED): the restore keeps these from the current state. They are
# set apart from the compat view and reported as one boolean against the source.
CURRENT_STATE_PREFS = ('current_section', 'color_help_is_visible', 'clipboard_read_permission',
                       'install_help_is_visible')
# Verified defaults (provenance defaults.prefs) of the removed optional prefs and of mode.
OPTIONAL_PREF_DEFAULTS = {'backgrounds_per_page': 200, 'one_backup_file_size_in_bytes': THRESHOLD_DEFAULT}
MODE_DEFAULT = 'one_background'
OLDER_VERSION = MUTATIONS['pref_version_older'][2]
SYNTHETIC_LABEL = 'SYNTHETIC_INPUT_NOT_UI_CREATABLE'
SYNTHETIC_SCOPES = ('NATIVE_EXPORT_BOUNDED_MUTATION', SYNTHETIC_LABEL)
# Per runnable E case: fixed input class, target class, evidence group, the known components its
# declared edit changes, and the edited fields the edit-aware compat view leaves out (prefs, or each
# row's theme_id).
COMPAT_CASES = {
    'E-TOP': {'input_class': 'UNKNOWN_TOP_LEVEL_KEY', 'target_class': 'TOP_LEVEL', 'group': 'unknown',
              'changed': (), 'prefs': (), 'theme_id': False},
    'E-BG': {'input_class': 'UNKNOWN_BACKGROUND_KEY', 'target_class': 'ROW_1_DATA', 'group': 'unknown',
             'changed': (), 'prefs': (), 'theme_id': False},
    'E-PREF': {'input_class': 'UNKNOWN_PREFERENCE_KEY', 'target_class': 'SETTINGS_PREFS', 'group': 'unknown',
               'changed': (), 'prefs': (), 'theme_id': False},
    'E-CODE': {'input_class': 'UNKNOWN_CUSTOM_CODE_KEY', 'target_class': 'CUSTOM_CODE', 'group': 'unknown',
               'changed': (), 'prefs': (), 'theme_id': False},
    'E-TASK': {'input_class': 'UNKNOWN_TASK_KEY', 'target_class': 'FIRST_TASK_OF_FIRST_ROW_WITH_TASKS',
               'group': 'unknown', 'changed': (), 'prefs': (), 'theme_id': False},
    'E-ABSENT-OPT': {'input_class': 'OPTIONAL_PREFS_ABSENT', 'target_class': 'SETTINGS_PREFS',
                     'group': 'optional_prefs', 'changed': ('settings',), 'prefs': OPTIONAL_PREFS, 'theme_id': False},
    'E-VERSION': {'input_class': 'OLDER_VERSION_PREF', 'target_class': 'SETTINGS_PREFS_VERSION',
                  'group': 'version', 'changed': ('settings',), 'prefs': ('version',), 'theme_id': False},
    'E-THEMEID-DUP': {'input_class': 'SYNTHETIC_DUPLICATE_THEME_ID', 'target_class': 'ROWS_1_2_DATA',
                      'group': 'theme', 'changed': ('backgrounds',), 'prefs': (), 'theme_id': True},
    'E-MODE-THEME': {'input_class': 'SYNTHETIC_MODE_THEME_BACKGROUND', 'target_class': 'SETTINGS_PREFS_MODE',
                     'group': 'theme', 'changed': ('settings',), 'prefs': ('mode',), 'theme_id': False}}
COMPAT_COMPONENT_CLASSES = ('EQUAL_TO_SOURCE', 'PRE_STATE_RETAINED', 'NORMALIZED', 'NOT_DISCRIMINATING',
                            'INCOMPLETE_EVIDENCE')
APPLICATION_CLASSES = ('APPLIED', 'PARTIALLY_APPLIED', 'RESTORE_REJECTED', 'UNSETTLED_NO_COMPLETION_SIGNAL',
                       'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE')
_NOT_APPLIED = APPLICATION_CLASSES[1:]
UNKNOWN_CLASSES = ('UNKNOWN_IGNORED', 'UNKNOWN_RETAINED', 'UNKNOWN_RELOCATED', 'KNOWN_STATE_NORMALIZED',
                   *_NOT_APPLIED)
ACCEPTANCE_CLASSES = ('ACCEPTED_EQUIVALENT_KNOWN_STATE', 'ACCEPTED_WITH_NORMALIZATION', *_NOT_APPLIED)
THEME_CLASSES = ('ACCEPTED_AS_INPUT', 'ACCEPTED_AS_SOURCE_EQUIVALENT', 'ACCEPTED_WITH_NORMALIZATION',
                 *_NOT_APPLIED)
OPTIONAL_PREF_CLASSES = ('DEFAULTED', 'DEFAULT_NOT_DISCRIMINATED', 'REMAINED_ABSENT', 'NORMALIZED',
                         'SETTINGS_NOT_APPLIED', 'RESTORE_REJECTED', 'UNSETTLED_NO_COMPLETION_SIGNAL',
                         'NOT_DISCRIMINATING', 'INCOMPLETE_EVIDENCE')
VALUE_CLASSES = ('ABSENT', 'DEFAULT_VALUE', 'SOURCE_VALUE', 'INPUT_VALUE', 'OTHER_VALUE')
VERSION_CLASSES = ('ABSENT', 'SOURCE_VERSION', 'INPUT_OLDER_VERSION', 'OTHER_VERSION')
VERSION_SCOPE = 'EXACT_6_12_1_ARTIFACT_WITH_6_0_0_VERSION_ONLY'
OBSERVATION_SCOPE = 'EXACT_CNT_6_12_1_ON_BOUND_FIREFOX_OBSERVATION_NOT_CERTIFICATION'
COMPAT_PREDICTION_BASIS = 'COMPAT_UNKNOWN_PRESENCE_ON_APPLIED_STATE'
# The only prediction key an E case may carry (E-TOP's); any other catalogue key is dropped.
COMPAT_PREDICTION_KEYS = ('unknown',)
READINESS_GATE = 'SAME_ROOT_S_RICH_READY_BEFORE_LAUNCH'


def _strip_allowlisted(value):
    if not isinstance(value, dict):
        return value
    literal = value.get('literal')
    return dict(value, literal=[k for k in literal if k not in COMPAT_UNKNOWN_KEYS]
                if isinstance(literal, list) else literal)


def compat_view(fp, case_id=None):
    """The maintained semantic view (volatile values excluded) with only the allowlisted x_bux_*
    literal names removed, the volatile presence list and the current-state prefs set apart, and for
    a runnable E case its declared edited field left out (the optional prefs, version, mode, or each
    row's theme_id). Non-allowlisted unknown counts and digests stay in, so a native-added field still
    differs. A copy; raises only on a malformed fingerprint (callers contain it)."""
    view = json.loads(json.dumps(semantic(fp)))
    spec = COMPAT_CASES.get(case_id) or {}
    excluded = CURRENT_STATE_PREFS + tuple(spec.get('prefs') or ())
    view['top_unknown'] = [_strip_allowlisted(u) for u in view['top_unknown'] or []]
    settings = view['settings']
    if settings is not None:
        settings['prefs'] = {k: v for k, v in settings['prefs'].items() if k not in excluded}
        settings.pop('volatile', None)
        settings['unknown_literal'] = [k for k in settings.get('unknown_literal') or []
                                       if k not in COMPAT_UNKNOWN_KEYS]
    if isinstance(view['custom_code'], dict):
        view['custom_code']['unknown'] = _strip_allowlisted(view['custom_code'].get('unknown'))
    for r in view['rows']:
        if isinstance(r.get('unknown'), dict):
            r['unknown'] = {k: _strip_allowlisted(v) for k, v in r['unknown'].items()}
        if spec.get('theme_id'):
            r['presentation'].pop('theme_id', None)
            r.pop('theme_id_present', None)
        for t in r.get('tasks') or []:
            t['unknown'] = _strip_allowlisted(t.get('unknown'))
    return view


def _view_components(view):
    rows = view['rows']
    return {'backgrounds': [{k: v for k, v in r.items() if k != 'tasks'} for r in rows],
            'tasks': [t for r in rows for t in (r.get('tasks') or [])],
            'settings': view['settings'], 'custom_code': view['custom_code']}


def _changed_components(a, b):
    """Known components (compat view, no case edit left out) in which two fingerprints differ."""
    x, y = _view_components(compat_view(a)), _view_components(compat_view(b))
    return [k for k in COMPONENTS if x[k] != y[k]]


def _contains_key(value, key):
    if isinstance(value, dict):
        return key in value or any(_contains_key(v, key) for v in value.values())
    if isinstance(value, list):
        return any(_contains_key(v, key) for v in value)
    return False


def _walk(value, path):
    for step in path:
        value = value[step]
    return value


def _expected_record(mutation, original_raw):
    """(edit, target) mutate() records for this mutation on these source bytes."""
    action, path, _ = MUTATIONS[mutation]
    if action == 'insert':
        node, resolved = _resolve(locate(original_raw), path)
        return 'insert', _path(resolved) if node is not None else None
    if action == 'theme':
        return 'insert', 'chunks.0-1.data'
    return action, _path(path)


def _edit_facts(mutation, given, original, original_raw):
    """(edit_present, outside_edit_unchanged) on the parsed input and the parsed unmutated source."""
    action, path, value = MUTATIONS[mutation]
    if action == 'insert':
        node, resolved = _resolve(locate(original_raw), path)
        if node is None:
            return False, False
        target = _walk(given, resolved)
        present = (isinstance(target, dict) and target.get(value) == UNKNOWN_VALUE
                   and not _contains_key(original, value))
        return present, _drop(given, resolved, value) == original
    if action == 'remove':
        prefs, before = _walk(given, path), _walk(original, path)
        present = all(k not in prefs and k in before for k in OPTIONAL_PREFS)
        expected = original
        for key in OPTIONAL_PREFS:
            expected = _drop(expected, path, key) if key in _walk(expected, path) else expected
        return present, given == expected
    if action == 'replace':
        before = _walk(original, path)
        return (_walk(given, path) == value and before != value), _set(given, path, before) == original
    rows = _walk(given, path)
    present = (len(rows) >= 2 and all(rows[i]['data'].get('theme_id') == value for i in (0, 1))
               and not any(isinstance(c, dict) and isinstance(c.get('data'), dict) and 'theme_id' in c['data']
                           for c in _walk(original, path)))
    undone = _drop(_drop(given, ('chunks', 0, 'data'), 'theme_id'), ('chunks', 1, 'data'), 'theme_id')
    return present, undone == original


def compat_input_proof(entry, inputs, source_parts, original_parts, selected_parts):
    """Pre-restore proof that the restore input is exactly one declared bounded mutation of the
    same-root S-RICH artifact: the mutation record binds the unmutated and mutated part digests; the
    declared key or value edit is present; with that edit undone the parsed input equals the parsed
    source, so every field outside it is unchanged; the known components it changes are exactly the
    declared set; every unmutated part and the selected file bytes are byte-identical. Pure and total:
    fixed enums, booleans and counts; `proven` only when every fact holds."""
    case_id = entry.get('id') if isinstance(entry, dict) else None
    spec = COMPAT_CASES.get(case_id) if isinstance(case_id, str) else None
    mutation = entry.get('mutation') if spec and isinstance(entry.get('mutation'), str) else None
    out = {'schema': COMPAT_INPUT_SCHEMA, 'case': case_id if spec else None,
           'input_class': spec['input_class'] if spec else None,
           'target_class': spec['target_class'] if spec else None,
           'mutation_class': _fixed(mutation, tuple(MUTATIONS)), 'selection_class': None,
           'source_part_count': None, 'mutated_part': None,
           'synthetic_input_scope': (SYNTHETIC_LABEL if mutation in SYNTHETIC_ONLY else SYNTHETIC_SCOPES[0])
           if spec else None,
           'mutation_record_binds': False, 'edit_present': False, 'outside_edit_unchanged': False,
           'known_components_changed': None, 'known_components_expected': list(spec['changed']) if spec else None,
           'unmutated_parts_byte_identical': False, 'selection_bytes_equal_input': False, 'proven': False}
    if not (spec and entry.get('category') == 'E' and entry.get('runnable') is True and mutation in MUTATIONS
            and entry.get('mutate_part') == 1 and entry.get('selection') == 'single'):
        return out
    try:
        inputs = inputs if isinstance(inputs, dict) else {}
        source, original, selected = list(source_parts), list(original_parts), list(selected_parts)
        if not (source and all(isinstance(p, bytes) for p in source + original + selected)):
            return out
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        record = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else {}
        listed = inputs.get('selection') if isinstance(inputs.get('selection'), list) else []
        out['source_part_count'] = len(original)
        out['mutated_part'] = _count(record.get('part_number'))
        out['selection_class'] = 'single' if [
            (s.get('named_part'), s.get('slot'), s.get('part_number')) for s in listed if isinstance(s, dict)
        ] == [(n, 0, n) for n in range(1, len(source) + 1)] and len(listed) == len(source) else 'UNEXPECTED'
        out['unmutated_parts_byte_identical'] = (len(source) == len(original)
                                                 and all(a == b for a, b in zip(source[1:], original[1:])))
        out['selection_bytes_equal_input'] = (selected == source and _digests(listed) == [sha(p) for p in source])
        if not original or record.get('part_number') != 1:
            return out
        edit, target = _expected_record(mutation, original[0])
        out['mutation_record_binds'] = (
            record.get('mutation') == mutation and record.get('edit') == edit and record.get('target') == target
            and record.get('parseable') is True and record.get('before_sha256') == sha(original[0])
            and record.get('after_sha256') == sha(source[0])
            and record.get('synthetic_label') == (SYNTHETIC_LABEL if mutation in SYNTHETIC_ONLY else None)
            and _digests(inputs.get('source')) == [sha(p) for p in source]
            and _digests(inputs.get('original')) == [sha(p) for p in original])
        given, before = json.loads(source[0]), json.loads(original[0])
        out['edit_present'], out['outside_edit_unchanged'] = _edit_facts(mutation, given, before, original[0])
        out['known_components_changed'] = _changed_components(fingerprint(source), fingerprint(original))
        out['proven'] = (out['selection_class'] == 'single' and out['mutated_part'] == 1
                         and all(out[k] is True for k in ('mutation_record_binds', 'edit_present',
                                                          'outside_edit_unchanged', 'unmutated_parts_byte_identical',
                                                          'selection_bytes_equal_input'))
                         and out['known_components_changed'] == out['known_components_expected'])
    except _MALFORMED + (VerificationError,):
        out['proven'] = False
    return out


def compat_components(pre, original, post, case_id):
    """Per known component on the edit-aware compat view, first matching rule wins: incomplete;
    NOT_DISCRIMINATING (the source equals the fresh pre-state, so no reading is possible);
    EQUAL_TO_SOURCE; PRE_STATE_RETAINED; otherwise NORMALIZED. Never reads restore_error."""
    try:
        if not all(_well_formed(fp) for fp in (pre, original, post)):
            return dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE')
        before, source, after = (_view_components(compat_view(fp, case_id)) for fp in (pre, original, post))
        out = {}
        for k in COMPONENTS:
            out[k] = ('NOT_DISCRIMINATING' if source[k] == before[k] else 'EQUAL_TO_SOURCE' if after[k] == source[k]
                      else 'PRE_STATE_RETAINED' if after[k] == before[k] else 'NORMALIZED')
        return out
    except _MALFORMED:
        return dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE')


def compat_application(components, completion):
    """State-only, from the components: APPLIED when no discriminating component kept the fresh
    pre-state; RESTORE_REJECTED when every one did, PARTIALLY_APPLIED when some did. A pre-state kept
    after DEADLINE_NO_SIGNAL (the reload may have cut the restore) is UNSETTLED_NO_COMPLETION_SIGNAL.
    RESTORE_REJECTED means not applied, never that an error was reported."""
    c = components if isinstance(components, dict) else {}
    values = [c.get(k) for k in COMPONENTS]
    if any(v not in COMPAT_COMPONENT_CLASSES or v == 'INCOMPLETE_EVIDENCE' for v in values) \
            or completion not in COMPLETIONS:
        return 'INCOMPLETE_EVIDENCE'
    discriminating = [v for v in values if v != 'NOT_DISCRIMINATING']
    if not discriminating:
        return 'NOT_DISCRIMINATING'
    retained = [v == 'PRE_STATE_RETAINED' for v in discriminating]
    if not any(retained):
        return 'APPLIED'
    if completion == 'DEADLINE_NO_SIGNAL':
        return 'UNSETTLED_NO_COMPLETION_SIGNAL'
    return 'RESTORE_REJECTED' if all(retained) else 'PARTIALLY_APPLIED'


def _unknown_sites(fp, key):
    """Sorted sites of one allowlisted key in a fingerprint. Row and task ids key the sites here and
    are never returned by any caller."""
    sites = set()
    has = lambda u: isinstance(u, dict) and isinstance(u.get('literal'), list) and key in u['literal']
    if any(has(u) for u in fp.get('top_unknown') or []):
        sites.add(('top',))
    settings = fp.get('settings') if isinstance(fp.get('settings'), dict) else {}
    if key in (settings.get('unknown_literal') or []):
        sites.add(('pref',))
    if has(settings.get('settings_unknown')):
        sites.add(('settings',))
    if isinstance(fp.get('custom_code'), dict) and has(fp['custom_code'].get('unknown')):
        sites.add(('code',))
    for r in fp['rows']:
        row = json.dumps(r.get('id'), sort_keys=True)
        for part, value in (r.get('unknown') or {}).items():
            if has(value):
                sites.add(('row', part, row))
        for t in r.get('tasks') or []:
            if has(t.get('unknown')):
                sites.add(('task', row, json.dumps(t.get('id'), sort_keys=True)))
    return sorted(sites)


def _unknown_residue(view):
    rows = view['rows']
    return [view['top_unknown'], (view['settings'] or {}).get('unknown_literal'),
            (view['settings'] or {}).get('settings_unknown'), (view['custom_code'] or {}).get('unknown'),
            [r.get('unknown') for r in rows], [t.get('unknown') for r in rows for t in (r.get('tasks') or [])]]


def _prefs(fp):
    settings = fp.get('settings') if isinstance(fp, dict) and isinstance(fp.get('settings'), dict) else {}
    return settings.get('prefs') if isinstance(settings.get('prefs'), dict) else {}


def _value_class(present, value, default, source, given=_ABSENT):
    if not present:
        return 'ABSENT'
    if given is not _ABSENT and _same(value, given):
        return 'INPUT_VALUE'
    if _same(value, default):
        return 'DEFAULT_VALUE'
    return 'SOURCE_VALUE' if _same(value, source) else 'OTHER_VALUE'


def _optional_prefs(pre, original, post, components, application):
    out = {}
    for name in OPTIONAL_PREFS:
        default = OPTIONAL_PREF_DEFAULTS[name]
        before, source, after = _prefs(pre), _prefs(original), _prefs(post)
        present = name in after
        value_class = _value_class(present, after.get(name), default, source.get(name))
        default_pre, default_source = _same(before.get(name), default), _same(source.get(name), default)
        if application == 'INCOMPLETE_EVIDENCE':
            kind = 'INCOMPLETE_EVIDENCE'
        elif components.get('settings') == 'NOT_DISCRIMINATING':
            kind = 'NOT_DISCRIMINATING'
        elif components.get('settings') == 'PRE_STATE_RETAINED':
            kind = application if application in ('RESTORE_REJECTED', 'UNSETTLED_NO_COMPLETION_SIGNAL') \
                else 'SETTINGS_NOT_APPLIED'
        elif not present:
            kind = 'REMAINED_ABSENT'
        elif value_class == 'DEFAULT_VALUE':
            # A default equal to the fresh pre-state or the source cannot be told from retention.
            kind = 'DEFAULT_NOT_DISCRIMINATED' if default_pre or default_source else 'DEFAULTED'
        else:
            kind = 'NORMALIZED'
        out[name] = {'class': kind, 'post_value_class': value_class,
                     'post_value': after.get(name) if value_class in ('DEFAULT_VALUE', 'SOURCE_VALUE')
                     and type(after.get(name)) is int else None,
                     'default_value': default, 'default_equals_pre': default_pre,
                     'default_equals_source': default_source}
    return out


def _accepted(application, equal, as_input=_ABSENT):
    """Group class once applied. Without an edit fate (optional prefs, version): equivalent or
    normalized known state. With one (synthetic theme inputs): the edit kept as input (True), undone to
    the source (False) or neither (None, normalization). The edit's own fate is reported beside it."""
    if application != 'APPLIED':
        return application
    if as_input is _ABSENT:
        return 'ACCEPTED_EQUIVALENT_KNOWN_STATE' if equal else 'ACCEPTED_WITH_NORMALIZATION'
    if equal and as_input is True:
        return 'ACCEPTED_AS_INPUT'
    if equal and as_input is False:
        return 'ACCEPTED_AS_SOURCE_EQUIVALENT'
    return 'ACCEPTED_WITH_NORMALIZATION'


def _group(case_id, spec, pre, given, original, post, components, application, equal):
    """(compat_class, {group block}) of one gated E case."""
    group = spec['group']
    if group == 'unknown':
        key = MUTATIONS[case(case_id)['mutation']][2]
        declared = _unknown_sites(given, key)
        after = _unknown_sites(post, key)
        at = len(declared) == 1 and declared[0] in after
        elsewhere = [s for s in after if s not in declared]
        if application != 'APPLIED':
            kind = application
        elif not equal:
            kind = 'KNOWN_STATE_NORMALIZED'
        else:
            kind = 'UNKNOWN_RETAINED' if at else 'UNKNOWN_RELOCATED' if elsewhere else 'UNKNOWN_IGNORED'
        return kind, {'unknown': {'declared_key': key, 'input_at_declared_object': len(declared) == 1,
                                  'original_anywhere': bool(_unknown_sites(original, key)),
                                  'post_at_declared_object': at, 'post_elsewhere': bool(elsewhere),
                                  'allowlisted_keys_in_post': [k for k in COMPAT_UNKNOWN_KEYS
                                                               if _unknown_sites(post, k)]}}
    if group == 'optional_prefs':
        return _accepted(application, equal), {'optional_prefs': _optional_prefs(pre, original, post, components,
                                                                                 application)}
    if group == 'version':
        after, source = _prefs(post), _prefs(original)
        present, value = 'version' in after, after.get('version')
        version = ('ABSENT' if not present else 'INPUT_OLDER_VERSION' if _same(value, OLDER_VERSION)
                   else 'SOURCE_VERSION' if _same(value, source.get('version')) else 'OTHER_VERSION')
        return _accepted(application, equal), {'version': {'post_version_class': version,
                                                           'input_version_class': 'INPUT_OLDER_VERSION',
                                                           'scope': VERSION_SCOPE}}
    theme = {'synthetic_input_scope': SYNTHETIC_LABEL, 'ui_support_claimed': False}
    if case_id == 'E-MODE-THEME':
        after = _prefs(post)
        mode = _value_class('mode' in after, after.get('mode'), MODE_DEFAULT, _prefs(original).get('mode'),
                            MUTATIONS['pref_mode_theme_background'][2])
        theme.update(post_mode_class=mode, not_representable=NOT_REPRESENTABLE['theme_background_mode'])
        as_input = True if mode == 'INPUT_VALUE' else False if mode == 'SOURCE_VALUE' else None
    else:
        value = MUTATIONS['synthetic_theme_id_duplicate'][2]
        carriers = [r for r in post['rows'] if r.get('theme_id_present') is True]
        values = {json.dumps((r.get('presentation') or {}).get('theme_id')) for r in carriers}
        rows, source_rows = len(post['rows']), len(original['rows'])
        theme.update(rows_relation='ROWS_EQUAL' if rows == source_rows else 'ROWS_REDUCED' if rows < source_rows
                     else 'ROWS_INCREASED', rows_with_theme_id=len(carriers),
                     theme_id_value_class='ABSENT' if not carriers else 'INPUT_VALUE'
                     if values == {json.dumps(value)} else 'OTHER_VALUE',
                     not_representable=NOT_REPRESENTABLE['theme_install'])
        as_input = (True if len(carriers) == 2 and theme['theme_id_value_class'] == 'INPUT_VALUE'
                    else False if not carriers else None)
    return _accepted(application, equal, as_input), {'theme': theme}


def compat_prediction(entry, record, application, compat_class, retained):
    """E-TOP's catalogue prediction, copied as a prediction only. MATCH needs an APPLIED restore with
    the key absent everywhere and the known state equal (UNKNOWN_IGNORED); MISMATCH an APPLIED restore
    that kept the key anywhere (at its declared object or relocated); anything else is UNOBSERVED."""
    recorded = record.get('predictions') if isinstance(record.get('predictions'), dict) else {}
    catalogue = entry.get('predictions') if isinstance(entry.get('predictions'), dict) else {}
    out = {}
    for key in COMPAT_PREDICTION_KEYS:
        if key not in catalogue:
            continue
        predicted = catalogue[key]
        item = recorded.get(key) if isinstance(recorded.get(key), dict) else {}
        observed = None
        if application == 'APPLIED' and retained:
            observed = 'RETAINED_UNKNOWN'
        elif application == 'APPLIED' and compat_class == 'UNKNOWN_IGNORED':
            observed = 'IGNORED'
        out[key] = {'predicted': _fixed(predicted, COMPONENT_CLASSES), 'observed': observed,
                    'status': prediction_status(predicted, observed) if observed else 'UNOBSERVED',
                    'basis': COMPAT_PREDICTION_BASIS,
                    'legacy_status': _fixed(item.get('status'), PREDICTION_STATUSES),
                    'legacy_basis': PREDICTION_BASIS}
    return out


PROOF_FACTS = ('proven', 'mutation_record_binds', 'edit_present', 'outside_edit_unchanged',
               'unmutated_parts_byte_identical', 'selection_bytes_equal_input')


def _proof_projection(proof):
    """The recorded input proof reduced to fixed values; anything else reads None."""
    components = lambda v: [c for c in v if c in COMPONENTS] if isinstance(v, list) \
        and all(c in COMPONENTS for c in v) else None
    return {'schema': _fixed(proof.get('schema'), (COMPAT_INPUT_SCHEMA,)),
            **{k: _fixed(proof.get(k), (True, False)) for k in PROOF_FACTS},
            'known_components_changed': components(proof.get('known_components_changed')),
            'known_components_expected': components(proof.get('known_components_expected')),
            'selection_class': _fixed(proof.get('selection_class'), ('single', 'UNEXPECTED')),
            'source_part_count': _count(proof.get('source_part_count')), 'mutated_part': _count(proof.get('mutated_part'))}


def compat_evidence(entry, fingerprints, given, original, record, inputs):
    """The fixed per-case compatibility evidence for a runnable E case; None for any other case.

    `given` is the fingerprint of the actual restore input, `original` that of the unmutated same-root
    S-RICH parts, `record` the session record (restores, artifacts, the recorded pre-restore proof and
    ribbon reading) and `inputs` the digest-level matrix_inputs record. Every class is computed only
    when the one restore was positively observed to start with a known completion, the post-export
    closed, every fingerprint is well formed, the recorded input proof holds and the input's compat
    view equals the source's; otherwise every class is INCOMPLETE_EVIDENCE and the digests are still
    disclosed. The completion tri-state is malformed_restore_error_state() under the pinned
    REPORT_OBSERVABILITY; it never reaches a class, and a completion without a ribbon stays UNKNOWN."""
    case_id = entry.get('id') if isinstance(entry, dict) else None
    spec = COMPAT_CASES.get(case_id) if isinstance(case_id, str) else None
    if not (spec and entry.get('category') == 'E' and entry.get('runnable') is True):
        return None
    try:
        fps = fingerprints if isinstance(fingerprints, dict) else {}
        record = record if isinstance(record, dict) else {}
        inputs = inputs if isinstance(inputs, dict) else {}
        pre, post = fps.get('pre'), fps.get('post')
        restores = [r for r in record.get('restores') or [] if isinstance(r, dict)] \
            if isinstance(record.get('restores'), list) else []
        restore = restores[0] if len(restores) == 1 else {}
        pre_ribbon = _fixed(record.get('pre_restore_error_ribbon'), PRE_RESTORE_RIBBONS)
        state, consistent = (malformed_restore_error_state(restore, REPORT_OBSERVABILITY, pre_ribbon)
                             if len(restores) == 1 else ('UNKNOWN', False))
        artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
        post_record = artifacts.get('post') if isinstance(artifacts.get('post'), dict) else {}
        post_derived = post_record.get('derived') if isinstance(post_record.get('derived'), dict) else {}
        closure = _fixed(post_record.get('closure'), CLOSURES)
        completion = _fixed(restore.get('completion'), COMPLETIONS)
        proof = record.get('compat_input') if isinstance(record.get('compat_input'), dict) else {}
        formed = all(_well_formed(fp) for fp in (pre, given, original, post))
        view = lambda fp: compat_view(fp, case_id) if _well_formed(fp) else None
        given_equal = formed and view(given) == view(original)
        gate = (restore.get('start_observed') is True and completion is not None and closure == 'CLOSED'
                and formed and proof.get('proven') is True and given_equal)
        components = (compat_components(pre, original, post, case_id) if gate
                      else dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE'))
        application = compat_application(components, completion) if gate else 'INCOMPLETE_EVIDENCE'
        equal = gate and view(post) == view(original)
        if gate:
            kind, block = _group(case_id, spec, pre, given, original, post, components, application, equal)
        else:
            kind, block = 'INCOMPLETE_EVIDENCE', {}
        sites = block.get('unknown', {})
        retained = bool(sites.get('post_at_declared_object') or sites.get('post_elsewhere'))
        codes, silent = restore.get('error_codes'), restore.get('silent_codes')
        source_prefs, post_prefs = _prefs(original), _prefs(post)
        return {
            'schema': COMPAT_EVIDENCE_SCHEMA, 'case': case_id,
            'evidence': 'OBSERVED' if gate else 'INCOMPLETE_EVIDENCE',
            'observation_scope': OBSERVATION_SCOPE, 'live_data_scope': LIVE_DATA_SCOPE,
            'input': {'input_class': spec['input_class'], 'target_class': spec['target_class'],
                      'mutation': _fixed(entry.get('mutation'), tuple(MUTATIONS)),
                      'synthetic_input_scope': SYNTHETIC_LABEL if entry.get('mutation') in SYNTHETIC_ONLY
                      else SYNTHETIC_SCOPES[0],
                      'proof': _proof_projection(proof)},
            'source': {'source_case': _fixed(entry.get('source'), ('S-RICH',)),
                       'artifact': _fixed(entry.get('artifact'), ('rich',)), 'readiness_gate': READINESS_GATE,
                       'original_semantic_sha256': semantic_sha256(original),
                       'given_semantic_sha256': semantic_sha256(given),
                       'original_view_sha256': digest(view(original)) if formed else None,
                       'given_view_equals_original': given_equal, **_input_binding(inputs)},
            'completion': {'completion': completion, 'restore_count': len(restores), 'restore_error': state,
                           'state_consistent': consistent,
                           'recorded_restore_error': _fixed(restore.get('restore_error'), (True, False)),
                           'start_observed': _fixed(restore.get('start_observed'), (True, False)),
                           'transition_end_observed': _fixed(restore.get('transition_end_observed'), (True, False)),
                           'selected_files': _count(restore.get('selected_files')),
                           'pre_restore_error_ribbon': pre_ribbon,
                           'report_observability': _fixed(REPORT_OBSERVABILITY, REPORT_OBSERVABILITIES),
                           'observability_gaps': [g for g in OBSERVABILITY_GAPS if g in OBSERVABILITY_OBLIGATIONS],
                           'completion_basis': None if completion is None else 'NO_COMPLETION_SIGNAL'
                           if completion == 'DEADLINE_NO_SIGNAL' else 'COMPLETION_OBSERVED'},
            'reports': {'loud_present': bool(codes) or restore.get('restore_error') is True
                        or restore.get('error_ribbon_seen') is True,
                        'silent_present': bool(silent),
                        'error_ribbon_seen': _fixed(restore.get('error_ribbon_seen'), (True, False)),
                        'loud_codes': report_projection(codes, False), 'silent_codes': report_projection(silent, True),
                        'restore_route_codes': RESTORE_ROUTE_CODES},
            'post': {'closure': closure, 'complete': _fixed(post_record.get('complete'), (True, False)),
                     'row_count': _count(post_derived.get('row_count')),
                     'task_count': _count(post_derived.get('task_count'))},
            'semantics': {'pre_semantic_sha256': semantic_sha256(pre), 'post_semantic_sha256': semantic_sha256(post),
                          'post_vs_original': semantic_relation(post, original),
                          'post_vs_given': semantic_relation(post, given), 'post_vs_pre': semantic_relation(post, pre),
                          'post_view_sha256': digest(view(post)) if gate else None,
                          'post_view_equals_original': equal if gate else None,
                          'post_view_equals_pre': view(post) == view(pre) if gate else None,
                          'current_state_prefs_equal_to_source':
                              {k: post_prefs.get(k, _ABSENT) for k in CURRENT_STATE_PREFS} ==
                              {k: source_prefs.get(k, _ABSENT) for k in CURRENT_STATE_PREFS} if gate else None,
                          'other_unknown_changed_vs_source':
                              _unknown_residue(view(post)) != _unknown_residue(view(original)) if gate else None},
            'components': components, 'application': application, 'compat_class': kind,
            'ranks': {'post_rank_class': _fixed(post['derived'].get('rank_class'), RANK_SHAPES)
                      if gate and isinstance(post.get('derived'), dict) else None,
                      'vs_source': malformed_ranks(original, original, post) if gate else 'INCOMPLETE_EVIDENCE'},
            **block,
            'predictions': compat_prediction(entry, record, application, kind, retained),
            'prediction_scope': PREDICTION_SCOPE}
    except _MALFORMED:
        return {'schema': COMPAT_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'INCOMPLETE_EVIDENCE'}


# --- Multipart B (bux-r6-multi-readiness-v1, bux-r6-multipart-input-v1, bux-r6-multipart-evidence-v1)
# S-MULTI readiness decides whether its same-root `minimum` artifact may feed any B dependent. The input
# proof binds each dependent's selected file bytes, before any file selection, to that ready artifact and
# to exactly one declared selection relation (and, for TRUNC and BADDATA, one bounded mutation). The
# evidence is observation only: never a gate, a verdict on native success, a compatibility certification
# or a live-data claim. Raw part bytes, data URLs, row and task ids, names and paths never leave: fixed
# enums, ints, booleans and digests computed here. Every function is total.

MULTI_READINESS_SCHEMA = 'bux-r6-multi-readiness-v1'
MULTIPART_INPUT_SCHEMA = 'bux-r6-multipart-input-v1'
MULTIPART_EVIDENCE_SCHEMA = 'bux-r6-multipart-evidence-v1'
MULTI_LABELS = ('calibration', 'at_t', 'at_t_plus_1', 'minimum')
# (threshold step, the export whose own Part 1 pref must show it committed)
MULTI_COMMITS = (('predicted', 'at_t'), ('predicted_plus_1', 'at_t_plus_1'), ('minimum', 'minimum'))
MULTI_MIN_PARTS = 3
MULTI_MIDDLE = 2
MULTI_PART_LIMIT = 512 * 1024 * 1024
THRESHOLD_PREF = 'one_backup_file_size_in_bytes'
MULTI_READINESS_GATE = 'SAME_ROOT_S_MULTI_READY_BEFORE_LAUNCH'
PARTITION_STATUSES = ('CONSISTENT', 'INCONSISTENT', 'NOT_NATIVE_TEMPLATE', 'INCOMPLETE_EVIDENCE')
BOUNDARY_CLASSES = ('EXACT_BOUNDARY_OBSERVED', 'BOUNDARY_SHIFTED', 'PREDICTION_HEADER_DRIFT',
                    'BOUNDARY_NOT_SETTABLE', 'INCOMPLETE_EVIDENCE')
HEADER_RELATIONS = ('HEADER_MATCH', 'HEADER_DRIFT', 'INCOMPLETE_EVIDENCE')
ORDINAL_CLASSES = ('CONTIGUOUS_1_N', 'BROKEN')
# Each dependent's selection kind and the one relation its input must have to the ready source.
MULTIPART_SELECTIONS = {'ordered': 'COMPLETE_NATIVE_ORDER', 'reversed': 'COMPLETE_REVERSED',
                        'no_part_1': 'MISSING_PART_1', 'no_middle': 'MISSING_MIDDLE',
                        'duplicate_middle': 'DUPLICATE_MIDDLE', 'truncate_last': 'FINAL_PART_TRUNCATED',
                        'bad_data_part_2': 'PART_2_DATA_URL_INVALID'}
# selection -> (mutation, mutated part (-1 = last), recorded edit, recorded target, parseable, proof class)
MULTIPART_MUTATIONS = {'truncate_last': ('truncate_json', -1, 'truncate', None, False, 'TRUNCATED_PREFIX_PROVEN'),
                       'bad_data_part_2': ('invalid_data_url', MULTI_MIDDLE, 'replace', 'chunks.0.file.background',
                                           True, 'DATA_URL_REPLACED_PROVEN')}
MUTATION_PROOFS = ('TRUNCATED_PREFIX_PROVEN', 'DATA_URL_REPLACED_PROVEN', 'NOT_APPLICABLE', 'UNPROVEN')
MULTIPART_ROW_ORIGINS = ('SOURCE', 'SOURCE_ID_CONTENT_CHANGED', 'PRE_STATE', 'OTHER')
MULTIPART_ROW_RELATIONS = ('SOURCE_ROWS_EXACT_ORDER', 'SOURCE_ROWS_PERMUTED', 'SOURCE_SUBSET_IN_ORDER',
                           'SOURCE_SUBSET_REORDERED', 'SOURCE_ROWS_DUPLICATED', 'PRE_STATE_ONLY',
                           'MIXED_SOURCE_AND_PRE_STATE', 'OTHER_ROWS_PRESENT', 'NO_ROWS', 'INCOMPLETE_EVIDENCE')
THRESHOLD_PREF_CLASSES = ('SOURCE_MINIMUM', 'TARGET_DEFAULT', 'OTHER', 'ABSENT', 'INCOMPLETE_EVIDENCE')
MULTIPART_ROW_LIMIT = 64
MULTIPART_PREDICTION_BASIS = 'MULTIPART_ROWS_AND_COMPONENTS_ON_COMPLETED_APPLIED_STATE'
_EMPTY_UNKNOWN = {'literal': [], 'other_count': 0, 'other_sha256': None}


def export_threshold(fp):
    """The threshold an export itself read: its own Part 1 pref (backup.partition_header), an int, or
    None. Never an assumed or intended value."""
    try:
        value = fp['settings']['prefs'].get(THRESHOLD_PREF)
    except (TypeError, KeyError, AttributeError):
        return None
    return value if type(value) is int else None


def multi_view(fp, drop_threshold=False):
    """The maintained semantic view (volatile prefs excluded) with the part-count artifacts removed:
    the empty top-level unknown entry of each later part. `drop_threshold` also leaves out the threshold
    pref, which S-MULTI changes between its exports. A copy; raises only on a malformed fingerprint."""
    view = json.loads(json.dumps(semantic(fp)))
    view['top_unknown'] = [u for u in view['top_unknown'] or [] if u != _EMPTY_UNKNOWN]
    if drop_threshold and view['settings'] is not None:
        view['settings']['prefs'].pop(THRESHOLD_PREF, None)
    return view


def multi_relation(a, b):
    """SEMANTIC_EQUAL / SEMANTIC_DIFFERENT on multi_view(), so a state split into more or fewer parts
    compares by content; INCOMPLETE_EVIDENCE when either side is not well formed."""
    try:
        if not (_well_formed(a) and _well_formed(b)):
            return 'INCOMPLETE_EVIDENCE'
        return 'SEMANTIC_EQUAL' if multi_view(a) == multi_view(b) else 'SEMANTIC_DIFFERENT'
    except _MALFORMED:
        return 'INCOMPLETE_EVIDENCE'


def multi_requirements():
    """The fixed, ordered S-MULTI source-readiness requirement ids (pinned by tests)."""
    return (['seed:uploaded', 'seed:rows', 'calibration:closed_single', 'calibration:threshold_default',
             'prediction:in_range'] + [f'threshold:committed:{which}' for which, _ in MULTI_COMMITS]
            + ['rows:stable', 'at_t:multipart', 'at_t:header_premise', 'at_t_plus_1:single', 'boundary:exact']
            + [f'partition:{label}' for label in MULTI_LABELS]
            + ['minimum:closed_contiguous', 'minimum:part_facts', 'minimum:semantic', 'minimum:dependent_targets',
               'steps:all_done'])


def _multi_export(record, layouts, fingerprints, label):
    artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
    artifact = artifacts.get(label) if isinstance(artifacts.get(label), dict) else {}
    parts = artifact.get('parts') if isinstance(artifact.get('parts'), list) else []
    lay = layouts.get(label)
    fp = fingerprints.get(label)
    lay = lay if isinstance(lay, list) and lay and all(isinstance(l, dict) for l in lay) else None
    closed = (artifact.get('closure') == 'CLOSED' and bool(parts) and lay is not None and len(lay) == len(parts))
    return {'parts': parts, 'closed': closed, 'threshold': artifact.get('threshold'),
            'layouts': lay if closed else None, 'fp': fp if closed and _well_formed(fp) else None}


def _multi_targets(export):
    """What the dependents consume exists in the minimum artifact: settings and custom code only in
    Part 1, every part parsed with at least one chunk (so the middle Part 2 and the final part are
    real), and Part 2's first row carries a decoded data URL (BADDATA's declared field)."""
    fp = export['fp']
    if fp is None or len(export['parts']) < MULTI_MIN_PARTS or len(fp['parts']) != len(export['parts']):
        return False
    counts = [p.get('chunk_count') for p in fp['parts']]
    if not all(type(c) is int and c >= 1 for c in counts) or sum(counts) != len(fp['rows']):
        return False
    row = fp['rows'][counts[0]]
    content = ((row.get('file') or {}).get('content') or {}) if isinstance(row, dict) else {}
    return (fp['parts'][0].get('has_settings') is True and fp.get('custom_code') is not None
            and not any(p.get('has_settings') for p in fp['parts'][1:])
            and all(p.get('parse') == 'PARSED' for p in fp['parts']) and content.get('status') == 'DECODED')


def _multi_holds(record, layouts, fingerprints, seed_sha256):
    ex = {label: _multi_export(record, layouts, fingerprints, label) for label in MULTI_LABELS}
    cal, at_t, plus, low = (ex[label] for label in MULTI_LABELS)
    prediction = record.get('boundary_prediction') if isinstance(record.get('boundary_prediction'), dict) else {}
    intended = record.get('thresholds') if isinstance(record.get('thresholds'), dict) else {}
    steps = [s for s in record.get('steps') or [] if isinstance(s, dict)]
    seed = next((s for s in steps if s.get('step') == 'seed_multi'), {})
    seeds = list(seed_sha256) if isinstance(seed_sha256, (list, tuple)) else []
    holds = {'seed:uploaded': _same(seed.get('uploaded'), MULTI_COUNT) and _same(seed.get('backgrounds_dom'), MULTI_COUNT)}
    # Content multiset, not upload order (ui.upload_limits: the stored blob is the uploaded file;
    # the rendered order is decided by ranks, never assumed here).
    contents = [((r.get('file') or {}).get('content') or {}) for r in cal['fp']['rows']] if cal['fp'] else []
    holds['seed:rows'] = (len(contents) == MULTI_COUNT == len(seeds) and all(isinstance(d, str) for d in seeds)
                          and all(c.get('status') == 'DECODED' and isinstance(c.get('sha256'), str) for c in contents)
                          and sorted(c['sha256'] for c in contents) == sorted(seeds))
    holds['calibration:closed_single'] = (cal['closed'] and len(cal['parts']) == 1
                                          and cal['layouts'][0].get('native_template') is True
                                          and cal['layouts'][0].get('settings_header') is True)
    holds['calibration:threshold_default'] = _same(cal['threshold'], THRESHOLD_DEFAULT)
    t = prediction.get('threshold')
    holds['prediction:in_range'] = (prediction.get('converged') is True and prediction.get('in_ui_range') is True
                                    and type(t) is int and THRESHOLD_MIN <= t and t + 1 <= THRESHOLD_MAX
                                    and _same(prediction.get('calibration_threshold'), cal['threshold']))
    targets = {'predicted': t if type(t) is int else None, 'predicted_plus_1': t + 1 if type(t) is int else None,
               'minimum': THRESHOLD_MIN}
    for which, label in MULTI_COMMITS:
        holds[f'threshold:committed:{which}'] = (targets[which] is not None and _same(intended.get(which), targets[which])
                                                  and _same(ex[label]['threshold'], targets[which]))
    cores = [[c for l in ex[k]['layouts'] for c in l.get('chunk_core_bytes')] if ex[k]['layouts'] else None
             for k in MULTI_LABELS]
    rows = [ex[k]['fp']['rows'] if ex[k]['fp'] else None for k in MULTI_LABELS]
    holds['rows:stable'] = (cores[0] is not None and len(cores[0]) == MULTI_COUNT and all(c == cores[0] for c in cores)
                            and rows[0] is not None and all(r == rows[0] for r in rows))
    holds['at_t:multipart'] = at_t['closed'] and len(at_t['parts']) >= 2
    header = (at_t['layouts'][0].get('header_bytes') if at_t['layouts'] and at_t['layouts'][0].get('settings_header')
              else None)
    holds['at_t:header_premise'] = type(header) is int and _same(prediction.get('header_adjusted_bytes'), header)
    holds['at_t_plus_1:single'] = plus['closed'] and len(plus['parts']) == 1
    holds['boundary:exact'] = classify_boundary(prediction, len(at_t['parts']) if at_t['closed'] else None,
                                                len(plus['parts']) if plus['closed'] else None,
                                                header) == 'EXACT_BOUNDARY_OBSERVED'
    for label in MULTI_LABELS:
        consistency = (partition_layouts(ex[label]['layouts'], ex[label]['threshold']) if ex[label]['closed']
                       else {'status': 'INCOMPLETE_EVIDENCE'})
        holds[f'partition:{label}'] = (consistency['status'] == 'CONSISTENT' and consistency.get('empty_parts') == 0
                                       and all(w is True for w in consistency.get('well_formed') or [False]))
    names = [p.get('name_class') if isinstance(p, dict) else None for p in low['parts']]
    holds['minimum:closed_contiguous'] = (low['closed'] and len(names) >= MULTI_MIN_PARTS
                                          and names == [f'NATIVE_PART_{n}' for n in range(1, len(names) + 1)]
                                          and all(l.get('native_template') is True for l in low['layouts'])
                                          and low['layouts'][0].get('settings_header') is True)
    holds['minimum:part_facts'] = bool(low['parts']) and all(
        isinstance(p, dict) and _same(p.get('index'), n) and type(p.get('bytes')) is int
        and 0 < p['bytes'] <= MULTI_PART_LIMIT and isinstance(p.get('sha256'), str)
        and _HEX64.fullmatch(p['sha256']) is not None for n, p in enumerate(low['parts']))
    holds['minimum:semantic'] = (cal['fp'] is not None and low['fp'] is not None
                                 and multi_view(cal['fp'], True) == multi_view(low['fp'], True))
    holds['minimum:dependent_targets'] = _multi_targets(low)
    expected = list(case('S-MULTI')['steps'])
    holds['steps:all_done'] = ([s.get('step') for s in steps if s.get('step') in expected] == expected
                               and all(s.get('status') == 'DONE' for s in steps))
    return holds


def multi_readiness(record, layouts, fingerprints, seed_sha256):
    """{'schema', 'ready', 'missing'} of one S-MULTI attempt: ready only when every requirement in
    multi_requirements() holds. `record` is the session record (steps, artifacts with each export's own
    threshold, boundary_prediction, intended thresholds), `layouts` and `fingerprints` are per export
    label and `seed_sha256` the digests of the deterministic seed files. Malformed input misses all."""
    try:
        holds = _multi_holds(record if isinstance(record, dict) else {}, layouts if isinstance(layouts, dict) else {},
                             fingerprints if isinstance(fingerprints, dict) else {}, seed_sha256)
    except _MALFORMED + (VerificationError,):
        holds = {}
    missing = [r for r in multi_requirements() if holds.get(r) is not True]
    return {'schema': MULTI_READINESS_SCHEMA, 'ready': not missing, 'missing': missing}


def multipart_slots(selection, count):
    """Expected (named part, directory slot, source part number) per selected file, in selection order,
    for a `count`-part source; None for an undeclared selection. Mirrors select_parts()."""
    ordered = [(n, 0, n) for n in range(1, count + 1)]
    return {'ordered': ordered, 'truncate_last': ordered, 'bad_data_part_2': ordered,
            'reversed': ordered[::-1], 'no_part_1': ordered[1:], 'no_middle': ordered[:1] + ordered[2:],
            'duplicate_middle': ordered + [(MULTI_MIDDLE, 1, MULTI_MIDDLE)]}.get(selection)


def _multipart_mutation_holds(selection, before, after):
    """TRUNC: the input is exactly the maintained prefix of the final part and unparseable. BADDATA: the
    parsed input equals the parsed original with only the declared field set to the declared literal,
    which was a decoded data URL and is now undecodable."""
    if selection == 'truncate_last':
        try:
            json.loads(after)
            return False
        except (ValueError, RecursionError):
            pass
        return len(after) < len(before) and after == before[:max(1, len(before) * 2 // 3)]
    path, literal = MUTATIONS['invalid_data_url'][1], MUTATIONS['invalid_data_url'][2]
    original, given = json.loads(before), json.loads(after)
    return (given == _set(original, path, literal) and content_digest(_walk(original, path))['status'] == 'DECODED'
            and content_digest(_walk(given, path))['status'] == 'UNDECODABLE')


MULTIPART_PROOF_FACTS = ('source_binding', 'unmutated_input_equals_ready_source', 'selection_bytes_equal_input',
                         'untouched_parts_byte_identical', 'mutation_record_binds')


def multipart_input_proof(entry, inputs, source_parts, original_parts, selected_parts):
    """Pre-selection proof for a B dependent. `inputs` is the attempt's matrix_inputs (with the
    preflight's source_readiness: ready, same_root and the ready minimum part digests),
    `source_parts` the restore input parts (mutated where declared), `original_parts` the unmutated
    same-root parts (the input itself when nothing is mutated) and `selected_parts` the bytes of the
    files about to be selected, in selection order. Pure and total: fixed enums, ints and booleans;
    `proven` only when every fact holds."""
    ok = (isinstance(entry, dict) and entry.get('category') == 'B' and entry.get('runnable') is True
          and entry.get('source') == 'S-MULTI' and entry.get('artifact') == 'minimum'
          and entry.get('selection') in MULTIPART_SELECTIONS)
    selection = entry['selection'] if ok else None
    mutated = selection in MULTIPART_MUTATIONS
    out = {'schema': MULTIPART_INPUT_SCHEMA, 'case': entry.get('id') if ok else None, 'selection_kind': selection,
           'declared_relation': MULTIPART_SELECTIONS.get(selection), 'source_binding': False,
           'source_part_count': None, 'source_ordinals': None, 'unmutated_input_equals_ready_source': False,
           'selection_class': None, 'selected_ordinals': None,
           'middle_ordinal': MULTI_MIDDLE if selection in ('no_middle', 'duplicate_middle') else None,
           'selection_bytes_equal_input': False, 'untouched_parts_byte_identical': False,
           'mutation_record_binds': False, 'mutated_part': None,
           'mutation_proof': 'UNPROVEN' if mutated else 'NOT_APPLICABLE', 'proven': False}
    if not ok:
        return out
    try:
        inputs = inputs if isinstance(inputs, dict) else {}
        source, original, selected = list(source_parts), list(original_parts), list(selected_parts)
        if not (source and all(isinstance(p, bytes) for p in source + original + selected)):
            return out
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        count = len(original)
        readiness = inputs.get('source_readiness') if isinstance(inputs.get('source_readiness'), dict) else {}
        numbers = lambda key: ([i.get('part_number') for i in inputs[key]] if isinstance(inputs.get(key), list)
                               and all(isinstance(i, dict) for i in inputs[key]) else None)
        contiguous = list(range(1, count + 1))
        out['source_part_count'] = count
        out['source_ordinals'] = ('CONTIGUOUS_1_N' if count and len(source) == count and numbers('source') == contiguous
                                  and (not mutated or numbers('original') == contiguous) else 'BROKEN')
        out['source_binding'] = (inputs.get('source_case') == 'S-MULTI' and inputs.get('artifact') == 'minimum'
                                 and inputs.get('selection_kind') == selection and readiness.get('ready') is True
                                 and readiness.get('same_root') is True)
        ready = readiness.get('minimum_part_sha256')
        out['unmutated_input_equals_ready_source'] = (isinstance(ready, list) and len(ready) == count
                                                      and [sha(p) for p in original] == ready)
        listed = inputs.get('selection') if isinstance(inputs.get('selection'), list) else []
        listed = [s for s in listed if isinstance(s, dict)] if all(isinstance(s, dict) for s in listed) else []
        expected = multipart_slots(selection, count) if count >= MULTI_MIN_PARTS else None
        observed = [(s.get('named_part'), s.get('slot'), s.get('part_number')) for s in listed]
        out['selection_class'] = selection if expected is not None and observed == expected else 'UNEXPECTED'
        out['selected_ordinals'] = [_count(s.get('part_number')) for s in listed[:MULTIPART_ROW_LIMIT]]
        out['selection_bytes_equal_input'] = (
            bool(listed) and len(selected) == len(listed) and _digests(inputs.get('source')) == [sha(p) for p in source]
            and all(type(s.get('part_number')) is int and 1 <= s['part_number'] <= len(source)
                    and raw == source[s['part_number'] - 1] and s.get('sha256') == sha(raw)
                    for s, raw in zip(listed, selected)))
        if not mutated:
            out['untouched_parts_byte_identical'] = source == original
            out['mutation_record_binds'] = inputs.get('mutation') is None and not inputs.get('original')
        else:
            mutation, at, edit, target, parseable, proof_class = MULTIPART_MUTATIONS[selection]
            number = count if at == -1 else at
            record = inputs.get('mutation') if isinstance(inputs.get('mutation'), dict) else {}
            out['mutated_part'] = _count(record.get('part_number'))
            if not (count >= MULTI_MIN_PARTS and len(source) == count
                    and entry.get('mutate_part') == at and entry.get('mutation') == mutation):
                return out
            out['untouched_parts_byte_identical'] = all(a == b for n, (a, b) in enumerate(zip(source, original), 1)
                                                        if n != number)
            out['mutation_record_binds'] = (
                record.get('mutation') == mutation and record.get('edit') == edit and record.get('target') == target
                and record.get('part_number') == number and record.get('parseable') is parseable
                and record.get('before_sha256') == sha(original[number - 1])
                and record.get('after_sha256') == sha(source[number - 1])
                and _digests(inputs.get('original')) == [sha(p) for p in original])
            out['mutation_proof'] = (proof_class if _multipart_mutation_holds(selection, original[number - 1],
                                                                              source[number - 1]) else 'UNPROVEN')
        out['proven'] = (out['source_ordinals'] == 'CONTIGUOUS_1_N' and out['selection_class'] == selection
                         and count >= MULTI_MIN_PARTS and all(out[k] is True for k in MULTIPART_PROOF_FACTS)
                         and out['mutation_proof'] == ('NOT_APPLICABLE' if not mutated
                                                       else MULTIPART_MUTATIONS[selection][5]))
    except _MALFORMED + (VerificationError,):
        out['proven'] = False
    return out


def _multipart_proof_projection(proof):
    """The recorded input proof reduced to fixed values; anything else reads None."""
    p = proof if isinstance(proof, dict) else {}
    ordinals = p.get('selected_ordinals')
    return {'schema': _fixed(p.get('schema'), (MULTIPART_INPUT_SCHEMA,)),
            'selection_kind': _fixed(p.get('selection_kind'), tuple(MULTIPART_SELECTIONS)),
            'declared_relation': _fixed(p.get('declared_relation'), tuple(MULTIPART_SELECTIONS.values())),
            'selection_class': _fixed(p.get('selection_class'), (*MULTIPART_SELECTIONS, 'UNEXPECTED')),
            'source_ordinals': _fixed(p.get('source_ordinals'), ORDINAL_CLASSES),
            'mutation_proof': _fixed(p.get('mutation_proof'), MUTATION_PROOFS),
            **{k: _fixed(p.get(k), (True, False)) for k in ('proven', *MULTIPART_PROOF_FACTS)},
            'source_part_count': _count(p.get('source_part_count')), 'middle_ordinal': _count(p.get('middle_ordinal')),
            'mutated_part': _count(p.get('mutated_part')),
            'selected_ordinals': [_count(n) for n in ordinals[:MULTIPART_ROW_LIMIT]] if isinstance(ordinals, list)
            else None}


def _ints(value):
    return [_count(v) for v in value[:MULTIPART_ROW_LIMIT]] if isinstance(value, list) else None


def _multi_source_block(record):
    """S-MULTI: readiness, supported range, prediction, boundary and per-export partition facts, from
    the session record only. Part bytes never leave: ordinals, sizes, digests and chunk counts."""
    classes = record.get('classifications') if isinstance(record.get('classifications'), dict) else {}
    prediction = record.get('boundary_prediction') if isinstance(record.get('boundary_prediction'), dict) else {}
    artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
    partition = record.get('partition') if isinstance(record.get('partition'), dict) else {}
    intended = record.get('thresholds') if isinstance(record.get('thresholds'), dict) else {}
    missing = classes.get('multi_source_missing')
    missing = [m for m in missing if m in multi_requirements()] if isinstance(missing, list) else None
    t = prediction.get('threshold') if type(prediction.get('threshold')) is int else None
    targets = {'at_t': t, 'at_t_plus_1': t + 1 if t is not None else None, 'minimum': THRESHOLD_MIN,
               'calibration': THRESHOLD_DEFAULT}
    exports = {}
    for label in MULTI_LABELS:
        artifact = artifacts.get(label) if isinstance(artifacts.get(label), dict) else {}
        parts = artifact.get('parts') if isinstance(artifact.get('parts'), list) else []
        parts = [p for p in parts if isinstance(p, dict)]
        names = [p.get('name_class') for p in parts]
        consistency = partition.get(label) if isinstance(partition.get(label), dict) else {}
        observed = _ints(consistency.get('observed_part_sizes'))
        own = artifact.get('threshold') if type(artifact.get('threshold')) is int else None
        exports[label] = {
            'closure': _fixed(artifact.get('closure'), CLOSURES), 'part_count': len(parts) if parts else None,
            'ordinal_class': (None if not parts else 'CONTIGUOUS_1_N'
                              if names == [f'NATIVE_PART_{n}' for n in range(1, len(parts) + 1)] else 'BROKEN'),
            'threshold': _count(own), 'threshold_matches_intended': own is not None and own == targets[label],
            'parts': [{'ordinal': n, 'bytes': _count(p.get('bytes')),
                       'sha256': p['sha256'] if isinstance(p.get('sha256'), str) and _HEX64.fullmatch(p['sha256'])
                       else None,
                       'chunk_count': observed[n - 1] if observed and len(observed) == len(parts) else None}
                      for n, p in enumerate(parts[:MULTIPART_ROW_LIMIT], 1)],
            'semantic_sha256': artifact.get('semantic_sha256') if isinstance(artifact.get('semantic_sha256'), str)
            and _HEX64.fullmatch(artifact['semantic_sha256']) else None,
            'partition': {'status': _fixed(consistency.get('status'), PARTITION_STATUSES),
                          'observed_part_sizes': observed,
                          'simulated_part_sizes': _ints(consistency.get('simulated_part_sizes')),
                          'well_formed': [_fixed(w, (True, False)) for w in consistency['well_formed']]
                          if isinstance(consistency.get('well_formed'), list) else None,
                          'empty_parts': _count(consistency.get('empty_parts'))}}
    header, adjusted = record.get('boundary_header_at_t'), prediction.get('header_adjusted_bytes')
    calibration = prediction.get('calibration_threshold')
    return {'readiness': {'schema': MULTI_READINESS_SCHEMA, 'ready': _fixed(classes.get('multi_source_ready'),
                                                                              (True, False)),
                          'missing': missing},
            'supported_threshold': {'minimum': THRESHOLD_MIN, 'default': THRESHOLD_DEFAULT, 'maximum': THRESHOLD_MAX},
            'calibration_threshold_class': ('DEFAULT' if _same(calibration, THRESHOLD_DEFAULT) else 'ABSENT'
                                            if calibration is None else 'OTHER'),
            'predicted_threshold': _count(t), 'prediction_converged': _fixed(prediction.get('converged'), (True, False)),
            'predicted_in_range': _fixed(prediction.get('in_ui_range'), (True, False)),
            'intended_thresholds': {k: _count(intended.get(k)) for k, _ in MULTI_COMMITS},
            'header': {'relation': ('INCOMPLETE_EVIDENCE' if type(header) is not int or type(adjusted) is not int
                                    else 'HEADER_MATCH' if header == adjusted else 'HEADER_DRIFT'),
                       'predicted_bytes': _count(adjusted), 'observed_bytes': _count(header)},
            'boundary': _fixed(classes.get('boundary'), BOUNDARY_CLASSES),
            'partition': _fixed(classes.get('partition'), PARTITION_STATUSES), 'exports': exports}


def multipart_rows(pre, original, post):
    """Where each post row came from, against the unmutated source (id + content) and the pre-state.
    Ids are compared here and never returned. (origins, relation, missing parts, duplicated parts)."""
    try:
        if not all(_well_formed(fp) for fp in (pre, original, post)):
            return None, 'INCOMPLETE_EVIDENCE', None, None
        keys = [_row_key(r) for r in original['rows']]
        ids = [json.dumps(r.get('id'), sort_keys=True) for r in original['rows']]
        part_of = []
        for number, part in enumerate(original['parts'], 1):
            part_of += [number] * (part.get('chunk_count') or 0)
        if len(part_of) != len(keys):
            return None, 'INCOMPLETE_EVIDENCE', None, None
        prior = {_row_key(r) for r in pre['rows']}
        origins, kinds, found = [], [], []
        for r in post['rows']:
            key, rid = _row_key(r), json.dumps(r.get('id'), sort_keys=True)
            if key in keys:
                kind, at = 'SOURCE', keys.index(key)
            elif r.get('id') is not None and rid in ids:
                kind, at = 'SOURCE_ID_CONTENT_CHANGED', ids.index(rid)
            elif key in prior:
                kind, at = 'PRE_STATE', None
            else:
                kind, at = 'OTHER', None
            kinds.append(kind)
            if kind == 'SOURCE':
                found.append(at)
            origins.append({'origin': kind, 'source_row': at, 'source_part': part_of[at] if at is not None else None})
        whole = list(range(len(keys)))
        if not kinds:
            relation = 'NO_ROWS'
        elif set(kinds) == {'SOURCE'}:
            relation = ('SOURCE_ROWS_EXACT_ORDER' if found == whole else 'SOURCE_ROWS_DUPLICATED'
                        if len(set(found)) < len(found) else 'SOURCE_ROWS_PERMUTED' if sorted(found) == whole
                        else 'SOURCE_SUBSET_IN_ORDER' if found == sorted(found) else 'SOURCE_SUBSET_REORDERED')
        elif set(kinds) == {'PRE_STATE'}:
            relation = 'PRE_STATE_ONLY'
        elif set(kinds) == {'SOURCE', 'PRE_STATE'}:
            relation = 'MIXED_SOURCE_AND_PRE_STATE'
        else:
            relation = 'OTHER_ROWS_PRESENT'
        seen = {}
        for at in found:
            seen[at] = seen.get(at, 0) + 1
        parts = sorted(set(part_of))
        missing = [p for p in parts if not any(seen.get(i) for i, q in enumerate(part_of) if q == p)]
        duplicated = [p for p in parts if any(seen.get(i, 0) > 1 for i, q in enumerate(part_of) if q == p)]
        return origins, relation, missing, duplicated
    except _MALFORMED:
        return None, 'INCOMPLETE_EVIDENCE', None, None


def threshold_pref_class(fp):
    """The post-restore threshold pref: the S-MULTI minimum, the target default, other or absent."""
    if not _well_formed(fp):
        return 'INCOMPLETE_EVIDENCE'
    prefs = _prefs(fp)
    if THRESHOLD_PREF not in prefs:
        return 'ABSENT'
    value = prefs[THRESHOLD_PREF]
    return 'SOURCE_MINIMUM' if _same(value, THRESHOLD_MIN) else 'TARGET_DEFAULT' if _same(value, THRESHOLD_DEFAULT) \
        else 'OTHER'


def multipart_predictions(entry, record, gate, completion, application, relation, components, state, consistent):
    """Catalogue predictions copied as predictions only. ORDERED and REVERSED `backgrounds=RESTORED`:
    MATCH only on a gated COMPLETED restore that applied (fresh-target application APPLIED) with the
    source rows in exact source order and backgrounds equal to the source; MISMATCH on any other
    observed COMPLETED reading; otherwise UNOBSERVED. Error-independent. Every other (inherited D-like)
    prediction uses the D rule: its legacy status counts only beside a consistent TRUE or FALSE
    tri-state, else UNOBSERVED."""
    recorded = record.get('predictions') if isinstance(record.get('predictions'), dict) else {}
    catalogue = entry.get('predictions') if isinstance(entry.get('predictions'), dict) else {}
    out = {}
    for key, predicted in catalogue.items():
        item = recorded.get(key) if isinstance(recorded.get(key), dict) else {}
        legacy = _fixed(item.get('status'), PREDICTION_STATUSES)
        if key == 'backgrounds' and entry.get('profile') == FRESH_TARGET and predicted == 'RESTORED':
            observed = (gate and completion == 'COMPLETED' and application not in (None, 'INCOMPLETE_EVIDENCE')
                        and relation not in (None, 'INCOMPLETE_EVIDENCE'))
            match = (observed and application == 'APPLIED' and relation == 'SOURCE_ROWS_EXACT_ORDER'
                     and components.get('backgrounds') == 'EQUAL_TO_SOURCE')
            status, basis = ('MATCH' if match else 'MISMATCH' if observed else 'UNOBSERVED'), MULTIPART_PREDICTION_BASIS
        else:
            status = legacy if state in ('TRUE', 'FALSE') and consistent and legacy else 'UNOBSERVED'
            basis = PREDICTION_BASIS
        out[key] = {'predicted': _fixed(predicted, COMPONENT_CLASSES), 'status': status, 'basis': basis,
                    'legacy_status': legacy, 'legacy_basis': PREDICTION_BASIS}
    return out


def multipart_evidence(entry, fingerprints, given, original, selected, record, inputs):
    """The fixed multipart evidence for S-MULTI (its source block) or a runnable B dependent; None for
    any other case.

    For a dependent, `given` is the fingerprint of the restore input parts, `original` that of the
    unmutated same-root S-MULTI minimum parts, `selected` {'native_order', 'selection_order'}
    fingerprints of the selected file bytes (native part order, stable; and selection order), `record`
    the session record (restores, artifacts, the recorded pre-restore proof and ribbon reading) and
    `inputs` the digest-level matrix_inputs. Every class is computed only when the one restore was
    positively observed to start with a known completion, the post-export closed, the pre, source and
    post fingerprints are well formed and the recorded input proof holds; otherwise every class is
    INCOMPLETE_EVIDENCE and the digests are still disclosed. Components never read restore_error: an
    error or ribbon never implies a sentinel was preserved. The tri-state is
    malformed_restore_error_state() under the pinned REPORT_OBSERVABILITY, so a completion without a
    ribbon stays UNKNOWN."""
    case_id = entry.get('id') if isinstance(entry, dict) else None
    if not (isinstance(entry, dict) and entry.get('category') == 'B' and entry.get('runnable') is True):
        return None
    if entry.get('source') is None:
        try:
            block = _multi_source_block(record if isinstance(record, dict) else {})
            return {'schema': MULTIPART_EVIDENCE_SCHEMA, 'case': case_id, 'role': 'SOURCE',
                    'evidence': 'OBSERVED' if block['readiness']['ready'] is not None else 'INCOMPLETE_EVIDENCE',
                    'observation_scope': OBSERVATION_SCOPE, 'source': block}
        except _MALFORMED:
            return {'schema': MULTIPART_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'INCOMPLETE_EVIDENCE'}
    if entry.get('selection') not in MULTIPART_SELECTIONS:
        return None
    try:
        fps = fingerprints if isinstance(fingerprints, dict) else {}
        record = record if isinstance(record, dict) else {}
        inputs = inputs if isinstance(inputs, dict) else {}
        selected = selected if isinstance(selected, dict) else {}
        native, ordered = selected.get('native_order'), selected.get('selection_order')
        pre, post = fps.get('pre'), fps.get('post')
        fresh = entry.get('profile') == FRESH_TARGET
        restores = [r for r in record.get('restores') or [] if isinstance(r, dict)] \
            if isinstance(record.get('restores'), list) else []
        restore = restores[0] if len(restores) == 1 else {}
        pre_ribbon = _fixed(record.get('pre_restore_error_ribbon'), PRE_RESTORE_RIBBONS)
        state, consistent = (malformed_restore_error_state(restore, REPORT_OBSERVABILITY, pre_ribbon)
                             if len(restores) == 1 else ('UNKNOWN', False))
        artifacts = record.get('artifacts') if isinstance(record.get('artifacts'), dict) else {}
        post_record = artifacts.get('post') if isinstance(artifacts.get('post'), dict) else {}
        post_derived = post_record.get('derived') if isinstance(post_record.get('derived'), dict) else {}
        closure = _fixed(post_record.get('closure'), CLOSURES)
        completion = _fixed(restore.get('completion'), COMPLETIONS)
        proof = record.get('multipart_input') if isinstance(record.get('multipart_input'), dict) else {}
        gate = (len(restores) == 1 and restore.get('start_observed') is True and completion is not None
                and closure == 'CLOSED' and all(_well_formed(fp) for fp in (pre, original, post))
                and proof.get('proven') is True)
        application = effect = residue = None
        if gate and fresh:
            components = compat_components(pre, original, post, None)
            application = compat_application(components, completion)
        elif gate:
            components = sentinel_components(pre, native, original, post)
            effect, residue = state_effect(components), prior_residue(pre, original, post)
        else:
            components = dict.fromkeys(COMPONENTS, 'INCOMPLETE_EVIDENCE')
            application = 'INCOMPLETE_EVIDENCE' if fresh else None
            effect = None if fresh else 'INCOMPLETE_EVIDENCE'
        origins, relation, missing, duplicated = (multipart_rows(pre, original, post) if gate
                                                  else (None, 'INCOMPLETE_EVIDENCE', None, None))
        codes, silent = restore.get('error_codes'), restore.get('silent_codes')
        post_parts = post_record.get('parts') if isinstance(post_record.get('parts'), list) else None
        out = {
            'schema': MULTIPART_EVIDENCE_SCHEMA, 'case': case_id, 'role': 'DEPENDENT',
            'evidence': 'OBSERVED' if gate else 'INCOMPLETE_EVIDENCE',
            'observation_scope': OBSERVATION_SCOPE, 'live_data_scope': LIVE_DATA_SCOPE,
            'input': {'selection_kind': entry['selection'], 'declared_relation': MULTIPART_SELECTIONS[entry['selection']],
                      'target_profile': _fixed(entry.get('profile'), (FRESH_TARGET, SEEDED_SENTINEL)),
                      'mutation': _fixed(entry.get('mutation'), tuple(MUTATIONS)),
                      'proof': _multipart_proof_projection(proof)},
            'source': {'source_case': _fixed(entry.get('source'), ('S-MULTI',)),
                       'artifact': _fixed(entry.get('artifact'), ('minimum',)), 'readiness_gate': MULTI_READINESS_GATE,
                       'original_semantic_sha256': semantic_sha256(original),
                       'given_semantic_sha256': semantic_sha256(given),
                       'selected_native_order_semantic_sha256': semantic_sha256(native),
                       'selected_order_semantic_sha256': semantic_sha256(ordered), **_input_binding(inputs)},
            'completion': {'completion': completion, 'restore_count': len(restores), 'restore_error': state,
                           'state_consistent': consistent,
                           'recorded_restore_error': _fixed(restore.get('restore_error'), (True, False)),
                           'start_observed': _fixed(restore.get('start_observed'), (True, False)),
                           'transition_end_observed': _fixed(restore.get('transition_end_observed'), (True, False)),
                           'selected_files': _count(restore.get('selected_files')),
                           'pre_restore_error_ribbon': pre_ribbon,
                           'report_observability': _fixed(REPORT_OBSERVABILITY, REPORT_OBSERVABILITIES),
                           'observability_gaps': [g for g in OBSERVABILITY_GAPS if g in OBSERVABILITY_OBLIGATIONS],
                           'completion_basis': None if completion is None else 'NO_COMPLETION_SIGNAL'
                           if completion == 'DEADLINE_NO_SIGNAL' else 'COMPLETION_OBSERVED'},
            'reports': {'loud_present': bool(codes) or restore.get('restore_error') is True
                        or restore.get('error_ribbon_seen') is True,
                        'silent_present': bool(silent),
                        'error_ribbon_seen': _fixed(restore.get('error_ribbon_seen'), (True, False)),
                        'loud_codes': report_projection(codes, False), 'silent_codes': report_projection(silent, True),
                        'restore_route_codes': RESTORE_ROUTE_CODES},
            'post': {'closure': closure, 'complete': _fixed(post_record.get('complete'), (True, False)),
                     'row_count': _count(post_derived.get('row_count')),
                     'task_count': _count(post_derived.get('task_count')),
                     'part_count': len(post_parts) if post_parts is not None else None},
            'semantics': {'pre_semantic_sha256': semantic_sha256(pre), 'post_semantic_sha256': semantic_sha256(post),
                          'post_vs_source': multi_relation(post, original),
                          'post_vs_given': multi_relation(post, given),
                          'post_vs_selection_native_order': multi_relation(post, native),
                          'post_vs_selection_order': multi_relation(post, ordered),
                          'post_vs_pre': multi_relation(post, pre)},
            'rows': {'post_row_count': len(post['rows']) if gate else None,
                     'post_row_origins': origins[:MULTIPART_ROW_LIMIT] if origins is not None else None,
                     'origins_truncated': len(origins) > MULTIPART_ROW_LIMIT if origins is not None else None,
                     'row_relation': relation, 'missing_source_parts': missing,
                     'duplicated_source_parts': duplicated,
                     'post_rank_class': _fixed(post['derived'].get('rank_class'), RANK_SHAPES)
                     if gate and isinstance(post.get('derived'), dict) else None,
                     'ranks_vs_source': malformed_ranks(original, original, post) if gate else 'INCOMPLETE_EVIDENCE'},
            'components': components, 'application': application, 'state_effect': effect,
            'prior_residue': residue,
            'settings': {'threshold_pref_class': threshold_pref_class(post) if gate else 'INCOMPLETE_EVIDENCE'},
            'predictions': multipart_predictions(entry, record, gate, completion, application, relation, components,
                                                 state, consistent),
            'prediction_scope': PREDICTION_SCOPE}
        if not fresh:
            out['sentinel_pre'] = {'contract': 'SEEDED_SENTINEL_V1', 'semantic_sha256': semantic_sha256(pre),
                                   'row_count': len(pre['rows']) if _well_formed(pre) else None,
                                   'task_count': len(_task_keys(pre)) if _well_formed(pre) else None}
        return out
    except _MALFORMED:
        return {'schema': MULTIPART_EVIDENCE_SCHEMA, 'case': case_id, 'evidence': 'INCOMPLETE_EVIDENCE'}


# --- Case catalogue ------------------------------------------------------------------------

FRESH_SOURCE, FRESH_TARGET, SEEDED_SENTINEL = 'FRESH_SOURCE', 'FRESH_TARGET', 'SEEDED_SENTINEL'
PROFILE_CONTRACTS = (FRESH_SOURCE, FRESH_TARGET, SEEDED_SENTINEL)


def _case(case_id, category, profile, *, source=None, artifact=None, selection=None, mutation=None,
          mutate_part=1, steps=(), predictions=None, runnable=True, reason=None, allow_no_signal=None):
    # A restore that is expected to be refused may end with no completion signal; that is an
    # observation there (recorded as DEADLINE_NO_SIGNAL) and a failure everywhere else. A silent E
    # rejection is an observation too (COMPAT-E-PREP1), never a stop of the budget.
    if allow_no_signal is None:
        allow_no_signal = category in ('D', 'E') or (category == 'B' and profile == SEEDED_SENTINEL)
    return {'id': case_id, 'category': category, 'profile': profile, 'source': source,
            'artifact': artifact, 'selection': selection, 'mutation': mutation, 'mutate_part': mutate_part,
            'steps': tuple(steps), 'predictions': dict(predictions or {}), 'runnable': runnable,
            'reason': reason, 'allow_no_signal': allow_no_signal}


RESTORE = ('pre_export', 'restore', 'reload', 'post_export')
_D = {'backgrounds': 'REJECTED_STATE_DESTROYED', 'custom_code': 'REJECTED_STATE_PRESERVED'}
CASES = (
    _case('S-RICH', 'A', FRESH_SOURCE, steps=('pre_export', 'seed_rich', 'export:rich')),
    _case('T-RICH', 'A', FRESH_TARGET, source='S-RICH', artifact='rich', selection='ordered', steps=RESTORE,
          predictions={'backgrounds': 'RESTORED', 'ranks': 'RANK_PRESERVED'}),
    _case('S-MULTI', 'B', FRESH_SOURCE,
          steps=('pre_export', 'seed_multi', 'export:calibration', 'threshold:predicted', 'export:at_t',
                 'threshold:predicted_plus_1', 'export:at_t_plus_1', 'threshold:minimum', 'export:minimum'),
          predictions={'boundary': 'EXACT_BOUNDARY_OBSERVED', 'partition': 'CONSISTENT'}),
    _case('T-MULTI-ORDERED', 'B', FRESH_TARGET, source='S-MULTI', artifact='minimum', selection='ordered',
          steps=RESTORE, predictions={'backgrounds': 'RESTORED'}),
    _case('T-MULTI-REVERSED', 'B', FRESH_TARGET, source='S-MULTI', artifact='minimum', selection='reversed',
          steps=RESTORE, predictions={'backgrounds': 'RESTORED'}),
    _case('T-MULTI-NO-P1', 'B', SEEDED_SENTINEL, source='S-MULTI', artifact='minimum', selection='no_part_1',
          steps=RESTORE),
    _case('T-MULTI-NO-MIDDLE', 'B', SEEDED_SENTINEL, source='S-MULTI', artifact='minimum',
          selection='no_middle', steps=RESTORE),
    _case('T-MULTI-DUP', 'B', SEEDED_SENTINEL, source='S-MULTI', artifact='minimum',
          selection='duplicate_middle', steps=RESTORE),
    _case('T-MULTI-TRUNC', 'B', SEEDED_SENTINEL, source='S-MULTI', artifact='minimum',
          selection='truncate_last', mutation='truncate_json', mutate_part=-1, steps=RESTORE,
          predictions=_D),
    _case('T-MULTI-BADDATA', 'B', SEEDED_SENTINEL, source='S-MULTI', artifact='minimum',
          selection='bad_data_part_2', mutation='invalid_data_url', mutate_part=2, steps=RESTORE),
    _case('T-DISPLACE', 'C', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='ordered',
          steps=RESTORE),
    _case('D-TRUNC-P1', 'D', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='single',
          mutation='truncate_json', steps=RESTORE, predictions=_D),
    _case('D-NO-CHUNKS', 'D', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='single',
          mutation='drop_chunks', steps=RESTORE, predictions=_D),
    _case('D-CHUNKS-TYPE', 'D', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='single',
          mutation='chunks_not_array', steps=RESTORE, predictions=_D),
    _case('D-BAD-DATAURL', 'D', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='single',
          mutation='invalid_data_url', steps=RESTORE),
    _case('D-NAME-NO-P1', 'D', SEEDED_SENTINEL, source='S-RICH', artifact='rich', selection='rename_no_part_1',
          steps=RESTORE),
    _case('D-EMPTY-SELECTION', 'D', SEEDED_SENTINEL, runnable=False,
          reason='NOT_DRIVEN: WebDriver file upload refuses an empty selection; not synthesized'),
    _case('E-TOP', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='unknown_top_level', steps=RESTORE, predictions={'unknown': 'IGNORED'}),
    _case('E-BG', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='unknown_background_data', steps=RESTORE),
    _case('E-PREF', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='unknown_pref', steps=RESTORE),
    _case('E-CODE', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='unknown_custom_code', steps=RESTORE),
    _case('E-TASK', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='unknown_task', steps=RESTORE),
    _case('E-ABSENT-OPT', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='absent_optional_prefs', steps=RESTORE),
    _case('E-VERSION', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='pref_version_older', steps=RESTORE),
    _case('E-THEMEID-DUP', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='synthetic_theme_id_duplicate', steps=RESTORE),
    _case('E-MODE-THEME', 'E', FRESH_TARGET, source='S-RICH', artifact='rich', selection='single',
          mutation='pref_mode_theme_background', steps=RESTORE),
    _case('F-REPEAT', 'F', FRESH_TARGET, source='S-RICH', artifact='rich', selection='ordered',
          steps=('pre_export', 'restore', 'reload', 'post_export', 'restore', 'reload', 'repeat_export'),
          predictions={'repeat': 'IDEMPOTENT'}),
)
CASE_INDEX = {c['id']: c for c in CASES}
CASE_COUNT, RUNNABLE_COUNT = 27, 26
# Classified, not faked (provenance keys cited in the candidate document).
NOT_REPRESENTABLE = {'theme_install': 'NOT_REPRESENTABLE_FIREFOX_6_12_1',
                     'theme_background_mode': 'NOT_REPRESENTABLE_FIREFOX_6_12_1',
                     'keep_old_theme_backgrounds': 'NOT_REPRESENTABLE_FIREFOX_6_12_1',
                     'video_background': 'NOT_EXERCISED_OFFLINE_SYNTHETIC_SCOPE',
                     'img_link_background': 'NOT_EXERCISED_NETWORK_DISABLED',
                     'solid_color_background': 'NOT_DRIVEN_NO_VERIFIED_DETERMINISTIC_SEAM'}


def case(case_id):
    require(case_id in CASE_INDEX, 'Unknown matrix case')
    return CASE_INDEX[case_id]


def validate_catalogue(cases=CASES):
    """Dependency closure: sources precede dependents and export the named artifact."""
    order = {c['id']: n for n, c in enumerate(cases)}
    require(len(order) == len(cases), 'Unknown matrix case')
    for entry in cases:
        require(entry['profile'] in PROFILE_CONTRACTS, 'Unknown matrix case')
        if entry['source'] is None:
            require(entry['selection'] is None and entry['mutation'] is None, 'Matrix input undeclared')
            continue
        source = cases[order[entry['source']]] if entry['source'] in order else None
        require(source is not None and order[source['id']] < order[entry['id']]
                and source['profile'] == FRESH_SOURCE
                and 'export:' + entry['artifact'] in source['steps'], 'Matrix input undeclared')
        require(entry['selection'] in SELECTIONS, 'Matrix input undeclared')
        require(entry['mutation'] is None or entry['mutation'] in MUTATIONS, 'Matrix input undeclared')
    return [c['id'] for c in cases if c['runnable']]


# --- Seed attribution trace (bux-r6-seed-trace-v1) ---------------------------------------------
# One entry per native UI action: fixed action ids and routes, and before/after observations
# reduced to allowlisted values. Page text, editor contents, ids, paths and messages never enter.

TRACE_SCHEMA = 'bux-r6-seed-trace-v1'
TRACE_LIMIT = 64
TRACE_ROUTES = ('option_click', 'box_click', 'keys_replace', 'element_click', 'file_keys', 'prompt',
                'codemirror_set', 'button_click', 'read_only')
TRACE_STATUSES = ('STARTED', 'DONE', 'FAILED', 'SKIPPED')
TRACE_ACTION = re.compile(
    r'upload|delete_gap|move_fractional|pref:[a-z_]{1,48}|context:(select_background|return_global)'
    r'|override:background_size|invariant:(override_global_unchanged|global_background_size)'
    r'|custom_code:(open|html|css|js|close)|scheduler:(mode|open|close)'
    r'|task:[1-9]:(background|year|time|day_of_the_month|add)|threshold:(minimum|predicted|predicted_plus_1)')
TRACE_NAME = re.compile(r'[a-z_]{1,48}')
TEXT_VALUE = re.compile(r'[0-9:]{0,24}')
CONTEXTS = ('global', 'selected_background', 'OTHER')
TRACE_INT = 2 ** 53


def trace_allowlist(provenance):
    """Per-control string values a trace may carry verbatim: verified defaults, harness targets
    and the two context tokens. Text controls also pass `[0-9:]{0,24}`; everything else is classed."""
    allow = {}
    def add(name, value):
        if isinstance(value, str) and SAFE_TEXT.fullmatch(value):
            allow.setdefault(name, set()).add(value)
    for name, value in provenance_value(provenance, 'defaults.prefs').items():
        add(name, value)
    for _, name, value in provenance['rich_prefs']:
        add(name, value)
    add(*provenance['rich_override'])
    for value in provenance_value(provenance, 'ui.options_page_theme'):
        add('options_page_theme', value)
    for value in CONTEXTS[:2]:
        add('settings_context', value)
    for task in provenance['rich_tasks']:
        for name in ('year', 'time', 'day_of_the_month'):
            add(name, task.get(name))
    for name in ('year', 'time', 'day_of_the_month', 'day_of_the_week', 'month'):
        add(name, '')
    return {k: frozenset(v) for k, v in allow.items()}


def trace_value(value, allowed=()):
    if value is None or type(value) is bool:
        return value
    if type(value) is int and -TRACE_INT < value < TRACE_INT:
        return value
    if isinstance(value, str) and (value in allowed or TEXT_VALUE.fullmatch(value)):
        return value
    kind = type(value).__name__ if type(value) in (str, int, float, list, dict) else 'other'
    return {'value': None, 'type': kind, 'allowlisted': False}


def _flag(value):
    return value if type(value) is bool else None


def _count(value):
    return value if type(value) is int and 0 <= value < TRACE_INT else None


def trace_observation(raw, allow):
    """Classify one page observation. Unknown keys are dropped; values outside the allowlist
    are replaced by their type. Never raises on malformed input."""
    if not isinstance(raw, dict):
        return {'observation': 'UNAVAILABLE'}
    context = raw.get('context')
    add = raw.get('add_task') if isinstance(raw.get('add_task'), dict) else {}
    out = {'context': context if context in CONTEXTS else None,
           'counts': {k: _count(raw.get(k)) for k in ('backgrounds', 'tasks')},
           'panels': {k: _flag(raw.get(k)) for k in ('scheduler', 'code_editor', 'background_id',
                                                     'background_changed', 'target_identity',
                                                     'background_matches_target')},
           'add_task': {k: _flag(add.get(k)) for k in ('present', 'shown', 'enabled')},
           'controls': {}}
    controls = raw.get('controls') if isinstance(raw.get('controls'), dict) else {}
    for name, value in list(controls.items())[:8]:
        if not (isinstance(name, str) and TRACE_NAME.fullmatch(name)):
            continue
        if not isinstance(value, dict) or value.get('present') is not True:
            out['controls'][name] = {'present': False}
            continue
        allowed = allow.get(name, ())
        out['controls'][name] = {
            'present': True, 'state': trace_value(value.get('pref'), allowed),
            'ui': trace_value(value.get('ui'), allowed), 'dom': trace_value(value.get('dom'), allowed),
            'dom_length': _count(value.get('length')),
            'wrapper': {k: _flag(value.get(k)) for k in ('shown', 'enabled', 'warn')}}
    editors = raw.get('editors')
    if isinstance(editors, dict):
        items = editors.get('items') if isinstance(editors.get('items'), list) else []
        out['editors'] = {'open': _flag(editors.get('open')), 'count': _count(editors.get('count')),
                          'items': [{'ready': _flag(i.get('ready')), 'matches': _flag(i.get('matches')),
                                     'length': i.get('length') if type(i.get('length')) is int
                                     and -1 <= i.get('length') < TRACE_INT else None}
                                    for i in items[:3] if isinstance(i, dict)]}
    return out


def validate_trace(trace):
    """Shape check used by tests and the host projection: bounded, fixed ids, projectable."""
    require(isinstance(trace, list) and len(trace) <= TRACE_LIMIT, 'Privacy projection refused')
    for n, entry in enumerate(trace, 1):
        require(isinstance(entry, dict) and entry.get('n') == n
                and isinstance(entry.get('action'), str) and TRACE_ACTION.fullmatch(entry['action'])
                and entry.get('route') in TRACE_ROUTES and entry.get('status') in TRACE_STATUSES,
                'Privacy projection refused')
    project(trace)
    return trace


# --- Privacy projection ---------------------------------------------------------------------

SAFE_KEY = re.compile(r'[a-z][a-z0-9_]{0,63}')
SAFE_TEXT = re.compile(r'[A-Za-z0-9_.:+-]{0,128}')
FORBIDDEN_KEY = re.compile(r'(^|_)(pid|pids|path|paths|message|stack|log|url|raw)($|_)')
PROJECTION_LIMIT = 2 * 1024 * 1024


def project(value, depth=0):
    """Fixed-shape, bounded copy for review payloads; refuses rather than truncates."""
    require(depth < 24, 'Privacy projection refused')
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        require(value == value and abs(value) < 1e15, 'Privacy projection refused')
        return value
    if isinstance(value, str):
        require(SAFE_TEXT.fullmatch(value) is not None and not value.startswith('data:'),
                'Privacy projection refused')
        return value
    if isinstance(value, (list, tuple)):
        require(len(value) <= 4096, 'Privacy projection refused')
        return [project(v, depth + 1) for v in value]
    if isinstance(value, dict):
        require(len(value) <= 512, 'Privacy projection refused')
        out = {}
        for key, item in value.items():
            require(isinstance(key, str) and SAFE_KEY.fullmatch(key) is not None
                    and FORBIDDEN_KEY.search(key) is None, 'Privacy projection refused')
            out[key] = project(item, depth + 1)
        if depth == 0:
            require(len(json.dumps(out)) <= PROJECTION_LIMIT, 'Privacy projection refused')
        return out
    raise VerificationError('Privacy projection refused')


def projected_fingerprint(fp):
    """Review-safe fingerprint: string values that are not bounded tokens become digests."""
    def clean(value):
        if isinstance(value, dict):
            return {k if SAFE_KEY.fullmatch(k) and not FORBIDDEN_KEY.search(k) else 'k_' + digest(k)[:16]:
                    clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str) and not SAFE_TEXT.fullmatch(value):
            return 'sha256:' + digest(value)[:32]
        return value
    return project(clean(fp))
