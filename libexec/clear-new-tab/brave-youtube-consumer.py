"""Clear New Tab Brave YouTube derived consumer (BUX5B1 CONSUMER-ADAPT1). CLI helper; not a command.

The only authority is Browser UX durable state: one stored canonical manifest that the
operator selects by digest, verified (stored bytes, every native part, every content
reference) through the accepted guarded_recovery/durable_state path loaded from this file's
directory. No browser profile is read, and no live Chromium storage is a fallback source.

Brave YouTube is a derived consumer. Chromium/Brave CNT import is uncharacterized, Firefox
native parts are not Chromium storage, and only the Firefox 6.12.1 projection has neutral
semantics, so every brave-youtube run refuses before the target is opened. The target and
roots are only path arithmetic here; nothing is created, copied, moved or removed.

Every refusal is ConsumerError(code) or a library refusal whose text is the fixed code
alone. Checks are explicit raises and behave identically under python -O.
"""
from __future__ import annotations

from decimal import Decimal
import importlib.util
import os
from pathlib import Path, PurePosixPath
import stat
import sys


def _load_recovery():
    # A private module object (never registered in sys.modules), always the shipped sibling.
    spec = importlib.util.spec_from_file_location('browser_ux_cnt_guarded_recovery',
                                                  Path(__file__).with_name('guarded_recovery.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gr = _load_recovery()
ds = gr.ds

CONSUMER_CODES = (
    'USAGE', 'MANIFEST_SELECTION_REQUIRED', 'STATE_ROOT_RELOCATION_UNBOUND', 'STATE_ROOT_INVALID',
    'ROOTS_OVERLAP', 'CHROMIUM_NATIVE_UNCHARACTERIZED', 'NATIVE_ONLY_NO_NEUTRAL_PROJECTION',
    'BRAVE_CNT_IMPORT_UNQUALIFIED',
)
REFUSAL_CODES = gr.REFUSAL_CODES + CONSUMER_CODES
PLAN_SCHEMA = 'browser-ux-cnt-brave-derived-plan-v1'
BACKUP_COVERAGE = 'BACKUP_COVERAGE_NOT_CONFIRMED'
AUTHORITY = 'browser-ux-durable-state'
BRAVE_TARGET_SUFFIX = ('Library', 'Application Support', 'Brave YouTube')
# The retired legacy authority, named only so that no root may overlap it. Never opened.
RETIRED_LEGACY_ZONE = ('Library', 'Application Support', 'Google', 'Chrome')
# Browser profile/runtime roots the state and Shared Images roots must stay outside (lexical only).
BROWSER_PROFILE_ZONES = (
    BRAVE_TARGET_SUFFIX,
    ('Library', 'Application Support', 'BraveSoftware'),
    ('Library', 'Application Support', 'Chromium'),
    ('Library', 'Application Support', 'Firefox'),
    ('Library', 'Application Support', 'Mozilla'),
    ('Library', 'Caches', 'Firefox'),
)
XDG_DEFAULT_SUFFIX = ('.local', 'state')
# Fields the derived plan never carries: native-only or uncharacterized for Chromium/Brave.
EXCLUDED = ('settings', 'custom_code', 'presentation', 'thumbnail', 'tasks', 'native_id',
            'file_name', 'file_type', 'file_last_modified', 'native_part_bytes')
BUX5C_REQUIREMENTS = (
    'CHROMIUM_CNT_NATIVE_EXPORT_IMPORT_CHARACTERIZATION',
    'BRAVE_ENGINE_LABEL_IDENTITY',
    'QUALIFIED_NEUTRAL_TO_BRAVE_IMPORT_ADAPTER',
    'BRAVE_TARGET_IDENTITY_PRESERVATION_AND_JOURNAL',
    'BRAVE_EXTENSION_BUNDLE_PROVENANCE',
    'CANONICAL_HEAD_MANIFEST_SELECTOR',
    'ORDER_SEMANTICS_FOR_NON_ASCENDING_RANKS',
    'SETTINGS_PRESENTATION_TASKS_PORTABILITY',
    'NATIVE_ONLY_CONTENT_MATERIALIZATION',
    'LEGACY_CHROME_DERIVED_TARGET_RESIDUE',
    'CANONICAL_ROOT_CREATION_AND_BACKUP_COVERAGE',
    'SESSION_IMPLICIT_CALL_NON_MUTATING_UNTIL_BUX6',
)
REFUSED, PROJECTED_ORDER, ORDER_NOT_PROJECTED = 'REFUSED', 'RANK_STRICTLY_ASCENDING', 'NOT_PROJECTED'
DIGEST_BOUND, NATIVE_PART_ONLY, NOT_DERIVABLE = 'DIGEST_BOUND', 'NATIVE_PART_ONLY', 'NOT_DERIVABLE'
COMMANDS = ('status', 'plan', 'brave-youtube')
OPTIONS = ('--manifest', '--state-root', '--shared-images-root')
EXIT_OK, EXIT_USAGE, EXIT_REFUSED = 0, 2, 3


class ConsumerError(ValueError):
    """Bounded refusal. str(error) is exactly one REFUSAL_CODES member."""

    def __init__(self, code):
        if code not in REFUSAL_CODES:
            code = 'RECOVERY_INVALID'
        super().__init__(code)
        self.code = code


def _require(condition, code):
    if not condition:
        raise ConsumerError(code)


# --- Pure root resolution and confinement ------------------------------------------------------

def _absolute(text, code):
    """PurePosixPath of an absolute, already-normalized path text; never touches the filesystem."""
    _require(type(text) is str and text.startswith('/') and text != '/' and '\0' not in text
             and '\\' not in text, code)
    _require(ds._utf8(text) is not None, code)
    _require(all(part not in ('', '.', '..') for part in text.split('/')[1:]), code)
    return PurePosixPath(text)


def _home(environ):
    return _absolute(environ.get('HOME'), 'HOME_INVALID')


def resolve_state_root(explicit, environ):
    """(root, source). An explicit root wins; else the frozen XDG default, never created.

    A relocated XDG_STATE_HOME is refused: the default root's backup verdict must not be
    reused for another path.
    """
    if explicit is not None:
        return _absolute(explicit, 'STATE_ROOT_INVALID'), 'explicit'
    home = _home(environ)
    xdg = environ.get('XDG_STATE_HOME')
    if xdg not in (None, ''):
        _require(type(xdg) is str and xdg.rstrip('/') == str(home.joinpath(*XDG_DEFAULT_SUFFIX)),
                 'STATE_ROOT_RELOCATION_UNBOUND')
    try:
        return PurePosixPath(str(ds.canonical_root(str(home)))), 'default'
    except ds.DurableStateError as error:
        raise ConsumerError(error.code) from None


def resolve_target(environ):
    """Brave YouTube user-data directory: path arithmetic only; it is never opened here."""
    configured = environ.get('BRAVE_YOUTUBE_USER_DATA_DIR')
    if configured not in (None, ''):
        return _absolute(configured, 'TARGET_INVALID')
    return _home(environ).joinpath(*BRAVE_TARGET_SUFFIX)


def _overlaps(first, second):
    a, b = first.parts, second.parts
    return a[:len(b)] == b or b[:len(a)] == a


def check_confinement(state_root, target, shared_images_root, environ):
    """Pure lexical check: state root, Shared Images root and Brave target are pairwise
    disjoint (neither equal nor nested), none overlaps the retired legacy zone, and neither
    source root overlaps a browser profile zone. Ancestor symlinks are not resolved."""
    sources = [state_root] + ([shared_images_root] if shared_images_root is not None else [])
    roots = sources + [target]
    for index, first in enumerate(roots):
        for second in roots[index + 1:]:
            _require(not _overlaps(first, second), 'ROOTS_OVERLAP')
    home = _home(environ)
    legacy = home.joinpath(*RETIRED_LEGACY_ZONE)
    _require(not any(_overlaps(root, legacy) for root in roots), 'ROOTS_OVERLAP')
    zones = [home.joinpath(*zone) for zone in BROWSER_PROFILE_ZONES]
    _require(not any(_overlaps(root, zone) for root in sources for zone in zones), 'ROOTS_OVERLAP')


# --- Verified source and the pure derived plan --------------------------------------------------

def verified_source(state_root, manifest_sha256, shared_images_root):
    """VerifiedManifest whose stored bytes, native parts and content refs all verified.

    Private content is bound to the state root's content/sha256/ (the canonical layout);
    Shared Images refs need an explicit caller root (ROOT_REQUIRED otherwise).
    """
    verified = gr.load_verified(str(state_root), manifest_sha256)
    try:
        ds.verify_manifest_content(
            verified.manifest, private_root=str(state_root),
            shared_images_root=None if shared_images_root is None else str(shared_images_root))
    except ds.DurableStateError as error:
        raise ConsumerError(error.code) from None
    return verified


def _ranks_strictly_ascending(ranks):
    values = [Decimal(rank) for rank in ranks]
    return all(left < right for left, right in zip(values, values[1:]))


def _content_state(occurrence):
    """NOT_DERIVABLE without a decoded digest. A native_only digest is proven only through the
    Firefox native parts, and no neutral bytes exist for it (NATIVE_PART_ONLY). DIGEST_BOUND
    means a shared_images/private ref whose bytes verify_manifest_content proved by digest."""
    if occurrence['content_sha256'] is None:
        return NOT_DERIVABLE
    return NATIVE_PART_ONLY if occurrence['content_ref']['kind'] == 'native_only' else DIGEST_BOUND


def _derived(manifest):
    if manifest['projection_status'] != ds.PROJECTED:
        return None
    occurrences = manifest['occurrences']
    ascending = _ranks_strictly_ascending([o['native_rank'] for o in occurrences])
    return {
        'order': {'basis': 'native_rank', 'status': PROJECTED_ORDER if ascending else ORDER_NOT_PROJECTED},
        'occurrences': [{'position': o['position'], 'native_rank': o['native_rank'],
                         'content_sha256': o['content_sha256'],
                         'content_ref_kind': o['content_ref']['kind'],
                         'content': _content_state(o)}
                        for o in occurrences],
    }


def _refusal(manifest):
    if manifest['labels']['engine'] == 'chrome':
        return 'CHROMIUM_NATIVE_UNCHARACTERIZED'
    if manifest['projection_status'] != ds.PROJECTED:
        return 'NATIVE_ONLY_NO_NEUTRAL_PROJECTION'
    return 'BRAVE_CNT_IMPORT_UNQUALIFIED'


def derived_plan(verified):
    """Pure plan dict for a verified record. Its verdict is always REFUSED in this phase."""
    _require(type(verified) is gr.VerifiedManifest and verified.origin == gr.STATE_ROOT, 'UNVERIFIED_INPUT')
    manifest = verified.manifest
    return {
        'schema': PLAN_SCHEMA,
        'source': {'authority': AUTHORITY, 'manifest_sha256': verified.manifest_sha256,
                   'fingerprint': verified.fingerprint, 'labels': verified.labels,
                   'revision': verified.revision, 'projection_status': verified.projection_status,
                   'native_part_sha256': list(verified.part_digests)},
        'native_parts_brave_portable': False,
        'derived': _derived(manifest),
        'excluded': list(EXCLUDED),
        'verdict': REFUSED,
        'refusal': _refusal(manifest),
        'bux5c_requirements': list(BUX5C_REQUIREMENTS),
        'backup_coverage': BACKUP_COVERAGE,
    }


def plan_bytes(plan):
    return ds.canonical_bytes(plan) + b'\n'


# --- CLI ------------------------------------------------------------------------------------------

def parse_args(argv):
    _require(len(argv) >= 1 and argv[0] in COMMANDS, 'USAGE')
    options, rest = {}, list(argv[1:])
    while rest:
        name = rest.pop(0)
        _require(name in OPTIONS and name not in options and rest, 'USAGE')
        options[name] = rest.pop(0)
    return argv[0], options


def _selection(options):
    selected = options.get('--manifest')
    _require(selected is not None, 'MANIFEST_SELECTION_REQUIRED')
    try:
        return ds.require_digest(selected)
    except ds.DurableStateError as error:
        raise ConsumerError(error.code) from None


def _shared_root(options):
    value = options.get('--shared-images-root')
    return None if value is None else _absolute(value, 'ROOT_INVALID')


def _roots(options, environ):
    state_root, source = resolve_state_root(options.get('--state-root'), environ)
    target, shared = resolve_target(environ), _shared_root(options)
    check_confinement(state_root, target, shared, environ)
    return state_root, source, target, shared


def _verified_plan(options, environ):
    """Selection first (before any root or target is resolved), then roots, then verification."""
    selected = _selection(options)
    state_root, _source, _target, shared = _roots(options, environ)
    return derived_plan(verified_source(state_root, selected, shared))


def _presence(path):
    """lstat only: never follows, opens or creates the path."""
    try:
        info = os.lstat(str(path))
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unreadable'
    if stat.S_ISLNK(info.st_mode):
        return 'symlink-refused'
    return 'directory' if stat.S_ISDIR(info.st_mode) else 'not-a-directory'


def _code(error):
    return getattr(error, 'code', 'RECOVERY_INVALID')


BOUNDED = (ConsumerError, gr.RecoveryError, ds.DurableStateError)


def status_lines(options, environ):
    lines = [('authority', AUTHORITY), ('legacy_chrome_profile_authority', 'retired')]
    try:
        state_root, source = resolve_state_root(options.get('--state-root'), environ)
    except BOUNDED as error:
        lines.append(('state_root', 'REFUSED ' + _code(error)))
    else:
        lines += [('state_root', str(state_root)), ('state_root_source', source),
                  ('state_root_present', _presence(state_root))]
    lines.append(('backup_coverage', BACKUP_COVERAGE))
    try:
        lines.append(('brave_youtube_target', str(resolve_target(environ))))
    except BOUNDED as error:
        lines.append(('brave_youtube_target', 'REFUSED ' + _code(error)))
    selected = options.get('--manifest')
    try:
        plan = _verified_plan(options, environ)
    except BOUNDED as error:
        manifest = 'unselected' if selected is None else 'REFUSED ' + _code(error)
        consumer = _code(error)
    else:
        manifest = ' '.join(('VERIFIED', plan['source']['manifest_sha256'], plan['source']['projection_status']))
        consumer = plan['refusal']
    lines += [('manifest', manifest), ('brave_youtube_consumer', 'REFUSED ' + consumer),
              ('brave_extension_bundle', 'NOT_PROVISIONED')]
    return ''.join('%s: %s\n' % pair for pair in lines)


def main(argv, environ, stdout, stderr):
    """Exit 0 (status/plan output), 2 (usage) or 3 (refusal). No path ever reaches stderr."""
    try:
        command, options = parse_args(argv)
        if command == 'status':
            stdout.write(status_lines(options, environ))
            return EXIT_OK
        plan = _verified_plan(options, environ)
        if command == 'plan':
            stdout.write(plan_bytes(plan).decode('ascii'))
            return EXIT_OK
        # brave-youtube: verified, then refused before the target is ever opened.
        raise ConsumerError(plan['refusal'])
    except BOUNDED as error:
        code = _code(error)
        stderr.write('clear-new-tab-sync: refused: %s\n' % code)
        return EXIT_USAGE if code == 'USAGE' else EXIT_REFUSED


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], os.environ, sys.stdout, sys.stderr))
