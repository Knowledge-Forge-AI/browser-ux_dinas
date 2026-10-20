"""Accepted production Firefox runtime identity: the sole owner. Read-only; never launches.

Firefox 156.0.1, manager-accepted for source adoption from the R6 15601 trusted-synthetic
NORMAL+ABNORMAL requalification pair (`bux-r6-firefox-15601-requal.claim`, consumed). It replaces
the R4 HOST-PAIR3 Firefox 155.0.1 binding, which remains only as the historical CONT6 D1 baseline
in `cnt_host_d2.D1_*`. Production consumers alias these names and never repeat the values.

There is exactly one identity: no version family, prefix, pattern, alias list, second accepted
identity or fallback. The superseded identity is deliberately not stored here.

`bind_runtime` requires the link-free installed Firefox.app, the exact Info.plist identifier,
version and build version, the exact application.ini version and build ID, and the app-tree and
executable digests. The original signature stays the caller's check (the matrix `signature`), as
before. Refusal messages are fixed and carry no path. The plist and application.ini readers repeat
the requalification lane's readers on purpose, so that lane stays byte-stable as history.
"""
from __future__ import annotations

import configparser
import hashlib
from pathlib import Path
import plistlib
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402  (bounded reader only; never its D1 identity or binder)
from cnt_native_evidence import VerificationError, plain_descendant, require, tree_digest  # noqa: E402

VERSION = '156.0.1'
BUNDLE_ID = 'org.mozilla.firefox'
BUNDLE_VERSION = '15626.9.21'
BUILD_ID = '20260921121718'
RUNTIME = '35172d4e392575860ed48cd7e7a45a6eb1a59eacdfef277aced6c5610bbcdab3'
EXECUTABLE = 'f2559282d3ef1ceeb0083700e57092c905f043eddb02a9b8ac09009ec9719ac3'
IDENTITY = {'version': VERSION, 'bundle_identifier': BUNDLE_ID, 'bundle_version': BUNDLE_VERSION,
            'build_id': BUILD_ID, 'runtime_sha256': RUNTIME, 'executable_sha256': EXECUTABLE}
PLIST_LIMIT = 4 * 1024 * 1024
INI_LIMIT = 1024 * 1024
# Fixed refusal codes; a runner records a code, never message text or a path.
CODES = {
    'Firefox runtime must be the link-free installed Firefox.app': 'FIREFOX_RUNTIME_PATH_REFUSED',
    'Firefox bundle metadata unreadable': 'FIREFOX_PLIST_UNREADABLE',
    'Firefox bundle identity differs': 'FIREFOX_BUNDLE_ID_DIFFERS',
    'Firefox bundle version differs': 'FIREFOX_VERSION_DIFFERS',
    'Firefox bundle build version differs': 'FIREFOX_BUNDLE_VERSION_DIFFERS',
    'Firefox application.ini unreadable': 'FIREFOX_INI_UNREADABLE',
    'Firefox application.ini version differs': 'FIREFOX_INI_VERSION_DIFFERS',
    'Firefox application.ini build differs': 'FIREFOX_BUILD_ID_DIFFERS',
    'Firefox runtime differs from the production runtime': 'FIREFOX_RUNTIME_DIFFERS',
    'Firefox executable differs from the production executable': 'FIREFOX_EXECUTABLE_DIFFERS'}


def exact(value, expected):
    return type(value) is str and value == expected


def bundle_info(runtime):
    try:
        info = plistlib.loads(d2.read_bounded(plain_descendant(runtime, 'Contents/Info.plist'), PLIST_LIMIT))
    except Exception:
        info = None
    require(isinstance(info, dict), 'Firefox bundle metadata unreadable')
    return info


def application_ini(runtime):
    try:
        raw = d2.read_bounded(plain_descendant(runtime, 'Contents/Resources/application.ini'), INI_LIMIT)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(raw.decode('utf-8'))
        app = {'version': parser.get('App', 'Version', fallback=None),
               'build_id': parser.get('App', 'BuildID', fallback=None)}
    except Exception:
        app = None
    require(isinstance(app, dict), 'Firefox application.ini unreadable')
    return app


def runtime_digest(runtime):
    try:
        return tree_digest(runtime)
    except (OSError, VerificationError):
        return None


def executable_digest(runtime):
    try:
        raw = d2.read_bounded(plain_descendant(runtime, 'Contents/MacOS/firefox'), 1 << 30)
    except (OSError, VerificationError):
        return None
    return hashlib.sha256(raw).hexdigest()


def bind_runtime(runtime):
    """Read-only identity of the installed production Firefox. Exact values only."""
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.name == 'Firefox.app' and runtime.resolve() == runtime,
            'Firefox runtime must be the link-free installed Firefox.app')
    info = bundle_info(runtime)
    require(exact(info.get('CFBundleIdentifier'), BUNDLE_ID), 'Firefox bundle identity differs')
    require(exact(info.get('CFBundleShortVersionString'), VERSION), 'Firefox bundle version differs')
    require(exact(info.get('CFBundleVersion'), BUNDLE_VERSION), 'Firefox bundle build version differs')
    app = application_ini(runtime)
    require(exact(app['version'], VERSION), 'Firefox application.ini version differs')
    require(exact(app['build_id'], BUILD_ID), 'Firefox application.ini build differs')
    require(runtime_digest(runtime) == RUNTIME, 'Firefox runtime differs from the production runtime')
    require(executable_digest(runtime) == EXECUTABLE, 'Firefox executable differs from the production executable')
    return dict(IDENTITY)
