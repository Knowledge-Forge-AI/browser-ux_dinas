"""Read-only runtime and host binding for the attended scrollbar GUI kit (BUX5C0-R2-GUI-BIND1,
running-browser detector corrected in R3-PROCESS-ID1).

Test-owned and unpackaged. Nothing here launches a browser, writes a preference or reads a
browser profile.

Chrome has exactly one execution authority: the selected nix-darwin generation app at
CHROME_SELECTION. It must resolve to a link-free Nix store Google Chrome.app accepted by the
maintained `cnt-native-preflight.chrome_bundle` identity reader, keep its original signature and
not change while it is bound. There is no search, list or fallback: the daily
/Applications app and the mutable Nix Apps activation copy are never consulted. This is
attended-test binding only, not a change in product Chrome ownership.

Firefox is the current signed installed /Applications/Firefox.app, read here independently
of CNT's production pin. A normal release at or above the sealed extension's Gecko floor is
eligible for attended qualification; its exact version, build and digests are recorded.

Every refusal is `Unavailable(result, code)` with a fixed code. Messages from the reused
helpers can carry paths and are never exported. Public identities hold versions, bundle IDs and
digests only; app and executable paths go to the caller's private state.
"""
from __future__ import annotations

import functools
import configparser
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import sys
from xml.parsers.expat import ExpatError

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import cnt_host_d2 as d2  # noqa: E402  (bounded reader only)
from cnt_native_evidence import VerificationError, plain_descendant, tree_digest  # noqa: E402

CHROME_SELECTION = Path('/run/current-system/Applications/Google Chrome.app')
FIREFOX_APP = Path('/Applications/Firefox.app')
FIREFOX_EXECUTABLE = 'Contents/MacOS/firefox'
FIREFOX_SELECTION = 'ATTENDED_INSTALLED_FIREFOX_APP'
EXTENSION_MANIFEST = HERE.parent / 'extensions/browser-ux-scrollbars/manifest.json'
RELEASE_VERSION = re.compile(r'([1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(?:\.(0|[1-9][0-9]{0,3}))?')
BUILD_ID = re.compile(r'[0-9]{14}')
CHANNEL_FRAMEWORK = 'Contents/Frameworks/ChannelPrefs.framework/ChannelPrefs'
CODESIGN = ('/usr/bin/codesign', '--verify', '--deep', '--strict')
CODESIGN_TIMEOUT = 120
EXECUTABLE_LIMIT = 1 << 30
CHROME_UNAVAILABLE = 'SELECTED_CHROME_UNAVAILABLE'
FIREFOX_UNAVAILABLE = 'SELECTED_FIREFOX_UNAVAILABLE'
# Codes added here; the rest are the maintained helpers' own fixed codes.
CHROME_CODES = ('SELECTION_ABSENT', 'CHROME_APP_LAYOUT_REFUSED', 'ORIGINAL_SIGNATURE_INVALID',
                'CHROME_RUNTIME_CHANGED')
FIREFOX_CODES = (
    'FIREFOX_APP_ABSENT', 'FIREFOX_RUNTIME_PATH_REFUSED', 'FIREFOX_RUNTIME_UNREADABLE',
    'FIREFOX_PLIST_UNREADABLE', 'FIREFOX_BUNDLE_ID_DIFFERS', 'FIREFOX_APP_LAYOUT_REFUSED',
    'FIREFOX_VERSION_INVALID', 'FIREFOX_FLOOR_UNREADABLE', 'FIREFOX_VERSION_BELOW_FLOOR',
    'FIREFOX_BUNDLE_VERSION_INVALID', 'FIREFOX_INI_UNREADABLE', 'FIREFOX_INI_VERSION_DIFFERS',
    'FIREFOX_BUILD_ID_INVALID', 'FIREFOX_EXECUTABLE_UNREADABLE', 'FIREFOX_CHANNEL_UNREADABLE',
    'FIREFOX_CHANNEL_REFUSED', 'ORIGINAL_SIGNATURE_INVALID', 'FIREFOX_RUNTIME_CHANGED')

SCROLLBAR_ALWAYS = 'Always'
SCROLLBAR_UNSET = 'Automatic (unset)'
SCROLLBAR_VALUE = re.compile(r'[A-Za-z]{1,32}')
HOST_SCROLLBAR_MODE_NOT_ALWAYS = 'HOST_SCROLLBAR_MODE_NOT_ALWAYS'
# The only place the host setting change is spelled out. The kit never runs it: the operator
# may, then quits and reopens the browsers and restarts the kit.
HOST_SCROLLBAR_GUIDANCE = (
    'The attended session needs always-visible macOS scroll bars. Either open System Settings > '
    'Appearance and set "Show scroll bars" to "Always", or run in your own terminal:\n'
    '    defaults write -g AppleShowScrollBars -string Always\n'
    'Then quit and reopen any running browser and start the kit again. The kit never changes '
    'this setting itself.')

PROCESS_NAMES = {'chrome': 'Google Chrome', 'firefox': 'firefox'}
RUNNING, NOT_RUNNING, UNKNOWN = 'RUNNING', 'NOT_RUNNING', 'UNKNOWN'
# R3: a pgrep name match is only a candidate. Long-lived tools such as Playwright MCP and Chrome
# DevTools MCP retitle themselves `npm exec ... --executable-path <Chrome executable>` and so share
# the `Google Chrome` process name without being a browser. Classification only: these suffixes
# never select anything to execute.
MAIN_EXECUTABLES = {'chrome': '/Google Chrome.app/Contents/MacOS/Google Chrome',
                    'firefox': f'/{FIREFOX_APP.name}/{FIREFOX_EXECUTABLE}'}
PS = ('/bin/ps', '-ww', '-p')
PID = re.compile(r'[1-9][0-9]{0,9}')
CANDIDATE_LIMIT = 32
REAL_BROWSER, NAME_COLLISION, UNREADABLE = 'REAL_BROWSER', 'NON_BROWSER_NAME_COLLISION', 'UNREADABLE'
# Text in front of the executable suffix that cannot be part of one absolute executable path:
# a second absolute argument, an option or an `option=value` join.
NOT_ONE_PATH = re.compile(r' /| -|=|\t')
PROCESS_CONTRACT = (
    'pgrep -x "Google Chrome" / pgrep -x firefox only enumerates candidates: exit 1 is NOT_RUNNING, '
    'any exit other than 0 or 1, empty or malformed PID output, or more than 32 candidates is '
    'UNKNOWN. Every candidate is read with /bin/ps -ww -p <pid> -o command=. A candidate is '
    'REAL_BROWSER only when its command line begins with an absolute path whose first occurrence '
    'of the main executable suffix (/Google Chrome.app/Contents/MacOS/Google Chrome or '
    '/Firefox.app/Contents/MacOS/firefox) is followed by a space or the end, and the text before '
    'that suffix holds no " /", " -", "=" or tab. A nonzero ps exit, an empty or multi-line '
    'command, or a parenthesized (comm) placeholder is UNREADABLE. Anything else is '
    'NON_BROWSER_NAME_COLLISION. Any REAL_BROWSER is RUNNING; otherwise any UNREADABLE is UNKNOWN; '
    'otherwise NOT_RUNNING. Only counts leave the census; no PID or command line is exported, and '
    'no process is ever signalled.')


class Unavailable(Exception):
    """A runtime binding refusal: one fixed result and one fixed code, never a path."""

    def __init__(self, result, code):
        super().__init__(f'{result}:{code}')
        self.result, self.code = result, code


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


@functools.lru_cache(maxsize=None)
def preflight():
    """The maintained Chrome identity reader, loaded by spec as `cnt_host_chrome` does."""
    spec = importlib.util.spec_from_file_location('cnt_native_preflight_scrollbar_gui',
                                                  HERE / 'cnt-native-preflight.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bind_chrome(run, selection=CHROME_SELECTION):
    """(public, private) identity of the selected-generation Chrome. `run(argv, timeout)`."""
    reader = preflight()

    def refuse(code):
        raise Unavailable(CHROME_UNAVAILABLE, code)

    selection = Path(selection)
    if not selection.is_absolute() or not os.path.lexists(selection):
        refuse('SELECTION_ABSENT')
    try:
        app = selection.resolve(strict=True)
    except (OSError, RuntimeError):
        refuse('SELECTION_ABSENT')  # dangling or looping selection link
    try:
        executable, version = reader.chrome_bundle(app)
        before = tree_digest(app)
        executable_sha256 = sha256(d2.read_bounded(executable, EXECUTABLE_LIMIT))
    except VerificationError as error:
        refuse(reader.CHROME_PREPARATION_CODES.get(str(error), 'CHROME_APP_LAYOUT_REFUSED'))
    except (OSError, ValueError):
        refuse('CHROME_APP_LAYOUT_REFUSED')
    code, _ = run([*CODESIGN, str(app)], timeout=CODESIGN_TIMEOUT)
    if code != 0:
        refuse('ORIGINAL_SIGNATURE_INVALID')
    try:
        after = tree_digest(app)
    except (OSError, VerificationError):
        after = None
    if after != before:
        refuse('CHROME_RUNTIME_CHANGED')
    store_root = reader.CHROME_STORE / app.relative_to(reader.CHROME_STORE).parts[0]
    public = {'selection': 'RUN_CURRENT_SYSTEM', 'bundle_id': reader.CHROME_BUNDLE_ID,
              'version': version, 'executable_sha256': executable_sha256,
              'runtime_sha256': before, 'store_root_sha256': sha256(str(store_root).encode()),
              'signature_valid': True}
    return public, {'app': str(app), 'executable': str(executable)}


def release_version(value):
    """Bounded ASCII release version; suffixes, leading zeroes and extra parts are refused."""
    match = RELEASE_VERSION.fullmatch(value) if type(value) is str else None
    return tuple(int(part or '0') for part in match.groups()) if match else None


def gecko_floor():
    """The extension manifest is the sole maintained floor, also sealed into the GUI kit."""
    try:
        manifest = json.loads(d2.read_bounded(EXTENSION_MANIFEST, 64 << 10))
        floor = release_version(manifest['browser_specific_settings']['gecko']['strict_min_version'])
        if floor is None:
            raise ValueError('invalid floor')
        return floor
    except (OSError, ValueError, TypeError, KeyError, RecursionError, VerificationError):
        raise Unavailable(FIREFOX_UNAVAILABLE, 'FIREFOX_FLOOR_UNREADABLE') from None


def firefox_executable_sha256(executable):
    """Bounded executable digest; a synthetic-target test seam, never a production override."""
    return sha256(d2.read_bounded(executable, EXECUTABLE_LIMIT))


def firefox_release_channel(app):
    """Read ChannelPrefs without loading code. Accept only release in every Mach-O slice.

    Mozilla documents this framework as the macOS installed update-channel owner. Its tiny
    __TEXT,__cstring section holds the channel. Unknown layouts fail closed; no strings scan,
    alternate metadata source, dynamic-library load or browser execution is used.
    """
    raw = d2.read_bounded(plain_descendant(app, CHANNEL_FRAMEWORK), 1 << 20)

    def need(condition):
        if not condition:
            raise ValueError('channel layout refused')

    slices = [raw]
    if raw[:4] == b'\xca\xfe\xba\xbe':
        need(len(raw) >= 8)
        count = struct.unpack_from('>I', raw, 4)[0]
        need(1 <= count <= 4 and len(raw) >= 8 + count * 20)
        slices, ranges, cpus = [], [], set()
        for i in range(count):
            cpu, _, offset, size, _ = struct.unpack_from('>IIIII', raw, 8 + i * 20)
            need(cpu in (0x1000007, 0x100000c) and cpu not in cpus)
            need(offset >= 8 + count * 20 and size >= 32 and offset + size <= len(raw))
            need(all(offset + size <= start or offset >= end for start, end in ranges))
            data = raw[offset:offset + size]
            need(struct.unpack_from('<I', data, 4)[0] == cpu)
            slices.append(data)
            ranges.append((offset, offset + size))
            cpus.add(cpu)
    for data in slices:
        need(len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe')
        cpu, _, filetype, count, length = struct.unpack_from('<IIIII', data, 4)
        need(cpu in (0x1000007, 0x100000c) and filetype == 6 and 1 <= count <= 64)
        end, cursor, channels = 32 + length, 32, []
        need(end <= len(data))
        for _ in range(count):
            need(cursor + 8 <= end)
            command, size = struct.unpack_from('<II', data, cursor)
            need(size >= 8 and size % 8 == 0 and cursor + size <= end)
            if command == 0x19:  # LC_SEGMENT_64
                need(size >= 72)
                sections = struct.unpack_from('<I', data, cursor + 64)[0]
                need(sections <= 64 and size == 72 + sections * 80)
                for i in range(sections):
                    at = cursor + 72 + i * 80
                    section, segment = struct.unpack_from('<16s16s', data, at)
                    if section.rstrip(b'\0') == b'__cstring' and segment.rstrip(b'\0') == b'__TEXT':
                        need(data[cursor + 8:cursor + 24] == segment)
                        section_size, offset = struct.unpack_from('<QI', data, at + 40)
                        need(offset >= end and section_size <= 64 and offset + section_size <= len(data))
                        channels.append(data[offset:offset + section_size])
            cursor += size
        need(cursor == end and channels == [b'release\0'])


def bind_firefox(run, app=FIREFOX_APP):
    """(public, private) identity of the exact attended app. No alternate app selection."""
    def refuse(code):
        raise Unavailable(FIREFOX_UNAVAILABLE, code)

    app = Path(app)
    if not app.is_absolute() or app != FIREFOX_APP:
        refuse('FIREFOX_RUNTIME_PATH_REFUSED')
    if not os.path.lexists(app):
        refuse('FIREFOX_APP_ABSENT')
    try:
        if app.resolve(strict=True) != app or not stat.S_ISDIR(app.lstat().st_mode):
            refuse('FIREFOX_RUNTIME_PATH_REFUSED')
    except (OSError, RuntimeError):
        refuse('FIREFOX_RUNTIME_PATH_REFUSED')
    try:
        before = tree_digest(app)
    except (OSError, VerificationError):
        refuse('FIREFOX_RUNTIME_UNREADABLE')
    try:
        metadata = plistlib.loads(d2.read_bounded(plain_descendant(app, 'Contents/Info.plist'), 4 << 20))
        if type(metadata) is not dict:
            raise ValueError('not a dictionary')
    except (OSError, ValueError, VerificationError, plistlib.InvalidFileException, ExpatError, RecursionError):
        refuse('FIREFOX_PLIST_UNREADABLE')
    bundle_id, name = metadata.get('CFBundleIdentifier'), metadata.get('CFBundleExecutable')
    if type(bundle_id) is not str or bundle_id != 'org.mozilla.firefox':
        refuse('FIREFOX_BUNDLE_ID_DIFFERS')
    if type(name) is not str or name != 'firefox':
        refuse('FIREFOX_APP_LAYOUT_REFUSED')
    version, bundle_version = metadata.get('CFBundleShortVersionString'), metadata.get('CFBundleVersion')
    numeric = release_version(version)
    if numeric is None:
        refuse('FIREFOX_VERSION_INVALID')
    if numeric < gecko_floor():
        refuse('FIREFOX_VERSION_BELOW_FLOOR')
    if (type(bundle_version) is not str or not 1 <= len(bundle_version) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in bundle_version)):
        refuse('FIREFOX_BUNDLE_VERSION_INVALID')
    try:
        ini = configparser.ConfigParser(interpolation=None, strict=True)
        ini.read_string(d2.read_bounded(plain_descendant(app, 'Contents/Resources/application.ini'),
                                      1 << 20).decode('utf-8'))
        # Require explicit App values, rather than inherited DEFAULT entries.
        values = ini._sections['App']
        ini_version, build_id = values['version'], values['buildid']
    except (OSError, ValueError, VerificationError, configparser.Error, KeyError):
        refuse('FIREFOX_INI_UNREADABLE')
    if ini_version != version:
        refuse('FIREFOX_INI_VERSION_DIFFERS')
    try:
        if not BUILD_ID.fullmatch(build_id):
            raise ValueError('invalid build id')
        datetime.strptime(build_id, '%Y%m%d%H%M%S')
    except ValueError:
        refuse('FIREFOX_BUILD_ID_INVALID')
    try:
        executable = plain_descendant(app, FIREFOX_EXECUTABLE)
    except (OSError, VerificationError):
        refuse('FIREFOX_APP_LAYOUT_REFUSED')
    try:
        executable_sha256 = firefox_executable_sha256(executable)
    except (OSError, ValueError, VerificationError):
        refuse('FIREFOX_EXECUTABLE_UNREADABLE')
    try:
        firefox_release_channel(app)
    except (OSError, VerificationError):
        refuse('FIREFOX_CHANNEL_UNREADABLE')
    except (ValueError, struct.error):
        refuse('FIREFOX_CHANNEL_REFUSED')
    code, _ = run([*CODESIGN, str(app)], timeout=CODESIGN_TIMEOUT)
    if code != 0:
        refuse('ORIGINAL_SIGNATURE_INVALID')
    try:
        after = tree_digest(app)
    except (OSError, VerificationError):
        after = None
    if after != before:
        refuse('FIREFOX_RUNTIME_CHANGED')
    public = {'selection': FIREFOX_SELECTION, 'version': version, 'bundle_identifier': bundle_id,
              'bundle_version': bundle_version, 'build_id': build_id, 'runtime_sha256': before,
              'executable_sha256': executable_sha256, 'signature_valid': True}
    return public, {'app': str(app), 'executable': str(executable)}


def host_scrollbar_mode(run):
    """`defaults read -g AppleShowScrollBars`, read-only. Unset reads as Automatic."""
    code, out = run(['/usr/bin/defaults', 'read', '-g', 'AppleShowScrollBars'], timeout=30)
    value = out.strip() if code == 0 else ''
    if not value:
        return SCROLLBAR_UNSET
    return value if SCROLLBAR_VALUE.fullmatch(value) else 'UNRECOGNIZED'


def classify_command(browser, command):
    """REAL_BROWSER, NON_BROWSER_NAME_COLLISION or UNREADABLE for one candidate's `ps` command
    line. Anchored at the start: naming the executable later, as an argument, never counts."""
    text = command.strip()
    if not text or '\n' in text or (text.startswith('(') and text.endswith(')')):
        return UNREADABLE  # BSD ps prints `(comm)` when the arguments cannot be read
    suffix = MAIN_EXECUTABLES[browser]
    at = text.find(suffix)
    end = at + len(suffix)
    if (text.startswith('/') and at >= 0 and text[end:end + 1] in ('', ' ')
            and NOT_ONE_PATH.search(text[:at + 1]) is None):
        return REAL_BROWSER
    return NAME_COLLISION


def _candidates(run, name):
    """Sorted distinct candidate PIDs, or None when pgrep cannot prove the list."""
    code, out = run(['/usr/bin/pgrep', '-x', name], timeout=30)
    if code == 1:
        return []
    lines = out.splitlines() if code == 0 else []
    if not lines or not all(PID.fullmatch(line) for line in lines):
        return None
    pids = sorted(set(lines), key=int)
    return pids if len(pids) <= CANDIDATE_LIMIT else None


def browser_census(run):
    """Per browser: state plus candidate counts. Counts only; never a PID or a command line."""
    census = {}
    for browser, name in PROCESS_NAMES.items():
        pids = _candidates(run, name)
        counts = {REAL_BROWSER: 0, NAME_COLLISION: 0, UNREADABLE: 0}
        for pid in pids or ():
            code, out = run([*PS, pid, '-o', 'command='], timeout=30)
            counts[classify_command(browser, out) if code == 0 else UNREADABLE] += 1
        if pids is None:
            state = UNKNOWN
        elif counts[REAL_BROWSER]:
            state = RUNNING
        elif counts[UNREADABLE]:
            state = UNKNOWN
        else:
            state = NOT_RUNNING
        census[browser] = {'state': state, 'candidates': len(pids or ()),
                           'real_browser': counts[REAL_BROWSER],
                           'name_collision': counts[NAME_COLLISION],
                           'unreadable': counts[UNREADABLE]}
    return census


def browser_processes(run):
    """RUNNING, NOT_RUNNING or UNKNOWN per browser (fail closed); see PROCESS_CONTRACT."""
    return {browser: entry['state'] for browser, entry in browser_census(run).items()}
