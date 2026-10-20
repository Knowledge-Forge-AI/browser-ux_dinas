"""Attended scrollbar GUI kit for BUX5C0-PREFERENCES1 (R10 freshness / R8 product, disposable only).

R10 post-load and post-reenable evidence machinery, bound to the selected R8 browser runtimes
(`scrollbar_gui_runtime`). Test-owned and unpackaged; never run during semantic dispatch.
The guided observer (`scrollbar_gui_observer.py`) owns current-session fixture freshness and
ordered rail comparisons. The diagnostic primitives stay usable directly:

  prepare --scratch DIR [--work DIR]
                            verify R8 identities, bind Chrome and Firefox read-only, create
                            fresh disposable profile roots, copy the extension and fixtures
  serve   --scratch DIR [--work DIR]
                            serve the fixtures on 127.0.0.1 only (foreground)
  launch  --scratch DIR [--work DIR] chrome|firefox --port PORT
                            re-bind and start one isolated browser (once per session), wait
                            for the observer to quit it, journal the exit, recheck sentinels
                            and re-bind the runtime
  record  --scratch DIR BROWSER GATE pass|fail|not-run [--note TEXT]
                            only pre-fixture load gates until the guided observer proves freshness
  stop    --scratch DIR --reason TEXT
  bundle  --scratch DIR     deterministic privacy-safe evidence zip plus sha256 sidecar

DIR (`--scratch`) holds the evidence: SESSION.json, the hash-chained journal and the bundle.
The work root (default: the same directory) holds the disposable profiles, the extension and
fixture copies and `private/` (paths and browser logs; never bundled).

A recorded result is final: a gate is recorded once and may only be corrected to fail, and any
required fail decides the verdict even when the session also stopped.
Bare fixture URLs never satisfy freshness. Qualification URLs are presented only after the
extension-loaded observation, and the guided observer must record current-token GET evidence
before any visual gate. Static content scripts are never assumed to inject retroactively.

The kit never writes outside its directories, never touches the default browser profiles or
managed preferences, never signs anything, never signals a browser and loads the extension only
as a temporary (unpacked / about:debugging) add-on. It reads live state only as digests or key
names.
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import scrollbar_gui_runtime as runtime  # noqa: E402

EXTENSION_DIR = 'extensions/browser-ux-scrollbars'
FIXTURE = 'tests/fixtures/browser-preferences/scrollbar-matrix.html'
TOPLAYER_FIXTURE = 'tests/fixtures/browser-preferences/scrollbar-toplayer-matrix.html'
SHADOW_SENTINEL_FIXTURE = 'tests/fixtures/browser-preferences/scrollbar-shadow-sentinel-matrix.html'
VERSION = '0.4.0'
GECKO_ID = 'scrollbar-visibility@browser-ux'

FIXTURE_NAMES = (
    'scrollbar-matrix.html',
    'scrollbar-toplayer-matrix.html',
    'scrollbar-shadow-sentinel-matrix.html',
)
PRE_FIXTURE_GATES = ('extension-loaded', 'manifest-known-warnings-only')

RAIL_STEPS = {
    'disabled-reload': {'state': 'EXTENSION_DISABLED', 'fresh': 'DISABLED_COMPARISON_FRESH',
                        'fixtures': FIXTURE_NAMES[:2]},
    'reenabled-reload': {'state': 'EXTENSION_REENABLED', 'fresh': 'ALL_FIXTURES_FRESH_POSTREENABLE',
                         'fixtures': FIXTURE_NAMES},
}
VALID_RAIL_STEPS = tuple(RAIL_STEPS)
PHASES = ('LAUNCHED', 'EXTENSION_LOADED', 'fixtures-presented', 'FIXTURES_OPENED_POSTLOAD',
          'VISUAL_GATES', 'EXTENSION_DISABLED', 'DISABLED_COMPARISON_FRESH',
          'EXTENSION_REENABLED', 'ALL_FIXTURES_FRESH_POSTREENABLE', 'SENTINEL_VISUAL_GATES')
SENTINEL_FIXTURE_GATES = (
    'handshake', 'closed-shadow-top-layer', 'closed-shadow-modal', 'closed-shadow-popover',
    'late-shadow', 'early-closed-root', 'coverage-throttle-recovery', 'detached-root-reattach',
    'dsd-fail-closed', 'budget-fail-closed', 'foreign-realm-attempt',
)
SCENES = {
    'scrollbar-matrix.html': (),
    'scrollbar-toplayer-matrix.html': (
        'control', 'overlays', 'visual-overlay', 'root-after', 'root-mask', 'root-clip',
        'root-filter', 'root-opacity', 'root-transform', 'multi-routing', 'overlap', 'siblings',
        'toplayer-dialog', 'pre-modal', 'toplayer-popover', 'pre-popover', 'pre-auto',
        'toplayer-toast', 'fullscreen', 'shadow-modal', 'author-attacks', 'inert-clipped',
        'geometry', 'dynamics', 'hydration', 'gate', 'limits', 'focus', 'root-zoom', 'late-shadow'),
    'scrollbar-shadow-sentinel-matrix.html': (
        'control', 'early-closed', 'closed-modal', 'closed-popover', 'late-shadow', 'nested-shadow',
        'dsd', 'dsd-parser', 'budget', 'recovery', 'root-after', 'root-mask', 'root-clip',
        'multi-routing', 'overlap', 'siblings', 'gate', 'changing-content', 'throttle-recovery',
        'detached-root'),
}
FRESHNESS_RETRIES = 3
FRESHNESS_CONTRACT = {
    'initial': ['EXTENSION_LOADED', 'FIXTURES_OPENED_POSTLOAD', 'VISUAL_GATES'],
    'disabled': ['EXTENSION_DISABLED', 'DISABLED_COMPARISON_FRESH'],
    'reenabled': ['EXTENSION_REENABLED', 'ALL_FIXTURES_FRESH_POSTREENABLE', 'SENTINEL_VISUAL_GATES'],
    'initial_fixtures': list(FIXTURE_NAMES),
    'disabled_fixtures': list(RAIL_STEPS['disabled-reload']['fixtures']),
    'reenabled_fixtures': list(FIXTURE_NAMES),
    'counting_rule': 'Distinct current-token GET sequences strictly after the acknowledged toggle barrier; '
                     'HEAD, other tokens and earlier requests never count; barriers never regress.',
    'sentinel_gates': list(SENTINEL_FIXTURE_GATES),
    'scene_navigation': 'Generated URLs and current-token Scene menus preserve exactly one qual token.',
    'retry_rule': 'First attempt + 3 retries = four confirmations, same token/barrier, missing only; '
                  'q or exhaustion stops once with INCOMPLETE. Retry entries contain only browser, '
                  'proof, retry number and missing basenames.',
}
SENTINEL_CONTRACT = {
    'sentinels': [
        'chrome-local-state',
        'firefox-profiles-ini',
        'firefox-installs-ini',
    ],
    'count': 3,
    'execution_baseline': 'Execution baseline established before directory creation; quiescent sampling requires at least 3 samples with <=3s total bound.',
    'prelaunch': 'Prelaunch verification compares live sentinels to SESSION_BASELINE_UNCHANGED; live changes immediately refuse launch with no rebase.',
    'after_exit': 'Strict post-exit verification compares live sentinel digests to session baseline; any change stops the session.',
}
FIREFOX_SENTINELS = ('firefox-profiles-ini', 'firefox-installs-ini')
FIREFOX_ONLY_SENTINEL_CONTRACT = {
    'sentinels': list(FIREFOX_SENTINELS),
    'count': 2,
    'execution_baseline': 'Execution baseline established before directory creation; quiescent sampling requires at least 3 samples with <=3s total bound.',
    'prelaunch': 'Prelaunch verification compares live sentinels to SESSION_BASELINE_UNCHANGED; live changes immediately refuse launch with no rebase.',
    'after_exit': 'Strict post-exit verification compares live sentinel digests to session baseline; any change stops the session.',
}

# Product digests for R8-DETACHED-ROOT1 (preserved in R10).
PACKAGE_SHA256 = 'fc5cd1e97c0e8fa708896815cd84e1061ca6e483508d0918d08d7f8c702cd0e4'
MEMBER_SHA256 = {
    'background.js': 'e9af249a96f825e6219d4d1dbb3a0a5399cc45ecb29dd78137e361484f02d68a',
    'content.js': '19fe94a2078aa281050aa3c93f850126684759b2957716e83a3ee87f5afb57d2',
    'manifest.json': '9f50bd3d2f04fd15e9617d49a52f9089dfc19953a66098c6dcdcac52f4ed84eb',
    'rail-core.js': '7477ea6c4abbb9bd4ff223dba7fb21c5a903bb85547149703e98dad8ec023a32',
    'rail-host.css': 'c67f8696b588aa4622acc70edf9b09506747ba5db542cd43437a98c8a43b1ebe',
    'scrollbars.css': '95dcb31fa6b2711cde503d2de6b82214add49aef78fc53e9adcd7a61a76b73db',
    'toplayer-sentinel-main.js': '5a6cdb16d08e127eaa206aeb7d4a61892451bf9c2883c53a6b027e855ede5e08',
}
FIXTURE_SHA256 = 'be06f524c6e8a91427d759290fcbdfd7298d465a92df4df5a44d2fc1d37d766c'
TOPLAYER_FIXTURE_SHA256 = 'b0691058dc2a0d16a4bcbe8c25dd255f07f071f63b59c5ae6f8b786063a2fc49'
SHADOW_SENTINEL_FIXTURE_SHA256 = 'fcd6c5ef9d71df83d88d9b5b5ed14511f5a5c34cd323ccd1bb5b582087ee29f4'

CHROME_AUTHORITY_MEMBER = 'tests/bux5c0-r14-chrome-carry-forward-authority.json'
CHROME_AUTHORITY_SHA256 = '77dd61a4fc99e131518af2a4c799334e103a5dcf07193204a9953a97a87f13d3'
CHROME_AUTHORITY_SCRATCH_NAME = 'CHROME-AUTHORITY.json'

BROWSERS = ('chrome', 'firefox')
RESULTS = ('pass', 'fail', 'not-run', 'not-reproduced')
ROOT_GUTTER_CHOICES = ('RAIL_VISIBLE_USABLE', 'NATIVE_UNOCCLUDED', 'ROOT_GUTTER_UNPAINTABLE', 'FAIL', 'NOT_RUN')
EARLY_CLOSED_ROOT_CHOICES = ('CAPTURED', 'NOT_CAPTURED_FAIL_CLOSED', 'FAIL', 'NOT_RUN')
# No '/', '~' or '\\': observer notes must not be able to carry filesystem paths into the bundle.
NOTE = re.compile(r'[A-Za-z0-9 .,:;_()+=#-]{0,200}')
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
KEEPASSXC_IDS = ('oboonakemofpalcgghocfoadofidjkkk', 'keepassxc-browser@keepassxc.org')
SESSION_SCHEMA = 'bux5c0-r10-reenable-freshness1-scrollbar-gui-session-v1'
FIREFOX_ONLY_SESSION_SCHEMA = 'bux5c0-r14-firefox-only1-scrollbar-gui-session-v1'
EVIDENCE = 'BUX5C0-R10-REENABLE-FRESHNESS1-SCROLLBAR-GUI-EVIDENCE.zip'
FIREFOX_ONLY_EVIDENCE = 'BUX5C0-R14-FIREFOX-ONLY1-SCROLLBAR-GUI-EVIDENCE.zip'
# Bundle members may never carry these; the caller adds its home, work root and user name.
PRIVATE_MARKERS = ('/Users/', '/home/', '/nix/store/', '/private/var/', '/var/folders/')


def _fixture_cases(repo_root=REPO_ROOT):
    html = (Path(repo_root) / FIXTURE).read_text()
    return dict(re.findall(r'id="(c\d+)" data-expect="(visible|absent|related|record)"', html))


def _toplayer_fixture_cases(repo_root=REPO_ROOT):
    html = (Path(repo_root) / TOPLAYER_FIXTURE).read_text()
    return dict(re.findall(r'id="(t\d+)" data-expect="(visible|absent|suspended|record)"', html))


def _shadow_sentinel_fixture_cases(repo_root=REPO_ROOT):
    path = Path(repo_root) / SHADOW_SENTINEL_FIXTURE
    if not path.is_file():
        return {}
    html = path.read_text()
    return dict(re.findall(r'id="([st]\d+)" data-expect="(visible|absent|suspended|record)"', html))


BROWSER_GATES = (
    'extension-loaded', 'manifest-known-warnings-only', 'no-extension-console-errors',
    'keepassxc-not-associated',
    'custom-rail-discriminator',
    # Top-layer occlusion resistance gates
    'fixed-bottom', 'visual-pointer-none', 'root-after', 'root-mask-clip', 'nested-overlay',
    # Interaction & dynamics gates
    'pointer-priority', 'outside-click-escape', 'drag-track-wheel-budget',
    # Lifecycle & popover gates
    'modal-popover-recovery', 'popover-stacks', 'fullscreen',
    # Resilience & integrity gates
    'host-css-attacks', 'lazy-parser-hydration', 'no-severe-layout-changes',
    'system-colors-usable',
    # Explicit per-engine root gutter evaluation gate
    'root-gutter', 'eligibility-noninterference', 'dynamics-recovery', 'discovery-limits',
    # Inherited R6 shadow sentinel gates
    'handshake', 'closed-shadow-top-layer', 'closed-shadow-modal', 'closed-shadow-popover', 'late-shadow',
    'dsd-fail-closed', 'budget-fail-closed', 'early-closed-root',
    # R7 coverage throttle recovery gate
    'coverage-throttle-recovery',
    # R8 detached root reattach gate
    'detached-root-reattach',
)

CUSTOM_RAIL_BROWSER_GATES = (
    'fixed-bottom', 'visual-pointer-none', 'root-after', 'root-mask-clip', 'nested-overlay',
    'pointer-priority', 'outside-click-escape', 'drag-track-wheel-budget',
    'modal-popover-recovery', 'popover-stacks', 'fullscreen',
    'host-css-attacks', 'lazy-parser-hydration', 'system-colors-usable',
    'root-gutter', 'eligibility-noninterference', 'dynamics-recovery', 'discovery-limits',
    'handshake', 'closed-shadow-top-layer', 'closed-shadow-modal', 'closed-shadow-popover',
    'late-shadow', 'dsd-fail-closed', 'budget-fail-closed', 'early-closed-root',
    'coverage-throttle-recovery', 'detached-root-reattach',
)


def _fixture_visible_related_c_gates(repo_root=REPO_ROOT):
    cases = _fixture_cases(repo_root)
    return tuple(c for c, exp in sorted(cases.items(), key=lambda x: int(x[0][1:])) if exp in ('visible', 'related'))


CUSTOM_RAIL_GATES = _fixture_visible_related_c_gates() + CUSTOM_RAIL_BROWSER_GATES
AUTO_GATES = ('normal-exit',)
RECORD_ONLY_GATES = ('c14', 'c25', 'public-observation-chatgpt', 'foreign-realm-attempt')

GATE_ALIASES = {
    'root::after': 'root-after',
    'outsideClickEscape': 'outside-click-escape',
    'no-severe-reflow': 'no-severe-layout-changes',
    'control': 'handshake',
    'control-handshake': 'handshake',
    'coverage-throttle': 'coverage-throttle-recovery',
    'throttle-recovery': 'coverage-throttle-recovery',
    'detached-root': 'detached-root-reattach',
    'detached-reattach': 'detached-root-reattach',
    'foreign-realm': 'foreign-realm-attempt',
}

KNOWN_WARNINGS = {
    'chrome': ('background.scripts is ignored in favor of service_worker (Chrome >=121)',
               'unrecognized key browser_specific_settings'),
    'firefox': ('background.service_worker is unsupported; background.scripts is used',
                'unrecognized key minimum_chrome_version'),
}

RESIDUALS = (
    'LIVE_POLICY_FORCE_INSTALL: live managed policy still applies to the disposable profiles, so '
    'each browser installs the force_installed extensions there from their normal update source; '
    'the kit does not weaken policy and this browser-initiated install is a recorded residual',
    'FIREFOX_UPDATE_DRIFT: no Firefox update policy exists, so a launch may stage an update of the '
    'current signed installed /Applications/Firefox.app, whose exact selected identity is recorded '
    'in evidence; each runtime is re-bound after its browser exits and any identity change STOPs; '
    'attended Firefox is independent of the CNT production pin with no CNT recovery claim',
    'LOAD_ROUTE_POLICY_LEVEL_ONLY: before launch the temporary-load route is confirmed only by '
    'live policy classification; the attended load gate decides whether the route still works',
    'PERSISTENT_MANUAL_TOAST_SUSPENSION: persistent manual page popovers or toasts suspend extension '
    'rails while open to avoid competing in top-layer stack order; rails resume upon popover closure; '
    'this behavior is a recorded residual',
    'ROOT_GUTTER_MATERIAL_HOLD: ROOT_GUTTER_UNPAINTABLE and NATIVE_UNOCCLUDED both fail '
    'R5 qualification; only demonstrated custom-rail visibility and usability qualify',
    'EARLY_CLOSED_ROOT_MANAGER_LIMIT: early inline closed shadow roots not captured by the MAIN '
    'sentinel latch UNCAPTURED_ROOT and fail closed; manager limit decides acceptance',
    'SHADOW_AVAILABILITY_LIMITS: 256 captured roots include live disconnected roots; this budget '
    'is not a sufficiency claim for shadow-heavy sites. Session-replay attachShadow wrappers, '
    'clonable roots, declarative HTML APIs, uncaptured closed declarative roots and late about:blank '
    'installation can permanently suspend custom rails. Work overloads suspend during cooldown '
    'and require complete bounded coverage before recovery. Structural subtrees exceeding 60000 elements '
    'require a qualifying page mutation and 1s doubling to 30s backoff; quiet oversized trees never '
    'auto-retry. Continuous large-document mutations can suspend custom rails until a quiet interval '
    'permits complete coverage',
)


class KitError(Exception):
    """Refusal or STOP condition; the message is the reason, `code` an optional fixed token."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def require(condition, message, code=None):
    if not condition:
        raise KitError(message, code=code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclasses.dataclass
class Host:
    """Everything the kit observes about the machine; tests inject a fake."""
    home: Path
    managed_root: Path = Path('/Library/Managed Preferences')
    preferences_root: Path = Path('/Library/Preferences')
    firefox_app: Path = runtime.FIREFOX_APP
    chrome_selection: Path = runtime.CHROME_SELECTION
    user: str = ''

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def run(self, argv, timeout=30):
        """(exit code, stdout). A timeout or unstartable binary is a bounded failure code, never
        a traceback; every caller treats any nonzero code as not proven."""
        try:
            done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, ''
        except OSError:
            return 127, ''
        return done.returncode, done.stdout

    def bind(self, browser):
        """(public, private) runtime identity; raises runtime.Unavailable."""
        if browser == 'chrome':
            return runtime.bind_chrome(self.run, self.chrome_selection)
        return runtime.bind_firefox(self.run, self.firefox_app)

    def start(self, argv, log):
        """Own session (terminal signals never reach it), no stdin, output to a private log.
        The handle is only ever waited for."""
        descriptor = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=descriptor,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            os.close(descriptor)

    def live_roots(self):
        support = self.home / 'Library/Application Support'
        return [support / 'Google/Chrome', support / 'Firefox', support / 'Mozilla']

    def sentinels(self):
        support = self.home / 'Library/Application Support'
        return {'chrome-local-state': support / 'Google/Chrome/Local State',
                'firefox-profiles-ini': support / 'Firefox/profiles.ini',
                'firefox-installs-ini': support / 'Firefox/installs.ini'}


# Source identity ---------------------------------------------------------------------------

def package_extension(repo_root):
    """Deterministic 6-member extension package bytes (ZipFile STORED, FIXED_DATE, 0644)."""
    source = Path(repo_root) / EXTENSION_DIR
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(MEMBER_SHA256):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (source / name).read_bytes())
    return stream.getvalue()


def verify_sources(repo_root=REPO_ROOT):
    source = Path(repo_root) / EXTENSION_DIR
    for name, expected in MEMBER_SHA256.items():
        path = source / name
        require(path.is_file(), f'member {name} is missing')
        require(sha256(path.read_bytes()) == expected, f'member {name} is not R8')
    pkg_raw = package_extension(repo_root)
    require(sha256(pkg_raw) == PACKAGE_SHA256, 'package is not R8')
    fix_path = Path(repo_root) / FIXTURE
    require(fix_path.is_file(), f'fixture {FIXTURE} is missing')
    require(sha256(fix_path.read_bytes()) == FIXTURE_SHA256, 'fixture is not R8')
    toplayer_path = Path(repo_root) / TOPLAYER_FIXTURE
    require(toplayer_path.is_file(), f'toplayer fixture {TOPLAYER_FIXTURE} is missing')
    require(sha256(toplayer_path.read_bytes()) == TOPLAYER_FIXTURE_SHA256, 'toplayer fixture is not R8')
    shadow_path = Path(repo_root) / SHADOW_SENTINEL_FIXTURE
    require(shadow_path.is_file(), f'shadow sentinel fixture {SHADOW_SENTINEL_FIXTURE} is missing')
    require(sha256(shadow_path.read_bytes()) == SHADOW_SENTINEL_FIXTURE_SHA256, 'shadow sentinel fixture is not R8')


# Host classification (read-only) -----------------------------------------------------------

def _plist(path):
    try:
        return plistlib.loads(path.read_bytes())
    except FileNotFoundError:
        return {}


def managed_policy(host, domain):
    """Every policy delivery source merged, later sources winning: /Library/Preferences (the
    Browser UX Firefox `macos-preferences` delivery; also read for Chrome so a stray value fails
    closed), then Managed Preferences, system-wide and per user."""
    merged = {}
    for path in (host.preferences_root / f'{domain}.plist', host.managed_root / f'{domain}.plist',
                 host.managed_root / host.user / f'{domain}.plist'):
        merged.update(_plist(path))
    return merged


def chrome_authority_status(repo_root=REPO_ROOT):
    p = Path(repo_root)
    path = p if p.is_file() else p / CHROME_AUTHORITY_MEMBER
    if not path.is_file() or path.is_symlink():
        raise KitError('CHROME_AUTHORITY_INVALID: authority file missing or symlink', code='CHROME_AUTHORITY_INVALID')
    try:
        raw = path.read_bytes()
    except OSError:
        raise KitError('CHROME_AUTHORITY_INVALID: authority unreadable',
                       code='CHROME_AUTHORITY_INVALID') from None
    if sha256(raw) != CHROME_AUTHORITY_SHA256:
        raise KitError('CHROME_AUTHORITY_INVALID: authority hash mismatch', code='CHROME_AUTHORITY_INVALID')
    try:
        doc = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise KitError('CHROME_AUTHORITY_INVALID: malformed JSON', code='CHROME_AUTHORITY_INVALID')
    if (not isinstance(doc, dict)
            or doc.get('disposition') != 'MANAGER_ACCEPTED_PRIOR_ATTENDED'
            or doc.get('browser') != 'chrome'
            or doc.get('version') != '149.0.7827.201'
            or doc.get('source_session') != '20261004T193451Z-ae8e8bf7'
            or doc.get('fresh_launch_in_r14') is not False
            or doc.get('not_a_pass_journal') is not True):
        raise KitError('CHROME_AUTHORITY_INVALID: authority fields mismatch', code='CHROME_AUTHORITY_INVALID')
    return doc


def _normalize_browser_scope(browsers):
    if browsers is None:
        return BROWSERS
    t = tuple(browsers)
    require(t in (('chrome', 'firefox'), ('firefox',)), 'unsupported browser scope')
    return t


def classify_policy(host, browsers=BROWSERS):
    """Return (stops, keys, force_installed); records key names and IDs only."""
    scope = _normalize_browser_scope(browsers)
    chrome = managed_policy(host, 'com.google.Chrome') if 'chrome' in scope else {}
    firefox = managed_policy(host, 'org.mozilla.firefox') if 'firefox' in scope else {}
    if 'firefox' in scope:
        policies_json = host.firefox_app / 'Contents/Resources/distribution/policies.json'
        if policies_json.exists():
            firefox = {**json.loads(policies_json.read_text()).get('policies', {}), **firefox}
    stops = []
    policies = {'chrome': chrome, 'firefox': firefox}
    for name in scope:
        policy = policies[name]
        settings = policy.get('ExtensionSettings', {})
        if any(GECKO_ID in key or 'scrollbar' in key.lower() for key in settings):
            stops.append(f'{name}: the scrollbar extension is registered in live policy')
        if settings.get('*', {}).get('installation_mode') in ('blocked', 'removed'):
            stops.append(f'{name}: ExtensionSettings "*" blocks extensions')
    if 'chrome' in scope:
        if '*' in chrome.get('ExtensionInstallBlocklist', []):
            stops.append('chrome: ExtensionInstallBlocklist blocks all extensions')
        if chrome.get('DeveloperToolsAvailability') == 2:
            stops.append('chrome: developer tools are disabled')
        if chrome.get('ExtensionDeveloperModeSettings') == 1:
            stops.append('chrome: extension developer mode is disabled')
        if 'ExtensionAllowedTypes' in chrome and 'extension' not in chrome['ExtensionAllowedTypes']:
            stops.append('chrome: ExtensionAllowedTypes excludes extensions')
    if 'firefox' in scope:
        if firefox.get('DisableDeveloperTools') is True:
            stops.append('firefox: developer tools are disabled')
        if firefox.get('BlockAboutAddons') is True:
            stops.append('firefox: about:addons is blocked')
    forced = sorted(
        key for name in scope
        for key, value in policies[name].get('ExtensionSettings', {}).items()
        if isinstance(value, dict) and value.get('installation_mode') == 'force_installed')
    if 'chrome' in scope:
        forced += sorted(entry.split(';')[0] for entry in chrome.get('ExtensionInstallForcelist', []))
    keys = {name: sorted(policies[name]) for name in scope}
    return stops, keys, sorted(set(forced))


def scrollbar_mode(host):
    return runtime.host_scrollbar_mode(host.run)


def running(host, browsers=BROWSERS):
    """Browsers not proven absent: a name if running, NAME:UNKNOWN if pgrep could not tell."""
    scope = _normalize_browser_scope(browsers)
    return [name if state == runtime.RUNNING else f'{name}:{state}'
            for name, state in runtime.browser_processes(host.run).items()
            if name in scope and state != runtime.NOT_RUNNING]


def sentinel_digests(host, names=None):
    all_sentinels = host.sentinels()
    if names is not None:
        require(isinstance(names, (list, tuple, set)), 'names must be a collection')
        require(set(names).issubset(all_sentinels), 'unknown sentinel name')
        sentinels = {name: all_sentinels[name] for name in names}
    else:
        sentinels = all_sentinels
    return {name: (sha256(path.read_bytes()) if path.exists() else 'absent')
            for name, path in sentinels.items()}


def quiescent_sentinel_digests(host, *, names=None, samples=3, interval=1.0, sleeper=time.sleep):
    """Sample host sentinel digests until quiescent; drift or OSError raises KitError with fixed code."""
    require(type(samples) is int and samples >= 3, 'samples must be an integer >= 3')
    require(type(interval) in (int, float) and 0 < interval <= 1.5, 'interval must be positive and at most 1.5')
    require((samples - 1) * interval <= 3.0, 'total sample duration must not exceed 3 seconds')
    first = None
    for i in range(samples):
        if i > 0:
            sleeper(interval)
        try:
            current = sentinel_digests(host, names=names)
        except OSError:
            raise KitError('LIVE_SENTINEL_NOT_QUIESCENT', code='LIVE_SENTINEL_NOT_QUIESCENT') from None
        if first is None:
            first = current
        elif current != first:
            raise KitError('LIVE_SENTINEL_NOT_QUIESCENT', code='LIVE_SENTINEL_NOT_QUIESCENT')
    return dict(first)


def bind_all(host, browsers=BROWSERS):
    """Both runtime bindings or a KitError carrying the fixed result:code."""
    scope = _normalize_browser_scope(browsers)
    bindings = {}
    for browser in scope:
        try:
            bindings[browser] = host.bind(browser)
        except runtime.Unavailable as error:
            raise KitError(f'{error.result}:{error.code}', code=error.result) from None
    return bindings


# Session and journal -----------------------------------------------------------------------

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def session_scope(session, entries):
    require(isinstance(session, dict), 'session must be a dict')
    require(isinstance(entries, (list, tuple)), 'entries must be a list or tuple')
    schema = session.get('schema')
    if schema not in (SESSION_SCHEMA, FIREFOX_ONLY_SESSION_SCHEMA):
        raise KitError(f'unsupported session schema: {schema!r}')

    prepared = next((e for e in entries if e.get('kind') == 'prepared'), None)
    require(prepared is not None, 'prepared entry missing in journal')
    require(prepared.get('session_id') == session.get('session_id'), 'journal belongs to another session')
    require(prepared.get('schema') == schema, 'prepared schema mismatch')

    if schema == SESSION_SCHEMA:
        require(set(session.get('runtimes', {}).keys()) == set(BROWSERS), 'combined session runtimes mismatch')
        require(set(session.get('sentinels', {}).keys()) == set(SENTINEL_CONTRACT['sentinels']), 'combined session sentinels mismatch')
        return BROWSERS, tuple(SENTINEL_CONTRACT['sentinels'])

    if schema == FIREFOX_ONLY_SESSION_SCHEMA:
        scope = session.get('scope')
        prepared_scope = prepared.get('scope')
        require(isinstance(scope, dict), 'scope must be a dict in Firefox-only session')
        require(scope == prepared_scope, 'session and prepared scope mismatch')
        require(scope.get('mode') == 'FIREFOX_ONLY', 'scope mode must be FIREFOX_ONLY')
        require(list(scope.get('browsers', [])) == ['firefox'], 'scope browsers must be ["firefox"]')
        require(list(scope.get('sentinels', [])) == list(FIREFOX_SENTINELS), 'scope sentinels must match FIREFOX_SENTINELS')
        require(scope.get('chrome_authority_sha256') == CHROME_AUTHORITY_SHA256, 'invalid chrome authority pin in scope')
        require(session.get('authority_sha256') == CHROME_AUTHORITY_SHA256, 'invalid authority_sha256')
        require(session.get('authority_member') == CHROME_AUTHORITY_MEMBER,
                'invalid authority member')
        require(session.get('provenance') == {'authority_member': CHROME_AUTHORITY_MEMBER,
                                           'authority_sha256': CHROME_AUTHORITY_SHA256},
                'invalid authority provenance')
        require(set(session.get('runtimes', {}).keys()) == {'firefox'}, 'Firefox-only session runtimes must contain only firefox')
        require(set(session.get('sentinels', {}).keys()) == set(FIREFOX_SENTINELS), 'Firefox-only session sentinels must contain only Firefox sentinels')
        return ('firefox',), FIREFOX_SENTINELS

    raise KitError(f'unsupported session schema: {schema!r}')


class Session:
    def __init__(self, scratch):
        self.scratch = Path(scratch)
        self.session_path = self.scratch / 'SESSION.json'
        self.journal_path = self.scratch / 'journal.jsonl'
        require(self.session_path.is_file(), 'no prepared session in this scratch directory')
        self.session = json.loads(self.session_path.read_text())
        self.entries = self._load()

    def _load(self):
        entries, previous = [], '0' * 64
        if self.journal_path.exists():
            for line in self.journal_path.read_text().splitlines():
                entry = json.loads(line)
                body = {k: v for k, v in entry.items() if k != 'hash'}
                require(entry['prev'] == previous and entry['hash'] == sha256(_canonical(body)),
                        f'journal chain broken at entry {len(entries)}')
                previous = entry['hash']
                entries.append(entry)
        return entries

    @property
    def stopped(self):
        return any(entry['kind'] == 'stop' for entry in self.entries)

    def append(self, kind, **fields):
        body = {'seq': len(self.entries), 'time': int(time.time()), 'kind': kind,
                'prev': self.entries[-1]['hash'] if self.entries else '0' * 64, **fields}
        entry = {**body, 'hash': sha256(_canonical(body))}
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, _canonical(entry) + b'\n')
            os.fsync(fd)
        finally:
            os.close(fd)
        self.entries.append(entry)
        return entry

    def active(self, browser=None, allow_stopped=False):
        scoped_browsers, _ = session_scope(self.session, self.entries)
        if not allow_stopped:
            require(not self.stopped, 'session is stopped; only bundle is allowed')
        if browser is not None:
            require(browser in scoped_browsers,
                    f'browser {browser} not permitted in session scope ({scoped_browsers})',
                    code='FOREIGN_BROWSER_ENTRY')


def _request_proof_valid(entry, names, token, session_id, barrier):
    seqs = entry.get('seqs', {})
    return (entry.get('token') == token and entry.get('session_id') == session_id
            and entry.get('method') == 'GET' and type(entry.get('barrier')) is int
            and entry.get('barrier') == barrier
            and isinstance(seqs, dict)
            and set(seqs) == set(names)
            and all(type(seq) is int and seq > barrier for seq in seqs.values())
            and len(set(seqs.values())) == len(names))


def observation_allowed(phase, gate, result):
    """Shared recording/replay/verdict contract; sentinel evidence requires the new instance."""
    if gate in AUTO_GATES:
        return True, None
    if gate in PRE_FIXTURE_GATES:
        return phase is not None, 'FIXTURE_NOT_POSTLOAD_FRESH'
    if gate in SENTINEL_FIXTURE_GATES or (gate == 'custom-rail-discriminator' and result == 'pass'):
        return phase == 'SENTINEL_VISUAL_GATES', 'FIXTURE_NOT_POSTREENABLE_FRESH'
    return phase in ('VISUAL_GATES', 'SENTINEL_VISUAL_GATES'), 'FIXTURE_NOT_POSTLOAD_FRESH'


def browser_phase(entries, browser):
    """Replay all ordered, session-bound freshness facts and observation prerequisites."""
    phase, token, barrier, proof_last_seq = None, None, None, 0
    prepared = next((e for e in entries if e.get('kind') == 'prepared'), {})
    session_id = prepared.get('session_id')
    require(prepared.get('schema') in (SESSION_SCHEMA, FIREFOX_ONLY_SESSION_SCHEMA) and isinstance(session_id, str)
            and re.fullmatch(r'[0-9a-f]{32}', session_id), 'missing prepared session binding')
    state_steps = {v['state']: v for v in RAIL_STEPS.values()}
    fresh_steps = {v['fresh']: v for v in RAIL_STEPS.values()}
    for i, entry in enumerate(entries):
        if entry.get('browser') != browser:
            continue
        kind = entry.get('kind')
        target = 'LAUNCHED' if kind == 'launch' else kind
        if target in PHASES:
            previous = PHASES[PHASES.index(target) - 1] if target != 'LAUNCHED' else None
            if phase != previous:
                code = 'FIXTURE_NOT_POSTREENABLE_FRESH' if target in PHASES[7:] else 'FIXTURE_NOT_POSTLOAD_FRESH'
                raise KitError(f'{browser} {target} out of order from phase {phase}', code=code)
            if target == 'LAUNCHED':
                argv = entry.get('argv', [])
                require(argv and argv[-1] == 'about:blank'
                        and not any(name in arg for name in FIXTURE_NAMES for arg in argv),
                        f'{browser} launch must be neutral')
            elif target == 'EXTENSION_LOADED':
                require(latest(entries[:i]).get((browser, 'extension-loaded')) == 'pass',
                        f'{browser} extension-loaded must pass before EXTENSION_LOADED phase')
                barrier = entry.get('barrier')
                require(type(barrier) is int and barrier >= 0, 'invalid extension-load request barrier')
            elif target == 'fixtures-presented':
                token = entry.get('token')
                require(entry.get('session_id') == session_id and isinstance(token, str)
                        and re.fullmatch(r'[0-9a-f]{32}', token), 'invalid fixture token/session binding')
            elif target == 'FIXTURES_OPENED_POSTLOAD' or target in fresh_steps:
                names = FIXTURE_NAMES if target == 'FIXTURES_OPENED_POSTLOAD' else fresh_steps[target]['fixtures']
                code = ('FIXTURE_NOT_POSTREENABLE_FRESH' if target == 'ALL_FIXTURES_FRESH_POSTREENABLE'
                        else 'RAIL_COMPARISON_NOT_PROVEN' if target in fresh_steps else 'FIXTURE_NOT_POSTLOAD_FRESH')
                if not _request_proof_valid(entry, names, token, session_id, barrier):
                    raise KitError(f'{code}: missing current-session ordered GET evidence', code=code)
                proof_last_seq = max(entry['seqs'].values())
            elif target in state_steps:
                barrier = entry.get('barrier')
                require(type(barrier) is int and barrier >= proof_last_seq,
                        'RAIL_COMPARISON_NOT_PROVEN: request barrier regressed')
                require(entry.get('token') == token and entry.get('session_id') == session_id,
                        'RAIL_COMPARISON_NOT_PROVEN: toggle belongs to another session')
            phase = target
        elif kind == 'observation':
            gate, result = entry.get('gate'), entry.get('result')
            ok, code = observation_allowed(phase, gate, result)
            if not ok:
                raise KitError(f'{browser}:{gate}: {code}: observation forbidden in phase {phase}', code=code)
            if result == 'pass' and gate in CUSTOM_RAIL_GATES:
                require(latest(entries[:i]).get((browser, 'custom-rail-discriminator')) == 'pass',
                        f'{browser}:{gate}: custom rail gate passed before custom-rail-discriminator pass')
    return phase


def load_local(state, work):
    """Private session state in the work root: paths only, bound to this session's ID."""
    path = Path(work) / 'private/LOCAL.json'
    require(path.is_file() and not path.is_symlink(), 'no private state for this session in the work root')
    local = json.loads(path.read_text())
    require(local.get('session_id') == state.session['session_id'],
            'the work root belongs to another session')
    return local


def _cases(session, *kinds):
    return tuple(case for case, expect in sorted(session['cases'].items(), key=lambda c: int(c[0][1:]))
                 if expect in kinds)


def required_gates(session):
    return BROWSER_GATES + AUTO_GATES + _cases(session, 'visible', 'absent')


def related_coverage(session, entries):
    """Related-frame claims are judged apart from the core verdict; a fail narrows coverage."""
    try:
        scoped_browsers, _ = session_scope(session, entries)
    except KitError:
        scoped_browsers = ('firefox',) if session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA else BROWSERS
    for entry in entries:
        b = entry.get('browser')
        if b is not None and b not in scoped_browsers:
            return 'PARTIAL', [f'{b}:FOREIGN_BROWSER_ENTRY']
    results = latest(entries)
    cases = _cases(session, 'related')
    gaps = [f'{b}:{c}' for b in scoped_browsers for c in cases if results.get((b, c)) != 'pass']
    return ('FULL', []) if not gaps else ('PARTIAL', gaps)


def latest(entries):
    """Last result per gate, except that a fail is sticky: no later answer can launder it."""
    results = {}
    for entry in entries:
        if entry['kind'] == 'observation':
            key = (entry['browser'], entry['gate'])
            if results.get(key) != 'fail':
                results[key] = entry['result']
    return results


def verdict(session, entries):
    """FAIL outranks a stop: a recorded required fail is never reported as incomplete."""
    freshness_issues = []
    prepared = next((e for e in entries if e.get('kind') == 'prepared'), {})
    if (session.get('schema') not in (SESSION_SCHEMA, FIREFOX_ONLY_SESSION_SCHEMA)
            or prepared.get('session_id') != session.get('session_id')):
        freshness_issues.append('FIXTURE_NOT_POSTLOAD_FRESH: obsolete or foreign session journal')

    try:
        scoped_browsers, scoped_sentinels = session_scope(session, entries)
    except KitError as err:
        if session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA:
            scoped_browsers, scoped_sentinels = ('firefox',), FIREFOX_SENTINELS
        else:
            scoped_browsers, scoped_sentinels = BROWSERS, tuple(SENTINEL_CONTRACT['sentinels'])
        if not freshness_issues:
            freshness_issues.append(f'FIXTURE_NOT_POSTLOAD_FRESH: {err}')
    is_firefox_only = (session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA)

    results = latest(entries)
    gates = required_gates(session)
    stops = [entry['reason'] for entry in entries if entry['kind'] == 'stop']
    failed = [f'{b}:{g}' for b in scoped_browsers for g in gates if results.get((b, g)) == 'fail']

    for entry in entries:
        b = entry.get('browser')
        if b is not None and b not in scoped_browsers:
            failed.append(f'{b}:FOREIGN_BROWSER_ENTRY')

    for browser in scoped_browsers:
        try:
            phase = browser_phase(entries, browser)
        except KitError as error:
            code = 'FIXTURE_NOT_POSTREENABLE_FRESH' if error.code == 'FIXTURE_NOT_POSTREENABLE_FRESH' else 'FIXTURE_NOT_POSTLOAD_FRESH'
            freshness_issues.append(f'{browser}:{code}: invalid phase or request evidence')
        else:
            if phase != 'SENTINEL_VISUAL_GATES':
                code = 'FIXTURE_NOT_POSTLOAD_FRESH' if phase not in PHASES[4:] else 'FIXTURE_NOT_POSTREENABLE_FRESH'
                freshness_issues.append(f'{browser}:{code}')

    for entry in entries:
        if entry.get('kind') == 'observation' and entry.get('gate') == 'root-gutter':
            if entry.get('root_gutter') == 'ROOT_GUTTER_UNPAINTABLE':
                hold = f"{entry['browser']}:root-gutter:ROOT_GUTTER_UNPAINTABLE (material hold)"
                if hold not in failed:
                    failed.append(hold)
            elif entry.get('root_gutter') == 'NATIVE_UNOCCLUDED':
                disqual = f"{entry['browser']}:root-gutter:NATIVE_UNOCCLUDED (native-only visibility does not qualify)"
                if disqual not in failed:
                    failed.append(disqual)
        elif entry.get('kind') == 'observation' and entry.get('gate') == 'early-closed-root':
            if entry.get('early_closed_root') == 'NOT_CAPTURED_FAIL_CLOSED':
                limit_msg = f"{entry['browser']}:early-closed-root:NOT_CAPTURED_FAIL_CLOSED (manager limit)"
                if limit_msg not in failed:
                    failed.append(limit_msg)

    # Challenge scenes linkage: root-after and root-mask-clip cannot qualify without RAIL_VISIBLE_USABLE
    for b in scoped_browsers:
        rg_entry = next((e for e in entries if e.get('kind') == 'observation' and e.get('browser') == b and e.get('gate') == 'root-gutter'), None)
        rg_branch = rg_entry.get('root_gutter') if rg_entry else None
        if rg_branch in ('NATIVE_UNOCCLUDED', 'ROOT_GUTTER_UNPAINTABLE', 'FAIL'):
            for cg in ('root-after', 'root-mask-clip'):
                if results.get((b, cg)) == 'pass':
                    link_msg = f"{b}:{cg}:challenge scene cannot qualify without root-gutter RAIL_VISIBLE_USABLE"
                    if link_msg not in failed:
                        failed.append(link_msg)

    # Freshness chain and visual gate order validation
    for b in scoped_browsers:
        launch_idx = next((i for i, e in enumerate(entries) if e.get('kind') == 'launch' and e.get('browser') == b), None)
        ext_idx = next((i for i, e in enumerate(entries) if (e.get('kind') == 'EXTENSION_LOADED' or e.get('phase') == 'EXTENSION_LOADED') and e.get('browser') == b), None)
        pres_idx = next((i for i, e in enumerate(entries) if (e.get('kind') == 'fixtures-presented' or e.get('phase') == 'fixtures-presented') and e.get('browser') == b), None)
        post_idx = next((i for i, e in enumerate(entries) if (e.get('kind') == 'FIXTURES_OPENED_POSTLOAD' or e.get('phase') == 'FIXTURES_OPENED_POSTLOAD') and e.get('browser') == b), None)
        vis_idx = next((i for i, e in enumerate(entries) if (e.get('kind') == 'VISUAL_GATES' or e.get('phase') == 'VISUAL_GATES') and e.get('browser') == b), None)

        chain_valid = (
            launch_idx is not None and ext_idx is not None and pres_idx is not None
            and post_idx is not None and vis_idx is not None
            and launch_idx < ext_idx < pres_idx < post_idx < vis_idx
        )

        observed_phase = None
        for i, entry in enumerate(entries):
            if entry.get('browser') == b and entry.get('kind') in PHASES:
                observed_phase = entry['kind']
            elif entry.get('browser') == b and entry.get('kind') == 'launch':
                observed_phase = 'LAUNCHED'
            if entry.get('browser') == b and entry.get('kind') == 'observation':
                gate = entry.get('gate')
                if gate not in PRE_FIXTURE_GATES and gate not in AUTO_GATES:
                    if not chain_valid or vis_idx is None or i < vis_idx:
                        bad_obs = f"{b}:FIXTURE_NOT_POSTLOAD_FRESH:{gate}: visual pass recorded without valid VISUAL_GATES chain"
                        if bad_obs not in failed:
                            failed.append(bad_obs)
                    elif not observation_allowed(observed_phase, gate, entry.get('result'))[0]:
                        code = observation_allowed(observed_phase, gate, entry.get('result'))[1]
                        freshness_issues.append(f'{b}:{code}:{gate}: premature observation')

        # Custom rail pass prerequisite and comparison chain validation
        has_custom_pass = any(results.get((b, g)) == 'pass' for g in CUSTOM_RAIL_GATES)
        if has_custom_pass:
            disc_idx = next((i for i, e in enumerate(entries)
                             if e.get('kind') == 'observation' and e.get('browser') == b
                             and e.get('gate') == 'custom-rail-discriminator' and e.get('result') == 'pass'), None)
            dis_prompt_idx = next((i for i, e in enumerate(entries)
                                   if e.get('kind') == 'EXTENSION_DISABLED' and e.get('browser') == b), None)
            dis_comp_idx = next((i for i, e in enumerate(entries)
                                 if e.get('kind') == 'DISABLED_COMPARISON_FRESH' and e.get('browser') == b), None)
            reen_prompt_idx = next((i for i, e in enumerate(entries)
                                    if e.get('kind') == 'EXTENSION_REENABLED' and e.get('browser') == b), None)
            reen_comp_idx = next((i for i, e in enumerate(entries)
                                  if e.get('kind') == 'SENTINEL_VISUAL_GATES' and e.get('browser') == b), None)

            comp_valid = (
                vis_idx is not None
                and dis_prompt_idx is not None and dis_comp_idx is not None
                and reen_prompt_idx is not None and reen_comp_idx is not None
                and disc_idx is not None
                and vis_idx < dis_prompt_idx < dis_comp_idx < reen_prompt_idx < reen_comp_idx < disc_idx
            )
            if not comp_valid:
                chain_msg = f"{b}:custom-rail-discriminator: missing or invalid comparison chain for custom rail passes"
                freshness_issues.append('FIXTURE_NOT_POSTREENABLE_FRESH: ' + chain_msg)
            else:
                for g in CUSTOM_RAIL_GATES:
                    if results.get((b, g)) == 'pass':
                        first_custom_pass_idx = next((i for i, e in enumerate(entries)
                                                      if e.get('kind') == 'observation' and e.get('browser') == b and e.get('gate') == g and e.get('result') == 'pass'), None)
                        if first_custom_pass_idx is not None and first_custom_pass_idx < disc_idx:
                            ord_msg = f"{b}:{g}: custom rail gate passed before custom-rail-discriminator pass"
                            if g in SENTINEL_FIXTURE_GATES and first_custom_pass_idx < reen_comp_idx:
                                freshness_issues.append(f'{b}:FIXTURE_NOT_POSTREENABLE_FRESH:{g}')
                            elif ord_msg not in failed:
                                failed.append(ord_msg)

    # Firefox-only qualification requires the recorded exact exit comparisons.
    if is_firefox_only:
        for b in scoped_browsers:
            launch_index = next((i for i, e in enumerate(entries)
                                 if e.get('kind') == 'launch' and e.get('browser') == b), None)
            exit_index = next((i for i, e in enumerate(entries)
                               if e.get('kind') == 'observation' and e.get('browser') == b
                               and e.get('gate') == 'normal-exit' and e.get('result') == 'pass'), None)
            checked = any(
                e.get('kind') == 'after-exit' and e.get('browser') == b
                and e.get('verified') is True and e.get('status') == 'VERIFIED_MATCH'
                and e.get('sentinels') == session['sentinels']
                and e.get('runtime') == session['runtimes'][b]
                and launch_index is not None and exit_index is not None
                and launch_index < exit_index < i
                for i, e in enumerate(entries))
            if not checked:
                freshness_issues.append(f'{b}:after-exit: verified after-exit check required')

    if failed:
        return 'FAIL', failed + [f'stopped: {reason}' for reason in stops]
    if stops:
        return 'INCOMPLETE', ['session stopped; no qualification claim'] + stops + freshness_issues
    missing = [f'{b}:{g}' for b in scoped_browsers for g in gates if results.get((b, g)) != 'pass']
    reasons = list(missing) + freshness_issues
    if session['host']['AppleShowScrollBars'] != runtime.SCROLLBAR_ALWAYS:
        reasons.append('host scrollbar mode is not Always; overlay scrollbars make visibility '
                       'observations inconclusive')
    return ('PASS', []) if not reasons else ('INCOMPLETE', reasons)


# Commands ----------------------------------------------------------------------------------

def _fresh_dir(path, host, repo_root):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink(), 'scratch must not exist yet')
    require(path.parent.is_dir(), 'scratch parent must exist')
    require(path.parent.resolve() == path.parent, 'scratch has a symlinked ancestor')
    for forbidden in [Path(repo_root).resolve(), *[p.resolve() for p in host.live_roots()]]:
        require(not path.is_relative_to(forbidden), f'scratch inside {forbidden.name}')
    return path


def prepare(scratch, host, repo_root=REPO_ROOT, work=None, bindings=None, sentinels=None,
            browsers=BROWSERS, chrome_authority_sha256=None):
    """Create a fresh session. `bindings` lets the observer reuse its seconds-old check."""
    verify_sources(repo_root)
    scope = _normalize_browser_scope(browsers)
    is_firefox_only = (scope == ('firefox',))

    if is_firefox_only:
        chrome_authority_status(repo_root)
        pin = CHROME_AUTHORITY_SHA256
        if chrome_authority_sha256 is not None:
            require(chrome_authority_sha256 == pin, 'chrome authority sha256 mismatch', code='CHROME_AUTHORITY_INVALID')
        expected_sentinel_scope = set(FIREFOX_SENTINELS)
    else:
        require(chrome_authority_sha256 is None, 'chrome_authority_sha256 only valid for firefox-only sessions')
        expected_sentinel_scope = set(host.sentinels().keys())

    scratch = _fresh_dir(scratch, host, repo_root)
    work = scratch if work is None else _fresh_dir(work, host, repo_root)
    require(work == scratch or not (work.is_relative_to(scratch) or scratch.is_relative_to(work)),
            'work and evidence directories must be disjoint')
    busy = running(host, browsers=scope) if is_firefox_only else running(host)
    require(not busy, f'quit these browsers first: {busy}')
    stops, keys, forced = classify_policy(host, browsers=scope) if is_firefox_only else classify_policy(host)
    require(not stops, 'STOP: ' + '; '.join(stops))
    bindings = (bind_all(host, browsers=scope) if is_firefox_only else bind_all(host)) if bindings is None else bindings
    mode = scrollbar_mode(host)
    if sentinels is not None:
        require(isinstance(sentinels, dict), 'sentinels must be a dict')
        require(set(sentinels.keys()) == expected_sentinel_scope, 'sentinel baseline keys do not match the fixed scope')
        for k, v in sentinels.items():
            require(v == 'absent' or (isinstance(v, str) and len(v) == 64 and bool(re.fullmatch(r'[0-9a-f]{64}', v))),
                    f'invalid sentinel value for {k}')
        baseline_sentinels = dict(sentinels)
        sentinel_baseline_label = 'QUIESCENT_3_SAMPLES'
    else:
        baseline_sentinels = sentinel_digests(host, names=FIREFOX_SENTINELS if is_firefox_only else None)
        sentinel_baseline_label = 'SINGLE_SAMPLE_DIAGNOSTIC'
    scratch.mkdir(mode=0o700)
    if work != scratch:
        work.mkdir(mode=0o700)

    if is_firefox_only:
        src_auth = Path(repo_root) / CHROME_AUTHORITY_MEMBER
        dst_auth = scratch / CHROME_AUTHORITY_SCRATCH_NAME
        shutil.copyfile(src_auth, dst_auth)
        os.chmod(dst_auth, 0o600)
        require(sha256(dst_auth.read_bytes()) == CHROME_AUTHORITY_SHA256, 'authority copy verification failed')

    profile_dirs = [f'profiles/{b}' for b in scope]
    for name in (*profile_dirs, 'extension', 'site', 'private'):
        (work / name).mkdir(parents=True, mode=0o700)
    for name in MEMBER_SHA256:
        shutil.copyfile(Path(repo_root) / EXTENSION_DIR / name, work / 'extension' / name)
        require(sha256((work / 'extension' / name).read_bytes()) == MEMBER_SHA256[name], name)
    shutil.copyfile(Path(repo_root) / FIXTURE, work / 'site/scrollbar-matrix.html')
    shutil.copyfile(Path(repo_root) / TOPLAYER_FIXTURE, work / 'site/scrollbar-toplayer-matrix.html')
    shutil.copyfile(Path(repo_root) / SHADOW_SENTINEL_FIXTURE, work / 'site/scrollbar-shadow-sentinel-matrix.html')
    session_id = secrets.token_hex(16)
    local = {'session_id': session_id, 'work': str(work),
             'runtimes': {browser: bindings[browser][1] for browser in scope}}
    descriptor = os.open(work / 'private/LOCAL.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(json.dumps(local, indent=2, sort_keys=True) + '\n')

    if is_firefox_only:
        session = {
            'schema': FIREFOX_ONLY_SESSION_SCHEMA, 'session_id': session_id,
            'package_sha256': PACKAGE_SHA256, 'members': MEMBER_SHA256,
            'fixture_sha256': FIXTURE_SHA256,
            'toplayer_fixture_sha256': TOPLAYER_FIXTURE_SHA256,
            'shadow_sentinel_fixture_sha256': SHADOW_SENTINEL_FIXTURE_SHA256,
            'version': VERSION,
            'scratch': '<scratch>', 'work': '<work>',
            'cases': _fixture_cases(repo_root),
            'toplayer_cases': _toplayer_fixture_cases(repo_root),
            'shadow_sentinel_cases': _shadow_sentinel_fixture_cases(repo_root),
            'runtimes': {browser: bindings[browser][0] for browser in scope},
            'host': {'AppleShowScrollBars': mode},
            'policy_keys': keys, 'force_installed': forced,
            'keepassxc_forced': [i for i in KEEPASSXC_IDS if i in forced],
            'sentinels': baseline_sentinels,
            'sentinel_baseline': sentinel_baseline_label,
            'sentinel_scope': 'Firefox profiles.ini/installs.ini only; '
                              'Chrome Local State and browser-global files such as ~/Library/Preferences '
                              'plists and crash-report directories are not checked',
            'live_policy_scope': 'live managed policy still applies to the disposable profiles, so '
                                 'the force_installed extensions are installed there; native-messaging '
                                 'host manifests are user-wide, so the live KeePassXC is reachable '
                                 'from them; keepassxc-not-associated is the required gate',
            'residuals': list(RESIDUALS),
            'scope': {
                'mode': 'FIREFOX_ONLY',
                'browsers': ['firefox'],
                'sentinels': list(FIREFOX_SENTINELS),
                'chrome_authority_sha256': CHROME_AUTHORITY_SHA256,
            },
            'provenance': {
                'authority_member': CHROME_AUTHORITY_MEMBER,
                'authority_sha256': CHROME_AUTHORITY_SHA256,
            },
            'authority_member': CHROME_AUTHORITY_MEMBER,
            'authority_sha256': CHROME_AUTHORITY_SHA256,
        }
        (scratch / 'SESSION.json').write_text(json.dumps(session, indent=2, sort_keys=True) + '\n')
        Session(scratch).append('prepared', host=session['host'], session_id=session_id,
                                schema=FIREFOX_ONLY_SESSION_SCHEMA, scope=session['scope'])
    else:
        session = {
            'schema': SESSION_SCHEMA, 'session_id': session_id,
            'package_sha256': PACKAGE_SHA256, 'members': MEMBER_SHA256,
            'fixture_sha256': FIXTURE_SHA256,
            'toplayer_fixture_sha256': TOPLAYER_FIXTURE_SHA256,
            'shadow_sentinel_fixture_sha256': SHADOW_SENTINEL_FIXTURE_SHA256,
            'version': VERSION,
            'scratch': '<scratch>', 'work': '<work>',
            'cases': _fixture_cases(repo_root),
            'toplayer_cases': _toplayer_fixture_cases(repo_root),
            'shadow_sentinel_cases': _shadow_sentinel_fixture_cases(repo_root),
            'runtimes': {browser: bindings[browser][0] for browser in BROWSERS},
            'host': {'AppleShowScrollBars': mode},
            'policy_keys': keys, 'force_installed': forced,
            'keepassxc_forced': [i for i in KEEPASSXC_IDS if i in forced],
            'sentinels': baseline_sentinels,
            'sentinel_baseline': sentinel_baseline_label,
            'sentinel_scope': 'Chrome Local State and Firefox profiles.ini/installs.ini only; '
                              'browser-global files such as ~/Library/Preferences plists and '
                              'crash-report directories are not checked',
            'live_policy_scope': 'live managed policy still applies to the disposable profiles, so '
                                 'the force_installed extensions are installed there; native-messaging '
                                 'host manifests are user-wide, so the live KeePassXC is reachable '
                                 'from them; keepassxc-not-associated is the required gate',
            'residuals': list(RESIDUALS),
        }
        (scratch / 'SESSION.json').write_text(json.dumps(session, indent=2, sort_keys=True) + '\n')
        Session(scratch).append('prepared', host=session['host'], session_id=session_id, schema=SESSION_SCHEMA)

    return session


def verify_scratch(state, work):
    """Bind every launch and serve to the R8 bytes copied by prepare; a change STOPs."""
    work = Path(work)
    extension = work / 'extension'
    problems = []
    if sorted(p.name for p in extension.iterdir()) != sorted(MEMBER_SHA256):
        problems.append('extension copy has unexpected members')
    for name, expected in MEMBER_SHA256.items():
        path = extension / name
        if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()) != expected:
            problems.append(f'extension copy {name} is not R8')
    site = work / 'site/scrollbar-matrix.html'
    if site.is_symlink() or not site.is_file() or sha256(site.read_bytes()) != FIXTURE_SHA256:
        problems.append('served fixture is not R8')
    toplayer_site = work / 'site/scrollbar-toplayer-matrix.html'
    if toplayer_site.is_symlink() or not toplayer_site.is_file() or sha256(toplayer_site.read_bytes()) != TOPLAYER_FIXTURE_SHA256:
        problems.append('served toplayer fixture is not R8')
    shadow_site = work / 'site/scrollbar-shadow-sentinel-matrix.html'
    if shadow_site.is_symlink() or not shadow_site.is_file() or sha256(shadow_site.read_bytes()) != SHADOW_SENTINEL_FIXTURE_SHA256:
        problems.append('served shadow sentinel fixture is not R8')
    if state.session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA:
        auth_file = state.scratch / CHROME_AUTHORITY_SCRATCH_NAME
        if not auth_file.is_file() or auth_file.is_symlink() or sha256(auth_file.read_bytes()) != CHROME_AUTHORITY_SHA256:
            problems.append('authority copy CHROME-AUTHORITY.json is missing or tampered')
    if problems:
        state.append('stop', reason='scratch copy changed: ' + ', '.join(problems))
        raise KitError('STOP: scratch copy changed: ' + ', '.join(problems))


def launch_argv(browser, work, executable, port=0):
    root = str(Path(work) / 'profiles' / browser)
    if browser == 'chrome':
        # --use-mock-keychain (Chromium test switch) keeps the disposable profile away from the
        # login keychain's Chrome Safe Storage item.
        return [str(executable), f'--user-data-dir={root}', '--no-first-run',
                '--no-default-browser-check', '--use-mock-keychain', 'about:blank']
    return [str(executable), '-profile', root, '-no-remote', '-new-instance', 'about:blank']


GUIDE = {
    'chrome': ('In the neutral setup tab, open chrome://extensions, enable Developer mode, choose "Load unpacked" and '
               'select {ext}. Confirm version {version}; record extension-loaded, and record '
               'manifest-known-warnings-only as pass only if every warning is listed in the kit. '
               'Deny any keychain or KeePassXC association prompt. Do not open qualification fixtures '
               'yet; the guided observer supplies fresh URLs after extension-loaded.'),
    'firefox': ('In the neutral setup tab, open about:debugging#/runtime/this-firefox, choose "Load Temporary Add-on" and '
                'select {ext}/manifest.json. Confirm version {version}; record extension-loaded, '
                'and record manifest-known-warnings-only as pass only if every warning is listed '
                'in the kit. Deny any KeePassXC association prompt. Do not open qualification fixtures '
                'yet; the guided observer supplies fresh URLs after extension-loaded.'),
}
LIVE_POLICY_NOTE = ('Live managed policy also applies here: force-installed extensions such as '
                    'the content blocker and KeePassXC-Browser may appear. Leave them '
                    'unconfigured; the KeePassXC native host is user-wide, so deny every '
                    'association prompt and record keepassxc-not-associated.')


def print_guide(browser, work, out=print):
    """Local terminal only: the extension path is shown here and never journaled."""
    out(GUIDE[browser].format(ext=Path(work) / 'extension', version=VERSION))
    out('Known manifest warnings: ' + '; '.join(KNOWN_WARNINGS[browser]))
    out(LIVE_POLICY_NOTE)


def begin_launch(scratch, browser, host, port, work=None):
    """Re-verify everything, then start the one launch of `browser` in this session."""
    require(browser in BROWSERS, 'browser must be chrome or firefox')
    work = Path(scratch if work is None else work)
    state = Session(scratch)
    state.active(browser=browser)
    scoped_browsers, scoped_sentinels = session_scope(state.session, state.entries)
    require(not any(e['kind'] == 'launch' and e['browser'] == browser for e in state.entries),
            f'{browser} was already launched in this session; start a new session')
    local = load_local(state, work)
    verify_scratch(state, work)
    busy = running(host, browsers=scoped_browsers)
    require(not busy, f'quit the normal browsers before a disposable launch: {busy}')
    profile = work / 'profiles' / browser
    require(profile.is_dir() and not profile.is_symlink(), 'disposable profile root missing')
    problems = []
    if scrollbar_mode(host) != state.session['host']['AppleShowScrollBars']:
        problems.append('HOST_SCROLLBAR_MODE_CHANGED')
    try:
        public, private = host.bind(browser)
    except runtime.Unavailable as error:
        problems.append(f'RUNTIME_UNAVAILABLE {error.result}:{error.code}')
    else:
        if public != state.session['runtimes'][browser] or private != local['runtimes'][browser]:
            problems.append('RUNTIME_CHANGED')
    if problems:
        state.append('stop', reason=f'{browser} before launch: ' + ', '.join(problems))
        raise KitError(f'STOP: {browser} before launch: ' + ', '.join(problems))
    argv = launch_argv(browser, work, local['runtimes'][browser]['executable'], port)
    redacted = [f'<{browser}>'] + [a.replace(str(work), '<work>') for a in argv[1:]]
    baseline = state.session['sentinels']
    try:
        current = sentinel_digests(host, names=scoped_sentinels)
    except OSError:
        changed = sorted(baseline)
    else:
        changed = sorted(name for name in set(current) | set(baseline)
                         if current.get(name) != baseline.get(name))

    if changed:
        other_browser = next((b for b in scoped_browsers if b != browser), None)
        if other_browser:
            other_exit_pass = any(e.get('kind') == 'observation' and e.get('browser') == other_browser
                                  and e.get('gate') == 'normal-exit' and e.get('result') == 'pass'
                                  for e in state.entries)
            prior_browser_exit_checked = bool(other_exit_pass and not state.stopped)
        else:
            prior_browser_exit_checked = False
        state.append('stop', reason='LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH',
                     browser=browser, changed=changed,
                     baseline='SESSION_BASELINE_UNCHANGED',
                     prior_browser_exit_checked=prior_browser_exit_checked)
        raise KitError(f'LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH: {browser}: ' + ', '.join(changed),
                       code='LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH')
    state.append('launch', browser=browser, argv=redacted)
    return host.start(argv, work / 'private' / f'{browser}.log')


def end_launch(scratch, browser, host, code):
    """Journal the exit, then recheck live sentinels and re-bind the runtime; a change STOPs.
    Runs even after a stop, so the exit facts of an interrupted session are still recorded."""
    require(browser in BROWSERS, 'browser must be chrome or firefox')
    state = Session(scratch)
    state.active(browser=browser, allow_stopped=True)
    scoped_browsers, scoped_sentinels = session_scope(state.session, state.entries)
    is_firefox_only = (state.session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA)

    state.append('observation', browser=browser, gate='normal-exit',
                 result='pass' if code == 0 else 'fail', note=f'exit status {code}')
    problems = []
    current_sentinels = {}
    try:
        current_sentinels = sentinel_digests(host, names=scoped_sentinels)
    except OSError:
        problems.append('live browser state unreadable after exit')
    else:
        changed = sorted(k for k, v in current_sentinels.items() if state.session['sentinels'].get(k) != v)
        if changed:
            problems.append('live browser state changed: ' + ', '.join(changed))
    try:
        public, _ = host.bind(browser)
    except runtime.Unavailable as error:
        problems.append(f'runtime unavailable after exit {error.result}:{error.code}')
    except OSError:
        problems.append('runtime unreadable after exit')
    else:
        if public != state.session['runtimes'][browser]:
            problems.append(f'{browser} RUNTIME_CHANGED during the session')
    if problems:
        state.append('stop', reason=f'{browser} after exit: ' + '; '.join(problems))
        raise KitError(f'STOP: {browser} after exit: ' + '; '.join(problems))

    if is_firefox_only and code == 0:
        state.append('after-exit', browser=browser, verified=True, status='VERIFIED_MATCH',
                     sentinels=current_sentinels, runtime=public)


def wait_retained(handle, out=print):
    """Wait for the owned browser; an interrupt never signals it, the wait just continues."""
    while True:
        try:
            return handle.wait()
        except KeyboardInterrupt:
            out('The kit never signals the browser; quit it (Cmd-Q) and the kit continues.')


def launch(scratch, browser, host, port, work=None):
    work = Path(scratch if work is None else work)
    require(browser in BROWSERS, 'browser must be chrome or firefox')
    state = Session(scratch)
    state.active(browser=browser)
    print_guide(browser, work)
    handle = begin_launch(scratch, browser, host, port, work)
    code = wait_retained(handle)
    end_launch(scratch, browser, host, code)
    return code


def mark_extension_loaded(scratch, browser, request_barrier):
    require(browser in BROWSERS, f'invalid browser {browser}')
    state = Session(scratch)
    state.active(browser=browser)
    require(type(request_barrier) is int and request_barrier >= 0, 'invalid extension-load request barrier')
    require(any(e.get('kind') == 'launch' and e.get('browser') == browser for e in state.entries),
            f'{browser} must be launched before marking extension loaded')
    require(latest(state.entries).get((browser, 'extension-loaded')) == 'pass',
            f'{browser}: extension-loaded must pass before marking extension loaded')
    current_phase = browser_phase(state.entries, browser)
    require(current_phase == 'LAUNCHED',
            f'{browser}: EXTENSION_LOADED phase allowed only once after launch (current phase: {current_phase})')
    return state.append('EXTENSION_LOADED', browser=browser, barrier=request_barrier, phase='EXTENSION_LOADED')


def present_fixtures(scratch, browser):
    require(browser in BROWSERS, f'invalid browser {browser}')
    state = Session(scratch)
    state.active(browser=browser)
    current_phase = browser_phase(state.entries, browser)
    require(current_phase == 'EXTENSION_LOADED',
            f'{browser}: present_fixtures requires EXTENSION_LOADED phase (current: {current_phase})')
    token = secrets.token_hex(16)
    session_id = state.session['session_id']
    state.append('fixtures-presented', browser=browser, session_id=session_id, token=token, phase='fixtures-presented')
    return token


def _qualifying_seqs(requests, names, token, barrier):
    seqs = {}
    for name in names:
        qualifying = [req['seq'] for req in requests
                      if isinstance(req, dict) and req.get('method') == 'GET' and req.get('path') == f'/{name}'
                      and req.get('qual') == [token] and type(req.get('seq')) is int
                      and req['seq'] > barrier]
        if qualifying:
            seqs[name] = min(qualifying)
    return seqs


def fixture_proof_status(requests, names, token, barrier):
    """Pure status evaluation preserving qualifying distinct-seq GET rules."""
    require(type(barrier) is int, 'invalid request barrier')
    seqs = _qualifying_seqs(requests, names, token, barrier)
    missing = [name for name in names if name not in seqs]
    if len(set(seqs.values())) != len(seqs):
        missing = list(names)
    return {'missing': missing, 'seqs': seqs}


def pending_fixture_proof(scratch, browser):
    """Read-only inspection of the current pending fixture proof prerequisites."""
    require(browser in BROWSERS, f'invalid browser {browser}')
    state = Session(scratch)
    state.active(browser=browser)
    current_phase = browser_phase(state.entries, browser)

    if current_phase == 'fixtures-presented':
        presentation = next((e for e in reversed(state.entries)
                             if e.get('kind') == 'fixtures-presented' and e.get('browser') == browser), None)
        require(presentation is not None, 'fixtures-presented entry not found')
        require(presentation.get('session_id') == state.session['session_id'],
                'fixtures-presented entry belongs to another session')
        token = presentation.get('token')
        require(token, 'presentation token missing')

        ext_entry = next((e for e in reversed(state.entries)
                          if (e.get('kind') == 'EXTENSION_LOADED' or e.get('phase') == 'EXTENSION_LOADED') and e.get('browser') == browser), None)
        require(ext_entry is not None, 'EXTENSION_LOADED entry not found')
        barrier = ext_entry.get('barrier', 0)
        return {
            'proof': 'FIXTURES_OPENED_POSTLOAD',
            'names': list(FIXTURE_NAMES),
            'token': token,
            'barrier': barrier,
            'code': 'FIXTURE_NOT_POSTLOAD_FRESH',
        }
    elif current_phase in ('EXTENSION_DISABLED', 'EXTENSION_REENABLED'):
        step = 'disabled-reload' if current_phase == 'EXTENSION_DISABLED' else 'reenabled-reload'
        contract = RAIL_STEPS[step]
        toggle = next((e for e in reversed(state.entries)
                       if e.get('browser') == browser and e.get('kind') == contract['state']), None)
        require(toggle is not None, f'{contract["state"]} entry not found')
        token = toggle.get('token')
        barrier = toggle.get('barrier')
        code = 'FIXTURE_NOT_POSTREENABLE_FRESH' if step == 'reenabled-reload' else 'RAIL_COMPARISON_NOT_PROVEN'
        return {
            'proof': contract['fresh'],
            'names': list(contract['fixtures']),
            'token': token,
            'barrier': barrier,
            'code': code,
        }
    else:
        raise KitError(f'{browser}: no pending fixture proof in phase {current_phase}',
                       code='FIXTURE_NOT_POSTLOAD_FRESH')


def note_freshness_retry(scratch, browser, retry, missing):
    """Record an operator retry for a pending fixture proof."""
    require(browser in BROWSERS, f'invalid browser {browser}')
    require(type(retry) is int and 1 <= retry <= FRESHNESS_RETRIES,
            f'retry must be an int between 1 and {FRESHNESS_RETRIES}')
    state = Session(scratch)
    state.active(browser=browser)
    target = pending_fixture_proof(scratch, browser)
    require(isinstance(missing, (list, tuple)) and len(missing) > 0,
            'missing must be a nonempty ordered subset')
    target_names = target['names']
    ordered_subset = [name for name in target_names if name in missing]
    require(list(missing) == ordered_subset and len(set(missing)) == len(missing),
            'missing must be a nonempty ordered subset of target names')
    return state.append('freshness-retry', browser=browser, proof=target['proof'],
                        retry=retry, missing=list(missing))


def prove_postload(scratch, browser, requests):
    require(browser in BROWSERS, f'invalid browser {browser}')
    state = Session(scratch)
    state.active(browser=browser)
    current_phase = browser_phase(state.entries, browser)
    require(current_phase == 'fixtures-presented',
            f'{browser}: prove_postload requires fixtures-presented phase (current: {current_phase})')

    target = pending_fixture_proof(scratch, browser)
    status = fixture_proof_status(requests, target['names'], target['token'], target['barrier'])
    missing_fixtures = status['missing']

    if missing_fixtures:
        state.append('stop', reason='FIXTURE_NOT_POSTLOAD_FRESH', browser=browser, missing=missing_fixtures)
        raise KitError('FIXTURE_NOT_POSTLOAD_FRESH: ' + ', '.join(missing_fixtures),
                       code='FIXTURE_NOT_POSTLOAD_FRESH')

    state.append('FIXTURES_OPENED_POSTLOAD', browser=browser, phase='FIXTURES_OPENED_POSTLOAD',
                 method='GET', seqs=status['seqs'], token=target['token'], session_id=state.session['session_id'], barrier=target['barrier'])
    state.append('VISUAL_GATES', browser=browser, phase='VISUAL_GATES')


def begin_rail_step(scratch, browser, step, request_barrier):
    require(browser in BROWSERS, f'invalid browser {browser}')
    require(step in RAIL_STEPS, f'invalid step {step!r}')
    state = Session(scratch)
    state.active(browser=browser)
    contract = RAIL_STEPS[step]
    phase = browser_phase(state.entries, browser)
    target = contract['state']
    require(phase == PHASES[PHASES.index(target) - 1],
            f'{browser}: {step} requires prior {PHASES[PHASES.index(target) - 1]} (current: {phase})')
    proofs = [e for e in state.entries if e.get('browser') == browser
               and e.get('kind') in ('FIXTURES_OPENED_POSTLOAD', 'DISABLED_COMPARISON_FRESH')]
    require(type(request_barrier) is int and request_barrier >= max(proofs[-1]['seqs'].values()),
            'RAIL_COMPARISON_NOT_PROVEN: request barrier regressed')
    presentation = next(e for e in reversed(state.entries)
                        if e.get('browser') == browser and e['kind'] == 'fixtures-presented')
    return state.append(target, browser=browser, phase=target, step=step, barrier=request_barrier,
                        token=presentation['token'], session_id=state.session['session_id'])


def prove_rail_step(scratch, browser, step, requests):
    require(browser in BROWSERS, f'invalid browser {browser}')
    require(step in RAIL_STEPS, f'invalid step {step!r}')
    state = Session(scratch)
    state.active(browser=browser)
    contract = RAIL_STEPS[step]
    phase = browser_phase(state.entries, browser)
    require(phase == contract['state'],
            f'{browser}: {step} requires {contract["state"]} (current: {phase})')
    target = pending_fixture_proof(scratch, browser)
    status = fixture_proof_status(requests, target['names'], target['token'], target['barrier'])
    missing = status['missing']
    if missing:
        code = target['code']
        state.append('stop', browser=browser, reason=code, missing=missing)
        raise KitError(f'{browser}: {code}: ' + ', '.join(missing), code=code)
    proof = state.append(contract['fresh'], browser=browser, phase=contract['fresh'], step=step,
                         token=target['token'], barrier=target['barrier'], basenames=list(target['names']),
                         seqs=status['seqs'], method='GET', session_id=state.session['session_id'])
    if step == 'reenabled-reload':
        state.append('SENTINEL_VISUAL_GATES', browser=browser, phase='SENTINEL_VISUAL_GATES')
    return proof


def record(scratch, browser, gate, result, note='', root_gutter=None, early_closed_root=None):
    require(browser in BROWSERS and result in RESULTS, 'bad browser or result')
    state = Session(scratch)
    state.active(browser=browser)
    gate = GATE_ALIASES.get(gate, gate)
    require(result != 'not-reproduced' or gate == 'public-observation-chatgpt', 'not-reproduced is public record-only')
    allowed = set(required_gates(state.session)) | set(state.session.get('cases', {})) | set(RECORD_ONLY_GATES)
    require(gate in allowed and gate not in AUTO_GATES, f'unknown or automatic gate {gate!r}')
    require(NOTE.fullmatch(note) is not None, 'note has disallowed characters or is too long')

    phase = browser_phase(state.entries, browser)
    ok, code = observation_allowed(phase, gate, result)
    if not ok:
        raise KitError(f'{browser}:{gate} cannot be recorded before VISUAL_GATES phase '
                       f'or its required reenable freshness (current phase: {phase}); {code}', code=code)

    if gate in CUSTOM_RAIL_GATES and result == 'pass':
        require(latest(state.entries).get((browser, 'custom-rail-discriminator')) == 'pass',
                f'{browser}:{gate} cannot pass without prior custom-rail-discriminator pass')

    if gate == 'root-gutter':
        require(root_gutter in ROOT_GUTTER_CHOICES, 'root-gutter requires an explicit observed branch')
        expected_result = ('pass' if root_gutter == 'RAIL_VISIBLE_USABLE'
                           else 'not-run' if root_gutter == 'NOT_RUN' else 'fail')
        require(result == expected_result, 'root-gutter branch/result disagree')
        if root_gutter == 'ROOT_GUTTER_UNPAINTABLE':
            require(result == 'fail', 'ROOT_GUTTER_UNPAINTABLE does not qualify root visibility and must fail gate')
            if not note:
                note = 'ROOT_GUTTER_UNPAINTABLE (material hold)'
        elif root_gutter == 'NATIVE_UNOCCLUDED':
            require(result == 'fail', 'NATIVE_UNOCCLUDED does not qualify root visibility and must fail gate')
            if not note:
                note = 'NATIVE_UNOCCLUDED (native-only visibility does not qualify)'
    elif gate == 'early-closed-root':
        require(early_closed_root in EARLY_CLOSED_ROOT_CHOICES, 'early-closed-root requires an explicit observed branch')
        expected_result = ('pass' if early_closed_root == 'CAPTURED'
                           else 'not-run' if early_closed_root == 'NOT_RUN' else 'fail')
        require(result == expected_result, 'early-closed-root branch/result disagree')
        if early_closed_root == 'NOT_CAPTURED_FAIL_CLOSED':
            require(result == 'fail', 'NOT_CAPTURED_FAIL_CLOSED does not qualify full capture and must fail gate (manager limit)')
            if not note:
                note = 'NOT_CAPTURED_FAIL_CLOSED (manager limit)'
    elif gate in ('root-after', 'root-mask-clip') and result == 'pass':
        existing_rg = next((e for e in reversed(state.entries)
                            if e.get('kind') == 'observation' and e.get('browser') == browser and e.get('gate') == 'root-gutter'), None)
        if existing_rg is not None:
            require(existing_rg.get('root_gutter') == 'RAIL_VISIBLE_USABLE',
                    f'{gate} cannot pass on {browser}: root-gutter branch is {existing_rg.get("root_gutter")} (requires RAIL_VISIBLE_USABLE; native visibility does not qualify)')
    previous = latest(state.entries).get((browser, gate))
    require(previous is None or (result == 'fail' and previous != 'fail'),
            f'{browser}:{gate} is already recorded as {previous}; a result is final and can '
            'only be corrected to fail')
    kwargs = {}
    if root_gutter is not None:
        kwargs['root_gutter'] = root_gutter
    if early_closed_root is not None:
        kwargs['early_closed_root'] = early_closed_root
    return state.append('observation', browser=browser, gate=gate, result=result, note=note,
                        mode=state.session['host']['AppleShowScrollBars'], **kwargs)


def stop(scratch, reason):
    require(NOTE.fullmatch(reason) is not None and reason, 'reason is required and restricted')
    state = Session(scratch)
    state.active()
    return state.append('stop', reason=reason)


def privacy_problems(members, forbidden=(), user=''):
    """Names of members carrying a private path marker, a forbidden string or the user as a
    path segment."""
    tokens = [t.encode() for t in (*PRIVATE_MARKERS, *forbidden) if t]
    segment = re.compile(rb'/' + re.escape(user.encode()) + rb'(?=[/"\s\\]|$)') if user else None
    return sorted(name for name, raw in members.items()
                  if any(t in raw for t in tokens) or (segment and segment.search(raw)))


def summary_of(state):
    result, reasons = verdict(state.session, state.entries)
    coverage, gaps = related_coverage(state.session, state.entries)
    root_gutters = {}
    early_closed_roots = {}
    for entry in state.entries:
        if entry.get('kind') == 'observation':
            if entry.get('gate') == 'root-gutter':
                root_gutters[entry['browser']] = entry.get('root_gutter')
            elif entry.get('gate') == 'early-closed-root':
                early_closed_roots[entry['browser']] = entry.get('early_closed_root')
    summary = {'verdict': result, 'reasons': reasons,
               'related_frames': coverage, 'related_gaps': gaps,
               'root_gutter': root_gutters,
               'early_closed_root': early_closed_roots,
               'latest': {f'{b}:{g}': r for (b, g), r in sorted(latest(state.entries).items())},
               'journal_head': state.entries[-1]['hash'] if state.entries else None}
    if state.session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA:
        summary['verdict_scope'] = 'FRESH_FIREFOX_ONLY'
        summary['provenance_chrome_authority'] = {
            'member': CHROME_AUTHORITY_MEMBER,
            'sha256': CHROME_AUTHORITY_SHA256,
            'disposition': 'MANAGER_ACCEPTED_PRIOR_ATTENDED',
            'combined_qualification': False,
        }
    return summary


def bundle(scratch, forbidden=(), user=''):
    """Write the evidence zip only if no member carries a private path (home always checked)."""
    state = Session(scratch)
    is_firefox_only = (state.session.get('schema') == FIREFOX_ONLY_SESSION_SCHEMA)
    evidence_name = FIREFOX_ONLY_EVIDENCE if is_firefox_only else EVIDENCE
    out = Path(scratch) / 'bundle' / evidence_name
    require(not out.exists(), 'bundle already written')
    summary = summary_of(state)
    members = {'SESSION.json': state.session_path.read_bytes(),
               'journal.jsonl': state.journal_path.read_bytes(),
               'SUMMARY.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode()}
    if is_firefox_only:
        auth_file = Path(scratch) / CHROME_AUTHORITY_SCRATCH_NAME
        try:
            require(auth_file.is_file() and not auth_file.is_symlink(),
                    'authority copy is not a regular file', code='CHROME_AUTHORITY_INVALID')
            authority_raw = auth_file.read_bytes()
        except OSError:
            raise KitError('authority copy is unreadable', code='CHROME_AUTHORITY_INVALID') from None
        if sha256(authority_raw) != CHROME_AUTHORITY_SHA256:
            raise KitError('authority copy CHROME-AUTHORITY.json is missing or tampered',
                           code='CHROME_AUTHORITY_INVALID')
        members[CHROME_AUTHORITY_SCRATCH_NAME] = authority_raw
    leaked = privacy_problems(members, (str(Path.home()), *forbidden), user)
    if leaked:
        raise KitError('PRIVACY_GUARD: refused to bundle members carrying a private path: '
                       + ', '.join(leaked), code='PRIVACY_GUARD')
    members['MEMBERS.sha256'] = ''.join(f'{sha256(raw)}  {name}\n'
                                        for name, raw in sorted(members.items())).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name])
    raw = stream.getvalue()
    out.parent.mkdir(mode=0o700, exist_ok=True)
    out.write_bytes(raw)
    out.with_name(out.name + '.sha256').write_text(f'{sha256(raw)}  {out.name}\n')
    return summary['verdict'], sha256(raw)


POST_EXTENSION_QUALIFICATION_BANNER = (
    b'<div id="post-extension-qualification-banner" '
    b'style="background:#222;color:#fff;padding:4px 8px;font-size:12px;font-family:sans-serif;'
    b'border-bottom:1px solid #444;">POST-EXTENSION QUALIFICATION PAGE</div>'
)


SCENE_MENU_ASSIGNMENT = b"location.search = '?scene=' + encodeURIComponent(menu.value);"


def qualification_url(port, fixture, token, scene=None):
    require(type(port) is int and 1 <= port <= 65535, 'invalid fixture port')
    require(fixture in FIXTURE_NAMES, 'unknown qualification fixture')
    require(isinstance(token, str) and re.fullmatch(r'[0-9a-f]{32}', token), 'invalid qualification token')
    require(scene is None or scene in SCENES[fixture], 'unknown fixture scene')
    query = {'qual': token}
    if scene is not None:
        query['scene'] = scene
    return f'http://127.0.0.1:{port}/{fixture}?' + urllib.parse.urlencode(query)


class RequestLedger:
    """Socket-free current-session request sequence and qualification binding."""
    def __init__(self):
        self.lock = threading.Lock()
        self.qual_token = None
        self.req_seq = 0
        self.requests = []

    def record(self, method, path, qual):
        with self.lock:
            self.req_seq += 1
            self.requests.append({'seq': self.req_seq, 'method': method, 'path': path, 'qual': list(qual)})
            return self.qual_token

    def snapshot_requests(self):
        with self.lock:
            return [dict(r, qual=list(r['qual'])) for r in self.requests]

    def request_barrier(self):
        with self.lock:
            return self.req_seq

    def set_qualification(self, token):
        require(token is None or (isinstance(token, str) and re.fullmatch(r'[0-9a-f]{32}', token)),
                'invalid qualification token')
        with self.lock:
            self.qual_token = token


def fixture_response(ledger, site_dir, method, raw_path):
    """Serve pinned bytes with the qualification banner or token-preserving menu rewrite."""
    require(method in ('GET', 'HEAD'), 'unsupported fixture method')
    parsed = urllib.parse.urlsplit(raw_path)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qual = qs.get('qual', [])
    current_token = ledger.record(method, parsed.path, qual)
    filename = parsed.path.removeprefix('/')
    if filename not in FIXTURE_NAMES:
        return 404, b''
    file_path = Path(site_dir) / filename
    if not file_path.is_file():
        return 404, b''
    content = file_path.read_bytes()
    if current_token is not None and qual == [current_token] and 'frame' not in qs:
        if filename == 'scrollbar-matrix.html':
            idx = content.find(b'<body')
            close_body = content.find(b'>', idx) if idx != -1 else -1
            if close_body != -1:
                content = content[:close_body + 1] + POST_EXTENSION_QUALIFICATION_BANNER + content[close_body + 1:]
        else:
            require(content.count(SCENE_MENU_ASSIGNMENT) == 1, 'pinned Scene menu assignment changed')
            replacement = ("location.search = '?qual=" + current_token
                           + "&scene=' + encodeURIComponent(menu.value);").encode()
            content = content.replace(SCENE_MENU_ASSIGNMENT, replacement, 1)
    return 200, content


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self._handle(send_body=True)

    def do_HEAD(self):
        self._handle(send_body=False)

    def _handle(self, send_body=True):
        status, content = fixture_response(self.server.ledger, self.server.site_dir, self.command, self.path)
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        if send_body:
            self.wfile.write(content)


class _ThreadedFixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, site_dir):
        self.site_dir = Path(site_dir)
        self.ledger = RequestLedger()
        super().__init__(server_address, _FixtureHandler)

    def snapshot_requests(self):
        return self.ledger.snapshot_requests()

    def request_barrier(self):
        return self.ledger.request_barrier()

    def set_qualification(self, token):
        self.ledger.set_qualification(token)


def fixture_server(work, port):
    """Loopback threaded fixture server over the verified site copy."""
    site_dir = Path(work) / 'site'
    return _ThreadedFixtureServer(('127.0.0.1', port), site_dir)


def serve(scratch, port, work=None):
    work = Path(scratch if work is None else work)
    state = Session(scratch)
    state.active()
    verify_scratch(state, work)
    with fixture_server(work, port) as server:
        p = server.server_address[1]
        print(f'serving http://127.0.0.1:{p}/scrollbar-matrix.html, http://127.0.0.1:{p}/scrollbar-toplayer-matrix.html and http://127.0.0.1:{p}/scrollbar-shadow-sentinel-matrix.html')
        print('Bare URLs do not qualify; use the guided observer for post-extension-load qualification.')
        server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['prepare', 'serve', 'launch', 'record', 'stop', 'bundle'])
    parser.add_argument('args', nargs='*')
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--work', type=Path, default=None)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--note', default='')
    parser.add_argument('--reason', default='')
    parser.add_argument('--root-gutter', default=None, choices=ROOT_GUTTER_CHOICES)
    parser.add_argument('--early-closed-root', default=None, choices=EARLY_CLOSED_ROOT_CHOICES)
    parser.add_argument('--firefox-only', action='store_true', default=False)
    args = parser.parse_args(argv)
    host = Host(home=Path.home(), user=os.environ.get('USER', ''))
    try:
        if args.command == 'prepare':
            if args.firefox_only:
                prepare(args.scratch, host, work=args.work, browsers=('firefox',),
                        chrome_authority_sha256=CHROME_AUTHORITY_SHA256)
            else:
                prepare(args.scratch, host, work=args.work)
            print(json.dumps({'status': 'PREPARED'}))
        elif args.command == 'serve':
            serve(args.scratch, args.port, args.work)
        elif args.command == 'launch':
            require(len(args.args) == 1 and args.port > 0, 'usage: launch BROWSER --port PORT')
            launch(args.scratch, args.args[0], host, args.port, args.work)
        elif args.command == 'record':
            require(len(args.args) == 3, 'usage: record BROWSER GATE RESULT [--note TEXT]')
            record(args.scratch, *args.args, note=args.note, root_gutter=args.root_gutter,
                   early_closed_root=args.early_closed_root)
        elif args.command == 'stop':
            stop(args.scratch, args.reason)
        else:
            forbidden = [str(args.work)] if args.work else []
            result, digest = bundle(args.scratch, forbidden, host.user)
            print(json.dumps({'verdict': result, 'sha256': digest}))
    except KitError as error:
        print(f'refused: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
