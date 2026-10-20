"""Guided attended observer for the BUX5C0-R10-REENABLE-FRESHNESS1 kit / R8 product. Test-owned and unpackaged.

The operator runs the sealed kit's wrapper, never raw kit commands:

  zsh ./RUN-SCROLLBAR-GUI.sh --check     read-only readiness report; launches and creates nothing
  zsh ./RUN-SCROLLBAR-GUI.sh --execute   one fresh attended session: Chrome, then Firefox

From a source checkout only:

  python3 tests/scrollbar_gui_observer.py --seal DIR --source-tree TREE --source-inventory-sha256 SHA
                                                    bind the reviewed source in the operator kit

`--check` verifies the kit and R8 source identities, binds the selected Chrome and the attended
installed Firefox read-only (`scrollbar_gui_runtime`), proves neither normal browser is running, reads the
host scroll-bar mode, classifies live managed policy and checks that the evidence and work
destinations are safe. It never writes.

`--execute` repeats the check, requires the operator to accept the live-policy force-install
residual (typed; anything else stops before any session exists), creates one new evidence session
under the operator outbox and one new disposable work root under the temporary directory, serves
the fixtures on loopback, and guides one browser at a time through grouped prompts. Every answer
is journaled (hash-chained, fsynced) before the next prompt; a fail is final and shown at once;
nothing is re-asked. The observer waits for the operator to quit each browser and never signals it.
Every terminal path (pass, fail, not-run, stop, end of input, interrupt, error) closes the server
and writes the privacy-safe evidence bundle and RESULT.json. Old sessions are never resumed or changed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
import tempfile
import threading
import time
import zipfile

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import scrollbar_gui_kit as kit  # noqa: E402
import scrollbar_gui_runtime as runtime  # noqa: E402

KIT_ROOT = Path(__file__).resolve().parents[1]
PHASE = 'DINAS-BROWSER-UX5C0-PREFERENCES1-R10-REENABLE-FRESHNESS1'
R1_ENTRY_TREE = '75bfc971e2b81ca89039fa5dcbb97c089f6b0323'
KIT_ZIP = 'BUX5C0-R13-SCROLLBAR-GUIDED-GUI-KIT.zip'
WRAPPER = 'RUN-SCROLLBAR-GUI.sh'
MANIFEST = 'MANIFEST.json'
MEMBERS_FILE = 'MEMBERS.sha256'
README = 'README-VALIDATION.md'
CHECK_SCHEMA = 'bux5c0-r10-reenable-freshness1-scrollbar-gui-check-v1'
RESULT_SCHEMA = 'bux5c0-r10-reenable-freshness1-scrollbar-gui-result-v1'
MANIFEST_SCHEMA = 'bux5c0-r10-reenable-freshness1-scrollbar-guided-gui-kit-manifest-v1'
OUTBOX = ('Documents', 'agent', 'outbox', 'browser-ux_dinas')  # under the operator's home
SESSION_ROOT = 'BUX5C0-PREFERENCES1-R10-REENABLE-FRESHNESS1-SCROLLBAR-GUI'
WORK_PREFIX = 'bux5c0-r10-reenable-freshness1-scrollbar-'
# Everything the attended run imports or reads; nothing else from the repository.
SOURCE_MEMBERS = (
    'tests/scrollbar_gui_observer.py', 'tests/scrollbar_gui_kit.py', 'tests/scrollbar_gui_runtime.py',
    'tests/browser_preferences.py', 'tests/cnt-native-preflight.py', 'tests/cnt_native_evidence.py',
    'tests/cnt_confinement.py', 'tests/cnt_crash_paths.py',
    'tests/cnt_host_d2.py', 'tests/source_only_snapshot.py',
    *[f'{kit.EXTENSION_DIR}/{name}' for name in sorted(kit.MEMBER_SHA256)],
    kit.FIXTURE, kit.TOPLAYER_FIXTURE, kit.SHADOW_SENTINEL_FIXTURE)

FIREFOX_ONLY_PHASE = 'DINAS-BROWSER-UX5C0-PREFERENCES1-R14-FIREFOX-ONLY1'
FIREFOX_ONLY_KIT_ZIP = 'BUX5C0-R14-FIREFOX-ONLY-GUI-KIT.zip'
FIREFOX_ONLY_WRAPPER = 'RUN-SCROLLBAR-FIREFOX-ONLY.sh'
FIREFOX_ONLY_SESSION_ROOT = 'BUX5C0-PREFERENCES1-R14-FIREFOX-ONLY1-SCROLLBAR-GUI'
FIREFOX_ONLY_WORK_PREFIX = 'bux5c0-r14-firefox-only1-scrollbar-'
FIREFOX_ONLY_MANIFEST_SCHEMA = 'bux5c0-r14-firefox-only1-scrollbar-gui-kit-manifest-v1'


def mode_contract(firefox_only=False):
    """Select the complete contract once, without altering the combined defaults."""
    if firefox_only:
        return {'mode': 'FIREFOX_ONLY', 'phase': FIREFOX_ONLY_PHASE,
                'browsers': ('firefox',), 'sentinels': kit.FIREFOX_SENTINELS,
                'sentinel_contract': kit.FIREFOX_ONLY_SENTINEL_CONTRACT,
                'session_root': FIREFOX_ONLY_SESSION_ROOT, 'work_prefix': FIREFOX_ONLY_WORK_PREFIX,
                'check_schema': 'bux5c0-r14-firefox-only1-scrollbar-gui-check-v1',
                'result_schema': 'bux5c0-r14-firefox-only1-scrollbar-gui-result-v1',
                'manifest_schema': FIREFOX_ONLY_MANIFEST_SCHEMA,
                'evidence': kit.FIREFOX_ONLY_EVIDENCE, 'zip': FIREFOX_ONLY_KIT_ZIP,
                'wrapper': FIREFOX_ONLY_WRAPPER,
                'sources': (*SOURCE_MEMBERS, kit.CHROME_AUTHORITY_MEMBER)}
    return {'mode': 'COMBINED', 'phase': PHASE, 'browsers': kit.BROWSERS, 'sentinels': None,
            'sentinel_contract': kit.SENTINEL_CONTRACT, 'session_root': SESSION_ROOT,
            'work_prefix': WORK_PREFIX, 'check_schema': CHECK_SCHEMA, 'result_schema': RESULT_SCHEMA,
            'manifest_schema': MANIFEST_SCHEMA, 'evidence': kit.EVIDENCE,
            'zip': KIT_ZIP, 'wrapper': WRAPPER, 'sources': SOURCE_MEMBERS}

RESOLVER_CONTRACT = {
    'chrome': 'exactly /run/current-system/Applications/Google Chrome.app, resolved canonically; '
              'must be a link-free /nix/store/<hash>-google-chrome-<version>/Applications/'
              'Google Chrome.app accepted by cnt-native-preflight.chrome_bundle (bundle ID '
              'com.google.Chrome, executable Google Chrome, four-part version); original '
              'signature verified; unchanged across binding; no fallback to /Applications or '
              'Nix Apps; otherwise SELECTED_CHROME_UNAVAILABLE',
    'firefox': 'exactly link-free /Applications/Firefox.app, bundle ID org.mozilla.firefox, '
               'CFBundleExecutable firefox and executable Contents/MacOS/firefox; '
               'selection ATTENDED_INSTALLED_FIREFOX_APP; dynamic numeric version >= manifest gecko '
               'strict_min_version; plist/ini exact equality; bounded string bundle version (do not '
               'derive from BuildID); valid 14-digit calendar BuildID; original codesign and '
               'app-tree digest brackets; exact version, bundle ID, bundle version, BuildID, '
               'app-tree/executable SHA-256 and signature-valid boolean recorded without paths; '
               'read-only bounded macOS ChannelPrefs.framework Mach-O '
               '__TEXT,__cstring must be exactly release NUL in every supported architecture '
               '(ESR/non-release/malformed/unreadable refused; binary not loaded or executed); '
               'otherwise SELECTED_FIREFOX_UNAVAILABLE',
    'host': 'defaults read -g AppleShowScrollBars must read Always; never written by the kit',
}
# Live policy force-installs extensions into the disposable profiles from their normal update
# sources. That residual is accepted per session by the operator, never silently.
FORCE_INSTALL_ACK = 'accept-force-install'
FORCE_INSTALL_DECLINED = 'LIVE_POLICY_FORCE_INSTALL_NOT_ACCEPTED'
ROUTE_BLOCKED = {'chrome': 'CHROME_LOAD_UNPACKED_ROUTE_BLOCKED',
                 'firefox': 'FIREFOX_TEMPORARY_ADDON_ROUTE_BLOCKED'}
NAMES = {'chrome': 'Google Chrome', 'firefox': 'Firefox'}


class Refused(Exception):
    """Refusal before any session exists; the message is printed, nothing is written."""


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


# Grouped prompts ---------------------------------------------------------------------------

CUSTOM_RAIL_RULES = (
    'A 1–2 px border is not a scrollbar. '
    'Native scrollbar visibility alone does not prove the custom top-layer rail. '
    'Gray box borders do not qualify. '
    'Pass requires the custom Canvas/GrayText rail and working drag/track/wheel behavior; '
    'if the custom surface cannot be distinguished, record FAIL. '
    'GrayText/Canvas coloring alone can come from native restoration and does not qualify. '
    'Use the covered top-layer scenes to distinguish the custom rail from restored native bars. '
    'The served Scene menu preserves the qualification token; use it or the generated links to change scenes. '
)
FIRST_TAB_DIAGNOSTICS = (
    'The first matrix page must show POST-EXTENSION QUALIFICATION PAGE. Its scrollbar-width and '
    'bar/gutter readouts are native/computed-style diagnostics, never custom-rail evidence. '
    'A none/0px or approximately 0–2 px readout must be noted and the current qualification page '
    'reloaded before observation; do not ignore it. If the custom surface remains indistinguishable, '
    'record FAIL. Fixture JavaScript cannot inspect the extension closed shadow internals. '
)

GATE_LABELS = {
    'custom-rail-discriminator': 'ordered disabled/re-enabled comparison proves custom rails on c1, '
                                 'c16, c23, root/c5 and covered t3/t7/t8/t5 scenes',
    'extension-loaded': 'the extension is loaded and shows version ' + kit.VERSION,
    'manifest-known-warnings-only': 'only the known manifest warnings are shown',
    'no-severe-layout-changes': 'the extension causes no severe page layout changes, reflow or broken layout',
    'system-colors-usable': 'system-colored scrollbars are visible and usable',
    'no-extension-console-errors': 'no console errors from this extension',
    'keepassxc-not-associated': 'every KeePassXC association prompt was denied or cancelled; '
                                 'no association was accepted',
    'fixed-bottom': 'rail paints above fixed-bottom overlays and stays interactive',
    'visual-pointer-none': 'rail is visible and interactive above visual pointer-events:none covers',
    'root-after': 'custom top-layer rail escapes root::after trailing pseudo-element covers at maximum z-index (t8; requires RAIL_VISIBLE_USABLE)',
    'root-mask-clip': 'custom top-layer rail escapes root mask and clip-path paint-path suppression (t9, t10; requires RAIL_VISIBLE_USABLE)',
    'nested-overlay': 'nested overlay scrollers display correctly positioned interactive rails',
    'pointer-priority': 'multiple simultaneous+overlap descendant and sibling pointer priority respected',
    'outside-click-escape': 'outside click and Escape key dismissal of popovers behaves correctly',
    'drag-track-wheel-budget': 'drag track and wheel dynamics remain smooth within timing budget',
    'modal-popover-recovery': 'rails suspend during page modal popovers and recover cleanly after close',
    'popover-stacks': 'popover stacks maintain correct ordering without rail interference',
    'fullscreen': 'rails suspend during element fullscreen and resume on exit',
    'host-css-attacks': 'rail host styles resist aggressive author CSS !important attacks',
    'lazy-parser-hydration': 'lazy parser hydration and root re-render preserve rail styling',
    'root-gutter': 'explicit per-engine root-gutter rendering branch (passes ONLY on RAIL_VISIBLE_USABLE; NATIVE_UNOCCLUDED and ROOT_GUTTER_UNPAINTABLE fail)',
    'closed-shadow-top-layer': 'all custom rails suspend during closed-shadow top-layer UI and visibly recover after dismissal',
    'public-observation-chatgpt': 'optional public observation (https://chatgpt.com/): test in disposable browser without sign-in, conversation, DOM exports or screenshots (record-only)',
    'handshake': 'sentinel startup handshake between MAIN and ISOLATED worlds completes ({v:1,type:"ready"})',
    'closed-shadow-modal': 'rails suspend during closed-shadow modal dialog and recover cleanly on close',
    'closed-shadow-popover': 'rails suspend during closed-shadow popover and recover cleanly on close',
    'late-shadow': 'late open and closed shadow roots attached after discovery suspend rails when active',
    'dsd-fail-closed': 'declarative shadow DOM parsing APIs latch permanent fail-closed suspension',
    'budget-fail-closed': 'exceeding 256 shadow root budget latches permanent fail-closed suspension',
    'early-closed-root': 'early inline closed shadow root evaluation (passes ONLY on CAPTURED; NOT_CAPTURED_FAIL_CLOSED records manager limit; FAIL rejects)',
    'coverage-throttle-recovery': 'coverage throttle and structural recovery: 600-element batch suspends and recovers after cooldown; >60000-node subtree suspends >=10s until shrink with structural backoff (1s doubling to 30s) and no retry while quiet',
    'detached-root-reattach': 'captured closed popover inside retained closed root: detach then mutate then reattach; suspend while page popover open and recover on close',
    'foreign-realm-attempt': 'record-only foreign-realm shadow root attempt without capture claim',
}

GROUPS = (
    ('load', 'Extension load',
     'Load the extension as shown above. Answer blocked (not f) if the browser no longer offers '
     'the temporary-load route under live policy.',
     ('extension-loaded', 'manifest-known-warnings-only')),
    ('rail-discriminator', 'Custom rail comparison',
     CUSTOM_RAIL_RULES + FIRST_TAB_DIAGNOSTICS +
     'Compare the disabled and re-enabled states on c1 (scrollbar-width:none), c16 (standard none '
     'plus WebKit display:none), c23 (transparent standard and WebKit thumb/track), and root/c5. '
     'Also compare scrollbar-toplayer-matrix.html: t3 fixed-bottom, t7 pointer-events:none cover, '
     't8 root::after cover and t5 nested overlay (overlays, visual-overlay and root-after scenes). '
     'In the re-enabled state the custom rail must '
     'remain visible ABOVE the covers and support drag, track click and wheel. Native bars restored '
     'behind the covers cannot pass. The two reload steps above must each have server evidence.',
     ('custom-rail-discriminator',)),
    ('core-frames', 'Core visibility: root, nested and frame scrollers',
     CUSTOM_RAIL_RULES + FIRST_TAB_DIAGNOSTICS +
     'Scroll the page itself and each box. Each listed scroller must show a visible, usable Browser UX custom rail.',
     ('c5', 'c18', 'c6', 'c7')),
    ('core-author', 'Core visibility: author hiding',
     CUSTOM_RAIL_RULES + FIRST_TAB_DIAGNOSTICS +
     'Each box hides its scrollbar with author CSS; each must still show a visible, usable Browser UX custom rail.',
     ('c1', 'c2', 'c3', 'c4', 'c13', 'c15')),
    ('core-webkit', 'Core visibility: WebKit and combined hiding',
     CUSTOM_RAIL_RULES + FIRST_TAB_DIAGNOSTICS +
     'Each box hides its scrollbar with ::-webkit-scrollbar rules, alone or combined with the '
     'standard properties; each must still show a visible, usable Browser UX custom rail.',
     ('c11', 'c12', 'c16', 'c17', 'c23')),
    ('layout', 'Layout noninterference',
     'c9, c10 and c24 must show NO scrollbar: overflow:hidden stays hidden and non-scrollable, '
     'non-overflowing content stays non-scrollable. The page must not be badly reflowed.',
     ('c9', 'c10', 'c24', 'no-severe-layout-changes')),
    ('related', 'Related frames (coverage only)',
     CUSTOM_RAIL_RULES + 'Does each frame show a visible, usable Browser UX custom rail? A fail here narrows related-frame coverage to '
     'PARTIAL; it never fails the core verdict.',
     ('c8', 'c19', 'c20', 'c21', 'c22')),
    ('color', 'Color and system presentation',
     CUSTOM_RAIL_RULES + 'Custom rails must be visible and distinguishable. On c27 (dark page without color-scheme) a light '
     'track stripe is the accepted trade-off: it is NOT a failure unless rendering is severe or '
     'unusable.',
     ('c26', 'c27', 'system-colors-usable')),
    ('toplayer-occlusion', 'Top-layer occlusion resistance',
     CUSTOM_RAIL_RULES + 'In scrollbar-toplayer-matrix.html, inspect fixed-bottom overlays (t3), visual pointer-events:none '
     'covers (t7), root::after pseudo-elements (t8), root mask and clip-path suppression (t9, t10), '
     'and nested overlay scrollers (t5). All rails must paint above covers and remain interactive. '
     'Distinguish custom Browser UX rail from native: custom rail renders in top layer with Canvas track '
     'and GrayText thumb with square corners; its closed shadow root cannot be inspected by page scripts. '
     'Compare the narrow track with the native rounded macOS thumb using the completed disabled/re-enabled '
     'comparison above. If the custom surface cannot be distinguished, '
     'record FAIL; pointer usability of a native control is insufficient. On root challenge scenes (t8 root-after, '
     't9 root-mask, t10 root-clip), custom rail must escape the ::after cover and root clipping/masking. '
     'Challenge scenes require root-gutter RAIL_VISIBLE_USABLE; native-only visibility does not qualify.',
     ('fixed-bottom', 'visual-pointer-none', 'root-after', 'root-mask-clip', 'nested-overlay')),
    ('interaction-priority', 'Interaction and pointer dynamics',
     'Inspect multiple simultaneous+overlap descendant/sibling pointer priority (t14, t15, t16), '
     'outside click and Escape key dismissal (t21), and drag/track/wheel dynamics within timing budget.',
     ('pointer-priority', 'outside-click-escape', 'drag-track-wheel-budget')),
    ('popover-lifecycle', 'Popover and modal lifecycle',
     'Inspect page-modal-popover before/after suspension recovery (t17, t18, t19), popover stacks (t20), '
     'and element fullscreen suspension/resume (t23). In scene late-shadow wait for rails, '
     'then create/open the modal (t46); every rail must hide and recover on close. Failure is a material hold.',
     ('modal-popover-recovery', 'popover-stacks', 'fullscreen')),
    ('resilience-integrity', 'Host resilience and style integrity',
     'Inspect host resistance to aggressive author CSS !important attacks (t26, t27) '
     'and lazy parser hydration / re-render styling preservation (t41).',
     ('host-css-attacks', 'lazy-parser-hydration')),
    ('eligibility-dynamics', 'Eligibility, layout and bounded dynamics',
     'In scene inert-clipped: t31-t37 must have no usable extension rail. '
     'In scene geometry: t38 fixed escape remains usable, t39 rotation is recorded as a limit. '
     'In scene dynamics: t40 add/remove, grow/shrink and resize must update rails; outside input stays page-owned. '
     'Use the page baseline/compare controls after resetting intentional fixture changes. '
     'In scene focus: focus t44 input, interact with root/nested rails, then type without clicking '
     'a page control; input focus must remain. In scene root-zoom: after rails appear, set zoom '
     'at t45; custom rails must refuse placement while native scroll works. Record this availability limit. '
     'In scene limits: create 61000 nodes, observe responsiveness and bounded degradation; do not infer runtime state from fixture counters.',
     ('eligibility-noninterference', 'dynamics-recovery', 'discovery-limits')),
    ('root-gutter', 'Root gutter rendering evaluation',
     CUSTOM_RAIL_RULES + 'Evaluate root document scroller gutter rendering for this engine. '
     'Root gate passes ONLY on RAIL_VISIBLE_USABLE: custom Browser UX rail visible and interactive above '
     'root gutter (distinguished from native by system Canvas track / GrayText thumb, pointer-capture drag, '
     'track jump, and qualifying t8 root-after and t9/t10 root-mask-clip challenge scenes). '
     'NATIVE_UNOCCLUDED (native scrollbars visible without custom top-layer rail) does NOT qualify and FAILS '
     'the gate (challenge scenes cannot qualify on native visibility; no effective OR pass). '
     'ROOT_GUTTER_UNPAINTABLE fails gate as a material hold. Enter RAIL_VISIBLE_USABLE, NATIVE_UNOCCLUDED, '
     'ROOT_GUTTER_UNPAINTABLE, FAIL, or NOT_RUN.',
     ('root-gutter',)),
    ('sentinel-handshake', 'Shadow sentinel handshake & control',
     CUSTOM_RAIL_RULES + 'In the control scene, verify the custom Browser UX rail appears and supports drag, track click and wheel. '
     'In changing-content, drag continuously for at least five seconds while the counter updates; the rail must stay visible and keep scrolling. '
     'Then open/close the early closed modal and popover and verify disappearance/recovery. '
     'Native visibility alone cannot pass this handshake gate.',
     ('handshake',)),
    ('shadow-lifecycle', 'Closed shadow modal and popover lifecycle',
     'In scrollbar-shadow-sentinel-matrix.html, open/close closed-shadow modal dialog and closed-shadow popover. '
     'Rails must suspend while open and recover visibly upon close. Late shadow roots attached after discovery '
     'must also suspend rails when modal/popover is active.',
     ('closed-shadow-top-layer', 'closed-shadow-modal', 'closed-shadow-popover', 'late-shadow')),
    ('shadow-bounds', 'Shadow budget and declarative fail-closed bounds',
     'Reload the dsd-parser scene and verify rails never appear; reload dsd and trigger the parsing API. Then reload budget and exceed 256 roots. '
     'Both must permanently suspend rails fail-closed.',
     ('dsd-fail-closed', 'budget-fail-closed')),
    ('early-closed-root', 'Early inline closed root evaluation',
     'In early-closed scene, verify custom rails appear before opening the early closed modal/popover, disappear while it is open, and return after closing. The first head script created the root. '
     'Enter CAPTURED (passing, early closed root successfully captured), NOT_CAPTURED_FAIL_CLOSED '
     '(manager limit, uncaptured closed root latches fail-closed suspension), FAIL, or NOT_RUN.',
     ('early-closed-root',)),
    ('coverage-throttle', 'Coverage throttle and structural recovery',
     'In scrollbar-shadow-sentinel-matrix.html scene throttle-recovery: verify that a 600-element '
     'one-batch insertion suspends rails then returns after cooldown without further mutation. '
     'Then verify that a structural >60000-node subtree suspends rails for at least 10s until shrink, '
     'confirming structural backoff (1s doubling to 30s) with no automatic retry while quiet.',
     ('coverage-throttle-recovery',)),
    ('detached-root', 'Detached root reattachment',
     'In scrollbar-shadow-sentinel-matrix.html scene detached-root: verify that a captured closed popover '
     'inside a retained closed root can be detached from the document, mutated, and reattached. Rails must '
     'suspend while the page popover is open and recover visibly on close.',
     ('detached-root-reattach',)),
    ('record-only', 'Record-only cases (never gate)',
     'Record what you see; these document known limits and optional observations and never decide the verdict. '
     'foreign-realm-attempt records foreign-realm shadow root attempt without capture claim.',
     ('c14', 'c25', 'foreign-realm-attempt')),
    ('public-observation', 'Optional public observation',
     'Optional https://chatgpt.com/ in this disposable profile only. No sign-in, conversation capture, '
     'DOM/class/selector export or screenshots. Use not-reproduced when the report cannot be reproduced; '
     'n skips this non-gating observation.', ('public-observation-chatgpt',)),
    ('runtime', 'Extension runtime',
     'Inspect the extension (Chrome: chrome://extensions > the extension > Inspect views; '
     'Firefox: about:debugging > the extension > Inspect) and review any KeePassXC prompts.',
     ('no-extension-console-errors', 'keepassxc-not-associated')),
)
# Identical retained gates; only instructions that name an engine are specialized.
FIREFOX_ONLY_GROUPS = tuple(
    (key, title,
     ('Inspect the temporary extension in about:debugging > the extension > Inspect and review '
      'any KeePassXC prompts.' if key == 'runtime' else
      instruction + ' Firefox ignores ::-webkit-scrollbar; observe the same required compatibility cases.'
      if key == 'core-webkit' else instruction), items)
    for key, title, instruction, items in GROUPS)

ANSWER_HELP = ('Answer: p = every item passes; f = every item fails; f c11,c12 = those fail and '
               'the rest pass; native [ids] = native-only visibility, recorded FAIL; '
               'n = not observed (not-run); q = stop the session.')

GROUP_FIXTURES = {
    'rail-discriminator': ('scrollbar-matrix.html', 'scrollbar-toplayer-matrix.html'),
    'core-frames': ('scrollbar-matrix.html',),
    'core-author': ('scrollbar-matrix.html',),
    'core-webkit': ('scrollbar-matrix.html',),
    'layout': ('scrollbar-matrix.html',),
    'related': ('scrollbar-matrix.html',),
    'color': ('scrollbar-matrix.html',),
    'toplayer-occlusion': ('scrollbar-toplayer-matrix.html',),
    'interaction-priority': ('scrollbar-toplayer-matrix.html',),
    'popover-lifecycle': ('scrollbar-toplayer-matrix.html',),
    'resilience-integrity': ('scrollbar-toplayer-matrix.html',),
    'eligibility-dynamics': ('scrollbar-toplayer-matrix.html',),
    'root-gutter': ('scrollbar-toplayer-matrix.html',),
    'sentinel-handshake': ('scrollbar-shadow-sentinel-matrix.html',),
    'shadow-lifecycle': ('scrollbar-shadow-sentinel-matrix.html',),
    'shadow-bounds': ('scrollbar-shadow-sentinel-matrix.html',),
    'early-closed-root': ('scrollbar-shadow-sentinel-matrix.html',),
    'coverage-throttle': ('scrollbar-shadow-sentinel-matrix.html',),
    'detached-root': ('scrollbar-shadow-sentinel-matrix.html',),
    'record-only': ('scrollbar-matrix.html', 'scrollbar-shadow-sentinel-matrix.html'),
}

GROUP_SCENES = {
    'rail-discriminator': ('overlays', 'visual-overlay', 'root-after'),
    'toplayer-occlusion': ('overlays', 'visual-overlay', 'root-after', 'root-mask', 'root-clip'),
    'interaction-priority': ('multi-routing', 'overlap', 'siblings', 'toplayer-popover'),
    'popover-lifecycle': ('toplayer-dialog', 'pre-modal', 'toplayer-popover', 'pre-popover',
                          'pre-auto', 'fullscreen', 'late-shadow'),
    'resilience-integrity': ('author-attacks', 'hydration'),
    'eligibility-dynamics': ('inert-clipped', 'geometry', 'dynamics', 'focus', 'root-zoom', 'limits'),
    'root-gutter': ('root-after', 'root-mask', 'root-clip'),
    'sentinel-handshake': ('control', 'changing-content', 'early-closed'),
    'shadow-lifecycle': ('closed-modal', 'closed-popover', 'late-shadow'),
    'shadow-bounds': ('dsd', 'dsd-parser', 'budget'),
    'early-closed-root': ('early-closed',),
    'coverage-throttle': ('throttle-recovery',),
    'detached-root': ('detached-root',),
    'record-only': ('detached-root',),
}



def group_urls(port, token, key):
    if not token or key == 'load':
        return []
    urls = []
    fixtures = GROUP_FIXTURES.get(key, ())
    for fix in fixtures:
        urls.append(kit.qualification_url(port, fix, token))
    scenes = GROUP_SCENES.get(key, ())
    if scenes:
        for scene in scenes:
            fix = next((f for f in fixtures if scene in kit.SCENES[f]), None)
            kit.require(fix is not None, f'{key}: scene {scene} lacks its group fixture')
            urls.append(kit.qualification_url(port, fix, token, scene=scene))
    return urls


def print_group_links(scratch, browser, server, key, out=print):
    if key == 'load':
        return []
    presentation = next((e for e in reversed(kit.Session(scratch).entries)
                         if e.get('browser') == browser and e.get('kind') == 'fixtures-presented'), None)
    if presentation is None:
        return []
    token = presentation.get('token')
    if not token:
        return []
    port = server.server_address[1]
    urls = group_urls(port, token, key)
    for url in urls:
        out(url)
    return urls


def binding_link_callable(scratch, browser, server, out=print):
    def print_links(key):
        return print_group_links(scratch, browser, server, key, out)
    return print_links


def case_labels(kit_root=KIT_ROOT):
    html = (Path(kit_root) / kit.FIXTURE).read_text()
    labels = dict(re.findall(r'id="(c\d+)" data-expect="[a-z]+">([^<]*)', html))
    toplayer_file = Path(kit_root) / kit.TOPLAYER_FIXTURE
    if toplayer_file.is_file():
        html2 = toplayer_file.read_text()
        labels.update(re.findall(r'id="(t\d+)"[^>]*>.*?<span class="case-id">[^<]*</span>\s*<strong>([^<]*)</strong>', html2, flags=re.S))
    shadow_file = Path(kit_root) / kit.SHADOW_SENTINEL_FIXTURE
    if shadow_file.is_file():
        html3 = shadow_file.read_text()
        labels.update(re.findall(r'id="([st]\d+)"[^>]*>.*?<span class="case-id">[^<]*</span>\s*<strong>([^<]*)</strong>', html3, flags=re.S))
    return labels


def label(item, labels):
    return GATE_LABELS.get(item) or labels.get(item, item)


def parse_answer(raw, items, allow_blocked):
    """(kind, failing) for p/f/n/q/blocked, or None when the answer is not understood."""
    words = raw.strip().split(None, 1)
    if not words:
        return None
    head, rest = words[0].lower(), (words[1] if len(words) > 1 else '')
    if head == 'p' and 'early-closed-root' in items:
        return None
    if head in ('p', 'n', 'q') and not rest:
        return head, ()
    if head == 'blocked' and allow_blocked and not rest:
        return 'blocked', ()
    if head == 'not-reproduced' and 'public-observation-chatgpt' in items and not rest:
        return 'nr', ()
    if head.upper() in kit.ROOT_GUTTER_CHOICES and 'root-gutter' in items and not rest:
        choice = head.upper()
        if choice == 'RAIL_VISIBLE_USABLE':
            return 'p', ()
        if choice == 'NOT_RUN':
            return 'n', ()
        return 'f', ('root-gutter',)
    if head.upper() in kit.EARLY_CLOSED_ROOT_CHOICES and 'early-closed-root' in items and not rest:
        choice = head.upper()
        if choice == 'CAPTURED':
            return 'p', ()
        if choice == 'NOT_RUN':
            return 'n', ()
        return 'f', ('early-closed-root',)
    if head == 'f' or (head == 'native' and any(x in kit.CUSTOM_RAIL_GATES or
                                             x == 'custom-rail-discriminator' for x in items)):
        failing = tuple(dict.fromkeys(x for x in re.split(r'[\s,]+', rest) if x)) or tuple(items)
        if all(x in items or kit.GATE_ALIASES.get(x) in items for x in failing):
            normalized = tuple(kit.GATE_ALIASES.get(x, x) for x in failing)
            return head, normalized
    return None


def ask_note(ask, out):
    while True:
        note = ask('Optional note (Enter to skip; letters, digits and . , : ; _ ( ) + = # - only): ').strip()
        if kit.NOTE.fullmatch(note):
            return note
        out('That note has a character the kit refuses (no paths); enter it again.')


def failed_so_far(scratch):
    return [k for k, v in kit.latest(kit.Session(scratch).entries).items() if v == 'fail']


def ask_group(scratch, browser, group, labels, ask, out, server=None, link_fn=None):
    """One grouped prompt; every item is journaled before return. Returns the answer kind."""
    key, title, instruction, items = group
    out('')
    out(f'== {NAMES[browser]}: {title}')
    out(instruction)
    if link_fn is not None:
        link_fn(key)
    elif server is not None:
        print_group_links(scratch, browser, server, key, out)
    for item in items:
        out(f'  {item}: {label(item, labels)}')
    while True:
        prompt_str = f'[{browser} {key}] p / f [ids] / n / q'
        if key == 'load':
            prompt_str += ' / blocked'
        elif key == 'root-gutter':
            prompt_str = f'[{browser} {key}] p = RAIL_VISIBLE_USABLE / f = FAIL / n = NOT_RUN / q / branch name'
        elif key == 'early-closed-root':
            prompt_str += ' (or branch: CAPTURED, NOT_CAPTURED_FAIL_CLOSED, FAIL, NOT_RUN)'
        raw = ask(prompt_str + ': ')
        answer = parse_answer(raw, items, key == 'load')
        if answer is None:
            help_text = ANSWER_HELP
            if key == 'load':
                help_text += ' blocked = the temporary-load route is unavailable.'
            elif key == 'root-gutter':
                help_text = 'Answer: p = RAIL_VISIBLE_USABLE; f = FAIL; n = NOT_RUN; q = stop. branch = RAIL_VISIBLE_USABLE (only passing branch), NATIVE_UNOCCLUDED (fails gate), ROOT_GUTTER_UNPAINTABLE (material hold, fails gate), FAIL, NOT_RUN.'
            elif key == 'early-closed-root':
                help_text += ' branch = CAPTURED (only passing branch), NOT_CAPTURED_FAIL_CLOSED (manager limit, fails gate), FAIL, NOT_RUN.'
            out(help_text)
            continue
        kind, failing = answer
        passing = items if kind == 'p' else tuple(x for x in items if x not in failing) if kind in ('f', 'native') else ()
        if (any(x in kit.CUSTOM_RAIL_GATES for x in passing)
                and kit.latest(kit.Session(scratch).entries).get((browser, 'custom-rail-discriminator')) != 'pass'):
            out('Custom-rail comparison did not pass. These items cannot pass; record f, native, n or q.')
            continue
        if kind in ('f', 'native'):
            out('About to record:')
            for item in items:
                out(f'  {item}: {"FAIL" if item in failing else "pass"}')
            if ask('Type yes to record this (a recorded fail is final), anything else to re-enter: ').strip() != 'yes':
                continue
        break
    if kind == 'q':
        kit.Session(scratch).append('stop', reason=f'OPERATOR_STOPPED during {browser} {key}')
        return 'q'
    if kind == 'blocked':
        kit.Session(scratch).append('stop', reason=ROUTE_BLOCKED[browser])
        return 'blocked'
    note = ask_note(ask, out)
    for item in items:
        if item == 'root-gutter':
            upper_raw = raw.strip().upper()
            if upper_raw in kit.ROOT_GUTTER_CHOICES:
                branch = upper_raw
            else:
                branch = 'RAIL_VISIBLE_USABLE' if kind == 'p' else ('NOT_RUN' if kind == 'n' else 'FAIL')
            result = 'pass' if (branch == 'RAIL_VISIBLE_USABLE' and item not in failing) else ('not-run' if kind == 'n' else 'fail')
            gutter_note = note
            if branch == 'ROOT_GUTTER_UNPAINTABLE' and not gutter_note:
                gutter_note = 'ROOT_GUTTER_UNPAINTABLE (material hold)'
            elif branch == 'NATIVE_UNOCCLUDED' and not gutter_note:
                gutter_note = 'NATIVE_UNOCCLUDED (native-only visibility does not qualify)'
            kit.record(scratch, browser, item, result, note=gutter_note, root_gutter=branch)
            if branch in ('NATIVE_UNOCCLUDED', 'ROOT_GUTTER_UNPAINTABLE', 'FAIL'):
                # Root challenge linkage: challenge scenes cannot stand as pass without root RAIL_VISIBLE_USABLE
                for cg in ('root-after', 'root-mask-clip'):
                    if kit.latest(kit.Session(scratch).entries).get((browser, cg)) == 'pass':
                        kit.record(scratch, browser, cg, 'fail',
                                   note=f'disqualified by root-gutter {branch} (native visibility does not qualify)')
        elif item == 'early-closed-root':
            upper_raw = raw.strip().upper()
            if upper_raw in kit.EARLY_CLOSED_ROOT_CHOICES:
                branch = upper_raw
            else:
                branch = 'CAPTURED' if kind == 'p' else ('NOT_RUN' if kind == 'n' else 'FAIL')
            result = 'pass' if (branch == 'CAPTURED' and item not in failing) else ('not-run' if kind == 'n' else 'fail')
            early_note = note
            if branch == 'NOT_CAPTURED_FAIL_CLOSED' and not early_note:
                early_note = 'NOT_CAPTURED_FAIL_CLOSED (manager limit)'
            kit.record(scratch, browser, item, result, note=early_note, early_closed_root=branch)
        else:
            result = 'pass' if kind == 'p' else 'not-run' if kind == 'n' else 'not-reproduced' if kind == 'nr' else (
                'fail' if item in failing else 'pass')
            item_note = note
            if kind == 'native' and item in failing:
                prefix = 'NATIVE_ONLY (native visibility does not qualify)'
                item_note = prefix + ('; ' + note[:200 - len(prefix) - 2] if note else '')
            kit.record(scratch, browser, item, result, note=item_note)
    failures = failed_so_far(scratch)
    gates = set(kit.required_gates(kit.Session(scratch).session))
    core = [f'{b}:{g}' for b, g in sorted(failures) if g in gates]
    other = [f'{b}:{g}' for b, g in sorted(failures) if g not in gates]
    if core:
        out('FAILED so far (final): ' + ', '.join(core))
    if other:
        out('Related or record-only fails (final; never decide the core verdict): ' + ', '.join(other))
    return kind


def prompt_groups(scratch, browser, handle, labels, ask, out, groups=GROUPS, server=None, link_fn=None):
    for group in groups:
        if handle.poll() is not None:
            kit.Session(scratch).append('stop', reason=f'{browser} exited before every group was observed')
            out(f'{NAMES[browser]} exited before every group was observed; the session stops.')
            return False
        if ask_group(scratch, browser, group, labels, ask, out, server=server, link_fn=link_fn) in ('q', 'blocked'):
            return False
    return True


def postload_fixtures(scratch, browser, handle, server, ask, out):
    """Present URLs only after load, and refuse observation without current server evidence."""
    kit.mark_extension_loaded(scratch, browser, server.request_barrier())
    token = kit.present_fixtures(scratch, browser)
    server.set_qualification(token)
    out('Open each URL below in a NEW tab now. Close or ignore every pre-extension fixture tab.')
    port = server.server_address[1]
    for name in kit.FIXTURE_NAMES:
        out(kit.qualification_url(port, name, token))
    out(FIRST_TAB_DIAGNOSTICS)
    out('The served Scene menu preserves qual; use it or the generated links to change scenes.')
    if handle.poll() is not None:
        kit.Session(scratch).append('stop', reason=f'{browser} exited before fixture freshness')
        return False
    requests = await_fixture_freshness(
        scratch, browser, handle, server, ask, out,
        f'[{browser} fixtures] press Enter when all three fresh pages are open (q stops): ', 'fixtures')
    if requests is None:
        return False
    kit.prove_postload(scratch, browser, requests)
    return True


def confirm_reload(ask, out, prompt):
    while True:
        answer = ask(prompt).strip().lower()
        if answer in ('', 'q'):
            return answer != 'q'
        out('Press Enter after completing the instructed action, or q to stop. A visual answer cannot confirm a reload.')


def await_fixture_freshness(scratch, browser, handle, server, ask, out, first_prompt, label):
    """Keep one token and barrier through the first attempt and three bounded retries.

    Inspection never advances the session. The caller uses the returned ledger snapshot
    for the existing terminal proof, including on exhaustion.
    """
    target = kit.pending_fixture_proof(scratch, browser)
    missing = []
    for attempt in range(kit.FRESHNESS_RETRIES + 1):
        if attempt and handle.poll() is not None:
            kit.Session(scratch).append('stop', reason=f'{browser} exited during {label}')
            return None
        prompt = first_prompt if not attempt else (
            f'[{browser} {label} retry {attempt}/{kit.FRESHNESS_RETRIES}] '
            'press Enter after reloading the missing URL(s) (q stops): ')
        if not confirm_reload(ask, out, prompt):
            details = {'missing': missing} if attempt else {}
            kit.Session(scratch).append('stop', reason=f'OPERATOR_STOPPED during {browser} {label}', **details)
            return None
        requests = server.snapshot_requests()
        status = kit.fixture_proof_status(requests, target['names'], target['token'], target['barrier'])
        missing = status['missing']
        if not missing or attempt == kit.FRESHNESS_RETRIES:
            return requests
        kit.note_freshness_retry(scratch, browser, attempt + 1, missing)
        out('Still missing a fresh GET for: ' + ', '.join(missing))
        out('The fixture server did not observe the reload.')
        for name in missing:
            out(kit.qualification_url(server.server_address[1], name, target['token']))
        out('Paste each printed exact URL into that tab and press Return, or perform a hard reload '
            '(Cmd-Shift-R) if needed; then press Enter here again.')


def rail_comparison(scratch, browser, handle, server, ask, out):
    """Interleave operator acknowledgements with server-ordered reloads and post-toggle barriers."""
    out(CUSTOM_RAIL_RULES)
    presentation = next(e for e in reversed(kit.Session(scratch).entries)
                        if e.get('browser') == browser and e['kind'] == 'fixtures-presented')
    token = presentation['token']
    port = server.server_address[1]

    if browser == 'chrome':
        disable_action = 'In chrome://extensions, toggle this temporary extension OFF.'
        enable_action = 'Toggle the same extension ON again in chrome://extensions.'
    else:
        disable_action = ('Disable the temporary add-on in about:addons. If no toggle is offered, use '
                          'about:debugging > this add-on > Remove within this disposable profile.')
        enable_action = ('Re-enable the add-on in about:addons. If removed, use about:debugging > Load '
                         'Temporary Add-on and select the same extension/manifest.json shown above.')

    for step, action, toggle_key, state in (
        ('disabled-reload', disable_action, 'extension-disabled', 'OFF'),
        ('reenabled-reload', enable_action, 'extension-reenabled', 'ON'),
    ):
        if handle.poll() is not None:
            kit.Session(scratch).append('stop', reason=f'{browser} exited during custom rail comparison')
            return False
        out(action + ' Do not reload pages yet.')
        if not confirm_reload(ask, out, f'[{browser} {toggle_key}] press Enter after toggling the extension {state} (do not reload yet; q stops): '):
            kit.Session(scratch).append('stop', reason=f'OPERATOR_STOPPED during {browser} {toggle_key}')
            return False
        if handle.poll() is not None:
            kit.Session(scratch).append('stop', reason=f'{browser} exited during custom rail comparison')
            return False
        kit.begin_rail_step(scratch, browser, step, server.request_barrier())
        names = kit.RAIL_STEPS[step]['fixtures']
        count = 'BOTH' if step == 'disabled-reload' else 'all THREE (including shadow sentinel)'
        out(f'Now reload {count} current qualification fixture tabs IN PLACE using these exact URLs:')
        for name in names:
            out(kit.qualification_url(port, name, token))
        out('Inspect these covered scenes in this state using the Scene menu or exact links:')
        for scene in ('overlays', 'visual-overlay', 'root-after'):
            out(kit.qualification_url(port, 'scrollbar-toplayer-matrix.html', token, scene))
        if step == 'disabled-reload':
            out('Observe c1/c16/c23/root and t3/t7/t8/t5 with the custom rail absent; note the native baseline.')
        else:
            out('Observe c1/c16/c23/root and t3/t7/t8/t5 again: the custom rail must escape covers '
                'and support drag, track click and wheel. Native colors alone do not qualify.')
        requests = await_fixture_freshness(
            scratch, browser, handle, server, ask, out,
            f'[{browser} {step}] press Enter after the required reloads and comparison (q stops): ', step)
        if requests is None:
            return False
        kit.prove_rail_step(scratch, browser, step, requests)
    return True


def guide_browser(scratch, work, browser, host, server, labels, ask, out, groups=GROUPS):
    """One browser, start to closed. True when the session may continue to the next browser."""
    out('')
    out(f'######## {NAMES[browser]} ########')
    kit.print_guide(browser, work, out)
    out('In the file dialog, Cmd-Shift-G accepts the folder path above.')
    server.set_qualification(None)
    handle = kit.begin_launch(scratch, browser, host, server.server_address[1], work)
    interrupted = None
    try:
        link_fn = binding_link_callable(scratch, browser, server, out)
        proceed = prompt_groups(scratch, browser, handle, labels, ask, out, groups[:1], server=server, link_fn=link_fn)
        if proceed and kit.latest(kit.Session(scratch).entries).get((browser, 'extension-loaded')) != 'pass':
            kit.Session(scratch).append('stop', reason=f'EXTENSION_NOT_LOADED {browser}')
            proceed = False
        if proceed:
            proceed = postload_fixtures(scratch, browser, handle, server, ask, out)
        if proceed:
            proceed = rail_comparison(scratch, browser, handle, server, ask, out)
        if proceed:
            proceed = prompt_groups(scratch, browser, handle, labels, ask, out, groups[1:], server=server, link_fn=link_fn)
        out(f'Now quit the disposable {NAMES[browser]} (Cmd-Q). The kit waits and never signals it.')
    except BaseException as error:  # recorded, then re-raised after the browser is closed
        interrupted = error
        reason = {EOFError: 'OBSERVER_INPUT_CLOSED', KeyboardInterrupt: 'OBSERVER_INTERRUPTED'}.get(
            type(error), f'OBSERVER_EXCEPTION {type(error).__name__}')
        if isinstance(error, kit.KitError) and error.code:
            reason = error.code
        if not kit.Session(scratch).stopped:
            kit.Session(scratch).append('stop', reason=f'{reason} while {browser} was open')
        out(f'{reason}: quit the disposable {NAMES[browser]} (Cmd-Q) to finish; the kit never signals it.')
    code = kit.wait_retained(handle, out)
    kit.end_launch(scratch, browser, host, code)
    if interrupted is not None:
        raise interrupted
    while True:
        busy = kit.running(host, kit.session_scope(kit.Session(scratch).session, kit.Session(scratch).entries)[0])
        if not busy:
            break
        try:
            answer = ask(f'Still not proven closed: {busy}. Quit it, then press Enter '
                         '(q stops the session): ')
        except (EOFError, KeyboardInterrupt):
            answer = 'q'
        if answer.strip() == 'q':
            kit.Session(scratch).append('stop', reason=f'BROWSER_STILL_RUNNING after {browser}')
            return False
    return proceed and not kit.Session(scratch).stopped


# Readiness ---------------------------------------------------------------------------------

def dir_state(path, uid):
    """SAFE, ABSENT or a fixed refusal for one destination directory; never follows a link."""
    path = Path(path)
    try:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode):
            return 'NOT_DIRECTORY'
        if path.resolve(strict=True) != path:
            return 'LINKED'
        os.listdir(path)  # a privacy (TCC) denial surfaces here
    except FileNotFoundError:
        return 'ABSENT'
    except OSError:
        return 'UNREADABLE'
    if info.st_uid != uid:
        return 'NOT_OWNED'
    if info.st_mode & 0o022:
        return 'SHARED_WRITABLE'
    return 'SAFE'


def destinations(host, kit_root, outbox, work_parent, uid, firefox_only=False):
    """(outbox_state, work_state). Both must be private, link-free and outside every root the
    kit must not write into (the kit or repository and the live browser roots), and apart from
    each other."""
    forbidden = [Path(kit_root).resolve(), *[Path(p) for p in host.live_roots()]]

    def inside(path):
        return any(path.is_relative_to(root) for root in forbidden)

    outbox, work_parent = Path(outbox), Path(work_parent)
    parent, root = dir_state(outbox, uid), dir_state(outbox / mode_contract(firefox_only)['session_root'], uid)
    outbox_state = 'SAFE' if parent == 'SAFE' and root in ('SAFE', 'ABSENT') else f'{parent}/{root}'
    if outbox_state == 'SAFE' and inside(outbox):
        outbox_state = 'INSIDE_FORBIDDEN_ROOT'
    work_state = dir_state(work_parent, uid)
    if work_state == 'SAFE' and (inside(work_parent) or work_parent.is_relative_to(outbox)
                                 or outbox.is_relative_to(work_parent)):
        work_state = 'INSIDE_FORBIDDEN_ROOT'
    return outbox_state, work_state


def manifest_problems(kit_root, firefox_only=False):
    """Exact sealed-kit membership and digests; returns (problems, manifest_sha256)."""
    contract = mode_contract(firefox_only)
    kit_root = Path(kit_root)
    try:
        raw = (kit_root / MANIFEST).read_bytes()
        manifest = json.loads(raw)
        members = manifest['members']
    except (OSError, ValueError, KeyError, TypeError):
        return ['manifest unreadable'], None
    problems = []
    if (manifest.get('schema') != contract['manifest_schema']
            or manifest.get('mode', 'COMBINED') != contract['mode']):
        raise Refused('KIT_MODE_MISMATCH: use the dedicated sealed wrapper for this kit')
    if set(members) != set(contract['sources']) | {contract['wrapper'], README}:
        problems.append('manifest member set differs')
    if (manifest.get('package_sha256'), manifest.get('fixture_sha256'), manifest.get('toplayer_fixture_sha256'), manifest.get('shadow_sentinel_fixture_sha256'), manifest.get('extension_members'), manifest.get('freshness_contract'), manifest.get('sentinel_contract')) != (
            kit.PACKAGE_SHA256, kit.FIXTURE_SHA256, kit.TOPLAYER_FIXTURE_SHA256, kit.SHADOW_SENTINEL_FIXTURE_SHA256, kit.MEMBER_SHA256, kit.FRESHNESS_CONTRACT, contract['sentinel_contract']):
        problems.append('manifest pins differ from the kit')
    if firefox_only and manifest.get('chrome_authority') != {
            'member': kit.CHROME_AUTHORITY_MEMBER, 'sha256': kit.CHROME_AUTHORITY_SHA256}:
        problems.append('Chrome authority binding differs')
    present = {p.relative_to(kit_root).as_posix() for p in kit_root.rglob('*')
               if p.is_symlink() or not p.is_dir()}
    if present != set(members) | {MANIFEST, MEMBERS_FILE}:
        problems.append('kit directory holds files outside the manifest')
    for name, meta in sorted(members.items()):
        path = kit_root / name
        if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()) != meta.get('sha256'):
            problems.append(f'{name} differs from the manifest')
    try:
        listed = (kit_root / MEMBERS_FILE).read_text()
    except OSError:
        listed = None
    if listed != members_listing({**{n: m['sha256'] for n, m in members.items()}, MANIFEST: sha256(raw)}):
        problems.append('MEMBERS.sha256 differs from the manifest')
    return problems, sha256(raw)


def check(host, kit_root=KIT_ROOT, outbox=None, work_parent=None, uid=None, firefox_only=False):
    """Read-only readiness. Returns (report, bindings); report is privacy-safe."""
    contract = mode_contract(firefox_only)
    uid = os.getuid() if uid is None else uid
    outbox = Path(host.home).joinpath(*OUTBOX) if outbox is None else Path(outbox)
    work_parent = Path(tempfile.gettempdir()).resolve() if work_parent is None else Path(work_parent)
    codes, bindings = [], {}
    report = {'schema': contract['check_schema'], 'phase': contract['phase'], 'r1_entry_tree': R1_ENTRY_TREE}
    if firefox_only:
        report['mode'] = 'FIREFOX_ONLY'
        try:
            kit.chrome_authority_status(kit_root)
            report['chrome_authority'] = 'MANAGER_ACCEPTED_PRIOR_ATTENDED'
        except kit.KitError:
            report['chrome_authority'] = 'CHROME_AUTHORITY_INVALID'
            codes.append('CHROME_AUTHORITY_INVALID')
    try:
        kit.verify_sources(kit_root)
        report['sources'] = 'R8_PINS_MATCH'
    except Exception:  # any reader failure is an identity mismatch, never a pass
        report['sources'] = 'KIT_IDENTITY_MISMATCH'
        codes.append('KIT_IDENTITY_MISMATCH')
    if (Path(kit_root) / MANIFEST).exists():
        problems, digest = manifest_problems(kit_root, firefox_only)
        report['kit'] = 'SEALED_MANIFEST_MATCH' if not problems else 'KIT_IDENTITY_MISMATCH'
        report['kit_manifest_sha256'] = digest
        report['kit_problems'] = problems
        if problems:
            codes.append('KIT_IDENTITY_MISMATCH')
    else:
        report['kit'] = 'UNSEALED_SOURCE_CHECKOUT'
    report['runtimes'] = {}
    for browser in contract['browsers']:
        try:
            bindings[browser] = host.bind(browser)
            report['runtimes'][browser] = bindings[browser][0]
        except runtime.Unavailable as error:
            report['runtimes'][browser] = {'result': error.result, 'code': error.code}
            codes.append(error.result)
    census = runtime.browser_census(host.run)  # one census: states and counts agree
    census = {b: census[b] for b in contract['browsers']}
    states = {browser: entry['state'] for browser, entry in census.items()}
    report['browser_processes'] = states
    report['browser_candidates'] = {browser: {k: v for k, v in entry.items() if k != 'state'}
                                    for browser, entry in census.items()}
    if runtime.RUNNING in states.values():
        codes.append('BROWSER_RUNNING')
    if runtime.UNKNOWN in states.values():
        codes.append('BROWSER_STATE_UNKNOWN')
    report['live_sentinels'] = 'NOT_SAMPLED'
    if all(state == runtime.NOT_RUNNING for state in states.values()):
        try:
            kit.quiescent_sentinel_digests(host, names=contract['sentinels'], sleeper=host.sleep)
        except kit.KitError:
            report['live_sentinels'] = 'LIVE_SENTINEL_NOT_QUIESCENT'
            codes.append('LIVE_SENTINEL_NOT_QUIESCENT')
        else:
            report['live_sentinels'] = 'QUIESCENT'
    mode = kit.scrollbar_mode(host)
    report['host'] = {'AppleShowScrollBars': mode}
    if mode != runtime.SCROLLBAR_ALWAYS:
        codes.append(runtime.HOST_SCROLLBAR_MODE_NOT_ALWAYS)
    try:
        stops, keys, forced = (kit.classify_policy(host, contract['browsers'])
                               if firefox_only else kit.classify_policy(host))
        report['policy'] = {'stops': stops, 'key_names': keys, 'force_installed': forced,
                            'keepassxc_forced': [i for i in kit.KEEPASSXC_IDS if i in forced]}
        if stops:
            codes.append('POLICY_STOP')
    except Exception:
        report['policy'] = 'UNREADABLE'
        codes.append('POLICY_UNREADABLE')
    outbox_state, work_state = destinations(host, kit_root, outbox, work_parent, uid, firefox_only)
    report['destinations'] = {'outbox': outbox_state, 'work_parent': work_state}
    if outbox_state != 'SAFE':
        codes.append('OUTBOX_UNSAFE')
    if work_state != 'SAFE':
        codes.append('WORK_ROOT_UNSAFE')
    report['residuals'] = list(kit.RESIDUALS)
    report['codes'] = sorted(set(codes))
    report['status'] = 'READY' if not codes else 'NOT_READY'
    return report, bindings


def render(report, out):
    title = 'R14 Firefox-only' if report.get('mode') == 'FIREFOX_ONLY' else 'BUX5C0-R10-REENABLE-FRESHNESS1'
    out(f'{title} scrollbar GUI kit readiness ({report["phase"]})')
    out(f'  sources: {report["sources"]}; kit: {report["kit"]}'
        + (f' (manifest {report["kit_manifest_sha256"]})' if report.get('kit_manifest_sha256') else ''))
    for problem in report.get('kit_problems', []):
        out(f'    {problem}')
    for browser, identity in report['runtimes'].items():
        if 'code' in identity:
            out(f'  {browser}: {identity["result"]} ({identity["code"]})')
        else:
            out(f'  {browser}: {identity["bundle_id"] if "bundle_id" in identity else identity["bundle_identifier"]} '
                f'{identity["version"]}, executable {identity["executable_sha256"]}, '
                f'runtime {identity["runtime_sha256"]}'
                + (f', store root {identity["store_root_sha256"]}' if 'store_root_sha256' in identity else '')
                + ', signature valid')
    if report.get('mode') == 'FIREFOX_ONLY':
        out('  chrome: OUT_OF_SCOPE (may remain running)')
        out('  Chrome authority: ' + report['chrome_authority'])
    out('  normal browsers: ' + ', '.join(f'{b} {s}' for b, s in report['browser_processes'].items()))
    out('  live sentinels: ' + report['live_sentinels'])
    for key, text in (('name_collision', 'process-name collisions ignored (not browsers)'),
                      ('unreadable', 'candidates whose command line could not be read')):
        counts = [f'{b} {c[key]}' for b, c in report['browser_candidates'].items() if c[key]]
        if counts:
            out(f'  {text}: ' + ', '.join(counts))
    out(f'  host AppleShowScrollBars: {report["host"]["AppleShowScrollBars"]}')
    policy = report['policy']
    if isinstance(policy, dict):
        out('  live policy: ' + ('; '.join(policy['stops']) or 'no stop')
            + '; force-installed: ' + (', '.join(policy['force_installed']) or 'none'))
    else:
        out(f'  live policy: {policy}')
    out(f'  destinations: outbox {report["destinations"]["outbox"]}, work parent '
        f'{report["destinations"]["work_parent"]}')
    for residual in report['residuals']:
        out(f'  residual: {residual.split(":")[0]}')
    if isinstance(policy, dict) and policy['force_installed']:
        out(f'  --execute asks you to type {FORCE_INSTALL_ACK} before creating any session; '
            'anything else stops with nothing written')
    if runtime.HOST_SCROLLBAR_MODE_NOT_ALWAYS in report['codes']:
        out(runtime.HOST_SCROLLBAR_MODE_NOT_ALWAYS)
        out(runtime.HOST_SCROLLBAR_GUIDANCE)
    out(report['status'] + ('' if report['status'] == 'READY' else ': ' + ', '.join(report['codes'])))


# Execute -----------------------------------------------------------------------------------

def finish(scratch, work, host, manifest_sha256, out, kit_root=KIT_ROOT, firefox_only=False):
    """Bundle, write RESULT.json and print where they are. Paths are printed, never exported."""
    contract = mode_contract(firefox_only)
    firefox_verdict = None
    if firefox_only:
        state = kit.Session(scratch)
        firefox_verdict = kit.verdict(state.session, state.entries)[0]
        try:
            kit.chrome_authority_status(kit_root)
            kit.require(state.session['scope']['chrome_authority_sha256'] == kit.CHROME_AUTHORITY_SHA256,
                        'authority session binding differs')
            copied = Path(scratch) / 'CHROME-AUTHORITY.json'
            kit.require(not copied.is_symlink() and copied.is_file()
                        and sha256(copied.read_bytes()) == kit.CHROME_AUTHORITY_SHA256,
                        'authority evidence copy differs')
        except (kit.KitError, OSError, KeyError):
            kit.Session(scratch).append('stop', reason='CHROME_AUTHORITY_INVALID')
    try:
        verdict, digest = kit.bundle(scratch, (str(work), str(work.parent)), host.user)
    except kit.KitError as error:
        out(f'BUNDLE_REFUSED: {error}. The journal is retained in {scratch}.')
        return 2
    state = kit.Session(scratch)
    summary = kit.summary_of(state)
    result = {'schema': contract['result_schema'], 'phase': contract['phase'], 'session_id': state.session['session_id'],
              'verdict': verdict, 'reasons': summary['reasons'],
              'related_frames': summary['related_frames'], 'related_gaps': summary['related_gaps'],
              'root_gutter': summary.get('root_gutter', {}),
              'early_closed_root': summary.get('early_closed_root', {}),
              'evidence': f"bundle/{contract['evidence']}", 'evidence_sha256': digest,
              'journal_head': summary['journal_head'], 'kit_manifest_sha256': manifest_sha256}
    if firefox_only:
        identity = state.session['runtimes']['firefox']
        launched = any(e.get('kind') == 'launch' and e.get('browser') == 'firefox' for e in state.entries)
        result.update(mode='FIREFOX_ONLY', firefox_verdict=firefox_verdict,
                      chrome={'disposition': 'MANAGER_ACCEPTED_PRIOR_ATTENDED', 'fresh_launch': False,
                              'version': '149.0.7827.201', 'source_session': '20261004T193451Z-ae8e8bf7',
                              'authority_sha256': kit.CHROME_AUTHORITY_SHA256},
                      firefox={'disposition': 'FRESH_ATTENDED' if launched else 'NOT_LAUNCHED',
                               'fresh_launch': launched, **identity})
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    if kit.privacy_problems({'RESULT.json': raw}, (str(Path.home()), str(work)), host.user):
        out('BUNDLE_REFUSED: RESULT.json would carry a private path.')
        return 2
    (Path(scratch) / 'RESULT.json').write_bytes(raw)
    out('')
    out(f'VERDICT: {verdict}; related frames: {summary["related_frames"]}')
    for reason in summary['reasons']:
        out(f'  {reason}')
    out(f'Result: {Path(scratch) / "RESULT.json"}')
    out(f'Evidence: {Path(scratch) / "bundle" / contract["evidence"]}')
    out(f'Evidence SHA-256: {digest}')
    out(f'The disposable work root is left for you to delete after review: {work.parent}')
    return {'PASS': 0, 'FAIL': 4}.get(verdict, 5)


def execute(host, ask, out, kit_root=KIT_ROOT, outbox=None, work_parent=None, uid=None, port=0, firefox_only=False):
    contract = mode_contract(firefox_only)
    report, bindings = check(host, kit_root, outbox, work_parent, uid, firefox_only)
    render(report, out)
    if report['kit'] == 'UNSEALED_SOURCE_CHECKOUT':
        raise Refused('KIT_NOT_SEALED: --execute runs only from a verified sealed kit')
    if report['kit'] != 'SEALED_MANIFEST_MATCH' or report['sources'] != 'R8_PINS_MATCH':
        raise Refused('KIT_IDENTITY_MISMATCH: the sealed kit does not match its manifest or R8 pins')
    if report['status'] != 'READY':
        return 3
    forced = report['policy']['force_installed']
    if forced:
        out('')
        out('LIVE_POLICY_FORCE_INSTALL: live managed policy will install these extensions into the '
            'disposable profiles from their normal update sources: ' + ', '.join(forced))
        out('They also run on the fixture page, so a reflow or console problem may come from them '
            'rather than from the scrollbar extension; say so in the note if you see one.')
        try:
            answer = ask(f'Type {FORCE_INSTALL_ACK} to accept this residual for this session, '
                         'anything else to stop with nothing written: ')
        except (EOFError, KeyboardInterrupt):
            answer = ''
        if answer.strip() != FORCE_INSTALL_ACK:
            raise Refused(f'{FORCE_INSTALL_DECLINED}: no session was created')
    # The acknowledgement can outlive readiness. Prove the baseline again before
    # creating either session or disposable work directories.
    if kit.running(host, contract['browsers']):
        raise Refused('BROWSER_RUNNING: no session was created')
    try:
        baseline = kit.quiescent_sentinel_digests(host, names=contract['sentinels'], sleeper=host.sleep)
    except kit.KitError:
        raise Refused('LIVE_SENTINEL_NOT_QUIESCENT: no session was created') from None
    outbox = Path(host.home).joinpath(*OUTBOX) if outbox is None else Path(outbox)
    work_parent = Path(tempfile.gettempdir()).resolve() if work_parent is None else Path(work_parent)
    if firefox_only:
        try:
            kit.chrome_authority_status(kit_root)
        except (kit.KitError, OSError):
            raise Refused('CHROME_AUTHORITY_INVALID: no session was created') from None
        try:
            rebound = kit.bind_all(host, contract['browsers'])
        except kit.KitError:
            raise Refused('RUNTIME_CHANGED: no session was created') from None
        if rebound != bindings:
            raise Refused('RUNTIME_CHANGED: no session was created')
        bindings = rebound
    root = outbox / contract['session_root']
    if not root.exists():
        root.mkdir(mode=0o700)
    if dir_state(root, os.getuid() if uid is None else uid) != 'SAFE':
        raise Refused('OUTBOX_UNSAFE: the session root is not a private directory')
    scratch = root / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4))
    work = Path(tempfile.mkdtemp(prefix=contract['work_prefix'], dir=work_parent)) / 'work'
    try:
        kit.prepare(scratch, host, kit_root, work=work, bindings=bindings, sentinels=baseline,
                    browsers=contract['browsers'],
                    chrome_authority_sha256=kit.CHROME_AUTHORITY_SHA256 if firefox_only else None)
    except kit.KitError as error:
        raise Refused(f'refused before the session started: {error}') from None
    out('')
    out(f'New session (local only): {scratch}')
    out(f'Disposable work root (local only): {work}')
    state = kit.Session(scratch)
    if state.session['force_installed'] != forced:
        state.append('stop', reason='LIVE_POLICY_CHANGED after the force-install acknowledgement')
        return finish(scratch, work, host, report.get('kit_manifest_sha256'), out, kit_root, firefox_only)
    if forced:
        state.append('acknowledged', residual='LIVE_POLICY_FORCE_INSTALL', force_installed=forced)
    try:
        server = kit.fixture_server(work, port)
    except OSError:
        state.append('stop', reason='FIXTURE_SERVER_UNAVAILABLE')
        return finish(scratch, work, host, report.get('kit_manifest_sha256'), out, kit_root, firefox_only)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    labels = case_labels(kit_root)
    try:
        for browser in contract['browsers']:
            if not guide_browser(scratch, work, browser, host, server, labels, ask, out,
                                 FIREFOX_ONLY_GROUPS if firefox_only else GROUPS):
                break
    except BaseException as error:  # every terminal path still bundles
        if not kit.Session(scratch).stopped:
            reason = {EOFError: 'OBSERVER_INPUT_CLOSED', KeyboardInterrupt: 'OBSERVER_INTERRUPTED'}.get(type(error))
            if reason is None and isinstance(error, kit.KitError):
                reason = 'OBSERVER_REFUSED ' + re.sub(r'[^A-Za-z0-9 .,:;_()+=#-]', '_', str(error))[:160]
            kit.Session(scratch).append('stop', reason=reason or f'OBSERVER_EXCEPTION {type(error).__name__}')
        out(f'Session stopped: {type(error).__name__}: {error}')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return finish(scratch, work, host, report.get('kit_manifest_sha256'), out, kit_root, firefox_only)


# Seal --------------------------------------------------------------------------------------

WRAPPER_TEXT = """#!/bin/zsh
# BUX5C0-R13 retry and quiescence GUI kit / R8 product. Usage: zsh ./RUN-SCROLLBAR-GUI.sh --check | --execute
emulate -L zsh
setopt err_exit no_unset pipe_fail
if (( $# != 1 )) || [[ $1 != --check && $1 != --execute ]]; then
  print -u2 'usage: RUN-SCROLLBAR-GUI.sh --check | --execute'
  exit 2
fi
cd -- "${0:A:h}"
if ! /usr/bin/shasum -a 256 -s -c MEMBERS.sha256; then
  print -u2 'KIT_IDENTITY_MISMATCH: a kit member differs from MEMBERS.sha256'
  exit 2
fi
if ! python3 -I -B -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  print -u2 'python3 3.10 or newer is required'
  exit 2
fi
exec python3 -I -B tests/scrollbar_gui_observer.py "$1"
"""

README_TEXT = f"""# BUX5C0-R13 guided GUI kit / R8 product

Attended qualification kit for the Browser UX scrollbar extension (version {kit.VERSION}, package
SHA-256 `{kit.PACKAGE_SHA256}`). It holds only the
observer, kit and runtime helpers it imports, the seven extension files and the three fixtures.

## Validate

1. Compare the zip SHA-256 with the reviewed value: `shasum -a 256 {KIT_ZIP}`.
2. Extract into a fresh directory: `ditto -x -k {KIT_ZIP} <fresh dir>`.
   Do not add files there; the kit refuses any file outside MANIFEST.json (browsing the
   directory in Finder can add a .DS_Store, so work from the terminal).
3. The wrapper re-checks MEMBERS.sha256 on every run; the observer re-checks MANIFEST.json and
   the R8 extension, package and fixture pins.

## Run

From the extracted directory, with Google Chrome and Firefox quit:

    zsh ./RUN-SCROLLBAR-GUI.sh --check
    zsh ./RUN-SCROLLBAR-GUI.sh --execute

`--check` launches nothing and writes nothing. It must print READY. It counts as running only a
process whose command line starts with the Chrome or Firefox main executable. Long-lived tools
that merely name Chrome in their arguments (Playwright MCP, Chrome DevTools MCP) are reported as
ignored process-name collisions and need not be stopped; a browser window those tools actually
opened is a real browser and must still be closed. The ignored count equals the number of such
tools running, not a fixed value. A browser owned by another logged-in user cannot be read and
keeps the state UNKNOWN (not READY) until that user quits it. If it prints
HOST_SCROLLBAR_MODE_NOT_ALWAYS, follow the printed System Settings or `defaults` instruction
yourself, quit and reopen the browsers, and run `--check` again; the kit never changes it.

After browsers are NOT_RUNNING, readiness samples only the three existing live sentinels
three times over two seconds and prints `live sentinels: QUIESCENT`. Any drift refuses with
LIVE_SENTINEL_NOT_QUIESCENT. Running or unknown browsers skip sampling. Execution repeats this
proof after the force-install acknowledgement and before session creation, stores that exact
baseline, then compares immediately before each launch. LIVE_SENTINEL_CHANGED_BEFORE_LAUNCH
stops before a process is created. The session baseline is never refreshed between browsers;
the journal states whether the prior browser's after-exit comparison passed. A later change
may include a delayed write from the prior disposable browser and needs manager investigation.
After-exit changes still stop strictly, reporting only fixed sentinel names. Diagnostic
`prepare` without a supplied stable map labels its baseline SINGLE_SAMPLE_DIAGNOSTIC;
guided sessions label it QUIESCENT_3_SAMPLES.

`--execute` creates a new session under
`~/Documents/agent/outbox/browser-ux_dinas/{SESSION_ROOT}/` and a disposable
work root under your temporary directory, then guides Chrome and then Firefox. Load the extension
only as instructed (Chrome: Developer mode > Load unpacked; Firefox: about:debugging > Load
Temporary Add-on). Deny or cancel every KeePassXC association prompt. A fail is final. Quit each
browser with Cmd-Q when told; the kit never signals it. At the end it prints the verdict, the
evidence zip path and its SHA-256. Send the evidence zip and RESULT.json for review.

The browser launches only about:blank. Load the extension first and record extension-loaded;
the guide then supplies three new per-session `?qual=` URLs. Open all three in new tabs. The
first suppression matrix must show POST-EXTENSION QUALIFICATION PAGE (fixture text only).
The server must see every current-token fixture GET after extension-loaded before any visual
gate; otherwise a bounded reload loop precedes FIXTURE_NOT_POSTLOAD_FRESH. Earlier session schemas
cannot be resumed for R10 qualification. Use the served Scene menu or generated URLs to navigate
scenes; the Scene menu preserves the qualification token. Current-token non-frame responses differ
from pinned fixture bytes only by the matrix banner or the Scene-menu rewrite; disk files are unchanged.

Follow the separately journaled disabled-reload and reenabled-reload steps in order. Each step
captures its barrier after the operator acknowledges the completed toggle, then requires
new current-token GET evidence strictly after that barrier. Disabled requires matrix and top-layer;
re-enabled requires all three fixtures before any sentinel gate. Reload the existing tabs in place.
The journal enforces EXTENSION_REENABLED -> ALL_FIXTURES_FRESH_POSTREENABLE -> SENTINEL_VISUAL_GATES;
missing freshness after retry exhaustion stops with FIXTURE_NOT_POSTREENABLE_FRESH. Chrome uses chrome://extensions
off/on; Firefox uses about:addons off/on or about:debugging Remove and Load Temporary Add-on
again in the disposable profile. Compare c1/c16/c23/root plus covered t3/t7/t8/t5 scenes;
the re-enabled custom rail must paint above covers and remain usable. Native restoration can
also be GrayText/Canvas, so colors alone never qualify. `native [ids]` records FAIL.

For each freshness proof, there is one initial attempt plus three retries (four confirmations
total). A missing GET prints only the missing fixture basenames and their exact current-token
URLs. The server did not observe that reload: paste the exact URL into that tab and press
Return, or hard reload with Cmd-Shift-R, then press Enter again. Previously observed qualifying
GETs remain valid under the same token and original barrier. No visual gate becomes available
while requests are missing. `q` or exhaustion stops once with an INCOMPLETE session.

{CUSTOM_RAIL_RULES}
{FIRST_TAB_DIAGNOSTICS}

## Limits

Chrome is only the selected nix-darwin generation app; Firefox is only the
attended installed Firefox at `/Applications/Firefox.app`, with its original signature verified
and its exact selected identity recorded in evidence. This is independent of Clear New Tab
production with no CNT recovery claim. No signing, publication, permanent registration,
default-profile use or policy change.
Live managed policy still force-installs its extensions into the disposable profiles from their
normal update sources; `--execute` asks you to type `accept-force-install` for each session, and
anything else stops before a session is created. The wrapper uses the `python3` on your PATH.

The root budget is 256, including live disconnected roots; it is not qualified as sufficient for
shadow-heavy sites. Session-replay tools wrapping attachShadow can disable custom rails for the
document. Uncaptured closed declarative roots, declarative HTML API calls, clonable roots and late
installation (including empty about:blank frames) suspend permanently. Work overloads suspend
during cooldown and recover only after complete coverage. A tree beyond the 60000-element safety
walk stays suspended until a qualifying page addition/removal permits a bounded recheck after
1s doubling to 30s backoff; quiet oversized trees never auto-retry. Continuous large-document
mutations can suspend custom rails until a quiet interval permits complete coverage.

In `changing-content`, drag for at least five seconds during the 100 ms counter updates. Verify
the custom rail stays visible and keeps scrolling, then disappears during early closed-root modal
and popover UI and returns after closing. Record earliest inline closed-root capture separately in
Chrome and Firefox. Source tests do not establish paint, injection order or cross-world delivery.
"""


FIREFOX_ONLY_WRAPPER_TEXT = (WRAPPER_TEXT.replace('BUX5C0-R13 retry and quiescence', 'BUX5C0-R14 Firefox-only')
                             .replace('RUN-SCROLLBAR-GUI.sh', FIREFOX_ONLY_WRAPPER)
                             .replace('scrollbar_gui_observer.py "$1"',
                                      'scrollbar_gui_observer.py --firefox-only "$1"'))

FIREFOX_ONLY_README_TEXT = f"""# R14 Firefox-only attended scrollbar kit

Chrome is carried forward under the embedded manager authority. It may remain running.
This kit starts Firefox only, in a fresh disposable profile; it never loads or prompts for Chrome.
The authority is specific to this campaign and is not a reconstructed R13 PASS journal.

Compare `{FIREFOX_ONLY_KIT_ZIP}` with the reviewed SHA-256, extract into a fresh directory,
and run from that directory with Firefox quit:

    zsh ./RUN-SCROLLBAR-FIREFOX-ONLY.sh --check
    zsh ./RUN-SCROLLBAR-FIREFOX-ONLY.sh --execute

Check launches and writes nothing. It must print READY. The sealed wrapper verifies MEMBERS.sha256;
the observer checks exact membership, product pins, mode and the independent Chrome authority pin.
Firefox RUNNING or UNKNOWN refuses; Chrome state is informational only. Process-name collisions
are ignored only when command-line classification proves they are tools rather than Firefox.

Readiness and execution require three identical samples of Firefox profiles.ini and installs.ini.
Chrome Local State is never sampled. After any force-install acknowledgement, execution rebinds
Firefox and stores its exact current signed release runtime and sentinel baseline before creating
its session under `{FIREFOX_ONLY_SESSION_ROOT}`. Immediately before Firefox starts, exact runtime
and sentinel checks repeat. After Cmd-Q, identity and the two sentinels must still match.

Follow the full neutral about:blank setup, Load Temporary Add-on, initial all-three fixture
freshness, disabled/re-enabled comparison and post-reenable all-three freshness. Each missing
fixture GET receives up to three retries with the same current token and original barrier.
Every inherited visual group, related frame, root-gutter, sentinel, closed-root, throttle and
detach gate remains. Root-gutter accepts p = RAIL_VISIBLE_USABLE, f = FAIL, n = NOT_RUN,
q = stop, or the explicit branch names. Only RAIL_VISIBLE_USABLE passes, after the discriminator.
Early-closed-root requires CAPTURED explicitly. A recorded fail is final; quit Firefox when told.
Deny every KeePassXC association prompt; live managed force-installs remain a session residual.

Combined PASS requires the pinned Chrome manager authority, every required fresh Firefox gate,
complete freshness, normal exit, unchanged Firefox runtime and unchanged Firefox sentinel baseline.
RESULT.json distinguishes Chrome fresh_launch=false from exact fresh Firefox runtime/version.
The evidence SUMMARY verdict is explicitly scoped to Firefox. No actual Firefox qualification
is claimed by this sealed source kit. All CNT, recovery, native, multipart, backup, BUX6,
deployment, permanent registration/signing/publication and live/default-profile mutation holds remain.

Extension package SHA-256: `{kit.PACKAGE_SHA256}`.
Chrome authority SHA-256: `{kit.CHROME_AUTHORITY_SHA256}`.

{CUSTOM_RAIL_RULES}
{FIRST_TAB_DIAGNOSTICS}
"""


def members_listing(digests):
    return ''.join(f'{digest}  {name}\n' for name, digest in sorted(digests.items()))


def seal(repo_root, out_dir, *, source_tree=None, inventory_sha256=None, firefox_only=False):
    """Deterministic operator kit zip plus sha256 sidecar; returns the zip SHA-256."""
    # Closeout owns review acceptance and zero-drift enforcement. Unit tests may
    # seal unbound temporary kits; the publication CLI requires both identities.
    contract = mode_contract(firefox_only)
    binding = None
    if source_tree is not None or inventory_sha256 is not None:
        if (not isinstance(source_tree, str) or not re.fullmatch(r'[0-9a-f]{40}', source_tree)
                or not isinstance(inventory_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', inventory_sha256)):
            raise Refused('source tree and inventory SHA-256 must be supplied together')
        binding = {'tree': source_tree, 'inventory_sha256': inventory_sha256}
    repo_root, out_dir = Path(repo_root), Path(out_dir)
    if not out_dir.is_dir():
        raise Refused('seal output directory must exist')
    target = out_dir / contract['zip']
    if target.exists():
        raise Refused('the sealed kit already exists')
    kit.verify_sources(repo_root)
    if firefox_only:
        kit.chrome_authority_status(repo_root)
    members = {name: (repo_root / name).read_bytes() for name in contract['sources']}
    wrapper = contract['wrapper']
    members[wrapper] = (FIREFOX_ONLY_WRAPPER_TEXT if firefox_only else WRAPPER_TEXT).encode()
    members[README] = (FIREFOX_ONLY_README_TEXT if firefox_only else README_TEXT).encode()
    modes = {name: 0o755 if name == wrapper else 0o644 for name in members}
    manifest = {
        'schema': contract['manifest_schema'], 'phase': contract['phase'], 'r1_entry_tree': R1_ENTRY_TREE,
        'source_binding': binding,
        'members': {name: {'sha256': sha256(raw), 'mode': f'{modes[name]:04o}'}
                    for name, raw in sorted(members.items())},
        'package_sha256': kit.PACKAGE_SHA256, 'fixture_sha256': kit.FIXTURE_SHA256,
        'toplayer_fixture_sha256': kit.TOPLAYER_FIXTURE_SHA256,
        'shadow_sentinel_fixture_sha256': kit.SHADOW_SENTINEL_FIXTURE_SHA256,
        'extension_members': kit.MEMBER_SHA256, 'resolver_contract': RESOLVER_CONTRACT,
        'process_contract': runtime.PROCESS_CONTRACT,
        'freshness_contract': kit.FRESHNESS_CONTRACT,
        'sentinel_contract': contract['sentinel_contract'],
        'operator_command': [f'zsh ./{wrapper} --check', f'zsh ./{wrapper} --execute'],
        'residuals': list(kit.RESIDUALS),
    }
    if firefox_only:
        manifest.update(mode='FIREFOX_ONLY',
                        chrome_authority={'member': kit.CHROME_AUTHORITY_MEMBER,
                                          'sha256': kit.CHROME_AUTHORITY_SHA256})
        manifest['resolver_contract'] = {k: v for k, v in RESOLVER_CONTRACT.items() if k != 'chrome'}
    members[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    modes[MANIFEST] = 0o644
    members[MEMBERS_FILE] = members_listing({n: sha256(r) for n, r in members.items()}).encode()
    modes[MEMBERS_FILE] = 0o644
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=kit.FIXED_DATE)
            info.create_system = 3
            info.external_attr = (0o100000 | modes[name]) << 16
            archive.writestr(info, members[name])
    raw = stream.getvalue()
    target.write_bytes(raw)
    target.with_name(target.name + '.sha256').write_text(f'{sha256(raw)}  {target.name}\n')
    return sha256(raw)


def main(argv=None, host=None, ask=input, out=print):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true')
    action.add_argument('--execute', action='store_true')
    action.add_argument('--seal', type=Path, metavar='DIR')
    parser.add_argument('--firefox-only', action='store_true')
    parser.add_argument('--source-tree')
    parser.add_argument('--source-inventory-sha256')
    args = parser.parse_args(argv)
    if host is None:
        host = kit.Host(home=Path.home(), user=pwd.getpwuid(os.getuid()).pw_name)
    try:
        if args.seal:
            if (KIT_ROOT / MANIFEST).exists():
                raise Refused('seal runs only from a source checkout')
            if not args.source_tree or not args.source_inventory_sha256:
                raise Refused('seal requires the reviewed source tree and inventory SHA-256')
            digest = seal(KIT_ROOT, args.seal, source_tree=args.source_tree,
                          inventory_sha256=args.source_inventory_sha256, firefox_only=args.firefox_only)
            out(f"{digest}  {mode_contract(args.firefox_only)['zip']}")
            return 0
        if args.check:
            report, _ = check(host, firefox_only=args.firefox_only)
            render(report, out)
            return 0 if report['status'] == 'READY' else 3
        return execute(host, ask, out, firefox_only=args.firefox_only)
    except Refused as error:
        out(f'refused: {error}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
