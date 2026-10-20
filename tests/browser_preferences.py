"""Source-only helpers for the BUX5C0 Browser UX operator preference contract.

Deterministic packaging of the scrollbar-visibility extension, a minimal CSS
declaration reader, and a CSS Cascade 5 *specification model* of origin and
importance precedence. The model encodes the spec; it is not browser evidence.
Checks raise explicitly so they survive ``python -O``.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

EXTENSION_DIR = 'extensions/browser-ux-scrollbars'
MEMBERS = ('background.js', 'content.js', 'manifest.json', 'rail-core.js', 'rail-host.css', 'scrollbars.css', 'toplayer-sentinel-main.js')
FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def package_bytes(repo_root):
    """Stored (uncompressed) zip with sorted members, fixed time and mode 0644."""
    source = Path(repo_root) / EXTENSION_DIR
    present = sorted(p.name for p in source.iterdir())
    require(tuple(present) == MEMBERS, f'unexpected extension members: {present}')
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in MEMBERS:
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (source / name).read_bytes())
    return stream.getvalue()


def css_rules(text):
    """Return [(selector, [(property, value, important)])] for flat stylesheets."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    require('@' not in text, 'at-rules are outside the flat stylesheet model')
    rules = []
    for selector, body in re.findall(r'([^{}]+)\{([^{}]*)\}', text):
        declarations = []
        for item in body.split(';'):
            if not item.strip():
                continue
            name, _, value = item.partition(':')
            value = value.strip()
            important = value.endswith('!important')
            value = value.removesuffix('!important').strip()
            declarations.append((name.strip().lower(), value, important))
        rules.append((selector.strip(), declarations))
    require(re.sub(r'([^{}]+)\{([^{}]*)\}', '', text).strip() == '', 'unparsed CSS remains')
    return rules


# CSS Cascade 5, "Cascade Sorting Order": origin and importance precede
# context, element-attached (inline) styles, layers, specificity and order.
_ORIGIN_RANK = {
    ('user-agent', False): 1, ('user', False): 2, ('author', False): 3,
    ('animation', False): 4, ('author', True): 5, ('user', True): 6,
    ('user-agent', True): 7, ('transition', True): 8,
}


def _key(declaration):
    origin, important = declaration['origin'], declaration['important']
    inline = 1 if declaration.get('inline') else 0
    layer = declaration.get('layer')  # None is the implicit final (unlayered) layer
    # Normal: unlayered beats layers, later layers beat earlier ones.
    # Important: the order is reversed, so earlier layers beat later ones and
    # every layered important declaration beats an unlayered one.
    layer_rank = (0 if layer is None else 10_000 - layer) if important else \
        (10_000 if layer is None else layer)
    return (_ORIGIN_RANK[(origin, important)], inline, layer_rank,
            declaration.get('specificity', (0, 0, 0)), declaration.get('order', 0))


def winner(*declarations):
    return max(declarations, key=_key)


# Scrollbar case matrix -------------------------------------------------------------------
#
# One row per GUI fixture case (tests/fixtures/browser-preferences/scrollbar-matrix.html).
# This is a specification/cascade model only. It resolves the computed standard scrollbar
# properties and whether the non-standard ::-webkit-scrollbar path would apply under the
# documented rule (MDN; Blink ComputedStyle::UsesStandardScrollbarStyle): pseudo rules are
# ignored when computed scrollbar-width or scrollbar-color is not auto. It does not emulate
# rendering, overlay scrollbars, layout or frame injection timing. The attended GUI kit is
# the only browser evidence.

def _author(prop, value, important=False, layer=None, inline=False, order=9):
    return {'property': prop, 'value': value, 'origin': 'author', 'important': important,
            'layer': layer, 'inline': inline, 'specificity': (1, 1, 0), 'order': order}


_NONE = _author('scrollbar-width', 'none')
_ROOT_HIDE = (_author('scrollbar-width', 'none'),
              _author('scrollbar-color', 'transparent transparent'))
_WK_HIDE = ('display:none',)
_WK_TRANSPARENT = ('scrollbar:transparent', 'thumb:transparent', 'track:transparent')

# expect: visible / absent / record as in the fixture; related = visible is claimed for an
# about:/data:/blob:/sandboxed frame whose injection path is upstream-unverified in at least
# one browser, so the attended verdict judges it separately from the core cases.
# frame: how the extension reaches the document. 'http' = content-script match;
# 'about' = about:blank/about:srcdoc via match_about_blank; 'opaque' = sandboxed srcdoc or
# data: (match_origin_as_fallback); 'blob' = blob: (match_origin_as_fallback in Firefox 128+).
SCROLLBAR_CASES = (
    dict(id='c1', frame='http', overflow='auto', overflows=True, author=(_NONE,), expect='visible'),
    dict(id='c2', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-width', 'none', important=True),), expect='visible'),
    dict(id='c3', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-width', 'none', important=True, layer=0),), expect='visible'),
    dict(id='c4', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-width', 'none', important=True, inline=True),), expect='visible'),
    dict(id='c5', frame='http', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='visible'),
    dict(id='c6', frame='http', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='visible'),
    dict(id='c7', frame='http', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='visible'),
    dict(id='c8', frame='about', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='related'),
    dict(id='c9', frame='http', overflow='hidden', overflows=True, expect='absent'),
    dict(id='c10', frame='http', overflow='auto', overflows=False, expect='absent'),
    dict(id='c11', frame='http', overflow='auto', overflows=True, webkit=_WK_HIDE, expect='visible'),
    dict(id='c12', frame='http', overflow='auto', overflows=True,
         webkit=('width:0', 'height:0'), expect='visible'),
    dict(id='c13', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-color', 'transparent transparent'),), expect='visible'),
    dict(id='c14', frame='http', overflow='auto', overflows=True, author=(_NONE,),
         expect='record', note='shadow tree: user-origin reach is observed, not asserted'),
    dict(id='c15', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-width', 'thin'),), expect='visible'),
    dict(id='c16', frame='http', overflow='auto', overflows=True, author=(_NONE,),
         webkit=_WK_HIDE, expect='visible'),
    dict(id='c17', frame='http', overflow='auto', overflows=True, webkit=_WK_TRANSPARENT,
         expect='visible'),
    dict(id='c18', frame='http', overflow='auto', overflows=True, author=(_NONE,),
         webkit=_WK_HIDE, expect='visible', note='inner box of a nested pair'),
    dict(id='c19', frame='about', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='related'),
    dict(id='c20', frame='opaque', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='related'),
    dict(id='c21', frame='opaque', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='related'),
    dict(id='c22', frame='blob', overflow='root', overflows=True, author=_ROOT_HIDE,
         webkit=_WK_HIDE, expect='related'),
    dict(id='c23', frame='http', overflow='auto', overflows=True,
         author=(_author('scrollbar-color', 'transparent transparent'),),
         webkit=_WK_TRANSPARENT[1:], expect='visible'),
    dict(id='c24', frame='http', overflow='visible', overflows=True, expect='absent'),
    dict(id='c25', frame='http', overflow='auto', overflows=True, expect='record',
         note='bar clipped by an overflow:hidden ancestor; geometric hiding is out of scope'),
    dict(id='c26', frame='http', overflow='auto', overflows=True,
         author=(_author('color-scheme', 'dark'),), expect='visible'),
    dict(id='c27', frame='http', overflow='auto', overflows=True, expect='visible',
         note='dark author background without color-scheme: Canvas track stays light'),
)

_INITIAL = {'scrollbar-width': 'auto', 'scrollbar-color': 'auto'}
_WK_HIDING = {'display:none', 'width:0', 'height:0', 'scrollbar:transparent',
              'thumb:transparent', 'track:transparent'}


def sheet_declarations(rules, origin):
    """Universal-selector declarations of the extension sheet as cascade inputs."""
    out = []
    for selector, declarations in rules:
        require(selector == '*', f'unexpected selector {selector!r}')
        for prop, value, important in declarations:
            out.append({'property': prop, 'value': value, 'origin': origin,
                        'important': important, 'specificity': (0, 0, 0), 'order': 0})
    return out


def frame_reached(case, manifest):
    """Whether the manifest's content-script contract claims this case's document."""
    script = manifest['content_scripts'][0]
    if case['frame'] == 'http':
        return True
    if case['frame'] == 'about':
        return bool(script.get('match_about_blank') or script.get('match_origin_as_fallback'))
    return bool(script.get('match_origin_as_fallback'))


def declared_state(case, sheet):
    """Spec/cascade resolution for one case; ``sheet`` is a list of cascade inputs."""
    computed = {}
    for prop, initial in _INITIAL.items():
        candidates = [{'property': prop, 'value': initial, 'origin': 'user-agent',
                       'important': False}]
        candidates += [d for d in case.get('author', ()) if d['property'] == prop]
        candidates += [d for d in sheet if d['property'] == prop]
        computed[prop] = winner(*candidates)['value']
    scrollbars = case['overflow'] in ('auto', 'scroll', 'root') and case['overflows']
    standard = computed['scrollbar-width'] != 'auto' or computed['scrollbar-color'] != 'auto'
    webkit_active = bool(case.get('webkit')) and not standard
    color = computed['scrollbar-color']
    hidden = (computed['scrollbar-width'] == 'none'
              or (color != 'auto' and set(color.split()) == {'transparent'})
              or (webkit_active and bool(_WK_HIDING.intersection(case['webkit']))))
    return {'scroll_container': scrollbars, 'width': computed['scrollbar-width'],
            'color': color, 'webkit_path': webkit_active,
            'outcome': ('visible' if not hidden else 'hidden') if scrollbars else 'absent'}


# Extension checker -----------------------------------------------------------------------

SYSTEM_COLORS = {'accentcolor', 'accentcolortext', 'activetext', 'buttonborder', 'buttonface',
                 'buttontext', 'canvas', 'canvastext', 'field', 'fieldtext', 'graytext',
                 'highlight', 'highlighttext', 'linktext', 'mark', 'marktext',
                 'selecteditem', 'selecteditemtext', 'visitedtext'}
FORBIDDEN_SHEET_TOKENS = ('overflow', 'display', 'height', 'gutter', 'webkit', 'position',
                          'contain', 'clip', 'visibility', 'opacity', '@')
EXPECTED_SCRIPT_KEYS = {'world', 'matches', 'js', 'run_at', 'all_frames', 'match_about_blank',
                        'match_origin_as_fallback'}
WEB_PATTERNS = ['http://*/*', 'https://*/*']


def check_sheet(text):
    violations = []
    stripped = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    for token in FORBIDDEN_SHEET_TOKENS:
        if token in stripped.replace('scrollbar-width', '').replace('scrollbar-color', ''):
            violations.append(f'sheet: forbidden token {token!r}')
    try:
        rules = css_rules(text)
    except AssertionError as error:
        return violations + [f'sheet: {error}']
    declared = {prop: (value, important) for _, decls in rules for prop, value, important in decls}
    if [sel for sel, _ in rules] != ['*'] or len(rules[0][1]) != 2 or \
            set(declared) != {'scrollbar-width', 'scrollbar-color'}:
        violations.append(f'sheet: must be exactly * {{scrollbar-width; scrollbar-color}}: {rules}')
    if declared.get('scrollbar-width') != ('auto', True):
        violations.append('sheet: scrollbar-width must be auto !important (normal platform width)')
    color, important = declared.get('scrollbar-color', ('', False))
    parts = color.lower().split()
    if not important:
        violations.append('sheet: scrollbar-color must be !important')
    if len(parts) != 2 or not set(parts) <= SYSTEM_COLORS or parts[0] == parts[1]:
        violations.append(f'sheet: scrollbar-color must be two distinct system colors: {color!r}')
    return violations


def check_manifest(manifest):
    violations = []
    scripts = manifest.get('content_scripts') or []
    if len(scripts) != 2:
        violations.append('manifest: exactly MAIN and ISOLATED entries required')
    for index, (world, files) in enumerate((('MAIN', ['toplayer-sentinel-main.js']), ('ISOLATED', ['rail-core.js', 'content.js']))):
        script = scripts[index] if index < len(scripts) else {}
        if set(script) != EXPECTED_SCRIPT_KEYS:
            violations.append(f'manifest: content script keys {sorted(script)}')
        for key in ('all_frames', 'match_about_blank', 'match_origin_as_fallback'):
            if script.get(key) is not True:
                violations.append(f'manifest: content script {key} must be true')
        if script.get('run_at') != 'document_start' or script.get('js') != files or script.get('world') != world:
            violations.append('manifest: explicit worlds must load at document_start')
        if script.get('matches') != WEB_PATTERNS:
            violations.append('manifest: matches must be exactly http/https')
    if manifest.get('version') != '0.4.0':
        violations.append('manifest: R6 runtime version must be 0.4.0')
    if manifest.get('host_permissions') != WEB_PATTERNS:
        violations.append('manifest: host_permissions must be exactly http/https')
    if manifest.get('permissions') != ['scripting']:
        violations.append('manifest: permissions must be exactly scripting')
    if manifest.get('background') != {'service_worker': 'background.js',
                                      'scripts': ['background.js']}:
        violations.append('manifest: background must declare both service_worker and scripts')
    gecko = manifest.get('browser_specific_settings', {}).get('gecko', {})
    if gecko.get('id') != 'scrollbar-visibility@browser-ux':
        violations.append('manifest: gecko id changed')
    if manifest.get('minimum_chrome_version') != '121' or gecko.get('strict_min_version') != '140.0':
        violations.append('manifest: browser floors must stay Chrome 121 / Firefox 140.0')
    if 'key' in manifest or 'update_url' in manifest:
        violations.append('manifest: no key or update_url in source')
    return violations


def check_background(text):
    violations = []
    if not re.search(r'origin:\s*"USER"', text) or 'AUTHOR' in text:
        violations.append('background: insertCSS must use origin "USER"')
    if 'frameIds: [frameId]' not in text or 'files: ["scrollbars.css", "rail-host.css"]' not in text:
        violations.append('background: both USER sheets must target only the sender frame')
    if 'sender.id !== chrome.runtime.id' not in text:
        violations.append('background: sender.id guard missing')
    if 'sendResponse' not in text or not re.search(r'return\s+true\s*;', text):
        violations.append('background: confirmed asynchronous response gate missing')
    return violations


HOST = 'browser-ux-scrollbar-shell'
# Independent policy oracle: removing any pin must make the source checker fail.
HOST_OPEN_PINS = {
    'display': 'block', 'position': 'fixed', 'margin': '0', 'padding': '0',
    'border': '0', 'background': 'transparent', 'visibility': 'visible',
    'opacity': '1', 'pointer-events': 'none', 'transform': 'none',
    'translate': 'none', 'rotate': 'none', 'scale': 'none',
    'filter': 'none', 'backdrop-filter': 'none', 'mask': 'none', 'mask-image': 'none',
    'clip': 'auto', 'clip-path': 'none', 'contain': 'none',
    'content-visibility': 'visible', 'mix-blend-mode': 'normal', 'isolation': 'auto',
    'zoom': '1', 'transition': 'none', 'transition-property': 'none',
    'animation': 'none', 'animation-name': 'none', 'direction': 'ltr',
    'writing-mode': 'horizontal-tb', 'box-sizing': 'border-box',
}


def check_host_sheet(text):
    try:
        rules = css_rules(text)
    except AssertionError as error:
        return [f'host: {error}']
    violations = []
    allowed = {HOST, HOST + ':not(:popover-open)', HOST + ':popover-open',
               HOST + '::before', HOST + '::after', HOST + '::backdrop'}
    values = {}
    for selector, decls in rules:
        if selector not in allowed:
            violations.append(f'host: unscoped selector {selector}')
        target = values.setdefault(selector, {})
        for prop, value, important in decls:
            if not important:
                violations.append(f'host: {selector} {prop} lacks USER importance')
            target[prop] = value
            if prop == 'display' and selector in (HOST, HOST + ':not(:popover-open)') and value != 'none':
                violations.append('host: base display defeats hidden popover state')
            if any(token in value.lower() for token in ('url(', 'var(', '@', '#')):
                violations.append(f'host: non-neutral value {prop}')
    opened = values.get(HOST + ':popover-open', {})
    for prop, expected in HOST_OPEN_PINS.items():
        if opened.get(prop) != expected:
            violations.append(f'host: open {prop} must be {expected}')
    if values.get(HOST + ':not(:popover-open)', {}).get('display') != 'none':
        violations.append('host: explicit hidden selector required')
    if values.get(HOST, {}).get('all') != 'initial':
        violations.append('host: inherited presentation reset required')
    if opened.get('width') != '100vw' or opened.get('height') != '100vh' or \
            opened.get('inset') not in ('0', '0 auto auto 0'):
        violations.append('host: viewport geometry required')
    for pseudo in ('::before', '::after'):
        if values.get(HOST + pseudo, {}).get('content') != 'none' or \
                values.get(HOST + pseudo, {}).get('display') != 'none':
            violations.append(f'host: generated {pseudo} must be suppressed')
    backdrop = values.get(HOST + '::backdrop', {})
    for prop, value in {'display': 'none', 'background': 'transparent',
                        'pointer-events': 'none', 'filter': 'none', 'backdrop-filter': 'none'}.items():
        if backdrop.get(prop) != value:
            violations.append(f'host: backdrop {prop} must be {value}')
    return violations


def check_extension(directory):
    """Pure structural checker for an extension directory; returns violation strings."""
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    sheet_text = (directory / 'scrollbars.css').read_text()
    violations = (check_manifest(manifest) + check_sheet(sheet_text)
                  + check_host_sheet((directory / 'rail-host.css').read_text())
                  + check_background((directory / 'background.js').read_text()))
    if violations:
        return violations
    origin = 'user' if 'origin: "USER"' in (directory / 'background.js').read_text() else 'author'
    sheet = sheet_declarations(css_rules(sheet_text), origin)
    for case in SCROLLBAR_CASES:
        state = declared_state(case, sheet)
        if case['expect'] in ('visible', 'related'):
            if not frame_reached(case, manifest):
                violations.append(f"{case['id']}: frame kind {case['frame']} not claimed")
            if state['outcome'] != 'visible' or state['webkit_path'] or state['width'] != 'auto':
                violations.append(f"{case['id']}: expected visible, model gives {state}")
        elif case['expect'] == 'absent' and state['outcome'] != 'absent':
            violations.append(f"{case['id']}: expected absent, model gives {state}")
    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['package'])
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw = package_bytes(args.repo_root)
    with args.out.open('xb') as stream:
        stream.write(raw)
    manifest = json.loads((args.repo_root / EXTENSION_DIR / 'manifest.json').read_text())
    print(json.dumps({'status': 'PACKAGED', 'sha256': hashlib.sha256(raw).hexdigest(),
                      'bytes': len(raw), 'version': manifest['version']}))


if __name__ == '__main__':
    main()
