// R6 Firefox matrix page helper. Runs in the settings page realm (Marionette mutable sandbox,
// as the accepted R1 adapter). Host-boundary adapters only:
//  - URL.createObjectURL is delegated; HTMLAnchorElement.click captures the native download
//    Blob and filename instead of the OS save (accepted R1 adapter);
//  - globalThis.show_err_ribbon is delegated unchanged; only the native error code token and
//    its silent flag are recorded, so an auto-hidden ribbon is not missed (R6 observation adapter).
// A read-only identity read (REPAIR2): mark_target reads the item's React host-fiber expando to
// learn which background its own click handler passes (ui.background_identity).
// It never reads or writes extension storage and never replaces a native handler's behaviour.
// arguments[0] is the provenance selector map; only section_content transitions count as
// restore-start evidence (the native deletion runs in that element's transition-end callback).
if (window.__buxMatrix) return 'PRESENT';
const selectors = arguments[0];
if (!selectors || typeof selectors.section !== 'string') return 'REFUSED';
const blobs = new Map();
const captured = [];
const reports = [];
const originalURL = URL.createObjectURL;
URL.createObjectURL = function (object) {
  const url = originalURL.call(URL, object);
  if (object instanceof Blob) blobs.set(url, object);
  return url;
};
const originalClick = HTMLAnchorElement.prototype.click;
HTMLAnchorElement.prototype.click = function () {
  const blob = blobs.get(this.href);
  if (blob && blob.type === 'application/octet-stream' && this.download) {
    captured.push({name: String(this.download), blob});
    return undefined;
  }
  return originalClick.call(this);
};
const originalReport = window.show_err_ribbon;
if (typeof originalReport === 'function') {
  window.show_err_ribbon = function (error, code, options) {
    reports.push({code: /^[a-z]{2,4}_[0-9]{1,5}$/.test(String(code)) ? String(code) : 'OTHER',
                  silent: !!(options && options.silent)});
    return originalReport.apply(this, arguments);
  };
}
let transitions = 0;
let sectionTransitions = 0;
document.addEventListener('transitionend', event => {
  transitions += 1;
  if (event.target instanceof Element && event.target.matches(selectors.section)) sectionTransitions += 1;
}, true);
const shown = element => {
  if (!element || element.classList.contains('none')) return false;
  const style = getComputedStyle(element);
  return style.display !== 'none' && style.visibility !== 'hidden';
};
const shadow = (selector, inner) => {
  const root = document.querySelector(selector);
  return root && root.shadowRoot ? root.shadowRoot.querySelector(inner) : null;
};
// Read-only seed observations. Values leave as bounded scalars; the harness classifies them
// against an allowlist before anything is recorded. Nothing below writes page state.
const visible = element => !!element && element.getClientRects().length > 0
  && !element.closest('.none, .opacity_0, .hidden') && getComputedStyle(element).visibility !== 'hidden';
const enabled = element => !element.closest('.is_disabled:not(.input_item.group)');
const scalar = value => value === undefined || value === null ? null
  : typeof value === 'boolean' || typeof value === 'number' ? value
  : typeof value === 'string' ? value.slice(0, 64) : {type: typeof value};
const control = name => {
  const element = document.querySelector(`select[name="${name}"], input[name="${name}"]`);
  if (!element) return {present: false};
  const box = element.type === 'checkbox';
  const wrapper = element.closest('.input_w');
  return {present: true, dom: box ? element.checked : scalar(element.value),
          length: box ? 0 : String(element.value).length,
          shown: visible(box ? wrapper : element), enabled: enabled(element),
          warn: !!wrapper && wrapper.classList.contains('is_in_warn_state'),
          pref: scalar(data.settings.prefs[name]), ui: scalar(data.ui[name])};
};
// The task background id seen before a scheduler background click. Held in the helper only;
// ids never leave the page, only whether the current id differs (ui.task_background_id).
let backgroundMark = {set: false, id: undefined};
// The intended task target (ui.background_identity): the id of the background the item's own
// click handler passes, read from React's host-fiber expando on the item. Read-only: it follows
// `return` links (at most 16) to the nearest fiber whose props hold a background object and
// reads that object's id, an observable getter; the helper calls no function and writes nothing.
// A stale (alternate) fiber belongs to the same item, keyed by its id. The id stays here; only
// booleans leave the page.
let targetMark = {set: false, id: undefined};
const button = selector => {
  const element = document.querySelector(selector);
  return {present: !!element, shown: visible(element), enabled: !!element && enabled(element)};
};
window.__buxMatrix = {
  state(s) {
    const section = document.querySelector(s.section);
    return {
      ready: !!document.querySelector(s.ready) && !document.querySelector(s.hidden_roots)
        && !shown(shadow(s.loading_root, '.loading_screen')),
      protecting: [...document.querySelectorAll(s.protecting)].some(shown),
      error_visible: shown(shadow(s.error_root, '.main')),
      reports: reports.length,
      loud_reports: reports.filter(r => !r.silent).length,
      backgrounds: document.querySelectorAll(s.background).length,
      tasks: document.querySelectorAll(s.task).length,
      section_visible: !!section && section.classList.contains('opacity_1'),
      transitions,
      section_transitions: sectionTransitions,
      captured: captured.length,
      report_recorder: typeof originalReport === 'function',
    };
  },
  reports(from) { return reports.slice(from); },
  captured() {
    return captured.map((c, index) => ({index, name: c.name, size: c.blob.size}));
  },
  clear() { captured.length = 0; return 0; },
  async slice(index, start, end) {
    const bytes = new Uint8Array(await captured[index].blob.slice(start, end).arrayBuffer());
    let text = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(text);
  },
  async sha256(index) {
    const hash = await crypto.subtle.digest('SHA-256', await captured[index].blob.arrayBuffer());
    return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
  },
  pref(name) {
    const value = data.settings.prefs[name];
    return value === undefined ? {present: false} : {present: true, value: JSON.parse(JSON.stringify(value))};
  },
  context() {
    // In-page UI state only (data.ui), never storage: which settings context is active.
    const value = data.ui.settings_context;
    return value === 'global' || value === 'selected_background' ? value : 'OTHER';
  },
  code(index, value) {
    // Native CodeMirror API, as the accepted R1 adapter; the native debounce saves it.
    const editors = [...document.querySelectorAll('.CodeMirror')];
    if (!editors[index] || !editors[index].CodeMirror) return -1;
    editors[index].CodeMirror.setValue(value);
    return editors.length;
  },
  editors(expected) {
    // Booleans and lengths only; editor contents never leave the page.
    const nodes = [...document.querySelectorAll('.CodeMirror')];
    return {open: visible(document.querySelector(selectors.code_editor)), count: nodes.length,
            items: nodes.slice(0, 3).map((node, i) => {
              const value = node.CodeMirror ? node.CodeMirror.getValue() : null;
              return {ready: value !== null, length: value === null ? -1 : value.length,
                      matches: value !== null && Array.isArray(expected) && value === expected[i]};
            })};
  },
  observe(names, expected) {
    if (!Array.isArray(names) || names.length > 8 || !names.every(n => /^[a-z_]{1,48}$/.test(n))) return 'REFUSED';
    const id = data.ui.background_id;
    const out = {context: this.context(), backgrounds: document.querySelectorAll(selectors.background).length,
                 tasks: document.querySelectorAll(selectors.task).length,
                 scheduler: visible(document.querySelector(selectors.close_scheduler)),
                 code_editor: visible(document.querySelector(selectors.code_editor)),
                 background_id: id !== undefined && id !== null && id !== '',
                 background_changed: backgroundMark.set && id !== backgroundMark.id,
                 target_identity: targetMark.set,
                 background_matches_target: targetMark.set && id === targetMark.id,
                 add_task: button(selectors.add_new_task), controls: {}};
    for (const name of names) out.controls[name] = control(name);
    if (Array.isArray(expected)) out.editors = this.editors(expected);
    return out;
  },
  button(selector) { return button(selector); },
  mark_background() {
    const id = data.ui.background_id;
    backgroundMark = {set: true, id};
    return id !== undefined && id !== null && id !== '';
  },
  mark_target(index) {
    // Returns the very node to click, so the mark and the click cannot name different items.
    targetMark = {set: false, id: undefined};
    const node = Number.isInteger(index) ? document.querySelectorAll(selectors.background)[index] : undefined;
    if (!(node instanceof Element)) return {element: null, bound: false};
    const key = Object.keys(node).find(k => k.startsWith('__reactFiber$'));
    let fiber = key ? node[key] : null;
    for (let step = 0; fiber && typeof fiber === 'object' && step < 16; step += 1, fiber = fiber.return) {
      const props = fiber.memoizedProps;
      const background = props && typeof props === 'object' ? props.background : undefined;
      if (background && typeof background === 'object') {
        const id = background.id;
        if (typeof id === 'string' && id !== '') targetMark = {set: true, id};
        break;
      }
    }
    return {element: node, bound: targetMark.set};
  },
};
return 'INSTALLED';
