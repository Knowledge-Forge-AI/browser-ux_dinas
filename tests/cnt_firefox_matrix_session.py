"""R6 Firefox matrix: drive the unmodified captured XPI through its native settings UI.

Runs inside the accepted R4 preflight session (ObservedClient: every Marionette call is
bracketed by owned-listener samples). The extension is the only importer and exporter:
state is created with WebDriver clicks, option selection, typing, native file selection
(ElementSendKeys on the native file inputs) and the native move prompt; it is observed only
through the native exporter, DOM counts and the page's own prefs object. Nothing here reads
or writes extension storage, serializes Clear New Tab state or rewrites native bytes.

Every wait has an explicit deadline, a state predicate and a fixed failure code. Large native
parts stay in run/artifacts; the result carries only digests, counts and classifications.

Seed routes follow the verified 6.12.1 handlers (provenance ui.event.*): a select commits on
the change event WebDriver's option click fires; a checkbox on the label activation from a
.box click; a text input on each native input event, so text is replaced with native
Backspace/Delete keys and typed (never ElementClear, whose property write is not an input
event). Each action is recorded in `seed_trace` with allowlisted before/after observations.

A task background click is bound to its intended item (REPAIR2): the page helper marks the
item's own background identity (ui.background_identity) and returns that very node to click;
the readback then requires the task background to equal the mark, compared in the page. The
exported source is usable only when its readiness (cnt_firefox_matrix.rich_readiness) holds.

T-RICH, T-DISPLACE and F-REPEAT also record fixed `restore_evidence` (RICH-VALID-PREP1): semantic
fingerprint relations, restored rich coverage, displacement and repeat identity. It is observation
only and never gates completion.

Runnable D cases record fixed `malformed_evidence` (MALFORMED-D-PREP1): the restore_error tri-state,
allowlisted report codes, a sticky error-ribbon observation and what happened to each synthetic
sentinel component, against the actual input and the unmutated same-root source (inputs/original).
It too is observation only and never gates completion.

REPORT-GATE1: a runnable D restore is refused before any file selection unless the error ribbon
read immediately before it reads hidden (MATRIX_PREEXISTING_ERROR_RIBBON), and the fixed
`pre_restore_error_ribbon` enum is recorded. The malformed tri-state reads it together with the
pinned report observability (cnt_firefox_matrix.malformed_restore_error_state).

COMPAT-E-PREP1: before a runnable E restore's file selection the input is proven to be exactly one
declared bounded mutation of the same-root S-RICH artifact (cnt_firefox_matrix.compat_input_proof),
recorded as `compat_input`, and refused otherwise (MATRIX_COMPAT_INPUT_UNPROVEN). The pre-existing
ribbon gate applies to E as to D. Runnable E cases record fixed `compat_evidence`; like the D evidence
it is observation only and never gates completion.

MULTIPART-B-PREP1: every export of a B case uses the multipart deadline. S-MULTI predicts its boundary
from the calibration export's own Part 1 threshold pref, records each export's own threshold, checks the
partition of each export against the threshold that export read, and is a usable source only when its
fixed readiness (cnt_firefox_matrix.multi_readiness) holds; otherwise it stops
MATRIX_MULTI_SOURCE_INCOMPLETE with its parts retained. Before a B dependent's file selection the
selection (and its one bounded mutation) is proven against the ready same-root S-MULTI minimum artifact
(cnt_firefox_matrix.multipart_input_proof), recorded as `multipart_input` and refused otherwise
(MATRIX_MULTIPART_INPUT_UNPROVEN); the pre-existing ribbon gate and the observability-aware tri-state
apply as for D and E. S-MULTI and every B dependent record fixed `multipart_evidence`, observation only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time

from cnt_native_evidence import VerificationError, require
from cnt_synthetic_firefox import poll, script
import cnt_firefox_matrix as matrix

PAGE_HELPER = Path(__file__).with_name('cnt_firefox_matrix_page.js')
HELPER_LIMIT = 16 * 1024
SLICE = 512 * 1024  # raw bytes per readout call; base64 stays well under the 1 MiB frame
ARTIFACT_LIMIT = 512 * 1024 * 1024
ELEMENT = 'element-6066-11e4-a52e-4f735466cecf'
SETTINGS_URL = re.compile(r'moz-extension://[0-9a-f-]{36}/settings\.html')
SETTLE = 1.5
# Seconds. Multipart budgets cover ~100 MiB of native JSON per export.
DEADLINES = {'ready': 30, 'upload': 60, 'upload_multi': 600, 'delete': 20, 'move': 20, 'pref': 10,
             'code': 15, 'task': 20, 'export': 60, 'export_multi': 900, 'restore': 120,
             'restore_multi': 1200, 'script': 30, 'readout': 60}
SESSION_CODES = {
    'Matrix readiness deadline': 'MATRIX_READINESS_DEADLINE',
    'Matrix step deadline': 'MATRIX_STEP_DEADLINE',
    'Cross-case state leakage': 'CROSS_CASE_STATE_LEAKAGE',
    'Artifact readout mismatch': 'ARTIFACT_READOUT_MISMATCH',
    'Matrix add-on identity mismatch': 'MATRIX_ADDON_ID_MISMATCH',
    'Matrix settings URL invalid': 'MATRIX_SETTINGS_URL_INVALID',
    'Matrix page helper refused': 'MATRIX_PAGE_HELPER_REFUSED',
    'Matrix element missing': 'MATRIX_ELEMENT_MISSING',
    'Matrix UI value not applied': 'MATRIX_UI_VALUE_NOT_APPLIED',
    'Matrix export absent': 'MATRIX_EXPORT_ABSENT',
    'Matrix artifact oversized': 'MATRIX_ARTIFACT_OVERSIZED',
    'Matrix input path outside run': 'MATRIX_INPUT_OUTSIDE_RUN',
    'Matrix static fact unverified': 'BLOCKED_STATIC_UNVERIFIED',
    'Matrix report recorder unavailable': 'MATRIX_REPORT_RECORDER_UNAVAILABLE',
    'Matrix script result shape': 'MATRIX_SCRIPT_RESULT_SHAPE',
    'Matrix export incomplete': 'MATRIX_EXPORT_INCOMPLETE',
    'Matrix control not interactable': 'MATRIX_CONTROL_NOT_INTERACTABLE',
    'Matrix trace refused': 'MATRIX_TRACE_REFUSED',
    'Matrix pre-existing error ribbon': 'MATRIX_PREEXISTING_ERROR_RIBBON',
    'Matrix compat input unproven': 'MATRIX_COMPAT_INPUT_UNPROVEN',
    'Matrix multipart input unproven': 'MATRIX_MULTIPART_INPUT_UNPROVEN',
}
# Native keys for the text route (WebDriver key codes). The route never clears by script.
BACKSPACE, DELETE = '', ''
TEXT_LIMIT = 64
# Seconds after each editor value: longer than the verified shared 250 ms save debounce
# (ui.custom_code_gate), so each editor's trailing save runs before the next value.
QUIET = 1.0
PROTOCOL_TOKENS = ('unknown command', 'unknown error', 'invalid argument', 'session not created',
                   'javascript error', 'script timeout', 'timeout', 'no such window',
                   'unsupported operation', 'other')
CODE_KINDS = matrix.KNOWN_CODE
# Exports whose closure must be proven: every case's pre-target export and every source
# artifact that feeds dependent cases. Other exports record an unclosed set as unusable.
CLOSURE_REQUIRED = ('pre',)
RICH_CODE = matrix.RICH_CODE
SENTINEL_CODE = '<p>BUX R6 sentinel</p>'
SENTINEL_TASK = {'background_position': 1, 'year': '2033', 'time': '01:02:03'}
# Static facts each step binds to; an UNVERIFIED fact blocks the step before any UI action.
STEP_FACTS = {'seed': ('ui.upload_input', 'ui.upload_ranks', 'ui.button_dom', 'ui.select_dom',
                       'ui.text_dom', 'ui.checkbox_dom', 'ui.background_item'),
              'rich': ('ui.background_delete', 'ui.background_actions', 'ui.move_prompt', 'ui.move_rank',
                       'ui.background_select', 'ui.settings_context', 'ui.scheduler', 'ui.custom_code',
                       'ui.visibility_conditions', 'ui.data_global', 'ui.event.select', 'ui.event.checkbox',
                       'ui.event.text', 'ui.validation.threshold', 'ui.validation.year', 'ui.validation.time',
                       'ui.val_accessor', 'ui.override_routing', 'ui.background_click', 'ui.global_return',
                       'ui.control_wrapper', 'ui.visibility_enablement', 'ui.custom_code_open',
                       'ui.custom_code_gate', 'ui.custom_code_close', 'ui.scheduler_store',
                       'ui.add_task_enablement', 'ui.task_background_id'),
              # The S-RICH row/task relation the source readiness relies on (rich_rows.facts).
              'rich_source': ('ui.upload_first_rank', 'ui.move_neighbours', 'ui.background_render_order',
                              'backup.chunk_order', 'backup.task_placement', 'ui.task_add_background'),
              'export': ('ui.download_button', 'backup.download_boundary', 'backup.filename'),
              'threshold': ('backup.threshold_ui_range', 'backup.threshold_commit', 'backup.partition',
                            'ui.data_global', 'ui.event.text', 'ui.validation.threshold', 'ui.control_wrapper'),
              'restore': ('ui.restore_input', 'ui.section_content', 'ui.error_ribbon', 'ui.protecting_screen')}


class Session:
    """One case in one fresh profile. `result['matrix']` holds only projection-safe facts."""

    def __init__(self, client, run, result, entry, provenance, clock=time.monotonic):
        self.client, self.run, self.result, self.entry = client, Path(run), result, entry
        self.provenance, self.clock = provenance, clock
        self.selectors = provenance['selectors']
        self.fingerprints, self.layouts, self.thresholds = {}, {}, {}
        self.task_background = None  # index of the last scheduler background click this page
        # Page-side target binding only on the verified identity fact; otherwise every task
        # click is NOT_BOUND and the export relation alone decides.
        self.target_binding = matrix.fact_status(provenance, 'ui.background_identity') in ('VERIFIED', 'CORRECTED')
        self.bindings = {}  # task number -> REACT_FIBER_READ | NOT_BOUND
        self.allow = matrix.trace_allowlist(provenance)
        self.val_accessor = frozenset(matrix.provenance_value(provenance, 'ui.val_accessor'))
        self.record = result.setdefault('matrix', {})
        self.record.update(case=entry['id'], category=entry['category'], profile=entry['profile'],
                           steps=[], artifacts={}, classifications={}, predictions={},
                           seed_trace=[], seed_failed_action=None, completed=False)

    # --- transport -----------------------------------------------------------------------
    def call(self, method, params=None, timeout=10):
        return self.client.call(method, params or {}, timeout=timeout)

    def page(self, source, arguments=(), timeout=10):
        value = self.call('WebDriver:ExecuteScript', {
            'script': source, 'args': list(arguments), 'newSandbox': False, 'sandbox': None,
            'line': 0, 'filename': 'bux-r6-matrix'}, timeout=timeout)
        require(isinstance(value, dict) and 'value' in value, 'Matrix script result shape')
        return value['value']

    def page_async(self, expression, arguments=(), timeout=DEADLINES['script']):
        self.call('WebDriver:SetTimeouts', {'script': int(timeout * 1000)})
        source = ('const done = arguments[arguments.length - 1];'
                  'Promise.resolve().then(() => ' + expression + ').then('
                  'value => done({ok: true, value}), error => done({ok: false, '
                  'error: String(error && error.name || "Error").slice(0, 32)}));')
        value = self.call('WebDriver:ExecuteAsyncScript', {
            'script': source, 'args': list(arguments), 'newSandbox': False, 'sandbox': None,
            'line': 0, 'filename': 'bux-r6-matrix'}, timeout=timeout + 5)
        require(isinstance(value, dict) and isinstance(value.get('value'), dict)
                and value['value'].get('ok') is True, 'Matrix script result shape')
        return value['value'].get('value')

    def elements(self, selector, within=None):
        params = {'using': 'css selector', 'value': selector}
        if within is not None:
            params['element'] = within
        found = self.call('WebDriver:FindElements', params)
        found = found.get('value', found) if isinstance(found, dict) else found
        require(isinstance(found, list), 'Matrix element missing')
        return [e[ELEMENT] for e in found if isinstance(e, dict) and isinstance(e.get(ELEMENT), str)]

    def element(self, selector, index=0, within=None):
        found = self.elements(selector, within)
        require(len(found) > index, 'Matrix element missing')
        return found[index]

    def click(self, selector, index=0, within=None):
        self.call('WebDriver:ElementClick', {'id': self.element(selector, index, within)})

    def until(self, predicate, message, timeout):
        poll(lambda remaining: predicate(), message, timeout)

    # --- page observations -----------------------------------------------------------------
    def install_helper(self):
        source = PAGE_HELPER.read_text()
        require(len(source.encode()) <= HELPER_LIMIT, 'Matrix page helper refused')
        require(self.page(source, [self.selectors]) in ('INSTALLED', 'PRESENT'), 'Matrix page helper refused')

    def state(self):
        value = self.page('return window.__buxMatrix.state(arguments[0]);', [self.selectors])
        require(isinstance(value, dict), 'Matrix script result shape')
        return value

    def ready(self):
        self.until(lambda: self.page(
            'const s = arguments[0]; return !!document.querySelector(s.ready)'
            ' && !document.querySelector(s.hidden_roots);', [self.selectors]) is True,
            'Matrix readiness deadline', DEADLINES['ready'])
        self.install_helper()
        self.until(lambda: self.state().get('ready') is True and not self.state().get('protecting'),
                   'Matrix readiness deadline', DEADLINES['ready'])
        require(self.state().get('report_recorder') is True, 'Matrix report recorder unavailable')

    def idle(self, check, timeout):
        """Wait for `check(state)` and a non-protecting page, stable across SETTLE seconds."""
        stable = {'since': None, 'last': None}
        def settled():
            current = self.state()
            key = (current.get('backgrounds'), current.get('tasks'), current.get('protecting'),
                   current.get('captured'), current.get('section_visible'))
            if not (check(current) and not current.get('protecting')):
                stable.update(since=None, last=None)
                return False
            if key != stable['last']:
                stable.update(since=self.clock(), last=key)
                return False
            return self.clock() - stable['since'] >= SETTLE
        self.until(settled, 'Matrix step deadline', timeout)
        return self.state()

    def observe(self, names=(), expected=None):
        """Read-only page observation (raw; classified before it is recorded)."""
        value = self.page('return window.__buxMatrix.observe(arguments[0], arguments[1]);',
                          [list(names), expected])
        require(isinstance(value, dict), 'Matrix script result shape')
        return value

    @staticmethod
    def control(observed, name):
        value = (observed.get('controls') or {}).get(name)
        return value if isinstance(value, dict) else {'present': False}

    @staticmethod
    def same(observed, expected):
        """Strict equality: a committed number never matches its typed string, or the reverse."""
        return type(observed) is type(expected) and observed == expected

    def expect(self, predicate, names=(), expected=None, message='Matrix UI value not applied',
               timeout=None):
        latest = {}
        def check():
            latest['value'] = self.observe(names, expected)
            return predicate(latest['value'])
        self.until(check, message, DEADLINES['pref'] if timeout is None else timeout)
        return latest['value']

    def committed(self, name, value):
        """Page state after the application's own handler ran (provenance ui.event.*): the pref,
        the in-page value for val_accessor controls in the global context, the DOM, no warn."""
        def check(observed):
            c = self.control(observed, name)
            if c.get('present') is not True or c.get('warn') is True:
                return False
            dom = value if type(value) is bool else str(value)
            return (self.same(c.get('pref'), value) and self.same(c.get('dom'), dom)
                    and (name not in self.val_accessor or self.same(c.get('ui'), value)))
        return self.expect(check, (name,))

    def interactable(self, name):
        """The native wrapper is shown and not is_disabled (ui.control_wrapper), so the click
        reaches the control instead of failing interactability."""
        observed = self.expect(lambda o: self.control(o, name).get('shown') is True
                               and self.control(o, name).get('enabled') is True, (name,),
                               message='Matrix control not interactable')
        return self.control(observed, name)

    def button_ready(self, selector, deadline='pref'):
        self.until(lambda: self.page('return window.__buxMatrix.button(arguments[0]);', [selector])
                   == {'present': True, 'shown': True, 'enabled': True},
                   'Matrix control not interactable', DEADLINES[deadline])

    def quiet(self, seconds):
        started = self.clock()
        self.until(lambda: self.clock() - started >= seconds, 'Matrix step deadline', seconds + DEADLINES['code'])

    # --- attribution ---------------------------------------------------------------------------
    @staticmethod
    def failure_class(error):
        message = str(error)
        code = (SESSION_CODES.get(message) or matrix.MATRIX_CODES.get(message)
                if isinstance(error, VerificationError) else None)
        protocol = None
        if isinstance(error, RuntimeError) and message.startswith('Marionette protocol: '):
            token = message[len('Marionette protocol: '):]
            protocol = (token if token in PROTOCOL_TOKENS else 'other').replace(' ', '_')
        name = type(error).__name__
        return {'type': name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) else 'Error',
                'code': code, 'protocol': protocol}

    def act(self, action, route, expected, run, names=(), editors=None):
        """One attributed native action. `run(before)` performs it and returns 'SKIPPED' when
        the page already held the target. The primary failure is re-raised unchanged."""
        trace = self.record['seed_trace']
        require(matrix.TRACE_ACTION.fullmatch(action) is not None and route in matrix.TRACE_ROUTES
                and len(trace) < matrix.TRACE_LIMIT and all(matrix.TRACE_NAME.fullmatch(n) for n in names),
                'Matrix trace refused')
        allowed = frozenset().union(*(self.allow.get(n, ()) for n in names))
        entry = {'n': len(trace) + 1, 'action': action, 'route': route, 'status': 'STARTED',
                 'expected': matrix.trace_value(expected, allowed)}
        trace.append(entry)
        started = self.clock()
        classify = lambda raw: matrix.trace_observation(raw, self.allow)
        def elapsed():
            return max(0, min(int(round((self.clock() - started) * 1000)), 10 ** 9))
        try:
            before = self.observe(names, editors)
            entry['before'] = classify(before)
            status = run(before)
        except BaseException as error:
            failure = self.failure_class(error)
            entry.update(status='FAILED', failure=failure)
            entry.setdefault('before', {'observation': 'UNAVAILABLE'})
            if self.record.get('seed_failed_action') is None:
                self.record['seed_failed_action'] = action
            after = {'observation': 'UNAVAILABLE'}
            # Observe again only after a page-level failure or a well-formed protocol reply. Never
            # after an interrupt or a transport failure (EOF, deadline, frame or response mismatch,
            # identity loss), where the stream may be out of step.
            if failure['code'] is not None or failure['protocol'] is not None:
                try:
                    after = classify(self.observe(names, editors))
                except Exception:
                    pass
            entry.update(after=after, elapsed_ms=elapsed())
            raise
        entry['status'] = 'SKIPPED' if status == 'SKIPPED' else 'DONE'
        try:
            entry['after'] = classify(self.observe(names, editors))
        except Exception:
            entry['after'] = {'observation': 'UNAVAILABLE'}
        entry['elapsed_ms'] = elapsed()
        return entry

    # --- native UI actions ---------------------------------------------------------------------
    def inside(self, path):
        path = Path(path)
        require(path.is_absolute() and path.is_relative_to(self.run) and not path.is_symlink()
                and path.resolve() == path, 'Matrix input path outside run')
        return str(path)

    def choose_files(self, selector, paths):
        """Native file selection; order is the selection order the page receives."""
        text = '\n'.join(self.inside(p) for p in paths)
        self.call('WebDriver:ElementSendKeys', {'id': self.element(selector), 'text': text})

    def select(self, name, value, action=None):
        """Option click; WebDriver fires the select's change event, which React's onChange
        commits (ui.event.select). An option already selected is not clicked (SKIPPED)."""
        def run(before):
            current = self.interactable(name)
            if self.same(current.get('dom'), value):
                self.committed(name, value)
                return 'SKIPPED'
            self.click(f'select[name="{name}"] option[value="{value}"]')
            self.committed(name, value)
        return self.act(action or f'pref:{name}', 'option_click', value, run, (name,))

    def checkbox(self, name, value):
        """.box click inside the wrapping label; the label activation toggles the hidden
        input whose onChange commits (ui.event.checkbox)."""
        def run(before):
            current = self.interactable(name)
            if self.same(current.get('pref'), value):
                self.committed(name, value)
                return 'SKIPPED'
            self.click(f'.input_w.checkbox.{name} .box')
            self.committed(name, value)
        return self.act(f'pref:{name}', 'box_click', value, run, (name,))

    def text(self, name, value, action=None):
        """Native key replacement: Backspace and Delete once per current character from any
        caret position, then the value. Every key is a native input event, so the onInput
        handler sees each intermediate (ui.event.text); the committed value is read back with
        the verified type (a valid threshold is written back as a number)."""
        def run(before):
            current = self.interactable(name)
            length = current.get('length')
            require(type(length) is int and 0 <= length <= TEXT_LIMIT, 'Matrix control not interactable')
            keys = BACKSPACE * length + DELETE * length + str(value)
            self.call('WebDriver:ElementSendKeys', {'id': self.element(f'input[name="{name}"]'), 'text': keys})
            self.committed(name, value)
        return self.act(action or f'pref:{name}', 'keys_replace', value, run, (name,))

    def code(self, index, value):
        """Library adapter input (accepted R1): CodeMirror setValue on an open editor. The
        application's own editor change listener, save gate and debounce still run."""
        return self.page('return window.__buxMatrix.code(arguments[0], arguments[1]);', [index, value])

    def facts(self, group):
        blocked = sorted(k for k in STEP_FACTS[group] if matrix.fact_status(self.provenance, k)
                         not in ('VERIFIED', 'CORRECTED'))
        if blocked:
            self.record['blocked_facts'] = blocked
        require(not blocked, 'Matrix static fact unverified')

    # --- steps ---------------------------------------------------------------------------------
    def step(self, name, action):
        entry = {'step': name, 'status': 'STARTED'}
        self.record['steps'].append(entry)
        try:
            outcome = action()
        except BaseException as error:
            entry['status'] = 'FAILED'
            entry['error_type'] = type(error).__name__
            raise
        entry['status'] = 'DONE'
        if isinstance(outcome, dict):
            entry.update(outcome)
        return outcome

    def seed_files(self, kind):
        target = self.run / 'inputs' / ('seed-' + kind)
        target.mkdir(parents=True, mode=0o700)
        paths = []
        for name, raw in matrix.synthetic_inputs(kind):
            path = target / name
            with path.open('xb') as stream:
                stream.write(raw)
            paths.append(path)
        return paths

    def upload(self, kind, deadline):
        self.facts('seed')
        outcome = {}
        def run(before):
            count = before.get('backgrounds')
            paths = self.seed_files(kind)
            if kind == 'multi':
                # Digests of the deterministic, project-authored seed files (never user data).
                self.record['seed_sha256'] = [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
            self.choose_files(self.selectors['upload'], paths)
            after = self.idle(lambda s: s['backgrounds'] == count + len(paths), DEADLINES[deadline])
            outcome.update(uploaded=len(paths), backgrounds_dom=after['backgrounds'])
        count = {'rich': len(matrix.RICH_COLOURS), 'sentinel': len(matrix.SENTINEL_COLOURS),
                 'multi': matrix.MULTI_COUNT}[kind]
        self.act('upload', 'file_keys', count, run)
        return outcome

    def target(self, index):
        """(element, bound): the item to click and whether the page marked the background its
        own click handler passes (ui.background_identity). Mark and element come from one page
        script, so they name the same node. Without the verified fact, or when the page finds
        no identity, the click proceeds unbound and the export relation alone decides."""
        if not self.target_binding:
            return self.element(self.selectors['background'], index), False
        value = self.page('return window.__buxMatrix.mark_target(arguments[0]);', [index])
        require(isinstance(value, dict) and type(value.get('bound')) is bool, 'Matrix script result shape')
        element = value.get('element')
        element = element.get(ELEMENT) if isinstance(element, dict) else None
        require(isinstance(element, str), 'Matrix element missing')
        return element, value['bound']

    def add_task(self, number, task):
        index = task['background_position'] - 1
        def background(before):
            # With the scheduler open, a background click sets the task background id to that
            # background (ui.background_select). Nothing else sets it and adding a task keeps it
            # (ui.task_background_id), so a click on another background than the last one must
            # change it. When bound, the id must also equal the intended item's mark: a click that
            # lands on another existing background fails here. The page compares the ids; none
            # leaves the page. The count must hold.
            require(before.get('scheduler') is True, 'Matrix control not interactable')
            count, changes = before.get('backgrounds'), index != self.task_background
            require(type(self.page('return window.__buxMatrix.mark_background();')) is bool,
                    'Matrix script result shape')
            element, bound = self.target(index)
            self.bindings[number] = 'REACT_FIBER_READ' if bound else 'NOT_BOUND'
            self.call('WebDriver:ElementClick', {'id': element})
            self.expect(lambda o: o.get('background_id') is True and o.get('scheduler') is True
                        and (o.get('background_changed') is True) is changes and o.get('backgrounds') == count
                        and (not bound or o.get('background_matches_target') is True))
            self.task_background = index
        self.act(f'task:{number}:background', 'element_click', task['background_position'], background)
        self.text('year', task['year'], action=f'task:{number}:year')
        self.text('time', task['time'], action=f'task:{number}:time')
        if 'day_of_the_month' in task:
            self.select('day_of_the_month', task['day_of_the_month'], action=f'task:{number}:day_of_the_month')
        def add(before):
            count = before.get('tasks')
            # Enablement is asynchronous (background preview lookup; ui.add_task_enablement).
            self.button_ready(self.selectors['add_new_task'], 'task')
            self.click(self.selectors['add_new_task'])
            self.idle(lambda s: s['tasks'] == count + 1, DEADLINES['task'])
        self.act(f'task:{number}:add', 'button_click', True, add)

    def scheduled(self, tasks):
        self.select('mode', 'scheduled', action='scheduler:mode')
        def open_(before):
            self.button_ready(self.selectors['open_scheduler'])
            self.click(self.selectors['open_scheduler'])
            self.expect(lambda o: o.get('scheduler') is True, timeout=DEADLINES['task'])
        self.act('scheduler:open', 'button_click', True, open_)
        for number, task in enumerate(tasks, 1):
            self.add_task(number, task)
        def close(before):
            self.click(self.selectors['close_scheduler'])
            self.expect(lambda o: o.get('scheduler') is False, timeout=DEADLINES['task'])
        self.act('scheduler:close', 'button_click', False, close)

    def custom_code(self, values):
        """Open the editor through the native custom_code button (its value reset supplies the
        three changes the save gate counts), set each editor, wait out the shared debounce,
        close through the native control. Saved code is observed only in the export."""
        values = list(values)
        expected = values + [None] * (len(CODE_KINDS) - len(values))
        def open_(before):
            self.button_ready(self.selectors['custom_code'])
            self.click(self.selectors['custom_code'])
            self.expect(lambda o: (o.get('editors') or {}).get('open') is True
                        and (o['editors'].get('count') == len(CODE_KINDS))
                        and all(i.get('ready') for i in o['editors'].get('items') or [{}]),
                        expected=expected, timeout=DEADLINES['code'])
        self.act('custom_code:open', 'button_click', True, open_, editors=expected)
        for index, value in enumerate(values):
            def set_(before, index=index, value=value):
                require(self.code(index, value) == len(CODE_KINDS), 'Matrix element missing')
                self.quiet(QUIET)
                self.expect(lambda o: ((o.get('editors') or {}).get('items') or [{}] * 3)[index].get('matches') is True,
                            expected=expected, timeout=DEADLINES['code'])
            self.act(f'custom_code:{CODE_KINDS[index]}', 'codemirror_set', True, set_, editors=expected)
        def close(before):
            self.button_ready(self.selectors['close_code_editor'])
            self.click(self.selectors['close_code_editor'])
            self.expect(lambda o: (o.get('editors') or {}).get('open') is False,
                        expected=expected, timeout=DEADLINES['code'])
        self.act('custom_code:close', 'button_click', False, close, editors=expected)

    def override(self):
        """Per-background override (ui.override_routing): a background click enters the
        selected_background context; background_size then goes to that background, not the
        global pref; the settings_context option global returns and restores the in-page value."""
        name, value = self.provenance['rich_override']
        names = (name, 'settings_context')
        captured = {}
        def enter(before):
            require(before.get('scheduler') is False, 'Matrix control not interactable')
            captured['global'] = self.control(before, name).get('pref')
            count = before.get('backgrounds')
            self.click(self.selectors['background'], 0)
            # A click that reached the item's delete button would not select (it stops
            # propagation) and would drop the count; both fail here.
            self.expect(lambda o: o.get('context') == 'selected_background' and o.get('backgrounds') == count)
        self.act('context:select_background', 'element_click', 'selected_background', enter, names)
        global_value = captured['global']
        def apply(before):
            self.interactable(name)
            self.click(f'select[name="{name}"] option[value="{value}"]')
            self.expect(lambda o: self.same(self.control(o, name).get('ui'), value)
                        and o.get('context') == 'selected_background', names)
        self.act(f'override:{name}', 'option_click', value, apply, names)
        def unchanged(before):
            require(self.same(self.control(before, name).get('pref'), global_value), 'Matrix UI value not applied')
        self.act('invariant:override_global_unchanged', 'read_only', global_value, unchanged, names)
        def leave(before):
            self.interactable('settings_context')
            self.click('select[name="settings_context"] option[value="global"]')
            self.expect(lambda o: o.get('context') == 'global', names)
        self.act('context:return_global', 'option_click', 'global', leave, names)
        def restored(before):
            c = self.control(before, name)
            require(self.same(c.get('pref'), global_value) and self.same(c.get('ui'), global_value),
                    'Matrix UI value not applied')
        self.act('invariant:global_background_size', 'read_only', global_value, restored, names)

    def seed_rich(self):
        self.facts('rich')
        self.facts('rich_source')
        uploaded = self.upload('rich', 'upload')
        # Rank gap: delete the third item (no confirm dialog in 6.12.1; the button stops
        # propagation, so the item is not selected).
        def delete(before):
            self.click(self.selectors['delete'], 2)
            self.idle(lambda s: s['backgrounds'] == 5, DEADLINES['delete'])
        self.act('delete_gap', 'element_click', 5, delete)
        # Fractional rank: move the last item to position 2 through the native prompt.
        def move(before):
            item = self.element(self.selectors['background'], 4)
            self.call('WebDriver:ElementClick', {'id': self.element(self.selectors['actions'], within=item)})
            self.call('WebDriver:ElementClick', {'id': self.element(self.selectors['move'], within=item)})
            self.call('WebDriver:SendAlertText', {'text': '2'})
            self.call('WebDriver:AcceptAlert')
            self.idle(lambda s: s['backgrounds'] == 5, DEADLINES['move'])
        self.act('move_fractional', 'prompt', 2, move)
        applied = []
        # Listed order matters: mode=scheduled first makes slideshow and its children visible,
        # and each parent checkbox enables its children (ui.visibility_enablement).
        for kind, name, value in self.provenance['rich_prefs']:
            {'select': self.select, 'checkbox': self.checkbox, 'text': self.text}[kind](name, value)
            applied.append(name)
        self.override()
        self.custom_code(RICH_CODE)
        self.scheduled(self.provenance['rich_tasks'])
        return {'uploaded': uploaded['uploaded'], 'prefs_applied': len(applied),
                'tasks_added': len(self.provenance['rich_tasks'])}

    def seed_sentinel(self):
        self.facts('rich')
        uploaded = self.upload('sentinel', 'upload')
        self.custom_code([SENTINEL_CODE])
        self.scheduled([SENTINEL_TASK])
        return {'uploaded': uploaded['uploaded'], 'tasks_added': 1}

    def closure_required(self, label):
        """Pre-target exports, the calibration and every artifact a dependent case consumes."""
        return label in CLOSURE_REQUIRED or label == 'calibration' or any(
            c['source'] == self.entry['id'] and c['artifact'] == label for c in matrix.CASES)

    @staticmethod
    def closure(parts, fp, expected_rows):
        """A captured part set is closed only by contiguous native part names 1..N and an
        exported row count equal to the page's background count. Quiescence alone never is."""
        if [p['name_class'] for p in parts] != [f'NATIVE_PART_{n}' for n in range(1, len(parts) + 1)]:
            return 'PART_SEQUENCE_BROKEN'
        if not fp['complete']:
            return 'UNPARSEABLE_PART'
        rows = fp['derived']['row_count']
        return 'CLOSED' if rows == expected_rows else 'ROWS_SHORT' if rows < expected_rows else 'ROWS_EXCESS'

    def read_part(self, target, entry):
        size = entry.get('size')
        require(type(size) is int and 0 <= size <= ARTIFACT_LIMIT, 'Matrix artifact oversized')
        number = matrix.PART_NAME.search(entry.get('name') or '')
        name_class = f'NATIVE_PART_{number.group(1)}' if number and str(entry.get('name')).endswith(
            f'Part {number.group(1)}.json') else 'UNEXPECTED_NAME'
        path = target / f'part-{entry["index"] + 1}.json'
        digest = hashlib.sha256()
        with path.open('xb') as stream:
            for start in range(0, size, SLICE):
                chunk = self.page_async('window.__buxMatrix.slice(arguments[0], arguments[1], arguments[2])',
                                        [entry['index'], start, min(size, start + SLICE)],
                                        DEADLINES['readout'])
                require(isinstance(chunk, str), 'Artifact readout mismatch')
                raw = base64.b64decode(chunk, validate=True)
                require(len(raw) == min(SLICE, size - start), 'Artifact readout mismatch')
                stream.write(raw)
                digest.update(raw)
        page_digest = self.page_async('window.__buxMatrix.sha256(arguments[0])', [entry['index']],
                                      DEADLINES['readout'])
        require(page_digest == digest.hexdigest(), 'Artifact readout mismatch')
        return {'index': entry['index'], 'name_class': name_class, 'bytes': size,
                'sha256': digest.hexdigest()}, path

    def export(self, label, multi=False):
        self.facts('export')
        self.page('return window.__buxMatrix.clear();')
        self.click(self.selectors['download'])
        deadline, started = DEADLINES['export_multi' if multi else 'export'], self.clock()
        target = self.run / 'artifacts' / label
        target.mkdir(parents=True, mode=0o700)
        parts, paths, closure, expected = [], [], 'UNCLOSED', None
        while True:
            # Wait for more parts than already read; a short set keeps waiting until the deadline.
            try:
                state = self.idle(lambda s, have=len(parts): s['captured'] > have,
                                  deadline - (self.clock() - started))
            except VerificationError as error:
                if str(error) != 'Matrix step deadline' or not parts:
                    raise
                break
            captured = self.page('return window.__buxMatrix.captured();')
            require(isinstance(captured, list) and len(captured) == state['captured'] > len(parts),
                    'Matrix export absent')
            for entry in captured[len(parts):]:
                part, path = self.read_part(target, entry)
                parts.append(part)
                paths.append(path)
            expected = state['backgrounds']
            fp = matrix.fingerprint([p.read_bytes() for p in paths])
            closure = self.closure(parts, fp, expected)
            if closure != 'ROWS_SHORT':
                break
        self.write_manifest(label, parts)
        raw = [p.read_bytes() for p in paths]
        fp = matrix.fingerprint(raw)
        closed = closure == 'CLOSED'
        self.record['artifacts'][label] = {
            'parts': parts, 'fingerprint_sha256': fp['sha256'], 'semantic_sha256': fp['semantic_sha256'],
            'complete': fp['complete'], 'derived': fp['derived'], 'closure': closure,
            'expected_rows': expected, 'native_template': None}
        if self.closure_required(label):
            require(closed, 'Matrix export incomplete')
        # An unclosed set is retained as evidence but is never classified.
        self.fingerprints[label] = fp if closed else None
        try:
            self.layouts[label] = [matrix.part_layout(r) for r in raw] if closed else None
        except VerificationError:
            self.layouts[label] = None
        if self.layouts[label] is not None:
            self.record['artifacts'][label]['native_template'] = all(l['native_template'] for l in self.layouts[label])
        if self.entry['category'] == 'B':
            # The threshold this export itself read (its own Part 1 pref), never the intended value.
            self.record['artifacts'][label]['threshold'] = matrix.export_threshold(fp) if closed else None
        return {'label': label, 'parts': len(parts), 'closure': closure}

    def write_manifest(self, label, parts):
        manifest = self.run / 'artifacts/MANIFEST.json'
        current = json.loads(manifest.read_text()) if manifest.exists() else {}
        current[label] = parts
        temporary = manifest.with_suffix('.tmp')
        temporary.write_text(json.dumps(current, indent=2, sort_keys=True) + '\n')
        temporary.replace(manifest)

    def threshold(self, which):
        self.facts('threshold')
        if which == 'minimum':
            # The supported UI minimum itself; there is no other (reduced) threshold path.
            value = matrix.THRESHOLD_MIN
        else:
            layout = self.layouts.get('calibration')
            require(layout is not None and len(layout) == 1, 'Matrix step deadline')
            raw = (self.run / 'artifacts/calibration/part-1.json').read_bytes()
            # The calibration export's own Part 1 threshold, not an assumed default.
            own = self.record['artifacts']['calibration'].get('threshold')
            prediction = matrix.boundary_prediction(raw, own)
            self.record['boundary_prediction'] = prediction
            if not prediction['in_ui_range']:
                return {'status_detail': 'BOUNDARY_NOT_SETTABLE'}
            value = prediction['threshold'] + (1 if which == 'predicted_plus_1' else 0)
        # Same native key route and typed readback as the rich seed. Unlike the S-RICH values, a
        # general in-range start value can pass validation mid-replacement, so a transient threshold
        # may be saved before the final committed value; the next export's own Part 1 pref decides
        # whether the intended value was committed (multi_readiness threshold:committed:*).
        self.text('one_backup_file_size_in_bytes', value, action=f'threshold:{which}')
        self.thresholds[which] = value
        self.record.setdefault('thresholds', {})[which] = value
        return {'threshold': value}

    def restore_inputs(self):
        declared = self.result.get('matrix_inputs') or {}
        selection = declared.get('selection') or []
        paths = []
        for item in selection:
            path = self.run / 'inputs/select' / str(item['slot']) / matrix.INPUT_NAME.format(item['named_part'])
            require(matrix.file_bytes(path, ARTIFACT_LIMIT) is not None
                    and hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'],
                    'Matrix input digest mismatch')
            paths.append(path)
        return paths

    def observed_restore(self):
        """Runnable D, E and B dependents: the restores read with the observability-aware tri-state."""
        return self.entry['runnable'] is True and (self.entry['category'] in ('D', 'E') or self.multipart())

    def multipart(self):
        """A runnable B dependent (it consumes the same-root S-MULTI minimum artifact)."""
        return (self.entry['category'] == 'B' and self.entry['runnable'] is True
                and self.entry['source'] == 'S-MULTI')

    def unmutated(self):
        """The unmutated same-root source parts (inputs/original), else the restore input itself."""
        declared = self.result.get('matrix_inputs') or {}
        if not declared.get('original'):
            return self.input_bytes()
        return [(self.run / 'inputs/original' / f'part-{item["part_number"]}.json').read_bytes()
                for item in declared['original']]

    def multipart_input(self, paths):
        """B dependents only, before any selection: the fixed selection proof from the bytes on disk (the
        restore input, the unmutated same-root source and the files about to be selected, in selection
        order) against the preflight's same-root S-MULTI readiness record. Anything short of proven
        refuses before a selection; the fixed-shape proof is recorded either way. A proof that cannot be
        read or projected is replaced by the empty (unproven) proof, so it refuses as
        MATRIX_MULTIPART_INPUT_UNPROVEN rather than under another code."""
        declared = self.result.get('matrix_inputs') or {}
        try:
            proof = matrix.multipart_input_proof(self.entry, declared, self.input_bytes(), self.unmutated(),
                                                 [Path(p).read_bytes() for p in paths])
            projected = matrix.project(proof)
        except (OSError, KeyError, TypeError, AttributeError, VerificationError):
            proof = matrix.multipart_input_proof(self.entry, {}, [], [], [])
            projected = matrix.project(proof)
        self.record['multipart_input'] = projected
        require(proof['proven'] is True, 'Matrix multipart input unproven')

    def compat_input(self, paths):
        """Runnable E only, before any selection: the fixed input proof from the bytes on disk (the
        mutated input, the unmutated same-root source and the files about to be selected). Anything
        short of proven refuses before a selection; the fixed-shape proof is recorded either way. A
        proof that cannot be read or projected is replaced by the empty (unproven) proof, so it refuses
        as MATRIX_COMPAT_INPUT_UNPROVEN rather than under another code."""
        declared = self.result.get('matrix_inputs') or {}
        try:
            original = [(self.run / 'inputs/original' / f'part-{item["part_number"]}.json').read_bytes()
                        for item in declared.get('original') or []]
            proof = matrix.compat_input_proof(self.entry, declared, self.input_bytes(), original,
                                              [Path(p).read_bytes() for p in paths])
            projected = matrix.project(proof)
        except (OSError, KeyError, TypeError, AttributeError, VerificationError):
            proof = matrix.compat_input_proof(self.entry, {}, [], [], [])
            projected = matrix.project(proof)
        self.record['compat_input'] = projected
        require(proof['proven'] is True, 'Matrix compat input unproven')

    def pre_restore_ribbon(self, before):
        """Runnable D, E and B dependents: the error ribbon read once, immediately before the file
        selection. Only a ribbon read as hidden may precede a malformed restore (a visible or unreadable one is refused
        before any selection), so a ribbon seen later is not one left over from seeding. The page
        also reads an absent ribbon root as hidden, so HIDDEN does not prove the ribbon loaded. A
        fixed enum only; the ribbon text is never read."""
        visible = before.get('error_visible')
        self.record['pre_restore_error_ribbon'] = ('HIDDEN' if visible is False else
                                                   'VISIBLE' if visible is True else 'UNREADABLE')
        require(visible is False, 'Matrix pre-existing error ribbon')

    def restore(self):
        self.facts('restore')
        paths = self.restore_inputs()
        if self.entry['category'] == 'E' and self.observed_restore():
            self.compat_input(paths)
        if self.multipart():
            self.multipart_input(paths)
        before = self.state()
        if self.observed_restore():
            self.pre_restore_ribbon(before)
        multi = self.entry['source'] == 'S-MULTI'
        self.choose_files(self.selectors['restore'], paths)
        started = self.clock()
        # `ribbon` is sticky: the native error ribbon auto-hides (ui.error_ribbon), so a ribbon seen
        # while polling is kept even when it is gone by the final read. Observation only: it never
        # changes the completion or the recorded restore_error below.
        observed = {'last': None, 'since': None, 'start': False, 'ribbon': False}
        def began(s):
            # Positive evidence the native restore ran: provenance restore.delete_before_parse
            # hides the section (section_content transition) before any parse or validation.
            return bool(s['protecting'] or (before['section_visible'] and not s['section_visible'])
                        or s['section_transitions'] > before['section_transitions']
                        or s['reports'] > before['reports'])
        def finished():
            s = self.state()
            observed['start'] = observed['start'] or began(s)
            observed['ribbon'] = observed['ribbon'] or s['error_visible'] is True
            loud = s['loud_reports'] > before['loud_reports'] or s['error_visible']
            key = (s['backgrounds'], s['protecting'], s['section_visible'], s['section_transitions'], s['reports'])
            if key != observed['last']:
                observed.update(last=key, since=self.clock())
                return False
            if self.clock() - observed['since'] < SETTLE or self.clock() - started < SETTLE:
                return False
            # Quiescence without a start signal is not completion (a dropped change event).
            return observed['start'] and ((not s['protecting'] and s['section_visible']) or loud)
        completion = 'COMPLETED'
        try:
            self.until(finished, 'Matrix step deadline', DEADLINES['restore_multi' if multi else 'restore'])
        except VerificationError as error:
            if str(error) != 'Matrix step deadline':
                raise
            completion = 'DEADLINE_NO_SIGNAL'
        after = self.state()
        started_observed = observed['start'] or began(after)
        reports = self.page('return window.__buxMatrix.reports(arguments[0]);', [before['reports']]) or []
        reports = [r for r in reports if isinstance(r, dict)]
        codes = sorted({r.get('code') for r in reports if not r.get('silent')})
        silent = sorted({r.get('code') for r in reports if r.get('silent')})
        loud = bool(codes) or after['error_visible']
        if loud:
            completion = 'ERROR_REPORTED' if completion == 'COMPLETED' else completion
        elif silent and completion == 'COMPLETED':
            # A silently reported native error is not a clean restore; no no-error verdict.
            completion = 'SILENT_REPORTED'
        restore_error = True if loud else (False if completion == 'COMPLETED' else None)
        outcome = {'completion': completion, 'restore_error': restore_error, 'error_codes': codes,
                   'silent_codes': silent, 'start_observed': started_observed,
                   'transition_end_observed': after['section_transitions'] > before['section_transitions'],
                   'error_ribbon_seen': observed['ribbon'] or after['error_visible'] is True,
                   'backgrounds_dom_after': after['backgrounds'], 'selected_files': len(paths)}
        self.record.setdefault('restores', []).append(outcome)
        if completion == 'DEADLINE_NO_SIGNAL':
            require(self.entry.get('allow_no_signal') is True, 'Matrix step deadline')
        return outcome

    def reload(self):
        self.call('WebDriver:Refresh')
        self.task_background = None  # a new page starts with data.ui empty (ui.task_background_id)
        self.ready()

    def pre_export(self):
        outcome = self.export('pre')
        fp = self.fingerprints['pre']
        if self.entry['profile'] == matrix.SEEDED_SENTINEL:
            expected = [hashlib.sha256(raw).hexdigest() for _, raw in matrix.synthetic_inputs('sentinel')]
            contents = [((r.get('file') or {}).get('content') or {}).get('sha256') for r in fp['rows']]
            code = (fp.get('custom_code') or {}).get('html', {}).get('sha256')
            ok = (contents == expected and code == matrix.digest(SENTINEL_CODE)
                  and fp['derived']['task_count'] == 1)
        else:
            ok = fp['complete'] and fp['derived']['row_count'] == 0 and fp['derived']['task_count'] == 0
        require(ok, 'Cross-case state leakage')
        return outcome

    def run_steps(self):
        steps = list(self.entry['steps'])
        if self.entry['profile'] == matrix.SEEDED_SENTINEL:
            steps.insert(0, 'seed_sentinel')
        skip_boundary = False
        for name in steps:
            if name.startswith('export:'):
                label = name.split(':', 1)[1]
                if skip_boundary and label in ('at_t', 'at_t_plus_1'):
                    self.record['steps'].append({'step': name, 'status': 'SKIPPED_NOT_SETTABLE'})
                    continue
                self.step(name, lambda: self.export(label, multi=self.entry['category'] == 'B'))
            elif name.startswith('threshold:'):
                which = name.split(':', 1)[1]
                if skip_boundary and which == 'predicted_plus_1':
                    self.record['steps'].append({'step': name, 'status': 'SKIPPED_NOT_SETTABLE'})
                    continue
                outcome = self.step(name, lambda: self.threshold(which))
                skip_boundary = skip_boundary or outcome.get('status_detail') == 'BOUNDARY_NOT_SETTABLE'
            elif name == 'post_export':
                # A restored multipart source re-exports as ~100 MiB of native JSON.
                self.step(name, lambda: self.export('post', multi=self.entry['category'] == 'B'))
            elif name == 'repeat_export':
                self.step(name, lambda: self.export('repeat'))
            else:
                self.step(name, {'seed_rich': self.seed_rich, 'seed_sentinel': self.seed_sentinel,
                                 'seed_multi': lambda: self.upload('multi', 'upload_multi'),
                                 'pre_export': self.pre_export, 'restore': self.restore,
                                 'reload': self.reload}[name])

    # --- classification ------------------------------------------------------------------------
    def given(self):
        declared = self.result.get('matrix_inputs') or {}
        source = declared.get('source') or []
        raw = [(self.run / 'inputs/source' / f'part-{item["part_number"]}.json').read_bytes() for item in source]
        return matrix.fingerprint(raw) if raw else None

    def input_bytes(self):
        declared = self.result.get('matrix_inputs') or {}
        return [(self.run / 'inputs/source' / f'part-{item["part_number"]}.json').read_bytes()
                for item in declared.get('source') or []]

    def original(self):
        """The unmutated same-root source parts (inputs/original, re-verified against their recorded
        digests); without a mutation the restore input is the source itself."""
        declared = self.result.get('matrix_inputs') or {}
        if not declared.get('original'):
            return self.given()
        raw = []
        for item in declared['original']:
            data = (self.run / 'inputs/original' / f'part-{item["part_number"]}.json').read_bytes()
            require(hashlib.sha256(data).hexdigest() == item['sha256'], 'Matrix input digest mismatch')
            raw.append(data)
        return matrix.fingerprint(raw)

    def selected_fingerprints(self):
        """Fingerprints of the files actually selected: in native part order (named part, stable) and in
        selection order. Re-verified against their recorded digests."""
        declared = self.result.get('matrix_inputs') or {}
        items = [i for i in declared.get('selection') or [] if isinstance(i, dict)]
        raw = []
        for item in items:
            path = self.run / 'inputs/select' / str(item['slot']) / matrix.INPUT_NAME.format(item['named_part'])
            data = path.read_bytes()
            require(hashlib.sha256(data).hexdigest() == item['sha256'], 'Matrix input digest mismatch')
            raw.append((item['named_part'], data))
        native = [data for _, data in sorted(raw, key=lambda pair: pair[0])]
        return {'native_order': matrix.fingerprint(native) if native else None,
                'selection_order': matrix.fingerprint([data for _, data in raw]) if raw else None}

    def classify(self):
        entry, fps, out = self.entry, self.fingerprints, self.record['classifications']
        restores = self.record.get('restores') or []
        given = None
        if entry['source'] is not None and 'post' in fps and restores:
            given, error = self.given(), restores[0]['restore_error']
            out['backgrounds'] = matrix.classify_backgrounds(fps.get('pre'), given, fps['post'], restore_error=error)
            out['tasks'] = matrix.classify_tasks(fps.get('pre'), given, fps['post'], restore_error=error)
            out['settings'] = matrix.classify_component(fps.get('pre'), given, fps['post'], 'settings',
                                                        restore_error=error)
            out['custom_code'] = matrix.classify_component(fps.get('pre'), given, fps['post'], 'custom_code',
                                                           restore_error=error)
            out['ranks'] = matrix.classify_ranks(given, fps['post'])
            if entry['mutation'] and matrix.MUTATIONS[entry['mutation']][0] == 'insert':
                out['unknown'] = matrix.classify_unknown(fps['post'], entry['mutation'])
        if entry['id'] == 'F-REPEAT':
            out['repeat'] = matrix.classify_repeat(fps.get('post'), fps.get('repeat'),
                                                   restore_errors=[r['restore_error'] for r in restores])
        if entry['id'] == 'S-MULTI':
            closed = {k for k, v in self.record['artifacts'].items() if v.get('closure') == 'CLOSED'}
            counts = {k: len(self.record['artifacts'][k]['parts']) if k in closed else None
                      for k in ('at_t', 'at_t_plus_1')}
            # The prediction assumed the Part 1 header changes only by the threshold's digits;
            # the at-T export's own header decides whether that premise held.
            at_t = self.layouts.get('at_t')
            header = at_t[0]['header_bytes'] if at_t and at_t[0]['settings_header'] else None
            self.record['boundary_header_at_t'] = header
            out['boundary'] = matrix.classify_boundary(self.record.get('boundary_prediction'),
                                                       counts['at_t'], counts['at_t_plus_1'], header)
            consistency = {}
            for label in matrix.MULTI_LABELS:
                # Each export against the threshold it read itself (its own Part 1 pref).
                if label in closed and self.layouts.get(label) is not None:
                    consistency[label] = matrix.partition_layouts(self.layouts[label],
                                                                  self.record['artifacts'][label].get('threshold'))
            self.record['partition'] = consistency
            statuses = {v['status'] for v in consistency.values()}
            out['partition'] = ('CONSISTENT' if statuses == {'CONSISTENT'} else
                                'INCOMPLETE_EVIDENCE' if not statuses else 'INCONSISTENT')
        if entry['id'] == 'S-RICH' and fps.get('rich') is not None:
            out['rich_coverage'] = self.rich_coverage(fps['rich'])
        self.record['predictions'] = {k: {'predicted': v, 'status': matrix.prediction_status(v, out.get(k))}
                                      for k, v in entry['predictions'].items()}
        if entry['id'] in matrix.RICH_VALID_EVIDENCE:
            self.record['restore_evidence'] = self.restore_evidence(given)
        if entry['category'] == 'D' and entry['runnable']:
            self.record['malformed_evidence'] = self.malformed_evidence(given)
        if entry['category'] == 'E' and entry['runnable']:
            self.record['compat_evidence'] = self.compat_evidence(given)
        if entry['id'] == 'S-MULTI':
            readiness = matrix.multi_readiness(self.record, self.layouts, self.fingerprints,
                                               self.record.get('seed_sha256'))
            out.update(multi_source_ready=readiness['ready'], multi_source_missing=readiness['missing'])
            artifact = self.record['artifacts'].get('minimum')
            if isinstance(artifact, dict):
                artifact['source_ready'] = readiness['ready']
        if entry['category'] == 'B' and entry['runnable']:
            self.record['multipart_evidence'] = self.multipart_evidence(given)

    def multipart_evidence(self, given):
        """multipart evidence (cnt_firefox_matrix.multipart_evidence). Observation only: it never gates
        completion or changes a step, completion, classification or prediction, and a failure to compute
        or project it is contained here as a fixed REFUSED marker instead of failing the case."""
        try:
            if self.entry['source'] is None:
                return matrix.project(matrix.multipart_evidence(self.entry, self.fingerprints, None, None, None,
                                                                self.record, None))
            if given is None:
                given = self.given()
            return matrix.project(matrix.multipart_evidence(
                self.entry, self.fingerprints, given, self.original(), self.selected_fingerprints(), self.record,
                self.result.get('matrix_inputs')))
        except Exception:
            return {'schema': matrix.MULTIPART_EVIDENCE_SCHEMA, 'case': self.entry['id'], 'evidence': 'REFUSED'}

    def compat_evidence(self, given):
        """compatibility evidence (cnt_firefox_matrix.compat_evidence). Observation only: it never gates
        completion or changes a step, completion, classification or prediction, and a failure to compute
        or project it is contained here as a fixed REFUSED marker instead of failing the case."""
        try:
            if given is None and self.entry['source'] is not None:
                given = self.given()
            return matrix.project(matrix.compat_evidence(self.entry, self.fingerprints, given, self.original(),
                                                         self.record, self.result.get('matrix_inputs')))
        except Exception:
            return {'schema': matrix.COMPAT_EVIDENCE_SCHEMA, 'case': self.entry['id'], 'evidence': 'REFUSED'}

    def malformed_evidence(self, given):
        """malformed-input evidence (cnt_firefox_matrix.malformed_evidence). Observation only: it never
        gates completion or changes a step, completion, classification or prediction, and a failure to
        compute or project it is contained here as a fixed REFUSED marker instead of failing the case."""
        try:
            if given is None and self.entry['source'] is not None:
                given = self.given()
            return matrix.project(matrix.malformed_evidence(
                self.entry, self.fingerprints, given, self.original(), self.record,
                self.result.get('matrix_inputs'), matrix.input_shape(self.input_bytes())))
        except Exception:
            return {'schema': matrix.MALFORMED_EVIDENCE_SCHEMA, 'case': self.entry['id'], 'evidence': 'REFUSED'}

    def restore_evidence(self, given):
        """rich-valid evidence (cnt_firefox_matrix.restore_evidence). Observation only: it never
        gates completion or changes a classification, and a failure to compute or project it is
        contained here as a fixed REFUSED marker instead of failing the case."""
        try:
            if given is None and self.entry['source'] is not None:
                given = self.given()
            return matrix.project(matrix.restore_evidence(self.entry, self.fingerprints, given,
                                                          self.record, self.provenance))
        except Exception:
            return {'schema': matrix.RESTORE_EVIDENCE_SCHEMA, 'case': self.entry['id'], 'evidence': 'REFUSED'}

    def rich_coverage(self, fp):
        """Export-derived coverage (cnt_firefox_matrix.rich_coverage) plus the page-side
        target binding each task click recorded. Custom code entered through the CodeMirror
        library adapter counts only as OBSERVED in the export."""
        return matrix.rich_coverage(fp, self.provenance, [self.bindings.get(n) for n in
                                                          range(1, len(self.provenance['rich_tasks']) + 1)])

    def source_readiness(self):
        """Fixed S-RICH readiness. A complete-looking export that misses any requirement is
        never a usable source: the case stops MATRIX_RICH_SOURCE_INCOMPLETE with its parts and
        seed trace retained. This is a seed-artifact result, never a restore semantic."""
        readiness = matrix.rich_readiness(self.record['classifications'].get('rich_coverage'), self.provenance)
        self.record['classifications'].update(rich_source_ready=readiness['ready'],
                                              rich_source_missing=readiness['missing'])
        artifact = self.record['artifacts'].get('rich')
        if isinstance(artifact, dict):
            artifact['source_ready'] = readiness['ready']
        require(readiness['ready'], 'Matrix rich source incomplete')
        return {'rich_source_ready': True}

    def multi_source_readiness(self):
        """Fixed S-MULTI readiness (computed in classify()). A false gate is never a usable source: the
        case stops MATRIX_MULTI_SOURCE_INCOMPLETE with its parts, partition facts and evidence retained,
        so every B dependent is refused before launch. A seed-artifact result, never a restore semantic."""
        require(self.record['classifications'].get('multi_source_ready') is True, 'Matrix multi source incomplete')
        return {'multi_source_ready': True}


def open_settings(session):
    """Install the captured copy temporarily and open its native settings page."""
    client, run = session.client, session.run
    session.result['captured_code_loaded'] = True  # set before the attempt, never under-reported
    handles = client.call('WebDriver:GetWindowHandles', {})
    installed = client.call('Addon:Install', {'path': str(run / 'capture/clear-new-tab.xpi'),
                                              'temporary': True}, timeout=30)
    installed = installed.get('value') if isinstance(installed, dict) else installed
    require(installed == matrix.EXTENSION_ID, 'Matrix add-on identity mismatch')
    after = client.call('WebDriver:GetWindowHandles', {})
    before = handles.get('value', handles) if isinstance(handles, dict) else handles
    after = after.get('value', after) if isinstance(after, dict) else after
    session.record['install_new_windows'] = len([h for h in after or [] if h not in (before or [])])
    if before:
        client.call('WebDriver:SwitchToWindow', {'handle': before[0]})
    client.call('Marionette:SetContext', {'value': 'chrome'})
    try:
        url = script(client, 'return WebExtensionPolicy.getByID(arguments[0]).getURL("settings.html");',
                     [matrix.EXTENSION_ID])
    finally:
        client.call('Marionette:SetContext', {'value': 'content'})
    require(isinstance(url, str) and SETTINGS_URL.fullmatch(url) is not None, 'Matrix settings URL invalid')
    client.call('WebDriver:Navigate', {'url': url}, timeout=30)
    session.ready()


def exercise(client, run, result, case_id, provenance=None, clock=time.monotonic):
    """Run one catalogue case. Raises on any step failure; partial facts stay in result."""
    entry = matrix.case(case_id)
    require(entry['runnable'], 'Matrix case not drivable')
    provenance = provenance or matrix.load_provenance()
    session = Session(client, run, result, entry, provenance, clock)
    session.step('open_settings', lambda: open_settings(session))
    session.run_steps()
    session.classify()
    if entry['id'] == 'S-RICH':
        session.step('source_readiness', session.source_readiness)
    if entry['id'] == 'S-MULTI':
        session.step('source_readiness', session.multi_source_readiness)
    session.record['completed'] = True
    matrix.project(session.record)
    result['matrix_completed'] = True
    return session
