"""R6 matrix session against an in-process fake Marionette peer. No browser or captured code.

The fake models only the page facts the harness observes (counts, flags, captured Blobs);
it is a test double for the transport, never a stand-in used by production code.
"""
import base64
from decimal import Decimal
import hashlib
import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).resolve().parent / 'fixtures/cnt-native/firefox/6.12.1'
EXPORT = (FIXTURE / 'export.json').read_bytes()
EMPTY = EXPORT[:EXPORT.index(b'"chunks":[') + len(b'"chunks":[')] + b']}'
ID = 'clear-new-tab@loftyshaky'


def rows_export(count):
    """The accepted export with `count` rows (extra rows copy the last with a new id/rank)."""
    value = json.loads(EXPORT)
    while len(value['chunks']) < count:
        extra = json.loads(json.dumps(value['chunks'][-1]))
        extra['data']['id'] = f'bux-test-{len(value["chunks"]) + 1}'
        extra['data']['i'] = str(len(value['chunks']) + 1)
        value['chunks'].append(extra)
    return json.dumps(value, separators=(',', ':')).encode()


def split_export():
    """Native-shaped two-part set of the accepted export: settings plus rows 1-2, then rows 3-4."""
    value = json.loads(EXPORT)
    first = dict(value, chunks=value['chunks'][:2])
    return [json.dumps(first, separators=(',', ':')).encode(),
            json.dumps({'chunks': value['chunks'][2:]}, separators=(',', ':')).encode()]


PROVENANCE = json.loads((FIXTURE / 'static-matrix-provenance.json').read_text())
TEXT = ('one_backup_file_size_in_bytes', 'year', 'time')
CHECKBOXES = ('slideshow', 'home_btn_is_visible')
VAL_ACCESSOR = ('settings_context', 'background_size', 'background_position', 'background_repeat')
OVERRIDABLE = ('background_size', 'background_position', 'background_repeat')
NOT_INTERACTABLE = RuntimeError('Marionette protocol: other')


def valid(name, text, year=2026):
    """Static-derived test model of ui.validation.* (provenance offsets 1317247/1317403/1317479).
    Test-only: the harness never imports or evaluates it; the native validators decide."""
    import re
    if name == 'one_backup_file_size_in_bytes':
        return text != '' and re.fullmatch(r'[0-9]+', text) is not None and 52428800 <= int(text) <= 419430400
    if name == 'year':
        return text == '' or (re.fullmatch(r'2[0-9]{3}', text) is not None and int(text) >= year)
    return text == '' or re.fullmatch(r'(2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]', text) is not None


def replace_keys(start, keys, caret):
    """Native editing of a text field: returns every intermediate value an input event sees."""
    text, seen = list(start), []
    for key in keys:
        if key == '':
            if caret == 0:
                continue
            del text[caret - 1]
            caret -= 1
        elif key == '':
            if caret >= len(text):
                continue
            del text[caret]
        else:
            text.insert(caret, key)
            caret += 1
        seen.append(''.join(text))
    return seen


class Clock:
    """Deterministic session clock shared with the fake page's debounce model."""
    def __init__(self, step=0.05):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


class Fake:
    def __init__(self, run, clock=None):
        self.run = run
        self.clock = clock
        self.calls, self.typed, self.alerts = [], [], []
        self.ready, self.protecting, self.section = True, False, True
        self.backgrounds, self.tasks, self.transitions, self.section_transitions = 0, 0, 0, 0
        self.reports, self.captured = [], []
        defaults = PROVENANCE['facts']['defaults.prefs']['value']
        self.prefs = dict(defaults, year='', time='', day_of_the_month='', day_of_the_week='', month='')
        self.ui = {'settings_context': 'global', **{k: self.prefs[k] for k in OVERRIDABLE}}
        self.dom = {k: str(v) if not isinstance(v, bool) else v for k, v in self.prefs.items()}
        self.warn = set()
        self.exports = [[EMPTY]]
        self.late = []  # parts that arrive after `late_after` further state polls
        self.late_after, self.state_polls = 3, 0
        self.names = None
        self.restore_behaviour = 'ok'
        self.restore_rows = 4
        self.click_enters_context, self.overrides = True, {}
        self.scheduler, self.background_id, self.task_rows = False, None, []
        self.installed = ID
        self.page_digest = None
        self.short_slice = False
        self.fail_on = None
        # Fault injection: a control whose event never commits, a control left disabled.
        self.no_commit, self.disabled, self.caret_start = set(), set(), False
        self.revert_on_clear = False  # React restores a controlled value after a script clear
        self.persisted = {name: [] for name in TEXT}
        # Custom code: editors exist from boot, one shared gate counter and one shared debounce.
        self.editors = [' ', ' ', ' ']
        self.editor_count = 3
        self.code_open, self.gate, self.pending, self.saved = False, 0, None, {}
        self.debounce = 0.25
        self.add_enables = True
        self.scheduler_open_works = True
        # Further faults: overlay/close controls, override leakage, global restore, add no-op.
        self.code_opens, self.close_works, self.override_leaks = True, True, False
        self.global_restores, self.add_noop, self.resets_editors = True, False, True
        # Background clicks: the page-side id mark, scheduler clicks that do nothing (by ordinal)
        # and a centre click that lands on the item's delete button.
        self.mark, self.task_clicks, self.task_click_noop, self.click_hits_delete = None, 0, set(), set()
        # REPAIR2 background model: per rendered position an id, a rank string and the uploaded
        # bytes (ui.upload_ranks, ui.move_neighbours, ui.background_render_order); the page-side
        # target mark (ui.background_identity); task clicks that land on another existing item
        # (by ordinal); and an export built from this state (backup.chunk_order/task_placement).
        self.items, self.item_serial, self.target, self.fiber_hidden = [], 0, None, False
        self.task_click_other, self.moving, self.selected = {}, None, None
        self.item_overrides, self.task_model, self.clicked = {}, [], []
        # MALFORMED-D-PREP1: the native error ribbon (module-local report route, no wrapper code),
        # visible until reload, or only for `ribbon_polls` further state polls (it auto-hides).
        self.error_visible, self.ribbon_polls = False, 0

    # Marionette surface used by the session (ObservedClient.call signature).
    def call(self, method, params=None, timeout=10):
        params = params or {}
        self.calls.append(method)
        self.flush()
        if self.fail_on and self.fail_on[0] == method and len(self.calls) >= self.fail_on[1]:
            raise self.fail_on[2]
        handler = getattr(self, method.replace(':', '_'), None)
        return handler(params) if handler else {}

    # --- modelled native handlers (static facts ui.event.*, ui.override_routing) -------------
    def now(self):
        return self.clock.now if self.clock else 0.0

    def flush(self):
        if self.pending and self.now() - self.pending[2] >= self.debounce:
            self.saved[self.pending[0]] = self.pending[1]
            self.pending = None

    def shown(self, name):
        scheduled = self.prefs['mode'] == 'scheduled'
        if name in ('slideshow', 'background_change_effect', 'slide_direction'):
            return scheduled
        return True

    def enabled(self, name):
        if name in self.disabled:
            return False
        if name in ('background_change_effect', 'slide_direction'):
            return self.prefs['slideshow'] is True and (name != 'slide_direction'
                                                         or self.prefs['background_change_effect'] == 'slide')
        if name == 'home_btn_position':
            return self.prefs['home_btn_is_visible'] is True
        if name == 'day_of_the_month':
            return self.prefs['day_of_the_week'] == ''
        return True

    def react_global(self):
        self.ui['settings_context'] = 'global'
        if self.global_restores:
            self.ui.update({k: self.prefs[k] for k in OVERRIDABLE})

    def change(self, name, value):
        """Generic change: DOM value to page state, then the settings callback."""
        if name in self.no_commit:
            return
        self.dom[name] = value
        if name == 'settings_context':
            self.ui[name] = value
            if value == 'global':
                self.react_global()
            else:
                self.ui[name] = 'global'  # selected_background only notifies
        elif name in OVERRIDABLE:
            self.ui[name] = value
            if self.ui['settings_context'] == 'global':
                self.prefs[name] = value
            elif self.ui['settings_context'] == 'selected_background':
                self.overrides[name] = value
                self.item_overrides.setdefault(self.selected, {})[name] = value
                if self.override_leaks:
                    self.prefs[name] = value
        else:
            self.prefs[name] = value

    def text_input(self, name, value):
        """onInput: raw string to the page pref; a valid value is coerced and persisted."""
        self.dom[name] = value
        if name in self.no_commit:
            return
        self.prefs[name] = value
        if valid(name, value):
            self.warn.discard(name)
            self.prefs[name] = int(value) if name == 'one_backup_file_size_in_bytes' else value
            self.persisted[name].append(self.prefs[name])
        else:
            self.warn.add(name)

    def interactable(self, name):
        if not (self.shown(name) and self.enabled(name)):
            raise NOT_INTERACTABLE

    def add_enabled(self):
        fields = any(self.prefs[k] != '' for k in ('year', 'time', 'day_of_the_month'))
        return (self.add_enables and self.background_id is not None and fields
                and not self.warn & {'year', 'time'})

    def observe(self, names, expected):
        def control(name):
            value = self.dom.get(name, '')
            return {'present': True, 'dom': value, 'length': 0 if isinstance(value, bool) else len(str(value)),
                    'shown': self.shown(name), 'enabled': self.enabled(name), 'warn': name in self.warn,
                    'pref': self.prefs.get(name), 'ui': self.ui.get(name)}
        out = {'context': self.ui['settings_context'], 'backgrounds': self.backgrounds, 'tasks': self.tasks,
               'scheduler': self.scheduler, 'code_editor': self.code_open,
               'background_id': self.background_id is not None,
               'background_changed': self.mark is not None and self.background_id != self.mark[0],
               'target_identity': self.target is not None,
               'background_matches_target': self.target is not None and self.background_id == self.target,
               'add_task': {'present': True, 'shown': self.scheduler, 'enabled': self.add_enabled()},
               'controls': {n: control(n) for n in names}}
        if isinstance(expected, list):
            out['editors'] = self.editor_state(expected)
        return out

    def editor_state(self, expected):
        return {'open': self.code_open, 'count': self.editor_count,
                'items': [{'ready': True, 'length': len(v), 'matches': i < len(expected) and v == expected[i]}
                          for i, v in enumerate(self.editors[:self.editor_count])]}

    def set_editor(self, index, value):
        self.editors[index] = value
        if self.gate >= 3:
            self.pending = (('html', 'css', 'js')[index], value, self.now())
        self.gate += 1

    def WebDriver_GetWindowHandles(self, _):
        return {'value': ['h1']}

    def Addon_Install(self, params):
        assert params['temporary'] is True and params['path'].endswith('capture/clear-new-tab.xpi')
        return {'value': self.installed}

    def WebDriver_ExecuteScript(self, params):
        source, args = params['script'], params['args']
        if 'WebExtensionPolicy' in source:
            return {'value': 'moz-extension://12345678-1234-1234-1234-123456789abc/settings.html'}
        assert params['sandbox'] is None and params['newSandbox'] is False
        if source.startswith('// R6 Firefox matrix page helper'):
            return {'value': 'INSTALLED'}
        if 'document.querySelector(s.ready)' in source:
            return {'value': self.ready}
        if '.state(' in source:
            self.state_polls += 1
            if self.late and self.state_polls >= self.late_after:
                self.captured.append(self.late.pop(0))
                self.state_polls = 0
            ribbon = self.error_visible or self.ribbon_polls > 0
            self.ribbon_polls = max(0, self.ribbon_polls - 1)
            return {'value': {'ready': self.ready, 'protecting': self.protecting, 'error_visible': ribbon,
                              'reports': len(self.reports), 'loud_reports': sum(not r['silent'] for r in self.reports),
                              'backgrounds': self.backgrounds, 'tasks': self.tasks,
                              'section_visible': self.section, 'transitions': self.transitions,
                              'section_transitions': self.section_transitions,
                              'captured': len(self.captured), 'report_recorder': True}}
        if '.observe(' in source:
            names, expected = args
            assert all(isinstance(n, str) for n in names) and len(names) <= 8
            return {'value': self.observe(names, expected)}
        if '.button(' in source:
            selector = args[0]
            if 'add_new_task' in selector:
                return {'value': {'present': True, 'shown': self.scheduler, 'enabled': self.add_enabled()}}
            if 'close_code_editor' in selector:
                return {'value': {'present': True, 'shown': self.code_open, 'enabled': True}}
            return {'value': {'present': True, 'shown': True, 'enabled': True}}
        if '.clear()' in source:
            self.captured = []
            return {'value': 0}
        if '.captured()' in source:
            names = self.names or [i + 1 for i in range(len(self.captured))]
            return {'value': [{'index': i, 'name': f'Clear New Tab back up 1/2/2031, 03:04:05 Part {names[i]}.json',
                               'size': len(b)} for i, b in enumerate(self.captured)]}
        if '.code(' in source:
            index, value = args
            if index >= self.editor_count:
                return {'value': -1}
            self.set_editor(index, value)
            return {'value': self.editor_count}
        if '.mark_target(' in source:
            index = args[0]
            if not (isinstance(index, int) and 0 <= index < self.backgrounds):
                self.target = None
                return {'value': {'element': None, 'bound': False}}
            self.target = None if self.fiber_hidden else self.item_id(index)
            return {'value': {'element': {'element-6066-11e4-a52e-4f735466cecf': f'bg|{index}'},
                              'bound': self.target is not None}}
        if '.mark_background(' in source:
            self.mark = (self.background_id,)
            return {'value': self.background_id is not None}
        if '.reports(' in source:
            return {'value': self.reports[args[0]:]}
        raise AssertionError(source[:60])

    def WebDriver_ExecuteAsyncScript(self, params):
        source, args = params['script'], params['args']
        if '__buxMatrix.slice(' in source:
            index, start, end = args
            raw = self.captured[index][start:end]
            if self.short_slice:
                raw = raw[:-1]
            return {'value': {'ok': True, 'value': base64.b64encode(raw).decode()}}
        if '__buxMatrix.sha256(' in source:
            digest = self.page_digest or hashlib.sha256(self.captured[args[0]]).hexdigest()
            return {'value': {'ok': True, 'value': digest}}
        raise AssertionError(source[:60])

    def WebDriver_FindElements(self, params):
        selector = params['value']
        if selector.startswith('select[name='):
            name = selector.split('"')[1]
            value = selector.split('"')[3]
            ids = [f'opt|{name}|{value}']
        elif selector.startswith('.input_w.checkbox.'):
            ids = ['box|' + selector.split('.')[3].split(' ')[0]]
        elif selector.startswith('input[name='):
            ids = ['text|' + selector.split('"')[1]]
        elif selector.endswith('.scrollable .ui'):
            ids = [f'bg|{i}' for i in range(self.backgrounds)]
        elif selector == '.delete_background_btn':
            ids = [f'.delete_background_btn|{i}' for i in range(self.backgrounds)]
        else:
            ids = [selector + (('@' + params['element']) if 'element' in params else '')]
        return {'value': [{'element-6066-11e4-a52e-4f735466cecf': i} for i in ids]}

    def WebDriver_ElementClick(self, params):
        target = params['id']
        if target.startswith('opt|'):
            _, name, value = target.split('|')
            self.interactable(name)
            # WebDriver fires input/change on the select; React onChange commits.
            self.change(name, value)
        elif target.startswith('bg|'):
            index = int(target.split('|')[1])
            self.clicked.append(index)
            kind = 'task' if self.scheduler else 'context'
            if kind in self.click_hits_delete:
                self.delete(index)  # the delete button stops propagation: nothing is selected
                return
            if self.scheduler:
                self.task_clicks += 1
                if self.task_clicks in self.task_click_noop:
                    return
                # The task background, never the context; a mis-hit lands on another item.
                self.background_id = self.item_id(self.task_click_other.get(self.task_clicks, index))
            elif self.click_enters_context:
                self.ui['settings_context'] = 'selected_background'
                self.ui.update({k: 'global' for k in OVERRIDABLE})
                self.selected = self.item_id(index)
        elif target.startswith('.btn_w.open_scheduler'):
            self.scheduler = self.scheduler_open_works
        elif target.startswith('.btn_w.close_scheduler'):
            self.scheduler = False
        elif target.startswith('.btn_w.custom_code'):
            self.code_open = self.code_opens
            if self.code_open and self.resets_editors:
                for index, value in enumerate(self.editors):  # the overlay resets every editor
                    self.set_editor(index, value)
        elif target.startswith('.btn_w.close_code_editor'):
            self.code_open = self.code_open and not self.close_works
        elif target.startswith('box|'):
            name = target.split('|')[1]
            self.interactable(name)
            if name not in self.no_commit:
                self.prefs[name] = self.dom[name] = not self.prefs.get(name, False)
        elif target.startswith('.btn_w.download_back_up'):
            parts = self.exports.pop(0) if len(self.exports) > 1 else self.exports[0]
            self.captured = ([self.export_model()] if parts == 'MODEL' else
                             [self.export_model(rows=False)] if parts == 'MODEL_EMPTY' else list(parts))
            self.state_polls = 0
        elif target.startswith('.delete_background_btn'):
            self.delete(int(target.split('|')[1]))
        elif target.startswith(PROVENANCE['selectors']['move']) and '@bg|' in target:
            self.moving = int(target.split('@bg|')[1])
        elif target.startswith('.btn_w.add_new_task'):
            if not self.add_enabled():
                raise NOT_INTERACTABLE  # is_disabled: pointer-events none
            if self.add_noop:
                return
            self.tasks += 1
            self.task_rows.append({k: self.prefs[k] for k in ('year', 'time', 'day_of_the_month')})
            # ui.task_add_background: the task copies the task background id, no fallback.
            self.task_model.append({'id': f'task{self.tasks}', 'i': str(self.tasks),
                                    'background_id': self.background_id, 'year': self.prefs['year'],
                                    'day_of_the_week': self.prefs['day_of_the_week'], 'month': self.prefs['month'],
                                    'day_of_the_month': self.prefs['day_of_the_month'], 'time': self.prefs['time']})

    def WebDriver_ElementClear(self, params):
        # The superseded route: a script property write plus change, never an input event.
        name = params['id'].split('|')[1]
        self.dom[name] = ''
        if self.revert_on_clear and self.prefs[name] != '':
            self.dom[name] = str(self.prefs[name])  # controlled re-render after blur

    def WebDriver_ElementSendKeys(self, params):
        target, text = params['id'], params['text']
        self.typed.append((target, text))
        if target.startswith('text|'):
            name = target.split('|')[1]
            self.interactable(name)
            start = str(self.dom[name])
            for value in replace_keys(start, text, 0 if self.caret_start else len(start)):
                self.text_input(name, value)
            return
        if target.startswith('.input_w.upload_box'):
            paths = text.split('\n')
            if len(self.items) == self.backgrounds:  # ui.upload_first_rank: '0' when empty
                last = Decimal(self.items[-1]['i']) if self.items else Decimal(0)
                for n, path in enumerate(paths, 1):
                    self.item_serial += 1
                    self.items.append({'id': f'1790{self.item_serial:09d}bux', 'i': str(last + n),
                                       'raw': Path(path).read_bytes()})
            self.backgrounds += len(paths)
        elif target.startswith('input.file.back_up'):
            behaviour = (self.restore_behaviour.pop(0) if isinstance(self.restore_behaviour, list)
                         else self.restore_behaviour)
            self.transitions += 1  # any document transition; never start evidence by itself
            if behaviour in ('dropped', 'unrelated'):
                return
            self.section_transitions += 1  # the section fade that performs the native deletion
            if behaviour == 'error':
                self.reports.append({'code': 'cnt_1556', 'silent': False})
            elif behaviour == 'silent':
                self.protecting, self.section = True, False
            elif behaviour == 'ribbon':  # restore.report_route: ribbon only, no wrapper code
                self.backgrounds, self.error_visible = self.restore_rows, True
            elif behaviour == 'ribbon_flash':  # the ribbon auto-hides before the final read
                self.section_transitions += 1
                self.backgrounds, self.ribbon_polls = self.restore_rows, 2
            elif behaviour == 'hidden':  # started, then no completion signal of any kind
                self.section, self.backgrounds = False, self.restore_rows
            elif behaviour in ('ok', 'silent_report'):
                self.section_transitions += 1
                self.backgrounds = self.restore_rows
                if behaviour == 'silent_report':
                    self.reports.append({'code': 'cnt_1999', 'silent': True})

    def WebDriver_SendAlertText(self, params):
        self.alerts.append(('text', params['text']))

    def WebDriver_AcceptAlert(self, params):
        self.alerts.append(('accept',))
        texts = [a[1] for a in self.alerts if a[0] == 'text']
        if self.moving is not None and texts and len(self.items) == self.backgrounds:
            self.move(self.moving, int(texts[-1]))
        self.moving = None

    # --- background model helpers ------------------------------------------------------------
    def item_id(self, index):
        return self.items[index]['id'] if len(self.items) == self.backgrounds else f'bg{index}'

    def delete(self, index):
        if len(self.items) == self.backgrounds:
            removed = self.items.pop(index)['id']
            if self.background_id == removed:  # deletion resets the task background id
                self.background_id = None
        self.backgrounds -= 1

    def move(self, source, position):
        """ui.move_neighbours for a move to an earlier position: dropped left of the item at
        `position`; the moved rank is the midpoint of the ranks either side (minus 1 at the
        start), then the collection is re-sorted by rank."""
        at = position - 1
        assert 0 <= at < source, 'the fake models only moves to an earlier position'
        ranks = [Decimal(item['i']) for item in self.items]
        new = ranks[at] - 1 if at == 0 else (ranks[at - 1] + ranks[at]) / 2
        self.items[source]['i'] = str(new)
        self.items.sort(key=lambda item: Decimal(item['i']))

    def WebDriver_Refresh(self, params):
        self.error_visible, self.ribbon_polls = False, 0

    def export_model(self, rows=True):
        """A native-shaped export of this model: one chunk per item in collection order, each
        with exactly the tasks on its id; prefs, the saved custom code and the overrides. Without
        rows: the same settings and custom code with every row and task gone."""
        value = json.loads(EXPORT)
        template = value['chunks'][0]
        value['settings']['prefs'].update(self.prefs)
        value['custom_code'].update(self.saved)
        chunks = []
        for item in self.items if rows else ():
            chunk = json.loads(json.dumps(template))
            chunk['data'].update(id=item['id'], i=item['i'], **self.item_overrides.get(item['id'], {}))
            chunk['file']['background'] = 'data:image/png;base64,' + base64.b64encode(item['raw']).decode()
            chunk['tasks'] = [dict(t) for t in self.task_model if t['background_id'] == item['id']]
            chunks.append(chunk)
        value['chunks'] = chunks
        return json.dumps(value, separators=(',', ':')).encode()


@pytest.fixture
def s(monkeypatch, repo_root, tmp_path):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_matrix as matrix
    import cnt_firefox_matrix_session as session
    monkeypatch.setattr(session, 'SETTLE', 0.0)
    monkeypatch.setattr(session, 'QUIET', 0.3)
    monkeypatch.setattr(session, 'DEADLINES', {k: 0.6 for k in session.DEADLINES})
    run = tmp_path / 'attempt'
    (run / 'capture').mkdir(parents=True)
    return session, matrix, run


def start(session, matrix, run, case_id, fake=None, result=None, clock=None):
    clock = clock or Clock()
    fake = fake or Fake(run, clock)
    result = result if result is not None else {}
    entry = matrix.case(case_id)
    return session.Session(fake, run, result, entry, matrix.load_provenance(), clock), fake, result


def trace(result):
    return {e['action']: e for e in result['matrix']['seed_trace']}


def test_chunked_readout_digest_and_frame_bound(s, monkeypatch):
    session, matrix, run = s
    monkeypatch.setattr(session, 'SLICE', 1000)
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.exports, fake.backgrounds = [[EXPORT]], 4
    assert sess.export('rich')['parts'] == 1
    assert (run / 'artifacts/rich/part-1.json').read_bytes() == EXPORT
    assert fake.calls.count('WebDriver:ExecuteAsyncScript') == -(-len(EXPORT) // 1000) + 1
    parts = result['matrix']['artifacts']['rich']['parts']
    assert parts == [{'index': 0, 'name_class': 'NATIVE_PART_1', 'bytes': len(EXPORT),
                      'sha256': hashlib.sha256(EXPORT).hexdigest()}]
    manifest = json.loads((run / 'artifacts/MANIFEST.json').read_text())
    assert manifest['rich'] == parts
    # The production slice keeps each base64 reply inside the 1 MiB Marionette frame.
    assert 4 * -(-512 * 1024 // 3) + 256 < 1024 * 1024


@pytest.mark.parametrize('damage', ['page-digest', 'short-slice'])
def test_readout_mismatch_refuses(s, damage):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.exports = [[EXPORT]]
    if damage == 'page-digest':
        fake.page_digest = '0' * 64
    else:
        fake.short_slice = True
    with pytest.raises(session.VerificationError, match='Artifact readout mismatch'):
        sess.export('rich')


def test_file_selection_confined_to_run_and_ordered(s, tmp_path):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    inside = [run / 'inputs/a.png', run / 'inputs/b.png']
    (run / 'inputs').mkdir()
    for p in inside:
        p.write_bytes(b'x')
    sess.choose_files('.input_w.upload_box.upload_background input[type=file]', list(reversed(inside)))
    assert fake.typed[-1][1] == f'{inside[1]}\n{inside[0]}'
    outside = tmp_path / 'outside.png'
    outside.write_bytes(b'x')
    link = run / 'inputs/link.png'
    link.symlink_to(outside)
    for bad in (outside, link, Path('relative.png')):
        with pytest.raises(session.VerificationError, match='Matrix input path outside run'):
            sess.choose_files('x', [bad])


def test_rich_seed_uses_native_prompt_flow(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.seed_rich()
    assert fake.alerts == [('text', '2'), ('accept',)]
    clicks = [c for c in fake.calls if c.startswith('WebDriver:') and 'Alert' in c]
    assert clicks == ['WebDriver:SendAlertText', 'WebDriver:AcceptAlert']
    assert fake.backgrounds == 5 and fake.tasks == 2
    assert fake.prefs['mode'] == 'scheduled' and fake.prefs['one_backup_file_size_in_bytes'] == 209715200
    # The override went to the selected background; the global value is untouched.
    assert fake.overrides == {'background_size': 'stretch_browser'}
    assert fake.prefs['background_size'] == 'fit_browser' and fake.ui['settings_context'] == 'global'
    assert fake.ui['background_size'] == 'fit_browser'
    # Every editor saved through the native gate and its own debounce window.
    assert fake.saved == dict(zip(('html', 'css', 'js'), session.RICH_CODE)) and not fake.code_open
    assert fake.task_rows == [{'year': '2031', 'time': '12:34:56', 'day_of_the_month': ''},
                              {'year': '2032', 'time': '07:08:09', 'day_of_the_month': '4'}]
    # Every seed file is harness-authored and inside the owned run.
    assert all(Path(p).is_relative_to(run) for t, text in fake.typed if t.startswith('.input_w')
               for p in text.split('\n'))
    record = result['matrix']
    assert record['seed_failed_action'] is None
    assert all(e['status'] in ('DONE', 'SKIPPED') for e in record['seed_trace'])
    matrix.validate_trace(record['seed_trace'])


def test_rich_seed_fails_when_background_click_does_not_enter_context(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.click_enters_context = False
    with pytest.raises(session.VerificationError, match='Matrix UI value not applied'):
        sess.seed_rich()
    # The override was never sent to the global pref, and the failure names the action.
    assert fake.prefs['background_size'] == 'fit_browser' and not fake.overrides
    assert result['matrix']['seed_failed_action'] == 'context:select_background'
    entry = trace(result)['context:select_background']
    assert entry['after']['context'] == 'global' and entry['failure']['code'] == 'MATRIX_UI_VALUE_NOT_APPLIED'
    assert 'override:background_size' not in trace(result)


def test_readiness_deadline(s):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    fake.ready = False
    with pytest.raises(session.VerificationError, match='Matrix readiness deadline'):
        sess.ready()
    assert session.SESSION_CODES['Matrix readiness deadline'] == 'MATRIX_READINESS_DEADLINE'


def inputs(run, result, parts):
    (run / 'inputs/source').mkdir(parents=True)
    selection = []
    for n, raw in enumerate(parts, 1):
        (run / f'inputs/source/part-{n}.json').write_bytes(raw)
        target = run / 'inputs/select/0' / f'bux-matrix Part {n}.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        selection.append({'named_part': n, 'slot': 0, 'part_number': n, 'sha256': hashlib.sha256(raw).hexdigest()})
    result['matrix_inputs'] = {'source': [{'part_number': n, 'bytes': len(r), 'sha256': hashlib.sha256(r).hexdigest()}
                                          for n, r in enumerate(parts, 1)], 'selection': selection}


@pytest.mark.parametrize('case_id,behaviour,expected,error,started', [
    ('D-TRUNC-P1', 'silent', 'DEADLINE_NO_SIGNAL', None, True),
    ('D-TRUNC-P1', 'error', 'ERROR_REPORTED', True, True),
    ('T-RICH', 'ok', 'COMPLETED', False, True),
    ('T-RICH', 'silent_report', 'SILENT_REPORTED', None, True),
    # No start evidence: quiescence is never completion, and no verdict is drawn.
    ('D-TRUNC-P1', 'dropped', 'DEADLINE_NO_SIGNAL', None, False),
    ('D-TRUNC-P1', 'unrelated', 'DEADLINE_NO_SIGNAL', None, False)])
def test_restore_completion_signals(s, case_id, behaviour, expected, error, started):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, case_id, result=result)
    inputs(run, result, [EXPORT])
    fake.restore_behaviour = behaviour
    outcome = sess.restore()
    assert outcome['completion'] == expected
    assert outcome['restore_error'] is error
    assert outcome['start_observed'] is started
    # Only section-content transitions count; a document transition alone is not evidence.
    assert outcome['transition_end_observed'] is started
    assert outcome['error_ribbon_seen'] is False  # this Fake page never shows the ribbon here
    if behaviour == 'error':
        assert outcome['error_codes'] == ['cnt_1556']
    if behaviour == 'silent_report':
        assert outcome['silent_codes'] == ['cnt_1999'] and outcome['error_codes'] == []


@pytest.mark.parametrize('behaviour', ['silent', 'dropped', 'unrelated'])
def test_no_signal_is_a_failure_where_a_restore_must_complete(s, behaviour):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-RICH', result=result)
    inputs(run, result, [EXPORT])
    fake.restore_behaviour = behaviour
    with pytest.raises(session.VerificationError, match='Matrix step deadline'):
        sess.restore()


def test_dropped_restore_is_never_preservation_in_a_seeded_target(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'D-TRUNC-P1', result=result)
    inputs(run, result, [EXPORT])
    fake.restore_behaviour = 'dropped'
    sess.restore()
    # Identical pre and post would read as preservation if absence were accepted as evidence.
    sess.fingerprints.update(pre=matrix.fingerprint([EXPORT]), post=matrix.fingerprint([EXPORT]))
    sess.classify()
    classes = result['matrix']['classifications']
    assert {classes[k] for k in ('backgrounds', 'tasks', 'settings', 'custom_code')} == {'INCOMPLETE_EVIDENCE'}


def test_export_waits_for_late_parts_until_closed(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    first, second = split_export()
    fake.exports, fake.late, fake.backgrounds = [[first]], [second], 4
    fake.late_after = 4  # after the first part has settled and been read
    outcome = sess.export('rich')
    assert outcome == {'label': 'rich', 'parts': 2, 'closure': 'CLOSED'}
    record = result['matrix']['artifacts']['rich']
    assert [p['name_class'] for p in record['parts']] == ['NATIVE_PART_1', 'NATIVE_PART_2']
    assert record['derived']['row_count'] == 4 and record['expected_rows'] == 4


@pytest.mark.parametrize('case_id,label,required', [('S-RICH', 'rich', True), ('S-MULTI', 'minimum', True),
                                                    ('S-MULTI', 'calibration', True), ('T-RICH', 'pre', True),
                                                    ('S-MULTI', 'at_t', False), ('T-RICH', 'post', False)])
def test_truncated_export_is_never_accepted(s, case_id, label, required):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, case_id)
    fake.exports, fake.backgrounds = [[split_export()[0]]], 4  # the second part never arrives
    if required:
        with pytest.raises(session.VerificationError, match='Matrix export incomplete'):
            sess.export(label)
    else:
        assert sess.export(label)['closure'] == 'ROWS_SHORT'
        assert sess.fingerprints[label] is None and sess.layouts[label] is None
    assert result['matrix']['artifacts'][label]['closure'] == 'ROWS_SHORT'
    assert session.SESSION_CODES['Matrix export incomplete'] == 'MATRIX_EXPORT_INCOMPLETE'


@pytest.mark.parametrize('names,rows,closure', [([2, 1], 4, 'PART_SEQUENCE_BROKEN'), ([1, 3], 4, 'PART_SEQUENCE_BROKEN'),
                                                (None, 3, 'ROWS_EXCESS')])
def test_export_closure_classes(s, names, rows, closure):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'T-RICH')
    fake.exports, fake.names, fake.backgrounds = [split_export()], names, rows
    assert sess.export('post')['closure'] == closure
    assert sess.fingerprints['post'] is None


def test_unclosed_multipart_exports_are_not_classified(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-MULTI')
    fake.exports, fake.backgrounds = [[split_export()[0]]], 4
    sess.thresholds.update(predicted=100, predicted_plus_1=101)
    sess.record['boundary_prediction'] = {'threshold': 100, 'in_ui_range': True, 'header_adjusted_bytes': 1}
    sess.export('at_t')
    sess.export('at_t_plus_1')
    sess.classify()
    assert result['matrix']['classifications']['boundary'] == 'INCOMPLETE_EVIDENCE'
    assert result['matrix']['classifications']['partition'] == 'INCOMPLETE_EVIDENCE'


def test_repeat_rejected_second_import_is_not_idempotent(s):
    session, matrix, run = s
    result = {}
    inputs(run, result, [EXPORT])
    fake = Fake(run)
    fake.exports = [[EMPTY], [EXPORT], [EXPORT]]
    fake.restore_behaviour = ['ok', 'error']
    session.exercise(fake, run, result, 'F-REPEAT')
    assert [r['restore_error'] for r in result['matrix']['restores']] == [False, True]
    assert result['matrix']['classifications']['repeat'] == 'REJECTED_ON_REPEAT'
    assert result['matrix']['predictions']['repeat'] == {'predicted': 'IDEMPOTENT', 'status': 'MISMATCH'}


def test_restore_input_digest_rechecked(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-RICH', result=result)
    inputs(run, result, [EXPORT])
    (run / 'inputs/select/0/bux-matrix Part 1.json').write_bytes(EXPORT + b' ')
    with pytest.raises(session.VerificationError, match='Matrix input digest mismatch'):
        sess.restore()


@pytest.mark.parametrize('case_id,exported', [('T-RICH', EXPORT), ('D-TRUNC-P1', EMPTY)])
def test_pre_restore_state_leakage_detected(s, case_id, exported):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, case_id)
    fake.exports = [[exported]]
    fake.backgrounds = matrix.fingerprint([exported])['derived']['row_count']  # the page agrees
    with pytest.raises(session.VerificationError, match='Cross-case state leakage'):
        sess.pre_export()


def test_interrupt_leaves_partial_step_evidence(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.fail_on = ('WebDriver:ExecuteAsyncScript', 0, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        sess.step('export:rich', lambda: sess.export('rich'))
    assert result['matrix']['steps'][-1] == {'step': 'export:rich', 'status': 'FAILED',
                                             'error_type': 'KeyboardInterrupt'}
    assert result['matrix']['completed'] is False


def test_addon_identity_checked_and_load_never_under_reported(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'S-RICH', result=result)
    fake.installed = 'other@example.invalid'
    with pytest.raises(session.VerificationError, match='Matrix add-on identity mismatch'):
        session.open_settings(sess)
    assert result['captured_code_loaded'] is True


def test_unverified_static_fact_blocks_before_ui(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.provenance['facts']['ui.upload_input']['status'] = 'UNVERIFIED'
    before = len(fake.calls)
    with pytest.raises(session.VerificationError, match='Matrix static fact unverified'):
        sess.upload('rich', 'upload')
    assert len(fake.calls) == before and result['matrix']['blocked_facts'] == ['ui.upload_input']
    assert session.SESSION_CODES['Matrix static fact unverified'] == 'BLOCKED_STATIC_UNVERIFIED'


def test_full_source_case_completes_and_projects(s):
    session, matrix, run = s
    result, clock = {}, Clock()
    fake = Fake(run, clock)
    fake.exports = [[EMPTY], 'MODEL']  # the export the seeded model state produces
    session.exercise(fake, run, result, 'S-RICH', clock=clock)
    assert result['matrix_completed'] is True and result['matrix']['completed'] is True
    assert [st['step'] for st in result['matrix']['steps']] == ['open_settings', 'pre_export', 'seed_rich',
                                                                'export:rich', 'source_readiness']
    coverage = result['matrix']['classifications']['rich_coverage']
    assert coverage['duplicate_content'] is True and coverage['rank_class'] == 'FRACTIONAL'
    assert result['matrix']['classifications']['rich_source_ready'] is True
    matrix.project(result['matrix'])


def test_full_target_case_classifies_against_inputs(s):
    session, matrix, run = s
    result = {}
    inputs(run, result, [EXPORT])
    fake = Fake(run)
    fake.exports = [[EMPTY], [EXPORT]]
    session.exercise(fake, run, result, 'T-RICH')
    c = result['matrix']['classifications']
    assert c['backgrounds'] == 'RESTORED' and c['ranks'] == 'RANK_PRESERVED'
    assert result['matrix']['predictions']['backgrounds'] == {'predicted': 'RESTORED', 'status': 'MATCH'}
    assert 'WebDriver:Refresh' in fake.calls


def test_not_drivable_case_refused(s):
    session, matrix, run = s
    with pytest.raises(session.VerificationError, match='Matrix case not drivable'):
        session.exercise(Fake(run), run, {}, 'D-EMPTY-SELECTION')


def test_no_storage_serializer_or_chrome_route(repo_root):
    for name in ('tests/cnt_firefox_matrix_session.py', 'tests/cnt_firefox_matrix_page.js',
                 'tests/cnt_firefox_matrix.py'):
        text = (repo_root / name).read_text()
        for token in ('indexedDB', 'storage.local', 'browser.storage', 'chrome.storage', 'IDBFactory',
                      'CDPPipe', 'cnt_synthetic_chrome', 'remote-debugging'):
            assert token not in text, (name, token)
    js = (repo_root / 'tests/cnt_firefox_matrix_page.js').read_text()
    assert len(js.encode()) <= 16 * 1024 and 'originalReport.apply(this, arguments)' in js
    assert 'originalURL.call(URL, object)' in js
    # Restore-start evidence counts only transitions targeting the section-content element.
    assert 'event.target.matches(selectors.section)' in js and 'section_transitions: sectionTransitions' in js
    assert "return 'REFUSED'" in js


# --- SRICH-REPAIR1: native routes and per-action attribution ----------------------------------

RICH = [(kind, name, value) for kind, name, value in PROVENANCE['rich_prefs']]


def seed_fails(session, matrix, run, setup, message='Matrix UI value not applied'):
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    setup(fake)
    with pytest.raises(session.VerificationError, match=message):
        sess.seed_rich()
    record = result['matrix']
    failed = [e for e in record['seed_trace'] if e['status'] == 'FAILED']
    assert len(failed) == 1 and failed[0] is record['seed_trace'][-1]
    assert failed[0]['action'] == record['seed_failed_action']
    assert all(e['status'] in ('DONE', 'SKIPPED') for e in record['seed_trace'][:-1])
    matrix.validate_trace(record['seed_trace'])
    return record, failed[0], fake


@pytest.mark.parametrize('kind,name,value', RICH, ids=[n for _, n, _ in RICH])
def test_each_rich_preference_failure_is_attributed(s, kind, name, value):
    session, matrix, run = s
    record, failed, fake = seed_fails(session, matrix, run, lambda f: f.no_commit.add(name))
    assert failed['action'] == f'pref:{name}' and failed['failure']['code'] == 'MATRIX_UI_VALUE_NOT_APPLIED'
    assert failed['route'] == {'select': 'option_click', 'checkbox': 'box_click', 'text': 'keys_replace'}[kind]
    names = [n for _, n, _ in RICH]
    started = [e['action'] for e in record['seed_trace'] if e['action'].startswith('pref:')]
    assert started == [f'pref:{n}' for n in names[:names.index(name) + 1]]  # nothing later started
    before, after = failed['before']['controls'][name], failed['after']['controls'][name]
    default = PROVENANCE['facts']['defaults.prefs']['value'][name]
    assert before['state'] == default and after['state'] == default  # never committed
    if kind == 'text':
        assert after['dom'] == str(value) and after['wrapper']['warn'] is False
    assert failed['expected'] == value


def test_hosts1_shaped_text_defect_old_route_appends_new_route_commits(s):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    fake.revert_on_clear = True
    # The superseded route: a script clear the controlled input restores, then typing appends.
    fake.call('WebDriver:ElementClear', {'id': 'text|one_backup_file_size_in_bytes'})
    fake.call('WebDriver:ElementSendKeys', {'id': 'text|one_backup_file_size_in_bytes', 'text': '209715200'})
    assert fake.prefs['one_backup_file_size_in_bytes'] == '419430400209715200'
    assert 'one_backup_file_size_in_bytes' in fake.warn and fake.persisted['one_backup_file_size_in_bytes'] == []
    # The native key route from the same page state commits the typed number.
    fake2 = Fake(run, fake.clock)
    fake2.revert_on_clear = True
    sess2 = session.Session(fake2, run, {}, matrix.case('S-RICH'), matrix.load_provenance(), fake.clock)
    sess2.text('one_backup_file_size_in_bytes', 209715200)
    assert fake2.prefs['one_backup_file_size_in_bytes'] == 209715200
    assert fake2.persisted['one_backup_file_size_in_bytes'] == [209715200]
    assert 'WebDriver:ElementClear' not in fake2.calls


@pytest.mark.parametrize('caret_start', [False, True])
def test_text_route_commits_from_either_caret_end(s, caret_start):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.caret_start = caret_start
    fake.prefs.update(year='2031', time='12:34:56')
    fake.dom.update(year='2031', time='12:34:56')
    sess.text('year', '2032', action='task:2:year')
    sess.text('time', '07:08:09', action='task:2:time')
    assert (fake.prefs['year'], fake.prefs['time']) == ('2032', '07:08:09')
    typed = [t for target, t in fake.typed if target == 'text|year']
    assert typed == [session.BACKSPACE * 4 + session.DELETE * 4 + '2032']


@pytest.mark.parametrize('name,start_value,target', [
    ('one_backup_file_size_in_bytes', '419430400', '209715200'), ('year', '', '2031'),
    ('year', '2031', '2032'), ('time', '', '12:34:56'), ('time', '12:34:56', '07:08:09')])
def test_no_unintended_intermediate_passes_the_validator(s, name, start_value, target):
    """Exhaustive over every caret position: only '' (itself valid for year/time) or the final
    value can pass the static-derived validator model, so nothing else is persisted."""
    session, _, _ = s
    keys = session.BACKSPACE * len(start_value) + session.DELETE * len(start_value) + target
    for caret in range(len(start_value) + 1):
        seen = replace_keys(start_value, keys, caret)
        assert seen[-1] == target
        persisted = [v for v in seen if valid(name, v)]
        assert set(persisted) <= {'', target} and persisted[-1] == target, caret
        if name == 'one_backup_file_size_in_bytes':
            assert persisted == [target]


def test_chosen_routes_are_native_webdriver_only(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.seed_rich()
    assert 'WebDriver:ElementClear' not in fake.calls
    assert {c for c in fake.calls if c.startswith('WebDriver:Element')} == {
        'WebDriver:ElementClick', 'WebDriver:ElementSendKeys'}
    typed = {target: text for target, text in fake.typed if target.startswith('text|')}
    assert typed['text|one_backup_file_size_in_bytes'] == (
        session.BACKSPACE * 9 + session.DELETE * 9 + '209715200')
    routes = {e['action']: e['route'] for e in result['matrix']['seed_trace']}
    for kind, name, _ in RICH:
        assert routes[f'pref:{name}'] == {'select': 'option_click', 'checkbox': 'box_click',
                                          'text': 'keys_replace'}[kind]
    order = [e['action'] for e in result['matrix']['seed_trace']]
    assert order.index('custom_code:open') < order.index('custom_code:html') < order.index('custom_code:close')
    assert order.index('context:select_background') < order.index('override:background_size') \
        < order.index('invariant:override_global_unchanged') < order.index('context:return_global') \
        < order.index('invariant:global_background_size') < order.index('scheduler:open')
    # The rich prefs left mode scheduled: the already-selected option is not clicked again.
    assert trace(result)['scheduler:mode']['status'] == 'SKIPPED'
    assert trace(result)['task:1:background']['before']['panels']['scheduler'] is True
    assert trace(result)['context:select_background']['before']['panels']['scheduler'] is False


@pytest.mark.parametrize('setup,action,code', [
    (lambda f: f.no_commit.add('settings_context'), 'context:return_global', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'override_leaks', True), 'invariant:override_global_unchanged',
     'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'global_restores', False), 'invariant:global_background_size',
     'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'code_opens', False), 'custom_code:open', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'close_works', False), 'custom_code:close', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'editor_count', 2), 'custom_code:open', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'scheduler_open_works', False), 'scheduler:open', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: setattr(f, 'add_enables', False), 'task:1:add', 'MATRIX_CONTROL_NOT_INTERACTABLE'),
    (lambda f: setattr(f, 'add_noop', True), 'task:1:add', 'MATRIX_STEP_DEADLINE'),
    (lambda f: f.no_commit.add('time'), 'task:1:time', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: f.no_commit.add('day_of_the_month'), 'task:2:day_of_the_month', 'MATRIX_UI_VALUE_NOT_APPLIED'),
    (lambda f: f.disabled.add('background_change_effect'), 'pref:background_change_effect',
     'MATRIX_CONTROL_NOT_INTERACTABLE')])
def test_context_override_code_and_scheduler_failures_are_attributed(s, setup, action, code):
    session, matrix, run = s
    message = {v: k for k, v in session.SESSION_CODES.items()}[code]
    record, failed, fake = seed_fails(session, matrix, run, setup, message)
    assert failed['action'] == action and failed['failure']['code'] == code
    assert failed['failure']['protocol'] is None
    if action.startswith(('context:', 'invariant:')):
        # The global value is never written by the override.
        assert failed['expected'] in ('global', 'fit_browser')
    if action == 'invariant:global_background_size':
        assert failed['before']['controls']['background_size']['ui'] == 'stretch_browser'


def test_protocol_refusal_is_attributed_with_a_safe_token(s):
    session, matrix, run = s
    def setup(fake):
        fake.fail_on = ('WebDriver:ElementClick', 0, RuntimeError('Marionette protocol: other'))
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.backgrounds = 6
    setup(fake)
    with pytest.raises(RuntimeError):
        sess.act('delete_gap', 'element_click', 5, lambda before: sess.click(sess.selectors['delete'], 2))
    entry = result['matrix']['seed_trace'][-1]
    assert entry['failure'] == {'type': 'RuntimeError', 'code': None, 'protocol': 'other'}
    assert result['matrix']['seed_failed_action'] == 'delete_gap'


def test_interrupt_records_the_action_without_touching_the_page_again(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.fail_on = ('WebDriver:ElementClick', 0, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        sess.select('options_page_theme', 'ruby')
    entry = result['matrix']['seed_trace'][-1]
    assert entry['status'] == 'FAILED' and entry['after'] == {'observation': 'UNAVAILABLE'}
    assert entry['failure']['type'] == 'KeyboardInterrupt' and fake.calls[-1] == 'WebDriver:ElementClick'


def test_custom_code_needs_the_debounce_quiet_and_the_native_open(s, monkeypatch):
    session, matrix, run = s
    # Without the quiet window the shared debounce keeps only the last editor value.
    monkeypatch.setattr(session, 'QUIET', 0.0)
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    sess.custom_code(session.RICH_CODE)
    assert fake.saved != dict(zip(('html', 'css', 'js'), session.RICH_CODE))
    # If the open did not reset the editors, the gate stays closed: nothing saves, and the
    # export coverage (not the editor readback) is what shows it.
    monkeypatch.setattr(session, 'QUIET', 0.3)
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    fake.resets_editors = False
    sess.custom_code(session.RICH_CODE)
    assert fake.saved == {} or len(fake.saved) < 3


def test_sentinel_seed_opens_the_editor_and_saves_html(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'T-DISPLACE')
    sess.seed_sentinel()
    assert fake.saved == {'html': session.SENTINEL_CODE} and fake.tasks == 1
    assert fake.task_rows == [{'year': '2033', 'time': '01:02:03', 'day_of_the_month': ''}]
    assert trace(result)['scheduler:mode']['status'] == 'DONE'


def test_trace_privacy_against_adversarial_page_values(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.dom['options_page_theme'] = '/Users/someone/private/path'
    fake.prefs['options_page_theme'] = 'data:image/png;base64,AAAA'
    fake.ui['options_page_theme'] = 'x' * 300
    sess.select('options_page_theme', 'ruby')
    entry = result['matrix']['seed_trace'][-1]
    control = entry['before']['controls']['options_page_theme']
    for key in ('state', 'ui', 'dom'):
        assert control[key] == {'value': None, 'type': 'str', 'allowlisted': False}
    text = json.dumps(result['matrix']['seed_trace'])
    assert '/Users' not in text and 'data:' not in text and 'xxxx' not in text
    matrix.validate_trace(result['matrix']['seed_trace'])
    matrix.project(result['matrix'])


def test_unverified_handler_fact_blocks_the_rich_seed_before_any_call(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.provenance['facts']['ui.event.text']['status'] = 'UNVERIFIED'
    before = len(fake.calls)
    with pytest.raises(session.VerificationError, match='Matrix static fact unverified'):
        sess.seed_rich()
    assert len(fake.calls) == before and result['matrix']['blocked_facts'] == ['ui.event.text']
    assert result['matrix']['seed_trace'] == []


def test_rich_coverage_reports_custom_code_and_task_fields(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    value = json.loads(rows_export(5))
    value['custom_code'] = dict(zip(('html', 'css', 'js'), session.RICH_CODE))
    value['chunks'][1]['tasks'] = [{'id': 't1', 'i': '1', 'background_id': 'b', 'year': '2031',
                                    'day_of_the_week': '', 'month': '', 'day_of_the_month': '',
                                    'time': '12:34:56'}]
    coverage = sess.rich_coverage(matrix.fingerprint([json.dumps(value).encode()]))
    assert coverage['custom_code'] == {'html': 'OBSERVED', 'css': 'OBSERVED', 'js': 'OBSERVED'}
    assert coverage['custom_code_input'] == 'LIBRARY_ADAPTER'
    assert coverage['task_fields'] == ['OBSERVED', 'NOT_OBSERVED']
    empty = sess.rich_coverage(matrix.fingerprint([rows_export(5)]))
    assert set(empty['custom_code'].values()) == {'NOT_OBSERVED'}


def test_no_storage_write_or_synthetic_event_shortcut(repo_root):
    import re
    session_src = (repo_root / 'tests/cnt_firefox_matrix_session.py').read_text()
    js = (repo_root / 'tests/cnt_firefox_matrix_page.js').read_text()
    for name, text in (('session', session_src), ('page', js)):
        for token in ('dispatchEvent', 'new Event', 'createEvent', 'initEvent', 'new InputEvent',
                      'new KeyboardEvent', 'new MouseEvent', 'Dexie', 'indexedDB', 'send_msg',
                      'WebDriver:ElementClear', 'storage.local', 'localStorage', '.focus()', '.blur()'):
            assert token not in text, (name, token)
        # No script write of a control value, checkedness, selectedness or page data.
        assert not re.search(r'\.(value|checked|selected)\s*=[^=]', text), name
        assert not re.search(r'\bdata(\.[A-Za-z_]+|\[[^\]]+\])+\s*=[^=]', text), name
        assert 'set_vals' not in text and 'save_val' not in text and 'change_background_val' not in text
    exported = set(re.findall(r'^  (?:async )?([a-z_0-9]+)\(', js, re.M))
    assert exported == {'state', 'reports', 'captured', 'clear', 'slice', 'sha256', 'pref', 'context',
                        'code', 'editors', 'observe', 'button', 'mark_background', 'mark_target'}
    # REPAIR2 identity read: the host-fiber expando only. No props object with handlers, no
    # component instance or hook state, no state setter and no handler reached from script.
    for token in ('__reactProps$', 'stateNode', 'memoizedState', 'setState', '.onClick', 'onClick(',
                  '__reactEvents$', 'dispatch'):
        assert token not in js, token


# --- SRICH-REPAIR1 closeout: discriminating background clicks, transport-safe attribution ---------

@pytest.mark.parametrize('setup,action', [
    (lambda f: f.task_click_noop.add(2), 'task:2:background'),
    (lambda f: f.task_click_noop.add(1), 'task:1:background'),
    (lambda f: f.click_hits_delete.add('task'), 'task:1:background'),
    (lambda f: f.click_hits_delete.add('context'), 'context:select_background')])
def test_background_click_that_does_not_select_fails_at_that_action(s, setup, action):
    session, matrix, run = s
    record, failed, fake = seed_fails(session, matrix, run, setup)
    assert failed['action'] == action and failed['failure']['code'] == 'MATRIX_UI_VALUE_NOT_APPLIED'
    if action == 'task:2:background':
        # Task 1 left an id set, so presence alone would have passed; the change check fails.
        assert failed['before']['panels']['background_id'] is True
        assert failed['after']['panels']['background_changed'] is False
        assert fake.tasks == 1
    if fake.click_hits_delete:
        assert failed['after']['counts']['backgrounds'] == failed['before']['counts']['backgrounds'] - 1


def test_task_background_ids_are_compared_in_page_only(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.seed_rich()
    entries = trace(result)
    assert entries['task:1:background']['before']['panels']['background_id'] is False
    for n in (1, 2):
        assert entries[f'task:{n}:background']['after']['panels'] == {
            'scheduler': True, 'code_editor': False, 'background_id': True, 'background_changed': True,
            'target_identity': True, 'background_matches_target': True}
    assert fake.background_id == fake.items[3]['id']
    text = json.dumps(result['matrix'])
    assert not [item['id'] for item in fake.items if item['id'] in text]  # no id leaves the page


def test_repeated_task_background_needs_no_change(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    sess.provenance['rich_tasks'][1]['background_position'] = sess.provenance['rich_tasks'][0]['background_position']
    sess.seed_rich()
    assert trace(result)['task:2:background']['after']['panels']['background_changed'] is False
    assert fake.tasks == 2


def test_reload_forgets_the_last_task_background(s):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    sess.task_background = 1
    sess.reload()
    assert sess.task_background is None


@pytest.mark.parametrize('kind', ['eof', 'deadline', 'reset', 'response-mismatch'])
def test_transport_failure_is_attributed_without_touching_the_page_again(s, kind):
    session, matrix, run = s
    import cnt_protocol
    error = {'eof': cnt_protocol.MarionetteEOF('Marionette EOF'),
             'deadline': TimeoutError('Marionette read deadline'), 'reset': ConnectionResetError(),
             'response-mismatch': session.VerificationError('Marionette response mismatch')}[kind]
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.fail_on = ('WebDriver:ElementClick', 0, error)
    with pytest.raises(type(error)):
        sess.select('options_page_theme', 'ruby')
    entry = result['matrix']['seed_trace'][-1]
    assert entry['status'] == 'FAILED' and entry['after'] == {'observation': 'UNAVAILABLE'}
    assert entry['failure']['code'] is None and entry['failure']['protocol'] is None
    assert fake.calls[-1] == 'WebDriver:ElementClick'
    assert result['matrix']['seed_failed_action'] == 'pref:options_page_theme'


# --- SRICH-REPAIR2: exact task target binding and the S-RICH source-readiness gate -------------

BG = PROVENANCE['selectors']['background']


def provenance(identity='VERIFIED'):
    value = json.loads(json.dumps(PROVENANCE))
    value['facts']['ui.background_identity']['status'] = identity
    return value


def source_case(session, matrix, run, setup=lambda fake: None, identity='VERIFIED'):
    """Full S-RICH case against the model; returns (result, fake, error or None)."""
    result, clock = {}, Clock()
    fake = Fake(run, clock)
    fake.exports = [[EMPTY], 'MODEL']
    setup(fake)
    try:
        session.exercise(fake, run, result, 'S-RICH', provenance=provenance(identity), clock=clock)
    except session.VerificationError as error:
        return result, fake, error
    return result, fake, None


def test_model_seed_yields_the_verified_rich_rows(s):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, 'S-RICH')
    sess.seed_rich()
    rows = PROVENANCE['rich_rows']
    assert [item['i'] for item in fake.items] == rows['ranks'] == ['1', '1.5', '2', '4', '5']
    # Uploads 0..5, delete position 3, move the last to position 2: colours 0, 5, 1, 3, 4.
    colours = [matrix.RICH_COLOURS.index(c) for c in matrix.RICH_COLOURS]
    order = [i for i in range(len(matrix.RICH_COLOURS)) if i != 2]
    order.insert(1, order.pop())
    assert order == [0, 5, 1, 3, 4]
    raw = [item['raw'] for item in fake.items]
    assert raw == [matrix.png(matrix.RICH_COLOURS[i]) for i in order]
    groups = matrix._groups([hashlib.sha256(r).hexdigest() for r in raw])
    assert groups == rows['duplicate_content_groups'] == [[0, 3]] and colours[3] == 0
    # Each task sits on its intended rendered position; the override on position 1.
    ids = [item['id'] for item in fake.items]
    assert [t['background_id'] for t in fake.task_model] == [ids[1], ids[3]]
    assert fake.item_overrides == {ids[rows['override_position'] - 1]: {'background_size': 'stretch_browser'}}


def test_intended_seed_binds_every_task_and_is_source_ready(s):
    session, matrix, run = s
    result, fake, error = source_case(session, matrix, run)
    assert error is None and result['matrix_completed'] is True
    record = result['matrix']
    classes = record['classifications']
    assert classes['rich_source_ready'] is True and classes['rich_source_missing'] == []
    assert record['artifacts']['rich']['source_ready'] is True
    coverage = classes['rich_coverage']
    assert coverage['task_target_binding'] == ['REACT_FIBER_READ', 'REACT_FIBER_READ']
    assert coverage['task_fields'] == coverage['task_background'] == ['OBSERVED', 'OBSERVED']
    assert (coverage['row_order'], coverage['override_background'], coverage['row_identity']) == ('OBSERVED',) * 3
    assert coverage['custom_code'] == {'html': 'OBSERVED', 'css': 'OBSERVED', 'js': 'OBSERVED'}
    assert coverage['custom_code_input'] == 'LIBRARY_ADAPTER'
    # The context click (position 1), then the two task clicks on their marked nodes.
    assert fake.clicked == [0, 1, 3]
    text = json.dumps(record)
    assert not [item['id'] for item in fake.items if item['id'] in text]
    assert not [t['id'] for t in fake.task_model if t['id'] in text]
    matrix.project(record)


@pytest.mark.parametrize('ordinal,hit', [(1, 2), (2, 0)], ids=['task1-wrong-existing', 'task2-same-content'])
def test_bound_click_on_another_existing_background_fails_at_that_action(s, ordinal, hit):
    session, matrix, run = s
    record, failed, fake = seed_fails(session, matrix, run, lambda f: f.task_click_other.update({ordinal: hit}))
    assert failed['action'] == f'task:{ordinal}:background'
    assert failed['failure']['code'] == 'MATRIX_UI_VALUE_NOT_APPLIED'
    panels = failed['after']['panels']
    # The id did change (REPAIR1 alone would have passed); only the target match fails.
    assert panels['background_changed'] is True and panels['background_id'] is True
    assert panels['target_identity'] is True and panels['background_matches_target'] is False
    assert fake.tasks == ordinal - 1


@pytest.mark.parametrize('ordinal,hit,missing', [(1, 2, ['task:1:background']), (2, 0, ['task:2:background'])],
                         ids=['task1-wrong-existing', 'task2-same-content'])
@pytest.mark.parametrize('route', ['fact-unverified', 'fiber-hidden'])
def test_unbound_wrong_background_is_refused_by_the_export_gate(s, ordinal, hit, missing, route):
    session, matrix, run = s
    def setup(fake):
        fake.task_click_other[ordinal] = hit
        fake.fiber_hidden = route == 'fiber-hidden'
    result, fake, error = source_case(session, matrix, run, setup,
                                      identity='UNVERIFIED' if route == 'fact-unverified' else 'VERIFIED')
    assert error is not None and str(error) == 'Matrix rich source incomplete'
    assert matrix.MATRIX_CODES[str(error)] == 'MATRIX_RICH_SOURCE_INCOMPLETE'
    record = result['matrix']
    assert record['completed'] is False and 'matrix_completed' not in result
    assert record['steps'][-1] == {'step': 'source_readiness', 'status': 'FAILED',
                                   'error_type': 'VerificationError'}
    classes = record['classifications']
    assert classes['rich_source_ready'] is False and classes['rich_source_missing'] == missing
    assert record['artifacts']['rich']['source_ready'] is False
    assert classes['rich_coverage']['task_target_binding'] == ['NOT_BOUND', 'NOT_BOUND']
    # The seed itself passed: the raw parts and the trace stay for private diagnosis.
    assert (run / 'artifacts/rich/part-1.json').is_file() and record['seed_failed_action'] is None
    assert all(e['status'] in ('DONE', 'SKIPPED') for e in record['seed_trace'])
    matrix.validate_trace(record['seed_trace'])
    matrix.project(record)
    if route == 'fact-unverified':
        assert '.mark_target(' not in json.dumps(fake.calls)  # no identity read at all


@pytest.mark.parametrize('route', ['fact-unverified', 'fiber-hidden'])
def test_unbound_intended_seed_is_ready_and_discloses_not_bound(s, route):
    session, matrix, run = s
    result, fake, error = source_case(session, matrix, run, lambda f: setattr(f, 'fiber_hidden', route == 'fiber-hidden'),
                                      identity='UNVERIFIED' if route == 'fact-unverified' else 'VERIFIED')
    assert error is None and result['matrix']['classifications']['rich_source_ready'] is True
    assert result['matrix']['classifications']['rich_coverage']['task_target_binding'] == ['NOT_BOUND'] * 2


def test_bound_click_uses_the_marked_node_not_a_second_lookup(s, monkeypatch):
    session, matrix, run = s
    for identity, lookups in (('VERIFIED', 2), ('UNVERIFIED', 4)):
        sess, fake, _ = start(session, matrix, run / identity, 'S-RICH')
        (run / identity).mkdir(parents=True)
        sess.provenance = provenance(identity)
        sess.target_binding = identity == 'VERIFIED'
        found = []
        find = fake.WebDriver_FindElements
        monkeypatch.setattr(fake, 'WebDriver_FindElements', lambda params: found.append(params['value']) or find(params))
        sess.seed_rich()
        # Context click and move item: always looked up; bound task clicks never are.
        assert found.count(BG) == lookups, identity
        assert fake.clicked == [0, 1, 3]


def test_missing_target_node_is_refused_before_any_click(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-RICH')
    fake.backgrounds, fake.scheduler = 2, True
    with pytest.raises(session.VerificationError, match='Matrix element missing'):
        sess.act('task:1:background', 'element_click', 4, lambda before: sess.target(3))
    assert fake.clicked == []


def test_complete_looking_export_is_not_a_usable_source(s):
    session, matrix, run = s
    result, fake, error = source_case(session, matrix, run, lambda f: setattr(f, 'exports', [[EMPTY], [rows_export(5)]]))
    assert str(error) == 'Matrix rich source incomplete' and result['matrix']['completed'] is False
    record = result['matrix']
    assert record['artifacts']['rich']['closure'] == 'CLOSED'  # syntactically complete
    missing = record['classifications']['rich_source_missing']
    assert {'rows:order', 'task:1:background', 'custom_code:html'} <= set(missing)
    assert missing == [r for r in matrix.rich_requirements(PROVENANCE) if r in missing]


def test_readiness_gate_is_load_bearing(s, monkeypatch):
    """Mutant check: without the gate a wrong-background source would complete."""
    session, matrix, run = s
    monkeypatch.setattr(session.Session, 'source_readiness', lambda self: {})
    result, fake, error = source_case(session, matrix, run, lambda f: f.task_click_other.update({2: 0}),
                                      identity='UNVERIFIED')
    assert error is None and result['matrix_completed'] is True
    assert result['matrix']['classifications']['rich_coverage']['task_background'] == ['OBSERVED', 'NOT_OBSERVED']


# --- RICH-VALID-PREP1: restore evidence on the Fake (observation only) --------------------------

class Rows(Fake):
    """Fake whose successive restores leave successive page row counts (a list), else one count."""
    @property
    def restore_rows(self):
        return self._rows.pop(0) if isinstance(self._rows, list) else self._rows

    @restore_rows.setter
    def restore_rows(self, value):
        self._rows = value


def rich_source(session, matrix, run):
    """The native-shaped S-RICH export the model seed produces (source readiness true)."""
    result, fake, error = source_case(session, matrix, run / 'source')
    assert error is None and result['matrix']['classifications']['rich_source_ready'] is True
    return (run / 'source/artifacts/rich/part-1.json').read_bytes(), result


def dependent(session, matrix, run, case_id, source, exports, rows, behaviour='ok'):
    result, clock = {}, Clock()
    fake = Rows(run, clock)
    inputs(run, result, [source])
    fake.exports, fake.restore_rows, fake.restore_behaviour = exports, rows, behaviour
    session.exercise(fake, run, result, case_id, clock=clock)
    return result, fake


def no_ids(record, *fakes):
    text = json.dumps(record)
    ids = [i['id'] for f in fakes for i in f.items] + [t['id'] for f in fakes for t in f.task_model]
    return not [i for i in ids if f'"{i}"' in text]


def test_t_rich_restores_the_source_and_records_restored_coverage(s):
    session, matrix, run = s
    source, source_result = rich_source(session, matrix, run)
    result, fake = dependent(session, matrix, run / 't-rich', 'T-RICH', source, [[EMPTY], [source]], 5)
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    evidence = record['restore_evidence']
    assert evidence['case'] == 'T-RICH' and evidence['evidence'] == 'OBSERVED'
    assert evidence['post_vs_given'] == 'SEMANTIC_EQUAL' and evidence['post_vs_pre'] == 'SEMANTIC_DIFFERENT'
    assert evidence['given_semantic_sha256'] == source_result['matrix']['artifacts']['rich']['semantic_sha256']
    assert evidence['restored_rich']['requirements'] == {'schema': 'bux-r6-rich-readiness-v1', 'met': True,
                                                         'missing': []}
    assert evidence['restored_rich']['source_seed_custom_code_input'] == 'LIBRARY_ADAPTER'
    assert evidence['restore_sequence']['restores'] == [{'completion': 'COMPLETED', 'restore_error': False,
                                                         'start_observed': True}]
    assert evidence['restore_sequence']['post_closure'] == 'CLOSED'
    assert record['classifications']['backgrounds'] == 'RESTORED' and record['classifications']['ranks'] == \
        'RANK_PRESERVED'
    assert record['predictions']['backgrounds'] == {'predicted': 'RESTORED', 'status': 'MATCH'}
    assert matrix.project(record) == record and no_ids(record, fake)


def test_t_displace_replaces_the_sentinel_and_records_no_residue(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, fake = dependent(session, matrix, run / 'displace', 'T-DISPLACE', source, ['MODEL', [source]], 5)
    record = result['matrix']
    assert [st['step'] for st in record['steps']] == ['open_settings', 'seed_sentinel', 'pre_export', 'restore',
                                                      'reload', 'post_export']
    evidence = record['restore_evidence']
    assert evidence['sentinel_pre']['contract'] == 'SEEDED_SENTINEL_V1'
    assert (evidence['sentinel_pre']['row_count'], evidence['sentinel_pre']['task_count']) == (2, 1)
    assert evidence['displacement'] == 'REPLACES' and evidence['prior_state'] == 'REMOVED'
    residue = evidence['prior_residue']
    assert (residue['prior_rows'], residue['prior_rows_remaining'], residue['prior_tasks_remaining'],
            residue['prior_contents_remaining']) == (2, 0, 0, 0)
    assert residue['prior_custom_code_remaining']['html'] is False
    assert evidence['components']['backgrounds'] == 'DISPLACED'
    assert evidence['live_data_scope'] == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
    assert record['predictions'] == {}  # T-DISPLACE predicts nothing: the policy is observed
    assert matrix.project(record) == record and no_ids(record, fake)


def test_t_displace_merged_native_state_is_recorded_as_a_merge(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    first, _ = dependent(session, matrix, run / 'probe', 'T-DISPLACE', source, ['MODEL', [source]], 5)
    pre = (run / 'probe/artifacts/pre/part-1.json').read_bytes()
    value = json.loads(source)
    value['chunks'] += json.loads(pre)['chunks']  # deterministic Fake: the same sentinel pre-state
    merged = json.dumps(value, separators=(',', ':')).encode()
    result, fake = dependent(session, matrix, run / 'merged', 'T-DISPLACE', source, ['MODEL', [merged]], 7)
    evidence = result['matrix']['restore_evidence']
    assert evidence['pre_semantic_sha256'] == first['matrix']['restore_evidence']['pre_semantic_sha256']
    assert evidence['displacement'] == 'MERGES' and evidence['prior_state'] == 'PARTIALLY_RETAINED'
    assert evidence['prior_residue']['prior_rows_remaining'] == 2
    assert result['matrix']['classifications']['backgrounds'] == 'MERGED'


def test_f_repeat_idempotent_versus_duplicated_second_restore(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, fake = dependent(session, matrix, run / 'repeat', 'F-REPEAT', source, [[EMPTY], [source], [source]], 5)
    identity = result['matrix']['restore_evidence']['repeat_identity']
    assert identity['repeat_class'] == identity['idempotence'] == 'IDEMPOTENT'
    assert identity['part_bytes_equal'] is True and identity['row_counts'] == [5, 5]
    assert result['matrix']['predictions']['repeat'] == {'predicted': 'IDEMPOTENT', 'status': 'MATCH'}
    value = json.loads(source)
    value['chunks'] += json.loads(json.dumps(value['chunks']))
    twice = json.dumps(value, separators=(',', ':')).encode()
    result, fake = dependent(session, matrix, run / 'twice', 'F-REPEAT', source, [[EMPTY], [source], [twice]],
                             [5, 10])
    identity = result['matrix']['restore_evidence']['repeat_identity']
    assert (identity['repeat_class'], identity['idempotence']) == ('DUPLICATED', 'NOT_IDEMPOTENT')
    assert identity['row_counts'] == [5, 10] and identity['semantic_equal'] is False
    assert result['matrix']['predictions']['repeat']['status'] == 'MISMATCH'
    assert result['matrix']['completed'] is True  # a finding, not a failure
    assert no_ids(result['matrix'], fake)


def test_rejected_repeat_is_its_own_idempotence_class(s):
    session, matrix, run = s
    result = {}
    inputs(run, result, [EXPORT])
    fake = Fake(run)
    fake.exports = [[EMPTY], [EXPORT], [EXPORT]]
    fake.restore_behaviour = ['ok', 'error']
    session.exercise(fake, run, result, 'F-REPEAT')
    identity = result['matrix']['restore_evidence']['repeat_identity']
    assert identity['repeat_class'] == 'REJECTED_ON_REPEAT'
    assert identity['idempotence'] == 'REJECTED_ON_REPEAT_STATE_PRESERVED' and identity['semantic_equal'] is True


@pytest.mark.parametrize('fault', ['raises', 'unsafe', 'absent-given'])
def test_restore_evidence_never_changes_completion_or_classes(s, monkeypatch, fault):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    baseline, _ = dependent(session, matrix, run / 'baseline', 'T-RICH', source, [[EMPTY], [source]], 5)
    if fault == 'raises':
        monkeypatch.setattr(matrix, 'restore_evidence', lambda *a: 1 / 0)
    elif fault == 'unsafe':
        monkeypatch.setattr(matrix, 'restore_evidence', lambda *a: {'row_id': '/Users/someone/raw id'})
    else:
        monkeypatch.setattr(session.Session, 'given', lambda self: (_ for _ in ()).throw(OSError('gone')))
        monkeypatch.setattr(session.Session, 'classify', lambda self: self.record.update(
            restore_evidence=self.restore_evidence(None)))
    result, _ = dependent(session, matrix, run / fault, 'T-RICH', source, [[EMPTY], [source]], 5)
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    assert record['restore_evidence'] == {'schema': 'bux-r6-restore-evidence-v1', 'case': 'T-RICH',
                                          'evidence': 'REFUSED'}
    if fault != 'absent-given':
        assert record['classifications'] == baseline['matrix']['classifications']
        assert record['predictions'] == baseline['matrix']['predictions']
    assert '/Users' not in json.dumps(record)


def test_only_rich_valid_dependents_carry_restore_evidence(s):
    session, matrix, run = s
    result, _, error = source_case(session, matrix, run / 'source')
    assert error is None and 'restore_evidence' not in result['matrix']
    source = (run / 'source/artifacts/rich/part-1.json').read_bytes()
    result, _, _ = e_case(session, matrix, run / 'e', 'E-TOP', source, [source], 5)
    assert 'restore_evidence' not in result['matrix'] and 'compat_evidence' in result['matrix']


# --- MALFORMED-D-PREP1: malformed-input evidence on the Fake (observation only) -----------------

def d_inputs(matrix, run, result, case, source):
    """What the preflight materializes for a D case: the (mutated) input, the unmutated original for a
    declared mutation and the selection files, with the matching matrix_inputs record."""
    entry, parts, mutation = matrix.case(case), [source], None
    if entry['mutation']:
        out, mutation = matrix.mutate(source, entry['mutation'])
        mutation['part_number'] = 1
        parts = [out]
        (run / 'inputs/original').mkdir(parents=True)
        (run / 'inputs/original/part-1.json').write_bytes(source)
    (run / 'inputs/source').mkdir(parents=True)
    (run / 'inputs/source/part-1.json').write_bytes(parts[0])
    selection = matrix.select_parts(parts, entry['selection'])
    for named, raw, _, slot in selection:
        target = run / 'inputs/select' / str(slot) / f'bux-matrix Part {named}.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    result['matrix_inputs'] = {
        'source_case': 'S-RICH', 'artifact': 'rich', 'selection_kind': entry['selection'],
        'source': [{'part_number': 1, 'bytes': len(parts[0]), 'sha256': digest(parts[0])}], 'mutation': mutation,
        'selection': [{'named_part': n, 'slot': s, 'part_number': p, 'sha256': digest(r)} for n, r, p, s in selection]}
    if mutation:
        result['matrix_inputs']['original'] = [{'part_number': 1, 'bytes': len(source), 'sha256': digest(source)}]
    return parts


def d_case(session, matrix, run, case, source, post, rows, behaviour):
    result, clock = {}, Clock()
    fake = Rows(run, clock)
    parts = d_inputs(matrix, run, result, case, source)
    fake.exports, fake.restore_rows, fake.restore_behaviour = ['MODEL', post], rows, behaviour
    session.exercise(fake, run, result, case, clock=clock)
    return result, fake, parts


def test_error_ribbon_seen_is_sticky_and_never_changes_the_completion(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'D-TRUNC-P1', result=result)
    inputs(run, result, [EXPORT])
    fake.restore_behaviour = 'ribbon_flash'
    outcome = sess.restore()
    # Seen while polling, hidden by the final read: the legacy completion is unchanged ...
    assert (outcome['completion'], outcome['restore_error'], outcome['error_ribbon_seen']) == ('COMPLETED', False, True)
    # ... the legacy tri-state never reads it as a clean completion ...
    assert matrix.restore_error_state(outcome) == ('UNKNOWN', False)
    # ... and, the gate having proven no earlier ribbon (REPORT-GATE1), the malformed tri-state reads a
    # post-start ribbon as TRUE, inconsistent with the recorded legacy False.
    pre = result['matrix']['pre_restore_error_ribbon']
    assert pre == 'HIDDEN' and outcome['start_observed'] is True
    assert matrix.malformed_restore_error_state(outcome, matrix.REPORT_OBSERVABILITY, pre) == ('TRUE', False)


def test_module_local_restore_report_is_a_ribbon_without_codes(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'D-NO-CHUNKS', result=result)
    inputs(run, result, [EXPORT])
    fake.restore_behaviour = 'ribbon'
    outcome = sess.restore()
    assert (outcome['completion'], outcome['restore_error'], outcome['error_codes']) == ('ERROR_REPORTED', True, [])
    assert outcome['error_ribbon_seen'] is True and matrix.restore_error_state(outcome) == ('TRUE', True)
    pre = result['matrix']['pre_restore_error_ribbon']
    assert matrix.malformed_restore_error_state(outcome, matrix.REPORT_OBSERVABILITY, pre) == ('TRUE', True)


@pytest.mark.parametrize('case,behaviour,post,rows,completion,error,effect', [
    # Rows deleted before the parse, the error only as a ribbon: the predicted D shape.
    ('D-TRUNC-P1', 'ribbon', 'MODEL_EMPTY', 0, 'ERROR_REPORTED', 'TRUE', 'SENTINEL_CONTENT_DESTROYED'),
    # Started, then no signal: an observation with restore_error unknown, never a clean restore.
    ('D-NO-CHUNKS', 'hidden', 'MODEL_EMPTY', 0, 'DEADLINE_NO_SIGNAL', 'UNKNOWN', 'SENTINEL_CONTENT_DESTROYED'),
    # REPORT-GATE1: observability is partial, so no ribbon seen is not proof of no native error.
    ('D-CHUNKS-TYPE', 'ok', 'MODEL', 2, 'COMPLETED', 'UNKNOWN', 'STATE_PRESERVED'),
    ('D-BAD-DATAURL', 'ok', 'INPUT', 5, 'COMPLETED', 'UNKNOWN', 'STATE_REPLACED_BY_INPUT'),
    # The Part 1 gate after the deletion: the sentinel is destroyed with no report at all.
    ('D-NAME-NO-P1', 'ok', 'MODEL_EMPTY', 0, 'COMPLETED', 'UNKNOWN', 'SENTINEL_CONTENT_DESTROYED')])
def test_d_case_records_malformed_evidence(s, case, behaviour, post, rows, completion, error, effect):
    session, matrix, run = s
    source, source_result = rich_source(session, matrix, run)
    exported = None if post != 'INPUT' else matrix.mutate(source, 'invalid_data_url')[0]
    result, fake, parts = d_case(session, matrix, run / case, case, source,
                                 [exported] if exported else post, rows, behaviour)
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    assert [st['step'] for st in record['steps']] == ['open_settings', 'seed_sentinel', 'pre_export', 'restore',
                                                      'reload', 'post_export']
    evidence = record['malformed_evidence']
    assert evidence['case'] == case and evidence['evidence'] == 'OBSERVED'
    assert evidence['completion']['completion'] == completion and evidence['completion']['restore_error'] == error
    assert record['pre_restore_error_ribbon'] == evidence['completion']['pre_restore_error_ribbon'] == 'HIDDEN'
    assert evidence['completion']['report_observability'] == 'PARTIAL_SUPPRESSION_UNRESOLVED'
    assert evidence['state_effect'] == effect
    assert evidence['input']['input_class_observed'] is True and evidence['input']['source_part_count'] == 1
    rich = source_result['matrix']['artifacts']['rich']['semantic_sha256']
    assert evidence['source']['original_semantic_sha256'] == rich
    assert evidence['source']['input_mutated'] is (case != 'D-NAME-NO-P1')
    assert evidence['sentinel_pre']['row_count'] == 2 and evidence['sentinel_pre']['task_count'] == 1
    assert evidence['live_data_scope'] == 'SYNTHETIC_SENTINEL_ONLY_NO_LIVE_DATA_SAFETY_CLAIM'
    assert evidence['reports']['loud_codes'] == [] and evidence['reports']['restore_route_codes'] == \
        'NOT_OBSERVABLE_MODULE_LOCAL_ROUTE'
    assert 'restore_evidence' not in record
    # Predictions stay the legacy predictions; the evidence copies them without asserting them.
    assert set(evidence['predictions']) == set(matrix.case(case)['predictions'])
    for key, value in evidence['predictions'].items():
        assert value['legacy_status'] == record['predictions'][key]['status']
        assert value['status'] == (value['legacy_status'] if error in ('TRUE', 'FALSE') else 'UNOBSERVED')
    assert matrix.project(record) == record and no_ids(record, fake)


def test_predicted_d_shape_matches_its_legacy_prediction(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, _, _ = d_case(session, matrix, run / 'trunc', 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'ribbon')
    assert result['matrix']['predictions'] == {
        'backgrounds': {'predicted': 'REJECTED_STATE_DESTROYED', 'status': 'MATCH'},
        'custom_code': {'predicted': 'REJECTED_STATE_PRESERVED', 'status': 'MATCH'}}
    assert {k: v['status'] for k, v in result['matrix']['malformed_evidence']['predictions'].items()} == {
        'backgrounds': 'MATCH', 'custom_code': 'MATCH'}
    # A deadline with the same state keeps the legacy value but never reports a match.
    result, _, _ = d_case(session, matrix, run / 'deadline', 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'hidden')
    assert {k: v['status'] for k, v in result['matrix']['malformed_evidence']['predictions'].items()} == {
        'backgrounds': 'UNOBSERVED', 'custom_code': 'UNOBSERVED'}


@pytest.mark.parametrize('fault', ['raises', 'unsafe', 'original-tampered'])
def test_malformed_evidence_never_changes_completion_or_classes(s, monkeypatch, fault):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    baseline, _, _ = d_case(session, matrix, run / 'baseline', 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'ribbon')
    if fault == 'raises':
        monkeypatch.setattr(matrix, 'malformed_evidence', lambda *a: 1 / 0)
    elif fault == 'unsafe':
        monkeypatch.setattr(matrix, 'malformed_evidence', lambda *a: {'raw_message': '/Users/someone/raw report'})
    else:
        original = session.Session.original
        def tampered(self):
            (self.run / 'inputs/original/part-1.json').write_bytes(b'{}')
            return original(self)
        monkeypatch.setattr(session.Session, 'original', tampered)
    result, _, _ = d_case(session, matrix, run / fault, 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'ribbon')
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    assert record['malformed_evidence'] == {'schema': 'bux-r6-malformed-evidence-v2', 'case': 'D-TRUNC-P1',
                                            'evidence': 'REFUSED'}
    assert record['classifications'] == baseline['matrix']['classifications']
    assert record['predictions'] == baseline['matrix']['predictions']
    assert record['restores'] == baseline['matrix']['restores']
    assert '/Users' not in json.dumps(record)


def test_only_runnable_d_cases_carry_malformed_evidence(s):
    session, matrix, run = s
    result, _, error = source_case(session, matrix, run / 'source')
    assert error is None and 'malformed_evidence' not in result['matrix']
    source = (run / 'source/artifacts/rich/part-1.json').read_bytes()
    result, _ = dependent(session, matrix, run / 't-rich', 'T-RICH', source, [[EMPTY], [source]], 5)
    assert 'malformed_evidence' not in result['matrix'] and 'restore_evidence' in result['matrix']
    with pytest.raises(session.VerificationError, match='Matrix case not drivable'):
        session.exercise(Fake(run / 'empty'), run / 'empty', {}, 'D-EMPTY-SELECTION')


def test_session_original_is_the_given_source_without_a_mutation(s):
    session, matrix, run = s
    source = (FIXTURE / 'export.json').read_bytes()
    result = {}
    sess, _, _ = start(session, matrix, run, 'D-NAME-NO-P1', result=result)
    d_inputs(matrix, run, result, 'D-NAME-NO-P1', source)
    assert not (run / 'inputs/original').exists()
    assert sess.original() == sess.given() and sess.given()['semantic_sha256'] == matrix.fingerprint([source])['semantic_sha256']
    result2 = {}
    sess2, _, _ = start(session, matrix, run / 'm', 'D-CHUNKS-TYPE', result=result2)
    parts = d_inputs(matrix, run / 'm', result2, 'D-CHUNKS-TYPE', source)
    assert sess2.original()['semantic_sha256'] == matrix.fingerprint([source])['semantic_sha256']
    assert sess2.input_bytes() == parts and sess2.given()['complete'] is False


# --- REPORT-GATE1: pre-existing error-ribbon refusal and the observability-aware tri-state -------

def ribbon_case(session, matrix, run, case, source, visible):
    result, clock = {}, Clock()
    fake = Rows(run, clock)
    d_inputs(matrix, run, result, case, source)
    fake.exports, fake.restore_rows, fake.restore_behaviour = ['MODEL', 'MODEL_EMPTY'], 0, ['ok']
    fake.error_visible = visible  # left over from seeding: visible until a reload
    with pytest.raises(session.VerificationError, match='Matrix pre-existing error ribbon') as caught:
        session.exercise(fake, run, result, case, clock=clock)
    return result, fake, caught.value


@pytest.mark.parametrize('case', ['D-TRUNC-P1', 'D-NO-CHUNKS', 'D-CHUNKS-TYPE', 'D-BAD-DATAURL', 'D-NAME-NO-P1'])
def test_pre_existing_ribbon_refuses_every_d_restore_before_file_selection(s, case):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, fake, error = ribbon_case(session, matrix, run / case, case, source, True)
    record = result['matrix']
    assert session.Session.failure_class(error)['code'] == 'MATRIX_PREEXISTING_ERROR_RIBBON'
    assert record['pre_restore_error_ribbon'] == 'VISIBLE'
    # No restore selection (the Fake's restore input was never sent keys: its behaviour list is unread
    # and no transition started), no restore record, no evidence and no later step.
    assert fake.restore_behaviour == ['ok'] and fake.transitions == 0
    assert 'restores' not in record and 'malformed_evidence' not in record
    assert [(st['step'], st['status']) for st in record['steps']][-1] == ('restore', 'FAILED')
    assert [st['step'] for st in record['steps']] == ['open_settings', 'seed_sentinel', 'pre_export', 'restore']
    assert record['completed'] is False and 'matrix_completed' not in result
    assert matrix.project(record) == record and 'ribbon text' not in json.dumps(record)


def test_pre_existing_ribbon_code_is_a_fixed_preflight_code(s):
    session, matrix, run = s
    assert session.SESSION_CODES['Matrix pre-existing error ribbon'] == 'MATRIX_PREEXISTING_ERROR_RIBBON'
    assert 'Matrix pre-existing error ribbon' not in matrix.MATRIX_CODES


@pytest.mark.parametrize('visible', ['yes', 1, None])
def test_unreadable_pre_restore_ribbon_is_refused(s, monkeypatch, visible):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'D-NO-CHUNKS', result=result)
    inputs(run, result, [EXPORT])
    state = sess.state
    monkeypatch.setattr(sess, 'state', lambda: dict(state(), error_visible=visible))
    with pytest.raises(session.VerificationError, match='Matrix pre-existing error ribbon'):
        sess.restore()
    assert result['matrix']['pre_restore_error_ribbon'] == 'UNREADABLE'
    assert 'WebDriver:ElementSendKeys' not in fake.calls and fake.transitions == 0
    assert 'restores' not in result['matrix']


def test_hidden_pre_state_restores_and_is_recorded(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'D-CHUNKS-TYPE', result=result)
    inputs(run, result, [EXPORT])
    outcome = sess.restore()
    assert result['matrix']['pre_restore_error_ribbon'] == 'HIDDEN'
    assert outcome['completion'] == 'COMPLETED' and fake.calls.count('WebDriver:ElementSendKeys') == 1
    assert matrix.malformed_restore_error_state(outcome, matrix.REPORT_OBSERVABILITY, 'HIDDEN') == ('UNKNOWN', True)


@pytest.mark.parametrize('case', ['T-RICH', 'T-DISPLACE', 'F-REPEAT'])
def test_non_d_restores_are_not_gated(s, case):
    """Accepted RICH-VALID behaviour: a ribbon already visible is still attributed to the restore."""
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, case, result=result)
    inputs(run, result, [EXPORT])
    fake.error_visible = True
    outcome = sess.restore()
    assert 'pre_restore_error_ribbon' not in result['matrix']
    assert (outcome['completion'], outcome['restore_error']) == ('ERROR_REPORTED', True)
    assert matrix.restore_error_state(outcome) == ('TRUE', True)


def test_deadline_no_signal_stays_unknown_with_a_hidden_pre_state(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, _, _ = d_case(session, matrix, run / 'deadline', 'D-NO-CHUNKS', source, 'MODEL_EMPTY', 0, 'hidden')
    completion = result['matrix']['malformed_evidence']['completion']
    assert completion['completion'] == 'DEADLINE_NO_SIGNAL' and completion['restore_error'] == 'UNKNOWN'
    assert completion['pre_restore_error_ribbon'] == 'HIDDEN'


def test_sticky_post_start_ribbon_is_true_in_the_recorded_case(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, _, _ = d_case(session, matrix, run / 'flash', 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'ribbon_flash')
    record = result['matrix']
    assert (record['restores'][0]['completion'], record['restores'][0]['restore_error']) == ('COMPLETED', False)
    evidence = record['malformed_evidence']
    assert (evidence['completion']['restore_error'], evidence['completion']['state_consistent']) == ('TRUE', False)
    # The legacy predictions were computed on the recorded False, so they are not observed here.
    assert {v['status'] for v in evidence['predictions'].values()} == {'UNOBSERVED'}


def test_full_observability_would_make_a_clean_d_case_false_without_touching_other_facts(s, monkeypatch):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    partial, _, _ = d_case(session, matrix, run / 'partial', 'D-CHUNKS-TYPE', source, 'MODEL', 2, 'ok')
    monkeypatch.setattr(matrix, 'REPORT_OBSERVABILITY', 'FULLY_OBSERVABLE')
    monkeypatch.setattr(matrix, 'OBSERVABILITY_GAPS', ())
    fully, _, _ = d_case(session, matrix, run / 'fully', 'D-CHUNKS-TYPE', source, 'MODEL', 2, 'ok')
    a, b = partial['matrix'], fully['matrix']
    assert a['malformed_evidence']['completion']['restore_error'] == 'UNKNOWN'
    assert b['malformed_evidence']['completion']['restore_error'] == 'FALSE'
    # Legacy restores, classifications, predictions and every other evidence channel are identical.
    for key in ('restores', 'classifications', 'predictions', 'pre_restore_error_ribbon', 'completed'):
        assert a[key] == b[key], key
    assert [(st['step'], st['status']) for st in a['steps']] == [(st['step'], st['status']) for st in b['steps']]
    for key in ('components', 'state_effect', 'input', 'post', 'semantics', 'sentinel_pre', 'ranks', 'reports'):
        assert a['malformed_evidence'][key] == b['malformed_evidence'][key], key


# --- COMPAT-E-PREP1: E input proof before selection and compat evidence on the Fake ----------------

E_CASES = ['E-TOP', 'E-BG', 'E-PREF', 'E-CODE', 'E-TASK', 'E-ABSENT-OPT', 'E-VERSION', 'E-THEMEID-DUP',
           'E-MODE-THEME']
E_SOURCE_CLASS = {'E-ABSENT-OPT': 'ACCEPTED_EQUIVALENT_KNOWN_STATE', 'E-VERSION': 'ACCEPTED_EQUIVALENT_KNOWN_STATE',
                  'E-THEMEID-DUP': 'ACCEPTED_AS_SOURCE_EQUIVALENT', 'E-MODE-THEME': 'ACCEPTED_AS_SOURCE_EQUIVALENT'}


def e_case(session, matrix, run, case, source, post, rows, behaviour='ok', setup=None):
    """One E case on a fresh target: the preflight-shaped inputs (d_inputs), a fresh pre-export and
    the given post-export. `post` 'MODEL' is the fresh state left untouched."""
    result, clock = {}, Clock()
    fake = Rows(run, clock)
    parts = d_inputs(matrix, run, result, case, source)
    fake.exports, fake.restore_rows, fake.restore_behaviour = ['MODEL', post], rows, behaviour
    if setup:
        setup(fake, run, result)
    session.exercise(fake, run, result, case, clock=clock)
    return result, fake, parts


@pytest.mark.parametrize('case', E_CASES)
def test_e_case_proves_its_input_then_records_compat_evidence(s, case):
    session, matrix, run = s
    source, source_result = rich_source(session, matrix, run)
    result, fake, parts = e_case(session, matrix, run / case, case, source, [source], 5)
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    assert [st['step'] for st in record['steps']] == ['open_settings', 'pre_export', 'restore', 'reload',
                                                      'post_export']
    proof = record['compat_input']
    assert proof['proven'] is True and proof['case'] == case and proof['selection_bytes_equal_input'] is True
    assert record['pre_restore_error_ribbon'] == 'HIDDEN'
    evidence = record['compat_evidence']
    assert evidence['case'] == case and evidence['evidence'] == 'OBSERVED'
    assert evidence['application'] == 'APPLIED'
    assert evidence['compat_class'] == E_SOURCE_CLASS.get(case, 'UNKNOWN_IGNORED')
    assert evidence['completion']['restore_error'] == 'UNKNOWN'  # partial observability, no ribbon
    assert evidence['source']['original_semantic_sha256'] == source_result['matrix']['artifacts']['rich'][
        'semantic_sha256']
    assert evidence['input']['proof']['proven'] is True
    assert 'malformed_evidence' not in record and 'restore_evidence' not in record
    assert matrix.project(record) == record and no_ids(record, fake)


def test_e_rejection_and_retention_on_the_fake(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    rejected, _, _ = e_case(session, matrix, run / 'rejected', 'E-TOP', source, 'MODEL', 0)
    record = rejected['matrix']
    assert record['compat_evidence']['compat_class'] == 'RESTORE_REJECTED'
    # The legacy classifier reads IGNORED on the unapplied state and its prediction reads MATCH ...
    assert record['classifications']['unknown'] == 'IGNORED'
    assert record['predictions']['unknown'] == {'predicted': 'IGNORED', 'status': 'MATCH'}
    # ... while the compat prediction stays unobserved and keeps the legacy status apart.
    prediction = record['compat_evidence']['predictions']['unknown']
    assert (prediction['status'], prediction['legacy_status']) == ('UNOBSERVED', 'MATCH')
    mutated = matrix.mutate(source, 'unknown_top_level')[0]
    retained, _, _ = e_case(session, matrix, run / 'retained', 'E-TOP', source, [mutated], 5)
    evidence = retained['matrix']['compat_evidence']
    assert evidence['compat_class'] == 'UNKNOWN_RETAINED' and evidence['predictions']['unknown']['status'] == \
        'MISMATCH'


def test_silent_e_restore_is_an_observation_not_a_stop(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, _, _ = e_case(session, matrix, run / 'silent', 'E-VERSION', source, 'MODEL', 0, 'hidden')
    evidence = result['matrix']['compat_evidence']
    assert result['matrix_completed'] is True
    assert evidence['completion']['completion'] == 'DEADLINE_NO_SIGNAL'
    assert evidence['completion']['restore_error'] == 'UNKNOWN'
    assert evidence['application'] == evidence['compat_class'] == 'UNSETTLED_NO_COMPLETION_SIGNAL'


def tamper_original(fake, run, result):
    (run / 'inputs/original/part-1.json').write_bytes(b'{"settings":{}}')


def tamper_extra_edit(fake, run, result):
    raw = (run / 'inputs/source/part-1.json').read_bytes()
    value = json.loads(raw)
    value['settings']['prefs']['options_page_theme'] = 'lavender'
    out = json.dumps(value, separators=(',', ':')).encode()
    digest = hashlib.sha256(out).hexdigest()
    (run / 'inputs/source/part-1.json').write_bytes(out)
    (run / 'inputs/select/0/bux-matrix Part 1.json').write_bytes(out)
    inputs = result['matrix_inputs']
    inputs['source'][0]['sha256'] = inputs['selection'][0]['sha256'] = inputs['mutation']['after_sha256'] = digest


def tamper_no_original(fake, run, result):
    del result['matrix_inputs']['original']


@pytest.mark.parametrize('tamper,fact', [(tamper_original, 'mutation_record_binds'),
                                         (tamper_extra_edit, 'outside_edit_unchanged'),
                                         (tamper_no_original, 'mutation_record_binds')],
                         ids=['original', 'extra-edit', 'no-original'])
def test_unproven_e_input_is_refused_before_file_selection(s, tamper, fact):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    with pytest.raises(session.VerificationError, match='Matrix compat input unproven') as caught:
        e_case(session, matrix, run / 'e', 'E-PREF', source, [source], 5, setup=tamper)
    assert session.Session.failure_class(caught.value)['code'] == 'MATRIX_COMPAT_INPUT_UNPROVEN'


def test_unprojectable_e_input_proof_refuses_as_unproven(s, monkeypatch):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    real = matrix.compat_input_proof
    def unsafe(entry, declared, *args):
        proof = real(entry, declared, *args)
        return {**proof, 'proven': True, 'schema': 'data:unsafe'} if declared else proof
    monkeypatch.setattr(matrix, 'compat_input_proof', unsafe)
    result, clock = {}, Clock()
    fake = Rows(run / 'e', clock)
    d_inputs(matrix, run / 'e', result, 'E-PREF', source)
    fake.exports, fake.restore_rows, fake.restore_behaviour = ['MODEL', [source]], 5, ['ok']
    with pytest.raises(session.VerificationError, match='Matrix compat input unproven') as caught:
        session.exercise(fake, run / 'e', result, 'E-PREF', clock=clock)
    assert session.Session.failure_class(caught.value)['code'] == 'MATRIX_COMPAT_INPUT_UNPROVEN'
    record = result['matrix']
    assert record['compat_input']['proven'] is False and 'data:unsafe' not in json.dumps(record)
    assert fake.restore_behaviour == ['ok'] and fake.transitions == 0


def test_unproven_e_input_leaves_the_proof_and_no_selection(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, clock = {}, Clock()
    fake = Rows(run / 'e', clock)
    d_inputs(matrix, run / 'e', result, 'E-PREF', source)
    tamper_extra_edit(fake, run / 'e', result)
    fake.exports, fake.restore_rows, fake.restore_behaviour = ['MODEL', [source]], 5, ['ok']
    with pytest.raises(session.VerificationError, match='Matrix compat input unproven'):
        session.exercise(fake, run / 'e', result, 'E-PREF', clock=clock)
    record = result['matrix']
    assert record['compat_input']['proven'] is False and record['compat_input']['outside_edit_unchanged'] is False
    assert fake.restore_behaviour == ['ok'] and fake.transitions == 0  # the restore input was never sent keys
    assert 'restores' not in record and 'compat_evidence' not in record and 'pre_restore_error_ribbon' not in record
    assert [(st['step'], st['status']) for st in record['steps']][-1] == ('restore', 'FAILED')
    assert record['completed'] is False and matrix.project(record) == record


def test_pre_existing_ribbon_refuses_an_e_restore_before_file_selection(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    def visible(fake, run, result):
        fake.error_visible = True
    with pytest.raises(session.VerificationError, match='Matrix pre-existing error ribbon'):
        e_case(session, matrix, run / 'e', 'E-CODE', source, [source], 5, ['ok'], setup=visible)
    result = json.loads(json.dumps({}))
    sess, fake, result = start(session, matrix, run / 'direct', 'E-CODE')
    d_inputs(matrix, run / 'direct', result, 'E-CODE', source)
    fake.error_visible = True
    with pytest.raises(session.VerificationError, match='Matrix pre-existing error ribbon'):
        sess.restore()
    assert result['matrix']['pre_restore_error_ribbon'] == 'VISIBLE'
    assert result['matrix']['compat_input']['proven'] is True  # the proof precedes the ribbon read
    assert 'WebDriver:ElementSendKeys' not in fake.calls and 'restores' not in result['matrix']


@pytest.mark.parametrize('fault', ['raises', 'unsafe'])
def test_compat_evidence_never_changes_completion_or_classes(s, monkeypatch, fault):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    baseline, _, _ = e_case(session, matrix, run / 'baseline', 'E-TOP', source, [source], 5)
    if fault == 'raises':
        monkeypatch.setattr(matrix, 'compat_evidence', lambda *a: 1 / 0)
    else:
        monkeypatch.setattr(matrix, 'compat_evidence', lambda *a: {'raw_key': '/Users/someone/x_bux_secret'})
    result, _, _ = e_case(session, matrix, run / fault, 'E-TOP', source, [source], 5)
    record = result['matrix']
    assert result['matrix_completed'] is True and record['completed'] is True
    assert record['compat_evidence'] == {'schema': 'bux-r6-compat-evidence-v1', 'case': 'E-TOP', 'evidence': 'REFUSED'}
    for key in ('classifications', 'predictions', 'restores', 'compat_input', 'pre_restore_error_ribbon'):
        assert record[key] == baseline['matrix'][key], key
    assert '/Users' not in json.dumps(record)


def test_full_observability_changes_only_the_e_completion(s, monkeypatch):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    partial, _, _ = e_case(session, matrix, run / 'partial', 'E-MODE-THEME', source, [source], 5)
    monkeypatch.setattr(matrix, 'REPORT_OBSERVABILITY', 'FULLY_OBSERVABLE')
    monkeypatch.setattr(matrix, 'OBSERVABILITY_GAPS', ())
    fully, _, _ = e_case(session, matrix, run / 'fully', 'E-MODE-THEME', source, [source], 5)
    a, b = partial['matrix']['compat_evidence'], fully['matrix']['compat_evidence']
    assert (a['completion']['restore_error'], b['completion']['restore_error']) == ('UNKNOWN', 'FALSE')
    for key in ('components', 'application', 'compat_class', 'theme', 'semantics', 'input', 'source', 'ranks'):
        assert a[key] == b[key], key


def test_only_runnable_e_cases_carry_compat_input_and_evidence(s):
    session, matrix, run = s
    source, _ = rich_source(session, matrix, run)
    result, _, _ = d_case(session, matrix, run / 'd', 'D-TRUNC-P1', source, 'MODEL_EMPTY', 0, 'ribbon')
    assert not {'compat_input', 'compat_evidence'} & set(result['matrix'])
    result, _ = dependent(session, matrix, run / 't-rich', 'T-RICH', source, [[EMPTY], [source]], 5)
    assert not {'compat_input', 'compat_evidence', 'pre_restore_error_ribbon'} & set(result['matrix'])
    assert session.SESSION_CODES['Matrix compat input unproven'] == 'MATRIX_COMPAT_INPUT_UNPROVEN'
    assert 'Matrix compat input unproven' not in matrix.MATRIX_CODES


# --- MULTIPART-B-PREP1: B exports, S-MULTI threshold binding and readiness, B pre-selection gates -----

B_DEPENDENTS = ('T-MULTI-ORDERED', 'T-MULTI-REVERSED', 'T-MULTI-NO-P1', 'T-MULTI-NO-MIDDLE', 'T-MULTI-DUP',
                'T-MULTI-TRUNC', 'T-MULTI-BADDATA')


def multi_parts(threshold=52428800, groups=((0,), (1, 2), (3,))):
    """A native-template three-part set of the accepted export, as an S-MULTI minimum export of its
    four rows would be split: settings plus row 1, rows 2-3, row 4."""
    value = json.loads(EXPORT)
    value['settings']['prefs']['one_backup_file_size_in_bytes'] = threshold
    chunks = [json.dumps(c, separators=(',', ':')).encode() for c in value['chunks']]
    raw = json.dumps(value, separators=(',', ':')).encode()
    header = raw[:raw.index(b'"chunks":[') + len(b'"chunks":[')]
    return [(header if n == 0 else b'{"chunks":[') + b','.join(chunks[i] for i in g) + b']}'
            for n, g in enumerate(groups)]


def b_inputs(run, result, matrix, case, parts=None, ready=True, same_root=True):
    """The preflight's materialization of one B dependent: input, unmutated original, selection and the
    same-root S-MULTI readiness record."""
    entry = matrix.case(case)
    original = list(parts or multi_parts())
    source, mutation = list(original), None
    if entry['mutation']:
        at = len(source) - 1 if entry['mutate_part'] == -1 else entry['mutate_part'] - 1
        source[at], mutation = matrix.mutate(source[at], entry['mutation'])
        mutation['part_number'] = at + 1
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    for n, raw in enumerate(source, 1):
        (run / 'inputs/source').mkdir(parents=True, exist_ok=True)
        (run / f'inputs/source/part-{n}.json').write_bytes(raw)
    if mutation:
        for n, raw in enumerate(original, 1):
            (run / 'inputs/original').mkdir(parents=True, exist_ok=True)
            (run / f'inputs/original/part-{n}.json').write_bytes(raw)
    selection = []
    for named, raw, number, slot in matrix.select_parts(source, entry['selection']):
        target = run / 'inputs/select' / str(slot) / f'bux-matrix Part {named}.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        selection.append({'named_part': named, 'slot': slot, 'part_number': number, 'sha256': sha(raw)})
    result['matrix_inputs'] = {
        'source_case': 'S-MULTI', 'artifact': 'minimum', 'selection_kind': entry['selection'],
        'source': [{'part_number': n, 'bytes': len(r), 'sha256': sha(r)} for n, r in enumerate(source, 1)],
        'mutation': mutation, 'selection': selection,
        'source_readiness': {'ready': ready, 'same_root': same_root, 'minimum_part_sha256': [sha(r) for r in original]}}
    if mutation:
        result['matrix_inputs']['original'] = [{'part_number': n, 'bytes': len(r), 'sha256': sha(r)}
                                               for n, r in enumerate(original, 1)]
    return source, original


@pytest.mark.parametrize('case_id,multi', [('S-MULTI', True), ('T-MULTI-ORDERED', True), ('T-MULTI-TRUNC', True),
                                           ('T-RICH', False), ('E-TOP', False), ('D-TRUNC-P1', False)])
def test_every_b_step_export_uses_the_multipart_deadline(s, monkeypatch, case_id, multi):
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, case_id)
    calls = []
    monkeypatch.setattr(sess, 'export', lambda label, multi=False: calls.append((label, multi)) or {})
    for name in ('pre_export', 'restore', 'reload', 'seed_sentinel', 'upload'):
        monkeypatch.setattr(sess, name, lambda *a, **kw: {})
    monkeypatch.setattr(sess, 'threshold', lambda which: {})
    sess.run_steps()
    labels = [label for label, _ in calls]
    assert labels and {flag for _, flag in calls} == {multi}, calls
    if case_id == 'S-MULTI':
        assert labels == list(matrix.MULTI_LABELS)
    elif case_id.startswith('T-'):
        assert 'post' in labels


@pytest.mark.parametrize('case_id', ['S-MULTI', 'T-MULTI-ORDERED', 'T-MULTI-NO-P1'])
def test_a_b_pre_export_keeps_the_ordinary_export_deadline(s, monkeypatch, case_id):
    # A fresh or sentinel pre-state is small; only step exports use export_multi.
    session, matrix, run = s
    sess, fake, _ = start(session, matrix, run, case_id)
    calls = []

    def export(label, multi=False):
        calls.append((label, multi))
        raise RuntimeError('recorded')
    monkeypatch.setattr(sess, 'export', export)
    with pytest.raises(RuntimeError):
        sess.pre_export()
    assert calls == [('pre', False)]


def test_b_exports_record_their_own_threshold_and_others_do_not(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-MULTI')
    fake.exports, fake.backgrounds = [multi_parts(52428800)], 4
    assert sess.export('minimum', multi=True)['closure'] == 'CLOSED'
    assert result['matrix']['artifacts']['minimum']['threshold'] == 52428800
    assert len(result['matrix']['artifacts']['minimum']['parts']) == 3
    rich, fake2, result2 = start(session, matrix, run / 'other', 'T-RICH')
    (run / 'other').mkdir()
    fake2.exports, fake2.backgrounds = [[EXPORT]], 4
    rich.export('post')
    assert 'threshold' not in result2['matrix']['artifacts']['post']


@pytest.mark.parametrize('own', [419430400, 209715200, None])
def test_the_prediction_reads_the_calibration_exports_own_threshold(s, own):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-MULTI')
    value = json.loads(EXPORT)
    if own is None:
        del value['settings']['prefs']['one_backup_file_size_in_bytes']
    else:
        value['settings']['prefs']['one_backup_file_size_in_bytes'] = own
    fake.exports, fake.backgrounds = [[json.dumps(value, separators=(',', ':')).encode()]], 4
    sess.export('calibration', multi=True)
    if own is None:
        with pytest.raises(session.VerificationError, match='Native part structure invalid'):
            sess.threshold('predicted')
        return
    # The tiny accepted rows cannot reach 50 MiB: not settable, nothing typed, the premise recorded.
    assert sess.threshold('predicted') == {'status_detail': 'BOUNDARY_NOT_SETTABLE'}
    prediction = result['matrix']['boundary_prediction']
    assert prediction['calibration_threshold'] == own and prediction['converged'] is True
    assert not [t for t in fake.typed if t[0] == 'text|one_backup_file_size_in_bytes']


def test_the_minimum_step_types_exactly_the_supported_minimum(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-MULTI')
    assert sess.threshold('minimum') == {'threshold': matrix.THRESHOLD_MIN}
    assert fake.prefs['one_backup_file_size_in_bytes'] == 52428800 == matrix.THRESHOLD_MIN
    assert result['matrix']['thresholds'] == {'minimum': 52428800}
    assert trace(result)['threshold:minimum']['status'] in ('DONE', 'SKIPPED')


def test_s_multi_partition_uses_each_exports_own_threshold(s):
    session, matrix, run = s
    sess, fake, result = start(session, matrix, run, 'S-MULTI')
    fake.exports, fake.backgrounds = [multi_parts(52428800)], 4
    sess.export('minimum', multi=True)
    sess.thresholds['minimum'] = 1  # an intended value never replaces the export's own threshold
    sess.classify()
    partition = result['matrix']['partition']['minimum']
    assert partition['observed_part_sizes'] == [1, 2, 1] and partition['status'] in ('CONSISTENT', 'INCONSISTENT')
    assert partition == matrix.partition_layouts(sess.layouts['minimum'], 52428800)


def test_unready_s_multi_stops_with_its_parts_and_evidence_retained(s, monkeypatch):
    session, matrix, run = s
    monkeypatch.setattr(session.Session, 'run_steps', lambda self: None)
    result, fake = {}, Fake(run)
    with pytest.raises(session.VerificationError, match='Matrix multi source incomplete') as caught:
        session.exercise(fake, run, result, 'S-MULTI')
    record = result['matrix']
    assert session.Session.failure_class(caught.value)['code'] == 'MATRIX_MULTI_SOURCE_INCOMPLETE'
    assert record['classifications']['multi_source_ready'] is False
    assert record['classifications']['multi_source_missing'] == matrix.multi_requirements()
    assert [(st['step'], st['status']) for st in record['steps']][-1] == ('source_readiness', 'FAILED')
    assert record['multipart_evidence']['role'] == 'SOURCE' and record['completed'] is False
    assert record['multipart_evidence']['source']['readiness']['ready'] is False
    assert matrix.project(record) == record and 'matrix_completed' not in result


def test_ready_s_multi_completes_and_marks_its_minimum_artifact(s, monkeypatch):
    session, matrix, run = s
    monkeypatch.setattr(session.Session, 'run_steps', lambda self: self.record['artifacts'].update(
        minimum={'parts': [], 'closure': 'CLOSED'}))
    monkeypatch.setattr(matrix, 'multi_readiness', lambda *a: {'schema': matrix.MULTI_READINESS_SCHEMA,
                                                               'ready': True, 'missing': []})
    result = {}
    session.exercise(Fake(run), run, result, 'S-MULTI')
    record = result['matrix']
    assert record['classifications']['multi_source_ready'] is True and record['artifacts']['minimum']['source_ready']
    assert record['steps'][-1] == {'step': 'source_readiness', 'status': 'DONE', 'multi_source_ready': True}
    assert matrix.source_ready(record, matrix.case('T-MULTI-ORDERED')) is True


@pytest.mark.parametrize('case', B_DEPENDENTS)
def test_b_restore_is_proven_and_ribbon_gated_before_file_selection(s, case):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, case, result=result)
    b_inputs(run, result, matrix, case)
    fake.restore_rows = 4
    outcome = sess.restore()
    record = result['matrix']
    assert record['multipart_input']['proven'] is True and record['pre_restore_error_ribbon'] == 'HIDDEN'
    assert outcome['selected_files'] == len(result['matrix_inputs']['selection'])
    selected = [t for t in fake.typed if t[0].startswith('input.file.back_up')]
    assert len(selected) == 1 and selected[0][1].count('\n') + 1 == outcome['selected_files']
    assert matrix.project(record['multipart_input']) == record['multipart_input']


@pytest.mark.parametrize('damage', ['unready', 'other-root', 'tampered-selection', 'unreadable'])
def test_unproven_b_selection_refuses_before_any_file_selection(s, damage):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-MULTI-DUP', result=result)
    b_inputs(run, result, matrix, 'T-MULTI-DUP', ready=damage != 'unready', same_root=damage != 'other-root')
    if damage == 'tampered-selection':
        # A consistent but undeclared selection (no duplicate): digests match, the relation does not.
        result['matrix_inputs']['selection'].pop()
    elif damage == 'unreadable':
        (run / 'inputs/source/part-2.json').unlink()
    with pytest.raises(session.VerificationError, match='Matrix multipart input unproven') as caught:
        sess.restore()
    assert session.Session.failure_class(caught.value)['code'] == 'MATRIX_MULTIPART_INPUT_UNPROVEN'
    record = result['matrix']
    assert record['multipart_input']['proven'] is False
    assert 'pre_restore_error_ribbon' not in record and 'restores' not in record
    assert not [t for t in fake.typed if t[0].startswith('input.file.back_up')] and fake.transitions == 0


@pytest.mark.parametrize('visible', [True, None])
def test_pre_existing_or_unreadable_ribbon_refuses_a_proven_b_restore(s, monkeypatch, visible):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-MULTI-NO-P1', result=result)
    b_inputs(run, result, matrix, 'T-MULTI-NO-P1')
    state = sess.state
    monkeypatch.setattr(sess, 'state', lambda: dict(state(), error_visible=visible))
    with pytest.raises(session.VerificationError, match='Matrix pre-existing error ribbon'):
        sess.restore()
    assert result['matrix']['multipart_input']['proven'] is True
    assert result['matrix']['pre_restore_error_ribbon'] == ('VISIBLE' if visible else 'UNREADABLE')
    assert not [t for t in fake.typed if t[0].startswith('input.file.back_up')] and fake.transitions == 0


def test_no_signal_fails_a_complete_b_set_but_is_an_observation_for_a_sentinel_case(s):
    session, matrix, run = s
    for case, allowed in (('T-MULTI-ORDERED', False), ('T-MULTI-NO-MIDDLE', True)):
        result, root = {}, run / case
        root.mkdir()
        sess, fake, _ = start(session, matrix, root, case, result=result)
        b_inputs(root, result, matrix, case)
        fake.restore_behaviour = 'silent'
        if allowed:
            assert sess.restore()['completion'] == 'DEADLINE_NO_SIGNAL'
        else:
            with pytest.raises(session.VerificationError, match='Matrix step deadline'):
                sess.restore()
            assert result['matrix']['restores'][0]['completion'] == 'DEADLINE_NO_SIGNAL'


def test_post_export_split_notices_are_never_restore_reports_and_the_multipart_post_closes(s):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-MULTI-ORDERED', result=result)
    source, _ = b_inputs(run, result, matrix, 'T-MULTI-ORDERED')
    outcome = sess.restore()
    assert outcome['completion'] == 'COMPLETED' and outcome['silent_codes'] == [] and outcome['error_codes'] == []
    sess.reload()
    # The restored minimum threshold makes the post-export multipart; each split silently reports cnt_1436
    # (backup.partition_split_notice) after the restore window closed.
    fake.reports += [{'code': 'cnt_1436', 'silent': True}] * 2
    fake.exports, fake.backgrounds = [source], 4
    assert sess.export('post', multi=True) == {'label': 'post', 'parts': 3, 'closure': 'CLOSED'}
    assert result['matrix']['restores'] == [outcome] and result['matrix']['artifacts']['post']['threshold'] == 52428800


def test_b_classify_records_contained_multipart_evidence(s, monkeypatch):
    session, matrix, run = s
    result = {}
    sess, fake, _ = start(session, matrix, run, 'T-MULTI-REVERSED', result=result)
    source, _ = b_inputs(run, result, matrix, 'T-MULTI-REVERSED')
    sess.restore()
    sess.fingerprints.update(pre=matrix.fingerprint([EMPTY]), post=matrix.fingerprint(source))
    sess.record['artifacts']['post'] = {'closure': 'CLOSED', 'complete': True, 'parts': [{}, {}, {}],
                                        'derived': sess.fingerprints['post']['derived']}
    sess.classify()
    evidence = result['matrix']['multipart_evidence']
    assert evidence['schema'] == 'bux-r6-multipart-evidence-v1' and evidence['case'] == 'T-MULTI-REVERSED'
    assert evidence['evidence'] == 'OBSERVED' and evidence['input']['proof']['selected_ordinals'] == [3, 2, 1]
    assert evidence['semantics']['post_vs_selection_native_order'] == 'SEMANTIC_EQUAL'
    assert evidence['completion']['restore_error'] == 'UNKNOWN'
    monkeypatch.setattr(matrix, 'multipart_evidence', lambda *a: {'raw': '/Users/x'})
    sess.classify()
    assert result['matrix']['multipart_evidence'] == {'schema': 'bux-r6-multipart-evidence-v1',
                                                      'case': 'T-MULTI-REVERSED', 'evidence': 'REFUSED'}


def test_b_session_codes_are_fixed(s):
    session, matrix, run = s
    assert session.SESSION_CODES['Matrix multipart input unproven'] == 'MATRIX_MULTIPART_INPUT_UNPROVEN'
    assert matrix.MATRIX_CODES['Matrix multi source incomplete'] == 'MATRIX_MULTI_SOURCE_INCOMPLETE'
    assert set(session.SESSION_CODES).isdisjoint(matrix.MATRIX_CODES)
