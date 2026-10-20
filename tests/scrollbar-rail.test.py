"""R8 source-only independent model/oracles; no browser rendering claim."""
import json
import re
import shutil
import subprocess

import pytest

EXT = 'extensions/browser-ux-scrollbars'
SCENARIOS = ('activation', 'empty', 'geometry', 'rootStyles', 'rootOverflow',
             'rootPaintVariable', 'hostCascade', 'thickness', 'preexistingTopLayer',
             'topLayerLifecycle', 'manualStack', 'shadowTopLayer', 'fullscreenVariants',
             'documentLifecycle', 'dragAndSuspend', 'trackAndWheel', 'eligibility',
             'flatInert', 'layoutClip', 'clippedTrack', 'overlap', 'siblingOverlap',
             'discovery', 'dynamics', 'bounds', 'scanLimit', 'slowRefusal', 'frameworkRemoval',
             'rootSidesAndQuirks', 'resizeAndContent', 'mutationStorm', 'externalContest',
             'sameNamePagePopover', 'idleContentGrowth', 'nonFocusable', 'routingRecovery',
             'selectRecovery', 'dynamicRootZoom', 'layoutBudgetRetention', 'opacityEligibility',
             'dragQueryBound', 'selectorCostBackoff')
SCENARIOS += ('mutationCallbackBudget', 'recomputationBudget', 'focusPreserved', 'selectorRecognizedWithoutSemantics', 'selectorFailureAfterInstall', 'closedShadowModal', 'closedShadowModalNoToggleEvents', 'closedShadowPopoverDeclarative', 'lateOpenShadow', 'nestedClosedShadow', 'rootAfterManyMutations', 'rootBudgetAtLimit', 'rootBudgetExceeded', 'attachShadowReplaced', 'attachShadowThrows', 'wrapperFidelity', 'selectorUnsupportedmodal', 'selectorUnsupportedpopoveropen', 'selectorUnsupportedselectopen', 'rootInstrumentationFailure', 'hostPopoverAlone', 'hostPlusClosedPopover', 'lateHandshake', 'missingSentinel', 'heartbeatExpiry', 'malformedBridge', 'changedInstance', 'pointermoveNoQuery', 'adoptedUncapturedClosedHost', 'droppedDiscoveryRecords', 'droppedDiscoveryAddedNodes', 'lostVerifyAck', 'crossRootPicker', 'parserDsdClosedBackstop', 'lateInstall', 'dsdApiLatch', 'clonableLatch', 'documentOpenProbe', 'coverageAccessorUnavailable')
SCENARIOS += ('continuouslyChangingSmallMutationDragPreservation', 'largeParserInsertionRecovery', 'unrelatedKeystrokesWith26ClosedRoots', 'relevantTargetedSelectActivation', 'incrementalMutationQueryWalkBoundedness', 'activePageModalDuringMutationOverload')
SCENARIOS += ('coalescedPickerRoots',)
SCENARIOS += ('isolatedRecordsOverflowRecovery', 'isolatedAddedNodesOverflowRecovery',
              'coverageAddedOverflowRecovery', 'coverageAddedTwoWorldRecovery',
              'coverageWorkBudgetRecovery', 'coverageStartBudgetRecovery', 'cooldownNoPolling',
              'structuralTreeLimitHold', 'permanentLossSurvivesLocalThrottle',
              'activeModalDuringLocalThrottle', 'throttleDuringBridgeGap',
              'incrementalRestartRetainsUnwalkedDelta', 'disconnectedUnfinishedRootRetry',
              'continuousLargeMutationBoundedHold')
SCENARIOS += ('detachedVerifiedRootReattach', 'detachedBenignReverify',
              'detachedMutationUndone', 'detachedCoalescedMutations',
              'nestedDetachedAncestor', 'multiLevelDetachedAncestor',
              'detachedNeverReattached', 'detachReattachNoMutation',
              'reattachImmediateTopLayer', 'dirtyRootMovesConnected',
              'detachedRootPermanentLatch', 'throttledDetachedRoot',
              'structuralHoldDetachedRoot', 'disconnectedAddedNodeAtCallback',
              'restartDropsDetachedPendingTask', 'throttleClearedDetachedDelta',
              'detachedCapturedRootFullWalk', 'aggregateRootRemovalBudget',
              'reattachBeforeDetachedRecordDelivery', 'connectedCallbackDetachedThreat')


def run_model(root, extension=None, scenario=None):
    argv = [shutil.which('node'), str(root / 'tests/scrollbar-rail-harness.mjs'),
            str(extension or root / EXT)]
    if scenario:
        argv.append(scenario)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert not completed.stderr, completed.stderr
    return json.loads(completed.stdout), completed.returncode


@pytest.fixture(scope='module')
def model_results(repo_root):
    return run_model(repo_root)


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_observable_invariant(model_results, scenario):
    results, _ = model_results
    assert results[scenario] == 'PASS', results[scenario]


@pytest.fixture
def prefs(load_module):
    return load_module('tests/browser_preferences.py')


def test_host_pins_cover_open_hidden_and_pseudos(prefs, repo_root):
    sheet = (repo_root / EXT / 'rail-host.css').read_text()
    assert prefs.check_host_sheet(sheet) == []
    for prop, value in prefs.HOST_OPEN_PINS.items():
        start = sheet.index('browser-ux-scrollbar-shell:popover-open {')
        prefix, opened = sheet[:start], sheet[start:]
        old = f'{prop}: {value} !important;'
        assert old in opened, prop
        assert prefs.check_host_sheet(prefix + opened.replace(old, '', 1)), prop
    assert prefs.check_host_sheet(sheet + '\nbrowser-ux-scrollbar-shell { display: block !important; }')


@pytest.mark.parametrize('attack', ['normal', 'important', 'layer', 'inline', 'animation'])
def test_user_host_pins_dominate_author_origin(prefs, repo_root, attack):
    sheet = (repo_root / EXT / 'rail-host.css').read_text()
    for selector, declarations in prefs.css_rules(sheet):
        for prop, value, important in declarations:
            user = dict(origin='user', important=important, property=prop, value=value)
            author = dict(origin='animation' if attack == 'animation' else 'author',
                          important=attack in ('important', 'layer', 'inline'), property=prop,
                          value='ATTACK', specificity=(100, 100, 100), order=100)
            if attack == 'layer':
                author['layer'] = 0
            if attack == 'inline':
                author['inline'] = True
            assert prefs.winner(user, author)['value'] == value, (selector, prop, attack)
            if attack not in ('animation', 'normal'):
                assert prefs.winner(dict(user, origin='author', specificity=(0, 0, 1)), author)['value'] == 'ATTACK'


def test_transitions_require_disabling_motion(prefs, repo_root):
    sheet = (repo_root / EXT / 'rail-host.css').read_text()
    # Cascade 5 ranks an active transition above USER-important. Disabling its
    # creation is required; a raw origin model must never pretend it loses.
    assert prefs.winner(dict(origin='user', important=True, value='1'),
                        dict(origin='transition', important=True, value='0'))['value'] == '0'
    assert prefs.check_host_sheet(sheet.replace('transition: none !important;', '', 1))


MUTATIONS = (
    ('content.js', ' || sentinelReason === "COVERAGE_THROTTLED"', '', 'isolatedRecordsOverflowRecovery'),
    ('content.js', 'Math.max(1, coverageUntil - now())', '1', 'cooldownNoPolling'),
    ('content.js', 'coverageAdded.add(task.root)', 'void task.root', 'incrementalRestartRetainsUnwalkedDelta'),
    ('content.js', 'let qualifying = false;', 'coverageBlocked = false; let qualifying = false;', 'structuralTreeLimitHold'),
    ('content.js', 'mainPermanent = true;', 'mainPermanent = false;', 'permanentLossSurvivesLocalThrottle'),
    ('content.js', 'observeSafety(root);',
     'observeSafety(root); verifiedRoots.add(root);',
     'disconnectedUnfinishedRootRetry'),
    ('content.js', 'verifiedRoots.delete(root)', 'void root', 'detachedVerifiedRootReattach'),
    ('content.js', 'root = root.host.getRootNode()', 'root = document', 'nestedDetachedAncestor'),
    ('content.js', 'if (records.length && observed.host && (coverageRescan || detachedPath(observed.host))) unverify(observed);', '', 'disconnectedAddedNodeAtCallback'),
    ('content.js', 'detachedSubtrees.add(node)', 'void node', 'reattachBeforeDetachedRecordDelivery'),
    ('content.js', 'else unverify(node);', 'else void node;', 'restartDropsDetachedPendingTask'),
    ('content.js', 'if (current.full) verifiedRoots = new WeakSet(current.roots);\n      else ', '', 'throttleClearedDetachedDelta'),
    ('content.js', 'safetyRecordsThisCycle > 512', 'records.length > 512', 'aggregateRootRemovalBudget'),
    ('toplayer-sentinel-main.js', 'else registerRoot(root, this);', 'else void root;', 'closedShadowModal'),
    ('toplayer-sentinel-main.js', 'rootRefs.size >= MAX_ROOTS', 'false', 'rootBudgetExceeded'),
    ('toplayer-sentinel-main.js', 'descriptor(target, name)?.value !== wrapper', 'false', 'attachShadowReplaced'),
    ('toplayer-sentinel-main.js', 'if (el !== boundHost)', 'if (el.localName !== "browser-ux-scrollbar-shell")', 'sameNamePagePopover'),
    ('content.js', 'message.seq <= sentinelSeq', 'false', 'malformedBridge'),
    ('rail-core.js', 'SENTINEL_LIVENESS_MS: 3000', 'SENTINEL_LIVENESS_MS: 300000', 'heartbeatExpiry'),
    ('content.js', 'if (!sendSentinel("verify", el, current.epoch))', 'if (false && !sendSentinel("verify", el, current.epoch))', 'lostVerifyAck'),
    ('toplayer-sentinel-main.js', 'if (changed) invalidate();', 'if (false) invalidate();', 'adoptedUncapturedClosedHost'),
    ('content.js', 'if (!verifyHost())', 'if (false)', 'hostCascade'),
    ('content.js', 'scanCount >= L.SCAN_TOTAL', 'false', 'scanLimit'),
    ('content.js', 'items.slice(0, L.MAX_RAILS)', 'items.slice(0, 1000)', 'bounds'),
    ('content.js', 'b.item.depth - a.item.depth)[0]', 'a.item.depth - b.item.depth)[0]', 'overlap'),
)


@pytest.mark.parametrize('name,old,new,scenario', MUTATIONS)
def test_model_kills_semantic_mutations(repo_root, tmp_path, name, old, new, scenario):
    copy = tmp_path / 'extension'
    shutil.copytree(repo_root / EXT, copy, copy_function=shutil.copyfile)
    path = copy / name
    text = path.read_text()
    assert old in text
    text = text.replace(old, new, 1)
    if scenario == 'disconnectedUnfinishedRootRetry':
        # R8's dropped-task withdrawal and full-walk replacement
        # mask R7's premature-marking mutation. The retained R7 kill therefore
        # removes those two fallback guards as one explicit mutation family.
        text = text.replace('else unverify(node);', 'else void node;')
        text = text.replace('if (current.full) verifiedRoots = new WeakSet(current.roots);\n      else ', '')
    if scenario == 'sameNamePagePopover' and name == 'toplayer-sentinel-main.js':
        # One mutation family replaces exact host identity with a generic name
        # in transition observation and both document-query branches.
        text = text.replace('target === boundHost', 'target?.localName === "browser-ux-scrollbar-shell"')
        text = text.replace('first !== boundHost', 'first.localName !== "browser-ux-scrollbar-shell"')
    path.write_text(text)
    results, code = run_model(repo_root, copy, scenario)
    assert code != 0 and results[scenario].startswith('FAIL:'), (scenario, results)


def test_dom_write_oracle_is_independent(repo_root, tmp_path):
    copy = tmp_path / 'extension'
    shutil.copytree(repo_root / EXT, copy, copy_function=shutil.copyfile)
    path = copy / 'content.js'
    source = path.read_text().replace('function start() {', 'function start() { document.body.style.overflow = "auto";')
    path.write_text(source)
    results, code = run_model(repo_root, copy, 'geometry')
    assert code != 0 and 'page presentation was mutated' in results['geometry']


def test_toplayer_fixture_is_offline_and_matrix_is_explicit(repo_root):
    source = (repo_root / 'tests/fixtures/browser-preferences/scrollbar-toplayer-matrix.html').read_text()
    for token in ('fetch(', 'XMLHttpRequest', 'WebSocket(', 'EventSource(', 'sendBeacon(', 'https://', 'http://'):
        assert token not in source
    ids = re.findall(r'id="(t\d+)"\s+data-expect="(visible|absent|suspended|record)"', source)
    assert len(ids) >= 40 and len({i for i, _ in ids}) == len(ids)
    assert not re.search(r'createElement\([\"\']browser-ux-scrollbar', source), 'fixture must not provide a substitute rail'
    for token in ('ROOT_GUTTER_UNPAINTABLE', 'RAIL_VISIBLE_USABLE', 'NATIVE_UNOCCLUDED', '61000', 'showModal', 'showPopover', 'requestFullscreen'):
        assert token in source
