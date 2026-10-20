"""BUX5B1 RECOVERY-HOSTPREP1 adapter contracts. Portable: no browser, XPI execution or live profile.

The accepted guarded_recovery library runs for real; the native side is a fake driver over the
accepted 6.12.1 fixture export (test-only byte edits stand in for the extension's own UI and
restore). Nothing here is evidence of native recovery behaviour.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures/cnt-native/firefox/6.12.1'
FIX = (FIXTURE / 'export.json').read_bytes()
NONCE, GLOBAL = 'c' * 64, 'd' * 64
UUID_STAGING, UUID_TARGET = '11111111-2222-4333-8444-555555555555', '66666666-7777-4888-9999-aaaaaaaaaaaa'
SCENARIOS = ('NOOP_MATCH', 'SYNTHETIC_RESET_COMPLETED', 'OPERATOR_AUTH_COMPLETED', 'CONCURRENT_CHANGE',
             'POST_APPLY_MISMATCH_ROLLBACK', 'ROLLBACK_FAILURE', 'INTERRUPTED_ROLLBACK_RESUME',
             'TARGET_IDENTITY_REFUSAL', 'REQUESTED_PART_REFUSAL', 'IDEMPOTENT_REPEAT')


@pytest.fixture
def r(monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_firefox_recovery
    return cnt_firefox_recovery


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def empty_export():
    import cnt_firefox_matrix as m
    return FIX[:m.part_layout(FIX)['header_bytes']] + b']}'


def theme(raw, value):
    return re.sub(rb'"options_page_theme":"[a-z_]+"', b'"options_page_theme":"' + value.encode() + b'"', raw, count=1)


def split(threshold=None, minimum=2):
    """Test-only native-template regrouping of the fixture at a threshold whose verified partition
    predicate yields at least `minimum` parts (the first such threshold when none is given)."""
    import cnt_firefox_matrix as m
    for value in ([threshold] if threshold else range(1000, 60000, 250)):
        v = json.loads(FIX)
        for n in range(len(v['chunks']) + 1, 9):  # distinct extra rows, as the R6 session tests add
            extra = json.loads(json.dumps(v['chunks'][0]))
            extra['data']['id'], extra['data']['i'] = f'bux-test-{n}', str(n)
            v['chunks'].append(extra)
        v['settings']['prefs']['one_backup_file_size_in_bytes'] = value
        raw = json.dumps(v, separators=(',', ':')).encode()
        header = raw[:raw.index(b'"chunks":[') + len(b'"chunks":[')]
        chunks = [json.dumps(c, separators=(',', ':')).encode() for c in v['chunks']]
        sim = m.simulate_partition([len(c) for c in chunks], len(header), value)
        if len(sim['parts']) >= minimum and all(sim['well_formed']) and not sim['empty_parts']:
            return [(header if n == 0 else b'{"chunks":[') + b','.join(chunks[i] for i in g) + b']}'
                    for n, g in enumerate(sim['parts'])]
    raise AssertionError('no split')


def observation(parts, **changes):
    value = {'facts_verified': True, 'baseline_captured': 0, 'baseline_stable': True, 'clicks': 1,
             'start_observed': True, 'end_observed': True, 'end_captured': len(parts),
             'dom_backgrounds': sum(len(json.loads(p)['chunks']) for p in parts),
             'entries': [{'index': i, 'name_class': f'NATIVE_PART_{i + 1}', 'bytes': len(p), 'sha256': sha(p)}
                         for i, p in enumerate(parts)], 'parts': list(parts)}
    value.update(changes)
    return value


def labels(r):
    return dict(r.ds.PROJECTED_LABELS)


# --- bindings, pins and library loading --------------------------------------------------------------

def test_recovery_prep1_binding_and_library_pins_are_exact(r, repo_root):
    assert r.RECOVERY_PREP1 == {'tree': '622154aa87074f394f0f0baca3879a58bb4d9a76', 'candidate_paths': 56,
                                'entries': 201,
                                'inventory_sha256': '24c0faa0008c4cf889ba93fbec47bca4d84e56489bfc37e36ea9ff67a66a1837'}
    assert r.GUARDED_RECOVERY_SHA256 == '1cf34e0edbbaee0ceb5e9ad80284abbb2f84c813b3b853766954254d950b8053'
    assert r.DURABLE_STATE_SHA256 == '7a1dd704988088c22d1502b72318183960c8f70e3bde6e9908ec42255c653eea'
    libexec = repo_root / 'libexec/clear-new-tab'
    assert sha((libexec / 'guarded_recovery.py').read_bytes()) == r.GUARDED_RECOVERY_SHA256
    assert sha((libexec / 'durable_state.py').read_bytes()) == r.DURABLE_STATE_SHA256
    # The stale staged-manager value is recorded only; it is never the loaded foundation.
    assert r.STALE_DURABLE_STATE_SHA256.startswith('4a861666') and r.STALE_DURABLE_STATE_SHA256 != r.DURABLE_STATE_SHA256


def test_firefox_xpi_and_r4_pins_alias_their_owners(r):
    import cnt_firefox_matrix as m, cnt_firefox_production as f
    assert r.CAPTURE_SHA256 == m.XPI_SHA256 == 'bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f'
    assert r.FIREFOX_VERSION == f.VERSION == '156.0.1' and r.EXTENSION_VERSION == '6.12.1'
    assert r.ds.PROJECTED_LABELS == {'engine': 'firefox', 'extension_id': 'clear-new-tab@loftyshaky',
                                     'extension_version': '6.12.1', 'browser_version': '156.0.1'}


def test_library_is_private_and_has_one_foundation_instance(r, repo_root):
    assert all(module is not r.gr and module is not r.ds for module in list(sys.modules.values()))
    assert 'browser_ux_cnt_durable_state' not in sys.modules
    assert Path(r.ds.__spec__.origin) == repo_root / 'libexec/clear-new-tab/durable_state.py'
    assert r.gr.ds is r.ds and r.gr.RecoveryError.__module__ == r.gr.__name__


@pytest.mark.parametrize('name', ['guarded_recovery.py', 'durable_state.py'])
def test_tampered_library_refuses_before_execution(r, repo_root, tmp_path, name):
    libexec = tmp_path / 'libexec'
    shutil.copytree(repo_root / 'libexec/clear-new-tab', libexec)
    marker = tmp_path / 'executed'
    (libexec / name).chmod(0o644)  # copytree keeps the read-only mode of a Nix store source
    with (libexec / name).open('a') as stream:
        stream.write(f'\nopen({str(marker)!r}, "w").close()\n')
    with pytest.raises(r.VerificationError, match='^Recovery library digest mismatch$'):
        r.load_libraries(libexec)
    assert not marker.exists()
    assert r.RECOVERY_CODES['Recovery library digest mismatch'] == 'RECOVERY_LIBRARY_DIGEST_MISMATCH'


def test_untampered_copy_loads_with_its_own_sibling_foundation(r, repo_root, tmp_path):
    libexec = tmp_path / 'libexec'
    shutil.copytree(repo_root / 'libexec/clear-new-tab', libexec)
    loaded = r.load_libraries(libexec)
    assert Path(loaded.ds.__spec__.origin) == libexec / 'durable_state.py' and loaded is not r.gr


# --- independent export closure ------------------------------------------------------------------------

def test_single_part_export_closes_and_counts_only_the_closed_set(r):
    proof = r.prove_export_closure(observation([FIX]), labels(r))
    assert proof.part_count == 1 and proof.parts == (FIX,)
    assert proof.facts['partition_status'] == 'CONSISTENT' and proof.facts['projection_status'] == r.ds.PROJECTED
    assert proof.facts['part_sha256'] == [sha(FIX)] and proof.facts['rows'] == 4


def test_multipart_export_closes_on_the_native_partition_predicate(r):
    parts = split()
    proof = r.prove_export_closure(observation(parts), labels(r))
    assert proof.part_count == len(parts) >= 2 and proof.facts['partition_status'] == 'CONSISTENT'


def test_empty_state_closes_only_as_one_empty_part(r):
    proof = r.prove_export_closure(observation([empty_export()]), labels(r))
    assert proof.part_count == 1 and proof.facts['partition_status'] == r.EMPTY_SINGLE_PART
    assert proof.facts['rows'] == 0
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        r.prove_export_closure(observation([empty_export()], dom_backgrounds=1), labels(r))


def _negatives():
    def drop(index):
        def change(parts, obs):
            del obs['parts'][index]
            del obs['entries'][index]
            for n, e in enumerate(obs['entries']):
                e['index'] = n
            obs['end_captured'] = len(obs['parts'])
        return change
    def drop_named(index):
        def change(parts, obs):
            del obs['parts'][index]
            del obs['entries'][index]
            obs['end_captured'] = len(obs['parts'])
        return change
    def setter(key, value):
        return lambda parts, obs: obs.update({key: value})
    def entry(index, key, value):
        return lambda parts, obs: obs['entries'][index].update({key: value})
    def regroup(parts, obs):
        merged = [parts[0][:-2] + b',' + parts[1][len(b'{"chunks":['):]] + parts[2:]
        obs.update(observation(merged))
        obs['parts'], obs['entries'] = obs['parts'][:1] + [parts[-1]], obs['entries'][:1] + [
            {'index': 1, 'name_class': 'NATIVE_PART_2', 'bytes': len(parts[-1]), 'sha256': sha(parts[-1])}]
        obs['end_captured'] = 2
    def pretty(parts, obs):
        raw = json.dumps(json.loads(parts[0]), indent=1).encode()
        obs['parts'][0], obs['entries'][0] = raw, dict(obs['entries'][0], bytes=len(raw), sha256=sha(raw))
    def settings_on_two(parts, obs):
        first = json.loads(parts[0])
        second = dict(first, chunks=json.loads(parts[1])['chunks'])
        raw = json.dumps(second, separators=(',', ':')).encode()
        obs['parts'][1], obs['entries'][1] = raw, dict(obs['entries'][1], bytes=len(raw), sha256=sha(raw))
    def truncate(parts, obs):
        raw = parts[0][:-7]
        obs['parts'][0], obs['entries'][0] = raw, dict(obs['entries'][0], bytes=len(raw), sha256=sha(raw))
    def duplicate(parts, obs):
        obs['parts'].append(parts[-1])
        obs['entries'].append({'index': len(parts), 'name_class': f'NATIVE_PART_{len(parts) + 1}',
                               'bytes': len(parts[-1]), 'sha256': sha(parts[-1])})
        obs['end_captured'] += 1
    def extra_part(parts, obs):
        obs['end_captured'] += 1
    return {
        'missing-first': drop(0), 'missing-middle': drop(1), 'missing-last': drop(-1),
        'gap-in-names': drop_named(1), 'duplicate-part': duplicate, 'extra-unread-part': extra_part,
        'duplicate-name': entry(1, 'name_class', 'NATIVE_PART_1'), 'duplicate-index': entry(1, 'index', 0),
        'unexpected-name': entry(0, 'name_class', 'UNEXPECTED_NAME'), 'digest-mismatch': entry(0, 'sha256', '0' * 64),
        'size-mismatch': entry(0, 'bytes', 1),
        'baseline-not-empty': setter('baseline_captured', 1), 'baseline-unstable': setter('baseline_stable', False),
        'no-start': setter('start_observed', False), 'no-end': setter('end_observed', False),
        'two-clicks': setter('clicks', 2), 'no-click': setter('clicks', 0),
        'facts-unverified': setter('facts_verified', False),
        'rows-short': lambda parts, obs: obs.update(dom_backgrounds=obs['dom_backgrounds'] + 1),
        'rows-excess': lambda parts, obs: obs.update(dom_backgrounds=obs['dom_backgrounds'] - 1),
        'unparseable': truncate, 'not-native-template': pretty, 'settings-header-off-part-1': settings_on_two,
        'inconsistent-partition': regroup,
        'forged-part-count': setter('part_count', 1), 'unknown-key': setter('total', 3),
    }


NEGATIVES = _negatives()


@pytest.mark.parametrize('name', sorted(NEGATIVES))
def test_export_closure_negatives_refuse_export_incomplete(r, name):
    parts = split(minimum=3)
    obs = observation(parts)
    NEGATIVES[name](parts, obs)
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        r.prove_export_closure(obs, labels(r))
    assert r.RECOVERY_CODES['Recovery export incomplete'] == 'EXPORT_INCOMPLETE'


@pytest.mark.parametrize('bound', ['part', 'set', 'count'])
def test_export_closure_bounds(r, monkeypatch, bound):
    parts = split()
    if bound == 'part':
        monkeypatch.setattr(r.gr, 'MAX_NATIVE_PART_BYTES', max(len(p) for p in parts) - 1)
    elif bound == 'set':
        monkeypatch.setattr(r.gr, 'MAX_PART_SET_BYTES', sum(len(p) for p in parts) - 1)
    else:
        monkeypatch.setattr(r.ds, 'MAX_ARTIFACTS', len(parts) - 1)
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        r.prove_export_closure(observation(parts), labels(r))


def test_unprojected_labels_never_close(r):
    other = dict(labels(r), browser_version='155.0.1')
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        r.prove_export_closure(observation([FIX]), other)


def test_forged_part_count_cannot_bypass_the_closure_proof(r):
    with pytest.raises(r.VerificationError):
        r.ClosureProof()
    proof = r.prove_export_closure(observation([FIX]), labels(r))
    with pytest.raises(r.VerificationError):
        proof.part_count = 3
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        r.export_from_proof({'parts': [FIX], 'part_count': 1, 'facts': {}}, labels(r))
    export = r.export_from_proof(proof, labels(r))
    assert export == {'labels': labels(r), 'part_count': 1, 'parts': [FIX]}
    # The adapter's export comes only from a ClosureProof the driver returns.
    class Forger:
        def closed_export(self):
            return {'parts': [FIX], 'part_count': 2}
        def labels(self):
            return labels(r)
    adapter = r.FirefoxRecoveryAdapter(Forger())
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        adapter.export_current()
    assert adapter.codes == ['EXPORT_INCOMPLETE']
    target = r.gr.bind_target({'labels': labels(r), 'profile_token': 'a' * 64, 'storage_token': 'b' * 64})
    with pytest.raises(r.gr.RecoveryError, match='^EXPORT_INCOMPLETE$'):
        r.gr.verify_export({'labels': labels(r), 'part_count': 2, 'parts': [FIX]}, target)


# --- tokens and labels -----------------------------------------------------------------------------------

def test_tokens_are_opaque_role_free_and_independent(r):
    a, b = r.profile_token(NONCE, 7, 2), r.profile_token(NONCE, 7, 3)
    assert a != b and re.fullmatch('[0-9a-f]{64}', a) and r.profile_token(NONCE, 7, 2) == a
    assert r.profile_token('e' * 64, 7, 2) != a
    s1, s2 = r.storage_token(NONCE, UUID_STAGING), r.storage_token(NONCE, UUID_TARGET)
    assert s1 != s2 and s1 not in (a, b)
    for bad in (None, 'moz-extension://x', '/Users/x/Library', UUID_TARGET.upper()):
        with pytest.raises(r.VerificationError, match='^Recovery storage identity unavailable$'):
            r.storage_token(NONCE, bad)


def test_labels_are_proven_only_from_session_facts(r):
    result = {'browser_version': '156.0.1',
              'capture_copy': {'xpi_sha256': r.CAPTURE_SHA256, 'extension_id': r.EXTENSION_ID, 'version': '6.12.1'},
              'recovery_session': {'steps': [{'step': 'open_settings', 'status': 'DONE'}]}}
    assert r.proven_labels(result) == labels(r)
    for change in ({'browser_version': '155.0.1'}, {'capture_copy': {}},
                   {'recovery_session': {'steps': [{'step': 'open_settings', 'status': 'FAILED'}]}}):
        with pytest.raises(r.VerificationError, match='^Recovery target labels unproven$'):
            r.proven_labels({**result, **change})


# --- pre-launch freshness / staging disposability ----------------------------------------------------------

@pytest.fixture
def fresh(r, tmp_path, monkeypatch):
    import cnt_confinement, cnt_firefox_matrix as m
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', scratch)
    root = scratch / 'claim'
    (root / 'cases').mkdir(parents=True, mode=0o700)
    run = root / 'cases' / '03-staging-x'
    run.mkdir(mode=0o700)
    for name in ('home', 'profile', 'tmp', 'downloads', 'crash-data', 'capture'):
        (run / name).mkdir(mode=0o700)
    user_js = b'user_pref("network.offline",true);\n'
    (run / 'profile/user.js').write_bytes(user_js)
    (run / 'capture/clear-new-tab.xpi').write_bytes(b'synthetic capture')
    monkeypatch.setattr(m, 'verify_capture', lambda path: {'xpi_sha256': r.CAPTURE_SHA256})
    plan = {'role': 'staging', 'claim_root': str(root), 'attempt_name': run.name}
    return r, plan, run, user_js


def test_fresh_staging_profile_is_proven(fresh):
    r, plan, run, user_js = fresh
    facts = r.prove_fresh_profile(plan, run, user_js, created_exclusive=True)
    assert facts['proven'] is True and facts['copy_route'] == 'NONE' and facts['xpi_only_capture'] is True


@pytest.mark.parametrize('damage', ['not-exclusive', 'outside-claim-root', 'symlink-final', 'symlink-ancestor',
                                    'mode', 'cases-mode', 'owner', 'extra-profile-entry', 'altered-user-js', 'extra-xpi',
                                    'missing-capture', 'profile-not-directory'])
def test_staging_disposability_negatives_refuse_before_launch(fresh, monkeypatch, tmp_path, damage):
    r, plan, run, user_js = fresh
    exclusive = damage != 'not-exclusive'
    if damage == 'outside-claim-root':
        plan = dict(plan, attempt_name='other')
    elif damage == 'symlink-final':
        real = run.parent / 'real'
        run.rename(real)
        run.symlink_to(real)
    elif damage == 'symlink-ancestor':
        cases = run.parent
        cases.rename(cases.parent / 'cases-real')
        cases.symlink_to(cases.parent / 'cases-real')
    elif damage == 'mode':
        run.chmod(0o755)
    elif damage == 'cases-mode':
        run.parent.chmod(0o755)
    elif damage == 'owner':
        monkeypatch.setattr(os, 'geteuid', lambda: os.getuid() + 1)
    elif damage == 'extra-profile-entry':
        (run / 'profile/prefs.js').write_text('copied')
    elif damage == 'altered-user-js':
        (run / 'profile/user.js').write_bytes(user_js + b'user_pref("x",1);\n')
    elif damage == 'extra-xpi':
        (run / 'downloads/other.XPI').write_bytes(b'x')
    elif damage == 'missing-capture':
        (run / 'capture/clear-new-tab.xpi').unlink()
    elif damage == 'profile-not-directory':
        shutil.rmtree(run / 'profile')
        (run / 'profile').write_text('')
    with pytest.raises(r.VerificationError, match='^Recovery staging disposability unproven$'):
        r.prove_fresh_profile(plan, run, user_js, created_exclusive=exclusive)


def test_frozen_runtime_feature_addons_are_not_profile_input(fresh):
    r, plan, run, user_js = fresh
    features = run / 'runtime/Firefox.app/Contents/Resources/browser/features'
    features.mkdir(parents=True)
    (features / 'builtin@mozilla.org.xpi').write_bytes(b'application code')
    assert r.prove_fresh_profile(plan, run, user_js, created_exclusive=True)['xpi_only_capture'] is True
    (run / 'home/runtime').mkdir()
    (run / 'home/runtime/smuggled.xpi').write_bytes(b'x')
    with pytest.raises(r.VerificationError, match='^Recovery staging disposability unproven$'):
        r.prove_fresh_profile(plan, run, user_js, created_exclusive=True)


def test_target_freshness_uses_its_own_code(fresh):
    r, plan, run, user_js = fresh
    with pytest.raises(r.VerificationError, match='^Recovery profile freshness unproven$'):
        r.prove_fresh_profile(dict(plan, role='target'), run, user_js + b'x', created_exclusive=True)
    assert r.RECOVERY_CODES['Recovery staging disposability unproven'] == 'STAGING_DISPOSABILITY_UNPROVEN'


# --- per-state-root claim ----------------------------------------------------------------------------------

def test_second_owner_is_refused_and_the_claim_is_never_deleted(r, tmp_path, repo_root):
    root = tmp_path / 'state'
    root.mkdir(mode=0o700)
    claim = r.StateRootClaim.acquire(root, 'OPERATOR_AUTH_COMPLETED', '06-target-x')
    assert claim.verify()
    with pytest.raises(r.VerificationError, match='^Recovery state root claim exists$'):
        r.StateRootClaim.acquire(root, 'OPERATOR_AUTH_COMPLETED', 'other')
    code = ('import sys; sys.path.insert(0, sys.argv[1]); import cnt_firefox_recovery as r\n'
            'try:\n    r.StateRootClaim.acquire(sys.argv[2], "S", "other")\n'
            'except r.VerificationError as e:\n    print(str(e))\n')
    out = subprocess.run([sys.executable, '-c', code, str(repo_root / 'tests'), str(root)], capture_output=True,
                         text=True, timeout=120, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    assert out.stdout.strip() == 'Recovery state root claim exists'
    claim.release()
    assert (root / r.STATE_ROOT_CLAIM).exists()
    with pytest.raises(r.VerificationError, match='^Recovery state root claim exists$'):
        r.StateRootClaim.acquire(root, 'OPERATOR_AUTH_COMPLETED', 'again')


def test_held_flock_refuses_even_a_replacement_file(r, tmp_path):
    import fcntl
    root = tmp_path / 'state'
    root.mkdir(mode=0o700)
    claim = r.StateRootClaim.acquire(root, 'S', 'a')
    other = os.open(root / r.STATE_ROOT_CLAIM, os.O_RDONLY)
    with pytest.raises(OSError):
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.close(other)
    claim.release()


@pytest.mark.parametrize('loss', ['replaced', 'rewritten', 'removed', 'symlinked'])
def test_lost_claim_is_detected_before_any_library_call(r, tmp_path, loss):
    root = tmp_path / 'state'
    root.mkdir(mode=0o700)
    claim = r.StateRootClaim.acquire(root, 'S', 'a')
    path = root / r.STATE_ROOT_CLAIM
    if loss == 'replaced':
        path.unlink()
        path.write_bytes(claim.raw)
    elif loss == 'rewritten':
        os.pwrite(claim.descriptor, b'X', 0)
    elif loss == 'removed':
        path.unlink()
    else:
        path.unlink()
        path.symlink_to(tmp_path)
    with pytest.raises(r.VerificationError, match='^Recovery state root claim lost$'):
        claim.verify()


def test_state_root_symlink_claim_is_refused(r, tmp_path):
    root = tmp_path / 'state'
    root.mkdir(mode=0o700)
    (root / r.STATE_ROOT_CLAIM).symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(r.VerificationError, match='^Recovery state root claim exists$'):
        r.StateRootClaim.acquire(root, 'S', 'a')
    assert not (tmp_path / 'elsewhere').exists()


# --- caller-level single-use token ---------------------------------------------------------------------------

def test_caller_token_is_consumed_once_and_binds_the_exact_authorization(r, tmp_path):
    token = r.issue_token(tmp_path, 'OPERATOR_AUTH_COMPLETED', 's03-operator', GLOBAL, 'OPERATOR_AUTHORIZATION')
    consumed = r.consume_token(token, 'OPERATOR_AUTH_COMPLETED', GLOBAL, 'OPERATOR_AUTHORIZATION', 'e' * 64)
    assert consumed['bound_sha256'] == 'e' * 64 and r.token_consumed(token)
    assert json.loads(Path(token['path'] + r.CONSUMED_SUFFIX).read_text())['token_sha256'] == token['sha256']
    for bound in ('e' * 64, 'f' * 64):
        with pytest.raises(r.VerificationError, match='^Recovery caller token reused$'):
            r.consume_token(token, 'OPERATOR_AUTH_COMPLETED', GLOBAL, 'OPERATOR_AUTHORIZATION', bound)


@pytest.mark.parametrize('change', ['scenario', 'global-claim', 'kind', 'token-digest', 'unbound-operator',
                                    'bound-none', 'edited-file', 'symlinked-file'])
def test_caller_token_binding_differences_are_invalid(r, tmp_path, change):
    kind = 'NONE' if change == 'bound-none' else 'OPERATOR_AUTHORIZATION'
    token = r.issue_token(tmp_path, 'OPERATOR_AUTH_COMPLETED', 's03-operator', GLOBAL, kind)
    args = ['OPERATOR_AUTH_COMPLETED', GLOBAL, kind, None if kind == 'NONE' else 'e' * 64]
    if change == 'scenario':
        args[0] = 'NOOP_MATCH'
    elif change == 'global-claim':
        args[1] = 'f' * 64
    elif change == 'kind':
        args[2] = 'NONE'
    elif change == 'token-digest':
        token = dict(token, sha256='0' * 64)
    elif change == 'unbound-operator':
        args[3] = None
    elif change == 'bound-none':
        args[3] = 'e' * 64
    elif change == 'edited-file':
        Path(token['path']).write_text(Path(token['path']).read_text().replace('s03', 's04'))
    else:
        Path(token['path']).rename(tmp_path / 'real.token')
        Path(token['path']).symlink_to(tmp_path / 'real.token')
    with pytest.raises(r.VerificationError, match='^Recovery caller token invalid$'):
        r.consume_token(token, *args)
    assert not r.token_consumed(token)


def test_library_authorization_stays_a_reusable_state_transition_authorization(r):
    # Not globally single-use: the same record authorizes the same transition every time it is
    # planned. Single use for native qualification is the caller token's, around recover().
    target = r.gr.bind_target({'labels': labels(r), 'profile_token': 'a' * 64, 'storage_token': 'b' * 64})
    mint = lambda parts: r.gr.verify_export({'labels': labels(r), 'part_count': 1, 'parts': parts}, target)
    current, export = mint([theme(FIX, 'dark')]), mint([FIX])
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        requested = r.gr.capture_export(root, export)
        authorization = {'schema': r.gr.AUTHORIZATION_SCHEMA, 'labels': labels(r), 'profile_token': 'a' * 64,
                         'storage_token': 'b' * 64, 'requested_manifest_sha256': requested.manifest_sha256,
                         'requested_fingerprint': requested.fingerprint, 'before_fingerprint': current.fingerprint}
        plans = [r.gr.plan_recovery(target, current, requested, authorization=authorization) for _ in range(2)]
    assert [p.decision for p in plans] == ['MUTATE_OPERATOR', 'MUTATE_OPERATOR']
    assert r.TOKEN_SCHEMA == 'bux5b1-qual-caller-token-v1' != r.gr.AUTHORIZATION_SCHEMA


# --- end-to-end scenarios through the real library with a fake native driver ---------------------------------

class FakeDriver:
    """Test-only native stand-in: the 'profile' state is a list of native part bytes. Restores
    replace it with the exact bytes; the UI change edits one accepted pref; exports go through the
    real prove_export_closure and land in run/artifacts as the session writes them."""

    def __init__(self, r, run, inode, uuid, state, restore_ok=True):
        self.r, self.run, self.inode, self.uuid = r, Path(run), inode, uuid
        self.state, self.restore_ok, self.ops, self.exports, self.last_label = list(state), restore_ok, [], 0, None

    def labels(self):
        return dict(self.r.ds.PROJECTED_LABELS)

    def profile_identity(self):
        return (7, self.inode)

    def identity(self):
        return {'labels': self.labels(), 'profile_token': self.r.profile_token(NONCE, 7, self.inode),
                'storage_token': self.r.storage_token(NONCE, self.uuid)}

    def closed_export(self):
        self.exports += 1
        self.last_label = f'recovery-{self.exports}'
        folder = self.run / 'artifacts' / self.last_label
        folder.mkdir(parents=True)
        for n, raw in enumerate(self.state, 1):
            (folder / f'part-{n}.json').write_bytes(raw)
        return self.r.prove_export_closure(observation(self.state), self.labels())

    def native_restore(self, parts, op):
        self.ops.append(op)
        if self.restore_ok:
            self.state = list(parts)
        return self.restore_ok, {'completion': 'COMPLETED' if self.restore_ok else 'DEADLINE_NO_SIGNAL'}

    def set_ui_pref(self, value):
        self.ops.append('ui:' + value)
        self.state = [theme(self.state[0], value)] + self.state[1:]

    def seed_sentinel(self):
        self.ops.append('seed')
        self.state = [FIX]


class World:
    def __init__(self, r, tmp_path, monkeypatch):
        import cnt_confinement
        self.r = r
        scratch = tmp_path / 'scratch'
        scratch.mkdir()
        monkeypatch.setattr(cnt_confinement, 'SCRATCH', scratch)
        self.root = scratch / 'claim'
        for name in ('cases', 'tokens', 'staging', 'plans'):
            (self.root / name).mkdir(parents=True, mode=0o700)
        self.tokens = {j: r.issue_token(self.root / 'tokens', s, j, GLOBAL, r.TOKEN_KIND[j])
                       for s, journals in r.JOURNALS.items() for j in journals}
        self.empty = empty_export()

    def plan(self, role, scenario, name):
        (self.root / 'cases' / name).mkdir()
        return {'schema': self.r.PLAN_SCHEMA, 'role': role, 'scenario': scenario, 'plan_nonce': NONCE,
                'claim_root': str(self.root), 'attempt': str(self.root / 'cases' / name), 'attempt_name': name,
                'source_attempt': str(self.root / 'cases/01-source'), 'global_claim_sha256': GLOBAL,
                'tokens': [self.tokens[j] for j in self.r.JOURNALS[scenario]] if role == 'target' else [],
                '_inputs': {'requested': [FIX], 'reset': [self.empty]},
                '_freshness': {'proven': True, 'role': role}}

    def staging(self, scenario, **driver):
        plan = self.plan('staging', scenario, 's-' + scenario.lower().replace('_', '-'))
        drv = FakeDriver(self.r, plan['attempt'], 2, UUID_STAGING, [self.empty], **driver)
        record = {}
        self.r.run_staging(drv, plan, record)
        return record, drv

    def target(self, scenario, staged=True, **driver):
        if staged and scenario in self.r.STAGED_SCENARIOS:
            self.staged = self.staging(scenario)
        plan = self.plan('target', scenario, 't-' + scenario.lower().replace('_', '-'))
        drv = FakeDriver(self.r, plan['attempt'], 3, UUID_TARGET, [self.empty], **driver)
        record = {}
        self.r.run_target(drv, plan, record)
        return record, drv, plan


@pytest.fixture
def world(r, tmp_path, monkeypatch):
    return World(r, tmp_path, monkeypatch)


def calls(record, kind, journal_id):
    return [c for c in record['calls'] if c['call'] == kind and c['journal_id'] == journal_id]


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_every_scenario_reaches_its_declared_expectation(world, scenario):
    record, drv, _ = world.target(scenario)
    assert record['expectation'] == 'MATCHED', record['expectation_reasons']
    assert [i['kind'] for i in record['injections']] == list(world.r.FAULTS[scenario])
    assert all(i['label'] == 'QUALIFICATION_FAULT_INJECTION' for i in record['injections'])
    world.r.matrix.project(record)


def test_noop_match_makes_zero_native_mutation_and_no_journal(world):
    record, drv, plan = world.target('NOOP_MATCH')
    first = calls(record, 'recover', 's01-noop')[0]
    assert first['status'] == 'NOOP' and first['token'] == 'CONSUMED'
    assert {k: first['deltas'][k] for k in ('stage', 'apply', 'rollback', 'native_apply', 'native_rollback')} == \
        dict.fromkeys(('stage', 'apply', 'rollback', 'native_apply', 'native_rollback'), 0)
    assert record['journal_dirs'] == 0 and record['setup']['label'] == 'QUALIFICATION_TARGET_SETUP'
    assert drv.ops == ['setup']


def test_synthetic_reset_stores_the_synthetic_kind_and_applies_natively_once(world):
    record, drv, _ = world.target('SYNTHETIC_RESET_COMPLETED')
    assert record['final']['stored_evidence_kind'] == 'QUALIFICATION_SYNTHETIC_RESET'
    assert record['final']['basis'] == 'POSITIVE_VERSIONED_RESET_EVIDENCE'
    assert record['reset_fingerprint_relation'] == 'EQUAL' and drv.ops == ['apply']


def test_operator_token_reuse_refuses_before_recover(world):
    record, drv, _ = world.target('OPERATOR_AUTH_COMPLETED')
    first, again = calls(record, 'recover', 's03-operator')
    assert first['status'] == 'COMPLETED' and again['refusal'] == 'CALLER_TOKEN_REUSED'
    assert set(again['deltas'].values()) == {0} and drv.ops == ['setup', 'ui:dark', 'apply']


def test_concurrent_change_fails_before_any_apply(world):
    record, drv, _ = world.target('CONCURRENT_CHANGE')
    first = calls(record, 'recover', 's04-concurrent')[0]
    assert first['history'][-1] == ['FAILED_BEFORE_MUTATION', 'CONCURRENT_CHANGE']
    assert first['deltas']['apply'] == first['deltas']['native_apply'] == 0 and 'apply' not in drv.ops
    assert drv.ops == ['setup', 'ui:dark', 'ui:clover']


def test_post_apply_mismatch_rolls_back_natively_from_the_verified_preserved_parts(world):
    record, drv, _ = world.target('POST_APPLY_MISMATCH_ROLLBACK')
    assert record['final']['rollback_from_preserved'] is True
    assert drv.ops == ['setup', 'ui:dark', 'apply', 'ui:clover', 'rollback']
    assert drv.state == [theme(FIX, 'dark')]


def test_rollback_failure_keeps_the_preserved_state_independently_verifiable(world):
    record, drv, _ = world.target('ROLLBACK_FAILURE')
    first = calls(record, 'recover', 's06-rollback-fault')[0]
    assert first['history'][-1] == ['ROLLBACK_FAILED', 'ROLLBACK_APPLY_FAILED']
    assert first['deltas']['rollback'] == 1 and first['deltas']['native_rollback'] == 0
    assert record['final']['preserved_verifiable'] is True and 'rollback' not in drv.ops
    assert record['adapter_codes'][-1] == 'QUALIFICATION_ROLLBACK_FAULT'


def test_interrupted_rollback_resumes_without_reapplying(world):
    record, drv, _ = world.target('INTERRUPTED_ROLLBACK_RESUME')
    first, resumed = calls(record, 'recover', 's07-interrupted')[0], calls(record, 'resume', 's07-interrupted')[0]
    assert first['interrupted'] is True and first['persisted'] == 'ROLLBACK_REQUIRED'
    assert record['interrupted_at'] == 'ROLLBACK_REQUIRED'
    assert resumed['history'][-1] == ['ROLLED_BACK', None]
    assert all(resumed['deltas'][k] == 0 for k in ('stage', 'apply', 'rollback', 'native_apply', 'native_rollback'))
    assert drv.ops.count('apply') == 1 and drv.ops.count('rollback') == 1


@pytest.mark.parametrize('scenario', ['TARGET_IDENTITY_REFUSAL', 'REQUESTED_PART_REFUSAL'])
def test_identity_and_part_refusals_happen_before_any_export_or_mutation(world, scenario):
    record, drv, _ = world.target(scenario)
    for call in record['calls']:
        assert call['refusal'] in ('TARGET_IDENTITY_MISMATCH', 'NATIVE_PART_MISSING', 'NATIVE_PART_SIZE_MISMATCH',
                                   'NATIVE_PART_DIGEST_MISMATCH')
        assert call['deltas']['identity'] == 1 and call['journal_present'] is False
        assert all(call['deltas'][k] == 0 for k in ('export', 'stage', 'apply', 'rollback'))
    assert not [op for op in drv.ops if op != 'setup']


def test_idempotent_repeat_is_noop_and_resume_of_completed_makes_no_adapter_call(world):
    record, drv, _ = world.target('IDEMPOTENT_REPEAT')
    repeat, resumed = calls(record, 'recover', 's10-repeat')[0], calls(record, 'resume', 's10-first')[0]
    assert repeat['status'] == 'NOOP' and resumed['status'] == 'COMPLETED'
    assert set(resumed['deltas'].values()) == {0} and drv.ops.count('apply') == 1


def test_expectation_is_not_vacuous(world):
    # A restore that never changes state: the NOOP setup cannot reach the requested state, so the
    # recover() refuses for lack of authorization and the scenario is MISMATCHED.
    record, _, _ = world.target('NOOP_MATCH', restore_ok=True)
    assert record['expectation'] == 'MATCHED'
    with pytest.raises(world.r.VerificationError, match='^Recovery target setup not completed$'):
        world.target('OPERATOR_AUTH_COMPLETED', restore_ok=False)


def test_resume_requires_a_consumed_token_and_the_held_claim(world):
    r = world.r
    record, drv, plan = world.target('IDEMPOTENT_REPEAT')
    ctx = r.Target(drv, plan, {}, r.FirefoxRecoveryAdapter(drv))
    state_root = Path(plan['attempt'] + '-state')
    ctx.claims[str(state_root)] = r.StateRootClaim(state_root / r.STATE_ROOT_CLAIM, os.open(
        state_root / r.STATE_ROOT_CLAIM, os.O_RDONLY), b'not this owner')
    target = r.gr.bind_target(drv.identity())
    with pytest.raises(r.VerificationError, match='^Recovery state root claim lost$'):
        ctx.resume(state_root, 's10-first', target)
    other = world.plan('target', 'NOOP_MATCH', 'fresh-noop')
    ctx = r.Target(drv, other, {}, r.FirefoxRecoveryAdapter(drv))
    root = ctx.state_root()
    with pytest.raises(r.VerificationError, match='^Recovery resume without consumed token$'):
        ctx.resume(root, 's01-noop', target)


# --- staging replay ---------------------------------------------------------------------------------------------

def replay_world(world, scenario='OPERATOR_AUTH_COMPLETED'):
    world.staging(scenario)
    plan = world.plan('target', scenario, 'replay-target')
    drv = FakeDriver(world.r, plan['attempt'], 3, UUID_TARGET, [world.empty])
    return plan, drv


def test_staging_replay_returns_the_recorded_staged_export_once(world):
    plan, drv = replay_world(world)
    replay = world.r.StagingReplay(plan)
    staged = replay.replay([FIX], drv.identity(), drv.profile_identity())
    assert staged['export'] == {'labels': labels(world.r), 'part_count': 1, 'parts': [FIX]}
    assert staged['identity']['profile_token'] != drv.identity()['profile_token']
    with pytest.raises(world.r.VerificationError, match='^Recovery staging record reused$'):
        replay.replay([FIX], drv.identity(), drv.profile_identity())
    with pytest.raises(world.r.VerificationError, match='^Recovery staging record reused$'):
        world.r.StagingReplay(plan).replay([FIX], drv.identity(), drv.profile_identity())


@pytest.mark.parametrize('damage,code', [
    ('other-scenario', 'Recovery staging record invalid'), ('other-nonce', 'Recovery staging record invalid'),
    ('other-claim-root', 'Recovery staging record invalid'),
    ('not-disposable', 'Recovery staging disposability unproven'),
    ('requested-differs', 'Recovery staged input mismatch'), ('staged-bytes-tampered', 'Recovery staging record invalid'),
    ('same-tokens', 'Recovery staging disposability unproven'),
    ('same-profile', 'Recovery staging disposability unproven'),
    ('same-attempt', 'Recovery staging disposability unproven')])
def test_staging_replay_refusals(world, damage, code):
    r = world.r
    plan, drv = replay_world(world)
    path = r.staging_path(plan['claim_root'], plan['scenario'])
    record = json.loads(path.read_text())
    parts, identity, profile = [FIX], drv.identity(), drv.profile_identity()
    if damage == 'other-scenario':
        record['scenario'] = 'CONCURRENT_CHANGE'
    elif damage == 'other-nonce':
        plan = dict(plan, plan_nonce='e' * 64)
    elif damage == 'other-claim-root':
        record['claim_root_name'] = 'other'
    elif damage == 'not-disposable':
        record['disposability'] = {'proven': False, 'role': 'staging'}
    elif damage == 'requested-differs':
        parts = [theme(FIX, 'dark')]
    elif damage == 'staged-bytes-tampered':
        staged = Path(plan['claim_root']) / 'cases' / record['attempt_name'] / 'artifacts' / record['staged_label']
        (staged / 'part-1.json').write_bytes(theme(FIX, 'ruby'))
    elif damage == 'same-tokens':
        identity = dict(identity, profile_token=record['identity']['profile_token'])
    elif damage == 'same-profile':
        profile = tuple(record['profile_identity'])
    else:
        plan = dict(plan, attempt_name=record['attempt_name'])
    path.write_text(json.dumps(record))
    with pytest.raises(r.VerificationError, match='^' + code + '$'):
        r.StagingReplay(plan).replay(parts, identity, profile)


def test_staging_failure_inside_recover_is_staging_mismatch_before_mutation(world):
    r = world.r
    plan = world.plan('target', 'OPERATOR_AUTH_COMPLETED', 'no-staging-target')
    drv = FakeDriver(r, plan['attempt'], 3, UUID_TARGET, [world.empty])
    record = {}
    r.run_target(drv, plan, record)
    first = calls(record, 'recover', 's03-operator')[0]
    assert first['history'][-1] == ['FAILED_BEFORE_MUTATION', 'STAGING_MISMATCH']
    assert first['deltas']['apply'] == 0 and record['expectation'] == 'MISMATCHED'
    assert 'STAGING_RECORD_REUSED' in record['adapter_codes'] or 'STAGING_RECORD_INVALID' in record['adapter_codes']


# --- roster, plans, projection and static boundaries -------------------------------------------------------------

def test_exact_scenario_roster_and_journals(r):
    assert r.SCENARIOS == SCENARIOS and r.ROSTER == SCENARIOS + ('ZERO_LIVE_CONTACT',)
    assert set(r.JOURNALS) == set(SCENARIOS) == set(r.SETUP) == set(r.FAULTS)
    assert sorted(j for js in r.JOURNALS.values() for j in js) == sorted(r.TOKEN_KIND)
    assert set(r.STAGED_SCENARIOS) == set(SCENARIOS) - {'NOOP_MATCH', 'TARGET_IDENTITY_REFUSAL',
                                                        'REQUESTED_PART_REFUSAL'}
    assert set(r.FAULT_KINDS) == {k for v in r.FAULTS.values() for k in v}
    assert r.QUAL_UI_VALUES == {'requested_default': 'lavender', 'setup': 'dark', 'injection': 'clover'}


def test_fault_injection_seams_are_adapter_or_caller_only(r):
    tree = ast.parse(Path(r.__file__).read_text())
    seams = {n.args[1].value for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, 'attr', None) == 'inject' and len(n.args) == 2 and isinstance(n.args[1], ast.Constant)}
    assert seams == {'ADAPTER_IDENTITY', 'ADAPTER_AFTER_APPLY', 'ADAPTER_BEFORE_ROLLBACK', 'ADAPTER_AFTER_ROLLBACK',
                     'CALLER_TARGET_BINDING', 'CALLER_STATE_ROOT'}


def test_plan_is_digest_bound_and_shape_checked_before_any_root(world, tmp_path):
    r = world.r
    plan = {k: v for k, v in world.plan('source', None, '01-source').items() if not k.startswith('_')}
    plan.update(scenario=None, source_attempt=None, tokens=[])
    path = world.root / 'plans/01-source.json'
    raw = json.dumps(plan).encode()
    path.write_bytes(raw)
    loaded = r.load_plan(path, sha(raw), Path(plan['attempt']))
    assert loaded['role'] == 'source'
    for bad in (dict(plan, role='live'), dict(plan, attempt_name='../x'), dict(plan, extra=1),
                dict(plan, claim_root=str(tmp_path))):
        raw = json.dumps(bad).encode()
        path.write_bytes(raw)
        with pytest.raises(r.VerificationError, match='^Recovery plan invalid$'):
            r.load_plan(path, sha(raw), Path(plan['attempt']))
    with pytest.raises(r.VerificationError, match='^Recovery plan invalid$'):
        r.load_plan(path, '0' * 64, Path(plan['attempt']))


def test_source_inputs_are_bound_to_the_source_result(world):
    r = world.r
    source = world.root / 'cases/01-source'
    drv = FakeDriver(r, source, 1, UUID_TARGET, [world.empty])
    source.mkdir()
    record = {}
    r.run_source(drv, {'plan_nonce': NONCE}, record)
    record.update(role='source', completed=True)
    (source / 'result.json').write_text(json.dumps({'status': 'RECOVERY_ATTEMPT_COMPLETED', 'recovery': record}))
    inputs = r.source_inputs(source)
    assert inputs == {'reset': [world.empty], 'requested': [FIX]} and drv.ops == ['seed']
    (source / f'artifacts/{record["exports"]["requested"]["label"]}/part-1.json').write_bytes(theme(FIX, 'dark'))
    with pytest.raises(r.VerificationError, match='^Recovery source invalid$'):
        r.source_inputs(source)


def test_projection_keeps_only_fixed_safe_facts(world, tmp_path):
    r = world.r
    record, _, _ = world.target('POST_APPLY_MISMATCH_ROLLBACK')
    result = {'status': 'RECOVERY_ATTEMPT_COMPLETED', 'recovery_role': 'target', 'recovery': record,
              'settlement': {'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'workload_status': 'exited',
                             'observed_escapes': 0, 'survivors': [4242]},
              'primary_failure': {'stage': 'browser', 'type': 'X', 'code': 'Y', 'classification': str(tmp_path)},
              'preflight': {'policy_template_sha256': 'a' * 64, 'policy_sha256': 'b' * 64}}
    projected = r.projected_attempt(result)
    text = json.dumps(projected)
    assert projected['recovery']['expectation'] == 'MATCHED' and '4242' not in text and str(tmp_path) not in text
    assert projected['primary_failure'] == {'stage': 'browser', 'type': 'X', 'code': 'Y'}
    leaky = dict(result, recovery=dict(record, note=str(tmp_path)))
    assert r.projected_attempt(leaky)['recovery'] == {'projection': 'REFUSED'}
    assert r.projected_attempt(dict(result, recovery={'pid': 1}))['recovery'] == {'projection': 'REFUSED'}


LIVE = ('Library/Application Support/Firefox', 'profiles.ini', 'extensions.json', 'storage/default',
        'moz-extension+++', 'Profiles/', 'prefs.js"', 'cookies.sqlite', 'places.sqlite', 'storage.sqlite')


@pytest.mark.parametrize('name', ['cnt_firefox_recovery.py', 'cnt_host_firefox_recovery.py'])
def test_no_live_default_profile_or_direct_storage_route(name):
    text = (HERE / name).read_text()
    assert not [s for s in LIVE if s in text]
    tree = ast.parse(text)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {
        n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {'cnt_synthetic_chrome', 'cnt_protocol', 'cnt_chrome_rendezvous', 'cnt_chrome_peer',
                           'cnt_host_chrome', 'cnt_owned_process', 'cnt_supervisor', 'sqlite3'}
    assert "'chrome'" not in text.replace("{'value': 'chrome'}", '')
    assert 'canonical_root(' not in text


def test_recovery_codes_are_fixed_and_allowlisted(r):
    assert all(re.fullmatch('[A-Z][A-Z0-9_]{2,63}', c) for c in r.RECOVERY_CODES.values())
    assert r.code_of(r.VerificationError('Recovery caller token reused')) == 'CALLER_TOKEN_REUSED'
    assert r.code_of(r.VerificationError('/Users/x leaked')) == 'UNCLASSIFIED'
    assert r.code_of(RuntimeError('x')) == 'UNCLASSIFIED'


# --- in-session driver against the accepted R6 fake Marionette peer -------------------------------------------

@pytest.fixture
def sess(r, load_module, monkeypatch, tmp_path):
    fakes = load_module('tests/cnt-firefox-matrix-session.test.py')
    import cnt_firefox_matrix as m, cnt_firefox_matrix_session as session
    monkeypatch.setattr(session, 'SETTLE', 0.0)
    monkeypatch.setattr(session, 'QUIET', 0.3)
    monkeypatch.setattr(session, 'DEADLINES', {k: 0.6 for k in session.DEADLINES})
    run = tmp_path / 'attempt'
    (run / 'capture').mkdir(parents=True)

    class Peer(fakes.Fake):
        def __init__(self, run, clock):
            super().__init__(run, clock)
            self.active, self.uuid, self.late_on_click = [r.EXTENSION_ID], UUID_TARGET, []

        def WebDriver_ElementClick(self, params):
            out = super().WebDriver_ElementClick(params)
            if params['id'].startswith('.btn_w.download_back_up') and self.late_on_click:
                self.late, self.late_on_click = self.late_on_click, []
            return out

        def WebDriver_ExecuteScript(self, params):
            source = params['script']
            if 'getActiveExtensions' in source:
                return {'value': list(self.active)}
            if 'mozExtensionHostname' in source:
                return {'value': self.uuid}
            return super().WebDriver_ExecuteScript(params)

    def make(plan=None, browser='156.0.1'):
        clock = fakes.Clock()
        peer = Peer(run, clock)
        result = {'browser_version': browser,
                  'capture_copy': {'xpi_sha256': r.CAPTURE_SHA256, 'extension_id': r.EXTENSION_ID, 'version': '6.12.1'}}
        drv = r.RecoverySession(peer, run, result, m.load_provenance(),
                                plan or {'plan_nonce': NONCE, 'role': 'target', 'scenario': 'NOOP_MATCH'}, clock)
        drv.step('open_settings', lambda: session.open_settings(drv))
        return drv, peer, result
    return make, fakes, run


def test_session_export_is_attributed_closed_and_read_back(sess, r):
    make, fakes, run = sess
    drv, peer, result = make()
    peer.exports, peer.backgrounds = [[fakes.EXPORT]], 4
    proof = drv.closed_export()
    assert proof.part_count == 1 and proof.parts == (fakes.EXPORT,)
    assert (run / 'artifacts/recovery-1/part-1.json').read_bytes() == fakes.EXPORT
    assert result['recovery_session']['exports'][-1]['proven'] is True and 'matrix' not in result
    assert peer.calls.count('WebDriver:ElementClick') == 1


def test_session_multipart_and_late_parts_close_only_when_complete(sess, r, monkeypatch):
    import cnt_firefox_matrix_session as session
    # Each late part costs real 50 ms polls (cnt_synthetic_firefox.poll enforces the deadline in
    # wall time), so the fixture's 0.6 s leaves no margin on a slower builder. The set still closes
    # on its own stable end, never on the deadline.
    monkeypatch.setattr(session, 'DEADLINES', {k: 5.0 for k in session.DEADLINES})
    make, fakes, run = sess
    drv, peer, _ = make()
    parts = split(minimum=3)
    peer.exports, peer.backgrounds = [parts[:1]], 8
    peer.late_on_click, peer.late_after = list(parts[1:]), 3
    proof = drv.closed_export()
    assert proof.part_count == len(parts) and proof.facts['partition_status'] == 'CONSISTENT'


def test_session_straggler_before_the_click_is_never_attributed(sess, r):
    make, fakes, run = sess
    drv, peer, result = make()
    peer.exports, peer.backgrounds = [[fakes.EXPORT]], 4
    peer.late, peer.late_after = [fakes.EXPORT], 1  # arrives after clear(), before any click
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        drv.closed_export()
    assert result['recovery_session']['exports'][-1] == {'label': 'recovery-1', 'proven': False,
                                                         'baseline_quiescent': False}
    assert 'WebDriver:ElementClick' not in peer.calls


@pytest.mark.parametrize('case', ['inconsistent-split', 'rows-short', 'no-export', 'unparseable'])
def test_session_export_refusals(sess, r, case):
    make, fakes, run = sess
    drv, peer, result = make()
    if case == 'inconsistent-split':
        peer.exports, peer.backgrounds = [fakes.split_export()], 4
    elif case == 'rows-short':
        peer.exports, peer.backgrounds = [[fakes.EXPORT]], 5
    elif case == 'no-export':
        peer.exports, peer.backgrounds = [[]], 0
    else:
        peer.exports, peer.backgrounds = [[fakes.EXPORT[:-9]]], 4
    with pytest.raises(r.VerificationError, match='^Recovery export incomplete$'):
        drv.closed_export()
    assert result['recovery_session']['exports'][-1]['proven'] is False


def test_session_native_restore_writes_fresh_inputs_and_requires_completion(sess, r):
    make, fakes, run = sess
    drv, peer, result = make()
    ok, outcome = drv.native_restore([fakes.EXPORT], 'apply')
    path = run / 'inputs/apply-1/bux-matrix Part 1.json'
    assert ok is True and path.read_bytes() == fakes.EXPORT and oct(path.stat().st_mode & 0o777) == '0o600'
    assert outcome['completion'] == 'COMPLETED' and 'WebDriver:Refresh' in peer.calls
    peer.restore_behaviour = 'error'
    ok, outcome = drv.native_restore([fakes.EXPORT], 'rollback')
    assert ok is False and outcome['restore_error'] is True
    peer.restore_behaviour = 'dropped'
    with pytest.raises(r.VerificationError, match='^Matrix step deadline$'):
        drv.native_restore([fakes.EXPORT], 'apply')


def test_session_native_restore_refuses_a_preexisting_error_ribbon(sess, r):
    make, fakes, run = sess
    drv, peer, _ = make()
    peer.error_visible = True
    with pytest.raises(r.VerificationError, match='^Recovery pre-existing error ribbon$'):
        drv.native_restore([fakes.EXPORT], 'apply')
    assert not [t for t in peer.typed if t[0].startswith('input.file.back_up')]


@pytest.mark.parametrize('active,ok', [(['clear-new-tab@loftyshaky'], True),
                                       (['clear-new-tab@loftyshaky', 'other@example.org'], False), ([], False)])
def test_session_extension_set_must_be_cnt_only(sess, r, active, ok):
    make, fakes, run = sess
    drv, peer, _ = make()
    peer.active = active
    if ok:
        assert drv.prove_extension_set() == {'extension_set_proven': True}
    else:
        with pytest.raises(r.VerificationError, match='^Recovery extension set unproven$'):
            drv.prove_extension_set()


def test_session_identity_is_rederived_from_profile_and_storage(sess, r):
    make, fakes, run = sess
    drv, peer, _ = make()
    (run / 'profile').mkdir()
    first = drv.identity()
    assert first == drv.identity() and first['labels'] == labels(r)
    info = os.stat(run / 'profile')
    assert first['profile_token'] == r.profile_token(NONCE, info.st_dev, info.st_ino)
    peer.uuid = 'not-a-uuid'
    with pytest.raises(r.VerificationError, match='^Recovery storage identity unavailable$'):
        drv.identity()
    drv, peer, _ = make(browser='155.0.1')
    with pytest.raises(r.VerificationError, match='^Recovery target labels unproven$'):
        drv.identity()


def test_source_role_runs_end_to_end_in_the_fake_session(sess, r, monkeypatch):
    make, fakes, run = sess
    (run / 'profile').mkdir()
    clock = fakes.Clock()
    result = {'browser_version': '156.0.1',
              'capture_copy': {'xpi_sha256': r.CAPTURE_SHA256, 'extension_id': r.EXTENSION_ID, 'version': '6.12.1'}}
    drv, peer, _ = make()
    peer.exports = ['MODEL', 'MODEL']
    plan = {'plan_nonce': NONCE, 'role': 'source', 'scenario': None}
    driver = r.exercise(peer, run, result, plan, clock=clock)
    record = result['recovery']
    assert result['recovery_completed'] is True and record['completed'] is True
    assert record['exports']['reset']['rows'] == 0 and record['exports']['requested']['rows'] == 2
    assert record['exports']['reset']['partition_status'] == 'EMPTY_SINGLE_PART'
    assert re.fullmatch('[0-9a-f]{64}', record['requested_manifest_sha256'])
    assert [s['step'] for s in result['recovery_session']['steps']] == ['open_settings', 'extension_set', 'role']
    r.matrix.project(record)
    assert isinstance(driver, r.RecoverySession)


def test_an_escaped_qualification_interrupt_is_a_classified_role_failure(r, monkeypatch):
    class Driver:
        def __init__(self):
            self.record, self.steps = {'steps': []}, []
        def step(self, name, action):
            return action()
        def prove_extension_set(self):
            return {}
    def interrupted(driver, plan, record):
        raise r.QualificationInterrupt()
    monkeypatch.setitem(r.ROLE_DRIVERS, 'target', interrupted)
    monkeypatch.setattr(r, 'RecoverySession', lambda *a, **k: Driver())
    monkeypatch.setattr(r.session_module, 'open_settings', lambda driver: None)
    result = {}
    with pytest.raises(r.VerificationError, match='^Recovery scenario refused$'):
        r.exercise(None, None, result, {'role': 'target', 'scenario': 'NOOP_MATCH'}, provenance={})
    assert 'recovery_completed' not in result and result['recovery']['completed'] is False


@pytest.mark.parametrize('scenario', ['CONCURRENT_CHANGE', 'POST_APPLY_MISMATCH_ROLLBACK'])
def test_a_failed_injection_is_never_a_matched_change(world, monkeypatch, scenario):
    # The injected UI change itself fails: the library still sees "not before"/"not requested", but
    # from a failed observation, so the scenario must read MISMATCHED, not MATCHED.
    original = FakeDriver.set_ui_pref
    def failing(self, value):
        if value == 'clover':
            raise world.r.VerificationError('Matrix UI value not applied')
        return original(self, value)
    monkeypatch.setattr(FakeDriver, 'set_ui_pref', failing)
    record, _, _ = world.target(scenario)
    assert record['expectation'] == 'MISMATCHED'
    assert not record['injections']
