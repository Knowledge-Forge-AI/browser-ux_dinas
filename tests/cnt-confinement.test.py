"""Offline contracts only; OS canary results remain separate native evidence."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture
def boundary(load_module, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent))
    return load_module('tests/cnt_confinement.py')


def test_environment_does_not_inherit_credentials(boundary, monkeypatch, tmp_path):
    monkeypatch.setenv('SYNTHETIC_AGENT_TOKEN', 'synthetic')
    monkeypatch.setenv('HTTP_PROXY', 'synthetic')
    result = boundary.environment(tmp_path)
    assert set(result) == {'HOME', 'CFFIXED_USER_HOME', 'TMPDIR', 'TMP', 'TEMP',
                           'LANG', 'PATH', 'PYTHONDONTWRITEBYTECODE'}
    assert not any('MOZ_DISABLE' in k for k in result)


def test_policy_denies_services_network_and_runtime_writes(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    run = tmp_path / 'attempt'
    run.mkdir()
    (run / 'runtime').mkdir()
    text = boundary.policy(run, [run / 'runtime'])
    assert '(deny default)' in text and '(allow default)' not in text
    assert '(deny network*)' in text
    assert '(allow mach-lookup' not in text
    for service in boundary.CREDENTIAL_SERVICES:
        assert '(global-name ' + json.dumps(service) + ')' in text
    assert '(deny file-write* (subpath ' + json.dumps(str(run / 'runtime')) + '))' in text


def test_fresh_attempt_refuses_reuse_and_symlink_parent(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    boundary.fresh_attempt(tmp_path / 'one')
    with pytest.raises(FileExistsError):
        boundary.fresh_attempt(tmp_path / 'one')
    (tmp_path / 'alias').symlink_to(tmp_path / 'one', target_is_directory=True)
    with pytest.raises(Exception, match='Symlink'):
        boundary.fresh_attempt(tmp_path / 'alias/two')


@pytest.mark.parametrize('name', ['cnt-native-static-probe.py', 'cnt-native-firefox-ui.py'])
@pytest.mark.parametrize('optimized', [False, True])
def test_unqualified_old_entrypoints_refuse(name, optimized):
    result = subprocess.run([sys.executable, '-B', *(['-O'] if optimized else []),
                             str(Path(__file__).with_name(name))], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'BLOCKED' in result.stderr and 'confinement' in result.stderr


def test_native_prefix_has_no_executable_body():
    source = Path(__file__).with_name('cnt-native-import-prefix.mjs').read_text()
    assert 'throw new Error' in source
    assert 'readFile' not in source and 'vm.' not in source


def test_chrome_explicit_flags_keep_sandbox_and_pipe(load_module, monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).parent))
    module = load_module('tests/cnt-native-preflight.py')
    argv = module.arguments('chrome', Path('/synthetic/chrome'), tmp_path)
    assert '--remote-debugging-pipe' in argv
    assert '--enable-unsafe-extension-debugging' in argv
    assert '--no-sandbox' not in argv and '--disable-extensions' not in argv
    assert not any(a.startswith('--remote-debugging-port') for a in argv)


@pytest.mark.parametrize('port', [0, -1, 65536, True, '12345', None])
def test_invalid_automation_port(boundary, port):
    with pytest.raises(Exception): boundary.valid_port(port)


def test_single_port_policy(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    (tmp_path / 'runtime').mkdir()
    text = boundary.policy(tmp_path, [tmp_path / 'runtime'], automation_port=12345)
    assert 'localhost:12345' in text and 'localhost:*' not in text
    assert 'global-name-regex' not in text
    assert '(allow network-outbound' not in text


def test_port_reservation_collision(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    module = load_module('tests/cnt-native-preflight.py')
    with module.reserve_port() as first:
        with pytest.raises(OSError): module.reserve_port(first.getsockname()[1])


def test_component_exceptions_explicit_only(load_module, monkeypatch, repo_root, tmp_path):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    module = load_module('tests/cnt-native-preflight.py')
    monkeypatch.setenv('MOZ_DISABLE_GPU_SANDBOX', '1')
    assert not any(k.startswith('MOZ_DISABLE') for k in module.browser_environment(tmp_path, 'firefox'))
    result = module.browser_environment(tmp_path, 'firefox', ['content'])
    assert {k for k in result if k.startswith('MOZ_DISABLE')} == {'MOZ_DISABLE_CONTENT_SANDBOX'}
    with pytest.raises(Exception): module.browser_environment(tmp_path, 'firefox', ['gpu'])
    with pytest.raises(Exception): module.browser_environment(tmp_path, 'chrome', ['content'])


@pytest.mark.parametrize('error,expected', [(None, 'ALLOWED'), (1, 'DENIED'), (13, 'DENIED'),
                                          (48, 'COLLISION'), (98, 'COLLISION'), (22, 'ERROR_22')])
def test_canary_classification(boundary, error, expected):
    import ast
    import errno
    import inspect
    tree = ast.parse(inspect.getsource(boundary.run_probe))
    script = next(n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'script' for t in n.targets))
    functions = '\n'.join(ast.get_source_segment(script, n) for n in ast.parse(script).body
                          if isinstance(n, ast.FunctionDef) and n.name in ('outcome', 'refused'))
    namespace = {'errno': errno}
    exec(functions, namespace)
    actual_error = errno.EADDRINUSE if error in (48, 98) else error
    def operation():
        if actual_error is not None: raise OSError(actual_error, 'synthetic')
    assert namespace['outcome'](operation) == expected
    assert namespace['refused'](operation) is (expected == 'DENIED')


@pytest.mark.parametrize('caller', ['chrome', 'old-layout', 'firefox'])
def test_firefox_ipc_explicit_bundle_only(boundary, tmp_path, monkeypatch, caller):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    bundle = tmp_path / 'runtime/Firefox.app'
    bundle.mkdir(parents=True)
    executable = bundle / 'Contents/MacOS/firefox'
    if caller == 'chrome': executable = tmp_path / 'chrome'
    if caller == 'old-layout': executable = tmp_path / 'runtime/Contents/MacOS/firefox'
    if caller != 'firefox':
        with pytest.raises(Exception):
            boundary.policy(tmp_path, [bundle], firefox_child_ipc=True, firefox_executable=executable)
        return
    text = boundary.policy(tmp_path, [bundle], firefox_child_ipc=True, firefox_executable=executable)
    assert '(global-name-regex #"^org[.]mozilla[.]machname[.][0-9]+$")' in text
    assert '(deny file-write* (subpath ' + json.dumps(str(tmp_path / 'runtime')) + '))' in text
    evidence = boundary.policy_evidence(text, tmp_path, None, True)
    assert evidence['firefox_child_ipc'] is True
    assert evidence['mach_canary'] == 'NOT_EXERCISED'


def test_policy_template_stable_across_attempt_roots_and_ports(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    records = []
    for name, port in [('one', 12345), ('two', 12346)]:
        run = tmp_path / name
        bundle = run / 'runtime/Firefox.app'
        bundle.mkdir(parents=True)
        text = boundary.policy(run, [bundle], automation_port=port, firefox_child_ipc=True,
                               firefox_executable=bundle / 'Contents/MacOS/firefox')
        records.append(boundary.policy_evidence(text, run, port, True))
    assert records[0]['policy_sha256'] != records[1]['policy_sha256']
    assert records[0]['policy_template_sha256'] == records[1]['policy_template_sha256']


def test_crash_data_directory_is_fresh_private(load_module, monkeypatch, tmp_path, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    m = load_module('tests/cnt_confinement.py')
    monkeypatch.setattr(m, 'SCRATCH', tmp_path)
    run = m.fresh_attempt(tmp_path / 'attempt')
    assert (run / 'crash-data').is_dir()
    assert (run / 'crash-data').stat().st_mode & 0o777 == 0o700
    assert not (run / 'crash-data').is_symlink()
    assert (run / 'crash-data').stat().st_ino != (run / 'tmp').stat().st_ino


# R4-CONT7: one explicit, default-off, Firefox-lane-only configd lookup.
WINDOW_SERVER, LAUNCH_SERVICES = 'com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd'
CONFIGD_LINE = '(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))\n'
# Pre-edit (CONT6 terminal) template for the fixed D1-shaped synthetic configuration below.
DEFAULT_TEMPLATE = 'fab8c31ce797f36a63fc7ae1e4f08f406e363add0a6a7dbc8844cc0f024e048a'


def firefox_lane(boundary, run, services=(WINDOW_SERVER, LAUNCH_SERVICES), port=12345, ipc=True):
    bundle = run / 'runtime/Firefox.app'
    bundle.mkdir(parents=True, exist_ok=True)
    return boundary.policy(run, [bundle], services, port, firefox_child_ipc=ipc,
                           firefox_executable=bundle / 'Contents/MacOS/firefox')


def test_absent_configd_preserves_pre_edit_policy_bytes(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    text = firefox_lane(boundary, tmp_path)
    assert boundary.policy_evidence(text, tmp_path, 12345, True)['policy_template_sha256'] == DEFAULT_TEMPLATE
    assert 'SystemConfiguration' not in text
    evidence = boundary.policy_evidence(text, tmp_path, 12345, True, (WINDOW_SERVER, LAUNCH_SERVICES))
    assert evidence['policy_template_sha256'] == DEFAULT_TEMPLATE
    assert evidence['policy_template_without_configd_sha256'] == DEFAULT_TEMPLATE
    assert evidence['configd_compatibility'] is False and evidence['configd_lookup'] == 'NOT_SELECTED'


@pytest.mark.parametrize('base', [(), (WINDOW_SERVER,), (WINDOW_SERVER, LAUNCH_SERVICES)])
@pytest.mark.parametrize('port', [None, 12345])
@pytest.mark.parametrize('position', ['first', 'last'])
def test_configd_adds_exactly_one_rule_and_no_other_bytes(boundary, tmp_path, monkeypatch, base, port, position):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    without = firefox_lane(boundary, tmp_path, base, port)
    selected = (boundary.CONFIGD, *base) if position == 'first' else (*base, boundary.CONFIGD)
    text = firefox_lane(boundary, tmp_path, selected, port)
    assert boundary.CONFIGD_RULE == CONFIGD_LINE
    assert text.count(CONFIGD_LINE) == 1 and text.count('SystemConfiguration') == 1
    assert text.replace(CONFIGD_LINE, '', 1) == without
    assert len(text.splitlines()) == len(without.splitlines()) + 1
    assert text.index(CONFIGD_LINE) < text.index('global-name-regex')


@pytest.mark.parametrize('name', ['com.apple.SystemConfiguration.configd ', 'com.apple.systemconfiguration.configd',
                                  'com.apple.SystemConfiguration.PPPController', 'com.apple.SystemConfiguration.*',
                                  'com.apple.SystemConfiguration[.]configd', 'com.apple.SystemConfiguration',
                                  'com.apple.securityd', b'com.apple.SystemConfiguration.configd'])
def test_wrong_service_names_refuse(boundary, tmp_path, monkeypatch, name):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    with pytest.raises(RuntimeError, match='Unreviewed service'):
        firefox_lane(boundary, tmp_path, (WINDOW_SERVER, name))


def test_duplicate_configd_refuses(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    with pytest.raises(RuntimeError, match='Duplicate configd'):
        firefox_lane(boundary, tmp_path, (boundary.CONFIGD, WINDOW_SERVER, boundary.CONFIGD))


@pytest.mark.parametrize('caller', ['no-child-ipc', 'chrome', 'old-layout', 'truthy-ipc'])
def test_configd_refuses_outside_frozen_firefox_lane(boundary, tmp_path, monkeypatch, caller):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    bundle = tmp_path / 'runtime/Firefox.app'
    bundle.mkdir(parents=True)
    executable = {'chrome': tmp_path / 'chrome',
                  'old-layout': tmp_path / 'runtime/Contents/MacOS/firefox'}.get(
                      caller, bundle / 'Contents/MacOS/firefox')
    ipc = {'no-child-ipc': False, 'truthy-ipc': 1}.get(caller, True)
    roots = [tmp_path / 'runtime'] if caller == 'chrome' else [bundle]
    with pytest.raises(RuntimeError, match='configd|Firefox child IPC'):
        boundary.policy(tmp_path, roots, (boundary.CONFIGD,), 12345, firefox_child_ipc=ipc,
                        firefox_executable=executable)


def test_configd_keeps_existing_denials(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    text = firefox_lane(boundary, tmp_path, (WINDOW_SERVER, LAUNCH_SERVICES, boundary.CONFIGD))
    assert '(deny default)' in text and '(allow default)' not in text
    assert '(deny network*)' in text
    assert '(deny mach-lookup ' + ' '.join('(global-name ' + json.dumps(s) + ')'
                                          for s in boundary.CREDENTIAL_SERVICES) + ')' in text
    assert '(deny file-write* (subpath ' + json.dumps(str(tmp_path / 'runtime')) + '))' in text
    assert text.count('mach-register') == 1 and text.count('global-name-regex') == 1
    assert text.count('network-outbound') == 1 and '(allow network-outbound' not in text
    assert text.count('(allow mach-lookup (global-name ') == 3


def test_configd_evidence_records_choice_residual_and_new_template(boundary, tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    records = []
    for name, port in [('one', 12345), ('two', 12346)]:
        run = tmp_path / name
        services = (WINDOW_SERVER, LAUNCH_SERVICES, boundary.CONFIGD)
        text = firefox_lane(boundary, run, services, port)
        records.append(boundary.policy_evidence(text, run, port, True, services))
    first, second = records
    assert first['policy_template_sha256'] == second['policy_template_sha256'] != DEFAULT_TEMPLATE
    assert first['policy_template_without_configd_sha256'] == DEFAULT_TEMPLATE
    assert first['mach_services'] == [WINDOW_SERVER, LAUNCH_SERVICES, boundary.CONFIGD]
    assert first['configd_compatibility'] is True
    assert first['configd_lookup'] == 'POLICY_ALLOWED_NOT_EXERCISED'
    assert 'not read-only message filtering' in first['configd_residual']
    assert first['mach_canary'] == 'NOT_EXERCISED'
