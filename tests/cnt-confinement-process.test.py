"""Host-only owned trees. Caller MUST supply a fresh managed --basetemp."""
import os
from pathlib import Path
import sys
import pytest

@pytest.fixture
def module(load_module, monkeypatch, repo_root, request):
    base = request.config.getoption('basetemp')
    if not base or not Path(base).is_relative_to('/Users/Shared/agent-scratch/r'):
        pytest.fail('A new run-owned managed --basetemp is required')
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt_owned_process.py')

@pytest.mark.parametrize('kind', ['exit', 'parent-exit', 'timeout', 'exception', 'interrupt'])
def test_owned_lifetimes(module, tmp_path, kind):
    child = 'import time;time.sleep(30)'
    script = ('import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",' + repr(child) + ']);'
              + ('raise SystemExit(7)' if kind == 'parent-exit' else 'time.sleep(30)'))
    if kind == 'exit':
        script = 'raise SystemExit(7)'
    with (tmp_path / 'log').open('w') as log:
        owner = module.OwnedProcess([sys.executable, '-B', '-c', script], tmp_path,
                                   {'PATH': '/usr/bin:/bin'}, log)
        try:
            if kind in ('exit', 'parent-exit'):
                owner.until(lambda: owner.returncode is not None, 3)
            elif kind == 'exception':
                raise ValueError('intentional')
            elif kind == 'interrupt':
                raise KeyboardInterrupt
            else:
                with pytest.raises(Exception, match='timeout'):
                    owner.until(lambda: False, .2)
        except (ValueError, KeyboardInterrupt):
            pass
        finally:
            result = owner.settle()
        assert result['zero_survivors'] and not result['unsettled']
        assert owner.settle() is result
        if kind in ('exit', 'parent-exit'):
            assert result['exit_code'] == 7


def test_lost_observation_uses_channel_cleanup(module, tmp_path, monkeypatch):
    with (tmp_path / 'log').open('w') as log:
        owner = module.OwnedProcess([sys.executable, '-c', 'import time;time.sleep(30)'],
                                   tmp_path, {'PATH': '/usr/bin:/bin'}, log)
        def lost(_): raise ChildProcessError('injected lost identity')
        monkeypatch.setattr(module, 'observe_child', lost)
        result = owner.settle()
        assert result['unsettled'] and not result['zero_survivors']
        assert owner.process.returncode == -9


@pytest.mark.parametrize('disposition', ['python', 'callable', 'ignore', 'default'])
def test_real_sigint_during_cleanup_in_owned_controller(module, tmp_path, repo_root, disposition):
    import subprocess
    script = r"""
import os,sys,signal
sys.path.insert(0,sys.argv[1])
from cnt_owned_process import OwnedProcess
kind=sys.argv[3]
if kind=='ignore': signal.signal(signal.SIGINT,signal.SIG_IGN)
if kind=='default': signal.signal(signal.SIGINT,signal.SIG_DFL)
seen=[]
if kind=='callable': signal.signal(signal.SIGINT,lambda *_:seen.append(True))
previous=signal.getsignal(signal.SIGINT)
with open(sys.argv[2]+'/log','w') as log:
    owner=OwnedProcess([sys.executable,'-c','import time;time.sleep(30)'],
                       sys.argv[2],{'PATH':'/usr/bin:/bin'},log)
    original=owner._settle
    def interrupted():
        # A real kernel-delivered signal to this exclusively owned controller.
        signal.raise_signal(signal.SIGINT)
        return original()
    owner._settle=interrupted
    original_reap=owner._reap
    def recorded_reap():
        original_reap()
        with open(sys.argv[2]+'/reaped','w') as marker:
            marker.write('cleanup completed')
    owner._reap=recorded_reap
    try:
        result=owner.settle()
    except KeyboardInterrupt:
        if kind!='python': raise
        result=owner.result
    if signal.getsignal(signal.SIGINT)!=previous: raise RuntimeError('handler changed')
    if not result['zero_survivors']: raise RuntimeError('cleanup failed')
    if kind=='callable' and seen!=[True]: raise RuntimeError('not delivered')
    if owner.settle() is not result: raise RuntimeError('not idempotent')
"""
    result = subprocess.run([sys.executable, '-B', '-c', script, str(repo_root / 'tests'),
                             str(tmp_path), disposition], capture_output=True, timeout=15)
    assert result.returncode == (-2 if disposition == 'default' else 0), result.stderr.decode()
    assert (tmp_path / 'reaped').read_text() == 'cleanup completed'


@pytest.mark.parametrize('layout', ['absent', 'occupied', 'pipe-ends'])
def test_pipe_mapping_in_separate_parent(module, tmp_path, repo_root, layout):
    import subprocess
    script = r"""
import os,sys,select
sys.path.insert(0,sys.argv[1])
from cnt_owned_process import OwnedProcess
for fd in (3,4):
    try: os.close(fd)
    except OSError: pass
if sys.argv[3]=='occupied':
    for _ in range(2): os.open(os.devnull,os.O_RDONLY)
a,b=os.pipe();c,d=os.pipe()
import fcntl
if sys.argv[3]=='absent':
    original=(a,b,c,d)
    a,b,c,d=[fcntl.fcntl(fd,fcntl.F_DUPFD,20) for fd in original]
    for fd in original: os.close(fd)
elif sys.argv[3]=='pipe-ends':
    moved=fcntl.fcntl(b,fcntl.F_DUPFD,20);os.close(b);b=moved
    os.dup2(d,4);os.close(d);d=4
with open(sys.argv[2]+'/log','w') as log:
    owner=OwnedProcess([sys.executable,'-B','-c',
       'import os;data=os.read(3,10);os.write(4,data.upper())'],sys.argv[2],
       {'PATH':'/usr/bin:/bin'},log,(a,d))
    os.close(a);os.close(d)
    try:
        os.write(b,b'nonce')
        if not select.select([c],[],[],3)[0]: raise RuntimeError('pipe timeout')
        if os.read(c,10)!=b'NONCE': raise RuntimeError('pipe mismatch')
        owner.until(lambda:owner.returncode is not None,3)
        if not select.select([c],[],[],3)[0] or os.read(c,1)!=b'':
            raise RuntimeError('supervisor retained browser pipe')
    finally:
        result=owner.settle();os.close(b);os.close(c)
    if not result['zero_survivors']: raise RuntimeError('unsettled')
"""
    result = subprocess.run([sys.executable, '-B', '-c', script, str(repo_root / 'tests'),
                             str(tmp_path), layout], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode()


def test_control_eof_failsafe(module, tmp_path):
    import signal
    import time
    with (tmp_path / 'log').open('w') as log:
        owner = module.OwnedProcess([sys.executable, '-c', 'import time;time.sleep(30)'],
                                   tmp_path, {'PATH': '/usr/bin:/bin'}, log)
        owner.control.shutdown(1)
        deadline = time.monotonic() + 3
        while module.observe_child(owner.process.pid) is None and time.monotonic() < deadline:
            time.sleep(.01)
        try:
            assert module.observe_child(owner.process.pid) is not None
            assert not [p for p, state in module.group_rows(owner.process.pid)
                        if p != owner.process.pid and not state.startswith('Z')]
        finally:
            owner.settle()


def test_forced_kill_records_unknown_exit(module, tmp_path):
    script = "import signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);pathlib.Path('ready').touch();time.sleep(30)"
    with (tmp_path / 'log').open('w') as log:
        owner = module.OwnedProcess([sys.executable, '-c', script], tmp_path,
                                   {'PATH': '/usr/bin:/bin'}, log)
        try:
            owner.until(lambda: (tmp_path / 'ready').exists(), 3)
        finally:
            result = owner.settle()
        assert result['zero_survivors'] and not result['unsettled']
        assert result['exit_code'] is None and result['workload_status'] == 'unknown-before-kill'
        assert owner.settle() is result
