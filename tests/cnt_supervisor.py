"""Private harness supervisor. No captured code; no public installed command."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time


def remap_pipes(fds):
    if not fds:
        return
    # Child-only copies above 4 handle absent, occupied and overlapping 3/4.
    import fcntl
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD, 10) for fd in fds]
    for source, target in zip(copies, (3, 4)):
        os.dup2(source, target)
    for fd in set(copies + list(fds)) - {3, 4}:
        os.close(fd)


def send(control, token, **message):
    control.sendall(json.dumps(dict(token=token, **message)).encode() + b'\n')


def shutdown_requested(control, token, buffer):
    if not select.select([control], [], [], .02)[0]:
        return False, buffer
    data = control.recv(4096)
    if not data:
        return True, buffer
    buffer += data
    if len(buffer) > 4096:
        return True, buffer
    if b'\n' not in buffer:
        return False, buffer
    # This private channel has exactly one command. Invalid traffic terminates
    # the owned workload as a fail-safe, never as a successful acknowledgement.
    message = json.loads(buffer)
    if message != {'token': token, 'command': 'shutdown'}:
        raise ValueError('Invalid control command')
    return True, b''


def cleanup(control, token, process):
    if os.getpgrp() != os.getpid():
        os._exit(125)
    os.killpg(os.getpgrp(), signal.SIGTERM)
    deadline = time.monotonic() + .75
    while process is not None and process.poll() is None and time.monotonic() < deadline:
        time.sleep(.02)
    try:
        if process is not None and process.returncode is not None:
            send(control, token, exit=process.returncode)
        send(control, token, cleanup='pre-kill',
             workload_status=('exited' if process is not None and process.returncode is not None
                              else 'unknown-before-kill'))
    except (OSError, ValueError):
        pass
    finally:
        # Nothing is promised after this syscall. Parent requires pre-kill
        # acknowledgement, explicit status classification, self-SIGKILL and
        # pre-reap empty-group observation. Unknown workload exit is not zero.
        os.killpg(os.getpgrp(), signal.SIGKILL)


def main():
    control = socket.socket(fileno=int(sys.argv[1]))
    control.settimeout(1)
    fds = json.loads(sys.argv[2])
    token = sys.argv[3]
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, lambda *_: None)
    signal.signal(signal.SIGINT, lambda *_: None)
    process = None
    try:
        if os.getpgrp() != os.getpid():
            raise RuntimeError('Supervisor is not group leader')
        argv = sys.argv[4:]
        if fds:
            argv = [sys.executable, '-B', str(Path(__file__).with_name('cnt_pipe_exec.py')),
                    json.dumps(fds), *argv]
        process = subprocess.Popen(argv, pass_fds=tuple(fds), close_fds=True)
        for fd in fds:
            os.close(fd)
        os.close(1)
        os.close(2)
        send(control, token, supervisor=os.getpid(), started=process.pid)
        reported, buffer = False, b''
        while True:
            stop, buffer = shutdown_requested(control, token, buffer)
            if stop:
                break
            if not reported and process.poll() is not None:
                send(control, token, exit=process.returncode)
                reported = True
    finally:
        cleanup(control, token, process)


if __name__ == '__main__':
    main()
