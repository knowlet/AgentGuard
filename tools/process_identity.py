"""Linux-only attribution of the listening socket to the launched child.

An isolated CI host is assumed; this is not a defense against a compromised kernel
or another process with ptrace/write access to the runner. Missing /proc evidence fails.
"""
from __future__ import annotations
import os
from pathlib import Path
import time


def listener_owned(process, executable: Path, port: int) -> bool:
    if process.poll() is not None:
        raise RuntimeError('GATEWAY_PROCESS_EXITED')
    proc = Path('/proc') / str(process.pid)
    try:
        if not os.path.samefile(proc / 'exe', executable):
            return False
        inodes = set()
        for fd in (proc / 'fd').iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue  # A descriptor may close while enumerating.
            if link.startswith('socket:['):
                inodes.add(link[8:-1])
        listeners = set()
        for table in ('tcp', 'tcp6'):
            path = proc / 'net' / table
            if not path.exists() and table == 'tcp6':
                continue
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
                    listeners.add(fields[9])
        return bool(listeners) and listeners <= inodes
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeError('GATEWAY_PROCESS_EVIDENCE_UNAVAILABLE') from exc


def wait_listener(process, executable: Path, port: int, seconds: float = 30) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if listener_owned(process, executable, port):
            return
        time.sleep(.05)
    raise RuntimeError('GATEWAY_LISTENER_NOT_OWNED')


def require_listener(process, executable: Path, port: int) -> None:
    if not listener_owned(process, executable, port):
        raise RuntimeError('GATEWAY_LISTENER_NOT_OWNED')
