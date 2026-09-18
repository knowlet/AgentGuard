"""Stage a small write set, using no-follow directory handles, with I/O rollback.

POSIX only. Not crash-atomic across files; a killed installer needs a new checkout.
The caller owns a private workspace: concurrent directory renames by the same UID
or root remain outside this helper's trust boundary.
"""
from __future__ import annotations
import os
from pathlib import Path
import secrets
import stat


def _path(path: Path) -> Path:
    p = path.absolute()
    if '..' in p.parts or p.name in ('', '.', '..'):
        raise ValueError('PATCH_OUTPUT_ALIAS')
    return p


def _check_ancestors(path: Path) -> None:
    # Preflight the whole write set before creating even staging files/directories.
    for parent in reversed(path.parents):
        try:
            mode = parent.lstat().st_mode
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(mode):
            raise ValueError('PATCH_PARENT_NOT_DIRECTORY_OR_SYMLINK')
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise ValueError('PATCH_OUTPUT_NOT_REGULAR')


def _parent_fd(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parent.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_set(outputs: dict[Path, bytes]) -> None:
    paths = [_path(p) for p in outputs]
    if len(set(paths)) != len(paths):
        raise ValueError('PATCH_OUTPUT_ALIAS')
    for p in paths:
        _check_ancestors(p)
    staged, backups, committed, directories = {}, {}, [], {}

    def stage(directory, data, mode):
        name = '.agentguard-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fchmod(out.fileno(), mode)
                os.fsync(out.fileno())
            return name
        except BaseException:
            os.unlink(name, dir_fd=directory)
            raise

    try:
        for p, data in zip(paths, outputs.values()):
            directory = _parent_fd(p)
            directories[p] = directory
            try:
                fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                original, mode = None, 0o644
            else:
                with os.fdopen(fd, 'rb') as stream:
                    st = os.fstat(stream.fileno())
                    if not stat.S_ISREG(st.st_mode):
                        raise ValueError('PATCH_OUTPUT_NOT_REGULAR')
                    original, mode = stream.read(), stat.S_IMODE(st.st_mode) & 0o777
            backups[p] = stage(directory, original, mode) if original is not None else None
            staged[p] = stage(directory, data, mode)
        for p in paths:
            directory = directories[p]
            os.replace(staged[p], p.name, src_dir_fd=directory, dst_dir_fd=directory)
            committed.append(p)
    except BaseException:
        failures = []
        for p in reversed(committed):
            directory = directories[p]
            try:
                if backups[p] is None:
                    os.unlink(p.name, dir_fd=directory)
                else:
                    os.replace(backups[p], p.name, src_dir_fd=directory, dst_dir_fd=directory)
            except OSError as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError('PATCH_ROLLBACK_FAILED: discard this checkout') from failures[0]
        raise
    finally:
        try:
            for mapping in (staged, backups):
                for p, name in mapping.items():
                    if name is not None:
                        try:
                            os.unlink(name, dir_fd=directories[p])
                        except FileNotFoundError:
                            pass
        finally:
            for fd in directories.values():
                os.close(fd)
