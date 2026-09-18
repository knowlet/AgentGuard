"""Stage a small write set and roll it back on a caught I/O failure.

Not crash-atomic across files. A killed installer requires a fresh disposable checkout.
"""
from __future__ import annotations
import os
from pathlib import Path
import tempfile


def write_set(outputs: dict[Path, bytes]) -> None:
    paths = [p.absolute() for p in outputs]
    if len({p.resolve() for p in paths}) != len(paths):
        raise ValueError('PATCH_OUTPUT_ALIAS')
    if any(p.is_symlink() or (p.exists() and not p.is_file()) for p in paths):
        raise ValueError('PATCH_OUTPUT_NOT_REGULAR')
    staged, backups, committed = {}, {}, []
    def stage(path, data, mode):
        fd, name = tempfile.mkstemp(prefix='.agentguard-', dir=path.parent)
        tmp = Path(name)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            tmp.chmod(mode)
            return tmp
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        for original, data in outputs.items():
            p = original.absolute()
            p.parent.mkdir(parents=True, exist_ok=True)
            mode = p.stat().st_mode & 0o777 if p.exists() else 0o644
            backups[p] = stage(p, p.read_bytes(), mode) if p.exists() else None
            staged[p] = stage(p, data, mode)
        for p in paths:
            os.replace(staged[p], p)
            committed.append(p)
    except BaseException:
        failures = []
        for p in reversed(committed):
            try:
                if backups[p] is None:
                    p.unlink(missing_ok=True)
                else:
                    os.replace(backups[p], p)
            except OSError as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError('PATCH_ROLLBACK_FAILED: discard this checkout') from failures[0]
        raise
    finally:
        for tmp in list(staged.values()) + list(backups.values()):
            if tmp is not None:
                tmp.unlink(missing_ok=True)
