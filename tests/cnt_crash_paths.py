"""Admit crash directories lexically, then walk owned directory FDs only."""
from contextlib import contextmanager
import errno
import os
from pathlib import PurePosixPath
import stat


def relative_destination(run, value):
    # Do not normalize away traversal, duplicate separators, or dot components.
    if (type(value) is not str or not value.startswith('/')
            or '\\' in value or any(ord(c) < 32 for c in value)):
        return None
    parts = value.split('/')[1:]
    root = str(run).split('/')[1:]
    if (any(p in ('', '.', '..') for p in parts)
            or parts[:len(root)] != root or len(parts) <= len(root)):
        return None
    return '/'.join(parts[len(root):])


@contextmanager
def owned_directory(run, value):
    relative = relative_destination(run, value)
    if relative is None:
        yield {'status': 'REFUSED_OUTSIDE_OWNED_ROOT'}, None
        return
    descriptor = None
    admission = {'status': 'OWNED_DIRECTORY', 'relative': relative}
    try:
        descriptor = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in relative.split('/'):
            info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                admission = {'status': 'REFUSED_LINK'}
                break
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        status = {errno.ENOENT: 'ABSENT_DIRECTORY', errno.ENOTDIR: 'NOT_DIRECTORY',
                  errno.ELOOP: 'REFUSED_LINK'}.get(error.errno, 'INACCESSIBLE_DIRECTORY')
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        yield {'status': status, 'errno': error.errno}, None
    else:
        try:
            yield admission, descriptor if admission['status'] == 'OWNED_DIRECTORY' else None
        finally:
            os.close(descriptor)
            descriptor = None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def count_directory(descriptor):
    counts = {'dmp': 0, 'extra': 0, 'other': 0, 'non_regular': 0}
    with os.scandir(descriptor) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                try:
                    nested = count_directory(child)
                finally:
                    os.close(child)
                for key in counts:
                    counts[key] += nested[key]
            elif stat.S_ISREG(info.st_mode):
                suffix = PurePosixPath(entry.name).suffix.lstrip('.')
                counts[suffix if suffix in ('dmp', 'extra') else 'other'] += 1
            else:
                counts['non_regular'] += 1
    return counts
