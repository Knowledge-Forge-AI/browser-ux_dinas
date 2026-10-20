"""Enumerated source export before Nix sees a flake root. Never invokes Nix.

Tracked files plus tests/source-only-roster.json are the only inputs. The roster
is an explicit adoption list, not an untracked-file glob. It may be retired once
all its entries are tracked; tracked entries in it are harmless duplicates.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

ROSTER = 'tests/source-only-roster.json'
EXCLUDED = {'.git', '.scratch', 'scratch', '__pycache__', '.pytest_cache',
            'reports', 'outbox', 'node_modules', '.venv'}
CAPTURE_XPI = 'bd6ed1160739fb475e4f13c9f43885436f9a5ef6395be8ca514773e77ae9cf9f'
CAPTURE_ID = 'felphkbfjadmcejnibcmcncimlappdde'


def require(value, message):
    if not value:
        raise ValueError(message)


def stamp(info):
    # Reading may update atime; that is not a content/identity change.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def safe_name(name):
    path = PurePosixPath(name)
    require(bool(name) and str(path) == name and not path.is_absolute()
            and '..' not in path.parts and '\\' not in name
            and not any(ord(c) < 32 for c in name), 'Unsafe source name')
    require(not EXCLUDED.intersection(path.parts), 'Excluded source path')
    require('_metadata' not in path.parts, 'Extension signature material refused')
    return path.parts


def read_entry(root, name):
    """Open every ancestor relative to an owned FD with O_NOFOLLOW."""
    parts = safe_name(name)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
            os.close(directory)
            directory = next_fd
        info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raw = os.readlink(parts[-1], dir_fd=directory).encode()
            kind = 'symlink'
        else:
            require(stat.S_ISREG(info.st_mode), 'Special source entry refused')
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                require(stamp(os.fstat(stream.fileno())) == stamp(info), 'Source replaced before read')
                raw = stream.read()
                require(stamp(os.fstat(stream.fileno())) == stamp(info), 'Source changed during read')
            kind = 'file'
        require(stamp(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)) == stamp(info),
                'Source entry changed during read')
        return {'kind': kind, 'mode': stat.S_IMODE(info.st_mode),
                'sha256': hashlib.sha256(raw).hexdigest()}, raw
    finally:
        os.close(directory)


def reject_capture(name, raw):
    require(hashlib.sha256(raw).hexdigest() != CAPTURE_XPI, 'Captured XPI refused')
    # Extension manifests can be renamed; parse objects rather than match docs
    # that legitimately discuss extension IDs and capture hashes.
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return
    if not isinstance(value, dict) or 'manifest_version' not in value:
        return
    identity = value.get('browser_specific_settings', {}).get('gecko', {}).get('id')
    require(identity != 'clear-new-tab@loftyshaky', 'Captured Firefox manifest refused')
    if 'key' in value:
        try:
            digest = hashlib.sha256(base64.b64decode(value['key'], validate=True)).hexdigest()[:32]
        except (ValueError, TypeError):
            raise ValueError('Malformed extension manifest key') from None
        identity = ''.join(chr(ord('a') + int(c, 16)) for c in digest)
    require(identity != CAPTURE_ID and value.get('id') != CAPTURE_ID,
            'Captured Chrome manifest refused')


def git_paths(root, *flags):
    raw = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', *flags])
    return {p.decode() for p in raw.split(b'\0') if p}


def inventory(root):
    _, raw = read_entry(root, ROSTER)
    roster = json.loads(raw)
    require(isinstance(roster, list) and all(isinstance(p, str) for p in roster), 'Invalid roster')
    require(len(roster) == len(set(roster)), 'Duplicate roster entry')
    tracked = git_paths(root, '--cached')
    selected = tracked | set(roster) | {ROSTER}
    for name in selected:
        safe_name(name)
    # Explicit exclusion is independent of .gitignore / .git/info/exclude.
    others = git_paths(root, '--others', '--exclude-standard')
    unexpected = {p for p in others if not EXCLUDED.intersection(PurePosixPath(p).parts)} - selected
    require(not unexpected, 'Unexpected untracked source inputs: ' + ', '.join(sorted(unexpected)))
    return sorted(selected)


def validate_link(name, raw, selected, entries):
    pending = list(PurePosixPath(name).parent.parts) + raw.decode().split('/')
    require(not raw.startswith(b'/'), 'Absolute source link refused')
    current = []
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            require(bool(current), 'Escaping source link')
            current.pop()
            continue
        current.append(part)
        candidate = '/'.join(current)
        safe_name(candidate)
        if candidate in entries and entries[candidate][0]['kind'] == 'symlink':
            hops += 1
            require(hops < 40, 'Source link cycle')
            target = entries[candidate][1].decode()
            require(not target.startswith('/'), 'Absolute source link chain')
            current.pop()
            pending = target.split('/') + pending
    target = '/'.join(current)
    require(target in selected or any(p.startswith(target + '/') for p in selected),
            'Link target outside enumerated source')


def collect(root, names):
    entries = {name: read_entry(root, name) for name in names}
    for name, (record, raw) in entries.items():
        if record['kind'] == 'symlink':
            validate_link(name, raw, names, entries)
        else:
            reject_capture(name, raw)
    return entries


def export(root, destination):
    root, destination = Path(root).absolute(), Path(destination).absolute()
    require(root.resolve() == root, 'Source root has symlink ancestors')
    require(destination.parent.resolve() == destination.parent, 'Destination ancestor substitution')
    require(not destination.is_relative_to(root), 'Snapshot must be outside worktree')
    names = inventory(root)
    entries = collect(root, names)
    destination.mkdir(mode=0o700, exist_ok=False)
    for name, (record, raw) in entries.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if record['kind'] == 'symlink':
            target.symlink_to(raw.decode())
            # macOS applies umask to symlink modes; preserve the link entry,
            # never the referent, before checking the exact source inventory.
            if os.chmod in os.supports_follow_symlinks:
                os.chmod(target, record['mode'], follow_symlinks=False)
        else:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, record['mode'])
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), record['mode'])
    require(inventory(root) == names and collect(root, names) == entries,
            'Candidate changed while snapshotting')
    require(collect(destination, names) == entries, 'Snapshot byte/mode/link mismatch')
    manifest = {name: record for name, (record, _) in entries.items()}
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema': 'browser-ux-source-inventory-v1', 'sha256': digest, 'entries': manifest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    scratch = Path('/Users/Shared/agent-scratch/r')
    require(args.destination.absolute().is_relative_to(scratch), 'Use APGR scratch outside the worktree')
    result = export(args.source_root, args.destination)
    manifest = args.destination.with_name(args.destination.name + '-inventory.json')
    with manifest.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'EXPORTED', 'sha256': result['sha256'], 'files': len(result['entries'])}))


if __name__ == '__main__':
    main()
