"""Source export adversaries use synthetic canaries, never private captures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).with_name('source_only_snapshot.py'))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'tests').mkdir()
    (root / snapshot.ROSTER).write_text(json.dumps(['new.py']))
    (root / 'tracked.py').write_text('dirty candidate\n')
    (root / 'new.py').write_text('adopted candidate\n')
    tracked = {'tracked.py', snapshot.ROSTER}
    others = {'new.py'}
    monkeypatch.setattr(snapshot, 'git_paths', lambda root, *flags: tracked if '--cached' in flags else others)
    return root, tmp_path / 'snapshot', tracked, others


def test_dirty_and_roster_bytes_modes_and_private_exclusion(repo):
    root, dest, _, others = repo
    private = root / '.scratch'
    private.mkdir()
    (private / 'private-canary').write_text('never export')
    others.add('.scratch/private-canary')  # No Git ignore rule exists.
    (root / 'tracked.py').chmod(0o755)
    result = snapshot.export(root, dest)
    assert (dest / 'tracked.py').read_text() == 'dirty candidate\n'
    assert (dest / 'new.py').read_text() == 'adopted candidate\n'
    assert (dest / 'tracked.py').stat().st_mode & 0o777 == 0o755
    assert not (dest / '.scratch').exists()
    assert set(result['entries']) == {'tracked.py', 'new.py', snapshot.ROSTER}


def test_unexpected_input_refused_before_copy(repo):
    root, dest, _, others = repo
    others.add('unexpected.py')
    with pytest.raises(ValueError, match='Unexpected'):
        snapshot.export(root, dest)
    assert not dest.exists()


@pytest.mark.parametrize('name', ['.scratch/private', 'a/../private', '/private',
                                  'a/_metadata/verified_contents.json', 'reports/x'])
def test_unsafe_roster(repo, name):
    root, dest, _, _ = repo
    (root / snapshot.ROSTER).write_text(json.dumps([name]))
    with pytest.raises(ValueError):
        snapshot.export(root, dest)
    assert not dest.exists()


def test_internal_link_preserved_without_following(repo):
    root, dest, tracked, _ = repo
    (root / 'link').symlink_to('tracked.py')
    tracked.add('link')
    snapshot.export(root, dest)
    assert (dest / 'link').is_symlink()
    assert os.readlink(dest / 'link') == 'tracked.py'


def test_directory_link_preserves_entry_mode_across_umask(repo):
    root, dest, tracked, _ = repo
    (root / 'folder').mkdir()
    (root / 'folder/canary').write_text('synthetic directory target')
    (root / 'directory-link').symlink_to('folder', target_is_directory=True)
    tracked.update(['folder/canary', 'directory-link'])
    before = (root / 'directory-link').lstat().st_mode & 0o777
    previous = os.umask(0o077)
    try:
        result = snapshot.export(root, dest)
    finally:
        os.umask(previous)
    assert os.readlink(dest / 'directory-link') == 'folder'
    assert (dest / 'directory-link').lstat().st_mode & 0o777 == before
    assert result['entries']['directory-link']['sha256'] == hashlib.sha256(b'folder').hexdigest()


@pytest.mark.parametrize('target', ['../outside', '/etc/passwd', '.scratch/private', 'link'])
def test_escaping_private_and_cyclic_links(repo, target):
    root, dest, tracked, _ = repo
    (root / 'link').symlink_to(target)
    tracked.add('link')
    with pytest.raises(ValueError):
        snapshot.export(root, dest)


def test_symlink_ancestor_refused(repo, tmp_path):
    root, dest, tracked, _ = repo
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'private').write_text('synthetic')
    (root / 'ancestor').symlink_to(outside, target_is_directory=True)
    tracked.add('ancestor/private')
    with pytest.raises(OSError):
        snapshot.export(root, dest)
    assert not dest.exists()


def test_capture_digest_even_if_renamed(repo, monkeypatch):
    root, dest, _, _ = repo
    raw = b'synthetic forbidden package'
    monkeypatch.setattr(snapshot, 'CAPTURE_XPI', hashlib.sha256(raw).hexdigest())
    (root / 'new.py').write_bytes(raw)
    with pytest.raises(ValueError, match='XPI'):
        snapshot.export(root, dest)


@pytest.mark.parametrize('manifest', [
    {'manifest_version': 3, 'id': snapshot.CAPTURE_ID},
    {'manifest_version': 3, 'browser_specific_settings': {'gecko': {'id': 'clear-new-tab@loftyshaky'}}},
])
def test_renamed_native_manifest_refused(repo, manifest):
    root, dest, _, _ = repo
    (root / 'new.py').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='manifest'):
        snapshot.export(root, dest)


def test_candidate_drift_fails_and_leaves_unqualified_snapshot(repo, monkeypatch):
    root, dest, _, _ = repo
    original = snapshot.collect
    calls = []
    def collect(path, names):
        result = original(path, names)
        calls.append(path)
        if len(calls) == 1:
            (root / 'tracked.py').write_text('concurrent change')
        return result
    monkeypatch.setattr(snapshot, 'collect', collect)
    with pytest.raises(ValueError, match='changed'):
        snapshot.export(root, dest)
    assert not dest.with_name(dest.name + '-inventory.json').exists()


def test_destination_inside_source_refused(repo):
    root, _, _, _ = repo
    with pytest.raises(ValueError, match='outside'):
        snapshot.export(root, root / 'snapshot')


@pytest.mark.parametrize('optimized', [False, True])
def test_refusal_remains_active_under_optimization(optimized):
    module = Path(__file__).with_name('source_only_snapshot.py')
    program = ('import runpy; m=runpy.run_path(' + repr(str(module)) + ');'
               'm["safe_name"](".scratch/private-canary")')
    result = subprocess.run([sys.executable, '-B', *(['-O'] if optimized else []),
                             '-c', program], capture_output=True, text=True)
    assert result.returncode != 0 and 'Excluded source path' in result.stderr
