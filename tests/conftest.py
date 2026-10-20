"""Offline fixtures shared by the migrated and destination package suites."""
import importlib.util
import itertools
import re
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_counter = itertools.count()


@pytest.fixture(scope="session")
def repo_root():
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def load_module(repo_root):
    def load(relative_path, module_name=None):
        name = module_name or f"browser_ux_{next(_counter)}_{re.sub('[^a-zA-Z0-9_]', '_', relative_path)}"
        loader = SourceFileLoader(name, str(repo_root / relative_path))
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        loader.exec_module(module)
        return module
    return load


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
