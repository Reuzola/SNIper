"""Best-effort guard for the README's "Python 3.7+" promise.

Every shipped module and tool is parsed with the 3.7 grammar, which rejects
the walrus operator, positional-only parameters, match statements and other
newer syntax. It can't see runtime-only problems (a list[str] annotation that
is evaluated at runtime, functools.cache), which is why every module also has
to start with "from __future__ import annotations".
"""
from __future__ import annotations

import ast
import glob
import os
import sys

import pytest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _files():
    patterns = ("src/**/*.py", "tools/*.py", "tests/manual/*.py")
    found = []
    for pattern in patterns:
        found += glob.glob(os.path.join(_ROOT, pattern), recursive=True)
    return sorted(found)


def _rel(path):
    return os.path.relpath(path, _ROOT).replace("\\", "/")


def test_files_found():
    rels = [_rel(f) for f in _files()]
    assert "src/sniper/winproxy.py" in rels
    assert "src/sniper/sessionwatch.py" in rels
    assert "tools/proxy_state.py" in rels
    assert "tests/manual/block_shutdown.py" in rels


@pytest.mark.skipif(sys.version_info < (3, 8),
                    reason="ast.parse(feature_version=...) needs Python 3.8+")
@pytest.mark.parametrize("path", _files(), ids=_rel)
def test_parses_as_python37(path):
    with open(path, encoding="utf-8") as f:
        source = f.read()
    ast.parse(source, filename=path, feature_version=(3, 7))


@pytest.mark.parametrize("path", _files(), ids=_rel)
def test_has_future_annotations(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)
    futures = {alias.name for node in tree.body
               if isinstance(node, ast.ImportFrom) and node.module == "__future__"
               for alias in node.names}
    assert "annotations" in futures
