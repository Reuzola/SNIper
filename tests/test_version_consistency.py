"""One version everywhere: the package, the EXE's version resource, its
manifest, and the User-Agent of SNIper's DoH requests. Also the CHANGELOG's
newest entry and the PyInstaller pin the safety guard relies on.
"""
from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import sniper
import sniper.dns as dns

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_SRC = os.path.join(_ROOT, "src")


def _read(*parts):
    with open(os.path.join(_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _four_part():
    return tuple(int(x) for x in sniper.__version__.split(".")) + (0,)


def test_the_package_version_is_major_minor_patch():
    assert re.fullmatch(r"\d+\.\d+\.\d+", sniper.__version__)
    assert sniper.__version__ == "1.2.0"


def test_the_exe_version_resource_agrees():
    text = _read("packaging", "version_info.txt")
    four = _four_part()
    dotted = ".".join(str(n) for n in four)
    for name in ("filevers", "prodvers"):
        m = re.search(r"\b%s=\((\d+), (\d+), (\d+), (\d+)\)" % name, text)
        assert m, name
        assert tuple(int(g) for g in m.groups()) == four, name
    for name in ("FileVersion", "ProductVersion"):
        m = re.search(r"StringStruct\(u'%s',\s*u'([^']*)'\)" % name, text)
        assert m, name
        assert m.group(1) == dotted, name


def test_the_manifest_agrees():
    root = ET.fromstring(_read("packaging", "app.manifest").encode("utf-8"))
    ns = {"asm": "urn:schemas-microsoft-com:asm.v1"}
    identity = root.find("asm:assemblyIdentity", ns)
    assert identity is not None
    assert identity.get("version") == ".".join(str(n) for n in _four_part())


def test_doh_requests_carry_the_package_version(monkeypatch):
    assert dns._DOH_USER_AGENT == "Mozilla/5.0 SNIper/" + sniper.__version__
    sent = []

    def fake_get(server_ip, path_with_query, headers, timeout):
        sent.append(headers)
        return 503, b""   # every server "fails", so each one is asked once

    monkeypatch.setattr(dns, "_fragmented_https_get", fake_get)
    monkeypatch.setattr(dns, "_skip_unroutable", lambda ip: False)
    dns._doh_lookup("example.com", "A", 1, queue.Queue())
    assert sent and all(h["User-Agent"] == "Mozilla/5.0 SNIper/" + sniper.__version__
                        for h in sent)


def test_no_version_number_is_hardcoded_in_dns():
    assert not re.search(r"SNIper/\d", _read("src", "sniper", "dns.py"))


def test_dns_imports_first_without_a_circular_import():
    # sniper.dns now imports the package for its version: importing it first,
    # in a fresh interpreter, must work.
    code = "import sniper.dns as d, sniper; assert d._DOH_USER_AGENT.endswith(sniper.__version__)"
    proc = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, PYTHONPATH=_SRC),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_the_newest_changelog_entry_is_this_version():
    first = re.search(r"^## v(\S+) - ", _read("CHANGELOG.md"), re.MULTILINE)
    assert first and first.group(1) == sniper.__version__


def test_the_build_pins_pyinstaller_for_the_guardian():
    # 6.9 documents PYINSTALLER_RESET_ENVIRONMENT, which the guardian needs;
    # an installed PyInstaller outside the range is replaced, not used.
    text = _read("packaging", "build_exe.bat")
    assert 'pip install "pyinstaller>=6.9,<7.0"' in text
    assert "(6,9)<=v<(7,0)" in text
    assert "pyinstaller>=6.0" not in text
