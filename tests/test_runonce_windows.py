"""The RunOnce safety net's commands, run for real by Windows' own reg.exe.

An apply in the registry sandbox, in either mode, writes the net to
<sandbox>\\RunOnce, a plain key Windows never runs. The test then plays the
crash and the next sign-in itself: it never restores, and passes each stored
command unchanged to subprocess.run, which hands a string to CreateProcess
as-is, exactly as Windows runs a RunOnce entry. That proves the commands are
valid on real Windows. Every command is checked to name the sandbox's own
Internet Settings key before it runs, so nothing here can reach the real one.
"""
from __future__ import annotations

import os
import subprocess

import pytest

import sniper.winproxy as winproxy
from helpers import ABSENT
from sniper.compat import IS_WINDOWS, winreg

pytestmark = [pytest.mark.skipif(not IS_WINDOWS, reason="runs Windows' reg.exe"),
              pytest.mark.windows_integration]

ADDR = "127.0.0.1:8881"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
_CREATE_NO_WINDOW = 0x08000000   # no console flashing while the suite runs


def run(command):
    """Run a stored command exactly as Windows would: the string, unsplit."""
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30,
                          creationflags=_CREATE_NO_WINDOW)


def checked_net(box):
    """The sandbox's RunOnce commands, each verified to target the sandbox
    (and nothing else) before a test may run it."""
    net = box.runonce() or {}
    reg = (os.environ.get("SystemRoot") or r"C:\Windows").rstrip("\\") + r"\System32\reg.exe"
    for name, command in net.items():
        assert name.startswith("SNIperRestore"), name
        assert command.startswith(tuple('"%s" %s "HKCU\\%s" /v ' % (reg, verb, box.ie)
                                        for verb in ("add", "delete"))), command
        assert len(command) <= 260, command
    return net


def forget(box, name):
    """Windows deletes a RunOnce value before it runs it."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, box.runonce_key, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.DeleteValue(k, name)
    finally:
        winreg.CloseKey(k)


@pytest.mark.parametrize("genuine", [
    (0, "", ABSENT),
    (1, "corp-proxy:8080", ABSENT),
    (0, "http=a:1;https=b:2", "http://corp/p.pac?a=1&b=%20x"),
    (1, "corp\\proxy with spaces:8080", "http://corp/a b.pac"),
    (1, "\u00fcml\u00e4ut-proxy:1", ABSENT),
], ids=["nothing", "manual-proxy", "pac-and-list", "backslash-and-spaces", "unicode"])
def test_the_commands_restore_the_genuine_values_for_real(registry_sandbox, genuine):
    box = registry_sandbox
    box.set_live(*genuine)
    winproxy.proxy_enable(ADDR)
    footprint = box.live()
    assert footprint[:2] == (1, ADDR)
    net = checked_net(box)
    expected = {"SNIperRestoreProxyEnable", "SNIperRestoreProxyServer"}
    if genuine[2]:
        expected.add("SNIperRestoreAutoConfigURL")
    assert set(net) == expected

    # The crash: no restore. Then the sign-in: Windows runs each command.
    for command in net.values():
        result = run(command)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
    assert box.live() == genuine

    # The next launch finds the record settled by someone else.
    assert winproxy.recover_orphaned_proxy() == "already"
    assert not box.runonce()
    assert box.record() is None
    assert box.live() == genuine


@pytest.mark.parametrize("genuine", [
    (0, "", ABSENT, ABSENT),
    (0, "127.0.0.1:8881", ABSENT, ABSENT),
    (1, "corp-proxy:8080", ABSENT, "*.corp.example;<local>"),
    (0, "", "http://corp/p.pac?a=1&b=%20x", "*"),
    (0, "", "", ""),
    (1, "corp\\proxy with spaces:8080", "http://corp/a b.pac", "a b;\u00fcml\u00e4ut;<local>"),
], ids=["nothing", "old-sniper-server", "manual-proxy-and-list", "pac-and-star", "empty",
        "spaces-backslash-unicode"])
@pytest.mark.parametrize("cut_short", [False, True], ids=["applied", "before-the-list"])
def test_the_safe_mode_commands_restore_everything_for_real(registry_sandbox, genuine,
                                                           cut_short):
    box = registry_sandbox
    box.set_live(*genuine[:3], override=genuine[3])
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert box.live() == (1, ADDR, URL)
    if cut_short:   # the power went right before the last live write
        box.set_live(1, ADDR, URL, override="*")
    net = checked_net(box)
    assert set(net) == {"SNIperRestore" + name for name in (
        "ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride")}
    for name, command in net.items():
        assert (" delete " in command) == (
            name.endswith(("AutoConfigURL", "ProxyOverride"))
            and genuine[2 if name.endswith("URL") else 3] is ABSENT), command

    for name, command in net.items():
        forget(box, name)
        result = run(command)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
    # Absent stays absent, empty stays empty: exactly as found.
    assert box.live_all() == genuine
    assert winproxy.recover_orphaned_proxy() == "already"
    assert not box.runonce()
    assert box.record() is None
    assert box.live_all() == genuine


def test_deleting_what_is_gone_already_is_harmless(registry_sandbox):
    # E.g. the user took SNIper's script out by hand before signing in again:
    # reg.exe says there is nothing to delete, and does nothing else.
    box = registry_sandbox
    winproxy.proxy_enable(ADDR, pac_url=URL)
    net = checked_net(box)
    box.set_live(0, "", ABSENT, override=ABSENT)
    for name in ("SNIperRestoreAutoConfigURL", "SNIperRestoreProxyOverride"):
        result = run(net[name])
        assert result.returncode == 1
        assert box.live_all() == (0, "", ABSENT, ABSENT)


def test_a_value_left_out_never_breaks_the_other_commands(registry_sandbox):
    # The server can't be carried (reg.exe would wait forever for an
    # overwrite confirmation), so only the enable flag goes back. That alone
    # turns the dead static proxy off: apps connect directly again.
    box = registry_sandbox
    box.set_live(0, "corp:8080\\", ABSENT)
    winproxy.proxy_enable(ADDR)
    net = checked_net(box)
    assert set(net) == {"SNIperRestoreProxyEnable"}
    result = run(net["SNIperRestoreProxyEnable"])
    assert result.returncode == 0, result.stderr
    assert box.live()[0] == 0


def test_each_apply_replaces_the_net_and_stop_leaves_none(registry_sandbox):
    box = registry_sandbox
    for pac_url, size in ((None, 2), (URL, 4), (None, 2)):   # both mode switches
        winproxy.proxy_enable(ADDR, pac_url=pac_url)
        assert len(checked_net(box)) == size
    assert winproxy.proxy_restore() == "restored"
    assert not box.runonce()
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert len(checked_net(box)) == 4
    assert winproxy.proxy_restore() == "restored"
    assert not box.runonce()
    assert box.live_all() == (0, "", ABSENT, ABSENT)
