"""The RunOnce safety net's commands, run for real by Windows' own reg.exe.

A static (Compatibility-mode) apply in the registry sandbox writes the net to
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
from sniper.compat import IS_WINDOWS

pytestmark = [pytest.mark.skipif(not IS_WINDOWS, reason="runs Windows' reg.exe"),
              pytest.mark.windows_integration]

ADDR = "127.0.0.1:8881"
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
        assert command.startswith('"%s" add "HKCU\\%s" /v ' % (reg, box.ie)), command
        assert len(command) <= 260, command
    return net


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


def test_safe_mode_and_stop_leave_no_net(registry_sandbox):
    box = registry_sandbox
    winproxy.proxy_enable(ADDR)
    assert checked_net(box)
    winproxy.proxy_enable(ADDR, pac_url="http://127.0.0.1:8881/sniper-0123456789abcdef.pac")
    assert not box.runonce()          # the static record was restored first
    assert winproxy.proxy_restore() == "restored"
    winproxy.proxy_enable(ADDR)
    assert checked_net(box)
    assert winproxy.proxy_restore() == "restored"
    assert not box.runonce()
    assert box.live() == (0, "", ABSENT)
