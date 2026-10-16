"""Tests for the RunOnce safety net in sniper.winproxy, on the fake registry.

In Compatibility mode, after the record is committed and the static proxy is
live, one RunOnce value per genuine value holds a complete reg.exe command
that writes it back, so an unclean exit that also took the guardian down is
undone at the next sign-in even if SNIper never runs again. Safe mode never
writes them. They go whenever the record is cleared, on every safe-mode
apply and on every launch recovery. test_runonce_windows.py runs the commands
for real against the registry sandbox.
"""
from __future__ import annotations

import queue
import re

import pytest

import sniper.procutil as procutil
import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, IE_KEY, REG_DWORD, REG_SZ, RESTORE_KEY, RUNONCE_KEY)

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
CORP_PAC = "http://corp/p.pac"
SID = "0123456789abcdef"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()
RUNONCE = RUNONCE_KEY.lower()
WINDIR = r"C:\Windows"
HEAD = (r'"C:\Windows\System32\reg.exe" add '
        r'"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ')
OTHER = ("OneDriveSetup", r"C:\x\OneDriveSetup.exe /thfirstsetup")  # not ours


def enable_cmd(n):
    return HEAD + "ProxyEnable /t REG_DWORD /d %d /f" % n


def sz_cmd(name, data):
    return HEAD + '%s /t REG_SZ /d "%s" /f' % (name, data)


@pytest.fixture(autouse=True)
def windir(monkeypatch):
    """A fixed SystemRoot, so the exact command strings are known."""
    monkeypatch.setenv("SystemRoot", WINDIR)


@pytest.fixture(autouse=True)
def owner(monkeypatch):
    monkeypatch.setattr(procutil, "process_identity",
                        lambda pid=None: (4242, 133_700_000_000_000_000))


def net(fake):
    """{name: command} of SNIper's RunOnce values (none -> {})."""
    return {name: data for name, (data, kind) in (fake.runonce() or {}).items()
            if name.lower().startswith("sniperrestore")}


def put_runonce(fake, *pairs):
    for name, data in pairs:
        fake.put(RUNONCE_KEY, name, data, REG_SZ)


def stale_net(fake):
    put_runonce(fake, ("SNIperRestoreProxyEnable", enable_cmd(1)),
                ("sniperrestoreAutoConfigURL", sz_cmd("AutoConfigURL", "http://old/x.pac")),
                ("SNIperRestoreFromTheFuture", "anything"), OTHER)


_CMD_RX = re.compile(r'^"(?P<exe>[^"]+)" add "HKCU\\(?P<key>[^"]+)" /v (?P<name>\w+) '
                     r'/t (?P<kind>REG_DWORD|REG_SZ) /d (?:"(?P<sz>[^"]*)"|(?P<dw>\d+)) /f$')


def run_net(fake):
    """Do what the commands say, on the fake: what reg.exe would do at sign-in.
    Fails the test on any command that isn't exactly the expected shape."""
    for name, command in net(fake).items():
        m = _CMD_RX.match(command)
        assert m, command
        assert m["exe"] == WINDIR + r"\System32\reg.exe"
        assert name == "SNIperRestore" + m["name"]
        if m["kind"] == "REG_DWORD":
            fake.put(m["key"], m["name"], int(m["dw"]), REG_DWORD)
        else:
            fake.put(m["key"], m["name"], m["sz"], REG_SZ)


# ── What is written ──────────────────────────────────────────────────────────
def test_static_enable_from_a_clean_state_writes_exactly_two_commands(fake_reg):
    winproxy.proxy_enable(ADDR)
    assert fake_reg.runonce() == {
        "SNIperRestoreProxyEnable": (enable_cmd(0), REG_SZ),
        "SNIperRestoreProxyServer": (sz_cmd("ProxyServer", ""), REG_SZ),
    }
    assert all(len(c) <= 260 for c in net(fake_reg).values())


@pytest.mark.parametrize("genuine, expected", [
    ((1, "corp:8080", ABSENT),
     {"ProxyEnable": enable_cmd(1), "ProxyServer": sz_cmd("ProxyServer", "corp:8080")}),
    ((0, "", CORP_PAC),
     {"ProxyEnable": enable_cmd(0), "ProxyServer": sz_cmd("ProxyServer", ""),
      "AutoConfigURL": sz_cmd("AutoConfigURL", CORP_PAC)}),
    ((1, "http=a:1;https=b:2", "http://corp/p.pac?a=1&b=%20x"),
     {"ProxyEnable": enable_cmd(1), "ProxyServer": sz_cmd("ProxyServer", "http=a:1;https=b:2"),
      "AutoConfigURL": sz_cmd("AutoConfigURL", "http://corp/p.pac?a=1&b=%20x")}),
    # An empty genuine script is never emptied by static mode: nothing to undo.
    ((0, "corp:8080", ""),
     {"ProxyEnable": enable_cmd(0), "ProxyServer": sz_cmd("ProxyServer", "corp:8080")}),
], ids=["manual-proxy", "genuine-pac", "both", "empty-pac"])
def test_the_commands_name_the_genuine_values(fake_reg, genuine, expected):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR)
    assert net(fake_reg) == {"SNIperRestore" + k: v for k, v in expected.items()}
    assert all(kind == REG_SZ for _, kind in fake_reg.runonce().values())


@pytest.mark.parametrize("genuine", [
    (0, "", ABSENT), (1, "corp:8080", ABSENT), (0, "", CORP_PAC),
    (1, "proxy with spaces:1", "http://corp/a b.pac"), (1, r"corp\proxy:8080", ABSENT),
    (0, "\u00fcml\u00e4ut:1", ABSENT),
])
def test_running_the_net_after_a_crash_restores_the_genuine_values(fake_reg, genuine):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.live() != genuine          # SNIper's static proxy is live
    run_net(fake_reg)                          # sign-in after the crash
    assert fake_reg.live() == genuine
    # The next launch finds the record already settled and clears up.
    assert winproxy.recover_orphaned_proxy() == "already"
    assert net(fake_reg) == {} and fake_reg.record() is None


def test_safe_mode_writes_no_net_and_removes_a_stale_one(fake_reg):
    stale_net(fake_reg)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    # The script next to the manual proxy that bypasses every host: fail-open
    # for all but the apps that read only the manual proxy.
    assert fake_reg.live_all() == (1, ADDR, URL, "*")
    assert net(fake_reg) == {}
    assert fake_reg.runonce() == {OTHER[0]: (OTHER[1], REG_SZ)}  # others stay
    assert not [op for op in fake_reg.ops if op[0] == "SetValueEx" and op[1] == RUNONCE]


def test_a_reapply_rewrites_the_net_from_the_record_not_the_live_footprint(fake_reg):
    fake_reg.set_live(0, "", CORP_PAC)
    winproxy.proxy_enable(ADDR)
    first = net(fake_reg)
    assert fake_reg.live() == (1, ADDR, "")    # the footprint, never genuine
    winproxy.proxy_enable(ADDR2)               # the idempotent path
    assert net(fake_reg) == first


def test_a_stale_command_never_survives_a_fresh_net(fake_reg):
    # Left by an earlier session whose genuine config had a script; this
    # one has none, so running it would put an old script back.
    stale_net(fake_reg)
    winproxy.proxy_enable(ADDR)
    assert set(net(fake_reg)) == {"SNIperRestoreProxyEnable", "SNIperRestoreProxyServer"}
    assert net(fake_reg)["SNIperRestoreProxyEnable"] == enable_cmd(0)
    assert fake_reg.runonce()[OTHER[0]] == (OTHER[1], REG_SZ)


# ── What can't be written ────────────────────────────────────────────────────
@pytest.mark.parametrize("genuine, left_out, reason", [
    ((1, 'corp"x:1', ABSENT), "ProxyServer", "it contains a quote"),
    ((1, "corp:8080\\", ABSENT), "ProxyServer", "it ends with a backslash"),
    ((0, "corp:8080", 'http://corp/"p".pac'), "AutoConfigURL", "it contains a quote"),
    ((0, "corp:8080", "http://corp/p\\"), "AutoConfigURL", "it ends with a backslash"),
    ((1, "x" * 200, ABSENT), "ProxyServer", "its command would be longer than 260 characters"),
    ((0, "", "http://corp/" + "p" * 200), "AutoConfigURL",
     "its command would be longer than 260 characters"),
], ids=["server-quote", "server-backslash", "pac-quote", "pac-backslash",
        "server-long", "pac-long"])
def test_a_value_a_command_cannot_carry_is_left_out(fake_reg, genuine, left_out, reason):
    fake_reg.set_live(*genuine)
    log = queue.Queue()
    winproxy.proxy_enable(ADDR, log_q=log)
    written = net(fake_reg)
    assert "SNIperRestore" + left_out not in written
    assert written["SNIperRestoreProxyEnable"] == enable_cmd(genuine[0])  # the rest stays
    expected = {"ProxyEnable", "ProxyServer"} | ({"AutoConfigURL"} if genuine[2] else set())
    assert set(written) == {"SNIperRestore" + n for n in expected - {left_out}}
    assert list(log.queue) == [("DEBUG", "Sign-in safety net: %s left out, because %s."
                                % (left_out, reason))]
    # The record and the live apply are unaffected.
    assert fake_reg.record()["Complete"] == 1
    assert fake_reg.live()[:2] == (1, ADDR)


def test_the_length_limit_is_260_characters_exactly(fake_reg):
    room = 260 - len(sz_cmd("ProxyServer", ""))
    for size, fits in ((room, True), (room + 1, False)):
        fake_reg.set_live(1, "s" * size, ABSENT)
        winproxy.proxy_enable(ADDR)
        written = net(fake_reg).get("SNIperRestoreProxyServer")
        assert (written is not None) is fits, size
        if fits:
            assert len(written) == 260
        winproxy.proxy_restore()


@pytest.mark.parametrize("size", range(0, 301, 7))
def test_every_command_ever_written_fits(fake_reg, size):
    fake_reg.set_live(1, "s" * size, "http://c/" + "u" * size)
    winproxy.proxy_enable(ADDR)
    assert all(len(c) <= 260 for c in net(fake_reg).values())
    assert "SNIperRestoreProxyEnable" in net(fake_reg)


@pytest.mark.parametrize("root, exe", [
    (r"D:\WINNT", r"D:\WINNT\System32\reg.exe"),
    ("C:\\Windows\\", r"C:\Windows\System32\reg.exe"),   # a trailing backslash
    (None, r"C:\Windows\System32\reg.exe"),              # not set at all
    ("", r"C:\Windows\System32\reg.exe"),                # set but empty
])
def test_reg_exe_comes_from_system_root(fake_reg, monkeypatch, root, exe):
    if root is None:
        monkeypatch.delenv("SystemRoot", raising=False)
    else:
        monkeypatch.setenv("SystemRoot", root)
    winproxy.proxy_enable(ADDR)
    for command in net(fake_reg).values():
        assert command.startswith('"%s" add ' % exe)


def test_a_long_system_root_leaves_every_command_out(fake_reg, monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\" + "w" * 200)
    log = queue.Queue()
    winproxy.proxy_enable(ADDR, log_q=log)
    assert net(fake_reg) == {}
    assert [line[1].split(",")[0] for line in log.queue] == [
        "Sign-in safety net: ProxyEnable left out", "Sign-in safety net: ProxyServer left out"]


def test_the_notes_stay_out_of_the_friendly_log(fake_reg):
    from sniper.logformat import friendly_format
    fake_reg.set_live(1, 'a"b', ABSENT)
    log = queue.Queue()
    winproxy.proxy_enable(ADDR, log_q=log)
    lines = list(log.queue)
    assert lines and all(level == "DEBUG" for level, _ in lines)
    assert all(friendly_format(*line) is None for line in lines)  # verbose only


# ── When it goes ─────────────────────────────────────────────────────────────
def _restored(fake):
    return winproxy.proxy_restore()


def _kept(fake):
    fake.set_live(1, "user:3128", ABSENT)
    return winproxy.proxy_restore()


def _already(fake):
    fake.set_live(1, "corp:8080", ABSENT)
    return winproxy.proxy_restore()


def _by_the_guardian(fake):
    return winproxy.proxy_restore(session_id=SID)


def _by_launch_recovery(fake):
    return winproxy.recover_orphaned_proxy()


@pytest.mark.parametrize("clear, outcome", [
    (_restored, "restored"), (_kept, "kept"), (_already, "already"),
    (_by_the_guardian, "restored"), (_by_launch_recovery, "restored"),
], ids=["restored", "kept", "already", "guardian", "launch-recovery"])
def test_the_net_goes_whenever_the_record_is_cleared(fake_reg, clear, outcome):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    put_runonce(fake_reg, OTHER)
    winproxy.proxy_enable(ADDR, session_id=SID)
    assert len(net(fake_reg)) == 2
    mark = len(fake_reg.ops)
    assert clear(fake_reg) == outcome
    assert net(fake_reg) == {}
    assert fake_reg.record() is None
    assert fake_reg.runonce() == {OTHER[0]: (OTHER[1], REG_SZ)}
    # The net goes before the record: an interruption in between can then
    # only leave a record, which recovery checks against the footprint, and
    # never a blind restore with no record.
    ops = fake_reg.ops[mark:]
    last_net = max(i for i, op in enumerate(ops) if op[1] == RUNONCE)
    first_record = min(i for i, op in enumerate(ops) if op[1] == REC)
    assert last_net < first_record


@pytest.mark.parametrize("record", [None, "incomplete"])
def test_launch_recovery_removes_a_net_with_no_record(fake_reg, record):
    stale_net(fake_reg)
    if record == "incomplete":
        fake_reg.put(RESTORE_KEY, "ProxyEnable", 0, REG_DWORD)  # no Complete
    assert winproxy.recover_orphaned_proxy() is None
    assert net(fake_reg) == {}
    assert fake_reg.runonce() == {OTHER[0]: (OTHER[1], REG_SZ)}
    assert fake_reg.ie_writes() == []  # and nothing else is touched


def test_launch_recovery_with_no_runonce_key_at_all(fake_reg):
    assert winproxy.recover_orphaned_proxy() is None
    assert fake_reg.runonce() is None  # never created just to look into it


@pytest.mark.parametrize("op", [lambda: winproxy.proxy_restore(),
                                lambda: winproxy.recover_orphaned_proxy()],
                         ids=["restore", "recover"])
def test_a_record_that_cannot_be_restored_keeps_its_net(fake_reg, op):
    winproxy.proxy_enable(ADDR)
    before = net(fake_reg)
    fake_reg.fail.add(("OpenKey", IE))     # the live state can't be read
    assert op() is None
    assert fake_reg.record() is not None
    assert net(fake_reg) == before


def test_another_sessions_record_keeps_its_net(fake_reg):
    winproxy.proxy_enable(ADDR, session_id=SID)
    before = net(fake_reg)
    assert winproxy.proxy_restore(session_id="fedcba9876543210") == "not-ours"
    assert net(fake_reg) == before


@pytest.mark.parametrize("old, new", [(None, URL), (URL, None)], ids=["to-safe", "to-compat"])
def test_a_mode_switch(fake_reg, old, new):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=old)
    winproxy.proxy_enable(ADDR2, pac_url=new)
    if new is None:
        assert net(fake_reg) == {"SNIperRestoreProxyEnable": enable_cmd(1),
                                 "SNIperRestoreProxyServer": sz_cmd("ProxyServer", "corp:8080")}
    else:
        assert net(fake_reg) == {}


# ── The kill switch ──────────────────────────────────────────────────────────
def test_the_kill_switch_writes_nothing_but_still_removes_stale_values(fake_reg, monkeypatch):
    monkeypatch.setattr(winproxy, "RUNONCE_SAFETY_NET", False)
    stale_net(fake_reg)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.live() == (1, ADDR, ABSENT)     # Compatibility mode still works
    assert net(fake_reg) == {}
    assert not [op for op in fake_reg.ops if op[0] == "SetValueEx" and op[1] == RUNONCE]
    stale_net(fake_reg)
    winproxy.proxy_restore()
    assert net(fake_reg) == {}
    stale_net(fake_reg)
    winproxy.recover_orphaned_proxy()
    assert net(fake_reg) == {}


# ── Order, lock and failures ─────────────────────────────────────────────────
def test_write_order_record_then_live_then_net(fake_reg):
    fake_reg.set_live(0, "", CORP_PAC)
    winproxy.proxy_enable(ADDR)
    sets = [(op[1], op[2]) for op in fake_reg.ops if op[0] == "SetValueEx"]
    complete = sets.index((REC, "Complete"))
    live = [i for i, (path, _) in enumerate(sets) if path == IE]
    nets = [i for i, (path, _) in enumerate(sets) if path == RUNONCE]
    assert complete < min(live) and max(live) < min(nets)
    assert [sets[i][1] for i in nets] == ["SNIperRestoreProxyEnable",
                                          "SNIperRestoreProxyServer",
                                          "SNIperRestoreAutoConfigURL"]
    # One refresh, after everything (the net included), in one lock hold.
    assert fake_reg.refresh_calls == [len(fake_reg.ops)]
    assert len(fake_reg.lock_spans) == 1
    start, end = fake_reg.lock_spans[0]
    runonce_calls = [i for i, c in enumerate(fake_reg.calls) if c[1] == RUNONCE]
    assert runonce_calls and all(start <= i < end for i in runonce_calls)


@pytest.mark.parametrize("op", [
    lambda: winproxy.proxy_enable(ADDR, pac_url=URL),
    lambda: winproxy.recover_orphaned_proxy(),
], ids=["safe-enable", "recover-no-record"])
def test_removing_a_stale_net_runs_under_the_state_lock(fake_reg, op):
    stale_net(fake_reg)
    op()
    assert len(fake_reg.lock_spans) == 1
    start, end = fake_reg.lock_spans[0]
    runonce_calls = [i for i, c in enumerate(fake_reg.calls) if c[1] == RUNONCE]
    assert runonce_calls and all(start <= i < end for i in runonce_calls)


@pytest.mark.parametrize("failing", ["CreateKey", "first-write", "second-write"])
def test_a_net_that_cannot_be_written_never_fails_the_apply(fake_reg, monkeypatch, failing):
    fake_reg.set_live(0, "", CORP_PAC)
    if failing == "CreateKey":
        fake_reg.fail.add(("CreateKey", RUNONCE))
    else:
        real_set = fake_reg.SetValueEx
        seen = []

        def set_value(hkey, name, reserved, kind, data):
            if hkey.path == RUNONCE:
                seen.append(name)
                if len(seen) == (1 if failing == "first-write" else 2):
                    raise PermissionError(13, "Access is denied")
            return real_set(hkey, name, reserved, kind, data)
        monkeypatch.setattr(fake_reg, "SetValueEx", set_value)
    log = queue.Queue()
    assert winproxy.proxy_enable(ADDR, log_q=log) == CORP_PAC   # the apply worked
    assert fake_reg.live() == (1, ADDR, "")
    assert fake_reg.record()["Complete"] == 1
    assert fake_reg.refresh_calls                               # and took effect
    assert net(fake_reg) == {}                                  # no half net left
    lines = list(log.queue)
    assert len(lines) == 1 and lines[0][0] == "DEBUG"
    assert lines[0][1].startswith("Sign-in safety net could not be written: ")


def test_gpo_locked_touches_no_runonce_at_all(fake_reg):
    fake_reg.set_gpo_locked(True)
    stale_net(fake_reg)
    before = fake_reg.runonce()
    winproxy.proxy_enable(ADDR)
    assert fake_reg.runonce() == before
    assert not [c for c in fake_reg.calls if c[1] == RUNONCE]


def test_an_unrecordable_value_writes_no_net(fake_reg):
    fake_reg.put(IE_KEY, "ProxyEnable", "x", REG_SZ)
    with pytest.raises(winproxy.UnrecordableProxyValue):
        winproxy.proxy_enable(ADDR)
    assert fake_reg.runonce() is None
    assert fake_reg.record() is None


def test_the_kill_switch_is_on_by_default():
    assert winproxy.RUNONCE_SAFETY_NET is True
    assert winproxy._RUNONCE_PREFIX == "SNIperRestore"
