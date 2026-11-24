"""Tests for safe mode (PAC) in sniper.winproxy, on the fake registry.

Safe mode writes a one-off AutoConfigURL and a manual proxy for the apps that
read nothing else, such as the Discord desktop app's updater: ProxyEnable=1,
ProxyServer=SNIper's address, and a ProxyOverride bypass list that only holds
the user's own entries and local hosts (test_bypass_list.py). While it is
being applied the list is "*", every host, so a SNIper that dies half-way
fails open on its own; the real list goes in last, once the sign-in safety net
is there. After that a dead SNIper needs one of the nets, so what counts is
that every state an interruption can leave is fully undone by each of them.

Its restore judges the script URL, the manual proxy and its bypass list apart.
While our URL is still there it is always removed (it is provably SNIper's);
the manual proxy goes back to its genuine values unless the user changed its
flag or server, the list unless the user changed any of the three, and
anything the user changed is left alone. Records from v1.2.0, whose list was
"*" for good, and from v1.1.7 and before must behave as they always did (the
latter as the characterization tests in test_winproxy.py pin down).
"""
from __future__ import annotations

import copy

import pytest

import sniper.procutil as procutil
import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, IE_KEY, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD,
                        REG_SZ, RESTORE_KEY, RUNONCE_KEY, SNIPER_KEY)
from sniper.pac import bypass_rules
from test_runonce import net, run_net

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
URL2 = "http://127.0.0.1:9999/sniper-fedcba9876543210.pac"
CORP_PAC = "http://corp/p.pac"
SID = "0123456789abcdef"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()
RUNONCE = RUNONCE_KEY.lower()
# Who applied the record (test_winproxy_owner.py covers them).
OWNER_VALUES = ("OwnerPid", "OwnerCreateTime", "SessionId")
# Genuine states as (ProxyEnable, ProxyServer, AutoConfigURL, ProxyOverride).
CLEAN = (0, "", ABSENT, ABSENT)
CORP = (1, "corp:8080", ABSENT, "<local>")
# SNIper's own bypass rules, which are all there is over an absent list.
RULES = ";".join(bypass_rules())
# The same four values once safe mode is applied, over CLEAN, for ADDR and URL...
FOOTPRINT = (1, ADDR, URL, RULES)
# ...and right before its last write, or as v1.2.0 left them.
STAR_FOOTPRINT = (1, ADDR, URL, "*")


def footprint(genuine, addr=ADDR, url=URL):
    """What safe mode leaves live over this genuine state."""
    return (1, addr, url, winproxy._bypass_list(genuine[3]))


def writes(fake, path=None, start=0):
    return [op for op in fake.ops[start:] if path is None or op[1] == path]


def set_state(fake, state):
    """Set all four live values; ABSENT removes one."""
    e, s, a, o = state
    fake.set_live(e, s, a, override=o)


def fail_open(state):
    """True if this live state is harmless with SNIper dead and nothing having
    restored it: no manual proxy that is enabled and names SNIper takes effect
    (a "*" list keeps it from doing so)."""
    e, s, _a, o = state
    return not (e == 1 and s in (ADDR, ADDR2) and o != "*")


class PowerLoss(BaseException):
    """The PC is off: no handler of SNIper's catches this one."""


class PowerCut:
    """Let the next n registry writes through, of any key, and cut the power
    at the one after (writes counts them). What is in the registry then is
    what the next sign-in and the next launch find: writes reach the disk in
    the order they were made."""

    def __init__(self, fake, monkeypatch, n=None):
        self.n = n
        self.writes = 0
        for name in ("SetValueEx", "DeleteValue", "DeleteKey"):
            monkeypatch.setattr(fake, name, self._wrap(getattr(fake, name)))

    def _wrap(self, real):
        def call(*args):
            if self.n is not None and self.writes >= self.n:
                raise PowerLoss()
            self.writes += 1
            return real(*args)
        return call


def reset(fake, keys):
    """Put the fake registry back to a copy of these contents."""
    fake.keys.clear()
    fake.keys.update(copy.deepcopy(keys))


def after_sign_in(fake):
    """The live values once Windows has run what RunOnce holds; fake itself is
    left as it was."""
    before = copy.deepcopy(fake.keys)
    run_net(fake)
    live = fake.live_all()
    reset(fake, before)
    return live


class FailIEWritesAfter:
    """Let the next n live Internet Settings writes or deletes through, then
    fail every one after them as an access-denied key would, until stop().
    done names the values that got through.

    Patched on the fake instance with the test's monkeypatch, and never
    undone by hand: undoing that monkeypatch would also undo the fake_reg
    fixture and point winproxy at the real registry."""

    def __init__(self, fake, monkeypatch, n):
        self.n = n
        self.done = []
        for name in ("SetValueEx", "DeleteValue"):
            monkeypatch.setattr(fake, name, self._wrap(getattr(fake, name)))

    def _wrap(self, real):
        def call(hkey, *args):
            if hkey.path == IE and self.n is not None:
                if len(self.done) >= self.n:
                    raise PermissionError(13, "Access is denied")
                self.done.append(args[0])
            return real(hkey, *args)
        return call

    def stop(self):
        self.n = None


def v117_record(fake, enable, server, pac=ABSENT, applied=ADDR):
    """A record exactly as v1.1.7 wrote it: a footprint, but no AppliedMode.
    applied=None makes it a legacy (pre-footprint) record."""
    fake.put(RESTORE_KEY, "ProxyEnable", enable, REG_DWORD)
    fake.put(RESTORE_KEY, "ProxyServer", server, REG_SZ)
    if pac is ABSENT:
        fake.put(RESTORE_KEY, "AutoConfigURLPresent", 0, REG_DWORD)
    else:
        fake.put(RESTORE_KEY, "AutoConfigURLPresent", 1, REG_DWORD)
        fake.put(RESTORE_KEY, "AutoConfigURL", pac, REG_SZ)
    if applied is not None:
        fake.put(RESTORE_KEY, "AppliedProxyServer", applied, REG_SZ)
    fake.put(RESTORE_KEY, "Complete", 1, REG_DWORD)


def v120_record(fake, genuine):
    """A safe-mode record exactly as v1.2.0 wrote it, with its footprint live:
    the manual proxy's bypass list was always "*", so the record doesn't name
    it (no AppliedProxyOverride)."""
    e, s, a, o = genuine
    v117_record(fake, e, s, a)
    for name, data, kind in (("AppliedMode", "pac", REG_SZ),
                             ("AppliedAutoConfigURL", URL, REG_SZ),
                             ("ProxyOverridePresent", int(o is not ABSENT), REG_DWORD),
                             ("AppliedManualProxy", 1, REG_DWORD),
                             ("OwnerPid", 4242, REG_DWORD),
                             ("OwnerCreateTime", 133_700_000_000_000_000, REG_QWORD),
                             ("SessionId", SID, REG_SZ)):
        fake.put(RESTORE_KEY, name, data, kind)
    if o is not ABSENT:
        fake.put(RESTORE_KEY, "ProxyOverride", o, REG_SZ)
    set_state(fake, STAR_FOOTPRINT)


def early_pac_record(fake, enable, server, pac=ABSENT, url=URL):
    """A safe-mode record as v1.2.0 wrote it before the manual proxy: the
    script URL and ProxyEnable=0 were the whole footprint, so it holds no
    ProxyOverride and no AppliedManualProxy."""
    v117_record(fake, enable, server, pac)
    fake.put(RESTORE_KEY, "AppliedMode", "pac", REG_SZ)
    fake.put(RESTORE_KEY, "AppliedAutoConfigURL", url, REG_SZ)


# ── Enable ───────────────────────────────────────────────────────────────────
def test_enable_from_clean_state(fake_reg):
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.live_all() == FOOTPRINT
    rec = fake_reg.record(types=True)
    owner = {name: rec.pop(name) for name in OWNER_VALUES}
    assert [kind for _, kind in owner.values()] == [REG_DWORD, REG_QWORD, REG_SZ]
    assert rec == {
        "ProxyEnable": (0, REG_DWORD),
        "ProxyServer": ("", REG_SZ),
        "AutoConfigURLPresent": (0, REG_DWORD),
        "AppliedProxyServer": (ADDR, REG_SZ),
        "AppliedMode": ("pac", REG_SZ),
        "AppliedAutoConfigURL": (URL, REG_SZ),
        "ProxyOverridePresent": (0, REG_DWORD),
        "AppliedManualProxy": (1, REG_DWORD),
        "AppliedProxyOverride": (RULES, REG_SZ),
        "Complete": (1, REG_DWORD),
    }
    assert fake_reg.value(IE_KEY, "ProxyEnable") == (1, REG_DWORD)
    assert fake_reg.value(IE_KEY, "ProxyOverride") == (RULES, REG_SZ)


def test_the_list_goes_live_last_after_the_net(fake_reg, monkeypatch):
    written = []
    real = fake_reg.SetValueEx

    def spy(hkey, name, reserved, kind, data):
        written.append((hkey.path, name, data))
        return real(hkey, name, reserved, kind, data)

    monkeypatch.setattr(fake_reg, "SetValueEx", spy)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    # The record is committed (Complete last) before anything else.
    record = [w for w in written if w[0] == REC]
    assert written[:len(record)] == record and record[-1] == (REC, "Complete", 1)
    # Then the live values: the bypass list first, still "*", then the server,
    # our URL and the enable flag, so the manual proxy is never on without it.
    rest = written[len(record):]
    assert rest[:4] == [(IE, "ProxyOverride", "*"), (IE, "ProxyServer", ADDR),
                        (IE, "AutoConfigURL", URL), (IE, "ProxyEnable", 1)]
    # Then the whole sign-in net, and last of all the list that puts the
    # manual proxy into effect.
    assert [w[:2] for w in rest[4:-1]] == [
        (RUNONCE, "SNIperRestore" + name)
        for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride")]
    assert rest[-1] == (IE, "ProxyOverride", RULES)
    # One refresh, after everything.
    assert fake_reg.refresh_calls == [len(fake_reg.ops)]


@pytest.mark.parametrize("genuine", [
    CLEAN, CORP, (0, "corp:8080", CORP_PAC, ABSENT), (1, "corp:8080", "", ""),
    (0, "127.0.0.1:8881", ABSENT, ABSENT), (1, "corp:8080", ABSENT, "*.corp;<local>"),
    (0, "", ABSENT, "*"), (1, ADDR, ABSENT, "*"), (1, ADDR, ABSENT, RULES),
    (1, "corp:8080", CORP_PAC, "*.corp;*;<local>"),
], ids=["clean", "manual", "pac", "manual-empty-pac-and-list", "old-sniper-server",
        "list", "genuine-bypass-all", "genuine-equals-star-footprint",
        "genuine-equals-footprint", "everything"])
def test_round_trip_puts_every_genuine_value_back(fake_reg, genuine):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert fake_reg.live_all() == footprint(genuine)
    rec = fake_reg.record()
    assert rec["AppliedProxyOverride"] == footprint(genuine)[3]
    # The genuine list is recorded as it was, "*" included, though SNIper's
    # own never holds that.
    assert "*" not in fake_reg.live_all()[3].split(";")
    if genuine[3] is ABSENT:
        assert rec["ProxyOverridePresent"] == 0 and "ProxyOverride" not in rec
    else:
        assert (rec["ProxyOverridePresent"], rec["ProxyOverride"]) == (1, genuine[3])
    assert winproxy.proxy_restore() == "restored"
    # Absent stays absent and empty stays empty, for the script and the list.
    assert fake_reg.live_all() == genuine
    assert fake_reg.record() is None
    assert not fake_reg.exists(SNIPER_KEY)


def test_genuine_pac_is_replaced_and_put_back(fake_reg):
    set_state(fake_reg, (0, "", CORP_PAC, ABSENT))
    # The genuine PAC comes back to the caller, for the "PAC was active" note.
    assert winproxy.proxy_enable(ADDR, pac_url=URL) == CORP_PAC
    assert fake_reg.live_all() == FOOTPRINT
    rec = fake_reg.record()
    assert (rec["AutoConfigURLPresent"], rec["AutoConfigURL"]) == (1, CORP_PAC)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == (0, "", CORP_PAC, ABSENT)


def test_gpo_locked_writes_nothing(fake_reg):
    fake_reg.set_gpo_locked(True)
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert writes(fake_reg) == []
    assert not [c for c in fake_reg.calls if c[0] == "CreateKey"]
    assert fake_reg.refresh_calls == []
    assert fake_reg.live_all() == CLEAN


def test_record_write_failure_never_touches_live(fake_reg):
    fake_reg.fail.add(("SetValueEx", REC))
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.live_all() == CLEAN
    assert writes(fake_reg, IE) == []
    assert winproxy.proxy_restore() is None  # what got written is incomplete


GENUINE_STATES = pytest.mark.parametrize(
    "genuine", [CLEAN, CORP, (0, "corp:8080", CORP_PAC, ""), (0, "", ABSENT, "*"),
                (1, "corp:8080", CORP_PAC, "*.corp;<local>")],
    ids=["clean", "manual", "pac", "bypass-all", "everything"])


@pytest.mark.parametrize("landed", [0, 1, 2, 3, 4])
@GENUINE_STATES
def test_interrupted_apply_fails_open_and_is_fully_undone(fake_reg, monkeypatch,
                                                         genuine, landed):
    # Cut short after `landed` of the five live writes (the record is
    # committed by then), the last of which is the real bypass list: until
    # that one the proxy must be fail-open, and launch recovery must end at
    # the genuine values.
    set_state(fake_reg, genuine)
    cut = FailIEWritesAfter(fake_reg, monkeypatch, landed)
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert len(cut.done) == landed
    assert fake_reg.record()["Complete"] == 1
    assert fail_open(fake_reg.live_all())
    cut.stop()
    expected = "already" if fake_reg.live_all() == genuine else "restored"
    assert winproxy.recover_orphaned_proxy() == expected
    assert fake_reg.live_all() == genuine
    assert fake_reg.record() is None
    assert net(fake_reg) == {}


def count_writes(fake, monkeypatch, operation):
    """How many registry writes operation makes; fake itself is left as it
    was."""
    before = copy.deepcopy(fake.keys)
    with monkeypatch.context() as m:
        counter = PowerCut(fake, m)
        operation()
    reset(fake, before)
    return counter.writes


@GENUINE_STATES
def test_a_power_loss_anywhere_in_an_apply_is_undone(fake_reg, monkeypatch, genuine):
    set_state(fake_reg, genuine)

    def apply():
        winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)

    start = copy.deepcopy(fake_reg.keys)
    total = count_writes(fake_reg, monkeypatch, apply)
    for n in range(total + 1):
        reset(fake_reg, start)
        with monkeypatch.context() as m:
            PowerCut(fake_reg, m, n)
            if n < total:
                with pytest.raises(PowerLoss):
                    apply()
            else:
                apply()
        live = fake_reg.live_all()
        if (fake_reg.record() or {}).get("Complete") != 1:
            assert live == genuine and net(fake_reg) == {}, n
            continue
        # With nothing running at all, apps only lose their connection once
        # the whole net is there to put it right at the next sign-in.
        assert fail_open(live) or len(net(fake_reg)) == 4, n
        signed_in = after_sign_in(fake_reg)
        assert fail_open(signed_in) or signed_in == genuine, n
        if len(net(fake_reg)) == 4:
            assert signed_in == genuine, n
        # And the next launch puts everything back, sign-in or not.
        assert winproxy.recover_orphaned_proxy() in ("restored", "already"), n
        assert fake_reg.live_all() == genuine, n
        assert fake_reg.record() is None and net(fake_reg) == {}, n


@GENUINE_STATES
def test_a_power_loss_anywhere_in_a_restore_is_undone(fake_reg, monkeypatch, genuine):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    start = copy.deepcopy(fake_reg.keys)
    total = count_writes(fake_reg, monkeypatch, winproxy.proxy_restore)
    for n in range(total + 1):
        reset(fake_reg, start)
        with monkeypatch.context() as m:
            PowerCut(fake_reg, m, n)
            if n < total:
                with pytest.raises(PowerLoss):
                    winproxy.proxy_restore()
            else:
                assert winproxy.proxy_restore() == "restored"
        live = fake_reg.live_all()
        # Live values first, then the net, then the record: nothing is taken
        # away before what it would put right is right already.
        assert live == genuine or len(net(fake_reg)) == 4, n
        assert after_sign_in(fake_reg) == genuine, n
        if fake_reg.record() is not None:
            assert winproxy.recover_orphaned_proxy() in ("restored", "already"), n
        assert fake_reg.live_all() == genuine, n
        assert fake_reg.record() is None and net(fake_reg) == {}, n


@pytest.mark.parametrize("live", [STAR_FOOTPRINT, FOOTPRINT], ids=["star", "list"])
def test_the_restore_knows_both_lists_as_its_own(fake_reg, live):
    # The one it applied, and the "*" that held its place until then.
    winproxy.proxy_enable(ADDR, pac_url=URL)
    set_state(fake_reg, live)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CLEAN


def test_a_star_of_the_users_own_comes_back(fake_reg):
    genuine = (0, "", ABSENT, "*")
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert fake_reg.live_all() == FOOTPRINT       # SNIper's list never holds it
    set_state(fake_reg, STAR_FOOTPRINT)           # an apply cut before its last write
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == genuine


@pytest.mark.parametrize("override", [["a", "b"], 7, b"\x01"],
                         ids=["multi-sz", "dword", "binary"])
def test_enable_refuses_a_bypass_list_it_cannot_record(fake_reg, override):
    kind = {list: REG_MULTI_SZ, int: REG_DWORD, bytes: REG_BINARY}[type(override)]
    fake_reg.put(IE_KEY, "ProxyOverride", override, kind)
    with pytest.raises(winproxy.UnrecordableProxyValue) as exc:
        winproxy.proxy_enable(ADDR, pac_url=URL)
    assert "ProxyOverride" in str(exc.value)
    assert writes(fake_reg) == []
    assert fake_reg.record() is None
    # Compatibility mode never writes the bypass list, so it doesn't mind.
    winproxy.proxy_enable(ADDR)
    assert fake_reg.live() == (1, ADDR, ABSENT)
    assert fake_reg.value(IE_KEY, "ProxyOverride") == (override, kind)


@pytest.mark.parametrize("data, kind", [(7, REG_DWORD), (["a"], REG_MULTI_SZ)],
                         ids=["dword", "multi-sz"])
def test_unwritable_recorded_bypass_list_reads_as_empty(fake_reg, data, kind):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.put(RESTORE_KEY, "ProxyOverride", data, kind)
    base = winproxy._read_baseline()
    assert (base.override_present, base.override) == (True, "")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.value(IE_KEY, "ProxyOverride") == ("", REG_SZ)
    assert fake_reg.live_all() == CORP[:3] + ("",)


# ── Re-enable while a record exists ──────────────────────────────────────────
def test_reenable_same_session_writes_no_record(fake_reg):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    record = fake_reg.record()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID) is None
    assert writes(fake_reg, REC, mark) == []
    assert fake_reg.record() == record
    assert fake_reg.live_all() == footprint(CORP)


def test_reenable_with_a_new_url_keeps_genuine_and_updates_footprint(fake_reg):
    genuine = (1, "corp:8080", CORP_PAC, "<local>")
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    # The live values now look like SNIper's; they must never be captured.
    assert winproxy.proxy_enable(ADDR2, pac_url=URL2) == CORP_PAC
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AutoConfigURL"],
            rec["ProxyOverride"]) == (1, "corp:8080", CORP_PAC, "<local>")
    assert (rec["AppliedProxyServer"], rec["AppliedAutoConfigURL"]) == (ADDR2, URL2)
    assert fake_reg.live_all() == footprint(genuine, ADDR2, URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == genuine


def test_reenable_goes_through_the_star_again(fake_reg, monkeypatch):
    # A re-apply swaps the list back to "*" before anything else, so the
    # window in which the net is rewritten is fail-open as well.
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    seen = []
    real = winproxy._write_runonce
    monkeypatch.setattr(winproxy, "_write_runonce", lambda *a, **k: (
        seen.append(fake_reg.live_all()), real(*a, **k)))
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    assert seen == [STAR_FOOTPRINT]
    assert fake_reg.live_all() == FOOTPRINT


# ── Restore ──────────────────────────────────────────────────────────────────
def test_restore_untouched_writes_back_in_order(fake_reg):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CORP
    # The flag first (here already genuine, so not written), the bypass list
    # after the server, and our URL last, where a retry finds it.
    assert writes(fake_reg, IE, mark) == [("SetValueEx", IE, "ProxyServer"),
                                          ("SetValueEx", IE, "ProxyOverride"),
                                          ("DeleteValue", IE, "AutoConfigURL")]
    assert fake_reg.record() is None
    assert not fake_reg.exists(SNIPER_KEY)
    assert len(fake_reg.refresh_calls) == 1


def test_restore_from_clean_deletes_what_was_absent(fake_reg):
    winproxy.proxy_enable(ADDR, pac_url=URL)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "restored"
    assert writes(fake_reg, IE, mark) == [("SetValueEx", IE, "ProxyEnable"),
                                          ("SetValueEx", IE, "ProxyServer"),
                                          ("DeleteValue", IE, "ProxyOverride"),
                                          ("DeleteValue", IE, "AutoConfigURL")]
    assert fake_reg.live_all() == (0, "", ABSENT, ABSENT)


@pytest.mark.parametrize("url", ["http://user/x.pac", "", URL2, URL.upper(), ABSENT],
                         ids=["replaced", "emptied", "other-session", "case", "deleted"])
def test_user_took_the_url_so_it_stays_and_the_manual_proxy_goes(fake_reg, url):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    e, s, _, o = footprint(CORP)
    set_state(fake_reg, (e, s, url, o))
    mark = len(fake_reg.ops)
    # Deleting our URL where there was no genuine script is no change of the
    # user's: that is the genuine state.
    assert winproxy.proxy_restore() == ("restored" if url is ABSENT else "kept")
    assert fake_reg.live_all() == (1, "corp:8080", url, "<local>")
    assert "AutoConfigURL" not in [op[2] for op in writes(fake_reg, IE, mark)]
    assert fake_reg.record() is None


@pytest.mark.parametrize("manual", [
    (0, ADDR, RULES),                  # proxy switched off
    (1, "user:3128", RULES),           # another server
    (1, "user:3128", "*.user"),        # another server, with a list of its own
    (0, "", ABSENT),                   # all of it, by hand
    ("garbage", ADDR, RULES),          # a flag nobody can read as a number
], ids=["flag", "server", "server-and-list", "everything", "unreadable-flag"])
def test_user_changed_the_manual_proxy_so_it_stays_and_the_url_goes(fake_reg, manual):
    # Each change differs from the genuine CORP values as well as from
    # SNIper's: a value set back to the genuine one is no change of the user's.
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    e, s, o = manual
    set_state(fake_reg, (e, s, URL, o))
    if isinstance(e, str):
        fake_reg.put(IE_KEY, "ProxyEnable", e, REG_SZ)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    # Only our URL was touched; the user's manual proxy was not written.
    assert writes(fake_reg, IE, mark) == [("DeleteValue", IE, "AutoConfigURL")]
    assert fake_reg.live_all() == (e, s, ABSENT, o)
    assert len(fake_reg.refresh_calls) == 1
    assert fake_reg.record() is None


@pytest.mark.parametrize("edited", ["*.user;<local>", RULES + ";*.user", "", ABSENT],
                         ids=["replaced", "added-to", "emptied", "removed"])
@pytest.mark.parametrize("genuine", [CORP, (0, ADDR, ABSENT, "<local>")],
                         ids=["manual", "old-sniper-server"])
def test_user_edited_only_the_bypass_list_so_only_that_stays(fake_reg, genuine, edited):
    # E.g. an exception added in Windows' proxy settings while SNIper runs.
    # The list is theirs now, but the proxy it goes with is still SNIper's own:
    # left enabled it would keep every app on a port nobody answers any more.
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    set_state(fake_reg, (1, ADDR, URL, edited))
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live_all() == genuine[:3] + (edited,)
    assert "ProxyOverride" not in [op[2] for op in writes(fake_reg, IE, mark)]
    assert fake_reg.record() is None and net(fake_reg) == {}


def test_user_changed_both_parts_nothing_is_written(fake_reg):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    changed = (1, "other:3128", "http://user/x.pac", "*")
    set_state(fake_reg, changed)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert writes(fake_reg, IE, mark) == []
    assert fake_reg.refresh_calls == []
    assert fake_reg.live_all() == changed


@pytest.mark.parametrize("genuine", [
    CLEAN, (0, "", CORP_PAC, ABSENT), CORP, (0, "corp:8080", "", ""),
], ids=["clean", "pac", "manual", "empty-pac-and-list"])
def test_everything_back_to_genuine_is_already(fake_reg, genuine):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    set_state(fake_reg, genuine)  # someone else undid safe mode exactly
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "already"
    assert fake_reg.live_all() == genuine
    assert writes(fake_reg, IE, mark) == []
    assert fake_reg.refresh_calls == []
    assert fake_reg.record() is None


@pytest.mark.parametrize("failing", [
    ("SetValueEx", IE), ("DeleteValue", IE), ("OpenKey", IE), "QueryValueEx",
], ids=["write", "delete", "open", "read"])
def test_restore_failure_keeps_the_record_for_a_retry(fake_reg, failing):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    record = fake_reg.record()
    fake_reg.fail.add(failing)
    assert winproxy.proxy_restore() is None
    fake_reg.fail.clear()
    assert fake_reg.record() == record
    assert fake_reg.live()[2] == URL  # our URL is still there to find
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CORP
    assert fake_reg.record() is None


@pytest.mark.parametrize("genuine, landed", [
    (CLEAN, 0), (CLEAN, 1), (CLEAN, 2), (CLEAN, 3),
    # The genuine flag is SNIper's 1 too, so this restore writes only three.
    (CORP, 0), (CORP, 1), (CORP, 2),
], ids=["clean-0", "clean-1", "clean-2", "clean-3", "manual-0", "manual-1", "manual-2"])
def test_interrupted_restore_is_finished_by_the_retry(fake_reg, monkeypatch, genuine,
                                                     landed):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    cut = FailIEWritesAfter(fake_reg, monkeypatch, landed)
    assert winproxy.proxy_restore() is None
    assert len(cut.done) == landed
    # The very first write takes SNIper's proxy out of effect; until then the
    # record and the net are there as they were.
    assert fail_open(fake_reg.live_all()) == (landed > 0)
    assert fake_reg.record()["Complete"] == 1
    assert len(net(fake_reg)) == 4
    assert after_sign_in(fake_reg) == genuine
    cut.stop()
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live_all() == genuine
    assert fake_reg.record() is None


def test_recover_after_enable_without_stop(fake_reg):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live_all() == CORP
    assert winproxy.recover_orphaned_proxy() is None  # and nothing left


@pytest.mark.parametrize("live, expected, after", [
    (CLEAN, "already", CLEAN),
    # Our URL can't be proven ours without the record's copy, so it stays;
    # the manual proxy is still exactly SNIper's and goes.
    (FOOTPRINT, "kept", (0, "", URL, ABSENT)),
    (STAR_FOOTPRINT, "kept", (0, "", URL, ABSENT)),
], ids=["clean", "footprint", "star"])
def test_pac_record_without_its_url_never_writes_the_url(fake_reg, live, expected,
                                                         after):
    winproxy.proxy_enable(ADDR, pac_url=URL)
    k = fake_reg.keys[REC]
    del k["appliedautoconfigurl"]
    set_state(fake_reg, live)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == expected
    assert "AutoConfigURL" not in [op[2] for op in writes(fake_reg, IE, mark)]
    assert fake_reg.live_all() == after


def test_unknown_mode_reads_as_static(fake_reg):
    winproxy.proxy_enable(ADDR)  # static footprint
    fake_reg.put(RESTORE_KEY, "AppliedMode", "future-mode", REG_SZ)
    assert winproxy._read_baseline().applied_mode == "static"
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)


def test_baseline_shape(fake_reg):
    set_state(fake_reg, (1, "corp:8080", CORP_PAC, "<local>"))
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    pid, created = procutil.process_identity()
    assert winproxy._read_baseline() == winproxy.Baseline(
        enable=1, server="corp:8080", pac_present=True, pac=CORP_PAC,
        applied_server=ADDR, applied_mode="pac", applied_pac_url=URL,
        owner_pid=pid, owner_create_time=created, session_id=SID,
        override_present=True, override="<local>", applied_manual=True,
        applied_override=winproxy._bypass_list("<local>"))
    winproxy.proxy_restore()
    winproxy.proxy_enable(ADDR)
    base = winproxy._read_baseline()
    assert (base.applied_mode, base.applied_pac_url) == ("static", None)
    assert (base.override_present, base.override, base.applied_manual,
            base.applied_override) == (None, None, False, None)
    rec = fake_reg.record()
    assert not {"ProxyOverridePresent", "ProxyOverride", "AppliedManualProxy",
                "AppliedProxyOverride"} & set(rec)


def test_baseline_defaults_keep_old_call_sites_working():
    base = winproxy.Baseline(1, "corp:8080", False, None, ADDR, "static", None,
                             None, None, None)
    assert (base.override_present, base.override, base.applied_manual,
            base.applied_override) == (None, None, False, None)


# ── v1.2.0 records: the bypass list was "*" for good ─────────────────────────
@GENUINE_STATES
def test_a_v120_record_restores_as_v120_did(fake_reg, genuine):
    v120_record(fake_reg, genuine)
    base = winproxy._read_baseline()
    assert (base.applied_manual, base.applied_override) == (True, "*")
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live_all() == genuine
    assert fake_reg.record() is None


@pytest.mark.parametrize("live, expected, after", [
    # The user's own proxy, setup script or switched-off flag stays.
    ((1, "user:3128", URL, "*"), "kept", (1, "user:3128", ABSENT, "*")),
    ((0, ADDR, URL, "*"), "kept", (0, ADDR, ABSENT, "*")),
    ((1, ADDR, "http://user/x.pac", "*"), "kept", CORP[:2] + ("http://user/x.pac", "<local>")),
    # Someone else already undid it.
    (CORP, "already", CORP),
    # A list that v1.2.0 never wrote is the user's, SNIper's own new one too.
    ((1, ADDR, URL, "*.user"), "kept", CORP[:3] + ("*.user",)),
    ((1, ADDR, URL, RULES), "kept", CORP[:3] + (RULES,)),
], ids=["server", "flag", "script", "already", "list", "new-list"])
def test_a_v120_record_after_a_change(fake_reg, live, expected, after):
    v120_record(fake_reg, CORP)
    set_state(fake_reg, live)
    assert winproxy.proxy_restore() == expected
    assert fake_reg.live_all() == after
    assert fake_reg.record() is None


def test_a_v120_record_is_upgraded_by_a_new_safe_session(fake_reg):
    # It could not be restored at launch, say; the new session takes it over.
    v120_record(fake_reg, CORP)
    winproxy.proxy_enable(ADDR2, pac_url=URL2)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["ProxyOverride"]) == \
        (1, "corp:8080", "<local>")          # genuine, never the footprint
    assert rec["AppliedProxyOverride"] == footprint(CORP)[3]
    assert fake_reg.live_all() == footprint(CORP, ADDR2, URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CORP


def test_the_same_session_upgrades_a_v120_record_too(fake_reg, monkeypatch):
    # Nothing but the list differs, and that alone rewrites the record.
    monkeypatch.setattr(procutil, "process_identity",
                        lambda pid=None: (4242, 133_700_000_000_000_000))
    v120_record(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    assert fake_reg.record()["AppliedProxyOverride"] == footprint(CORP)[3]
    assert winproxy.proxy_restore(session_id=SID) == "restored"
    assert fake_reg.live_all() == CORP


@pytest.mark.parametrize("data, kind", [(7, REG_DWORD), (["a"], REG_MULTI_SZ),
                                        (b"\x01", REG_BINARY)],
                         ids=["dword", "multi-sz", "binary"])
def test_an_applied_list_that_is_no_string_reads_as_a_star(fake_reg, data, kind):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.put(RESTORE_KEY, "AppliedProxyOverride", data, kind)
    assert winproxy._read_baseline().applied_override == "*"
    # The live list can't be proven SNIper's then, so it stays; the proxy,
    # which can, goes all the same.
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live_all() == CORP[:3] + footprint(CORP)[3:]


# ── Records from before the manual proxy ─────────────────────────────────────
@pytest.mark.parametrize("live, expected, after", [
    # Untouched: the flag and the URL go back; ProxyServer and ProxyOverride
    # were never written, so they stay.
    ((0, "corp:8080", URL, "<local>"), "restored", (1, "corp:8080", ABSENT, "<local>")),
    # The user switched a manual proxy on: it stays, our URL goes.
    ((1, "user:3128", URL, "<local>"), "kept", (1, "user:3128", ABSENT, "<local>")),
    # Someone else already undid it.
    ((1, "corp:8080", ABSENT, "<local>"), "already", (1, "corp:8080", ABSENT, "<local>")),
], ids=["untouched", "user-enabled", "already"])
def test_early_pac_record_restores_its_own_footprint(fake_reg, live, expected, after):
    early_pac_record(fake_reg, 1, "corp:8080")
    set_state(fake_reg, live)
    base = winproxy._read_baseline()
    assert (base.applied_manual, base.override_present) == (False, None)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == expected
    assert fake_reg.live_all() == after
    assert "ProxyOverride" not in [op[2] for op in writes(fake_reg, IE, mark)]
    assert fake_reg.record() is None


def test_early_pac_record_is_upgraded_by_a_new_safe_session(fake_reg):
    # The live bypass list is still the genuine one (the early footprint
    # never wrote it), so it is recorded before anything of SNIper's goes in.
    early_pac_record(fake_reg, 1, "corp:8080")
    set_state(fake_reg, (0, "corp:8080", URL, "<local>"))
    winproxy.proxy_enable(ADDR2, pac_url=URL2)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "corp:8080")
    assert (rec["ProxyOverridePresent"], rec["ProxyOverride"]) == (1, "<local>")
    assert (rec["AppliedManualProxy"], rec["AppliedProxyOverride"]) == \
        (1, footprint(CORP)[3])
    assert fake_reg.live_all() == footprint(CORP, ADDR2, URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == (1, "corp:8080", ABSENT, "<local>")


# ── Mode switch with a leftover record ───────────────────────────────────────
@pytest.mark.parametrize("make_record", ["new-static", "v117", "legacy"])
def test_static_record_is_restored_before_a_pac_session(fake_reg, make_record):
    set_state(fake_reg, CORP)
    if make_record == "new-static":
        winproxy.proxy_enable(ADDR)
    else:
        v117_record(fake_reg, 1, "corp:8080",
                    applied=ADDR if make_record == "v117" else None)
        fake_reg.set_live(1, ADDR, ABSENT)
    assert fake_reg.live() == (1, ADDR, ABSENT)  # the stranded static footprint
    assert winproxy.proxy_enable(ADDR2, pac_url=URL2) is None
    # Restored first, then captured afresh: the genuine values are corp's.
    assert fake_reg.live_all() == footprint(CORP, ADDR2, URL2)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["ProxyOverride"]) == \
        (1, "corp:8080", "<local>")
    assert (rec["AppliedMode"], rec["AppliedAutoConfigURL"]) == ("pac", URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CORP


def test_static_record_the_user_changed_is_released_before_a_pac_session(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.set_live(1, "user:3128", ABSENT)  # the user took over
    winproxy.proxy_enable(ADDR2, pac_url=URL2)
    rec = fake_reg.record()
    # The user's values are the genuine ones now.
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "user:3128")
    winproxy.proxy_restore()
    assert fake_reg.live_all() == (1, "user:3128", ABSENT, ABSENT)


@pytest.mark.parametrize("make_record", ["new", "new-cut-short", "v120"])
def test_pac_record_is_restored_before_a_static_session(fake_reg, make_record):
    set_state(fake_reg, CORP)
    if make_record == "v120":
        v120_record(fake_reg, CORP)
    else:
        winproxy.proxy_enable(ADDR, pac_url=URL)
        if make_record == "new-cut-short":
            set_state(fake_reg, STAR_FOOTPRINT)
    assert winproxy.proxy_enable(ADDR2) is None
    # Our dead URL and our bypass list are gone: a stale URL would make the
    # static footprint check fail at Stop and strand the static proxy, and
    # "*" would send every host past it.
    assert fake_reg.live_all() == (1, ADDR2, ABSENT, "<local>")
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AppliedMode"]) == \
        (1, "corp:8080", "static")
    assert "AppliedAutoConfigURL" not in rec
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == CORP


@pytest.mark.parametrize("old_mode", ["static", "pac", "pac-cut-short", "pac-v120"])
def test_mode_switch_when_the_old_restore_cannot_act(fake_reg, monkeypatch, old_mode):
    # The leftover record could not be restored (say its live write failed):
    # its genuine values are still the only genuine ones, so they are kept and
    # the record is taken over for the new mode.
    genuine = (1, "corp:8080", CORP_PAC, "<local>")
    set_state(fake_reg, genuine)
    if old_mode == "pac-v120":
        v120_record(fake_reg, genuine)
    else:
        winproxy.proxy_enable(ADDR, pac_url=None if old_mode == "static" else URL)
        if old_mode == "pac-cut-short":
            set_state(fake_reg, STAR_FOOTPRINT)
    monkeypatch.setattr(winproxy, "_restore_static", lambda base: None)
    monkeypatch.setattr(winproxy, "_restore_pac", lambda base: None)
    new_url = URL2 if old_mode == "static" else None
    assert winproxy.proxy_enable(ADDR2, pac_url=new_url) == CORP_PAC
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AutoConfigURL"]) == \
        (1, "corp:8080", CORP_PAC)
    assert rec["AppliedMode"] == ("pac" if new_url else "static")
    assert rec["AppliedProxyServer"] == ADDR2
    assert rec.get("AppliedAutoConfigURL") == new_url
    assert rec["Complete"] == 1
    if new_url is None:
        # The safe-mode bypass list the static footprint doesn't cover went
        # back before the record forgot it.
        assert fake_reg.value(IE_KEY, "ProxyOverride") == ("<local>", REG_SZ)
        assert not {"ProxyOverride", "AppliedProxyOverride"} & set(rec)
    else:
        assert rec["ProxyOverride"] == "<local>"
        assert fake_reg.live_all() == footprint(genuine, ADDR2, URL2)


def test_mode_switch_never_puts_back_a_list_the_user_changed(fake_reg, monkeypatch):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    set_state(fake_reg, (1, ADDR, URL, "*.user"))
    monkeypatch.setattr(winproxy, "_restore_pac", lambda base: None)
    winproxy.proxy_enable(ADDR2)
    assert fake_reg.value(IE_KEY, "ProxyOverride") == ("*.user", REG_SZ)


# ── Records from earlier versions behave exactly as before ──────────────────
def _scenario(fake, kind):
    """Set up a v1.1.7 record (by hand) or a new static record (through
    proxy_enable) for the same situation."""
    def setup(record):
        fake.keys.clear()
        fake.set_live(1, "corp:8080", CORP_PAC)
        if record == "new":
            winproxy.proxy_enable(ADDR)
        else:
            v117_record(fake, 1, "corp:8080", CORP_PAC)
            fake.set_live(1, ADDR, "")
        if kind == "kept":
            fake.set_live(1, "user:3128", "")
        elif kind == "pac-added":
            fake.set_live(1, ADDR, "http://user/x.pac")
    return setup


@pytest.mark.parametrize("kind", ["restored", "kept", "pac-added"])
def test_v117_record_restores_like_a_new_static_record(fake_reg, kind):
    setup = _scenario(fake_reg, kind)

    def run(record):
        setup(record)
        mark = len(fake_reg.ops)
        result = winproxy.proxy_restore()
        return result, fake_reg.live(), fake_reg.record(), writes(fake_reg, start=mark)

    v117, new = run("v117"), run("new")
    # A new static record also has the RunOnce safety net (Step 4), which its
    # clear removes (test_runonce.py); a v1.1.7 record never had one. Apart
    # from deleting the net, the restore is the same, write for write.
    net = [op for op in new[3] if op[1] == RUNONCE_KEY.lower()]
    assert net and all(op[0] == "DeleteValue" for op in net)
    assert v117[:3] == new[:3]
    assert v117[3] == [op for op in new[3] if op not in net]
    assert v117[0] == ("restored" if kind == "restored" else "kept")


def test_legacy_record_is_still_restored_unconditionally(fake_reg):
    v117_record(fake_reg, 1, "corp:8080", applied=None)
    fake_reg.set_live(0, "someone:1", URL)  # even with a PAC URL in place
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)


# ── The WinINet refresh ──────────────────────────────────────────────────────
def test_refresh_calls_both_options_through_the_bound_function(monkeypatch):
    calls = []
    monkeypatch.setattr(winproxy, "IS_WINDOWS", True)
    monkeypatch.setattr(winproxy, "_internet_set_option",
                        lambda *args: calls.append(args) or 1)
    winproxy._refresh()
    assert calls == [(None, 39, None, 0), (None, 37, None, 0)]


def test_refresh_never_raises(monkeypatch):
    def boom(*args):
        raise OSError("wininet missing")
    monkeypatch.setattr(winproxy, "IS_WINDOWS", True)
    monkeypatch.setattr(winproxy, "_internet_set_option", boom)
    winproxy._refresh()


@pytest.mark.skipif(not winproxy.IS_WINDOWS, reason="wininet is Windows-only")
def test_internet_set_option_is_fully_bound(monkeypatch):
    import ctypes
    monkeypatch.setattr(winproxy, "_internet_set_option", None)
    fn = winproxy._bind_internet_set_option()  # binds, never calls
    assert fn.argtypes == [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    assert fn.restype is ctypes.c_int
    # A private binding: the shared ctypes.windll.wininet is left alone.
    assert fn is not ctypes.windll.wininet.InternetSetOptionW
