"""Tests for safe mode (PAC) in sniper.winproxy, on the fake registry.

Safe mode writes a one-off AutoConfigURL and a manual proxy that bypasses
every host: ProxyEnable=1, ProxyServer=SNIper's address, ProxyOverride="*".
The manual proxy is for apps that read only ProxyEnable/ProxyServer, such as
the Discord desktop app's updater; the bypass list keeps it fail-open for
everything that follows the script or the list.

Its restore judges the script URL and the manual proxy apart. While our URL is
still there it is always removed (it is provably SNIper's); the manual proxy
goes back to its genuine values unless the user changed any of them, and
anything the user changed is left alone. Records from v1.1.7 and before must
behave exactly as the characterization tests in test_winproxy.py pin down.
"""
from __future__ import annotations

import pytest

import sniper.procutil as procutil
import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, IE_KEY, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD,
                        REG_SZ, RESTORE_KEY, RUNONCE_KEY, SNIPER_KEY)

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
URL2 = "http://127.0.0.1:9999/sniper-fedcba9876543210.pac"
CORP_PAC = "http://corp/p.pac"
SID = "0123456789abcdef"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()
# Who applied the record (test_winproxy_owner.py covers them).
OWNER_VALUES = ("OwnerPid", "OwnerCreateTime", "SessionId")
# Genuine states as (ProxyEnable, ProxyServer, AutoConfigURL, ProxyOverride).
CLEAN = (0, "", ABSENT, ABSENT)
CORP = (1, "corp:8080", ABSENT, "<local>")
# What safe mode leaves live, for ADDR and URL.
FOOTPRINT = (1, ADDR, URL, "*")


def writes(fake, path=None, start=0):
    return [op for op in fake.ops[start:] if path is None or op[1] == path]


def set_state(fake, state):
    """Set all four live values; ABSENT removes one."""
    e, s, a, o = state
    fake.set_live(e, s, a, override=o)


def fail_open(state):
    """True if this live state is harmless with SNIper dead: a manual proxy
    that is enabled and names SNIper always bypasses every host."""
    e, s, _a, o = state
    return not (e == 1 and s in (ADDR, ADDR2) and o != "*")


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
        "Complete": (1, REG_DWORD),
    }
    # The record is committed (Complete last) before any live write, and the
    # live writes are exactly: the bypass list, the server, our URL, then the
    # enable flag, so the manual proxy is never on without the bypass list.
    ops = [(op[0], op[1], op[2]) for op in fake_reg.ops]
    rec_sets = [op[2] for op in ops if op[1] == REC and op[0] == "SetValueEx"]
    assert rec_sets[-1] == "Complete" and rec_sets.count("Complete") == 1
    live = [op for op in ops if op[1] == IE]
    assert live == [("SetValueEx", IE, "ProxyOverride"), ("SetValueEx", IE, "ProxyServer"),
                    ("SetValueEx", IE, "AutoConfigURL"), ("SetValueEx", IE, "ProxyEnable")]
    assert ops.index(("SetValueEx", REC, "Complete")) < ops.index(live[0])
    assert fake_reg.refresh_calls == [len(fake_reg.ops)]
    assert fake_reg.value(IE_KEY, "ProxyEnable") == (1, REG_DWORD)
    assert fake_reg.value(IE_KEY, "ProxyOverride") == ("*", REG_SZ)


@pytest.mark.parametrize("genuine", [
    CLEAN, CORP, (0, "corp:8080", CORP_PAC, ABSENT), (1, "corp:8080", "", ""),
    (0, "127.0.0.1:8881", ABSENT, ABSENT), (1, "corp:8080", ABSENT, "*.corp;<local>"),
    (0, "", ABSENT, "*"), (1, ADDR, ABSENT, "*"),
], ids=["clean", "manual", "pac", "manual-empty-pac-and-list", "old-sniper-server",
        "list", "genuine-bypass-all", "genuine-equals-footprint"])
def test_round_trip_puts_every_genuine_value_back(fake_reg, genuine):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert fake_reg.live_all() == FOOTPRINT
    rec = fake_reg.record()
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


@pytest.mark.parametrize("landed", [0, 1, 2, 3])
@pytest.mark.parametrize("genuine", [CLEAN, CORP, (0, "corp:8080", CORP_PAC, "")],
                         ids=["clean", "manual", "pac"])
def test_interrupted_apply_fails_open_and_is_fully_undone(fake_reg, monkeypatch,
                                                         genuine, landed):
    # Cut short after `landed` of the four live writes (the record is
    # committed by then): the proxy must already be fail-open, and launch
    # recovery must end at the genuine values.
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
    assert fake_reg.live_all() == FOOTPRINT


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
    assert fake_reg.live_all() == (1, ADDR2, URL2, "*")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live_all() == genuine


# ── Restore ──────────────────────────────────────────────────────────────────
def test_restore_untouched_writes_back_in_a_fail_open_order(fake_reg):
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
    set_state(fake_reg, FOOTPRINT[:2] + (url, "*"))
    mark = len(fake_reg.ops)
    # Deleting our URL where there was no genuine script is no change of the
    # user's: that is the genuine state.
    assert winproxy.proxy_restore() == ("restored" if url is ABSENT else "kept")
    assert fake_reg.live_all() == (1, "corp:8080", url, "<local>")
    assert "AutoConfigURL" not in [op[2] for op in writes(fake_reg, IE, mark)]
    assert fake_reg.record() is None


@pytest.mark.parametrize("manual", [
    (0, ADDR, "*"),                    # proxy switched off
    (1, "user:3128", "*"),             # another server
    (1, ADDR, "*.user;<local>"),       # the bypass list edited
    (1, ADDR, ABSENT),                 # the bypass list removed
    ("garbage", ADDR, "*"),            # a flag nobody can read as a number
], ids=["flag", "server", "list", "list-removed", "unreadable-flag"])
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
def test_interrupted_restore_fails_open_and_the_retry_finishes(fake_reg, monkeypatch,
                                                              genuine, landed):
    set_state(fake_reg, genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    cut = FailIEWritesAfter(fake_reg, monkeypatch, landed)
    assert winproxy.proxy_restore() is None
    assert len(cut.done) == landed
    assert fail_open(fake_reg.live_all())
    assert fake_reg.record()["Complete"] == 1
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
], ids=["clean", "footprint"])
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
        override_present=True, override="<local>", applied_manual=True)
    winproxy.proxy_restore()
    winproxy.proxy_enable(ADDR)
    base = winproxy._read_baseline()
    assert (base.applied_mode, base.applied_pac_url) == ("static", None)
    assert (base.override_present, base.override, base.applied_manual) == \
        (None, None, False)
    rec = fake_reg.record()
    assert not {"ProxyOverridePresent", "ProxyOverride", "AppliedManualProxy"} & set(rec)


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
    # never wrote it), so it is recorded before "*" goes in.
    early_pac_record(fake_reg, 1, "corp:8080")
    set_state(fake_reg, (0, "corp:8080", URL, "<local>"))
    winproxy.proxy_enable(ADDR2, pac_url=URL2)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "corp:8080")
    assert (rec["ProxyOverridePresent"], rec["ProxyOverride"]) == (1, "<local>")
    assert rec["AppliedManualProxy"] == 1
    assert fake_reg.live_all() == (1, ADDR2, URL2, "*")
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
    assert fake_reg.live_all() == (1, ADDR2, URL2, "*")
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


def test_pac_record_is_restored_before_a_static_session(fake_reg):
    set_state(fake_reg, CORP)
    winproxy.proxy_enable(ADDR, pac_url=URL)
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


@pytest.mark.parametrize("old_mode", ["static", "pac"])
def test_mode_switch_when_the_old_restore_cannot_act(fake_reg, monkeypatch, old_mode):
    # The leftover record could not be restored (say its live write failed):
    # its genuine values are still the only genuine ones, so they are kept and
    # the record is taken over for the new mode.
    set_state(fake_reg, (1, "corp:8080", CORP_PAC, "<local>"))
    winproxy.proxy_enable(ADDR, pac_url=URL if old_mode == "pac" else None)
    monkeypatch.setattr(winproxy, "_restore_static", lambda base: None)
    monkeypatch.setattr(winproxy, "_restore_pac", lambda base: None)
    new_url = None if old_mode == "pac" else URL2
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
        assert "ProxyOverride" not in rec
    else:
        assert rec["ProxyOverride"] == "<local>"
        assert fake_reg.live_all() == (1, ADDR2, URL2, "*")


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
