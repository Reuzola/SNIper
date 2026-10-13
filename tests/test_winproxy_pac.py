"""Tests for safe mode (PAC) in sniper.winproxy, on the fake registry.

Safe mode writes ProxyEnable=0 and a one-off AutoConfigURL and never touches
ProxyServer. Its restore is decided by that URL: while it is still there it is
always removed (it is provably SNIper's), the genuine enable flag goes back
only while the flag is still the 0 SNIper set, and anything the user changed
is left alone. Records from v1.1.7 and before must behave exactly as the
characterization tests in test_winproxy.py pin down.
"""
from __future__ import annotations

import pytest

import sniper.winproxy as winproxy
from fakewinreg import ABSENT, IE_KEY, REG_DWORD, REG_SZ, RESTORE_KEY, SNIPER_KEY

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
URL2 = "http://127.0.0.1:9999/sniper-fedcba9876543210.pac"
CORP_PAC = "http://corp/p.pac"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()


def writes(fake, path=None, start=0):
    return [op for op in fake.ops[start:] if path is None or op[1] == path]


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


# ── Enable ───────────────────────────────────────────────────────────────────
def test_enable_from_clean_state(fake_reg):
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.live() == (0, "", URL)
    assert fake_reg.record(types=True) == {
        "ProxyEnable": (0, REG_DWORD),
        "ProxyServer": ("", REG_SZ),
        "AutoConfigURLPresent": (0, REG_DWORD),
        "AppliedProxyServer": (ADDR, REG_SZ),
        "AppliedMode": ("pac", REG_SZ),
        "AppliedAutoConfigURL": (URL, REG_SZ),
        "Complete": (1, REG_DWORD),
    }
    # The record is committed (Complete last) before any live write, and the
    # live writes are exactly: our URL, then the enable flag. ProxyServer is
    # never written in safe mode.
    ops = [(op[0], op[1], op[2]) for op in fake_reg.ops]
    rec_sets = [op[2] for op in ops if op[1] == REC and op[0] == "SetValueEx"]
    assert rec_sets[-1] == "Complete" and rec_sets.count("Complete") == 1
    live = [op for op in ops if op[1] == IE]
    assert live == [("SetValueEx", IE, "AutoConfigURL"), ("SetValueEx", IE, "ProxyEnable")]
    assert ops.index(("SetValueEx", REC, "Complete")) < ops.index(live[0])
    assert fake_reg.refresh_calls == [len(fake_reg.ops)]


@pytest.mark.parametrize("genuine", [
    (0, "", ABSENT), (1, "corp:8080", ABSENT), (0, "corp:8080", CORP_PAC),
    (1, "corp:8080", ""), (0, "127.0.0.1:8881", ABSENT),
], ids=["clean", "manual", "pac", "manual-empty-pac", "old-sniper-server"])
def test_enable_never_writes_proxy_server(fake_reg, genuine):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert [op for op in writes(fake_reg, IE) if op[2] == "ProxyServer"] == []
    assert fake_reg.live() == (0, genuine[1], URL)


def test_genuine_manual_proxy_round_trip(fake_reg):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.live() == (0, "corp:8080", URL)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)
    assert fake_reg.record() is None
    assert not fake_reg.exists(SNIPER_KEY)


def test_genuine_pac_is_replaced_and_put_back(fake_reg):
    fake_reg.set_live(0, "", CORP_PAC)
    # The genuine PAC comes back to the caller, for the "PAC was active" note.
    assert winproxy.proxy_enable(ADDR, pac_url=URL) == CORP_PAC
    assert fake_reg.live() == (0, "", URL)
    rec = fake_reg.record()
    assert (rec["AutoConfigURLPresent"], rec["AutoConfigURL"]) == (1, CORP_PAC)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", CORP_PAC)


def test_genuine_empty_pac_value_is_kept_as_empty(fake_reg):
    fake_reg.set_live(0, "", "")
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", "")  # empty, not absent


def test_gpo_locked_writes_nothing(fake_reg):
    fake_reg.set_gpo_locked(True)
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert writes(fake_reg) == []
    assert not [c for c in fake_reg.calls if c[0] == "CreateKey"]
    assert fake_reg.refresh_calls == []
    assert fake_reg.live() == (0, "", ABSENT)


def test_record_write_failure_never_touches_live(fake_reg):
    fake_reg.fail.add(("SetValueEx", REC))
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.live() == (0, "", ABSENT)
    assert writes(fake_reg, IE) == []
    assert winproxy.proxy_restore() is None  # what got written is incomplete


def test_live_apply_failure_leaves_a_committed_record_that_backs_off(fake_reg):
    fake_reg.fail.add(("SetValueEx", IE))
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert fake_reg.record()["Complete"] == 1
    assert fake_reg.live() == (0, "", ABSENT)
    fake_reg.fail.clear()
    # Our URL never landed, so nothing of SNIper's is live: "kept", no writes.
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert writes(fake_reg, IE, mark) == []
    assert fake_reg.record() is None


# ── Re-enable while a record exists ──────────────────────────────────────────
def test_reenable_same_session_writes_no_record(fake_reg):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    record = fake_reg.record()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_enable(ADDR, pac_url=URL) is None
    assert writes(fake_reg, REC, mark) == []
    assert fake_reg.record() == record
    assert fake_reg.live() == (0, "corp:8080", URL)


def test_reenable_with_a_new_url_keeps_genuine_and_updates_footprint(fake_reg):
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    # The live values now look like SNIper's; they must never be captured.
    assert winproxy.proxy_enable(ADDR2, pac_url=URL2) == CORP_PAC
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AutoConfigURL"]) == \
        (1, "corp:8080", CORP_PAC)
    assert (rec["AppliedProxyServer"], rec["AppliedAutoConfigURL"]) == (ADDR2, URL2)
    assert fake_reg.live() == (0, "corp:8080", URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", CORP_PAC)


# ── Restore ──────────────────────────────────────────────────────────────────
def test_restore_untouched_deletes_the_url_and_writes_the_flag(fake_reg):
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)  # deleted, not left empty
    assert writes(fake_reg, IE, mark) == [("SetValueEx", IE, "ProxyEnable"),
                                          ("DeleteValue", IE, "AutoConfigURL")]
    assert fake_reg.record() is None
    assert not fake_reg.exists(SNIPER_KEY)
    assert len(fake_reg.refresh_calls) == 1


@pytest.mark.parametrize("genuine, changed", [
    ((0, "", ABSENT), (0, "", "http://user/x.pac")),          # replaced
    ((0, "", ABSENT), (0, "", ABSENT)),                       # deleted
    ((0, "", ABSENT), (0, "", "")),                           # emptied
    ((0, "", ABSENT), (0, "", URL2)),                         # another session's URL
    ((0, "", ABSENT), (0, "", URL.upper())),                  # not byte-identical
    ((0, "", CORP_PAC), (0, "", CORP_PAC)),                   # user put theirs back
    ((1, "corp:8080", ABSENT), (1, "other:3128", "http://user/x.pac")),
], ids=["replaced", "deleted", "emptied", "other-session", "case", "user-restored",
        "everything-changed"])
def test_user_took_the_url_so_everything_is_kept(fake_reg, genuine, changed):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.set_live(*changed)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live() == changed
    assert writes(fake_reg, IE, mark) == []
    assert fake_reg.refresh_calls == []
    assert fake_reg.record() is None


@pytest.mark.parametrize("genuine, user_live, expected", [
    ((0, "", ABSENT), (1, "", URL), (1, "", ABSENT)),
    ((0, "", ABSENT), (1, "user:3128", URL), (1, "user:3128", ABSENT)),
    ((0, "corp:8080", CORP_PAC), (1, "user:3128", URL), (1, "user:3128", CORP_PAC)),
    ((1, "corp:8080", ABSENT), (1, "corp:8080", URL), (1, "corp:8080", ABSENT)),
    ((0, "", ABSENT), ("garbage", "user:3128", URL), ("garbage", "user:3128", ABSENT)),
], ids=["enable-only", "enable-and-server", "with-genuine-pac", "same-as-genuine",
        "unreadable-flag"])
def test_user_enabled_a_manual_proxy_our_url_still_goes(fake_reg, genuine, user_live,
                                                        expected):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    e, s, a = user_live
    fake_reg.set_live(e, s, a)
    if isinstance(e, str):  # a REG_SZ flag nobody can read as a number
        fake_reg.put(IE_KEY, "ProxyEnable", e, REG_SZ)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live() == expected
    # Only our URL was touched; the user's flag and server were not written.
    assert [op[2] for op in writes(fake_reg, IE, mark)] == ["AutoConfigURL"]
    assert len(fake_reg.refresh_calls) == 1
    assert fake_reg.record() is None


def test_enable_flag_still_zero_but_server_changed_restores_flag_only(fake_reg):
    # ProxyServer is not part of the safe-mode footprint: SNIper never wrote
    # it, so it never writes it back either.
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.set_live(0, "user:3128", URL)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "user:3128", ABSENT)


@pytest.mark.parametrize("failing", [
    ("SetValueEx", IE), ("DeleteValue", IE), ("OpenKey", IE), "QueryValueEx",
], ids=["write", "delete", "open", "read"])
def test_restore_failure_keeps_the_record_for_a_retry(fake_reg, failing):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    record = fake_reg.record()
    fake_reg.fail.add(failing)
    assert winproxy.proxy_restore() is None
    fake_reg.fail.clear()
    assert fake_reg.record() == record
    assert fake_reg.live()[2] == URL  # our URL is still there to find
    assert winproxy.proxy_restore() in ("restored", "kept")
    assert fake_reg.live() == (1, "corp:8080", ABSENT)
    assert fake_reg.record() is None


@pytest.mark.parametrize("genuine_enable, expected_result", [(0, "restored"), (1, "kept")])
def test_interrupted_enable_is_fully_undone(fake_reg, genuine_enable, expected_result):
    # Killed between the two live writes of _apply_live_pac: our URL is in,
    # the flag is still the genuine one. The restore must end at genuine.
    genuine = (genuine_enable, "corp:8080", ABSENT)
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.set_live(genuine_enable, "corp:8080", URL)
    assert winproxy.recover_orphaned_proxy() == expected_result
    assert fake_reg.live() == genuine


def test_interrupted_restore_is_finished_by_the_retry(fake_reg):
    # Killed after the restore wrote the genuine flag, before our URL went.
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    fake_reg.set_live(1, "corp:8080", URL)
    winproxy.recover_orphaned_proxy()
    assert fake_reg.live() == (1, "corp:8080", CORP_PAC)
    assert fake_reg.record() is None


def test_recover_after_enable_without_stop(fake_reg):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)
    assert winproxy.recover_orphaned_proxy() is None  # and nothing left


def test_pac_record_without_its_url_never_writes(fake_reg):
    # A complete PAC record missing AppliedAutoConfigURL can't name our URL,
    # so nothing live is provably ours.
    winproxy.proxy_enable(ADDR, pac_url=URL)
    k = fake_reg.keys[REC]
    del k["appliedautoconfigurl"]
    fake_reg.set_live(0, "", ABSENT)  # would equal "no URL" if compared blindly
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert writes(fake_reg, IE, mark) == []


def test_unknown_mode_reads_as_static(fake_reg):
    winproxy.proxy_enable(ADDR)  # static footprint
    fake_reg.put(RESTORE_KEY, "AppliedMode", "future-mode", REG_SZ)
    assert winproxy._read_baseline().applied_mode == "static"
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)


def test_baseline_shape(fake_reg):
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert winproxy._read_baseline() == winproxy.Baseline(
        enable=1, server="corp:8080", pac_present=True, pac=CORP_PAC,
        applied_server=ADDR, applied_mode="pac", applied_pac_url=URL)
    winproxy.proxy_restore()
    winproxy.proxy_enable(ADDR)
    assert winproxy._read_baseline().applied_mode == "static"
    assert winproxy._read_baseline().applied_pac_url is None


# ── Mode switch with a leftover record ───────────────────────────────────────
@pytest.mark.parametrize("make_record", ["new-static", "v117", "legacy"])
def test_static_record_is_restored_before_a_pac_session(fake_reg, make_record):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    if make_record == "new-static":
        winproxy.proxy_enable(ADDR)
    else:
        v117_record(fake_reg, 1, "corp:8080",
                    applied=ADDR if make_record == "v117" else None)
        fake_reg.set_live(1, ADDR, ABSENT)
    assert fake_reg.live() == (1, ADDR, ABSENT)  # the stranded static footprint
    assert winproxy.proxy_enable(ADDR2, pac_url=URL2) is None
    # Restored first, then captured afresh: the genuine values are corp's.
    assert fake_reg.live() == (0, "corp:8080", URL2)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "corp:8080")
    assert (rec["AppliedMode"], rec["AppliedAutoConfigURL"]) == ("pac", URL2)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)


def test_static_record_the_user_changed_is_released_before_a_pac_session(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.set_live(1, "user:3128", ABSENT)  # the user took over
    winproxy.proxy_enable(ADDR2, pac_url=URL2)
    rec = fake_reg.record()
    # The user's values are the genuine ones now.
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "user:3128")
    winproxy.proxy_restore()
    assert fake_reg.live() == (1, "user:3128", ABSENT)


def test_pac_record_is_restored_before_a_static_session(fake_reg):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL)
    assert winproxy.proxy_enable(ADDR2) is None
    # Our dead URL is gone; a stale one would make the static footprint
    # check fail at Stop and strand the static proxy.
    assert fake_reg.live() == (1, ADDR2, ABSENT)
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AppliedMode"]) == \
        (1, "corp:8080", "static")
    assert "AppliedAutoConfigURL" not in rec
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)


@pytest.mark.parametrize("old_mode", ["static", "pac"])
def test_mode_switch_when_the_old_restore_cannot_act(fake_reg, monkeypatch, old_mode):
    # The leftover record could not be restored (say its live write failed):
    # its genuine values are still the only genuine ones, so they are kept and
    # the record is taken over for the new mode.
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
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

    assert run("v117") == run("new")
    assert run("v117")[0] == ("restored" if kind == "restored" else "kept")


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
