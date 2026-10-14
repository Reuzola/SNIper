"""Characterization tests for sniper.winproxy (v1.1.7 behavior).

They pin down today's proxy_enable / proxy_restore contract on the fake
registry so later refactors can't change it by accident: the restore record is
committed (Complete last) before the live values change, a restore only ever
undoes SNIper's own footprint, a manual change is left alone, and an
incomplete or unreadable state is never acted on.
"""
from __future__ import annotations

import pytest

import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, IE_KEY, REG_BINARY, REG_DWORD, REG_MULTI_SZ,
                        REG_QWORD, REG_SZ, RESTORE_KEY, SETTINGS_KEY, SNIPER_KEY)

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
CORP_PAC = "http://corp/proxy.pac"
PAC_URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
SID = "0123456789abcdef"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()
# Added with the guardian: who applied the record. test_winproxy_owner.py
# covers them; here they are only split off from the v1.1.7 values.
OWNER_VALUES = ("OwnerPid", "OwnerCreateTime", "SessionId")


def _writes(fake, path=None, start=0):
    return [op for op in fake.ops[start:] if path is None or op[1] == path]


def _legacy_record(fake, enable, server, pac=ABSENT, complete=True):
    """A record as a pre-footprint SNIper wrote it: no AppliedProxyServer."""
    fake.put(RESTORE_KEY, "ProxyEnable", enable, REG_DWORD)
    fake.put(RESTORE_KEY, "ProxyServer", server, REG_SZ)
    if pac is ABSENT:
        fake.put(RESTORE_KEY, "AutoConfigURLPresent", 0, REG_DWORD)
    else:
        fake.put(RESTORE_KEY, "AutoConfigURLPresent", 1, REG_DWORD)
        fake.put(RESTORE_KEY, "AutoConfigURL", pac, REG_SZ)
    if complete:
        fake.put(RESTORE_KEY, "Complete", 1, REG_DWORD)


# ── 1. Enable from a clean state ─────────────────────────────────────────────
def test_enable_from_clean_state(fake_reg):
    assert winproxy.proxy_enable(ADDR) is None
    rec = fake_reg.record(types=True)
    owner = {name: rec.pop(name) for name in OWNER_VALUES}
    assert [kind for _, kind in owner.values()] == [REG_DWORD, REG_QWORD, REG_SZ]
    assert rec == {
        "ProxyEnable": (0, REG_DWORD),
        "ProxyServer": ("", REG_SZ),
        "AutoConfigURLPresent": (0, REG_DWORD),
        "AppliedProxyServer": (ADDR, REG_SZ),
        # Added with safe mode: every record now names its mode. v1.1.7
        # records without it still read as static (test_winproxy_pac.py).
        "AppliedMode": ("static", REG_SZ),
        "Complete": (1, REG_DWORD),
    }
    assert fake_reg.live() == (1, ADDR, ABSENT)

    # Crash-durability ordering: every record write comes first, Complete is
    # the last of them, and only then are the live values touched.
    writes = [(op[1], op[2]) for op in fake_reg.ops if op[0] == "SetValueEx"]
    rec = [name for path, name in writes if path == REC]
    live = [i for i, (path, _) in enumerate(writes) if path == IE]
    assert rec[-1] == "Complete"
    assert writes.index((REC, "Complete")) < min(live)
    assert [name for path, name in writes if path == IE] == ["ProxyEnable", "ProxyServer"]
    # One refresh, after all the writes.
    assert fake_reg.refresh_calls == [len(fake_reg.ops)]


def test_enable_drops_a_stale_complete_marker_first(fake_reg):
    # Re-writing over an existing (here: incomplete-looking) key removes the
    # marker before anything else, so a crash mid-rewrite is never acted on.
    _legacy_record(fake_reg, 1, "old:1", complete=False)
    fake_reg.put(RESTORE_KEY, "Complete", 0, REG_DWORD)  # not 1: incomplete
    winproxy.proxy_enable(ADDR)
    rec_ops = _writes(fake_reg, REC)
    assert rec_ops[0] == ("DeleteValue", REC, "Complete")
    assert rec_ops[-1] == ("SetValueEx", REC, "Complete")
    # The incomplete record was ignored: the live values became the baseline.
    assert fake_reg.record()["ProxyEnable"] == 0


# ── 2. Enable with a genuine PAC ─────────────────────────────────────────────
def test_enable_with_a_genuine_pac(fake_reg):
    fake_reg.set_live(0, "", CORP_PAC)
    assert winproxy.proxy_enable(ADDR) == CORP_PAC
    rec = fake_reg.record(types=True)
    assert rec["AutoConfigURLPresent"] == (1, REG_DWORD)
    assert rec["AutoConfigURL"] == (CORP_PAC, REG_SZ)
    assert rec["AppliedProxyServer"] == (ADDR, REG_SZ)
    # Emptied, not deleted, while SNIper runs.
    assert fake_reg.live() == (1, ADDR, "")


def test_enable_keeps_a_genuine_manual_proxy_as_baseline(fake_reg):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.record()["ProxyEnable"] == 1
    assert fake_reg.record()["ProxyServer"] == "corp:8080"
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)


# ── 3./4. Restore with the footprint intact ──────────────────────────────────
def test_restore_with_footprint_intact(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.refresh_calls.clear()
    assert winproxy.proxy_restore() == "restored"
    # Genuine values back; AutoConfigURL absent again (never an empty value).
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is None
    assert not fake_reg.exists(SNIPER_KEY)  # the emptied parent went too
    assert len(fake_reg.refresh_calls) == 1


def test_restore_puts_a_genuine_pac_back(fake_reg):
    fake_reg.set_live(0, "", CORP_PAC)
    winproxy.proxy_enable(ADDR)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", CORP_PAC)


def test_restore_keeps_sibling_settings_and_the_parent(fake_reg):
    fake_reg.put(SETTINGS_KEY, "Port", 9123)
    winproxy.proxy_enable(ADDR)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.record() is None
    assert fake_reg.exists(SNIPER_KEY)
    assert fake_reg.value(SETTINGS_KEY, "Port") == (9123, REG_DWORD)


def test_restore_keeps_a_parent_that_holds_values(fake_reg):
    fake_reg.put(SNIPER_KEY, "Unrelated", 1)
    winproxy.proxy_enable(ADDR)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.exists(SNIPER_KEY)


# ── 5. The user took control during the session ──────────────────────────────
@pytest.mark.parametrize("genuine, changed", [
    ((0, "", ABSENT), (1, "other:3128", ABSENT)),      # ProxyServer changed
    ((0, "", ABSENT), (0, ADDR, ABSENT)),              # ProxyEnable turned off
    ((0, "", ABSENT), (1, ADDR, "http://user/x.pac")), # a PAC was added
    ((0, "", ABSENT), (1, ADDR, "")),                  # even an empty PAC value
    ((0, "", CORP_PAC), (1, ADDR, "http://user/x.pac")),  # PAC set again
    ((0, "", CORP_PAC), (1, ADDR, ABSENT)),            # emptied PAC deleted
], ids=["server", "enable", "pac-added", "pac-empty", "pac-replaced", "pac-deleted"])
def test_restore_keeps_a_manual_change(fake_reg, genuine, changed):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR)
    fake_reg.set_live(*changed)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live() == changed
    assert _writes(fake_reg, IE, mark) == []
    assert fake_reg.record() is None


# ── 6. Legacy record (no footprint) ──────────────────────────────────────────
def test_legacy_record_is_restored_unconditionally(fake_reg):
    _legacy_record(fake_reg, 1, "corp:8080")
    # Whatever the live state is, it can't be compared, so it is restored;
    # a leftover empty AutoConfigURL is deleted because none was genuine.
    fake_reg.set_live(0, "someone:1", "")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)
    assert fake_reg.record() is None


def test_legacy_record_with_pac_is_restored(fake_reg):
    _legacy_record(fake_reg, 0, "", pac=CORP_PAC)
    fake_reg.set_live(1, ADDR, "")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", CORP_PAC)


def test_pac_present_flag_without_url_reads_as_no_pac(fake_reg):
    fake_reg.put(RESTORE_KEY, "ProxyEnable", 0, REG_DWORD)
    fake_reg.put(RESTORE_KEY, "ProxyServer", "", REG_SZ)
    fake_reg.put(RESTORE_KEY, "AutoConfigURLPresent", 1, REG_DWORD)
    fake_reg.put(RESTORE_KEY, "AppliedProxyServer", ADDR, REG_SZ)
    fake_reg.put(RESTORE_KEY, "Complete", 1, REG_DWORD)
    fake_reg.set_live(1, ADDR, ABSENT)  # footprint for "no genuine PAC"
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)


# ── 7. Incomplete record ─────────────────────────────────────────────────────
@pytest.mark.parametrize("complete", [None, 0, 2])
def test_incomplete_record_is_never_acted_on(fake_reg, complete):
    _legacy_record(fake_reg, 1, "corp:8080", complete=False)
    fake_reg.put(RESTORE_KEY, "AppliedProxyServer", ADDR, REG_SZ)
    if complete is not None:
        fake_reg.put(RESTORE_KEY, "Complete", complete, REG_DWORD)
    fake_reg.set_live(1, ADDR, ABSENT)
    before = dict(fake_reg.record())
    assert winproxy.proxy_restore() is None
    assert winproxy.recover_orphaned_proxy() is None
    assert fake_reg.live() == (1, ADDR, ABSENT)
    assert fake_reg.record() == before
    assert _writes(fake_reg) == []


def test_restore_without_a_record_does_nothing(fake_reg):
    assert winproxy.proxy_restore() is None
    assert _writes(fake_reg) == []
    assert fake_reg.refresh_calls == []


# ── 8. Re-enable while a complete record exists ──────────────────────────────
def test_reenable_same_address_writes_no_record(fake_reg):
    # The same session re-applying the same address. (Without a session id
    # every apply is a new session, and the record names the newest one; see
    # test_winproxy_owner.py.)
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, session_id=SID)
    record = fake_reg.record()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_enable(ADDR, session_id=SID) is None
    assert fake_reg.record() == record
    assert _writes(fake_reg, REC, mark) == []
    assert fake_reg.live() == (1, ADDR, ABSENT)


def test_reenable_new_address_keeps_genuine_and_updates_footprint(fake_reg):
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR)
    # Even if the live values now look like SNIper's, they are never captured.
    assert winproxy.proxy_enable(ADDR2) == CORP_PAC
    rec = fake_reg.record()
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AutoConfigURL"]) == \
        (1, "corp:8080", CORP_PAC)
    assert rec["AppliedProxyServer"] == ADDR2
    assert rec["Complete"] == 1
    assert fake_reg.live() == (1, ADDR2, "")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (1, "corp:8080", CORP_PAC)


# ── 9. Read / write failures keep the record for a retry ─────────────────────
def test_live_read_failure_keeps_the_record(fake_reg):
    winproxy.proxy_enable(ADDR)
    record = fake_reg.record()
    fake_reg.fail.add(("OpenKey", IE))
    assert winproxy.proxy_restore() is None
    assert fake_reg.record() == record
    assert fake_reg.live() == (1, ADDR, ABSENT)
    fake_reg.fail.clear()
    assert winproxy.proxy_restore() == "restored"  # the retry works


def test_live_write_failure_keeps_the_record(fake_reg):
    winproxy.proxy_enable(ADDR)
    record = fake_reg.record()
    fake_reg.fail.add(("SetValueEx", IE))
    assert winproxy.proxy_restore() is None
    assert fake_reg.record() == record
    fake_reg.fail.clear()
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)


def test_record_write_failure_never_touches_live(fake_reg):
    fake_reg.fail.add(("SetValueEx", REC))
    assert winproxy.proxy_enable(ADDR) is None
    assert fake_reg.live() == (0, "", ABSENT)
    assert _writes(fake_reg, IE) == []
    assert fake_reg.refresh_calls == []
    # What got written is incomplete and therefore ignored.
    assert "Complete" not in (fake_reg.record() or {})
    assert winproxy.proxy_restore() is None


def test_record_create_failure_never_touches_live(fake_reg):
    fake_reg.fail.add("CreateKey")
    assert winproxy.proxy_enable(ADDR) is None
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is None


def test_live_apply_failure_leaves_a_committed_record(fake_reg):
    fake_reg.fail.add(("SetValueEx", IE))
    assert winproxy.proxy_enable(ADDR) is None
    assert fake_reg.record()["Complete"] == 1
    assert fake_reg.live() == (0, "", ABSENT)
    fake_reg.fail.clear()
    # Live values were never changed, so they aren't the footprint; they are
    # still the genuine ones: "already", and nothing is written.
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "already"
    assert _writes(fake_reg, IE, mark) == []
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is None


def test_record_delete_failure_reports_restored_then_already(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.fail.add("DeleteKey")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is not None
    fake_reg.fail.clear()
    mark = len(fake_reg.ops)
    # Next time the live values are genuine, not the footprint.
    assert winproxy.proxy_restore() == "already"
    assert _writes(fake_reg, IE, mark) == []
    assert fake_reg.record() is None


# ── 10. Group Policy lock ────────────────────────────────────────────────────
def test_gpo_locked_enable_writes_nothing(fake_reg):
    fake_reg.set_gpo_locked(True)
    assert winproxy.proxy_enable(ADDR) is None
    assert _writes(fake_reg) == []
    assert not [c for c in fake_reg.calls if c[0] == "CreateKey"]
    assert fake_reg.refresh_calls == []
    assert fake_reg.live() == (0, "", ABSENT)


def test_gpo_explicitly_unlocked_enables(fake_reg):
    fake_reg.set_gpo_locked(False)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.live() == (1, ADDR, ABSENT)


# ── 11. Launch recovery is proxy_restore ─────────────────────────────────────
def _scenario_restored(fake):
    winproxy.proxy_enable(ADDR)


def _scenario_kept(fake):
    winproxy.proxy_enable(ADDR)
    fake.set_live(1, "other:1", ABSENT)


def _scenario_legacy(fake):
    _legacy_record(fake, 1, "corp:8080")


def _scenario_incomplete(fake):
    _legacy_record(fake, 1, "corp:8080", complete=False)


def _scenario_clean(fake):
    pass


@pytest.mark.parametrize("scenario", [
    _scenario_restored, _scenario_kept, _scenario_legacy,
    _scenario_incomplete, _scenario_clean])
def test_recover_orphaned_proxy_matches_proxy_restore(fake_reg, scenario):
    def run(fn):
        fake_reg.keys.clear()
        fake_reg.set_live(0, "", ABSENT)
        scenario(fake_reg)
        mark = len(fake_reg.ops)
        result = fn()
        return result, fake_reg.live(), fake_reg.record(), fake_reg.ops[mark:]
    assert run(winproxy.recover_orphaned_proxy) == run(winproxy.proxy_restore)


# ── 12. A ProxyEnable that can't be read as a number ─────────────────────────
# What a user or another tool may leave in ProxyEnable instead of a DWORD.
UNREADABLE = [("x", REG_SZ), ("", REG_SZ), (b"\x01\x00\x00\x00", REG_BINARY)]
UNREADABLE_IDS = ["sz", "empty-sz", "binary"]


def _static_record(fake, record):
    """A committed static record over a genuine (0, "", no PAC), with its
    footprint (1, ADDR, no PAC) live: as this version writes it, or v1.1.7."""
    if record == "new":
        winproxy.proxy_enable(ADDR)
    else:
        _legacy_record(fake, 0, "")
        fake.put(RESTORE_KEY, "AppliedProxyServer", ADDR, REG_SZ)
        fake.set_live(1, ADDR, ABSENT)


@pytest.mark.parametrize("record", ["new", "v117"])
@pytest.mark.parametrize("data, reg_type", UNREADABLE, ids=UNREADABLE_IDS)
def test_unreadable_live_flag_is_not_the_footprint(fake_reg, record, data, reg_type):
    _static_record(fake_reg, record)
    # Server and PAC still match the footprint; only the flag can't be read.
    fake_reg.put(IE_KEY, "ProxyEnable", data, reg_type)
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.value(IE_KEY, "ProxyEnable") == (data, reg_type)
    assert fake_reg.live() == (data, ADDR, ABSENT)
    assert _writes(fake_reg, IE, mark) == []
    assert fake_reg.refresh_calls == []
    assert fake_reg.record() is None


def test_unreadable_live_flag_recovery_backs_off_once(fake_reg):
    _static_record(fake_reg, "new")
    fake_reg.put(IE_KEY, "ProxyEnable", "x", REG_SZ)
    mark = len(fake_reg.ops)
    assert winproxy.recover_orphaned_proxy() == "kept"
    # The record is gone, so the next launch has nothing left to recover.
    assert winproxy.recover_orphaned_proxy() is None
    assert fake_reg.live() == ("x", ADDR, ABSENT)
    assert _writes(fake_reg, IE, mark) == []


@pytest.mark.parametrize("pac_url", [None, PAC_URL], ids=["static", "safe"])
@pytest.mark.parametrize("data, reg_type", UNREADABLE + [
    ("-1", REG_SZ), (2 ** 32, REG_QWORD),  # numbers, but no DWORD
], ids=UNREADABLE_IDS + ["negative", "qword"])
def test_unreadable_recorded_flag_reads_as_off(fake_reg, pac_url, data, reg_type):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=pac_url)
    fake_reg.put(RESTORE_KEY, "ProxyEnable", data, reg_type)
    assert winproxy._read_baseline().enable == 0
    assert winproxy.proxy_restore() == "restored"
    # Fails open: the flag goes off as a real DWORD 0; the genuine server
    # comes back (static) or was never touched (safe mode).
    assert fake_reg.value(IE_KEY, "ProxyEnable") == (0, REG_DWORD)
    assert fake_reg.live() == (0, "corp:8080", ABSENT)
    assert fake_reg.record() is None


def test_unreadable_recorded_flag_never_overrides_a_manual_change(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.put(RESTORE_KEY, "ProxyEnable", "x", REG_SZ)
    fake_reg.set_live(1, "user:3128", ABSENT)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live() == (1, "user:3128", ABSENT)
    assert _writes(fake_reg, IE, mark) == []
    assert fake_reg.record() is None


def test_unreadable_recorded_flag_never_lets_the_footprint_be_captured(fake_reg):
    # The footprint is live under a committed record whose flag is garbage.
    # Were that record read as absent, the next enable would capture the
    # footprint as the genuine baseline and stop would put SNIper's dead
    # proxy back. Read as off, the record is kept and stop fails open.
    winproxy.proxy_enable(ADDR)
    fake_reg.put(RESTORE_KEY, "ProxyEnable", "x", REG_SZ)
    winproxy.proxy_enable(ADDR2)
    rec = fake_reg.record(types=True)
    assert rec["ProxyEnable"] == (0, REG_DWORD)  # rewritten clean, not "x"
    assert rec["ProxyServer"] == ("", REG_SZ)    # never ADDR
    assert fake_reg.live() == (1, ADDR2, ABSENT)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)


# ── 13. Capture refuses a live value it can't record exactly ─────────────────
# A record holds ProxyEnable as a DWORD and the two strings as REG_SZ, the
# way a restore writes them back. Anything else would come back changed, so
# capture writes nothing at all and Start fails with the reason.
NOT_TEXT = [(5, REG_DWORD), (b"corp:8080", REG_BINARY),
            (["corp:8080"], REG_MULTI_SZ)]
NOT_TEXT_IDS = ["dword", "binary", "multi-sz"]
UNRECORDABLE = (
    [("ProxyEnable",) + v for v in UNREADABLE + [("-1", REG_SZ), (2 ** 32, REG_QWORD)]]
    + [("ProxyServer",) + v for v in NOT_TEXT]
    + [("AutoConfigURL",) + v for v in NOT_TEXT])
UNRECORDABLE_IDS = (
    ["enable-" + i for i in UNREADABLE_IDS + ["negative", "qword"]]
    + ["server-" + i for i in NOT_TEXT_IDS]
    + ["pac-" + i for i in NOT_TEXT_IDS])


@pytest.mark.parametrize("pac_url", [None, PAC_URL], ids=["static", "safe"])
@pytest.mark.parametrize("name, data, reg_type", UNRECORDABLE, ids=UNRECORDABLE_IDS)
def test_enable_refuses_a_live_value_it_cant_record(fake_reg, pac_url, name,
                                                    data, reg_type):
    fake_reg.put(IE_KEY, name, data, reg_type)
    before = fake_reg.live()
    with pytest.raises(winproxy.UnrecordableProxyValue) as exc:
        winproxy.proxy_enable(ADDR, pac_url=pac_url)
    assert name in str(exc.value)
    # Refused before the record key was even created: nothing written.
    assert _writes(fake_reg) == []
    assert not fake_reg.exists(SNIPER_KEY)
    assert fake_reg.refresh_calls == []
    assert fake_reg.value(IE_KEY, name) == (data, reg_type)
    assert fake_reg.live() == before
    assert not fake_reg.locked
    assert fake_reg.open == 0
    assert winproxy.proxy_restore() is None  # nothing to undo either


def test_refusal_message_names_the_value_and_cuts_a_long_one(fake_reg):
    data = b"\xff" * 64
    fake_reg.put(IE_KEY, "ProxyServer", data, REG_BINARY)
    with pytest.raises(winproxy.UnrecordableProxyValue) as exc:
        winproxy.proxy_enable(ADDR)
    assert str(exc.value).startswith(
        "the Windows proxy setting ProxyServer holds %s..., which SNIper "
        "can't save" % repr(data)[:37])


@pytest.mark.parametrize("first, then", [(None, PAC_URL), (PAC_URL, None)],
                         ids=["static-to-safe", "safe-to-static"])
def test_mode_switch_refuses_after_the_old_record_backs_off(fake_reg, first, then):
    winproxy.proxy_enable(ADDR, pac_url=first)
    # Garbage in the flag while the session ran: the old record backs off.
    fake_reg.put(IE_KEY, "ProxyEnable", "x", REG_SZ)
    mark = len(fake_reg.ops)
    with pytest.raises(winproxy.UnrecordableProxyValue):
        winproxy.proxy_enable(ADDR, pac_url=then)
    # The old record is gone and no new one was started.
    assert fake_reg.record() is None
    assert [op for op in _writes(fake_reg, REC, mark) if op[0] != "DeleteKey"] == []
    assert fake_reg.value(IE_KEY, "ProxyEnable") == ("x", REG_SZ)
    if first is None:
        # Static: the back-off wrote nothing live.
        assert fake_reg.live() == ("x", ADDR, ABSENT)
        assert _writes(fake_reg, IE, mark) == []
    else:
        # Safe: our one-off script URL went, as it always does; nothing else.
        assert fake_reg.live() == ("x", "", ABSENT)
        assert _writes(fake_reg, IE, mark) == [("DeleteValue", IE, "AutoConfigURL")]
    assert winproxy.proxy_restore() is None


def test_enable_records_a_flag_it_can_read_as_that_dword(fake_reg):
    # Only what _flag can't read is refused: a REG_SZ "1" reads as 1, so it
    # is captured as the DWORD 1 that a restore writes back.
    fake_reg.set_live(0, "corp:8080", ABSENT)
    fake_reg.put(IE_KEY, "ProxyEnable", "1", REG_SZ)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.record(types=True)["ProxyEnable"] == (1, REG_DWORD)
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.value(IE_KEY, "ProxyEnable") == (1, REG_DWORD)


# ── 14. A recorded ProxyServer / AutoConfigURL that isn't a string ───────────
# SNIper only records them as REG_SZ, so anything else was put there by
# someone else. A restore writes them back as REG_SZ, which takes only a
# string, so they read as "": no server, no script.
@pytest.mark.parametrize("pac_url", [None, PAC_URL], ids=["static", "safe"])
@pytest.mark.parametrize("data, reg_type", NOT_TEXT, ids=NOT_TEXT_IDS)
def test_unwritable_recorded_server_reads_as_empty(fake_reg, pac_url, data, reg_type):
    fake_reg.set_live(0, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=pac_url)
    fake_reg.put(RESTORE_KEY, "ProxyServer", data, reg_type)
    assert winproxy._read_baseline().server == ""
    assert winproxy.proxy_restore() == "restored"
    # Static mode writes the "" back as a real REG_SZ; safe mode never
    # touched ProxyServer, so the user's own stays.
    server = "" if pac_url is None else "corp:8080"
    assert fake_reg.value(IE_KEY, "ProxyServer") == (server, REG_SZ)
    assert fake_reg.live() == (0, server, ABSENT)
    assert fake_reg.record() is None


@pytest.mark.parametrize("pac_url", [None, PAC_URL], ids=["static", "safe"])
@pytest.mark.parametrize("data, reg_type", NOT_TEXT, ids=NOT_TEXT_IDS)
def test_unwritable_recorded_pac_reads_as_empty(fake_reg, pac_url, data, reg_type):
    fake_reg.set_live(0, "", CORP_PAC)
    winproxy.proxy_enable(ADDR, pac_url=pac_url)
    fake_reg.put(RESTORE_KEY, "AutoConfigURL", data, reg_type)
    base = winproxy._read_baseline()
    assert (base.pac_present, base.pac) == (True, "")
    # Still SNIper's footprint (static: the PAC it emptied; safe: its URL),
    # so it is undone, and the script comes back empty, never as the garbage.
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.value(IE_KEY, "AutoConfigURL") == ("", REG_SZ)
    assert fake_reg.live() == (0, "", "")
    assert fake_reg.record() is None


@pytest.mark.parametrize("name", ["ProxyServer", "AutoConfigURL"])
def test_reenable_rewrites_an_unwritable_recorded_string_as_empty(fake_reg, name):
    fake_reg.set_live(0, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR)
    fake_reg.put(RESTORE_KEY, name, 5, REG_DWORD)
    winproxy.proxy_enable(ADDR2)  # a new footprint: the record is rewritten
    rec = fake_reg.record(types=True)
    assert rec[name] == ("", REG_SZ)
    assert rec["AppliedProxyServer"] == (ADDR2, REG_SZ)
    assert rec["Complete"] == (1, REG_DWORD)
    assert fake_reg.live() == (1, ADDR2, "")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == ((0, "", CORP_PAC) if name == "ProxyServer"
                               else (0, "corp:8080", ""))


# ── Without a registry (non-Windows) ─────────────────────────────────────────
def test_no_registry_means_no_op(monkeypatch):
    monkeypatch.setattr(winproxy, "IS_WINDOWS", False)
    monkeypatch.setattr(winproxy, "winreg", None)
    assert winproxy.proxy_enable(ADDR) is None
    assert winproxy.proxy_restore() is None
    assert winproxy.recover_orphaned_proxy() is None
    assert winproxy._proxy_gpo_locked() is False
