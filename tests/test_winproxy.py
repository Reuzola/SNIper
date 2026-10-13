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
from fakewinreg import (ABSENT, IE_KEY, REG_DWORD, REG_SZ, RESTORE_KEY,
                        SETTINGS_KEY, SNIPER_KEY)

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
CORP_PAC = "http://corp/proxy.pac"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()


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
    assert fake_reg.record(types=True) == {
        "ProxyEnable": (0, REG_DWORD),
        "ProxyServer": ("", REG_SZ),
        "AutoConfigURLPresent": (0, REG_DWORD),
        "AppliedProxyServer": (ADDR, REG_SZ),
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
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR)
    record = fake_reg.record()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_enable(ADDR) is None
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
    # Live values were never changed, so they aren't the footprint: "kept".
    assert winproxy.proxy_restore() == "kept"
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is None


def test_record_delete_failure_reports_restored_then_kept(fake_reg):
    winproxy.proxy_enable(ADDR)
    fake_reg.fail.add("DeleteKey")
    assert winproxy.proxy_restore() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is not None
    fake_reg.fail.clear()
    mark = len(fake_reg.ops)
    # Next time the live values are genuine, not the footprint.
    assert winproxy.proxy_restore() == "kept"
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


# ── Without a registry (non-Windows) ─────────────────────────────────────────
def test_no_registry_means_no_op(monkeypatch):
    monkeypatch.setattr(winproxy, "IS_WINDOWS", False)
    monkeypatch.setattr(winproxy, "winreg", None)
    assert winproxy.proxy_enable(ADDR) is None
    assert winproxy.proxy_restore() is None
    assert winproxy.recover_orphaned_proxy() is None
    assert winproxy._proxy_gpo_locked() is False
