"""Tests for record ownership in sniper.winproxy, on the fake registry.

Every record names the process and session that applied it, so the guardian
can restore exactly its own session and nothing else: another session's
record, or an older one with no session at all, is "not-ours" and left
completely untouched. "already" means the live proxy is no longer SNIper's
footprint but already equals the genuine values (someone restored first).
Every read-decide-write runs under the cross-process state lock.
"""
from __future__ import annotations

import re

import pytest

import sniper.procutil as procutil
import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, IE_KEY, REG_DWORD, REG_QWORD, REG_SZ, RESTORE_KEY,
                        SNIPER_KEY)

ADDR = "127.0.0.1:8881"
ADDR2 = "127.0.0.1:9999"
URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
CORP_PAC = "http://corp/p.pac"
SID = "0123456789abcdef"
SID2 = "fedcba9876543210"
IE = IE_KEY.lower()
REC = RESTORE_KEY.lower()
# A realistic FILETIME: well beyond 32 bits, so it needs the REG_QWORD.
OWNER = (4242, 133_700_000_000_000_000)
OWNER2 = (5151, 133_800_000_000_000_000)
WRITES = {"SetValueEx", "DeleteValue", "DeleteKey", "CreateKey"}


@pytest.fixture
def owner(monkeypatch):
    """procutil.process_identity, as winproxy sees it, returns owner.value."""
    holder = type("Owner", (), {"value": OWNER})()
    monkeypatch.setattr(procutil, "process_identity", lambda pid=None: holder.value)
    return holder


def writes(fake, path=None, start=0):
    return [op for op in fake.ops[start:] if path is None or op[1] == path]


def api_writes(fake, start=0):
    return [c for c in fake.calls[start:] if c[0] in WRITES]


def old_record(fake, enable, server, applied=ADDR, mode=None):
    """A complete record as v1.1.7 (applied, no mode) or Step 2 (mode) wrote
    it: no OwnerPid, OwnerCreateTime or SessionId."""
    fake.put(RESTORE_KEY, "ProxyEnable", enable, REG_DWORD)
    fake.put(RESTORE_KEY, "ProxyServer", server, REG_SZ)
    fake.put(RESTORE_KEY, "AutoConfigURLPresent", 0, REG_DWORD)
    if applied is not None:
        fake.put(RESTORE_KEY, "AppliedProxyServer", applied, REG_SZ)
    if mode is not None:
        fake.put(RESTORE_KEY, "AppliedMode", mode, REG_SZ)
    fake.put(RESTORE_KEY, "Complete", 1, REG_DWORD)


# ── The record names its owner ───────────────────────────────────────────────
@pytest.mark.parametrize("pac_url", [None, URL], ids=["static", "pac"])
def test_record_carries_owner_and_session_before_complete(fake_reg, owner, pac_url):
    winproxy.proxy_enable(ADDR, pac_url=pac_url, session_id=SID)
    rec = fake_reg.record(types=True)
    assert rec["OwnerPid"] == (OWNER[0], REG_DWORD)
    assert rec["OwnerCreateTime"] == (OWNER[1], REG_QWORD)
    assert rec["SessionId"] == (SID, REG_SZ)
    # All three are part of the commit: written before Complete, which is
    # still the last record write and still precedes every live write.
    rec_sets = [op[2] for op in fake_reg.ops if op[1] == REC and op[0] == "SetValueEx"]
    assert rec_sets[-1] == "Complete"
    assert {"OwnerPid", "OwnerCreateTime", "SessionId"} <= set(rec_sets[:-1])
    first_live = min(i for i, op in enumerate(fake_reg.ops) if op[1] == IE)
    assert fake_reg.ops.index(("SetValueEx", REC, "Complete")) < first_live
    assert winproxy.current_session_id() == SID


def test_a_new_session_id_for_every_apply_without_one(fake_reg, owner):
    winproxy.proxy_enable(ADDR)
    first = winproxy.current_session_id()
    assert re.fullmatch(r"[0-9a-f]{16}", first)
    winproxy.proxy_enable(ADDR)
    second = winproxy.current_session_id()
    assert re.fullmatch(r"[0-9a-f]{16}", second) and second != first


def test_current_session_id_without_a_usable_record(fake_reg, owner):
    assert winproxy.current_session_id() is None           # no record
    old_record(fake_reg, 0, "")
    assert winproxy.current_session_id() is None           # predates sessions
    fake_reg.keys.pop(REC)
    winproxy.proxy_enable(ADDR, session_id=SID)
    fake_reg.put(RESTORE_KEY, "Complete", 0, REG_DWORD)
    assert winproxy.current_session_id() is None           # incomplete
    assert writes(fake_reg, start=len(fake_reg.ops)) == []


def test_garbage_owner_values_read_as_unknown(fake_reg, owner):
    winproxy.proxy_enable(ADDR, session_id=SID)
    fake_reg.put(RESTORE_KEY, "OwnerPid", "not a number", REG_SZ)
    fake_reg.put(RESTORE_KEY, "SessionId", 1234, REG_DWORD)
    base = winproxy._read_baseline()
    assert (base.owner_pid, base.session_id) == (None, None)
    assert winproxy.proxy_restore(session_id=SID) == "not-ours"
    assert winproxy.proxy_restore() == "restored"  # recovery still works


# ── Idempotent re-apply ──────────────────────────────────────────────────────
def test_reapply_updates_owner_and_session_but_never_the_genuine_values(fake_reg, owner):
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR, session_id=SID)
    owner.value = OWNER2
    winproxy.proxy_enable(ADDR, session_id=SID2)  # same address, new session
    rec = fake_reg.record()
    assert (rec["OwnerPid"], rec["OwnerCreateTime"], rec["SessionId"]) == OWNER2 + (SID2,)
    # The live values now look like SNIper's; they were never captured.
    assert (rec["ProxyEnable"], rec["ProxyServer"], rec["AutoConfigURL"]) == \
        (1, "corp:8080", CORP_PAC)
    assert rec["Complete"] == 1
    assert winproxy.proxy_restore(session_id=SID) == "not-ours"
    assert winproxy.proxy_restore(session_id=SID2) == "restored"
    assert fake_reg.live() == (1, "corp:8080", CORP_PAC)


def test_reapply_with_a_new_session_by_the_same_process(fake_reg, owner):
    # The cancelled sign-out re-apply: same process, same address, new session.
    winproxy.proxy_enable(ADDR, session_id=SID)
    mark = len(fake_reg.ops)
    winproxy.proxy_enable(ADDR, session_id=SID2)
    assert ("SetValueEx", REC, "SessionId") in fake_reg.ops[mark:]
    assert fake_reg.record()["Complete"] == 1
    assert winproxy.current_session_id() == SID2
    assert winproxy.proxy_restore(session_id=SID) == "not-ours"  # the old guardian's


def test_reapply_by_another_process_with_the_same_session_takes_ownership(fake_reg, owner):
    winproxy.proxy_enable(ADDR, session_id=SID)
    owner.value = OWNER2
    mark = len(fake_reg.ops)
    winproxy.proxy_enable(ADDR, session_id=SID)
    assert writes(fake_reg, REC, mark)  # rewritten: the owner changed
    assert fake_reg.record()["OwnerPid"] == OWNER2[0]


def test_reapply_takes_over_an_old_record(fake_reg, owner):
    old_record(fake_reg, 1, "corp:8080", mode="static")
    fake_reg.set_live(1, ADDR, ABSENT)
    winproxy.proxy_enable(ADDR, session_id=SID)
    rec = fake_reg.record()
    assert rec["SessionId"] == SID and rec["OwnerPid"] == OWNER[0]
    assert (rec["ProxyEnable"], rec["ProxyServer"]) == (1, "corp:8080")


# ── "not-ours" ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("pac_url", [None, URL], ids=["static", "pac"])
def test_another_sessions_record_is_left_completely_alone(fake_reg, owner, pac_url):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=pac_url, session_id=SID)
    live, record = fake_reg.live(), fake_reg.record()
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.calls)
    assert winproxy.proxy_restore(session_id="other") == "not-ours"
    assert winproxy.proxy_restore(session_id=SID2) == "not-ours"
    assert api_writes(fake_reg, mark) == []
    assert fake_reg.refresh_calls == []
    assert (fake_reg.live(), fake_reg.record()) == (live, record)
    # Its own session restores it.
    assert winproxy.proxy_restore(session_id=SID) == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)
    assert fake_reg.record() is None and not fake_reg.exists(SNIPER_KEY)


@pytest.mark.parametrize("make", ["v117", "step2-static", "step2-pac", "legacy"])
def test_old_records_are_never_a_sessions_own(fake_reg, owner, make):
    if make == "step2-pac":
        old_record(fake_reg, 0, "", mode="pac")
        fake_reg.put(RESTORE_KEY, "AppliedAutoConfigURL", URL, REG_SZ)
        fake_reg.set_live(0, "", URL)
    else:
        old_record(fake_reg, 0, "", applied=None if make == "legacy" else ADDR,
                   mode="static" if make == "step2-static" else None)
        fake_reg.set_live(1, ADDR, ABSENT)
    live, record = fake_reg.live(), fake_reg.record()
    mark = len(fake_reg.calls)
    assert winproxy.proxy_restore(session_id=SID) == "not-ours"
    assert api_writes(fake_reg, mark) == []
    assert (fake_reg.live(), fake_reg.record()) == (live, record)
    # Launch recovery (no session) still restores them exactly as before.
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live() == (0, "", ABSENT)
    assert fake_reg.record() is None


def test_not_ours_needs_a_record(fake_reg, owner):
    assert winproxy.proxy_restore(session_id=SID) is None


@pytest.mark.parametrize("pac_url", [None, URL], ids=["static", "pac"])
def test_recover_handles_a_new_record_whatever_its_session(fake_reg, owner, pac_url):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=pac_url, session_id=SID)
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert fake_reg.live() == (1, "corp:8080", ABSENT)


# ── "already" ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("genuine", [
    (0, "", ABSENT), (1, "corp:8080", ABSENT), (0, "", CORP_PAC), (1, "corp:8080", ""),
], ids=["clean", "manual", "pac", "empty-pac"])
@pytest.mark.parametrize("pac_url", [None, URL], ids=["static", "pac"])
def test_already_back_to_genuine(fake_reg, owner, genuine, pac_url):
    fake_reg.set_live(*genuine)
    winproxy.proxy_enable(ADDR, pac_url=pac_url, session_id=SID)
    assert fake_reg.live() != genuine
    fake_reg.set_live(*genuine)  # e.g. the guardian restored first
    fake_reg.refresh_calls.clear()
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore(session_id=SID) == "already"
    assert writes(fake_reg, IE, mark) == []
    assert fake_reg.refresh_calls == []
    assert fake_reg.live() == genuine
    assert fake_reg.record() is None


@pytest.mark.parametrize("pac_url", [None, URL], ids=["static", "pac"])
@pytest.mark.parametrize("near", [
    (0, "corp:8080", CORP_PAC), (1, "corp:9090", CORP_PAC),
    (1, "corp:8080", ABSENT), (1, "corp:8080", ""),
], ids=["flag", "server", "pac-absent", "pac-empty"])
def test_almost_genuine_is_kept_not_already(fake_reg, owner, pac_url, near):
    fake_reg.set_live(1, "corp:8080", CORP_PAC)
    winproxy.proxy_enable(ADDR, pac_url=pac_url, session_id=SID)
    fake_reg.set_live(*near)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "kept"
    assert writes(fake_reg, IE, mark) == []


def test_unreadable_flag_is_kept_not_already_in_safe_mode(fake_reg, owner):
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    fake_reg.set_live(1, "corp:8080", ABSENT)
    fake_reg.put(IE_KEY, "ProxyEnable", "x", REG_SZ)  # not the genuine DWORD 1
    assert winproxy.proxy_restore() == "kept"


def test_footprint_takes_precedence_over_already_static(fake_reg, owner):
    # The user's own manual proxy WAS SNIper's address: the live values are
    # SNIper's footprint and the genuine ones at the same time. The footprint
    # check comes first, so it is "restored" (the genuine values written).
    fake_reg.set_live(1, ADDR, ABSENT)
    winproxy.proxy_enable(ADDR, session_id=SID)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore(session_id=SID) == "restored"
    assert writes(fake_reg, IE, mark)
    assert fake_reg.live() == (1, ADDR, ABSENT)


def test_footprint_takes_precedence_over_already_pac(fake_reg, owner):
    # A genuine setup script identical to the URL we apply (a leftover that
    # became the genuine value): footprint first, so our URL is "restored".
    fake_reg.set_live(0, "", URL)
    winproxy.proxy_enable(ADDR, pac_url=URL, session_id=SID)
    assert fake_reg.live() == (0, "", URL)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore(session_id=SID) == "restored"
    assert writes(fake_reg, IE, mark)


def test_legacy_record_is_restored_even_when_already_genuine(fake_reg, owner):
    # Pre-footprint records are restored unconditionally, exactly as v1.1.7:
    # "already" never applies to them.
    old_record(fake_reg, 0, "", applied=None)
    fake_reg.set_live(0, "", ABSENT)
    mark = len(fake_reg.ops)
    assert winproxy.proxy_restore() == "restored"
    assert writes(fake_reg, IE, mark)


# ── The state lock ───────────────────────────────────────────────────────────
def _inside_locks(fake, start, end):
    """True if every HKCU registry call in calls[start:end] ran under the
    lock. HKLM reads are the Group Policy check: no part of the record."""
    return all(any(a <= i < b for a, b in fake.lock_spans)
               for i in range(start, end) if not fake.calls[i][1].startswith("hklm\\"))


@pytest.mark.parametrize("op", [
    lambda: winproxy.proxy_enable(ADDR),
    lambda: winproxy.proxy_enable(ADDR, pac_url=URL),
    lambda: winproxy.proxy_restore(),
    lambda: winproxy.proxy_restore(session_id=SID),
    lambda: winproxy.recover_orphaned_proxy(),
    lambda: winproxy.current_session_id(),
], ids=["enable-static", "enable-pac", "restore", "restore-session", "recover",
        "current-session"])
def test_every_record_access_runs_under_the_state_lock(fake_reg, owner, op):
    winproxy.proxy_enable(ADDR, session_id=SID)
    fake_reg.lock_spans.clear()
    mark = len(fake_reg.calls)
    op()
    assert len(fake_reg.lock_spans) == 1  # one hold per operation
    assert fake_reg.calls[mark:], "the operation made no registry call at all"
    assert _inside_locks(fake_reg, mark, len(fake_reg.calls))


@pytest.mark.parametrize("old, new", [(None, URL), (URL, None)])
def test_mode_switch_restores_under_the_same_hold(fake_reg, owner, old, new):
    # The other mode's record is restored inside the enable's own hold: the
    # recorder fails the test if the lock is taken a second time.
    fake_reg.set_live(1, "corp:8080", ABSENT)
    winproxy.proxy_enable(ADDR, pac_url=old, session_id=SID)
    fake_reg.lock_spans.clear()
    mark = len(fake_reg.calls)
    winproxy.proxy_enable(ADDR2, pac_url=new, session_id=SID2)
    assert len(fake_reg.lock_spans) == 1
    assert _inside_locks(fake_reg, mark, len(fake_reg.calls))
    assert winproxy.current_session_id() == SID2


def test_gpo_locked_enable_takes_no_lock(fake_reg, owner):
    fake_reg.set_gpo_locked(True)
    winproxy.proxy_enable(ADDR)
    assert fake_reg.lock_spans == []


def test_is_genuine_never_raises():
    base = winproxy.Baseline(1, "corp:8080", False, None, ADDR, "static", None,
                             None, None, None)
    assert winproxy._is_genuine((1, "corp:8080", None), base)
    assert not winproxy._is_genuine(("garbage", "corp:8080", None), base)
    assert not winproxy._is_genuine((None, "corp:8080", None), base)
    assert not winproxy._is_genuine((1, "corp:8080", ""), base)
