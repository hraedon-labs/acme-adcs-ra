"""The coalescer's in-memory window index is bounded, not just its rows.

Round-7 pre-Daybreak review. The 2026-08-15 rescan-2 fix made *durable* audit
growth a function of elapsed time: repeated denials of the same kind update a
row that is already committed, so ten thousand attempts cost a handful of rows.
Nothing, however, bounded the dictionary that tracks which windows are open.

A key was dropped only when that same key was recorded again after its window
had lapsed, and no sweep ever ran. For account-creation denials that is
harmless — the key is (event type x server-chosen reason), a small fixed set.
The round-5 additions changed the shape: ``finalize-csr-mismatch`` and
``finalize-policy-denied`` put ``order_id`` in the key, so a client that
finalizes many orders badly mints a fresh key each time and none is ever
collected. The installer configures the app pool with ``idleTimeout=00:00:00``
and ``recycling.periodicRestart.time=00:00:00``, so the worker process does not
recycle and reclaim it either.

Every test names the mutation that breaks it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from acme_adcs_ra.audit_coalesce import MAX_OPEN_WINDOWS, DenialCoalescer
from acme_adcs_ra.store import Store


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _store(tmp_path: Path) -> Store:
    return Store(tmp_path / "audit.db")


def _rows(store: Store) -> list[sqlite3.Row]:
    con = sqlite3.connect(store._db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        return list(con.execute("SELECT * FROM audit_log ORDER BY id").fetchall())
    finally:
        con.close()


def _finalize_denial(order_id: str, account_id: str = "acct-1") -> dict[str, Any]:
    return {
        "event_type": "finalize-policy-denied",
        "outcome": "denied",
        "account_id": account_id,
        "order_id": order_id,
        "details": {"reason": "requested SAN is out of scope"},
    }


class TestOpenWindowIndexIsBounded:
    def test_distinct_order_ids_do_not_grow_the_index_without_bound(
        self, tmp_path: Path
    ) -> None:
        """THE FINDING.

        Mutation: delete the ``_evict_for_new_window`` call in ``record``.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_open_windows=32, clock=_Clock())

        for i in range(500):
            coalescer.record(store, **_finalize_denial(f"order-{i}"))

        assert coalescer.open_window_count() <= 32

    def test_eviction_loses_no_durable_evidence(self, tmp_path: Path) -> None:
        """Nothing is deleted; every denial is still on disk with its count.

        Eviction only gives up the ability to fold FUTURE repeats into an
        already-committed row. If it ever removed a row, the remediation would
        have become the pruner this design refuses to be.

        Mutation: have ``_evict_for_new_window`` delete audit rows, or make
        eviction skip writing the new row.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_open_windows=8, clock=_Clock())

        for i in range(64):
            coalescer.record(store, **_finalize_denial(f"order-{i}"))

        rows = _rows(store)
        assert len(rows) == 64
        assert {r["order_id"] for r in rows} == {f"order-{i}" for i in range(64)}
        assert all(json.loads(r["details"])["denial_count"] == 1 for r in rows)

    def test_expired_windows_are_evicted_before_live_ones(
        self, tmp_path: Path
    ) -> None:
        """A window that can no longer be folded into goes first.

        Mutation: drop the expiry pass and evict purely by ``opened_at``.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, max_open_windows=4, clock=clock)

        # Four windows open, then all four lapse.
        for i in range(4):
            coalescer.record(store, **_finalize_denial(f"stale-{i}"))
        clock.advance(61)

        # One more key: the four lapsed entries are collectable, so the index
        # holds only the newcomer.
        coalescer.record(store, **_finalize_denial("fresh-0"))
        assert coalescer.open_window_count() == 1

        # And the newcomer is the LIVE one: a repeat folds into its row rather
        # than opening a second.
        coalescer.record(store, **_finalize_denial("fresh-0"))
        fresh_rows = [r for r in _rows(store) if r["order_id"] == "fresh-0"]
        assert len(fresh_rows) == 1
        assert json.loads(fresh_rows[0]["details"])["denial_count"] == 2

    def test_a_live_window_survives_below_the_cap(self, tmp_path: Path) -> None:
        """Under the cap, behaviour is exactly what it was before.

        Mutation: delete the under-cap early return in
        ``_evict_for_new_window``.

        The clock MUST advance here (an earlier version froze it, so the
        expiry pass had nothing to sweep and the test was blind), and the
        assertion that actually catches the mutation is the LAST one. A
        previous draft asserted only the ``previous_window`` hand-off, which
        the mutation does NOT break: ``closed`` is captured from the dict
        entry before eviction runs, so the breadcrumb survives even when the
        sweep destroys the entry it came from. What the unguarded sweep does
        add is an ``_evicted`` increment, which stamps
        ``coalescer_evictions`` on the reopened row -- so the absence of that
        marker, below the cap, is the detection. This is the third rewrite of
        this test; each of the first two passed against its own mutation.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, max_open_windows=64, clock=clock)

        for _ in range(10):
            coalescer.record(store, **_finalize_denial("order-a"))
        # order-a lapses while a handful of other keys stay well under the cap.
        clock.advance(61)
        for i in range(5):
            coalescer.record(store, **_finalize_denial(f"order-b{i}"))
        # Reopening order-a must still hand off its predecessor's tally: under
        # the cap nothing may be swept.
        coalescer.record(store, **_finalize_denial("order-a"))

        a_rows = [r for r in _rows(store) if r["order_id"] == "order-a"]
        assert len(a_rows) == 2
        assert json.loads(a_rows[0]["details"])["denial_count"] == 10
        assert json.loads(a_rows[1]["details"])["previous_window"]["denial_count"] == 10
        # BELOW THE CAP NOTHING IS EVER EVICTED. If this marker appears here,
        # the expiry sweep ran without the index being full.
        for row in _rows(store):
            assert "coalescer_evictions" not in json.loads(row["details"]), (
                "the index shed a window while below its cap"
            )

    def test_the_expiry_sweep_is_counted_as_an_eviction(
        self, tmp_path: Path
    ) -> None:
        """A victim swept by the expiry pass must not look like a first window.

        Only the LRU loop used to increment ``_evicted`` — and the expiry pass is
        the branch an attacker drives, since minting fresh keys to reach the cap
        is what triggers the sweep. The victim's successor row then carried
        neither ``previous_window`` nor ``coalescer_evictions``, making it
        byte-identical to a first-ever window.

        Mutation: drop the ``self._evicted += 1`` from the expiry pass. (An
        earlier draft asserted ``previous_window OR coalescer_evictions``; this
        scenario cannot rely on ``previous_window`` — the victim's lapsed entry
        is collected by the cap eviction at filler-3, so its reopen finds no
        dict entry to hand off. That is precisely the ambiguity the marker
        exists to resolve, so the MARKER itself is asserted.)
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, max_open_windows=4, clock=clock)

        for _ in range(7):
            coalescer.record(store, **_finalize_denial("victim"))
        clock.advance(61)
        # Exactly enough fillers to reach the cap once, so the expiry pass sweeps
        # the victim's lapsed entry and the LRU loop never has to run.
        for i in range(4):
            coalescer.record(store, **_finalize_denial(f"filler-{i}"))
        # Now lapse the fillers too, so the victim's reopen is served entirely by
        # the expiry pass. If only the LRU loop counted, nothing here would --
        # which is what makes this test able to fail.
        clock.advance(61)
        coalescer.record(store, **_finalize_denial("victim"))

        rows = [r for r in _rows(store) if r["order_id"] == "victim"]
        assert len(rows) == 2
        assert json.loads(rows[0]["details"])["denial_count"] == 7
        successor = json.loads(rows[1]["details"])
        assert "coalescer_evictions" in successor, (
            "the expiry sweep is an eviction; the row it makes room for must say so"
        )

    def test_the_row_displacing_an_entry_carries_the_marker(
        self, tmp_path: Path
    ) -> None:
        """THE STAMP-ORDERING FINDING.

        ``coalescer_evictions`` was stamped from ``_evicted`` BEFORE the
        eviction that made room for the row, so a brand-new key whose open
        displaced an LRU entry carried neither ``previous_window`` (it has no
        predecessor) nor ``coalescer_evictions`` — byte-identical to a
        first-ever window on an index that has never shed anything.

        Mutation: move the ``_evict_for_new_window`` call back below the
        ``store.record_audit`` that persists the row.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(3600, max_open_windows=4, clock=clock)

        for i in range(4):
            coalescer.record(store, **_finalize_denial(f"live-{i}"))
        # All four windows are LIVE (no clock advance). One more NEW key must
        # displace the least-recently-touched one, and its row is the affected
        # row: no previous_window, so the marker is the only breadcrumb.
        coalescer.record(store, **_finalize_denial("newcomer"))

        newcomer = [
            json.loads(r["details"])
            for r in _rows(store)
            if r["order_id"] == "newcomer"
        ]
        assert len(newcomer) == 1
        assert "previous_window" not in newcomer[0]
        assert newcomer[0]["coalescer_evictions"] >= 1, (
            "the row that displaced a window carries no eviction marker"
        )

    def test_the_previous_window_handoff_still_works(self, tmp_path: Path) -> None:
        """The ``previous_window`` breadcrumb is preserved under the cap.

        This is the behaviour a naive "sweep everything expired on every
        record" would have silently destroyed, so it is asserted here as well
        as in the rescan-2 suite.

        Mutation: sweep expired windows unconditionally at the top of
        ``record``.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, max_open_windows=64, clock=clock)

        for _ in range(7):
            coalescer.record(store, **_finalize_denial("order-a"))
        clock.advance(61)
        coalescer.record(store, **_finalize_denial("order-a"))

        rows = [r for r in _rows(store) if r["order_id"] == "order-a"]
        assert len(rows) == 2
        assert json.loads(rows[1]["details"])["previous_window"]["denial_count"] == 7

    def test_reopening_a_lapsed_key_at_the_cap_keeps_live_neighbours(
        self, tmp_path: Path
    ) -> None:
        """Reopening a lapsed key must not cost a live neighbour its window.

        NOT a mutation detector, and deliberately so: an earlier draft guarded
        the eviction call with ``if key not in self._windows`` and claimed a
        test for it. The guard is unreachable-by-construction dead weight — a
        key present here is always one whose window has lapsed, because a live
        key folds and returns before this point, so the expiry pass frees its
        slot either way. Both the guard and that test were removed. This one
        stays as a behavioural fact worth pinning at the cap boundary.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, max_open_windows=2, clock=clock)

        coalescer.record(store, **_finalize_denial("order-a"))
        clock.advance(61)
        coalescer.record(store, **_finalize_denial("order-b"))
        coalescer.record(store, **_finalize_denial("order-a"))
        coalescer.record(store, **_finalize_denial("order-b"))

        b_rows = [r for r in _rows(store) if r["order_id"] == "order-b"]
        assert len(b_rows) == 1
        assert json.loads(b_rows[0]["details"])["denial_count"] == 2

    def test_account_creation_denials_are_unaffected(self, tmp_path: Path) -> None:
        """The unauthenticated flood path keys on server-chosen data only.

        Its key set is small and fixed, so the cap can never bite there. This
        is the positive control: the fix must not change the class of denial
        the coalescer was originally built for.

        Mutation: add ``kid`` back into the coalescing key.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, max_open_windows=2, clock=_Clock())

        for i in range(2000):
            coalescer.record(
                store,
                event_type="account-creation-denied",
                outcome="failed",
                details={"reason": "unknown EAB kid", "kid": f"kid-{i}"},
            )

        rows = _rows(store)
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 2000
        assert coalescer.open_window_count() == 1

    def test_the_shipped_default_is_a_real_cap(self) -> None:
        """Mutation: set ``MAX_OPEN_WINDOWS`` to a sentinel meaning unlimited."""
        assert isinstance(MAX_OPEN_WINDOWS, int)
        assert 0 < MAX_OPEN_WINDOWS <= 65536
        assert DenialCoalescer(60)._max_open_windows == MAX_OPEN_WINDOWS

    def test_a_nonsense_cap_is_refused(self) -> None:
        """Mutation: accept 0 and treat it as unlimited."""
        with pytest.raises(ValueError, match="max_open_windows"):
            DenialCoalescer(60, max_open_windows=0)


class TestTheKeyExcludesAttackerChosenData:
    """The module docstring's central promise, applied to every coalesced class.

    ``IssuancePolicy.evaluate`` returns prose containing the offending SAN, and
    ``finalize`` passed it through as ``details["reason"]`` — which the coalescer
    keys on. One order plus one varied identifier per request therefore produced
    one durable row per request, which is precisely the bound-defeat the key is
    documented to prevent.
    """

    def test_varying_the_san_does_not_defeat_the_bound(self, tmp_path: Path) -> None:
        """THE FINDING. Mutation: key on ``reason`` instead of ``reason_code``."""
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())

        for i in range(40):
            coalescer.record(
                store,
                event_type="finalize-policy-denied",
                outcome="denied",
                account_id="acct-1",
                order_id="order-1",
                details={
                    "reason": f"SAN out of scope for kid kid-001-0123456789abcdef: host{i}.evil.test",
                    "reason_code": "san-out-of-scope",
                },
            )

        rows = _rows(store)
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 40
        assert coalescer.open_window_count() == 1

    def test_distinct_reason_codes_still_keep_distinct_rows(
        self, tmp_path: Path
    ) -> None:
        """Coalescing must not merge genuinely different failures.

        Mutation: key on ``event_type`` alone, or drop ``reason_code`` from the
        key entirely.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())

        for code in ("san-out-of-scope", "no-sans-requested", "unknown-kid"):
            for _ in range(5):
                coalescer.record(
                    store,
                    event_type="finalize-policy-denied",
                    outcome="denied",
                    account_id="acct-1",
                    order_id="order-1",
                    details={"reason": f"prose for {code}", "reason_code": code},
                )

        rows = _rows(store)
        assert len(rows) == 3
        assert all(json.loads(r["details"])["denial_count"] == 5 for r in rows)

    def test_the_prose_reason_is_still_recorded_in_full(
        self, tmp_path: Path
    ) -> None:
        """Keying on a code must not cost the investigator the detail.

        Mutation: drop ``reason`` from the details written to the row.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        coalescer.record(
            store,
            event_type="finalize-policy-denied",
            outcome="denied",
            account_id="acct-1",
            order_id="order-1",
            details={
                "reason": "SAN out of scope for kid kid-001-0123456789abcdef: first.evil.test",
                "reason_code": "san-out-of-scope",
            },
        )
        details = json.loads(_rows(store)[0]["details"])
        assert details["reason"] == "SAN out of scope for kid kid-001-0123456789abcdef: first.evil.test"

    def test_a_call_site_without_a_reason_code_still_keys_on_reason(
        self, tmp_path: Path
    ) -> None:
        """Back-compatibility: the account-denial classes send no code.

        Mutation: key on ``reason_code`` only, so every codeless call site
        collapses into one window regardless of reason.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        for reason in ("unknown EAB kid", "EAB MAC verification failed"):
            for _ in range(4):
                coalescer.record(
                    store,
                    event_type="account-creation-denied",
                    outcome="failed",
                    details={"reason": reason},
                )
        assert len(_rows(store)) == 2

    def test_an_explicit_empty_reason_code_does_not_fall_back_to_prose(
        self, tmp_path: Path
    ) -> None:
        """A falsy-but-present reason_code must not reopen the prose key.

        ``str(details.get("reason_code") or reason)`` treated an explicitly
        EMPTY code as absent and keyed on ``reason`` — which is attacker-chosen
        prose on the finalize paths. No current call site sends an empty code,
        but one typo away from it the bound would be silently defeated: five
        requests with varying prose and reason_code="" produced five durable
        rows. Keying on the explicit "" folds all of them into one window.

        Mutation: revert the key line to ``str(... or reason)``.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        for i in range(5):
            coalescer.record(
                store,
                event_type="finalize-policy-denied",
                outcome="denied",
                account_id="acct-1",
                order_id="order-1",
                details={"reason": f"attacker-chosen prose {i}", "reason_code": ""},
            )
        rows = _rows(store)
        assert len(rows) == 1, "an empty reason_code must not key on the prose"
        assert json.loads(rows[0]["details"])["denial_count"] == 5

    def test_caller_supplied_markers_cannot_forge_eviction_state(
        self, tmp_path: Path
    ) -> None:
        """The coalescer's own breadcrumb fields are stripped on the way in.

        No call site sends these keys, but an investigator uses them to tell
        "first window for this key" from "the index dropped my predecessor",
        so a buggy or future call site passing them in must not be able to
        forge that judgement.

        Mutation: delete the two ``details.pop(...)`` calls in ``record``.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        coalescer.record(
            store,
            event_type="account-creation-denied",
            outcome="failed",
            details={
                "reason": "unknown EAB kid",
                "previous_window": {"denial_count": 99999},
                "coalescer_evictions": 99999,
            },
        )
        details = json.loads(_rows(store)[0]["details"])
        assert "previous_window" not in details
        assert "coalescer_evictions" not in details


class TestWindowInternalsAreBounded:
    def test_distinct_kid_tracking_is_capped_and_says_so(
        self, tmp_path: Path
    ) -> None:
        """``kid_samples`` was capped and ``distinct_kids`` was not.

        Mutation: remove the ``_max_distinct_kids`` guard in ``_extend``.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(
            3600, max_distinct_kids=16, clock=_Clock()
        )
        for i in range(500):
            coalescer.record(
                store,
                event_type="account-creation-denied",
                outcome="failed",
                details={"reason": "unknown EAB kid", "kid": f"kid-{i}"},
            )

        details = json.loads(_rows(store)[0]["details"])
        assert details["distinct_kids"] == 16
        assert details["distinct_kids_truncated"] is True
        # The security-relevant number stays EXACT regardless.
        assert details["denial_count"] == 500

    def test_an_untruncated_window_says_so_too(self, tmp_path: Path) -> None:
        """Mutation: hard-code ``distinct_kids_truncated`` to True."""
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_distinct_kids=16, clock=_Clock())
        for i in range(5):
            coalescer.record(
                store,
                event_type="account-creation-denied",
                outcome="failed",
                details={"reason": "unknown EAB kid", "kid": f"kid-{i}"},
            )
        details = json.loads(_rows(store)[0]["details"])
        assert details["distinct_kids"] == 5
        assert details["distinct_kids_truncated"] is False

    def test_the_sample_cap_applies_at_window_open(self, tmp_path: Path) -> None:
        """The first kid is subject to ``max_kid_samples`` too.

        The cap used to be enforced only in ``_extend``, so a window opened
        with ``max_kid_samples=0`` still carried one digest -- the cap held
        for every kid after the first and never for the first. The row only
        carries ``kid_digests`` once a fold rewrites it, so the second denial
        below is what makes the open-time append visible.

        Mutation: revert the open-time ``kid_samples`` append to unconditional.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_kid_samples=0, clock=_Clock())
        for _ in range(2):
            coalescer.record(
                store,
                event_type="account-creation-denied",
                outcome="failed",
                details={"reason": "unknown EAB kid", "kid": "kid-first-0123456789abcdef"},
            )
        details = json.loads(_rows(store)[0]["details"])
        assert details["kid_digests"] == []


class TestEvictionOrderingAndVisibility:
    def test_a_hot_window_survives_a_flood_of_cold_ones(
        self, tmp_path: Path
    ) -> None:
        """Eviction is least-recently-TOUCHED, not longest-open.

        Ordering by ``opened_at`` destroys the window that has been folding the
        longest — the one whose survival saves the most rows — and an attacker
        minting fresh keys steers that choice.

        Mutation: sort by ``opened_at`` instead of ``last_touch``.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(3600, max_open_windows=8, clock=clock)

        # The hot window opens FIRST, so opened_at ordering would evict it.
        for _ in range(5):
            coalescer.record(store, **_finalize_denial("hot"))
            clock.advance(1)

        for i in range(200):
            coalescer.record(store, **_finalize_denial(f"cold-{i}"))
            clock.advance(1)
            # Keep the hot window hot.
            coalescer.record(store, **_finalize_denial("hot"))
            clock.advance(1)

        hot_rows = [r for r in _rows(store) if r["order_id"] == "hot"]
        assert len(hot_rows) == 1
        assert json.loads(hot_rows[0]["details"])["denial_count"] == 205

    def test_the_window_opened_at_the_cap_is_actually_tracked(
        self, tmp_path: Path
    ) -> None:
        """Eviction must make room FOR the newcomer, not instead of it.

        Mutation: skip ``self._windows[key] = fresh`` when eviction ran, so the
        hottest key gets one durable row per denial forever.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_open_windows=4, clock=_Clock())

        for i in range(4):
            coalescer.record(store, **_finalize_denial(f"filler-{i}"))
        # This one opens at the cap and must survive as a live window.
        coalescer.record(store, **_finalize_denial("newcomer"))
        for _ in range(9):
            coalescer.record(store, **_finalize_denial("newcomer"))

        rows = [r for r in _rows(store) if r["order_id"] == "newcomer"]
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 10

    def test_eviction_is_visible_on_the_rows_it_affects(
        self, tmp_path: Path
    ) -> None:
        """An absent ``previous_window`` is ambiguous once eviction is running.

        Mutation: stop stamping ``coalescer_evictions``.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, max_open_windows=4, clock=_Clock())

        for i in range(4):
            coalescer.record(store, **_finalize_denial(f"k-{i}"))
        # Nothing evicted yet: no marker on these.
        assert all(
            "coalescer_evictions" not in json.loads(r["details"])
            for r in _rows(store)
        )

        for i in range(4, 12):
            coalescer.record(store, **_finalize_denial(f"k-{i}"))

        last = json.loads(_rows(store)[-1]["details"])
        assert last["coalescer_evictions"] >= 1


# ---------------------------------------------------------------------------
# End to end: the wiring, not just the coalescer
# ---------------------------------------------------------------------------
#
# Every test above drives DenialCoalescer directly, so all of them stayed green
# when finalize.py stopped sending ``reason_code`` at all — the fix was in the
# library and nothing proved the call site used it. This exercises the real
# route: one order, one EAB-authenticated client, a different out-of-scope SAN
# per finalize.


def _build_env(tmp_path: Path) -> tuple[Any, Any]:
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    from acme_adcs_ra.config import EABEntry, RAConfig
    from acme_adcs_ra.enrollment import FakeEnrollmentLeg
    from acme_adcs_ra.policy import IssuancePolicy
    from acme_adcs_ra.revocation import FakeRevocationLeg
    from acme_adcs_ra.server import ServerContext, create_app

    cfg = RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=_KID, mac_key=_MAC_B64)],
        san_scopes={_KID: {"dns_patterns": ["*.in-scope.local"]}},
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        nonce_rate_limit_per_second=0.0,
        audit_denial_coalesce_window_seconds=3600,
    )
    store = Store(cfg.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(cfg.eab_keys_by_kid()),
        san_scopes={k: s.dns_patterns for k, s in cfg.san_scopes.items()},
        template=cfg.adcs_template,
    )
    ctx = ServerContext(
        config=cfg,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(ctx)), ctx


_KID = "kid-001-0123456789abcdef"
_MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"


def test_one_order_with_varied_out_of_scope_sans_costs_one_row(
    tmp_path: Path,
) -> None:
    """THE END-TO-END FINDING.

    Mutation: drop ``reason_code`` from the ``finalize-policy-denied`` details
    in ``finalize.py``, or from ``PolicyDecision``.
    """
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from .hand_rolled_acme_client import HandRolledAcmeClient

    client, ctx = _build_env(tmp_path)
    mac = base64.urlsafe_b64decode(_MAC_B64 + "=" * ((-len(_MAC_B64)) % 4))
    acme = HandRolledAcmeClient(
        client, "http://testserver", ec.generate_private_key(ec.SECP256R1())
    )
    assert acme.new_account(_KID, mac).status_code in (200, 201)

    # ONE order carrying every out-of-scope name up front. SAN scope is enforced
    # at FINALIZE, not at newOrder, so the order is created — and because each
    # CSR below requests a name that IS one of these identifiers, the
    # order-identifier check (whose reason is a fixed string) passes and the
    # POLICY check is what denies. That is the path whose reason embeds the SAN.
    names = [f"h{i}.evil.test" for i in range(25)]
    order = acme.new_order(names).json()
    for authz_url in order["authorizations"]:
        authz = acme.get_authorization(authz_url).json()
        acme.validate_challenge(authz["challenges"][0]["url"])

    denied = 0
    for name in names:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        resp = acme.finalize_order(
            order["finalize"], csr.public_bytes(serialization.Encoding.DER)
        )
        if resp.status_code >= 400:
            denied += 1

    assert denied == 25, "every finalize should have been refused"

    con = sqlite3.connect(ctx.config.db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        rows = list(
            con.execute(
                "SELECT * FROM audit_log WHERE event_type = 'finalize-policy-denied'"
                " ORDER BY id"
            ).fetchall()
        )
    finally:
        con.close()

    assert len(rows) == 1, (
        f"{len(rows)} durable rows from one order in one window; the coalescing "
        "key absorbed attacker-chosen SANs"
    )
    # The prose that varies is still on the row, in full.
    assert "evil.test" in json.loads(rows[0]["details"])["reason"]
    assert json.loads(rows[0]["details"])["denial_count"] == 25


def test_csr_mismatch_finalizes_carry_a_stable_reason_code(
    tmp_path: Path,
) -> None:
    """THE SIBLING CALL SITE, end to end.

    ``finalize-csr-mismatch`` was left without a ``reason_code`` when
    ``finalize-policy-denied`` got one. Its ``reason`` is a fixed string today,
    so the bound holds -- but ``out_of_order`` (the attacker-chosen SAN list)
    sits in the same details dict one refactor away from being interpolated
    into that string, which is exactly how the policy-denied site defeated the
    bound. The first assertion pins the stable key at the real call site; the
    second pins the bound itself under varied attacker-chosen content.

    Mutation 1: drop ``reason_code`` from the ``finalize-csr-mismatch``
    details in ``finalize.py`` (row assertion fails).
    Mutation 2: interpolate ``out_of_order`` into that call site's ``reason``
    (row-count assertion fails).
    """
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from .hand_rolled_acme_client import HandRolledAcmeClient

    client, ctx = _build_env(tmp_path)
    mac = base64.urlsafe_b64decode(_MAC_B64 + "=" * ((-len(_MAC_B64)) % 4))
    acme = HandRolledAcmeClient(
        client, "http://testserver", ec.generate_private_key(ec.SECP256R1())
    )
    assert acme.new_account(_KID, mac).status_code in (200, 201)

    # One in-scope order; every CSR below asks for a name that is NOT one of
    # its identifiers, so the denial is the order-identifier (mismatch) check,
    # not the policy check -- the sibling path to the test above.
    order = acme.new_order(["ok.in-scope.local"]).json()
    authz = acme.get_authorization(order["authorizations"][0]).json()
    acme.validate_challenge(authz["challenges"][0]["url"])

    denied = 0
    for i in range(25):
        name = f"wrong{i}.evil.test"
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        resp = acme.finalize_order(
            order["finalize"], csr.public_bytes(serialization.Encoding.DER)
        )
        if resp.status_code >= 400:
            denied += 1

    assert denied == 25, "every finalize should have been refused"

    con = sqlite3.connect(ctx.config.db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        rows = list(
            con.execute(
                "SELECT * FROM audit_log WHERE event_type = 'finalize-csr-mismatch'"
                " ORDER BY id"
            ).fetchall()
        )
    finally:
        con.close()

    assert len(rows) == 1, (
        f"{len(rows)} durable rows from one order in one window; the mismatch "
        "coalescing key absorbed attacker-chosen SANs"
    )
    details = json.loads(rows[0]["details"])
    assert details["reason_code"] == "csr-san-mismatch"
    assert details["denial_count"] == 25
