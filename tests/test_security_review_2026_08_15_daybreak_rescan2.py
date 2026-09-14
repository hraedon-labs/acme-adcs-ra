"""Daybreak 2026-08-15 SECOND rescan, F4: bounded durable audit growth.

The finding (the long-standing WI-014): an allowlisted peer needs no account
and no valid EAB secret to make the RA write a durable audit row. Every
rejected ``newAccount`` persisted one SQLite row and one appended JSONL record,
with no cumulative bound and an attacker-chosen ``kid`` inside it.

Three previous waves deferred it because the obvious remediation is a *pruner*,
and deleting audit evidence is the operation an attacker most wants. The fix
here deletes nothing and loses no count: repeated denials of the same kind
update the row that is already committed, so durable growth is a function of
elapsed time rather than of request rate.

Every test below is mutation-checked; the mutation that breaks each one is
named in its docstring. A test that cannot fail against the pre-fix code is not
evidence — a lesson this repo has recorded twice.

The three installer findings from the same report (F1 manifest
self-authentication, F2 raced reparse points, F3 live-tree claim races) are
PowerShell and are covered in ``tests/pester/InstallVerify.Tests.ps1``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.audit_bounds import (
    MAX_DETAILS_CHARS,
    MAX_VALUE_CHARS,
    bound_details,
    bound_value,
)
from acme_adcs_ra.audit_coalesce import COALESCED_EVENT_TYPES, DenialCoalescer
from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient

KID = "kid-001"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
BASE_URL = "http://testserver"


def _mac_bytes() -> bytes:
    import base64

    return base64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))


class _Clock:
    """A monotonic clock the test drives, so windows expire without sleeping."""

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


def _denial(**details: Any) -> dict[str, Any]:
    return {
        "event_type": "account-creation-denied",
        "outcome": "failed",
        "details": details,
    }


# ---------------------------------------------------------------------------
# Part one: the attacker does not choose how big an audit row is
# ---------------------------------------------------------------------------


class TestBoundedAuditFields:
    def test_an_oversized_value_is_truncated_and_digested(self) -> None:
        """Mutation: return ``value`` unchanged from ``bound_value``."""
        kid = "A" * 50_000
        bounded = bound_value(kid)
        assert isinstance(bounded, str)
        assert len(bounded) < 500
        assert bounded.startswith("A" * MAX_VALUE_CHARS)
        assert "sha256:" in bounded
        assert "50000 chars" in bounded

    def test_the_digest_distinguishes_two_different_oversized_values(self) -> None:
        """Truncation alone would make every long kid look identical.

        Mutation: drop the digest suffix and keep only the prefix.
        """
        a = bound_value("A" * 5000)
        b = bound_value("A" * 4999 + "B")
        assert a != b

    def test_a_legitimate_value_is_left_exactly_as_it_was(self) -> None:
        """Mutation: truncate unconditionally."""
        assert bound_value(KID) == KID
        assert bound_value("A" * MAX_VALUE_CHARS) == "A" * MAX_VALUE_CHARS

    def test_nested_values_are_bounded_too(self) -> None:
        """Mutation: only bound top-level strings."""
        out = bound_value({"outer": ["B" * 9000]})
        assert isinstance(out, dict)
        assert "sha256:" in out["outer"][0]

    def test_a_wide_details_dict_is_bounded_as_a_whole(self) -> None:
        """A dict of many short values evades the per-value bound.

        Mutation: return ``bounded`` without the total-size pass.
        """
        details = {f"k{i}": "v" * 200 for i in range(200)}
        out = bound_details(details)
        assert len(json.dumps(out, separators=(",", ":"))) <= MAX_DETAILS_CHARS
        assert out["_dropped"]["count"] > 0
        assert len(out["_dropped"]["keys"]) <= 10

    def test_the_reason_survives_the_total_bound(self) -> None:
        """An operator reads ``reason`` first; it must never be the key dropped.

        Mutation: sort keys plainly instead of putting ``reason`` first.
        """
        details: dict[str, Any] = {f"k{i}": "v" * 200 for i in range(200)}
        details["reason"] = "unknown EAB kid"
        out = bound_details(details)
        assert out["reason"] == "unknown EAB kid"

    def test_the_store_bounds_details_before_writing_them(self, tmp_path: Path) -> None:
        """The bound must live at the durable sink, not at each call site.

        Mutation: pass ``details`` straight through in ``_record_audit_in_conn``.
        """
        store = _store(tmp_path)
        store.record_audit(
            event_type="account-creation-denied",
            outcome="failed",
            requester="R" * 9000,
            details={"reason": "unknown EAB kid", "kid": "K" * 40_000},
        )
        row = _rows(store)[0]
        assert len(row["details"]) < 1000
        assert "sha256:" in json.loads(row["details"])["kid"]
        assert len(row["requester"]) < 500


# ---------------------------------------------------------------------------
# Part two: the attacker does not choose how MANY audit rows there are
# ---------------------------------------------------------------------------


class TestDenialCoalescing:
    def test_a_flood_of_identical_denials_makes_one_row_with_an_exact_count(
        self, tmp_path: Path
    ) -> None:
        """THE FINDING. Mutation: set the window to 0, or bypass the coalescer."""
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(500):
            coalescer.record(store, **_denial(reason="unknown EAB kid", kid=KID))

        rows = _rows(store)
        assert len(rows) == 1
        details = json.loads(rows[0]["details"])
        assert details["denial_count"] == 500
        # ...and the original evidence is still on the row, not overwritten by
        # the counters.
        assert details["reason"] == "unknown EAB kid"
        assert details["kid"] == KID

    def test_varying_the_kid_does_not_defeat_the_bound(self, tmp_path: Path) -> None:
        """Keying on attacker-chosen data would make the bound decorative.

        Mutation: add ``kid`` to the coalescing key.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for i in range(300):
            coalescer.record(
                store, **_denial(reason="unknown EAB kid", kid=f"kid-{i}")
            )

        rows = _rows(store)
        assert len(rows) == 1
        details = json.loads(rows[0]["details"])
        assert details["denial_count"] == 300
        # The distinct kids are counted in full, and a bounded sample is named.
        assert details["distinct_kids"] == 300
        assert len(details["kid_digests"]) == 10

    def test_distinct_denial_reasons_keep_distinct_rows(self, tmp_path: Path) -> None:
        """Coalescing must not merge different failures into one another.

        Mutation: key on ``event_type`` alone.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for reason in ("unknown EAB kid", "EAB MAC verification failed"):
            for _ in range(10):
                coalescer.record(store, **_denial(reason=reason, kid=KID))

        rows = _rows(store)
        assert len(rows) == 2
        assert {json.loads(r["details"])["reason"] for r in rows} == {
            "unknown EAB kid",
            "EAB MAC verification failed",
        }
        assert all(json.loads(r["details"])["denial_count"] == 10 for r in rows)

    def test_a_new_window_opens_once_the_old_one_elapses(self, tmp_path: Path) -> None:
        """Growth is a function of TIME. Mutation: never expire the window."""
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, clock=clock)

        for _ in range(100):
            coalescer.record(store, **_denial(reason="unknown EAB kid"))
        clock.advance(61)
        for _ in range(100):
            coalescer.record(store, **_denial(reason="unknown EAB kid"))

        rows = _rows(store)
        assert len(rows) == 2
        # The second row carries the first window's final tally, so the SIEM
        # sink learns it too rather than only SQLite.
        second = json.loads(rows[1]["details"])
        assert second["previous_window"]["denial_count"] == 100
        assert json.loads(rows[0]["details"])["denial_count"] == 100

    def test_ten_thousand_attempts_cost_a_bounded_number_of_rows(
        self, tmp_path: Path
    ) -> None:
        """The quantitative claim: rows track windows, not requests.

        Mutation: remove the in-place update and always insert.
        """
        store = _store(tmp_path)
        clock = _Clock()
        coalescer = DenialCoalescer(60, clock=clock)

        for i in range(10_000):
            if i % 1000 == 0:
                clock.advance(61)
            coalescer.record(store, **_denial(reason="unknown EAB kid", kid=f"k{i}"))

        rows = _rows(store)
        assert len(rows) == 10
        assert sum(json.loads(r["details"])["denial_count"] for r in rows) == 10_000

    def test_authenticated_and_issuance_events_are_never_coalesced(
        self, tmp_path: Path
    ) -> None:
        """Accountable, STATE-CHANGING events keep one row each.

        The set was extended in round 5 with the *replayable* authenticated
        denial classes (see test_security_review_2026_08_15_daybreak_round5).
        The exact membership is pinned so a future addition is a deliberate,
        reviewed change rather than drift — this test failing is that review
        being demanded, not a bug.

        ``key-change-rate-limited`` was added deliberately with 14a: it is a
        cap-exceeded denial, the same class as ``order-rate-limited`` and
        unbounded for the same reason. Its SUCCESS counterpart,
        ``account-key-changed``, deliberately stays out — that row is both the
        provenance of the new key and the counter the ceiling reads.

        Extended again 2026-08-25, and the wording above had to sharpen with
        it. The old rule said "issuance, revocation and admin actions must
        never join"; replayable admin events now do, and the distinction that
        matters is not the SUBSYSTEM but whether the event records a state change:

        * ``finalize-enrollment-admission-denied`` — a cap-exceeded denial on
          an order the route restores to ``ready``. Identical in class to
          ``order-rate-limited``; missed when the enrollment gate was added.
        * ``admin-revocation-confirm-denied`` — a confirm-token holder can POST
          a nonexistent serial forever. Nothing transitions; the lookup misses.
        * ``admin-list-pending-revocations`` — a read-only poll. The ONLY
          success in the original set, admissible solely because nothing counts
          these rows (contrast ``account-key-changed``, which is a counter).
        * The reclaim not-found/denied/noop outcomes, order-list read, and
          revocation-confirm deferral likewise transition nothing. Unknown
          probed order ids are samples only and never coalescing keys.

        Extended again 2026-09-05 with ``revocation-issuer-evidence-recovery``
        (UNFILED item 25), and it passes the state-change test cleanly: the
        event is written ONLY on the branch where recovery found nothing, so
        by construction no chain was persisted and nothing transitioned. The
        sync agent retries a blocked certificate on its interval forever, which
        is the same benign unbounded growth as the denials above. Its SUCCESS
        counterpart, ``revocation-issuer-evidence-recovered``, deliberately
        stays out: that row is the provenance of a chain the RA wrote into the
        store, and a compare-and-set means it can fire at most once per
        certificate anyway.

        What must still never join: issuance, actual revocation, key rotation,
        and any admin call that changes state. ``certificate-issued`` is
        asserted below.

        Mutation: coalesce every event type; or drop any member and watch its
        own bound test fail.
        """
        assert COALESCED_EVENT_TYPES == {
            "account-creation-denied",
            "account-request-denied",
            "order-rate-limited",
            "key-change-rate-limited",
            "finalize-csr-mismatch",
            "finalize-policy-denied",
            "finalize-enrollment-admission-denied",
            "admin-order-reclaim-not-found",
            "admin-order-reclaim-denied",
            "admin-order-reclaim-noop",
            "admin-list-orders",
            "admin-revocation-confirm-denied",
            "admin-revocation-confirm-deferred",
            "admin-list-pending-revocations",
            "revocation-issuer-evidence-recovery",
        }
        assert "account-key-changed" not in COALESCED_EVENT_TYPES
        # State-changing admin counterparts remain individual.
        assert "admin-revocation-confirmed" not in COALESCED_EVENT_TYPES
        assert "admin-order-reclaimed" not in COALESCED_EVENT_TYPES
        assert "certificate-revoked" not in COALESCED_EVENT_TYPES
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(5):
            coalescer.record(
                store,
                event_type="certificate-issued",
                outcome="success",
                details={"reason": "same reason string on purpose"},
            )
        assert len(_rows(store)) == 5

    def test_a_zero_window_restores_one_row_per_denial(self, tmp_path: Path) -> None:
        """The bound is configurable, and 0 means the pre-fix behaviour.

        Mutation: ignore ``window_seconds`` and always coalesce.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(0, clock=_Clock())
        assert not coalescer.enabled

        for _ in range(20):
            coalescer.record(store, **_denial(reason="unknown EAB kid"))
        assert len(_rows(store)) == 20

    def test_the_count_is_durable_at_every_step_not_only_at_window_close(
        self, tmp_path: Path
    ) -> None:
        """A crash mid-window must not lose the tally.

        This is why the row is UPDATED rather than the count held in memory.
        Mutation: buffer the count and write it only when the window closes.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        for expected in range(1, 6):
            coalescer.record(store, **_denial(reason="unknown EAB kid"))
            rows = _rows(store)
            assert len(rows) == 1
            assert json.loads(rows[0]["details"])["denial_count"] == expected

    def test_a_vanished_row_makes_the_next_denial_open_a_fresh_one(
        self, tmp_path: Path
    ) -> None:
        """An operator archiving the table must not silently swallow counts.

        Mutation: ignore ``update_audit_details``' return value.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(3600, clock=_Clock())
        coalescer.record(store, **_denial(reason="unknown EAB kid"))
        coalescer.record(store, **_denial(reason="unknown EAB kid"))

        con = sqlite3.connect(store._db_path, timeout=30)
        con.execute("DELETE FROM audit_log")
        con.commit()
        con.close()

        coalescer.record(store, **_denial(reason="unknown EAB kid"))
        rows = _rows(store)
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 1

    def test_update_audit_details_reports_a_missing_row(self, tmp_path: Path) -> None:
        """Mutation: return True unconditionally."""
        store = _store(tmp_path)
        assert store.update_audit_details(4242, {"reason": "nope"}) is False

    def test_the_aggregate_row_details_are_bounded_too(self, tmp_path: Path) -> None:
        """The in-place update goes through the same size bound as the insert.

        Mutation: write ``details`` unbounded in ``update_audit_details``.
        """
        store = _store(tmp_path)
        event = store.record_audit(
            event_type="account-creation-denied", outcome="failed", details={}
        )
        store.update_audit_details(int(event["id"]), {"blob": "X" * 60_000})
        row = _rows(store)[0]
        assert len(row["details"]) < 1000


# ---------------------------------------------------------------------------
# End to end: a real peer, over HTTP, with no credentials at all
# ---------------------------------------------------------------------------


def _build(tmp_path: Path, **overrides: Any) -> tuple[TestClient, ServerContext]:
    cfg = RAConfig(
        base_url=BASE_URL,
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=KID, mac_key=MAC_B64)],
        san_scopes={KID: {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        max_accounts_per_eab_kid=3,
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        # The nonce limiter would otherwise throttle the flood before the audit
        # path is reached, and it is the audit path under test here.
        nonce_rate_limit_per_second=0.0,
        **overrides,
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


@pytest.fixture()
def env(tmp_path: Path) -> tuple[TestClient, ServerContext]:
    return _build(tmp_path)


class TestUnauthenticatedFloodEndToEnd:
    def test_rejected_newaccount_requests_do_not_grow_storage_per_request(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        """The reachability claim, exercised: no account, no valid EAB secret.

        Mutation: set ``audit_denial_coalesce_window_seconds`` to 0.
        """
        client, ctx = env
        acme = HandRolledAcmeClient(
            client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
        )
        for i in range(40):
            resp = acme.new_account(f"no-such-kid-{i}", b"not-the-real-key")
            assert resp.status_code == 400

        con = sqlite3.connect(ctx.config.db_path, timeout=30)
        con.row_factory = sqlite3.Row
        rows = list(
            con.execute(
                "SELECT * FROM audit_log WHERE event_type = 'account-creation-denied'"
            ).fetchall()
        )
        con.close()
        assert len(rows) == 1
        details = json.loads(rows[0]["details"])
        assert details["denial_count"] == 40
        assert details["distinct_kids"] == 40

    def test_the_jsonl_mirror_grows_per_window_not_per_request(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        """The second durable sink the finding named.

        Mutation: fan every coalesced event out to the SIEM hook.
        """
        client, ctx = env
        acme = HandRolledAcmeClient(
            client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
        )
        for i in range(40):
            acme.new_account(f"no-such-kid-{i}", b"not-the-real-key")

        path = ctx.config.siem_jsonl_path
        assert path is not None
        lines = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        denials = [
            e for e in lines if e.get("event_type") == "account-creation-denied"
        ]
        assert len(denials) == 1

    def test_a_successful_account_is_still_audited_once_per_event(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        """Coalescing must not touch the evidence the RA exists to produce.

        Mutation: add ``account-created`` to ``COALESCED_EVENT_TYPES``.
        """
        client, ctx = env
        for _ in range(3):
            acme = HandRolledAcmeClient(
                client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
            )
            assert acme.new_account(KID, _mac_bytes()).status_code == 201

        con = sqlite3.connect(ctx.config.db_path, timeout=30)
        con.row_factory = sqlite3.Row
        created = con.execute(
            "SELECT COUNT(*) c FROM audit_log WHERE event_type = 'account-created'"
        ).fetchone()["c"]
        con.close()
        assert created == 3

    def test_audit_deletion_exists_in_exactly_one_gated_place(self) -> None:
        """Audit deletion is possible, but only through one reviewed door.

        This assertion used to be ``"DELETE FROM audit_log" not in source`` — a
        tripwire whose docstring said adding a pruner "is the review
        conversation worth having before that ships". That conversation happened
        (2026-08-17, WI-014 part three): retention ships, but only because
        ``audit_offbox_required`` turns the local table into a buffer whose
        contents have already left the host. With it unset the local table is
        still the only copy and nothing deletes from it.

        So the invariant is narrowed rather than dropped. The tripwire's real
        purpose was to stop deletion appearing *casually*, and that still holds:
        exactly one statement, in one primitive that makes no policy decisions,
        with every gate in ``audit_retention``.

        Mutation: add a second ``DELETE FROM audit_log`` anywhere in the store,
        or call the primitive from outside the retention module, and this fails.
        """
        src_root = Path(__file__).resolve().parents[1] / "src" / "acme_adcs_ra"
        store_source = (src_root / "store.py").read_text(encoding="utf-8")

        assert store_source.count("DELETE FROM audit_log") == 1, (
            "audit deletion must exist in exactly one place in the store"
        )
        # ...and that place must be the dumb primitive, not some other method
        # that happens to have grown a delete.
        after = store_source.split("def delete_audit_rows_before", 1)[1]
        next_def = after.find("\n    def ")
        assert "DELETE FROM audit_log" in after[:next_def], (
            "the only audit deletion must live in delete_audit_rows_before"
        )

        # No caller outside the retention module may reach the primitive: the
        # gates are useless if a route can bypass them.
        callers = [
            path.name
            for path in src_root.rglob("*.py")
            if "delete_audit_rows_before" in path.read_text(encoding="utf-8")
            and path.name not in {"store.py", "audit_retention.py"}
        ]
        assert callers == [], (
            f"delete_audit_rows_before must only be called from audit_retention; "
            f"found callers in {callers}"
        )
