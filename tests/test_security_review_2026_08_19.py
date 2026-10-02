"""Regression tests for the 2026-08-19 review (of `c8ad4c2`).

Six findings — one high, one medium, four low — from an independent source
review run against the commit that closed the 2026-08-14 live-validation round.

* F1 (high) — the elevated installer executed a destination-local interpreter
  before it created or ACL'd that destination. PowerShell; covered by
  `tests/pester/InstallVerify.Tests.ps1`.
* F2 (medium) — admin and confirmation tokens were interpolated into scheduled
  task actions, so they sat in task metadata and in process arguments.
  PowerShell; covered by `tests/pester/TaskAction.Tests.ps1`.
* F4 (low) — those same generated actions took unescaped registration values
  into single-quoted literals. PowerShell; same file.
* F5 (low) — order reclaim committed its transition, its CA-marker cleanup and
  its mandatory audit event separately. Covered here.
* F3 (low) — request bodies were byte-capped but had no read deadline, and the
  direct-Uvicorn topology had no concurrency ceiling. Covered here.
* F6 (low) — unbounded audit growth from unauthenticated denials. **Deliberately
  not fixed**, as in wave 3; it remains WI-014. See
  docs/security-review-2026-08-19.md.

Also covered here: the CRL-gate cleanup lag that flaked CI on Windows.

Each test was mutation-checked. See docs/security-review-2026-08-19.md.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, ClassVar

import pytest

from acme_adcs_ra.acme_errors import AcmeError
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import CrlEvidenceGate
from acme_adcs_ra.store import OrderStatus, Store

from .conftest import placeholder_ec_jwk


def _order_in_processing(
    store: Store, db_path: Path, *, req_id: str | None = None
) -> str:
    """An account + order driven into `processing`, optionally with a CA marker."""
    account = store.create_account(
        jwk=placeholder_ec_jwk("reclaim-atomicity"), eab_kid="kid-1-0123456789abcdef"
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "host.example.test"}],
        challenge_url_fn=lambda i: f"https://ra.example.test/chal/{i}",
        authz_url_fn=lambda i: f"https://ra.example.test/authz/{i}",
        finalize_url_fn=lambda i: f"https://ra.example.test/finalize/{i}",
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE orders SET status = ?, processing_generation = 1 WHERE id = ?",
            (OrderStatus.PROCESSING, order.id),
        )
        if req_id is not None:
            conn.execute(
                "UPDATE orders SET pending_ca_request_id = ? WHERE id = ?",
                (req_id, order.id),
            )
    return order.id


class TestReclaimIsAtomic:
    """F5 (low, CWE-362) — reclaim was three separate commits.

    The transition, the CA-request marker clear and the mandatory
    `admin-order-reclaimed` audit event each committed on their own. An
    interruption between them could reopen an issuance-path order while leaving
    a discharged ReqID marker set, or — worse — reopen it with no audit event at
    all, so an administrative change to issuance state had nothing in the trail
    saying who made it.
    """

    def test_a_failing_audit_insert_rolls_back_the_transition(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        order_id = _order_in_processing(store, tmp_path / "ra.db", req_id="4242")

        def boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise sqlite3.OperationalError("disk I/O error")

        store._record_audit_in_conn = boom  # type: ignore[method-assign]
        with pytest.raises(sqlite3.OperationalError):
            store.reclaim_processing_order(
                order_id,
                expected_generation=1,
                pending_req_id="4242",
                audit_event_type="admin-order-reclaimed",
                audit_outcome="success",
                audit_details={"new_status": OrderStatus.READY},
            )
        del store._record_audit_in_conn  # type: ignore[attr-defined]

        reopened = Store(tmp_path / "ra.db")
        row = reopened.get_order(order_id)
        assert row is not None
        assert row.status == OrderStatus.PROCESSING, (
            "the order reopened without its audit event: an administrative "
            "change to issuance state with nothing recording it"
        )

    def test_a_failing_audit_insert_leaves_the_ca_marker_set(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        order_id = _order_in_processing(store, tmp_path / "ra.db", req_id="4242")

        def boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise sqlite3.OperationalError("disk I/O error")

        store._record_audit_in_conn = boom  # type: ignore[method-assign]
        with pytest.raises(sqlite3.OperationalError):
            store.reclaim_processing_order(
                order_id,
                expected_generation=1,
                pending_req_id="4242",
                audit_event_type="admin-order-reclaimed",
                audit_outcome="success",
                audit_details={},
            )
        del store._record_audit_in_conn  # type: ignore[attr-defined]

        with sqlite3.connect(tmp_path / "ra.db") as conn:
            marker = conn.execute(
                "SELECT pending_ca_request_id FROM orders WHERE id = ?", (order_id,)
            ).fetchone()[0]
        assert marker == "4242", (
            "the marker cleared without the audit event, so the next operator "
            "sees a ReqID that was already discharged"
        )

    def test_a_successful_reclaim_writes_all_three(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "ra.db")
        order_id = _order_in_processing(store, tmp_path / "ra.db", req_id="4242")

        won, event = store.reclaim_processing_order(
            order_id,
            expected_generation=1,
            pending_req_id="4242",
            audit_event_type="admin-order-reclaimed",
            audit_outcome="success",
            audit_details={"new_status": OrderStatus.READY},
        )
        assert won is True
        assert event is not None

        row = store.get_order(order_id)
        assert row is not None
        assert row.status == OrderStatus.READY
        with sqlite3.connect(tmp_path / "ra.db") as conn:
            marker = conn.execute(
                "SELECT pending_ca_request_id FROM orders WHERE id = ?", (order_id,)
            ).fetchone()[0]
            audited = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE order_id = ? "
                "AND event_type = 'admin-order-reclaimed'",
                (order_id,),
            ).fetchone()[0]
        assert marker is None
        assert audited == 1

    def test_a_lost_cas_changes_nothing_and_audits_nothing(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        order_id = _order_in_processing(store, tmp_path / "ra.db", req_id="4242")

        # Generation moved since the handler read the order: the CAS must lose
        # rather than reopen an order now in flight under a different lease.
        won, event = store.reclaim_processing_order(
            order_id,
            expected_generation=99,
            pending_req_id="4242",
            audit_event_type="admin-order-reclaimed",
            audit_outcome="success",
            audit_details={},
        )
        assert won is False
        assert event is None
        row = store.get_order(order_id)
        assert row is not None
        assert row.status == OrderStatus.PROCESSING
        with sqlite3.connect(tmp_path / "ra.db") as conn:
            marker = conn.execute(
                "SELECT pending_ca_request_id FROM orders WHERE id = ?", (order_id,)
            ).fetchone()[0]
        assert marker == "4242", "a lost CAS must not discharge the marker"

    def test_the_valid_branch_records_the_certificate_url(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        order_id = _order_in_processing(store, tmp_path / "ra.db")
        won, _ = store.reclaim_processing_order(
            order_id,
            to_valid_certificate_url="https://ra.example.test/cert/abc",
            expected_generation=1,
            audit_event_type="admin-order-reclaimed",
            audit_outcome="success",
            audit_details={},
        )
        assert won is True
        row = store.get_order(order_id)
        assert row is not None
        assert row.status == OrderStatus.VALID
        assert row.certificate_url == "https://ra.example.test/cert/abc"


class TestBodyReadDeadline:
    """F3 (low, CWE-400) — bytes were bounded, time was not.

    A peer that dribbles one byte per interval never trips the byte cap and
    never finishes, holding a worker for as long as it likes. The cap answers
    "how much", and nothing answered "for how long".
    """

    def test_a_dribbling_peer_is_cut_at_the_total_deadline(self) -> None:
        from acme_adcs_ra.http_body import read_body_limited

        class _SlowRequest:
            """Sends one byte, then stalls far past the deadline."""

            headers: ClassVar[dict[str, str]] = {}

            async def stream(self) -> Any:
                yield b"x"
                await asyncio.sleep(30)
                yield b"y"

        async def scenario() -> None:
            with pytest.raises(AcmeError) as excinfo:
                await read_body_limited(
                    _SlowRequest(), max_bytes=1024, total_timeout_seconds=0.2
                )
            # Fails closed with a client error, not a hang and not a 500.
            assert "deadline" in str(excinfo.value).lower() or "timeout" in str(
                excinfo.value
            ).lower()

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_an_ordinary_body_still_reads_completely(self) -> None:
        from acme_adcs_ra.http_body import read_body_limited

        class _NormalRequest:
            headers: ClassVar[dict[str, str]] = {}

            async def stream(self) -> Any:
                yield b"hello "
                yield b"world"

        async def scenario() -> bytes:
            return await read_body_limited(
                _NormalRequest(), max_bytes=1024, total_timeout_seconds=5
            )

        assert asyncio.run(scenario()) == b"hello world"

    def test_the_byte_cap_still_fires_independently(self) -> None:
        from acme_adcs_ra.http_body import read_body_limited

        class _BigRequest:
            headers: ClassVar[dict[str, str]] = {}

            async def stream(self) -> Any:
                yield b"x" * 5000

        async def scenario() -> None:
            with pytest.raises(AcmeError, match="too large"):
                await read_body_limited(
                    _BigRequest(), max_bytes=10, total_timeout_seconds=5
                )

        asyncio.run(scenario())


class TestUvicornConcurrencyCeiling:
    """F3, second half — the direct-Uvicorn topology set no concurrency limit."""

    def test_a_concurrency_ceiling_is_configurable(self) -> None:
        cfg = RAConfig(server_max_concurrency=64)
        assert cfg.server_max_concurrency == 64

    def test_it_has_a_bounded_default_rather_than_unlimited(self) -> None:
        assert RAConfig().server_max_concurrency > 0


class TestCrlGateCleanupLag:
    """The CI flake: `inflight` clears one event-loop iteration late.

    `_clear` is registered with `add_done_callback`, which asyncio dispatches
    through `call_soon`, while the awaiting caller resumes as soon as the future
    settles. So a caller can observe `inflight` still counting a finished
    flight. Benign for correctness — but `inflight` is the `max_pending`
    admission signal, so a caller arriving inside that window can be shed while
    capacity is actually free.
    """

    def test_capacity_is_released_once_the_loop_turns(self) -> None:
        async def scenario() -> None:
            gate = CrlEvidenceGate(max_workers=2, max_pending=2)
            try:
                for i in range(6):
                    assert await gate.run(f"KEY-{i}", lambda: "evidence") == "evidence"
                await gate.drain()
                assert gate.inflight == 0
            finally:
                gate.close()

        asyncio.run(scenario())

    def test_drain_is_idempotent_on_an_idle_gate(self) -> None:
        async def scenario() -> None:
            gate = CrlEvidenceGate(max_workers=2, max_pending=2)
            try:
                await gate.drain()
                await gate.drain()
                assert gate.inflight == 0
            finally:
                gate.close()

        asyncio.run(scenario())
