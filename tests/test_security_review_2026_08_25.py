"""Standard whole-repository scan of `a566050` — three medium findings.

All three are the same family the previous rounds keep producing: a control
that already exists, with its reasoning already written down, not pointed at
one more call site. Two are audit-growth bounds; one is the post-issuance
orphan path, which is the one that can leave a domain-trusted certificate
outside the RA entirely.

* **F1 (the one that matters).** ``Store.record_issuance`` is the FIRST durable
  record of something ADCS has already done, and it was unguarded. On a full or
  read-only database the certificate/order/audit transaction rolls back, the
  exception escapes before the SIEM fan-out, and a live certificate exists with
  no row, no audit event, no quarantine record and no revocation queue entry.
  Both neighbouring paths — verifier rejection and transport failure — already
  had orphan handlers; the SUCCESS path did not. Neither of those handlers
  would have helped anyway: both fall back to ``_audit``, which is the same
  database that just failed.

* **F2.** ``finalize-enrollment-admission-denied`` was not coalesced. The gate
  sheds at ``adcs_enrollment_max_pending`` and the route CAS-restores the order
  to ``ready``, so the identical signed finalize can be replayed for as long as
  capacity stays full — one durable row apiece. This is the same sentence the
  coalescer's own docstring already wrote for ``order-rate-limited``.

* **F3.** The revocation-confirm credential could POST nonexistent serials
  forever (``admin-revocation-confirm-denied``), and every poll of the pending
  list wrote a row. The second half is not really an attack: the sync task
  polls on a fixed interval forever, so that table grows without bound in
  entirely benign operation, and this deployment refuses audit pruning.

Every test below is mutation-checked; the mutation that breaks each one is
named in its docstring. A test that cannot fail against the pre-fix code is not
evidence.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.app_state import IssuanceHalt
from acme_adcs_ra.audit_coalesce import COALESCED_EVENT_TYPES, DenialCoalescer
from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.finalize import _store_is_unwritable
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient

_KID = "kid-001-0123456789abcdef"
_MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
_ADMIN = "test-admin-token-0123456789abcdef-32+"
_CONFIRM = "test-confirm-token-0123456789abcdef-32+"
_BASE = "http://testserver"


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _build_env(
    tmp_path: Path, *, raise_server_exceptions: bool = True
) -> tuple[TestClient, ServerContext]:
    cfg = RAConfig(
        base_url=_BASE,
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=_KID, mac_key=_MAC_B64)],
        san_scopes={_KID: {"dns_patterns": ["*.in-scope.local"]}},
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr(_ADMIN),
        revocation_confirm_token=SecretStr(_CONFIRM),
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
    # The orphan tests need the 500/503 the client actually sees. TestClient
    # re-raises server exceptions by default, which would hide the response
    # Starlette produces in production.
    return (
        TestClient(
            create_app(ctx), raise_server_exceptions=raise_server_exceptions
        ),
        ctx,
    )


def _mac() -> bytes:
    return base64.urlsafe_b64decode(_MAC_B64 + "=" * ((-len(_MAC_B64)) % 4))


def _rows(ctx: ServerContext, event_type: str | None = None) -> list[sqlite3.Row]:
    con = sqlite3.connect(ctx.config.db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        if event_type is None:
            return list(con.execute("SELECT * FROM audit_log ORDER BY id"))
        return list(
            con.execute(
                "SELECT * FROM audit_log WHERE event_type = ? ORDER BY id",
                (event_type,),
            )
        )
    finally:
        con.close()


def _csr(name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def _ready_order(acme: HandRolledAcmeClient, name: str) -> Any:
    order = acme.new_order([name]).json()
    for authz_url in order["authorizations"]:
        authz = acme.get_authorization(authz_url).json()
        acme.validate_challenge(authz["challenges"][0]["url"])
    return order


def _account(client: TestClient) -> HandRolledAcmeClient:
    acme = HandRolledAcmeClient(client, _BASE, ec.generate_private_key(ec.SECP256R1()))
    assert acme.new_account(_KID, _mac()).status_code in (200, 201)
    return acme


# ---------------------------------------------------------------------------
# F1 — a live certificate the RA could not record
# ---------------------------------------------------------------------------


class _Boom(sqlite3.OperationalError):
    """Stands in for whatever SQLite raises when the disk is gone."""


class TestPostIssuanceOrphan:
    def test_a_store_failure_after_issuance_emits_evidence_off_box(
        self, tmp_path: Path
    ) -> None:
        """THE FINDING.

        ADCS has issued. The store cannot take the row. Before the fix the
        exception escaped ``_finalize_complete`` and NOTHING recorded that a
        live certificate existed — no row, no audit event, no SIEM event.

        Mutation: delete the ``try/except`` around ``record_issuance`` in
        ``_finalize_complete`` and this fails with zero captured events.
        """
        client, ctx = _build_env(tmp_path, raise_server_exceptions=False)
        captured: list[dict[str, Any]] = []
        ctx.audit_hook = captured.append

        def _explode(*_a: Any, **_kw: Any) -> Any:
            raise _Boom("database or disk is full")

        ctx.store.record_issuance = _explode  # type: ignore[method-assign]

        acme = _account(client)
        order = _ready_order(acme, "srv01.in-scope.local")
        resp = acme.finalize_order(order["finalize"], _csr("srv01.in-scope.local"))

        assert resp.status_code >= 500, "the client must not be told this succeeded"

        orphans = [
            e for e in captured if e["event_type"] == "finalize-issuance-record-failed"
        ]
        assert len(orphans) == 1, "the orphan must reach the off-box sink exactly once"
        details = orphans[0]["details"]
        assert details["ca_issued"] is True
        assert details["recorded"] is False
        assert details["serial"], "the serial is how an operator revokes it by hand"
        assert details["store_unwritable"] is True
        assert "disk is full" in details["store_error"]
        assert orphans[0]["order_id"] == order["finalize"].rsplit("/", 1)[-1]

    def test_the_emergency_path_does_not_touch_the_failed_database(
        self, tmp_path: Path
    ) -> None:
        """The whole point: no sink that needs the store that just died.

        The two neighbouring orphan handlers both fall back to ``_audit`` ->
        ``Store.record_audit``. Under this fault that fallback raises from
        inside its own except block and writes nothing.

        Mutation: route the emergency event through ``_audit`` instead of
        calling ``ctx.audit_hook`` directly — the assertion below then finds a
        durable row and fails.
        """
        client, ctx = _build_env(tmp_path, raise_server_exceptions=False)
        captured: list[dict[str, Any]] = []
        ctx.audit_hook = captured.append

        def _explode(*_a: Any, **_kw: Any) -> Any:
            raise _Boom("attempt to write a readonly database")

        ctx.store.record_issuance = _explode  # type: ignore[method-assign]

        acme = _account(client)
        order = _ready_order(acme, "srv02.in-scope.local")
        acme.finalize_order(order["finalize"], _csr("srv02.in-scope.local"))

        assert captured, "the off-box sink got it"
        assert _rows(ctx, "finalize-issuance-record-failed") == [], (
            "the emergency event must NOT be written through the store — that "
            "is the database the fault is about"
        )

    def test_an_unwritable_store_halts_further_issuance(self, tmp_path: Path) -> None:
        """One orphan, not N.

        Every finalize admitted after an unwritable-store orphan would issue at
        the CA and fail to record it the same way. The second one is refused.

        Mutation: drop the ``ctx.issuance_halt.halt(...)`` call, or the check in
        ``routes/orders.py`` — the second finalize then reaches the CA again.
        """
        client, ctx = _build_env(tmp_path, raise_server_exceptions=False)
        ctx.audit_hook = lambda _e: None

        def _explode(*_a: Any, **_kw: Any) -> Any:
            raise _Boom("database or disk is full")

        ctx.store.record_issuance = _explode  # type: ignore[method-assign]

        acme = _account(client)
        first = _ready_order(acme, "srv03.in-scope.local")
        acme.finalize_order(first["finalize"], _csr("srv03.in-scope.local"))
        assert ctx.issuance_halt, "the latch must be set"
        assert "srv03" not in (ctx.issuance_halt.reason or ""), (
            "the reason names the order, not the SAN"
        )

        second = _ready_order(acme, "srv04.in-scope.local")
        resp = acme.finalize_order(second["finalize"], _csr("srv04.in-scope.local"))
        assert resp.status_code == 503, (
            "a halted RA refuses to issue; 503 so a conformant client retries "
            "after the operator restarts"
        )

    def test_a_merely_busy_store_does_not_halt_issuance(self, tmp_path: Path) -> None:
        """Lock contention is transient — halting on it is a self-inflicted outage.

        The evidence still goes off-box (the certificate is just as orphaned);
        only the latch is conditional.

        Mutation: latch unconditionally in ``_emergency_issuance_orphan`` and
        the ``not ctx.issuance_halt`` assertion fails.
        """
        client, ctx = _build_env(tmp_path, raise_server_exceptions=False)
        captured: list[dict[str, Any]] = []
        ctx.audit_hook = captured.append

        def _explode(*_a: Any, **_kw: Any) -> Any:
            raise _Boom("database is locked")

        ctx.store.record_issuance = _explode  # type: ignore[method-assign]

        acme = _account(client)
        order = _ready_order(acme, "srv05.in-scope.local")
        acme.finalize_order(order["finalize"], _csr("srv05.in-scope.local"))

        # `captured` carries every fanned-out event, not just this one.
        orphans = [
            e for e in captured if e["event_type"] == "finalize-issuance-record-failed"
        ]
        assert len(orphans) == 1, "the certificate is orphaned either way"
        assert orphans[0]["details"]["store_unwritable"] is False
        assert not ctx.issuance_halt, "a busy store must not stop the service"

    @pytest.mark.parametrize(
        ("message", "unwritable"),
        [
            ("database or disk is full", True),
            ("attempt to write a readonly database", True),
            ("disk I/O error", True),
            ("unable to open database file", True),
            ("database disk image is malformed", True),
            ("database is locked", False),
            ("database table is locked", False),
        ],
    )
    def test_the_writability_classifier(self, message: str, unwritable: bool) -> None:
        """sqlite3 reports all of these as OperationalError; the text is the only
        discriminator the driver offers.

        Mutation: return True unconditionally and the two locked cases fail.
        """
        assert _store_is_unwritable(sqlite3.OperationalError(message)) is unwritable

    def test_a_constraint_violation_is_a_bug_not_a_dead_disk(self) -> None:
        """Mutation: drop the IntegrityError branch."""
        assert _store_is_unwritable(sqlite3.IntegrityError("UNIQUE failed")) is False

    def test_the_latch_is_one_way_and_keeps_the_first_reason(self) -> None:
        """A later, vaguer cause must not overwrite the one that explains it.

        Mutation: let ``halt()`` reassign ``_reason`` unconditionally.
        """
        halt = IssuanceHalt()
        assert not halt
        halt.halt("first: disk full on order A")
        halt.halt("second: something else")
        assert halt
        assert halt.reason is not None and halt.reason.startswith("first:")


# ---------------------------------------------------------------------------
# F2 — enrollment admission denials are replayable
# ---------------------------------------------------------------------------


class TestAdmissionDenialsAreBounded:
    def test_an_admission_denial_storm_makes_one_row_per_order(
        self, tmp_path: Path
    ) -> None:
        """THE FINDING (F2).

        Mutation: remove ``finalize-enrollment-admission-denied`` from
        COALESCED_EVENT_TYPES and this becomes 400 rows.
        """
        assert "finalize-enrollment-admission-denied" in COALESCED_EVENT_TYPES
        store = Store(tmp_path / "ra.db")
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(400):
            coalescer.record(
                store,
                event_type="finalize-enrollment-admission-denied",
                outcome="denied",
                account_id="acct-A",
                order_id="order-1",
                details={
                    "reason": "enrollment-capacity",
                    "reason_code": "enrollment-capacity",
                    "revert_applied": True,
                },
            )

        con = sqlite3.connect(store._db_path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            rows = list(
                con.execute(
                    "SELECT * FROM audit_log "
                    "WHERE event_type='finalize-enrollment-admission-denied'"
                )
            )
        finally:
            con.close()
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["denial_count"] == 400

    def test_two_accounts_stay_separable(self, tmp_path: Path) -> None:
        """Folding must not cost attribution.

        Mutation: drop account_id/order_id from the coalescing key.
        """
        store = Store(tmp_path / "ra.db")
        coalescer = DenialCoalescer(60, clock=_Clock())
        for account in ("acct-A", "acct-B"):
            for _ in range(50):
                coalescer.record(
                    store,
                    event_type="finalize-enrollment-admission-denied",
                    outcome="denied",
                    account_id=account,
                    order_id=f"order-{account}",
                    details={
                        "reason": "enrollment-capacity",
                        "reason_code": "enrollment-capacity",
                    },
                )
        con = sqlite3.connect(store._db_path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            rows = list(
                con.execute(
                    "SELECT * FROM audit_log "
                    "WHERE event_type='finalize-enrollment-admission-denied'"
                )
            )
        finally:
            con.close()
        assert len(rows) == 2
        assert {r["account_id"] for r in rows} == {"acct-A", "acct-B"}

    def test_the_call_site_pins_the_key_to_a_server_constant(self) -> None:
        """``reason`` must not become the key's only anchor.

        EnrollmentGateBusy's message carries live counts. One edit putting
        ``str(exc)`` into ``reason`` would put a varying value in the key and
        silently un-bound the row count — unless an explicit ``reason_code``
        is what the coalescer reads.

        Mutation: delete ``reason_code`` from the details dict in
        ``routes/orders.py``.
        """
        source = Path("src/acme_adcs_ra/routes/orders.py").read_text(encoding="utf-8")
        marker = source.index('"reason": "enrollment-capacity"')
        window = source[marker : marker + 200]
        assert '"reason_code": "enrollment-capacity"' in window


# ---------------------------------------------------------------------------
# F3 — the revocation-confirm credential as a durable write primitive
# ---------------------------------------------------------------------------


class TestRevocationConfirmAuditGrowth:
    def test_probing_unknown_serials_costs_one_row(self, tmp_path: Path) -> None:
        """THE FINDING (F3, the denial half).

        The probed serial varies every time and is attacker-chosen, so it must
        be on the row but NOT in the key.

        Mutation: remove the type from COALESCED_EVENT_TYPES (200 rows), or put
        ``serial`` in the coalescing key instead of ``reason_code`` (also 200).
        """
        assert "admin-revocation-confirm-denied" in COALESCED_EVENT_TYPES
        client, ctx = _build_env(tmp_path)

        for i in range(200):
            resp = client.post(
                f"/acme/admin/revocations/{i:040X}/confirm",
                headers={"Authorization": f"Bearer {_CONFIRM}"},
                json={"crl_published": True},
            )
            assert resp.status_code == 404

        rows = _rows(ctx, "admin-revocation-confirm-denied")
        assert len(rows) == 1, "200 distinct serials, one durable row"
        details = json.loads(rows[0]["details"])
        assert details["denial_count"] == 200, "the count stays exact"
        assert details["serial"], "the window's first serial is kept for the operator"

    def test_an_empty_pending_poll_writes_nothing(self, tmp_path: Path) -> None:
        """The benign case coalescing cannot fix.

        The sync task polls every interval forever. At a 15-minute cadence and a
        60-second window, no two polls ever fold — so coalescing alone leaves
        this growing without bound in normal operation, on a deployment that
        refuses audit pruning.

        Mutation: drop the ``if pending_revocations:`` guard in
        ``routes/admin.py`` and this finds 30 rows.
        """
        client, ctx = _build_env(tmp_path)
        for _ in range(30):
            resp = client.get(
                "/acme/admin/revocations/pending",
                headers={"Authorization": f"Bearer {_CONFIRM}"},
            )
            assert resp.status_code == 200
            assert resp.json()["pending_revocations"] == []

        assert _rows(ctx, "admin-list-pending-revocations") == [], (
            "an empty work list reports nothing an investigator can use"
        )

    def test_a_poll_that_returns_work_is_still_audited(self, tmp_path: Path) -> None:
        """The skip must not become a hole.

        "The revocation host was handed these serials" is the audit trail for
        whatever it does next, so a non-empty poll keeps its row.

        Mutation: skip the audit unconditionally and this finds no row.
        """
        client, ctx = _build_env(tmp_path)
        acme = _account(client)
        order = _ready_order(acme, "srv06.in-scope.local")
        finalize = acme.finalize_order(order["finalize"], _csr("srv06.in-scope.local"))
        assert finalize.status_code == 200
        cert_url = finalize.json()["certificate"]
        leaf_pem = acme.get_certificate(cert_url).text
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
        acme.revoke_certificate(leaf.public_bytes(serialization.Encoding.DER))

        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": f"Bearer {_CONFIRM}"},
        )
        assert resp.status_code == 200
        assert resp.json()["pending_revocations"], "there is work to hand over"

        rows = _rows(ctx, "admin-list-pending-revocations")
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["returned"] >= 1


# ---------------------------------------------------------------------------
# F3b — found by MEASURING the deployed store, not by reading the code
# ---------------------------------------------------------------------------


class TestMaintenanceSweepsDoNotNarrate:
    """The audit table on the lab RA was 78.5% self-generated noise.

    Counted on the real deployed store at the start of the 2026-08-25 re-proof,
    722 rows total::

        199  admin-list-pending-revocations
        184  admin-nonce-cleanup
        184  admin-expired-order-sweep
         ...
         11  certificate-issued

    567 of 722 rows were this RA's own scheduled maintenance reporting that it
    had nothing to do. The evidence the system exists to produce was 11 rows.
    On a deployment that refuses audit pruning, every one of those is permanent.

    The static scan found the first of the three. The other two came from one
    ``GROUP BY event_type`` against the backup taken before deploy.
    """

    def test_a_nonce_cleanup_that_deleted_nothing_writes_no_row(
        self, tmp_path: Path
    ) -> None:
        """Mutation: drop the ``if deleted:`` guard — this finds 20 rows."""
        client, ctx = _build_env(tmp_path)
        for _ in range(20):
            resp = client.delete(
                "/acme/admin/nonces",
                headers={"Authorization": f"Bearer {_ADMIN}"},
            )
            assert resp.status_code == 200
            assert resp.json()["deleted"] == 0
        assert _rows(ctx, "admin-nonce-cleanup") == []

    def test_a_sweep_that_invalidated_nothing_writes_no_row(
        self, tmp_path: Path
    ) -> None:
        """Mutation: drop the ``if invalidated:`` guard."""
        client, ctx = _build_env(tmp_path)
        for _ in range(20):
            resp = client.delete(
                "/acme/admin/expired-orders",
                headers={"Authorization": f"Bearer {_ADMIN}"},
            )
            assert resp.status_code == 200
            assert resp.json()["invalidated"] == 0
        assert _rows(ctx, "admin-expired-order-sweep") == []

    def test_a_cleanup_that_did_something_is_still_audited(
        self, tmp_path: Path
    ) -> None:
        """The skip must not become a hole: destroying state stays on the record.

        Mutation: skip the audit unconditionally and this finds no row.
        """
        client, ctx = _build_env(tmp_path)
        # A nonce is minted per newNonce; expire them all, then sweep.
        for _ in range(3):
            assert client.head("/acme/new-nonce").status_code in (200, 204)
        con = sqlite3.connect(ctx.config.db_path, timeout=30)
        try:
            con.execute("UPDATE nonces SET created_at = '2000-01-01T00:00:00Z'")
            con.commit()
        finally:
            con.close()

        resp = client.delete(
            "/acme/admin/nonces", headers={"Authorization": f"Bearer {_ADMIN}"}
        )
        assert resp.json()["deleted"] >= 1, "the sweep must actually delete"
        rows = _rows(ctx, "admin-nonce-cleanup")
        assert len(rows) == 1
        assert json.loads(rows[0]["details"])["deleted"] >= 1
