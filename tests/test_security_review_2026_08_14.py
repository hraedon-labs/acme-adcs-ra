"""Regression tests for the 2026-08-14 security review.

Each test is named for the finding it pins. Every one was mutation-checked:
the fix was reverted in turn and the test confirmed to fail.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from acme_adcs_ra.enrollment import (
    EnrollmentResult,
    EnrollmentTransportError,
    FakeEnrollmentLeg,
)
from acme_adcs_ra.store import CertStatus, Store

_ADMIN_TOKEN = "test-admin-token-0123456789abcdef-32+"


class _IssuedThenFailedLeg:
    """An enrollment leg where the CA issues and the RA then fails.

    This is the window the review named: ``certfnsh.asp`` has already returned
    an "issued" disposition with a ReqID, so a live, domain-trusted certificate
    exists at the CA, and only then does the chain fetch or the
    chain-binds-to-leaf check blow up.
    """

    def __init__(self, *, with_cert: bool) -> None:
        self._with_cert = with_cert
        self.cert_pem = FakeEnrollmentLeg()._read_cert() if with_cert else None

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        raise EnrollmentTransportError(
            "PKCS#7 chain does not bind to the issued leaf",
            req_id="4242",
            cert_pem=self.cert_pem,
            chain_pem=[],
        )


class TestTransportOrphanQuarantine:
    """F14 — a CA-issued certificate must never be silently orphaned.

    Before the fix the finalize handler recorded ``{"error": ...}`` and
    returned 503: no certificate row, no serial anywhere in the RA, and the
    order left in ``processing``. That is the same orphan class the
    post-issuance verifiers were fixed for in the 2026-08-13 review, on a path
    that review did not reach.
    """

    def test_the_transport_error_carries_what_the_ca_already_issued(self) -> None:
        """The identifiers must survive the exception, or nothing downstream
        can act on them."""
        leg = _IssuedThenFailedLeg(with_cert=True)
        with pytest.raises(EnrollmentTransportError) as caught:
            leg.submit_csr("csr", account_id="acct", requested_sans=["a.example.com"])
        assert caught.value.ca_issued is True
        assert caught.value.req_id == "4242"
        assert caught.value.cert_pem is not None

    def test_a_pre_issuance_transport_error_is_not_flagged_as_issued(self) -> None:
        """The negative control. Without it, every transport failure would
        look like an orphan and the signal would be worthless."""
        exc = EnrollmentTransportError("connection refused")
        assert exc.ca_issued is False
        assert exc.req_id is None

    def _orphaned(self, tmp_path: Path, *, with_cert: bool) -> tuple[Store, Any]:
        return _app_with_leg(tmp_path, _IssuedThenFailedLeg(with_cert=with_cert))

    def test_the_orphan_is_quarantined_with_its_serial(self, tmp_path: Path) -> None:
        """With the leaf in hand the RA can identify the certificate exactly,
        so it must land in the store rather than only in a log line."""
        store, _client = self._orphaned(tmp_path, with_cert=True)
        leg = _IssuedThenFailedLeg(with_cert=True)
        assert leg.cert_pem is not None
        cert = x509.load_pem_x509_certificate(leg.cert_pem.encode())
        expected_serial = format(cert.serial_number, "x").upper()


        # Drive the handler directly: the HTTP path needs a full authorized
        # order, and what is under test is the orphan handling itself.
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "chain does not bind", req_id="4242", cert_pem=leg.cert_pem, chain_pem=[]
        )
        _run_orphan_handler(store, order_id, account_id, exc)

        pending = store.list_revoked_certificates()
        assert [c.serial_number for c in pending] == [expected_serial]
        assert pending[0].status == CertStatus.QUARANTINED
        assert pending[0].metadata["req_id"] == "4242"

    def test_the_order_goes_terminal_so_finalize_cannot_re_enroll(
        self, tmp_path: Path
    ) -> None:
        """The CA has already satisfied this request. A retried finalize that
        re-enrolled would issue a second certificate for one order."""
        store, _client = self._orphaned(tmp_path, with_cert=True)
        order_id, account_id = _seed_processing_order(store)
        leg = _IssuedThenFailedLeg(with_cert=True)
        exc = EnrollmentTransportError(
            "chain does not bind", req_id="4242", cert_pem=leg.cert_pem, chain_pem=[]
        )
        _run_orphan_handler(store, order_id, account_id, exc)
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "invalid"

    def test_finalize_routes_an_issued_orphan_to_quarantine(
        self, tmp_path: Path
    ) -> None:
        """The dispatch itself, driven through the real finalize handler.

        The unit tests above call the orphan handler directly, so they pass
        even if ``_finalize_submit_enrollment``'s ``except`` never routes to
        it — a mutation confirmed exactly that. This drives a full authorized
        order through HTTP so the branch is genuinely covered.
        """
        store, client = self._orphaned(tmp_path, with_cert=True)
        resp = _drive_order_to_finalize(client)
        # The CA issued; the RA refuses to honour it and says so with a 500,
        # not the 503 "try again" that would invite a re-enrollment.
        assert resp.status_code == 500, resp.text

        pending = store.list_revoked_certificates()
        assert len(pending) == 1
        assert pending[0].status == CertStatus.QUARANTINED
        assert pending[0].metadata["req_id"] == "4242"

    def test_a_pre_issuance_transport_failure_still_returns_503(
        self, tmp_path: Path
    ) -> None:
        """The negative control for the dispatch: a failure *before* issuance
        must keep the old retryable behaviour and quarantine nothing."""
        store, client = self._orphaned_preissuance(tmp_path / "preissuance")
        resp = _drive_order_to_finalize(client)
        assert resp.status_code == 503, resp.text
        assert store.list_revoked_certificates() == []

    def _orphaned_preissuance(self, tmp_path: Path) -> tuple[Store, Any]:
        class _PreIssuanceFailure:
            def submit_csr(
                self, csr_pem: str, *, account_id: str, requested_sans: Sequence[str]
            ) -> EnrollmentResult:
                raise EnrollmentTransportError("connection refused")

        tmp_path.mkdir(parents=True, exist_ok=True)
        return _app_with_leg(tmp_path, _PreIssuanceFailure())

    def test_a_retrieval_failure_still_records_the_reqid(
        self, tmp_path: Path
    ) -> None:
        """When the leaf itself could not be fetched there are no bytes to
        store, so the ReqID is the only handle the operator has. It must be in
        the audit trail — previously the event carried only an error string."""
        store, _client = self._orphaned(tmp_path, with_cert=False)
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "certnew.cer did not return a parseable certificate", req_id="4242"
        )
        _run_orphan_handler(store, order_id, account_id, exc)

        events = _audit_events(store, "finalize-enrollment-transport-orphan")
        assert len(events) == 1
        assert events[0]["details"]["req_id"] == "4242"
        assert events[0]["details"]["ca_issued"] is True
        assert events[0]["details"]["quarantined"] is False

    def test_a_retrieval_failure_still_makes_the_order_terminal(
        self, tmp_path: Path
    ) -> None:
        """The ReqID-only branch writes no certificate row, so nothing else
        flips the order — this is the one path where the explicit terminal
        transition is load-bearing. Without it the order stays ``processing``
        and a client can poll it forever against a request the CA already
        satisfied.
        """
        store, _client = self._orphaned(tmp_path, with_cert=False)
        order_id, account_id = _seed_processing_order(store)
        exc = EnrollmentTransportError(
            "certnew.cer did not return a parseable certificate", req_id="4242"
        )
        _run_orphan_handler(store, order_id, account_id, exc)
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "invalid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestReclaimRefusesLiveEnrollment:
    """F7 — reclaim must not be able to race an in-flight enrollment.

    The endpoint's only machine check was "no certificate row exists for this
    order", which is equally true of an order the RA is *still enrolling* — the
    row is not written until the CA answers. Reclaiming such an order flips it
    to ``ready``, a client finalize re-enrolls, and the CA issues a second
    certificate for one order.
    """

    def _processing_order(
        self, tmp_path: Path, *, age_seconds: int
    ) -> tuple[Store, Any, str]:
        store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, _account_id = _seed_processing_order(store)
        _backdate_processing(store, order_id, age_seconds)
        return store, client, order_id

    def test_a_freshly_processing_order_cannot_be_reclaimed(
        self, tmp_path: Path
    ) -> None:
        store, client, order_id = self._processing_order(tmp_path, age_seconds=5)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing",
            headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
        )
        assert resp.status_code == 400
        # And crucially it is still processing — not flipped to ready, where a
        # finalize could re-enroll against a request the CA may be serving.
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "processing"

    def test_an_order_past_the_window_can_still_be_reclaimed(
        self, tmp_path: Path
    ) -> None:
        """The negative control: the endpoint must still do its job. Without
        this, refusing everything would pass the test above. The no-cert branch
        now requires the operator's explicit CA-checked assertion."""
        store, client, order_id = self._processing_order(tmp_path, age_seconds=3600)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true",
            headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
        )
        assert resp.status_code == 200
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "ready"

    def test_reclaim_to_ready_requires_ca_verification_assertion(
        self, tmp_path: Path
    ) -> None:
        """Elapsed time is not proof the CA did not issue. Reclaiming a
        no-cert order to ``ready`` must require the operator to assert they
        reconciled against the CA; without it, refuse and leave it processing."""
        store, client, order_id = self._processing_order(tmp_path, age_seconds=3600)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing",
            headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
        )
        assert resp.status_code == 400
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "processing"
        denied = store.list_audit_events(event_type="admin-order-reclaim-denied")
        assert any(
            e["details"].get("reason") == "ca-verification-not-asserted"
            for e in denied
        )

    def test_reclaim_refused_while_a_worker_is_actively_enrolling(
        self, tmp_path: Path
    ) -> None:
        """The authoritative guard: a live enrollment worker in this process
        holds the order in the in-memory registry. Reclaim must refuse it even
        past the age window and even with the CA-checked flag set, because the
        first enrollment is genuinely in flight and reclaiming would double-issue."""
        store, client, order_id = self._processing_order(tmp_path, age_seconds=3600)
        ctx = client.app.state.context
        with ctx.active_enrollments.enrolling(order_id):
            resp = client.post(
                f"/acme/admin/orders/{order_id}/reclaim-processing"
                "?ca_verified_no_issuance=true",
                headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
            )
        assert resp.status_code == 400
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == "processing"
        denied = store.list_audit_events(event_type="admin-order-reclaim-denied")
        assert any(
            e["details"].get("reason") == "enrollment-in-flight" for e in denied
        )


class TestOneAccountPerKey:
    """F8 — newAccount's read-then-insert could mint duplicate accounts.

    ``newAccount`` reads by thumbprint and returns any existing account, then
    inserts if it found none — two separate transactions. Two concurrent
    requests for the same key both read "absent" and both insert, leaving two
    active accounts for one key: separate order histories, separate rate-limit
    accounting, and a kid eviction or deactivation applied to one leaving the
    twin usable.
    """

    def test_the_database_refuses_a_second_account_for_one_key(
        self, tmp_path: Path
    ) -> None:
        """Pins the constraint itself, not the route's read-then-insert — the
        race is by definition not reproducible through the happy path."""
        import sqlite3

        from cryptography.hazmat.primitives.asymmetric import ec

        from .hand_rolled_acme_client import jwk_from_private_key

        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        jwk = jwk_from_private_key(ec.generate_private_key(ec.SECP256R1()))
        store.create_account(jwk=jwk, eab_kid="kid-001-0123456789abcdef")

        with pytest.raises(sqlite3.IntegrityError):
            store.create_account(jwk=jwk, eab_kid="kid-001-0123456789abcdef")

    def test_a_different_key_is_unaffected(self, tmp_path: Path) -> None:
        """Negative control: the constraint must be per-key, not a global cap."""
        from cryptography.hazmat.primitives.asymmetric import ec

        from .hand_rolled_acme_client import jwk_from_private_key

        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        for _ in range(3):
            jwk = jwk_from_private_key(ec.generate_private_key(ec.SECP256R1()))
            store.create_account(jwk=jwk, eab_kid="kid-001-0123456789abcdef")

    def test_the_route_resolves_the_race_instead_of_500ing(
        self, tmp_path: Path
    ) -> None:
        """A legitimate idempotent retry that loses the race must still get its
        account back (RFC 8555 §7.3), not a 500 from the constraint."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        from .hand_rolled_acme_client import HandRolledAcmeClient
        from .test_revocation import _eab_mac_key, _make_test_config

        _store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        cfg = _make_test_config(tmp_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, "http://testserver", key)
        mac = _eab_mac_key(cfg, "kid-001-0123456789abcdef")
        first = ac.new_account("kid-001-0123456789abcdef", mac)
        assert first.status_code == 201
        second = ac.new_account("kid-001-0123456789abcdef", mac)
        assert second.status_code == 200
        assert second.headers["Location"] == first.headers["Location"]


class TestRevocationAtomicity:
    """F13 — revocation state and its mandatory audit row must commit together."""

    def test_revocation_and_its_audit_row_are_atomic(self, tmp_path: Path) -> None:
        """Fault-inject the audit write; the certificate must NOT come back
        revoked. Otherwise a fault leaves a certificate served as 410 and
        queued for CA-side revocation with no event in the authoritative
        trail — and the local table, not the SIEM copy, is authoritative."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        from .hand_rolled_acme_client import HandRolledAcmeClient
        from .test_revocation import _eab_mac_key, _make_test_config

        store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        cfg = _make_test_config(tmp_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, "http://testserver", key)
        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(cfg, "kid-001-0123456789abcdef"))
        cert_der = _issue_via(ac, client)

        original = store._record_audit_in_conn

        def _boom(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("event_type") == "certificate-revoked":
                raise sqlite3.OperationalError("injected fault")
            return original(*args, **kwargs)

        store._record_audit_in_conn = _boom  # type: ignore[method-assign]
        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 500

        # The transaction rolled back: still valid, and NOT queued for the CA.
        cert = x509.load_der_x509_certificate(cert_der)
        serial = format(cert.serial_number, "x").upper()
        record = store.get_certificate_by_serial(serial)
        assert record is not None
        assert record.status == CertStatus.VALID
        assert store.list_revoked_certificates() == []


class TestConfirmAuthoritySeparation:
    """F9 — the confirm credential must not collapse into the admin one."""

    def test_identical_admin_and_confirm_tokens_are_refused(
        self, tmp_path: Path
    ) -> None:
        """Every individual length check passes, so nothing else catches this;
        the separation is silently gone and the revocation agent holds full
        maintenance authority."""
        from pydantic import SecretStr

        from acme_adcs_ra.config import RAConfig

        same = "identical-token-0123456789abcdef-32chars"
        with pytest.raises(ValueError, match="identical"):
            RAConfig(
                base_url="http://testserver",
                db_path=tmp_path / "ra.db",
                admin_token=SecretStr(same),
                revocation_confirm_token=SecretStr(same),
            )

    def test_distinct_tokens_are_accepted(self, tmp_path: Path) -> None:
        """Negative control."""
        from pydantic import SecretStr

        from acme_adcs_ra.config import RAConfig

        RAConfig(
            base_url="http://testserver",
            db_path=tmp_path / "ra.db",
            admin_token=SecretStr("admin-token-0123456789abcdef-32chars!"),
            revocation_confirm_token=SecretStr("confirm-token-0123456789abcdef-32c"),
        )


class TestHecQueueFloor:
    """F15 — a non-positive queue bound silently voids the off-box audit gate."""

    def test_a_nonpositive_queue_max_is_refused(self, tmp_path: Path) -> None:
        """At 0, `inflight >= max` is true with nothing in flight, so every
        event drops — while the emitter still reports itself enabled, so
        audit_offbox_required passes and the operator believes events are
        leaving the host. A typo defeats the whole control."""
        from acme_adcs_ra.config import RAConfig

        for bad in (0, -1):
            with pytest.raises(ValueError):
                RAConfig(
                    base_url="http://testserver",
                    db_path=tmp_path / "ra.db",
                    siem_hec_queue_max=bad,
                )


class TestUnauthenticatedResourceGetIsRemoved:
    """F16 — the legacy plain GET forms bypassed ownership AND eviction.

    They answered for a certificate whose account had been deactivated or whose
    EAB kid had been pulled, so a URL captured before an eviction still read.
    RFC 8555 (§6.3, §7.4.2) specifies POST-as-GET, which every conforming client
    uses. As of the 2026-08-15 review (finding 4) the plain GET forms are
    **removed entirely** — only the account-scoped POST-as-GET forms remain.
    """

    def _issued_cert_url(self, client: Any, tmp_path: Path) -> tuple[Any, str]:
        from cryptography.hazmat.primitives.asymmetric import rsa

        from .hand_rolled_acme_client import HandRolledAcmeClient
        from .test_revocation import _eab_mac_key, _make_csr, _make_test_config

        cfg = _make_test_config(tmp_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, "http://testserver", key)
        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(cfg, "kid-001-0123456789abcdef"))
        order = ac.new_order(["srv01.WORK-DOMAIN.local"]).json()
        for authz_url in order["authorizations"]:
            authz = ac.post_as_get(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])
        finalized = ac.finalize_order(
            order["finalize"], _make_csr(["srv01.WORK-DOMAIN.local"])
        ).json()
        return ac, str(finalized["certificate"])

    def test_the_plain_get_cert_route_is_gone(self, tmp_path: Path) -> None:
        """A real, valid certificate URL: a plain GET must no longer read it —
        only POST is registered, so the method is refused (405)."""
        _store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        _ac, url = self._issued_cert_url(client, tmp_path)
        assert client.get(url).status_code == 405

    def test_the_plain_get_authz_route_is_gone(self, tmp_path: Path) -> None:
        _store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        from cryptography.hazmat.primitives.asymmetric import rsa

        from .hand_rolled_acme_client import HandRolledAcmeClient
        from .test_revocation import _eab_mac_key, _make_test_config

        cfg = _make_test_config(tmp_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, "http://testserver", key)
        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(cfg, "kid-001-0123456789abcdef"))
        order = ac.new_order(["srv01.WORK-DOMAIN.local"]).json()
        authz_url = order["authorizations"][0]
        assert client.get(authz_url).status_code == 405

    def test_post_as_get_still_reads_the_certificate(self, tmp_path: Path) -> None:
        """The negative control: removing the plain GET must not break the
        conforming read path. The owning account reads its cert via POST-as-GET."""
        _store, client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        ac, url = self._issued_cert_url(client, tmp_path)
        assert ac.post_as_get(url).status_code == 200


def _issue_via(ac: Any, client: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    from .test_revocation import _make_csr

    resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
    order = resp.json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            ac.validate_challenge(challenge["url"])
    finalized = ac.finalize_order(
        order["finalize"], _make_csr(["srv01.WORK-DOMAIN.local"])
    ).json()
    cert_text = ac.get_certificate(finalized["certificate"]).text
    first = cert_text.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
    return x509.load_pem_x509_certificate(first.encode()).public_bytes(
        serialization.Encoding.DER
    )


def _backdate_processing(store: Store, order_id: str, seconds: int) -> None:
    from datetime import UTC, datetime, timedelta

    ts = (datetime.now(UTC) - timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    with store._connect() as conn:
        conn.execute(
            "UPDATE orders SET processing_started_at = ? WHERE id = ?",
            (ts, order_id),
        )


def _app_with_leg(tmp_path: Path, leg: Any) -> tuple[Store, Any]:
    """An app whose issuance policy actually permits an order to be driven.

    Reuses test_revocation's config (real EAB kids and SAN scopes) rather than
    the empty-policy one, because these tests must reach the enrollment leg.
    """
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    from acme_adcs_ra.app_state import ServerContext
    from acme_adcs_ra.policy import IssuancePolicy
    from acme_adcs_ra.revocation import FakeRevocationLeg
    from acme_adcs_ra.server import create_app

    from .test_revocation import _make_test_config

    tmp_path.mkdir(parents=True, exist_ok=True)
    cfg = _make_test_config(tmp_path).model_copy(
        update={"admin_token": SecretStr(_ADMIN_TOKEN)}
    )
    store = Store(cfg.db_path)
    ctx = ServerContext(
        config=cfg,
        store=store,
        policy=IssuancePolicy(
            allowed_kids=set(cfg.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in cfg.san_scopes.items()
            },
            template=cfg.adcs_template,
        ),
        enrollment=leg,
        revocation=FakeRevocationLeg(),
    )
    return store, TestClient(create_app(ctx), raise_server_exceptions=False)


def _drive_order_to_finalize(client: Any) -> Any:
    """New account -> order -> challenge -> finalize, returning the finalize
    response. The enrollment leg is what decides how finalize ends."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from .hand_rolled_acme_client import HandRolledAcmeClient
    from .test_revocation import _eab_mac_key, _make_csr, _make_test_config

    cfg = _make_test_config(Path("/nonexistent"))  # only for the MAC key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ac = HandRolledAcmeClient(client, "http://testserver", key)
    assert ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(cfg, "kid-001-0123456789abcdef")).status_code == 201

    resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
    assert resp.status_code == 201
    order = resp.json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            assert ac.validate_challenge(challenge["url"]).status_code == 200

    return ac.finalize_order(order["finalize"], _make_csr(["srv01.WORK-DOMAIN.local"]))


def _seed_processing_order(store: Store) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec

    from .hand_rolled_acme_client import jwk_from_private_key

    account = store.create_account(
        jwk=jwk_from_private_key(ec.generate_private_key(ec.SECP256R1())),
        eab_kid="kid-1-0123456789abcdef",
    )
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example.com"}],
        challenge_url_fn=lambda i: f"http://testserver/acme/chall/{i}",
        authz_url_fn=lambda i: f"http://testserver/acme/authz/{i}",
        finalize_url_fn=lambda i: f"http://testserver/acme/finalize/{i}",
    )
    store.transition_pending_to_ready(order.id)
    assert store.acquire_processing_lease(order.id) is not None
    return order.id, account.id


def _run_orphan_handler(
    store: Store, order_id: str, account_id: str, exc: EnrollmentTransportError
) -> None:
    from acme_adcs_ra.app_state import ServerContext
    from acme_adcs_ra.config import RAConfig
    from acme_adcs_ra.finalize import _quarantine_transport_orphan
    from acme_adcs_ra.policy import IssuancePolicy
    from acme_adcs_ra.revocation import FakeRevocationLeg

    ctx = ServerContext(
        config=RAConfig(db_path=store._db_path, base_url="http://testserver"),
        store=store,
        policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    _quarantine_transport_orphan(
        ctx,
        order_id=order_id,
        account_id=account_id,
        requested_sans=["a.example.com"],
        template="ACME-ServerAuth",
        exc=exc,
        generation=1,
    )


def _audit_events(store: Store, event_type: str) -> list[dict[str, Any]]:
    import json
    import sqlite3

    conn = sqlite3.connect(str(store._db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE event_type = ?", (event_type,)
    ).fetchall()
    conn.close()
    return [{**dict(r), "details": json.loads(r["details"])} for r in rows]
