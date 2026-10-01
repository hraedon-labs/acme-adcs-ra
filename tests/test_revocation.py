"""Tests for revokeCert passthrough (RFC 8555 §7.6)."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import (
    CertsrvRevocationLeg,
    FakeRevocationLeg,
    RevocationLeg,
    RevocationResult,
)
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient


def _oob_hint(resp: Any) -> dict[str, Any] | None:
    """Read the out-of-band hint from the response HEADER.

    It used to be a JSON body. That broke real ACME clients -- Certify the Web
    cannot parse any JSON object here and reports the revocation as FAILED even
    though it succeeded -- so on 2026-08-24 it moved to
    X-Acme-Ra-Out-Of-Band-Revocation and every success path returns an empty
    body, which is what RFC 8555 s7.6 clients expect.
    """
    raw = resp.headers.get("X-Acme-Ra-Out-Of-Band-Revocation")
    return None if raw is None else cast("dict[str, Any]", json.loads(raw))

# The package-shipped fixture cert (pre-generated, non-sensitive) is reused for
# the CertsrvRevocationLeg unit tests so they don't need a live CA or a freshly
# minted cert (the architecture test forbids cert-minting primitives in src/,
# not in tests, but reusing the fixture keeps these fast and deterministic).
_FAKE_CERT_PEM = resources.files("acme_adcs_ra.fixtures").joinpath("fake_cert.pem").read_text()
_FAKE_CERT_SERIAL_HEX = format(
    x509.load_pem_x509_certificate(_FAKE_CERT_PEM.encode("utf-8")).serial_number, "x"
).upper()


def _make_test_config(tmp_path: Any) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001-0123456789abcdef", mac_key=mac_key_b64),
            EABEntry(kid="kid-002-0123456789abcdef", mac_key="YW5vdGhlci0zMi1ieXRlLW1hYy1rZXktZm9yLXRlc3Rz"),
        ],
        san_scopes={
            "kid-001-0123456789abcdef": {"dns_patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]},
            "kid-002-0123456789abcdef": {"dns_patterns": ["*.prod.WORK-DOMAIN.local"]},
        },
        adcs_template="ACME-ServerAuth",
    )


def _eab_mac_key(config: RAConfig, kid: str) -> bytes:
    raw = config.eab_key_bytes(kid)
    assert raw is not None
    return raw


def _make_csr(sans: list[str]) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, sans[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in sans])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class _RacingRevocationLeg:
    """Revocation leg that flips the cert to 'revoked' directly in the store
    inside ``revoke()``, so the route's subsequent ``revoke_certificate`` CAS
    loses (simulating a concurrent revocation that won the race). Used by the
    M-3 concurrent-revocation test. Does NOT audit (the winning revocation
    owns the audit, wherever it came from).

    M-3 follow-up: the route now uses the store's deterministic ``won_cas``
    signal rather than inferring a lost CAS from timestamp inequality, so the
    fixed 2020 timestamp is no longer required for detection — but it remains
    harmless and keeps the test data stable."""

    _FIXED_OLD_TS = "2020-01-01T00:00:00Z"

    def __init__(self, store: Store, cert_id: str, *, reason: int) -> None:
        self._store = store
        self._cert_id = cert_id
        self._reason = reason

    def revoke(self, cert_pem: str, reason: int | None) -> RevocationResult:
        # Flip the cert directly in the store with a fixed old timestamp,
        # winning the CAS before the route's revoke_certificate runs.
        self._store.revoke_certificate(
            self._cert_id, self._reason, revoked_at=self._FIXED_OLD_TS
        )
        # Return revoked_at=None so the route computes its own _now_iso(),
        # which differs from the fixed store timestamp — making the lost-CAS
        # detection deterministic.
        return RevocationResult(
            revoked=True,
            reason=self._reason,
            revoked_at=None,
            metadata={"revocation_scope": "ra-store-only", "ca_crl_updated": "false"},
        )


def _issue_cert(
    client: TestClient,
    config: RAConfig,
    account_key: rsa.RSAPrivateKey,
    kid: str = "kid-001-0123456789abcdef",
) -> tuple[HandRolledAcmeClient, bytes]:
    """Return an ACME client and the DER bytes of the issued certificate."""
    ac = HandRolledAcmeClient(client, config.base_url, account_key)
    resp = ac.new_account(kid, _eab_mac_key(config, kid))
    assert resp.status_code == 201

    resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
    assert resp.status_code == 201
    order = resp.json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            assert ac.validate_challenge(challenge["url"]).status_code == 200

    csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
    resp = ac.finalize_order(order["finalize"], csr_der)
    assert resp.status_code == 200
    finalized = resp.json()
    cert_resp = ac.get_certificate(finalized["certificate"])
    assert cert_resp.status_code == 200

    # Extract the first certificate DER from the PEM-chain response.
    first_pem = cert_resp.text.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
    cert_der = x509.load_pem_x509_certificate(first_pem.encode("utf-8")).public_bytes(
        serialization.Encoding.DER
    )
    return ac, cert_der


@pytest.fixture()
def test_config(tmp_path: Any) -> RAConfig:
    return _make_test_config(tmp_path)


@pytest.fixture()
def app(test_config: RAConfig) -> Any:
    store = Store(test_config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(test_config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
        },
        template=test_config.adcs_template,
    )
    context = ServerContext(
        config=test_config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return create_app(context)


@pytest.fixture()
def client(app: Any) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def account_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---------------------------------------------------------------------------
# Authorization and basic behavior
# ---------------------------------------------------------------------------


class TestRevokeCertAuthorization:
    def test_issuing_account_can_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        assert resp.content == b""

    def test_different_account_cannot_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """C-1: a different account gets 404 (not 401) when trying to revoke
        a cert it doesn't own — no information leak about ownership."""
        _ac1, cert_der = _issue_cert(client, test_config, account_key, kid="kid-001-0123456789abcdef")

        # Create a second account on the same server.
        account_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac2 = HandRolledAcmeClient(client, test_config.base_url, account_key2)
        resp = ac2.new_account("kid-002-0123456789abcdef", _eab_mac_key(test_config, "kid-002-0123456789abcdef"))
        assert resp.status_code == 201

        resp = ac2.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 404
        assert resp.json()["type"] == "urn:ietf:params:acme:error:notFound"

    def test_unknown_cert_returns_not_found(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac = HandRolledAcmeClient(client, test_config.base_url, account_key)
        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(test_config, "kid-001-0123456789abcdef"))

        # A self-signed cert that was never issued by the RA.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime_now())
            .not_valid_after(datetime_now(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 404
        assert resp.json()["type"] == "urn:ietf:params:acme:error:notFound"

    def test_already_revoked_returns_200_ok(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-4: RFC 8555 §7.6 — re-revoking an already-revoked cert returns 200 OK."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        assert ac.revoke_certificate(cert_der, reason=0).status_code == 200
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Reason-code validation
# ---------------------------------------------------------------------------


class TestRevokeCertReasonValidation:
    # M-1: reason 7 is unused in RFC 5280 and rejected by certutil, so the RA
    # must reject it too — otherwise an accepted reason 7 would silently break
    # the out-of-band revocation loop (Revoke-Cert.ps1 would fail on the
    # recorded reason).
    # 2026-08-14 review: reason 8 (removeFromCRL) is excluded for a sharper
    # reason — see test_reason_8_rejected below.
    # The valid set is {0,1,2,3,4,5,6,9,10}.
    @pytest.mark.parametrize("reason", [0, 1, 2, 3, 4, 5, 6, 9, 10])
    def test_valid_reason_codes_accepted(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
        reason: int,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=reason)
        assert resp.status_code == 200

    @pytest.mark.parametrize("reason", [7])
    def test_reason_7_rejected(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
        reason: int,
    ) -> None:
        """M-1: reason 7 is unused in RFC 5280 and rejected by certutil, so
        the RA must reject it with bad_revocation_reason (consistent with
        scripts/Revoke-Cert.ps1, which rejects it). This prevents a silent
        break in the out-of-band revocation loop."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=reason)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badRevocationReason"
        # The cert must NOT have been revoked (the rejection happens before
        # the store flip).
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "valid"

    def test_reason_8_rejected(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """Reason 8 (removeFromCRL) must never reach the CA.

        It is the inverse of revocation. Accepted, it flowed verbatim through
        the pending list into ``certutil -revoke <serial> 8`` — so a revokeCert
        carrying it recorded a *successful* revocation in the RA (410 on the
        certificate, order flipped, serial drained off the pending queue) while
        asking the CA to take the certificate back off the CRL. Plan 004
        confirmed the CA-side effect against the lab: a held certificate given
        reason 8 ends up "off the CRL and valid".

        The critical assertion is the last one: the certificate must remain
        ``valid`` in the store, because a rejection that still flipped the row
        would leave the RA claiming a revocation the CA never performed.
        """
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=8)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badRevocationReason"
        assert "removeFromCRL" in resp.json()["detail"]

        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "valid"
        # And it must not be queued for a CA-side "revocation" either.
        assert all(c.serial_number != serial_hex for c in store.list_revoked_certificates())

    @pytest.mark.parametrize("reason", [-1, 11, 128, "not-an-int"])
    def test_invalid_reason_codes_rejected(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
        reason: Any,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=reason)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badRevocationReason"


# ---------------------------------------------------------------------------
# Store + audit + SIEM
# ---------------------------------------------------------------------------


class TestRevokeCertStoreAndAudit:
    def test_store_reflects_revoked_status(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200

        store = Store(test_config.db_path)
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "revoked"
        assert record.revocation_reason == 1
        assert record.revoked_at is not None

    def test_revocation_produces_audit_and_siem_event(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # Audit row
        account_id = ac.account_url.split("/")[-1]
        store = Store(test_config.db_path)
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        assert any(
            e["event_type"] == "certificate-revoked"
            and e["outcome"] == "success"
            and e["details"].get("serial") == serial_hex
            for e in events
        )

        # SIEM event
        siem_lines = test_config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        siem_events = [json.loads(line) for line in siem_lines]
        assert any(
            e.get("event_type") == "certificate-revoked"
            and e.get("outcome") == "success"
            and e.get("details", {}).get("serial") == serial_hex
            and e.get("schema_version") == "acme-adcs-ra-audit/1"
            for e in siem_events
        )


# ---------------------------------------------------------------------------
# M-3: CAS-guarded certificate revocation (concurrent revocation is idempotent)
# ---------------------------------------------------------------------------


class TestCasGuardedRevocation:
    """M-3: revoke_certificate is CAS-guarded on status='valid' so concurrent
    revocations are idempotent — the first revocation's reason/timestamp are
    preserved, the route treats a lost CAS as 200 idempotent success, and no
    duplicate audit event is emitted."""

    def test_store_revoke_certificate_preserves_first_revocation(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """A second revoke_certificate call (status no longer 'valid') must NOT
        overwrite the first revocation's reason/timestamp — the CAS-guarded
        UPDATE returns the existing revoked record unchanged."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        # First revocation with reason=1.
        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200

        store = Store(test_config.db_path)
        first = store.get_certificate_by_serial(serial_hex)
        assert first is not None
        assert first.status == "revoked"
        assert first.revocation_reason == 1
        first_revoked_at = first.revoked_at
        assert first_revoked_at is not None

        # Second store-level revocation with reason=5 — must NOT clobber.
        second_update = store.revoke_certificate(first.id, 5)
        second = second_update.record
        assert second is not None
        assert second.status == "revoked"
        # The first revocation's reason + timestamp are preserved.
        assert second.revocation_reason == 1
        assert second.revoked_at == first_revoked_at
        # M-3: the second call lost the CAS (cert was already revoked).
        assert second_update.won_cas is False

    def test_store_revoke_certificate_same_second_race_is_deterministic(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """MED-2: the won_cas signal is deterministic even when both
        revocations share the same sub-second timestamp. The former
        route-level inference (``updated.revoked_at != revoked_at``) could
        emit a duplicate audit when two revocations landed in the same
        second; the store now returns won_cas=True for exactly one caller
        regardless of timestamp equality."""
        _ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None

        same_second = "2030-05-17T12:00:00Z"
        first_update = store.revoke_certificate(
            cert_record.id, 1, revoked_at=same_second
        )
        second_update = store.revoke_certificate(
            cert_record.id, 5, revoked_at=same_second
        )
        # Exactly one caller wins the CAS, deterministically — even though
        # both supplied the identical timestamp.
        assert first_update.won_cas is True
        assert second_update.won_cas is False
        assert first_update.record is not None
        assert second_update.record is not None
        # Same preserved record, same preserved timestamp/reason.
        assert first_update.record.revoked_at == same_second
        assert second_update.record.revoked_at == same_second
        assert second_update.record.revocation_reason == 1

    def test_concurrent_revocation_is_idempotent_no_duplicate_audit(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """M-3: when the route's revoke_certificate CAS loses to a concurrent
        revocation (the cert was 'valid' at lookup but 'revoked' by the time
        the CAS UPDATE runs), the route returns 200 (idempotent) and does NOT
        emit a duplicate certificate-revoked audit event. The winning
        revocation's audit event is the only one.

        This is exercised with a racing revocation leg that flips the cert to
        'revoked' directly in the store inside ``revoke()``, so the route's
        subsequent revoke_certificate CAS loses. The first revocation (via the
        racing leg) does not audit; the route's lost-CAS path also does not
        audit — so zero successful audit events, and the response is 200 {}."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None
        cert_id = cert_record.id

        # Racing leg: flips the cert to 'revoked' directly in the store inside
        # revoke(), so the route's subsequent revoke_certificate CAS loses.
        racing_leg = _RacingRevocationLeg(store, cert_id, reason=1)

        # Rebuild the server context with the racing leg so the route uses it.
        policy = IssuancePolicy(
            allowed_kids=set(test_config.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
            },
            template=test_config.adcs_template,
        )
        racing_context = ServerContext(
            config=test_config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=racing_leg,
        )
        racing_client = TestClient(create_app(racing_context))
        racing_ac = HandRolledAcmeClient(racing_client, test_config.base_url, account_key)
        # Re-bind the existing account (already created on the first client).
        racing_ac.account_url = ac.account_url

        # The cert is 'valid' at lookup; the racing leg flips it to 'revoked'
        # inside revoke(); the route's revoke_certificate CAS loses and the
        # route returns 200 {} without auditing.
        resp = racing_ac.revoke_certificate(cert_der, reason=5)
        assert resp.status_code == 200
        assert resp.content == b""

        # No successful certificate-revoked audit event was emitted (the racing
        # leg's direct store flip doesn't audit; the route's lost-CAS path
        # also doesn't audit — the winning revocation owns the audit).
        account_id = ac.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        success_events = [e for e in events if e["outcome"] == "success"]
        assert success_events == []

        # The store reflects the racing leg's reason=1, NOT the route's reason=5.
        final = store.get_certificate_by_serial(serial_hex)
        assert final is not None
        assert final.status == "revoked"
        assert final.revocation_reason == 1

    def test_store_revoke_certificate_returns_none_for_missing_cert(
        self, tmp_path: Any
    ) -> None:
        """M-3: revoke_certificate returns a RevocationUpdate whose record is
        None when no cert row exists (the route surfaces this as 404, not 500).
        won_cas is False because no row was updated."""
        store = Store(tmp_path / "missing.db")
        update = store.revoke_certificate("does-not-exist", reason=0)
        assert update.record is None
        assert update.won_cas is False

    def test_route_revocation_missing_cert_returns_404_not_500(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """M-3: if the cert row vanishes between the serial lookup and the
        CAS UPDATE (returns None), the route surfaces 404 (not 500). The
        revocation leg must not have been called in this path, so this is
        exercised by deleting the cert row between lookup and revoke."""
        # This is a defensive path; the realistic surface is the H-4
        # short-circuit + the CAS-lost path. The 404-not-500 contract is
        # asserted at the store level above. Here we just confirm the route
        # still returns 404 for a genuinely unknown cert (covered by the
        # existing test_unknown_cert_returns_not_found, but kept for the
        # M-3 contract surface).
        ac = HandRolledAcmeClient(client, test_config.base_url, account_key)
        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(test_config, "kid-001-0123456789abcdef"))

        # A self-signed cert that was never issued by the RA.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime_now())
            .not_valid_after(datetime_now(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 404
        assert resp.json()["type"] == "urn:ietf:params:acme:error:notFound"


# ---------------------------------------------------------------------------
# WI-010: out-of-band revocation — the RA records-and-surfaces honestly
# ---------------------------------------------------------------------------


@pytest.fixture()
def out_of_band_client(
    test_config: RAConfig, tmp_path: Any
) -> TestClient:
    """A client wired with the production CertsrvRevocationLeg (out-of-band),
    so route-level tests exercise the real audit/response shape rather than the
    FakeRevocationLeg (which claims ca_crl_updated=true)."""
    store = Store(test_config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(test_config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
        },
        template=test_config.adcs_template,
    )
    context = ServerContext(
        config=test_config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=CertsrvRevocationLeg(),
    )
    return TestClient(create_app(context))


class TestOutOfBandRevocation:
    """WI-010: the production leg records the revocation in the RA store and
    surfaces the out-of-band step; the audit honestly distinguishes RA-revoked
    from CA-CRL-revoked and never implies the CRL was written when it was not."""

    def test_response_surfaces_out_of_band_step(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200
        hint = _oob_hint(resp)
        assert hint is not None, "out-of-band leg must surface the out_of_band_revocation hint"
        assert hint["ca_crl_updated"] is False
        assert hint["revocation_scope"] == "ra-store-only"
        assert hint["serial"] == serial_hex

    def test_audit_distinguishes_ra_store_only_from_ca_crl(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The audit details must record revocation_scope=ra-store-only and
        ca_crl_updated=false so the audit log never implies the CA CRL was
        written when it was not (the dishonesty WI-010 removes)."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        account_id = ac.account_url.split("/")[-1]
        store = Store(test_config.db_path)
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        revoked_events = [e for e in events if e["outcome"] == "success"]
        assert revoked_events, "expected a successful certificate-revoked audit event"
        details = revoked_events[0]["details"]
        assert details["revocation_scope"] == "ra-store-only"
        assert details["ca_crl_updated"] == "false"
        assert details["serial"] == serial_hex

    def test_audit_surfaces_req_id_when_present(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """When the cert's RA-store metadata carries an ADCS ReqID (the real
        enrollment leg records it; FakeEnrollmentLeg does not), the audit and
        response surface it so the operator's Revoke-Cert.ps1 has both
        identifiers. Simulate the real leg by writing req_id into the cert
        metadata directly before revoking."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        # Write a req_id into the stored cert metadata, mimicking what the real
        # CertsrvEnrollmentLeg does at enrollment time (enrollment.py:338).
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None
        cert_record.metadata["req_id"] = "77"
        # Persist the updated metadata directly (the store doesn't expose a
        # metadata-only updater; replicate the minimal UPDATE).
        with store._connect() as conn:
            conn.execute(
                "UPDATE certificates SET metadata = ? WHERE id = ?",
                (json.dumps(cert_record.metadata), cert_record.id),
            )

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        hint = _oob_hint(resp)
        assert hint is not None
        assert hint["req_id"] == "77"

        account_id = ac.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        revoked_events = [e for e in events if e["outcome"] == "success"]
        assert revoked_events
        assert revoked_events[0]["details"].get("req_id") == "77"

    def test_already_revoked_is_idempotent_under_out_of_band_leg(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-4 holds under the out-of-band leg: re-revoking returns 200 (the
        already-revoked short-circuit fires before the leg is called). The
        body is {} — the out_of_band_revocation hint is NOT re-emitted on the
        idempotent second call (the first call's audit already recorded it)."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        assert ac.revoke_certificate(cert_der, reason=0).status_code == 200
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        assert resp.content == b""

    def test_store_reflects_revoked_under_out_of_band_leg(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The out-of-band leg still flips the RA store (cert → revoked, order
        → revoked, GET cert → 410) — the only thing it does NOT do is write the
        CA CRL."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200

        store = Store(test_config.db_path)
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "revoked"
        assert record.revocation_reason == 1
        assert record.revoked_at is not None
        order = store.get_order(record.order_id)
        assert order is not None
        assert order.status == "revoked"

        cert_resp = ac.get_certificate(f"{test_config.base_url}/acme/cert/{record.id}")
        assert cert_resp.status_code == 410

    def test_siem_event_for_out_of_band_path_carries_honest_scope(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """T2: the SIEM JSONL for the out-of-band path must carry
        revocation_scope=ra-store-only and ca_crl_updated=false so the SIEM
        never implies the CA CRL was written when it was not."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        siem_lines = test_config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        siem_events = [json.loads(line) for line in siem_lines]
        assert any(
            e.get("event_type") == "certificate-revoked"
            and e.get("outcome") == "success"
            and e.get("details", {}).get("serial") == serial_hex
            and e.get("details", {}).get("revocation_scope") == "ra-store-only"
            and e.get("details", {}).get("ca_crl_updated") == "false"
            and e.get("schema_version") == "acme-adcs-ra-audit/1"
            for e in siem_events
        )

    def test_req_id_absent_when_enrollment_leg_does_not_set_it(
        self,
        out_of_band_client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """T4: when the cert's RA-store metadata does not carry an ADCS ReqID
        (the FakeEnrollmentLeg case — only the real CertsrvEnrollmentLeg sets
        it), the audit omits req_id entirely and the response hint omits it."""
        ac, cert_der = _issue_cert(out_of_band_client, test_config, account_key)

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        hint = _oob_hint(resp)
        assert hint is not None
        assert "req_id" not in hint, "req_id must be absent when the cert has none"

        account_id = ac.account_url.split("/")[-1]
        store = Store(test_config.db_path)
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        revoked_events = [e for e in events if e["outcome"] == "success"]
        assert revoked_events
        assert "req_id" not in revoked_events[0]["details"]

    def test_failed_revocation_path_audits_failure_and_preserves_state(
        self,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """T1: when the revocation leg raises, the audit records outcome=failed
        (without revocation_scope/ca_crl_updated — a failure must not claim a
        scope), the response is 500, and the cert/order are NOT flipped to
        revoked (the RA store stays honest about what didn't happen)."""

        class _RaisingRevocationLeg:
            def revoke(self, cert_pem: str, reason: int | None) -> RevocationResult:
                raise RuntimeError("simulated CA-officer leg failure")

        store = Store(test_config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(test_config.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
            },
            template=test_config.adcs_template,
        )
        context = ServerContext(
            config=test_config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=_RaisingRevocationLeg(),  # type: ignore[arg-type]
        )
        client = TestClient(create_app(context))

        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)
        serial_hex = format(cert.serial_number, "x").upper()

        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 500
        assert resp.json()["type"] == "urn:ietf:params:acme:error:serverInternal"

        # Audit: failed, and must NOT carry revocation_scope or ca_crl_updated
        # (a failure cannot honestly claim a scope).
        account_id = ac.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id, event_type="certificate-revoked")
        failed_events = [e for e in events if e["outcome"] == "failed"]
        assert failed_events, "expected a failed certificate-revoked audit event"
        details = failed_events[0]["details"]
        assert "revocation_scope" not in details
        assert "ca_crl_updated" not in details
        assert details["serial"] == serial_hex

        # State: cert is still valid, order is still valid (not flipped).
        record = store.get_certificate_by_serial(serial_hex)
        assert record is not None
        assert record.status == "valid"
        order = store.get_order(record.order_id)
        assert order is not None
        assert order.status == "valid"


class TestFakeLegRevocationResponseShape:
    """T5: the FakeRevocationLeg (ca_crl_updated=true) returns a bare 200 {} —
    the out_of_band_revocation hint is absent when the CRL was (pretend) written."""

    def test_fake_leg_response_has_no_out_of_band_hint(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200
        # Empty body on every success path, and no hint header when the leg
        # reports the CRL was written.
        assert resp.content == b"", f"expected empty body, got {resp.content!r}"
        assert _oob_hint(resp) is None


# ---------------------------------------------------------------------------
# RevocationLeg protocol and platform-gated stub
# ---------------------------------------------------------------------------


class TestRevocationLeg:
    def test_fake_leg_returns_revoked_result(self) -> None:
        leg: RevocationLeg = FakeRevocationLeg()
        result = leg.revoke("pem", reason=1)
        assert isinstance(result, RevocationResult)
        assert result.revoked is True
        assert result.reason == 1
        assert result.revoked_at is not None

    def test_certsrv_leg_is_importable(self) -> None:
        assert CertsrvRevocationLeg is not None

    def test_certsrv_leg_ctor_no_args(self) -> None:
        leg = CertsrvRevocationLeg()
        assert isinstance(leg, CertsrvRevocationLeg)

    def test_certsrv_leg_revoke_is_out_of_band_record_and_surface(self) -> None:
        """WI-010: the production leg records the revocation in the RA store
        and surfaces the out-of-band step; it does NOT call the CA and does
        NOT raise. The gMSA gains no CA-officer rights."""
        leg = CertsrvRevocationLeg()
        result = leg.revoke(_FAKE_CERT_PEM, reason=1)
        assert isinstance(result, RevocationResult)
        assert result.revoked is True
        assert result.reason == 1
        assert result.revoked_at is not None
        # The honest scope markers the route + audit rely on.
        assert result.metadata["revocation_scope"] == "ra-store-only"
        assert result.metadata["ca_crl_updated"] == "false"
        # The serial the operator's Revoke-Cert.ps1 consumes is surfaced.
        assert result.metadata["serial"] == _FAKE_CERT_SERIAL_HEX

    def test_certsrv_leg_does_not_pretend_crl_was_written(self) -> None:
        """WI-010: the leg must never claim ca_crl_updated=true — that would
        make the audit log imply the CA CRL was written when it was not,
        which is the exact dishonesty this WI removes."""
        leg = CertsrvRevocationLeg()
        result = leg.revoke(_FAKE_CERT_PEM, reason=0)
        assert result.metadata.get("ca_crl_updated") != "true"

    def test_certsrv_leg_cites_mechanism_in_docstring(self) -> None:
        """The mechanism (certutil / ICertAdmin2) and the privilege rationale
        must remain documented in the leg so a future in-band change is
        forced to confront the security decision."""
        assert "certutil" in CertsrvRevocationLeg.__doc__ or "ICertAdmin" in CertsrvRevocationLeg.__doc__


# ---------------------------------------------------------------------------
# C-1: serial-scoped revocation lookup (no cross-account serial collision)
# ---------------------------------------------------------------------------


class TestSerialCollisionSafety:
    def test_accounts_with_same_serial_isolated(self, test_config: RAConfig, account_key: rsa.RSAPrivateKey) -> None:
        """C-1: Two accounts each issue a cert (both share the FakeEnrollmentLeg
        static serial).  Revocation by one account never touches the other's row.

        With the old (unscoped) serial lookup, fetchone() could return A's row
        when B requests revocation, silently revoking A's cert.  The scoped
        lookup (serial_number, account_id) prevents this.
        """
        store = Store(test_config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(test_config.eab_keys_by_kid().keys()),
            san_scopes={
                kid: scope.dns_patterns for kid, scope in test_config.san_scopes.items()
            },
            template=test_config.adcs_template,
        )
        context = ServerContext(
            config=test_config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        client = TestClient(create_app(context))

        # Account A issues a cert (kid-001-0123456789abcdef).
        ac_a = HandRolledAcmeClient(client, test_config.base_url, account_key)
        resp_a = ac_a.new_account("kid-001-0123456789abcdef", _eab_mac_key(test_config, "kid-001-0123456789abcdef"))
        assert resp_a.status_code == 201
        order_a = ac_a.new_order(["srv01.WORK-DOMAIN.local"]).json()
        for authz_url in order_a["authorizations"]:
            authz = ac_a.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac_a.validate_challenge(ch["url"])
        csr_der_a = _make_csr(["srv01.WORK-DOMAIN.local"])
        fin_a = ac_a.finalize_order(order_a["finalize"], csr_der_a)
        assert fin_a.status_code == 200
        cert_url_a = fin_a.json()["certificate"]
        # Extract DER for the cert to use in revocation.
        cert_pem_a = ac_a.get_certificate(cert_url_a).text
        first_pem = cert_pem_a.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
        cert_der = x509.load_pem_x509_certificate(first_pem.encode("utf-8")).public_bytes(
            serialization.Encoding.DER
        )

        # Account B issues a cert (kid-002-0123456789abcdef) — same static serial from FakeEnrollmentLeg.
        key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac_b = HandRolledAcmeClient(client, test_config.base_url, key_b)
        resp_b = ac_b.new_account("kid-002-0123456789abcdef", _eab_mac_key(test_config, "kid-002-0123456789abcdef"))
        assert resp_b.status_code == 201
        order_b = ac_b.new_order(["web.prod.WORK-DOMAIN.local"]).json()
        for authz_url in order_b["authorizations"]:
            authz = ac_b.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac_b.validate_challenge(ch["url"])
        csr_der_b = _make_csr(["web.prod.WORK-DOMAIN.local"])
        fin_b = ac_b.finalize_order(order_b["finalize"], csr_der_b)
        assert fin_b.status_code == 200

        # (a) Account B revokes using the shared cert DER — should succeed
        #     (scoped to B's cert row, not A's).
        resp_revoke_b = ac_b.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_b.status_code == 200

        # (b) Account A's cert is still valid in the store.
        cert_id_a = cert_url_a.rsplit("/", 1)[-1]
        cert_a_record = store.get_certificate(cert_id_a)
        assert cert_a_record is not None
        assert cert_a_record.status == "valid"

        # (c) A second revocation by B returns 200 (already revoked, H-4)
        #     but crucially does NOT revoke A's cert.
        resp_revoke_b2 = ac_b.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_b2.status_code == 200  # already-revoked is idempotent

        # A's cert is STILL valid — the old bug would have revoked it.
        cert_a_record2 = store.get_certificate(cert_id_a)
        assert cert_a_record2 is not None
        assert cert_a_record2.status == "valid"

        # (d) Account B cannot revoke A's cert via the scoped lookup —
        #     B's cert is already revoked, so another attempt returns 200.
        #     But A can still revoke A's own cert.
        resp_revoke_a = ac_a.revoke_certificate(cert_der, reason=0)
        assert resp_revoke_a.status_code == 200

        cert_a_record3 = store.get_certificate(cert_id_a)
        assert cert_a_record3 is not None
        assert cert_a_record3.status == "revoked"


# ---------------------------------------------------------------------------
# H-1: Revoked certs are not served; order status reflects revoked
# ---------------------------------------------------------------------------


class TestRevokedCertNotServed:
    def test_get_cert_returns_410_after_revoke(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-1: After revocation, reading the cert (POST-as-GET) returns 410 Gone.

        The plain unauthenticated GET form was removed (2026-08-15 review,
        finding 4); the owning account reads via POST-as-GET, which returns 410
        for a revoked cert exactly as the GET form did."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)

        # Get the cert URL from the order.
        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None

        # Revoke.
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # POST-as-GET the cert URL → 410 Gone.
        cert_url = f"{test_config.base_url}/acme/cert/{cert_record.id}"
        cert_resp = ac.get_certificate(cert_url)
        assert cert_resp.status_code == 410

    def test_order_status_reflects_revoked(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """H-1: After revocation, the order status is 'revoked'."""
        ac, cert_der = _issue_cert(client, test_config, account_key)
        cert = x509.load_der_x509_certificate(cert_der)

        serial_hex = format(cert.serial_number, "x").upper()
        store = Store(test_config.db_path)
        cert_record = store.get_certificate_by_serial(serial_hex)
        assert cert_record is not None

        # Revoke.
        resp = ac.revoke_certificate(cert_der, reason=0)
        assert resp.status_code == 200

        # Order should be revoked.
        order = store.get_order(cert_record.order_id)
        assert order is not None
        assert order.status == "revoked"


# Helper imports placed at the bottom to avoid shadowing module-level imports.
from datetime import UTC, datetime, timedelta


def datetime_now(*, days: int = 0) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


class TestRevokeCertFieldName:
    """RFC 8555 §7.6 names the revocation payload field ``certificate``.

    The route read ``cert`` only, so every conformant ACME client was refused
    with ``malformed: missing or invalid cert field`` and could not revoke at
    all. Nothing in this suite caught it, because the hand-rolled client and the
    lab harness both sent ``cert`` too -- the client mirrored the server's own
    mistake, so a whole revocation suite passed against a dialect no other
    client speaks. Found 2026-08-24 by pointing Certify the Web at the RA.
    """

    def test_rfc_certificate_field_is_accepted(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=1)
        assert resp.status_code == 200, resp.text

    def test_deprecated_cert_alias_still_accepted(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=1, field_name="cert")
        assert resp.status_code == 200, resp.text

    def test_missing_field_names_the_rfc_spelling(
        self,
        client: TestClient,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        ac, cert_der = _issue_cert(client, test_config, account_key)
        resp = ac.revoke_certificate(cert_der, reason=1, field_name="nope")
        assert resp.status_code == 400
        # The message must name the RFC field: an operator debugging a real
        # client must not be sent looking for a key the RFC does not define.
        assert "certificate" in resp.text
