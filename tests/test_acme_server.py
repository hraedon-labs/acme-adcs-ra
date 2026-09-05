"""Integration tests for the ACME server endpoints and round-trip flow."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import EnrollmentDenied, EnrollmentResult, FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import NONCE_TTL_SECONDS, Store, _now_iso, is_expired

from .hand_rolled_acme_client import HandRolledAcmeClient

# ---------------------------------------------------------------------------
# Test config and fixtures
# ---------------------------------------------------------------------------


def _make_test_config(tmp_path: Path) -> RAConfig:
    # 32-byte base64url-encoded key.
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001", mac_key=mac_key_b64),
            EABEntry(kid="kid-002", mac_key="YW5vdGhlci0zMi1ieXRlLW1hYy1rZXktZm9yLXRlc3Rz"),
        ],
        san_scopes={
            "kid-001": {"dns_patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]},
            "kid-002": {"dns_patterns": ["*.prod.WORK-DOMAIN.local"]},
        },
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        revocation_confirm_token=SecretStr("test-confirm-token-0123456789abcdef-32+"),
    )


@pytest.fixture()
def test_config(tmp_path: Path) -> RAConfig:
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


@pytest.fixture()
def acme_client(
    client: TestClient,
    account_key: rsa.RSAPrivateKey,
) -> HandRolledAcmeClient:
    return HandRolledAcmeClient(
        http_client=client,
        base_url="http://testserver",
        account_key=account_key,
    )


def _eab_mac_key(config: RAConfig, kid: str) -> bytes:
    raw = config.eab_key_bytes(kid)
    assert raw is not None
    return raw


def _make_csr(sans: list[str]) -> bytes:
    """Build a self-signed CSR with the given DNS SANs (test code may sign)."""
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


def _order_id_from_finalize_url(finalize_url: str) -> str:
    return finalize_url.rsplit("/", 1)[-1]


def _backdate_order(store: Store, order_id: str, seconds_ago: int = 60) -> None:
    """Set an order's `expires` into the past so it is expired."""
    past = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    with store._connect() as conn:
        conn.execute("UPDATE orders SET expires = ? WHERE id = ?", (past, order_id))


def _force_order_status(
    store: Store, order_id: str, status: str, *, age_seconds: int = 3600
) -> None:
    """Test-only direct write of an order status (simulates a crash mid-flight).

    ``age_seconds`` backdates ``processing_started_at``. The default is an hour
    because that is what these tests actually depict: an order an operator
    *found* wedged, long after the enrollment leg's 30s timeout. Reclaim now
    refuses an order young enough that an enrollment could still be in flight,
    so a freshly-stamped timestamp would be simulating a different scenario —
    one the endpoint is supposed to reject.
    """
    ts = (
        (datetime.now(UTC) - timedelta(seconds=age_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if status == "processing"
        else None
    )
    with store._connect() as conn:
        conn.execute(
            "UPDATE orders SET status = ?, processing_started_at = ? WHERE id = ?",
            (status, ts, order_id),
        )


def _walk_to_ready(acme_client: HandRolledAcmeClient, identifiers: list[str]) -> Any:
    """Create an order and validate its challenges so it transitions to 'ready'."""
    order = acme_client.new_order(identifiers).json()
    for authz_url in order["authorizations"]:
        authz = acme_client.get_authorization(authz_url).json()
        acme_client.validate_challenge(authz["challenges"][0]["url"])
    return order


def _issue_cert_record(
    acme_client: HandRolledAcmeClient,
    test_config: RAConfig,
) -> Any:
    """Issue a certificate through the ACME flow and return its store record."""
    acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
    order = _walk_to_ready(acme_client, ["srv01.WORK-DOMAIN.local"])
    csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
    finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
    assert finalize_resp.status_code == 200
    cert_url = finalize_resp.json()["certificate"]
    cert_id = cert_url.rsplit("/", 1)[-1]
    return Store(test_config.db_path).get_certificate(cert_id)


class _CountingEnrollmentLeg:
    """Wraps FakeEnrollmentLeg and counts submit_csr calls.

    Used to prove that reconciliation paths (reclaim-to-valid, finalize self-heal)
    do NOT re-enroll at the CA — the security property, not just 'one cert row'.
    """

    def __init__(self, inner: FakeEnrollmentLeg | None = None) -> None:
        self._inner = inner or FakeEnrollmentLeg()
        self.submit_csr_call_count = 0

    def submit_csr(self, csr_pem: str, *, account_id: str, requested_sans: Any) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        return self._inner.submit_csr(csr_pem, account_id=account_id, requested_sans=requested_sans)


class _DenyingEnrollmentLeg:
    """Enrollment leg that always raises EnrollmentDenied.

    An optional ``pre_hook`` fires before the denial so tests can simulate
    a concurrent operation moving the order out of 'processing' (lost race).
    """

    def __init__(self, *, pre_hook: Any | None = None) -> None:
        self.submit_csr_call_count = 0
        self._pre_hook = pre_hook

    def submit_csr(self, csr_pem: str, *, account_id: str, requested_sans: Any) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        if self._pre_hook is not None:
            self._pre_hook()
        raise EnrollmentDenied("Denied by CA policy")


class _RacingDenyingEnrollmentLeg:
    """Denies enrollment after moving the order, simulating a concurrent reclaim.

    Set ``order_id`` after creating the order, before finalizing.
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self.order_id: str = ""
        self.submit_csr_call_count = 0

    def submit_csr(self, csr_pem: str, *, account_id: str, requested_sans: Any) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        self._store.transition_processing_to_ready(self.order_id)
        raise EnrollmentDenied("Denied by CA policy")


class _RacingEnrollmentLeg:
    """Enrollment leg that moves the order to 'valid' before returning.

    Simulates a concurrent self-heal: inside submit_csr it creates a cert and
    CAS-transitions the order to 'valid', so the success-path CAS-to-valid
    in finalize loses the race. Set ``order_id`` after creating the order.
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self.order_id: str = ""
        self.submit_csr_call_count = 0

    def submit_csr(self, csr_pem: str, *, account_id: str, requested_sans: Any) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        inner = FakeEnrollmentLeg()
        result = inner.submit_csr(csr_pem, account_id=account_id, requested_sans=requested_sans)
        cert = self._store.create_certificate(
            order_id=self.order_id,
            account_id=account_id,
            cert_pem=result.cert_pem,
            chain_pem=result.chain_pem,
            template=result.template,
            requester=result.requester,
            metadata=dict(result.metadata),
        )
        cert_url = f"http://testserver/acme/cert/{cert.id}"
        self._store.transition_processing_to_valid(self.order_id, cert_url)
        return result


def _make_context(config: RAConfig, enrollment: Any) -> tuple[Store, ServerContext]:
    """Build a (store, ServerContext) with an injectable enrollment leg."""
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={k: s.dns_patterns for k, s in config.san_scopes.items()},
        template=config.adcs_template,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=enrollment,
        revocation=FakeRevocationLeg(),
    )
    return store, context


# ---------------------------------------------------------------------------
# Endpoint smoke tests
# ---------------------------------------------------------------------------


class TestDirectory:
    def test_directory_shape(self, client: TestClient) -> None:
        resp = client.get("/directory")
        assert resp.status_code == 200
        body = resp.json()
        assert body["newNonce"].endswith("/acme/new-nonce")
        assert body["newAccount"].endswith("/acme/new-acct")
        assert body["newOrder"].endswith("/acme/new-order")
        assert body["revokeCert"].endswith("/acme/revoke-cert")
        assert body["meta"]["externalAccountRequired"] is True


class TestNonce:
    def test_new_nonce_head(self, client: TestClient) -> None:
        resp = client.head("/acme/new-nonce")
        assert resp.status_code == 204
        assert "Replay-Nonce" in resp.headers
        assert resp.headers["Cache-Control"] == "no-store"

    def test_new_nonce_get(self, client: TestClient) -> None:
        resp = client.get("/acme/new-nonce")
        assert resp.status_code == 204
        assert "Replay-Nonce" in resp.headers


# ---------------------------------------------------------------------------
# newAccount + EAB
# ---------------------------------------------------------------------------


class TestNewAccount:
    def test_oversized_jws_body_rejected_before_buffering(
        self, client: TestClient, test_config: RAConfig
    ) -> None:
        body = b"{" + (b"x" * test_config.max_jws_body_size_bytes) + b"}"
        resp = client.post(
            "/acme/new-acct",
            content=body,
            headers={"Content-Type": "application/jose+json"},
        )
        assert resp.status_code == 400
        assert "JWS request body too large" in resp.json()["detail"]

    def test_new_account_success(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "valid"
        assert "Location" in resp.headers
        assert resp.headers["Location"].startswith("http://testserver/acme/acct/")

    def test_new_account_requires_eab(self, acme_client: HandRolledAcmeClient) -> None:
        url = f"{acme_client.base_url}/acme/new-acct"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": url,
            "jwk": acme_client.account_jwk,
        }
        body = sign_jws({"termsOfServiceAgreed": True}, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "externalAccountBinding" in resp.json()["detail"]

    def test_new_account_unknown_kid_rejected(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        resp = acme_client.new_account("kid-unknown", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badExternalAccountBinding"

    def test_new_account_wrong_mac_rejected(
        self, acme_client: HandRolledAcmeClient
    ) -> None:
        bad_key = b"wrong-key-32-bytes-long!!!!!!!!!"
        resp = acme_client.new_account("kid-001", bad_key)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badExternalAccountBinding"

    def test_replayed_nonce_rejected(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        url = f"{acme_client.base_url}/acme/new-acct"
        from .hand_rolled_acme_client import make_eab_jws, sign_jws

        nonce = acme_client._fresh_nonce()
        eab_jws = make_eab_jws(
            acme_client.account_jwk,
            "kid-001",
            _eab_mac_key(test_config, "kid-001"),
            url=url,
        )
        protected = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
            "jwk": acme_client.account_jwk,
        }
        body = sign_jws(
            {"externalAccountBinding": eab_jws, "termsOfServiceAgreed": True},
            acme_client.account_key,
            protected,
        )
        resp1 = acme_client.http.post(url, json=body)
        assert resp1.status_code == 201
        resp2 = acme_client.http.post(url, json=body)
        assert resp2.status_code == 400
        assert resp2.json()["type"] == "urn:ietf:params:acme:error:badNonce"


# ---------------------------------------------------------------------------
# M-2: Failed account-creation attempts are audited
# ---------------------------------------------------------------------------


class TestAccountCreationDeniedAudit:
    def test_unknown_kid_produces_audit_row(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """M-2: An unknown-kid newAccount attempt produces an account-creation-denied audit row."""
        store = Store(test_config.db_path)
        before = store.list_audit_events(event_type="account-creation-denied")
        resp = acme_client.new_account("kid-unknown", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 400
        after = store.list_audit_events(event_type="account-creation-denied")
        assert len(after) == len(before) + 1
        assert after[0]["outcome"] == "failed"
        assert after[0]["details"]["reason"] == "unknown EAB kid"
        assert after[0]["details"]["kid"] == "kid-unknown"

    def test_wrong_mac_produces_audit_row(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """M-2: A bad-MAC newAccount attempt produces an account-creation-denied audit row."""
        store = Store(test_config.db_path)
        before = store.list_audit_events(event_type="account-creation-denied")
        bad_key = b"wrong-key-32-bytes-long!!!!!!!!!"
        resp = acme_client.new_account("kid-001", bad_key)
        assert resp.status_code == 400
        after = store.list_audit_events(event_type="account-creation-denied")
        assert len(after) == len(before) + 1
        assert after[0]["outcome"] == "failed"
        assert "EAB MAC verification failed" in after[0]["details"]["reason"]
        # The MAC key itself must NOT appear in the audit row.
        details_str = json.dumps(after[0]["details"])
        assert "wrong-key" not in details_str


# ---------------------------------------------------------------------------
# newOrder / finalize / policy
# ---------------------------------------------------------------------------


class TestPolicyViaFinalize:
    def test_in_scope_san_issues_certificate(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201

        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        order = resp.json()
        assert order["status"] == "pending"
        assert len(order["authorizations"]) == 1

        # Walk authz -> challenge -> valid.
        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        assert authz_resp.status_code == 200
        challenge = authz_resp.json()["challenges"][0]
        assert challenge["status"] == "pending"
        challenge_resp = acme_client.validate_challenge(challenge["url"])
        assert challenge_resp.status_code == 200
        assert challenge_resp.json()["status"] == "valid"

        # Finalize with a CSR matching the identifier.
        csr_der = _make_csr(["web.WORK-DOMAIN.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        finalized_order = finalize_resp.json()
        assert finalized_order["status"] == "valid"
        assert "certificate" in finalized_order

        cert_resp = acme_client.get_certificate(finalized_order["certificate"])
        assert cert_resp.status_code == 200
        assert cert_resp.headers["Content-Type"] == "application/pem-certificate-chain"
        assert "BEGIN CERTIFICATE" in cert_resp.text

    def test_out_of_scope_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["evil.other-domain.local"])
        assert resp.status_code == 201
        order = resp.json()

        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        challenge = authz_resp.json()["challenges"][0]
        acme_client.validate_challenge(challenge["url"])

        csr_der = _make_csr(["evil.other-domain.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"

    def test_empty_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["srv01.WORK-DOMAIN.local"])
        order = resp.json()

        authz_url = order["authorizations"][0]
        authz_resp = acme_client.get_authorization(authz_url)
        challenge = authz_resp.json()["challenges"][0]
        acme_client.validate_challenge(challenge["url"])

        # CSR with only a subject CN and no SAN extension.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"
        assert "no SANs" in finalize_resp.json()["detail"]

    def test_wrong_account_kid_rejected(self, acme_client: HandRolledAcmeClient, test_config: RAConfig) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        # Send a newOrder signed with a bogus account URL.
        acme_client.account_url = "http://testserver/acme/acct/00000000000000000000000000000000"
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 401
        assert resp.json()["type"] == "urn:ietf:params:acme:error:unauthorized"


class TestNewOrderDnsIdentifierValidation:
    """WI-009: malformed DNS identifiers must be rejected at newOrder, not at finalize.

    ``validate_dns_name`` (RFC 1123) is called at order creation so the client
    learns of a rejection immediately rather than wasting a challenge +
    finalize round-trip. The CSR path keeps its own copy of the gate as
    defense-in-depth.
    """

    @pytest.mark.parametrize("identifier", [
        "*.WORK-DOMAIN.local",
        "foo*.WORK-DOMAIN.local",
        "web..WORK-DOMAIN.local",
        "web!.WORK-DOMAIN.local",
        "web_.WORK-DOMAIN.local",
        "-web.WORK-DOMAIN.local",
        "web-.WORK-DOMAIN.local",
        "a" * 254 + ".WORK-DOMAIN.local",
    ])
    def test_malformed_identifier_rejected_at_new_order(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        identifier: str,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order([identifier])
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"
        if "*" in identifier:
            assert "wildcard" in resp.json()["detail"]
        else:
            assert "invalid DNS identifier" in resp.json()["detail"]

    def test_valid_identifier_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A valid DNS identifier must still create an order (regression)."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"

    def test_fqdn_with_trailing_dot_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A trailing-dot FQDN (RFC 1034 notation) is valid DNS syntax."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local."])
        assert resp.status_code == 201

    def test_one_bad_identifier_among_many_rejects_whole_order(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """If any identifier is malformed, the whole order is rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order([
            "web.WORK-DOMAIN.local",
            "web..WORK-DOMAIN.local",
        ])
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"


# ---------------------------------------------------------------------------
# Full round trip
# ---------------------------------------------------------------------------


class TestOrderExpiry:
    def test_order_expires_in_the_future(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """Orders must not be born expired (RFC 8555 §7.1.4) — a well-behaved
        client rejects an already-expired order."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        expires_str = resp.json()["expires"]
        expires = datetime.fromisoformat(expires_str)
        assert expires > datetime.now(UTC)
        # Default lifetime is 1h; allow slack for test runtime.
        assert (expires - datetime.now(UTC)).total_seconds() > 3000


class TestFullRoundTrip:
    def test_certify_the_web_like_flow(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        # 1. EAB-bound newAccount.
        resp = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201

        # 2. newOrder for an in-scope SAN.
        resp = acme_client.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        order = resp.json()
        assert order["status"] == "pending"

        # 3. Walk each authorization to valid.
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                val_resp = acme_client.validate_challenge(challenge["url"])
                assert val_resp.json()["status"] == "valid"

        # 4. Finalize with CSR.
        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert resp.status_code == 200
        finalized = resp.json()
        assert finalized["status"] == "valid"
        assert "certificate" in finalized

        # 5. Retrieve certificate.
        cert_resp = acme_client.get_certificate(finalized["certificate"])
        assert cert_resp.status_code == 200
        assert cert_resp.headers["Content-Type"] == "application/pem-certificate-chain"
        pem_text = cert_resp.text
        assert "BEGIN CERTIFICATE" in pem_text
        cert_count = pem_text.count("BEGIN CERTIFICATE")
        assert cert_count >= 1

        # 6. Audit row exists.
        store = Store(test_config.db_path)
        assert acme_client.account_url is not None
        account_id = acme_client.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id)
        assert any(e["event_type"] == "certificate-issued" for e in events)


# ---------------------------------------------------------------------------
# Audit hook
# ---------------------------------------------------------------------------


class TestAuditHook:
    def test_hook_called_for_account_created(
        self,
        test_config: RAConfig,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        events: list[dict[str, Any]] = []

        def hook(event: dict[str, Any]) -> None:
            events.append(event)

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
            audit_hook=hook,
        )
        client = TestClient(create_app(context))
        ac = HandRolledAcmeClient(client, "http://testserver", account_key)
        resp = ac.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert resp.status_code == 201
        assert any(e["event_type"] == "account-created" and e["outcome"] == "success" for e in events)


# ---------------------------------------------------------------------------
# Nonce garbage collection
# ---------------------------------------------------------------------------


class TestNonceGarbageCollection:
    def test_cleanup_expired_nonces(self, tmp_path: Path) -> None:
        """Expired nonces are removed by cleanup_expired_nonces."""
        store = Store(tmp_path / "test_gc.db")
        now = datetime.now(UTC)
        old_ts = (now - timedelta(seconds=NONCE_TTL_SECONDS + 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with store._connect() as conn:
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("old-nonce-1", old_ts))
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("old-nonce-2", old_ts))
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("fresh-nonce", now.strftime("%Y-%m-%dT%H:%M:%SZ")))
        deleted = store.cleanup_expired_nonces()
        assert deleted == 2
        with store._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as c FROM nonces").fetchone()
            assert row["c"] == 1


class TestNonceConsumeTtl:
    """TTL is enforced at consume time, not just by the cleanup sweep."""

    def test_fresh_nonce_consumes(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "test_consume_fresh.db")
        nonce = store.create_nonce()
        assert store.consume_nonce(nonce) is True
        # Single-use: a second consume of the same nonce is a replay.
        assert store.consume_nonce(nonce) is False

    def test_expired_nonce_rejected_at_consume(self, tmp_path: Path) -> None:
        """An unused nonce older than the TTL is rejected even if neither the
        probabilistic GC nor the admin cron has swept it yet."""
        store = Store(tmp_path / "test_consume_expired.db")
        old_ts = (datetime.now(UTC) - timedelta(seconds=NONCE_TTL_SECONDS + 60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with store._connect() as conn:
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("stale-nonce", old_ts))
        assert store.consume_nonce("stale-nonce") is False
        # A retry fails identically (no oracle between expired and unknown).
        assert store.consume_nonce("stale-nonce") is False
        assert store.consume_nonce("never-existed") is False

    def test_consume_ttl_boundary(self, tmp_path: Path) -> None:
        """The cutoff is inclusive: a nonce within the TTL window is consumable,
        one just past it is rejected (created_at >= now-TTL)."""
        store = Store(tmp_path / "test_consume_boundary.db")
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        now = datetime.now(UTC)
        just_inside = (now - timedelta(seconds=NONCE_TTL_SECONDS - 5)).strftime(fmt)
        just_outside = (now - timedelta(seconds=NONCE_TTL_SECONDS + 5)).strftime(fmt)
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("in-nonce", just_inside)
            )
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                ("out-nonce", just_outside),
            )
        assert store.consume_nonce("in-nonce") is True
        assert store.consume_nonce("out-nonce") is False

    def test_concurrent_consume_is_single_use(self, tmp_path: Path) -> None:
        """Racing many consumers of one fresh nonce yields exactly one winner
        (single-statement DELETE is atomic; busy_timeout serializes writers)."""
        from concurrent.futures import ThreadPoolExecutor

        store = Store(tmp_path / "test_consume_race.db")
        nonce = store.create_nonce()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: store.consume_nonce(nonce), range(16)))
        assert results.count(True) == 1
        assert results.count(False) == 15

    def test_expired_nonce_rejected_via_endpoint(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        """End-to-end: an issued nonce aged past the TTL is rejected with
        badNonce when presented to the ACME endpoint (consume-time enforcement
        is wired into the request path, not just the store)."""
        url = f"{acme_client.base_url}/acme/new-acct"
        from .hand_rolled_acme_client import make_eab_jws, sign_jws

        nonce = acme_client._fresh_nonce()
        # Age the issued nonce past the TTL in the backing store.
        old_ts = (datetime.now(UTC) - timedelta(seconds=NONCE_TTL_SECONDS + 60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        backing = Store(test_config.db_path)
        with backing._connect() as conn:
            conn.execute("UPDATE nonces SET created_at = ? WHERE nonce = ?", (old_ts, nonce))

        eab_jws = make_eab_jws(
            acme_client.account_jwk,
            "kid-001",
            _eab_mac_key(test_config, "kid-001"),
            url=url,
        )
        protected = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
            "jwk": acme_client.account_jwk,
        }
        body = sign_jws(
            {"externalAccountBinding": eab_jws, "termsOfServiceAgreed": True},
            acme_client.account_key,
            protected,
        )
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badNonce"


# ---------------------------------------------------------------------------
# H2: Full-URL binding (scheme + host + path + query)
# ---------------------------------------------------------------------------


class TestFullUrlBinding:
    def test_jws_with_wrong_host_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A JWS whose protected url has a different host must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        # Forge a JWS with a wrong host in the url.
        url = f"{acme_client.base_url}/acme/new-order"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": "http://evil-host/acme/new-order",  # wrong host
            "kid": acme_client.account_url,
        }
        payload = {
            "identifiers": [{"type": "dns", "value": "test.WORK-DOMAIN.local"}],
        }
        body = sign_jws(payload, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "host mismatch" in resp.json()["detail"]

    def test_jws_with_correct_full_url_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A JWS whose protected url matches scheme+host+path works."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        assert resp.status_code == 201

    def test_jws_with_relative_url_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A relative url (no scheme/host) must be rejected - otherwise a stolen
        JWS could replay against any host at the same path."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        url = f"{acme_client.base_url}/acme/new-order"
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": "/acme/new-order",  # relative - must be rejected
            "kid": acme_client.account_url,
        }
        payload = {"identifiers": [{"type": "dns", "value": "test.WORK-DOMAIN.local"}]}
        body = sign_jws(payload, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "absolute URL" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# H3: Challenge payload must be {}
# ---------------------------------------------------------------------------


class TestChallengePayloadValidation:
    def test_non_empty_payload_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A challenge POST with non-empty payload must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        authz_url = order["authorizations"][0]
        authz = acme_client.get_authorization(authz_url).json()
        challenge = authz["challenges"][0]

        # Send a challenge POST with a non-empty payload.
        url = challenge["url"]
        from .hand_rolled_acme_client import sign_jws

        protected = {
            "alg": "RS256",
            "nonce": acme_client._fresh_nonce(),
            "url": url,
            "kid": acme_client.account_url,
        }
        body = sign_jws({"keyAuthorization": "bogus"}, acme_client.account_key, protected)
        resp = acme_client.http.post(url, json=body)
        assert resp.status_code == 400
        assert "empty object" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# M-2: CAS-guarded pending→ready transition (_maybe_ready_order)
# ---------------------------------------------------------------------------


class TestMaybeReadyOrderCasGuard:
    """M-2: _maybe_ready_order uses transition_pending_to_ready (CAS on
    status='pending') so a concurrent finalize that has moved the order to
    'processing' cannot be clobbered back to 'ready' by a late/racing
    challenge validation."""

    def test_pending_to_ready_does_not_clobber_processing(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """A pending order whose authz are all valid should transition to
        ready; but if a concurrent finalize has moved it to 'processing'
        between the authz check and the CAS UPDATE, the CAS must NOT clobber
        it back to 'ready' (which would allow a re-enroll / double-issue)."""
        from acme_adcs_ra.routes.authorizations import _maybe_ready_order

        config = _make_test_config(tmp_path)
        store, context = _make_context(config, FakeEnrollmentLeg())
        client = TestClient(create_app(context))
        ac = HandRolledAcmeClient(client, config.base_url, account_key)
        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(ac, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        # The order is 'ready' after _walk_to_ready. Simulate the race: a
        # concurrent finalize moved it to 'processing' (no cert yet). Manually
        # flip ready→processing so the CAS in transition_pending_to_ready loses.
        assert store.acquire_processing_lease(order_id) is not None
        assert store.get_order(order_id).status == "processing"

        # Reset the order to 'pending' so _maybe_ready_order's status check
        # passes, then immediately move it to 'processing' to simulate the
        # race. We exercise the CAS directly via the store method, which is
        # what _maybe_ready_order now calls.
        _force_order_status(store, order_id, "pending")
        # Now simulate: a concurrent finalize flips pending→ready→processing
        # before _maybe_ready_order's CAS runs. First walk to processing:
        assert store.acquire_processing_lease(
            order_id
        ) is None  # can't: it's pending, not ready
        # Manually set to processing to simulate the concurrent finalize.
        _force_order_status(store, order_id, "processing")

        # The CAS must lose: transition_pending_to_ready returns False, the
        # order stays 'processing' (NOT clobbered to 'ready').
        assert store.transition_pending_to_ready(order_id) is False
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "processing"
        assert refreshed.processing_started_at is not None

        # And _maybe_ready_order itself is a no-op when the order is not
        # pending (it returns before touching the store). Confirm by calling
        # it directly: the order stays 'processing'.
        _maybe_ready_order(context, order_id)
        refreshed2 = store.get_order(order_id)
        assert refreshed2 is not None
        assert refreshed2.status == "processing"

    def test_pending_to_ready_succeeds_when_still_pending(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """The happy path: a genuinely pending order with all valid authz
        transitions to ready (the CAS applies because status is still
        'pending'). Regression guard for the M-2 CAS change."""
        config = _make_test_config(tmp_path)
        store, context = _make_context(config, FakeEnrollmentLeg())
        client = TestClient(create_app(context))
        ac = HandRolledAcmeClient(client, config.base_url, account_key)
        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))

        # Create an order but do NOT walk its challenges — it stays 'pending'.
        order = ac.new_order(["web.WORK-DOMAIN.local"]).json()
        order_id = _order_id_from_finalize_url(order["finalize"])
        assert store.get_order(order_id).status == "pending"

        # Mark all authz valid directly so _maybe_ready_order's authz check
        # passes, without driving the challenge endpoint (which would itself
        # call _maybe_ready_order).
        for authz_url in order["authorizations"]:
            authz_id = authz_url.rsplit("/", 1)[-1]
            store.update_authorization_status(authz_id, "valid")
            # Mark the challenge valid too so the authz is internally consistent.
            authz = store.get_authorization(authz_id)
            assert authz is not None
            for ch in authz.challenges:
                store.update_challenge_status(ch.id, "valid", validated_at=_now_iso())

        # The CAS applies: pending→ready.
        assert store.transition_pending_to_ready(order_id) is True
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"
        assert refreshed.processing_started_at is None

    def test_expired_pending_order_not_promoted_to_ready(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """LOW-2: an expired-but-still-pending order (sweep hasn't run) whose
        authz are all valid must NOT be advanced to 'ready' by
        _maybe_ready_order. Finalize rejects expired orders anyway, so a
        transient 'ready' serves no client. The order stays 'pending' for the
        sweep to move to 'invalid'."""
        from acme_adcs_ra.routes.authorizations import _maybe_ready_order

        config = _make_test_config(tmp_path)
        store, context = _make_context(config, FakeEnrollmentLeg())
        client = TestClient(create_app(context))
        ac = HandRolledAcmeClient(client, config.base_url, account_key)
        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))

        order = ac.new_order(["web.WORK-DOMAIN.local"]).json()
        order_id = _order_id_from_finalize_url(order["finalize"])
        assert store.get_order(order_id).status == "pending"

        # Mark all authz valid so the only thing blocking ready is expiry.
        for authz_url in order["authorizations"]:
            authz_id = authz_url.rsplit("/", 1)[-1]
            store.update_authorization_status(authz_id, "valid")
            authz = store.get_authorization(authz_id)
            assert authz is not None
            for ch in authz.challenges:
                store.update_challenge_status(ch.id, "valid", validated_at=_now_iso())

        # Backdate the order's expiry into the past.
        with store._connect() as conn:
            conn.execute(
                "UPDATE orders SET expires = ? WHERE id = ?",
                ("1990-01-01T00:00:00Z", order_id),
            )
        assert store.get_order(order_id).expires == "1990-01-01T00:00:00Z"

        # _maybe_ready_order must NOT promote an expired order to ready.
        _maybe_ready_order(context, order_id)
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "pending"

    def test_idempotent_pending_to_ready_returns_false_on_second_call(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """A second transition_pending_to_ready on an already-ready order
        returns False (the CAS no longer applies) — no clobber."""
        config = _make_test_config(tmp_path)
        store, _context = _make_context(config, FakeEnrollmentLeg())
        client = TestClient(create_app(_make_context(config, FakeEnrollmentLeg())[1]))
        ac = HandRolledAcmeClient(client, config.base_url, account_key)
        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(ac, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])
        assert store.get_order(order_id).status == "ready"

        # Already ready — the pending→ready CAS does not apply.
        assert store.transition_pending_to_ready(order_id) is False
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"


# ---------------------------------------------------------------------------
# M3: Processing state + double-finalize guard
# ---------------------------------------------------------------------------


class TestDoubleFinalizeGuard:
    def test_double_finalize_returns_existing_cert(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """Finalizing an already-finalized order returns the existing cert."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()

        # Walk to valid.
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        # First finalize.
        csr_der = _make_csr(["web.WORK-DOMAIN.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        first_cert_url = finalize_resp.json().get("certificate")

        # Second finalize with same order — should return existing cert, not error.
        finalize_resp2 = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp2.status_code == 200
        second_cert_url = finalize_resp2.json().get("certificate")
        assert first_cert_url == second_cert_url

    def test_finalize_on_processing_order_does_not_re_enroll(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        """An order at 'processing' (mid-flight, no cert yet) must NOT be
        re-enrolled - the server returns it for polling. Prevents double
        issuance on a concurrent/retried finalize."""
        config = _make_test_config(tmp_path)
        store = Store(config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(config.eab_keys_by_kid().keys()),
            san_scopes={k: s.dns_patterns for k, s in config.san_scopes.items()},
            template=config.adcs_template,
        )
        app = create_app(
            ServerContext(
                config=config,
                store=store,
                policy=policy,
                enrollment=FakeEnrollmentLeg(),
                revocation=FakeRevocationLeg(),
            )
        )
        client = TestClient(app)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = ac.new_order(["web.WORK-DOMAIN.local"]).json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for ch in authz["challenges"]:
                ac.validate_challenge(ch["url"])

        order_id = order["finalize"].split("/")[-1]
        # Simulate a first finalize that crashed mid-enrollment: order is
        # 'processing', no cert stored yet.
        assert store.acquire_processing_lease(order_id) is not None
        assert store.get_certificate_by_order(order_id) is None

        resp = ac.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        # Must NOT have re-enrolled: no cert stored, order still processing,
        # client told to retry.
        assert resp.status_code == 200
        assert resp.json()["status"] == "processing"
        assert resp.headers.get("retry-after") is not None
        assert store.get_certificate_by_order(order_id) is None


# ---------------------------------------------------------------------------
# M4: CSR with non-DNS SAN types rejected
# ---------------------------------------------------------------------------


class TestCsrSanTypeValidation:
    def test_csr_with_ip_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with an IPAddress SAN must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        # CSR with both DNS and IP SANs.
        import ipaddress
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("web.WORK-DOMAIN.local"),
            x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "IPAddress" in finalize_resp.json()["detail"]

    def test_csr_with_uri_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with a URI SAN must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("web.WORK-DOMAIN.local"),
            x509.UniformResourceIdentifier("https://example.com"),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert "UniformResourceIdentifier" in finalize_resp.json()["detail"]

    def test_csr_with_wildcard_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with a wildcard SAN (*.example.com) must be rejected.

        Wildcard certificates are a distinct risk profile from wildcard scope
        patterns. Without this gate, a *.example.com SAN would match a
        *.example.com scope pattern, silently authorizing a wildcard cert.

        The order uses a valid identifier (WI-009 rejects wildcards at newOrder);
        the CSR gate is defense-in-depth — it fires before the CSR⊆order check.
        """
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "*.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("*.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "wildcard" in finalize_resp.json()["detail"]

    def test_csr_with_partial_wildcard_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with a partial-wildcard SAN (foo*.example.com) must be rejected.

        Without this gate, foo*.example.com would bypass the scope matcher
        because the suffix after the first dot still matches the pattern base.

        The order uses a valid identifier (WI-009 rejects wildcards at newOrder);
        the CSR gate is defense-in-depth — it fires before the CSR⊆order check.
        """
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "foo*.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("foo*.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "wildcard" in finalize_resp.json()["detail"]


# ---------------------------------------------------------------------------
# M4c: DNS name syntax validation (RFC 1123)
# ---------------------------------------------------------------------------


class TestCsrDnsNameValidation:
    """CSRs with malformed DNS SANs must be rejected before reaching ADCS.

    ``cryptography.x509.DNSName`` accepts names that violate RFC 1123 label
    rules (empty labels, invalid characters, leading/trailing hyphens). The
    ADCS template might honor them. These tests verify the general syntax
    gate catches them — the DNS validation runs before the order-mismatch
    check, so the order identifier can differ from the CSR SAN.
    """

    @pytest.mark.parametrize("san,fragment", [
        ("web..WORK-DOMAIN.local", "empty label"),
        ("web!.WORK-DOMAIN.local", "invalid character"),
        ("web_.WORK-DOMAIN.local", "invalid character"),
        ("-web.WORK-DOMAIN.local", "hyphen"),
        ("web-.WORK-DOMAIN.local", "hyphen"),
    ])
    def test_malformed_san_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        san: str,
        fragment: str,
    ) -> None:
        """A CSR with a malformed DNS SAN must be rejected with badCSR."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])

        csr_der = _make_csr([san])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "valid DNS name" in finalize_resp.json()["detail"]

    def test_hyphenated_san_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """A CSR with a valid hyphenated SAN (my-host) must be accepted.

        Regression test: the DNS syntax validator must not reject hyphens
        in the middle of a label — only leading/trailing hyphens.
        """
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["my-host.WORK-DOMAIN.local"])

        csr_der = _make_csr(["my-host.WORK-DOMAIN.local"])
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200


# ---------------------------------------------------------------------------
# M5: Minimum key strength
# ---------------------------------------------------------------------------


class TestMinimumKeyStrength:
    def test_rsa_1024_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        tmp_path: Path,
    ) -> None:
        """An RSA-1024 CSR must be rejected."""
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = acme_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                acme_client.validate_challenge(challenge["url"])

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("web.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 400
        assert finalize_resp.json()["type"] == "urn:ietf:params:acme:error:badCSR"
        assert "1024" in finalize_resp.json()["detail"]

    def test_ec_p256_accepted(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        """An EC P-256 CSR must be accepted."""
        # Create an ACME client with an EC key.
        ec_key = ec.generate_private_key(ec.SECP256R1())
        from .hand_rolled_acme_client import HandRolledAcmeClient as HRC
        ec_client = HRC(
            http_client=acme_client.http,
            base_url=acme_client.base_url,
            account_key=ec_key,
        )
        ec_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        resp = ec_client.new_order(["web.WORK-DOMAIN.local"])
        order = resp.json()
        for authz_url in order["authorizations"]:
            authz = ec_client.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ec_client.validate_challenge(challenge["url"])

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "web.WORK-DOMAIN.local")])
        san = x509.SubjectAlternativeName([x509.DNSName("web.WORK-DOMAIN.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        finalize_resp = ec_client.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200


class TestReviewFixes:
    """Regression tests for the post-review fixes (CSR<=order, idempotent
    newAccount, validation-before-processing)."""

    def _ready_order(
        self, acme_client: HandRolledAcmeClient, identifiers: list[str]
    ) -> Any:
        order = acme_client.new_order(identifiers).json()
        for authz_url in order["authorizations"]:
            authz = acme_client.get_authorization(authz_url).json()
            acme_client.validate_challenge(authz["challenges"][0]["url"])
        return order

    def test_finalize_rejects_csr_san_not_in_order(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        # other.WORK-DOMAIN.local is within kid-001's EAB scope (*.WORK-DOMAIN.local)
        # but was NOT in the order — it must still be rejected (RFC 8555 §7.4).
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = self._ready_order(acme_client, ["web.WORK-DOMAIN.local"])
        csr_der = _make_csr(["other.WORK-DOMAIN.local"])
        resp = acme_client.finalize_order(order["finalize"], csr_der)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:rejectedIdentifier"
        assert "not present in the order" in resp.json()["detail"]

    def test_rejected_csr_leaves_order_retryable(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        # A CSR rejected by validation must NOT wedge the order in 'processing';
        # the client can retry the same order with a correct CSR.
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = self._ready_order(acme_client, ["web.WORK-DOMAIN.local"])
        bad = acme_client.finalize_order(order["finalize"], _make_csr(["other.WORK-DOMAIN.local"]))
        assert bad.status_code == 400
        # Retry with the correct CSR succeeds.
        good = acme_client.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert good.status_code == 200
        assert good.json()["status"] == "valid"

    def test_finalize_csr_san_case_insensitive_subset(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = self._ready_order(acme_client, ["web.WORK-DOMAIN.local"])
        resp = acme_client.finalize_order(order["finalize"], _make_csr(["WEB.work-domain.local"]))
        assert resp.status_code == 200
        assert resp.json()["status"] == "valid"

    def test_new_account_is_idempotent(
        self, acme_client: HandRolledAcmeClient, test_config: RAConfig
    ) -> None:
        first = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert first.status_code == 201
        second = acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        assert second.status_code == 200
        assert second.headers["Location"] == first.headers["Location"]

    def test_only_return_existing_unknown_key(
        self, acme_client: HandRolledAcmeClient
    ) -> None:
        # No account for this key yet; onlyReturnExisting must 400 accountDoesNotExist
        # without needing EAB.
        url = f"{acme_client.base_url}/acme/new-acct"
        resp = acme_client._post_jws(url, {"onlyReturnExisting": True}, is_new_account=True)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:accountDoesNotExist"


# ---------------------------------------------------------------------------
# RFC 8555 §7.1.6: order expiry enforcement at finalize
# ---------------------------------------------------------------------------


class TestOrderExpiryEnforcement:
    """An expired order MUST NOT be finalizable (RFC 8555 §7.1.6)."""

    def test_finalize_expired_order_rejected_and_marked_invalid(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        _backdate_order(store, order_id)

        resp = acme_client.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
        assert "expired" in resp.json()["detail"]

        # The order was transitioned to invalid (RFC 8555 §7.1.6).
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "invalid"

        # Audited as a denied finalize.
        events = store.list_audit_events(event_type="finalize-expired-order")
        assert any(e["order_id"] == order_id and e["outcome"] == "denied" for e in events)

    def test_fresh_order_still_finalizes(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
    ) -> None:
        # Guard against the expiry check being over-broad: a fresh order issues.
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        resp = acme_client.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert resp.status_code == 200
        assert resp.json()["status"] == "valid"


# ---------------------------------------------------------------------------
# Operator reconciliation of an order stuck in 'processing'
# ---------------------------------------------------------------------------


class TestStuckProcessingReclaim:
    """Admin endpoint to reconcile an order wedged in 'processing'."""

    def test_reclaim_without_certificate_returns_ready(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        # Simulate a crash mid-enrollment: order stuck in 'processing', no cert.
        _force_order_status(store, order_id, "processing")
        assert store.get_certificate_by_order(order_id) is None

        # The no-cert branch requires the operator's explicit CA-checked
        # assertion (absence of a cert row does not prove non-issuance).
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"
        assert refreshed.processing_started_at is None

        events = store.list_audit_events(event_type="admin-order-reclaimed")
        assert any(
            e["order_id"] == order_id
            and e["details"].get("new_status") == "ready"
            and e["details"].get("had_certificate") is False
            for e in events
        )

    def test_reclaim_with_certificate_returns_valid(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # Reproduce the crash window BETWEEN create_certificate and the status
        # flip: complete a real issue, then reset the order to 'processing'.
        # The cert row remains, so reclaim must close the loop to 'valid'
        # without re-enrolling (no double-issuance at the CA).
        config = _make_test_config(tmp_path)
        leg = _CountingEnrollmentLeg()
        store, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        order_id = _order_id_from_finalize_url(order["finalize"])
        assert leg.submit_csr_call_count == 1  # one enrollment so far

        assert store.get_certificate_by_order(order_id) is not None
        _force_order_status(store, order_id, "processing")

        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "valid"
        assert "certificate" in body

        # Reclaim closed the loop WITHOUT contacting the CA again.
        assert leg.submit_csr_call_count == 1

        # Exactly one cert row exists.
        with store._connect() as conn:
            cert_count = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE order_id = ?", (order_id,)
            ).fetchone()[0]
        assert cert_count == 1

        events = store.list_audit_events(event_type="admin-order-reclaimed")
        assert any(
            e["order_id"] == order_id
            and e["details"].get("new_status") == "valid"
            and e["details"].get("had_certificate") is True
            for e in events
        )

    def test_finalize_self_heals_processing_order_with_existing_cert(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # Crash window: a cert row exists but the order is stuck in 'processing'.
        # A client re-finalizing must get back valid + the certificate URL
        # (self-heal), NOT be told to poll forever — and must NOT re-enroll.
        config = _make_test_config(tmp_path)
        leg = _CountingEnrollmentLeg()
        store, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        order_id = _order_id_from_finalize_url(order["finalize"])
        _force_order_status(store, order_id, "processing")

        resp = acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "valid"
        assert "certificate" in body
        assert leg.submit_csr_call_count == 1  # not re-enrolled

        events = store.list_audit_events(event_type="finalize-order-reconciled")
        assert any(e["order_id"] == order_id and e["outcome"] == "success" for e in events)

    def test_reclaim_to_ready_then_finalize_enrolls_exactly_once(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # The most dangerous path: reclaim-to-ready (no cert recorded) is the
        # one operator action that can enable a re-enroll. Prove end-to-end that
        # after reclaim, a re-finalize produces EXACTLY ONE enrollment — not
        # zero (the order is still issuable) and not two (no double-enrollment).
        config = _make_test_config(tmp_path)
        leg = _CountingEnrollmentLeg()
        store, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        # Crash mid-enrollment: no cert recorded, order stuck in 'processing'.
        _force_order_status(store, order_id, "processing")
        assert leg.submit_csr_call_count == 0
        assert store.get_certificate_by_order(order_id) is None

        # Operator (having confirmed no cert at the CA) reclaims to ready,
        # asserting the CA-checked reconciliation the endpoint now requires.
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"
        assert leg.submit_csr_call_count == 0  # reclaim does not enroll

        # Client re-finalizes -> exactly one enrollment, order ends valid.
        finalize_resp = acme.finalize_order(
            order["finalize"], _make_csr(["web.WORK-DOMAIN.local"])
        )
        assert finalize_resp.status_code == 200
        assert finalize_resp.json()["status"] == "valid"
        assert leg.submit_csr_call_count == 1

    def test_reclaim_requires_admin_token(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        # No Authorization header.
        resp = client.post(f"/acme/admin/orders/{order_id}/reclaim-processing")
        assert resp.status_code == 401

        # Wrong token.
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

        # Order unchanged.
        store = Store(test_config.db_path)
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"

    def test_reclaim_non_processing_is_idempotent_noop(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        # Order is 'ready' (not stuck): reclaim returns current state, and the
        # no-op is audited (so a stolen admin token probing order IDs is visible
        # to SIEM — threat-model §4.F).
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

        store = Store(test_config.db_path)
        noop_events = store.list_audit_events(event_type="admin-order-reclaim-noop")
        assert any(
            e["order_id"] == order_id
            and e["outcome"] == "noop"
            and e["details"].get("order_status") == "ready"
            for e in noop_events
        )
        # No success reclaim row for the no-op.
        success_events = store.list_audit_events(event_type="admin-order-reclaimed")
        assert not any(e["order_id"] == order_id for e in success_events)

    def test_reclaim_unknown_order_is_not_found_and_audited(
        self, test_config: RAConfig, client: TestClient
    ) -> None:
        for i in range(40):
            resp = client.post(
                f"/acme/admin/orders/does-not-exist-{i}/reclaim-processing",
                headers={
                    "Authorization":
                        "Bearer test-admin-token-0123456789abcdef-32+"
                },
            )
            assert resp.status_code == 404

        # Unknown ids use a distinct coalesced event whose structured order_id
        # stays empty, so varying attacker input cannot mint coalescing keys.
        store = Store(test_config.db_path)
        events = store.list_audit_events(event_type="admin-order-reclaim-not-found")
        assert len(events) == 1
        event = events[0]
        assert event["outcome"] == "failed"
        assert event["order_id"] is None
        assert event["details"].get("reason") == "order-not-found"
        assert event["details"].get("sample_order_id") == "does-not-exist-0"
        assert event["details"].get("denial_count") == 40


# ---------------------------------------------------------------------------
# Admin maintenance sweeps (nonce cleanup + expired-order sweep)
# ---------------------------------------------------------------------------


class TestAdminSweeps:
    """Admin cron endpoints: nonce cleanup and expired-order sweep."""

    def test_nonce_cleanup_endpoint_requires_token(self, client: TestClient) -> None:
        resp = client.delete("/acme/admin/nonces")
        assert resp.status_code == 401

    def test_nonce_cleanup_endpoint_deletes_expired(
        self, test_config: RAConfig, client: TestClient
    ) -> None:
        store = Store(test_config.db_path)
        now = datetime.now(UTC)
        old = (now - timedelta(seconds=NONCE_TTL_SECONDS + 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with store._connect() as conn:
            conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", ("stale-nonce", old))

        resp = client.delete(
            "/acme/admin/nonces",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"] >= 1

    def test_expired_orders_sweep_requires_token(self, client: TestClient) -> None:
        resp = client.delete("/acme/admin/expired-orders")
        assert resp.status_code == 401

    def test_expired_orders_sweep_invalidates_expired(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = acme_client.new_order(["web.WORK-DOMAIN.local"]).json()
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        _backdate_order(store, order_id)

        resp = client.delete(
            "/acme/admin/expired-orders",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        assert resp.json()["invalidated"] >= 1

        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "invalid"

        events = store.list_audit_events(event_type="admin-expired-order-sweep")
        assert any(e["outcome"] == "success" for e in events)

    def test_sweep_leaves_processing_order_alone(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        # A 'processing' order must NOT be auto-invalidated by the sweep — that
        # is operator-reconciliation territory (the reclaim endpoint).
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        _force_order_status(store, order_id, "processing")
        _backdate_order(store, order_id)

        resp = client.delete(
            "/acme/admin/expired-orders",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200

        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "processing"

    def test_sweep_and_is_expired_agree_on_boundary(self, tmp_path: Path) -> None:
        # The sweep now uses the datetime-based is_expired (same as finalize);
        # this test verifies they agree across the expiry boundary.
        # Use a single parsed `now` for both sides so the test is not flaky
        # across a one-second boundary, and exercise the REAL sweep against
        # a temp store.
        from acme_adcs_ra.store import _now_iso, _parse_iso

        now_str = _now_iso()
        now_dt = _parse_iso(now_str)  # same instant as the sweep's `now`

        # Account + order rows so the sweep has something to act on per delta.
        store = Store(tmp_path / "boundary.db")
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO accounts (id, status, jwk_json, eab_kid, contact, created_at) "
                "VALUES ('acct-1', 'valid', '{}', 'kid', '[]', ?)",
                (now_str,),
            )
        for delta in (-120, -1, 0, 1, 120):
            ts = (now_dt + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")
            datetime_expired = is_expired(ts, now=now_dt)
            # What the sweep's `WHERE expires <= <now_str>` will compute:
            sql_expired = ts <= now_str
            assert datetime_expired == sql_expired, (
                f"sweep/is_expired divergence at delta={delta}: ts={ts} now={now_str} "
                f"is_expired={datetime_expired} sql={sql_expired}"
            )

            # And confirm the real sweep agrees: insert an order at this ts,
            # run the sweep, and check it was invalidated iff is_expired is True.
            oid = f"order-d{delta}"
            with store._connect() as conn:
                conn.execute(
                    "INSERT INTO orders (id, account_id, status, identifiers, authorizations, "
                    "finalize_url, certificate_url, expires, created_at, updated_at) "
                    "VALUES (?, 'acct-1', 'ready', '[]', '[]', '', NULL, ?, ?, ?)",
                    (oid, ts, now_str, now_str),
                )
            before = store.get_order(oid)
            assert before is not None and before.status == "ready"
            store.sweep_expired_orders()  # uses a fresh _now_iso() internally
            # Sweep's now is >= now_str, so if is_expired(ts, now_dt) the sweep
            # must have invalidated; if not expired at now_dt+epsilon it must not.
            after = store.get_order(oid)
            assert after is not None
            if datetime_expired:
                assert after.status == "invalid", f"delta={delta} ts={ts} not swept"
            else:
                # delta=+120 is safely in the future; +1 could race the sweep's
                # slightly-later now, so only assert strictly-future cases.
                if delta >= 60:
                    assert after.status == "ready", f"delta={delta} wrongly swept"


# ---------------------------------------------------------------------------
# CAS-guarded enrollment error / success transitions (threat-model §4.D)
# ---------------------------------------------------------------------------


class TestEnrollmentCasRevert:
    """Verify that enrollment error and success paths use CAS-guarded
    transitions so a concurrent reclaim/self-heal cannot be clobbered."""

    def test_enrollment_denied_reverts_to_ready(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # Normal path: CA denies, CAS revert succeeds, order is retryable.
        config = _make_test_config(tmp_path)
        leg = _DenyingEnrollmentLeg()
        store, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        resp = acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert resp.status_code == 400
        assert "rejectedIdentifier" in resp.json()["type"]

        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"
        assert refreshed.processing_started_at is None

        events = store.list_audit_events(event_type="finalize-enrollment-denied")
        assert any(
            e["order_id"] == order_id
            and e["details"].get("revert_applied") is True
            for e in events
        )

    def test_enrollment_denial_lost_race_does_not_clobber(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # A concurrent reclaim moved the order out of 'processing' before the
        # denial handler's CAS runs. The handler must NOT clobber the order —
        # it returns the current state (200) instead of raising 400.
        config = _make_test_config(tmp_path)
        store = Store(config.db_path)
        leg = _RacingDenyingEnrollmentLeg(store)
        _, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])
        leg.order_id = order_id

        resp = acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        # Lost the race: 200 with current state, NOT 400 rejectedIdentifier.
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.status == "ready"

        events = store.list_audit_events(event_type="finalize-enrollment-denied")
        assert any(
            e["order_id"] == order_id
            and e["details"].get("revert_applied") is False
            for e in events
        )

    def test_enrollment_success_lost_race_audited(
        self,
        tmp_path: Path,
        account_key: rsa.RSAPrivateKey,
    ) -> None:
        # A concurrent self-heal moved the order to 'valid' (with a cert)
        # during the enrollment call. The success-path CAS loses the race;
        # the anomaly is audited and the client sees the valid order.
        # The re-check prevents a duplicate cert row (orphan).
        config = _make_test_config(tmp_path)
        store = Store(config.db_path)
        leg = _RacingEnrollmentLeg(store)
        _, context = _make_context(config, leg)
        client = TestClient(create_app(context))
        acme = HandRolledAcmeClient(client, "http://testserver", account_key)
        acme.new_account("kid-001", _eab_mac_key(config, "kid-001"))
        order = _walk_to_ready(acme, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])
        leg.order_id = order_id

        resp = acme.finalize_order(order["finalize"], _make_csr(["web.WORK-DOMAIN.local"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "valid"
        assert "certificate" in body

        # The race anomaly is audited.
        race_events = store.list_audit_events(event_type="finalize-enrollment-race")
        assert any(
            e["order_id"] == order_id
            and e["outcome"] == "failed"
            and e["details"].get("reason") == "lost-processing-cas"
            for e in race_events
        )

        # The normal certificate-issued event was NOT emitted (CAS lost).
        issued_events = store.list_audit_events(event_type="certificate-issued")
        assert not any(e["order_id"] == order_id for e in issued_events)

        # No orphaned cert row — the re-check found the racing leg's cert.
        with store._connect() as conn:
            cert_count = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE order_id = ?", (order_id,)
            ).fetchone()[0]
        assert cert_count == 1


# ---------------------------------------------------------------------------
# Admin order listing endpoint
# ---------------------------------------------------------------------------


class TestAdminOrderListing:
    """GET /acme/admin/orders?status=processing — stuck-order visibility."""

    def test_list_processing_orders_requires_token(self, client: TestClient) -> None:
        resp = client.get("/acme/admin/orders")
        assert resp.status_code == 401

    def test_list_processing_orders_returns_stuck(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        _force_order_status(store, order_id, "processing")

        resp = client.get(
            "/acme/admin/orders",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        orders = resp.json()["orders"]
        assert any(o["status"] == "processing" for o in orders)
        stuck = next(o for o in orders if o["status"] == "processing")
        assert "processing_started_at" in stuck

    def test_list_orders_filter_by_ready(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])

        resp = client.get(
            "/acme/admin/orders?status=ready",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        orders = resp.json()["orders"]
        assert all(o["status"] == "ready" for o in orders)
        assert len(orders) >= 1

    def test_list_orders_rejects_invalid_status(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get(
            "/acme/admin/orders?status=invalid_status",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

    def test_list_orders_rejects_negative_limit(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get(
            "/acme/admin/orders?limit=-1",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

    def test_list_orders_rejects_excessive_limit(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get(
            "/acme/admin/orders?limit=999",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

    def test_list_orders_is_audited(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])

        client.get(
            "/acme/admin/orders?status=ready",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )

        store = Store(test_config.db_path)
        events = store.list_audit_events(event_type="admin-list-orders")
        assert any(
            e["outcome"] == "success"
            and e["details"].get("status") == "ready"
            and e["details"].get("returned", 0) >= 1
            for e in events
        )

    def test_list_orders_minimal_view_no_sans(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        acme_client.new_account("kid-001", _eab_mac_key(test_config, "kid-001"))
        order = _walk_to_ready(acme_client, ["web.WORK-DOMAIN.local"])
        order_id = _order_id_from_finalize_url(order["finalize"])

        store = Store(test_config.db_path)
        _force_order_status(store, order_id, "processing")

        resp = client.get(
            "/acme/admin/orders",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        orders = resp.json()["orders"]
        stuck = next(o for o in orders if o["id"] == order_id)
        # Minimal admin view: no SANs, no certificate URL.
        assert "identifiers" not in stuck
        assert "certificate" not in stuck
        assert "authorizations" not in stuck
        assert "finalize" not in stuck
        # But monitoring-relevant fields are present.
        assert stuck["status"] == "processing"
        assert "processing_started_at" in stuck
        assert "account_id" in stuck


# ---------------------------------------------------------------------------
# WI-023: pending revocations admin view
# ---------------------------------------------------------------------------


class TestAdminPendingRevocations:
    """GET /acme/admin/revocations/pending — RA-side revocation pull feed."""

    def test_pending_revocations_requires_token(self, client: TestClient) -> None:
        resp = client.get("/acme/admin/revocations/pending")
        assert resp.status_code == 401

    def test_pending_revocations_rejects_wrong_token(self, client: TestClient) -> None:
        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_pending_revocations_empty_when_none(
        self, client: TestClient
    ) -> None:
        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        # The exact body, not a subset: the leafless view (UNFILED item 25.5)
        # must report "none in the window scanned" explicitly rather than by
        # omission, so an empty list and a truncated scan cannot look alike.
        assert resp.json() == {
            "pending_revocations": [],
            "leafless_incidents": [],
            "leafless_incidents_truncated": False,
        }

    def test_pending_revocations_returns_revoked_cert(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["pending_revocations"]) == 1
        entry = body["pending_revocations"][0]
        assert entry["serial"] == cert.serial_number
        assert entry["reason"] == 1
        assert entry["revoked_at"] is not None
        assert entry["req_id"] == ""

    def test_pending_revocations_does_not_return_valid_cert(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None

        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["pending_revocations"] == []

    def test_pending_revocations_limit_validation(
        self, client: TestClient
    ) -> None:
        resp = client.get(
            "/acme/admin/revocations/pending?limit=0",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

        resp = client.get(
            "/acme/admin/revocations/pending?limit=501",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

    def test_pending_revocations_is_audited(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )

        events = store.list_audit_events(event_type="admin-list-pending-revocations")
        assert any(
            e["outcome"] == "success"
            and e["details"].get("returned") == 1
            for e in events
        )


class TestAdminConfirmRevocation:
    """POST /acme/admin/revocations/{serial}/confirm — WI-024 callback."""

    def test_confirm_requires_token(self, client: TestClient) -> None:
        resp = client.post("/acme/admin/revocations/ABC123/confirm")
        assert resp.status_code == 401

    def test_confirm_rejects_wrong_token(self, client: TestClient) -> None:
        resp = client.post(
            "/acme/admin/revocations/ABC123/confirm",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_confirm_unknown_serial_404(self, client: TestClient) -> None:
        resp = client.post(
            "/acme/admin/revocations/DEADBEEF/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 404

    def test_confirm_valid_cert_is_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 400

    def test_confirm_revoked_cert_succeeds(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["serial"] == cert.serial_number
        assert body["ca_crl_updated"] is True

    def test_confirm_is_audited(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )

        events = store.list_audit_events(event_type="revocation-ca-confirmed")
        assert any(
            e["outcome"] == "success"
            and e["details"].get("serial") == cert.serial_number
            and e["details"].get("ca_crl_updated") is True
            for e in events
        )

    def test_confirm_denied_is_audited(
        self,
        client: TestClient,
        test_config: RAConfig,
    ) -> None:
        client.post(
            "/acme/admin/revocations/DEADBEEF/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        store = Store(test_config.db_path)
        events = store.list_audit_events(event_type="admin-revocation-confirm-denied")
        assert any(e["details"].get("reason") == "not-found" for e in events)

    def test_confirm_drops_serial_from_pending(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert len(resp.json()["pending_revocations"]) == 1

        client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )

        resp = client.get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        )
        assert resp.json()["pending_revocations"] == []

    def test_confirm_is_idempotent(
        self,
        acme_client: HandRolledAcmeClient,
        test_config: RAConfig,
        client: TestClient,
    ) -> None:
        cert = _issue_cert_record(acme_client, test_config)
        assert cert is not None
        store = Store(test_config.db_path)
        store.revoke_certificate(cert.id, reason=1)

        resp1 = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer test-confirm-token-0123456789abcdef-32+"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["ca_crl_updated"] is True

        events = store.list_audit_events(event_type="revocation-ca-confirmed")
        assert len(events) == 1
