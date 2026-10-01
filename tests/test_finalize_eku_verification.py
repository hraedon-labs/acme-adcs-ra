"""WI-026: post-issuance Extended Key Usage verification.

The RA's "blast radius bounded to spoofing internal TLS" guarantee rests on the
ADCS template issuing serverAuth-only certs. If a template ever gained
clientAuth/PKINIT/anyEKU — or issued a no-EKU (all-purpose) cert — a compromised
RA/gMSA could mint certs usable to authenticate *as* a principal, the
domain-takeover escalation the threat model calls the worst case short of a
signing key. WI-026 closes that gap by inspecting the *result*: the issued cert's
EKU must be exactly serverAuth, else finalize fails closed (500), the mismatch is
audited, and no cert is recorded or served.

Cert-minting primitives are forbidden in ``src/`` (the architecture test), not in
``tests/``; the helper below signs throwaway certs only to exercise the verifier.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import EnrollmentResult, FakeEnrollmentLeg
from acme_adcs_ra.finalize import _issued_cert_eku_violations
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import CertStatus, Store

from .hand_rolled_acme_client import HandRolledAcmeClient

_SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
_CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
_ANY_EKU = x509.ObjectIdentifier("2.5.29.37.0")


def _make_cert_pem(
    ekus: list[x509.ObjectIdentifier] | None, dns_sans: list[str] | None = None
) -> str:
    """Sign a throwaway self-signed cert with the given EKU OIDs (tests only).

    ``ekus=None`` omits the EKU extension entirely (an all-purpose cert).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eku.test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    )
    if ekus is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    if dns_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in dns_sans]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


class TestIssuedCertEkuVerifier:
    def test_serverauth_only_passes(self) -> None:
        assert _issued_cert_eku_violations(_make_cert_pem([_SERVER_AUTH])) == []

    def test_no_eku_extension_rejected(self) -> None:
        violations = _issued_cert_eku_violations(_make_cert_pem(None))
        assert violations
        assert "all-purpose" in violations[0]

    def test_clientauth_added_rejected(self) -> None:
        violations = _issued_cert_eku_violations(_make_cert_pem([_SERVER_AUTH, _CLIENT_AUTH]))
        assert any("clientAuth" in v for v in violations)
        # serverAuth is present, so 'absent' must NOT be reported.
        assert not any("absent" in v for v in violations)

    def test_any_eku_rejected(self) -> None:
        violations = _issued_cert_eku_violations(_make_cert_pem([_ANY_EKU]))
        assert any("anyExtendedKeyUsage" in v for v in violations)
        assert any("serverAuth" in v and "absent" in v for v in violations)

    def test_clientauth_only_rejected(self) -> None:
        violations = _issued_cert_eku_violations(_make_cert_pem([_CLIENT_AUTH]))
        assert any("clientAuth" in v for v in violations)
        assert any("serverAuth" in v and "absent" in v for v in violations)

    def test_unknown_eku_oid_rejected(self) -> None:
        unknown_oid = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")
        violations = _issued_cert_eku_violations(_make_cert_pem([_SERVER_AUTH, unknown_oid]))
        assert any("1.2.3.4.5.6.7.8.9" in v for v in violations)


class _EkuMisconfigEnrollmentLeg:
    """Returns an EnrollmentResult whose cert carries a non-serverAuth EKU.

    Simulates a misconfigured ADCS template that issues (e.g.) serverAuth +
    clientAuth. The cert carries no SAN so MED-1's SAN check passes and the EKU
    check is the one that must reject it.
    """

    def __init__(self, ekus: list[x509.ObjectIdentifier] | None) -> None:
        self._ekus = ekus
        self.submit_csr_call_count = 0

    def submit_csr(
        self, csr_pem: str, *, account_id: str, requested_sans: Any
    ) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        base = FakeEnrollmentLeg().submit_csr(
            csr_pem, account_id=account_id, requested_sans=requested_sans
        )
        return EnrollmentResult(
            cert_pem=_make_cert_pem(self._ekus),
            chain_pem=base.chain_pem,
            template=base.template,
            requester=base.requester,
            metadata=base.metadata,
        )


def _make_test_config(tmp_path: Any) -> RAConfig:
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid="kid-001-0123456789abcdef", mac_key="c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE")],
        san_scopes={"kid-001-0123456789abcdef": {"dns_patterns": ["srv01.WORK-DOMAIN.local"]}},
        adcs_template="ACME-ServerAuth",
    )


@pytest.fixture()
def test_config(tmp_path: Any) -> RAConfig:
    return _make_test_config(tmp_path)


@pytest.fixture()
def account_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr_der(account_key: rsa.RSAPrivateKey) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("srv01.WORK-DOMAIN.local")]), critical=False
        )
        .sign(account_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def _full_round_trip_to_finalize(
    client: TestClient, config: RAConfig, key: rsa.RSAPrivateKey, csr_der: bytes
) -> Any:
    ac = HandRolledAcmeClient(client, config.base_url, key)
    ac.new_account(eab_kid="kid-001-0123456789abcdef", eab_mac_key=config.eab_key_bytes("kid-001-0123456789abcdef"))
    order = ac.new_order(["srv01.WORK-DOMAIN.local"]).json()
    for authz_url in order["authorizations"]:
        authz = ac.get_authorization(authz_url).json()
        ac.validate_challenge(authz["challenges"][0]["url"])
    return ac.finalize_order(order["finalize"], csr_der)


def _context_with_leg(config: RAConfig, leg: Any) -> ServerContext:
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={k: s.dns_patterns for k, s in config.san_scopes.items()},
        template=config.adcs_template,
    )
    return ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=leg,
        revocation=FakeRevocationLeg(),
    )


def test_finalize_rejects_issued_cert_with_clientauth_eku(
    test_config: RAConfig, account_key: rsa.RSAPrivateKey
) -> None:
    """WI-026: a template that issues serverAuth+clientAuth must not be served.

    Finalize returns 500 and the mismatch is audited. The certificate is
    *quarantined* rather than discarded: ADCS already issued it, so the RA
    records the serial and queues it for CA-side revocation instead of leaving
    an unrevocable orphan (2026-08-13 review, finding 6).
    """
    context = _context_with_leg(
        test_config, _EkuMisconfigEnrollmentLeg([_SERVER_AUTH, _CLIENT_AUTH])
    )
    client = TestClient(create_app(context))

    resp = _full_round_trip_to_finalize(client, test_config, account_key, _csr_der(account_key))
    assert resp.status_code == 500
    assert "EKU verification" in resp.json()["detail"]

    store = Store(test_config.db_path)
    rows = store._connect().execute(
        "SELECT id, status, serial_number FROM certificates"
    ).fetchall()
    assert len(rows) == 1, "the CA-issued certificate must be tracked"
    assert rows[0]["status"] == CertStatus.QUARANTINED
    assert rows[0]["serial_number"]

    # No valid certificate exists for the order, so nothing is servable and a
    # retried finalize cannot pick it up.
    assert store.get_certificate_by_order(rows[0]["id"]) is None

    # It is queued for CA-side revocation through the normal pull-agent loop.
    pending = store.list_revoked_certificates()
    assert [c.serial_number for c in pending] == [rows[0]["serial_number"]]

    events = store.list_audit_events(
        account_id=None, event_type="finalize-issued-cert-eku-mismatch"
    )
    failed = next(e for e in events if e["outcome"] == "failed")
    assert any("clientAuth" in v for v in failed["details"]["violations"])
    # The serial is in the audit trail — the operator's handle on the orphan.
    assert failed["details"]["serial"] == rows[0]["serial_number"]


def test_finalize_rejects_issued_cert_with_no_eku(
    test_config: RAConfig, account_key: rsa.RSAPrivateKey
) -> None:
    """WI-026: an all-purpose (no-EKU) issued cert is rejected."""
    context = _context_with_leg(test_config, _EkuMisconfigEnrollmentLeg(None))
    client = TestClient(create_app(context))
    resp = _full_round_trip_to_finalize(client, test_config, account_key, _csr_der(account_key))
    assert resp.status_code == 500
    assert "EKU verification" in resp.json()["detail"]


def test_finalize_accepts_serverauth_only_cert(
    test_config: RAConfig, account_key: rsa.RSAPrivateKey
) -> None:
    """WI-026: the normal path — the FakeEnrollmentLeg fixture is serverAuth-only
    — still succeeds (the verifier does not reject a correct issuance)."""
    context = _context_with_leg(test_config, FakeEnrollmentLeg())
    client = TestClient(create_app(context))
    resp = _full_round_trip_to_finalize(client, test_config, account_key, _csr_der(account_key))
    assert resp.status_code == 200
    assert resp.json()["status"] == "valid"
