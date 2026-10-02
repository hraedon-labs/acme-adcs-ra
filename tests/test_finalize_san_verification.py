"""MED-1: post-issuance SAN verification.

The RA enforces SAN-scope policy on the CSR (the request), but the ADCS
template ultimately decides which SANs land on the cert. If a template is
misconfigured (e.g. it pulls SANs from AD, or appends extras), the issued cert
could authorize identities the RA's policy never approved. MED-1 closes that
gap by inspecting the *result*: every DNS SAN on the issued cert must be within
the set the order authorized, else finalize fails closed (500), the mismatch
is audited, and no cert is recorded or served.

Cert-minting primitives are forbidden in ``src/`` (the architecture test), not
in ``tests/``; the helper below signs throwaway certs only to exercise the
verifier against realistic cert objects.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import EnrollmentResult, FakeEnrollmentLeg
from acme_adcs_ra.finalize import _issued_cert_san_violations
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import CertStatus, Store

from .hand_rolled_acme_client import HandRolledAcmeClient


def _make_cert_pem(dns_sans: list[str]) -> str:
    """Sign a throwaway self-signed cert carrying the given DNS SANs (tests only)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "med1.test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    )
    if dns_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in dns_sans]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class TestIssuedCertSanVerifier:
    def test_no_san_extension_passes(self) -> None:
        # The package fixture cert has only a CN, no SAN extension.
        issued, unauthorized, non_dns = _issued_cert_san_violations(
            _fixture_cert(), ["x.test"]
        )
        assert issued == []
        assert unauthorized == []
        assert non_dns == []

    def test_exact_match_passes_case_insensitively(self) -> None:
        pem = _make_cert_pem(["Foo.example.com", "bar.Example.com"])
        issued, unauthorized, non_dns = _issued_cert_san_violations(
            pem, ["foo.example.com", "BAR.example.com"]
        )
        assert {s.lower() for s in issued} == {"foo.example.com", "bar.example.com"}
        assert unauthorized == []
        assert non_dns == []

    def test_extra_san_flagged(self) -> None:
        pem = _make_cert_pem(["ok.example.com", "evil.example.com"])
        issued, unauthorized, _ = _issued_cert_san_violations(pem, ["ok.example.com"])
        assert "evil.example.com" in issued
        assert unauthorized == ["evil.example.com"]

    def test_subset_passes(self) -> None:
        # A cert missing a requested SAN is not a privilege escalation; the
        # security property is "no unauthorized identity", so a subset passes.
        pem = _make_cert_pem(["ok.example.com"])
        _, unauthorized, _ = _issued_cert_san_violations(
            pem, ["ok.example.com", "also.example.com"]
        )
        assert unauthorized == []

    def test_trailing_dot_normalized_no_false_reject(self) -> None:
        """M-1: an FQDN-form issued SAN (trailing dot) must not be falsely
        rejected against a non-dotted order SAN, matching policy's own
        ``rstrip('.').lower()`` normalization."""
        pem = _make_cert_pem(["srv01.example.com."])
        _, unauthorized, _ = _issued_cert_san_violations(pem, ["SRV01.example.com"])
        assert unauthorized == []

    def test_non_dns_san_flagged(self) -> None:
        """H-1: a non-DNS SAN (email, IP, URI, …) injected by a misconfigured
        template must be rejected — the CSR gate already forbids these, so
        their presence on the issued cert means the template bypassed the
        request. A server-auth-only template may carry only DNS SANs."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        import ipaddress
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("ok.example.com"),
                x509.RFC822Name("rogue@example.com"),
                x509.IPAddress(ipaddress.ip_address("10.0.0.1")),
            ]
        )
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h1.test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        _issued, unauthorized, non_dns = _issued_cert_san_violations(
            pem, ["ok.example.com"]
        )
        # The DNS SAN is authorized, but the non-DNS SANs are a violation.
        assert unauthorized == []
        assert "RFC822Name (email)" in non_dns
        assert "IPAddress" in non_dns


def _fixture_cert() -> str:
    from importlib import resources
    return resources.files("acme_adcs_ra.fixtures").joinpath("fake_cert.pem").read_text()


class _MisconfigEnrollmentLeg:
    """Returns an EnrollmentResult whose cert carries an extra, unauthorized SAN.

    Simulates a misconfigured ADCS template that appends a SAN the RA's policy
    never approved for the order.
    """

    def __init__(self, issued_sans: list[str]) -> None:
        self._issued_sans = issued_sans
        self.submit_csr_call_count = 0

    def submit_csr(
        self, csr_pem: str, *, account_id: str, requested_sans: Any
    ) -> EnrollmentResult:
        self.submit_csr_call_count += 1
        # Reuse the fake leg for template/requester/metadata shape, but swap in
        # a cert whose SANs the template "misconfigured".
        base = FakeEnrollmentLeg().submit_csr(
            csr_pem, account_id=account_id, requested_sans=requested_sans
        )
        return EnrollmentResult(
            cert_pem=_make_cert_pem(self._issued_sans),
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


@pytest.fixture()
def client(test_config: RAConfig) -> TestClient:
    store = Store(test_config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(test_config.eab_keys_by_kid().keys()),
        san_scopes={k: s.dns_patterns for k, s in test_config.san_scopes.items()},
        template=test_config.adcs_template,
    )
    context = ServerContext(
        config=test_config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=None,  # type: ignore[arg-type]
    )
    return TestClient(create_app(context))


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


def test_finalize_rejects_issued_cert_with_unauthorized_san(
    test_config: RAConfig, account_key: rsa.RSAPrivateKey, tmp_path: Any
) -> None:
    """MED-1: a misconfigured template that appends an unauthorized SAN must
    not be recorded or served. Finalize returns 500, the mismatch is audited
    (outcome=failed), and no cert row is created."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("srv01.WORK-DOMAIN.local")]),
            critical=False,
        )
        .sign(account_key, hashes.SHA256())
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    store = Store(test_config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(test_config.eab_keys_by_kid().keys()),
        san_scopes={k: s.dns_patterns for k, s in test_config.san_scopes.items()},
        template=test_config.adcs_template,
    )
    # Template "appends" an extra SAN the order never authorized.
    bad_leg = _MisconfigEnrollmentLeg(
        ["srv01.WORK-DOMAIN.local", "evil.WORK-DOMAIN.local"]
    )
    context = ServerContext(
        config=test_config,
        store=store,
        policy=policy,
        enrollment=bad_leg,
        revocation=None,  # type: ignore[arg-type]
    )
    bad_client = TestClient(create_app(context))

    resp = _full_round_trip_to_finalize(bad_client, test_config, account_key, csr_der)
    assert resp.status_code == 500
    assert "SAN verification" in resp.json()["detail"]

    # The CA already issued this certificate, so it is quarantined rather than
    # forgotten: tracked, never served, and queued for CA-side revocation
    # (2026-08-13 review, finding 6).
    cert_rows = store._connect().execute(
        "SELECT id, status, serial_number FROM certificates"
    ).fetchall()
    assert len(cert_rows) == 1
    assert cert_rows[0]["status"] == CertStatus.QUARANTINED
    assert store.list_revoked_certificates()[0].serial_number == (
        cert_rows[0]["serial_number"]
    )

    # The mismatch was audited, with the serial the operator needs.
    events = store.list_audit_events(
        account_id=None, event_type="finalize-issued-cert-san-mismatch"
    )
    assert any(e["outcome"] == "failed" for e in events)
    failed = next(e for e in events if e["outcome"] == "failed")
    assert "evil.WORK-DOMAIN.local" in failed["details"]["unauthorized_dns_sans"]
    assert failed["details"]["serial"] == cert_rows[0]["serial_number"]


def test_finalize_accepts_issued_cert_with_matching_san(
    client: TestClient, test_config: RAConfig, account_key: rsa.RSAPrivateKey
) -> None:
    """MED-1: the normal path — issued cert SANs match the order — still
    succeeds (the verifier does not reject a correct issuance)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("srv01.WORK-DOMAIN.local")]),
            critical=False,
        )
        .sign(account_key, hashes.SHA256())
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    resp = _full_round_trip_to_finalize(client, test_config, account_key, csr_der)
    # The default FakeEnrollmentLeg returns a fixture cert with NO SANs (subset
    # of the requested set), so MED-1's subset check passes and issuance works.
    assert resp.status_code == 200
    assert resp.json()["status"] == "valid"
