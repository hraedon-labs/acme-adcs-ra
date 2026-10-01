"""Regression tests for the smaller 2026-08-11 review findings.

Covered here: the unauthenticated nonce ceiling, the published OpenAPI/docs
surface, the off-box audit gate, serial canonicalisation, the certfnsh pending
scan, the PKCS#7 chain binding, and the keyChange ``oldKey`` error path.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import (
    EnrollmentTransportError,
    FakeEnrollmentLeg,
    _parse_certfnsh_disposition,
    _validate_chain_binds_to_leaf,
)
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.rate_limit import TokenBucket
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store, canonical_serial
from tests.conftest import placeholder_ec_jwk

# ---------------------------------------------------------------------------
# Nonce rate limiting
# ---------------------------------------------------------------------------


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    cfg = RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        **overrides,  # type: ignore[arg-type]
    )
    store = Store(cfg.db_path)
    ctx = ServerContext(
        config=cfg,
        store=store,
        policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(ctx))


def test_nonce_flood_is_capped(tmp_path: Path) -> None:
    """An unauthenticated nonce flood must be refused before the SQLite write."""
    client = _client(
        tmp_path, nonce_rate_limit_burst=5, nonce_rate_limit_per_second=0.001
    )
    codes = [client.head("/acme/new-nonce").status_code for _ in range(8)]
    assert codes[:5] == [204] * 5
    assert codes[5:] == [429] * 3


def test_nonce_rate_limit_sets_retry_after(tmp_path: Path) -> None:
    client = _client(
        tmp_path, nonce_rate_limit_burst=1, nonce_rate_limit_per_second=0.001
    )
    assert client.head("/acme/new-nonce").status_code == 204
    refused = client.head("/acme/new-nonce")
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1


def test_nonce_rate_limit_can_be_disabled(tmp_path: Path) -> None:
    """0 = rely on the reverse proxy only; must not accidentally cap at 0."""
    client = _client(tmp_path, nonce_rate_limit_per_second=0)
    codes = [client.head("/acme/new-nonce").status_code for _ in range(30)]
    assert set(codes) == {204}


def test_token_bucket_refills() -> None:
    now = [0.0]
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=lambda: now[0])
    assert bucket.take() and bucket.take()
    assert not bucket.take()
    now[0] = 1.0
    assert bucket.take(), "a token should be available one second later"
    assert not bucket.take()


def test_token_bucket_does_not_exceed_capacity() -> None:
    now = [0.0]
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=lambda: now[0])
    now[0] = 1000.0
    assert bucket.take() and bucket.take()
    assert not bucket.take(), "idle time must not accumulate unbounded burst"


# ---------------------------------------------------------------------------
# Published surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_interactive_docs_are_not_published(tmp_path: Path, path: str) -> None:
    """The OpenAPI surface enumerated every /acme/admin/* route to anyone."""
    assert _client(tmp_path).get(path).status_code == 404


def test_app_version_matches_the_installed_distribution(tmp_path: Path) -> None:
    """The app version must not be a second hand-maintained literal."""
    from importlib.metadata import version

    client = _client(tmp_path)
    assert client.app.version == version("acme-adcs-ra")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Off-box audit gate
# ---------------------------------------------------------------------------


def test_offbox_audit_required_rejects_the_jsonl_sink(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="audit_offbox_required"):
        RAConfig(
            base_url="http://testserver",
            db_path=tmp_path / "ra.db",
            audit_offbox_required=True,
            siem_sink="jsonl",
        )


def test_offbox_audit_required_rejects_plaintext_syslog(tmp_path: Path) -> None:
    """Still refused by DEFAULT; the acknowledged posture is exercised in
    ``test_offbox_syslog_acknowledgement.py``."""
    with pytest.raises(ValidationError, match="does not authenticate the collector"):
        RAConfig(
            base_url="http://testserver",
            db_path=tmp_path / "ra.db",
            audit_offbox_required=True,
            siem_sink="syslog",
            siem_syslog_host="siem.example",
            siem_syslog_proto="tcp",
        )


def test_offbox_audit_required_accepts_https_hec(tmp_path: Path) -> None:
    cfg = RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "ra.db",
        audit_offbox_required=True,
        siem_sink="hec",
        siem_hec_url="https://siem.example/services/collector",
        siem_hec_token="placeholder-token",
    )
    assert cfg.siem_sink == "hec"


def test_jsonl_sink_still_default_without_the_gate(tmp_path: Path) -> None:
    """The gate is opt-in; lab/CI keep the zero-config sink."""
    cfg = RAConfig(base_url="http://testserver", db_path=tmp_path / "ra.db")
    assert cfg.siem_sink == "jsonl"
    assert cfg.audit_offbox_required is False


# ---------------------------------------------------------------------------
# Serial canonicalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0a1b2c", "A1B2C"),          # certutil's zero-padded lowercase form
        ("A1B2C", "A1B2C"),           # what format(n, 'x').upper() produces
        ("0xA1B2C", "A1B2C"),         # operator copy-paste
        ("  0A1B2C  ", "A1B2C"),      # whitespace
        ("0", "0"),                   # must not collapse to empty
        ("0000", "0"),
    ],
)
def test_serial_canonicalisation(raw: str, expected: str) -> None:
    assert canonical_serial(raw) == expected


def test_confirm_accepts_a_certutil_shaped_serial(tmp_path: Path) -> None:
    """The confirm callback must find a cert whether or not the serial is padded.

    Pre-fix, the store keyed on the unpadded form while certutil emits a
    zero-padded one, so an operator confirming a serial copied from certutil
    output got a 404 and the serial never left the pending set.
    """
    store = Store(tmp_path / "ra.db")
    account = store.create_account(jwk=_jwk(), eab_kid="k")
    order = store.create_order_with_authz(
        account_id=account.id,
        identifiers=[{"type": "dns", "value": "a.example"}],
        challenge_url_fn=lambda i: f"http://t/c/{i}",
        authz_url_fn=lambda i: f"http://t/a/{i}",
        finalize_url_fn=lambda i: f"http://t/f/{i}",
    )
    cert_pem = _self_signed_pem(serial=0x0A1B2C)
    cert = store.create_certificate(
        order_id=order.id,
        account_id=account.id,
        cert_pem=cert_pem,
        chain_pem=[],
        template="ACME-ServerAuth",
        requester="X",
    )
    store.revoke_certificate(cert.id, 1)

    # Zero-padded lowercase, as certutil prints it.
    assert store.get_certificate_by_serial("0a1b2c") is not None
    assert store.confirm_ca_revocation("0a1b2c") is True


# ---------------------------------------------------------------------------
# certfnsh pending scan + chain binding
# ---------------------------------------------------------------------------


def test_pending_scan_ignores_commented_out_reqid() -> None:
    """A ReqID in an HTML comment is page chrome, not a disposition.

    Steps 1/2/4 of the parser were hardened to scan the comment-stripped body
    (LOW-1); step 3 still scanned the raw body.

    The body below deliberately carries **no** denial marker and no real ReqID,
    so step 3 is the only step that can fire. Reading the raw body yields
    ``pending`` (wrong — the RA would tell the client to keep polling a request
    the CA never accepted); reading the stripped body correctly falls through
    to ``unknown``, which surfaces the response to the operator.
    """
    body = (
        "<html><!-- sample markup: certnew.cer?ReqID=999&Enc=b64 -->"
        "<body>Nothing this parser recognises.</body></html>"
    )
    disposition, _detail = _parse_certfnsh_disposition(body, 200)
    assert disposition == "unknown"


def test_pending_scan_ignores_scripted_reqid() -> None:
    """Same for a ReqID inside a <script> literal."""
    body = (
        "<html><script>var u = 'certnew.cer?ReqID=123&Enc=b64';</script>"
        "<body>Nothing this parser recognises.</body></html>"
    )
    disposition, _detail = _parse_certfnsh_disposition(body, 200)
    assert disposition == "unknown"


def test_pending_scan_still_reads_a_real_reqid() -> None:
    """Control: a genuine pending body is still classified pending."""
    body = "<html><body>Your Request Id is 42. ReqID=42</body></html>"
    disposition, detail = _parse_certfnsh_disposition(body, 200)
    assert disposition == "pending"
    assert detail == "42"


def test_chain_that_does_not_issue_the_leaf_is_rejected() -> None:
    """certnew.p7b is a separate fetch; it must actually match the leaf."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf_pem, issuer_pem = _issued_pair(issuer_key)
    unrelated_pem = _self_signed_pem(serial=7, common_name="Unrelated CA")

    # Control: the real chain validates.
    _validate_chain_binds_to_leaf(leaf_pem, [issuer_pem])

    with pytest.raises(EnrollmentTransportError, match="does not issue"):
        _validate_chain_binds_to_leaf(leaf_pem, [unrelated_pem])


def test_chain_with_same_name_but_wrong_key_is_rejected() -> None:
    """Name equality is not enough — this is the CA re-key case."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf_pem, _issuer_pem = _issued_pair(issuer_key)
    # Same subject name, different key: what a re-keyed CA looks like.
    impostor_pem = _self_signed_pem(serial=9, common_name="Test Issuing CA")

    with pytest.raises(EnrollmentTransportError, match="does not issue"):
        _validate_chain_binds_to_leaf(leaf_pem, [impostor_pem])


def test_enrollment_leg_rejects_a_mismatched_chain_end_to_end() -> None:
    """The chain check must be WIRED IN, not merely present.

    Exercised through ``submit_csr`` with an injected session, so removing the
    call site fails this test even though the helper above still passes.
    """
    import base64 as _b64

    from cryptography.hazmat.primitives.serialization import pkcs7

    from acme_adcs_ra.enrollment import CertsrvEnrollmentLeg

    from .test_enrollment import _build_leaf_cert_and_chain, _FakeResponse, _FakeSession

    _leaf_pem, leaf_der, _good_p7b = _build_leaf_cert_and_chain()
    cert_b64 = _b64.b64encode(leaf_der).decode("ascii")

    # A well-formed p7b that simply does not contain the leaf's issuer.
    unrelated = x509.load_pem_x509_certificate(
        _self_signed_pem(serial=11, common_name="Some Other CA").encode("ascii")
    )
    bad_p7b = _b64.b64encode(
        pkcs7.serialize_certificates([unrelated], serialization.Encoding.DER)
    ).decode("ascii")

    fake = _FakeSession(
        routes={
            "certfnsh.asp": _FakeResponse(
                text='<a href="certnew.cer?ReqID=42&Enc=b64">x</a>'
            ),
            "certnew.cer": _FakeResponse(
                text=cert_b64,
                content=cert_b64.encode("ascii"),
                headers={"Content-Type": "application/pkix-cert"},
            ),
            "certcarc.asp": _FakeResponse(text="var nRenewals=0;"),
            "certnew.p7b": _FakeResponse(content=bad_p7b.encode("ascii")),
        }
    )
    leg = CertsrvEnrollmentLeg(
        host="CA01.WORK-DOMAIN.local",
        template="ACME-ServerAuth",
        session_factory=lambda: fake,
    )
    with pytest.raises(EnrollmentTransportError, match="does not issue"):
        leg.submit_csr(
            "-----BEGIN CERTIFICATE REQUEST-----\nnot-a-real-csr\n"
            "-----END CERTIFICATE REQUEST-----\n",
            account_id="a",
            requested_sans=["srv01.WORK-DOMAIN.local"],
        )


# ---------------------------------------------------------------------------
# keyChange oldKey error path
# ---------------------------------------------------------------------------


def test_key_change_malformed_oldkey_is_a_client_error(tmp_path: Path) -> None:
    """A JWK missing its members must be a 400, not an unhandled 500.

    ``oldKey`` is attacker-supplied and reached ``jwk_thumbprint`` unvalidated,
    so ``{"kty": "RSA"}`` raised KeyError and surfaced as a 500 with a stack
    trace.
    """
    import base64 as _b64

    from .hand_rolled_acme_client import HandRolledAcmeClient, sign_jws
    from .test_account_lifecycle import BASE_URL, KID, MAC_B64, _build

    client, _ctx = _build(tmp_path)
    acme = HandRolledAcmeClient(
        client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
    )
    mac = _b64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))
    assert acme.new_account(KID, mac).status_code == 201

    url = f"{BASE_URL}/acme/key-change"
    new_key = ec.generate_private_key(ec.SECP256R1())
    from .hand_rolled_acme_client import jwk_from_private_key

    inner = sign_jws(
        # oldKey declares a kty but carries none of its required members.
        {"account": acme.account_url, "oldKey": {"kty": "RSA"}},
        new_key,
        {
            "alg": "ES256",
            "jwk": jwk_from_private_key(new_key),
            "url": url,
        },
    )
    outer = sign_jws(
        inner,
        acme.account_key,
        {
            "alg": "ES256",
            "kid": acme.account_url,
            "nonce": client.head("/acme/new-nonce").headers["Replay-Nonce"],
            "url": url,
        },
    )
    resp = client.post("/acme/key-change", json=outer)
    assert resp.status_code == 400, resp.text
    assert "not a usable JWK" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _jwk() -> dict[str, str]:
    return placeholder_ec_jwk("hardening-2026-08-11")


def _self_signed_pem(*, serial: int, common_name: str = "Test") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _issued_pair(issuer_key: ec.EllipticCurvePrivateKey) -> tuple[str, str]:
    """Return (leaf_pem, issuer_pem) where issuer genuinely signed leaf."""
    issuer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")]
    )
    now = datetime.datetime.now(datetime.UTC)
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")])
        )
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(issuer_key, hashes.SHA256())
    )
    return (
        leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        issuer_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )
