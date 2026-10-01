"""Interop-harness entrypoint: the real RA app in front of a throwaway fake CA.

HARNESS ONLY. This file lives outside ``src/`` on purpose and is never part of
the wheel: it is the one place in the repository that signs a certificate, so
that stock ACME clients (certbot, lego, acme.sh, Posh-ACME) receive a leaf that
actually carries *their* public key and *their* SANs. The packaged
``FakeEnrollmentLeg`` returns one static fixture for every order, which stock
clients refuse (Posh-ACME pairs the leaf with its private key) and which makes
every revocation ambiguous (all leaves share one serial).

Everything else is the production composition: ``RAConfig`` from the
environment, the real ``Store``, ``IssuancePolicy``, ``create_app`` and uvicorn.
Only the enrollment leg is swapped. The CA key is generated in memory at
startup and dies with the container; nothing here can reach a real CA.
"""

from __future__ import annotations

import datetime as dt
import sys
from collections.abc import Sequence

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from acme_adcs_ra.__main__ import _build_policy
from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import EnrollmentResult
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store


class HarnessSigningCA:
    """An in-memory P-256 root that signs exactly what the CSR asks for."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme-ra interop fake CA")])
        now = dt.datetime.now(dt.UTC)
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )
        self.pem = self._cert.public_bytes(serialization.Encoding.PEM).decode()

    def submit_csr(
        self,
        csr_pem: str,
        *,
        account_id: str,
        requested_sans: Sequence[str],
    ) -> EnrollmentResult:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        now = dt.datetime.now(dt.UTC)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, requested_sans[0])])
            )
            .issuer_name(self._cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in requested_sans]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        return EnrollmentResult(
            cert_pem=leaf.public_bytes(serialization.Encoding.PEM).decode(),
            chain_pem=[self.pem],
            template="ACME-ServerAuth",
            requester=account_id,
            metadata={"source": "interop-harness-fake-ca", "sans": ",".join(requested_sans)},
        )


def main() -> int:
    config = RAConfig()
    if not config.allow_fake_adcs_backends:
        raise SystemExit("interop harness requires ACME_RA_ALLOW_FAKE_ADCS_BACKENDS=true")
    store = Store(
        config.db_path,
        order_expiry_seconds=config.order_expiry_seconds,
        max_authorizations_per_order=config.max_identifiers_per_order,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=_build_policy(config),
        enrollment=HarnessSigningCA(),
        revocation=FakeRevocationLeg(),
    )
    app = create_app(context)
    uvicorn.run(app, host="0.0.0.0", port=config.bind_port or 8000, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
