"""Regression tests for the three 2026-08-23 Daybreak follow-up fixes."""

from __future__ import annotations

import http.server
import socket
import sqlite3
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from urllib3 import HTTPSConnectionPool

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.crl_evidence import _PinnedAddressAdapter, fetch_crl_evidence
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.jws import jwk_thumbprint
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import AccountKeyStale, AccountStatus, Store

from .conftest import placeholder_rsa_jwk


def _rotation_audit() -> dict[str, Any]:
    return {
        "event_type": "account-key-changed",
        "outcome": "success",
        "details": {},
    }


class TestKeyChangeCompareAndSwap:
    def test_two_rollovers_authorized_by_one_old_key_have_one_winner(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        old_jwk = placeholder_rsa_jwk("old")
        account = store.create_account(jwk=old_jwk, eab_kid="kid")
        old_thumbprint = jwk_thumbprint(old_jwk)
        barrier = threading.Barrier(2)

        def rotate(label: str) -> str:
            barrier.wait()
            try:
                store.update_account_key_with_audit(
                    account.id,
                    placeholder_rsa_jwk(label),
                    expected_old_thumbprint=old_thumbprint,
                    audit=_rotation_audit(),
                    rate_limit_per_kid=0,
                )
            except AccountKeyStale:
                return "stale"
            return "success"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(rotate, ("new-a", "new-b")))

        assert outcomes == ["stale", "success"]
        assert len(
            store.list_audit_events(event_type="account-key-changed", limit=10)
        ) == 1

    def test_deactivation_invalidates_an_already_authorized_rollover(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        old_jwk = placeholder_rsa_jwk("old")
        account = store.create_account(jwk=old_jwk, eab_kid="kid")
        assert store.update_account_status(account.id, AccountStatus.DEACTIVATED)

        with pytest.raises(AccountKeyStale):
            store.update_account_key_with_audit(
                account.id,
                placeholder_rsa_jwk("new"),
                expected_old_thumbprint=jwk_thumbprint(old_jwk),
                audit=_rotation_audit(),
                rate_limit_per_kid=0,
            )

        assert store.get_account_by_jwk(old_jwk) is not None
        assert store.get_account_by_jwk(placeholder_rsa_jwk("new")) is None
        assert not store.list_audit_events(
            event_type="account-key-changed", limit=10
        )

    def test_real_unique_constraint_conflict_rolls_back_rotation_and_audit(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        old_jwk = placeholder_rsa_jwk("old")
        account = store.create_account(jwk=old_jwk, eab_kid="kid-a-0123456789abcdef")
        occupied_jwk = placeholder_rsa_jwk("occupied")
        store.create_account(jwk=occupied_jwk, eab_kid="kid-b-0123456789abcdef")

        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
            store.update_account_key_with_audit(
                account.id,
                occupied_jwk,
                expected_old_thumbprint=jwk_thumbprint(old_jwk),
                audit=_rotation_audit(),
                rate_limit_per_kid=0,
            )

        assert store.get_account_by_jwk(old_jwk) is not None
        assert not store.list_audit_events(
            event_type="account-key-changed", limit=10
        )


class TestCrlSocketPinning:
    def test_request_uses_the_first_resolution_and_preserves_host(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.headers["Host"])
                body = b"not a CRL"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        real_getaddrinfo = socket.getaddrinfo
        hostname_lookups = 0

        def rebind(host: str, requested_port: int, *args: Any, **kwargs: Any) -> list[Any]:
            nonlocal hostname_lookups
            if host == "crl.example.test":
                hostname_lookups += 1
                address = "127.0.0.1" if hostname_lookups == 1 else "127.0.0.2"
                return real_getaddrinfo(address, requested_port, *args, **kwargs)
            return real_getaddrinfo(host, requested_port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", rebind)
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"http://crl.example.test:{port}/ca.crl",
                serial_number=1,
                cert_pem="",
                chain_pem=[],
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        assert evidence.checked is False
        assert hits == [f"crl.example.test:{port}"]
        assert hostname_lookups == 1

    def test_redirect_reuses_the_initial_resolution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                if self.path == "/ca.crl":
                    self.send_response(302)
                    self.send_header("Location", "/latest.crl")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"not a CRL"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        real_getaddrinfo = socket.getaddrinfo
        hostname_lookups = 0

        def rebind(host: str, requested_port: int, *args: Any, **kwargs: Any) -> list[Any]:
            nonlocal hostname_lookups
            if host == "crl.example.test":
                hostname_lookups += 1
                address = "127.0.0.1" if hostname_lookups == 1 else "127.0.0.2"
                return real_getaddrinfo(address, requested_port, *args, **kwargs)
            return real_getaddrinfo(host, requested_port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", rebind)
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"http://crl.example.test:{port}/ca.crl",
                serial_number=1,
                cert_pem="",
                chain_pem=[],
                follow_redirects=True,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        assert evidence.checked is False
        assert hits == ["/ca.crl", "/latest.crl"]
        assert hostname_lookups == 1

    def test_empty_initial_resolution_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0

        def no_dns(*_args: Any, **_kwargs: Any) -> list[Any]:
            nonlocal calls
            calls += 1
            raise OSError("NXDOMAIN")

        monkeypatch.setattr(socket, "getaddrinfo", no_dns)
        evidence = fetch_crl_evidence(
            crl_url="http://crl.example.test/ca.crl",
            serial_number=1,
            cert_pem="",
            chain_pem=[],
        )
        assert evidence.checked is False
        assert "did not resolve" in evidence.detail
        assert calls == 1

    def test_https_pool_connects_to_ip_but_authenticates_hostname(self) -> None:
        request = requests.Request(
            "GET", "https://crl.example.test/ca.crl"
        ).prepare()
        adapter = _PinnedAddressAdapter("192.0.2.10", "crl.example.test")
        try:
            pool = adapter.get_connection_with_tls_context(request, True)
        finally:
            adapter.close()

        assert isinstance(pool, HTTPSConnectionPool)
        assert pool.host == "192.0.2.10"
        assert pool.assert_hostname == "crl.example.test"
        assert pool.conn_kw["server_hostname"] == "crl.example.test"

    def test_https_pin_preserves_sni_and_real_hostname_verification(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(UTC)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            # SKI/AKI are not decoration here. OpenSSL 3.5 (shipped with the
            # CPython 3.13/3.14 builds CI uses) refuses a chain whose issuer
            # carries no key identifier with X509_V_ERR_MISSING_AUTHORITY_KEY_
            # IDENTIFIER, while the OpenSSL behind 3.12 accepts it. Without
            # these the handshake fails before hostname verification is ever
            # reached, so the assertion below passes only on 3.12 and this test
            # proves nothing about SNI on the versions the lab host runs.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "crl.example.test")]
        )
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("crl.example.test")]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        ca_path = tmp_path / "ca.pem"
        cert_path = tmp_path / "server.pem"
        key_path = tmp_path / "server.key"
        ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        hits: list[str] = []
        server_names: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                body = b"not a CRL"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        tls.set_servername_callback(
            lambda _socket, name, _context: server_names.append(name)
        )
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        real_getaddrinfo = socket.getaddrinfo

        def local_dns(host: str, requested_port: int, *args: Any, **kwargs: Any) -> list[Any]:
            if host in {"crl.example.test", "wrong.example.test"}:
                return real_getaddrinfo("127.0.0.1", requested_port, *args, **kwargs)
            return real_getaddrinfo(host, requested_port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", local_dns)
        monkeypatch.setattr(requests.adapters, "DEFAULT_CA_BUNDLE_PATH", str(ca_path))
        try:
            accepted = fetch_crl_evidence(
                crl_url=f"https://crl.example.test:{port}/ca.crl",
                serial_number=1,
                cert_pem="",
                chain_pem=[],
            )
            refused = fetch_crl_evidence(
                crl_url=f"https://wrong.example.test:{port}/ca.crl",
                serial_number=1,
                cert_pem="",
                chain_pem=[],
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        assert accepted.checked is False
        assert "CRL is neither valid DER nor PEM" in accepted.detail
        assert refused.checked is False
        assert "doesn't match 'crl.example.test'" in refused.detail
        assert hits == ["/ca.crl"]
        assert server_names == ["crl.example.test", "wrong.example.test"]


class TestUnavailableAuditPruning:
    def test_configuration_refuses_to_promise_unimplemented_pruning(self) -> None:
        with pytest.raises(ValueError, match="audit_prune_enabled is not available"):
            RAConfig(audit_prune_enabled=True)

    def test_composition_root_refuses_a_validation_bypass(self, tmp_path: Path) -> None:
        config = RAConfig(db_path=tmp_path / "ra.db")
        config.audit_prune_enabled = True
        context = ServerContext(
            config=config,
            store=Store(config.db_path),
            policy=IssuancePolicy(
                allowed_kids=set(), san_scopes={}, template=config.adcs_template
            ),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        with pytest.raises(RuntimeError, match="audit_prune_enabled is not available"):
            create_app(context)
