"""Regression tests for the 2026-08-16 external scan (findings 1, 2, 4).

Finding 3 (the installer's unpinned build closure) is PowerShell + lockfile and
is covered by `tests/pester/` plus the hash-pinned
`deploy/build-requirements.lock.txt`; there is nothing for pytest to assert.

Each test here was mutation-checked: the fix was reverted in turn and the test
confirmed to fail. See docs/security-review-2026-08-16.md.
"""

from __future__ import annotations

import datetime
import threading
import time
from typing import Any, ClassVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_adcs_ra.crl_evidence import fetch_crl_evidence
from acme_adcs_ra.siem import SiemConfig, SiemEmitter

# ---------------------------------------------------------------------------
# Finding 4 — presence on a CRL is not the same as being revoked
# ---------------------------------------------------------------------------


def _crl_fixture() -> dict[str, Any]:
    """A CA, a leaf, and a CRL builder that can set reasons and delta markers."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_serial = 0x1A2B3C4D
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv01.example")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(leaf_serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )

    def build_crl(
        serials: list[int],
        *,
        reason: x509.ReasonFlags | None = None,
        delta_of: int | None = None,
    ) -> bytes:
        last = now - datetime.timedelta(minutes=5)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name)
            .last_update(last)
            .next_update(now + datetime.timedelta(days=7))
            .add_extension(x509.CRLNumber(12), critical=False)
        )
        if delta_of is not None:
            builder = builder.add_extension(
                x509.DeltaCRLIndicator(delta_of), critical=True
            )
        for s in serials:
            rb = (
                x509.RevokedCertificateBuilder()
                .serial_number(s)
                .revocation_date(last)
            )
            if reason is not None:
                rb = rb.add_extension(x509.CRLReason(reason), critical=False)
            builder = builder.add_revoked_certificate(rb.build())
        return builder.sign(ca_key, hashes.SHA256()).public_bytes(
            serialization.Encoding.DER
        )

    return {
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "chain": [ca_cert.public_bytes(serialization.Encoding.PEM).decode()],
        "serial": leaf_serial,
        "build_crl": build_crl,
    }


def _serve(body: bytes) -> tuple[str, Any]:
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/ca.crl", server.shutdown


def _check(body: bytes, fx: dict[str, Any]) -> Any:
    url, shutdown = _serve(body)
    try:
        return fetch_crl_evidence(
            crl_url=url,
            serial_number=fx["serial"],
            cert_pem=fx["leaf_pem"],
            chain_pem=fx["chain"],
        )
    finally:
        shutdown()


class TestCrlPresenceIsNotProofOfRevocation:
    """F4 — the evidence check read entry existence and nothing else.

    `removeFromCRL` (reason 8) means a certificate came OFF hold: it is the one
    CRL entry that asserts a certificate is NOT revoked. The RA already refuses
    reason 8 on the ACME revoke route (2026-08-14 F3); accepting it as evidence
    of revocation was the same defect facing the other way, and it would drain a
    live certificate off the pending-revocation queue while recording
    `crl-verified`.
    """

    def test_remove_from_crl_entry_is_not_evidence_of_revocation(self) -> None:
        fx = _crl_fixture()
        ev = _check(
            fx["build_crl"]([fx["serial"]], reason=x509.ReasonFlags.remove_from_crl),
            fx,
        )
        assert ev.revoked is False, "an un-hold was read as a revocation"
        assert ev.checked is True, "the CRL was readable; this is an answer, not a failure"
        assert "removeFromCRL" in ev.detail

    def test_an_ordinary_revocation_is_still_evidence(self) -> None:
        """Positive control. A guard that refused every entry would satisfy the
        assertion above while breaking the feature entirely."""
        fx = _crl_fixture()
        ev = _check(
            fx["build_crl"]([fx["serial"]], reason=x509.ReasonFlags.key_compromise), fx
        )
        assert (ev.revoked, ev.checked) == (True, True)
        assert "key_compromise" in ev.detail

    def test_an_entry_with_no_reason_is_still_evidence(self) -> None:
        """An absent CRLReason means `unspecified`, which IS a revocation. Reading
        a missing extension as "not revoked" would be the opposite failure."""
        fx = _crl_fixture()
        ev = _check(fx["build_crl"]([fx["serial"]]), fx)
        assert (ev.revoked, ev.checked) == (True, True)

    def test_a_delta_crl_is_refused_as_standalone_evidence(self) -> None:
        """A delta CRL carries only changes since its base, and is the document
        where removeFromCRL legitimately appears. The RA holds no base CRL to
        apply it to, so it must decline to conclude rather than guess."""
        fx = _crl_fixture()
        ev = _check(fx["build_crl"]([fx["serial"]], delta_of=11), fx)
        assert ev.revoked is False
        assert ev.checked is False, "a delta CRL must not count as a checked answer"
        assert "delta" in ev.detail.lower()


# ---------------------------------------------------------------------------
# Finding 2 — TCP syslog backpressure must not reach the request path
# ---------------------------------------------------------------------------


class TestSyslogBackpressureIsBounded:
    """F2 — the syslog sink emitted inline, synchronously, on the issuance path.

    The HEC sink already had a bounded worker queue for exactly this reason;
    syslog never got it, and TCP syslog is the shipped production setting in
    deploy/iis/web.config. A receiver that stops reading blocks `sendall`, and
    the blocked thread is the event loop.
    """

    def _emitter_with_blocking_sink(self, release: threading.Event) -> SiemEmitter:
        emitter = SiemEmitter(SiemConfig(sink="jsonl"))
        # Stand in for a syslog logger whose send blocks forever, without needing
        # a real syslog server: the property under test is the queueing, not the
        # wire format.
        emitter._config = SiemConfig(sink="syslog", syslog_host="127.0.0.1", hec_queue_max=5)
        emitter._enabled = True

        class _BlockingLogger:
            handlers: ClassVar[list[Any]] = []

            def info(self, _msg: str) -> None:
                release.wait(timeout=30)

        emitter._syslog = _BlockingLogger()  # type: ignore[assignment]
        from concurrent.futures import ThreadPoolExecutor

        emitter._pool = ThreadPoolExecutor(max_workers=1)
        return emitter

    def test_export_does_not_block_when_the_sink_stalls(self) -> None:
        release = threading.Event()
        emitter = self._emitter_with_blocking_sink(release)
        # Watchdog: if the fix is absent, `export` blocks inline on the FIRST
        # event and every subsequent one blocks too. Releasing after 6s bounds
        # the failing run to seconds instead of the stub timeout times fifty,
        # while still leaving the elapsed time far above the 5s threshold.
        watchdog = threading.Timer(6.0, release.set)
        watchdog.start()
        try:
            start = time.time()
            for i in range(50):
                emitter.export({"event_type": "certificate-issued", "n": i})
            elapsed = time.time() - start
            assert elapsed < 5.0, (
                f"export blocked for {elapsed:.1f}s against a stalled sink; "
                "the issuance request path is stalled with it"
            )
        finally:
            watchdog.cancel()
            release.set()
            emitter.close()

    def test_the_queue_is_bounded_and_drops_are_counted(self) -> None:
        release = threading.Event()
        emitter = self._emitter_with_blocking_sink(release)
        watchdog = threading.Timer(6.0, release.set)
        watchdog.start()
        try:
            for i in range(200):
                emitter.export({"event_type": "certificate-issued", "n": i})
            # One event is in the worker's hands, the rest fill the bound.
            assert emitter._sink_inflight <= 5
            assert emitter.sink_dropped >= 195, (
                f"dropped={emitter.sink_dropped}; an unbounded queue would have "
                "accepted all 200 and grown without limit"
            )
        finally:
            watchdog.cancel()
            release.set()
            emitter.close()


# ---------------------------------------------------------------------------
# Finding 1 — CRL retrieval must not run on the event loop
# ---------------------------------------------------------------------------


class TestConfirmDoesNotBlockTheEventLoop:
    """F1 — the confirm handler is `async def` and fetched the CRL inline.

    Same class of defect as the enrollment leg, which was moved off the loop in
    an earlier review; this path was missed. In the single-process deployment a
    slow or trickling CRL endpoint stalls every ACME route for the whole timeout.
    """

    def _app(self, tmp_path: Any, **overrides: Any) -> tuple[Any, Any, Any]:
        from fastapi.testclient import TestClient
        from pydantic import SecretStr

        from acme_adcs_ra.app_state import ServerContext
        from acme_adcs_ra.enrollment import FakeEnrollmentLeg
        from acme_adcs_ra.policy import IssuancePolicy
        from acme_adcs_ra.revocation import FakeRevocationLeg
        from acme_adcs_ra.server import create_app
        from acme_adcs_ra.store import Store

        from .test_revocation import _make_test_config

        tmp_path.mkdir(parents=True, exist_ok=True)
        cfg = _make_test_config(tmp_path).model_copy(
            update={
                "revocation_confirm_token": SecretStr("confirm-token-0123456789abcdef-32+"),
                "revocation_confirm_crl_url": "http://127.0.0.1:1/ca.crl",
                **overrides,
            }
        )
        store = Store(cfg.db_path)
        ctx = ServerContext(
            config=cfg,
            store=store,
            policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
        return store, TestClient(create_app(ctx), raise_server_exceptions=False), cfg

    def test_the_crl_fetch_runs_off_the_event_loop(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Asserted behaviourally, not by reading the source.

        The discriminator is whether a *running event loop* exists on the thread
        the helper is called from. `asyncio.get_running_loop()` succeeds only on
        the loop thread, so it succeeds exactly when the fetch is inline and
        raises when it has been handed to a worker.

        The first version of this test compared against `threading.main_thread()`
        and was VACUOUS: `TestClient` drives the app from a portal thread, so the
        helper is off the main thread either way and the assertion held with the
        fix reverted. Mutation-checking is what caught it.
        """
        import asyncio

        from acme_adcs_ra.routes import admin as admin_module

        store, client, _cfg = self._app(tmp_path)
        seen: dict[str, Any] = {}

        def _spy(ctx: Any, cert: Any) -> Any:
            try:
                asyncio.get_running_loop()
                seen["on_event_loop"] = True
            except RuntimeError:
                seen["on_event_loop"] = False
            return None

        monkeypatch.setattr(admin_module, "_crl_evidence_for", _spy)

        cert = _revoked_cert(store)
        resp = client.post(
            f"/acme/admin/revocations/{cert.serial_number}/confirm",
            headers={"Authorization": "Bearer confirm-token-0123456789abcdef-32+"},
        )
        assert resp.status_code == 200, resp.text
        assert seen, "the evidence helper was never called"
        assert seen["on_event_loop"] is False, (
            "CRL evidence ran ON the event-loop thread; a slow or trickling CRL "
            "endpoint would stall every other request in the process for the "
            "whole timeout"
        )

    def test_an_already_confirmed_serial_does_no_external_fetch(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Idempotence must short-circuit BEFORE the network, or a retry loop on
        the revocation host becomes repeated outbound work on the issuance path."""
        from acme_adcs_ra.routes import admin as admin_module

        store, client, _cfg = self._app(tmp_path)
        calls: list[int] = []

        def _spy(ctx: Any, cert: Any) -> Any:
            calls.append(1)
            return None

        monkeypatch.setattr(admin_module, "_crl_evidence_for", _spy)

        cert = _revoked_cert(store)
        hdr = {"Authorization": "Bearer confirm-token-0123456789abcdef-32+"}
        url = f"/acme/admin/revocations/{cert.serial_number}/confirm"
        assert client.post(url, headers=hdr).status_code == 200
        first = len(calls)
        assert client.post(url, headers=hdr).status_code == 200
        assert len(calls) == first, (
            f"a repeat confirmation fetched the CRL again ({len(calls)} calls); "
            "it has nothing to learn and should short-circuit"
        )


def _revoked_cert(store: Any) -> Any:
    """A stored certificate in the revoked state, ready to be confirmed."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from acme_adcs_ra.enrollment import FakeEnrollmentLeg

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
    cert = store.create_certificate(
        order_id=order.id,
        account_id=account.id,
        cert_pem=FakeEnrollmentLeg()._read_cert(),
        chain_pem=[],
        template="ACME-ServerAuth",
        requester="",
        metadata={},
    )
    store.revoke_certificate(cert.id, 1)
    return store.get_certificate_by_serial(cert.serial_number)
