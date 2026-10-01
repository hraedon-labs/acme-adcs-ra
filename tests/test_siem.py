"""Tests for SIEM audit emission (Phase 3)."""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.siem import (
    SiemConfig,
    SiemEmitter,
    _NoRedirects,
    build_siem_config,
    default_jsonl_path,
)
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient


def _make_test_config(tmp_path: Path) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001-0123456789abcdef", mac_key=mac_key_b64),
        ],
        san_scopes={
            "kid-001-0123456789abcdef": {"dns_patterns": ["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]},
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


def _make_app(config: RAConfig, audit_hook: Any = None) -> Any:
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in config.san_scopes.items()
        },
        template=config.adcs_template,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
        audit_hook=audit_hook,
    )
    return create_app(context)


# ---------------------------------------------------------------------------
# SiemEmitter unit behavior
# ---------------------------------------------------------------------------


class TestSiemEmitter:
    def test_jsonl_sink_appends_events(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        emitter.export({"event_type": "test", "outcome": "success"})
        emitter.close()

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["event_type"] == "test"
        assert event["outcome"] == "success"
        assert event["schema_version"] == "acme-adcs-ra-audit/1"
        assert "instance" in event

    def test_export_is_fail_open(self, tmp_path: Path) -> None:
        # A path under a non-existent parent that cannot be created as a file.
        path = tmp_path / "not-a-dir" / "events.jsonl"
        path.mkdir(parents=True)
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        # Should not raise even though *path* is a directory.
        emitter.export({"event_type": "test", "outcome": "success"})
        emitter.close()

    def test_disabled_when_no_config(self) -> None:
        emitter = SiemEmitter(SiemConfig(sink="syslog"))
        assert emitter.enabled is False
        # Export must be a no-op, not an error.
        emitter.export({"event_type": "test"})


# ---------------------------------------------------------------------------
# Default config wiring
# ---------------------------------------------------------------------------


class TestDefaultSiemWiring:
    def test_default_config_wires_jsonl_sink(self, tmp_path: Path) -> None:
        config = _make_test_config(tmp_path)
        config.siem_jsonl_path = None
        app = _make_app(config)
        assert app.state.context.audit_hook is not None

    def test_default_jsonl_path_derived_from_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "ra.db"
        assert default_jsonl_path(db_path) == tmp_path / "ra.siem.jsonl"

    def test_build_siem_config_reads_ra_config(self, tmp_path: Path) -> None:
        config = _make_test_config(tmp_path)
        siem_config = build_siem_config(config)
        assert siem_config.sink == "jsonl"
        assert siem_config.jsonl_path == tmp_path / "test_ra.siem.jsonl"
        assert siem_config.hec_token == ""


# ---------------------------------------------------------------------------
# Every audited event produces a SIEM event
# ---------------------------------------------------------------------------


class TestSiemAuditEvents:
    def test_account_created_emits_to_siem(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)
        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        resp = ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))
        assert resp.status_code == 201

        lines = config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line) for line in lines]
        assert any(
            e["event_type"] == "account-created" and e["outcome"] == "success"
            for e in events
        )

    def test_order_created_and_certificate_issued_emit_to_siem(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)
        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        assert order_resp.status_code == 201
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200

        lines = config.siem_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line) for line in lines]
        assert any(e["event_type"] == "order-created" for e in events)
        assert any(
            e["event_type"] == "certificate-issued" and e["outcome"] == "success"
            for e in events
        )

        # Schema fields present on the issuance event.
        issued = next(e for e in events if e["event_type"] == "certificate-issued")
        assert issued["schema_version"] == "acme-adcs-ra-audit/1"
        assert "timestamp" in issued
        assert "account_id" in issued
        assert "order_id" in issued
        assert "sans" in issued
        assert "template" in issued
        assert "requester" in issued
        assert "outcome" in issued
        assert "details" in issued
        assert "instance" in issued

    def test_failing_siem_sink_does_not_abort_issuance(
        self,
        tmp_path: Path,
    ) -> None:
        config = _make_test_config(tmp_path)

        def exploding_hook(event: dict[str, Any]) -> None:
            raise RuntimeError("SIEM is down")

        client = TestClient(_make_app(config, audit_hook=exploding_hook))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200
        assert finalize_resp.json()["status"] == "valid"


# ---------------------------------------------------------------------------
# C-2: SIEM startup probe
# ---------------------------------------------------------------------------


class TestSiemStartupProbe:
    def test_unwritable_jsonl_path_disables_emitter(self, tmp_path: Path) -> None:
        """C-2: An unwritable jsonl path sets enabled=False at init time."""
        # Create a directory where the jsonl file would be — open() will fail
        # with IsADirectoryError during the startup probe.
        path = tmp_path / "blocked" / "events.jsonl"
        path.mkdir(parents=True)
        emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        assert emitter.enabled is False
        emitter.close()

    def test_unwritable_jsonl_path_logs_error(self, tmp_path: Path, caplog: Any) -> None:
        """C-2: An unwritable path causes an ERROR-level log."""
        path = tmp_path / "blocked" / "events.jsonl"
        path.mkdir(parents=True)
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="jsonl", jsonl_path=path))
        assert any(
            "startup probe failed" in rec.message
            for rec in caplog.records
            if rec.levelno >= logging.ERROR
        )
        emitter.close()

    def test_unwritable_siem_still_allows_issuance(self, tmp_path: Path) -> None:
        """C-2: Fail-open — a broken SIEM sink does not abort issuance.
        The RA-store row is still written."""
        # Point SIEM at an unwritable path.
        unwritable = tmp_path / "no-access" / "dir-as-file"
        unwritable.mkdir(parents=True)
        config = _make_test_config(tmp_path)
        config.siem_jsonl_path = unwritable

        client = TestClient(_make_app(config))
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ac = HandRolledAcmeClient(client, config.base_url, account_key)

        ac.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))
        order_resp = ac.new_order(["srv01.WORK-DOMAIN.local"])
        order = order_resp.json()
        for authz_url in order["authorizations"]:
            authz = ac.get_authorization(authz_url).json()
            for challenge in authz["challenges"]:
                ac.validate_challenge(challenge["url"])

        csr_der = _make_csr(["srv01.WORK-DOMAIN.local"])
        finalize_resp = ac.finalize_order(order["finalize"], csr_der)
        assert finalize_resp.status_code == 200

        # The RA-store row exists (fail-open — issuance proceeds).
        store = Store(config.db_path)
        account_id = ac.account_url.split("/")[-1]
        events = store.list_audit_events(account_id=account_id, event_type="certificate-issued")
        assert any(e["outcome"] == "success" for e in events)

    def test_hec_missing_url_disables(self, caplog: Any) -> None:
        """C-2: HEC sink with empty hec_url is disabled at init."""
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="hec", hec_url="", hec_token="tok"))
        assert emitter.enabled is False
        emitter.close()

    def test_hec_plain_http_disables_to_protect_token(self, caplog: Any) -> None:
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(
                SiemConfig(
                    sink="hec",
                    hec_url="http://splunk.example/services/collector",
                    hec_token="secret-token",
                )
            )
        assert emitter.enabled is False
        emitter.close()

    def test_syslog_missing_host_disables(self, caplog: Any) -> None:
        """C-2: syslog sink with empty syslog_host is disabled at init."""
        with caplog.at_level(logging.ERROR, logger="acme_adcs_ra.siem"):
            emitter = SiemEmitter(SiemConfig(sink="syslog", syslog_host=""))
        assert emitter.enabled is False


class _DeadStreamSocket:
    """Stands in for a stream socket whose peer has gone away.

    Killing a real collector mid-test is racy: after an RST the *first*
    ``sendall`` is often absorbed by the local send buffer and the error only
    surfaces on the next write, so a test that asserts on the first send flakes
    (measured at roughly one run in three). The defect under test is not "how
    fast does TCP notice" — it is "when the transport raises, does the emitter
    count a delivery". Injecting the raise makes that deterministic.
    """

    def __init__(self, timeout: float | None) -> None:
        self._timeout = timeout
        self.closed = False

    def sendall(self, *_args: Any, **_kwargs: Any) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    def close(self) -> None:
        self.closed = True

    def gettimeout(self) -> float | None:
        return self._timeout

    def settimeout(self, value: float | None) -> None:
        self._timeout = value


class TestSyslogDeliveryIntegrity:
    """Daybreak 2026-08-17 F4 — a failed syslog send must not count as delivered.

    The stock ``SysLogHandler`` routes transport errors into ``handleError``,
    which returns rather than raising, so ``Logger.info()`` succeeds after a send
    that never left the host. Both the ``audit_offbox_required`` startup probe
    and the runtime delivery counters inferred success from that return, so a
    dead collector read as a healthy off-box audit trail.

    Measured against the pre-fix code with a killed TCP collector: five sends
    produced a ``ConnectionResetError`` followed by four ``BrokenPipeError``s,
    every one swallowed, while the emitter recorded five deliveries, zero
    failures, and the startup probe still answered "syslog accepted the probe
    over TCP".
    """

    SEND_TIMEOUT = 2.0

    @staticmethod
    def _listener() -> tuple[socket.socket, int]:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        return srv, srv.getsockname()[1]

    @staticmethod
    def _accept_in_background(srv: socket.socket, sink: list[socket.socket]) -> None:
        def run() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                sink.append(conn)

        threading.Thread(target=run, daemon=True).start()

    def _emitter(self, port: int) -> SiemEmitter:
        return SiemEmitter(
            SiemConfig(
                sink="syslog",
                syslog_host="127.0.0.1",
                syslog_port=port,
                syslog_proto="tcp",
                syslog_timeout_seconds=self.SEND_TIMEOUT,
            )
        )

    @staticmethod
    def _handler(emitter: SiemEmitter) -> Any:
        assert emitter._syslog is not None
        return emitter._syslog.handlers[0]

    def _kill_transport(self, emitter: SiemEmitter) -> None:
        """Make the established connection behave as if the peer vanished."""
        handler = self._handler(emitter)
        handler.socket = _DeadStreamSocket(self.SEND_TIMEOUT)

    # ---- control: the healthy path must still work, or nothing below proves anything

    def test_live_collector_probe_passes_and_counts_delivery(self) -> None:
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is True, detail
            emitter._syslog_send({"event_type": "test"})
            assert emitter._offbox_delivered == 1
            assert emitter._offbox_failures == 0
        finally:
            emitter.close()
            srv.close()

    def test_tcp_probe_does_not_claim_collector_acknowledgment(self) -> None:
        """A completed TCP send is a live transport, not proof of receipt."""
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is True
            assert "cannot acknowledge receipt" in detail
        finally:
            emitter.close()
            srv.close()

    def test_absent_collector_disables_the_sink_at_construction(self) -> None:
        """Nothing listening at all: connect refused, sink disabled, probe fails."""
        probe, port = self._listener()
        probe.close()  # free the port so the connect is refused
        emitter = self._emitter(port)
        try:
            assert emitter.enabled is False
            assert emitter.probe_offbox_delivery()[0] is False
        finally:
            emitter.close()

    # ---- the defect: an established connection that has died

    def test_dead_transport_fails_the_startup_probe(self) -> None:
        """The audit_offbox_required gate must refuse when the transport is dead."""
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            assert emitter.probe_offbox_delivery()[0] is True
            self._kill_transport(emitter)
            ok, detail = emitter.probe_offbox_delivery()
            assert ok is False, "a dead transport was reported as a healthy off-box sink"
            assert "syslog refused the startup probe" in detail
            assert "Broken pipe" in detail
        finally:
            emitter.close()
            srv.close()

    def test_dead_transport_counts_failures_not_deliveries(self) -> None:
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            for i in range(5):
                self._kill_transport(emitter)  # re-kill: each failure drops the socket
                emitter._syslog_send({"event_type": "test", "n": i})
            assert emitter._offbox_delivered == 0
            assert emitter._offbox_failures == 5
            assert emitter._offbox_last_error is not None
            assert "BrokenPipeError" in emitter._offbox_last_error
        finally:
            emitter.close()
            srv.close()

    def test_failed_send_drops_the_socket_so_the_next_send_reconnects(self) -> None:
        """A blip must not wedge the sink until the process restarts.

        The stock handler never clears a dead stream socket, so without the
        reset in ``handleError`` the first failure would be permanent.
        """
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            dead = _DeadStreamSocket(self.SEND_TIMEOUT)
            self._handler(emitter).socket = dead

            emitter._syslog_send({"event_type": "during-outage"})
            assert emitter._offbox_failures == 1
            assert dead.closed is True, "the dead socket was not closed"
            assert self._handler(emitter).socket is None, (
                "the dead socket was not dropped, so emit() will never reconnect"
            )

            # The collector was never actually down, so the reconnect succeeds.
            emitter._syslog_send({"event_type": "after-recovery"})
            assert emitter._offbox_delivered == 1, "the sink did not reconnect"
        finally:
            emitter.close()
            srv.close()

    def test_reconnected_stream_keeps_its_send_timeout(self) -> None:
        """A reconnect must not silently restore an unbounded blocking send."""
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            handler = self._handler(emitter)
            assert handler.socket.gettimeout() == self.SEND_TIMEOUT
            handler.socket = _DeadStreamSocket(self.SEND_TIMEOUT)
            emitter._syslog_send({"event_type": "during-outage"})
            emitter._syslog_send({"event_type": "after-recovery"})
            assert emitter._offbox_delivered == 1
            assert handler.socket is not None
            assert handler.socket.gettimeout() == self.SEND_TIMEOUT, (
                "the reconnected socket lost its send timeout"
            )
        finally:
            emitter.close()
            srv.close()

    # ---- one real-transport test, bounded so it cannot flake

    def test_real_collector_death_is_detected(self) -> None:
        """End-to-end over a real socket, without asserting on TCP timing.

        "Within a few sends" rather than "on the first send": after the peer
        RSTs, the first ``sendall`` is often absorbed locally and the error
        surfaces on the next write. What must hold is that the failure is
        detected and accounted, not that it is instantaneous.
        """
        srv, port = self._listener()
        conns: list[socket.socket] = []
        self._accept_in_background(srv, conns)
        emitter = self._emitter(port)
        try:
            assert emitter.probe_offbox_delivery()[0] is True
            deadline = time.monotonic() + 5.0
            while not conns and time.monotonic() < deadline:
                time.sleep(0.01)
            assert conns, "the collector never accepted a connection"
            for conn in conns:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                conn.close()
            srv.close()  # nothing to reconnect to either

            for _ in range(10):
                emitter._syslog_send({"event_type": "post-mortem"})
                if emitter._offbox_failures:
                    break
            assert emitter._offbox_failures > 0, (
                "a genuinely dead collector was never reported as a delivery failure"
            )
        finally:
            emitter.close()


class TestJsonlRotation:
    """The JSONL mirror was append-forever, silently doubling the local footprint.

    It is the larger half of a default install's audit footprint, so a retention
    story that covers only the SQLite table leaves most of the problem in place.
    """

    def _emitter(self, tmp_path: Path, max_mib: int = 1, keep: int = 2) -> SiemEmitter:
        return SiemEmitter(
            SiemConfig(
                sink="jsonl",
                jsonl_path=tmp_path / "audit.jsonl",
                jsonl_max_mib=max_mib,
                jsonl_keep=keep,
            )
        )

    @staticmethod
    def _fill(emitter: SiemEmitter, payload_bytes: int, rounds: int) -> None:
        for i in range(rounds):
            emitter.export({"event_type": "e", "n": i, "pad": "x" * payload_bytes})

    def test_rotates_at_the_configured_size(self, tmp_path: Path) -> None:
        emitter = self._emitter(tmp_path)
        try:
            self._fill(emitter, 4096, 400)  # comfortably past 1 MiB
            assert (tmp_path / "audit.jsonl.1").exists(), "the mirror never rolled"
            assert (tmp_path / "audit.jsonl").stat().st_size < 1024 * 1024
        finally:
            emitter.close()

    def test_keeps_only_the_configured_number_of_files(self, tmp_path: Path) -> None:
        emitter = self._emitter(tmp_path, keep=2)
        try:
            self._fill(emitter, 4096, 1600)  # several rotations
            assert (tmp_path / "audit.jsonl.1").exists()
            assert (tmp_path / "audit.jsonl.2").exists()
            assert not (tmp_path / "audit.jsonl.3").exists(), (
                "retained more files than audit_jsonl_keep allows"
            )
        finally:
            emitter.close()

    def test_zero_max_keeps_the_append_forever_behaviour(self, tmp_path: Path) -> None:
        emitter = self._emitter(tmp_path, max_mib=0)
        try:
            self._fill(emitter, 4096, 400)
            assert not (tmp_path / "audit.jsonl.1").exists()
            assert (tmp_path / "audit.jsonl").stat().st_size > 1024 * 1024
        finally:
            emitter.close()

    def test_jsonl_bytes_counts_rotated_files(self, tmp_path: Path) -> None:
        """The footprint must not shrink just because the mirror rolled."""
        emitter = self._emitter(tmp_path)
        try:
            self._fill(emitter, 4096, 400)
            live = (tmp_path / "audit.jsonl").stat().st_size
            assert (tmp_path / "audit.jsonl.1").exists()
            assert emitter.jsonl_bytes() > live
        finally:
            emitter.close()

    def test_rotation_failure_never_breaks_emission(self, tmp_path: Path) -> None:
        """Emission is the audit path; a capacity chore must not raise into it."""
        emitter = self._emitter(tmp_path)
        try:
            self._fill(emitter, 4096, 400)
            # A directory where the rolled file belongs makes replace() fail.
            (tmp_path / "audit.jsonl.1").exists() and (tmp_path / "audit.jsonl.1").unlink()
            (tmp_path / "audit.jsonl.1").mkdir()
            emitter.export({"event_type": "after-broken-rotation"})
            assert "after-broken-rotation" in (tmp_path / "audit.jsonl").read_text()
        finally:
            emitter.close()


class TestHecRedirectDoesNotLeakTheToken:
    """2026-08-24 daybreak F12 — a redirect used to carry the collector token.

    ``urllib``'s default redirect handler copies every header except
    content-length/content-type onto the new request, so ``Authorization``
    followed the ``Location`` — to any host, and to plain http, defeating the
    https-only check the sink is gated on. These tests drive real sockets
    rather than mocking ``urlopen``, because the defect lived entirely in
    urllib's handler chain: a mock would have asserted our own assumptions and
    passed against the vulnerable code.
    """

    @staticmethod
    def _serve(handler_fn: Any) -> Any:
        """A throwaway HTTP server that DRAINS the request body first.

        The drain is not tidiness. Without it the handler answers and closes
        while the client's POST body is still unread in the receive buffer, and
        Windows answers an unread-data close with an RST rather than a FIN. The
        client then gets ``ConnectionAbortedError [WinError 10053]`` instead of
        the response it was about to read — intermittently, depending on how the
        writes interleave. It reddened CI on 2026-09-05 against a docs-only
        commit and passed on a re-run of the identical tree.

        That matters here for a reason worth stating, because the obvious fix is
        the wrong one. On an abort the request never reaches the redirect, so
        the attacker sink is never contacted, so ``seen["authorization"] is
        None`` passes — **for the wrong reason**. The ``"302" in
        offbox_last_error`` assertion is the only thing that caught it, which is
        why the flake showed up as a loud failure instead of a quiet green.
        Anyone relaxing that assertion to "fix the flake" would convert a real
        security test into one that cannot fail. Drain the body instead, and
        assert the redirect was reached by direct observation.
        """
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class _H(BaseHTTPRequestHandler):
            def _drain(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)

            def do_POST(self) -> None:
                self._drain()
                handler_fn(self)

            def do_GET(self) -> None:
                self._drain()
                handler_fn(self)

            def log_message(self, *a: Any) -> None:
                pass

        srv = HTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_token_never_reaches_a_redirect_target(self) -> None:
        seen: dict[str, Any] = {}

        def attacker(h: Any) -> None:
            seen["authorization"] = h.headers.get("Authorization")
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b'{"text":"Success","code":0}')

        sink = self._serve(attacker)
        front_hits: list[str] = []

        def collector(h: Any) -> None:
            front_hits.append(h.path)
            h.send_response(302)
            h.send_header("Location", f"http://127.0.0.1:{sink.server_port}/x")
            h.end_headers()

        front = self._serve(collector)
        try:
            emitter = SiemEmitter(
                SiemConfig(
                    sink="hec",
                    hec_url=f"http://127.0.0.1:{front.server_port}/services/collector",
                    hec_token="SUPER-SECRET-HEC-TOKEN",
                )
            )
            try:
                emitter._hec_post_inner({"event_type": "probe"})
            finally:
                emitter.close()

            # Anti-vacuity, by direct observation rather than by parsing an
            # error string. The sink is never contacted when the code is
            # CORRECT, so "the token did not arrive" is only evidence if the
            # request actually got as far as being redirected.
            assert front_hits, (
                "the collector was never reached, so this test proves nothing "
                "about what a redirect would have carried"
            )
            # The whole finding, in one assertion.
            assert seen.get("authorization") is None, (
                "the collector token was forwarded to the redirect target"
            )
            # And the refusal is recorded as a delivery FAILURE, not swallowed
            # as a success -- audit_offbox_required is a boolean gate, so a
            # redirect that silently counted as delivered would be the
            # 2026-08-18 UDP defect in a new place.
            assert emitter.offbox_delivered == 0
            assert emitter.offbox_failures == 1
            assert "302" in (emitter.offbox_last_error or "")
        finally:
            front.shutdown()
            sink.shutdown()

    def test_the_startup_probe_fails_rather_than_starting_on_a_leak(self) -> None:
        """raise_on_error is the path audit_offbox_required gates startup on."""

        def collector(h: Any) -> None:
            h.send_response(301)
            h.send_header("Location", "http://evil.invalid/collector")
            h.end_headers()

        front = self._serve(collector)
        try:
            emitter = SiemEmitter(
                SiemConfig(
                    sink="hec",
                    hec_url=f"http://127.0.0.1:{front.server_port}/services/collector",
                    hec_token="SUPER-SECRET-HEC-TOKEN",
                )
            )
            try:
                with pytest.raises(HTTPError) as caught:
                    emitter._hec_post_inner({"event_type": "probe"}, raise_on_error=True)
            finally:
                emitter.close()
            assert caught.value.code == 301
            assert "refusing to follow" in str(caught.value.reason)
        finally:
            front.shutdown()

    def test_redirect_handler_refuses_every_code_urllib_would_follow(self) -> None:
        """301/302/303/307/308 all reach redirect_request; none may be followed."""
        handler = _NoRedirects()
        req = Request("https://splunk.example/services/collector", method="POST")
        for code in (301, 302, 303, 307, 308):
            with pytest.raises(HTTPError) as caught:
                handler.redirect_request(
                    req, None, code, "Found", {}, "http://evil.invalid/x"
                )
            assert caught.value.code == code
