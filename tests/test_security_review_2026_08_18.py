"""Regression tests for the 2026-08-18 scan of `8a4baca`.

Two medium and three low, all five covered here:

* F1 — CRL redirects escaped the URL, size and wall-clock controls entirely:
  `requests.get` followed them itself, before the watchdog was armed and
  against destinations nothing had validated.
* F2 — revocation reconciliation could report PASS while certificates the RA
  had revoked were live at the CA (wrong issued disposition, dropped rows,
  intersection-only comparison, quarantined state ignored).
* F3 — a stale single-flight cleanup callback could evict its own successor.
* F4 — a pending CA request was reported as a generic transport failure, so
  administrative recovery could reopen the order and issue a second time.
* F5 — equivalent JWK encodings produced different account identities, so one
  key could keep a twin account across deactivation.

Each test here was mutation-checked: the fix was reverted in turn and the test
confirmed to fail. See docs/security-review-2026-08-18.md.
"""

from __future__ import annotations

import asyncio
import base64
import http.server
import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from acme_adcs_ra.crl_evidence import CrlEvidenceGate, fetch_crl_evidence
from acme_adcs_ra.enrollment import EnrollmentPending
from acme_adcs_ra.jws import (
    JWSValidationError,
    _public_key_from_jwk,
    canonicalize_jwk,
    jwk_thumbprint,
)
from acme_adcs_ra.store import OrderStatus, Store

from .conftest import placeholder_rsa_jwk

_RECONCILE = Path(__file__).resolve().parent.parent / "scripts" / "reconcile_revocation.py"


# ---------------------------------------------------------------------------
# Finding 1 (medium) — CRL redirects bypassed URL, size and deadline controls
# ---------------------------------------------------------------------------


def _serve(handler_body: Any) -> tuple[str, Any]:
    """Run a one-off HTTP server; returns (base_url, shutdown)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            handler_body(self)

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}", server.shutdown


class TestCrlRedirectsAreNotFollowedOffHost:
    """The configured CDP is trusted; what it *says* to fetch next is not.

    A `Location` header is chosen by whoever answers the CDP. Following it
    wherever it points made the RA a blind SSRF probe against anything on its
    network — and requests resolved the whole chain inside one call, so the
    byte budget and the total deadline never saw any of it.
    """

    def test_a_redirect_to_another_host_is_refused(self) -> None:
        # The "internal service" the redirect aims at. If the fix regresses,
        # this records the hit.
        hits: list[str] = []

        def internal(handler: Any) -> None:
            hits.append(handler.path)
            handler.send_response(200)
            handler.send_header("Content-Length", "2")
            handler.end_headers()
            handler.wfile.write(b"hi")

        internal_url, stop_internal = _serve(internal)

        # Aimed at the same loopback address under a different *name*, so the
        # host rule is what refuses it rather than the port rule — the SSRF
        # shape the finding describes is "off to some other host entirely".
        internal_port = internal_url.rsplit(":", 1)[1]

        def redirector(handler: Any) -> None:
            handler.send_response(302)
            handler.send_header("Location", f"http://localhost:{internal_port}/secrets")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        crl_url, stop_crl = _serve(redirector)
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{crl_url}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
                follow_redirects=True,
            )
        finally:
            stop_crl()
            stop_internal()

        assert evidence.checked is False
        assert "refused a redirect" in evidence.detail
        assert "leaves the configured CRL host" in evidence.detail
        # The load-bearing assertion: the redirected request was never made.
        assert hits == []

    def test_a_redirect_to_loopback_is_refused_from_a_named_host(self) -> None:
        """Same rule, stated the way the finding did: 302 to loopback."""
        from urllib.parse import urlparse

        from acme_adcs_ra.crl_evidence import _vet_redirect

        origin = urlparse("http://pki.example.test/ca.crl")
        target, refusal = _vet_redirect(
            "http://127.0.0.1/latest.crl", "http://pki.example.test/ca.crl", origin
        )
        assert target is None
        assert "leaves the configured CRL host" in refusal

    def test_a_same_host_redirect_is_followed(self) -> None:
        """The rule is 'stay on the host', not 'never redirect'."""
        seen: list[str] = []

        def handler(handler_self: Any) -> None:
            seen.append(handler_self.path)
            if handler_self.path == "/ca.crl":
                handler_self.send_response(302)
                handler_self.send_header("Location", "/real.crl")
                handler_self.send_header("Content-Length", "0")
                handler_self.end_headers()
                return
            body = b"not a crl at all"
            handler_self.send_response(200)
            handler_self.send_header("Content-Length", str(len(body)))
            handler_self.end_headers()
            handler_self.wfile.write(body)

        base, stop = _serve(handler)
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{base}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
                follow_redirects=True,
            )
        finally:
            stop()

        assert seen == ["/ca.crl", "/real.crl"]
        # Reached the document and rejected it on content, not on policy.
        assert "neither valid DER nor PEM" in evidence.detail

    def test_a_redirect_loop_terminates(self) -> None:
        """Same host, so the destination rule permits it — the hop cap stops it."""
        hits: list[str] = []

        def handler(handler_self: Any) -> None:
            hits.append(handler_self.path)
            handler_self.send_response(302)
            handler_self.send_header("Location", f"/hop{len(hits)}")
            handler_self.send_header("Content-Length", "0")
            handler_self.end_headers()

        base, stop = _serve(handler)
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{base}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
                follow_redirects=True,
            )
        finally:
            stop()

        assert evidence.checked is False
        assert "exceeded 4 redirects" in evidence.detail
        assert len(hits) == 5  # the initial request plus four permitted hops

    def test_an_https_to_http_downgrade_is_refused(self) -> None:
        from urllib.parse import urlparse

        from acme_adcs_ra.crl_evidence import _vet_redirect

        origin = urlparse("https://pki.example.test/ca.crl")
        target, refusal = _vet_redirect(
            "http://pki.example.test/ca.crl", "https://pki.example.test/ca.crl", origin
        )
        assert target is None
        assert "downgrades https to http" in refusal

    def test_a_same_host_port_change_is_refused(self) -> None:
        """Same host on a different port is a different service."""
        from urllib.parse import urlparse

        from acme_adcs_ra.crl_evidence import _vet_redirect

        origin = urlparse("http://pki.example.test/ca.crl")
        target, refusal = _vet_redirect(
            "http://pki.example.test:8500/v1/secret",
            "http://pki.example.test/ca.crl",
            origin,
        )
        assert target is None
        assert "changes the port" in refusal

    def test_a_redirect_to_a_non_http_scheme_is_refused(self) -> None:
        from urllib.parse import urlparse

        from acme_adcs_ra.crl_evidence import _vet_redirect

        origin = urlparse("http://pki.example.test/ca.crl")
        target, refusal = _vet_redirect(
            "file:///etc/shadow", "http://pki.example.test/ca.crl", origin
        )
        assert target is None
        assert "not an http(s) URL" in refusal


class TestRedirectHeadersCountAgainstTheDeadline:
    def test_a_stalled_redirect_chain_hits_the_total_deadline(self) -> None:
        """Redirect handling used to sit entirely outside the wall-clock bound.

        Each hop answers, slowly. Under the old code the chain resolved inside
        `requests.get` with no deadline in force at all; now the clock is armed
        before the first request and checked between hops.
        """
        import time

        def handler(handler_self: Any) -> None:
            time.sleep(0.4)
            handler_self.send_response(302)
            handler_self.send_header("Location", "/next")
            handler_self.send_header("Content-Length", "0")
            handler_self.end_headers()

        base, stop = _serve(handler)
        started = time.monotonic()
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{base}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                timeout_seconds=8.0,
                total_timeout_seconds=0.6,
                follow_redirects=True,
            )
        finally:
            stop()
        elapsed = time.monotonic() - started

        assert evidence.checked is False
        assert "total deadline" in evidence.detail
        # Would have run ~2s (five 0.4s hops) with the deadline out of the loop.
        assert elapsed < 1.6


class TestDeadlineClassificationToleratesTimerGranularity:
    def test_a_clamped_timeout_firing_a_tick_early_still_reads_as_the_deadline(
        self,
    ) -> None:
        """Windows CI, 2026-10-03: the clamped socket timeout fired just before
        `time.monotonic()` reached the deadline, so an exact comparison reported
        a generic fetch failure instead of the deadline."""
        import threading
        import time

        from acme_adcs_ra.crl_evidence import _past_deadline

        timed_out = threading.Event()
        assert _past_deadline(timed_out, time.monotonic() + 0.01) is True

    def test_an_error_well_before_the_deadline_is_not_the_deadline(self) -> None:
        import threading
        import time

        from acme_adcs_ra.crl_evidence import _past_deadline

        timed_out = threading.Event()
        assert _past_deadline(timed_out, time.monotonic() + 5.0) is False

# ---------------------------------------------------------------------------
# Finding 2 (medium) — reconciliation could falsely PASS
# ---------------------------------------------------------------------------


def _ca_export(rows: list[tuple[int, str, int]]) -> str:
    lines: list[str] = []
    for idx, (request_id, serial, disposition) in enumerate(rows, start=1):
        lines += [
            f"Row Index: {idx}",
            f"  Request ID: {request_id}",
            f"  Serial Number: {serial}",
            f"  Disposition: {disposition}",
            "",
        ]
    return "\n".join(lines)


def _seed_cert(db_path: Path, serial_hex: str, status: str) -> None:
    """Write a certificate row directly. Only serial + status are reconciled."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO certificates (id, order_id, account_id, cert_pem, "
            "chain_pem, template, requester, metadata, issued_at, status, "
            "serial_number) VALUES (?, ?, ?, '', '[]', 't', 'r', '{}', ?, ?, ?)",
            (
                f"cert-{serial_hex}",
                f"order-{serial_hex}",
                "acct-1",
                "2026-08-18T00:00:00+00:00",
                status,
                serial_hex,
            ),
        )


def _reconcile(db_path: Path, export: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    export_path = tmp_path / "ca-export.txt"
    export_path.write_text(export)
    return subprocess.run(
        [
            sys.executable,
            str(_RECONCILE),
            "--db",
            str(db_path),
            "--ca-export",
            str(export_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    Store(tmp_path / "ra.db")
    return tmp_path / "ra.db"


class TestReconciliationCannotFalselyPass:
    def test_disposition_20_active_at_ca_versus_revoked_in_ra_is_drift(
        self, db: Path, tmp_path: Path
    ) -> None:
        """The headline defect: 20 is ADCS's issued disposition, not 3.

        With the constant wrong, every ordinary issued row was discarded and the
        serial fell out of the comparison entirely — reported as PASS.
        """
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, _ca_export([(1, "AABBCCDD", 20)]), tmp_path)

        assert result.returncode == 1
        body = json.loads(result.stdout)
        assert body["revoked_in_ra_active_at_ca"] == ["AABBCCDD"]

    def test_a_quarantined_certificate_must_be_revoked_at_the_ca(
        self, db: Path, tmp_path: Path
    ) -> None:
        """Quarantined certificates are live at the CA and share the revoke path.

        `Store.list_revoked_certificates` includes them for exactly that reason;
        the reconciler treated only `revoked` as needing CA-side revocation, so
        a quarantined certificate active at the CA read as agreement.
        """
        _seed_cert(db, "CAFEBABE", "quarantined")
        result = _reconcile(db, _ca_export([(1, "CAFEBABE", 20)]), tmp_path)

        assert result.returncode == 1
        body = json.loads(result.stdout)
        assert body["revoked_in_ra_active_at_ca"] == ["CAFEBABE"]

    def test_a_quarantined_certificate_revoked_at_the_ca_is_in_sync(
        self, db: Path, tmp_path: Path
    ) -> None:
        _seed_cert(db, "CAFEBABE", "quarantined")
        result = _reconcile(db, _ca_export([(1, "CAFEBABE", 21)]), tmp_path)

        assert result.returncode == 0
        assert json.loads(result.stdout)["in_sync"] == ["CAFEBABE"]

    def test_an_ra_serial_missing_from_the_export_is_not_a_pass(
        self, db: Path, tmp_path: Path
    ) -> None:
        """The intersection could not express 'not covered', so it said nothing.

        A partial export — the single most likely failure of `certutil -view` —
        produced exit 0 while a revoked certificate went unchecked.
        """
        _seed_cert(db, "AABBCCDD", "revoked")
        _seed_cert(db, "DEADBEEF", "revoked")
        result = _reconcile(db, _ca_export([(1, "AABBCCDD", 21)]), tmp_path)

        assert result.returncode == 2
        body = json.loads(result.stdout)
        assert body["ra_serials_absent_from_ca"] == ["DEADBEEF"]
        assert body["coverage_complete"] is False

    def test_an_empty_export_is_not_a_pass(self, db: Path, tmp_path: Path) -> None:
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, "", tmp_path)

        assert result.returncode == 2
        body = json.loads(result.stdout)
        assert body["coverage_complete"] is False
        assert any("no certutil rows" in p for p in body["parse_problems"])

    def test_an_unknown_disposition_is_a_problem_not_a_silent_drop(
        self, db: Path, tmp_path: Path
    ) -> None:
        _seed_cert(db, "AABBCCDD", "revoked")
        result = _reconcile(db, _ca_export([(1, "AABBCCDD", 99)]), tmp_path)

        assert result.returncode == 2
        body = json.loads(result.stdout)
        assert any("unrecognized Disposition 99" in p for p in body["parse_problems"])

    def test_a_serial_with_no_disposition_is_a_problem(
        self, db: Path, tmp_path: Path
    ) -> None:
        _seed_cert(db, "AABBCCDD", "revoked")
        export = "Row Index: 1\n  Request ID: 1\n  Serial Number: AABBCCDD\n"
        result = _reconcile(db, export, tmp_path)

        assert result.returncode == 2
        body = json.loads(result.stdout)
        assert any("no Disposition" in p for p in body["parse_problems"])

    def test_a_failed_certutil_export_refuses_to_compare(
        self, db: Path, tmp_path: Path
    ) -> None:
        """certutil's exit status was ignored, so a failed export was reconciled."""
        _seed_cert(db, "AABBCCDD", "revoked")
        export_path = tmp_path / "ca.txt"
        export_path.write_text(_ca_export([(1, "AABBCCDD", 21)]))
        result = subprocess.run(
            [
                sys.executable, str(_RECONCILE),
                "--db", str(db),
                "--ca-export", str(export_path),
                "--ca-export-exit-code", "1",
            ],
            capture_output=True, text=True, check=False,
        )

        assert result.returncode == 2
        assert "certutil exited 1" in result.stderr
        assert "PASS" not in result.stdout

    def test_denied_and_pending_rows_do_not_invent_drift(
        self, db: Path, tmp_path: Path
    ) -> None:
        """A request that never became a certificate is not a live certificate."""
        _seed_cert(db, "AABBCCDD", "revoked")
        export = _ca_export([(1, "AABBCCDD", 21), (2, "11112222", 31)])
        result = _reconcile(db, export, tmp_path)

        assert result.returncode == 0
        body = json.loads(result.stdout)
        assert body["in_sync"] == ["AABBCCDD"]
        assert body["parse_problems"] == []

    def test_ca_certificates_the_ra_never_issued_are_not_drift(
        self, db: Path, tmp_path: Path
    ) -> None:
        """The CA legitimately issues certificates this RA never requested."""
        _seed_cert(db, "AABBCCDD", "revoked")
        export = _ca_export([(1, "AABBCCDD", 21), (2, "99998888", 20)])
        result = _reconcile(db, export, tmp_path)

        assert result.returncode == 0
        assert json.loads(result.stdout)["coverage_complete"] is True


# ---------------------------------------------------------------------------
# Finding 3 (low) — a stale cleanup callback could evict its successor
# ---------------------------------------------------------------------------


class TestSingleFlightCleanupIsIdentityChecked:
    def test_a_stale_callback_does_not_evict_a_successor(self) -> None:
        """`add_done_callback` is dispatched through `call_soon`, so a caller
        can observe a settled future, pop it, and install a successor before the
        old callback runs. An unconditional `pop(key)` then removed the live
        successor: further callers submitted duplicates, and the successor was
        no longer counted against `max_pending`.

        The lateness is the whole defect and racing for it would be flaky, so
        this drives it directly: capture the first flight's cleanup callback,
        let a successor take the key, then fire that callback by hand — exactly
        what `call_soon` does if it lands after the successor is installed.
        """
        gate = CrlEvidenceGate(max_workers=2, max_pending=4)
        release_first = threading.Event()
        release_second = threading.Event()

        async def scenario() -> bool:
            first = asyncio.ensure_future(
                gate.run("SERIAL-A", lambda: release_first.wait(5))
            )
            await asyncio.sleep(0.05)
            f1 = gate._inflight["SERIAL-A"]
            # Captured before it settles: asyncio clears the list once it
            # schedules them.
            cleanup = [
                cb
                for cb, _ctx in list(f1._callbacks)
                if "asyncio" not in (getattr(cb, "__module__", "") or "")
            ]
            assert cleanup, "the gate registered no cleanup callback"

            release_first.set()
            await first
            assert "SERIAL-A" not in gate._inflight

            # The successor takes the key.
            second = asyncio.ensure_future(
                gate.run("SERIAL-A", lambda: release_second.wait(5))
            )
            await asyncio.sleep(0.05)
            successor = gate._inflight["SERIAL-A"]
            assert successor is not f1

            # The first flight's cleanup arrives late.
            for cb in cleanup:
                cb(f1)

            survived = gate._inflight.get("SERIAL-A") is successor
            release_second.set()
            await second
            return survived

        try:
            assert asyncio.run(scenario()) is True
        finally:
            release_first.set()
            release_second.set()
            gate.close()

    def test_the_ordinary_cleanup_still_happens(self) -> None:
        """The identity check must not turn into a leak: a finished flight's own
        callback still clears its key."""
        gate = CrlEvidenceGate(max_workers=1)

        async def scenario() -> int:
            await gate.run("SERIAL-A", lambda: "done")
            await asyncio.sleep(0.05)  # let the done callback run
            return gate.inflight

        try:
            assert asyncio.run(scenario()) == 0
        finally:
            gate.close()


# ---------------------------------------------------------------------------
# Finding 4 (low) — a pending CA request could be retried into double issuance
# ---------------------------------------------------------------------------


class TestPendingCaRequestsAreDurablyTracked:
    def test_the_pending_disposition_carries_its_req_id(self) -> None:
        """The ReqID used to exist only inside a message string.

        `EnrollmentTransportError.ca_issued` was therefore false, finalize
        recorded a generic non-issuance, and nothing durable said which CA
        request was outstanding.
        """
        exc = EnrollmentPending("pending at the CA (ReqID=4242)", req_id="4242")
        assert exc.req_id == "4242"

    def test_the_leg_does_not_rewrap_pending_as_a_transport_error(self) -> None:
        """`submit_csr`'s catch-all re-wraps unexpected exceptions as
        `EnrollmentTransportError`. Left alone it swallowed `EnrollmentPending`
        on the way out, stripped the ReqID, and put the pending request straight
        back into the bucket recovery is allowed to retry — the fix undone one
        frame above where it was applied."""
        from acme_adcs_ra.enrollment import CertsrvEnrollmentLeg, EnrollmentTransportError

        from .test_enrollment import _CSR_PEM, _FakeResponse, _FakeSession

        fake = _FakeSession(
            routes={
                "certfnsh.asp": _FakeResponse(
                    text="... Certificate Pending ... Your Request Id is 7 ..."
                ),
            }
        )
        leg = CertsrvEnrollmentLeg(
            host="ca.example.test", template="ACME-ServerAuth",
            session_factory=lambda: fake,
        )
        with pytest.raises(EnrollmentPending) as caught:
            leg.submit_csr(_CSR_PEM, account_id="a", requested_sans=[])
        assert caught.value.req_id == "7"
        assert not isinstance(caught.value, EnrollmentTransportError)

    def test_the_leg_raises_pending_with_the_req_id(self) -> None:
        """End-to-end through the certfnsh parser, so the wiring is covered."""
        from acme_adcs_ra.enrollment import _parse_certfnsh_disposition

        body = (
            "<html>Your certificate request has been received. "
            'Your Request Id is 4242. <a href="certckpn.asp?ReqID=4242">'
            "</a></html>"
        )
        disposition, detail = _parse_certfnsh_disposition(body, 200)
        assert disposition == "pending"
        assert detail == "4242"

    def _processing_order_with_pending(self, tmp_path: Path) -> tuple[Store, str]:
        store = Store(tmp_path / "ra.db")
        account = store.create_account(
            jwk=placeholder_rsa_jwk("pending-f4"), eab_kid="kid-001-0123456789abcdef"
        )
        order = store.create_order_with_authz(
            account_id=account.id,
            identifiers=[{"type": "dns", "value": "srv.example.test"}],
            challenge_url_fn=lambda cid: f"http://t/acme/chall/{cid}",
            authz_url_fn=lambda aid: f"http://t/acme/authz/{aid}",
            finalize_url_fn=lambda oid: f"http://t/acme/order/{oid}/finalize",
        )
        assert store.transition_pending_to_ready(order.id)
        generation = store.acquire_processing_lease(order.id)
        assert generation is not None
        assert store.record_pending_ca_request(
            order.id, "4242", expected_generation=generation
        )
        return store, order.id

    def test_the_pending_req_id_survives_a_reload(self, tmp_path: Path) -> None:
        """Durable, not in-memory: the whole point is surviving the crash that
        wedged the order in the first place."""
        store, order_id = self._processing_order_with_pending(tmp_path)
        del store

        reopened = Store(tmp_path / "ra.db")
        order = reopened.get_order(order_id)
        assert order is not None
        assert order.pending_ca_request_id == "4242"

    def test_a_stale_generation_cannot_stamp_its_req_id(self, tmp_path: Path) -> None:
        """A worker whose lease was reclaimed must not mark an order now owned
        by a different enrollment."""
        store, order_id = self._processing_order_with_pending(tmp_path)
        order = store.get_order(order_id)
        assert order is not None

        assert not store.record_pending_ca_request(
            order_id, "9999", expected_generation=order.processing_generation + 5
        )
        refreshed = store.get_order(order_id)
        assert refreshed is not None
        assert refreshed.pending_ca_request_id == "4242"

    def test_clearing_is_keyed_on_the_req_id(self, tmp_path: Path) -> None:
        """Clearing 'whatever is pending' would let an assertion made about one
        request discharge a different one."""
        store, order_id = self._processing_order_with_pending(tmp_path)

        assert not store.clear_pending_ca_request(order_id, "1111")
        order = store.get_order(order_id)
        assert order is not None
        assert order.pending_ca_request_id == "4242"

        assert store.clear_pending_ca_request(order_id, "4242")
        order = store.get_order(order_id)
        assert order is not None
        assert order.pending_ca_request_id is None


class TestReclaimRefusesAPendingCaRequest:
    """`?ca_verified_no_issuance=true` asserts something about the past.

    An officer approving the pending request afterwards makes it false — and the
    order has been reopened and re-enrolled by then. Two live certificates for
    one order, which is the invariant the lifecycle exists to hold.
    """

    def _client_with_pending_order(self, tmp_path: Path) -> tuple[Any, str, Any]:
        from .test_security_review_2026_08_13 import STRONG_ADMIN_TOKEN, _client

        client = _client(tmp_path)
        ctx = client.app.state.context  # type: ignore[attr-defined]
        store = ctx.store
        account = store.create_account(
            jwk=placeholder_rsa_jwk("reclaim-f4"), eab_kid="kid-001-0123456789abcdef"
        )
        order = store.create_order_with_authz(
            account_id=account.id,
            identifiers=[{"type": "dns", "value": "srv.example.test"}],
            challenge_url_fn=lambda cid: f"http://t/acme/chall/{cid}",
            authz_url_fn=lambda aid: f"http://t/acme/authz/{aid}",
            finalize_url_fn=lambda oid: f"http://t/acme/order/{oid}/finalize",
        )
        assert store.transition_pending_to_ready(order.id)
        generation = store.acquire_processing_lease(order.id)
        assert generation is not None
        store.record_pending_ca_request(order.id, "4242", expected_generation=generation)
        # Past the reclaim age floor: this test is about the pending gate, not
        # the enrollment window.
        with sqlite3.connect(str(store._db_path)) as conn:
            conn.execute(
                "UPDATE orders SET processing_started_at = ? WHERE id = ?",
                ("2020-01-01T00:00:00Z", order.id),
            )
        return client, order.id, {"Authorization": f"Bearer {STRONG_ADMIN_TOKEN}"}

    def test_reclaim_is_refused_while_a_ca_request_is_pending(
        self, tmp_path: Path
    ) -> None:
        client, order_id, auth = self._client_with_pending_order(tmp_path)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true",
            headers=auth,
        )

        assert resp.status_code == 400
        assert "ReqID=4242" in resp.text
        store = client.app.state.context.store  # type: ignore[attr-defined]
        order = store.get_order(order_id)
        assert order.status == OrderStatus.PROCESSING

    def test_a_wrong_req_id_assertion_is_refused(self, tmp_path: Path) -> None:
        """The ReqID must match exactly — a bare boolean would let an assertion
        about one request discharge another."""
        client, order_id, auth = self._client_with_pending_order(tmp_path)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true&ca_request_resolved=1111",
            headers=auth,
        )

        assert resp.status_code == 400
        assert "ReqID=4242" in resp.text

    def test_naming_the_resolved_req_id_permits_the_reclaim(
        self, tmp_path: Path
    ) -> None:
        client, order_id, auth = self._client_with_pending_order(tmp_path)
        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true&ca_request_resolved=4242",
            headers=auth,
        )

        assert resp.status_code == 200
        store = client.app.state.context.store  # type: ignore[attr-defined]
        order = store.get_order(order_id)
        assert order.status == OrderStatus.READY
        # The marker is discharged, so the next reclaim starts clean.
        assert order.pending_ca_request_id is None

    def test_an_order_with_no_pending_request_is_unaffected(
        self, tmp_path: Path
    ) -> None:
        """The gate must not become a new way to wedge ordinary recovery."""
        client, order_id, auth = self._client_with_pending_order(tmp_path)
        store = client.app.state.context.store  # type: ignore[attr-defined]
        store.clear_pending_ca_request(order_id, "4242")

        resp = client.post(
            f"/acme/admin/orders/{order_id}/reclaim-processing"
            "?ca_verified_no_issuance=true",
            headers=auth,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Finding 5 (low) — equivalent JWK encodings gave one key several accounts
# ---------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _real_rsa_jwk() -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa

    numbers = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": "AQAB",
    }


class TestJwkIdentityIsCanonical:
    """One key, one thumbprint, one account.

    Verification decoded padded base64url and non-minimal leading-zero integers
    into an identical key, while `jwk_thumbprint` hashed the member *strings*.
    So one key registered under several thumbprints with one EAB credential, and
    deactivating the observed account left the twin usable.
    """

    def test_a_leading_zero_exponent_is_refused(self) -> None:
        jwk = _real_rsa_jwk()
        assert _public_key_from_jwk(jwk)  # canonical form works

        twin = {**jwk, "e": _b64u(b"\x00\x01\x00\x01")}  # same e=65537
        with pytest.raises(JWSValidationError, match="leading zero octet"):
            _public_key_from_jwk(twin)
        with pytest.raises(JWSValidationError, match="leading zero octet"):
            jwk_thumbprint(twin)

    def test_a_padded_member_is_refused(self) -> None:
        jwk = _real_rsa_jwk()
        twin = {**jwk, "n": jwk["n"] + "="}
        with pytest.raises(JWSValidationError, match="unpadded base64url"):
            jwk_thumbprint(twin)

    def test_a_leading_zero_modulus_is_refused(self) -> None:
        jwk = _real_rsa_jwk()
        raw = base64.urlsafe_b64decode(jwk["n"] + "=" * ((-len(jwk["n"])) % 4))
        twin = {**jwk, "n": _b64u(b"\x00" + raw)}
        with pytest.raises(JWSValidationError, match="leading zero octet"):
            jwk_thumbprint(twin)

    def test_trailing_bits_are_refused(self) -> None:
        """`"Aw"` and `"Ax"` both decode to b"\\x03" — two spellings, one value."""
        with pytest.raises(JWSValidationError, match="not canonical base64url"):
            jwk_thumbprint({"kty": "RSA", "n": "Ax", "e": "AQAB"})

    def test_a_stripped_ec_coordinate_is_refused(self) -> None:
        """RFC 7518 §6.2.1.2 fixes the width, so a stripped leading zero is a
        second spelling rather than a normalisation."""
        x = bytes([0x00]) + b"\x11" * 31
        y = b"\x22" * 32
        canonical = {"kty": "EC", "crv": "P-256", "x": _b64u(x), "y": _b64u(y)}
        assert jwk_thumbprint(canonical)

        stripped = {**canonical, "x": _b64u(x.lstrip(b"\x00"))}
        with pytest.raises(JWSValidationError, match="requires exactly 32"):
            jwk_thumbprint(stripped)

    def test_an_over_padded_ec_coordinate_is_refused(self) -> None:
        y = b"\x22" * 32
        over = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u(b"\x00" + b"\x11" * 32),
            "y": _b64u(y),
        }
        with pytest.raises(JWSValidationError, match="requires exactly 32"):
            jwk_thumbprint(over)

    def test_deactivation_cannot_leave_a_twin(self, tmp_path: Path) -> None:
        """The finding's end state, asserted at the store: a second account for
        the same key cannot be created, so there is nothing to survive
        deactivation."""
        store = Store(tmp_path / "ra.db")
        jwk = _real_rsa_jwk()
        first = store.create_account(jwk=jwk, eab_kid="kid-001-0123456789abcdef")

        twin_jwk = {**jwk, "e": _b64u(b"\x00\x01\x00\x01")}
        with pytest.raises(JWSValidationError):
            store.create_account(jwk=twin_jwk, eab_kid="kid-001-0123456789abcdef")

        # And the twin encoding does not resolve to a *different* account.
        with pytest.raises(JWSValidationError):
            store.get_account_by_jwk(twin_jwk)
        assert store.get_account_by_jwk(jwk).id == first.id


class TestLegacyAccountsAreNormalizedOnUpgrade:
    """Strictness alone would have broken every account already on record.

    A stored non-canonical JWK is rebuilt into a key on every authenticated
    request, so the migration has to re-spell it rather than reject it.
    """

    def _write_legacy_account(self, db_path: Path, jwk: dict[str, Any]) -> str:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO accounts (id, status, jwk_json, eab_kid, contact, "
                "created_at, jwk_thumbprint) VALUES (?, 'valid', ?, 'kid-001-0123456789abcdef', "
                "'[]', '2026-08-18T00:00:00+00:00', ?)",
                ("acct-legacy", json.dumps(jwk), "legacy-thumbprint"),
            )
        return "acct-legacy"

    def test_a_padded_legacy_jwk_is_re_encoded_in_place(self, tmp_path: Path) -> None:
        db_path = tmp_path / "ra.db"
        Store(db_path)
        jwk = _real_rsa_jwk()
        legacy = {**jwk, "n": jwk["n"] + "=", "e": _b64u(b"\x00\x01\x00\x01")}
        account_id = self._write_legacy_account(db_path, legacy)

        reopened = Store(db_path)
        account = reopened.get_account(account_id)
        assert account is not None
        # Same key, canonical spelling, and the identity now matches what a
        # fresh registration of that key would produce.
        assert json.loads(account.jwk_json) == jwk
        assert reopened.get_account_by_jwk(jwk).id == account_id

    def test_an_already_canonical_jwk_is_left_alone(self, tmp_path: Path) -> None:
        db_path = tmp_path / "ra.db"
        store = Store(db_path)
        jwk = _real_rsa_jwk()
        created = store.create_account(jwk=jwk, eab_kid="kid-001-0123456789abcdef")
        before = store.get_account(created.id).jwk_json

        reopened = Store(db_path)
        assert reopened.get_account(created.id).jwk_json == before

    def test_canonicalize_is_idempotent(self) -> None:
        jwk = _real_rsa_jwk()
        once = canonicalize_jwk(jwk)
        assert canonicalize_jwk(once) == once == jwk
