"""Regression tests for the 2026-08-18 rescan of `d26b892`.

Two findings, both defects introduced by the 2026-08-18 fixes themselves:

* F1 (medium) — the legacy JWK canonicalization migration mutated rows before it
  had resolved collisions, so a database holding one key under two encodings
  either crashed startup with an uncaught `IntegrityError` or came up serving
  both rows — preserving the very deactivation bypass the migration existed to
  remove.
* F2 (low) — the CRL redirect origin check accepted the target scheme's default
  port as an alternative to the configured one (so `:8080` → `:80` passed), and
  compared hostname text without binding the resolved address.

Each test here was mutation-checked: the fix was reverted in turn and the test
confirmed to fail. See docs/security-review-2026-08-18-rescan.md.
"""

from __future__ import annotations

import base64
import http.server
import json
import socket
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from acme_adcs_ra.crl_evidence import _vet_redirect, fetch_crl_evidence
from acme_adcs_ra.store import Store, StoreMigrationError


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _real_rsa_jwk() -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa

    numbers = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_numbers()
    )
    return {
        "kty": "RSA",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": "AQAB",
    }


# ---------------------------------------------------------------------------
# Finding 1 (medium) — the twin migration crashed or preserved the bypass
# ---------------------------------------------------------------------------


def _insert_account(
    db_path: Path, account_id: str, jwk: dict[str, Any], thumbprint: str
) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO accounts (id, status, jwk_json, eab_kid, contact, "
            "created_at, jwk_thumbprint) VALUES (?, 'valid', ?, 'kid-001-0123456789abcdef', '[]', "
            "'2026-08-18T00:00:00+00:00', ?)",
            (account_id, json.dumps(jwk), thumbprint),
        )


def _drop_unique_index(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("DROP INDEX IF EXISTS idx_accounts_thumbprint_unique")


def _thumbprints(db_path: Path) -> list[tuple[str, str]]:
    with sqlite3.connect(str(db_path)) as conn:
        return list(conn.execute("SELECT id, jwk_thumbprint FROM accounts"))


class TestTwinMigrationFailsClosed:
    """A duplicate account key is an operator decision, not something to log past.

    The first version canonicalized row by row with only advisory duplicate
    detection. Both outcomes were wrong, and which one you got depended on row
    order and on whether the UNIQUE index already existed.
    """

    def _staged_twin(self, tmp_path: Path, *, canonical_first: bool) -> Path:
        """A database holding one key under two encodings."""
        db_path = tmp_path / "ra.db"
        Store(db_path)  # create the schema
        jwk = _real_rsa_jwk()
        from acme_adcs_ra.jws import jwk_thumbprint

        canonical_tp = jwk_thumbprint(jwk)
        # Same key, non-minimal exponent encoding — accepted by the old lenient
        # decoder, and it hashes to a different thumbprint.
        legacy = {**jwk, "e": _b64u(b"\x00\x01\x00\x01")}

        _drop_unique_index(db_path)
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM accounts")
        if canonical_first:
            _insert_account(db_path, "acct-aaa-canonical", jwk, canonical_tp)
            _insert_account(db_path, "acct-bbb-legacy", legacy, "legacy-thumbprint")
        else:
            _insert_account(db_path, "acct-aaa-legacy", legacy, "legacy-thumbprint")
            _insert_account(db_path, "acct-bbb-canonical", jwk, canonical_tp)
        return db_path

    @pytest.mark.parametrize("canonical_first", [True, False])
    def test_a_staged_twin_refuses_startup_in_either_row_order(
        self, tmp_path: Path, canonical_first: bool
    ) -> None:
        """Row order used to decide crash-vs-fail-open. Now it decides nothing."""
        db_path = self._staged_twin(tmp_path, canonical_first=canonical_first)

        with pytest.raises(StoreMigrationError) as caught:
            Store(db_path)

        message = str(caught.value)
        assert "duplicate account key" in message
        assert "Nothing has been modified" in message

    @pytest.mark.parametrize("canonical_first", [True, False])
    def test_the_refusal_leaves_the_database_untouched(
        self, tmp_path: Path, canonical_first: bool
    ) -> None:
        """Two passes: nothing is written until the whole picture is known.

        The old version mutated as it walked, so a refusal (or a crash) could
        leave the database half-canonicalized.
        """
        db_path = self._staged_twin(tmp_path, canonical_first=canonical_first)
        before = sorted(_thumbprints(db_path))

        with pytest.raises(StoreMigrationError):
            Store(db_path)

        assert sorted(_thumbprints(db_path)) == before

    @pytest.mark.parametrize("canonical_first", [True, False])
    def test_it_never_comes_up_serving_two_rows_for_one_key(
        self, tmp_path: Path, canonical_first: bool
    ) -> None:
        """The fail-open half of the finding, stated as its consequence.

        With the index absent the old migration started fine and left both rows
        holding the same canonical key — so deactivating one did not disable the
        other, which is exactly the bypass F5 closed.
        """
        db_path = self._staged_twin(tmp_path, canonical_first=canonical_first)

        with pytest.raises(StoreMigrationError):
            Store(db_path)

        # And the RA is not serving: no Store instance exists to answer with.
        rows = _thumbprints(db_path)
        canonical = [tp for _id, tp in rows if tp != "legacy-thumbprint"]
        assert len(set(canonical)) == len(canonical), "no duplicate was written"

    def test_a_staged_twin_does_not_raise_integrityerror(self, tmp_path: Path) -> None:
        """Specifically not a raw sqlite3 error escaping Store construction.

        With the UNIQUE index present, rewriting the legacy row to the canonical
        twin's thumbprint raised `UNIQUE constraint failed: accounts.jwk_thumbprint`
        straight out of `__init__` — an uncaught IntegrityError from a migration
        whose job was to repair the database.
        """
        db_path = tmp_path / "ra.db"
        Store(db_path)
        jwk = _real_rsa_jwk()
        from acme_adcs_ra.jws import jwk_thumbprint

        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM accounts")
        # Index left in place this time.
        _insert_account(
            db_path, "acct-aaa-legacy", {**jwk, "e": _b64u(b"\x00\x01\x00\x01")},
            "legacy-thumbprint",
        )
        _insert_account(db_path, "acct-bbb-canonical", jwk, jwk_thumbprint(jwk))

        with pytest.raises(StoreMigrationError):
            Store(db_path)

    def test_a_singleton_legacy_account_is_still_rescued(self, tmp_path: Path) -> None:
        """Fail-closed on twins must not break the ordinary rescue path."""
        db_path = tmp_path / "ra.db"
        Store(db_path)
        jwk = _real_rsa_jwk()
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM accounts")
        legacy = {**jwk, "n": jwk["n"] + "=", "e": _b64u(b"\x00\x01\x00\x01")}
        _insert_account(db_path, "acct-legacy", legacy, "legacy-thumbprint")

        reopened = Store(db_path)
        account = reopened.get_account("acct-legacy")
        assert account is not None
        assert json.loads(account.jwk_json) == jwk
        assert reopened.get_account_by_jwk(jwk).id == "acct-legacy"

    def test_an_unreadable_row_does_not_block_startup(self, tmp_path: Path) -> None:
        """It cannot authenticate either way, so it is inert — loud, not fatal."""
        db_path = tmp_path / "ra.db"
        Store(db_path)
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM accounts")
        _insert_account(db_path, "acct-junk", {"kty": "oct", "k": "nope"}, "junk-tp")

        reopened = Store(db_path)  # must not raise
        assert reopened.get_account("acct-junk") is not None

    def test_a_clean_database_reopens_cleanly_and_repeatedly(
        self, tmp_path: Path
    ) -> None:
        """The invariant check runs on every start; it must be a no-op when clean."""
        db_path = tmp_path / "ra.db"
        store = Store(db_path)
        first = store.create_account(jwk=_real_rsa_jwk(), eab_kid="kid-001-0123456789abcdef")
        second = store.create_account(jwk=_real_rsa_jwk(), eab_kid="kid-002-0123456789abcdef")

        for _ in range(3):
            reopened = Store(db_path)
            assert reopened.get_account(first.id) is not None
            assert reopened.get_account(second.id) is not None


# ---------------------------------------------------------------------------
# Finding 2 (low) — redirect origin checks were incomplete
# ---------------------------------------------------------------------------


class TestRedirectPortRule:
    """Only the path may change, plus one documented scheme upgrade.

    The first version accepted the *target scheme's default port* as an
    alternative to the configured one. That was meant to allow 80→443 on an
    upgrade; it also allowed the reverse move onto a different service.
    """

    def test_a_custom_http_port_cannot_redirect_to_port_80(self) -> None:
        origin = urlparse("http://crl.example:8080/ca.crl")
        target, refusal = _vet_redirect(
            "http://crl.example:80/internal", "http://crl.example:8080/ca.crl", origin
        )
        assert target is None
        assert "changes the port (8080 -> 80)" in refusal

    def test_a_custom_https_port_cannot_redirect_to_port_443(self) -> None:
        origin = urlparse("https://crl.example:8443/ca.crl")
        target, refusal = _vet_redirect(
            "https://crl.example:443/internal",
            "https://crl.example:8443/ca.crl",
            origin,
        )
        assert target is None
        assert "changes the port (8443 -> 443)" in refusal

    def test_the_documented_http_to_https_upgrade_is_still_allowed(self) -> None:
        origin = urlparse("http://crl.example/ca.crl")
        target, refusal = _vet_redirect(
            "https://crl.example/ca.crl", "http://crl.example/ca.crl", origin
        )
        assert target == "https://crl.example/ca.crl", refusal

    def test_the_upgrade_does_not_apply_from_a_custom_port(self) -> None:
        """80→443 is the transition, not 'any http port to 443'."""
        origin = urlparse("http://crl.example:8080/ca.crl")
        target, refusal = _vet_redirect(
            "https://crl.example/ca.crl", "http://crl.example:8080/ca.crl", origin
        )
        assert target is None
        assert "changes the port" in refusal

    def test_a_path_only_redirect_on_a_custom_port_still_works(self) -> None:
        origin = urlparse("http://crl.example:8080/ca.crl")
        target, refusal = _vet_redirect(
            "/latest.crl", "http://crl.example:8080/ca.crl", origin
        )
        assert target == "http://crl.example:8080/latest.crl", refusal


class TestRedirectAddressPinning:
    """Redirect vetting must not perform a second, raceable DNS lookup."""

    def test_a_same_origin_redirect_is_vetted_without_dns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unexpected_lookup(*_args: Any, **_kwargs: Any) -> list[Any]:
            raise AssertionError("redirect vetting must not re-resolve the host")

        monkeypatch.setattr(socket, "getaddrinfo", unexpected_lookup)
        origin = urlparse("http://crl.example/ca.crl")
        target, refusal = _vet_redirect(
            "/latest.crl", "http://crl.example/ca.crl", origin
        )
        assert target == "http://crl.example/latest.crl", refusal


class TestRedirectsAreOffByDefault:
    """The strictest available default: no hop at all unless asked for.

    Every redirect is a destination chosen by whoever answers the CDP, and a CDP
    that redirects is unusual — so the default removes the hop rather than
    trying to police it.
    """

    def _redirecting_server(self) -> tuple[str, Any, list[str]]:
        hits: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                if self.path == "/ca.crl":
                    self.send_response(302)
                    self.send_header("Location", "/real.crl")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"not a crl at all"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return (
            f"http://127.0.0.1:{server.server_address[1]}",
            server.shutdown,
            hits,
        )

    def test_a_redirect_is_not_followed_by_default(self) -> None:
        base, stop, hits = self._redirecting_server()
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{base}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
            )
        finally:
            stop()

        assert evidence.checked is False
        assert "redirects are disabled" in evidence.detail
        # The point: the second request was never made.
        assert hits == ["/ca.crl"]

    def test_the_refusal_names_both_ways_out(self) -> None:
        """An operator hitting this needs to know what to do about it."""
        base, stop, _hits = self._redirecting_server()
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"{base}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
            )
        finally:
            stop()

        assert "revocation_confirm_crl_url" in evidence.detail
        assert "revocation_confirm_crl_follow_redirects" in evidence.detail

    def test_opting_in_restores_the_hop(self) -> None:
        base, stop, hits = self._redirecting_server()
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

        assert hits == ["/ca.crl", "/real.crl"]
        assert "neither valid DER nor PEM" in evidence.detail

    def test_a_non_redirecting_cdp_is_unaffected_by_the_default(self) -> None:
        """The default must not disturb the ordinary case."""
        body = b"not a crl at all"

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
        try:
            evidence = fetch_crl_evidence(
                crl_url=f"http://127.0.0.1:{server.server_address[1]}/ca.crl",
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                total_timeout_seconds=10.0,
            )
        finally:
            server.shutdown()

        assert "neither valid DER nor PEM" in evidence.detail


class TestDeadlineReasonIsPlatformIndependent:
    """Two mechanisms terminate a transfer at the deadline, and they race.

    The watchdog tears the socket down and sets its flag; the per-hop socket
    timeout also expires on its own, because it is clamped to the wall-clock
    remaining. Nothing set the flag in the second case, so the outcome was
    reported as a generic "CRL read failed" — the exact thing the flag exists to
    prevent. Linux happened to win the race with the watchdog and Windows CI did
    not, which is how a green suite hid it.
    """

    def _silent_peer(self) -> tuple[str, Any]:
        """A server that sends headers promising a body, then nothing, ever."""
        stop = threading.Event()
        held: list[socket.socket] = []
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
            except OSError:
                return
            held.append(conn)
            stop.wait(10)

        threading.Thread(target=serve, daemon=True).start()

        def shutdown() -> None:
            stop.set()
            for conn in held:
                try:
                    conn.close()
                except OSError:
                    pass
            try:
                srv.close()
            except OSError:
                pass

        return f"http://127.0.0.1:{srv.getsockname()[1]}/ca.crl", shutdown

    def test_the_clamped_read_timeout_is_still_reported_as_a_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Neutralize the watchdog: the deadline must still be the stated reason.

        This is the Windows condition made deterministic. With `_abort_live`
        doing nothing, the only thing that ends the read is the socket timeout
        clamped to the remaining wall clock — and the reported reason must not
        depend on which of the two got there first.
        """
        import acme_adcs_ra.crl_evidence as mod

        monkeypatch.setattr(mod, "_abort_live", lambda *_args, **_kwargs: None)
        url, stop = self._silent_peer()
        try:
            evidence = fetch_crl_evidence(
                crl_url=url,
                serial_number=0x1234,
                cert_pem="",
                chain_pem=[],
                timeout_seconds=8.0,
                total_timeout_seconds=0.5,
            )
        finally:
            stop()

        assert evidence.checked is False
        assert "total deadline" in evidence.detail
        # The underlying transport error is kept, not discarded.
        assert "timed out" in evidence.detail.lower()

    def test_a_genuine_error_before_the_deadline_keeps_its_own_reason(self) -> None:
        """The deadline must not become a catch-all that swallows real errors."""
        # Nothing listening: connection refused, immediately, well inside the
        # generous deadline.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        evidence = fetch_crl_evidence(
            crl_url=f"http://127.0.0.1:{port}/ca.crl",
            serial_number=0x1234,
            cert_pem="",
            chain_pem=[],
            timeout_seconds=5.0,
            total_timeout_seconds=30.0,
        )

        assert evidence.checked is False
        assert "total deadline" not in evidence.detail
        assert "CRL fetch failed" in evidence.detail


def test_the_config_default_is_off() -> None:
    """Strict by default, per the standing project preference."""
    from acme_adcs_ra.config import RAConfig

    assert RAConfig().revocation_confirm_crl_follow_redirects is False
