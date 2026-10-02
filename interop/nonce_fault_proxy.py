"""TLS-terminating reverse proxy for the interop harness, with badNonce injection.

HARNESS ONLY. Clients speak HTTPS to this proxy (as they would to IIS in front
of the RA); it forwards plain HTTP to the RA container and copies the response
back verbatim. Every request/response line is logged so a failing run leaves a
transcript of what the *client* actually sent.

``--inject-bad-nonce-every N`` deliberately drives each client through its
badNonce-retry path (RFC 8555 §6.5), which no well-behaved run otherwise
exercises. On every Nth JWS POST the proxy first sends the RA a copy of the
request whose signature has been corrupted. The RA consumes the nonce before it
verifies anything else, so the copy burns the nonce and is refused with 401 —
no resource state changes beyond nonce accounting. The client's genuine
request is then forwarded and meets
``badNonce``; a conformant client retries with the nonce it was handed in that
error response (or a fresh one) and the run must still succeed. The request
immediately after an injection is never injected, so one retry always suffices.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TextIO

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    # The proxy's own BaseHTTPRequestHandler emits these; relaying upstream's
    # too would hand the client duplicated Server/Date headers.
    "server", "date",
}


class _State:
    def __init__(self, every: int) -> None:
        self.every = every
        self.count = 0
        self.last_injected = False
        self.injected = 0
        self.lock = threading.Lock()

    def should_inject(self) -> bool:
        if self.every <= 0:
            return False
        with self.lock:
            if self.last_injected:
                self.last_injected = False
                return False
            self.count += 1
            if self.count % self.every == 0:
                self.last_injected = True
                self.injected += 1
                return True
            return False


def _corrupt_signature(body: bytes) -> bytes | None:
    try:
        jws = json.loads(body)
    except ValueError:
        return None
    if not isinstance(jws, dict) or not isinstance(jws.get("signature"), str):
        return None
    sig = jws["signature"]
    if not sig:
        return None
    jws["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    return json.dumps(jws).encode()


def _jws_identity(body: bytes | None) -> tuple[str, str] | None:
    """Return the protected nonce and a stable hash of the JWS payload member."""
    if body is None:
        return None
    try:
        jws = json.loads(body)
        if not isinstance(jws, dict):
            return None
        protected = jws.get("protected")
        payload = jws.get("payload")
        if not isinstance(protected, str) or not isinstance(payload, str):
            return None
        padding = "=" * (-len(protected) % 4)
        protected_json = base64.urlsafe_b64decode((protected + padding).encode("ascii"))
        header = json.loads(protected_json)
        nonce = header.get("nonce") if isinstance(header, dict) else None
        if not isinstance(nonce, str):
            return None
        payload_hash = hashlib.sha256(payload.encode("ascii")).hexdigest()[:12]
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError, binascii.Error):
        return None
    return nonce, payload_hash


def _problem_type(body: bytes) -> str:
    try:
        problem = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return "-"
    if not isinstance(problem, dict):
        return "-"
    problem_type = problem.get("type")
    return problem_type if isinstance(problem_type, str) else "-"


def make_handler(upstream_host: str, upstream_port: int, state: _State, log: TextIO) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:  # silence default
            return

        def _upstream(self, method: str, body: bytes | None) -> http.client.HTTPResponse:
            conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=60)
            headers = {
                k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP
            }
            conn.request(method, self.path, body=body, headers=headers)
            return conn.getresponse()

        def _read_chunked_body(self) -> bytes:
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline(65537)
                if not line or len(line) > 65536 or not line.endswith(b"\r\n"):
                    raise ValueError("invalid chunk-size line")
                size_text = line[:-2].split(b";", 1)[0].strip()
                try:
                    size = int(size_text, 16)
                except ValueError as exc:
                    raise ValueError("invalid chunk size") from exc
                if size < 0:
                    raise ValueError("invalid chunk size")
                if size == 0:
                    while True:
                        trailer = self.rfile.readline(65537)
                        if not trailer or len(trailer) > 65536:
                            raise ValueError("invalid chunk trailer")
                        if trailer == b"\r\n":
                            return b"".join(chunks)
                chunk = self.rfile.read(size)
                if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                    raise ValueError("truncated chunked body")
                chunks.append(chunk)

        def _request_body(self) -> bytes | None:
            transfer_encoding = self.headers.get("Transfer-Encoding")
            if transfer_encoding is not None:
                encodings = [item.strip().lower() for item in transfer_encoding.split(",")]
                if encodings != ["chunked"]:
                    raise ValueError("unsupported Transfer-Encoding")
                return self._read_chunked_body()
            content_length = self.headers.get("Content-Length")
            if content_length is None:
                return None
            try:
                length = int(content_length)
            except ValueError as exc:
                raise ValueError("invalid Content-Length") from exc
            if length < 0:
                raise ValueError("invalid Content-Length")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("truncated request body")
            return body

        def _reject_bad_body(self, detail: str) -> None:
            payload = f"Bad request body: {detail}\n".encode()
            print(
                f"REJECT method={self.command} path={self.path} -> 400 reason={detail!r}",
                file=log,
                flush=True,
            )
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
            self.close_connection = True

        def _relay(self, method: str) -> None:
            try:
                body = self._request_body()
            except ValueError as exc:
                self._reject_bad_body(str(exc))
                return
            injected = False
            identity = _jws_identity(body) if method == "POST" else None
            identity_log = (
                f"path={self.path} nonce={identity[0]} payload={identity[1]}"
                if identity is not None
                else ""
            )
            # Decide corruptibility BEFORE taking an injection slot, so a
            # non-JWS POST can never consume (and waste) the slot.
            poisoned = (
                _corrupt_signature(body)
                if method == "POST"
                and body
                and identity is not None
                and self.path.startswith("/acme/")
                and not self.path.startswith("/acme/admin/")
                else None
            )
            if poisoned is not None and state.should_inject():
                burn = self._upstream("POST", poisoned)
                burn.read()
                injected = True
                print(f"INJECT {identity_log} -> {burn.status}", file=log, flush=True)
            resp = self._upstream(method, body)
            payload = resp.read()
            jws_log = f" {identity_log}" if identity is not None else ""
            print(
                f"{method} {self.path} ct={self.headers.get('Content-Type')!r}{jws_log} -> "
                f"{resp.status} replay_nonce={'Replay-Nonce' in resp.headers}"
                f"{' (after injection)' if injected else ''} "
                f"{payload[:300]!r}" if resp.status >= 400 else
                f"{method} {self.path} ct={self.headers.get('Content-Type')!r}{jws_log} -> "
                f"{resp.status} replay_nonce={'Replay-Nonce' in resp.headers}"
                f"{' (after injection)' if injected else ''}",
                file=log,
                flush=True,
            )
            # Keep this marker after the ordinary POST line: the next POST to
            # this path in the transcript is then the client's retry, not the
            # genuine request whose refused response this marker describes.
            if injected:
                problem_type = _problem_type(payload) if resp.status >= 400 else "-"
                print(
                    f"AFTER-INJECT {identity_log} -> {resp.status} type={problem_type}",
                    file=log,
                    flush=True,
                )
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in _HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)

        def do_GET(self) -> None:
            self._relay("GET")

        def do_HEAD(self) -> None:
            self._relay("HEAD")

        def do_POST(self) -> None:
            self._relay("POST")

        def do_DELETE(self) -> None:
            self._relay("DELETE")

        def handle(self) -> None:
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError) as exc:
                print(
                    f"CLIENT-DISCONNECT peer={self.client_address[0]} error={type(exc).__name__}",
                    file=log,
                    flush=True,
                )

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, default=443)
    ap.add_argument("--upstream", default="ra:8000")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--inject-bad-nonce-every", type=int, default=0)
    args = ap.parse_args()
    host, _, port = args.upstream.partition(":")
    state = _State(args.inject_bad_nonce_every)
    server = ThreadingHTTPServer(
        ("0.0.0.0", args.listen_port), make_handler(host, int(port or 80), state, sys.stdout)
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"proxy listening :{args.listen_port} -> {args.upstream} "
          f"inject-every={args.inject_bad_nonce_every}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
