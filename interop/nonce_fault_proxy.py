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

        def _relay(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            injected = False
            # Decide corruptibility BEFORE taking an injection slot, so a
            # non-JWS POST can never consume (and waste) the slot.
            poisoned = (
                _corrupt_signature(body)
                if method == "POST"
                and body
                and self.path.startswith("/acme/")
                and not self.path.startswith("/acme/admin/")
                else None
            )
            if poisoned is not None and state.should_inject():
                burn = self._upstream("POST", poisoned)
                burn.read()
                injected = True
                print(f"INJECT {self.path} burned nonce -> {burn.status}", file=log, flush=True)
            resp = self._upstream(method, body)
            payload = resp.read()
            print(
                f"{method} {self.path} ct={self.headers.get('Content-Type')!r} -> "
                f"{resp.status} nonce={'Replay-Nonce' in resp.headers}"
                f"{' (after injection)' if injected else ''} "
                f"{payload[:300]!r}" if resp.status >= 400 else
                f"{method} {self.path} ct={self.headers.get('Content-Type')!r} -> "
                f"{resp.status} nonce={'Replay-Nonce' in resp.headers}"
                f"{' (after injection)' if injected else ''}",
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
