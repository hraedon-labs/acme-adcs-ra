"""Independent CRL evidence for CA-side revocation confirmations.

The RA holds no CA rights, so it cannot ask the CA "did you revoke this?".
That is why the WI-024 confirmation callback exists: the CA-side pull agent
runs ``certutil -revoke`` and then tells the RA it succeeded. The RA used to
take that entirely on faith and write ``revocation-ca-confirmed`` — an audit
event asserting an external security event it had not observed.

There is exactly one check available to the RA that does **not** depend on the
calling agent's honesty: the CRL. It is published by the CA, signed by the CA's
own key, and readable without any privilege. If a serial appears on a validly
signed CRL, the certificate really is revoked, no matter what the agent claims.

This module fetches and verifies that evidence. It is deliberately strict:

* the CRL's signature is verified against the **issuing CA certificate taken
  from the certificate's own stored chain** — not against whatever the CRL
  claims about itself, and not against a separately configured trust anchor
  that could drift from the chain the certificate was actually issued under;
* freshness is checked independently of the signature, because a signed CRL
  stays cryptographically valid for ever: ``nextUpdate`` must be present and
  in the future, ``thisUpdate`` must not be in the future, and the document
  must be within an absolute age ceiling. A replayed pre-revocation CRL is
  exactly what an attacker suppressing a revocation would like the RA to keep
  accepting, and ``nextUpdate`` alone is under the CA's control;
* every failure returns "no evidence" rather than raising, so the caller
  decides whether missing evidence is fatal (``require_crl_evidence``) or
  merely downgrades the audit record to ``agent-asserted``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast
from urllib.parse import ParseResult, urljoin, urlparse

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

logger = logging.getLogger("acme_adcs_ra.crl_evidence")

# Tolerance for a CA clock running slightly ahead of the RA's.
_CLOCK_SKEW = timedelta(minutes=5)

# Verification outcomes recorded in the audit trail.
CRL_VERIFIED = "crl-verified"
AGENT_ASSERTED = "agent-asserted"

# Monotonicity verdicts (UNFILED item 23). A CRL is compared against the newest
# document this RA has previously acted on for the same issuing CA.
WATERMARK_FIRST = "first"          # nothing recorded yet: trust on first use
# The default maximum age of a CRL this module will accept as evidence.
#
# It is defined HERE, and `RAConfig.revocation_confirm_crl_max_age_seconds`
# imports it, so the library fallback and the deployment default cannot drift
# apart. They did not disagree before only because every production caller
# passes the config value explicitly -- a script or test that omitted it would
# have silently got a different bound. The reasoning behind the number is on
# the config field.
DEFAULT_CRL_MAX_AGE_SECONDS = 626400

WATERMARK_NEWER = "newer"          # advances the watermark
WATERMARK_EQUAL = "equal"          # the same document, re-served; fine
WATERMARK_OLDER = "older"          # a replay, or a lagging CDP replica
WATERMARK_INDETERMINATE = "indeterminate"  # nothing comparable on either side

# The reason code an RA records when it refuses a regressed CRL.
CRL_EVIDENCE_REGRESSED = "crl-evidence-regressed"

# How many ``Location`` hops a CRL retrieval will follow. A CDP that needs more
# than a couple is misconfigured; the cap is here because the chain is chosen by
# whoever answers the CDP, not by the operator.
_MAX_CRL_REDIRECTS = 4

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class CrlWatermark:
    """The newest CRL this RA has already acted on, for one issuing CA.

    Persisted by the store; passed in here so this module stays a pure
    fetch-and-verify unit with no database dependency.
    """

    issuer_key: str
    crl_number: str | None = None
    this_update: str | None = None


@dataclass(frozen=True)
class CrlEvidence:
    """The result of checking a serial against the CA's published CRL."""

    # True only when a validly signed, in-date CRL lists this serial.
    revoked: bool
    # True when a CRL was fetched and verified, whatever it said about the
    # serial. False means we learned nothing (fetch/parse/signature failure).
    checked: bool
    detail: str
    crl_number: str | None = None
    this_update: str | None = None
    next_update: str | None = None
    # Identity of the CA that signed this CRL: issuer DN *and* SPKI, digested.
    # Only ever set after the signature has verified, so it names a key that
    # really did sign the document (see `_watermark_key`).
    issuer_key: str | None = None
    # How this document compared against the caller's watermark, or None when
    # no comparison was reached (the fetch failed before it, or the caller
    # passed no watermark and monotonicity was not being enforced).
    watermark_verdict: str | None = None
    # True when the check could not start because the certificate's stored
    # chain holds no issuer certificate (UNFILED item 25). Distinguished from
    # every other "no evidence" because it is the one that can NEVER succeed on
    # retry: an unreachable CDP is a bad afternoon, a missing issuer is a
    # permanent wedge that needs a recovery action rather than another attempt.
    issuer_missing: bool = False

    @property
    def verification(self) -> str:
        return CRL_VERIFIED if (self.checked and self.revoked) else AGENT_ASSERTED

    @property
    def regressed(self) -> bool:
        """True when this document is older than one already acted on."""
        return self.watermark_verdict == WATERMARK_OLDER


def _watermark_key(ca_cert: x509.Certificate) -> str:
    """Identity of an issuing CA, for keying its monotonic watermark.

    Both halves are load-bearing:

    * the **issuer DN** alone is not enough, because a CA key rollover keeps
      the DN and changes the key. Two generations would then share a
      watermark, and the older generation's still-valid CRLs — legitimately
      lower-numbered, since CRL Number sequences are per key — would read as
      replays and be refused;
    * the **SPKI** alone is not enough either: it identifies the key but not
      which name it is asserting.

    Not the CDP URL. That is operator configuration and changes for reasons
    that have nothing to do with the CA's identity; keying on it would silently
    reset the control every time a CDP moved.

    Both halves are taken from the CA **certificate**, never from the CRL. A
    CRL's issuer field and a certificate's subject field are supposed to be the
    same name, but they are separately encoded and CAs do not always encode
    them identically (PrintableString vs UTF8String is the usual culprit) — so
    comparing the two, or keying off whichever happened to be at hand, risks a
    watermark that splits in half for one CA. There is nothing to compare here:
    the CRL is bound to this certificate by the signature check.
    """
    spki = ca_cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256()
    digest.update(ca_cert.subject.public_bytes())
    digest.update(b"\x00")
    digest.update(spki)
    return digest.hexdigest()


def compare_to_watermark(
    watermark: CrlWatermark | None,
    *,
    crl_number: str | None,
    this_update: str | None,
) -> str:
    """Compare a freshly verified CRL against the newest one already acted on.

    **CRL Number is preferred over ``thisUpdate``** whenever both documents
    carry one. RFC 5280 §5.2.3 requires the CA to increase it monotonically
    across every CRL it issues, which is exactly the property wanted, and
    unlike a timestamp it is not affected by a CA clock adjustment. When either
    side lacks the extension the comparison falls back to ``thisUpdate``; a
    missing CRL Number is not evidence of tampering, because the extension is
    covered by the CA's signature and cannot be stripped by whoever answers the
    CDP.

    ``WATERMARK_FIRST`` is returned when nothing has been recorded for this CA.
    That is **trust on first use and it protects nothing**: the first document
    seen becomes the baseline, whatever it is. Said plainly here because a
    control that quietly does nothing on first contact is worse than no control
    at all — an operator would reasonably assume it was working.
    """
    if watermark is None:
        return WATERMARK_FIRST
    if crl_number is not None and watermark.crl_number is not None:
        try:
            seen = int(watermark.crl_number)
            served = int(crl_number)
        except ValueError:
            # A watermark that will not parse is corrupt bookkeeping, not
            # evidence about the CA. Fall through to the timestamp.
            pass
        else:
            if served > seen:
                return WATERMARK_NEWER
            return WATERMARK_EQUAL if served == seen else WATERMARK_OLDER
    if this_update is not None and watermark.this_update is not None:
        try:
            seen_at = datetime.fromisoformat(watermark.this_update)
            served_at = datetime.fromisoformat(this_update)
        except ValueError:
            return WATERMARK_INDETERMINATE
        if served_at > seen_at:
            return WATERMARK_NEWER
        return WATERMARK_EQUAL if served_at == seen_at else WATERMARK_OLDER
    return WATERMARK_INDETERMINATE


def _issuing_ca_certificate(
    cert_pem: str, chain_pem: list[str]
) -> x509.Certificate | None:
    """Find the CA certificate that signed *cert_pem*, from its own stored chain.

    The chain is what the CA returned at issuance, so it is the authoritative
    statement of which CA certificate this leaf was issued under.

    **Matching is by signature, not by name.** Selecting the first chain entry
    whose subject equalled the leaf's issuer was wrong in a case ADCS produces
    routinely: a **CA key renewal** keeps the subject DN and changes the key, so
    a chain carrying both generations has two equally good name matches and only
    one of them actually signed this leaf. Picking the wrong one made the CRL
    signature check fail, which withholds evidence — safe, but it presents as an
    unexplained refusal to confirm, and under
    ``require_crl_evidence`` it wedges revocation confirmation entirely.

    ``verify_directly_issued_by`` checks the signature (and the issuer/subject
    correspondence) rather than trusting the name, so the right generation is
    selected even when several share a DN.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except ValueError:
        return None
    for pem in chain_pem:
        # A chain entry may itself hold several concatenated PEM certificates.
        try:
            candidates = x509.load_pem_x509_certificates(pem.encode("utf-8"))
        except ValueError:
            continue
        for candidate in candidates:
            if candidate.subject != leaf.issuer:
                continue
            try:
                leaf.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                # Right name, wrong key — keep looking for the generation that
                # actually signed this leaf.
                continue
            return candidate
    return None


def crl_watermark_key(cert_pem: str, chain_pem: list[str]) -> str | None:
    """The watermark identity of the CA that issued *cert_pem*, or None.

    Derived from the certificate's **stored chain** — what the CA returned at
    issuance — rather than from the fetched CRL. That ordering is the point: it
    lets the caller look up the watermark *before* going to the network, and it
    means the identity being compared against is one the RA already trusts
    rather than one the CDP asserted about itself. The fetched document is then
    bound to that identity by the signature check, which verifies against this
    same certificate's key.
    """
    ca_cert = _issuing_ca_certificate(cert_pem, chain_pem)
    if ca_cert is None:
        return None
    return _watermark_key(ca_cert)


def _abort_transfer(
    response: requests.Response, timed_out: threading.Event
) -> None:
    """Tear the transport down so a worker blocked in ``recv`` returns.

    ``response.close()`` alone is not enough: it releases the connection back
    to the pool and closes the buffered reader, but a thread already parked
    inside a socket read is not woken by that. ``shutdown(SHUT_RDWR)`` on the
    socket itself is — on POSIX the pending ``recv`` returns end-of-stream
    immediately. Reaching the socket means going through urllib3's internals,
    so every step is guarded: failing to abort must never raise into the timer
    thread, where nothing could handle it. The flag is set first so the reader
    reports a deadline rather than a fetch failure either way.

    **Windows needs the close as well, and that is not a detail** (2026-08-18).
    Winsock does not wake a ``recv`` parked in another thread on ``shutdown``;
    only ``closesocket`` does. So on the RA's *production* platform this
    watchdog set its flag and then achieved nothing: the read stayed parked
    until the per-read timeout expired. CI measured a 0.5s total deadline
    overshooting to 8.0s — exactly the per-read bound, i.e. precisely the
    behaviour the watchdog was added to eliminate. The control existed on Linux
    and was absent where the RA actually runs.
    """
    timed_out.set()
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        if sys.platform == "win32":
            # The blocked ``recv`` fails immediately with an OSError once the
            # handle is gone; the reader sees ``timed_out`` set and reports a
            # deadline, so the exact error does not matter.
            with contextlib.suppress(OSError):
                sock.close()
        # Deliberately NOT response.close() here as well. Closing from this
        # thread while the worker is inside ``read1`` frees the file object
        # out from under it, which surfaces as an AttributeError deep in
        # http.client rather than a clean end-of-stream. The shutdown is
        # sufficient on POSIX, and the reader's own ``contextlib.closing``
        # does the closing on the thread that owns the read.
        #
        # Closing the *socket* on POSIX is avoided for a different reason:
        # retiring an fd that another thread is blocked in ``read()`` on
        # invites an fd-reuse race, and ``shutdown`` already works there.
        return
    # No socket to reach (a mock, or urllib3 internals moved): fall back to
    # the blunt instrument, which at least stops a fresh read from starting.
    with contextlib.suppress(Exception):
        response.close()


def _effective_port(parsed: ParseResult) -> int | None:
    """The port a URL actually connects to, filling in the scheme default."""
    if parsed.port is not None:
        return parsed.port
    return _DEFAULT_PORTS.get(parsed.scheme)


def _resolve_addresses(host: str, port: int | None) -> tuple[str, ...]:
    """IP addresses for *host* in resolver order, or empty on failure."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return ()
    return tuple(dict.fromkeys(str(info[4][0]) for info in infos))


class _PinnedAddressAdapter(HTTPAdapter):
    """Connect to a numeric address while authenticating the URL hostname."""

    def __init__(self, address: str, hostname: str) -> None:
        self._address = address
        self._hostname = hostname
        super().__init__()

    def get_connection_with_tls_context(
        self,
        request: requests.PreparedRequest,
        verify: Any,
        proxies: Any = None,
        cert: Any = None,
    ) -> HTTPConnectionPool:
        if not isinstance(request.url, str):  # pragma: no cover - requests prepares str URLs
            raise requests.exceptions.InvalidURL("prepared URL is not text")
        parsed = urlparse(request.url)
        port = _effective_port(parsed)
        if port is None:  # pragma: no cover - caller accepts only http(s)
            raise requests.exceptions.InvalidURL(f"URL has no effective port: {request.url}")
        if parsed.scheme == "https":
            # `host` is the TCP destination. `server_hostname` controls SNI and
            # `assert_hostname` keeps certificate verification bound to the
            # configured hostname rather than to the numeric address.
            return HTTPSConnectionPool(
                self._address,
                port,
                assert_hostname=self._hostname,
                server_hostname=self._hostname,
            )
        return HTTPConnectionPool(self._address, port)


@contextlib.contextmanager
def _open_pinned_response(
    url: str,
    addresses: tuple[str, ...],
    *,
    timeout_seconds: float,
    deadline: float,
    timed_out: threading.Event,
) -> Iterator[requests.Response]:
    """Open *url* against one pre-resolved address, trying each in order."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname is None:  # pragma: no cover - caller validates this
        raise requests.exceptions.InvalidURL(f"URL has no hostname: {url}")

    last_error: requests.RequestException | None = None
    for address in addresses:
        remaining = deadline - time.monotonic()
        if timed_out.is_set() or remaining <= 0:
            raise requests.exceptions.Timeout("CRL retrieval deadline expired")
        adapter = _PinnedAddressAdapter(address, hostname)
        # PreparedRequest does not add Host itself; urllib3 would derive it from
        # the pool's numeric address unless it is explicit here.
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        if parsed.port is not None:
            host_header = f"{host_header}:{parsed.port}"
        request = requests.Request("GET", url, headers={"Host": host_header}).prepare()
        try:
            response = adapter.send(
                request,
                timeout=min(timeout_seconds, remaining),
                stream=True,
                proxies={},
            )
        except requests.RequestException as exc:
            last_error = exc
            adapter.close()
            continue
        try:
            yield response
        finally:
            response.close()
            adapter.close()
        return

    if last_error is not None:
        raise last_error
    raise requests.exceptions.ConnectionError("CRL host resolved to no addresses")


def _vet_redirect(
    location: str,
    current_url: str,
    origin: ParseResult,
) -> tuple[str | None, str]:
    """Resolve a ``Location`` and decide whether it may be followed.

    Returns ``(url, "")`` when the hop is allowed and ``(None, reason)`` when it
    is not.

    The operator picked the configured CDP, so that URL is trusted. A
    ``Location`` header is picked by whoever *answers* that CDP — a hostile or
    on-path CRL server — so following it wherever it points turns the RA into a
    blind SSRF probe against anything its network can reach. The rule is
    therefore: a redirect may change only the **path** of the configured origin,
    plus the one documented http→https upgrade.

    Two ways the first version of this was too loose (2026-08-18 rescan F2):

    * **The port.** It accepted the target scheme's default port as an
      alternative to the origin's, which was meant to allow 80→443 on an upgrade
      but also allowed the reverse move: a CDP configured on
      ``http://host:8080`` could redirect to ``http://host:80``, and
      ``https://host:8443`` to ``https://host:443``. Same host, different port,
      different service — exactly what the check claimed to forbid. The upgrade
      is now spelled out as precisely that one transition.
    Address binding is enforced by the transport, which connects every hop to
    the numeric addresses resolved once at the start of the retrieval. This
    function therefore decides URL authority only and performs no second DNS
    lookup that could race the actual connection.
    """
    target = urljoin(current_url, location)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, f"target is not an http(s) URL with a host: {target!r}"
    origin_host = (origin.hostname or "").lower()
    if parsed.hostname.lower() != origin_host:
        return None, (
            f"target leaves the configured CRL host "
            f"({origin_host!r} -> {parsed.hostname.lower()!r})"
        )
    if origin.scheme == "https" and parsed.scheme == "http":
        return None, "target downgrades https to http"

    origin_port = _effective_port(origin)
    allowed_ports = {origin_port}
    if (
        origin.scheme == "http"
        and parsed.scheme == "https"
        and origin_port == _DEFAULT_PORTS["http"]
    ):
        # The one documented transition: a CDP on plain http's default port
        # redirecting to https on *its* default port. Nothing else.
        allowed_ports.add(_DEFAULT_PORTS["https"])
    port = _effective_port(parsed)
    if port not in allowed_ports:
        return None, (
            f"target changes the port ({origin_port} -> {port}); same host, "
            "different service"
        )

    return target, ""


class _LiveTransfer:
    """The response the deadline watchdog should tear down, if one exists yet.

    The watchdog is armed *before* the first request so that DNS, connect, TLS
    and the status/header exchange count against the total deadline as well —
    previously the clock only started once a final response object was in hand,
    which left everything before that point outside every control the function
    advertises. Each hop registers its response here as soon as it has one.
    """

    def __init__(self) -> None:
        self.response: requests.Response | None = None


def _past_deadline(timed_out: threading.Event, deadline: float) -> bool:
    """Whether a failed retrieval should be reported as a deadline expiry.

    Two mechanisms can terminate a transfer at the deadline and they race
    (2026-08-18 rescan, found on Windows CI):

    * the watchdog tears the socket down and sets *timed_out* — definitive; and
    * the per-hop socket timeout expires on its own, because it is **clamped to
      the wall-clock remaining**. Nothing sets the flag in that case, so the
      outcome used to be reported as a generic "CRL read failed" — which is what
      the flag exists to prevent, and which made the reason nondeterministic
      between platforms. Linux happened to lose the race the other way.

    The clock comparison is exact rather than approximate, and does not need a
    tolerance: the clamped timeout is ``deadline - t0`` for some ``t0`` taken
    before the read begins at ``t1 >= t0``, so it cannot expire before
    ``t1 + (deadline - t0) >= deadline``. When the clamp is *not* what bound the
    read (``timeout_seconds`` was the smaller of the two), expiry says nothing
    about the deadline and the real transport error is reported instead.
    """
    return timed_out.is_set() or time.monotonic() >= deadline


def _abort_live(live: _LiveTransfer, timed_out: threading.Event) -> None:
    """Deadline expiry: flag it, and tear down the transfer if one is up."""
    response = live.response
    if response is None:
        # No response object yet, so there is no socket to reach: requests is
        # still inside its own connect/header read and does not hand back a
        # handle until that completes. Setting the flag is what is available,
        # and every check after that point sees it and bails without reading a
        # byte of body. The residual — a peer that never finishes sending
        # headers — is bounded by the per-read timeout, by http.client's
        # header-size caps, and by the gate's dedicated executor and admission
        # ceiling, which keep it off the issuance path entirely.
        timed_out.set()
        return
    _abort_transfer(response, timed_out)


def fetch_crl_evidence(
    *,
    crl_url: str,
    serial_number: int,
    cert_pem: str,
    chain_pem: list[str],
    timeout_seconds: float = 10.0,
    max_bytes: int = 10 * 1024 * 1024,
    max_age_seconds: int = DEFAULT_CRL_MAX_AGE_SECONDS,
    total_timeout_seconds: float = 30.0,
    follow_redirects: bool = False,
    watermark: CrlWatermark | None = None,
    enforce_monotonic: bool = True,
) -> CrlEvidence:
    """Check whether *serial_number* is on the CA's published CRL.

    Never raises: any failure is reported as ``checked=False`` with a reason.

    ``timeout_seconds`` is what ``requests`` understands: a bound on the
    connect and on each individual socket read. ``total_timeout_seconds`` is
    the wall-clock bound on the whole retrieval, and it is the one that
    matters for availability — a server that emits one byte just before every
    read timeout never trips the per-read bound and can hold the calling
    worker indefinitely (2026-08-16 rescan F4).

    ``follow_redirects`` defaults to **False** (2026-08-18 rescan F2). Every
    redirect is a destination chosen by whoever answers the configured CDP, and
    a CDP that redirects at all is unusual — so the default removes the hop
    rather than policing it. Enabled, hops are held to the configured origin:
    same host, same port (bar one documented http:80 → https:443 upgrade), and
    the host must keep resolving inside the address set seen at the start.

    ``watermark`` is the newest CRL this RA has already acted on for the same
    issuing CA. Supplied, a document that goes *backwards* from it is refused
    as ``crl-evidence-regressed`` rather than believed (UNFILED item 23). This
    is the control that actually defends against replay, and the age ceiling
    never was: a stale CRL that *lacks* the serial already fails closed, so the
    only wrong-*accept* an old CRL can produce is a hold->unhold replay — a
    certificate revoked with reason 6 and later released with reason 8
    (``removeFromCRL``) is still listed as revoked on the older document.

    ``enforce_monotonic=False`` computes and reports the verdict but does not
    refuse on it. That is for an estate whose CDP replicas are known to lag:
    the watermark still advances and the regression is still visible in the
    audit trail, so the operator gets the measurement without the refusal.
    """
    parsed = urlparse(crl_url)
    # A CRL is signed, so plain HTTP is normal and safe for CDPs; anything
    # that is not an HTTP(S) URL (file://, etc.) is not.
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL URL must be http(s) with a host: {crl_url!r}",
        )

    def deadline_evidence(received: int, cause: str | None = None) -> CrlEvidence:
        detail = (
            f"CRL retrieval exceeded its {total_timeout_seconds}s total "
            f"deadline after {received} bytes"
        )
        if cause:
            # Keep the underlying transport error visible: the deadline is the
            # right *reason*, but which mechanism actually tore the transfer
            # down is worth having when diagnosing a CDP.
            detail += f" ({cause})"
        return CrlEvidence(revoked=False, checked=False, detail=detail)

    origin = parsed
    # Resolve once and use those numeric addresses as the actual TCP targets for
    # the initial request and every redirect. A validation-only lookup followed
    # by a hostname request is still DNS-rebindable; an empty pin must fail
    # closed rather than disabling the control.
    pinned_addresses = _resolve_addresses(parsed.hostname, _effective_port(parsed))
    if not pinned_addresses:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL host {parsed.hostname!r} did not resolve to any address",
        )
    deadline = time.monotonic() + total_timeout_seconds
    # Set by the watchdog below, and the reason a torn-down transfer is
    # reported as a deadline rather than as a fetch failure.
    timed_out = threading.Event()
    live = _LiveTransfer()
    # 2026-08-17 F3 established that the deadline needs an enforcer that does
    # not depend on the read loop getting to run: for a **non-chunked,
    # Content-Length** response the underlying read waits for a full 64 KiB, and
    # a peer dribbling a byte every 20ms satisfies each socket read (so the
    # per-read timeout keeps resetting) while never delivering enough to yield a
    # chunk. Shutting the socket down from a timer thread is the only thing that
    # reliably interrupts a blocked read we are not the ones performing.
    #
    # 2026-08-18 F1 moved the arming to *here*, before the first request, rather
    # than after a final response object existed. Connect, TLS and the header
    # exchange are attacker-influenced work too, and a redirect chain used to
    # happen entirely inside `requests.get` — outside this deadline, outside the
    # byte budget, and against destinations nothing had validated.
    watchdog = threading.Timer(
        total_timeout_seconds, _abort_live, args=(live, timed_out)
    )
    watchdog.daemon = True
    watchdog.start()
    body = b""
    url = crl_url
    try:
        for _hop in range(_MAX_CRL_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if timed_out.is_set() or remaining <= 0:
                return deadline_evidence(len(body))
            # allow_redirects=False is the load-bearing part. With the default,
            # requests resolves the whole chain inside this one call: it reads
            # each redirect's body and issues each subsequent request itself,
            # so neither the destination check below nor the byte budget nor
            # the deadline ever saw any of it.
            response_context = _open_pinned_response(
                url,
                pinned_addresses,
                timeout_seconds=timeout_seconds,
                deadline=deadline,
                timed_out=timed_out,
            )
            # Closed on every exit path, including the deadline and size
            # bail-outs: with stream=True the transfer is only actually torn
            # down when the response is closed, so an early `return` that
            # leaked it would keep the socket — and the trickle — alive. It is
            # also what discards a redirect's body unread.
            with response_context as response:
                live.response = response
                if timed_out.is_set():
                    return deadline_evidence(len(body))

                if 300 <= response.status_code < 400:
                    if not follow_redirects:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=(
                                f"CRL fetch returned {response.status_code} and "
                                "redirects are disabled. Point "
                                "revocation_confirm_crl_url at the final CRL URL, "
                                "or set "
                                "revocation_confirm_crl_follow_redirects=true if "
                                "this CDP must redirect."
                            ),
                        )
                    location = response.headers.get("Location")
                    if not location:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=(
                                f"CRL fetch returned {response.status_code} "
                                "with no Location header"
                            ),
                        )
                    target, refusal = _vet_redirect(location, url, origin)
                    if target is None:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=f"CRL fetch refused a redirect: {refusal}",
                        )
                    url = target
                    continue

                response.raise_for_status()

                # ``read1`` returns as soon as the socket has data, rather than
                # waiting to fill a chunk, so the deadline check below also runs
                # once per socket read instead of once per 64 KiB. Belt and
                # braces with the watchdog: this exits cleanly on the common
                # trickle, the watchdog guarantees the pathological one.
                while not timed_out.is_set():
                    chunk = response.raw.read1(65536, decode_content=True)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > max_bytes:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=f"CRL exceeded {max_bytes} bytes",
                        )
                    if time.monotonic() >= deadline:
                        return deadline_evidence(len(body))
                if timed_out.is_set():
                    return deadline_evidence(len(body))
                break
        else:
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=(
                    f"CRL fetch exceeded {_MAX_CRL_REDIRECTS} redirects "
                    f"without reaching a document"
                ),
            )
    except requests.RequestException as exc:
        # A watchdog teardown surfaces here as a broken/incomplete read on a
        # Content-Length response. Report what actually happened.
        if _past_deadline(timed_out, deadline):
            return deadline_evidence(len(body), str(exc))
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL fetch failed: {exc}"
        )
    except Exception as exc:
        # Reading through ``response.raw`` means urllib3's exceptions, not
        # requests' — a transport torn down mid-read surfaces as
        # ``ProtocolError``/``IncompleteRead``, and http.client can contribute
        # its own low-level errors. urllib3 is only a transitive dependency
        # here (via requests), so catching its hierarchy by name would mean
        # importing something this project does not declare. Everything is "no
        # evidence" either way; the caller decides whether that is fatal.
        if _past_deadline(timed_out, deadline):
            return deadline_evidence(len(body), str(exc))
        logger.warning("CRL read failed", exc_info=True)
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL read failed: {exc}"
        )
    finally:
        if watchdog is not None:
            watchdog.cancel()

    crl: x509.CertificateRevocationList | None = None
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            crl = loader(body)
            break
        except ValueError:
            continue
    if crl is None:
        return CrlEvidence(
            revoked=False, checked=False, detail="CRL is neither valid DER nor PEM"
        )

    ca_cert = _issuing_ca_certificate(cert_pem, chain_pem)
    if ca_cert is None:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                "could not locate the issuing CA certificate in the stored "
                "chain, so the CRL signature cannot be verified"
            ),
            issuer_missing=True,
        )
    if not crl.is_signature_valid(ca_cert.public_key()):  # type: ignore[arg-type]
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail="CRL signature does not verify against the certificate's issuer",
        )

    # From here on the document is bound to the CA certificate in the stored
    # chain, so the watermark identity below names the key that demonstrably
    # signed it. Deriving that identity from the CRL instead would let whoever
    # answers the CDP choose which watermark it is compared against — and hand
    # them a way to plant an unreachably high CRL Number under a name of their
    # choosing, wedging every subsequent confirmation.
    issuer_key = _watermark_key(ca_cert)

    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    now = datetime.now(UTC)

    # Freshness, three ways. A signed CRL stays cryptographically valid forever,
    # so signature verification alone says nothing about *when* it was true — an
    # attacker who can replay an old, genuinely-signed CRL could otherwise keep
    # feeding the RA a pre-revocation view indefinitely.
    if next_update is None:
        # Without nextUpdate there is no expiry, so the document would be
        # accepted for ever. ADCS always sets it; a CRL that does not is not
        # something to accept as evidence.
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail="CRL has no nextUpdate, so its freshness cannot be established",
            this_update=this_update.isoformat() if this_update else None,
        )
    if next_update < now:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL expired at {next_update.isoformat()}",
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat(),
        )
    if this_update is not None:
        if this_update > now + _CLOCK_SKEW:
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=f"CRL thisUpdate {this_update.isoformat()} is in the future",
                this_update=this_update.isoformat(),
                next_update=next_update.isoformat(),
            )
        # nextUpdate alone is under the CA's control and can be set arbitrarily
        # far out; an independent ceiling on age bounds how stale a view the RA
        # will act on regardless.
        age = now - this_update
        if age > timedelta(seconds=max_age_seconds):
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=(
                    f"CRL is {int(age.total_seconds())}s old, over the "
                    f"{max_age_seconds}s freshness limit"
                ),
                this_update=this_update.isoformat(),
                next_update=next_update.isoformat(),
            )

    crl_number: str | None = None
    try:
        crl_number = str(
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        pass

    # A delta CRL is not standalone evidence. It carries only the CHANGES since
    # its base CRL, and it is the one document where `removeFromCRL` is allowed
    # to appear (RFC 5280 §5.3.1) — an entry there can mean "this certificate
    # came OFF the revocation list". Treating a delta as a base CRL therefore
    # gets the answer backwards in exactly the case that matters. The RA has no
    # base CRL to apply it to, so it refuses to draw a conclusion.
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        pass
    else:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                "CRL is a delta CRL (DeltaCRLIndicator present); it lists only "
                "changes since a base CRL and cannot prove a serial's current "
                "revocation state. Point revocation_confirm_crl_url at the base CRL."
            ),
            crl_number=crl_number,
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat() if next_update else None,
            issuer_key=issuer_key,
        )

    # Monotonicity (UNFILED item 23). Last of the document-level checks,
    # deliberately: a CRL that already failed freshness or is a delta must not
    # advance anything, and there is no point comparing a document we have
    # refused for another reason.
    verdict = compare_to_watermark(
        watermark, crl_number=crl_number, this_update=this_update.isoformat() if this_update else None
    )
    if verdict == WATERMARK_OLDER and enforce_monotonic:
        # No evidence, not counter-evidence. The RA has learned that its CDP
        # served something older than a document it has already acted on; that
        # says nothing trustworthy about this serial either way, so it refuses
        # to draw a conclusion — which is fail-closed under
        # ``require_crl_evidence`` and an honest `agent-asserted` without it.
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                f"{CRL_EVIDENCE_REGRESSED}: served CRL "
                f"(number={crl_number}, thisUpdate={this_update.isoformat() if this_update else None}) "
                f"is older than the newest already acted on for this CA "
                f"(number={watermark.crl_number if watermark else None}, "
                f"thisUpdate={watermark.this_update if watermark else None})"
            ),
            crl_number=crl_number,
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat() if next_update else None,
            issuer_key=issuer_key,
            watermark_verdict=verdict,
        )

    entry = crl.get_revoked_certificate_by_serial_number(serial_number)

    # Presence on a CRL is not the same as being revoked. `removeFromCRL`
    # (reason 8) means the opposite: a certificate that was on hold has been
    # REINSTATED, and relying parties should stop treating it as revoked. The
    # RA already refuses reason 8 on the ACME revoke route for this reason
    # (2026-08-14 F3); accepting it as *evidence* of revocation is the same
    # defect facing the other way, and it would drain a still-valid certificate
    # off the pending-revocation queue while recording `crl-verified`.
    #
    # This state is reachable in practice, not hypothetically: `certutil
    # -revoke <serial> 8` after a hold is the documented un-hold, and it is how
    # this project's own lab has released test certificates.
    reason: x509.ReasonFlags | None = None
    if entry is not None:
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        except x509.ExtensionNotFound:
            reason = None  # absent reason means unspecified, which IS a revocation

    if entry is not None and reason is x509.ReasonFlags.remove_from_crl:
        return CrlEvidence(
            revoked=False,
            checked=True,
            detail=(
                "serial is listed on the CRL with reason removeFromCRL, which "
                "means the certificate was taken OFF hold and is NOT revoked"
            ),
            crl_number=crl_number,
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat() if next_update else None,
            issuer_key=issuer_key,
            watermark_verdict=verdict,
        )

    return CrlEvidence(
        revoked=entry is not None,
        checked=True,
        detail=(
            f"serial is listed on the CRL (reason={reason.name if reason else 'unspecified'})"
            if entry is not None
            else "serial is NOT listed on the CRL"
        ),
        crl_number=crl_number,
        this_update=this_update.isoformat() if this_update else None,
        next_update=next_update.isoformat() if next_update else None,
        issuer_key=issuer_key,
        watermark_verdict=verdict,
    )


_T = TypeVar("_T")


# Bookkeeping-only: how many loop turns `drain` will yield for before
# giving up. Settled-future callbacks are dispatched one turn later, and
# a callback can settle another future, so a handful of turns is ample.
_DRAIN_MAX_TURNS = 8


class CrlEvidenceGateBusy(Exception):
    """The gate is at its admission ceiling; shed the request, do not queue it.

    Raised rather than returning "no evidence" on purpose. Absent evidence is a
    statement about the CRL, and under ``require_crl_evidence`` it would be
    recorded as one — but being too busy to look says nothing about whether the
    certificate is revoked. The caller turns this into a retryable status.
    """


class CrlEvidenceGate:
    """Run CRL evidence fetches off the shared enrollment worker pool.

    Two separate problems, one owner (2026-08-16 rescan F4):

    *Pool isolation.* ``run_in_threadpool`` hands work to AnyIO's default
    thread limiter — the same finite set of tokens that ``finalize`` uses for
    the synchronous ADCS enrollment call. CRL retrieval is an outbound fetch
    of an operator-configured URL whose duration a third party influences, so
    letting it draw from that pool means a slow CRL host can queue issuance
    behind it. This gate owns a small dedicated executor instead: a stalled
    CRL can exhaust *this* pool, and issuance is unaffected.

    *Single flight.* Confirmations are idempotent but the idempotence check
    (``ca_crl_updated``) only helps once a reconciliation has committed, so N
    concurrent confirmations for one serial all passed the check and all
    fetched. Concurrent callers for the same key now share one retrieval, and
    a flood of confirmations for a single serial costs exactly one fetch.

    *Admission control* (2026-08-17 F3). ``max_workers`` bounds how many
    retrievals *run*, not how many are accepted. ``ThreadPoolExecutor``'s work
    queue is an unbounded ``SimpleQueue``, and every waiting caller also
    retains a suspended request task, so distinct keys arriving faster than
    they complete grow both without limit. ``max_pending`` is the ceiling on
    distinct flights in progress; past it, :meth:`run` raises
    :class:`CrlEvidenceGateBusy` and the caller sheds the request instead of
    queueing it. Callers joining an *existing* flight are never rejected —
    they cost nothing new.

    Cancellation-safe: a caller that disconnects does not cancel the shared
    retrieval out from under the callers still waiting on it.
    """

    def __init__(self, max_workers: int = 2, max_pending: int = 32) -> None:
        self._max_workers = max_workers
        self._max_pending = max_pending
        self._executor: ThreadPoolExecutor | None = None
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._closed = False

    def set_limits(self, *, max_workers: int, max_pending: int) -> None:
        """Size the gate from config, before the pool is first used.

        ``ServerContext`` builds a gate eagerly so a directly-constructed
        context is always usable; ``create_app`` calls this to apply the
        operator's settings. Once the pool exists its size is fixed — resizing
        under live confirmations would be a needless race, and the RA reads
        config once at startup anyway. The admission ceiling is not tied to the
        pool, so it always takes effect.
        """
        self._max_pending = max_pending
        if self._executor is None:
            self._max_workers = max_workers

    @property
    def inflight(self) -> int:
        """Distinct retrievals currently in progress."""
        return len(self._inflight)

    async def drain(self) -> None:
        """Wait until settled flights have actually left the in-flight map.

        ``_clear`` is registered with ``add_done_callback``, which asyncio
        dispatches through ``call_soon`` — one event-loop iteration after the
        future settles, while the awaiting caller resumes as soon as it settles.
        So a caller that has just awaited its own retrieval can still observe it
        counted here. That lag flaked CI on Windows, where the loop happens to
        schedule the resumption first.

        It is not merely cosmetic: ``inflight`` is the ``max_pending`` admission
        signal, so a request arriving inside the window can be shed with 503
        while capacity is in fact free. Yielding once lets every pending
        callback run; the loop re-checks because a callback may itself settle
        another future.

        Bounded so a genuinely busy gate cannot spin here forever — this waits
        for *bookkeeping* to catch up, never for real work to finish.
        """
        for _ in range(_DRAIN_MAX_TURNS):
            done = [f for f in self._inflight.values() if f.done()]
            if not done:
                return
            await asyncio.sleep(0)

    def _pool(self) -> ThreadPoolExecutor:
        # Lazy: an RA with no CRL configured never spawns the threads.
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="ra-crl-evidence",
            )
        return self._executor

    async def run(
        self, key: str, fn: Callable[..., _T], /, *args: Any
    ) -> _T:
        """Run ``fn(*args)`` on the dedicated pool, single-flighted on *key*."""
        if self._closed:
            raise RuntimeError("CrlEvidenceGate is closed")
        pending = self._inflight.get(key)
        # A *finished* entry is not a flight to join. ``add_done_callback`` on
        # a Future is dispatched through ``call_soon``, so between a retrieval
        # completing and its cleanup callback running there is a window in
        # which the key is still mapped to a settled future — and a caller that
        # arrived in that window would be handed the previous fetch's result as
        # if it were fresh. Confirmations are exactly the workload that arrives
        # in bursts, so this is reachable, not theoretical.
        if pending is not None and pending.done():
            self._inflight.pop(key, None)
            pending = None
        if pending is None:
            # Admission control before submission, and only for work that is
            # genuinely new — a caller joining an existing flight adds nothing
            # to shed.
            if len(self._inflight) >= self._max_pending:
                raise CrlEvidenceGateBusy(
                    f"{len(self._inflight)} CRL evidence retrievals already in "
                    f"progress (limit {self._max_pending})"
                )
            pending = asyncio.wrap_future(self._pool().submit(fn, *args))
            self._inflight[key] = pending
            # Clear on completion rather than in a caller's ``finally``: the
            # first caller may be cancelled while later ones still await the
            # same retrieval, and popping the key early would let a third
            # caller start a duplicate fetch. Single-threaded event loop, so
            # no lock is needed around the dict.
            #
            # The identity check is what makes this safe against its own
            # lateness (2026-08-18 F3). ``add_done_callback`` is dispatched
            # through ``call_soon``, so a caller can observe the settled future
            # in the branch above, pop it, and install a *successor* under the
            # same key before this callback ever runs. An unconditional
            # ``pop(key)`` would then evict that live successor: further callers
            # would submit duplicates for a serial already being fetched, and
            # the successor would drop out of the ``max_pending`` accounting
            # while still holding a worker.
            def _clear(finished: asyncio.Future[Any], k: str = key) -> None:
                if self._inflight.get(k) is finished:
                    del self._inflight[k]

            pending.add_done_callback(_clear)
        # shield() so that one caller's cancellation (a client disconnect)
        # leaves the shared retrieval running for the others.
        return cast("_T", await asyncio.shield(pending))

    def close(self) -> None:
        """Stop accepting work and release the threads, if any were started."""
        self._closed = True
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
