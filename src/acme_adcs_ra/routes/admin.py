"""Administrative routes for the ACME server."""

from __future__ import annotations

import hmac
import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import malformed, not_found, rate_limited, unauthorized
from acme_adcs_ra.app_state import (
    ServerContext,
    _audit,
    _certificate_url,
    emit_audit_hook,
    get_context,
    logger,
)
from acme_adcs_ra.crl_evidence import (
    AGENT_ASSERTED,
    CrlEvidence,
    CrlEvidenceGateBusy,
    CrlWatermark,
    crl_watermark_key,
    fetch_crl_evidence,
)
from acme_adcs_ra.finalize import _refresh_order_or_500
from acme_adcs_ra.http_body import read_body_limited
from acme_adcs_ra.serializers import _order_to_admin_json, _order_to_json
from acme_adcs_ra.store import (
    CertificateRecord,
    CertStatus,
    OrderStatus,
    canonical_serial,
)

router = APIRouter()

# Canonical serials are uppercase hex with no prefix and no leading zeros.
# Checked with a character set rather than a compiled pattern: the no-signing-key
# architecture test bans `compile(...)` anywhere under src/ (dynamic code
# execution), and `re.compile` matches that ban. A set is clearer here anyway.
_HEX_DIGITS = frozenset("0123456789ABCDEF")


def _crl_published_from(raw_body: bytes) -> bool:
    """Decode the confirmation body's one field: did the agent republish?

    An absent, empty, or unparseable body means **no** — the conservative
    answer, since claiming publication that did not happen is the failure mode
    that matters here (it is what `ca_crl_updated` already overclaims).
    """
    if not raw_body:
        return False
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(body, dict) and body.get("crl_published") is True


def _crl_evidence_for(
    ctx: ServerContext, cert: CertificateRecord
) -> CrlEvidence | None:
    """Fetch CRL evidence for a certificate, or None when not configured.

    Never raises: a CRL problem must not become a 500 on the confirm path. The
    caller decides whether absent evidence is fatal.

    Monotonicity (UNFILED item 23) is applied here rather than deeper down
    because it is the layer that has both the store and the network: the
    watermark is read before the fetch — keyed off the certificate's own stored
    chain, so no round trip is needed to learn which CA to look up — and the
    verdict is decided against the document that comes back.

    **A regression is retried exactly once before it is believed.** Round-robin
    CDP replicas at different vintages are the common cause and they are a
    transient, not an attack; refusing on a single sample would make a normal
    load-balanced PKI look compromised. A regression that survives a re-fetch is
    reported, because a CDP that persistently serves backwards is a genuine
    operational fault and silence about it would be the worse failure.

    The retry doubles the worst-case wall time of a confirmation to two full
    ``total_timeout_seconds``. That is bounded and it lands on the CRL gate's
    own worker pool — separate from enrollment's since 2026-08-16 F4 — which
    sheds with 429 rather than queueing, so a CDP that regresses under load
    cannot spread into the issuance path.
    """
    crl_url = ctx.config.revocation_confirm_crl_url
    if not crl_url:
        return None
    try:
        serial_int = int(cert.serial_number or "", 16)
    except ValueError:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"stored serial is not hexadecimal: {cert.serial_number!r}",
        )

    enforce = ctx.config.revocation_confirm_crl_require_monotonic
    # Inside the guard below, not above it. Reading the watermark touches the
    # store, and the contract of this function is that a CRL problem never
    # becomes a 500 on the confirm path — a read that raised here would have
    # been the one uncaught path left.
    watermark: CrlWatermark | None = None

    def fetch() -> CrlEvidence:
        return fetch_crl_evidence(
            crl_url=crl_url,
            serial_number=serial_int,
            cert_pem=cert.cert_pem,
            chain_pem=cert.chain_pem,
            timeout_seconds=ctx.config.revocation_confirm_crl_timeout_seconds,
            max_bytes=ctx.config.revocation_confirm_crl_max_bytes,
            max_age_seconds=ctx.config.revocation_confirm_crl_max_age_seconds,
            total_timeout_seconds=(
                ctx.config.revocation_confirm_crl_total_timeout_seconds
            ),
            follow_redirects=(
                ctx.config.revocation_confirm_crl_follow_redirects
            ),
            watermark=watermark,
            enforce_monotonic=enforce,
        )

    try:
        issuer_key = crl_watermark_key(cert.cert_pem, cert.chain_pem)
        if issuer_key is not None:
            watermark = ctx.store.read_crl_watermark(issuer_key)
        evidence = fetch()
        if evidence.regressed and enforce:
            logger.warning(
                "CRL evidence regressed against the watermark; re-fetching once"
            )
            evidence = fetch()
        return evidence
    except Exception as exc:  # noqa: BLE001 - evidence gathering must never 500
        logger.warning("CRL evidence check failed", exc_info=True)
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL check error: {exc}"
        )


def _bearer_token(request: Request) -> bytes:
    """Return the Bearer credential as the **bytes the client sent**.

    Bytes, not ``str``, because every caller feeds this to
    ``hmac.compare_digest``, which raises ``TypeError`` — not ``False`` — when
    a ``str`` argument carries a non-ASCII character. Starlette decodes inbound
    header bytes as latin-1, so a single byte >= 0x80 anywhere in the
    credential turned all three admin guards into an unhandled 500, at an
    unauthenticated peer's choosing. Failing closed, but not as a 401: no
    audit-legible denial, a traceback per request, and a rejection that costs
    more than an accepted call.

    Same class as the one ``app_state._dummy_hmac`` was fixed for on the EAB
    path; that sweep never reached this surface.

    ``latin-1`` is the exact inverse of Starlette's own header decode, so this
    recovers the bytes that were on the wire rather than a re-interpretation of
    them — which is what a credential comparison should be against. It is total
    over anything Starlette can produce (every codepoint is U+0000..U+00FF);
    the fallback covers a hand-built ``Request`` in a test.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise unauthorized("missing Bearer token")
    token = auth_header.split(" ", 1)[1]
    try:
        return token.encode("latin-1")
    except UnicodeEncodeError:  # pragma: no cover - unreachable via Starlette
        return token.encode("utf-8")


def _configured_token_bytes(configured: str) -> bytes:
    """The configured credential as bytes, for comparison against the wire.

    UTF-8, because that is how the value reached the process: pydantic-settings
    reads ``.env`` as UTF-8 and the environment decodes as UTF-8. Pairing it
    with the latin-1 wire decode above is not a mismatch but the correct round
    trip — a client presenting the operator's credential puts its UTF-8 bytes
    on the wire, and those are the bytes both sides end up holding.

    Encoding is lossless on both sides deliberately. ``errors="replace"`` would
    have removed the crash too, and folded every unencodable character onto
    ``?`` — turning distinct credentials into equal ones. See
    ``test_non_ascii_credential_does_not_become_a_false_accept``.
    """
    return configured.encode("utf-8")


def _require_admin_token(request: Request, ctx: ServerContext) -> None:
    """Verify the Authorization: Bearer <admin_token> header."""
    admin_token = ctx.config.admin_token.get_secret_value()
    if not admin_token:
        raise unauthorized("admin endpoint not configured")
    if not hmac.compare_digest(
        _bearer_token(request), _configured_token_bytes(admin_token)
    ):
        raise unauthorized("invalid admin token")


def _require_revocation_authority(request: Request, ctx: ServerContext) -> None:
    """Accept either the confirm token or the admin token, for revocation reads.

    The pending-revocations list is read-only and revocation-scoped, so the
    confirm credential is sufficient authority for it. Accepting that token
    here is what lets the sync agent run with **only** the confirm token: it
    previously needed the admin token just to read its work list, which also
    handed the revocation host the authority to reclaim a processing order and
    drain the nonce table — powers it has no use for and should not carry.

    The admin token is still accepted, because this is a maintenance read and
    existing ops tooling uses it. Confirming a revocation remains
    confirm-token-only.
    """
    provided = _bearer_token(request)
    confirm_token = ctx.config.revocation_confirm_token.get_secret_value()
    admin_token = ctx.config.admin_token.get_secret_value()
    for candidate in (confirm_token, admin_token):
        if candidate and hmac.compare_digest(
            provided, _configured_token_bytes(candidate)
        ):
            return
    raise unauthorized("invalid admin or revocation confirmation token")


def _require_revocation_confirm_token(request: Request, ctx: ServerContext) -> None:
    """Verify the dedicated revocation-confirmation credential.

    Confirming a CA-side revocation is a different authority from general
    maintenance: it asserts an external security event the RA cannot observe.
    While it shared ``admin_token``, **any** holder of that token — monitoring,
    ops tooling, a stale runbook credential — could mark a still-valid
    certificate as confirmed-revoked, drop it off the retry queue, and leave a
    success audit behind for a revocation that never happened.

    The admin token is deliberately NOT accepted here, and an unset confirm
    token disables the endpoint rather than silently falling back.
    """
    confirm_token = ctx.config.revocation_confirm_token.get_secret_value()
    if not confirm_token:
        raise unauthorized(
            "revocation confirmation is not configured; set "
            "ACME_RA_REVOCATION_CONFIRM_TOKEN (the general admin token is "
            "deliberately not accepted for this endpoint)"
        )
    if not hmac.compare_digest(
        _bearer_token(request), _configured_token_bytes(confirm_token)
    ):
        raise unauthorized("invalid revocation confirmation token")


# Administrative: explicit nonce cleanup endpoint for cron (replaces
# probabilistic GC). Returns count of deleted nonces. Requires Bearer token.
@router.delete("/acme/admin/nonces")
async def cleanup_nonces(
    request: Request, ctx: ServerContext = Depends(get_context)
) -> JSONResponse:
    _require_admin_token(request, ctx)
    deleted = ctx.store.cleanup_expired_nonces()
    # 2026-08-25, found by MEASURING the deployed store rather than reading the
    # code: `admin-nonce-cleanup` and `admin-expired-order-sweep` were 184 rows
    # each out of 722, and `admin-list-pending-revocations` another 199 --
    # 78.5% of the entire audit table was this RA's own maintenance tasks
    # reporting that they had nothing to do. `certificate-issued`, the evidence
    # this system exists to produce, was 11 rows.
    #
    # A sweep that changed nothing is not evidence, and on a deployment that
    # refuses audit pruning it is permanent. A sweep that DID something keeps
    # its row: "these nonces were destroyed" is a real fact about the trail.
    if deleted:
        _audit(ctx,
            event_type="admin-nonce-cleanup",
            outcome="success",
            details={"deleted": deleted},
        )
    return JSONResponse(content={"deleted": deleted})


# Administrative: sweep expired orders to 'invalid' (RFC 8555 §7.1.6).
# Intended for an external cron; expiry is also enforced lazily at finalize.
@router.delete("/acme/admin/expired-orders")
async def sweep_expired_orders(
    request: Request, ctx: ServerContext = Depends(get_context)
) -> JSONResponse:
    _require_admin_token(request, ctx)
    invalidated = ctx.store.sweep_expired_orders()
    # Same rule as the nonce cleanup above: a sweep that invalidated nothing
    # records nothing. See that comment for the measurement behind it.
    if invalidated:
        _audit(ctx,
            event_type="admin-expired-order-sweep",
            outcome="success",
            details={"invalidated": invalidated},
        )
    return JSONResponse(content={"invalidated": invalidated})


# Administrative: reconcile an order wedged in 'processing' after a crash
# mid-enrollment. See Store.transition_processing_to_ready / _to_valid for
# the two-branch recovery and its double-issuance precondition.
@router.post("/acme/admin/orders/{order_id}/reclaim-processing")
async def reclaim_processing_order(
    order_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
    ca_verified_no_issuance: bool = False,
    ca_request_resolved: str = "",
) -> JSONResponse:
    _require_admin_token(request, ctx)
    order = ctx.store.get_order(order_id)
    if order is None:
        # Audit the probe — a stolen admin token enumerating order IDs is a
        # meaningful reconnaissance signal (threat-model §4.A/§4.F). The
        # attacker-chosen id is a bounded sample in details, not the structured
        # order_id column that forms part of the coalescing key.
        _audit(ctx,
            event_type="admin-order-reclaim-not-found",
            outcome="failed",
            details={
                "reason": "order-not-found",
                "reason_code": "order-not-found",
                "sample_order_id": order_id,
            },
        )
        raise not_found("order not found")

    # Idempotent no-op for anything not actually stuck in 'processing'.
    # Audited so a stolen admin token probing many order IDs is visible.
    if order.status != OrderStatus.PROCESSING:
        _audit(ctx,
            event_type="admin-order-reclaim-noop",
            order_id=order_id,
            account_id=order.account_id,
            outcome="noop",
            details={
                "reason": "not-processing",
                "reason_code": "not-processing",
                "order_status": order.status,
            },
        )
        return JSONResponse(content=_order_to_json(order))

    # Authoritative liveness check FIRST. The RA is a single process, and a
    # live enrollment marks its order in this in-memory registry for the whole
    # in-flight interval — the ready→processing CAS, the wait for a threadpool
    # slot, the ADCS call sequence, and the completion that records the
    # certificate (see routes/orders.finalize_order). If an enrollment is in
    # flight for this order, reclaiming it back to `ready` would let the client
    # drive a SECOND CA issuance while the first is still live — the loser then
    # becomes an untracked orphan at the CA. Elapsed time cannot see this; the
    # registry can. Refuse regardless of age.
    if ctx.active_enrollments.is_active(order_id):
        _audit(ctx,
            event_type="admin-order-reclaim-denied",
            order_id=order_id,
            account_id=order.account_id,
            outcome="failed",
            details={
                "reason": "enrollment-in-flight",
                "reason_code": "enrollment-in-flight",
            },
        )
        raise malformed(
            "an enrollment worker for this order is running in this process "
            "right now; reclaim is refused because it would cause double "
            "issuance. Wait for the enrollment to finish or fail."
        )

    # Secondary age floor, defence-in-depth behind the registry. A live worker
    # is already refused above; this additionally refuses a hasty reclaim within
    # the enrollment window even in a (future) multi-process deployment where the
    # registry would not see another process's worker.
    age_seconds = ctx.store.processing_age_seconds(order_id)
    minimum = ctx.config.reclaim_minimum_processing_age_seconds
    if age_seconds is not None and age_seconds < minimum:
        _audit(ctx,
            event_type="admin-order-reclaim-denied",
            order_id=order_id,
            account_id=order.account_id,
            outcome="failed",
            details={
                "reason": "still-within-enrollment-window",
                "reason_code": "still-within-enrollment-window",
                "processing_age_seconds": round(age_seconds, 1),
                "minimum_seconds": minimum,
            },
        )
        raise malformed(
            f"order has only been processing for {age_seconds:.0f}s; an "
            f"enrollment may still be in flight. Reclaim is refused until "
            f"{minimum}s have passed, because reclaiming a live enrollment "
            f"causes double issuance."
        )

    # An accepted-but-undecided CA request outranks every check below, because
    # it is the one state where "no certificate was issued" can be *true right
    # now* and false an hour later (2026-08-18 F4). The operator asserting
    # non-issuance is answering a question about the past; an officer approving
    # ReqID N afterwards makes a live certificate for an order that has since
    # been reopened and re-enrolled. So: name the request, or the order stays
    # shut. The ReqID must match exactly — a bare boolean would let an
    # assertion made about one request discharge a different one.
    pending_req_id = order.pending_ca_request_id
    if pending_req_id and ca_request_resolved != pending_req_id:
        _audit(ctx,
            event_type="admin-order-reclaim-denied",
            order_id=order_id,
            account_id=order.account_id,
            outcome="failed",
            details={
                "reason": "ca-request-pending",
                "reason_code": "ca-request-pending",
                "pending_ca_request_id": pending_req_id,
                "asserted": ca_request_resolved,
            },
        )
        raise malformed(
            f"the CA accepted request ReqID={pending_req_id} for this order and "
            "has not decided it. Reclaiming now lets the client re-enroll while "
            "that request can still be approved into a live certificate — two "
            "certificates for one order. Deny or cancel ReqID "
            f"{pending_req_id} at the CA (certutil -deny -config <CA> "
            f"{pending_req_id}), then retry with "
            f"?ca_request_resolved={pending_req_id}. If it was instead ISSUED, "
            "revoke it at the CA and record it before reclaiming."
        )

    existing_cert = ctx.store.get_certificate_by_order(order_id)
    if existing_cert is not None:
        # Enrollment succeeded but the status flip was missed — close the
        # loop safely (no re-enrollment, no double-issuance). Always allowed:
        # a recorded certificate is authoritative proof issuance happened.
        certificate_url = _certificate_url(ctx, existing_cert.id)
        reclaim_to_url = certificate_url
        new_status = OrderStatus.VALID
        had_certificate = True
    else:
        # No cert recorded. This is the dangerous branch: reclaiming to `ready`
        # lets the client re-enroll, and the *absence* of a cert row does NOT
        # prove the CA did not issue — the wedged order may have crashed after
        # the CA committed but before the row was written. Elapsed time cannot
        # prove non-issuance either. Require the operator to explicitly assert
        # they have reconciled against the ADCS CA database that no certificate
        # exists for this order; without that assertion, refuse rather than
        # silently trust time.
        if not ca_verified_no_issuance:
            _audit(ctx,
                event_type="admin-order-reclaim-denied",
                order_id=order_id,
                account_id=order.account_id,
                outcome="failed",
                details={
                    "reason": "ca-verification-not-asserted",
                    "reason_code": "ca-verification-not-asserted",
                },
            )
            raise malformed(
                "reclaiming this order to 'ready' lets the client re-enroll. "
                "No certificate row exists, but that does not prove the CA did "
                "not issue one (a crash after the CA committed leaves exactly "
                "this state), and elapsed time proves nothing. Retry with "
                "?ca_verified_no_issuance=true only after confirming at the "
                "ADCS CA database that no certificate was issued for this order."
            )
        # Scoped to the lease generation this decision was made against. The
        # liveness check, the CA-verification assertion, and the age floor were
        # all evaluated against the order as read at the top of this handler;
        # if its lease has moved since, every one of those judgements is stale
        # and the CAS must lose rather than reopen an order that is now in
        # flight under a different enrollment.
        reclaim_to_url = None
        new_status = OrderStatus.READY
        had_certificate = False

    # One BEGIN IMMEDIATE for the transition, the marker clear and the audit
    # event (2026-08-19 F5). Previously three separate commits, so an
    # interruption could reopen an issuance-path order with the CA-request
    # marker still set, or with no `admin-order-reclaimed` event at all.
    applied, event = ctx.store.reclaim_processing_order(
        order_id,
        to_valid_certificate_url=reclaim_to_url,
        expected_generation=order.processing_generation,
        pending_req_id=pending_req_id or None,
        audit_event_type="admin-order-reclaimed",
        audit_account_id=order.account_id,
        audit_outcome="success",
        audit_details={
            "new_status": new_status,
            "had_certificate": had_certificate,
            "ca_verified_no_issuance": ca_verified_no_issuance,
            "ca_request_resolved": pending_req_id or None,
        },
    )

    if not applied:
        # Lost a race with a concurrent finalize/reclaim; audit + return state.
        refreshed = _refresh_order_or_500(ctx, order_id, "during reclaim")
        _audit(ctx,
            event_type="admin-order-reclaim-denied",
            order_id=order_id,
            account_id=order.account_id,
            outcome="failed",
            details={
                "reason": "lost-race",
                "reason_code": "lost-race",
                "current_status": refreshed.status,
            },
        )
        return JSONResponse(content=_order_to_json(refreshed))

    # The durable write is done and committed as one unit; SIEM fan-out is
    # best-effort and deliberately outside the transaction, as everywhere else.
    if event is not None:
        emit_audit_hook(ctx, event)
    refreshed = _refresh_order_or_500(ctx, order_id, "after reclaim")
    return JSONResponse(content=_order_to_json(refreshed))


# Administrative: list orders by status — primarily for monitoring
# stuck-processing orders (threat-model §4.D: monitor time-in-
# ``processing`` p99). Requires admin token. Returns a minimal admin
# view (no SANs/cert URLs) to limit blast radius of a stolen token.
@router.get("/acme/admin/orders")
async def list_orders(
    request: Request,
    ctx: ServerContext = Depends(get_context),
    status: str = "processing",
    limit: int = 100,
) -> JSONResponse:
    _require_admin_token(request, ctx)
    valid_statuses = {
        OrderStatus.PROCESSING, OrderStatus.VALID, OrderStatus.INVALID,
        OrderStatus.READY, OrderStatus.PENDING, OrderStatus.REVOKED,
    }
    if status not in valid_statuses:
        raise malformed(f"invalid status filter: {status}")
    if not 1 <= limit <= 500:
        raise malformed("limit must be between 1 and 500")
    orders = ctx.store.list_orders_by_status(status, limit=limit)
    _audit(ctx,
        event_type="admin-list-orders",
        outcome="success",
        details={
            "reason_code": "read-only-list",
            "status": status,
            "limit": limit,
            "returned": len(orders),
        },
    )
    return JSONResponse(
        content={"orders": [_order_to_admin_json(o) for o in orders]}
    )


# Administrative: list certificates the RA has marked revoked, for the
# out-of-band CA-side revocation loop (WI-024). Read-only; the CA agent
# pulls this view and runs certutil -revoke against the CA itself.
@router.get("/acme/admin/revocations/pending")
async def list_pending_revocations(
    request: Request,
    ctx: ServerContext = Depends(get_context),
    limit: int = 500,
) -> JSONResponse:
    _require_revocation_authority(request, ctx)
    if not 1 <= limit <= 500:
        raise malformed("limit must be between 1 and 500")
    certs = ctx.store.list_revoked_certificates(limit=limit)
    pending_revocations = []
    for cert in certs:
        if cert.serial_number is None:
            continue
        pending_revocations.append({
            "serial": cert.serial_number,
            "req_id": cert.metadata.get("req_id", ""),
            "reason": cert.revocation_reason,
            "revoked_at": cert.revoked_at,
            # "revoked" = a client asked for it; "quarantined" = the CA issued
            # it and a post-issuance verifier rejected it, so it was never
            # served. Both must come off the CA, but the operator should be
            # able to tell a routine revocation from a template misconfiguration.
            "status": cert.status,
        })
    # 2026-08-25. This route is polled by the revocation sync task on a fixed
    # interval, forever, and every poll used to write a durable row. That grows
    # the audit table without bound in entirely BENIGN operation -- no attacker
    # needed -- and this deployment refuses audit pruning on purpose, so nothing
    # ever reclaims it.
    #
    # An empty list is the steady state and reports nothing an investigator can
    # use, so it gets no row. A poll that actually returns work still does,
    # because "the revocation host was handed these serials" is the audit trail
    # for what happens next. The event is also coalesced, which bounds the case
    # this skip cannot: a token holder polling a NON-empty list at line rate.
    if pending_revocations:
        _audit(ctx,
            event_type="admin-list-pending-revocations",
            outcome="success",
            details={
                "returned": len(pending_revocations),
                "reason_code": "pending-revocations-listed",
            },
        )
    return JSONResponse(content={"pending_revocations": pending_revocations})


# Administrative: confirm that the CA-side CRL was written for a serial the
# RA had marked revoked (WI-024 callback). The pull agent calls this after a
# successful certutil -revoke so the RA flips ca_crl_updated=1 and the serial
# drops out of the pending set on the next pull. Idempotent: a repeat call for
# an already-confirmed serial returns 200 without a new audit event.
@router.post("/acme/admin/revocations/{serial}/confirm")
async def confirm_ca_revocation(
    serial: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    _require_revocation_confirm_token(request, ctx)

    # Read the body FIRST, bounded (2026-08-17 F2). It carries one boolean, and
    # it used to be decoded with `request.json()` — which buffers the whole
    # body — after the CRL fetch had already been paid for. Bounded and up
    # front: the cheapest rejection, before any external work.
    crl_published = _crl_published_from(
        await read_body_limited(
            request,
            max_bytes=ctx.config.max_admin_body_size_bytes,
            what="confirmation request",
        )
    )

    # Canonicalize BEFORE anything keys off the serial (2026-08-17 F3). The
    # store canonicalizes inside its lookup, so `A`, `0A` and `00A` all select
    # the same row — but the route kept its own half-normalized spelling
    # (uppercase, `0x` stripped, leading zeros NOT stripped) and used that as
    # the single-flight key, so the aliases of one certificate each started a
    # separate CRL retrieval. Same normalization as the store, one spelling
    # from here on, and it is the form that reaches the audit trail too.
    serial_upper = canonical_serial(serial)
    if not serial.strip():
        raise malformed("serial must not be empty")
    # Hex-validate rather than pass arbitrary path text into audit details and
    # `int(..., 16)` further down.
    if not set(serial_upper) <= _HEX_DIGITS:
        raise malformed("serial must be hexadecimal")
    cert = ctx.store.get_certificate_by_serial(serial_upper)
    if cert is None:
        # The serial is attacker-chosen and stays in `details` for the
        # investigator, but `reason_code` is what keys the coalescing window --
        # otherwise one character of variance per probe mints a durable row
        # apiece, which is the bound-defeating move audit_coalesce exists to
        # stop. The coalesced row names the window's FIRST serial; the count
        # stays exact.
        _audit(ctx,
            event_type="admin-revocation-confirm-denied",
            outcome="failed",
            details={
                "serial": serial_upper,
                "reason": "not-found",
                "reason_code": "not-found",
            },
        )
        raise not_found("certificate not found in RA store")
    if cert.status not in (CertStatus.REVOKED, CertStatus.QUARANTINED):
        _audit(ctx,
            event_type="admin-revocation-confirm-denied",
            outcome="failed",
            details={
                "serial": serial_upper,
                "reason": "not-revoked",
                "reason_code": "not-revoked",
                "cert_status": cert.status,
            },
        )
        raise malformed("certificate is not revoked in the RA store")

    # Idempotence BEFORE any external I/O. A repeat confirmation for a serial
    # that is already reconciled has nothing to learn from the CRL, and fetching
    # anyway turned a retry loop on the revocation host into repeated outbound
    # requests on the issuance path.
    if cert.ca_crl_updated:
        return JSONResponse(content={
            "serial": serial_upper,
            "ca_crl_updated": True,
            "verification": AGENT_ASSERTED,
        })

    # Independent evidence, where the operator has configured it. The RA cannot
    # ask the CA whether it revoked something, but a CRL is signed by the CA and
    # readable by anyone — it is the one check that does not rest on the calling
    # agent's honesty.
    #
    # On a worker thread, never inline. This handler is `async def`, so FastAPI
    # runs it ON the event loop, and the evidence check is a synchronous
    # `requests` fetch of an operator-configured URL followed by signature and
    # parse work. Called inline, a slow or trickling CRL endpoint stalled every
    # other request in the process for the whole timeout — the same
    # single-process event-loop starvation the enrollment leg was moved off the
    # loop to avoid, on a path that had been missed.
    #
    # On the RA's OWN worker pool, not Starlette's. `run_in_threadpool` draws
    # from the same AnyIO limiter that ADCS enrollment uses, so moving the
    # fetch off the event loop only relocated the contention: enough slow CRL
    # fetches in flight and issuance queues behind them (2026-08-16 rescan F4).
    # The gate also single-flights, so a flood of confirmations for one
    # certificate costs one retrieval rather than one per request, and sheds
    # rather than queues once too many distinct retrievals are in progress.
    #
    # Keyed by the certificate ROW ID, not by the serial. The row is what the
    # retrieval is actually about, and an id cannot be spelled two ways — which
    # is the failure the canonicalization above also closes, belt and braces
    # (2026-08-17 F3).
    try:
        evidence = await ctx.crl_evidence_gate.run(
            cert.id, _crl_evidence_for, ctx, cert
        )
    except CrlEvidenceGateBusy as exc:
        # Not "no evidence" — being too busy to look says nothing about the
        # certificate, and recording it as absent evidence would be a false
        # statement in the audit trail. Shed, and let the agent retry: the
        # serial stays pending, so the next sweep picks it up.
        _audit(ctx,
            event_type="admin-revocation-confirm-deferred",
            account_id=cert.account_id,
            order_id=cert.order_id,
            outcome="failed",
            details={
                "serial": serial_upper,
                "reason": "crl-evidence-capacity",
                "reason_code": "crl-evidence-capacity",
                "detail": str(exc),
            },
        )
        raise rate_limited(
            f"too many CRL evidence retrievals in progress: {exc}",
            retry_after=30,
        ) from exc
    if ctx.config.revocation_confirm_require_crl_evidence and not (
        evidence is not None and evidence.revoked
    ):
        detail = evidence.detail if evidence is not None else "no CRL configured"
        # A regression is a materially different denial from "the CDP was
        # unreachable" or "the serial is not listed": it says the CA's
        # publication point served a document older than one this RA has
        # already acted on. Recording both under one reason code would bury the
        # only signal that distinguishes a replay from a bad afternoon.
        #
        # Two call sites rather than one with a computed reason, and the reason
        # spelled as a literal rather than as `CRL_EVIDENCE_REGRESSED`, because
        # the coalescing key must be provably server-chosen *syntactically*
        # (tests/test_audit_coalescing_enumeration.py). Weakening that check to
        # accept a name would be the fourth call-site patch to the same guard
        # (UNFILED item 13). The literal is pinned to the constant by
        # test_crl_watermark.py, so the two cannot drift apart in silence.
        # `not checked` as well as `regressed`: in advisory mode a regression is
        # recorded but not acted on, so the denial there is about something else
        # (the serial is absent) and blaming the watermark would misdirect
        # whoever reads the trail.
        if evidence is not None and evidence.regressed and not evidence.checked:
            _audit(ctx,
                event_type="admin-revocation-confirm-denied",
                account_id=cert.account_id,
                order_id=cert.order_id,
                outcome="failed",
                details={
                    "serial": serial_upper,
                    "reason": "crl-evidence-regressed",
                    "reason_code": "crl-evidence-regressed",
                    "crl_detail": detail,
                },
            )
        else:
            _audit(ctx,
                event_type="admin-revocation-confirm-denied",
                account_id=cert.account_id,
                order_id=cert.order_id,
                outcome="failed",
                details={
                    "serial": serial_upper,
                    "reason": "crl-evidence-required-but-absent",
                    "reason_code": "crl-evidence-required-but-absent",
                    "crl_detail": detail,
                },
            )
        raise malformed(
            "CRL evidence is required to confirm a CA-side revocation, and the "
            f"CRL does not prove this serial is revoked: {detail}"
        )

    verification = evidence.verification if evidence is not None else AGENT_ASSERTED

    # Whether the agent actually republished the CRL, as opposed to revoking at
    # the CA and leaving publication to the next scheduled run.
    #
    # This matters because the default sync path deliberately passes
    # -SkipPublishCrl: a least-privilege officer cannot republish (that needs
    # Manage-CA). So the common case is "revoked in the CA database, not yet on
    # any published CRL" — during which relying parties still accept the
    # certificate — while the RA drained the serial off its pending list and
    # recorded a field named `ca_crl_updated`. The name overclaims. Recording
    # the distinction is the same honesty fix as `verification`, one layer down.
    # (Decoded from the bounded body read at the top of this handler.)
    details: dict[str, Any] = {
        "serial": serial_upper,
        "certificate_id": cert.id,
        "ca_crl_updated": True,
        "revocation_scope": "ca-crl",
        "prior_status": cert.status,
        # The load-bearing distinction: "crl-verified" means the RA saw the
        # serial on a validly signed, in-date CRL. "agent-asserted" means the
        # RA is recording a claim it could not check — the audit trail must
        # never imply more than that.
        "verification": verification,
        # False means: revoked at the CA, but not yet on a published CRL.
        "crl_published": crl_published,
    }
    if evidence is not None:
        details["crl_detail"] = evidence.detail
        if evidence.crl_number:
            details["crl_number"] = evidence.crl_number
        if evidence.this_update:
            details["crl_this_update"] = evidence.this_update
        if evidence.watermark_verdict:
            # Recorded even when monotonicity is not being enforced: the point
            # of an advisory mode is that the operator can see what a strict
            # one would have refused before they turn it on.
            details["crl_watermark_verdict"] = evidence.watermark_verdict

    # The document this decision was taken on becomes the new floor, in the
    # confirm's own transaction (see Store.confirm_ca_revocation_with_audit).
    # Never backwards: the store's compare-and-set drops an advance that does
    # not move forward, so losing a race with a concurrent confirmation leaves
    # the higher watermark standing.
    watermark_advance: CrlWatermark | None = None
    if (
        evidence is not None
        and evidence.checked
        and evidence.issuer_key
        and evidence.this_update
    ):
        watermark_advance = CrlWatermark(
            issuer_key=evidence.issuer_key,
            crl_number=evidence.crl_number,
            this_update=evidence.this_update,
        )

    # The flag and its audit event commit together (2026-08-18 wave 3 F6).
    # Flipping ca_crl_updated is what removes the serial from
    # `list_revoked_certificates`, so committing it before the audit meant a
    # crash in between dropped the certificate off the retry feed with no
    # `revocation-ca-confirmed` event — and the idempotence check above returns
    # early on that same flag, so no retry could ever repair it.
    flipped, event = ctx.store.confirm_ca_revocation_with_audit(
        serial_upper,
        event_type="revocation-ca-confirmed",
        account_id=cert.account_id,
        order_id=cert.order_id,
        outcome="success",
        details=details,
        watermark_advance=watermark_advance,
        watermark_source_url=ctx.config.revocation_confirm_crl_url or None,
    )
    if not flipped:
        # Lost the race with a concurrent confirmation, which already audited.
        return JSONResponse(content={
            "serial": serial_upper,
            "ca_crl_updated": True,
            "verification": verification,
        })
    # Fan-out only after the write is durable: it is best-effort and must not
    # hold the transaction open.
    if event is not None:
        emit_audit_hook(ctx, event)
    return JSONResponse(content={
        "serial": serial_upper,
        "ca_crl_updated": True,
        "verification": verification,
        "crl_published": crl_published,
    })
