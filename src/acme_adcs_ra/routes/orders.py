"""Order creation (incl. rate limiting) and finalize orchestration (RFC 8555 §7.1, §7.4)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    issuance_halted,
    malformed,
    order_not_ready,
    rate_limited,
    rejected_identifier,
    unauthorized,
    unsupported_identifier,
)
from acme_adcs_ra.app_state import (
    _ACME_PATHS,
    ServerContext,
    _audit,
    _authz_url,
    _challenge_url,
    _finalize_url,
    _order_url,
    authenticate_account,
    get_context,
)
from acme_adcs_ra.enrollment import EnrollmentGateBusy
from acme_adcs_ra.finalize import (
    _finalize_complete,
    _finalize_existing_cert,
    _finalize_expired_order,
    _finalize_parse_and_validate_csr,
    _finalize_submit_enrollment,
    _finalize_transition_to_processing,
)
from acme_adcs_ra.policy import validate_dns_name
from acme_adcs_ra.serializers import _order_to_json
from acme_adcs_ra.store import OrderRateLimitExceeded, OrderStatus

router = APIRouter()


def _check_rate_limit(ctx: ServerContext, account_id: str) -> None:
    """Enforce per-account (per-kid) and global order rate limits.

    WI-016: defense-in-depth that does not depend on the operator's reverse-
    proxy config. On breach, raises ``rateLimited`` (RFC 8555) with a
    ``Retry-After`` header and emits a SIEM-audited denial event. The limit
    is per EAB kid (not per ACME account_id) so a leaked credential cannot
    evade it by creating multiple account keys.
    """
    window = ctx.config.rate_limit_window_seconds
    per_kid_limit = ctx.config.rate_limit_orders_per_window

    if per_kid_limit > 0:
        account = ctx.store.get_account(account_id)
        if account is None:
            raise unauthorized("account not found")
        kid = account.eab_kid
        limit = ctx.config.rate_limit_overrides.get(kid, per_kid_limit)
        if limit > 0:
            count = ctx.store.count_recent_orders_by_kid(kid, window)
            if count >= limit:
                _audit(ctx,
                    event_type="order-rate-limited",
                    account_id=account_id,
                    outcome="denied",
                    details={
                        "reason": "per-account-limit",
                        "limit": limit,
                        "window_seconds": window,
                        "count": count,
                        "scope": "per-account",
                        "kid": kid,
                    },
                )
                raise rate_limited(
                    f"order rate limit exceeded: {count} orders in the last "
                    f"{window}s (limit: {limit})",
                    retry_after=window,
                )

    global_limit = ctx.config.rate_limit_global_per_window
    if global_limit > 0:
        global_count = ctx.store.count_all_recent_orders(window)
        if global_count >= global_limit:
            _audit(ctx,
                event_type="order-rate-limited",
                account_id=account_id,
                outcome="denied",
                details={
                    "reason": "global-limit",
                    "limit": global_limit,
                    "window_seconds": window,
                    "count": global_count,
                    "scope": "global",
                },
            )
            raise rate_limited(
                f"global order rate limit exceeded: {global_count} orders in "
                f"the last {window}s (limit: {global_limit})",
                retry_after=window,
            )


@router.post(_ACME_PATHS["newOrder"])
async def new_order(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    _header, payload, account, _authenticated_thumbprint = await authenticate_account(
        ctx, request, _ACME_PATHS["newOrder"]
    )
    account_id = account.id

    # WI-016: in-app per-account rate limiting (defense-in-depth inside the
    # trust model). The window is computed from order-creation timestamps
    # already in the store — no wall-clock nondeterminism in the tested path.
    # This bounds a leaked EAB credential's cert flood even when no reverse-
    # proxy rate limit is configured or correct.
    _check_rate_limit(ctx, account_id)

    identifiers_raw = payload.get("identifiers")
    if not isinstance(identifiers_raw, list) or not identifiers_raw:
        raise malformed("newOrder payload must contain a non-empty identifiers list")

    # DoS cap: max identifiers per order (threat-model §4.G)
    max_idents = ctx.config.max_identifiers_per_order
    if len(identifiers_raw) > max_idents:
        raise malformed(
            f"too many identifiers in order (max {max_idents}, got {len(identifiers_raw)})"
        )

    identifiers: list[dict[str, str]] = []
    for item in identifiers_raw:
        if not isinstance(item, dict):
            raise malformed("identifier must be an object")
        ident_type = item.get("type")
        value = item.get("value")
        if ident_type != "dns" or not isinstance(value, str) or not value:
            raise unsupported_identifier(
                "only DNS identifiers are supported and value must be non-empty"
            )
        if "*" in value:
            raise rejected_identifier(
                f"wildcard DNS identifiers are not supported: {value!r}"
            )
        try:
            validate_dns_name(value)
        except ValueError as exc:
            raise rejected_identifier(
                f"invalid DNS identifier {value!r}: {exc}"
            ) from exc
        identifiers.append({"type": "dns", "value": value})

    # H5: atomic order creation — all order/authz/challenge rows and URLs
    # are written in a single transaction via Store.create_order_with_authz.
    per_kid_limit = ctx.config.rate_limit_overrides.get(
        account.eab_kid, ctx.config.rate_limit_orders_per_window
    )
    try:
        refreshed_order = ctx.store.create_order_with_authz(
            account_id=account_id,
            identifiers=identifiers,
            challenge_url_fn=lambda cid: _challenge_url(ctx, cid),
            authz_url_fn=lambda aid: _authz_url(ctx, aid),
            finalize_url_fn=lambda oid: _finalize_url(ctx, oid),
            rate_limit_window_seconds=ctx.config.rate_limit_window_seconds,
            rate_limit_per_kid=per_kid_limit,
            rate_limit_global=ctx.config.rate_limit_global_per_window,
        )
    except OrderRateLimitExceeded as exc:
        details = {
            "reason": f"{exc.scope}-limit",
            # The coalescing identity, split out from the prose for the same
            # reason finalize-policy-denied splits it: the key must be a value
            # the server chose. ``scope`` is raised from a closed set of
            # literals in Store.create_order_with_authz, so per-account and
            # global denials keep separate windows without any client-supplied
            # text reaching the key.
            "reason_code": exc.scope,
            "limit": exc.limit,
            "window_seconds": exc.window_seconds,
            "count": exc.count,
            "scope": exc.scope,
        }
        if exc.eab_kid is not None:
            details["kid"] = exc.eab_kid
        _audit(
            ctx,
            event_type="order-rate-limited",
            account_id=account_id,
            outcome="denied",
            details=details,
        )
        raise rate_limited(
            f"{exc.scope} order rate limit exceeded: {exc.count} orders in "
            f"the last {exc.window_seconds}s (limit: {exc.limit})",
            retry_after=exc.window_seconds,
        ) from exc

    _audit(ctx,
        event_type="order-created",
        account_id=account_id,
        order_id=refreshed_order.id,
        sans=[i["value"] for i in identifiers],
        outcome="success",
        details={"identifier_count": len(identifiers)},
    )

    return JSONResponse(
        status_code=201,
        content=_order_to_json(refreshed_order),
        headers={"Location": _order_url(ctx, refreshed_order.id)},
    )


@router.post("/acme/order/{order_id}")
async def get_order(
    order_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """POST-as-GET the order resource (RFC 8555 §7.1.3, §6.3).

    This is the URL handed to the client in newOrder's ``Location`` header and
    the one a conforming client polls after finalize. It previously had no
    handler at all — every poll 404'd, so any client that follows the RFC
    state machine rather than reading finalize's inline response could not
    complete. Account-scoped: another account's order is 404, not 403, so the
    endpoint is not an order-ID oracle.
    """
    _header, payload, account, _authenticated_thumbprint = await authenticate_account(
        ctx, request, f"/acme/order/{order_id}"
    )
    if payload != {}:
        raise malformed("POST-as-GET requires an empty payload")

    order = ctx.store.get_order(order_id)
    if order is None or order.account_id != account.id:
        raise unauthorized("order not found")
    return JSONResponse(content=_order_to_json(order))


@router.post("/acme/finalize/{order_id}")
async def finalize_order(
    order_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    _header, payload, account, authenticated_thumbprint = await authenticate_account(
        ctx, request, f"/acme/finalize/{order_id}"
    )
    account_id = account.id

    order = ctx.store.get_order(order_id)
    if order is None or order.account_id != account_id:
        raise unauthorized("order not found")

    # Idempotent: order already valid.
    if order.status == OrderStatus.VALID:
        return JSONResponse(content=_order_to_json(order))

    # Double-issuance guard: if a cert already exists, return it.
    existing_cert = ctx.store.get_certificate_by_order(order_id)
    if existing_cert is not None:
        return _finalize_existing_cert(ctx, order_id, account_id, existing_cert)

    # Another finalize is mid-enrollment (or crashed). Tell client to poll.
    if order.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(order), headers={"Retry-After": "3"}
        )

    # Expired order: CAS-flip to invalid or return current state.
    expired_resp = _finalize_expired_order(ctx, order_id, account_id, order)
    if expired_resp is not None:
        return expired_resp

    # RFC 8555 §7.4: finalize on a not-ready order MUST be 403 orderNotReady
    # (WI-043; it used to be malformed/400). ``valid`` and ``processing`` are
    # answered above with the current order instead, deliberately: a retried
    # finalize must never read as an error once issuance has happened or is
    # under way, and the double-issuance guard depends on that path.
    if order.status != OrderStatus.READY:
        raise order_not_ready(
            f"order is not ready for finalization (status={order.status}); "
            f"POST-as-GET the order for its current state"
        )

    # Parse CSR, validate SANs, evaluate policy (while still 'ready').
    csr, csr_subject, requested_sans, decision = _finalize_parse_and_validate_csr(
        ctx, payload, order, account_id, order_id
    )

    # Point of no return. Everything from here to the terminal state is one
    # in-flight enrollment, and it is marked as such for its *whole* duration —
    # the CAS, the wait for a threadpool slot, the ADCS call sequence, and the
    # completion that records the certificate. The admin reclaim endpoint
    # refuses any order that is marked, so no part of this interval can be
    # reclaimed out from under us and re-finalized into a second CA issuance.
    #
    # The mark deliberately starts *before* the CAS and the threadpool
    # hand-off. Marking inside the worker (the original shape) meant a task
    # still queued behind a saturated threadpool was invisible: a reclaim could
    # truthfully observe no live worker and no certificate, reopen the order,
    # and let a second finalize race the queued one to the CA. Losing the CAS
    # simply releases the mark on the way out.
    with ctx.active_enrollments.enrolling(order_id):
        transition = _finalize_transition_to_processing(ctx, order_id)
        if isinstance(transition, JSONResponse):
            return transition
        generation = transition

        # Submit to enrollment — on a worker thread, not the event loop.
        #
        # This handler is `async def`, so FastAPI runs it ON the loop rather than
        # in the threadpool it uses for `def` handlers. The enrollment leg is
        # synchronous `requests` against the CA and routinely takes seconds (its
        # own default timeout is 30s). Called inline it stalled every other
        # request in the process for that whole window — new-nonce, revokeCert,
        # the admin endpoints — turning one slow CA into a service-wide outage.
        # The supported deployment is a single process, so there is no second
        # worker to absorb it.
        #
        # The worker re-checks `generation` against the store immediately before
        # it touches ADCS. That is the durable half of the guarantee: the mark
        # above is process-local memory, the lease is a row.
        # Refuse before admitting when a previous issuance was orphaned by an
        # unwritable store (see finalize._emergency_issuance_orphan). Every
        # finalize admitted after that point would issue at the CA and fail to
        # record it the same way, so the second orphan is refused rather than
        # created. One-way until restart, deliberately: this process cannot
        # prove the store became writable again.
        if ctx.issuance_halt:
            raise issuance_halted(
                "issuance is halted: a previous certificate was issued at the "
                "CA and could not be recorded, so the RA is refusing to issue "
                "more until an operator restores the store and restarts. "
                f"Cause: {ctx.issuance_halt.reason}"
            )
        try:
            enrollment_result = await ctx.enrollment_gate.run(
                _finalize_submit_enrollment,
                ctx,
                order_id,
                account_id,
                authenticated_thumbprint,
                requested_sans,
                csr,
                csr_subject,
                decision,
                generation,
            )
        except EnrollmentGateBusy as exc:
            reverted = ctx.store.transition_processing_to_ready(
                order_id, expected_generation=generation
            )
            _audit(
                ctx,
                event_type="finalize-enrollment-admission-denied",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=decision.template,
                outcome="denied",
                # reason_code pins the coalescing key to a server constant.
                # `reason` happens to be a literal today, but the key must not
                # depend on that staying true -- EnrollmentGateBusy carries a
                # message with live counts in it, and one edit putting str(exc)
                # in `reason` would put a varying value back in the key and
                # defeat the bound. See audit_coalesce's reason/reason_code split.
                details={
                    "reason": "enrollment-capacity",
                    "reason_code": "enrollment-capacity",
                    "revert_applied": reverted,
                },
            )
            raise rate_limited(
                f"enrollment capacity is full: {exc}", retry_after=3
            ) from exc
        if isinstance(enrollment_result, JSONResponse):
            return enrollment_result

        # Record cert and transition to valid — still inside the mark, because
        # the CA has issued but the RA has not yet recorded it. A reclaim landing
        # in this window would see no certificate row and could reopen an order
        # the CA has already satisfied.
        return _finalize_complete(
            ctx, order_id, account_id, requested_sans,
            csr_subject, decision, enrollment_result, generation,
        )
