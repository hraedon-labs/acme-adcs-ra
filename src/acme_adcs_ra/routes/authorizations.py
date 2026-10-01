"""Authorization retrieval and challenge validation (RFC 8555 §7.5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import malformed, server_internal, unauthorized
from acme_adcs_ra.app_state import (
    ServerContext,
    _audit,
    _url,
    authenticate_account,
    get_context,
)
from acme_adcs_ra.serializers import _authz_to_json, _challenge_to_json
from acme_adcs_ra.store import OrderStatus, _now_iso, is_expired

router = APIRouter()


# The plain unauthenticated GET form was removed in the 2026-08-15 review
# (finding 4); it bypassed account deactivation and EAB-kid eviction. RFC 8555
# §6.3 specifies POST-as-GET, which every conforming client uses. Only the
# account-scoped POST-as-GET form below remains.
@router.post("/acme/authz/{authz_id}")
async def post_authorization(
    authz_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """POST-as-GET the authorization (RFC 8555 §6.3, §7.5).

    Unlike the plain GET above, this is account-scoped: it closes the
    existence oracle for callers who hold the URL but not the account key.
    """
    _header, payload, account, _authenticated_thumbprint = await authenticate_account(
        ctx, request, f"/acme/authz/{authz_id}"
    )
    if payload != {}:
        raise malformed("POST-as-GET requires an empty payload")

    authz = ctx.store.get_authorization(authz_id)
    if authz is None or authz.account_id != account.id:
        raise unauthorized("authorization not found")
    return JSONResponse(content=_authz_to_json(authz))


def _maybe_ready_order(ctx: ServerContext, order_id: str) -> None:
    order = ctx.store.get_order(order_id)
    if order is None:
        return
    # Only a pending order advances to ready. Without this, re-POSTing a
    # challenge on an already valid/processing order would regress it to
    # ready (a state machine regression; finalize's guards prevent a double
    # issue, but the regression is still wrong).
    if order.status != OrderStatus.PENDING:
        return
    # LOW-2: do not advance an already-expired order to 'ready'. The sweep and
    # the finalize path both handle expired orders (finalize rejects with 403
    # orderNotReady and flips to 'invalid'), so a transient 'ready' for an order whose
    # 'expires' is already past serves no client and could only confuse a
    # polling client into a finalize that would correctly reject. Defense in
    # depth, not a state-machine correctness fix.
    if is_expired(order.expires):
        return
    for authz_url in order.authorizations:
        authz_id = authz_url.rsplit("/", 1)[-1]
        authz = ctx.store.get_authorization(authz_id)
        if authz is None or authz.status != "valid":
            return
    # M-2: CAS-guard the pending→ready transition so a concurrent finalize
    # that has already moved the order to 'processing' (or any other state)
    # cannot be clobbered back to 'ready' by this late challenge validation.
    # If the CAS does not apply (returns False), the order is no longer
    # pending — simply return; whatever moved it owns the state.
    ctx.store.transition_pending_to_ready(order_id)


def _up_link(ctx: ServerContext, authz_id: str) -> dict[str, str]:
    """RFC 8555 §7.1: the "up" link relation points a challenge at its
    authorization (§7.5.1). acme-python (certbot) requires it on the challenge
    response and aborts issuance without it ("up" Link header missing) — found
    by the stock-client interop harness (WI-036)."""
    return {"Link": f'<{_url(ctx, f"/acme/authz/{authz_id}")}>;rel="up"'}


@router.post("/acme/challenge/{challenge_id}")
async def post_challenge(
    challenge_id: str,
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    _header, payload, account, _authenticated_thumbprint = await authenticate_account(
        ctx, request, f"/acme/challenge/{challenge_id}"
    )
    account_id = account.id

    challenge = ctx.store.get_challenge(challenge_id)
    if challenge is None:
        raise unauthorized("challenge not found")
    authz = ctx.store.get_authorization(challenge.authz_id)
    if authz is None or authz.account_id != account_id:
        raise unauthorized("challenge does not belong to account")

    # The challenge payload must be an empty object — defense-in-depth:
    # EAB + network allowlist + SAN-scope policy is the trust gate
    # (architecture.md); the payload body is intentionally ignored.
    if payload != {}:
        raise malformed("challenge payload must be an empty object {}")

    # Replay short-circuit (Daybreak round 5): a challenge already ``valid``
    # is a finished, idempotent operation. Re-running the block below on every
    # replay rewrote identical state and emitted a fresh audit row per POST --
    # durable audit growth at the attacker's request rate for an operation
    # that happened once. Return the current object; the original validation
    # keeps its row.
    if challenge.status == "valid":
        return JSONResponse(
            content=_challenge_to_json(challenge), headers=_up_link(ctx, authz.id)
        )

    # ------------------------------------------------------------------
    # Enterprise trust decision point.
    #
    # This RA is gated by External Account Binding (enterprise identity) +
    # network access control + deterministic SAN-scope policy.  Public
    # domain-control proofs (DNS-01 / HTTP-01 against the internet) are
    # explicitly out of scope for this enterprise issuance path.  The
    # challenge object still exists and transitions per RFC 8555 shape so
    # generic ACME clients can drive it; the actual validation is the
    # enterprise authorization already established at account creation.
    #
    # If domain-validation is required later, replace the block below with
    # a real challenge verifier and gate it on policy.
    # ------------------------------------------------------------------
    validated_at = _now_iso()
    ctx.store.update_challenge_status(challenge_id, "valid", validated_at=validated_at)
    ctx.store.update_authorization_status(challenge.authz_id, "valid")

    _maybe_ready_order(ctx, authz.order_id)

    refreshed_challenge = ctx.store.get_challenge(challenge_id)
    if refreshed_challenge is None:
        raise server_internal("challenge disappeared after validation")

    _audit(ctx,
        event_type="challenge-validated",
        account_id=account_id,
        order_id=authz.order_id,
        outcome="success",
        details={"challenge_id": challenge_id, "authz_id": authz.id},
    )
    return JSONResponse(
        content=_challenge_to_json(refreshed_challenge), headers=_up_link(ctx, authz.id)
    )
