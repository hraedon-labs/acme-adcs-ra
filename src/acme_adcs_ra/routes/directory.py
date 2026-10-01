"""Directory and nonce endpoints (RFC 8555 §7.1.1, §7.2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from starlette.concurrency import run_in_threadpool

from acme_adcs_ra.acme_errors import rate_limited
from acme_adcs_ra.app_state import (
    _ACME_PATHS,
    ServerContext,
    _url,
    get_context,
)

router = APIRouter()


@router.get("/directory", response_model=dict)
async def directory(ctx: ServerContext = Depends(get_context)) -> dict[str, Any]:
    meta: dict[str, Any] = {"externalAccountRequired": True}
    if ctx.config.terms_of_service:
        meta["termsOfService"] = ctx.config.terms_of_service
    return {
        "newNonce": _url(ctx, _ACME_PATHS["newNonce"]),
        "newAccount": _url(ctx, _ACME_PATHS["newAccount"]),
        "newOrder": _url(ctx, _ACME_PATHS["newOrder"]),
        "revokeCert": _url(ctx, _ACME_PATHS["revokeCert"]),
        "keyChange": _url(ctx, _ACME_PATHS["keyChange"]),
        "meta": meta,
    }


async def _nonce_response(ctx: ServerContext) -> Response:
    # Bounded BEFORE the SQLite write: an unauthenticated flood must not be
    # able to hold the single writer against the issuance path. Cheap enough
    # that a rejected request costs less than an accepted one.
    bucket = ctx.nonce_bucket
    if bucket is not None and not bucket.take():
        raise rate_limited(
            "nonce request rate limit exceeded",
            retry_after=bucket.retry_after_seconds(),
        )
    # Off the event loop, like the response-time mints in server.py: an INSERT
    # that waits out the busy timeout must not stall every other request
    # (DeepSeek round 4 noted this, the busiest unauthenticated mint, was
    # still on the loop).
    # Unlike the response-time mints in server.py, a failure here is NOT
    # swallowed: a new-nonce response without a nonce is useless, so it fails
    # loud (500) rather than answer 204 with nothing.
    nonce = await run_in_threadpool(ctx.store.create_nonce)
    return Response(
        status_code=204,
        headers={
            "Replay-Nonce": nonce,
            "Cache-Control": "no-store",
        },
    )


@router.head(_ACME_PATHS["newNonce"])
async def new_nonce_head(ctx: ServerContext = Depends(get_context)) -> Response:
    return await _nonce_response(ctx)


@router.get(_ACME_PATHS["newNonce"])
async def new_nonce_get(ctx: ServerContext = Depends(get_context)) -> Response:
    return await _nonce_response(ctx)
