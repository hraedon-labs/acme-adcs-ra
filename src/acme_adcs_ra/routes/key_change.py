"""Account-key rollover (RFC 8555 §7.3.5)."""

from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    bad_public_key,
    malformed,
    rate_limited,
    unauthorized,
)
from acme_adcs_ra.app_state import (
    _ACME_PATHS,
    ServerContext,
    _audit,
    authenticate_account,
    emit_audit_hook,
    enforce_account_usable,
    get_context,
)
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    _public_key_from_jwk,
    jwk_thumbprint,
    require_flattened_without_unprotected_header,
    verify_flattened_jws,
)
from acme_adcs_ra.serializers import _account_to_json
from acme_adcs_ra.store import AccountKeyStale, KeyChangeRateLimitExceeded

router = APIRouter()


@router.post(_ACME_PATHS["keyChange"])
async def key_change(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> JSONResponse:
    """Account-key rollover (RFC 8555 §7.3.5).

    The outer JWS is signed by the *old* account key (kid lookup). Its
    payload is the *inner* JWS, signed by the *new* account key (jwk in
    the inner protected header). The inner payload carries the account
    URL and the old key JWK. After validation the account's stored key is
    replaced; the old key is no longer accepted.
    """
    outer_header, outer_payload, account, authenticated_thumbprint = await authenticate_account(
        ctx, request, _ACME_PATHS["keyChange"]
    )
    account_id = account.id

    inner_jws = outer_payload
    if not isinstance(inner_jws, dict) or "protected" not in inner_jws:
        raise malformed("keyChange payload must be an inner JWS object")
    # The nonce/kid refusals below read the protected header only; an
    # unprotected "header" member would otherwise smuggle either past them.
    try:
        require_flattened_without_unprotected_header(inner_jws)
    except JWSValidationError as exc:
        raise malformed(f"inner JWS: {exc}") from exc

    try:
        inner_header = json.loads(_base64url_decode(inner_jws["protected"]))
    except Exception as exc:
        raise malformed(f"invalid inner JWS protected header: {exc}") from exc

    if not isinstance(inner_header, dict):
        raise malformed("inner JWS protected header must be a JSON object")

    new_jwk = inner_header.get("jwk")
    if not isinstance(new_jwk, dict):
        raise malformed("inner JWS protected header missing jwk")

    inner_url = inner_header.get("url")
    if inner_url != outer_header.get("url"):
        raise malformed(
            "inner JWS url does not match outer JWS url (RFC 8555 §7.3.5)"
        )

    # RFC 8555 §7.3.5: "The inner JWS MUST omit the 'nonce' header parameter."
    # Replay protection for the whole request is the OUTER nonce, which
    # authenticate_account has already verified and consumed; the inner JWS is
    # only ever accepted as the payload of that one outer request. This route
    # used to REQUIRE and consume an inner nonce, so every conformant client
    # (which omits it, as the RFC says) failed rollover with badNonce — at the
    # exact moment a key-compromise response needs the endpoint (item 27).
    # A present inner nonce is refused rather than ignored: the RFC says MUST
    # omit, and accepting it would keep the old non-standard dialect alive in
    # the in-repo test client.
    if "nonce" in inner_header:
        raise malformed(
            "inner JWS protected header must omit nonce (RFC 8555 §7.3.5)"
        )
    # The inner JWS is identified by its embedded jwk (the NEW key); jwk and kid
    # are mutually exclusive (RFC 8555 §6.2), and a kid here would name an
    # account rather than the key being proven.
    if "kid" in inner_header:
        raise malformed(
            "inner JWS protected header must use jwk, not kid (RFC 8555 §7.3.5)"
        )

    try:
        new_public_key = _public_key_from_jwk(new_jwk)
    except Exception as exc:
        raise bad_public_key(f"invalid new account JWK: {exc}") from exc

    try:
        inner_payload_bytes = verify_flattened_jws(inner_jws, new_public_key)
    except JWSValidationError as exc:
        raise unauthorized(f"inner JWS verification failed: {exc}") from exc

    try:
        inner_payload = json.loads(inner_payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise malformed(f"inner JWS payload is not valid JSON: {exc}") from exc

    if not isinstance(inner_payload, dict):
        raise malformed("inner JWS payload must be a JSON object")

    inner_account = inner_payload.get("account")
    if inner_account != outer_header.get("kid"):
        raise malformed(
            "inner JWS account does not match outer JWS kid "
            "(RFC 8555 §7.3.5)"
        )

    old_key_jwk = inner_payload.get("oldKey")
    if not isinstance(old_key_jwk, dict):
        raise malformed("inner JWS payload missing oldKey")

    # ``oldKey`` is attacker-supplied and reaches jwk_thumbprint unvalidated —
    # a JWK missing its required members (e.g. {"kty": "RSA"} with no n/e)
    # raises KeyError, and an unknown kty raises UnsupportedAlgorithmError.
    # Both are client errors; without this they surfaced as an unhandled 500
    # with a stack trace instead of a 400.
    try:
        old_key_thumbprint = jwk_thumbprint(old_key_jwk)
    except (KeyError, TypeError, JWSValidationError) as exc:
        raise malformed(f"inner JWS oldKey is not a usable JWK: {exc}") from exc
    if old_key_thumbprint != jwk_thumbprint(json.loads(account.jwk_json)):
        raise unauthorized("oldKey in inner JWS does not match account key")

    # Same treatment as ``oldKey`` above: ``newKey`` is attacker-supplied, and
    # jwk_thumbprint now also refuses non-canonical member encodings (F5), which
    # is a client error rather than a 500.
    try:
        new_key_thumbprint = jwk_thumbprint(new_jwk)
    except (KeyError, TypeError, JWSValidationError) as exc:
        raise malformed(f"inner JWS newKey is not a usable JWK: {exc}") from exc
    if new_key_thumbprint == old_key_thumbprint:
        raise malformed("new key must differ from the current account key")

    existing = ctx.store.get_account_by_jwk(new_jwk)
    if existing is not None:
        raise bad_public_key("new account key is already registered to another account")

    # Key rotation and its audit row commit in ONE transaction (Daybreak
    # 2026-08-15): the ``account-key-changed`` row is the only record naming
    # the new key's thumbprint, and it used to be written after the rotation
    # had already committed. The SIEM fan-out runs after the commit via the
    # returned event, matching finalize and newAccount.
    # 14a: the rollover ceiling is enforced INSIDE that transaction, not by a
    # check here. keyChange was the last authenticated transition with no rate
    # limit at all, and a route-level count-then-rotate would let a parallel
    # burst past the ceiling — with each winner an irreversible key rotation.
    try:
        async with ctx.account_issuance_locks.mutating(account_id):
            current = ctx.store.get_account(account_id)
            if current is None:
                raise AccountKeyStale("account disappeared before rollover")
            enforce_account_usable(ctx, current)
            # Build the whole success response BEFORE the rotation commits,
            # so nothing that can fail runs between the commit and the 200
            # (Daybreak Blue round 6: serialization was still after it).
            success = JSONResponse(content=_account_to_json(ctx, current))
            if jwk_thumbprint(json.loads(current.jwk_json)) != authenticated_thumbprint:
                raise AccountKeyStale("account key changed before rollover")
            event = ctx.store.update_account_key_with_audit(
                account_id,
                new_jwk,
                expected_old_thumbprint=authenticated_thumbprint,
                audit={
                    "event_type": "account-key-changed",
                    "outcome": "success",
                    "details": {
                        "eab_kid": account.eab_kid,
                        "new_key_thumbprint": new_key_thumbprint,
                    },
                },
                rate_limit_window_seconds=ctx.config.rate_limit_window_seconds,
                rate_limit_per_kid=ctx.config.rate_limit_key_changes_per_window,
            )
    except AccountKeyStale as exc:
        _audit(
            ctx,
            event_type="key-change-stale",
            account_id=account_id,
            outcome="denied",
            details={"reason": "account-key-or-status-changed"},
        )
        raise unauthorized(
            "account key or status changed while the key rollover was in progress"
        ) from exc
    except KeyChangeRateLimitExceeded as exc:
        _audit(
            ctx,
            event_type="key-change-rate-limited",
            account_id=account_id,
            outcome="denied",
            details={
                "reason": "per-account-limit",
                "limit": exc.limit,
                "window_seconds": exc.window_seconds,
                "count": exc.count,
                "scope": "per-account",
                "kid": exc.kid,
            },
        )
        raise rate_limited(
            f"key change rate limit exceeded: {exc.count} rollovers in the "
            f"last {exc.window_seconds}s (limit: {exc.limit})",
            retry_after=exc.window_seconds,
        ) from exc
    except sqlite3.IntegrityError as exc:
        # The route-level lookup is only an optimization. A different account
        # can claim the proposed key before this transaction acquires SQLite's
        # writer lock; the UNIQUE index is authoritative and must map to the
        # ACME client error rather than an unhandled 500.
        existing = ctx.store.get_account_by_jwk(new_jwk)
        if existing is not None and existing.id != account_id:
            raise bad_public_key(
                "new account key is already registered to another account"
            ) from exc
        raise
    emit_audit_hook(ctx, event)

    # RFC 8555 §7.3.5 requires only 200 (OK). The body is the account object
    # (status, contact, orders — none changed by a rollover), built above
    # from the record read under the lock, before the commit: a post-commit
    # failure would tell the client "failed" while its old key was already
    # gone (Daybreak Blue rounds 5 and 6). emit_audit_hook swallows errors.
    return success
