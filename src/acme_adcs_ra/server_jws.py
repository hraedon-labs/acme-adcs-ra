"""JWS request verification used by the ACME server routes.

This module only **verifies** signatures; it never signs anything.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from fastapi import Request

from acme_adcs_ra.acme_errors import (
    bad_nonce,
    bad_public_key,
    malformed,
    unauthorized,
)
from acme_adcs_ra.http_body import read_body_limited
from acme_adcs_ra.jws import (
    JWSValidationError,
    _base64url_decode,
    _public_key_from_jwk,
    jwk_thumbprint,
    require_flattened_without_unprotected_header,
    verify_flattened_jws,
)
from acme_adcs_ra.store import Store


def _kid_to_account_id(kid: str, account_url_prefix: str) -> str:
    """Extract the account UUID from a kid (account URL).

    RFC 8555 §6.2.1 requires kid to be the account URL *on this server*. The
    kid must therefore start with this RA's configured account-URL prefix — a
    bare ID, or an account URL naming some other host, is a protocol violation
    and is rejected. Checking against the configured prefix (not whatever host
    the request happened to arrive with) means a kid minted against a
    different deployment cannot be presented here.
    """
    prefix = account_url_prefix.rstrip("/") + "/"
    if not kid.startswith(prefix):
        raise malformed(
            f"kid is not an account URL on this server (expected prefix "
            f"{prefix!r}): {kid!r}"
        )
    return kid[len(prefix):].split("/", 1)[0]


def _verify_url(header: dict[str, Any], expected_url: str) -> None:
    """Ensure the JWS protected-header url matches this endpoint's canonical URL.

    RFC 8555 §6.4 requires full-URL binding (scheme + host + path + query).

    *expected_url* is built from the configured ``base_url``, **not** from the
    inbound request. That distinction is the control: ``request.url`` is
    derived from the client-supplied ``Host`` header (and, behind a proxy, from
    ``X-Forwarded-Proto``), so comparing the two only proves the client is
    consistent with itself. Comparing against the configured URL pins the
    signature to *this* RA, which is what makes a JWS — or an EAB binding —
    minted for another deployment unusable here.
    """
    header_url = header.get("url")
    if not header_url:
        raise malformed("protected header missing url")
    header_parsed = urlparse(str(header_url))
    expected_parsed = urlparse(str(expected_url))

    # The protected-header url MUST be absolute. A relative url would evade
    # the scheme/host comparison below and allow cross-host replay (a stolen
    # JWS replayed against a different host at the same path). RFC 8555 §6.4
    # requires full-URL binding.
    if not header_parsed.scheme or not header_parsed.netloc:
        raise malformed(
            "protected header 'url' must be an absolute URL "
            f"(got {header_url!r})"
        )

    # Scheme + host + path + query must all match (RFC 8555 §6.4).
    if header_parsed.scheme != expected_parsed.scheme:
        raise malformed(
            f"url scheme mismatch: protected header {header_parsed.scheme}, "
            f"expected {expected_parsed.scheme}"
        )
    if header_parsed.netloc != expected_parsed.netloc:
        raise malformed(
            f"url host mismatch: protected header {header_parsed.netloc}, "
            f"expected {expected_parsed.netloc}"
        )
    if header_parsed.path != expected_parsed.path:
        raise malformed(
            f"url path mismatch: protected header {header_parsed.path}, "
            f"expected {expected_parsed.path}"
        )
    if header_parsed.query != expected_parsed.query:
        raise malformed(
            f"url query mismatch: protected header {header_parsed.query!r}, "
            f"expected {expected_parsed.query!r}"
        )


def _consume_nonce(store: Store, header: dict[str, Any], request_url: str) -> None:
    nonce = header.get("nonce")
    if not nonce:
        raise bad_nonce(f"missing Replay-Nonce in protected header for {request_url}")
    # A JSON object or array is truthy, so it passed the check above and reached
    # SQLite parameter binding, raising ProgrammingError — an unauthenticated
    # 500 on every JWS-authenticated route. RFC 8555 §6.5 nonces are strings.
    if not isinstance(nonce, str):
        raise bad_nonce(f"Replay-Nonce must be a string for {request_url}")
    if not store.consume_nonce(nonce):
        raise bad_nonce(f"invalid or replayed Replay-Nonce for {request_url}")


async def _parse_jws_body(
    request: Request, *, max_body_size_bytes: int = 65536
) -> dict[str, Any]:
    body = await read_body_limited(
        request, max_bytes=max_body_size_bytes, what="JWS request"
    )
    if not body:
        raise malformed("empty request body")
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise malformed(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise malformed("request body must be a JSON object")
    return data


async def _parse_jws_header(
    request: Request,
    store: Store,
    *,
    expected_url: str,
    max_body_size_bytes: int = 65536,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the JWS body, decode the protected header, consume the nonce,
    and verify the URL binding.

    Returns (header, jws_dict).
    """
    jws = await _parse_jws_body(
        request, max_body_size_bytes=max_body_size_bytes
    )
    try:
        require_flattened_without_unprotected_header(jws)
    except JWSValidationError as exc:
        raise malformed(str(exc)) from exc
    protected_b64 = jws.get("protected")
    if not isinstance(protected_b64, str):
        raise malformed("JWS missing protected header")
    try:
        header = json.loads(_base64url_decode(protected_b64))
    except Exception as exc:
        raise malformed(f"invalid protected header: {exc}") from exc

    if not isinstance(header, dict):
        raise malformed("JWS protected header must be a JSON object")

    # Consume nonce BEFORE verifying URL so that a bad-URL probe still
    # burns the nonce, limiting replay probing (M6).
    _consume_nonce(store, header, expected_url)
    # Read by the Replay-Nonce middleware in server.py (item 28): a request
    # that spent a nonce is owed one back in its response.
    request.state.acme_nonce_consumed = True
    _verify_url(header, expected_url)

    return header, jws


def _verify_jws_signature(
    jws: dict[str, Any],
    public_key: Any,
) -> dict[str, Any]:
    """Verify the JWS signature and return the parsed payload dict."""
    try:
        payload = verify_flattened_jws(jws, public_key)
    except JWSValidationError as exc:
        raise unauthorized(f"JWS verification failed: {exc}") from exc

    # RFC 8555 §6.3: a POST-as-GET request carries an *empty string* payload,
    # not an empty object. Conforming clients use it for every read of a
    # protected resource (order, authz, cert). Normalizing it to {} here lets
    # routes treat "no payload" uniformly; no route is weakened by it, because
    # every route that needs a payload field checks for that field explicitly.
    if payload == b"":
        return {}

    try:
        decoded_payload = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise malformed(f"JWS payload is not valid JSON: {exc}") from exc

    if not isinstance(decoded_payload, dict):
        raise malformed("JWS payload must be a JSON object")
    return decoded_payload


async def verify_existing_account_jws(
    request: Request,
    store: Store,
    *,
    expected_url: str,
    account_url_prefix: str,
    max_body_size_bytes: int = 65536,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Verify a JWS signed by an existing account (kid lookup).

    Returns (protected_header, payload_dict, account_id, key_thumbprint).  The
    thumbprint is computed from the exact stored JWK used to verify this
    signature; a later account read may already see a concurrently-rotated key.
    """
    header, jws = await _parse_jws_header(
        request,
        store,
        expected_url=expected_url,
        max_body_size_bytes=max_body_size_bytes,
    )

    kid = header.get("kid")
    if not kid:
        raise malformed("protected header missing kid")
    if not isinstance(kid, str):
        raise malformed("protected header kid must be a string")
    if "jwk" in header:
        raise malformed("existing-account JWS must use kid, not jwk")
    account_id = _kid_to_account_id(kid, account_url_prefix)
    account = store.get_account(account_id)
    if account is None:
        raise unauthorized("account not found")

    try:
        authenticated_jwk = json.loads(account.jwk_json)
        public_key = _public_key_from_jwk(authenticated_jwk)
        authenticated_thumbprint = jwk_thumbprint(authenticated_jwk)
    except Exception as exc:
        raise bad_public_key(f"stored account key is invalid: {exc}") from exc

    payload_dict = _verify_jws_signature(jws, public_key)

    return header, payload_dict, account_id, authenticated_thumbprint


async def verify_new_account_jws(
    request: Request,
    store: Store,
    *,
    expected_url: str,
    max_body_size_bytes: int = 65536,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Verify a JWS signed by the new account key (jwk in header).

    Returns (protected_header, payload_dict, account_jwk).
    """
    header, jws = await _parse_jws_header(
        request,
        store,
        expected_url=expected_url,
        max_body_size_bytes=max_body_size_bytes,
    )

    account_jwk = header.get("jwk")
    if not isinstance(account_jwk, dict):
        raise malformed("newAccount JWS protected header missing jwk")
    if "kid" in header:
        raise malformed("newAccount JWS must use jwk, not kid")

    try:
        public_key = _public_key_from_jwk(account_jwk)
    except Exception as exc:
        raise bad_public_key(f"invalid account JWK: {exc}") from exc

    payload_dict = _verify_jws_signature(jws, public_key)

    return header, payload_dict, account_jwk
