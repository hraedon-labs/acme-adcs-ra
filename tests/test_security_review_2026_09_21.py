"""Regression tests for the 2026-09-21 security review findings.

Each test here was written against a *reproduced* defect: the behaviour it
asserts is the one that was missing, and every test in this file was confirmed
to fail against the pre-fix code.

Finding 1 — a non-ASCII ``Authorization`` header 500'd every admin endpoint.
``hmac.compare_digest`` raises ``TypeError`` (not ``False``) when handed a
``str`` carrying a non-ASCII character, and Starlette decodes inbound header
bytes as latin-1. So any byte >= 0x80 in the credential reached the comparison
as a non-ASCII ``str`` and became an unhandled 500, at an unauthenticated
peer's choosing, on all three admin guards.

This is the same bug class ``app_state._dummy_hmac`` was fixed for on the EAB
path (see test_security_review_2026_08_13.py's non-ASCII EAB payload test).
That sweep never reached the admin header surface.
"""

from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.routes.admin import _bearer_token, _configured_token_bytes
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

STRONG_ADMIN_TOKEN = "test-admin-token-0123456789abcdef-32+"
STRONG_CONFIRM_TOKEN = "test-confirm-token-0123456789abcdef-32+"


def _client(tmp_path: Path, **overrides: Any) -> TestClient:
    overrides.setdefault("base_url", "http://testserver")
    overrides.setdefault("admin_token", SecretStr(STRONG_ADMIN_TOKEN))
    overrides.setdefault(
        "revocation_confirm_token", SecretStr(STRONG_CONFIRM_TOKEN)
    )
    cfg = RAConfig(
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        **overrides,
    )
    ctx = ServerContext(
        config=cfg,
        store=Store(cfg.db_path),
        policy=IssuancePolicy(allowed_kids=set(), san_scopes={}),
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(ctx), raise_server_exceptions=False)


# Every admin endpoint, one per guard path:
#   _require_admin_token           -- nonces, expired-orders, reclaim, orders
#   _require_revocation_authority  -- revocations/pending
#   _require_revocation_confirm_token -- revocations/<serial>/confirm
#
# The serial and order id below are deliberately well-formed: the guard runs
# before any lookup, so a 404 here would mean the credential was ACCEPTED.
_ADMIN_ENDPOINTS: list[tuple[str, str]] = [
    ("DELETE", "/acme/admin/nonces"),
    ("DELETE", "/acme/admin/expired-orders"),
    ("POST", "/acme/admin/orders/order-abc/reclaim-processing"),
    ("GET", "/acme/admin/orders"),
    ("GET", "/acme/admin/revocations/pending"),
    ("POST", "/acme/admin/revocations/0A1B/confirm"),
]

# Header values are passed as BYTES. httpx refuses to encode a non-ASCII *str*
# into a header at all, which is part of why the existing suite never reached
# this defect -- on the wire a credential is just bytes.
#
# Note what httpx still does to the bytes you hand it: it re-encodes them as
# UTF-8, so `b"caf\xe9"` is delivered to the app as `b"caf\xc3\xa9"`. That is
# harmless here -- these cases only need *some* non-ASCII byte to reach the
# guard, and one does either way -- but it means TestClient cannot distinguish
# two byte spellings of the same characters. The test that must distinguish
# them builds the ASGI scope directly; see
# _request_with_raw_authorization below.
_REJECTED_CREDENTIALS: list[tuple[str, bytes]] = [
    ("wrong-ascii", b"Bearer wrong-token-but-plain-ascii-0123456789"),
    ("latin1-high-byte", b"Bearer caf\xe9-token-0123456789abcdef-32+++"),
    ("utf8-multibyte", b"Bearer \xc3\xa9\xc3\xa8-token-0123456789abcdef+"),
    ("raw-high-bytes", b"Bearer \x80\x81\x82-token-0123456789abcdef++"),
    ("not-bearer", b"Basic dXNlcjpwYXNz"),
]


def _call(client: TestClient, method: str, path: str, auth: bytes) -> Any:
    return client.request(method, path, headers={"Authorization": auth}, json={})


@pytest.mark.parametrize(("method", "path"), _ADMIN_ENDPOINTS)
@pytest.mark.parametrize(("label", "credential"), _REJECTED_CREDENTIALS)
def test_rejected_admin_credential_is_401_never_500(
    tmp_path: Path, method: str, path: str, label: str, credential: bytes
) -> None:
    """A rejected admin credential is a clean 401 on every endpoint.

    The 500 this replaces was not an auth bypass -- it failed closed -- but it
    cost the property that every rejected admin call is cheap, audit-legible,
    and traceback-free at an unauthenticated peer's choosing.
    """
    client = _client(tmp_path)
    response = _call(client, method, path, credential)
    assert response.status_code == 401, (
        f"{label} on {method} {path} returned {response.status_code}, "
        f"expected 401"
    )


@pytest.mark.parametrize(("method", "path"), _ADMIN_ENDPOINTS)
def test_missing_authorization_header_is_401(
    tmp_path: Path, method: str, path: str
) -> None:
    """No header at all is the same clean 401, not a 500."""
    client = _client(tmp_path)
    response = client.request(method, path, json={})
    assert response.status_code == 401


def test_non_ascii_credential_does_not_become_a_false_accept(
    tmp_path: Path,
) -> None:
    """The fix must not make the comparison *looser*.

    Encoding both sides to bytes removes the TypeError. The risk in that move
    is a lossy encode -- ``errors="replace"`` would fold every unencodable
    character onto ``?``, so two different credentials could collide. Assert
    the near-miss cases are still refused: a token that differs from the real
    one only by a high byte, and the real token with one byte appended.
    """
    client = _client(tmp_path)
    near_misses = [
        STRONG_ADMIN_TOKEN.encode("ascii")[:-1] + b"\xe9",
        STRONG_ADMIN_TOKEN.encode("ascii") + b"\xe9",
        STRONG_ADMIN_TOKEN.encode("ascii") + b"\x00",
        b"\xe9" + STRONG_ADMIN_TOKEN.encode("ascii")[1:],
    ]
    for candidate in near_misses:
        response = _call(
            client, "DELETE", "/acme/admin/nonces", b"Bearer " + candidate
        )
        assert response.status_code == 401, (
            f"near-miss credential {candidate!r} was accepted"
        )


def test_the_real_admin_token_still_works(tmp_path: Path) -> None:
    """The control: the fix must not break the credential that should pass.

    Without this, every assertion above is satisfiable by a guard that refuses
    everything -- the failure mode a hardening change is most likely to
    introduce and least likely to notice.
    """
    client = _client(tmp_path)
    response = _call(
        client,
        "DELETE",
        "/acme/admin/nonces",
        b"Bearer " + STRONG_ADMIN_TOKEN.encode("ascii"),
    )
    assert response.status_code == 200


def test_the_real_confirm_token_still_reaches_its_endpoint(
    tmp_path: Path,
) -> None:
    """Control for the confirm guard, which does NOT accept the admin token.

    404 (not 401) is the pass: the credential was accepted and the route got
    as far as looking the serial up.
    """
    client = _client(tmp_path)
    response = _call(
        client,
        "POST",
        "/acme/admin/revocations/0A1B/confirm",
        b"Bearer " + STRONG_CONFIRM_TOKEN.encode("ascii"),
    )
    assert response.status_code == 404
    # And the admin token is still refused here, as the authority split requires.
    refused = _call(
        client,
        "POST",
        "/acme/admin/revocations/0A1B/confirm",
        b"Bearer " + STRONG_ADMIN_TOKEN.encode("ascii"),
    )
    assert refused.status_code == 401


def test_a_non_ascii_configured_token_is_usable(tmp_path: Path) -> None:
    """A non-ASCII admin token must authenticate, not lock the operator out.

    The narrower fix -- refusing a non-ASCII credential at the door -- also
    removes the 500, but it silently bricks any deployment whose operator set a
    non-ASCII token: the credential is configured, accepted by config
    validation, and can never be presented. Comparing wire bytes against
    UTF-8-encoded config bytes fixes the crash without that side effect.
    """
    token = "café-admin-token-0123456789abcdef-32+"
    client = _client(tmp_path, admin_token=SecretStr(token))
    response = _call(
        client,
        "DELETE",
        "/acme/admin/nonces",
        b"Bearer " + token.encode("utf-8"),
    )
    assert response.status_code == 200


def _request_with_raw_authorization(raw: bytes) -> Request:
    """Build a Request carrying *raw* as the literal Authorization bytes.

    Not TestClient: httpx **re-encodes** a bytes header value as UTF-8 before
    it reaches the app (``b"caf\\xe9"`` is delivered as ``b"caf\\xc3\\xa9"``),
    so the two byte spellings this test needs to tell apart arrive identical
    and the assertion would be vacuous. The ASGI scope is the wire here.

    The end-to-end tests above are unaffected -- they only need *some*
    non-ASCII byte to reach the guard, and one still does.
    """
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", raw)],
        }
    )


def test_wire_bytes_are_compared_not_a_reinterpretation() -> None:
    """Two byte spellings of the same characters are different credentials.

    ``latin-1`` is chosen for the wire side because it is the exact inverse of
    Starlette's header decode. Getting this wrong in the lenient direction --
    normalizing both sides to the same text -- would make ``caf\\xe9`` and
    ``caf\\xc3\\xa9`` authenticate against one configured token.
    """
    configured = "café-admin-token-0123456789abcdef-32+"
    expected = _configured_token_bytes(configured)

    utf8_on_the_wire = _bearer_token(
        _request_with_raw_authorization(b"Bearer " + configured.encode("utf-8"))
    )
    latin1_on_the_wire = _bearer_token(
        _request_with_raw_authorization(b"Bearer " + configured.encode("latin-1"))
    )

    assert utf8_on_the_wire == expected
    assert latin1_on_the_wire != expected
    assert utf8_on_the_wire != latin1_on_the_wire


def test_bearer_token_returns_bytes_for_every_credential_shape() -> None:
    """``_bearer_token`` never raises on a byte a peer can put on the wire.

    The defect was an exception reaching the route, so the property worth
    pinning is totality, not any particular value.
    """
    for raw in (
        b"Bearer plain-ascii",
        b"Bearer caf\xe9",
        b"Bearer \x80\x81\x82",
        b"Bearer \xc3\xa9\xc3\xa8",
        b"Bearer ",
    ):
        token = _bearer_token(_request_with_raw_authorization(raw))
        assert isinstance(token, bytes)
        # And it is comparable -- the operation that used to raise.
        assert isinstance(
            hmac.compare_digest(token, _configured_token_bytes("x")), bool
        )


def test_unset_admin_token_still_disables_the_endpoint(tmp_path: Path) -> None:
    """Fail-closed on an unconfigured token survives the change."""
    client = _client(tmp_path, admin_token=SecretStr(""))
    response = _call(client, "DELETE", "/acme/admin/nonces", b"Bearer anything")
    assert response.status_code == 401
