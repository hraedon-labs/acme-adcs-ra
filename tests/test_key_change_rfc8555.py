"""keyChange inner-JWS conformance (RFC 8555 §7.3.5) — item 27.

The route used to REQUIRE an inner-JWS ``nonce`` and consume it. RFC 8555
§7.3.5 says the opposite: "The inner JWS MUST omit the 'nonce' header
parameter." Every conformant client (Posh-ACME, Certes/Certify the Web, ...)
therefore failed account-key rollover with ``badNonce``, while the in-repo
hand-rolled client -- which sent an inner nonce -- kept the suite green.

These tests build the inner JWS by hand, the way the RFC describes it, rather
than through ``HandRolledAcmeClient.key_change``, so that a future regression in
the helper cannot silently re-align client and server on a private dialect.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from acme_adcs_ra.jws import jwk_thumbprint
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import (
    HandRolledAcmeClient,
    jwk_from_private_key,
    sign_jws,
)
from .test_key_change import _make_app, _make_config

BASE = "http://testserver"
KEY_CHANGE_URL = f"{BASE}/acme/key-change"
_KID = "kid-001"


def _setup(tmp_path: Path) -> tuple[TestClient, Store, HandRolledAcmeClient]:
    config = _make_config(tmp_path)
    app, store, _ctx = _make_app(config)
    client = TestClient(app)
    acme = HandRolledAcmeClient(
        client, BASE, rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    mac_key = config.eab_key_bytes("kid-001")
    assert mac_key is not None
    assert acme.new_account("kid-001", mac_key).status_code == 201
    return client, store, acme


def _fresh_nonce(client: TestClient) -> str:
    return client.head("/acme/new-nonce").headers["Replay-Nonce"]


def _inner_jws(
    acme: HandRolledAcmeClient,
    new_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    **extra_header: Any,
) -> dict[str, str]:
    """The inner JWS exactly as RFC 8555 §7.3.5 specifies it: alg + jwk + url."""
    protected: dict[str, Any] = {
        "alg": "RS256" if isinstance(new_key, rsa.RSAPrivateKey) else "ES256",
        "jwk": jwk_from_private_key(new_key),
        "url": KEY_CHANGE_URL,
        **extra_header,
    }
    return sign_jws(
        {"account": acme.account_url, "oldKey": acme.account_jwk},
        new_key,
        protected,
    )


def _outer_jws(
    client: TestClient, acme: HandRolledAcmeClient, inner: dict[str, str]
) -> dict[str, str]:
    return sign_jws(
        inner,
        acme.account_key,
        {
            "alg": "RS256",
            "kid": acme.account_url,
            "nonce": _fresh_nonce(client),
            "url": KEY_CHANGE_URL,
        },
    )


def _stored_thumbprint(store: Store, acme: HandRolledAcmeClient) -> str:
    assert acme.account_url is not None
    account = store.get_account(acme.account_url.rsplit("/", 1)[-1])
    assert account is not None
    return jwk_thumbprint(json.loads(account.jwk_json))


def _post(client: TestClient, body: dict[str, str]) -> Any:
    return client.post(
        "/acme/key-change",
        content=json.dumps(body),
        headers={"Content-Type": "application/jose+json"},
    )


def test_rfc_shaped_inner_jws_without_nonce_rolls_the_key(tmp_path: Path) -> None:
    client, _store, acme = _setup(tmp_path)
    new_key = ec.generate_private_key(ec.SECP256R1())

    resp = _post(client, _outer_jws(client, acme, _inner_jws(acme, new_key)))

    assert resp.status_code == 200, resp.text
    # §7.3.5: success returns "the updated account object", not {}.
    body = resp.json()
    assert body["status"] == "valid"
    assert body["orders"].endswith("/orders")

    # The old key no longer authenticates; the new one does.
    assert acme.new_order(["srv01.WORK-DOMAIN.local"]).status_code == 401
    rolled = HandRolledAcmeClient(client, BASE, new_key)
    rolled.account_url = acme.account_url
    assert rolled.new_order(["srv01.WORK-DOMAIN.local"]).status_code == 201


def test_inner_jws_carrying_a_nonce_is_refused(tmp_path: Path) -> None:
    """§7.3.5 MUST omit: a present inner nonce is malformed, not consumed."""
    client, store, acme = _setup(tmp_path)
    before = _stored_thumbprint(store, acme)
    new_key = ec.generate_private_key(ec.SECP256R1())
    inner = _inner_jws(acme, new_key, nonce=_fresh_nonce(client))

    resp = _post(client, _outer_jws(client, acme, inner))

    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
    assert "omit nonce" in resp.json()["detail"]
    assert _stored_thumbprint(store, acme) == before


def test_inner_jws_carrying_a_kid_is_refused(tmp_path: Path) -> None:
    client, store, acme = _setup(tmp_path)
    before = _stored_thumbprint(store, acme)
    new_key = ec.generate_private_key(ec.SECP256R1())
    inner = _inner_jws(acme, new_key, kid=acme.account_url)

    resp = _post(client, _outer_jws(client, acme, inner))

    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
    assert _stored_thumbprint(store, acme) == before


def test_replaying_the_whole_request_is_refused_by_the_outer_nonce(
    tmp_path: Path,
) -> None:
    """Dropping the inner nonce removes no replay protection: the outer nonce is
    single-use, so the byte-identical request cannot be accepted twice."""
    client, store, acme = _setup(tmp_path)
    new_key = ec.generate_private_key(ec.SECP256R1())
    body = _outer_jws(client, acme, _inner_jws(acme, new_key))

    assert _post(client, body).status_code == 200
    rolled = _stored_thumbprint(store, acme)

    replay = _post(client, body)
    assert replay.status_code == 400, replay.text
    assert replay.json()["type"] == "urn:ietf:params:acme:error:badNonce"
    assert _stored_thumbprint(store, acme) == rolled


def test_captured_inner_jws_cannot_be_rewrapped_after_rollover(tmp_path: Path) -> None:
    """A captured inner JWS re-wrapped in a fresh outer request signed by the
    OLD key is refused once the rollover has happened: the old key no longer
    authenticates the account."""
    client, store, acme = _setup(tmp_path)
    new_key = ec.generate_private_key(ec.SECP256R1())
    inner = _inner_jws(acme, new_key)
    assert _post(client, _outer_jws(client, acme, inner)).status_code == 200
    rolled = _stored_thumbprint(store, acme)

    resp = _post(client, _outer_jws(client, acme, inner))
    assert resp.status_code == 401, resp.text
    assert _stored_thumbprint(store, acme) == rolled


def test_rollover_consumes_exactly_one_nonce(tmp_path: Path) -> None:
    """Only the outer nonce is spent. An unrelated, still-unused nonce minted
    before the rollover must remain redeemable afterwards."""
    client, _store, acme = _setup(tmp_path)
    spare = _fresh_nonce(client)
    new_key = ec.generate_private_key(ec.SECP256R1())
    assert _post(client, _outer_jws(client, acme, _inner_jws(acme, new_key))).status_code == 200

    rolled = HandRolledAcmeClient(client, BASE, new_key)
    rolled.account_url = acme.account_url
    rolled._nonce = spare
    assert rolled.new_order(["srv01.WORK-DOMAIN.local"]).status_code == 201


def test_captured_inner_jws_is_valid_again_after_a_b_a(tmp_path: Path) -> None:
    """PINS a trade the RFC makes (Daybreak Blue, round 1), not a defence.

    Without an inner nonce, an A->B inner JWS becomes acceptable again once the
    account is back on key A. Only the current-key holder can re-wrap it, and
    that holder could mint a fresh rollover anyway, so it is not a bypass; this
    test exists so the behaviour stays visible if anyone changes it."""
    client, store, acme = _setup(tmp_path)
    key_a = acme.account_key
    key_b = ec.generate_private_key(ec.SECP256R1())
    captured = _inner_jws(acme, key_b)
    assert _post(client, _outer_jws(client, acme, captured)).status_code == 200

    # B -> A, driven by the holder of B.
    on_b = HandRolledAcmeClient(client, BASE, key_b)
    on_b.account_url = acme.account_url
    back = _inner_jws(on_b, key_a)
    outer_b = sign_jws(
        back,
        key_b,
        {"alg": "ES256", "kid": acme.account_url, "nonce": _fresh_nonce(client), "url": KEY_CHANGE_URL},
    )
    assert _post(client, outer_b).status_code == 200

    # The captured A->B inner JWS, re-wrapped by the (again current) key A.
    resp = _post(client, _outer_jws(client, acme, captured))
    assert resp.status_code == 200, resp.text
    assert _stored_thumbprint(store, acme) == jwk_thumbprint(jwk_from_private_key(key_b))


def test_inner_jws_with_an_unprotected_header_is_refused(tmp_path: Path) -> None:
    """Daybreak Blue round 3: a flattened JWS 'header' member was ignored, so an
    inner nonce could ride there past the protected-header refusal."""
    client, store, acme = _setup(tmp_path)
    before = _stored_thumbprint(store, acme)
    inner = dict(_inner_jws(acme, ec.generate_private_key(ec.SECP256R1())))
    inner["header"] = {"nonce": _fresh_nonce(client)}  # type: ignore[assignment]

    resp = _post(client, _outer_jws(client, acme, inner))

    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
    assert _stored_thumbprint(store, acme) == before


@pytest.mark.parametrize("member", ["header", "signatures"])
def test_outer_jws_must_be_flattened_without_unprotected_header(
    tmp_path: Path, member: str
) -> None:
    client, _store, acme = _setup(tmp_path)
    body: dict[str, Any] = dict(
        sign_jws(
            {"identifiers": [{"type": "dns", "value": "srv01.WORK-DOMAIN.local"}]},
            acme.account_key,
            {"alg": "RS256", "kid": acme.account_url, "nonce": _fresh_nonce(client),
             "url": f"{BASE}/acme/new-order"},
        )
    )
    body[member] = {"x": 1} if member == "header" else []
    resp = client.post(
        "/acme/new-order", content=json.dumps(body),
        headers={"Content-Type": "application/jose+json"},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"


@pytest.mark.parametrize("member", ["header", "signatures"])
def test_eab_jws_must_be_flattened_without_unprotected_header(
    tmp_path: Path, member: str
) -> None:
    """DeepSeek round 4: the EAB leg of the §6.2 refusal had no test."""
    from .hand_rolled_acme_client import make_eab_jws

    config = _make_config(tmp_path)
    app, _store, _ctx = _make_app(config)
    client = TestClient(app)
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwk_from_private_key(key)
    mac = config.eab_key_bytes(_KID)
    assert mac is not None
    url = f"{BASE}/acme/new-acct"
    eab: dict[str, Any] = dict(make_eab_jws(jwk, _KID, mac, url=url))
    eab[member] = {"x": 1} if member == "header" else []
    outer = sign_jws(
        {"externalAccountBinding": eab, "termsOfServiceAgreed": True},
        key,
        {"alg": "ES256", "jwk": jwk, "nonce": _fresh_nonce(client), "url": url},
    )
    resp = _post_to(client, "/acme/new-acct", outer)
    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:badExternalAccountBinding"
    assert "RFC 8555 §6.2" in resp.json()["detail"]


def _post_to(client: TestClient, path: str, body: dict[str, Any]) -> Any:
    return client.post(path, content=json.dumps(body), headers={"Content-Type": "application/jose+json"})
