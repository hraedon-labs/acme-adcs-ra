"""RFC 8555 error mappings, media type, challenge Link, and the EAB kid floor.

WI-033 (UNFILED item 29): finalize on a not-ready order -> 403 orderNotReady
  (§7.4); an unsupported JWS alg -> 400 badSignatureAlgorithm with an
  ``algorithms`` array (§6.2).
WI-034 (UNFILED item 30): POSTs that are not application/jose+json -> 415
  (§6.2); EAB kids below the 22-character floor refuse startup unless they are
  already in use (grandfathered) or ``allow_weak_credentials`` is set.
WI-036: the challenge response carries ``Link: <authz>;rel="up"`` (§7.1,
  §7.5.1); certbot aborts issuance without it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import MIN_EAB_KID_CHARS, EABEntry, RAConfig
from acme_adcs_ra.jws import SUPPORTED_JWS_ALGORITHMS, _base64url_encode
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import (
    JOSE_HEADERS,
    HandRolledAcmeClient,
    b64url_encode,
    jwk_from_private_key,
)
from .test_key_change import _make_app, _make_config

BASE = "http://testserver"
KID = "kid-001-0123456789abcdef"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
SAN = "srv01.WORK-DOMAIN.local"


def _setup(tmp_path: Path) -> tuple[TestClient, Store, HandRolledAcmeClient]:
    config = _make_config(tmp_path)
    app, store, _ctx = _make_app(config)
    client = TestClient(app)
    acme = HandRolledAcmeClient(client, BASE, ec.generate_private_key(ec.SECP256R1()))
    mac_key = config.eab_key_bytes(KID)
    assert mac_key is not None
    assert acme.new_account(KID, mac_key).status_code == 201
    return client, store, acme


def _csr(san: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def _fresh(client: TestClient) -> str:
    return str(client.head("/acme/new-nonce").headers["Replay-Nonce"])


def _unsigned_jws(protected: dict[str, Any], payload: dict[str, Any] | None) -> dict[str, str]:
    """A JWS whose alg the RA must refuse before any signature math."""
    return {
        "protected": b64url_encode(json.dumps(protected).encode()),
        "payload": b64url_encode(json.dumps(payload).encode()) if payload is not None else "",
        "signature": _base64url_encode(b"\x00" * 64),
    }


# --- WI-033 (a): orderNotReady -------------------------------------------------


def test_finalize_on_a_pending_order_is_403_order_not_ready(tmp_path: Path) -> None:
    _client, store, acme = _setup(tmp_path)
    order = acme.new_order([SAN]).json()

    resp = acme.finalize_order(order["finalize"], _csr(SAN))

    assert resp.status_code == 403, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:orderNotReady"
    order_id = order["finalize"].rsplit("/", 1)[-1]
    refreshed = store.get_order(order_id)
    assert refreshed is not None and refreshed.status == "pending"


def test_finalize_on_a_valid_order_still_answers_with_the_order(tmp_path: Path) -> None:
    """Deliberate deviation kept: a retried finalize after issuance must not
    read as an error (the double-issuance guard depends on this path)."""
    _client, _store, acme = _setup(tmp_path)
    order = acme.new_order([SAN]).json()
    authz = acme.get_authorization(order["authorizations"][0]).json()
    acme.validate_challenge(authz["challenges"][0]["url"])
    first = acme.finalize_order(order["finalize"], _csr(SAN))
    assert first.status_code == 200, first.text
    again = acme.finalize_order(order["finalize"], _csr(SAN))
    assert again.status_code == 200, again.text
    assert again.json()["status"] == "valid"


# --- WI-033 (b): badSignatureAlgorithm -----------------------------------------


@pytest.mark.parametrize("alg", ["HS256", "none", "PS256", "EdDSA"])
def test_unsupported_alg_on_an_account_request_is_bad_signature_algorithm(
    tmp_path: Path, alg: str
) -> None:
    client, _store, acme = _setup(tmp_path)
    url = f"{BASE}/acme/new-order"
    body = _unsigned_jws(
        {"alg": alg, "kid": acme.account_url, "nonce": _fresh(client), "url": url},
        {"identifiers": [{"type": "dns", "value": SAN}]},
    )
    resp = client.post("/acme/new-order", content=json.dumps(body), headers=JOSE_HEADERS)

    assert resp.status_code == 400, resp.text
    problem = resp.json()
    assert problem["type"] == "urn:ietf:params:acme:error:badSignatureAlgorithm"
    assert problem["algorithms"] == list(SUPPORTED_JWS_ALGORITHMS)


def test_unsupported_alg_on_new_account_is_bad_signature_algorithm(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    app, _store, _ctx = _make_app(config)
    client = TestClient(app)
    jwk = jwk_from_private_key(ec.generate_private_key(ec.SECP256R1()))
    url = f"{BASE}/acme/new-acct"
    body = _unsigned_jws(
        {"alg": "HS256", "jwk": jwk, "nonce": _fresh(client), "url": url},
        {"termsOfServiceAgreed": True},
    )
    resp = client.post("/acme/new-acct", content=json.dumps(body), headers=JOSE_HEADERS)
    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:badSignatureAlgorithm"
    assert resp.json()["algorithms"] == list(SUPPORTED_JWS_ALGORITHMS)


def test_unsupported_alg_on_the_inner_key_change_jws(tmp_path: Path) -> None:
    _client, _store, acme = _setup(tmp_path)
    url = f"{BASE}/acme/key-change"
    new_jwk = jwk_from_private_key(ec.generate_private_key(ec.SECP256R1()))
    inner = _unsigned_jws(
        {"alg": "HS256", "jwk": new_jwk, "url": url},
        {"account": acme.account_url, "oldKey": acme.account_jwk},
    )
    resp = acme._post_jws(url, inner)  # outer is properly signed by the old key
    assert resp.status_code == 400, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:badSignatureAlgorithm"


def test_a_bad_signature_with_a_supported_alg_stays_unauthorized(tmp_path: Path) -> None:
    """Only the unsupported-alg case moved; a forged ES256 signature is still
    an authentication failure, not an algorithm negotiation."""
    client, _store, acme = _setup(tmp_path)
    url = f"{BASE}/acme/new-order"
    body = _unsigned_jws(
        {"alg": "ES256", "kid": acme.account_url, "nonce": _fresh(client), "url": url},
        {"identifiers": [{"type": "dns", "value": SAN}]},
    )
    resp = client.post("/acme/new-order", content=json.dumps(body), headers=JOSE_HEADERS)
    assert resp.status_code == 401, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:unauthorized"


# --- WI-034 (a): application/jose+json -----------------------------------------


@pytest.mark.parametrize(
    "content_type", ["application/json", "text/plain", None, "application/jose"]
)
def test_wrong_media_type_is_415_and_spends_no_nonce(
    tmp_path: Path, content_type: str | None
) -> None:
    client, _store, acme = _setup(tmp_path)
    nonce = _fresh(client)
    url = f"{BASE}/acme/new-order"
    from .hand_rolled_acme_client import sign_jws

    body = json.dumps(
        sign_jws(
            {"identifiers": [{"type": "dns", "value": SAN}]},
            acme.account_key,
            {"alg": "ES256", "kid": acme.account_url, "nonce": nonce, "url": url},
        )
    )
    headers = {"Content-Type": content_type} if content_type else {}
    resp = client.post("/acme/new-order", content=body, headers=headers)
    assert resp.status_code == 415, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"

    # Refused before the nonce was touched: the same signed request, resent
    # with the right media type, succeeds.
    ok = client.post("/acme/new-order", content=body, headers=JOSE_HEADERS)
    assert ok.status_code == 201, ok.text


@pytest.mark.parametrize(
    "content_type", ["application/jose+json; charset=utf-8", "Application/JOSE+JSON"]
)
def test_media_type_parameters_and_case_are_accepted(
    tmp_path: Path, content_type: str
) -> None:
    client, _store, acme = _setup(tmp_path)
    acme.http = _HeaderOverride(client, content_type)
    assert acme.new_order([SAN]).status_code == 201


class _HeaderOverride:
    """Wraps a TestClient so the hand-rolled client sends a chosen Content-Type."""

    def __init__(self, client: TestClient, content_type: str) -> None:
        self._client = client
        self._ct = content_type

    def post(self, url: str, **kwargs: Any) -> Any:
        kwargs["headers"] = {"Content-Type": self._ct}
        return self._client.post(url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Any:
        return self._client.head(url, **kwargs)


@pytest.mark.parametrize(
    "fields",
    [
        [("content-type", "application/jose+json"), ("content-type", "text/plain")],
        [("content-type", "text/plain"), ("content-type", "application/jose+json")],
        [("content-type", "application/jose+json"), ("content-type", "application/jose+json")],
        [("content-type", "application/jose+json; charset=utf-8, text/plain")],
        [("content-type", "application/jose+json, text/plain")],
        [("content-type", "text/plain, application/jose+json")],
    ],
)
def test_duplicate_content_type_fields_are_refused_in_either_order(
    tmp_path: Path, fields: list[tuple[str, str]]
) -> None:
    client, _store, acme = _setup(tmp_path)
    from .hand_rolled_acme_client import sign_jws

    url = f"{BASE}/acme/new-order"
    body = json.dumps(
        sign_jws(
            {"identifiers": [{"type": "dns", "value": SAN}]},
            acme.account_key,
            {"alg": "ES256", "kid": acme.account_url, "nonce": _fresh(client), "url": url},
        )
    )
    resp = client.post("/acme/new-order", content=body, headers=fields)
    assert resp.status_code == 415, resp.text
    # Refused before the nonce was spent, as for a wrong single type.
    assert client.post("/acme/new-order", content=body, headers=JOSE_HEADERS).status_code == 201


def test_admin_json_endpoints_are_not_subject_to_the_jose_rule(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    app, _store, _ctx = _make_app(config)
    client = TestClient(app)
    resp = client.post(
        "/acme/admin/orders/does-not-exist/reclaim-processing",
        headers={"Authorization": "Bearer test-admin-token-0123456789abcdef-32+"},
        json={},
    )
    assert resp.status_code != 415


# --- WI-034 (b): EAB kid floor ------------------------------------------------


def _config_with_kid(tmp_path: Path, kid: str, **extra: Any) -> RAConfig:
    return RAConfig(
        base_url=BASE,
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=kid, mac_key=SecretStr(MAC_B64))],
        san_scopes={kid: {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        **extra,
    )


def test_floor_is_twenty_two_characters() -> None:
    assert MIN_EAB_KID_CHARS == 22


def test_a_new_short_kid_refuses_startup(tmp_path: Path) -> None:
    config = _config_with_kid(tmp_path, "k" * (MIN_EAB_KID_CHARS - 1))
    with pytest.raises(RuntimeError, match="below the 22-character floor"):
        _make_app(config)


def test_a_kid_at_the_floor_starts(tmp_path: Path) -> None:
    _make_app(_config_with_kid(tmp_path, "k" * MIN_EAB_KID_CHARS))


def test_allow_weak_credentials_skips_the_floor(tmp_path: Path) -> None:
    _make_app(_config_with_kid(tmp_path, "short", allow_weak_credentials=True))


def test_a_short_kid_that_already_has_accounts_is_grandfathered(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Upgrade path: an existing deployment's short kid must keep working, or
    every account under it is locked out by an upgrade."""
    short = "lab-kid-01"
    # Create the account under the weak gate (the pre-upgrade world)...
    weak = _config_with_kid(tmp_path, short, allow_weak_credentials=True)
    app, _store, _ctx = _make_app(weak)
    acme = HandRolledAcmeClient(TestClient(app), BASE, ec.generate_private_key(ec.SECP256R1()))
    mac = weak.eab_key_bytes(short)
    assert mac is not None
    assert acme.new_account(short, mac).status_code == 201

    # ...then restart with the floor in force: starts, and says so loudly.
    with caplog.at_level(logging.WARNING, logger="acme_adcs_ra.eab_kid_floor"):
        app2, _s, _c = _make_app(_config_with_kid(tmp_path, short))
    assert any("GRANDFATHERED" in r.getMessage() for r in caplog.records)
    acme.http = TestClient(app2)
    assert acme.new_order([SAN]).status_code == 201


def test_grandfathering_is_exact_match(tmp_path: Path) -> None:
    """Re-declaring an in-use short kid with different case is a NEW kid."""
    used = "lab-kid-01"
    weak = _config_with_kid(tmp_path, used, allow_weak_credentials=True)
    app, _store, _ctx = _make_app(weak)
    acme = HandRolledAcmeClient(TestClient(app), BASE, ec.generate_private_key(ec.SECP256R1()))
    mac = weak.eab_key_bytes(used)
    assert mac is not None
    assert acme.new_account(used, mac).status_code == 201
    with pytest.raises(RuntimeError, match="LAB-KID-01"):
        _make_app(_config_with_kid(tmp_path, used.upper()))


def test_grandfathering_is_per_kid(tmp_path: Path) -> None:
    """One short kid in use does not excuse a second, new short kid."""
    used, fresh = "lab-kid-01", "lab-kid-02"
    weak = _config_with_kid(tmp_path, used, allow_weak_credentials=True)
    app, _store, _ctx = _make_app(weak)
    acme = HandRolledAcmeClient(TestClient(app), BASE, ec.generate_private_key(ec.SECP256R1()))
    mac = weak.eab_key_bytes(used)
    assert mac is not None
    assert acme.new_account(used, mac).status_code == 201

    both = RAConfig(
        base_url=BASE,
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid=used, mac_key=SecretStr(MAC_B64)),
            EABEntry(kid=fresh, mac_key=SecretStr(MAC_B64)),
        ],
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
    )
    with pytest.raises(RuntimeError, match=fresh):
        _make_app(both)


# --- WI-036: challenge Link rel="up" ------------------------------------------


def test_challenge_response_links_up_to_its_authorization(tmp_path: Path) -> None:
    _client, _store, acme = _setup(tmp_path)
    order = acme.new_order([SAN]).json()
    authz_url = order["authorizations"][0]
    challenge_url = acme.get_authorization(authz_url).json()["challenges"][0]["url"]

    first = acme.validate_challenge(challenge_url)
    replay = acme.validate_challenge(challenge_url)  # the already-valid branch

    for resp in (first, replay):
        assert resp.status_code == 200, resp.text
        assert resp.headers["Link"] == f'<{authz_url}>;rel="up"'
