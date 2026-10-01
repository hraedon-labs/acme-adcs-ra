"""Regression tests: JWS/EAB URL binding must pin to the configured base_url.

The 2026-08-11 review found that `_verify_url` and the EAB `expected_url` were
both derived from `request.url` — which is built from the client-supplied
`Host` header (and, behind a proxy, `X-Forwarded-Proto`). Comparing the
protected-header url to the request url therefore only proved the client was
consistent with itself: an EAB minted for a *different* RA deployment verified
here, defeating the cross-endpoint replay control added on 2026-08-07.

**Test design note.** These tests deliberately configure ``base_url`` to a
value that differs from the host the test transport uses. That is not an
artificial contortion — it is the production shape (``base_url`` is the public
name; the request reaches the worker over loopback with whatever ``Host`` and
scheme the proxy passed through). It is also what makes the tests meaningful:
when ``base_url`` matches the transport host, ``str(request.url)`` and the
config-derived URL are the same string, so a test written that way passes
identically against the vulnerable and the fixed code.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import (
    JOSE_HEADERS,
    HandRolledAcmeClient,
    jwk_from_private_key,
    make_eab_jws,
    sign_jws,
)

# The kid/MAC pair below IS in this RA's allowlist. The attack being modelled
# is not a forged MAC — it is a legitimate credential minted against a
# different deployment's URL being replayed here.
KID = "kid-001-0123456789abcdef"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"

# The RA's configured public identity...
PUBLIC_URL = "https://acme-ra.WORK-DOMAIN.local"
# ...which is NOT the host the test transport connects to.
TRANSPORT_HOST = "testserver"
# A second RA deployment (e.g. the test environment) sharing the EAB kid.
ROGUE_URL = "https://acme-ra-test.WORK-DOMAIN.local"


def _mac_bytes() -> bytes:
    return base64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    cfg = RAConfig(
        base_url=PUBLIC_URL,
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=KID, mac_key=MAC_B64)],
        san_scopes={KID: {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
    )
    store = Store(cfg.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(cfg.eab_keys_by_kid()),
        san_scopes={k: s.dns_patterns for k, s in cfg.san_scopes.items()},
        template=cfg.adcs_template,
    )
    ctx = ServerContext(
        config=cfg,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(ctx))


def _new_account(client: TestClient, *, jws_url: str, eab_url: str) -> Any:
    """newAccount with independently-chosen urls in the outer JWS and the EAB.

    Keeping the two separate matters: if both name the rogue deployment, the
    outer JWS url check rejects the request first and the EAB binding is never
    reached — a test written that way passes even with the EAB check disabled.
    """
    nonce = client.head("/acme/new-nonce").headers["Replay-Nonce"]
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwk_from_private_key(key)
    eab = make_eab_jws(jwk, KID, _mac_bytes(), url=eab_url)
    body = sign_jws(
        {"externalAccountBinding": eab, "contact": []},
        key,
        {"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": jws_url},
    )
    return client.post("/acme/new-acct", content=json.dumps(body), headers=JOSE_HEADERS)


def test_new_account_signed_against_the_public_url_succeeds(
    client: TestClient,
) -> None:
    """Control: a client signing the configured public URL works.

    Note the transport host is ``testserver`` while both URLs name
    ``acme-ra.WORK-DOMAIN.local`` — i.e. the server must validate against its
    configuration, not against the request it received.
    """
    resp = _new_account(
        client,
        jws_url=f"{PUBLIC_URL}/acme/new-acct",
        eab_url=f"{PUBLIC_URL}/acme/new-acct",
    )
    assert resp.status_code == 201, resp.text


def test_eab_minted_for_another_deployment_is_rejected(client: TestClient) -> None:
    """An EAB whose protected url names a different RA must not verify here.

    The outer JWS is entirely well-formed for *this* server — only the EAB
    binding names the other deployment. That isolates the EAB check, and it is
    the real scenario: a client legitimately talking to production while
    presenting a credential minted against the test RA.
    """
    resp = _new_account(
        client,
        jws_url=f"{PUBLIC_URL}/acme/new-acct",
        eab_url=f"{ROGUE_URL}/acme/new-acct",
    )
    assert resp.status_code != 201, (
        f"EAB bound to {ROGUE_URL} was accepted: {resp.status_code} {resp.text}"
    )
    assert resp.json()["type"].endswith(":badExternalAccountBinding")
    assert "url does not match" in resp.json()["detail"]


def test_new_account_signed_against_the_transport_host_is_rejected(
    client: TestClient,
) -> None:
    """Signing the URL the request actually arrived on is not sufficient.

    This is the pre-fix behaviour: the server accepted whatever the Host header
    implied. It must now require the configured public URL.
    """
    resp = _new_account(
        client,
        jws_url=f"http://{TRANSPORT_HOST}/acme/new-acct",
        eab_url=f"http://{TRANSPORT_HOST}/acme/new-acct",
    )
    assert resp.status_code == 400, resp.text
    # Scheme is compared before host, so either mismatch is a correct rejection.
    assert "url scheme mismatch" in resp.json()["detail"] or (
        "url host mismatch" in resp.json()["detail"]
    )


def _authenticated_client(client: TestClient) -> HandRolledAcmeClient:
    key = ec.generate_private_key(ec.SECP256R1())
    acme = HandRolledAcmeClient(client, PUBLIC_URL, key)
    resp = acme.new_account(KID, _mac_bytes())
    assert resp.status_code == 201, resp.text
    return acme


def test_authenticated_jws_url_must_name_the_configured_host(
    client: TestClient,
) -> None:
    """A signed newOrder whose url names another deployment is rejected (§6.4)."""
    acme = _authenticated_client(client)
    nonce = client.head("/acme/new-nonce").headers["Replay-Nonce"]
    body = sign_jws(
        {"identifiers": [{"type": "dns", "value": "srv01.WORK-DOMAIN.local"}]},
        acme.account_key,
        {
            "alg": "ES256",
            "kid": acme.account_url,
            "nonce": nonce,
            "url": f"{ROGUE_URL}/acme/new-order",
        },
    )
    resp = client.post("/acme/new-order", content=json.dumps(body), headers=JOSE_HEADERS)
    assert resp.status_code == 400, resp.text
    assert "url host mismatch" in resp.json()["detail"]


def test_kid_from_another_deployment_is_rejected(client: TestClient) -> None:
    """A kid naming another RA's account URL is not accepted as ours."""
    acme = _authenticated_client(client)
    account_id = str(acme.account_url).rsplit("/", 1)[-1]

    nonce = client.head("/acme/new-nonce").headers["Replay-Nonce"]
    body = sign_jws(
        {"identifiers": [{"type": "dns", "value": "srv01.WORK-DOMAIN.local"}]},
        acme.account_key,
        {
            "alg": "ES256",
            # Same account id, presented as a URL on another server.
            "kid": f"{ROGUE_URL}/acme/acct/{account_id}",
            "nonce": nonce,
            "url": f"{PUBLIC_URL}/acme/new-order",
        },
    )
    resp = client.post("/acme/new-order", content=json.dumps(body), headers=JOSE_HEADERS)
    assert resp.status_code == 400, resp.text
    assert "not an account URL on this server" in resp.json()["detail"]


def test_scheme_is_pinned_to_the_configured_url(client: TestClient) -> None:
    """http:// must not satisfy a binding whose configured scheme is https.

    Behind IIS/HttpPlatformHandler the worker sees plain http on loopback, and
    uvicorn's proxy-header trust cannot distinguish the proxy from a client
    that simply sent X-Forwarded-Proto (the peer is always 127.0.0.1). Taking
    the scheme from configuration removes that input from the decision.
    """
    acme = _authenticated_client(client)
    nonce = client.head("/acme/new-nonce").headers["Replay-Nonce"]
    body = sign_jws(
        {"identifiers": [{"type": "dns", "value": "srv01.WORK-DOMAIN.local"}]},
        acme.account_key,
        {
            "alg": "ES256",
            "kid": acme.account_url,
            "nonce": nonce,
            "url": f"{PUBLIC_URL.replace('https://', 'http://')}/acme/new-order",
        },
    )
    resp = client.post(
        "/acme/new-order", content=json.dumps(body), headers={**JOSE_HEADERS, "X-Forwarded-Proto": "http"}
    )
    assert resp.status_code == 400, resp.text
    assert "url scheme mismatch" in resp.json()["detail"]
