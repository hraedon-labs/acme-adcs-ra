"""Replay-Nonce on ACME POST responses (RFC 8555 §6.5) — item 28.

§6.5: the server MUST include ``Replay-Nonce`` in every successful response to
a POST, and a ``badNonce`` error MUST carry a fresh nonce the client can retry
with. The RA used to set the header only on ``new-nonce``: certbot could not
register at all (acme-python raises ``MissingNonce``) and Posh-ACME re-sent its
spent nonce and failed every POST after new-account.

The bucket rules are the security half of this: successful (authenticated)
POSTs are owed a nonce even when the nonce bucket is dry, but no ERROR response
may mint a nonce around the bucket, or "valid nonce + garbage signature" would
be an unbounded unauthenticated nonce chain past the flood control.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from acme_adcs_ra.server import ServerContext
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient, sign_jws
from .test_key_change import _make_app, _make_config

BASE = "http://testserver"
NEW_ORDER = f"{BASE}/acme/new-order"
JOSE = {"Content-Type": "application/jose+json"}


class _Bucket:
    """A nonce bucket the test can open and close, counting every draw."""

    def __init__(self) -> None:
        self.open = True
        self.draws = 0

    def take(self, tokens: float = 1.0) -> bool:
        self.draws += 1
        return self.open

    def retry_after_seconds(self, tokens: float = 1.0) -> int:
        return 1


def _setup(tmp_path: Path) -> tuple[TestClient, Store, ServerContext, _Bucket, HandRolledAcmeClient]:
    config = _make_config(tmp_path)
    app, store, ctx = _make_app(config)
    bucket = _Bucket()
    ctx.nonce_bucket = bucket  # type: ignore[assignment]
    client = TestClient(app)
    acme = HandRolledAcmeClient(client, BASE, ec.generate_private_key(ec.SECP256R1()))
    mac_key = config.eab_key_bytes("kid-001")
    assert mac_key is not None
    assert acme.new_account("kid-001", mac_key).status_code == 201
    return client, store, ctx, bucket, acme


def _new_order_body(acme: HandRolledAcmeClient, nonce: str, *, corrupt: bool = False) -> str:
    body = sign_jws(
        {"identifiers": [{"type": "dns", "value": "srv01.WORK-DOMAIN.local"}]},
        acme.account_key,
        {"alg": "ES256", "kid": acme.account_url, "nonce": nonce, "url": NEW_ORDER},
    )
    if corrupt:
        sig = body["signature"]
        body["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    return json.dumps(body)


def _post(client: TestClient, path: str, content: str) -> Any:
    return client.post(path, content=content, headers=JOSE)


def _fresh(client: TestClient) -> str:
    return str(client.head("/acme/new-nonce").headers["Replay-Nonce"])


def test_every_successful_post_carries_a_redeemable_nonce(tmp_path: Path) -> None:
    client, _store, _ctx, bucket, acme = _setup(tmp_path)

    first = _fresh(client)
    before = bucket.draws
    resp = _post(client, "/acme/new-order", _new_order_body(acme, first))
    assert resp.status_code == 201, resp.text
    assert bucket.draws == before  # a success never draws, open bucket or not
    chained = resp.headers["Replay-Nonce"]

    # The nonce handed back is live: the next request can spend it directly,
    # which is exactly what Posh-ACME and acme-python do.
    resp2 = _post(client, "/acme/new-order", _new_order_body(acme, chained))
    assert resp2.status_code == 201, resp2.text
    assert resp2.headers["Replay-Nonce"] not in (chained,)


def test_new_account_success_carries_a_nonce(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    app, _store, _ctx = _make_app(config)
    client = TestClient(app)
    acme = HandRolledAcmeClient(client, BASE, ec.generate_private_key(ec.SECP256R1()))
    mac_key = config.eab_key_bytes("kid-001")
    assert mac_key is not None
    resp = acme.new_account("kid-001", mac_key)
    assert resp.status_code == 201
    assert resp.headers.get("Replay-Nonce")


def test_post_as_get_success_carries_a_nonce(tmp_path: Path) -> None:
    _client, _store, _ctx, _bucket, acme = _setup(tmp_path)
    order = acme.new_order(["srv01.WORK-DOMAIN.local"])
    authz_url = order.json()["authorizations"][0]
    resp = acme.post_as_get(authz_url)
    assert resp.status_code == 200
    assert resp.headers.get("Replay-Nonce")


def test_bad_nonce_error_carries_a_retry_nonce(tmp_path: Path) -> None:
    client, _store, _ctx, _bucket, acme = _setup(tmp_path)
    spent = _fresh(client)
    assert _post(client, "/acme/new-order", _new_order_body(acme, spent)).status_code == 201

    replay = _post(client, "/acme/new-order", _new_order_body(acme, spent))
    assert replay.status_code == 400
    problem = replay.json()
    assert problem["type"] == "urn:ietf:params:acme:error:badNonce"
    # acme.sh keys its retry on Boulder's detail wording, not the type.
    assert problem["detail"].startswith("JWS has an invalid anti-replay nonce")
    retry_nonce = replay.headers["Replay-Nonce"]

    retried = _post(client, "/acme/new-order", _new_order_body(acme, retry_nonce))
    assert retried.status_code == 201, retried.text


def test_bad_nonce_with_a_dry_bucket_becomes_rate_limited(tmp_path: Path) -> None:
    """§6.5: a badNonce MUST carry a fresh nonce. With the bucket dry the RA
    cannot mint one without defeating the flood control, so it must not send a
    badNonce at all: it answers rateLimited + Retry-After (Daybreak Blue r2)."""
    client, _store, _ctx, bucket, acme = _setup(tmp_path)
    bucket.open = False
    resp = _post(client, "/acme/new-order", _new_order_body(acme, "not-a-real-nonce"))
    assert resp.status_code == 429
    assert resp.json()["type"] == "urn:ietf:params:acme:error:rateLimited"
    assert resp.headers.get("Retry-After")
    assert "Replay-Nonce" not in resp.headers


def test_bad_nonce_draws_exactly_one_token(tmp_path: Path) -> None:
    client, _store, _ctx, bucket, acme = _setup(tmp_path)
    before = bucket.draws
    resp = _post(client, "/acme/new-order", _new_order_body(acme, "not-a-real-nonce"))
    assert resp.status_code == 400
    assert resp.json()["type"] == "urn:ietf:params:acme:error:badNonce"
    assert resp.headers.get("Replay-Nonce")
    assert bucket.draws == before + 1


def test_unauthenticated_error_cannot_chain_nonces_around_the_bucket(
    tmp_path: Path,
) -> None:
    """Valid nonce + garbage signature spends the nonce and fails with 401.
    That error must draw its replacement nonce from the bucket: with the
    bucket dry, no nonce comes back, so the chain ends."""
    client, _store, _ctx, bucket, acme = _setup(tmp_path)
    nonce = _fresh(client)
    bucket.open = False
    before = bucket.draws

    resp = _post(client, "/acme/new-order", _new_order_body(acme, nonce, corrupt=True))

    assert resp.status_code == 401, resp.text
    assert "Replay-Nonce" not in resp.headers
    assert bucket.draws == before + 1


def test_unauthenticated_error_with_open_bucket_gets_a_bucketed_nonce(
    tmp_path: Path,
) -> None:
    client, _store, _ctx, bucket, acme = _setup(tmp_path)
    nonce = _fresh(client)
    before = bucket.draws
    resp = _post(client, "/acme/new-order", _new_order_body(acme, nonce, corrupt=True))
    assert resp.status_code == 401
    assert resp.headers.get("Replay-Nonce")
    assert bucket.draws == before + 1


def test_successful_post_gets_its_nonce_even_with_a_dry_bucket(tmp_path: Path) -> None:
    """The §6.5 MUST holds under nonce-flood pressure: a verified request has
    spent one nonce and is owed one back regardless of the bucket."""
    client, _store, _ctx, bucket, acme = _setup(tmp_path)
    nonce = _fresh(client)
    bucket.open = False
    before = bucket.draws
    resp = _post(client, "/acme/new-order", _new_order_body(acme, nonce))
    assert resp.status_code == 201, resp.text
    assert resp.headers.get("Replay-Nonce")
    assert bucket.draws == before


def test_errors_before_any_nonce_is_spent_get_no_nonce(tmp_path: Path) -> None:
    client, _store, _ctx, bucket, _acme = _setup(tmp_path)
    before = bucket.draws
    resp = _post(client, "/acme/new-order", "{not json")
    assert resp.status_code == 400
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
    assert "Replay-Nonce" not in resp.headers
    assert bucket.draws == before


def test_non_jws_routes_are_untouched(tmp_path: Path) -> None:
    client, _store, _ctx, _bucket, _acme = _setup(tmp_path)
    assert "Replay-Nonce" not in client.get("/directory").headers
    # new-nonce keeps exactly one nonce (its own), not a second appended one.
    head = client.head("/acme/new-nonce")
    assert len(head.headers.get_list("Replay-Nonce")) == 1


def test_a_failed_mint_does_not_turn_a_completed_post_into_a_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, store, _ctx, _bucket, acme = _setup(tmp_path)
    nonce = _fresh(client)

    def unwritable() -> str:
        raise sqlite3.OperationalError("attempt to write a readonly database")

    monkeypatch.setattr(store, "create_nonce", unwritable)
    resp = _post(client, "/acme/new-order", _new_order_body(acme, nonce))
    assert resp.status_code == 201, resp.text
    assert "Replay-Nonce" not in resp.headers


def test_the_mint_runs_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The response-time mint is a SQLite write that can wait out the busy
    timeout; on the event loop it would stall every request (Daybreak Blue,
    round 1). asyncio.get_running_loop() raises outside the loop's thread."""
    import asyncio

    client, store, _ctx, _bucket, acme = _setup(tmp_path)
    original = store.create_nonce
    on_loop: list[bool] = []

    def recording() -> str:
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return original()

    nonce = _fresh(client)
    monkeypatch.setattr(store, "create_nonce", recording)
    resp = _post(client, "/acme/new-order", _new_order_body(acme, nonce))
    assert resp.status_code == 201
    assert resp.headers.get("Replay-Nonce")
    assert on_loop == [False]


def test_bad_nonce_whose_mint_fails_becomes_rate_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DeepSeek round 3: the bucket is not the only way the mint can fail. A
    badNonce whose nonce cannot be minted (writer lock past the busy timeout,
    read-only store) must not go out nonce-less either."""
    client, store, _ctx, _bucket, acme = _setup(tmp_path)

    def unwritable() -> str:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "create_nonce", unwritable)
    resp = _post(client, "/acme/new-order", _new_order_body(acme, "not-a-real-nonce"))
    assert resp.status_code == 429, resp.text
    assert resp.json()["type"] == "urn:ietf:params:acme:error:rateLimited"
    assert resp.headers.get("Retry-After")
    assert "Replay-Nonce" not in resp.headers
