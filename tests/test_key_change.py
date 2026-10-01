"""Tests for WI-019: ACME keyChange endpoint (RFC 8555 §7.3.5)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import AccountKeyStale, Store

from .hand_rolled_acme_client import HandRolledAcmeClient, jwk_from_private_key, sign_jws


def _make_config(tmp_path: Path) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid="kid-001", mac_key=mac_key_b64)],
        san_scopes={"kid-001": {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        max_accounts_per_eab_kid=2,
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
    )


def _make_app(config: RAConfig) -> tuple[Any, Store, ServerContext]:
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in config.san_scopes.items()
        },
        template=config.adcs_template,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return create_app(context), store, context


@pytest.fixture()
def config(tmp_path: Path) -> RAConfig:
    return _make_config(tmp_path)


@pytest.fixture()
def app_and_store(config: RAConfig) -> tuple[Any, Store, ServerContext]:
    return _make_app(config)


@pytest.fixture()
def client(app_and_store: tuple[Any, Store, ServerContext]) -> TestClient:
    app, _, _ = app_and_store
    return TestClient(app)


@pytest.fixture()
def old_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def acme_client(
    client: TestClient, config: RAConfig, old_key: rsa.RSAPrivateKey
) -> HandRolledAcmeClient:
    acme = HandRolledAcmeClient(client, "http://testserver", old_key)
    mac_key = config.eab_key_bytes("kid-001")
    assert mac_key is not None
    resp = acme.new_account("kid-001", mac_key)
    assert resp.status_code == 201
    return acme


class TestDirectoryListsKeyChange:
    def test_directory_includes_keychange(self, client: TestClient) -> None:
        resp = client.get("/directory")
        assert resp.status_code == 200
        body = resp.json()
        assert "keyChange" in body
        assert body["keyChange"].endswith("/acme/key-change")


class TestSuccessfulKeyChange:
    def test_key_change_succeeds_and_old_key_rejected(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
        app_and_store: tuple[Any, Store, ServerContext],
    ) -> None:
        _, store, _ = app_and_store
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        resp = acme_client.key_change(new_key)
        assert resp.status_code == 200

        events = store.list_audit_events(event_type="account-key-changed", limit=5)
        assert len(events) == 1
        assert events[0]["outcome"] == "success"

        resp = acme_client.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 401

        new_acme = HandRolledAcmeClient(
            client, "http://testserver", new_key
        )
        new_acme.account_url = acme_client.account_url
        resp = new_acme.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 201

    def test_key_change_with_ec_new_key(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
    ) -> None:
        new_key = ec.generate_private_key(ec.SECP256R1())
        resp = acme_client.key_change(new_key)
        assert resp.status_code == 200

        new_acme = HandRolledAcmeClient(client, "http://testserver", new_key)
        new_acme.account_url = acme_client.account_url
        resp = new_acme.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 201


class TestKeyChangeRejects:
    def test_rejects_a_rollover_that_loses_the_store_cas(
        self,
        acme_client: HandRolledAcmeClient,
        app_and_store: tuple[Any, Store, ServerContext],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, store, _ = app_and_store

        def stale(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AccountKeyStale("lost race")

        monkeypatch.setattr(store, "update_account_key_with_audit", stale)
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        resp = acme_client.key_change(new_key)

        assert resp.status_code == 401
        assert resp.json()["type"] == "urn:ietf:params:acme:error:unauthorized"
        events = store.list_audit_events(event_type="key-change-stale", limit=5)
        assert len(events) == 1
        assert events[0]["outcome"] == "denied"

    def test_uniqueness_race_is_a_bad_public_key_not_a_500(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
        config: RAConfig,
        app_and_store: tuple[Any, Store, ServerContext],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, store, _ = app_and_store
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_acme = HandRolledAcmeClient(client, "http://testserver", other_key)
        mac_key = config.eab_key_bytes("kid-001")
        assert mac_key is not None
        assert other_acme.new_account("kid-001", mac_key).status_code == 201
        assert other_acme.account_url is not None
        other_account = store.get_account(other_acme.account_url.rsplit("/", 1)[-1])
        assert other_account is not None

        proposed_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        proposed_jwk = jwk_from_private_key(proposed_key)
        original_lookup = store.get_account_by_jwk
        proposed_lookups = 0

        def raced_lookup(jwk: dict[str, Any]) -> Any:
            nonlocal proposed_lookups
            if jwk == proposed_jwk:
                proposed_lookups += 1
                return None if proposed_lookups == 1 else other_account
            return original_lookup(jwk)

        def conflict(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise sqlite3.IntegrityError("UNIQUE constraint failed")

        monkeypatch.setattr(store, "get_account_by_jwk", raced_lookup)
        monkeypatch.setattr(store, "update_account_key_with_audit", conflict)
        resp = acme_client.key_change(proposed_key)

        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badPublicKey"
        assert proposed_lookups == 2

    def test_reject_mismatched_url(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
    ) -> None:
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        new_jwk = jwk_from_private_key(new_key)
        url = f"{acme_client.base_url}/acme/key-change"
        inner_protected = {
            "alg": "RS256",
            "url": f"{acme_client.base_url}/acme/wrong-url",
            "jwk": new_jwk,
        }
        inner_payload = {
            "account": acme_client.account_url,
            "oldKey": acme_client.account_jwk,
        }
        inner_jws = sign_jws(inner_payload, new_key, inner_protected)
        resp = acme_client._post_jws(url, inner_jws)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"

    def test_reject_wrong_account(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
    ) -> None:
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        new_jwk = jwk_from_private_key(new_key)
        url = f"{acme_client.base_url}/acme/key-change"
        inner_protected = {
            "alg": "RS256",
            "url": url,
            "jwk": new_jwk,
        }
        inner_payload = {
            "account": f"{acme_client.base_url}/acme/acct/wrong-account-id",
            "oldKey": acme_client.account_jwk,
        }
        inner_jws = sign_jws(inner_payload, new_key, inner_protected)
        resp = acme_client._post_jws(url, inner_jws)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"

    def test_reject_key_already_in_use(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
        config: RAConfig,
    ) -> None:
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_acme = HandRolledAcmeClient(client, "http://testserver", other_key)
        mac_key = config.eab_key_bytes("kid-001")
        assert mac_key is not None
        other_acme.new_account("kid-001", mac_key)

        resp = acme_client.key_change(other_key)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:badPublicKey"

    def test_reject_new_key_equals_old_key(
        self,
        acme_client: HandRolledAcmeClient,
        old_key: rsa.RSAPrivateKey,
    ) -> None:
        resp = acme_client.key_change(old_key)
        assert resp.status_code == 400
        assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"

    def test_reject_wrong_old_key(
        self,
        acme_client: HandRolledAcmeClient,
        client: TestClient,
    ) -> None:
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_old_jwk = jwk_from_private_key(
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )
        url = f"{acme_client.base_url}/acme/key-change"
        new_jwk = jwk_from_private_key(new_key)
        inner_protected = {
            "alg": "RS256",
            "url": url,
            "jwk": new_jwk,
        }
        inner_payload = {
            "account": acme_client.account_url,
            "oldKey": wrong_old_jwk,
        }
        inner_jws = sign_jws(inner_payload, new_key, inner_protected)
        resp = acme_client._post_jws(url, inner_jws)
        assert resp.status_code == 401
        assert resp.json()["type"] == "urn:ietf:params:acme:error:unauthorized"
