"""Tests for WI-016: in-app per-account order rate limiting."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import OrderRateLimitExceeded, Store
from tests.conftest import placeholder_rsa_jwk

from .hand_rolled_acme_client import HandRolledAcmeClient


def _make_rate_limit_config(
    tmp_path: Path,
    *,
    per_kid: int = 3,
    window: int = 3600,
    global_limit: int = 0,
    overrides: dict[str, int] | None = None,
) -> RAConfig:
    mac_key_b64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001-0123456789abcdef", mac_key=mac_key_b64),
            EABEntry(kid="kid-002-0123456789abcdef", mac_key="YW5vdGhlci0zMi1ieXRlLW1hYy1rZXktZm9yLXRlc3Rz"),
        ],
        san_scopes={
            "kid-001-0123456789abcdef": {"dns_patterns": ["*.WORK-DOMAIN.local"]},
            "kid-002-0123456789abcdef": {"dns_patterns": ["*.prod.WORK-DOMAIN.local"]},
        },
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
        rate_limit_orders_per_window=per_kid,
        rate_limit_window_seconds=window,
        rate_limit_global_per_window=global_limit,
        rate_limit_overrides=overrides or {},
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


def _eab_mac_key(config: RAConfig, kid: str) -> bytes:
    raw = config.eab_key_bytes(kid)
    assert raw is not None
    return raw


@pytest.fixture()
def rate_config(tmp_path: Path) -> RAConfig:
    return _make_rate_limit_config(tmp_path, per_kid=3)


@pytest.fixture()
def rate_app(rate_config: RAConfig) -> tuple[Any, Store, ServerContext]:
    return _make_app(rate_config)


@pytest.fixture()
def rate_client(rate_app: tuple[Any, Store, ServerContext]) -> TestClient:
    app, _, _ = rate_app
    return TestClient(app)


@pytest.fixture()
def rate_acme_client(
    rate_client: TestClient,
    rate_config: RAConfig,
) -> HandRolledAcmeClient:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = HandRolledAcmeClient(
        http_client=rate_client,
        base_url="http://testserver",
        account_key=key,
    )
    mac_key = _eab_mac_key(rate_config, "kid-001-0123456789abcdef")
    resp = client.new_account("kid-001-0123456789abcdef", mac_key)
    assert resp.status_code == 201
    return client


class TestPerAccountRateLimit:
    def test_orders_within_limit_succeed(self, rate_acme_client: HandRolledAcmeClient) -> None:
        for i in range(3):
            resp = rate_acme_client.new_order([f"srv0{i}.WORK-DOMAIN.local"])
            assert resp.status_code == 201

    def test_order_over_limit_returns_429_with_retry_after(
        self, rate_acme_client: HandRolledAcmeClient
    ) -> None:
        for i in range(3):
            resp = rate_acme_client.new_order([f"srv0{i}.WORK-DOMAIN.local"])
            assert resp.status_code == 201

        resp = rate_acme_client.new_order(["srv99.WORK-DOMAIN.local"])
        assert resp.status_code == 429
        body = resp.json()
        assert body["type"] == "urn:ietf:params:acme:error:rateLimited"
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) == 3600

    def test_rate_limit_denial_is_audited(
        self,
        rate_acme_client: HandRolledAcmeClient,
        rate_app: tuple[Any, Store, ServerContext],
    ) -> None:
        _, store, _ = rate_app
        for i in range(3):
            rate_acme_client.new_order([f"srv0{i}.WORK-DOMAIN.local"])

        rate_acme_client.new_order(["srv99.WORK-DOMAIN.local"])

        events = store.list_audit_events(event_type="order-rate-limited", limit=10)
        assert len(events) == 1
        ev = events[0]
        assert ev["outcome"] == "denied"
        assert ev["details"]["scope"] == "per-account"
        assert ev["details"]["limit"] == 3
        assert ev["details"]["count"] == 3
        assert ev["details"]["kid"] == "kid-001-0123456789abcdef"
        assert ev["details"]["window_seconds"] == 3600

    def test_disabled_rate_limit_allows_unlimited(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(tmp_path, per_kid=0)
        app, _, _ = _make_app(config)
        client = TestClient(app)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, "http://testserver", key)
        acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))

        for i in range(10):
            resp = acme.new_order([f"srv{i:02d}.WORK-DOMAIN.local"])
            assert resp.status_code == 201


class TestPerKidOverride:
    def test_override_lowers_limit(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(
            tmp_path, per_kid=10, overrides={"kid-001-0123456789abcdef": 2}
        )
        app, _, _ = _make_app(config)
        client = TestClient(app)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, "http://testserver", key)
        acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))

        for i in range(2):
            resp = acme.new_order([f"srv0{i}.WORK-DOMAIN.local"])
            assert resp.status_code == 201

        resp = acme.new_order(["srv99.WORK-DOMAIN.local"])
        assert resp.status_code == 429
        body = resp.json()
        assert body["type"] == "urn:ietf:params:acme:error:rateLimited"

    def test_override_only_affects_specified_kid(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(
            tmp_path, per_kid=10, overrides={"kid-001-0123456789abcdef": 2}
        )
        app, _, _ = _make_app(config)
        client = TestClient(app)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, "http://testserver", key)
        acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))

        for i in range(2):
            acme.new_order([f"srv0{i}.WORK-DOMAIN.local"])
        resp = acme.new_order(["srv99.WORK-DOMAIN.local"])
        assert resp.status_code == 429

        key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme2 = HandRolledAcmeClient(client, "http://testserver", key2)
        acme2.new_account("kid-002-0123456789abcdef", _eab_mac_key(config, "kid-002-0123456789abcdef"))
        for i in range(5):
            resp = acme2.new_order([f"srv{i:02d}.prod.WORK-DOMAIN.local"])
            assert resp.status_code == 201


class TestGlobalBackstop:
    def test_global_limit_denies_regardless_of_per_kid(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(
            tmp_path, per_kid=100, global_limit=3
        )
        app, _, _ = _make_app(config)
        client = TestClient(app)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, "http://testserver", key)
        acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))

        for i in range(3):
            resp = acme.new_order([f"srv0{i}.WORK-DOMAIN.local"])
            assert resp.status_code == 201

        resp = acme.new_order(["srv99.WORK-DOMAIN.local"])
        assert resp.status_code == 429

    def test_global_limit_audited_with_scope_global(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(
            tmp_path, per_kid=100, global_limit=2
        )
        app, store, _ = _make_app(config)
        client = TestClient(app)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, "http://testserver", key)
        acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))

        for i in range(2):
            acme.new_order([f"srv0{i}.WORK-DOMAIN.local"])
        acme.new_order(["srv99.WORK-DOMAIN.local"])

        events = store.list_audit_events(event_type="order-rate-limited", limit=10)
        assert len(events) == 1
        assert events[0]["details"]["scope"] == "global"
        assert events[0]["details"]["limit"] == 2


class TestStoreCounting:
    def test_atomic_limit_blocks_parallel_burst(self, tmp_path: Path) -> None:
        """The count and insert are one serialized decision, not a TOCTOU pair."""
        config = _make_rate_limit_config(tmp_path, per_kid=1)
        _, store, _ = _make_app(config)
        account = store.create_account(
            jwk=placeholder_rsa_jwk("parallel"),
            eab_kid="kid-001-0123456789abcdef",
        )

        def create(index: int) -> bool:
            try:
                store.create_order_with_authz(
                    account_id=account.id,
                    identifiers=[{
                        "type": "dns",
                        "value": f"srv{index}.WORK-DOMAIN.local",
                    }],
                    challenge_url_fn=lambda cid: f"http://t/c/{cid}",
                    authz_url_fn=lambda aid: f"http://t/a/{aid}",
                    finalize_url_fn=lambda oid: f"http://t/f/{oid}",
                    rate_limit_window_seconds=3600,
                    rate_limit_per_kid=1,
                )
            except OrderRateLimitExceeded:
                return False
            return True

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(create, range(8)))
        assert outcomes.count(True) == 1
        assert outcomes.count(False) == 7

    def test_count_recent_orders_by_kid_with_injected_now(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(tmp_path, per_kid=100)
        _, store, _ = _make_app(config)

        account = store.create_account(
            jwk=placeholder_rsa_jwk("x"),
            eab_kid="kid-001-0123456789abcdef",
        )

        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(5):
            store.create_order_with_authz(
                account_id=account.id,
                identifiers=[{"type": "dns", "value": f"srv{i}.WORK-DOMAIN.local"}],
                challenge_url_fn=lambda cid: f"http://testserver/acme/challenge/{cid}",
                authz_url_fn=lambda aid: f"http://testserver/acme/authz/{aid}",
                finalize_url_fn=lambda oid: f"http://testserver/acme/finalize/{oid}",
            )
        with store._connect() as conn:
            conn.execute("UPDATE orders SET created_at = ?", (now_str,))

        within = now + timedelta(seconds=30)
        assert store.count_recent_orders_by_kid("kid-001-0123456789abcdef", 3600, now=within) == 5

        future = now + timedelta(seconds=7200)
        assert store.count_recent_orders_by_kid("kid-001-0123456789abcdef", 3600, now=future) == 0

    def test_count_all_recent_orders_with_injected_now(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(tmp_path, per_kid=100)
        _, store, _ = _make_app(config)

        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        a1 = store.create_account(
            jwk=placeholder_rsa_jwk("x1"), eab_kid="kid-001-0123456789abcdef",
        )
        a2 = store.create_account(
            jwk=placeholder_rsa_jwk("x2"), eab_kid="kid-002-0123456789abcdef",
        )
        for acct in (a1, a2):
            store.create_order_with_authz(
                account_id=acct.id,
                identifiers=[{"type": "dns", "value": "srv.WORK-DOMAIN.local"}],
                challenge_url_fn=lambda cid: f"http://t/c/{cid}",
                authz_url_fn=lambda aid: f"http://t/a/{aid}",
                finalize_url_fn=lambda oid: f"http://t/f/{oid}",
            )
        with store._connect() as conn:
            conn.execute("UPDATE orders SET created_at = ?", (now_str,))

        within = now + timedelta(seconds=30)
        assert store.count_all_recent_orders(3600, now=within) == 2

        future = now + timedelta(seconds=7200)
        assert store.count_all_recent_orders(3600, now=future) == 0

    def test_count_includes_multiple_accounts_same_kid(
        self, tmp_path: Path
    ) -> None:
        config = _make_rate_limit_config(tmp_path, per_kid=100)
        _, store, _ = _make_app(config)

        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(3):
            acct = store.create_account(
                jwk=placeholder_rsa_jwk(f"x{i}"), eab_kid="kid-001-0123456789abcdef",
            )
            store.create_order_with_authz(
                account_id=acct.id,
                identifiers=[{"type": "dns", "value": "srv.WORK-DOMAIN.local"}],
                challenge_url_fn=lambda cid: f"http://t/c/{cid}",
                authz_url_fn=lambda aid: f"http://t/a/{aid}",
                finalize_url_fn=lambda oid: f"http://t/f/{oid}",
            )
        with store._connect() as conn:
            conn.execute("UPDATE orders SET created_at = ?", (now_str,))

        within = now + timedelta(seconds=30)
        assert store.count_recent_orders_by_kid("kid-001-0123456789abcdef", 3600, now=within) == 3
        assert store.count_recent_orders_by_kid("kid-002-0123456789abcdef", 3600, now=within) == 0
