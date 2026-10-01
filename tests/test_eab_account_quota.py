"""Regression tests for the lifetime per-EAB account quota."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
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
from acme_adcs_ra.store import (
    AccountStatus,
    EabAccountLimitExceeded,
    Store,
)

from .conftest import placeholder_rsa_jwk
from .hand_rolled_acme_client import HandRolledAcmeClient

KID = "kid-001-0123456789abcdef"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
BASE_URL = "http://testserver"


def _mac_bytes() -> bytes:
    import base64

    return base64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))


def _audit() -> dict[str, Any]:
    return {
        "event_type": "account-created",
        "outcome": "success",
        "details": {"eab_kid": KID},
    }


def _create_account(
    store: Store,
    label: str,
    *,
    limit: int = 1,
) -> Any:
    return store.create_account_with_audit(
        jwk=placeholder_rsa_jwk(label),
        eab_kid=KID,
        audit=_audit(),
        max_accounts_per_eab_kid=limit,
    )


def _build_app(
    tmp_path: Path,
    *,
    limit: int = 1,
) -> tuple[TestClient, ServerContext]:
    config = RAConfig(
        base_url=BASE_URL,
        db_path=tmp_path / "ra.db",
        siem_jsonl_path=tmp_path / "ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=KID, mac_key=MAC_B64)],
        san_scopes={KID: {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        max_accounts_per_eab_kid=limit,
        nonce_rate_limit_per_second=0.0,
        admin_token=SecretStr("test-admin-token-0123456789abcdef-32+"),
    )
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid()),
        san_scopes={kid: scope.dns_patterns for kid, scope in config.san_scopes.items()},
        template=config.adcs_template,
    )
    context = ServerContext(
        config=config,
        store=store,
        policy=policy,
        enrollment=FakeEnrollmentLeg(),
        revocation=FakeRevocationLeg(),
    )
    return TestClient(create_app(context)), context


def test_config_default_and_floor() -> None:
    assert RAConfig().max_accounts_per_eab_kid == 1
    with pytest.raises(ValueError):
        RAConfig(max_accounts_per_eab_kid=0)


def test_store_enforces_lifetime_quota_and_exposes_current_count(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "ra.db")
    _create_account(store, "first")

    with pytest.raises(EabAccountLimitExceeded) as raised:
        _create_account(store, "second")

    exc = raised.value
    assert exc.kid == KID
    assert exc.limit == 1
    assert exc.count == 1
    assert len(store.list_audit_events(event_type="account-created")) == 1


def test_deactivation_does_not_free_lifetime_quota(tmp_path: Path) -> None:
    store = Store(tmp_path / "ra.db")
    account, _event = _create_account(store, "first")
    assert store.update_account_status(account.id, AccountStatus.DEACTIVATED)

    with pytest.raises(EabAccountLimitExceeded) as raised:
        _create_account(store, "second")

    assert raised.value.count == 1
    assert store.get_account(account.id).status == AccountStatus.DEACTIVATED


def test_account_and_created_audit_are_atomic_with_quota(tmp_path: Path) -> None:
    store = Store(tmp_path / "ra.db")
    with store._connect() as conn:
        conn.execute(
            "CREATE TRIGGER fail_account_audit BEFORE INSERT ON audit_log "
            "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"
        )

    with pytest.raises(sqlite3.IntegrityError):
        _create_account(store, "rolled-back")

    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
        conn.execute("DROP TRIGGER fail_account_audit")

    _create_account(store, "after-failure")
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_concurrent_distinct_jwks_cannot_exceed_quota(tmp_path: Path) -> None:
    db_path = tmp_path / "ra.db"
    store_count = 8
    stores = [Store(db_path) for _ in range(store_count)]
    start = threading.Barrier(store_count)

    def create(index: int) -> bool:
        start.wait()
        try:
            _create_account(stores[index], f"concurrent-{index}", limit=2)
        except EabAccountLimitExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=store_count) as executor:
        committed = list(executor.map(create, range(store_count)))

    assert sum(committed) == 2
    with stores[0]._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE eab_kid = ?", (KID,)
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type = 'account-created'"
        ).fetchone()[0] == 2


def test_route_returns_bad_eab_and_coalesces_quota_denials(
    tmp_path: Path,
) -> None:
    client, context = _build_app(tmp_path, limit=2)
    first = HandRolledAcmeClient(
        client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
    )
    second = HandRolledAcmeClient(
        client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
    )

    assert first.new_account(KID, _mac_bytes()).status_code == 201
    assert second.new_account(KID, _mac_bytes()).status_code == 201

    for _ in range(20):
        acme = HandRolledAcmeClient(
            client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
        )
        response = acme.new_account(KID, _mac_bytes())
        assert response.status_code == 400
        assert response.json()["type"] == (
            "urn:ietf:params:acme:error:badExternalAccountBinding"
        )

    quota_denials = [
        event
        for event in context.store.list_audit_events(
            event_type="account-creation-denied"
        )
        if event["details"].get("reason") == "eab-account-limit"
    ]
    assert len(quota_denials) == 1
    assert quota_denials[0]["details"]["denial_count"] == 20
    assert quota_denials[0]["details"]["limit"] == 2
    assert quota_denials[0]["details"]["count"] == 2
    assert len(context.store.list_audit_events(event_type="account-created")) == 2
