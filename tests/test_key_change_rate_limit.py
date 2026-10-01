"""14a: the keyChange endpoint had no rate, quota or cardinality check.

Daybreak 2026-08-17 Finding 1. Every other authenticated transition that a
valid credential can repeat is bounded; account-key rollover was not, so a
valid — or stolen — account key could chain rotations indefinitely, each one
writing a non-coalesced ``account-key-changed`` row. Retention bounds the
storage consequence of that; these tests are about the action itself.

The ceiling is per **EAB kid**, not per ACME account, for the reason the order
limiter documents: a leaked EAB credential must not be able to spread its
rotations across freshly minted account keys.
"""

from __future__ import annotations

import json
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
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient

MAC_KEY_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"


def _make_config(
    tmp_path: Path,
    *,
    key_change_limit: int,
    window: int = 3600,
    accounts_per_kid: int = 3,
) -> RAConfig:
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid="kid-001-0123456789abcdef", mac_key=MAC_KEY_B64)],
        san_scopes={"kid-001-0123456789abcdef": {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        max_accounts_per_eab_kid=accounts_per_kid,
        rate_limit_key_changes_per_window=key_change_limit,
        rate_limit_window_seconds=window,
        # The denial row is coalesced; keep the window open so the repeat-denial
        # test observes folding rather than one row per attempt.
        audit_denial_coalesce_window_seconds=60,
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


def _rsa_key() -> rsa.RSAPrivateKey:
    # 2048 is the smallest size the RA accepts; key generation dominates this
    # module's runtime and every test needs several.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _enrolled_client(
    client: TestClient, config: RAConfig, key: rsa.RSAPrivateKey
) -> HandRolledAcmeClient:
    acme = HandRolledAcmeClient(client, "http://testserver", key)
    mac_key = config.eab_key_bytes("kid-001-0123456789abcdef")
    assert mac_key is not None
    resp = acme.new_account("kid-001-0123456789abcdef", mac_key)
    assert resp.status_code == 201, resp.text
    return acme


def _rotate(
    client: TestClient,
    acme: HandRolledAcmeClient,
    new_key: rsa.RSAPrivateKey,
) -> tuple[Any, HandRolledAcmeClient]:
    """Rotate and return (response, a client bound to the new key).

    The hand-rolled client does not re-key itself, so a chain of rollovers
    needs a fresh client per link — the same move the happy-path test makes.
    """
    resp = acme.key_change(new_key)
    rotated = HandRolledAcmeClient(client, "http://testserver", new_key)
    rotated.account_url = acme.account_url
    return resp, rotated


class TestCeilingIsEnforced:
    def test_rollover_is_refused_at_the_ceiling(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, key_change_limit=2)
        app, store, _ = _make_app(config)
        client = TestClient(app)
        acme = _enrolled_client(client, config, _rsa_key())

        resp, acme = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 200
        resp, acme = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 200

        # Third rollover, same account, same window.
        third_key = _rsa_key()
        resp, _ = _rotate(client, acme, third_key)
        assert resp.status_code == 429
        body = resp.json()
        assert body["type"] == "urn:ietf:params:acme:error:rateLimited"
        assert "key change rate limit exceeded" in body["detail"]
        assert resp.headers["Retry-After"] == "3600"

        # The refusal is atomic: the key did NOT rotate. The second key still
        # authenticates and the refused third key does not.
        assert acme.new_order(["srv01.WORK-DOMAIN.local"]).status_code == 201
        refused = HandRolledAcmeClient(client, "http://testserver", third_key)
        refused.account_url = acme.account_url
        assert refused.new_order(["srv02.WORK-DOMAIN.local"]).status_code == 401

        # And no success row was written for the refused attempt.
        successes = store.list_audit_events(
            event_type="account-key-changed", limit=10
        )
        assert len(successes) == 2

    def test_limit_is_per_eab_kid_not_per_account(self, tmp_path: Path) -> None:
        """A leaked EAB credential cannot reset the ceiling with a new account."""
        config = _make_config(tmp_path, key_change_limit=2)
        app, _, _ = _make_app(config)
        client = TestClient(app)

        first = _enrolled_client(client, config, _rsa_key())
        resp, first = _rotate(client, first, _rsa_key())
        assert resp.status_code == 200
        resp, first = _rotate(client, first, _rsa_key())
        assert resp.status_code == 200

        # A DIFFERENT account, minted under the same kid, gets no fresh budget.
        second = _enrolled_client(client, config, _rsa_key())
        assert second.account_url != first.account_url
        resp, _ = _rotate(client, second, _rsa_key())
        assert resp.status_code == 429

    def test_zero_disables_the_limit(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, key_change_limit=0)
        app, _, _ = _make_app(config)
        client = TestClient(app)
        acme = _enrolled_client(client, config, _rsa_key())

        for _ in range(4):
            resp, acme = _rotate(client, acme, _rsa_key())
            assert resp.status_code == 200

    def test_window_is_rolling(self, tmp_path: Path) -> None:
        """Rollovers older than the window stop counting.

        Backdating the audit rows is the only way to move the clock here: the
        counter is the durable ``account-key-changed`` rows themselves, and the
        store stamps them from wall-clock UTC inside the transaction.
        """
        config = _make_config(tmp_path, key_change_limit=1, window=60)
        app, store, _ = _make_app(config)
        client = TestClient(app)
        acme = _enrolled_client(client, config, _rsa_key())

        resp, acme = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 200
        resp, _denied = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 429

        with store._connect() as conn:
            conn.execute(
                "UPDATE audit_log SET timestamp = '2020-01-01T00:00:00Z' "
                "WHERE event_type = 'account-key-changed'"
            )

        resp, _ = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 200


class TestDenialIsAccountable:
    def test_denial_is_audited_and_bounded(self, tmp_path: Path) -> None:
        """The denial is recorded — and coalesced, so it is not the new leak.

        A ceiling that writes one durable row per refused attempt would simply
        move 14a's unbounded growth from the success row to the denial row.
        """
        config = _make_config(tmp_path, key_change_limit=1)
        app, store, _ = _make_app(config)
        client = TestClient(app)
        acme = _enrolled_client(client, config, _rsa_key())

        resp, acme = _rotate(client, acme, _rsa_key())
        assert resp.status_code == 200

        for _ in range(3):
            resp, _ = _rotate(client, acme, _rsa_key())
            assert resp.status_code == 429

        denials = store.list_audit_events(
            event_type="key-change-rate-limited", limit=10
        )
        assert len(denials) == 1, "repeat denials must fold into one window"
        row = denials[0]
        assert row["outcome"] == "denied"
        details = row["details"]
        if isinstance(details, str):
            details = json.loads(details)
        assert details["reason"] == "per-account-limit"
        assert details["scope"] == "per-account"
        assert details["limit"] == 1
        assert details["window_seconds"] == 3600
        assert details["kid"] == "kid-001-0123456789abcdef"
        # ``count`` is the rollovers observed in the window (what tripped the
        # ceiling); ``denial_count`` is the coalescer's tally of folded
        # attempts. Every attempt is counted even though only one row exists.
        assert details["count"] == 1
        assert details["denial_count"] == 3


class TestConfigDefault:
    def test_the_limit_is_on_by_default(self) -> None:
        """14a is a defect fix, so the ceiling ships enabled, not opt-in."""
        assert RAConfig.model_fields["rate_limit_key_changes_per_window"].default == 5

    def test_negative_limits_are_refused(self) -> None:
        with pytest.raises(ValueError):
            RAConfig(
                base_url="http://testserver",
                rate_limit_key_changes_per_window=-1,
            )
