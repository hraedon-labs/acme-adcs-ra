"""Round 5 of the Daybreak reviews (2026-08-15): app-side findings.

The round's app finding: replayable authenticated requests could grow the
durable audit stores (SQLite rows + JSONL mirror) without bound, because
coalescing covered only the pre-authentication denial path and treated
"authenticated" as synonymous with "accountable". It is not: accountability
does not bound disk, and several authenticated paths are replayable at line
rate against unchanged server state:

* ``account-request-denied`` -- a deactivated or EAB-evicted account key still
  authenticates the JWS; the denial IS the point of the replay.
* ``order-rate-limited`` -- requests rejected *because* they exceed a cap are
  unbounded by definition; the limiter does not throttle the audit row.
* ``finalize-csr-mismatch`` / ``finalize-policy-denied`` -- cheap validation
  failures on an order that stays ``ready``.
* ``challenge-validated`` -- a challenge already ``valid`` is an idempotent
  operation; re-validating it rewrote identical state and re-audited per POST.

The fixes: those denial classes join the coalescing set (keyed additionally by
account/order so different accounts stay separable), and the challenge route
short-circuits an already-valid challenge with no writes and no audit row.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from acme_adcs_ra.audit_coalesce import COALESCED_EVENT_TYPES, DenialCoalescer
from acme_adcs_ra.store import Store
from tests.hand_rolled_acme_client import HandRolledAcmeClient
from tests.test_acme_server import _eab_mac_key, _make_test_config

KID = "0f" * 20


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _store(tmp_path: Path) -> Store:
    return Store(tmp_path / "ra.db")


def _rows(store: Store) -> list[sqlite3.Row]:
    con = sqlite3.connect(store._db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        return list(con.execute("SELECT * FROM audit_log ORDER BY id"))
    finally:
        con.close()


def _event(event_type: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"event_type": event_type, "outcome": "denied"}
    base.update(kw)
    return base


class TestReplayableAuthenticatedDenialsAreBounded:
    def test_a_deactivated_account_denial_storm_makes_one_row(
        self, tmp_path: Path
    ) -> None:
        """THE FINDING (account-request-denied leg).

        Mutation: drop the type from COALESCED_EVENT_TYPES, or remove
        account_id/order_id from the key and watch separability die.
        """
        assert "account-request-denied" in COALESCED_EVENT_TYPES
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(500):
            coalescer.record(
                store,
                **_event(
                    "account-request-denied",
                    account_id="acct-A",
                    details={"reason": "account-not-valid"},
                ),
            )

        rows = _rows(store)
        assert len(rows) == 1
        details = json.loads(rows[0]["details"])
        assert details["denial_count"] == 500
        assert rows[0]["account_id"] == "acct-A"

    def test_two_accounts_denials_stay_in_separate_rows(self, tmp_path: Path) -> None:
        """The account in the key keeps folded tallies attributable."""
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for acct in ("acct-A", "acct-B", "acct-A", "acct-B", "acct-A"):
            coalescer.record(
                store,
                **_event(
                    "account-request-denied",
                    account_id=acct,
                    details={"reason": "eab-kid-not-allowlisted"},
                ),
            )

        rows = _rows(store)
        assert len(rows) == 2
        assert {r["account_id"] for r in rows} == {"acct-A", "acct-B"}
        counts = {r["account_id"]: json.loads(r["details"])["denial_count"] for r in rows}
        assert counts == {"acct-A": 3, "acct-B": 2}

    def test_rate_limit_rejections_fold_per_account_and_scope(self, tmp_path: Path) -> None:
        """Every over-cap request is a rejection the limiter does not bound.

        The scope lands in the key via ``reason`` so per-account and global
        storms do not fold into one ambiguous row.
        """
        assert "order-rate-limited" in COALESCED_EVENT_TYPES
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(300):
            coalescer.record(
                store,
                **_event(
                    "order-rate-limited",
                    account_id="acct-A",
                    details={"reason": "per-account-limit", "limit": 10},
                ),
            )
        for _ in range(7):
            coalescer.record(
                store,
                **_event(
                    "order-rate-limited",
                    account_id="acct-A",
                    details={"reason": "global-limit", "limit": 100},
                ),
            )

        rows = _rows(store)
        assert len(rows) == 2
        counts = sorted(json.loads(r["details"])["denial_count"] for r in rows)
        assert counts == [7, 300]

    def test_finalize_validation_failures_fold_per_order(self, tmp_path: Path) -> None:
        """One account replaying one failing finalize folds; other orders do not."""
        assert "finalize-csr-mismatch" in COALESCED_EVENT_TYPES
        assert "finalize-policy-denied" in COALESCED_EVENT_TYPES
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())

        for _ in range(100):
            coalescer.record(
                store,
                **_event(
                    "finalize-csr-mismatch",
                    account_id="acct-A",
                    order_id="order-1",
                    details={"reason": "CSR SANs not in order identifiers"},
                ),
            )
        coalescer.record(
            store,
            **_event(
                "finalize-csr-mismatch",
                account_id="acct-A",
                order_id="order-2",
                details={"reason": "CSR SANs not in order identifiers"},
            ),
        )

        rows = _rows(store)
        assert len(rows) == 2
        assert {r["order_id"] for r in rows} == {"order-1", "order-2"}

    def test_accountable_events_still_one_row_each(self, tmp_path: Path) -> None:
        """The extension must not swallow accountable history.

        Mutation: coalesce every event type.
        """
        store = _store(tmp_path)
        coalescer = DenialCoalescer(60, clock=_Clock())
        for _ in range(5):
            coalescer.record(
                store,
                **_event(
                    "certificate-revoked",
                    account_id="acct-A",
                    order_id="order-1",
                    details={"reason": "same reason on purpose"},
                ),
            )
        assert len(_rows(store)) == 5


class TestChallengeReplayShortCircuit:
    @pytest.fixture()
    def replay_app_and_config(self, tmp_path: Path) -> tuple[Any, Any]:
        from acme_adcs_ra.enrollment import FakeEnrollmentLeg
        from acme_adcs_ra.policy import IssuancePolicy
        from acme_adcs_ra.revocation import FakeRevocationLeg
        from acme_adcs_ra.server import ServerContext, create_app

        config = _make_test_config(tmp_path)
        store = Store(config.db_path)
        policy = IssuancePolicy(
            allowed_kids=set(config.eab_keys_by_kid().keys()),
            san_scopes={kid: s.dns_patterns for kid, s in config.san_scopes.items()},
            template=config.adcs_template,
        )
        context = ServerContext(
            config=config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
            denial_coalescer=DenialCoalescer(3600, clock=_Clock()),
        )
        return create_app(context), config

    def test_replaying_a_valid_challenge_adds_no_audit_rows(
        self, tmp_path: Path, replay_app_and_config: tuple[Any, Any]
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from fastapi.testclient import TestClient

        app, config = replay_app_and_config
        client = TestClient(app)
        acme = HandRolledAcmeClient(
            http_client=client,
            base_url="http://testserver",
            account_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        )

        resp = acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(config, "kid-001-0123456789abcdef"))
        assert resp.status_code == 201
        resp = acme.new_order(["srv01.WORK-DOMAIN.local"])
        assert resp.status_code == 201
        authz_url = resp.json()["authorizations"][0]
        authz_resp = acme.get_authorization(authz_url)
        assert authz_resp.status_code == 200
        challenge_url = authz_resp.json()["challenges"][0]["url"]

        first = acme.validate_challenge(challenge_url)
        assert first.status_code == 200
        assert first.json()["status"] == "valid"

        con = sqlite3.connect(config.db_path, timeout=30)
        count_after_first = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type='challenge-validated'"
        ).fetchone()[0]
        assert count_after_first == 1

        # THE FINDING: each replay used to rewrite state and re-audit.
        for _ in range(25):
            replay = acme.validate_challenge(challenge_url)
            assert replay.status_code == 200
            assert replay.json()["status"] == "valid"

        count_after_replays = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type='challenge-validated'"
        ).fetchone()[0]
        con.close()
        assert count_after_replays == 1
