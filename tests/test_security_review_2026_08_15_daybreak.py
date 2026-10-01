"""Daybreak 2026-08-15 post-validation review: audit-atomicity regressions.

Two low findings, one root cause: a state change committed first and its audit
row second, so a failure in between left a durable change with no record —

* newAccount committed the account, then wrote ``account-created`` (the row
  that ties an account to the EAB kid that minted it);
* keyChange committed the rotation, then wrote ``account-key-changed`` (the
  only row naming the *new* key's thumbprint).

Both now commit state and audit in one transaction
(``create_account_with_audit`` / ``update_account_key_with_audit``), the same
fix shape v1.9 applied to issuance (``record_issuance``).

The tests below fault-inject with a SQLite trigger that aborts every
``audit_log`` INSERT and assert the STATE change rolled back with it. Against
the pre-fix code — two separate commits — the account/rotation persists and
these tests fail, which is the point: a test that cannot fail against the
vulnerable code is not evidence (a lesson recorded twice in the validation log).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import Store

from .hand_rolled_acme_client import HandRolledAcmeClient, jwk_from_private_key

KID = "kid-001-0123456789abcdef"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
BASE_URL = "http://testserver"


def _mac_bytes() -> bytes:
    import base64

    return base64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))


def _build(tmp_path: Path) -> tuple[TestClient, ServerContext]:
    cfg = RAConfig(
        base_url=BASE_URL,
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
    # raise_server_exceptions=False: the fault-injected requests below must be
    # observed as 500 RESPONSES, not re-raised in the test process — what the
    # caller sees is the thing being asserted on.
    return TestClient(create_app(ctx), raise_server_exceptions=False), ctx


@pytest.fixture()
def env(tmp_path: Path) -> tuple[TestClient, ServerContext]:
    return _build(tmp_path)


_FAIL_AUDIT_TRIGGER = (
    "CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"
)


def _db(ctx: ServerContext) -> sqlite3.Connection:
    con = sqlite3.connect(ctx.config.db_path, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def _install_trigger(con: sqlite3.Connection) -> None:
    con.execute(_FAIL_AUDIT_TRIGGER)
    con.commit()


def _drop_trigger(con: sqlite3.Connection) -> None:
    con.execute("DROP TRIGGER fail_audit_insert")
    con.commit()


class TestNewAccountAtomicWithAudit:
    def test_account_rolls_back_when_the_audit_row_cannot_be_written(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        client, ctx = env
        con = _db(ctx)
        accounts_before = con.execute("SELECT COUNT(*) c FROM accounts").fetchone()[
            "c"
        ]
        _install_trigger(con)

        acme = HandRolledAcmeClient(
            client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
        )
        resp = acme.new_account(KID, _mac_bytes())

        # The injected failure surfaces as a server error, not a silent gap.
        assert resp.status_code >= 500
        # ...and NOTHING was committed: no account row (the pre-fix code left
        # one — the account existed with no provenance), no audit row.
        assert (
            con.execute("SELECT COUNT(*) c FROM accounts").fetchone()["c"]
            == accounts_before
        )
        assert (
            con.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE event_type='account-created'"
            ).fetchone()["c"]
            == 0
        )

        # The same request succeeds once the fault is gone, and then leaves
        # BOTH rows — proving the trigger (not the request) was the failure.
        _drop_trigger(con)
        assert acme.new_account(KID, _mac_bytes()).status_code == 201
        assert (
            con.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE event_type='account-created'"
            ).fetchone()["c"]
            == 1
        )
        con.close()

    def test_success_path_writes_account_and_audit_together(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        client, ctx = env
        acme = HandRolledAcmeClient(
            client, BASE_URL, ec.generate_private_key(ec.SECP256R1())
        )
        resp = acme.new_account(KID, _mac_bytes())
        assert resp.status_code == 201
        con = _db(ctx)
        assert con.execute("SELECT COUNT(*) c FROM accounts").fetchone()["c"] == 1
        assert (
            con.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE event_type='account-created'"
            ).fetchone()["c"]
            == 1
        )
        con.close()

    def test_audit_mapping_may_not_carry_account_id(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        _client, ctx = env
        from tests.conftest import placeholder_rsa_jwk

        with pytest.raises(ValueError, match="account_id"):
            ctx.store.create_account_with_audit(
                jwk=placeholder_rsa_jwk("daybreak-guard"),
                eab_kid=KID,
                audit={
                    "event_type": "account-created",
                    "outcome": "success",
                    "account_id": "smuggled",
                    "details": {},
                },
            )


class TestKeyChangeAtomicWithAudit:
    def test_rotation_rolls_back_when_the_audit_row_cannot_be_written(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        client, ctx = env
        old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        acme = HandRolledAcmeClient(client, BASE_URL, old_key)
        assert acme.new_account(KID, _mac_bytes()).status_code == 201
        con = _db(ctx)
        thumb_before = con.execute(
            "SELECT jwk_thumbprint t FROM accounts"
        ).fetchone()["t"]
        _install_trigger(con)

        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        resp = acme.key_change(new_key)

        assert resp.status_code >= 500
        # The rotation did NOT commit: the account still resolves by the OLD
        # key's thumbprint (pre-fix code had already rotated it, silently).
        row = con.execute("SELECT jwk_thumbprint t FROM accounts").fetchone()
        assert row["t"] == thumb_before
        assert ctx.store.get_account_by_jwk(
            jwk_from_private_key(old_key)
        ) is not None
        assert ctx.store.get_account_by_jwk(
            jwk_from_private_key(new_key)
        ) is None
        assert (
            con.execute(
                "SELECT COUNT(*) c FROM audit_log "
                "WHERE event_type='account-key-changed'"
            ).fetchone()["c"]
            == 0
        )

        _drop_trigger(con)
        assert acme.key_change(new_key).status_code == 200
        assert (
            con.execute(
                "SELECT COUNT(*) c FROM audit_log "
                "WHERE event_type='account-key-changed'"
            ).fetchone()["c"]
            == 1
        )
        con.close()

    def test_audit_mapping_may_not_carry_account_id(
        self, env: tuple[TestClient, ServerContext]
    ) -> None:
        _client, ctx = env
        from tests.conftest import placeholder_rsa_jwk

        with pytest.raises(ValueError, match="account_id"):
            ctx.store.update_account_key_with_audit(
                "any",
                placeholder_rsa_jwk("daybreak-guard-2"),
                expected_old_thumbprint="old-thumbprint",
                audit={
                    "event_type": "account-key-changed",
                    "outcome": "success",
                    "account_id": "smuggled",
                    "details": {},
                },
            )
