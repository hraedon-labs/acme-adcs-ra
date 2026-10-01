"""Regression tests: account eviction and the previously-missing ACME resources.

Two 2026-08-11 review findings are covered here.

**No way to disable a compromised account.** ``AccountRecord.status`` was
written as ``valid`` and never read, and the EAB kid was only re-checked inside
``IssuancePolicy`` at finalize. So pulling a kid from ``eab_allowlist`` — the
operator's credential-revocation action — stopped issuance but still left the
account able to create orders, roll its key, and *revoke its own live
certificates*. Both conditions are now enforced on every authenticated request.

**Advertised resource URLs 404'd.** newOrder's ``Location``, newAccount's
``Location`` and the account object's ``orders`` link had no handlers, so a
conforming client that polls the order URL could not complete.
"""

from __future__ import annotations

import base64
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
from acme_adcs_ra.store import AccountStatus, Store

from .hand_rolled_acme_client import HandRolledAcmeClient
from .test_acme_server import _make_csr

KID = "kid-001-0123456789abcdef"
MAC_B64 = "c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE"
BASE_URL = "http://testserver"
SAN = "srv01.WORK-DOMAIN.local"


def _mac_bytes() -> bytes:
    return base64.urlsafe_b64decode(MAC_B64 + "=" * ((-len(MAC_B64)) % 4))


def _build(tmp_path: Path) -> tuple[TestClient, ServerContext]:
    cfg = RAConfig(
        base_url=BASE_URL,
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[EABEntry(kid=KID, mac_key=MAC_B64)],
        san_scopes={KID: {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        max_accounts_per_eab_kid=2,
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
    return TestClient(create_app(ctx)), ctx


@pytest.fixture()
def env(tmp_path: Path) -> tuple[TestClient, ServerContext]:
    return _build(tmp_path)


def _account(env: tuple[TestClient, ServerContext]) -> HandRolledAcmeClient:
    client, _ctx = env
    acme = HandRolledAcmeClient(client, BASE_URL, ec.generate_private_key(ec.SECP256R1()))
    assert acme.new_account(KID, _mac_bytes()).status_code == 201
    return acme


def _issue_cert(acme: HandRolledAcmeClient) -> dict[str, Any]:
    """Drive a full round-trip and return the finalized order JSON."""
    order = acme.new_order([SAN]).json()
    authz = acme.get_authorization(order["authorizations"][0]).json()
    acme.validate_challenge(authz["challenges"][0]["url"])
    resp = acme.finalize_order(order["finalize"], _make_csr([SAN]))
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


# ---------------------------------------------------------------------------
# Account eviction
# ---------------------------------------------------------------------------


def test_pulling_the_eab_kid_blocks_new_orders(
    env: tuple[TestClient, ServerContext],
) -> None:
    """Removing a kid from the allowlist evicts accounts created under it."""
    acme = _account(env)
    _client, ctx = env
    assert acme.new_order([SAN]).status_code == 201

    ctx.config.eab_allowlist = []

    resp = acme.new_order([SAN])
    assert resp.status_code == 401, resp.text
    assert "no longer authorized" in resp.json()["detail"]


def test_pulling_the_eab_kid_blocks_revocation(
    env: tuple[TestClient, ServerContext],
) -> None:
    """The eviction must cover revokeCert, not just the issuance path.

    This is the case the pre-fix code missed entirely: an attacker holding a
    stolen account key could still revoke the victim's live certificates after
    the operator believed the credential was cut off.
    """
    acme = _account(env)
    _client, ctx = env
    order = _issue_cert(acme)
    # Download the cert via POST-as-GET while the account is still valid (the
    # plain GET form was removed — 2026-08-15 review, finding 4).
    cert_pem = acme.get_certificate(order["certificate"]).text
    cert_der = base64.b64decode(
        "".join(cert_pem.split("-----")[2].split())
    )

    ctx.config.eab_allowlist = []

    resp = acme.revoke_certificate(cert_der)
    assert resp.status_code == 401, resp.text
    assert "no longer authorized" in resp.json()["detail"]


def test_deactivated_account_cannot_act(
    env: tuple[TestClient, ServerContext],
) -> None:
    """RFC 8555 §7.3.6 deactivation is a one-way client-side kill switch."""
    acme = _account(env)
    resp = acme.deactivate_account()
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == AccountStatus.DEACTIVATED

    followup = acme.new_order([SAN])
    assert followup.status_code == 401, followup.text
    assert "deactivated" in followup.json()["detail"]


def test_deactivation_is_not_reversible(
    env: tuple[TestClient, ServerContext],
) -> None:
    """A deactivated account cannot re-activate itself."""
    acme = _account(env)
    assert acme.deactivate_account().status_code == 200
    # Any further request from the account — including another status change —
    # is refused before the payload is even considered.
    assert acme.deactivate_account().status_code == 401


def test_deactivation_audits(env: tuple[TestClient, ServerContext]) -> None:
    acme = _account(env)
    _client, ctx = env
    acme.deactivate_account()
    events = {e["event_type"] for e in ctx.store.list_audit_events()}
    assert "account-deactivated" in events

    acme.new_order([SAN])
    denied = [
        e for e in ctx.store.list_audit_events()
        if e["event_type"] == "account-request-denied"
    ]
    assert denied, "a request from a disabled account must be visible to SIEM"
    assert denied[0]["details"]["reason"] == "account-not-valid"


# ---------------------------------------------------------------------------
# Previously-missing resources
# ---------------------------------------------------------------------------


def test_order_location_url_resolves(env: tuple[TestClient, ServerContext]) -> None:
    """newOrder's Location header must point at a real resource (RFC 8555 §7.1.3)."""
    acme = _account(env)
    created = acme.new_order([SAN])
    order_url = created.headers["Location"]

    polled = acme.post_as_get(order_url)
    assert polled.status_code == 200, polled.text
    assert polled.json()["status"] == "pending"
    assert polled.json()["identifiers"] == [{"type": "dns", "value": SAN}]


def test_order_polling_reflects_completion(
    env: tuple[TestClient, ServerContext],
) -> None:
    """The poll-the-order-URL flow a conforming client uses after finalize."""
    acme = _account(env)
    created = acme.new_order([SAN])
    order_url = created.headers["Location"]
    order = created.json()
    authz = acme.get_authorization(order["authorizations"][0]).json()
    acme.validate_challenge(authz["challenges"][0]["url"])
    acme.finalize_order(order["finalize"], _make_csr([SAN]))

    polled = acme.post_as_get(order_url)
    assert polled.status_code == 200, polled.text
    assert polled.json()["status"] == "valid"
    assert "certificate" in polled.json()


def test_order_is_account_scoped(tmp_path: Path) -> None:
    """Another account's order is 404, not an oracle."""
    env = _build(tmp_path)
    first = _account(env)
    order_url = first.new_order([SAN]).headers["Location"]

    second = _account(env)
    resp = second.post_as_get(order_url)
    assert resp.status_code == 401, resp.text


def test_account_url_and_orders_list_resolve(
    env: tuple[TestClient, ServerContext],
) -> None:
    """newAccount's Location and the advertised orders link must both work."""
    acme = _account(env)
    account_url = str(acme.account_url)

    read = acme.post_as_get(account_url)
    assert read.status_code == 200, read.text
    assert read.json()["status"] == "valid"

    acme.new_order([SAN])
    orders = acme.post_as_get(read.json()["orders"])
    assert orders.status_code == 200, orders.text
    assert len(orders.json()["orders"]) == 1


def test_certificate_post_as_get_is_account_scoped(tmp_path: Path) -> None:
    """POST-as-GET for the cert closes the existence oracle the plain GET leaves."""
    env = _build(tmp_path)
    owner = _account(env)
    order = _issue_cert(owner)
    cert_url = order["certificate"]

    mine = owner.post_as_get(cert_url)
    assert mine.status_code == 200
    assert "BEGIN CERTIFICATE" in mine.text

    other = _account(env)
    theirs = other.post_as_get(cert_url)
    assert theirs.status_code == 401, theirs.text
