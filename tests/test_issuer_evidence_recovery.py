"""Issuer-evidence recovery for transport orphans (UNFILED item 25).

A certificate the CA issued but whose chain fetch failed is stored with its
leaf and an EMPTY chain. CRL evidence takes the issuing CA certificate from the
certificate's own stored chain, so such a row can never be CRL-confirmed — and
with ``require_crl_evidence=true`` that is permanent, for the population the RA
knows least about and that is live at the CA.

The fix recovers the missing *input* and then runs the existing verifier with no
exemptions. These tests are shaped around the two ways that could go wrong:

* recovering the WRONG issuer — which a name-based match does routinely, because
  an ADCS CA key renewal keeps the DN and changes the key. Every test that
  matters here therefore builds two CAs with an **identical subject** and asserts
  the one that actually signed is chosen;
* recovering material and then treating the recovery as if it settled something.
  It settles nothing: freshness, signature and monotonicity all still have to
  pass, and the certificate stays quarantined either way.

**Mutation-proved.** Each fix was reverted in turn and this file re-run:

* ``_direct_issuer``'s ``verify_directly_issued_by``, reduced to returning the
  first subject-name match → ``test_the_signing_generation_is_chosen_not_the_
  name_match`` and ``test_recovery_selects_the_generation_that_signed`` fail;
* fingerprint deduplication, changed to dedupe by subject →
  ``test_two_generations_of_one_dn_are_both_candidates`` fails;
* the compare-and-set in ``attach_recovered_chain_with_audit``, relaxed to a
  bare id match → ``test_an_existing_chain_is_never_overwritten`` fails;
* the ``issuer_missing`` flag on ``fetch_crl_evidence``'s no-issuer branch →
  ``test_a_missing_issuer_is_flagged_as_such`` and the denial-reason test fail;
* the ``details.get("quarantined") is not False`` discriminator, relaxed to
  ``not details.get("quarantined")`` →
  ``test_quarantined_orphans_are_not_reported_as_leafless`` fails. That test
  had to be strengthened to earn this line: the first version asserted only
  that a *quarantined* orphan stays out, which both forms already do, and it
  survived the mutation untouched.
"""

from __future__ import annotations

import datetime
import http.server
import threading
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr

from acme_adcs_ra.config import EABEntry, RAConfig
from acme_adcs_ra.crl_evidence import crl_watermark_key, fetch_crl_evidence
from acme_adcs_ra.enrollment import FakeEnrollmentLeg
from acme_adcs_ra.issuer_recovery import (
    certificate_fingerprint,
    collect_candidate_issuers,
    recover_issuer_chain,
)
from acme_adcs_ra.policy import IssuancePolicy
from acme_adcs_ra.revocation import FakeRevocationLeg
from acme_adcs_ra.routes.admin import ISSUER_EVIDENCE_MISSING
from acme_adcs_ra.server import ServerContext, create_app
from acme_adcs_ra.store import CertStatus, Store

_NOW = datetime.datetime.now(datetime.UTC)
_CONFIRM_TOKEN = "test-confirm-token-0123456789abcdef-32+"
_ADMIN_TOKEN = "test-admin-token-0123456789abcdef-32+"


# ---------------------------------------------------------------------------
# A CA that can be renewed under the same DN, and leaves it signed
# ---------------------------------------------------------------------------


class Ca:
    """One CA generation: a key, a self-signed certificate, and its leaves."""

    def __init__(self, common_name: str = "CONTOSO-CA01-CA") -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        )
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(self.name)
            .issuer_name(self.name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.key, hashes.SHA256())
        )

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def fingerprint(self) -> str:
        return certificate_fingerprint(self.cert)

    def issue(self, serial: int, cn: str = "srv01.WORK-DOMAIN.local") -> x509.Certificate:
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
            )
            .issuer_name(self.name)
            .public_key(leaf_key.public_key())
            .serial_number(serial)
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=30))
            .sign(self.key, hashes.SHA256())
        )

    def crl(self, *, number: int, serials: list[int]) -> bytes:
        last = _NOW - datetime.timedelta(minutes=5)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(last)
            .next_update(_NOW + datetime.timedelta(days=7))
            .add_extension(x509.CRLNumber(number), critical=False)
        )
        for serial in serials:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(last)
                .build()
            )
        return builder.sign(self.key, hashes.SHA256()).public_bytes(
            serialization.Encoding.DER
        )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _serve(body: bytes) -> tuple[str, Any]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/ca.crl", server.shutdown


# ---------------------------------------------------------------------------
# Selection: by signature, never by name
# ---------------------------------------------------------------------------


class TestCandidateSelection:
    def test_the_signing_generation_is_chosen_not_the_name_match(self) -> None:
        """Two CAs, one DN, one signature. Only the signature can tell them apart.

        This is the ADCS case that made ``_issuing_ca_certificate`` select by
        signature in the first place: a CA key renewal keeps the subject DN and
        changes the key, so a store holding both generations offers two equally
        good name matches and exactly one of them is right.
        """
        old = Ca()
        new = Ca()  # same CN, different key
        assert old.cert.subject == new.cert.subject
        leaf = old.issue(0x1111)

        # Deliberately offer the wrong generation FIRST, so a first-name-match
        # implementation picks it.
        outcome = recover_issuer_chain(
            _pem(leaf), [("newer-cert", [new.pem]), ("older-cert", [old.pem])]
        )
        assert outcome.recovered
        assert outcome.fingerprints == [old.fingerprint]
        assert outcome.source_certificate_ids == ["older-cert"]

    def test_two_generations_of_one_dn_are_both_candidates(self) -> None:
        """Dedup by fingerprint, not by subject.

        Collapsing by name here would discard one of the two generations, and
        it is a coin flip which — including, half the time, the one that signed
        the orphan.
        """
        old, new = Ca(), Ca()
        candidates, rows, truncated = collect_candidate_issuers(
            [("a", [old.pem]), ("b", [new.pem])]
        )
        assert {c.fingerprint for c in candidates} == {old.fingerprint, new.fingerprint}
        assert rows == 2
        assert truncated is False

    def test_the_same_ca_seen_a_hundred_times_is_one_candidate(self) -> None:
        ca = Ca()
        candidates, rows, _ = collect_candidate_issuers(
            [(f"cert-{i}", [ca.pem]) for i in range(100)]
        )
        assert len(candidates) == 1
        assert rows == 100

    def test_a_chain_is_walked_to_its_root(self) -> None:
        """Every link is signature-verified, so a returned path is an honest one."""
        root = Ca("CONTOSO-ROOT-CA")
        issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuing_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")]
        )
        issuing = (
            x509.CertificateBuilder()
            .subject_name(issuing_name)
            .issuer_name(root.name)
            .public_key(issuing_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(root.key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "srv02.example")])
            )
            .issuer_name(issuing_name)
            .public_key(leaf_key.public_key())
            .serial_number(0x2222)
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=30))
            .sign(issuing_key, hashes.SHA256())
        )
        outcome = recover_issuer_chain(
            _pem(leaf), [("healthy", [_pem(issuing), root.pem])]
        )
        assert outcome.fingerprints == [
            certificate_fingerprint(issuing),
            root.fingerprint,
        ]

    def test_a_cold_store_says_so_rather_than_just_failing(self) -> None:
        """"Nothing to recover from" and "nothing matched" are different facts.

        A check whose failure mode is silence cannot tell being wrong from
        being aimed at nothing; the outcome reports how far it looked so the
        two cannot be read as the same result.
        """
        ca = Ca()
        outcome = recover_issuer_chain(_pem(ca.issue(0x3333)), [])
        assert not outcome.recovered
        assert outcome.rows_scanned == 0
        assert outcome.candidates_considered == 0
        assert "nothing" in outcome.detail

    def test_a_foreign_ca_does_not_match_and_the_count_is_reported(self) -> None:
        stranger = Ca("OTHER-CA")
        mine = Ca()
        outcome = recover_issuer_chain(
            _pem(mine.issue(0x4444)), [("x", [stranger.pem])]
        )
        assert not outcome.recovered
        assert outcome.candidates_considered == 1
        assert outcome.rows_scanned == 1
        assert "signed this certificate" in outcome.detail

    def test_a_malformed_chain_entry_does_not_abandon_the_search(self) -> None:
        ca = Ca()
        leaf = ca.issue(0x5555)
        outcome = recover_issuer_chain(
            _pem(leaf), [("broken", ["-----BEGIN CERTIFICATE-----\nnope\n"]),
                         ("good", [ca.pem])]
        )
        assert outcome.recovered
        assert outcome.fingerprints == [ca.fingerprint]

    def test_the_scan_reports_when_a_bound_stopped_it(self) -> None:
        ca = Ca()
        outcome = recover_issuer_chain(
            _pem(ca.issue(0x6666)),
            [(f"c-{i}", [Ca(f"FILLER-{i}").pem]) for i in range(4)] + [("real", [ca.pem])],
            max_rows=2,
        )
        assert not outcome.recovered
        assert outcome.truncated is True
        assert outcome.rows_scanned == 2


# ---------------------------------------------------------------------------
# The store side: fill an empty chain, never overwrite one
# ---------------------------------------------------------------------------


def _quarantine(store: Store, cert: x509.Certificate, chain: list[str]) -> Any:
    record, _event = store.quarantine_certificate(
        order_id=f"order-{cert.serial_number:x}",
        account_id="acct-1",
        cert_pem=_pem(cert),
        chain_pem=chain,
        template="ACME-ServerAuth",
        requester="",
        metadata={"req_id": "761"},
        event_type="finalize-enrollment-transport-orphan",
        violations=["chain fetch failed"],
        reason="the CA issued it but the RA could not complete enrollment",
        sans=["srv01.WORK-DOMAIN.local"],
        extra_details={"ca_issued": True},
    )
    return record


def _set_issued_at(store: Store, cert_id: str, stamp: str) -> None:
    """Pin a row's ``issued_at`` so candidate ORDER is deterministic.

    ``list_certificate_chains`` returns newest first and ``_now_iso`` has
    one-second resolution, so two rows written in the same test tie and fall
    back to a random uuid. A test that means "the WRONG generation is offered
    first" has to say so rather than hope for it — otherwise it passes half the
    time against a name-matching implementation, which is worse than not
    testing it at all.
    """
    import sqlite3

    with sqlite3.connect(str(store._db_path)) as conn:
        conn.execute(
            "UPDATE certificates SET issued_at = ? WHERE id = ?", (stamp, cert_id)
        )


class TestStoreRecovery:
    def test_an_empty_chain_is_filled_and_audited_together(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "ra.db")
        ca = Ca()
        record = _quarantine(store, ca.issue(0x7777), [])
        assert record.chain_pem == []

        updated, event = store.attach_recovered_chain_with_audit(
            record.id,
            chain_pem=[ca.pem],
            event_type="revocation-issuer-evidence-recovered",
            outcome="success",
            details={"issuer_fingerprints": [ca.fingerprint]},
        )
        assert updated is not None and event is not None
        assert updated.chain_pem == [ca.pem]
        assert store.get_certificate(record.id).chain_pem == [ca.pem]  # type: ignore[union-attr]
        events = store.list_audit_events(
            event_type="revocation-issuer-evidence-recovered"
        )
        assert len(events) == 1
        assert events[0]["details"]["issuer_fingerprints"] == [ca.fingerprint]

    def test_an_existing_chain_is_never_overwritten(self, tmp_path: Path) -> None:
        """Recovered material must never displace what the CA actually returned.

        This is also the concurrency guard: two confirmations racing on one
        certificate cannot both write, and the loser learns it lost.
        """
        store = Store(tmp_path / "ra.db")
        ca, other = Ca(), Ca("SOMEONE-ELSE-CA")
        record = _quarantine(store, ca.issue(0x8888), [ca.pem])

        updated, event = store.attach_recovered_chain_with_audit(
            record.id,
            chain_pem=[other.pem],
            event_type="revocation-issuer-evidence-recovered",
            outcome="success",
        )
        assert (updated, event) == (None, None)
        assert store.get_certificate(record.id).chain_pem == [ca.pem]  # type: ignore[union-attr]
        # No audit row either: nothing happened, so nothing is claimed.
        assert store.list_audit_events(
            event_type="revocation-issuer-evidence-recovered"
        ) == []

    def test_chains_with_no_material_are_not_offered_as_a_source(
        self, tmp_path: Path
    ) -> None:
        store = Store(tmp_path / "ra.db")
        ca = Ca()
        _quarantine(store, ca.issue(0x9990), [])
        _quarantine(store, ca.issue(0x9991), [ca.pem])
        chains = store.list_certificate_chains()
        assert len(chains) == 1
        assert chains[0][1] == [ca.pem]


# ---------------------------------------------------------------------------
# The evidence layer: a missing issuer is a distinct, permanent condition
# ---------------------------------------------------------------------------


class TestEvidenceFlag:
    def test_a_missing_issuer_is_flagged_as_such(self) -> None:
        """Distinguished from every other "no evidence" because it never retries out.

        An unreachable CDP is a bad afternoon. A missing issuer is a permanent
        wedge under ``require_crl_evidence``, and a trail that spells them the
        same way hides the only one that needs an operator.
        """
        ca = Ca()
        leaf = ca.issue(0xAAAA)
        url, shutdown = _serve(ca.crl(number=10, serials=[0xAAAA]))
        try:
            evidence = fetch_crl_evidence(
                crl_url=url,
                serial_number=0xAAAA,
                cert_pem=_pem(leaf),
                chain_pem=[],
            )
        finally:
            shutdown()
        assert evidence.issuer_missing is True
        assert evidence.checked is False
        assert evidence.revoked is False

    def test_a_present_issuer_is_not_flagged(self) -> None:
        ca = Ca()
        leaf = ca.issue(0xBBBB)
        url, shutdown = _serve(ca.crl(number=10, serials=[0xBBBB]))
        try:
            evidence = fetch_crl_evidence(
                crl_url=url,
                serial_number=0xBBBB,
                cert_pem=_pem(leaf),
                chain_pem=[ca.pem],
            )
        finally:
            shutdown()
        assert evidence.issuer_missing is False
        assert evidence.revoked is True


# ---------------------------------------------------------------------------
# End to end, through the confirmation route
# ---------------------------------------------------------------------------


def _config(tmp_path: Path, *, crl_url: str = "", require: bool = False) -> RAConfig:
    return RAConfig(
        base_url="http://testserver",
        db_path=tmp_path / "test_ra.db",
        siem_jsonl_path=tmp_path / "test_ra.siem.jsonl",
        eab_allowlist=[
            EABEntry(kid="kid-001", mac_key="c3VwZXItc2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISE")
        ],
        san_scopes={"kid-001": {"dns_patterns": ["*.WORK-DOMAIN.local"]}},
        adcs_template="ACME-ServerAuth",
        admin_token=SecretStr(_ADMIN_TOKEN),
        revocation_confirm_token=SecretStr(_CONFIRM_TOKEN),
        revocation_confirm_crl_url=crl_url,
        revocation_confirm_require_crl_evidence=require,
    )


def _app(config: RAConfig) -> Any:
    store = Store(config.db_path)
    policy = IssuancePolicy(
        allowed_kids=set(config.eab_keys_by_kid().keys()),
        san_scopes={
            kid: scope.dns_patterns for kid, scope in config.san_scopes.items()
        },
        template=config.adcs_template,
    )
    return create_app(
        ServerContext(
            config=config,
            store=store,
            policy=policy,
            enrollment=FakeEnrollmentLeg(),
            revocation=FakeRevocationLeg(),
        )
    )


class TestConfirmPathRecovery:
    def test_recovery_selects_the_generation_that_signed(self, tmp_path: Path) -> None:
        """The whole path: an orphan is repaired from another row and confirms.

        The store deliberately holds BOTH generations of the CA under one DN,
        and the CRL is signed by the older one — so a name-based recovery
        installs a chain whose key does not verify the CRL, and the
        confirmation still fails. Only selection by signature gets here.
        """
        old, new = Ca(), Ca()
        orphan_serial = 0xC0FFEE
        orphan = old.issue(orphan_serial)
        url, shutdown = _serve(old.crl(number=42, serials=[orphan_serial]))
        try:
            config = _config(tmp_path, crl_url=url, require=True)
            app = _app(config)
            store = Store(config.db_path)
            # A healthy issuance from the NEW generation, and one from the old:
            # both are legitimate stored chains from this CA.
            wrong = _quarantine(store, new.issue(0xD001), [new.pem])
            healthy = _quarantine(store, old.issue(0xD002), [old.pem])
            record = _quarantine(store, orphan, [])
            assert record.chain_pem == []
            # Offer the wrong generation FIRST. Without this the two rows tie on
            # a one-second timestamp and the order is a coin flip, so a
            # name-matching implementation would pass half the time.
            _set_issued_at(store, wrong.id, "2030-01-01T00:00:00Z")
            _set_issued_at(store, healthy.id, "2020-01-01T00:00:00Z")

            client = TestClient(app)
            resp = client.post(
                f"/acme/admin/revocations/{record.serial_number}/confirm",
                headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
            )
        finally:
            shutdown()

        assert resp.status_code == 200, resp.text
        assert resp.json()["verification"] == "crl-verified"

        repaired = store.get_certificate(record.id)
        assert repaired is not None
        assert repaired.chain_pem == [old.pem]
        # Requirement 4: recovery and confirmation are evidence facts. Neither
        # un-quarantines the certificate.
        assert repaired.status == CertStatus.QUARANTINED
        assert repaired.ca_crl_updated is True
        # The recovered chain is the one the CRL verifies against.
        assert crl_watermark_key(repaired.cert_pem, repaired.chain_pem) is not None

        events = store.list_audit_events(
            event_type="revocation-issuer-evidence-recovered"
        )
        assert len(events) == 1
        details = events[0]["details"]
        assert details["issuer_fingerprints"] == [old.fingerprint]
        assert details["issuer_source"] == "stored-chain"
        # Requirement 2: where the material came from is part of the evidence.
        assert details["source_certificate_ids"] == [healthy.id]
        assert details["candidates_considered"] == 2

    def test_an_unrecoverable_orphan_is_denied_with_its_own_reason(
        self, tmp_path: Path
    ) -> None:
        """Requirement 3, the part that must not wait on the rest.

        Nothing in the store signed this leaf, so the certificate stays blocked
        — and the denial has to say *that*, not the generic "no evidence" it
        shares with an unreachable CDP.
        """
        mine, stranger = Ca(), Ca("OTHER-CA")
        orphan_serial = 0xBADBAD
        orphan = mine.issue(orphan_serial)
        url, shutdown = _serve(stranger.crl(number=9, serials=[orphan_serial]))
        try:
            config = _config(tmp_path, crl_url=url, require=True)
            app = _app(config)
            store = Store(config.db_path)
            _quarantine(store, stranger.issue(0xE001), [stranger.pem])
            record = _quarantine(store, orphan, [])
            client = TestClient(app)
            resp = client.post(
                f"/acme/admin/revocations/{record.serial_number}/confirm",
                headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
            )
        finally:
            shutdown()

        assert resp.status_code == 400
        denials = store.list_audit_events(event_type="admin-revocation-confirm-denied")
        assert denials, "the denial must be recorded"
        assert denials[0]["details"]["reason_code"] == ISSUER_EVIDENCE_MISSING
        assert denials[0]["details"]["recovery_action"]
        # The serial stays owed: refusing to confirm must not drain the queue.
        assert store.get_certificate(record.id).ca_crl_updated is False  # type: ignore[union-attr]

        attempts = store.list_audit_events(
            event_type="revocation-issuer-evidence-recovery"
        )
        assert len(attempts) == 1
        assert attempts[0]["details"]["candidates_considered"] == 1
        assert attempts[0]["details"]["chains_scanned"] == 1

    def test_the_audit_literal_matches_the_constant(self) -> None:
        """The coalescing key must be a source literal; this pins it to its name.

        Same guard as ``CRL_EVIDENCE_REGRESSED``: the literal is what
        tests/test_audit_coalescing_enumeration.py can prove is server-chosen,
        and this assertion is what stops the two spellings drifting apart in
        silence.
        """
        assert ISSUER_EVIDENCE_MISSING == "issuer-evidence-missing"
        source = Path("src/acme_adcs_ra/routes/admin.py").read_text()
        assert source.count('"reason_code": "issuer-evidence-missing"') == 2


# ---------------------------------------------------------------------------
# Visibility: the blocked state, and the class that has no automated path
# ---------------------------------------------------------------------------


class TestPendingFeedVisibility:
    def test_a_blocked_row_is_labelled_and_a_healthy_one_is_not(
        self, tmp_path: Path
    ) -> None:
        config = _config(tmp_path)
        app = _app(config)
        store = Store(config.db_path)
        ca = Ca()
        _quarantine(store, ca.issue(0xF001), [ca.pem])
        _quarantine(store, ca.issue(0xF002), [])

        body = TestClient(app).get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
        ).json()
        by_serial = {e["serial"]: e for e in body["pending_revocations"]}
        assert len(by_serial) == 2
        blocked = by_serial["F002"]
        assert blocked["blocked_reason"] == ISSUER_EVIDENCE_MISSING
        assert blocked["issuer_evidence"] == "missing"
        assert "ReqID" in blocked["recovery_action"]
        # The positive claim is only ever made where it is true.
        assert "blocked_reason" not in by_serial["F001"]

    def test_leafless_incidents_are_listed_separately(self, tmp_path: Path) -> None:
        """Requirement 5: no certificate row, no serial, no automated path.

        Folding these into ``pending_revocations`` would hand the sync agent
        something it cannot act on and hide that a human must.
        """
        config = _config(tmp_path)
        app = _app(config)
        store = Store(config.db_path)
        store.record_audit(
            event_type="finalize-enrollment-transport-orphan",
            order_id="order-leafless",
            outcome="failed",
            details={
                "error": "the chain fetch timed out",
                "ca_issued": True,
                "req_id": "812",
                "quarantined": False,
                "reason": "the CA issued but the RA never received the bytes",
            },
        )

        body = TestClient(app).get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
        ).json()
        assert body["pending_revocations"] == []
        assert body["leafless_incidents_truncated"] is False
        assert len(body["leafless_incidents"]) == 1
        incident = body["leafless_incidents"][0]
        assert incident["req_id"] == "812"
        assert incident["order_id"] == "order-leafless"
        assert "ReqID" in incident["recovery_action"]

    def test_quarantined_orphans_are_not_reported_as_leafless(
        self, tmp_path: Path
    ) -> None:
        """The two classes need different operator actions and must not merge.

        A quarantined transport orphan writes the SAME audit event type — the
        store's quarantine writer sets ``quarantined: True`` — so the event
        type alone cannot separate them.

        The second row is the one that makes ``is False`` load-bearing rather
        than stylistic: an event of this type that states nothing about
        quarantine is not evidence that no row was written, and a falsy test
        reads it as exactly that. Listing it would tell an operator to go and
        revoke by ReqID at the CA on the strength of a missing key.
        """
        config = _config(tmp_path)
        app = _app(config)
        store = Store(config.db_path)
        ca = Ca()
        _quarantine(store, ca.issue(0xF003), [])
        store.record_audit(
            event_type="finalize-enrollment-transport-orphan",
            order_id="order-says-nothing",
            outcome="failed",
            details={"error": "something else", "req_id": "999"},
        )

        body = TestClient(app).get(
            "/acme/admin/revocations/pending",
            headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
        ).json()
        assert len(body["pending_revocations"]) == 1
        assert body["leafless_incidents"] == []

    def test_polling_the_leafless_view_writes_no_audit_rows(
        self, tmp_path: Path
    ) -> None:
        """These never drain, so counting them as work is unbounded growth.

        The 2026-08-25 fix skipped the audit row on an empty poll precisely to
        stop benign forever-growth; an incident class that is permanent by
        construction would undo it in the other direction.
        """
        config = _config(tmp_path)
        app = _app(config)
        store = Store(config.db_path)
        store.record_audit(
            event_type="finalize-enrollment-transport-orphan",
            order_id="order-leafless",
            outcome="failed",
            details={"req_id": "813", "quarantined": False, "ca_issued": True},
        )
        client = TestClient(app)
        for _ in range(5):
            client.get(
                "/acme/admin/revocations/pending",
                headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
            )
        assert store.list_audit_events(
            event_type="admin-list-pending-revocations"
        ) == []


# ---------------------------------------------------------------------------
# Recovery repairs the input and decides nothing
# ---------------------------------------------------------------------------


class TestRecoveryGrantsNoExemption:
    def test_an_expired_crl_is_still_refused_after_recovery(
        self, tmp_path: Path
    ) -> None:
        """Requirement 3 of the item: no exemptions, on any check.

        The chain is recovered — provably, the row is repaired — and the
        confirmation still fails, because the document is stale. Finding an
        issuer is evidence repair, not revocation confirmation.
        """
        ca = Ca()
        orphan_serial = 0xDEAD01
        orphan = ca.issue(orphan_serial)
        stale = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.name)
            .last_update(_NOW - datetime.timedelta(days=40))
            .next_update(_NOW - datetime.timedelta(days=1))
            .add_extension(x509.CRLNumber(3), critical=False)
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(orphan_serial)
                .revocation_date(_NOW - datetime.timedelta(days=40))
                .build()
            )
            .sign(ca.key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        url, shutdown = _serve(stale)
        try:
            config = _config(tmp_path, crl_url=url, require=True)
            app = _app(config)
            store = Store(config.db_path)
            _quarantine(store, ca.issue(0xD003), [ca.pem])
            record = _quarantine(store, orphan, [])
            resp = TestClient(app).post(
                f"/acme/admin/revocations/{record.serial_number}/confirm",
                headers={"Authorization": f"Bearer {_CONFIRM_TOKEN}"},
            )
        finally:
            shutdown()

        assert resp.status_code == 400
        repaired = store.get_certificate(record.id)
        assert repaired is not None and repaired.chain_pem == [ca.pem]
        assert repaired.ca_crl_updated is False
        denials = store.list_audit_events(event_type="admin-revocation-confirm-denied")
        assert denials[0]["details"]["reason_code"] == "crl-evidence-required-but-absent"
        assert "expired" in denials[0]["details"]["crl_detail"]
