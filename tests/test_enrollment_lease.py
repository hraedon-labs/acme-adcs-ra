"""Regression tests for the enrollment lease (2026-08-15 rescan, DIFF-RECLAIM-001).

The rescan of the 2026-08-15 hardening branch found that the ``ActiveEnrollments``
mark was *nested inside the worker*: it was taken after the ``ready``→``processing``
CAS and after the threadpool hand-off, and released before the certificate row was
written. Two gaps followed, and in both of them a reclaim could truthfully observe
"no live worker, no certificate" and reopen the order for a second CA issuance:

1. **The queue gap.** A finalize whose task is still queued behind a saturated
   threadpool has already committed the order to ``processing`` but is invisible
   to the registry. Past the reclaim age floor an operator can verify at the CA
   that nothing was issued, reclaim to ``ready``, and a second finalize can take
   the order — after which *both* the stale queued task and the new one submit
   the same order to ADCS.
2. **The completion gap.** The mark ended when the worker returned, before
   ``_finalize_complete`` wrote the certificate row.

The fix has two halves and this file pins both:

* the mark is taken in the *route*, around the CAS, the hand-off and the
  completion, so no part of the in-flight interval is unmarked (tests A, B); and
* a durable ``processing_generation`` lease in the store, re-checked immediately
  before the CA is touched, so a stale task cannot submit even if the
  process-local mark is wrong or absent (tests C onward).

Every test here was mutation-checked: the corresponding fix was reverted in turn
and the test confirmed to fail. See docs/security-review-2026-08-15-rescan.md.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from acme_adcs_ra.acme_errors import AcmeError
from acme_adcs_ra.enrollment import EnrollmentResult, FakeEnrollmentLeg
from acme_adcs_ra.jws import jwk_thumbprint
from acme_adcs_ra.store import OrderStatus, Store

from .test_security_review_2026_08_14 import (
    _ADMIN_TOKEN,
    _app_with_leg,
    _backdate_processing,
    _drive_order_to_finalize,
    _seed_processing_order,
)

_TIMEOUT = 30.0


class _CountingLeg(FakeEnrollmentLeg):
    """A working enrollment leg that counts how often the CA was asked to issue.

    The whole point of the lease is that a stale caller never reaches this, so
    ``calls`` is the assertion that matters: not "the second issuance was tidied
    up afterwards" but "the CA was never asked a second time".
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0
        self.seen_order_generations: list[int] = []

    def submit_csr(
        self, csr_pem: str, *, account_id: str, requested_sans: Any
    ) -> EnrollmentResult:
        self.calls += 1
        return super().submit_csr(
            csr_pem, account_id=account_id, requested_sans=requested_sans
        )


def _ready_finalize(client: Any) -> tuple[Any, Any, str, bytes]:
    """Create an authenticated account and ready order for race tests."""
    from .hand_rolled_acme_client import HandRolledAcmeClient
    from .test_revocation import _eab_mac_key, _make_csr, _make_test_config

    cfg = _make_test_config(Path("/nonexistent"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    acme = HandRolledAcmeClient(client, "http://testserver", key)
    assert acme.new_account("kid-001-0123456789abcdef", _eab_mac_key(cfg, "kid-001-0123456789abcdef")).status_code == 201
    order = acme.new_order(["srv01.WORK-DOMAIN.local"]).json()
    for authz_url in order["authorizations"]:
        authz = acme.get_authorization(authz_url).json()
        for challenge in authz["challenges"]:
            assert acme.validate_challenge(challenge["url"]).status_code == 200
    return acme, key, order["finalize"], _make_csr(["srv01.WORK-DOMAIN.local"])


def _mutation_client(client: Any, key: Any, account_url: str) -> Any:
    from .hand_rolled_acme_client import HandRolledAcmeClient

    acme = HandRolledAcmeClient(client, "http://testserver", key)
    acme.account_url = account_url
    return acme


def _only_processing_order_id(store: Store) -> str:
    processing = store.list_orders_by_status(OrderStatus.PROCESSING)
    assert len(processing) == 1, f"expected exactly one processing order, got {processing}"
    return processing[0].id


def _reclaim(client: Any, order_id: str, *, ca_verified: bool = True) -> Any:
    suffix = "?ca_verified_no_issuance=true" if ca_verified else ""
    return client.post(
        f"/acme/admin/orders/{order_id}/reclaim-processing{suffix}",
        headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
    )


def _denied_reasons(store: Store) -> list[str]:
    return [
        e["details"].get("reason")
        for e in store.list_audit_events(event_type="admin-order-reclaim-denied")
    ]


class _GatedFinalize:
    """Drive a real finalize on a background thread and pause it mid-flight.

    ``wait_until_paused`` returns once the request has reached the gate — the
    order is committed to ``processing`` and the request is genuinely in flight —
    so the test body can act on the exact window the finding described. The main
    thread then makes the reclaim request; TestClient runs each request in its
    own portal, so the paused request does not block it.
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self.reached = threading.Event()
        self.release = threading.Event()
        self.response: Any = None
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self.response = _drive_order_to_finalize(self._client)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the main thread
            self._error = exc
        finally:
            self.reached.set()  # never leave the test blocked on a crashed thread

    def gate(self) -> None:
        """Called from inside the app: announce arrival, then wait for release."""
        self.reached.set()
        assert self.release.wait(timeout=_TIMEOUT), "test never released the gate"

    def __enter__(self) -> Self:
        self._thread.start()
        assert self.reached.wait(timeout=_TIMEOUT), "finalize never reached the gate"
        if self._error is not None:
            raise self._error
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release.set()
        self._thread.join(timeout=_TIMEOUT)
        assert not self._thread.is_alive(), "finalize thread did not finish"
        if self._error is not None:
            raise self._error


class TestTheMarkCoversTheWholeInFlightInterval:
    """A — the queue gap, and B — the completion gap.

    Both are route-level: the mark must be held from before the CAS until the
    certificate row is durable, not merely while the worker is running.
    """

    def test_reclaim_is_refused_while_the_enrollment_is_still_queued(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The finding's primary schedule. The order is ``processing`` and the
        enrollment task has not started — exactly what a saturated threadpool
        produces. Before the fix the registry was empty here, so this reclaim
        returned 200 and reopened the order; the stale task then submitted to
        ADCS alongside the client's second finalize."""
        leg = _CountingLeg()
        store, client = _app_with_leg(tmp_path, leg)
        gate = client.app.state.context.enrollment_gate
        real_run = gate.run
        gated = _GatedFinalize(client)

        async def gated_run(func: Any, *args: Any, **kwargs: Any) -> Any:
            # Stand in for the wait for a dedicated enrollment slot: the task
            # is admitted and queued, but not yet running.
            gated.gate()
            return await real_run(func, *args, **kwargs)

        monkeypatch.setattr(gate, "run", gated_run)

        with gated:
            order_id = _only_processing_order_id(store)
            assert leg.calls == 0, "the CA has not been called yet — the task is queued"
            # Push past the age floor so the *only* thing that can refuse this
            # reclaim is the registry, not the secondary time check.
            _backdate_processing(store, order_id, 3600)

            resp = _reclaim(client, order_id)

            assert resp.status_code == 400
            assert "enrollment" in resp.json()["detail"].lower()
            order = store.get_order(order_id)
            assert order is not None
            assert order.status == OrderStatus.PROCESSING, (
                "a queued enrollment was reclaimed out from under itself"
            )
            assert "enrollment-in-flight" in _denied_reasons(store)

        assert gated.response is not None
        assert gated.response.status_code == 200
        assert leg.calls == 1, "the CA must be asked exactly once for this order"

    def test_reclaim_is_refused_after_the_ca_issued_but_before_the_cert_is_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The narrower second gap. The CA has issued; the RA has not yet written
        the certificate row. Reclaim's no-cert branch would find no certificate
        and — with the operator's assertion, which was true when they checked —
        reopen an order the CA has already satisfied."""
        from acme_adcs_ra.routes import orders as orders_module

        leg = _CountingLeg()
        store, client = _app_with_leg(tmp_path, leg)
        real_finalize_complete = orders_module._finalize_complete
        gated = _GatedFinalize(client)

        def gated_finalize_complete(*args: Any, **kwargs: Any) -> Any:
            gated.gate()
            return real_finalize_complete(*args, **kwargs)

        monkeypatch.setattr(
            orders_module, "_finalize_complete", gated_finalize_complete
        )

        with gated:
            order_id = _only_processing_order_id(store)
            assert leg.calls == 1, "the CA has issued"
            assert store.get_certificate_by_order(order_id) is None, (
                "…and the RA has not recorded it yet — this is the window"
            )
            _backdate_processing(store, order_id, 3600)

            resp = _reclaim(client, order_id)

            assert resp.status_code == 400
            order = store.get_order(order_id)
            assert order is not None
            assert order.status == OrderStatus.PROCESSING
            assert "enrollment-in-flight" in _denied_reasons(store)

        assert gated.response is not None
        assert gated.response.status_code == 200
        assert store.get_certificate_by_order(order_id) is not None
        assert leg.calls == 1


class TestAccountMutationLinearization:
    @pytest.mark.parametrize("mutation", ["deactivate", "key-change"])
    def test_mutation_committed_while_finalize_is_queued_blocks_the_ca_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
    ) -> None:
        leg = _CountingLeg()
        store, client = _app_with_leg(tmp_path, leg)
        acme, key, finalize_url, csr = _ready_finalize(client)
        assert acme.account_url is not None
        mutator = _mutation_client(client, key, acme.account_url)

        gate = client.app.state.context.enrollment_gate
        real_run = gate.run
        queued = threading.Event()
        release = threading.Event()

        async def queued_run(fn: Any, *args: Any) -> Any:
            queued.set()
            assert release.wait(_TIMEOUT)
            return await real_run(fn, *args)

        monkeypatch.setattr(gate, "run", queued_run)
        result: dict[str, Any] = {}

        def finalize() -> None:
            result["response"] = acme.finalize_order(finalize_url, csr)

        thread = threading.Thread(target=finalize, daemon=True)
        thread.start()
        assert queued.wait(_TIMEOUT)
        if mutation == "deactivate":
            mutation_response = mutator.deactivate_account()
        else:
            mutation_response = mutator.key_change(
                rsa.generate_private_key(public_exponent=65537, key_size=2048)
            )
        assert mutation_response.status_code == 200
        release.set()
        thread.join(_TIMEOUT)
        assert not thread.is_alive()

        assert result["response"].status_code == 401
        assert leg.calls == 0
        events = store.list_audit_events(event_type="finalize-enrollment-abandoned")
        assert events[-1]["details"]["reason"] == "account-authorization-changed"

    @pytest.mark.parametrize("mutation", ["deactivate", "key-change"])
    def test_mutation_waits_when_ca_submission_linearized_first(
        self, tmp_path: Path, mutation: str
    ) -> None:
        entered_ca = threading.Event()
        release_ca = threading.Event()

        class _BlockingLeg(_CountingLeg):
            def submit_csr(
                self, csr_pem: str, *, account_id: str, requested_sans: Any
            ) -> EnrollmentResult:
                entered_ca.set()
                assert release_ca.wait(_TIMEOUT)
                return super().submit_csr(
                    csr_pem, account_id=account_id, requested_sans=requested_sans
                )

        leg = _BlockingLeg()
        store, client = _app_with_leg(tmp_path, leg)
        acme, key, finalize_url, csr = _ready_finalize(client)
        assert acme.account_url is not None
        account_id = acme.account_url.rsplit("/", 1)[-1]
        mutator = _mutation_client(client, key, acme.account_url)
        results: dict[str, Any] = {}

        finalize_thread = threading.Thread(
            target=lambda: results.update(
                finalize=acme.finalize_order(finalize_url, csr)
            ),
            daemon=True,
        )
        finalize_thread.start()
        assert entered_ca.wait(_TIMEOUT)

        def mutate() -> None:
            if mutation == "deactivate":
                results["mutation"] = mutator.deactivate_account()
            else:
                results["mutation"] = mutator.key_change(
                    rsa.generate_private_key(public_exponent=65537, key_size=2048)
                )

        mutation_thread = threading.Thread(target=mutate, daemon=True)
        mutation_thread.start()
        mutation_thread.join(0.1)
        assert mutation_thread.is_alive(), "mutation bypassed the account issuance lock"
        account = store.get_account(account_id)
        assert account is not None and account.status == "valid"

        release_ca.set()
        finalize_thread.join(_TIMEOUT)
        mutation_thread.join(_TIMEOUT)
        assert not finalize_thread.is_alive() and not mutation_thread.is_alive()
        assert results["finalize"].status_code == 200
        assert results["mutation"].status_code == 200
        assert leg.calls == 1


class TestCsrEkuPreEnrollmentBoundary:
    @pytest.mark.parametrize(
        "ekus",
        [
            [ExtendedKeyUsageOID.CLIENT_AUTH],
            [ObjectIdentifier("2.5.29.37.0")],
            [ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")],
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
        ],
    )
    def test_forbidden_standard_eku_never_reaches_enrollment(
        self, tmp_path: Path, ekus: list[ObjectIdentifier]
    ) -> None:
        leg = _CountingLeg()
        _store, client = _app_with_leg(tmp_path, leg)
        acme, _account_key, finalize_url, _csr = _ready_finalize(client)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("srv01.WORK-DOMAIN.local")]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

        response = acme.finalize_order(finalize_url, csr)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":badCSR")
        assert leg.calls == 0

    def test_microsoft_application_policies_never_reaches_enrollment(
        self, tmp_path: Path
    ) -> None:
        leg = _CountingLeg()
        _store, client = _app_with_leg(tmp_path, leg)
        acme, _account_key, finalize_url, _csr = _ready_finalize(client)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "srv01.WORK-DOMAIN.local")]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("srv01.WORK-DOMAIN.local")]
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.311.21.10"), b"0\x00"
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

        response = acme.finalize_order(finalize_url, csr)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":badCSR")
        assert leg.calls == 0


class TestTheDurableLeaseStopsAStaleWorker:
    """C — the half that does not depend on process-local memory being right.

    These drive the submission helper directly, which is what the threadpool
    calls, with the registry deliberately *not* holding the order. That models
    the case the in-memory mark cannot cover — a mark that was lost, or a future
    multi-process deployment where one process cannot see another's workers — and
    proves the store row alone is enough to stop the CA call.
    """

    def _ctx_and_order(self, tmp_path: Path, leg: Any) -> tuple[Any, Store, str, str]:
        store, client = _app_with_leg(tmp_path, leg)
        order_id, account_id = _seed_processing_order(store)
        ctx = client.app.state.context
        # _seed_processing_order predates the live-EAB recheck and uses kid-1-0123456789abcdef;
        # make that seed authorized unless a test deliberately evicts it.
        ctx.config.eab_allowlist = [
            *ctx.config.eab_allowlist,
            ctx.config.eab_allowlist[0].model_copy(update={"kid": "kid-1-0123456789abcdef"}),
        ]
        return ctx, store, order_id, account_id

    def _submit(
        self,
        ctx: Any,
        store: Store,
        order_id: str,
        account_id: str,
        generation: int,
        *,
        authenticated_thumbprint: str | None = None,
    ) -> Any:
        from cryptography.x509 import load_der_x509_csr

        from acme_adcs_ra.finalize import _finalize_submit_enrollment
        from acme_adcs_ra.policy import PolicyDecision

        from .test_revocation import _make_csr

        csr = load_der_x509_csr(_make_csr(["a.example.com"]))
        account = store.get_account(account_id)
        assert account is not None
        if authenticated_thumbprint is None:
            authenticated_thumbprint = jwk_thumbprint(json.loads(account.jwk_json))
        return _finalize_submit_enrollment(
            ctx,
            order_id,
            account_id,
            authenticated_thumbprint,
            ["a.example.com"],
            csr,
            "CN=a.example.com",
            PolicyDecision(
                allowed=True, reason="ok", reason_code="allowed",
                template="ACME-ServerAuth",
            ),
            generation,
        )

    @pytest.mark.parametrize("mutation", ["deactivate", "key-change", "eab-evict"])
    def test_account_authorization_is_rechecked_under_lock_before_ca_submission(
        self, tmp_path: Path, mutation: str
    ) -> None:
        """Every predicate is independently load-bearing at the CA boundary."""
        from .hand_rolled_acme_client import jwk_from_private_key

        leg = _CountingLeg()
        ctx, store, order_id, account_id = self._ctx_and_order(tmp_path, leg)
        order = store.get_order(order_id)
        account = store.get_account(account_id)
        assert order is not None and account is not None
        authenticated = jwk_thumbprint(json.loads(account.jwk_json))

        if mutation == "deactivate":
            assert store.update_account_status(account_id, "deactivated")
        elif mutation == "key-change":
            new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            store.update_account_key(account_id, jwk_from_private_key(new_key))
        else:
            ctx.config.eab_allowlist = []

        with pytest.raises(AcmeError, match="CA was not called"):
            self._submit(
                ctx,
                store,
                order_id,
                account_id,
                order.processing_generation,
                authenticated_thumbprint=authenticated,
            )

        assert leg.calls == 0
        refreshed = store.get_order(order_id)
        assert refreshed is not None and refreshed.status == OrderStatus.READY
        events = store.list_audit_events(event_type="finalize-enrollment-abandoned")
        assert events[-1]["details"]["reason"] == "account-authorization-changed"

    def test_a_task_queued_across_a_reclaim_never_reaches_the_ca(
        self, tmp_path: Path
    ) -> None:
        """Daybreak's reproduction, inverted into a regression test. The order is
        reclaimed to ``ready`` and re-finalized while the first task is queued;
        when that task finally runs it must abandon, not submit."""
        leg = _CountingLeg()
        ctx, store, order_id, account_id = self._ctx_and_order(tmp_path, leg)
        order = store.get_order(order_id)
        assert order is not None
        stale_generation = order.processing_generation

        # The operator checks the CA, finds nothing, and reclaims. The client
        # then re-finalizes, taking a fresh lease.
        assert store.transition_processing_to_ready(order_id) is True
        fresh_generation = store.acquire_processing_lease(order_id)
        assert fresh_generation is not None
        assert fresh_generation > stale_generation

        # Now the original task is finally scheduled.
        result = self._submit(ctx, store, order_id, account_id, stale_generation)

        assert leg.calls == 0, "a stale enrollment reached the CA"
        assert result.status_code == 200  # the client is told the order's real state
        abandoned = store.list_audit_events(event_type="finalize-enrollment-abandoned")
        assert len(abandoned) == 1
        details = abandoned[0]["details"]
        assert details["reason"] == "processing-lease-lapsed"
        assert details["stage"] == "before-submit"
        assert details["held_generation"] == stale_generation
        assert details["current_generation"] == fresh_generation

    def test_a_task_queued_across_a_reclaim_that_was_not_re_finalized_also_stops(
        self, tmp_path: Path
    ) -> None:
        """The order left ``processing`` and nobody took it again. The status
        check alone must stop the submission — the generation is unchanged here,
        so a lease check that only compared generations would let this through."""
        leg = _CountingLeg()
        ctx, store, order_id, account_id = self._ctx_and_order(tmp_path, leg)
        order = store.get_order(order_id)
        assert order is not None
        generation = order.processing_generation

        assert store.transition_processing_to_ready(order_id) is True

        result = self._submit(ctx, store, order_id, account_id, generation)

        assert leg.calls == 0
        assert result.status_code == 200
        assert store.list_audit_events(event_type="finalize-enrollment-abandoned")

    def test_the_holder_of_the_current_lease_is_not_blocked(
        self, tmp_path: Path
    ) -> None:
        """The guard must not be a blanket refusal — the ordinary path still
        enrolls. A test that only proved "nothing is submitted" would pass on a
        version of this code that never issues at all."""
        leg = _CountingLeg()
        ctx, store, order_id, account_id = self._ctx_and_order(tmp_path, leg)
        order = store.get_order(order_id)
        assert order is not None

        result = self._submit(
            ctx, store, order_id, account_id, order.processing_generation
        )

        assert leg.calls == 1
        assert isinstance(result, EnrollmentResult)
        assert not store.list_audit_events(event_type="finalize-enrollment-abandoned")


class TestTheLeaseItself:
    """The store-level invariants everything above rests on."""

    def test_every_entry_into_processing_mints_a_new_generation(
        self, tmp_path: Path
    ) -> None:
        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, _account_id = _seed_processing_order(store)
        first = store.get_order(order_id)
        assert first is not None
        assert first.processing_generation == 1

        assert store.transition_processing_to_ready(order_id) is True
        second = store.acquire_processing_lease(order_id)
        assert second == 2

        # And it never goes backwards, which is what makes a stale generation
        # safe to compare against: a reclaim must not hand a queued task a
        # generation it is still holding.
        assert store.transition_processing_to_ready(order_id) is True
        reclaimed = store.get_order(order_id)
        assert reclaimed is not None
        assert reclaimed.processing_generation == 2

    def test_a_lost_cas_mints_nothing(self, tmp_path: Path) -> None:
        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, _account_id = _seed_processing_order(store)
        before = store.get_order(order_id)
        assert before is not None

        assert store.acquire_processing_lease(order_id) is None  # already processing

        after = store.get_order(order_id)
        assert after is not None
        assert after.processing_generation == before.processing_generation

    def test_holds_processing_lease_tracks_both_status_and_generation(
        self, tmp_path: Path
    ) -> None:
        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, _account_id = _seed_processing_order(store)

        assert store.holds_processing_lease(order_id, 1) is True
        assert store.holds_processing_lease(order_id, 2) is False
        assert store.holds_processing_lease("no-such-order", 1) is False

        assert store.transition_processing_to_ready(order_id) is True
        assert store.holds_processing_lease(order_id, 1) is False

    def test_reclaims_cas_is_scoped_to_the_lease_it_decided_against(
        self, tmp_path: Path
    ) -> None:
        """The finding's structural complaint: reclaim reads the order and
        mutates it in two separate critical sections. Scoping the write to the
        generation the read observed makes a lease change between them lose the
        CAS instead of overwriting a decision that is now stale."""
        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, _account_id = _seed_processing_order(store)
        observed = store.get_order(order_id)
        assert observed is not None

        # Something re-leases the order between the read and the write.
        assert store.transition_processing_to_ready(order_id) is True
        assert store.acquire_processing_lease(order_id) is not None

        assert (
            store.transition_processing_to_ready(
                order_id, expected_generation=observed.processing_generation
            )
            is False
        )
        current = store.get_order(order_id)
        assert current is not None
        assert current.status == OrderStatus.PROCESSING

    def test_an_issuance_under_a_lapsed_lease_records_the_cert_but_not_the_flip(
        self, tmp_path: Path
    ) -> None:
        """An issued certificate is never left untracked, even when its order has
        moved on — that is the orphan class the earlier reviews closed. But the
        order belongs to the newer lease and must not be flipped by the old one."""
        store, _client = _app_with_leg(tmp_path, FakeEnrollmentLeg())
        order_id, account_id = _seed_processing_order(store)
        cert_pem = FakeEnrollmentLeg()._read_cert()

        record, applied, event = store.record_issuance(
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=[],
            template="ACME-ServerAuth",
            requester="",
            metadata={},
            certificate_url_fn=lambda cert_id: f"http://testserver/acme/cert/{cert_id}",
            sans=["a.example.com"],
            csr_subject="CN=a.example.com",
            expected_generation=99,  # not the lease this order carries
        )

        assert applied is False
        assert event["event_type"] == "finalize-enrollment-race"
        assert store.get_certificate_by_order(order_id) is not None
        assert record.serial_number
        order = store.get_order(order_id)
        assert order is not None
        assert order.status == OrderStatus.PROCESSING

    def test_an_existing_database_gains_the_column_and_starts_at_zero(
        self, tmp_path: Path
    ) -> None:
        """Upgrade path: a store created before the lease existed must migrate
        cleanly, and its untouched orders must not look like they hold lease 1."""
        import sqlite3
        from contextlib import closing

        if sqlite3.sqlite_version_info < (3, 35, 0):
            pytest.skip("ALTER TABLE DROP COLUMN requires SQLite 3.35+")

        db_path = tmp_path / "legacy.db"
        store = Store(db_path)
        order_id, _account_id = _seed_processing_order(store)
        assert store.transition_processing_to_ready(order_id) is True

        with closing(sqlite3.connect(str(db_path))) as conn:
            conn.execute("ALTER TABLE orders DROP COLUMN processing_generation")
            conn.commit()

        migrated = Store(db_path)
        order = migrated.get_order(order_id)
        assert order is not None
        assert order.processing_generation == 0
        assert migrated.holds_processing_lease(order_id, 0) is False  # not processing
        assert migrated.acquire_processing_lease(order_id) == 1


class TestTheMarkIsReferenceCounted:
    """One holder finishing must not clear the mark for another.

    Overlapping holders should not arise — the CAS admits one finalize at a time
    — but the mark is what stands between a reclaim and a double issuance, and
    "should not arise" is the wrong strength for that.
    """

    def test_an_inner_holder_exiting_leaves_the_order_marked(self) -> None:
        from acme_adcs_ra.app_state import ActiveEnrollments

        active = ActiveEnrollments()
        with active.enrolling("order-1"):
            with active.enrolling("order-1"):
                assert active.is_active("order-1") is True
            assert active.is_active("order-1") is True, (
                "one holder's completion cleared liveness for another"
            )
        assert active.is_active("order-1") is False

    def test_orders_do_not_interfere(self) -> None:
        from acme_adcs_ra.app_state import ActiveEnrollments

        active = ActiveEnrollments()
        with active.enrolling("order-1"):
            assert active.is_active("order-2") is False
        assert active.is_active("order-1") is False
