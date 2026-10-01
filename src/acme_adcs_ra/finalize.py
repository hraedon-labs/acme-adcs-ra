"""Finalize-order helpers (WI-001: decomposed from ~350-line handler)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import DNSName, load_der_x509_csr
from cryptography.x509.oid import ExtensionOID
from fastapi.responses import JSONResponse

from acme_adcs_ra.acme_errors import (
    bad_csr,
    order_not_ready,
    rejected_identifier,
    server_internal,
    unauthorized,
)
from acme_adcs_ra.app_state import (
    ServerContext,
    _audit,
    _certificate_url,
    emit_audit_hook,
    logger,
)
from acme_adcs_ra.csr_validation import (
    _reject_ca_capable_csr_extensions,
    _reject_invalid_dns_sans,
    _reject_non_dns_sans,
    _reject_unrequested_common_names,
    _reject_wildcard_sans,
    _validate_csr_key_strength,
)
from acme_adcs_ra.enrollment import (
    EnrollmentDenied,
    EnrollmentPending,
    EnrollmentResult,
    EnrollmentTransportError,
)
from acme_adcs_ra.issued_certificate_validation import (
    issued_cert_ca_capability_violations as _issued_cert_ca_capability_violations,
)
from acme_adcs_ra.issued_certificate_validation import (
    issued_cert_eku_violations as _issued_cert_eku_violations,
)
from acme_adcs_ra.issued_certificate_validation import (
    issued_cert_san_violations as _issued_cert_san_violations,
)
from acme_adcs_ra.jws import _base64url_decode, jwk_thumbprint
from acme_adcs_ra.policy import PolicyDecision
from acme_adcs_ra.serializers import _order_to_json
from acme_adcs_ra.store import (
    AccountStatus,
    CertificateRecord,
    OrderRecord,
    OrderStatus,
    _now_iso,
    _serial_from_pem,
    is_expired,
)


def _refresh_order_or_500(
    ctx: ServerContext, order_id: str, context: str,
) -> OrderRecord:
    """Refresh the order after a lost CAS race, or raise 500 if it disappeared."""
    refreshed = ctx.store.get_order(order_id)
    if refreshed is None:
        raise server_internal(f"order disappeared {context}")
    return refreshed


def _finalize_existing_cert(
    ctx: ServerContext, order_id: str, account_id: str,
    existing_cert: CertificateRecord,
) -> JSONResponse:
    """Handle a finalize call when a cert already exists for this order.

    Self-heals the crash window between create_certificate and the status flip
    to 'valid': a cert row exists, so issuance definitively succeeded — close
    the loop so the client isn't left polling a 'processing' order with no
    certificate URL. CAS-guarded (only processing->valid), no re-enrollment,
    no double-issuance.
    """
    refreshed = _refresh_order_or_500(ctx, order_id, "after double-finalize check")
    if refreshed.status == OrderStatus.PROCESSING:
        certificate_url = _certificate_url(ctx, existing_cert.id)
        # Guarded on the lease we just read: this call does not hold one, so if
        # the order's lease moved on between the read and here, the decision
        # this branch was made on is stale and the CAS must lose.
        applied = ctx.store.transition_processing_to_valid(
            order_id,
            certificate_url,
            expected_generation=refreshed.processing_generation,
        )
        if applied:
            _audit(ctx,
                event_type="finalize-order-reconciled",
                account_id=account_id,
                order_id=order_id,
                outcome="success",
                details={
                    "certificate_id": existing_cert.id,
                    "prior_status": refreshed.status,
                },
            )
        refreshed = _refresh_order_or_500(ctx, order_id, "after reconcile")
    return JSONResponse(content=_order_to_json(refreshed))


def _finalize_expired_order(
    ctx: ServerContext, order_id: str, account_id: str, order: OrderRecord,
) -> JSONResponse | None:
    """If order is expired, CAS-flip to invalid and raise/return.

    Returns None if the order is not expired.
    Returns a JSONResponse if the CAS lost the race (return current state).
    Raises orderNotReady (403) if the CAS applied (order is definitively expired).
    """
    if not is_expired(order.expires):
        return None
    applied = ctx.store.transition_active_to_invalid(order_id)
    if applied:
        _audit(ctx,
            event_type="finalize-expired-order",
            account_id=account_id,
            order_id=order_id,
            outcome="denied",
            details={"expires": order.expires},
        )
        raise order_not_ready(
            f"order has expired (expires={order.expires}) and is now invalid; "
            f"create a new order to retry"
        )
    refreshed = _refresh_order_or_500(ctx, order_id, "during expiry check")
    if refreshed.status == OrderStatus.VALID:
        return JSONResponse(content=_order_to_json(refreshed))
    if refreshed.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(refreshed), headers={"Retry-After": "3"}
        )
    raise order_not_ready(
        f"order has expired (expires={order.expires}) and is now invalid; "
        f"create a new order to retry"
    )


def _finalize_parse_and_validate_csr(
    ctx: ServerContext,
    payload: dict[str, Any],
    order: OrderRecord,
    account_id: str,
    order_id: str,
) -> tuple[x509.CertificateSigningRequest, str, list[str], PolicyDecision]:
    """Parse CSR, validate key strength/SANs, check against order, evaluate policy.

    All validation runs while the order is still 'ready'. The transition to
    'processing' (the point-of-no-return CAS) happens only after this passes,
    so a rejected CSR or policy denial leaves the order retryable.

    Returns (csr, csr_subject, requested_sans, decision).
    """
    csr_b64 = payload.get("csr")
    if not isinstance(csr_b64, str) or not csr_b64:
        raise bad_csr("missing or invalid csr field")

    try:
        csr_der = _base64url_decode(csr_b64)
    except Exception as exc:
        raise bad_csr(f"csr is not valid base64url: {exc}") from exc

    if len(csr_der) > ctx.config.max_csr_size_bytes:
        raise bad_csr(
            f"CSR too large (max {ctx.config.max_csr_size_bytes} bytes, got {len(csr_der)})"
        )

    try:
        csr = load_der_x509_csr(csr_der)
    except Exception as exc:
        raise bad_csr(f"unable to parse CSR: {exc}") from exc

    if not csr.is_signature_valid:
        raise bad_csr("CSR signature is invalid")

    _validate_csr_key_strength(csr)

    csr_subject = csr.subject.rfc4514_string()

    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        san_values: list[str] = []
    else:
        san_value = cast(x509.SubjectAlternativeName, san_ext.value)
        _reject_non_dns_sans(san_value)
        san_values = [str(v) for v in san_value.get_values_for_type(DNSName)]
        _reject_wildcard_sans(san_values)
        _reject_invalid_dns_sans(san_values)

    requested_sans = san_values

    # The template takes the subject and extensions from the request.  Scope
    # the legacy CN identity path and reject any attempt to request a CA-capable
    # certificate before the CSR reaches ADCS.
    _reject_ca_capable_csr_extensions(csr)

    order_dns = {
        i["value"].lower()
        for i in order.identifiers
        if i.get("type") == "dns" and isinstance(i.get("value"), str)
    }
    out_of_order = sorted(s for s in requested_sans if s.lower() not in order_dns)
    if out_of_order:
        _audit(
            ctx,
            event_type="finalize-csr-mismatch",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            outcome="denied",
            details={
                "reason": "CSR SANs not in order identifiers",
                # Same reason/reason_code split as the policy-denied call
                # below: the reason is currently a fixed string, but
                # out_of_order -- the attacker-chosen SAN list -- sits in this
                # same dict one refactor away from being interpolated into it,
                # which would put it straight back into the coalescing key.
                # The sibling call site was the R2-5 finding; this one is
                # pinned now rather than after that refactor.
                "reason_code": "csr-san-mismatch",
                "out_of_order": out_of_order,
            },
        )
        raise rejected_identifier(
            "CSR contains identifiers not present in the order: "
            + ", ".join(out_of_order)
        )

    account = ctx.store.get_account(account_id)
    if account is None:
        raise unauthorized("account not found")

    decision = ctx.policy.evaluate(
        eab_kid=account.eab_kid,
        csr_subject=csr_subject,
        requested_sans=requested_sans,
    )
    if not decision.allowed:
        _audit(ctx,
            event_type="finalize-policy-denied",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            outcome="denied",
            # ``reason`` is prose and contains the offending SAN, which the
            # client chooses; ``reason_code`` is the stable coalescing identity.
            # Without the split, varying one identifier per finalize produced one
            # durable audit row per request on a single order — the bound-defeat
            # the coalescer excludes attacker-chosen data to prevent.
            details={
                "reason": decision.reason,
                "reason_code": decision.reason_code,
            },
        )
        if "out of scope" in decision.reason or "no SANs" in decision.reason:
            raise rejected_identifier(decision.reason)
        raise bad_csr(decision.reason)

    _reject_unrequested_common_names(csr, requested_sans)

    return csr, csr_subject, requested_sans, decision


def _finalize_transition_to_processing(
    ctx: ServerContext, order_id: str,
) -> int | JSONResponse:
    """Atomically transition ready→processing and take the enrollment lease.

    Returns the lease generation (an ``int >= 1``) on success — the caller
    must carry it to the worker and hand it back on every lease re-check.
    Returns a JSONResponse if the CAS lost the race (return current state).
    """
    generation = ctx.store.acquire_processing_lease(order_id)
    if generation is not None:
        return generation
    refreshed = _refresh_order_or_500(ctx, order_id, "during finalization")
    if refreshed.status == OrderStatus.PROCESSING:
        return JSONResponse(
            content=_order_to_json(refreshed), headers={"Retry-After": "3"}
        )
    return JSONResponse(content=_order_to_json(refreshed))


def _finalize_submit_enrollment(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    authenticated_thumbprint: str,
    requested_sans: list[str],
    csr: x509.CertificateSigningRequest,
    csr_subject: str,
    decision: PolicyDecision,
    generation: int,
) -> EnrollmentResult | JSONResponse:
    """Submit CSR to enrollment, if this call still owns the order.

    Runs on a threadpool thread. ``generation`` is the lease minted by the
    ``ready``→``processing`` CAS that admitted this call; it is re-checked
    against the store here, *immediately* before the CA is touched, because
    an arbitrary amount of wall-clock time can pass between the CAS and this
    function actually running — the threadpool may be saturated, and the task
    can sit queued past the reclaim age floor. In that window an operator can
    truthfully verify at the CA that nothing was issued, reclaim the order to
    ``ready``, and a second finalize can take a fresh lease. Submitting anyway
    would put two requests for one order in front of ADCS.

    Returns EnrollmentResult on success, or JSONResponse on recoverable error
    (stale lease, enrollment denied with lost race, or transport error).
    Raises on unrecoverable error.
    """
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    # The lock is intentionally held across ADCS I/O, but no SQLite transaction
    # is.  A deactivation/keyChange that commits first makes the checks below
    # fail; if this call takes the lock first, its submission linearizes before
    # that later mutation.
    with ctx.account_issuance_locks.submitting(account_id):
        account = ctx.store.get_account(account_id)
        current_thumbprint = (
            jwk_thumbprint(json.loads(account.jwk_json)) if account is not None else None
        )
        eab_allowlisted = (
            account is not None
            and account.eab_kid in ctx.config.eab_keys_by_kid()
        )
        if (
            account is None
            or account.status != AccountStatus.VALID
            or current_thumbprint != authenticated_thumbprint
            or not eab_allowlisted
        ):
            applied = ctx.store.transition_processing_to_ready(
                order_id, expected_generation=generation
            )
            _audit(
                ctx,
                event_type="finalize-enrollment-abandoned",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=decision.template,
                outcome="denied",
                details={
                    "reason": "account-authorization-changed",
                    "stage": "before-submit",
                    "account_status": account.status if account is not None else "missing",
                    "key_matches_authenticated_request": (
                        current_thumbprint == authenticated_thumbprint
                    ),
                    "eab_kid_allowlisted": eab_allowlisted,
                    "revert_applied": applied,
                },
            )
            raise unauthorized(
                "account status, key, or external-account authorization changed "
                "before certificate submission; the CA was not called"
            )

        stale = _abandon_if_lease_lapsed(
            ctx, order_id, account_id, requested_sans, decision, generation
        )
        if stale is not None:
            return stale
        return _submit_enrollment_inner(
            ctx, order_id, account_id, requested_sans, csr_pem, decision, generation
        )


def _abandon_if_lease_lapsed(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    decision: PolicyDecision,
    generation: int,
) -> JSONResponse | None:
    """Return a response (and audit) if this call no longer owns the order.

    Returns None when the lease is still held and the caller should proceed.

    There is exactly one place this can be asked, and it is deliberate:
    immediately before ``submit_csr``. Once the CA has issued, the answer stops
    mattering — the certificate exists and must be recorded whether or not the
    order moved on, which is what ``record_issuance`` does (row written, order
    flip lease-scoped). A lease check *after* issuance could only choose to
    orphan a live certificate, which is the defect the earlier reviews closed.

    The abandoning call must not write to the order: it does not own it any
    more, and whoever does is mid-flight. It reports the order's *current*
    state to its own client, which is the truthful answer — the client's
    finalize was superseded, and the order status tells it what to do next.

    The audit row is the operator's signal that a reclaim landed on a request
    that was still queued. It should be rare; if it is not, the threadpool is
    saturated and the reclaim floor is being crossed by ordinary queueing.
    """
    if ctx.store.holds_processing_lease(order_id, generation):
        return None
    order = _refresh_order_or_500(ctx, order_id, "after a lapsed lease")
    _audit(ctx,
        event_type="finalize-enrollment-abandoned",
        account_id=account_id,
        order_id=order_id,
        sans=requested_sans,
        template=decision.template,
        outcome="denied",
        details={
            "reason": "processing-lease-lapsed",
            "stage": "before-submit",
            "held_generation": generation,
            "current_generation": order.processing_generation,
            "current_status": order.status,
        },
    )
    logger.warning(
        "abandoned enrollment for order %s before submitting to the CA: this "
        "call held processing generation %d but the order is now %s at "
        "generation %d. The CA was NOT called. A reclaim (or a competing "
        "finalize) took the order while this request was queued.",
        order_id, generation, order.status, order.processing_generation,
    )
    return JSONResponse(
        content=_order_to_json(order), headers={"Retry-After": "3"}
    )


def _submit_enrollment_inner(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr_pem: str,
    decision: PolicyDecision,
    generation: int,
) -> EnrollmentResult | JSONResponse:
    try:
        return ctx.enrollment.submit_csr(
            csr_pem,
            account_id=account_id,
            requested_sans=requested_sans,
        )
    except EnrollmentDenied as exc:
        # Revert only our own lease: if the order moved on while the CA was
        # deciding, releasing it back to `ready` would hand a client a second
        # finalize against work someone else now owns.
        applied = ctx.store.transition_processing_to_ready(
            order_id, expected_generation=generation
        )
        _audit(ctx,
            event_type="finalize-enrollment-denied",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=decision.template,
            outcome="denied",
            details={"error": str(exc), "revert_applied": applied},
        )
        if not applied:
            refreshed = _refresh_order_or_500(
                ctx, order_id, "during enrollment denial"
            )
            return JSONResponse(content=_order_to_json(refreshed))
        raise rejected_identifier(str(exc)) from exc
    except EnrollmentPending as exc:
        # The CA accepted the request and has not decided it. That is neither
        # "issued" (there is no certificate to quarantine) nor "the CA was
        # unreachable" (there is a live request that may still become one), and
        # collapsing it into the latter is what allowed a second submission
        # (2026-08-18 F4).
        #
        # The order stays in `processing`, so no client retry can re-enroll;
        # the ReqID is persisted so the only route that *can* reopen the order
        # — administrative reclaim — knows exactly which CA request has to be
        # accounted for first.
        recorded = ctx.store.record_pending_ca_request(
            order_id, exc.req_id, expected_generation=generation
        )
        _audit(ctx,
            event_type="finalize-enrollment-pending",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=decision.template,
            outcome="failed",
            details={
                "error": str(exc),
                "ca_issued": False,
                "req_id": exc.req_id,
                "pending_recorded": recorded,
            },
        )
        if not recorded:
            logger.error(
                "The CA has ACCEPTED request %s for order %s but the pending "
                "marker could not be written (the lease moved to a different "
                "generation). That request is live at the CA and this order can "
                "now be reclaimed without accounting for it — resolve ReqID %s "
                "at the CA by hand.",
                exc.req_id, order_id, exc.req_id,
            )
        else:
            logger.warning(
                "CA request %s for order %s is PENDING (awaiting a decision at "
                "the CA). The order stays in 'processing' and cannot be "
                "reclaimed until that request is resolved.",
                exc.req_id, order_id,
            )
        order = _refresh_order_or_500(ctx, order_id, "during a pending CA request")
        return JSONResponse(
            status_code=503,
            content=_order_to_json(order),
            headers={"Retry-After": "300"},
        )
    except EnrollmentTransportError as exc:
        if exc.ca_issued:
            # The CA issued and then something downstream failed — the leaf
            # fetch, the PKCS#7 chain fetch, or the chain-binds-to-leaf check.
            # A live, domain-trusted certificate exists at the CA. Recording
            # only the error string (the previous behaviour) left it an
            # untracked orphan whose serial appeared nowhere in the RA, which
            # is the same defect the post-issuance verifiers were fixed for.
            return _quarantine_transport_orphan(
                ctx,
                order_id=order_id,
                account_id=account_id,
                requested_sans=requested_sans,
                template=decision.template,
                exc=exc,
                generation=generation,
            )
        _audit(ctx,
            event_type="finalize-enrollment-transport-failed",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=decision.template,
            outcome="failed",
            details={"error": str(exc), "ca_issued": False},
        )
        order = _refresh_order_or_500(
            ctx, order_id, "during enrollment transport error"
        )
        return JSONResponse(
            status_code=503,
            content=_order_to_json(order),
            headers={"Retry-After": "30"},
        )
    except Exception as exc:
        _audit(ctx,
            event_type="finalize-enrollment-failed",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=decision.template,
            outcome="failed",
            details={"error": str(exc)},
        )
        raise server_internal(f"enrollment failed: {exc}") from exc


def _quarantine_and_fail(
    ctx: ServerContext,
    *,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    enrollment_result: EnrollmentResult,
    event_type: str,
    violations: list[str],
    reason: str,
    message: str,
    extra_details: dict[str, Any] | None = None,
) -> NoReturn:
    """Quarantine a CA-issued certificate the RA refuses to honour, then 500.

    All three post-issuance verifiers (SAN, EKU, CA-capability) run *after*
    ADCS has issued: the certificate exists, has a serial, and is trusted
    domain-wide. Recording nothing — the previous behaviour — left it as an
    unrevocable orphan whose serial appeared neither in the store nor in the
    audit event. The quarantine row makes it identifiable and puts it in the
    existing CA-side revocation queue; the 500 is unchanged, because a
    template that issues outside policy really is a server-side fault.

    Quarantining must never itself lose the finding, so a store failure here
    is logged loudly and the original violation is still surfaced.
    """
    try:
        record, event = ctx.store.quarantine_certificate(
            order_id=order_id,
            account_id=account_id,
            cert_pem=enrollment_result.cert_pem,
            chain_pem=enrollment_result.chain_pem,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            metadata=dict(enrollment_result.metadata),
            event_type=event_type,
            violations=violations,
            reason=reason,
            sans=requested_sans,
            extra_details=extra_details,
        )
        emit_audit_hook(ctx, event)
        logger.error(
            "QUARANTINED a CA-issued certificate: serial=%s req_id=%s order=%s "
            "violations=%s. It is LIVE at the CA and queued for CA-side "
            "revocation; run the revocation sync agent.",
            record.serial_number,
            record.metadata.get("req_id", ""),
            order_id,
            violations,
        )
    except Exception:  # noqa: BLE001 - the finding must survive any store failure
        # Fall back to a plain audit row so the violation is never silent.
        logger.exception(
            "failed to quarantine a rejected CA-issued certificate for order %s; "
            "the certificate is LIVE at the CA and NOT tracked — revoke it manually",
            order_id,
        )
        _audit(
            ctx,
            event_type=event_type,
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            outcome="failed",
            details={
                "violations": violations,
                "reason": reason,
                "quarantined": False,
                "quarantine_error": "see logs",
                **(extra_details or {}),
            },
        )

    raise server_internal(message)


def _quarantine_transport_orphan(
    ctx: ServerContext,
    *,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    template: str | None,
    exc: EnrollmentTransportError,
    generation: int,
) -> JSONResponse:
    """Record a certificate the CA issued but the RA could not complete.

    Two cases, and the difference matters to whoever cleans up:

    * **The leaf is in hand** (the chain fetch or the chain-binds-to-leaf check
      failed). The serial is derivable, so this quarantines exactly like a
      verifier rejection: a ``quarantined`` row carrying the serial and ReqID,
      queued for CA-side revocation through the ordinary pull agent.
    * **Only the ReqID is known** (the leaf fetch itself failed). There is no
      certificate row to write — the store keys on the bytes, which the RA
      never received. All that can be done is to make the ReqID impossible to
      miss, so the operator can revoke by ReqID at the CA by hand.

    Either way the order goes terminal-``invalid``: a retried finalize must not
    re-enroll against a request the CA has already satisfied.
    """
    if exc.cert_pem is not None:
        try:
            record, event = ctx.store.quarantine_certificate(
                order_id=order_id,
                account_id=account_id,
                cert_pem=exc.cert_pem,
                chain_pem=exc.chain_pem,
                template=template or "",
                requester="",
                metadata={"req_id": exc.req_id or ""},
                event_type="finalize-enrollment-transport-orphan",
                violations=[str(exc)],
                reason=(
                    "the CA issued this certificate, but the RA could not "
                    "complete enrollment (chain fetch or chain validation "
                    "failed), so it was never honoured"
                ),
                sans=requested_sans,
                extra_details={"ca_issued": True, "transport_error": str(exc)},
            )
            emit_audit_hook(ctx, event)
            logger.error(
                "QUARANTINED a CA-issued certificate after a transport failure: "
                "serial=%s req_id=%s order=%s. It is LIVE at the CA and queued "
                "for CA-side revocation; run the revocation sync agent.",
                record.serial_number,
                exc.req_id,
                order_id,
            )
        except Exception:  # noqa: BLE001 - the finding must survive a store failure
            logger.exception(
                "failed to quarantine a CA-issued certificate for order %s "
                "(req_id %s); it is LIVE at the CA and NOT tracked — revoke it "
                "manually",
                order_id,
                exc.req_id,
            )
            _audit(ctx,
                event_type="finalize-enrollment-transport-orphan",
                account_id=account_id,
                order_id=order_id,
                sans=requested_sans,
                template=template,
                outcome="failed",
                details={
                    "error": str(exc),
                    "ca_issued": True,
                    "req_id": exc.req_id,
                    "quarantined": False,
                    "quarantine_error": "see logs",
                },
            )
    else:
        # No bytes, so no row can be written. Make the ReqID loud instead.
        logger.error(
            "The CA ISSUED a certificate the RA could not retrieve: req_id=%s "
            "order=%s. It is LIVE at the CA, is NOT in the RA store, and CANNOT "
            "be revoked by the sync agent. Revoke it by ReqID at the CA by hand.",
            exc.req_id,
            order_id,
        )
        _audit(ctx,
            event_type="finalize-enrollment-transport-orphan",
            account_id=account_id,
            order_id=order_id,
            sans=requested_sans,
            template=template,
            outcome="failed",
            details={
                "error": str(exc),
                "ca_issued": True,
                "req_id": exc.req_id,
                "quarantined": False,
                "reason": (
                    "the CA issued but the RA never received the certificate "
                    "bytes; revoke by ReqID at the CA manually"
                ),
            },
        )

    # Terminal either way — the CA has already satisfied this request.
    # NOT transition_active_to_invalid: that one excludes 'processing' on
    # purpose, so it would silently no-op here and leave the client polling.
    # Scoped to our own lease so this cannot terminate an order that a reclaim
    # plus a later finalize have since handed to a different enrollment.
    ctx.store.transition_processing_to_invalid(
        order_id, expected_generation=generation
    )
    order = _refresh_order_or_500(ctx, order_id, "after transport orphan")
    return JSONResponse(
        status_code=500,
        content=_order_to_json(order),
    )



# Substrings that mean the store cannot be WRITTEN TO, as opposed to being
# momentarily busy. Matched case-insensitively against the exception text,
# because sqlite3 reports all of these as OperationalError and the message is
# the only discriminator the driver offers.
#
# "database is locked" / "table is locked" are deliberately ABSENT: contention
# is transient and ordinary, and latching issuance on it would trade a rare
# orphan for a routine self-inflicted outage.
_UNWRITABLE_STORE_MARKERS = (
    "disk is full",
    "database or disk is full",
    "readonly database",
    "read-only database",
    "attempt to write a readonly database",
    "disk i/o error",
    "unable to open database file",
    "database disk image is malformed",
    "no space left",
)


def _store_is_unwritable(exc: BaseException) -> bool:
    """True when *exc* says the store cannot take writes at all."""
    if isinstance(exc, sqlite3.IntegrityError):
        # A constraint violation is a bug or a duplicate, not a dead disk.
        return False
    if isinstance(exc, OSError):
        # ENOSPC/EROFS surfacing from the filesystem rather than the driver.
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _UNWRITABLE_STORE_MARKERS)


def _emergency_issuance_orphan(
    ctx: ServerContext,
    *,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    enrollment_result: EnrollmentResult,
    exc: BaseException,
) -> None:
    """Record a live certificate the store could not be told about.

    ADCS has already issued by the time ``record_issuance`` runs, and that call
    is the FIRST durable record of the fact. If it raises -- a full disk, a
    read-only database, a corrupt file -- the whole certificate/order/audit
    transaction rolls back and the certificate is live at the CA with no row,
    no audit event, no quarantine record and no revocation queue entry.

    ``audit_retention`` states the invariant this protects: *"the
    certificate-issued audit row commits in the same transaction as the
    certificate, so a full disk stops issuance rather than issuing unaudited."*
    That holds only while the disk fills BEFORE the CA call. In the window
    between "ADCS committed" and "SQLite committed" it cannot hold, because the
    issuance has already happened and no local rollback can undo it. This is
    the compensation for that window.

    **Nothing here touches the store.** That is the whole point, and it is why
    the two neighbouring handlers are not reused: ``_quarantine_and_fail`` and
    ``_quarantine_transport_orphan`` both fall back to ``_audit``, which is
    ``Store.record_audit`` -- the same database that just failed. Under the
    fault this function exists for, that fallback raises from inside its own
    except block and no evidence is written anywhere.

    Two sinks, both independent of SQLite:

    * ``logger.critical`` -- goes to the RA's own log file, which is on a
      DIFFERENT path from the database and, on the supported deployment, is
      also what the Windows Event Log collector reads.
    * ``ctx.audit_hook`` -- called DIRECTLY with a hand-built event rather than
      through ``emit_audit_hook``'s usual after-the-row-commits contract,
      because there is no row and there is not going to be one. When
      ``audit_offbox_required`` is set this is a live off-box collector and the
      evidence leaves the host.

    Neither sink is trusted to succeed. The hook is wrapped because a SIEM
    transport error must not replace the exception the caller is about to
    re-raise, and because logging handlers swallow transport errors anyway --
    so a delivered-looking emission is not proof of delivery.
    """
    try:
        serial = _serial_from_pem(enrollment_result.cert_pem)
    except Exception:  # noqa: BLE001 - never let evidence fail on a parse
        serial = ""
    req_id = str(enrollment_result.metadata.get("req_id", ""))

    logger.critical(
        "ORPHANED a CA-issued certificate: the RA could not record it. "
        "serial=%s req_id=%s order=%s account=%s template=%s sans=%s. "
        "The certificate is LIVE at the CA, is NOT in the RA store, and CANNOT "
        "be revoked by the sync agent. Revoke it at the CA by hand using the "
        "serial (or the ReqID), then restart the RA once the store is writable. "
        "Store error: %s",
        serial,
        req_id,
        order_id,
        account_id,
        enrollment_result.template,
        requested_sans,
        exc,
        exc_info=True,
    )

    unwritable = _store_is_unwritable(exc)
    event = {
        "event_type": "finalize-issuance-record-failed",
        "outcome": "failed",
        "timestamp": _now_iso(),
        "account_id": account_id,
        "order_id": order_id,
        "sans": list(requested_sans),
        "template": enrollment_result.template,
        "requester": enrollment_result.requester,
        "details": {
            "ca_issued": True,
            "serial": serial,
            "req_id": req_id,
            "recorded": False,
            "store_error": str(exc),
            "store_unwritable": unwritable,
            "issuance_halted": unwritable,
            "reason": (
                "the CA issued this certificate and the RA could not persist "
                "it; no store row exists and it must be revoked by hand"
            ),
            # This event never had a durable local row -- say so on the row
            # itself, so an investigator reconciling SIEM against the local
            # audit table does not read the absence as a gap in the SIEM feed.
            "emergency_offbox_only": True,
        },
    }
    if ctx.audit_hook is not None:
        try:
            ctx.audit_hook(event)
        except Exception:  # noqa: BLE001 - the caller's exception must survive
            logger.critical(
                "the emergency off-box emission for orphaned serial %s ALSO "
                "failed; the log line above is the only remaining record",
                serial,
                exc_info=True,
            )
    else:
        logger.critical(
            "no audit hook is configured, so the orphaned serial %s has NO "
            "off-box record at all",
            serial,
        )

    if unwritable:
        ctx.issuance_halt.halt(
            f"post-issuance store failure on order {order_id} "
            f"(serial {serial or 'unknown'}): {exc}"
        )


def _finalize_complete(
    ctx: ServerContext,
    order_id: str,
    account_id: str,
    requested_sans: list[str],
    csr_subject: str,
    decision: PolicyDecision,
    enrollment_result: EnrollmentResult,
    generation: int,
) -> JSONResponse:
    """Record the certificate and transition to valid.

    Handles the post-enrollment completion: create cert record, CAS-flip
    processing→valid, audit, and return the final order state.

    ``generation`` is the enrollment lease this issuance was performed under.
    The CA has already issued by the time this runs, so the certificate row is
    written unconditionally — an issued certificate is never left untracked —
    but the order flip is scoped to the lease.
    """
    # MED-1: verify the issued cert carries only DNS SANs the order authorized.
    # A misconfigured template injecting an unauthorized SAN (or any non-DNS
    # SAN) must not be recorded or served, even though the CSR was approved.
    issued_dns_sans, unauthorized_dns, non_dns_san_types = _issued_cert_san_violations(
        enrollment_result.cert_pem, requested_sans
    )
    if unauthorized_dns or non_dns_san_types:
        violations: list[str] = []
        if unauthorized_dns:
            violations.append(
                f"unauthorized DNS SANs: {unauthorized_dns} "
                f"(authorized={requested_sans})"
            )
        if non_dns_san_types:
            violations.append(
                f"non-DNS SAN types present: {non_dns_san_types} "
                "(only DNS SANs are permitted)"
            )
        reason = (
            "issued cert SANs outside order scope — ADCS template likely "
            "misconfigured (it must take only DNS SANs from the request)"
        )
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-san-mismatch",
            violations=violations,
            reason=reason,
            message=(
                f"issued certificate fails SAN verification — {'; '.join(violations)}; "
                "the ADCS template is likely misconfigured"
            ),
            extra_details={
                "issued_dns_sans": issued_dns_sans,
                "unauthorized_dns_sans": unauthorized_dns,
                "non_dns_san_types": non_dns_san_types,
            },
        )

    # WI-026: verify the issued cert is serverAuth-only. The cardinal blast-radius
    # bound rests on the template issuing serverAuth EKU only; a template that ever
    # gained clientAuth/PKINIT/anyEKU (or a no-EKU all-purpose cert) would silently
    # break it — the domain-takeover escalation the threat model calls the worst
    # case short of a signing key. Enforce on the result; fail closed like MED-1.
    eku_violations = _issued_cert_eku_violations(enrollment_result.cert_pem)
    if eku_violations:
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-eku-mismatch",
            violations=eku_violations,
            reason=(
                "issued cert is not serverAuth-only — the ADCS template must "
                "issue the serverAuth EKU and nothing else"
            ),
            message=(
                f"issued certificate fails EKU verification — "
                f"{'; '.join(eku_violations)}; the ADCS template is likely "
                "misconfigured (serverAuth-only required)"
            ),
        )

    ca_capability_violations = _issued_cert_ca_capability_violations(
        enrollment_result.cert_pem
    )
    if ca_capability_violations:
        _quarantine_and_fail(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            event_type="finalize-issued-cert-ca-capability",
            violations=ca_capability_violations,
            reason=(
                "issued cert is CA-capable — the ADCS template is dangerously "
                "misconfigured"
            ),
            message=(
                "issued certificate is CA-capable — "
                f"{'; '.join(ca_capability_violations)}; "
                "the ADCS template is dangerously misconfigured"
            ),
        )

    # The certificate row, the order transition, and the mandatory issuance
    # audit row commit together — see Store.record_issuance.
    #
    # Guarded because this is the first durable record of something the CA has
    # ALREADY done, and a local rollback cannot undo a CA issuance. Both
    # neighbouring failure paths (verifier rejection, transport failure) have
    # an orphan handler; this one — the SUCCESS path — did not, so a store
    # failure here left a live certificate with no row, no audit event and no
    # revocation queue entry. See _emergency_issuance_orphan.
    try:
        cert_record, applied, _event = ctx.store.record_issuance(
            order_id=order_id,
            account_id=account_id,
            cert_pem=enrollment_result.cert_pem,
            chain_pem=enrollment_result.chain_pem,
            template=enrollment_result.template,
            requester=enrollment_result.requester,
            metadata=dict(enrollment_result.metadata),
            certificate_url_fn=lambda cert_id: _certificate_url(ctx, cert_id),
            sans=requested_sans,
            csr_subject=csr_subject,
            expected_generation=generation,
        )
    except Exception as exc:
        _emergency_issuance_orphan(
            ctx,
            order_id=order_id,
            account_id=account_id,
            requested_sans=requested_sans,
            enrollment_result=enrollment_result,
            exc=exc,
        )
        # Re-raised, not swallowed: the client must not be told the order is
        # valid when nothing was recorded, and the order stays `processing`
        # so a retried finalize cannot re-enroll against a request the CA has
        # already satisfied.
        raise
    # The audit row is already durable; this only fans it out to SIEM.
    emit_audit_hook(ctx, _event)

    if not applied:
        logger.error(
            "finalize CAS lost race for order %s; cert %s recorded but "
            "order was moved by a concurrent operation (winner cert=%s)",
            order_id,
            cert_record.id,
            _event["details"].get("winner_certificate_id"),
        )

    refreshed_order = _refresh_order_or_500(ctx, order_id, "after finalization")
    return JSONResponse(content=_order_to_json(refreshed_order))
