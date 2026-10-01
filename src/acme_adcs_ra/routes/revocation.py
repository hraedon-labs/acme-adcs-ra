"""Certificate revocation (RFC 8555 §7.6)."""

from __future__ import annotations

import json
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from acme_adcs_ra.acme_errors import (
    bad_revocation_reason,
    malformed,
    not_found,
    server_internal,
)
from acme_adcs_ra.app_state import (
    _ACME_PATHS,
    ServerContext,
    _audit,
    authenticate_account,
    emit_audit_hook,
    get_context,
)
from acme_adcs_ra.jws import _base64url_decode
from acme_adcs_ra.store import CertStatus, _now_iso, canonical_serial

router = APIRouter()


def _dns_sans(cert: x509.Certificate) -> list[str]:
    """The certificate's dNSName SANs, or an empty list when it has none."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return []
    san_value = cast(x509.SubjectAlternativeName, san_ext.value)
    return [str(v) for v in san_value.get_values_for_type(DNSName)]


@router.post(_ACME_PATHS["revokeCert"])
async def revoke_cert(
    request: Request,
    ctx: ServerContext = Depends(get_context),
) -> Response:
    _header, payload, account, _authenticated_thumbprint = await authenticate_account(
        ctx, request, _ACME_PATHS["revokeCert"]
    )
    account_id = account.id

    # RFC 8555 §7.6 names this field "certificate". This route read "cert" only,
    # so EVERY conformant ACME client was refused with
    # `malformed: missing or invalid cert field` and could not revoke at all.
    # It went unnoticed because the lab harness and tests/hand_rolled_acme_client
    # both sent "cert" too -- the client mirrored the server's own mistake, so
    # the whole revocation suite passed against a dialect nobody else speaks.
    # Found 2026-08-24 by pointing Certify the Web at the RA.
    #
    # "cert" stays accepted as a deprecated alias so existing in-house tooling
    # keeps working, but "certificate" is the spelling clients are told to use
    # and the one the error message names.
    cert_b64 = payload.get("certificate")
    if cert_b64 is None:
        cert_b64 = payload.get("cert")
    if not isinstance(cert_b64, str) or not cert_b64:
        raise malformed("missing or invalid certificate field")

    try:
        cert_der = _base64url_decode(cert_b64)
    except Exception as exc:
        raise malformed(f"certificate is not valid base64url: {exc}") from exc

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        raise malformed(f"unable to parse certificate: {exc}") from exc

    # RFC 5280 §5.3.1 reason codes, minus two that must never reach the CA:
    #
    #   7 — "unused" in RFC 5280, and `certutil` rejects it. An accepted 7
    #       would silently break the out-of-band loop, because the operator's
    #       `Revoke-Cert.ps1` would fail on the recorded reason (M-1).
    #
    #   8 — **removeFromCRL: the inverse of revocation.** This reached
    #       `certutil -revoke <serial> 8` verbatim through the pending list and
    #       the sync agent. A revokeCert carrying reason 8 therefore recorded a
    #       successful revocation in the RA — 410 on the certificate, order
    #       flipped, serial drained off the pending queue — while the CA-side
    #       call asked to *undo* a revocation rather than perform one. Plan 004
    #       confirmed the effect against the lab CA: a held certificate given
    #       reason 8 ends up "off the CRL and valid". The owner is told the
    #       certificate is contained while it stays live and trusted
    #       domain-wide.
    #
    # Valid set: {0,1,2,3,4,5,6,9,10}. Both exclusions use bad_revocation_reason.
    _VALID_REVOCATION_REASONS = frozenset({0, 1, 2, 3, 4, 5, 6, 9, 10})
    reason = payload.get("reason")
    if reason is not None and (
        not isinstance(reason, int)
        or isinstance(reason, bool)
        or reason not in _VALID_REVOCATION_REASONS
    ):
        raise bad_revocation_reason(
            "reason code must be an integer in the set 0-6, 9-10 "
            "(reason 7 is unused in RFC 5280 and rejected by certutil; "
            "reason 8 is removeFromCRL, which un-revokes rather than revokes)"
        )

    serial_hex = canonical_serial(format(cert.serial_number, "x"))

    # C-1: scope the serial lookup to (serial, account_id) so that a
    # serial collision cannot return another account's row.  Merging the
    # not-found and unauthorised outcomes into a single 404 avoids
    # information leakage about whether another account owns that serial.
    cert_record = ctx.store.get_certificate_by_serial(serial_hex, account_id)
    if cert_record is None:
        raise not_found("certificate not found in RA store")

    try:
        stored_cert = x509.load_pem_x509_certificate(
            cert_record.cert_pem.encode("utf-8")
        )
    except ValueError as exc:
        raise server_internal(
            f"the stored certificate for serial {serial_hex} does not parse"
        ) from exc

    # 2026-08-16 rescan F3: bind the *whole* submitted certificate to the
    # stored one, not just its serial.
    #
    # The lookup above matches on (serial, account_id), and both of those come
    # from the request. An owner could therefore submit a self-signed
    # certificate carrying the same serial and any SANs it liked: the lookup
    # still found the authoritative row, the right certificate was revoked —
    # and the mandatory `certificate-revoked` audit event recorded the
    # attacker's SAN list as if it were the issued one. The audit trail is the
    # authoritative record of a containment action, so letting the subject of
    # that action choose part of its contents is a defect even when the
    # security-relevant fields (id, serial, account) stay honest.
    #
    # Byte equality is the right bar here rather than a lenient re-check:
    # RFC 8555 §7.6 has the client submit the certificate it was issued, and
    # that is exactly the DER the RA stored and served back. Comparing
    # re-encoded DER (rather than the raw request bytes) normalises the
    # PEM/DER round trip without loosening anything.
    if cert.public_bytes(Encoding.DER) != stored_cert.public_bytes(Encoding.DER):
        raise malformed(
            "the submitted certificate does not match the certificate the RA "
            f"issued for serial {serial_hex}"
        )

    # Derived from the stored PEM, never from the request. Redundant now that
    # the bodies must match byte-for-byte, and deliberately so: this is the
    # field that reaches the audit row, and it should not depend on the
    # equality check above staying correct.
    cert_sans = _dns_sans(stored_cert)

    if cert_record.status == CertStatus.REVOKED:
        # H-4: an already-revoked cert returns 200 OK (idempotent). This is a
        # DELIBERATE DEVIATION, not RFC behaviour: RFC 8555 §7.6 says the server
        # "returns an error response with status code 400 (Bad Request) and
        # type ...:alreadyRevoked". The comment here used to claim the RFC
        # required the 200 (corrected 2026-10-01; open decision WI-037). The
        # 200 is kept because a client retrying a revocation that DID succeed
        # must not be told it failed -- Certify the Web already turned one
        # parse failure into a reported-failed revocation (2026-08-24, below).
        # Empty body, like every other success path here.
        return Response(status_code=200)

    try:
        revocation_result = ctx.revocation.revoke(
            cert_record.cert_pem,
            reason,
        )
    except Exception as exc:
        _audit(
            ctx,
            event_type="certificate-revoked",
            account_id=account_id,
            order_id=cert_record.order_id,
            sans=cert_sans,
            outcome="failed",
            details={
                "certificate_id": cert_record.id,
                "serial": serial_hex,
                "error": str(exc),
            },
        )
        raise server_internal(f"revocation failed: {exc}") from exc

    revoked_at = revocation_result.revoked_at or _now_iso()

    # Build the audit detail before the write: the certificate row, the order
    # transition, and this audit row all commit in ONE transaction, so the
    # details have to be known going in. See Store.record_revocation — a fault
    # between the three separate commits this replaces left a certificate
    # revoked in the store, served as 410 and queued for CA-side revocation,
    # with no certificate-revoked event anywhere in the authoritative trail.
    rev_meta = revocation_result.metadata
    # The ADCS ReqID is carried in the cert's RA-store metadata (set by the
    # enrollment leg), not on the cert itself — surface it so the operator's
    # Revoke-Cert.ps1 has both identifiers (serial + ReqID) without re-parsing.
    req_id = cert_record.metadata.get("req_id", "")
    audit_details: dict[str, Any] = {
        "certificate_id": cert_record.id,
        "serial": serial_hex,
        "reason": reason,
        # WI-010: honestly distinguish RA-store revocation from CA-CRL
        # revocation. The out-of-band leg records revocation_scope
        # "ra-store-only" and ca_crl_updated "false" — the cert is revoked in
        # the RA (GET → 410, order → revoked) but the CA CRL was NOT written.
        "revocation_scope": rev_meta.get("revocation_scope", "ra-store-only"),
        "ca_crl_updated": rev_meta.get("ca_crl_updated", "false"),
    }
    if req_id:
        audit_details["req_id"] = req_id

    (updated, won_cas), event = ctx.store.record_revocation(
        cert_id=cert_record.id,
        order_id=cert_record.order_id,
        account_id=account_id,
        reason=(
            revocation_result.reason
            if revocation_result.reason is not None
            else reason
        ),
        revoked_at=revoked_at,
        sans=cert_sans,
        audit_details=audit_details,
    )
    if updated is None:
        # The cert row vanished between the serial lookup and the UPDATE —
        # surface as 404 (no information leak; same outcome as not-found above).
        raise not_found("certificate not found in RA store")

    # M-3: the store signals deterministically whether this caller won the CAS.
    # If a concurrent revocation won (won_cas=False), treat it as idempotent
    # success (the H-4 deviation above; §7.6 itself says alreadyRevoked) and
    # DO NOT emit a duplicate audit event — the
    # winning revocation already recorded one with its own reason/timestamp.
    # Return 200 with an empty body (the out_of_band_revocation hint is NOT
    # re-emitted on the idempotent second call; the first call's audit already
    # recorded it). Deterministic signal — no timestamp-inference race.
    if not won_cas:
        return Response(status_code=200)

    # The order transition and the audit row committed with the certificate
    # CAS above. Only the SIEM fan-out is left, and it stays fail-open: the
    # durable record is the audit table row, already written.
    if event is not None:
        emit_audit_hook(ctx, event)

    revocation_scope = audit_details["revocation_scope"]
    ca_crl_updated = audit_details["ca_crl_updated"]

    # WI-010: surface the out-of-band step, but in a HEADER, not the body.
    #
    # This used to return the hint as a JSON body, on the stated assumption that
    # extra fields are "ignored by standard ACME clients". That assumption was
    # disproven live on 2026-08-24: Certify the Web fails to parse ANY JSON
    # object body here -- it errors at line 1, position 1, on the opening brace,
    # so even `{}` breaks it -- and then reports the revocation as FAILED to the
    # operator. The revocation had in fact succeeded. A false negative on a
    # revocation is worse than a missing hint: an operator may believe a
    # certificate is still live when it is not, or retry against a CA that has
    # already revoked it.
    #
    # RFC 8555 §7.6 asks only for 200 on success. An empty body is what every
    # public CA returns and what clients are built against, so that is what we
    # return. The hint moves to X-Acme-Ra-Out-Of-Band-Revocation, where tooling
    # that wants it can still read it and no JSON parser ever sees it. The same
    # information is, as before, in the audit row -- which remains the durable
    # record.
    headers: dict[str, str] = {}
    if ca_crl_updated == "false":
        hint: dict[str, Any] = {
            "ca_crl_updated": False,
            "revocation_scope": revocation_scope,
            "serial": serial_hex,
            "runbook": "scripts/Revoke-Cert.ps1 (run by a CA officer; see docs/threat-model.md §E)",
        }
        if req_id:
            hint["req_id"] = req_id
        # Compact, header-safe: no newlines, ASCII only.
        headers["X-Acme-Ra-Out-Of-Band-Revocation"] = json.dumps(
            hint, separators=(",", ":")
        )

    return Response(status_code=200, headers=headers)
