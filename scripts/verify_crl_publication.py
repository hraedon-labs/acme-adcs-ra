#!/usr/bin/env python3
"""Prove, from the CDP, that a revocation reached a published CRL.

Why this exists (UNFILED item 26). The lab teardown revokes every certificate a
session caused the CA to issue and then restores the RA — but revoking at the CA
and *publishing* a CRL are two operations, and only the first was ever written
down. One round left thirty certificates revoked-but-unpublished for five and a
half hours, and would have left them that way until the next scheduled
publication; on a one-week ``CRLPeriod`` that is close to a week during which
every relying party still accepts them. It was found by accident, because an
unrelated publication made the entry count jump by thirty-one.

A certificate the CA considers revoked but that no relying party can see as
revoked is the gap this product's revocation evidence exists to make visible;
the least-privilege path accepts it only until the next scheduled publication. Leaving the lab in it also means the *next* session's CRL evidence and
the watermark's first-use baseline run against a CRL silently missing the prior
session's revocations.

**The teardown already claimed to do this.** Validation-log entries for earlier
rounds assert "revoked ... and the CRL republished", and at least one round did
not. That is the recurring shape: the step was believed done because the
sentence describing it was written, and nothing checked. So this script exists
to make the claim evidence-bearing rather than asserted — the same treatment the
runbook's preserve step already gets.

**Authenticity first.** ``--issuer`` (the issuing CA certificate, PEM or DER)
is required, and the CRL must name that CA as its issuer and carry a valid
signature under its key; it must also be a *base* CRL (a delta CRL is refused)
and still current (``nextUpdate`` in the future). Without those checks any
parseable document listing the serials - a CRL from another CA, an expired one,
one signed by nobody in particular - printed the verified banner (2026-10-01
cross-lineage review of PR #18). An entry whose reason is ``removeFromCRL`` is
the *un*-revoke marker, not a revocation, and is not counted as listed. A second
review round added: ``--issuer`` must be exactly one CA certificate able to sign
CRLs; ``thisUpdate`` may not be in the future (5 minutes' skew); an indirect CRL,
a CRL scoped away from end-entity certificates, an entry naming another issuer,
and any critical extension this script does not understand are all refused.
Rounds three and four added: an onlySomeReasons scope (even an empty one), an
--issuer file with anything but certificate blocks outside a leading BOM, an
issuer certificate outside its validity period, and a negative
--prior-crl-number; a malformed extension is "no verdict" (exit 2).

**Controls, because absence proves nothing on its own.** A CRL lookup that
matches nothing returns exactly what a correct negative returns. Two controls
separate the cases, and both are REQUIRED whenever a serial is checked:

* the revoked serials are the **positive control**. If the lookup is broken —
  wrong CRL, wrong encoding, a comparison that never matches — they read as
  absent, and the run fails;
* ``--absent`` names a serial that must NOT be listed (an un-revoked
  certificate, or an arbitrary unused value). If it reads as listed, the lookup
  matches everything and a "found" verdict means nothing.

``--prior-crl-number`` is the third, also required: the CRL Number observed
BEFORE the republish. The document must carry a number strictly greater than
it, which proves it is a *new* one rather than the pre-revocation CRL still
being served from a cache or a replica. (An earlier ``--min-crl-number``
accepted equality, so the very CRL observed before the republish passed.)

Interaction with ``sample_crl_age.py``: a forced republication truncates the
current publication cycle. That **cannot** corrupt the served-age floor — every
age a truncated cycle serves is a genuine served age, so it can never push the
observed maximum above the true one; it can only fail to reach it — but it does
spend that cycle as a clean natural observation.
The trade is real and one-sided; do not skip the republish to protect the
sampler.

Usage::

    # after the teardown's revocation loop and `certutil -config <CA> -CRL`
    python scripts/verify_crl_publication.py \\
        --url http://ca.example/crl/ca.crl \\
        --issuer issuing-ca.cer \\
        --revoked 5A00000123 --revoked 5A00000124 \\
        --absent 5A00000999 \\
        --prior-crl-number 130

    # a CRL already on disk
    python scripts/verify_crl_publication.py --file ca.crl --issuer issuing-ca.cer \\
        --revoked 5A00000123 --absent 5A00000999 --prior-crl-number 130

Exit status is 0 only when every check passed. Output lines are stable and
greppable so a harness can assert on them:
``CRL-NUMBER=``, ``CRL-THIS-UPDATE=``, ``LISTED ``, ``MISSING ``,
``NEGATIVE-CONTROL=``, ``CRL-SIGNATURE=``, ``CRL-PUBLICATION-VERIFIED``.
Exit 1 means "checked, and not proven"; exit 2 means no verdict (usage error,
missing control, unreadable issuer, unreachable CDP or unparseable body).
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
# Tolerated clock skew for a thisUpdate slightly ahead of this host's clock.
CLOCK_SKEW = timedelta(minutes=5)
# CRL extensions this verifier understands well enough to accept as critical.
# Anything else marked critical makes the document uninterpretable here
# (RFC 5280 section 5.2), so it is refused rather than read past. That includes
# a critical CRLNumber or AuthorityKeyIdentifier, which RFC 5280 says MUST be
# non-critical and ADCS marks non-critical; DeltaCRLIndicator is refused
# outright by its own check below.
_UNDERSTOOD_CRITICAL = frozenset({ExtensionOID.ISSUING_DISTRIBUTION_POINT})
_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----", re.DOTALL
)
_HEX = re.compile(r"\A[0-9A-Fa-f]+\Z")


def parse_serial(text: str) -> int:
    """Accept a serial as ADCS or the RA spell it, and mean the same number.

    ``certutil`` prints lowercase hex, the RA canonicalizes to uppercase with
    leading zeros stripped, and an operator pasting from either is right. A
    comparison that is case- or width-sensitive would report a genuinely listed
    serial as missing, which on this path reads as "the CA did not publish it"
    — the exact wrong conclusion.
    """
    cleaned = text.strip().replace(" ", "").replace(":", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError("empty serial")
    # ASCII hex only. int(x, 16) alone also takes "-5", "1_000" and non-ASCII
    # digits, each of which silently becomes a different number.
    if not _HEX.match(cleaned):
        raise ValueError(f"not a hex serial: {text!r}")
    return int(cleaned, 16)


def fetch(url: str, *, timeout: float, max_bytes: int, follow_redirects: bool) -> bytes:
    """Retrieve the CRL body, or raise.

    Redirects are not followed by default, matching the RA's own default: the
    hop target is chosen by whoever answers the CDP, and a check that quietly
    follows one is verifying a different endpoint than the RA reads.
    """
    with requests.get(
        url, timeout=timeout, stream=True, allow_redirects=follow_redirects
    ) as response:
        if response.status_code != 200:
            raise RuntimeError(f"CDP returned HTTP {response.status_code}")
        body = bytearray()
        for chunk in response.iter_content(64 * 1024):
            body.extend(chunk)
            if len(body) > max_bytes:
                raise RuntimeError(f"CRL exceeded {max_bytes} bytes")
    return bytes(body)


def load_crl(body: bytes) -> x509.CertificateRevocationList:
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(body)
        except ValueError:
            continue
    raise RuntimeError("body is neither valid DER nor PEM CRL")


def load_issuer(body: bytes) -> x509.Certificate:
    """Exactly one certificate, and it must be able to sign a CRL.

    A multi-certificate PEM is refused rather than reduced to its first entry,
    which for a saved chain is usually the wrong one and surfaces as a puzzling
    issuer mismatch.
    """
    try:
        certificates = [x509.load_der_x509_certificate(body)]
    except ValueError:
        # PEM must be ONLY certificate blocks: the PEM loader skips anything
        # between them, so a trailing DER certificate (or any other bytes)
        # would otherwise be dropped without a word.
        # A leading UTF-8 BOM (common in Windows-exported PEM) is tolerated;
        # any other bytes outside the certificate blocks are not.
        if _PEM_CERT.sub(b"", body.removeprefix(b"\xef\xbb\xbf")).strip():
            raise RuntimeError(
                "issuer file is neither one DER certificate nor PEM certificate "
                "blocks only"
            ) from None
        try:
            certificates = x509.load_pem_x509_certificates(
                body.removeprefix(b"\xef\xbb\xbf")
            )
        except ValueError:
            raise RuntimeError(
                "issuer file is neither a DER nor a PEM certificate"
            ) from None
    if len(certificates) != 1:
        raise RuntimeError(
            f"issuer file holds {len(certificates)} certificates; pass exactly "
            "the issuing CA certificate"
        )
    issuer = certificates[0]
    now = datetime.now(UTC)
    if not issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc:
        raise RuntimeError(
            f"issuer certificate is not currently valid (valid "
            f"{issuer.not_valid_before_utc.isoformat()} to "
            f"{issuer.not_valid_after_utc.isoformat()})"
        )
    if not _can_sign_crls(issuer):
        raise RuntimeError(
            "issuer certificate is not a CA able to sign CRLs (needs "
            "BasicConstraints CA=true, and cRLSign when KeyUsage is present)"
        )
    return issuer


def _can_sign_crls(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except (x509.ExtensionNotFound, ValueError):
        return False
    if not constraints.ca:
        return False
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    except ValueError:
        return False
    return bool(usage.crl_sign)


def _is_remove_from_crl(entry: x509.RevokedCertificate) -> bool:
    try:
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value
    except x509.ExtensionNotFound:
        return False
    return reason.reason == x509.ReasonFlags.remove_from_crl


def _signature_valid(
    crl: x509.CertificateRevocationList, issuer: x509.Certificate
) -> bool:
    try:
        return bool(crl.is_signature_valid(issuer.public_key()))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # A key type that cannot sign a CRL cannot have signed this one.
        return False


def crl_number(crl: x509.CertificateRevocationList) -> int | None:
    try:
        return int(
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        return None


def check(
    crl: x509.CertificateRevocationList,
    *,
    issuer: x509.Certificate,
    revoked: list[int],
    absent: list[int],
    prior_crl_number: int | None,
    now: datetime | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(report_lines, failures)``. Failures empty means verified."""
    lines: list[str] = []
    failures: list[str] = []
    now = now or datetime.now(UTC)

    # Authenticity before content: a membership answer from a document nobody
    # vouches for is not evidence of anything.
    if crl.issuer != issuer.subject:
        lines.append("CRL-SIGNATURE=issuer-mismatch")
        failures.append(
            f"CRL issuer {crl.issuer.rfc4514_string()!r} is not the supplied CA "
            f"{issuer.subject.rfc4514_string()!r}"
        )
    elif not _signature_valid(crl, issuer):
        lines.append("CRL-SIGNATURE=invalid")
        failures.append("CRL signature does not verify under the supplied CA key")
    else:
        lines.append("CRL-SIGNATURE=valid")
    try:
        crl.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR)
    except x509.ExtensionNotFound:
        pass
    else:
        failures.append(
            "this is a delta CRL; membership in a delta is not publication in "
            "the base CRL relying parties fetch - point at the base CRL"
        )
    for extension in crl.extensions:
        if extension.critical and extension.oid not in _UNDERSTOOD_CRITICAL:
            failures.append(
                f"CRL carries a critical extension this verifier does not "
                f"understand ({extension.oid.dotted_string}); it cannot be "
                "interpreted safely"
            )
    try:
        idp = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if idp.indirect_crl:
            failures.append(
                "this is an indirect CRL; its entries can belong to other CAs, "
                "so a serial match does not attribute a revocation to --issuer"
            )
        # `is not None`: a present-but-EMPTY onlySomeReasons is still a scope
        # (2026-10-01 round 4), and a falsy test let it through.
        if idp.only_some_reasons is not None:
            failures.append(
                "this CRL is scoped to some revocation reasons only, so it can "
                "be silent about a revocation for any other reason"
            )
        if idp.only_contains_ca_certs or idp.only_contains_attribute_certs:
            failures.append(
                "this CRL's scope excludes end-entity certificates, so it is not "
                "the CRL relying parties check for them"
            )
    if crl.last_update_utc > now + CLOCK_SKEW:
        failures.append(
            f"CRL thisUpdate {crl.last_update_utc.isoformat()} is in the future: "
            "a document not yet in force is not evidence of a publication"
        )
    if crl.next_update_utc is None:
        failures.append("CRL carries no nextUpdate, so its currency cannot be shown")
    elif crl.next_update_utc <= now:
        failures.append(
            f"CRL expired at {crl.next_update_utc.isoformat()}: a stale document "
            "is not evidence of a publication after the revocations"
        )

    number = crl_number(crl)
    lines.append(f"CRL-NUMBER={number if number is not None else 'absent'}")
    lines.append(f"CRL-THIS-UPDATE={crl.last_update_utc.isoformat()}")
    lines.append(
        f"CRL-NEXT-UPDATE="
        f"{crl.next_update_utc.isoformat() if crl.next_update_utc else 'absent'}"
    )
    lines.append(f"CRL-ENTRY-COUNT={len(crl)}")

    if prior_crl_number is not None:
        if number is None:
            failures.append(
                "a prior CRL Number was supplied but the document carries none, "
                "so it cannot be shown to be newer than the pre-revocation CRL"
            )
        elif number <= prior_crl_number:
            failures.append(
                f"CRL Number {number} is not greater than the prior number "
                f"{prior_crl_number}: this is not a document published after the "
                "revocations"
            )

    # Build the listed set once. `get_revoked_certificate_by_serial_number`
    # exists, but iterating makes the entry count above and the membership test
    # come from the same read of the same document.
    # removeFromCRL is the un-revoke marker (it appears in delta CRLs); an entry
    # carrying it says the certificate is NOT revoked, so it must not count.
    listed = {entry.serial_number for entry in crl if not _is_remove_from_crl(entry)}
    for entry in crl:
        # Entry-level: a certificateIssuer entry (indirect CRL) names another
        # CA, and any other critical entry extension is uninterpretable here.
        for extension in entry.extensions:
            if extension.critical or extension.oid == (
                x509.oid.CRLEntryExtensionOID.CERTIFICATE_ISSUER
            ):
                failures.append(
                    f"CRL entry {entry.serial_number:X} carries "
                    f"{extension.oid.dotted_string} (critical or certificateIssuer); "
                    "it cannot be attributed to --issuer safely"
                )
                break

    for serial in revoked:
        if serial in listed:
            lines.append(f"LISTED {serial:X}")
        else:
            lines.append(f"MISSING {serial:X}")
            failures.append(
                f"serial {serial:X} was revoked at the CA but is NOT on the "
                "published CRL"
            )

    for serial in absent:
        if serial in listed:
            lines.append(f"NEGATIVE-CONTROL={serial:X} PRESENT")
            failures.append(
                f"negative control {serial:X} is listed on the CRL, so a "
                "'listed' verdict here proves nothing"
            )
        else:
            lines.append(f"NEGATIVE-CONTROL={serial:X} absent")

    if not revoked:
        # Not a failure — a teardown that revoked nothing has nothing to prove
        # — but it must not print a verification banner either. An empty check
        # reporting success is how a green gate ends up meaning nothing.
        lines.append("NO-SERIALS-SUPPLIED (nothing was checked)")
    return lines, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify from the CDP that revocations reached a published CRL"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="CDP URL to fetch the CRL from")
    source.add_argument("--file", help="a CRL already on disk (DER or PEM)")
    parser.add_argument(
        "--issuer",
        required=True,
        help=(
            "the issuing CA certificate (DER or PEM). The CRL must name it as "
            "issuer and verify under its key."
        ),
    )
    parser.add_argument(
        "--revoked",
        action="append",
        default=[],
        metavar="SERIAL",
        help="a serial that MUST be listed; repeatable. Hex, any case.",
    )
    parser.add_argument(
        "--absent",
        action="append",
        default=[],
        metavar="SERIAL",
        help=(
            "negative control: a serial that must NOT be listed; repeatable, "
            "and required with --revoked. Without one, 'found' cannot be told "
            "from a lookup that matches everything."
        ),
    )
    parser.add_argument(
        "--prior-crl-number",
        type=int,
        default=None,
        help=(
            "the CRL Number observed BEFORE the republish; required with "
            "--revoked. Fails unless the document's number is strictly "
            "greater, so a cached pre-revocation CRL cannot pass."
        ),
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--follow-redirects", action="store_true")
    args = parser.parse_args(argv)

    try:
        revoked = [parse_serial(s) for s in args.revoked]
        absent = [parse_serial(s) for s in args.absent]
    except ValueError as exc:
        print(f"CRL-PUBLICATION-FAILED bad serial: {exc}", file=sys.stderr)
        return 2
    if args.prior_crl_number is not None and args.prior_crl_number < 0:
        # A CRL Number is non-negative, so a negative "prior" was never
        # observed and would let CRL Number 0 pass the freshness control.
        print(
            "CRL-PUBLICATION-INDETERMINATE --prior-crl-number must be a CRL "
            "Number actually observed (>= 0)",
            file=sys.stderr,
        )
        return 2
    if revoked and (not absent or args.prior_crl_number is None):
        # The controls are what make a "listed" answer mean something. A run
        # without them cannot verify, so it does not get to try.
        print(
            "CRL-PUBLICATION-INDETERMINATE --revoked requires at least one "
            "--absent negative control and --prior-crl-number",
            file=sys.stderr,
        )
        return 2
    try:
        issuer = load_issuer(Path(args.issuer).read_bytes())
    except (OSError, RuntimeError) as exc:
        print(f"CRL-PUBLICATION-INDETERMINATE issuer: {exc}", file=sys.stderr)
        return 2

    try:
        body = (
            Path(args.file).read_bytes()
            if args.file
            else fetch(
                args.url,
                timeout=args.timeout,
                max_bytes=args.max_bytes,
                follow_redirects=args.follow_redirects,
            )
        )
        crl = load_crl(body)
    except (OSError, RuntimeError, requests.RequestException) as exc:
        # A fetch failure is NOT "the serials are unpublished"; it is no
        # evidence either way, and it must not read as either verdict.
        print(f"CRL-PUBLICATION-INDETERMINATE {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2

    try:
        lines, failures = check(
            crl,
            issuer=issuer,
            revoked=revoked,
            absent=absent,
            prior_crl_number=args.prior_crl_number,
        )
    except (ValueError, x509.DuplicateExtension) as exc:
        # cryptography parses extensions lazily, so a malformed or duplicated
        # one surfaces here rather than at load. No verdict, not a traceback.
        print(f"CRL-PUBLICATION-INDETERMINATE malformed CRL: {exc}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)

    if failures:
        for failure in failures:
            print(f"CRL-PUBLICATION-FAILED {failure}", file=sys.stderr)
        return 1
    if revoked:
        print(
            f"CRL-PUBLICATION-VERIFIED serials={len(revoked)} "
            f"negative_controls={len(absent)} "
            f"source={'file' if args.file else 'url'} at "
            f"{datetime.now(UTC).isoformat()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
