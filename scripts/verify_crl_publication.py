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
revoked is precisely the state this product's revocation story exists to
prevent. Leaving the lab in it also means the *next* session's CRL evidence and
the watermark's first-use baseline run against a CRL silently missing the prior
session's revocations.

**The teardown already claimed to do this.** Validation-log entries for earlier
rounds assert "revoked ... and the CRL republished", and at least one round did
not. That is the recurring shape: the step was believed done because the
sentence describing it was written, and nothing checked. So this script exists
to make the claim evidence-bearing rather than asserted — the same treatment the
runbook's preserve step already gets.

**Controls, because absence proves nothing on its own.** A CRL lookup that
matches nothing returns exactly what a correct negative returns. Two controls
separate the cases:

* the revoked serials are the **positive control**. If the lookup is broken —
  wrong CRL, wrong encoding, a comparison that never matches — they read as
  absent, and the run fails;
* ``--absent`` names a serial that must NOT be listed (an un-revoked
  certificate, or an arbitrary unused value). If it reads as listed, the lookup
  matches everything and a "found" verdict means nothing.

``--min-crl-number`` is the third: it proves the document is a *new* one rather
than the pre-revocation CRL still being served from a cache or a replica. Pass
the CRL Number observed before the republish.

Interaction with ``sample_crl_age.py``: a forced republication truncates the
current publication cycle. That **cannot** corrupt the served-age floor — a
truncated cycle only ever serves ages below the running maximum, so it can move
neither bound — but it does spend that cycle as a clean natural observation.
The trade is real and one-sided; do not skip the republish to protect the
sampler.

Usage::

    # after the teardown's revocation loop and `certutil -config <CA> -CRL`
    python scripts/verify_crl_publication.py \\
        --url http://ca.example/crl/ca.crl \\
        --revoked 5A00000123 --revoked 5A00000124 \\
        --absent 5A00000999 \\
        --min-crl-number 130

    # a CRL already on disk
    python scripts/verify_crl_publication.py --file ca.crl --revoked 5A00000123

Exit status is 0 only when every check passed. Output lines are stable and
greppable so a harness can assert on them:
``CRL-NUMBER=``, ``CRL-THIS-UPDATE=``, ``LISTED ``, ``MISSING ``,
``NEGATIVE-CONTROL=``, ``CRL-PUBLICATION-VERIFIED``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import requests
from cryptography import x509

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0


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
    revoked: list[int],
    absent: list[int],
    min_crl_number: int | None,
) -> tuple[list[str], list[str]]:
    """Return ``(report_lines, failures)``. Failures empty means verified."""
    lines: list[str] = []
    failures: list[str] = []

    number = crl_number(crl)
    lines.append(f"CRL-NUMBER={number if number is not None else 'absent'}")
    lines.append(f"CRL-THIS-UPDATE={crl.last_update_utc.isoformat()}")
    lines.append(
        f"CRL-NEXT-UPDATE="
        f"{crl.next_update_utc.isoformat() if crl.next_update_utc else 'absent'}"
    )
    lines.append(f"CRL-ENTRY-COUNT={len(crl)}")

    if min_crl_number is not None:
        if number is None:
            failures.append(
                "a minimum CRL Number was required but the document carries none, "
                "so it cannot be shown to be newer than the pre-revocation CRL"
            )
        elif number < min_crl_number:
            failures.append(
                f"CRL Number {number} is below the required minimum "
                f"{min_crl_number}: this is not a document published after the "
                "revocations"
            )

    # Build the listed set once. `get_revoked_certificate_by_serial_number`
    # exists, but iterating makes the entry count above and the membership test
    # come from the same read of the same document.
    listed = {entry.serial_number for entry in crl}

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
            "negative control: a serial that must NOT be listed; repeatable. "
            "Without one, 'not found' cannot be told from a lookup that "
            "matches nothing."
        ),
    )
    parser.add_argument(
        "--min-crl-number",
        type=int,
        default=None,
        help=(
            "fail unless the CRL Number is at least this. Pass the number "
            "observed BEFORE the republish, so a cached pre-revocation CRL "
            "cannot pass."
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

    lines, failures = check(
        crl, revoked=revoked, absent=absent, min_crl_number=args.min_crl_number
    )
    for line in lines:
        print(line)

    if failures:
        for failure in failures:
            print(f"CRL-PUBLICATION-FAILED {failure}", file=sys.stderr)
        return 1
    if revoked:
        print(
            f"CRL-PUBLICATION-VERIFIED serials={len(revoked)} "
            f"negative_controls={len(absent)} at "
            f"{datetime.now(UTC).isoformat()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
