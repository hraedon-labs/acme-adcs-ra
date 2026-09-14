"""Recover missing issuer material for a stored certificate (UNFILED item 25).

A **transport orphan** — a certificate the CA issued but whose chain fetch
failed — is stored with its leaf and an EMPTY ``chain_pem``. CRL evidence
verifies the CRL's signature against the issuing CA certificate taken from the
certificate's *own stored chain* (deliberately: selecting the issuer by name
rather than by signature picks the wrong generation across a CA key rollover),
so an orphan has no issuer certificate and every confirmation is refused. With
``require_crl_evidence=true`` that is permanent, and it is permanent for the
population the RA knows *least* about — certificates that are live at the CA.

The fix is deliberately narrow: **recover the missing evidence, then run the
existing verifier unchanged.** Nothing about the trust model moves. The same
signature check, the same freshness ceiling, the same watermark; only the input
is repaired.

**Where the material comes from.** The RA's own store already holds complete
chains from the same CA for every certificate it issued successfully. That
material arrived over the *same* authenticated enrollment leg as the orphan
itself, so it carries the same provenance — a strictly better source than a new
trust setting, and it works *after* the failure rather than depending on another
network request succeeding during quarantine.

``ACME_RA_ADCS_CA_BUNDLE`` is **not** a candidate source and must never become
one. It is TLS trust for the ``/certsrv/`` leg; a knob that means "trust this
for transport" quietly acquiring the second meaning "trust this to attest
issuance" is exactly the kind of overload that is invisible in review.

**Deduplicate by fingerprint, select by signature.** Collapsing candidates by
subject name would discard the generation that actually signed the orphan: a CA
key renewal keeps the DN and changes the key, so a store holding both
generations has two equally good name matches and only one of them is right.
``verify_directly_issued_by`` dispatches on the signature algorithm, so an
ECDSA CA works too — a hand-rolled PKCS1v15 check fails silently there.

Not in scope, and deliberately so: the cold-start inventory fallback (an orphan
produced before the store holds any complete chain from that CA), and
CA-database reconciliation for the **leafless** class, which has no certificate
row at all and needs an operator revoking by ReqID at the CA.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

logger = logging.getLogger(__name__)

# How far a recovered path is followed upwards. A chain from this CA is leaf ->
# issuing CA -> root; the cap exists so a pathological candidate pool cannot
# turn recovery into an unbounded walk. Cycles are already impossible (every
# link is consumed by fingerprint), so this only bounds depth.
MAX_CHAIN_DEPTH = 8

# Bounds on the scan of stored chains. Both are reported in the outcome, so an
# empty result can be told apart from a result that ran out of budget -- a check
# whose failure mode is silence has to say how far it looked.
DEFAULT_MAX_ROWS = 1000
DEFAULT_MAX_CANDIDATES = 64


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    """Uppercase hex SHA-256 of the DER encoding.

    The identity used for deduplication and for the audit record. It names the
    key material, which is the thing that matters here; a subject DN does not.
    """
    return certificate.fingerprint(hashes.SHA256()).hex().upper()


@dataclass(frozen=True)
class CandidateIssuer:
    """One distinct CA certificate found in the store, and where it came from."""

    certificate: x509.Certificate
    fingerprint: str
    source_certificate_id: str

    @property
    def pem(self) -> str:
        return self.certificate.public_bytes(Encoding.PEM).decode("ascii")


@dataclass(frozen=True)
class RecoveryOutcome:
    """What a recovery attempt found, including how hard it looked.

    ``chain_pem`` is empty when nothing verified. ``rows_scanned`` and
    ``candidates_considered`` are part of the answer rather than debug noise:
    "no issuer found" over an empty candidate pool is a cold store, and "no
    issuer found" over sixty-four distinct CA certificates is a different fact
    entirely. Reporting one as the other is how a negative result gets believed
    for the wrong reason.
    """

    chain_pem: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    source_certificate_ids: list[str] = field(default_factory=list)
    rows_scanned: int = 0
    candidates_considered: int = 0
    truncated: bool = False
    detail: str = ""

    @property
    def recovered(self) -> bool:
        return bool(self.chain_pem)


def collect_candidate_issuers(
    chains: Iterable[tuple[str, Sequence[str]]],
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> tuple[list[CandidateIssuer], int, bool]:
    """Distinct CA certificates from stored chains, newest source first.

    *chains* is ``(certificate_id, chain_pem)`` pairs. A chain entry may itself
    hold several concatenated PEM certificates, which is how ADCS's p7b arrives
    once unwrapped, so each entry is parsed as a list rather than as one
    certificate.

    Returns ``(candidates, rows_scanned, truncated)``. ``truncated`` is True
    when a bound stopped the scan early, so a caller that found nothing knows
    whether the store was exhausted.
    """
    candidates: list[CandidateIssuer] = []
    seen: set[str] = set()
    rows_scanned = 0
    truncated = False
    for certificate_id, chain_pem in chains:
        if rows_scanned >= max_rows:
            truncated = True
            break
        rows_scanned += 1
        for entry in chain_pem or ():
            try:
                parsed = x509.load_pem_x509_certificates(entry.encode("utf-8"))
            except (ValueError, TypeError):
                # A malformed stored chain entry is not a reason to abandon the
                # search; the next row may hold the material.
                continue
            for certificate in parsed:
                fingerprint = certificate_fingerprint(certificate)
                if fingerprint in seen:
                    continue
                if len(candidates) >= max_candidates:
                    truncated = True
                    break
                seen.add(fingerprint)
                candidates.append(
                    CandidateIssuer(
                        certificate=certificate,
                        fingerprint=fingerprint,
                        source_certificate_id=certificate_id,
                    )
                )
            if truncated:
                break
        if truncated:
            break
    return candidates, rows_scanned, truncated


def _direct_issuer(
    child: x509.Certificate,
    candidates: Sequence[CandidateIssuer],
    consumed: set[str],
) -> CandidateIssuer | None:
    """The candidate whose key actually signed *child*, or None.

    Name equality is a filter, never the decision — same rule as
    ``crl_evidence._issuing_ca_certificate``, and for the same reason.
    """
    for candidate in candidates:
        if candidate.fingerprint in consumed:
            continue
        if candidate.certificate.subject != child.issuer:
            continue
        try:
            child.verify_directly_issued_by(candidate.certificate)
        except (ValueError, TypeError, InvalidSignature):
            # Right name, wrong key — keep looking for the generation that
            # actually signed this certificate.
            continue
        return candidate
    return None


def build_verified_chain(
    leaf: x509.Certificate, candidates: Sequence[CandidateIssuer]
) -> list[CandidateIssuer]:
    """Walk upwards from *leaf*, verifying every link by signature.

    Stops at a self-issued certificate (the root), when no candidate signs the
    current certificate, or at ``MAX_CHAIN_DEPTH``. Every element returned has
    been signature-verified against the one below it, so a partial path is
    still an honest one: it just does not reach a root.
    """
    path: list[CandidateIssuer] = []
    consumed: set[str] = set()
    current = leaf
    for _ in range(MAX_CHAIN_DEPTH):
        issuer = _direct_issuer(current, candidates, consumed)
        if issuer is None:
            break
        path.append(issuer)
        consumed.add(issuer.fingerprint)
        if issuer.certificate.subject == issuer.certificate.issuer:
            break
        current = issuer.certificate
    return path


def recover_issuer_chain(
    cert_pem: str,
    chains: Iterable[tuple[str, Sequence[str]]],
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> RecoveryOutcome:
    """Rebuild issuer material for *cert_pem* out of other stored chains.

    Pure: it reads nothing and writes nothing. The caller supplies the stored
    chains and decides what to do with the outcome, which keeps the selection
    rule testable without a store and keeps the write on the one path that is
    allowed to make it.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except (ValueError, TypeError):
        return RecoveryOutcome(detail="the stored certificate is not valid PEM")

    candidates, rows_scanned, truncated = collect_candidate_issuers(
        chains, max_rows=max_rows, max_candidates=max_candidates
    )
    if not candidates:
        return RecoveryOutcome(
            rows_scanned=rows_scanned,
            truncated=truncated,
            detail=(
                "no stored chain holds any CA certificate, so there is nothing "
                f"to recover from ({rows_scanned} chain(s) scanned)"
            ),
        )

    path = build_verified_chain(leaf, candidates)
    if not path:
        return RecoveryOutcome(
            rows_scanned=rows_scanned,
            candidates_considered=len(candidates),
            truncated=truncated,
            detail=(
                f"none of the {len(candidates)} distinct CA certificate(s) in "
                f"{rows_scanned} stored chain(s) signed this certificate"
            ),
        )

    return RecoveryOutcome(
        chain_pem=[link.pem for link in path],
        fingerprints=[link.fingerprint for link in path],
        subjects=[link.certificate.subject.rfc4514_string() for link in path],
        source_certificate_ids=[link.source_certificate_id for link in path],
        rows_scanned=rows_scanned,
        candidates_considered=len(candidates),
        truncated=truncated,
        detail=(
            f"recovered {len(path)} issuer certificate(s) by signature from "
            f"{len(candidates)} distinct candidate(s) in {rows_scanned} stored "
            "chain(s)"
        ),
    )
