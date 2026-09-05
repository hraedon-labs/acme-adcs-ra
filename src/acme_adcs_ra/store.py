"""SQLite persistence for accounts, orders, authorizations, certificates, and audit.

The store is intentionally plain sqlite3 — no ORM, no migrations beyond
``CREATE TABLE IF NOT EXISTS``.  It is part of the issuance path and therefore
carries no signing primitives.
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple

from cryptography import x509

from acme_adcs_ra.audit_bounds import bound_details, bound_value
from acme_adcs_ra.crl_evidence import CrlWatermark
from acme_adcs_ra.jws import canonicalize_jwk, jwk_thumbprint

# ---------------------------------------------------------------------------
# Status enums — replace bare string literals throughout the codebase
# ---------------------------------------------------------------------------


class OrderStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"
    REVOKED = "revoked"


class CertStatus(StrEnum):
    VALID = "valid"
    REVOKED = "revoked"
    # The CA issued this certificate, but a post-issuance verifier (SAN, EKU,
    # or CA-capability) rejected it. It is recorded so the serial is knowable
    # and revocable, and it is NEVER served to a client. See
    # Store.quarantine_certificate.
    QUARANTINED = "quarantined"


class AccountStatus(StrEnum):
    VALID = "valid"
    DEACTIVATED = "deactivated"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return a UTC RFC 3339 / ISO 8601 timestamp."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso_plus(seconds: int) -> str:
    """Return a UTC RFC 3339 timestamp ``seconds`` in the future."""
    return (datetime.now(UTC) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_iso(ts: str) -> datetime:
    """Parse a UTC RFC 3339 timestamp produced by ``_now_iso``.

    Only accepts the ``%Y-%m-%dT%H:%M:%SZ`` format that ``_now_iso`` emits.
    Returns a timezone-aware datetime (UTC). Raises ``ValueError`` if *ts*
    does not match.
    """
    return datetime.strptime(ts, _ISO_FORMAT).replace(tzinfo=UTC)


def is_expired(expires: str, *, now: datetime | None = None) -> bool:
    """Return True if an RFC 3339 ``expires`` timestamp is at or past ``now``.

    Used to enforce RFC 8555 §7.1.6: an order whose ``expires`` is in the past
    MUST NOT be finalized, and the server SHOULD transition it to ``invalid``.
    """
    return _parse_iso(expires) <= (now or datetime.now(UTC))


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _load_json(text: str | None) -> Any:
    if text is None:
        return None
    return json.loads(text)


class StoreMigrationError(RuntimeError):
    """A schema migration could not complete safely, so the RA must not start.

    Reserved for migrations whose failure would leave a *security* control
    silently inoperative — the serial backfill, whose absence makes
    certificates unrevokable. Migrations that only lose a redundant defence
    log and continue instead.
    """


def canonical_serial(serial_hex: str) -> str:
    """Normalize a hex serial to the single form the store keys on.

    Serials reach the RA from three directions that disagree on presentation:
    ``format(n, 'x')`` (no padding), ``certutil`` output (lowercase,
    zero-padded to an even length), and operator copy-paste (sometimes
    ``0x``-prefixed). Storing one form and looking up another silently fails
    to find the row — for the revocation-confirm callback that means the serial
    never drops out of the pending set and is re-revoked on every sweep.

    Canonical form: no ``0x`` prefix, no leading zeros, uppercase. ``"0"``
    survives as ``"0"`` rather than becoming empty.
    """
    stripped = serial_hex.strip().upper().removeprefix("0X")
    return stripped.lstrip("0") or "0"


def _serial_from_pem(cert_pem: str) -> str:
    """Return the certificate serial number in canonical uppercase hex."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return canonical_serial(format(cert.serial_number, "x"))


def _validity_from_pem(cert_pem: str) -> tuple[str, str]:
    """Return ``(not_before, not_after)`` as UTC ISO-8601 with a ``Z`` suffix.

    Recorded as columns rather than re-parsed on demand because the audit
    retention floor is a function of how long the certificates this RA actually
    issues stay valid: retaining for less than that leaves a *live* certificate
    with no issuance record, which is an evidence hole rather than a capacity
    choice. Deriving it from observed issuance rather than from configuration is
    deliberate — ADCS can issue shorter than the template asks (CA validity
    clamping), so the template is a request and the certificate is the fact.

    The ``Z`` format matches ``_now_iso`` so the columns sort and range-compare
    against the rest of the schema's timestamps.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    # The naive *_utc accessors are the non-deprecated ones and already UTC.
    return (
        cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _processing_cas(
    sql: str, params: tuple[Any, ...], expected_generation: int | None
) -> tuple[str, tuple[Any, ...]]:
    """Optionally narrow a ``status = 'processing'`` CAS to one lease generation.

    Every transition *out* of ``processing`` ends an enrollment lease. When the
    caller knows which lease it is ending — its own, or the one it read before
    deciding — it passes that generation and the UPDATE additionally requires
    ``processing_generation = ?``. A caller that legitimately does not hold or
    observe a lease passes None and gets the plain status CAS.

    ``sql`` must end with the ``AND status = ?`` clause, which is where the
    generation predicate is appended.
    """
    if expected_generation is None:
        return sql, params
    return f"{sql} AND processing_generation = ?", (*params, expected_generation)


NONCE_TTL_SECONDS: int = 1800  # 30 minutes
NONCE_GC_PROBABILITY: int = 100  # 1-in-N chance to clean expired nonces on create


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccountRecord:
    id: str
    status: str
    jwk_json: str
    eab_kid: str
    created_at: str
    contact: list[str]
    orders_url: str | None = None


@dataclass(frozen=True)
class OrderRecord:
    id: str
    account_id: str
    status: str
    identifiers: list[dict[str, str]]
    authorizations: list[str]
    finalize_url: str
    certificate_url: str | None
    expires: str
    created_at: str
    updated_at: str
    processing_started_at: str | None = None
    # Monotonic counter, incremented on every entry into ``processing``. It is
    # the durable identity of the current enrollment lease: a worker that was
    # admitted under generation N must not touch the CA once the row has moved
    # on. See Store.acquire_processing_lease / holds_processing_lease.
    processing_generation: int = 0
    # ADCS ReqID of an accepted-but-undecided CA request, or None. See the
    # schema comment and Store.record_pending_ca_request.
    pending_ca_request_id: str | None = None


@dataclass(frozen=True)
class AuthorizationRecord:
    id: str
    account_id: str
    order_id: str
    identifier: dict[str, str]
    status: str
    expires: str
    challenges: list[ChallengeRecord]


@dataclass(frozen=True)
class ChallengeRecord:
    id: str
    authz_id: str
    type: str
    status: str
    token: str
    url: str
    validated_at: str | None


@dataclass(frozen=True)
class CertificateRecord:
    id: str
    order_id: str
    account_id: str
    cert_pem: str
    chain_pem: list[str]
    template: str
    requester: str
    issued_at: str
    metadata: dict[str, str]
    serial_number: str | None = None
    status: str = "valid"
    revocation_reason: int | None = None
    revoked_at: str | None = None
    ca_crl_updated: bool = False


class RevocationUpdate(NamedTuple):
    """Result of a CAS-guarded certificate revocation.

    ``won_cas`` is True when *this* caller's UPDATE flipped the row from
    ``valid`` to ``revoked``; False when a concurrent revocation had already
    won (the returned ``record`` is the existing, already-revoked row, and
    the caller should treat it as idempotent success without re-auditing).
    ``record`` is None only when no certificate row exists for the id.
    """

    record: CertificateRecord | None
    won_cas: bool


class OrderRateLimitExceeded(Exception):
    """Raised when atomic order creation would exceed a configured ceiling."""

    def __init__(
        self,
        *,
        scope: str,
        limit: int,
        count: int,
        window_seconds: int,
        eab_kid: str | None = None,
    ) -> None:
        super().__init__(f"{scope} order rate limit exceeded")
        self.scope = scope
        self.limit = limit
        self.count = count
        self.window_seconds = window_seconds
        self.eab_kid = eab_kid


class EabAccountLimitExceeded(Exception):
    """Raised when a lifetime EAB-kid account quota is exhausted."""

    def __init__(self, *, kid: str, limit: int, count: int) -> None:
        super().__init__("EAB account limit exceeded")
        self.kid = kid
        self.limit = limit
        self.count = count


class KeyChangeRateLimitExceeded(Exception):
    """Raised when atomic key rollover would exceed the per-kid window ceiling."""

    def __init__(
        self, *, kid: str, limit: int, count: int, window_seconds: int
    ) -> None:
        super().__init__("key change rate limit exceeded")
        self.kid = kid
        self.limit = limit
        self.count = count
        self.window_seconds = window_seconds


class AccountKeyStale(Exception):
    """Raised when a rollover was authorized by a key that is no longer current."""


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    jwk_json TEXT NOT NULL,
    eab_kid TEXT NOT NULL,
    contact TEXT NOT NULL,  -- JSON array
    created_at TEXT NOT NULL,
    jwk_thumbprint TEXT  -- RFC 7638 account-key identity, for dedup
);
CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint
    ON accounts (jwk_thumbprint);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_created_at
    ON nonces (created_at);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    status TEXT NOT NULL,
    identifiers TEXT NOT NULL,  -- JSON array
    authorizations TEXT NOT NULL,  -- JSON array of URLs
    finalize_url TEXT NOT NULL,
    certificate_url TEXT,
    expires TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    processing_started_at TEXT,
    processing_generation INTEGER NOT NULL DEFAULT 0,
    -- The ADCS ReqID of a request the CA accepted but has not decided.
    -- Non-NULL means a live request exists in the CA database that may still
    -- become a certificate; reopening the order for a retry while it is set
    -- risks a second issuance. See Store.record_pending_ca_request.
    pending_ca_request_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_status_created
    ON orders (status, created_at);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    identifier TEXT NOT NULL,  -- JSON object
    status TEXT NOT NULL,
    expires TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    authz_id TEXT NOT NULL REFERENCES authorizations(id),
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    token TEXT NOT NULL,
    url TEXT NOT NULL,
    validated_at TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    cert_pem TEXT NOT NULL,
    chain_pem TEXT NOT NULL,  -- JSON array
    template TEXT NOT NULL,
    requester TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    metadata TEXT NOT NULL,  -- JSON object
    serial_number TEXT,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revoked_at TEXT,
    ca_crl_updated INTEGER NOT NULL DEFAULT 0,
    not_before TEXT,
    not_after TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    account_id TEXT,
    order_id TEXT,
    sans TEXT,  -- JSON array
    template TEXT,
    requester TEXT,
    outcome TEXT NOT NULL,
    details TEXT NOT NULL,  -- JSON object
    timestamp TEXT NOT NULL
);

-- audit_log carried no index at all beyond its primary key, so every
-- time-ranged read was a full table scan. That was invisible while the table
-- was small and becomes the dominant cost once retention keeps months of rows:
-- the footprint report, the oldest/newest probe and the retention sweep are all
-- range queries on timestamp. The column is fixed-width UTC (`...Z`, written by
-- _now_iso), so lexicographic order is chronological order and BETWEEN/`<`
-- comparisons are correct without parsing.
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
    ON audit_log(timestamp);

-- The newest CRL this RA has acted on, per issuing CA (UNFILED item 23).
--
-- One row per CA, not per CDP URL: the URL is operator configuration and moves
-- for reasons unconnected to the CA's identity, so keying on it would reset the
-- control silently every time a CDP was repointed. `issuer_key` is a digest
-- over the issuer DN *and* the signing key's SPKI, computed only after that key
-- has verified the document — so a CA key rollover produces a fresh watermark
-- by construction rather than by special case, and nobody who merely answers
-- the CDP can choose which watermark they are compared against.
--
-- `crl_number` is TEXT because a CRL Number is an unbounded integer (RFC 5280
-- §5.2.3 permits 20 octets); it is compared as an int, never lexicographically.
CREATE TABLE IF NOT EXISTS crl_watermark (
    issuer_key TEXT PRIMARY KEY,
    crl_number TEXT,
    this_update TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source_url TEXT
);
"""


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class Store:
    """SQLite-backed RA store."""

    def __init__(
        self,
        db_path: Path,
        order_expiry_seconds: int = 3600,
        max_authorizations_per_order: int = 50,
    ) -> None:
        self._db_path = db_path
        self._order_expiry_seconds = order_expiry_seconds
        self._max_authorizations_per_order = max_authorizations_per_order
        # Ensure parent directory exists so SQLite can create the file.
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        # FastAPI runs sync handlers in a threadpool, so issuance requests open
        # concurrent connections. Without a busy timeout, a second writer hits
        # "database is locked" immediately and surfaces as a 500 instead of the
        # graceful CAS-loss path; WAL lets readers proceed alongside one writer.
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate_certificates_table(conn)
            self._migrate_accounts_table(conn)
            self._migrate_orders_table(conn)
            self._migrate_authorizations_table(conn)
            self._migrate_certificates_unique_order_index(conn)
            self._migrate_accounts_canonical_jwk(conn)
            self._migrate_accounts_unique_thumbprint_index(conn)

    def _migrate_accounts_canonical_jwk(self, conn: sqlite3.Connection) -> None:
        """Rewrite stored account JWKs into their one canonical encoding.

        Until the 2026-08-18 F5 fix, ``n``/``e``/``x``/``y`` were decoded
        leniently: padded base64url and non-minimal leading-zero integers built
        the same key but hashed to a *different* thumbprint, so one key could
        hold several accounts and deactivating the observed one left a twin
        usable. The verifier is now strict, which leaves two jobs for an
        already-deployed database.

        First, **rescue**: a legacy account whose stored JWK is non-canonical
        would otherwise stop authenticating outright, because
        ``authenticate_account`` rebuilds its key from ``jwk_json``. Re-encoding
        the members changes no key material — only its spelling — so the row is
        rewritten in place and its thumbprint recomputed. The account URL is the
        row id, so clients see nothing.

        Second, **refuse to serve a twin**. Two rows that normalize to the same
        key are the deactivation bypass F5 exists to close, and merging them
        automatically would silently join two accounts' order histories and
        rate-limit accounting.

        **Two passes, and nothing is written until the whole picture is known**
        (2026-08-18 rescan F1). The first version canonicalized row by row with
        only advisory duplicate detection, which failed both ways depending on
        row order and on whether the UNIQUE index already existed:

        * index present — rewriting a non-canonical row to its canonical twin's
          thumbprint raised ``UNIQUE constraint failed`` out of ``Store``
          construction. An uncaught ``IntegrityError`` during startup, from a
          migration whose job was to *repair* the database.
        * index absent — the twin was logged, the index creation then failed and
          was suppressed, and the RA served with **both rows holding the same
          canonical key**. Deactivating one still left the other usable, so the
          migration preserved exactly the bypass it was written to remove.

        So: read and canonicalize everything in memory, group by the thumbprint
        each row *will* have, and refuse startup on any collision before a single
        UPDATE runs. A duplicate account key is a security-invariant violation
        and an operator decision, not something to log past.
        """
        log = logging.getLogger(__name__)
        rows = conn.execute("SELECT id, jwk_json, jwk_thumbprint FROM accounts").fetchall()

        # --- Pass 1: canonicalize in memory. No writes. ---
        # Keyed by the thumbprint the row will hold once this migration is done,
        # which is the canonical one for a readable JWK and the stored one for a
        # row we cannot parse. Both have to take part in the collision check, or
        # the UNIQUE index could still fail after we declared the DB clean.
        planned: dict[str, list[str]] = {}
        updates: list[tuple[str, str, str]] = []
        unreadable: list[str] = []
        for account_id, jwk_json, stored_thumbprint in rows:
            try:
                jwk = json.loads(jwk_json)
                canonical_jwk = canonicalize_jwk(jwk)
                thumbprint = jwk_thumbprint(canonical_jwk)
            except Exception:  # noqa: BLE001 - an unparseable row is inert, not a twin
                # It cannot authenticate either way: `authenticate_account`
                # rebuilds the key from this same JSON and the strict decoder
                # rejects it. So it is not a deactivation-bypass risk and does
                # not justify refusing startup on its own — but it is still
                # loud, and it still has to be counted below.
                unreadable.append(account_id)
                planned.setdefault(str(stored_thumbprint), []).append(account_id)
                continue
            planned.setdefault(thumbprint, []).append(account_id)
            # Compare the parsed JWKs, not the serialized text: rewriting a row
            # whose members are already canonical just because `json.dumps`
            # ordered the keys differently would churn every account on every
            # start. `_dump_json` is what `create_account` writes with, so a
            # rescued row is byte-identical to a freshly registered one.
            if canonical_jwk != jwk or thumbprint != stored_thumbprint:
                updates.append((_dump_json(canonical_jwk), thumbprint, account_id))

        # --- Collision policy, before any mutation. ---
        collisions = {tp: ids for tp, ids in planned.items() if len(ids) > 1}
        if collisions:
            detail = "; ".join(
                f"accounts {', '.join(sorted(ids))} share one account key"
                for ids in collisions.values()
            )
            raise StoreMigrationError(
                f"{len(collisions)} duplicate account key(s) found: {detail}. "
                "These rows hold the SAME key under different JWK encodings, so "
                "deactivating one would NOT disable the other — the bypass this "
                "migration exists to close. Nothing has been modified. Reconcile "
                "them offline (keep one account, delete or deactivate the rest, "
                "and disable the EAB kid if the key is suspect), then restart."
            )

        for account_id in unreadable:
            log.error(
                "Account %s has a stored JWK that cannot be parsed; it is left "
                "as-is and CANNOT authenticate. Inspect or remove the row.",
                account_id,
            )

        # --- Pass 2: apply. Every thumbprint below is known unique. ---
        if updates:
            conn.executemany(
                "UPDATE accounts SET jwk_json = ?, jwk_thumbprint = ? WHERE id = ?",
                updates,
            )
            log.warning(
                "Re-encoded %d stored account JWK(s) into canonical form; the "
                "keys are unchanged.",
                len(updates),
            )

        # Post-migration invariant, in the same migration that established it.
        # Cheap, runs on every start, and it is the check that would catch a
        # future insert path forgetting to canonicalize.
        duplicate_count = conn.execute(
            "SELECT COUNT(*) FROM (SELECT jwk_thumbprint FROM accounts "
            "WHERE jwk_thumbprint IS NOT NULL "
            "GROUP BY jwk_thumbprint HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        if duplicate_count:
            raise StoreMigrationError(
                f"{duplicate_count} account thumbprint(s) are still duplicated "
                "after canonicalization. One account key would map to several "
                "accounts, so account deactivation is not enforceable. Refusing "
                "to serve."
            )

    def _migrate_certificates_unique_order_index(
        self, conn: sqlite3.Connection
    ) -> None:
        """LOW-4: add a UNIQUE index on certificates(order_id).

        A DB-level last line of defense against two cert rows for the same
        order — the CAS on ``acquire_processing_lease`` plus the
        existing-cert check already prevent this in normal operation. The
        index is created inside the schema migration (not in ``_SCHEMA``) so
        that an upgrade of an already-deployed DB that somehow accumulated a
        duplicate ``order_id`` row (pre-CAS legacy data, manual repair) does
        NOT crash Store init: a unique-index CREATE validates existing rows on
        creation, so we catch that, log an operator-actionable warning, and
        leave the RA running on its primary (CAS) defense rather than failing
        to start. The operator reconciles the duplicates and the next start
        installs the index.
        """
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_order "
                "ON certificates(order_id)"
            )
        except sqlite3.IntegrityError:
            import logging
            logging.getLogger(__name__).error(
                "Cannot create the certificates(order_id) UNIQUE index: the "
                "existing database contains duplicate order_id rows. The RA "
                "will run on its CAS-based duplicate-prevention (still safe), "
                "but the DB-level guarantee is NOT installed. Reconcile the "
                "duplicate rows and restart to install the index."
            )

    def _migrate_accounts_unique_thumbprint_index(
        self, conn: sqlite3.Connection
    ) -> None:
        """UNIQUE index on accounts(jwk_thumbprint) — one account per key.

        ``newAccount`` reads by thumbprint and returns the existing account
        (RFC 8555 §7.3 idempotence), then inserts if it found none. Those are
        two separate transactions, so two concurrent newAccount requests for
        the same key both read "absent" and both insert. The result is two
        active accounts for one key, each with its own order history and its
        own rate-limit accounting — and a kid eviction or deactivation applied
        to "the" account leaves the twin usable.

        Same defensive pattern as the certificates(order_id) index: created in
        the migration rather than ``_SCHEMA`` so an already-deployed DB that
        accumulated duplicates does not fail to start. The RA keeps running on
        the read-then-insert path; the operator reconciles and restarts.
        """
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_thumbprint_unique "
                "ON accounts(jwk_thumbprint) WHERE jwk_thumbprint IS NOT NULL"
            )
        except sqlite3.IntegrityError:
            import logging
            logging.getLogger(__name__).error(
                "Cannot create the accounts(jwk_thumbprint) UNIQUE index: the "
                "existing database holds more than one account for the same "
                "account key. The RA will run without the DB-level guarantee. "
                "Reconcile the duplicate accounts and restart to install it."
            )

    def _migrate_accounts_table(self, conn: sqlite3.Connection) -> None:
        """Add the jwk_thumbprint column to accounts if missing (dedup support)."""
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()
        }
        if "jwk_thumbprint" not in columns:
            conn.execute("ALTER TABLE accounts ADD COLUMN jwk_thumbprint TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint "
                "ON accounts (jwk_thumbprint)"
            )

    def _migrate_certificates_table(self, conn: sqlite3.Connection) -> None:
        """Add revocation columns to certificates if they are missing."""
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(certificates)"
            ).fetchall()
        }
        for column, ddl in (
            ("serial_number", "TEXT"),
            ("status", "TEXT NOT NULL DEFAULT 'valid'"),
            ("revocation_reason", "TEXT"),
            ("revoked_at", "TEXT"),
            ("ca_crl_updated", "INTEGER NOT NULL DEFAULT 0"),
            ("not_before", "TEXT"),
            ("not_after", "TEXT"),
        ):
            if column not in columns:
                conn.execute(f"ALTER TABLE certificates ADD COLUMN {column} {ddl}")
        self._backfill_certificate_serials(conn)
        self._backfill_certificate_validity(conn)

    def _backfill_certificate_serials(self, conn: sqlite3.Connection) -> None:
        """Derive ``serial_number`` for rows that predate the column.

        ``ALTER TABLE ... ADD COLUMN serial_number TEXT`` gives every existing
        row NULL, and nothing else ever filled it in. That is not a cosmetic
        gap: ``serial_number`` is the **only** key ``revokeCert`` resolves a
        certificate by (:meth:`get_certificate_by_serial`), and SQL equality
        against NULL never matches. So on any deployment upgraded across the
        column's introduction, every pre-migration certificate answered
        revocation with 404 — its owner could not revoke it through the RA at
        all, and a compromised key stayed trusted until expiry or until an
        operator went to the CA by hand. The pending-revocation feed skips
        NULL-serial rows too (``routes/admin.py``), so the gap was silent.

        The serial is not lost, only underived: it is in the row's own
        ``cert_pem``. Backfilling is a pure re-derivation of data already held,
        which is why it can run unattended at startup.

        **Strict, not best-effort.** A row whose PEM will not parse, or two
        rows for one account that derive the same serial, leave the store in
        exactly the ambiguous state the lookup cannot resolve safely — so the
        migration raises and the RA refuses to start rather than come up with a
        subset of certificates quietly unrevokable. This differs deliberately
        from the two UNIQUE-index migrations above, which degrade to a warning:
        those lose a *secondary* defence while the primary (CAS) still holds,
        whereas an underived serial has no fallback path at all. The whole
        migration runs in the caller's transaction, so a raise rolls back.
        """
        rows = conn.execute(
            "SELECT id, account_id, cert_pem FROM certificates "
            "WHERE serial_number IS NULL OR serial_number = ''"
        ).fetchall()
        if not rows:
            return

        derived: list[tuple[str, str, str]] = []
        unparseable: list[str] = []
        for row in rows:
            try:
                serial = _serial_from_pem(row["cert_pem"])
            except (ValueError, TypeError, AttributeError):
                unparseable.append(str(row["id"]))
                continue
            derived.append((serial, str(row["id"]), str(row["account_id"])))

        if unparseable:
            raise StoreMigrationError(
                "cannot derive serial numbers for legacy certificate rows "
                f"{sorted(unparseable)}: their cert_pem does not parse as a "
                "certificate. Those certificates would be unrevokable through "
                "ACME, so the RA refuses to start. Inspect them with "
                "\"SELECT id, cert_pem FROM certificates WHERE id IN (...)\" "
                "and either repair the PEM or delete the corrupt rows."
            )

        # A serial must resolve to at most one row per account, because that
        # pair is the revocation lookup key. Check against both the rows this
        # backfill is about to write and the rows already carrying a serial.
        seen: dict[tuple[str, str], str] = {}
        conflicts: list[str] = []
        for serial, cert_id, account_id in derived:
            key = (serial, account_id)
            twin = seen.get(key)
            if twin is not None:
                conflicts.append(
                    f"rows {twin} and {cert_id} both derive serial {serial} "
                    f"for account {account_id}"
                )
                continue
            seen[key] = cert_id
            clash = conn.execute(
                "SELECT id FROM certificates "
                "WHERE serial_number = ? AND account_id = ? AND id != ?",
                (serial, account_id, cert_id),
            ).fetchone()
            if clash is not None:
                conflicts.append(
                    f"row {cert_id} derives serial {serial}, already held by "
                    f"row {clash['id']} for account {account_id}"
                )
        if conflicts:
            raise StoreMigrationError(
                "legacy certificate rows derive conflicting serial numbers, so "
                "revocation could not resolve them unambiguously: "
                + "; ".join(sorted(conflicts))
                + ". The RA refuses to start; reconcile the duplicate rows."
            )

        conn.executemany(
            "UPDATE certificates SET serial_number = ? WHERE id = ?",
            [(serial, cert_id) for serial, cert_id, _ in derived],
        )

        # Post-migration invariant. Cheap, and it runs on every start: an
        # insert path that ever forgets the serial reproduces the same
        # unrevokable-certificate bug, and this is where it surfaces.
        remaining = conn.execute(
            "SELECT COUNT(*) FROM certificates "
            "WHERE serial_number IS NULL OR serial_number = ''"
        ).fetchone()[0]
        if remaining:
            raise StoreMigrationError(
                f"{remaining} certificate row(s) still have no serial_number "
                "after the backfill; they would be unrevokable through ACME."
            )

    def _backfill_certificate_validity(self, conn: sqlite3.Connection) -> None:
        """Derive ``not_before``/``not_after`` for rows that predate the columns.

        Like the serial backfill this is a pure re-derivation of data the row
        already holds in its own ``cert_pem``, so it runs unattended at startup.

        **Best-effort, unlike the serial backfill, and deliberately so.** An
        underived serial has no fallback — the certificate is simply unrevokable
        — which is why that migration refuses to start. An underived *validity*
        has a safe fallback: the row keeps NULL, and
        :meth:`certificate_validity_summary` reports it as unknown, which makes
        the retention floor unknowable and therefore blocks pruning. Refusing to
        delete is the fail-safe direction, so a historical certificate with a
        corrupt PEM should not take the RA down; it should cost the deployment
        its ability to prune until someone looks. Warn loudly and carry on.
        """
        rows = conn.execute(
            "SELECT id, cert_pem FROM certificates "
            "WHERE not_after IS NULL OR not_after = ''"
        ).fetchall()
        if not rows:
            return

        derived: list[tuple[str, str, str]] = []
        unparseable: list[str] = []
        for row in rows:
            try:
                not_before, not_after = _validity_from_pem(row["cert_pem"])
            except (ValueError, TypeError, AttributeError):
                unparseable.append(str(row["id"]))
                continue
            derived.append((not_before, not_after, str(row["id"])))

        if derived:
            conn.executemany(
                "UPDATE certificates SET not_before = ?, not_after = ? WHERE id = ?",
                derived,
            )
        if unparseable:
            logging.getLogger(__name__).warning(
                "could not derive validity for %d certificate row(s) %s: their "
                "cert_pem does not parse. The audit retention floor cannot be "
                "computed while any certificate's validity is unknown, so the "
                "retention sweep will refuse to run until these are repaired or "
                "removed.",
                len(unparseable),
                sorted(unparseable),
            )

    def _migrate_orders_table(self, conn: sqlite3.Connection) -> None:
        """Add the processing-lease columns to orders if they are missing."""
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(orders)"
            ).fetchall()
        }
        for column, ddl in (
            ("processing_started_at", "TEXT"),
            ("processing_generation", "INTEGER NOT NULL DEFAULT 0"),
            ("pending_ca_request_id", "TEXT"),
        ):
            if column not in columns:
                conn.execute(f"ALTER TABLE orders ADD COLUMN {column} {ddl}")

    def _migrate_authorizations_table(self, conn: sqlite3.Connection) -> None:
        """Drop the dead challenges JSON column from authorizations if present.

        WI-005: the column was written but never read — challenges are sourced
        from the challenges table via JOIN in get_authorization. SQLite 3.35.0+
        supports ALTER TABLE DROP COLUMN; older versions leave it as harmless
        dead weight.
        """
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorizations)"
            ).fetchall()
        }
        if "challenges" in columns:
            try:
                conn.execute("ALTER TABLE authorizations DROP COLUMN challenges")
            except sqlite3.OperationalError:
                pass

    def _certificate_from_row(self, row: sqlite3.Row) -> CertificateRecord:
        reason_raw = row["revocation_reason"]
        revocation_reason = int(reason_raw) if reason_raw is not None else None
        return CertificateRecord(
            id=row["id"],
            order_id=row["order_id"],
            account_id=row["account_id"],
            cert_pem=row["cert_pem"],
            chain_pem=_load_json(row["chain_pem"]),
            template=row["template"],
            requester=row["requester"],
            issued_at=row["issued_at"],
            metadata=_load_json(row["metadata"]),
            serial_number=row["serial_number"],
            status=row["status"],
            revocation_reason=revocation_reason,
            revoked_at=row["revoked_at"],
            ca_crl_updated=bool(row["ca_crl_updated"]),
        )

    def _account_from_row(self, row: sqlite3.Row) -> AccountRecord:
        return AccountRecord(
            id=row["id"],
            status=row["status"],
            jwk_json=row["jwk_json"],
            eab_kid=row["eab_kid"],
            created_at=row["created_at"],
            contact=_load_json(row["contact"]) or [],
        )

    def _order_from_row(self, row: sqlite3.Row) -> OrderRecord:
        return OrderRecord(
            id=row["id"],
            account_id=row["account_id"],
            status=row["status"],
            identifiers=_load_json(row["identifiers"]),
            authorizations=_load_json(row["authorizations"]),
            finalize_url=row["finalize_url"],
            certificate_url=row["certificate_url"],
            expires=row["expires"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            processing_started_at=row["processing_started_at"],
            processing_generation=row["processing_generation"],
            pending_ca_request_id=row["pending_ca_request_id"],
        )

    def record_pending_ca_request(
        self, order_id: str, req_id: str, *, expected_generation: int
    ) -> bool:
        """Durably record that the CA accepted a request it has not decided.

        Written before the finalize path returns, so an accepted ADCS request
        is never left knowable only from a log line (2026-08-18 F4). The
        generation is checked so a worker whose lease has already been reclaimed
        cannot stamp its stale ReqID onto an order now owned by a different
        enrollment.

        Returns True when the row was updated.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET pending_ca_request_id = ?, updated_at = ? "
                "WHERE id = ? AND processing_generation = ?",
                (req_id, _now_iso(), order_id, expected_generation),
            )
            return cursor.rowcount == 1

    def clear_pending_ca_request(self, order_id: str, req_id: str) -> bool:
        """Drop the pending marker once *req_id* has been accounted for.

        Keyed on the ReqID as well as the order: clearing "whatever is pending"
        would let a stale operator assertion discharge a request that had been
        replaced since, which is the same fail-open shape the marker exists to
        prevent.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET pending_ca_request_id = NULL, updated_at = ? "
                "WHERE id = ? AND pending_ca_request_id = ?",
                (_now_iso(), order_id, req_id),
            )
            return cursor.rowcount == 1


    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def _insert_account(
        self,
        conn: sqlite3.Connection,
        *,
        jwk: dict[str, Any],
        eab_kid: str,
        status: str,
        contact: Sequence[str] | None,
    ) -> AccountRecord:
        """INSERT the account row on *conn* (the caller owns the transaction).

        Shared by ``create_account`` and ``create_account_with_audit`` so the
        row shape can never drift between the two.
        """
        account_id = uuid.uuid4().hex
        created_at = _now_iso()
        contact_list = list(contact or [])
        thumbprint = jwk_thumbprint(jwk)
        conn.execute(
            """
            INSERT INTO accounts
                (id, status, jwk_json, eab_kid, contact, created_at, jwk_thumbprint)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                status,
                _dump_json(jwk),
                eab_kid,
                _dump_json(contact_list),
                created_at,
                thumbprint,
            ),
        )
        return AccountRecord(
            id=account_id,
            status=status,
            jwk_json=_dump_json(jwk),
            eab_kid=eab_kid,
            created_at=created_at,
            contact=contact_list,
        )

    def create_account(
        self,
        *,
        jwk: dict[str, Any],
        eab_kid: str,
        status: str = "valid",
        contact: Sequence[str] | None = None,
    ) -> AccountRecord:
        with self._connect() as conn:
            return self._insert_account(
                conn,
                jwk=jwk,
                eab_kid=eab_kid,
                status=status,
                contact=contact,
            )

    def create_account_with_audit(
        self,
        *,
        jwk: dict[str, Any],
        eab_kid: str,
        status: str = "valid",
        contact: Sequence[str] | None = None,
        audit: Mapping[str, Any],
        max_accounts_per_eab_kid: int = 1,
    ) -> tuple[AccountRecord, dict[str, Any]]:
        """``create_account`` plus its provenance audit row in ONE transaction.

        Daybreak 2026-08-15 review: the route used to commit the account and
        only then write the ``account-created`` row, so a crash or SQLite error
        in the window left a live account with no provenance — an account the
        operator could not tie to the EAB kid that minted it. Same shape as
        ``record_issuance`` (v1.9): state change and audit row commit together
        or not at all. ``account_id`` is always taken from the inserted row;
        passing one in *audit* is rejected rather than silently overridden.

        Returns ``(record, audit_event)``; the caller fans the event out to
        SIEM via ``emit_audit_hook`` (the row is already durable).

        ``max_accounts_per_eab_kid`` is a lifetime quota: every account row
        for the kid counts, regardless of status. The quota check, account
        insert, and audit insert share the same ``BEGIN IMMEDIATE`` transaction;
        an exhausted quota raises :class:`EabAccountLimitExceeded` without
        creating either row.
        """
        if max_accounts_per_eab_kid < 1:
            raise ValueError("max_accounts_per_eab_kid must be at least 1")
        kwargs = dict(audit)
        if "account_id" in kwargs:
            raise ValueError("audit must not carry account_id; it is set from the row")
        with self._connect() as conn:
            # The count and insert must be serialized with other account
            # creations. A route-level count is only advisory: two concurrent
            # requests could both observe the same count and both insert.
            conn.execute("BEGIN IMMEDIATE")
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM accounts WHERE eab_kid = ?", (eab_kid,)
                ).fetchone()[0]
            )
            if count >= max_accounts_per_eab_kid:
                raise EabAccountLimitExceeded(
                    kid=eab_kid,
                    limit=max_accounts_per_eab_kid,
                    count=count,
                )
            record = self._insert_account(
                conn,
                jwk=jwk,
                eab_kid=eab_kid,
                status=status,
                contact=contact,
            )
            event = self._record_audit_in_conn(
                conn, account_id=record.id, **kwargs
            )
        return record, event

    def get_account(self, account_id: str) -> AccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
        if row is None:
            return None
        return self._account_from_row(row)

    def get_account_by_jwk(self, jwk: dict[str, Any]) -> AccountRecord | None:
        """Return the account whose key matches this JWK (RFC 7638 thumbprint).

        Used to make newAccount idempotent (RFC 8555 §7.3): the same account key
        returns the existing account rather than creating a duplicate.
        """
        thumbprint = jwk_thumbprint(jwk)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE jwk_thumbprint = ?", (thumbprint,)
            ).fetchone()
        if row is None:
            return None
        return self._account_from_row(row)

    def update_account_status(self, account_id: str, status: str) -> bool:
        """Set an account's status (RFC 8555 §7.3.6 deactivation).

        CAS-guarded on the account still being ``valid`` so a repeat
        deactivation is an idempotent no-op rather than a second state change,
        and so it can never resurrect an already-deactivated account. Returns
        True if this call applied the transition.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE accounts SET status = ? WHERE id = ? AND status = ?",
                (status, account_id, AccountStatus.VALID),
            )
            return cursor.rowcount == 1

    def update_account_key(
        self, account_id: str, new_jwk: dict[str, Any]
    ) -> None:
        """Replace an account's public key (RFC 8555 §7.3.5 keyChange).

        Updates both ``jwk_json`` and the ``jwk_thumbprint`` index so
        subsequent JWS verifications use the new key and the old key is
        no longer accepted. The thumbprint is recomputed from ``new_jwk``
        so the caller cannot desync the index from the stored JWK.
        """
        thumbprint = jwk_thumbprint(new_jwk)
        with self._connect() as conn:
            self._update_account_key_in_conn(conn, account_id, new_jwk, thumbprint)

    def update_account_key_with_audit(
        self,
        account_id: str,
        new_jwk: dict[str, Any],
        *,
        expected_old_thumbprint: str,
        audit: Mapping[str, Any],
        rate_limit_window_seconds: int | None = None,
        rate_limit_per_kid: int = 0,
    ) -> dict[str, Any]:
        """``update_account_key`` plus its audit row in ONE transaction.

        Daybreak 2026-08-15 review: the route committed the key rotation and
        wrote the ``account-key-changed`` row afterwards, so a failure in the
        window could leave an account whose key had silently rotated with no
        audit trail of the rotation — the one row that names the new key's
        thumbprint. Same fix shape as ``record_issuance`` and
        ``create_account_with_audit``: commit together or not at all.

        When ``rate_limit_per_kid`` is positive, rollovers already recorded for
        this account's EAB kid inside the window are counted and the rotation is
        refused with :class:`KeyChangeRateLimitExceeded` at the ceiling —
        14a / daybreak 2026-08-17 F1. The count, the key update and the audit
        insert share one ``BEGIN IMMEDIATE`` transaction for the reason
        ``create_order_with_authz`` documents: a count-then-check split lets a
        parallel burst all observe the same below-limit count and all proceed,
        and here each winner is a key rotation that cannot be undone. The
        successful ``account-key-changed`` rows ARE the counter — the denial
        coalescer excludes successes, and the retention floor (validity + 14
        days) is far longer than any sane window, so the evidence a rotation
        happened is still on disk when the next one asks.

        Returns the audit event for the caller's ``emit_audit_hook``.
        """
        kwargs = dict(audit)
        if "account_id" in kwargs:
            raise ValueError("audit must not carry account_id; it is set from the row")
        thumbprint = jwk_thumbprint(new_jwk)
        with self._connect() as conn:
            # Serialize the current-key/status check, rate-limit decision,
            # rotation and success audit. A request authenticated before a
            # concurrent rollover or deactivation must not remain authorized
            # after that transition commits.
            conn.execute("BEGIN IMMEDIATE")
            account_row = conn.execute(
                "SELECT eab_kid, jwk_thumbprint, status FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if (
                account_row is None
                or str(account_row["jwk_thumbprint"]) != expected_old_thumbprint
                or str(account_row["status"]) != AccountStatus.VALID
            ):
                raise AccountKeyStale("account key or status changed before rollover")

            if rate_limit_per_kid > 0:
                if rate_limit_window_seconds is None or rate_limit_window_seconds < 1:
                    raise ValueError(
                        "rate_limit_window_seconds must be positive when a limit is enabled"
                    )
                eab_kid = str(account_row["eab_kid"])
                cutoff = (
                    datetime.now(UTC)
                    - timedelta(seconds=rate_limit_window_seconds)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                # Joined on the account rather than read out of the audit row's
                # details JSON: the kid on the ACCOUNT is the authoritative one,
                # and it is what the order limiter keys on too.
                row = conn.execute(
                    "SELECT COUNT(*) FROM audit_log al "
                    "JOIN accounts a ON al.account_id = a.id "
                    "WHERE a.eab_kid = ? AND al.event_type = 'account-key-changed' "
                    "AND al.outcome = 'success' AND al.timestamp >= ?",
                    (eab_kid, cutoff),
                ).fetchone()
                count = int(row[0])
                if count >= rate_limit_per_kid:
                    raise KeyChangeRateLimitExceeded(
                        kid=eab_kid,
                        limit=rate_limit_per_kid,
                        count=count,
                        window_seconds=rate_limit_window_seconds,
                    )
            cursor = conn.execute(
                "UPDATE accounts SET jwk_json = ?, jwk_thumbprint = ? "
                "WHERE id = ? AND jwk_thumbprint = ? AND status = ?",
                (
                    _dump_json(new_jwk),
                    thumbprint,
                    account_id,
                    expected_old_thumbprint,
                    AccountStatus.VALID,
                ),
            )
            if cursor.rowcount != 1:
                # Defensive even under BEGIN IMMEDIATE: keep the authorization
                # predicate attached to the write that consumes it.
                raise AccountKeyStale("account key or status changed before rollover")
            return self._record_audit_in_conn(conn, account_id=account_id, **kwargs)

    def _update_account_key_in_conn(
        self,
        conn: sqlite3.Connection,
        account_id: str,
        new_jwk: dict[str, Any],
        thumbprint: str,
    ) -> None:
        conn.execute(
            "UPDATE accounts SET jwk_json = ?, jwk_thumbprint = ? WHERE id = ?",
            (_dump_json(new_jwk), thumbprint, account_id),
        )

    # ------------------------------------------------------------------
    # Nonces
    # ------------------------------------------------------------------

    def create_nonce(self) -> str:
        nonce = uuid.uuid4().hex + uuid.uuid4().hex
        now = datetime.now(UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                (nonce, now_str),
            )
            # Probabilistic GC safety net: clean expired nonces on ~1% of
            # creations so the table doesn't grow unbounded if the admin
            # cron is missed (threat-model §4.G). The admin endpoint remains
            # the primary cleanup path; this is a belt-and-suspenders fallback.
            # Bounded by LIMIT to avoid holding the writer lock too long.
            if uuid.uuid4().int % NONCE_GC_PROBABILITY == 0:
                cutoff = (now - timedelta(seconds=NONCE_TTL_SECONDS)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                conn.execute(
                    "DELETE FROM nonces WHERE rowid IN "
                    "(SELECT rowid FROM nonces WHERE created_at < ? LIMIT 5000)",
                    (cutoff,),
                )
        return nonce

    def consume_nonce(self, nonce: str) -> bool:
        """Return True if the nonce existed, was within TTL, and was removed.

        TTL is enforced *at consume time*, not just by the cleanup sweep: an
        unused nonce older than NONCE_TTL_SECONDS is rejected even if the
        probabilistic GC and the admin cron have both missed it. An expired
        nonce is left in the table for the sweep (a retry of the same nonce
        fails identically — badNonce either way, no oracle).

        **Invalid nonces are rejected by a read, never a write.** A nonce
        arrives on an unauthenticated POST, before signature/account/EAB
        checks, so an unauthenticated peer chooses it. Issuing the DELETE
        unconditionally took SQLite's single writer lock even for a nonce that
        could not possibly match, letting a flood of garbage nonces contend
        with the issuance path (measured: a bogus nonce blocked for the full
        5s busy_timeout and then raised "database is locked", surfacing as a
        500 rather than a 400 badNonce). The SELECT below runs in WAL read
        mode alongside a live writer, so the overwhelming majority of hostile
        traffic never reaches the write lock at all.

        The DELETE's ``rowcount`` remains the authority for single-use: two
        concurrent consumers of the *same valid* nonce both pass the SELECT,
        but only one DELETE reports a row, so replay protection is unchanged.
        """
        # Defence in depth: the protocol layer rejects non-string nonces with a
        # badNonce problem document, but a non-string reaching sqlite3 binding
        # raises ProgrammingError, so never let one through to a query.
        if not isinstance(nonce, str):
            return False
        cutoff = (datetime.now(UTC) - timedelta(seconds=NONCE_TTL_SECONDS)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self._connect() as conn:
            present = conn.execute(
                "SELECT 1 FROM nonces WHERE nonce = ? AND created_at >= ?",
                (nonce, cutoff),
            ).fetchone()
            if present is None:
                return False
            cursor = conn.execute(
                "DELETE FROM nonces WHERE nonce = ? AND created_at >= ?",
                (nonce, cutoff),
            )
            return cursor.rowcount == 1

    def cleanup_expired_nonces(self) -> int:
        """Delete all nonces older than NONCE_TTL_SECONDS. Returns count deleted."""
        cutoff = (datetime.now(UTC) - timedelta(seconds=NONCE_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
            return cursor.rowcount

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------

    def get_order(self, order_id: str) -> OrderRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        if row is None:
            return None
        return self._order_from_row(row)

    def acquire_processing_lease(self, order_id: str) -> int | None:
        """Atomically transition 'ready'→'processing' and mint a lease generation.

        M3: prevents double-issuance on concurrent or retried finalize calls.
        Returns the new ``processing_generation`` (always ``>= 1``) if the CAS
        succeeded, or ``None`` if the order was not in 'ready' state (already
        processing/valid or other).

        The returned generation is the caller's *durable* claim on this order.
        It is the sole way into ``processing``, so every entry mints a fresh
        one, and any earlier holder is invalidated the moment a new one is
        minted. A worker must re-check it with ``holds_processing_lease``
        immediately before any issue-capable CA call: winning the CAS is not
        enough, because the worker may sit queued behind the threadpool for
        long enough that an operator reclaim (``processing``→``ready``) and a
        second finalize both complete before it runs. Without the re-check,
        both the stale worker and the new one submit the same order to ADCS.

        The UPDATE and the read-back share one connection (and therefore one
        implicit transaction), so the generation returned is the one this call
        wrote, not a later writer's.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ?, "
                "processing_started_at = ?, "
                "processing_generation = processing_generation + 1 "
                "WHERE id = ? AND status = ?",
                (OrderStatus.PROCESSING, updated_at, updated_at, order_id,
                 OrderStatus.READY),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT processing_generation FROM orders WHERE id = ?",
                (order_id,),
            ).fetchone()
        # The UPDATE matched, so the row exists.
        return int(row["processing_generation"])

    def holds_processing_lease(self, order_id: str, generation: int) -> bool:
        """True iff ``order_id`` is still ``processing`` under ``generation``.

        The revalidation half of ``acquire_processing_lease``. False means the
        caller's claim has lapsed — the order left ``processing`` (reclaimed,
        completed, invalidated) and/or a newer finalize minted a later
        generation. A caller that gets False must not perform the work it was
        admitted for; it no longer owns the order.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status, processing_generation FROM orders WHERE id = ?",
                (order_id,),
            ).fetchone()
        if row is None:
            return False
        return (
            row["status"] == OrderStatus.PROCESSING
            and int(row["processing_generation"]) == generation
        )

    def transition_pending_to_ready(self, order_id: str) -> bool:
        """Atomically transition an order from 'pending' to 'ready'.

        M-2: CAS-guarded on ``status = 'pending'`` so a concurrent finalize
        that has already moved the order to ``processing`` (or any other state)
        cannot be clobbered back to ``ready`` by a late/racing challenge
        validation. Clears ``processing_started_at`` (it should already be
        NULL for a pending order, but the clear is explicit for safety).
        Returns True if the transition was applied, False if the order was no
        longer ``pending`` (the caller simply returns — the order has moved on).
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, processing_started_at = NULL, "
                "updated_at = ? WHERE id = ? AND status = ?",
                (OrderStatus.READY, updated_at, order_id, OrderStatus.PENDING),
            )
            return cursor.rowcount == 1

    def transition_processing_to_ready(
        self, order_id: str, *, expected_generation: int | None = None
    ) -> bool:
        """Atomically transition an order from 'processing' back to 'ready'.

        Operator-initiated reconciliation of an order wedged in 'processing'
        (e.g. after a crash mid-enrollment where no certificate was recorded).
        CAS-guarded on ``status = 'processing'`` so it can never clobber a live
        enrollment or a concurrent transition. Clears ``processing_started_at``.
        Returns True if the transition was applied.

        Leaving ``processing`` ends the current enrollment lease: any worker
        still holding the generation this order was in ``processing`` under
        will now fail ``holds_processing_lease`` and abandon rather than
        submit to the CA. ``processing_generation`` itself is deliberately NOT
        reset — it must never go backwards, or a later finalize could re-mint a
        generation a queued worker is still holding.

        **Safety:** the caller (an operator via the admin endpoint) MUST first
        confirm from the ADCS CA database that no certificate was issued for
        this order's request — otherwise re-finalizing would double-issue.

        ``expected_generation`` narrows the CAS to one specific lease. Callers
        that read the order and then decide (the admin reclaim endpoint) pass
        the generation they read, so a lease that changed between the read and
        this write loses the CAS instead of silently overwriting the decision
        the read was based on.
        """
        updated_at = _now_iso()
        sql, params = _processing_cas(
            "UPDATE orders SET status = ?, processing_started_at = NULL, "
            "updated_at = ? WHERE id = ? AND status = ?",
            (OrderStatus.READY, updated_at, order_id, OrderStatus.PROCESSING),
            expected_generation,
        )
        with self._connect() as conn:
            return conn.execute(sql, params).rowcount == 1

    def reclaim_processing_order(
        self,
        order_id: str,
        *,
        to_valid_certificate_url: str | None = None,
        expected_generation: int | None = None,
        pending_req_id: str | None = None,
        audit_event_type: str,
        audit_account_id: str | None = None,
        audit_outcome: str,
        audit_details: dict[str, Any],
    ) -> tuple[bool, dict[str, Any] | None]:
        """Reclaim a wedged order: transition, marker clear and audit, atomically.

        2026-08-19 F5 (low, CWE-362). The admin reclaim route used to call
        ``transition_processing_to_ready``/``_to_valid``, then
        ``clear_pending_ca_request``, then ``record_audit`` — three separate
        commits. An interruption between them left the order reopened with the
        CA-request marker still set (so the next operator sees a pending ReqID
        that has already been discharged), or reopened with **no
        ``admin-order-reclaimed`` event at all** — an administrative state
        change to an issuance-path order with nothing in the audit trail saying
        who did it or why. This is the same shape, and the same fix, as the
        revocation-confirm path above.

        One ``BEGIN IMMEDIATE`` covers all three, so either the order stays
        wedged and the operator retries, or it is reclaimed *and* the marker is
        cleared *and* the action is audited. SIEM fan-out stays outside, as it
        does everywhere else: best-effort, and must not hold the write open.

        ``to_valid_certificate_url`` selects the destination: supplied means the
        certificate exists and the order becomes ``valid``; omitted means it
        becomes ``ready`` for re-enrollment. The CAS is scoped to
        ``expected_generation`` exactly as the individual transitions were.

        Returns ``(won_cas, event)``; ``event`` is None when the CAS was lost,
        which is the caller's "audit a denial and return current state" path.
        """
        updated_at = _now_iso()
        if to_valid_certificate_url is not None:
            sql, params = _processing_cas(
                "UPDATE orders SET status = ?, certificate_url = ?, "
                "processing_started_at = NULL, updated_at = ? "
                "WHERE id = ? AND status = ?",
                (OrderStatus.VALID, to_valid_certificate_url, updated_at,
                 order_id, OrderStatus.PROCESSING),
                expected_generation,
            )
        else:
            sql, params = _processing_cas(
                "UPDATE orders SET status = ?, processing_started_at = NULL, "
                "updated_at = ? WHERE id = ? AND status = ?",
                (OrderStatus.READY, updated_at, order_id, OrderStatus.PROCESSING),
                expected_generation,
            )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute(sql, params).rowcount != 1:
                return False, None
            if pending_req_id:
                # Still keyed on the ReqID: a marker replaced since the
                # operator's assertion must survive, exactly as before.
                conn.execute(
                    "UPDATE orders SET pending_ca_request_id = NULL, updated_at = ? "
                    "WHERE id = ? AND pending_ca_request_id = ?",
                    (updated_at, order_id, pending_req_id),
                )
            event = self._record_audit_in_conn(
                conn,
                event_type=audit_event_type,
                account_id=audit_account_id,
                order_id=order_id,
                outcome=audit_outcome,
                details=audit_details,
            )
            return True, event

    def transition_processing_to_valid(
        self,
        order_id: str,
        certificate_url: str,
        *,
        expected_generation: int | None = None,
    ) -> bool:
        """Atomically transition an order from 'processing' to 'valid'.

        Reconciliation for the case where enrollment succeeded and a certificate
        row was recorded, but the order's status flip was missed (e.g. a crash
        between ``create_certificate`` and this transition). CAS-guarded
        on ``status = 'processing'``, and on ``processing_generation`` when
        ``expected_generation`` is supplied. Returns True if the transition was
        applied.
        """
        updated_at = _now_iso()
        sql, params = _processing_cas(
            "UPDATE orders SET status = ?, certificate_url = ?, "
            "processing_started_at = NULL, updated_at = ? "
            "WHERE id = ? AND status = ?",
            (OrderStatus.VALID, certificate_url, updated_at, order_id,
             OrderStatus.PROCESSING),
            expected_generation,
        )
        with self._connect() as conn:
            return conn.execute(sql, params).rowcount == 1

    def transition_active_to_invalid(self, order_id: str) -> bool:
        """Atomically transition a still-active order to 'invalid'.

        CAS-guarded on ``status IN ('pending', 'ready')`` so it can never clobber
        an order a concurrent finalize has already moved to ``processing`` or
        ``valid`` (the double-issuance guard). Used by finalize's expiry check
        (RFC 8555 §7.1.6) so a stale snapshot cannot flip a now-processing order
        to ``invalid`` out from under a live enrollment. Returns True if applied.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status IN (?, ?)",
                (OrderStatus.INVALID, updated_at, order_id,
                 OrderStatus.PENDING, OrderStatus.READY),
            )
            return cursor.rowcount == 1

    def processing_age_seconds(self, order_id: str) -> float | None:
        """Seconds since the order entered ``processing``, or None if unknown.

        None means the order has no ``processing_started_at`` — either it is
        not processing, or it is a legacy row written before that column
        existed. Callers must treat None as "cannot tell" rather than as zero.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT processing_started_at FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        if row is None or not row["processing_started_at"]:
            return None
        started = datetime.strptime(
            row["processing_started_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        return (datetime.now(UTC) - started).total_seconds()

    def transition_processing_to_invalid(
        self, order_id: str, *, expected_generation: int | None = None
    ) -> bool:
        """Terminate an order whose enrollment is definitively over.

        Deliberately separate from ``transition_active_to_invalid``, which
        excludes ``processing`` so a stale snapshot can never flip an order out
        from under a live enrollment. This one is the opposite case and needs
        the opposite CAS: the caller *knows* the enrollment finished — the CA
        issued and the RA could not complete — so leaving the order in
        ``processing`` would have a client poll forever against a request the
        CA has already satisfied, and would leave it eligible for the admin
        reclaim path.

        Returns True if applied. ``expected_generation`` narrows the CAS to the
        caller's own lease, so a worker whose lease already lapsed cannot
        terminate an order a later finalize now owns.
        """
        updated_at = _now_iso()
        sql, params = _processing_cas(
            "UPDATE orders SET status = ?, updated_at = ? "
            "WHERE id = ? AND status = ?",
            (OrderStatus.INVALID, updated_at, order_id, OrderStatus.PROCESSING),
            expected_generation,
        )
        with self._connect() as conn:
            return conn.execute(sql, params).rowcount == 1

    def transition_to_revoked(self, order_id: str) -> bool:
        """Atomically transition an order to 'revoked' (CAS-guarded).

        WI-003: replaces the former non-CAS order-status UPDATE in
        ``revoke_cert``. CAS-guarded on ``status IN ('valid', 'processing')``
        so it can never clobber an order a concurrent finalize has moved to
        ``invalid`` or that is still ``pending``/``ready`` (no cert to revoke).
        The ``valid``→``revoked`` path is the normal case; ``processing``→``revoked``
        handles the crash-window where the cert was recorded but the status flip
        was missed (same window as ``transition_processing_to_valid``). Returns
        True if the transition was applied.
        """
        updated_at = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status IN (?, ?)",
                (OrderStatus.REVOKED, updated_at, order_id,
                 OrderStatus.VALID, OrderStatus.PROCESSING),
            )
            return cursor.rowcount == 1

    def list_orders_by_status(
        self, status: str, *, limit: int = 100
    ) -> list[OrderRecord]:
        """Return orders with the given status, newest first.

        Used by the admin monitoring endpoint to list orders stuck in
        ``processing`` (threat-model §4.D: monitor time-in-``processing`` p99).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE status = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return [self._order_from_row(row) for row in rows]

    def list_orders_by_account(
        self, account_id: str, *, limit: int = 500
    ) -> list[OrderRecord]:
        """Return an account's orders, newest first (RFC 8555 §7.1.2.1)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE account_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (account_id, limit),
            ).fetchall()
        return [self._order_from_row(row) for row in rows]

    def count_recent_orders_by_kid(
        self,
        eab_kid: str,
        window_seconds: int,
        *,
        now: datetime | None = None,
    ) -> int:
        """Count orders created within the rolling window for a given EAB kid.

        WI-016: the rate-limit check counts orders across all ACME accounts
        that share the same EAB kid, so a leaked credential cannot evade the
        limit by creating multiple account keys. The window is computed from
        ``created_at`` timestamps in the store. Pass ``now`` for deterministic
        testing; production callers omit it (uses wall-clock UTC).
        """
        current = now or datetime.now(UTC)
        cutoff = (current - timedelta(seconds=window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM orders o "
                "JOIN accounts a ON o.account_id = a.id "
                "WHERE a.eab_kid = ? AND o.created_at >= ?",
                (eab_kid, cutoff),
            ).fetchone()
        return int(row[0])

    def count_all_recent_orders(
        self,
        window_seconds: int,
        *,
        now: datetime | None = None,
    ) -> int:
        """Count all orders created within the rolling window (global backstop).

        WI-016: a global ceiling that bounds total order creation across all
        accounts, independent of the per-kid limit.
        """
        current = now or datetime.now(UTC)
        cutoff = (current - timedelta(seconds=window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM orders WHERE created_at >= ?",
                (cutoff,),
            ).fetchone()
        return int(row[0])

    def sweep_expired_orders(self) -> int:
        """Transition every still-active expired order to 'invalid'.

        RFC 8555 §7.1.6: the server SHOULD move an expired order (and its
        authorizations) to ``invalid``. This sweep transitions the **order**
        rows; the order's authorization/challenge rows are left as-is (a
        follow-up — the invalid order can no longer be finalized, so the stale
        authz are unreachable, not a security gap). Only ``pending``/``ready``
        orders are swept — ``processing``/``valid``/``invalid``/``revoked`` are
        terminal or operator-reconcilable and are left alone. Returns the count
        transitioned.

        Intended to be driven by an external cron via the admin endpoint (the
        same operator pattern as ``cleanup_expired_nonces``); expiry is also
        enforced lazily at finalize so issuance can never proceed past expiry
        even between sweeps.
        """
        now = datetime.now(UTC)
        now_str = _now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, expires FROM orders WHERE status IN (?, ?)",
                (OrderStatus.PENDING, OrderStatus.READY),
            ).fetchall()
            expired_ids = [
                row["id"] for row in rows
                if is_expired(row["expires"], now=now)
            ]
            if not expired_ids:
                return 0
            # Batch to stay under SQLite's default 999 host-parameter limit.
            total = 0
            for i in range(0, len(expired_ids), 900):
                batch = expired_ids[i:i + 900]
                placeholders = ",".join("?" for _ in batch)
                cursor = conn.execute(
                    f"UPDATE orders SET status = ?, updated_at = ? "
                    f"WHERE id IN ({placeholders}) AND status IN (?, ?)",
                    (OrderStatus.INVALID, now_str, *batch,
                     OrderStatus.PENDING, OrderStatus.READY),
                )
                total += cursor.rowcount
            return total

    def create_order_with_authz(
        self,
        *,
        account_id: str,
        identifiers: Sequence[dict[str, str]],
        challenge_url_fn: Callable[[str], str],
        authz_url_fn: Callable[[str], str],
        finalize_url_fn: Callable[[str], str],
        rate_limit_window_seconds: int | None = None,
        rate_limit_per_kid: int = 0,
        rate_limit_global: int = 0,
    ) -> OrderRecord:
        """Create an order with authorizations and challenge URLs atomically.

        H5: replaces the former non-transactional sequence of create_order →
        create_authorization → update_challenge_url → raw SQL update.  The
        ``*_fn`` callbacks produce the URLs from IDs (the store does not know
        about the server's URL scheme).
        """
        order_id = uuid.uuid4().hex
        created_at = _now_iso()
        expires = _now_iso_plus(self._order_expiry_seconds)
        authz_urls: list[str] = []

        with self._connect() as conn:
            if rate_limit_per_kid > 0 or rate_limit_global > 0:
                if rate_limit_window_seconds is None or rate_limit_window_seconds < 1:
                    raise ValueError(
                        "rate_limit_window_seconds must be positive when a limit is enabled"
                    )
                # Serialize the count-and-insert decision with every other
                # rate-limited writer.  A separate SELECT followed by INSERT
                # lets a parallel burst have every request observe the same
                # below-limit count and all proceed.
                conn.execute("BEGIN IMMEDIATE")
                cutoff = (
                    datetime.now(UTC)
                    - timedelta(seconds=rate_limit_window_seconds)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                account_row = conn.execute(
                    "SELECT eab_kid FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
                if account_row is None:
                    raise ValueError("account does not exist")
                eab_kid = str(account_row["eab_kid"])

                if rate_limit_per_kid > 0:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM orders o "
                        "JOIN accounts a ON o.account_id = a.id "
                        "WHERE a.eab_kid = ? AND o.created_at >= ?",
                        (eab_kid, cutoff),
                    ).fetchone()
                    count = int(row[0])
                    if count >= rate_limit_per_kid:
                        raise OrderRateLimitExceeded(
                            scope="per-account",
                            limit=rate_limit_per_kid,
                            count=count,
                            window_seconds=rate_limit_window_seconds,
                            eab_kid=eab_kid,
                        )

                if rate_limit_global > 0:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM orders WHERE created_at >= ?",
                        (cutoff,),
                    ).fetchone()
                    count = int(row[0])
                    if count >= rate_limit_global:
                        raise OrderRateLimitExceeded(
                            scope="global",
                            limit=rate_limit_global,
                            count=count,
                            window_seconds=rate_limit_window_seconds,
                        )

            # Create the order row with placeholder authorizations — will be
            # updated in the same transaction below.
            conn.execute(
                """
                INSERT INTO orders
                (id, account_id, status, identifiers, authorizations, finalize_url,
                 certificate_url, expires, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order_id,
                    account_id,
                    OrderStatus.PENDING,
                    _dump_json(list(identifiers)),
                    _dump_json([]),  # placeholder
                    finalize_url_fn(order_id),
                    None,
                    expires,
                    created_at,
                    created_at,
                ),
            )

            for identifier in identifiers:
                authz_id = uuid.uuid4().hex
                challenge_id = uuid.uuid4().hex
                token = uuid.uuid4().hex + uuid.uuid4().hex
                challenge_url = challenge_url_fn(challenge_id)

                # Insert challenge first (FK dependency).
                conn.execute(
                    """
                    INSERT INTO challenges
                    (id, authz_id, type, status, token, url, validated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (challenge_id, authz_id, "http-01", "pending", token, challenge_url, None),
                )

                # Insert authorization — challenges are in the challenges table (SSoT).
                conn.execute(
                    """
                    INSERT INTO authorizations
                    (id, account_id, order_id, identifier, status, expires)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        authz_id,
                        account_id,
                        order_id,
                        _dump_json(identifier),
                        "pending",
                        expires,
                    ),
                )

                authz_urls.append(authz_url_fn(authz_id))

            # Update the order row with the real authz URLs.
            conn.execute(
                "UPDATE orders SET authorizations = ? WHERE id = ?",
                (_dump_json(authz_urls), order_id),
            )

        return OrderRecord(
            id=order_id,
            account_id=account_id,
            status=OrderStatus.PENDING,
            identifiers=list(identifiers),
            authorizations=authz_urls,
            finalize_url=finalize_url_fn(order_id),
            certificate_url=None,
            expires=expires,
            created_at=created_at,
            updated_at=created_at,
        )

    # ------------------------------------------------------------------
    # Authorizations + Challenges
    # ------------------------------------------------------------------

    def get_authorization(self, authz_id: str) -> AuthorizationRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM authorizations WHERE id = ?", (authz_id,)
            ).fetchone()
            if row is None:
                return None
            # H4: challenges table is the single source of truth — derive the
            # challenge list by JOINing rather than reading the JSON blob.
            challenge_rows = conn.execute(
                "SELECT * FROM challenges WHERE authz_id = ?", (authz_id,)
            ).fetchall()
            challenges = [
                ChallengeRecord(
                    id=cr["id"],
                    authz_id=cr["authz_id"],
                    type=cr["type"],
                    status=cr["status"],
                    token=cr["token"],
                    url=cr["url"],
                    validated_at=cr["validated_at"],
                )
                for cr in challenge_rows
            ]
        return AuthorizationRecord(
            id=row["id"],
            account_id=row["account_id"],
            order_id=row["order_id"],
            identifier=_load_json(row["identifier"]),
            status=row["status"],
            expires=row["expires"],
            challenges=challenges,
        )

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
        if row is None:
            return None
        return ChallengeRecord(
            id=row["id"],
            authz_id=row["authz_id"],
            type=row["type"],
            status=row["status"],
            token=row["token"],
            url=row["url"],
            validated_at=row["validated_at"],
        )

    def update_authorization_status(
        self,
        authz_id: str,
        status: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE authorizations SET status = ? WHERE id = ?",
                (status, authz_id),
            )

    def update_challenge_status(
        self,
        challenge_id: str,
        status: str,
        *,
        validated_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE challenges
                SET status = ?, validated_at = ?
                WHERE id = ?
                """,
                (status, validated_at, challenge_id),
            )

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def get_certificate_by_order(self, order_id: str) -> CertificateRecord | None:
        """Return the *honoured* certificate for an order, if one exists.

        M3: used by the finalize path to detect double-issuance — if a
        certificate already exists for this order, do not re-enroll.

        Quarantined rows are deliberately excluded. Every caller of this method
        treats a hit as "issuance already succeeded, close the loop and serve
        it" — the finalize double-issuance guard, ``_finalize_existing_cert``,
        and the admin reclaim path all flip the order to ``valid`` with this
        certificate's URL. A quarantined certificate is one the RA has decided
        it must **not** honour, so returning it here would hand a client the
        certificate a post-issuance verifier just rejected.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE order_id = ? AND status != ?",
                (order_id, CertStatus.QUARANTINED),
            ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def create_certificate(
        self,
        *,
        order_id: str,
        account_id: str,
        cert_pem: str,
        chain_pem: Sequence[str],
        template: str,
        requester: str,
        metadata: dict[str, str] | None = None,
    ) -> CertificateRecord:
        cert_id = uuid.uuid4().hex
        issued_at = _now_iso()
        serial_number = _serial_from_pem(cert_pem)
        not_before, not_after = _validity_from_pem(cert_pem)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO certificates
                (id, order_id, account_id, cert_pem, chain_pem, template,
                 requester, issued_at, metadata, serial_number, status,
                 revocation_reason, revoked_at, not_before, not_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert_id,
                    order_id,
                    account_id,
                    cert_pem,
                    _dump_json(list(chain_pem)),
                    template,
                    requester,
                    issued_at,
                    _dump_json(metadata or {}),
                    serial_number,
                    CertStatus.VALID,
                    None,
                    None,
                    not_before,
                    not_after,
                ),
            )
        return CertificateRecord(
            id=cert_id,
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=list(chain_pem),
            template=template,
            requester=requester,
            issued_at=issued_at,
            metadata=metadata or {},
            serial_number=serial_number,
        )

    def record_issuance(
        self,
        *,
        order_id: str,
        account_id: str,
        cert_pem: str,
        chain_pem: Sequence[str],
        template: str,
        requester: str,
        metadata: dict[str, str] | None,
        certificate_url_fn: Callable[[str], str],
        sans: Sequence[str],
        csr_subject: str,
        expected_generation: int | None = None,
    ) -> tuple[CertificateRecord, bool, dict[str, Any]]:
        """Persist an issuance — certificate row, order transition, audit row —
        in ONE transaction.

        Auditing every issuance is a hard rule of this project, but the three
        writes used to be three independent commits: ``create_certificate``,
        then the CAS to ``valid``, then ``record_audit``. A crash or a SQLite
        error in the window between them committed a stored, serveable
        certificate with **no** ``certificate-issued`` audit row — proven by
        fault injection, which left one certificate row and zero issuance
        events. That is precisely the silent issuance the audit rule exists to
        make impossible.

        Returns ``(record, applied, event)`` where *applied* is whether this
        caller won the processing→valid CAS. The audit event reflects the
        outcome that actually committed: ``certificate-issued`` when the CAS
        applied, ``finalize-enrollment-race`` when it did not.

        ``expected_generation`` additionally requires that the order still
        carries the caller's enrollment lease. Losing on generation means the
        order was reclaimed and re-finalized while this issuance was in flight:
        the certificate row is still written (an issued certificate is never
        left untracked), but the order belongs to the newer lease and this
        caller must not flip it to ``valid``.
        """
        existing = self.get_certificate_by_order(order_id)
        cert_id = existing.id if existing is not None else uuid.uuid4().hex
        issued_at = existing.issued_at if existing is not None else _now_iso()
        serial_number = _serial_from_pem(cert_pem)
        not_before, not_after = _validity_from_pem(cert_pem)
        certificate_url = certificate_url_fn(cert_id)

        with self._connect() as conn:
            # One transaction for the certificate row, the order transition,
            # and the audit row. BEGIN IMMEDIATE takes the write lock up front
            # so the CAS cannot interleave with a concurrent finalize.
            conn.execute("BEGIN IMMEDIATE")
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO certificates
                    (id, order_id, account_id, cert_pem, chain_pem, template,
                     requester, issued_at, metadata, serial_number, status,
                     revocation_reason, revoked_at, not_before, not_after)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cert_id,
                        order_id,
                        account_id,
                        cert_pem,
                        _dump_json(list(chain_pem)),
                        template,
                        requester,
                        issued_at,
                        _dump_json(metadata or {}),
                        serial_number,
                        CertStatus.VALID,
                        None,
                        None,
                        not_before,
                        not_after,
                    ),
                )
            cas_sql, cas_params = _processing_cas(
                "UPDATE orders SET status = ?, certificate_url = ? "
                "WHERE id = ? AND status = ?",
                (
                    OrderStatus.VALID,
                    certificate_url,
                    order_id,
                    OrderStatus.PROCESSING,
                ),
                expected_generation,
            )
            applied = conn.execute(cas_sql, cas_params).rowcount == 1

            if applied:
                event = self._record_audit_in_conn(
                    conn,
                    event_type="certificate-issued",
                    account_id=account_id,
                    order_id=order_id,
                    sans=sans,
                    template=template,
                    requester=requester,
                    outcome="success",
                    details={
                        "certificate_id": cert_id,
                        "serial": serial_number,
                        "csr_subject": csr_subject,
                    },
                )
            else:
                winner = conn.execute(
                    "SELECT certificate_url FROM orders WHERE id = ?", (order_id,)
                ).fetchone()
                winner_cert_id = (
                    winner["certificate_url"].rsplit("/", 1)[-1]
                    if winner is not None and winner["certificate_url"]
                    else None
                )
                event = self._record_audit_in_conn(
                    conn,
                    event_type="finalize-enrollment-race",
                    account_id=account_id,
                    order_id=order_id,
                    sans=sans,
                    template=template,
                    requester=requester,
                    outcome="failed",
                    details={
                        "certificate_id": cert_id,
                        "serial": serial_number,
                        "winner_certificate_id": winner_cert_id,
                        "reason": "lost-processing-cas",
                    },
                )

        record = CertificateRecord(
            id=cert_id,
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=list(chain_pem),
            template=template,
            requester=requester,
            issued_at=issued_at,
            metadata=metadata or {},
            serial_number=serial_number,
            status=CertStatus.VALID,
        )
        return record, applied, event

    def quarantine_certificate(
        self,
        *,
        order_id: str,
        account_id: str,
        cert_pem: str,
        chain_pem: Sequence[str],
        template: str,
        requester: str,
        metadata: dict[str, str] | None,
        event_type: str,
        violations: list[str],
        reason: str,
        sans: Sequence[str],
        extra_details: dict[str, Any] | None = None,
    ) -> tuple[CertificateRecord, dict[str, Any]]:
        """Record a CA-issued certificate that a post-issuance verifier rejected.

        By the time the SAN / EKU / CA-capability verifiers run, **ADCS has
        already issued the certificate**: it has a serial, it is in the CA
        database, and it is valid to every relying party in the domain. The RA
        used to respond 500 and record nothing — no certificate row, and an
        audit event that did not even carry the serial. The dangerous
        certificate the RA had just decided it must not honour was therefore
        invisible to the RA's own revocation workflow, and an operator had only
        a timestamp with which to go hunting in the CA database.

        This records it instead, in one transaction:

        * a certificate row with status ``quarantined`` — carrying the serial,
          the ReqID (in metadata), the bytes, and the violations, so it is
          identifiable; never served, because ``_certificate_response`` serves
          only ``valid``, and never returned by ``get_certificate_by_order``,
          so a retried finalize cannot pick it up;
        * ``ca_crl_updated = 0`` and a ``revoked_at`` stamp, so it appears in
          ``list_revoked_certificates`` and the existing CA-side pull agent
          revokes it through the normal loop rather than a bespoke path;
        * the order flipped to ``invalid`` (terminal — the client must create a
          new order; it must not be able to retry into a serve path);
        * the audit row, carrying the serial and the violations.
        """
        cert_id = uuid.uuid4().hex
        issued_at = _now_iso()
        serial_number = _serial_from_pem(cert_pem)
        not_before, not_after = _validity_from_pem(cert_pem)
        req_id = (metadata or {}).get("req_id", "")

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO certificates
                (id, order_id, account_id, cert_pem, chain_pem, template,
                 requester, issued_at, metadata, serial_number, status,
                 revocation_reason, revoked_at, ca_crl_updated,
                 not_before, not_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    cert_id,
                    order_id,
                    account_id,
                    cert_pem,
                    _dump_json(list(chain_pem)),
                    template,
                    requester,
                    issued_at,
                    _dump_json(metadata or {}),
                    serial_number,
                    CertStatus.QUARANTINED,
                    # Reason 0 (unspecified) is the RFC 5280 code the CA-side
                    # certutil call will use; the real cause is the violation
                    # list on the audit row and in metadata.
                    0,
                    issued_at,
                    not_before,
                    not_after,
                ),
            )
            # Terminal: the client must not be able to retry this order into a
            # path that serves the quarantined certificate.
            conn.execute(
                "UPDATE orders SET status = ? WHERE id = ? AND status IN (?, ?)",
                (
                    OrderStatus.INVALID,
                    order_id,
                    OrderStatus.PROCESSING,
                    OrderStatus.READY,
                ),
            )
            event = self._record_audit_in_conn(
                conn,
                event_type=event_type,
                account_id=account_id,
                order_id=order_id,
                sans=sans,
                template=template,
                requester=requester,
                outcome="failed",
                details={
                    "certificate_id": cert_id,
                    "serial": serial_number,
                    "req_id": req_id,
                    "violations": violations,
                    "reason": reason,
                    "quarantined": True,
                    "pending_ca_revocation": True,
                    # Verifier-specific context (which SANs, which EKUs) must be
                    # part of the row that is written, not decorated onto the
                    # returned dict afterwards — the persisted audit trail is
                    # the artefact an investigator reads.
                    **(extra_details or {}),
                },
            )

        record = CertificateRecord(
            id=cert_id,
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=list(chain_pem),
            template=template,
            requester=requester,
            issued_at=issued_at,
            metadata=metadata or {},
            serial_number=serial_number,
            status=CertStatus.QUARANTINED,
            revocation_reason=0,
            revoked_at=issued_at,
        )
        return record, event

    def get_certificate(self, cert_id: str) -> CertificateRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def get_certificate_by_serial(
        self,
        serial_hex: str,
        account_id: str | None = None,
    ) -> CertificateRecord | None:
        """Look up a certificate by its uppercase hex serial number.

        When *account_id* is provided the lookup is scoped to
        ``(serial_number, account_id)`` so that a serial collision
        (possible in test with a static fixture cert) cannot return
        another account's row.  When *account_id* is ``None`` the
        legacy serial-only behaviour is preserved for callers that
        do not have an account context.
        """
        lookup = canonical_serial(serial_hex)
        with self._connect() as conn:
            if account_id is not None:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_number = ? AND account_id = ?",
                    (lookup, account_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_number = ?",
                    (lookup,),
                ).fetchone()
        if row is None:
            return None
        return self._certificate_from_row(row)

    def record_revocation(
        self,
        *,
        cert_id: str,
        order_id: str,
        account_id: str,
        reason: int | None,
        revoked_at: str | None,
        sans: Sequence[str],
        audit_details: dict[str, Any],
    ) -> tuple[RevocationUpdate, dict[str, Any] | None]:
        """Revoke a certificate, flip its order, and audit — in ONE transaction.

        The same rule that forced ``record_issuance`` to be atomic applies here:
        revocation is a security state change with a mandatory audit row, and
        the three writes were three independent commits (the certificate CAS,
        the order transition, then ``record_audit``). A fault between them left
        a certificate revoked in the store — served as 410, queued for CA-side
        revocation — with no ``certificate-revoked`` event anywhere. The local
        audit table is the authoritative trail, so a gap in it is not
        recoverable from the SIEM copy.

        Returns ``(update, event)``. *event* is None when this caller lost the
        CAS, in which case the winning revocation already wrote the audit row
        and this caller must not write a second one.
        """
        timestamp = revoked_at or _now_iso()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE certificates "
                "SET status = ?, revocation_reason = ?, revoked_at = ? "
                "WHERE id = ? AND status = ?",
                (CertStatus.REVOKED, reason, timestamp, cert_id, CertStatus.VALID),
            )
            won = cursor.rowcount == 1
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
            if row is None:
                return RevocationUpdate(record=None, won_cas=False), None
            if not won:
                return (
                    RevocationUpdate(
                        record=self._certificate_from_row(row), won_cas=False
                    ),
                    None,
                )

            # Same transaction: the order must not be left inconsistent with a
            # revoked certificate, and the audit row must not be able to go
            # missing.
            conn.execute(
                "UPDATE orders SET status = ?, updated_at = ? "
                "WHERE id = ? AND status IN (?, ?)",
                (
                    OrderStatus.REVOKED,
                    _now_iso(),
                    order_id,
                    OrderStatus.VALID,
                    OrderStatus.PROCESSING,
                ),
            )
            event = self._record_audit_in_conn(
                conn,
                event_type="certificate-revoked",
                account_id=account_id,
                order_id=order_id,
                sans=sans,
                outcome="success",
                details=audit_details,
            )
            return (
                RevocationUpdate(
                    record=self._certificate_from_row(row), won_cas=True
                ),
                event,
            )

    def revoke_certificate(
        self,
        cert_id: str,
        reason: int | None,
        *,
        revoked_at: str | None = None,
    ) -> RevocationUpdate:
        """Mark a certificate as revoked in the RA store (CAS-guarded).

        M-3: the UPDATE is guarded on ``status = 'valid'`` so concurrent
        revocations are idempotent — the first revocation wins and its
        reason/timestamp are preserved; a concurrent caller sees the existing
        (now-revoked) record returned unchanged with ``won_cas=False``. If the
        cert was already revoked, no row is updated and the existing revoked
        record is returned with ``won_cas=False`` (idempotent success).

        Returns a ``RevocationUpdate`` whose ``record`` is None only when no
        certificate row exists for *cert_id*; ``won_cas`` is True exactly when
        this caller's UPDATE flipped the row (so the caller owns the audit).
        This lets the route decide whether to audit on a deterministic signal
        rather than inferring a lost CAS from timestamp inequality (which has
        a sub-second race).
        """
        timestamp = revoked_at or _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE certificates "
                "SET status = ?, "
                "    revocation_reason = ?, "
                "    revoked_at = ? "
                "WHERE id = ? AND status = ?",
                (CertStatus.REVOKED, reason, timestamp, cert_id, CertStatus.VALID),
            )
            if cursor.rowcount == 1:
                # This caller won the CAS — the cert was 'valid', now 'revoked'.
                row = conn.execute(
                    "SELECT * FROM certificates WHERE id = ?", (cert_id,)
                ).fetchone()
                if row is None:
                    # The row vanished between the UPDATE and the SELECT (a
                    # concurrent delete — certs are never deleted in normal
                    # operation, so this is near-impossible). Report won_cas=False:
                    # the caller did not end up owning a persisted revocation, so
                    # it must not audit, and the route surfaces this as 404.
                    return RevocationUpdate(record=None, won_cas=False)
                return RevocationUpdate(
                    record=self._certificate_from_row(row), won_cas=True
                )
            # No row updated: either the cert doesn't exist, or it was already
            # revoked (a concurrent revocation won the CAS). Return the current
            # record so the caller can distinguish the two cases (None = not
            # found; a revoked record = idempotent success, won_cas=False).
        return RevocationUpdate(record=self.get_certificate(cert_id), won_cas=False)

    def list_revoked_certificates(self, *, limit: int = 500) -> list[CertificateRecord]:
        """Certificates awaiting a CA-side revocation.

        Includes ``quarantined`` rows as well as ``revoked`` ones. A quarantined
        certificate was issued by the CA and then rejected by a post-issuance
        verifier — it is live at the CA and must come off through exactly the
        same pull-agent loop as a client-requested revocation, rather than
        needing a second mechanism.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM certificates WHERE status IN (?, ?) "
                "AND ca_crl_updated = 0 ORDER BY revoked_at DESC LIMIT ?",
                (CertStatus.REVOKED, CertStatus.QUARANTINED, limit),
            ).fetchall()
        return [self._certificate_from_row(row) for row in rows]

    def list_certificate_chains(
        self, *, limit: int = 1000
    ) -> list[tuple[str, list[str]]]:
        """Stored chains, newest first, as issuer material for recovery.

        UNFILED item 25. A transport orphan has an empty ``chain_pem`` and can
        therefore never be CRL-confirmed; the material that repairs it is
        already here, because every successful issuance stored the chain the CA
        returned over the same authenticated enrollment leg.

        Rows with no chain are excluded — they are the population being
        repaired, not a source for it — and the read is bounded, because this
        runs on the confirmation path. ``[]`` is what an empty chain is
        serialized as; ``''`` is defended against because a hand-repaired or
        pre-migration row can hold it and ``json.loads('')`` raises.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, chain_pem FROM certificates "
                "WHERE chain_pem IS NOT NULL AND chain_pem NOT IN ('[]', '') "
                "ORDER BY issued_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        chains: list[tuple[str, list[str]]] = []
        for row in rows:
            try:
                parsed = _load_json(row["chain_pem"])
            except json.JSONDecodeError:
                # One unreadable row must not deny the whole search; the next
                # row may carry the same CA's certificate.
                logging.getLogger(__name__).warning(
                    "certificate %s has an unparseable chain_pem; skipping it "
                    "as issuer material",
                    row["id"],
                )
                continue
            if isinstance(parsed, list) and parsed:
                chains.append((row["id"], [str(entry) for entry in parsed]))
        return chains

    def attach_recovered_chain_with_audit(
        self,
        cert_id: str,
        *,
        chain_pem: Sequence[str],
        event_type: str,
        outcome: str,
        account_id: str | None = None,
        order_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> tuple[CertificateRecord | None, dict[str, Any] | None]:
        """Fill in an EMPTY ``chain_pem``, with its audit event, atomically.

        UNFILED item 25. Two properties are load-bearing:

        * **It only ever fills an empty chain.** The UPDATE is compare-and-set
          against ``'[]'``/``''``, so a chain the CA actually returned can never
          be overwritten by recovered material, and two concurrent
          confirmations for the same certificate cannot both write.
        * **The chain and its provenance commit together.** A recovered chain
          that cannot be traced back to what supplied it is not better than no
          chain — it looks exactly like material the CA returned. Splitting the
          two transactions would allow precisely that row to exist, which is
          the same failure ``confirm_ca_revocation_with_audit`` was rewritten to
          close.

        Returns ``(record, event)``, or ``(None, None)`` when the row was not
        updated: unknown id, or a chain that was already present — both of which
        mean this caller has nothing to audit.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE certificates SET chain_pem = ? "
                "WHERE id = ? AND chain_pem IN ('[]', '')",
                (_dump_json(list(chain_pem)), cert_id),
            )
            if cursor.rowcount != 1:
                return None, None
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
            if row is None:  # pragma: no cover - the UPDATE just matched it
                return None, None
            event = self._record_audit_in_conn(
                conn,
                event_type=event_type,
                account_id=account_id,
                order_id=order_id,
                outcome=outcome,
                details=details,
            )
            return self._certificate_from_row(row), event

    def confirm_ca_revocation(self, serial_hex: str) -> bool:
        """Flip ca_crl_updated=1 for a revoked cert (WI-024 confirm callback).

        Returns True if a row was updated, False if no matching revoked cert
        was found (already confirmed, not revoked, or unknown serial).

        Prefer :meth:`confirm_ca_revocation_with_audit` on the confirmation
        route: committing this flag without its audit event in the same
        transaction can lose the event permanently (see that method).
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE certificates SET ca_crl_updated = 1 "
                "WHERE serial_number = ? AND status IN (?, ?) AND ca_crl_updated = 0",
                (
                    canonical_serial(serial_hex),
                    CertStatus.REVOKED,
                    CertStatus.QUARANTINED,
                ),
            )
            return cursor.rowcount == 1

    # ------------------------------------------------------------------
    # CRL monotonicity watermark (UNFILED item 23)
    # ------------------------------------------------------------------

    def read_crl_watermark(self, issuer_key: str) -> CrlWatermark | None:
        """The newest CRL already acted on for *issuer_key*, or None.

        None means first observation for this CA, which is trust-on-first-use
        and protects nothing — the caller is expected to say so rather than
        imply a check happened.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT issuer_key, crl_number, this_update FROM crl_watermark "
                "WHERE issuer_key = ?",
                (issuer_key,),
            ).fetchone()
        if row is None:
            return None
        return CrlWatermark(
            issuer_key=row["issuer_key"],
            crl_number=row["crl_number"],
            this_update=row["this_update"],
        )

    def reset_crl_watermark(self, issuer_key: str) -> bool:
        """Drop the watermark for one CA. Returns True if a row was removed.

        Deliberately an **explicit operator action** with no automatic caller.
        The state that needs it is a CA restored from backup, whose CRL Number
        sequence legitimately restarts below what this RA has already seen; the
        control then refuses every CRL until someone intervenes. Wiring that
        recovery to fire by itself — "the number went backwards, so clear the
        watermark" — would hand exactly the sequence an attacker wants to the
        attacker, and the control would defeat itself the first time it worked.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "DELETE FROM crl_watermark WHERE issuer_key = ?", (issuer_key,)
            )
            return cursor.rowcount > 0

    @staticmethod
    def _advance_crl_watermark_in_conn(
        conn: sqlite3.Connection,
        *,
        issuer_key: str,
        crl_number: str | None,
        this_update: str,
        source_url: str | None,
    ) -> bool:
        """Move the watermark forward, never backward. Returns True if it moved.

        The compare-and-set lives **inside the caller's transaction** rather
        than being a read followed by a write, because the confirmation route
        reads the watermark before it fetches the CRL and writes it after: a
        concurrent confirmation can advance the row in between, and a plain
        UPDATE would then walk the watermark backwards to this request's older
        document — turning the control off precisely under the concurrency an
        attacker can generate.

        Comparison prefers the CRL Number and falls back to ``this_update``,
        matching ``compare_to_watermark``; the two must not disagree, so the
        precedence is stated once in each and tested against the other.
        """
        existing = conn.execute(
            "SELECT crl_number, this_update FROM crl_watermark WHERE issuer_key = ?",
            (issuer_key,),
        ).fetchone()
        if existing is not None:
            advances = False
            if crl_number is not None and existing["crl_number"] is not None:
                try:
                    advances = int(crl_number) > int(existing["crl_number"])
                except ValueError:
                    advances = this_update > existing["this_update"]
            else:
                advances = this_update > existing["this_update"]
            if not advances:
                return False
        conn.execute(
            "INSERT INTO crl_watermark "
            "(issuer_key, crl_number, this_update, observed_at, source_url) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(issuer_key) DO UPDATE SET "
            "crl_number = excluded.crl_number, "
            "this_update = excluded.this_update, "
            "observed_at = excluded.observed_at, "
            "source_url = excluded.source_url",
            (issuer_key, crl_number, this_update, _now_iso(), source_url),
        )
        return True

    def confirm_ca_revocation_with_audit(
        self,
        serial_hex: str,
        *,
        event_type: str,
        outcome: str,
        account_id: str | None = None,
        order_id: str | None = None,
        sans: Sequence[str] | None = None,
        details: dict[str, Any] | None = None,
        watermark_advance: CrlWatermark | None = None,
        watermark_source_url: str | None = None,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Flip ``ca_crl_updated`` and record its audit event atomically.

        The two used to be separate transactions on separate connections
        (2026-08-18 wave 3 F6). The flag committed first, and it is what
        *removes* the serial from ``list_revoked_certificates`` — so a crash or
        an audit-insert failure in the window between them left the certificate
        gone from the retry feed with no ``revocation-ca-confirmed`` event ever
        recorded. Worse, the route's idempotence check returns early on
        ``ca_crl_updated``, so a retry could not repair it either: the evidence
        that the CA-side revocation was confirmed was permanently absent, which
        is the one thing this route exists to record.

        One ``BEGIN IMMEDIATE`` covers both, so either the serial stays pending
        and can be retried, or it is confirmed *and* audited. SIEM fan-out stays
        outside — it is best-effort by design and must not hold the write open.

        ``watermark_advance`` carries the CRL this confirmation acted on, and
        it moves the monotonic watermark forward in **this same transaction**
        (UNFILED item 23). Same reasoning as the audit event: the watermark is
        part of the record of the decision, and a watermark advanced in its own
        transaction could survive a confirmation that then failed, or be lost
        by a confirmation that succeeded. It advances only for a document that
        is genuinely newer, so losing the race with a concurrent confirmation
        leaves the higher watermark standing.

        Known and deliberate gap: a CRL fetched on a check that does **not**
        end in a confirmation — evidence required but the serial absent, say —
        does not advance the watermark, so a later replay of that document is
        not caught. Advancing on observation instead would be strictly
        stronger; it is not done here because the advance would then no longer
        be atomic with the decision it belongs to. The residue is small: the
        unadvanced document is one the RA declined to act on.

        Returns ``(won_cas, event)``. ``event`` is None when no row was updated,
        which is the idempotent/unknown-serial case and carries nothing to audit.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE certificates SET ca_crl_updated = 1 "
                "WHERE serial_number = ? AND status IN (?, ?) AND ca_crl_updated = 0",
                (
                    canonical_serial(serial_hex),
                    CertStatus.REVOKED,
                    CertStatus.QUARANTINED,
                ),
            )
            if cursor.rowcount != 1:
                return False, None
            if watermark_advance is not None and watermark_advance.this_update:
                self._advance_crl_watermark_in_conn(
                    conn,
                    issuer_key=watermark_advance.issuer_key,
                    crl_number=watermark_advance.crl_number,
                    this_update=watermark_advance.this_update,
                    source_url=watermark_source_url,
                )
            event = self._record_audit_in_conn(
                conn,
                event_type=event_type,
                account_id=account_id,
                order_id=order_id,
                sans=sans,
                outcome=outcome,
                details=details,
            )
            return True, event

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def record_audit(
        self,
        *,
        event_type: str,
        account_id: str | None = None,
        order_id: str | None = None,
        sans: Sequence[str] | None = None,
        template: str | None = None,
        requester: str | None = None,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist an unconditional audit row for every issuance event.

        Returns the audit event dict so callers can feed an extension hook
        (e.g. a SIEM emitter in Phase 3).
        """
        with self._connect() as conn:
            return self._record_audit_in_conn(
                conn,
                event_type=event_type,
                account_id=account_id,
                order_id=order_id,
                sans=sans,
                template=template,
                requester=requester,
                outcome=outcome,
                details=details,
            )

    def _record_audit_in_conn(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        account_id: str | None = None,
        order_id: str | None = None,
        sans: Sequence[str] | None = None,
        template: str | None = None,
        requester: str | None = None,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write an audit row on an existing connection/transaction.

        Callers that must not commit state without its audit (issuance,
        quarantine) use this so both rows land in a single transaction.
        """
        timestamp = _now_iso()
        # Bound the attacker-controlled parts before anything durable is
        # written (second daybreak rescan F4). ``details`` carries the client's
        # EAB kid on the account-creation denial paths, and a peer that
        # passes the network allowlist chooses its length. The bound preserves
        # a readable prefix plus a digest of the whole value, so nothing an
        # investigator needs survives only in the discarded tail.
        event: dict[str, Any] = {
            "event_type": event_type,
            "account_id": account_id,
            "order_id": order_id,
            "sans": list(sans or []),
            "template": template,
            "requester": bound_value(requester),
            "outcome": outcome,
            "details": bound_details(details),
            "timestamp": timestamp,
        }
        cursor = conn.execute(
            """
            INSERT INTO audit_log
            (event_type, account_id, order_id, sans, template, requester,
             outcome, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                account_id,
                order_id,
                _dump_json(event["sans"]),
                template,
                event["requester"],
                outcome,
                _dump_json(event["details"]),
                timestamp,
            ),
        )
        event["id"] = cursor.lastrowid
        return event

    def update_audit_details(self, audit_id: int, details: dict[str, Any]) -> bool:
        """Replace one audit row's details blob. Returns False if it is gone.

        The single mutation this table allows, and it exists for exactly one
        caller: ``DenialCoalescer`` bumping the tally on an open window's row
        (second daybreak rescan F4). Folding repeats into a committed row is
        what makes the count survive a crash — a counter held in memory until
        the window closes would not — and it is why the fix for unbounded
        denial growth deletes nothing.

        Every other column is immutable; there is no method that changes one.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE audit_log SET details = ? WHERE id = ?",
                (_dump_json(bound_details(details)), audit_id),
            )
            return cursor.rowcount > 0

    def certificate_validity_summary(self) -> tuple[int | None, int]:
        """Return ``(max_validity_days, unknown_count)`` over issued certificates.

        The first element is the longest validity this RA has actually issued,
        which is the input to the audit retention floor. It is ``None`` when the
        answer cannot be trusted — no certificates yet, or at least one row whose
        validity could not be derived. ``None`` must be read as "unknown", never
        as "zero": the floor exists to stop retention dropping below the life of
        a certificate that is still valid, so an unknown makes the floor
        unknowable and the sweep must decline rather than guess low.

        Computed from the stored columns rather than by parsing every PEM, which
        is the reason those columns exist.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN not_before IS NULL OR not_before = '' "
                "         OR not_after IS NULL OR not_after = '' "
                "    THEN 1 ELSE 0 END) AS unknown "
                "FROM certificates"
            ).fetchone()
            total = int(row["total"] or 0)
            unknown = int(row["unknown"] or 0)
            if total == 0 or unknown:
                return None, unknown
            # julianday() is days-as-float, so the difference is the validity in
            # days directly. Ceil, so a 7-day-minus-a-second certificate does not
            # round down and shave the floor.
            longest = conn.execute(
                "SELECT MAX(julianday(not_after) - julianday(not_before)) AS d "
                "FROM certificates"
            ).fetchone()["d"]
            if longest is None:
                return None, unknown
            return math.ceil(float(longest)), unknown

    def audit_footprint(self) -> dict[str, Any]:
        """Row count and time span of ``audit_log``, plus the database size.

        The database file covers every table, not just the audit log, so it is
        reported as what it is — total on-disk cost — rather than attributed to
        the audit rows. Both numbers are what an operator needs to answer "is
        this growing in a way I should care about".
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS rows, MIN(timestamp) AS oldest, "
                "MAX(timestamp) AS newest FROM audit_log"
            ).fetchone()
        db_bytes = 0
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self._db_path) + suffix)
            if path.exists():
                db_bytes += path.stat().st_size
        return {
            "rows": int(row["rows"] or 0),
            "oldest": row["oldest"],
            "newest": row["newest"],
            "db_bytes": db_bytes,
        }

    def delete_audit_rows_before(self, cutoff_iso: str) -> int:
        """Delete audit rows strictly older than *cutoff_iso*; return the count.

        Deliberately a dumb primitive with no policy in it. Every decision about
        whether deleting is safe — off-box audit required, off-box audit
        *healthy*, a known retention floor — lives in :mod:`audit_retention`, so
        that this method can never be the thing that decides to destroy
        evidence. Callers that have not made those checks should not be here.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?", (cutoff_iso,)
            )
            return int(cursor.rowcount)

    def list_audit_events(
        self,
        *,
        account_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []
        if account_id is not None:
            query += " AND account_id = ?"
            params.append(account_id)
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "account_id": row["account_id"],
                "order_id": row["order_id"],
                "sans": _load_json(row["sans"]),
                "template": row["template"],
                "requester": row["requester"],
                "outcome": row["outcome"],
                "details": _load_json(row["details"]),
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]
