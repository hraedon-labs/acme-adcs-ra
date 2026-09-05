"""Time-windowed coalescing of account-creation denial audit rows.

Daybreak 2026-08-15 second rescan, F4 (the standing WI-014), part two.

The finding, restated: an allowlisted peer needs no account and no valid EAB
secret to make the RA write a durable audit row. It generates its own account
key, fetches a nonce, sends a ``newAccount`` whose EAB will not verify, and one
SQLite row plus one appended JSONL record land on the issuance host's disk. Per
request. Forever.

Three previous waves declined to fix this, and their reason was right: the
remediation people usually reach for is a *pruner*, and deleting audit evidence
is precisely the operation an attacker wants. Trading a disk-space problem for
a missing-evidence problem is not a fix.

So this is not a pruner. Nothing is ever deleted, and no denial goes
unrecorded. Within a window, repeats of the same *kind* of denial are folded
into the row that is already on disk:

* The first denial of a kind opens a window and writes a normal audit row.
* Every later denial of that kind inside the window **updates that row in
  place** — bumping ``denial_count``, moving ``last_seen``, and adding the
  offered ``kid`` to a bounded set of digests.
* The next denial after the window has elapsed opens a fresh row, which also
  carries the closed window's final tally in ``previous_window``.

Durable growth therefore becomes a function of *time* — at most one row per
(reason x window) — rather than of the attacker's request rate, while the count
of attempts stays exact. Because the counter is updated on a row that is
already committed, even a hard crash cannot lose it.

That bound holds while the number of distinct keys live in a window stays under
``MAX_OPEN_WINDOWS``. **Above it the bound degrades back toward one row per
request**, because round-robin across more keys than the index can hold makes
every lookup a miss. At shipped defaults this is out of reach — it needs >1024
live ``finalize`` keys inside one 60s window against a 50-orders/hour/kid limit
— but an operator who sets ``rate_limit_orders_per_window=0`` (documented as a
supported "rely on the reverse proxy" mode) removes the thing keeping it out of
reach, and a LONGER coalesce window makes it easier rather than harder, because
keys stay resident. ``coalescer_evictions`` on the rows is the signal.

The in-memory index of open windows is separately capped (``MAX_OPEN_WINDOWS``).
Bounding the durable rows says nothing about the dictionary that tracks them,
and the round-5 keys carry an ``order_id``, so distinct keys accrue with orders
in a worker process the installer configures never to recycle.

The coalescing key deliberately excludes the ``kid`` and the requester. Both
are attacker-chosen; keying on them would let a peer defeat the bound by
varying one character per request. The distinct kids seen in a window are
recorded as digests instead, bounded in number and counted in full. For the
replayable *authenticated* classes added in Daybreak round 5, the key carries
the account and order ids (not attacker-chosen per request): one account's
replay storm folds, different accounts stay separable, and the row's own
``account_id``/``order_id`` columns keep the folded tally attributable.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acme_adcs_ra.store import Store, _now_iso

# Which denials are coalesced, and why exactly these.
#
# Account-creation denials (``account-creation-denied``): an allowlisted peer
# needs no account and, for most paths, no valid EAB secret to make the RA write
# a durable audit row. The lifetime EAB account-quota denial is also folded
# here: it has no account id and a valid client can replay it indefinitely.
#
# Replayable authenticated denials (Daybreak round 5): a *valid* credential
# replayed at line rate could grow the durable stores without bound even
# though every request is individually accountable -- accountability does not
# bound disk. These classes are replayable because each one can be re-sent
# indefinitely against unchanged server state, costing the attacker nothing:
#
# * ``account-request-denied`` -- a deactivated or EAB-evicted account key
#   still authenticates the JWS; the denial is the point.
# * ``order-rate-limited`` / ``key-change-rate-limited`` -- requests rejected
#   *because* they exceed a cap are unbounded by definition: the limiter does
#   not throttle the audit row. (14a: the keyChange ceiling would otherwise
#   just move the growth from the success row to the denial row.)
# * ``finalize-csr-mismatch`` / ``finalize-policy-denied`` -- cheap pre-enrollment
#   validation failures on an order that stays ``ready``, so the identical
#   failing finalize can be replayed forever.
# * ``finalize-enrollment-admission-denied`` (2026-08-25) -- the enrollment gate
#   sheds at ``adcs_enrollment_max_pending`` and the route CAS-restores the
#   rejected order to ``ready``, so the identical finalize can be re-sent for as
#   long as capacity stays full. This is the same sentence as
#   ``order-rate-limited`` two bullets up -- a denial issued BECAUSE a cap was
#   hit is unbounded by definition, since the cap throttles the work and not the
#   audit row -- and it was missed when the gate was added. Its ``reason`` is a
#   fixed server literal and an explicit ``reason_code`` pins it, so nothing
#   attacker-chosen reaches the key.
# * ``admin-revocation-confirm-denied`` (2026-08-25) -- the confirm credential
#   can POST a well-formed but nonexistent serial forever; the store lookup
#   misses, nothing transitions, and the row was durable. The probed serial
#   stays in ``details`` for the investigator but NOT in the key (an explicit
#   ``reason_code`` carries the key), so varying it cannot defeat the bound.
#   Note the row then names the WINDOW'S FIRST serial while ``denial_count``
#   stays exact -- the trade the module docstring describes, chosen here
#   because "someone is probing serials" is the signal and the individual
#   values are not.
# * ``admin-order-reclaim-not-found`` / ``admin-order-reclaim-denied`` /
#   ``admin-order-reclaim-noop`` -- the maintenance credential can replay each
#   outcome forever without changing state. Unknown order ids are omitted from
#   the row's structured ``order_id`` and key; the first probed value is kept
#   only as a bounded sample in ``details``.
# * ``admin-revocation-confirm-deferred`` -- capacity shedding changes no
#   revocation state and explicitly asks the caller to retry.
#
# Two SUCCESS types are coalesced, against the general rule below, and the
# reason is worth stating because the rule is otherwise load-bearing:
#
# * ``admin-list-pending-revocations`` (2026-08-25) -- a read-only poll of the
#   revocation work list that transitions nothing. It is safe to fold ONLY
#   because nothing counts these rows. The contrast is ``account-key-changed``,
#   which is excluded precisely because the successful rows ARE the 14a
#   limiter's counter (see ``Store.change_account_key``). Before coalescing any
#   future success, check whether something reads it as a tally.
# * ``admin-list-orders`` -- a read-only monitoring query. Its bounded status
#   and limit remain on the first row as a sample, but not in the key, so
#   varying filters cannot turn a polling credential into durable row growth.
#
#   Coalescing alone does not fix that route: the sync agent polls on a
#   15-minute cadence and the window is 60s, so benign polls never fold. The
#   route therefore ALSO skips the audit row entirely when the pending list is
#   empty, which is the steady state. Coalescing is what bounds the other case
#   -- a token holder polling a non-empty list at line rate.
#
# Everything else -- issuance, revocation, admin state change, one-time
# transitions -- keeps one row per event, unconditionally.
COALESCED_EVENT_TYPES = frozenset(
    {
        "account-creation-denied",
        "account-request-denied",
        "order-rate-limited",
        "key-change-rate-limited",
        "finalize-csr-mismatch",
        "finalize-policy-denied",
        "finalize-enrollment-admission-denied",
        "admin-order-reclaim-not-found",
        "admin-order-reclaim-denied",
        "admin-order-reclaim-noop",
        "admin-list-orders",
        "admin-revocation-confirm-denied",
        "admin-revocation-confirm-deferred",
        "admin-list-pending-revocations",
        # A recovery that finds nothing (UNFILED item 25) is retried by the
        # revocation sync agent on its interval, forever, for as long as the
        # certificate stays blocked — the same benign unbounded growth the
        # denial events above are coalesced for. The window's first row keeps
        # the full finding (candidates considered, chains scanned) and the
        # replay count stays exact. The successful counterpart,
        # `revocation-issuer-evidence-recovered`, is deliberately NOT here: the
        # compare-and-set means it can fire at most once per certificate.
        "revocation-issuer-evidence-recovery",
    }
)

# These authenticated admin operations are deliberately keyed only by their
# event type and stable reason code. Keying on account_id/order_id looked more
# attributable, but it let a stolen admin token cycle through more live order
# keys than MAX_OPEN_WINDOWS, evict each window, and force a fresh durable row
# on every request. The first target remains in the row as a bounded sample and
# the exact replay count remains authoritative; target variation cannot choose
# durable-row cardinality.
_GLOBAL_ADMIN_KEY_EVENT_TYPES = frozenset(
    {
        "admin-order-reclaim-not-found",
        "admin-order-reclaim-denied",
        "admin-order-reclaim-noop",
        "admin-list-orders",
        "admin-revocation-confirm-denied",
        "admin-revocation-confirm-deferred",
        "admin-list-pending-revocations",
    }
)

# Distinct offered kids sampled per window. The full number seen is counted
# regardless; this bounds only how many are named.
MAX_KID_SAMPLES = 10

# How many open windows the in-memory index may hold at once.
#
# Durable growth is bounded by time -- at most one row per (reason x window) --
# but the index that makes that true was not bounded by anything. A key was only
# ever dropped when that same key was seen again after its window lapsed, and
# nothing swept. For account-creation denials the key set is small and fixed
# (event type x server-chosen reason). For the replayable authenticated classes
# added in round 5 the key also carries ``order_id``, so a client that finalizes
# many orders badly mints a new, never-collected key each time -- and the
# installer configures the app pool with ``idleTimeout=00:00:00`` and
# ``periodicRestart.time=00:00:00``, so the worker process never recycles to
# reclaim it.
#
# The cap is enforced only when a NEW window is opened, and expired entries are
# dropped before any live one is: below the cap the behaviour -- including the
# ``previous_window`` hand-off to a reopened key -- is byte-identical to before.
MAX_OPEN_WINDOWS = 1024

# How many DISTINCT kid digests one window may retain. The denial count stays
# exact regardless; this bounds only the set used to answer "how many different
# kids were offered", which is attacker-controlled in both content and
# cardinality.
MAX_DISTINCT_KIDS = 4096


def _kid_digest(kid: str) -> str:
    return "sha256:" + hashlib.sha256(kid.encode("utf-8", "surrogatepass")).hexdigest()[:16]


@dataclass
class _Window:
    """An open coalescing window and the durable row backing it."""

    audit_id: int
    opened_at: float
    # Monotonic clock reading of the most recent fold into this window. Drives
    # LRU eviction; ``last_seen`` is the human-facing ISO timestamp and is not
    # usable for ordering.
    last_touch: float
    first_seen: str
    last_seen: str
    # The details the row was opened with. Kept because an in-place update
    # rewrites the whole blob, and the aggregate must not overwrite the
    # original reason and kid with counters.
    base_details: dict[str, Any] = field(default_factory=dict)
    count: int = 1
    kid_samples: list[str] = field(default_factory=list)
    distinct_kids: set[str] = field(default_factory=set)
    # True once distinct-kid tracking hit its cap: ``distinct_kids`` is then a
    # floor, not a total, and the row says so.
    distinct_kids_truncated: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "denial_count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class DenialCoalescer:
    """Fold repeated account-creation denials into one row per time window.

    ``window_seconds`` of 0 (or less) disables coalescing entirely: every
    denial gets its own row, which is the behaviour that shipped before this
    existed. Callers that want that back can set it in config.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        max_kid_samples: int = MAX_KID_SAMPLES,
        max_open_windows: int = MAX_OPEN_WINDOWS,
        max_distinct_kids: int = MAX_DISTINCT_KIDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window_seconds = float(window_seconds)
        self._max_kid_samples = max_kid_samples
        if max_distinct_kids < 1:
            raise ValueError("max_distinct_kids must be at least 1")
        self._max_distinct_kids = max_distinct_kids
        if max_open_windows < 1:
            raise ValueError("max_open_windows must be at least 1")
        self._max_open_windows = max_open_windows
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str, str, str], _Window] = {}
        # Monotonic count of windows dropped to stay under the cap. An evicted
        # window's successor cannot carry ``previous_window``, so without this an
        # investigator could not tell "first window for this key" from "the index
        # dropped my predecessor". Stamped onto every row opened after the first
        # eviction.
        self._evicted = 0

    def _evict_for_new_window(self, now: float) -> None:
        """Make room for one more open window. Caller holds the lock.

        Nothing durable is touched: every window's tally was written to its row
        on each increment, so dropping the in-memory entry loses only the
        ability to fold FUTURE repeats into that already-committed row, and the
        ``previous_window`` breadcrumb the key would have carried if it reopened.
        Expired windows go first -- they can no longer be folded into anyway --
        and only then the longest-open live ones.
        """
        if len(self._windows) < self._max_open_windows:
            return
        for key in [
            k
            for k, w in self._windows.items()
            if (now - w.opened_at) >= self._window_seconds
        ]:
            del self._windows[key]
            # Counted as well. Only the LRU loop below used to increment, and
            # this is the branch an attacker actually drives: minting fresh keys
            # to reach the cap is what triggers the sweep. A victim key whose
            # lapsed window was swept here then reopened with no
            # ``previous_window`` AND no ``coalescer_evictions`` -- byte-identical
            # to a first-ever window, which is the ambiguity the marker exists to
            # remove.
            self._evicted += 1
        if len(self._windows) < self._max_open_windows:
            return
        # Least-recently-TOUCHED, not longest-open. Ordering by ``opened_at``
        # preferentially destroyed the window that had been folding the longest
        # — the one whose survival saves the most rows — and an attacker minting
        # fresh keys steers that choice. ``last_touch`` moves on every fold, so
        # a hot window survives a flood of cold ones.
        for key, _ in sorted(
            self._windows.items(), key=lambda item: item[1].last_touch
        )[: len(self._windows) - self._max_open_windows + 1]:
            del self._windows[key]
            self._evicted += 1

    @property
    def enabled(self) -> bool:
        return self._window_seconds > 0

    def record(self, store: Store, /, **kwargs: Any) -> dict[str, Any] | None:
        """Persist an audit event, coalescing it when it is a repeat denial.

        Returns the event dict when a new durable row was written — the caller
        fans that out to SIEM — or ``None`` when the event was folded into an
        open window's existing row. The SQLite row is authoritative for counts;
        the SIEM sink sees one event per window, carrying the previous window's
        final tally.
        """
        event_type = kwargs.get("event_type", "")
        if not self.enabled or event_type not in COALESCED_EVENT_TYPES:
            return store.record_audit(**kwargs)

        details = dict(kwargs.get("details") or {})
        # The coalescer's own markers are stripped from caller-supplied
        # details before anything is decided, then re-added from authoritative
        # state. No call site sends these keys today, but they are the fields
        # an investigator uses to distinguish "first window for this key" from
        # "the index dropped my predecessor" -- exactly the judgement a buggy
        # or future call site must not be able to forge by passing them in.
        details.pop("previous_window", None)
        details.pop("coalescer_evictions", None)
        # ``reason_code`` is the coalescing identity; ``reason`` is prose for a
        # human and MAY contain attacker-chosen text.
        #
        # This distinction was missing, and one call site made the omission
        # matter: ``IssuancePolicy.evaluate`` returns
        # ``f"SAN out of scope for kid {kid}: {san}"``, which ``finalize`` passed
        # straight into ``details["reason"]``. The requested SAN was therefore
        # IN THE COALESCING KEY, so varying one identifier per request produced
        # one durable row per request — exactly the bound-defeating move this
        # module's own docstring says the key excludes attacker-chosen data to
        # prevent. Call sites that can carry variable prose now send a stable
        # ``reason_code`` alongside it; ``reason`` remains on the row.
        reason = str(details.get("reason", ""))
        # An EXPLICIT reason_code keys the window on itself even when falsy: the
        # fallback to ``reason`` exists for call sites that predate the split,
        # not as a licence to put attacker-chosen prose back into the key by
        # passing an empty code. An empty-string code folds everything that
        # sends it into one bounded window, which is the safe direction.
        raw_reason_code = details.get("reason_code")
        reason_key = str(raw_reason_code) if raw_reason_code is not None else reason
        kid = details.get("kid")
        # The coalescing key. For account-creation denials it is (type, reason)
        # as before -- there is no account to key on, and keying on the
        # attacker-chosen kid would let one character of variance defeat the
        # bound. Finalize denials additionally carry account_id/order_id so one
        # order's evidence stays distinct. Replayable admin operations use a
        # fixed global key per event/reason: even server-issued order ids become
        # attacker-selectable once an admin token can enumerate and rotate
        # through more keys than the in-memory window cap.
        global_admin_key = event_type in _GLOBAL_ADMIN_KEY_EVENT_TYPES
        key = (
            event_type,
            reason_key,
            "" if global_admin_key else str(kwargs.get("account_id") or ""),
            "" if global_admin_key else str(kwargs.get("order_id") or ""),
        )
        now = self._clock()

        with self._lock:
            window = self._windows.get(key)
            if window is not None and (now - window.opened_at) < self._window_seconds:
                if not self._extend(store, window, kid):
                    # The durable row went away under us (an operator archived
                    # the table). Fall through and open a new window rather
                    # than counting into a record that no longer exists.
                    self._windows.pop(key, None)
                    window = None
                else:
                    return None
            closed = window.summary() if window is not None else None
            # Make room BEFORE the row is built, not after. Stamp-first ordering
            # read ``_evicted`` before the eviction this open caused, so the row
            # that actually displaced an entry carried no
            # ``coalescer_evictions`` -- byte-identical to a first-ever window,
            # the exact ambiguity the marker exists to remove. ``closed`` is
            # captured above, so the lapsed same-key entry's hand-off survives
            # the sweep, and a key still in the index here is always one whose
            # window has lapsed (a LIVE key folds and returns above), so the
            # expiry pass inside collects that entry first and no live
            # bystander is displaced to make room for it. If the record below
            # fails and no window is inserted, entries were still only dropped,
            # never rows -- fail-safe on both counts.
            self._evict_for_new_window(now)
            new_kwargs = dict(kwargs)
            new_details = dict(details)
            new_details["denial_count"] = 1
            new_details["coalesce_window_seconds"] = self._window_seconds
            if closed is not None:
                new_details["previous_window"] = closed
            if self._evicted:
                # Absence of ``previous_window`` is ambiguous once the index has
                # been shedding windows; say so on the row rather than leaving
                # the reader to guess. CUMULATIVE for the life of the process and
                # never reset, so it answers "has the index been shedding?" and
                # not "is it shedding now" -- successive rows are diffable, a
                # single row is not.
                new_details["coalescer_evictions"] = self._evicted
            new_kwargs["details"] = new_details
            event = store.record_audit(**new_kwargs)
            audit_id = event.get("id")
            timestamp = str(event.get("timestamp", ""))
            if isinstance(audit_id, int):
                fresh = _Window(
                    audit_id=audit_id,
                    opened_at=now,
                    last_touch=now,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    base_details=dict(event.get("details") or new_details),
                )
                if isinstance(kid, str):
                    digest = _kid_digest(kid)
                    fresh.distinct_kids.add(digest)
                    # The sample cap applies at window open too, not only in
                    # _extend: with max_kid_samples=0 the first kid still
                    # landed in the list, so the cap was enforced on the Nth
                    # kid but never the first. (max_distinct_kids has a floor
                    # of 1 in __init__, so the set add above is always within
                    # its cap.)
                    if len(fresh.kid_samples) < self._max_kid_samples:
                        fresh.kid_samples.append(digest)
                self._windows[key] = fresh
            else:
                # No row id means nothing to update in place later, so do not
                # open a window: the fail-safe direction is more rows, not a
                # lost count.
                self._windows.pop(key, None)
            return event

    def _extend(self, store: Store, window: _Window, kid: Any) -> bool:
        """Fold one more denial into an open window's already-durable row.

        Returns False when the row could not be updated because it no longer
        exists, which is the caller's signal to open a fresh one.
        """
        window.count += 1
        window.last_touch = self._clock()
        window.last_seen = _now_iso()
        if isinstance(kid, str):
            digest = _kid_digest(kid)
            if digest not in window.distinct_kids:
                # The DISTINCT-kid set is bounded too, not just the named
                # sample. ``kid_samples`` was capped and ``distinct_kids`` was
                # not, so an attacker varying the kid every request retained one
                # 16-byte digest each inside a single window -- ~5 MB per 50,000
                # kids, freed only when the window rolls -- and a longer
                # coalesce window, which reduces row growth, multiplies exactly
                # this. Past the cap the exact count is no
                # longer knowable, so the row says so rather than reporting a
                # number that has quietly stopped counting.
                if len(window.distinct_kids) < self._max_distinct_kids:
                    window.distinct_kids.add(digest)
                    if len(window.kid_samples) < self._max_kid_samples:
                        window.kid_samples.append(digest)
                else:
                    window.distinct_kids_truncated = True
        # The update rewrites the whole details blob, so start from what the
        # row already said (reason, the first offered kid) and layer the
        # aggregate on top. Nothing the first denial recorded is lost.
        details = dict(window.base_details)
        details.update(
            {
                "denial_count": window.count,
                "coalesce_window_seconds": self._window_seconds,
                "first_seen": window.first_seen,
                "last_seen": window.last_seen,
                "kid_digests": list(window.kid_samples),
                "distinct_kids": len(window.distinct_kids),
                "distinct_kids_truncated": window.distinct_kids_truncated,
            }
        )
        return store.update_audit_details(window.audit_id, details)

    def close(self) -> None:
        """Drop every open window at shutdown.

        There is nothing to flush: each window's tally was written to its row
        on every increment, so the durable counts are already exact. This only
        clears process state, so a long-lived window cannot outlive the run it
        was measuring.
        """
        with self._lock:
            self._windows.clear()

    def open_window_count(self) -> int:
        with self._lock:
            return len(self._windows)
