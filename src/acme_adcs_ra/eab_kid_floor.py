"""Startup floor on EAB kid length, grandfathering kids already in use (WI-044).

``config._credentials_are_strong`` floors the EAB MAC key at load time. The kid
had no floor at all, although threat model §4.B treats an unguessable kid as
load-bearing against account-existence probing. A load-time floor would refuse
to start any deployment whose existing kid is short — locking every account
under it out on upgrade, to defend against a probe the dummy-HMAC equalizer and
the ``account-creation-denied`` audit already compensate for. So the floor needs
the store, and runs here at startup instead:

* a short kid with **no** accounts is a new credential: refuse to start;
* a short kid that **already has** accounts is grandfathered: start, and warn
  loudly on every startup until it is rotated (``scripts/eab.py --rotate``);
* ``allow_weak_credentials`` (the existing lab/CI gate) skips the floor, the
  same as it skips the MAC-key floor.
"""

from __future__ import annotations

import logging

from acme_adcs_ra.config import MIN_EAB_KID_CHARS, RAConfig
from acme_adcs_ra.store import Store

logger = logging.getLogger("acme_adcs_ra.eab_kid_floor")


def assert_eab_kids_meet_floor(config: RAConfig, store: Store) -> None:
    if config.allow_weak_credentials:
        return
    short = [e.kid for e in config.eab_allowlist if len(e.kid) < MIN_EAB_KID_CHARS]
    if not short:
        return
    in_use = store.eab_kids_with_accounts(short)
    refused = [k for k in short if k not in in_use]
    for kid in short:
        if kid in in_use:
            logger.warning(
                "EAB kid %r is %d characters, below the %d-character floor. It is "
                "GRANDFATHERED because accounts already exist under it; rotate it "
                "(python scripts/eab.py --rotate %s) to clear this warning.",
                kid, len(kid), MIN_EAB_KID_CHARS, kid,
            )
    if refused:
        raise RuntimeError(
            "weak credentials rejected at startup: EAB kid(s) "
            + ", ".join(f"{k!r} ({len(k)} chars)" for k in refused)
            + f" are below the {MIN_EAB_KID_CHARS}-character floor and have no "
            "existing accounts. Mint kids with `python scripts/eab.py new`. Set "
            "allow_weak_credentials=true ONLY for a lab or CI fixture."
        )
