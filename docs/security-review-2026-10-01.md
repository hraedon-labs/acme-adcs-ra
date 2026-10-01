# 2026-10-01 — RFC 8555 nonce conformance: keyChange (WI-031) and Replay-Nonce (WI-032)

Two protocol defects filed on 2026-09-20 as UNFILED items 27 and 28 (store
WI-031, WI-032). Both were invisible to the suite for the reason AGENTS.md has
recorded twice: `tests/hand_rolled_acme_client.py` spoke the server's dialect.
Both were then **reproduced with stock clients** against a local RA at
`ed1bab5` with a throwaway in-memory CA (the interop harness of item 31,
WI-035; no real or lab CA was involved).

## WI-031 — keyChange demanded an inner-JWS nonce (medium)

RFC 8555 §7.3.5: *"The inner JWS MUST omit the 'nonce' header parameter."*
`routes/key_change.py` raised `badNonce` when it was absent and consumed it
when present.

**Stock-client reproduction at `ed1bab5`:** lego 5.5.2 (`accounts
keyrollover`), acme.sh 3.1.6 (`--update-account-key`) and Posh-ACME 4.34.0
(`Set-PAAccount -KeyRollover`) all failed with `badNonce: inner JWS protected
header missing nonce`. certbot has no key rollover. Certify the Web (Anvil)
also omits the inner nonce, per its source; not run here.

**Fix.**

- An absent inner nonce is the accepted form. Only the **outer** nonce is
  consumed (by `authenticate_account`, as before), and it is what makes the
  request single-use.
- A **present** inner nonce is refused (`malformed`), not ignored: the RFC says
  MUST omit, and tolerating it would keep the old private dialect alive in the
  in-repo client. An inner `kid` is refused too (jwk and kid are mutually
  exclusive, §6.2).
- Success now returns the updated account object, as §7.3.5 says, rather than
  `{}`.
- `HandRolledAcmeClient.key_change()` and two hand-built tests stop sending an
  inner nonce.

**Replay analysis.** Dropping the inner nonce removes no protection: the inner
JWS is only ever accepted inside one outer request whose nonce is single-use;
it binds `url` (equal to the outer `url`) and `account` (equal to the outer
`kid`); and once the rollover succeeds the old key no longer authenticates, so
a captured inner JWS cannot be re-wrapped. Each property has a test.

## WI-032 — Replay-Nonce only on new-nonce (raised low → medium)

RFC 8555 §6.5: the server MUST send `Replay-Nonce` *"in every successful
response to a POST request"*, and a `badNonce` error MUST carry a fresh nonce
for the retry. The RA set it only on `new-nonce`.

**Stock-client reproduction at `ed1bab5` — the filing understated it:**
**certbot 5.8.0 could not register at all** (acme-python raises
`MissingNonce` on the first POST response without the header), and **Posh-ACME
4.34.0 failed every POST after new-account** (it re-sends the nonce it already
spent when a response carries none, and the `badNonce` it gets back offered no
nonce to recover with). lego and acme.sh fetch a fresh nonce and were
unaffected.

**Fix: `ReplayNonceMiddleware` (server.py)**, a pure ASGI wrapper driven by two
request-state flags rather than by path: `acme_nonce_consumed` (set by
`server_jws._parse_jws_header` once a nonce is spent) and `acme_error_type` (set
by the `AcmeError` handler). Directory and admin routes set neither and are
untouched; `new-nonce` keeps its single header.

**The bucket rule is the security-relevant part.** The nonce bucket (20/s,
burst 100) exists so an unauthenticated flood cannot hold SQLite's single
writer.

| Response | Nonce | Source |
|---|---|---|
| 2xx/3xx to a POST that spent a nonce | always | **unbucketed** — a success implies a verified JWS (an account, or a new account past EAB); one spent, one minted, and the MUST holds even under nonce-flood pressure |
| error to a POST that spent a nonce | if the bucket allows | bucket — the error may be an unauthenticated peer's |
| `badNonce` error (nothing spent) | if the bucket allows | bucket |
| any other error | none | — |

Without the error rule, "valid nonce + garbage signature → 401 carrying a fresh
nonce" would be an unbounded unauthenticated nonce chain around the bucket. A
dry bucket on an error simply omits the header; the client falls back to
`new-nonce`, which answers `rateLimited`.

**Accepted trade, stated plainly.** Before this change every POST needed a
bucketed nonce, so the bucket incidentally capped the *global* POST rate at
20/s, authenticated traffic included. That incidental cap is gone for
authenticated successful requests: an account can now chain POSTs at the rate
it can sign them. This is what §6.5 requires. Per-account order creation is
still rate-limited in-app, and `docs/operations.md` already assigns raw request
rate to the reverse proxy.

A nonce mint that fails (unwritable store) is logged and the header omitted —
the request's effects have already committed, and a post-hoc 500 would be
worse than a missing nonce.

**Interop accommodation (not protocol).** acme.sh 3.1.6 retries a `badNonce`
only when the problem *detail* contains Boulder's wording; it ignores the type.
`bad_nonce()` details now begin `JWS has an invalid anti-replay nonce: …`. The
type and status are unchanged.

## Tests and mutation matrix

New: `tests/test_key_change_rfc8555.py` (6), `tests/test_replay_nonce_rfc8555.py`
(11). Each mutation below was applied alone against the fixed tree.

| Mutation | Result |
|---|---|
| keyChange route reverted to `ed1bab5` | 6/6 keyChange tests fail |
| present-nonce and inner-kid refusals disabled | 2 fail (nonce-present, kid-present) |
| `ReplayNonceMiddleware` not registered | 7/11 fail |
| error responses mint unbucketed | 3 fail (both dry-bucket error tests, chain test) |
| success responses drawn from the bucket | 1 fails (dry-bucket success) |
| badNonce detail prefix removed | 1 fails |
| mint guard removed (`create_nonce` raises) | 1 fails (completed POST becomes a 500) |
| `acme_error_type` never set | 1 fails (badNonce retry nonce) |
| errors that spent a nonce get none | 2 fail |

The success-body change (account object) is covered by
`test_rfc_shaped_inner_jws_without_nonce_rolls_the_key`.

## Not covered here

Stock-client proof of the *fixed* tree is recorded in the PR (interop harness,
WI-035). Items 29–30 (WI-033, WI-034) are a separate PR. Live IIS/ADCS is
untouched; nothing here changes the enrollment or revocation legs.
