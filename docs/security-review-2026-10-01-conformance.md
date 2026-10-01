# 2026-10-01 — RFC 8555 error mappings, media type, kid floor, challenge Link (WI-043, WI-044, WI-046)

Second of the 2026-10-01 conformance PRs (the first, WI-041/032, is
`docs/security-review-2026-10-01.md`). Items 29 and 30 of
`UNFILED-WORK-ITEMS.md` (store WI-043, WI-044), plus WI-046, which the
stock-client interop harness (WI-045) found once certbot could register.

## WI-043 (a) — finalize on a not-ready order: 403 `orderNotReady`

RFC 8555 §7.4: *"A request to finalize an order will result in error if the
order is not in the 'ready' state. In such cases, the server MUST return a 403
(Forbidden) error with a problem document of type 'orderNotReady'."* The RA
answered `malformed`/400. Now `orderNotReady`/403 for `pending`, `invalid`, and
an order found expired at finalize (flipped to `invalid`, on both the CAS-won
and CAS-lost branches).

**Deliberate deviation kept:** `valid` and `processing` orders are still
answered with the current order (200, `Retry-After` for processing), not 403.
A retried finalize must never read as an error once issuance has happened or is
under way, and the double-issuance guard returns the existing certificate on
that path. Strict §7.4 would make both a 403; changing it would put the
finalize-retry behaviour every client depends on at risk for no security gain.
Recorded here rather than silently left.

## WI-043 (b) — unsupported `alg`: 400 `badSignatureAlgorithm` + `algorithms`

§6.2: an unsupported JWS algorithm MUST be 400 `badSignatureAlgorithm`, and the
problem document MUST include an `algorithms` array. A new
`UnsupportedSignatureAlgorithmError` (a subclass, so every existing
`except UnsupportedAlgorithmError` still catches it) is raised only for an
`alg` outside the allowlist — not for unsupported JWK key types or curves,
which stay `badPublicKey`. Mapped for account requests, newAccount, and the
keyChange inner JWS. `AcmeError` gained RFC 7807 extension members to carry
the array. The allowlist itself is unchanged; this is the error mapping only.
A forged signature under a supported `alg` is still `unauthorized`.

## WI-044 (a) — `application/jose+json` enforced (415)

§6.2: a request without `Content-Type: application/jose+json` MUST get 415.
The threat model's CSRF argument relied on this property while the code never
checked it. `_require_jose_json` runs in `_parse_jws_body`, i.e. on every JWS
route and **before the body is read and before any nonce is spent**, so a
wrong-media-type request costs nothing and burns nothing (tested: the same
signed request, resent with the right type, succeeds). Media-type parameters
(`; charset=utf-8`) do not affect the match and the type compares
case-insensitively (RFC 9110 §8.3.1); the field must appear **exactly once** —
duplicates are refused in either order (Daybreak Blue, round 1, found the
first-of-two was trusted) — and the value must parse as **one RFC 9110 §8.3.1 media type** (type/subtype
plus well-formed `;` parameters, token or quoted-string values). Round 2 found
`application/jose+json; charset=utf-8, text/plain` slipping past a split at
`;`; round 3 found the "refuse any comma" fix both accepted the malformed
`application/jose+json; text/plain` and refused the valid
`application/jose+json; profile="one,two"`. A grammar parse settles all three:
a list (folded duplicates, unfolded obs-fold) is not a media type.

**Round 4 (both lineages, independently): the first grammar regex was a ReDoS.**
The OWS on both sides of `;` and the optional (empty) parameter overlapped, so
`"; " * n` followed by a rejecting byte had exponentially many parses — ~0.3 s
at 62 bytes, a hang at ~72–100 bytes — on an unauthenticated header, before
auth, nonce or body. Fixed with possessive OWS quantifiers (`*+`, linear match)
plus a 256-character cap; a test runs the hostile shapes in a child process
with a timeout (the regex holds the GIL, so an in-process timer cannot fire).
Empty parameters (`application/jose+json;`) are accepted deliberately — RFC
9110 §5.6.6 permits empty list elements. A
**missing** Content-Type is also 415: §6.2's wording is "if a request does not
meet this requirement", and a request without the field does not. The problem type is
`malformed` — RFC 8555 registers none for 415. Because the check precedes the body read, an oversized body with a wrong type is now 415 rather than 413. Admin JSON endpoints do not use
`_parse_jws_body` and are unaffected. All four stock clients send the right
type (harness transcripts).

## WI-044 (b) — EAB kid floor, grandfathering kids in use

`MIN_EAB_KID_CHARS = 22`: the necessary-not-sufficient length for 128 random
bits in base64url. No length rule measures entropy; `scripts/eab.py` mints 32
hex characters (128 bits) and passes.

**Compatibility.** A load-time floor in `_credentials_are_strong` would refuse
to start any deployment whose existing kid is short, locking every account
under it out on upgrade. So the floor runs at startup against the store
(`eab_kid_floor.assert_eab_kids_meet_floor`, called from `create_app` beside the
retention floor):

| kid below the floor… | result |
|---|---|
| with no accounts (a new credential) | **refuse to start**, same gate and wording as the MAC-key floor |
| with ≥ 1 account, any status | **grandfathered**: start, WARNING on every startup naming the kid and the rotate command |
| `allow_weak_credentials=true` | floor skipped (existing lab/CI gate) |

Grandfathering is per kid and **exact-match**: one short kid in use does not
excuse a second new one, and re-declaring a grandfathered kid with different
case or whitespace is a new kid (refused) — consistent with every other kid
lookup in the RA, which is also exact. A store error during the check aborts
startup with the store's own exception (fails closed; DeepSeek round 1 notes
the message is the raw one, not the floor's). **I could not check the lab's actual kids** (lab estate untouched by
instruction); if any lab kid is short it will be grandfathered, not refused,
provided it already has an account.

Test churn: the suite's fixture kids (`kid-001` …) were 5–9 characters and are
now padded to ≥ 22 across 26 test files, mechanically; `tests/test_eab.py` is
left alone because it exercises the audit CLI only, not `create_app`.

## WI-046 — challenge responses link `up` to the authorization

Found by the interop harness: with Replay-Nonce fixed, certbot 5.8.0 reached
the challenge and aborted (`"up" Link header missing`). §7.1 defines the `up`
relation from a challenge to its authorization (shown in the §7.5.1 example).
Both challenge responses (first validation and the already-valid replay
short-circuit) now carry `Link: <authz-url>;rel="up"`. Still open: the `index`
relation §7.1 describes on every non-directory resource is not sent; no client
in the harness needs it.

## Found on the way: a false RFC citation in revokeCert (WI-047, not changed)

The harness's certbot run revoked the same certificate twice and got 200 both
times. `routes/revocation.py` (H-4) justified that with *"RFC 8555 §7.6 says an
already-revoked cert returns 200 OK"*. It does not: §7.6 says the server
*"returns an error response with status code 400 (Bad Request) and type
'urn:ietf:params:acme:error:alreadyRevoked'"*. The comment is corrected here;
the behaviour is **not** changed, because a client retrying a revocation that
did succeed must not be told it failed (the 2026-08-24 Certify the Web finding
is the precedent). Whether to conform is an owner decision, filed as WI-047.

## Mutation matrix

New: `tests/test_rfc8555_conformance_2026_10_01.py` (37; 23 at first review, +3 duplicate-field cases in round 1, +3 comma-list cases and an exact-match grandfathering test in round 2, +1 CAS-lost expiry test and +2 media-type grammar cases in round 3, +4 hostile-input timing cases in round 4). One mutation at a
time, against the fixed tree:

| Mutation | Result |
|---|---|
| pending finalize → `malformed` | 1 fails |
| expired finalize (CAS-won branch) → `malformed` | 1 fails (`test_acme_server` expiry test) |
| (round 3) expired finalize, CAS-lost branch (order already `invalid`) → `malformed` | 1 fails (new deterministic test; round 3 showed the branch is reachable without a race) |
| outer unsupported-alg mapping removed | 5 fail |
| inner keyChange mapping removed | 1 fails |
| `jws.py` raises the parent exception | 6 fail |
| media-type check removed | 10 fail (was 4 on the original 23) |
| media type compared raw (no param/case handling) | 2 fail |
| (round 1) duplicate-field refusal removed | 2 fail |
| (round 3) grammar parse replaced by the round-2 split-at-`;` + comma refusal | 2 fail (malformed parameter, quoted comma) |
| (round 4) possessive OWS quantifiers made plain again | 3 fail (child processes time out); the 20 000-char case still passes on the length cap alone |
| kid floor not called | 4 fail |
| grandfathering disabled | 1 fails |
| (round 2) grandfathering made case-insensitive (store query + floor) | 1 fails |
| `allow_weak_credentials` ignored | 3 fail |
| `up` link missing on the replay branch | 1 fails |
| floor lowered to 16 | 2 fail |
