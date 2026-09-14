# Operations runbook — acme-adcs-ra

This runbook covers the operator-owned prerequisites the
[pre-pilot checklist](pre-pilot-checklist.md) names as blockers. It is the
single reference for EAB lifecycle, network allowlist / rate limiting,
scheduled maintenance, the admin token + reclaim runbook, monitoring/SLOs,
retention/archival, the revocation runbook, and backup/restore.

All identifiers here are placeholders (`WORK-DOMAIN.local`, `CA01`,
`CONTOSO-CA01-CA`, `ACME-ServerAuth`). Real values live in gitignored local
config / `samples/`.

## EAB lifecycle

External Account Binding (EAB) is the *who-is-allowed* gate (threat-model
§4.B). Each authorized ACME client gets a kid + MAC key + SAN scope. A stolen
EAB key allows rogue account creation within that kid's SAN scope until it is
rotated, so kids must be high-entropy and the MAC key must be treated like a
password.

Each EAB kid has a lifetime durable-account quota, configured with
`ACME_RA_MAX_ACCOUNTS_PER_EAB_KID` (default `1`). Deactivated accounts still
consume their slot; the quota is not a concurrency hint or a rolling limit.
The RA enforces it in the store transaction that inserts the account and its
`account-created` audit row, so concurrent distinct account keys cannot exceed
the configured value. A rejected creation returns
`badExternalAccountBinding` and is coalesced with other account-limit denials
for audit-growth control.

### Minting a new EAB credential

Use `scripts/eab.py` to mint a high-entropy kid (UUID4, 32 hex chars, 128
bits) and MAC key (base64url of 32 random bytes, ≥256 bits). The helper prints
stdout-only env-var lines you paste into the locked-down `acme-ra.env`:

```bash
python scripts/eab.py
```

Output (example — the real kid/key are freshly generated each run):

```
# !!! TREAT LIKE A PASSWORD — never commit, never paste into chat/tickets. !!!
# !!! ACL the env file to the gMSA + Administrators only.                  !!!
ACME_RA_EAB_ALLOWLIST=[{"kid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4","mac_key":"ZmFrZS1tYWMta2V5LTMyLWJ5dGVzLWxvbmctYW5kLXNlY3VyZQ"}]
ACME_RA_SAN_SCOPES__a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4__DNS_PATTERNS=["*.WORK-DOMAIN.local"]
```

After pasting:
1. Merge the `ACME_RA_EAB_ALLOWLIST` JSON array into the existing value in
   `acme-ra.env` (append the new object; do not overwrite other kids).
2. Replace the placeholder DNS patterns with the real SAN scope for this
   client (e.g. `["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]`).
3. ACL `acme-ra.env` to the gMSA + Administrators only (the installer lays
   it down locked; re-check after editing).
4. Restart the RA app pool so the new env vars take effect.
5. Configure the ACME client (Certify the Web) with the kid + MAC key.

The helper never logs secrets, never writes to disk, and never accepts a MAC
key as input — the MAC key is always freshly generated.

### Rotating an EAB credential

Rotation is a dual-credential cutover: the old kid stays valid until the
client is switched over, then it is removed.

```bash
python scripts/eab.py --rotate OLDKID1234567890abcdef1234567890ab
```

This mints a new credential and prints a rotation checklist. Follow it:

1. Merge the new entry into `ACME_RA_EAB_ALLOWLIST` in `acme-ra.env` as a
   JSON array (do not remove the old kid during the cutover — both must be
   valid).
2. Add `ACME_RA_SAN_SCOPES__<NEW_KID>__DNS_PATTERNS` for the new account.
3. Restart the RA app pool.
4. Re-issue the ACME client's EAB credential (kid + MAC key) and point the
   client at the new kid.
5. Confirm the new account can create an account + issue a test cert.
6. Once the old account is no longer used, remove the old kid's
   `ACME_RA_EAB_ALLOWLIST__<i>__*` entries and its SAN scope, restart the RA,
   and confirm the old account can no longer create new orders (existing
   orders/certs remain valid).
7. Keep the old kid's audit trail for the standard audit retention period.

### When to rotate

- **Suspected or confirmed compromise** of the MAC key or the client that
  holds it (the primary driver — rotate immediately and audit `account-created`
  events for the affected kid).
- **Client decommissioning** (rotate to retire the kid cleanly).
- **Routine rotation** per your org's secrets policy (e.g. annually).

### Auditing EAB scopes

The challenge is intentionally a no-op (enterprise trust model), so the
kid→scope mapping *is* the entire authorization surface. Run the audit
subcommand periodically to confirm no scope has quietly widened and that
every configured kid is accounted for:

```bash
python scripts/eab.py audit --env acme-ra.env --db acme_ra.db
```

Output (example — placeholders only; the real kid prefix comes from
`acme-ra.env`):

```
EAB scope audit — kid → SAN scope → last-used (no MAC keys shown)

KID          SAN SCOPE PATTERNS                            LAST USED             FLAGS
-----------  --------------------------------------------  --------------------  --------
a1b2c3d4...  *.WORK-DOMAIN.local, srv01.WORK-DOMAIN.local  2026-01-03T00:00:00Z  WILDCARD
b2c3d4e5...  exact.WORK-DOMAIN.local                       2026-02-01T00:00:00Z
c3d4e5f6...  (no scope — fail-closed)                      never                 NO SCOPE

3 kid(s): 1 wildcard, 1 no-scope, 1 never-used.
```

- **KID** — first 8 chars + `...` (the full kid is never printed; cross-reference
  with `acme-ra.env` to identify the account).
- **SAN SCOPE PATTERNS** — the DNS patterns this kid may request. A kid with no
  scope configured shows `(no scope — fail-closed)` and the `NO SCOPE` flag
  (no SANs are allowed for it).
- **LAST USED** — the most recent `account-created` or `order-created`
  timestamp for this kid in the RA store. `never` means no account has ever
  been created with this kid (it may be a freshly minted, not-yet-deployed
  credential, or a stale entry that should be cleaned up).
- **FLAGS** — `WILDCARD` if any pattern is a leftmost-label wildcard
  (`*.example.com`), the widest blast radius. `NO SCOPE` if the kid has no
  SAN scope configured.

The audit **never prints MAC key material** and is strictly read-only — it
does not write to the store. `--env` and `--db` are optional; if omitted the
config is read from `ACME_RA_*` environment variables and the store from
`ACME_RA_DB_PATH` (or the default `acme_ra.db`).

**What to look for:**

- A `WILDCARD` scope you did not expect (e.g. `*.corp.local`) — the widest
  blast radius; confirm it is intended.
- A `NO SCOPE` kid — this kid can authenticate but issue nothing; either add a
  scope or remove it from the allowlist.
- A `never`-used kid that has been configured for a long time — may indicate
  a stale entry or a client that was never switched over after rotation.

## Disabling a compromised account

There are two independent kill switches, and both take effect on the **next
request** — no restart, no cache to wait out.

**Operator side — pull the EAB kid.** Remove the kid's entry from
`eab_allowlist` in `acme-ra.env` and recycle the app pool. Every ACME account
created under that kid is then refused entirely: new orders, key rollover, and
`revokeCert` alike. Each refusal is audited as `account-request-denied` with
`reason: eab-kid-not-allowlisted`, so a client still trying to use the
credential is visible in SIEM.

> Before 2026-08-11 this only stopped *issuance* — an attacker holding a stolen
> account key could still revoke the victim's live certificates after the
> credential was believed cut off. If you are running an older build, treat kid
> removal as incomplete and revoke at the CA instead.

**Client side — deactivate the account (RFC 8555 §7.3.6).** The client POSTs
`{"status": "deactivated"}` to its own account URL. This is one-way: the RA
does not allow reactivation, and every later request from that account is
refused with `reason: account-not-valid`. Useful when the client knows its own
key is compromised but the operator is not on hand.

Neither switch revokes already-issued certificates. Certificates outstanding at
the time of eviction remain valid until revoked — use the revocation runbook
below, driven by an operator, since the evicted account can no longer revoke
them itself.

## Network allowlist and in-app rate limiting

The RA has an **in-app per-account rate limit** (WI-016) that bounds order
creation per EAB kid per rolling window, plus an optional global backstop.
This is defense-in-depth that does not depend on the operator's reverse-proxy
config being present or correct: even a directly-fronted RA, or one whose
proxy rule was fat-fingered, is protected so a leaked EAB credential cannot
mint an unbounded cert flood before the network layer notices.

The installer deliberately does not restrict the endpoint itself
(threat-model §4.G). Three operator controls bound this: the in-app rate
limit (how many orders per kid), a network allowlist (who may reach the RA
at all), and reverse-proxy rate limiting (how fast they may go).

### In-app rate limit (WI-016)

The in-app rate limit is configured via environment variables in
`acme-ra.env`:

| Env var | Default | Description |
|---|---|---|
| `ACME_RA_RATE_LIMIT_ORDERS_PER_WINDOW` | `50` | Max new orders per EAB kid per window. `0` = disabled. |
| `ACME_RA_RATE_LIMIT_WINDOW_SECONDS` | `3600` | Rolling window duration in seconds. |
| `ACME_RA_RATE_LIMIT_GLOBAL_PER_WINDOW` | `0` | Global backstop across all accounts. `0` = disabled. |
| `ACME_RA_RATE_LIMIT_OVERRIDES__<KID>` | (default) | Per-kid override: `ACME_RA_RATE_LIMIT_OVERRIDES__a1b2c3d4=10` sets kid `a1b2c3d4`'s limit to 10. |

On breach, the RA returns RFC 8555 `rateLimited` (HTTP 429) with a
`Retry-After` header and emits a SIEM audit event (`order-rate-limited`)
with the account, window, count, and scope (`per-account` or `global`).

**This is in addition to, not instead of, the reverse-proxy guidance below.**
The in-app limit bounds order creation (the expensive path that reaches
ADCS); the proxy limit bounds raw request rate (including polls and
challenge POSTs). Both should be configured.

### Key-rollover ceiling (14a)

Order creation is not the only transition a valid credential can repeat.
Account-key rollover (`keyChange`, RFC 8555 §7.3.5) had no rate, quota or
cardinality check at all, so a valid — or stolen — account key could chain
rotations indefinitely, each writing an audit row that is deliberately never
coalesced. Retention bounds what that costs on disk; this bounds the action.

| Env var | Default | Description |
|---|---|---|
| `ACME_RA_RATE_LIMIT_KEY_CHANGES_PER_WINDOW` | `5` | Max successful key rollovers per EAB kid per window. `0` = disabled. |

It shares `ACME_RA_RATE_LIMIT_WINDOW_SECONDS` with the order limiter and is
keyed per **EAB kid**, not per ACME account, for the same reason: a leaked EAB
credential must not be able to reset its budget by enrolling a fresh account
key. Over the limit the RA returns `429` with `Retry-After` and emits
`key-change-rate-limited`; repeats inside the coalescing window fold into one
row carrying an exact `denial_count`.

The check, the key update and its audit row share one transaction, so a
parallel burst cannot slip several rotations past the ceiling — each one that
did would be irreversible.

**Raising it.** The default is far above legitimate use: rollover is a rare
operational event, not a per-renewal one, and `max_accounts_per_eab_kid`
defaults to `1`. Raise it only if you are deliberately rotating many accounts
under one kid inside a single window (a bulk key-hygiene pass, say), and lower
it back afterwards.

### Nonce ceiling (unauthenticated)

`GET`/`HEAD /acme/new-nonce` is unauthenticated by protocol design, and every
call performs a SQLite `INSERT`. SQLite has a single writer, so a nonce flood
does not merely grow a table — it contends for the write lock with the issuance
path, where a blocked write surfaces as a 500 once the 5-second `busy_timeout`
expires. The per-account limiter cannot help here: there is no account yet at
nonce time.

The RA therefore applies an **in-process token bucket before the write**:

| Setting | Default | Meaning |
|---|---|---|
| `ACME_RA_NONCE_RATE_LIMIT_PER_SECOND` | `20` | Sustained nonces/sec. `0` disables the bucket. |
| `ACME_RA_NONCE_RATE_LIMIT_BURST` | `100` | Burst size. |

Over the limit the RA returns `429` with `Retry-After` and does **not** touch
the database. The defaults are far above real ACME client volume — a renewal
consumes a handful of nonces, not hundreds — so raise them only if you have
measured a legitimate need.

**Caveat:** the bucket is per worker *process*. Under IIS/HttpPlatformHandler
the RA runs as a single uvicorn process, so one bucket sees all traffic; if you
ever scale to multiple workers the effective ceiling multiplies by worker count.

The nonce bucket bounds the *rate* of the cheapest step. It does not bound what
a slower, sustained stream of rejected `newAccount` requests writes to disk;
that is a separate control:

| Setting | Default | Meaning |
|---|---|---|
| `ACME_RA_AUDIT_DENIAL_COALESCE_WINDOW_SECONDS` | `60` | Window in which repeats of the same pre-auth denial reason update one durable audit row instead of adding rows. `0` writes one row per denial. |

See **Retention and archival → audit_log table** below for what the coalesced
row contains and why nothing is deleted.
The network allowlist below remains the authoritative outer bound.

### Network allowlist (`<ipSecurity>`)

Add to `deploy/iis/web.config` under `<system.webServer><security>` (requires
the "IP and Domain Restrictions" role service, installed by
`install-windows.ps1 -InstallPrereqs`). Set `allowUnlisted="false"` and add
the authorized client IP(s):

```xml
<security>
  <requestFiltering removeServerHeader="true" />
  <ipSecurity allowUnlisted="false">
    <!-- Authorized ACME client(s) only. -->
    <add ipAddress="10.0.0.50" allowed="true" />
    <!-- Add more client IPs as needed. -->
  </ipSecurity>
</security>
```

> **SNI-shared-443 caveat.** If the RA shares port 443 by SNI with
> cert-watch / gpo-lens on the same IIS site (the `-SharePort443 -HostName`
> install mode), do **not** blanket-block 443 at the firewall or site level
> — that would also block the sibling tools. Apply `<ipSecurity>` at the
> application/site level scoped to the RA's SNI hostname, or use a
> per-hostname firewall rule. The default unrestricted behavior is kept so a
> misconfigured allowlist cannot lock the sibling tools out by accident.

### Reverse-proxy rate limiting

Apply per-account and per-IP rate limits at the reverse proxy / load balancer
in front of the RA. The in-app per-account rate limit above bounds **order
creation**; the proxy limit additionally bounds **raw request rate** (polls,
challenge POSTs, finalize retries), which the in-app limit does not cover.
Without a proxy limit, a flood of in-window non-order requests still reaches
the ADCS CA, so both should be configured.

- **nginx:** `limit_req_zone` keyed on the ACME account URL (from the JWS
  `kid`) for per-account, and on `$remote_addr` for per-IP. Example:

  ```nginx
  # Per-IP: 10 req/s burst 20.
  limit_req_zone $binary_remote_addr zone=acme_ip:10m rate=10r/s;
  # Per-account: 2 req/s burst 5 (tune to your client's renewal cadence).
  limit_req_zone $http_authorization zone=acme_acct:10m rate=2r/s;

  location / {
    limit_req zone=acme_ip burst=20 nodelay;
    limit_req zone=acme_acct burst=5 nodelay;
    proxy_pass http://127.0.0.1:<HTTP_PLATFORM_PORT>;
  }
  ```

- **IIS Dynamic IP Restrictions:** enable dynamic mode, restrict by IP and by
  request path, with a per-IP concurrent-connection cap. This is the
  per-IP control when IIS is the only proxy.
- **Azure Application Gateway / other LB:** configure per-backend-pool
  rate-limit rules keyed on the client IP and the `Authorization` /
  `content-type: application/jose+json` signature.

Tune the limits to your client's real renewal cadence (Certify the Web
renews on a schedule, so the steady-state rate is very low). Alert on
`limit_req` rejections — a spike there is a probe or a runaway client.

## Scheduled maintenance tasks

Two admin endpoints must be driven by an external cron (threat-model §4.G):
nonce GC and expired-order sweep (RFC 8555 §7.1.6). The probabilistic 1%
nonce cleanup on `create_nonce` is a safety net only — wire the cron.

`scripts/Register-MaintenanceTasks.ps1` registers two Windows Scheduled Tasks
that call these endpoints on a cadence (default 15 minutes):

```powershell
# Register both tasks (run as the gMSA so the task can read acme-ra.env).
# -AdminToken is a FLAG: the task action loads ACME_RA_ADMIN_TOKEN from the
# dotenv at run time -- the value is never accepted on a command line.
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken `
    -IntervalMinutes 15 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$"

# Dry run (does not register anything):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken `
    -WhatIf
```

**Task-user choice.** Run the tasks as the gMSA (the same identity the RA app
pool uses) so the task can read the env file, and so the task has no more
privilege than the RA itself. Alternatively, run as `NT AUTHORITY\SYSTEM` if
the gMSA is not desired for scheduled tasks; either way the task action reads
its credentials from the dotenv at run time (2026-08-19 F2) — no token value
is stored in the task definition or accepted by the registration script
(Daybreak 2026-08-15).

After registering, verify:

```powershell
Get-ScheduledTask -TaskName "acme-adcs-ra-nonce-cleanup" | Select-Object TaskName, State
Get-ScheduledTask -TaskName "acme-adcs-ra-expired-order-sweep" | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName "acme-adcs-ra-nonce-cleanup" | Select-Object NextRunTime
```

Each task invokes `Invoke-RestMethod` with `Authorization: Bearer <token>`.
The admin token is a high-value secret — see the admin-token runbook below
for rotation/ACL rules. The task action does not log the token.

## Admin token and reclaim runbook

`ACME_RA_ADMIN_TOKEN` gates the `/acme/admin/*` endpoints (nonce cleanup,
expired-order sweep, stuck-`processing` reclaim, order listing). A holder can
reconcile a stuck order to `ready`, the one action that can enable a
re-enroll — so the token is a high-value secret, treated like an EAB MAC key.

### Setting and ACL-ing the token

1. Generate a high-entropy token (≥256 bits). `python -c "import secrets;
   print(secrets.token_urlsafe(32))"` is sufficient.
2. Set `ACME_RA_ADMIN_TOKEN=<token>` in `acme-ra.env` (the locked-down env
   file, readable by the gMSA + Administrators only).
3. Do NOT put the token in `deploy/iis/web.config` (that file is
   checked-in-adjacent and carries only non-secret operator settings).
4. Restart the RA app pool so the token takes effect.
5. Distribute the token only to the operators who need to run
   `Register-MaintenanceTasks.ps1` or drive the admin endpoints — and no
   further.

### Rotating the admin token

1. Generate a new high-entropy token.
2. Update `ACME_RA_ADMIN_TOKEN` in `acme-ra.env`.
3. Restart the RA app pool.
4. Nothing else: the scheduled tasks read the token from the dotenv at run
   time, so there is nothing to re-register.
5. Confirm the old token is rejected (`GET /acme/admin/orders` with the old
   token → 401).

### Minimum strength (enforced at startup)

Since v1.10.0 (the 1.9 line was never released) the RA **refuses to start** on a weak credential: EAB MAC keys
must decode to at least 32 bytes and `ACME_RA_ADMIN_TOKEN` /
`ACME_RA_REVOCATION_CONFIRM_TOKEN` must be at least 32 characters. Everything
`python scripts/eab.py new` generates clears this. `allow_weak_credentials=true`
waives it and exists for lab and CI fixtures only — never set it in production.

The floor also closes a sharper hole: an EAB entry whose `mac_key` decoded to
zero bytes used to count as a *present* key, so anyone who knew the kid could
forge the binding with an empty HMAC key.

### The revocation-confirmation token (separate authority)

`ACME_RA_REVOCATION_CONFIRM_TOKEN` gates **only**
`POST /acme/admin/revocations/{serial}/confirm`, and the general admin token is
**not accepted** there. Confirming a revocation asserts something the RA cannot
see — that the CA really revoked the serial — so it is deliberately not the same
authority as nonce cleanup or order listing. While they shared a credential, any
admin-token holder could drop a still-valid certificate off the retry queue and
leave a success audit behind for a revocation that never happened.

If it is unset the confirm endpoint is **disabled** (401), which fails closed but
means the sync agent revokes at the CA and then cannot confirm — serials stay on
the pending list. Set it before promoting the revocation loop to `-Execute`.

Set it the same way as the admin token (own value, `acme-ra.env`, app-pool
restart), and pass it to the agent as `-ConfirmToken` (or `ACME_CONFIRM_TOKEN`).

**Registering the revocation-sync task least-privilege (dedicated host).** On a
separate revocation host, register **only** the sync task and give it **only**
the confirm token — the confirm token alone is sufficient authority for the whole
sync workflow (reading the pending list and confirming serials). Use
`-RevocationSyncOnly` so the general nonce/sweep tasks (which need the admin
token) are not registered there, and omit `-AdminToken` entirely:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -RevocationSyncOnly -ConfirmToken `
    -CaConfig 'CA01\WORK-DOMAIN-CA' -RequesterName "WORK-DOMAIN\gMSA-acme-ra$"
```

The generated task action then carries zero admin-token bytes, so a compromise
of the revocation host cannot reach order reclaim or nonce cleanup. The
`-ConfirmToken` FLAG declares which key the action loads from the dotenv at
run time; put `ACME_RA_REVOCATION_CONFIRM_TOKEN=<value>` in the host's
`acme-ra.env` (`-DotEnvPath`, ACL'd like the RA's own). Adding `-AdminToken`
(flag) is for a single-host deployment that has not split the credentials, and
for the general tasks on the RA host.

### Optional: independent CRL evidence for confirmations

By default a confirmation is recorded honestly as `verification:
"agent-asserted"` — the RA is writing down a claim it could not check. To make
it verifiable, point the RA at the CA's published CRL:

```ini
ACME_RA_REVOCATION_CONFIRM_CRL_URL=http://pki.WORK-DOMAIN.local/crl/WORK-DOMAIN-CA.crl
# Fail closed: refuse to confirm unless the CRL proves the serial is revoked.
ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE=true
# 626400 (7d 6h) is the application default and the measured value for the
# lab's weekly CA -- NOT a universal constant. It has to sit inside a band:
#
#   above  the maximum age your CDP actually SERVES, or it refuses healthy
#          evidence. Measured on the lab CA at 603654s (upper bound 605454s
#          at a 1800s sampling interval) over one complete publication cycle.
#   below  the CRL's published window (nextUpdate - thisUpdate), or it sits
#          behind the CRL's own expiry and can never fire first. Measured at
#          649200s on every sample.
#
# 626400 clears the floor by ~5h49m and the roof by ~6h20m. That band exists
# because this CA publishes with overlap; a CA with a different CRLPeriod or
# overlap has a different band, and possibly none.
#
# MEASURE YOUR OWN CA before changing this. Run scripts/sample_crl_age.py
# against your CDP across at least one full publication cycle; the served-age
# distribution is the only source for the floor. Do NOT reconstruct the window
# from the CRLOverlap* registry values, which do not decompose to the observed
# one, and do not derive the floor from the window -- that substitution is the
# error that cost this project four derivations (WI-052, UNFILED item 24).
ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS=626400
```

The CRL is signed by the CA and readable without privilege, so this is the one
check available to the RA that does not depend on the calling agent's honesty.
The RA verifies the CRL's signature against the issuing CA certificate from the
certificate's **own stored chain**, and refuses an expired CRL as evidence.
Confirmations then record `verification: "crl-verified"` with the CRL number.

These are three separate time bounds:

- **Publication cadence:** `CRLPeriod` is the expected interval between CRLs.
- **Overlap / validity:** `nextUpdate - thisUpdate` is the CRL's validity window;
  `nextUpdate` is a hard expiry, not a delay budget that can be extended here.
- **Publication-liveness ceiling:** `revocation_confirm_crl_max_age_seconds`
  bounds the age of a signed CRL the RA will accept as an alarm on a stalled
  publication path. It is not the replay control; the monotonic watermark below
  detects regressions in CRL sequence.

For this CA, the committed evidence measures `CRLPeriod` as 604800 seconds (1
week) and the `thisUpdate` → `nextUpdate` window as 649200 seconds (7d 12h
20m). **The floor for the age ceiling is neither of those — it is the maximum
age the CDP actually serves, and it was measured on 2026-09-05 at 603654s
(bounded above by 605454s).** The window is the attacker's replay reach: how
long a replayed document stays unexpired, and therefore the value a ceiling
must stay *below* to bind at all. The served age is what governs false
refusals. On a CA that publishes with overlap the two differ by exactly the
overlap (44400s here), which is why a usable band exists at all. Substituting
the window for the served age is the error that produced four wrong
derivations; `scripts/sample_crl_age.py` measures the right quantity.

### Deriving the ceiling (WI-052), with worked numbers

`A_sched_max` is the maximum age a still-current CRL reaches, on the RA's clock,
at its scheduled replacement. Earlier revisions of this runbook asked operators
to *observe* it over successive publication cycles and declined to suggest a
number. That was more conservative than necessary: `A_sched_max` follows from
the CA's own configuration, and the derivation can be checked against a single
published CRL.

ADCS stamps a CRL as:

```
thisUpdate = publish_time − ClockSkewMinutes
nextUpdate = publish_time + CRLPeriod + CRLOverlapPeriod + ClockSkewMinutes
```

so the validity window is `CRLPeriod + CRLOverlapPeriod + 2·ClockSkewMinutes`,
and the age of the current CRL when the next one is published is:

```
A_sched_max = CRLPeriod + ClockSkewMinutes + L + S
```

where `L` is scheduled-publication lateness and `S` is the worst CA→RA clock
skew. **Validate the model before trusting it**: compute the predicted validity
window and compare it with `nextUpdate − thisUpdate` on a real CRL. If they do
not match, the CA is not behaving as configured and the derivation is void —
fall back to observing cycles.

Worked example, measured on the lab CA (2026-08-24). Registry: `CRLPeriod =
1 Week`, `ClockSkewMinutes = 10`, `CRLOverlapUnits = 0` (so ADCS computes the
overlap, which lands on 12h).

| term | value |
|---|---|
| `CRLPeriod` | 604800s |
| `ClockSkewMinutes` | 600s, applied at **both** ends |
| computed overlap | 43200s |
| **predicted** window | 604800 + 43200 + 1200 = **649200s** |
| **measured** `nextUpdate − thisUpdate` | **649200s** — exact match |
| `A_sched_max` (on-time, zero skew) | 604800 + 600 = **605400s** |
| hard ceiling (`nextUpdate`) | **649200s** |
| **usable headroom** | **43800s ≈ 12h10m** |

`max_age_seconds` must sit strictly inside `(A_sched_max, 649200)`. The headroom
is the budget for `L + S` plus whatever replay margin you want:

| value | margin above measured served age | margin below hard expiry |
|---|---|---|
| 615600 (7d 3h) | 2h49m | 9h20m |
| **626400 (7d 6h) — the measured value, and the shipped default** | **5h49m** | **6h20m** |
| 637200 (7d 9h) | 8h49m | 3h20m |

All three rows sit inside the measured band `(605454, 649200)`. 626400 is
shipped because it splits the band almost evenly: the two failure modes it
trades between — refusing a healthy CRL and accepting a replayed one — have no
common unit, so there is no argument for weighting one side, and the midpoint is
the honest default. Move within the band deliberately if your CDP's served-age
distribution has a longer tail than the lab's.

> ## ✅ RESOLVED 2026-09-05 — measured, and the answer is **626400**
>
> *This supersedes the 2026-08-27 banner that superseded 626400. Five entries in
> this section's history argued about a number; the sixth measured it. The
> earlier text is not reproduced because it was wrong in a way that reads
> plausibly, which is exactly how it survived four rounds.*
>
> **What was wrong.** Every derivation took the ceiling's floor to be the
> published *window* — reasoning that a CRL stays current for its whole window,
> so the oldest still-valid CRL the RA can be served is one full window old.
> That is true of what an attacker may *replay*. It is not true of what an
> honest CDP *serves*: the CDP replaces the document at the publication
> interval, not at expiry. On a CA with overlap those differ by exactly the
> overlap, so the floor sits a whole overlap below where the derivations put
> it, and the band the derivations declared empty is 43,746 seconds wide.
>
> **The measurement.** `scripts/sample_crl_age.py` against the lab CDP every 30
> minutes from 2026-08-27 to 2026-09-05: 399 samples, zero failed fetches, one
> complete publication cycle (CRL 127 ageing from 55,446s to 603,654s, then 128
> arriving at age 626s).
>
> | quantity | value | how |
> |---|---|---|
> | maximum age served | **603654s** | last sample of CRL 127 |
> | upper bound on that | **605454s** | + one 1800s sampling interval |
> | published window | **649200s** | identical on all 399 samples |
> | usable band | **(605454, 649200)** | 43746s ≈ 12h9m wide |
> | CRL Number regressions | **0** | a strict watermark would have refused nothing |
>
> **Set `ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS=626400` on a CA with
> this cadence** — and measure your own before copying it. This is what one
> observation period supports for a 1-week `CRLPeriod` with ADCS's computed 12h
> overlap; it is not a property of CRLs in general.
>
> **Both previously published numbers were outside the band.** `649800` is above
> the window, so it never fires before `nextUpdate` and bounds nothing the
> expiry check does not already bound. `604800` — the previous application
> default — clears the *observed* maximum by 1146s but not its upper bound, so
> it could refuse a genuinely healthy CRL in the minutes before republication.
> `tests/test_crl_max_age_calibration.py` pins all of this, and proves the
> redundancy claim against the implementation rather than on paper.
>
> ### Methodological point, worth more than the number
>
> **Derive the roof from a published CRL and the floor from a sampler.** The
> `CRLOverlap*` registry values do not decompose to the observed window, so read
> `thisUpdate`/`nextUpdate` off a real CRL for the roof. No document at all
> carries the floor — the maximum age a CDP serves is a property of its
> behaviour over time, which is why four attempts to read it off a document
> failed and a sampler settled it in nine days.
>
> **And the ceiling is not the replay control regardless.** The monotonic
> watermark in the next section is, it needs no calibration, and it was proven
> live on 2026-09-05. Nothing security-critical ever hung on this number; what
> hung on it was whether operators would be told to configure something inert.


### Monotonic CRL evidence

*Added 2026-08-27 (UNFILED item 23), and proven against the real CA on
2026-09-05 with two genuine CRLs — the older one still unexpired and still
listing the serial, so the only thing separating them was the watermark. The
watermark is the replay control and needs no calibration; the age ceiling is a
separate, now-measured bound. Do not infer a universal relationship between a
CA's served-age floor and its published validity window.*

The RA records the newest CRL it has acted on for each issuing CA, and refuses
one that goes **backwards** from it —
`revocation-ca-confirmed` is denied with reason `crl-evidence-regressed`.

Why this is the right shape and the ceiling was not:

* it needs **no calibration**. RFC 5280 §5.2.3 already requires the CRL Number
  to increase per CA, so the property is the CA's to maintain rather than the
  operator's to derive. Four derivations of the ceiling produced two wrong
  numbers; there is no number here to get wrong;
* it defends the threat that is actually there. A stale CRL that *lacks* the
  serial already fails closed, so age never protected the "was it really
  revoked?" direction — `nextUpdate` and the signature do that. The only
  wrong-*accept* an old CRL can produce is a **hold→unhold replay**: a
  certificate revoked with reason 6 and later released with reason 8
  (`removeFromCRL`) is still listed as revoked on the older document. Narrow,
  real, and it carries the confirm token.

```
ACME_RA_REVOCATION_CONFIRM_CRL_REQUIRE_MONOTONIC=true    # default
```

**What it does not do, said plainly.** The first CRL seen for a CA becomes the
baseline whatever it is — trust on first use, which protects nothing on the
first confirmation after a deployment or a CA key rollover. A control that
quietly does nothing on first contact is worse than no control, so it is stated
here rather than left to be discovered.

**Operational behaviour to expect:**

| situation | what happens |
|---|---|
| CDP replicas at different vintages | the fetch is retried **once** before a regression is believed; a transient skew resolves itself |
| a CDP that persistently serves backwards | denied with `crl-evidence-regressed`, and that is a real fault worth an alarm |
| CA key rollover | new SPKI ⇒ new watermark, by construction — the watermark is keyed on the issuer DN **and** the CA certificate's SPKI |
| CA restored from backup (CRL Number resets) | confirmations wedge until an operator resets the watermark. **Deliberately manual**: an automatic reset on "the number went backwards" would hand the attacker the exact sequence that defeats the control |
| an estate with known-lagging replicas | set `...REQUIRE_MONOTONIC=false`. The verdict is still recorded in the audit trail (`crl_watermark_verdict`) and the watermark still advances, so you keep the measurement without the refusal |

**What the age ceiling is for.** A **binding freshness bound** on the CA's
publication pipeline, and the alarm that a CA has stopped publishing. Set it
above the maximum age the CDP actually serves and below the published window —
measure the first, read the second off a real CRL — and read a refusal as "the
CA's publication has stalled", not as evidence about a certificate. It is not
the replay control; the watermark above is, and it works whatever this number
is set to.

```bash
# Sample the CDP on a schedule. Needs nothing but reach: no RA, no store, no
# privilege. Run it from a cron entry or a scheduled task, anywhere.
python scripts/sample_crl_age.py \
    --url http://pki.example.local/crl/example-CA.crl \
    --out /var/lib/crl-samples.jsonl

# After two-plus publication cycles, what the data says:
python scripts/sample_crl_age.py --out /var/lib/crl-samples.jsonl --summarize
```

The summary prints the observed age distribution (which is what the ceiling is
compared against), the published window (which is the bound a ceiling has to sit
below to do anything at all), and any **CRL Number regressions** — each one a
document a strict watermark would have refused, which is how you find out
whether your CDP replicas are stable enough to enforce monotonicity before you
turn it on.

The log lives **outside** anything a lab teardown or a store restore touches, on
purpose: this project's own audit trail could not answer the age question
because every validation session restored the store that held the answer
(UNFILED item 22).

> **Before re-tightening the ceiling, read UNFILED item 24.** The floor above is
> derived from the published *window*, which is the age a replayed document
> stays unexpired — not the age an honest CDP serves. Those differ by exactly
> the CA's overlap, and a sampler has been running against the lab CA since
> 2026-08-27 to settle which one binds. Do not produce a fifth derivation on
> paper.

**626400 is the shipped default and the measured value for a CA on this cadence** — see the
refutation above before using it. The reasoning was that it splits the headroom
evenly, so neither a late publication nor a wider replay window is favoured.
Measured CA→RA clock skew on this estate is sub-second, so `S` is noise; `L` is
the only term worth watching.

Re-derive rather than copy the number if your CA's `CRLPeriod`,
`CRLOverlapPeriod` or `ClockSkewMinutes` differ — and re-check the predicted
window against a real CRL, which is the step that makes this a measurement
rather than an assumption.

The prior 691200-second (8-day) plumbing test is **not** a safe production
value for this CA: it exceeds the 649200-second validity window and would leave
the independent age ceiling non-binding before `nextUpdate`.

Any operational margin belongs between the measured `A_sched_max` and the hard
`nextUpdate` bound. If that gap is insufficient, change the CA's publication
schedule/validity policy or accept fail-closed confirmations; do not widen the
age ceiling past `nextUpdate`.

If publication misses `nextUpdate`, the CRL must fail closed; no extra
`max_age_seconds` margin can make an expired CRL acceptable. Fix the CA's
publication path or accept the pending confirmation rather than widening this
ceiling beyond the measured validity window.

Note the timing trade-off before setting `REQUIRE_CRL_EVIDENCE`: a serial is not
on the CRL until the CA next publishes one. On the default least-privilege path
the agent does not force a republish (it has no Manage-CA right), so a
confirmation can legitimately fail until the scheduled CRL publication catches
up. The serial simply stays pending and the next sync cycle confirms it.
The CRL-evidence path was exercised against a real ADCS CRL in the 2026-08-14
live re-proof: required evidence refused a serial before publication and
accepted it as `crl-verified` after publication. See
`docs/security-review-2026-08-13.md` and the validation log in
`docs/pre-pilot-checklist.md`.

The retrieval is bounded on both axes, because the CRL host is an
operator-configured third party on a path a scoped confirmation credential can
drive:

```ini
# Per-read bound (connect, and each socket read).
ACME_RA_REVOCATION_CONFIRM_CRL_TIMEOUT_SECONDS=10
# Wall-clock bound on the WHOLE retrieval. The per-read timeout above cannot
# stop a server that trickles one byte before each read deadline; this can.
# Must be >= the per-read timeout (validated at config load).
ACME_RA_REVOCATION_CONFIRM_CRL_TOTAL_TIMEOUT_SECONDS=30
# Size of the dedicated CRL-evidence thread pool. Deliberately NOT the shared
# pool that runs ADCS enrollment: a stalled CRL host may exhaust this one
# without touching the issuance path. Created lazily — an RA with no CRL URL
# configured never spawns these threads.
ACME_RA_REVOCATION_CONFIRM_CRL_MAX_WORKERS=2
# Admission ceiling on distinct retrievals in progress. MAX_WORKERS bounds what
# RUNS; the executor's work queue is unbounded and every waiting caller also
# pins a suspended request, so this is the bound that provides backpressure.
# Must be >= MAX_WORKERS (validated at config load).
ACME_RA_REVOCATION_CONFIRM_CRL_MAX_PENDING=32
```

**If the CRL URL is `https://`, the CRL host's own chain must be RFC 5280 clean.**
CRL retrieval verifies that TLS chain against the system trust store, and the
OpenSSL shipped with Python 3.13+ (the lab host runs 3.14) enforces checks the
3.12 build did not: an issuing CA whose certificate omits a Subject Key
Identifier or a `keyCertSign` Key Usage is refused with
`CERTIFICATE_VERIFY_FAILED`. A public CA meets this; a hand-rolled internal
one may not. The failure is a fetch error, so evidence is recorded as absent
and the confirmation fails closed rather than passing on an unverified CRL —
correct, but it looks like an unreachable CRL host. Prefer a plain `http://`
CDP: the CRL is signed by the CA and its signature is verified independently,
so TLS adds no evidentiary value here.

Concurrent confirmations for the **same certificate** share a single retrieval,
so a retry loop or a burst on the revocation host costs one CRL fetch rather
than one per request. Serials are canonicalized at route entry, so `A`, `0A` and
`00A` are one certificate for this purpose as well as for the store lookup.

Past the admission ceiling the endpoint responds **429 with `Retry-After`**
rather than queueing the work. That is not a statement about the certificate:
the RA was too busy to fetch the CRL, which is different from the CRL not
proving the revocation, and it is deliberately never recorded as absent
evidence. The serial stays on the pending list and the next sync sweep picks it
up. If you see these regularly, the CRL host is slow or the ceiling is too low
for your confirmation volume — raise `MAX_PENDING`, and check
`MAX_WORKERS`/`TOTAL_TIMEOUT_SECONDS` before assuming the ceiling is the
problem.

See `docs/security-review-2026-08-16-rescan.md` finding 4 and
`docs/security-review-2026-08-17.md` finding 3.

Request bodies on the token-gated admin routes are bounded too:

```ini
# The confirmation callback carries one boolean; this is generous for it. Both
# a declared Content-Length over the cap and a stream that exceeds it while
# arriving are refused (a chunked request declares no length, and a declared
# length is a claim by the sender, not a limit on it).
ACME_RA_MAX_ADMIN_BODY_SIZE_BYTES=4096
```

### The reclaim endpoint (double-issuance gate)

`POST /acme/admin/orders/{id}/reclaim-processing` (admin-token-gated)
reconciles an order wedged in `processing` after a crash mid-enrollment.

**Live enrollments are refused authoritatively.** The RA keeps an in-process
registry of orders with an enrollment in flight; if one exists for this order,
reclaim is refused (`-denied`, `reason=enrollment-in-flight`) regardless of how
long it has been processing. This is what makes reclaiming a genuinely in-flight
enrollment — and thus double-issuing — impossible in the single-process
deployment, rather than relying on an elapsed-time heuristic. A secondary age
floor (`reclaim_minimum_processing_age_seconds`, default 60s) still applies as
defence-in-depth.

The mark covers the **whole** in-flight interval, not just the running worker:
the `ready`→`processing` CAS, the wait for a threadpool slot, the ADCS call
sequence, and the completion that records the certificate. That matters because
a finalize queued behind a busy threadpool has already committed its order to
`processing` while doing no visible work, and the window between the CA issuing
and the RA recording the certificate looks identical to "nothing happened".

**A durable lease backs the registry.** Each entry into `processing` mints a
`processing_generation` on the order row, and the enrollment re-checks it against
the store immediately before submitting to ADCS. If the order was reclaimed (or
re-finalized) in the meantime, the stale enrollment abandons without calling the
CA and audits `finalize-enrollment-abandoned` with `reason=processing-lease-lapsed`.
**Seeing this event means a reclaim landed on a request that was still queued.**
It is safe — nothing was issued — but it should be rare; a run of them means the
threadpool is saturated and ordinary queueing is crossing the reclaim age floor.
Investigate enrollment latency and the CA's responsiveness, not the reclaim.

For a wedged order (no live worker) it has two branches:

- **Cert recorded, status flip missed** (crash window between
  `create_certificate` and the status flip): the endpoint CAS-closes the
  loop to `valid` (`admin-order-reclaimed`, `had_certificate=true`). Always
  allowed — a recorded cert is authoritative proof issuance happened. No
  re-enrollment, no operator judgment needed.
- **No cert recorded** (enrollment did not visibly complete): reverting to
  `ready` lets the client re-enroll, so the endpoint **refuses unless the
  operator passes `?ca_verified_no_issuance=true`**, asserting they have
  confirmed at the ADCS CA database that no cert was issued for the order's
  ReqID. Absence of a cert row does **not** prove non-issuance (a crash after
  the CA committed leaves exactly this state), and elapsed time proves nothing —
  so the assertion is now enforced by the server, not merely documented. Without
  it the attempt is refused (`-denied`, `reason=ca-verification-not-asserted`)
  and the order stays `processing`. The assertion is recorded on the success
  audit (`ca_verified_no_issuance`).

No-op, lost-race, in-flight, unverified, and not-found reclaim attempts are all
audited (`admin-order-reclaim-noop` / `-denied`) so a stolen admin token probing
order IDs is visible to SIEM.

## Monitoring and SLOs

### Stuck-processing orders (pilot condition)

Monitor time-in-`processing` p99 and alert when it exceeds a threshold (e.g.
5 minutes). The `processing` state is the crash window; a stuck order there
means a potential double-issuance risk if an operator reclaims without
checking the CA DB.

- `GET /acme/admin/orders?status=processing` (admin-token-gated) returns the
  minimal admin view (no SANs/cert URLs): id, account_id, status,
  processing_started_at, created_at, expires.
- Alert on `processing_started_at` age: any order in `processing` for more
  than N minutes should page the on-call (the operator decides N based on
  the enrollment leg's expected latency — typically a few minutes).

### Nonce-table growth

The probabilistic 1% cleanup on `create_nonce` is a safety net. The primary
control is the `DELETE /acme/admin/nonces` cron (see Scheduled maintenance
tasks above). Monitor:
- The `admin-nonce-cleanup` audit event's `details.deleted` count (a sudden
  drop to 0 while traffic is steady may indicate the cron stopped firing).
- Direct count: `SELECT COUNT(*) FROM nonces` (the table is indexed on
  `created_at`; a steady-state count above ~10k suggests the cron is
  misfiring or traffic spiked).

### SIEM delivery

- `audit_offbox_required=true` accepts authenticated HTTPS HEC by default, and
  that is the posture to deploy: it proves delivery *and* authenticates the
  collector.
- If your SIEM is reached through a **syslog relay**, set
  `audit_offbox_allow_unauthenticated_syslog=true` alongside
  `siem_syslog_proto=tcp`. The requirement is then satisfied by plain TCP
  syslog, which proves a live transport but does **not** authenticate the
  collector and does **not** protect events in transit — anyone on the path can
  read the trail or feed the SIEM forged issuance events. The RA logs a
  `UNAUTHENTICATED OFF-BOX AUDIT` warning on every start and stamps
  `offbox_transport=syslog-unauthenticated` on the startup probe event, so the
  posture is legible to whoever reads the trail rather than only to whoever
  wrote the config. This exists so that an estate without HEC is not pushed
  into turning `audit_offbox_required` off altogether, which is strictly worse.
- **UDP can never satisfy the requirement**, acknowledged or not: a datagram
  socket accepts bytes with nothing listening, so the delivery probe cannot
  distinguish a working collector from none and "required" would assert
  nothing.
- The SIEM startup probe logs **ERROR** on init if the JSONL sink is
  unwritable or the HEC/syslog config is invalid; the sink is set to
  `enabled=False` and issuance continues (fail-open applies to *emission*,
  not to the local audit record).
- **Runtime SIEM failures log at WARNING, not ERROR.** Therefore: the
  production monitoring stack MUST alert on the RA logger at WARNING+ (not
  ERROR-only) — this is a pilot condition, not a runbook footnote.
- Alert on any `certificate-issued` event with `outcome != success` (there
  is no such event today — a failure surfaces as `finalize-enrollment-denied`
  or `finalize-enrollment-race`; alert on those categories at ERROR+).

### Events that mean someone is using a credential you cut off

Added 2026-08-11. These fire *after* a valid signature, so they mean the holder
of a real key is still trying — treat them as security events, not noise:

- **`account-request-denied`** with `details.reason = eab-kid-not-allowlisted` —
  an account whose EAB credential you removed is still making requests. Expect a
  short tail after a planned rotation as the client is reconfigured; a sustained
  or *unexpected* stream means a key you revoked is still in someone's hands.
- **`account-request-denied`** with `details.reason = account-not-valid` —
  requests from a deactivated account. Same reading.
- **`account-deactivated`** — a client disabled its own account. Expected during
  incident response; unexpected otherwise, and worth correlating with who holds
  that account key.

Alert on the first two at WARNING+ and route them to the same place as
`account-creation-denied` (EAB kid probing) — together they are the picture of
someone attempting to use credentials they should not have.

### Request / error rate SLOs

- Monitor the ACME endpoint request rate and error rate (4xx/5xx) at the
  reverse proxy. A spike in 4xx (especially `badNonce`, `malformed`) may
  indicate a misbehaving client or a probe; a spike in 5xx indicates an RA
  or CA problem.
- Alert on any 5xx from the ACME surface (the RA should never 500 in normal
  operation — `server_internal` is a bug or a CA-side failure).

## Retention and archival

### audit_log table

The `audit_log` table is the authoritative local audit (the SIEM JSONL is a
secondary emission).

**Attacker-driven growth is bounded; ordinary growth is not.** Since the
2026-08-15 audit work,
repeated *pre-authentication denials* — the one audit path an unauthenticated
peer can drive, by failing EAB validation on `newAccount` over and over — no
longer write a row each. Within
`ACME_RA_AUDIT_DENIAL_COALESCE_WINDOW_SECONDS` (default 60), repeats of the
same denial reason update the row that is already on disk, bumping an exact
`denial_count` and recording how many distinct `kid` values were offered. Set
the window to 0 to go back to one row per denial.

No rows are pruned: the counter is written to a
committed row on every increment, so even a crash mid-window keeps the tally.
What this bounds is *rows per unit time* (at most one per reason per window),
not the total, so the retention guidance below still applies to normal
operation:

- **Keep hot** for the incident-review window (e.g. 90 days) for fast query.
- **Archive cold** after the hot window only through an independently managed,
  write-once / append-only process; the RA does not delete those rows from its
  live SQLite store.
- **Never delete** `certificate-issued` / `certificate-revoked` events until
  the corresponding certificates have expired AND been removed from the CRL
  (the audit is the matching half of the revocation trail; see the
  revocation runbook below).

#### Built-in retention (`audit_retention_days`)

The RA records and validates this policy, but the current server refuses to
start when `audit_prune_enabled=true`: its SIEM path has no per-row delivery
acknowledgement, so a health probe cannot prove that each row selected for
deletion reached off-box storage. Setting `audit_retention_days` still enforces
the startup floor and keeps footprint reporting meaningful; it does not enable
deletion.

**The floor.** `audit_retention_days` is validated at startup against the
longest certificate validity this RA has *actually issued* (recorded per row in
`certificates.not_before` / `not_after`) plus a fixed 14-day grace. Configure it
below that and **startup is refused**, not warned: retaining for less than a
certificate's own lifetime means a certificate can be valid and servable while
the record of how it was issued has been deleted. The floor is derived from
observed issuance rather than from the template, because ADCS can issue shorter
than the template asks — the template is a request, the certificate is the fact.
The grace term is a constant rather than a setting, so it cannot be tuned to
zero, and so it does not collapse as certificate lifetimes shrink.

**The gates.** Deletion requires *all* of:

| Gate | Why |
|---|---|
| `audit_retention_days` ≥ floor | see above |
| `audit_prune_enabled` | required by the library-level deletion decision; the current server refuses `true` at startup because per-row off-box delivery is not acknowledged |
| `audit_offbox_required` | with no off-box copy the local table is the only evidence, so nothing is deleted from it |
| A delivery probe that succeeds **at sweep time** | a sink that worked at startup and has since died is the exact state where deleting is unrecoverable |

The current server does not wire a pruning sweep. Any library-level evaluation
that is used by tooling remains fail-closed and deletes nothing when a gate is
missing; local-only deployments therefore rely on footprint reporting and
JSONL rotation.

The sweep audits itself (`audit-retention-swept`, carrying the cutoff, the row
count and the floor). A retention pass that leaves no trace is indistinguishable
from an attacker's cleanup.

Deleting is still the last resort rather than the first tool: `audit_bounds`
caps each row's size, `audit_coalesce` caps rows-per-window for replayable
denials, and the footprint report tells you whether any of it matters. Measured
growth is a few GiB per 180 days even under sustained flooding.

Attacker-supplied fields inside `details` (notably the offered EAB `kid`) are
truncated to 256 characters with a SHA-256 of the full value appended, and the
whole `details` blob is capped at ~4 KB. Two rows for the same oversized value
still compare equal, so a row can still be matched against a captured request.

### certificates table

The `certificates` table holds every issued cert PEM + metadata. It is
needed for revocation lookups (serial → cert) and audit. Retention guidance:

- **Keep** all rows for at least the certificate validity period + the CRL
  overlap (so revoked certs remain queryable until they fall off the CRL).
- **Archive** expired-and-not-revoked cert rows to cold storage after the
  validity period + overlap, then delete from the live SQLite. Keep
  revoked cert rows until the revocation is no longer on the CRL.
- The `serial_number` index supports fast revocation lookup; the table is
  not on the hot path (only `revoke_cert` and the POST-as-GET
  `/acme/cert/{id}` read it).

### SIEM JSONL sink

- The JSONL sink (`<db>.siem.jsonl`, next to the DB) is the secondary
  emission. Back it up with the DB (see Backup and restore below).
- **The RA rotates it.** `audit_jsonl_max_mib` (default 256) rolls the mirror to
  `<name>.1`, `.2`, … and `audit_jsonl_keep` (default 4) bounds how many are
  retained; set the size to 0 for the previous append-forever behaviour. This is
  independent of `audit_retention_days` on purpose — the table's retention is
  gated on off-box audit, whereas a file that grows without limit is a capacity
  fault on *every* deployment, and the mirror is the larger half of a default
  install's local footprint. The SIEM ingest should be the authoritative copy;
  the local JSONL is the fail-open buffer.
- Rotated files count toward the startup footprint report, so the measured
  number does not drop simply because the mirror rolled.
- Coalesced denials reach this sink once per window, not once per request:
  the SIEM sees the window's opening event, and the *next* window's event
  carries the closed one's final tally in `previous_window`. For an exact
  live count of an in-progress flood, read `denial_count` on the `audit_log`
  row — SQLite is authoritative there, and is updated on every attempt.

## Revocation runbook

CA-side revocation is **out-of-band, operator-run** (WI-010, threat-model
§4.E). The RA's `revokeCert` endpoint records the revocation in the RA store
only — it does **not** write the CA CRL. The operator closes the loop by
running `scripts/Revoke-Cert.ps1`.

### The two halves of the revocation trail

1. **RA audit event** (`certificate-revoked`, `outcome=success`): recorded by
   the RA's `revokeCert` endpoint. The `details` dict honestly records:
   - `revocation_scope`: `"ra-store-only"` (the RA store was flipped; the CA
     CRL was NOT written).
   - `ca_crl_updated`: `"false"` (the audit log never implies the CA CRL was
     written when it was not).
   - `serial`: the cert's hex serial (what `Revoke-Cert.ps1` consumes).
   - `req_id`: the ADCS ReqID if the enrollment leg recorded it (the
     preferred identifier for `Revoke-Cert.ps1`).
   - `reason`: the RFC 8555 reason code (0-6, 9-10; reason 7 is rejected as
     "unused" in RFC 5280, and reason 8 (removeFromCRL) is rejected because it
     un-revokes rather than revokes —
     see below).
2. **CA-DB operator record**: `scripts/Revoke-Cert.ps1` (run by a CA
   officer, NOT the gMSA) performs `certutil -revoke` against the CA and
   republishes the CRL. The CA database records the operator identity. This
   is the matching out-of-band half.

Keep both records together in incident review.

### Quarantined certificates (mis-issuance, not a client request)

A third kind of entry can appear on the pending-revocation list, with
`status: "quarantined"` rather than `"revoked"`.

The RA runs three verifiers on the certificate ADCS returns — SAN scope, EKU
(serverAuth-only), and CA-capability. By the time they run **the CA has already
issued**: the certificate has a serial, is in the CA database, and is trusted
domain-wide. When one of them rejects, the RA refuses to serve the certificate
(finalize returns 500, the order goes `invalid`) — but the certificate is still
live at the CA.

Before the 1.9 line the RA recorded *nothing* in this case, not even the serial, so
that certificate was invisible to this runbook. It is now recorded as a
`quarantined` certificate row and queued for CA-side revocation through the
**same** pull-agent loop as any other pending serial. No separate procedure:
the agent revokes it, confirms it, and it drops off the list.

Treat a quarantined entry as an incident, not routine traffic. It means the
ADCS template issued outside the policy the RA enforces, which is the condition
the serverAuth-only blast-radius bound depends on. Check:

* the audit event (`finalize-issued-cert-san-mismatch`,
  `finalize-issued-cert-eku-mismatch`, or `finalize-issued-cert-ca-capability`)
  — its `details.violations` names exactly what was wrong, and `details.serial`
  and `details.req_id` identify the certificate at the CA;
* the `ACME-ServerAuth` template's current configuration — something changed it,
  or the RA is pointed at the wrong template;
* whether any earlier certificate was issued under the same misconfiguration
  and **was** honoured (the verifiers are the only thing standing between a
  template change and a clientAuth-capable certificate reaching a client).

### Transport orphans: two classes, two different actions

A **transport orphan** is a certificate the CA issued and the RA could not
finish collecting. There are two shapes and they need different things from you;
`GET /acme/admin/revocations/pending` now reports them separately rather than
leaving both to be reconstructed from the audit trail.

**1. The leaf is in hand, the chain is not** — the chain fetch or the
chain-binds-to-leaf check failed. The certificate is stored `quarantined` with
its serial and ReqID and it goes off the CA through the ordinary pull-agent
loop. What used to make it a dead end is that CRL evidence verifies the CRL's
signature against the issuing CA certificate taken from **the certificate's own
stored chain**, and this row has none — so with
`ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE=true` its confirmation was
refused for ever, for a certificate that is live at the CA.

The RA now **recovers the issuer material** on the confirm path, from chains it
already holds: every successful issuance stored the chain the CA returned over
the same authenticated enrollment leg, so the material has the same provenance
as the orphan itself. The candidate that actually **signed** the leaf is chosen
by signature (`verify_directly_issued_by`), never by subject name — an ADCS CA
key renewal keeps the DN and changes the key, so a name match picks the wrong
generation half the time. Recovery runs on the next confirmation attempt for that serial and needs no
new configuration — though it is reached only where
`ACME_RA_REVOCATION_CONFIRM_CRL_URL` is set, since a deployment that gathers no
CRL evidence has nothing for it to unblock. And:

* it repairs the **input** and decides nothing. Signature, freshness and
  monotonicity all still have to pass on their own terms afterwards;
* it never overwrites a chain the CA actually returned (compare-and-set on an
  empty chain), and it writes the chain and its provenance in one transaction —
  `revocation-issuer-evidence-recovered` names the fingerprints, the subjects
  and which stored certificate supplied each one;
* it leaves the certificate `quarantined`. Quarantine is a statement about the
  certificate; pending-revocation is a statement about the CA.

`ACME_RA_ADCS_CA_BUNDLE` is **not** used for this and must never be. It is TLS
trust for the `/certsrv/` leg; reusing it as an issuing-CA pin would quietly
turn "trust this for transport" into "trust this to attest issuance".

If nothing in the store signed the leaf — a cold store, or a CA whose chain the
RA has never successfully collected — the entry is reported as blocked rather
than retried in silence:

```json
{ "serial": "...", "status": "quarantined",
  "issuer_evidence": "missing",
  "blocked_reason": "issuer-evidence-missing",
  "recovery_action": "..." }
```

and the denial carries `reason_code: "issuer-evidence-missing"`. That reason
code is the one denial on this path that **cannot** be resolved by retrying;
every other one ("CDP unreachable", "serial not listed", "regressed") means
"not yet". It clears itself as soon as the store holds any complete chain from
that CA; until then, reconcile the certificate at the CA by ReqID.

**2. Only the ReqID is known** — the leaf fetch itself failed, so there are no
certificate bytes and **no store row at all**. Nothing automated can revoke it:
the sync agent works from serials and there is no serial. These appear under
their own key:

```json
{ "leafless_incidents": [
    { "req_id": "812", "order_id": "...", "observed_at": "...",
      "reason": "...", "recovery_action": "revoke it by ReqID at the CA by hand" }
  ],
  "leafless_incidents_truncated": false }
```

They are reconstructed from the audit trail, which is the only place they exist,
so `leafless_incidents_truncated` says whether the scan window was exhausted —
an empty list that means "none" and one that means "none *in the window*" are
different claims. They also **never drain**: there is no acknowledgement state,
so an incident stays visible for as long as its audit row does. That is
deliberate. A record whose only resolution is a person going to the CA must not
disappear because nothing automated can close it. Polling this view writes no
audit rows, so a permanent incident does not grow the audit table.

### Reason 7 is rejected

RFC 5280 reason 7 ("unused") is rejected by the RA's `revokeCert` route AND
by `scripts/Revoke-Cert.ps1` (because `certutil` rejects it). The valid set
is `{0,1,2,3,4,5,6,8,9,10}`. This prevents a silent break in the
out-of-band revocation loop: an accepted reason 7 would cause
`Revoke-Cert.ps1` to fail on the recorded reason.

### Steps to revoke a cert

1. The ACME client (or an operator driving `revokeCert`) revokes the cert
   via the RA. The RA records `revocation_scope=ra-store-only`,
   `ca_crl_updated=false`, and the response carries an
   `X-Acme-Ra-Out-Of-Band-Revocation` response **header** naming the runbook
   and the serial/ReqID. (It was a JSON body until 2026-08-24; that broke real
   ACME clients, which reported successful revocations as failed.)
2. A CA officer runs `scripts/Revoke-Cert.ps1` with the serial or ReqID:

   ```powershell
   powershell -File .\scripts\Revoke-Cert.ps1 `
       -CaConfig 'CA01\WORK-DOMAIN-CA' -Serial '1A2B3C' -Reason 1
   ```

   (Run as a CA officer, NOT the gMSA — the gMSA holds no CA-officer
   rights, by design.)
3. **Verify the CRL republished.** Invoked as above (no `-SkipPublishCrl`),
   `Revoke-Cert.ps1` runs `certutil -CRL republish` and prints the outcome.
   Confirm the publication succeeded before considering the revocation
   complete — the RA audit cannot see the CA side.

   **On the `-SkipPublishCrl` path the certificate is NOT yet contained.**
   That is the default for the batch agent (`Sync-Revocations.ps1`), because a
   least-privilege officer holds no Manage-CA right and cannot republish. The
   CA database records the revocation, but no published CRL lists the serial,
   so relying parties keep accepting the certificate until the next scheduled
   publication. The script's completion text says so explicitly on that
   branch — read it rather than assuming the manual-path wording.
4. Update the incident record. Note the out-of-band step is done, and record
   **which** state was reached: CRL republished (contained now), or CA database
   updated with publication pending (contained at the next scheduled CRL). Do
   not close containment on the second without waiting for that publication and
   verifying the serial appears on the CRL.

### What the RA cannot see

The RA's audit log records `ca_crl_updated=false` until the operator runs
`Revoke-Cert.ps1`. The RA has no way to know whether the CRL was actually
republished — the operator must verify this on the CA side. The RA's
POST-as-GET `/acme/cert/{id}` returns 410 Gone for revoked certs (RA-store
level); clients that check the CA's CRL will see the revocation only after
`Revoke-Cert.ps1` runs.

### Revocation reconciliation (WI-017)

Because revocation is out-of-band, the RA store and the CA database can
silently diverge: an operator may call `revokeCert` (RA store flipped) but
forget the out-of-band `Revoke-Cert.ps1` step (CA CRL not written), or the
CA may be revoked directly without the RA knowing. Run the reconciliation
tool periodically (e.g. daily, or after each revocation) to catch drift:

```powershell
powershell -File .\scripts\Reconcile-Revocation.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -DbPath 'C:\acme-adcs-ra\acme_ra.db'
```

Or run the Python reconciler directly against a pre-exported CA-DB dump:

```bash
python scripts/reconcile_revocation.py --db acme_ra.db --ca-export ca_dump.txt
```

The tool classifies each certificate into three buckets:

- **in-sync** — both RA and CA agree (both revoked or both active).
- **revoked-in-RA-but-active-at-CA** — the dangerous one: the operator
  called `revokeCert` but the out-of-band CA step was never done. The cert
  is revoked in the RA (GET → 410) but still valid on the CA's CRL. Run
  `Revoke-Cert.ps1` immediately.
- **revoked-at-CA-but-valid-in-RA** — the CA revoked a cert the RA still
  shows valid. Investigate whether the cert was revoked directly at the CA
  without going through the RA.

The tool is **read-only**: it never revokes, reactivates, or writes to
either store. Exit code: `0` = all in-sync, `1` = drift found, `2` = error.
Use `--json` for machine-readable output (e.g. for SIEM ingestion).

### Automated revocation (WI-022/023/024/025)

The out-of-band revocation loop (above) is **automated** in v1.5, closing the
functional gap without granting the enrollment gMSA any CA-officer rights.

> **Deploying the operator scripts:** copy the **entire `scripts/` directory,
> including `scripts/lib/`** — do not cherry-pick individual `.ps1` files.
> `Set-OfficerRights.ps1` and `Register-MaintenanceTasks.ps1` dot-source
> `scripts/lib/*.ps1` at runtime (the shared byte/SD and task-action builders,
> also exercised by the Pester suite); without `scripts/lib/` alongside them they
> fail at load with a "cannot find lib/..." error.
>
> **Copy it somewhere administrator-only, and not `C:\Temp`.** The installer
> does not place this tree for you, so wherever you put it is where a scheduled
> task will execute privileged code from every interval, forever. Any directory
> a non-administrator can write to — or any writable directory *above* it — lets
> that user replace `Sync-Revocations.ps1` between runs and have the gMSA run it.
> Measured on the lab host 2026-08-17: `C:\Temp\ra-scripts` inherited
> `BUILTIN\Users:(I)(CI)(AD)` and `(I)(CI)(WD)` from `C:\Temp`. A subdirectory of
> `%ProgramFiles%` is the right shape — it is what the installer uses for the
> code root, and for the same reason.
>
> `Register-MaintenanceTasks.ps1` now **refuses** to register the revocation-sync
> task from a tree that fails this check, naming the offending object and the
> principal that can write it. It checks the whole ancestor chain *and* every
> file beneath the tree, because the action dot-sources `lib\` siblings at run
> time. `-AllowUntrustedScriptPath` downgrades the refusal to a warning for lab
> reproduction; do not use it for a pilot or production registration.

The loop:

1. **RA `revokeCert`** records the revocation in the RA store
   (`revocation_scope=ra-store-only`, `ca_crl_updated=false`) — unchanged.
2. **Pull agent** (`scripts/Sync-Revocations.ps1`, WI-024) runs as a
   scheduled task on a **utility host** (not the CA) under a dedicated
   `gMSA-acme-revoker$`. Each cycle it `GET`s the RA's pending set
   (`GET /acme/admin/revocations/pending`, WI-023 — admin-token-gated),
   then for each serial calls `Revoke-Cert.ps1` (which self-checks the
   requester, WI-022) against the CA via remote-capable
   `certutil -revoke -config` (no Kerberos double-hop).
3. **Confirm callback**: on success the agent `POST`s to
   `/acme/admin/revocations/<serial>/confirm` so the RA audit flips
   `ca_crl_updated=true` and the serial drops out of the pending set
   (idempotent — the agent is safe to run repeatedly).

The authority to revoke lives **on the CA side**, under a separate
template-bounded principal (`gMSA-acme-revoker$`), never on the RA host.
The enrollment gMSA holds no CA-officer rights — the cardinal invariant
holds (threat-model §E).

#### Two hard provisioning constraints for `gMSA-acme-revoker$`

Both were proven load-bearing in the Plan-004 live spike; skipping either
silently defeats or breaks the restriction:

1. **NOT a member of any broader certificate-manager group.** Officer
   rights are evaluated across the caller's *entire* token (union
   semantics). A restricted officer that is *also* a member of an
   unrestricted certificate-manager group can revoke anything — the
   restriction is silently defeated. Provision the revoker as a plain
   domain principal with *only* its `ManageCertificates` grant and the
   `OfficerRights` restriction; do not nest it in any broader role group.
2. **Member of `Certificate Service DCOM Access`.** Without it the
   revoke fails `0x8007000d ERROR_INVALID_DATA` — a visible failure, not
   a silent bypass, but the loop will not complete. Add the gMSA to the
   `Certificate Service DCOM Access` built-in group on the CA.

#### Provisioning the officer restriction

`scripts/Set-OfficerRights.ps1` (WI-025) productionizes the Plan-004
builder — it writes the CA's `OfficerRights` registry value (a
self-relative security descriptor with one callback ACE per officer) that
scopes the revoker to `ACME-ServerAuth` only. Run **on the CA host**:

```powershell
# 1. Grant the revoker ManageCertificates on the CA Security descriptor
#    (use certsrv.msc or PSPKI; this is the coarse role grant, distinct
#    from the template-scoped OfficerRights below):
Add-CAAccessControlEntry -User "WORK-DOMAIN\gMSA-acme-revoker$" `
    -AccessType Allow -AccessMask ManageCertificates

# 2. Add the revoker to Certificate Service DCOM Access (constraint 2):
net localgroup "Certificate Service DCOM Access" "WORK-DOMAIN\gMSA-acme-revoker$" /add

# 3. Scope the revoker to the ACME-ServerAuth template only (constraint 1
#    is enforced by this restriction; confirm the gMSA is in no broader
#    cert-manager group before proceeding):
powershell -ExecutionPolicy Bypass -File .\scripts\Set-OfficerRights.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -OfficerSid 'S-1-5-21-<revoker-gMSA-sid>' `
    -TemplateOid '<ACME-ServerAuth-template-OID>'

# 4. Verify by readback:
powershell -File .\scripts\Get-OfficerRights.ps1 -CaConfig 'CA01\WORK-DOMAIN-CA'
```

`Set-OfficerRights.ps1` restarts `certsvc` (required for the change to
take effect) and verifies the value by readback. To remove the restriction
later: re-run with `-Remove` (if it was the last ACE, the `OfficerRights`
value is deleted and the CA reverts to unrestricted — logged visibly).

The GUI alternative (`certsrv.msc` → Certificate Managers tab) is correct
by construction and is the reference path; the script reproduces the same
byte-level ACE the GUI produces (proven in Plan 004).

#### Scheduling the agent

Register `Sync-Revocations.ps1` as a Windows Scheduled Task on the utility
host, running as `gMSA-acme-revoker$`. Use the registration script, whose
task action loads the confirm token from an ACL'd dotenv at run time — no
credential ever lands in the task definition or on a command line:

```powershell
# 1. On the utility host, write the confirm token to a dotenv (this host needs
#    ONLY this key -- do not copy the RA's whole env file):
#    C:\ProgramData\acme-adcs-ra\acme-ra.env containing
#        ACME_RA_REVOCATION_CONFIRM_TOKEN=<confirm-token>
#    then ACL it: icacls <file> /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" "WORK-DOMAIN\gMSA-acme-revoker$:R"
# 2. Register only the sync task, confirm-token only:
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://ra.WORK-DOMAIN.local" `
    -RevocationSyncOnly -ConfirmToken `
    -DotEnvPath "C:\ProgramData\acme-adcs-ra\acme-ra.env" `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -TaskUser "WORK-DOMAIN\gMSA-acme-revoker$" `
    -IntervalMinutes 5 -Execute
```

Rotate the token by editing the dotenv — the action re-reads it on every run,
so there is nothing to re-register. Tune the interval to your latency
requirement (default 5 minutes shown; the RA audit records `ca_crl_updated`
lag so you can measure the actual cadence).

`-ConfirmToken` (as a flag) declares which credential the action loads from
the dotenv; without it every confirm returns 401 and serials never leave the
pending list, and the registration warns. The load happens into
`ACME_CONFIRM_TOKEN` inside the task, so the value never appears on the
script's process command line.

**`-RaBaseUrl` must be https.** Since v1.10.0 both `Sync-Revocations.ps1` and
`Register-MaintenanceTasks.ps1` validate it before attaching any token — https
only, no embedded credentials, no query, fragment, or path. A scheduled task
bakes the URL in, so a cleartext typo would have disclosed the maintenance
token on every run with nothing in the output to show it. A loopback-only lab
over http needs the explicit `-AllowInsecureUrl`.

#### Dry-run → execute promotion

`Sync-Revocations.ps1` is **dry-run by default** (fail-visible). Without
`-Execute` it fetches the pending set and prints what it would do, making
no change. Promotion path:

1. Deploy the script and the scheduled task **without** `-Execute`
   (report-only). Confirm the dry-run output shows the expected pending
   serials and the correct `Revoke-Cert.ps1` invocation.
2. Review the first few cycles' dry-run logs against
   `Reconcile-Revocation.ps1` (the `revoked_in_ra_active_at_ca` bucket
   should match the dry-run pending set).
3. Arm the task by re-registering with `-Execute`. The first cycle after
   arming should revoke the pending serials and confirm them back to the RA
   (`ca_crl_updated=true` in the audit).

#### Monitoring

Alert on:

- **Agent exit codes** (the scheduled task's last result):
  - `0` = success (all pending revoked, or dry-run completed, or nothing
    pending).
  - `1` = RA unreachable — the agent could not fetch the pending set.
    Investigate network / RA health.
  - `2` = partial failure — one or more serials failed to revoke **or to
    confirm**. The per-serial log lines name the failing serial and the
    `Revoke-Cert.ps1` exit code; investigate (common causes: requester mismatch
    = exit 5 = the serial was not issued by the RA's gMSA; certutil error =
    CA-side issue).
- **`already-revoked-at-CA` in the batch summary** is *not* an error. It counts
  serials the CA had already revoked, whose RA confirmation was retried — the
  self-healing path for a confirmation callback that failed on an earlier run
  (`Revoke-Cert.ps1` exit 6). A steady nonzero count with no accompanying
  `confirm-failed` means the loop is repairing itself as designed. A count that
  keeps growing alongside `confirm-failed` means the callback is persistently
  failing: check RA reachability and the confirm token, not the CA.
- **RA audit events**: `certificate-revoked` with
  `ca_crl_updated=false` lingering longer than the agent interval × 2
  means the loop is stuck (the agent is not closing the confirm callback).
- **`admin-revocation-confirm-deferred`** means the RA shed a confirmation at
  its CRL-evidence admission ceiling (429). Occasional entries under burst are
  expected and self-correcting — the serial stays pending. Sustained entries mean
  the CRL host is slow or the ceiling is too low; see the CRL-evidence settings
  above.
- **The `revoked_in_ra_active_at_ca` reconciliation bucket** (run
  `Reconcile-Revocation.ps1` periodically) — if it grows, the agent is
  not keeping up or is failing silently. This is the independent
  cross-check (it reads the CA DB directly, not the agent's self-report).

#### Deployment variant: single-identity (enrollment gMSA as its own revoker)

**WI-033 / WI-034.** An opt-in variant in which the **same** gMSA used for
enrollment is also granted the template-scoped OfficerRights and runs the
revocation pull agent on the RA host in `-LocalMode`. Choose this only when
the RA runs on a single host, the operator accepts the compromise-correlation
risk, and operational simplicity outweighs the independence guarantee. The
two-identity design (`gMSA-acme-revoker$` on a utility host) remains the
**recommended default**; see threat-model §E for the full trade-off analysis.

**The explicit trade-off.** One credential compromise grants both issue and
revoke capability, enabling a mint-and-swap attack that the two-identity
design prevents. The template boundary and requester boundary are preserved;
compromise independence is not. Full analysis: threat-model §E.

##### Provisioning the enrollment gMSA as its own revoker

Apply the same steps as for the dedicated revoker, but target
`WORK-DOMAIN\gMSA-acme-ra$` instead of `WORK-DOMAIN\gMSA-acme-revoker$`:

```powershell
# 1. Grant the enrollment gMSA ManageCertificates on the CA Security descriptor
#    (the coarse role grant; the template-scoped OfficerRights below is the
#    actual restriction):
Add-CAAccessControlEntry -User "WORK-DOMAIN\gMSA-acme-ra$" `
    -AccessType Allow -AccessMask ManageCertificates

# 2. Add the enrollment gMSA to Certificate Service DCOM Access (constraint 2):
net localgroup "Certificate Service DCOM Access" "WORK-DOMAIN\gMSA-acme-ra$" /add

# 3. Scope the enrollment gMSA to the ACME-ServerAuth template only
#    (constraint 1 is enforced by this restriction; confirm the gMSA is in no
#    broader cert-manager group before proceeding):
powershell -ExecutionPolicy Bypass -File .\scripts\Set-OfficerRights.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -OfficerSid 'S-1-5-21-<enrollment-gMSA-sid>' `
    -TemplateOid '<ACME-ServerAuth-template-OID>'

# 4. Verify by readback:
powershell -File .\scripts\Get-OfficerRights.ps1 -CaConfig 'CA01\WORK-DOMAIN-CA'
```

**The two hard provisioning constraints still apply** (union semantics; DCOM
access) — same as the two-identity design; see `### Two hard provisioning
constraints for gMSA-acme-revoker$` above.

##### Scheduling the agent on the RA host

Use `Register-MaintenanceTasks.ps1` to register the revocation sync task
alongside the nonce-sweep and expired-order-sweep tasks. The task runs as the
enrollment gMSA on the RA host and passes `-LocalMode` to
`Sync-Revocations.ps1`. `-LocalMode` does **not** change how revocation
happens — `Sync-Revocations.ps1` invokes `Revoke-Cert.ps1` (and
`certutil -revoke -config <CaConfig>`) identically in both topologies; the CA
is always reached over RPC/DCOM per `-CaConfig`, whether the agent sits on a
utility host or on the RA host. The flag is a deployment-intent signal: it
records that the agent is running under the enrollment gMSA (which is also the
revoker) and adjusts the run banner accordingly. Register in dry-run mode
first (report-only), then re-register without `-DryRun` to arm it:

```powershell
# Step 1: register in dry-run mode (report-only — no revocations applied):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken -ConfirmToken `
    -IntervalMinutes 5 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
    -RegisterRevocationSync `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -RequesterName "WORK-DOMAIN\gMSA-acme-ra$" `
    -LocalMode -DryRun

# Step 2: after dry-run review, re-register without -DryRun to arm the task:
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken -ConfirmToken `
    -IntervalMinutes 5 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
    -RegisterRevocationSync `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -RequesterName "WORK-DOMAIN\gMSA-acme-ra$" `
    -LocalMode
```

This registers the `acme-adcs-ra-sync-revocations` task. With `-DryRun` the
task action passes `-DryRun` to `Sync-Revocations.ps1` (report-only); without
it the task action passes `-Execute` (live). Rotate the admin token by
re-registering the tasks (see the admin-token runbook).

**`-RequesterName` is required in practice.** Replace `WORK-DOMAIN\...` with the
**real** `DOMAIN\account` under which the RA enrolls, exactly as it appears in
the CA database `Requester` column (e.g. `CONTOSO\gMSA-acme-ra$`). The WI-022
requester check in `Revoke-Cert.ps1` refuses to revoke any cert whose CA-DB
requester does not match this value; if you leave the committed placeholder,
**every** revoke is rejected with "Requester mismatch". `Register-MaintenanceTasks.ps1`
forwards `-RequesterName` into the scheduled-task action.

**gMSA task logon type.** The revocation-sync task runs as a gMSA, which is
never interactively logged on. `Register-MaintenanceTasks.ps1` registers it (and
the nonce/sweep tasks) with `LogonType=Password` so the host retrieves the
managed password — do not change the principal to Interactive or the task will
register but silently never run.

**CRL freshness (`-PublishCrl`, off by default).** By default the sync agent
revokes each cert at the CA but does **not** republish the CRL: the revocation
is recorded immediately in the CA database and becomes visible on the next
**scheduled** CRL publication. This is deliberate least-privilege — `certutil
-CRL republish` requires the **Manage-CA** role, which the template-scoped
officer identity does not (and should not) hold. Pass `-PublishCrl` to force an
immediate republish, but only if you have granted the identity CRL-publish
rights. In the **single-identity** topology that means the internet-facing
enrollment identity also holds Manage-CA (able to edit CA configuration,
including its own `OfficerRights`) — **strongly discouraged**; it collapses the
escalation bound. `-PublishCrl` is more defensible for the **dedicated
two-identity revoker**, where CRL freshness may be worth the narrower blast
radius of a revoke-only account holding Manage-CA. Choose it deliberately and
record the decision (see threat-model §E). Default (scheduled CRL) is the
recommended posture for both topologies.

##### Monitoring differences

- The CA-DB requester for **both issuance and revocation** is
  `gMSA-acme-ra$` — the reconciliation cross-check
  (`Reconcile-Revocation.ps1`) is the primary way to distinguish issuance from
  revocation in the CA DB, because the CA DB alone cannot tell them apart by
  identity.
- The `revoked_in_ra_active_at_ca` bucket still works as the independent
  cross-check (it reads the CA DB directly, not the agent's self-report).
- Agent exit codes are the same as the two-identity design (0/1/2/5), and
  `Revoke-Cert.ps1` exit 6 (already revoked at the CA, confirmation retried)
  behaves identically.

##### Dry-run → execute promotion

`Register-MaintenanceTasks.ps1` supports `-DryRun` for the revocation-sync
task: in that mode the task action passes `-DryRun` (not `-Execute`) to
`Sync-Revocations.ps1`, so it fetches the pending set and prints what it would
do without making any change.

1. Register the task with `-DryRun` (see the scheduling example above).
2. Review the dry-run output and `Reconcile-Revocation.ps1` (the pending set
   should match the `revoked_in_ra_active_at_ca` bucket).
3. Re-register without `-DryRun` to arm the task. The first cycle after arming
   should revoke the pending serials and confirm them back to the RA
   (`ca_crl_updated=true` in the audit).

## Upgrading: the schema migration can refuse to start

The RA migrates its schema on startup, in one transaction. Most migrations
degrade gracefully — if a UNIQUE index cannot be created because the existing
data violates it, the RA logs an operator-actionable error and keeps running on
its primary (CAS-based) defence.

**One migration is deliberately fatal instead: the certificate serial
backfill.** `serial_number` is the only key `revokeCert` resolves a certificate
by, so a row without one is a certificate its owner cannot revoke through the
RA — with no fallback path and no signal (it is skipped by the
pending-revocation feed too). Coming up in that state is worse than not coming
up, so the RA raises `StoreMigrationError` and exits when it cannot derive a
serial for every row:

- **`cannot derive serial numbers for legacy certificate rows [...]`** — those
  rows' `cert_pem` does not parse. Inspect them
  (`SELECT id, cert_pem FROM certificates WHERE id IN (...)`) and either repair
  the PEM or delete the corrupt rows.
- **`legacy certificate rows derive conflicting serial numbers`** — two rows for
  one account derive the same serial, so revocation could not resolve them
  unambiguously. Reconcile the duplicates.

The migration is transactional: a refused start leaves the database exactly as
it was, so it is safe to inspect, fix, and restart. Back up the DB before an
upgrade as usual (below).

## Backup and restore

### What to back up

1. **SQLite DB** (`acme_ra.db`): the authoritative audit + every issued cert
   PEM + account JWKs + the EAB kid map + orders/authorizations. Back up
   with the DB cold (or use SQLite's online backup API / `.backup` command to
   avoid a torn copy).
2. **`.env` / `acme-ra.env`**: the EAB MAC keys, SIEM HEC token, admin
   token. This is the secrets-at-rest file — back it up encrypted, ACL'd to
   the backup operator + gMSA only.
3. **SIEM JSONL sink** (`<db>.siem.jsonl`): the secondary emission log.
   Back it up alongside the DB (or rely on the SIEM ingest as the
   authoritative copy, keeping the local JSONL as the fail-open buffer).

### Backup procedure

1. Snapshot the SQLite DB (e.g. `sqlite3 acme_ra.db ".backup acme_ra.db.bak"`
   or a file-system snapshot). The DB is in WAL mode; a raw file copy while
   the RA is running may be torn — use the `.backup` command or stop the RA.
2. Copy `acme-ra.env` to the encrypted backup (it is already ACL'd; ensure
   the backup target is too).
3. Copy the SIEM JSONL sink (or confirm the SIEM has ingested up to the
   current tail).
4. Store all three on tamper-evident, backed-up storage (the audit is the
   authoritative record — treat it as such).

### Restore procedure

1. Stop the RA app pool.
2. Restore `acme_ra.db` from the backup to the DB path in `web.config`.
3. Restore `acme-ra.env` to the env-file path in `web.config`
   (`ACME_RA_DOTENV`); re-ACL it to the gMSA + Administrators only.
4. Restore the SIEM JSONL sink (or accept the SIEM as the authoritative
   copy and let the RA append new events).
5. Start the RA app pool.
6. **Validate the restore:**
   - `GET /directory` returns JSON (the RA is up).
   - `GET /acme/admin/orders?status=processing` (with the admin token)
     returns the expected shape (the DB is readable).
   - Spot-check a recent `certificate-issued` audit event via
     `store.list_audit_events` (or the SIEM) to confirm the audit trail is
     intact.
   - Confirm the EAB allowlist loaded (a `newAccount` with a known kid
     succeeds; an unknown kid fails with `badExternalAccountBinding`).
7. If the restore is from before a known incident, note the gap in the
   audit trail (the SIEM may have events the DB restore lacks — reconcile).
