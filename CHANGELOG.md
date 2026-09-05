# Changelog

All notable changes to acme-adcs-ra are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Transport-orphaned certificates can be confirmed again (2026-09-05)

**Fixes a permanent wedge.** A certificate the CA issued but whose chain fetch
failed was stored with its leaf and an empty chain. CRL evidence verifies the
CRL's signature against the issuing CA certificate taken from **the
certificate's own stored chain**, so such a row had no issuer certificate and
every confirmation was refused — permanently under
`ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE=true`, for a certificate that
is live at the CA. There was no operator path out that did not weaken the
evidence requirement.

The RA now recovers the missing issuer material from chains it already holds:
every successful issuance stored the chain the CA returned over the same
authenticated enrollment leg, so the material carries the same provenance as the
orphan. The candidate that actually **signed** the leaf is selected by
signature, never by subject name — an ADCS CA key renewal keeps the DN and
changes the key. Recovery needs no configuration and no new trust setting;
`ACME_RA_ADCS_CA_BUNDLE` is TLS trust for the `/certsrv/` leg and is
deliberately not reused as an issuing-CA pin.

**Recovery repairs the input to the verifier and decides nothing.** Signature,
freshness and monotonicity all still have to pass afterwards, with no
exemptions, and the certificate stays `quarantined` on success. The recovered
chain and its provenance — issuer fingerprints, subjects, and which stored
certificate supplied each — commit in one transaction as
`revocation-issuer-evidence-recovered`, and a compare-and-set means a chain the
CA actually returned can never be overwritten.

**The blocked state is now visible instead of being an indistinguishable
repeating denial.** `GET /acme/admin/revocations/pending` marks an entry with no
issuer material (`issuer_evidence`, `blocked_reason`, `recovery_action`), and
the denial carries `reason_code: "issuer-evidence-missing"` — the one reason on
this path that cannot be resolved by retrying.

**Leafless orphans are listed separately.** When the leaf fetch itself failed
there are no certificate bytes and no store row, so nothing automated can revoke
it. Those incidents now appear under `leafless_incidents`, with
`leafless_incidents_truncated` saying whether the scan window was exhausted, and
they never drain — a record whose only resolution is a person going to the CA
must not disappear because no automated path exists. Polling the view writes no
audit rows.

### `scripts/verify_crl_publication.py`: prove a revocation reached a published CRL (2026-09-05)

New tool, and a lab-procedure fix behind it. Revoking at the CA and publishing a
CRL are two operations, and the teardown procedure only ever wrote down the
first — so one round left thirty certificates revoked-but-unpublished for five
and a half hours, and on a one-week `CRLPeriod` would have left them that way
for close to a week. Earlier validation-log entries assert "revoked … and the
CRL republished"; at least one round did not.

The script verifies from the CDP rather than from `certutil`'s exit code, and
carries its controls, because a CRL lookup that matches nothing returns what a
correct negative returns: the revoked serials are the positive control,
`--absent` is the negative control, and `--min-crl-number` proves the document
was published *after* the revocations rather than served from a cache. An
unreachable CDP exits 2 — no evidence either way — distinct from the exit 1 that
means the serials are genuinely not there. `docs/live-reproof-runbook.md` §E now
requires it.


### The CRL age ceiling is calibrated from measurement, not derivation (2026-09-05)

**Changed default: `ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS` is now
`626400` (was `604800`).** Operators who set this explicitly are unaffected;
operators on the default get a ceiling that is both binding and clear of the
observed served-age floor, which the previous default was not.

Two different quantities constrain this setting, and five revisions of the
documentation conflated them. The **floor** is the maximum age the CDP actually
*serves* — below it the ceiling refuses healthy evidence. The **roof** is the
CRL's published window — at or above it the ceiling sits behind the CRL's own
expiry and can never fire first. Every previous derivation took the floor from
the window, which is the attacker's replay reach rather than the CA's output, and
on a CA that publishes with overlap those differ by exactly the overlap.

`scripts/sample_crl_age.py` measured it: 399 samples over 8.3 days covering one
complete publication cycle put the maximum served age at 603654s (upper bound
605454s) against a 649200s window. `626400` clears the floor by ~5h49m and the
roof by ~6h20m. **This is what one observation period supports for a 1-week
`CRLPeriod` with ADCS's computed 12h overlap — not a universal bound.** Measure
your own CA; `docs/pre-pilot-checklist.md` §F says how.

Both previously published numbers were outside the band: the recommended
`649800` is above the roof, and the shipped `604800` clears the observed maximum
by only 1146s, less than one sampling interval. The number is now defined once,
in `crl_evidence.DEFAULT_CRL_MAX_AGE_SECONDS`, which `RAConfig` imports so the
library fallback and the deployment default cannot drift.
`tests/test_crl_max_age_calibration.py` pins it against the measurement and
proves — against the implementation, not on paper — that a ceiling at or above
the window is redundant with the expiry check.

**The monotonic watermark is now proven live** (2026-09-05, two genuine CA-signed
CRLs, with a negative control isolating the refusal to the watermark and
persistence across a service restart). It remains the replay control and remains
independent of this calibration.

### Maintenance and reproof preparation (2026-09-05)

- Extracted issued-certificate SAN, EKU, and CA-capability validation into
  `issued_certificate_validation.py`. The validation logic, finalization
  order, error responses, and quarantine behavior are unchanged.
- Made the CRL sampler's age test deterministic: certificate timestamps and
  the sample clock now share an explicit instant instead of depending on how
  long earlier tests took to run. The sampler itself is unchanged.
- Reconciled release status, authenticated resource reads, unavailable audit
  pruning, and CRL-age guidance with the implementation. The weekly-lab age
  ceiling remains interim pending measured served-age evidence; no defaults
  or deployment settings changed.
- Added a repeatable independent-client check to the live reproof runbook.
  Local verification and the remaining lab work are recorded in
  `docs/reproof-handoff-2026-09-05.md`; this change has not been lab-reproven.

### CRL replay is now bounded by a monotonic watermark, not by an age ceiling

**New setting: `ACME_RA_REVOCATION_CONFIRM_CRL_REQUIRE_MONOTONIC`, default
`true`.** It only affects deployments that have already configured
`revocation_confirm_crl_url`; nothing changes for anyone who has not.

The RA now records the newest CRL it has acted on for each issuing CA, and
refuses one that goes backwards — the confirmation is denied with reason
`crl-evidence-regressed`. The threat this closes is narrow and specific: a
**hold→unhold replay**. A certificate revoked with reason 6 and later released
with reason 8 (`removeFromCRL`) is still listed as revoked on the older CRL, so
replaying that document confirms a revocation for a certificate that is
currently valid. A stale CRL that *lacks* the serial already failed closed, so
this was the only wrong-accept an old CRL could produce.

`revocation_confirm_crl_max_age_seconds` remains an enforced freshness check
and serves as a **liveness alarm** on the CA's publication pipeline. Its
operational margin must come from the age the CDP actually serves, which can
differ from the published validity window. The lab's prior floor derivation
is disputed pending measurements (UNFILED item 24). The watermark comparison
does not depend on that calibration. No configured value changed.

**What the watermark does not do, stated because a quiet no-op is worse than no
control:** the first CRL seen for a CA is trust-on-first-use and protects
nothing. A CA key rollover creates a fresh watermark by construction (the key is
the issuer DN *and* the CA certificate's SPKI). A CA restored from backup
restarts its CRL Number sequence and will wedge confirmations until an operator
clears the watermark — deliberately manual, because an automatic reset on "the
number went backwards" would hand an attacker the sequence that defeats the
control. Round-robin CDP replicas at different vintages are retried once before
a regression is believed; if yours lag persistently, set the new setting to
`false` and the verdict is still recorded (`crl_watermark_verdict`) without the
refusal.

### New: `scripts/sample_crl_age.py`

An operator tool that samples a CDP on a schedule and reports the observed CRL
age distribution, the published window, and any CRL Number regressions. It uses
no RA, no store and no privilege — only reach.

It exists because this project could not measure its own CRL ages: the setting
above was calibrated four times without data, since every lab validation
restored the store that held the evidence. Use `--summarize` to set the liveness
alarm from measurement, and to find out whether your CDP is stable enough to
enforce monotonicity before you enable it.

### Earlier in this cycle

Remediation of a standard scan of `7808046`, live-validated on 2026-08-25.

**Check this before upgrading if you set `audit_offbox_required`.** The sink
that satisfies it by default is now authenticated HTTPS HEC — an `https`
`siem_hec_url` with no embedded credentials, plus a non-empty
`siem_hec_token` — because a *load-bearing* off-box trail should authenticate
its collector and protect events in transit, and plain syslog does neither.

**TCP syslog still works, but you now have to say so.** Set
`audit_offbox_allow_unauthenticated_syslog=true` and the requirement is
satisfied by TCP syslog exactly as it was in 1.12.0. It is deliberately not
silent: the RA logs `UNAUTHENTICATED OFF-BOX AUDIT` on every start and stamps
`offbox_transport=syslog-unauthenticated` on the startup probe event, so the
posture is visible to whoever reads the audit trail and not only to whoever
wrote the config file.

The acknowledgement exists because requiring HEC outright would strand every
estate that reaches its SIEM through a syslog relay — this codebase has no
syslog-over-TLS transport to offer instead — and the realistic response to a
refused start is `audit_offbox_required=false`, which is strictly worse: it
drops the off-box requirement entirely rather than just the transport
strictness. Two further boundaries are deliberate: the acknowledgement does
**not** reach UDP (that refusal is about whether "required" can assert anything
at all, since a datagram socket accepts bytes with nothing listening), and it
does **not** relax the HEC checks. Setting it without `audit_offbox_required`
is refused rather than ignored, so it can never be a switch that looks set and
does nothing.

**Also check your SIEM rules — one event was renamed and four more now
coalesce.** The reclaim route's order-not-found branch emits
`admin-order-reclaim-not-found` instead of `admin-order-reclaim-denied`; the
denied event now means only "an order existed and reclaiming it was refused",
which is the sharper signal. `admin-list-orders`,
`admin-list-pending-revocations`, the three reclaim outcomes and
`admin-revocation-confirm-deferred` now coalesce, so row *counts* change on
those exactly as they did in 1.12.0 for the sweeps.

### Security

- **The library that authenticates the privileged script tree could not
  authenticate itself.** All five privileged entry points (`Revoke-Cert`,
  `Set-OfficerRights`, `Sync-Revocations`, `Register-MaintenanceTasks`,
  `Reconcile-Revocation`) now verify `InstallVerifyLib.ps1` against a pinned
  release digest, computed over canonical UTF-8/LF bytes so a CRLF checkout
  still matches, and then execute **those same verified in-memory bytes** — the
  path is never reopened between validation and use.
- **Three provenance walks were fail-open.** The hand-rolled
  `while ($p -and $guard -lt 32)` ancestor loops, a `Get-ChildItem
  -ErrorAction SilentlyContinue` tree enumeration, and a runtime-closure walk
  that skipped past a queued interpreter that had vanished all returned a
  partial answer that read as proof. They now throw, and callers treat an
  unprovable chain as a violation.
- **Replayable admin audit growth is bounded.** A stolen maintenance credential
  could enumerate order ids and, because each id was part of the coalescing key,
  cycle through more keys than the in-memory window cap and force a fresh
  durable row per request. Those paths now key on the event and a stable reason
  code only; the probed id survives as a bounded `sample_order_id` sample and
  the replay count stays exact.
- **The lab spike wrote its private key and then protected it.** The output
  directory and key are now created with their final restrictive DACL, and a
  rerun refuses an existing directory or key rather than overwriting it.

### Fixed

- Two Pester tests added by this work could never pass on Windows PowerShell
  5.1, the engine these scripts ship on — they were green on the Linux pwsh job
  and through a full live lab validation. One read a correct refusal as a
  failure because CI runs with `$ErrorActionPreference='stop'`, under which 5.1
  turns a native child's stderr into a terminating error; the other had its
  embedded double quotes stripped out of a native command line. No product
  behaviour was involved in either.

## [1.12.0] — 2026-08-25

Three medium security findings from a cross-lineage whole-repository scan, a
fourth found by measuring the deployed store, and a live re-proof that turned
up two defects in the lab teardown itself.

**Upgrade if you consume the audit stream.** This is the minor bump, and it is
a minor rather than a patch for one reason: **audit rows that used to appear no
longer do.** Nothing is lost that recorded a state change, but row *counts*
change, so a SIEM rule or dashboard that counts them needs a look:

- `admin-nonce-cleanup` and `admin-expired-order-sweep` emit **only when the
  sweep actually deleted or invalidated something**. A no-op sweep is silent.
- `admin-list-pending-revocations` emits **only when the poll returned work**.
  An empty poll is silent.
- `finalize-enrollment-admission-denied`, `admin-revocation-confirm-denied` and
  `admin-list-pending-revocations` now **coalesce**: one row per window with an
  exact `denial_count`, instead of one row per request.

**Also new:** after a post-issuance store failure the RA answers finalize with
**503 `issuance_halted`** and keeps doing so until it is restarted. That is
deliberate and one-way; see the finding below.

### The part worth keeping

The static scan found three call sites. A single `GROUP BY event_type` against
the real deployed store found two more it could not have — and showed that
**78.5% of the audit table was this RA narrating its own idle maintenance**,
against eleven `certificate-issued` rows. Reading the source tells you an
event exists; only counting rows tells you it dominates.

The same lesson repeated in teardown, twice, and cost more: the procedure's
"is the CA clean?" check restricted on a template *display name* where the
column holds an OID, so it matched nothing, returned zero, and read as clean.
Fifteen certificates from earlier sessions were live at the CA the whole time,
each of those sessions having recorded a clean teardown. **A verification step
whose failure mode is silence is not a verification step.**

### Security — 2026-08-25 whole-repository standard scan (three findings, all fixed)

A cross-lineage static scan of `a566050`: three medium, no high or critical.
Two are audit-growth bounds. The first is the one that mattered — it could
leave a domain-trusted certificate outside the RA entirely.

- **A post-issuance store failure orphaned a live certificate (medium; high
  impact, low likelihood).** `Store.record_issuance` is the *first* durable
  record of something ADCS has **already done**, and it was unguarded. On a
  full or read-only database the certificate/order/audit transaction rolls
  back and the exception escapes before the SIEM fan-out, so a live
  certificate existed with no row, no audit event, no quarantine record and no
  revocation-queue entry.

  The asymmetry was the tell: both *neighbouring* paths — verifier rejection
  (`_quarantine_and_fail`) and transport failure
  (`_quarantine_transport_orphan`) — already had orphan handlers. The success
  path had none. And neither would have helped: both fall back to `_audit`,
  which is `Store.record_audit` — **the same database that just failed**.
  Under this fault that fallback raises from inside its own except block and
  writes nothing anywhere.

  This breaks an invariant the code states explicitly. `audit_retention`
  argues that *"the `certificate-issued` audit row commits in the same
  transaction as the certificate, so a full disk stops issuance rather than
  issuing unaudited."* That holds only while the disk fills **before** the CA
  call. In the window between "ADCS committed" and "SQLite committed" it
  cannot hold, because the issuance has already happened. Worth stating
  plainly: this deployment **refuses audit pruning on purpose**, so a filling
  disk is not a freak event — it is the long-run destination of the shipped
  configuration, and the other two findings shorten the timeline.

  `_emergency_issuance_orphan` now compensates for that window, and **nothing
  in it touches the store**. Two independent sinks: a `logger.critical`
  carrying serial, ReqID, order, account and template (a different path from
  the database), and a direct `ctx.audit_hook` call with a hand-built event —
  deliberately bypassing `emit_audit_hook`'s after-the-row-commits contract,
  because there is no row and there is not going to be one. Neither sink is
  trusted: the hook is wrapped so a SIEM transport error cannot replace the
  exception being re-raised, and logging handlers swallow transport errors
  anyway, so a delivered-looking emission is not proof of delivery.

  **Issuance then halts** (`IssuanceHalt`, 503 `issuance_halted`), because
  every finalize admitted afterwards would orphan another certificate the same
  way. One-way until restart, deliberately: this process cannot prove the
  store became writable again, and an endpoint that clears a safety latch is a
  way to turn the latch off under pressure. The latch does **not** fire for a
  merely *busy* store (`database is locked`) — lock contention is transient
  and ordinary, and halting on it would trade a rare orphan for a routine
  self-inflicted outage. The emergency evidence is emitted either way; only
  the latch is conditional.

- **Enrollment admission denials were replayable into unbounded audit writes
  (medium).** The enrollment gate sheds at `adcs_enrollment_max_pending`
  (default 32) and the route CAS-restores the rejected order to `ready`, so
  the identical signed finalize can be re-sent for as long as capacity stays
  full — one durable row apiece. Shipped defaults allow one account to set
  this up: `rate_limit_orders_per_window` is 50, and 33 ready orders is enough.

  `finalize-enrollment-admission-denied` now coalesces. The reasoning is not
  new — the coalescer's own docstring already wrote it for
  `order-rate-limited`: *a denial issued because a cap was hit is unbounded by
  definition, since the cap throttles the work and not the audit row.* It was
  simply never pointed at the gate. An explicit `reason_code` pins the
  coalescing key to a server constant, because `EnrollmentGateBusy`'s message
  carries live counts and one edit putting `str(exc)` into `reason` would put
  a varying value back in the key.

- **The revocation-confirm credential was a durable write primitive
  (medium→low).** Two replayable routes. A confirm-token holder could POST
  well-formed but nonexistent serials forever
  (`admin-revocation-confirm-denied`) — nothing transitions, the lookup
  misses, the row was durable. The probed serial stays in `details` for the
  investigator but an explicit `reason_code` keys the window, so varying it
  cannot defeat the bound; the coalesced row then names the window's *first*
  serial while the count stays exact. That trade is deliberate: "someone is
  probing serials" is the signal, the individual values are not.

  The pending-list poll is the more interesting half, and **it is not really
  an attack**. The revocation sync task polls `admin-list-pending-revocations`
  on a fixed interval, forever, and every poll wrote a row — so the table grew
  without bound in entirely benign operation. Coalescing alone does not fix
  that: at a 15-minute cadence and a 60-second window, no two polls ever fold.
  The route now writes **no row at all when the list is empty**, which is the
  steady state and reports nothing an investigator can use; a poll that
  actually returns work keeps its row, because "the revocation host was handed
  these serials" is the audit trail for what happens next. Coalescing bounds
  the case the skip cannot — a token holder polling a *non-empty* list at line
  rate.

  This is the only **success** event in `COALESCED_EVENT_TYPES`, and it is
  admissible only because nothing counts these rows. The contrast is
  `account-key-changed`, excluded precisely because its successful rows *are*
  the 14a limiter's counter. The membership guard test now pins all nine types
  and states that rule, so the next addition is a reviewed decision.

- **Two more of the same, found by MEASURING rather than reading (added during
  the live re-proof).** Before deploying, one `GROUP BY event_type` against the
  backup of the deployed store said this, out of 722 rows:

  ```
  199  admin-list-pending-revocations
  184  admin-nonce-cleanup
  184  admin-expired-order-sweep
   ...
   11  certificate-issued
  ```

  **567 of 722 rows — 78.5% of the entire audit table — were this RA's own
  scheduled maintenance reporting that it had nothing to do.** The evidence the
  system exists to produce was eleven rows. On a deployment that refuses audit
  pruning, every one of those is permanent.

  `admin-nonce-cleanup` and `admin-expired-order-sweep` now follow the same
  rule as the pending-list poll: a sweep that deleted or invalidated nothing
  writes no row; a sweep that actually destroyed state keeps its row, because
  "these nonces were destroyed" is a real fact about the trail. The static scan
  found one of these three call sites. The other two took one read-only query
  against a real store — which is the part worth keeping.

**The pattern, said out loud.** All three are the shape the 2026-08-24 entry
below already names: *the correct primitive already existed, with the correct
reasoning written beside it, and was not pointed at every call site.* That is
four rounds running. The durable fix is structural rather than another
call-site patch — invert the allowlist to a denylist, or add a test that
enumerates every denial-shaped event emitted under `routes/` and requires each
to be coalesced or exempt-with-a-reason. Recorded as an open item rather than
done, because it is a design change and this release is a park.

Suite 953 passed / 1 skipped (was 931); Pester 467 passed / 0 failed / 4
skipped; ruff and mypy clean. Twenty-two new tests, **every one mutation-checked
against twelve separate mutations** — including reverting each fix in place and
recording the failure.

### Security — 2026-08-24 daybreak standard scan (four findings, all fixed)

A cross-lineage standard review at `0a47955`. Two findings were re-rated here
and one required overturning a documented earlier decision. Full write-up in
`docs/security-review-2026-08-24-daybreak-standard.md`; the pre-action
declaration is in `docs/UNFILED-WORK-ITEMS.md`.

Every one of the four is the same shape, which is the part worth keeping: **the
correct primitive already existed, with the correct reasoning written beside
it, and was not pointed at every call site.** Several of the new tests are
therefore coverage assertions rather than behaviour assertions.

- **A privileged script tree was judged AFTER its siblings had already run
  (high).** `Register-MaintenanceTasks.ps1` dot-sourced `TaskActionLib.ps1` and
  `SyncLib.ps1` ~70 lines above the provenance gate, so both executed as
  Administrator before anything checked the tree — and the gate was scoped to
  the revocation-sync path, so registering only the nonce/sweep tasks skipped it
  entirely. Writing `SyncLib.ps1` alone was enough; neutering the checker was
  never necessary. `Sync-Revocations.ps1` (run by the scheduled task as the gMSA
  every interval, forever), `Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and
  `Reconcile-Revocation.ps1` had no gate at all.

  One `Assert-PrivilegedScriptTreeTrusted` now runs in all five, **before** any
  sibling loads. `-AllowUntrustedScriptPath` propagates into the registered task
  action, so the documented lab flow does not register a task that always
  refuses.

  This overturns the 2026-08-18 decision to skip the run-time re-check, and the
  reasons matter. That decision rested on two `Add-Type` C# compiles per load on
  a 15-minute cadence, and closed with its own condition for revisiting: *"worth
  revisiting if the lib is ever split so the DACL primitives can be loaded on
  their own."* Both compiles are now on demand
  (`Initialize-AtomicDirectoryType`, `Initialize-FinalPathType`) and neither is
  on the trust path — dot-source cost **1298 ms → 321 ms** (pwsh 7.6/Linux). The
  objection is retired rather than overruled. The primitives were deliberately
  *not* split into a second file: `InstallVerifyLib.ps1:1680` records what a
  duplicated predicate cost last time.

- **Nothing checked whether a parent could replace a protected root (medium;
  reported as high).** `Get-RootProvenance` inspects the root and its contents,
  never above it, so everything the installer proves about `$InstallDir` /
  `$RuntimeDir` could describe a tree an attacker substituted. The installer
  already makes this argument for the IIS site tree and applies the check there.

  Rated medium because the reported impact does not reproduce on the defaults:
  swapping a child needs `Delete`/`DeleteSubdirectoriesAndFiles`, and
  `C:\ProgramData` grants Users create-class rights only. It bites a
  non-default root under a delete-granting parent — the documented `C:\Temp`
  staging habit.

  The reason it had never shipped is that `Test-PathChainTrusted` **fails**
  `C:\ProgramData`, on `WriteData` — which on a directory means *create a new
  entry*, not *replace an existing child*. So the broad predicate would have
  refused the default install. `Test-AceEndangersChildContainer` asks the narrow
  question (`Delete`, `DeleteSubdirectoriesAndFiles`, `ChangePermissions`,
  `TakeOwnership`, `GenericAll`, `GenericWrite` — and *not* `WriteData`), which
  passes `C:\ProgramData` and `%ProgramFiles%` and still fails `C:\Temp`.
  Default-safe by construction; the test asserting `C:\ProgramData` passes is
  load-bearing, because a wrong refusal aborts the upgrade of a live issuance
  host.

- **A redirect handed the HEC collector token to another origin (low→medium).**
  `urllib`'s redirect handler strips only content-length/content-type and
  copies `Authorization` onto the new request, and permits `http`/`ftp`
  targets — so the https-only check the sink is gated on was worth one hop.
  Confirmed by execution against a local redirect pair. The event body does not
  leak (the new request carries no `data=`, and 301/302/303 downgrade POST to
  GET), so this is credential disclosure — but an HEC token forges audit *into*
  the SIEM. The sink now refuses redirects outright.

- **`$env:windir` selected executables that run elevated (medium; reported as
  high).** `InstallVerifyLib.ps1` derived `icacls.exe` from the inherited
  process environment with a bare-name PATH fallback, while three sibling
  scripts and `Get-TrustedInboxModuleRoots` already refused to trust exactly
  that input. The fallback was the sharper half — reached by *unsetting* windir
  rather than redirecting it — and icacls is not only executed here, it
  produces the evidence every provenance verdict is read from.

  `Get-TrustedSystem32Path` resolves from machine-scope `windir` then the folder
  API, and **throws** on Windows rather than falling back. Applied to all nine
  installer sites as well as the library; the three test assertions that pinned
  the old `$env:windir` spelling now pin the new one. Fixing only the library
  would have split the doctrine across two files, which is how this class keeps
  returning.

Pester **467 passed / 0 failed** (baseline 424); pytest 931 passed / 1 skipped;
ruff and mypy clean. Every fix mutation-proven — reverted in place, suite re-run,
failure recorded. One vacuous test was caught and fixed in the process: rights
constants declared in a Pester `Describe` body are `$null` inside `It` blocks, so
every mask assertion would have passed against `[int]$null = 0`.

#### Live validation found two defects **in the fixes themselves** (2026-08-24)

The four fixes above shipped with local gates only. Running them on the lab RA
host and issuing CA the same day found two of them broken — the reason this
subsection exists rather than a line in the release notes.

- **The root-self substitution check refused the *designed* gMSA state grant.**
  The new `Get-AncestorSubstitutionViolations` judged the root itself by
  `Get-AllowedExecutableOwners`, a list that can never admit a service identity
  — but the state root's design grants the worker gMSA `Modify`, and `Modify`
  carries `Delete`. Fresh installs passed only because a not-yet-created root
  has no ACL to judge: **every upgrade of an existing deployment refused with
  `INSTALLER_EXIT=1`**, the round-5 wrong-refusal class the `C:\ProgramData`
  test was written to prevent. `Initialize-SecuredRoot` now passes
  `-AllowedRootWriterSids` for the **root-self** check only — the state root
  admits its design writers, the runtime root admits none (its design is gMSA
  `RX`, so any delete-class ACE there is drift), and **ancestors are never**
  judged by the design list. Re-proven live: upgrade install exit 0,
  `/directory` 200, twice.

- **The untrusted-tree override did not reach the `Revoke-Cert.ps1` child.**
  The chain ran registrar → task action → the sync's own gate and then stopped.
  `Revoke-Cert.ps1` carries the same tree gate and was never told, so an
  explicitly-allowed tree could enumerate the pending set and revoke nothing —
  measured live as `SYNC COMPLETE: 1 pending, 0 revoked, 1 failed` on a
  genuinely stuck orphan. `Sync-Revocations.ps1` now propagates the flag into
  the child argv. This is the same defect the F10 fix's own task-action
  propagation was written to close, one hop lower.

Also closed: the raw generic-bit branches of `Test-AceEndangersChildContainer`
(`0x10000000`/`0x40000000` flag; `0x80000000`/`0x20000000` do not) were
live-proven 10/10 against the deployed library and then pinned — the
adversarial review had found no existing case that reached them. All new tests
mutation-checked; Pester 457 → 467.

**Operator note, not a code defect:** the lab CA host's `C:\` carries an
*applicable* `Authenticated Users:(M)` ACE, so no tree on that host passes the
privileged-script gate and the officer scripts need `-AllowUntrustedScriptPath`
there. The refusal is correct (measured, not assumed) and the override is loud.
Filed in `docs/UNFILED-WORK-ITEMS.md`.

**Done since:** live Windows validation (WI-050) and an independent
third-lineage adversarial review, which rated F10/F12/F13 sound and held F11
ship-blocking on proof grounds — confirmed prescient by the first defect above.
A full canonical application re-proof ran on the final tip: §A 14/14, §A1 13/13,
CRL+§G 9/10 (the one FAIL is CRL3, the designed WI-052 calibration check),
§K 12/12, both transport-orphan branches 6/6, §R+Rverify through four cycles,
least privilege, authority split, CRL evidence, teardown verified on both hosts.

**Still not done:** phase L was not re-run here (no enrollment-leg change on
this branch; owed on a v1.11.x tag per the standing lab-network item).

## [1.11.0] — 2026-08-24

Two defects that made ACME revocation unusable for real clients, both found by
pointing **Certify the Web** at the RA for the first time.

**Breaking:** the `revokeCert` response shape — success is now 200 with an
**empty body**, and the non-normative out-of-band hint moved to the
`X-Acme-Ra-Out-Of-Band-Revocation` header. Anything that parsed the body must
read the header instead. That is the minor bump, following the same convention
as 1.10.0, whose breaking `Sync-Revocations.ps1` change was also a minor.

**Upgrade if anything other than this project's own tooling revokes
certificates** — before this release, nothing else could.

### The part worth keeping

Neither bug was findable from inside this repository. The lab harness and
`tests/hand_rolled_acme_client.py` both sent `cert`, exactly as the server read
it, so a full revocation suite — authorization, reason-code policy, CAS races,
the out-of-band leg — passed against a dialect no other ACME client speaks. And
the response-body shape was not merely untested but **documented as safe**, in
the stability contract, on the reasoning that standard clients ignore extra
fields. A client that shares the server's assumptions cannot test the server's
assumptions, and a written assumption is not evidence.

### Validation

Suite 928 passed / 1 skipped; ruff and mypy clean. Both fixes verified live
against the real client on the lab RA: the revocation that had been refused,
then misreported, returned `isOK=true "Certificate revoked"`.

Scope of that proof, stated rather than implied — the fixes were verified by
hot-patching the single changed file onto the lab, **not** by a full installer
deployment, and the lab was restored to the v1.10.0 artifact afterwards. The
full §A–§L live re-proof was **not** re-run: the change is confined to the
`revokeCert` route, and the path that matters for it was the path exercised.

**Superseded 2026-08-24, after release.** The full re-proof did then run on
`0a47955` — the exact shipped artifact, by real installer deployment reporting
`VERSION=1.11.0`, not a hot patch. §A 14/14, §A1 13/13, CRL/§G 9/10 (CRL3 is
the designed WI-052 calibration check), §K 12/12, both transport-orphan
branches 6/6, §R+Rverify across three cycles, least privilege, authority split,
CRL evidence. The v1.11.0 delta itself is proven on every cycle by a new `R2b`
check — empty §7.6 body plus the `X-Acme-Ra-Out-Of-Band-Revocation` header,
with the harness finally speaking the standard `certificate` dialect rather
than the server's old `cert` one. **`Lqueue`/`Ldrain` did not run:** three
attempts were defeated in turn by warm keep-alives surviving the route
blackhole, a saturation check counting `TIME_WAIT`, and a flapping lab network
fabric. Not a product regression — the diff to `f6badc9`, where those phases
passed 22/22 the same morning, touches only `routes/revocation.py` — but it is
owed on a v1.11.x tag. See the validation log and `docs/UNFILED-WORK-ITEMS.md`
item 11.

### Changed — revokeCert returns an empty body; the out-of-band hint moves to a header (2026-08-24)

**Breaking for anything that read the response body.** Every `revokeCert`
success path now returns **200 with an empty body**, and the WI-010
out-of-band hint is carried in `X-Acme-Ra-Out-Of-Band-Revocation` as compact
JSON.

The old shape returned the hint as a JSON body on the stated assumption that
"extra fields are ignored by standard ACME clients". Certify the Web disproved
that live: it fails to parse any JSON object here — at line 1, position 1, the
opening brace, so even `{}` breaks it — and then reports the revocation as
**failed** to the operator. The revocation had succeeded. A false negative on a
revocation is the worst direction for that error to point: an operator may
believe a certificate is still live when it is not.

RFC 8555 §7.6 asks only for 200 on success; an empty body is what public CAs
return and what clients are built against. The same information remains in the
audit row, which was always the durable record.

Seven existing tests asserted the body shape. They were rewritten to read the
header — not deleted — via a `_oob_hint()` helper, so the hint's contents,
its absence when `ca_crl_updated=true`, and the `req_id` passthrough all stay
covered. Suite 928 passed / 1 skipped.

### Fixed — ACME revocation was impossible for every conformant client (2026-08-24)

`revokeCert` read the payload field **`cert`**. RFC 8555 §7.6 names it
**`certificate`**. So any client following the RFC was refused with
`urn:ietf:params:acme:error:malformed: missing or invalid cert field` and could
not revoke at all. Certificate revocation is a security-critical path, and it
did not work for anyone outside this repository.

**Why no test caught it, which is the more useful half.** The lab harness
(`raproof.py`) and `tests/hand_rolled_acme_client.py` both sent `cert` as well.
The client mirrored the server's own mistake, so an entire revocation suite —
authorization, reason-code policy, CAS races, the out-of-band leg — passed
against a dialect no other ACME client speaks. Every one of those tests was
correct about what it claimed and blind to the thing that mattered.

It was found by pointing **Certify the Web** at the RA, i.e. by using the real
client instead of our own.

- `certificate` is now the field, and the error message names it.
- `cert` stays accepted as a deprecated alias so in-house tooling keeps working.
- The hand-rolled test client sends `certificate` by default, with a
  `field_name` parameter so the alias stays covered.
- Three regression tests, mutation-proven: reverting the route to read `cert`
  fails the RFC-field and error-message tests while the alias test still
  passes — exactly the signature the old behaviour should produce.
- Verified live: the same Certify the Web revocation that had been refused now
  reaches the RA and records `certificate-revoked`.

### Validated — Certify the Web renews against the POST-as-GET-only RA (2026-08-24)

The last open pre-pilot item. Removing the unauthenticated `GET /acme/cert/{id}`
and `GET /acme/authz/{id}` forms (2026-08-15 F4) was closed on RFC 8555
conformance grounds, but whether the actual client this RA exists to serve still
worked was never tested — no lab phase can cover it, because it needs the real
client.

Certify the Web 7.1.1.0 (ACME stack `Certify.ACME.Anvil` 3.3.3) drove a full
issuance from a separate domain host. Server-side audit: `account-created` (EAB
accepted) → `order-created` → `challenge-validated` → `certificate-issued`. The
IIS log is the direct evidence rather than inference:

```
POST /acme/authz/<id>     200
POST /acme/order/<id>     200
POST /acme/finalize/<id>  200
POST /acme/cert/<id>      200
```

Every retrieval verb is a POST, all 200, **zero 405s**. The removed GET forms
are not a client-compatibility problem and nothing needs filing against CtW.

Two client-side observations, neither a product defect: CtW's pre-flight
challenge-URL check fails against this RA (the RA auto-validates on EAB +
network allowlist + SAN scope, so there is no responder to reach) and CtW
proceeds regardless — the pre-check does not need disabling. And storing the
issued certificate fails with "Access is denied" when the CtW service runs as a
non-administrator gMSA, which is a permission matter on the client host.

### Validated — the installer's MSI gate, proven live at last (2026-08-24)

Owed since round 6 and slipped by five consecutive live rounds, for a
structural reason rather than neglect: the MSI branch is gated by
`Test-HttpPlatformHandler`, which is true when the module is registered *or*
its DLL is present — and the RA host has both, so the branch was unreachable
there. Forcing it would have meant hiding a production DLL.

Run instead on a second Windows Server host with the handler deliberately
uninstalled, against the **released `v1.10.0` tarball** and the real Microsoft
MSI. All four cases:

- `http://` source → refused before any download; handler absent.
- `https://` with no digest → refused; handler absent.
- `https://` with a well-formed but wrong digest → the artifact **was**
  downloaded into protected staging and hashed there, then rejected on value.
  `msiexec` never opened it. This is the staged-copy refusal, live.
- Correct digest → Authenticode verified against `CN=Microsoft Corporation`,
  then installed. That signature check is the half no unit test can reach.

Host restored and verified against a pre-test snapshot: identical handler
version, module re-registered, sites and pools running, every
installer-created directory removed.

### Docs — WI-052 has a number: the CRL age ceiling is derivable (2026-08-24)

The runbook asked operators to *observe* `A_sched_max` (peak CRL age at
scheduled replacement) across publication cycles and deliberately refused to
suggest a value. That was more conservative than the problem needs, and it left
`require_crl_evidence` effectively unconfigurable without weeks of watching.

`A_sched_max` follows from the CA's own configuration:
`CRLPeriod + ClockSkewMinutes + lateness + skew`. The derivation is
**validated against a real CRL** rather than assumed — predict
`nextUpdate − thisUpdate` and compare. On the lab CA the prediction
(604800 + 43200 + 1200) matches the measured **649200s exactly**.

That gives `A_sched_max = 605400s` against a 649200s hard ceiling: **12h10m of
usable headroom**. The shipped recommendation for a 1-week CA is
**`ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS=626400`** (7d 6h), which
splits the headroom evenly — 5h50m of tolerance for late publication against
6h20m of margin below hard expiry. Measured CA→RA clock skew on this estate is
sub-second, so lateness is the only term worth watching.

`docs/operations.md` gains *Deriving the ceiling (WI-052)* with the worked
numbers and the instruction to re-derive (and re-validate) for a CA on a
different cadence. The 691200s (8-day) plumbing value remains explicitly unsafe
here: it exceeds the validity window and would make the age ceiling non-binding.


## [1.10.0] — 2026-08-24

Closes the 2026-08-15 → 2026-08-23 security review series (three external review
rounds, 40 commits) plus the phase-L lease proof. **Breaking:**
`Sync-Revocations.ps1` `-AdminToken` and `-ConfirmToken` are now switches —
token values are read only from `ACME_ADMIN_TOKEN` / `ACME_CONFIRM_TOKEN` and
can no longer be passed on argv. That is the minor bump.

**There is no 1.9.0 or 1.9.1 release.** `pyproject.toml` declared `1.9.1` and
the section below was written, but no tag was ever cut; the tagged history goes
v1.8.0 → v1.10.0. Anyone still on **v1.8.0 should upgrade**: it predates
`838eeb2`, which fixed a defect that left the entire CA-side revocation loop
inert.

**Known limitation, deliberate:** `audit_prune_enabled=true` is refused, so
cumulative local `audit_log` growth is **not** bounded. Disk monitoring and
archival are operator duties. See the audit-pruning entry below and
`docs/operations.md`.

### Validated — the stale-worker enrollment lease, proven live (2026-08-24)

Phase L ran end to end for the first time on tip `f6badc9`: §L 9/9, §Lqueue 8/8,
§Ldrain 5/5. The stale worker reached the CA boundary holding a lapsed
generation and abandoned **before submit**, leaving exactly one certificate for
the contested order. It had been unrunnable rather than skipped — no driver
invoked it, neither blackhole mechanism supported queue-then-drain, and the
phase aborted on a client timeout the bounded enrollment executor makes
inevitable. Detail in `docs/pre-pilot-checklist.md`.

### Fixed — the CRL hostname-verification test was inert on 3.13 and 3.14 (2026-08-24)

`test_https_pin_preserves_sni_and_real_hostname_verification` built its test CA
without a Subject Key Identifier or a `keyCertSign` Key Usage, and its leaf
without an Authority Key Identifier. The OpenSSL behind CPython 3.13/3.14
enforces all three, so the TLS handshake failed *before* hostname verification
was reached and the test failed on those versions — caught by CI on the first
push of the series, not locally, where the dev venv is 3.12.

The certificates now carry SKI, AKI, `keyCertSign`/`crlSign` and leaf
`BasicConstraints`. Mutation-checked on 3.14: removing the transport's
`assert_hostname` binding fails this test and the pool-level one. Suite is
925 passed / 1 skipped identically on 3.12 and 3.14.

**Product code was not involved.** But the version gap is the point: the lab
host and the shipped deployment run **3.14**, so the control this test exists
to protect had never actually been exercised on the version that runs it.

`docs/operations.md` gains the operator consequence: an `https://` CRL
distribution point now needs an RFC 5280-clean chain, because the same OpenSSL
strictness applies to the RA's own CRL fetch. It fails closed (evidence absent,
confirmation refused) but presents as an unreachable CRL host. A plain `http://`
CDP is preferred — the CRL's signature is verified independently, so TLS adds
no evidentiary value.

### Security — stale key-change requests could overwrite a completed rollover (2026-08-23)

- `keyChange` now carries the authenticated old-key thumbprint into one
  `BEGIN IMMEDIATE` transaction and compares account ID, current thumbprint and
  `status=valid` on the update itself. A concurrent rollover or deactivation
  invalidates the stale request; exactly one rollover and its success audit can
  commit.
- A database-level new-key uniqueness race now maps to ACME `badPublicKey`
  instead of escaping as a 500.
- The regression suite coordinates two real SQLite writers and mutation-proves
  the old last-writer-wins behavior.

### Security — CRL DNS validation is now bound to the socket (2026-08-23)

- The CRL host is resolved once and each request connects to one of those
  numeric addresses. Redirect hops reuse the same pin, so no validation-only
  lookup can race a second hostname resolution inside `requests`.
- The original hostname remains the HTTP `Host` header and, for HTTPS, the TLS
  SNI and certificate-verification name. Real HTTP, redirect and TLS-handshake
  tests cover the connection target, Host, SNI, accepted hostname and rejected
  hostname; an empty initial resolution fails closed.
- CRL retrieval is deliberately direct and does not use environment HTTP
  proxies: a proxy would perform its own destination resolution and defeat the
  socket pin. Internal/private CRL addresses remain supported. `requests>=2.32`
  is now explicit because that is the adapter API this control overrides.

### Security — unsupported audit pruning now fails loudly (2026-08-23)

`audit_prune_enabled=true` previously configured a production-inert feature:
`run_sweep` had no caller. Wiring it unchanged would be unsafe because the SIEM
path has no per-row delivery acknowledgement, deletion and self-audit are not
atomic, and the sweep event is not exported off-host. Configuration and app
construction now refuse the flag rather than silently claiming a cumulative
storage bound or activating evidence deletion. Operators who set it must remove
it or set it to false; retention-floor validation, footprint warnings, denial
coalescing and JSONL rotation remain active.

### Security — a UDP syslog probe satisfied `audit_offbox_required` with nothing listening (2026-08-18)

Codex scan of `7325cdb`→`47bb9f7`, recorded as unfiled item 8. `audit_offbox_required`
exists to refuse to start unless audit evidence leaves the box. On UDP it
refused nothing: `SiemExporter`'s startup probe returned `True` whenever the
socket accepted the datagram, which a datagram socket always does. Reproduced
against an unused port — `enabled=True`, `ok=True`, no collector.

The code was already candid about this; the returned *detail* said in as many
words that reachability was NOT proven. But the **boolean** is what gates
startup, and the caller never reads the detail. That candour shipped as the
previous wave's fix (2026-08-18 wave 3 F2), so this is the same finding one
level deeper.

- **The UDP probe now returns `False`.** Requiring off-box audit and
  demonstrating it over UDP are mutually exclusive, so the honest answer is a
  refusal, not a caveat. TCP still passes — it proves a live transport, which is
  the strongest claim syslog can make — and HEC still proves receipt.
- **Config refuses the combination outright**, so it fails at startup validation
  with an actionable message rather than at the probe. The shipped `web.config`
  already selects TCP, so no shipped configuration reaches this.
- **This was the prerequisite for wiring the retention sweep** (item 7, still
  open). Deletion in `audit_retention` is gated on this same probe, so wiring
  `run_sweep` while UDP passed would have made the hole load-bearing for
  deleting the only surviving copy of audit rows. A test asserts a real UDP
  emitter cannot open that gate.

### Fixed — the TCP syslog connect ignored the configured timeout (2026-08-18)

Unfiled item 9. `_apply_send_timeout` ran *after*
`SysLogHandler.createSocket()` had already resolved and connected, so
`siem_syslog_timeout_seconds` bounded **sends only**. DNS resolution and the TCP
handshake fell back to the OS default, so a blackholed collector could stall
service construction — or the single reconnect worker — well past the deadline
the operator set. The docstring only ever claimed to bound a send, so this was a
gap rather than a broken promise.

- **One wall-clock deadline** now covers resolution plus every address the
  resolver returns, so a multi-homed target cannot multiply the wait by its
  address count. `getaddrinfo` takes no timeout and blocks in the OS resolver,
  so it runs in a daemon thread that is abandoned rather than waited on.
- Datagram and Unix sockets keep the stock path; neither connects.
- The regression test measures it: against a resolver stub that never answers,
  the pre-fix code took 30s and then connected happily.

### Security — the privileged script tree was authenticated by nothing but `Test-Path` (2026-08-18)

Daybreak 2026-08-17 F3, recorded as unfiled item 3. The installer does not
install `scripts/` at all — `docs/operations.md` tells operators to hand-copy it
— so the tree lands wherever a human put it, and
`Register-MaintenanceTasks.ps1` then persists that path into a scheduled task
that executes `Sync-Revocations.ps1` as the gMSA every interval, forever.

Measured live 2026-08-17, so this is not a design concern awaiting evidence:
`C:\Temp\ra-scripts` — the path the registered task actually ran from — carried
`BUILTIN\Users:(I)(CI)(AD)` and `BUILTIN\Users:(I)(CI)(WD)`, inherited from
`C:\Temp`. An unprivileged local user could drop a replacement script there and
wait fifteen minutes. The same session watched `Test-ObjectDaclTrusted` refuse
`C:\Temp` as an *installer source* for exactly this reason: the control existed
and was simply not pointed at this path.

- **`Get-TreeTrustViolations`** applies the installer's provenance rule to
  a whole tree: the ancestor chain (catches the measured inherited-from-`C:\Temp`
  case, where every file looks locally fine) **and** every object beneath it
  (catches one loosened file in an otherwise clean tree). Either half alone
  passes a tree the other rejects; both are mutation-proven.
- **`Register-MaintenanceTasks.ps1` refuses** to register the revocation-sync
  task from a failing tree, naming the object and the principal that can write
  it. The nonce/sweep tasks are unaffected — they call `Invoke-RestMethod`
  inline and execute nothing from disk.
- **`-AllowUntrustedScriptPath`** downgrades the refusal to a loud warning, for
  lab and first-install staging. Same shape as `-AllowInsecureUrl`.
- Honest scope: the check is loaded from the tree it judges, so it does not stop
  an attacker who can already write there — it stops the tree being writable in
  the first place, and the plant that arrives *after* registration, which is the
  measured case.

### Security — the IIS site tree is now proven up its ancestor chain, WI-015 (2026-08-18)

The round-2 follow-up deliberately **withheld** the `-SitePath` ancestor-chain
refusal pending a live DACL baseline, because a default IIS install might
legitimately have failed it. The installer therefore checked the site tree and
everything in it, but not the directories above it — and a writable directory
above the site root lets a local user rename the tree aside and substitute
their own, `web.config` included, which is what names the executable IIS starts
as the gMSA.

The baseline was surveyed live on the lab IIS host 2026-08-17 and recorded on
WI-015: `C:\inetpub` and `C:\inetpub\acme-adcs-ra` are both clean — `BUILTIN\Users`
hold `(RX)` and `(OI)(CI)(IO)(GR,GE)`, no write-class access anywhere on the
chain — while `C:\ProgramData\acme-adcs-ra` reports two violations on the same
function, so the survey discriminates rather than passing everything. That was
the evidence the fix was waiting on, so the refusal now ships: the site-tree
proof calls the same `Get-TreeTrustViolations` as the script-tree gate above.

### Documented — the `<ipSecurity>` allowlist posture is now a recorded decision (2026-08-18)

Unfiled item 4. Two independent reviews (2026-08-11, 2026-08-17 Daybreak) raised
the commented-out allowlist in `deploy/iis/web.config`; the first adjudicated it
and the second re-found it because that adjudication lived only in a review
document. `SECURITY.md` gains a **Recorded decisions** section stating the
disposition, the compensating controls in code, and what would change it — so
the next reviewer argues with a decision rather than re-filing a finding.


### Fixed — the CA-side revocation loop was inert (2026-08-17, live)

Found by the live re-proof, not by CI: `Sync-Revocations.ps1` exited 2 with
nothing revoked, and every `certutil` call in `Revoke-Cert.ps1` failed with
*"No local Certification Authority; use -config option"* on the (non-CA) RA
host.

- **`Invoke-CertUtil` splatted its argument array into a PowerShell function.**
  `& certutil @CertutilArgs` is correct — a native command takes one argument
  per element — but `a69859d` refactored the native call into
  `Invoke-CertUtilCapture @CertutilArgs`, and splatting an array into a
  *function* binds only the first element to the first positional parameter.
  The remaining six landed in `$args`, which a non-advanced function accepts
  without complaint. Seven arguments in, one argument out, no error: every
  certutil invocation in the file ran as a bare `-view` or `-config` with no
  operands, including the `-revoke` itself.
- **Both helpers are now advanced functions** (`[CmdletBinding()]` with a
  declared `param` block), so surplus positional arguments are a binding error
  instead of silent `$args` overflow. The same mistake cannot recur quietly.
- **Three Pester tests assert the argv certutil actually receives** — whole
  array, order included, on the revoke call as well as the read-only views —
  and that a splatted array now throws. All three fail against the old code.
  The suite stubbed certutil before this, but never asserted *which* arguments
  arrived, which is why 363 green Pester tests and a green Windows CI job said
  nothing about a completely non-functional revocation path.

Verified live afterwards on the lab CA: 7 pending, 2 revoked, 5
already-revoked-at-CA recovered through the confirmation-retry path, 0 failed,
agent exit 0, RA queue drained to empty.

### Added — a ceiling on account-key rollover, WI-014 part 14a (2026-08-17)

`keyChange` (RFC 8555 §7.3.5) was the last authenticated transition with no
rate, quota or cardinality check of any kind. A valid — or stolen — account key
could chain rotations indefinitely, and each success wrote a durable
`account-key-changed` row that the denial coalescer deliberately excludes.
Retention (part three, below) bounds the *storage* consequence; an unbounded
authenticated action is a rate-limiting defect in its own right, which is why
this shipped separately rather than being folded into the retention build.

- **`rate_limit_key_changes_per_window` (default 5, `0` disables)** — a ceiling
  on successful rollovers per rolling window, sharing
  `rate_limit_window_seconds` with the order limiter. It ships **enabled**: this
  is a defect fix, and the default sits far above legitimate use (rollover is a
  rare operational event, and `max_accounts_per_eab_kid` defaults to 1).
- **Keyed per EAB kid, not per ACME account** — the same reasoning as WI-016's
  order limit. A per-account key would let a leaked EAB credential reset its
  budget by enrolling one more account key, which is precisely the move the
  limit exists to stop.
- **Enforced inside the rotation transaction**, not by a route-level check.
  `update_account_key_with_audit` counts, updates the key and writes the audit
  row under one `BEGIN IMMEDIATE`, following `create_order_with_authz` and the
  round-6 lifetime EAB account quota. A count-then-rotate split lets a parallel
  burst all observe the same below-limit count and all proceed — and here every
  winner is an irreversible key rotation.
- **The denial is coalesced** (`key-change-rate-limited` joins
  `COALESCED_EVENT_TYPES`). A ceiling that wrote one durable row per refused
  attempt would just move the unbounded growth from the success row to the
  denial row. The success row stays uncoalesced: it is both the only record
  naming the new key's thumbprint and the counter this limit reads.

### Added — audit retention, WI-014 part three (2026-08-17)

Parts one and two bounded audit growth without ever deleting (`audit_bounds`
capped row size, `audit_coalesce` capped rows-per-window for replayable
denials). Part three makes deletion possible — and spends most of its code
making it hard to do by accident.

- **`certificates.not_before` / `not_after`** recorded at issuance and
  backfilled from `cert_pem` for existing rows. Derived from observed issuance
  rather than the template, because ADCS can issue shorter than the template
  asks. Backfill is best-effort by design: an underived validity leaves the
  retention floor unknown, which blocks pruning, which is the fail-safe
  direction — unlike an underived serial, it should not stop the RA starting.
- **`audit_retention_days`, validated against a floor** of longest observed
  certificate validity + a fixed 14-day grace. Below the floor **startup is
  refused**, because retaining for less than a certificate's own lifetime means
  a certificate can be valid and servable with no record of how it was issued.
  The grace is a constant, not a setting: it must not be tunable to zero, and it
  must not collapse as certificate lifetimes shrink.
- **A retention sweep behind four gates** — retention at or above the floor,
  `audit_prune_enabled`, `audit_offbox_required`, and a delivery probe that
  succeeds *at sweep time*. Off by default. With no off-box copy the local
  `audit_log` is the only evidence there is and nothing is deleted from it, so
  local-only deployments bound growth by capacity and monitoring instead. The
  sweep audits itself; a retention pass that leaves no trace is
  indistinguishable from an attacker's cleanup. **`run_sweep` has no production
  caller yet** — no admin route, no scheduled task, no lifecycle hook — so a
  deployment that configures retention today prunes nothing. Wiring it is
  deliberately deferred until the delivery probe stops accepting an
  unacknowledged UDP datagram, the `DELETE` and its audit row commit atomically,
  and the sweep event is exported off-box.
- **Footprint reporting** at startup (rows, time span, database + JSONL bytes)
  with a warning past `audit_store_warn_mib` (default 1024). This is the half
  every deployment gets, and the whole control for local-only ones.
- **JSONL mirror rotation** (`audit_jsonl_max_mib`, `audit_jsonl_keep`). It was
  append-forever with no story at all, and it is the larger half of a default
  install's local footprint.
- **`audit_log(timestamp)` index.** The table carried no index beyond its
  primary key, so every time-ranged read was a full scan — invisible while the
  table was small, dominant once retention keeps months of rows.
- The `"DELETE FROM audit_log" not in source` architecture test is **narrowed,
  not removed**. It was a deliberate tripwire whose docstring said adding a
  pruner "is the review conversation worth having before that ships"; that
  conversation happened. It now pins deletion to exactly one statement, in one
  policy-free primitive, callable only from `audit_retention`.
- Documented the local-only posture alongside the other operator
  responsibilities, including its real cost: the `certificate-issued` audit row
  commits in the same transaction as the certificate, so **a full disk stops
  issuance** rather than issuing unaudited.

### Security — Daybreak standard pass (2026-08-17; four findings, one fixed)

- **Syslog send failures were counted as successful off-box audit delivery
  (reported medium; rated high).** `_setup_syslog` used a stock
  `SysLogHandler`, whose `handleError` reports and returns rather than raising,
  so `Logger.info()` succeeded after a send that never left the host. Both
  `_syslog_send`'s counters and the `audit_offbox_required` startup probe
  inferred delivery from that return. Measured against a killed TCP collector,
  the emitter recorded five deliveries and zero failures while swallowing a
  `ConnectionResetError` and four `BrokenPipeError`s, and the startup gate still
  passed. Same defect class as wave-3 F2, which was fixed for HEC only; the
  shipped `web.config` selects TCP syslog, so this was the default production
  audit path. Fixed with `_RaisingSysLogHandler`, which re-raises transport
  errors, drops the dead stream so the next event reconnects instead of wedging
  the sink, and re-applies the send timeout across a reconnect (the stock
  handler never did, including when the initial connect failed and the socket
  was created lazily on first emit). The TCP probe no longer reports "accepted",
  which overclaimed — a completed `sendall` is a live transport, not receipt.
  Eight tests, each mutation-checked. See
  `docs/security-review-2026-08-17-daybreak-standard.md`.
- Findings 1–3 triaged and **not** fixed, with reasons recorded in that
  document: unlimited `keyChange` rotations is a second vector on open WI-014;
  the commented-out IIS `ipSecurity` allowlist is the posture consciously
  adopted in the 2026-08-11 review and documented in
  `docs/operator-requirements.md`; the unauthenticated privileged script tree is
  valid and converges with open WI-015 and WI-053.

### Security — round-6 follow-up, round 4 (2026-08-16; seven findings, all fixed)

- **The R2-11 `@()` wrapping inverted the readback verdict (medium).**
  `@($null)` is a one-element array, so a truncated or DACL-less OfficerRights
  value printed "Found 1 OfficerRights ACE(s)" and exited 0 — the
  verify-by-readback tool affirming a restriction not in force. Early exits now
  return `@()` (the OfficerRightsLib convention), with behavioural + text
  tests.
- **Two more control-removing env names were settable from web.config
  (medium).** `ACME_RA_ALLOW_FAKE_ADCS_BACKENDS` is now forbidden there;
  `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` is pinned-when-present to
  `true` (absent stays the documented optional mode; the lab's true value
  passes).
- **`finalize-csr-mismatch` lacked a `reason_code` (medium).** Its coalescing
  window keyed on prose one refactor away from carrying the attacker-chosen
  SAN list; pinned now with an end-to-end test.
- **The 5.1 `2>&1`-under-`Stop` hazard was unshielded in every CA-officer
  script (medium).** On Windows PowerShell 5.1 the first merged stderr line
  terminates the pipeline before `$LASTEXITCODE` is read, breaking the
  documented exit-code relay and the `net stop`/`net start` recovery inside a
  catch block. The EAP-lowering shield SyncLib already uses is now applied to
  all CA-officer native calls (central `Invoke-CertUtilCapture` in
  Revoke-Cert.ps1; shields in Reconcile-Revocation.ps1 and
  Get/Set-OfficerRights.ps1).
- **Low:** `ConvertTo-PsSingleQuotedLiteral` refuses double quotes (the
  `-Command` wrapper invariant was an assumption); coalescer
  `previous_window`/`coalescer_evictions` markers are stripped from
  caller-supplied details; `kid_samples` honours its cap at window open; a
  whitespace-padded `modules` attribute no longer false-refuses; the
  template-terminator strip handles the 2-byte edge.
- The mutation-blind `test_a_live_window_survives_below_the_cap` was rewritten
  to assert what its mutation actually changes (the absent
  `coalescer_evictions` stamp below the cap).
- Gates: 830 pytest + 1 skipped, 345 Pester + 4 skipped, ruff, mypy; 9
  mutations against the new tests, all detected. Not a live Windows proof.

### Changed — the Windows install is split into code and state (BREAKING for deployments)

Not a review finding: a response to the *shape* of four rounds of them. Five of
the eight installer findings across those rounds were defects in the previous
round's fix, and every mechanism involved — an ACL claim, an ownership claim, a
link walk, a content manifest, an out-of-tree anchor for that manifest — existed
to make it safe to **adopt** a directory a local user might have created first.
The premise was the problem. See `docs/design-code-state-split.md`.

- **Executable content moved to `%ProgramFiles%\acme-adcs-ra`** (new
  `-RuntimeDir`), under a `current\` subdirectory rebuilt from scratch on every
  install. `%ProgramData%` grants `Users` create-folder rights with
  `CREATOR OWNER` inheritance — which is exactly why a non-administrator could
  pre-create `C:\ProgramData\acme-adcs-ra` and own it. `%ProgramFiles%` grants
  read and execute only, so the executable half cannot be pre-planted at all.
- **The gMSA gets read+execute on code and modify on state**, where it used to
  get modify over one tree holding both. A compromised app pool can no longer
  rewrite the interpreter it is about to be relaunched with.
- **Neither root is ever adopted.** `Get-RootProvenance` answers absent / ours /
  foreign, and a foreign root stops the install with a message naming what
  disqualified it, which files to rescue, and in what order. "Ours" is decided
  by the same function that proves the lockdown at the end of an install, so
  the two definitions cannot drift.
- **This closed an unreported path.** `acme-ra.env` is preserved no-clobber
  across reinstalls, so a pre-created state directory with a planted dotenv was
  *preserved and ACL'd* rather than rejected — and that file carries
  `ACME_RA_EAB_ALLOWLIST` and `ACME_RA_SAN_SCOPES`, which decide who may enrol
  and for which names.
- **The runtime is retired by atomic rename, rebuilt at the final path, and
  rolled back if the build throws.** In place rather than staged-then-renamed
  because a venv is not relocatable: `pyvenv.cfg` records an absolute `home`
  and `Scripts\*.exe` embed the interpreter path.
- **Deleted:** the tree manifest and its verifier, the
  `HKLM\SOFTWARE\acme-adcs-ra` anchor, `Test-DestinationInterpreterTrusted`,
  and the whole destination-reuse branch. They answered "may I reuse the bytes
  already there?", which no longer arises.
- **`web.config` `processPath` now points at
  `C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe`.** The
  database, logs and dotenv paths are unchanged.

**Upgrading is a deliberate, manual step.** An install from the old
single-directory layout will be refused, because it does not match the new
shape — it granted the gMSA modify over executable content, which is the state
the split exists to end. The migration runbook is
`docs/operator-requirements.md` §4.

### Added — `docs/operator-requirements.md`

The contract for everything the installer deliberately does not decide: what
the operator must provide, every condition the installer refuses on with the
exact remedy for each, the invariants that must stay true afterwards, the
migration runbook, and a post-install verification script.

### Security — round-6 follow-up (2026-08-16; four findings, all fixed)

An internal review of the round-6 fixes themselves, before re-validation. Two
high, two medium; three are in code round 6 added. See
`docs/security-review-2026-08-16-round6-followup.md`.

- **The elevated bootstrap's write-mask covered neither WRITE_DAC nor
  WRITE_OWNER (high, CWE-732).** It named `FileSystemRights::WriteDacl` and
  `::WriteOwner` — **members that do not exist** (the enum spells them
  `ChangePermissions` and `TakeOwnership`). PowerShell resolves a missing static
  member to `$null`, `[int]$null` is 0, and `-bor 0` is a silent no-op, so both
  terms vanished. An allow ACE granting a named non-administrator nothing but
  the right to rewrite the DACL and take ownership of `InstallVerifyLib.ps1`,
  `src\` or `deploy\` passed the gate that exists to stop exactly that — round-6
  finding 1, reachable through the fix for round-6 finding 2. The library's
  `Test-AceEndangersBytes` listed both pairs and was correct; carrying the dead
  half there is what made the bootstrap copy look right. The dead spellings are
  gone repository-wide.
- **The bootstrap never inspected `scripts\` or `scripts\lib\` (high,
  CWE-732/CWE-367).** Its ancestor loop walks *upward* from the release root and
  its input list names the helper *file*, so the two directories between them
  went unchecked — and `DeleteSubdirectoriesAndFiles` on a parent is
  delete-and-recreate on the child whatever the child's own DACL says. New
  `Get-BootstrapInteriorDirectories` proves every interior directory and refuses
  a path outside the release tree rather than returning nothing.
- **The TLS catch-all path invoked a null command (medium; install-breaking).**
  Round 6 moved the native utilities off ambient PATH but assigned the `netsh`
  path function-locally in `Ensure-SslCertBinding` and again inside the
  `-SharePort443` branch, so the **catch-all** branch's stale-SNI cleanup ran
  against an unassigned variable: a terminating `RuntimeException` after the TLS
  certificate was bound and before the app pool was started. Reachable on
  `-ConfigureIIS -HostName <name> -TlsCertThumbprint <t>` **without**
  `-SharePort443`; the lab only ever exercises the SNI path. One script-scope
  `$netshExe` now, asserted to be assigned before every use.
- **The audit coalescer's open-window index was unbounded (medium, CWE-400).**
  Durable growth is a function of time, but the dictionary tracking open windows
  was swept only when a lapsed key happened to recur — and the round-5 keys carry
  `order_id`, so a client finalizing many orders badly minted a fresh key each
  time, in a worker the installer configures never to recycle. Bounded by
  `MAX_OPEN_WINDOWS` (1024), enforced only when a new window opens and dropping
  expired entries before live ones. Nothing durable is touched and no count is
  lost; below the cap, behaviour is unchanged.

Adjacent variants closed: the `icacls /save` dump — the entire evidence for
every provenance verdict and lockdown proof — moved out of ambient `%TEMP%`
(`%windir%\Temp` is Users-writable when the installer runs as SYSTEM) into the
protected installer scratch directory, which is now created before the first
root claim; a pre-scratch failure no longer prints a spurious
`CommandNotFoundException` ahead of the real error; and the README prerequisite
table no longer tells operators that `-InstallPrereqs` installs Python with
`winget`, which round-6 finding 3 removed.

### Security — round-6 follow-up, round 6 (2026-08-17; cross-lineage review, six findings + three low, all fixed)

Four hazard-scoped reviewers on three lineages went over the whole
uncommitted follow-up before it was committed and lab-validated. One high:
the stop-and-prove loop's `appcmd list wp 2>$null` discarded stderr, so a
broken appcmd (stopped WAS, corrupt `applicationHost.config`, access denial)
produced an EMPTY worker list — which `Test-AppPoolWorkersGone` classifies as
"no workers", an all-clear — and the installer went on to claim trees a live
gMSA worker might still hold handles into. The suite's `noisy` fixture
modelled exactly this shape and had never been asserted. Also: both
OfficerRights parsers `break`-ed out of malformed descriptors into partial
success (the readback tool printed "Found 1 ACE(s)" + exit 0; the
preservation path would silently strip officers from the rewritten value);
the eviction marker was stamped one row late; "absolute" certutil/net
resolution trusted caller-settable `$env:windir` with bare-NAME (PATH)
fallbacks; ten control-REMOVING settings (the WI-014 coalescing bound, the
2026-08-11 nonce bucket, the WI-016 order limits, the 2026-08-07 body caps,
the M-2 reclaim age) were still settable from `web.config`; an explicit empty
`reason_code` fell back to attacker-chosen prose keying; the pinned-bool
comparison accepted `" true "` which pydantic rejects at worker startup; and
the "repository-wide" dead-spelling test checked two hard-coded files. Nine
mutations run against the new tests, all detected. See
`docs/security-review-2026-08-16-round6-followup.md` (Round 6).

### Security — round-6 follow-up, round 5 (2026-08-17; six findings, all fixed)

An inline review of the `web.config` gate — the surface round 4 left unexamined
when one of its two reviewers died before reading a file. Two of the six are
**false refusals**, which matter as much as bypasses: this gate runs on every
install including against a preserved operator-edited file, so a wrong refusal
aborts the upgrade of a live issuance host. See
`docs/security-review-2026-08-16-round6-followup.md`.

- **A pinned setting demanded the literal string `true`**, so an operator
  writing `ACME_RA_AUDIT_OFFBOX_REQUIRED="1"` — which pydantic reads as true —
  had the install refused. Now compared on meaning; every "off" spelling is
  still refused.
- **A trailing space in the `ACME_RA_DOTENV` value** was refused as an ambiguous
  Win32 path component. Trimmed.
- **`ACME_RA_SIEM_HEC_TOKEN` was settable** — a secret, whose home is the
  installer's own dotenv template.
- **`ACME_RA_MAX_ACCOUNTS_PER_EAB_KID` was settable**, retiring round-6 finding
  7's lifetime per-kid account quota in one line.
- **The CRL proof's strength knobs were settable.** Pinning
  `REQUIRE_CRL_EVIDENCE` on means nothing if `CRL_MAX_AGE_SECONDS` and
  `CRL_FOLLOW_REDIRECTS` can be widened beside it — a decade-old CRL still
  "proves" a serial revoked.
- **A managed handler (`type=`) was accepted.** The check read `scriptProcessor`
  and `modules` only; `type=` loads and runs .NET code in the worker as the
  gMSA.

`ACME_RA_REVOCATION_CONFIRM_CRL_URL` was examined and deliberately left
settable: the CRL's signature is verified against the issuing CA certificate
from the certificate's own stored chain, so the URL can deny evidence but not
manufacture it, and the docs present it as an operator setting.

### Security — round-6 follow-up, round 3 (2026-08-16; sixteen findings, all fixed)

Three more independent hazard-scoped reviews, this time of the round-2 fixes.
**All but two findings were in those fixes** — the third consecutive round in
which the remediation contained the next defect. See
`docs/security-review-2026-08-16-round6-followup.md`.

- **`Stop-AppPoolAndWait` would have aborted every first install (high).** The
  round-2 guard threw on any stderr, but `appcmd list apppool <absent>` writes an
  error and exits non-zero, and the installer does not create the pool until ~800
  lines later — so on a first install the pool is absent by construction. Same
  shape as the netsh catch-all: a guard only the untravelled path reaches.
  Ambiguity now resolves by falling through to stop-and-prove-the-worker-gone,
  independent of appcmd's exit code and of a localizable message. Mutation
  testing then exposed a second defect in the same fix: `$exists` included the
  ErrorRecords, making the new stderr clause dead code.
- **The forbidden-env-name list was one delimiter deep (medium).**
  `env_nested_delimiter="__"` means `ACME_RA_SAN_SCOPES__<kid>__DNS_PATTERNS` is
  a path into `san_scopes`; verified against the running config, it replaced the
  protected dotenv's patterns for an existing kid while the installer reported
  success. Now matches on the first segment.
- **`<handlers>`, `<modules>` and `<isapiFilters>` were never inspected
  (medium)** — and the installer itself unlocks the handlers section, which is
  what makes a site-level `scriptProcessor` authoritative.
- **Only `<environmentVariable>` children were read (medium)**, so the same
  setting as `<add name="…">` was invisible.
- **Controls with one production value were accepted at any value (medium):**
  `ACME_RA_AUDIT_OFFBOX_REQUIRED=false`, `ACME_RA_ALLOW_WEAK_CREDENTIALS=true`.
- **The anti-ambient-TEMP guard gated on `$env:OS` (medium)** — a caller-settable
  variable, in the function whose thesis is not trusting the ambient
  environment. Two further instances fixed, including one where an unset
  `$env:OS` skipped kernel final-path resolution, so a junction or 8.3 alias
  could make two spellings of one tree read as `disjoint` — the relation that
  *is* the code/state ACL boundary.
- **`PolicyDecision.reason_code` defaulted to `"allowed"` (medium)**, so a future
  denial branch omitting it would emit `outcome="denied"` with
  `reason_code="allowed"`. A default is invisible to mypy; it is now required.
- **The privileged scripts kept bare-PATH natives (medium).** Round 2 hardened
  the read-only `Reconcile-Revocation.ps1` and left `& certutil` in
  `Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and `Get-OfficerRights.ps1` — the
  ones holding CA-officer context. And that fix's python half closed nothing:
  `Get-Command python` *is* the PATH lookup. It now goes through
  `Test-PathChainTrusted`.
- Low: the expiry sweep shed windows without counting them, so a swept victim's
  successor was indistinguishable from a first-ever window; the durable-growth
  claim needed a caveat above `MAX_OPEN_WINDOWS`; three false refusals that would
  have aborted a live upgrade (forward-slash paths, a default `xmlns`, a
  double-space `arguments`); `ACME_RA_DOTENV` validated only if present, now
  **required**; and a doc claim of `PYTHON*` corrected to the three names the
  code actually matches.

**Test quality.** A reviewer demonstrated that six of round 2's guards could be
neutered without a single test failing — their only coverage was a source-grep
the mutation left intact. All six now have behavioural tests. Separately, a
second test was found that did not detect the mutation it named (its clock never
advanced, so nothing expired); it has been rewritten rather than deleted.

### Security — round-6 follow-up, round 2 (2026-08-16; twelve findings, all fixed)

Three independent reviews of the four fixes above, each pointed at one named
hazard. **Two findings were in those fixes**, which is why the round was run.
See `docs/security-review-2026-08-16-round6-followup.md`.

- **`Revoke-Cert.ps1 -ReqID` could never revoke (high).** Two `Write-Output`
  diagnostics sat above the `return` in `Get-SerialFromReqId`, and a PowerShell
  function returns everything written to the success stream — so the caller's
  `$targetSerial` was a five-element array of banner lines that went straight
  into `-restrict SerialNumber=<banner…>`. The same defect the wave-3 round fixed
  in `Test-SerialRevokedAtCa` 130 lines above, in the same file. Fails safe, but
  removes the manual containment path. `Sync-Revocations.ps1` always passes
  `-Serial`, so no live re-proof ever exercised it.
- **The launch-configuration gate read one attribute of four (medium).**
  `Assert-WebConfigLaunchTrusted` checked which tree `processPath` was in and
  nothing else — and `$ExpectedProcessPath` was a mandatory parameter that was
  **never compared to anything**. It accepted `arguments="-c …"`, a `PYTHONPATH`
  into a world-writable directory, a `<location>`-scoped `processPath` override,
  and — verified against the running code — `ACME_RA_EAB_ALLOWLIST` /
  `ACME_RA_SAN_SCOPES` / a redirected `ACME_RA_DOTENV` in
  `<environmentVariables>`, because pydantic-settings ranks an environment
  variable **above** the dotenv. `web.config` could therefore override the file
  the installer protects with its own DACL, owner check, rollback re-protect and
  `-ProtectedEntries` proof. **Operator-breaking:** a preserved `web.config`
  carrying any of these now fails the install.
- **An ACE-less DACL was judged administrator-only (medium).** A NULL DACL grants
  everyone full control and .NET renders it exactly like a deny-everyone empty
  one; both `Test-ObjectDaclTrusted` and the installer bootstrap decided trust
  only from inside a loop over `$acl.Access`, so an empty collection passed.
  `Test-AclDumpLocked` already failed closed on the identical condition.
- **The nonce-cleanup and expired-order-sweep tasks could never have run
  (medium).** `Build-ActionScriptBlock` emitted six double quotes across eleven
  lines into a string its caller wraps in `-Command "…"`, so the action
  re-tokenised at run time. Registration reported success regardless.
- **The coalescing key absorbed an attacker-chosen SAN (medium).** The policy
  denial reason embeds the offending SAN and the coalescer keys on `reason`, so
  one order plus one varied identifier per finalize produced one durable row per
  request — the bound-defeat the key excludes attacker-chosen data to prevent.
  `PolicyDecision` gained a fixed-vocabulary `reason_code`.
- **`Stop-AppPoolAndWait` read "appcmd failed" as "no such pool" (medium).**
  stderr discarded and exit code ignored, so a broken `applicationHost.config`
  led the installer to claim trees a live gMSA worker still held handles into.
- **`_Window.distinct_kids` was unbounded within a window (medium).** Capped, with
  an honest `distinct_kids_truncated` flag; `denial_count` stays exact.
- Low: bare-PATH `certutil`/`python` in `Reconcile-Revocation.ps1`; the
  interpreter proven at one resolution and executed at another; `.Trim()` on a
  null probe line making the "output not recognised" branch unreachable;
  `.Count` on an unwrapped single ACE and a descending range slice in
  `Get-OfficerRights.ps1`; the round-1 scratch fallback silently reopening the
  ambient-TEMP path it closed; and eviction being invisible and ordered by
  `opened_at` rather than least-recently-touched.

Reported and deliberately **not** fixed: `-SitePath` has no ancestor-chain
provenance. The fix is one `Test-PathChainTrusted` call, but its baseline cannot
be measured off Windows, and when round 5 added that kind of chain rule the live
run found two calibration defects in it. Recorded as a native item instead.

### Security — Daybreak round 6 (2026-08-16; seven findings, all fixed, plus one live-found)

Independent validation and remediation of Daybreak's review of `d1d7c17`: four
high and three medium, all valid. Six were one installer trust-boundary problem,
the seventh a missing durable account-cardinality invariant. Recorded here
retroactively — the round shipped in `b625247`/`8964eba` without a CHANGELOG
entry. See `docs/security-review-2026-08-16-daybreak-round6.md`.

- **Named writer ACEs bypassed provenance (high).** An allow ACE granting
  FullControl to an arbitrary named user or custom group returned safe before its
  rights were examined. Provenance is now an authorized-writer SID allowlist, not
  a familiar-principal denylist; an unresolved dangerous identity fails closed.
- **Mutable repository source was built elevated (high).** The installer
  dot-sourced its helper, read dependency locks and `web.config`, and invoked
  PEP 517 on the checkout without proving another principal could not modify it.
  An inline bootstrap now proves every consumed input first, and the build
  consumes an administrator-only snapshot under `%ProgramFiles%`.
- **`-InstallPrereqs` executed PATH programs (high).** Bare `py`, `python` and
  `winget`. Python package-manager execution is gone; discovery accepts only an
  `Application` command with an absolute source whose whole ACL/owner chain is
  trusted.
- **Fresh-root handles survived lockdown (high).** `New-Item` exposed a fresh
  root under inherited permissions and `/reset` ran before protection, so a
  low-privilege process could retain a create-capable handle across the DACL
  change. Roots are now born with their final protected DACL via
  `CreateDirectoryW` + `SECURITY_ATTRIBUTES`.
- **Win32 path aliases collapsed roots (medium).** Components ending in a period
  or space survived canonicalisation. Only ordinary absolute local DOS paths are
  accepted, and the runtime/state relation is recomputed after the runtime
  object exists.
- **MSI verification was not bound to execution (medium).** Hashing,
  Authenticode verification and `msiexec` each reopened a caller-controlled
  pathname. Every source now requires an out-of-band SHA-256 and is staged into a
  fresh administrator-only directory; only the staged path reaches
  `%windir%\System32\msiexec.exe`.
- **One EAB credential created unlimited accounts (medium).** Account idempotence
  was by JWK, so a valid `kid` could supply fresh keys indefinitely. New
  `max_accounts_per_eab_kid` (default 1): the store counts every account row for
  the verified kid — deactivated ones included — and commits the count, insert
  and audit under one `BEGIN IMMEDIATE`.
- **Finding 8, live-found during the round-6 native re-proof (high).** The
  mid-install re-assert ran `icacls /reset` on the ROOT, replacing the protected
  DACL with the inherited one until `/inheritance:r` restored it. `%ProgramData%`
  grants `Users (CI)(WD,AD,WEA,WA)`, and a looping standard-user process planted
  content through that window (3 successes in 43,701 attempts; caught by the
  post-claim proof, but the write must be impossible). Roots are never `/reset`
  mid-install: descendants only, plus `Set-ObjectProtectedDacl -SkipReset`. The
  live race re-run after the fix measured 0 successes in 43,920 attempts.

### Security — Daybreak 2026-08-15 rescan, iteration 3 (four findings; all fixed)

An independent re-review of `63529a6`. One high, two medium, one low (WI-014,
on its fourth consecutive review). Three of the four are in the Windows
installer. See `docs/security-review-2026-08-15-daybreak-rescan-2.md`.

- **A preplanted manifest authenticated a preplanted interpreter (high,
  CWE-345/CWE-426).** The previous iteration gated execution of
  `$InstallDir\python\python.exe` on a whole-tree SHA-256 match against
  `python.manifest.json` — a *sibling*, in the same namespace. On a first
  install into a predictable `C:\ProgramData\acme-adcs-ra`, a local
  low-privilege user writes both: the pair is self-consistent, verification
  passes, and the planted binary is the preferred launcher, executed as
  Administrator. Hash equality proves consistency, not provenance. The
  manifest's own digest is now anchored **out of tree** in
  `HKLM\SOFTWARE\acme-adcs-ra` (written by the elevated install that built the
  runtime, its key owner-checked on read); an unanchored runtime tree is
  deleted and rebuilt from an authenticated source, never executed. An upgrade
  from a pre-anchor install rebuilds once.
- **A raced junction still redirected privileged ownership changes (medium,
  CWE-59/CWE-367).** `icacls` had `/L` everywhere it recursed, but ownership
  went through `takeown /r`, which has **no no-follow option** — a junction
  inserted after the reparse pre-walk redirected an elevated recursive
  ownership rewrite outside the install tree, damage the post-walk could detect
  but never undo. `takeown` is gone: ownership is claimed with
  `icacls /setowner *S-1-5-32-544 /t /q /L`, before the DACL reset so the reset
  cannot be denied. `/L` is now on every icacls call including the
  single-object ones; `/c` is gone from all of them (it skips objects it cannot
  process); and every result goes through `Test-IcaclsOutputClean`, which
  checks the exit code *and* the "Failed processing N files" summary.
  **Behaviour change:** `icacls /setowner` does not force ownership, so the
  installer now *refuses* a tree a local attacker pre-created and locked
  against it, rather than force-adopting a hostile namespace.
- **The live-tree claim left retained handles and attacker-owned descendants
  (medium, CWE-367/CWE-732).** The app pool was stopped ~220 lines after the
  install root was claimed and after the destination interpreter had been
  verified and run — and Windows checks access at handle-open time, so a
  compromised gMSA worker's write handle survived the ACL reset and could
  rewrite interpreter bytes between the hash and the execution. The pool is now
  stopped and **proven dead** (`appcmd list wp` polled to empty, abort on
  timeout) before anything under the install root is claimed, hashed or run.
  Separately, the read-back proof checked only the root's owner; it now checks
  every descendant's, which also catches a child created between the ownership
  and DACL passes.
- **Unbounded durable audit growth from unauthenticated denials — WI-014,
  fixed (low, CWE-400).** Three waves deferred this because the usual
  remediation is a pruner, and deleting audit evidence is the operation an
  attacker most wants. That reasoning stands: nothing is pruned, and a test
  asserts no `DELETE FROM audit_log` exists in the store. Instead, within
  `ACME_RA_AUDIT_DENIAL_COALESCE_WINDOW_SECONDS` (default 60; `0` restores
  one row per denial), repeats of the same `account-creation-denied` reason
  **update the row already on disk** — exact `denial_count`, `last_seen`, and
  a bounded set of digests of the distinct `kid`s offered. The count is written
  on every increment, so a crash mid-window keeps it. Coalescing keys on
  `(event_type, reason)` and deliberately not on `kid` or requester, which
  would let a peer defeat the bound by varying one character. Only the
  unauthenticated denial path is coalesced; issuance, revocation and admin
  events keep one row each. Separately, attacker-controlled detail values are
  truncated at 256 chars with a SHA-256 of the whole value appended, and the
  `details` blob is capped at ~4 KB — bounded at the durable sink, not at each
  call site.

Suite: 795 pytest + 1 skip (was 773 + 1), 218 Pester (was 184), ruff and mypy
clean. The installer still owes a live Windows run before any tag; the two
newly-unobserved behaviours are named in the review doc.

### Security — 2026-08-19 review (six findings; five fixed, one deferred)

An independent source review of `c8ad4c2`. One high, one medium, four low. The
verdict was "fix the installer issue before recommending production
deployment", which is right: F1 is the only one that crosses a privilege
boundary. See `docs/security-review-2026-08-19.md`.

- **The elevated installer executed a destination-local interpreter before
  securing the destination (high, CWE-426).** `install-windows.ps1` probed — by
  executing — `$InstallDir\python\python.exe` at line 286, but did not create
  that directory until line 382 or ACL it until line 533.
  `C:\ProgramData\acme-adcs-ra` is predictable, so a local user who pre-creates
  the tree got their binary run as Administrator on the issuance host, no race
  required. The install root is now claimed and ACL'd (`/inheritance:r`, so an
  attacker-chosen inherited ACL is dropped) before anything beneath it is read
  or executed; a reparse point at the root is refused rather than followed; and
  the destination interpreter is a candidate only after that claim succeeds.
- **Maintenance credentials no longer live in scheduled-task arguments
  (medium, CWE-214).** The admin and confirm tokens were interpolated into the
  `-Command` text that Task Scheduler persists and `powershell.exe` receives,
  so they were readable from the task definition and visible in process
  arguments. The action now carries a *path*: it loads the tokens from the
  ACL'd `acme-ra.env` at run time into the environment variables
  `Sync-Revocations.ps1` already read. Least privilege is expressed by which
  keys the action loads, and `Build-SyncActionCommand` has no token parameter
  at all — passing one is now a binding error.
- **Generated task source escapes its inputs (low, CWE-78).** Base URL, CA
  config, requester and script path were pasted between bare single quotes
  under an "assume no single quote" comment that nothing enforced. All fields
  now go through `ConvertTo-PsSingleQuotedLiteral`; the test asserts the
  escaped literal round-trips through `Invoke-Expression` to the original
  string, which is what proves it became data rather than code.
- **Order reclaim is one atomic transition (low, CWE-362).** The status change,
  the CA-request marker clear and the mandatory `admin-order-reclaimed` audit
  event were three separate commits, so an interruption could reopen an
  issuance-path order with a discharged marker still set, or with no audit
  event at all. `Store.reclaim_processing_order` now covers all three in one
  `BEGIN IMMEDIATE`, with SIEM fan-out outside it as everywhere else.
- **Request bodies have a read deadline, and Uvicorn has a concurrency ceiling
  (low, CWE-400).** Bytes were bounded; time was not, so a one-byte-per-interval
  peer held a worker indefinitely. Each chunk pull is now bounded by a deadline
  computed from one fixed start instant (default 30s), and
  `server_max_concurrency` (default 256) is passed to Uvicorn as
  `limit_concurrency` for the direct-TLS topology that had no ceiling.
- **Unbounded audit growth from unauthenticated denials stays deferred (low).**
  Same decision as wave 3, same reasoning: auditing pre-auth denials is a
  requirement, and the fix is retention/quota policy on an operator-owned disk.
  Still WI-014.

### Changed — 2026-08-19 hardening and hygiene

- **The RA refuses to start on a non-Windows platform** unless
  `ACME_RA_ALLOW_FAKE_ADCS_BACKENDS=true`. Previously a non-Windows host
  silently selected the fake ADCS legs, producing an RA that answered ACME,
  looked healthy and issued nothing real.
- **`base_url` is validated as a bare origin.** A path, query or fragment
  component now fails at load time — every ACME URL, including the ones a client
  binds its JWS signatures to, is derived from this value. The plaintext-scheme
  check logs loudly rather than refusing; the reasoning is in the review doc.
- **Pester runs on Windows PowerShell 5.1 as well as pwsh 7.** These scripts
  ship on 5.1, and the 2026-08-14 live re-proof found two defects in exactly
  this PowerShell that CI could not see.
- **The CRL evidence gate gained `drain()`**, and the test that flaked
  `windows-import-check` uses it. `_clear` is dispatched via `call_soon` one
  loop turn after a flight settles, so a caller could observe stale `inflight`
  — which matters because `inflight` is the `max_pending` admission signal.
- **Release metadata reconciled in the CHANGELOG.** `pyproject.toml` says
  `1.9.1` but no `v1.9.0`/`v1.9.1` tag or release exists; the newest release is
  `v1.8.0`. Recorded rather than silently tagged — cutting it is an owner
  decision.

### Fixed — 2026-08-14 full E2E lab validation (two defects CI could not see)

The first full live pass over the whole 2026-08-15 → 2026-08-18-wave-3 series.
Both defects are in PowerShell that CI never executes: the Windows job runs
`pytest`, and it never invokes the installer or the revocation scripts. See the
validation log in `docs/pre-pilot-checklist.md`.

- **The pinned installer could not install on Windows at all (blocker).**
  `install-windows.ps1` rejected pip 26.2.1 as "too old for `--require-hashes`".
  `(& $venvPy -m pip --version) 2>&1` is a two-element `Object[]` — the banner
  plus pip's trailing empty line — and `-match` against an array *filters* it
  rather than capturing, so `$Matches` stayed unset, `$Matches[1]` read as
  `$null`, `[int]$null` was `0`, and the `-lt 23` floor fired. Live from
  `fb3a14e`, which added the floor check, so every fresh install on the RA's only
  production platform was broken for the whole series. The parse moves to
  `Get-PipMajorVersion` in `scripts/lib/InstallVerifyLib.ps1` and returns `-1`,
  not `0`, for an unparseable banner so "cannot tell" can never read as
  "ancient".

- **The 2026-08-18 wave-3 F1 fix was inert in exactly the case it existed for.**
  `Test-SerialRevokedAtCa` detected a disposition-21/reason-8 row correctly and
  was then defeated by its own diagnostics: a PowerShell function returns
  everything written to the success stream, so three `Write-Output` calls before
  `return $false` yielded `@(three strings, $false)` — and the call site,
  `if (Test-SerialRevokedAtCa ...)`, reads a non-empty array as **true**. Against
  the real CA, a certificate taken off the CRL and left **valid** was reported
  "ALREADY revoked" and exited 6, which drains the serial off the RA's pending
  feed and records `revocation-ca-confirmed` — a containment failure booked as a
  success. Both branches of the function were affected. Diagnostics now go to
  `[Console]::Error.WriteLine`, the idiom this file already documents for
  values that must not become a return value. The function lives in
  `Revoke-Cert.ps1` rather than `lib/`, so nothing covered it; the new tests
  AST-extract the shipped text and assert the caller's truthiness rather than
  `-Be $false`, which the defect would have passed.

### Security — 2026-08-18 wave 3 (seven findings; two already closed, four fixed, one deferred)

A standard review of `d26b892`, run in parallel with the rescan of the same
commit — so its CRL-redirect and twin-migration findings were already closed at
HEAD by `83abd62`. Two medium and three low were new. See
`docs/security-review-2026-08-18-wave3.md`.

- **ADCS disposition 21 is no longer read as proof of revocation (medium).**
  `scripts/lib/RevocationLib.ps1` records the lab finding that a certificate
  given reason 8 (`removeFromCRL`) ends up off the CRL and **valid** while ADCS
  keeps disposition 21 — but `Test-SerialRevokedAtCa` returned true for any
  disposition-21 row (making the sync agent exit 6, drain the serial off the
  pending feed and record `revocation-ca-confirmed`), and the reconciler counted
  it in sync. Both now check the reason: `Revoke-Cert.ps1` adds a
  `Request.RevokedReason=8` restrict clause and re-revokes on a match, and
  `Reconcile-Revocation.ps1` exports the reason so a reason-8 row reports drift.
  A disposition-21 row with *no* reason is still revoked, so an older export does
  not turn the estate into drift.
- **`audit_offbox_required` now proves delivery, not configuration (medium).** It
  asserted only that a SIEM emitter had been constructed from valid-looking
  config, so a revoked HEC token or an endpoint answering 403 let the RA issue
  certificates believing an off-box audit trail was in force. `create_app` now
  runs a real delivery probe when off-box audit is required and refuses to start
  if it fails; a UDP syslog probe explicitly reports what it could *not* prove.
  Off-box delivery failures are counted (`offbox_failures`, `offbox_delivered`,
  `offbox_last_error`) rather than only logged.
- **certsrv responses are bounded before buffering (low).** Every call was
  non-streaming, so the size cap — and the declared `Content-Length` check —
  ran after `requests` had the whole body resident. `_NoRedirectSession` now
  streams (same place `allow_redirects=False` lives, so no protocol or test fake
  changes), oversized declared lengths are refused before a byte is read, and the
  body is read incrementally to cap+1. The Negotiate 401 challenge drain is
  bounded to 64 KiB.
- **The revocation confirmation flag and its audit event commit together (low).**
  `ca_crl_updated` committed first on a separate connection, and it is what
  removes the serial from the retry feed — so a crash in between lost the
  `revocation-ca-confirmed` event permanently, with the route's idempotence check
  preventing any repair. Now one `BEGIN IMMEDIATE`, with SIEM fan-out after the
  commit.
- **Deferred:** unbounded `audit_log` growth from unauthenticated newAccount
  denials (tracked as WI-014). Retention is already operator-owned in
  `docs/operations.md`, and the remediation is a subsystem with its own security
  design rather than an end-of-wave patch.

### Security — 2026-08-18 rescan (two findings)

A rescan of `d26b892` that **confirmed all five 2026-08-18 fixes closed** and
found two more — both introduced by those fixes. One medium, one low, both
fixed. See `docs/security-review-2026-08-18-rescan.md`.

- **The legacy JWK canonicalization migration no longer crashes startup or
  preserves a duplicate key (medium).** It canonicalized rows one at a time with
  only advisory duplicate detection, so a database holding one key under two
  encodings either raised an uncaught `UNIQUE constraint failed` out of `Store`
  construction (index present) or came up serving **both** rows with the same
  canonical key (index absent) — preserving the exact deactivation bypass the
  migration existed to remove. Now two passes: canonicalize in memory, group by
  the thumbprint each row will hold, and raise `StoreMigrationError` naming the
  colliding accounts before any write. A post-migration SQL invariant re-checks
  for duplicates on every start. Note the operational consequence: **a database
  containing a staged twin will refuse to start**, by design; audit for
  canonical-thumbprint collisions before deploying.
- **CRL redirects are off by default, and the origin check is exact (low).** The
  port rule accepted the target scheme's default port as an alternative to the
  configured one, so `http://host:8080` could redirect to `http://host:80` and
  `https://host:8443` to `https://host:443` — same host, different service, which
  is what the check claimed to forbid. Hostname equality also did not bind the
  resolved address, so DNS could rebind a later hop. New
  `ACME_RA_REVOCATION_CONFIRM_CRL_FOLLOW_REDIRECTS` (**default false**) removes
  the hop entirely unless a deployment needs it; when enabled, the effective port
  must equal the origin's bar one documented http:80 → https:443 upgrade, and the
  host must keep resolving inside the address set seen at the start of the
  retrieval.
- **The CRL deadline reason no longer depends on which mechanism won the race
  (found while landing the rescan, not a scan finding).** Clamping the per-hop
  socket timeout to the wall-clock remaining made it expire at the same moment
  the watchdog fires — and when the socket timeout won, nothing set the
  watchdog's flag, so the outcome was reported as a generic "CRL read failed"
  instead of a deadline. Linux won the race one way and Windows the other. The
  reason is now the flag *or* the clock, with the underlying transport error kept
  in the detail; a genuine error before the deadline still reports itself.

### Security — 2026-08-18 scan (five findings)

A standard scan of `8a4baca`, the branch that closed the 2026-08-17 findings.
Two medium, three low; all real, all fixed. See
`docs/security-review-2026-08-18.md`.

- **CRL retrieval no longer follows redirects off-host, and its deadline now
  covers connection setup (medium).** `fetch_crl_evidence` validated only the
  configured URL and then let `requests` resolve the whole redirect chain inside
  one call — reading redirect bodies outside the byte budget, against
  destinations nothing revalidated, before the watchdog was armed. Redirects are
  now followed by hand with a four-hop cap; every hop must stay on the
  configured host (path redirects and http→https upgrades still work, a
  different host/port, an https→http downgrade, or a non-HTTP(S) scheme is
  refused); and the watchdog is armed before the first request so connect, TLS
  and header time count against the total deadline.
- **Revocation reconciliation can no longer report PASS with certificates live
  at the CA (medium).** `reconcile_revocation.py` used disposition 3 as "issued"
  where ADCS uses 20, dropped unparseable rows silently, compared only the set
  intersection of the two inventories, and ignored `quarantined` certificates —
  which are live at the CA. `Reconcile-Revocation.ps1` also ignored `certutil`'s
  exit status. PASS now requires full coverage: every RA serial must be
  accounted for in the export, the export must parse cleanly, and a new exit
  code **2 (INDETERMINATE)** covers everything else. Quarantined rows count as
  must-be-revoked.
- **A pending CA request is now durable state that blocks retry (low).**
  `certfnsh.asp` returns a pending disposition with a ReqID; the leg raised it
  as a generic transport error with the ReqID only in the message, so nothing
  recorded which request was outstanding and administrative reclaim could reopen
  the order on an operator's "no certificate was issued" assertion — true when
  made, false once an officer approves. New `EnrollmentPending` exception
  carrying the ReqID, a new `orders.pending_ca_request_id` column written before
  finalize returns, and reclaim refuses until the operator names that exact
  ReqID via `?ca_request_resolved=<id>`.
- **Equivalent JWK encodings no longer produce separate accounts (low).**
  Verification accepted padded base64url and non-minimal leading-zero integers
  into an identical key while `jwk_thumbprint` hashed the member strings, so one
  key could hold several accounts and deactivating the observed one left a twin
  usable. JWK integer members must now be canonical: unpadded base64url, no
  trailing bits, minimal for RSA `n`/`e`, exact curve width for EC `x`/`y`.
  Stored account JWKs are re-encoded in place on upgrade (same key, canonical
  spelling); two rows normalizing to one key are logged for the operator rather
  than merged.
- **The CRL deadline watchdog now works on Windows (found while landing this
  round, not a scan finding).** Winsock does not wake a `recv` parked in another
  thread on `shutdown()` — only `closesocket()` does — so the 2026-08-17
  watchdog set its flag and achieved nothing on the RA's production platform: CI
  measured a 0.5s total deadline overshooting to 8.0s, the per-read bound.
  `_abort_transfer` now also closes the socket on `win32`; POSIX keeps
  shutdown-only.
- **A stale CRL single-flight callback can no longer evict its successor
  (low).** Cleanup popped by key unconditionally, so a callback arriving after a
  successor had taken the key removed the live successor — letting further
  callers submit duplicates and dropping the successor out of the admission
  count. Cleanup is now identity-checked.

### Security — 2026-08-17 scan (four findings)

A scan of `38f2638` that **closed three of the four preceding findings** and
reported the CRL work as only partially done. One medium, three low; all real,
all fixed. See `docs/security-review-2026-08-17.md`.

- **The elevated installer no longer runs an unverified MSI (medium).**
  `install-windows.ps1` hash-pinned its whole Python runtime and build closure,
  then accepted `-HttpPlatformHandlerMsi http://…` and handed the downloaded
  bytes to `msiexec /i` as Administrator with no digest and no signature check —
  every Python artifact pinned, the one executable artifact not. Plaintext HTTP
  is now refused outright; a remote source requires the new
  `-HttpPlatformHandlerSha256`; and every source, local included, must carry a
  `Valid` Authenticode signature whose publisher matches
  `-HttpPlatformHandlerPublisher` (default `CN=Microsoft Corporation`). Nothing
  reaches msiexec if any check fails.
- **The confirmation body is bounded (low).** The route consumes one boolean and
  read it with `request.json()`, which buffers the whole body before decoding —
  the only attacker-reachable body in the codebase without the streaming cap the
  JWS routes already had. The cap moved to a shared
  `acme_adcs_ra.http_body.read_body_limited` used by both, and the read moved to
  the top of the handler so an oversized body is rejected before any external
  work. New `ACME_RA_MAX_ADMIN_BODY_SIZE_BYTES` (default 4096).
- **Three ways past the CRL resource controls, closed (low).** (a) The store
  canonicalizes serials internally, so `A`/`0A`/`00A` are one certificate — but
  the route kept its own half-normalized spelling as the single-flight key, so
  each alias started its own retrieval. The route now canonicalizes with the
  store's own function and keys the gate by `cert.id`. (b) `max_workers` bounds
  what runs, not what is admitted, and the executor's queue is unbounded: new
  `ACME_RA_REVOCATION_CONFIRM_CRL_MAX_PENDING` (default 32) sheds with 429 +
  Retry-After instead of queueing. (c) A **non-chunked** trickle never reached
  the per-chunk deadline check at all — a 0.3s deadline ran past 20s. Retrieval
  now reads per socket read and a watchdog shuts the socket down at the
  deadline, which also bounds a peer that goes silent after its headers (8.01s
  → 0.50s).
- **A failed confirmation callback no longer wedges reconciliation for ever
  (low).** The sync agent revokes at the CA then confirms to the RA; if that
  POST failed, the next sweep re-revoked, saw certutil's non-zero
  already-revoked result, booked it as a failure and skipped the confirmation —
  permanently, from one transient network fault. `Revoke-Cert.ps1` now
  recognizes an already-revoked CA state, makes no change, and exits **6**,
  which the agent treats as "confirm it anyway". The requester check still runs
  first, so a mis-requested certificate still fails closed.

### Security — 2026-08-16 rescan (four findings)

A rescan (Codex, with Daybreak Blue) of `fb3a14e` that **confirmed all four
2026-08-16 fixes** and found four more: one medium, three low, all real, all
fixed. See `docs/security-review-2026-08-16-rescan.md`.

- **Legacy certificate rows are backfilled with their serial (medium).**
  `serial_number` is the only key `revokeCert` resolves a certificate by, and
  the migration that introduced it left every pre-existing row `NULL` — so on
  any upgraded deployment, every certificate issued before that point answered
  its owner's revocation request with 404 and stayed trusted until expiry, with
  no signal (the pending-revocation feed skips those rows too). The migration
  now re-derives each missing serial from the row's own `cert_pem`, and a
  post-migration invariant runs on every start. Deliberately strict: an
  unparseable PEM or two rows deriving one serial for one account raise
  `StoreMigrationError` and the RA refuses to start, because an underived
  serial has no fallback path.
- **The default revocation script no longer claims a publication it skipped
  (low).** `Sync-Revocations.ps1` passes `-SkipPublishCrl` by default (a
  least-privilege officer cannot republish), and `Revoke-Cert.ps1` honoured it
  and then said "the CRL is published" anyway — contradictory containment
  evidence in one operator-facing log. The completion text moved to
  `Get-RevocationCompletionMessage` with two distinct branches; the skip path
  reports `PARTIALLY complete` and says not to close containment on it alone.
- **Revocation audit metadata comes from the stored certificate (low).**
  `revokeCert` bound the request to state by `(serial, account_id)` only, so an
  owner could submit a same-serial self-signed certificate and have its SANs
  recorded in the mandatory `certificate-revoked` event. The submitted
  certificate must now match the stored one byte for byte (RFC 8555 §7.6 has
  the client submit the certificate it was issued, so this costs a compliant
  client nothing), and audit SANs are derived from the stored PEM regardless.
- **CRL retrieval is bounded and isolated from enrollment (low).** `requests`'
  timeout is per-read, so a trickling server never tripped it and held a worker
  indefinitely — a worker drawn from the same pool as ADCS enrollment. Adds a
  wall-clock `revocation_confirm_crl_total_timeout_seconds` (default 30s), a
  dedicated `revocation_confirm_crl_max_workers` pool (default 2, created
  lazily), and single-flight per serial so a burst of confirmations for one
  certificate costs one retrieval.

### Security — 2026-08-16 external scan (four findings)

First **full-repository** scan since the enrollment-lease work (the two before it
were diff-scoped). Three medium, one low; all four real, all four fixed, none
reclassified. See `docs/security-review-2026-08-16.md`.

- **CRL retrieval no longer blocks the event loop (finding 1).** The confirm
  handler is `async def` and fetched the CRL inline, so a slow endpoint stalled
  every ACME route in the single-process deployment — the same defect the
  enrollment leg was fixed for, on a path that was missed. It now runs via
  `run_in_threadpool`, and an already-confirmed serial short-circuits **before**
  any network work instead of refetching on every retry.
- **Syslog delivery is bounded like HEC (finding 2).** TCP syslog — the shipped
  production setting — emitted synchronously on the issuance path with no socket
  deadline and no queue bound, so a stalled receiver blocked issuance. Both
  off-box sinks now share one bounded queue with drop accounting, and the TCP
  handler has a socket timeout. New `ACME_RA_SIEM_SYSLOG_TIMEOUT_SECONDS`
  (default 5s).
- **The installer no longer resolves anything live (finding 3).** It
  hash-verified the runtime closure while upgrading pip from a live index and
  building through PEP 517 isolation with an unpinned `hatchling`, both elevated
  on an issuance-path host. The pip upgrade is removed (replaced by a version
  floor check), a hash-pinned `deploy/build-requirements.lock.txt` carries the
  build closure, and the project builds with `--no-build-isolation`. Verified to
  build with `--no-index`.
- **`removeFromCRL` is no longer proof of revocation (finding 4).** CRL evidence
  read entry existence only, so a validly signed `removeFromCRL` entry — which
  means a certificate came OFF hold — could satisfy `require_crl_evidence`, drain
  a live certificate from the pending-revocation queue, and record
  `crl-verified`. Reason 8 now returns "not revoked", and a delta CRL
  (`DeltaCRLIndicator`) is refused as standalone evidence. An absent reason still
  counts as revoked (`unspecified`).

### Security — 2026-08-15 hardening rescan (one finding)

A rescan (Codex, with Daybreak Blue) of the two commits below, `5468e0f..f1fd80a`
— one medium finding, high confidence, and the first in the series to arrive with
a working reproduction rather than a source-only hypothesis. It reproduced here
before anything changed. See `docs/security-review-2026-08-15-rescan.md`.

- **An enrollment is now marked in flight for its whole duration.** The
  `ActiveEnrollments` mark added below sat *inside* the worker: a finalize whose
  task was still queued behind a busy threadpool had already committed the order
  to `processing` but was invisible to the reclaim endpoint, and the mark was
  released before the certificate row was written. In either gap a reclaim could
  truthfully observe "no live worker, no certificate", reopen the order, and let
  a second finalize race the first to the CA. The mark now lives in the finalize
  route, covering the `ready`→`processing` CAS, the threadpool hand-off, and the
  completion. It is also reference-counted, so one holder finishing cannot clear
  liveness for another.
- **A durable enrollment lease backs it up.** New `processing_generation` column
  on `orders`: `Store.acquire_processing_lease` (replacing
  `transition_order_to_processing`) is the only way into `processing` and mints a
  monotonically increasing generation. The worker re-checks it via
  `holds_processing_lease` **immediately before `submit_csr`**, so a task that was
  queued across a reclaim abandons — audited `finalize-enrollment-abandoned`,
  `reason=processing-lease-lapsed` — instead of submitting to ADCS. Every
  transition out of `processing` (the enrollment-denied revert, the transport
  orphan, the issuance flip, the finalize self-heal, both reclaim branches) is
  now scoped to the lease its caller holds or observed, so reclaim's read and its
  write are no longer independent critical sections. Upgrade-safe: the column is
  added by the existing migration and defaults to 0; no config or API change.

### Security — 2026-08-15 external scan (four findings)

A third external scan (Codex, with Daybreak Blue), of `v1.9.1` at `5468e0f` —
three medium, one low, none high. Every finding was reproduced before any code
changed. See `docs/security-review-2026-08-15.md` for the full validation,
including the one finding whose stated DoS impact did not survive measurement.

- **Reclaim can no longer race a live enrollment (finding 2).** The reclaim
  endpoint now refuses any order with a live in-process enrollment worker
  (authoritative, age-independent), and the `processing → ready` recovery branch
  requires an explicit `?ca_verified_no_issuance=true` operator assertion rather
  than trusting elapsed time. Closes a double-issuance race.
- **Revocation-task registration is least-privilege (finding 3).** `-AdminToken`
  is now optional; `-RevocationSyncOnly -ConfirmToken …` registers only the sync
  task with **zero admin-token bytes** in its action, so a dedicated revocation
  host no longer carries unrelated maintenance authority.
- **Legacy unauthenticated GET removed (finding 4).** The plain
  `GET /acme/cert/{id}` and `GET /acme/authz/{id}` forms — which bypassed
  account deactivation and EAB-kid eviction — are removed entirely; only the
  account-scoped POST-as-GET forms (RFC 8555 §6.3, §7.4.2) remain. A plain GET
  now returns 405. The `allow_unauthenticated_resource_get` config field is
  removed (a stale `ACME_RA_ALLOW_UNAUTHENTICATED_RESOURCE_GET` env var is
  ignored, not an error). Clients must use POST-as-GET, which every conforming
  ACME client already does.
- **RSA account-key bounds (finding 1, defence-in-depth).**
  `_public_key_from_jwk` now bounds the modulus to `[2048, 16384]` bits and the
  public exponent to `{3, 65537}` before constructing the key, rather than
  relying on the crypto backend to reject oversized values.

## [1.9.1] — 2026-08-14

> **NEVER TAGGED — superseded by 1.10.0 (recorded 2026-08-24).** This section
> describes work that shipped, but under the `v1.10.0` tag; no `v1.9.1` tag
> exists or will be created. Original note follows.
>
> **NOT YET TAGGED (recorded 2026-08-19).** `pyproject.toml` declares `1.9.1`
> and this section is written, but no `v1.9.1` (or `v1.9.0`) tag or GitHub
> release exists: the newest release is **v1.8.0**, with `v1.9.0-rc1` and
> `v1.9.0-rc2` as pre-releases. The 2026-08-19 review flagged the mismatch —
> anyone reading the releases page sees a project that stopped at 1.8.0 while
> the source calls itself 1.9.1. The 1.9 line is *ready* rather than *shipped*:
> the live re-proof that gates the tag passed on 2026-08-14, but several
> security waves have landed since and the tag is an owner decision, not an
> automated one. Cut `v1.9.1` from a commit that has been live-re-proven, or
> renumber, but do not leave the two disagreeing.

> **The release of the 1.9 line.** 1.9.0 never shipped: it existed only as
> `v1.9.0-rc1` and `v1.9.0-rc2`, and the live re-proof that gates the tag found
> two things wrong with rc2 — a red `ruff` gate on its tip, and a
> `Set-OfficerRights.ps1` defect that stopped it provisioning a CA whose
> `OfficerRights` value was absent (the default, so the first-provisioning
> path). Both are fixed here, so the shipped version is **1.9.1** and there is
> no 1.9.0 tag. Everything below is what 1.9.1 contains.
>
> **Live-proven 2026-08-14** against `bef2022`, the exact commit these fixes
> landed on: issuance, both transport-orphan branches, the revocation round
> trip, the confirm-authority split and CRL evidence verified against a real
> ADCS CRL all pass. Three residuals are open and none blocks the release. See
> the [validation log](docs/pre-pilot-checklist.md#validation-log).

### Security — 2026-08-14 external scan (seventeen findings)

A second external scan, of `v1.9.0-rc1`. Every finding was reproduced before any
code changed; every new test was mutation-checked and has a negative control.
See `docs/security-review-2026-08-14.md`, which also records what it did **not**
prove and the one place the stricter default was deliberately not taken.

> ### ⚠️ Additional upgrade requirements
>
> **5. ACME reason 8 (`removeFromCRL`) is rejected.** It is the inverse of
> revocation and reached `certutil -revoke <serial> 8` verbatim, so a revokeCert
> carrying it recorded a *successful* revocation in the RA while asking the CA
> to take the certificate back off the CRL. Plan 004 confirmed the CA-side
> effect against the lab: the certificate ends up "off the CRL and valid".
> Tooling that submitted reason 8 now gets a 400 (or exit 3 from
> `Revoke-Cert.ps1`); there is no replacement.
>
> **6. `deploy/requirements.lock.txt` is required by the Windows installer.**
> Dependencies now install from a hash-pinned closure with `--require-hashes`,
> not a live resolve. An incomplete copy fails rather than silently resolving
> from the index.
>
> **7. `admin_token` and `revocation_confirm_token` must differ**, and
> **`siem_hec_queue_max` must be ≥ 1.** Both now refuse startup.
>
> **8. `Verify-TemplateEnrollment.ps1` exits 3** when principals outside
> `-ExpectedEnrollee` hold enroll. Pass `-AllowAdditionalEnrollees` to accept
> them deliberately.

- **Certificates orphaned by a post-issuance *transport* failure are now
  quarantined.** The 2026-08-13 review covered the three post-issuance verifier
  rejections but not the window after `certfnsh.asp` returns "issued" with a
  ReqID — the leaf fetch, the chain fetch, and the chain-binds-to-leaf check. A
  failure there recorded only an error string (no serial, no ReqID) and returned
  503 with the order left `processing`, leaving a live domain-trusted
  certificate untracked at the CA. The error now carries what the CA committed
  to, and finalize quarantines it; where only the ReqID is known, that is made
  loud in the audit row and the log instead.
- **The enrollment leg refuses redirects.** `requests` strips `Authorization`
  across a cross-host redirect, but that does not apply here — `NegotiateAuth`
  registers a 401 *response hook*, so a redirect to a host answering
  `401 Negotiate` would draw a freshly minted gMSA ticket out of the RA.
- **Finalize no longer blocks the event loop.** The handler is `async def`, so
  FastAPI runs it on the loop rather than in a threadpool; the synchronous CA
  call (30 s default timeout) stalled every other request in the process.
- **Revocation, its order transition, and its audit row commit in one
  transaction** (`Store.record_revocation`), matching `record_issuance`.
- **CRL evidence is freshness-checked and its issuer pinned by signature.** A
  signed CRL verifies for ever, so a CRL with no `nextUpdate` was accepted
  indefinitely and `thisUpdate` was never checked. Issuer selection matched on
  subject DN alone, which picks the wrong generation after a CA key renewal.
- **The revocation agent no longer needs the admin token** — the pending list
  accepts the confirm token, so the revocation host stops carrying authority to
  reclaim orders and drain nonces.
- **Reclaim refuses an order that may still be enrolling**, closing a
  double-issuance race its only check ("no certificate row") could not see.
- **One account per key**, enforced by a partial `UNIQUE` index; the route
  resolves a lost race by returning the winning account.
- **The sync agent reports `crl_published` honestly** instead of letting
  `ca_crl_updated` imply a publication the default least-privilege path
  deliberately skips, and **counts a failed confirmation** so the exit code
  reflects a CA/RA disagreement.
- Enrollment responses are size-capped before parsing.

### Fixed — 2026-08-14 (live re-proof of rc2)

- **`Set-OfficerRights.ps1` could not provision a CA that had no
  `OfficerRights` value — the default, and therefore the first-provisioning
  path.** It aborted with `Exception calling "Write" ... Buffer cannot be null`
  and wrote nothing, while the CA-side grant that precedes it *had* been made,
  so the CA looked half-configured. Cause: the 2026-08-13 fix for the
  single-element unwrap wrapped every return in `,$result`, which makes `,@()`
  arrive at the call site as a **one-element array holding an empty array** —
  so `@(Get-ExistingAces $bytes).Count` was 1 with no ACEs, and the phantom
  entry reached the ACE builder with a `$null` RawAce. The contract is now
  stated where it belongs: the function returns plainly and the call sites wrap
  in `@()` (both already did). `Set-OfficerRights.ps1` additionally drops
  entries with no ACE bytes before building. Found on the lab CA, 2026-08-14.
- **Two Pester tests asserted a shape the shipped code never uses.** They
  bound the result with `$result = Get-ExistingAces ...`, and assignment
  collapses a single-item pipeline back to the item — so the empty case looked
  correct while `@(...)` at the real call site did not. They now assert the
  call-site expression, and two count tests cover the empty and single-ACE
  cases. Reverting the library fix fails them.
- **`TestHecQueueBound` was flaky.** It relied on `.invalid` DNS *stalling* to
  pin its workers; a resolver returning NXDOMAIN quickly lets them drain, so the
  drop count came in under what the test expected. It failed once during a full
  run. The workers are now pinned with an explicit barrier, making the bound
  exact on any machine.

**Security hardening (2026-08-13 external scan).** Ten findings — nine medium,
one low — from an external static scan of v1.8.0. Every one was independently
reproduced against the shipped build before any code changed, and every new
test was mutation-checked. See `docs/security-review-2026-08-13.md`, which also
records what this review did **not** prove.

The live lab re-proof of these fixes then found **two further defects that Linux
CI structurally cannot see** — both Windows PowerShell 5.1 language semantics
that `pwsh` 7 silently differs on, one of them inside this review's own
finding-8 fix. They are in the **Fixed** section below and are the reason this
release is worth reading past the security summary.

> ### ⚠️ Upgrade requirements — read before deploying
>
> **1. `ACME_RA_REVOCATION_CONFIRM_TOKEN` is now required for the CA-side
> revocation loop.** Confirming a revocation asserts an external event the RA
> cannot observe, so it is no longer the same authority as general maintenance:
> the confirm endpoint requires its own credential and **refuses the admin
> token**. Without it, `POST /acme/admin/revocations/{serial}/confirm` returns
> 401 and serials remain on the pending list. Pass it to
> `Sync-Revocations.ps1 -ConfirmToken` (or `ACME_CONFIRM_TOKEN`);
> `Register-MaintenanceTasks.ps1 -ConfirmToken` forwards it.
>
> **2. Weak credentials now refuse startup.** EAB MAC keys must decode to ≥ 32
> bytes and admin/confirm tokens must be ≥ 32 characters. Regenerate with
> `python scripts/eab.py new`, or set `allow_weak_credentials` for a lab/CI
> fixture only.
>
> **3. The revocation scripts reject non-https RA URLs.** A loopback-http lab
> needs `-AllowInsecureUrl`.
>
> **4. `audit_offbox_required` now fails startup** when the configured sink
> cannot actually emit (previously it checked only the sink's name).

### Security

- **Revocation confirmations are no longer taken on faith.** The confirm
  endpoint requires a dedicated token, and every confirmation records
  `verification: "agent-asserted"` or `"crl-verified"` so the audit trail never
  implies the RA observed a CA-side event it did not. Optional independent
  verification against the CA's published CRL
  (`ACME_RA_REVOCATION_CONFIRM_CRL_URL`) can be made mandatory with
  `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE`; the CRL's signature is
  checked against the issuing CA certificate from the certificate's own stored
  chain, and an expired CRL is not accepted as evidence.
- **Certificates rejected by a post-issuance verifier are now quarantined
  rather than orphaned.** ADCS has already issued by the time the SAN / EKU /
  CA-capability checks run; the RA previously recorded nothing at all — not even
  the serial — leaving a live, unrevocable certificate at the CA. It is now
  recorded as `quarantined` (serial, ReqID, bytes, violations), the order goes
  terminal, and it is queued for CA-side revocation through the existing pull
  agent. It is never served: `get_certificate_by_order` excludes quarantined
  rows and the certificate response serves only `valid`.
- **Issuance and its mandatory audit row now commit in one transaction**
  (`Store.record_issuance`). Fault injection previously left a stored,
  serveable certificate with zero `certificate-issued` events. The issuance
  event now also carries the serial.
- **Invalid nonces are rejected by a read, not a SQLite write.** An
  unauthenticated peer could make every bogus nonce contend for the single
  writer lock; measured, a bogus nonce blocked for the full 5 s `busy_timeout`
  and then raised `database is locked` (a 500, not a 400). Single-use semantics
  are unchanged.
- **EAB MAC keys and admin/confirm tokens have enforced strength floors.** An
  EAB key decoding to zero bytes was previously treated as *present*, letting
  anyone who knew the kid forge the binding with an empty HMAC key.
- **The HEC audit queue is bounded** (`ACME_RA_SIEM_HEC_QUEUE_MAX`, default
  1000). A dead HEC endpoint previously let request-driven audit events
  accumulate without limit; overflow now drops from the HEC sink only — never
  from the local audit table — and is counted and logged.
- **`audit_offbox_required` asserts the constructed emitter**, so a deployment
  can no longer claim the off-box audit gate while emitting nothing.
- **Malformed JWS input returns ACME 4xx instead of 500.** Three
  unauthenticated crashes: a non-object EAB protected header, a non-string
  nonce reaching SQLite parameter binding, and a non-ASCII EAB payload reaching
  the timing-equalisation helper's ASCII encode.
- **`Sync-Revocations.ps1` / `Register-MaintenanceTasks.ps1` validate the RA URL
  before attaching the token** — https only, no embedded credentials, no query,
  fragment, or path. A scheduled task bakes the URL in, so a typo would have
  disclosed the token on every run.
- **`Set-OfficerRights.ps1` proves activation before reporting success.** The
  CA loads `OfficerRights` at service start, so a written-but-not-reloaded
  restriction is not in force. `net start` failure is now fatal, the service
  must be `Running`, the process must have actually recycled, and the readback
  asserts the target officer's ACE landed (or is gone, for `-Remove`) instead of
  merely printing it. `Get-OfficerRightsBytes` reads the registry provider
  first rather than regex-scanning `certutil` console text.

### Fixed

- **`Set-OfficerRights.ps1` aborted on a *successful* single-officer
  provisioning.** `Get-ExistingAces` returns an array, but PowerShell unwraps a
  single-element array across a function boundary, and a bare `[pscustomobject]`
  has **no `.Count` under Windows PowerShell 5.1** (pwsh 7 yields 1, which is
  why the Pester suite was green). With exactly one ACE — the default, documented
  single-officer deployment — the script reported an in-force restriction as
  "absent — unrestricted", then failed its own readback assertion and exited 1
  after correctly writing and loading the restriction. An operator, or any
  automation treating a non-zero exit as failure, would conclude the CA-side
  least-privilege control had not been applied. The library now always returns an
  array and both call sites wrap defensively. Found by the live lab re-proof of
  the 1.9 line; the assertion itself came from the 2026-08-13 review, finding 8.
  See also the 2026-08-14 entry below: this fix was itself half wrong.

- **`Sync-Revocations.ps1` aborted the whole batch on the first failed revoke.**
  `& $pwshExe @revokeArgs 2>&1` turns the child's stderr into ErrorRecords, and
  under the script's own `$ErrorActionPreference='Stop'` the first one is a
  *terminating* error — so the per-serial "log it and continue" handling, the
  requester-mismatch abort (exit 5) and the partial-failure exit code (2) were
  all unreachable, and a single bad serial silently stranded every serial behind
  it while the script exited 1. The child invocation moved to
  `SyncLib.ps1::Invoke-ChildScript`, which suppresses `Stop` for the duration of
  the call. Pre-existing (not introduced by the 2026-08-13 review); it only bites when a revoke
  fails, which no previous re-proof had provoked. **Note:** this cannot be
  regression-tested on Linux CI — pwsh defaults
  `$PSNativeCommandUseErrorActionPreference` to `$false`, so a "does not throw"
  assertion passes with the fix reverted (verified by mutation). See the note in
  `tests/pester/Sync.Tests.ps1`.

- **`Assert-SafeRaUrl` never recognised an IPv6 literal loopback.**
  `[System.Uri].Host` renders IPv6 in bracketed form (`[::1]`), so comparing it
  against `::1` meant `-AllowInsecureUrl` silently did not apply to an IPv6
  loopback lab. Fail-closed, so not exploitable — but wrong, and it would have
  read as a mysterious rejection during a lab setup.

- **`__version__` reported `0.1.0`.** The literal in `acme_adcs_ra/__init__.py`
  had never been updated because nothing read it; it now derives from the
  installed distribution metadata, so it cannot drift from `pyproject.toml`
  again. A test asserts the two agree.

### Changed

- `scripts/lib/SyncLib.ps1` is now dot-sourced by `Sync-Revocations.ps1` rather
  than being a test-only copy, so the URL validation the Pester suite exercises
  is the code that actually runs.
- `/acme/admin/revocations/pending` entries carry `status`, distinguishing a
  client-requested revocation from a quarantined mis-issuance.

## [1.8.0] — 2026-08-11

**Security hardening (2026-08-11 pre-deployment review).** Thirteen findings
across the ACME front, the account lifecycle, the unauthenticated surface, the
enrollment leg's chain handling, and the deployment artifacts — twelve from the
review itself and one more found while reading real `certutil` output during the
live re-proof. See `docs/security-review-2026-08-11.md`.

> ### ⚠️ Upgrade requirement — read before deploying
>
> **`ACME_RA_BASE_URL` is now security configuration, not a display value.**
> Every JWS and EAB binding is validated against the URL derived from it rather
> than against the URL the request arrived on. Set it to the *exact* public
> origin clients use — scheme, host **and port**. If it does not match, every
> legitimate request is refused (fail-closed) from the first request after
> upgrade.
>
> A deployment where `base_url` was merely approximately right — the loopback
> host, the wrong port, `http` where clients use `https` — worked before this
> release and will not after it. That is the intended behaviour: the old
> permissiveness *was* the vulnerability.
>
> Two operator controls also move from recommended to **required**: an off-box
> audit sink (`ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with syslog or HEC) and the
> network allowlist in front of the unauthenticated nonce endpoint. See
> `docs/pre-pilot-checklist.md` §C/§E.

### Security
- **JWS and EAB URL bindings now pin to `base_url` (MEDIUM).** Both were
  previously derived from `str(request.url)` — i.e. from the client's `Host`
  header — so they only proved the client was self-consistent. An EAB minted for
  a different deployment verified here, which meant the 2026-08-07 "EAB
  cross-endpoint replay" fix was not actually closed. `kid` must now also start
  with this RA's configured account-URL prefix.
  **Operator impact: `ACME_RA_BASE_URL` is now load-bearing** — it must be the
  exact public origin, or every request fail-closes.
- **Accounts can be disabled (MEDIUM).** `account.status` and the account's EAB
  kid are re-checked on every authenticated request. Removing a kid from
  `eab_allowlist` previously stopped issuance but still let the account create
  orders, roll its key, and **revoke its own live certificates**. RFC 8555
  §7.3.6 deactivation is implemented as the client-side kill switch. Both
  rejections are audited (`account-deactivated`, `account-request-denied`).
- **Interactive API docs disabled (MEDIUM).** `/docs`, `/redoc` and
  `/openapi.json` published the full route inventory, including every
  `/acme/admin/*` endpoint, to any unauthenticated caller.
- **Off-box audit gate (MEDIUM).** New `audit_offbox_required` refuses startup
  unless audit events leave the host. The default `jsonl` sink writes next to
  the database, so a host compromise destroyed the audit trail and its only
  mirror together.
- **Issued chain bound to the issued certificate (LOW).** `certnew.p7b` is a
  separate fetch that was stored and served unvalidated; a chain certificate
  must now match the leaf's issuer *and* verify its signature.

### Fixed
- **Nonce-endpoint flood ceiling (MEDIUM).** `/acme/new-nonce` is
  unauthenticated and each call is a SQLite write, so a flood contended for the
  single writer with the issuance path. An in-process token bucket now bounds it
  *before* the write (`nonce_rate_limit_per_second`, default 20/s, burst 100).
- **Advertised resource URLs resolve (MEDIUM).** newOrder's `Location`,
  newAccount's `Location` and the account `orders` link all returned 404, so a
  conforming client that polls the order URL could not complete. Adds
  account-scoped POST-as-GET for order, account, orders-list, authorization and
  certificate resources, and RFC 8555 §6.3 empty-payload handling.
- **`certfnsh.asp` pending detection** now scans the comment/script-stripped
  body like every other step of the parser.
- **`keyChange` malformed `oldKey`** returns 400 instead of an unhandled 500.
- **Serial canonicalisation.** One `canonical_serial` helper on every path, so a
  `certutil`-shaped (zero-padded, lowercase) serial matches the stored form and
  the revocation-confirm callback cannot 404 into an endless re-revoke loop.
- **App version** is read from installed distribution metadata (it had drifted
  to `1.6.0` against a `1.7.0` release).
- **Serial form vs the ADCS database (found during the live re-proof).** ADCS
  stores the full byte string, so a certificate whose high-order byte is `0x0N`
  is recorded with a leading zero the RA's `format(n, 'x')` form never has, and
  `-restrict "SerialNumber=…"` is an exact match — the lookup would find 0 rows
  and `Revoke-Cert.ps1` would exit 4, silently stopping the automated revocation
  loop for that certificate. `Get-CaSerialForm` re-pads to even length;
  `Revoke-Cert.ps1` now dot-sources `scripts/lib/RevocationLib.ps1` (removing the
  test-only-copy drift risk noted in v1.6.0).

### Live re-proof
- **PASSED (2026-08-11)** against commit `db06c6f` on the lab RA host (ADCS CA,
  Mode A). 26 checks, 26 passed: the standing issuance proof (serverAuth-only
  EKU, SAN from the CSR, chain off the existing CA, policy denial, reason-7
  rejection) plus every new control — EAB/Host/kid rebinding, POST-as-GET
  resources, docs 404, nonce flood capped, account deactivation, and the
  revocation round-trip through `Revoke-Cert.ps1` and the confirm callback.
  The chain-binding check accepted the real CA's `certnew.p7b` (the check that
  no unit test could validate). Account eviction was proven with a control
  confirming the allowlist had actually reloaded. See
  `docs/security-review-2026-08-11.md`.

### Changed
- `deploy/iis/web.config` sets the off-box audit sink and an explicit global
  order ceiling, and documents that the network allowlist is required rather
  than recommended.
- The no-signing-key guardrail's importlib allowlist admits
  `importlib.metadata` (data-only, like `importlib.resources`), with two new
  negative controls asserting `importlib.machinery` still trips the detector.

## [1.7.0] — 2026-08-08

**Security hardening (2026-08-07 review), no new feature surface.** Closes
nine findings across the issuance leg, the ACME/JWS front, rate limiting,
and the dependency closure. Live re-proven against ADCS on the lab. The
issuance path is behaviourally unchanged for legitimate requests.

### Security
- **CA-capable CSR/cert rejection (HIGH).** A dangerously drifted template
  returning `CA=true` or signing key usage while carrying serverAuth EKU is
  now rejected at CSR intake (`_reject_ca_capable_csr_extensions`) **and**
  independently on the issued certificate (`_issued_cert_ca_capability_violations`)
  before it is recorded or served. Reinforces the no-signing-key-ever invariant.
- **CN bound to SAN set.** The template takes the subject from the CSR, so a
  CSR/issued-cert Common Name must be a member of the requested DNS SANs,
  closing the legacy-CN second identity path (`_reject_unrequested_common_names`).
- **certsrv response bound to CSR key.** The production enrollment leg now
  compares `SubjectPublicKeyInfo` bytes and the subject CN against the
  authorized SAN set, failing closed on a mismatch
  (`_validate_issued_certificate_binding`).
- **Algorithm exactness.** RS/ES alg names are exact-matched (no `startswith`),
  EC algorithms are curve-matched to their key, and RSA account keys require
  ≥2048 bits. Eliminates algorithm-confusion and weak-key acceptance.
- **EAB URL binding.** The EAB protected-header `url` must equal this RA's
  `newAccount` endpoint, preventing cross-endpoint/environment replay.
- **HEC HTTPS enforcement.** The SIEM HEC sink enables only for HTTPS URLs
  without embedded credentials, so its bearer token cannot be sent in plaintext.

### Fixed
- **Rate-limit TOCTOU.** Order count-and-insert is now one `BEGIN IMMEDIATE`
  transaction (`create_order_with_authz`), so a parallel burst cannot all
  observe a below-limit count and race past the ceiling.
- **JWS body streaming cap.** Unauthenticated request bodies are bounded by
  `max_jws_body_size_bytes` (default 64 KiB), enforced on declared
  `Content-Length` and while streaming, before JSON/base64 decoding.
- **Type-confusion hardening.** Every JSON-decoded protected header, payload,
  and JWK is now checked to be a JSON object.
- **Dependency:** `cryptography` floor raised to ≥50.0.0 (PYSEC-2026-3552).

### Added
- `docs/security-review-2026-08-07.md` — the review itself.
- `tests/test_issuance_security_bindings.py` — regression tests for the
  CA-capable, CN-binding, and key-binding checks.

### Changed
- `max_jws_body_size_bytes` config knob (default 65536) added to `RAConfig`.

### Live re-proof
- **PASSED (2026-08-08)** against commit `5d30937` on the lab RA host (ADCS
  CA, Mode A). Core 12 cases + 3 new CSR-rejection checks. CA DB confirmed
  requester = the enrollment gMSA, template = `ACME-ServerAuth`. See
  `docs/pre-pilot-checklist.md` validation log.

## [1.6.0] — 2026-07-24

**Hardening + validation sweep (Plan 007), no new feature surface.** The
issuance path is behaviourally unchanged.

### Fixed
- **Finding E-1 (enrollment-side blast radius) — remediated (WI-035).** The
  enrollment gMSA held `Machine`-template enroll rights via Domain Computers
  membership, so a compromised gMSA that *bypassed* the RA was not ACL-bounded to
  `ACME-ServerAuth`. Remediated by moving the gMSA off the Domain Computers enroll
  path (`primaryGroupID` change); verified live three ways (template ACLs, the
  gMSA's Kerberos token, an issuance regression). It now enrolls only
  `ACME-ServerAuth`. See `docs/revocation-scope-validation.md`.

### Added
- **PowerShell test coverage (WI-037).** The pure logic of the operator scripts
  is extracted into dot-sourceable `scripts/lib/*.ps1` and covered by a Pester
  suite (61 tests) that runs on the Linux CI runner under `pwsh` — including a
  **golden-bytes** regression test for the `OfficerRights` SD/ACE builder and the
  scheduled-task action-string builder. **Deploy the whole `scripts/` directory
  including `scripts/lib/`** (the officer/registration scripts dot-source it).
- **Live re-proof runbook (WI-038)** — `docs/live-reproof-runbook.md`: the
  repeatable ADCS-integration re-proof (issuance + EKU + both revocation
  topologies), its cadence, and the standing note that **green CI ≠ ADCS-verified**
  (cloud CI cannot reach a CA).
- **Two-identity topology — proven live end-to-end (WI-036).** A dedicated
  revoker gMSA (a *separate* identity from the enrollment gMSA) revoked an
  `ACME-ServerAuth` cert at the CA and confirmed it back to the RA, with the WI-022
  requester check active and the enrollment gMSA holding **no** officer rights
  throughout (compromise independence). *Operator note:* create the revoker gMSA
  with explicit AES Kerberos etypes (`-KerberosEncryptionType AES128,AES256`) —
  without them RC4 is added and, if blocked on the DCs, the account is unusable.

### Changed
- **Deterministic CI (WI-039).** CI installs via `uv sync --locked` (respects
  `uv.lock` for all deps); `ruff`, `mypy`, and Pester are pinned. A dependency
  bump is now a deliberate, reviewed `uv lock` change, not a surprise drift.

## [1.5.0] — 2026-07-23

**Automated CA-side revocation + self-enforced serverAuth.** Builds on 1.0.0's
issuance path (behaviourally unchanged) by closing the revocation loop the RA
previously left to a manual operator step, and by making the serverAuth-only
guarantee self-enforcing at finalize. Landed via Plans 004–006. The automated
revocation loop — both the recommended two-identity topology and the opt-in
single-identity (`-LocalMode`) topology — was **live-reproven end-to-end on the
lab (2026-07-23, WI-028)**: base issuance + EKU verification, and the full
round-trip (RA `revokeCert` → CA-side pull agent → CA revoke → RA confirm) with
the WI-022 requester check and the WI-025 template-scoped officer restriction
both active, the least-privilege bound intact (CRL republish denied to the
officer identity), and the confirm loop closing (`ca_crl_updated=true`).

### Added
- **WI-026 — post-issuance EKU verification.** Finalize now inspects the *issued*
  certificate's Extended Key Usage and fails closed (500, audited as
  `finalize-issued-cert-eku-mismatch`, no cert recorded or served) unless it is
  exactly `serverAuth`. This self-enforces the cardinal "blast radius bounded to
  spoofing internal TLS" guarantee, which previously rested solely on ADCS
  template configuration — a template that ever gained clientAuth/PKINIT/anyEKU
  (or issued a no-EKU all-purpose cert) would otherwise silently break it. Sibling
  to the MED-1 SAN check (`finalize.py::_issued_cert_eku_violations`). Validated
  against a real lab ACME-ServerAuth cert (EKU = serverAuth only → passes) plus
  unit coverage for clientAuth/anyEKU/no-EKU rejection; the dev/CI `fake_cert.pem`
  fixture is regenerated as serverAuth-only to match.
- **`-PublishCrl` opt-in for the automated revocation loop.**
  `Sync-Revocations.ps1` / `Register-MaintenanceTasks.ps1` now default to
  least-privilege (revoke at the CA; let the CRL refresh on its scheduled
  publication — the officer identity holds no Manage-CA/CRL-publish right) and
  expose `-PublishCrl` to force an immediate republish where CRL freshness is
  worth granting the identity Manage-CA (an explicit, recorded trade-off — see
  threat-model §E; strongly discouraged in single-identity).

### Fixed
- **Live re-proof of the single-identity revocation path (2026-07-23, on the lab CA).** Provisioned the enrollment gMSA as a template-scoped officer
  and drove the full loop as that identity; confirmed it revokes an
  `ACME-ServerAuth` cert at the CA while the least-privilege bound holds (CRL
  republish denied — needs Manage-CA). The pass surfaced and fixed the defects
  below; CA returned to a pristine baseline afterward.
- **`Revoke-Cert.ps1`: `certutil` argument order.** `-config` was placed *after*
  the `-revoke`/`-CRL` verb, so `certutil` mis-parsed it as positional
  ("Expected no more than 2 args, received 4") and no revoke could complete.
  `-config` now precedes the verb.
- **`Register-MaintenanceTasks.ps1`: gMSA task logon type.** Tasks were
  registered with the default `LogonType=Interactive`; a gMSA never logs on
  interactively, so the task registered but never ran. Now uses
  `LogonType=Password` (or `ServiceAccount` for well-known SIDs).
- **`Register-MaintenanceTasks.ps1`: `-RequesterName` pass-through.** The
  revocation-sync task did not forward `-RequesterName`, so the committed
  `WORK-DOMAIN\…` placeholder made the WI-022 requester check reject every
  revoke. It is now a parameter, forwarded into the task action.
- **`Register-MaintenanceTasks.ps1`: validation false-negative.** The
  post-registration check queried `Get-ScheduledTask -TaskName "\folder\name"`
  (a form that never matches), reporting "registration failed" and exiting 1
  after a successful registration. Now queries by `-TaskName` + `-TaskPath`.
- **`Set-OfficerRights.ps1`: OfficerRights written as REG_SZ.** The primary
  `certutil -setreg <hex>` path stored the blob as a *string* on some builds
  (observed on Server 2025), yielding a malformed, fail-closed value that breaks
  all officer operations. The blob is now written as `REG_BINARY` via the
  registry provider with a raw-bytes readback verify.
- **All `.ps1` scripts: encoding.** Em-dashes/`§`/`→` in the (UTF-8, no-BOM)
  scripts broke Windows PowerShell 5.1 parsing when a non-ASCII char landed in a
  string literal. Normalised to ASCII (`--`, `section`, `->`).

## [1.0.0] — 2026-07-15

Promotion of 1.0.0-rc1 to final. **No issuance-path source changes** since the
lab-proven commit `c283d81` (15/15 E2E cases green, CA database confirms gMSA
requester) — everything between rc1 and this release is documentation, CI, and
release mechanics. The re-proof that gated rc1 gates this release identically.

### Added
- Monthly scheduled CI run — a rot canary for a parked project (dependency
  CVEs via `pip-audit`, Python/runner drift) so decay surfaces as a failed-run
  email rather than at re-entry.

### Changed
- Project status: **parked at 1.0** — feature-complete for its charter, no
  active development planned. `README.md` / `AGENTS.md` document the
  maintenance posture and re-entry pointers. A production pilot remains gated
  on the operator-owned sections of `docs/pre-pilot-checklist.md`, which is
  unchanged.
- The known MED-1 limitation (post-issuance verification covers SANs but not
  EKU; the serverAuth-only guarantee rests on template configuration) is now
  tracked as work item **WI-021** instead of living only in a reflection.

## [1.0.0-rc1] — 2026-07-14

First release candidate. An ACME Registration Authority for ADCS: speaks ACME
(RFC 8555) on the front, holds **no signing key**, forwards CSRs to the existing
ADCS issuing CA over the Web Enrollment surface as a passwordless gMSA. Lab-proven
against commit `c283d81` (15/15 E2E cases green, CA database confirms gMSA requester).

### Added
- **ACME server (RFC 8555 subset):** directory, newNonce, newAccount with **EAB**
  (External Account Binding), newOrder, authorizations + challenge handling,
  finalize (CSR acceptance), certificate retrieval, revokeCert, and keyChange
  (RFC 8555 §7.3.5 account-key rollover).
- **EAB-gated front:** each authorized ACME client gets a high-entropy kid + MAC
  key + SAN scope. The challenge is intentionally a no-op (enterprise trust model:
  EAB + network allowlist + SAN scope is the whole authorization surface).
- **Deterministic SAN-scope policy:** fail-closed — an account with no `san_scopes`
  entry has an empty allow-list and every SAN is denied; subject-only issuance is
  rejected. DNS name validation at order creation (RFC 1123) rejects malformed
  identifiers early.
- **Channel-bound gMSA enrollment:** submits CSRs to `/certsrv/certfnsh.asp` via
  SPNEGO/Negotiate with RFC 5929 `tls-server-end-point` channel binding (in-tree
  `negotiate_auth.NegotiateAuth` over `pyspnego`), authenticated as the service's
  ambient gMSA identity. Works against `/certsrv/` hardened with EPA=Require.
- **Post-issuance SAN verification (MED-1):** the issued cert's SANs are checked
  against the order's authorized set, not just the CSR. A misconfigured template
  that appends an unauthorized DNS SAN or any non-DNS SAN (email, IP, URI) causes
  finalize to fail closed (500 + audit, no cert recorded or served).
- **Deterministic revocation CAS (MED-2):** the `revokeCert` route's CAS
  (compare-and-swap) returns a deterministic `won_cas` signal — no timestamp-
  inference race on concurrent revocation.
- **Out-of-band revocation (WI-010):** `revokeCert` records the revocation in the
  RA store only (cert → revoked, order → revoked, GET → 410 Gone) with an honest
  audit event (`revocation_scope=ra-store-only`, `ca_crl_updated=false`). The
  operator closes the loop with `scripts/Revoke-Cert.ps1` (CA officer, not the
  gMSA). Reason 7 (RFC 5280 "unused") is rejected by both the RA and the script.
- **Revocation reconciliation (WI-017):** read-only `scripts/Reconcile-Revocation.ps1`
  + `scripts/reconcile_revocation.py` compares the RA store against the CA database
  and reports drift in three buckets (in-sync, revoked-in-RA-but-active-at-CA,
  revoked-at-CA-but-valid-in-RA).
- **In-app per-account order rate limiting (WI-016):** deterministic, store-backed
  rate limit on order creation keyed by EAB kid, with per-kid overrides and a
  global backstop. Returns RFC 8555 `rateLimited` (429) with `Retry-After`.
- **EAB lifecycle tooling (WI-011):** `scripts/eab.py` mints high-entropy kid +
  MAC key, supports rotation, and includes an audit subcommand that lists every
  kid with its SAN scope and last-used timestamp (no MAC keys printed).
- **SIEM audit:** every issuance, policy-denial, enrollment-failure, account
  creation, and revocation is recorded in the RA SQLite store unconditionally
  and emitted to a JSONL sink (optional syslog/HEC). Fail-open applies to
  emission, not to the local audit record.
- **Operator enablement artifacts:** `scripts/install-windows.ps1` (IIS +
  HttpPlatformHandler, app pool as gMSA), `scripts/Register-MaintenanceTasks.ps1`
  (nonce GC + expired-order sweep), `docs/operations.md` (EAB lifecycle, network
  allowlist, rate limiting, admin token + reclaim runbook, monitoring/SLOs,
  retention/archival, revocation runbook, backup/restore).
- **Architecture tests:** no-signing-key scan (positive + negative controls) and
  no-signing-dependencies scan assert the RA never invokes a signing primitive
  in the issuance path.

### Security hardening (post-review)
- **M-1:** reason 7 rejected by `revokeCert` and `Revoke-Cert.ps1` (certutil
  rejects it; prevents a silent break in the out-of-band revocation loop).
- **M-2:** CAS-guarded pending→ready transition (expired pending orders stay
  pending until the sweep moves them, not silently promoted).
- **M-3:** CAS-guarded cert revocation with deterministic `won_cas` signal.
- **MED-1:** post-issuance SAN verification (issued cert SANs checked against
  the order, not just the CSR; non-DNS SANs rejected).
- **MED-2:** deterministic `won_cas` signal replaces timestamp-inference.
- **LOW-1, LOW-2, LOW-4:** expiry guard in `_maybe_ready_order`, UNIQUE index
  on certificates.order_id (graceful migration), and other robustness fixes.

### Stability contracts (from 1.0.0-rc1)
- **ACME API surface:** the directory endpoints, JWS validation, EAB binding,
  and the `revokeCert` response shape are the frozen public API.

  > **AMENDED 2026-08-24.** This clause used to say the `out_of_band_revocation`
  > hint shipped in the response **body** and was "ignored by standard ACME
  > clients per RFC 8555 §7.6". That claim was disproven live: Certify the Web
  > cannot parse *any* JSON object body on this endpoint — it fails at line 1,
  > position 1 — and then reports a revocation that actually SUCCEEDED as
  > failed. A false negative on revocation is worse than a missing hint. The
  > hint therefore moved to the `X-Acme-Ra-Out-Of-Band-Revocation` response
  > header and every success path now returns an empty body. The header, not a
  > body field, is the frozen surface from here.

  Changing `ca_crl_updated` to `true` still requires a future in-band revocation
  capability (a deferred, explicit privilege decision — see
  `docs/threat-model.md` §E).
- **Audit event types:** the `event_type` strings in `audit_log` are stable
  for SIEM ingestion. New event types may be added; existing ones are not
  renamed or removed.
- **Config env vars:** `ACME_RA_*` env vars are stable. New vars may be added
  with defaults; existing vars are not renamed.

### Known limitations
- **CA-side revocation is out-of-band.** The RA records revocation in its own
  store only; the CA CRL is not written until an operator runs
  `scripts/Revoke-Cert.ps1`. The audit honestly records `ca_crl_updated=false`.
  A standard ACME client reads 200 as "revoked" while relying parties still trust
  the cert until the CRL is republished — this is a documented, decided
  trade-off (threat-model §E) to keep the gMSA least-privileged.
- **Single-backend CBT assumption.** The channel-binding token is derived from
  a side-channel TLS probe of the `/certsrv/` host. Multi-backend topologies
  (NLB/ARR) are unsupported without reworking CBT derivation.
- **Challenge is a no-op.** The enterprise trust model (EAB + network + SAN
  scope) replaces domain-control proof. This is deliberate, not a gap.
- **No in-band CA revocation.** The gMSA holds Enroll rights only, not CA-officer
  rights. In-band revocation is a deferred, explicit privilege decision.

### Read-only / defensive boundary
acme-adcs-ra is **not** a read-only tool. It is in the certificate-issuance path
and holds a standing ADCS enrollment identity. The read-only / air-gapped /
flag-don't-probe conventions that govern cert-watch and adcs-lens **do not
apply**. The compensating disciplines are the hard rules in `AGENTS.md`: no
signing key, deterministic policy, passwordless, least-privilege template, audit
everything.
