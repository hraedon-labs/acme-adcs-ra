# Unfiled work items — manual fallback

**Why this file exists.** On 2026-08-17 the regista-backed work-item store
stopped accepting writes, estate-wide:

```
RegistaError: [MIGRATION_REQUIRED] v6 genesis requires the clean-epoch
project_identity baseline; recreate this schema instead of importing legacy history
```

Reads still work (`agent-notes work-item find` returns the existing 24 items for
this project); only `work-item file` / `update` fail. Reproduced against both
`acme-adcs-ra` and `cert-watch`, so it is not project-specific. The suite was
being worked on concurrently, so this was left alone rather than migrated —
recreating the authoritative store is an owner decision, not a mechanical fix.

**Re-checked 2026-08-18** — still failing, identically, for both
`work-item update` and `breadcrumb file`. Reads still work. So this file is
still the only tracker, and it has grown a second job: recording work that is
*finished* but cannot be marked finished anywhere else.

**Re-checked 2026-08-24** — still blocked, but the *error has changed*, so this
is no longer the same failure:

```
[MIGRATION_REQUIRED] Migrations pending: schema 'acme_adcs_ra' has applied
[1..44], missing [45, 46, 47, 48, 49, 50]. Run regista migrations before starting.
```

Reads still work — `agent-notes work-item find --project acme-adcs-ra` returns
all 24 items. The v6-genesis message is gone; what remains is six unapplied
migrations. That is a *mechanically* fixable state, unlike the genesis reset,
but the store is shared estate-wide and migrating it is an owner decision with
blast radius past this repo, so it was left alone again. Note the project
schema is `acme_adcs_ra` (underscores) — `--project acme-adcs-ra` is rejected
by the name validator, which is worth knowing before concluding the store is
down.

**Re-checked 2026-09-05** — still blocked, same error, same six missing
migrations `[45..50]`. Reads still work. Confirmed with the owner that
`agent-notes` stays down pending the agent-operations-suite work, so this file
remains the tracker; item 26 below was filed here rather than in the store.

**Reconcile this file into regista once writes are restored, then delete it.**

---

## Status at a glance (2026-08-18)

| # | What | State |
|---|---|---|
| 1 | Syslog sends counted as delivered | closed 2026-08-17, filed here for the record |
| 2 | WI-014 second vector (`keyChange`) | **needs filing** — shipped as 14a, the tracker does not know |
| 3 | Privileged script tree unauthenticated | **CLOSED 2026-08-18** (code + tests + docs) |
| — | WI-015 `-SitePath` ancestor chain | **CLOSED 2026-08-18** — fell out of item 3's helper; **mark done in the store** |
| 4 | `ipSecurity` posture undocumented | **CLOSED 2026-08-18** (`SECURITY.md` → Recorded decisions) |
| 5 | WI-053 is stale | **needs closing in the store** — re-verified in code 2026-08-18 |
| 6 | WI-014 split | **needs filing** — 14a shipped, 14b built and unwired |
| 7 | Audit retention never runs | **open** — prerequisite (item 8) now cleared; three safety gaps remain |
| 8 | UDP probe satisfied `audit_offbox_required` | **CLOSED 2026-08-18** |
| 9 | TCP syslog connect unbounded | **CLOSED 2026-08-18** (acme-adcs-ra); cert-watch half open, see below |
| 10 | Sibling dot-source precedes the provenance gate | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 11 | No ancestor check on the state/runtime roots | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 12 | HEC token forwarded across redirects | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 13 | `$env:windir` selects elevated executables | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |

Everything marked CLOSED is in the working tree on
`security-review-2026-08-15-daybreak`, with tests, and needs no tracker entry
beyond a note that it happened. Everything marked **needs filing** is a
tracker-only action with no code left to write.

---

## Items to file

### 1. (bug, high) — CLOSED IN THE SAME PASS, file for the record

**Syslog send failures were counted as successful off-box audit delivery, and
the `audit_offbox_required` startup probe passed with the collector dead.**

Daybreak standard review 2026-08-17 (commit `7325cdb`) Finding 4 — confirmed by
execution. Fixed on branch `security-review-2026-08-15-daybreak`; full write-up
in `docs/security-review-2026-08-17-daybreak-standard.md`. Filed here only so
the store has the history when it comes back.

### 2. (risk) — APPEND TO EXISTING **WI-014**, do not open a new item

WI-014 currently reads as "unauthenticated `newAccount` denials grow the
mandatory audit database without bound". Daybreak Finding 1 is a **second vector
on the same root cause**: `routes/key_change.py` has no rate, quota or
cardinality check, and every successful rotation inserts a non-coalesced
`audit_log` row, so a valid or stolen account key can chain rotations
indefinitely.

Append to WI-014 rather than filing separately — one retention-plus-quota design
closes both, and splitting them invites two half-fixes.

### 3. (task) — APPEND TO EXISTING **WI-015** / **WI-053**

Daybreak Finding 3 (privileged maintenance automation executes an
unauthenticated script tree) is valid and better founded than the report knows:

- the installer does not install `scripts/` at all — `docs/operations.md:857`
  tells operators to hand-copy it to an unspecified location;
- round 7 measured `BUILTIN\Users:(Write)` on `C:\ProgramData`, which is exactly
  why the *code* root lives under `%ProgramFiles%` — the scripts tree has no
  equivalent requirement;
- the lab itself stages CA-officer scripts in `C:\Temp\ra-scripts`.

`Test-ObjectDaclTrusted` already exists; it is simply not applied to the
privileged script path.

**Measured live 2026-08-17.** `C:\Temp\ra-scripts` — the path the registered
revocation-sync task actually executes as the gMSA — carries
`BUILTIN\Users:(I)(CI)(AD)` and `BUILTIN\Users:(I)(CI)(WD)`, inherited from
`C:\Temp`. So an unprivileged local user can create files in the directory tree
a scheduled task runs privileged code from. That is no longer a design concern
awaiting evidence; it is a measurement. The same session watched
`Test-ObjectDaclTrusted` refuse `C:\Temp` as an *installer source* for exactly
this reason — the control exists and is simply not pointed at this path.

> **CLOSED 2026-08-18.** `Get-TreeTrustViolations` (in `InstallVerifyLib.ps1`,
> beside `Test-PathChainTrusted`) applies the installer's provenance rule to a
> whole tree — ancestor chain *and* every object beneath it, because the action
> dot-sources `lib\` siblings at run time. Either half alone passes a tree the
> other rejects; both halves are mutation-proven in
> `tests/pester/InstallVerify.Tests.ps1` (5 new tests, suite 368 green).
> `Register-MaintenanceTasks.ps1` refuses to register the revocation-sync task
> from a failing tree, with `-AllowUntrustedScriptPath` as the explicit lab
> override (same shape as `-AllowInsecureUrl`). `docs/operations.md` now says
> where to put the tree and why, in the same note that already told operators to
> copy it.
>
> **Residual, deliberately not done:** `Sync-Revocations.ps1` does not re-check
> the tree at *run* time. Doing so would load `InstallVerifyLib.ps1` — two
> `Add-Type` C# compiles — on a 15-minute cadence, and with registration now
> refusing untrusted trees the remaining exposure is a DACL loosened *after*
> registration, which needs administrator rights. Worth revisiting if the lib is
> ever split so the DACL primitives can be loaded on their own.
>
> **REVISITED AND TAKEN, 2026-08-24 — see item 10.** The stated condition was
> met: both `Add-Type` compiles are now on demand, so the library dot-sources in
> 321 ms rather than 1298 ms and neither compile is on the trust path. The
> second premise — "registration now refuses untrusted trees" — turned out to
> hold only on the `$registerSync` path and only *after* two siblings had
> already loaded, and never covered `-AllowUntrustedScriptPath` at all.
> `Sync-Revocations.ps1` now re-checks on every run.
>
> **WI-015 is a different path, and it is now closed too.** That item is the
> `-SitePath` ancestor-chain refusal for the *IIS site* tree — round 2 withheld
> it pending a live DACL baseline, and the baseline was surveyed on 2026-08-17
> (`C:\inetpub` chain clean; `C:\ProgramData\acme-adcs-ra` still reports two
> violations, so the check discriminates). Writing `Get-TreeTrustViolations` for
> the script tree produced exactly the chain-plus-contents shape WI-015 needed,
> so the installer's site-tree proof now calls it and the ancestor half ships.
> **Mark WI-015 done when the store accepts writes.**

### 4. (decision) — NEW, low effort

**Record the IIS `ipSecurity` posture explicitly in `SECURITY.md`.**

Daybreak Finding 2 re-reported the commented-out allowlist, which the
2026-08-11 review already adjudicated (token bucket as the compensating control;
allowlist documented as required and operator-owned in
`docs/operator-requirements.md:87`). This is the second independent reviewer to
raise it. A short "accepted, and why" note in `SECURITY.md` ends the cycle — or,
if the posture should actually change, that is a deliberate decision to take
rather than a finding to keep re-triaging.

> **CLOSED 2026-08-18.** `SECURITY.md` gains a **Recorded decisions** section
> carrying the disposition, why the installer does not enforce an allowlist (the
> IPs are per-deployment; `<ipSecurity>` needs a role service a first install may
> not have), where it *is* documented as required, the compensating controls in
> code (nonce token bucket, WI-016 order limits), and what would change the
> trade. The posture did not change — only its visibility. A reviewer who
> disagrees is now arguing with a decision rather than filing a finding.

### 5. **WI-053 IS ALREADY FIXED — close it**

Checked 2026-08-17. The item (filed 08-13) says `-AdminToken` is a mandatory
parameter and `Build-SyncActionCommand` always emits `$env:ACME_ADMIN_TOKEN`
into the revocation-sync action. Neither is true any more:

- **Code** — `-AdminToken` is a `[switch]`, and is required only when
  `$registerGeneral` (`Register-MaintenanceTasks.ps1:204`). `-RevocationSyncOnly`
  skips the general tasks entirely, so `-RevocationSyncOnly -ConfirmToken`
  registers the sync task with no admin authority on the host. The admin env is
  gated behind `-LoadAdminToken` (default `$false`), wired from
  `([bool]$AdminToken)`. `Build-SyncActionCommand` has **no token parameter at
  all** — tokens are loaded from the ACL'd dotenv at run time, so a value cannot
  reach the action even by mistake.
- **Test** — `tests/pester/TaskAction.Tests.ps1`, *"Omits the admin-token load
  entirely in confirm-only mode"*, asserts exactly the WI's ask. Suite 39/39
  green on pwsh 7.
- **Docs** — `docs/operations.md:419-425` and `:956` document
  `-RevocationSyncOnly -ConfirmToken`; `docs/pre-pilot-checklist.md:722`
  *requires* it. So the "documented way to deploy it", which was the item's
  actual complaint, is fixed too.

**Re-verified 2026-08-18** against the working tree: `-AdminToken` is still
`[switch]`, still gated on `$registerGeneral`, and `Build-SyncActionCommand`
still has no token parameter. The item is stale, not wrong-once. Attempting the
close is what proved the store is still refusing writes.

Closed by the 2026-08-15 review (`-AdminToken` made non-mandatory plus the new
`-RevocationSyncOnly` switch — see `docs/security-review-2026-08-15.md:114`) and
hardened by 2026-08-19 F2 in `71e7d8a` (tokens became dotenv loads). The tracker
entry is simply stale. Only residual: it sits in the D1–D7 officer/registration
class that has never been live-proven, so live assurance rides the lab session.

### 6. Split **WI-014** — parts one to three now shipped

> **Update 2026-08-17: 14a is closed; 14b is BUILT BUT NOT WIRED.** Retention
> exists (floor, gates, sweep, footprint, JSONL rotation, timestamp index) and
> 14a, the `keyChange` ceiling, shipped the same day — but **nothing calls the
> sweep** (item 7, found 2026-08-18). An earlier revision of this note said
> "WI-014 IS CLOSED"; that was wrong on the 14b half. Detail in the two bullets
> below.

Parts one and two are **done**: `audit_bounds.py` bounds each row's *size*
(attacker-chosen `kid` truncated with a SHA-256 of the whole), and
`audit_coalesce.py` bounds row *count* for five replayable denial classes within
a window, without deleting anything. What is left is two very different jobs
that should not share one item:

- **14a — BUILT 2026-08-17.** Bounds *repeatable successful* transitions:
  Daybreak F1's `keyChange` had no rate, quota or cardinality check, and the
  coalescer deliberately excludes successes. Shipped as
  `rate_limit_key_changes_per_window` (default 5, `0` disables), keyed per
  **EAB kid** so a leaked EAB cannot spread rotations across fresh accounts,
  and enforced **atomically** inside `update_account_key_with_audit` rather
  than count-then-check — the round-6 lifetime per-EAB account quota was the
  precedent followed. The denial (`key-change-rate-limited`) is coalesced so
  the ceiling does not simply move the growth to the refusal row; the success
  row stays uncoalesced because it is the counter. Seven tests in
  `tests/test_key_change_rate_limit.py`, each mutation-proven. See the
  CHANGELOG and `docs/operations.md` → *Key-rollover ceiling*.

  Nothing needs filing for this. It was descoped from the retention build
  deliberately, not forgotten: retention bounds the *storage* consequence, but
  an unbounded authenticated action is a rate-limiting defect in its own right
  and wanted its own change.
- **14b — BUILT 2026-08-17, NOT REACHABLE IN PRODUCTION.** The code, the floor,
  the gates and the self-audit are all real; `run_sweep` simply has no caller
  outside the tests, so a deployment that configures retention prunes nothing
  (**item 7**). Three deferred safety gaps must close before it is wired, and
  **item 8 is a hard prerequisite** — see the sequencing note. Everything below
  describes what was built, not what runs: the floor is `observed certificate validity + 14 days`
  (enforced, startup refused below it), and deletion is gated on
  `audit_offbox_required` *and* a live delivery probe, so the dangerous
  capability only exists where the local table is a buffer rather than the
  system of record. Local-only stays supported and never prunes. The sweep
  audits itself. See the CHANGELOG and `docs/operations.md`.

### 7. (bug, medium) — NEW. **Audit retention never runs.**

`run_sweep` (`audit_retention.py:190`) has **no caller outside the test suite**.
Verified 2026-08-18: no admin route, no entry in
`Register-MaintenanceTasks.ps1` (which registers nonce-cleanup and
expired-order-sweep, but nothing for retention), no lifecycle hook.

So an operator who follows `docs/operations.md` → *Built-in retention*, sets
`audit_retention_days` at or above the floor and turns on
`audit_prune_enabled`, gets a feature that is configured, validated at startup,
documented — and never executes. Nothing unsafe happens; the harm is the belief
that audit growth is bounded when it is not, which is the belief that stops
someone watching the disk.

Shipped by the 14b retention build (WI-014 part three). Options are a scheduled
task against a new admin route (the shape the other two maintenance jobs
already use), a lifecycle hook, or documenting it explicitly as library-only.

**Do not wire this before item 8 and the three deferred safety gaps below.**
See the sequencing note after item 9.

> **CLOSED 2026-08-23 by refusing the unsupported configuration, not by wiring
> unsafe deletion.** `RAConfig` now rejects `audit_prune_enabled=true`, and the
> composition root repeats the refusal for a mutated or validation-bypassed
> config. This removes the false operational claim while preserving
> `audit_retention_days` floor validation and footprint reporting. The library
> sweep remains unreachable until per-row off-box acknowledgement exists,
> deletion plus self-audit are atomic, and the sweep event is exported off-host.
> Tests mutation-prove both refusal boundaries.

### 8. (bug, medium) — NEW. **A UDP syslog probe satisfies `audit_offbox_required` with nothing listening.**

`SiemExporter`'s startup probe (`siem.py:560-581`) returns `True` for
`syslog_proto=udp` whenever the socket accepts the datagram, which it always
does. Reproduced by the scanner against an unused port: `enabled=True`,
`ok=True`, no collector.

The code is *candid* about it — the returned detail says in as many words that
"reachability is NOT proven" — but the **boolean** is what gates startup, and
the boolean says yes. `audit_offbox_required` exists to refuse to start unless
audit evidence leaves the box; on UDP it refuses nothing.

Mitigating: the shipped `web.config` selects TCP, so no shipped configuration
reaches this. Fix is small — make the UDP probe return `False` for this gate,
and require HEC acknowledgment or an explicitly accepted TCP check.

**This is the prerequisite for item 7.** See the sequencing note below.

> **CLOSED 2026-08-18.** The UDP branch returns `False`, and `RAConfig` refuses
> `audit_offbox_required` with `siem_syslog_proto=udp` outright, so the failure
> is an actionable startup message rather than a probe result nobody sees. No
> escape hatch: requiring off-box audit and demonstrating it over UDP are
> mutually exclusive, which is the whole finding. Covered by
> `tests/test_codex_scan_2026_08_18.py` — including the case that matters most,
> that a real UDP emitter is `enabled` (so it clears the earlier gate) and still
> cannot open `audit_retention.evaluate`'s deletion gate.
>
> Three existing tests encoded the old behaviour and were updated rather than
> deleted; the wave-3 one that asserted "True with an honest caveat" now asserts
> the refusal, since a refactor restoring the caveat would reopen this.
>
> **Item 7's prerequisite is therefore cleared** — but the three deferred safety
> gaps below are not, so item 7 stays shut.

### 9. (bug, low) — NEW. **TCP syslog connect is not bounded by the configured timeout.**

`_apply_send_timeout` (`siem.py:69-92`) runs *after*
`SysLogHandler.createSocket()` has already resolved and connected, so
`siem_syslog_timeout_seconds` bounds **sends only**. DNS resolution and the TCP
connect fall back to the OS default, so a blackholed collector can stall
service construction — or the single reconnect worker — well past the deadline
the operator configured.

The docstring only ever claimed to bound a send, so this is a gap rather than a
broken promise. Fix: create the socket, set the deadline, then connect, and
bound resolution plus establishment with one wall-clock deadline.

**Check cert-watch for the same shape** — it shares this handler's lineage and
is already recorded as having no TCP send timeout at all.

> **CLOSED 2026-08-18 for acme-adcs-ra.** `_RaisingSysLogHandler.createSocket`
> now resolves and connects under one wall-clock deadline covering every address
> the resolver returns, so a multi-homed target cannot multiply the wait.
> `getaddrinfo` takes no timeout and blocks in the OS resolver, so it runs in a
> daemon thread that is abandoned rather than waited on — documented in place,
> because leaking a thread is a real cost and the alternative is worse. Datagram
> and Unix sockets keep the stock path. The regression test measures the defect
> by wall clock: against a resolver stub that never answers, the pre-fix code
> took 30s and then connected happily.
>
> **cert-watch: CONFIRMED, NOT FIXED.** `src/cert_watch/siem.py:89` constructs a
> stock `SysLogHandler` with no timeout of any kind — so it has *both* defects,
> the missing send timeout already on record and this connect one. It also
> inherits the stock `handleError` swallow. cert-watch has no
> `audit_offbox_required` gate riding on that, so the consequence is a stall and
> a silent drop rather than a defeated control. Left alone deliberately: it is a
> different repo, and it had uncommitted work from a concurrent session at the
> time. `acme_adcs_ra/siem.py` is the reference fix, `_getaddrinfo_within`
> included. **A breadcrumb could not be filed — the store refuses those writes
> too — so this paragraph is the only record. It must reach cert-watch.**

### Sequencing note for items 7, 8 and 9

Items 7 and 8 are individually low-severity and were scored separately. They
interlock, and the order matters:

> Deletion is gated on `audit_offbox_required` **and** a live delivery probe at
> sweep time. Item 8 says that probe passes on UDP with no collector. So wiring
> up the sweep (item 7) while item 8 stands would make the UDP hole
> **load-bearing for deleting the only surviving copy** of audit rows.

Fix 8 first, then 7. **8 is now fixed (2026-08-18) and 7 is still shut** — the
three gaps below are what hold it, and they are the substantive half. The same review deferred three more must-fix-before-wiring
gaps on the same theme, all of which are only harmless today *because* nothing
calls `run_sweep`:

- retention can delete rows that were never delivered to SIEM — the
  delivery-watermark semantics need to exist before deletion is reachable;
- the `DELETE` and its `audit-retention-swept` row **commit separately**; they
  should be atomic, the same rule `record_issuance`, `create_account_with_audit`
  and `update_account_key_with_audit` already follow;
- the sweep event is never exported off-box, so a retention pass leaves no
  off-host trace — which is precisely the property that makes a sweep
  indistinguishable from an attacker's cleanup.

**Provenance for items 7–9.** Codex security scan of
`7325cdb`→`47bb9f7` (run `f0da0988`, sealed 2026-08-18T01:00:33Z): 3 findings,
all low severity and high confidence. Each was independently re-verified by
hand before being recorded here. The same run found **no issue** in the 14a
keyChange ceiling ("the prior unlimited-rotation vector is resolved") and **no
regression** in the `Revoke-Cert.ps1` certutil fix, though it had no live
PowerShell 5.1 or ADCS to execute against — that half is covered by the
2026-08-17 lab pass. Report and artifacts kept at
`samples/codex-scans/20260818-SvRVRx/` (gitignored: they name lab hosts).

Items 2 and 3 of that scan's predecessor run remain open and unchanged as
items 4 and 3 above.

---

## Standing validation debt (not work items, but do not lose them)

- ~~**Rverify, the sync/queue drain, and the officer-script class D1–D7 have
  never been executed**~~ — **DONE 2026-08-17** on tip `e7c4254`. All three ran
  live and passed, after the run found and fixed the defect that made the whole
  revocation loop inert (`838eeb2`). See the validation log in
  `docs/pre-pilot-checklist.md`.
- ~~**Phase L** (`Lqueue`/`Ldrain`, the stale-worker enrollment lease)~~ —
  **DONE 2026-08-24** on tip `f6badc9`, 22/22. It had not been skipped: no
  driver invoked it, neither blackhole mechanism could support queue-then-drain
  (the firewall rule does not block on this host and hardcoded a CA address that
  had moved; config mode needs a recycle that kills the queue), and `L5` aborted
  the phase on a client timeout that the bounded enrollment executor makes
  inevitable. All three fixed; `Ldrain` proved the stale worker abandons
  `before-submit` on a lapsed generation with exactly one certificate for the
  contested order.
- ~~**`01417b5`** (98-line Windows PowerShell 5.1 fix to `InstallVerifyLib.ps1`)
  has never been live-installed~~ — **DONE 2026-08-17**: the installer ran from
  `e7c4254` on the lab host and exited 0. Note it also *refused* a `C:\Temp`
  source tree on DACL grounds, which is the hardening working and which every
  earlier runbook deploy step now trips over.
- Branch `security-review-2026-08-15-daybreak` is **26 commits ahead of `main`
  with no PR open** (14a `e7c4254` and the revocation fix `838eeb2` are the two
  newest). `security-review-2026-08-18` and `-08-19` are fully merged and stale.
  This branch now carries a full live E2E pass; opening the PR is an owner
  decision, not a blocked one.

---

## Round 2026-08-24 (daybreak standard review at `0a47955`) — DECLARED BEFORE MUTATION

Four findings, reviewed and re-rated before any code was written. This section
is the pre-action declaration the steward path requires; the store cannot take
it (see the header). Severities below are **this repo's** rating, not the
reporting reviewer's, and two of them differ — the reasoning is recorded so the
disagreement is arguable rather than silent.

**Actor / lineage.** Implementation by Claude Opus 5 (`claude-opus-5`). The
findings came from a daybreak standard review — a different actor and lineage.
Independent review of the *fix* is still owed; see the closing note.

**Declared working set.** Nothing outside these paths:

- `scripts/lib/InstallVerifyLib.ps1`
- `scripts/install-windows.ps1`
- `scripts/Register-MaintenanceTasks.ps1`, `scripts/Sync-Revocations.ps1`,
  `scripts/Revoke-Cert.ps1`, `scripts/Set-OfficerRights.ps1`,
  `scripts/Reconcile-Revocation.ps1`
- ~~`scripts/lib/BootstrapTrustLib.ps1` (new)~~ — **not created.** Lazy type
  compilation achieved the same goal (a library cheap enough to dot-source at
  run time) with a far smaller diff, and a second file invites a second copy of
  a predicate — see `InstallVerifyLib.ps1:1680` for what that cost last time.
  Recorded here because the declared working set is the contract.

**Two paths were touched that the declaration did not list**, both recorded
here for the same reason:

- `scripts/lib/TaskActionLib.ps1` — `Build-SyncActionCommand` had to carry
  `-AllowUntrustedScriptPath` into the registered action. Not foreseeable until
  the run-time gate existed: without it, the documented lab flow registers a
  task that refuses on every run, so this is part of finding 10's fix rather
  than scope creep.
- `.gitignore` — `Invoke-Pester -CI` writes `testResults.xml` into the
  invocation directory, which showed up as untracked noise on every status.
- `src/acme_adcs_ra/siem.py`
- `tests/pester/*.Tests.ps1`, `tests/test_siem*.py`
- `CHANGELOG.md`, `docs/security-review-2026-08-24-daybreak-standard.md`, this file

**Declared acceptance checks.** Each must have a fresh result *after the last
edit*, not before it:

1. `pytest -q`
2. `ruff check . && ruff format --check .`
3. `mypy src/`
4. `pwsh -Command "Invoke-Pester tests/pester -CI"`
5. Mutation proof for every new test: revert the fix, show the test fails,
   restore. A test that cannot fail is not evidence.
6. For finding 12, a **live probe**: a local redirect server proving the
   `Authorization` header no longer reaches the redirect target.

**Known risks going in.**

- Findings 10, 11 and 13 are Windows-side. Linux Pester covers the pure decision
  functions; it **cannot** cover the live ACL and process behaviour (WI-050).
  Live assurance rides the outstanding lab session, same as the D1–D7 class.
- Finding 11 changes a **refusal** on the default install path. A wrong refusal
  aborts the upgrade of a live issuance host — the round-5 lesson. The predicate
  must pass `C:\ProgramData` and `%ProgramFiles%` or it is worse than the bug.
- Finding 13 touches assertions that currently *pin* the `$env:windir` spelling,
  so the tests move with the code. That is the change most likely to look green
  while covering nothing.

### 10. (bug, high) — sibling code is loaded before the provenance gate

**Rated high; the report also said high.** The one I would fix first.

`Register-MaintenanceTasks.ps1:199-200` dot-sources `lib/TaskActionLib.ps1` and
`lib/SyncLib.ps1` immediately after param binding. The script-tree provenance
gate is at `:269`. Two libraries have already executed as Administrator by the
time the gate is consulted.

The gate carries an honest caveat — *"the check is loaded from the very tree it
judges, so someone who can already write here can neuter it"* — and that caveat
is **not** what this is. Neutering the check requires rewriting
`InstallVerifyLib.ps1`; this requires only `SyncLib.ps1`, and the gate never
runs at all. Ordering, not self-reference.

Two further holes the report did not name:

- The gate is inside `if ($registerSync)`. Registering only the nonce/sweep
  tasks skips it entirely, while `:199-200` still load two siblings elevated.
  The justification — *"the nonce/sweep tasks execute nothing from disk"* — is
  true of the **tasks** and false of the **registration script**.
- **The worst instance is in a different file.** `Sync-Revocations.ps1:199`
  dot-sources `SyncLib.ps1` with no gate at all, and *that* is the script the
  scheduled task runs as the gMSA every interval, forever.
  `Revoke-Cert.ps1:130` (CA-officer context), `Set-OfficerRights.ps1:105` and
  `Reconcile-Revocation.ps1:97` are the same shape.

**Correction — the run-time gap was a decision, not an oversight.** Item 3's
closing note (above) records it explicitly: *"Residual, deliberately not done:
`Sync-Revocations.ps1` does not re-check the tree at run time"*, on two grounds
— loading `InstallVerifyLib.ps1` means **two `Add-Type` C# compiles** on a
15-minute cadence (verified: `:444` `ACMERA.AtomicDirectory`, `:1519`
`ACMERA.FinalPath`), and the residual exposure after registration refuses
untrusted trees is a DACL loosened later, which needs admin rights. An earlier
draft of this entry called it an oversight; that was wrong and is withdrawn.

The decision was sound on its own premises. What this round adds is that **one
premise does not hold**, and that the note's own escape hatch is now cheap:

- *The premise.* "Registration now refuses untrusted trees" is true only on the
  `$registerSync` path, and only *after* `:199-200` have already loaded two
  siblings elevated. On the nonce/sweep path the gate never runs. So the
  run-time check was traded away against a registration-time check that has a
  hole in front of it. Fix the ordering and the trade becomes defensible again
  — which is why the ordering fix is the one that matters most.
- *The escape hatch.* The note ends: *"Worth revisiting **if the lib is ever
  split so the DACL primitives can be loaded on their own**."* That is exactly
  what this change does. `Test-ObjectDaclTrusted`, `Test-PathChainTrusted`,
  `Get-TreeTrustViolations` and their dependencies touch neither compiled type
  (only `New-AtomicProtectedDirectory:513` and `Get-CanonicalPathString:1586`
  do), so they move to a new `lib/BootstrapTrustLib.ps1` that dot-sources with
  no `Add-Type` at all. `InstallVerifyLib.ps1` dot-sources it too, so there is
  exactly **one** definition of each predicate.

That last point is the reason for moving rather than copying. `:1680-1682`
records what a second copy cost last time — the installer's inline bootstrap
copy listed only the dead half of a rights mask and *"looked correct while
covering neither right"*. A duplicated predicate is how this file already got
burned once.

- *`-AllowUntrustedScriptPath` outlives its warning.* An operator who takes the
  documented lab override registers a task against a writable tree and gets a
  warning saying "re-register before pilot" — after which nothing ever checks
  again. A run-time gate is what makes that override self-correcting.

So: a legitimate re-find of the remainder of item 3 (one entry point of five,
with the fix placed after the load), plus the split that retires its stated
blocker.

### 11. (bug, medium) — no ancestor check on the state and runtime roots

**Report said high; rated medium here, and the framing is wrong at defaults.**

Confirmed: `Get-RootProvenance` inspects the root and its contents, never above
it, so `Initialize-SecuredRoot` claims `$InstallDir`/`$RuntimeDir` with no
ancestor check. `install-windows.ps1:1393` applies `Get-TreeTrustViolations` to
`$SitePath` with a comment making exactly the reviewer's argument.

But *"protected roots remain replaceable"* does not hold on the defaults.
Substituting an existing child needs `Delete` on the child or
`DeleteSubdirectoriesAndFiles` on the parent. `C:\ProgramData`'s Users ACE is
create-class only (`WD,AD,WEA,WA` — no `DE`, no `DC`) and `%ProgramFiles%` is
Users RX, so the attack does not work there. It works on a **non-default**
`-InstallDir`/`-RuntimeDir` under a parent that grants delete — which is not
hypothetical, because admin-created top-level folders inherit
`Authenticated Users:(OI)(CI)(M)` from `C:\`, and the lab is documented as
staging under `C:\Temp`.

**Why this stalled, and what unblocks it.** `install-windows.ps1:1385-1387`
records that the `$SitePath` refusal shipped once `C:\inetpub` was *measured
clean* — "the evidence this was waiting on". That evidence can never arrive for
`C:\ProgramData`, because `InstallVerifyLib.ps1:1790` records that it **FAILS**
`Test-PathChainTrusted`.

It fails on `WriteData`. On a directory that bit means *create a new entry*, not
*modify an existing child* — a false positive for this question.
`Test-AceEndangersBytes` is correctly named and is the right predicate for a
file about to be executed; it is the wrong predicate for an ancestor of a
protected root, where the dangerous bits are `Delete`,
`DeleteSubdirectoriesAndFiles`, `ChangePermissions`, `TakeOwnership`,
`GenericAll` and `GenericWrite` — and **not** bare `WriteData`/`AppendData`.

So the fix is a sibling predicate with the narrower mask, which passes
`C:\ProgramData` and still fails `C:\Temp`. Default-safe by construction, which
is the property the round-5 lesson demands.

### 12. (bug, low→medium) — the HEC token is forwarded across redirects

**Report said low; kept at low-to-medium.** Confirmed **by execution**, not by
reading: a local redirect server received `Authorization: Splunk <token>`
verbatim after a 302.

`urlopen` (`siem.py:757`) uses the default `HTTPRedirectHandler`, whose
`redirect_request` strips exactly `("content-length", "content-type")` and
copies every other header onto the new request — `Authorization` included,
cross-host. `http_error_302` permits redirect targets with scheme `http`,
`https` **or** `ftp`, so the https-only gate at `siem.py:335-340` is defeated
one hop deep and the token can leave in cleartext.

Two precisions the report did not have:

- **Only the token leaks, not the audit events.** `redirect_request` builds the
  new request without `data=`, and 301/302/303 downgrade POST to GET. Measured:
  method `GET`, empty body. Even 307/308 drop the body, and POST+307 raises
  rather than following. This is credential disclosure, not audit disclosure.
- Adjacent dead code: `if not (200 <= resp.status < 300)` at `:758` cannot fire.
  Non-2xx raises `HTTPError` and 3xx is followed automatically — which is
  precisely why a redirect leaves no trace in the logs.

Nudged above the reported severity for one reason: an HEC token lets an attacker
**forge audit into the SIEM**, and for this product the audit trail is the
thing being sold.

### 13. (bug, medium) — `$env:windir` selects executables that run elevated

**Report said high; rated medium here.** Real, and inconsistent with this
repo's own stated doctrine — but the precondition is controlling the
environment block of a process about to elevate, which generally means already
holding the launching context.

`InstallVerifyLib.ps1:17` derives `icacls.exe` from `$env:windir`, while
`Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and `Reconcile-Revocation.ps1`
resolve System32 from the runtime, and `Get-TrustedInboxModuleRoots:2336` goes
further still (machine-scope registry plus the folder API) with a comment
spelling out why the process environment cannot be trusted. Line 17 is simply
on the old pattern.

The report named the weaker half. Two additions:

- **The bare-name fallback is the sharper bug.** `else { 'icacls.exe' }` is PATH
  resolution — exactly what round-6 finding 3 removed elsewhere. Test `:1607`
  asserts the *installer* never invokes icacls by bare name; the *library* still
  can, whenever `windir` is **unset** rather than redirected. Unsetting is a
  lower bar than redirecting.
- **Double impact.** icacls output is not merely executed, it is the evidence
  `Get-RootProvenance` and `Assert-InstallTreeLocked` read. A substituted icacls
  forges the lockdown proof as well as running code.

**Decision: fix it completely rather than at line 17.** `install-windows.ps1`
has eight more `$env:windir` sites (msiexec, secedit, cmd, netsh, attrib,
appcmd, the handler DLL probe), and tests at `:1379` and `:1605-1607` *pin* that
spelling. Half-fixing the library while leaving the installer on the old pattern
is how this class keeps returning: the doctrine ends up split across two files
and the next reviewer finds whichever half they open first.

### 8. (observation, medium) — The lab CA's C:\ carries an APPLICABLE Authenticated Users Modify ACE

*Found live 2026-08-24 during the daybreak-branch validation (F10 gates).*
`CA01`'s `C:\` DACL includes `NT AUTHORITY\Authenticated Users:(M)` with
no inheritance flags (applicable to the root itself), alongside the normal
`(OI)(CI)(IO)(M)` twin. Every tree on that host has `C:\` in its ancestor
chain, so **no path on the CA passes the privileged-script tree gate** — the
officer scripts (`Set-OfficerRights.ps1`, `Revoke-Cert.ps1`,
`Reconcile-Revocation.ps1`) need `-AllowUntrustedScriptPath` on that host,
which is correct-but-loud (the refusal message says exactly what to do). The
RA host's `C:\` carries only Users create-class and needs no override.

Operator decision: either fix the CA's `C:\` DACL to the inherit-only default
shape (remove the applicable ACE), or accept that every CA-side privileged
script run carries the override. Not a product defect — the gate measured a
real escalation surface — but it should be a conscious choice, and the next
CA-host deploy should state it in `docs/operator-requirements.md`.

### 9. (bug, medium) — NEW. **Two of this repo's own gates cannot both be satisfied**

*Found 2026-08-25 when the daybreak branch's first CI run went red.*

The pre-push publication guard refuses a push whose commit authors are not
listed in `publication.toml`'s `author_email`.
`scripts/check_publication_plumbing.py` compares those entries as **literal
strings** — there is no pattern, domain, or hash form. So satisfying the guard
means writing the literal address into a tracked file.

The `identifier-gate` job forbids the homelab domain in tracked files. Both
addresses this repo's history actually carries end in that domain. **The two
gates are unsatisfiable together**, and the only ways through today are to
re-author every commit to the `users.noreply.github.com` address, to push with
`--no-verify`, or to leave the declaration knowingly stale.

Why it stayed invisible: the addresses are already on 17 commits on `main` and
CI has been green the whole time, because the identifier gate scans tracked
**files**, not commit metadata. The collision only surfaces when someone
declares what history already carries — which is precisely what the file exists
to do. A guard whose correct use trips a sibling guard is not a working guard.

**Options, in the order they should be considered:**

1. Drop the domain from the `ACME_RA_FORBIDDEN_IDENTIFIERS` secret. It is the
   homelab, not the work domain, and the repo is public under the owner's real
   name already — the entry may simply be over-broad. **Owner-only: a repo
   secret cannot be edited from a checkout.** This is the chosen direction as
   of 2026-08-25; the declaration re-lands once the secret changes.
2. Teach `check_publication_plumbing.py` a non-literal form (a domain suffix,
   or a hash of the address) so the guard can be satisfied without publishing
   the string. More work, but it is the version that survives the domain being
   genuinely sensitive later.
3. Re-author all commits to the noreply address. Cheapest, and it costs the
   distinct actor identity in the author field — which this repo relies on
   everywhere else it argues about lineage.

Until one lands, **the pre-push guard refuses this branch on identity**. That
refusal is expected. Do not silence it by widening the declaration; that is the
path that just failed CI.

### 10. (bug, medium) — NEW. **The Linux Pester job cannot see the tree gate at all**

*Found 2026-08-25, same CI run.*

`Assert-PrivilegedScriptTreeTrusted` is inert on Linux — it has no ACLs to
read. Every test that executes a gated script therefore proves nothing about
the gate on the Linux job, and the Linux job is the one everyone runs locally.

Concretely: the F10 fix (`ade72a8`) put the gate at the top of
`Sync-Revocations.ps1`, above the credential checks and the RA fetch that three
cases in `Sync.Tests.ps1` exercise. A CI checkout is not a DACL-trusted tree,
so on Windows the script refused at the gate with exit 1 and all three failed.
**Linux stayed 467/0 through the fix session, the live lab validation, and a
third-lineage adversarial review.** Only `pester-windows-powershell` saw it.

Fixed test-side by passing `-AllowUntrustedScriptPath` in that file's
invocation helper — the subject there is the credential surface, and the gate
keeps its own coverage in `InstallVerify.Tests.ps1`. The gate was **not**
weakened to suit a test.

**The item is the general case, not the three tests.** Any future assertion
about refusal behaviour written against the Linux job is vacuous by
construction, and vacuous tests manufacture confidence in the next reviewer.
Worth either marking the gate-dependent cases Windows-only so the Linux job
reports them skipped rather than passed, or giving the gate an injectable
verdict so its refusal path is exercisable everywhere.

### 11. (observation, would-be medium) — Lab network fabric flaps reachability, defeating any host-local CA blackhole

*Unfilable in the store (MIGRATION_REQUIRED, see header). Discovered
2026-08-24 during the v1.11.0 re-proof of `0a47955`, three Lqueue attempts.*

With a /32 host route for the CA's verified IPv4 via a verified-unreachable
next hop (and a /128 for its dead AAAA), a fresh .NET probe to the CA hung at
the 5 s ceiling at 13:23 — and the **identical probe, identical route, and an
Unreachable neighbor entry for the dead gateway, connected in 22 ms at
13:38**. During the same window, real enrollments completed in 0.5–0.7 s
through the verified-blackholed state: genuine CA issuance (ReqIDs advanced),
requester `WORK-DOMAIN\gMSA-acme-ra$`, and the CA's IIS log records the certsrv
requests arriving from the RA host's IPv4. The CA also carries a **dead AAAA
record** (refused in ~2 ms with or without routes), so single-family
blackholes are unsound even when the fabric is stable.

Risk: `Lqueue`/`Ldrain` of the live re-proof cannot produce a sound result
while this holds — the premise (enrollments hang on connect, so one order
provably queues) is silently false, and the failure mode reads like a product
defect. Second lab-network event this month (the CA silently changed v4
addresses earlier in August — runbook §11).

First step when picked up: from the RA host, run the same probe twice a few
minutes apart, with and without a route blackhole; if reachability still
flaps, the fabric (Hyper-V virtual switch / ARP / the dead-gateway `.251`)
needs the operator before any lease-pass re-run. Harness side is already
fixed (bh-route blackholes every resolved address; lease-pass recycles the
pool after route-on; the socket counter counts live states only) — owed is
re-running `lease-pass.sh` on a v1.11.x tag and getting Lqueue/Ldrain green
on the record.

### 12. (operator, medium) — NEW. **13 throwaway EAB kids are still allowlisted on the deployed lab RA**

*Found 2026-08-25 by a cross-lineage review of the v1.11.0 re-proof record,
which had closed with "the throwaway kids are gone" one sentence after saying
the dotenv was restored as-found. Both cannot be true; the record is corrected
in `docs/pre-pilot-checklist.md`.*

The deployed RA dotenv carries the previous session's throwaway phase-L EAB
allowlist — **13 kids** — because the v1.11.0 re-proof backed up that state and
restored to it. Restoring a backup preserves a deviation; it does not clean it.

Each kid is a live EAB credential path into the lab RA for whoever still holds
its MAC key, and **who holds them is unknown** — they were minted as throwaways
across two sessions with no record of disposal. EAB is the front control on
account creation: a holder can create an account and then operate inside that
kid's configured SAN scope. Lab-only today, which is why this is medium rather
than high.

**Close it by minting a real dotenv**, not by restoring another backup — every
restore since has re-installed the same 13. Do it before pilot regardless; a
pilot RA that inherits throwaway credentials from a test harness is the exact
shape this checklist exists to prevent.

### 13. (design, medium) — NEW. **The coalescing allowlist is a call-site patch four rounds running**

*Raised 2026-08-25 while fixing the third instance of it.*

Every audit-growth finding since round 5 has had the same shape: the coalescer
already existed, its docstring already contained the exact sentence justifying
the fix, and the new call site was simply not in `COALESCED_EVENT_TYPES`. Round
5 added four types. 14a added one. 2026-08-25 added three more.

`COALESCED_EVENT_TYPES` is an **allowlist**, so the default for a new
denial-shaped event is unbounded durable growth, and nothing fails until a
reviewer notices. The membership guard test
(`test_authenticated_and_issuance_events_are_never_coalesced`) catches *drift*
in the set — it fired correctly on this round's change — but it cannot catch an
event type that was never added to anything.

**Two candidate fixes, neither done:**

1. **Invert to a denylist.** Coalesce by default; list the event types that
   must keep one row per event (issuance, revocation, key rotation, admin state
   change) with a reason each. The default then fails safe. Cost: every
   existing call site needs auditing once, and a wrongly-defaulted *success*
   would silently lose a counter — which is exactly the
   `account-key-changed` hazard, so the denylist must be got right in one pass.
2. **Enumerate at test time.** A test that walks `routes/` for `_audit(...)`
   calls with a denial-shaped `outcome` and asserts each event type is either
   coalesced or in an explicit exempt-with-a-reason table. Cheaper, catches the
   next omission at CI rather than at review, and needs no behaviour change.

(2) is the smaller change and would have caught all three of this round's
findings. Not done here because this release is a park and a design change
wants its own round.

> **RESOLVED 2026-08-26** — option (2), in
> `tests/test_audit_coalescing_enumeration.py`. Five tests, six mutations, each
> caught.
>
> The enumeration walks the whole package rather than `routes/` alone: the
> denial-shaped sites are spread across `finalize.py`, `app_state.py` and
> `audit_retention.py` too, and a walker aimed only at `routes/` would have
> reported a clean tree while missing ten of them. It resolves `details` through
> one level of local-variable indirection, because the one site that builds its
> dict as a local (`orders.py`) is also the one site that had no `reason_code`.
>
> Two invariants, not one. The first is the item as filed: a denial-shaped event
> must be coalesced or listed in `_UNCOALESCED_WITH_A_BOUND` **with a written
> statement of what bounds the row count instead**. Ten events are listed there
> now, each with its actual bound (a one-way CAS, a TOCTOU race that cannot be
> replayed on demand, a CA round trip).
>
> The second was not in the filing and is the sharper of the two: **the
> coalescing key must be provably server-chosen.** The round-6 SAN defect was
> not that a call site was missing from the allowlist — it was *in* the
> allowlist, and still produced one durable row per request, because the key
> fell back to `reason` prose carrying the client's SAN. So the test requires
> the load-bearing value (`reason_code`, else `reason`) to be a source literal,
> or an allowlisted attribute expression whose closed set is **proven on every
> run** by reading the module that constructs it. Mutating
> `reason_code="san-out-of-scope"` to an f-string carrying the SAN fails that
> proof — the original defect is now caught at its source.
>
> One production change fell out of it: `order-rate-limited` in `orders.py` was
> the last coalesced site with no `reason_code`, keying on `f"{exc.scope}-limit"`.
> `scope` is server-chosen so there was no live defect, but the invariant could
> not be stated without it. It now sends `reason_code=exc.scope`; per-account
> and global denials keep separate windows exactly as before.
>
> A new denial-shaped event added with no decision now fails CI rather than
> waiting for round five of this class.

### 14. (harness, medium) — RESOLVED 2026-08-25. **The teardown's clean-CA check was inert**

The runbook's "did we clean up?" command was
`certutil -view -restrict "CertificateTemplate=ACME-ServerAuth"`. The
`CertificateTemplate` column holds the template **OID** for a custom template,
so the display-name form matches nothing and returns zero rows — which reads
exactly like "the CA is clean", and was recorded as that.

Restricting on the OID during the 2026-08-25 teardown found **18 certificates
still Issued under the template, only 3 of them from that run.** Fifteen were
live residue from earlier sessions, each of which had recorded a clean CA.

Third instance of this exact class in this project: the CONNECT-PROBE that
dialled a stale constant and certified an inert firewall rule; the blackhole
whose own probe hung on the wrong address; and now this. **The pattern is a
verification step whose failure mode is silence.** A check that can return
"nothing found" must be cross-checked against a broader query that is known to
return something, or it proves nothing.

Fixed in the runbook (OID form, plus an explicit instruction to cross-check a
zero against an unrestricted `Disposition=20` sweep) and in a new
`samples/lab-harness/teardown-revoke.ps1` that builds the revocation set from
the CA's own view rather than a pasted serial list — which is also what makes
it catch the ReqID-only transport orphan, the one certificate nothing in the RA
tracks.

### 15. (harness, low) — RESOLVED 2026-08-25. **Teardown order made administrators unable to revoke**

The teardown list said revoke first (step 1), revert the officer grant later
(step 3). A template-scoped `OfficerRights` blob restricts **every** certificate
manager to its own scoped requesters — Domain Admins included — so revoking as
an administrator while the grant is live fails with
`CERTSRV_E_RESTRICTEDOFFICER`. Measured 2026-08-25: 18/18 refused, then 18/18
succeeded after reverting the grant first.

This was already known (it is in the estate memory) and the runbook still had
it backwards, which is the more useful half of the lesson: a trap recorded in
one place and not in the procedure is a trap you pay for again. The runbook now
leads the teardown section with the ordering.


### 16. (harness, low) — NEW 2026-08-25. **lab/spike_mode_a.py cannot run on the deployed venv**

Found during the `3c599ca` lab validation (2026-08-25). The installer rebuilds
the venv from the hash-pinned product closure, which does not include
`requests_negotiate_sspi`; `spike main()` imports it BEFORE
`_create_protected_output_directory`, so the spike aborts with
`ModuleNotFoundError` before it creates anything. The 3c599ca protected-output
delta was therefore proven by driving the spike's own functions directly
(`spike-drive.py`, run as the gMSA: fresh-dir creation, exclusive key create,
rerun refusals, DACL evidence — 4/4), but the spike's enrollment leg has not
run since the code/state split moved the interpreter (the spike-runbook still
names the retired single-tree venv). Options: pin an SSPI client for a lab
extra, or port the spike to the product's own pyspnego-based
`negotiate_auth.NegotiateAuth` (already installed).

> **RESOLVED 2026-08-26** — the second option, which was the right one on the
> merits and not merely the installable one. `requests-negotiate-sspi` was
> retired from the issuance path in 2026-06 (single maintainer, broken on
> 3.14), so a spike still on it was exercising a leg the RA no longer has, and
> would fail against EPA=Require — which is what the lab actually runs.
> `docs/spike-runbook.md` had *already* been updated to tell operators to use
> the in-tree implementation, so the code was the last thing still on the old
> library. **The enrollment leg still has not run; it is now merely able to.**

### 17. (harness, medium) — NEW 2026-08-26. **The phase-L blackhole instrument is unsound in two independent ways**

Both found by inspection plus execution on 2026-08-26, while deciding what to
fix before booking the next rig. Neither is the "flapping lab network" that
item 11 blamed, and item 11's diagnosis should be treated as retracted.

**The probe cannot distinguish success from refusal.** `bh-route.ps1`'s `Probe`
calls `BeginConnect(...).AsyncWaitHandle.WaitOne(5000)` and never calls
`EndConnect`, so it reports whether the operation *completed*, not whether it
*connected*. Running the old function verbatim against real sockets:

```
OLD CONNECT-PROBE[127.0.0.1:22]:  completed=True   elapsed_ms=66     <- real connection
OLD CONNECT-PROBE[127.0.0.1:9]:   completed=True   elapsed_ms=2      <- REFUSED
OLD CONNECT-PROBE[192.0.2.1:443]: completed=False  elapsed_ms=3000   <- dropped
```

Two opposite verdicts, one word. With the blackhole on, a refusal reads as a
failed blackhole; with it off, a refusal reads as a restored CA — so a teardown
can certify itself complete while the CA is unreachable, and every later phase
measures a broken lab without saying so. The distinction is load-bearing beyond
reporting: an RST unblocks the client immediately, so the enrollment pool never
saturates and **Lqueue cannot build a queue at all**. Only a silent drop hangs
the client.

**The mechanism is unsound for this topology.** A `/32` via a dead next hop
cannot be trusted when the CA is **on-link**: the destination is also covered by
the interface's connected route, and Windows can satisfy the send from it while
`Get-NetRoute` still reports the `/32` as `PRESENT`. The precheck is fail-open
in the literal sense — `if ($n -and $n.State -notin (...))` proceeds when
`Get-NetNeighbor` returns nothing, treating *unknown* as *verified
unreachable* — and it only ever checks the v4 dead gateway, never the v6 one.

**Replacement written, not yet run on the lab:** `reachprobe.ps1` (three
verdicts — connected/refused/dropped — as exit codes, proven against real
sockets) and `ca-inbound-block.ps1` (inbound Block on the CA scoped to the RA's
source addresses; Windows Firewall Block discards silently, which is the
behaviour phase L needs). Both live outside the repo because
`samples/lab-harness/` is gitignored; they were handed off on 2026-08-26 with
`PHASE-L-HANDOFF.md`. **Do not go back to an outbound Block on the RA** — that
was measured not blocking at all on that host.

This is the third instrument in this project whose failure mode was silence
(stale CONNECT-PROBE target, inert firewall rule, the template-name teardown
check that matched nothing). **Prove the instrument before the phenomenon:**
blackhole on, probe says `dropped` on every address, and only then run Lqueue.

### 18. (test, medium) — NEW 2026-08-27. **Two enrollment deadline tests race the wall clock**

*Found when CI went red on a branch that could not have caused it.*

`tests/test_enrollment.py` built `CertsrvEnrollmentLeg` with
`total_timeout=0.05` in two places. The property under test is that a deadline
expiring **during the certificate stream** still reports the ReqID the CA has
already issued — so the 50 ms budget had to cover the `certfnsh.asp` POST and
the ReqID parse before the blocked read even began. On a loaded runner it did
not: the deadline fired first, `req_id` was never attached, and
`test_one_deadline_aborts_stream_and_preserves_issued_req_id` failed on
`assert None == '42'`.

**The evidence that it is a race, not a regression:** the *same commit*
(`37ec313`) passed the push run and failed the pull_request run — same Python
3.12, same tree, opposite results. A suite whose green is load-bearing cannot
have a test that disagrees with itself on identical input.

Mitigated by widening both budgets to 0.5 s and scaling the elapsed assertion
to 2.0 s — still far below the 5.0 s per-operation timeout, so the tests still
prove the *total* deadline is what fired, and still inside the blocked read's
1.0 s wait, so the deadline still expires mid-stream. Verified not vacuous:
mutating `req_id=issued_req_id` to `req_id=None` still fails the first test.

**This widens the race rather than removing it, and that is the open item.**
The real fix is an injectable clock on `CertsrvEnrollmentLeg` so the deadline
is not wall-clock at all. Deliberately not done here: `time.monotonic()` is
read at six sites in the issuance path plus a watchdog thread, and rewriting
that to be fake-clock-driven immediately before a live lab validation is the
wrong order of operations. Do it in its own round, with the lab available to
re-prove the enrollment leg afterwards.

The second site (`ReqID=73`) had never failed but carried identical exposure —
fixed at the same time rather than waiting for it to lose the race too.

> **NUMBERING NOTE.** This file already contains two independent numbering runs
> merged together, so items 8–13 each appear twice. New items continue from 18
> to avoid a third collision; refer to anything below by number **and title**.

### 19. (bug, low) — RESOLVED 2026-08-27. **The spike failed a SUCCESSFUL enrollment on content-type**

*Found by the 2026-08-27 lab validation, hazard 4 — the first run of the spike's
enrollment leg since the code/state split.*

`lab/spike_mode_a.py` required `Content-Type: application/pkix-cert` exactly
when fetching `certnew.cer`. Real ADCS serves that response as **text/html**
with the PEM inside it. So the leg worked perfectly — gMSA identity,
`NegotiateAuth` against `EPA=Require`, CSR accepted, **ReqID 671, disposition
20 at the CA, certificate genuinely issued and verified serverAuth-only with
the SAN from the CSR** — and the spike then exited 1. The spike was stricter
than the CA is truthful.

The product has always known this: `_parse_cert_body` tolerates a PEM block or
a raw base64 DER blob, and uses the content-type only to decorate a parse
*failure*. The gate was a lab-code re-implementation that was stricter than the
shipped behaviour it was supposed to be exercising.

> **Fixed** by calling the product's own `_parse_cert_body` and demoting
> content-type to diagnostic. The spike now proves the shipped parser against
> real CA output instead of asserting a rule the product does not hold.

### 20. (operator, HIGH) — NEW 2026-08-27. **The shipped CRL-freshness recommendation is below the floor**

*WI-052 / CRL3, finally measured. This supersedes every prior "unchanged
operator calibration item" note — it is no longer a calibration gap, it is a
wrong published number.*

`docs/operations.md` derives `A_sched_max = CRLPeriod + ClockSkewMinutes =
605400s`, a hard ceiling of `649200s`, and recommends **626400**. The live
re-derivation measured `A_sched_max` at **649800s**.

That is **above** the hard ceiling. The interval
`(A_sched_max, nextUpdate − thisUpdate)` that `max_age_seconds` must sit
strictly inside is therefore **empty**: no safe value exists on this cadence.
The shipped 626400 is **23400s (6h30m) below the floor**, so an operator
following the documentation would judge a genuinely current CRL stale and fail
every confirmation closed — the failure the setting exists to prevent.

**Docs corrected 2026-08-27** with a refutation banner in `operations.md` and a
warning in the checklist: leave
`ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` at `false` on a CA with this
schedule, or change the CA's publication policy.

**The open half is the model, not the number.** A floor above the ceiling means
the derivation is wrong somewhere, and the obvious candidate is the 43200s
overlap that `A_sched_max` excludes — whether a still-*current* CRL can be
served at an age past `CRLPeriod`, through CDP caching or otherwise. **Do not
just substitute 649800 and republish**: shipping a second unverified
recommendation is exactly how this item arrived. Capture the working from the
2026-08-27 run, decide whether the overlap belongs in `A_sched_max`, then
re-derive and re-measure against a real CRL.

> ## RESOLVED 2026-08-27 — the overlap does belong, and **≥ 649800** is the answer
>
> **REOPENED hours later by item 24 (below): this resolution derives the floor
> from the published window, which is the wrong quantity — the floor that
> governs false refusals is the maximum age an honest CDP serves, and the two
> differ by exactly the CA's overlap. The number is deliberately left in place
> as the interim value (it cannot false-fail on either reading) pending two
> publication cycles of `sample_crl_age.py` data. Item 24 records why it must
> not be re-derived on paper. The "RESOLVED" heading and body below are kept
> as the record of the reasoning, not as a settled answer.**
>
> The decomposition, derived live against the CA:
>
> ```
> 649800 = 604800  CRLPeriod (CRLPeriod=Weeks, CRLPeriodUnits=1)
>        +  43200  computed overlap (CRLOverlapUnits=0 ⇒ ADCS computes it; lands on 12h)
>        +   1200  2 × ClockSkewMinutes, stamped at BOTH thisUpdate and nextUpdate
>        +    600  1 × ClockSkewMinutes, CA↔RA skew allowance
> ```
>
> The first three are the published window (**649200s**, matching the measured
> `nextUpdate − thisUpdate` exactly); the fourth is the RA-clock allowance. So
> the overlap **does** belong in `A_sched_max`: a CRL is *current* for its whole
> published window, and the oldest still-valid CRL the RA can be handed is one
> full window old. The original table's `CRLPeriod + ClockSkewMinutes` was the
> age of the newest CRL, not the oldest valid one.
>
> **Two corrections to what this item said yesterday**, both mine:
>
> 1. **"No safe value exists" was wrong** — an overstatement. 649800 is
>    perfectly safe against false staleness. What does not exist is a value that
>    is *both* safe and **binding**, because 649800 exceeds the 649200s window.
>    The original constraint `A_sched_max < max_age < window` is unsatisfiable
>    here and it is the **upper** bound that must give.
> 2. **"Leave `REQUIRE_CRL_EVIDENCE` at false" was the wrong remedy.** It should
>    be enabled with `max_age_seconds ≥ 649800`. A non-binding ceiling behind
>    the CRL's own `nextUpdate` is a weaker control than designed, but it is
>    strictly better than no CRL evidence at all.
>
> **The trade to state in any deployment review:** on this cadence the
> independent age ceiling does not fire before the CRL expires on its own. A
> binding ceiling comes back only by shortening the CA's **overlap** — the
> 43200s term is what pushes the floor past the window.
>
> **The durable methodological point, which outlives the number: derive the
> floor from the published CRL, not from the registry.** Whatever mechanism
> produces the observed 12h20m, the `CRLOverlap*` registry values do not
> decompose to it. Read `thisUpdate`/`nextUpdate` off a real CRL and add one
> `ClockSkewMinutes`. Reconstructing the window from configuration is what
> produced both wrong numbers in this item's history.

### 21. (harness, medium) — RESOLVED LIVE 2026-08-27. **Both phase-L instruments were defective, and Rule Zero caught them**

*The replacements written on 2026-08-26 (item 17) had two defects of their own,
both found before the phenomenon ran. Recording them because the pattern is the
point: an instrument written to replace a silently-failing instrument failed
silently in two new ways.*

1. **`reachprobe.ps1` was IPv4-only.** The parameterless `TcpClient`
   constructor binds AF_INET on .NET Framework, so every IPv6 target reported
   an instant `refused`. Compounding it, the "dead AAAA record" assumed by
   earlier rounds **is alive** — the CA holds a ULA. The probe would have
   reported `refused` on v6 forever; the gate ("anything but `dropped` → stop")
   held, but for the wrong reason.
2. **`ca-inbound-block.ps1` reported through the success stream.** `Show-State`
   used `Write-Output` *and* returned a count, so `$n = Show-State` captured
   the printed lines too and `if ($n -lt 1)` compared an array — the postcheck
   could never fire, and `-Mode show` printed nothing. **This is the same
   defect class as the 2026-08-14 wave-3 F1 finding** (`Write-Output`×3 +
   `return $false` read as a non-empty array = true), reproduced by the author
   of the memory note describing it, inside a script written specifically about
   instruments that fail silently.

Both fixed live; the fixes persist in gitignored `samples/lab-harness/`.

**Result once the instrument was sound: phase L is GREEN for the first time.**
Inbound Block scoped to both RA addresses → probe `dropped` on both CA
addresses at the ceiling → §L 9/9 → Lqueue 8/8 → block off → `connected` →
Ldrain 4/5 (Ld1 is the documented §9 caveat from a manual gap; Ld2–Ld5 pass —
stale worker abandoned on a lapsed generation, one certificate, no double
issuance). **Item 11's "flapping lab fabric" is formally RETRACTED**; the fabric
was never the problem.

**Also found:** `raproof.py`'s Lqueue fired 42 fillers against a 32-slot
admission gate, deterministically shedding the target
(`finalize-enrollment-admission-denied`, `revert_applied=true`). The product
was correct both times — the harness was over-driving it. Fillers now capped at
`max_pending − workers − 1`; new driver `lease-pass-fw.sh`.

### 22. (measurement, medium) — NEW 2026-08-27. **The teardown destroys the only evidence that could calibrate WI-052**

*Found while trying to answer "what age of CRL is the RA actually served?" from
the deployed store.*

`routes/admin.py` records `crl_this_update` on every revocation confirmation, so
the age distribution should be derivable from `audit_log`. It is not. Measured
against the deployed store (read-only copy, 2026-08-27):

```
audit_log rows: 722
span:           2026-06-20T01:49:26Z -> 2026-08-25T04:35:26Z
rows carrying crl_this_update:  NONE
admin-revocation-confirm-* rows: NONE
```

The CRL-evidence path has been exercised live in at least three sessions
(2026-08-14, 08-17, 08-25/27), each producing `crl-verified` confirmations. Not
one survives. **Every validation ends by restoring the store to its pre-run
fingerprint, which is exactly right for isolation and is amnesia for
measurement.** All the `reproof-backup-*` copies on the RA host are *pre*-run
snapshots; no post-run store is retained.

So WI-052 was never merely un-measured — under the current procedure it is
**un-measurable**, and would have stayed that way however many validations ran.
That is why the item survived so long: each session generated the evidence and
then deleted it.

**Two things follow.**

1. **The age distribution needs a sampler that lives outside the restore
   scope**, not the RA's audit table. It does not need the RA at all: fetch the
   CDP URL on a schedule for two-plus publication cycles and log
   `thisUpdate` / `nextUpdate` / observed age to a file. That answers the
   binding-vs-non-binding question directly, and it can run from anywhere with
   CDP reach. See item 20 for why the question matters.
2. **The general case is worth a decision:** any property needing longitudinal
   evidence is invisible to this lab process. Either preserve the post-run store
   under a dated name (one file per session, no interference with the restore),
   or accept that only within-session properties can ever be measured. The first
   is nearly free.

> **BUILT 2026-08-27.** Both halves.
>
> * `scripts/sample_crl_age.py` — samples a CDP, appends
>   `thisUpdate`/`nextUpdate`/observed age/CRL Number to a JSONL file, and
>   `--summarize` prints the age distribution, the binding upper bound, and any
>   **CRL Number regressions** (which is also the false-positive measurement
>   item 23's control needs). Failed fetches are recorded, not skipped: a
>   sampler that drops failures measures only the CA's good days.
> * `samples/lab-harness/restore.ps1` now copies the post-run store — all three
>   SQLite files, after the pool is confirmed stopped — to
>   `postrun-store-<ts>` **before** removing anything, and throws rather than
>   warning if it cannot, so the restore can be re-run without loss.
>
> **Caveat on the second half: `samples/` is gitignored**, so the `restore.ps1`
> change exists only in this operator box's checkout. It ships to the RA host on
> the next teardown (the harness is scp'd per run), but it is not in the repo, not
> on CI, and not in a fresh clone. The *policy* is therefore also written into
> `docs/live-reproof-runbook.md` §E, which is committed — if the harness copy is
> ever lost, the requirement survives. Anyone re-proving from a clean checkout
> must re-apply it.
>
> **Gap closed 2026-08-28:** runbook §E now carries the reference
> implementation of the preserve block itself (identifier-free,
> placeholder-parameterised), so a clean checkout re-applies the change by
> paste rather than re-deriving it from policy prose. The live copy in
> `samples/lab-harness/restore.ps1` remains the authoritative one; the two
> must not drift.
>
> Running against the lab CA every 30 minutes from the operator box since
> 2026-08-27T19:13Z (first sample: CRL Number 127, age 55446s, window 649200s).
> The first thing it found was **item 24**, which is not the question it was
> pointed at.

### 23. (design, medium) — NEW 2026-08-27. **Replace the replay control: monotonic CRL, not an age ceiling**

*Design filed rather than built; it wants its own round and a live proof.*

**Why.** `revocation_confirm_crl_max_age_seconds` was intended as an independent
replay-age bound, and item 20 shows it cannot be one: the floor
(`window + skew`) exceeds the binding upper bound (`window`) for **any** CA. An
age ceiling is the wrong shape for the job.

**What the control is actually defending.** A stale CRL that *lacks* the serial
fails closed, so age never protects the "was it really revoked?" direction —
`nextUpdate` and the signature do that. The only wrong-*accept* an old CRL can
produce is a **hold→unhold replay**: a certificate revoked with reason 6 and
later removed from the CRL with reason 8 (which this lab does routinely) is
still listed on an older CRL, so replaying it confirms a revocation for a
currently-valid certificate. Narrow, but real, and it needs the confirm token.

**Design.**

A watermark per issuing CA, checked on every CRL fetch that reaches evidence
evaluation:

- New table, one row per CA:
  `crl_watermark(issuer_key TEXT PRIMARY KEY, crl_number TEXT NULL,
  this_update TEXT NOT NULL, observed_at TEXT NOT NULL, source_url TEXT)`.
- `issuer_key` = digest over the issuer DN **and** the CA certificate's SPKI.
  Not the CDP URL (which changes), and not the DN alone (which is reused across
  key rollover).
- Prefer the **CRL Number** extension (2.5.29.20): RFC 5280 requires it to be
  monotonically increasing per CA, which is exactly the property wanted. Fall
  back to `thisUpdate` when absent.
- Compare, then: `newer` → accept and advance the watermark **in the same
  transaction as the confirm**; `equal` → accept (same document); `older` →
  refuse with `crl-evidence-regressed`.

**Failure modes that must be designed for, not discovered:**

- **Replica skew.** Round-robin CDP replicas at different vintages will regress.
  Retry once before refusing; refuse loudly if it persists, because a regressing
  CDP is a genuine operational fault worth surfacing.
- **CA key rollover.** New SPKI ⇒ new `issuer_key` ⇒ fresh watermark. Correct by
  construction, which is why SPKI belongs in the key.
- **CRL Number reset** (CA restored from backup) wedges the control. Needs an
  explicit operator reset, deliberately **not** automatic — an auto-reset
  defeats the control entirely.
- **First observation** is trust-on-first-use and protects nothing. Say so
  plainly rather than implying otherwise.

**What this does to the age ceiling.** It stops being the replay control and
becomes a **liveness alarm** on the CA's publication pipeline — set from measured
served-age (item 22), documented as an alarm, and honestly non-binding at the
conservative default.

**Live proof does not need the CA.** The RA fetches by URL, so point
`revocation_confirm_crl_url` at a local stand-in: serve a captured older CRL
after a newer one has been seen and assert `crl-evidence-regressed`. No CA-side
change, no officer rights, no teardown risk.

**Tests:** advance / equal / regress; CRL-Number-over-`thisUpdate` precedence;
first observation; rollover producing a distinct key; watermark advancing in the
confirm's transaction and not before it. Mutation-prove the regress refusal —
it is the only branch that carries the security property.

> **BUILT 2026-08-27**, to the design above, with two deviations worth naming.
>
> * **The watermark identity is derived from the certificate's stored chain, not
>   from the fetched CRL.** The design said "issuer DN plus the CA cert's SPKI"
>   without saying where the DN comes from, and taking it from the CRL would
>   have meant a network round trip before the store could be consulted — plus a
>   DN-encoding comparison (PrintableString vs UTF8String) that CAs do not
>   always make cleanly. Both halves now come from the CA certificate the leaf
>   was issued under; the fetched document is bound to that identity by the
>   signature check that already existed.
> * **`enforce_monotonic=False`** was not in the design. It records the verdict
>   without refusing on it, for an estate whose replicas are known to lag —
>   because the alternative an operator reaches for is turning CRL evidence off
>   entirely, and then nothing is measured either.
>
> Shipped: `crl_watermark` table (`Store.read_crl_watermark`,
> `reset_crl_watermark`, and a compare-and-set advance inside the confirm's own
> transaction), `compare_to_watermark` / `crl_watermark_key` in `crl_evidence`,
> the single re-fetch before a regression is believed, the
> `crl-evidence-regressed` denial reason, and
> `ACME_RA_REVOCATION_CONFIRM_CRL_REQUIRE_MONOTONIC` (default **true**).
> `tests/test_crl_watermark.py`, 21 tests, mutation-proved against four
> reverted fixes: the regress refusal, the compare-and-set, the SPKI in the key,
> and CRL-Number precedence — each kills exactly the tests that claim it.
>
> **Still owed: the live proof.** It needs no CA-side change — point
> `revocation_confirm_crl_url` at a stand-in serving a captured older CRL after
> a newer one has been seen, and assert `crl-evidence-regressed`. Until that
> runs, this is a control that has only ever been exercised against CRLs this
> repository generated itself.

### 24. (measurement, HIGH) — NEW 2026-08-27. **The WI-052 floor conflates the attacker's reach with the CDP's output**

*Found while writing the sampler's tests for item 22: a test asserting "no
binding ceiling can exist" failed against the summariser, and the summariser was
right.*

Item 20's resolution derives the floor as **published window + one
`ClockSkewMinutes` = 649800s**, on the reasoning that "the oldest still-valid CRL
the RA can be handed is one full window old". That sentence is true, and it is
the wrong quantity for a floor.

Two different ages are in play and the derivation uses one for both:

| quantity | what it is | value on this CA |
|---|---|---|
| **publication interval `P`** | how often the CA republishes; bounds the age of what an honest CDP serves | `CRLPeriod` = 604800s |
| **published window `W`** | `nextUpdate − thisUpdate`; bounds how long a replayed document stays unexpired | measured 649200s |

The **floor** (below which healthy CRLs get refused) is set by `P` plus
lateness and skew — the RA is only ever *served* the current document. The
**upper bound** (above which the ceiling adds nothing to `nextUpdate`) is set by
`W` — that is the attacker's reach. Using `W` for both closes the interval by
construction, which is exactly the "unsatisfiable for any CA" conclusion.

For a CA that publishes with **overlap** (`P < W`, which is the point of
overlap) the interval is not empty; its width is the overlap itself. On this CA
that is `604800 < max_age < 649200`, a 44400s (12h20m) gap — and the originally
shipped **626400** sits inside it. So the "wrong published number" finding may
itself be wrong, and the correction to `≥ 649800` may have made the ceiling
non-binding for no reason.

**Not changing the number on this reasoning.** Item 20 warns in its own body
that shipping a second unverified recommendation is how it arrived, and this is
a third derivation on paper — the fourth would be the same mistake with a
different sign. **`P` is the measurable one**: it is the maximum age the CDP
actually serves, and `scripts/sample_crl_age.py` (item 22) has been sampling it
every 30 minutes since 2026-08-27T19:13Z. Two publication cycles settle it.

* if measured max served age stays near 604800 → a binding ceiling exists, item
  20's floor is wrong, and 626400 was defensible all along;
* if it reaches toward 649200 (the CA publishes late, or a cache serves stale)
  → item 20's floor is right for the reason it is *actually* right, which is
  lateness rather than the window, and the ceiling genuinely cannot bind.

**This does not change item 23.** The monotonic watermark is the replay control
either way, and its value is that it does not depend on which of these answers
is correct — no calibration, so no derivation to get wrong a fifth time. The
ceiling stays a liveness alarm regardless; the only thing at stake here is where
that alarm's threshold sits.

**In fairness to item 20:** `operations.md` already flags this as an open
question — *"How often the RA is handed an old-but-still-current CRL depends on
CDP and cache behaviour — measure it before tightening"*. What is added here is
naming **which quantity the floor actually is** (served age, not window) and
pointing a running instrument at it, rather than leaving it as an open question
for a fifth session to re-derive on paper.

**Do not "resolve" this from the registry, the docs, or another table.** Three
of the four derivations so far were done that way and two of them were wrong.
Read the sampler.

---

### 24 (continued). RESOLVED 2026-09-05 — measured, and 626400 was defensible all along

The sampler ran from 2026-08-27T19:13Z to 2026-09-05T02:00Z: **399 samples, zero
failed fetches, one complete publication cycle** (CRL 127 ageing 55,446s →
603,654s, then 128 arriving at 626s).

| quantity | measured |
|---|---|
| max age served | **603654s** |
| upper bound on that (+ one 1800s sampling interval) | **605454s** |
| published window, all 399 samples | **649200s** |
| usable band | **(605454, 649200)** — 43746s wide |
| CRL Number regressions | **0** |

This is the first branch of the two this item predicted: *"if measured max
served age stays near 604800 → a binding ceiling exists, item 20's floor is
wrong, and 626400 was defensible all along."* It does, one is, it was, and it
was. The application default is now **626400**, pinned with its reasoning in
`tests/test_crl_max_age_calibration.py`.

**Both previously published numbers were outside the band.** `649800` is above
the roof, so it never fires before `nextUpdate`. `604800` — the default this
replaces — clears the *observed* maximum by 1146s but not its upper bound, so it
could refuse a healthy CRL in the minutes before republication. That second one
matters more than it looks: it was the shipped default while the documentation
recommended a different, also-wrong number, so no deployment was configured the
way any part of the record advised.

**The lesson is the one this item already named, now with a cost attached.** No
document carries the maximum age a CDP serves; it is a property of behaviour
over time. Four attempts to read it off a document produced two published wrong
numbers. Nine days of a 40-line sampler settled it. When a quantity's failure
mode is "the derivation looks plausible", the instrument is cheaper than the
argument.

**Caveat kept honest:** one publication cycle, one CA, one CDP. The band's
*existence* generalises to any CA that publishes with overlap; the *numbers* do
not generalise anywhere. A second cycle would tighten the floor, though the band
is wide enough that the conclusion is unlikely to move.

---

### 25. (design, medium) — NEW 2026-09-05, **CORRECTED same day**. **A transport-orphaned certificate has no issuer material, so its revocation can never be confirmed**

> **Correction to this item's first draft, which was too broad and got the
> remedy wrong.** It said quarantine means "the RA has the serial but no
> chain", and proposed reusing `ACME_RA_ADCS_CA_BUNDLE` as issuer material.
> Both are wrong, and the second is the more dangerous:
>
> * **Quarantine does not imply a missing chain.** `_quarantine_and_fail`
>   passes `enrollment_result.chain_pem`, so a certificate quarantined for a
>   SAN or EKU violation carries a full chain and confirms normally. Only the
>   *transport-orphan* path can produce a chainless row.
> * **The orphans are not identity-less either.** `_quarantine_transport_orphan`
>   already separates two cases in so many words: leaf in hand (chain fetch or
>   chain-binds-to-leaf failed) writes a `quarantined` row with `cert_pem`, the
>   derived serial and the ReqID; leaf never received writes **no certificate
>   row at all**, because the store keys on the bytes. Verified on the lab
>   store: both blocked records carry a 2308-byte `cert_pem` and an empty
>   `chain_pem`, and the same session produced two genuinely leafless incidents
>   (`quarantined=false`, ReqID only) that must not be conflated with them.
> * **`ACME_RA_ADCS_CA_BUNDLE` is TLS trust for the `/certsrv/` leg**, passed as
>   `ca_bundle` to `CertsrvEnrollmentLeg`/`CertsrvRevocationLeg`. It is not an
>   issuing-CA pin and must not silently acquire that second meaning — a knob
>   that means "trust this for transport" quietly becoming "trust this to
>   attest issuance" is exactly the kind of overload that is invisible in
>   review.
>
> So the problem is **narrower and more tractable** than the draft claimed:
> certificate identity is present, **issuer material is missing**, and the fix
> is to recover the missing evidence and then run the existing verifier
> unchanged.

**The blocked state.** A transport-orphaned certificate whose chain fetch failed
has `chain_pem` empty. CRL evidence verifies the CRL's signature against the
issuing CA certificate taken from **the certificate's own stored chain**
(deliberately: selecting the issuer by name rather than by signature picks the
wrong generation across a CA key rollover). With no chain there is no issuer
certificate, so every confirmation is refused:

```
crl_detail: "could not locate the issuing CA certificate in the stored chain,
             so the CRL signature cannot be verified"
```

With `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE=true` that is permanent.
The serial sits in the pending set with no operator path out — and it is a
certificate that is **live at the CA**, which is the worst population to lose
track of.

**What NOT to do.** Both shortcuts are tempting and both are wrong:

* do **not** exempt these from the evidence requirement. This is the state where
  the RA knows *least* about what the CA did; it is the last place to relax
  verification.
* do **not** clear them out of the pending set to make the queue drain. The
  pending set is the record that a revocation is owed.

**The design principle: recover the missing evidence, then run the existing
verifier.** Nothing about the trust model changes — the same signature check,
the same freshness ceiling, the same watermark. Only the input is repaired.

**1. Recover issuer material for the stored leaf.** Obtain candidate issuer
certificates, verify **which candidate actually signed the stored leaf**
(`x509.Certificate.verify_directly_issued_by`, which dispatches on the signature
algorithm — do not hand-roll a PKCS1v15 check, it fails silently on an ECDSA
CA), persist the validated chain with an audit record, then let the ordinary
confirm path run. The record stays `quarantined` and stays pending until
confirmation actually succeeds; recovery repairs evidence, it does not decide
anything. Note that a successful confirmation sets `ca_crl_updated` and does
**not** change status today — that is correct and should stay: quarantine is a
statement about the certificate, pending-revocation is a statement about the CA,
and they are not the same fact.

> **The candidate source is already on disk, and it needs no new configuration.**
> The RA's own store holds complete chains from the same CA for every
> certificate it issued successfully. Measured on the lab store: 80 issuer
> certificates across the stored chains, 2 distinct, and the correct one
> verifies both orphans' signatures. That material arrived over the *same*
> authenticated enrollment leg as the orphan itself, so it carries the same
> provenance — a strictly better source than a new trust setting, and it
> satisfies the constraint that recovery must work **after** the failure rather
> than depend on another network request succeeding during quarantine.
>
> Fallback for a cold store (an orphan on the very first issuance, before any
> chain has been stored): an explicit, separately-named issuer inventory whose
> provenance is at least as strong as the enrollment leg's. Not
> `ACME_RA_ADCS_CA_BUNDLE`.

**2. CA-database reconciliation is a separate evidence policy, not a
substitute.** `certutil -view` by ReqID or serial — which
`Reconcile-Revocation.ps1` already drives — is the only route for the
**leafless** class, where there is no certificate row and the ReqID is all that
exists: it can recover the certificate bytes and correlate a ReqID with a
specific CA request, feeding the recovered leaf back into (1). That is recovery
of *input*. It is **not** evidence: a database assertion does not satisfy
`require_crl_evidence=true`, and recording it under a different `verification`
value would not change that — honesty about the label does not move the gate.
Anything that closes a record on a CA-DB assertion alone is a weakening of the
requirement and has to be argued as one, explicitly, not smuggled in as a
naming choice.

**3. Expose the blocked state now, before either of the above.** This is the
cheap part and should not wait on the design. Today the failure is an
indistinguishable repeating denial in the audit trail with no signal that the
serial can *never* succeed under the current configuration. The revocation
obligation must stay visible with a reason of its own — `issuer-evidence-missing`
— and a documented recovery action, and it must be distinguishable from the
leafless ReqID-only incidents, which need a different action (revoke by ReqID at
the CA by hand). Neither category may disappear merely because ordinary retries
cannot resolve it.

**Blast radius.** Narrower than the first draft implied. Not "quarantined
certificates" — only transport orphans whose chain fetch failed, of which the
lab store holds two, plus two leafless incidents in the other category. In a
pilot the population is whatever the CA issued while the RA could not hear the
response: small, live at the CA, and exactly the set an operator most needs
reconciled.

**Scope and acceptance criteria, agreed 2026-09-05.** This item is ready for a
bounded implementation. **In scope:** existing-chain recovery (1) and
blocked-state visibility (3). **Explicitly unresolved, and deliberately not
blocking:** the cold-start inventory fallback, which only affects an orphan
produced before the store holds any complete chain from that CA — a case not
demonstrated here, while the two that are demonstrated are both recoverable from
material already on disk. CA-database reconciliation (2) stays a separate
evidence policy and is not part of this item.

Requirements the implementation must satisfy:

1. **Deduplicate candidate issuer certificates, and select by
   `verify_directly_issued_by` — never by subject name alone.** Deduplicate by
   certificate fingerprint, *not* by subject: the store can legitimately hold
   more than one generation of the same CA's key under an identical DN, and
   collapsing them by name would discard the generation that actually signed the
   orphan. Selecting by signature is what keeps older generations supported,
   and it is the same property `_watermark_key` already relies on.
2. **Persist the recovered issuer evidence with an audit record naming its
   source and the certificate's fingerprint.** Where the material came from is
   part of the evidence; a recovered chain that cannot be traced back to what
   supplied it is not better than no chain.
3. **Run the ordinary CRL verification and watermark checks afterwards, with no
   exemptions.** Finding an issuer is *evidence repair*, not revocation
   confirmation. Freshness, signature and monotonicity all still have to pass on
   their own terms.
4. **Preserve `QUARANTINED` status after a successful confirmation; update only
   the existing CA-revocation bookkeeping.** This is the current behaviour
   (`ca_crl_updated` is set, status is untouched) and it is correct: quarantine
   is a statement about the certificate, pending-revocation is a statement about
   the CA. An implementer reading "pending until confirmation succeeds" could
   easily un-quarantine on success — do not.
5. **Keep leafless ReqID-only incidents separately visible.** This recovery path
   cannot resolve them; they need an operator revoking by ReqID at the CA. They
   must not be folded into the recoverable class, and must not disappear from
   view because no automated path exists.

---

### 26. (bug, medium) — NEW 2026-09-05. **The teardown revokes at the CA but never republishes the CRL, so a session's revocations stay invisible to relying parties for up to a week**

**Observed live, and only by accident.** While completing the §A.2
independent-client record, one certificate was revoked and the CRL published.
The CRL's entry count went **370 → 401**. One revocation, thirty-one new
entries.

The other thirty were `raproof-*` certificates that the **previous session's
teardown** had revoked at the CA — 29 at `2026-09-05T02:40Z` and 1 at
`04:26Z`, all reason `0x4 Superseded` — and never published. CRL 129 was
published at `02:11Z`, *before* those revocations, and the sampler shows CRL
Number 129 served continuously through `07:30Z`. They sat revoked-but-
unpublished for ~5.5 hours and would have stayed that way until the next
scheduled publication had this session not published for an unrelated reason.
This CA has `CRLPeriod = 1 Week`, so worst-case exposure is close to a week.

**§E says to revoke and restore. It does not say to republish** — and the
validation-log entries for earlier rounds assert "revoked … and the CRL
republished", a claim at least one round did not actually satisfy. That is the
familiar shape: the step was believed done because the sentence describing it
was written, and nothing checked.

**Why this is not lab housekeeping.** A certificate the CA considers revoked
but that no relying party can see as revoked is precisely the state this
product's revocation story exists to prevent. Leaving the lab in it also means
the *next* session's CRL-evidence checks — `require_crl_evidence`, and the
monotonic watermark's first-use baseline — run against a CRL that is silently
missing the prior session's revocations. And it makes any cross-session claim
about revocation latency unmeasurable, in the same way item 22 made the CRL age
unmeasurable: not un-measured, **un-measurABLE**.

**Fix.**

1. Add an explicit `certutil -config <CA> -CRL` to §E, after the revocation
   loop.
2. **Make it evidence-bearing rather than asserted.** Re-fetch the CDP and
   assert both that the CRL Number advanced *and* that every serial the
   teardown just revoked is listed — with a negative control, because a CRL
   lookup that matches nothing returns the same "not found" as a correct
   negative. A teardown step whose failure mode is silence needs the same
   treatment §E already gives the preserve step: verify, do not assert.
3. Note the interaction with `scripts/sample_crl_age.py`. A forced
   republication truncates the current publication cycle. That **cannot**
   corrupt the served-age floor — a truncated cycle only ever serves ages below
   the running maximum, so it can move neither bound — but it does spend that
   cycle as a clean natural observation. Worth saying out loud in the runbook so
   a future session does not skip the republish to protect the sampler; the
   trade is real but one-sided.

**Cross-check performed:** the 31 rows were enumerated from the CA
(`certutil -view -restrict "Disposition=21,RevokedEffectiveWhen>=…"`) and
account exactly — 29 + 1 previous-session Superseded, plus 1 Unspecified from
this session. `370 + 31 = 401`. Nothing in this run is unexplained.
