# AGENTS.md

Conventions and quick reference for agents (and humans) working on acme-adcs-ra.

## What this is

An **ACME Registration Authority** for ADCS: speaks ACME (RFC 8555) on the front,
holds **no signing key**, forwards CSRs to the existing ADCS issuing CA over the
Web Enrollment (`/certsrv/`) surface as a passwordless **gMSA**. It exists so
Certify the Web can renew ADFS/Exchange-class certs off the existing chain with
no new intermediate. See `README.md` for the charter.

## Orient

1. **Read `docs/architecture.md`** — the design spine: the RA model, the ACME
   surfaces, the enrollment leg, the transport modes, the security model.
2. **Read `docs/certsrv-setup.md`** — how to configure the ADCS Web Enrollment
   surface in Mode A and Mode C. The lab spike validates this.
3. The first plan is `plans/001-spike-and-mvp.md`.

## Hard rules (issuance infra — these REPLACE the read-only family rules)

- **No signing key. Ever.** This is an RA. It must never hold a CA/private signing
  key or sign a certificate itself. If a change moves toward that, stop. An
  architecture test asserts no signing primitive is invoked in the issuance path.
- **In the issuance path — treat every issue-capable code path as
  security-critical.** This is not read-only software; there is no "it's just
  analysis" safety margin.
- **Passwordless to ADCS.** Authenticate as a **gMSA** via Negotiate/SSPI
  (`pyspnego`, SPNEGO + RFC 5929 channel binding so EPA=Require is supported;
  ambient process identity via in-tree `negotiate_auth.NegotiateAuth`). **No
  stored ADCS passwords.** EAB keys and any secrets are never committed.
- **Deterministic issuance policy.** Which template, which SANs are permitted, who
  may request — explicit policy code. **No LLM in the issuance decision path.**
- **Least privilege.** One **server-authentication-only** template; subject/SAN
  from the CSR; the gMSA holds minimal Enroll rights. This bounds a compromise to
  TLS-service spoofing, short of client-auth/PKINIT domain-takeover.
- **Gate the ACME front.** EAB (External Account Binding) pinned to the
  authorized client(s) + network allowlist.
- **Audit every issuance.** RA store + emit (SIEM). No silent issuance.
- **No work-domain identifiers in committed files.** Real CA names, hostnames,
  template names, EAB keys, and configs live in gitignored local config /
  `samples/` — placeholders (`CA01`, `WORK-DOMAIN.local`) in committed docs.

## Stack / build

FastAPI + SQLite + `cryptography`. The Windows SSPI enrollment dependency is
platform-gated (`sys_platform == 'win32'`) so CI on Linux is unaffected; the
enrollment leg is exercised via the lab/Windows host.

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Transport modes

- **Mode A** — Web Enrollment (`/certsrv/`) installed on the CA itself. Simplest;
  no Kerberos delegation needed (enrollment is local to the CA). Matches the
  production CA's existing posture.
- **Mode C** — a separate Web-Enrollment or CES host fronting the CA. Keeps the CA
  role-pure, but the enrollment host enrolls *on behalf of* the requester, which
  requires **Kerberos constrained delegation** to the CA. See `docs/certsrv-setup.md`.

## Boundary

[cert-watch](../cert-watch/) = cert lifecycle; [adcs-lens](../adcs-lens/) = CA
posture; this = automated issuance off the CA. The RA's gMSA/template is itself an
ESC surface adcs-lens would flag — scope it tightly.

## Status

**2026-09-21: two security findings fixed and live-validated; a third
retracted.** WI-025 — a non-ASCII `Authorization` header raised `TypeError`
out of `hmac.compare_digest` and 500'd **every** admin endpoint for an
unauthenticated peer, the same bug class `_dummy_hmac` was fixed for on the EAB
path and never swept here. WI-026 — `$Serial` reached `certutil` unvalidated,
and `certutil -revoke` takes a *comma-separated list*, so the RA's JSON could
have steered a CA-officer call; unreachable today, fixed because of the
boundary it crosses, not a live exploit. Validated on the lab estate: 33/33
raw-socket credential checks, 2736 real serial spellings accepted with zero
false refusals under Windows PowerShell 5.1, 12/12 injection shapes refused,
and `certutil` provably never reached on a bad serial.

**WI-027 was retracted — it was my own harness.** An apparent one-packet
unauthenticated DoS was a probe running the server with an unread
`subprocess.PIPE`; tracebacks filled the buffer and the server blocked writing
to stderr. Two things survive it. **Starlette re-raises past
`@app.exception_handler(Exception)`** ("We always continue to raise the
exception" — its own source), so such a handler contains nothing; and the unit
test that certified it used `TestClient(raise_server_exceptions=False)`, which
swallows exactly the re-raise in question — a test that could not fail. Use
`raise_server_exceptions=True` when the question is whether something escapes.
Full write-up in `docs/security-review-2026-09-21.md`.

**Regista work-item writes are working again** — the block recorded below on
2026-09-20 has lifted. New items go to the store, not `UNFILED-WORK-ITEMS.md`.

**2026-09-05 (later): WI-052 settled by measurement, and the watermark proven
live.** The sampler's 399 samples over one complete publication cycle put the
maximum served age at 603654s against a 649200s window, so a binding,
non-false-refusing ceiling exists and the default is now **626400** (was
604800). Both numbers this project previously published were outside the band.
The monotonic watermark was proven against two genuine CRLs with a negative
control. Full lab re-proof of the candidate: **72/74**, both failures explained
and left visible (`CRL3` asserts the superseded rule; `Ld1` is the documented
transport-failure residue). See the 2026-09-05 entry in
`docs/pre-pilot-checklist.md`. **New: UNFILED item 25** — a quarantined
certificate has no stored chain, so it can never be CRL-confirmed and its
revocation never drains.

**2026-09-05 maintenance candidate:** issued-certificate validation was
extracted from `finalize.py` without changing its logic or call order; the CRL
sampler test now uses an explicit clock. Current operator guidance distinguishes
tagged v1.12.0 from the unreleased watermark, and documents the pruning startup
refusal. Local Python and Linux Pester suites pass. **Full lab reproof remains
owed on the final candidate.** See
[`docs/reproof-handoff-2026-09-05.md`](docs/reproof-handoff-2026-09-05.md) for
validation evidence and the operator handoff. The entries below are historical.

**2026-08-27: WI-052 is closed by replacing the control, not by finding the
number.** For the lab CA, the CRL age ceiling was introduced as an independent
replay bound, but its safe floor is disputed because the published window and
the age the CDP actually serves are different quantities. The replay control is now
a **monotonic CRL watermark** (`ACME_RA_REVOCATION_CONFIRM_CRL_REQUIRE_MONOTONIC`,
default true): the newest CRL acted on per issuing CA is recorded, and one that
goes backwards is denied `crl-evidence-regressed`. It needs no calibration, since
RFC 5280 already requires the CRL Number to increase. The ceiling is demoted to a
liveness alarm on the CA's publication pipeline. **Live proof landed 2026-09-05**
— see the entry above; the ceiling is no longer only an alarm, it is a measured
binding bound.

**The reason WI-052 survived so long is the more useful finding.** Its
calibration data existed — `crl_this_update` on every confirmation — and the lab
teardown restored the store that held it at the end of every session. 722 audit
rows spanning two months, not one carrying `crl_this_update`. The item was not
un-measured; under that procedure it was **un-measurable**, and no number of
further validation rounds would have changed it. Generalise it: *any*
longitudinal property is invisible to a lab process that restores to a pre-run
fingerprint. `restore.ps1` now preserves the post-run store first (and throws
before destroying anything if it cannot), and `scripts/sample_crl_age.py` samples
the CDP from outside the restore scope entirely — running against the lab CA
every 30 minutes since 2026-08-27T19:13Z.

The first thing the sampler found was that the merged floor derivation uses the
published *window* where it needs the *served age* — different quantities on any
CA with publication overlap (UNFILED item 24). **2026-09-05: the sampler settled
it**, and item 24 was right: max served age 603654s against a 649200s window, so
the band is `(605454, 649200)` and the default is now **626400**. Every committed
surface that asserted ≥ 649800 has been corrected. The standing rule stands and
earned its keep — **do not re-derive that number on paper; read the sampler.**
The watermark remains independent of the answer. The
`restore.ps1` preserve block is likewise committed now, as the identifier-free
reference implementation in `docs/live-reproof-runbook.md` §E, so a clean
checkout re-applies it by paste instead of re-deriving from policy prose.

**2026-08-25 whole-repository scan: three medium findings, fixed and LIVE
VALIDATED on tip `5580519`.** (1) `Store.record_issuance` was unguarded — the
first durable record of something ADCS had already done, so a full or
read-only store rolled back the transaction and left a live certificate with
no row, no audit event and no revocation-queue entry. Both neighbouring paths
already had orphan handlers and neither would have helped: both fall back
through `_audit` to the same database. `_emergency_issuance_orphan` now
compensates without touching the store (critical log + direct SIEM hook), and
issuance halts one-way until restart — but not for a merely busy store, which
would trade a rare orphan for a routine outage. (2)
`finalize-enrollment-admission-denied` and (3) the two revocation-confirm
routes were replayable into unbounded durable audit writes; all now coalesce,
with `reason_code` keeping attacker-chosen values out of the key.

**A fourth came from measuring rather than reading.** One `GROUP BY
event_type` against the deployed store before deploy: 567 of 722 audit rows
(78.5%) were this RA's own scheduled maintenance reporting it had nothing to
do, against 11 `certificate-issued` rows. Idle sweeps now write nothing; a
sweep that destroyed state still does. Proven live: 60 idle maintenance calls
wrote **zero** rows, 15 distinct unknown-serial probes wrote **one**.

Live results on `5580519`: §A 14/14, §A1 13/13, CRL+§G 9/10 (CRL3 = WI-052),
§K 12/12, orphans 6/6 ×2, §R+Rverify ×3, least privilege, authority split, CRL
evidence. Suite 953 + 1 skip; Pester 467; 22 new tests, 12 mutations.
**Teardown found two harness defects:** the clean-CA check restricted on the
template's display name, which never matches (the column holds the OID), so it
returned zero and read as clean — 18 certificates were actually still Issued,
15 of them residue from earlier "verified" teardowns; and the teardown order
put revocation before reverting the officer grant, which locks out
administrators too. Both fixed in the runbook. Not run: phase L. Open at park:
the deployed dotenv is still the prior session's 13-kid throwaway env.

**2026-08-24 daybreak review: four findings, fixed at `ade72a8`, then LIVE
VALIDATED the same day on the branch — the validation found and fixed two
defects in the fixes themselves (final tip `b8d3343`).** (1) The F11
root-self substitution check judged the DESIGNED gMSA Modify on the state
root by the executable-owners list — first install refused (`INSTALLER_EXIT=1`)
and every upgrade of an existing deployment would brick; fixed with
`-AllowedRootWriterSids` (state root passes its design writers, runtime root
none, ancestors never) and live-re-proven. (2) The untrusted-tree override
propagated registrar→task action→sync but not into the `Revoke-Cert.ps1`
child, so an allowed tree could list pending revocations and never revoke
one; fixed and live-re-proven by draining a genuinely stuck orphan. (3) The
CA host's `C:\` carries an applicable `Authenticated Users:(M)` ACE — no
tree on that host passes the gate; officer scripts there need
`-AllowUntrustedScriptPath` (correct refusal, loud override, operator item).
Generic-bit branches of the new predicate live-proven 10/10 then pinned;
Pester 457→467, all new tests mutation-checked; third-lineage adversarial
review rated F10/F12/F13 SOUND. Full canonical app re-proof on `b8d3343`:
§A 14/14, §A1 13/13, CRL+§G 9/10 (CRL3 = WI-052), §K 12/12, orphans 6/6×2,
§R+Rverify ×4 with R2b, least privilege, authority split, CRL evidence.
Teardown verified both hosts. Phase L not run (no enrollment-leg change
here; owed on a v1.11.x tag per the standing lab-network item). See
`docs/security-review-2026-08-24-daybreak-standard.md` (live addendum) and
the validation log.


**v1.11.0 re-proven live on the released tip `0a47955` (2026-08-24).** Full
re-proof on the exact shipped artifact: §A 14/14, §A1 13/13, CRL/§G 9/10 (the
one FAIL is CRL3, the designed WI-052 calibration check), §K 12/12, both
transport-orphan branches 6/6 each, §R+Rverify through three revocation
cycles, least-privilege, authority split, and the CRL-evidence cycle. **The
v1.11.0 delta itself is live-proven by a new R2b check on every cycle: empty
RFC 8555 §7.6 body + `X-Acme-Ra-Out-Of-Band-Revocation` header, with the
harness finally speaking the standard `certificate` dialect.** Phase L: §L
9/9 and Ld5, but **Lqueue/Ldrain NOT PROVEN on this tip** — three attempts
were defeated, in order, by warm keep-alives surviving the route blackhole, a
TIME_WAIT-counting saturation check, and finally a **flapping lab network
fabric** (the same probe hung 5 s at 13:23 and connected in 22 ms at 13:38
with identical routes; enrollments really completed through a
verified-blackholed state — real CA issuance, gMSA requester, CA IIS log
evidence). Not a product regression: the diff to `f6badc9` (where
Lqueue/Ldrain passed 22/22 the same morning) touches only
`routes/revocation.py`. Owed: lease-pass on a v1.11.x tag once the lab
network stabilizes (the harness now blackholes every resolved address, counts
live socket states only, and recycles the pool after route-on — runbook §12).
Teardown verified: 141+1 serials revoked (0 failed, template fully drained),
CA pristine (224/4/absent), store fingerprint identical, pool Started. Note:
the deployed dotenv is the prior session's throwaway phase-L env (13 kids),
restored as-found — see the checklist log. Local gates before deploy: 928
pytest + 1 skip, 424 Pester + 4 platform skips, ruff, mypy; CI 8/8 on the
exact commit.

**Daybreak standard pass (review of `7325cdb`, 2026-08-17) found four medium
issues, no high or critical. One fixed, three triaged and consciously left.**
Fixed: syslog transport failures were counted as successful off-box audit
delivery, and the `audit_offbox_required` startup probe passed with the
collector dead — a stock `SysLogHandler` swallows send errors, and both the
counters and the probe inferred success from `Logger.info()` returning.
Confirmed by execution (five sends to a killed collector recorded five
deliveries and zero failures); rated **high** rather than the reported medium,
because it is the same defect class as wave-3 F2 which was fixed for HEC only,
and the shipped `web.config` selects TCP syslog. Fixed with
`_RaisingSysLogHandler` (re-raises, drops the dead stream so the next event
reconnects, re-applies the send timeout across a reconnect). Eight tests, each
mutation-checked — the first version of the timeout test was vacuous and only
earned its place after a rewrite. Not fixed, with reasons: unlimited `keyChange`
rotations is a second vector on open WI-014; the commented-out IIS `ipSecurity`
allowlist is the posture adopted in the 2026-08-11 review (second reviewer to
re-report it — record the decision in `SECURITY.md`); the unauthenticated
privileged script tree is valid and converges with WI-015/WI-053. Coverage was
partial (37 of 167 files) and the reviewer's own follow-ups are
*live-windows-validation* and *remaining-file-review*. See
`docs/security-review-2026-08-17-daybreak-standard.md`. Local gates: 840 pytest
+ 1 skipped, ruff, mypy. **Not a live Windows proof.**

**Audit retention landed 2026-08-17 (WI-014 part three).** Deletion is now
possible, and most of the code exists to make it hard to do by accident.
`certificates.not_before`/`not_after` are recorded at issuance (and backfilled),
so the retention floor is `longest observed certificate validity + a fixed 14-day
grace` — configure `audit_retention_days` below it and **startup is refused**,
because retaining for less than a certificate's own lifetime means a certificate
can be valid and servable with no record of how it was issued. Derived from
observed issuance, not the template, since ADCS can issue shorter than asked.
The sweep additionally requires `audit_prune_enabled`, `audit_offbox_required`
and a delivery probe that succeeds **at sweep time**; miss any gate and it
reports and deletes nothing. The current server also refuses
`audit_prune_enabled=true` at startup because the SIEM path has no per-row
delivery acknowledgement. **Local-only deployments never prune** — with no
off-box copy the local table is the only evidence there is — and instead get
footprint reporting plus JSONL rotation. Their stated cost is availability: the
`certificate-issued` audit row commits in the same transaction as the
certificate, so a full disk stops issuance rather than issuing unaudited. The
`"DELETE FROM audit_log" not in source` tripwire was **narrowed, not removed**;
it now pins deletion to one statement in one policy-free primitive callable only
from `audit_retention`. Local gates: 869 pytest + 1 skipped, ruff, mypy.
**Not a live Windows proof.**

> **The binding constraint is lab time, not review.** Rverify, the sync/queue
> drain and the officer class D1–D7 have never been executed on this branch, and
> `01417b5` (a 5.1 installer fix) postdates the last live proof. Round 7 blamed
> a CA DCOM fault; that was **retracted 2026-08-17** — it was the SSH logon
> session holding no Kerberos TGT (runbook §1), so nothing is blocked. Work-item
> writes are also down estate-wide; see `docs/UNFILED-WORK-ITEMS.md`.

**Daybreak round 6 (review of `d1d7c17`) found seven more issues: 4 high,
3 medium; all are remediated in source, and the full native Windows re-proof
has now been EXECUTED on the final tip `8964eba` (2026-08-16, lab RA host,
PowerShell 5.1) — it found and fixed one more defect live: the post-build
re-assert ran `icacls /reset` on the protected state root, re-inheriting
ProgramData's Users-create rights for the interval before `/inheritance:r`
(a looping standard user planted 3 entries through it; caught fail-closed by
the proof, then 0-for-43,920 after the fix). Roots are never `/reset`
mid-install now (`Reset-TreeChildrenToInherited` + `-SkipReset`).** The six
installer findings were treated as one trust-boundary redesign: fresh roots
are created with their final protected DACL in `CreateDirectoryW` (no
retained-handle window), executable provenance uses an authorized-writer SID
allowlist, ambiguous Win32 paths are refused, PATH-selected prerequisite
execution is gone, repository inputs are proven then built from protected
staging, and MSI verification/execution occurs only on a protected staged
copy. The application finding is an atomic lifetime per-EAB account quota
(default one), live-proven at its default (denial, coalescing 46→2 rows,
no slot recycling on deactivation). Full app re-proof (A/A1/CRL/G/Q/R/
least-privilege/authority/CRL-evidence) green on the same tip; teardown
returned both hosts to their pre-run fingerprints. One native case still
owed: live MSI-source replacement (Pester- and order-proven; the lab host's
installed handler short-circuits the path). See
`docs/security-review-2026-08-16-daybreak-round6.md` (incl. Finding 8) and
the validation log in `docs/pre-pilot-checklist.md`. Local gates: 807
pytest + 1 skipped, 268 Pester + 1 skipped, ruff, mypy.

**Status update (2026-08-15, post-validation):** Daybreak's review of `f495092`
(the E2E-proven tip) found the installer's ACL claim was bypassable —
`/inheritance:r` removes only *inherited* ACEs, so an attacker's explicit ACEs
and ownership survived the "claim" — plus registration tokens on the command
line and two commit-before-audit orderings. All four are fixed on
`security-review-2026-08-15-daybreak` (takeown+/reset+read-back-proof for the
tree; switch-only `-AdminToken`/`-ConfirmToken`; account/keyChange audit
atomicity, fault-injection proven); WI-014 stays deferred. See
`docs/security-review-2026-08-15-daybreak.md`. **Daybreak's rescan of that fix
found two more (both fixed, same branch):** the ACL lockdown bounded *writes*
but not *bytes* — a planted `python\python.exe` was still preferred and
executed, and a planted venv `.pth` survived `python -m venv` (now: the shared
interpreter runs only on strict whole-tree manifest verification against a
gMSA-unwritable manifest, and the venv is deleted and rebuilt every run); and
child junctions redirected the recursive `takeown`/`icacls /t` outside the
tree (now: a never-following reparse-point walk refuses any link, `/L` on
every icacls traversal; takeown's remaining TOCTOU window is detected
post-hoc, not prevented — documented). See
`docs/security-review-2026-08-15-daybreak-rescan.md`.

**Daybreak's THIRD pass (of `63529a6`) found four more; all four are fixed on
the same branch** — see `docs/security-review-2026-08-15-daybreak-rescan-2.md`.
Briefly: the manifest could not authenticate anything on a first install
because a local user pre-creates both it and the interpreter it vouches for
(now: the manifest's own digest is anchored in `HKLM\SOFTWARE\acme-adcs-ra`,
and an unanchored runtime tree is deleted, never executed); `takeown` has no
`/L`, so a raced junction still redirected elevated recursive ownership out of
tree (now: `takeown` is gone entirely, ownership is claimed with
`icacls /setowner … /L`, and `/c` is gone from every call so a partial run
aborts); the app pool was stopped ~220 lines *after* the claim, so retained
gMSA write handles outlived the ACL reset (now: stopped and proven dead via
`appcmd list wp` before anything is claimed, hashed or run) and only the root's
owner was verified (now: every descendant's). And **WI-014 is fixed rather than
deferred a fourth time** — not with a pruner, which the earlier deferrals were
right to refuse, but by folding repeated pre-auth denials into the row already
on disk, so growth tracks time instead of request rate and nothing is deleted.

**Then the adoption model itself was retired** — see
`docs/design-code-state-split.md`. Five of the eight installer findings across
those four rounds were defects in the previous round's fix, and every mechanism
involved existed to make it safe to *adopt* a directory a local user might have
created first. So: executable content moved to `%ProgramFiles%\acme-adcs-ra`
(new `-RuntimeDir`; `%ProgramData%` grants Users create-folder rights with
CREATOR OWNER inheritance, `%ProgramFiles%` does not), state stayed in
`%ProgramData%` with the gMSA on modify and **read+execute only** on code, and
a pre-existing root is now proven ours or refused with an actionable message.
That also closed an unreported path: `acme-ra.env` is preserved no-clobber, so
a planted dotenv in a pre-created state dir used to be preserved and ACL'd —
and it carries the EAB allowlist and SAN scopes. Deleted with the model: the
tree manifest, the HKLM anchor, `Test-DestinationInterpreterTrusted`, the whole
reuse branch. `docs/operator-requirements.md` is the operator contract.

**BREAKING for deployments: an old single-directory install is refused.**
Migration is manual and deliberate — `docs/operator-requirements.md` §4.

**The installer rework is now EXECUTED and lab-validated (2026-08-15, on
`54b90db`)** — every item the design doc's "still unproven" list demanded:
clean install, reinstall over it, refusal runs (the real old-layout tree AND
a genuine non-admin pre-plant), a rollback run, the §4 migration end to end,
and the load-bearing **gMSA `RX` launch** (HttpPlatformHandler starts the
ProgramFiles venv as the gMSA; `/directory` 200). The run found **two escaped
PowerShell defects, both fixed on the branch and re-proven live**: the ACL
proof could not read `icacls /save` output (UTF-16LE without BOM vs
`Get-Content`'s ANSI decode on 5.1 — and pwsh *sniffs* BOM-less UTF-16, which
is why local Pester never saw it), and a failed build left `acme-ra.env`
inheriting gMSA Modify — the claim's `/reset` strips the dotenv's protected
DACL and the re-protect was 150 lines downstream of the abort point — bricking
the next install's pre-flight. Both fixes carry byte-realistic / source-order
regression tests. Also closed: the `*S-1-5-32-544` star form **works** for
`icacls /setowner`. Still not proven: the no-rollback proof-failure path and
a bare-`-ConfigureIIS` first install. Refusal runs leave the app pool stopped
(fail-closed) — restart by hand. The lab RA host now runs the two-tree layout
(old tree preserved as the migration rollback artifact); see the validation
log in `docs/pre-pilot-checklist.md` and the gitignored
`samples/lab-run-2026-08-15-installer-validation.md`.

**Daybreak's FIFTH pass (of `f0597a5`) found five more (1 high, 4 medium);
all five are fixed, the final tip is `88e9c07`, live-proven where
deterministically possible** — the high was a *file*-plant race into a
freshly created root (the round-4 collision fix closed the directory race,
but between `New-Item` and the claim's protect step the fresh root still
inherited Users-create rights, and a planted dotenv rode the whole claim —
`Lock-FreshRoot` now protects at creation, proves the directory empty, and
never runs `/reset` on the fresh path); lexical path comparison missed
dot-segment/8.3/junction aliases (canonicalisation + kernel final-path
resolution, all three refused live); PATH-resolved interpreters executed
elevated unproven (ancestor-chain provenance gate — a fake PATH-first
python is rejected and never executed, live-proven with a marker file);
SitePath/web.config were adopted unverified (site-tree provenance +
throwing launch-config validation, both halves refused live); and
replayable authenticated requests grew the audit stores unbounded
(coalescing extended to the replayable denial classes + an
already-valid-challenge short-circuit; the deployed build held **zero**
durable rows against a 40-request live denial storm). The live run found
**two more calibration defects in the new chain rule itself** — the raw
generic-bit constants (0x80000000 is GenericRead, not GenericAll) and
SID-vs-name in the owner check — plus InheritOnly handling, each
live-fixed and pinned by a Pester case. The lab host runs `88e9c07`,
`/directory` 200, store unchanged.

**Daybreak's FOURTH pass (of `27127af`) found four more; all four are fixed
on `102a1f4` and live-proven where deterministically possible** — a TOCTOU on
first-install state-root creation (`New-Item -Force` adopted a raced
pre-creation and the whole proof chain then normalised and *preserved* the
planted dotenv — now created without `-Force`, provenance re-verified on
collision); a clean legacy single-tree layout passing the generic
trustee/owner/DACL provenance while the preserved web.config kept launching
the old gMSA-writable venv (now: `venv`/`python`/`scripts` at the state root
are a pre-icacls refusal, proven against the real `.preSplit` tree; and a
post-install loud warning when web.config's `processPath` points inside the
state tree); a CWD-executable hijack on the bare `py`/`python` probes through
`cmd /c` (now: `NoDefaultCurrentDirectoryInExePath` + absolute-path
resolution); and overlapping `-RuntimeDir`/`-InstallDir` silently collapsing
the RX/Modify boundary — both grant sets have the same proof *shape*, so
nested roots stayed green (now: refused before any host mutation). The
collision branch of the TOCTOU fix is the one thing not live-proven (it is
reachable only by a genuinely won race). The lab host now runs `102a1f4`'s
runtime, `/directory` 200, store unchanged.

**Released: v1.11.0 (2026-08-24).** 1.11.0 fixes two revocation defects found by
pointing a real ACME client at the RA: `revokeCert` read `cert` where RFC 8555
§7.6 says `certificate` (so no conformant client could revoke at all), and the
JSON success body made a real client report succeeded revocations as failed.
The response is now an empty body plus an `X-Acme-Ra-Out-Of-Band-Revocation`
header — **breaking** for anything that read the body. Neither bug was
catchable in-repo: the harness and the test client both spoke the same
non-standard dialect as the server.

**v1.10.0 (2026-08-24).** There is **no 1.9.0 or 1.9.1 release**: the
1.9 line was written up and `pyproject.toml` declared `1.9.1`, but no tag was
ever cut — 1.9.0 shipped only as `rc1`/`rc2` (the re-proof that gates a tag
found a red lint gate on the rc2 tip and a `Set-OfficerRights.ps1` defect on the
first-provisioning path), and the 2026-08-15 → 2026-08-23 review series kept
finding work. The tagged history goes v1.8.0 → v1.10.0; the minor bump is
earned by a breaking change to `Sync-Revocations.ps1` (`-AdminToken` and
`-ConfirmToken` became switches, so token values can no longer reach argv). The
2026-08-14 scan of rc1 found seventeen further findings, two blocking: ACME
**reason 8 (removeFromCRL) was accepted and reached `certutil`**, so a revokeCert
carrying it recorded a successful revocation while asking the CA to *un-revoke*
(Plan 004 recorded the CA-side effect: "off the CRL and valid"); and
post-issuance **transport** failures orphaned live certificates on a path the
2026-08-13 quarantine work did not reach. All seventeen are fixed — see
`docs/security-review-2026-08-14.md`, including the one place the stricter
default was deliberately not taken and why.

v1.9 closes
ten findings from an external static scan of v1.8.0 (separated
revocation-confirm authority with optional CRL proof, certificate quarantine,
atomic issuance+audit, read-path nonce rejection, credential floors, bounded
HEC queue, off-box audit gate on the constructed emitter, JWS type guards, RA
URL validation in the revocation scripts, OfficerRights activation proof).
**The live re-proof of those fixes then found two defects Linux CI structurally
cannot see** — Windows PowerShell 5.1 language semantics that `pwsh` 7 differs
on, one inside the review's own fix. Read `docs/security-review-2026-08-13.md`
§ Proof status before touching the PowerShell.

v1.8 (2026-08-11) bound URL validation to `base_url` and added account
eviction. v1.7 (2026-08-08) closed
nine findings from the 2026-08-07 security review (CA-capable CSR/cert
rejection, CN→SAN binding, certsrv key binding, rate-limit TOCTOU fix, JWS
streaming cap, algorithm exactness, EAB URL binding, HEC HTTPS enforcement,
cryptography ≥50.0.0) — live re-proven against ADCS. v1.5–v1.6 added
automated CA-side revocation (template-scoped officer restriction; two-identity
default + opt-in single-identity `-LocalMode`) + self-enforced serverAuth EKU
(Plans 004–006); the **v1.6 hardening sweep** (Plan 007) closed Finding E-1,
added a Pester suite + deterministic CI (`uv sync --locked`), proved the
two-identity compromise-independence property live, and added the live-re-proof
runbook. The repo is public and CI-gated (incl. a monthly rot-canary). Re-entry
rules:

- **Any change to the issuance leg earns a live lab re-proof** (the standing
  project rule — see the validation log in `docs/pre-pilot-checklist.md` and the
  procedure in `docs/live-reproof-runbook.md`). Latest: WI-028 (v1.5, 2026-07-23)
  + WI-035/036 (v1.6, 2026-07-23/24) + 2026-08-07 security-hardening (2026-08-08)
  + 2026-08-11 security review (26/26, incl. the new §A.1 front-control checks)
  + **2026-08-13 review (on `26eae31`; found two PowerShell defects)**
  + **2026-08-14 review (on `bef2022`; found one blocking PowerShell defect and
  a red lint gate on the rc2 tip)**. The rule is *on the exact commit being
  shipped* — a re-proof on an earlier commit does not transfer.
- **Run the whole re-proof, not the delta, and start it from a known config.**
  The 2026-08-14 pass is automated end to end (methodology in the gitignored
  `samples/lab-validation-runbook.md`). One toggle left set by an earlier step
  silently changed what three later steps proved, so the driver now asserts the
  default configuration before it measures anything.
- **A green cross-platform Pester run is not evidence about the CA host.** The
  two defects the 2026-08-13 re-proof found were Windows PowerShell 5.1 *language*
  semantics — a single-element array has no `.Count` under 5.1 but yields `1`
  under `pwsh` 7; `$PSNativeCommandUseErrorActionPreference` defaults differ —
  not Windows-only APIs, which is the gap everyone anticipates. Linux Pester was
  green while the shipped script was broken on the CA.
- **Two review lessons worth carrying forward.** (1) Every finding in the
  2026-08-11 review was in an *inherited framework default* — FastAPI's docs
  endpoints, Starlette's `request.url`, uvicorn's proxy-header trust, the
  `jsonl` sink path — never in hand-written security logic. Audit the defaults
  you did not choose. (2) The 480-test suite would not have caught any of them,
  and the missing order endpoint survived three "proven end-to-end" milestones
  because every proof used a hand-rolled client sharing the server's
  assumptions. **Mutation-verify new security tests** (three of the review's own
  tests initially passed against both vulnerable and fixed code), and prefer a
  client nobody here wrote for the next interop proof.
- **Remaining before pilot (not code debt):** the operator-owned §B–E items. The
  two-identity round-trip (WI-036) is now **fully proven live** (2026-07-24) — a
  separate revoker gMSA revoked at the CA and confirmed back, enrollment gMSA held
  no officer rights. (RCA of the earlier block, an out-of-project homelab AD issue
  — NOT clocks: new gMSAs need explicit AES etypes, else RC4 is added and blocked.)
  WI numbering: WI-011..015 exist only in plan documents, not the store — file new
  items with an explicit identifier ≥ WI-040.
- A production pilot is gated on the operator-owned sections (§B–E) of
  `docs/pre-pilot-checklist.md`; those are per-deployment, not code debt.
- If the scheduled CI run has gone red, fix CI first — it is
  dependency/runner rot (pip-audit especially), not a code regression.

**Plans 001–006 complete; at the production-pilot bar (v1.5 on `main`).**
WI-001–WI-010 (ACME server, EAB/policy, enrollment, SIEM audit, out-of-band
revocation) and WI-011–WI-014 (operator-enablement artifacts) shipped for 1.0;
Plans 004–006 (WI-021–WI-034) add the automated CA-side revocation loop, EKU
self-enforcement, and the single-identity option for v1.5.
**WI-015** (live lab re-proof against the exact piloted commit) **PASSED**
2026-07-13 on the lab host against `7d5c5b9` — all 12 cases (issue, policy
denial, revocation, reason-7 rejection, chain off the existing CA). **Plan 003**
(WI-016–WI-020) is complete: in-app per-account order rate limiting, RA-vs-CA
revocation reconciliation (read-only), EAB scope audit view, `keyChange`
(RFC 8555 §7.3.5), and locale-robust `certfnsh.asp` parsing. See `docs/operations.md`.
Post-review security fixes: M-1 (reason 7 rejected), M-2 (CAS-guarded
pending→ready), M-3 (CAS-guarded cert revocation, now with a deterministic
`won_cas` signal), and MED-1 (post-issuance SAN verification — the issued
cert's SANs are checked against the order, not just the CSR).

Auth is SPNEGO + channel binding
(`negotiate_auth.NegotiateAuth` over `pyspnego`) against `/certsrv/` **EPA=Require**.
**CA-side revocation is out-of-band (WI-010)**: ADCS Web Enrollment exposes no
revocation endpoint, so `revokeCert` records the revocation in the RA store
only (cert → revoked, GET → 410) with an honest audit
(`revocation_scope=ra-store-only`, `ca_crl_updated=false`). The operator closes
the loop by running `scripts/Revoke-Cert.ps1` (a CA officer, not the gMSA),
which runs `certutil -revoke` and republishes the CRL. The enrollment gMSA
gains no CA-officer rights (threat-model §E).

**Previously on `main`: the 2026-08-11 security review** (13 findings; see
`docs/security-review-2026-08-11.md`). The load-bearing two: the JWS **and** EAB
URL bindings were derived from `str(request.url)` — i.e. the client's `Host`
header — so they only proved a client was self-consistent and an EAB minted for
another deployment verified here (which meant the 2026-08-07 EAB-replay fix was
never actually closed); and `account.status` was never read while the EAB kid was
re-checked only at finalize, so pulling a kid stopped issuance but left the
account able to **revoke its own live certificates**. Both are fixed and
live-proven (26/26 checks, 2026-08-11). Also: nonce token bucket, `/docs`
disabled, off-box audit gate, the previously-404 order/account resource
endpoints, and the PKCS#7 chain now bound to the leaf.
**Consequence for operators: `ACME_RA_BASE_URL` is now security configuration** —
wrong value ⇒ everything fail-closes.
