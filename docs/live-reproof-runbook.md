# Live re-proof runbook (WI-038)

**Why this exists.** Cloud CI **cannot reach an ADCS CA**, so a green CI run does
**not** confirm that the enrollment and revocation legs still work — those depend
on a real CA, a domain-joined RA host, and a passwordless gMSA. This runbook is
the repeatable procedure for proving the ADCS integration end-to-end, plus the
cadence at which it must be run so "proven" does not decay silently.

> **Green CI ≠ ADCS-verified.** CI (lint + type + Python unit + Pester
> pure-logic + identifier-gate + pip-audit) proves the code and the operator
> scripts' *logic*. It does not prove issuance or CA-side revocation. Only this
> live re-proof does.

## Cadence (when to run it)

Run the full live re-proof:

1. **At every release** (before tagging), on the exact commit being shipped.
2. **Before any production pilot.**
3. **On a fixed interval while deployed** (recommended: quarterly) — a rot check
   against ADCS/OS/template drift the monthly Python rot-canary can't see.
4. **After any change to the issuance leg** (the standing project rule).

Record each run in the validation log in
[`pre-pilot-checklist.md`](pre-pilot-checklist.md).

## Prerequisites

- The deployed build on the RA host is the commit under test (`pip install
  --force-reinstall` the wheel into the app-pool venv; **deploy the entire
  `scripts/` directory including `scripts/lib/`** — the officer/registration
  scripts dot-source `scripts/lib/`).
- Access to the CA host (to provision/verify officer rights) and the RA host.
- A throwaway EAB credential + admin token in the RA dotenv (removed at teardown).

## Procedure

### A. Issuance + EKU (shared leg)

1. Start the RA app pool; confirm `GET /directory` → 200.
2. Use an independently maintained ACME client, such as the deployed Certify
   the Web installation, to drive a full ACME round-trip
   (new-account EAB → order → challenge → finalize →
   cert). Confirm: serverAuth-only EKU (WI-026 passes on a real cert),
   `clientAuth` absent, chain off the existing CA (no new intermediate), SAN from
   the CSR, requester = the enrollment gMSA in the CA DB.
   **Also confirm the chain check did not false-reject** (2026-08-11): the RA now
   requires a certificate in `certnew.p7b` to both match the leaf's issuer *and*
   verify its signature. A successful issuance is the proof — a validator that is
   subtly wrong breaks *every* issuance, and no unit test can show that because
   only the real CA produces the real chain.
3. Provoke a policy denial (out-of-scope SAN) → rejected at finalize.
4. Confirm reason-7 revocation is rejected (`badRevocationReason`).

### A.1 ACME front controls (added 2026-08-11)

These are cheap (no CA involvement) and belong in every run — they are the
controls a *deployment* mistake silently disables, which unit tests cannot see.

1. **URL binding pins to `base_url`, not the request.** With the site binding
   left catch-all (the installer default), send a `newAccount` whose JWS `url`
   and `Host:` header both name some other hostname → **rejected**, `url host
   mismatch … expected <base_url host>`. Then send a well-formed request whose
   *EAB only* names another deployment → **rejected**,
   `badExternalAccountBinding`. Then a `kid` naming another deployment →
   **rejected**, `not an account URL on this server`.
   *Why here:* a proxy or binding change can make `request.url` and `base_url`
   disagree; this is where that shows up.
2. **Account eviction — with the control first.** Rename the allowlisted kid in
   the dotenv, recycle the pool, then:
   - **control:** a *new* account under the renamed kid must **succeed** (201).
     Without this the next two steps pass trivially if the dotenv failed to
     parse. (PowerShell 5.1's `Set-Content -Encoding utf8` writes a BOM that
     breaks it — write UTF-8 without BOM via
     `[System.IO.File]::WriteAllText($p, $txt, (New-Object System.Text.UTF8Encoding($false)))`.)
   - the pre-existing account: `newOrder` → **401**, and `revokeCert` → **401**.
     The revoke case is the one that regressed silently before.
3. **Deactivation** (RFC 8555 §7.3.6): POST `{"status":"deactivated"}` to the
   account URL → 200; the next request from that account → **401**.
4. **Resource URLs resolve:** POST-as-GET the order `Location`, the account URL
   and the account's `orders` link → all 200. POST-as-GET another account's
   certificate → **401**.
5. **Nothing extra is published:** `/docs`, `/redoc`, `/openapi.json` → **404**.
6. **Nonce ceiling:** ~220 rapid `HEAD /acme/new-nonce` → a mix of 204 and
   **429** with `Retry-After`.

### A.2 Independent-client compatibility record

Repeat this on each candidate artifact as part of the full run. The in-repo
client is useful for controlled checks, but cannot establish compatibility
with an independent implementation.

1. Record the RA commit, client version, and ACME library version when exposed
   by the client. Use a fresh, scoped test account and record the effective
   configuration without credentials.
2. Complete issuance and a subsequent renewal/order through that client's
   normal workflow. Confirm it can poll the order and retrieve the certificate
   through authenticated POST-as-GET. Verify the resulting certificate and
   chain as in §A.
3. Request revocation through the same client. Record both the client's success
   result and the RA's empty HTTP 200 response. Separately verify CA-side
   revocation, queue confirmation, and CRL publication under §B or §C; the
   client's success is not evidence that publication has completed.
4. Preserve redacted client logs and the associated RA/CA evidence before
   teardown. Record any skipped client operation as unproven, with its reason.

### A.3 The phase-L blackhole, and proving the instrument first

The queue/drain phases need the CA's inbound TCP/443 blocked from the RA so
enrollments hang on connect. Two things about that mechanism are load-bearing
and have each silently voided a round:

1. **Scope the rule to every address the RA can source from, in both families.**
   A v4-only scope lets enrollments ride IPv6 straight through it.
2. **Quote the addresses when you build the PowerShell array literal, and check
   the exit code.** Unquoted, an IPv6 literal is not a valid PowerShell
   expression: the wrapper dies with `Missing expression after ','`, creates no
   rule, and — if the caller does not check the exit code — reports success. The
   harness driver did exactly this until 2026-09-05.

```bash
# The array elements MUST be quoted, and a failed block MUST be fatal.
printf '& C:\\Temp\\ca-inbound-block.ps1 -Mode %s -RaAddress @("%s","%s")\n' \
    "$mode" "$RA_V4" "$RA_V6" > "$D/blk.ps1"
scp -q "$D/blk.ps1" "$CA:C:/Temp/blk.ps1"
ssh "$CA" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Temp\blk.ps1' || {
    echo "BLOCK $mode FAILED on the CA - refusing to continue"; exit 1; }
```

**Then prove the drop from the RA before measuring anything.** `reachprobe.ps1`
must report `dropped` — not `refused`, which means something is answering with
RST and nothing will queue — for **every** address, and the driver must exit
rather than proceed on any other result. That gate is the only reason the
2026-09-05 run did not take a measurement on top of a blackhole that was never
installed.

The harness lives under gitignored `samples/`, so this section is the copy that
survives a fresh clone. Same convention as §E's preserve block: the prose is the
policy, the snippet is the code, and the two must not drift.

### B. Automated revocation — two-identity (recommended topology)

1. Provision a dedicated revoker gMSA on a utility host: grant it
   **Certificate Manager (`0x2`, not Manage-CA)** on the CA security descriptor,
   apply the template-scoped `OfficerRights` (`Set-OfficerRights.ps1`), add
   `Certificate Service DCOM Access`, and confirm it belongs to **no** broader
   certificate-manager group (union-semantics constraint).
2. Register `Sync-Revocations.ps1` as a scheduled task **under the revoker gMSA**
   (`Register-MaintenanceTasks.ps1 -RegisterRevocationSync`, no `-LocalMode`,
   `-RequesterName <DOMAIN>\<enrollment-gMSA>$`).
3. Revoke a test cert in the RA (`revokeCert`), run the task, and confirm the
   round-trip: CA DB disposition = Revoked, RA pending set drains to empty,
   `ca_crl_updated=true`.
4. **Compromise independence:** confirm the **enrollment gMSA holds no officer
   rights** (its SID absent from the CA security descriptor's manager ACEs;
   `GetMyRoles` shows Enroll only).

### C. Automated revocation — single-identity (opt-in variant)

Same as B, but the enrollment gMSA itself holds the template-scoped officer
rights and the task runs on the RA host with `-LocalMode`. Confirm the
least-privilege bound holds: with the default (no `-PublishCrl`), the officer
revokes and confirms but the inline CRL republish is **denied** (needs Manage-CA);
the revocation appears at the next scheduled CRL publication.

### D. Enrollment-side bound (E-1)

Confirm the enrollment gMSA can enroll **only** `ACME-ServerAuth`, not `Machine`:
inspect the gMSA's live token (no `Machine`-enroll principal, e.g. Domain
Computers) and confirm issuance still works. See
[`revocation-scope-validation.md`](revocation-scope-validation.md) Finding E-1.

### E. Teardown (return to pristine)

Remove the `OfficerRights` value and restore the CA security descriptor to its
original bytes (back them up first); delete any test revoker gMSA + its CA grant;
unregister the scheduled tasks; restore the RA store DB + dotenv (removing the
throwaway EAB + admin token); stop the app pool if the deployment is parked.
Leave the CA and RA exactly as found. **Do not** revert the E-1 remediation (the
enrollment gMSA's restricted primary group is a permanent hardening, not a test
artifact).

**Republish the CRL after the revocation loop, and PROVE it from the CDP.**
Revoking at the CA and publishing a CRL are two operations, and only the first
used to be written down here. Revoking without publishing leaves every
certificate the session created still accepted by every relying party until the
next scheduled publication — on a one-week `CRLPeriod`, for close to a week.

That is not lab housekeeping. A certificate the CA considers revoked but that
nobody can see as revoked is precisely the state this product's revocation story
exists to prevent, and leaving the lab in it also means the *next* session's
`require_crl_evidence` checks and the watermark's first-use baseline run against
a CRL silently missing the previous session's revocations — which makes any
cross-session claim about revocation latency un-measurABLE, in the same way item
22 made the CRL age un-measurable.

It went unnoticed for rounds because the validation log asserted it. Entries for
earlier rounds say "revoked … and the CRL republished"; at least one round did
not. Same shape as the preserve step before it: the step was believed done
because the sentence describing it was written, and nothing checked. So:

1. run `certutil -config <CA> -CRL` after the revocation loop;
2. **verify from the CDP, not from `certutil`'s exit code.**
   `scripts/verify_crl_publication.py` is committed for this and takes the
   controls with it:

   ```bash
   python scripts/verify_crl_publication.py \
       --url <CDP-URL> \
       --revoked <SERIAL> [--revoked <SERIAL> ...] \
       --absent <UN-REVOKED-SERIAL> \
       --min-crl-number <NUMBER OBSERVED BEFORE THE REPUBLISH>
   ```

   `CRL-PUBLICATION-VERIFIED …` on stdout is the required evidence; its absence
   means the teardown did not prove publication, whatever else it printed. The
   three checks are there because absence proves nothing on its own — a CRL
   lookup that matches nothing returns what a correct negative returns. The
   revoked serials are the **positive control** (a broken lookup reads them as
   absent and fails), `--absent` is the **negative control** (a lookup that
   matches everything fails), and `--min-crl-number` proves the document is one
   published *after* the revocations rather than a cached pre-revocation CRL.
   An unreachable CDP exits **2**, distinct from the **1** that means "checked,
   and the serials are not there": a transport failure is no evidence either
   way and must not be recorded as either verdict.

**Interaction with the sampler, so a future session does not get this backwards.**
A forced republication truncates the current publication cycle, which costs
`scripts/sample_crl_age.py` that cycle as a clean natural observation. It
**cannot** corrupt the served-age floor — a truncated cycle only ever serves
ages below the running maximum, so it can move neither bound. The trade is real
and one-sided: do not skip the republish to protect the sampler.

**Preserve the post-run store BEFORE restoring it.** Copy the live store — all
three SQLite files, and only after the app pool is confirmed *stopped* — to a
dated directory that the restore does not touch, and fail the teardown if that
copy cannot be made rather than proceeding. Do it before removing anything, so a
failure costs a re-run and not the evidence.

This is not housekeeping. WI-052 went four rounds unresolved while the data that
would have settled it was generated by every session and deleted by this step:
the store carried `crl_this_update` on every CRL-verified confirmation, and 722
audit rows spanning two months contained not one of them. The item was not
un-measured, it was **un-measurable** — and the same is true of *any* property
that needs evidence from more than one session. A restore-to-pristine teardown
is correct for isolation and is amnesia for measurement; keeping one dated copy
per session costs almost nothing and is what makes the class measurable at all.

Anything you intend to measure *across* sessions must live outside the restore
scope entirely — see `scripts/sample_crl_age.py`, which needs no RA at all.

**Reference implementation of the preserve step.** The prose above is the
policy; this is the code, committed here so that anyone re-proving from a
clean checkout re-applies the change by paste instead of re-deriving it. It is
identifier-free and parameterised (`$StateRoot`, `$Python`); the live copy in
the gitignored harness (`samples/lab-harness/restore.ps1` in this checkout) is
the authoritative one, and the two must not drift. Load-bearing semantics:

- it runs **only after the app pool is confirmed stopped** (copying a store a
  live writer still holds is what corrupted the 2026-08-14 run);
- it copies **all three SQLite files** — a `.db` without its `-wal` is missing
  the newest commits, which are precisely the rows the session was run to
  produce — plus the SIEM mirror;
- it **throws before anything is removed**, so a failure to preserve leaves
  the post-run store intact on disk and the teardown re-runnable.

```powershell
# PRESERVE THE POST-RUN STORE BEFORE DESTROYING IT (UNFILED item 22).
$postrun = Join-Path $StateRoot ("postrun-store-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $postrun | Out-Null
$preserved = 0
foreach ($suffix in @('', '-wal', '-shm')) {
    $src = Join-Path $StateRoot ('acme_ra.db' + $suffix)
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $postrun ('acme_ra.db' + $suffix)) -Force
        $preserved++
    }
}
if ($preserved -eq 0) { throw "no post-run store found at $StateRoot to preserve; refusing to restore over an unexamined state" }
if (-not (Test-Path (Join-Path $postrun 'acme_ra.db'))) { throw "preserved $preserved file(s) but not acme_ra.db itself; refusing to proceed" }
Copy-Item (Join-Path $StateRoot 'acme_ra.siem.jsonl') (Join-Path $postrun 'acme_ra.siem.jsonl') -Force -ErrorAction SilentlyContinue
# Row counts, not file size: "the store was preserved" is the kind of claim
# whose failure mode is silence, and a byte count would not distinguish a
# session's worth of audit rows from an empty schema.
& $Python -c "import sqlite3,json,sys;c=sqlite3.connect(sys.argv[1]);print('POSTRUN-PRESERVED '+json.dumps({t:c.execute('select count(*) from '+t).fetchone()[0] for t in ['audit_log','certificates','orders']}))" (Join-Path $postrun 'acme_ra.db')
Write-Output ("POSTRUN-STORE=" + $postrun)
```

Treat `POSTRUN-PRESERVED {…}` and `POSTRUN-STORE=…` in the teardown output as
required evidence of the preserve step; their absence means the teardown ran
without it and the session's longitudinal evidence was destroyed.

## The lab-specific half of this procedure

This document is deliberately placeholder-only: it says *what* must be proven.
The *how* for a given lab — hosts, credentials, the automated harness, and the
tricks for provoking paths a well-behaved CA will not hand you (a policy denial,
both transport-orphan branches, a failed confirmation) — belongs in a gitignored
companion, because it names real infrastructure. In this checkout that is
`samples/lab-validation-runbook.md`, with the harness itself at
`samples/lab-harness/`. If you are re-proving in a different estate, write the
equivalent for yours rather than putting identifiers here.

## Environment gotchas (observed)

- **gMSA scheduled tasks** need `LogonType=Password` (a gMSA never logs on
  interactively). `Register-MaintenanceTasks.ps1` sets this.
- **`certutil` argument order:** `-config` must precede the `-revoke`/`-CRL` verb.
- **CA-side officer provisioning** must ship `scripts/lib/` alongside the scripts.
- **Create the revoker gMSA with explicit AES Kerberos etypes.** A gMSA created
  without `msDS-SupportedEncryptionTypes` set gets **RC4** added to its supported
  etypes; if the DCs block RC4 (common hardening), the account's Kerberos context
  fails (`Install`/`Test-ADServiceAccount` → *"the provided context did not match
  the target"*) and its managed password is unusable on members. Create it with
  `New-ADServiceAccount … -KerberosEncryptionType AES128,AES256` (or set
  `msDS-SupportedEncryptionTypes = 24` after the fact). Symptom is easy to
  misread as a KDS/time-sync problem — it is not.
- **`certutil` does not echo the `-restrict` clause** (verified 2026-08-11). A
  serial with no matching row returns `Maximum Row Index: 0` / `0 Rows` with the
  serial *absent* from the output, so `Confirm-SerialAtCa`'s "does this serial
  exist" grep is sound rather than vacuous. Re-check this if the CA's OS or
  locale ever changes — the whole WI-022 requester guard sits behind it.
- **Serial form: the CA stores the padded byte string.** The RA emits
  `format(n,'x')`, which never has a leading zero, so a certificate whose
  high-order byte is `0x0N` would not match an exact `-restrict` lookup.
  `Get-CaSerialForm` re-pads to even length; `Revoke-Cert.ps1` dot-sources
  `scripts/lib/RevocationLib.ps1` for it. If a revoke exits 4 on a serial the RA
  says is pending, check this first.
- **The revoker needs its own readable copy of the scripts.** In the two-identity
  topology the revoker runs on a separate utility host with its own
  `scripts/` (+ `scripts/lib/`); if you co-locate it on the RA host for a test,
  the revoker gMSA has no ACL on the RA's locked-down `C:\ProgramData\acme-adcs-ra\`
  — stage a copy it can read/execute and point `-ScriptDir` at it.
