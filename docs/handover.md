# Taking over acme-adcs-ra

Start here if you have inherited a running acme-adcs-ra, or are about to deploy
one, and the person who built it is not around to ask.

This page describes the project as of **2026-10-24**: latest release **v1.12.0**
(tagged 2026-08-24), with `main` 114 commits ahead of that tag.

## Read this first: what is and is not proven

acme-adcs-ra sits in the certificate-issuance path. It mints real certificates
and holds a standing ADCS enrollment identity. Treat it as production
infrastructure, not as a reporting tool.

**The live re-proof of current `main` against a real CA is outstanding.**

- Continuous integration (CI) cannot reach a CA. A green build proves the code
  and the logic of the operator scripts. It does not prove that issuance or
  CA-side revocation still work.
- The last **full** live re-proof ran on 2026-09-05, against the CRL-watermark
  candidate and then its merge commit. Result: 72 of 74 checks on the candidate
  (the two failures were explained and left visible), then A 14/14, A1 13/13
  and CRL 7/7 on the merge commit. A targeted validation followed on
  2026-09-21 (two security fixes); it was explicitly **not** a re-proof.
- Since then, `main` has taken changes that have **not** been run against a
  real CA and a real IIS host: the RFC 8555 conformance fixes (key rollover,
  `Replay-Nonce`, error mappings, media type, EAB kid floor, challenge `Link`),
  and the CRL deadline-clock change. Those were tested with unit tests and a
  stock-client harness against a fake in-memory CA (`interop/`).
- v1.12.0 itself was live-proven in August 2026. The tag predates the
  watermark, the sampler, orphan recovery and everything listed under
  `[Unreleased]` in `CHANGELOG.md`.

Before you deploy `main`, or tag a release from it, run
[`live-reproof-runbook.md`](live-reproof-runbook.md) on the exact commit. The
runbook says when it is required: at every release, before any pilot, after any
change to the issuance leg, and quarterly while deployed. The validation log in
[`pre-pilot-checklist.md`](pre-pilot-checklist.md#validation-log) records every
run to date.

## What it is, in one page

An ACME server (RFC 8555 subset) that does not sign anything. A client such as
Certify the Web asks it for a certificate; the RA checks the request against
policy, then submits the CSR to your ADCS issuing CA through the Web Enrollment
page (`/certsrv/`). ADCS signs it with the CA's existing key, so the chain is
the one your machines already trust.

```
ACME client ──ACME, EAB-gated──▶ RA (IIS + app pool as gMSA) ──/certsrv/, Negotiate──▶ ADCS CA
```

Two identities are involved in a typical deployment:

- **The enrollment gMSA.** It runs the IIS application pool. It holds only the
  Enroll right on one server-authentication-only template. It has no CA-officer
  rights, so it cannot revoke anything at the CA.
- **The revoker identity.** ADCS Web Enrollment has no revocation endpoint, so
  CA-side revocation is a separate, scheduled, out-of-band job
  (`scripts/Sync-Revocations.ps1`) running as an identity with officer rights
  scoped to that one template. A single-identity option exists and is weaker;
  see `operations.md`, "Deployment variant: single-identity".

### Where things live

| Thing | Location |
|---|---|
| ACME routes (directory, accounts, orders, finalize, certificates, revoke, key change) | `src/acme_adcs_ra/routes/` |
| Admin routes (nonce and order sweeps, order reclaim, pending revocations, revocation confirm) | `src/acme_adcs_ra/routes/admin.py` |
| Request signature (JWS) and EAB checks | `jws.py`, `server_jws.py` |
| Issuance policy (which SANs, which account) | `policy.py`, `csr_validation.py` |
| The call to ADCS `/certsrv/` and SPNEGO auth | `enrollment.py`, `negotiate_auth.py` |
| Finalize flow and post-issuance checks of the returned certificate | `finalize.py`, `issued_certificate_validation.py` |
| Revocation queue and CRL evidence | `revocation.py`, `crl_evidence.py`, `issuer_recovery.py` |
| Settings and startup refusals | `config.py` (see [`configuration.md`](configuration.md)) |
| SQLite store, schema and migrations | `store.py` (tables: `accounts`, `nonces`, `orders`, `authorizations`, `challenges`, `certificates`, `audit_log`, `crl_watermark`) |
| Audit emission (JSONL, syslog, Splunk HEC) | `siem.py`, `audit_coalesce.py`, `audit_retention.py` |
| Windows installer | `scripts/install-windows.ps1`, `scripts/lib/` |
| Operator scripts (revoke, sync, officer rights, scheduled tasks) | `scripts/*.ps1` |
| IIS template (`web.config`) | `deploy/iis/` |
| Pinned dependency lists | `deploy/requirements.lock.txt`, `deploy/build-requirements.lock.txt`, and `uv.lock` for development |
| Tests | `tests/` (Python), `tests/pester/` (PowerShell), `tests/architecture/` (the no-signing-key guards) |
| Stock-client interop harness (needs Docker) | `interop/` |
| Maintainer tools | `scripts/eab.py` (mint EAB credentials), `scripts/sample_crl_age.py`, `scripts/verify_crl_publication.py`, `scripts/reconcile_revocation.py` (read-only check that everything the RA believes is revoked is revoked at the CA) |

Deeper reading: [`architecture.md`](architecture.md) for the design,
[`threat-model.md`](threat-model.md) for what each control is for,
[`certsrv-setup.md`](certsrv-setup.md) for the CA side.

## The hard rules, and why they bind

These are in `AGENTS.md` and each is tested or enforced in code.

- **The RA never holds a signing key.** If a change moves that way, it is the
  wrong change. `tests/architecture/` fails if a signing primitive appears in
  the issuance path.
- **No stored ADCS credentials.** The gMSA's ambient Kerberos identity does it.
- **Issuance policy is plain code.** SAN scope per EAB kid is the whole
  authorization surface; the ACME challenge is deliberately a no-op because the
  trust model is enterprise identity (EAB plus network allowlist), not public
  domain validation.
- **Every issuance is audited**, and a failure to record the issuance halts
  further issuance rather than issuing unaudited.

## Running it

- **Install:** README, "Installation", and
  [`operator-requirements.md`](operator-requirements.md) (read this before the
  first run; it lists every condition the installer refuses on).
- **Daily operation and runbooks:** [`operations.md`](operations.md): EAB
  rotation, admin token, scheduled maintenance, network allowlist, monitoring,
  retention, revocation, backup and restore.
- **Every setting:** [`configuration.md`](configuration.md).
- **Upgrade and rollback:** [`upgrade-and-rollback.md`](upgrade-and-rollback.md).
- **When it misbehaves:** [`troubleshooting.md`](troubleshooting.md).

Things a new owner should do in the first week:

1. Confirm the network allowlist is in place in front of the RA. It ships
   commented out on purpose and is the operator's responsibility
   (`SECURITY.md`, "Recorded decisions").
2. Confirm the audit trail leaves the box (`ACME_RA_AUDIT_OFFBOX_REQUIRED=true`
   with an HTTPS Splunk HEC sink). Without it the audit dies with the host.
3. Confirm the scheduled maintenance and revocation tasks exist and are running
   (`operations.md`, "Scheduled maintenance tasks").
4. Confirm the revocation queue drains: `GET /acme/admin/revocations/pending`
   should not grow without bound.
5. List the allowlisted EAB kids and check each belongs to a client you still
   use (`operations.md`, "Auditing EAB scopes").
6. Check that `GET /acme/admin/orders?status=processing` shows no old orders.
   An order stuck in `processing` needs a human to check the CA database before
   it is reclaimed, because reclaiming a live enrollment can double-issue.

## Building, testing, releasing

```bash
uv sync --locked --extra dev
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
```

Pester for the PowerShell scripts is described in `AGENTS.md`. CI
(`.github/workflows/ci.yml`) runs the Python matrix (3.12, 3.13, 3.14), a
Windows import check, the identifier gate, Pester under PowerShell 7 and
Windows PowerShell 5.1, and `pip-audit`. A scheduled run on the 3rd of each
month catches dependency drift. The stock-client harness has its own workflow
(`.github/workflows/interop.yml`).

**Releasing** has no automated pipeline in this repository. The practice, as
recorded in the changelog and validation log:

1. Move the `[Unreleased]` changelog entries under a new version heading and
   bump `version` in `pyproject.toml`.
2. Run the full live re-proof on the exact commit to be tagged, and record it in
   the validation log.
3. Tag the commit (`vX.Y.Z`). The installer builds from a source tree; there is
   no published package.

Not yet documented: who is authorized to tag, and whether artifacts are
published anywhere. Neither is stated in the repository.

## Known gaps and debts

- **Live re-proof of current `main` is outstanding** (above).
- **Audit pruning is not available.** `audit_prune_enabled=true` refuses
  startup, because the SIEM path has no per-row delivery acknowledgement and
  deleting local rows could destroy the only copy. `audit_retention_days` still
  enforces its floor, and the footprint warning still works. The audit table
  grows without bound until this exists.
- **The CRL age ceiling default (626400 seconds) was measured on one CA** with a
  weekly CRL and 12-hour overlap. It is not a universal number. Measure your own
  CDP with `scripts/sample_crl_age.py` before relying on it
  (`operations.md`, "Deriving the ceiling").
- **Revocation at the CA is out-of-band by design.** The RA records a
  revocation and queues it; the CA does not learn of it until the sync job runs.
  An operator must confirm the CRL republished after each revocation.
- **Some transport-failed issuances need a person.** A certificate the CA
  issued but whose chain fetch failed ("transport orphan") is recovered
  automatically when issuer material is already held. A *leafless* orphan (no
  certificate bytes at all) has no automated path and is listed separately on
  the pending-revocations endpoint (`operations.md`, "Transport orphans").
- **The IP allowlist is not enforced by the installer or at startup.** Accepted
  posture, documented in `SECURITY.md`.
- **The tracker.** Work was tracked in an external work-item store that was
  unavailable for part of 2026; the fallback record is
  [`UNFILED-WORK-ITEMS.md`](UNFILED-WORK-ITEMS.md). It mixes open and resolved
  items, and some entries predate later fixes. Check an item against
  `CHANGELOG.md` before treating it as open. Not yet documented: where open
  work should be tracked after the repository moves to a new organisation.
- **A Windows host test gap.** One Pester test failed on one lab host because
  `python3.exe` was not executable there; this was recorded and not filed
  (validation log, 2026-09-21).

## What it depends on

- **ADCS** with Web Enrollment (`/certsrv/`) and the `ACME-ServerAuth` template
  (`certsrv-setup.md`). Mode A (on the CA) or Mode C (separate host with
  Kerberos constrained delegation).
- **Windows Server, IIS and HttpPlatformHandler**, with Python 3.12 or later.
- **A gMSA** on the host (AES Kerberos encryption types if your DCs block RC4).
- **A SIEM collector** reachable over HTTPS (Splunk HEC) for the audit trail.
- **An ACME client**, tested with Certify the Web; the interop harness also
  drives certbot, lego, acme.sh and Posh-ACME against a fake CA.
- **Python dependencies**, pinned with hashes in `deploy/requirements.lock.txt`.

## Security reports

See [`../SECURITY.md`](../SECURITY.md). The documented channel is GitHub private
vulnerability reporting on the upstream repository. Not yet documented: the
reporting contact for your own organisation's copy.
