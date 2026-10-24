# acme-adcs-ra

An **ACME Registration Authority (RA)** for Active Directory Certificate
Services (AD CS).

It speaks ACME (RFC 8555) to clients and holds **no signing key of its own**.
It forwards each certificate request to your existing AD CS issuing CA, which
signs it with the **existing chain**. Standard ACME clients, specifically an
existing **Certify the Web** install, can then keep "traditional" certificates
renewed for **apps that cannot speak ACME (ADFS, Exchange and similar)**, using
the trust you already run and **no new intermediate CA**.

**Who it is for:** a Windows and Active Directory team that runs its own AD CS
and wants ACME-style automation against it.

## Status, stated plainly

> **Latest release: v1.12.0. The live re-proof of current `main` against a real
> CA is outstanding.**
>
> - **v1.12.0** is the tagged release (2026-08-24). It was live-proven against a
>   real CA in August 2026.
> - **`main` is ahead of the tag** with unreleased changes: a monotonic CRL
>   watermark for revocation-confirmation replay detection; recovery of
>   transport-orphaned certificates; a CRL publication check script; fixes that
>   let stock ACME clients (certbot, lego, acme.sh, Posh-ACME) roll account
>   keys and keep a nonce; several RFC 8555 error-mapping, media-type and
>   challenge-link fixes; and a Windows timer-granularity fix. See the
>   `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md).
> - **The last full live re-proof** ran on 2026-09-05. Later changes on `main`
>   have been tested with unit tests and with a stock-client harness against a
>   fake in-memory CA, **not** against a real CA and IIS host. A targeted lab
>   check on 2026-09-21 covered two security fixes and was not a re-proof.
> - **Before you deploy `main`, or tag a release from it, run the live
>   re-proof** ([`docs/live-reproof-runbook.md`](docs/live-reproof-runbook.md))
>   on the exact commit. Use the v1.12.0 tag if you want the released,
>   live-proven artifact.
> - The project is feature-complete for its charter and maintained
>   deliberately rather than passively. The upstream project accepts security
>   and bug reports with no response-time commitment. If you run your own copy,
>   see [`docs/handover.md`](docs/handover.md).

**Green CI is not ADCS verification.** Cloud CI cannot reach a CA, so a green
build proves the code and the logic of the operator scripts. It does not prove
that issuance or CA-side revocation still work. Only the live re-proof does. It
is required at every release, before any pilot, after any change to the issuance
leg, and quarterly while deployed.

That distinction has paid for itself repeatedly. The 2026-08-13 re-proof found
two defects that Linux CI structurally could not see. Both were Windows
PowerShell 5.1 language behaviours that `pwsh` 7 on Linux handles differently,
and one of them was inside the review's own fix. A second static scan then found
seventeen findings (two serious) that a green live re-proof had not surfaced.
The 2026-08-14 re-proof of the fixes for those found one more, on the CA.
Neither kind of check substitutes for the other. See the 2026-08-13 and
2026-08-14 entries in the
[validation log](docs/pre-pilot-checklist.md#validation-log).

## This is not a read-only tool

The sibling projects ([cert-watch](https://github.com/hraedon/cert-watch/) and
adcs-lens) only observe. Their worst case is a wrong report. **acme-adcs-ra is in
the certificate-issuance path.** It mints real certificates and holds a standing
AD CS enrollment identity. Its worst case is **mis-issuing a certificate or
leaking that identity**. It is load-bearing production infrastructure and is
engineered to a higher bar. The read-only, air-gapped and "flag, don't probe"
conventions of the family **do not apply here**. The hard rules in
[`AGENTS.md`](AGENTS.md) replace them.

## What it does and does not do

**It does:**

- Serve ACME: directory, accounts gated by **EAB** (External Account Binding),
  orders, finalize, certificate retrieval, key change, revocation.
- Forward each CSR to AD CS through `/certsrv/` as a passwordless gMSA.
- Support two AD CS layouts: **Mode A** (Web Enrollment on the CA itself) and
  **Mode C** (a separate Web Enrollment or CES host). Both are described in
  [`docs/certsrv-setup.md`](docs/certsrv-setup.md).
- Write an audit record for every issuance, to its own store and to your SIEM.
- Queue revocations and carry them to the CA through a separate, scoped
  identity (see "How revocation works").

**It does not:**

- **Act as a CA or hold any signing key, ever.** If a change would make it sign
  certificates itself, it is the wrong change.
- Manage endpoint TLS lifecycle (cert-watch's job).
- Analyse CA posture or misconfiguration (adcs-lens's job).
- Validate domain control the way a public CA does. Gating here is enterprise
  identity (EAB plus a network allowlist), not public domain validation.
- Revoke at the CA by itself. The enrollment identity has no CA-officer rights.

## How it works

```
Certify the Web  ──ACME (RFC 8555, EAB-gated)──▶  acme-adcs-ra  (RA, runs as a gMSA)
                                                        │
                                          /certsrv/ POST, Negotiate/SSPI (passwordless)
                                                        ▼
                                                  ADCS issuing CA  ──signs──▶  existing chain
```

The RA terminates ACME, authorizes the request, and submits the CSR to AD CS
through the **Web Enrollment** page. The CA signs with its existing key.

Why an RA: the "stand up a parallel CA and another intermediate" problem comes
from using ACME *CAs* (step-ca, Boulder, Caddy internal). An RA holds no signing
key, so it avoids that problem. The chain it returns is your existing AD CS
chain, which every domain-joined machine already trusts.

Design principles:

- **No signing key, ever.**
- **Deterministic issuance policy.** Which template and which SANs are allowed
  is explicit policy code. No LLM anywhere in the issuance path.
- **Passwordless.** It authenticates to AD CS as a **gMSA** over Negotiate/SSPI.
  No ADCS credential is stored. Secrets (EAB keys) are never committed.
- **A narrow chokepoint.** One **server-authentication-only** template, with
  subject and SAN taken from the CSR. Concentrating SAN-capable enrollment in
  one hardened, audited identity is better than spreading it across app servers,
  and it makes auditing possible.
- **Audit every issuance**, in the RA's own store and in the AD CS CA database,
  and emit it to your SIEM.
- **Stack:** FastAPI and SQLite (the family stack), with `cryptography` for
  CSR and JWS handling.

The RA's own enrollment identity is itself an ESC (AD CS escalation) surface
that adcs-lens would analyse. Get the template scope right (see `AGENTS.md`).

## Before you deploy

Work through [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md) first.
Passing tests is necessary but not sufficient for this kind of infrastructure.
The checklist covers the operator-owned prerequisites: the network allowlist,
EAB rotation, admin-token handling, monitoring, and a live re-issue against the
deployed commit.

Items that are easy to miss:

- **`base_url` is security configuration, not a display value.** Every JWS and
  EAB binding is checked against the URL derived from `ACME_RA_BASE_URL`, not
  the URL the request arrived on. Set it to the exact public origin (scheme,
  host and port), or every legitimate request is refused from day one. Use
  **separate EAB kids per environment**: a kid shared with a staging RA no
  longer verifies against production.
- **An off-box audit sink is required, not recommended.** Set
  `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with authenticated HTTPS HEC. The default
  `jsonl` sink dies with the host it is auditing, and plain syslog cannot
  authenticate the collector or protect events in transit. Syslog is still
  supported as an optional mirror when this requirement is false. The RA
  refuses to start if the required HEC sink cannot actually emit.
- **The network allowlist is required**, in front of the unauthenticated nonce
  endpoint.
- **`ACME_RA_REVOCATION_CONFIRM_TOKEN` is required** for the CA-side revocation
  loop, and the general admin token is deliberately refused there. Without it,
  serials revoke at the CA but stay on the RA's pending list.
- **Credentials have strength floors, and must differ.** EAB MAC keys must
  decode to at least 32 bytes and admin and confirm tokens must be at least 32
  characters. Mint EAB credentials with `python scripts/eab.py` and generate
  tokens with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
  Weak values refuse startup. So does setting the admin and confirm tokens to the same string,
  which would collapse the separation the second credential exists to create.
- **Install from the pinned closure.** `scripts/install-windows.ps1` installs
  dependencies from `deploy/requirements.lock.txt` with `--require-hashes`, so
  the host runs the set CI tested rather than whatever the package index
  resolves that day. A missing lock file is fatal, not a fallback.
- **Apply the enrollment-side bound (Finding E-1) for your estate.** Move the
  enrollment gMSA off the Domain Computers `Machine`-enroll path and verify it
  can enroll only `ACME-ServerAuth`. See
  [`docs/revocation-scope-validation.md`](docs/revocation-scope-validation.md).
- **If you use the two-identity topology, create the revoker gMSA with AES
  Kerberos types** (`-KerberosEncryptionType AES128,AES256`). A gMSA created
  without them gets RC4 added, which fails wherever DCs block RC4, and the
  symptom reads misleadingly as a KDS or time-sync problem.

## How revocation works

AD CS Web Enrollment has no revocation endpoint. Revocation is therefore a
separate, out-of-band path, so the enrollment identity does not need wider
rights (WI-010, threat-model section E).

1. `revokeCert` records the revocation in the RA store and queues the serial.
2. `scripts/Sync-Revocations.ps1`, running as an identity with officer rights
   scoped to the template, revokes it at the CA and confirms back to the RA.
3. `scripts/Revoke-Cert.ps1` is the manual equivalent.

Reason 7 is rejected by both the RA and the scripts (RFC 5280 "unused";
`certutil` rejects it), so an accepted reason cannot silently break the loop.

**Wire contract (since v1.11.0).** The request payload field is
**`certificate`**, per RFC 8555 section 7.6. `cert` is still accepted as a
deprecated alias for in-house tooling, but clients should not send it. Success
is **200 with an empty body**. Because the CA's CRL is written out of band, the
RA adds a non-normative `X-Acme-Ra-Out-Of-Band-Revocation` response **header**
naming the serial, the runbook and any request ID. It is a header and not a body
field because real ACME clients do not ignore a JSON body here: it made Certify
the Web report a successful revocation as failed.

Authentication to `/certsrv/` is the ambient **gMSA** identity over SPNEGO with
**channel binding** (RFC 5929 `tls-server-end-point`), through the in-tree
`negotiate_auth.NegotiateAuth` over `pyspnego`. It therefore works against a
`/certsrv/` hardened with **EPA=Require**.

## Installation

The RA runs on **Windows Server** behind **IIS** (HttpPlatformHandler). The
application pool runs **as a gMSA**; that ambient Kerberos identity is what
authenticates to `/certsrv/`. `scripts/install-windows.ps1` does the host side.
The CA side (Web Enrollment and the issuance template) is set up once per CA
with [`docs/certsrv-setup.md`](docs/certsrv-setup.md).

> **Read [`docs/operator-requirements.md`](docs/operator-requirements.md)
> first.** It is the contract for everything the installer deliberately does not
> decide for you. It lists every condition the installer *refuses* on, with the
> exact remedy. The installer fails closed in several places by design, and
> knowing which in advance saves a confusing first run.

**The install is split across two directories, and the split is a security
boundary:**

| | Code (`-RuntimeDir`) | State (`-InstallDir`) |
|---|---|---|
| Default | `%ProgramFiles%\acme-adcs-ra` | `C:\ProgramData\acme-adcs-ra` |
| Holds | interpreter and venv, under `current\` | audit DB, logs, `acme-ra.env` |
| The gMSA gets | **read + execute** | **modify** (dotenv: read) |
| Lifecycle | rebuilt from scratch every install | survives every install |

`%ProgramData%` grants `Users` create-folder rights by default, so a local user
can pre-create a predictable path there and own it. `%ProgramFiles%` does not.
Keeping executable content out of the tree the worker can write to is what stops
a compromised app pool from rewriting the interpreter it runs as. Neither root
is ever *adopted*: a pre-existing directory must match what a completed install
leaves behind, or the installer refuses and tells you what to do.

### Prerequisites

| Prerequisite | How to satisfy it |
|---|---|
| **IIS** role plus `Web-Mgmt-Console`, `Web-Scripting-Tools`, `Web-IP-Security` | `install-windows.ps1 -InstallPrereqs` (uses `Install-WindowsFeature`) |
| **HttpPlatformHandler** (IIS module, third-party MSI) | Get the v1.2 amd64 MSI from [iis.net](https://www.iis.net/downloads/microsoft/httpplatformhandler). Install it by hand, or pass `-HttpPlatformHandlerMsi <path>` (see the note below) |
| **Python 3.12 or later**, machine-wide | Install it **separately, before** running the installer (for example `winget install Python.Python.3.12` from your own elevated session). `-InstallPrereqs` deliberately does **not** do this: an elevated bootstrapper running a `py`, `python` or `winget` chosen from PATH turns a writable PATH entry into Administrator code execution on the issuance host |
| **A gMSA installed on this host** | `Install-ADServiceAccount`. `Test-ADServiceAccount` must return `True` |
| **On the CA: Web Enrollment and the `ACME-ServerAuth` template** (server-auth-only EKU, subject from request, gMSA granted Enroll only) | One-time per CA. See [`docs/certsrv-setup.md`](docs/certsrv-setup.md) |

> **HttpPlatformHandler is never auto-downloaded, and never installed
> unverified.** It is a separate Microsoft module whose download has been
> unreliable, and this is issuance-path infrastructure. The installer detects
> it and, if it is missing, installs it **only** from an MSI you point at
> (`-HttpPlatformHandlerMsi`).
>
> It is the one third-party executable the installer runs, and it runs as
> Administrator on the host that holds the RA's gMSA context. So it is verified
> before `msiexec` sees it:
>
> - **every source**, local or HTTPS, needs an out-of-band
>   `-HttpPlatformHandlerSha256` and a `Valid` Authenticode signature from the
>   expected publisher;
> - **plaintext `http://` is refused outright**, because a digest delivered over
>   a channel an attacker controls proves nothing;
> - the source is copied or downloaded into fresh administrator-only staging,
>   the staged bytes are verified, and only that protected path reaches the
>   System32 `msiexec.exe`.
>
> Any failure aborts the install. See
> [`docs/security-review-2026-08-17.md`](docs/security-review-2026-08-17.md)
> finding 1.

### Install

Run from an **elevated** PowerShell on the RA host, from an administrator-only
local release tree. The installer verifies the source tree before it dot-sources
or builds anything, snapshots it into protected storage, and refuses a checkout
that another user or group can write to.

```powershell
# 1. Install Python 3.12+ machine-wide first. Optionally install the native
#    IIS prerequisites with this script.
#    HttpPlatformHandler is installed too if you point at its MSI. The MSI's
#    Authenticode signature, publisher, and SHA-256 are always checked for both
#    local and HTTPS sources (Get-FileHash -Algorithm SHA256 gives the digest).
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -InstallPrereqs `
    -HttpPlatformHandlerMsi "C:\path\to\HttpPlatformHandler_amd64.msi" `
    -HttpPlatformHandlerSha256 "<expected-sha256-of-that-msi>"

# 2. install + configure IIS (app pool as the gMSA, TLS, site on :443 by SNI).
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -ConfigureIIS `
    -HostName "acme-ra.work-domain.local" -SharePort443 `
    -TlsCertThumbprint "<thumbprint in LocalMachine\My>"
```

Replace the `WORK-DOMAIN` account and host names with your own.

Both steps can be combined (`-InstallPrereqs -ConfigureIIS`). `-InstallPrereqs`
does not run a Python or winget picked from PATH; install Python separately
first. The script always prints a **prerequisite check** first (IIS role, IIS
module, Python, RSAT), so you see what is missing before it does anything.

It is **safe to re-run**. The secret env file and an existing `web.config` are
never overwritten, and the IIS steps are idempotent. `-SharePort443 -HostName`
lets the RA share port 443 by SNI with cert-watch or gpo-lens on the same VM.
Leave them out for a single-site catch-all binding. IIS detail is in
[`deploy/iis/README.md`](deploy/iis/README.md).

### After install, required before first use

1. **Fill in the EAB credential and SAN scope** in `...\acme-ra.env`. The
   installer lays the file down locked, readable by the gMSA and Administrators
   only. Pin it to your ACME client.
2. **Set `ACME_RA_BASE_URL` and the `ACME_RA_ADCS_*` values** in the site's
   `web.config`. `BASE_URL` must be the *public* `https://host:port/`, or every
   JWS is rejected from day one.
3. **Restrict the endpoint to the ACME client.** Add `<ipSecurity>` to
   `web.config` (needs `Web-IP-Security`, which `-InstallPrereqs` installs) or a
   scoped firewall rule. This is a threat-model pilot condition and the
   installer deliberately does not do it for you. See
   [`docs/operations.md`](docs/operations.md) for the full allowlist snippet,
   reverse-proxy rate-limit guidance, the EAB rotation runbook, scheduled
   maintenance tasks, the admin-token and reclaim runbook, monitoring and SLOs,
   retention and archival, the revocation runbook, and backup and restore.

Every setting is listed in [`docs/configuration.md`](docs/configuration.md).

### Verify

```powershell
# The ACME directory should return JSON:
Invoke-WebRequest https://acme-ra.work-domain.local/directory -UseBasicParsing
# The Negotiate stack imports (run as the venv python):
& "C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe" -c "import spnego; import acme_adcs_ra.negotiate_auth"
```

Then work through [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md)
before going live.

## Documentation map

| If you want to... | Read |
|---|---|
| Take over a running install | [`docs/handover.md`](docs/handover.md) |
| Understand the design | [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md) |
| Set up the CA side | [`docs/certsrv-setup.md`](docs/certsrv-setup.md) |
| Install without surprises | [`docs/operator-requirements.md`](docs/operator-requirements.md) |
| Look up a setting | [`docs/configuration.md`](docs/configuration.md) |
| Run it day to day | [`docs/operations.md`](docs/operations.md) |
| Upgrade or roll back | [`docs/upgrade-and-rollback.md`](docs/upgrade-and-rollback.md) |
| Fix a problem | [`docs/troubleshooting.md`](docs/troubleshooting.md) |
| Sign off a pilot | [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md) |
| Prove it still works against your CA | [`docs/live-reproof-runbook.md`](docs/live-reproof-runbook.md) |
| Change the code | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`AGENTS.md`](AGENTS.md) |
| Report a vulnerability | [`SECURITY.md`](SECURITY.md) |
| See what changed | [`CHANGELOG.md`](CHANGELOG.md) |

## How it got here

| Release | What it added |
|---|---|
| **v1.0** | ACME server (RFC 8555 subset), deterministic issuance policy, the live AD CS enrollment leg |
| **v1.5 to v1.6** | Automated CA-side revocation (two-identity default, opt-in single-identity), self-enforced serverAuth EKU verification, the enrollment-side bound (Finding E-1), a Pester suite, and the live re-proof runbook |
| **v1.7** | Security hardening: CA-capable CSR and certificate rejection, CN to SAN binding, rate-limit TOCTOU, JWS streaming cap, algorithm exactness |
| **v1.8** | `base_url` URL binding, account eviction, serial re-padding to the CA database form |
| **v1.9** | Two external security reviews. The [2026-08-13 review](docs/security-review-2026-08-13.md) had ten findings, including separated revocation-confirm authority with optional CRL proof, certificate quarantine, and atomic issuance plus audit. The [2026-08-14 review](docs/security-review-2026-08-14.md) had seventeen more, including rejecting ACME reason 8 (`removeFromCRL`, which un-revokes), quarantining certificates orphaned by post-issuance *transport* failures, refusing redirects on the gMSA-authenticated enrollment leg, and a hash-pinned install closure |
| **v1.10** | The 2026-08-15 to 2026-08-23 review series (three external rounds). Finalize revalidated at the CA boundary; `keyChange` compare-and-swap guarded; CRL retrieval pinned to a resolved socket address; the certsrv leg given one monotonic deadline and a dedicated bounded executor; CSR application purposes constrained to `serverAuth`; the installer proving its whole Python interpreter closure and binding inbox cmdlets to a trusted module export table; `audit_prune_enabled` refused rather than silently inert. **Breaking:** `Sync-Revocations.ps1` token parameters became switches, so values can no longer reach argv |
| **v1.11** | Revocation made usable by real ACME clients: `revokeCert` reads the RFC 8555 field `certificate` (it read `cert`, so conformant clients could not revoke at all), and success returns an empty body with the out-of-band hint moved to a response header (a JSON body made a real client report successful revocations as failed). **Breaking:** the `revokeCert` response shape |
| **v1.12** | Audit-growth remediations, issuance-orphan handling with a one-way halt, and live re-proof and teardown corrections. Audit pruning remains explicitly refused until per-row off-box delivery exists |

There is no 1.9.0 or 1.9.1 release. The 1.9 line was written up and
`pyproject.toml` declared `1.9.1`, but no release tag was cut: 1.9.0 shipped
only as `rc1` and `rc2`, and the review series kept finding work. The tagged
history goes v1.8.0, then v1.10.0.

Notes on upgrading from older versions:

- **From 1.10.0 or earlier:** upgrading to 1.11.0 or later is strongly
  recommended if anything other than this project's own tooling revokes
  certificates. 1.11.0 fixed two defects that made ACME revocation unusable for
  real clients: `revokeCert` read the payload field `cert` while RFC 8555
  section 7.6 names it `certificate`, so conformant clients were refused; and
  the success response carried a JSON body that made Certify the Web report a
  successful revocation as failed. The body is now empty, which is a breaking
  response change. Both were found by pointing a real ACME client at the RA for
  the first time. The lab harness and the test client had both sent `cert` as
  well, so a whole revocation suite passed against a dialect no other client
  speaks. See the [changelog](CHANGELOG.md) for why that matters more than the
  fix itself.
- **From 1.8.0:** strongly recommended. 1.8.0 predates `838eeb2`, which fixed a
  defect that left the **entire CA-side revocation loop inert**: every
  `certutil` call ran without its `-config`.
- Each release's live re-proof is recorded in the
  [validation log](docs/pre-pilot-checklist.md#validation-log). The v1.10.0
  series was live-proven across four lab runs, including the stale-worker
  enrollment lease, proven end to end for the first time.

See [`docs/upgrade-and-rollback.md`](docs/upgrade-and-rollback.md) for how to
upgrade.
