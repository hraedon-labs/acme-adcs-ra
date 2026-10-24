# AGENTS.md

Conventions and a quick reference for anyone working on acme-adcs-ra, human or
agent. For taking over the project, start with `docs/handover.md`. For making a
change, see `CONTRIBUTING.md`.

## What this is

An **ACME Registration Authority** for ADCS. It speaks ACME (RFC 8555) to
clients, holds **no signing key**, and forwards CSRs to the existing ADCS
issuing CA over the Web Enrollment (`/certsrv/`) surface as a passwordless
**gMSA**. It exists so Certify the Web can renew ADFS- and Exchange-class
certificates from the existing chain, with no new intermediate. `README.md`
states the charter.

## Where to start reading

1. `docs/handover.md` — the one-page map: what runs where, where things live,
   how to build, test and release, known gaps.
2. `docs/architecture.md` — the design: the RA model, the ACME surfaces, the
   enrollment leg, the transport modes, the security model.
3. `docs/certsrv-setup.md` — how to configure ADCS Web Enrollment in Mode A and
   Mode C.
4. `docs/threat-model.md` — what each control is for.
5. `plans/` — the numbered plans, `001` to `007`. Every one is marked done or
   complete, so they are history, not a to-do list. Open work is in
   `docs/UNFILED-WORK-ITEMS.md` and the known gaps in `docs/handover.md`.

## Hard rules (issuance infrastructure)

These replace the read-only rules that the sibling projects follow.

- **No signing key. Ever.** This is an RA. It must never hold a CA or signing
  private key, or sign a certificate itself. If a change moves that way, stop.
  An architecture test asserts that no signing primitive is invoked in the
  issuance path.
- **Every issue-capable code path is security-critical.** This is not read-only
  software. There is no "it's just analysis" safety margin.
- **Passwordless to ADCS.** Authenticate as a **gMSA** over Negotiate/SSPI
  (`pyspnego`, SPNEGO plus RFC 5929 channel binding, so EPA=Require works; the
  ambient process identity is used through the in-tree
  `negotiate_auth.NegotiateAuth`). **No stored ADCS passwords.** EAB keys and
  any other secrets are never committed.
- **Deterministic issuance policy.** Which template, which SANs, and who may
  request are decided by explicit policy code. **No LLM in the issuance
  decision path.**
- **Least privilege.** One **server-authentication-only** template, with
  subject and SAN taken from the CSR, and the gMSA holding only the Enroll
  right it needs. This limits a compromise to spoofing TLS services, short of
  client-auth or PKINIT domain takeover.
- **Gate the ACME front.** EAB (External Account Binding) pinned to the
  authorized clients, plus a network allowlist.
- **Audit every issuance.** Write to the RA store and emit to the SIEM. No
  silent issuance.
- **No work-domain identifiers in committed files.** Real CA names, hostnames,
  template names, EAB keys and configs belong in gitignored local config or
  `samples/`. Committed docs use placeholders (`CA01`, `WORK-DOMAIN.local`).

## Stack and build

FastAPI, SQLite and `cryptography`. The Windows SSPI enrollment dependency is
platform-gated (`sys_platform == 'win32'`), so CI on Linux does not install it.
The enrollment leg runs only on a Windows host.

```bash
uv sync --locked --extra dev      # what CI does; or: uv venv && uv pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/mypy src                # strict
.venv/bin/pytest -q
```

The PowerShell operator scripts have a Pester 5.7.1 suite under
`tests/pester/`. Run it with `pwsh`:

```powershell
Import-Module Pester -RequiredVersion 5.7.1 -Force
$config = New-PesterConfiguration
$config.Run.Path = "tests/pester"
$config.Run.Exit = $true
Invoke-Pester -Configuration $config
```

CI runs it twice, under PowerShell 7 on Linux and under Windows PowerShell 5.1.
The scripts run on 5.1 in production, and 7 behaves differently in ways that
have hidden real defects. A `pwsh` pass alone is not enough for a change to the
scripts.

A green build is not a statement about ADCS. See `docs/live-reproof-runbook.md`.

## Transport modes

- **Mode A** — Web Enrollment (`/certsrv/`) installed on the CA itself. This is
  the simplest: enrollment is local to the CA, so no Kerberos delegation is
  needed.
- **Mode C** — a separate Web Enrollment or CES host in front of the CA. This
  keeps the CA role-pure, but the enrollment host enrolls on behalf of the
  requester, which requires **Kerberos constrained delegation** to the CA. See
  `docs/certsrv-setup.md`.

## Boundary with the sibling projects

cert-watch covers certificate lifecycle. adcs-lens covers CA posture. This
project is automated issuance off the CA. The RA's gMSA and template are
themselves an ESC surface that adcs-lens would flag, so scope them tightly.

## Status

Current status is in the README (**Status** section). In short: the latest
release is v1.12.0; `main` carries unreleased changes; and the **live re-proof
of current `main` against a real CA is outstanding**. Green CI does not
substitute for it.

The dated engineering status log that this file used to carry (July to
September 2026: review rounds, live validations, retractions) is now
`docs/status-log-2026.md`. Read it for the history and reasoning behind a
control. Do not read it for the current state.
