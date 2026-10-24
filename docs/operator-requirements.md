# Operator requirements

This RA leaves a lot to whoever installs it. That is deliberate: the installer
refuses to guess about anything that decides what certificates get issued. It
only works if the delegation is written down. This document is the contract. It
covers what you must provide, what the installer refuses to do and why, and what
to do when it refuses.

For day-two operations (retention, revocation, the admin token, backup/restore)
see `operations.md`. For the pre-pilot sign-off list see
`pre-pilot-checklist.md`. This file is about getting a correct install and
keeping its invariants true.

---

## 1. The two-tree layout

The install is split in two. The split is a security boundary, not tidiness.

| | Code | State |
|---|---|---|
| Parameter | `-RuntimeDir` | `-InstallDir` |
| Default | `%ProgramFiles%\acme-adcs-ra` | `C:\ProgramData\acme-adcs-ra` |
| Holds | interpreter, virtualenv (under `current\`) | audit DB, logs, `acme-ra.env` |
| Administrators / SYSTEM | Full | Full |
| The gMSA | **Read + Execute** | **Modify** (dotenv: **Read**) |
| Lifecycle | rebuilt from scratch on every install | survives every install |
| Executed? | yes — this is the only executed tree | **never** |

### Why the split exists

The default ACL on `%ProgramData%` grants `Users` *create folders / append
data* with `CREATOR OWNER` inheritance. Any local user can therefore
pre-create `C:\ProgramData\acme-adcs-ra` and own it. Four consecutive security
review rounds produced findings that all began there: a planted interpreter, a
planted venv startup file, a planted checksum manifest that authenticated the
planted interpreter, and junctions that redirected the elevated ACL fix-ups.

`%ProgramFiles%` grants `Users` read and execute only. Moving the executable
half of the install there removes the attacker's ability to pre-plant it at
all, rather than detecting the plant afterwards.

The second half of the split matters just as much. The gMSA needs write access
to the database and the log, and it used to get that over a single tree that
also held the interpreter it runs as, so a compromised app pool could rewrite
its own interpreter. Now it can write only to things that are never executed.

### Invariants you must not break

These are not style preferences. Each one is load-bearing:

1. **Never grant the gMSA write, modify or full control anywhere under
   `-RuntimeDir`.** It runs the code in that tree. Write access there is
   remote-code-execution-as-the-issuance-identity.
2. **Never put executable content under `-InstallDir`.** No scripts, no
   `.pth` files, no copied interpreters. The gMSA can write there.
3. **Never point `-RuntimeDir` at a location non-administrators can create in**
   — including `%ProgramData%`, `C:\`, `%TEMP%`, or a user profile. If you
   override the default, pick somewhere with `%ProgramFiles%`-like permissions.
4. **Never relax the dotenv's ACL.** `acme-ra.env` is gMSA **read-only** on
   purpose. It holds `ACME_RA_EAB_ALLOWLIST` and `ACME_RA_SAN_SCOPES`, which
   decide which clients may enrol and for which names. A worker that can
   rewrite its own SAN scope has no SAN scope.
5. **Never hand-edit the ACLs on either tree.** The next install re-verifies
   them and will refuse to proceed if they do not match; see §3.

---

## 2. What you must provide before running the installer

The installer checks and reports on all of these. `-InstallPrereqs` installs
the Windows IIS features and, when explicitly supplied, the pinned
HttpPlatformHandler MSI. Python must already be installed: the elevated
installer never runs PATH-selected `py`, `python`, or `winget`.

| Requirement | How to satisfy it | Installer behaviour if missing |
|---|---|---|
| Elevated PowerShell | Run as Administrator | Refuses immediately |
| Windows PowerShell 5.1 or PowerShell 7 | Ships with Windows | — |
| A gMSA, installed on this host | `New-ADServiceAccount`, then `Install-ADServiceAccount` on the RA host; `Test-ADServiceAccount` must return True | SID resolution failure is fatal; a False from `Test-ADServiceAccount` is a loud warning (the app pool will not start) |
| gMSA has **Enroll** on a server-authentication-only template | ADCS template ACL | Not checked — **your responsibility**, and it is the control that bounds what the RA can ever mint |
| IIS role + `Web-Mgmt-Console`, `Web-Scripting-Tools`, `Web-IP-Security` | `-InstallPrereqs`, or `Install-WindowsFeature` | Reported as MISSING |
| HttpPlatformHandler v1.2 (amd64) | Pass `-HttpPlatformHandlerMsi <path-or-https-url>` **and** an out-of-band `-HttpPlatformHandlerSha256` | Reported as MISSING; never auto-fetched |
| Python 3.12+ | Install machine-wide before running this script | Fatal — the runtime cannot be built; `-InstallPrereqs` deliberately does not run winget |
| A TLS server certificate in `LocalMachine\My` | Your PKI | Binding created without a certificate, with a warning |
| A network allowlist in front of the endpoint | `<ipSecurity>` in web.config, or a scoped firewall rule | Not enforced by the installer — **your responsibility**, and it is a stated pilot condition in the threat model |
| Capacity for the local audit store, **or** off-box audit | Monitor the footprint warning; or set `audit_offbox_required` with working authenticated HTTPS HEC | Not enforced — **your responsibility**. The `certificate-issued` audit row commits in the *same transaction* as the certificate, so **a full disk stops issuance** rather than issuing unaudited. See below. |

### Local-only audit: a supported posture with a stated cost

`audit_offbox_required` is **off by default**, and running without an off-box
sink is supported, not merely tolerated. The cost is explicit, and it is
availability rather than confidentiality:

- **A full disk stops issuance.** Auditing every issuance is a hard rule of this
  project, enforced by committing the audit row in the same transaction as the
  certificate. When that transaction cannot commit, issuance fails. This is the
  intended failure direction (the alternative is issuing certificates with no
  record), but it makes audit-store capacity an issuance dependency.
- **The retention sweep will not run.** With no off-box copy, the local
  `audit_log` is the only evidence there is, so this RA refuses to delete from
  it regardless of `audit_retention_days` or `audit_prune_enabled`. Local-only
  deployments bound growth by *capacity and monitoring*, not by pruning.

What you get instead is measurement. The footprint (SQLite database plus the
JSONL mirror and its rotated files) is reported at startup and warns past
`audit_store_warn_mib` (default 1024). Growth is slow — a few GiB per 180 days
even under sustained denial flooding, because denial rows are coalesced per
time window rather than per request — so crossing the threshold means something
has changed rather than that the RA is busy.

Pruning is not available in production. The design would need **all** of
`audit_retention_days` at or above the floor, `audit_prune_enabled`,
`audit_offbox_required`, and a delivery probe that succeeds at sweep time. But
startup refuses `audit_prune_enabled=true`, because the current SIEM path has no
acknowledged per-row delivery (`config.py`, `server.py`). `audit_retention_days`
alone declares the policy, is checked against the retention floor at startup,
and deletes nothing.

### A note on the Python you provide

A **machine-wide** interpreter (`%ProgramFiles%\Python3xx`, or the `py`
launcher pointing at one) is referenced in place, because it already lives
somewhere non-administrators cannot write. A **user-profile** interpreter
(`%LOCALAPPDATA%`, Windows Store) is copied into the runtime tree, because the
gMSA cannot read another account's profile. Prefer a machine-wide install:
fewer bytes to copy, and one less thing that can drift.

### A note on the installer source

Run the script from a local release tree that only the invoking administrator,
Administrators, SYSTEM, or TrustedInstaller can write. Do not run it from a
shared checkout, a broadly writable tools directory, or a network share. Before
dot-sourcing its helper library, the installer verifies the owner and write ACEs
of every source/build/deployment input and their ancestor chain. It then copies
those inputs into a fresh protected snapshot under `%ProgramFiles%` and builds
only from that snapshot. A named user or custom group with write access is a
refusal, even if the familiar broad `Users` groups are absent.

---

## 3. Every condition the installer refuses on

The installer fails closed. Each refusal below is deliberate, and each one has
a specific remedy. **Do not work around these by pre-creating directories,
loosening ACLs, or editing the script.** Every one of them exists because the
permissive version of it was a finding.

### 3.1 "Refusing to install into `<path>`" — a root that is not ours

**When:** `-RuntimeDir` or `-InstallDir` already exists, and does not match
what a completed install of this RA leaves behind: wrong owner, an unexpected
trustee in the ACL, an explicit ACE that should have been inherited, a deny
ACE, or a reparse point anywhere in the tree.

**Why:** the installer cannot distinguish a hostile pre-planted tree from a
half-finished one, so it treats both as "not mine". Earlier versions
force-claimed a pre-existing directory with `takeown`, which was a
privilege-escalation route on a path a local user can create first.

**What to do:** the message lists what disqualified the directory and which
files are worth keeping. In order:

1. Copy out anything you need — normally `acme_ra.db`, `acme-ra.env`, `logs\`.
2. **Inspect them.** If the directory was pre-created by someone else, so were
   its contents. In particular, read `acme-ra.env` line by line: a planted one
   carries someone else's `ACME_RA_EAB_ALLOWLIST` and `ACME_RA_SAN_SCOPES`.
3. Remove or rename the directory.
4. Re-run the installer. It will create the directory itself.
5. Restore only what you verified, then re-check it against §5 below.

### 3.2 "could not claim ownership of `<path>` … without following links"

**When:** ownership of an existing tree could not be taken using
`icacls /setowner`, which never follows a junction or symlink.

**Why:** `takeown` would have forced it, but `takeown` has no no-follow option.
A junction raced into the tree mid-operation redirects an elevated recursive
ownership rewrite *outside* the install directory. The installer no longer has
a force path.

**What to do:** treat the directory as hostile. Inspect, move or delete it,
re-run. If this happens on a directory you are certain is yours, something
else on the host has taken ownership of it. Find out what before continuing.

### 3.3 "app pool `<name>` still has a live worker process after N s"

**When:** the app pool was told to stop but `appcmd list wp` still shows a
worker after the timeout.

**Why:** Windows checks access when a handle is *opened*. A worker holding a
write handle from before the ACL reset keeps that access through it, and could
rewrite runtime bytes between verification and execution. "The pool says
Stopped" is not evidence, because the worker lingers while it drains.

**What to do:** stop the pool by hand (`appcmd stop apppool`), or kill the
`w3wp.exe` for that pool, and re-run. If it will not die, something is holding
a request open; investigate before installing.

### 3.4 "Install-tree ACL verification FAILED"

**When:** after the installer has set ownership and DACLs, reading the tree
back does not produce the expected shape.

**Why:** "we ran icacls" is not evidence. This is the proof step, and it is
also exactly the evidence the *next* install's pre-flight will demand.

**What to do:** this should not happen on a healthy host. Read the listed
violations. Common causes are a Group Policy that reapplies ACLs, an EDR agent
holding files, or a second install running concurrently.

### 3.5 Refusals on the prerequisite MSI

`-HttpPlatformHandlerMsi` over plaintext `http://` is refused outright. Every
source, local or HTTPS, requires `-HttpPlatformHandlerSha256`, because TLS
authenticates an origin, not an artifact. The input is copied/downloaded into a
fresh administrator-only staging directory, and that staged file's digest,
Authenticode signature, and publisher are checked before the absolute System32
`msiexec.exe` path opens it. The source pathname is never the execution path.

### 3.6 Refusals on install paths and source provenance

The three install roots accept ordinary absolute local drive paths only. UNC,
device/extended namespaces, ADS syntax, dot segments, reserved device names,
and components ending in a period or space are refused rather than normalized,
because these spellings can alias one filesystem object and collapse the
code/state ACL boundary. Existing ancestors are also resolved through the
kernel for junction and 8.3 aliases.

The installer source gate similarly refuses an unreadable/reparse input,
untrusted owner, unresolved writer, or any write-class ACE for a principal
outside the explicit administrator allowlist. Move the complete release tree
to an administrator-only local directory; do not loosen the check.

### 3.7 Refusals on the pinned dependency closure

A missing `deploy/requirements.lock.txt` or `deploy/build-requirements.lock.txt`
is fatal, and there is no unpinned fallback. Both are hash-pinned and installed
with `--require-hashes`. If they are missing you have an incomplete copy of the
repository; copy the whole thing rather than regenerating them on the RA host.

---

## 4. Migrating an install that predates the code/state split

Earlier versions put everything (interpreter, venv, database, logs, dotenv)
under `C:\ProgramData\acme-adcs-ra`. The new installer will **refuse** that
directory, because a tree from the old layout does not match the new shape.
This is the "refuse and instruct" path from §3.1, and it is intentional: the
old tree granted the gMSA Modify over executable content, so it is exactly the
state the split exists to end.

Migrate deliberately:

1. Stop the app pool and confirm the worker is gone.
2. Back up `C:\ProgramData\acme-adcs-ra` in full.
3. Copy `acme_ra.db` and `acme-ra.env` somewhere outside both trees.
4. **Read `acme-ra.env`.** Confirm the EAB kids and SAN scopes are the ones you
   configured and nothing else is present.
5. Delete or rename `C:\ProgramData\acme-adcs-ra`.
6. Run the installer. It creates both trees.
7. Stop the app pool again, copy `acme_ra.db` and `acme-ra.env` into the new
   `-InstallDir`, and re-run the installer so the ACLs and the proof cover
   them.
8. Update `web.config` if you had customised `processPath`. It now points at
   `<RuntimeDir>\current\venv\Scripts\python.exe`.
9. Start the pool and verify per §5.

The audit database carries the issuance and revocation trail. Do not start
fresh unless you genuinely have no history worth keeping: the audit is the
matching half of the revocation record.

---

## 5. Verifying an install

After the installer reports success:

```powershell
# The code tree: no gMSA write ACE anywhere.
icacls "C:\Program Files\acme-adcs-ra\current" /L
# Expect Administrators:(F) SYSTEM:(F) DOMAIN\gMSA$:(RX) and nothing else.

# The state tree: gMSA modify, dotenv read-only.
icacls "C:\ProgramData\acme-adcs-ra" /L
icacls "C:\ProgramData\acme-adcs-ra\acme-ra.env" /L
# Expect the dotenv to show DOMAIN\gMSA$:(R) -- NOT (M) or (F).

# Owners are the Administrators group, not an individual admin account.
Get-Acl "C:\Program Files\acme-adcs-ra\current" | Select-Object Owner

# The Negotiate stack imports under the runtime interpreter.
& "C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe" `
    -c "import spnego; import acme_adcs_ra.negotiate_auth"

# The ACME directory answers.
Invoke-RestMethod https://<hostname>/directory
```

Then finish the operator-owned configuration:

1. Fill the EAB credential and SAN scope in `acme-ra.env`, pinned to your ACME
   client. Use a high-entropy kid (UUID or ≥128-bit).
2. Set `ACME_RA_BASE_URL` and the `ACME_RA_ADCS_*` values in `web.config`.
3. Restrict the endpoint to the ACME client (`<ipSecurity>` or a firewall
   rule). This is a stated threat-model pilot condition, not a suggestion.
4. Decide the audit retention policy — see `operations.md`. The RA bounds
   attacker-driven growth but never deletes an audit row; pruning is yours.
5. Set `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with authenticated HTTPS HEC for
   production. The default JSONL sink lives on the host an attacker is assumed
   to control. Plain syslog remains an optional mirror but cannot satisfy this
   load-bearing requirement.

---

## 6. What stays yours, permanently

The installer will never do these, and no future version should:

- **The ADCS template ACL.** The gMSA's Enroll right on a
  server-authentication-only template is what bounds the blast radius of a
  total RA compromise. The RA cannot check it and must not be trusted to.
- **The network allowlist.** Every reachability assumption in the threat model
  depends on it.
- **The contents of `acme-ra.env`.** Which clients may enrol, and for which
  names.
- **Audit retention and archival.** The RA never deletes evidence.
- **Certificate lifecycle on the CA side**, including CRL publication.
