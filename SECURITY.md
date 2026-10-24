# Security policy

## About this tool

acme-adcs-ra is an **ACME Registration Authority** for Active Directory
Certificate Services. It speaks ACME (RFC 8555) on the front, holds **no
signing key**, and forwards CSRs to the existing ADCS issuing CA over the Web
Enrollment surface as a passwordless gMSA.

Unlike the sibling projects (cert-watch, adcs-lens), this tool is **in the
certificate-issuance path**. It mints real certificates and holds a standing
ADCS enrollment identity. Its worst case is mis-issuing a certificate or leaking
that identity, not a wrong report. The read-only and air-gapped conventions of
the siblings **do not apply here**. The hard rules in `AGENTS.md` replace them.

### What it can and cannot touch

- **It can:** request certificates from one template on the CA, as the
  enrollment gMSA. It reads and writes its own SQLite database and audit sinks.
  It fetches the CA's CRL when CRL evidence is configured.
- **It cannot:** sign anything (it holds no signing key), revoke at the CA (the
  enrollment gMSA has no CA-officer rights), or enroll for any other template
  once the template ACL is set as documented. The template ACL is the operator's
  to set and verify.
- **Revocation at the CA** is done by a separate scheduled script running as a
  different, template-scoped identity (or, in the weaker single-identity
  option, as the enrollment gMSA with template-scoped officer rights).

## Reporting a vulnerability

Found a security issue in acme-adcs-ra itself, for example a SAN-scope bypass,
an EAB forgery, a signing key introduced into the issuance path, or a
revocation compare-and-swap race that double-issues?

Report it **privately**, not as a public issue. Open a private vulnerability
report through GitHub
[Security Advisories](https://github.com/hraedon/acme-adcs-ra/security/advisories/new).
Private vulnerability reporting is enabled on that upstream repository.

Include the affected version, a reproduction, and the expected and actual
behavior. The upstream project is stable and passively maintained. Reports are
read and acknowledged on a best-effort basis, with no committed response time.

If you run a copy of this repository inside your own organisation, that link
reaches the upstream project, not your team. Not yet documented: your
organisation's internal reporting contact. Agree one and record it here.

## Scope

**In scope:** vulnerabilities in acme-adcs-ra code that cause mis-issuance (a
certificate with unauthorized SANs, a policy bypass, a signing key introduced),
a revocation race that double-issues, an EAB forgery or scope escalation, or a
crash that disrupts the issuance path.

**Out of scope, but welcome as regular issues:** ADCS CA misconfigurations
(operator-owned, documented in `docs/certsrv-setup.md`), and the behavior of the
ACME client (Certify the Web) or the ADCS CA itself.

## Security model summary

The full security model is in `docs/threat-model.md`. The load-bearing controls
are:

1. **No signing key, ever.** The RA never signs a certificate. An architecture
   test with positive and negative controls asserts no signing primitive is
   invoked in the issuance path.
2. **Passwordless to ADCS.** The RA authenticates as a gMSA via SPNEGO with
   channel binding (RFC 5929). No stored ADCS passwords.
3. **Server-authentication-only template.** One template, EKU scoped to
   server-auth only, subject and SAN from the CSR. This limits a compromise to
   spoofing TLS services, short of client-auth or PKINIT domain takeover.
4. **EAB, network allowlist and SAN scope.** The challenge is intentionally a
   no-op (enterprise trust model). EAB binds the ACME account to an
   enterprise-issued credential, the network allowlist limits who can reach the
   endpoint, and the SAN scope is the whole authorization surface.
5. **Post-issuance SAN verification (MED-1).** The issued cert's SANs are
   checked against the order's authorized set — a misconfigured template that
   appends an unauthorized SAN causes finalize to fail closed.
6. **Audit every issuance.** RA store + SIEM emission. No silent issuance.
7. **CA-side revocation is out-of-band.** The enrollment gMSA holds Enroll
   rights only, not CA-officer rights. Revocation at the CA is done by
   `scripts/Sync-Revocations.ps1` (scheduled, template-scoped officer identity)
   or by hand with `scripts/Revoke-Cert.ps1`, which keeps the standing identity
   least-privileged.

## Recorded decisions

Findings that independent reviews keep re-raising, with the disposition and the
reasoning, so the cycle can stop. These are **accepted postures**, not open
defects — but they are postures, so a reviewer who disagrees is arguing about a
decision rather than reporting a bug, and that is a useful thing to be clear
about.

### The `<ipSecurity>` allowlist ships commented out (accepted)

`deploy/iis/web.config` carries the `<ipSecurity>` block inside an XML comment,
and neither the installer nor startup requires an allowlist to exist. Raised
independently by the 2026-08-11 review and again by the 2026-08-17 Daybreak
review; the observation is accurate both times.

**Why it stays that way.** The correct addresses are per-deployment — the RA
cannot know the operator's ACME client addresses, and inventing a default would
be worse than the comment. `<ipSecurity>` also needs the *IP and Domain
Restrictions* role service, so a hard startup refusal would break first-install
and lab flows on a feature the operator may not have installed yet. The
allowlist is therefore documented as **required rather than recommended**, and
owned by the operator:

- `docs/operator-requirements.md` lists it as an operator responsibility and a
  stated pilot condition in the threat model;
- `docs/pre-pilot-checklist.md` requires it before pilot;
- `docs/operations.md` → *Network allowlist* carries the full snippet and the
  SNI-shared-443 caveat;
- the comment in `web.config` says in as many words that it is commented
  because the IPs are per-deployment, **not** because it is optional.

**Compensating controls in code**, so the allowlist is not the only thing
standing in front of an unauthenticated peer: an in-process token bucket applied
*before* the unauthenticated nonce write (default 20/s, burst 100, added
2026-08-11), and per-account order rate limiting (WI-016). These bound the
unauthenticated SQLite writer that made the allowlist load-bearing in the first
place. They do not replace it — a network allowlist keeps unknown peers away
from the endpoint entirely, which no in-app ceiling can do.

**What would change this.** Making the installer refuse without an allowlist is
a coherent proposal, and it is a change of posture rather than a defect fix. If
the deployment model narrows to "always installed by an operator who already has
the role service", that trade reverses. Until then: accepted, documented, and
operator-owned.
