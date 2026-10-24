# Architecture & security model

The design spine. The ACME server, the enrollment leg and the policy all derive
from the decisions here.

## The RA model (why no intermediate, no signing key)

acme-adcs-ra is a **Registration Authority**, not a CA. It authenticates and
authorizes certificate requests, then **forwards the CSR to the existing ADCS
issuing CA**, which signs with its existing key and chain. The RA holds no
signing key. Consequences:

- **No new intermediate / no parallel trust.** Certs come off the chain already
  distributed to every domain-joined machine.
- **The blast radius of compromising the RA is bounded by its enrollment
  rights**, not by possession of a CA key. That is why the template scope (below)
  is the load-bearing control.

## Component flow

```
Certify the Web ──ACME (RFC 8555)──▶ acme-adcs-ra ──/certsrv/ POST (Negotiate)──▶ ADCS CA ──▶ cert
        │                  EAB-gated         │  runs as gMSA (passwordless)            signs
        └──────────────── returns the ADCS-issued cert + existing chain ◀────────────────────┘
```

## ACME server responsibilities (RFC 8555 subset)

The minimum to serve an enterprise client:
- `directory`, `newNonce`, `newAccount` (JWS account-key verification) **with EAB**,
  `newOrder`, authorizations + challenge handling, `finalize` (accept the CSR),
  `certificate` retrieval, `revokeCert`, `keyChange`.
- **Resource reads (added 2026-08-11).** Account-scoped `POST`-as-`GET`
  (RFC 8555 §6.3, empty-string payload) serves the order (`/acme/order/{id}` —
  the `Location` newOrder returns and the URL a conforming client polls), the
  account (`/acme/acct/{id}`), the account's order list, the authorization and
  the certificate. Account deactivation (§7.3.6) is a `status` change POSTed to
  the account URL. Certificate and authorization retrieval are account-scoped
  `POST`-as-`GET` only. The former unauthenticated `GET` routes were removed so
  a captured URL cannot bypass account deactivation or EAB-kid eviction.
- **URL binding is against configuration.** Every JWS, and the EAB binding,
  must name the URL derived from the configured `base_url`, never the URL the
  request happened to arrive on. `base_url` is therefore load-bearing security
  configuration, not a display value.
- Trust model is **enterprise identity, not public domain control**. EAB binds
  the ACME account to an enterprise-issued credential; the network allowlist
  bounds who can reach the endpoint. (Challenge handling still runs per the RFC;
  EAB is the *who-is-allowed* gate, not the challenge.) An account is usable
  only while its `status` is `valid` **and** its EAB kid is still in the
  allowlist. Both are re-checked on every authenticated request, so pulling a
  kid is a complete eviction rather than an issuance-only block.
- Each EAB kid has a lifetime durable-account quota (default: one). The store
  counts all account rows, including deactivated accounts, and performs the
  count, account insert, and `account-created` audit insert under one
  `BEGIN IMMEDIATE` transaction. Deactivation therefore never frees a slot,
  and concurrent distinct JWK requests cannot exceed the configured quota.

## Enrollment leg (RA → ADCS)

- Submit the CSR to `/certsrv/certfnsh.asp` with **SPNEGO/Negotiate + channel
  binding** (RFC 5929 `tls-server-end-point`, via the in-tree
  `negotiate_auth.NegotiateAuth` over `pyspnego`), authenticated as the service's
  ambient **gMSA** identity, with no stored password. Channel binding is what
  lets it work against `/certsrv/` hardened with **EPA=Require** (the secure
  setting).
- The **certificate template** governs validity, EKU, key rules, and subject
  handling. The RA does not set validity; the template does.
- **Reference implementation (read, do not depend on):** acme2certifier's
  `mscertsrv` CA handler in `auth_method=gssapi` mode is a working model of this
  exact call. We reuse the *approach*, not the package.
- Transport modes A and C differ only in *where* `/certsrv/` lives and whether
  Kerberos delegation is required — see `certsrv-setup.md`. The ACME server side
  is identical across modes.
- **Redirects are refused outright.** `requests` strips the `Authorization`
  header when a redirect crosses hosts, but that protection does not reach this
  path. `NegotiateAuth` sets no static header; it registers a *response hook*
  that fires on any 401 and mints a fresh Kerberos token. A redirect to a host
  answering `401 Negotiate` would therefore draw a freshly minted gMSA ticket
  out of the RA, channel-bound to the real CA's certificate and so relayable.
  Nothing in `/certsrv/` legitimately redirects, since every URL is built from
  the configured host, so refusing costs nothing. It is enforced in the session
  factory rather than per call site.
- **The CA call runs on a worker thread.** The finalize handler is `async def`,
  which FastAPI runs on the event loop rather than in its threadpool, so a
  synchronous multi-second CA round-trip inline would stall every other request
  in the process. The supported deployment is a single process, so nothing else
  absorbs it.
- **An enrollment holds a lease over its order, not just a mark.**
  - The `ready`→`processing` CAS mints a monotonically increasing
    `processing_generation` on the order row.
  - The route holds the in-process `ActiveEnrollments` mark across the CAS, the
    threadpool hand-off, the CA calls and the certificate recording.
  - The worker re-checks the generation against the store immediately before it
    submits.

  The mark is the fast, authoritative answer for the reclaim endpoint. The
  lease is the durable one, and it is what stops an enrollment that sat
  *queued* (committed to `processing`, doing no visible work) from submitting
  after a reclaim reopened its order. Both are needed: the mark alone is process
  memory over an interval it did not cover, and the lease alone would let a
  reclaim proceed and merely fail the loser late. See
  `docs/security-review-2026-08-15-rescan.md`.
- **Single-backend CBT assumption (WI-006):** the channel-binding token is
  derived from a side-channel TLS probe of the `/certsrv/` host. This is correct
  for Mode A (one CA host) and single-host Mode C. If `/certsrv/` is fronted by
  **NLB/ARR** with multiple backends, the probe and the enrollment connection may
  see different certificates, so EPA=Require rejects the channel-bound token
  (fail-closed). Multi-backend topologies are unsupported without reworking the
  CBT derivation — see `negotiate_auth.NegotiateAuth`.

## Security model

- **Server-authentication-only template, subject/SAN from the CSR.** Scoping the
  EKU to server-auth bounds a compromise to spoofing internal TLS services and
  keeps it short of client-auth / PKINIT (domain takeover). SAN-supply on a
  server-auth-only template is a categorically smaller risk than on an
  any-purpose or client-auth template.
- **One hardened gMSA chokepoint.** ADFS/Exchange need SAN certs, so *something*
  must hold SAN-capable enrollment. Concentrating it in one audited,
  single-purpose, tier-0-adjacent identity reduces attack surface compared with
  distributing the right to every app server, and yields a complete,
  monitorable issuance record. **Condition:** the RA host/identity must be
  hardened *beyond* the app servers it replaces, or it is merely a single
  high-value target.
- **The RA's gMSA + template is itself an ESC surface.** adcs-lens would analyze
  it. Keep Enroll rights minimal and the template free of requester-supplied
  client-auth EKUs.
- **Gating:** EAB credential pinned to the authorized ACME client (Certify the
  Web) + network/IP allowlist at the reverse proxy.

## Certificate lifecycle states

A certificate row in the RA store is in exactly one of three states. The
distinction is load-bearing, not bookkeeping:

| State | Meaning | Served to a client? |
|---|---|---|
| `valid` | Issued by the CA and honoured by the RA | Yes |
| `revoked` | A client asked for it back | No — `410 Gone` |
| `quarantined` | The CA issued it; a post-issuance verifier rejected it | **Never** |

**Quarantine exists because rejection happens too late to prevent issuance.** By
the time the SAN, EKU, and CA-capability verifiers run, ADCS has already signed:
the certificate has a serial, sits in the CA database, and is trusted
domain-wide. Before v1.9 the RA recorded nothing, which left a live certificate
it had just refused to honour with no serial anywhere in its own records, and
therefore invisible to its revocation workflow.

**The same window opens on failure, not just on rejection.** `certfnsh.asp`
returns an "issued" disposition with a ReqID *before* the RA fetches the leaf,
fetches the PKCS#7 chain, and checks that the chain binds to the leaf. A failure
in any of those steps is equally a live certificate at the CA, so it quarantines
by the same route. Where the failure came before the leaf arrived, there are no
bytes to store (the store keys on them). The ReqID is then made loud in the
audit row and the log instead, and the operator revokes by ReqID at the CA by
hand. That asymmetry is deliberate: it is better to be explicit that the RA
cannot clean this one up itself than to record a row it cannot act on.

A quarantined row is recorded with its serial, ReqID, bytes, and the violations.
Its order goes terminal-`invalid` so a retried finalize cannot reach a serve
path. It is **queued for CA-side revocation through the ordinary pull-agent
loop** rather than a bespoke mechanism. "Never served" is enforced in the
response builder itself, not left to each caller to remember.

## Audit model

Every issuance is recorded in **two independent places**: the RA's own SQLite
store (request, account, SANs, template, outcome) and the **ADCS CA database**
(with requester = the gMSA). The RA **emits** each issuance to SIEM, reusing
cert-watch's export pattern, which satisfies "an audit trail for every cert."

Three properties make that claim hold rather than merely state it:

- **The certificate row and its audit row commit in one transaction.** They used
  to be independent commits, so a fault between them could leave a stored,
  serveable certificate with zero `certificate-issued` events — precisely the
  silent issuance the rule exists to prevent. SIEM fan-out happens *after* the
  commit and stays fail-open: the durable record is the local row.
- **The off-box requirement asserts the constructed emitter, not the configured
  sink name.** An emitter that disabled itself (empty syslog host, an unusable
  HEC URL or token) previously let the app start while the operator believed the
  off-box gate was satisfied, and the only evidence lived on the host an attacker
  is assumed to control. The RA now refuses to start.
- **The in-memory delivery queue is bounded.** A slow or unreachable HEC
  endpoint could otherwise let unauthenticated, request-driven audit events
  accumulate without limit on an issuance-path host. Overflow drops from the HEC
  sink only, never from the audit table, and is counted and logged.

## Trusting a CA-side revocation

The RA holds no CA rights, so it cannot ask the CA "did you revoke this?". The
pull agent runs `certutil -revoke` and then tells the RA it succeeded. Two
things keep that from being a bare act of faith:

- **Separated authority.** Confirming a revocation asserts an external security
  event the RA did not observe, so it takes a dedicated credential
  (`ACME_RA_REVOCATION_CONFIRM_TOKEN`) and **refuses the general admin token**.
  While the two were shared, any admin-token holder could drop a still-valid
  certificate off the retry queue and leave a success audit behind. An unset
  confirm token disables the endpoint rather than falling back.
- **Optional independent evidence.** A CRL is published by the CA, signed by the
  CA's own key, and readable without privilege. It is the one check available to
  the RA that does not rest on the calling agent's honesty. With
  `ACME_RA_REVOCATION_CONFIRM_CRL_URL` set, the RA verifies the CRL's signature
  against the issuing CA certificate **taken from the certificate's own stored
  chain**, and records `verification: "crl-verified"` or `"agent-asserted"`
  accordingly. The audit trail never implies the RA saw more than it did.

  Two properties make that check mean what it says:
  - **Freshness is verified separately from the signature**, because a signed
    CRL verifies for ever. `nextUpdate` must be present and future, and
    `thisUpdate` must not be future. An absolute age ceiling provides a
    configurable publication-liveness bound independently of `nextUpdate`, which
    the CA chooses. Replay detection uses the per-CA monotonic CRL watermark; its
    comparison is independent of the age threshold.
  - **The issuer is selected by signature, not by name.** A CA key renewal keeps
    the subject DN and changes the key, so name-matching picks the wrong
    generation from a chain holding both.

- **Publication is reported separately from revocation.** `ca_crl_updated` means
  the CA revoked; `crl_published` means the CRL was actually republished. On the
  default least-privilege path the officer *cannot* republish (that needs
  Manage-CA), so the normal case is revoked-but-not-yet-published, during which
  relying parties still accept the certificate. Collapsing the two would let a
  field named `ca_crl_updated` imply a publication that was deliberately
  skipped.

## Credentials

EAB MAC keys and the admin/confirm tokens are validated at config load, which is
the only place that sees them before they become load-bearing. MAC keys must be
valid base64url decoding to ≥ 32 bytes; tokens must be ≥ 32 characters. These
floors accept everything `scripts/eab.py` generates and reject hand-typed values.
A MAC key decoding to *zero* bytes was previously treated as a present key,
which let anyone who knew the kid forge the binding with an empty HMAC key. That
was an authentication bypass, not merely a weak credential.

## Deliberate deviation from the family

The read-only / air-gapped / flag-don't-probe conventions that govern cert-watch
and adcs-lens **do not apply**: this system writes to the world (it causes
issuance) and holds a standing identity. The compensating disciplines are the
hard rules in `AGENTS.md`: no signing key, deterministic policy, passwordless,
least-privilege template, audit-everything.
