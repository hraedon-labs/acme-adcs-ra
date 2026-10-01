# Threat Model — acme-adcs-ra

**Status:** post-WI-1 (enrollment proven on the lab 2026-06-20); WI-015 live
re-proof PASSED 2026-07-13 against the piloted commit. Living document —
re-review on any change to the issuance path, the gMSA, the template scope, or
the dependency set.

This is an ACME **Registration Authority** for ADCS. It mints real certificates
and holds a standing enrollment identity. Worst case is *mis-issuance* or *leak
of that identity* — not "wrong analysis." The read-only family conventions do
not apply.

> **✅ WI-1 CONFIRMED (2026-06-20) — the enrollment round-trip issues a real
> cert on the lab CA. Revocation still has no `/certsrv/` endpoint (by design —
> see below).**
>
> - **Enrollment (`CertsrvEnrollmentLeg`)** is **live-validated**: the deployed
>   RA (IIS app pool running as the gMSA) authenticates to `/certsrv/` over SPNEGO
>   **with channel binding** (`negotiate_auth.NegotiateAuth` over `pyspnego`, so
>   it works against EPA=Require), POSTs the CSR to `certfnsh.asp`, and gets back
>   a **serverAuth-only** cert (SAN from the CSR) issued off the existing CA and
>   **chaining to the existing root**, with requester = `gMSA-acme-ra$`. The leg
>   tolerates the CA's real response formats (`certnew.cer` returned as
>   `text/html`; `certnew.p7b` returned as PKCS7 wrapped in
>   `-----BEGIN CERTIFICATE-----` markers — see `docs/spike-runbook.md`).
> - **Revocation (`CertsrvRevocationLeg`)** is **out-of-band, operator-runbook'd
>   (WI-010, decided 2026-06-30).** ADCS Web Enrollment exposes **no revocation
>   endpoint** (Microsoft Learn enumerates only request-cert / retrieve-CA-cert /
>   retrieve-CRL; `magnuswatn/certsrv` has no `revoke()`; `acme2certifier`
>   returns "not supported"). A fictional `certrev.asp` form that appeared in one
>   draft was removed. The real mechanism is `certutil -revoke` or
>   `ICertAdmin2::RevokeCertificate`, which requires **CA-officer ("Manage CA")
>   rights**. To preserve least privilege the enrollment gMSA gains **no**
>   CA-officer rights; instead the RA's `revokeCert` records the revocation in
>   the RA store (cert → `revoked`, order → `revoked`, GET cert → 410 Gone) and
>   emits an honest audit event (`revocation_scope=ra-store-only`,
>   `ca_crl_updated=false`), and `scripts/Revoke-Cert.ps1` is the operator-run,
>   CA-officer credential that writes the CRL out-of-band. The server's
>   `revokeCert` endpoint remains wired to this leg via the `RevocationLeg`
>   protocol, so a future in-band mechanism (an explicit, recorded privilege
>   decision) can drop in without an ACME-surface change.
>
> Controls downstream of "ADCS issued a cert" (chain fetch, requester capture,
> audit fields) are now **live-verified**, not just unit-tested. WI-015 (the
> live re-proof) PASSED 2026-07-13; the enrollment physics is proven. The
> remaining per-deployment conditions are the §6 operator-owned items (host
> hardening, network allowlist) — in-app per-account rate limiting (WI-016),
> revocation reconciliation (WI-017), and the operational runbook (WI-011..014)
> all ship with the RA.

## 1. System & trust model

- **RA, not CA.** acme-adcs-ra holds **no signing key**. It terminates ACME
  (RFC 8555), authorizes the request, and forwards the CSR to the existing ADCS
  issuing CA via `/certsrv/` as a passwordless gMSA. The CA signs; the RA never
  does.
- **Enterprise trust, not public DV.** The gate is **EAB** (kid→MAC key, pinned
  to the authorized client) + **network allowlist** + **deterministic SAN-scope
  policy**. Domain-control challenges exist (RFC shape) but auto-satisfy under
  the enterprise-trust model — EAB is the *who-is-allowed* gate, not the
  challenge. **Any in-scope SAN can be issued without domain proof; the SAN
  scope is therefore the critical control.** Public DV is out of scope.
- **Blast-radius bound.** One **server-authentication-only** template; subject
  /SAN from the CSR; the gMSA holds Read+Enroll only. A compromise is bounded
  to **spoofing internal TLS services** — short of client-auth/PKINIT (domain
  takeover).
- **Pilot transport: Mode A only.** Web Enrollment on the CA itself; enrollment
  is local → no Kerberos constrained delegation. **Mode C** (separate enrollment
  host) introduces constrained delegation to `HOST/CA01`+`RPCSS/CA01` — a
  distinct threat class (misconfigured delegation → unconstrained; on-behalf-of
  surface) — and **requires a separate threat-model addendum** before use.
  Mode C2 (CES/WSTEP/SOAP) is documented only.

## 2. Assets

| Asset | Compromise impact |
|---|---|
| **gMSA enrollment identity** (`gMSA-acme-ra$`) | Enroll server-auth certs for any allowed SAN, for the lifetime of compromise. Highest-value asset. |
| **EAB MAC keys** (`RAConfig.eab_allowlist`, loaded from `.env`/env) | Rogue account creation within each kid's SAN scope. |
| **RA HTTPS server cert + private key** (IIS/uvicorn endpoint) | TLS termination; key compromise is its own incident (not the gMSA). |
| **SQLite DB file** (`acme_ra.db`) | Contains every issued cert PEM, every account JWK, the EAB kid map, the audit log. Loss = loss of the authoritative audit; theft = issuance history + account keys. |
| **`.env` / config** (EAB keys, SIEM HEC token, base_url) | Secrets at rest. |
| **SIEM JSONL sink** (`<db>.siem.jsonl`, next to the DB) | Emission log; same backup/perimeter as the DB. |
| **Reverse proxy / LB** (allowlist, TLS termination, `X-Forwarded-*`) | If misconfigured, the JWS URL binding and the source-IP allowlist are both wrong. |
| **Issued certificates** | Spoofable internal TLS identities. |

## 3. The cardinal invariant — no signing key, ever

The RA must never hold a CA/private signing key or sign a certificate. Enforced by:

- **Architecture test** (`tests/architecture/test_no_signing_key.py`): AST-scans
  `src/` for cert-minting primitives — `CertificateBuilder`, **any** `.sign()`
  call, pyOpenSSL, ctypes/marshal/pickle/runpy, `os.exec*`/`spawn*`, dynamic
  exec (`eval`/`exec`/`__import__`/`importlib.util`/`exec_module`), assignment-
  RHS aliasing (incl. tuple-unpack), wildcard imports, targeted `getattr`.
  **Scope:** catches *accidental* drift toward signing; **not** a defense
  against a determined adversary who controls the repo (that is code review +
  the gMSA/template scoping). The guard is paired with positive/negative
  controls so it cannot silently become a no-op.
- **Locked-dependency backstop** (`test_no_signing_dependencies.py`): asserts no
  signing-capable library (pyOpenSSL, asn1crypto, signxml) is declared in
  `pyproject.toml` or importable in the env. **Limitation:** name-level only —
  it does not pin versions or detect a backdoored `cryptography`. See supply
  chain (§3.1).
- The enrollment/revocation legs are **Protocols** with platform-gated real
  implementations; the RA only forwards CSRs.

### 3.1 Supply chain
- A **lockfile** (`uv.lock`) must be in use and committed for the pilot;
  dependencies reviewed for known vulns at pilot time.
- `cryptography`, `fastapi`, `pydantic`, `uvicorn` are on the issuance path
  (request parsing, settings); `requests` + `pyspnego` (SSPI via `sspilib`) are
  the win32 enrollment client — the in-tree `negotiate_auth.NegotiateAuth`
  replaced the single-maintainer `requests-negotiate-sspi`, which also broke on
  Python 3.14. **A CVE in any of these is a pilot-blocker.**
- Binary/native deps (SSPI, Kerberos) are pinned to a known-good version.

## 4. Adversaries → controls → residual risk

### A. Compromised RA host / gMSA  *(the load-bearing operational risk)*
- **Controls:** gMSA (no stored password); least-privilege Enroll-only on one
  server-auth template; **audit every issuance** (requester=`gMSA-acme-ra$` is
  visible in the ADCS CA database + the RA store + SIEM).
- **Host-hardening bar (non-negotiable pilot condition):** the RA host is
  tier-0-adjacent and must clear, at minimum, **all** of: no interactive logon
  except via PAW/jump box; Credential Guard on; LSA protection on; WDAC
  (application allow-listing) enforced; no browsing/general software; dedicated
  OU + dedicated service-account group; the gMSA installed on this host only;
  no other service running as the gMSA; LAPS-equivalent posture; network-
  segmented from the app servers it replaces. **If the host is not hardened
  beyond the app servers it replaces, the RA is merely a single high-value
  target and this control fails.**
- **Insider:** the RA host administrator is the most privileged insider for this
  control plane. Enforce **separation of duty**: the RA host admin is distinct
  from the CA host admin and from the EAB-allowlist custodian. gMSA key
  retrieval (adding the host to `PrincipalsAllowedToRetrieveManagedPassword`) is
  logged and alerted.
- **Residual:** the gMSA is a chokepoint **and** a target; this does not reduce
  to zero. Bounded by the server-auth-only EKU — no client-auth/PKINIT.
- **Admin surface (operator-owned):** maintenance endpoints under
  `/acme/admin/*` (nonce cleanup, expired-order sweep, stuck-`processing`
    reclaim) are gated by a single `admin_token` Bearer secret (`RAConfig`).
    The token is a high-value secret (a holder can reconcile a stuck order to
    `ready`, the one action that can enable a re-enroll) and MUST be rotated,
    ACL'd, and distributed with the same care as an EAB MAC key. The reclaim
    `ready` branch is the operator's double-issuance gate (confirm at the ADCS
    CA DB that no cert was issued first); the server cannot make that decision
    itself.

### B. Stolen/compromised EAB key
- **Controls:** EAB MAC verified **constant-time** (`hmac.compare_digest`); the
  binding must equal the account JWK (canonical compare, ignoring optional
  `alg`); the kid maps to a deterministic SAN scope; **failed account creation
  is audited** (`account-creation-denied`) to detect kid-space probing.
- **Kids must be high-entropy** (UUID / ≥128-bit random) — a kid guess is a
  meaningful probe event; operator-chosen, **not** a hostname or customer name.
- **Timing residual:** the unknown-kid path runs a dummy HMAC
  (`server._dummy_hmac`) so the known/unknown-kid wall-clock is comparable,
  closing the kid-*existence* timing side-channel. High-entropy kids remain the
  primary control (a kid guess is still a meaningful probe event that is
  audited as `account-creation-denied`).
- **Rotation:** a documented EAB rotation procedure (kid + MAC key + SAN scope)
  must exist before pilot.
- **Residual:** in-scope issuance is possible until the kid is rotated. Bounded
  by the SAN scope + server-auth EKU.

### C. Rogue ACME client (in/out-of-policy)
- **Out-of-policy SAN:** refused at `finalize` by deterministic `IssuancePolicy`
  (kid→SAN scope, case-insensitive per RFC 4343); audited as
  `finalize-policy-denied`. No issuance.
- **CSR hardening:** CSR signature verified; minimum key strength (RSA≥2048, EC
  P-256/384/521); **non-DNSName SANs rejected** (IPAddress/otherName/URI/
  RFC822Name/RegisteredID) — prevents scope expansion via SAN type. CSR
  identifiers must be ⊆ the order's identifiers (RFC). Subject Common Names
  must be one of those DNS SANs, closing the legacy-CN second identity path.
  CSR requests for `BasicConstraints CA=true`, `keyCertSign`, or `cRLSign`
  are rejected before they reach ADCS.
- **Post-issuance SAN verification (MED-1):** the policy above gates the
  *request*, but the ADCS template decides what SANs land on the cert. After
  enrollment the RA inspects the *result*: every DNS SAN on the issued cert
  must be ⊆ the order's requested SANs (same `rstrip('.').lower()`
  normalization as the policy, so a trailing-dot/case difference cannot cause a
  false rejection), and **no non-DNS SAN may be present at all**. A violation
  is fail-closed — 500 + `finalize-issued-cert-san-mismatch` audit, the cert is
  neither recorded nor served — catching a template that pulls SANs from AD or
  appends extras instead of taking them from the CSR.
- **Result binding and CA-capability rejection (2026-08-07 hardening):** the
  real `/certsrv/` response public key must equal the CSR public key, and every
  issued subject Common Name must remain within the requested DNS SAN set.
  Independently, the finalize path rejects an issued certificate with
  `BasicConstraints CA=true`, `keyCertSign`, or `cRLSign`. This keeps template
  drift from turning the server-auth enrollment identity into a subordinate-CA
  issuance path.
- **Residual:** none beyond the configured SAN scope (the intended policy).

### D. ACME protocol attacks (replay, cross-endpoint, IDOR, alg confusion)
- **JWS:** **full-URL binding** (RFC 8555 §6.4 — relative/cross-host URLs
  rejected); nonce consumed **before** the URL check (bad-URL probes burn the
  nonce); **exact RS256/384/512 or curve-matched ES256/384/512 only** for
  account keys, with RSA account keys ≥2048 bits; **HS-only** for EAB (no alg
  confusion / no "HS256 with the server's public key"); ES raw R‖S→DER
  validated. EAB JWS objects are bound to this RA's `newAccount` URL.
- **URL binding is computed from configuration, not from the request
  (2026-08-11).** `_verify_url` and the EAB `expected_url` both previously
  compared the protected-header `url` to `str(request.url)` — which is built
  from the client-supplied `Host` header (and, behind a proxy, from
  `X-Forwarded-Proto`). That only proved the client was self-consistent: with
  `Host:` set to another deployment's name, a JWS *and* an EAB minted for that
  deployment verified here, defeating the cross-endpoint replay control added on
  2026-08-07. The expected URL is now built from `base_url`, and `kid` must
  start with this RA's configured account-URL prefix. **Consequence for
  operators:** `ACME_RA_BASE_URL` is now load-bearing, not cosmetic — it must be
  the exact public origin clients use, or every request is refused (fail-closed).
  Note also that `forwarded_allow_ips` cannot distinguish a proxy from a client
  behind a same-host reverse proxy (the peer is always loopback), which is why
  no security decision may depend on forwarded headers.
- **Account eviction (2026-08-11).** `account.status` and the account's EAB kid
  are re-checked on **every** authenticated request. Previously `status` was
  never read and the kid was only re-checked inside `IssuancePolicy` at
  finalize, so pulling a kid from `eab_allowlist` — the operator's
  credential-revocation action — stopped issuance but left the account able to
  create orders, roll its key, and **revoke its own live certificates**. RFC 8555
  §7.3.6 deactivation is implemented as the client-side kill switch; removing
  the kid is the operator-side one. Both are audited
  (`account-deactivated`, `account-request-denied`).
- **CSRF / cross-protocol:** ACME POSTs are `application/jose+json` (RFC 8555
  §6.2; enforced since 2026-10-01 — anything else is 415 before the body is
  read or a nonce spent) and the body is a key-bound JWS signature. There is no browser-rendered
  surface; a same-origin attacker would still need the account key. CSRF is a
  non-issue *because* of JWS + EAB + the network allowlist — not because of a
  CSRF token.
- **IDOR (mutating endpoints):** every order/authz/finalize/revoke is scoped to
  the caller's account (kid→account from the JWS); cross-account → 404 (no leak).
- **Double-issuance:** atomic `ready`→`processing` CAS; a `processing` order is
  **never re-enrolled** (client told to poll via `Retry-After`); an existing
  cert is returned idempotently.
- **Proxy / Host-header footgun (deployment):** the JWS URL check compares the
  protected-header URL to `request.url`. **Behind a reverse proxy, uvicorn must
  run with `--proxy-headers` and `--forwarded-allow-ips` set to the proxy**, and
  `base_url` must be the *public* hostname — otherwise every legitimate JWS is
  rejected as a URL mismatch (fail-closed) on day 1. This is a deployment
  prerequisite, not optional.
- **Stuck-`processing` blast radius:** `processing_started_at` is recorded on
  the `ready`→`processing` CAS. *Auto*-recovery is intentionally absent for the
  no-cert case — blindly reverting an order to `ready` risks double-issuance if
  the CA accepted the first request and the RA crashed before recording the
  cert. Two reconciliation paths exist:
  - **Cert recorded, status flip missed** (crash window between
    `create_certificate` and the status flip): self-heals automatically.
    `finalize` detects the cert row and CAS-closes the loop to `valid`
    (`finalize-order-reconciled` audit); the admin `reclaim-processing`
    endpoint does the same. No re-enrollment, no operator judgment needed.
  - **No cert recorded** (enrollment did not visibly complete): operator
    reconciliation via the audited `POST /acme/admin/orders/{id}/reclaim-processing`
    endpoint (admin-token-gated), which CAS-reverts to `ready`. **Before this
    `ready` branch the operator MUST confirm from the ADCS CA database that no
    cert was issued for the order's ReqID** — this is the one operator action
    that can enable a re-enroll, and it is the operator's double-issuance gate,
    not the server's. No-op, lost-race, and not-found reclaim attempts are
    audited (`admin-order-reclaim-noop` / `-denied`) so a stolen admin token
    probing order IDs is visible to SIEM.
  The server's **automated** paths never double-issue (the `ready`→`processing`
  CAS is the guard); the reclaim `ready` branch is the one operator-enabled
  exception, gated by the documented CA-DB pre-condition **and by an enrollment
  lease** (2026-08-15 rescan). Every entry into `processing` mints a
  monotonically increasing `processing_generation`; the enrollment carries it and
  re-checks it against the store immediately before submitting to ADCS, and every
  transition *out* of `processing` is scoped to the generation its caller holds or
  observed. That closes the gap where an enrollment still queued behind a busy
  threadpool — already committed to `processing`, but invisible to the in-process
  registry — could be reclaimed out from under itself and then submit alongside
  the client's second finalize. A stale enrollment abandons before the CA call
  (`finalize-enrollment-abandoned`, `reason=processing-lease-lapsed`). The
  in-process registry now covers the whole in-flight interval (CAS, threadpool
  hand-off, ADCS calls, certificate recording), so the two guards are
  coextensive. Both the
  `EnrollmentDenied` revert and the success-path `processing`→`valid` flip
  are CAS-guarded so a concurrent reclaim or self-heal cannot be clobbered; a
  lost CAS race is audited (`finalize-enrollment-race` at ERROR + SIEM) and
  returns the order's current state without clobbering it. The success path
  re-checks for an existing cert before creating one, preventing orphaned
  duplicate cert rows. **Monitoring MUST alert on time-in-`processing` p99**
  (pilot condition); the audited `GET /acme/admin/orders?status=processing`
  endpoint surfaces stuck orders (minimal admin view — no SANs/cert URLs).

### D.1 Availability of the unauthenticated surface (2026-08-11)

- **`/acme/new-nonce` is unauthenticated and every call is a SQLite write.**
  SQLite has a single writer, so a nonce flood does not merely grow a table — it
  contends for the write lock with the issuance path, where a blocked write
  surfaces as a 500 once `busy_timeout` (5s) expires. The WI-016 limiter cannot
  help: it keys on an account that does not exist yet at nonce time.
- **Controls:** an in-process token bucket (`nonce_rate_limit_per_second`,
  default 20/s, burst 100) applied **before** the write, so a rejected request
  costs less than an accepted one; plus the network allowlist, which is the
  authoritative outer bound and a pilot condition.
- **Residual:** the bucket is per worker process. Under IIS/HttpPlatformHandler
  the RA is a single uvicorn process so one bucket sees all traffic; if that is
  ever scaled out, the effective ceiling multiplies by worker count. The proxy
  limit remains the real ceiling.
- **Audit durability:** the default `jsonl` sink writes next to the database, so
  a compromise of the RA host takes the audit table *and* its only mirror. Set
  `audit_offbox_required` in production — the RA then refuses to start unless
  the syslog or HEC sink is configured. There is no append-only or hash-chain
  protection on `audit_log` itself; off-box emission is the control.
- **Published surface:** FastAPI's `/docs`, `/redoc` and `/openapi.json` are
  disabled. They previously enumerated every `/acme/admin/*` route to any
  unauthenticated caller that could reach the RA.

### E. Revocation abuse
- **Confirming a CA-side revocation is a distinct authority (2026-08-13).** The
  WI-024 callback exists because the RA holds no CA rights and so cannot observe
  whether the CA actually revoked a serial. It previously accepted the general
  `admin_token` and wrote `revocation-ca-confirmed` on the caller's word alone,
  which made the audit trail assert an external security event the RA had not
  seen — and let any admin-token holder drop a **still-valid** certificate off
  the retry queue, suppressing the very retry that would have revoked it. Now:
  a dedicated `revocation_confirm_token` (the admin token is refused; unset ⇒
  endpoint disabled, fail closed); every confirmation labelled
  `verification="agent-asserted"` unless proven otherwise; and optional
  independent proof via the CA's **published CRL** — signed by the CA, readable
  without privilege, and the only check available to the RA that does not depend
  on the calling agent's honesty. The CRL signature is verified against the
  issuing CA certificate from the certificate's own stored chain, and an expired
  CRL is not evidence. `require_crl_evidence` makes proof mandatory.
  *Residual:* an attacker holding the **confirm** token can still assert falsely
  unless CRL evidence is required; the control is least privilege plus honest
  labelling, not elimination.
- **Mis-issued certificates are quarantined, not forgotten (2026-08-13).** The
  post-issuance verifiers (SAN, EKU, CA-capability) run *after* ADCS has issued,
  so a rejection leaves a real, trusted certificate in the CA database. The RA
  previously recorded nothing — not even the serial — so the certificate it had
  just refused to honour was unrevocable through the RA's own workflow. It is
  now written as a `quarantined` row (serial, ReqID, bytes, violations), the
  order goes terminal, and it enters the **same** CA-side revocation queue as
  any other pending serial. It is never served: `get_certificate_by_order`
  excludes quarantined rows so a retried finalize cannot pick it up, and the
  certificate response serves only `valid`.
- **Only the issuing account may revoke** its own cert (lookup scoped to
  `(serial, account_id)`); cross-account → 404 (no leak). Already-revoked →
  **200** (RFC §7.6 idempotent). Revoked certs are **not served** (GET → 410
  Gone); the order is flipped to `revoked`. **Reason 7 is rejected** (RFC 5280
  reason 7 is "unused" and `certutil` rejects it) — the valid set is
  `{0,1,2,3,4,5,6,8,9,10}`, consistent with `scripts/Revoke-Cert.ps1`, so an
  accepted reason can never silently break the out-of-band revocation loop.
  **Scope decision:** the RFC 8555 §7.6 *second* authorization path — a
  revokeCert JWS signed with the certificate's own key pair — is **not
  implemented**; revocation requires the issuing account's key. Certify the
  Web only ever uses the account-key path, and the operator out-of-band path
  (`Revoke-Cert.ps1` / the v1.5 automated loop) already covers revocation
  when the ACME account is unavailable (e.g. a stolen cert key). Adding a
  second crypto authorization path to a security endpoint for a client that
  never uses it would widen surface for no operational gain — recorded here
  as a deliberate non-goal, reversible if a future client needs it.
- **Cert-URL discoverability (narrowed 2026-08-11; plain GET removed 2026-08-15):**
  the cert URL remains in the order JSON after revocation (the URL is 128-bit
  unguessable); the *body* is 410. The plain, unauthenticated `GET /acme/cert/{id}`
  and `GET /acme/authz/{id}` forms leaked existence (**401 vs 410 vs 200**) and
  bypassed account deactivation and EAB-kid eviction. As of the 2026-08-15 review
  (finding 4) they are **removed entirely** — only the account-scoped
  `POST`-as-`GET` forms remain (RFC 8555 §6.3, §7.4.2), so no unauthenticated read
  path exists and the oracle is closed. A plain GET to either path now returns
  405.
- **Residual:** a compromised issuing account can revoke its own certs (denial
  of availability for that account's services). Bounded; audited.
- **CA-side revocation is out-of-band, operator-runbook'd (WI-010, decided
  2026-06-30).** The controls above are all **RA-store-level** (the RA marks
  the cert revoked and stops serving it). The passthrough to the ADCS CA
  database / CRL is **deliberately not wired in-band**: ADCS Web Enrollment
  exposes no revocation endpoint, and the real mechanism (`certutil -revoke`
  or `ICertAdmin2` COM) requires granting the caller **CA-officer ("Manage
  CA") rights** — which would let a compromised RA host revoke *any* cert on
  the CA, not just its own. That blast-radius increase was an **operator
  decision** and the decision is **out-of-band first-class** (preserve least
  privilege): the enrollment gMSA gains **no** CA-officer rights. Instead:

  - The RA's `revokeCert` endpoint records the revocation in the RA store
    (cert → `revoked`, order → `revoked`, GET cert → 410 Gone) and emits an
    honest audit event whose `details.revocation_scope` is `"ra-store-only"`
    and `details.ca_crl_updated` is `false` — the audit log never implies the
    CA CRL was written when it was not. The ACME response carries an
    `X-Acme-Ra-Out-Of-Band-Revocation` response header (non-normative).
    It moved out of the response body on 2026-08-24: a JSON body here is NOT
    ignored by standard ACME clients -- Certify the Web fails to parse it and
    reports a successful revocation as failed.
  - `scripts/Revoke-Cert.ps1` is the operator-run, CA-officer credential that
    performs the actual `certutil -revoke` against the CA and republishes the
    CRL, taking the serial or ReqID the RA already stores. It is run by a CA
    officer, **not** the gMSA, so the standing enrollment identity never gains
    CA-officer power. The RA audit log and this script's CA-database record
    (operator identity) are the matching halves of the revocation trail;
    keep both in incident review.

  A future in-band revocation capability (gMSA granted CA-officer rights and
  `certutil`/`ICertAdmin2` called from the RA) remains a **deferred, explicit
  privilege decision** — it would drop into the `RevocationLeg` protocol
  without changing the ACME surface, and only the `revocation_scope` metadata
  would change from `"ra-store-only"` to `"ca-crl"`. Until that decision is
  made and recorded here, `revokeCert` flips the RA store only — **the cert
  is still valid against the CA's CRL until the operator runs
  `Revoke-Cert.ps1`.**

- **Automated CA-side revocation (v1.5, WI-022/023/024/025).** v1.5 adds an
  **automated, template-bounded** CA-side revocation loop that closes the
  functional gap without widening the *enrollment* gMSA's rights. A separate
  **`gMSA-acme-revoker$`** identity — distinct from the enrollment gMSA — runs
  `scripts/Sync-Revocations.ps1` as a scheduled task on a utility host. The
  loop: `GET /acme/admin/revocations/pending` (WI-023) → `Revoke-Cert.ps1`
  (WI-022, with requester-check) → `POST /acme/admin/revocations/{serial}/confirm`
  (WI-024 callback, flips `ca_crl_updated=true` in the RA audit). The revoker
  is **not** the enrollment gMSA; the enrollment gMSA still holds no CA-officer
  rights.

  **Blast radius of `gMSA-acme-revoker$`:** the revoker's CA-officer rights are
  **template-scoped** via an `OfficerRights` callback ACE (Plan 004, proven live
  in WI-021): it can revoke certs issued under `ACME-ServerAuth` only. Revoking
  any other template yields `CERTSRV_E_RESTRICTEDOFFICER`. This bounds a
  compromised revoker to **denial-of-availability for the RA's own TLS certs** —
  the same blast radius as a compromised issuing account (which can already
  revoke its own certs via `revokeCert`). It cannot revoke DomainController,
  CAExchange, or any other template; it cannot issue certs; it cannot read
  private keys.

  **Two hard provisioning constraints** (violating either silently defeats the
  restriction or breaks it visibly):
  1. **Not a member of any broader certificate-manager group.** Officer rights
     are a union over the token — a broader-manager membership (e.g. Certificate
     Administrators) silently grants unrestricted revoke, defeating the
     `OfficerRights` ACE. The revoker must belong to no such group.
  2. **Member of `Certificate Service DCOM Access`.** Without this, `certutil
     -revoke` fails with `ERROR_INVALID_DATA` (0x8007000d) — a visible failure,
     not a silent bypass, but it breaks the automation.

  **Defense-in-depth layers:**
  - `Revoke-Cert.ps1` (WI-022) asserts `Request.RequesterName` matches the
    enrollment gMSA before revoking — the CA-side restriction is template-scoped,
    not requester-scoped (C2 in the validation matrix), so this check prevents
    the agent from revoking certs the RA did not issue even if they share the
    `ACME-ServerAuth` template.
  - The agent ships in **dry-run default** (`-Execute` required to arm); every
    auto-revoke lands in both the CA DB (under the revoker identity) and the RA
    audit (`revocation-ca-confirmed`, `ca_crl_updated=true`).
  - The loop is **one-directional** (RA→CA only). CA-initiated revocations
    (the reverse bucket) remain a human review item surfaced by
    `Reconcile-Revocation.ps1`.

- **serverAuth guarantee is now self-enforced (WI-026, v1.5).** The
  "blast radius bounded to spoofing internal TLS" property no longer rests
  solely on ADCS template config. `finalize.py::_issued_cert_eku_violations`
  inspects the issued cert's EKU and **rejects** any cert whose EKU is not
  exactly `{serverAuth}` (1.3.6.1.5.5.7.3.1) — absent EKU (all-purpose),
  `clientAuth`, `anyExtendedKeyUsage`, PKINIT, or any other OID all fail
  closed (audit `finalize-issued-cert-eku-mismatch` + `server_internal`, cert
  not recorded or served). A template that ever gained clientAuth/PKINIT would
  be caught at finalize, not silently passed through. The threat-model §E
  worst case (domain-takeover via clientAuth/PKINIT mis-issuance) is now
  bounded by the RA itself, not assumed from the CA config.

- **Single-identity deployment (explicit, recorded option — WI-033).**
  An opt-in variant in which the **same** gMSA used for enrollment
  (`gMSA-acme-ra$`) is also granted the template-scoped OfficerRights and
  runs `Sync-Revocations.ps1` on the RA host in `-LocalMode`. This collapses
  the two-identity design into one identity, one host, and one provisioning
  path.

  **What the scoping preserves (same as two-identity):**
  - **Template boundary.** OfficerRights still restricts revocation to the
    `ACME-ServerAuth` template only; revoking any other template yields
    `CERTSRV_E_RESTRICTEDOFFICER`.
  - **Requester boundary.** `Revoke-Cert.ps1` still asserts
    `Request.RequesterName` matches the enrollment gMSA. In single-identity
    mode this passes trivially — the revoker is the enrollment gMSA — but it
    continues to reject certs the RA did not issue (e.g., another principal's
    `ACME-ServerAuth` cert; validation-matrix C2).
  - **Dry-run default, audit on both sides, one-directional loop (RA→CA only).**
    Every auto-revoke is still CA-DB-recorded under the gMSA identity and
    confirmed back to the RA audit (`revocation-ca-confirmed`,
    `ca_crl_updated=true`).

  **What it loses (the honest trade-off):**
  - **Compromise independence.** In the two-identity design, stealing the
    enrollment credential grants issue-only; stealing the revoker grants
    revoke-only (template-bounded). In single-identity, one credential
    compromise grants **both**. This enables a **mint-and-swap attack**:
    revoke the legitimate cert, issue a spoof under the same SAN, and
    redirect traffic — a combined attack that no single compromise enables
    in the two-identity design.
  - **Co-residence with the internet-facing enrollment path.** In the
    two-identity design, the revoker is an isolated batch job on a utility
    host. In single-identity, any flaw in the ACME surface that lets an
    attacker act as the enrollment gMSA also lets them revoke.
  - **Audit granularity.** Issuance and revocation share the same CA-DB
    requester (`gMSA-acme-ra$`). The reconciliation cross-check
    (`Reconcile-Revocation.ps1`) matters more because the CA DB alone cannot
    distinguish issuance from revocation by identity.

  **The explicit decision requirement:** this is a *defensible but weaker*
  posture, chosen for operational simplicity (one identity to provision,
  rotate, and monitor; one host). It must be an **explicit, recorded operator
  decision**, not a default. This subsection is that record. The two-identity
  design remains the **recommended default** for any deployment where the
  additional gMSA is operationally feasible.

  **The two hard provisioning constraints still apply** (union semantics;
  DCOM access) — same as the two-identity design; see `docs/operations.md`.

  **CRL freshness vs. Manage-CA (the `-PublishCrl` trade-off).** By default the
  automated loop revokes the cert (recorded immediately in the CA DB) but does
  **not** republish the CRL — `certutil -CRL republish` requires the
  **Manage-CA** role, which the template-scoped officer identity deliberately
  does not hold, so the revocation appears at the next *scheduled* CRL
  publication. `Sync-Revocations.ps1 -PublishCrl` (and
  `Register-MaintenanceTasks.ps1 -PublishCrl`) can force an immediate republish,
  but only if the identity is granted Manage-CA. In **single-identity** that is
  especially dangerous: Manage-CA lets the identity edit CA configuration —
  including lifting its **own** `OfficerRights` restriction — which **collapses
  the escalation bound** described above (the restriction can no longer be
  trusted to survive a compromise). It is more defensible for the **dedicated
  two-identity revoker**, where a revoke-only account holding Manage-CA has a
  much narrower blast radius. Treat `-PublishCrl` as a second explicit, recorded
  decision on top of the single-identity choice; the least-privilege default
  (scheduled CRL) is recommended for both topologies.

### F. Audit / SIEM
- **Every** issuance, policy-denial, enrollment-failure, account creation
  (success **and** denied), and revocation is recorded in the RA SQLite store
  **unconditionally** — the store write cannot be skipped by a SIEM-hook
  exception (fail-open applies to *emission*, not to the local record).
- **SIEM startup probe:** jsonl writability verified at init; a broken sink →
  `enabled=False` + **ERROR** log; HEC/syslog config validated. HEC requires
  HTTPS and rejects embedded URL credentials so its bearer token cannot be
  sent in plaintext. Fail-open: a broken sink never aborts issuance.
- **Runtime SIEM failures log at WARNING, not ERROR.** Therefore: **the
  production monitoring stack MUST alert on the RA logger at WARNING+** (not
  ERROR-only) — this is a pilot condition, not a runbook footnote.
- **Secret handling:** the EAB MAC key is never logged (verified). Other
  secrets-at-rest: the `.env` (EAB keys, HEC token), the SQLite file, the SIEM
  JSONL — all must be ACL'd to the gMSA + backup operator only, encrypted at
  rest in backups. Audit `details` dicts are operator-validated for content
  (the real enrollment leg's stringified exceptions could carry ADCS error XML
  including the requester/template — review before pilot).
- **Residual:** the local SQLite is the authoritative audit — it must be on
  tamper-evident, backed-up storage (consider a write-once/append-only sink for
  `audit_log`).

### G. Resource exhaustion / DoS *(per-request caps + in-app per-account rate limit + expiry in code; raw-request rate-limiting operator/proxy)*
- **In-app per-account order rate limiting (WI-016):** order creation is
  capped per `kid` over a rolling window plus a global backstop, returning
  RFC 8555 `rateLimited` + `Retry-After`, with denials SIEM-audited as
  `order-rate-limited`. The count-and-create decision runs under one SQLite
  `BEGIN IMMEDIATE` transaction, so a parallel burst cannot race past the
  limit. This bounds order creation even if the deployment
  fronts the RA directly or the proxy rule is misconfigured. See the
  `### In-app rate limit (WI-016)` section of `docs/operations.md`.
- **Per-account / per-IP rate limiting** at the reverse proxy complements the
  in-app limit by bounding **raw request rate** (polls, challenge POSTs), which
  the in-app order limit does not cover. The ADCS `/certsrv/` leg is not
  high-performance — a flood here becomes a flood at the CA. See
  `docs/operations.md` ## Network allowlist and in-app rate limiting for
  copy-paste-ready snippets.
- **Caps in code:** `max_identifiers_per_order` (default 50, 1 identifier = 1
  authz), `max_csr_size_bytes` (default 8192), and the streaming pre-parse
  `max_jws_body_size_bytes` (default 65536) are enforced on the request path.
  Order/authz lifetime is bounded by `order_expiry_seconds` (default
  3600) and enforced at `finalize` (expired → `invalid` + audited as
  `finalize-expired-order`) and via the `DELETE /acme/admin/expired-orders`
  sweep for cron (RFC 8555 §7.1.6).
- **Caps still to add (operator):** audit-log / cert-table retention+archival;
  nonce-table size (GC is a probabilistic 1% cleanup on `create_nonce` as a
  safety net, bounded by `LIMIT 5000` and indexed on `created_at`, + the public
  `DELETE /acme/admin/nonces` for an external cron — wire the cron at pilot).
  Independent of both sweeps, the 30-minute nonce TTL is enforced **at consume
  time** (`consume_nonce` rejects an expired nonce even if GC never ran), so
  an unused nonce's replay window is bounded by TTL, not by cleanup cadence.
  `scripts/Register-MaintenanceTasks.ps1` (WI-013) ships the two scheduled
  tasks (nonce GC + expired-order sweep) ready-to-install; see
  `docs/operations.md` ## Scheduled maintenance tasks.
- **Residual:** a single in-scope EAB account can still amplify work O(n) per
  order up to the identifier cap, and grow the store up to the retention bound.

## 5. Platform & deployment controls (operator-owned)

- **Mode A** (pilot): Web Enrollment on the CA; local enrollment; no delegation.
- **gMSA:** passwordless; one host; Read+Enroll on one server-auth template.
- **Template (`ACME-ServerAuth`):** Server Authentication EKU **only**; subject
  in request; no manager approval (the RA is the gate); minimum key size ≤ CSR.
- **IIS `/certsrv/`:** HTTPS-only; Windows Auth enabled, Anonymous disabled;
  Negotiate preferred, **NTLM removed** once Kerberos is proven; **EPA=Require**
  (the RA channel-binds via `pyspnego`, so the hardened setting is supported —
  no need to weaken to Accept); IP-restricted to the RA host.
- **CA `/certsrv/` TLS cert + RA trust:** `/certsrv/` must present a **server-
  auth** TLS certificate — **not the CA's own certificate** (a CA cert used as a
  TLS leaf is rejected by OpenSSL/the RA as "unsuitable purpose"; SChannel
  tolerates it, so the misconfig hides until a non-Windows client connects). The
  RA verifies that cert against `ACME_RA_ADCS_CA_BUNDLE` = the **enterprise root**
  (Python verifies against certifi, not the Windows store, so the private root
  must be pinned; the server supplies the intermediate).
- **Reverse proxy:** network allowlist enforced here (the RA endpoint is not
  public); `--proxy-headers` + `--forwarded-allow-ips` on uvicorn; per-account
  rate limit. See `docs/operations.md` ## Network allowlist and reverse-proxy
  rate limiting.
- **CA renewal / chain rollover:** when the ADCS CA renews (`nRenewals`), the
  served chain changes and consumers (ADFS/Exchange) need the new root/OCSP.
  Coordinate with cert-watch; validate the chain the RA serves after any CA
  renewal.

> **Operational runbook:** `docs/operations.md` is the single reference for
> the operator-owned prerequisites the pre-pilot checklist names as blockers
> (EAB lifecycle, network allowlist / rate limiting, scheduled maintenance,
> admin token + reclaim, monitoring/SLOs, retention/archival, revocation
> runbook, backup/restore). It is a pilot condition that the runbook exists
> and is reviewed.

## 6. Conditions for a production pilot

1. **Spike confirmed (WI-1)** — **DONE 2026-06-20**: requester=`gMSA-acme-ra$`
   in the CA DB; cert chains to the existing root; serverAuth-only EKU; SAN from
   the CSR. The `CertsrvEnrollmentLeg` is live-validated against the lab CA.
2. **Template hardened** per §5; verified by inspection (adcs-lens can analyze
   the RA's own enrollment surface).
3. **gMSA host hardened** to the §4.A bar (tier-0-adjacent, auditable).
4. **Separation of duty** (§4.A insider): RA host admin ≠ CA host admin ≠ EAB
   custodian.
5. **NTLM removed** from `/certsrv/` providers; **EPA=Require** (channel-bound
   by the RA via `pyspnego`).
6. **Network allowlist** at the reverse proxy; uvicorn `--proxy-headers` +
   `--forwarded-allow-ips` configured (§4.D).
7. **Rate limiting + caps** (§4.G) in place at the proxy / code.
8. **SIEM sink** configured, startup-probed, and **monitored at WARNING+**.
9. **Operational runbook** documented and reviewed: backup/restore for the RA
   SQLite + `.env`; EAB key rotation procedure; monitoring/SLOs (request/error
   rate, time-in-`processing` p99, nonce-table size, SIEM delivery); **gMSA-
   suspected-compromise incident-response plan** (the §4.A worst case).
10. **Lockfile** committed; dependencies reviewed (§3.1).
11. **This threat model reviewed** by the operator; Mode C (if ever) gets its own
    addendum.
12. **Sanitization review** (`docs/publication-review.md`) before any public
    repo — real CA topology, hostnames, template names, kids stay in gitignored
    local config / `samples/`.

## 7. Known gaps & residuals (tracked, not resolved)

- **Enrollment HTTP path — CLOSED (WI-1 confirmed 2026-06-20):** the leg issues
  a real cert off the lab CA (requester, chain, serverAuth EKU verified). The
  live findings — channel binding (`pyspnego`) for EPA=Require, `certnew.cer`
  served as `text/html`, `certnew.p7b` as PKCS7-in-CERTIFICATE-markers — are
  folded into the leg and `docs/spike-runbook.md`. Kept here only as a pointer.
- **Revocation is out-of-band, operator-runbook'd (WI-010)** — CLOSED for
  the RA-store half: `revokeCert` records the revocation in the RA store
  (cert → `revoked`, order → `revoked`, GET cert → 410 Gone) and emits an
  honest audit event (`revocation_scope=ra-store-only`, `ca_crl_updated=false`).
  The CA-CRL write is **deliberately out-of-band**: `scripts/Revoke-Cert.ps1`
  is the operator-run, CA-officer credential that runs `certutil -revoke` and
  republishes the CRL, taking the serial/ReqID the RA stores. The enrollment
  gMSA gains no CA-officer rights (decision recorded 2026-06-30; see §4.E).
  A future in-band revocation capability remains a deferred, explicit
  privilege decision. **Pilot condition: the on-call runbook must reference
  `Revoke-Cert.ps1` and the operator must confirm the CRL republished after
  each revocation** (the RA audit cannot see the CA side).
- **Stuck-`processing` orders** have no *auto*-recovery for the no-cert case
  (intentional — blindly reverting risks double-issuance). `processing_started_at`
  is recorded. Two reconciliation paths: (a) **cert recorded, status flip
  missed** self-heals — `finalize` and the admin reclaim endpoint both CAS-close
  the loop to `valid` (`finalize-order-reconciled` / `admin-order-reclaimed`),
  no re-enrollment; (b) **no cert recorded** — operator reconciliation via the
  audited `POST /acme/admin/orders/{id}/reclaim-processing` (admin-token-gated;
  CAS revert to `ready`; no-op / lost-race / not-found are audited). **Pilot
  condition: monitor time-in-`processing`** and alert; before the `ready` branch
  the operator MUST confirm from the ADCS CA DB that no cert was issued.
- **`EnrollmentDenied` vs `EnrollmentTransportError` are wired through
  finalize** — CLOSED. Transport errors return 503+`Retry-After` (order stays
  `processing`, client polls); CA policy denials CAS-revert the order to
  `ready` and return 400 (`rejectedIdentifier`); both emit distinct audit
  categories. The revert is CAS-guarded (`transition_processing_to_ready`) so
  a concurrent reclaim or self-heal cannot be clobbered; a lost CAS race
  returns the current state and is audited.
- **Success-path `processing`→`valid` is CAS-guarded** — CLOSED. The
  non-atomic `update_order_status` was replaced with
  `transition_processing_to_valid` (CAS on `status = 'processing'`). A lost
  race is audited as `finalize-enrollment-race` (ERROR + SIEM) and the
  success path re-checks for an existing cert before creating one, preventing
  orphaned duplicate cert rows.
- **EAB kid-existence timing side-channel** (§4.B) — CLOSED: the unknown-kid
  path runs a dummy HMAC (`server._dummy_hmac`) before returning, equalising
  the known/unknown-kid timing. Residual: high-entropy kids remain the primary
  control.
- **Per-request DoS caps are in code** (§4.G) — CLOSED:
  `max_identifiers_per_order` + `max_csr_size_bytes` + the streaming
  `max_jws_body_size_bytes` limit are enforced on the request path. Still
  operator: proxy rate-limiting and retention/archival.
- **Order expiry is enforced** (RFC 8555 §7.1.6) — CLOSED: an expired
  pending/ready order cannot be finalized (flipped to `invalid` + audited as
  `finalize-expired-order`) and expired pending/ready orders are swept by
  `DELETE /acme/admin/expired-orders` for cron. (Processing/valid/revoked
  orders are left alone — they are terminal or operator-reconcilable.)
- **Enterprise-trust shortcut:** in-scope SANs issue without domain proof; the
  SAN scope is the critical control (not a bug — the model).

## 8. Out of scope

- Becoming a CA / holding a signing key (**cardinal non-goal**).
- Public-DV trust model.
- CES/WSTEP (Mode C2) transport — documented only.
- Auto-recovery of a stuck `processing` order (near-term follow-up, §7).
- **Account deactivation** (RFC 8555 §7.3.6, `POST status=deactivated`). The
  account lifecycle here is EAB rotation (kid + MAC key + SAN scope) plus
  `keyChange` key rollover; a self-service deactivate endpoint adds surface no
  chartered client uses. Reversible if a future client needs it.
- **In-band** CA-side revocation (CRL write from the RA) — deferred behind an
  explicit, recorded privilege decision to grant the gMSA CA-officer rights
  (§4.E). The out-of-band path (`scripts/Revoke-Cert.ps1`, operator-run) is
  the shipped mechanism; the in-band path would drop into the `RevocationLeg`
  protocol without an ACME-surface change.
