# Pre-pilot checklist

`acme-adcs-ra` is **issuance-path infrastructure** — its worst case is
mis-issuance or leak of a standing ADCS enrollment identity. The read-only
family's "worst case it's wrong" margin does not apply. This checklist gates a
deployment from "the code works" to "responsible to run." Nothing here is
optional for a pilot; items are owned by the operator unless marked otherwise.

Derived from `docs/threat-model.md` (the §-references point back to it). Keep it
honest: check a box only when the thing is actually true, not when it's planned.

## A. Code / artifact integrity (engineering)

> **Engineering status at v1.10.0 (2026-08-24).** The three boxes below are
> satisfied for the released artifact; they stay unticked because they are
> *per-deployment* gates — whoever deploys the pilot re-checks them against the
> commit they actually ship. Read the caveat on the third one.

- [ ] **Working tree committed.** Never deploy issuance infra from an uncommitted
      tree — it breaks the provenance story the tool exists to provide.
      *(v1.10.0: `main` clean and tagged at `229574d`.)*
- [ ] **CI green on the deployed commit.** Linux gates (ruff, mypy --strict,
      pytest, pip-audit) pass on the exact commit being deployed, on a remote
      runner — not just locally. See `.github/workflows/ci.yml`.
      *(v1.10.0: all six jobs green on `59fba73` — the 3.12/3.13/3.14 matrix,
      both Pester engines including Windows PowerShell 5.1, pip-audit and the
      identifier gate — on both the push and `pull_request` runs. This gate
      earned its place on the first push of the series: a test that passed on
      the 3.12 dev venv failed on 3.13/3.14, the versions the lab host and the
      shipped deployment actually run.)*
- [ ] **Live re-issue against current `main`.** The post-WI-001..005 finalize
      decomposition and CAS-guarded transitions landed *after* the 2026-06-20
      live proof and are validated by unit tests only. Re-run a real end-to-end
      issue on the lab against the current commit before pilot. **The proven
      artifact and the shipped artifact must be the same commit.**
      *(v1.10.0 caveat, stated rather than glossed: the live proof ran on
      `f6badc9`; the tag is `59fba73`. The delta is the version string plus
      documentation — no `src/` or `scripts/` change — so it is not the same
      commit and this box is not claimed. A pilot deployer who wants the
      literal guarantee should re-run §A issuance against the tag.)*
- [ ] **Live-only checks accumulated by the scan series.** Each of these is
      unit-tested as far as it can be on a Linux dev host and genuinely unproven
      against a real CA/host. They are cheap to fold into the next live
      re-proof, and two of them decide whether a *revocation* proceeds:
  - [x] **`Test-SerialRevokedAtCa` (2026-08-17 F4) — PROVEN LIVE 2026-08-17.**
        A disposition-21/reason-8 row was correctly detected and the
        both-20-and-21 self-check did not fire. Original text follows.
        **`Test-SerialRevokedAtCa` (2026-08-17 F4).** `certutil -view -restrict
        "SerialNumber=<s>,Disposition=21"` is assumed to select only revoked
        rows. Confirm against the lab CA that a revoked serial matches and an
        issued one does not — and that the self-check (serial appearing under
        both 20 and 21) does not fire. Fails safe either way, so a mismatch
        means "no worse than before", not "broken".
  - [x] **End-to-end confirmation retry (2026-08-17 F4) — PROVEN LIVE, twice
        on 2026-08-23.** Admin-token-only revoked at the CA but was refused on
        the confirm endpoint (exit 2); confirm-token-only then recovered the
        already-revoked row and drained the queue (exit 0). Original text
        follows.
        **End-to-end confirmation retry (2026-08-17 F4).** Revoke at the CA,
        make the RA callback fail (block it / stop the pool), then re-run
        `Sync-Revocations.ps1 -Execute` and confirm it reports
        `already-revoked-at-CA`, reaches the confirm POST, and drains the
        pending set. This is the whole point of exit 6, and only a live run
        exercises the wiring.
  - [x] **Installer MSI verification (2026-08-17 F1) — PROVEN LIVE 2026-08-24,
        after five rounds owed.** Run against the **released `v1.10.0` tarball**
        on a second Windows Server host, with the handler deliberately
        uninstalled so the MSI branch became reachable (the RA host's own
        installed handler is what had made this untestable). All four cases
        against the real Microsoft MSI:
        - `http://` URL → refused before any download, handler absent;
        - `https://` with **no** digest → refused, handler absent;
        - `https://` with a well-formed but **wrong** digest → the MSI *was*
          downloaded into protected staging, hashed there, and rejected on
          value — `msiexec` never opened it, handler absent. This is the
          staged-copy refusal, live;
        - correct digest → Authenticode verified against
          `CN=Microsoft Corporation` (the `Get-AuthenticodeSignature` call no
          unit test can reach), installed, handler present.

        Host restored and verified against a pre-test snapshot: same handler
        version, module re-registered, sites and pools running, every
        installer-created directory removed. Original text follows.
        **Installer MSI verification (2026-08-17 F1).** With a real
        HttpPlatformHandler MSI: correct `-HttpPlatformHandlerSha256` installs;
        a wrong digest aborts before `msiexec`; an `http://` URL is refused.
        The decision functions are unit-tested, the `Get-FileHash` /
        `Get-AuthenticodeSignature` calls around them are not.
  - [x] **POST-as-GET-only RA (2026-08-15 F4) — FULLY CLOSED 2026-08-24.**
        The 405s were proven live 2026-08-23 (§G 5/5, and again in the 9-check
        CRL/POST-as-GET pass). **The Certify the Web half is now proven too**,
        which no lab phase could cover because it needs the real client.

        Certify the Web 7.1.1.0 (ACME stack `Certify.ACME.Anvil` 3.3.3) drove a
        full issuance against the RA from a separate domain host. Server-side
        audit: `account-created` (EAB accepted) → `order-created` →
        `challenge-validated` → `certificate-issued`. The **IIS log is the
        direct evidence** that it never used the removed GET forms:

        ```
        POST /acme/authz/<id>     200
        POST /acme/order/<id>     200
        POST /acme/finalize/<id>  200
        POST /acme/cert/<id>      200   <- certificate retrieval
        ```

        Every retrieval verb is a POST, all 200, **zero 405s**. So the removed
        GET forms are not a client-compatibility problem and there is nothing
        to file against CtW.

        Two client-side notes, neither a product issue: CtW's pre-flight
        "check the challenge URL is accessible" fails (the name has no DNS
        record and the RA needs no challenge responder — it auto-validates on
        EAB + network + SAN scope), and CtW **proceeds anyway**, so the
        pre-check does not need disabling. Separately, storing the issued
        certificate failed with "Access is denied" when its service runs as a
        non-administrator gMSA — a Windows permission matter on the client
        host, unrelated to the RA. Original text follows.
        **POST-as-GET-only RA (2026-08-15 F4).** Plain `GET /acme/cert/{id}`
        and `/acme/authz/{id}` now return 405. Prove Certify the Web renews
        against it; any breakage is a CtW bug to file, not a reason to restore
        the forms.

## B. ADCS enrollment leg (the gMSA chokepoint — §4.A)

- [ ] **gMSA installed on the host**: `Test-ADServiceAccount` returns `True`.
      (AES Kerberos-etype + group-membership gotchas are on record if it fails.)
- [ ] **Template is server-authentication-only** (no client-auth/PKINIT EKU) and
      its ACL grants **Enroll to the gMSA only** — verified with
      `scripts/Verify-TemplateEnrollment.ps1` (confirms a normal user cannot
      request it). This EKU scope is what bounds a compromise to TLS-service
      spoofing.
- [ ] **`/certsrv/` reachable** in the chosen transport mode (A or C per
      `docs/certsrv-setup.md`); EPA posture matches the channel-binding client.

## C. ACME front gating (§4.B, §5)

- [ ] **EAB enabled and pinned** to the authorized Certify-the-Web client(s).
      Kids are high-entropy (UUID / ≥128-bit), **not** hostnames/customer names.
- [ ] **EAB MAC keys placed in `acme-ra.env` by hand** (never committed, never on
      a command line); file readable only by the gMSA + Administrators. Use
      `scripts/eab.py` to mint a high-entropy kid + MAC key (stdout-only; see
      `docs/operations.md` ## EAB lifecycle).
- [ ] **Documented EAB rotation procedure exists** (kid + MAC key + SAN scope)
      *before* pilot — threat-model §B calls this a precondition. Runbook:
      `docs/operations.md` ## EAB lifecycle (mint + rotate via
      `scripts/eab.py`).
- [ ] **Network allowlist in place.** The installer deliberately does **not**
      restrict the endpoint. Add `<ipSecurity>` (IP and Domain Restrictions role
      service) or a scoped firewall rule to the Certify-the-Web host. Do **not**
      blanket-firewall 443 if it is SNI-shared with cert-watch/gpo-lens. Snippet
      + caveats: `docs/operations.md` ## Network allowlist and reverse-proxy
      rate limiting.
- [ ] **`base_url` is the exact public origin (scheme + host + any port).** It is
      the **authority** for the JWS and EAB URL bindings as of 2026-08-11, not a
      display value: a JWS or EAB signed against any other URL is refused, and a
      mismatch fail-closes every legitimate request on day 1 (§4.D).
- [ ] **EAB credentials are per-deployment.** Because the EAB binding now pins to
      this RA's `newAccount` URL, a kid+MAC pair shared with a test/staging RA no
      longer verifies here — but sharing one is still a credential-hygiene
      failure. Mint separate kids per environment.
- [ ] **Account eviction path understood.** Removing a kid from `eab_allowlist`
      now evicts every account created under it *completely* (orders, key
      rollover, and revocation), not just issuance. Clients can also self-disable
      via RFC 8555 §7.3.6 deactivation. Both are audited.

## D. Admin surface (§4.A, §4.D)

- [ ] **`admin_token` set, high-entropy, ACL'd, and rotatable** — treat it like an
      EAB MAC key. A holder can reconcile a stuck order to `ready`, the one
      action that can enable a re-enroll. Runbook: `docs/operations.md` ##
      Admin token and reclaim runbook.
- [ ] **Reclaim runbook understood:** before using the reclaim→`ready` branch the
      operator MUST confirm at the ADCS CA database that no cert was issued for
      the order's ReqID. The server cannot make that double-issuance call itself.
      Runbook: `docs/operations.md` ## Admin token and reclaim runbook.

## E. Operations / DoS / observability (§4.G, §6)

- [ ] **Reverse-proxy rate limiting** per-account / per-IP (complements the
      in-app per-account order limit from WI-016, which bounds order creation
      but not raw request rate; a proxy flood still reaches the CA). Snippets +
      tuning guidance: `docs/operations.md` ## Network allowlist and in-app
      rate limiting.
- [ ] **Crons wired:** `DELETE /acme/admin/nonces` (nonce GC) and
      `DELETE /acme/admin/expired-orders` (order sweep, RFC 8555 §7.1.6).
      Install via `scripts/Register-MaintenanceTasks.ps1` (WI-013); see
      `docs/operations.md` ## Scheduled maintenance tasks.
- [ ] **Monitoring alerts on time-in-`processing` p99** (pilot condition);
      `GET /acme/admin/orders?status=processing` surfaces stuck orders. SLOs +
      alerting guidance: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **SIEM alerts on `finalize-enrollment-abandoned`.** A stale enrollment
      abandoned before the CA call because its order was reclaimed while it was
      still queued. Nothing was issued — but it means ordinary queueing is
      crossing the reclaim age floor, which is the schedule the double-issuance
      finding needed. Investigate enrollment latency, not the reclaim.
      Background: `docs/security-review-2026-08-15-rescan.md`.
- [ ] **Audit leaves the box — REQUIRED, not "consider" (§4.D.1).** The default
      `jsonl` sink writes next to the database, so a compromise of the RA host —
      the adversary §4.A calls load-bearing — destroys the audit table *and* its
      only mirror. Set `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with an
      authenticated HTTPS HEC sink; the RA then refuses to start with local
      JSONL or unauthenticated plaintext syslog as its load-bearing trail. A
      write-once/append-only destination on the SIEM side remains desirable.
      SIEM delivery monitoring: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **If HEC is not available, the syslog trade is recorded and accepted.**
      `ACME_RA_AUDIT_OFFBOX_ALLOW_UNAUTHENTICATED_SYSLOG=true` lets TCP syslog
      satisfy the requirement. Tick this box only if someone with the authority
      to accept it has: the collector is unauthenticated and the trail is
      readable and forgeable in transit. Prefer fixing the transport. UDP is
      refused regardless. Confirm the `UNAUTHENTICATED OFF-BOX AUDIT` startup
      warning is visible in whatever reads the RA's logs — it fires on every
      start by design.
- [ ] **Nonce ceiling reviewed.** `/acme/new-nonce` is unauthenticated and each
      call is a SQLite write; the in-app token bucket
      (`nonce_rate_limit_per_second`, default 20/s burst 100) bounds it before
      the write. Confirm the default is comfortably above real client volume and
      that the network allowlist above is actually in place — the bucket is
      defence in depth, not a substitute for it.
- [ ] **Retention/archival** for `audit_log` and the cert table decided. Guidance:
      `docs/operations.md` ## Retention and archival.

## F. Known limitation to accept with eyes open

- [ ] **CA-side revocation is out-of-band, operator-run (WI-010, §4.E).**
      `revokeCert` records the revocation in the RA store only (cert → revoked,
      order → revoked, GET cert → 410 Gone) — it does **not** write the CA CRL.
      The audit event honestly records `revocation_scope=ra-store-only`,
      `ca_crl_updated=false`; the ACME response surfaces an
      `X-Acme-Ra-Out-Of-Band-Revocation` header. The operator closes the loop by running
      `scripts/Revoke-Cert.ps1` (a CA officer, **not** the gMSA) which runs
      `certutil -revoke` and republishes the CRL. The enrollment gMSA gains no
      CA-officer rights (the project's tightest security tenet). Confirm the
      on-call runbook references `Revoke-Cert.ps1` and that the operator
      verifies the CRL republished after each revocation before pilot. Runbook:
      `docs/operations.md` ## Revocation runbook. **Reason 7 is rejected** by
      both the RA and `Revoke-Cert.ps1` (RFC 5280 "unused"; `certutil` rejects
      it) so an accepted reason can never silently break the out-of-band loop.
- [ ] **CRL evidence freshness is configured from your own CDP's observed
      served age.** Before enabling
      `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE`, run
      `scripts/sample_crl_age.py` against your CDP across at least one complete
      publication cycle — you must see the CRL Number turn over — and keep the
      failed fetches, which are part of the distribution. Then set
      `ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS` strictly inside the band:

      > **above** the maximum age your CDP serves, with margin for a late
      > publication, or the ceiling refuses healthy evidence;
      > **below** the published window (`nextUpdate − thisUpdate`), or the
      > ceiling sits behind the CRL's own expiry and never fires first.

      The application default is **626400** (7d 6h), which is the value measured
      on the lab's weekly CA on 2026-09-05: served age at most 603654s (bounded
      above by 605454s), window 649200s, so it clears the floor by ~5h49m and
      the roof by ~6h20m. **That number is what one observation period supports
      for a 1-week `CRLPeriod` with ADCS's computed 12h overlap — it is not a
      universal bound, and a CA with a different cadence or overlap has a
      different band, possibly an empty one.** Measure before you copy it.

      Do **not** derive the floor from the window: that substitution is what
      produced four wrong derivations and two published numbers that were both
      outside the band (`649800` above the roof, `604800` inside the
      uncertainty on the floor). See `docs/operations.md` → *Deriving the
      ceiling (WI-052)*. Preserve the samples outside the lab restore scope —
      a teardown that restores to a pre-run fingerprint destroys exactly this
      class of evidence.

- [ ] **Monotonic CRL evidence is left enabled, and its baseline is understood.**
      `ACME_RA_REVOCATION_CONFIRM_CRL_REQUIRE_MONOTONIC` defaults to `true`.
      When CRL evidence is configured, it refuses evidence older than the
      newest CRL already acted on for that issuing CA, independently of the
      age ceiling's calibration. It does not establish that a first-seen CRL
      is the newest document available: the first confirmation after deployment
      or a CA key rollover has no prior watermark to compare against.
      Document the recovery procedure before deployment. If a CA restore
      produces a CRL Number below the stored watermark, confirmations remain
      deferred until an operator resolves the regression; do not automatically
      clear the watermark when a number goes backwards. An RA database restore
      also restores its watermark, so reconcile the evidence gap before
      resuming confirmations. If CDP replicas serve different vintages, use
      the sampler's regression report to assess replica lag; it is evidence
      about observed regressions, not a prediction of the exact confirmation
      failure rate. See `docs/operations.md` → *Monotonic CRL evidence*.
      **Proven live 2026-09-05** against two genuine CA-signed CRLs, including
      a negative control (the same serial and the same older CRL are accepted
      with `REQUIRE_MONOTONIC=false`, so the refusal is attributable to the
      watermark and nothing else) and persistence across an app-pool recycle.

---

When every box above is checked, the deployment has cleared the bar this tool is
engineered to. Until then it has not — regardless of a green local test run.

---

## Validation log

- **2026-09-05 (second session) — `8f1685e` (the PR #16 merge commit): the
  §A.2 independent-client record COMPLETED, and the MSI refusals cleared after
  six rounds.** Deployed over the running v1.12.0. Note the version string is
  **not** a deploy discriminator — `pyproject` still declares 1.12.0 because the
  watermark is unreleased — so the deploy was confirmed by content:
  `issued_certificate_validation.py` present *and*
  `DEFAULT_CRL_MAX_AGE_SECONDS=626400`.

  **Merge commit behaves as the branch did: A 14/14, A1 13/13, CRL 7/7.**

  **§A.2, the item that blocked a tag — COMPLETE.** Certify the Web **7.2.0.0**
  (`Certify.ACME.Anvil/3.3.4.0`, .NET 10.0.11) from a separate domain host, a
  newer client than August's 7.1.1.0/3.3.3. Issuance, renewal, retrieval and
  revocation, on a dedicated EAB kid so the record separates from the harness.

  - **POST-as-GET-only is proven twice, on two independent orders.** Issuance:
    16 POST / 19 HEAD / 3 GET, the GETs being `/` and `/directory` only.
    Renewal: 15 POST / 18 HEAD and **zero GET of any kind**. `STATUS-405-COUNT=0`
    and `ACME-RESOURCE-GET-COUNT=0` throughout. The removed GET forms are not a
    client-compatibility problem; nothing to file against CtW.
  - The renewal reused the account (proven two ways: `NEW-ACCT-COUNT=0` in the
    IIS log *and* identical `account_id` in the store) and is a real second
    issuance, not a cached replay (different order, serial, key and fingerprint;
    the CA recorded two distinct request IDs, 761 and 762).
  - **Revocation is where the step earned its place.** The client reported
    success, the RA returned an empty 200, the store said `revoked` — and the CA
    said `Disposition: 0x14 (20) Issued`, revocation date EMPTY. Three layers
    agreed and the authoritative one disagreed. Designed behaviour (the
    enrollment gMSA holds no officer rights; the audit row says
    `revocation_scope="ra-store-only"` rather than overclaiming), and exactly
    why §A.2 forbids treating the client's success as evidence. The CA query
    carried a control so `0 Rows` could not pass for "not revoked".
  - CA-side revocation and publication driven separately and verified **from the
    CDP**, not from `certutil`'s exit code: CRL 129 → 130, target serial listed,
    with a negative control (the un-revoked issuance cert, absent) and a positive
    control (an arbitrary existing entry, found).
  - Queue confirmation returned `verification: crl-verified`; pending went
    **5 → 6 → 5**, evidenced from the RA's own audit log. The **monotonic
    watermark's first-use baseline was taken live** (`crl_watermark_verdict:
    "first"`, CRL 130) — the earlier 12/12 proof used a stand-in serving captured
    CRLs. The two CRL config toggles this required were removed immediately after
    and verified absent.
  - **Not covered, recorded as unproven:** the CA-side revoke was performed by a
    CA local administrator, not by a template-scoped revoker gMSA running
    `Sync-Revocations.ps1`. The §B compromise-independence bound was not
    exercised; `OfficerRights` was deliberately not provisioned (hand-built blobs
    are known to be rejected by this CA and to break all officer operations until
    removed). The confirmation *code path* is proven, being the same endpoint the
    scheduled task calls.

  **MSI no-digest and staged-copy refusals — PROVEN LIVE, clearing a six-round
  debt.** Two facts unblocked it. A second Windows Server 2025 host in the
  estate (the one running the independent ACME client) has the handler absent
  both ways, so `Test-HttpPlatformHandler` is false; and
  **`Install-Prerequisites` runs at line 785, before Python discovery and the
  venv build**, so the refusals throw long before an interpreter is needed — that
  host has no Python and it did not matter. Roots pointed at throwaway paths.
  All three refusals fired: `http://` (InstallVerifyLib:147), **no digest**
  (InstallVerifyLib:152), and the **staged-copy** mismatch
  (install-windows:482) against the genuine Microsoft MSI (Authenticode Valid,
  `CN=Microsoft Corporation`) with one nibble changed in the digest. The reported
  `got` value is the hash of the *staged copy*, so the artifact was copied into
  protected staging and hashed there before rejection. **`msiexec` never opened
  it — proven, not inferred:** handler still absent, zero `MsiInstaller` events
  since a pre-run mark, **with a control showing three such events do exist in
  that log**. Host restored; post-state diffs identical to pre-state (the one
  mutation, `Web-IP-Security`, removed; `RestartNeeded=No`). The 2026-08-24
  clearance was against the v1.10.0 tarball and the installer has changed three
  times since, so this debt was real rather than bookkeeping.

  **NEW FINDING, filed as UNFILED item 26.** One certificate was revoked and the
  CRL gained 31 entries. The other 30 were the *previous* session's teardown
  revocations, sitting unpublished for ~5.5 hours because §E says to revoke and
  restore but never says to republish. Earlier validation-log entries assert
  "revoked … and the CRL republished" — a claim at least one round did not
  satisfy. On a 1-week `CRLPeriod` the exposure approaches a week.

  **Teardown.** Post-run store preserved *before* the restore
  (`POSTRUN-PRESERVED {"audit_log": 752, "certificates": 16, "orders": 45}`,
  `postrun-store-20260905-015115`). All three certificates this session caused
  the CA to issue were revoked **from the CA-side query**, republished, and
  `STILL-ISSUED=0` cross-checked against a control returning 3 rows; the CDP was
  re-fetched to confirm CRL 131 lists all three (applying item 26's own fix).
  Store restored fingerprint-identical table-by-table including
  `crl_watermark: 0`; throwaway EAB, admin/confirm tokens and both CRL toggles
  verified gone; pool Started as found.

  **Deviation, flagged deliberately:** the lab is left on **`8f1685e`**, not on
  the released `v1.12.0`, contrary to the usual "leave the lab on the released
  tag" convention. `8f1685e` is `main`, is now the most-proven build, and is the
  intended next tag. Roll back if the lab is to be parked on a release.

  **Not run:** hosted CI on this commit; the §B two-identity topology; the
  fourth MSI case (correct digest → install), deliberately, since only the
  refusals were owed and it would have left the handler on a host with no use
  for it.

- **2026-09-05 — review of `610a5a3` and full live re-proof, run by Opus 5
  against a change authored by another agent.** Same split as 2026-08-27: the
  reviewer did not write the change.

  **Candidate installed over the deployed v1.12.0 after a baseline control run
  (A+A1 27/27 on the released build), then every phase re-run: 72/74.** Real
  certificates off the lab issuing CA throughout — A 14/14 (serverAuth-only EKU, SAN
  from CSR, 3-cert chain to the existing root), A1 13/13, G 5/5, K 12/12,
  L 9/9, Lqueue 8/8. **Two failures, both explained, both left visible:**

  - `CRL3` — asserts `window <= ceiling`, which is the superseded rule: it fails
    unless the ceiling is set to a value that can never bind. Detecting the real
    miscalibration with an assertion that demands it be made worse. The harness
    assertion is replaced (expiry, configured age and monotonicity are now three
    separate checks, mirroring `tests/test_crl_max_age_calibration.py`).
  - `Ld1` — four orders left in `processing`, all four carrying
    `finalize-enrollment-transport-failed`: the documented operator-reconcilable
    residue from connects that burned before the block was lifted. Ld2–Ld5 pass,
    which is the substantive property: the stale worker abandoned on a lapsed
    generation, exactly one certificate for the contested order, no duplicates
    anywhere.

  **The extraction in `610a5a3` does not change issuance behaviour** — verified
  by AST comparison of every extracted body against `325eeff` before the lab
  ran, and by A/A1 passing identically on both builds.

  **The monotonic CRL watermark is proven live, 12/12 — the proof owed since
  2026-08-27.** No archived CRL existed, so CRL 128 was captured from the CDP
  and the CA was made to publish 129: two genuine, still-unexpired,
  differently-numbered documents both listing the target serial. Newer CRL
  confirms and advances the watermark; the older one is refused with audit
  `reason_code: crl-evidence-regressed`; the refusal survives an app-pool
  recycle; and — the check that makes the rest mean anything — **the same serial
  with the same CRL 128 is accepted when `REQUIRE_MONOTONIC=false`**, so the
  refusal is attributable to the watermark and not to freshness, chain or
  parsing. Advisory mode does not walk the watermark backwards.

  **WI-052 settled by measurement, and the ceiling corrected** — see the §F
  checklist item and `operations.md`. 399 samples over 8.3 days covering one
  complete publication cycle; default moved 604800 → **626400**.

  **Harness defect found, and it bounds what earlier rounds can claim.**
  `lease-pass-fw.sh`'s `block()` emitted the RA's IPv6 address into a PowerShell
  array literal unquoted, so the wrapper died with a parser error, created no
  firewall rule, and — because the function never checked ssh's exit code —
  reported success. Only the reachability gate caught it, correctly refusing to
  measure. `samples/` is gitignored, so **there is no record of whether the
  2026-08-27 Lqueue/Ldrain results came from this driver or from a manual
  invocation with correct quoting; that entry's claims are neither confirmed nor
  retracted here.** What is claimed is narrower and demonstrated: on 2026-09-05
  the block was verified dropping on both address families before either phase
  ran. Fixed by quoting the elements and making a failed block fatal; the
  semantics are recorded in the runbook so a fresh checkout re-applies them.

  **New finding — transport orphans have no issuer material (UNFILED item 25).**
  A certificate orphaned by a failed *chain* fetch is stored with its leaf but
  no chain, so CRL evidence has no issuing CA certificate to verify against and
  the confirmation is refused permanently under `require_crl_evidence=true`.
  Not worked around: see the item. *(The first draft of that item generalised
  this to "quarantined certificates" and proposed reusing the `/certsrv/` TLS
  bundle as issuer material; both were wrong and are corrected there.
  Certificate identity is present — the missing thing is issuer material, and
  the RA's own store already holds it.)*

  **Teardown verified, not asserted:** post-run store preserved before restore
  (904 audit rows, carrying the first `crl-verified` confirmations and
  `crl-evidence-regressed` refusals this project has ever kept), store restored
  to the pre-run fingerprint exactly, all 29 session certificates revoked with
  `STILL-ISSUED=0` cross-checked at the CA, firewall rule count 0, v1.12.0
  reinstalled over the candidate, throwaway EAB removed, both hosts as-found.
  The manually forced CRL 129 publication is recorded in the sampler's evidence
  README so the 128→129 transition is not later read as cadence.

  **Follow-up run, same day, on the ceiling correction itself.** The default
  change and the rewritten `CRL` phase were deployed and re-run rather than
  reasoned about: **A 14/14, CRL 7/7**. Issuance is unaffected by the new
  ceiling, `CRL3` now asserts that the ceiling *binds* (`626400 < 649200`,
  margin 22800s) instead of the superseded inverse, and `CRL5`/`CRL6`/`CRL7`
  provoke the configured age bound, expiry and monotonicity one at a time with
  the other two satisfied — so a refusal can be attributed to the bound that
  produced it. `Ld1` is untouched and stays a visible failure: its assertion is
  correct and the recovery behaviour behind it has not changed.

  **Not run:** hosted CI at the time of writing (identifier gate, `pip-audit`
  and the 3.13 matrix leg are all CI-only, and the local gate skips without the
  repo secret — it was a manual grep of the diff that caught a real CA CN in a
  draft of this very entry); the §A.2 independent-client record that this same
  change added to the runbook; the MSI no-digest/staged-copy refusals, still
  owed.

- **2026-08-27 — full hazard-scoped validation of `a60768d` (PRs #9/#10/#11),
  run by GLM against a brief written by the agent that authored four of the
  five changes.** That split was deliberate: on this project, fixes get found
  defective by whoever did not write them.

  **PHASE L IS GREEN, for the first time, and item 11's "flapping lab fabric"
  is RETRACTED.** §L 9/9, Lqueue 8/8, Ldrain 4/5 (Ld1 = the documented §9
  caveat from a manual gap; Ld2–Ld5 pass: stale worker abandoned on a lapsed
  generation, one certificate, no double issuance).

  **Rule zero — prove the instrument before the phenomenon — paid for itself
  twice, and both defects were in the NEW instruments.** `reachprobe.ps1`'s
  parameterless `TcpClient` binds AF_INET on .NET Framework, so every IPv6
  target read as an instant `refused` (and the "dead AAAA" assumed by earlier
  rounds is alive — the CA holds a ULA); `ca-inbound-block.ps1` reported
  through the success stream, so `-Mode show` printed nothing and the `-Mode
  on` postcheck compared an array and could never fire. Both fixed live. See
  UNFILED item 21 — the second is the same defect class as the 2026-08-14
  wave-3 F1 finding.

  **Hazard results.** CRLF: `lib_digest` STALE×5/exit 1 → `--write` ×5/exit 0 →
  sizes and CRLF counts identical (514→514, `lf_only=0` everywhere), pins
  re-verify, an entry point runs past the digest gate. Off-box ack: 6/6 matrix
  with exact refusal markers, plus the real-pool halves — ack in force → pool
  starts, `UNAUTHENTICATED OFF-BOX AUDIT` in the real stdout log, collector
  receives `offbox_transport=syslog-unauthenticated`; no ack → fails closed,
  zero collector receipts. Spike enrollment: gMSA/`NegotiateAuth`/EPA=Require
  accepted, **ReqID 671, disposition 20**, cert verified serverAuth-only with
  SAN from CSR — with a finding, item 19. Audit volume: the idle trio wrote
  **+0 rows across a ~10-recycle session** (last wrote 08-25), the 4 new
  pending-revocations rows carried real serials with live coalesce counters,
  27 new `certificate-issued`.

  **Regression in the record:** WI-052's shipped `626400` recommendation is
  **superseded — use `≥ 649800`**. The floor is the measured published window
  (649200s) plus one `ClockSkewMinutes` (600s), because a CRL is *current* for
  its whole window and the oldest still-valid CRL the RA can be handed is one
  full window old. `626400` is 6h30m below that and fails CRL3 with zero
  margin. Since 649800 exceeds the window, the independent age ceiling is
  **non-binding** on this cadence — a real trade, and a weaker control than
  designed, but strictly better than leaving CRL evidence off. §F and
  `operations.md` corrected; UNFILED item 20.

  *(An earlier revision of this entry said "no safe value exists" and advised
  leaving `REQUIRE_CRL_EVIDENCE` at `false`. Both were wrong: 649800 is safe,
  it is merely non-binding, and the feature should be enabled at that value.)*

  *(The supersession itself was disputed hours later — UNFILED item 24: the
  649800 floor derives from the published *window*, but false refusals are
  governed by the maximum age an honest CDP *serves*, and the overlap
  separates those by 44400s on this CA — with the old 626400 sitting in the
  gap. ≥ 649800 is held as the **interim** value, not a settled answer: it
  cannot false-fail on either reading, and `scripts/sample_crl_age.py` is
  measuring the served age (two publication cycles needed). Do not re-derive
  on paper. See the §F item above and `operations.md` → *Deriving the
  ceiling*.)*

  *(**SETTLED 2026-09-05 by the sampler: item 24 was right and this entry's
  supersession was wrong.** Measured served age at most 603654s against a
  649200s window, so the band is `(605454, 649200)` and `626400` — the value
  this entry superseded — sits inside it with ~5h49m and ~6h20m of margin.
  `649800` is above the window and can never fire before `nextUpdate`. The
  application default is now 626400. Nothing above is edited, because the shape
  of the error is the useful part of the record: every wrong number here came
  from taking the floor off a document instead of off a measurement.)*

  **Teardown verified, not asserted:** revert-before-revoke honoured, 26/26
  revoked by OID with 0 still Issued **cross-checked against queries known to
  return rows**, fingerprint-identical store restore, firewall rule count 0,
  mock-collector cert untrusted, both hosts as-found.

  **Not run:** the MSI no-digest/staged-copy refusals — still owed.

- **2026-08-25 security-fix branch `security-fix-7808046` — live validation
  EXECUTED, tip `3c599ca` (base `7808046` = v1.12.0, live-proven at
  `5580519`).** Preflight: local gates 960 pytest + 1 skip, 482 Pester + 4
  platform skips, ruff, mypy; the branch's pinned InstallVerifyLib digest was
  independently recomputed and matches the committed file. **CI has not run on
  this commit** (local branch, not pushed) — local gates are the proxy, said
  plainly.

  **Standard pass: §A 14/14 (twice — the second run under load-bearing HEC,
  below), §A1 13/13, CRL+§G 9/10, §K 12/12, both transport-orphan branches
  6/6 each, §R 6/6 ×3, Rverify 3/3 ×3, §D least privilege, authority split,
  CRL-evidence cycle.** The one FAIL is CRL3, the designed WI-052 calibration
  check (unchanged operator finding). Least privilege: gMSA token succeeds,
  CRL publication denied `0x80070005`, out-of-template revocation
  `CERTSRV_E_RESTRICTEDOFFICER`, reason 8 refused pre-CA (exit 3). Authority
  split: admin-token-only → exit 2; confirm-token-only → exit 0. CRL
  evidence: `crl-evidence-required-but-absent` → admin republish →
  `crl-verified`.

  **This delta's own fixes proven live on Windows PowerShell 5.1 through the
  real call sites, not just unit tests:**

  1. **HEC-only `audit_offbox_required`.** Config layer, one fresh process
     per case on the deployed interpreter, 7/7: syslog/TCP and syslog/UDP
     refused, `http://` HEC URL refused, embedded-credentials URL refused,
     empty token refused, valid HTTPS+token accepted, syslog still allowed
     when the requirement is false. Live app cycle against a localhost mock
     collector (TLS-1.3-verified, throwaway self-signed cert imported to
     `LocalMachine\Root` and removed at teardown): startup probe delivered
     with the `Authorization: Splunk` header; a full §A under
     `audit_offbox_required=true` delivered `order-created` and
     `certificate-issued` off-box (14/14 again); collector killed → pool
     recycle → the RA refuses to serve (`/directory` fails; no worker);
     collector restored → recycle → 200 with a second probe event.
  2. **Replayable admin audit growth bounded by the global key.** 8/8 live:
     15 reclaim probes against 15 different nonexistent order ids wrote
     exactly ONE durable row (`denial_count` 15, attacker id kept only as a
     bounded `sample_order_id`, structured `order_id` empty); 15 list-orders
     polls with varying filters wrote one row; a real-order reclaim kept its
     own `noop` row WITH order-id attribution (distinct reasons stay
     distinct); a further in-window probe folded (count 16).
  3. **Pinned-digest InstallVerifyLib loading.** RA host, admin-only tree so
     only the digest could fail, `Revoke-Cert -Reason 8` (no CA contact):
     untampered passes (reason-8 exit 3); one byte appended to the lib →
     "does not match this entry point's pinned release digest", exit 1, no
     script logic ran; tampered + `-AllowUntrustedScriptPath` → the UNSAFE
     LAB OVERRIDE warning then reason-8 exit 3; restored → passes again. CA
     host (everything under its `AU:(M)` `C:\` carries the override): the
     digest differential still proved itself 3/3.
  4. **Fail-closed ancestor/runtime-tree walks + `python*._pth` refusal.**
     Every privileged run this session exercised the strict
     `Get-FilesystemAncestorChain` path on 5.1 (Set-OfficerRights
     provisioning, the registered sync task, Revoke-Cert, the reconcile
     gate). A throwaway venv under an admin-only scratch: clean control →
     planted `python._pth` refused with the path-override violation →
     removed → clean again.
  5. **Spike protected-at-creation output.** Run as the gMSA via scheduled
     task: output directory born with exactly SYSTEM / Administrators /
     gMSA full control, `AreAccessRulesProtected=True`, OI/CI to children,
     owner gMSA; `spike.key` born with the same three-trustee DACL, no
     inheritance flags; rerun refuses the existing directory and the
     existing key path (FileExistsError). Driven through the spike's own
     functions (`_create_protected_output_directory`, `build_csr`,
     `_write_new_protected_private_key`) in main()'s order because
     `requests_negotiate_sspi` is not in the pinned deployment closure —
     see `docs/UNFILED-WORK-ITEMS.md` item 16. The spike's enrollment leg
     did not run this round (that leg is separately covered by §A against
     the product).

  **Not run:** phase L (`Lqueue`/`Ldrain`) — no enrollment-leg change in this
  delta and the lab fabric remains unsound for it (unchanged status);
  the spike's full enrollment path (item 16); CI on this exact commit.

  **Teardown verified, not assumed:** 5 serials revoked (0 failed), zero
  `ACME-ServerAuth` certificates remain Issued, CRL republished, CA back to
  224 bytes / 4 ACEs / `OfficerRights` ABSENT / certsvc Running, IIS
  `denyUrlSequences` empty, all scheduled tasks unregistered (0 remaining),
  the mock collector's root cert removed (0 left) and its task stopped,
  web.config carrying no SIEM/CRL/GET overrides, the store restored with
  `integrity=ok` and every table count identical to the session-start
  fingerprint (accounts 37, audit_log 722, authorizations 38, certificates
  13, challenges 38, nonces 0, orders 38), dotenv restored, pool Started,
  `/directory` 200. The deployed runtime is now the `3c599ca` build (version
  string 1.12.0); the store and all operator configuration are as found.

- **2026-08-25 whole-repository scan remediation — live validation EXECUTED,
  tip `5580519`.** Preflight: CI green on all eight jobs for the exact commit;
  local gates 953 pytest + 1 skip, 467 Pester + 4 platform skips, ruff, mypy.
  Installer exited 0, deployment reports VERSION=1.11.0, `/directory` 200.

  **Results: §A 14/14, §A1 13/13, CRL+§G 9/10, §K 12/12, both transport-orphan
  branches 6/6 each, §R+Rverify 6/6 + 3/3 through three cycles, least
  privilege, authority split, CRL-evidence cycle.** The one FAIL is CRL3, the
  designed WI-052 calibration check (this CA's 649200 s window vs the 604800 s
  default ceiling) — unchanged operator finding, deliberately measured against
  the shipped default. Least privilege re-proven live: gMSA token succeeds,
  CRL publication denied `0x80070005`, out-of-template revocation denied
  `CERTSRV_E_RESTRICTEDOFFICER`, reason 8 refused by the script before any CA
  action (exit 3). Authority split re-proven: admin-token-only revokes at the
  CA but the confirm 401s → exit 2; confirm-token-only recovers → exit 0. CRL
  evidence fail-closed (`crl-evidence-required-but-absent`) → administrator
  republishes → `crl-verified`.

  **This round's own fixes proven live, not just in unit tests.** 60 idle
  maintenance calls (15 each to nonce-cleanup, expired-order-sweep, and the
  pending-revocations poll) wrote **zero** audit rows, where before the fix
  each call wrote one. 15 confirm probes for 15 **different** nonexistent
  serials wrote **one** coalesced row. F1 (the post-issuance orphan) and F2
  (admission-denial coalescing) could not be driven live — one needs a genuine
  ENOSPC at a precise moment, the other needs sustained gate saturation — and
  are covered by fault injection and mutation testing only. Said plainly
  because it is the gap in this proof.

  **Two teardown defects found, both in the HARNESS and both now fixed.**

  1. **The teardown's own "is the CA clean?" check was inert, and had been for
     an unknown number of rounds.** The runbook prescribed
     `certutil -view -restrict "CertificateTemplate=ACME-ServerAuth"`. The
     `CertificateTemplate` column stores the **OID** for a custom template, so
     the name form matches nothing and returns zero rows — indistinguishable
     from "the CA is clean", and recorded as exactly that. Restricting on the
     OID found **18 certificates still Issued, of which only 3 were from this
     run**: fifteen were live residue from earlier sessions whose records each
     claimed zero remained. Same family as the stale-constant CONNECT-PROBE and
     the inert firewall rule — a check pointed at the wrong thing certifies the
     state it was written to detect. All 18 are now revoked.
  2. **The teardown list had the ORDER wrong.** It said revoke (step 1) before
     reverting the officer grant (step 3). A template-scoped `OfficerRights`
     blob restricts *every* certificate manager to its scoped requesters,
     administrators included, so revoking while the grant is live fails every
     serial with `CERTSRV_E_RESTRICTEDOFFICER` — measured here as 18/18
     refused, then 18/18 succeeding after the revert. The runbook now leads
     with the ordering.

  Also confirmed unchanged: the CA host's `C:\` still carries an *applicable*
  `Authenticated Users:(M)` ACE, so `Set-OfficerRights.ps1` exits 1 there
  without `-AllowUntrustedScriptPath`. The refusal is the gate working; the
  harness now passes the override on both the grant and the revert paths.

  **Teardown verified, not assumed:** 18 serials revoked (0 failed), zero
  `ACME-ServerAuth` certificates remain Issued, CRL republished, CA back to
  224 bytes / 4 ACEs / `OfficerRights` ABSENT / certsvc Running, IIS
  `denyUrlSequences` empty, all three scheduled tasks unregistered (0
  remaining), web.config carrying no CRL or unauthenticated-GET overrides, the
  store restored with `integrity=ok` and **every table count identical to the
  session-start fingerprint** (accounts 37, audit_log 722, authorizations 38,
  certificates 13, challenges 38, nonces 0, orders 38), the dotenv restored
  with the throwaway kid gone, pool Started, `/directory` 200, and scratch
  removed on both hosts.

  **Not run:** phase L (`Lqueue`/`Ldrain`). No enrollment-leg change on this
  branch, and the blackhole mechanism is still unsound for this topology — see
  `docs/UNFILED-WORK-ITEMS.md` item 11 and the analysis recorded there.

  **Still open at park:** the deployed dotenv is the prior session's throwaway
  phase-L env (13 kids), restored as-found. That is item 12, and closing it
  means minting a real dotenv, which is an operator action.


- **2026-08-24 daybreak review — live validation EXECUTED on the branch, final
  tip `b8d3343`.** Scope: the four findings of
  `docs/security-review-2026-08-24-daybreak-standard.md` (F10 provenance gates,
  F11 ancestor substitution check, F12 HEC redirect, F13 System32 resolution),
  which had shipped with local gates only. Preflight: local gates reproduced
  (pytest 931+1, Pester 457+4 at `ade72a8`; 467+4 at the final tip), plus an
  independent third-lineage adversarial review (F10/F12/F13 SOUND; F11
  ship-blocking on proof grounds — confirmed prescient by what follows).

  **The live run found three defects.** Two in the fixes themselves, both
  fixed in-session and live-re-proven:

  1. **`29ad5da` — the F11 root-self check refused the DESIGNED gMSA state
     grant.** Measured before deploy against the real root: the gMSA's
     Modify (⇒ Delete) on `C:\ProgramData\acme-adcs-ra` is a violation under
     `Get-AllowedExecutableOwners`, which can never admit a service identity.
     First install: `INSTALLER_EXIT=1` — fresh installs passed, **every
     upgrade of an existing deployment bricked** (the round-5 refusal class).
     Fix: `-AllowedRootWriterSids` for the root-self check only (state root
     passes its design writers; runtime root passes none; ancestors never).
     Live re-proven: upgrade install exit 0, `/directory` 200, twice.
  2. **`b8d3343` — the untrusted-tree override did not reach the
     `Revoke-Cert.ps1` child.** The chain ran registrar→task action→the sync's
     own gate, then stopped: the child carries the same gate and refused
     (exit 1 → 'failed'), so an allowed tree could list but never revoke —
     measured live as a genuinely stuck orphan. Fix: propagate the flag into
     the child argv; live re-proven by draining that orphan (task exit 0).
  3. **Environment, operator-owned:** the CA host's `C:\` carries an
     *applicable* `Authenticated Users:(M)` ACE, so no tree on that host
     passes the gate and the officer scripts need `-AllowUntrustedScriptPath`
     everywhere there. The refusal is correct (measured, not assumed), the
     override is loud, the RA host (Users create-class `C:\`) needs none.
     Filed in `docs/UNFILED-WORK-ITEMS.md`.

  Also closed from the adversarial review: the generic-bit branches
  (`0x10000000`/`0x40000000`) were live-proven 10/10 against the deployed
  library, then pinned with four Pester cases (+ the four designed-root-writer
  regressions, + the child-propagation regression — all mutation-checked;
  Pester 457→467).

  **Application re-proof on `b8d3343`:** §A 14/14, §A1 13/13, CRL+§G 9/10
  (CRL3 = standing WI-052), §K 12/12 (same-hour second run refused at the
  durable per-kid ceiling — the control working), both transport-orphan
  branches 6/6, §R+Rverify through four cycles with R2b (empty §7.6 body +
  out-of-band header) each, least privilege, authority split (exit 2 → 0),
  CRL evidence (`crl-evidence-required-but-absent` → publish →
  `crl-verified`). F10 additionally proven live in both directions (refuse
  without override as the gMSA; override present in the registered task's
  action, read back after registration). Teardown verified: 14 store-diffed
  serials + both ReqID-only orphans revoked (0 failed, template drained),
  CRL republished, CA pristine (224/4/absent), store restored to the
  session-start fingerprint, pool Started, `/directory` 200, hardened CA
  staging tree removed. Not run: phase L (no enrollment-leg change on this
  branch; owed on a v1.11.x tag per the standing lab-network item).


- **v1.11.0 full re-proof — 2026-08-24, tip `0a47955` (the exact released
  artifact), on the lab RA host and issuing CA.** The v1.11.0 code commits
  touch the revocation leg (`routes/revocation.py` only — verified by diff
  against `f6badc9`), so per the standing rule the whole re-proof ran on the
  shipped commit. Preflight: CI green on all eight jobs for `0a47955`; local
  gates 928 pytest + 1 skip, 424 Pester + 4 platform skips, ruff, mypy clean.
  The installer exited 0 and the deployment reports **VERSION=1.11.0** (first
  deploy carrying 1.11.0 metadata) with the lease symbols verified in the
  installed package, not the source tree.

  **The v1.11.0 delta itself is now live-proven, on every revocation cycle of
  the run (3/3):** new check R2b asserts the RFC 8555 §7.6 success body is
  **empty** and the `X-Acme-Ra-Out-Of-Band-Revocation` header carries the
  out-of-band hint JSON. The harness now sends the standard `certificate`
  field (it had mirrored the server's old `cert` dialect — the reason no
  in-repo test could catch the original defect). Also proven: a
  reason-1 revoke through the standard dialect is accepted (200), the cert
  serves 410 afterwards, the serial queues for CA-side revocation, and the
  registered sync task drains it.

  Full results: §A 14/14 (issuance, serverAuth-only EKU, SAN-from-CSR, chain
  off the existing CA, out-of-scope SAN refused at finalize, CA policy denial
  mapped to 400, reasons 7 and 8 refused and not queued); §A1 13/13 front
  controls; CRL/§G 9/10 with the single failure being **CRL3, the designed
  WI-052 calibration check** (649200 s validity window vs the 604800 s default
  ceiling — unchanged operator finding, deliberately measured against the
  shipped default); §K 12/12 key-rollover ceiling; **both transport-orphan
  branches 6/6 each** (leaf-in-hand quarantined with serial+ReqID and queued;
  ReqID-only leaves no row, audit-only — the orphan was later found and revoked
  by hand at teardown from the audit row's ReqID); §R+Rverify 9/9 per cycle;
  least privilege re-proven (gMSA token succeeds, CRL publication denied
  `0x80070005`, out-of-template revocation denied `CERTSRV_E_RESTRICTEDOFFICER`,
  reason 8 refused by the script before CA action, exit 3); authority split
  re-proven (admin-token-only revokes at the CA but confirm 401s → exit 2;
  confirm-token-only recovers and exits 0); CRL evidence fail-closed
  (`crl-evidence-required-but-absent`) then `crl-verified` after an
  administrator republishes; `audit_prune_enabled=true` refused by the
  deployed config loader.

  **Phase L: §L 9/9 (migration, lease minted on a real issuance, reclaim
  refused mid-flight, enrollment completes despite the reclaim attempt) and
  Ld5 (no order anywhere has two certificates) PASS. Lqueue/Ldrain NOT PROVEN
  on this tip — blocked by a lab-network anomaly, not by product behavior.**
  Three attempts, each defeating a different harness assumption; the evidence
  chain, in order:

  1. Attempt 1 (unmodified harness): 43 filler enrollments completed *through*
     the blackhole within ~1 s — the enrollment session's keep-alive pool held
     connections established during phase L's real issuance, and established
     Windows flows are not redirected by a route added afterwards. The
     saturation check passed **vacuously** on TIME_WAIT leftovers (the socket
     counter counted every state).
  2. Attempt 2 (pool recycled after route-on, counter fixed to live states
     only): enrollments still completed — the CA name now carries a working
     path beyond the pinned IPv4. Both fixes were correct but insufficient.
  3. Attempt 3 (route blackhole on **every** resolved address — v4 /32 and
     v6 /128): the CA's AAAA turned out to be dead (refused in ~2 ms with or
     without routes), yet enrollments *still* completed. Controlled
     single-issuance probes through the verified-blackholed state completed in
     0.5–0.7 s, the CA database shows real issuances by
     `WORK-DOMAIN\gMSA-acme-ra$`, and the CA's IIS log records the certsrv
     requests arriving from the RA host — while a fresh `.NET` probe to the
     same address hung 5 s at 13:23 and **connected in 22 ms at 13:38 with the
     identical route present and the dead-gateway neighbor entry unchanged**.
     The lab network fabric is flapping reachability today; no host-local
     blackhole mechanism can be trusted against it.

  **Disposition.** Not a product regression: (a) `git diff f6badc9..0a47955`
  touches only `routes/revocation.py` — zero enrollment-path delta from the
  tip where Lqueue/Ldrain passed 22/22 earlier the same day; (b) §L 9/9 and
  Ld5 pass on this tip; (c) the bypass is environmental, demonstrated at the
  packet level. **Owed:** re-run `lease-pass.sh` on a v1.11.x tag once the lab
  network stabilizes; the harness now blackholes every resolved address,
  counts only live socket states, and the driver recycles the pool after
  route-on, so the first two failure modes cannot recur. The flapping itself
  is filed for the operator (see the lab runbook §12).

  **Teardown verified, not assumed:** 141 store-diffed serials plus the
  ReqID-only orphan (serial resolved at the CA from ReqID 353) revoked —
  141 + 1, **0 failed**, first/middle/last/orphan spot-checked at disposition
  21, and **zero** `ACME-ServerAuth` certificates remain Issued on the CA;
  CRL republished; `CA\Security` back to 224 bytes/4 ACEs with `OfficerRights`
  absent and certsvc running; IIS `denyUrlSequences` empty; the RA store
  restored from the pre-run backup with `integrity=ok` and **every table
  count identical** (audit_log 701); web.config at steady state; app pool
  `Started`, `/directory` 200; no leftover one-shot tasks; scratch cleaned on
  both hosts. The deployed runtime stays at the last-proven tip (`0a47955`,
  VERSION=1.11.0), per house pattern.

  **Inherited deviation, recorded:** the RA dotenv at session start carried the
  previous session's throwaway phase-L allowlist (13 kids) and the store held
  36 post-backup audit rows — the 2026-08-24 Certify/v1.11.0 session restored
  neither. This run's backup captured that state and restored to it ("as
  found").

  **Restored as-found means those 13 throwaway kids are still allowlisted in
  the deployed dotenv.** An earlier draft of this paragraph closed with "the
  throwaway kids are gone", which contradicted its own preceding sentence and
  was corrected on 2026-08-25 after a review caught it. Restoring a backup
  preserves the deviation; it does not clean it. Each kid is a live EAB
  credential path into the lab RA for whoever still holds its MAC key, which
  is unknown — they were minted as throwaways across two sessions. Filed as an
  operator item; the correct close is minting a real dotenv, not restoring
  another backup.

- **Phase L (the stale-worker enrollment lease) PROVEN END TO END for the first
  time — 2026-08-24, tip `f6badc9`, on the lab RA host and issuing CA.**
  22/22: §L 9/9, §Lqueue 8/8, §Ldrain 5/5. CI green on all six jobs for the
  proven commit before deploy; installer exited 0 against the host's real
  Python 3.14, IIS, ServerManager and ActiveDirectory.

  **`Ldrain` is the half that had never run in three sessions**, and it is the
  one that matters: the stale worker reached the CA boundary still holding
  generation 1, found generation 2, and abandoned **before submit** —
  `{"reason": "processing-lease-lapsed", "stage": "before-submit",
  "held_generation": 1, "current_generation": 2}`. Exactly one certificate
  exists for the contested order, and no order anywhere has two. That is the
  double-issuance defence working against a real CA rather than a test double.

  **Why it had never run, finally diagnosed.** Not neglect — the phase was
  unrunnable, for three separate reasons that each had to be fixed:

  1. **No driver called it.** `final-pass.sh` runs §A through the CRL cycle and
     never invokes `L`, `Lqueue` or `Ldrain`. The phases existed in
     `raproof.py`; nothing executed them. Added `lab-harness/lease-pass.sh`.
  2. **Neither blackhole mechanism could support queue-then-drain.** The
     outbound firewall rule **does not block on this host** — measured at 14ms
     to connect with the rule present, enabled and carrying the CA's correct
     address. It had also hardcoded the CA's address, and the CA had since moved;
     its own CONNECT-PROBE dialled the same stale constant, hung, and reported
     the inert rule as *working*. (Addresses stay in the gitignored harness.) The config-mode blackhole
     (`ACME_RA_ADCS_HOST`) does saturate, but lifting it needs an app-pool
     recycle that **kills the queued enrollments**, leaving nothing to drain —
     measured as 47 orders wedged in `processing`, zero abandon rows, unchanged
     across a full 420s wait. Added `lab-harness/bh-route.ps1`: a host route via
     a verified-unreachable next hop, which drops silently *and* lifts without
     touching the app pool.
  3. **`L5` aborted the phase on an expected client timeout.** The re-finalize
     is admitted and then waits for an enrollment worker; with the 2026-08-23
     bounded executor no worker frees until an in-flight enrollment burns its
     120s ceiling, so the wait exceeds any sane client timeout **by design**.
     The exception escaped before `save_state`, which is why `Ldrain` then had
     no target and `Ld2`–`Ld4` never executed at all. It now reads the committed
     result from the store.

  **Two harness checks were measuring the wrong thing and are fixed:**

  - **`L4a` hardcoded `ca_sockets >= 40`**, encoding the old architecture where
    enrollment ran on Starlette's shared ~40-thread pool. The 2026-08-23
    final-scan fix gave enrollment its own bounded executor
    (`adcs_enrollment_max_workers`, **default 4**) precisely so a stalled CA
    cannot consume the whole server — so the check reported the security fix
    working as a FAIL. It now reads the ceiling from the deployment, the same
    rule §K already follows.
  - **`L1c` read its "pre-existing orders" baseline from the newest backup**,
    which is only a pre-migration snapshot on the single run where the migration
    landed. Every run since backs up a store that already has the column and
    already holds legitimately-leased orders, so "must still be 0" failed on
    correct behaviour. It now branches on the backup's schema: upgrade
    assertion when the backup is genuinely pre-migration, generation *stability*
    otherwise. Measured this run: 38 pre-existing orders, **zero** changed.

  **One self-inflicted failure worth recording**, because the harness reported
  it misleadingly: lifting the config blackhole with `setenv -Remove` does not
  restore the real CA. An absent `ACME_RA_ADCS_HOST` falls back to the shipped
  documentation placeholder `ca01.work-domain.local`, which does not resolve —
  every enrollment then died with `NameResolutionError` and finalize answered
  **503**, which reads exactly like a product fault. `show-floor.ps1` printed
  `ADCS_HOST=ABSENT (real CA)`, actively asserting the wrong thing. Both fixed;
  absent is not a synonym for correct.

  **Operational property measured, not previously recorded.** With the bounded
  executor's defaults (`max_workers=4`, `max_pending=32`,
  `total_timeout=120s`), an *admitted* enrollment behind a stalled CA can wait
  roughly `(32/4) x 120s` — about 16 minutes — before it starts. Requests past
  the ceiling are shed promptly; admitted ones are not cancelled, deliberately,
  because abandoning a worker after CA issuance would skip the durable
  completion or quarantine step. Clients see a long hang rather than a fast
  failure, and should be given timeouts and retry accordingly.

  **Teardown verified, not assumed.** The session caused the CA to issue **47**
  certificates (the drained queue issued far more than the harness's own state
  file tracked, which is why the ledger is generated by diffing the backup's
  serials against the live store rather than hardcoded). All 47 revoked at the
  CA, 0 failed, CRL republished, and first/middle/last spot-checked as
  disposition 21. The four `finalize-enrollment-transport-orphan` rows were
  confirmed to **predate** this session (audit ids 114-171 against a backup
  maximum of 656) and belong to an earlier round's ledger. Store restored with
  `integrity=ok` and all eight table counts identical to the pre-run
  fingerprint; app pool `Started`; `/directory` 200; no residual firewall rule,
  route, or scheduled task; `ACME_RA_ADCS_HOST` back to the real CA and the
  reclaim floor back to its shipped default.

- **Full live E2E re-proof executed (2026-08-17), tip `e7c4254` (14a), on the
  lab RA host and issuing CA.** CI green on the proven commit before deploy;
  local gates green (`ruff`, `mypy`, 876 pytest, 363 Pester on pwsh 7). The run
  covered the whole canonical pass — §A issuance/EKU/SAN/chain/CA-denial/reason
  codes (14/14), §A.1 front controls (13/13), CRL freshness, the GET-form
  default, both transport-orphan branches, the revocation round trip through the
  registered task as the gMSA, the least-privilege denials, the agent authority
  split, and the CRL-evidence cycle — plus the new §K for 14a. **It found one
  defect, fixed and re-proven live in the same session:**

  - **Live-found (fixed in `838eeb2`): the entire CA-side revocation loop was
    inert.** `Sync-Revocations.ps1` exited 2 with nothing revoked; every
    `certutil` call in `Revoke-Cert.ps1` reached the process **without its
    `-config`** and the non-CA RA host answered *"No local Certification
    Authority; use -config option"*. Cause: `Invoke-CertUtil` splatted its
    argument array into `Invoke-CertUtilCapture`. Splatting an array into a
    **native** command (the original `& certutil @CertutilArgs`) gives one
    argument per element; splatting it into a **PowerShell function** binds only
    the first element and drops the rest into `$args`, silently. Seven arguments
    in, one out, on every certutil call in the file — the `-revoke` included.
    Introduced by `a69859d`, a security-hardening commit. Both helpers are now
    advanced functions, so the mistake is a binding error rather than silence,
    and three Pester tests assert the argv certutil actually receives (all three
    fail against the old code). Re-proven live: 7 pending, 2 revoked, 5
    already-revoked-at-CA recovered through the confirmation retry, 0 failed,
    agent exit 0, RA queue drained to empty.
  - **CI could not have caught it.** The Windows job runs pytest; the Pester
    suite already stubbed `certutil` but never asserted *which* arguments
    arrived. 363 green Pester tests coexisted with a revocation path that could
    not revoke. This is the fifth escaped PowerShell defect across three rounds,
    and the third whose common factor is that no test executed the real call.
  - **14a (§K, 12/12) proven live**: the ceiling ships **enabled** (read from
    the deployment, not assumed), five rollovers accepted and the sixth refused
    `429 rateLimited` with `Retry-After: 3600`; the refusal is **atomic** — the
    account key did not rotate, the last allowed key still authenticates and the
    refused key gets 401; exactly five `account-key-changed` rows and one
    coalesced `key-change-rate-limited` row naming the kid and limit; and a
    freshly minted account under the same EAB kid is refused on its **first**
    rollover, so the per-kid keying holds.
  - **Least privilege re-proven**: the scoped officer cannot publish a CRL
    (`0x80070005`), cannot revoke outside its template
    (`CERTSRV_E_RESTRICTEDOFFICER`), reason 8 is refused before the CA is
    touched (exit 3), and the gMSA token still carries no `Domain Computers`
    (the E-1 restricted primary group).
  - **Agent authority split re-proven**: admin-token-only revokes at the CA but
    is refused on the confirm endpoint (401 → exit 2, serial stays pending);
    confirm-token-only, with no admin token on the host at all, recovers it and
    exits 0. Both runs took their credentials from the ACL'd dotenv, so no token
    reached an argv or a log.
  - **CRL evidence fail-closed then verified**: with
    `require_crl_evidence` on, the confirm is refused 400 with audit
    `crl-evidence-required-but-absent` (exit 2); after an administrator
    republishes, the confirm succeeds and the audit records
    `verification: "crl-verified"`.
  - **`Set-OfficerRights.ps1` provisioned a CA whose `OfficerRights` was ABSENT**
    — the round-7 "Buffer cannot be null" defect on the first-provisioning path
    is fixed and live-proven.
  - **Reproduced, not a regression**: this CA's CRL validity window
    (7d 12h 20m) still exceeds the RA's default 7-day evidence ceiling (CRL3),
    so the ceiling must be set from the measured maximum CRL age at scheduled
    replacement, including `thisUpdate` backdating and clock skew, not from
    `CRLPeriod` alone. Unchanged operator finding, deliberately measured against
    the shipped default.
  - **Not proven this round**: phase L (`Lqueue`/`Ldrain`, the stale-worker
    enrollment lease) was not run. **CLEARED 2026-08-24** — proven end to end,
    22/22, on tip `f6badc9`; see the newest validation-log entry above for why
    it had been unrunnable rather than merely skipped. The MSI
    no-digest/staged-copy refusals remain owed from round 6.
    **BOTH CLEARED 2026-08-24** — phase L proven 22/22, and all four MSI
    cases proven live on a second Windows host against the released
    `v1.10.0` tarball (including the Authenticode check and a staged
    wrong-digest artifact that `msiexec` never opened). The privileged-script-path item gained live evidence
    rather than a fix: `C:\Temp\ra-scripts`, the path the gMSA sync task
    executes from, measures `BUILTIN\Users:(CI)(AD)` and `(WD)`.
  - **Teardown verified**: all 7 certificates this run caused the CA to issue
    are revoked (including the untracked ReqID-only orphan, ReqID 249) and the
    CRL republished; `OfficerRights` ABSENT and `CA\Security` back to its
    pristine 224 bytes / 4 ACEs; `denyUrlSequences` empty; store and dotenv
    restored with an identical fingerprint (integrity ok, all row counts equal)
    and the app pool back to `Started`.

- **Round-6 native Windows re-proof executed (2026-08-16), final tip
  `8964eba`, on the lab RA host under Windows PowerShell 5.1.** The run
  covered the full live re-proof (§A, §A.1, CRL/G, both transport-orphan
  branches, revocation round-trip through the registered task as the gMSA,
  least-privilege denials, agent authority split, CRL evidence) **and** the
  native items the round-6 review demanded — and it found one more defect,
  fixed and re-proven live in the same session:

  - **Live-found (and fixed on `8964eba`): the mid-install state re-assert
    ran `icacls /reset` on the protected state root**, re-inheriting
    `%ProgramData%`'s `Users (CI)(WD,AD,WEA,WA)` until `/inheritance:r`
    restored — a create-capable window the atomic `CreateDirectoryW` birth
    DACL does not cover. A looping standard-user process planted 3 entries
    into the installer-created state root through it (3 successes in 43,701
    attempts); the post-claim proof caught the plants and aborted (fail-closed
    held; nothing was adopted), and a deterministic `/reset`-window probe
    confirmed the cause. Fix: roots are never `/reset` mid-install —
    `Reset-TreeChildrenToInherited` resets descendants only and
    `Set-ObjectProtectedDacl -SkipReset` re-asserts the protected shape with
    no unprotected interval (claim, runtime re-assert, state re-assert).
    Re-proven live: the same race loop then achieved **0 successes in 43,920
    attempts** with the install exiting 0.
  - retained-handle/race item: see above — 0 plants post-fix; the loop's
    pre-creation of a ProgramData root was separately proven to hit the
    collision refusal (user-owned tree, never adopted);
  - named user (`M`/`W`) and named group (`F`) write ACEs on the source tree
    are refused by the bootstrap before the helper loads (no scratch created);
    a `C:\Temp`-staged checkout (Users create rights) is likewise refused;
  - post-snapshot mutation of the checkout cannot reach the build: a syntax
    bomb written into `src/` after the snapshot appeared left the install
    green and the built runtime importable;
  - path spellings refused before any host mutation (pool untouched):
    trailing dot, trailing space, ADS component, reserved device name, UNC,
    forward slashes, dot segments, nested roots, equal roots;
  - PATH-first `py`/`python`/`winget` marker executables were never executed
    (`-InstallPrereqs`); trusted discovery accepted only the chain-proven
    interpreter;
  - MSI: the no-digest and staged-copy refusals are Pester-proven and
    source-ordered, but **not live-executed this round** — the handler is
    installed on the lab host and its DLL fallback short-circuits the MSI
    path; forcing it would have meant hiding a production DLL. Recorded as
    the one native case still owed;
  - clean install (also under the live race), reinstall ("recognised as a
    previous install"), rollback (corrupted pinned hash → previous runtime
    restored byte-identically, dotenv re-protected, no leftovers), and the
    §4 migration refusal against the real `.preSplit` tree all passed;
  - the EAB quota (finding 7) was proven live at its default: a second
    distinct-key account is denied `badExternalAccountBinding`, 46 replayed
    denials coalesced into 2 durable rows with exact tallies, and a
    deactivated account's slot was not recycled;
  - the standing WI-052 was re-observed unchanged (CRL3: the lab CA's 7d12h
    window vs the 7d default ceiling) — operator-owned, not a regression.

  Teardown returned both hosts to their pre-run state (store fingerprint
  byte-identical: 21/87/22/5/22/42/22/1; CA `Security` 224 bytes,
  `OfficerRights` absent; `SeBatchLogonRight` restored exactly and verified
  by re-export; every issued cert revoked and the CRL republished; zero
  scratch/retired/task leftovers). The lab host now runs `8964eba`,
  `/directory` 200.

- **Daybreak round-6 review remediated in source (2026-08-16); native Windows
  re-proof is still required before pilot.** Seven findings at `d1d7c17` (four
  high, three medium) were independently reproduced and addressed as one
  boundary redesign rather than seven local predicates:

  - fresh runtime/state/site/scratch roots now receive their final protected
    DACL in the `CreateDirectoryW` call itself. The old create-then-lock design
    could not revoke a create-capable directory handle opened in its window;
  - executable/site ACL provenance is an authorized-writer SID allowlist.
    Arbitrary named users/groups with write rights fail closed;
  - install paths are restricted to unambiguous local DOS paths, and runtime is
    kernel-re-resolved before any state Modify grant is applied;
  - `-InstallPrereqs` no longer executes PATH-selected Python or winget;
  - consumed repository inputs and ancestors are proven before the helper is
    dot-sourced, copied into administrator-only staging, and PEP 517 builds only
    the snapshot;
  - local/remote MSI inputs both require a digest, are staged under the same
    protected namespace, verified there, and opened only by the absolute
    System32 `msiexec.exe` path;
  - account creation has an atomic lifetime per-EAB-kid quota (default one),
    counting deactivated accounts and committing the count/insert/audit under
    `BEGIN IMMEDIATE`.

  Local gates: **807 pytest + 1 skipped, 264 Pester + 1 skipped, ruff, mypy**.
  The native tests still owed are explicit: retained low-privilege directory
  handles, named-user/group ACE refusals, trailing-dot/space paths, PATH marker
  executables, mutable source refusal/snapshot build, MSI replacement attempts,
  clean install/reinstall/rollback, and gMSA launch. Source-only success is not
  pilot evidence for this installer.

- **Round-7 validation on tip `45643f8` (2026-08-17) — the accumulated
  follow-up rounds executed on Windows for the first time.** The five rounds
  landed since the last live proof (`8964eba`) had only ever been
  source-verified; the round-6-followup doc said so explicitly. This run
  executed them. Full record: `samples/lab-run-2026-08-17-round7-validation.md`
  (gitignored).

  **Proven live on the tip's own bytes** (staging hash-verified equal to
  `git archive HEAD`):

  - **Install at tip**: reinstall over the two-tree layout, exit 0; both roots
    recognised as a previous install and re-proven; `web.config` launch
    configuration verified; **zero** `.retired-*` leftovers; **zero** installer
    scratch left under `%ProgramFiles%`; **zero** `icacls /save` dumps in
    `%TEMP%` or `C:\Windows\Temp` (the evidence stays in the protected
    scratch); pool Started, `/directory` 200; store fingerprint **unchanged**.
  - **web.config gate — 31/31**, driving the shipped
    `Assert-WebConfigLaunchTrusted` against real files on real 5.1. The
    deployed `web.config` is accepted unchanged (control); all 25 refusal
    shapes owed by rounds 2/3/5/6 refuse (arguments, PYTHON* vars, issuance
    policy vars, redirected AND absent `ACME_RA_DOTENV`, processPath mismatch,
    `<location>`-scoped `httpPlatform`, nested `__` env names, `<add>`-shaped
    entries, `scriptProcessor` and managed `type=` handlers, the SIEM token,
    the per-kid quota, both CRL strength knobs, and the five control-removing
    settings); and all 5 **false-refusal guards accept** (`"1"` for a pinned
    bool, a trailing space in the dotenv path, forward-slash paths, a
    namespaced `<configuration>`, `REQUIRE_CRL_EVIDENCE="true"`).
  - **appcmd family — 5/5.** A genuinely broken appcmd aborts with the
    worker-still-live message rather than "[ok] no such app pool yet"; the
    tip's own shielded stop no longer aborts the install when appcmd writes to
    stderr, falling through to the prove loop (**and the control proves it is
    not vacuous**: the same fixture through the unshielded path *does* abort).
  - **Bootstrap ACE refusals — 5/5, full installer runs.** A `WDAC`/`WO`-only
    ACE — the two rights the dead `::WriteDacl`/`::WriteOwner` spellings
    dropped from the mask — is refused for a **named user** and a **custom
    group**, on the release root, on `scripts\lib\` (so
    `Get-BootstrapInteriorDirectories` works), and on `src\`; a plain write ACE
    on `scripts\` alone is refused. Every case exits non-zero, names the path,
    and refuses **before any build step**.
  - **App re-proof**: A 14/14, A1 14/14, G 5/5, Q both branches 6/6 each
    (chain → quarantined row + ReqID; leaf → **no row written**, by design),
    R 5/5. CRL 4/5 — the failure is **WI-052 re-observed unchanged** (CA CRL
    window 649200s vs the 604800s default ceiling, short by 12.3h). The
    validation did not measure the lower-bound `A_sched_max`; do not infer it
    from either this validity window or `CRLPeriod` alone.

  **Defect found live and fixed** (`01417b5`): the `icacls` owner-candidate
  **fallback loops could not fall back** on Windows PowerShell 5.1.
  `Reset-TreeToInherited` and `New-ProtectedDirectory` ran
  `& $script:IcaclsExe … 2>&1` under an explicit `EAP=Stop`, so the first
  candidate that wrote to stderr terminated the loop — the documented
  name-form fallback was dead code, and the actionable hostile-namespace throw
  was unreachable on the very path it was written for. Still fail-closed (the
  install refuses either way), so it is a defeated fallback plus lost
  diagnostics, not a bypass. Fixed with one primitive,
  `Invoke-NativeShielded`, replacing the seven-line shield at all seven icacls
  sites — the repetition being the actual defect, this family having now
  escaped **seven** times. Tests mutation-verified, with the honest caveat that
  the three behavioural ones **only fail on 5.1** and pass on pwsh 7: they are
  meaningful solely on the `pester-windows-powershell` job.

  **Still owed — blocked on lab infrastructure, not on the code.** The lab CA's
  remote DCOM/RPC path is broken: `certutil -ping` succeeds locally on the CA
  and fails from the RA host with `RPC_S_SERVER_UNAVAILABLE` **as a plain
  administrator, outside the product**, with every relevant port open, the
  firewall rules correct, certsvc running and the DCOM class registered. It
  broke at 05:02Z on 2026-08-17, mid-way through the previous session, and a
  reboot did not clear it. Because enrollment rides HTTP `/certsrv/` while
  revocation rides DCOM, issuance kept working and hid it. **Unproven as a
  result**: `Rverify`/the queue drain, and the whole officer-script class —
  `Revoke-Cert.ps1 -ReqID`, malformed and truncated `OfficerRights`, the
  spoofed-`$env:windir` regression proof, the `net stop`/`net start` fallback,
  the 5.1 `certutil 2>&1` exit-code contract, and
  `Reconcile-Revocation.ps1`. These carry over intact.

- **Round-6 follow-up review remediated in source (2026-08-16); native Windows
  re-proof required before pilot.** An internal review of the round-6 fixes
  themselves found four defects — three of them in code round 6 added — and two
  were PowerShell evaluating to something other than what it reads as. See
  `docs/security-review-2026-08-16-round6-followup.md`.

  - **H** the bootstrap's dangerous-rights mask named `FileSystemRights::WriteDacl`
    and `::WriteOwner`, **which are not members of that enum** (they are
    `ChangePermissions` and `TakeOwnership`): both terms resolved to `$null`,
    contributed 0 to the `-bor` chain, and the gate covered neither WRITE_DAC nor
    WRITE_OWNER. An ACE granting a named non-administrator only those two rights
    over the helper or the build inputs passed;
  - **H** the bootstrap's ancestor walk runs *upward* from the release root and
    its input list names the helper *file*, so `scripts\` and `scripts\lib\` were
    never inspected — and delete-child on a parent replaces the child whatever the
    child's own DACL says;
  - **M** the `-ConfigureIIS` catch-all TLS branch invoked an unassigned variable
    (round 6 assigned the `netsh` path only function-locally and inside the
    `-SharePort443` branch), killing the install after the certificate was bound
    and before the pool was started. Reachable **only** without `-SharePort443`,
    which is why no live re-proof of any round could have found it;
  - **M** the audit coalescer's open-window index had no bound (the round-5 keys
    carry `order_id`, and the app pool is configured never to recycle).

  Adjacent: the `icacls /save` dump — the evidence for every provenance verdict —
  moved out of ambient `%TEMP%` into the protected installer scratch, which is now
  created before the first root claim.

  Local gates: **816 pytest + 1 skipped, 285 Pester + 1 skipped, ruff, mypy**;
  every new test mutation-verified (8 PowerShell, 4 Python), and one test that did
  not survive its own mutation was deleted rather than shipped.

  **Native cases owed on top of round 6's list**: a `WDAC`/`WO`-only ACE (named
  user and custom group) on the release tree, on `scripts\lib\`, and on `src\` is
  refused before the helper loads, with a clean control; a write ACE on `scripts\`
  alone is refused; `-ConfigureIIS -HostName <name> -TlsCertThumbprint <t>`
  **without** `-SharePort443` completes and starts the pool; the `/save` dumps
  appear under `%ProgramFiles%\.acme-adcs-ra-installer-*` and nowhere else, on
  both the success and failure paths; and round 6's standard-user race loop
  re-run unchanged.

- **Round-6 follow-up, ROUND 2 remediated in source (2026-08-16); native Windows
  re-proof required before pilot.** Three independent hazard-scoped reviews of
  the fixes above found twelve more defects, **two of them in those fixes**. One
  high: `Get-SerialFromReqId` returned its own diagnostics, so
  `Revoke-Cert.ps1 -ReqID` could never revoke — the same success-stream defect the
  wave-3 round fixed 130 lines above it in the same file. Medium: the
  launch-configuration gate validated one attribute of four and never compared
  `$ExpectedProcessPath` to anything (an `<environmentVariables>` entry in
  `web.config` overrides the protected dotenv — verified against the running
  code); an ACE-less DACL read as administrator-only; the nonce-cleanup and
  expired-order-sweep task actions re-tokenised at run time and could never have
  run; the coalescing key absorbed an attacker-chosen SAN; `Stop-AppPoolAndWait`
  read an appcmd failure as "no such pool"; and `distinct_kids` was unbounded
  within a window. Six low. Full detail in
  `docs/security-review-2026-08-16-round6-followup.md`.

  Local gates: **826 pytest + 1 skipped, 319 Pester + 3 skipped, ruff, mypy**;
  10 PowerShell and 12 Python mutations run, all detected.

  **Operator-breaking:** a preserved `web.config` carrying `arguments` other than
  `-m acme_adcs_ra`, `PYTHONPATH`/`PYTHONHOME`/`PYTHONSTARTUP`, an issuance-policy `ACME_RA_*`
  variable, a redirected `ACME_RA_DOTENV`, a `<location>`-scoped `httpPlatform`,
  or a `processPath` that is not exactly the built interpreter now **fails the
  install** instead of being adopted.

  **Native cases owed, adding to the two lists above:**
  - `Revoke-Cert.ps1 -ReqID <n>` resolves a serial and revokes it at the CA;
  - the nonce-cleanup task runs once and reports `LastTaskResult 0`;
  - the deployed `web.config` is accepted unchanged, and each refused shape above
    is refused;
  - `Reconcile-Revocation.ps1` still reconciles after the interpreter change;
  - **under real Windows PowerShell 5.1**: the whole Pester suite, plus the
    `& certutil … 2>&1` behaviour in `Revoke-Cert.ps1` under `EAP=Stop` — pwsh 7
    cannot demonstrate it either way, and `SyncLib` documents that on 5.1 the
    first stderr line terminates, which would break the documented exit-code
    contract. **Open and unresolved.**
  - **`C:\inetpub` chain survey** — `-SitePath` has no ancestor-chain provenance
    and the fix was deliberately withheld pending a live DACL baseline. If the
    chain passes `Test-PathChainTrusted` on the lab host, add the refusal.

- **Round-6 follow-up, ROUND 6 remediated in source (2026-08-17); native Windows
  re-proof required before pilot.** Four cross-lineage reviewers over the whole
  uncommitted follow-up (installer, Python leg, officer scripts, claims-vs-code
  audit). One high: the stop-and-prove loop's `appcmd list wp 2>$null`
  discarded stderr, so a *broken* appcmd yielded an empty worker list — which
  the classifier reads as "no workers", an all-clear — and the installer went
  on to claim trees a live gMSA worker might still hold write handles into
  (rescan-2 F3 again; the suite's `noisy` fixture had modelled the shape and
  was never asserted). Also: both OfficerRights parsers `break`-ed malformed
  descriptors into partial success (the readback tool affirming half a
  restriction; the Set-OfficerRights preservation path would silently strip
  officers from the rewritten value); the eviction marker stamped one row
  late; certutil/net "absolute" paths built from caller-settable
  `$env:windir` with bare-name PATH fallbacks; ten control-removing settings
  (WI-014 coalescing bound, nonce bucket, order limits, body caps, M-2
  reclaim age) still settable from `web.config`; and three low findings
  (empty `reason_code` falling back to prose keying; padded `" true "`
  accepted where pydantic rejects it; the "repository-wide" dead-spelling
  test checking two hard-coded files).

  Local gates: **832 pytest + 1 skipped, 356 Pester + 4 skipped, ruff,
  mypy**; nine mutations run against the new tests, all detected.

  **Native cases owed (16–18 in the follow-up doc's list):**
  - `appcmd list wp` against a genuinely broken appcmd (stop WAS by hand):
    the installer aborts on the timeout throw, never "[ok] no such app pool";
  - `Get-OfficerRights.ps1` against a malformed OfficerRights value throws
    and exits non-zero — never "Found N ACE(s)" over a partial walk;
  - with `$env:windir` spoofed, the officer scripts still resolve the real
    System32 certutil and never execute the spoofed one.

- **Round-6 follow-up, ROUND 5 remediated in source (2026-08-17); native Windows
  re-proof required before pilot.** An inline review of the `web.config` gate,
  the surface round 4 left unexamined. Six findings, **two of them false
  refusals** — a pinned setting demanded the literal string `true` (so an
  operator writing `1`, which pydantic reads as true, had the install refused),
  and a trailing space in the `ACME_RA_DOTENV` value was refused as an ambiguous
  path component. Four bypasses: `ACME_RA_SIEM_HEC_TOKEN` (a secret whose home
  is the dotenv), `ACME_RA_MAX_ACCOUNTS_PER_EAB_KID` (retires the round-6
  finding-7 quota in one line), the CRL proof's `MAX_AGE`/`FOLLOW_REDIRECTS`
  strength knobs (a pinned `REQUIRE_CRL_EVIDENCE` means nothing if the freshness
  bound can be widened beside it), and a managed handler declared with `type=`
  rather than `scriptProcessor` — the .NET half of the primitive round 3 closed
  for native executables.

  Local gates: **830 pytest + 1 skipped, 351 Pester + 4 skipped, ruff, mypy**;
  five mutations run, all detected.

  **Native cases owed:**
  - the deployed `web.config` is accepted unchanged (the control), and each of
    the four refused shapes above is refused on the real host;
  - a `web.config` written with `ACME_RA_AUDIT_OFFBOX_REQUIRED="1"` installs
    cleanly — this is the false refusal that would have aborted an upgrade.

- **Round-6 follow-up, ROUND 3 remediated in source (2026-08-16); native Windows
  re-proof required before pilot.** Three more hazard-scoped reviews, of the
  round-2 fixes. Sixteen findings, **all but two in those fixes**. One high:
  `Stop-AppPoolAndWait` would have aborted every FIRST install (it threw on the
  stderr `appcmd list apppool <absent>` legitimately produces, and the pool does
  not exist until ~800 lines later) — the netsh defect's shape again, invisible
  to a lab whose host already has the pool. Medium: the forbidden-env-name list
  was defeated by `env_nested_delimiter="__"` (verified live against the running
  config); `<handlers>`/`<modules>`/`<isapiFilters>` unchecked while the
  installer itself unlocks the handlers section; `<add>`-shaped env entries
  unread; `ACME_RA_AUDIT_OFFBOX_REQUIRED=false` and
  `ACME_RA_ALLOW_WEAK_CREDENTIALS=true` accepted; three platform gates reading
  `$env:OS`; `PolicyDecision.reason_code` defaulting to `"allowed"`; and the
  privileged CA-officer scripts still on bare-PATH `certutil` while the
  read-only one had been hardened. Full detail in
  `docs/security-review-2026-08-16-round6-followup.md`.

  Local gates: **827 pytest + 1 skipped, 337 Pester + 4 skipped, ruff, mypy.**

  **Additionally operator-breaking:** a preserved `web.config` that does not set
  `ACME_RA_DOTENV` at all now fails the install (absent, the worker reads `.env`
  from its own working directory rather than the protected file).

  **Native cases owed, adding to the lists above:**
  - `appcmd list apppool "<absent>"` on a real host — record the exit code and
    stderr. The design is deliberately independent of both, but this is the
    command that settles it;
  - a FIRST install (no pre-existing app pool) completes end to end;
  - a `web.config` with a nested `ACME_RA_SAN_SCOPES__<kid>__DNS_PATTERNS`, an
    `<add>`-shaped env entry, a `scriptProcessor` handler, or no
    `ACME_RA_DOTENV` is refused; forward-slash paths and a namespaced
    `<configuration>` are handled without a false refusal;
  - `Reconcile-Revocation.ps1` and the officer scripts still run after the
    absolute-path change;
  - whether IIS honours a `<location>`-scoped `httpPlatform`, and whether
    `IsapiModule`/`CgiModule` are registered by the installer's feature set —
    these set the severity of a refusal already in place, not the fix.

- **Round-6 follow-up, ROUND 4 remediated in source (2026-08-16); native
  Windows re-proof required before pilot.** Three hazard-scoped reviews of the
  three rounds above, run before lab validation. Seven findings: the R2-11
  `@()` wrapping inverted the readback tool's verdict (`@($null).Count` is 1,
  so a corrupt OfficerRights value printed "Found 1 ACE(s)" and exited 0);
  `ACME_RA_ALLOW_FAKE_ADCS_BACKENDS` and
  `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` were still settable from
  web.config (the latter now pinned-when-present — the lab sets it to true
  there, which passes); `finalize-csr-mismatch` still lacked a `reason_code`;
  the 5.1 `2>&1`-under-`Stop` exit-code hazard was unshielded in every
  CA-officer script including the `net stop`/`net start` fallback that runs
  inside a catch; plus marker-forgery, sample-cap-at-open, whitespace and
  descending-range edges. The mutation-blind
  `test_a_live_window_survives_below_the_cap` was rewritten a third time, now
  asserting what the mutation actually changes. Full detail:
  `docs/security-review-2026-08-16-round6-followup.md` (Round 4).

  Local gates: **830 pytest + 1 skipped, 345 Pester + 4 skipped, ruff, mypy**;
  9 mutations run against the new tests, all detected.

  **Native cases owed, adding to the lists above:** Get-OfficerRights against a
  truncated/no-DACL value exits 1 (never "Found 1 ACE(s)"); the
  net stop/net start fallback completes on 5.1; a failing `certutil -revoke`
  relays the exit code on 5.1 (item 12 becomes a confirmation).

- **Daybreak round-5 findings validated and fixed (2026-08-15), final tip
  `88e9c07`, live-proven on the lab RA host.** Five findings on the round-4
  fixes (1 high, 4 medium), all closed; the live run itself found and fixed
  **two calibration defects in the new chain-trust rule** (both classes CI
  could not see: the raw generic-bit constants — `0x80000000` is
  Generic*Read*, not GenericAll — and SID-vs-name comparison in the owner
  check), plus a third (honouring `PropagationFlags.InheritOnly`, live-probed
  both directions on the host) — each now pinned by a Pester case.

  - **H — file-plant race into a freshly created root**: between `New-Item`
    and the claim's protect step, the fresh root still *inherited* the
    parent's Users-create rights; a dotenv planted there rode the whole claim
    (the claim proof verifies shape, and an inherited-DACL dotenv has exactly
    the descendant shape) and shipped via the no-clobber branch.
    Fix: `Lock-FreshRoot` — protect the DACL in one atomic swap at creation,
    prove the directory **empty** (anything present was raced through the only
    remaining window), normalise the root owner without `/reset`, and skip
    the reset on the fresh path entirely. **Live-proven on the absent path**
    (both roots "protected at creation and verified empty", full install
    exit 0); the raced-plant branch itself needs a genuinely won race and is
    source-asserted + reviewed instead, like round-4's collision branch.
  - **M — lexical path comparison missed aliases**: `Get-PathRelation` now
    canonicalises (dot segments, slashes, case, UNC lexically everywhere;
    junctions/symlinks/8.3 through kernel final-path resolution of the
    deepest existing ancestor on Windows). **Live-proven**: dot-segment,
    `C:\PROGRA~1` and a real junction alias each refused with the relation
    named, pool untouched, nothing created.
  - **M — PATH-resolved interpreter executed elevated unproven**: every
    candidate (launcher resolution *and* the `sys.executable` self-resolution)
    is chain-gated before first execution. **Live-proven both directions**:
    a fake `python.exe` first on PATH in a Users-writable dir is rejected
    with its chain reasons and **never executed** (marker-file proof), while
    the legitimate ProgramFiles/profile candidates pass and the install
    completes.
  - **M — SitePath/web.config adopted unverified**: SitePath joins the
    disjointness check against both managed roots; a pre-existing site tree
    must prove itself (no reparse points, admin-only owners, no write-class
    ACE for any broad trustee — the gMSA included) or the install refuses; a
    fresh one is locked at birth. The web.config check became
    `Assert-WebConfigLaunchTrusted` (throwing): unparseable XML, a
    processPath inside the state tree, or outside the runtime tree, each
    refuse. **Live-proven**: a Users-writable site tree with a planted
    web.config is refused naming the ACEs (no IIS mutation, live sites
    untouched); a hostile processPath is refused; and a mismatched-runtime
    processPath on a *passing* tree also refuses — found while testing on
    throwaway roots, exactly the fail-closed behaviour intended.
  - **M — replayable authenticated requests grew the durable audit stores**:
    coalescing now covers `account-request-denied`, `order-rate-limited`,
    `finalize-csr-mismatch`, `finalize-policy-denied` (keyed additionally by
    account/order so folded tallies stay attributable), and the challenge
    route short-circuits an already-valid challenge (no state write, no audit
    row) instead of re-auditing per POST. App-level pytest coverage; the
    deployed build **live-proven** end-to-end with a 40-request denial storm:
    40/40 rejected, **zero** durable rows (store counts unchanged at
    22/5/21/87).

  Local gates on `88e9c07`: 801 pytest / 259 Pester / ruff / mypy; CI green
  on every tip in the chain (`b4cb6c6`, `fca6458`, `88e9c07`). The lab host
  now runs `88e9c07`'s runtime; the CA host was never touched.

- **Daybreak round-4 findings validated and fixed (2026-08-15) on `102a1f4`,
  live-proven on the lab RA host.** Four findings on the installer rework
  (2 medium, 2 low), all closed on the same branch with 14 new Pester cases
  (235 total, plus 795 pytest / ruff / mypy green):

  - **M1 TOCTOU on first-install state-root creation** — between the
    provenance check and `New-Item -Force`, a local attacker could pre-create
    the predictable ProgramData path; the claim then worked *for* them
    (`setowner /t` normalised their files' owners, the proof passed, the
    re-protect protected their planted dotenv, and no-clobber preserved it —
    the adoption finding reopened by race). Fix: creation without `-Force`
    (throws on an existing path) plus a provenance re-verdict on collision; a
    non-admin cannot manufacture an "ours"-shaped tree (owner Administrators
    is unreachable for them), so the retry can only land in the foreign
    refusal. **Not live-proven** — the branch is reachable only by a genuinely
    won race; it is source-asserted and reviewed instead.
  - **M2 legacy single-tree layout passing the generic provenance check** —
    a clean pre-split tree has the same trustee/owner/DACL shape as ours, so
    it verified as "ours" while the preserved web.config kept launching the
    old gMSA-writable ProgramData venv. Fix, both halves **live-proven**:
    the state tree now refuses `venv`/`python`/`scripts` at its root
    (decided before the icacls walk) — proven against the **real preserved
    `.preSplit` tree**: refusal names the venv as executable content, tree
    untouched; and a post-install check warns loudly when the site's
    web.config `processPath` points inside the state tree — proven with a
    simulated half-done migration (warning printed, then a clean install over
    the healthy tree still exits 0 and `/directory` answers 200, so the new
    rule does not trip on our own layout).
  - **L1 CWD executable hijack on bare `py`/`python` probes through
    `cmd /c`** — an elevated shell in a user-writable directory would execute
    a planted interpreter during the probe. Fix:
    `NoDefaultCurrentDirectoryInExePath` process-wide (set before any
    `cmd /c`) plus absolute-path resolution in `Invoke-PyProbe`. Source-
    asserted; deliberately not "proven" live by executing planted bytes as
    admin.
  - **L2 overlapping `-RuntimeDir`/`-InstallDir` silently collapsing the
    RX/Modify boundary** — both grant sets have the same proof shape, so
    nested or equal roots stayed green while the gMSA gained Modify over
    executable content. Fix: `Get-PathRelation` refusal before any host
    mutation. **Live-proven**: equal roots and nested roots both refused
    (relation named), app pool never touched (still Started), nothing
    created.

- **Installer rework validation — the two-tree layout EXECUTED for the first
  time (2026-08-15) on `54b90db`, the tip after two live-found defects were
  fixed and re-proven on the host.** Everything the code/state split's "what is
  still unproven" list demanded, on the exact commit, from CI-green preflight
  through teardown. See `samples/lab-run-2026-08-15-installer-validation.md`
  (gitignored) for the full transcript map.

  **Proven live, all on `54b90db`'s own bytes:** clean install from absent
  roots (exit 0, both trees claimed, built, and read-back-proven); reinstall
  over the result (both roots recognised as ours, runtime retired → rebuilt →
  retired copy deleted, dotenv preserved no-clobber); **refusal of the real
  old-layout tree** (the §4 BREAKING behaviour, actionable message naming the
  violations and the rescue list); **refusal of a genuine non-admin pre-plant**
  (a throwaway local user pre-created a ProgramData state root with a hostile
  `acme-ra.env` — refused, tree untouched, refusal precedes any dotenv read;
  and its attempt to pre-create under `%ProgramFiles%` is access-denied, so
  the code root cannot be pre-planted at all); **rollback** (deliberately
  corrupted pinned hash → build fails after retirement → previous runtime
  restored byte-identically, zero `.retired-*` leftovers, and after the
  by-hand pool restart the old runtime still serves `/directory` 200);
  **the gMSA `RX` grant launches uvicorn** — HttpPlatformHandler starts the
  ProgramFiles venv as the domain gMSA and `/directory` answers 200 with the
  app running as the gMSA identity; **the §4 migration walked end to end**
  (backup → rescue → read-the-dotenv → rename → fresh install → restore db/env
  byte-identical → re-run installer → web.config processPath → verify: §5
  shape, owners Administrators, spnego imports, db integrity + counts
  unchanged).

  **Two escaped defects found and fixed on the branch (both the WI-050
  class — PowerShell semantics invisible to Linux CI):**
  1. `icacls /save` writes UTF-16LE **without BOM**; `Get-Content -Raw`
     decoded it as ANSI on Windows PowerShell 5.1 (this pwsh *sniffs* BOM-less
     UTF-16, which is why local Pester was green) — the ACL proof failed
     closed on a healthy tree and blocked every install. Fixed in `b816352`
     (`Get-IcaclsDumpText`, byte-sniffed decode, ordinal `StartsWith`).
  2. The state-root claim's `icacls /reset /t` strips the dotenv's protected
     DACL, and it was only re-applied ~150 lines later — a build failure in
     between (the rollback path) left `acme-ra.env` inheriting gMSA **Modify**
     (EAB allowlist + SAN scopes worker-writable), and the *next* pre-flight
     then correctly refused the tree, bricking the install. Fixed in
     `54b90db` (re-protect immediately after the claim; the rollback catch now
     re-protects and re-proves the state tree too). Both fixes re-proven live
     on the host: the failed-build rerun prints "state tree re-protected and
     re-proven" and the dotenv survives the failure protected.

  **Also closed:** the `*S-1-5-32-544` star form **works** for
  `icacls /setowner` on this host (previously "unverified for that verb").

  **Not proven:** the no-rollback proof-failure path (a runtime that builds
     but fails its proof — the honest "app pool left stopped deliberately"
     message); a `-ConfigureIIS` first install from bare IIS (the lab host
     already had the site); the user-scoped-Python copy path was exercised,
     the machine-wide reference path was not (the host's 3.13 lost the
     launcher preference to the profile 3.14).

  **Host end-state (deliberate, not restored):** the lab RA now runs the
  two-tree layout on `54b90db`'s runtime with the same store (counts
  22/5/21/87, unchanged), same dotenv, same siem trail; the old tree is
  preserved at `C:\ProgramData\acme-adcs-ra.preSplit` as the migration
  rollback artifact; `web.config` processPath points at the ProgramFiles
  venv. The CA host was never touched (no issuance, no revocation, no
  ca-provision this run). Refusal runs leave the app pool stopped
  (fail-closed; restart by hand) — observed behaviour worth knowing
  operationally, not a defect.

- **Full E2E lab validation — PASSED (2026-08-15) on `2d6ac20`, the tip after the
  two fixes the `b028b96` pass produced plus the three CI/test/PowerShell commits
  behind them.** Preflight green on the exact commit (CI, ruff, mypy, pytest
  768/1, Pester 148). Deployed by the ordinary installer (exit 0) and asserted on
  the *installed* package; the hash-pinned closure installed clean into a
  throwaway venv on Windows/3.14. **No new product defect found.** The
  sync-path PowerShell fix (`2d6ac20`) is exercised live: the agent ran to
  completion six times on this deployment.

  **What passed.** §A 14/14, §A1 front controls 13/13, §G 5/5 (removed GET
  routes answer 405), both transport-orphan branches 6/6, the revocation round
  trip three times (R 5/5 + Rverify 3/3 each: through the registered task as the
  gMSA, then the agent-authority pair, then under CRL evidence). Agent authority:
  admin-token-only exits 2 with the confirm 401'd; confirm-token-only completes
  with no admin token present at all. CRL evidence fails closed
  (`crl-evidence-required-but-absent`) until an administrator republishes, then
  records `crl-verified`. Least privilege live: the gMSA is denied CRL
  publication (`0x80070005`), denied an out-of-template revocation
  (`CERTSRV_E_RESTRICTEDOFFICER`), and its token carries no domain groups (E-1).
  Reason 8 refused inside the gMSA context by `Revoke-Cert.ps1` (exit 3, exact
  error text). The lease: §L 9/9 (migration on the real store, pre-existing
  orders still generation 0, in-flight reclaims refused by the registry) and
  §Lqueue 8/8 (saturation 40 sockets, target provably queued — committed to
  `processing` with **no** enrollment audit row — reclaim denied
  `enrollment-in-flight`, nothing reopened, re-finalize takes a fresh lease).

  **The WI-053 deployment shape, proven live for the first time.** The sync task
  registered with `-RevocationSyncOnly -ConfirmToken` only: the task action
  loads **only** `ACME_RA_REVOCATION_CONFIRM_TOKEN` from the ACL'd dotenv at run
  time (F2), contains no admin-key load and no literal token, runs as the gMSA
  with LogonType Password — and that task drained every revocation this run
  queued. The revocation host needs no admin authority, in the deployed
  artifact, not just in the script.

  **STILL NOT established: the durable lease stopping a stale worker.** Third
  run, same verdict — raced, neither confirmed nor refuted. The contested
  order's two `finalize-enrollment-transport-failed` rows are sequential: the
  gen-1 worker ran and returned (transport failure) before the SQL-reclaim +
  re-finalize could invalidate it, so no worker ever survived a generation bump
  and no `finalize-enrollment-abandoned` row exists anywhere. `total_abandoned=0`
  with Ld4/Ld5 holding (no order anywhere has two certificates; the contested
  order has none — the CA never issued for it). Ld1 remains the documented
  non-defect: 86 orders wedge in `processing` for operator reconciliation.

  **The CRL cadence finding stands unchanged** (CRL3 FAIL by design of the
  check): 7d 12h20m validity window vs the 604800s default ceiling — the WI-052
  operator item, configuration not code. The lower bound still requires a
  measured maximum CRL age at scheduled replacement, including `thisUpdate`
  backdating and clock skew.

  **Two harness defects found (not product).** (1) Lqueue's saturation counter
  reads `ca-ip.txt`, which held the *real* CA address, but the §9-approved
  blackhole is **config-mode** (`ACME_RA_ADCS_HOST=192.0.2.1`), so it counted
  the wrong destination and failed at `ca_sockets=2` while the substantive
  checks passed — the counter must be pointed at the blackhole address in that
  mode (re-run then measured 40/40 clean). (2) `bh-off.ps1` only clears the
  *firewall* blackhole; the config blackhole needs the explicit
  `setenv ACME_RA_ADCS_HOST` restore, which teardown.ps1 does. Also: the lab's
  key-auth SSH admin logon **cannot DCOM to the CA** (it carries no network
  credential —
  `RPC_S_SERVER_UNAVAILABLE` on `-ping` while the same call succeeds on the CA
  console and as the gMSA task), so teardown revocations must run through the
  gMSA runner. The §2 ssh-quoting trap claimed three more victims this run
  (icacls `$:`, a method call, a pipe under cmd.exe).

  **Teardown verified, not assumed.** All five certificates this run caused the
  CA to issue revoked — including the untracked ReqID-only orphan (ReqID 201,
  serial `6c…c9`) — and the CRL republished; CA back to 224 bytes / 4 ACEs /
  `OfficerRights: ABSENT`; `denyUrlSequences` empty; RA store restored from the
  pre-run backup and **fingerprint-identical** (integrity `ok`, every row count
  equal); tasks unregistered; dotenv verified free of throwaway credentials;
  web.config back to its pristine 10-variable set; harness temp removed on both
  hosts. Artifacts table in `samples/lab-run-2026-08-15-notes.md`.

- **Full E2E lab validation — PASSED (2026-08-14) on `b028b96` + two fixes it
  produced, with one claim still NOT established.** The first full pass over the
  whole 2026-08-15 → 2026-08-18-wave-3 security series; every one of those
  rounds had landed on `main` without a live run. Deployed by the ordinary
  installer and asserted on the *installed* package. **Two defects found, both
  invisible to CI, both in PowerShell that CI never executes.**

  **Defect 1 — the pinned installer could not install at all.** `install-windows.ps1`
  aborted with "Bundled pip is too old for --require-hashes" against pip 26.2.1.
  `(& $venvPy -m pip --version) 2>&1` returns a two-element `Object[]` (the
  banner plus pip's trailing empty line), and `-match` against an ARRAY filters
  the collection instead of capturing, so `$Matches` was never set, `$Matches[1]`
  read as `$null`, `[int]$null` was 0, and `0 -lt 23` threw. Live from `fb3a14e`
  (2026-08-16), which introduced the floor check — **every fresh install on
  Windows, the RA's only production platform, was broken for the whole series.**
  Fixed by `Get-PipMajorVersion` in `lib/InstallVerifyLib.ps1`, covered by tests
  fed the real two-element array captured on the host.

  **Defect 2 — the wave-3 F1 fix was inert in exactly the case it existed for.**
  `Test-SerialRevokedAtCa` correctly detected a disposition-21/reason-8 row, then
  defeated itself: its three `Write-Output` diagnostics joined the return value,
  because a PowerShell function returns its whole success stream. The call site
  is `if (Test-SerialRevokedAtCa ...)`, `@(three strings, $false)` is a non-empty
  array, and a non-empty array is truthy. Proven end to end against the real CA:
  a certificate placed off the CRL and **still valid** was reported "ALREADY
  revoked", exiting 6 — which drains the serial off the RA's pending feed and
  records `revocation-ca-confirmed`, booking a containment failure as a success.
  Diagnostics moved to `[Console]::Error.WriteLine` (the file's own idiom for
  exactly this reason); re-run live afterwards, exit 0 and a real re-revocation.
  Both branches of the function had the defect. Nothing covered this function —
  it lives in `Revoke-Cert.ps1`, not `lib/`, so the Pester suite never saw it;
  it is now covered by AST-extracting the shipped text.

  **What passed.** §A issuance 14/14 (EKU exactly `serverAuth`, SAN from CSR,
  chain to root, CA policy denial mapped, reasons 7/8 refused). §A1 front
  controls 13/13 (JWS/EAB URL pinning, kid locality, deactivation, cross-account
  401, nonce ceiling). §G 5/5 — the removed GET routes answer **405, not 401**.
  Both transport-orphan branches 6/6 each: leaf-in-hand quarantined with serial
  and ReqID and queued; ReqID-only leaves no row, only the audit record. The
  revocation round trip drained three times through the registered task running
  as the gMSA. Least privilege, live: the gMSA is **denied** CRL publication
  (`0x80070005`) and **denied** an out-of-template revocation
  (`CERTSRV_E_RESTRICTEDOFFICER`), and its token carries **no domain groups at
  all** (E-1 hardening). Agent authority: admin-token-only exits 2 with the
  confirm 401'd, confirm-token-only completes with no admin token present. CRL
  evidence fails closed (`crl-evidence-required-but-absent`) until an
  administrator republishes, then records `crl-verified` with CRL number 87.
  The account-JWK twin migration applied to the real 21-account store: every row
  canonical, zero duplicate thumbprints, the UNIQUE index present, integrity
  `ok`. The lease: 9/9 and 8/8, the queue gap reproduced and refused
  `enrollment-in-flight` with the age floor at 0 so it cannot have answered.
  The hash-pinned closure installs clean into a throwaway venv on Windows/3.14.

  **The Windows CRL watchdog, proven where it was previously absent.** A hostile
  server that sends headers and goes silent is cut at **3.01 s** against a 30 s
  per-read timeout, on `win32`, reporting the deadline rather than a bare read
  timeout, and fails closed (`checked=False`). This is the control that existed
  on Linux and was missing on Windows for the whole of the 08-17 round.

  **STILL NOT established: the durable lease stopping a stale worker.** Same
  outcome and same evidence as the 2026-08-14 run, reached independently: the
  contested order's two `finalize-enrollment-transport-failed` rows are
  **sequential** (21:23:18 then 21:23:19), so the gen-1 worker returned before
  the gen-2 re-finalize began and no stale worker ever survived a generation
  bump. Neither confirmed nor refuted; still unit-tested and mutation-proven
  only. It needs a CA stand-in that accepts the connection and stalls.

  **Observation 1 of the previous run is confirmed, and is by design.** Orders
  wedge in `processing` after a connect-level transport failure (43/43 here) and
  nothing ever retires them: `Store.sweep_expired_orders` sweeps only
  `pending`/`ready` and documents `processing` as "operator-reconcilable". A
  client retry does take a fresh lease, so orders are not bricked — but a CA
  outage still turns every in-flight order into operator work.

  **The CRL cadence finding stands unchanged.** This CA's 7d 12h 20m validity
  window still exceeds the 7-day default ceiling. The override is plumbed and
  works (`ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS=691200` reads back as
  691200 against a 604800 default), proving the setting is configurable. That
  8-day test value is **not** a safe production value for this CA: it exceeds
  the 649200-second `nextUpdate` window and would leave the independent age
  ceiling non-binding. Production must measure `A_sched_max` and choose
  `A_sched_max < max_age_seconds < 649200`; the repository does not supply the
  numeric lower bound.
  *(Record retained as written. **Superseded 2026-08-27**: `A_sched_max` was
  measured at 649800s, so that interval is empty — it is empty for any CA. See
  §F and `operations.md` → Deriving the ceiling.)*
  *(**That supersession is itself withdrawn, 2026-09-05.** "Empty for any CA" is
  false: it followed from measuring `A_sched_max` off the published window
  instead of off the CDP's output. Sampled, the maximum age this CDP serves is
  603654s, and the interval `A_sched_max < max_age_seconds < 649200` this record
  originally specified is 43746s wide and contains the shipped default of
  626400. **The record as first written was right; the correction was the
  error.**)*

  **Teardown verified, not assumed.** CA back to 224 bytes / 4 ACEs /
  `OfficerRights: ABSENT`, `denyUrlSequences` empty (checked via the full
  `appcmd` path after a PATH miss made a first check meaningless), all five
  certificates this run caused the CA to issue revoked — including the
  ReqID-only orphan that nothing tracks — and the CRL republished. The RA store
  restored and **verified against the pre-run fingerprint**: integrity `ok` and
  every row count identical. Tasks unregistered, dotenv restored, web.config
  back to its exact pristine 10-variable set. Ten ACME-template certificates
  from *earlier* sessions remain issued at the CA — pre-existing, not this run.

- **Enrollment-lease live re-proof — PASSED (2026-08-14) on `1832163`, with one
  claim explicitly NOT established and three observations opened.** Targeted at
  the 2026-08-15 rescan fix rather than a full pass: §A issuance regression, the
  removed GET routes, and a new lease phase. Deployed by the ordinary installer
  and confirmed on the *installed* package, not the source tree — the version
  string is `1.9.1` both before and after this change, so it proves nothing on
  its own.

  **§A issuance regression + removed GET routes, 19/19.** A real certificate
  issued with EKU exactly `serverAuth`, SAN from the CSR, chain to the existing
  root. `GET /acme/cert/{id}` and `GET /acme/authz/{id}` return **405, not 401**
  — the routes are unregistered, not merely refusing, which is the stronger
  evidence and the one the previous harness could not have distinguished.

  **The lease, 9/9 + 8/8.** The migration applied to the real production-shaped
  store (integrity `ok`, all 22 pre-existing orders still at generation 0, row
  counts unchanged). A normal issuance mints generation 1 and completes. Against
  a genuinely running enrollment, repeated reclaim attempts were refused
  `enrollment-in-flight` and **none ever reopened the order**.

  **The queue gap — the finding's own schedule — reproduced and refused.** With
  the threadpool saturated (40 concurrent hung enrollments, confirmed by socket
  count against the CA address) one further finalize was submitted. Its order
  committed to `processing` while the audit log showed **no enrollment event for
  it at all**, proving its task had never run. Reclaiming that order was refused
  `enrollment-in-flight`, with `reclaim_minimum_processing_age_seconds=0` so the
  age floor could not have been what answered. Before the fix this returns 200
  and reopens the order.

  **NOT established: the durable lease stopping a stale worker.** The attempt
  bypassed the in-memory mark by reclaiming in SQL, but the audit trail shows
  two `finalize-enrollment-transport-failed` rows for the contested order —
  both tasks ran, so the stale-worker condition was never created. The lease
  check remains unit-tested and mutation-proven only. Reproducing it live needs
  a CA stand-in that accepts the connection and stalls, so enrollments expire on
  a read timeout at staggered times instead of all at once.

  **Three observations, none security-blocking:**
  1. **A connect-level transport failure leaves the order wedged in
     `processing` permanently** (no revert on `ca_issued=False`) and returns
     503. This run produced 285 such failures and therefore 285 wedged orders.
     Recovery is an admin reclaim that asks the operator to confirm at the CA
     database that nothing was issued — when the RA already knows the CA was
     never reached. A CA outage turns every in-flight order into an admin
     ticket.
  2. **Under ~42 concurrent hung enrollments the RA takes ~21 s to admit a new
     request**, and admin reclaims serialise (the handler does its SQLite work
     on the event loop).
  3. **Measured end-to-end finalize against the real CA is ~0.4–0.5 s.** The
     `reclaim_minimum_processing_age_seconds` default of 60 s is ~120× that.
     The figure it was reasoned from (4 × 30 s per-call timeouts) is a
     worst-case bound, not the operating point; the floor should be set from
     measurement.

  Lab left pristine: all 8 certificates this run caused revoked at the CA
  (`21 -- Revoked`) and the CRL republished; store, dotenv and `web.config`
  restored and **verified against a fingerprint taken at backup time** (integrity
  `ok`, every table count identical); app pool back to `Started`.

- **v1.9.1 live re-proof — PASSED (2026-08-14), one blocking defect found and
  fixed, three residuals opened.** Run against commit `bef2022`, which is
  `v1.9.0-rc2` plus the two fixes this run produced — and the reason the shipped
  version is **1.9.1**: 1.9.0 never released, because this run is what found the
  two things wrong with rc2. This is the full
  pass the rc1 row below demanded: **§A, §A.1, §B/§C, §D, §E from a clean
  start**, plus every case the 2026-08-14 review added. The whole sequence is
  automated end to end, so it is repeatable rather than a one-off; the
  methodology, the access paths and the tricks for provoking each path live in
  a gitignored runbook (`samples/lab-validation-runbook.md`) because they name
  the real hosts.

  **Before anything was measured: the tip was CI-red.** `v1.9.0-rc2`
  (`cb1285c`) failed `ruff` on three `RUF059` findings in the new review tests
  — the lint job, on all three Python versions. Fixed in `a3e68d8`. Proving a
  commit that cannot ship is wasted lab time, so this is now the first
  preflight step.

  **§A — issuance (real CA), 14/14.** Full round-trip issued a real
  certificate: EKU exactly `serverAuth`, SAN from the CSR, chain leaf → issuing
  CA → existing root, and the CA database recording the requester as the
  enrollment gMSA under `ACME-ServerAuth`. An out-of-scope SAN is refused at
  finalize; an EC P-256 key draws a genuine `Denied by Policy Module` from the
  CA, mapped to `400 rejectedIdentifier`.

  **Reason 8 is refused, and no path emits it** (the 2026-08-14 blocker).
  `revokeCert` with reason 8 → `400 badRevocationReason`; the certificate stays
  valid, is still served, and **is not queued** for CA-side revocation.
  `Revoke-Cert.ps1 -Reason 8` exits **3** before it touches `certutil`. Reason 7
  likewise refused.

  **§A.1 — front controls, 13/13.** URL binding pinned to `base_url` (JWS `url`
  + `Host:` naming another deployment → rejected; EAB naming another deployment
  → `badExternalAccountBinding`; foreign `kid` → rejected), deactivation then
  401, POST-as-GET resolves order/account/orders, another account's certificate
  → 401, `/docs` `/redoc` `/openapi.json` → 404, and the nonce ceiling returning
  a 204/429 mix with `Retry-After`.

  **The transport-orphan quarantine, against the real CA — both branches.**
  Provoked by making the CA refuse exactly one Web Enrollment URL (IIS request
  filtering scoped to `/CertSrv`), so the CA genuinely issues and the RA fails
  after it:
  - `certnew.p7b` refused (leaf in hand) → **500**, order terminal-`invalid`, a
    `quarantined` row carrying serial and ReqID, queued for CA-side revocation,
    never served on a retried finalize. The CA confirms the certificate as
    `Issued` — and the ordinary pull agent later revoked it, which is the whole
    design closing.
  - `certnew.cer` refused (ReqID only) → **500**, order terminal-`invalid`, **no
    row** (the RA never received the bytes), and the ReqID made loud in the
    audit. Both orphans were revoked by hand at teardown, which is exactly the
    operator action this branch documents.

  **§C — revocation round trip, as the gMSA, through the shipped registration
  path.** `Register-MaintenanceTasks.ps1` registered the sync task
  (`LogonType=Password`), the task ran as `gMSA-acme-ra$`, revoked at the CA and
  confirmed back: CA disposition `Revoked` with the requested reason, RA pending
  set drained to empty, exit 0.

  **Authority separation, end to end.** The admin token is **refused** on the
  confirm endpoint (401) — both directly and through the agent: an agent given
  only the admin token revokes at the CA, fails every confirm, leaves the serial
  pending and **exits 2**. The same agent given only `-ConfirmToken` — no admin
  token anywhere — reads the pending list, confirms, drains the queue and exits
  0.

  **CRL evidence, against the real ADCS CRL.** With
  `revocation_confirm_require_crl_evidence=true`: the confirm is **refused**
  (`400`, audit `reason: crl-evidence-required-but-absent`) while the serial is
  not yet on a published CRL — the scoped officer cannot publish one
  (`certutil -CRL` → `0x80070005`). After an administrator republished, the same
  confirm succeeded with audit `verification: "crl-verified"`, carrying the CRL
  number and `thisUpdate`. Fail-closed control and positive both observed.

  **§C least privilege / §D enrollment bound.** As the gMSA: CRL publication
  denied `0x80070005` (no Manage-CA); revoking a certificate on another template
  denied `0x80094009 CERTSRV_E_RESTRICTEDOFFICER` (template scoping enforced);
  and the live token shows **no `Domain Computers`** — the E-1 hardening still
  holds.

  **The pinned installer runs on Windows.** `install-windows.ps1` installed from
  `deploy/requirements.lock.txt` with `--require-hashes --only-binary :all:`,
  exit 0. Stronger form also checked: the full 29-package closure — exported on
  Linux for 3.13 — installs clean into a **throwaway venv** on Windows /
  Python 3.14, so every wheel was actually fetched and hash-verified rather than
  reported "already satisfied". No platform wheel gap.

  ### The defect this run found

  **`Set-OfficerRights.ps1` could not provision a CA that had no `OfficerRights`
  value — the default, and therefore the first-provisioning path.** It aborted
  with `Buffer cannot be null` and wrote nothing, *after* the CA-side
  Certificate Manager grant had already been made, leaving the CA
  half-configured. Cause: the 2026-08-13 fix for the single-element unwrap
  wrapped every return in `,$result`, and `,@()` reaches the call site as a
  one-element array holding an empty array — so `@(Get-ExistingAces $b).Count`
  was 1 with no ACEs and the phantom entry went into the ACE builder with a null
  `RawAce`. Fixed in `bef2022`; provisioning then succeeded on the pristine lab
  CA and the template scoping enforced correctly.

  It **reproduces under pwsh 7 on Linux** — unlike the previous round's two
  defects, CI could have caught this one. It did not, because the two Pester
  tests covering the empty case asserted `$result = Get-ExistingAces $null`,
  and assignment collapses a single-item pipeline back to the item, while the
  shipped code says `@(Get-ExistingAces …)`. **The tests asserted a shape the
  shipped code never uses.** They now assert the call-site expression, and
  reverting the library fix fails them.

  ### Residuals this run opened

  - [ ] **A quarantined transport orphan can never satisfy
        `revocation_confirm_require_crl_evidence=true`.** The chain-fetch
        failure *is* the orphan case, so the quarantined row has **no stored
        chain** — and CRL evidence pins the issuer by selecting, from the
        certificate's own stored chain, the key that signed it (the F12 fix).
        Observed live: `could not locate the issuing CA certificate in the
        stored chain, so the CRL signature cannot be verified`. The serial is
        revoked at the CA on every run and confirmed on none, so the queue never
        drains and the agent exits 2 forever. Fail-closed, so not an exposure,
        but a guaranteed stuck queue. **Default configuration is unaffected** —
        verified: with the default (`false`) the same serial confirmed as
        `agent-asserted` and drained. Needs a decision on which trust source may
        verify a CRL for a chain-less row.
  - [x] **WI-052 CLOSED 2026-08-24 — a number now exists.** The ceiling is
        derived from the CA's own config (`CRLPeriod`, `ClockSkewMinutes`,
        computed overlap), and the derivation predicts this CA's measured
        `649200s` window exactly. `A_sched_max = 605400s`; recommended
        `max_age_seconds = 626400` (mid-headroom). Original item follows.
  - [ ] **WI-052 remains an operator setting, not a code gap.** `CRLPeriod = 1
        Week` (604800s), and the published CRL's validity window is **7d 12h
        20m** (649200s) against a default `revocation_confirm_crl_max_age_seconds`
        of 7 days. The runbook now requires measuring `A_sched_max`, the maximum
        CRL age at scheduled replacement including `thisUpdate` backdating and
        clock skew, then using `A_sched_max < max_age_seconds < 649200`. The
        repository does not record `A_sched_max`; a value beyond 649200 would
        make the independent replay-age ceiling non-binding. The freshness gate
        itself was confirmed live (a 1-second ceiling refuses the real CRL).
        *(Record retained as written. **Superseded 2026-08-27**: `A_sched_max`
        measured at 649800s, so that interval is empty — for any CA. The
        non-binding ceiling this entry warns against is now the documented,
        deliberate default. See §F.)*
        *(**Withdrawn 2026-09-05.** `A_sched_max` is the age the CDP *serves*,
        measured at 603654s, not the window. The interval is 43746s wide, the
        default is 626400 and binds, and the warning this entry raised against a
        non-binding ceiling was correct all along. See §F.)*
  - [x] **`Register-MaintenanceTasks.ps1` re-introduces the admin token on the
        revocation host.** `-AdminToken` was mandatory and always written into
        the revocation-sync task action as `$env:ACME_ADMIN_TOKEN`, even when a
        confirm token was supplied — which undoes, at deployment time, the
        authority split the confirm token exists to create. **Resolved in the
        2026-08-15 review (finding 3):** `-AdminToken` is now optional, and
        `-RevocationSyncOnly -ConfirmToken …` registers only the sync task with
        zero admin-token bytes in its action. See docs/operations.md.
  - [x] **The plain GET forms are removed (finding 4, 2026-08-15).**
        `allow_unauthenticated_resource_get` was exercised both ways: with it
        **off**, a complete order still issues through POST-as-GET only. On that
        basis (and RFC 8555 conformance) the owner + Sol closed the loop
        entirely — both plain GET routes and the config flag are removed; a plain
        GET now returns 405. The re-proof runs against the POST-as-GET-only RA;
        if Certify the Web regresses, file a CtW bug (it uses Certes, which does
        POST-as-GET).

  **Lab returned to its pre-run state** (verified, not assumed): CA security
  descriptor byte-identical at 224 bytes with its four original ACEs,
  `OfficerRights` absent, `denyUrlSequences` empty, `certsvc` running; every
  certificate this run caused the CA to issue revoked and the CRL republished;
  scheduled tasks unregistered; RA store and dotenv restored from the pre-run
  backup (`integrity_check` ok, matching row counts); app pool left `Started` as
  found; temp directories cleared on both hosts. Ten unrevoked ACME test
  certificates from *earlier* sessions remain and were deliberately not touched.
  The E-1 hardening was left in place, as the runbook requires.

  **Teardown hazard worth recording:** restoring the SQLite store by copying the
  backup `.db` over a newer database corrupted it (`database disk image is
  malformed`) — the write landed while the worker still held the file. Stop the
  pool, confirm it is actually `Stopped`, remove `acme_ra.db` **and its `-wal`
  / `-shm` sidecars**, then copy. Re-done that way, `integrity_check` returned
  `ok` and the row counts matched the backup exactly.

- **v1.9.0 live re-proof — PASSED (2026-08-13), with two defects found and
  fixed.** Run against commit `26eae31` (the 2026-08-13 security review),
  deployed as a wheel into the gMSA app-pool venv on the lab RA host with
  `scripts/` and `scripts/lib/` shipped alongside. This closes proof gaps 1–3
  of `docs/security-review-2026-08-13.md`, which had shipped ten security fixes
  validated **only against fakes on Linux**.

  **§A — issuance + EKU (real CA).** Full ACME round-trip (new-account EAB →
  order → challenge → finalize → cert) issued a real certificate: EKU exactly
  `serverAuth`, `clientAuth` absent, SAN taken from the CSR, chain leaf →
  issuing CA → existing root (no new intermediate), requester recorded in the CA
  database as the enrollment gMSA. Out-of-scope SAN rejected at finalize; a CSR
  whose SANs did not match the order rejected before the CA saw it; reason 7
  rejected with `badRevocationReason`; revoked certificate → `410 Gone`. The
  strict chain validator did **not** false-reject — a successful issuance is the
  only proof of that, and no unit test can give it.

  **§A.1 — ACME front controls.** All passed: JWS `url` naming another host
  rejected against `base_url` (not the request Host); an EAB or `kid` naming
  another deployment rejected; account eviction on kid rename — **with the
  control first** (a new account under the renamed kid must succeed) — old
  account `newOrder` and `revokeCert` both 401; deactivation then 401;
  POST-as-GET of order/account/orders resolving while another account's
  certificate is refused; `/docs`, `/redoc`, `/openapi.json` all 404; the nonce
  ceiling returning a 204/429 mix with `Retry-After`.

  **§C — automated revocation, single-identity.** The enrollment gMSA was
  granted Certificate Manager (`0x2`, **not** Manage-CA) plus template-scoped
  `OfficerRights`, and the registered scheduled task ran as the gMSA: serials
  revoked at the CA and confirmed back to the RA, pending set draining. The
  least-privilege bound held live and visibly — `certutil -revoke` **succeeded**
  while the `-PublishCrl` republish was **denied** `0x80070005` (needs
  Manage-CA), and a certificate issued from a *different* template was refused
  `0x80094009 CERTSRV_E_RESTRICTEDOFFICER`.

  **§D — enrollment-side bound.** The gMSA's **live token** carries no Domain
  Computers membership (the WI-035 / Finding E-1 hardening persists), and
  issuance continued to work throughout.

  **2026-08-13 review findings, exercised against the deployment:** separated
  confirm authority — the admin token is refused on the confirm endpoint, the
  confirm token is accepted, and an unset confirm token disables the endpoint
  (finding 1); the sync agent refusing a non-https / credential-bearing / path-
  bearing RA URL **with a listener proving no request carrying the Bearer token
  left the host**, plus a control showing the listener would have caught one
  (finding 4); startup refusing an `audit_offbox_required` deployment whose sink
  cannot emit (finding 5); a certificate the CA issued outside policy
  **quarantined** — recorded with its serial and ReqID, order terminal-invalid,
  queued for CA-side revocation, and never served on a retried finalize
  (finding 6); an unknown nonce answered `400 badNonce` in ~44 ms rather than
  blocking on the writer lock (finding 7); credential floors refusing startup on
  short tokens and on an EAB `mac_key` decoding to zero bytes, while accepting
  every credential `scripts/eab.py` generates (finding 9); malformed JWS field
  types answered 4xx, not 500 (finding 10).

  **CRL evidence against a real ADCS CRL (closes proof gap 2).** With
  `revocation_confirm_require_crl_evidence` set, a serial the CA had really
  revoked confirmed as `verification: "crl-verified"`; the **negative control**
  — a serial absent from the CRL — was refused, fail-closed; with evidence made
  optional the same serial confirmed as `agent-asserted`. Note the operational
  coupling observed live: the serial only reached the CRL after an
  administrator republished it, because the scoped officer cannot.

  **Two defects found, fixed, and re-verified live** (see the CHANGELOG
  `[Unreleased]` entry): `Set-OfficerRights.ps1` aborting on a *successful*
  single-officer provisioning (a Windows PowerShell 5.1 `.Count` semantic the
  Linux Pester suite structurally cannot see), and `Sync-Revocations.ps1`
  aborting the whole batch on the first failed revoke instead of logging and
  continuing. Both were re-run against the CA after fixing: provisioning exits 0
  and reports the ACE correctly; the batch now continues past a failure and
  exits 2 (partial), as documented.

  - [x] §A re-cleared on the deployed commit (live issue + denial + revocation).
  - [x] §F revocation runbook re-exercised (`Sync-Revocations.ps1` +
        `Revoke-Cert.ps1` requester check, live at the CA).
  - [x] **The proven artifact is NOT the shipped artifact — a fresh full pass is
        required before the v1.9.0 tag.** Everything above ran against
        `26eae31`. The two fixes landed after it, as did the release-preparation
        changes (docs, an IPv6-loopback fix in `Assert-SafeRaUrl`, and
        `__version__`). The issuance leg is untouched by all of them and both
        defects were re-run live after fixing, but `Set-OfficerRights.ps1` and
        `Sync-Revocations.ps1` are not the bytes that were proved end-to-end
        from a clean start.

        This is not a formality. The runbook's cadence rule — *a full live
        re-proof at every release, on the exact commit being shipped* — is
        precisely what caught these two defects, and both were invisible to a
        green Linux CI run. Waiving it for the commit that fixes them would draw
        the wrong lesson. **Re-run the full runbook — §A, §A.1, §B or §C, §D,
        §E — against `v1.9.0-rc2`, from a clean start, and add a second
        validation-log entry before the v1.9.0 tag.** Full scope rather than
        the PowerShell delta: the lesson of this round is exactly that a subset
        does not transfer.

        **The target is now `v1.9.0-rc2`, not rc1.** A second external scan
        (2026-08-14, `docs/security-review-2026-08-14.md`) found seventeen more
        findings against rc1, two of them blocking, and all seventeen are fixed
        in rc2. The re-proof was correctly *not* run against rc1.

- **Additional cases the 2026-08-14 review adds to the re-proof.** These are
  the fixes whose correctness genuinely cannot be established off a real CA:

  - [x] **Reason 8 is refused, and never reaches `certutil`.** Submit a
        `revokeCert` with `reason: 8` → **400 badRevocationReason**, and the
        certificate must remain valid and absent from the pending list. Then run
        `Revoke-Cert.ps1 -Reason 8` directly → **exit 3**. Plan 004 recorded
        that reason 8 leaves a held certificate "off the CRL and valid", so the
        point is that no path can now emit it.
  - [x] **The transport-orphan quarantine, against a real CA.** The fix most in
        need of live proof, because provoking it means interrupting the RA
        between the CA's "issued" response and the chain fetch — and the whole
        question is what the CA is left holding. Confirm the certificate is
        recorded `quarantined` with its serial and ReqID, is queued for CA-side
        revocation, is never served, and that the order is terminal. Confirm the
        ReqID-only branch too (block `certnew.cer`): no row, but a loud audit
        row carrying the ReqID.
  - [x] **The pinned installer runs on Windows.** `--require-hashes` with
        `--only-binary :all:` is stricter than what the host did before, and the
        lock file was exported on Linux for Python 3.13 — a platform-specific
        wheel gap surfaces only here.
  - [x] **CRL freshness against the real publication cadence — measured
        2026-08-14, and the default has zero delay margin.** The lab CA publishes
        weekly (`CRLPeriod = 1 Week` = 604800s) and its CRL declares a **7d 12h
        20m** validity window (= 649200s). The lower bound must instead be the
        measured `A_sched_max` at scheduled replacement, including `thisUpdate`
        backdating and clock skew; the repository does not record that value.
        Configure `A_sched_max < revocation_confirm_crl_max_age_seconds < 649200`.
        Do not widen it past `nextUpdate`: after that hard expiry the CRL must
        fail closed, and the independent age ceiling must remain binding. The
        gate itself is live — a 1-second ceiling refuses the real CRL, and the
        default accepts it.
  - [x] **The unauthenticated GET forms are removed (finding 4, 2026-08-15).**
        Closed entirely on RFC 8555 conformance grounds: `GET /acme/cert/{id}`
        and `GET /acme/authz/{id}` and the `allow_unauthenticated_resource_get`
        flag are gone; only account-scoped POST-as-GET remains, and a plain GET
        returns 405. The re-proof should confirm Certify the Web completes a full
        round-trip against the POST-as-GET-only RA; if it does not, that is a CtW
        bug to file. (The test harness already drives a complete order to
        issuance via POST-as-GET only.)
  - [x] **The revocation agent runs with only `-ConfirmToken`.** No admin token
        on the revocation host: confirm the pending-list read still works and
        the whole loop completes.
  - [x] **A failed confirm exits 2.** Point the agent at an RA that will refuse
        the confirm; the CA-side revocation should succeed, the serial stay
        pending, and the script exit 2 rather than 0.
  - **Still open before pilot:** the operator-owned items in §B–§E, unchanged.
  - **Lab returned to its pre-run state:** CA `OfficerRights` removed and the CA
    security descriptor restored byte-for-byte, the temporary group membership
    removed, the throwaway template deleted and unpublished, every test
    certificate revoked and the CRL republished, scheduled tasks unregistered,
    RA database and dotenv restored from a pre-run backup, app pool left running
    as found. The RA venv now holds the **v1.9.0** package (it held v1.7.0 before
    the run).

- **2026-06-24 — §A cleared.** Working tree committed; CI green on the deployed
  commit (`lint-typecheck-test` 3.12/3.13 + `pip-audit`); **live re-issue against
  the deployed commit performed on the lab.** A full ACME round-trip
  (new-account → new-order → challenge → finalize) driven through the deployed RA
  (IIS app pool as the gMSA) issued a real **serverAuth-only** cert with the
  **SAN from the CSR**, off the existing CA, chaining leaf → issuing CA → existing
  root (no new intermediate); the CA database recorded the requester as the gMSA.
  A first attempt was correctly **denied by the CA policy module**
  (`CERTSRV_E_KEY_LENGTH`, an EC test key below the template's minimum) and the RA
  mapped it to `400 rejectedIdentifier` — incidentally exercising the new
  enrollment-error wiring against a genuine CA denial. The throwaway test cert was
  revoked CA-side and the temporary EAB credential removed.
  - **Still open before pilot:** all operator-owned items in §C.4 (network
    allowlist), §C (EAB rotation procedure), §D (admin token), §E (rate
    limiting, crons, monitoring), and the §F revocation-runbook acknowledgement.

- **WI-015 — PASSED (2026-07-13):**
  Live re-proof against commit `7d5c5b9` on the lab RA host. Full ACME
  round-trip (new-account → new-order → challenge → finalize) through the
  deployed RA (IIS app pool as the gMSA, port 9443) issued
  a real **serverAuth-only** cert with the **SAN from the CSR**
  (`reproof.WORK-DOMAIN.local` placeholder — real lab hostname recorded in
  gitignored local notes, not committed per the AGENTS.md identifier rule),
  off the existing CA (`CN=CA01` → existing root, no new intermediate). Serial
  redacted (real lab serial kept in gitignored local notes). A policy-denial
  (out-of-scope SAN `evil-example-com.test`) was rejected at finalize
  with `400`. Revocation with reason=1 succeeded (cert → revoked, GET →
  410). Reason 7 was rejected with `badRevocationReason`. The re-proof
  also found and fixed a Windows-specific SQLite bug (`DELETE ... LIMIT`
  in the probabilistic nonce GC; replaced with a portable subquery).
  - [x] §A re-cleared on the new commit (CI green on the deployed SHA; live
        re-issue + denial + revocation performed).
  - [x] §F revocation runbook acknowledged (`docs/operations.md` ##
        Revocation runbook; `scripts/Revoke-Cert.ps1` lab-validated revoking a
        throwaway cert; reason 7 rejection confirmed at the RA surface).
  - [x] The proven artifact == the shipped artifact (same SHA `7d5c5b9`).

- **MED-1/MED-2 re-proof — PASSED (2026-07-14):**
  Live re-proof against commit `c283d81` on the lab RA host (IIS app pool
  as the gMSA, ADCS CA in Mode A). All 15 test cases passed:

  1.  Account creation (EAB) — PASS
  2.  Order creation (in-scope SAN) — PASS
  3.  Challenge completion — PASS
  4.  Finalize (CSR → real cert from ADCS) — PASS
  5.  Certificate download — PASS
  6.  SAN in cert matches request — PASS
  7.  serverAuth EKU only (no clientAuth) — PASS
  8.  Chain off existing CA (leaf → issuing CA → root, no new intermediate) — PASS
  9.  Policy denial (out-of-scope SAN rejected at finalize) — PASS
  10. Revocation (reason=1, RA store) — PASS
  11. Revoked cert → 410 Gone — PASS
  12. Reason 7 rejected — PASS
  13. **MED-1 positive**: multi-SAN issue (two in-scope SANs), all issued
      cert SANs verified within order scope, no non-DNS SANs — PASS
  14. **MED-1 audit**: zero `finalize-issued-cert-san-mismatch` events in
      the audit log — PASS
  15. **MED-2**: revocation CAS completed deterministically, audit records
      `revocation_scope=ra-store-only`, `ca_crl_updated=false` — PASS

  CA-side verification (via domain admin on the CA host): CA database
  confirms Requester = `WORK-DOMAIN\gMSA-acme-ra$` for both test certs,
  Template = `ACME-ServerAuth`, Disposition = Issued. Both test certs
  revoked CA-side (reason=1) and CRL republished. Lab database restored
  to pre-test state; temporary scripts removed.
  - [x] §A re-cleared on commit `c283d81` (live re-issue + denial +
        revocation + MED-1/MED-2 performed).
  - [x] The live proof ran against source commit `c283d81`; the RC prep
        commit (`4942178` and subsequent fixes) adds only non-issuance
        artifacts (CHANGELOG, SECURITY, CI, checklist). The issuance-path
        source is unchanged between the proof and the RC tag.

- **2026-07-15 — parked at v1.0.0; lab deployment stopped.** The project is
  parked (feature-complete, no active development; see `AGENTS.md` ## Status).
  The lab RA's IIS app pool was **stopped** (verified: pool state `Stopped`,
  ACME directory endpoint unreachable) so no standing enrollment-capable
  identity runs unattended while parked. The deployment remains installed and
  configured — re-enabling for a pilot is `Start-WebAppPool` plus a fresh run
  through this checklist (§A first: re-proof on the deployed commit).

- **WI-028 — v1.5 automated-revocation re-proof — PASSED (2026-07-23):**
  Live E2E re-proof of the v1.5 build (automated revocation + WI-026 EKU
  self-enforcement) on the lab RA host, plus the **single-identity** deployment
  option (Plan 006). Base issuance re-proof went 12/12 (issuance, serverAuth-only
  EKU verified live, chain off the existing CA, out-of-scope SAN denied, revoke →
  410, reason-7 rejected). For revocation, the enrollment gMSA was provisioned as
  a **template-scoped officer** (Certificate-Manager only — no Manage-CA) and the
  `Sync-Revocations.ps1 -LocalMode` agent, scheduled as that gMSA, **revoked
  `ACME-ServerAuth` certs at the CA and confirmed them back to the RA**
  (`ca_crl_updated=true`; pending set drained to empty; CA DB Disposition =
  Revoked). The least-privilege bound held live: `certutil -CRL republish` was
  **denied** for the officer identity (needs Manage-CA), so the default loop skips
  it and relies on scheduled CRL publication (`-PublishCrl` is the opt-in for
  immediate freshness, gated on granting Manage-CA — see threat-model §E). The
  pass found and fixed six PowerShell defects (see `CHANGELOG.md` [Unreleased]
  Fixed); all fixes were re-validated live. CA returned to a pristine baseline
  (no OfficerRights, CA-Security restored) and the RA re-parked (tasks removed,
  app pool stopped) afterward.
  - [x] §A issuance-leg re-proof on the v1.5 build (issuance + WI-026 EKU).
  - [x] Automated revocation round-trip proven (RA `revokeCert` → agent →
        CA revoke → RA confirm) with WI-022 requester check + WI-025 officer
        restriction both active.
  - [ ] **Still open before pilot:** the operator-owned §B–E items, the
        Finding E-1 remediation (enrollment gMSA's Domain Computers membership
        confers `Machine`-template enroll; see `docs/revocation-scope-validation.md`),
        and cutting the v1.5.0 release (WI-029).

- **Plan 007 v1.6 hardening sweep (2026-07-23/24):**
  - **WI-035 (Finding E-1) — REMEDIATED + VERIFIED.** Enrollment gMSA moved off
    the Domain Computers enroll path (`primaryGroupID` change); verified by
    template ACLs, the gMSA's live token (no Domain Computers), and an issuance
    regression pass. It can now enroll only `ACME-ServerAuth`. See
    `docs/revocation-scope-validation.md` Finding E-1.
  - **WI-036 (two-identity topology) — PROVEN LIVE (2026-07-24).** A dedicated
    revoker gMSA (`gMSA-acme-rev`, separate identity) held template-scoped officer
    rights while the enrollment gMSA held **none**, and ran the full round-trip: RA
    `revokeCert` → pull agent as the revoker → `certutil -revoke` at the CA → RA
    confirm. Verified: WI-022 requester check passed, CA-DB disposition =
    **Revoked**, RA pending drained to empty, compromise independence held,
    least-privilege CRL skip applied. **The earlier block was an unrelated homelab
    AD defect, NOT clock skew (that was ruled out):** a gMSA created without an
    explicit `msDS-SupportedEncryptionTypes` gets RC4 added, which the DCs block,
    so its Kerberos fails and its managed password is unusable — create revoker
    gMSAs with **AES128,AES256** (see `docs/live-reproof-runbook.md`).
  - **WI-037/038/039 — DONE.** Pester pure-logic suite (CI); the live re-proof
    runbook (`docs/live-reproof-runbook.md`) + cadence; deterministic CI
    (`uv sync --locked`, pinned linters/Pester).

- **2026-08-07 security-hardening re-proof — PASSED (2026-08-08):**
  Live re-proof of commit `5d30937` (the 2026-08-07 security review: CA-capable
  CSR/cert rejection, CN→SAN binding, certsrv key binding, rate-limit TOCTOU
  fix, JWS streaming cap, algorithm exactness, EAB URL binding, HEC HTTPS
  enforcement, cryptography ≥50.0.0) on the lab RA host (the lab Windows
  host, IIS app pool as the gMSA, ADCS CA `CA01` in Mode A). Deployed the
  1.6.0 wheel + cryptography 50.0.0 into the app-pool venv; app pool started;
  `/directory` → 200.

  **Core 12 cases (all PASS):** account creation (EAB) → order (in-scope SAN)
  → challenge → finalize (CSR→real cert) → download → SAN matches CSR →
  serverAuth EKU only (no clientAuth) → chain off existing CA (leaf → issuing
  CA → existing root, no new intermediate) → out-of-scope SAN denied at
  finalize → revoke (reason=1, RA store) → revoked cert 410 Gone → reason 7
  rejected (`badRevocationReason`). Serial `6C00…006C`, RequestID 108.

  **New security-hardening checks (3/3 PASS):** CSR with
  `BasicConstraints CA=true` → rejected at finalize; CSR with `keyCertSign`
  KeyUsage → rejected; CSR with out-of-scope CN (not in SAN set) → rejected.
  All three exercise the new `csr_validation` rejection paths before the CSR
  reaches ADCS.

  **CA-side verification (via domain admin on the CA host):** CA DB RequestID
  108 confirms **Requester = `WORK-DOMAIN\gMSA-acme-ra$`** (the enrollment
  gMSA), **Template = `ACME-ServerAuth`**, **Disposition = Issued**. The
  w3wp.exe + python.exe process owners are both the gMSA (confirmed via
  `Win32_Process`). The RA audit-log `requester` field shows the RA host's
  machine account — this is a known artifact of the `_requester()` best-effort
  env-var capture (`USERNAME` resolves to the machine account for gMSAs, not
  the gMSA name); the authoritative CA DB shows the gMSA.

  **Teardown:** app pool stopped (re-parked); DB restored from backup; test
  scripts removed. The test cert (serial `6C00…006C`, RequestID 108) is
  serverAuth-only, for a test hostname, and expires in 90 days; CA-side
  revocation via `certutil -revoke` / `ICertAdmin::RevokeCertificate` returns
  `ERROR_INVALID_PARAMETER` on this lab CA (a CA-level quirk, not code-related)
  — left as a harmless test artifact.

  - [x] §A issuance-leg re-proof on the security-hardening commit (core 12 +
        3 new CSR-rejection checks).
  - [x] cryptography 50.0.0 verified on Windows Server 2025 / Python 3.14.
  - [ ] **Still open before pilot:** the operator-owned §B–E items (unchanged).

- **2026-08-13 — security review closed in code, LIVE RE-PROOF OUTSTANDING.**
  Ten findings from an external static scan of v1.8.0, all independently
  reproduced first and all remediated (`docs/security-review-2026-08-13.md`).
  566 tests + 81 Pester tests green; `ruff` and `mypy --strict` clean; every new
  test mutation-checked.

  **This entry is deliberately not marked PASSED.** Unlike the 2026-08-07 and
  2026-08-11 rows above, no live lab re-proof has been run against this code.
  The issuance leg changed (`Store.record_issuance`, certificate quarantine, the
  `_certificate_response` valid-only gate), so §A must be re-run per
  `docs/live-reproof-runbook.md` before pilot.

  - [ ] **§A issuance-leg re-proof on the 2026-08-13 commit — NOT RUN.**
  - [ ] **CRL-evidence path never exercised against a real ADCS CRL.** Only
        enable `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` after proving
        it against the lab CA's published CRL.
  - [ ] **`Set-OfficerRights.ps1` restart assertions not run on a CA.** The new
        `Get-Service` / `Get-Process certsrv` checks are Windows-only and were
        parse-checked on Linux `pwsh` only.
  - [ ] **New required config before the revocation loop works:**
        `ACME_RA_REVOCATION_CONFIRM_TOKEN` on the RA and `-ConfirmToken` on the
        sync agent. Without it every confirm returns 401.
  - [ ] **Existing deployments: re-check credential strength.** EAB MAC keys
        < 32 bytes or admin tokens < 32 chars now refuse startup.
  - [ ] Still open before pilot: the operator-owned §B–E items (unchanged).

- **2026-08-11 — security review + live re-proof, PASSED.** Twelve findings from
  a pre-production-deployment review closed (`docs/security-review-2026-08-11.md`),
  plus a thirteenth found while reading real `certutil` output. Re-proved live
  against commit `db06c6f` on the lab RA (IIS app pool as the enrollment gMSA,
  ADCS CA, Mode A): **26 checks, 26 passed.** Section A unchanged (serverAuth-only
  EKU, SAN from the CSR, issuer `CONTOSO-CA01-CA`, out-of-scope SAN denied, reason-7
  rejected), and the new chain-binding verifier accepted the real CA's
  `certnew.p7b`. New controls proven live: EAB minted for another deployment
  rejected; `Host:`-header spoof rejected against a **catch-all `*:9443:`
  binding** (so the request genuinely reached the app); `kid` from another
  deployment rejected; order/account/orders POST-as-GET resolve; cert POST-as-GET
  is account-scoped; `/docs` `/redoc` `/openapi.json` all 404; a 220-request nonce
  flood capped (162×204, 58×429); account deactivation refuses the next request.
  **Account eviction proven with a control** (a new account under the renamed kid
  must still succeed, ruling out a false pass from a dotenv that failed to load):
  after the kid was pulled, both `newOrder` and — the case the pre-fix code
  allowed — `revokeCert` returned 401. Revocation round-trip completed through
  the real `Revoke-Cert.ps1` (`Confirm-SerialAtCa` found the row, WI-022 requester
  check confirmed the gMSA, `certutil -revoke` succeeded) and the confirm callback
  accepted the lowercase `certutil` serial form, draining the pending set.
  Also verified: `certutil` does **not** echo the `-restrict` clause, so
  `Confirm-SerialAtCa`'s existence test is sound (a flagged concern, cleared).
  Lab left as found — RA parked (pool stopped, endpoint unreachable, dotenv/DB/
  web.config restored), CA pristine (no `OfficerRights` ever written), all
  session certificates revoked at the CA, temp cleared on both hosts.
  - **Still open before pilot:** the operator-owned items in §B–§E, unchanged —
    plus the two new required items (off-box audit sink, network allowlist).
