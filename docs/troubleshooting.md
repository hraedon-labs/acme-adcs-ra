# Troubleshooting

A first-response index. Each entry says what you are seeing, what it usually
means, and where the full procedure is. It repeats nothing that the other
documents already explain in depth. Nothing here is a substitute for the
runbooks.

## Where the logs are

- **The process output** goes to the `stdoutLogFile` path in the site's
  `web.config`: `C:\ProgramData\acme-adcs-ra\logs\stdout` by default
  (the IIS module may append a timestamp or process id to that name; look for the newest file with the prefix). Startup
  refusals and tracebacks appear here.
- **The audit trail** is the `audit_log` table in the SQLite database, mirrored
  to the configured sink: a JSONL file next to the database by default, or
  syslog, or Splunk HEC. Event names are in `operations.md` ("Monitoring and
  SLOs") and `threat-model.md`.
- **ADCS side:** the CA database (requester, template, disposition) and the
  `/certsrv/` IIS log on the CA or enrollment host.
- **Installer output** is on the console of the run. Nothing is retained
  elsewhere.

## The RA will not start (the pool stops, `/directory` gives 502 or 503)

Read the stdout log. The RA refuses to start, with a message, on configuration
that would weaken it. The list is in `configuration.md`, "Startup refusals worth
knowing". The usual ones:

- `ACME_RA_BASE_URL` has a path, a query or no host. (Plain `http` off loopback
  does not stop startup; it logs a warning.)
- A weak or short credential: EAB MAC key under 32 bytes, kid under 22
  characters, admin or confirm token under 32 characters, or both tokens equal.
- `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` but the sink cannot actually emit
  (collector unreachable, wrong URL or token).
- `audit_prune_enabled=true`, which is refused.
- A startup migration error naming serial numbers (`operations.md`, "Upgrading").
- An IIS startup timeout: `web.config` allows 60 seconds and 3 retries. A host
  whose Python cannot import the Negotiate stack fails here. Run the import
  check from `operator-requirements.md` section 5.
- The application pool will not start at all: the gMSA usually lacks **Log on as
  a service**, or `Test-ADServiceAccount` does not return `True` on this host
  (`deploy/iis/README.md`).

## Every request is refused

- **Every request is rejected, with a message about a URL host mismatch:** `ACME_RA_BASE_URL`
  does not match the origin clients use (scheme, host and port). Fix the
  setting; it is security configuration.
- **`badExternalAccountBinding`:** the kid is not in the allowlist, or the
  client holds the credential for another environment. A kid shared with a
  staging RA does not verify against production.
- **401 for an account that worked before:** its kid was removed from the
  allowlist, or the account was deactivated. Removing a kid evicts the account
  completely.
- **A `rateLimited` answer:** the per-kid, global, key-change or nonce limit was
  hit (`operations.md`, "Network allowlist and in-app rate limiting").

## Issuance fails or hangs

- **Finalize returns 503 `issuance_halted`, and keeps doing so:** the RA could
  not record an issuance after the CA had issued it, and it stops issuing until
  restarted. This is deliberate and one-way. Check the critical log line in
  stdout and the disk and store state, restart, then reconcile the CA database
  against the RA (`reconcile_revocation.py` is read-only).
- **Order stuck in `processing`:** check the CA database for a certificate
  before touching it. Reclaiming an order that really issued a certificate
  causes double issuance. Procedure: `operations.md`, "Admin token and reclaim
  runbook".
- **The CA denied the request:** the order goes back to `ready` with
  `rejectedIdentifier`. Look at the template and the CA's policy module.
- **A certificate with an unexpected SAN or EKU was issued by the CA:** the RA
  quarantines it and queues revocation (`operations.md`, "Quarantined
  certificates"). Fix the template.
- **Authentication to `/certsrv/` fails:** the usual cause is a gMSA created
  without AES Kerberos types where the DCs block RC4. It looks like a KDS or
  time-sync problem and is not. See `certsrv-setup.md` for EPA and Mode C delegation.
- **Transport failures (503 with `Retry-After`):** the CA host was unreachable
  or too slow within the 30-second per-call and 120-second total limits. The
  order stays `processing` and the client polls.

## Revocation does not reach the CA

- Serials revoke at the CA but stay on the pending list: the confirm token is
  unset, or the confirm call failed. The general admin token is deliberately not
  accepted there.
- Nothing is revoked at the CA: the sync task is not running, or it runs as an
  identity without officer rights on the template. The script refuses to run
  from a tree writable by non-administrators.
- Revocation reason 7 is refused everywhere by design (RFC 5280 "unused").
- A revocation reached the CA but not the CRL: the CRL was not republished.
  `scripts/verify_crl_publication.py` checks it.
- A confirmation is refused for a CRL: stale (age ceiling) or older than one
  already used (monotonic watermark). The refusal reason is in the audit row
  (`crl-evidence-regressed` for the latter). Measure your CDP before tuning.

Full procedures: `operations.md`, "Revocation runbook".

## The audit grows or has gaps

- **Growth:** the database and JSONL mirror warn at `audit_store_warn_mib`.
  Repeated denials are coalesced, but nothing is pruned
  (`handover.md`, "Known gaps").
- **Fewer rows than before after upgrading to 1.12.0:** idle sweeps and empty
  polls no longer write rows. See the 1.12.0 changelog entry.
- **No events in the SIEM:** check the sink settings and the collector. With
  `audit_offbox_required` the RA refuses to start if it cannot emit.

## If this does not help

Gather the stdout log, the relevant `audit_log` rows, the CA database record,
the version or commit running, and the configuration with secrets removed.
Then see `handover.md`. Not yet documented: an escalation contact for your
organisation.
