# Configuration reference

Every setting the RA reads. This page is derived from
`src/acme_adcs_ra/config.py` (class `RAConfig`); if the two disagree, the code
is right. Please fix this page.

## How settings are supplied

- Every setting is an environment variable named `ACME_RA_` plus the setting
  name in upper case. `base_url` is `ACME_RA_BASE_URL`.
- Under IIS, non-secret values go in the `<environmentVariables>` block of the
  site's `web.config`. Secrets go in the locked env file
  (`C:\ProgramData\acme-adcs-ra\acme-ra.env` by default), which `web.config`
  points to with `ACME_RA_DOTENV`. The installer never overwrites either file
  once it exists.
- Lists and dictionaries are JSON. A nested setting uses a double underscore:
  `ACME_RA_SAN_SCOPES__<kid>__DNS_PATTERNS=["*.example.com"]`.
- Unknown `ACME_RA_*` names are ignored silently. A typo in a name therefore
  leaves the setting at its default. Check spelling against this page.
- Changes take effect when the application pool restarts.
- Settings that fail validation stop the RA from starting. This is deliberate.
  The sections below say which ones.

Use `<your-domain>`-style values of your own. The defaults named `CA01`,
`CONTOSO-CA01-CA` and `WORK-DOMAIN.local` are placeholders and must be replaced.

## Identity and access

| Setting | Default | What it does |
|---|---|---|
| `eab_allowlist` | empty | JSON list of `{"kid": ..., "mac_key": ...}`. Only these EAB credentials can create accounts. The MAC key must decode to at least 32 bytes. Kids must be unique and at least 22 characters (see `allow_weak_credentials`); a shorter kid that already has accounts is grandfathered with a startup warning. Mint entries with `python scripts/eab.py`. |
| `san_scopes` | empty | Per kid, the DNS names that kid may request: `dns_patterns`, exact names or leftmost-label wildcards such as `*.example.com`. A wildcard matches one label only (`*.example.com` matches `a.example.com`, not `a.b.example.com`). This is the whole authorization surface. |
| `max_accounts_per_eab_kid` | 1 | Lifetime cap on accounts per kid. Deactivated accounts still count. |
| `admin_token` | empty | Bearer token for the maintenance endpoints. At least 32 characters. Treat like a password. |
| `revocation_confirm_token` | empty | A separate token that only the revocation-confirm endpoint accepts. Must differ from `admin_token` (startup refuses if they match). If unset, the confirm endpoint is disabled. |
| `allow_weak_credentials` | false | Turns off the credential strength floors and the kid length floor. For lab and CI only. Never set it in production. |

## Server and URLs

| Setting | Default | What it does |
|---|---|---|
| `base_url` | `http://localhost:8000` | The public origin of the RA. **Security configuration, not a display value**: every signed request and EAB binding is checked against it. It must be a bare origin (scheme, host, optional port), with no path, query or fragment. Use `https` for anything other than loopback: a plain `http` origin off loopback is **not** refused, the RA starts and logs a warning, and then serves over plaintext. |
| `terms_of_service` | empty | Terms-of-service URL published in the directory. |
| `bind_host`, `bind_port` | empty | Where the process listens. Under IIS the proxy supplies the port (`HTTP_PLATFORM_PORT`) and `web.config` sets the host to `127.0.0.1`. |
| `trust_proxy` | false | Trust forwarded headers from the reverse proxy. Set true behind IIS. |
| `forwarded_allow_ips` | `127.0.0.1` | Which proxy addresses may set those headers. |
| `tls_certfile`, `tls_keyfile` | unset | Both or neither. When both are set, the RA terminates TLS itself, for a deployment with no IIS in front. |
| `server_max_concurrency` | 256 | Concurrent requests when the RA runs its own server. Past this it answers 503. |
| `allow_fake_adcs_backends` | false | Development and CI only. Without it, the RA refuses to start on a non-Windows platform, so a fake CA cannot be picked by accident. |

## The ADCS enrollment leg

| Setting | Default | What it does |
|---|---|---|
| `adcs_host` | `CA01.WORK-DOMAIN.local` | Host serving `/certsrv/`. |
| `adcs_template` | `ACME-ServerAuth` | Template to enroll against. |
| `adcs_ca_name` | `CONTOSO-CA01-CA` | CA name. |
| `adcs_ca_bundle` | unset | PEM bundle to verify the `/certsrv/` TLS certificate. Unset means the host's trust store. |
| `adcs_locale` | `en` | Locale of the Web Enrollment pages. A value other than `en` turns off the English-text heuristics and relies on the request ID and `certnew.cer` URL only. |
| `adcs_enrollment_timeout_seconds` | 30 | Per socket operation. |
| `adcs_enrollment_total_timeout_seconds` | 120 | One ceiling across the whole enrollment sequence. Must be at least `adcs_enrollment_timeout_seconds`. |
| `adcs_enrollment_max_workers` | 4 | Threads reserved for ADCS calls. |
| `adcs_enrollment_max_pending` | 32 | Admitted enrollments, running plus waiting. Must be at least `adcs_enrollment_max_workers`. |

## ACME limits

| Setting | Default | What it does |
|---|---|---|
| `order_expiry_seconds` | 3600 | Lifetime of an order and its authorizations. |
| `max_identifiers_per_order` | 50 | Names per order. |
| `max_csr_size_bytes` | 8192 | CSR size cap. |
| `max_jws_body_size_bytes` | 65536 | Request body cap, enforced while streaming. |
| `max_admin_body_size_bytes` | 4096 | Body cap on admin routes. |
| `rate_limit_orders_per_window` | 50 | Orders per kid per window. 0 disables it. |
| `rate_limit_window_seconds` | 3600 | The window for the order and key-change limits. |
| `rate_limit_global_per_window` | 0 | Orders across all accounts per window. 0 disables it. The shipped `web.config` sets 500. |
| `rate_limit_overrides` | empty | JSON dictionary `{kid: limit}` that overrides the per-kid limit. |
| `rate_limit_key_changes_per_window` | 5 | Successful key rollovers per kid per window. 0 disables it. |
| `nonce_rate_limit_per_second` | 20.0 | Token-bucket rate on the unauthenticated new-nonce endpoint. 0 disables it. |
| `nonce_rate_limit_burst` | 100 | Bucket size for the above. |
| `reclaim_minimum_processing_age_seconds` | 60 | An order must have been in `processing` this long before an operator can reclaim it. |

## Storage and audit

| Setting | Default | What it does |
|---|---|---|
| `db_path` | `acme_ra.db` | SQLite database. The shipped `web.config` points it into the state tree. |
| `audit_offbox_required` | false | Refuse to start unless audit events leave the host and delivery can be shown. **Set true in production.** |
| `audit_offbox_allow_unauthenticated_syslog` | false | Lets plain TCP syslog satisfy the requirement. It warns on every start and is recorded in the audit trail. UDP never satisfies it. |
| `audit_denial_coalesce_window_seconds` | 60 | Repeated identical denials inside a window update one row with a count. 0 writes a row per denial. |
| `audit_retention_days` | 0 (keep everything) | Declares a retention period. Startup refuses a value below the longest certificate validity issued plus a 14-day grace. It does not delete anything. |
| `audit_prune_enabled` | false | **Reserved; setting it true refuses startup.** There is no per-row delivery acknowledgement, so deletion could destroy the only copy. |
| `audit_store_warn_mib` | 1024 | Warn when the database plus JSONL mirror exceed this size. 0 disables the warning. |
| `audit_jsonl_max_mib`, `audit_jsonl_keep` | 256, 4 | Rotate the local JSONL mirror at this size and keep this many files. A size of 0 turns rotation off. |
| `siem_sink` | `jsonl` | `jsonl`, `syslog` or `hec`. |
| `siem_jsonl_path` | unset | JSONL file path. When unset it sits next to the database. |
| `siem_syslog_host`, `siem_syslog_port`, `siem_syslog_proto` | empty, 514, `udp` | Syslog target. |
| `siem_syslog_timeout_seconds` | 5.0 | Longest a TCP syslog send may block. |
| `siem_hec_url`, `siem_hec_token`, `siem_hec_index`, `siem_hec_sourcetype` | empty, empty, empty, `acme-adcs-ra` | Splunk HEC target. Keep the token in the env file. |
| `siem_hec_queue_max` | 1000 | In-memory queue depth. Past it, HEC events are dropped and counted. The local audit table is never dropped. Must be at least 1. |

## CA-side revocation confirmation

Background: `operations.md`, "Admin token and reclaim runbook" and "Automated
revocation".

| Setting | Default | What it does |
|---|---|---|
| `revocation_confirm_crl_url` | empty | CRL distribution point used as independent proof that a serial is revoked. |
| `revocation_confirm_require_crl_evidence` | false | Refuse to confirm unless the CRL proves it. Needs the URL above. |
| `revocation_confirm_crl_timeout_seconds` | 10.0 | Per read. |
| `revocation_confirm_crl_total_timeout_seconds` | 30.0 | Whole-retrieval ceiling. Must be at least the per-read value. |
| `revocation_confirm_crl_max_bytes` | 10485760 | CRL size cap. |
| `revocation_confirm_crl_max_workers` | 2 | Threads for CRL fetches. Separate from the enrollment pool. |
| `revocation_confirm_crl_max_pending` | 32 | Admitted fetches. Must be at least `revocation_confirm_crl_max_workers`. Past it the endpoint answers 429 and the serial stays pending. |
| `revocation_confirm_crl_max_age_seconds` | 626400 | Refuse a CRL older than this. **Measured on one lab CA (weekly CRL, 12-hour overlap); measure yours** with `scripts/sample_crl_age.py` before relying on it (`operations.md`, "Deriving the ceiling"). |
| `revocation_confirm_crl_require_monotonic` | true | Refuse a CRL older than the newest one already used for the same issuer. Set false only where CDP replicas are known to lag. The regression is still audited. |
| `revocation_confirm_crl_follow_redirects` | false | Follow redirects when fetching the CRL. Prefer pointing the URL at the final address. |

## Startup refusals worth knowing

The RA stops with a message instead of running in a weaker state when:

- `base_url` has a path, a query or no host (plain `http` off loopback only logs a
  warning; see the `base_url` row above);
- the EAB list has duplicate or empty kids, a MAC key under 32 bytes, or a kid
  under 22 characters that has no existing accounts;
- `admin_token` or `revocation_confirm_token` is under 32 characters, or the two
  are equal;
- `audit_offbox_required` is true but the configured sink cannot emit;
- `audit_retention_days` is below its floor, or `audit_prune_enabled` is true;
- `tls_certfile` and `tls_keyfile` are not set together;
- a timeout or pool bound is inconsistent (the messages name the setting).

`docs/operator-requirements.md` section 3 lists the **installer's** refusals, which
are a separate set.
