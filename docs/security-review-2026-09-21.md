# Security review — 2026-09-21, ACME + officer-script scan at `5cdd83f`

Two valid findings, both fixed and both live-validated. A third was raised
during that validation and **retracted**: it was an artifact of my own probe
harness. The retraction is written up at the same length as the findings,
because the way it survived a passing unit test is the most reusable thing in
this document.

**Reviewer and implementation:** Claude Opus 5 — the same lineage for both.
The cross-lineage separation the gate asks for is therefore **not** satisfied
by this round, and the fixes have not been independently reviewed. Recorded,
not waived.

Work items: WI-025 (bug, medium), WI-026 (risk, medium), WI-027 (retracted,
closed). Regista work-item writes are **working again** — the block recorded in
`AGENTS.md` on 2026-09-20 has lifted, so these are filed in the store rather
than in `UNFILED-WORK-ITEMS.md`.

## Severity

| # | Finding | Rated | Why not higher / lower |
|---|---|---|---|
| WI-025 | Non-ASCII `Authorization` header 500s every admin endpoint | medium | Fails closed; no bypass. Costs a clean, audit-legible 401 and leaves an unauthenticated traceback. Briefly mis-rated **high** during this review — see the retraction. |
| WI-026 | `$Serial` reaches `certutil` unvalidated | medium | Unreachable today; the RA only emits `canonical_serial()` of a parsed certificate. It is rated on the *boundary* it crosses, not on a live exploit. |

## WI-025 — `hmac.compare_digest` raises on non-ASCII `str`

`hmac.compare_digest` raises `TypeError`, not `False`, when either `str`
argument carries a non-ASCII character. Starlette decodes inbound header bytes
as latin-1. So one byte ≥ 0x80 anywhere in an `Authorization` header reached
the comparison as a non-ASCII `str` and became an unhandled 500 — from an
unauthenticated peer, on every admin endpoint, through all three guards
(`_require_admin_token`, `_require_revocation_authority`,
`_require_revocation_confirm_token`).

**This class was already known here.** `app_state._dummy_hmac` carries a
comment about exactly it on the EAB path, and
`tests/test_security_review_2026_08_13.py` regression-tests that path. The
sweep never reached the admin header surface. A fixed bug class is only fixed
where someone looked.

**Fix.** `_bearer_token` returns the wire bytes — `latin-1` being the exact
inverse of Starlette's own decode, so the comparison is against what the client
actually sent — and the configured token is encoded UTF-8, which is how it
reached the process from `.env`/environment. Bytes on bytes, lossless in both
directions. A lossy `errors="replace"` would also have removed the crash and
would have folded distinct credentials onto one another; there is a test for
that specifically.

Deliberately **not** "reject non-ASCII at the door." That also removes the 500,
and silently bricks any deployment whose operator set a non-ASCII token:
configured, accepted by config validation, impossible to present.

## WI-026 — the CA-officer script validated none of its input

`Revoke-Cert.ps1` declared `[string]$Serial` with no validation, and
`Sync-Revocations.ps1` took `$serial` straight from the RA's JSON admin response
and passed it to the child process. The value flows into
`certutil -view -restrict "SerialNumber=$s"` and into `certutil -revoke <serial>`
— whose argument is documented as a **comma-separated list of serials**. No
shell, no quoting trick, no PowerShell native-argument-passing bug required:
`<real>,<other>` is simply another argument, and it revokes a second
certificate that was never confirmed, never requester-checked, never audited.

Nothing reachable emits such a value. It is worth fixing because of where the
value *comes from*: the sync agent holds CA-officer rights, the RA deliberately
does not, and the entire out-of-band revocation design (§4.A of the threat
model) exists so that compromising the RA does not confer them. The officer
script was treating the RA's HTTP response as trusted input to a privileged
`certutil` call.

**Fix.** `Test-CaSerialForm`, in `RevocationLib.ps1` beside `Get-CaSerialForm`,
because a validator and the normalizer it guards must not drift. It is
deliberately **no stricter than the normalizer is lenient** — refusing a
legitimate serial is a containment failure, the worse of the two directions —
and it uses `\A..\z` rather than `^..$`, since PowerShell's `$` matches before a
trailing newline and would accept a multi-line value on its first line alone.

**Scope, decided rather than widened:** `$ReqID` was *already* validated
(`^\d+$`) — the initial filing said otherwise and was wrong. `$CaConfig` and
`$RequesterName` also reach `certutil` unvalidated but are operator
command-line parameters, not network input; a different trust class, left alone
and recorded.

## The retraction — WI-027, and why a green test did not catch it

While validating WI-025 on the lab RA host I measured what looked like a much
worse bug: one unauthenticated non-ASCII `Authorization` header appeared to
wedge the RA permanently — `GET /directory` stopped answering, an authenticated
admin call timed out, the process never recovered. It reproduced
deterministically on three runs and three ports. Isolating it on a *bare*
FastAPI app appeared to show the cause was upstream, in uvicorn/starlette, and
that exception-plus-non-ASCII-header was a precise two-ingredient trigger.

All of it was my probe harness. It ran the server with
`stdout=subprocess.PIPE, stderr=subprocess.STDOUT` **and never read the pipe**.
Each traceback is multiple KB; once the OS pipe buffer filled, the server
blocked on its own write to stderr. The "non-ASCII header" ingredient was
coincidence of ordering — that case was simply the *second* traceback in each
run, and two are what overflow the buffer.

Redirecting the server's output to a file, changing nothing else, the unfixed
build answers the hostile request with a 500 and then serves six consecutive
`GET /directory` 200s and an authenticated admin 200. There is no denial of
service.

Two things are worth carrying forward.

**A registered `Exception` handler does not contain anything.** The first
attempt at containment was `@app.exception_handler(Exception)`. Starlette's
`ServerErrorMiddleware` calls the handler, sends its response, and then runs
`raise exc` regardless — its own source comment reads *"We always continue to
raise the exception."* The handler is inert for this purpose. Anyone adding one
to this app should know that.

**The unit test for it passed.** It used
`TestClient(raise_server_exceptions=False)`, which swallows exactly the
re-raise that was the whole question — a test that could not fail, certifying a
fix that did nothing. The correct discriminator is
`raise_server_exceptions=True`, which re-raises whatever escapes the
application, which is what the ASGI server would have received. The second
attempt (pure-ASGI middleware, inside `ServerErrorMiddleware`) genuinely *did*
contain the exception — and the wedge still happened, which is what finally
pointed at the harness.

Both attempts are reverted. The repo keeps no code justified by a finding that
does not exist.

## Live validation (the lab RA host and the lab CA, 2026-09-21)

The RA host was found torn down from the 2026-09-05 re-proof — app pool
stopped, no venv, no `scripts/`. Validation therefore ran against throwaway
venvs and a throwaway database under `C:\Temp`; **IIS, the app pool, the live
`acme_ra.db`, `acme-ra.env` and the co-hosted sites were not touched.**

| # | Check | Result |
|---|---|---|
| 1 | Pinned closure (`--require-hashes --only-binary :all:`) into a fresh venv, Windows/CPython 3.14 | 29 packages, clean |
| 2 | WI-025 on a **raw socket** — handcrafted requests, 5 credential shapes × 6 admin endpoints + 3 controls | **33/33**, every rejection a 401 |
| 3 | Same harness against unmodified `origin/main` | reproduces the 500 — the harness can detect the defect |
| 4 | `Test-CaSerialForm` vs the **real serial population** under Windows PowerShell 5.1: 443 serials from the CA database (dispositions 20 + 21) and 13 from the RA store, × 6 spellings | **2736 accepted, 0 false refusals** |
| 5 | 12 injection shapes, built from a *real* serial | 12/12 refused |
| 6 | `Revoke-Cert.ps1` on the CA host: comma-list, restrict-clause and extra-argument payloads | exit 3, **`certutil` never reached** |
| 7 | `Revoke-Cert.ps1` controls: real serial, and the `0x`+uppercase operator copy-paste form | passed validation, reached the CA, normalized identically |
| 8 | Full Pester under **Windows PowerShell 5.1 / Pester 5.7.1** | 495 passed, 1 failed, 1 skipped |

Check 2 is the one the unit suite structurally cannot do: `httpx` re-encodes a
bytes header value as UTF-8 before it reaches the app, so `b"caf\xe9"` arrives
as `b"caf\xc3\xa9"`. TestClient cannot put a chosen byte on the wire.

Check 4 exists because the dangerous direction here is over-strictness, and a
population test against real CA and RA data says more about false refusal than
any hand-written case could.

The single Pester failure in check 8 is **pre-existing and environmental** —
`python3.exe` is not executable on that host, so the `install-windows.ps1`
interpreter-flags test cannot run. Confirmed by running the same suite from
unmodified `origin/main` on the same host: 484 passed, the *identical* single
failure. This branch adds 11 passing tests and breaks nothing. It does mean
that test has no coverage on this box; it is not tracked yet.

### One unintended CA-side change

Check 7's control ran `Revoke-Cert.ps1` against serial
`…38`, chosen because it was `Disposition=21` — on the reasoning that an
already-revoked certificate makes the control a no-op. That reasoning was wrong
in exactly the way this project has documented at length: the certificate was
revoked with **reason 8 (removeFromCRL)**, the *un-revoke* state, so the script
correctly treated it as not revoked and re-revoked it with reason 4
(superseded). Reading the reason-8 handling code beforehand did not stop me
walking into it.

The change is lab-only and in the safe direction (a certificate that was off
the CRL and effectively valid is now genuinely revoked). It was **not**
reverted: restoring it means running `certutil -revoke <serial> 8`, the one
operation this project treats as never-automatic. Five reason-8 fixtures remain
at the CA, at least two of them gMSA-issued, so the fixture class for testing
that detection path is not exhausted.

## Not done

- **No independent review**, and no cross-lineage separation (see the header).
- **No ACME round-trip.** Issuance, chain, EKU and the revocation queue were
  not re-proven; this was not a release re-proof and the RA was not deployed to
  IIS. `docs/live-reproof-runbook.md` remains owed on the final candidate.
- The `python3.exe` Pester gap on the lab host is unfiled.
