<#
.SYNOPSIS
    CA-side pull agent that closes the automated revocation loop (WI-024).

.DESCRIPTION
    This is the headline deliverable of v1.5: it automates the out-of-band
    CA-side revocation step that was previously a manual operator action
    (`scripts/Revoke-Cert.ps1`).

    The loop:
      1. GET <RaBaseUrl>/acme/admin/revocations/pending  (WI-023 endpoint,
         admin-token-gated) -> the RA's "revoked-in-RA-but-active-at-CA" set:
         a list of {serial, req_id, reason, revoked_at}.
      2. For each serial, call `Revoke-Cert.ps1` (which now self-checks the
         requester, WI-022) against the CA. `certutil -revoke -config` is
         remote-capable, so the agent does NOT need to run on the CA -- no
         Kerberos double-hop.
      3. On success, POST <RaBaseUrl>/acme/admin/revocations/<serial>/confirm
         with {"ca_crl_updated": true} so the RA audit flips
         `ca_crl_updated` to true and the serial drops out of the pending
         set on the next pull (idempotent).

    Two deployment topologies are supported:

      - Two-identity (default, recommended): the agent runs as a scheduled
        task on a UTILITY HOST (not the CA) under a dedicated
        `gMSA-acme-revoker$` whose CA-side officer power is template-scoped
        to `ACME-ServerAuth` by the CA's `OfficerRights` restriction
        (WI-025). The enrollment gMSA holds no CA-officer rights -- the
        cardinal invariant holds.

      - Single-identity (opt-in, -LocalMode): the agent runs on the RA host
        under the enrollment gMSA, which is also the revoker. The enrollment
        gMSA must be granted template-scoped OfficerRights on the CA (see
        docs/operations.md ## Single-identity deployment). This is a weaker
        posture (one credential compromise grants both issue and revoke --
        see threat-model section E) but operationally simpler. The invocation
        mechanism is unchanged; -LocalMode signals deployment intent and
        adjusts the mode banner/output.

    Fail-visible, dry-run default. Without -Execute the script is report-only:
    it fetches the pending set and prints what it WOULD do, making no change.
    Pass -Execute to arm it. Every auto-revoke lands in the CA DB (under the
    revoker identity) and the RA audit (via the confirm callback).

    The script is safe to run repeatedly, and repeating it REPAIRS a partial
    run. `Revoke-Cert.ps1` rejects reason 7, and a serial the CA has already
    revoked exits 6 (already revoked, no change made) -- which the agent treats
    as "the CA side is done, retry the RA confirmation" rather than as a
    failure. That is what makes a dropped confirmation callback self-healing:
    before, the retry re-revoked, saw certutil's non-zero already-revoked
    result, booked it as a failure and skipped the callback for ever, so one
    transient network fault desynchronized the RA audit from the CA permanently
    (2026-08-17 F4).

    Exit codes:
      0  = success (all pending serials revoked-and-confirmed, already revoked
           at the CA and confirmed, or dry-run completed, or nothing pending)
      1  = the RA was unreachable or the pending endpoint returned an error
      2  = partial failure (one or more serials failed to revoke or to confirm;
           see the per-serial log lines above)

.PARAMETER RaBaseUrl
    The RA's base URL (e.g. "https://ra.WORK-DOMAIN.local"). The admin
    pending endpoint is at <RaBaseUrl>/acme/admin/revocations/pending.

.PARAMETER AdminToken
    Declare that this run should hold ADMIN authority, drawn from the
    ACME_ADMIN_TOKEN environment variable. This is a SWITCH, not a value:
    since the 2026-08-23 review the script accepts no secret on its command
    line at all -- the invocation is shell history and a process argument
    list, which is exactly where a token should never travel. Set the
    variable first (e.g. `$env:ACME_ADMIN_TOKEN = Read-Host "Admin token"`,
    or load it from the protected dotenv) and pass the bare flag. Fails
    loudly when the flag is given but the variable is unset. Only needed by a
    deployment that has not yet provisioned a confirm token: the RA refuses
    the admin token on the confirm endpoint, so prefer -ConfirmToken.

.PARAMETER ConfirmToken
    Declare that this run should use the revocation CONFIRM credential
    (ACME_CONFIRM_TOKEN), read from that environment variable. A SWITCH, like
    -AdminToken: the value itself is never accepted here. The confirm token
    is the least-privilege credential and the only one the confirm endpoint
    accepts; it alone can power the whole sync workflow. Set the variable
    first and pass the bare flag; the script fails loudly if the flag is
    given while the variable is unset.

.PARAMETER CaConfig
    The CA configuration string ("CA01\WORK-DOMAIN-CA" form). Passed through
    to `Revoke-Cert.ps1` for `certutil -revoke -config`.

.PARAMETER RequesterName
    The expected enrollment identity, passed through to `Revoke-Cert.ps1`'s
    -RequesterName (WI-022 requester check). Default:
    "WORK-DOMAIN\gMSA-acme-ra$" (placeholder form).

.PARAMETER DryRun
    Explicit dry-run: fetch the pending set and print what would be done,
    making no change. This is the default behavior when neither -DryRun nor
    -Execute is given.

.PARAMETER Execute
    Arm the script to actually revoke (call `Revoke-Cert.ps1` and the RA
    confirm callback). Mutually exclusive with -DryRun. Without this switch
    the script is report-only.

.PARAMETER ScriptDir
    Directory containing `Revoke-Cert.ps1`. Default: the same directory as
    this script ($PSScriptRoot).

.PARAMETER LocalMode
    Single-identity deployment: the agent runs on the RA host under the
    enrollment gMSA (which is also the revoker). The enrollment gMSA must
    have template-scoped OfficerRights on the CA (see docs/operations.md
    ## Single-identity deployment). The requester check passes trivially
    since the revoker IS the enrollment gMSA. This flag adjusts the mode
    banner and output; the invocation mechanism is unchanged.

.PARAMETER PublishCrl
    Force an immediate CRL republish after each revocation (passes through by
    NOT setting Revoke-Cert.ps1's -SkipPublishCrl). OFF by default: the default
    is least-privilege -- the revoker/officer identity revokes the cert (which
    the CA records immediately) but does NOT republish the CRL, so the
    revocation becomes visible at the next scheduled CRL publication.
    `certutil -CRL republish` requires the Manage-CA role, so -PublishCrl is
    only usable when the identity has been granted CRL-publish rights. That is
    an explicit operator trade-off: CRL freshness in exchange for a broader
    grant (in the single-identity topology it means the internet-facing
    enrollment identity also holds Manage-CA -- strongly discouraged; more
    defensible for the dedicated two-identity revoker). See threat-model
    section E and docs/operations.md.

.EXAMPLE
    # Dry run (default -- report only, no changes). The credential NEVER
    # travels on the command line: set it in the environment first (any
    # protected source -- the RA dotenv, a vault lookup, an interactive
    # prompt), then run with the bare -ConfirmToken flag:
    $env:ACME_CONFIRM_TOKEN = Read-Host "Revocation confirm token"
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -ConfirmToken

.EXAMPLE
    # Execute (actually revoke pending serials at the CA), same
    # environment-first rule:
    $env:ACME_CONFIRM_TOKEN = Read-Host "Revocation confirm token"
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -ConfirmToken -Execute

.EXAMPLE
    # Single-identity deployment (agent on the RA host under the enrollment
    # gMSA, which is also the revoker):
    $env:ACME_CONFIRM_TOKEN = Read-Host "Revocation confirm token"
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -ConfirmToken -Execute -LocalMode

.NOTES
    Schedule as a Windows Scheduled Task running as `gMSA-acme-revoker$` on
    a utility host with line-of-sight to both the RA (HTTPS) and the CA
    (certutil -config RPC/DCOM). See docs/operations.md ## Automated
    revocation. No signing key, no enrollment -- this is an operator/revoker
    tool only.

    For single-identity deployments, pass -LocalMode and schedule the task
    on the RA host under the enrollment gMSA (which is also the revoker).
    See docs/operations.md ## Single-identity deployment and threat-model
    section E for the explicit trade-off. The invocation mechanism is the same
    either way; -LocalMode signals the deployment topology.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RaBaseUrl,
    # 2026-08-23 finding 6: these used to be [string] parameters, so the
    # documented direct invocation carried the FULL token value through the
    # shell history and the process argument list -- the last place the
    # credential still travelled after the scheduled-task side was closed.
    # They are SWITCHES now (the same pattern as Register-MaintenanceTasks
    # since the 2026-08-15 review): they declare WHICH environment variable
    # supplies the value, so a token value can no longer be passed at all --
    # whatever follows the flag binds positionally to a non-secret parameter
    # and never reaches an Authorization header -- and a flag whose variable
    # is unset fails loudly before anything runs.
    [switch]$AdminToken,
    [switch]$ConfirmToken,
    [Parameter(Mandatory = $true)][string]$CaConfig,
    [string]$RequesterName = "WORK-DOMAIN\gMSA-acme-ra$",
    [switch]$DryRun,
    [switch]$Execute,
    [string]$ScriptDir = "",
    [switch]$LocalMode,
    [switch]$PublishCrl,
    [switch]$AllowInsecureUrl,
    # Accept a script tree that is not administrator-only. Registered into the
    # task action by Register-MaintenanceTasks.ps1 only when the registrar was
    # itself given the override, so a lab deployment keeps working and a
    # production one cannot silently acquire this.
    [switch]$AllowUntrustedScriptPath
)

$ErrorActionPreference = "Stop"

# PROVENANCE FIRST, THEN SIBLINGS (2026-08-24 F10).
#
# This is the script the revocation-sync scheduled task executes as the gMSA
# every interval, forever, from whatever path an operator copied scripts\ to.
# It dot-sourced SyncLib.ps1 with no check of any kind.
#
# The 2026-08-18 round considered a run-time check here and declined it, for a
# reason that was true at the time: loading InstallVerifyLib.ps1 cost two
# Add-Type C# compiles on a 15-minute cadence. It closed with the condition for
# revisiting -- "worth revisiting if the lib is ever split so the DACL
# primitives can be loaded on their own". Those compiles are now on demand and
# neither is on this path, so the load is 1298ms -> 321ms (pwsh 7.6/Linux) and
# the objection is retired rather than overruled.
#
# The other half of that reasoning was that registration already refuses
# untrusted trees, leaving only a DACL loosened afterwards. That held only for
# the revocation-sync path, and only after the registrar had already loaded two
# siblings unchecked -- and it never covered -AllowUntrustedScriptPath, which
# registers against a writable tree by design and then warns into the void.
# Checking here is what makes that override self-correcting. InstallVerifyLib
# is itself the code that authenticates this privileged script tree, so execute
# it only after its canonical UTF-8/LF bytes match the release digest pinned in
# this entry point. The scriptblock is built from those same verified in-memory
# bytes; the path is never reopened between validation and use.
$installVerifyLibPath = Join-Path $PSScriptRoot 'lib\InstallVerifyLib.ps1'
$installVerifyExpectedSha256 = '01a351e5494d0f3bf968488a99710f2a902e807e91acb27a8d576d4669428686'
try {
    $installVerifyBytes = [System.IO.File]::ReadAllBytes($installVerifyLibPath)
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $installVerifyText = $strictUtf8.GetString($installVerifyBytes).Replace("`r`n", "`n").Replace("`r", "`n")
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $installVerifyActualSha256 = [System.BitConverter]::ToString(
            $sha256.ComputeHash($strictUtf8.GetBytes($installVerifyText))).Replace('-', '').ToLowerInvariant()
    } finally { $sha256.Dispose() }
} catch {
    throw "InstallVerifyLib.ps1 could not be authenticated before execution: $($_.Exception.Message)"
}
if ($installVerifyActualSha256 -cne $installVerifyExpectedSha256) {
    if (-not $AllowUntrustedScriptPath) {
        throw "InstallVerifyLib.ps1 does not match this entry point's pinned release digest; refusing privileged execution."
    }
    Write-Warning "UNSAFE LAB OVERRIDE: InstallVerifyLib.ps1 does not match this entry point's release digest. Executing only the already-read bytes because -AllowUntrustedScriptPath was explicit."
}
$installVerifyScriptBlock = [scriptblock]::Create($installVerifyText)
. $installVerifyScriptBlock
Assert-PrivilegedScriptTreeTrusted -Root $PSScriptRoot `
    -Purpose 'the revocation-sync task' `
    -AllowUntrusted:$AllowUntrustedScriptPath -RunTime

. "$PSScriptRoot/lib/SyncLib.ps1"
# Test-CaSerialForm lives beside Get-CaSerialForm rather than being copied
# here: the validator and the normalizer have to agree on which spellings are
# legitimate, and two copies drift.
. "$PSScriptRoot/lib/RevocationLib.ps1"

function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# Fail-visible: dry-run is the default. -Execute arms the script. Both
# switches is a contradiction.
if ($Execute -and $DryRun) {
    Die "-Execute and -DryRun are mutually exclusive. Use -Execute to revoke, or neither for a dry run (default)." 3
}
$liveMode = [bool]$Execute

# Credentials: the VALUE always comes from the environment. -AdminToken /
# -ConfirmToken are switches that declare which one this run uses, fail loudly
# when the declared variable is unset, and never accept the secret itself --
# the command line is shell history and a process listing (2026-08-23
# finding 6). The scheduled-task action (Register-MaintenanceTasks.ps1) sets
# ACME_ADMIN_TOKEN / ACME_CONFIRM_TOKEN and passes no switch, so with no flag
# given the environment is still the source and direct manual operation works
# the same way: set the variable(s), then run the script.
$adminTokenValue = [string]$env:ACME_ADMIN_TOKEN
$confirmTokenValue = [string]$env:ACME_CONFIRM_TOKEN
if ($AdminToken -and [string]::IsNullOrWhiteSpace($adminTokenValue)) {
    Die ("-AdminToken was given but ACME_ADMIN_TOKEN is not set in the environment. " +
         "Set it first (e.g. `$env:ACME_ADMIN_TOKEN = Read-Host) -- the value is never " +
         "accepted on the command line.") 3
}
if ($ConfirmToken -and [string]::IsNullOrWhiteSpace($confirmTokenValue)) {
    Die ("-ConfirmToken was given but ACME_CONFIRM_TOKEN is not set in the environment. " +
         "Set it first (e.g. `$env:ACME_CONFIRM_TOKEN = Read-Host) -- the value is never " +
         "accepted on the command line.") 3
}
# The confirm token is now sufficient authority for this whole script: the RA
# accepts it for the read-only pending list as well as for confirming. That is
# deliberate least privilege -- a revocation host that also holds the admin
# token can reclaim a processing order and drain the nonce table, powers this
# agent has no use for. -AdminToken remains accepted for a deployment that has
# not yet provisioned a confirm token, but it is no longer required.
if ([string]::IsNullOrWhiteSpace($adminTokenValue) -and [string]::IsNullOrWhiteSpace($confirmTokenValue)) {
    Die ("No credential supplied: set ACME_CONFIRM_TOKEN (preferred) or ACME_ADMIN_TOKEN in the " +
         "environment first, and declare the choice with the -ConfirmToken / -AdminToken flag. " +
         "Token values are never accepted as command-line parameters.") 3
}
if ([string]::IsNullOrWhiteSpace($confirmTokenValue)) {
    Write-Warning ("No confirm token in the environment; falling back to the admin token to read the " +
                   "pending list. The RA REFUSES the admin token when confirming, so every confirm below " +
                   "will fail and serials will stay pending. Provision ACME_RA_REVOCATION_CONFIRM_TOKEN.")
}

# Resolve the Revoke-Cert.ps1 path.
if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    $ScriptDir = $PSScriptRoot
}
$revokeScript = Join-Path $ScriptDir 'Revoke-Cert.ps1'
if (-not (Test-Path $revokeScript)) {
    Die "Revoke-Cert.ps1 not found at '$revokeScript'" 1
}

# Resolve the PowerShell host to invoke Revoke-Cert.ps1 in a child process
# (so its `exit` becomes $LASTEXITCODE, not propagated as our own).
$pwshExe = $null
try {
    $pwshExe = (Get-Process -Id $PID).Path
} catch {
    $pwshExe = $null
}
if ([string]::IsNullOrWhiteSpace($pwshExe)) { $pwshExe = "powershell.exe" }

# Validate the URL BEFORE any token is attached to a request. A bad scheme or
# an embedded-credential URL must fail here, not after the token is on the wire.
try {
    $base = Assert-SafeRaUrl -Url $RaBaseUrl -AllowInsecureUrl:$AllowInsecureUrl
} catch {
    Die $_.Exception.Message 3
}
# Prefer the confirm token for the read; fall back to the admin token only if
# no confirm token was provisioned.
$readToken = if ([string]::IsNullOrWhiteSpace($confirmTokenValue)) { $adminTokenValue } else { $confirmTokenValue }
$headers = @{ 'Authorization' = "Bearer $readToken" }

# Confirming a CA-side revocation now requires its own credential -- the RA
# refuses the general admin token on that endpoint, so a compromised
# monitoring/ops token cannot forge "the CA revoked it". Fall back to the
# admin token only when no confirm token was supplied, so an operator who has
# not yet provisioned one gets the RA's explicit 401 rather than a silent skip.
$effectiveConfirmToken = if ([string]::IsNullOrWhiteSpace($confirmTokenValue)) { $adminTokenValue } else { $confirmTokenValue }
$confirmHeaders = @{ 'Authorization' = "Bearer $effectiveConfirmToken" }

if ($liveMode) {
    if ($LocalMode) {
        Write-Output "MODE: EXECUTE (live, single-identity -- revoking as the enrollment gMSA)."
    } else {
        Write-Output "MODE: EXECUTE (live -- revocations WILL be applied at the CA)."
    }
} else {
    if ($LocalMode) {
        Write-Output "MODE: DRY-RUN (report only, single-identity). Pass -Execute to apply."
        Write-Output "NOTE: -LocalMode in dry-run is still report-only -- no revocations are applied."
    } else {
        Write-Output "MODE: DRY-RUN (report only -- no changes). Pass -Execute to apply."
    }
}
Write-Output ""

# 1. Fetch the pending revocations from the RA.
$pendingUrl = "$base/acme/admin/revocations/pending"
Write-Output "Fetching pending revocations from: $pendingUrl"
try {
    $response = Invoke-RestMethod -Method Get -Uri $pendingUrl -Headers $headers -TimeoutSec 60
} catch {
    Die ("RA unreachable -- GET {0} failed: {1}" -f $pendingUrl, $_.Exception.Message) 1
}

# Invoke-RestMethod may unwrap a single-element array into a scalar, and an
# empty JSON array may deserialize as $null. Force a clean array, filtering
# out any null entries (defensive against PowerShell's inconsistent empty-
# array deserialization across versions).
$pending = @()
if ($response -and $response.pending_revocations) {
    $pending = @($response.pending_revocations | Where-Object { $_ })
}
$total = $pending.Count
Write-Output ("Pending revocations: {0}" -f $total)
Write-Output ""

if ($total -eq 0) {
    Write-Output "Nothing to do -- RA has no pending CA-side revocations."
    Write-Output "SYNC COMPLETE: 0 pending, 0 revoked, 0 failed, 0 dry-run"
    exit 0
}

# 2. Process each pending revocation.
$revoked = 0
$failed = 0
$confirmFailed = 0
$dryRunCount = 0
# Serials the CA had already revoked, whose RA confirmation is being retried
# (2026-08-17 F4). Counted separately from $revoked: no CA-side change was made
# for these, and conflating the two would misreport what the batch did.
$alreadyRevoked = 0
$index = 0

foreach ($entry in $pending) {
    $index++
    $serial = [string]$entry.serial
    $reqId = [string]$entry.req_id
    if ([string]::IsNullOrWhiteSpace($reqId)) { $reqId = "(none)" }
    $reason = 0
    if ($null -ne $entry.reason -and "$($entry.reason)" -ne '') {
        $reason = [int]$entry.reason
    }
    $revokedAt = [string]$entry.revoked_at

    # Validate what the RA sent BEFORE it becomes a child-process argument.
    #
    # This is the trust boundary the out-of-band revocation design exists to
    # create: this host holds CA-officer rights and the RA deliberately does
    # not, so a compromised or impersonated RA must not be able to steer
    # certutil. $serial arrives as free-form JSON text and would otherwise
    # travel straight to `certutil -revoke`, whose argument is a
    # COMMA-SEPARATED LIST of serials.
    #
    # A bad entry is skipped and counted as a failure, not thrown: one
    # malformed row must not strand every other pending revocation in the
    # batch. The malformed value is echoed for the investigator -- it is
    # evidence, and by this point it has been refused.
    if (-not (Test-CaSerialForm $serial)) {
        $failed++
        [Console]::Error.WriteLine(
            ("[{0}/{1}] REFUSED: the RA returned a serial that is not plain hex: '{2}'. Skipping (nothing was sent to certutil)." -f $index, $total, $serial)
        )
        continue
    }

    if (-not $liveMode) {
        $dryRunCount++
        Write-Output ("[DRY-RUN] [{0}/{1}] Would revoke serial {2} (reason {3}, req_id {4}, revoked_at {5})" -f $index, $total, $serial, $reason, $reqId, $revokedAt)
        continue
    }

    Write-Output ("[{0}/{1}] Revoking serial {2} (reason {3}, req_id {4})..." -f $index, $total, $serial, $reason, $reqId)
    # Run Revoke-Cert.ps1 in a child PowerShell process so its `exit` code is
    # captured via $LASTEXITCODE (not propagated as our own).
    #
    # `2>&1` alone does NOT make the child's stderr safe: it turns each stderr
    # line into an ErrorRecord in the output stream, and under this script's
    # $ErrorActionPreference='Stop' the FIRST one is a terminating error. So
    # the moment a revoke failed -- exactly when the handling below matters --
    # the batch aborted here instead, skipping every remaining serial and
    # exiting 1 rather than the documented 2 (partial failure) or 5 (requester
    # mismatch). Suppressing Stop for the duration of the call is what actually
    # lets the child's failure be *handled* rather than thrown.
    # (Observed live on the lab CA, 2026-08-13.)
    #
    # By default, skip the CRL republish (certutil -CRL republish requires the
    # Manage-CA role, which a least-privilege revoker/officer identity does NOT
    # hold -- the revocation is recorded at the CA and appears at the next
    # scheduled CRL publication). Pass -PublishCrl to force an immediate
    # republish, which requires the identity to hold CRL-publish (Manage-CA)
    # rights -- an explicit operator trade-off (CRL freshness vs. a broader
    # grant). See docs/operations.md and threat-model section E.
    $revokeArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $revokeScript,
        '-CaConfig', $CaConfig, '-Serial', $serial, '-Reason', "$reason",
        '-RequesterName', $RequesterName
    )
    if (-not $PublishCrl) { $revokeArgs += '-SkipPublishCrl' }
    # 2026-08-24 live-found: the override must reach the CHILD too. Revoke-Cert.ps1
    # carries the same tree gate as this script, so without this line an
    # untrusted tree that was explicitly allowed at the task level could still
    # never revoke anything -- every child invocation refused at its own gate
    # and was classified 'failed'. The override exists for this flow; breaking
    # it one hop below the task action is the same defect the review's own
    # propagation fix was written to close.
    if ($AllowUntrustedScriptPath) { $revokeArgs += '-AllowUntrustedScriptPath' }
    $revokeRun = Invoke-ChildScript $pwshExe $revokeArgs
    $revokeOutput = $revokeRun.Output
    $revokeExit = $revokeRun.ExitCode
    $revokeOutput | ForEach-Object { Write-Output $_ }

    # See Get-RevokeOutcome in scripts/lib/SyncLib.ps1 for why exit 6
    # (already revoked at the CA) must NOT be handled as a failure — it is the
    # recovery path for a confirmation callback that failed on an earlier run
    # (2026-08-17 F4).
    $outcome = Get-RevokeOutcome $revokeExit

    if ($outcome -eq 'requester-mismatch') {
        $failed++
        [Console]::Error.WriteLine(("CRITICAL: Revoke-Cert.ps1 exited 5 (requester mismatch) for serial {0} -- the cert was NOT issued by the expected enrollment gMSA. This is a policy violation. Aborting the batch." -f $serial))
        exit 5
    }
    if (-not (Test-ShouldConfirmWithRa $outcome)) {
        $failed++
        [Console]::Error.WriteLine(("WARNING: Revoke-Cert.ps1 exited {0} for serial {1} -- logged, continuing to next serial." -f $revokeExit, $serial))
        continue
    }

    $alreadyRevokedAtCa = ($outcome -eq 'already-revoked')
    if ($alreadyRevokedAtCa) {
        $alreadyRevoked++
        Write-Output ("NOTE: serial {0} was already revoked at the CA (no change made). Retrying the RA confirmation..." -f $serial)
    } else {
        Write-Output ("PASS: revoked serial {0} at the CA. Confirming with the RA..." -f $serial)
    }

    # 3. Confirm with the RA so the audit flips ca_crl_updated=true and the
    #    serial drops out of the pending set. A confirm failure does NOT undo
    #    the CA-side revocation (which already happened) -- it means the RA
    #    audit still shows ca_crl_updated=false and the serial will reappear
    #    on the next pull. Log visibly and keep counting it as revoked.
    # `crl_published` tells the RA whether the CRL was actually republished, or
    # only the CA database updated. On the default least-privilege path the
    # officer CANNOT republish (that needs Manage-CA), so the honest answer is
    # usually $false: the certificate is revoked at the CA but still absent
    # from any published CRL, and relying parties keep accepting it until the
    # next scheduled publication. The RA records the distinction rather than
    # letting a field named ca_crl_updated imply more than happened.
    $confirmUrl = "$base/acme/admin/revocations/$serial/confirm"
    $confirmBody = if ($PublishCrl) { '{"ca_crl_updated": true, "crl_published": true}' }
                   else { '{"ca_crl_updated": true, "crl_published": false}' }
    try {
        Invoke-RestMethod -Method Post -Uri $confirmUrl -Headers $confirmHeaders `
            -Body $confirmBody -ContentType 'application/json' -TimeoutSec 60 | Out-Null
        Write-Output ("PASS: confirmed serial {0} with the RA." -f $serial)
    } catch {
        [Console]::Error.WriteLine(("WARNING: confirm POST for serial {0} failed: {1}" -f $serial, $_.Exception.Message))
        [Console]::Error.WriteLine("         The CA-side revocation SUCCEEDED, but the RA audit was not updated.")
        [Console]::Error.WriteLine("         The serial will reappear on the next pull until the confirm succeeds.")
        # Count it: the CA and the RA now disagree, and exiting 0 would tell
        # the scheduler everything was fine while the two sides drifted apart.
        # The next run now RECOVERS this rather than compounding it -- the
        # serial is still pending, Revoke-Cert exits 6 (already revoked at the
        # CA, no change made), and the agent retries just this callback.
        $confirmFailed++
    }
    if (-not $alreadyRevokedAtCa) { $revoked++ }
    Write-Output ""
}

# 4. Summary.
Write-Output ""
Write-Output ("SYNC COMPLETE: {0} pending, {1} revoked, {2} already-revoked-at-CA, {3} failed, {4} confirm-failed, {5} dry-run" -f $total, $revoked, $alreadyRevoked, $failed, $confirmFailed, $dryRunCount)

if ($alreadyRevoked -gt 0) {
    Write-Output ("NOTE: {0} serial(s) were already revoked at the CA -- their RA confirmation was retried" -f $alreadyRevoked)
    Write-Output "      rather than being booked as a revoke failure. That is the recovery path for a"
    Write-Output "      confirmation callback that failed on an earlier run (2026-08-17 F4)."
}

if ($confirmFailed -gt 0) {
    [Console]::Error.WriteLine(("WARNING: {0} serial(s) were revoked at the CA but NOT confirmed back to the RA." -f $confirmFailed))
    [Console]::Error.WriteLine("         The RA still lists them as pending and will offer them again next run.")
}

if ($failed -gt 0 -or $confirmFailed -gt 0) {
    exit 2
}
exit 0
