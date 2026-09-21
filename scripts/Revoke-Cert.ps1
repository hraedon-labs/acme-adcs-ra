<#
.SYNOPSIS
    Revoke a certificate at the ADCS CA out-of-band (WI-010), with a
    requester check (WI-022) that refuses to revoke certs not issued by the
    expected enrollment identity.

.DESCRIPTION
    acme-adcs-ra's `revokeCert` endpoint records the revocation in the RA store
    only -- it does NOT write the CA CRL, because the RA's gMSA intentionally
    holds no CA-officer ("Manage CA") rights (the project's tightest security
    tenet; see docs/threat-model.md section E). This script is the operator-run,
    CA-officer credential that performs the actual `certutil -revoke` against
    the CA, closing the loop the RA started.

    Run this as a CA officer (NOT the gMSA, NOT the RA host service account)
    from a management host that has RSAT / certutil available and line-of-sight
    to the CA. The serial or ReqID it consumes is exactly what the RA already
    stores and surfaces in its audit log and `revokeCert` response
    (`details.serial`, `details.req_id`, and the `out_of_band_revocation` hint).

    The script:
      1. Confirms the cert exists at the CA (by serial or ReqID) before
         revoking, so a typo cannot silently no-op. Confirmation is
         locale-independent: it matches the hex serial value (which is always
         hex regardless of OS locale), not a localized column header. It then
         asserts the CA-DB `Request.RequesterName` equals -RequesterName
         (default the enrollment gMSA), refusing to revoke a cert not issued by
         the expected identity (WI-022 -- defense-in-depth before the CA-side
         officer restriction; the requester value is a SID/name string, not a
         localized header, so the check is locale-independent).
      2. Maps the RFC 8555 reason code (0-10) to the `certutil -revoke`
         reason code (0=unspecified, 1=compromised, 2=CA compromise,
         3=affiliation changed, 4=superseded, 5=cessation of operation,
         6=certificate hold, 8=remove from CRL, 9=privilege withdrawn,
         10=AA compromise). Reason 7 is unused in RFC 5280 and is rejected.
      3. Runs `certutil -revoke <serial> <reason> -config <CA>` and prints the
         outcome.
      4. Re-publishes the CRL so the revocation is visible without waiting for
         the next scheduled publication (`certutil -CRL republish -config <CA>`).

    This is a documented, auditable operator action -- the RA's audit log
    records `revocation_scope=ra-store-only, ca_crl_updated=false` and this
    script's invocation (with the operator identity in the CA database) is the
    matching out-of-band half. Keep both records together in incident review.

    Exit codes:
      0  = success
      3  = validation error (bad params, invalid reason)
      4  = cert not found at the CA (serial or ReqID does not resolve)
      5  = requester mismatch (cert was not issued by the expected enrollment
           identity -- WI-022)
      6  = already revoked at the CA; no CA-side change was made. NOT a failure:
           the CA state is what was wanted. Sync-Revocations.ps1 treats this as
           "retry the RA confirmation", which is what makes a dropped callback
           recoverable instead of permanent (2026-08-17 F4).
      N  = certutil exit code (transport / CA-side failure)

.PARAMETER Serial
    The certificate serial number (uppercase hex, no `0x` prefix) as the RA
    stores it (e.g. `1A2B3C...`). Use this when you have the RA's
    `details.serial`.

.PARAMETER ReqID
    The ADCS request ID (decimal) as the RA stores it (e.g. `42`). Use this
    when you have the RA's `details.req_id`. The script looks up the serial
    from the CA database via `certutil -view` and then revokes by serial
    (`certutil -revoke` accepts serials only). Either -Serial or -ReqID is
    required; -Serial wins if both are given.

.PARAMETER CaConfig
    The CA configuration string (`CA01\WORK-DOMAIN-CA` form). Required --
    certutil needs it to address the CA. Use the placeholder form in committed
    samples; the real value lives in gitignored local config.

.PARAMETER Reason
    RFC 8555 revocation reason code (0-10). Default 0 (unspecified).

.PARAMETER RequesterName
    The expected enrollment identity (the gMSA that enrolls via the RA), in
    `DOMAIN\account` form. The script asserts the CA-DB
    `Request.RequesterName` of the target cert matches this value before
    revoking (WI-022 -- defense-in-depth, bounds any operator typo or
    automation to the RA's own issuance). Default:
    `WORK-DOMAIN\gMSA-acme-ra$` (placeholder form -- the real value lives in
    gitignored local config). The comparison is case-insensitive and
    locale-independent (the requester value is a SID/name string, not a
    localized column header).

.PARAMETER SkipPublishCrl
    Skip the `certutil -CRL republish` step (use if a scheduled publication is
    imminent or another operator is publishing).

.EXAMPLE
    # Revoke by serial with the RA's details.serial:
    powershell -File .\scripts\Revoke-Cert.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -Serial '1A2B3C' -Reason 1

.EXAMPLE
    # Revoke by the RA's details.req_id (looks up the serial first):
    powershell -File .\scripts\Revoke-Cert.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -ReqID 42 -Reason 0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Serial")]
    [string]$Serial,

    [Parameter(Mandatory = $true, ParameterSetName = "ReqID")]
    [string]$ReqID,

    [Parameter(Mandatory = $true)][string]$CaConfig,
    [int]$Reason = 0,
    [string]$RequesterName = "WORK-DOMAIN\gMSA-acme-ra$",
    [switch]$SkipPublishCrl,
    # Accept a script tree that is not administrator-only -- lab and
    # first-install flows stage scripts\ under paths like C:\Temp, and a hard
    # refusal with no override strands them. See the gate below.
    [switch]$AllowUntrustedScriptPath
)

$ErrorActionPreference = "Stop"

# Elevated native helpers resolve to absolute System32 paths, never to ambient
# PATH. Round-6 finding 3 removed PATH-selected programs from the installer;
# these scripts were missed, and they are the higher-value half -- this one
# runs with CA-officer context. A writable PATH entry would be code execution
# with that context. The System directory comes from the RUNTIME, not
# $env:windir -- which is caller-settable process state, the same class as the
# $env:OS gate the round-3 review moved off the environment.

# Shared pure logic (serial normalization, reason/requester rules), covered by
# tests/pester/Revocation.Tests.ps1. Deploy scripts/lib/ alongside this script
# -- see docs/operations.md; copying individual .ps1 files breaks provisioning.
# PROVENANCE FIRST, THEN SIBLINGS (2026-08-24 F10). This script runs with
# CA-officer context and dot-sourced its sibling with nothing checking whether
# the tree it came from is administrator-only -- the same class the paragraph
# above closed for PATH-selected programs, one line lower down.
# InstallVerifyLib is the code that authenticates this privileged script tree,
# so executing it from disk before authenticating it would make the later tree
# verdict self-referential. Pin its canonical UTF-8/LF bytes here, hash the
# in-memory text, and execute that exact verified text (never reopen the path).
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
    -Purpose 'manual certificate revocation' `
    -AllowUntrusted:$AllowUntrustedScriptPath -RunTime

. "$PSScriptRoot/lib/RevocationLib.ps1"

# Write an error message to stderr and exit with a specific code. Using
# [Console]::Error.WriteLine (not Write-Error) so $ErrorActionPreference=Stop
# does not turn the message into a terminating exception that swallows the
# exit code -- the documented exit-code contract (3=validation, 4=not-found,
# 5=requester mismatch, certutil-code=transport) must be reachable by wrapping
# automation.
function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

$script:CertUtilExe = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)) 'certutil.exe'
if (-not (Test-Path -LiteralPath $script:CertUtilExe)) {
    Die "certutil.exe not found at $script:CertUtilExe" 2
}

# RFC 5280 section 5.3.1 reason codes. certutil -revoke uses the same numeric
# codes, with two exclusions:
#
#   7 -- "unused" in RFC 5280 (not an RFC 8555 reason); certutil rejects it.
#   8 -- removeFromCRL. This is the UN-revoke operation, not a revocation.
#        `certutil -revoke <serial> 8` asks the CA to take a certificate back
#        OFF the CRL. This script exists to revoke, and it is the last gate in
#        front of the CA for both the operator path and the sync agent, so it
#        refuses 8 outright. Reason 6 (certificateHold) is still accepted: a
#        hold is strictly more restrictive than valid.
#
# The RA rejects 8 at the ACME surface too, but this check is what protects a
# deployment whose store still holds a reason-8 row written before that fix.
$validReasons = @(0, 1, 2, 3, 4, 5, 6, 9, 10)
if ($Reason -notin $validReasons) {
    Die ("Reason {0} is not a valid revocation reason (0-6, 9-10). Reason 7 is unused in RFC 5280; reason 8 is removeFromCRL, which un-revokes rather than revokes." -f $Reason) 3
}

# WI-022: the requester check is a defense-in-depth gate -- an empty value
# would match trivially, so require it non-empty. The default is the gMSA
# placeholder; an operator may override it per deployment.
if ([string]::IsNullOrWhiteSpace($RequesterName)) {
    Die "-RequesterName is empty or whitespace. Pass the expected enrollment identity (e.g. WORK-DOMAIN\gMSA-acme-ra$)." 3
}

# Capture certutil output with stderr merged, WITHOUT the Windows PowerShell
# 5.1 redirection trap. Under EAP=Stop a merged stderr line terminates the
# pipeline before $LASTEXITCODE is ever read -- SyncLib documents the
# behaviour from a live 2026-08-13 observation -- which makes the documented
# exit-code contract ("exit N = certutil's own code") unreachable and replaces
# it with an unhandled terminating error (powershell.exe exits 1 instead of
# N, so batch automation cannot distinguish failure classes). EAP is lowered
# ONLY around the native call; pwsh 7 behaviour is unchanged (there
# $PSNativeCommandUseErrorActionPreference defaults off and merged stderr
# arrives as ErrorRecords either way). Every `2>&1` call to certutil in this
# file goes through here -- Invoke-CertUtil and the three direct -view calls
# in Test-SerialRevokedAtCa, which deliberately do NOT Die so they can treat
# "certutil could not answer" as not-revoked and re-revoke on the next pass.
#
# Both helpers are ADVANCED functions ([CmdletBinding()]) for a reason found
# live on 2026-08-17: a plain function silently collects surplus positional
# arguments into $args. `Invoke-CertUtilCapture @CertutilArgs` -- splatting an
# ARRAY into a PowerShell function rather than into a native command -- bound
# only the first element and dropped the other six, so every certutil call in
# this file ran WITHOUT its `-config`, and the agent failed on a non-CA host
# with "No local Certification Authority; use -config option". The splat was
# correct in the original `& certutil @CertutilArgs` (native commands do take
# one argument per element) and was carried unchanged onto a function call in
# a69859d. With [CmdletBinding()] that mistake is a loud binding error instead
# of six silently discarded arguments.
function Invoke-CertUtilCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$CertutilArgs)
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        return (& $script:CertUtilExe @CertutilArgs 2>&1)
    } finally {
        $ErrorActionPreference = $prior
    }
}

function Invoke-CertUtil {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$CertutilArgs)
    # Pass the array as ONE argument -- NOT `@CertutilArgs`. See above.
    $out = Invoke-CertUtilCapture $CertutilArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Die ("certutil exited {0}: {1}" -f $code, ($out -join "`n")) $code
    }
    return $out
}

# Locale-independent confirmation: match the hex serial value itself (always
# hex regardless of OS locale), not a localized column header. This avoids
# the WI-007 class of bug (locale-dependent string parsing). Also asserts the
# CA-DB RequesterName matches the expected enrollment identity (WI-022):
# the requester value is a SID/name string (locale-independent), so the check
# matches the value, not a localized column header.
function Confirm-SerialAtCa([string]$CaConfig, [string]$SerialHex, [string]$ExpectedRequester) {
    Write-Output ("Confirming cert with serial {0} at CA '{1}'..." -f $SerialHex, $CaConfig)
    $viewOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex", '-out', 'SerialNumber')
    $viewOut | ForEach-Object { Write-Output $_ }
    # The hex serial value is locale-independent; match it case-insensitively
    # in the joined output. If certutil -view found no matching row, the
    # serial value will not appear. Join the array first -- -notmatch on an
    # array filters (returns non-matching elements, always truthy), not a
    # boolean test.
    $joined = $viewOut -join "`n"
    if ($joined -notmatch [regex]::Escape($SerialHex)) {
        Die ("No certificate with serial {0} found at CA '{1}' -- refusing to revoke." -f $SerialHex, $CaConfig) 4
    }

    # WI-022: assert the cert was requested by the expected enrollment
    # identity (defense-in-depth before the CA-side officer restriction).
    Write-Output ("Confirming requester for serial {0} is '{1}'..." -f $SerialHex, $ExpectedRequester)
    $reqOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex", '-out', 'Request.RequesterName')
    $reqOut | ForEach-Object { Write-Output $_ }
    $reqJoined = $reqOut -join "`n"
    # The requester value is a DOMAIN\account string (locale-independent);
    # extract it with a regex rather than matching a localized header. The
    # first DOMAIN\account token in the output is the requester -- certutil
    # -view -out Request.RequesterName emits only that column, so no other
    # backslash-bearing token appears.
    $actualRequester = $null
    $reqMatch = [regex]::Match($reqJoined, '([A-Za-z0-9][A-Za-z0-9._-]*\\[A-Za-z0-9][A-Za-z0-9._$-]*)')
    if ($reqMatch.Success) {
        $actualRequester = $reqMatch.Groups[1].Value
    }
    if ($null -eq $actualRequester) {
        Die ("Could not parse Request.RequesterName for serial {0} at CA '{1}' -- refusing to revoke (unable to confirm requester)." -f $SerialHex, $CaConfig) 5
    }
    if (-not $actualRequester.Equals($ExpectedRequester, [System.StringComparison]::OrdinalIgnoreCase)) {
        Die ("Requester mismatch for serial {0}: expected '{1}', got '{2}' -- refusing to revoke (cert was not issued by the expected enrollment identity)." -f $SerialHex, $ExpectedRequester, $actualRequester) 5
    }
    Write-Output ("PASS: requester confirmed: {0}" -f $actualRequester)
}

# Is this serial already revoked in the CA database?
#
# Locale-independent by the same technique Confirm-SerialAtCa uses and this
# project already trusts: restrict the view and look for the serial VALUE in the
# output rather than parsing a localized column header or status word. The extra
# restriction is `Disposition=21`, ADCS's numeric code for a revoked row (20 is
# issued) -- a number, so no locale enters into it.
#
# Two deliberate safety properties, because this decides whether to skip a
# revocation:
#
#   * `Invoke-CertUtil` is NOT used, because a restriction that matches no rows
#     can exit non-zero and that is a normal answer here, not a fatal error. Any
#     non-zero exit means "could not establish it" and returns $false, so the
#     script falls through to attempting the revoke exactly as it did before.
#   * The Disposition restriction is self-checked. If the serial also comes back
#     under `Disposition=20` (issued), the CA is not honouring the restriction
#     the way this assumes, so its answer is not trusted and the result is
#     $false. Skipping a revocation that was actually needed is the one outcome
#     here that would be worse than the bug being fixed, so it takes a filter
#     that demonstrably discriminates -- not an assumption about certutil's
#     behaviour that this host cannot verify.
function Test-SerialRevokedAtCa([string]$CaConfig, [string]$SerialHex) {
    $escaped = [regex]::Escape($SerialHex)

    $revokedOut = Invoke-CertUtilCapture @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex,Disposition=21", '-out', 'SerialNumber')
    if ($LASTEXITCODE -ne 0) { return $false }
    if (($revokedOut -join "`n") -notmatch $escaped) { return $false }

    # It claims revoked. Prove the filter actually filters before acting on it.
    $issuedOut = Invoke-CertUtilCapture @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex,Disposition=20", '-out', 'SerialNumber')
    if ($LASTEXITCODE -eq 0 -and (($issuedOut -join "`n") -match $escaped)) {
        # stderr, NOT Write-Output: this function's value is consumed as a
        # boolean by `if (Test-SerialRevokedAtCa ...)`, and anything written to
        # the success stream becomes part of the return value. Three strings
        # plus $false is a non-empty array, which PowerShell evaluates as TRUE
        # -- inverting the answer. See the reason-8 branch below.
        [Console]::Error.WriteLine(("WARNING: the CA returned serial {0} for BOTH Disposition=21 (revoked) and Disposition=20 (issued)." -f $SerialHex))
        [Console]::Error.WriteLine("         The Disposition restriction is not discriminating, so its answer is not trusted.")
        [Console]::Error.WriteLine("         Proceeding with the revocation attempt as though the state were unknown.")
        return $false
    }
    # Disposition 21 is NOT proof of revocation on its own.
    #
    # `RevocationLib.ps1` records what the Plan 004 lab spike established: a
    # certificate placed on hold and then given reason 8 (removeFromCRL) ends up
    # "off the CRL and valid" while ADCS keeps its DB Disposition at 21. So the
    # row this function has just matched may describe a certificate that relying
    # parties still accept (2026-08-18 wave 3 F1).
    #
    # That matters here specifically because returning $true makes the caller
    # exit 6 -- "already revoked, go confirm to the RA" -- which drains the
    # serial off the RA's pending-revocation feed and records
    # `revocation-ca-confirmed`. For a reason-8 row that is a containment
    # failure written down as a success.
    #
    # Same technique as the Disposition self-check above: restrict on the
    # numeric reason rather than parsing a localized column, and treat an
    # inconclusive answer as "not revoked" so the caller re-revokes. Re-revoking
    # a genuinely revoked certificate is harmless; skipping a live one is not.
    $unrevokedOut = Invoke-CertUtilCapture @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex,Disposition=21,Request.RevokedReason=8", '-out', 'SerialNumber')
    if ($LASTEXITCODE -eq 0 -and (($unrevokedOut -join "`n") -match $escaped)) {
        # stderr, NOT Write-Output. The 2026-08-14 live re-proof caught this
        # branch firing correctly and then being defeated by its own
        # diagnostics: a PowerShell function returns everything written to the
        # success stream, so `return $false` after three Write-Output calls
        # yields @(three strings, $false). The call site is
        # `if (Test-SerialRevokedAtCa ...)`, a non-empty array is truthy, and
        # the caller therefore read "already revoked" for a certificate that is
        # off the CRL and still VALID -- exiting 6, draining the serial off the
        # RA's pending feed and recording `revocation-ca-confirmed`. The fix for
        # wave-3 F1 was inert in exactly the case it existed to catch.
        [Console]::Error.WriteLine(("NOTE: serial {0} is Disposition=21 but its revocation reason is 8 (removeFromCRL)." -f $SerialHex))
        [Console]::Error.WriteLine("      That is the UN-revoke state: the certificate is off the CRL and still valid.")
        [Console]::Error.WriteLine("      Treating it as NOT revoked and proceeding with the revocation.")
        return $false
    }
    return $true
}

# Look up the serial from a ReqID via certutil -view, locale-independently.
# certutil -view output pairs the column with its value; the SerialNumber
# value is a hex string (locale-independent). Parse it with a hex regex.
function Get-SerialFromReqId([string]$CaConfig, [string]$Rid) {
    # Diagnostics go to STDERR, never the success stream.
    #
    # A PowerShell function returns EVERYTHING written to the success stream, so
    # emitting a banner there does not print it -- it prepends banner lines to
    # the return value. `$targetSerial` at the call site became a 5-element
    # array, and the very next statement pasted it into
    # `-restrict SerialNumber=<banner lines...>`, so -ReqID could never revoke
    # anything: it dies at exit 4 ("no certificate with serial ... found") or on
    # a certutil parse error.
    #
    # This is the same defect the 2026-08-18 wave-3 round fixed in
    # Test-SerialRevokedAtCa, 130 lines above, in this file -- the sibling was
    # missed. It fails SAFE (nothing wrong is revoked) but it takes out the
    # manual containment path an operator reaches for during an incident.
    # Sync-Revocations.ps1 always passes -Serial, which is why no live re-proof
    # has ever exercised this branch.
    [Console]::Error.WriteLine(("Looking up serial for ReqID {0} at CA '{1}'..." -f $Rid, $CaConfig))
    $viewOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "RequestID=$Rid", '-out', 'SerialNumber')
    $viewOut | ForEach-Object { [Console]::Error.WriteLine([string]$_) }
    # The serial is a hex string (0-9A-Fa-f). With -out SerialNumber the output
    # is restricted to the serial column, so the longest hex run is the serial
    # (row indices and other metadata are shorter / non-hex). Word-boundary
    # anchored to avoid matching a hex substring embedded in a longer token.
    $joined = $viewOut -join "`n"
    $allMatches = [regex]::Matches($joined, '\b[0-9A-Fa-f]{8,}\b')
    if ($allMatches.Count -eq 0) {
        Die ("Could not find a serial number for ReqID {0} at CA '{1}' -- the request may not have issued a cert." -f $Rid, $CaConfig) 4
    }
    # Serials are the longest hex run in -out SerialNumber output.
    $serial = ($allMatches | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1).Value
    return $serial.ToUpperInvariant()
}

# 1. Resolve the target serial and confirm it exists at the CA.
if ($PSCmdlet.ParameterSetName -eq "Serial") {
    if ([string]::IsNullOrWhiteSpace($Serial)) {
        Die "-Serial is empty or whitespace." 3
    }
    # The serial reaches certutil as an argument, and certutil gives some
    # characters meaning there -- `-revoke` takes a COMMA-SEPARATED LIST, so
    # `<real>,<other>` would revoke a second certificate that was never
    # confirmed, never requester-checked, and never audited by the RA. Refuse
    # before the first certutil call rather than after. See Test-CaSerialForm
    # in scripts/lib/RevocationLib.ps1 for why this lives at the privileged end.
    if (-not (Test-CaSerialForm $Serial)) {
        Die ("-Serial '{0}' is not a plain hex serial." -f $Serial) 3
    }
    # Re-pad to the CA database's stored form before any -restrict lookup: the
    # RA emits serials without a leading zero (Python format(n,'x')), while
    # ADCS stores the full byte string, and -restrict is an exact string match.
    # See Get-CaSerialForm in scripts/lib/RevocationLib.ps1.
    $targetSerial = (Get-CaSerialForm ($Serial.Trim())).ToUpperInvariant()
    Confirm-SerialAtCa $CaConfig $targetSerial $RequesterName
} else {
    $rid = $ReqID.Trim()
    if ($rid -notmatch '^\d+$') {
        Die ("ReqID '{0}' is not a decimal integer." -f $rid) 3
    }
    $targetSerial = Get-SerialFromReqId $CaConfig $rid
    Confirm-SerialAtCa $CaConfig $targetSerial $RequesterName
}

# 1b. Is the CA already holding this serial as revoked?
#
# 2026-08-17 F4. The sync agent revokes at the CA and THEN calls the RA back.
# If that callback failed (a transient network fault is enough), the serial
# stayed pending, the next sweep re-ran this script, `certutil -revoke` returned
# non-zero for an already-revoked certificate, and the agent booked that as a
# failure and skipped the callback -- for ever. One dropped HTTPS request
# permanently desynchronized the RA's audit from the CA, and recovery required a
# human. The CA side was already correct the whole time; only the callback was
# outstanding, and nothing would retry it.
#
# So: ask the CA whether it has already revoked this serial, and if so exit with
# a distinct code that tells the agent "no change needed here, go retry your
# callback" instead of re-attempting a mutation that cannot succeed.
#
# The requester check above has already run, so a certificate that is not ours
# still exits 5 on this path -- being already revoked does not buy an unknown or
# mis-requested certificate a pass.
if (Test-SerialRevokedAtCa $CaConfig $targetSerial) {
    Write-Output ("NOTE: serial {0} is ALREADY revoked in the CA database; not re-revoking." -f $targetSerial)
    if ($SkipPublishCrl) {
        Write-Output "Skipping CRL publication (-SkipPublishCrl)."
    } else {
        # Still worth doing: the certificate may be revoked in the CA database
        # while no published CRL lists it yet, which is exactly the state the
        # default least-privilege path leaves behind.
        Write-Output ("Publishing CRL at CA '{0}'..." -f $CaConfig)
        $publishOut = Invoke-CertUtil @('-config', $CaConfig, '-CRL', 'republish')
        $publishOut | ForEach-Object { Write-Output $_ }
        Write-Output "PASS: CRL republished."
    }
    Write-Output ""
    Write-Output ("Serial {0} was already revoked at the CA. No CA-side change was made." -f $targetSerial)
    Write-Output "If the RA still lists it as pending, its confirmation callback never landed --"
    Write-Output "that is what exit code 6 tells the sync agent to retry."
    exit 6
}

# 2. Revoke by serial. certutil -revoke accepts serials only (not ReqIDs).
#    Syntax: certutil -config <CA> -revoke <SerialNumber> [Reason]
#    NOTE: -config must precede the -revoke verb. certutil's -revoke collects
#    every following token as a positional arg, so a trailing "-config <CA>"
#    is mis-parsed ("Expected no more than 2 args, received 4") rather than
#    consumed as the config option.
Write-Output ("Revoking serial {0}, reason = {1}..." -f $targetSerial, $Reason)
$revokeOut = Invoke-CertUtil @('-config', $CaConfig, '-revoke', $targetSerial, "$Reason")
$revokeOut | ForEach-Object { Write-Output $_ }
Write-Output ("PASS: certutil -revoke reported success for serial {0} (reason {1})." -f $targetSerial, $Reason)

# 3. Re-publish the CRL so the revocation is visible without waiting for the
#    next scheduled publication. This is the operator-visible "the CRL now
#    reflects the revocation" step the RA's audit log records as still-pending
#    (ca_crl_updated=false) until this script runs.
if ($SkipPublishCrl) {
    Write-Output "Skipping CRL publication (-SkipPublishCrl). The revocation will appear at the next scheduled publication."
} else {
    Write-Output ("Publishing CRL at CA '{0}'..." -f $CaConfig)
    $publishOut = Invoke-CertUtil @('-config', $CaConfig, '-CRL', 'republish')
    $publishOut | ForEach-Object { Write-Output $_ }
    Write-Output "PASS: CRL republished."
}

# 4. Completion text that matches the branch actually taken.
#
# This block used to end with an unconditional "...and the CRL is published",
# which is false on the DEFAULT path (-SkipPublishCrl, which Sync-Revocations
# passes because a least-privilege officer cannot republish). See
# Get-RevocationCompletionMessage in scripts/lib/RevocationLib.ps1 for why the
# distinction matters and tests/pester/Revocation.Tests.ps1 for its coverage.
Write-Output ""
Get-RevocationCompletionMessage -Serial $targetSerial -SkipPublishCrl:$SkipPublishCrl |
    ForEach-Object { Write-Output $_ }
exit 0
