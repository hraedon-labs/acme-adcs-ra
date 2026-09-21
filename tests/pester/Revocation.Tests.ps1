BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/RevocationLib.ps1"
}

Describe 'Get-ValidRevocationReasons' {
    It 'Returns exactly @(0, 1, 2, 3, 4, 5, 6, 9, 10)' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Be @(0, 1, 2, 3, 4, 5, 6, 9, 10)
    }

    It 'Does NOT contain 7' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Not -Contain 7
    }

    It 'Does NOT contain 8 (removeFromCRL un-revokes)' {
        # Plan 004 proved against the lab CA that reason 8 leaves a held
        # certificate "off the CRL and valid". A revocation path must never
        # be able to emit it.
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Not -Contain 8
    }
}

Describe 'Test-RevocationReason' {
    It 'Returns $true for each valid reason' {
        foreach ($r in @(0, 1, 2, 3, 4, 5, 6, 9, 10)) {
            Test-RevocationReason $r | Should -BeTrue -Because "reason $r should be valid"
        }
    }

    It 'Returns $false for 7 (unused in RFC 5280)' {
        Test-RevocationReason 7 | Should -BeFalse
    }

    It 'Returns $false for 8 (removeFromCRL is the un-revoke operation)' {
        Test-RevocationReason 8 | Should -BeFalse
    }

    It 'Returns $false for -1' {
        Test-RevocationReason -1 | Should -BeFalse
    }

    It 'Returns $false for 11' {
        Test-RevocationReason 11 | Should -BeFalse
    }
}

Describe 'Compare-RequesterName' {
    It 'Exact match returns $true' {
        Compare-RequesterName 'WORK-DOMAIN\gMSA-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeTrue
    }

    It 'Case-insensitive match returns $true' {
        Compare-RequesterName 'WORK-DOMAIN\gmsa-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeTrue
    }

    It 'Different domain returns $false' {
        Compare-RequesterName 'OTHER-DOMAIN\gMSA-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }

    It 'Different account returns $false' {
        Compare-RequesterName 'WORK-DOMAIN\svc-other$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }

    It 'Empty actual returns $false' {
        Compare-RequesterName '' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }
}

Describe "Get-CaSerialForm" {
    It "re-pads an odd-length serial to the CA's stored even-length form" {
        # The RA emits format(n,'x') which drops a leading zero; ADCS stores the
        # full byte string, and -restrict is an exact string match.
        Get-CaSerialForm "6AB1C" | Should -Be "06AB1C"
    }

    It "leaves an even-length serial unchanged" {
        Get-CaSerialForm "6C0000006E14EDCC" | Should -Be "6C0000006E14EDCC"
    }

    It "strips an 0x prefix before padding" {
        Get-CaSerialForm "0x6AB1C" | Should -Be "06AB1C"
        Get-CaSerialForm "0X6AB1C2" | Should -Be "6AB1C2"
    }

    It "trims surrounding whitespace" {
        Get-CaSerialForm "  6AB1C2  " | Should -Be "6AB1C2"
    }

    It "returns empty or whitespace input unchanged" {
        Get-CaSerialForm "" | Should -Be ""
    }
}

Describe "Test-CaSerialForm" {
    # The serial reaches certutil as an ARGUMENT. `certutil -revoke` documents
    # its argument as a comma-separated LIST of serials, and `-restrict
    # "SerialNumber=$s"` treats a comma as a second query clause -- so a
    # non-hex serial is not a cosmetic problem at the CA-officer end.
    #
    # Nothing reachable emits one today (the RA serves canonical_serial() of a
    # parsed certificate). The check guards the boundary, not a known input:
    # Sync-Revocations takes this value from the RA's JSON over the network,
    # and the RA is exactly the component that must NOT be able to drive
    # certutil.

    It "accepts every spelling Get-CaSerialForm already normalizes" {
        # The over-strict direction is the dangerous one: refusing a
        # legitimate serial is a containment failure. These must all pass.
        foreach ($s in @(
            "6C0000006E14EDCC",   # canonical: uppercase, even length
            "6ab1c2",             # lowercase
            "6AB1C",              # odd length (RA's format(n,'x') form)
            "0x6AB1C2",           # operator copy-paste, 0x prefix
            "0X6AB1C2",           # uppercase prefix
            "  6AB1C2  ",         # surrounding whitespace
            "0006AB1C2",          # zero-padded
            "0",                  # the minimum
            ("A" * 64)            # the documented ceiling
        )) {
            Test-CaSerialForm $s | Should -BeTrue -Because "'$s' is a legitimate serial spelling"
        }
    }

    It "refuses a comma-separated list, which certutil -revoke would honour" {
        Test-CaSerialForm "6AB1C2,DEADBEEF" | Should -BeFalse
    }

    It "refuses a value that would inject a second -restrict clause" {
        Test-CaSerialForm "6AB1C2,Disposition=20" | Should -BeFalse
    }

    It "refuses whitespace-separated extra arguments" {
        Test-CaSerialForm "6AB1C2 -config EVIL" | Should -BeFalse
        Test-CaSerialForm "6AB1C2`tDEADBEEF" | Should -BeFalse
    }

    It "refuses an EMBEDDED newline, which the \\A..\\z anchors are for" {
        # PowerShell's $ anchor matches before a trailing newline, so a naive
        # '^[0-9A-Fa-f]+$' would accept a multi-line value on the strength of
        # its first line alone. Test-CaSerialForm uses \A..\z instead.
        Test-CaSerialForm "6AB1C2`nDEADBEEF" | Should -BeFalse
        Test-CaSerialForm "6AB1C2`r`nDEADBEEF" | Should -BeFalse
        Test-CaSerialForm "6AB1C2`n-config EVIL" | Should -BeFalse
    }

    It "ACCEPTS a trailing newline, because Trim removes it before use" {
        # Not an inconsistency with the case above: Trim() strips leading and
        # trailing whitespace (newlines included), and the trimmed value is
        # exactly what Get-CaSerialForm hands to certutil. The character is
        # gone by the time anything acts on it, so refusing here would reject
        # a legitimate serial -- the containment-failure direction.
        Test-CaSerialForm "6AB1C2`n" | Should -BeTrue
        Test-CaSerialForm "`n6AB1C2`n" | Should -BeTrue
        Get-CaSerialForm "6AB1C2`n" | Should -Be "6AB1C2"
    }

    It "refuses non-hex characters" {
        foreach ($s in @("6AB1G2", "ZZZZ", "6AB1C2;", "6AB1C2&whoami", "../../etc", "6AB1C2%00")) {
            Test-CaSerialForm $s | Should -BeFalse -Because "'$s' is not plain hex"
        }
    }

    It "refuses empty, whitespace, and null" {
        Test-CaSerialForm "" | Should -BeFalse
        Test-CaSerialForm "   " | Should -BeFalse
        Test-CaSerialForm $null | Should -BeFalse
    }

    It "refuses a serial longer than the documented ceiling" {
        # Bounds the argument; 64 hex digits is 32 octets, well past RFC 5280's
        # 20-octet cap and past anything the lab CA emits (32 and 38 digits).
        Test-CaSerialForm ("A" * 65) | Should -BeFalse
    }

    It "refuses an 0x prefix with nothing after it" {
        Test-CaSerialForm "0x" | Should -BeFalse
    }

    It "agrees with Get-CaSerialForm on everything it accepts" {
        # The two must not disagree about which spellings are legitimate: a
        # value this accepts but the normalizer mangles, or vice versa, is how
        # the pair drifts apart. Every accepted value must normalize to plain
        # even-length hex.
        foreach ($s in @("6C0000006E14EDCC", "6ab1c2", "6AB1C", "0x6AB1C2", "  6AB1C2  ", "0")) {
            $normalized = Get-CaSerialForm $s
            $normalized | Should -Match '\A[0-9A-Fa-f]+\z'
            ($normalized.Length % 2) | Should -Be 0
        }
    }
}

Describe 'Get-RevocationCompletionMessage' {
    # 2026-08-16 rescan F2. The default batch path passes -SkipPublishCrl, and
    # the old unconditional trailer told the operator the CRL was published
    # anyway -- in the same output that had just said publication was skipped.
    # Closing containment on that line leaves a revoked certificate accepted by
    # relying parties until the next scheduled CRL.

    It 'never claims publication on the skip path' {
        $lines = Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl
        $text = $lines -join ' '
        $text | Should -Not -Match 'CRL is published'
        $text | Should -Not -Match 'has been republished'
        $text | Should -Match 'NOT republished'
    }

    It 'says containment is not complete on the skip path' {
        $text = (Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join ' '
        $text | Should -Match 'PARTIALLY complete'
        $text | Should -Match 'Do NOT close containment'
    }

    It 'claims publication only on the publish path' {
        $text = (Get-RevocationCompletionMessage -Serial '6AB1C2') -join ' '
        $text | Should -Match 'the CRL is published'
        $text | Should -Match 'has been republished'
        $text | Should -Not -Match 'PARTIALLY complete'
    }

    It 'gives the two branches distinct completion text' {
        $skip = (Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join "`n"
        $publish = (Get-RevocationCompletionMessage -Serial '6AB1C2') -join "`n"
        $skip | Should -Not -Be $publish
    }

    It 'names the serial it acted on in both branches' {
        ((Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join ' ') |
            Should -Match '6AB1C2'
        ((Get-RevocationCompletionMessage -Serial '6AB1C2') -join ' ') |
            Should -Match '6AB1C2'
    }
}

# 2026-08-14 live re-proof. Test-SerialRevokedAtCa lives in Revoke-Cert.ps1
# rather than lib/, so nothing covered it, and the wave-3 F1 fix shipped inert:
# its branches wrote three Write-Output diagnostics before `return $false`, and
# a PowerShell function returns EVERYTHING on the success stream. The call site
# is `if (Test-SerialRevokedAtCa ...)`; @(three strings, $false) is a non-empty
# array, which is truthy, so a reason-8 certificate -- off the CRL and still
# VALID -- was read as "already revoked".
#
# The function is extracted by AST so these assertions run against the real
# shipped text, and certutil is stubbed so no CA is required.
Describe 'Test-SerialRevokedAtCa (extracted from Revoke-Cert.ps1)' {
    BeforeAll {
        $script:src = Join-Path $PSScriptRoot '../../scripts/Revoke-Cert.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path $script:src).Path, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Test-SerialRevokedAtCa' }, $true) | Select-Object -First 1
        if ($null -eq $fn) { throw 'Test-SerialRevokedAtCa not found in Revoke-Cert.ps1' }
        Invoke-Expression $fn.Extent.Text
        # Round 7.4: Test-SerialRevokedAtCa's certutil calls now go through
        # Invoke-CertUtilCapture (the EAP shield that keeps the exit-code
        # contract reachable on Windows PowerShell 5.1), so the lift needs the
        # sibling too or every test below dies on CommandNotFoundException --
        # the same lifted-function dependency the harness already documents for
        # $script:CertUtilExe.
        $cap = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Invoke-CertUtilCapture' }, $true) | Select-Object -First 1
        if ($null -eq $cap) { throw 'Invoke-CertUtilCapture not found in Revoke-Cert.ps1' }
        Invoke-Expression $cap.Extent.Text
        # Supply the script-scope context the lifted function expects. The shipped
        # script resolves certutil to an absolute System32 path (round 7.3, so a
        # writable PATH entry is not code execution with CA-officer rights); these
        # tests stub certutil as a COMMAND, so the harness points the variable at
        # the bare name. Without it the lifted function invokes $null -- which is
        # the same "& $null" class these rounds keep finding, surfaced here by the
        # AST lift rather than in production.
        $script:CertUtilExe = 'certutil'
    }

    It 'returns a value that is FALSE at the call site for a reason-8 row' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        # Every restrict matches: disposition 21 yes, disposition 20 no, reason 8 yes.
        function certutil {
            $global:LASTEXITCODE = 0
            # Round 7.4: the shipped calls now go through
            # Invoke-CertUtilCapture, which SPLATS the argument array, so the
            # restrict string is one element among several in $args rather
            # than inside a single array-valued $args[0]. Scan all of $args:
            # correct under both shapes.
            $restrict = $args | Where-Object { $_ -like 'SerialNumber=*' }
            if ("$restrict" -like '*Disposition=20*') { return @('no rows') }
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial

        # The assertion that matters is the caller's, not -Be $false: the bug
        # returned an ARRAY ending in $false, which -Be $false would not catch
        # but `if (...)` reads as true.
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeFalse -Because 'a reason-8 row must not be read as already-revoked'
        @($result).Count | Should -Be 1 -Because 'diagnostics must not join the return value'
    }

    It 'returns a value that is FALSE at the call site when the CA fails to discriminate' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        # Pathological CA: returns the serial for BOTH dispositions.
        function certutil {
            $global:LASTEXITCODE = 0
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeFalse -Because 'an undiscriminating Disposition filter is not proof of revocation'
        @($result).Count | Should -Be 1 -Because 'diagnostics must not join the return value'
    }

    It 'still reports TRUE for an ordinarily revoked certificate' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        function certutil {
            $global:LASTEXITCODE = 0
            # Round 7.4: shape-agnostic restrict scan (see the stub above).
            $restrict = $args | Where-Object { $_ -like 'SerialNumber=*' }
            if ("$restrict" -like '*Disposition=20*') { return @('no rows') }
            if ("$restrict" -like '*RevokedReason=8*') { return @('no rows') }
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeTrue -Because 'a plain disposition-21 row with no reason 8 IS revoked'
    }
}

# 2026-08-16 round 7.2. The 2026-08-18 wave-3 round fixed exactly this defect in
# Test-SerialRevokedAtCa: a PowerShell function returns EVERYTHING written to
# the success stream, so Write-Output diagnostics become part of the return
# value. Get-SerialFromReqId, 130 lines further down the SAME file, still did
# it -- so `$targetSerial` was a 5-element array of banner lines with the serial
# last, and the next statement pasted the whole thing into
# `-restrict SerialNumber=<banner...>`. -ReqID could not revoke anything: it
# died at exit 4 or on a certutil parse error. It fails SAFE, but it takes out
# the manual containment path an operator reaches for during an incident.
# Sync-Revocations.ps1 always passes -Serial, which is why no live re-proof has
# ever exercised this branch.
Describe 'Get-SerialFromReqId returns a serial, not a transcript' {
    BeforeAll {
        $scriptPath = "$PSScriptRoot/../../scripts/Revoke-Cert.ps1"
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath, [ref]$null, [ref]$null)
        $fn = $ast.Find({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Get-SerialFromReqId'
        }, $true)
        if (-not $fn) { throw 'Get-SerialFromReqId is missing from Revoke-Cert.ps1' }
        . ([scriptblock]::Create($fn.Extent.Text))

        # Stand in for the real certutil call with a faithful -view transcript.
        function script:Invoke-CertUtil {
            param([string[]]$CertUtilArgs)
            return @(
                'Row 1:',
                '  Serial Number: "6c000000c053029c6a2f5fa7a7000000000012"',
                'CertUtil: -view command completed successfully.'
            )
        }
        function script:Die { param([string]$Message, [int]$Code) throw $Message }
    }

    It 'returns a bare string, not an array' {
        $serial = Get-SerialFromReqId 'CA01\lab-ca' '77'
        # The bug produced System.Object[] with the banner lines in front.
        $serial | Should -BeOfType [string]
        $serial | Should -Be '6C000000C053029C6A2F5FA7A7000000000012'
    }

    It 'the value is usable as a certutil -restrict argument' {
        $serial = Get-SerialFromReqId 'CA01\lab-ca' '77'
        $restrict = "SerialNumber=$serial"
        $restrict | Should -Be 'SerialNumber=6C000000C053029C6A2F5FA7A7000000000012'
        $restrict | Should -Not -Match 'Looking up'
        $restrict | Should -Not -Match 'CertUtil:'
    }

    It 'the shipped function writes its diagnostics to stderr, not the success stream' {
        $src = Get-Content -Raw "$PSScriptRoot/../../scripts/Revoke-Cert.ps1"
        $start = $src.IndexOf('function Get-SerialFromReqId')
        $body = $src.Substring($start, [Math]::Min(1800, $src.Length - $start))
        $body | Should -Not -Match 'Write-Output'
        $body | Should -Match '\[Console\]::Error\.WriteLine'
    }
}

# Round 7.4: the R2-11 @() wrapping at the Get-OfficerRights.ps1 call site
# turned a $null parse into a one-element array CONTAINING $null (@($null).Count
# is 1), so a corrupt or DACL-less OfficerRights value printed "Found 1
# OfficerRights ACE(s)" and exited 0 -- the verify-by-readback tool affirming a
# restriction that is not in force. The function now returns @() on its early
# exits (the OfficerRightsLib convention), which the call-site wrapper counts
# as zero. Extracted by AST so the assertion runs against the shipped text.
Describe 'Parse-OfficerRightsSD empty-return semantics (round 7.4)' {
    BeforeAll {
        $script:src = Join-Path $PSScriptRoot '../../scripts/Get-OfficerRights.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path $script:src).Path, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Parse-OfficerRightsSD' }, $true) | Select-Object -First 1
        if ($null -eq $fn) { throw 'Parse-OfficerRightsSD not found in Get-OfficerRights.ps1' }
        Invoke-Expression $fn.Extent.Text
    }

    It 'a truncated (<20 byte) value unwraps to ZERO ACEs at the call-site idiom' {
        # Mutation: revert the early return to `return $null` -- @($null).Count
        # is 1, so the no-ACEs guard at the call site is skipped.
        $short = [byte[]](1, 0, 0, 0)
        @(Parse-OfficerRightsSD $short).Count | Should -Be 0
    }

    It 'a descriptor with no DACL unwraps to ZERO ACEs at the call-site idiom' {
        # 20+ bytes with a zero Dacl offset: present but unrestricted/unusable.
        $bytes = [byte[]]::new(40)
        $bytes[0] = 1
        @(Parse-OfficerRightsSD $bytes).Count | Should -Be 0
    }

    It 'the shipped function text never returns bare $null' {
        # Belt and braces: the AST text itself must not contain `return $null`,
        # so the defect cannot re-enter through either early exit.
        $fn.Extent.Text | Should -Not -Match 'return\s+\$null'
    }

    It 'a descriptor whose declared ACEs extend past the buffer THROWS (follow-up round 6)' {
        # The loop used to `break` on truncation and return a PARTIAL list, so
        # a value declaring 2 ACEs with room for 1 printed "Found 1 OfficerRights
        # ACE(s)" and exited 0 -- the verify-by-readback tool affirming a
        # restriction it stopped reading half-way. A well-formed descriptor
        # always walks its declared ACEs exactly; anything else is corruption
        # and must be loud.
        # Mutation: revert the throw to `break` -- @(parse).Count is then 0
        # instead of a terminating error.
        # 26 bytes: a 20-byte header whose DACL offset is 20, an 8-byte ACL
        # header at 20..27 -- no, 20+8=28 > 26 is the point: AceCount declares 1
        # but even the first ACE header cannot fit.
        $bytes = [byte[]]::new(26)
        $bytes[0] = 1                                             # revision
        [BitConverter]::GetBytes([uint16]0x8004).CopyTo($bytes, 2)   # control
        [BitConverter]::GetBytes([uint32]20).CopyTo($bytes, 4)       # owner offset
        [BitConverter]::GetBytes([uint32]20).CopyTo($bytes, 16)      # Dacl offset
        $bytes[20] = 2                                            # ACL revision
        [BitConverter]::GetBytes([uint16]8).CopyTo($bytes, 22)       # AclSize
        [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 24)       # AceCount = 1
        { Parse-OfficerRightsSD $bytes } | Should -Throw '*extends past the*'
    }
}

# 2026-08-17 live re-proof. The whole CA-side revocation loop was inert on the
# lab host: every certutil call reached the process WITHOUT its `-config`, so a
# non-CA host answered "No local Certification Authority; use -config option"
# and Sync-Revocations exited 2 with nothing revoked.
#
# Cause: `Invoke-CertUtil` splatted its array into `Invoke-CertUtilCapture`.
# Splatting an array into a NATIVE command (the original `& certutil @args`) is
# correct and gives one argument per element; splatting it into a POWERSHELL
# FUNCTION binds only the first element to the first positional parameter and
# drops the rest into $args, which a non-advanced function accepts in silence.
# Seven arguments in, one argument out, no error anywhere.
#
# CI could not see this: the Windows job runs pytest, and the Pester suite
# stubbed certutil in ways that never asserted WHICH arguments arrived. So the
# assertion here is exactly that -- the argv the process would receive.
Describe 'Invoke-CertUtil argument passing (extracted from Revoke-Cert.ps1)' {
    BeforeAll {
        $script:src = Join-Path $PSScriptRoot '../../scripts/Revoke-Cert.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path $script:src).Path, [ref]$null, [ref]$null)
        foreach ($name in @('Invoke-CertUtilCapture', 'Invoke-CertUtil')) {
            $fn = $ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $n.Name -eq $name }, $true) | Select-Object -First 1
            if ($null -eq $fn) { throw "$name not found in Revoke-Cert.ps1" }
            Invoke-Expression $fn.Extent.Text
        }
        # Stand in for certutil and record the argv it was handed.
        function certutil {
            $global:LASTEXITCODE = 0
            $global:CapturedArgs = @($args)
            return @('ok')
        }
        $script:CertUtilExe = 'certutil'
    }

    It 'delivers EVERY argument to certutil, -config included' {
        $global:CapturedArgs = @()
        $expected = @('-view', '-config', 'CA01\lab-ca', '-restrict',
                      'SerialNumber=6C000000C0', '-out', 'SerialNumber')
        Invoke-CertUtil $expected | Out-Null

        # The bug delivered exactly one argument ('-view'). Assert the whole
        # argv, not just the count: a helper that passed the arguments in the
        # wrong ORDER would also break certutil while keeping the count right.
        @($global:CapturedArgs) | Should -Be $expected
    }

    It 'delivers -config on the revoke call itself, not only on the -view calls' {
        # Line 432's `-revoke` went through the same helper, so the failure was
        # not confined to the read-only confirmation steps.
        $global:CapturedArgs = @()
        Invoke-CertUtil @('-config', 'CA01\lab-ca', '-revoke', '6C000000C0', '1') | Out-Null
        @($global:CapturedArgs)[0] | Should -Be '-config'
        @($global:CapturedArgs).Count | Should -Be 5
    }

    It 'refuses a splatted array loudly instead of dropping arguments' {
        # The regression shape itself: with [CmdletBinding()] the surplus
        # positional arguments are a binding ERROR, not silent $args overflow.
        $splatted = @('-view', '-config', 'CA01\lab-ca')
        { Invoke-CertUtilCapture @splatted } | Should -Throw
    }
}
