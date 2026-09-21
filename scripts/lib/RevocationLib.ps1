# Dot-sourceable library: revocation reason validation and requester comparison.
# Extracted from Revoke-Cert.ps1 for testability. Used by the Pester tests
# (tests/pester/Revocation.Tests.ps1). The production script keeps its logic
# inline (it is simple enough); this lib validates the same logic independently.

# RFC 5280 section 5.3.1 reason codes. certutil -revoke uses the same numeric
# codes. Two are excluded:
#
#   7 -- "unused" in RFC 5280 (not an RFC 8555 reason); certutil rejects it.
#   8 -- removeFromCRL, the UN-revoke operation. Confirmed against the lab CA
#        during the Plan 004 spike: a certificate placed on hold and then
#        given reason 8 ends up "off the CRL and valid" while ADCS keeps its
#        DB Disposition at 21. A revocation tool must never emit it.
#
# Reason 6 (certificateHold) stays valid: a hold is strictly more restrictive
# than valid, so it cannot be used to undo containment.
function Get-ValidRevocationReasons {
    return @(0, 1, 2, 3, 4, 5, 6, 9, 10)
}

function Test-RevocationReason([int]$Reason) {
    return $Reason -in (Get-ValidRevocationReasons)
}

function Compare-RequesterName([string]$Actual, [string]$Expected) {
    if ([string]::IsNullOrEmpty($Actual)) { return $false }
    return $Actual.Equals($Expected, [System.StringComparison]::OrdinalIgnoreCase)
}

# Convert a serial to the form the ADCS CA database stores, so a
# `-restrict "SerialNumber=..."` clause matches exactly.
#
# The RA emits serials via Python's format(n, 'x'), which never produces a
# leading zero. ADCS stores the full byte string, so a certificate whose
# high-order byte is 0x0N is recorded with a leading zero the RA's form lacks
# (e.g. RA "6AB1..." vs CA "06AB1..."). The restrict clause is an exact string
# match, so the lookup would find 0 rows and Revoke-Cert.ps1 would exit 4 --
# fail-safe (nothing wrongly revoked) but it silently stops the automated
# revocation loop for that certificate until someone investigates.
#
# A hex serial derived from bytes always has an even number of digits, so
# re-padding an odd-length value to even reconstructs the CA's form exactly.
# Verified against the lab CA 2026-08-11: 61 issued serials, lengths 32 and 38,
# none currently leading-zero -- this is a latent case, not an observed one.
function Get-CaSerialForm([string]$Serial) {
    if ([string]::IsNullOrWhiteSpace($Serial)) { return $Serial }
    $s = $Serial.Trim()
    if ($s.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
        $s = $s.Substring(2)
    }
    if ($s.Length % 2 -eq 1) { $s = "0" + $s }
    return $s
}

# Longest serial this tooling will pass to certutil, in hex digits. RFC 5280
# caps a serial at 20 octets (40 digits); 64 leaves generous headroom for a
# non-conforming CA while still bounding the argument. The lab CA's 61 issued
# serials measured 32 and 38 digits (see Get-CaSerialForm above).
$script:MaxSerialHexDigits = 64

# Is this a plain hex serial in one of the spellings the revocation tooling
# accepts?
#
# The check exists because $Serial reaches `certutil` as an ARGUMENT, and
# certutil's own grammar gives some characters meaning:
#
#   * `certutil -revoke` documents its argument as a COMMA-SEPARATED LIST of
#     serials, so `<real>,<other>` revokes two certificates. No shell, no
#     quoting trick, no PowerShell native-argument-passing bug is needed --
#     it is simply another argument.
#   * `-restrict "SerialNumber=$s"` is a query clause, and a comma starts a
#     second clause there too.
#
# Nothing reachable emits such a value today: the RA only ever serves
# canonical_serial() of a parsed certificate, which is hex by construction.
# The reason to check anyway is where the value COMES FROM. Sync-Revocations
# takes it from the RA's JSON over the network and hands it to a certutil
# invocation running with CA-officer rights -- and this project's whole
# out-of-band revocation design exists so that compromising the RA does NOT
# confer those rights (threat-model section 4.A; the enrollment gMSA holds no
# Manage-CA). Validating here keeps that boundary a property of the privileged
# script rather than a property of the RA staying honest.
#
# Deliberately NOT stricter than Get-CaSerialForm is lenient. An over-strict
# pattern refuses a LEGITIMATE revocation, which is a containment failure --
# the worse direction of the two. Every spelling the normalizer already
# accepts (lowercase, `0x`-prefixed, odd-length, surrounded by whitespace) is
# accepted here.
function Test-CaSerialForm([string]$Serial) {
    if ([string]::IsNullOrWhiteSpace($Serial)) { return $false }
    $s = $Serial.Trim()
    if ($s.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
        $s = $s.Substring(2)
    }
    if ($s.Length -lt 1 -or $s.Length -gt $script:MaxSerialHexDigits) { return $false }
    # -cmatch, not -match: the case-insensitive form is the default and the
    # character class already covers both cases, but pinning it makes the
    # intent explicit and immune to a caller changing $PSDefaultParameterValues.
    # Anchors are ^...$ and PowerShell's $ tolerates a trailing newline, so the
    # \A...\z form is used instead -- a serial with an embedded newline would
    # otherwise pass and reach the argument.
    return $s -cmatch '\A[0-9A-Fa-f]+\z'
}

# The operator-facing completion text for a single revocation.
#
# 2026-08-16 rescan F2: this used to be an unconditional trailer on
# Revoke-Cert.ps1 ending "...and the CRL is published." That is false on the
# DEFAULT path. Sync-Revocations.ps1 passes -SkipPublishCrl because the
# least-privilege revocation officer cannot republish a CRL (that needs
# Manage-CA), and the batch relays this script's output verbatim -- so the
# containment record showed "Skipping CRL publication" and "the CRL is
# published" for the same certificate, minutes apart. An operator who closes
# containment on the second line leaves relying parties accepting a revoked
# certificate until the next scheduled publication.
#
# Returned as an array of lines so the Pester tests can assert the two branches
# never share a claim.
function Get-RevocationCompletionMessage {
    param(
        [Parameter(Mandatory = $true)][string]$Serial,
        [switch]$SkipPublishCrl
    )
    if ($SkipPublishCrl) {
        return @(
            ("Out-of-band revocation PARTIALLY complete: serial {0} is revoked in the CA" -f $Serial),
            "database, but the CRL was NOT republished, so no published CRL lists it yet.",
            "Relying parties will keep accepting this certificate until the next scheduled",
            "CRL publication. Do NOT close containment on this step alone -- either wait for",
            "that publication and verify the serial appears, or re-run with -PublishCrl as an",
            "identity holding Manage-CA."
        )
    }
    return @(
        ("Out-of-band revocation complete: serial {0} is revoked in the CA database" -f $Serial),
        "and the CRL has been republished. Update the incident record to note that the",
        "out-of-band step is done and the CRL is published."
    )
}
