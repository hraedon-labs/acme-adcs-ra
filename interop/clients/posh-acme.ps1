# Posh-ACME scenario (PowerShell 7, mcr.microsoft.com/powershell).
# ENDPOINTS: directory new-nonce-head new-acct acct-post new-order order-post-as-get authz challenge finalize cert revoke-cert key-change
$ErrorActionPreference = 'Stop'
$client = 'posh-acme'
# Step <name> ok <body>              PASS when the body does not throw
# Step <name> fail <body> <regex>    PASS when it throws AND the message matches
function Step([string]$Name, [string]$Expect, [scriptblock]$Body, [string]$Pattern = '.') {
    Write-Host "=== STEP $Name (expect $Expect)"
    $ok = $true; $msg = ''
    try { & $Body | Out-Host } catch { $ok = $false; $msg = $_.Exception.Message; Write-Host "ERROR: $msg" }
    if (($Expect -eq 'ok' -and $ok) -or ($Expect -eq 'fail' -and -not $ok -and $msg -match $Pattern)) {
        Write-Host "RESULT $client $Name PASS"
    } else {
        Write-Host "RESULT $client $Name FAIL"
    }
}

$env:POSHACME_HOME = '/w/posh-acme'
New-Item -ItemType Directory -Force -Path $env:POSHACME_HOME, '/w/webroot' | Out-Null
Install-Module Posh-ACME -RequiredVersion $env:POSH_ACME_VERSION -Force -Scope CurrentUser
Import-Module Posh-ACME
Write-Host "Posh-ACME $((Get-Module Posh-ACME).Version)"
$D = 'poshacme.interop.test'
$plugin = @{ Plugin = 'WebRoot'; PluginArgs = @{ WRPath = '/w/webroot' } }

Step 'new-account' ok {
    Set-PAServer -DirectoryUrl $env:DIRECTORY_URL -SkipCertificateCheck
    New-PAAccount -AcceptTOS -Contact 'ops@interop.test' -KeyLength 'ec-256' `
        -ExtAcctKID $env:EAB_KID -ExtAcctHMACKey $env:EAB_HMAC -ExtAcctAlgorithm HS256 -Force
}
Step 'issue' ok { New-PACertificate $D @plugin -Force }
Step 'update-account-contact' ok { Set-PAAccount -Contact 'ops2@interop.test' }
Step 'key-change' ok { Set-PAAccount -KeyRollover -KeyLength 'ec-256' }
Step 'issue-after-key-change' ok { New-PACertificate 'poshacme2.interop.test' @plugin -Force }
Step 'revoke' ok { Revoke-PACertificate -MainDomain $D -Reason keyCompromise -Force }
Step 'deactivate-account' ok { Set-PAAccount -Deactivate -Force }
# After deactivation Posh-ACME refuses locally (it would try to register a new
# account), so a further order never reaches the RA; certbot and acme.sh cover
# the server-side refusal. What Posh-ACME can show is the status the RA returned.
Step 'deactivated-status-reported' ok {
    $st = (Get-PAAccount).status
    if ($st -ne 'deactivated') { throw "account status is '$st', expected 'deactivated'" }
} 
