<#
.SYNOPSIS
  READ-ONLY evidence from one NPS (RADIUS) server for an 802.1X Wi-Fi problem. Run it on EVERY NPS server.

.DESCRIPTION
  Prints, without changing anything and without ever reading RADIUS shared secrets:
    - NPS service state, NPS audit policy (must be Success and Failure, or failures are invisible)
    - Message-Authenticator hardening state (limitproxystate / requiremsgauth, KB5040268)
    - events 6272 (granted) / 6273 (denied) / 6274 (discarded) with user, client MAC, SSID, policy, EAP type and
      the reason code + reason text, plus a per-user summary
    - network policies, and for each one whether a PEAP certificate is actually SAVED (the PEAP "Edit" dialog
      pre-selects a certificate even when none is saved — this checks ias.xml) and which certificate it uses
    - server-authentication certificates with expiry and chain status
    - optional: AD group membership and userAccountControl flags for given accounts

.EXAMPLE
  .\Get-NpsEvidence.ps1 -Hours 6 -Users alice,bob > nps-$env:COMPUTERNAME.txt
#>
param(
    [int] $Hours = 24,
    [string[]] $Users = @()
)
$ErrorActionPreference = 'Continue'
function Write-Section($t) { "`n=== $t" }

Write-Section 'SERVER'
"$env:COMPUTERNAME  now: $((Get-Date).ToString('s'))  UTC offset: $([TimeZoneInfo]::Local.GetUtcOffset((Get-Date)))  NPS service: $((Get-Service IAS -ErrorAction SilentlyContinue).Status)"
auditpol /get /subcategory:"Network Policy Server" | Select-String 'Network Policy Server' | ForEach-Object { "audit: $($_.Line.Trim())" }
netsh nps show limitproxystate | Select-String '=' | ForEach-Object { $_.Line.Trim() }
netsh nps show requiremsgauth | Select-String '=' | ForEach-Object { $_.Line.Trim() }

Write-Section "NPS EVENTS last $Hours h"
$names = 'SubjectUserName', 'CallingStationID', 'CalledStationID', 'NASIPv4Address', 'ClientName', 'NetworkPolicyName',
         'AuthenticationType', 'EAPType', 'ReasonCode', 'Reason'
$rows = @()
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 6272, 6273, 6274, 6276; StartTime = (Get-Date).AddHours(-$Hours) } -MaxEvents 2000 -ErrorAction Stop |
        Sort-Object TimeCreated | ForEach-Object {
            $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            $rows += [pscustomobject]@{ Id = $_.Id; User = $d.SubjectUserName; Reason = "$($d.ReasonCode) $($d.Reason)" }
            "$($_.TimeCreated.ToString('s')) id=$($_.Id) " + (($names | Where-Object { $d[$_] -and $d[$_] -ne '-' } | ForEach-Object { "$_=$($d[$_])" }) -join '; ')
        }
} catch { "no NPS events in window — is auditing on? ($($_.Exception.Message.Split([char]10)[0]))" }
Write-Section 'PER-USER SUMMARY'
$rows | Group-Object User | ForEach-Object {
    $ok = @($_.Group | Where-Object Id -eq 6272).Count
    $bad = @($_.Group | Where-Object Id -ne 6272)
    "$($_.Name): granted $ok, denied/discarded $($bad.Count)" + $(if ($bad) { "; reasons: " + (($bad | Group-Object Reason | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join ' | ') })
}

Write-Section 'NETWORK POLICIES and saved PEAP certificate'
$np = netsh nps show np
$np | Select-String -Pattern '^Name\s+=|^State\s+=|^Processing order|NP-Allowed-EAP-Type' | ForEach-Object { $_.Line.Trim() }
$peapPolicies = @{}; $current = $null
foreach ($l in $np) {
    if ($l -match '^Name\s+=\s+(.+)$') { $current = $Matches[1].Trim() }
    elseif ($current -and $l -match 'NP-Allowed-EAP-Type\s+0x100a\s+(.+)$' -and $Matches[1] -match '"19') { $peapPolicies[$current] = $true }   # 0x19 = 25 = PEAP
}
$x = [xml](Get-Content "$env:windir\System32\ias\ias.xml" -Raw)
$saved = @{}
foreach ($e in $x.SelectNodes('//*[local-name()="msEAPConfiguration"]')) {
    $policy = $e.ParentNode.ParentNode.GetAttribute('name')
    $thumb = if ($e.InnerText -match '14000000([0-9a-fA-F]{40})') { $Matches[1].ToUpper() } else { '(none found in blob)' }
    $saved[$policy] = $thumb
    "policy '$policy': EAP configuration saved, certificate thumbprint $thumb"
}
foreach ($p in $x.SelectNodes('//*[local-name()="RadiusProfiles"]/*[local-name()="Children"]/*')) {
    $n = $p.GetAttribute('name')
    if ($n -and $peapPolicies[$n] -and -not $saved.ContainsKey($n)) { "policy '$n': NO EAP configuration saved (if it allows PEAP, open PEAP > Edit > OK, then OK on the policy)" }
}

Write-Section 'SERVER-AUTHENTICATION CERTIFICATES (LocalMachine\My)'
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' } | ForEach-Object {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $ok = $chain.Build($_)
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $status = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join ','
    "subject=$($_.Subject) notAfter=$($_.NotAfter.ToString('s')) thumb=$($_.Thumbprint) privateKey=$($_.HasPrivateKey) chainOK=$ok $status root=$($root.Subject) rootThumb=$($root.Thumbprint)"
}
"note: a chain status of OfflineRevocation/RevocationStatusUnknown from a remote (SSH/WinRM) session can be a false alarm for LDAP-only CRLs — re-check in an elevated local session."

if ($Users) {
    Write-Section 'ACCOUNTS (AD read via ADSI)'
    foreach ($u in $Users) {
        try {
            $r = ([adsisearcher]"(|(sAMAccountName=$u)(userPrincipalName=$u))").FindOne()
            if (-not $r) { "$u : not found"; continue }
            $uac = [int]$r.Properties.useraccountcontrol[0]
            $flags = @(); if ($uac -band 0x2) { $flags += 'DISABLED' }; if ($uac -band 0x40000) { $flags += 'SMARTCARD_REQUIRED (no usable password: PEAP-MSCHAPv2 cannot work)' }
            "$u : upn=$($r.Properties.userprincipalname) uac=$uac $($flags -join ' ') dialin=$($r.Properties.msnpallowdialin) memberOf=" +
                (($r.Properties.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ',')
        } catch { "$u : AD not readable from this session" }
    }
}
