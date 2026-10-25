<#
.SYNOPSIS
  READ-ONLY evidence for a WPA2/WPA3-Enterprise (802.1X) Wi-Fi sign-in problem on a Windows client.

.DESCRIPTION
  Prints, without changing anything:
    - who is signed in (whoami, UPN), OS build/edition, domain / Entra join state
    - which credential provider was used to sign in (password, Windows Hello, smart card ...)
    - Credential Guard / VBS state
    - the SSID's Wi-Fi profile: netsh summary + the EAP XML (authMode, TrustedRootCA, ServerNames,
      UseWinLogonCredentials). Enterprise profiles hold no keys; key=clear is never used.
    - whether the profile comes from Group Policy or MDM
    - WLAN-AutoConfig events for the SSID as structured fields: the identity sent, reason codes, EAP root cause
  Compare the "Identity=" values here with the user names in the NPS 6272/6273 events (Get-NpsEvidence.ps1)
  at the same time and MAC address (LocalMac here = Calling-Station-Id on NPS).

.EXAMPLE
  .\Get-WifiClientEvidence.ps1 -Ssid "Corp-Secure" -Hours 24 > client.txt
#>
param(
    [Parameter(Mandatory)] [string] $Ssid,
    [string] $Interface = 'Wi-Fi',
    [int] $Hours = 72
)
$ErrorActionPreference = 'Continue'
function Write-Section($t) { "`n=== $t" }

Write-Section 'IDENTITY'
"computer: $env:COMPUTERNAME   whoami: $(whoami)   upn: $(whoami /upn 2>&1)"
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"os: $($os.Caption) $($cv.DisplayVersion) build $($os.BuildNumber).$($cv.UBR) edition $($cv.EditionID)"
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|DomainName|NgcSet' | ForEach-Object { $_.Line.Trim() }

Write-Section 'SIGN-IN METHOD (last credential provider on the logon screen)'
$providers = @{
    '{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}' = 'Password'
    '{D6886603-9D2F-4EB2-B667-1971041FA96B}' = 'Windows Hello PIN'
    '{8AF662BF-65A0-4D0A-A540-A338A999D36F}' = 'Windows Hello face'
    '{BEC09223-B018-416D-A0AC-523971B639F5}' = 'Windows Hello fingerprint'
    '{8FD7E19C-3BF7-489B-A72C-846AB3678C96}' = 'Smart card'
    '{F8A1793B-7873-4046-B2A7-1F318747F427}' = 'FIDO2 security key'
}
$last = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction SilentlyContinue).LastLoggedOnProvider
"last provider: $last = $(if ($providers[$last]) { $providers[$last] } else { 'unknown/other' })"

Write-Section 'CREDENTIAL GUARD / VBS'
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    "VBS status: $($dg.VirtualizationBasedSecurityStatus) (2 = running); services running: $($dg.SecurityServicesRunning -join ',') (1 = Credential Guard)"
} catch { "DeviceGuard WMI not available" }

Write-Section 'WLAN PROFILES'
netsh wlan show profiles interface="$Interface"
Write-Section "PROFILE '$Ssid'"
netsh wlan show profile name="$Ssid" interface="$Interface"
Write-Section "PROFILE '$Ssid' EAP XML (temp export, printed, deleted)"
$tmp = Join-Path $env:TEMP ("wlanx-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
netsh wlan export profile name="$Ssid" interface="$Interface" folder="$tmp" | Out-Null
Get-ChildItem $tmp -Filter *.xml | ForEach-Object { (Get-Content $_.FullName -Raw) -replace '<keyMaterial>.*?</keyMaterial>', '<keyMaterial>REDACTED</keyMaterial>' }
Remove-Item $tmp -Recurse -Force
"Group Policy wireless policy present: $(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy')"
"MDM Wi-Fi profiles: $(@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Wifi' -ErrorAction SilentlyContinue).Count)"

Write-Section "WLAN-AutoConfig events for '$Ssid', last $Hours h (8001 ok, 8002 fail, 12011-12014 802.1X)"
$since = (Get-Date).AddHours(-$Hours)
$keep = 'ConnectionMode', 'AuthenticationAlgorithm', 'CipherAlgorithm', 'FailureReason', 'ReasonCode', 'Identity', 'User',
        'ErrorCode', 'EAPReasonCode', 'EAPRootCauseString', 'PeerMac', 'LocalMac'
$events = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' -MaxEvents 3000 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $since -and $_.Id -in 8001, 8002, 8003, 12011, 12012, 12013, 12014 }
foreach ($e in ($events | Sort-Object TimeCreated)) {
    $data = ([xml]$e.ToXml()).Event.EventData.Data
    $ssidField = ($data | Where-Object Name -eq 'SSID').'#text'
    if ($ssidField -and $ssidField -ne $Ssid) { continue }
    $fields = ($data | Where-Object { $_.Name -in $keep -and $_.'#text' } | ForEach-Object { "$($_.Name)=$($_.'#text')" }) -join '; '
    "$($e.TimeCreated.ToString('s')) id=$($e.Id) $fields"
}
