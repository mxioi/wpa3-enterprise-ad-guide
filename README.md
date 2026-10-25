# WPA3-Enterprise with Active Directory and UniFi

Complete guide for implementing WPA3-Enterprise Wi-Fi authentication using Microsoft NPS (RADIUS) with Active Directory on UniFi networks.

## Architecture Overview

```
[Client Device]
    ↓ WPA3-Enterprise (802.1X/PEAP-MSCHAPv2)
[UniFi Access Point]
    ↓ 802.1X EAP
[UniFi Dream Machine Pro Max]
    ↓ RADIUS (UDP 1812/1813)
[NPS Server on Domain Controller]
    ↓ LDAP Query
[Active Directory]
    → Group membership validation
    → User authentication
    ← Access-Accept/Reject
```

## Prerequisites

- Windows Server 2022/2025 Domain Controller
- Active Directory Domain Services configured
- Enterprise CA (AD CS) installed and operational
- UniFi Dream Machine (Pro/Pro Max) or similar
- UniFi Access Points with WPA3 support
- Domain functional level: Windows Server 2016 or higher

## Part 1: NPS Server Configuration

### 1.1 Install NPS Role

```powershell
# Install Network Policy Server role
Install-WindowsFeature -Name NPAS -IncludeManagementTools
```

### 1.2 Register NPS in Active Directory

```powershell
# This adds the computer account to the RAS and IAS Servers security group
netsh nps add registeredserver
```

Verify registration:
```powershell
# The computer should be a member of this group
Get-ADGroupMember -Identity "RAS and IAS Servers"
```

## Part 2: Certificate Configuration

### 2.1 Enable RAS and IAS Server Certificate Template

```powershell
# On the CA server, enable the RAS and IAS template
certutil -SetCATemplates +RASAndIASServer

# Restart Certificate Services
Restart-Service -Name CertSvc
```

### 2.2 Request Server Authentication Certificate

```powershell
# Request certificate for NPS server
Get-Certificate -Template RASAndIASServer -CertStoreLocation Cert:\LocalMachine\My

# Verify certificate was issued
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
} | Select-Object Subject, Thumbprint, NotAfter, @{Name="EKU";Expression={$_.EnhancedKeyUsageList.FriendlyName -join ", "}}
```

**Important:** Note the certificate thumbprint - you'll need this for the Network Policy.

### 2.3 Export Root CA Certificate (for Clients)

```powershell
# Find the Root CA certificate
$rootCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*CA*" -and $_.Issuer -eq $_.Subject
} | Select-Object -First 1

# Export it
Export-Certificate -Cert $rootCert -FilePath C:\RootCA.cer -Type CERT
```

Distribute `RootCA.cer` to all client devices.

## Part 3: Active Directory Security Group

### 3.1 Create Wi-Fi Users Group

```powershell
# Create security group for authorized Wi-Fi users
New-ADGroup -Name "WiFi-Users" `
    -SamAccountName "WiFi-Users" `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "Wi-Fi Authorized Users" `
    -Path "CN=Users,DC=yourdomain,DC=local" `
    -Description "Users authorized for WPA3-Enterprise Wi-Fi"
```

### 3.2 Add Users to Group

```powershell
# Add users to the WiFi-Users group
Add-ADGroupMember -Identity "WiFi-Users" -Members "username1", "username2"

# Verify membership
Get-ADGroupMember -Identity "WiFi-Users"
```

## Part 4: RADIUS Client Configuration

### 4.1 Generate Strong Shared Secret

```powershell
# Generate a strong random shared secret (save this securely!)
$secret = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,61) |
    Get-Random -Count 32 | ForEach-Object {[char]$_})

Write-Output "RADIUS Shared Secret: $secret"
$secret | Out-File -FilePath C:\radius_secret.txt -Encoding ASCII
```

**Important:** Save this secret securely - you'll need it for UniFi configuration.

### 4.2 Add RADIUS Clients in NPS

```powershell
# Add UniFi gateway as RADIUS client
# Replace IP_ADDRESS with your UniFi gateway IP
# Replace SHARED_SECRET with the generated secret

netsh nps add client name="UniFi-Gateway" `
    address="IP_ADDRESS" `
    state="enable" `
    sharedsecret="SHARED_SECRET" `
    vendor="other"

# Verify RADIUS client was added
Get-NpsRadiusClient | Select-Object Name, Address, Enabled
```

**Note:** You may need to add multiple RADIUS clients:
- UniFi Gateway/Controller IP
- Individual Access Point IPs (if they send RADIUS requests directly)

## Part 5: NPS Network Policy Configuration

### 5.1 Create Network Policy (GUI Method)

**This MUST be done through the NPS GUI due to PowerShell limitations.**

1. Open **Server Manager** → **Tools** → **Network Policy Server**

2. Expand **Policies** → Right-click **Network Policies** → **New**

3. **Configure Policy Settings:**

   **Page 1: Policy Name**
   - Policy name: `WPA3-Enterprise-WiFi`
   - Network access server type: `Unspecified`
   - Click **Next**

   **Page 2: Conditions**
   - Click **Add** → Select **Windows Groups**
     - Click **Add Groups** → Enter `WiFi-Users` → Click **Check Names** → **OK**
   - Click **Add** again → Select **NAS Port Type**
     - Check: **Wireless - IEEE 802.11**
     - Click **OK**
   - Click **Next**

   **Page 3: Permissions**
   - Select: **Access granted**
   - Click **Next**

   **Page 4: Authentication Methods (CRITICAL)**
   - **UNCHECK ALL** existing authentication methods
   - **CHECK ONLY:** `Microsoft: Protected EAP (PEAP)`
   - Click **Edit** next to PEAP:
     - **Certificate:** Select your server certificate (Subject: yourservername.domain.local)
     - **EAP Types:** Ensure `Secured password (EAP-MSCHAP v2)` is enabled
     - **Check:** `Enable Fast Reconnect`
     - Click **OK**
   - Click **Next**

   **Page 5: Constraints**
   - Leave at defaults
   - Click **Next**

   **Page 6: Settings**
   - (Optional) Add RADIUS attribute: `Framed-Protocol = PPP`
   - Click **Next**

   **Page 7: Complete**
   - Click **Finish**

4. **Verify Policy:**
   - Policy should show as **Enabled**
   - **Processing Order** should be **1**

5. **Restart NPS Service:**
   ```powershell
   Restart-Service -Name IAS
   ```

### 5.2 Verify NPS Configuration

```powershell
# Check NPS service is running
Get-Service -Name IAS

# Export configuration as backup (contains secrets - secure this file!)
netsh nps export filename="C:\nps_backup.xml" exportPSK=YES

# Verify Network Policy exists (check for policy name in output)
netsh nps show config
```

## Part 5.3: Connection Request Policy (CRITICAL - MOST COMMON FAILURE POINT)

**⚠️ WARNING:** This is the #1 cause of "Unable to connect" errors. If you skip this, authentication will fail with no clear error message.

### What is a Connection Request Policy (CRP)?

NPS requires **TWO types of policies**:
1. **Connection Request Policy (CRP)** - Tells NPS HOW to process requests (locally vs proxy)
2. **Network Policy** - Defines WHO can authenticate and authorization rules

**Without a CRP, all RADIUS requests are silently rejected before reaching the Network Policy.**

### 5.3.1 Create Connection Request Policy (GUI Method)

1. Open **Network Policy Server** console
2. Expand **Policies** → Right-click **Connection Request Policies** → **New**

3. **Configure Policy:**

   **Page 1: Policy Name**
   - Policy name: `Use Windows authentication for all users`
   - Click **Next**

   **Page 2: Conditions**
   - Click **Add** → Select **Day and time restrictions**
   - Click **Add** → Select all days, all hours (24/7)
   - Click **OK**
   - Click **Next**

   **Page 3: Settings (CRITICAL)**
   - Authentication Provider: **Windows Authentication**
   - Click **Next**

   **Page 4: Complete**
   - Click **Finish**

4. **Verify:**
   - Policy should show as **Enabled**
   - Processing order should be **1**

5. **Restart NPS:**
   ```powershell
   Restart-Service -Name IAS
   ```

### 5.3.2 Alternative: Create CRP via Command Line

```powershell
# Create Connection Request Policy for local Windows authentication
netsh nps add crp name="Use Windows authentication for all users" `
    state=enable `
    processingorder=1 `
    policysource=0 `
    conditionid=0x1006 `
    conditiondata="0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00" `
    profileid=0x1025 `
    profiledata=0x1

# Verify it was created
netsh nps show crp

# Restart NPS to apply
Restart-Service -Name IAS
```

### 5.3.3 Verify CRP Configuration

```powershell
# Check if CRP exists
netsh nps show crp

# Expected output should show:
# Name: Use Windows authentication for all users
# State: Enabled
# Processing order: 1
```

### 5.3.4 Bind PEAP Certificate to NPS

**CRITICAL:** Even with a certificate installed, NPS won't use it until you explicitly bind it.

```powershell
# Find your server certificate thumbprint
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
} | Select Subject, Thumbprint, NotAfter

# Bind certificate to PEAP (replace THUMBPRINT with actual value)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" `
    -Name ServerConfigured -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" `
    -Name CertificateThumbprint -Value "YOUR_CERTIFICATE_THUMBPRINT_HERE"

# Verify binding
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" |
    Select ServerConfigured, CertificateThumbprint

# Restart NPS
Restart-Service -Name IAS
```

**Expected output:**
```
ServerConfigured      : 1
CertificateThumbprint : ABC123...YOUR_THUMBPRINT
```

## Part 6: UniFi Configuration

### 6.1 Create RADIUS Profile

1. Open **UniFi Network Application**
2. Go to **Settings** → **Profiles** → **RADIUS**
3. Click **"+ Create New RADIUS Profile"**

**Configuration:**
```
Profile Name:              Your-RADIUS-Profile-Name
Authentication Servers:
  IP Address:              [NPS Server IP]
  Port:                    1812
  Shared Secret:           [Your Generated Secret]

Accounting Servers (Optional):
  IP Address:              [NPS Server IP]
  Port:                    1813
  Shared Secret:           [Same Secret]
```

4. Check **Wireless Networks**
5. Click **Apply Changes**

### 6.2 Create WPA3-Enterprise SSID

1. Go to **Settings** → **WiFi**
2. Click **"+ Create New WiFi Network"**

**Configuration:**
```
Name/SSID:               Your-Enterprise-SSID
Security Protocol:       WPA3 Enterprise (or WPA2/WPA3 Enterprise for compatibility)
RADIUS Profile:          [Select your RADIUS profile]
Wi-Fi Band:              2.4 GHz + 5 GHz (or 6 GHz if supported)
Network:                 [Select network/VLAN]
```

3. Click **Add WiFi Network**
4. Wait 30-60 seconds for APs to provision

### 6.3 Verify AP Provisioning

Check that your Access Points have provisioned the new SSID:
- **Settings** → **UniFi Devices** → Select AP
- Verify SSID appears in the Wi-Fi settings
- Ensure AP shows as "Connected" and "Provisioned"

## Part 7: Firewall Configuration

### 7.1 Windows Firewall on NPS Server

```powershell
# Enable NPS firewall rules
Enable-NetFirewallRule -DisplayGroup "Network Policy Server"

# Verify rules are enabled
Get-NetFirewallRule -DisplayGroup "Network Policy Server" |
    Select-Object DisplayName, Enabled, Direction, Action
```

### 7.2 Required Ports

**From UniFi to NPS Server:**
- **UDP 1812** - RADIUS Authentication
- **UDP 1813** - RADIUS Accounting (optional)

**Test connectivity:**
```powershell
# From NPS server, test connectivity to UniFi gateway
Test-NetConnection -ComputerName [UniFi-Gateway-IP] -Port 443
```

## Part 8: Client Configuration

### 8.1 Install Root CA Certificate

**Windows:**
1. Copy `RootCA.cer` to the client
2. Double-click the file
3. Click **Install Certificate**
4. Store Location: **Local Machine** (requires admin)
5. Place in: **Trusted Root Certification Authorities**
6. Click **Finish**

**macOS:**
1. Double-click `RootCA.cer`
2. Add to **System** keychain
3. Open **Keychain Access** → System
4. Find the certificate, double-click it
5. Expand **Trust** → Set to **Always Trust**

**iOS/iPadOS:**
1. AirDrop or email the `.cer` file
2. Settings → Profile Downloaded → **Install**
3. Settings → General → About → **Certificate Trust Settings**
4. Enable full trust for the certificate

**Android:**
1. Settings → Security → **Install from storage**
2. Select the `.cer` file
3. Name it (e.g., "CompanyCA")
4. For use in: **VPN and apps**

### 8.2 Connect to Wi-Fi

1. Select the WPA3-Enterprise SSID
2. Enter credentials:
   - **Username:** `username@domain.local` (or `DOMAIN\username`)
   - **Password:** Active Directory password
3. Trust the server certificate when prompted
   - Server: yourservername.domain.local
   - Issued by: Your CA name
4. Click **Connect/Trust**

## Part 9: Validation & Testing

### 9.1 Monitor Authentication Attempts

```powershell
# Successful authentications (Event ID 6272)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6272} -MaxEvents 10

# Failed authentications (Event ID 6273)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6273} -MaxEvents 10

# All RADIUS events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6272,6273,6274,6278} -MaxEvents 20 |
    Format-List TimeCreated, Id, Message
```

### 9.2 Verify User Group Membership

```powershell
# Check if user is in WiFi-Users group
Get-ADPrincipalGroupMembership -Identity "username" |
    Where-Object {$_.Name -eq "WiFi-Users"}
```

### 9.3 Test RADIUS Connectivity

```powershell
# Check if NPS is listening on RADIUS ports
netstat -ano | findstr ":1812"

# Verify NPS service status
Get-Service -Name IAS | Select-Object Name, Status, StartType
```

## Part 10: Troubleshooting

### 10.0 Systematic Diagnosis Methodology

When troubleshooting "Unable to connect" errors, follow this diagnostic chain:

**Diagnosis Order:**
1. **Client-side:** Is the SSID visible and attempting connection?
2. **NPS-side:** Are RADIUS requests reaching NPS?
3. **Authentication:** Is NPS processing and rejecting/accepting requests?
4. **Authorization:** Is the Network Policy allowing access?

### 10.0.1 Quick Diagnostic Script

Run this on the NPS server to check all critical components:

```powershell
# Quick NPS Health Check
Write-Host "=== NPS Health Check ===" -ForegroundColor Cyan

# 1. Service Status
Write-Host "`n[1/6] NPS Service Status" -ForegroundColor Yellow
Get-Service ias | Select Status, StartType

# 2. UDP Port Listeners
Write-Host "`n[2/6] RADIUS Port Listeners" -ForegroundColor Yellow
Get-NetUDPEndpoint -LocalPort 1812,1813 | Select LocalAddress, LocalPort

# 3. Firewall Rules
Write-Host "`n[3/6] Firewall Rules" -ForegroundColor Yellow
Get-NetFirewallRule -DisplayGroup "Network Policy Server" |
    Where-Object {$_.Direction -eq 'Inbound'} |
    Select DisplayName, Enabled, Action

# 4. Connection Request Policy
Write-Host "`n[4/6] Connection Request Policy" -ForegroundColor Yellow
netsh nps show crp

# 5. PEAP Certificate Binding
Write-Host "`n[5/6] PEAP Certificate Binding" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25" |
    Select ServerConfigured, CertificateThumbprint

# 6. Recent Authentication Events
Write-Host "`n[6/6] Recent Authentication Events (last 5 minutes)" -ForegroundColor Yellow
$startTime = (Get-Date).AddMinutes(-5)
Get-WinEvent -LogName Security -MaxEvents 50 |
    Where-Object {$_.Id -in @(6272,6273) -and $_.TimeCreated -gt $startTime} |
    Select TimeCreated, Id, @{N='Result';E={if($_.Id -eq 6272){'Success'}else{'Failure'}}} |
    Format-Table -AutoSize

Write-Host "`n=== End Health Check ===`n" -ForegroundColor Cyan
```

### 10.0.2 Enable Comprehensive Logging

```powershell
# Enable NPS audit logging
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable

# Enable firewall logging for troubleshooting
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# Verify audit settings
auditpol /get /subcategory:"Network Policy Server"
```

### 10.1 Common Event IDs

| Event ID | Meaning | Action |
|----------|---------|--------|
| 6272 | Access granted | Normal - successful authentication |
| 6273 | Access denied | Check reason code in event details |
| 6274 | Request discarded | Possible shared secret mismatch |
| 6278 | Granted full access | Normal - successful authorization |

### 10.2 Common Reason Codes (Event 6273)

Meanings from Microsoft's [NPS Reason Codes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197570(v=ws.10)) reference. The event's own *Reason* text says the same thing — read it.

| Code | Meaning | Usual fix |
|------|---------|-----|
| 8 | The user account in User-Name does not exist | Check the identity the client actually sent (typo, wrong domain/prefix, a saved Wi-Fi identity) — see 10.7 |
| 16 | Credentials mismatch: bad user name or password | Re-enter the password; check lockout; a *smart-card-required* account has no usable password (10.7) |
| 22 | NPS could not negotiate an EAP type with the client | Client and policy must allow the same method (e.g. PEAP) |
| 23 | Error during EAP | Check the PEAP certificate is saved on **this** NPS (10.9) and EAP logs |
| 34 / 35 / 36 | Account disabled / expired / locked out | Fix the account in AD |
| **48** | **No network policy matched** | Identity not in the policy's group (e.g. `WiFi-Users`). Computer accounts (`host/PC…`) land here when the profile tries machine authentication first — harmless if you only allow users |
| **49** | **No connection request policy matched** | **Create the CRP (see Part 5.3) — the most common setup issue** |
| 65 | The account's dial-in *Network Access Permission* is **Deny** | Account → Dial-in tab → *Control access through NPS Network Policy* |
| 66 | Client used an authentication method not enabled on the matching policy | Align the client profile and the policy's EAP types |
| 260 | RADIUS/EAP message altered (MD5 of the message does not match) | Usually a shared-secret mismatch between the AP/controller and NPS |
| 265 / 268 / 280 | Client certificate untrusted / expired / not from a valid CA | Only for EAP-TLS/PEAP-TLS |

A shared-secret mismatch more often shows as **System event ID 18** ("Access-Request … with a message authenticator attribute that isn't valid") than as a 6273.

### 10.2.1 CRITICAL: Reason Code 49 - Missing Connection Request Policy

**Symptom:**
- Client fails immediately after entering credentials
- Windows error: "Unable to connect to this network" or "Network authentication failed due to a problem with the user account"
- Event ID 6273 with Reason Code 49

**Diagnosis:**
```powershell
# Check if CRP exists
netsh nps show crp
```

**If output is empty or shows "Ok." with no policy, you're missing the CRP!**

**Fix:**
```powershell
# Create Connection Request Policy
netsh nps add crp name="Use Windows authentication for all users" `
    state=enable processingorder=1 policysource=0 `
    conditionid=0x1006 `
    conditiondata="0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00" `
    profileid=0x1025 profiledata=0x1

# Restart NPS
Restart-Service ias

# Test again - should now work!
```

### 10.2.2 CRITICAL: Empty ServerNames Field - "Driver Disconnected While Associating"

⚠️ **THIS IS A NEWLY DISCOVERED CRITICAL ISSUE** - Windows WiFi profiles with empty `<ServerNames>` fields cause connection failures BEFORE reaching NPS.

**Symptoms:**
- Windows error: "The driver disconnected while associating"
- Alternative error: "Unable to connect to this network" or "The specific network is not available"
- Connection attempts show RSSI: 255 (invalid value)
- WiFi 802.1X starts but fails immediately
- **ZERO RADIUS requests reach NPS** (unlike Reason Code 49)
- Works on mobile devices (Android/iOS) but fails on Windows

**Root Cause:**
The WiFi profile XML has `<ServerNames></ServerNames>` (empty tag) instead of the actual NPS server certificate common name. This causes Windows to fail server validation during WiFi association, before 802.1X authentication even begins.

**Diagnosis:**
```powershell
# Export the WiFi profile
netsh wlan export profile name="YourSSID" folder="C:\Temp" key=clear

# Check the ServerNames field
$profileXml = Get-Content "C:\Temp\Wi-Fi-YourSSID.xml" -Raw
if ($profileXml -match '<ServerNames>(.*?)</ServerNames>') {
    $serverName = $matches[1]
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        Write-Host "PROBLEM FOUND: ServerNames is EMPTY!" -ForegroundColor Red
        Write-Host "This causes 'driver disconnected while associating' errors" -ForegroundColor Yellow
    } else {
        Write-Host "ServerNames: $serverName" -ForegroundColor Green
    }
}
```

**Fix - Manual (Immediate):**
```powershell
# Delete broken profile
netsh wlan delete profile name="YourSSID"

# Create corrected profile with ServerNames field
# Replace YOUR-NPS-SERVER-FQDN with the Common Name from your NPS certificate
# Replace YOUR-CA-CERT-THUMBPRINT with your Root CA certificate thumbprint

$profileXml = @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>YourSSID</name>
    <SSIDConfig>
        <SSID>
            <name>YourSSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>machineOrUser</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>25</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                                        <ServerNames>YOUR-NPS-SERVER-FQDN</ServerNames>
                                        <TrustedRootCA>YOUR-CA-CERT-THUMBPRINT</TrustedRootCA>
                                    </ServerValidation>
                                    <FastReconnect>true</FastReconnect>
                                    <InnerEapOptional>false</InnerEapOptional>
                                    <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                        <Type>26</Type>
                                        <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
                                            <UseWinLogonCredentials>true</UseWinLogonCredentials>
                                        </EapType>
                                    </Eap>
                                    <EnableQuarantineChecks>false</EnableQuarantineChecks>
                                    <RequireCryptoBinding>false</RequireCryptoBinding>
                                    <PeapExtensions>
                                        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>
                                        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName>
                                    </PeapExtensions>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>
'@

# Save and deploy
$tempFile = "$env:TEMP\WiFi-Fixed.xml"
$profileXml | Out-File -FilePath $tempFile -Encoding ASCII
netsh wlan add profile filename=$tempFile user=all
Remove-Item $tempFile -Force

Write-Host "✓ Profile deployed with correct ServerNames field!" -ForegroundColor Green
```

**How to Get Your NPS Server Certificate Name:**
```powershell
# On NPS server - get the certificate Common Name
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
} | Select-Object Subject, @{Name="ServerName";Expression={
    if ($_.Subject -match "CN=([^,]+)") { $matches[1] }
}}
```

**How to Get Your Root CA Certificate Thumbprint:**
```powershell
# On client machine
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*CA*"
} | Select-Object Subject, Thumbprint | Format-Table
```

**For GPO Deployments:**
- If deploying via Group Policy, ensure the WiFi profile XML in the GPO includes the `<ServerNames>` field
- See Part 12.2.3 for the complete corrected WiFi profile XML template
- GPO-deployed profiles with empty ServerNames **cannot** be overwritten from the client side
- Must fix the GPO itself and force client update with `gpupdate /force` + reboot

**Prevention:**
- Always validate WiFi profiles before deployment
- Test on a single Windows client before rolling out via GPO
- Include this check in your deployment scripts

### 10.3 Authentication Fails Immediately

**Problem:** Client connects but fails authentication without reaching NPS

**Check on NPS Server:**
```powershell
# Look for "invalid RADIUS client" errors
Get-WinEvent -LogName System -MaxEvents 50 |
    Where-Object {$_.Message -like "*RADIUS*" -or $_.ProviderName -eq "NPS"}
```

**Solution:** Add the actual IP sending RADIUS requests:
- Check UniFi logs for the source IP of RADIUS requests
- Add that IP as a RADIUS client in NPS

### 10.4 Certificate Validation Errors

**Problem:** "Cannot verify server identity" or certificate errors

**On Client:**
- Verify Root CA certificate is installed in **Trusted Root Certification Authorities**
- Windows: `certmgr.msc` → Trusted Root Certification Authorities → Certificates
- macOS: Keychain Access → System → Certificate is "Always Trust"

**On NPS Server:**
- Verify server certificate has "Server Authentication" EKU
- Verify certificate is selected in Network Policy PEAP settings

### 10.5 No RADIUS Requests Reaching NPS

**Check UniFi Configuration:**
1. Settings → Profiles → RADIUS → Verify IP address is correct
2. Settings → WiFi → Verify RADIUS profile is assigned to SSID
3. Force reprovision Access Points if needed

**Check Network Connectivity:**
```powershell
# From NPS server
Test-NetConnection -ComputerName [UniFi-IP] -Port 443

# From UniFi (if SSH access available)
nc -zvu [NPS-IP] 1812
```

### 10.6 User Account Issues

**Account locked:**
```powershell
# Check if account is locked
Get-ADUser -Identity username | Select-Object Enabled, LockedOut

# Unlock account
Unlock-ADAccount -Identity username
```

**Password expired:**
```powershell
# Check password status
Get-ADUser -Identity username -Properties PasswordExpired, PasswordLastSet

# Set password to never expire (not recommended for production)
Set-ADUser -Identity username -PasswordNeverExpires $true
```

### 10.7 "Sign in with current user" fails but typed credentials work

Typed credentials working proves the AP, NPS, policy and certificates are fine — the difference is **the identity Windows sends**.

1. Find the identity in the client log: `Microsoft-Windows-WLAN-AutoConfig/Operational`, event **12013** (802.1X failed) has `Identity=` and `User=` fields; **12012** is the success. `tools/Get-WifiClientEvidence.ps1` prints them.
2. Find the same attempt on NPS (same minute, `LocalMac` = `Calling-Station-Id`): its reason code tells you why.
3. Typical causes:
   - **A saved Wi-Fi identity**, not the Windows account: the profile has `<UseWinLogonCredentials>false</UseWinLogonCredentials>`, so Windows reuses whatever was typed and remembered for that SSID (reason 8 if that name doesn't exist). Re-enter the right credentials, or set `UseWinLogonCredentials` to `true` so "current user" really is the signed-in account.
   - **The account requires a smart card** (`userAccountControl` includes `0x40000` SMARTCARD_REQUIRED, e.g. 262656 = 0x40000 + 0x200). AD keeps a random password for such accounts, so PEAP-MSCHAPv2 can never succeed for them; use a normal account, or EAP-TLS with certificates.
   - **Windows Hello / smart-card sign-in**: there is no password to reuse, so password-based SSO cannot work for that session.
   - **Credential Guard** (Enterprise/Education with VBS) blocks saved/SSO credentials for MSCHAPv2-based Wi-Fi; check `Win32_DeviceGuard.SecurityServicesRunning` contains `1`.
   - **Machine authentication noise**: `authMode` `machineOrUser` tries `host/<PC>` first; if computers aren't in the group, NPS logs reason 48 every time. Use `authMode` `user` if you don't need Wi-Fi before logon.
4. `whoami` over SSH/WinRM shows the *remote* session's user — use `quser` or `(Get-CimInstance Win32_ComputerSystem).UserName` for the person at the desk.

### 10.8 Client profile trusts the NPS server certificate instead of the CA root

If a profile was created by clicking **Connect** on the certificate prompt, `TrustedRootCA` may hold the thumbprint of the **NPS server's own certificate** rather than your root CA. It works until that certificate is renewed — or until the *other* NPS answers — and then clients fail or prompt.

```powershell
# On the client: what does the profile trust?
netsh wlan export profile name="YOUR-SSID" folder=$env:TEMP    # then look at <TrustedRootCA> and <ServerNames>
# On each NPS: the certificate thumbprints and their root
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
```

Fix: `TrustedRootCA` = the **root CA** thumbprint, `ServerNames` = every NPS server name (`nps1.example.com;nps2.example.com`). Deploy via GPO (Part 12) or re-import the profile **in the user's desktop session** — re-importing a profile clears its saved Wi-Fi credentials, so expect one prompt.

### 10.9 Second NPS server: PEAP certificate not actually saved

The PEAP **Edit** dialog in the NPS console *pre-selects* a suitable certificate even when none is saved, so it looks correct. The setting is stored only after **OK** in that dialog **and** OK/Apply on the policy. Until then the backup NPS can't complete PEAP — you only find out when the primary is down.

Check on every NPS (read-only):
```powershell
$x = [xml](Get-Content "$env:windir\System32\ias\ias.xml" -Raw)
$x.SelectNodes('//*[local-name()="msEAPConfiguration"]') | ForEach-Object { "$($_.ParentNode.ParentNode.GetAttribute('name')): saved" }
```
A policy that allows PEAP but is missing from that list has no certificate saved. `tools/Get-NpsEvidence.ps1` does this check and shows the thumbprint in use.

### 10.10 Message-Authenticator hardening (BlastRADIUS, KB5040268)

NPS logs System event **4421** while *RequireMsgAuth / limitProxyState* are disabled. Turn the client-side check on in two steps on **every** NPS:

```cmd
netsh nps set limitproxystate all=audit
:: after a day with no audit warnings in the NPS System log:
netsh nps set limitproxystate all=enable
netsh nps show limitproxystate
```
`requiremsgauth` applies to responses from **remote RADIUS servers** (when NPS proxies) — it has no effect if NPS answers itself. 802.1X/EAP requests always carry Message-Authenticator, so Wi-Fi is not affected; the audit step catches any non-EAP RADIUS client.

### 10.11 Read-only evidence tools

`tools/` contains two scripts that collect everything above without changing anything (no keys, no RADIUS secrets):

| Script | Run on | Shows |
|---|---|---|
| `Get-WifiClientEvidence.ps1 -Ssid <SSID>` | the Windows client | signed-in identity and sign-in method, Credential Guard, the profile's EAP XML, policy source, WLAN events with the identity sent and reason codes |
| `Get-NpsEvidence.ps1 -Hours 6 -Users alice,bob` | **each** NPS server | audit + Message-Authenticator state, 6272/6273/6274 events and a per-user summary, policies and the **saved** PEAP certificate, certificate expiry/chain, account flags (SMARTCARD_REQUIRED) |

Pair client and NPS lines by time and MAC (see 10.7). See `tools/README.md`.

## Part 11: Security Best Practices

### 11.1 Secure RADIUS Shared Secret

```powershell
# Secure the secret file with NTFS permissions (Administrators only)
$acl = Get-Acl "C:\radius_secret.txt"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\radius_secret.txt" $acl
```

### 11.2 NPS Configuration Backups

```powershell
# Regular backups (contains plaintext secrets - encrypt/secure!)
$date = Get-Date -Format "yyyyMMdd_HHmmss"
netsh nps export filename="C:\Backups\nps_backup_$date.xml" exportPSK=YES
```

### 11.3 Certificate Management

- **Monitor expiration:** Certificates typically expire in 1-2 years
- **Renew 3 months before expiration**
- **Update Network Policy** with new certificate thumbprint after renewal

### 11.4 Monitoring

```powershell
# Create scheduled task to monitor failed authentications
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
    "-Command `"Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6273} -MaxEvents 50 | Export-Csv C:\Logs\failed_auth.csv`""
Register-ScheduledTask -TaskName "NPS-FailedAuth-Monitor" -Trigger $trigger -Action $action
```

## Part 12: Advanced Configurations

### 12.1 Dynamic VLAN Assignment

Configure NPS to assign users to different VLANs based on group membership:

1. Edit Network Policy → **Settings** tab
2. Add RADIUS attributes:
   - **Tunnel-Type:** `Virtual LANs (VLAN)`
   - **Tunnel-Medium-Type:** `802`
   - **Tunnel-Private-Group-ID:** `[VLAN ID]` (e.g., 10, 20, 30)

3. Enable RADIUS VLAN support in UniFi:
   - SSID Settings → Advanced → Enable RADIUS Dynamic Authorization

### 12.2 Automated Deployment via Group Policy (Recommended for Production)

For organizations with multiple devices, automate WiFi and certificate deployment using Group Policy.

#### 12.2.1 Overview

**What gets deployed automatically:**
- ✅ Root CA certificate to all domain computers
- ✅ WiFi profile with proper security settings
- ✅ Automatic connection to corporate WiFi after domain join
- ✅ No manual configuration required on client devices

#### 12.2.2 Create GPO for CA Certificate Deployment

```powershell
# On Domain Controller
Import-Module GroupPolicy

# Create GPO for CA certificate
$caCertGPO = New-GPO -Name "Deploy Root CA Certificate" `
    -Comment "Deploys internal Root CA to all domain computers"

# Link to domain
$domain = (Get-ADDomain).DistinguishedName
New-GPLink -Name "Deploy Root CA Certificate" -Target $domain -LinkEnabled Yes

Write-Output "GPO Created: Deploy Root CA Certificate"
Write-Output "Next: Configure the GPO via Group Policy Management Console"
```

**Configure in GPMC:**
1. Open **Group Policy Management** (`gpmc.msc`)
2. Navigate to **Forest → Domains → [your domain] → Group Policy Objects**
3. Right-click **Deploy Root CA Certificate** → **Edit**
4. Navigate to:
   ```
   Computer Configuration
    → Policies
      → Windows Settings
        → Security Settings
          → Public Key Policies
            → Trusted Root Certification Authorities
   ```
5. Right-click **Trusted Root Certification Authorities** → **Import**
6. Select your Root CA certificate file (e.g., `RootCA.cer`)
7. Complete the wizard
8. Close Group Policy Editor

#### 12.2.3 Create GPO for WiFi Profile Deployment

```powershell
# Create GPO for WiFi profile
$wifiGPO = New-GPO -Name "Deploy Corporate WiFi Profile" `
    -Comment "Deploys WPA3-Enterprise WiFi configuration"

# Link to domain
New-GPLink -Name "Deploy Corporate WiFi Profile" -Target $domain -LinkEnabled Yes

Write-Output "GPO Created: Deploy Corporate WiFi Profile"
Write-Output "Next: Configure WiFi settings via Group Policy Management Console"
```

**Configure WiFi Policy in GPMC:**

1. Right-click **Deploy Corporate WiFi Profile** → **Edit**
2. Navigate to:
   ```
   Computer Configuration
    → Policies
      → Windows Settings
        → Security Settings
          → Wireless Network (IEEE 802.11) Policies
   ```
3. Right-click **Wireless Network (IEEE 802.11) Policies** → **Create A New Wireless Network Policy for Windows Vista and Later Releases**
4. Policy name: `Corporate WiFi Policy`
5. Click **Add** → **Infrastructure**

**Network Profile Configuration:**

**General Tab:**
- Profile Name: `YourSSIDName`
- Network Name (SSID): `YourSSIDName`
- ✅ Check "Connect automatically when this network is in range"
- ✅ Check "Connect to a more preferred network if available"

**Security Tab:**
- Authentication: **WPA2-Enterprise** or **WPA3-Enterprise**
- Encryption: **AES**
- Select authentication method: **Microsoft: Protected EAP (PEAP)**
- Click **Properties**

**PEAP Properties:**
- ✅ Check "Validate server certificate"
- Connect to these servers: `your-nps-server.domain.local` (optional but recommended)
- Trusted Root Certification Authorities:
  - ✅ Check your Root CA (e.g., "Company-Root-CA")
- Select Authentication Method: **Secured password (EAP-MSCHAP v2)**
- Click **Configure** (next to EAP-MSCHAP v2):
  - ❌ Uncheck "Automatically use my Windows logon name and password"
  - Click **OK**
- ✅ Check "Enable Fast Reconnect" (recommended for roaming)
- Click **OK**

**Connection Tab:**
- ✅ Check "Connect automatically when this network is in range"

Click **OK** to save the profile.

#### 12.2.4 GPO Deployment and Testing

**Force GPO Update on Test Client:**
```powershell
# On Windows client
gpupdate /force

# Wait 1-2 minutes for policies to apply

# Verify CA certificate was deployed
Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object {$_.Subject -like "*YourCA*"}

# Verify WiFi profile was deployed
netsh wlan show profiles
```

**Expected Results:**
- Root CA certificate appears in `Cert:\LocalMachine\Root`
- WiFi profile appears in network list
- User can connect by entering AD credentials once
- Subsequent connections are automatic

#### 12.2.5 Production Deployment Workflow

**For New Laptops:**
1. Image laptop with Windows
2. Join to Active Directory domain
3. Reboot
4. Group Policy automatically applies (5-10 minutes, or `gpupdate /force`)
5. WiFi profile and CA certificate deployed
6. User connects to WiFi → Enters AD credentials once
7. Windows caches credentials → Future connections are automatic

**For Existing Domain Computers:**
- Policies apply at next Group Policy refresh (every 90 minutes)
- Or force immediate application: `gpupdate /force`

#### 12.2.6 GPO Targeting Options

**Option 1: Deploy to All Computers (Default)**
- Link GPOs to domain root
- Applies to all domain-joined computers

**Option 2: Deploy to Specific OUs**
```powershell
# Create Laptops OU if it doesn't exist
New-ADOrganizationalUnit -Name "Laptops" -Path "DC=yourdomain,DC=local"

# Link GPOs to Laptops OU only
$laptopsOU = "OU=Laptops,DC=yourdomain,DC=local"
New-GPLink -Name "Deploy Root CA Certificate" -Target $laptopsOU
New-GPLink -Name "Deploy Corporate WiFi Profile" -Target $laptopsOU
```

**Option 3: Security Group Filtering**
```powershell
# Create AD group for WiFi-enabled devices
New-ADGroup -Name "WiFi-Enabled-Devices" -GroupScope Global -GroupCategory Security

# Add computer accounts to group
Add-ADGroupMember -Identity "WiFi-Enabled-Devices" -Members "LAPTOP01$", "LAPTOP02$"

# In GPMC: GPO → Delegation → Advanced
# Add "WiFi-Enabled-Devices" with "Read" and "Apply group policy" permissions
# Remove "Authenticated Users" if you want exclusive targeting
```

#### 12.2.7 Troubleshooting GPO Deployment

**Check GPO Application:**
```powershell
# On client, check which GPOs are applied
gpresult /r

# Generate detailed HTML report
gpresult /h C:\gpresult.html
# Open gpresult.html and look for:
# - "Deploy Root CA Certificate" under Computer Configuration
# - "Deploy Corporate WiFi Profile" under Computer Configuration
```

**Certificate Not Deployed:**
```powershell
# Force computer policy refresh
gpupdate /force /target:computer

# Check if GPO link is enabled
Get-GPO -Name "Deploy Root CA Certificate" | Select DisplayName, GpoStatus

# Verify GPO is linked to correct OU/domain
Get-GPInheritance -Target "DC=yourdomain,DC=local" |
    Select-Object -ExpandProperty GpoLinks
```

**WiFi Profile Not Deployed:**
```powershell
# Check Wireless Network Policy settings
Get-NetFirewallRule -DisplayGroup "Network List Manager Policies"

# Verify WLAN AutoConfig service is running
Get-Service -Name WlanSvc | Select Status, StartType

# Manually refresh wireless profiles
netsh wlan refresh policy
```

#### 12.2.8 GPO Maintenance

**Backup GPOs:**
```powershell
# Backup all GPOs
$backupPath = "C:\GPO-Backups\$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path $backupPath -ItemType Directory -Force

Backup-GPO -All -Path $backupPath
Write-Output "GPOs backed up to: $backupPath"
```

**Monitor GPO Application:**
```powershell
# Get GPO replication status
Get-GPOReport -All -ReportType Html -Path "C:\GPO-Report.html"
```

### 12.3 EAP-TLS (Certificate-Based Authentication)

For even stronger security, use client certificates instead of passwords:

1. Create and distribute user certificates from AD CS
2. Modify Network Policy authentication to include EAP-TLS
3. Configure clients with user certificates
4. No password required - certificate is the credential

## Part 13: Documentation

### 13.1 Record Keeping

Maintain documentation of:
- **RADIUS Shared Secret** (in password manager)
- **Certificate Thumbprints** (current and historical)
- **RADIUS Client IPs** (UniFi devices)
- **Network Policy Conditions**
- **Authorized User Groups**

### 13.2 Change Management

When making changes:
1. **Export NPS configuration** before changes
2. **Test in non-production** if possible
3. **Document changes** (date, reason, who made them)
4. **Verify functionality** after changes

## Appendix A: PowerShell Quick Reference

```powershell
# NPS Service Management
Get-Service -Name IAS
Restart-Service -Name IAS
Set-Service -Name IAS -StartupType Automatic

# RADIUS Client Management
Get-NpsRadiusClient
netsh nps add client name="NAME" address="IP" sharedsecret="SECRET" vendor="other"
netsh nps delete client name="NAME"

# Active Directory Management
Get-ADGroupMember -Identity "WiFi-Users"
Add-ADGroupMember -Identity "WiFi-Users" -Members "username"
Remove-ADGroupMember -Identity "WiFi-Users" -Members "username"

# Certificate Management
Get-ChildItem Cert:\LocalMachine\My
Get-ChildItem Cert:\LocalMachine\Root
Get-Certificate -Template RASAndIASServer -CertStoreLocation Cert:\LocalMachine\My

# Event Log Queries
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6272} -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=6273} -MaxEvents 10
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object {$_.ProviderName -eq "NPS"}

# NPS Configuration
netsh nps export filename="backup.xml" exportPSK=YES
netsh nps import filename="backup.xml"
netsh nps show config
```

## Appendix B: Architecture Diagrams

### Authentication Flow

```
1. Client → AP: EAP-Identity Request
2. AP → UDM: Forward EAP message
3. UDM → NPS: RADIUS Access-Request (EAP payload)
4. NPS → Client: PEAP TLS tunnel establishment
   4a. NPS presents server certificate
   4b. Client validates certificate chain
   4c. TLS tunnel established
5. Client → NPS: Username/Password (inside encrypted tunnel)
6. NPS → AD: LDAP query for user authentication
7. AD → NPS: Authentication success
8. NPS → AD: Query group membership
9. AD → NPS: User is in WiFi-Users group
10. NPS → UDM: RADIUS Access-Accept
11. UDM → AP: Allow connection
12. AP → Client: Encryption keys + network access
```

### Network Topology

```
[Internet]
    |
[ISP Router]
    |
[UniFi Dream Machine Pro Max]
    |
    |--- [Switch] --- [Access Point 1]
    |             |-- [Access Point 2]
    |             |-- [Access Point N]
    |
    |--- [VLAN: Management] --- [NPS Server / DC]
    |--- [VLAN: Corporate] ----- [WiFi Clients]
    |--- [VLAN: Guest] ---------- [Guest WiFi]
```

## Appendix C: Supported Devices

### UniFi Devices with WPA3-Enterprise Support

- Dream Machine Pro / Pro Max
- Dream Machine SE
- Cloud Gateway Ultra / Max
- U6 Series Access Points (Lite, LR, Pro, Enterprise, Mesh, IW)
- U7 Series Access Points (Pro, Wall)
- BeaconHD (with updated firmware)

### Client OS Compatibility

| OS | WPA3 Support | WPA2-Enterprise |
|----|--------------|-----------------|
| Windows 10 (1903+) | Yes | Yes |
| Windows 11 | Yes | Yes |
| macOS 10.15+ | Yes | Yes |
| iOS 13+ | Yes | Yes |
| iPadOS 13+ | Yes | Yes |
| Android 10+ | Yes | Yes |
| Linux (wpa_supplicant 2.9+) | Yes | Yes |

## Support and Additional Resources

- [Microsoft NPS Documentation](https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/)
- [UniFi RADIUS Configuration](https://help.ui.com/hc/en-us/articles/115002662607)
- [WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)

---

**Version:** 1.1
**Last Updated:** 2025-12-30
**License:** MIT
**Author:** Homelab Infrastructure Documentation

---

## Changelog

### v1.2 (2025-12-31) - CRITICAL FIX: Empty ServerNames Field

⚠️ **NEWLY DISCOVERED CRITICAL ISSUE** - Windows WiFi profiles with empty `<ServerNames>` fields cause "driver disconnected while associating" errors

**Critical Additions:**
- 🚨 **ADDED Section 10.2.2: Empty ServerNames Field Troubleshooting** - Fixes "driver disconnected while associating" errors on Windows
- ✅ **Complete WiFi profile XML template with ServerNames field** - Prevents the most common Windows connection failure
- ✅ **Diagnostic script to detect empty ServerNames** - Catch this issue before deployment
- ✅ **Manual and GPO fix procedures** - Solutions for both deployment methods

**What This Fixes:**
- Windows error: "The driver disconnected while associating"
- Windows error: "Unable to connect to this network" / "The specific network is not available"
- Connection fails BEFORE reaching NPS (RSSI: 255, no RADIUS requests)
- Works on mobile devices but fails on Windows laptops
- GPO-deployed WiFi profiles that cannot be overwritten

**Why This Matters:**
- This issue is **different** from Reason Code 49 (Connection Request Policy)
- Affects WiFi association at the driver level, not authentication
- Cannot be diagnosed using NPS logs (no requests reach NPS)
- Common when using Windows GUI to configure GPO WiFi profiles

**Migration Notes:**
- If experiencing "driver disconnected" errors, check Section 10.2.2 immediately
- Validate all existing WiFi profiles have `<ServerNames>YOUR-NPS-FQDN</ServerNames>`
- GPO profiles must be updated on the server and clients must run `gpupdate /force` + reboot

### v1.1 (2025-12-30) - CRITICAL UPDATE
- ⚠️ **ADDED Part 5.3: Connection Request Policy (CRP) configuration** - THE MOST COMMON FAILURE POINT
- ⚠️ **ADDED Section 5.3.4: PEAP Certificate Binding** - Required step often missed
- ✅ **ADDED Part 10.0: Systematic Diagnosis Methodology** - Step-by-step troubleshooting approach
- ✅ **ADDED Part 10.0.1: Quick Diagnostic Script** - Automated NPS health check
- ✅ **ADDED Section 10.2.1: Reason Code 49 Troubleshooting** - Missing CRP diagnosis and fix
- ✅ **MASSIVELY EXPANDED Part 12.2: Group Policy Deployment** - Complete automated deployment guide
  - GPO creation scripts
  - Step-by-step GPMC configuration
  - Production deployment workflow
  - Targeting options (OU, Security Groups)
  - Comprehensive troubleshooting
  - GPO maintenance and backups
- 📝 Updated troubleshooting section with real-world diagnosis examples
- 📝 Added audit logging configuration
- 📝 Improved firewall configuration guidance

**Breaking Changes:** None - all additions are supplementary

**Migration Notes:**
- If you previously set up NPS and are experiencing "Unable to connect" errors, check Part 5.3 and Part 10.2.1
- Existing working configurations are not affected

### v1.0 (2025-12-30)
- Initial documentation
- Complete NPS setup procedure
- UniFi configuration steps
- Troubleshooting guide
- Security best practices
