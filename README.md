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

### 10.1 Common Event IDs

| Event ID | Meaning | Action |
|----------|---------|--------|
| 6272 | Access granted | Normal - successful authentication |
| 6273 | Access denied | Check reason code in event details |
| 6274 | Request discarded | Possible shared secret mismatch |
| 6278 | Granted full access | Normal - successful authorization |

### 10.2 Common Reason Codes (Event 6273)

| Code | Meaning | Fix |
|------|---------|-----|
| 8 | No matching policy | Verify policy conditions |
| 16 | User not authorized | Add user to WiFi-Users group |
| 65 | Shared secret mismatch | Verify RADIUS secret in UniFi matches NPS |
| 66 | NPS not registered | Run: `netsh nps add registeredserver` |
| 260 | EAP authentication failed | Check certificate or PEAP settings |

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

### 12.2 Deploy via Group Policy

Deploy Root CA certificate automatically:

1. **Group Policy Management** → Create new GPO
2. Edit GPO:
   ```
   Computer Configuration
     → Policies
       → Windows Settings
         → Security Settings
           → Public Key Policies
             → Trusted Root Certification Authorities
   ```
3. Right-click → **Import** → Select Root CA certificate
4. Link GPO to domain

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

**Version:** 1.0
**Last Updated:** 2025-12-30
**License:** MIT
**Author:** Homelab Infrastructure Documentation

---

## Changelog

### v1.0 (2025-12-30)
- Initial documentation
- Complete NPS setup procedure
- UniFi configuration steps
- Troubleshooting guide
- Security best practices
