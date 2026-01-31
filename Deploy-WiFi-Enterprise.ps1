# WiFi Deployment Script for HomeNet_Admin
# Run this as Administrator on new domain-joined laptops

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " HomeNet_Admin WiFi Deployment Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[1/4] Checking CA Certificate..." -ForegroundColor Yellow
$caCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*homelab-VM1-DC1-CA*" }
if ($caCert) {
    Write-Host "  ✓ CA Certificate found" -ForegroundColor Green
} else {
    Write-Host "  ✗ CA Certificate NOT found!" -ForegroundColor Red
    Write-Host "  Install the homelab CA certificate first!" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host ""
Write-Host "[2/4] Removing old WiFi profiles..." -ForegroundColor Yellow
# Remove any existing HomeNet_Admin profiles (ignore errors if they don't exist)
netsh wlan delete profile name="HomeNet_Admin" interface="WiFi" 2>$null
netsh wlan delete profile name="HomeNet_Admin_Fixed" interface="WiFi" 2>$null
netsh wlan delete profile name="HomeNet_Admin_Working" interface="WiFi" 2>$null
Write-Host "  ✓ Old profiles removed" -ForegroundColor Green

Write-Host ""
Write-Host "[3/4] Creating corrected WiFi profile..." -ForegroundColor Yellow

$profileXml = @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>HomeNet_Admin</name>
    <SSIDConfig>
        <SSID>
            <name>HomeNet_Admin</name>
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
                                        <ServerNames><ADD-DC-HOSTNAME></ServerNames>
                                        <TrustedRootCA>f7 78 4b bb 1d a8 5f aa c5 4b 6a c4 a5 db fa 19 91 ab a5 b8</TrustedRootCA>
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

$tempFile = "$env:TEMP\HomeNet_Admin.xml"
$profileXml | Out-File -FilePath $tempFile -Encoding ASCII

Write-Host ""
Write-Host "[4/4] Adding WiFi profile..." -ForegroundColor Yellow
$result = netsh wlan add profile filename=$tempFile interface="WiFi" user=all 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ WiFi profile added successfully!" -ForegroundColor Green
} else {
    Write-Host "  ✗ Failed to add profile: $result" -ForegroundColor Red
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    pause
    exit 1
}

# Clean up
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Deployment Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now connect to HomeNet_Admin WiFi" -ForegroundColor Cyan
Write-Host "using your domain credentials." -ForegroundColor Cyan
Write-Host ""
pause
