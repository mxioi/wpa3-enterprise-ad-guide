# Troubleshooting tools

Both scripts are **read-only**: they never change Wi-Fi profiles, NPS configuration, certificates or accounts, never
print Wi-Fi keys (`key=clear` is not used) and never read RADIUS shared secrets. Run from an elevated PowerShell.

```powershell
# On the Windows client that can't connect
.\Get-WifiClientEvidence.ps1 -Ssid "YOUR-SSID" -Interface "Wi-Fi" -Hours 24 > client.txt

# On EVERY NPS server (the AP may fail over to the second one)
.\Get-NpsEvidence.ps1 -Hours 24 -Users alice,bob > "nps-$env:COMPUTERNAME.txt"
```

How to read them together:

1. In `client.txt`, find the failing attempt: event **12013** (802.1X failed) with `Identity=` (what was sent) and
   `LocalMac=`. **12012** is a success, **8001** a completed connection.
2. In the NPS files, find the event at the same time with `CallingStationID` = that MAC. **6273** = denied (read
   `ReasonCode` + `Reason`), **6272** = granted, **6274** = discarded.
3. Reason codes → README section 10.2; "current user" vs typed credentials → 10.7; certificate pinning → 10.8;
   backup NPS without a saved PEAP certificate → 10.9.

If the two sides disagree about time, check the `SERVER` line in the NPS output for its UTC offset.
