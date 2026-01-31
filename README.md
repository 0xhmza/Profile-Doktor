<div align="center">
  <h1>ProfileDoktor</h1>
  <p><b>Windows roaming profile auditor</b></p>
  <p>
    <span class="badge">PowerShell 5.1+</span>
    <span class="badge"> | Windows 10/11, Server 2016+</span>
  </p>
</div>


![Screenshot](Screenshot.png)

## What It Does
ProfileDoktor audits local accounts for roaming-related problems. It automates tasks that take system administrators a long time to do manually.

## Quick Start
```powershell
# In an admin PowerShell session:
.\ProfileDoktor.ps1 -AllUsers
```

```powershell
# Target one user (DOMAIN\user or user@domain)
.\ProfileDoktor.ps1 -UserName "CONTOSO\\jdoe"
```

```powershell
# Write to a custom folder and skip the browser prompt
.\ProfileDoktor.ps1 -AllUsers -OutputPath "C:\\Temp\\ProfileDoktor.html" -NoPrompt
```

## Output
- A comprehensive HTML report containing all collected data. The report is saved in the same folder as the script if no `-OutputPath` is specified.

## Parameters
| Parameter | Purpose | Default |
| --- | --- | --- |
| `-UserName` | Scan one user (DOMAIN\user or user@domain). | None |
| `-AllUsers` | Scan all local profiles. | True |
| `-OutputPath` | HTML output path. | Auto in current folder |
| `-DaysBack` | Event lookback window. | 30 |
| `-LargeFileMB` | Large-file threshold. | 50 |
| `-TopFileCount` | Top N large/locked/long paths. | 25 |
| `-MaxEvents` | Per-log event cap. | 2000 |
| `-NoPrompt` | Do not ask to open the report. | False |

## Data Sources
- WMI/CIM: `Win32_UserProfile`, `Win32_LogicalDisk`, `Win32_OperatingSystem`, `Win32_ComputerSystem`
- Registry: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
- Event Logs:
  - `Microsoft-Windows-User Profile Service/Operational`
  - `Application`, `System`
  - `Security` (Logon 4624 for logon server and context)

<details>
  <summary><b>Event IDs scanned</b></summary>
  1500, 1501, 1502, 1504, 1505, 1508, 1509, 1511, 1515, 1517, 1521, 1525,
  1530, 1533, 1542, 1546, 1550, 1552, 1554, 1561, 1564, 1565, 1570, 1571,
  1581, 1583, 1600
</details>

## Notes
- Security log access is required to surface logon server and 4624 data.
- The ActiveDirectory module is optional; if available, ProfilePath/HomeDirectory are added.
- Long path checks are based on classic Windows MAX_PATH behavior (>= 260 chars).
