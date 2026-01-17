<div align="center">
  <h1>ProfileDoktor</h1>
  <p><b>Roaming profile forensics + health audit for Windows endpoints and servers.</b></p>
  <p>
    <span class="badge">PowerShell 5.1+</span>
    <span class="badge">Admin Required</span>
    <span class="badge">Windows 10/11 + Server 2016+</span>
  </p>
</div>

## What It Does
ProfileDoktor scans local Windows profiles and correlates registry state, event logs, roaming paths, disk health, and file inventory. The output is a technical HTML report with collapsible sections and a left-side navigation tree for fast triage.

<div class="grid">
  <div class="card"><b>Profile Registry</b><br>ProfileList state, flags, refcount, load/unload time, .bak keys.</div>
  <div class="card"><b>Event Correlation</b><br>User Profile Service + System/Application events plus Security 4624 logon context.</div>
  <div class="card"><b>Roaming Risk</b><br>Locked files, oversized files, long paths, missing core hives.</div>
  <div class="card"><b>Disk & Paths</b><br>Free space checks, orphaned profile dirs, roaming path access.</div>
</div>

## Quick Start
```powershell
# From repo root, run as Admin
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
- HTML report with collapsible sections and left navigation.
- Uses `ProfileDoktor.Report.template.html` and `ProfileDoktor.Report.css` from the same folder as the script.
- If the report is written to another folder, the CSS is copied next to the HTML for offline viewing.

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

## File Layout
| File | Purpose |
| --- | --- |
| `ProfileDoktor.ps1` | Scanner and HTML generator. |
| `ProfileDoktor.Report.template.html` | HTML shell with placeholders. |
| `ProfileDoktor.Report.css` | Offline CSS for the report. |

## Automation (Task Scheduler)
```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\\Tools\\ProfileDoktor.ps1" -AllUsers -OutputPath "C:\\Reports\\ProfileDoktor_Daily.html" -NoPrompt'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'ProfileDoktor_Audit' -Action $action -Trigger $trigger
```

## Notes
- Security log access is required to surface logon server and 4624 data.
- The ActiveDirectory module is optional; if available, ProfilePath/HomeDirectory are added.
- Long path checks are based on classic Windows MAX_PATH behavior (>= 260 chars).
