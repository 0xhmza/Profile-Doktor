<div align="center">
  <h1>ProfileDoktor</h1>
  <p><b>Roaming profile forensics + health audit for Windows endpoints and servers.</b></p>
  <p>
    <span class="badge">PowerShell 5.1+</span>
    <span class="badge">Admin Required</span>
    <span class="badge">Windows 10/11 + Server 2016+</span>
  </p>
</div>

<style>
.badge {
  display: inline-block;
  padding: 3px 9px;
  margin: 2px;
  border-radius: 999px;
  border: 1px solid #d8d8d8;
  background: #f3f3f3;
  font-size: 12px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}
.card {
  border: 1px solid #e1e1e1;
  border-radius: 10px;
  padding: 10px 12px;
  background: #ffffff;
}
</style>

<hr>

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
<table>
  <tr><th>Parameter</th><th>Purpose</th><th>Default</th></tr>
  <tr><td><code>-UserName</code></td><td>Scan one user (DOMAIN\\user or user@domain).</td><td>None</td></tr>
  <tr><td><code>-AllUsers</code></td><td>Scan all local profiles.</td><td>True</td></tr>
  <tr><td><code>-OutputPath</code></td><td>HTML output path.</td><td>Auto in current folder</td></tr>
  <tr><td><code>-DaysBack</code></td><td>Event lookback window.</td><td>30</td></tr>
  <tr><td><code>-LargeFileMB</code></td><td>Large-file threshold.</td><td>50</td></tr>
  <tr><td><code>-TopFileCount</code></td><td>Top N large/locked/long paths.</td><td>25</td></tr>
  <tr><td><code>-MaxEvents</code></td><td>Per-log event cap.</td><td>2000</td></tr>
  <tr><td><code>-NoPrompt</code></td><td>Do not ask to open the report.</td><td>False</td></tr>
</table>

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
  1581, 1583
</details>

## File Layout
<table>
  <tr><th>File</th><th>Purpose</th></tr>
  <tr><td><code>ProfileDoktor.ps1</code></td><td>Scanner and HTML generator.</td></tr>
  <tr><td><code>ProfileDoktor.Report.template.html</code></td><td>HTML shell with placeholders.</td></tr>
  <tr><td><code>ProfileDoktor.Report.css</code></td><td>Offline CSS for the report.</td></tr>
</table>

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

## License
MIT
