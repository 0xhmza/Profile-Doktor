<div align="center">
  <h1>🩺 ProfileDoktor</h1>
  <p><b>Windows roaming profile auditor — diagnose profile issues in seconds</b></p>
  <p>
    <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white" alt="PowerShell 5.1+">
    <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Server%202016%2B-0078D4?logo=windows&logoColor=white" alt="Platform">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
    <img src="https://img.shields.io/badge/Version-1.1.0-orange" alt="Version">
  </p>
</div>

---

## What It Does

ProfileDoktor audits local accounts for roaming-related problems. It automates tasks that take system administrators a long time to do manually, producing a rich interactive HTML report.

### Key Features

- **Profile Health Scoring** — each profile gets a color-coded health badge (Healthy / Fair / Issues Found)
- **Severity-Classified Findings** — every issue is tagged as `ERROR`, `WARN`, or `INFO`
- **Interactive Report** — sortable table columns, full-text search, expand/collapse all, keyboard shortcuts
- **Self-Contained Export** — use `-InlineCSS` to produce a single-file HTML report with no external dependencies
- **Active Directory Enrichment** — if the AD module is available, profile paths and home directories are included
- **Event Correlation** — profile service events, sync timestamps, and security logon context in one view
- **Print-Ready** — clean print stylesheet for hardcopy reports

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
# Self-contained report to a custom folder, no browser prompt
.\ProfileDoktor.ps1 -AllUsers -OutputPath "C:\\Temp\\ProfileDoktor.html" -InlineCSS -NoPrompt
```

## Parameters

| Parameter | Purpose | Default |
| --- | --- | --- |
| `-UserName` | Scan one user (`DOMAIN\user` or `user@domain`). | — |
| `-AllUsers` | Scan all local profiles. | `True` |
| `-OutputPath` | HTML output path. | Auto-generated in `$PWD` |
| `-DaysBack` | Event lookback window (days). | `30` |
| `-LargeFileMB` | Large-file threshold in MB. | `50` |
| `-TopFileCount` | Top N large / locked / long-path files. | `25` |
| `-MaxEvents` | Per-log event cap. | `2000` |
| `-NoPrompt` | Skip the "open report?" prompt. | `False` |
| `-InlineCSS` | Embed CSS in the HTML for a self-contained single-file report. | `False` |

## Report Features

| Feature | Description |
| --- | --- |
| 🔍 **Table Search** | `Ctrl+K` — filter any table row across the entire report |
| ⇅ **Column Sorting** | Click any table header to sort ascending/descending |
| 📂 **Expand / Collapse** | `Ctrl+E` / `Ctrl+W` — toggle all detail sections |
| 🎯 **Nav Filter** | Type in the sidebar search to filter navigation items |
| 📊 **Health Badges** | Per-profile health score with color-coded severity |
| 🖨️ **Print Styles** | Clean print layout that hides UI chrome |
| 🔝 **Back to Top** | Floating button appears after scrolling |
| 📏 **Scroll Progress** | Thin progress bar at the top of the viewport |

## Data Sources

- **WMI/CIM:** `Win32_UserProfile`, `Win32_LogicalDisk`, `Win32_OperatingSystem`, `Win32_ComputerSystem`
- **Registry:** `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
- **Event Logs:**
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
- Long path checks are based on classic Windows MAX_PATH behavior (≥ 260 chars).
- Use `-InlineCSS` when sharing the report file — it embeds all styles so the CSS file is not needed.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
