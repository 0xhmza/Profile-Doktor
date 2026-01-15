# ProfileDoktor

ProfileDoktor is a PowerShell tool for auditing Windows user profile health. It automates the "detective work" behind roaming profile sync failures (like Event ID 1504) by identifying locked, oversized, or corrupted files.

---------------------------------------------------------
🚀 FEATURES
---------------------------------------------------------
* Sync Auditing: Detects roaming upload/download failures.
* Root Cause Analysis: Identifies locked, missing, or oversized files.
* Flexible Scanning: Target specific users or audit all local profiles.
* Reporting: Exports detailed logs to CSV or JSON.
* Automation-Ready: Designed for scheduled checks.

---------------------------------------------------------
⚙️ INSTALLATION & USAGE
---------------------------------------------------------
# Clone and prepare:
git clone https://github.com/<YOUR_ORG>/ProfileDoktor.git
cd ProfileGuard
Get-ChildItem -Recurse | Unblock-File

# Examples:
.\ProfileGuard.ps1 -UserName "usrnm"
.\ProfileGuard.ps1 -AllUsers -ExportFormat CSV -OutputPath 'C:\Temp\Report.csv'

---------------------------------------------------------
📌 PARAMETERS
---------------------------------------------------------
-UserName:     Scan a specific user profile
-AllUsers:     Scan all local profiles
-ExportFormat: Output format (CSV or JSON)
-OutputPath:   Destination path for reports

---------------------------------------------------------
🛠 REMEDIATION TIPS
---------------------------------------------------------
* Exclusions: Skip volatile folders like AppData\Local.
* Redirection: Use Folder Redirection for Desktop/Documents.
* Permissions: Verify NTFS and Share permissions.
* Modernize: Consider moving to FSLogix or OneDrive KFM.

---------------------------------------------------------
🕐 AUTOMATION (Task Scheduler)
---------------------------------------------------------
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File "C:\Tools\ProfileGuard.ps1" -AllUsers -ExportFormat CSV -OutputPath "C:\Reports\Daily.csv"'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'ProfileGuard_Check' -Action $action -Trigger $trigger

---------------------------------------------------------
🧩 REQUIREMENTS & LICENSE
---------------------------------------------------------
* OS: Windows PowerShell 5.1+ (Admin privileges required).
* License: MIT License.
