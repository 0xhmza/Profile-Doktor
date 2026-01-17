#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Single', Mandatory = $true)]
    [string]$UserName,

    [Parameter(ParameterSetName = 'All')]
    [switch]$AllUsers,

    [string]$OutputPath,

    [int]$DaysBack = 30,

    [int]$LargeFileMB = 50,

    [int]$TopFileCount = 25,

    [int]$MaxEvents = 2000,

    [switch]$NoPrompt
)

if (-not $UserName -and -not $AllUsers) {
    $AllUsers = $true
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error 'This script must be run as Administrator.'
    exit 1
}

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$reportTitle = 'ProfileDoktor - Roaming Profile Audit'
$templateFileName = 'ProfileDoktor.Report.template.html'
$cssFileName = 'ProfileDoktor.Report.css'
$templatePath = Join-Path -Path $scriptRoot -ChildPath $templateFileName
$cssSourcePath = Join-Path -Path $scriptRoot -ChildPath $cssFileName

$scriptVersion = '1.0.0'
$scanStart = Get-Date

function Convert-BytesToHuman {
    param([long]$Bytes)
    if ($null -eq $Bytes) { return '' }
    if ($Bytes -lt 0) { return '0 B' }
    $units = @('B', 'KB', 'MB', 'GB', 'TB')
    $size = [double]$Bytes
    $idx = 0
    while ($size -ge 1024 -and $idx -lt $units.Count - 1) {
        $size /= 1024
        $idx++
    }
    return ('{0:N2} {1}' -f $size, $units[$idx])
}

function Convert-WmiTime {
    param([string]$WmiTime)
    if ([string]::IsNullOrWhiteSpace($WmiTime)) { return $null }
    try {
        return [Management.ManagementDateTimeConverter]::ToDateTime($WmiTime)
    } catch {
        return $null
    }
}

function Convert-FileTimeValue {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try {
        $ft = [int64]$Value
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
    } catch {
        return $null
    }
}

function Convert-FileTimeHighLow {
    param([object]$High, [object]$Low)
    if ($null -eq $High -or $null -eq $Low) { return $null }
    try {
        $ft = ([int64]$High -shl 32) -bor ([uint32]$Low)
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
    } catch {
        return $null
    }
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = [string]$Text
    $t = $t -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"', '&quot;'
    $t = $t -replace "'", '&#39;'
    return $t
}

function ConvertTo-HtmlId {
    param(
        [string]$Text,
        [string]$Prefix = 'section'
    )
    $base = if ([string]::IsNullOrWhiteSpace($Text)) { 'item' } else { $Text }
    $slug = ($base.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($slug)) { $slug = 'item' }
    if ($Prefix) { return "$Prefix-$slug" }
    return $slug
}

function New-DetailsBlock {
    param(
        [string]$Title,
        [string]$BodyHtml,
        [switch]$Open
    )
    $openAttr = if ($Open) { ' open' } else { '' }
    return "<details class='detail'$openAttr><summary>$(ConvertTo-HtmlSafe $Title)</summary><div class='detail-body'>$BodyHtml</div></details>"
}

function Split-AccountName {
    param([string]$AccountName)
    $result = [ordered]@{ Domain = $null; User = $null }
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return [pscustomobject]$result }
    if ($AccountName -match '^(?<domain>[^\\]+)\\(?<user>.+)$') {
        $result.Domain = $Matches['domain']
        $result.User = $Matches['user']
    } elseif ($AccountName -match '^(?<user>[^@]+)@(?<domain>.+)$') {
        $result.Domain = $Matches['domain']
        $result.User = $Matches['user']
    } else {
        $result.User = $AccountName
    }
    return [pscustomobject]$result
}

function Convert-SidToAccount {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $null
    }
}

function Test-UserFilter {
    param(
        [string]$AccountName,
        [string]$Filter
    )
    if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $false }
    $filterLower = $Filter.ToLowerInvariant()
    $acctLower = $AccountName.ToLowerInvariant()
    if ($acctLower -eq $filterLower) { return $true }
    if ($acctLower -match "\\$([regex]::Escape($filterLower))$") { return $true }
    if ($acctLower -match "^$([regex]::Escape($filterLower))@") { return $true }
    return $false
}

function Get-ProfileVersion {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($Path -match '\.V(\d+)(\\)?$') { return "V$($Matches[1])" }
    return $null
}

function Get-DriveInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $drive = Split-Path -Qualifier $Path
    if ([string]::IsNullOrWhiteSpace($drive)) { return $null }
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction SilentlyContinue
    if ($null -eq $disk) { return $null }
    return [pscustomobject]@{
        DeviceId = $disk.DeviceID
        FileSystem = $disk.FileSystem
        SizeBytes = [int64]$disk.Size
        FreeBytes = [int64]$disk.FreeSpace
        FreePercent = if ($disk.Size) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2) } else { $null }
    }
}

function Test-FileLocked {
    param([string]$Path)
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        $stream.Close()
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $null
    } catch [System.IO.IOException] {
        return $true
    } catch {
        return $null
    }
}
function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($data in $xml.Event.EventData.Data) {
            if ($data.Name) { $map[$data.Name] = $data.'#text' }
        }
    } catch {
    }
    return $map
}

function Test-EventMatchesUser {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [string]$AccountName,
        [string]$Sid
    )
    if ($Event.UserId -and $Sid -and $Event.UserId.Value -eq $Sid) { return $true }
    $map = Get-EventDataMap -Event $Event
    if ($Sid) {
        foreach ($key in @('UserSid', 'TargetUserSid', 'Sid')) {
            if ($map.ContainsKey($key) -and $map[$key] -eq $Sid) { return $true }
        }
    }
    $acctParts = Split-AccountName -AccountName $AccountName
    foreach ($key in @('UserName', 'TargetUserName', 'AccountName', 'SubjectUserName')) {
        if ($map.ContainsKey($key) -and $acctParts.User -and ($map[$key] -ieq $acctParts.User)) {
            if (-not $acctParts.Domain) { return $true }
            foreach ($dKey in @('Domain', 'TargetDomainName', 'SubjectDomainName')) {
                if ($map.ContainsKey($dKey) -and ($map[$dKey] -ieq $acctParts.Domain)) { return $true }
            }
            return $true
        }
    }
    $msg = $Event.Message
    if ($msg) {
        if ($Sid -and $msg -match [regex]::Escape($Sid)) { return $true }
        if ($AccountName -and $msg -match [regex]::Escape($AccountName)) { return $true }
        if ($acctParts.User -and $msg -match "\b$([regex]::Escape($acctParts.User))\b") { return $true }
    }
    return $false
}

function New-EventRecord {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $procId = $null
    $threadId = $null
    $task = $null
    $opcode = $null
    $keywords = $null
    try {
        $xml = [xml]$Event.ToXml()
        $exec = $xml.Event.System.Execution
        if ($exec) {
            $procId = $exec.ProcessID
            $threadId = $exec.ThreadID
        }
        $task = $xml.Event.System.Task
        $opcode = $xml.Event.System.Opcode
        $keywords = $xml.Event.System.Keywords
    } catch {
    }
    return [pscustomobject]@{
        TimeCreated = $Event.TimeCreated
        Id = $Event.Id
        Level = $Event.LevelDisplayName
        LogName = $Event.LogName
        Provider = $Event.ProviderName
        RecordId = $Event.RecordId
        ProcessId = $procId
        ThreadId = $threadId
        Task = $task
        Opcode = $opcode
        Keywords = ($Event.KeywordsDisplayNames -join ', ')
        ActivityId = $Event.ActivityId
        UserId = if ($Event.UserId) { $Event.UserId.Value } else { $null }
        Message = $Event.Message
    }
}

function Get-UserEvents {
    param(
        [string]$AccountName,
        [string]$Sid,
        [int]$DaysBack,
        [int]$MaxEvents,
        [int[]]$ProfileEventIds
    )
    $startTime = (Get-Date).AddDays(-$DaysBack)
    $logs = @(
        'Microsoft-Windows-User Profile Service/Operational',
        'Application',
        'System'
    )
    $events = @()
    foreach ($log in $logs) {
        $filter = @{ LogName = $log; StartTime = $startTime }
        if ($ProfileEventIds) { $filter.Id = $ProfileEventIds }
        try {
            $rawEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        } catch {
            continue
        }
        foreach ($evt in $rawEvents) {
            if (Test-EventMatchesUser -Event $evt -AccountName $AccountName -Sid $Sid) {
                $events += (New-EventRecord -Event $evt)
            }
        }
    }
    return $events | Sort-Object TimeCreated -Descending
}

function Get-LastLogonEvent {
    param(
        [string]$AccountName,
        [string]$Sid,
        [int]$DaysBack,
        [int]$MaxEvents
    )
    $startTime = (Get-Date).AddDays(-$DaysBack)
    $filter = @{ LogName = 'Security'; Id = 4624; StartTime = $startTime }
    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
    $acctParts = Split-AccountName -AccountName $AccountName
    foreach ($evt in $events) {
        $map = Get-EventDataMap -Event $evt
        $targetSid = $map['TargetUserSid']
        $targetUser = $map['TargetUserName']
        $targetDomain = $map['TargetDomainName']
        $match = $false
        if ($Sid -and $targetSid -and ($targetSid -eq $Sid)) {
            $match = $true
        } elseif ($targetUser -and $acctParts.User -and ($targetUser -ieq $acctParts.User)) {
            if ($acctParts.Domain -and $targetDomain) {
                if ($targetDomain -ieq $acctParts.Domain) { $match = $true }
            } else {
                $match = $true
            }
        }
        if (-not $match) { continue }
        return [pscustomobject]@{
            TimeCreated = $evt.TimeCreated
            LogonType = $map['LogonType']
            LogonProcess = $map['LogonProcessName']
            AuthPackage = $map['AuthenticationPackageName']
            LogonServer = $map['LogonServer']
            Workstation = $map['WorkstationName']
            IpAddress = $map['IpAddress']
            IpPort = $map['IpPort']
            TargetUserName = $targetUser
            TargetDomainName = $targetDomain
        }
    }
    return $null
}

function Get-ProfileFileInventory {
    param(
        [string]$ProfilePath,
        [int64]$LargeFileBytes,
        [int]$TopFileCount,
        [string[]]$ExcludeLikePatterns,
        [string[]]$LockCheckExtensions
    )
    $result = [ordered]@{
        TotalFiles = 0
        TotalBytes = 0
        RoamingFiles = 0
        RoamingBytes = 0
        LargeFiles = @()
        LockedFiles = @()
        LongPaths = @()
        MissingFiles = @()
        Errors = @()
    }
    if (-not (Test-Path -LiteralPath $ProfilePath)) {
        $result.Errors += 'Profile path not found.'
        return $result
    }
    try {
        $files = Get-ChildItem -LiteralPath $ProfilePath -Recurse -File -Force -ErrorAction SilentlyContinue
    } catch {
        $result.Errors += "File enumeration failed: $($_.Exception.Message)"
        return $result
    }

    $largeList = @()
    $longList = @()
    $lockedList = @()

    foreach ($file in $files) {
        $result.TotalFiles++
        $result.TotalBytes += [int64]$file.Length
        $isRoaming = $true
        foreach ($pattern in $ExcludeLikePatterns) {
            if ($file.FullName -like $pattern) { $isRoaming = $false; break }
        }
        if (-not $isRoaming) { continue }
        $result.RoamingFiles++
        $result.RoamingBytes += [int64]$file.Length
        if ($file.Length -ge $LargeFileBytes) {
            $largeList += [pscustomobject]@{
                Path = $file.FullName
                SizeBytes = [int64]$file.Length
                Size = Convert-BytesToHuman $file.Length
                LastWriteTime = $file.LastWriteTime
            }
        }
        if ($file.FullName.Length -ge 260) {
            $longList += [pscustomobject]@{
                Path = $file.FullName
                PathLength = $file.FullName.Length
                SizeBytes = [int64]$file.Length
            }
        }
        $ext = $file.Extension.ToLowerInvariant()
        if ($LockCheckExtensions -contains $ext -or $file.Name -ieq 'NTUSER.DAT' -or $file.Name -ieq 'USRCLASS.DAT') {
            $lockState = Test-FileLocked -Path $file.FullName
            if ($lockState -eq $true) {
                $lockedList += [pscustomobject]@{
                    Path = $file.FullName
                    SizeBytes = [int64]$file.Length
                    Size = Convert-BytesToHuman $file.Length
                    LastWriteTime = $file.LastWriteTime
                    Reason = 'Sharing violation'
                }
            } elseif ($null -eq $lockState) {
                $lockedList += [pscustomobject]@{
                    Path = $file.FullName
                    SizeBytes = [int64]$file.Length
                    Size = Convert-BytesToHuman $file.Length
                    LastWriteTime = $file.LastWriteTime
                    Reason = 'Access denied or unknown'
                }
            }
        }
    }

    $result.LargeFiles = $largeList | Sort-Object SizeBytes -Descending | Select-Object -First $TopFileCount
    $result.LongPaths = $longList | Sort-Object PathLength -Descending | Select-Object -First $TopFileCount
    $result.LockedFiles = $lockedList | Sort-Object SizeBytes -Descending | Select-Object -First $TopFileCount

    $coreFiles = @(
        (Join-Path -Path $ProfilePath -ChildPath 'NTUSER.DAT')
        (Join-Path -Path $ProfilePath -ChildPath 'NTUSER.DAT.LOG1')
        (Join-Path -Path $ProfilePath -ChildPath 'NTUSER.DAT.LOG2')
        (Join-Path -Path $ProfilePath -ChildPath 'AppData\Local\Microsoft\Windows\UsrClass.dat')
    )
    foreach ($cf in $coreFiles) {
        if (-not (Test-Path -LiteralPath $cf)) { $result.MissingFiles += $cf }
    }

    return $result
}

function ConvertTo-HtmlTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [string]$Caption,
        [string]$EmptyMessage = 'None'
    )
    if (-not $Rows -or $Rows.Count -eq 0) {
        return "<p class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</p>"
    }
    $sb = New-Object System.Text.StringBuilder
    if ($Caption) { [void]$sb.AppendLine("<div class='caption'>$(ConvertTo-HtmlSafe $Caption)</div>") }
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine('<thead><tr>')
    foreach ($col in $Columns) {
        [void]$sb.AppendLine("<th>$(ConvertTo-HtmlSafe $col)</th>")
    }
    [void]$sb.AppendLine('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$sb.AppendLine('<tr>')
        foreach ($col in $Columns) {
            $val = $row.$col
            if ($val -is [DateTime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
            elseif ($null -eq $val) { $val = '' }
            else { $val = [string]$val }
            [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $val)</td>")
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function ConvertTo-EventsTable {
    param(
        [object[]]$Rows,
        [string]$Caption,
        [string]$EmptyMessage = 'None'
    )
    if (-not $Rows -or $Rows.Count -eq 0) {
        return "<p class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</p>"
    }
    $sb = New-Object System.Text.StringBuilder
    if ($Caption) { [void]$sb.AppendLine("<div class='caption'>$(ConvertTo-HtmlSafe $Caption)</div>") }
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine('<thead><tr><th>Time</th><th>ID</th><th>Level</th><th>Log</th><th>Provider</th><th>Record</th><th>PID</th><th>TID</th><th>User</th><th>Message</th></tr></thead><tbody>')
    foreach ($row in $Rows) {
        $timeText = if ($row.TimeCreated) { $row.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $msg = if ($row.Message) { $row.Message } else { '' }
        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $timeText)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.Id)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.Level)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.LogName)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.Provider)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.RecordId)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.ProcessId)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.ThreadId)</td>")
        [void]$sb.AppendLine("<td>$(ConvertTo-HtmlSafe $row.UserId)</td>")
        [void]$sb.AppendLine("<td class='msg'>$(ConvertTo-HtmlSafe $msg)</td>")
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

$profileEventIds = @(
    1500, 1501, 1502, 1504, 1505, 1508, 1509,
    1511, 1515, 1517, 1521, 1525, 1530, 1533,
    1542, 1546, 1550, 1552, 1554, 1561, 1564,
    1565, 1570, 1571, 1581, 1583
)

$failureEventIds = @(1500, 1502, 1504, 1505, 1508, 1509, 1511, 1515, 1517, 1521, 1530, 1542, 1546, 1550, 1552, 1554, 1564, 1565, 1570, 1581, 1583)

$lockCheckExtensions = @(
    '.pst', '.ost', '.db', '.edb', '.sqlite', '.dat', '.log', '.tmp', '.vhd', '.vhdx',
    '.zip', '.7z', '.rar', '.bak'
)

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$systemDriveInfo = Get-DriveInfo -Path $env:SystemDrive

$profileRegRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profileRegBakKeys = @()
try {
    $profileRegBakKeys = Get-ChildItem -Path $profileRegRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*.bak' }
} catch {
}

$profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPath -and -not $_.Special } |
    Sort-Object LocalPath

if ($UserName) {
    $profiles = $profiles | Where-Object {
        $acct = Convert-SidToAccount $_.SID
        Test-UserFilter -AccountName $acct -Filter $UserName
    }
}

$adAvailable = $false
if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    $adAvailable = $true
} else {
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) { $adAvailable = $true }
    } catch {
    }
}

$reportProfiles = @()
foreach ($profile in $profiles) {
    $sid = $profile.SID
    $account = Convert-SidToAccount -Sid $sid
    if (-not $account) { $account = $sid }

    $regPath = Join-Path $profileRegRoot $sid
    $regProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    $regBakExists = Test-Path -LiteralPath ("$regPath.bak")
    $profileImageRaw = $null
    $profileImageExpanded = $null
    if ($regProps -and $regProps.PSObject.Properties.Name -contains 'ProfileImagePath') {
        $profileImageRaw = $regProps.ProfileImagePath
        $profileImageExpanded = [Environment]::ExpandEnvironmentVariables($profileImageRaw)
    }

    $loadTime = $null
    if ($regProps -and $regProps.PSObject.Properties.Name -contains 'ProfileLoadTime') {
        $loadTime = Convert-FileTimeValue -Value $regProps.ProfileLoadTime
    } elseif ($regProps -and $regProps.PSObject.Properties.Name -contains 'ProfileLoadTimeHigh') {
        $loadTime = Convert-FileTimeHighLow -High $regProps.ProfileLoadTimeHigh -Low $regProps.ProfileLoadTimeLow
    }

    $unloadTime = $null
    if ($regProps -and $regProps.PSObject.Properties.Name -contains 'ProfileUnloadTime') {
        $unloadTime = Convert-FileTimeValue -Value $regProps.ProfileUnloadTime
    } elseif ($regProps -and $regProps.PSObject.Properties.Name -contains 'ProfileUnloadTimeHigh') {
        $unloadTime = Convert-FileTimeHighLow -High $regProps.ProfileUnloadTimeHigh -Low $regProps.ProfileUnloadTimeLow
    }

    $localPath = $profile.LocalPath
    $localPathExists = Test-Path -LiteralPath $localPath
    $profileVersion = Get-ProfileVersion -Path $localPath
    $roamingPath = $profile.RoamingPath
    $roamingPathExists = $null
    $roamingPathError = $null
    if ($roamingPath) {
        try {
            $roamingPathExists = Test-Path -LiteralPath $roamingPath -ErrorAction Stop
        } catch {
            $roamingPathExists = $false
            $roamingPathError = $_.Exception.Message
        }
    }

    $excludePatterns = @(
        (Join-Path $localPath 'AppData\Local\*'),
        (Join-Path $localPath 'AppData\LocalLow\*'),
        (Join-Path $localPath 'AppData\Local\Temp\*'),
        (Join-Path $localPath 'AppData\Local\Microsoft\Windows\INetCache\*')
    )

    $fileInventory = Get-ProfileFileInventory -ProfilePath $localPath -LargeFileBytes ($LargeFileMB * 1MB) -TopFileCount $TopFileCount -ExcludeLikePatterns $excludePatterns -LockCheckExtensions $lockCheckExtensions
    $lastUseTime = Convert-WmiTime -WmiTime $profile.LastUseTime

    $userEvents = Get-UserEvents -AccountName $account -Sid $sid -DaysBack $DaysBack -MaxEvents $MaxEvents -ProfileEventIds $profileEventIds
    $eventSummary = @()
    if ($userEvents) {
        $eventSummary = $userEvents | Group-Object Id | ForEach-Object {
            $last = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msg = if ($last.Message) { ($last.Message -replace '\s+', ' ').Trim() } else { '' }
            if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) + '...' }
            [pscustomobject]@{
                Id = $_.Name
                Count = $_.Count
                LastSeen = $last.TimeCreated
                Provider = $last.Provider
                Example = $msg
            }
        } | Sort-Object { [int]$_.Id }
    }

    $lastSyncSuccess = $null
    $lastSyncFailure = $null
    if ($userEvents) {
        $lastSyncSuccess = $userEvents | Where-Object { $_.Message -match '(?i)success|saved|synchron|upload' } | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $lastSyncFailure = $userEvents | Where-Object { $failureEventIds -contains $_.Id } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    }

    $lastLogon = Get-LastLogonEvent -AccountName $account -Sid $sid -DaysBack $DaysBack -MaxEvents $MaxEvents

    $adInfo = $null
    if ($adAvailable) {
        $acctParts = Split-AccountName -AccountName $account
        if ($acctParts.Domain -and ($acctParts.Domain -ne $env:COMPUTERNAME) -and $acctParts.User) {
            try {
                $adUser = Get-ADUser -Identity $acctParts.User -Properties ProfilePath, HomeDirectory, HomeDrive, ScriptPath -ErrorAction Stop
                $adInfo = [ordered]@{
                    ProfilePath = $adUser.ProfilePath
                    HomeDirectory = $adUser.HomeDirectory
                    HomeDrive = $adUser.HomeDrive
                    ScriptPath = $adUser.ScriptPath
                }
            } catch {
            }
        }
    }

    $driveInfo = Get-DriveInfo -Path $localPath

    $findings = New-Object System.Collections.Generic.List[string]
    if (-not $localPathExists) { $findings.Add('Local profile path missing.') }
    if ($regBakExists) { $findings.Add('ProfileList .bak registry key exists (possible temp/backup profile).') }
    if ($regProps -and $regProps.PSObject.Properties.Name -contains 'RefCount' -and $regProps.RefCount -gt 0 -and -not $profile.Loaded) {
        $findings.Add("RefCount is non-zero while profile is not loaded (RefCount=$($regProps.RefCount)).")
    }
    if ($roamingPath -and $roamingPathExists -eq $false) {
        if ($roamingPathError) {
            $findings.Add("Roaming profile path not accessible: $roamingPath (error: $roamingPathError)")
        } else {
            $findings.Add("Roaming profile path not accessible: $roamingPath")
        }
    }
    if ($fileInventory.MissingFiles.Count -gt 0) { $findings.Add('Missing core profile files detected (NTUSER.DAT or UsrClass.dat).') }
    if ($fileInventory.LargeFiles.Count -gt 0) { $findings.Add("Large roaming files found (>= $LargeFileMB MB).") }
    if ($fileInventory.LockedFiles.Count -gt 0) { $findings.Add('Locked file candidates detected (sharing violations or access denied).') }
    if ($fileInventory.LongPaths.Count -gt 0) { $findings.Add('Long paths detected (>= 260 chars) which can break sync.') }
    if ($fileInventory.Errors.Count -gt 0) { $findings.Add('File inventory errors detected (see Inventory Errors section).') }
    if ($fileInventory.RoamingBytes -gt 1GB) { $findings.Add("Roaming size exceeds 1 GB ($([math]::Round($fileInventory.RoamingBytes / 1GB, 2)) GB).") }
    if ($driveInfo -and $driveInfo.FreePercent -ne $null -and $driveInfo.FreePercent -lt 10) {
        $findings.Add("Low free space on $($driveInfo.DeviceId): $($driveInfo.FreePercent)% free.")
    }
    if ($lastSyncFailure -and $lastSyncSuccess -and $lastSyncFailure.TimeCreated -gt $lastSyncSuccess.TimeCreated) {
        $findings.Add('Last roaming sync failure is newer than the last success.')
    }
    if ($userEvents -and ($userEvents | Where-Object { $failureEventIds -contains $_.Id })) {
        $findings.Add('Profile-related failure events detected in logs.')
    }

    $reportProfiles += [pscustomobject]@{
        Account = $account
        Sid = $sid
        LocalPath = $localPath
        LocalPathExists = $localPathExists
        ProfileVersion = $profileVersion
        ProfileLoaded = $profile.Loaded
        LastUseTime = $lastUseTime
        RoamingConfigured = $profile.RoamingConfigured
        RoamingPath = $roamingPath
        RoamingPathExists = $roamingPathExists
        RoamingPathError = $roamingPathError
        Registry = [pscustomobject]@{
            ProfileImagePathRaw = $profileImageRaw
            ProfileImagePathExpanded = $profileImageExpanded
            State = if ($regProps) { $regProps.State } else { $null }
            Flags = if ($regProps) { $regProps.Flags } else { $null }
            RefCount = if ($regProps) { $regProps.RefCount } else { $null }
            CentralProfile = if ($regProps) { $regProps.CentralProfile } else { $null }
            LoadTime = $loadTime
            UnloadTime = $unloadTime
            BakKeyPresent = $regBakExists
        }
        AdProfile = $adInfo
        DriveInfo = $driveInfo
        FileInventory = $fileInventory
        Events = [pscustomobject]@{
            Items = $userEvents
            Summary = $eventSummary
            LastSyncSuccess = $lastSyncSuccess
            LastSyncFailure = $lastSyncFailure
        }
        Logon = $lastLogon
        Findings = $findings
    }
}

$scanEnd = Get-Date

$runSummary = [ordered]@{
    'Hostname' = $env:COMPUTERNAME
    'Domain' = if ($cs) { $cs.Domain } else { $env:USERDOMAIN }
    'DomainRole' = if ($cs) { $cs.DomainRole } else { $null }
    'OS' = if ($os) { "$($os.Caption) $($os.Version) Build $($os.BuildNumber)" } else { $null }
    'LastBoot' = if ($os) { $os.LastBootUpTime } else { $null }
    'PowerShell' = $PSVersionTable.PSVersion.ToString()
    'RunAs' = $identity.Name
    'LogonServer' = $env:LOGONSERVER
    'ScriptVersion' = $scriptVersion
    'ScanStart' = $scanStart
    'ScanEnd' = $scanEnd
    'ProfilesScanned' = $reportProfiles.Count
}

$scanConfig = [ordered]@{
    'Scope' = if ($UserName) { "UserName=$UserName" } else { 'AllUsers' }
    'DaysBack' = $DaysBack
    'LargeFileMB' = $LargeFileMB
    'TopFileCount' = $TopFileCount
    'MaxEvents' = $MaxEvents
}

$systemDiskSummary = $null
if ($systemDriveInfo) {
    $systemDiskSummary = [ordered]@{
        'Device' = $systemDriveInfo.DeviceId
        'FileSystem' = $systemDriveInfo.FileSystem
        'Size' = Convert-BytesToHuman $systemDriveInfo.SizeBytes
        'Free' = Convert-BytesToHuman $systemDriveInfo.FreeBytes
        'FreePercent' = if ($systemDriveInfo.FreePercent -ne $null) { "$($systemDriveInfo.FreePercent)%" } else { $null }
    }
}

$profileDirOrphans = @()
$defaultUsersRoot = Join-Path $env:SystemDrive 'Users'
if (Test-Path -LiteralPath $defaultUsersRoot) {
    $knownPaths = $profiles.LocalPath
    try {
        $profileDirOrphans = Get-ChildItem -LiteralPath $defaultUsersRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $knownPaths -notcontains $_.FullName }
    } catch {
    }
}
function New-ReportHtml {
    param(
        [string]$TemplatePath,
        [string]$CssHref,
        [string]$ReportTitle,
        [object]$RunSummary,
        [object]$ScanConfig,
        [object]$SystemDiskSummary,
        [object[]]$ProfileRegBakKeys,
        [object[]]$ProfileDirOrphans,
        [object[]]$Profiles
    )
    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "Template file not found: $TemplatePath"
    }

    $navSb = New-Object System.Text.StringBuilder
    [void]$navSb.AppendLine('<nav class="nav">')
    [void]$navSb.AppendLine('<div class="nav-group">')
    [void]$navSb.AppendLine('<div class="nav-title">Overview</div>')
    [void]$navSb.AppendLine('<ul class="nav-list">')
    [void]$navSb.AppendLine("<li><a href='#run-summary'>Run Summary</a></li>")
    [void]$navSb.AppendLine("<li><a href='#scan-config'>Scan Configuration</a></li>")
    if ($SystemDiskSummary) { [void]$navSb.AppendLine("<li><a href='#system-disk'>System Disk</a></li>") }
    [void]$navSb.AppendLine("<li><a href='#profilelist-bak'>ProfileList .bak Keys</a></li>")
    [void]$navSb.AppendLine("<li><a href='#orphaned-profiles'>Orphaned Profile Dirs</a></li>")
    [void]$navSb.AppendLine('</ul></div>')

    [void]$navSb.AppendLine('<div class="nav-group">')
    [void]$navSb.AppendLine('<div class="nav-title">Profiles</div>')
    [void]$navSb.AppendLine('<ul class="nav-list">')
    if ($Profiles -and $Profiles.Count -gt 0) {
        foreach ($profile in $Profiles) {
            $profileId = ConvertTo-HtmlId -Text $profile.Sid -Prefix 'profile'
            $profileLabel = if ($profile.Account) { $profile.Account } else { $profile.Sid }
            [void]$navSb.AppendLine("<li><a href='#$profileId'>$(ConvertTo-HtmlSafe $profileLabel)</a></li>")
        }
    } else {
        [void]$navSb.AppendLine('<li class="muted">None detected</li>')
    }
    [void]$navSb.AppendLine('</ul></div>')
    [void]$navSb.AppendLine('</nav>')
    $navHtml = $navSb.ToString()

    $contentSb = New-Object System.Text.StringBuilder

    $runRows = @()
    foreach ($key in $RunSummary.Keys) {
        $val = $RunSummary[$key]
        if ($val -is [DateTime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
        $runRows += [pscustomobject]@{ Name = $key; Value = $val }
    }
    $runBody = ConvertTo-HtmlTable -Rows $runRows -Columns @('Name', 'Value')
    [void]$contentSb.AppendLine("<section id='run-summary' class='section'>")
    [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Run Summary' -BodyHtml $runBody -Open))
    [void]$contentSb.AppendLine('</section>')

    $cfgRows = @()
    foreach ($key in $ScanConfig.Keys) {
        $cfgRows += [pscustomobject]@{ Name = $key; Value = $ScanConfig[$key] }
    }
    $cfgBody = ConvertTo-HtmlTable -Rows $cfgRows -Columns @('Name', 'Value')
    [void]$contentSb.AppendLine("<section id='scan-config' class='section'>")
    [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Scan Configuration' -BodyHtml $cfgBody -Open))
    [void]$contentSb.AppendLine('</section>')

    if ($SystemDiskSummary) {
        $diskRows = @()
        foreach ($key in $SystemDiskSummary.Keys) {
            $diskRows += [pscustomobject]@{ Name = $key; Value = $SystemDiskSummary[$key] }
        }
        $diskBody = ConvertTo-HtmlTable -Rows $diskRows -Columns @('Name', 'Value')
        [void]$contentSb.AppendLine("<section id='system-disk' class='section'>")
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'System Disk' -BodyHtml $diskBody))
        [void]$contentSb.AppendLine('</section>')
    }

    $bakBody = if ($ProfileRegBakKeys -and $ProfileRegBakKeys.Count -gt 0) {
        $bakRows = $ProfileRegBakKeys | ForEach-Object { [pscustomobject]@{ Key = $_.PSChildName } }
        ConvertTo-HtmlTable -Rows $bakRows -Columns @('Key')
    } else {
        "<p class='empty'>None</p>"
    }
    [void]$contentSb.AppendLine("<section id='profilelist-bak' class='section'>")
    [void]$contentSb.AppendLine((New-DetailsBlock -Title 'ProfileList Registry .bak Keys' -BodyHtml $bakBody))
    [void]$contentSb.AppendLine('</section>')

    $orphBody = if ($ProfileDirOrphans -and $ProfileDirOrphans.Count -gt 0) {
        $orphRows = $ProfileDirOrphans | ForEach-Object { [pscustomobject]@{ Path = $_.FullName } }
        ConvertTo-HtmlTable -Rows $orphRows -Columns @('Path')
    } else {
        "<p class='empty'>None</p>"
    }
    [void]$contentSb.AppendLine("<section id='orphaned-profiles' class='section'>")
    [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Orphaned Profile Directories' -BodyHtml $orphBody))
    [void]$contentSb.AppendLine('</section>')

    foreach ($profile in $Profiles) {
        $profileId = ConvertTo-HtmlId -Text $profile.Sid -Prefix 'profile'
        $profileLabel = if ($profile.Account) { $profile.Account } else { $profile.Sid }
        [void]$contentSb.AppendLine("<section id='$profileId' class='section profile'>")
        [void]$contentSb.AppendLine("<details class='detail detail-profile' open><summary>User Profile: $(ConvertTo-HtmlSafe $profileLabel)</summary><div class='detail-body'>")

        $overview = [ordered]@{
            'Account' = $profile.Account
            'SID' = $profile.Sid
            'LocalPath' = $profile.LocalPath
            'LocalPathExists' = $profile.LocalPathExists
            'ProfileVersion' = $profile.ProfileVersion
            'ProfileLoaded' = $profile.ProfileLoaded
            'LastUseTime' = $profile.LastUseTime
            'RoamingConfigured' = $profile.RoamingConfigured
            'RoamingPath' = $profile.RoamingPath
            'RoamingPathExists' = $profile.RoamingPathExists
            'RoamingPathError' = $profile.RoamingPathError
            'RoamingBytes' = Convert-BytesToHuman $profile.FileInventory.RoamingBytes
            'TotalBytes' = Convert-BytesToHuman $profile.FileInventory.TotalBytes
        }
        $overviewRows = @()
        foreach ($key in $overview.Keys) {
            $val = $overview[$key]
            if ($val -is [DateTime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
            $overviewRows += [pscustomobject]@{ Name = $key; Value = $val }
        }
        $overviewBody = ConvertTo-HtmlTable -Rows $overviewRows -Columns @('Name', 'Value')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Profile Overview' -BodyHtml $overviewBody -Open))

        $logonBody = if ($profile.Logon) {
            $logonInfo = [ordered]@{
                'LastLogonTime' = $profile.Logon.TimeCreated
                'LogonServer' = $profile.Logon.LogonServer
                'LogonType' = $profile.Logon.LogonType
                'LogonProcess' = $profile.Logon.LogonProcess
                'AuthPackage' = $profile.Logon.AuthPackage
                'Workstation' = $profile.Logon.Workstation
                'IpAddress' = $profile.Logon.IpAddress
                'IpPort' = $profile.Logon.IpPort
                'TargetDomain' = $profile.Logon.TargetDomainName
                'TargetUser' = $profile.Logon.TargetUserName
            }
            $logonRows = @()
            foreach ($key in $logonInfo.Keys) {
                $val = $logonInfo[$key]
                if ($val -is [DateTime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
                $logonRows += [pscustomobject]@{ Name = $key; Value = $val }
            }
            ConvertTo-HtmlTable -Rows $logonRows -Columns @('Name', 'Value')
        } else {
            "<p class='empty'>No matching logon events found in the selected window.</p>"
        }
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Logon Context (Security Log 4624)' -BodyHtml $logonBody -Open:($null -ne $profile.Logon)))

        $regInfo = $profile.Registry
        $regRows = @()
        $regTable = [ordered]@{
            'ProfileImagePathRaw' = $regInfo.ProfileImagePathRaw
            'ProfileImagePathExpanded' = $regInfo.ProfileImagePathExpanded
            'State' = $regInfo.State
            'Flags' = $regInfo.Flags
            'RefCount' = $regInfo.RefCount
            'CentralProfile' = $regInfo.CentralProfile
            'ProfileLoadTime' = $regInfo.LoadTime
            'ProfileUnloadTime' = $regInfo.UnloadTime
            'BakKeyPresent' = $regInfo.BakKeyPresent
        }
        foreach ($key in $regTable.Keys) {
            $val = $regTable[$key]
            if ($val -is [DateTime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
            $regRows += [pscustomobject]@{ Name = $key; Value = $val }
        }
        $regBody = ConvertTo-HtmlTable -Rows $regRows -Columns @('Name', 'Value')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Registry State (ProfileList)' -BodyHtml $regBody))

        if ($profile.AdProfile) {
            $adRows = @()
            foreach ($key in $profile.AdProfile.Keys) {
                $adRows += [pscustomobject]@{ Name = $key; Value = $profile.AdProfile[$key] }
            }
            $adBody = ConvertTo-HtmlTable -Rows $adRows -Columns @('Name', 'Value')
            [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Active Directory Profile Path' -BodyHtml $adBody))
        }

        if ($profile.DriveInfo) {
            $driveRows = @()
            $driveRows += [pscustomobject]@{ Name = 'DeviceId'; Value = $profile.DriveInfo.DeviceId }
            $driveRows += [pscustomobject]@{ Name = 'FileSystem'; Value = $profile.DriveInfo.FileSystem }
            $driveRows += [pscustomobject]@{ Name = 'Size'; Value = (Convert-BytesToHuman $profile.DriveInfo.SizeBytes) }
            $driveRows += [pscustomobject]@{ Name = 'Free'; Value = (Convert-BytesToHuman $profile.DriveInfo.FreeBytes) }
            $driveRows += [pscustomobject]@{ Name = 'FreePercent'; Value = if ($profile.DriveInfo.FreePercent -ne $null) { "$($profile.DriveInfo.FreePercent)%" } else { '' } }
            $driveBody = ConvertTo-HtmlTable -Rows $driveRows -Columns @('Name', 'Value')
            [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Profile Disk' -BodyHtml $driveBody))
        }

        $findingsBody = if ($profile.Findings -and $profile.Findings.Count -gt 0) {
            $findSb = New-Object System.Text.StringBuilder
            [void]$findSb.AppendLine('<ul>')
            foreach ($finding in $profile.Findings) {
                [void]$findSb.AppendLine("<li>$(ConvertTo-HtmlSafe $finding)</li>")
            }
            [void]$findSb.AppendLine('</ul>')
            $findSb.ToString()
        } else {
            "<p class='empty'>No findings detected.</p>"
        }
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Findings' -BodyHtml $findingsBody -Open))

        $fileSummaryRows = @(
            [pscustomobject]@{ Name = 'TotalFiles'; Value = $profile.FileInventory.TotalFiles },
            [pscustomobject]@{ Name = 'TotalBytes'; Value = Convert-BytesToHuman $profile.FileInventory.TotalBytes },
            [pscustomobject]@{ Name = 'RoamingFiles'; Value = $profile.FileInventory.RoamingFiles },
            [pscustomobject]@{ Name = 'RoamingBytes'; Value = Convert-BytesToHuman $profile.FileInventory.RoamingBytes }
        )
        $fileSummaryBody = ConvertTo-HtmlTable -Rows $fileSummaryRows -Columns @('Name', 'Value')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'File Inventory' -BodyHtml $fileSummaryBody))

        $largeBody = ConvertTo-HtmlTable -Rows $profile.FileInventory.LargeFiles -Columns @('Path', 'Size', 'LastWriteTime')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Large Roaming Files' -BodyHtml $largeBody))

        $lockedBody = ConvertTo-HtmlTable -Rows $profile.FileInventory.LockedFiles -Columns @('Path', 'Size', 'LastWriteTime', 'Reason')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Locked File Candidates' -BodyHtml $lockedBody))

        $longBody = ConvertTo-HtmlTable -Rows $profile.FileInventory.LongPaths -Columns @('Path', 'PathLength', 'SizeBytes')
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Long Paths' -BodyHtml $longBody))

        $missingRows = $null
        if ($profile.FileInventory.MissingFiles -and $profile.FileInventory.MissingFiles.Count -gt 0) {
            $missingRows = $profile.FileInventory.MissingFiles | ForEach-Object { [pscustomobject]@{ Path = $_ } }
        }
        $missingBody = ConvertTo-HtmlTable -Rows $missingRows -Columns @('Path') -EmptyMessage 'None'
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Missing Core Files' -BodyHtml $missingBody))

        if ($profile.FileInventory.Errors -and $profile.FileInventory.Errors.Count -gt 0) {
            $errRows = $profile.FileInventory.Errors | ForEach-Object { [pscustomobject]@{ Error = $_ } }
            $errBody = ConvertTo-HtmlTable -Rows $errRows -Columns @('Error')
            [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Inventory Errors' -BodyHtml $errBody))
        }

        $eventsInfo = $profile.Events
        $syncRows = @()
        if ($eventsInfo) {
            $syncRows += [pscustomobject]@{
                Name = 'LastSyncSuccess'
                Value = if ($eventsInfo.LastSyncSuccess) { $eventsInfo.LastSyncSuccess.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            }
            $syncRows += [pscustomobject]@{
                Name = 'LastSyncFailure'
                Value = if ($eventsInfo.LastSyncFailure) { $eventsInfo.LastSyncFailure.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            }
        }
        $syncBody = ConvertTo-HtmlTable -Rows $syncRows -Columns @('Name', 'Value') -EmptyMessage 'No sync events detected.'
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Roaming Sync Timestamps (Derived from Events)' -BodyHtml $syncBody))

        $eventSummaryBody = ConvertTo-HtmlTable -Rows $eventsInfo.Summary -Columns @('Id', 'Count', 'LastSeen', 'Provider', 'Example') -EmptyMessage 'No profile events in window.'
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Event Summary' -BodyHtml $eventSummaryBody))

        $recentEvents = @()
        if ($eventsInfo.Items) {
            $recentEvents = $eventsInfo.Items | Select-Object -First 50
        }
        $recentBody = ConvertTo-EventsTable -Rows $recentEvents -EmptyMessage 'No profile events in window.'
        [void]$contentSb.AppendLine((New-DetailsBlock -Title 'Recent Events' -BodyHtml $recentBody))

        [void]$contentSb.AppendLine('</div></details></section>')
    }

    $template = Get-Content -LiteralPath $TemplatePath -Raw
    $html = $template.Replace('{{REPORT_TITLE}}', (ConvertTo-HtmlSafe $ReportTitle))
    $html = $html.Replace('{{CSS_HREF}}', $CssHref)
    $html = $html.Replace('{{NAV}}', $navHtml)
    $html = $html.Replace('{{CONTENT}}', $contentSb.ToString())
    $html = $html.Replace('{{GENERATED_AT}}', (ConvertTo-HtmlSafe (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    return $html
}
if (-not (Test-Path -LiteralPath $templatePath)) {
    Write-Error "Template file not found: $templatePath"
    exit 1
}
if (-not (Test-Path -LiteralPath $cssSourcePath)) {
    Write-Error "CSS file not found: $cssSourcePath"
    exit 1
}

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $PWD -ChildPath ("ProfileDoktor_Report_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$OutputDir = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = $PWD.Path
}
if ($OutputDir -and -not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$cssTargetPath = Join-Path -Path $OutputDir -ChildPath $cssFileName
try {
    $scriptRootResolved = (Resolve-Path -LiteralPath $scriptRoot).Path
    $outputDirResolved = (Resolve-Path -LiteralPath $OutputDir).Path
    if ($scriptRootResolved -ne $outputDirResolved) {
        Copy-Item -LiteralPath $cssSourcePath -Destination $cssTargetPath -Force
    }
} catch {
}

$cssHref = $cssFileName
if (-not (Test-Path -LiteralPath $cssTargetPath)) {
    try {
        $cssHref = (New-Object System.Uri($cssSourcePath)).AbsoluteUri
    } catch {
        $cssHref = $cssFileName
    }
}

$html = New-ReportHtml -TemplatePath $templatePath -CssHref $cssHref -ReportTitle $reportTitle -RunSummary $runSummary -ScanConfig $scanConfig -SystemDiskSummary $systemDiskSummary -ProfileRegBakKeys $profileRegBakKeys -ProfileDirOrphans $profileDirOrphans -Profiles $reportProfiles
$html | Out-File -LiteralPath $OutputPath -Encoding UTF8
Write-Host "HTML report written to: $OutputPath"

if (-not $NoPrompt) {
    $response = Read-Host 'Open report in default browser? (Y/N)'
    if ($response -match '^(y|yes)$') {
        Start-Process -FilePath $OutputPath
    }
}
