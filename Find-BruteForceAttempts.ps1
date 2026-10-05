<#
.SYNOPSIS
    Brute-Force Detector — flags accounts/source IPs with repeated failed
    logins (Event ID 4625) within a short rolling window.

.DESCRIPTION
    Groups 4625 events by TargetUser + source IP and flags any group whose
    count exceeds -Threshold within -WindowMinutes of each other. This is a
    simple clustering pass, not a replacement for a real SIEM correlation
    rule, but demonstrates the detection logic end to end.

.PARAMETER Hours
    Lookback window to pull events from. Defaults to 24.

.PARAMETER Threshold
    Minimum number of failures in the rolling window to flag. Defaults to 5.

.PARAMETER WindowMinutes
    Size of the rolling window used to cluster attempts. Defaults to 10.

.EXAMPLE
    .\Find-BruteForceAttempts.ps1 -Hours 12 -Threshold 5 -WindowMinutes 10
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$Threshold = 5,
    [int]$WindowMinutes = 10
)

$startTime = (Get-Date).AddHours(-$Hours)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Output "No failed logon events found in the last $Hours hour(s)."
    return
}

$parsed = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        TargetUser  = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        SourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    }
}

$flagged = @()

foreach ($group in ($parsed | Group-Object TargetUser, SourceIP)) {
    $sorted = $group.Group | Sort-Object TimeCreated
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $windowEnd = $sorted[$i].TimeCreated.AddMinutes($WindowMinutes)
        $inWindow  = $sorted | Where-Object {
            $_.TimeCreated -ge $sorted[$i].TimeCreated -and $_.TimeCreated -le $windowEnd
        }
        if ($inWindow.Count -ge $Threshold) {
            $flagged += [PSCustomObject]@{
                TargetUser     = $sorted[$i].TargetUser
                SourceIP       = $sorted[$i].SourceIP
                AttemptsInWindow = $inWindow.Count
                WindowStart    = $sorted[$i].TimeCreated
                WindowMinutes  = $WindowMinutes
            }
            break
        }
    }
}

if ($flagged) {
    Write-Output "Possible brute-force activity detected:"
    $flagged | Sort-Object AttemptsInWindow -Descending | Format-Table -AutoSize
} else {
    Write-Output "No accounts/IPs exceeded $Threshold failed attempts within a $WindowMinutes-minute window."
}
