<#
.SYNOPSIS
    Failed Login Detector — reads Event ID 4625 (failed logon) from the
    Windows Security log and reports each attempt.

.DESCRIPTION
    Pulls all 4625 events within a lookback window from the Security log,
    extracts the target account, source workstation/IP, and failure reason
    code, and prints a sorted table (most recent first).

.PARAMETER Hours
    How many hours back to search. Defaults to 24.

.EXAMPLE
    .\Get-FailedLogins.ps1 -Hours 48
#>

[CmdletBinding()]
param(
    [int]$Hours = 24
)

$startTime = (Get-Date).AddHours(-$Hours)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Output "No failed logon events (4625) found in the last $Hours hour(s)."
    return
}

$results = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $e.TimeCreated
        TargetUser    = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        SourceAddress = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        WorkstationName = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
        FailureReason = ($data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
        Status        = ($data | Where-Object { $_.Name -eq 'Status' }).'#text'
    }
}

$results | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
