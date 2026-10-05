<#
.SYNOPSIS
    Privileged Login Detector — reads Event ID 4672 (special/admin
    privileges assigned at logon) to identify privileged sign-ins.

.DESCRIPTION
    Pulls 4672 events in the lookback window and reports the account that
    received elevated privileges at logon, correlating the logon time so
    it can be cross-referenced against Get-SuccessfulLogins.ps1 output.

.PARAMETER Hours
    How many hours back to search. Defaults to 24.

.EXAMPLE
    .\Get-PrivilegedLogins.ps1 -Hours 24
#>

[CmdletBinding()]
param(
    [int]$Hours = 24
)

$startTime = (Get-Date).AddHours(-$Hours)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4672
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Output "No privileged logon events (4672) found in the last $Hours hour(s)."
    return
}

$results = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated     = $e.TimeCreated
        Account         = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        Domain          = ($data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
        PrivilegesGranted = ($data | Where-Object { $_.Name -eq 'PrivilegeList' }).'#text'
    }
}

$results | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
