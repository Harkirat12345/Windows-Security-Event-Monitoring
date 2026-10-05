<#
.SYNOPSIS
    Successful Login Monitor — reads Event ID 4624 (successful logon) and
    shows who logged in, when, and from where.

.DESCRIPTION
    Pulls 4624 events in the lookback window, decodes the logon type
    (interactive, network, RDP, service, etc.) into a readable label, and
    reports the account, source, and logon type.

.PARAMETER Hours
    How many hours back to search. Defaults to 24.

.EXAMPLE
    .\Get-SuccessfulLogins.ps1 -Hours 8
#>

[CmdletBinding()]
param(
    [int]$Hours = 24
)

$logonTypeMap = @{
    '2'  = 'Interactive'
    '3'  = 'Network'
    '4'  = 'Batch'
    '5'  = 'Service'
    '7'  = 'Unlock'
    '8'  = 'NetworkCleartext'
    '9'  = 'NewCredentials'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive'
}

$startTime = (Get-Date).AddHours(-$Hours)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Output "No successful logon events (4624) found in the last $Hours hour(s)."
    return
}

$results = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = $xml.Event.EventData.Data
    $type = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Account     = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        SourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        LogonType   = if ($logonTypeMap.ContainsKey($type)) { $logonTypeMap[$type] } else { "Type $type" }
    }
}

$results | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
