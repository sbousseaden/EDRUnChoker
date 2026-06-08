#Requires -Version 5.1
<#
.SYNOPSIS
    Reports fileless EDRChoker WMI defense subscription status.
#>
[CmdletBinding()]
param(
    [string]$FilterName = 'EDRChokerDefense_QoSFilter',
    [string]$ConsumerName = 'EDRChokerDefense_QoSConsumer',
    [string]$TimerId = 'EDRChokerDefense_Timer'
)

$WmiNs = 'root\subscription'
$MaxThrottleBps = 1048576

$ExactTargets = @(
    'amsvc', 'cb', 'cbdefense', 'cetasevc', 'cntaosmgr', 'cramtray', 'crsvc',
    'cylancesvc', 'cybereasonav', 'cyserver', 'cyveraservice', 'cyvrfsflt',
    'eiconnector', 'ekrn', 'elastic-agent', 'elastic-endpoint', 'endpointbasecamp',
    'executionpreventionsvc', 'filebeat', 'fortiedr', 'hurukai', 'logprocessorservice',
    'mpdefendercoreservice', 'msmpeng', 'mssense', 'ntrtscan', 'pccntmon', 'qualysagent',
    'sensecncproxy', 'senseir', 'sensendr', 'sensesampleuploader', 'sentinelagent',
    'sentinelagentworker', 'sentinelbrowsernativehost', 'sentinelhelperservice',
    'sentinelservicehost', 'sentinelstaticengine', 'sentinelstaticenginescanner',
    'sfc', 'taniumclient', 'taniumcx', 'taniumdetectengine', 'tmccsf', 'tmlisten',
    'tmbmsrv', 'tmwscsvc', 'traps', 'winlogbeat', 'wscommunicator', 'xagt'
)

$VendorPatterns = @(
    'elastic', 'sentinel', 'cybereason', 'carbonblack', 'carbon\', 'crowdstrike',
    'cylance', 'defender', 'msmpeng', 'mssense', 'windows defender', 'senseir',
    'tanium', 'qualys', 'fortiedr', 'mcafee', 'symantec', 'broadcom', 'trend micro',
    'eset', 'kaspersky', 'bitdefender', 'sophos', 'fireeye', 'mandiant', 'traps',
    'cbdefense', 'cyvera', 'hurukai', 'xagt', 'filebeat', 'winlogbeat', 'elastic-endpoint'
)

function Get-AppBaseName {
    param([string]$Path)
    $p = $Path.Trim().ToLowerInvariant()
    if ($p.EndsWith('.exe')) { $p = $p.Substring(0, $p.Length - 4) }
    $segments = $p -split '[\\/]'
    return $segments[-1]
}

function Test-KnownSecurityTarget {
    param([string]$AppPath)
    if ([string]::IsNullOrWhiteSpace($AppPath)) { return $false }
    $lower = $AppPath.ToLowerInvariant()
    $base = Get-AppBaseName -Path $lower
    foreach ($t in $ExactTargets) {
        if ($base -eq $t -or $base.EndsWith($t)) { return $true }
    }
    foreach ($p in $VendorPatterns) {
        if ($lower.Contains($p)) { return $true }
    }
    return $false
}

function Test-MaliciousQosPolicy {
    param($Policy)
    $appPath = [string]$Policy.AppPathNameMatchCondition
    if ([string]::IsNullOrWhiteSpace($appPath)) { return $false }
    $throttle = [uint64]$Policy.ThrottleRateAction
    if ($throttle -eq 0) { return $false }
    if (Test-KnownSecurityTarget -AppPath $appPath) { return $true }
    if ($throttle -le $MaxThrottleBps) { return $true }
    return $false
}

Write-Host '=== WMI subscription (root\subscription) ===' -ForegroundColor Cyan
Get-WmiObject -Namespace $WmiNs -Class __IntervalTimerInstruction -ErrorAction SilentlyContinue |
    Where-Object { $_.TimerId -eq $TimerId } |
    Format-List TimerId, IntervalBetweenEvents

Get-WmiObject -Namespace $WmiNs -Class __EventFilter -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $filterName } |
    Format-List Name, Query, EventNamespace

Get-WmiObject -Namespace $WmiNs -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $consumerName } |
    Format-List Name, ScriptingEngine, KillTimeout

Get-WmiObject -Namespace $WmiNs -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -match [regex]::Escape($filterName) } |
    Format-List Filter, Consumer

Write-Host '=== Policies matching hardened detection rules ===' -ForegroundColor Cyan
$all = @(Get-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetQosPolicySettingData -ErrorAction SilentlyContinue)
$malicious = @($all | Where-Object { Test-MaliciousQosPolicy -Policy $_ })

Write-Host "Count: $($malicious.Count) / $($all.Count) total QoS policies"
if ($malicious.Count -gt 0) {
    $malicious | Select-Object Name, AppPathNameMatchCondition, ThrottleRateAction, Owner |
        Format-Table -AutoSize
}

Write-Host '=== Recent remediation events (Application / EDRChokerDefense) ===' -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'EDRChokerDefense'
} -MaxEvents 15 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-Table -Wrap -AutoSize
