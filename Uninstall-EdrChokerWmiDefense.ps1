#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the fileless EDRChoker WMI defense subscription.
#>
[CmdletBinding()]
param(
    [string]$FilterName = 'EDRChokerDefense_QoSFilter',
    [string]$ConsumerName = 'EDRChokerDefense_QoSConsumer',
    [string]$TimerId = 'EDRChokerDefense_Timer'
)

$ErrorActionPreference = 'Stop'
$WmiNs = 'root\subscription'
$LogSource = 'EDRChokerDefense'
$LogName = 'Application'

function Remove-WmiSubscriptionComponent {
    param(
        [string]$Class,
        [string]$Filter
    )

    $instance = Get-WmiObject -Namespace $WmiNs -Class $Class -Filter $Filter -ErrorAction SilentlyContinue
    if ($instance) {
        $instance | Remove-WmiObject
        Write-Host "Removed $Class ($Filter)"
    }
}

$bindings = @(Get-WmiObject -Namespace $WmiNs -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -match [regex]::Escape($FilterName) -or $_.Consumer -match [regex]::Escape($ConsumerName) })

foreach ($binding in $bindings) {
    $binding | Remove-WmiObject
    Write-Host 'Removed __FilterToConsumerBinding'
}

Remove-WmiSubscriptionComponent -Class ActiveScriptEventConsumer -Filter "Name='$ConsumerName'"
Remove-WmiSubscriptionComponent -Class __EventFilter -Filter "Name='$FilterName'"
Remove-WmiSubscriptionComponent -Class __IntervalTimerInstruction -Filter "TimerId='$TimerId'"

if ([System.Diagnostics.EventLog]::SourceExists($LogSource)) {
    try {
        Write-EventLog -LogName $LogName -Source $LogSource -EventId 1001 -EntryType Information -Message 'action=uninstall subscription=EDRChokerDefense'
    }
    catch {
        Write-Warning "Could not write uninstall event: $($_.Exception.Message)"
    }
}

Write-Host 'Uninstall complete. WMI subscription removed; past Application log events retained for SOC.'
