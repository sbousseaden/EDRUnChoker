#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a fileless permanent WMI subscription against EDRChoker QoS policies.
.DESCRIPTION
    Timer-based subscription in root\subscription (no files on disk). Embedded VBScript
    enumerates QoS policies with WbemContext PolicyStore (ActiveStore + GPO:localhost);
    plain ExecQuery misses ActiveStore policies created by New-NetQosPolicy / PowerShell.
#>
[CmdletBinding()]
param(
    [string]$FilterName = 'EDRChokerDefense_QoSFilter',
    [string]$ConsumerName = 'EDRChokerDefense_QoSConsumer',
    [string]$TimerId = 'EDRChokerDefense_Timer',
    [int]$PollIntervalSeconds = 5
)

$ErrorActionPreference = 'Stop'
$WmiNs = 'root\subscription'
$pollIntervalMs = $PollIntervalSeconds * 1000
$LogSource = 'EDRChokerDefense'
$LogName = 'Application'

function Register-DefenseEventSource {
    if (-not [System.Diagnostics.EventLog]::SourceExists($LogSource)) {
        New-EventLog -LogName $LogName -Source $LogSource -ErrorAction Stop
    }
}

function Write-DefenseInstallLog {
    param([string]$Message)
    Write-EventLog -LogName $LogName -Source $LogSource -EventId 1000 -EntryType Information -Message $Message
}

function Get-LocalAdministratorsCreatorSid {
    $sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $bytes = New-Object byte[] ($sid.BinaryLength)
    $sid.GetBinaryForm($bytes, 0)
    return $bytes
}

function New-WmiSubscriptionObject {
    param(
        [Parameter(Mandatory)]
        [string]$Component,
        [Parameter(Mandatory)]
        [string]$ClassName,
        [Parameter(Mandatory)]
        [hashtable]$Properties
    )

    $scope = New-Object System.Management.ManagementScope("\\.\$WmiNs")
    $scope.Options.EnablePrivileges = $true
    $scope.Connect()

    $mgmtClass = New-Object System.Management.ManagementClass(
        $scope,
        (New-Object System.Management.ManagementPath($ClassName)),
        $null
    )
    $instance = $mgmtClass.CreateInstance()

    foreach ($key in $Properties.Keys) {
        $instance.SetPropertyValue($key, $Properties[$key])
    }

    try {
        $instance.Put() | Out-Null
        return $instance
    }
    catch {
        $message = $_.Exception.Message
        if ($_.Exception.InnerException) {
            $message = $_.Exception.InnerException.Message
        }
        $hresult = '0x{0:X8}' -f $_.Exception.HResult
        throw "Failed to create WMI $Component ($ClassName). $message (HRESULT $hresult)"
    }
}

if (Get-WmiObject -Namespace $WmiNs -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue) {
    throw "Subscription '$FilterName' already exists. Run Uninstall-EdrChokerWmiDefense.ps1 first."
}

$creatorSid = Get-LocalAdministratorsCreatorSid
$wql = "SELECT * FROM __TimerEvent WHERE TimerID = '$TimerId'"

$scriptText = @'
On Error Resume Next

Const MAX_THROTTLE_BPS = 1048576

Sub WriteDefenseLog(eventId, entryType, message)
    Dim proc, pid, cmd, safe
    safe = message
    safe = Replace(safe, "'", "''")
    safe = Replace(safe, """", "'")
    cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Write-EventLog -LogName Application -Source EDRChokerDefense -EventId " & eventId & " -EntryType " & entryType & " -Message '" & safe & "' -ErrorAction SilentlyContinue"""
    Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    proc.Create cmd, Null, Null, pid
End Sub

Function GetPolicyAppPath(pol)
    Dim p
    p = pol.AppPathNameMatchCondition
    If Len(Trim(p)) = 0 Then p = pol.AppPathName
    GetPolicyAppPath = p
End Function

Function GetPolicyThrottle(pol)
    Dim t
    t = GetNumericThrottle(pol.ThrottleRateAction)
    If t <= 0 Then t = GetNumericThrottle(pol.ThrottleRate)
    GetPolicyThrottle = t
End Function

Sub RemoveMaliciousPolicy(pol, storeName)
    Dim appPath, throttle, policyName, instanceId, tier, msg
    appPath = GetPolicyAppPath(pol)
    throttle = GetPolicyThrottle(pol)
    policyName = pol.Name
    instanceId = pol.InstanceID
    If MatchesKnownSecurityTarget(appPath) Then
        tier = "tier1-known-edr"
    Else
        tier = "tier2-aggressive-throttle"
    End If
    On Error Resume Next
    pol.Delete_
    If Err.Number <> 0 Then
        Err.Clear
        DeletePolicyViaPowerShell policyName, storeName
    End If
    If Err.Number = 0 Then
        msg = "action=remediate qos_policy=" & policyName & " target=" & appPath & " throttle_bps=" & throttle & " tier=" & tier & " store=" & storeName & " instance_id=" & instanceId
        WriteDefenseLog 1002, "Warning", msg
    Else
        msg = "action=remediate_failed qos_policy=" & policyName & " target=" & appPath & " store=" & storeName & " error=" & Err.Description
        WriteDefenseLog 1003, "Error", msg
        Err.Clear
    End If
    On Error GoTo 0
End Sub

Sub DeletePolicyViaPowerShell(policyName, storeName)
    Dim proc, pid, cmd, safeName, safeStore
    safeName = Replace(policyName, "'", "''")
    safeStore = Replace(storeName, "'", "''")
    cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Remove-NetQosPolicy -Name '" & safeName & "' -PolicyStore '" & safeStore & "' -Confirm:$false -ErrorAction SilentlyContinue"""
    Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    proc.Create cmd, Null, Null, pid
End Sub

Function GetNumericThrottle(val)
    If IsNull(val) Or IsEmpty(val) Then
        GetNumericThrottle = 0
        Exit Function
    End If
    If Len(CStr(val)) = 0 Then
        GetNumericThrottle = 0
        Exit Function
    End If
    On Error Resume Next
    GetNumericThrottle = CDbl(val)
    If Err.Number <> 0 Then GetNumericThrottle = 0
    On Error GoTo 0
End Function

Function GetBaseName(path)
    Dim p, i, c
    p = LCase(Trim(path))
    If Len(p) = 0 Then
        GetBaseName = ""
        Exit Function
    End If
    If Right(p, 4) = ".exe" Then p = Left(p, Len(p) - 4)
    i = Len(p)
    Do While i > 0
        c = Mid(p, i, 1)
        If c = "\" Or c = "/" Then
            GetBaseName = Mid(p, i + 1)
            Exit Function
        End If
        i = i - 1
    Loop
    GetBaseName = p
End Function

Function MatchesExactTarget(base)
    Dim t, i
    Dim targets
    targets = Array( _
        "amsvc", "cb", "cbdefense", "cetasevc", "cntaosmgr", "cramtray", "crsvc", _
        "cylancesvc", "cybereasonav", "cyserver", "cyveraservice", "cyvrfsflt", _
        "eiconnector", "ekrn", "elastic-agent", "elastic-defend", "elastic-endpoint", "endpointbasecamp", _
        "executionpreventionsvc", "filebeat", "fortiedr", "hurukai", "logprocessorservice", _
        "mpdefendercoreservice", "msmpeng", "mssense", "ntrtscan", "pccntmon", "qualysagent", _
        "sensecncproxy", "senseir", "sensendr", "sensesampleuploader", "sentinelagent", _
        "sentinelagentworker", "sentinelbrowsernativehost", "sentinelhelperservice", _
        "sentinelservicehost", "sentinelstaticengine", "sentinelstaticenginescanner", _
        "sfc", "taniumclient", "taniumcx", "taniumdetectengine", "tmccsf", "tmlisten", _
        "tmbmsrv", "tmwscsvc", "traps", "winlogbeat", "wscommunicator", "xagt" _
    )
    For i = 0 To UBound(targets)
        t = targets(i)
        If base = t Then
            MatchesExactTarget = True
            Exit Function
        End If
        If Len(base) >= Len(t) Then
            If Right(base, Len(t)) = t Then
                MatchesExactTarget = True
                Exit Function
            End If
        End If
    Next
    MatchesExactTarget = False
End Function

Function MatchesVendorPattern(pathLower)
    Dim p, i
    Dim patterns
    patterns = Array( _
        "elastic", "sentinel", "cybereason", "carbonblack", "carbon\", "crowdstrike", _
        "cylance", "defender", "msmpeng", "mssense", "windows defender", "senseir", _
        "tanium", "qualys", "fortiedr", "mcafee", "symantec", "broadcom", "trend micro", _
        "eset", "kaspersky", "bitdefender", "sophos", "fireeye", "mandiant", "traps", _
        "cbdefense", "cyvera", "hurukai", "xagt", "filebeat", "winlogbeat", "elastic-endpoint" _
    )
    For i = 0 To UBound(patterns)
        p = patterns(i)
        If InStr(1, pathLower, p, 1) > 0 Then
            MatchesVendorPattern = True
            Exit Function
        End If
    Next
    MatchesVendorPattern = False
End Function

Function MatchesKnownSecurityTarget(appPath)
    Dim pathLower, baseName
    pathLower = LCase(Trim(appPath))
    If Len(pathLower) = 0 Then
        MatchesKnownSecurityTarget = False
        Exit Function
    End If
    baseName = GetBaseName(pathLower)
    If MatchesExactTarget(baseName) Then
        MatchesKnownSecurityTarget = True
        Exit Function
    End If
    MatchesKnownSecurityTarget = MatchesVendorPattern(pathLower)
End Function

Function IsMaliciousPolicy(pol)
    Dim appPath, throttle
    IsMaliciousPolicy = False
    appPath = GetPolicyAppPath(pol)
    throttle = GetPolicyThrottle(pol)

    If Len(Trim(appPath)) = 0 Then Exit Function
    If throttle <= 0 Then Exit Function

    If MatchesKnownSecurityTarget(appPath) Then
        IsMaliciousPolicy = True
        Exit Function
    End If

    If throttle <= MAX_THROTTLE_BPS Then
        IsMaliciousPolicy = True
    End If
End Function

Function GetPoliciesForStore(storeName)
    Dim qosSvc, ctx
    Set qosSvc = GetObject("winmgmts:\\.\root\standardcimv2")
    Set ctx = CreateObject("WbemScripting.SWbemNamedValueSet")
    ctx.Add "PolicyStore", storeName
    Set GetPoliciesForStore = qosSvc.ExecQuery("SELECT * FROM MSFT_NetQosPolicySettingData", "WQL", , ctx)
End Function

Sub RunRemediation
    Dim stores, i, store, policies, pol
    stores = Array("ActiveStore", "GPO:localhost")
    For i = 0 To UBound(stores)
        store = stores(i)
        Set policies = GetPoliciesForStore(store)
        For Each pol In policies
            If IsMaliciousPolicy(pol) Then RemoveMaliciousPolicy pol, store
        Next
    Next
End Sub

RunRemediation
'@

$null = New-WmiSubscriptionObject -Component 'IntervalTimerInstruction' -ClassName __IntervalTimerInstruction -Properties @{
    TimerId               = $TimerId
    IntervalBetweenEvents = $pollIntervalMs
    SkipIfPassed          = $false
}

$filter = New-WmiSubscriptionObject -Component 'EventFilter' -ClassName __EventFilter -Properties @{
    Name           = $FilterName
    EventNamespace = $WmiNs
    QueryLanguage  = 'WQL'
    Query          = $wql
    CreatorSID     = $creatorSid
}

$consumer = New-WmiSubscriptionObject -Component 'ActiveScriptEventConsumer' -ClassName ActiveScriptEventConsumer -Properties @{
    Name            = $ConsumerName
    ScriptingEngine = 'VBScript'
    ScriptText      = $scriptText
    KillTimeout     = 60000
    CreatorSID      = $creatorSid
}

$null = New-WmiSubscriptionObject -Component 'FilterToConsumerBinding' -ClassName __FilterToConsumerBinding -Properties @{
    Filter     = $filter
    Consumer   = $consumer
    CreatorSID = $creatorSid
}

Register-DefenseEventSource
Write-DefenseInstallLog "action=install subscription=EDRChokerDefense poll_interval_seconds=$PollIntervalSeconds log_source=$LogSource"

Write-Host 'Fileless WMI subscription installed (hardened detection, polls every' $PollIntervalSeconds 's).'
Write-Host "  Timer         : $TimerId (${pollIntervalMs}ms)"
Write-Host "  Filter        : $FilterName"
Write-Host "  Consumer      : $ConsumerName (ActiveScriptEventConsumer / VBScript)"
Write-Host '  Detection     : WbemContext PolicyStore ActiveStore + GPO:localhost'
Write-Host "  Event log     : $LogName / Source $LogSource (ID 1002 = remediate, 1003 = failed)"
Write-Host ''
Write-Host 'Reinstall required when upgrading embedded remediation logic.'
Write-Host 'Verify: .\Get-EdrChokerDefenseStatus.ps1'
Write-Host "SOC query  : Get-WinEvent -FilterHashtable @{ LogName='$LogName'; ProviderName='$LogSource' } -MaxEvents 20"
