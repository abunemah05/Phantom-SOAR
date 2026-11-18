<#
.SYNOPSIS
  Wazuh active-response script for Phantom SOAR on Windows agents (PowerShell 5.1, Windows Firewall cmdlets).

.DESCRIPTION
  Reads ONE JSON line from stdin as sent by Wazuh:
    {"version":1,"origin":{...},"command":"add","parameters":{"extra_args":[...],"alert":{...},"program":"..."}}
  Only parameters.extra_args (the API "arguments") are used. Alert contents are untrusted and are never used to build
  a command. Every value is validated strictly; native commands and cmdlets get discrete, typed parameters (no string
  evaluation, no Invoke-Expression).

  Actions (selected by -Action, normally via phantom-<action>.cmd):
    isolate-host / unisolate-host   Windows Firewall default-block both ways except manager + allow-list; reversible
    block-ip IP [HOURS [DIRECTION]] firewall block rule(s); removed automatically after HOURS by a one-shot scheduled task
    unblock-ip IP
    rate-limit IP RATE [HOURS]      NOT SUPPORTED by Windows Firewall: logged and refused (exit 1), nothing is changed
    kill-process NAME [PID]
    quarantine-file PATH [HASH]     moved to C:\ProgramData\phantom-quarantine (SYSTEM/Administrators only), restorable
  Refuses to block/limit the Wazuh manager, loopback, link-local, multicast, this host's addresses and anything in
  <agent dir>\phantom-allowlist.txt. Logs to <agent dir>\active-response\active-responses.log.
  Exit status: 0 done, 1 refused or failed, 2 bad input.

  Dry run without a manager: set $env:PHANTOM_AR_DRY_RUN=1 (logs what would change, changes nothing).
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('isolate-host', 'unisolate-host', 'block-ip', 'unblock-ip', 'rate-limit', 'kill-process', 'quarantine-file', '__expire', 'restore')]
    [string]$Action,
    [string]$Arg1
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$AgentDir      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($env:PHANTOM_AR_AGENT_DIR) { $AgentDir = $env:PHANTOM_AR_AGENT_DIR }
$LogFile       = Join-Path $AgentDir 'active-response\active-responses.log'
$AllowlistFile = Join-Path $AgentDir 'phantom-allowlist.txt'
$OssecConf     = Join-Path $AgentDir 'ossec.conf'
$StateDir      = Join-Path $AgentDir 'phantom-state'
$QuarantineDir = 'C:\ProgramData\phantom-quarantine'
$DryRun        = ($env:PHANTOM_AR_DRY_RUN -eq '1')
$RuleGroup     = 'phantom-soar'
$MaxHours      = 720

class Refused : System.Exception { Refused([string]$m) : base($m) {} }
class BadInput : System.Exception { BadInput([string]$m) : base($m) {} }

function Write-Log([string]$Level, [string]$Message) {
    $clean = ($Message -replace '[^\x20-\x7E]', '?')
    if ($clean.Length -gt 300) { $clean = $clean.Substring(0, 300) }
    $line = '{0} phantom-ar: {1} action={2} msg={3}' -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Level, $Action, $clean
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { [Console]::Error.WriteLine($line) }
}

function Test-DryRun([string]$What) {
    if ($DryRun) { Write-Log 'DRYRUN' "would $What"; return $true }
    return $false
}

# --- validation ------------------------------------------------------------------------
function ConvertTo-StrictIp([string]$Text) {
    if ($Text -notmatch '^[0-9A-Fa-f:.]{2,45}$') { throw [BadInput]::new('not an IP address') }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Text, [ref]$ip)) { throw [BadInput]::new('not an IP address') }
    return $ip
}

function ConvertTo-Hours($Text, [int]$Default) {
    if ($null -eq $Text -or $Text -eq '') { return $Default }
    if ($Text -notmatch '^[0-9]{1,3}$' -or [int]$Text -gt $MaxHours) { throw [BadInput]::new("duration must be a whole number of hours from 0 to $MaxHours") }
    return [int]$Text
}

function Test-InCidr([System.Net.IPAddress]$Ip, [string]$Cidr) {
    $parts = $Cidr.Split('/')
    $net = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$net)) { return $false }
    if ($net.AddressFamily -ne $Ip.AddressFamily) { return $false }
    $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { $net.GetAddressBytes().Count * 8 }
    $a = $Ip.GetAddressBytes(); $b = $net.GetAddressBytes()
    for ($i = 0; $i -lt $a.Count -and $bits -gt 0; $i++) {
        $take = [Math]::Min(8, $bits); $mask = (0xFF -shl (8 - $take)) -band 0xFF
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
        $bits -= $take
    }
    return $true
}

function Get-AllowEntries {
    $entries = @()
    if (Test-Path -LiteralPath $AllowlistFile) {
        foreach ($raw in Get-Content -LiteralPath $AllowlistFile) {
            $e = ($raw -split '#')[0].Trim()
            if ($e -match '^[0-9A-Fa-f:.]{2,45}(/[0-9]{1,3})?$') { $entries += $e }
            elseif ($e) { Write-Log 'WARN' "ignoring invalid allow-list entry: $e" }
        }
    }
    return $entries
}

function Get-ManagerAddresses {
    $names = @()
    if ($env:PHANTOM_AR_MANAGER_IPS) { $names += $env:PHANTOM_AR_MANAGER_IPS.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
    if (Test-Path -LiteralPath $OssecConf) {
        $conf = Get-Content -LiteralPath $OssecConf -Raw
        foreach ($server in [regex]::Matches($conf, '(?s)<server>(.*?)</server>')) {
            foreach ($m in [regex]::Matches($server.Groups[1].Value, '<address>\s*([^<\s]+)\s*</address>')) { $names += $m.Groups[1].Value }
        }
    }
    $found = @()
    foreach ($n in $names) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($n, [ref]$ip)) { $found += $ip.ToString(); continue }
        try { $found += [System.Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.ToString() } } catch { Write-Log 'WARN' "could not resolve manager address $n" }
    }
    return @($found | Select-Object -Unique)
}

function Assert-NotProtectedIp([System.Net.IPAddress]$Ip) {
    $s = $Ip.ToString()
    $bytes = $Ip.GetAddressBytes()
    if ([System.Net.IPAddress]::IsLoopback($Ip) -or $s -eq '0.0.0.0' -or $s -eq '::') { throw [Refused]::new("$s is loopback or unspecified") }
    if ($Ip.AddressFamily -eq 'InterNetwork' -and ($bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254))) { throw [Refused]::new("$s is multicast or link-local") }
    if ($Ip.IsIPv6LinkLocal -or $Ip.IsIPv6Multicast) { throw [Refused]::new("$s is multicast or link-local") }
    if ((Get-ManagerAddresses) -contains $s) { throw [Refused]::new("$s is the Wazuh manager") }
    $own = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress.Split('%')[0] })
    if ($own -contains $s) { throw [Refused]::new("$s is an address of this host") }
    foreach ($entry in Get-AllowEntries) { if (Test-InCidr $Ip $entry) { throw [Refused]::new("$s is in the allow-list ($entry)") } }
}

# --- state -----------------------------------------------------------------------------
function Get-State([string]$Name) {
    $path = Join-Path $StateDir $Name
    if (Test-Path -LiteralPath $path) { try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { } }
    return $null
}
function Set-State([string]$Name, $Value) {
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $Value | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $StateDir $Name) -Encoding UTF8
}

# --- firewall actions ------------------------------------------------------------------
function Get-TaskName([string]$Ip) { return 'phantom-expire-' + ($Ip -replace '[^0-9A-Fa-f]', '_') }
function Get-RuleName([string]$Ip, [string]$Dir) { return "phantom-block-$Ip-$Dir" }

function Remove-BlockRules([string]$Ip) {
    foreach ($dir in 'in', 'out') {
        Get-NetFirewallRule -DisplayName (Get-RuleName $Ip $dir) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    Unregister-ScheduledTask -TaskName (Get-TaskName $Ip) -Confirm:$false -ErrorAction SilentlyContinue
    $state = Get-State 'blocks.json'
    if ($state -and $state.PSObject.Properties[$Ip]) { $state.PSObject.Properties.Remove($Ip); Set-State 'blocks.json' $state }
}

function Invoke-Block([System.Net.IPAddress]$Ip, [int]$Hours, [string]$Direction) {
    Assert-NotProtectedIp $Ip
    $s = $Ip.ToString()
    if (Test-DryRun "block $s $Direction for ${Hours}h") { return "dry run: block $s" }
    Remove-BlockRules $s
    if ($Direction -in 'inbound', 'both') {
        New-NetFirewallRule -DisplayName (Get-RuleName $s 'in') -Group $RuleGroup -Direction Inbound -Action Block -RemoteAddress $s -Profile Any | Out-Null
    }
    if ($Direction -in 'outbound', 'both') {
        New-NetFirewallRule -DisplayName (Get-RuleName $s 'out') -Group $RuleGroup -Direction Outbound -Action Block -RemoteAddress $s -Profile Any | Out-Null
    }
    if ($Hours -gt 0) {
        $expire = (Get-Date).AddHours($Hours)
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arg = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action __expire -Arg1 {1}' -f $PSCommandPath, $s
        $task = New-ScheduledTaskAction -Execute $exe -Argument $arg
        $trigger = New-ScheduledTaskTrigger -Once -At $expire
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName (Get-TaskName $s) -Action $task -Trigger $trigger -Principal $principal -Force | Out-Null
        $state = Get-State 'blocks.json'; if (-not $state) { $state = [pscustomobject]@{} }
        $state | Add-Member -NotePropertyName $s -NotePropertyValue ([DateTimeOffset]$expire).ToUnixTimeSeconds() -Force
        Set-State 'blocks.json' $state
    }
    return "blocked $s $Direction" + $(if ($Hours -gt 0) { " for ${Hours}h" } else { ' until unblocked' })
}

function Invoke-SweepExpired {
    $state = Get-State 'blocks.json'
    if (-not $state) { return }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($p in @($state.PSObject.Properties)) {
        if ([long]$p.Value -le $now) { Remove-BlockRules $p.Name; Write-Log 'INFO' "removed expired block $($p.Name)" }
    }
}

function Invoke-Isolate {
    $managers = Get-ManagerAddresses
    if ($managers.Count -eq 0) { throw [Refused]::new('cannot find the Wazuh manager address in ossec.conf; isolating would cut the agent off') }
    $allowed = @($managers + (Get-AllowEntries) | Select-Object -Unique)
    if (Test-DryRun ('isolate host, still allowing ' + ($allowed -join ','))) { return 'dry run: isolate' }
    if (-not (Get-State 'isolated.json')) {
        $before = Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; In = [string]$_.DefaultInboundAction; Out = [string]$_.DefaultOutboundAction; Enabled = [string]$_.Enabled } }
        Set-State 'isolated.json' ([pscustomobject]@{ since = (Get-Date).ToString('o'); profiles = @($before) })
    }
    Get-NetFirewallRule -Group "$RuleGroup-isolate" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'phantom-isolate-allow-in' -Group "$RuleGroup-isolate" -Direction Inbound -Action Allow -RemoteAddress $allowed -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'phantom-isolate-allow-out' -Group "$RuleGroup-isolate" -Direction Outbound -Action Allow -RemoteAddress $allowed -Profile Any | Out-Null
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    return 'host isolated; still reachable: ' + ($allowed -join ', ')
}

function Invoke-Unisolate {
    if (Test-DryRun 'remove isolation') { return 'dry run: unisolate' }
    Get-NetFirewallRule -Group "$RuleGroup-isolate" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $state = Get-State 'isolated.json'
    if ($state) {
        foreach ($p in $state.profiles) {
            Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.In -DefaultOutboundAction $p.Out
        }
        Remove-Item -LiteralPath (Join-Path $StateDir 'isolated.json') -Force
        return 'host network isolation removed; firewall profiles restored'
    }
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
    return 'host was not isolated by Phantom; set the Windows defaults (inbound block, outbound allow)'
}

# --- processes and files ---------------------------------------------------------------
$ProtectedProcesses = @('system', 'idle', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'ossec-agent', 'wazuh-agent', 'powershell', 'dwm', 'explorer')

function Invoke-Kill([string]$Name, [string]$PidText) {
    $leaf = ($Name -replace '/', '\').Split('\')[-1] -replace '\.exe$', ''
    if ($leaf -notmatch '^[A-Za-z0-9._+@ -]{1,128}$') { throw [BadInput]::new('invalid process name') }
    if ($ProtectedProcesses -contains $leaf.ToLower()) { throw [Refused]::new("$leaf is a protected process") }
    if ($PidText) {
        if ($PidText -notmatch '^[0-9]{1,8}$' -or [int]$PidText -lt 5) { throw [BadInput]::new('invalid pid') }
        $procs = @(Get-Process -Id ([int]$PidText) -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) { throw [Refused]::new("pid $PidText is not running") }
        if ($procs[0].ProcessName -ne $leaf) { throw [Refused]::new("pid $PidText is '$($procs[0].ProcessName)', not '$leaf'; refusing (pid may have been reused)") }
    } else {
        $procs = @(Get-Process -Name $leaf -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) { throw [Refused]::new("no running process named '$leaf'") }
        if ($procs.Count -gt 10) { throw [Refused]::new("$($procs.Count) processes match '$leaf'; refusing to kill more than 10") }
    }
    if (Test-DryRun "stop $($procs.Count) process(es) named $leaf") { return 'dry run: kill' }
    $procs | Stop-Process -Force
    return "killed $leaf pid(s) " + (($procs | ForEach-Object { $_.Id }) -join ',')
}

function Invoke-Quarantine([string]$Path, [string]$Hash) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains([char]0) -or $Path.Length -gt 1024 -or $Path -match '(^|\\)\.\.(\\|$)') { throw [BadInput]::new('path must be an absolute drive path without ..') }
    $Path = [System.IO.Path]::GetFullPath($Path)
    foreach ($prefix in "$env:SystemRoot\", 'C:\Program Files\', "$AgentDir\", 'C:\ProgramData\phantom-quarantine\') {
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [Refused]::new("$Path is in a protected location") }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { throw [Refused]::new("$Path is not an existing file") }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw [Refused]::new("$Path is a link (links are not followed)") }
    $sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    if ($Hash) {
        if ($Hash -notmatch '^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$') { throw [BadInput]::new('invalid hash') }
        $alg = @{ 32 = 'MD5'; 40 = 'SHA1'; 64 = 'SHA256' }[$Hash.Length]
        if ((Get-FileHash -LiteralPath $Path -Algorithm $alg).Hash -ne $Hash.ToUpper()) { throw [Refused]::new('file hash does not match the expected hash') }
    }
    $qid = '{0}-{1}' -f [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $sha.Substring(0, 16)
    if (Test-DryRun "quarantine $Path as $qid") { return 'dry run: quarantine' }
    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
        & icacls.exe $QuarantineDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    $meta = [pscustomobject]@{ original_path = $Path; sha256 = $sha; quarantined_at = (Get-Date).ToString('o') }
    Move-Item -LiteralPath $Path -Destination (Join-Path $QuarantineDir $qid) -Force
    $meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $QuarantineDir "$qid.json") -Encoding UTF8
    return "quarantined $Path as $qid (restore: move C:\ProgramData\phantom-quarantine\$qid back to the original path)"
}

# --- main ------------------------------------------------------------------------------
try {
    if ($Action -eq '__expire') {  # run by the one-shot scheduled task
        Remove-BlockRules (ConvertTo-StrictIp $Arg1).ToString()
        Write-Log 'INFO' "block expired for $Arg1"
        exit 0
    }
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line) -or $line.Length -gt 1000000) { throw [BadInput]::new('stdin is empty or too large') }
    try { $msg = $line | ConvertFrom-Json } catch { throw [BadInput]::new('stdin is not valid JSON') }
    if ($msg.command -ne 'add') { Write-Log 'INFO' "ignored non-add message ($($msg.command))"; exit 0 }
    $extra = @()
    if ($msg.parameters -and $msg.parameters.PSObject.Properties['extra_args'] -and $msg.parameters.extra_args) { $extra = @($msg.parameters.extra_args) }
    if ($extra.Count -gt 8) { throw [BadInput]::new('too many arguments') }
    foreach ($e in $extra) { if ($e -isnot [string] -or $e.Length -gt 4096 -or $e -match '[\x00\r\n]') { throw [BadInput]::new('extra_args must be single-line strings') } }
    function Arg([int]$i) { if ($extra.Count -gt $i) { return [string]$extra[$i] } else { return $null } }
    Invoke-SweepExpired

    switch ($Action) {
        'isolate-host'    { $r = Invoke-Isolate }
        'unisolate-host'  { $r = Invoke-Unisolate }
        'block-ip' {
            if ($extra.Count -lt 1 -or $extra.Count -gt 3) { throw [BadInput]::new('block-ip takes 1-3 arguments') }
            $dir = if (Arg 2) { Arg 2 } else { 'inbound' }
            if ($dir -notin 'inbound', 'outbound', 'both') { throw [BadInput]::new('direction must be inbound, outbound or both') }
            $r = Invoke-Block (ConvertTo-StrictIp (Arg 0)) (ConvertTo-Hours (Arg 1) 24) $dir
        }
        'unblock-ip' {
            if ($extra.Count -ne 1) { throw [BadInput]::new('unblock-ip takes 1 argument') }
            $ip = (ConvertTo-StrictIp (Arg 0)).ToString()
            if (-not (Test-DryRun "unblock $ip")) { Remove-BlockRules $ip }
            $r = "unblocked $ip"
        }
        'rate-limit'      { throw [Refused]::new('rate limiting is not supported on Windows (Windows Firewall cannot rate-limit); nothing was changed') }
        'kill-process' {
            if ($extra.Count -lt 1 -or $extra.Count -gt 2) { throw [BadInput]::new('kill-process takes 1-2 arguments') }
            $r = Invoke-Kill (Arg 0) (Arg 1)
        }
        'quarantine-file' {
            if ($extra.Count -lt 1 -or $extra.Count -gt 2) { throw [BadInput]::new('quarantine-file takes 1-2 arguments') }
            $r = Invoke-Quarantine (Arg 0) (Arg 1)
        }
        default           { throw [BadInput]::new("unknown action $Action") }
    }
    Write-Log 'INFO' "$r result=ok"
    exit 0
}
catch [BadInput] { Write-Log 'ERROR' "rejected input: $($_.Exception.Message) result=bad-input"; exit 2 }
catch [Refused]  { Write-Log 'WARN' "refused: $($_.Exception.Message) result=refused"; exit 1 }
catch            { Write-Log 'ERROR' "failed: $($_.Exception.GetType().Name): $($_.Exception.Message) result=failed"; exit 1 }
