# Install the Phantom SOAR active-response scripts on a Windows Wazuh agent. Run in an elevated PowerShell
# from this directory.
$ErrorActionPreference = 'Stop'
$agent = 'C:\Program Files (x86)\ossec-agent'
$bin = Join-Path $agent 'active-response\bin'
if (-not (Test-Path $bin)) { throw "$bin not found: is the Wazuh agent installed?" }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'phantom-ar.ps1') -Destination $bin -Force
foreach ($name in 'isolate-host', 'unisolate-host', 'block-ip', 'unblock-ip', 'rate-limit', 'kill-process', 'quarantine-file') {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'phantom-ar.cmd') -Destination (Join-Path $bin "phantom-$name.cmd") -Force
}
$allow = Join-Path $agent 'phantom-allowlist.txt'
if (-not (Test-Path $allow)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\phantom-allowlist.example.txt') -Destination $allow
    Write-Host "Created $allow from the example: EDIT IT before enabling live response."
}
Write-Host 'Installed. Add this agent id to the wazuh_windows_agent_ids setting in Phantom SOAR so commands get the .cmd suffix.'
