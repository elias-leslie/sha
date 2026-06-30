[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\SHA",
  [string]$ConfigPath = "$env:ProgramData\SHA\agent-config.json",
  [string]$TaskName = "SHA Agent",
  [switch]$SkipTask
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'sha-agent.exe'
if (-not (Test-Path $source)) {
  throw "sha-agent.exe must be next to this installer"
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath -Parent) | Out-Null
$binaryPath = Join-Path $InstallDir 'sha-agent.exe'
Copy-Item -Force $source $binaryPath

if (-not (Test-Path $ConfigPath)) {
  @'
{
  "control_plane_url": "https://sha.example.test",
  "api_token": "replace-with-SHA_AGENT_API_TOKEN",
  "profile_id": "windows-agent",
  "agent_version": "sha-go-agent-v0.1.0",
  "windows_firewall_rollback_path": "C:\\ProgramData\\SHA\\firewall-profiles-rollback.json"
}
'@ | Set-Content -Encoding UTF8 -Path $ConfigPath
}

if (-not $SkipTask) {
  $action = New-ScheduledTaskAction -Execute $binaryPath -Argument "-config `"$ConfigPath`" -loop"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
}

Write-Host "installed sha-agent binary=$binaryPath config=$ConfigPath task=$TaskName"
