[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\SHA",
  [string]$ConfigPath = "$env:ProgramData\SHA\agent-config.json",
  [string]$TaskName = "SHA Agent",
  [ValidateSet('install', 'repair', 'uninstall')][string]$Operation = 'install',
  [string]$ControlPlaneUrl,
  [string]$ProfileId = 'generic',
  [string]$EnrollmentToken,
  [string]$EnrollmentTokenFile,
  [switch]$EnrollmentTokenStdin,
  [string]$CaBundle,
  [string]$BootstrapManifest,
  [string]$TrustPolicy,
  [switch]$AllowInsecureLoopback,
  [switch]$PurgeState,
  [Alias('SkipTask')][switch]$SkipService,
  [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsElevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-DedicatedDirectory {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
    throw "$Label must be an absolute local path"
  }
  if ($Path.StartsWith('\\') -or $Path -match '[\x00-\x1f<>"|?*]') {
    throw "$Label must not use a UNC path or contain invalid path characters"
  }
  if (@($Path -split '[\\/]' | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -ne 0) {
    throw "$Label must be normalized and must not contain dot path components"
  }
  $resolved = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
  $root = [IO.Path]::GetPathRoot($resolved).TrimEnd([char[]]'\/')
  if ([string]::IsNullOrWhiteSpace($resolved) -or $resolved -eq $root) {
    throw "$Label must not be a filesystem root"
  }
  if (-not ([IO.Path]::GetFileName($resolved) -ieq 'SHA')) {
    throw "$Label must be a dedicated directory named SHA"
  }
  return $resolved
}

function Assert-NoReparsePoint {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $current = $Path
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -Force -LiteralPath $current
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label contains a reparse point: $current"
      }
    }
    $parent = [IO.Path]::GetDirectoryName($current)
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
      break
    }
    $current = $parent
  }
}

function Assert-NoNestedReparsePoint {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $pending = [Collections.Generic.Stack[string]]::new()
  $pending.Push($Path)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($item in @(Get-ChildItem -Force -LiteralPath $directory)) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label contains a nested reparse point: $($item.FullName)"
      }
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
}

function Get-OwnerSid {
  param([Parameter(Mandatory = $true)][string]$Path)

  $acl = Get-Acl -LiteralPath $Path
  return ([Security.Principal.NTAccount]::new($acl.Owner)).Translate(
    [Security.Principal.SecurityIdentifier]
  ).Value
}

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trustedSids = @('S-1-5-18', 'S-1-5-32-544', $currentSid)

function Assert-TrustedExistingPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet('Container', 'Leaf')][string]$PathType,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }
  if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
    throw "$Label has the wrong filesystem type: $Path"
  }
  Assert-NoReparsePoint -Path $Path -Label $Label
  $ownerSid = Get-OwnerSid -Path $Path
  if ($trustedSids -notcontains $ownerSid) {
    throw "$Label has an untrusted owner and will not be reused: $Path"
  }

  $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::FullControl -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
  $acl = Get-Acl -LiteralPath $Path
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  foreach ($rule in $rules) {
    if (
      $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $trustedSids -notcontains $rule.IdentityReference.Value -and
      (($rule.FileSystemRights -band $writeMask) -ne 0)
    ) {
      throw "$Label grants write-equivalent access to an untrusted principal and will not be reused: $Path"
    }
  }
}

function Assert-ConfidentialExistingFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )
  Assert-TrustedExistingPath -Path $Path -PathType Leaf -Label $Label
  $readMask = [Security.AccessControl.FileSystemRights]::Read -bor
    [Security.AccessControl.FileSystemRights]::ReadData -bor
    [Security.AccessControl.FileSystemRights]::ReadAttributes -bor
    [Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::FullControl
  $acl = Get-Acl -LiteralPath $Path
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if (
      $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $trustedSids -notcontains $rule.IdentityReference.Value -and
      (($rule.FileSystemRights -band $readMask) -ne 0)
    ) { throw "$Label grants read access to an untrusted principal" }
  }
}

function Protect-ShaPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$Container
  )

  & icacls.exe $Path /reset | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "failed to reset SHA ACL: $Path"
  }
  if ($Container) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
  }
  else {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  }
  if ($LASTEXITCODE -ne 0) {
    throw "failed to restrict SHA ACL: $Path"
  }
  & icacls.exe $Path /setowner '*S-1-5-32-544' | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "failed to set trusted SHA owner: $Path"
  }
}

function Get-Sha256Hex {
  param([Parameter(Mandatory = $true)][string]$Path)
  $stream = [IO.File]::OpenRead($Path)
  try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
  }
  finally { $stream.Dispose() }
}

function Assert-EnrollmentToken {
  param([Parameter(Mandatory = $true)][string]$Value)
  $match = [regex]::Match($Value, '^sha_enroll\.(et_[0-9a-f]{32})\.([A-Za-z0-9_-]{43,128})$')
  if (-not $match.Success) { throw 'enrollment token has an invalid format' }
  $secret = $match.Groups[2].Value
  try {
    $padded = $secret.Replace('-', '+').Replace('_', '/') + ('=' * ((4 - $secret.Length % 4) % 4))
    $raw = [Convert]::FromBase64String($padded)
    $canonical = [Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  }
  catch { throw 'enrollment token secret is invalid base64url' }
  if ($raw.Length -lt 32 -or $canonical -cne $secret) {
    throw 'enrollment token secret is not canonical or is too short'
  }
  return $match.Groups[1].Value
}

function Get-NormalizedControlPlaneUrl {
  param([Parameter(Mandatory = $true)][string]$Value, [switch]$AllowLoopbackHttp)
  $uri = $null
  if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { throw 'control-plane URL is invalid' }
  if (
    -not [string]::IsNullOrEmpty($uri.UserInfo) -or -not [string]::IsNullOrEmpty($uri.Query) -or
    -not [string]::IsNullOrEmpty($uri.Fragment) -or ($uri.AbsolutePath -ne '/')
  ) { throw 'control-plane URL must have no user info, path, query, or fragment' }
  $loopback = @('localhost', '127.0.0.1', '::1') -contains $uri.Host.ToLowerInvariant()
  if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $AllowLoopbackHttp -and $loopback)) {
    throw 'control-plane URL must use HTTPS (HTTP requires explicit exact loopback mode)'
  }
  return $uri.GetLeftPart([UriPartial]::Authority)
}

function Assert-PemCertificateBundle {
  param([Parameter(Mandatory = $true)][string]$Path)
  Assert-NoReparsePoint -Path $Path -Label 'CA bundle'
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'CA bundle must be a regular file' }
  $text = [IO.File]::ReadAllText($Path)
  if ($text -notmatch '-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----') {
    throw 'CA bundle contains no PEM certificate'
  }
}

function Test-IsManagedShaTask {
  param(
    [Parameter(Mandatory = $true)]$Task,
    [Parameter(Mandatory = $true)][string]$ExpectedPowerShellPath,
    [Parameter(Mandatory = $true)][string]$ExpectedBinaryPath,
    [Parameter(Mandatory = $true)][string]$ExpectedLegacyArguments,
    [Parameter(Mandatory = $true)][string]$ExpectedCommand,
    [Parameter(Mandatory = $true)][string]$LegacyCommand
  )

  if ($Task.TaskPath -ne '\' -or @($Task.Actions).Count -ne 1) {
    return $false
  }
  if (@('SYSTEM', 'S-1-5-18', 'NT AUTHORITY\SYSTEM') -notcontains $Task.Principal.UserId) {
    return $false
  }
  $action = @($Task.Actions)[0]
  if ([string]::Equals($action.Execute, $ExpectedBinaryPath, [StringComparison]::OrdinalIgnoreCase)) {
    return [string]$action.Arguments -eq $ExpectedLegacyArguments
  }
  if (-not [string]::Equals($action.Execute, $ExpectedPowerShellPath, [StringComparison]::OrdinalIgnoreCase)) {
    return $false
  }
  $match = [regex]::Match([string]$action.Arguments, '(?i)(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)(?:\s|$)')
  if (-not $match.Success) {
    return $false
  }
  try {
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($match.Groups[1].Value))
  }
  catch {
    return $false
  }
  return $decoded -eq $ExpectedCommand -or $decoded -eq $LegacyCommand
}

if (-not (Test-IsElevated)) {
  throw 'sha-agent installation requires an elevated PowerShell session'
}
if ($SkipService -and $env:SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK -ne '1') {
  throw '-SkipService is restricted to explicit test staging with SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1'
}
if (
  [string]::IsNullOrWhiteSpace($TaskName) -or
  $TaskName -match '[\\/\x00-\x1f]' -or
  $TaskName.IndexOfAny([char[]]'*?[]') -ge 0 -or
  $TaskName.Length -gt 200
) {
  throw 'TaskName must be a non-empty literal root task name without path separators, wildcards, or control characters'
}

$InstallDir = Resolve-DedicatedDirectory -Path $InstallDir -Label 'InstallDir'
if ([string]::IsNullOrWhiteSpace($ConfigPath) -or $ConfigPath -notmatch '^[A-Za-z]:[\\/]') {
  throw 'ConfigPath must be an absolute local path'
}
if ($ConfigPath.StartsWith('\\') -or $ConfigPath -match '[\x00-\x1f<>"|?*]') {
  throw 'ConfigPath must not use a UNC path or contain invalid path characters'
}
if (@($ConfigPath -split '[\\/]' | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -ne 0) {
  throw 'ConfigPath must be normalized and must not contain dot path components'
}
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not ([IO.Path]::GetFileName($ConfigPath) -ieq 'agent-config.json')) {
  throw 'ConfigPath must end in agent-config.json'
}
$stateDir = Resolve-DedicatedDirectory -Path ([IO.Path]::GetDirectoryName($ConfigPath)) -Label 'ConfigPath parent'
$binaryPath = Join-Path $InstallDir 'sha-agent.exe'
$powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$source = Join-Path $PSScriptRoot 'sha-agent.exe'

if ($Operation -ne 'uninstall') {
  Assert-NoReparsePoint -Path $source -Label 'bundled sha-agent binary'
  if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw 'sha-agent.exe must be a regular file next to this installer'
  }
}
Assert-NoReparsePoint -Path $InstallDir -Label 'InstallDir'
Assert-NoReparsePoint -Path $stateDir -Label 'state directory'
Assert-NoReparsePoint -Path $ConfigPath -Label 'ConfigPath'
Assert-NoReparsePoint -Path $binaryPath -Label 'installed sha-agent binary'
Assert-TrustedExistingPath -Path $InstallDir -PathType Container -Label 'InstallDir'
Assert-TrustedExistingPath -Path $stateDir -PathType Container -Label 'state directory'
Assert-TrustedExistingPath -Path $ConfigPath -PathType Leaf -Label 'agent config'
Assert-TrustedExistingPath -Path $binaryPath -PathType Leaf -Label 'installed sha-agent binary'

$escapedBinaryPath = $binaryPath.Replace("'", "''")
$escapedConfigPath = $ConfigPath.Replace("'", "''")
$legacyDirectArguments = "-config `"$ConfigPath`" -loop"
$legacyTaskCommand = "& '$escapedBinaryPath' -config '$escapedConfigPath' -loop"
$taskCommand = "$legacyTaskCommand; exit `$LASTEXITCODE"
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($taskCommand))
$existingTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if ($existingTasks.Count -gt 1) {
  throw "multiple scheduled tasks named $TaskName exist; refusing ambiguous repair"
}
$existingTask = if ($existingTasks.Count -eq 1) { $existingTasks[0] } else { $null }
$taskCheck = @{
  Task = $existingTask
  ExpectedPowerShellPath = $powerShellPath
  ExpectedBinaryPath = $binaryPath
  ExpectedLegacyArguments = $legacyDirectArguments
  ExpectedCommand = $taskCommand
  LegacyCommand = $legacyTaskCommand
}
if ($null -ne $existingTask -and -not (Test-IsManagedShaTask @taskCheck)) {
  throw "scheduled task $TaskName is not owned by this SHA installation"
}
$serviceName = 'SHAAgent'
$serviceCommand = "`"$binaryPath`" -config `"$ConfigPath`" -action service"
$existingService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
  if (
    [string]$existingService.PathName -cne $serviceCommand -or
    @('LocalSystem', 'NT AUTHORITY\LocalSystem') -notcontains [string]$existingService.StartName
  ) { throw "Windows service $serviceName is not owned by this SHA installation" }
}

if ($Operation -eq 'uninstall') {
  if (
    -not [string]::IsNullOrWhiteSpace($ControlPlaneUrl) -or -not [string]::IsNullOrWhiteSpace($EnrollmentToken) -or
    -not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile) -or $EnrollmentTokenStdin -or
    -not [string]::IsNullOrWhiteSpace($BootstrapManifest) -or -not [string]::IsNullOrWhiteSpace($TrustPolicy) -or
    -not [string]::IsNullOrWhiteSpace($CaBundle)
  ) { throw 'uninstall does not accept enrollment, trust, URL, or CA inputs' }
  if ($null -ne $existingService) {
    if ([string]$existingService.State -ne 'Stopped') {
      Stop-Service -Name $serviceName -ErrorAction Stop
      (Get-Service -Name $serviceName -ErrorAction Stop).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30)
      )
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "failed to delete SHA Windows service $serviceName" }
  }
  if ($null -ne $existingTask) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
  foreach ($path in @($binaryPath)) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -Force -LiteralPath $path }
  }
  if ($PurgeState -and (Test-Path -LiteralPath $stateDir -PathType Container)) {
    Assert-NoReparsePoint -Path $stateDir -Label 'state directory'
    Assert-NoNestedReparsePoint -Path $stateDir -Label 'state purge'
    [IO.Directory]::Delete($stateDir, $true)
  }
  $result = [ordered]@{ operation = 'uninstall'; purged_state = [bool]$PurgeState; status = 'ok' }
  if ($Json) { $result | ConvertTo-Json -Compress } else { Write-Output "uninstalled sha-agent; state_preserved=$(-not $PurgeState)" }
  return
}
if ($PurgeState) { throw '-PurgeState is valid only with -Operation uninstall' }
if ([string]::IsNullOrWhiteSpace($TrustPolicy)) { throw '-TrustPolicy is required for install and repair' }
Assert-NoReparsePoint -Path $TrustPolicy -Label 'trust policy'
Assert-TrustedExistingPath -Path $TrustPolicy -PathType Leaf -Label 'trust policy'
$releaseVerifier = Join-Path $PSScriptRoot 'verify-release.ps1'
$releaseManifest = Join-Path $PSScriptRoot 'release-manifest.json'
$releaseSignature = Join-Path $PSScriptRoot 'release-manifest.json.sig'
foreach ($path in @($releaseVerifier, $releaseManifest, $releaseSignature)) {
  Assert-NoReparsePoint -Path $path -Label 'release verification input'
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "signed release verification file is missing: $path" }
}
& $releaseVerifier -Manifest $releaseManifest -Signature $releaseSignature -TrustPolicy $TrustPolicy | Out-Null
$release = [IO.File]::ReadAllText($releaseManifest, [Text.Encoding]::UTF8) | ConvertFrom-Json
if ($release.platform -ne 'windows' -or $release.architecture -ne 'amd64') {
  throw 'release manifest does not match Windows amd64 installer'
}

$freshInstall = -not (Test-Path -LiteralPath $ConfigPath)
$newConfigJson = $null
$caSource = $null
$embeddedBootstrap = $false
if ($Operation -eq 'repair') {
  if ($freshInstall) { throw 'repair requires an existing SHA config' }
}
if (-not $freshInstall) {
  if (
    -not [string]::IsNullOrWhiteSpace($ControlPlaneUrl) -or -not [string]::IsNullOrWhiteSpace($EnrollmentToken) -or
    -not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile) -or $EnrollmentTokenStdin -or
    -not [string]::IsNullOrWhiteSpace($BootstrapManifest) -or -not [string]::IsNullOrWhiteSpace($CaBundle)
  ) { throw 'existing install cannot be re-enrolled; use repair or uninstall with purge first' }
  $existingConfig = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  if (
    $null -ne $existingConfig.PSObject.Properties['device_credential'] -or
    $null -ne $existingConfig.PSObject.Properties['credential_secret']
  ) {
    throw 'installer-managed config must never contain a long-lived device credential'
  }
  $existingLoopback = $false
  if ($null -ne $existingConfig.PSObject.Properties['allow_insecure_loopback']) {
    $existingLoopback = [bool]$existingConfig.allow_insecure_loopback
  }
  [void](Get-NormalizedControlPlaneUrl -Value ([string]$existingConfig.control_plane_url) -AllowLoopbackHttp:$existingLoopback)
}
else {
  if ([string]::IsNullOrWhiteSpace($BootstrapManifest)) {
    $embedded = Join-Path $PSScriptRoot 'bootstrap-manifest.json'
    if (Test-Path -LiteralPath $embedded -PathType Leaf) {
      $BootstrapManifest = $embedded
      $embeddedBootstrap = $true
    }
  }
  $sourceCount = 0
  if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken)) { $sourceCount++ }
  if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)) { $sourceCount++ }
  if ($EnrollmentTokenStdin) { $sourceCount++ }
  if (-not [string]::IsNullOrWhiteSpace($BootstrapManifest)) {
    if ($sourceCount -ne 0 -or -not [string]::IsNullOrWhiteSpace($ControlPlaneUrl) -or -not [string]::IsNullOrWhiteSpace($CaBundle) -or $AllowInsecureLoopback) {
      throw 'signed bootstrap mode cannot be combined with generic enrollment inputs'
    }
    Assert-NoReparsePoint -Path $BootstrapManifest -Label 'bootstrap manifest'
    $bootstrapSignature = "$BootstrapManifest.sig"
    if (-not (Test-Path -LiteralPath $BootstrapManifest -PathType Leaf) -or -not (Test-Path -LiteralPath $bootstrapSignature -PathType Leaf)) {
      throw 'signed bootstrap manifest or detached signature is missing'
    }
    Assert-ConfidentialExistingFile -Path $BootstrapManifest -Label 'token-bearing bootstrap manifest'
    & $releaseVerifier -Manifest $BootstrapManifest -Signature $bootstrapSignature -TrustPolicy $TrustPolicy -SignatureOnly | Out-Null
    $bootstrap = [IO.File]::ReadAllText($BootstrapManifest, [Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($bootstrap.schema_version -ne 'sha-agent-bootstrap-manifest-v1' -or $bootstrap.platform -ne 'windows' -or $bootstrap.architecture -ne 'amd64') {
      throw 'bootstrap schema or target does not match Windows amd64'
    }
    $createdAt = [DateTimeOffset]::Parse([string]$bootstrap.created_at)
    $expiresAt = [DateTimeOffset]::Parse([string]$bootstrap.expires_at)
    if ($expiresAt -le [DateTimeOffset]::UtcNow -or $expiresAt -le $createdAt -or ($expiresAt - $createdAt).TotalHours -gt 24) {
      throw 'bootstrap manifest is expired or has an invalid lifetime'
    }
    $tokenId = Assert-EnrollmentToken -Value ([string]$bootstrap.enrollment_token)
    if ($bootstrap.token_id -cne $tokenId -or @('pending', 'approved') -cnotcontains [string]$bootstrap.approval_policy) {
      throw 'bootstrap token metadata is inconsistent'
    }
    if ([int]$bootstrap.max_uses -lt 1 -or [int]$bootstrap.max_uses -gt 1000) { throw 'bootstrap max uses is invalid' }
    foreach ($field in @('client_id', 'location_id', 'profile_id')) {
      if ([string]::IsNullOrWhiteSpace([string]$bootstrap.$field)) { throw "bootstrap $field is missing" }
    }
    if (
      $bootstrap.release_version -cne $release.version -or
      $bootstrap.release_manifest_sha256 -cne (Get-Sha256Hex -Path $releaseManifest)
    ) { throw 'bootstrap manifest is bound to a different SHA agent release' }
    $normalizedUrl = Get-NormalizedControlPlaneUrl -Value ([string]$bootstrap.control_plane_url)
    if ($null -ne $bootstrap.PSObject.Properties['ca_bundle']) {
      if ($bootstrap.ca_bundle.file -cne 'bootstrap-ca.pem') { throw 'bootstrap CA metadata is invalid' }
      $caSource = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BootstrapManifest))) 'bootstrap-ca.pem'
      Assert-PemCertificateBundle -Path $caSource
      if ((Get-Sha256Hex -Path $caSource) -cne [string]$bootstrap.ca_bundle.sha256) { throw 'bootstrap CA digest mismatch' }
    }
    $config = [ordered]@{
      control_plane_url = $normalizedUrl
      enrollment_token = [string]$bootstrap.enrollment_token
      state_path = "$env:ProgramData\SHA\agent-state.json"
      allow_insecure_loopback = $false
      profile_id = [string]$bootstrap.profile_id
      agent_version = [string]$release.version
      service_context = 'system_service'
      windows_firewall_rollback_path = "$env:ProgramData\SHA\firewall-profiles-rollback.json"
    }
    if ($null -ne $caSource) { $config['ca_bundle_path'] = "$env:ProgramData\SHA\ca-bundle.pem" }
  }
  else {
    if ($sourceCount -ne 1) { throw 'fresh generic install requires exactly one enrollment-token source' }
    if ([string]::IsNullOrWhiteSpace($ControlPlaneUrl)) { throw 'fresh generic install requires -ControlPlaneUrl' }
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
      Write-Warning '-EnrollmentToken is visible in process listings; prefer file or stdin input.'
      $token = $EnrollmentToken
      $EnrollmentToken = $null
    }
    elseif (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)) {
      Assert-ConfidentialExistingFile -Path $EnrollmentTokenFile -Label 'enrollment-token file'
      if ((Get-Item -LiteralPath $EnrollmentTokenFile).Length -gt 4096) { throw 'enrollment-token file is too large' }
      $token = [IO.File]::ReadAllText($EnrollmentTokenFile, [Text.Encoding]::UTF8).Trim()
    }
    else { $token = [Console]::In.ReadLine() }
    [void](Assert-EnrollmentToken -Value $token)
    $normalizedUrl = Get-NormalizedControlPlaneUrl -Value $ControlPlaneUrl -AllowLoopbackHttp:$AllowInsecureLoopback
    if (-not [string]::IsNullOrWhiteSpace($CaBundle)) {
      Assert-TrustedExistingPath -Path $CaBundle -PathType Leaf -Label 'CA bundle'
      Assert-PemCertificateBundle -Path $CaBundle
      $caSource = $CaBundle
    }
    $config = [ordered]@{
      control_plane_url = $normalizedUrl
      enrollment_token = $token
      state_path = "$env:ProgramData\SHA\agent-state.json"
      allow_insecure_loopback = [bool]$AllowInsecureLoopback
      profile_id = $ProfileId
      agent_version = [string]$release.version
      service_context = 'system_service'
      windows_firewall_rollback_path = "$env:ProgramData\SHA\firewall-profiles-rollback.json"
    }
    if ($null -ne $caSource) { $config['ca_bundle_path'] = "$env:ProgramData\SHA\ca-bundle.pem" }
    $token = $null
  }
  $newConfigJson = $config | ConvertTo-Json -Depth 5
}

$taskWasRunning = $null -ne $existingTask -and [string]$existingTask.State -eq 'Running'
$taskStoppedForRepair = $false
$serviceWasRunning = $null -ne $existingService -and [string]$existingService.State -eq 'Running'
$serviceStoppedForRepair = $false
try {
  if ($serviceWasRunning) {
    Stop-Service -Name $serviceName -ErrorAction Stop
    (Get-Service -Name $serviceName -ErrorAction Stop).WaitForStatus(
      [ServiceProcess.ServiceControllerStatus]::Stopped,
      [TimeSpan]::FromSeconds(30)
    )
    $serviceStoppedForRepair = $true
  }
  if ($taskWasRunning) {
    Stop-ScheduledTask -TaskName $TaskName
    $taskStoppedForRepair = $true
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
      Start-Sleep -Milliseconds 250
      $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    } while ([string]$existingTask.State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
    if ([string]$existingTask.State -eq 'Running') {
      throw "scheduled task $TaskName did not stop for repair"
    }
  }

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Assert-NoReparsePoint -Path $InstallDir -Label 'InstallDir'
  Protect-ShaPath -Path $InstallDir -Container
  New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
  Assert-NoReparsePoint -Path $stateDir -Label 'state directory'
  Protect-ShaPath -Path $stateDir -Container

  Copy-Item -Force -LiteralPath $source -Destination $binaryPath
  Protect-ShaPath -Path $binaryPath

  $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
  if ($freshInstall) {
    [IO.File]::WriteAllText($ConfigPath, $newConfigJson, $utf8NoBom)
  }
  else {
    $configBytes = [IO.File]::ReadAllBytes($ConfigPath)
    if ($configBytes.Length -ge 3 -and $configBytes[0] -eq 0xEF -and $configBytes[1] -eq 0xBB -and $configBytes[2] -eq 0xBF) {
      $withoutBom = [byte[]]::new($configBytes.Length - 3)
      [Array]::Copy($configBytes, 3, $withoutBom, 0, $withoutBom.Length)
      [IO.File]::WriteAllBytes($ConfigPath, $withoutBom)
    }
  }
  Protect-ShaPath -Path $ConfigPath
  $installedCa = Join-Path $stateDir 'ca-bundle.pem'
  if ($null -ne $caSource) {
    Copy-Item -Force -LiteralPath $caSource -Destination $installedCa
    Protect-ShaPath -Path $installedCa
  }

  $skipEnrollmentCheck = $env:SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK -eq '1'
  if ($skipEnrollmentCheck -and -not $SkipService) {
    throw 'SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 is allowed only with -SkipService test staging'
  }
  $identity = $null
  if (-not $skipEnrollmentCheck) {
    $statusJson = (& $binaryPath -config $ConfigPath -action status | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'agent enrollment/TLS preflight failed before Windows service installation' }
    $identity = $statusJson | ConvertFrom-Json
    if (
      [string]::IsNullOrWhiteSpace([string]$identity.endpoint_id) -or
      $identity.credential_status -ne 'active' -or $identity.protocol_version -ne 'sha-agent-v1'
    ) { throw 'agent enrollment preflight returned incomplete endpoint identity' }
    $postEnrollmentConfig = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    foreach ($field in @('enrollment_token', 'api_token')) {
      $property = $postEnrollmentConfig.PSObject.Properties[$field]
      if ($null -ne $property -and -not [string]::IsNullOrEmpty([string]$property.Value)) {
        throw 'agent did not erase bootstrap/shared token after successful enrollment'
      }
    }
    $deviceStatePath = Join-Path $stateDir 'agent-state.json'
    Assert-TrustedExistingPath -Path $deviceStatePath -PathType Leaf -Label 'device credential state'
    if (-not (Test-Path -LiteralPath $deviceStatePath -PathType Leaf)) {
      throw 'device credential state was not created'
    }
    if ($embeddedBootstrap) {
      foreach ($bootstrapPath in @($BootstrapManifest, "$BootstrapManifest.sig", (Join-Path $PSScriptRoot 'bootstrap-ca.pem'))) {
        if (Test-Path -LiteralPath $bootstrapPath -PathType Leaf) { Remove-Item -Force -LiteralPath $bootstrapPath }
      }
    }
  }

  if (-not $SkipService) {
    if ($null -eq $existingService) {
      & sc.exe create $serviceName 'binPath=' $serviceCommand 'start=' 'auto' 'obj=' 'LocalSystem' | Out-Null
    }
    else {
      & sc.exe config $serviceName 'binPath=' $serviceCommand 'start=' 'auto' 'obj=' 'LocalSystem' | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "failed to create/configure SHA Windows service $serviceName" }
    & sc.exe failure $serviceName 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/restart/60000' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "failed to configure restart policy for $serviceName" }
    & sc.exe failureflag $serviceName '1' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "failed to enable failure actions for $serviceName" }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName -ErrorAction Stop).WaitForStatus(
      [ServiceProcess.ServiceControllerStatus]::Running,
      [TimeSpan]::FromSeconds(30)
    )
    $serviceStoppedForRepair = $false
    if ($null -ne $existingTask) {
      $taskStoppedForRepair = $false
      try {
        Disable-ScheduledTask -TaskName $TaskName | Out-Null
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $existingTask = $null
      }
      catch {
        $cleanupError = $_.Exception.Message
        $remainingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -ne $remainingTask) {
          if ([string]$remainingTask.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName }
          Disable-ScheduledTask -TaskName $TaskName | Out-Null
        }
        Write-Warning "SHAAgent service is running, but the disabled legacy task could not be removed: $cleanupError"
      }
    }
    $taskStoppedForRepair = $false
  }
  elseif ($taskWasRunning -and $null -ne $existingTask) {
    Start-ScheduledTask -TaskName $TaskName
    $taskStoppedForRepair = $false
  }
}
catch {
  if ($taskStoppedForRepair) {
    try {
      Start-ScheduledTask -TaskName $TaskName
    }
    catch {
      Write-Warning "failed to restart prior SHA task after repair failure: $($_.Exception.Message)"
    }
  }
  if ($serviceStoppedForRepair) {
    try { Start-Service -Name $serviceName }
    catch { Write-Warning "failed to restart prior SHA service after repair failure: $($_.Exception.Message)" }
  }
  throw
}

$installedConfigObject = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
$controlPlaneHost = ([Uri]([string]$installedConfigObject.control_plane_url)).Host
$serviceState = if ($SkipService) { 'not-checked-test-staging' } else { [string](Get-Service -Name $serviceName -ErrorAction Stop).Status }
$legacyTaskState = if ($null -eq (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { 'absent' } else { 'present' }
$result = [ordered]@{
  binary = $binaryPath
  config = $ConfigPath
  operation = $Operation
  status = 'ok'
  service = $serviceName
  control_plane_host = $controlPlaneHost
  service_state = $serviceState
  legacy_task_state = $legacyTaskState
  credential_storage = $(if ($null -ne $identity) { 'dpapi-local-machine-protected-state' } else { 'not-checked-test-staging' })
}
if ($null -ne $identity) {
  $result.endpoint_id = [string]$identity.endpoint_id
  $result.endpoint_status = [string]$identity.endpoint_status
  $result.credential_status = [string]$identity.credential_status
}
if ($Json) { $result | ConvertTo-Json -Compress }
else {
  $endpointText = if ($null -ne $identity) { [string]$identity.endpoint_id } else { 'not-checked-test-staging' }
  Write-Output "$Operation sha-agent host=$controlPlaneHost endpoint=$endpointText service=$serviceState credential_storage=$($result.credential_storage)"
}
