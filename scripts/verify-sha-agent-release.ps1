[CmdletBinding()]
param(
  [string]$Manifest = (Join-Path $PSScriptRoot 'release-manifest.json'),
  [string]$Signature = (Join-Path $PSScriptRoot 'release-manifest.json.sig'),
  [Parameter(Mandatory = $true)][string]$TrustPolicy,
  [switch]$SignatureOnly,
  [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-DerLength {
  param([byte[]]$Data, [ref]$Offset)
  $first = $Data[$Offset.Value]
  $Offset.Value++
  if (($first -band 0x80) -eq 0) { return [int]$first }
  $count = $first -band 0x7f
  if ($count -lt 1 -or $count -gt 4) { throw 'unsupported DER length' }
  $length = 0
  for ($index = 0; $index -lt $count; $index++) {
    $length = ($length -shl 8) -bor $Data[$Offset.Value]
    $Offset.Value++
  }
  return $length
}

function Read-DerValue {
  param([byte[]]$Data, [ref]$Offset, [byte]$Tag)
  if ($Offset.Value -ge $Data.Length -or $Data[$Offset.Value] -ne $Tag) {
    throw ('unexpected DER tag at byte {0}' -f $Offset.Value)
  }
  $Offset.Value++
  $length = Read-DerLength -Data $Data -Offset $Offset
  if ($length -lt 0 -or $Offset.Value + $length -gt $Data.Length) { throw 'invalid DER value length' }
  $value = [byte[]]::new($length)
  [Array]::Copy($Data, $Offset.Value, $value, 0, $length)
  $Offset.Value += $length
  return $value
}

function Import-RsaPublicKey {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -Force -LiteralPath $Path
  if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
    $pem = [IO.File]::ReadAllText($item.FullName)
  }
  else { throw 'trusted public key must be a regular non-reparse file' }
  $base64 = ($pem -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\s', '')
  if ([string]::IsNullOrWhiteSpace($base64)) { throw 'trusted public key must use PUBLIC KEY PEM format' }
  $der = [Convert]::FromBase64String($base64)
  $offset = 0
  $outer = Read-DerValue -Data $der -Offset ([ref]$offset) -Tag 0x30
  $innerOffset = 0
  [void](Read-DerValue -Data $outer -Offset ([ref]$innerOffset) -Tag 0x30)
  $bitString = Read-DerValue -Data $outer -Offset ([ref]$innerOffset) -Tag 0x03
  if ($bitString.Length -lt 2 -or $bitString[0] -ne 0) { throw 'invalid RSA public-key bit string' }
  $rsaDer = [byte[]]::new($bitString.Length - 1)
  [Array]::Copy($bitString, 1, $rsaDer, 0, $rsaDer.Length)
  $rsaOffset = 0
  $sequence = Read-DerValue -Data $rsaDer -Offset ([ref]$rsaOffset) -Tag 0x30
  $sequenceOffset = 0
  $modulus = Read-DerValue -Data $sequence -Offset ([ref]$sequenceOffset) -Tag 0x02
  $exponent = Read-DerValue -Data $sequence -Offset ([ref]$sequenceOffset) -Tag 0x02
  if ($modulus[0] -eq 0) { $modulus = $modulus[1..($modulus.Length - 1)] }
  $parameters = [Security.Cryptography.RSAParameters]::new()
  $parameters.Modulus = $modulus
  $parameters.Exponent = $exponent
  $rsa = [Security.Cryptography.RSACryptoServiceProvider]::new()
  $rsa.PersistKeyInCsp = $false
  $rsa.ImportParameters($parameters)
  return $rsa
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

function Get-PublicKeyFingerprint {
  param([Parameter(Mandatory = $true)][string]$Path)
  $pem = [IO.File]::ReadAllText($Path)
  $base64 = ($pem -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\s', '')
  if ([string]::IsNullOrWhiteSpace($base64)) { throw 'trusted public key must use PUBLIC KEY PEM format' }
  $der = [Convert]::FromBase64String($base64)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return 'sha256:' + ([BitConverter]::ToString($sha.ComputeHash($der))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Assert-TrustedPolicyPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  $current = [IO.Path]::GetFullPath($Path)
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -Force -LiteralPath $current
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "trust policy path contains a reparse point: $current"
      }
    }
    $parent = [IO.Path]::GetDirectoryName($current)
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
    $current = $parent
  }
  $acl = Get-Acl -LiteralPath $Path
  $owner = ([Security.Principal.NTAccount]::new($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $trusted = @('S-1-5-18', 'S-1-5-32-544', $currentSid)
  if ($trusted -notcontains $owner) { throw 'trust policy has an untrusted owner' }
  $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if (
      $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $trusted -notcontains $rule.IdentityReference.Value -and (($rule.FileSystemRights -band $writeMask) -ne 0)
    ) { throw 'trust policy grants write-equivalent access to an untrusted principal' }
  }
}

Assert-TrustedPolicyPath -Path $TrustPolicy

foreach ($path in @($Manifest, $Signature, $TrustPolicy)) {
  $item = Get-Item -Force -LiteralPath $path
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "release verification input must be a regular non-reparse file: $path"
  }
}
$manifestRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Manifest)).TrimEnd([char[]]'\/')
$policyFullPath = [IO.Path]::GetFullPath($TrustPolicy)
if (
  $policyFullPath -ieq $manifestRoot -or
  $policyFullPath.StartsWith($manifestRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
) { throw 'trust policy must be external to the downloaded package' }

$manifestObject = [IO.File]::ReadAllText($Manifest, [Text.Encoding]::UTF8) | ConvertFrom-Json
$policyObject = [IO.File]::ReadAllText($TrustPolicy, [Text.Encoding]::UTF8) | ConvertFrom-Json
if ($policyObject.schema_version -ne 'sha-agent-trust-policy-v1') { throw 'trust policy schema is unsupported' }
if ($manifestObject.signing.identity -cne $policyObject.expected_signing_identity) {
  throw 'manifest signing identity is not allowed by trust policy'
}
$fingerprint = [string]$manifestObject.signing.public_key_fingerprint
if (@($policyObject.revoked_fingerprints) -ccontains $fingerprint) { throw 'manifest signing key is explicitly revoked' }
$matchingKeys = @($policyObject.trusted_keys | Where-Object {
  $_.key_id -ceq $manifestObject.signing.key_id -and $_.fingerprint -ceq $fingerprint
})
if ($matchingKeys.Count -ne 1) { throw 'manifest signing key is not uniquely allowlisted' }
$relativeKey = [string]$matchingKeys[0].public_key_file
if (
  [string]::IsNullOrWhiteSpace($relativeKey) -or [IO.Path]::IsPathRooted($relativeKey) -or
  @($relativeKey -split '[\\/]' | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -ne 0
) { throw 'trust policy public_key_file is unsafe' }
$TrustedPublicKey = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($TrustPolicy))) $relativeKey
$keyItem = Get-Item -Force -LiteralPath $TrustedPublicKey
if ($keyItem.PSIsContainer -or ($keyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'allowlisted public key must be a regular non-reparse file'
}
if ((Get-PublicKeyFingerprint -Path $TrustedPublicKey) -cne $fingerprint) {
  throw 'allowlisted public key fingerprint does not match key bytes'
}

$rsa = Import-RsaPublicKey -Path $TrustedPublicKey
try {
  $manifestBytes = [IO.File]::ReadAllBytes($Manifest)
  $signatureBytes = [IO.File]::ReadAllBytes($Signature)
  if (-not $rsa.VerifyData($manifestBytes, 'SHA256', $signatureBytes)) {
    throw 'release manifest signature verification failed'
  }
}
finally { $rsa.Dispose() }

if ($SignatureOnly) {
  if ($Json) { [pscustomobject]@{ operation = 'verify-signature'; status = 'ok' } | ConvertTo-Json -Compress }
  else { Write-Output "verified SHA signed manifest identity=$($policyObject.expected_signing_identity)" }
  return
}

if ($manifestObject.schema_version -ne 'sha-agent-release-manifest-v1' -or $manifestObject.product -ne 'sha-agent') {
  throw 'release manifest schema or product is unsupported'
}
if ($manifestObject.signing.algorithm -ne 'rsa-pkcs1v15-sha256') { throw 'unsupported signature algorithm' }
if ($manifestObject.signing.identity -cne $policyObject.expected_signing_identity) { throw 'release signing identity mismatch' }
if ($manifestObject.signing.public_key_fingerprint -cne (Get-PublicKeyFingerprint -Path $TrustedPublicKey)) {
  throw 'release public key fingerprint mismatch'
}

$root = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Manifest))
$listed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($artifact in @($manifestObject.artifacts)) {
  $relative = [string]$artifact.path
  if (
    [string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or
    $relative -match '\\' -or @($relative.Split('/') | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -ne 0
  ) { throw 'release manifest contains an unsafe artifact path' }
  if (-not $listed.Add($relative)) { throw 'release manifest contains a duplicate artifact path' }
  $target = Join-Path $root ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
  $item = Get-Item -Force -LiteralPath $target
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "release artifact is missing, non-regular, or reparse-backed: $relative"
  }
  if ($item.Length -ne [long]$artifact.size -or (Get-Sha256Hex -Path $target) -cne [string]$artifact.sha256) {
    throw "release artifact failed digest verification: $relative"
  }
}

$allowedExtras = @(
  'release-manifest.json', 'release-manifest.json.sig',
  'bootstrap-manifest.json', 'bootstrap-manifest.json.sig', 'bootstrap-ca.pem'
)
foreach ($item in @(Get-ChildItem -Force -Recurse -LiteralPath $root)) {
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "release contains a reparse point: $($item.FullName)"
  }
  if (-not $item.PSIsContainer) {
    $relative = $item.FullName.Substring($root.Length).TrimStart([char[]]'\/').Replace('\', '/')
    if (-not $listed.Contains($relative) -and $allowedExtras -cnotcontains $relative) {
      throw "release contains an unlisted file: $relative"
    }
  }
}

if ($Json) {
  [pscustomobject]@{ operation = 'verify-release'; status = 'ok' } | ConvertTo-Json -Compress
}
else { Write-Output "verified SHA agent release identity=$($policyObject.expected_signing_identity)" }
