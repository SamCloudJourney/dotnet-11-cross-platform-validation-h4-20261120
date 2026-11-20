$ErrorActionPreference = 'Stop'
$cipherPath = Join-Path $env:GITHUB_WORKSPACE 'encrypted\wpf-paste.bin'
$work = Join-Path $env:RUNNER_TEMP ('h4-wpf-' + [Guid]::NewGuid().ToString('N'))
$plainZip = Join-Path $work 'input.zip'
$expanded = Join-Path $work 'expanded'
$harnessLog = Join-Path $work 'harness.log'
$archive = Join-Path $work 'evidence.zip'
$encryptedOutput = Join-Path $env:GITHUB_WORKSPACE 'wpf-encrypted-evidence.bin'
New-Item -ItemType Directory -Path $work, $expanded | Out-Null

function Protect-Bytes([byte[]]$Plain, [byte[]]$Key) {
  [byte[]]$nonce = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
  [byte[]]$tag = New-Object byte[] 16
  [byte[]]$cipher = New-Object byte[] $Plain.Length
  $aes = [Security.Cryptography.AesGcm]::new($Key, 16)
  try { $aes.Encrypt($nonce, $Plain, $cipher, $tag) }
  finally { $aes.Dispose() }
  [byte[]]$result = New-Object byte[] (28 + $cipher.Length)
  [Array]::Copy($nonce, 0, $result, 0, 12)
  [Array]::Copy($tag, 0, $result, 12, 16)
  [Array]::Copy($cipher, 0, $result, 28, $cipher.Length)
  return ,$result
}

$key = [Convert]::FromBase64String($env:H4_VALIDATION_KEY)
if ($key.Length -ne 32) { throw 'Validation secret has incorrect length' }
Remove-Item Env:H4_VALIDATION_KEY -ErrorAction SilentlyContinue
$blob = [IO.File]::ReadAllBytes($cipherPath)
if ($blob.Length -lt 29) { throw 'Encrypted input is too short' }
[byte[]]$nonce = $blob[0..11]
[byte[]]$tag = $blob[12..27]
[byte[]]$cipher = New-Object byte[] ($blob.Length - 28)
[Array]::Copy($blob, 28, $cipher, 0, $cipher.Length)
[byte[]]$plain = New-Object byte[] $cipher.Length
$aes = [Security.Cryptography.AesGcm]::new($key, 16)
try { $aes.Decrypt($nonce, $cipher, $tag, $plain) }
finally { $aes.Dispose() }
[IO.File]::WriteAllBytes($plainZip, $plain)
Expand-Archive -LiteralPath $plainZip -DestinationPath $expanded -Force
Remove-Item -LiteralPath $plainZip -Force

$failed = $false
try {
  & (Join-Path $expanded 'poc\run_windows.ps1') *> $harnessLog
} catch {
  $failed = $true
  $_ | Out-String | Add-Content -LiteralPath $harnessLog
}
$reportPath = Join-Path $expanded 'poc\report.json'
if (-not (Test-Path -LiteralPath $reportPath)) { $failed = $true }
Copy-Item -LiteralPath $harnessLog -Destination (Join-Path $expanded 'harness.log')
Compress-Archive -Path (Join-Path $expanded '*') -DestinationPath $archive -CompressionLevel Optimal
[byte[]]$encrypted = Protect-Bytes ([IO.File]::ReadAllBytes($archive)) $key
[IO.File]::WriteAllBytes($encryptedOutput, $encrypted)
Write-Host "RunnerImage=$env:ImageOS $env:ImageVersion"
Write-Host "SDK=$((& dotnet --version).Trim())"
Write-Host "InputSha256=$((Get-FileHash $cipherPath -Algorithm SHA256).Hash)"
Write-Host "PrivateReportAvailable=$(-not $failed)"
Write-Host "EncryptedEvidenceSha256=$((Get-FileHash $encryptedOutput -Algorithm SHA256).Hash)"
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) { throw 'Harness setup failed; encrypted evidence is available' }
