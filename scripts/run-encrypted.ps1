$ErrorActionPreference = 'Stop'
$cipherPath = Join-Path $env:GITHUB_WORKSPACE 'encrypted\validation.bin'
$work = Join-Path $env:RUNNER_TEMP ('h4-validation-' + [Guid]::NewGuid().ToString('N'))
$plainZip = Join-Path $work 'input.zip'
$expanded = Join-Path $work 'expanded'
$harnessLog = Join-Path $work 'harness.log'
$archive = Join-Path $env:RUNNER_TEMP ('h4-evidence-' + [Guid]::NewGuid().ToString('N') + '.zip')
$encryptedOutput = Join-Path $env:GITHUB_WORKSPACE 'encrypted-run-output.bin'
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

$harnessFailed = $false
try {
  & (Join-Path $expanded 'poc\run_windows.ps1') -Attempts 5 *> $harnessLog
} catch {
  $harnessFailed = $true
  $_ | Out-String | Add-Content -LiteralPath $harnessLog
}

$reportPath = Join-Path $expanded 'poc\report.json'
$report = $null
if (Test-Path -LiteralPath $reportPath) {
  try { $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json }
  catch { $harnessFailed = $true }
}
if (-not $report) { $harnessFailed = $true }
if ($report -and $report.setup_or_run_error) { $harnessFailed = $true }

if ($report) {
  $positive = @($report.positive | Where-Object { $_.marker_exists -and $_.actor.direct_write_denied -and $_.actor.probe_sent_completion }).Count -gt 0
  $negative = $report.negative -and $report.negative.actor.probe_sent_completion -and -not $report.negative.marker_exists
  $intervention = $report.intervention -and $report.intervention.actor.probe_sent_completion -and -not $report.intervention.marker_exists
  $principalDistinct = $report.owner -ne $report.actor
  Write-Host "SDK=$($report.sdk)"
  Write-Host "DistinctPrincipal=$principalDistinct"
  Write-Host "ControlBaseline=$(-not $report.valid_baseline.marker_exists)"
  Write-Host "ObservedTerminal=$positive"
  Write-Host "NegativeControl=$negative"
  Write-Host "CausalIntervention=$intervention"
  Write-Host "CompleteMatrix=$($positive -and $negative -and $intervention -and $principalDistinct)"
} else {
  Write-Host 'HarnessReport=false'
}

$publicEvidence = Join-Path $expanded 'runner-public-evidence'
New-Item -ItemType Directory -Path $publicEvidence | Out-Null
Get-ChildItem -LiteralPath $env:PUBLIC -Filter 'h4-vst-*' -File -ErrorAction SilentlyContinue | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination $publicEvidence
  Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
}
Copy-Item -LiteralPath $harnessLog -Destination (Join-Path $expanded 'harness.log')
Compress-Archive -Path (Join-Path $expanded '*') -DestinationPath $archive -CompressionLevel Optimal
[byte[]]$encrypted = Protect-Bytes ([IO.File]::ReadAllBytes($archive)) $key
[IO.File]::WriteAllBytes($encryptedOutput, $encrypted)
Write-Host "EncryptedEvidenceSha256=$((Get-FileHash $encryptedOutput -Algorithm SHA256).Hash)"
Write-Host "EncryptedEvidenceBytes=$($encrypted.Length)"
Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
if ($harnessFailed) { throw 'Harness setup failed; encrypted evidence is available' }
