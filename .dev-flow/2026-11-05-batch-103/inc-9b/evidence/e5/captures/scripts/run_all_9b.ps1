# CAP9b serial real-WT matrix, shared capture lock and complete-sequence skipping.
param(
  [Parameter(Mandatory = $true)][string]$Tree,
  [Parameter(Mandatory = $true)][string]$Fixtures,
  [Parameter(Mandatory = $true)][string]$Out,
  [string[]]$Only = @(),
  [string]$Commit = "d05b5180e5f48d4a167d13e7fb45b24586293eb6"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$capture = Join-Path $here "capture_9b.ps1"
$lockPath = Join-Path $env:USERPROFILE "clde\s19-relevo12-work\wt-capture.lock"
$logPath = Join-Path $Out "capture-run.log"
$createdLock = $false
$allLines = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $logPath) {
  foreach ($line in Get-Content -LiteralPath $logPath) { $allLines.Add("$line") }
}
$started = Get-Date

function Write-RunLog([string]$reason) {
  $clean = New-Object System.Collections.Generic.List[string]
  foreach ($line in $allLines) {
    $text = "$line"
    foreach ($word in @($env:USERPROFILE, $env:USERNAME, $Tree, $Fixtures, $Out)) {
      if ($word) { $text = $text.Replace("$word", "<capture>").Replace(("$word").Replace("\", "/"), "<capture>") }
    }
    $clean.Add($text)
  }
  $clean.Add("RUN_LOG_END " + (Get-Date).ToString("o") + " reason=" + $reason)
  [IO.File]::WriteAllLines($logPath, $clean, [Text.UTF8Encoding]::new($false))
}

function Test-Complete([string]$name, [bool]$job) {
  $frames = @(".f1.png", ".f2.png")
  if ($job) { $frames += ".idle.png" }
  foreach ($suffix in $frames) {
    $png = Join-Path $Out ($name + $suffix)
    if (-not (Test-Path -LiteralPath $png) -or -not (Test-Path -LiteralPath ($png + ".txt"))) { return $false }
  }
  return $true
}

$jobs = @()
foreach ($scene in @("decode", "preview", "stage-encode", "stage-refused", "stage-refresh")) {
  $jobs += ,@($scene, 118, 54, $true)
  $jobs += ,@($scene, 220, 60, $true)
}
foreach ($scene in @("name-markup", "name-brackets", "name-esc", "name-c1")) {
  $jobs += ,@($scene, 118, 54, $false)
  $jobs += ,@($scene, 220, 60, $false)
}
$jobs += ,@("name-long", 80, 24, $false)
$jobs += ,@("name-long", 118, 54, $false)
$jobs += ,@("name-long", 220, 60, $false)
$jobs += ,@("name-short", 80, 24, $false)

try {
  $allLines.Add("CAP9b START " + $started.ToString("o") + " commit=" + $Commit)
  $lockDeadline = (Get-Date).AddMinutes(60)
  while (-not $createdLock) {
    if (Test-Path -LiteralPath $lockPath) {
      $owner = (Get-Content -LiteralPath $lockPath -ErrorAction SilentlyContinue) -join " | "
      $allLines.Add("LOCK HELD " + (Get-Date).ToString("o") + " owner=" + $owner)
      if ((Get-Date) -ge $lockDeadline) { throw "captures not taken (lock)" }
      Start-Sleep -Seconds 120
      continue
    }
    try {
      $stream = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      $writer = New-Object IO.StreamWriter($stream, [Text.UTF8Encoding]::new($false))
      try {
        $writer.WriteLine("X9b E5 / CAP9b")
        $writer.WriteLine("host_pid=$PID")
        $writer.WriteLine("start=" + (Get-Date).ToString("o"))
      } finally {
        $writer.Dispose(); $stream.Dispose()
      }
      $createdLock = $true
      $allLines.Add("LOCK ACQUIRED " + (Get-Date).ToString("o") + " host_pid=$PID")
    } catch [System.IO.IOException] {
      Start-Sleep -Seconds 120
    }
  }
  foreach ($job in $jobs) {
    $name = "{0}.{1}x{2}" -f $job[0], $job[1], $job[2]
    if ($Only.Count -gt 0 -and (($Only -join ",").Split(",") -notcontains $name)) { continue }
    if (Test-Complete $name $job[3]) {
      $allLines.Add("SKIP COMPLETE $name")
      Write-Host "SKIP COMPLETE $name"
      continue
    }
    $allLines.Add("SEQUENCE START $name " + (Get-Date).ToString("o"))
    Write-Host "=== $name $(Get-Date -Format 'HH:mm:ss')"
    $outPng = Join-Path $Out ($name + ".f1.png")
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $lines = & powershell -NoProfile -File $capture -Root $Tree -Scenario $job[0] -OutPng $outPng `
      -Cols $job[1] -Rows $job[2] -Fixtures $Fixtures -Commit $Commit 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    foreach ($line in $lines) { $allLines.Add("$line") }
    $lines | ForEach-Object { Write-Host "  $_" }
    if ($rc -ne 0) { throw "capture sequence $name failed with rc=$rc" }
    if (-not (Test-Complete $name $job[3])) { throw "capture sequence $name is incomplete" }
    $allLines.Add("SEQUENCE COMPLETE $name " + (Get-Date).ToString("o"))
  }
  $allLines.Add("MATRIX DONE " + (Get-Date).ToString("o"))
  Write-RunLog "complete"
} catch {
  $allLines.Add("MATRIX ERROR " + $_.Exception.Message)
  Write-RunLog "error"
  throw
} finally {
  if ($createdLock) {
    Remove-Item -LiteralPath $lockPath -ErrorAction Stop
    $createdLock = $false
    $allLines.Add("LOCK RELEASED " + (Get-Date).ToString("o"))
    Write-RunLog "lock-released"
  }
}
