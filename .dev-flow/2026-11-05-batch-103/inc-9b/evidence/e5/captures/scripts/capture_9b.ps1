# CAP9b: one fresh real Windows Terminal window per scene/size, with per-frame ACK.
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Scenario,
  [Parameter(Mandatory = $true)][string]$Fixtures,
  [Parameter(Mandatory = $true)][string]$OutPng,
  [int]$Cols = 118,
  [int]$Rows = 54,
  [string]$Commit = "d05b5180e5f48d4a167d13e7fb45b24586293eb6",
  [int]$SettleSeconds = 240,
  [string]$Python = "$env:USERPROFILE\anaconda3\envs\s19env\python.exe"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path -LiteralPath $Root).Path
if (-not $OutPng.EndsWith(".f1.png")) { throw "OutPng must be the sequence's .f1.png path" }
$basePng = $OutPng.Substring(0, $OutPng.Length - 7)
$jobScene = $Scenario -in @("decode", "preview", "stage-encode", "stage-refresh", "stage-refused")
$framePaths = @($OutPng, ($basePng + ".f2.png"))
if ($jobScene) { $framePaths += ($basePng + ".idle.png") }

$stamp = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$scratch = Join-Path $env:TEMP ("zq_cap9b_" + $stamp)
$iso = Join-Path $scratch "capiso"
$base = Join-Path $scratch "workarea"
New-Item -ItemType Directory -Force -Path (
  (Join-Path $iso "home"), (Join-Path $iso "xdg_config"), (Join-Path $iso "xdg_cache"),
  (Join-Path $iso "xdg_data"), (Join-Path $iso "xdg_state"), (Join-Path $iso "localappdata")
) | Out-Null
$isoHome = Join-Path $iso "home"
$isoConfig = Join-Path $iso "xdg_config"
$isoCache = Join-Path $iso "xdg_cache"
$isoData = Join-Path $iso "xdg_data"
$isoState = Join-Path $iso "xdg_state"
$isoLocal = Join-Path $iso "localappdata"

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class ZqU32 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
[void][ZqU32]::SetProcessDPIAware()

function Find-ByTitle([string]$title) {
  $script:found = [IntPtr]::Zero
  $cb = [ZqU32+EnumProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 256
    [void][ZqU32]::GetWindowText($h, $sb, 256)
    if ($sb.ToString() -eq $title) { $script:found = $h; return $false }
    return $true
  }
  [void][ZqU32]::EnumWindows($cb, [IntPtr]::Zero)
  return $script:found
}

function Test-NearlyBlack([System.Drawing.Bitmap]$bmp) {
  $total = 0; $dark = 0
  for ($y = 0; $y -lt $bmp.Height; $y += 7) {
    for ($x = 0; $x -lt $bmp.Width; $x += 7) {
      $c = $bmp.GetPixel($x, $y); $total++
      if ($c.R -lt 10 -and $c.G -lt 10 -and $c.B -lt 10) { $dark++ }
    }
  }
  return ($dark -gt ($total * 0.98))
}

function Save-WindowPng([IntPtr]$hwnd, [ZqU32+RECT]$rect, [string]$path) {
  $w = $rect.Right - $rect.Left; $h = $rect.Bottom - $rect.Top
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  try {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [ZqU32]::PrintWindow($hwnd, $hdc, 2)
    $g.ReleaseHdc($hdc); $g.Dispose()
    $used = "PrintWindow"
    if (-not $ok -or (Test-NearlyBlack $bmp)) {
      $g2 = [System.Drawing.Graphics]::FromImage($bmp)
      $g2.CopyFromScreen($rect.Left, $rect.Top, 0, 0, (New-Object System.Drawing.Size($w, $h)))
      $g2.Dispose(); $used = "CopyFromScreen"
    }
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    return $used
  } finally { $bmp.Dispose() }
}

function Get-ReportValue([string[]]$reportLines, [string]$key) {
  $prefix = $key + "="
  $line = $reportLines | Where-Object { $_.StartsWith($prefix) } | Select-Object -Last 1
  if ($null -eq $line) { return $null }
  return $line.Substring($prefix.Length)
}

$title = "b103-9b-$Scenario-$Cols-$stamp"
$driver = Join-Path $PSScriptRoot "capture_9b_driver.py"
$outPath = [IO.Path]::GetFullPath($OutPng)
$report = $outPath + ".report"
$ack = Join-Path $scratch "capture.ack"
$releaseFile = Join-Path $scratch "release.flag"
New-Item -ItemType Directory -Force (Split-Path -Parent $outPath) | Out-Null
foreach ($path in $framePaths) {
  Remove-Item -LiteralPath $path, ($path + ".txt") -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue

$launcherPs1 = Join-Path $scratch "zq_launch.ps1"
$launcherTemplate = @'
$ErrorActionPreference = 'Stop'
Set-Content -LiteralPath '__PIDFILE__' -Value $PID -Encoding ASCII
foreach ($k in 'NO_COLOR','TERM','CLICOLOR','CLICOLOR_FORCE','FORCE_COLOR') {
  Remove-Item "Env:$k" -ErrorAction SilentlyContinue
}
Remove-Item Env:PYTHONPATH, Env:PYTHONHOME, Env:PYTHONSTARTUP -ErrorAction SilentlyContinue
$env:COLORTERM = 'truecolor'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONUTF8 = '1'
$env:HOME = '__ISO_HOME__'
$env:XDG_CONFIG_HOME = '__ISO_CONFIG__'
$env:XDG_CACHE_HOME = '__ISO_CACHE__'
$env:XDG_DATA_HOME = '__ISO_DATA__'
$env:XDG_STATE_HOME = '__ISO_STATE__'
$env:LOCALAPPDATA = '__ISO_LOCAL__'
& '__PYTHON__' -I -B '__DRIVER__' --root '__ROOT__' --scenario __SCENARIO__ --fixtures '__FIXTURES__' --size __SIZE__ --commit __COMMIT__ --base '__BASE__' --report '__REPORT__' --release '__RELEASE__' --ack '__ACK__' --png-f1 '__PNG_F1__'
exit $LASTEXITCODE
'@
$pidFile = Join-Path $scratch "launcher.pid"
$launcherText = $launcherTemplate.Replace('__PIDFILE__', $pidFile)
$launcherText = $launcherText.Replace('__ISO_HOME__', $isoHome)
$launcherText = $launcherText.Replace('__ISO_CONFIG__', $isoConfig)
$launcherText = $launcherText.Replace('__ISO_CACHE__', $isoCache)
$launcherText = $launcherText.Replace('__ISO_DATA__', $isoData)
$launcherText = $launcherText.Replace('__ISO_STATE__', $isoState)
$launcherText = $launcherText.Replace('__ISO_LOCAL__', $isoLocal)
$launcherText = $launcherText.Replace('__PYTHON__', $Python)
$launcherText = $launcherText.Replace('__DRIVER__', $driver)
$launcherText = $launcherText.Replace('__ROOT__', $Root)
$launcherText = $launcherText.Replace('__SCENARIO__', $Scenario)
$launcherText = $launcherText.Replace('__FIXTURES__', $Fixtures)
$launcherText = $launcherText.Replace('__SIZE__', ("{0}x{1}" -f $Cols, $Rows))
$launcherText = $launcherText.Replace('__COMMIT__', $Commit)
$launcherText = $launcherText.Replace('__BASE__', $base)
$launcherText = $launcherText.Replace('__REPORT__', $report)
$launcherText = $launcherText.Replace('__RELEASE__', $releaseFile)
$launcherText = $launcherText.Replace('__ACK__', $ack)
$launcherText = $launcherText.Replace('__PNG_F1__', $outPath)
Set-Content -LiteralPath $launcherPs1 -Value $launcherText -Encoding ASCII

$argLine = '-w new --size {0},{1} --title "{2}" --suppressApplicationTitle powershell -NoProfile -ExecutionPolicy Bypass -File "{3}"' -f `
  $Cols, $Rows, $title, $launcherPs1
Start-Process "wt.exe" -ArgumentList $argLine | Out-Null

function Get-Descendants([int]$RootPid) {
  $all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId
  $out = New-Object System.Collections.Generic.List[int]
  $queue = New-Object System.Collections.Generic.Queue[int]
  $queue.Enqueue($RootPid)
  while ($queue.Count -gt 0) {
    $p = $queue.Dequeue()
    foreach ($c in ($all | Where-Object { $_.ParentProcessId -eq $p })) {
      $out.Add([int]$c.ProcessId); $queue.Enqueue([int]$c.ProcessId)
    }
  }
  return $out
}

function Close-CaptureWindow([string]$Title) {
  $shellPid = $null
  if (Test-Path -LiteralPath $pidFile) {
    $txt = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($txt -match '^\d+$') { $shellPid = [int]$txt }
  }
  if ($null -eq $shellPid) {
    if ((Find-ByTitle $Title) -eq [IntPtr]::Zero) { return $null }
    return "window '$Title' is still open and its launcher PID was never written (not closed: never by title)"
  }
  Write-Host ("CLOSING launcher PID $shellPid")
  Set-Content -LiteralPath $releaseFile -Value "1" -Encoding ASCII
  for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Milliseconds 250
    if ((Find-ByTitle $Title) -eq [IntPtr]::Zero) { return $null }
  }
  $victims = @(Get-Descendants $shellPid) + @($shellPid)
  [array]::Reverse($victims)
  foreach ($v in $victims) { Stop-Process -Id $v -Force -ErrorAction SilentlyContinue }
  for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Milliseconds 250
    if ((Find-ByTitle $Title) -eq [IntPtr]::Zero) { return $null }
  }
  return "window '$Title' is still open after PID-only fallback"
}

$hwnd = [IntPtr]::Zero
$primaryError = $null
$cleanupError = $null
$firstRow = $null
try {
  for ($i = 0; $i -lt 80 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 250
    $hwnd = Find-ByTitle $title
  }
  if ($hwnd -eq [IntPtr]::Zero) { throw "window did not appear" }
  [void][ZqU32]::ShowWindow($hwnd, 9)
  [void][ZqU32]::SetForegroundWindow($hwnd)
  $rect = New-Object ZqU32+RECT
  for ($seq = 1; $seq -le $framePaths.Count; $seq++) {
    $png = $framePaths[$seq - 1]
    $ready = $false
    $deadline = (Get-Date).AddSeconds($SettleSeconds)
    while ((Get-Date) -lt $deadline -and -not $ready) {
      if (Test-Path -LiteralPath $report) {
        try {
          $reportLines = @(Get-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop)
          $reportSeq = Get-ReportValue $reportLines "capture_seq"
          $surface = Get-ReportValue $reportLines "surface"
          $reportName = Get-ReportValue $reportLines "png_name"
          if ($reportSeq -eq "$seq" -and "$surface".StartsWith("error")) {
            $diag = $basePng + ".error.seq$seq.png"
            [IO.File]::Copy($report, $diag + ".txt", $true)
            try {
              [void][ZqU32]::GetWindowRect($hwnd, [ref]$rect)
              if (($rect.Right - $rect.Left) -gt 100 -and ($rect.Bottom - $rect.Top) -gt 100) {
                [void](Save-WindowPng $hwnd $rect $diag)
              }
            } catch { }
            $reportLines | ForEach-Object { Write-Output ("REPORT " + $_) }
            throw "driver reported surface=error at sequence $seq (diagnostic only)"
          }
          if ($reportSeq -eq "$seq" -and $surface -eq "ready" -and $reportName -eq (Split-Path -Leaf $png)) {
            $ready = $true
          }
        } catch {
          if ($_.Exception.Message -match 'driver reported surface=error') { throw }
        }
      }
      if (-not $ready) { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ready) { throw "driver did not report exact ready sequence $seq within $SettleSeconds s" }
    $valid = $false
    for ($i = 0; $i -lt 20 -and -not $valid; $i++) {
      [void][ZqU32]::GetWindowRect($hwnd, [ref]$rect)
      if (($rect.Right - $rect.Left) -gt 100 -and ($rect.Bottom - $rect.Top) -gt 100) { $valid = $true }
      else { Start-Sleep -Milliseconds 200 }
    }
    if (-not $valid) { throw "invalid window rectangle" }
    $actualSize = Get-ReportValue $reportLines "app_size"
    if ($actualSize -ne ("{0}x{1}" -f $Cols, $Rows)) { throw "grid mismatch: $actualSize" }
    $row = Get-ReportValue $reportLines "painted_sheet_top_row"
    $dot = [char]0x00B7
    $replacement = [char]0xFFFD
    $nameNeedle = switch ($Scenario) {
      "name-markup" { "decode [@click=app.quit]X[/] $dot" }
      "name-brackets" { "decode A[b]B $dot" }
      "name-esc" { "decode A$replacement[2J $dot" }
      "name-c1" { "decode B${replacement}C $dot" }
      "name-short" { "decode N $dot" }
      default { $null }
    }
    if ($nameNeedle -and -not $row.Contains($nameNeedle)) { throw "painted hostile/name literal mismatch" }
    if ($seq -eq 1) { $firstRow = $row }
    if ($seq -eq 2) {
      if ($row -eq $firstRow) { throw "f2 painted row equals f1" }
      if ((Get-ReportValue $reportLines "frame_pair_valid") -ne "True") { throw "driver did not validate the spinner pair" }
    }
    $method = Save-WindowPng $hwnd $rect $png
    $check = [System.Drawing.Bitmap]::FromFile($png)
    try {
      if (Test-NearlyBlack $check) { throw "captured frame $seq is nearly black" }
      $pixelWidth = $check.Width; $pixelHeight = $check.Height
    } finally { $check.Dispose() }
    $extra = @(
      "png_width=$pixelWidth", "png_height=$pixelHeight", "capture_method=$method",
      "png_bytes=$((Get-Item $png).Length)", "png_captured_at=$((Get-Date).ToString('o'))"
    )
    [IO.File]::Copy($report, $png + ".txt", $true)
    [IO.File]::AppendAllText($png + ".txt", ("`n" + ($extra -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($ack + ".$seq", "$seq", [Text.Encoding]::ASCII)
    Write-Output ("CAPTURED {0}  {1}x{2}px  grid={3}x{4}  method={5}  bytes={6}  seq={7}  t={8:o}" -f `
      (Split-Path -Leaf $png), $pixelWidth, $pixelHeight, $Cols, $Rows, $method, (Get-Item $png).Length, $seq, (Get-Date))
    if ($seq -eq 2) {
      Write-Output ("FRAME_PAIR {0} delta_s={1}" -f (Split-Path -Leaf $basePng), (Get-ReportValue $reportLines "frame_delta_s"))
    }
  }
} catch {
  $primaryError = $_
} finally {
  $cleanupError = Close-CaptureWindow -Title $title
  if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $scratch) {
    if ($cleanupError) { $cleanupError += "; " }
    $cleanupError += "scratch zq_cap9b_$stamp was not removed"
  }
  Write-Output ("CLEANUP title={0} scratch_removed={1} error={2}" -f $title, (-not (Test-Path -LiteralPath $scratch)), $cleanupError)
}
if ($primaryError) {
  if ($cleanupError) { Write-Output ("CLEANUP-ALSO-FAILED: " + $cleanupError) }
  throw $primaryError
}
if ($cleanupError) { throw "capture cleanup failed: $cleanupError" }
