# capture_windows.ps1 - batch-103 Inc 12 E5: one real-Windows-Terminal capture.
# Opens a NEW Windows Terminal window (truecolor, NO_COLOR removed) running
# .dev-flow/2026-11-05-batch-103/inc-12/capture_driver.py against the tree in
# -Root under ``python -I -B``, saves that exact window as a PNG, then closes
# the window it opened and deletes only its own scratch. It never touches a
# window it did not open (-w new plus a unique title). The isolated HOME /
# XDG_* / LOCALAPPDATA (and with it the real recent-files store) and the
# color/PYTHON* variables are set INSIDE the launched command by a scratch
# launcher (a tiny PowerShell script wt runs), never via wt.exe's environment
# inheritance (wt may connect to an already-running Windows Terminal whose
# process environment is not this script's). Instead of a fixed settle it
# polls the driver's sidecar for surface=ready/error and captures the moment
# the surface is ready; on surface=error it captures for diagnosis, prints the
# failure and exits non-zero (never reports success). The finally block
# verifies the opened window actually closed and the scratch is gone, and
# fails loudly if either could not be cleaned up.
#
#   powershell -NoProfile -File capture_windows.ps1 -Root . -Scenario synmap -OutPng out/synmap.80x50.png -Cols 80 -Rows 50
#   powershell -NoProfile -File capture_windows.ps1 -Root . -Scenario curve -Cols 118 -Rows 54 -OutPng out/curve.118x54.png

param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Scenario,
  [Parameter(Mandatory = $true)][string]$OutPng,
  [int]$Cols = 118,
  [int]$Rows = 54,
  [int]$SettleSeconds = 15,
  [string]$Python = "$env:USERPROFILE\anaconda3\envs\s19env\python.exe"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path -LiteralPath $Root).Path

# ---------------------------------------------------------------------------
# One scratch root owns everything this capture creates: the work area the
# driver uses, and the isolated HOME / XDG_* / LOCALAPPDATA the launched app
# reads (the real recent-files store lives under %LOCALAPPDATA%, so isolating
# it is what keeps the operator's store untouched).
# ---------------------------------------------------------------------------
$stamp = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$scratch = Join-Path $env:TEMP ("zq_cap_" + $stamp)
$iso = Join-Path $scratch "zq_iso_user"
$base = Join-Path $scratch "workarea"
New-Item -ItemType Directory -Force -Path (
  (Join-Path $iso "home"),
  (Join-Path $iso "xdg_config"),
  (Join-Path $iso "xdg_cache"),
  (Join-Path $iso "xdg_data"),
  (Join-Path $iso "xdg_state"),
  (Join-Path $iso "localappdata")
) | Out-Null

# The isolated environment is applied INSIDE the launched command (the
# scratch launcher built just before Start-Process), not here: wt.exe can
# attach to a running Windows Terminal whose process environment is unrelated
# to this script's, so only a command-level set/remove is reliable. HOME /
# XDG_* / LOCALAPPDATA point below ``zq_iso_user``; NO_COLOR is REMOVED (an
# empty NO_COLOR still trips Textual's ``pop('NO_COLOR') is not None``) and
# COLORTERM=truecolor; PYTHON* is pinned/cleared so ``python -I`` starts clean.
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
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
# Physical pixels: without this, GetWindowRect returns scaled (logical)
# coordinates on a display above 100 % and the PNG keeps only the top-left part.
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

$title = "b103-i12-$Scenario-$Cols-$stamp"
$driver = Join-Path $PSScriptRoot "capture_driver.py"
$outPath = [IO.Path]::GetFullPath($OutPng)
$report = $outPath + ".txt"
New-Item -ItemType Directory -Force (Split-Path -Parent $outPath) | Out-Null

# Scratch launcher: the launched command removes/sets the isolated environment
# itself, then runs the driver under ``python -I -B`` (isolated, no .pyc); the
# driver inserts -Root at sys.path[0] itself. NO_COLOR is removed (not emptied)
# so Textual sees it as absent. Placeholders are replaced with the real paths.
$launcherPs1 = Join-Path $scratch "zq_launch.ps1"
$launcherTemplate = @'
$ErrorActionPreference = 'Stop'
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
& '__PYTHON__' -I -B '__DRIVER__' --root '__ROOT__' --scenario __SCENARIO__ --base '__BASE__' --report '__REPORT__'
exit $LASTEXITCODE
'@
$launcherText = $launcherTemplate
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
$launcherText = $launcherText.Replace('__BASE__', $base)
$launcherText = $launcherText.Replace('__REPORT__', $report)
Set-Content -LiteralPath $launcherPs1 -Value $launcherText -Encoding ASCII

# -w new opens a NEW window; the unique title is how we find (and later close)
# only our own window. --suppressApplicationTitle keeps that title even if the
# app changes it.
$argLine = '-w new --size {0},{1} --title "{2}" --suppressApplicationTitle powershell -NoProfile -ExecutionPolicy Bypass -File "{3}"' -f `
  $Cols, $Rows, $title, $launcherPs1
Start-Process "wt.exe" -ArgumentList $argLine | Out-Null

function Close-CaptureWindow([string]$Title, [IntPtr]$KnownHwnd) {
  # Close the unique-title window we opened. When discovery failed earlier
  # ($KnownHwnd -eq [IntPtr]::Zero), re-find it once so a late-appearing
  # window is still closed. Returns $null on success, else an error string.
  $h = $KnownHwnd
  if ($h -eq [IntPtr]::Zero) { $h = Find-ByTitle $Title }
  if ($h -eq [IntPtr]::Zero) { return $null }
  for ($i = 0; $i -lt 20; $i++) {
    [void][ZqU32]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 300
    $still = Find-ByTitle $Title
    if ($still -eq [IntPtr]::Zero) { return $null }
    $h = $still
  }
  return "window '$Title' did not close after best-effort WM_CLOSE"
}

$hwnd = [IntPtr]::Zero
$primaryError = $null
$cleanupError = $null
try {
  for ($i = 0; $i -lt 80 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 250
    $hwnd = Find-ByTitle $title
  }
  if ($hwnd -eq [IntPtr]::Zero) { throw "window '$title' did not appear" }
  [void][ZqU32]::ShowWindow($hwnd, 9)
  [void][ZqU32]::SetForegroundWindow($hwnd)
  # Poll the driver's sidecar instead of a fixed settle: capture as soon as
  # the surface is ready, and stop as soon as the driver reports an error.
  $surface = $null
  $deadline = (Get-Date).AddSeconds($SettleSeconds)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $report) {
      $surfaceLine = $null
      try {
        $surfaceLine = Get-Content -LiteralPath $report -ErrorAction Stop |
          Where-Object { $_ -match '^surface=' } | Select-Object -Last 1
      } catch { }
      if ($surfaceLine) {
        if ($surfaceLine -match '^surface=ready') { $surface = "ready"; break }
        if ($surfaceLine -match '^surface=error') { $surface = "error"; break }
      }
    }
    Start-Sleep -Milliseconds 200
  }

  if ($null -eq $surface) {
    $still = Find-ByTitle $title
    if ($still -eq [IntPtr]::Zero) {
      throw "window '$title' vanished before the driver reported a surface"
    }
    throw "driver for '$title' did not report surface=ready/error within $SettleSeconds s"
  }

  $rect = New-Object ZqU32+RECT
  $valid = $false
  for ($i = 0; $i -lt 20 -and -not $valid; $i++) {
    [void][ZqU32]::GetWindowRect($hwnd, [ref]$rect)
    if (($rect.Right - $rect.Left) -gt 100 -and ($rect.Bottom - $rect.Top) -gt 100) { $valid = $true }
    else {
      Start-Sleep -Milliseconds 400
      $hwnd = Find-ByTitle $title
      if ($hwnd -eq [IntPtr]::Zero) { throw "window '$title' vanished (traceback in the app?)" }
    }
  }
  if (-not $valid) { throw "invalid rect for '$title'" }

  if ($surface -eq "error") {
    # Capture for diagnosis only; print the failure and never claim success.
    $diagMethod = "not-captured"
    try { $diagMethod = Save-WindowPng $hwnd $rect $outPath } catch { }
    if (Test-Path -LiteralPath $report) {
      foreach ($line in Get-Content -LiteralPath $report) { Write-Output ("REPORT " + $line) }
    }
    throw "driver reported surface=error for '$title' (diagnosis capture: $diagMethod)"
  }
  $method = Save-WindowPng $hwnd $rect $outPath
  Write-Output ("CAPTURED {0}  {1}x{2}px  grid={3}x{4}  method={5}  bytes={6}" -f `
    $outPath, ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top), $Cols, $Rows, $method, (Get-Item $outPath).Length)
  if (Test-Path -LiteralPath $report) {
    foreach ($line in Get-Content -LiteralPath $report) { Write-Output ("REPORT " + $line) }
  }
} catch {
  $primaryError = $_
} finally {
  $cleanupError = Close-CaptureWindow -Title $title -KnownHwnd $hwnd
  if (Test-Path -LiteralPath $scratch) {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $scratch) {
    if ($cleanupError) { $cleanupError += "; " }
    $cleanupError += "scratch zq_cap_$stamp was not removed"
  }
}
if ($primaryError) {
  if ($cleanupError) { Write-Output ("CLEANUP-ALSO-FAILED: " + $cleanupError) }
  throw $primaryError
}
if ($cleanupError) {
  throw "capture cleanup failed: $cleanupError"
}
