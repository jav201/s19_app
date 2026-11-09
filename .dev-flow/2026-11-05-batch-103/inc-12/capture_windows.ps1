# capture_windows.ps1 - batch-103 Inc 12 E5: one real-Windows-Terminal capture.
# Opens a NEW Windows Terminal window (truecolor, NO_COLOR unset) running
# .dev-flow/2026-11-05-batch-103/inc-12/capture_driver.py against the tree in
# -Root under ``python -I -B``, saves that exact window as a PNG, then closes
# the window it opened and deletes only its own scratch. It never touches a
# window it did not open (-w new plus a unique title), and the operator's real
# HOME / XDG_* / LOCALAPPDATA (and with it the real recent-files store) are
# isolated below a scratch ``zq_iso_user`` for the launched process.
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

# truecolor, NO_COLOR unset (as E13); PYTHONDONTWRITEBYTECODE=1 (no .pyc).
foreach ($k in "NO_COLOR", "TERM", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR") {
  [Environment]::SetEnvironmentVariable($k, $null, "Process")
  Remove-Item "Env:$k" -ErrorAction SilentlyContinue
}
$env:COLORTERM = "truecolor"
$env:PYTHONUTF8 = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:HOME = Join-Path $iso "home"
$env:XDG_CONFIG_HOME = Join-Path $iso "xdg_config"
$env:XDG_CACHE_HOME = Join-Path $iso "xdg_cache"
$env:XDG_DATA_HOME = Join-Path $iso "xdg_data"
$env:XDG_STATE_HOME = Join-Path $iso "xdg_state"
$env:LOCALAPPDATA = Join-Path $iso "localappdata"

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

# -w new opens a NEW window; the unique title is how we find (and later close)
# only our own window. --suppressApplicationTitle keeps that title even if the
# app changes it. The driver runs under ``python -I -B`` (isolated, no .pyc);
# it inserts -Root at sys.path[0] itself.
$argLine = '-w new --size {0},{1} --title "{2}" --suppressApplicationTitle "{3}" -I -B "{4}" --root "{5}" --scenario {6} --base "{7}" --report "{8}"' -f `
  $Cols, $Rows, $title, $Python, $driver, $Root, $Scenario, $base, $report
Start-Process "wt.exe" -ArgumentList $argLine | Out-Null

$hwnd = [IntPtr]::Zero
try {
  for ($i = 0; $i -lt 80 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 250
    $hwnd = Find-ByTitle $title
  }
  if ($hwnd -eq [IntPtr]::Zero) { throw "window '$title' did not appear" }
  [void][ZqU32]::ShowWindow($hwnd, 9)
  [void][ZqU32]::SetForegroundWindow($hwnd)
  Start-Sleep -Seconds $SettleSeconds

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
  $method = Save-WindowPng $hwnd $rect $outPath
  Write-Output ("CAPTURED {0}  {1}x{2}px  grid={3}x{4}  method={5}  bytes={6}" -f `
    $outPath, ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top), $Cols, $Rows, $method, (Get-Item $outPath).Length)
  if (Test-Path -LiteralPath $report) {
    foreach ($line in Get-Content -LiteralPath $report) { Write-Output ("REPORT " + $line) }
  }
} finally {
  if ($hwnd -ne [IntPtr]::Zero) {
    [void][ZqU32]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  Start-Sleep -Milliseconds 1500
  if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
}
