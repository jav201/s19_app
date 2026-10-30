# capture.ps1 - batch-100 enabler E13 (C-UX-5): one real-terminal capture.
# Opens a NEW Windows Terminal window (truecolor, NO_COLOR unset) running
# tools/e13/run.py against the tree in -Root, saves the window as a PNG, then
# closes that window and deletes the scratch work area it used. It never
# touches a window it did not open: -w new plus a unique title.
#
#   powershell -NoProfile -File tools/e13/capture.ps1 -Root . -Scenario pe-problems -OutPng out/pe-problems.118.png
#   powershell -NoProfile -File tools/e13/capture.ps1 -Root . -Scenario pe-saveback -Close -Cols 99 -Rows 54 -OutPng out/x.png

param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Scenario,
  [Parameter(Mandatory = $true)][string]$OutPng,
  [switch]$Close,
  [int]$Cols = 118,
  [int]$Rows = 54,
  [int]$SettleSeconds = 9,
  [string]$Python = "C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path -LiteralPath $Root).Path

foreach ($k in "NO_COLOR", "TERM", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR") {
  [Environment]::SetEnvironmentVariable($k, $null, "Process")
  Remove-Item "Env:$k" -ErrorAction SilentlyContinue
}
$env:PYTHONUTF8 = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = $Root

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class E13U32 {
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
[void][E13U32]::SetProcessDPIAware()

function Find-ByTitle([string]$title) {
  $script:found = [IntPtr]::Zero
  $cb = [E13U32+EnumProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 256
    [void][E13U32]::GetWindowText($h, $sb, 256)
    if ($sb.ToString() -eq $title) { $script:found = $h; return $false }
    return $true
  }
  [void][E13U32]::EnumWindows($cb, [IntPtr]::Zero)
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

function Save-WindowPng([IntPtr]$hwnd, [E13U32+RECT]$rect, [string]$path) {
  $w = $rect.Right - $rect.Left; $h = $rect.Bottom - $rect.Top
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  try {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [E13U32]::PrintWindow($hwnd, $hdc, 2)
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

$stamp = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$title = "E13-$Scenario-$Cols-$stamp"
$base = Join-Path $env:TEMP "e13_$stamp"
$runner = Join-Path $Root "tools\e13\run.py"
$outPath = [IO.Path]::GetFullPath($OutPng)
New-Item -ItemType Directory -Force (Split-Path -Parent $outPath) | Out-Null

$closeArg = ""
if ($Close) { $closeArg = " --close" }
# --suppressApplicationTitle keeps our title even though the app sets its own
$argLine = '-w new --size {0},{1} --title "{2}" --suppressApplicationTitle "{3}" "{4}" --scenario {5} --base "{6}"{7}' -f `
  $Cols, $Rows, $title, $Python, $runner, $Scenario, $base, $closeArg
Start-Process "wt.exe" -ArgumentList $argLine | Out-Null

$hwnd = [IntPtr]::Zero
try {
  for ($i = 0; $i -lt 80 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 250
    $hwnd = Find-ByTitle $title
  }
  if ($hwnd -eq [IntPtr]::Zero) { throw "window '$title' did not appear" }
  [void][E13U32]::ShowWindow($hwnd, 9)
  [void][E13U32]::SetForegroundWindow($hwnd)
  Start-Sleep -Seconds $SettleSeconds

  $rect = New-Object E13U32+RECT
  $valid = $false
  for ($i = 0; $i -lt 20 -and -not $valid; $i++) {
    [void][E13U32]::GetWindowRect($hwnd, [ref]$rect)
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
} finally {
  if ($hwnd -ne [IntPtr]::Zero) {
    [void][E13U32]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  Start-Sleep -Milliseconds 1500
  if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
}
