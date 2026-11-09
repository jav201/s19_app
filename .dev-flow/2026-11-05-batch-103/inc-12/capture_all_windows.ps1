# capture_all_windows.ps1 - batch-103 Inc 12 E5: the AT-B103-I12-2 capture
# set. Each capture opens and closes its own Windows Terminal window
# (capture_windows.ps1), so no window is reused or left behind. A complete
# before/after set requires -BeforeRoot unless -SkipBefore is given, and the
# script exits non-zero on any failure or missing output file.
#
#   powershell -NoProfile -File capture_all_windows.ps1 -Root <after> -BeforeRoot <before> -OutDir out
#   powershell -NoProfile -File capture_all_windows.ps1 -Root <after> -OutDir out -Only v171 -SkipBefore

param(
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$BeforeRoot = "",
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$Only = "",
  [switch]$SkipBefore
)
$cap = Join-Path $PSScriptRoot "capture_windows.ps1"

# A complete before/after set needs the "before" checkout unless the operator
# explicitly asks for after-only with -SkipBefore.
if (-not $SkipBefore -and [string]::IsNullOrWhiteSpace($BeforeRoot)) {
  throw "capture_all_windows.ps1 requires -BeforeRoot unless -SkipBefore is set"
}

# AT-B103-I12-2: before/after at 80x50, 118x54 and 220x60 of the four page
# scenarios, plus the two extra captures (SYNMAP mid-scroll at 80x54, V171
# Name-line at 118x54). No personal path is hard-coded: Root / BeforeRoot /
# OutDir are parameters, and the Python default lives in capture_windows.ps1.
$sizes = @(@(80, 50), @(118, 54), @(220, 60))
$scenarios = @("synmap", "page64", "v171", "curve")
$extras = @(@("synmap-midscroll", 80, 54), @("v171-nameline", 118, 54))

$script:fail = 0

function Invoke-Capture([string]$CaptureRoot, [string]$Scenario, [string]$OutPng, [int]$Cols, [int]$Rows) {
  try {
    & $cap -Root $CaptureRoot -Scenario $Scenario -OutPng $OutPng -Cols $Cols -Rows $Rows
  } catch {
    $script:fail++
    Write-Output ("FAILED {0}: {1}" -f $OutPng, $_)
    return
  }
  if (-not (Test-Path -LiteralPath $OutPng)) {
    $script:fail++
    Write-Output ("FAILED {0}: no output file produced" -f $OutPng)
  }
}

foreach ($scn in $scenarios) {
  if ($Only -ne "" -and $scn -ne $Only) { continue }
  foreach ($size in $sizes) {
    $cols, $rows = $size
    if (-not $SkipBefore) {
      $out = Join-Path $OutDir ("{0}.{1}x{2}.before.png" -f $scn, $cols, $rows)
      Invoke-Capture -CaptureRoot $BeforeRoot -Scenario $scn -OutPng $out -Cols $cols -Rows $rows
    }
    $out = Join-Path $OutDir ("{0}.{1}x{2}.after.png" -f $scn, $cols, $rows)
    Invoke-Capture -CaptureRoot $Root -Scenario $scn -OutPng $out -Cols $cols -Rows $rows
  }
}
foreach ($ex in $extras) {
  $scn, $cols, $rows = $ex
  if ($Only -ne "" -and $scn -ne $Only) { continue }
  if (-not $SkipBefore) {
    $out = Join-Path $OutDir ("{0}.{1}x{2}.before.png" -f $scn, $cols, $rows)
    Invoke-Capture -CaptureRoot $BeforeRoot -Scenario $scn -OutPng $out -Cols $cols -Rows $rows
  }
  $out = Join-Path $OutDir ("{0}.{1}x{2}.after.png" -f $scn, $cols, $rows)
  Invoke-Capture -CaptureRoot $Root -Scenario $scn -OutPng $out -Cols $cols -Rows $rows
}

Write-Output "DONE failures=$script:fail"
exit $script:fail
