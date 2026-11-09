# capture_all_windows.ps1 - batch-103 Inc 12 E5: the AT-B103-I12-2 capture
# set. Each capture opens and closes its own Windows Terminal window
# (capture_windows.ps1), so no window is reused or left behind.
#
#   powershell -NoProfile -File capture_all_windows.ps1 -Root <after> -BeforeRoot <before> -OutDir out
#   powershell -NoProfile -File capture_all_windows.ps1 -Root <after> -OutDir out -Only v171

param(
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$BeforeRoot = "",
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$Only = "",
  [switch]$SkipBefore
)
$cap = Join-Path $PSScriptRoot "capture_windows.ps1"

# AT-B103-I12-2: before/after at 80x50, 118x54 and 220x60 of the four page
# scenarios, plus the two extra captures (SYNMAP mid-scroll at 80x54, V171
# Name-line at 118x54). No personal path is hard-coded: Root / BeforeRoot /
# OutDir are parameters, and the Python default lives in capture_windows.ps1.
$sizes = @(@(80, 50), @(118, 54), @(220, 60))
$scenarios = @("synmap", "page64", "v171", "curve")
$extras = @(@("synmap-midscroll", 80, 54), @("v171-nameline", 118, 54))

$fail = 0
foreach ($scn in $scenarios) {
  if ($Only -ne "" -and $scn -ne $Only) { continue }
  foreach ($size in $sizes) {
    $cols, $rows = $size
    if (-not $SkipBefore -and $BeforeRoot -ne "") {
      $out = Join-Path $OutDir ("{0}.{1}x{2}.before.png" -f $scn, $cols, $rows)
      try { & $cap -Root $BeforeRoot -Scenario $scn -OutPng $out -Cols $cols -Rows $rows }
      catch { $fail++; Write-Output ("FAILED {0}: {1}" -f $out, $_) }
    }
    $out = Join-Path $OutDir ("{0}.{1}x{2}.after.png" -f $scn, $cols, $rows)
    try { & $cap -Root $Root -Scenario $scn -OutPng $out -Cols $cols -Rows $rows }
    catch { $fail++; Write-Output ("FAILED {0}: {1}" -f $out, $_) }
  }
}
foreach ($ex in $extras) {
  $scn, $cols, $rows = $ex
  if ($Only -ne "" -and $scn -ne $Only) { continue }
  if (-not $SkipBefore -and $BeforeRoot -ne "") {
    $out = Join-Path $OutDir ("{0}.{1}x{2}.before.png" -f $scn, $cols, $rows)
    try { & $cap -Root $BeforeRoot -Scenario $scn -OutPng $out -Cols $cols -Rows $rows }
    catch { $fail++; Write-Output ("FAILED {0}: {1}" -f $out, $_) }
  }
  $out = Join-Path $OutDir ("{0}.{1}x{2}.after.png" -f $scn, $cols, $rows)
  try { & $cap -Root $Root -Scenario $scn -OutPng $out -Cols $cols -Rows $rows }
  catch { $fail++; Write-Output ("FAILED {0}: {1}" -f $out, $_) }
}
Write-Output "DONE failures=$fail"
