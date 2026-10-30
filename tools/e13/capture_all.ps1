# capture_all.ps1 - batch-100 enabler E13: every scenario at the three sizes
# C-UX-5 names (118x54, 220x60, 99x54). Each capture opens and closes its own
# Windows Terminal window (capture.ps1).
#
#   powershell -NoProfile -File tools/e13/capture_all.ps1 -Root . -OutDir <dir> [-Only pe-problems]

param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$Only = ""
)
$cap = Join-Path $PSScriptRoot "capture.ps1"
$plan = @(
  @("pe-clean", $false), @("pe-saveback", $false), @("pe-saveback", $true),
  @("pe-problems", $false), @("pe-damaged", $false)
)
$sizes = @(@(118, 54), @(220, 60), @(99, 54))
$fail = 0
foreach ($p in $plan) {
  $scn, $closed = $p
  if ($Only -ne "" -and $scn -ne $Only) { continue }
  $tag = if ($closed) { "$scn-closed" } else { $scn }
  foreach ($size in $sizes) {
    $out = Join-Path $OutDir ("{0}.{1}x{2}.png" -f $tag, $size[0], $size[1])
    try {
      if ($closed) { & $cap -Root $Root -Scenario $scn -Close -OutPng $out -Cols $size[0] -Rows $size[1] }
      else { & $cap -Root $Root -Scenario $scn -OutPng $out -Cols $size[0] -Rows $size[1] }
    } catch { $fail++; Write-Output ("FAILED {0}: {1}" -f $out, $_) }
  }
}
Write-Output "DONE failures=$fail"
