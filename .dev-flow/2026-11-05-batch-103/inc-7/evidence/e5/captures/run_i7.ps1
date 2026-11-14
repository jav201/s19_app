# run_i7.ps1 - every Inc 7 E5 capture, one window at a time (X7; adapted from inc-8 CAP8 run_all.ps1).
# Usage: powershell -NoProfile -File run_i7.ps1 -Root <tree> [-BaseRoot <base archive>] [-Only <scenario,...>]
# The isolated-HOME folder name comes from RUNNER_HOME_NAME (set by the caller, PP-03).
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$BaseRoot = "",
  [string]$Only = ""
)
$here = $PSScriptRoot
$wide = @(@(118, 54), @(220, 60))
$plan = [ordered]@{
  "layout" = @(@(118, 54), @(220, 60), @(80, 24), @(120, 30), @(160, 40), @(80, 54))
  "scrolled" = @(, @(80, 54))
  "text" = $wide; "field-all" = $wide
  "drop-cuvre" = $wide; "drop-0017" = $wide; "drop-zzzz" = $wide
  "mode-invalid" = $wide; "card-missing" = $wide; "card-dup" = $wide
  "window" = $wide; "window-big" = $wide; "similar-11" = $wide; "missing-25" = $wide
  "add-drop" = $wide; "add-enter" = $wide
  "hostile" = $wide; "hostile-drop" = $wide; "long-drop" = $wide; "unit300" = $wide
  "f2-typed" = $wide
}
$want = @()
if ($Only) { $want = $Only.Split(",") }
foreach ($sc in $plan.Keys) {
  if ($want.Count -gt 0 -and -not ($want -contains $sc)) { continue }
  foreach ($size in $plan[$sc]) {
    $c = $size[0]; $r = $size[1]
    $png = Join-Path $here ("{0}.{1}x{2}.png" -f $sc, $c, $r)
    "=== $sc $c x $r"
    $o = powershell -NoProfile -File (Join-Path $here "capture_i7.ps1") -Root $Root -Scenario $sc -Cols $c -Rows $r -OutPng $png 2>&1 | Out-String
    ($o -split "`n" | Where-Object { $_ -match 'CAPTURED|surface=|rror|failed|still open' }) -join "`n"
    if ($BaseRoot -and $sc -eq "f2-typed") {
      $png = Join-Path $here ("base-{0}.{1}x{2}.png" -f $sc, $c, $r)
      "=== base $sc $c x $r"
      $o = powershell -NoProfile -File (Join-Path $here "capture_i7.ps1") -Root $BaseRoot -Scenario $sc -Cols $c -Rows $r -OutPng $png 2>&1 | Out-String
      ($o -split "`n" | Where-Object { $_ -match 'CAPTURED|surface=|rror|failed|still open' }) -join "`n"
    }
  }
}
"ALL DONE"
