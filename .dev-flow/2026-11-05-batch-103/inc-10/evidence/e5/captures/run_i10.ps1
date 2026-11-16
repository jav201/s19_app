# run_i10.ps1 - every Inc 10 E5 capture, one window at a time (X10). Usage:
#   powershell -NoProfile -File run_i10.ps1 -Root <checkout>
# RUNNER_HOME_NAME must be set (capture_i10.ps1 names its isolated folder with it).
param([Parameter(Mandatory = $true)][string]$Root)
$here = $PSScriptRoot
$wide = @(@(118, 54), @(220, 60))
$plan = [ordered]@{ "idle" = $wide; "applied" = $wide; "format-hex" = $wide; "format-s19" = $wide; "numbered" = $wide }
foreach ($sc in $plan.Keys) {
  foreach ($size in $plan[$sc]) {
    $c = $size[0]; $r = $size[1]
    $png = Join-Path $here ("{0}.{1}x{2}.png" -f $sc, $c, $r)
    "=== $sc $c x $r"
    $o = powershell -NoProfile -File (Join-Path $here "capture_i10.ps1") -Root $Root -Scenario $sc -Cols $c -Rows $r -OutPng $png 2>&1 | Out-String
    ($o -split "`n" | Where-Object { $_ -match 'CAPTURED|surface=|rror|failed|still open' }) -join "`n"
  }
}
"ALL DONE"
