# run_all.ps1 - every Inc 8 capture, one window at a time (CAP8). Usage:
#   powershell -NoProfile -File run_all.ps1 -Root <checkout>
param([Parameter(Mandatory = $true)][string]$Root)
$here = $PSScriptRoot
$wide = @(@(118, 54), @(220, 60))
$plan = [ordered]@{
  "layout" = $wide; "rows" = $wide; "p046" = $wide; "number" = $wide; "notice" = $wide; "longmsg" = $wide
  "enum" = $wide; "mask" = $wide; "text" = $wide; "curve" = $wide; "array" = $wide; "refused" = $wide
  "bigtext" = $wide; "status-staged" = $wide; "status-notice" = $wide; "status-overlap" = $wide
  "narrow" = @(, @(80, 24)); "help" = $wide; "k1" = $wide
}
foreach ($sc in $plan.Keys) {
  foreach ($size in $plan[$sc]) {
    $c = $size[0]; $r = $size[1]
    $png = Join-Path $here ("{0}.{1}x{2}.png" -f $sc, $c, $r)
    "=== $sc $c x $r"
    $o = powershell -NoProfile -File (Join-Path $here "capture_i8.ps1") -Root $Root -Scenario $sc -Cols $c -Rows $r -OutPng $png 2>&1 | Out-String
    ($o -split "`n" | Where-Object { $_ -match 'CAPTURED|surface=|rror|failed|still open' }) -join "`n"
  }
}
"ALL DONE"
