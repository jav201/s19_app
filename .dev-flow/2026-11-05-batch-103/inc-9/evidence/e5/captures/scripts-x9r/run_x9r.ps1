# X9r re-capture matrix (HT-10): scenes on the head tree at 118x54 and 220x60, plus one pre-FX9d control (b21d5517).
# Usage: powershell -NoProfile -File run_x9r.ps1 [-Only name,name]
param([string[]]$Only = @())
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cap = Split-Path -Parent $here
$out = Join-Path $cap "out"
$fx = Join-Path $cap "fx"
$jobs = @()
foreach ($s in @("v2", "v2-vb1d", "v5b", "x-refused-decode", "ob-json")) {
  $jobs += ,@($s, 118, 54, "tree-head", "ab62093b", "r-$s")
  $jobs += ,@($s, 220, 60, "tree-head", "ab62093b", "r-$s")
}
$jobs += ,@("ob-json", 118, 54, "tree-b21", "b21d5517", "r-ob-json-pre-fx9d")
foreach ($j in $jobs) {
  if ($Only.Count -gt 0 -and ($Only -notcontains $j[5])) { continue }
  $name = "{0}.{1}x{2}" -f $j[5], $j[1], $j[2]
  $png = Join-Path $out ($name + ".png")
  Write-Host "=== $name $(Get-Date -Format 'HH:mm:ss')"
  $log = & powershell -NoProfile -File (Join-Path $here "capture_i9.ps1") -Root (Join-Path $cap $j[3]) -Scenario $j[0] -OutPng $png -Cols $j[1] -Rows $j[2] -Fixtures $fx -Commit $j[4] 2>&1 | Where-Object { $_ -match '^(CAPTURED|CLOSING|CLEANUP)|surface=|json_view|Exception|Error' } | ForEach-Object { "$_".Trim() }
  $log | ForEach-Object { Write-Host "  $_" }
}
Write-Host "DONE $(Get-Date -Format 'HH:mm:ss')"
