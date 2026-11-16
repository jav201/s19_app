# Runs the Inc 9 capture matrix sequentially. Usage: powershell -NoProfile -File run_all_i9.ps1 [-Only name,name]
param([string[]]$Only = @())
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cap = Split-Path -Parent $here
$out = Join-Path $cap "out"
$tree = Join-Path $cap "tree"
$both = @("i8v13","v1","v2","v2-summary","v2-large","v3","v4","v5a","v5b","v6-decoding","v6-window","v6-paged","v7-focus","v7-escape","v7-nofocus","v8-interp","v8-smooth","v9-ok","v9-notice","v9-refused","v9-cut","v10-encoding","v10-cut","v12-staged","v12-notice","v12-refused","v12-empty","v13-decoding","v13-undo","v13-nan","v13-texts","v13-novalue","v13-columns","v13-columns-smooth","x-refused-decode","x-refused-row")
$narrow = @("v14-map","v14-large","v9-cut","v10-cut","v10-encoding","v1")
$jobs = @()
foreach ($s in $both) { $jobs += ,@($s,118,54); $jobs += ,@($s,220,60) }
foreach ($s in $narrow) { $jobs += ,@($s,80,24) }
foreach ($j in $jobs) {
  if ($Only.Count -gt 0 -and ($Only -notcontains $j[0])) { continue }
  if ($Only.Count -eq 0 -and ($j[0] -like "v14-*") -and $j[1] -ne 80) { continue }
  $name = "{0}.{1}x{2}" -f $j[0], $j[1], $j[2]
  $png = Join-Path $out ($name + ".png")
  Write-Host "=== $name $(Get-Date -Format 'HH:mm:ss')"
  $log = & powershell -NoProfile -File (Join-Path $here "capture_i9.ps1") -Root $tree -Scenario $j[0] -OutPng $png -Cols $j[1] -Rows $j[2] 2>&1 | Where-Object { $_ -match '^(CAPTURED|CLOSING|CLEANUP)|surface=|status:|Exception|Error' } | ForEach-Object { "$_".Trim() }
  $log | ForEach-Object { Write-Host "  $_" }
}
Write-Host "DONE $(Get-Date -Format 'HH:mm:ss')"
