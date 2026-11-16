# Inc 8b E5 capture matrix (HT-10): every scene at 118x54 and 220x60, `end` and `grid` also at 80x24.
# Usage: powershell -NoProfile -File run_all_8b.ps1 -Tree <unpacked tree> -Fixtures <fx2 dir> -Out <captures dir> [-Only "name,name"] (skips scenes whose PNG already exists)
param([Parameter(Mandatory = $true)][string]$Tree, [Parameter(Mandatory = $true)][string]$Fixtures,
      [Parameter(Mandatory = $true)][string]$Out, [string[]]$Only = @())
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$jobs = @()
foreach ($s in @("grid", "end", "home", "enum", "bit", "text", "expanded", "filter", "array", "nan")) {
  $jobs += ,@($s, 118, 54); $jobs += ,@($s, 220, 60)
}
$jobs += ,@("end", 80, 24); $jobs += ,@("grid", 80, 24)
foreach ($j in $jobs) {
  $name = "{0}.{1}x{2}" -f $j[0], $j[1], $j[2]
  if ($Only.Count -gt 0 -and (($Only -join ",").Split(",") -notcontains $name)) { continue }
  if (Test-Path -LiteralPath (Join-Path $Out ($name + ".png"))) { continue }  # already taken: delete the PNG to re-take
  Write-Host "=== $name $(Get-Date -Format 'HH:mm:ss')"
  $log = & powershell -NoProfile -File (Join-Path $here "capture_8b.ps1") -Root $Tree -Scenario $j[0] -OutPng (Join-Path $Out ($name + ".png")) -Cols $j[1] -Rows $j[2] -Fixtures $Fixtures -Commit 7c4e377c 2>&1 |
    Where-Object { $_ -match '^(CAPTURED|CLOSING|CLEANUP)|surface=|Exception|Error|still open' } | ForEach-Object { "$_".Trim() }
  $log | ForEach-Object { Write-Host "  $_" }
}
Write-Host "DONE $(Get-Date -Format 'HH:mm:ss')"
