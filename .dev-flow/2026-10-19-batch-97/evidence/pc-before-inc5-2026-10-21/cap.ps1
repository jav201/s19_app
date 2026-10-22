param([string]$OutPng)
foreach ($k in "NO_COLOR","TERM","CLICOLOR","CLICOLOR_FORCE","FORCE_COLOR") { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
$env:PYTHONUTF8 = "1"; $env:PYTHONDONTWRITEBYTECODE = "1"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class U32G {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
$title = "GLYPH-RULER-B97"
$script:found = [IntPtr]::Zero
function Find([string]$t) { $script:found=[IntPtr]::Zero; $cb=[U32G+EnumProc]{ param($h,$l) $sb=New-Object System.Text.StringBuilder 256; [void][U32G]::GetWindowText($h,$sb,256); if($sb.ToString() -eq $t){$script:found=$h; return $false}; return $true }; [void][U32G]::EnumWindows($cb,[IntPtr]::Zero); return $script:found }
$py = "C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"
$script = Join-Path (Get-Location) "glyph_ruler.py"
$argLine = '--size 90,44 --title "{0}" "{1}" "{2}"' -f $title, $py, $script
Start-Process "wt.exe" -ArgumentList $argLine | Out-Null
$h=[IntPtr]::Zero; for($i=0;$i -lt 80 -and $h -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $h = Find $title }
if ($h -eq [IntPtr]::Zero) { throw "no window" }
[void][U32G]::ShowWindow($h,9); [void][U32G]::SetForegroundWindow($h); Start-Sleep -Seconds 6
$r = New-Object U32G+RECT; [void][U32G]::GetWindowRect($h,[ref]$r)
$w=$r.Right-$r.Left; $hh=$r.Bottom-$r.Top
$bmp = New-Object System.Drawing.Bitmap($w,$hh); $g=[System.Drawing.Graphics]::FromImage($bmp); $hdc=$g.GetHdc(); $ok=[U32G]::PrintWindow($h,$hdc,2); $g.ReleaseHdc($hdc); $g.Dispose()
$bmp.Save($OutPng,[System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
[void][U32G]::PostMessage($h,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
"CAPTURED $OutPng ${w}x${hh} printwindow=$ok"
