Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ClipRaw3 {
  [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr h);
  [DllImport("user32.dll")] public static extern bool CloseClipboard();
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
'@
$cw = [ClipRaw3]::GetConsoleWindow()
$fw = [ClipRaw3]::GetForegroundWindow()
"console-window: $cw  foreground-window: $fw"
foreach ($owner in @(@{n='NULL';v=[IntPtr]::Zero}, @{n='console';v=$cw}, @{n='foreground';v=$fw})) {
  $ok = [ClipRaw3]::OpenClipboard($owner.v)
  "owner $($owner.n) -> $ok"
  if ($ok) { [void][ClipRaw3]::CloseClipboard(); break }
}
