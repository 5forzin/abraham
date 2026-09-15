Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ClipDiag {
  [DllImport("user32.dll")] public static extern IntPtr GetOpenClipboardWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
'@
$h = [ClipDiag]::GetOpenClipboardWindow()
"open-clipboard-window: $h"
if ($h -ne [IntPtr]::Zero) {
  $holderPid = 0
  [void][ClipDiag]::GetWindowThreadProcessId($h, [ref]$holderPid)
  "holder-pid: $holderPid"
  Get-Process -Id $holderPid -ErrorAction SilentlyContinue | Select-Object ProcessName, Id, Path | Format-List | Out-String
}
