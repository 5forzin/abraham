Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ClipRaw {
  [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr h);
  [DllImport("user32.dll")] public static extern bool CloseClipboard();
}
'@
for ($i = 0; $i -lt 5; $i++) {
  $ok = [ClipRaw]::OpenClipboard([IntPtr]::Zero)
  "attempt ${i}: OpenClipboard(NULL) -> $ok (err $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
  if ($ok) { [void][ClipRaw]::CloseClipboard() }
  Start-Sleep -Milliseconds 200
}
