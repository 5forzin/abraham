# guardscan.ps1 - hunt for ABR-T041 (guard-page interposition) and any
# other PAGE_GUARD anomaly on image pages.
#
# Nothing legitimate guards a module's .text: the only sanctioned guard
# pages are stack-growth pages (thread stacks) and whatever the app
# itself allocates privately. A VirtualQuery walk reporting
# PAGE_GUARD on a MEM_IMAGE page inside a loaded module is therefore a
# high-fidelity IOC for this technique class.
#
# Usage: powershell -NoProfile -File lab\bench\guardscan.ps1 [-Pid <id>]
# Without -Pid, scans every process the caller can open.

param(
    [int]$TargetPid = 0
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Vq {
    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, int len);
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr Base;
        public IntPtr AllocBase;
        public uint AllocProt;
        public ushort PartitionId;   // x64: 4 bytes of pad after AllocProtect
        public ushort Pad;
        public ulong Size;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
"@

# VirtualQueryEx needs PROCESS_QUERY_INFORMATION|PROCESS_VM_READ.
$PROCESS_QUERY_VMREAD = 0x410
$PAGE_GUARD = 0x100
$MEM_IMAGE = 0x1000000
$hits = 0
$targets = if ($TargetPid -gt 0) { @($TargetPid) } else { (Get-Process).Id }

foreach ($proc in $targets) {
    $h = [Vq]::OpenProcess($PROCESS_QUERY_VMREAD, $false, $proc)
    if ($h -eq [IntPtr]::Zero) { continue }
    try {
        $addr = [IntPtr]::Zero
        while ($true) {
            $mbi = New-Object Vq+MBI
            $r = [Vq]::VirtualQueryEx($h, $addr, [ref]$mbi, [Runtime.InteropServices.Marshal]::SizeOf($mbi))
            if ($r -eq 0) { break }
            if (($mbi.Protect -band $PAGE_GUARD) -ne 0 -and ($mbi.Type -band $MEM_IMAGE) -ne 0) {
                $name = (Get-Process -Id $proc -ErrorAction SilentlyContinue).ProcessName
                Write-Output ("GUARD-ON-IMAGE pid={0} ({1}) page=0x{2:X} protect=0x{3:X}" -f $proc, $name, $mbi.Base.ToInt64(), $mbi.Protect)
                $hits++
            }
            $next = $mbi.Base.ToInt64() + [long]$mbi.Size
            if ($next -le $mbi.Base.ToInt64()) { break }
            $addr = [IntPtr]$next
        }
    } finally { [Vq]::CloseHandle($h) | Out-Null }
}
Write-Output ("guardscan: {0} hit(s) across {1} process(es)" -f $hits, $targets.Count)
if ($TargetPid -eq 0 -and $hits -eq 0) { Write-Output "clean: no PAGE_GUARD on any image page" }
