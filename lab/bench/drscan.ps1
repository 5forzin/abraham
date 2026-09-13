# drscan.ps1 - sensor-equivalent probe for x64 debug registers.
#
# Enumerates every thread of a target process, reads the thread CONTEXT
# debug registers via GetThreadContext (exactly the check an EDR or
# anti-cheat performs to detect hardware-breakpoint hooking), and emits
# one JSON line per scan. Any Dr0-Dr3 pointing at a module export such
# as ntdll!EtwEventWrite is the primary IOC for breakpoint-based
# AMSI/ETW suppression (see docs/detections/abr-t036.md).
#
# Usage (guest, elevated):
#   powershell -File drscan.ps1 -TargetPid 1234 -Loop 10 -IntervalSec 2
#   powershell -File drscan.ps1 -TargetPid 1234 -Once | out-file scan.jsonl
#
# Requires debug privilege only for processes owned by other users;
# same-user targets need plain THREAD_QUERY_INFORMATION access.

param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [switch]$Once,
    [int]$Loop = 1,
    [int]$IntervalSec = 2
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class DrProbe {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct THREADENTRY32 {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public long tpBasePri;
        public long tpDeltaPri;
        public uint dwFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

# CONTEXT (x64) is followed by XSAVE areas in modern Windows; 0x1000 is a
# safe allocation size. The struct must be 16-byte aligned, which we do
# manually because the P/Invoke marshaller only guarantees pointer size.
$ctxSize = 0x1000
$buffer = [byte[]]::new($ctxSize + 16)
$handle = [System.Runtime.InteropServices.GCHandle]::Alloc($buffer, [System.Runtime.InteropServices.GCHandleType]::Pinned)
$base = $handle.AddrOfPinnedObject().ToInt64()
$ctx = ($base + 15) -band (-bnot 15)   # align_up(16)

$TH32CS_SNAPTHREAD = 0x4
$THREAD_QUERY_INFORMATION = 0x40
# CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
$CONTEXT_DEBUG_REGISTERS = 0x00100008

# CONTEXT x64 field offsets we care about.
$OFF_CONTEXT_FLAGS = 0x30
$OFF_DR0 = 0x48; $OFF_DR1 = 0x50; $OFF_DR2 = 0x58; $OFF_DR3 = 0x60
$OFF_DR6 = 0x68; $OFF_DR7 = 0x70
$OFF_RIP = 0xF8; $OFF_RSP = 0x98

function Read-U64([long]$ptr, [int]$offset) {
    return [System.Runtime.InteropServices.Marshal]::ReadInt64($ptr + $offset)
}

function Resolve-ModuleFor([UInt64]$addr, $modules) {
    foreach ($m in $modules) {
        $start = [UInt64]$m.BaseAddress.ToInt64()
        $end = $start + [UInt64]$m.ModuleMemorySize
        if ($addr -ge $start -and $addr -lt $end) {
            return $m.ModuleName
        }
    }
    if ($addr -ne 0) { return "unbacked" }
    return $null
}

function Scan-Once([int]$pid) {
    $snap = [DrProbe]::CreateToolhelp32Snapshot($TH32CS_SNAPTHREAD, 0)
    if ($snap -eq [IntPtr]::Zero -or $snap -eq [IntPtr](-1)) {
        Write-Output (ConvertTo-Json -Compress @{ ts = (Get-Date).ToUniversalTime().ToString('o'); error = "snapshot failed" })
        return
    }

    $modules = @()
    try { $modules = (Get-Process -Id $pid -ErrorAction Stop).Modules } catch { }

    $te = New-Object DrProbe+THREADENTRY32
    $te.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][DrProbe+THREADENTRY32])

    $rows = @()
    if ([DrProbe]::Thread32First($snap, [ref]$te)) {
        do {
            if ($te.th32OwnerProcessID -eq [uint32]$pid) {
                $h = [DrProbe]::OpenThread($THREAD_QUERY_INFORMATION, $false, $te.th32ThreadID)
                if ($h -ne [IntPtr]::Zero) {
                    # zero only the fixed header, set flags, then read.
                    [System.Array]::Clear($buffer, 0, 0x200)
                    [System.Runtime.InteropServices.Marshal]::WriteInt32($ctx + $OFF_CONTEXT_FLAGS, $CONTEXT_DEBUG_REGISTERS)
                    if ([DrProbe]::GetThreadContext($h, [IntPtr]$ctx)) {
                        $dr0 = Read-U64 $ctx $OFF_DR0
                        $row = [ordered]@{
                            ts      = (Get-Date).ToUniversalTime().ToString('o')
                            pid     = $pid
                            tid     = $te.th32ThreadID
                            dr0     = ('0x{0:x}' -f $dr0)
                            dr1     = ('0x{0:x}' -f (Read-U64 $ctx $OFF_DR1))
                            dr2     = ('0x{0:x}' -f (Read-U64 $ctx $OFF_DR2))
                            dr3     = ('0x{0:x}' -f (Read-U64 $ctx $OFF_DR3))
                            dr7     = ('0x{0:x}' -f (Read-U64 $ctx $OFF_DR7))
                            rip     = ('0x{0:x}' -f (Read-U64 $ctx $OFF_RIP))
                        }
                        $row['dr0_module'] = Resolve-ModuleFor ([UInt64]$dr0) $modules
                        $rows += $row
                    }
                    [void][DrProbe]::CloseHandle($h)
                }
            }
        } while ([DrProbe]::Thread32Next($snap, [ref]$te))
    }
    [void][DrProbe]::CloseHandle($snap)

    foreach ($r in $rows) {
        Write-Output (ConvertTo-Json -Compress -InputObject ([pscustomobject]$r))
    }
    if ($rows.Count -eq 0) {
        Write-Output (ConvertTo-Json -Compress @{ ts = (Get-Date).ToUniversalTime().ToString('o'); pid = $pid; note = 'process exited or no readable threads' })
    }
}

$iterations = if ($Once) { 1 } else { $Loop }
for ($i = 0; $i -lt $iterations; $i++) {
    Scan-Once -pid $TargetPid
    if ($i -lt $iterations - 1) { Start-Sleep -Seconds $IntervalSec }
}

$handle.Free()
