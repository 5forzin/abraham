using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class HwbpProbe2 {
    [StructLayout(LayoutKind.Explicit, Size = 0x410)]
    public struct Ctx {
        [FieldOffset(0x30)] public uint Flags;
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x70)] public ulong Dr7;
    }

    delegate long VehFn(IntPtr info);
    static volatile int hitCount = 0;
    static long target;
    static int retOff = -1;
    static string result = "";

    public static string Run() {
        IntPtr sleep = GetProcAddress(GetModuleHandle("kernel32"), "Sleep");
        target = sleep.ToInt64();
        for (int off = 0; off < 0x100; off++) {
            if (Marshal.ReadByte(sleep, off) == 0xC3) { retOff = off; break; }
        }
        var veh = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate((VehFn)Veh));
        result = "retOff=" + retOff + " veh=" + veh;
        uint mainTid = GetCurrentThreadId();
        var t = new Thread(() => {
            // THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
            IntPtr h = OpenThread(0x0010 | 0x0002, false, mainTid);
            if (h == IntPtr.Zero) { result += " open=fail"; return; }
            SuspendThread(h);
            var set = new Ctx { Flags = 0x00100008u, Dr0 = (ulong)target, Dr7 = 3 };
            bool setOk = SetThreadContext(h, ref set);
            var rb = new Ctx { Flags = 0x00100008u };
            bool getOk = GetThreadContext(h, ref rb);
            ResumeThread(h);
            CloseHandle(h);
            result += " set=" + setOk + " get=" + getOk + " dr0=0x" + rb.Dr0.ToString("x") + " dr7=0x" + rb.Dr7.ToString("x");
        });
        t.Start(); t.Join();
        // Main thread: call Sleep — if the breakpoint is live the VEH
        // retires it before any actual sleeping happens.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Sleep(200);
        sw.Stop();
        result += " sleepMs=" + sw.ElapsedMilliseconds + " hits=" + hitCount;
        RemoveVectoredExceptionHandler(veh);
        return result;
    }

    static long Veh(IntPtr info) {
        IntPtr ctx = Marshal.ReadIntPtr(info, 8);
        long rip = Marshal.ReadInt64(ctx, 0xF8);
        if (rip == target && retOff >= 0) {
            hitCount++;
            Marshal.WriteInt64(ctx, 0xF8, target + retOff);
            Marshal.WriteInt64(ctx, 0x78, 0);
        }
        return -1;
    }

    [DllImport("kernel32.dll")] static extern void Sleep(uint ms);
    [DllImport("kernel32.dll")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    [DllImport("kernel32.dll")] static extern ulong RemoveVectoredExceptionHandler(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool SetThreadContext(IntPtr h, ref Ctx ctx);
    [DllImport("kernel32.dll")] static extern bool GetThreadContext(IntPtr h, ref Ctx ctx);
    [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll")] static extern uint SuspendThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string name);
}
