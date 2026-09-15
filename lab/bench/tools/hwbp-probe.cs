using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class HwbpProbe {
    [StructLayout(LayoutKind.Explicit, Size = 0x410)]
    public struct Ctx {
        [FieldOffset(0x30)] public uint Flags;
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x70)] public ulong Dr7;
    }

    delegate long MyFn(int x);
    delegate long VehFn(IntPtr info);

    static volatile int hitCount = 0;
    static long target;
    static int retOff = -1;

    public static string Run() {
        var fn = (MyFn)Target;
        target = Marshal.GetFunctionPointerForDelegate(fn).ToInt64();
        for (int off = 0; off < 64; off++) {
            if (Marshal.ReadByte((IntPtr)target, off) == 0xC3) { retOff = off; break; }
        }
        var veh = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate((VehFn)Veh));
        string result = "retOff=" + retOff + " veh=" + veh;
        var t = new Thread(() => {
            var set = new Ctx { Flags = 0x00100008u, Dr0 = (ulong)target, Dr1 = 0, Dr7 = 3 };
            IntPtr self = new IntPtr(-2);
            bool setOk = SetThreadContext(self, ref set);
            var rb = new Ctx { Flags = 0x00100008u };
            bool getOk = GetThreadContext(self, ref rb);
            result += " set=" + setOk + " get=" + getOk + " rbDr0=0x" + rb.Dr0.ToString("x") + " rbDr7=0x" + rb.Dr7.ToString("x");
            long r = fn(42);
            result += " call=" + r;
        });
        t.Start(); t.Join();
        result += " hits=" + hitCount;
        RemoveVectoredExceptionHandler(veh);
        return result;
    }

    static long Target(int x) { return x + 1; }

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

    [DllImport("kernel32.dll")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    [DllImport("kernel32.dll")] static extern ulong RemoveVectoredExceptionHandler(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool SetThreadContext(IntPtr h, ref Ctx ctx);
    [DllImport("kernel32.dll")] static extern bool GetThreadContext(IntPtr h, ref Ctx ctx);
}
