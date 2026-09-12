//! Dynamic unwind metadata (ABR-T008) for hand-assembled routines.
//!
//! Stack-walking telemetry (EDR thread sampling, exception dispatch, ETW
//! stack events) resolves every return address through
//! `RtlLookupFunctionEntry`. An address with no RUNTIME_FUNCTION does not
//! stop the walk: the x64 unwinder treats the frame as a leaf — the
//! return address is assumed at [rsp] and rsp advances one slot — so a
//! non-leaf routine's parked locals get replayed as return addresses and
//! the walk continues onto garbage (pinned empirically on build 26200 in
//! the tests below and in
//! `docs/lab/2026-09-11-stack-memory-observation.md`). That
//! misattribution is the "unbacked executable memory" tell — detectors
//! should expect plausible-but-wrong frames, not unwind failures.
//! Registering a dynamic function table
//! makes the walk traverse these routines like legitimate JIT-emitted
//! code, which is exactly what mainstream runtimes (CLR, V8, Delphi) do.
//! Concept borrowed from the Morgana prototype; the encoders and
//! verification here are Abraham-specific.
//!
//! RUNTIME_FUNCTION RVAs — including the UnwindData pointer — resolve
//! against the ImageBase handed to `RtlAddFunctionTable`, so the
//! metadata is written INTO the registered region (the private code
//! page), mirroring how .pdata/.xdata sit inside a real PE. ntdll keeps
//! its own copy of the 12-byte entries; the UNWIND_INFO blobs are read
//! live from the region and must stay readable for the table's lifetime.

use std::ffi::c_void;

use super::syscalls;

/// x64 unwind opcodes used by the hand-assembled routines (and parsed
/// from real modules by [`frame_adjust`]).
pub const UWOP_PUSH_NONVOL: u8 = 0;
pub const UWOP_ALLOC_LARGE: u8 = 1;
pub const UWOP_ALLOC_SMALL: u8 = 2;

/// Nonvolatile register numbers for UWOP_PUSH_NONVOL.
pub const REG_RBX: u8 = 3;
pub const REG_RSI: u8 = 6;
pub const REG_RDI: u8 = 7;
pub const REG_R12: u8 = 12;

#[repr(C)]
struct RuntimeFunction {
    _begin_address: u32,
    _end_address: u32,
    _unwind_address: u32,
}

/// One prolog unwind step: the offset just past the instruction it
/// describes (counted from the function start), the opcode and operand.
pub struct Code(pub u8, pub u8, pub u8);

/// Layout description of one hand-assembled function relative to the code
/// page base passed to [`FunctionTable::register`].
pub struct Routine {
    pub offset: usize,
    pub len: usize,
    /// Offset just past the final prolog instruction.
    pub prolog_end: u8,
    /// Prolog steps in the order they execute. The encoder stores them
    /// REVERSED: per the x64 ABI (verified against kernel32's own .xdata)
    /// slot 0 of the unwind-code array describes the LAST prolog
    /// instruction, and the unwinder replays the array front-to-back.
    pub prolog: &'static [Code],
}

type AddFunctionTableFn = unsafe extern "system" fn(*const RuntimeFunction, u32, usize) -> usize;
type DeleteFunctionTableFn = unsafe extern "system" fn(*const RuntimeFunction) -> i32;
type LookupFunctionEntryFn =
    unsafe extern "system" fn(usize, *mut usize, *mut c_void) -> *const RuntimeFunction;

/// A registered dynamic function table. The metadata itself lives inside
/// the code region it describes and is process-lifetime; dropping only
/// unregisters the entries with `RtlDeleteFunctionTable`.
pub struct FunctionTable {
    base: usize,
    meta: usize,
}

impl FunctionTable {
    /// Encodes the RUNTIME_FUNCTION array plus one UNWIND_INFO per routine
    /// at `base + meta_offset` (which must be committed, writable for the
    /// write and readable afterwards — the table and infos must fit inside
    /// the region), then registers the table with `RtlAddFunctionTable`
    /// for `base`. Fails loudly if the table is not discoverable
    /// afterwards — broken metadata is worse than none because it
    /// misdirects walkers.
    pub unsafe fn register(
        base: usize,
        routines: &[Routine],
        meta_offset: usize,
    ) -> Result<Self, String> {
        let add: AddFunctionTableFn = unsafe {
            std::mem::transmute(
                syscalls::export_address("kernel32.dll", "RtlAddFunctionTable")
                    .ok_or("RtlAddFunctionTable unresolved")?,
            )
        };
        let entry_len = std::mem::size_of::<RuntimeFunction>();
        let table = base + meta_offset;
        unsafe {
            let mut cursor = meta_offset + routines.len() * entry_len;
            for (index, routine) in routines.iter().enumerate() {
                // RUNTIME_FUNCTION: RVAs relative to the registered base.
                let entry = (table + index * entry_len) as *mut u32;
                entry.write_volatile(routine.offset as u32);
                entry
                    .add(1)
                    .write_volatile((routine.offset + routine.len) as u32);
                entry.add(2).write_volatile(cursor as u32);
                // UNWIND_INFO: version 1, no handler, RSP-based frame.
                let info = (base + cursor) as *mut u8;
                info.write_volatile(0x01);
                info.add(1).write_volatile(routine.prolog_end);
                info.add(2).write_volatile(routine.prolog.len() as u8);
                info.add(3).write_volatile(0);
                for (slot, Code(end, uop, opinfo)) in routine.prolog.iter().rev().enumerate() {
                    let code = info.add(4 + 2 * slot);
                    code.write_volatile(*end);
                    code.add(1).write_volatile(uop | (opinfo << 4));
                }
                cursor += 4 + 2 * ((routine.prolog.len() + 1) & !1);
            }
        }
        if unsafe { add(table as *const RuntimeFunction, routines.len() as u32, base) } == 0 {
            return Err("RtlAddFunctionTable rejected the table".into());
        }
        let table = FunctionTable {
            base,
            meta: meta_offset,
        };
        // Self-check: a stack walker resolving the first routine's entry
        // must land on our base. If not, roll back — a table that resolves
        // nowhere is silent failure, not hardening.
        if lookup(base + routines[0].offset + 1).map(|(image, _)| image) != Some(base) {
            drop(table);
            return Err("registered table not discoverable via RtlLookupFunctionEntry".into());
        }
        Ok(table)
    }
}

impl Drop for FunctionTable {
    fn drop(&mut self) {
        // Unregister only; the metadata bytes stay in the code region
        // (process-lifetime rule — ntdll may hold pointers into it).
        if let Some(delete) =
            unsafe { syscalls::export_address("kernel32.dll", "RtlDeleteFunctionTable") }
                .map(|addr| unsafe { std::mem::transmute::<usize, DeleteFunctionTableFn>(addr) })
        {
            unsafe { delete((self.base + self.meta) as *const RuntimeFunction) };
        }
    }
}

/// Resolves the dynamic (or image) function entry covering `control_pc`.
/// Returns (image_base, entry_address); the entry may be ntdll's private
/// copy of the RUNTIME_FUNCTION, so read its contents rather than
/// comparing pointers.
pub fn lookup(control_pc: usize) -> Option<(usize, usize)> {
    let lookup_fn: LookupFunctionEntryFn = unsafe {
        std::mem::transmute(syscalls::export_address(
            "kernel32.dll",
            "RtlLookupFunctionEntry",
        )?)
    };
    let mut image_base = 0usize;
    let entry = unsafe { lookup_fn(control_pc, &mut image_base, std::ptr::null_mut()) };
    (!entry.is_null()).then_some((image_base, entry as usize))
}

/// Minimal CONTEXT (x64) — only the fields RtlVirtualUnwind reads and
/// writes (fixed 0x4F8 extent, so the pointer can also be handed to
/// RtlCaptureContext); the remainder is zero-filled. Test/measurement
/// harness only — production evasion code never synthesizes contexts.
#[cfg(test)]
#[repr(C, align(16))]
pub(crate) struct Context {
    _homes: [u64; 6],
    pub(crate) context_flags: u32,
    _mxcsr: u32,
    _segs: [u16; 6],
    _eflags: u32,
    _debug: [u64; 6],
    pub(crate) rax: u64,
    _rcx: u64,
    _rdx: u64,
    pub(crate) rbx: u64,
    pub(crate) rsp: u64,
    _rbp: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    _r8: u64,
    _r9: u64,
    _r10: u64,
    _r11: u64,
    pub(crate) r12: u64,
    _r13: u64,
    _r14: u64,
    _r15: u64,
    pub(crate) rip: u64,
    _rest: [u8; 0x4F8 - 0x100],
}

#[cfg(test)]
type VirtualUnwindFn = unsafe extern "system" fn(
    u32,   // HandlerType
    usize, // ImageBase
    usize, // ControlPc
    usize, // FunctionEntry
    *mut Context,
    *mut *mut c_void, // HandlerData
    *mut u64,         // EstablisherFrame
    *mut u8,          // ContextPointers (optional)
) -> *mut c_void;

/// Unwinds one frame in-place through the entry's unwind program.
/// Returns the handler address (NULL for NHANDLER functions).
#[cfg(test)]
pub(crate) unsafe fn virtual_unwind(
    entry: usize,
    image_base: usize,
    context: &mut Context,
) -> *mut c_void {
    let unwind_fn: VirtualUnwindFn = unsafe {
        std::mem::transmute(syscalls::export_address("kernel32.dll", "RtlVirtualUnwind").unwrap())
    };
    let mut handler_data = std::ptr::null_mut();
    let mut frame = 0u64;
    unsafe {
        unwind_fn(
            0,
            image_base,
            context.rip as usize,
            entry,
            context,
            &mut handler_data,
            &mut frame,
            std::ptr::null_mut(),
        )
    }
}

#[cfg(test)]
pub(crate) fn context_with(rip: usize, rsp: usize) -> Context {
    let mut context: Context = unsafe { std::mem::zeroed() };
    context.context_flags = 0x1_0003; // CONTEXT_CONTROL | CONTEXT_INTEGER
    context.rip = rip as u64;
    context.rsp = rsp as u64;
    context
}

/// Parses the UNWIND_INFO of a real module's function entry and returns
/// (frame_adjust_bytes, prolog_len): the bytes the prolog pushes/allocates
/// BELOW the return-address slot — exactly what a walker adds to rsp
/// (before popping the return address) when replaying the frame. Strictly
/// accepts only unhandled, RSP-framed functions whose codes are limited to
/// PUSH_NONVOL/ALLOC_SMALL/ALLOC_LARGE — opcodes with provable arithmetic.
/// Anything richer (frame pointers, saved registers, chained info, machine
/// frames, epilog annotations) returns None so callers pick another
/// candidate instead of guessing.
pub fn frame_adjust(module_base: usize, function_entry: usize) -> Option<(usize, u8)> {
    unsafe {
        let entry = function_entry as *const u32;
        let unwind_rva = std::ptr::read_volatile(entry.add(2)) as usize;
        let info = (module_base + unwind_rva) as *const u8;
        let version_flags = std::ptr::read_volatile(info);
        if version_flags & 0x07 != 1 || version_flags >> 3 != 0 {
            return None; // not version-1 N-handler
        }
        let prolog_len = std::ptr::read_volatile(info.add(1));
        let count = std::ptr::read_volatile(info.add(2)) as usize;
        if std::ptr::read_volatile(info.add(3)) & 0x0F != 0 {
            return None; // frame-pointer function: different rsp math
        }
        let mut adjust = 0usize;
        let mut slot = 0usize;
        while slot < count {
            let code_ptr = info.add(4 + 2 * slot);
            let code = u16::from_le_bytes([
                std::ptr::read_volatile(code_ptr),
                std::ptr::read_volatile(code_ptr.add(1)),
            ]);
            let opcode = ((code >> 8) & 0x0F) as u8;
            let opinfo = (code >> 12) as u8;
            match opcode {
                UWOP_PUSH_NONVOL => adjust += 8,
                UWOP_ALLOC_SMALL => adjust += (opinfo as usize + 1) * 8,
                UWOP_ALLOC_LARGE if opinfo == 0 => {
                    slot += 1;
                    let size_ptr = info.add(4 + 2 * slot);
                    let size = u32::from_le_bytes([
                        std::ptr::read_volatile(size_ptr),
                        std::ptr::read_volatile(size_ptr.add(1)),
                        std::ptr::read_volatile(size_ptr.add(2)),
                        std::ptr::read_volatile(size_ptr.add(3)),
                    ]);
                    adjust += size as usize;
                }
                _ => return None,
            }
            slot += 1;
        }
        Some((adjust, prolog_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal CONTEXT moved to module scope (see [`Context`]) so the
    /// ABR-T010 stack harness reuses the same walker machinery.
    // The two Ekko routines' unwind programs, mirroring the shellcode in
    // sleep.rs: a trampoline whose only stack adjustment is
    // `sub rsp,0x28`, and a wait loop that pushes rbx/rsi/rdi/r12 first.
    fn routines() -> [Routine; 2] {
        [
            Routine {
                offset: 0,
                len: 0x20,
                prolog_end: 23,
                prolog: &[Code(23, UWOP_ALLOC_SMALL, 4)],
            },
            Routine {
                offset: 0x40,
                len: 0x30,
                prolog_end: 9,
                prolog: &[
                    Code(1, UWOP_PUSH_NONVOL, REG_RBX),
                    Code(2, UWOP_PUSH_NONVOL, REG_RSI),
                    Code(3, UWOP_PUSH_NONVOL, REG_RDI),
                    Code(5, UWOP_PUSH_NONVOL, REG_R12),
                    Code(9, UWOP_ALLOC_SMALL, 4),
                ],
            },
        ]
    }

    /// The metadata offset register() writes to inside the scratch page —
    /// clear of the routine bodies at 0..0x70.
    const META: usize = 0x200;

    #[test]
    fn lookup_finds_registered_routines() {
        let scratch = unsafe { syscalls::alloc_rw(0x1000) }.expect("scratch page");
        let table =
            unsafe { FunctionTable::register(scratch, &routines(), META) }.expect("register");
        for pc in [
            scratch + 1,
            scratch + 25,
            scratch + 0x40 + 4,
            scratch + 0x40 + 31,
        ] {
            let (image, entry) = lookup(pc).unwrap_or_else(|| panic!("no entry for {pc:#x}"));
            assert_eq!(image, scratch, "wrong image base for {pc:#x}");
            // The entry may be ntdll's copy; what matters is its contents.
            let (begin, end) = unsafe {
                let entry = entry as *const u32;
                (
                    std::ptr::read_volatile(entry) as usize,
                    std::ptr::read_volatile(entry.add(1)) as usize,
                )
            };
            let in_first = pc < scratch + 0x40;
            let expected = if in_first { 0 } else { 0x40 };
            let expected_end = if in_first { 0x20 } else { 0x70 };
            assert_eq!(begin, expected, "wrong begin RVA for {pc:#x}");
            assert_eq!(end, expected_end, "wrong end RVA for {pc:#x}");
        }
        drop(table);
        // After Drop the entries must be gone — proves RtlDeleteFunctionTable
        // really unregistered them.
        assert!(lookup(scratch + 1).is_none(), "entry survived Drop");
    }

    /// Legit-software control for the attribution tests, pinned on build
    /// 26200: a real image-backed frame (ntdll `RtlAllocateHeap`, which
    /// pushes a frame and therefore carries .pdata) resolves through the
    /// same lookup primitive to a bracketing RUNTIME_FUNCTION. The nuance
    /// the control exposes: kernel32's exports (VirtualProtect, Sleep,
    /// LoadLibraryA...) are `jmp [rip+disp]` thunks into KernelBase and
    /// LEGITIMATELY carry no RUNTIME_FUNCTION — a thunk never pushes a
    /// frame. "Lookup returned NULL for a module address" is therefore
    /// not an anomaly by itself; detectors must key on the frame's region
    /// type, not on the lookup failing.
    #[test]
    fn image_backed_frame_resolves_bracketing_entry() {
        #[allow(non_snake_case)]
        extern "system" {
            fn GetModuleHandleW(name: *const u16) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const i8) -> *const c_void;
        }
        let wide =
            |name: &str| -> Vec<u16> { name.encode_utf16().chain(std::iter::once(0)).collect() };
        let ntdll = unsafe { GetModuleHandleW(wide("ntdll.dll").as_ptr()) };
        let pc = unsafe { GetProcAddress(ntdll, c"RtlAllocateHeap".as_ptr()) as usize };
        assert_ne!(pc, 0, "RtlAllocateHeap unresolved");
        let (image, entry) = lookup(pc).expect("ntdll frame must resolve");
        assert_eq!(image, ntdll as usize, "resolved image is not ntdll's base");
        // The entry (ntdll's copy or the module's .pdata itself) must
        // bracket the pc.
        let (begin, end) = unsafe {
            let e = entry as *const u32;
            (
                std::ptr::read_volatile(e) as usize,
                std::ptr::read_volatile(e.add(1)) as usize,
            )
        };
        let rva = pc - image;
        assert!(
            rva >= begin && rva < end,
            "ntdll entry [{begin:#x},{end:#x}) does not bracket rva {rva:#x}"
        );

        // And the counter-control: kernel32's thunked exports carry no
        // entry — legal NULL lookups inside a Microsoft module.
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        let thunk = unsafe { GetProcAddress(kernel32, c"VirtualProtect".as_ptr()) as usize };
        assert_ne!(thunk, 0, "VirtualProtect unresolved");
        if lookup(thunk).is_none() {
            let bytes = unsafe { std::slice::from_raw_parts(thunk as *const u8, 3) };
            let is_indirect_jmp = bytes[..2] == [0xFF, 0x25] || bytes == [0x48, 0xFF, 0x25];
            assert!(
                is_indirect_jmp,
                "kernel32 export without an entry is not a jmp thunk: {:02x?}",
                bytes
            );
        }
    }

    /// Empirical pin (build 26200): what a walker does with a frame that
    /// carries NO RUNTIME_FUNCTION. The walk does not abort — the frame is
    /// treated as a leaf, the return address is assumed at [rsp] and rsp
    /// advances one slot. For a non-leaf unbacked routine [rsp] parks
    /// locals or arguments (the Ekko trampoline parks its RC4 argument
    /// block around there), so the walk continues onto attacker-controlled
    /// data as a fake call chain. Detectors must not wait for "unwind
    /// failed" telemetry.
    #[test]
    fn frame_without_runtime_function_walks_as_leaf() {
        let scratch = unsafe { syscalls::alloc_rw(0x1000) }.expect("scratch page");
        assert!(
            lookup(scratch + 0x11).is_none(),
            "unregistered page must not resolve to an entry"
        );
        let stack = unsafe { syscalls::alloc_rw(0x100) }.expect("fake stack");
        let rsp = stack + 0x80;
        const PARKED_LOCAL: u64 = 0x0000_0BAD_F00D_0000;
        unsafe { (rsp as *mut u64).write_volatile(PARKED_LOCAL) };
        let mut context = context_with(scratch + 0x11, rsp);
        let handler = unsafe { virtual_unwind(0, 0, &mut context) };
        assert!(handler.is_null(), "leaf treatment returned a handler");
        assert_eq!(
            context.rip, PARKED_LOCAL,
            "leaf treatment must replay [rsp] as the return address"
        );
        assert_eq!(
            context.rsp as usize,
            rsp + 8,
            "leaf treatment must advance rsp one slot"
        );
    }

    #[test]
    fn frame_adjust_matches_registered_programs() {
        // Deterministic arithmetic against our own registered table: the
        // trampoline allocates 0x28; the wait loop pushes 4 registers and
        // allocates 0x28 (4*8 + 0x28 = 0x48). The return-address slot is
        // NOT part of the adjust — walkers pop it separately.
        let scratch = unsafe { syscalls::alloc_rw(0x1000) }.expect("scratch page");
        let table =
            unsafe { FunctionTable::register(scratch, &routines(), META) }.expect("register");
        let (_, entry) = lookup(scratch + 25).expect("trampoline entry");
        assert_eq!(frame_adjust(scratch, entry), Some((0x28, 23)));
        let (_, entry) = lookup(scratch + 0x40 + 31).expect("wait loop entry");
        assert_eq!(frame_adjust(scratch, entry), Some((0x48, 9)));
        drop(table);
    }

    #[test]
    fn unwind_program_replays_trampolines_alloc() {
        let scratch = unsafe { syscalls::alloc_rw(0x1000) }.expect("scratch page");
        let table =
            unsafe { FunctionTable::register(scratch, &routines(), META) }.expect("register");
        let (image, entry) = lookup(scratch + 25).expect("trampoline entry");
        let stack = unsafe { syscalls::alloc_rw(0x100) }.expect("fake stack");
        let rsp = stack + 0x80;
        const RETADDR: u64 = 0x0000_DEAD_BEEF_0000;
        unsafe { ((rsp + 0x28) as *mut u64).write_volatile(RETADDR) };
        let mut context = context_with(scratch + 25, rsp);
        let handler = unsafe { virtual_unwind(entry, image, &mut context) };
        assert!(handler.is_null(), "NHANDLER routine returned a handler");
        assert_eq!(context.rip, RETADDR, "return address misread");
        assert_eq!(context.rsp as usize, rsp + 0x30, "RSP not rebalanced");
        drop(table);
    }

    #[test]
    fn unwind_program_restores_wait_loop_nonvolatiles() {
        let scratch = unsafe { syscalls::alloc_rw(0x1000) }.expect("scratch page");
        let table =
            unsafe { FunctionTable::register(scratch, &routines(), META) }.expect("register");
        let (image, entry) = lookup(scratch + 0x40 + 31).expect("wait loop entry");
        let stack = unsafe { syscalls::alloc_rw(0x100) }.expect("fake stack");
        let rsp = stack + 0x80;
        // Stack layout past the prolog, reconstructing the pre-prolog
        // stack R0 = rsp + 0x48: [R0-0x20]=r12 (last push, lowest), then
        // rdi, rsi, rbx upwards, [R0]=return address. During replay the
        // pops read those slots as rsp climbs back to R0.
        const R12: u64 = 0x1111_1111_1111_1111;
        const RDI: u64 = 0x2222_2222_2222_2222;
        const RSI: u64 = 0x3333_3333_3333_3333;
        const RBX: u64 = 0x4444_4444_4444_4444;
        const RETADDR: u64 = 0x0000_CAFE_BABE_0000;
        unsafe {
            ((rsp + 0x28) as *mut u64).write_volatile(R12);
            ((rsp + 0x30) as *mut u64).write_volatile(RDI);
            ((rsp + 0x38) as *mut u64).write_volatile(RSI);
            ((rsp + 0x40) as *mut u64).write_volatile(RBX);
            ((rsp + 0x48) as *mut u64).write_volatile(RETADDR);
        }
        let mut context = context_with(scratch + 0x40 + 31, rsp);
        let handler = unsafe { virtual_unwind(entry, image, &mut context) };
        assert!(handler.is_null(), "NHANDLER routine returned a handler");
        assert_eq!(context.rip, RETADDR, "return address misread");
        assert_eq!(context.r12, R12, "r12 not restored");
        assert_eq!(context.rdi, RDI, "rdi not restored");
        assert_eq!(context.rsi, RSI, "rsi not restored");
        assert_eq!(context.rbx, RBX, "rbx not restored");
        assert_eq!(context.rsp as usize, rsp + 0x50, "RSP not rebalanced");
        drop(table);
    }
}
