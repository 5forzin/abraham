use crate::frame::{FrameHeader, ProtocolError, HEADER_LEN, TAG_LEN};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const CLIENT_HELLO_LEN: usize = 64;
pub const SERVER_HELLO_LEN: usize = 128;

const HKDF_INFO: &[u8] = b"abraham-v1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const OKM_LEN: usize = 64;

#[derive(Clone, Copy)]
pub struct ClientHello {
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
}

impl ClientHello {
    pub fn generate() -> (EphemeralSecret, Self) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        (
            secret,
            ClientHello {
                public_key: *public_key.as_bytes(),
                nonce,
            },
        )
    }

    pub fn to_bytes(self) -> [u8; CLIENT_HELLO_LEN] {
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        buf[..32].copy_from_slice(&self.public_key);
        buf[32..].copy_from_slice(&self.nonce);
        buf
    }

    pub fn from_bytes(bytes: &[u8; CLIENT_HELLO_LEN]) -> Self {
        let mut hello = ClientHello {
            public_key: [0u8; 32],
            nonce: [0u8; 32],
        };
        hello.public_key.copy_from_slice(&bytes[..32]);
        hello.nonce.copy_from_slice(&bytes[32..]);
        hello
    }
}

#[derive(Clone, Copy)]
pub struct ServerHello {
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

impl ServerHello {
    pub fn to_bytes(self) -> [u8; SERVER_HELLO_LEN] {
        let mut buf = [0u8; SERVER_HELLO_LEN];
        buf[..32].copy_from_slice(&self.public_key);
        buf[32..64].copy_from_slice(&self.nonce);
        buf[64..].copy_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(bytes: &[u8; SERVER_HELLO_LEN]) -> Self {
        let mut hello = ServerHello {
            public_key: [0u8; 32],
            nonce: [0u8; 32],
            signature: [0u8; 64],
        };
        hello.public_key.copy_from_slice(&bytes[..32]);
        hello.nonce.copy_from_slice(&bytes[32..64]);
        hello.signature.copy_from_slice(&bytes[64..]);
        hello
    }
}

fn signature_material(server: &ServerHello, client: &ClientHello) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&server.public_key);
    buf.extend_from_slice(&server.nonce);
    buf.extend_from_slice(&client.public_key);
    buf.extend_from_slice(&client.nonce);
    buf
}

pub fn server_respond(
    signing_key: &SigningKey,
    client: &ClientHello,
) -> (EphemeralSecret, ServerHello) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut hello = ServerHello {
        public_key: *public_key.as_bytes(),
        nonce,
        signature: [0u8; 64],
    };
    let signature = signing_key.sign(&signature_material(&hello, client));
    hello.signature = signature.to_bytes();
    (secret, hello)
}

pub fn client_finish(
    server_identity: &VerifyingKey,
    client_secret: EphemeralSecret,
    client_hello: &ClientHello,
    server_hello: &ServerHello,
) -> Result<Session, ProtocolError> {
    let material = signature_material(server_hello, client_hello);
    let signature = Signature::from_bytes(&server_hello.signature);
    server_identity
        .verify(&material, &signature)
        .map_err(|_| ProtocolError::InvalidServerSignature)?;
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_hello.public_key));
    Ok(Session::new(
        shared.as_bytes(),
        &client_hello.nonce,
        &server_hello.nonce,
        Role::Client,
    ))
}

pub fn server_finish(
    server_secret: EphemeralSecret,
    client_hello: &ClientHello,
    server_hello: &ServerHello,
) -> Session {
    let shared = server_secret.diffie_hellman(&PublicKey::from(client_hello.public_key));
    Session::new(
        shared.as_bytes(),
        &client_hello.nonce,
        &server_hello.nonce,
        Role::Server,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

pub struct Session {
    cipher_tx: Aes256Gcm,
    cipher_rx: Aes256Gcm,
    direction_tx: u32,
    direction_rx: u32,
    counter_tx: u32,
    counter_rx: u32,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("direction_tx", &self.direction_tx)
            .field("counter_tx", &self.counter_tx)
            .field("counter_rx", &self.counter_rx)
            .finish()
    }
}

impl Session {
    fn new(shared: &[u8], client_nonce: &[u8; 32], server_nonce: &[u8; 32], role: Role) -> Self {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(client_nonce);
        salt.extend_from_slice(server_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
        let mut okm = [0u8; OKM_LEN];
        hk.expand(HKDF_INFO, &mut okm).expect("valid hkdf length");
        let (key_client_to_server, key_server_to_client) = okm.split_at(KEY_LEN);
        let key_tx = match role {
            Role::Client => key_client_to_server,
            Role::Server => key_server_to_client,
        };
        let key_rx = match role {
            Role::Client => key_server_to_client,
            Role::Server => key_client_to_server,
        };
        let cipher_tx = Aes256Gcm::new_from_slice(key_tx).expect("valid key length");
        let cipher_rx = Aes256Gcm::new_from_slice(key_rx).expect("valid key length");
        let direction_tx = match role {
            Role::Client => 0u32,
            Role::Server => 1u32,
        };
        Session {
            cipher_tx,
            cipher_rx,
            direction_tx,
            direction_rx: 1 - direction_tx,
            counter_tx: 0,
            counter_rx: 0,
        }
    }

    pub fn seal(&mut self, msg_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if plaintext.len() + TAG_LEN > u16::MAX as usize {
            return Err(ProtocolError::FrameTooLarge);
        }
        self.counter_tx += 1;
        let header = FrameHeader::new(msg_type, self.counter_tx, plaintext.len() + TAG_LEN);
        let header_bytes = header.to_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.direction_tx.to_be_bytes());
        nonce[8..].copy_from_slice(&self.counter_tx.to_be_bytes());
        let ciphertext = self
            .cipher_tx
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| ProtocolError::Crypto)?;
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    pub fn open(
        &mut self,
        msg_type: u8,
        counter: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if counter <= self.counter_rx {
            return Err(ProtocolError::CounterRegression);
        }
        let header = FrameHeader::new(msg_type, counter, ciphertext.len());
        let header_bytes = header.to_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.direction_rx.to_be_bytes());
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        let plaintext = self
            .cipher_rx
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| ProtocolError::Crypto)?;
        self.counter_rx = counter;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_pair() -> (Session, Session) {
        let server_key = SigningKey::generate(&mut OsRng);
        let (client_secret, client_hello) = ClientHello::generate();
        let (server_secret, server_hello) = server_respond(&server_key, &client_hello);
        let client = client_finish(
            &server_key.verifying_key(),
            client_secret,
            &client_hello,
            &server_hello,
        )
        .unwrap();
        let server = server_finish(server_secret, &client_hello, &server_hello);
        (client, server)
    }

    #[test]
    fn handshake_derives_matching_sessions() {
        let (mut client, mut server) = session_pair();
        let frame = client.seal(0x01, b"c2s").unwrap();
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let h = FrameHeader::from_bytes(&header).unwrap();
        assert_eq!(
            server
                .open(h.msg_type, h.counter, &frame[HEADER_LEN..])
                .unwrap(),
            b"c2s"
        );
        let frame = server.seal(0x02, b"s2c").unwrap();
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let h = FrameHeader::from_bytes(&header).unwrap();
        assert_eq!(
            client
                .open(h.msg_type, h.counter, &frame[HEADER_LEN..])
                .unwrap(),
            b"s2c"
        );
    }

    #[test]
    fn forged_server_is_rejected() {
        let server_key = SigningKey::generate(&mut OsRng);
        let (client_secret, client_hello) = ClientHello::generate();
        let (_, mut server_hello) = server_respond(&server_key, &client_hello);
        server_hello.signature[0] ^= 1;
        let result = client_finish(
            &server_key.verifying_key(),
            client_secret,
            &client_hello,
            &server_hello,
        );
        assert!(matches!(
            result.unwrap_err(),
            ProtocolError::InvalidServerSignature
        ));
    }

    #[test]
    fn counter_regression_is_rejected() {
        let (mut client, mut server) = session_pair();
        let frame = client.seal(0x01, b"first").unwrap();
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let h = FrameHeader::from_bytes(&header).unwrap();
        server
            .open(h.msg_type, h.counter, &frame[HEADER_LEN..])
            .unwrap();
        assert!(matches!(
            server.open(h.msg_type, h.counter, &frame[HEADER_LEN..]),
            Err(ProtocolError::CounterRegression)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut client, mut server) = session_pair();
        let mut frame = client.seal(0x01, b"payload").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let h = FrameHeader::from_bytes(&header).unwrap();
        assert!(matches!(
            server.open(h.msg_type, h.counter, &frame[HEADER_LEN..]),
            Err(ProtocolError::Crypto)
        ));
    }
}
