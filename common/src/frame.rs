use crate::crypto::Session;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: [u8; 2] = *b"AB";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 10;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub msg_type: u8,
    pub length: u16,
    pub counter: u32,
}

impl FrameHeader {
    pub fn new(msg_type: u8, counter: u32, ciphertext_len: usize) -> Self {
        FrameHeader {
            msg_type,
            length: ciphertext_len as u16,
            counter,
        }
    }

    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = MAGIC[0];
        buf[1] = MAGIC[1];
        buf[2] = VERSION;
        buf[3] = self.msg_type;
        buf[4..6].copy_from_slice(&self.length.to_be_bytes());
        buf[6..10].copy_from_slice(&self.counter.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Result<Self, ProtocolError> {
        if bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] {
            return Err(ProtocolError::BadMagic);
        }
        if bytes[2] != VERSION {
            return Err(ProtocolError::BadVersion);
        }
        Ok(FrameHeader {
            msg_type: bytes[3],
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            counter: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported version")]
    BadVersion,
    #[error("frame exceeds maximum size")]
    FrameTooLarge,
    #[error("counter regression")]
    CounterRegression,
    #[error("crypto operation failed")]
    Crypto,
    #[error("invalid server signature")]
    InvalidServerSignature,
    #[error("malformed message: {0}")]
    Malformed(String),
}

pub async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut Session,
    msg_type: u8,
    plaintext: &[u8],
) -> Result<(), ProtocolError> {
    let frame = session.seal(msg_type, plaintext)?;
    stream.write_all(&frame).await?;
    Ok(())
}

pub async fn read_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    session: &mut Session,
) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let parsed = FrameHeader::from_bytes(&header)?;
    let mut ciphertext = vec![0u8; parsed.length as usize];
    stream.read_exact(&mut ciphertext).await?;
    let plaintext = session.open(parsed.msg_type, parsed.counter, &ciphertext)?;
    Ok((parsed.msg_type, plaintext))
}

/// Decrypts a contiguous run of sealed frames (as carried inside an HTTP
/// envelope body). Frames are self-describing via their `AB` header.
pub fn open_frames(buf: &[u8], session: &mut Session) -> Result<Vec<(u8, Vec<u8>)>, ProtocolError> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let remaining = &buf[offset..];
        if remaining.len() < HEADER_LEN {
            return Err(ProtocolError::Malformed("truncated frame header".into()));
        }
        let header: [u8; HEADER_LEN] = remaining[..HEADER_LEN].try_into().expect("slice len");
        let parsed = FrameHeader::from_bytes(&header)?;
        let end = HEADER_LEN + parsed.length as usize;
        if remaining.len() < end {
            return Err(ProtocolError::Malformed("truncated frame body".into()));
        }
        let plaintext =
            session.open(parsed.msg_type, parsed.counter, &remaining[HEADER_LEN..end])?;
        out.push((parsed.msg_type, plaintext));
        offset += end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, ClientHello};

    fn session_pair() -> (Session, Session) {
        let server_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let (client_secret, client_hello) = ClientHello::generate();
        let (server_secret, server_hello) = crypto::server_respond(&server_key, &client_hello);
        let client = crypto::client_finish(
            &server_key.verifying_key(),
            client_secret,
            &client_hello,
            &server_hello,
        )
        .unwrap();
        let server = crypto::server_finish(server_secret, &client_hello, &server_hello);
        (client, server)
    }

    #[tokio::test]
    async fn write_read_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let (mut client, mut server) = session_pair();
        write_message(&mut a, &mut client, 0x03, b"task payload")
            .await
            .unwrap();
        let (msg_type, plaintext) = read_message(&mut b, &mut server).await.unwrap();
        assert_eq!(msg_type, 0x03);
        assert_eq!(plaintext, b"task payload");
    }

    #[test]
    fn open_frames_roundtrip() {
        let (mut client, mut server) = session_pair();
        let mut buf = Vec::new();
        buf.extend_from_slice(&client.seal(0x01, b"first").unwrap());
        buf.extend_from_slice(&client.seal(0x02, b"second").unwrap());
        buf.extend_from_slice(&client.seal(0x0a, b"").unwrap());
        let frames = open_frames(&buf, &mut server).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], (0x01, b"first".to_vec()));
        assert_eq!(frames[1], (0x02, b"second".to_vec()));
        assert_eq!(frames[2], (0x0a, Vec::new()));
    }

    #[test]
    fn open_frames_rejects_truncated() {
        let (mut client, mut server) = session_pair();
        let frame = client.seal(0x01, b"payload").unwrap();
        assert!(open_frames(&frame[..frame.len() - 3], &mut server).is_err());
        assert!(open_frames(&[], &mut server).unwrap().is_empty());
    }
}
