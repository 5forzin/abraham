use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 32;
const CHUNK: usize = 4096;

/// Demux headers of the cover envelope. A fronting proxy that pools
/// origin connections (Cloudflare et al.) can interleave requests from
/// several logical beacon transports on ONE server-side connection, so
/// every protocol POST tags itself: `X-Session` carries the session
/// token for routing and `X-Handshake: 1` marks a ClientHello POST.
/// Both ride inside the outer TLS; routing alone grants nothing — frames
/// still have to decrypt under the session key.
pub const HDR_SESSION: &str = "X-Session";
pub const HDR_HANDSHAKE: &str = "X-Handshake";

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub body: Vec<u8>,
    /// Header names lowercased; values as raw bytes.
    headers: Vec<(String, Vec<u8>)>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn reason_for(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    }
}

fn content_length_of(headers: &[httparse::Header<'_>]) -> io::Result<usize> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(header.value)
                .map_err(|_| invalid("non-utf8 content-length"))?;
            return text
                .trim()
                .parse()
                .map_err(|_| invalid("bad content-length"));
        }
    }
    Ok(0)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// Reads one HTTP/1.1 request with a Content-Length body. Returns None on
/// clean EOF before any bytes arrive.
pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<HttpRequest>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; CHUNK];
    let (method, uri, header_end, content_length, headers) = loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut preq = httparse::Request::new(&mut headers);
        match preq.parse(&buf) {
            Ok(httparse::Status::Complete(offset)) => {
                let method = preq
                    .method
                    .ok_or_else(|| invalid("missing method"))?
                    .to_string();
                let uri = preq.path.ok_or_else(|| invalid("missing uri"))?.to_string();
                let length = content_length_of(preq.headers)?;
                let headers = preq
                    .headers
                    .iter()
                    .map(|h| (h.name.to_ascii_lowercase(), h.value.to_vec()))
                    .collect();
                break (method, uri, offset, length, headers);
            }
            Ok(httparse::Status::Partial) => {}
            Err(e) => return Err(invalid(&format!("malformed request: {e}"))),
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(invalid("header block too large"));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof mid-request",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let total = header_end + content_length;
    while buf.len() < total {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-body"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[header_end..total].to_vec();
    Ok(Some(HttpRequest {
        method,
        uri,
        body,
        headers,
    }))
}

/// Writes an HTTP/1.1 keep-alive request with a binary body and extra
/// header lines (`(name, value)` pairs, sent verbatim).
pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    uri: &str,
    host: &str,
    user_agent: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let mut head = format!(
        "{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nContent-Type: application/octet-stream\r\n"
    );
    for (name, value) in extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    ));
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Reads one HTTP/1.1 response with a Content-Length body.
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<HttpResponse> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; CHUNK];
    let (status, header_end, content_length) = loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut pres = httparse::Response::new(&mut headers);
        match pres.parse(&buf) {
            Ok(httparse::Status::Complete(offset)) => {
                let status = pres.code.ok_or_else(|| invalid("missing status"))?;
                let length = content_length_of(pres.headers)?;
                break (status, offset, length);
            }
            Ok(httparse::Status::Partial) => {}
            Err(e) => return Err(invalid(&format!("malformed response: {e}"))),
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(invalid("header block too large"));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof mid-response",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let total = header_end + content_length;
    while buf.len() < total {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-body"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[header_end..total].to_vec();
    Ok(HttpResponse { status, body })
}

/// Writes an HTTP/1.1 keep-alive response with a binary body.
pub async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    server_header: &str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nServer: {server_header}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        reason_for(status),
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_request(
            &mut a,
            "POST",
            "/api/v1/telemetry",
            "h:1",
            "agent/1",
            &[(HDR_SESSION, "4242"), (HDR_HANDSHAKE, "1")],
            b"\x00\x01\x02AB",
        )
        .await
        .unwrap();
        let req = read_request(&mut b).await.unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/api/v1/telemetry");
        assert_eq!(req.body, b"\x00\x01\x02AB");
        assert_eq!(req.header("x-session"), Some(&b"4242"[..]));
        assert_eq!(req.header("X-SESSION"), Some(&b"4242"[..]));
        assert_eq!(req.header("x-handshake"), Some(&b"1"[..]));
        assert_eq!(req.header("x-missing"), None);
    }

    #[tokio::test]
    async fn response_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_response(&mut a, 200, "nginx", b"body-bytes")
            .await
            .unwrap();
        let resp = read_response(&mut b).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"body-bytes");
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_request(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_body_request() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_request(&mut a, "POST", "/x", "h", "ua", &[], b"")
            .await
            .unwrap();
        let req = read_request(&mut b).await.unwrap().unwrap();
        assert!(req.body.is_empty());
    }
}
