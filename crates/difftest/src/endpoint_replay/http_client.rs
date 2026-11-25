// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Raw TCP HTTP/1.1 client and wire helpers for out-of-process endpoint replay.
//!
//! Responsible for: parsing and resolving `http://host[:port]` endpoints, writing raw HTTP/1.1
//! requests over isolated loopback sockets with timeouts, reading and validating HTTP/1.1
//! responses (including `100 Continue`, `Content-Length`, `Transfer-Encoding: chunked`, and early
//! server refusals), and validating returned XML documents and header/URI encodings.
//! NOT responsible for: CLI argument parsing, corpus traversal, replay orchestration, or crash
//! artifact emission (`mod.rs`).
//! Upstream: `request.rs`, `xmltree.rs`.
//! Downstream: `endpoint_replay/mod.rs`.

use std::fmt::Write as _;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use http::{HeaderValue, Method};

use crate::request::RawRequest;
use crate::xmltree;

const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_BODY_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_BODY_BYTES: usize = 1024;

/// A parsed and resolved `http://host[:port]` target endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Original normalized URL without trailing slash.
    pub url: String,
    /// Value written in the HTTP `Host` header.
    pub authority: String,
    /// Resolved TCP socket address.
    pub addr: SocketAddr,
}

impl Endpoint {
    /// Parses and resolves an `http://host[:port]` URL.
    ///
    /// # Errors
    ///
    /// A malformed scheme/authority, an unsupported path/query, or DNS resolution failure.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| format!("endpoint {raw:?} must use the http:// scheme"))?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
            return Err(format!("endpoint {raw:?} must be http://host[:port] with no path, query, or userinfo"));
        }
        let (host, port) = split_host_port(authority)?;
        let lookup = format!("{host}:{port}");
        let mut addrs: Vec<SocketAddr> = lookup
            .to_socket_addrs()
            .map_err(|error| format!("cannot resolve endpoint {raw:?}: {error}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("endpoint {raw:?} resolved to no socket address"));
        }
        // Prefer IPv4 when a hostname resolves to both IPv4 and IPv6 loopback.
        addrs.sort_by_key(|addr| !addr.is_ipv4());
        Ok(Self {
            url: format!("http://{authority}"),
            authority: authority.to_owned(),
            addr: addrs[0],
        })
    }
}

fn split_host_port(authority: &str) -> Result<(&str, u16), String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, tail) = bracketed
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {authority:?}"))?;
        if host.is_empty() {
            return Err(format!("empty IPv6 host in {authority:?}"));
        }
        let port = if tail.is_empty() {
            80
        } else {
            let port_str = tail
                .strip_prefix(':')
                .ok_or_else(|| format!("invalid port separator in {authority:?}"))?;
            port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port {port_str:?} in {authority:?}"))?
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port_str)) if !host.is_empty() => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port {port_str:?} in {authority:?}"))?;
            Ok((host, port))
        }
        Some(_) => Err(format!("empty host in {authority:?}")),
        None => Ok((authority, 80)),
    }
}

/// One parsed HTTP/1.1 response returned by the external endpoint.
#[derive(Debug)]
pub(super) struct HttpResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

pub(super) fn send_http_request(endpoint: &Endpoint, request: &RawRequest, timeout: Duration) -> Result<HttpResponse, String> {
    let mut stream =
        TcpStream::connect_timeout(&endpoint.addr, timeout).map_err(|error| format!("connect {}: {error}", endpoint.addr))?;
    let _ = stream.set_nodelay(true);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("set_read_timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("set_write_timeout: {error}"))?;

    let mut head = Vec::with_capacity(256);
    let _ = write!(head, "{} {} HTTP/1.1\r\n", request.method, request.target);
    let mut has_connection = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    if !has_connection {
        head.extend_from_slice(b"Connection: close\r\n");
    }
    head.extend_from_slice(b"\r\n");

    if let Err(error) = write_request(&mut stream, &head, &request.body)
        && !matches!(
            error.kind(),
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        )
    {
        return Err(format!("write request: {error}"));
    }

    read_http_response(&mut stream, request.method == Method::HEAD)
}

fn write_request(stream: &mut TcpStream, head: &[u8], body: &[bytes::Bytes]) -> io::Result<()> {
    stream.write_all(head)?;
    for piece in body {
        if !piece.is_empty() {
            stream.write_all(piece)?;
        }
    }
    stream.flush()
}

struct ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
    header_len: usize,
}

fn read_http_response(stream: &mut TcpStream, head_request: bool) -> Result<HttpResponse, String> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        let head = read_response_head(stream, &mut buffer)?;
        let remainder = buffer.split_off(head.header_len);
        if (100..200).contains(&head.status) && head.status != 101 {
            buffer = remainder;
            continue;
        }
        let body = if head_request || head.status == 204 || head.status == 304 {
            Vec::new()
        } else {
            read_response_body(stream, &head.headers, remainder)?
        };
        return Ok(HttpResponse {
            status: head.status,
            body,
        });
    }
}

fn read_response_head(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<ResponseHead, String> {
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(pos) = find_subslice(buffer, b"\r\n\r\n") {
            let mut raw_headers = [httparse::EMPTY_HEADER; 128];
            let mut parsed = httparse::Response::new(&mut raw_headers);
            let status = parsed
                .parse(&buffer[..pos + 4])
                .map_err(|error| format!("malformed HTTP response head: {error}"))?;
            let httparse::Status::Complete(header_len) = status else {
                return Err("incomplete HTTP response head".to_owned());
            };
            let code = parsed.code.ok_or_else(|| "HTTP response missing status code".to_owned())?;
            let headers = parsed
                .headers
                .iter()
                .map(|header| (header.name.to_ascii_lowercase(), String::from_utf8_lossy(header.value).trim().to_owned()))
                .collect();
            return Ok(ResponseHead {
                status: code,
                headers,
                header_len,
            });
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err("HTTP response headers exceeded 256 KiB".to_owned());
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(if buffer.is_empty() {
                    "connection closed before HTTP response".to_owned()
                } else {
                    "connection closed mid-header before complete HTTP response".to_owned()
                });
            }
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) => return Err(format!("read HTTP response head: {error}")),
        }
    }
}

fn read_response_body(stream: &mut TcpStream, headers: &[(String, String)], mut remainder: Vec<u8>) -> Result<Vec<u8>, String> {
    let is_chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked"));
    if is_chunked {
        return read_chunked_body(stream, remainder);
    }

    let mut content_length: Option<usize> = None;
    for (name, value) in headers {
        if name != "content-length" {
            continue;
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| format!("malformed response Content-Length {value:?}"))?;
        if let Some(previous) = content_length
            && previous != parsed
        {
            return Err(format!("conflicting Content-Length values {previous} and {parsed}"));
        }
        content_length = Some(parsed);
    }

    if let Some(expected) = content_length {
        let mut received = remainder.len();
        let mut captured = Vec::with_capacity(expected.min(MAX_BODY_CAPTURE_BYTES));
        let initial_take = remainder.len().min(expected).min(MAX_BODY_CAPTURE_BYTES);
        captured.extend_from_slice(&remainder[..initial_take]);
        let mut scratch = [0_u8; 8192];
        while received < expected {
            match stream.read(&mut scratch) {
                Ok(0) => {
                    return Err(format!("truncated HTTP response body: received {received} of {expected} byte(s)"));
                }
                Ok(read) => {
                    let useful = read.min(expected - received);
                    if captured.len() < MAX_BODY_CAPTURE_BYTES {
                        let space = MAX_BODY_CAPTURE_BYTES - captured.len();
                        captured.extend_from_slice(&scratch[..useful.min(space)]);
                    }
                    received += useful;
                }
                Err(error) => return Err(format!("read HTTP response body: {error}")),
            }
        }
        return Ok(captured);
    }

    let mut scratch = [0_u8; 8192];
    loop {
        match stream.read(&mut scratch) {
            Ok(0) => break,
            Ok(read) => {
                if remainder.len() < MAX_BODY_CAPTURE_BYTES {
                    let space = MAX_BODY_CAPTURE_BYTES - remainder.len();
                    remainder.extend_from_slice(&scratch[..read.min(space)]);
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::ConnectionReset) && !remainder.is_empty() => break,
            Err(error) => return Err(format!("read close-delimited HTTP body: {error}")),
        }
    }
    Ok(remainder)
}

fn read_chunked_body(stream: &mut TcpStream, mut pending: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    loop {
        let line_end = loop {
            if let Some(offset) = find_subslice(&pending[cursor..], b"\r\n") {
                break cursor + offset;
            }
            read_more(stream, &mut pending, "chunk size line")?;
        };
        let size_line = std::str::from_utf8(&pending[cursor..line_end]).map_err(|_| "non-UTF-8 chunk size line".to_owned())?;
        let hex_part = size_line.split(';').next().unwrap_or_default().trim();
        let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|_| format!("invalid chunk size {hex_part:?}"))?;
        cursor = line_end + 2;

        if chunk_len == 0 {
            loop {
                if pending[cursor..].starts_with(b"\r\n") {
                    return Ok(out);
                }
                if find_subslice(&pending[cursor..], b"\r\n\r\n").is_some() {
                    return Ok(out);
                }
                read_more(stream, &mut pending, "chunked trailer terminator")?;
            }
        }

        let needed = chunk_len.checked_add(2).ok_or_else(|| "chunk length overflow".to_owned())?;
        while pending.len() - cursor < needed {
            read_more(stream, &mut pending, "chunk payload")?;
        }
        if &pending[cursor + chunk_len..cursor + chunk_len + 2] != b"\r\n" {
            return Err("chunk payload missing CRLF terminator".to_owned());
        }
        if out.len() < MAX_BODY_CAPTURE_BYTES {
            let space = MAX_BODY_CAPTURE_BYTES - out.len();
            out.extend_from_slice(&pending[cursor..cursor + chunk_len.min(space)]);
        }
        cursor += needed;
        if cursor > 65_536 {
            pending.drain(..cursor);
            cursor = 0;
        }
    }
}

fn read_more(stream: &mut TcpStream, buffer: &mut Vec<u8>, context: &str) -> Result<(), String> {
    let mut scratch = [0_u8; 8192];
    match stream.read(&mut scratch) {
        Ok(0) => Err(format!("truncated chunked response while reading {context}")),
        Ok(read) => {
            buffer.extend_from_slice(&scratch[..read]);
            Ok(())
        }
        Err(error) => Err(format!("read {context}: {error}")),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub(super) fn validate_xml_document(body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body).map_err(|error| format!("non-UTF-8 XML response: {error}"))?;
    let trimmed = text.trim_start();
    let without_decl = if let Some(rest) = trimmed.strip_prefix("<?xml") {
        let end = rest.find("?>").ok_or_else(|| "unterminated XML declaration".to_owned())?;
        &rest[end + 2..]
    } else {
        trimmed
    };
    xmltree::parse(without_decl)
        .map(|_| ())
        .ok_or_else(|| format!("document failed XML parse: {}", preview_body(body)))
}

pub(super) fn encode_metadata_header_value(value: &str) -> Vec<u8> {
    if value.is_ascii() && HeaderValue::from_bytes(value.as_bytes()).is_ok() {
        return value.as_bytes().to_vec();
    }
    format!("=?UTF-8?B?{}?=", base64_encode(value.as_bytes())).into_bytes()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(TABLE[((triple >> 6) & 0x3f) as usize]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(TABLE[(triple & 0x3f) as usize]));
        } else {
            out.push('=');
        }
    }
    out
}

pub(super) fn percent_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') || (!encode_slash && byte == b'/');
        if keep {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

pub(super) fn join_query(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn truncate_utf8(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &text[..boundary]
}

pub(super) fn preview_body(body: &[u8]) -> String {
    let slice = &body[..body.len().min(MAX_DIAGNOSTIC_BODY_BYTES)];
    let text = String::from_utf8_lossy(slice);
    text.replace(['\r', '\n'], " ")
}
