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

//! A minimal HTTP/1.1 client over `std::net::TcpStream`, used only to redeem presigned URLs.
//!
//! Responsible for: sending one request exactly as the SDK presigned it (method, URL, signed
//! headers) plus an optional body, and returning the status code and the response body.
//! Generation is the SDK's half and verification the server's, so the SDK must not be the one to
//! send it; the standard library is the smallest honest plain client, and the matrix endpoint is
//! plaintext `http://`, so no TLS is needed.
//! NOT responsible for: TLS, redirects, keep-alive or retries. It refuses an `https://` URL rather
//! than pretending to speak it.
//!
//! Upstream: the presigned-get and presigned-put scenarios in `scenarios.rs`. Downstream: the
//! system under test's plaintext listener.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::{fail, Step};

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends `method url` with `headers` (the `host` header is written from the URL) and `body`.
pub fn send<'a>(
    method: &str,
    url: &str,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
    body: Option<&[u8]>,
) -> Step<Response> {
    let Some(rest) = url.strip_prefix("http://") else {
        return fail(format!("the plain HTTP client speaks only http://, not {url}"));
    };
    let (authority, target) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = TcpStream::connect(&address)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let Some(status) = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
    else {
        return fail(format!("the server answered with a malformed status line {:?}", status_line.trim_end()));
    };
    let mut length = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return fail("the connection closed inside the response headers");
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                length = value.parse::<usize>().ok();
            } else if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    let body = if method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else if chunked {
        read_chunked(&mut reader)?
    } else if let Some(length) = length {
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        body
    } else {
        let mut body = Vec::new();
        reader.read_to_end(&mut body)?;
        body
    };
    Ok(Response { status, body })
}

fn read_chunked(reader: &mut impl BufRead) -> Step<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size_text = size_line.trim_end().split(';').next().unwrap_or("");
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return fail(format!("the server sent a malformed chunk size {size_text:?}"));
        };
        if size == 0 {
            return Ok(body); // trailers, if any, are not needed
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..])?;
        let mut crlf = [0; 2];
        reader.read_exact(&mut crlf)?;
    }
}
