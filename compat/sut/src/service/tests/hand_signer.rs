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

//! A SigV4 request built by an independent signer, with one rule bent at a time, for the
//! RustFS-profile cases whose shape no SDK signer produces (rustfs/gateway#1130).
//!
//! Responsible for: [`HandSigned`], which signs as the main identity — header-signed over `host`,
//! `x-amz-content-sha256` and `x-amz-date`, presigned over `host`, or as a browser `POST` form —
//! with HMAC-SHA256 written out here, so what it signs is decided by the case and not by the signer
//! under test.
//! NOT responsible for: judging an answer (the topic files that use it), or the shapes an SDK does
//! produce (the parent module's `signed`).
//! Upstream: the parent module's identity constants. Downstream: the topic files under `tests/`.

use super::*;

use hmac::{Hmac, KeyInit, Mac};

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// RFC 3986 percent-encoding of everything but the unreserved characters, as a query component.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => char::from(byte).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (index, byte)| acc | (u32::from(*byte) << (16 - 8 * index)));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[((value >> (18 - 6 * index)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The current second as the signing stamp, and a second an hour later: the assembly verifies
/// against the system clock.
fn stamps() -> (String, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let now = i64::try_from(now).expect("a representable clock");
    let stamp = Timestamp::from_secs(now)
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let later = Timestamp::from_secs(now + 3600)
        .render(TimestampFormat::Iso8601)
        .expect("a representable expiration");
    (stamp, later)
}

const BOUNDARY: &str = "----RustFSHandSigned";

/// A request as the main identity, signed by hand.
pub(super) struct HandSigned {
    method: http::Method,
    path: &'static str,
    body: Bytes,
    unsigned: &'static [&'static str],
    service: &'static str,
    secret: &'static str,
}

impl HandSigned {
    /// `method path` with `body`, scoped to `us-east-1` and `s3`, and header-signed over all three
    /// headers it sends.
    pub(super) fn new(method: http::Method, path: &'static str, body: Bytes) -> Self {
        Self {
            method,
            path,
            body,
            unsigned: &[],
            service: "s3",
            secret: MAIN_SECRET,
        }
    }

    /// Sends `names` — any of `host`, `x-amz-content-sha256` and `x-amz-date` — without naming
    /// them in `SignedHeaders`, so the canonical request leaves them out too.
    pub(super) fn leaving_unsigned(mut self, names: &'static [&'static str]) -> Self {
        self.unsigned = names;
        self
    }

    /// Names `service` in the credential scope, and derives the key from it.
    pub(super) fn in_service(mut self, service: &'static str) -> Self {
        self.service = service;
        self
    }

    /// Signs with the secret of the second identity under the main identity's access key: a
    /// signature that does not match.
    pub(super) fn forged(mut self) -> Self {
        self.secret = ALT_SECRET;
        self
    }

    fn scope(&self, day: &str) -> String {
        format!("{day}/us-east-1/{}/aws4_request", self.service)
    }

    fn signature(&self, day: &str, string_to_sign: &str) -> String {
        let mut key = hmac_sha256(format!("AWS4{}", self.secret).as_bytes(), day.as_bytes());
        for part in ["us-east-1", self.service, "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        hex(&hmac_sha256(&key, string_to_sign.as_bytes()))
    }

    fn string_to_sign(&self, stamp: &str, canonical: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{}\n{}",
            self.scope(&stamp[..8]),
            hex(&Sha256::digest(canonical.as_bytes()))
        )
    }

    /// The header-signed request, stamped now.
    pub(super) fn request(&self) -> http::Request<Bytes> {
        let (stamp, _) = stamps();
        let payload = hex(&Sha256::digest(&self.body));
        let sent = [
            ("host", "s3.example.com".to_owned()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", stamp.clone()),
        ];
        let named: Vec<&(&str, String)> = sent.iter().filter(|(name, _)| !self.unsigned.contains(name)).collect();
        let canonical_headers: String = named.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
        let signed_names = named.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
        let canonical = format!("{}\n{}\n\n{canonical_headers}\n{signed_names}\n{payload}", self.method, self.path);
        let signature = self.signature(&stamp[..8], &self.string_to_sign(&stamp, &canonical));
        let mut request = http::Request::builder().method(self.method.clone()).uri(self.path);
        for (name, value) in &sent {
            request = request.header(*name, value);
        }
        if !self.body.is_empty() || self.method == http::Method::PUT {
            request = request.header(http::header::CONTENT_LENGTH, self.body.len());
        }
        let scope = self.scope(&stamp[..8]);
        request
            .header(
                http::header::AUTHORIZATION,
                format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_names}, Signature={signature}"),
            )
            .body(self.body.clone())
            .expect("a valid request")
    }

    /// The same request presigned over `host`, stamped now, for five minutes: the payload is
    /// signed as `UNSIGNED-PAYLOAD`, as the RustFS profile reads every presigned request.
    pub(super) fn presigned(&self) -> http::Request<Bytes> {
        let (stamp, _) = stamps();
        let credential = format!("{MAIN_KEY}/{}", self.scope(&stamp[..8]));
        let parameters = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", credential.as_str()),
            ("X-Amz-Date", stamp.as_str()),
            ("X-Amz-Expires", "300"),
            ("X-Amz-SignedHeaders", "host"),
        ];
        let query = parameters
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let canonical = format!("{}\n{}\n{query}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD", self.method, self.path);
        let signature = self.signature(&stamp[..8], &self.string_to_sign(&stamp, &canonical));
        let mut request = http::Request::builder()
            .method(self.method.clone())
            .uri(format!("{}?{query}&X-Amz-Signature={signature}", self.path))
            .header(http::header::HOST, "s3.example.com");
        if !self.body.is_empty() || self.method == http::Method::PUT {
            request = request.header(http::header::CONTENT_LENGTH, self.body.len());
        }
        request.body(self.body.clone()).expect("a valid presigned request")
    }

    /// A browser `POST` to this request's path, a bucket, storing `file` under `key`, its policy
    /// signed now.
    pub(super) fn posted(&self, key: &str, file: &str) -> http::Request<Bytes> {
        let (stamp, expires) = stamps();
        let bucket = self.path.trim_start_matches('/');
        let credential = format!("{MAIN_KEY}/{}", self.scope(&stamp[..8]));
        let document = format!(
            "{{\"expiration\":\"{expires}\",\"conditions\":[{{\"bucket\":\"{bucket}\"}},[\"eq\",\"$key\",\"{key}\"],\
             {{\"x-amz-algorithm\":\"AWS4-HMAC-SHA256\"}},{{\"x-amz-credential\":\"{credential}\"}},{{\"x-amz-date\":\"{stamp}\"}}]}}"
        );
        let policy = base64(document.as_bytes());
        let signature = self.signature(&stamp[..8], &policy);
        let mut body = String::new();
        for (name, value) in [
            ("key", key),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", credential.as_str()),
            ("x-amz-date", stamp.as_str()),
            ("policy", policy.as_str()),
            ("x-amz-signature", signature.as_str()),
        ] {
            body.push_str(&format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ));
        }
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n\
             Content-Type: text/plain\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"
        ));
        http::Request::builder()
            .method(http::Method::POST)
            .uri(self.path)
            .header(http::header::HOST, "s3.example.com")
            .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(Bytes::from(body))
            .expect("a valid form request")
    }
}
