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

//! A header-signed SigV4 request built by an independent signer, with one rule bent at a time, for
//! the RustFS-profile cases whose shape no SDK signer produces (rustfs/gateway#1130).
//!
//! Responsible for: [`HandSigned`], which signs as the main identity over `host`,
//! `x-amz-content-sha256` and `x-amz-date` with HMAC-SHA256 written out here, so what it signs is
//! decided by the case and not by the signer under test.
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

/// A request as the main identity, header-signed by hand.
pub(super) struct HandSigned {
    method: http::Method,
    path: &'static str,
    body: Bytes,
    unsigned: &'static [&'static str],
}

impl HandSigned {
    /// `method path` with `body`, signed over all three headers it sends.
    pub(super) fn new(method: http::Method, path: &'static str, body: Bytes) -> Self {
        Self {
            method,
            path,
            body,
            unsigned: &[],
        }
    }

    /// Sends `names` — any of `host`, `x-amz-content-sha256` and `x-amz-date` — without naming
    /// them in `SignedHeaders`, so the canonical request leaves them out too.
    pub(super) fn leaving_unsigned(mut self, names: &'static [&'static str]) -> Self {
        self.unsigned = names;
        self
    }

    /// The signed request, stamped now: the assembly verifies against the system clock.
    pub(super) fn request(&self) -> http::Request<Bytes> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
            .render(TimestampFormat::Iso8601Basic)
            .expect("a representable signing stamp");
        let day = &stamp[..8];
        let scope = format!("{day}/us-east-1/s3/aws4_request");
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
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
        let mut key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
        for part in ["us-east-1", "s3", "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
        let mut request = http::Request::builder().method(self.method.clone()).uri(self.path);
        for (name, value) in &sent {
            request = request.header(*name, value);
        }
        if !self.body.is_empty() || self.method == http::Method::PUT {
            request = request.header(http::header::CONTENT_LENGTH, self.body.len());
        }
        request
            .header(
                http::header::AUTHORIZATION,
                format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_names}, Signature={signature}"),
            )
            .body(self.body.clone())
            .expect("a valid request")
    }
}
