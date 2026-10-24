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

//! Request-head assembly and external-profile signing inputs.
//!
//! Responsible for: structured framing, preserving authored raw bytes and supplying the RustFS
//! empty-payload SHA header before shared signing. NOT responsible for: socket I/O, signature
//! algorithms or fixture lifecycle. Upstream: `Conn`; downstream: the shared in-process signer.

use super::{Conn, ExternalEndpoint, Head, declared_content_length};
use crate::inprocess::{HOST, Wire, sign_request};
use crate::socket::parse_head;
use crate::sut::{Profile, SutError};
use crate::value::Value;

impl Conn {
    /// Builds the request head, signed, in the form the case asked for.
    pub(super) fn head(&self, wire: &Wire, request_time: &crate::time::Instant) -> Result<Head, SutError> {
        self.head_for_profile(wire, request_time, Profile::Aws)
    }

    /// Adds only the selected external profile's required signing input.
    pub(super) fn head_for_profile(
        &self,
        wire: &Wire,
        request_time: &crate::time::Instant,
        profile: Profile,
    ) -> Result<Head, SutError> {
        match &wire.raw_head {
            Some(raw) => self.raw_head(wire, raw, request_time, profile),
            None => self.structured_head(wire, request_time, profile),
        }
    }

    /// A head assembled from `method`, `target` and the header table.
    fn structured_head(&self, wire: &Wire, request_time: &crate::time::Instant, profile: Profile) -> Result<Head, SutError> {
        let mut headers = wire.headers.clone();
        add_profile_hash(wire, &mut headers, profile);
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            let host = self.external.as_ref().map_or(HOST, ExternalEndpoint::authority);
            headers.push(("host".to_owned(), host.to_owned()));
        }
        if !wire.body.is_empty() && !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            headers.push(("content-length".to_owned(), wire.body.len().to_string()));
        }
        // The framing is the header's, not the payload's: a case that announces five gigabytes and
        // writes ten bytes is announcing five gigabytes, and both the signature and the server's
        // body reader have to agree with what went on the wire.
        let declared_length = declared_content_length(&headers).unwrap_or(wire.body.len() as u64);
        let (headers, target) = match &wire.sign {
            None => (headers, wire.target.clone()),
            Some(sign) => sign_request(sign, wire, &headers, request_time, self.inner.limits(), declared_length)?,
        };
        let mut bytes = format!("{} {} HTTP/1.1\r\n", wire.method, target).into_bytes();
        for (name, value) in &headers {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        Ok(Head { bytes, declared_length })
    }

    /// A head the case wrote out byte for byte.
    ///
    /// The bytes are preserved and the signature is **appended**, never merged in. A raw head is an
    /// escape hatch for framing — `c-mpu-0045`'s whole subject is the `content-length` that is not
    /// there — and rewriting it to carry a signature would edit the very thing under test. What is
    /// added is what a real client adds and nothing else: the headers the signer minted that the
    /// head does not already carry.
    fn raw_head(&self, wire: &Wire, raw: &[u8], request_time: &crate::time::Instant, profile: Profile) -> Result<Head, SutError> {
        let Some(sign) = &wire.sign else {
            return Ok(Head {
                bytes: raw.to_vec(),
                declared_length: parse_head(raw).map_or(0, |head| declared_content_length(&head.headers).unwrap_or(0)),
            });
        };
        let parsed = parse_head(raw).ok_or_else(|| {
            SutError::Environment(
                "`request.raw_head_utf8` declares a signature and this head cannot be parsed well \
                 enough to compute one; a head that malformed has to be sent unsigned, which is a \
                 different case"
                    .to_owned(),
            )
        })?;
        let declared_length = declared_content_length(&parsed.headers).unwrap_or(0);
        // Signing needs a `Wire`, and the one the case wrote has no method or target of its own —
        // the raw head is where they live. Rebuilt from the parse so the signer sees what the wire
        // will carry.
        let signable = Wire {
            method: parsed.method.clone(),
            target: parsed.target.clone(),
            headers: parsed.headers.clone(),
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: wire.body.clone(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: wire.sign.clone(),
        };
        let mut signing_headers = parsed.headers.clone();
        add_profile_hash(&signable, &mut signing_headers, profile);
        let (signed, target) =
            sign_request(sign, &signable, &signing_headers, request_time, self.inner.limits(), declared_length)?;
        if target != parsed.target {
            return Err(SutError::Environment(
                "`sign.tamper` rewrote the request target of a raw head. Sending it would mean \
                 re-spelling the request line the case pinned, and sending the original would mean \
                 measuring a request nobody meant to send"
                    .to_owned(),
            ));
        }
        // Everything up to and including the last CRLF that ends the final header line; the blank
        // line is re-added after the appended headers so the head stays one message.
        let body_start = raw.len().saturating_sub(2);
        let mut bytes = raw.get(..body_start).unwrap_or_default().to_vec();
        for (name, value) in &signed {
            if parsed.headers.iter().any(|(have, _)| have.eq_ignore_ascii_case(name)) {
                continue;
            }
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        Ok(Head { bytes, declared_length })
    }
}

/// The shared signer already emits exact and unsigned payload hashes; only Empty omits its header.
fn add_profile_hash(wire: &Wire, headers: &mut Vec<(String, String)>, profile: Profile) {
    if profile != Profile::Rustfs
        || headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-content-sha256"))
    {
        return;
    }
    let Some(sign) = &wire.sign else { return };
    if sign.read("signSpec.mode").and_then(Value::as_str).unwrap_or("sigv4_header") != "sigv4_header" {
        return;
    }
    let empty_payload = match sign.read("signSpec.payload_hash").and_then(Value::as_str) {
        Some("empty") => true,
        None | Some("computed") => wire.body.is_empty(),
        _ => false,
    };
    if empty_payload {
        headers.push(("x-amz-content-sha256".to_owned(), crate::sha256::hex_digest(&[])));
    }
}
