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

//! Responsible for: the two signature carriers aws-chunked framing places inside a request
//! body — the `chunk-signature` chunk extension and the `x-amz-trailer-signature` trailer
//! line — finding a live one, rewriting its value to the placeholder, and proving that a
//! claimed rewrite really happened.
//! Not responsible for: any other body content. A secret anywhere else in a payload stays a
//! refusal; see `redact`.
//! Upstream: `redact::scan`, `redact::sanitize` and the redaction-claim check.
//! Downstream: nothing; this module only reads and rewrites `schema::Entry` bodies.
//!
//! These two are the only body carriers with a sanitizer because they are the only ones whose
//! location is fixed by the wire format rather than by whatever the payload happens to be. A
//! signed aws-chunked body is `<hex-size>;chunk-signature=<sig>\r\n<data>\r\n` repeated, with an
//! optional `x-amz-trailer-signature:<sig>` line after the trailers, so the signature can be
//! replaced without touching a single byte of data or a single chunk-size line. The rewrite is
//! applied only when the request head declares that framing: the same text inside an ordinary
//! payload is user data, and rewriting it would change what the entry records.

use crate::base64;
use crate::redact::PLACEHOLDER;
use crate::schema::{Chunk, Entry};

/// The `redacted` record name for a rewritten chunk-extension signature.
pub const CHUNK_SIGNATURE: &str = "chunk-signature";

/// The `redacted` record name for a rewritten trailer signature.
pub const TRAILER_SIGNATURE: &str = "x-amz-trailer-signature";

/// Every body carrier this module can rewrite, with the bytes that introduce its value.
const CARRIERS: &[(&str, &[u8])] = &[
    (CHUNK_SIGNATURE, b";chunk-signature="),
    (TRAILER_SIGNATURE, b"x-amz-trailer-signature:"),
];

/// Whether `name` is a body carrier this module owns.
pub fn is_body_carrier(name: &str) -> bool {
    CARRIERS.iter().any(|(carrier, _)| name.eq_ignore_ascii_case(carrier))
}

/// Whether the request head declares aws-chunked framing, which is what makes the carriers
/// structural rather than payload text.
pub fn declares_framing(entry: &Entry) -> bool {
    entry.has_chunk_framing()
}

fn find_ignore_case(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// Where a carrier value ends: at the line end, at the next chunk extension, or at the end of
/// the buffer.
fn value_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n' | b';'))
        .map_or(bytes.len(), |offset| start + offset)
}

/// Whether `text` holds a trailer signature line whose value is 64 or more hexadecimal
/// characters — a live SigV4 (or longer SigV4a) signature.
///
/// The chunk extension needs no rule of its own: `chunk-signature=<hex>` is already caught by
/// the general `Signature=<64 hex>` rule. The trailer line is spelled with a colon, which that
/// rule does not match, so without this one a live trailer signature was invisible to the gate.
pub fn has_live_trailer_signature(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = CARRIERS[1].1;
    let mut from = 0;
    while let Some(start) = find_ignore_case(bytes, needle, from) {
        let value_start = start + needle.len();
        from = value_start;
        let value = &bytes[value_start..];
        let value = &value[value.iter().take_while(|byte| **byte == b' ' || **byte == b'\t').count()..];
        if value.iter().take_while(|byte| byte.is_ascii_hexdigit()).count() >= 64 {
            return true;
        }
    }
    false
}

/// Rewrite every non-placeholder carrier value in `bytes`, returning the rewritten bytes and
/// the carrier names touched.
fn rewrite(bytes: &[u8]) -> (Vec<u8>, Vec<&'static str>) {
    let mut out = bytes.to_vec();
    let mut touched = Vec::new();
    for (name, needle) in CARRIERS {
        let mut from = 0;
        while let Some(start) = find_ignore_case(&out, needle, from) {
            let value_start = start + needle.len();
            let end = value_end(&out, value_start);
            let value = &out[value_start..end];
            if value.is_empty() || value == PLACEHOLDER.as_bytes() {
                from = end;
                continue;
            }
            out.splice(value_start..end, PLACEHOLDER.bytes());
            from = value_start + PLACEHOLDER.len();
            if !touched.contains(name) {
                touched.push(*name);
            }
        }
    }
    (out, touched)
}

/// Rewrite the framing signature carriers in every data chunk of a framed entry, returning the
/// carrier names touched.
///
/// An entry whose head declares no framing is left alone, and so is a chunk whose payload is not
/// decodable base64: in both cases the text is not provably a carrier, and the gate refuses it.
pub fn sanitize_body(entry: &mut Entry) -> Vec<String> {
    if !declares_framing(entry) {
        return Vec::new();
    }
    let mut touched: Vec<String> = Vec::new();
    for chunk in entry.chunks.iter_mut().flatten() {
        let Chunk::Data { bytes_b64, .. } = chunk else {
            continue;
        };
        let Ok(bytes) = base64::decode(bytes_b64) else {
            continue;
        };
        let (rewritten, names) = rewrite(&bytes);
        if names.is_empty() {
            continue;
        }
        *bytes_b64 = base64::encode(&rewritten);
        for name in names {
            if !touched.iter().any(|known| known == name) {
                touched.push(name.to_owned());
            }
        }
    }
    touched
}

/// Whether a `redacted` record naming body carrier `claimed` describes the entry: the head
/// declares framing, and some data chunk carries that carrier holding the placeholder.
pub fn claim_holds(entry: &Entry, claimed: &str) -> bool {
    let Some((_, needle)) = CARRIERS.iter().find(|(carrier, _)| claimed.eq_ignore_ascii_case(carrier)) else {
        return false;
    };
    if !declares_framing(entry) {
        return false;
    }
    let mut expected = needle.to_vec();
    expected.extend_from_slice(PLACEHOLDER.as_bytes());
    entry.chunks.iter().flatten().any(|chunk| match chunk {
        Chunk::Data { bytes_b64, .. } => {
            base64::decode(bytes_b64).is_ok_and(|bytes| find_ignore_case(&bytes, &expected, 0).is_some())
        }
        Chunk::Control { .. } => false,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{CHUNK_SIGNATURE, TRAILER_SIGNATURE, claim_holds, has_live_trailer_signature, sanitize_body};
    use crate::base64;
    use crate::redact::{self, PLACEHOLDER};
    use crate::schema::{self, Capture, Chunk, Entry, Sut};

    const SIG_A: &str = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
    const SIG_B: &str = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";

    fn signed_body() -> String {
        format!("5;chunk-signature={SIG_A}\r\nhello\r\n0;chunk-signature={SIG_B}\r\n\r\n")
    }

    fn trailer_body() -> String {
        format!(
            "5;chunk-signature={SIG_A}\r\nhello\r\n0;chunk-signature={SIG_B}\r\n\
             x-amz-checksum-crc32c:mnG7TA==\r\nx-amz-trailer-signature:{SIG_A}\r\n\r\n"
        )
    }

    fn entry(mode: &str, body: &str) -> Entry {
        Entry {
            v: schema::CORPUS_SCHEMA_VERSION,
            op: "PutObject".to_owned(),
            src: "handwritten:gateway".to_owned(),
            recorded: "2026-09-28".to_owned(),
            capture: Capture::HeadFull,
            sut: Sut::None,
            method: "PUT".to_owned(),
            target: "/bucket/key".to_owned(),
            headers: vec![
                ("x-amz-content-sha256".to_owned(), mode.to_owned()),
                ("x-amz-decoded-content-length".to_owned(), "5".to_owned()),
            ],
            chunks: Some(vec![Chunk::Data {
                bytes_b64: base64::encode(body.as_bytes()),
                delay_ms: None,
            }]),
            resp: None,
            redacted: Vec::new(),
        }
    }

    fn body_text(entry: &Entry) -> String {
        match entry.chunks.as_deref() {
            Some([Chunk::Data { bytes_b64, .. }]) => String::from_utf8(base64::decode(bytes_b64).unwrap()).unwrap(),
            other => panic!("expected one data chunk, got {other:?}"),
        }
    }

    /// Negative — a live chunk signature in a framed body is refused before any sanitizing.
    #[test]
    fn a_live_chunk_signature_is_refused() {
        let framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", &signed_body());
        assert!(redact::admit(&framed).is_err());
    }

    /// Negative — a live trailer signature is refused even with every chunk signature redacted.
    /// The general signature rule does not match the colon spelling; this rule is what does.
    #[test]
    fn a_live_trailer_signature_is_refused() {
        let body = format!(
            "5;chunk-signature={PLACEHOLDER}\r\nhello\r\n0;chunk-signature={PLACEHOLDER}\r\n\
             x-amz-trailer-signature:{SIG_A}\r\n\r\n"
        );
        let framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", &body);
        assert!(has_live_trailer_signature(&body));
        let refusal = redact::admit(&framed).expect_err("a live trailer signature must be refused");
        assert!(
            refusal
                .findings
                .iter()
                .any(|finding| finding.reason == redact::Reason::SigV4Signature),
            "{refusal}"
        );
    }

    /// Negative — the same signature text in a body whose head declares no framing is user data:
    /// the sanitizer must not rewrite it, and the gate must go on refusing it.
    #[test]
    fn an_unframed_body_is_never_rewritten() {
        let mut plain = entry("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &signed_body());
        let before = plain.clone();
        assert!(sanitize_body(&mut plain).is_empty());
        assert_eq!(plain, before);
        assert!(redact::admit(&plain).is_err());
    }

    /// Negative — a claim that a body carrier was redacted, on a body that still holds the live
    /// value, is a laundering record and is refused.
    #[test]
    fn a_body_carrier_claim_over_a_live_value_is_refused() {
        let mut framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", &signed_body());
        framed.redacted = vec![CHUNK_SIGNATURE.to_owned()];
        assert!(!claim_holds(&framed, CHUNK_SIGNATURE));
        let refusal = redact::admit(&framed).expect_err("a laundering claim must be refused");
        assert!(
            refusal
                .findings
                .iter()
                .any(|finding| finding.reason == redact::Reason::UnprovenRedactionClaim),
            "{refusal}"
        );
    }

    /// Negative — a placeholder in a body whose head declares no framing does not prove a claim.
    #[test]
    fn a_body_carrier_claim_without_declared_framing_is_refused() {
        let body = format!("0;chunk-signature={PLACEHOLDER}\r\n\r\n");
        let mut plain = entry("UNSIGNED-PAYLOAD", &body);
        plain.redacted = vec![CHUNK_SIGNATURE.to_owned()];
        assert!(!claim_holds(&plain, CHUNK_SIGNATURE));
        assert!(redact::admit(&plain).is_err());
    }

    /// Negative — a claim naming a carrier that is not in the body at all is refused.
    #[test]
    fn a_trailer_claim_on_a_body_without_a_trailer_is_refused() {
        let mut framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", &signed_body());
        let _ = redact::sanitize(&mut framed);
        framed.redacted.push(TRAILER_SIGNATURE.to_owned());
        assert!(redact::admit(&framed).is_err());
    }

    /// Positive — sanitizing a framed body rewrites exactly the signature values, keeps every
    /// chunk-size line and every data byte, records the carriers, and is then admitted.
    #[test]
    fn sanitize_rewrites_only_the_signature_values() {
        let mut framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", &trailer_body());
        let touched = redact::sanitize(&mut framed);
        assert_eq!(touched, vec![CHUNK_SIGNATURE.to_owned(), TRAILER_SIGNATURE.to_owned()]);
        assert_eq!(framed.redacted, touched);
        assert_eq!(
            body_text(&framed),
            format!(
                "5;chunk-signature={PLACEHOLDER}\r\nhello\r\n0;chunk-signature={PLACEHOLDER}\r\n\
                 x-amz-checksum-crc32c:mnG7TA==\r\nx-amz-trailer-signature:{PLACEHOLDER}\r\n\r\n"
            )
        );
        redact::admit(&framed).expect("a sanitized framed body is admitted");
    }

    /// Positive — sanitizing twice changes nothing the second time.
    #[test]
    fn sanitize_is_idempotent_on_a_framed_body() {
        let mut framed = entry("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", &signed_body());
        let _ = redact::sanitize(&mut framed);
        let once = framed.clone();
        assert!(sanitize_body(&mut framed).is_empty());
        assert_eq!(framed, once);
    }
}
