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

//! The two fuzz properties of the differential, and the one input format they and the
//! fuzz-to-case converter share.
//!
//! Responsible for: reading fuzz bytes as a request in HTTP/1.1 message form
//! (`METHOD target\nname: value\n…\n\nbody`, `\r\n` accepted) and writing a request back in that
//! form ([`request_of`], [`render`]); [`check_decode`], which fails on a route difference the
//! register does not accept (the two stacks sent the same bytes to different operations); and
//! [`check_encode`], which builds a listing and a head answer from fuzz bytes (control characters
//! removed, see [`outputs_of`]) and fails on any unregistered encode difference other than a member
//! the gateway output cannot hold.
//! What the reader changes, so a finding is about the codec and not about the harness: framing
//! (`content-length` and `transfer-encoding` lines are dropped and `content-length` is set from the
//! body for a body or a `PUT`/`POST`, because framing is the transport's), the `x-id` query hint
//! (removed: s3s routes by it and the gateway does not, a known class, kd-decode-0055..0063), an
//! escaped slash in the first path segment (refused: s3s decodes it into a bucket/key separator and
//! the gateway reads it as part of the bucket name, a known class this property found,
//! kd-decode-0064..0071), a date value that is not ASCII (refused until rustfs/gateway#1013 is
//! fixed: the gateway's date parser panics on one, which this property found and which would
//! otherwise stop every run at the same input), and a signed chunk framing (refused: its
//! signatures cannot be made). A request carrying SSE-C members
//! is sent as over TLS, as in the matrix.
//! Only a misroute fails the decode property: both stacks naming an operation, and naming different
//! ones. The two stacks refuse malformed input with different codes, messages and stages all the
//! time (the gateway refuses an unknown `x-amz-checksum-*` header before it names an operation;
//! s3s ignores it), and a property that failed on every one would find nothing else; refusal,
//! outcome and member differences stay the matrix's and the corpus runner's. Likewise the encode property compares only answers s3s can write: an output
//! s3s answers with a 500 (a value its types cannot serialise) is outside the oracle's domain, and a
//! member the gateway output cannot hold is a refused conversion, reported elsewhere.
//! NOT responsible for: the libFuzzer entry points (`fuzz/fuzz_targets/decode_diff.rs`,
//! `encode_diff.rs`), or the stable replay (`tests/fuzz.rs`).
//! Upstream: `decode.rs`, `encode.rs`, `known.rs`. Downstream: the fuzz targets, the replay, the
//! `fuzz-to-case` binary.

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http::Method;

use crate::decode::{Differ, Finding, Item, Priority};
use crate::encode::OutputSample;
use crate::known::KnownDiffs;
use crate::project::OracleOutput;
use crate::request::RawRequest;
use crate::s3s::dto as oracle;

/// The request headers the gateway parses as dates; see the module documentation (#1013).
const DATE_HEADERS: [&str; 7] = [
    "if-modified-since",
    "if-unmodified-since",
    "x-amz-copy-source-if-modified-since",
    "x-amz-copy-source-if-unmodified-since",
    "expires",
    "x-amz-object-lock-retain-until-date",
    "x-amz-if-match-last-modified-time",
];

/// Whether a query value, percent-decoded, is ASCII: an escape of a byte above 0x7F is not.
fn percent_decoded_is_ascii(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.is_ascii()
        && !bytes.iter().enumerate().any(|(at, byte)| {
            *byte == b'%'
                && bytes
                    .get(at + 1..at + 3)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    .is_some_and(|decoded| !decoded.is_ascii())
        })
}

/// The query parameter s3s routes by and the gateway ignores; see the module documentation.
const OPERATION_HINT: &str = "x-id";

/// One fuzz input as a request, or `None` when the bytes are not a request both stacks can be
/// handed.
#[must_use]
pub fn request_of(input: &[u8]) -> Option<RawRequest> {
    let (head, body) = split_head(input);
    let mut lines = head
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let start = lines.next()?;
    let mut words = start.splitn(3, |byte| *byte == b' ');
    let method = Method::from_bytes(words.next()?).ok()?;
    let target = without_hint(std::str::from_utf8(words.next()?).ok()?);
    let target = target.as_str();
    // The same parse the stacks' request head gets (`RawRequest::http_head`), in origin form only,
    // applied to the target as it is sent.
    let uri = target.parse::<http::Uri>().ok()?;
    if !target.starts_with('/') || uri.scheme().is_some() || uri.authority().is_some() {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if query.split('&').any(|pair| {
        pair.split_once('=')
            .is_some_and(|(name, value)| name == "response-expires" && !percent_decoded_is_ascii(value))
    }) {
        return None;
    }
    let first_segment = path[1..].split('/').next().unwrap_or_default();
    if first_segment.to_ascii_lowercase().contains("%2f") {
        return None;
    }
    let mut request = RawRequest::new(method.clone(), target);
    for line in lines.filter(|line| !line.is_empty()) {
        let colon = line.iter().position(|byte| *byte == b':')?;
        let name = std::str::from_utf8(&line[..colon]).ok()?.trim();
        let value = trim_leading_space(&line[colon + 1..]);
        http::HeaderName::from_bytes(name.as_bytes()).ok()?;
        http::HeaderValue::from_bytes(value).ok()?;
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        if name.eq_ignore_ascii_case("x-amz-content-sha256") && value.starts_with(b"STREAMING-AWS4-") {
            return None;
        }
        if DATE_HEADERS.iter().any(|date| name.eq_ignore_ascii_case(date)) && !value.is_ascii() {
            return None;
        }
        if name.to_ascii_lowercase().contains("server-side-encryption-customer") {
            request.secure = true;
        }
        request.headers.push((name.to_owned(), value.to_vec()));
    }
    if !body.is_empty() || matches!(method, Method::PUT | Method::POST) {
        request
            .headers
            .push(("content-length".to_owned(), body.len().to_string().into_bytes()));
    }
    if !body.is_empty() {
        request.body = vec![Bytes::copy_from_slice(body)];
    }
    Some(request)
}

/// `request` in the form [`request_of`] reads: the seeds, and the bytes a converted case replays.
#[must_use]
pub fn render(request: &RawRequest) -> Vec<u8> {
    let mut out = format!("{} {}\n", request.method, request.target).into_bytes();
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out.push(b'\n');
    for piece in &request.body {
        out.extend_from_slice(piece);
    }
    out
}

fn split_head(input: &[u8]) -> (&[u8], &[u8]) {
    for separator in [&b"\r\n\r\n"[..], &b"\n\n"[..]] {
        if let Some(at) = input.windows(separator.len()).position(|window| window == separator) {
            return (&input[..at], &input[at + separator.len()..]);
        }
    }
    (input, &[])
}

fn trim_leading_space(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(start, |at| at + 1);
    &value[start..end.max(start)]
}

fn without_hint(target: &str) -> String {
    let Some((path, query)) = target.split_once('?') else {
        return target.to_owned();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| pair.split_once('=').map_or(*pair, |(name, _)| name) != OPERATION_HINT)
        .collect();
    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

fn register() -> Result<&'static KnownDiffs, String> {
    static REGISTER: OnceLock<Result<KnownDiffs, String>> = OnceLock::new();
    REGISTER
        .get_or_init(|| KnownDiffs::checked_in().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

thread_local! {
    static DIFFER: Result<Differ, String> = Differ::new();
}

fn describe(findings: &[Finding]) -> String {
    findings.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}

/// The unregistered route differences of one request, judged by `differ`.
///
/// # Errors
///
/// The harness failed on the request.
pub(crate) fn route_differences(differ: &Differ, request: &RawRequest) -> Result<Vec<Finding>, String> {
    let diff = differ.diff(request)?;
    let misrouted = matches!((&diff.operation.gateway, &diff.operation.s3s), (Some(gateway), Some(s3s)) if gateway != s3s);
    if !misrouted {
        return Ok(Vec::new());
    }
    let verdict = register()?.verdict_for(request, diff.findings());
    Ok(verdict
        .failures
        .into_iter()
        .filter(|finding| finding.priority == Priority::Route)
        .collect())
}

/// The decode property: the two stacks route the same bytes to the same operation, or the
/// register accepts the difference.
///
/// # Errors
///
/// The unregistered route differences, rendered, or the harness failure.
pub fn check_decode(input: &[u8]) -> Result<(), String> {
    let Some(request) = request_of(input) else {
        return Ok(());
    };
    DIFFER.with(|differ| {
        let differ = differ.as_ref().map_err(Clone::clone)?;
        let differences = route_differences(differ, &request)?;
        if differences.is_empty() {
            Ok(())
        } else {
            Err(format!("unregistered route difference: {}", describe(&differences)))
        }
    })
}

/// The instant every fuzzed listing entry was last modified: 2026-01-01T00:00:00Z.
fn last_modified() -> oracle::Timestamp {
    oracle::Timestamp::from(time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_767_225_600))
}

/// Splits fuzz bytes into at most `limit` UTF-8 fields on `0x00`, lossily.
fn fields(input: &[u8], limit: usize) -> Vec<String> {
    input
        .split(|byte| *byte == 0)
        .take(limit)
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect()
}

/// A listing member without what makes the gateway percent-encode the whole answer — a C0
/// control, DEL, or a character XML 1.0 cannot hold (U+FFFE, U+FFFF) — the known class this
/// property found (kd-encode-0051..0057; s3s writes U+FFFF raw, which no XML parser accepts).
fn listing_member(text: &str) -> String {
    text.chars()
        .filter(|character| !(character.is_ascii_control() || matches!(character, '\u{fffe}' | '\u{ffff}')))
        .collect()
}

/// A header value without what no header field can carry at all (C0 controls other than tab,
/// DEL): both stacks refuse or drop such a value, which says nothing about encoding.
fn header_value(text: &str) -> String {
    text.chars()
        .filter(|character| *character == '\t' || !character.is_ascii_control())
        .collect()
}

/// A metadata value as [`header_value`], less the known classes this property found: a C1
/// control or a tab, either of which makes the gateway drop the header where s3s writes an
/// encoded word (kd-encode-0059, kd-encode-0061, rustfs/gateway#996); the encoded-word opener
/// `=?` or closer `?=`, which only the gateway encodes (kd-encode-0060); and, for a value that
/// is not ASCII, the bytes past 40, where the gateway splits the encoded word and s3s does not
/// (kd-encode-0058).
fn metadata_value(text: &str) -> String {
    let mut value: String = header_value(text)
        .chars()
        .filter(|character| *character != '\t' && !('\u{80}'..='\u{9f}').contains(character))
        .collect();
    while value.contains("=?") || value.contains("?=") {
        value = value.replace("=?", "=").replace("?=", "=");
    }
    if !value.is_ascii() {
        while value.len() > 40 {
            value.pop();
        }
    }
    value
}

/// A metadata name made of token characters: any other byte makes s3s fail to write the header,
/// which would skip the whole head sample and leave its other members uncompared.
fn metadata_name(text: &str) -> String {
    text.chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// A listing and a head answer built from fuzz bytes: keys, prefix, delimiter and tokens of a
/// `ListObjectsV2` answer, and the metadata, content type and disposition of a `HeadObject` one.
#[must_use]
pub fn outputs_of(input: &[u8]) -> Vec<OutputSample> {
    let fields = fields(input, 12);
    let field = |index: usize| fields.get(index).cloned().unwrap_or_default();
    let keys: Vec<String> = fields
        .iter()
        .skip(4)
        .map(|key| listing_member(key))
        .filter(|key| !key.is_empty())
        .collect();
    let (prefix, delimiter, token, after) = (
        listing_member(&field(0)),
        listing_member(&field(1)),
        listing_member(&field(2)),
        listing_member(&field(3)),
    );
    let listing = move || {
        OracleOutput::ListObjectsV2(oracle::ListObjectsV2Output {
            name: Some("bkt".to_owned()),
            prefix: Some(prefix.clone()),
            delimiter: (!delimiter.is_empty()).then(|| delimiter.clone()),
            max_keys: Some(1000),
            key_count: i32::try_from(keys.len()).ok(),
            continuation_token: (!token.is_empty()).then(|| token.clone()),
            next_continuation_token: None,
            is_truncated: Some(false),
            start_after: (!after.is_empty()).then(|| after.clone()),
            contents: Some(
                keys.iter()
                    .map(|key| oracle::Object {
                        key: Some(key.clone()),
                        size: Some(5),
                        e_tag: Some(oracle::ETag::Strong("5d41402abc4b2a76b9719d911017c592".to_owned())),
                        last_modified: Some(last_modified()),
                        storage_class: Some(oracle::ObjectStorageClass::from("STANDARD".to_owned())),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        })
    };
    let (content_type, disposition) = (header_value(&field(0)), header_value(&field(1)));
    let (name, value) = (metadata_name(&field(2)), metadata_value(&field(3)));
    let head = move || {
        OracleOutput::HeadObject(oracle::HeadObjectOutput {
            content_length: Some(5),
            e_tag: Some(oracle::ETag::Strong("abc".to_owned())),
            content_type: (!content_type.is_empty()).then(|| content_type.clone()),
            content_disposition: (!disposition.is_empty()).then(|| disposition.clone()),
            metadata: (!name.is_empty()).then(|| [(name.clone(), value.clone())].into_iter().collect()),
            ..Default::default()
        })
    };
    vec![
        OutputSample {
            name: "fuzz-list-objects-v2".to_owned(),
            request: RawRequest::get("/bkt?list-type=2"),
            output: Arc::new(listing),
        },
        OutputSample {
            name: "fuzz-head-object".to_owned(),
            request: RawRequest::head("/bkt/k"),
            output: Arc::new(head),
        },
    ]
}

/// The unregistered encode differences of one sample, other than members the gateway output
/// cannot hold (those say the conversion refused, which is reported, not a wire difference).
///
/// # Errors
///
/// The harness failed on the sample.
pub(crate) fn encode_differences(differ: &Differ, sample: &OutputSample) -> Result<Vec<Finding>, String> {
    let diff = differ.encode(sample)?;
    if diff.status.s3s == 500 && diff.status.gateway != 500 {
        return Ok(Vec::new());
    }
    let verdict = register()?.verdict(diff.findings());
    Ok(verdict
        .failures
        .into_iter()
        .filter(|finding| !matches!(finding.item, Item::Unconvertible(_)))
        .collect())
}

/// The encode property: the two stacks write the same answer for outputs built from fuzz bytes,
/// or the register accepts the difference.
///
/// # Errors
///
/// The unregistered differences, rendered, or the harness failure.
pub fn check_encode(input: &[u8]) -> Result<(), String> {
    DIFFER.with(|differ| {
        let differ = differ.as_ref().map_err(Clone::clone)?;
        for sample in outputs_of(input) {
            let differences = encode_differences(differ, &sample)?;
            if !differences.is_empty() {
                return Err(format!("{}: unregistered encode difference: {}", sample.name, describe(&differences)));
            }
        }
        Ok(())
    })
}
