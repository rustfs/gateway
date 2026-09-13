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

//! The `header_accept` property: arbitrary header fields through request acceptance.
//!
//! Responsible for: decoding one fuzz input into two header ceilings and a list of header fields;
//! building the request head the way a transport hands it over; running the one acceptance entry
//! point, `WireRequest::accept`; and asserting what acceptance promises about every header block,
//! accepted or refused.
//! NOT responsible for: choosing a libFuzzer entry point, generating samples (the stable replay in
//! `crates/http/tests/header_accept_replay.rs` does that), framing (`framing_smuggling.rs` owns
//! W-1 to W-6 and this property only checks that framing is decided first), the host, or the query.
//! Upstream: libFuzzer bytes, a committed seed under `fuzz/seeds/header_accept/`, or the replay's
//! fixed-seed sampler. Downstream: `fuzz/fuzz_targets/header_accept.rs` and the replay, which run
//! this same file.
//!
//! # Input layout
//!
//! | Offset | Meaning |
//! | --- | --- |
//! | 0 | header-count ceiling: index into [`COUNT_CEILINGS`], modulo its length |
//! | 1 | header-byte ceiling: index into [`BYTE_CEILINGS`] |
//! | 2.. | fields, each a name then a value |
//!
//! A name is one byte `n`: with the top bit set, it is `VOCABULARY[(n & 0x7f) % len]`; clear, it
//! is the next `n` bytes. A value is one length byte and that many bytes, cut short at the end of
//! the input. A field `http` cannot represent — a name that is not a token, a value holding a
//! control — is skipped and counted, as is a field named `host`: every request carries the one
//! [`HOST_VALUE`] this file puts first, so that the host is never what decides.
//!
//! # What is asserted, beyond "it did not panic"
//!
//! 1. **Framing is decided first.** When `Framing::classify` refuses the head, acceptance refuses
//!    it with that same error, whatever else the headers hold.
//! 2. **Both ceilings are exact.** For a header block every other rule accepts, the verdict under
//!    the case's ceilings is the first ceiling the map's own field order crosses — count before
//!    bytes on the same field — or acceptance; a ceiling of exactly the block's field count and
//!    byte count accepts it; one field or one byte less is `HeaderCount` or `HeaderBytes`.
//! 3. **Every single-valued header is refused when repeated, by name.** The eleven names are
//!    written here, from the S3 contract, not read from `SINGLE_VALUED_HEADERS`: a second value of
//!    each non-framing name added to an accepted block is `DuplicateSingleValuedHeader(name)`,
//!    while a second `range` or `if-match` is still accepted.
//! 4. **Only a significant header must be readable.** A non-UTF-8 value added under each named
//!    significant header and under an `x-amz-` name is `NonUtf8SignificantHeader(name)`; the same
//!    bytes under a header this gateway gives no meaning to are accepted (s3s#597).
//! 5. **A metadata header with no name is refused.** `x-amz-meta-` added to an accepted block is
//!    `MalformedMetadata(MalformedKey)`.
//! 6. **Whatever is accepted obeys every rule.** Within both ceilings, no single-valued name twice,
//!    every significant value UTF-8, every metadata header valid by the metadata rules.
//!
//! The control-character rule is not exercised: a `HeaderValue` built from bytes already refuses
//! every control but tab, so no input here can carry one to acceptance.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the tables.

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Version, header::HOST};
use rustfs_gateway_http::{
    Framing, LimitKind, Limits, METADATA_PREFIX, MetadataReject, WireReject, WireRequest, validate_metadata_key,
    validate_metadata_value,
};

/// How many leading input bytes select the ceilings rather than form the fields.
pub(crate) const HEADER_BYTES: usize = 2;
/// The one host every request carries, as the first field.
pub(crate) const HOST_VALUE: &str = "bucket.example.com";
/// The header-count ceilings an input can select; `None` is production's `Limits::default()`.
pub(crate) const COUNT_CEILINGS: [Option<usize>; 3] = [Some(2), Some(8), None];
/// The header-byte ceilings an input can select; `None` is production's `Limits::default()`.
pub(crate) const BYTE_CEILINGS: [Option<usize>; 3] = [Some(48), Some(512), None];

/// The names a top-bit name byte selects: every name a rule here is about, and two it is not.
pub(crate) const VOCABULARY: [&str; 21] = [
    "authorization",
    "content-length",
    "content-md5",
    "content-type",
    "transfer-encoding",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-decoded-content-length",
    "x-amz-security-token",
    "x-amz-trailer",
    "expect",
    "range",
    "if-match",
    "date",
    "content-encoding",
    "x-amz-meta-color",
    "x-amz-meta-",
    "x-amz-tagging",
    "x-forwarded-for",
    "user-agent",
    "host",
];

/// The headers whose S3 semantics are single-valued. Written from the contract rather than read
/// from production's list, so that a name dropped from that list is a red replay.
pub(crate) const SINGLE_VALUED: [&str; 11] = [
    "authorization",
    "content-length",
    "content-md5",
    "content-type",
    "transfer-encoding",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-decoded-content-length",
    "x-amz-security-token",
    "x-amz-trailer",
    "expect",
];
/// Framing answers a second value of these two before any header rule runs.
const FRAMING_OWNED: [&str; 2] = ["content-length", "transfer-encoding"];
/// Repeatable: two lines join into one value the binding judges (RFC 9110 §5.3).
pub(crate) const TOLERATED_REPEATS: [&str; 2] = ["range", "if-match"];
/// The named headers this gateway attributes meaning to, beyond the `x-amz-` family.
pub(crate) const SIGNIFICANT_NAMED: [&str; 10] = [
    "host",
    "authorization",
    "content-length",
    "content-type",
    "content-md5",
    "content-encoding",
    "transfer-encoding",
    "date",
    "range",
    "expect",
];
/// An `x-amz-` name no vocabulary entry uses, for the readability probe.
const SIGNIFICANT_PROBE: &str = "x-amz-fuzz-probe";
/// A name this gateway gives no meaning to, for the tolerance probe.
const UNRELATED_PROBE: &str = "x-fuzz-proxy";
/// Bytes that are not UTF-8 and that a `HeaderValue` can carry.
const NOT_UTF8: &[u8] = b"\xff\xfe";

/// What one input selected.
#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub(crate) limits: Limits,
    pub(crate) headers: HeaderMap,
    /// Fields `http` could not represent, or named `host`.
    pub(crate) skipped: usize,
}

impl Case {
    /// Decodes an input into ceilings and a header map, or `None` when it is too short to select.
    pub(crate) fn parse(input: &[u8]) -> Option<Self> {
        let (header, mut rest) = input.split_first_chunk::<HEADER_BYTES>()?;
        let [count, bytes] = *header;
        let defaults = Limits::default();
        let limits = Limits {
            max_header_count: COUNT_CEILINGS[usize::from(count) % COUNT_CEILINGS.len()].unwrap_or(defaults.max_header_count),
            max_header_bytes: BYTE_CEILINGS[usize::from(bytes) % BYTE_CEILINGS.len()].unwrap_or(defaults.max_header_bytes),
            ..defaults
        };
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static(HOST_VALUE));
        let mut skipped = 0;
        while let Some((&selector, after)) = rest.split_first() {
            let (name, after): (&[u8], &[u8]) = if selector & 0x80 != 0 {
                (VOCABULARY[usize::from(selector & 0x7f) % VOCABULARY.len()].as_bytes(), after)
            } else {
                after.split_at(usize::from(selector).min(after.len()))
            };
            let (value, after) = match after.split_first() {
                Some((&length, after)) => after.split_at(usize::from(length).min(after.len())),
                None => (&[][..], after),
            };
            rest = after;
            match (HeaderName::from_bytes(name), HeaderValue::from_bytes(value)) {
                (Ok(name), Ok(value)) if name != HOST => {
                    headers.append(name, value);
                }
                _ => skipped += 1,
            }
        }
        Some(Self {
            limits,
            headers,
            skipped,
        })
    }
}

/// Encodes a case the way [`Case::parse`] reads it, every name spelled out.
pub(crate) fn encode(selectors: [u8; HEADER_BYTES], fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut input = selectors.to_vec();
    for (name, value) in fields {
        input.push(
            u8::try_from(name.len())
                .ok()
                .filter(|length| *length < 0x80)
                .expect("a spelled-out name is short"),
        );
        input.extend_from_slice(name);
        input.push(u8::try_from(value.len()).expect("a value is at most 255 bytes"));
        input.extend_from_slice(value);
    }
    input
}

/// What acceptance did with one input.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// Acceptance, or the named refusal.
    pub(crate) verdict: Result<(), WireReject>,
    /// Header fields in the map, repeats counted separately, `host` included.
    pub(crate) fields: usize,
    /// Name plus value bytes over every field.
    pub(crate) bytes: usize,
    /// Fields the input named that the map could not hold.
    pub(crate) skipped: usize,
    /// Whether framing decided the verdict.
    pub(crate) framing_refused: bool,
}

/// Runs one input through acceptance and asserts every property in the module docs.
///
/// Returns `None` for an input shorter than [`HEADER_BYTES`].
pub(crate) fn check(input: &[u8]) -> Option<Outcome> {
    let case = Case::parse(input)?;
    let headers = &case.headers;
    let limits = &case.limits;
    let (fields, bytes) = totals(headers);
    let verdict = accept(headers, limits);
    let mut outcome = Outcome {
        verdict: verdict.clone(),
        fields,
        bytes,
        skipped: case.skipped,
        framing_refused: false,
    };

    // 1. Framing first.
    if let Err(framing) = Framing::classify(Version::HTTP_11, headers, limits) {
        assert_eq!(verdict, Err(framing), "framing is decided before any header rule");
        outcome.framing_refused = true;
        return Some(outcome);
    }

    // 6. Whatever is accepted obeys every rule.
    if verdict.is_ok() {
        assert!(
            fields <= limits.max_header_count,
            "{fields} fields passed a count ceiling of {}",
            limits.max_header_count
        );
        assert!(
            bytes <= limits.max_header_bytes,
            "{bytes} bytes passed a byte ceiling of {}",
            limits.max_header_bytes
        );
        for name in SINGLE_VALUED {
            assert!(headers.get_all(name).iter().count() <= 1, "a repeated {name} was accepted");
        }
        for (name, value) in headers {
            if is_significant(name.as_str()) {
                assert!(core::str::from_utf8(value.as_bytes()).is_ok(), "an unreadable {name} was accepted");
            }
            if name.as_str().starts_with(METADATA_PREFIX) {
                assert_eq!(validate_metadata_key(name.as_str()), Ok(()), "a malformed metadata name was accepted");
                assert_eq!(
                    validate_metadata_value(value.as_bytes()),
                    Ok(()),
                    "a malformed metadata value was accepted"
                );
            }
        }
    }

    // Everything below asks what one change does to a block every other rule accepts.
    let unlimited = Limits {
        max_header_count: usize::MAX,
        max_header_bytes: usize::MAX,
        ..case.limits
    };
    if accept(headers, &unlimited).is_err() {
        return Some(outcome);
    }

    // 2. Both ceilings, exactly.
    assert_eq!(
        verdict,
        first_crossing(headers, limits).map_or(Ok(()), |kind| Err(WireReject::LimitExceeded(kind))),
        "the verdict is not the first ceiling the field order crosses",
    );
    let ceilings = |count: usize, bytes: usize| Limits {
        max_header_count: count,
        max_header_bytes: bytes,
        ..case.limits
    };
    assert_eq!(
        accept(headers, &ceilings(fields, bytes)),
        Ok(()),
        "ceilings of exactly the block refused it"
    );
    assert_eq!(
        accept(headers, &ceilings(fields - 1, usize::MAX)),
        Err(WireReject::LimitExceeded(LimitKind::HeaderCount)),
        "one field over the count ceiling was not refused by name",
    );
    assert_eq!(
        accept(headers, &ceilings(usize::MAX, bytes - 1)),
        Err(WireReject::LimitExceeded(LimitKind::HeaderBytes)),
        "one byte over the byte ceiling was not refused by name",
    );

    // 3. Repeats.
    for name in SINGLE_VALUED.iter().filter(|name| !FRAMING_OWNED.contains(name)) {
        let repeated = with_values(headers, name, 2 - headers.get_all(*name).iter().count(), b"1");
        let verdict = accept(&repeated, &unlimited);
        assert!(
            matches!(verdict, Err(WireReject::DuplicateSingleValuedHeader(refused)) if refused == *name),
            "a repeated {name} was answered {verdict:?}",
        );
    }
    for name in TOLERATED_REPEATS {
        let repeated = with_values(headers, name, 2, b"1");
        assert_eq!(accept(&repeated, &unlimited), Ok(()), "a repeated {name} was refused");
    }

    // 4. Readability.
    for name in SIGNIFICANT_NAMED
        .iter()
        .filter(|name| **name != "host" && !FRAMING_OWNED.contains(name))
        .chain([&SIGNIFICANT_PROBE])
    {
        let unreadable = with_values(headers, name, 1, NOT_UTF8);
        assert_eq!(
            accept(&unreadable, &unlimited),
            Err(WireReject::NonUtf8SignificantHeader(HeaderName::from_static(name))),
            "an unreadable {name} was not refused by name",
        );
    }
    let tolerated = with_values(headers, UNRELATED_PROBE, 1, NOT_UTF8);
    assert_eq!(accept(&tolerated, &unlimited), Ok(()), "an unreadable header nobody reads was refused");

    // 5. A metadata header with no name.
    let nameless = with_values(headers, METADATA_PREFIX, 1, b"v");
    assert_eq!(
        accept(&nameless, &unlimited),
        Err(WireReject::MalformedMetadata(MetadataReject::MalformedKey)),
        "a metadata header with no name was not refused",
    );

    Some(outcome)
}

/// Accepts a `PUT /bucket/key` over HTTP/1.1 carrying exactly `headers`.
fn accept(headers: &HeaderMap, limits: &Limits) -> Result<(), WireReject> {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri("/bucket/key")
        .version(Version::HTTP_11)
        .body(())
        .expect("a constant request head");
    *request.headers_mut() = headers.clone();
    WireRequest::accept(request, limits).map(|_| ())
}

/// Field count and name-plus-value bytes over the whole map.
fn totals(headers: &HeaderMap) -> (usize, usize) {
    headers.iter().fold((0, 0), |(fields, bytes), (name, value)| {
        (fields + 1, bytes + name.as_str().len() + value.len())
    })
}

/// The first ceiling crossed walking the map's own field order, the count before the bytes of the
/// same field.
fn first_crossing(headers: &HeaderMap, limits: &Limits) -> Option<LimitKind> {
    let (mut fields, mut bytes) = (0usize, 0usize);
    for (name, value) in headers {
        fields += 1;
        if fields > limits.max_header_count {
            return Some(LimitKind::HeaderCount);
        }
        bytes += name.as_str().len() + value.len();
        if bytes > limits.max_header_bytes {
            return Some(LimitKind::HeaderBytes);
        }
    }
    None
}

/// `headers` with `copies` more values of `value` under `name`.
fn with_values(headers: &HeaderMap, name: &str, copies: usize, value: &[u8]) -> HeaderMap {
    let mut changed = headers.clone();
    let name = HeaderName::from_bytes(name.as_bytes()).expect("a probe name is a token");
    let value = HeaderValue::from_bytes(value).expect("a probe value is representable");
    for _ in 0..copies {
        changed.append(name.clone(), value.clone());
    }
    changed
}

fn is_significant(name: &str) -> bool {
    name.starts_with("x-amz-") || SIGNIFICANT_NAMED.contains(&name)
}
