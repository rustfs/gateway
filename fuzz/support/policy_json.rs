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

//! The `policy_json` property: arbitrary bytes as a `PutBucketPolicy` body.
//!
//! Responsible for: running one input through the generated `PutBucketPolicy` decoder and the
//! bucket policy checks every backend is handed (`validate_policy`), holding the verdict to an
//! independent strict reader, and probing every accepted document at each of its boundaries.
//! NOT responsible for: choosing a libFuzzer entry point, generating samples (the stable replay in
//! `crates/core/tests/policy_json_replay.rs` does that), evaluating what a policy grants, or the
//! POST-policy JSON of browser uploads (`rustfs-gateway-sig`'s `post_policy_json`, a different
//! contract).
//! Upstream: libFuzzer bytes, a committed seed under `fuzz/seeds/policy_json/`, or the replay's
//! fixed-seed sampler. Downstream: `fuzz/fuzz_targets/policy_json.rs` and the replay, which run
//! this same file.
//!
//! # Input layout
//!
//! The whole input is the request body. There is no header: the size ceiling is crossed by the
//! probes below rather than by selecting a smaller one, because the bucket policy has exactly one
//! ceiling and it is the production value.
//!
//! # The reference reader
//!
//! `serde_json` — the reader RustFS loads a stored bucket policy with — driven through a visitor
//! that measures nesting depth and refuses a member name repeated within one object, because
//! `serde_json::Value` would silently keep the last one. It shares no code with the scanner under
//! test, which is iterative and hand-written; that independence is what makes agreement mean
//! something.
//!
//! # What is asserted, beyond "it did not panic"
//!
//! 1. **The codec refuses only what is not text.** A body that is not UTF-8 is `MalformedPolicy`
//!    before any check runs; any other body reaches the handler byte for byte.
//! 2. **The size ceiling is first and exact.** A body over [`MAX_POLICY_BYTES`] is `TooLarge`
//!    whatever it holds; an accepted document padded with JSON whitespace to exactly the ceiling
//!    is still accepted, and one byte more is `TooLarge`.
//! 3. **The verdict agrees with the strict reader, both ways.** Whitespace alone is `Empty`. A
//!    document the reader takes as an object no deeper than [`MAX_POLICY_DEPTH`] is accepted, and
//!    nothing else is: any other well-formed value is `NotAnObject`, anything deeper is `TooDeep`,
//!    and a document the reader refuses — broken syntax, a non-string member name, an escape or
//!    number JSON does not have, an unpaired surrogate, an out-of-range number, a repeated member
//!    name — is `NotJson`, or `TooDeep` when the reader had already gone past the ceiling before
//!    it stopped.
//! 4. **The depth ceiling is exact.** An accepted document wrapped in objects to exactly the
//!    ceiling is accepted, and one more level is `TooDeep`.
//! 5. **Member names are compared as names, per object.** The accepted document with its root's
//!    first member name repeated in front of it — spelled with its first character as a `\u`
//!    escape, so a byte comparison would see two names — is `NotJson`.
//! 6. **An accepted document round-trips.** The `GetBucketPolicy` encoder hands back the exact
//!    bytes that were written, and the reader's own re-serialisation of the document is accepted
//!    at the same depth.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the outcome.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;

use bytes::Bytes;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody, ResponseBody};
use rustfs_gateway_core::ops::shared::bucket_policy::{MAX_POLICY_BYTES, MAX_POLICY_DEPTH, PolicyRejection, validate_policy};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;
use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

/// Why an input was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The codec refused a body that is not UTF-8, as `MalformedPolicy`.
    NotUtf8,
    /// `validate_policy` refused the document.
    Policy(PolicyRejection),
}

/// What the reference reader made of a UTF-8 document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    /// A JSON object, nesting `depth` containers deep (the root is one), whose first member name —
    /// when it has one — is `first_name`.
    Object { depth: usize, first_name: Option<String> },
    /// Any other JSON value; a scalar is depth zero.
    Other { depth: usize },
    /// Well-formed up to a member name repeated within one object.
    Duplicate { deepest: usize },
    /// Refused for any other reason, having reached `deepest` containers before stopping.
    Invalid { deepest: usize },
}

/// Which boundary probes ran on an accepted document; the replay counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Probes {
    pub(crate) size: bool,
    pub(crate) depth: bool,
    pub(crate) duplicate: bool,
    pub(crate) canonical: bool,
}

/// The verdict for one input, what the reference reader saw, and which probes ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) verdict: Result<(), Refusal>,
    /// `None` for a body that is not UTF-8, is over the ceiling, or is only whitespace.
    pub(crate) reading: Option<Reading>,
    pub(crate) probes: Probes,
}

/// Runs the property over one input and returns what it found. Panics on any violation.
pub(crate) fn check(input: &[u8]) -> Outcome {
    let decoded = decode(input);
    let Ok(document) = core::str::from_utf8(input) else {
        assert_eq!(
            decoded,
            Err("MalformedPolicy".to_owned()),
            "a body that is not UTF-8 is refused by the codec"
        );
        return Outcome {
            verdict: Err(Refusal::NotUtf8),
            reading: None,
            probes: Probes::default(),
        };
    };
    assert_eq!(
        decoded.as_deref(),
        Ok(document),
        "the codec carries a text body to the handler byte for byte"
    );
    let verdict = validate_policy(document).map_err(Refusal::Policy);

    if document.len() > MAX_POLICY_BYTES {
        assert_eq!(verdict, Err(Refusal::Policy(PolicyRejection::TooLarge)), "over the size ceiling");
        return Outcome {
            verdict,
            reading: None,
            probes: Probes::default(),
        };
    }
    if document.trim().is_empty() {
        assert_eq!(verdict, Err(Refusal::Policy(PolicyRejection::Empty)), "whitespace alone");
        return Outcome {
            verdict,
            reading: None,
            probes: Probes::default(),
        };
    }

    let reading = read(document);
    let policy = |rejection| Err(Refusal::Policy(rejection));
    match &reading {
        Reading::Object { depth, .. } if *depth <= MAX_POLICY_DEPTH => {
            assert_eq!(verdict, Ok(()), "a strict reader's object within the ceilings: {reading:?}");
        }
        Reading::Object { .. } | Reading::Other { .. } if reading_depth(&reading) > MAX_POLICY_DEPTH => {
            assert_eq!(verdict, policy(PolicyRejection::TooDeep), "{reading:?}");
        }
        Reading::Other { .. } => {
            assert_eq!(verdict, policy(PolicyRejection::NotAnObject), "{reading:?}");
        }
        Reading::Duplicate { deepest } | Reading::Invalid { deepest } => {
            if *deepest <= MAX_POLICY_DEPTH {
                assert_eq!(verdict, policy(PolicyRejection::NotJson), "{reading:?}");
            } else {
                assert!(
                    verdict == policy(PolicyRejection::NotJson) || verdict == policy(PolicyRejection::TooDeep),
                    "{reading:?} was answered {verdict:?}"
                );
            }
        }
        Reading::Object { .. } => unreachable!("the depth guards above are exhaustive"),
    }

    let mut probes = Probes::default();
    if let (Ok(()), Reading::Object { depth, first_name }) = (verdict, &reading) {
        assert_eq!(stored_then_read(document), input, "GetBucketPolicy hands back the written bytes");
        probes.size = size_probe(document);
        probes.depth = depth_probe(document, *depth);
        probes.duplicate = first_name.as_deref().is_some_and(|name| duplicate_probe(document, name));
        probes.canonical = canonical_probe(document, *depth);
    }
    Outcome {
        verdict,
        reading: Some(reading),
        probes,
    }
}

fn reading_depth(reading: &Reading) -> usize {
    match reading {
        Reading::Object { depth, .. } | Reading::Other { depth } => *depth,
        Reading::Duplicate { deepest } | Reading::Invalid { deepest } => *deepest,
    }
}

// ---------------------------------------------------------------------------------------------
// The production path.
// ---------------------------------------------------------------------------------------------

fn wire(method: &str) -> WireRequest<()> {
    let request = http::Request::builder()
        .method(method)
        .uri("http://host.invalid/photos?policy")
        .header("host", "host.invalid")
        // Presence satisfies the operation's integrity requirement; the codec verifies only a
        // declared Content-MD5, and this property is about the document, not the digest.
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(())
        .expect("the fixture request is valid");
    WireRequest::accept(request, &Limits::default()).expect("the fixture head is valid")
}

/// The body through the generated `PutBucketPolicy` decoder: the policy text, or the error code.
fn decode(input: &[u8]) -> Result<String, String> {
    let request = wire("PUT");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the fixture target is valid");
    dto::PutBucketPolicy::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(input)))
        .map(|decoded| decoded.policy)
        .map_err(|error| error.code().as_str().to_owned())
}

/// The document as the `GetBucketPolicy` encoder writes it back.
fn stored_then_read(document: &str) -> Vec<u8> {
    let request = wire("GET");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the fixture target is valid");
    let output = dto::GetBucketPolicyOutput {
        policy: Some(document.to_owned()),
    };
    match dto::GetBucketPolicy::encode(output, &view, 200)
        .expect("the stored policy encodes")
        .body
    {
        ResponseBody::Complete(bytes) => bytes,
        ResponseBody::Empty => Vec::new(),
        ResponseBody::Stream(_) => panic!("GetBucketPolicy answered with a streaming body"),
    }
}

// ---------------------------------------------------------------------------------------------
// The probes. Each returns whether it ran; a probe that would cross another ceiling is skipped.
// ---------------------------------------------------------------------------------------------

fn size_probe(document: &str) -> bool {
    let mut padded = document.to_owned();
    padded.extend(std::iter::repeat_n(' ', MAX_POLICY_BYTES - document.len()));
    assert_eq!(validate_policy(&padded), Ok(()), "padded to exactly the size ceiling");
    padded.push('\n');
    assert_eq!(validate_policy(&padded), Err(PolicyRejection::TooLarge), "one byte past the size ceiling");
    true
}

/// `document` inside `levels` objects, each `{"w":…}`.
pub(crate) fn wrapped(document: &str, levels: usize) -> String {
    let mut out = "{\"w\":".repeat(levels);
    out.push_str(document);
    out.push_str(&"}".repeat(levels));
    out
}

fn depth_probe(document: &str, depth: usize) -> bool {
    let levels = MAX_POLICY_DEPTH - depth;
    let deepest = wrapped(document, levels + 1);
    if deepest.len() > MAX_POLICY_BYTES {
        return false;
    }
    let at_ceiling = wrapped(document, levels);
    assert_eq!(validate_policy(&at_ceiling), Ok(()), "wrapped to exactly the depth ceiling");
    assert!(
        matches!(read(&at_ceiling), Reading::Object { depth, .. } if depth == MAX_POLICY_DEPTH),
        "the wrapper did not reach the ceiling"
    );
    assert_eq!(
        validate_policy(&deepest),
        Err(PolicyRejection::TooDeep),
        "one level past the depth ceiling"
    );
    true
}

/// `name` as a JSON string body with its first character written as a `\u` escape.
pub(crate) fn escaped_spelling(name: &str) -> String {
    let Some(first) = name.chars().next() else {
        return String::new();
    };
    let mut units = [0u16; 2];
    let mut out: String = first
        .encode_utf16(&mut units)
        .iter()
        .map(|unit| format!("\\u{unit:04x}"))
        .collect();
    let rest = serde_json::to_string(&name[first.len_utf8()..]).expect("a string serialises");
    out.push_str(&rest[1..rest.len() - 1]);
    out
}

fn duplicate_probe(document: &str, first_name: &str) -> bool {
    let open = document
        .find(|c: char| !matches!(c, ' ' | '\t' | '\n' | '\r'))
        .expect("an accepted document has a first token");
    assert_eq!(&document[open..=open], "{", "an accepted document is an object");
    let repeated = format!(
        "{}\"{}\":null,{}",
        &document[..=open],
        escaped_spelling(first_name),
        &document[open + 1..]
    );
    if repeated.len() > MAX_POLICY_BYTES {
        return false;
    }
    assert!(
        matches!(read(&repeated), Reading::Duplicate { .. }),
        "the reference reader sees the repeated name"
    );
    assert_eq!(
        validate_policy(&repeated),
        Err(PolicyRejection::NotJson),
        "a member name repeated under another spelling"
    );
    true
}

fn canonical_probe(document: &str, depth: usize) -> bool {
    let value: serde_json::Value = serde_json::from_str(document).expect("the reader accepted it once");
    let canonical = serde_json::to_string(&value).expect("a value serialises");
    if canonical.len() > MAX_POLICY_BYTES {
        return false;
    }
    assert_eq!(validate_policy(&canonical), Ok(()), "the re-serialised document: {canonical}");
    assert!(
        matches!(read(&canonical), Reading::Object { depth: again, .. } if again == depth),
        "the re-serialised document changed depth"
    );
    true
}

// ---------------------------------------------------------------------------------------------
// The reference reader.
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct ReaderState {
    deepest: usize,
    root_object: bool,
    duplicate: bool,
    first_name: Option<String>,
}

/// One value at `depth` containers in.
struct Probe<'a> {
    depth: usize,
    state: &'a RefCell<ReaderState>,
}

impl Probe<'_> {
    /// Enters a container, returning its depth.
    fn enter(&self) -> usize {
        let depth = self.depth + 1;
        let mut state = self.state.borrow_mut();
        state.deepest = state.deepest.max(depth);
        depth
    }
}

impl<'de> DeserializeSeed<'de> for Probe<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Probe<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value whose objects repeat no member name")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let depth = self.enter();
        while seq
            .next_element_seed(Probe {
                depth,
                state: self.state,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let depth = self.enter();
        if depth == 1 {
            self.state.borrow_mut().root_object = true;
        }
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if depth == 1 {
                let mut state = self.state.borrow_mut();
                if state.first_name.is_none() {
                    state.first_name = Some(name.clone());
                }
            }
            if !names.insert(name) {
                self.state.borrow_mut().duplicate = true;
                return Err(A::Error::custom("a member name is repeated"));
            }
            map.next_value_seed(Probe {
                depth,
                state: self.state,
            })?;
        }
        Ok(())
    }
}

/// What the reference reader makes of `document`.
pub(crate) fn read(document: &str) -> Reading {
    let state = RefCell::new(ReaderState::default());
    let mut deserializer = serde_json::Deserializer::from_str(document);
    let result = Probe { depth: 0, state: &state }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    let state = state.into_inner();
    match result {
        Ok(()) if state.root_object => Reading::Object {
            depth: state.deepest,
            first_name: state.first_name,
        },
        Ok(()) => Reading::Other { depth: state.deepest },
        Err(_) if state.duplicate => Reading::Duplicate { deepest: state.deepest },
        Err(_) => Reading::Invalid { deepest: state.deepest },
    }
}
