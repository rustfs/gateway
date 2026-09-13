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

//! The bucket policy document and the public-access block: the three things a gateway may check.
//!
//! Shares: bucket_policy
//! Members: DeleteBucketPolicy, DeletePublicAccessBlock, GetBucketPolicy, GetBucketPolicyStatus, GetPublicAccessBlock, PutBucketPolicy, PutPublicAccessBlock
//!
//! Responsible for: the size ceiling, the JSON syntax check and the nesting depth cap on a policy
//! document, and the one shape rule of a `PublicAccessBlockConfiguration`.
//! NOT responsible for: **evaluating the policy**. Whether a statement grants what it claims,
//! whether a principal exists, whether an action names a real operation, whether the caller is
//! allowed to hand out the access described, and whether the resulting bucket counts as public —
//! all of it belongs to the authorizer, which is a component this gateway calls and does not
//! contain. `GetBucketPolicyStatus` transports a boolean a backend computed; nothing here computes
//! one. Also not responsible for decoding (the generated codec reads the body as text and refuses
//! only non-UTF-8) or for storing anything.
//! Upstream: `rustfs-gateway-types`' `ErrorCode` and generated dto. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Why the syntax check exists at all, given the fence above
//!
//! Because the three checks below are the ones that can be made without a policy language, and
//! each of them protects something the authorizer cannot. A body that is not JSON will fail at
//! *every* future read of the stored document, so accepting it stores a bucket that cannot be
//! loaded. An unbounded body is memory a caller chose. And a deeply nested document is a stack the
//! next parser to touch it has to survive — which is why the scanner below counts depth in a
//! counter and never recurses: a recursive validator would be the denial of service it is meant to
//! refuse.
//!
//! "Is JSON" means what the strict reader that loads the stored document means by it — RustFS
//! reads a bucket policy with `serde_json` into typed, `deny_unknown_fields` structures — and not
//! merely balanced brackets: member names are strings and unique within their object, every
//! escape and number is one JSON has, and every number is a finite double. A scanner laxer than
//! that reader would store `{"Effect":"Allow","Effect":"Deny"}`, which one later reader takes as
//! an allow, another as a deny, and a typed one refuses outright. The `policy_json` fuzz property
//! (`fuzz/support/policy_json.rs`) holds this scanner to that reader in both directions.
//!
//! # No refusal ever repeats the document
//!
//! A policy names principals, account ids, role ARNs and resource paths. Every reason below is a
//! compile-time constant with no offset, no excerpt and no length in it: an error that said *where*
//! the syntax broke would let a caller who may not read the policy back reconstruct it one probe at
//! a time.

use std::collections::BTreeSet;

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::PublicAccessBlockConfiguration;

/// The largest bucket policy AWS accepts, in bytes.
///
/// Documented as 20 KB for a bucket policy. Applied to the raw body, before anything parses it, so
/// the refusal costs the scan and not the parse.
pub const MAX_POLICY_BYTES: usize = 20 * 1024;

/// How deep a policy document may nest before this refuses it.
///
/// A real policy reaches four or five levels: the document, the statement list, a statement, its
/// `Condition`, and the condition's operand map. A hundred is far past anything meaningful and far
/// short of anything that troubles a consumer.
pub const MAX_POLICY_DEPTH: usize = 100;

/// Why a policy document or a public-access block was refused, with the code AWS answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRejection {
    /// The body is larger than [`MAX_POLICY_BYTES`].
    TooLarge,
    /// The body is not a JSON document a strict reader accepts: broken syntax, a member name that
    /// is not a string, an escape or number JSON does not have, an unpaired surrogate escape, a
    /// number no IEEE double can hold, or one name used twice in one object (I-JSON, RFC 7493).
    /// Every one of these is a document the reader behind the gateway would refuse to load.
    NotJson,
    /// The body nests deeper than [`MAX_POLICY_DEPTH`].
    TooDeep,
    /// The body is valid JSON but not a JSON object. A policy is a document with `Version` and
    /// `Statement` members; an array or a bare string is not one, however well formed.
    NotAnObject,
    /// The body is empty. Clearing a policy is `DeleteBucketPolicy`, never a zero-byte write.
    Empty,
}

impl PolicyRejection {
    /// The S3 error code to render.
    ///
    /// Every one of these is `MalformedPolicy`, and deliberately so: AWS answers that single code
    /// for a policy body it cannot use, and splitting it into finer codes here would tell a caller
    /// which of the checks it tripped — which is the same disclosure the constant messages exist to
    /// prevent, moved into the `<Code>` element.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::MALFORMED_POLICY
    }

    /// A constant explanation with no offset, no excerpt and no length in it.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            PolicyRejection::TooLarge => "the policy document is larger than the 20 KB limit",
            PolicyRejection::NotJson => "the policy document is not valid JSON",
            PolicyRejection::TooDeep => "the policy document nests too deeply",
            PolicyRejection::NotAnObject => "the policy document must be a JSON object",
            PolicyRejection::Empty => "the policy document is empty",
        }
    }
}

/// Checks a policy document: size, JSON syntax, nesting depth, and that it is an object.
///
/// The document is **not** interpreted. This says the bytes are a JSON object that a future read
/// will be able to parse, and stops there.
///
/// # Errors
///
/// [`PolicyRejection`] naming the first rule the document breaks, checked cheapest first so a
/// twenty-megabyte body is refused by its length rather than by its syntax.
pub fn validate_policy(document: &str) -> Result<(), PolicyRejection> {
    if document.len() > MAX_POLICY_BYTES {
        return Err(PolicyRejection::TooLarge);
    }
    if document.trim().is_empty() {
        return Err(PolicyRejection::Empty);
    }
    match scan(document.as_bytes())? {
        Container::Object => Ok(()),
        Container::Other => Err(PolicyRejection::NotAnObject),
    }
}

/// Checks a decoded public-access block.
///
/// There is exactly one rule and it is not a refusal: all four booleans are optional and an omitted
/// one is `false`. The function exists so that a backend has one place to ask, and so that the day
/// AWS documents a constraint between two of the switches, it lands here rather than in four
/// backends.
///
/// # Errors
///
/// Never today. The signature carries the `Result` because the callers of this family's validators
/// are written against one shape, and a validator that could not fail would have to be called
/// differently from its four siblings.
pub const fn validate_public_access_block(_configuration: &PublicAccessBlockConfiguration) -> Result<(), PolicyRejection> {
    Ok(())
}

/// What the top-level value of a document turned out to be.
enum Container {
    /// A JSON object, which is what a policy must be.
    Object,
    /// Any other well-formed JSON value.
    Other,
}

/// One frame of the scanner's explicit stack.
enum Frame {
    /// Inside `{ }`, with every member name read so far, decoded, so that two spellings of one
    /// name (`"Effect"` and `"\u0045ffect"`) are one name.
    Object(BTreeSet<Vec<u8>>),
    /// Inside `[ ]`.
    Array,
}

/// What the scanner is allowed to see next. Spelling the grammar out as states is what keeps
/// `{"a" "b"}`, `{"a"}`, `{"a":1:2}`, `{1:2}` and `[1,,2]` from passing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Any value: the document's first token, or after `:` or an array's `,`.
    Value,
    /// A value or the `]` of an empty array.
    ValueOrClose,
    /// A member name or the `}` of an empty object.
    NameOrClose,
    /// A member name: after an object's `,`, where a `}` would be a trailing comma.
    Name,
    /// The `:` after a member name.
    Colon,
    /// A `,` or the close of the innermost container.
    CommaOrClose,
    /// Nothing: the document is complete and only whitespace may follow.
    End,
}

/// The four whitespace bytes JSON allows between tokens. Not `u8::is_ascii_whitespace`, which also
/// admits form feed: a document ending in `\x0C` is not JSON to any strict reader.
const fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Walks the bytes once, checking JSON syntax, member-name uniqueness and depth without recursion.
///
/// Iterative on purpose: the input is caller-controlled and a recursive descent over it would turn
/// [`MAX_POLICY_DEPTH`] into a promise the stack has to keep. Here the depth is `stack.len()` and
/// exceeding it is a refusal, not a crash. The first rule broken, reading left to right, is the
/// one reported: a document that nests too deep before its syntax breaks is `TooDeep`.
fn scan(bytes: &[u8]) -> Result<Container, PolicyRejection> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut index = 0usize;
    let mut top = Container::Other;
    let mut expect = Expect::Value;

    while let Some(&byte) = bytes.get(index) {
        if is_json_whitespace(byte) {
            index = index.saturating_add(1);
            continue;
        }
        match (expect, byte) {
            (Expect::Value | Expect::ValueOrClose, b'{' | b'[') => {
                if stack.is_empty() && byte == b'{' {
                    top = Container::Object;
                }
                if stack.len() >= MAX_POLICY_DEPTH {
                    return Err(PolicyRejection::TooDeep);
                }
                if byte == b'{' {
                    stack.push(Frame::Object(BTreeSet::new()));
                    expect = Expect::NameOrClose;
                } else {
                    stack.push(Frame::Array);
                    expect = Expect::ValueOrClose;
                }
                index = index.saturating_add(1);
            }
            (Expect::ValueOrClose | Expect::CommaOrClose, b']') | (Expect::NameOrClose | Expect::CommaOrClose, b'}') => {
                match (stack.pop(), byte) {
                    (Some(Frame::Array), b']') | (Some(Frame::Object(_)), b'}') => {}
                    _ => return Err(PolicyRejection::NotJson),
                }
                expect = after_value(&stack);
                index = index.saturating_add(1);
            }
            (Expect::Value | Expect::ValueOrClose, b'"') => {
                index = string_end(bytes, index, None)?;
                expect = after_value(&stack);
            }
            (Expect::Value | Expect::ValueOrClose, _) => {
                index = scalar_end(bytes, index)?;
                expect = after_value(&stack);
            }
            (Expect::NameOrClose | Expect::Name, b'"') => {
                let mut name = Vec::new();
                index = string_end(bytes, index, Some(&mut name))?;
                let Some(Frame::Object(names)) = stack.last_mut() else {
                    return Err(PolicyRejection::NotJson);
                };
                // Two members with one name are read differently by different readers — the first
                // wins in some, the last in others, and a typed reader such as RustFS's refuses
                // the document. Storing it would let the gateway, the backend and every later
                // reader disagree about what the policy says.
                if !names.insert(name) {
                    return Err(PolicyRejection::NotJson);
                }
                expect = Expect::Colon;
            }
            (Expect::Colon, b':') => {
                expect = Expect::Value;
                index = index.saturating_add(1);
            }
            (Expect::CommaOrClose, b',') => {
                expect = match stack.last() {
                    Some(Frame::Object(_)) => Expect::Name,
                    Some(Frame::Array) => Expect::Value,
                    None => return Err(PolicyRejection::NotJson),
                };
                index = index.saturating_add(1);
            }
            _ => return Err(PolicyRejection::NotJson),
        }
    }
    if expect == Expect::End {
        Ok(top)
    } else {
        Err(PolicyRejection::NotJson)
    }
}

/// What may follow a complete value inside `stack`.
fn after_value(stack: &[Frame]) -> Expect {
    if stack.is_empty() { Expect::End } else { Expect::CommaOrClose }
}

/// The index just past a JSON string starting at `start`, writing the decoded bytes to `decoded`
/// when the caller needs them (a member name) and only validating otherwise.
fn string_end(bytes: &[u8], start: usize, mut decoded: Option<&mut Vec<u8>>) -> Result<usize, PolicyRejection> {
    let mut index = start.saturating_add(1);
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => return Ok(index.saturating_add(1)),
            b'\\' => {
                let escape = bytes.get(index.saturating_add(1)).copied().ok_or(PolicyRejection::NotJson)?;
                index = index.saturating_add(2);
                let character = match escape {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let (character, next) = unicode_escape(bytes, index)?;
                        index = next;
                        character
                    }
                    // `\x`, `\'`, `\0`: escapes JSON does not have.
                    _ => return Err(PolicyRejection::NotJson),
                };
                if let Some(out) = decoded.as_deref_mut() {
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                }
            }
            // A raw control character inside a string is not JSON. Refusing it here keeps a
            // document that a stricter reader would reject from being stored by a laxer one.
            0x00..=0x1f => return Err(PolicyRejection::NotJson),
            _ => {
                if let Some(out) = decoded.as_deref_mut() {
                    out.push(byte);
                }
                index = index.saturating_add(1);
            }
        }
    }
    Err(PolicyRejection::NotJson)
}

/// The character a `\uXXXX` escape whose hex digits start at `start` names, and the index past it.
///
/// A high surrogate must be followed at once by a `\u` low surrogate, and a low surrogate may not
/// stand alone: an unpaired one names no character, and strict readers refuse it.
fn unicode_escape(bytes: &[u8], start: usize) -> Result<(char, usize), PolicyRejection> {
    let high = hex4(bytes, start)?;
    let next = start.saturating_add(4);
    match high {
        0xd800..=0xdbff => {
            if bytes.get(next..next.saturating_add(2)) != Some(&b"\\u"[..]) {
                return Err(PolicyRejection::NotJson);
            }
            let low = hex4(bytes, next.saturating_add(2))?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(PolicyRejection::NotJson);
            }
            let scalar = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
            let character = char::from_u32(scalar).ok_or(PolicyRejection::NotJson)?;
            Ok((character, next.saturating_add(6)))
        }
        0xdc00..=0xdfff => Err(PolicyRejection::NotJson),
        _ => Ok((char::from_u32(high).ok_or(PolicyRejection::NotJson)?, next)),
    }
}

/// Four hex digits starting at `start`, as a code unit.
fn hex4(bytes: &[u8], start: usize) -> Result<u32, PolicyRejection> {
    let digits = bytes.get(start..start.saturating_add(4)).ok_or(PolicyRejection::NotJson)?;
    digits.iter().try_fold(0u32, |unit, &digit| {
        let value = char::from(digit).to_digit(16).ok_or(PolicyRejection::NotJson)?;
        Ok((unit << 4) | value)
    })
}

/// The index just past a `true`, `false`, `null` or number starting at `start`.
///
/// A number follows JSON's grammar exactly — `-? (0 | [1-9][0-9]*) (.[0-9]+)? ([eE][+-]?[0-9]+)?`
/// — and must name a finite IEEE double. `01`, `1.`, `.5`, `+1` and `1.2.3` are not numbers, and
/// `1e400` is one no double holds: the reader RustFS stores the document for refuses it as out of
/// range, so the bucket would hold a policy it cannot load.
fn scalar_end(bytes: &[u8], start: usize) -> Result<usize, PolicyRejection> {
    for literal in [&b"true"[..], &b"false"[..], &b"null"[..]] {
        if bytes.get(start..start.saturating_add(literal.len())) == Some(literal) {
            return Ok(start.saturating_add(literal.len()));
        }
    }
    let digit_run = |from: usize| {
        let mut end = from;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end = end.saturating_add(1);
        }
        end
    };
    let mut index = start;
    if bytes.get(index) == Some(&b'-') {
        index = index.saturating_add(1);
    }
    match bytes.get(index) {
        Some(b'0') => index = index.saturating_add(1),
        Some(b'1'..=b'9') => index = digit_run(index),
        _ => return Err(PolicyRejection::NotJson),
    }
    if bytes.get(index) == Some(&b'.') {
        let end = digit_run(index.saturating_add(1));
        if end == index.saturating_add(1) {
            return Err(PolicyRejection::NotJson);
        }
        index = end;
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index = index.saturating_add(1);
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index = index.saturating_add(1);
        }
        let end = digit_run(index);
        if end == index {
            return Err(PolicyRejection::NotJson);
        }
        index = end;
    }
    let text = bytes
        .get(start..index)
        .and_then(|number| core::str::from_utf8(number).ok())
        .ok_or(PolicyRejection::NotJson)?;
    match text.parse::<f64>() {
        Ok(value) if value.is_finite() => Ok(index),
        _ => Err(PolicyRejection::NotJson),
    }
}
