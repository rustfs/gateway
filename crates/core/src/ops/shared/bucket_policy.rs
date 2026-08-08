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
//! # No refusal ever repeats the document
//!
//! A policy names principals, account ids, role ARNs and resource paths. Every reason below is a
//! compile-time constant with no offset, no excerpt and no length in it: an error that said *where*
//! the syntax broke would let a caller who may not read the policy back reconstruct it one probe at
//! a time.

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
    /// The body is not syntactically valid JSON.
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// Inside `{ }`.
    Object,
    /// Inside `[ ]`.
    Array,
}

/// Walks the bytes once, checking JSON syntax and depth without recursion.
///
/// Iterative on purpose: the input is caller-controlled and a recursive descent over it would turn
/// [`MAX_POLICY_DEPTH`] into a promise the stack has to keep. Here the depth is `stack.len()` and
/// exceeding it is a refusal, not a crash.
fn scan(bytes: &[u8]) -> Result<Container, PolicyRejection> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut index = 0usize;
    let mut top: Option<Container> = None;
    // What the scanner is allowed to see next. A JSON document is a small state machine and
    // spelling it out is what keeps `{"a" "b"}` and `[1,,2]` from passing.
    let mut expect_value = true;
    let mut after_value = false;

    while index < bytes.len() {
        let Some(&byte) = bytes.get(index) else { break };
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => {
                index = index.saturating_add(1);
            }
            b'{' | b'[' => {
                if !expect_value {
                    return Err(PolicyRejection::NotJson);
                }
                if stack.is_empty() {
                    top = Some(if byte == b'{' { Container::Object } else { Container::Other });
                }
                if stack.len() >= MAX_POLICY_DEPTH {
                    return Err(PolicyRejection::TooDeep);
                }
                stack.push(if byte == b'{' { Frame::Object } else { Frame::Array });
                expect_value = byte == b'[';
                after_value = false;
                index = index.saturating_add(1);
            }
            b'}' | b']' => {
                let wanted = if byte == b'}' { Frame::Object } else { Frame::Array };
                match stack.pop() {
                    Some(frame) if frame == wanted => {}
                    _ => return Err(PolicyRejection::NotJson),
                }
                // A closing brace after a comma is a trailing comma, which JSON does not allow.
                if expect_value && after_value {
                    return Err(PolicyRejection::NotJson);
                }
                expect_value = false;
                after_value = true;
                index = index.saturating_add(1);
            }
            b'"' => {
                index = string_end(bytes, index)?;
                expect_value = false;
                after_value = true;
            }
            b':' => {
                if !matches!(stack.last(), Some(Frame::Object)) || !after_value {
                    return Err(PolicyRejection::NotJson);
                }
                expect_value = true;
                after_value = false;
                index = index.saturating_add(1);
            }
            b',' => {
                if stack.is_empty() || !after_value {
                    return Err(PolicyRejection::NotJson);
                }
                expect_value = true;
                after_value = true;
                index = index.saturating_add(1);
            }
            _ => {
                if !expect_value {
                    return Err(PolicyRejection::NotJson);
                }
                if stack.is_empty() {
                    top = Some(Container::Other);
                }
                index = scalar_end(bytes, index)?;
                expect_value = false;
                after_value = true;
            }
        }
        if stack.is_empty() && after_value {
            // The document is complete; only whitespace may follow.
            let rest = bytes.get(index..).unwrap_or_default();
            if rest.iter().any(|b| !b.is_ascii_whitespace()) {
                return Err(PolicyRejection::NotJson);
            }
            break;
        }
    }
    if !stack.is_empty() {
        return Err(PolicyRejection::NotJson);
    }
    top.ok_or(PolicyRejection::NotJson)
}

/// The index just past a JSON string starting at `start`.
fn string_end(bytes: &[u8], start: usize) -> Result<usize, PolicyRejection> {
    let mut index = start.saturating_add(1);
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.saturating_add(2),
            b'"' => return Ok(index.saturating_add(1)),
            // A raw control character inside a string is not JSON. Refusing it here keeps a
            // document that a stricter reader would reject from being stored by a laxer one.
            0x00..=0x1f => return Err(PolicyRejection::NotJson),
            _ => index = index.saturating_add(1),
        }
    }
    Err(PolicyRejection::NotJson)
}

/// The index just past a `true`, `false`, `null` or number starting at `start`.
fn scalar_end(bytes: &[u8], start: usize) -> Result<usize, PolicyRejection> {
    for literal in [&b"true"[..], &b"false"[..], &b"null"[..]] {
        if bytes.get(start..start.saturating_add(literal.len())) == Some(literal) {
            return Ok(start.saturating_add(literal.len()));
        }
    }
    let mut index = start;
    let mut digits = 0usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'0'..=b'9' => {
                digits = digits.saturating_add(1);
                index = index.saturating_add(1);
            }
            b'-' | b'+' | b'.' | b'e' | b'E' => index = index.saturating_add(1),
            _ => break,
        }
    }
    if digits == 0 {
        Err(PolicyRejection::NotJson)
    } else {
        Ok(index)
    }
}
