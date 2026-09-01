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

//! Server-side encryption at run time: the transport gate, the key rules, and what a response may
//! never carry.
//!
//! Responsible for: [`enforce`] — one pass over a request head that refuses a customer-provided
//! key on a plaintext connection, refuses the two encryption channels claimed at once, and agrees
//! each key with its digest — and the vocabulary the answer is written in: [`TransportSecurity`],
//! [`SseConfig`], [`SseEnforced`], [`SseRejection`].
//! NOT responsible for: encrypting anything. No key derivation, no AES, no KMS call, no stored
//! object. Nor for the *stored* default-encryption document, which is
//! [`crate::ops::shared::encryption`]'s and whose rules this module calls rather than restates;
//! nor for deciding whether an object-level declaration overrides a bucket default, which is the
//! backend's and is fenced out below.
//! Upstream: [`crate::codec::MetaView`], `rustfs-gateway-types`' `ErrorCode`. Downstream: the
//! facade's pipeline, which calls [`enforce`] once for every request, and any backend that needs
//! the fingerprint of the key a request presented.
//!
//! # The three things a framework can guarantee here, and the one it cannot
//!
//! A customer-provided key travels in a request header. That makes three properties protocol
//! properties rather than storage properties, and they are the whole of this module:
//!
//! 1. **The wire must be encrypted.** `x-amz-server-side-encryption-customer-key` on a plaintext
//!    connection is the key in the clear, and no amount of correct behaviour afterwards undoes
//!    it. Refused with `400 InvalidRequest`, before the request body is read, unconditionally —
//!    not as a backend's opt-in.
//! 2. **The key never comes back.** A response carrying the key header hands it to every
//!    intermediary and every access log on the way home. The framework strips it from every
//!    response it writes, answered or refused, in `crate::invariants` in the facade.
//! 3. **The key and its digest agree.** Both are decoded strictly to their exact widths and
//!    compared in constant time, and the refusal says only that they do not agree.
//!
//! What a framework cannot guarantee is that a **backend** does not log the key it was handed.
//! `docs/security-model.md` states that division; this module makes the framework's half true.
//!
//! # Where the connection's security comes from, and what is never trusted
//!
//! [`TransportSecurity`] is a fact about the socket, so it can only come from whatever accepted
//! the socket. The facade reads it out of the `http::Request`'s extensions, where a transport
//! puts it, and **defaults to [`TransportSecurity::Plaintext`] when nothing put one there** —
//! fail closed, because the deployment that forgot to say is the deployment most likely to be
//! terminating TLS nowhere.
//!
//! `X-Forwarded-Proto` is deliberately not consulted, here or anywhere. It is a request header:
//! any client can send `X-Forwarded-Proto: https` over cleartext, and a gateway that believed it
//! would disable this gate for exactly the caller trying to disable it. A deployment that really
//! does terminate TLS in front of this service tells it so through its transport, or through
//! [`SseConfig`] and an explicit acknowledgement — never through a header the caller controls.
//!
//! # What is fenced out
//!
//! Whether an object-level declaration overrides a bucket's stored default, and what a
//! bucket-key-enabled default means for a request that names its own KMS key, are **the backend's
//! decisions**. The framework's obligation is to deliver both unambiguously and to guarantee that
//! neither carries a raw key — which the bucket document cannot, having no member for one, and
//! which [`SseEnforced`] does not, carrying digests only. The KMS error family is likewise the
//! backend's to produce; this crate only guarantees the codes are expressible.

pub mod base64;
pub mod consistency;
pub mod headers;
pub mod key;

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::SseAlgorithm;

use crate::codec::MetaView;

pub use consistency::{PartRejection, check_part};
pub use headers::{
    COPY_SSEC_ALGORITHM, COPY_SSEC_KEY, COPY_SSEC_KEY_MD5, CUSTOMER_ALGORITHM, ManagedRejection, NEVER_IN_A_RESPONSE,
    SSE_ALGORITHM, SSE_BUCKET_KEY_ENABLED, SSE_CONTEXT, SSE_KMS_KEY_ID, SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5, SseHeaders,
};
pub use key::{CUSTOMER_KEY_BYTES, KEY_DIGEST_BYTES, KeyFingerprint};

/// Whether the connection a request arrived on was encrypted.
///
/// A fact about the socket, which is why it is a parameter of [`enforce`] rather than something
/// read out of the request: nothing in a request head can establish it, and every header that
/// claims to is one the caller wrote. It lives in this crate because this is the only rule that
/// consumes it today; a second consumer is the moment it moves to the wire layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    /// Cleartext. Anything written into a header on this connection is readable by every hop.
    Plaintext,
    /// TLS, terminated by whatever handed this request over.
    Encrypted,
}

/// The witness a deployment must spell out to serve customer-provided keys over cleartext.
///
/// The name is the documentation. There is no `Default` and no public field, so the switch cannot
/// be flipped by a configuration file, a `..Default::default()`, or an absent-minded `true`.
///
/// ```compile_fail,E0599
/// use rustfs_gateway_core::sse::PlaintextCustomerKeyAck;
/// let _ = PlaintextCustomerKeyAck::default(); // no Default: does not compile
/// ```
///
/// ```compile_fail,E0423
/// use rustfs_gateway_core::sse::PlaintextCustomerKeyAck;
/// let _ = PlaintextCustomerKeyAck(()); // private field: does not compile outside this crate
/// ```
#[derive(Clone, Copy)]
pub struct PlaintextCustomerKeyAck(());

impl PlaintextCustomerKeyAck {
    /// Produces the witness.
    #[must_use]
    pub const fn i_understand_customer_keys_will_be_sent_in_the_clear() -> Self {
        Self(())
    }
}

impl core::fmt::Debug for PlaintextCustomerKeyAck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlaintextCustomerKeyAck(i_understand_customer_keys_will_be_sent_in_the_clear)")
    }
}

/// What a deployment is allowed to relax about server-side encryption.
///
/// One knob, and it is off. The only deployment for which turning it on is defensible is one
/// where TLS is terminated in front of this service *and the hop between is trusted* — and that
/// deployment is better served by having its transport declare
/// [`TransportSecurity::Encrypted`], because then the fact travels with the connection instead
/// of being asserted about all of them at start-up.
#[derive(Debug, Clone, Copy)]
pub struct SseConfig {
    allow_customer_keys_over_plaintext: bool,
}

impl SseConfig {
    /// The default: a customer-provided key on a cleartext connection is refused.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_customer_keys_over_plaintext: false,
        }
    }

    /// Serves customer-provided keys over cleartext. Requires the witness.
    #[must_use]
    pub const fn allowing_customer_keys_over_plaintext(_ack: PlaintextCustomerKeyAck) -> Self {
        Self {
            allow_customer_keys_over_plaintext: true,
        }
    }

    /// Whether the gate is open. A deployment's start-up posture report should name this.
    #[must_use]
    pub const fn allows_customer_keys_over_plaintext(&self) -> bool {
        self.allow_customer_keys_over_plaintext
    }
}

impl Default for SseConfig {
    fn default() -> Self {
        Self::strict()
    }
}

/// Which of a request's two independent key positions a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySide {
    /// The object being written or read.
    Target,
    /// The `x-amz-copy-source-…` trio: a second key, on the same request, for the source object.
    CopySource,
}

/// Why a request's SSE headers were refused.
///
/// Every [`SseRejection::reason`] is a constant. Not one is built from a request byte, and in
/// particular not one names a key, a digest, an expected value or a key id — an error message is
/// the shortest path from a secret to a log aggregator, and "expected versus actual" is an
/// oracle even when the value it quotes is the caller's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseRejection {
    /// A customer-provided key, or a fragment of the trio that carries one, on a cleartext
    /// connection.
    PlaintextCustomerKey,
    /// Both encryption channels claimed at once: a managed algorithm and a customer key.
    ChannelsContradict,
    /// One or two of a side's three headers, where the rule is all or none.
    CustomerTrioIncomplete(KeySide),
    /// A customer algorithm that is not `AES256`.
    CustomerAlgorithmUnknown(KeySide),
    /// The key and its digest are not a well-formed, agreeing pair.
    CustomerKeyMalformed(KeySide),
    /// The managed channel's own values.
    ManagedChannelInvalid(ManagedRejection),
}

impl SseRejection {
    /// The S3 error code this refusal answers with.
    ///
    /// One `InvalidRequest` and the rest `InvalidArgument`. The split is the documented one: the
    /// transport gate refuses a request that is well formed and may not be *made* this way, and
    /// everything else refuses a value.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            SseRejection::PlaintextCustomerKey => ErrorCode::INVALID_REQUEST,
            _ => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant sentence, never built from request bytes.
    ///
    /// [`SseRejection::CustomerKeyMalformed`] deliberately covers three different mistakes — a
    /// key of the wrong width, a digest of the wrong width, and a well-formed pair that does not
    /// agree — under one sentence. Telling a caller *which* of those it made distinguishes "your
    /// digest is wrong" from "your key is wrong", and those two are the same request seen from
    /// two sides.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            SseRejection::PlaintextCustomerKey => {
                "requests specifying a customer-provided encryption key must be made over a secure connection"
            }
            SseRejection::ChannelsContradict => {
                "a request may name a server-managed encryption algorithm or a customer-provided key, not both"
            }
            SseRejection::CustomerTrioIncomplete(KeySide::Target) => {
                "the customer-provided encryption algorithm, key and key MD5 headers must all be present or all be absent"
            }
            SseRejection::CustomerTrioIncomplete(KeySide::CopySource) => {
                "the copy-source customer-provided encryption algorithm, key and key MD5 headers must all be present or all be absent"
            }
            SseRejection::CustomerAlgorithmUnknown(KeySide::Target) => {
                "the customer-provided encryption algorithm must be AES256"
            }
            SseRejection::CustomerAlgorithmUnknown(KeySide::CopySource) => {
                "the copy-source customer-provided encryption algorithm must be AES256"
            }
            SseRejection::CustomerKeyMalformed(KeySide::Target) => {
                "the customer-provided encryption key and its MD5 must be base64 of 32 and 16 bytes and must agree"
            }
            SseRejection::CustomerKeyMalformed(KeySide::CopySource) => {
                "the copy-source customer-provided encryption key and its MD5 must be base64 of 32 and 16 bytes and must agree"
            }
            SseRejection::ManagedChannelInvalid(managed) => managed_reason(managed),
        }
    }
}

/// The managed channel's constant sentences, split out so [`SseRejection::reason`] stays a `const
/// fn` of manageable width.
const fn managed_reason(managed: &ManagedRejection) -> &'static str {
    match managed {
        ManagedRejection::QualifierWithoutAlgorithm => {
            "a KMS key id, encryption context or bucket-key switch requires x-amz-server-side-encryption beside it"
        }
        // The *rule* is the stored document's, reached through its validator. The *sentence* is
        // not: `EncryptionRejection::reason` names `SSEAlgorithm` and `KMSMasterKeyID`, which are
        // XML element names, and a caller who sent a header would go looking for a body it never
        // wrote. Both sentences are constants and neither quotes the value.
        ManagedRejection::Document(crate::ops::shared::encryption::EncryptionRejection::AlgorithmUnknown) => {
            "x-amz-server-side-encryption must be one of AES256, aws:fsx, aws:kms or aws:kms:dsse"
        }
        ManagedRejection::Document(
            crate::ops::shared::encryption::EncryptionRejection::KmsKeyWithoutKmsAlgorithm
            | crate::ops::shared::encryption::EncryptionRejection::KmsKeyWithoutKmsAlgorithmWithValue(_),
        ) => "x-amz-server-side-encryption-aws-kms-key-id is only valid with aws:kms or aws:kms:dsse",
        ManagedRejection::Document(crate::ops::shared::encryption::EncryptionRejection::TooManyRules) => {
            "the encryption configuration carries too many rules"
        }
        ManagedRejection::KmsQualifierWithoutKmsAlgorithm => {
            "an encryption context or bucket-key switch is only valid with aws:kms or aws:kms:dsse"
        }
        ManagedRejection::BucketKeyNotABoolean => "x-amz-server-side-encryption-bucket-key-enabled must be true or false",
        ManagedRejection::ContextNotBase64 => "x-amz-server-side-encryption-context must be base64 of at most 2048 UTF-8 bytes",
    }
}

/// What a request declared about encryption, once every rule has passed.
///
/// The only way to obtain one is [`enforce`]: there is no public constructor, no `Default` and no
/// public field, so a value of this type is evidence that the gate ran. What it carries is
/// **digests and an algorithm name** — never a key. A backend that must encrypt reads the key off
/// its own decoded operation input; nothing here will hand it one.
#[derive(Clone)]
#[must_use]
pub struct SseEnforced {
    customer: Option<KeyFingerprint>,
    copy_source: Option<KeyFingerprint>,
    managed: Option<SseAlgorithm>,
}

impl SseEnforced {
    #[cfg(test)]
    pub(crate) const fn empty_for_unit_test() -> Self {
        Self {
            customer: None,
            copy_source: None,
            managed: None,
        }
    }

    /// The digest of the key the request presented for the target object, if it presented one.
    ///
    /// This is the value a `CreateMultipartUpload` handler binds to its upload id, and the value
    /// every `UploadPart` is compared against by [`consistency::check_part`].
    #[must_use]
    pub const fn customer_key_fingerprint(&self) -> Option<&KeyFingerprint> {
        self.customer.as_ref()
    }

    /// The same for the copy source's key, which is a second and unrelated key.
    #[must_use]
    pub const fn copy_source_key_fingerprint(&self) -> Option<&KeyFingerprint> {
        self.copy_source.as_ref()
    }

    /// The server-managed algorithm the request named, if it named one.
    ///
    /// The object-level half of the precedence question. The bucket-level half is the backend's
    /// stored document, and which of the two wins is the backend's decision — see the module
    /// documentation's scope fence.
    #[must_use]
    pub const fn managed_algorithm(&self) -> Option<&SseAlgorithm> {
        self.managed.as_ref()
    }
}

/// Applies every head-decidable SSE rule to one request.
///
/// Pure, allocation-light and stated over the request head alone, which is what lets the facade
/// run it above the body read: a refusal costs the response and not the transfer. Called once by
/// the pipeline for **every** operation — the gate is not a property of which operation is being
/// invoked, because a key on a cleartext wire is disclosed whatever was going to be done with it.
///
/// The order of the checks is fixed and is part of the contract:
///
/// 1. **The transport gate first.** Over cleartext, every SSE-C request gets the same answer
///    whatever its key says, so a caller cannot use the refusal to learn anything about the key
///    material it just disclosed.
/// 2. **The contradiction second**, so a request that is wrong in both channels is refused
///    deterministically rather than by whichever check happens to run first.
/// 3. **The target key, then the copy-source key, then the managed channel.**
///
/// # Errors
///
/// [`SseRejection`] naming the first rule the request breaks.
pub fn enforce(request: &MetaView<'_>, transport: TransportSecurity, config: &SseConfig) -> Result<SseEnforced, SseRejection> {
    let headers = SseHeaders::read(request);

    if headers.any_customer_key_header()
        && transport == TransportSecurity::Plaintext
        && !config.allows_customer_keys_over_plaintext()
    {
        return Err(SseRejection::PlaintextCustomerKey);
    }

    if headers.managed.any_present() && headers.any_customer_key_header() {
        return Err(SseRejection::ChannelsContradict);
    }

    let customer = fingerprint_side(&headers.target, KeySide::Target)?;
    let copy_source = fingerprint_side(&headers.copy_source, KeySide::CopySource)?;
    let managed = headers.managed.validate().map_err(SseRejection::ManagedChannelInvalid)?;

    Ok(SseEnforced {
        customer,
        copy_source,
        managed,
    })
}

/// The fingerprint of the key a request presents on one of its two key positions.
///
/// For a backend that must *bind* a fingerprint to a multipart upload or *compare* one against a
/// binding it stored. It applies the value rules and nothing else: the transport gate is
/// [`enforce`]'s and has already run by the time a handler exists, so a decoder calling this is
/// not making the "is this connection encrypted" decision a second time and cannot get it wrong.
///
/// Reusing this rather than reading the two headers and hashing them is the point — a second
/// implementation of "decode strictly, agree with the digest" is a second implementation that can
/// become more tolerant than this one.
///
/// # Errors
///
/// [`SseRejection`] naming the rule the request breaks, ready to be rendered by the caller's own
/// error type.
pub fn presented_customer_key(request: &MetaView<'_>, side: KeySide) -> Result<Option<KeyFingerprint>, SseRejection> {
    let headers = SseHeaders::read(request);
    let trio = match side {
        KeySide::Target => &headers.target,
        KeySide::CopySource => &headers.copy_source,
    };
    fingerprint_side(trio, side)
}

/// One side's trio: all-or-none, `AES256`, and a key that agrees with its digest.
fn fingerprint_side(trio: &headers::CustomerTrio<'_>, side: KeySide) -> Result<Option<KeyFingerprint>, SseRejection> {
    if !trio.any_present() {
        return Ok(None);
    }
    if !trio.all_present() {
        return Err(SseRejection::CustomerTrioIncomplete(side));
    }
    let algorithm = trio.algorithm.as_deref().unwrap_or_default();
    if algorithm != CUSTOMER_ALGORITHM {
        return Err(SseRejection::CustomerAlgorithmUnknown(side));
    }
    // `all_present` was just checked, so both are `Some`; the `else` arm is the same refusal the
    // incompleteness check would have produced rather than an unwrap on external input.
    let (Some(text), Some(digest)) = (trio.key.as_ref(), trio.digest.as_deref()) else {
        return Err(SseRejection::CustomerTrioIncomplete(side));
    };
    key::fingerprint_of(text.expose(), digest)
        .map(Some)
        .map_err(|_| SseRejection::CustomerKeyMalformed(side))
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Base64 *encoding* for the tests in this module tree. Deliberately not in
    //! [`super::base64`]: nothing this service ships encodes an SSE value, and an encoder sitting
    //! beside the strict decoder is an invitation to round-trip a key.

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Standard base64 with padding.
    pub(crate) fn base64_of(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            for (slot, byte) in buffer.iter_mut().zip(chunk) {
                *slot = *byte;
            }
            let [high, middle, low] = buffer;
            let value = (u32::from(high) << 16) | (u32::from(middle) << 8) | u32::from(low);
            for slot in 0..4 {
                if slot <= chunk.len() {
                    let index = usize::try_from((value >> (18 - 6 * slot)) & 0x3f).unwrap_or(0);
                    out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `ops/shared/encryption.rs`.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
