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

//! Signature verification state machine (SigV2/SigV4, presigned, POST policy).
//!
//! Responsible for: `PayloadMode`/`AuthScheme`, canonical request construction, the
//! constant-time verification proof that makes "never compared" unrepresentable.
//! NOT responsible for: authorization (that is `rustfs-gateway-core`), credential storage, or
//! deciding the effective host — that is `rustfs-gateway-http`, and this crate consumes its answer.
//! Upstream: `rustfs-gateway-http`, for the one effective-host determination and the [`RawHost`] the
//! canonical request is built from. Downstream: `rustfs-gateway-core` (authn stage), and
//! `rustfs-gateway-http` reads [`PayloadMode`] to decide framing — a value, not a dependency.
//!
//! # What is frozen here, and what is not
//!
//! This crate currently contains the frozen signature *dimensions* and their strict parsers.
//! Canonical request construction, key derivation and the full verification flow arrive in
//! P2-02/P2-03 and build on these types without reshaping them.
//!
//! # The framing invariant
//!
//! The aws-chunked framing decision is derived from `x-amz-content-sha256`, and from nothing
//! else. [`PayloadMode`] is the single source of truth, [`PayloadMode::is_framed`] is the only
//! sanctioned input to "run the chunk parser", and no function in this crate accepts
//! `Content-Encoding` — so the wire layer cannot re-derive framing from it even by mistake.
//! This is why the signature phase is ordered before the wire phase: a decoder that shipped
//! first would have invented its own enum, and the two layers would then disagree about where
//! the body ends, which is the classic request-smuggling shape.
//!
//! Corollary, enforced by [`PayloadMode::requires_decoded_length`]:
//! `x-amz-decoded-content-length` is mandatory under the two streaming modes and **forbidden**
//! under the other four.
//!
//! # The one-host invariant
//!
//! There is exactly one function that decides which host a request addressed, and it lives in
//! `rustfs-gateway-http`: [`effective_host`]. This crate re-exports it and its types rather than
//! implementing them, because two implementations of that question are two answers to it, and the
//! whole class of attack the function exists to close is "the signature covered one host, the
//! routing used another". [`CanonicalRequestSpec::new`] takes a [`RawHost`] and nothing else — not
//! a `&str`, not a resolver's normalised value — so a many-to-one host cannot seed a signature.
//!
//! # The comparison invariant
//!
//! [`Signature`], [`CtBytes`], [`SecretBytes`], [`SigningKey`] and [`SessionToken`] have no
//! `PartialEq` and no `Debug`. `a == b` on signature material does not compile;
//! [`Signature::ct_verify`] is the only comparison, it is constant-time and length-exact, and it is
//! the only producer of [`SignatureMatch`].
//!
//! # The proof invariant
//!
//! [`Verdict::Authenticated`] requires that [`SignatureMatch`], and [`Verdict::Anonymous`] requires
//! an [`AnonymousAck`] that only [`CredentialPresence::into_evidence`] hands out, and only for a
//! request that presented nothing. So "the access key exists, therefore authenticated" — the shape
//! of MinIO CVE-2025-31489 — does not compile, and neither does "verification failed, fall back to
//! anonymous". Anonymous is an outcome that has to be established, never a fallback that can be
//! reached.
//!
//! # Two deployment facts that belong in the release notes
//!
//! 1. **Never run a debug build in production.** `subtle`'s invariant checks are `debug_assert!`s
//!    over secret-derived values: they exist only in debug builds, and they branch on
//!    secret-dependent conditions. No amount of care in this crate removes that. `subtle`'s
//!    barriers are `read_volatile`-based and documented as best-effort, so a release build is a
//!    strong mitigation and not a proof.
//! 2. **`InvalidAccessKeyId` and `SignatureDoesNotMatch` stay distinct**, because S3 clients branch
//!    on the code and collapsing them is a compatibility break. The leak that follows is mitigated,
//!    not removed: identical [`AuthError::message`], no detail fields, a uniform
//!    [`timing::FailureFloor`] on the failure path, the full derivation run against
//!    [`timing::placeholder_secret`] for unknown keys — and rate limiting, which belongs to the
//!    `Governor` extension point (P6-08). The full reasoning is the `T1` row of
//!    [`timing::SIDE_CHANNELS`].
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod canonical;
mod contracts {
    include!("../../../generated/signature_contracts.rs");
}
mod clock;
pub mod codec;
mod derive;
mod error;
mod floor;
mod mode;
mod operation;
mod parse;
pub mod post_policy;
mod post_policy_json;
pub mod presigned;
mod presigned_expiry;
mod query;
mod scheme;
mod scope;
mod secret;
pub mod sig_v2;
mod signature;
mod signed_headers;
mod signed_headers_legacy;
mod signer;
pub mod timing;
mod verdict;
mod verifier;

#[cfg(test)]
mod full_chain_tests;

pub use canonical::{
    CanonicalCandidates, CanonicalRequest, CanonicalRequestSpec, PathCandidate, RawPathFallback, SignatureMismatchDetail,
    StringToSign, UriPathCandidates,
};
pub use clock::{
    ClockChecked, MAX_PRESIGNED_EXPIRY_SECONDS, PresignExpiry, RequestClock, RequestNow, SkewWindow, SystemClock,
    enforce_clock_skew, enforce_expiry,
};
pub use derive::{VerifiedScope, calculate_signature, signing_key};
pub use error::{SigParseError, Unimplemented};
pub use floor::{
    Admission, SecurityFloor, WireView, X_AMZ_DATE_HEADER, X_AMZ_EXPIRES, X_AMZ_SECURITY_TOKEN, X_AMZ_SECURITY_TOKEN_HEADER,
    detect_credentials, enforce_no_duplicate_sig_params,
};
pub use mode::{
    CanonicalPayloadToken, DeclaredTrailers, EMPTY_PAYLOAD_SHA256_HEX, MAX_DECLARED_TRAILERS, PayloadMode, STREAMING_ECDSA,
    STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, STREAMING_UNSIGNED_TRAILER, TrailerName, TrailerSet,
    UNSIGNED_PAYLOAD,
};
pub use operation::{
    AllowedSchemes, AnonymousPolicy, FloorConfigError, OperationFloor, PresignedPolicy, SchemeSlot, SigV2Presigned,
};
pub use parse::{
    AmzDate, CredentialScope, EmptyRegion, PresignedParams, RegionLength, RegionRule, SCOPE_TERMINATOR, ScopeDate,
    ServiceReading, SigV4Authorization, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNED_HEADERS,
};
pub use post_policy::{
    PostPolicy, PostPolicyEnforcement, PostPolicyError, PostPolicyLimits, SigV2PostPolicy, build_success_action_redirect,
};
pub use presigned::{PayloadObligation, PresignedRequest};
pub use presigned_expiry::{PresignedExpiryRule, enforce_presign_expiry};
pub use query::{QueryExclusion, RawQuery, X_AMZ_SIGNATURE, percent_decode, percent_encode};
pub use secret::{SessionTokenMatch, TokenMismatch};
// The effective host is determined in `rustfs-gateway-http` and nowhere else. These are
// re-exports, not a second implementation: `rustfs_gateway_sig::RawHost` and
// `rustfs_gateway_http::RawHost` are the same type, so a value produced by the wire layer is
// accepted by the canonical request builder without a conversion — which is the point, since a
// conversion is where a normalisation gets applied. They are re-exported at all because
// `CanonicalRequestSpec::new` names `RawHost` in its signature, and a caller should not have to
// add a dependency to spell the argument of a function it can already see.
pub use rustfs_gateway_http::{EffectiveHost, HostError, HostSource, MAX_HOST_BYTES, RawHost, effective_host};
pub use scheme::{
    ALGORITHM_SIGV2_PREFIX, ALGORITHM_SIGV4, ALGORITHM_SIGV4A, AuthScheme, SigFamily, SigIdentity, SigLocation, SigService,
};
pub use scope::{ExpectedScope, RegionSet, ScopeRegion, ScopeRejection, enforce_scope};
pub use secret::{SafeToLog, SecretBytes, SessionToken, SigningKey, assert_safe_to_log};
pub use sig_v2::{SealedSigV2, SigV2Mode, SigV2Policy, SigV2Signer, SigV2StringToSign, SigV2StringToSignSpec};
pub use signature::{CtBytes, Signature, SignatureMatch, VerifyRejection};
pub use signed_headers::{AMZ_HEADER_PREFIX, SignedHeaderSet, UNSIGNED_HEADER_EXEMPTIONS};
pub use signer::{
    CHUNK_ALGORITHM, CHUNK_SIGNATURE_EXTENSION, ChunkSigner, SigV4Signer, SignedRequest, SignerError, SigningCredentials,
    SigningRequest, SigningScope, TRAILER_ALGORITHM, Tamper, TamperComponent, TimestampHeader, X_AMZ_CONTENT_SHA256_HEADER_NAME,
    X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME, X_AMZ_TRAILER_HEADER_NAME,
};
pub use verdict::{
    AnonymousAck, AuthError, CredentialPresence, CredentialsWerePresented, Identity, SessionBinding, SessionBindingError, Verdict,
};
pub use verifier::{
    AUTHORIZATION_HEADER, AWS_ACCESS_KEY_ID_PARAM, AwsCredentialMarker, CustomAuthRequest, CustomAuthScheme,
    CustomSchemeRegistry, ReplayDecision, ReplayFingerprint, ReplayNonceStore, SIGV2_SIGNATURE_PARAM, SchemeRegistrationError,
    SealedAws, SignatureVerifier, detect_aws_credential_marker,
};
#[cfg(feature = "dangerous-replace-signature-verifier")]
pub use verifier::{AwsSignatureVerifier, DangerAck};
