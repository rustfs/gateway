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
//! NOT responsible for: authorization (that is `s3gate-core`), credential storage.
//! Upstream: none today — the frozen dimensions are self-contained. Downstream: `s3gate-http`
//! (framing), `s3gate-core` (authn stage).
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
//! # The comparison invariant
//!
//! [`Signature`], [`CtBytes`], [`SecretBytes`] and [`SessionToken`] have no `PartialEq` and no
//! `Debug`. `a == b` on signature material does not compile; [`Signature::ct_verify`] is the only
//! comparison, it is constant-time and length-exact, and it is the only producer of
//! [`SignatureMatch`]. Downstream verdicts are expected to carry that proof, which makes
//! "authenticated without ever comparing" a compile error.
#![forbid(unsafe_code)]

pub mod codec;
mod error;
mod mode;
mod scheme;
mod secret;
mod signature;

pub use error::{SigParseError, Unimplemented};
pub use mode::{
    CanonicalPayloadToken, DeclaredTrailers, EMPTY_PAYLOAD_SHA256_HEX, MAX_DECLARED_TRAILERS, PayloadMode, STREAMING_ECDSA,
    STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, STREAMING_UNSIGNED_TRAILER, TrailerName, TrailerSet,
    UNSIGNED_PAYLOAD,
};
pub use scheme::{
    ALGORITHM_SIGV2_PREFIX, ALGORITHM_SIGV4, ALGORITHM_SIGV4A, AuthScheme, SigFamily, SigIdentity, SigLocation, SigService,
};
pub use secret::{SecretBytes, SessionToken};
pub use signature::{CtBytes, Signature, SignatureMatch, VerifyRejection};
