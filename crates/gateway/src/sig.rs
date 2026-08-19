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

//! The signature vocabulary, published through the facade.
//!
//! Responsible for: re-exporting the `rustfs-gateway-sig` types a consumer of this facade has to
//! name — the verdict an authenticator returns, the floor a deployment narrows, the errors a
//! rejection carries — so that nothing downstream takes a direct dependency on the signature
//! crate. The conformance suite in particular may use this facade and nothing else.
//! NOT responsible for: implementing any of it, or re-exporting the crate wholesale. A type is
//! listed here when something outside this workspace has to spell it.
//! Upstream: `rustfs-gateway-sig`. Downstream: every consumer of the facade.
//!
//! # The client-side signer
//!
//! The conformance runner's `REQUIRED_FACADE_EXPORTS` names `rustfs_gateway::sig::Signer`: a
//! *client-side* signer, which computes a header, streaming, streaming-trailer, unsigned-payload
//! or presigned signature. It is [`SigV4Signer`] in `rustfs-gateway-sig`, and [`Signer`] is an
//! alias so that the name the runner asks for resolves. The alias is the facade's promise; the
//! concrete name is the signature crate's, and keeping both means neither has to change to satisfy
//! the other.
//!
//! Nothing in this crate uses it: signing is what a *client* does, and this crate is the server.
//! It is published because the suite that drives the server has to produce signed requests, and it
//! may use this facade and nothing else.

pub use rustfs_gateway_sig::timing::LookupBudget;
pub use rustfs_gateway_sig::{
    AmzDate, AnonymousAck, AuthError, AuthScheme, CHUNK_ALGORITHM, CHUNK_SIGNATURE_EXTENSION, ChunkSigner, CredentialPresence,
    CredentialScope, CtBytes, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, Identity, MAX_PRESIGNED_EXPIRY_SECONDS,
    PayloadMode, PresignedParams, RegionSet, RequestClock, RequestNow, SecretBytes, SecurityFloor, SessionBinding,
    SessionBindingError, SessionToken, SigFamily, SigIdentity, SigLocation, SigService, SigV4Authorization, SigV4Signer,
    Signature, SignatureMatch, SignatureVerifier, SignedRequest, SignerError, SigningCredentials, SigningKey, SigningRequest,
    SigningScope, SkewWindow, SystemClock, TRAILER_ALGORITHM, Tamper, TamperComponent, TrailerSet, Verdict,
};
#[cfg(feature = "dangerous-replace-signature-verifier")]
pub use rustfs_gateway_sig::{AwsSignatureVerifier, DangerAck, SealedAws};

/// The client-side signer, under the name the conformance runner names it by.
pub use rustfs_gateway_sig::SigV4Signer as Signer;
