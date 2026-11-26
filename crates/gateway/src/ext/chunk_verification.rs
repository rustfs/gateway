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

//! Verified chunk-chain material published by an authenticator for streaming SigV4 bodies.
//!
//! Responsible for: [`ChunkVerification`] (derived signing key, scope line, timestamp, and
//! verified 32-byte request-head signature seed) and [`ChunkSink`] (write-once handoff).
//! NOT responsible for: verifying the request signature (`super::authenticator`) or decoding
//! `aws-chunked` frames (`crate::chunked`).
//! Upstream: `super::authenticator::SigV4Authenticator`. Downstream: `crate::chunked`.

/// The material a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body's per-chunk signatures are checked
/// against.
///
/// # Why this exists at all
///
/// The `aws-chunked` chunk chain is seeded by the verified *request* signature and verified with
/// the *same* `k_signing` the request signature was computed from. Neither value survives
/// [`rustfs_gateway_sig::Verdict`]: `Verdict::Authenticated` carries an identity, a scheme, the
/// verified scope and a zero-sized [`rustfs_gateway_sig::SignatureMatch`], which is exactly the
/// right shape for "who is this" and exactly the wrong shape for "keep verifying" — the scope
/// names the key, it does not hold it. `Verdict` is `rustfs-gateway-sig`'s and
/// `#[non_exhaustive]`, so it cannot grow a variant from here.
///
/// So the material — including the 32-byte verified request-head seed — travels beside the
/// verdict, through a write-once sink the pipeline owns and the authenticator fills only after
/// cryptographic verification succeeds. Downstream chunk decoding therefore never re-parses the
/// raw `Authorization` header or query string to guess the seed.
///
/// No `Debug`, no `Clone`: it holds a signing key.
pub struct ChunkVerification {
    key: rustfs_gateway_sig::SigningKey,
    scope_line: String,
    amz_date: String,
    seed: [u8; 32],
}

impl ChunkVerification {
    /// Publishes the derived key, scope line, timestamp, and verified 32-byte request-head
    /// signature seed that starts the chunk signature chain.
    #[must_use]
    pub fn new(key: rustfs_gateway_sig::SigningKey, scope_line: String, amz_date: String, seed: [u8; 32]) -> Self {
        Self {
            key,
            scope_line,
            amz_date,
            seed,
        }
    }

    /// The derived `k_signing`, as the fixed-width value the chunk signer takes.
    ///
    /// `None` when the key is not the 32 bytes SigV4 produces, which is a defect in whatever built
    /// it rather than a property of the request — the caller refuses instead of padding.
    #[must_use]
    pub fn chunk_signing_key(&self) -> Option<rustfs_gateway_http::ChunkSigningKey> {
        let bytes: [u8; 32] = self.key.expose().try_into().ok()?;
        Some(rustfs_gateway_http::ChunkSigningKey::from_derived(bytes))
    }

    /// The verified 32-byte request-head signature that seeds the first chunk HMAC.
    #[must_use]
    pub fn chunk_seed(&self) -> rustfs_gateway_http::ChunkSeed {
        rustfs_gateway_http::ChunkSeed::from_request_signature(self.seed)
    }

    /// The credential scope line, `<date>/<region>/<service>/aws4_request`.
    #[must_use]
    pub fn scope_line(&self) -> &str {
        &self.scope_line
    }

    /// The `x-amz-date` the string-to-sign is dated with.
    #[must_use]
    pub fn amz_date(&self) -> &str {
        &self.amz_date
    }
}

/// Where an [`super::Authenticator`] leaves a [`ChunkVerification`] for the body reader to collect.
///
/// Write-once: a second publication would mean two answers to "what key verifies this body", and
/// the reader has no way to choose between them. [`ChunkSink::publish`] silently keeps the first,
/// because the alternative — a panic on a path an extension point controls — turns an
/// implementation bug into an availability bug.
///
/// # Security
///
/// The default sink contains no chunk-verification material. It cannot make a streaming body
/// verifiable until an authenticator explicitly publishes that material.
#[derive(Default)]
pub struct ChunkSink {
    slot: std::sync::OnceLock<ChunkVerification>,
}

impl ChunkSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slot: std::sync::OnceLock::new(),
        }
    }

    /// Publishes the material, if nothing has been published yet.
    pub fn publish(&self, material: ChunkVerification) {
        let _ = self.slot.set(material);
    }

    /// What was published, if anything.
    #[must_use]
    pub fn get(&self) -> Option<&ChunkVerification> {
        self.slot.get()
    }
}

impl core::fmt::Debug for ChunkSink {
    /// Reports only whether it is filled. The contents are a signing key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkSink")
            .field("published", &self.slot.get().is_some())
            .finish()
    }
}
