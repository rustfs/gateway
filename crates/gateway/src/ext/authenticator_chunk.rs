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

//! Chunk-verification material hand-off between authentication and `aws-chunked` body ingest.
//!
//! Responsible for: [`ChunkVerification`] (either a derived SigV4 HMAC `k_signing` key or a
//! SigV4a 33-byte SEC1 compressed P-256 public verifying key, plus scope line and timestamp) and
//! [`ChunkSink`], the write-once slot populated only after request-head verification succeeds.
//! NOT responsible for: deriving keys (`rustfs-gateway-sig`), decoding frames
//! (`rustfs-gateway-http`), or verifying request heads (`super::authenticator`).
//! Upstream: `super::SigV4Authenticator` and `super::authenticator_sigv4a`.
//! Downstream: `crate::chunked`.

/// Maximum byte width of a canonical ASN.1 DER ECDSA P-256 signature.
const MAX_ECDSA_DER_BYTES: usize = 72;

/// Internal algorithm-typed key material carried by [`ChunkVerification`].
enum ChunkKeyMaterial {
    Hmac(rustfs_gateway_sig::SigningKey),
    Ecdsa {
        verifying_key_sec1: [u8; 33],
        seed_der: [u8; MAX_ECDSA_DER_BYTES],
        seed_der_len: u8,
    },
}

/// The material a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]` or
/// `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]` body's per-chunk signatures are checked
/// against.
///
/// # Why this exists at all
///
/// The `aws-chunked` chunk chain is seeded by the *request* signature and verified with the same
/// key (SigV4 `k_signing`, or SigV4a public P-256 verifying key) that verified the request head.
/// Neither value survives [`rustfs_gateway_sig::Verdict`], so the material travels beside the
/// verdict through a write-once sink that the pipeline reads only after the verdict succeeded.
///
/// No `Debug`, no `Clone`: the HMAC variant holds a derived signing key.
pub struct ChunkVerification {
    key: ChunkKeyMaterial,
    scope_line: String,
    amz_date: String,
}

impl ChunkVerification {
    /// Publishes the derived SigV4 HMAC key and the scope the chunk chain is dated with.
    #[must_use]
    pub fn new(key: rustfs_gateway_sig::SigningKey, scope_line: String, amz_date: String) -> Self {
        Self {
            key: ChunkKeyMaterial::Hmac(key),
            scope_line,
            amz_date,
        }
    }

    /// Publishes the derived SigV4a public P-256 verifying key (33-byte SEC1 compressed), the
    /// verified request-head ASN.1 DER seed bytes, and the scope the ECDSA chunk chain is dated
    /// with.
    ///
    /// Carries only the public curve point and the already-verified head signature bytes — never
    /// the derived private scalar — so downstream chunk ingest does not re-parse raw `Authorization`
    /// text to extract the seed.
    #[must_use]
    pub fn new_ecdsa(verifying_key_sec1: [u8; 33], seed_der_bytes: &[u8], scope_line: String, amz_date: String) -> Self {
        let mut seed_der = [0u8; MAX_ECDSA_DER_BYTES];
        let seed_der_len = if let Some(dest) = seed_der.get_mut(..seed_der_bytes.len())
            && let Ok(len) = u8::try_from(seed_der_bytes.len())
        {
            dest.copy_from_slice(seed_der_bytes);
            len
        } else {
            0
        };
        Self {
            key: ChunkKeyMaterial::Ecdsa {
                verifying_key_sec1,
                seed_der,
                seed_der_len,
            },
            scope_line,
            amz_date,
        }
    }

    /// The derived SigV4 `k_signing`, as the fixed-width value the HMAC chunk signer takes.
    ///
    /// `None` for ECDSA material or if the key is not 32 bytes.
    #[must_use]
    pub fn chunk_signing_key(&self) -> Option<rustfs_gateway_http::ChunkSigningKey> {
        let ChunkKeyMaterial::Hmac(key) = &self.key else {
            return None;
        };
        let bytes: [u8; 32] = key.expose().try_into().ok()?;
        Some(rustfs_gateway_http::ChunkSigningKey::from_derived(bytes))
    }

    /// The derived SigV4a public P-256 verifying key for the ECDSA chunk signer.
    ///
    /// `None` for HMAC material or if the 33 bytes are not a valid compressed P-256 SEC1 point.
    #[must_use]
    pub fn chunk_verifying_key(&self) -> Option<rustfs_gateway_http::ChunkVerifyingKey> {
        let ChunkKeyMaterial::Ecdsa { verifying_key_sec1, .. } = &self.key else {
            return None;
        };
        rustfs_gateway_http::ChunkVerifyingKey::from_sec1_compressed(*verifying_key_sec1).ok()
    }

    /// The verified SigV4a request-head ASN.1 DER seed for the ECDSA chunk signer.
    ///
    /// `None` for HMAC material or if the published DER bytes are malformed.
    #[must_use]
    pub fn chunk_ecdsa_seed(&self) -> Option<rustfs_gateway_http::EcdsaChunkSeed> {
        let ChunkKeyMaterial::Ecdsa {
            seed_der, seed_der_len, ..
        } = &self.key
        else {
            return None;
        };
        let slice = seed_der.get(..usize::from(*seed_der_len))?;
        rustfs_gateway_http::EcdsaChunkSeed::from_der(slice).ok()
    }

    /// The credential scope line (`<date>/<region>/<service>/aws4_request` for SigV4, or
    /// `<date>/<service>/aws4_request` for SigV4a).
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

/// Where an [`super::Authenticator`] leaves a [`ChunkVerification`] for the body reader to
/// collect.
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
    /// Reports only whether it is filled. The HMAC variant holds a signing key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkSink")
            .field("published", &self.slot.get().is_some())
            .finish()
    }
}
