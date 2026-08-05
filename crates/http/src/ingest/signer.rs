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

//! The chunk signature chain: one derivation per scope, one HMAC per chunk, no allocation.
//!
//! Responsible for: [`SigningKeyCache`] (the derived key, kept for as long as its scope is
//! valid), [`ChunkSigner`] (the running payload hash and the chained verification), and the
//! stack-resident string-to-sign the two share.
//! NOT responsible for: deriving a signing key. The four-step derivation is
//! `rustfs-gateway-sig`'s and stays there — this module holds the *result* and the closure that
//! produces it, because a security primitive implemented twice is a security primitive that
//! drifts. Also not responsible for verifying the request signature, or for the trailer
//! signature (P3-04).
//! Upstream: `hmac`, `sha2`, `subtle`, `zeroize`. Downstream: `pipeline`.
//!
//! # Why the derivation is cached and the chunk HMAC is not
//!
//! A SigV4 signing key is `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service),
//! "aws4_request")`. Every input is the credential scope; none of them is the chunk. Deriving it
//! per chunk therefore recomputes the same 32 bytes for every chunk of the upload:
//!
//! ```text
//! 5 GiB upload, 64 KiB chunks = 81,920 chunks
//!   derive per chunk : 81,920 x 5 HMAC = 409,600
//!   derive per scope :      1 x 4 HMAC + 81,920 x 1 = 81,924      (-80.0%)
//! ```
//!
//! [`SigningKeyCache::derivations`] and [`ChunkSigner::hmac_calls`] are public so that ratio is a
//! test assertion instead of a comment. The per-chunk string-to-sign is written into a stack
//! buffer and the comparison runs on the raw 32 bytes, so a chunk costs one HMAC, no allocation,
//! and no hex encoding.

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::ingest::reject::ChunkReject;

type HmacSha256 = Hmac<Sha256>;

/// The longest credential-scope line this module will sign with.
///
/// `20130524/us-east-1/s3/aws4_request` is 34 bytes; the ceiling leaves room for the longest
/// plausible region name and keeps the string-to-sign buffer a fixed, stack-resident size.
pub const MAX_SCOPE_LINE_BYTES: usize = 80;

/// The exact width of an ISO 8601 basic-format timestamp: `20130524T000000Z`.
const AMZ_DATE_BYTES: usize = 16;

/// The string-to-sign buffer size.
///
/// 25 (`AWS4-HMAC-SHA256-PAYLOAD\n`) + 17 (date) + 81 (scope) + 65 + 65 + 64 = 317, rounded up.
const STRING_TO_SIGN_CAPACITY: usize = 320;

/// Lowercase hex SHA-256 of the empty byte string, which is the payload hash of every chunk's
/// (absent) canonical request.
const EMPTY_SHA256_HEX: &[u8; 64] = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The fixed prefix of a chunk string-to-sign.
const CHUNK_STRING_TO_SIGN_PREFIX: &[u8] = b"AWS4-HMAC-SHA256-PAYLOAD\n";

/// One HMAC-SHA256 step.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    #[allow(clippy::expect_used)] // HMAC accepts a key of any length, so this construction cannot fail.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Writes `bytes` as lowercase hex into `out`, which must be twice as long.
fn write_hex_lower(bytes: &[u8; 32], out: &mut [u8]) -> Option<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.iter().enumerate() {
        let at = index.checked_mul(2)?;
        let high = *DIGITS.get(usize::from(byte >> 4))?;
        let low = *DIGITS.get(usize::from(byte & 0x0f))?;
        *out.get_mut(at)? = high;
        *out.get_mut(at.checked_add(1)?)? = low;
    }
    Some(())
}

/// Decodes exactly 64 lowercase hex characters into 32 bytes.
///
/// Uppercase is refused rather than accepted: AWS emits lowercase, two spellings of one signature
/// is one more thing two parsers can disagree about, and nothing legitimate sends the other one.
fn decode_hex_lower_32(input: &[u8]) -> Option<[u8; 32]> {
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index.checked_mul(2)?;
        let high = hex_value_lower(*input.get(at)?)?;
        let low = hex_value_lower(*input.get(at.checked_add(1)?)?)?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

/// The value of one lowercase hexadecimal digit.
fn hex_value_lower(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// A derived SigV4 signing key.
///
/// No `Debug`, no `PartialEq`, no `Display`: anybody holding these 32 bytes can sign every
/// request in the scope, so the type offers no way to print it and no way to compare it with
/// `==`. The bytes are wiped when the value is dropped.
pub struct ChunkSigningKey([u8; 32]);

impl ChunkSigningKey {
    /// Adopts the result of the four-step derivation performed one layer above.
    ///
    /// The constructor takes the finished key rather than the secret, and this crate contains no
    /// derivation of its own: `rustfs-gateway-sig::signing_key` is the single implementation, and
    /// a second one here would be a second place for the chain to be got subtly wrong.
    #[must_use]
    pub fn from_derived(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn copy(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for ChunkSigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The identity a derived key is valid for.
///
/// The credential is part of the key because two callers under different secrets share every
/// other field; a cache keyed on the scope alone would hand one caller's key to the other. It is
/// the access key *identifier*, which is public, never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeId {
    credential: Box<str>,
    date: Box<str>,
    region: Box<str>,
    service: Box<str>,
}

impl ScopeId {
    /// Builds a scope identity from the four public fields of a credential scope.
    #[must_use]
    pub fn new(credential: &str, date: &str, region: &str, service: &str) -> Self {
        Self {
            credential: Box::from(credential),
            date: Box::from(date),
            region: Box::from(region),
            service: Box::from(service),
        }
    }

    /// The day this identity is scoped to.
    #[must_use]
    pub fn date(&self) -> &str {
        &self.date
    }

    /// The region this identity is scoped to.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The service this identity is scoped to.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The `<date>/<region>/<service>/aws4_request` line as it appears in a string-to-sign.
    #[must_use]
    pub fn scope_line(&self) -> String {
        format!("{}/{}/{}/aws4_request", self.date, self.region, self.service)
    }
}

/// Derived signing keys, kept for as long as their scope can still be presented.
///
/// # What this fixes, in numbers
///
/// One derivation per scope instead of one per chunk: a 5 GiB upload in 64 KiB chunks performs
/// 81,924 HMAC operations instead of 409,600 — 80.0% fewer — and the difference is entirely
/// recomputation of a value that cannot change within a request. [`Self::derivations`],
/// [`Self::hits`] and [`Self::misses`] make that a test assertion.
///
/// # Bounded, and wiped
///
/// The cache holds at most `capacity` entries and evicts the oldest; an unbounded cache keyed on
/// a peer-supplied credential is an unbounded allocation keyed on a peer-supplied value. Every
/// evicted or dropped key is zeroed.
pub struct SigningKeyCache {
    entries: Vec<(ScopeId, ChunkSigningKey)>,
    capacity: usize,
    hits: u64,
    misses: u64,
    derivations: u64,
}

impl SigningKeyCache {
    /// The default number of scopes kept: two days times a handful of active credentials.
    pub const DEFAULT_CAPACITY: usize = 16;

    /// Builds a cache holding at most `capacity` derived keys; zero is raised to one.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            hits: 0,
            misses: 0,
            derivations: 0,
        }
    }

    /// Returns the key for `scope`, deriving it exactly once per scope.
    ///
    /// The derivation is a closure rather than a method because this crate must not contain the
    /// derivation chain: the caller supplies `rustfs-gateway-sig`'s. The closure is invoked on a
    /// miss and never on a hit, which is precisely the property the counters record.
    pub fn signing_key_for<F>(&mut self, scope: &ScopeId, derive: F) -> ChunkSigningKey
    where
        F: FnOnce() -> ChunkSigningKey,
    {
        if let Some((_, key)) = self.entries.iter().find(|(id, _)| id == scope) {
            self.hits = self.hits.saturating_add(1);
            return key.copy();
        }
        self.misses = self.misses.saturating_add(1);
        self.derivations = self.derivations.saturating_add(1);
        let key = derive();
        let stored = key.copy();
        if self.entries.len() >= self.capacity && !self.entries.is_empty() {
            // The oldest entry leaves; `remove` drops it, and the drop wipes the key.
            let _ = self.entries.remove(0);
        }
        self.entries.push((scope.clone(), stored));
        key
    }

    /// How many lookups were served without a derivation.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// How many lookups had to derive.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// How many derivations were performed; equal to [`Self::misses`] by construction.
    ///
    /// Both are exposed because they answer different questions: the miss count is about the
    /// cache, and the derivation count is about the four HMAC operations each one costs.
    #[must_use]
    pub fn derivations(&self) -> u64 {
        self.derivations
    }

    /// Hits per thousand lookups; zero when nothing has been looked up.
    ///
    /// Parts per thousand rather than a float, so a test can assert an exact value.
    #[must_use]
    pub fn hit_permille(&self) -> u64 {
        let lookups = self.hits.saturating_add(self.misses);
        if lookups == 0 {
            return 0;
        }
        self.hits.saturating_mul(1000).checked_div(lookups).unwrap_or(0)
    }

    /// How many HMAC operations the derivations performed: four per derivation.
    #[must_use]
    pub fn hmac_calls(&self) -> u64 {
        self.derivations.saturating_mul(4)
    }
}

impl fmt::Debug for SigningKeyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately renders no scope and no key material: a cache dump in a log would be a
        // list of which credentials are active, and worse.
        f.debug_struct("SigningKeyCache")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .finish()
    }
}

/// The signature that seeds the chunk chain: the signature of the request head.
///
/// A chunk chain that started from anything else would let a chunk signature from one request be
/// replayed into another. No `Debug` and no `PartialEq`, for the usual reason.
pub struct ChunkSeed([u8; 32]);

impl ChunkSeed {
    /// Adopts the verified request-head signature.
    #[must_use]
    pub fn from_request_signature(signature: [u8; 32]) -> Self {
        Self(signature)
    }

    /// Parses the seed from its 64-character lowercase hex spelling.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] for chunk zero when the spelling is not exactly 64
    /// lowercase hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, ChunkReject> {
        decode_hex_lower_32(hex.as_bytes())
            .map(Self)
            .ok_or(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    }
}

/// The scope and timestamp every chunk string-to-sign repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkScope {
    scope_line: Box<str>,
    amz_date: Box<str>,
}

impl ChunkScope {
    /// Builds the repeated part of the chunk string-to-sign.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] for chunk zero when the scope line is longer than
    /// [`MAX_SCOPE_LINE_BYTES`] or the timestamp is not the 16-character basic format. Both are
    /// server-side facts by the time they reach here, so a violation is a construction bug — but
    /// it is one that would otherwise silently truncate the buffer the signature is computed over.
    pub fn new(scope_line: &str, amz_date: &str) -> Result<Self, ChunkReject> {
        if scope_line.len() > MAX_SCOPE_LINE_BYTES || scope_line.is_empty() || amz_date.len() != AMZ_DATE_BYTES {
            return Err(ChunkReject::SignatureChainBroken { chunk_index: 0 });
        }
        Ok(Self {
            scope_line: Box::from(scope_line),
            amz_date: Box::from(amz_date),
        })
    }
}

/// The running payload hash and the chained chunk verification.
///
/// One instance per request. It holds the derived key, hashes each run of decoded bytes as the
/// decoder produces it, and verifies one chunk with one HMAC and one constant-time comparison.
pub struct ChunkSigner {
    key: ChunkSigningKey,
    scope: ChunkScope,
    previous: [u8; 32],
    hasher: Sha256,
    hashed_bytes: u64,
    hmac_calls: u64,
    chunk_index: u32,
}

impl ChunkSigner {
    /// Builds a signer over an already-derived key, seeded by the request signature.
    #[must_use]
    pub fn new(key: ChunkSigningKey, scope: ChunkScope, seed: ChunkSeed) -> Self {
        Self {
            key,
            scope,
            previous: seed.0,
            hasher: Sha256::new(),
            hashed_bytes: 0,
            hmac_calls: 0,
            chunk_index: 0,
        }
    }

    /// Adds one run of decoded chunk bytes to the running payload hash.
    ///
    /// Called from the decode loop while the bytes are still in cache; there is no second pass
    /// over the chunk and no buffer holding it for one.
    pub fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        Digest::update(&mut self.hasher, bytes);
        self.hashed_bytes = self.hashed_bytes.saturating_add(bytes.len() as u64);
    }

    /// Verifies the signature of the chunk that has just ended, and advances the chain.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] carrying the index of the failing chunk. The error
    /// never carries either signature: "expected versus actual" in an authentication failure is a
    /// signing oracle.
    pub fn verify_chunk(&mut self, presented: &[u8; 32]) -> Result<(), ChunkReject> {
        let chunk_index = self.chunk_index;
        let digest: [u8; 32] = core::mem::take(&mut self.hasher).finalize().into();

        let mut buf = [0u8; STRING_TO_SIGN_CAPACITY];
        let len = self
            .write_string_to_sign(&digest, &mut buf)
            .ok_or(ChunkReject::SignatureChainBroken { chunk_index })?;
        let signed = buf.get(..len).ok_or(ChunkReject::SignatureChainBroken { chunk_index })?;

        let expected = hmac_sha256(self.key.expose(), signed);
        self.hmac_calls = self.hmac_calls.saturating_add(1);

        // Constant time, over the raw 32 bytes. Comparing hex would cost an encoding per chunk
        // and would compare twice as many bytes for no additional strength.
        let matched: bool = expected.ct_eq(presented).into();
        if !matched {
            return Err(ChunkReject::SignatureChainBroken { chunk_index });
        }

        self.previous = expected;
        self.chunk_index = self.chunk_index.saturating_add(1);
        Ok(())
    }

    /// How many chunks have been verified so far.
    #[must_use]
    pub fn chunks_verified(&self) -> u32 {
        self.chunk_index
    }

    /// How many HMAC operations this signer has performed: exactly one per chunk.
    #[must_use]
    pub fn hmac_calls(&self) -> u64 {
        self.hmac_calls
    }

    /// How many body bytes have passed through the payload hash.
    ///
    /// Compared against the decoded byte count, this is the single-pass witness for the signing
    /// half of the pipeline.
    #[must_use]
    pub fn hashed_bytes(&self) -> u64 {
        self.hashed_bytes
    }

    /// Writes the chunk string-to-sign into `out` and returns its length.
    ///
    /// Entirely on the stack, and every write is bounds-checked: a request performs zero
    /// allocations for its 81,920 chunk signatures.
    fn write_string_to_sign(&self, chunk_digest: &[u8; 32], out: &mut [u8; STRING_TO_SIGN_CAPACITY]) -> Option<usize> {
        let mut at = 0usize;
        let mut put = |src: &[u8], at: &mut usize| -> Option<()> {
            let end = at.checked_add(src.len())?;
            out.get_mut(*at..end)?.copy_from_slice(src);
            *at = end;
            Some(())
        };

        put(CHUNK_STRING_TO_SIGN_PREFIX, &mut at)?;
        put(self.scope.amz_date.as_bytes(), &mut at)?;
        put(b"\n", &mut at)?;
        put(self.scope.scope_line.as_bytes(), &mut at)?;
        put(b"\n", &mut at)?;

        let mut hex = [0u8; 64];
        write_hex_lower(&self.previous, &mut hex)?;
        put(&hex, &mut at)?;
        put(b"\n", &mut at)?;

        put(EMPTY_SHA256_HEX, &mut at)?;
        put(b"\n", &mut at)?;

        write_hex_lower(chunk_digest, &mut hex)?;
        put(&hex, &mut at)?;

        Some(at)
    }
}

impl fmt::Debug for ChunkSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkSigner")
            .field("chunks_verified", &self.chunk_index)
            .field("hmac_calls", &self.hmac_calls)
            .field("hashed_bytes", &self.hashed_bytes)
            .finish_non_exhaustive()
    }
}

/// Parses the 64 lowercase hex characters of a chunk signature.
///
/// # Errors
///
/// `None` for any other spelling, including uppercase hex and a quoted value.
pub(crate) fn parse_chunk_signature(input: &[u8]) -> Option<[u8; 32]> {
    decode_hex_lower_32(input)
}
