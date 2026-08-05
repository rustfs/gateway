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

//! The size ceilings [`crate::WireRequest::accept`] enforces, and the name of the one that was hit.
//!
//! Responsible for: the [`Limits`] struct the acceptance layer reads, its defaults, and
//! [`LimitKind`] so a rejection says which ceiling was crossed instead of only that one was.
//! NOT responsible for: the six timeout layers (header read, header-to-first-body-byte, per-IP
//! half-open connection caps, and so on). Those need a driver and a clock; they are P3-05's, and
//! this struct is the place they will be added.
//! Upstream: nothing. Downstream: `framing`, `query_view`, `wire`, `reject`.

/// Which ceiling a request crossed.
///
/// The variant is carried on the rejection so an operator can raise the right limit; it is never
/// reflected to the client, because "your request was 4 bytes over the header budget" is a
/// probing oracle for the budget itself.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// Too many header fields.
    HeaderCount,
    /// The header block, counted as name plus value bytes, was too large.
    HeaderBytes,
    /// The request target (path plus query) was too long.
    UriBytes,
    /// The query string was too long.
    QueryBytes,
    /// Too many query parameters.
    QueryParams,
    /// The effective host was too long.
    HostBytes,
    /// The declared body length exceeded the ceiling.
    ///
    /// This one is decided from `Content-Length` alone, before a single body byte is read.
    /// Draining the body first to "be polite" would mean paying the attacker's bandwidth for
    /// them, so the rejection is immediate and the connection closes.
    BodyBytes,
    /// A chunk-size line was longer than [`crate::MAX_CHUNK_SIZE_LINE_BYTES`].
    ChunkSizeLine,
}

impl LimitKind {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderCount => "header-count",
            Self::HeaderBytes => "header-bytes",
            Self::UriBytes => "uri-bytes",
            Self::QueryBytes => "query-bytes",
            Self::QueryParams => "query-params",
            Self::HostBytes => "host-bytes",
            Self::BodyBytes => "body-bytes",
            Self::ChunkSizeLine => "chunk-size-line",
        }
    }
}

/// The ceilings the acceptance layer enforces.
///
/// The numbers below are working defaults, not a tuned policy: P3-05 owns the policy and the
/// timeouts. What is already fixed here is the *shape* — every ceiling is a plain count of bytes
/// or fields decidable before any body byte is read, so no limit check can be turned into a
/// reason to buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of header fields, counting repeats separately.
    pub max_header_count: usize,
    /// Maximum total header bytes, counting each field's name and value.
    pub max_header_bytes: usize,
    /// Maximum length of the request target as it appeared on the wire.
    pub max_uri_bytes: usize,
    /// Maximum length of the query string.
    ///
    /// Capped at [`Limits::QUERY_BYTES_CEILING`] on read: the query index stores offsets as
    /// `u16`, and a limit above that ceiling would silently truncate them.
    pub max_query_bytes: usize,
    /// Maximum number of query parameters.
    pub max_query_params: usize,
    /// Maximum length of the effective host, including any port.
    pub max_host_bytes: usize,
    /// Maximum declared body length, in bytes.
    pub max_body_bytes: u64,
}

impl Limits {
    /// The hard ceiling on [`Limits::max_query_bytes`], imposed by the `u16` offsets the query
    /// index stores. A configured value above this is clamped rather than honoured.
    pub const QUERY_BYTES_CEILING: usize = u16::MAX as usize;

    /// The effective query-byte ceiling, never above [`Limits::QUERY_BYTES_CEILING`].
    #[must_use]
    pub fn query_bytes(&self) -> usize {
        self.max_query_bytes.min(Self::QUERY_BYTES_CEILING)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_count: 128,
            max_header_bytes: 16 * 1024,
            max_uri_bytes: 8 * 1024,
            max_query_bytes: 4 * 1024,
            max_query_params: 64,
            max_host_bytes: crate::host::MAX_HOST_BYTES,
            max_body_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// The ceilings the `aws-chunked` decoder enforces, all of them decidable from a chunk header.
///
/// # The ceiling that is a security fix, not a tuning knob
///
/// A chunk *size* is parsed from a hexadecimal field whose natural ceiling is whatever the parser
/// happens to hold it in. Bounding only the metadata line — which is the shape a chunk decoder
/// usually arrives in — bounds the header and leaves the announced payload unbounded: a peer can
/// announce a four-gigabyte chunk, then feed it one byte per second, and a decoder that must hold
/// the chunk until its trailing signature arrives grows to four gigabytes while holding nothing it
/// is yet able to verify. [`ChunkLimits::max_chunk_size`] defaults to one mebibyte, is checked at
/// the chunk header before a single data byte is read, and has a hard ceiling that no
/// configuration can raise. There is deliberately no `unlimited()` constructor.
///
/// # Every field is private
///
/// The invariants — one mebibyte by default, never above [`ChunkLimits::HARD_MAX_CHUNK_SIZE`], a
/// metadata ceiling that leaves room for exactly one chunk signature — are enforced by the
/// setters. Public fields would let a caller construct precisely the states the setters clamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkLimits {
    max_chunk_size: u32,
    max_chunk_meta_size: u16,
    min_chunk_size_for_count: u32,
    max_chunk_count_slack: u32,
    max_overhead_permille: u16,
    overhead_ratio_floor_bytes: u64,
}

impl ChunkLimits {
    /// The largest chunk size any configuration may permit.
    ///
    /// A ceiling on the ceiling. The default is sixteen times lower; this exists so that raising
    /// the limit for an unusual client cannot re-open the unbounded-buffer hole by accident.
    pub const HARD_MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

    /// The default per-chunk data ceiling: one mebibyte.
    pub const DEFAULT_MAX_CHUNK_SIZE: u32 = 1024 * 1024;

    /// The smallest metadata ceiling that can still hold a chunk signature.
    ///
    /// `<16 hex digits>;chunk-signature=<64 hex>` is 96 bytes; the remainder is slack for the
    /// CRLF and for the parser to see a violation rather than run out of buffer.
    pub const MIN_CHUNK_META_SIZE: u16 = 128;

    /// The per-chunk data ceiling, in bytes.
    #[must_use]
    pub fn max_chunk_size(&self) -> u32 {
        self.max_chunk_size
    }

    /// The chunk-size line ceiling, in bytes, including the chunk extension and the CRLF.
    #[must_use]
    pub fn max_chunk_meta_size(&self) -> u16 {
        self.max_chunk_meta_size
    }

    /// The chunk size the chunk-count ceiling is derived from.
    #[must_use]
    pub fn min_chunk_size_for_count(&self) -> u32 {
        self.min_chunk_size_for_count
    }

    /// The largest framing overhead, in parts per thousand of the decoded body.
    ///
    /// Parts per thousand rather than a float: the comparison runs on the data path, and integer
    /// arithmetic here cannot round two different configurations onto the same behaviour.
    #[must_use]
    pub fn max_overhead_permille(&self) -> u16 {
        self.max_overhead_permille
    }

    /// The overhead below which the ratio is not enforced.
    ///
    /// A short upload is nearly all framing by definition — a one-byte body carries a whole chunk
    /// header — so the ratio only starts to mean anything once enough overhead has accumulated to
    /// distinguish a small request from a flood.
    #[must_use]
    pub fn overhead_ratio_floor_bytes(&self) -> u64 {
        self.overhead_ratio_floor_bytes
    }

    /// Sets the per-chunk data ceiling, clamped to [`ChunkLimits::HARD_MAX_CHUNK_SIZE`] and to at
    /// least one byte.
    #[must_use]
    pub fn with_max_chunk_size(mut self, bytes: u32) -> Self {
        self.max_chunk_size = bytes.clamp(1, Self::HARD_MAX_CHUNK_SIZE);
        self
    }

    /// Sets the chunk-size line ceiling, clamped to at least [`ChunkLimits::MIN_CHUNK_META_SIZE`]
    /// and to at most [`crate::MAX_CHUNK_SIZE_LINE_BYTES`].
    #[must_use]
    pub fn with_max_chunk_meta_size(mut self, bytes: u16) -> Self {
        let ceiling = u16::try_from(crate::MAX_CHUNK_SIZE_LINE_BYTES).unwrap_or(u16::MAX);
        self.max_chunk_meta_size = bytes.clamp(Self::MIN_CHUNK_META_SIZE, ceiling);
        self
    }

    /// Sets the chunk size the chunk-count ceiling is derived from; at least one byte.
    #[must_use]
    pub fn with_min_chunk_size_for_count(mut self, bytes: u32) -> Self {
        self.min_chunk_size_for_count = bytes.max(1);
        self
    }

    /// Sets the framing-overhead ceiling, in parts per thousand.
    #[must_use]
    pub fn with_max_overhead_permille(mut self, permille: u16) -> Self {
        self.max_overhead_permille = permille.min(1000);
        self
    }

    /// Sets the overhead floor below which the ratio is not enforced.
    #[must_use]
    pub fn with_overhead_ratio_floor_bytes(mut self, bytes: u64) -> Self {
        self.overhead_ratio_floor_bytes = bytes;
        self
    }

    /// The largest number of chunks a body of `decoded_length` bytes may be split into.
    ///
    /// Derived rather than configured: the ceiling that matters is a function of how much body
    /// there is, and a fixed number would be far too tight for a large upload and useless for a
    /// small one. The slack covers the terminal chunk and a client whose last chunk is short.
    #[must_use]
    pub fn max_chunk_count(&self, decoded_length: u64) -> u64 {
        let min_chunk = u64::from(self.min_chunk_size_for_count.max(1));
        decoded_length
            .div_ceil(min_chunk)
            .saturating_add(u64::from(self.max_chunk_count_slack))
    }
}

impl Default for ChunkLimits {
    fn default() -> Self {
        Self {
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
            max_chunk_meta_size: 256,
            min_chunk_size_for_count: 1024,
            max_chunk_count_slack: 16,
            max_overhead_permille: 50,
            overhead_ratio_floor_bytes: 4096,
        }
    }
}
