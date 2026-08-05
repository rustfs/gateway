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
