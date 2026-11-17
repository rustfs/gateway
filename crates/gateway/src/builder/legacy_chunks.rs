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

//! The RustFS-profile switches that decode aws-chunked framing under legacy RustFS's chunk and
//! trailer rules as far as this crate's residency bound allows (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::read_aws_chunks_as_legacy_rustfs`],
//! [`ServiceBuilder::accept_an_empty_line_before_aws_chunk_trailers`] and [`ChunkReading`], the
//! chunk limits the pipeline hands every aws-chunked body it decodes.
//! NOT responsible for: the decoder (`rustfs-gateway-http`'s ingest), or the wire length a framed
//! upload may declare (`crate::gate::max_framed_upload_bytes`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! Legacy RustFS decodes aws-chunked framing with no bound on how many chunks a body is cut into
//! or on how many bytes the framing spends, streams an unsigned chunk of any size, and holds a
//! signed chunk of up to 256 MiB until its signature verifies; its stack configuration leaves that
//! ceiling at the legacy stack's default (`rustfs/src/server/http.rs:166-173` on rustfs/rustfs
//! `3268c42e00`). Observed against a legacy RustFS build: a `PutObject` sent as one 8 MiB
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` chunk is stored — the shape a client produces when it
//! streams a whole buffer as one chunk. The core refuses a chunk past 1 MiB, a body cut into more
//! than one chunk per KiB, and framing past 5% of the body.
//!
//! # What the RustFS profile keeps
//!
//! This crate holds a chunk whole until it ends, and verifies a signed one before any of it is
//! delivered, so a chunk's size is what one connection holds. The profile lifts the ceiling to the
//! largest this crate allows, [`ChunkLimits::HARD_MAX_CHUNK_SIZE`] (16 MiB), and no further: a
//! chunk past it is still refused, `400 InvalidChunkSizeError`, with nothing stored, where legacy
//! RustFS streams an unsigned one of any size. Reading those needs a decoder that releases an
//! unsigned chunk before it ends, which rustfs/gateway#1173 leaves open for a decision.
//! The chunk count and the framing ratio are lifted entirely: each chunk carries at least one body
//! byte and a bounded size line, so the work a body can ask for stays linear in its length.
//!
//! # The empty line before a trailer section
//!
//! Legacy RustFS reads everything after the terminal chunk line to the end of the body as the
//! trailer section and skips every empty line in it (s3s `5761ddf`,
//! `crates/s3s/src/stream/aws_chunked_stream.rs:302-305` and `:425-446`: a zero-sized chunk
//! consumes no data CRLF, and the trailer reader drops empty lines), in both trailer modes. RustFS's
//! own suite signs its uploads as `0;chunk-signature=…\r\n\r\n` followed by the trailer fields,
//! which the core reads as an empty trailer section and refuses. The profile reads exactly one CRLF
//! there as part of the section ([`ChunkLimits::with_empty_line_before_trailers`]); a second one,
//! an empty line between fields, or a byte after the terminator stays refused, so the section's
//! end is still the first empty line after a field.

use rustfs_gateway_http::ChunkLimits;

use super::ServiceBuilder;

/// Which chunk limits an aws-chunked body is decoded under: the core's, [`ChunkLimits::default`],
/// with each legacy RustFS reading a switch turned on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChunkReading {
    /// [`ServiceBuilder::read_aws_chunks_as_legacy_rustfs`].
    pub(crate) legacy_chunks: bool,
    /// [`ServiceBuilder::accept_an_empty_line_before_aws_chunk_trailers`].
    pub(crate) empty_line_before_trailers: bool,
}

impl ChunkReading {
    /// The limits a body is decoded under.
    pub(crate) fn limits(self) -> ChunkLimits {
        let mut limits = ChunkLimits::default();
        if self.legacy_chunks {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS bounds neither the number of
            // chunks nor the bytes their framing spends, so a peer may cut a body into one-byte
            // chunks and make the decoder parse a size line per byte. Kept so the clients RustFS
            // serves today keep working (a stream of small writes becomes small chunks); the work
            // stays linear in the body. The intended future behaviour is the core's bounds.
            limits = limits
                .with_max_chunk_size(ChunkLimits::HARD_MAX_CHUNK_SIZE)
                .with_min_chunk_size_for_count(1)
                .with_overhead_ratio_floor_bytes(u64::MAX);
        }
        if self.empty_line_before_trailers {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS skips empty lines in a trailer
            // section, and RustFS's own signer writes one before the first field. Questionable
            // because the core reads that line as the section's end; kept, for exactly one CRLF,
            // so those uploads keep being stored. The intended future behaviour is the core's.
            limits = limits.with_empty_line_before_trailers();
        }
        limits
    }
}

impl ServiceBuilder {
    /// Decodes aws-chunked framing under legacy RustFS's chunk rules as far as this crate's
    /// residency bound allows (rustfs/gateway#1173): a chunk up to 16 MiB
    /// ([`ChunkLimits::HARD_MAX_CHUNK_SIZE`]) instead of 1 MiB, and any number of chunks spending
    /// any share of the body on framing.
    ///
    /// Off by default: the core refuses a chunk past 1 MiB, more chunks than one per KiB of body,
    /// and framing past 5% of it ([`ChunkLimits::default`]). Every other framing rule is unchanged
    /// — the declared decoded length, chunk signatures, the terminal chunk, the trailer — and a
    /// chunk past 16 MiB is still refused before any of it is read.
    #[must_use]
    pub fn read_aws_chunks_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.chunk_reading.legacy_chunks = true;
        self
    }

    /// Reads one CRLF between an aws-chunked body's terminal chunk line and its first trailer
    /// field as part of the trailer section, in both trailer modes, as legacy RustFS reads it.
    ///
    /// Off by default: the core reads that CRLF as the end of an empty trailer section, so the
    /// fields after it are bytes after the terminator and the upload is refused (`403` in signed
    /// framing, whose empty section lacks its signature). Exactly one is read: a second, or any byte
    /// after the section's terminator, is still refused, and a signed section's signature still
    /// covers every field after the line.
    #[must_use]
    pub fn accept_an_empty_line_before_aws_chunk_trailers(mut self) -> Self {
        self.view_policy.chunk_reading.empty_line_before_trailers = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_CHUNKS: ChunkReading = ChunkReading {
        legacy_chunks: true,
        empty_line_before_trailers: false,
    };

    /// Positive — the profile's limits admit a 16 MiB chunk and any chunk count or framing share.
    #[test]
    fn the_profile_lifts_the_chunk_ceiling_count_and_ratio() {
        let limits = LEGACY_CHUNKS.limits();
        assert_eq!(limits.max_chunk_size(), ChunkLimits::HARD_MAX_CHUNK_SIZE);
        assert_eq!(limits.max_chunk_count(10), 10 + limits.max_chunk_count(0), "one chunk per body byte");
        assert_eq!(limits.overhead_ratio_floor_bytes(), u64::MAX);
    }

    /// Negative — the default is the core's limits, and the profile keeps the meta-line ceiling.
    #[test]
    fn n_the_default_is_the_cores_limits_and_the_meta_line_is_kept() {
        assert_eq!(ChunkReading::default().limits(), ChunkLimits::default());
        assert_eq!(LEGACY_CHUNKS.limits().max_chunk_meta_size(), ChunkLimits::default().max_chunk_meta_size());
    }

    /// Negative — nothing past the crate's hard ceiling is admitted, however the profile asks.
    #[test]
    fn n_the_profile_stops_at_the_hard_chunk_ceiling() {
        assert!(LEGACY_CHUNKS.limits().max_chunk_size() <= ChunkLimits::HARD_MAX_CHUNK_SIZE);
        assert!(ChunkLimits::default().max_chunk_size() < LEGACY_CHUNKS.limits().max_chunk_size());
    }

    /// Positive — the empty-line switch reaches the limits, and only it.
    #[test]
    fn the_empty_line_switch_reaches_the_limits_alone() {
        let reading = ChunkReading {
            empty_line_before_trailers: true,
            ..ChunkReading::default()
        };
        assert!(reading.limits().accepts_empty_line_before_trailers());
        assert_eq!(reading.limits().max_chunk_size(), ChunkLimits::default().max_chunk_size());
    }

    /// Negative — neither the default nor the chunk switch reads the empty line.
    #[test]
    fn n_no_other_reading_accepts_the_empty_line() {
        assert!(!ChunkReading::default().limits().accepts_empty_line_before_trailers());
        assert!(!LEGACY_CHUNKS.limits().accepts_empty_line_before_trailers());
    }
}
