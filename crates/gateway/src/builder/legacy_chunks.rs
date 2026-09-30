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

//! The RustFS-profile switch that decodes aws-chunked framing under legacy RustFS's chunk rules as
//! far as this crate's residency bound allows (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::read_aws_chunks_as_legacy_rustfs`] and [`ChunkReading`],
//! the chunk limits the pipeline hands every aws-chunked body it decodes.
//! NOT responsible for: the decoder (`rustfs-gateway-http`'s ingest), the wire length a framed
//! upload may declare (`crate::gate::max_framed_upload_bytes`), or trailer sections.
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

use rustfs_gateway_http::ChunkLimits;

use super::ServiceBuilder;

/// Which chunk limits an aws-chunked body is decoded under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ChunkReading {
    /// The core's limits, [`ChunkLimits::default`].
    #[default]
    Model,
    /// Legacy RustFS's rules, as far as [`ChunkLimits::HARD_MAX_CHUNK_SIZE`] allows.
    LegacyRustfs,
}

impl ChunkReading {
    /// The limits a body is decoded under.
    pub(crate) fn limits(self) -> ChunkLimits {
        match self {
            Self::Model => ChunkLimits::default(),
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS bounds neither the number of
            // chunks nor the bytes their framing spends, so a peer may cut a body into one-byte
            // chunks and make the decoder parse a size line per byte. Kept so the clients RustFS
            // serves today keep working (a stream of small writes becomes small chunks); the work
            // stays linear in the body. The intended future behaviour is the core's bounds.
            Self::LegacyRustfs => ChunkLimits::default()
                .with_max_chunk_size(ChunkLimits::HARD_MAX_CHUNK_SIZE)
                .with_min_chunk_size_for_count(1)
                .with_overhead_ratio_floor_bytes(u64::MAX),
        }
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
        self.view_policy.chunk_reading = ChunkReading::LegacyRustfs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive — the profile's limits admit a 16 MiB chunk and any chunk count or framing share.
    #[test]
    fn the_profile_lifts_the_chunk_ceiling_count_and_ratio() {
        let limits = ChunkReading::LegacyRustfs.limits();
        assert_eq!(limits.max_chunk_size(), ChunkLimits::HARD_MAX_CHUNK_SIZE);
        assert_eq!(limits.max_chunk_count(10), 10 + limits.max_chunk_count(0), "one chunk per body byte");
        assert_eq!(limits.overhead_ratio_floor_bytes(), u64::MAX);
    }

    /// Negative — the default is the core's limits, and the profile keeps the meta-line ceiling.
    #[test]
    fn n_the_default_is_the_cores_limits_and_the_meta_line_is_kept() {
        assert_eq!(ChunkReading::default(), ChunkReading::Model);
        assert_eq!(ChunkReading::Model.limits(), ChunkLimits::default());
        assert_eq!(
            ChunkReading::LegacyRustfs.limits().max_chunk_meta_size(),
            ChunkLimits::default().max_chunk_meta_size()
        );
    }

    /// Negative — nothing past the crate's hard ceiling is admitted, however the profile asks.
    #[test]
    fn n_the_profile_stops_at_the_hard_chunk_ceiling() {
        assert!(ChunkReading::LegacyRustfs.limits().max_chunk_size() <= ChunkLimits::HARD_MAX_CHUNK_SIZE);
        assert!(ChunkLimits::default().max_chunk_size() < ChunkReading::LegacyRustfs.limits().max_chunk_size());
    }
}
