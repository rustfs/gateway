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

//! The migration-only pure-function differential between the gateway and the pinned s3s revision
//! RustFS main links (rustfs/backlog#1762).
//!
//! Responsible for: sending one raw request through the real assembled gateway service and through
//! the pinned s3s service, each with a backend that records what it was handed, and reporting where
//! the two decodes differ — the operation each routed to, every input member by field path, the
//! refusal (status, code, message), and the digest of the body bytes left for the handler.
//! NOT responsible for: storage, response replay, streaming cadence (conformance cases own those),
//! authentication of recorded traffic (the corpus redacts it), or anything RustFS installs around
//! s3s. Nothing here is linked by a shipping crate; see `README.md` for why this is not an
//! in-process dual stack.
//! Upstream: `rustfs-gateway` (assembly), `rustfs-gateway-core` (route table), the
//! `compat::s3s_0_17_0` seam of `rustfs-gateway-types` (the only path to s3s).
//! Downstream: this crate's tests and, later, its corpus runners and shadow proxy.

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod convert;
pub mod corpus;
mod fields;
mod gateway;
mod oracle;
mod probe;
mod project;
mod request;
mod resolver;
// Test-only for now: the seam diff is judged by `tests/seam.rs`; no runner drives it yet.
#[cfg(test)]
mod seam;
mod sign;
mod xmltree;

pub mod decode;
pub mod encode;
pub mod fuzz;
pub mod fuzz_case;
pub mod known;
pub mod normalize;
pub mod runner;
pub mod samples;
pub mod shadow;
pub mod tee;

pub use convert::Unconvertible;
pub use decode::{
    BodyDigest, Cmp, DecodeDiff, Differ, FieldDiff, Finding, Item, Priority, Profile, S3ErrorView, decode_diff,
    rustfs_decode_diff,
};
pub use encode::{EncodeDiff, HeaderDiff, OutputSample, PLACEHOLDER_LENGTH, WireAnswer, placeholder_body};
pub use fields::{FieldValue, Fields};
pub use known::{KnownDiff, KnownDiffs, Verdict};
pub use normalize::{Format, FormatAssertion, Normalizer, Side};
pub use project::{DIFFED_OPERATIONS, OracleOutput};
pub use request::RawRequest;

/// The s3s revision every oracle answer in this crate comes from: the one RustFS main links.
use rustfs_gateway_types::compat::s3s_0_17_0::s3s;

#[cfg(test)]
mod tests;
