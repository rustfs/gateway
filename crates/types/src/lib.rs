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

//! S3 scalar types, operation inputs/outputs, and their generated codecs.
//!
//! Responsible for: `ETag`, `Checksum`, `Timestamp`, names, `Range`, error codes, and the
//! generated per-operation DTOs plus their XML/header codec impls, and the manual browser
//! `PostObject` surface omitted by the pinned service model.
//! NOT responsible for: wire framing, signing, routing.
//! Upstream: `rustfs-gateway-xml`, `rustfs-gateway-stream`. Downstream: `rustfs-gateway-http` and everything above.
//!
//! # Two facades over one set of types
//!
//! [`ops`] is the module-per-operation layout: `ops::put_object::{Input, Output}`. [`dto`] is the
//! flat alias surface: `dto::PutObjectInput`. They are the same types under two names — the first
//! keeps rustdoc navigable once the operation whitelist is complete, the second keeps `grep` and
//! an in-flight migration from `s3s::dto` working. Neither declares anything: both are generated
//! by `cargo xtask codegen` into `generated/dto/`, which is why they are mounted with `#[path]`
//! instead of living under `src/`.
//!
//! The `#[path]` targets go through `crates/types/generated`, a symlink to `generated/dto`. It is
//! load-bearing for publishing, not cosmetic: `include`/`#[path]` may not reach outside the package
//! directory in a `.crate` tarball, and the symlink is what puts the generated tree inside it. See
//! ADR-0005.
//!
//! Constructing a dto: public fields plus `..Default::default()`, or the per-operation builder.
//! Never destructure one exhaustively — see ADR-0004 P1 and P3 for why that is the only usage a
//! new model member breaks.
//!
//! # Required members are bare, optional members are `Option`
//!
//! `PutObjectInput::bucket` is a [`BucketName`], not an `Option<BucketName>`: requiredness is
//! expressed by the type, and a handler never unwraps a value the wire contract says is always
//! there. The price is that every scalar reachable from a required member has a `Default`, whose
//! value is deliberately **invalid on the wire** — see [`placeholder`] for what that means, why it
//! is safe, and the guard that keeps one off the decode path.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cors_tagging;
pub mod ext;
pub mod persistence;
pub mod placeholder;
mod post_object;
mod scalar;
pub mod secret;

/// Temporary, feature-gated adapters to the pinned s3s revisions.
///
/// This module is deliberately the only s3s dependency surface in the protocol kernel. It has two
/// halves, each behind its own feature:
///
/// - `compat-s3s`: the persistence oracles. Those adapters expose owned gateway-neutral values
///   rather than s3s types, and answer from every s3s revision named by `compat::OracleRevision`.
///   Only `rustfs-gateway-goldens` consumes them.
/// - `compat-s3s-0-17-0` (also enabled by `compat-s3s`): the migration seam compiled against
///   the s3s revision RustFS `main` links, as `compat::s3s_0_17_0`. Its whole point is to produce
///   the s3s values a RustFS app body receives, so its signatures name s3s types. The RustFS ring-2
///   adapter enables this feature alone; `compat-s3s` adds the same seam against the baseline
///   oracle, `compat::s3s_9c4690d8`, for the goldens.
///
/// It owns no gateway XML behavior, golden assertion, or production decision.
#[cfg(any(feature = "compat-s3s", feature = "compat-s3s-0-17-0"))]
pub mod compat;

#[cfg(test)]
mod tests;

/// Operation DTOs, one module per operation; `post_object` is maintained manually because the
/// pinned service model omits browser POST.
#[path = "../generated/ops/mod.rs"]
mod generated_ops;

/// Operation DTOs, one module per operation.
pub mod ops {
    pub use crate::generated_ops::*;

    /// DTOs for the standard POST Object surface omitted by the Smithy S3 model.
    pub mod post_object {
        pub use crate::post_object::{PostObject, PostObjectInput as Input, PostObjectOutput as Output};
    }
}

/// Flat aliases for every generated type: `dto::PutObjectInput` is `ops::put_object::Input`.
#[path = "../generated/flat.rs"]
mod generated_dto;

/// Flat aliases for every operation DTO.
pub mod dto {
    pub use crate::generated_dto::*;
    pub use crate::post_object::{PostObject, PostObjectFields, PostObjectInput, PostObjectOutput};
}

pub use crate::placeholder::{PlaceholderDefault, WirePlaceholder, reject_placeholder};
pub use crate::scalar::{
    AwsNameValidator, BucketName, ByteRange, ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType,
    Checksummer, ContentMd5, ETag, ErrorCode, EtagRender, KeyFloor, LegacyRustfsNameValidator, Md5Digest, NamePolicy,
    NameRejection, NameValidator, ObjectKey, OpaqueString, ParseError, PathSplit, RangeOutcome, RangeParse, RangeSpec,
    RecordedUpload, ResolvedUploadId, SlashPolicy, Stricter, Timestamp, TimestampFormat, UploadIdClaim, UploadRejection,
    aws_bucket_rules, decode_once, floor_check_bucket, floor_check_key, is_xml_representable, names_unknown_checksum_algorithm,
    parse_request_checksum, resolve_upload, rules, validate_bucket_name, validate_object_key,
};
pub use crate::secret::SseCustomerKey;
