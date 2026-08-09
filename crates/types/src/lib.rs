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
//! generated per-operation DTOs plus their XML/header codec impls.
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

pub mod placeholder;
mod scalar;

#[cfg(test)]
mod tests;

/// The generated operation dto, one module per operation.
#[path = "../generated/ops/mod.rs"]
pub mod ops;

/// Flat aliases for every generated type: `dto::PutObjectInput` is `ops::put_object::Input`.
#[path = "../generated/flat.rs"]
pub mod dto;

pub use crate::placeholder::{PlaceholderDefault, WirePlaceholder, reject_placeholder};
pub use crate::scalar::{
    AwsNameValidator, BucketName, ByteRange, ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType,
    Checksummer, ContentMd5, ETag, ErrorCode, ErrorContext, EtagRender, NamePolicy, NameRejection, NameValidator, ObjectKey,
    OpaqueString, ParseError, RangeOutcome, RangeParse, RangeSpec, SlashPolicy, Stricter, Timestamp, TimestampFormat,
    aws_bucket_rules, decode_once, floor_check_bucket, floor_check_key, is_xml_representable, mask_for_authorization,
    parse_request_checksum, rules, status_of, validate_bucket_name, validate_object_key,
};
