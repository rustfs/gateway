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
//! Upstream: `s3gate-xml`, `s3gate-stream`. Downstream: `s3gate-http` and everything above.
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
//! Constructing a dto: public fields plus `..Default::default()`, or the per-operation builder.
//! Never destructure one exhaustively — see ADR-0004 P1 and P3 for why that is the only usage a
//! new model member breaks.
#![forbid(unsafe_code)]

mod scalar;

#[cfg(test)]
mod tests;

/// The generated operation dto, one module per operation.
#[path = "../../../generated/dto/ops/mod.rs"]
pub mod ops;

/// Flat aliases for every generated type: `dto::PutObjectInput` is `ops::put_object::Input`.
#[path = "../../../generated/dto/flat.rs"]
pub mod dto;

pub use crate::scalar::{
    BucketName, ByteRange, ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType, Checksummer, ContentMd5,
    ETag, ErrorCode, ErrorContext, EtagRender, ObjectKey, OpaqueString, ParseError, RangeOutcome, RangeParse, Timestamp,
    TimestampFormat, mask_for_authorization, parse_request_checksum, rules, status_of, validate_bucket_name, validate_object_key,
};
