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

//! Legacy RustFS's path split (rustfs/gateway#1115): the path decoded as a whole, the bucket ended
//! at the first decoded `/`, and every refusal made before routing, in legacy RustFS's order.
//!
//! Responsible for: [`legacy_rustfs_target`], the classification a RustFS-profile assembly makes
//! before routing, and [`legacy_labels`], the bucket and key [`super::view::MetaView`] reads under
//! the same split. Both go through one [`legacy_split`], so the target routing used and the names
//! the pipeline reads cannot disagree.
//! NOT responsible for: the decode, the slash rule or the floors, which are
//! [`rustfs_gateway_types::ObjectKey::materialize`]'s and [`rustfs_gateway_types::decode_once`]'s,
//! or choosing the split, which [`NamePolicy::path_split`] does.
//! Upstream: `super::view`. Downstream: the gateway service, and every decoder through the view.
//!
//! # Why splitting the raw path is decoding it first
//!
//! A decoded `/` comes from a literal `/` or from `%2F`/`%2f` and from nothing else: percent
//! decoding is one octet per escape, and no byte of a multi-byte UTF-8 sequence is `0x2F`. So the
//! first of those in the raw path is exactly the first `/` of the decoded path, each half can be
//! decoded on its own, and the key half still reaches `ObjectKey::materialize` undecoded and is
//! decoded there exactly once, keeping the spelling a signature covers.

use rustfs_gateway_types::{BucketName, ErrorCode, NamePolicy, NameRejection, ObjectKey, decode_once};

use super::error::CodecError;
use super::view::key_rejected;
use crate::route::TargetKind;

/// How legacy RustFS reads a path-style target, before any name is judged.
enum LegacySplit<'a> {
    /// `/`.
    Service,
    /// The bucket label, still encoded, with no key after it.
    Bucket(&'a str),
    /// The bucket label and the key label, both still encoded.
    Object(&'a str, &'a str),
}

fn legacy_split(path: &str) -> LegacySplit<'_> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    if rest.is_empty() {
        return LegacySplit::Service;
    }
    let separator = ["/", "%2F", "%2f"]
        .into_iter()
        .filter_map(|spelling| rest.find(spelling).map(|at| (at, spelling.len())))
        .min_by_key(|&(at, _)| at);
    match separator {
        None => LegacySplit::Bucket(rest),
        Some((at, len)) if rest[at + len..].is_empty() => LegacySplit::Bucket(&rest[..at]),
        Some((at, len)) => LegacySplit::Object(&rest[..at], &rest[at + len..]),
    }
}

/// The one decode of the whole path, judged before anything else: legacy RustFS answers a path
/// that is not UTF-8 once decoded `400 InvalidURI`, whatever else is wrong with it. The sentence is
/// the one the wire layer already answers an unparseable request target with.
fn decodable(path: &str) -> Result<(), CodecError> {
    decode_once(path)
        .map(drop)
        .map_err(|_| CodecError::new(ErrorCode::INVALID_URI, "Couldn't parse the specified URI."))
}

/// The key checks legacy RustFS makes before routing: its length once the slash rule has run, and
/// nothing else. Every other rule — a NUL, and whatever the key floor refuses — is the view's,
/// after routing, as RustFS's own storage refuses those keys after routing too.
fn legacy_key_length(label: &str, names: &NamePolicy) -> Result<(), CodecError> {
    match ObjectKey::materialize(label, names) {
        Err(NameRejection::TooLong) => Err(key_rejected(NameRejection::TooLong)),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// A bucket label, decoded, under the deployment's naming rules.
fn legacy_bucket(label: &str, names: &NamePolicy) -> Result<BucketName, CodecError> {
    let invalid = || CodecError::new(ErrorCode::INVALID_BUCKET_NAME, "The specified bucket is not valid").about("Bucket");
    let decoded = decode_once(label).map_err(|_| invalid())?;
    BucketName::materialize(&decoded, names).map_err(|_| invalid())
}

/// The target a RustFS-profile assembly routes a request under, and every refusal legacy RustFS
/// makes before routing: `InvalidURI` for a path that is not UTF-8 once decoded, then
/// `InvalidBucketName` for an empty or refused bucket segment, then `KeyTooLongError` for a key
/// over 1024 bytes once the slash rule has run. Nothing else about the key is judged here.
///
/// `host_named_bucket` is whether a virtual host named the bucket, which makes the whole path the
/// key: `/` is then the bucket and anything else an object.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS judges the path before it knows the
/// operation, so `PATCH /Bad_Bucket/k` is `InvalidBucketName` rather than `501`, and an empty
/// bucket segment (`GET //bkt`) is `InvalidBucketName` rather than the service root. Kept so a
/// RustFS client sees the answers it sees today; the intended future behaviour is the core
/// default, routing first.
///
/// # Errors
///
/// The [`CodecError`] legacy RustFS answers with, as above.
pub fn legacy_rustfs_target(path: &str, host_named_bucket: bool, names: &NamePolicy) -> Result<TargetKind, CodecError> {
    decodable(path)?;
    if host_named_bucket {
        let key = path.strip_prefix('/').unwrap_or(path);
        if key.is_empty() {
            return Ok(TargetKind::Bucket);
        }
        legacy_key_length(key, names)?;
        return Ok(TargetKind::Object);
    }
    match legacy_split(path) {
        LegacySplit::Service => Ok(TargetKind::Service),
        LegacySplit::Bucket(label) => legacy_bucket(label, names).map(|_| TargetKind::Bucket),
        LegacySplit::Object(bucket, key) => {
            legacy_bucket(bucket, names)?;
            legacy_key_length(key, names)?;
            Ok(TargetKind::Object)
        }
    }
}

/// The bucket and key a path-style request names under legacy RustFS's split, for the target
/// routing chose: the view's reading under [`rustfs_gateway_types::PathSplit::RustfsLegacy`].
pub(super) fn legacy_labels(
    path: &str,
    target: TargetKind,
    names: &NamePolicy,
) -> Result<(Option<BucketName>, Option<ObjectKey>), CodecError> {
    match (target, legacy_split(path)) {
        (TargetKind::Service, _) | (_, LegacySplit::Service) => Ok((None, None)),
        (TargetKind::Bucket, LegacySplit::Bucket(label)) => Ok((Some(legacy_bucket(label, names)?), None)),
        // Routing chose a bucket operation for a path that names a key: the classification it was
        // given disagrees with this split, and neither reading is handed on.
        (TargetKind::Bucket, LegacySplit::Object(..)) => {
            Err(CodecError::new(ErrorCode::INVALID_BUCKET_NAME, "The specified bucket is not valid").about("Bucket"))
        }
        (TargetKind::Object, LegacySplit::Object(bucket, key)) => {
            let bucket = legacy_bucket(bucket, names)?;
            let key = ObjectKey::materialize(key, names).map_err(key_rejected)?;
            Ok((Some(bucket), Some(key)))
        }
        (TargetKind::Object, LegacySplit::Bucket(_)) => {
            Err(CodecError::invalid_argument("the request path names no object key").about("Key"))
        }
    }
}

#[cfg(test)]
#[path = "tests/legacy_path.rs"]
mod tests;
