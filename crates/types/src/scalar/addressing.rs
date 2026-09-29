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

//! How a path-style request names its bucket under legacy RustFS (rustfs/gateway#1115): where the
//! path is split, and which bucket names legacy RustFS serves.
//!
//! Responsible for: [`PathSplit`], the choice [`super::naming::NamePolicy`] carries, and
//! [`LegacyRustfsNameValidator`], legacy RustFS's bucket naming rules as a validator.
//! NOT responsible for: splitting a path (`rustfs_gateway_core::codec`, which reads the choice), or
//! the bucket floor underneath the validator (`super::naming::floor_check_bucket`).
//! Upstream: `super::naming`. Downstream: the core's path split and every bucket materialisation.

use super::naming::{MAX_BUCKET_BYTES, MIN_BUCKET_BYTES, NameRejection, NameValidator, Stricter};

/// Where a path-style request's bucket ends.
///
/// The default splits the path as it arrived, at its first literal `/`, and decodes each half on
/// its own: `bkt%2Fkey` is one label, the bucket `bkt%2Fkey`, which no naming rule admits. The
/// other value is legacy RustFS's reading, for a deployment in front of RustFS.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum PathSplit {
    /// The first literal `/` ends the bucket; the bucket label is never decoded.
    #[default]
    Literal,
    /// Legacy RustFS's split: the path is decoded once as a whole — an undecodable path is refused
    /// before anything else — and the bucket ends at the first `/` of the decoded path, so
    /// `/bkt%2Fkey` is the key `key` in the bucket `bkt` and `/b%6Bt` the bucket `bkt`.
    ///
    /// Legacy-compat (rustfs/backlog#2684): an escaped separator is data in a URI (RFC 3986 §2.2),
    /// so reading `%2F` between the bucket and the key as the separator gives one object two
    /// spellings a signature covers differently. Kept so a client that escapes the separator keeps
    /// reaching its objects; the intended future behaviour is [`PathSplit::Literal`], with an
    /// escaped bucket segment answered `InvalidBucketName`.
    RustfsLegacy,
}

impl PathSplit {
    /// The identifier a posture report prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::RustfsLegacy => "rustfs-legacy",
        }
    }
}

/// Legacy RustFS's bucket naming rules, for a deployment in front of RustFS: the names it serves
/// and no other.
///
/// A bucket name is 3..=63 bytes of `a-z`, `0-9`, `.` and `-`, starts and ends with a letter or a
/// digit, holds no `..`, is not an IP address as the standard library parses one (so `01.2.3.4`
/// and `256.1.1.1` are names), and does not start with `xn--`. That is the rule legacy RustFS's
/// path parser applies before routing (`check_bucket_name`, reached from
/// `rustfs/src/server/http.rs:1384-1430` on rustfs/rustfs `e870a6d25b`).
///
/// Legacy-compat (rustfs/backlog#2684): it admits the prefixes and suffixes AWS reserves
/// (`sthree-`, `-s3alias`, `--ol-s3`, `--x-s3`) and every dotted-quad spelling the standard parser
/// refuses, all of which legacy RustFS creates or looks up. Kept so no bucket a RustFS client made
/// becomes unreachable; the intended future behaviour is [`super::naming::AwsNameValidator`] for
/// new buckets, once existing ones have been found and renamed.
///
/// Keys are opaque to it: it has no opinion on any key.
#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyRustfsNameValidator;

impl NameValidator for LegacyRustfsNameValidator {
    fn check_bucket(&self, name: &str) -> Stricter {
        match legacy_rustfs_bucket_rules(name) {
            Ok(()) => Stricter::NoOpinion,
            Err(rejection) => Stricter::Reject(rejection),
        }
    }

    fn check_key(&self, _key: &str) -> Stricter {
        Stricter::NoOpinion
    }
}

fn legacy_rustfs_bucket_rules(name: &str) -> Result<(), NameRejection> {
    if name.len() < MIN_BUCKET_BYTES {
        return Err(NameRejection::TooShort);
    }
    if name.len() > MAX_BUCKET_BYTES {
        return Err(NameRejection::TooLong);
    }
    let admitted = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-';
    let edge = |byte: Option<u8>| byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !name.bytes().all(admitted) || !edge(name.bytes().next()) || !edge(name.bytes().next_back()) || name.contains("..") {
        return Err(NameRejection::CharacterSet);
    }
    if name.parse::<std::net::IpAddr>().is_ok() || name.starts_with("xn--") {
        return Err(NameRejection::Reserved);
    }
    Ok(())
}
