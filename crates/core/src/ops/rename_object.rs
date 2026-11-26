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

//! `RenameObject`: one in-bucket object rename on the S3 Express directory-bucket surface.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, S3 Express signature floor, single-pass validation of
//! `x-amz-rename-source` against the shared naming floor and deployment validator, the sealed
//! derived source resource ([`RenameObjectResources`] / [`RenameSource`] /
//! [`ResolvedRenameSource`]), and erasing the raw source field after derivation.
//! NOT responsible for: implementing directory-bucket sessions, moving object state, or
//! evaluating the source/destination conditional headers against stored object metadata.
//! Upstream: the generated `RenameObject` dto and codec, and `rustfs-gateway-types` naming rules.
//! Downstream: routing, two-stage authorization, and handler registration.
//!
//! # Why `x-amz-rename-source` is sealed behind [`crate::AuthorizedRead`]
//!
//! `x-amz-rename-source` names a caller-chosen source object in the same bucket. Authorizing only
//! the destination key lets a caller with permission on the destination move or exfiltrate an
//! unauthorized source object (`GHSA-f4vq-9ffr-m8m3` / `rustfs/gateway#1629`). Here
//! [`RenameObjectResources`] parses and normalizes `x-amz-rename-source` once through
//! [`ObjectKey::materialize`] before input authorization, `seal_derived_input` erases the raw
//! header string from `RenameObjectInput`, and [`RenameSource::resolve`] reveals the normalized
//! source only against an [`crate::AuthorizedRead`] proof covering that exact bucket and key.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{RenameObject, RenameObjectInput, RenameObjectOutput};
use rustfs_gateway_types::{BucketName, ErrorCode, NamePolicy, ObjectKey, WirePlaceholder};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// The IAM action required for the derived `RenameObject` source object.
pub const RENAME_SOURCE_ACTION: &str = "s3express:CreateSession";

/// What this operation requires once routing has selected the directory-bucket rename surface.
static SPEC: OperationSpec = OperationSpec::standard("RenameObject")
    .required_params(&[])
    .auth(AuthRequirement::new(RENAME_SOURCE_ACTION, ResourceShape::Object))
    .build();

/// Rename requests run on the S3 Express directory-bucket surface and carry no request body.
static FLOOR: OperationFloor = OperationFloor::builtin("RenameObject", SigService::S3Express);

/// A rename-source value this gateway refuses, with the S3 error code it renders as.
///
/// The explanation is always a `&'static str` from a closed set so error responses never echo
/// caller-controlled bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameSourceRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl RenameSourceRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// A constant explanation, never assembled from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    const fn new(code: ErrorCode, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

impl core::fmt::Display for RenameSourceRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for RenameSourceRejection {}

/// A parsed and normalized, but not yet authorized, `x-amz-rename-source` object.
///
/// Its bucket and key are private and intentionally do not implement `Debug`. Only
/// [`RenameSource::resolve`] reveals them, and only against an [`crate::AuthorizedRead`] proof
/// that authorized this exact bucket and key.
#[derive(Clone, PartialEq, Eq)]
pub struct RenameSource {
    bucket: BucketName,
    key: ObjectKey,
}

impl RenameSource {
    /// Parses and validates one `x-amz-rename-source` header value under the default
    /// [`NamePolicy`].
    ///
    /// `RenameObject` renames within a single directory bucket, so `bucket` supplies the
    /// validated destination bucket and `raw` names only the URL-encoded source object key.
    ///
    /// # Errors
    ///
    /// Returns [`RenameSourceRejection`] with [`ErrorCode::INVALID_BUCKET_NAME`] if `bucket` is
    /// the empty wire placeholder, [`ErrorCode::KEY_TOO_LONG`] if the decoded key exceeds 1024
    /// UTF-8 bytes, or [`ErrorCode::INVALID_ARGUMENT`] when `raw` fails single-pass
    /// percent-decoding, UTF-8 validation, residual encoded-separator checks, the key safety
    /// floor, or the deployment validator.
    pub fn parse(bucket: &BucketName, raw: &str) -> Result<Self, RenameSourceRejection> {
        Self::parse_under(bucket, raw, &NamePolicy::default())
    }

    /// [`RenameSource::parse`] held to the request's [`NamePolicy`], applying the same single
    /// normalization floor, slash policy, and deployment validator as URI-carried object keys.
    ///
    /// # Errors
    ///
    /// As [`RenameSource::parse`], evaluated under `names`.
    pub fn parse_under(bucket: &BucketName, raw: &str, names: &NamePolicy) -> Result<Self, RenameSourceRejection> {
        if bucket.is_wire_placeholder() {
            return Err(RenameSourceRejection::new(
                ErrorCode::INVALID_BUCKET_NAME,
                "RenameObject destination bucket must not be empty",
            ));
        }
        let key = ObjectKey::materialize(raw, names)
            .map_err(|rejection| RenameSourceRejection::new(rejection.key_error_code(), rejection.reason()))?;
        Ok(Self {
            bucket: bucket.clone(),
            key,
        })
    }

    /// Reveals the normalized source only after the framework authorized every derived resource.
    #[must_use]
    pub fn resolve(&self, proof: &crate::AuthorizedRead) -> Option<ResolvedRenameSource> {
        proof
            .permits(crate::ResourceRef::object(RENAME_SOURCE_ACTION, Some(&self.bucket), &self.key))
            .then(|| ResolvedRenameSource {
                bucket: self.bucket.clone(),
                key: self.key.clone(),
            })
    }
}

/// The single normalized source object derived from `x-amz-rename-source`.
///
/// Intentionally does not implement `Debug`; callers obtain the source through
/// [`RenameObjectResources::source`] and [`RenameSource::resolve`].
#[derive(Clone, PartialEq, Eq)]
pub struct RenameObjectResources {
    source: RenameSource,
}

impl RenameObjectResources {
    /// The sealed rename source. Its bucket and key require [`crate::AuthorizedRead`] to reveal.
    #[must_use]
    pub const fn source(&self) -> &RenameSource {
        &self.source
    }
}

impl crate::DerivedResourceSet for RenameObjectResources {
    fn visit(&self, visitor: &mut dyn FnMut(crate::ResourceRef<'_>)) {
        visitor(crate::ResourceRef::object(
            RENAME_SOURCE_ACTION,
            Some(&self.source.bucket),
            &self.source.key,
        ));
    }
}

/// A rename source the caller has been authorized to access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRenameSource {
    bucket: BucketName,
    key: ObjectKey,
}

impl ResolvedRenameSource {
    /// The directory bucket containing both the source and destination objects.
    #[must_use]
    pub const fn bucket(&self) -> &BucketName {
        &self.bucket
    }

    /// The single-pass normalized source object key.
    #[must_use]
    pub const fn key(&self) -> &ObjectKey {
        &self.key
    }
}

impl Operation for RenameObject {
    const NAME: &'static str = "RenameObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = RenameObjectInput;
    type Output = RenameObjectOutput;
    type DerivedResources = RenameObjectResources;

    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Self::derive_resources_under(input, &NamePolicy::default())
    }

    fn derive_resources_under(
        input: &Self::Input,
        names: &NamePolicy,
    ) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        RenameSource::parse_under(&input.bucket, &input.rename_source, names)
            .map(|source| RenameObjectResources { source })
            .map_err(|error| crate::authz::DerivedResourceError::new(error.code().clone(), error.reason()))
    }

    fn seal_derived_input(input: &mut Self::Input) {
        input.rename_source.clear();
    }

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for RenameObjectInput {
    type Op = RenameObject;
}

#[cfg(test)]
// Test code only. The crate denies these three so no request path can panic.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use rustfs_gateway_types::{NameRejection, NameValidator, SlashPolicy, Stricter};

    use super::*;
    use crate::authz::{Decision, DerivedResourceSet, authorize_input, prepare_input_under};

    struct ForbidPrefix(&'static str);

    impl NameValidator for ForbidPrefix {
        fn check_bucket(&self, _name: &str) -> Stricter {
            Stricter::NoOpinion
        }

        fn check_key(&self, key: &str) -> Stricter {
            if key.starts_with(self.0) {
                Stricter::Reject(NameRejection::rejected_by_validator("key prefix refused by deployment"))
            } else {
                Stricter::NoOpinion
            }
        }
    }

    fn input(bucket: &str, key: &str, rename_source: &str) -> RenameObjectInput {
        RenameObjectInput {
            bucket: BucketName::new(bucket).expect("valid bucket"),
            key: ObjectKey::new(key).expect("valid key"),
            rename_source: rename_source.to_owned(),
            ..Default::default()
        }
    }

    /// Negative — unsafe source spellings fail single-pass normalization before authorization.
    #[test]
    fn n_unsafe_rename_sources_are_rejected_with_closed_codes() {
        let bucket = BucketName::new("directory-bucket").expect("valid bucket");
        let over_raw = "a".repeat(1025);
        let over_decoded = format!("{}%C3%A9", "a".repeat(1023));
        for (raw, expected) in [
            ("", ErrorCode::INVALID_ARGUMENT),
            ("..", ErrorCode::INVALID_ARGUMENT),
            ("../secret", ErrorCode::INVALID_ARGUMENT),
            ("a/../../etc/passwd", ErrorCode::INVALID_ARGUMENT),
            ("a\\..\\secret", ErrorCode::INVALID_ARGUMENT),
            ("%2e%2e/secret", ErrorCode::INVALID_ARGUMENT),
            ("a%2F..%2Fb", ErrorCode::INVALID_ARGUMENT),
            ("%252e%252e/secret", ErrorCode::INVALID_ARGUMENT),
            ("a%252Fb", ErrorCode::INVALID_ARGUMENT),
            ("a%255cb", ErrorCode::INVALID_ARGUMENT),
            ("a%00b", ErrorCode::INVALID_ARGUMENT),
            ("a%01b", ErrorCode::INVALID_ARGUMENT),
            ("a%7Fb", ErrorCode::INVALID_ARGUMENT),
            ("%FF%FE", ErrorCode::INVALID_ARGUMENT),
            ("//server/share", ErrorCode::INVALID_ARGUMENT),
            ("\\server\\share", ErrorCode::INVALID_ARGUMENT),
            ("C:/Windows/win.ini", ErrorCode::INVALID_ARGUMENT),
            ("c:\\boot.ini", ErrorCode::INVALID_ARGUMENT),
            (over_raw.as_str(), ErrorCode::KEY_TOO_LONG),
            (over_decoded.as_str(), ErrorCode::KEY_TOO_LONG),
        ] {
            let Err(err) = RenameSource::parse(&bucket, raw) else {
                panic!("must reject {raw:?}");
            };
            assert_eq!(err.code(), &expected, "raw={raw:?}");
            assert!(!err.reason().is_empty(), "raw={raw:?}");
            assert!(!err.to_string().contains(raw) || raw.is_empty(), "must not echo input: {raw:?}");
        }
    }

    /// Negative — the empty placeholder bucket cannot bind a rename source.
    #[test]
    fn n_placeholder_bucket_is_rejected() {
        let mut bad = input("directory-bucket", "dst.txt", "src.txt");
        bad.bucket = BucketName::default();
        let Err(err) = RenameObject::derive_resources(&bad) else {
            panic!("placeholder bucket must fail");
        };
        assert_eq!(err.code(), &ErrorCode::INVALID_BUCKET_NAME);
    }

    /// Negative — a deployment `NameValidator` refusal rejects `x-amz-rename-source`.
    #[test]
    fn n_custom_validator_refuses_forbidden_rename_source() {
        let policy = NamePolicy::default().with_validator(Arc::new(ForbidPrefix("restricted/")));
        let req = input("directory-bucket", "dst.txt", "restricted/secret.txt");
        let Err(err) = RenameObject::derive_resources_under(&req, &policy) else {
            panic!("validator must refuse");
        };
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
    }

    /// Negative — a proof minted for another bucket or another key never resolves this source.
    #[test]
    fn n_proof_from_other_bucket_or_key_does_not_resolve_source() {
        let policy = NamePolicy::default();
        let first = prepare_input_under::<RenameObject>(input("bucket-a", "dst.txt", "dir/old.txt"), &policy).expect("valid");
        let authorized_a = authorize_input(first, |_| Decision::Allow).expect("allowed");

        let other_bucket =
            RenameSource::parse(&BucketName::new("bucket-b").expect("bucket"), "dir/old.txt").expect("valid source");
        assert!(
            other_bucket.resolve(authorized_a.read_proof()).is_none(),
            "proof for bucket-a must not resolve bucket-b"
        );

        let other_key =
            RenameSource::parse(&BucketName::new("bucket-a").expect("bucket"), "dir/other.txt").expect("valid source");
        assert!(
            other_key.resolve(authorized_a.read_proof()).is_none(),
            "proof for dir/old.txt must not resolve dir/other.txt"
        );
    }

    /// Negative — denying the derived resource prevents obtaining an authorized request.
    #[test]
    fn n_denied_derived_source_refuses_authorization() {
        let decoded =
            prepare_input_under::<RenameObject>(input("bucket-a", "dst.txt", "dir/old%20file.txt"), &NamePolicy::default())
                .expect("valid");
        let mut visited = Vec::new();
        decoded.resources().visit(&mut |resource| {
            visited.push((
                resource.action(),
                resource.bucket().map(BucketName::as_str).map(str::to_owned),
                resource.key().map(ObjectKey::as_str).map(str::to_owned),
            ));
        });
        assert_eq!(
            visited,
            vec![(RENAME_SOURCE_ACTION, Some("bucket-a".to_owned()), Some("dir/old file.txt".to_owned()))]
        );
        assert!(authorize_input(decoded, |_| Decision::Deny).is_err());
    }

    /// Positive — `prepare_input_under` normalizes once, seals the raw header, and resolves with proof.
    #[test]
    fn valid_rename_source_normalizes_seals_and_resolves_with_proof() {
        let policy = NamePolicy::default().with_slash_policy(SlashPolicy::Collapse);
        let decoded = prepare_input_under::<RenameObject>(input("bucket-a", "dst.txt", "/dir//old%20file.txt"), &policy)
            .expect("valid rename");
        let authorized = authorize_input(decoded, |_| Decision::Allow).expect("allowed");
        assert!(
            authorized.input().rename_source.is_empty(),
            "seal_derived_input must erase the raw x-amz-rename-source value"
        );
        let resolved = authorized
            .resources()
            .source()
            .resolve(authorized.read_proof())
            .expect("proof covers derived source");
        assert_eq!(resolved.bucket().as_str(), "bucket-a");
        assert_eq!(resolved.key().as_str(), "dir/old file.txt");
    }

    /// Positive — `KeyFloor::RustfsLegacy` governs `x-amz-rename-source` identically to path keys.
    #[test]
    fn legacy_key_floor_applies_to_rename_source() {
        let policy = NamePolicy::default().with_legacy_rustfs_key_floor();
        let source = RenameSource::parse_under(&BucketName::new("bucket-a").expect("bucket"), "a/../b", &policy)
            .expect("legacy floor admits non-NUL non-empty <=1024 keys");
        let decoded = prepare_input_under::<RenameObject>(input("bucket-a", "dst.txt", "a/../b"), &policy).expect("legacy floor");
        let authorized = authorize_input(decoded, |_| Decision::Allow).expect("allowed");
        let resolved = source.resolve(authorized.read_proof()).expect("resolved under legacy floor");
        assert_eq!(resolved.key().as_str(), "a/../b");
        let Err(nul_err) = RenameSource::parse_under(&BucketName::new("bucket-a").expect("bucket"), "a%00b", &policy) else {
            panic!("NUL stays refused even under legacy floor");
        };
        assert_eq!(nul_err.code(), &ErrorCode::INVALID_ARGUMENT);
    }
}
