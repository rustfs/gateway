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

//! The one assembly of the system under test, and the evidence that it is the one that runs.
//!
//! Responsible for: opening the reference backend with the configured lifecycle cadence, reading
//! the operation set it really registers, and building the `S3Service` that `main` serves — with
//! every configured identity registered for signing, the bucket-owner registry installed as both
//! the authorizer and the `BucketOwnerSource`.
//! NOT responsible for: binding a socket (`main`), storing anything (`rustfs-gateway-fs`), or
//! deciding who owns what (`crate::ownership`).
//! Upstream: `crate::Options`. Downstream: `main`, and the tests in `service/tests.rs`, which drive signed
//! requests through **this** function rather than through an assembly of their own — an assembly
//! written for a test proves nothing about the one the suites are pointed at.

use std::io;
use std::sync::Arc;

use rustfs_gateway::{
    Credentials, RegionMatchPolicy, RegionSet, S3Service, SecurityFloor, ServiceBuilder, SigV4Authenticator, StaticCredentials,
    dto,
};
use rustfs_gateway_fs::FsBackend;

use crate::Options;
use crate::ownership::{BucketOwners, ReleasedNames, TakenNames};
use crate::policy_authorizer::PolicyAuthorizer;

/// Opens the reference backend, applying the configured lifecycle debug cadence when there is one.
///
/// # Errors
///
/// Any I/O error from opening the data root, and an invalid-input error for an unusable interval.
/// The configured region is handed to the backend as well as to the authenticator: it is what
/// `HeadBucket` and `GetBucketLocation` report, and a deployment whose signer and whose backend
/// disagreed about where its buckets are would answer a client two different regions depending on
/// which it asked first. The primary configured account is the owner of this single-tenant data
/// root, so that same id and display name are installed once for every listing response.
pub(crate) fn open_backend(options: &Options) -> io::Result<FsBackend> {
    let (owner_id, display_name) = options.accounts.data_root_owner();
    let backend = FsBackend::open(&options.data)?
        .with_region(&options.region)?
        // As RustFS does, accept the explicit us-east-1 minio-java's `makeBucket` writes (#914).
        .with_region_match_policy(RegionMatchPolicy::AcceptExplicitUsEast1)
        .with_owner(owner_id, display_name);
    match options.lifecycle_debug_interval {
        Some(interval) => backend.with_lifecycle_debug_interval(interval),
        None => Ok(backend),
    }
}

/// The operation names the assembled service really registers.
///
/// This is the capability boundary the matrix consults: a scenario needing an operation absent
/// from this list is recorded as `unsupported` with that operation named, never as a pass and
/// never as a failure. It is read from the backend rather than written down twice, so the
/// declared boundary cannot drift away from the registry.
pub(crate) fn capability_names(backend: &FsBackend) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = backend.supported_operations().collect();
    names.sort_unstable();
    names
}

/// Assembles the served service from the configured identities and the bucket-owner registry.
///
/// # Errors
///
/// An invalid credential, an unusable region, or an incomplete operation registry.
pub(crate) fn build_service(
    options: &Options,
    backend: &Arc<FsBackend>,
    owners: &Arc<BucketOwners>,
) -> Result<S3Service, Box<dyn std::error::Error>> {
    let mut credentials = StaticCredentials::new();
    for account in options.accounts.all() {
        credentials = credentials.with(Credentials::new(&account.access_key, account.secret_key.as_bytes())?);
    }
    let supported = capability_names(backend);
    let builder = backend.register_crud(
        ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(Arc::new(credentials), RegionSet::new([options.region.clone()])?))
            // Not an allow-all, and not a bare operation-set filter either: the matrix must see a
            // refusal for anything outside the reference backend's registered set, and the
            // external suites must see one identity refused on another identity's bucket, unless
            // the bucket's stored policy allows it. Ownership is `crate::ownership::decide`; the
            // policy is the second word, evaluated as RustFS evaluates one.
            .authorizer(PolicyAuthorizer::new(
                Arc::clone(backend),
                Arc::clone(owners),
                options.accounts.clone(),
                supported,
            ))
            // An anonymous request reaches the authorizer instead of being refused per operation
            // (ADR-0021): RustFS decides every request by policy, and a public bucket policy is
            // how a suite grants the public a read. The authorizer still refuses an anonymous
            // request the stored policy does not allow, and a bucket without a policy refuses
            // every one. RustFS also accepts SigV2 presigned URLs (`s3cmd signurl`) today (#913).
            .security_floor(
                SecurityFloor::new()
                    .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                    .enable_sigv2_presigned_compatibility(),
            )
            // The same registry answers `x-amz-expected-bucket-owner`, so the owner id a caller
            // asserts is the very id the authorization decision was made against.
            .bucket_owner_source(Arc::clone(owners))
            // RustFS accepts the MinIO SDKs' checksum-less policy and versioning writes (#916) and
            // s3cmd's checksum-less ACL writes (#912), and so must the launcher that stands for it.
            .accept_minio_client_checksum_omissions()
            .accept_s3cmd_acl_checksum_omissions()
            // And the same registry decides whether a name is taken: another identity's
            // re-creation is `409 BucketAlreadyExists` before the backend is asked, and a
            // creation the backend admitted is what gets recorded.
            .op_layer::<dto::CreateBucket, _>(TakenNames::new(Arc::clone(owners), options.accounts.clone()))
            // And released once the backend deleted the bucket, so the name is free again.
            .op_layer::<dto::DeleteBucket, _>(ReleasedNames::new(Arc::clone(owners))),
    );
    let service =
        backend
            .register_encryption(backend.register_policy(backend.register_acl(backend.register_tagging(
                backend.register_lifecycle(
                    backend.register_listing(backend.register_versioning(backend.register_multipart(builder))),
                ),
            ))))
            .build()?;
    Ok(service)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
