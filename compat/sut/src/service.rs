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
//! the operation set it really registers, and building the `S3Service` that `main` serves — the
//! RustFS profile applied whole through `ServiceBuilder::rustfs_profile` and
//! `SigV4Authenticator::rustfs_profile`, with every configured identity registered for signing and
//! the bucket-owner registry installed as both the authorizer and the `BucketOwnerSource`.
//! NOT responsible for: binding a socket (`main`), storing anything (`rustfs-gateway-fs`),
//! deciding who owns what (`crate::ownership`), or which readings the profile is made of
//! (`rustfs-gateway`'s `builder/rustfs_profile.rs` and `docs/rustfs-profile.md`; the posture golden
//! this assembly is held to is `crates/gateway/tests/golden/rustfs-profile-posture.txt`).
//! Upstream: `crate::Options`. Downstream: `main`, and the tests in `service/tests.rs`, which drive signed
//! requests through **this** function rather than through an assembly of their own — an assembly
//! written for a test proves nothing about the one the suites are pointed at.

use std::io;
use std::sync::Arc;

use rustfs_gateway::{
    CorsCacheConfig, Credentials, DEFAULT_MAX_BUFFERED_BODY_BYTES, HandlerDeadlineClass, HandlerDeadlineConfig,
    LegacyRustfsVirtualHosts, MintedTraces, RegionMatchPolicy, RegionSet, RequestBodyDeadlineConfig, S3Service, ServiceBuilder,
    ServiceConfig, SigV4Authenticator, SseConfig, StaticCredentials, dto,
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
        // RustFS ignores a creation's `LocationConstraint` — minio-java's explicit us-east-1
        // included — and creates the bucket in its own region; so does this launcher (#914).
        .with_region_match_policy(RegionMatchPolicy::IgnoreConstraint)
        .with_owner(owner_id, display_name)
        // RustFS's storage answers a batch delete's key it cannot hold, or whose segment its disk
        // cannot name, on its own and deletes the rest; every other operation is refused in front
        // of the backend (#1145, #1153).
        .refusing_batch_deletes_of(crate::storage_names::rustfs_storage_or_disk_refuses)
        // Legacy RustFS judges `If-Match` on a delete against the version it would remove
        // (`opts.precondition_check(&goi)`, `crates/ecstore/src/set_disk/ops/object.rs:8951` on
        // rustfs/rustfs 3268c42e00; measured on `528a36814`): another tag is `412` (#1191).
        .evaluating_delete_if_match()
        // Legacy RustFS answers an object's tag set sorted by key (`decode_tags`,
        // `crates/ecstore/src/bucket/tagging/mod.rs:20-43` on rustfs/rustfs 3268c42e00; measured on
        // `528a36814`: `foo=bar&bar` reads back `bar`, `foo`) (#1000).
        .sorting_object_tags()
        // Legacy RustFS keeps the last entry a completion names for each part number, then requires
        // the kept list to be strictly increasing (`normalize_complete_multipart_parts`,
        // `rustfs/src/app/multipart_usecase.rs:177-208` on rustfs/rustfs 3268c42e00; measured on
        // `528a36814`: part 1 named twice completes with its last upload) (#1002).
        .normalizing_completed_parts()
        // Legacy RustFS drops `aws-chunked` from a stored `Content-Encoding`, framed body or not
        // (`normalize_content_encoding_for_storage`, `rustfs/src/storage/options.rs:664-681` on
        // rustfs/rustfs 3268c42e00; measured on `528a36814`: `gzip, aws-chunked` over a plain body
        // answers `gzip`) (#1203).
        .normalizing_content_encoding();
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

/// The request settings of the RustFS profile: no framework deadline anywhere.
///
/// Legacy RustFS runs a handler until it finishes or its connection goes away: its external S3
/// middleware stack has no timeout layer (`rustfs/src/server/http.rs:2044-2072` on rustfs/rustfs
/// `1e7065101d`), and it reads the body of every operation the gateway serves with no deadline —
/// its one body idle bound, `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`, sits inside RustFS's own
/// `PutObject` and `UploadPart` handlers (`rustfs/src/app/object/put.rs:127-160`), which keep
/// applying it behind the gateway. Every framework deadline is therefore lifted, which arms no
/// timer at all (ADR-0034, rustfs/gateway#1070); everything else is the builder's default.
///
/// Legacy-compat (rustfs/backlog#2684): with no handler, committed-continuation or body deadline,
/// a stuck backend call or a client that stalls mid-body holds its task and buffers until the
/// connection drops. The intended behaviour is bounds taken from RustFS configuration, applied
/// the same way to both stacks.
pub(crate) fn rustfs_service_config() -> Result<ServiceConfig, Box<dyn std::error::Error>> {
    let handler = HandlerDeadlineConfig::default()
        .without_deadline(HandlerDeadlineClass::Standard)
        .without_deadline(HandlerDeadlineClass::Extended)
        .without_commit_progress_deadline();
    let body = RequestBodyDeadlineConfig::S3
        .without_idle_deadlines()
        .without_throughput_floor();
    Ok(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES)
        .with_handler_deadlines(handler)
        .with_request_body_deadlines(body))
}

/// RustFS's single-request ceiling on an upload's object: 5 GiB (`MAX_SINGLE_PUT_OBJECT_SIZE`,
/// `crates/config/src/constants/body_limits.rs:73` on rustfs/rustfs `e870a6d25b`).
pub(crate) const RUSTFS_MAX_SINGLE_UPLOAD_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The acceptance-layer ceilings of the RustFS profile: the defaults, with the declared-length
/// ceiling widened to the framing an aws-chunked upload of RustFS's largest object may carry.
///
/// RustFS refuses a `PutObject` or `UploadPart` whose object is larger than 5 GiB with `400
/// EntityTooLarge` before reading its body, and measures an aws-chunked upload by its decoded
/// length, so a 5 GiB streaming upload whose framed `Content-Length` is larger is stored
/// (`rustfs/src/server/http.rs:170`, rustfs/rustfs#7635). The wire's declared-length ceiling counts
/// the framing, so at its 5 GiB default it refused that upload; `build_service` sets the object
/// ceiling itself with `ServiceConfig::with_upload_object_ceiling`.
pub(crate) fn rustfs_limits() -> rustfs_gateway::Limits {
    rustfs_gateway::Limits {
        max_body_bytes: rustfs_gateway::max_framed_upload_bytes(RUSTFS_MAX_SINGLE_UPLOAD_BYTES),
        ..rustfs_gateway::Limits::default()
    }
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
            // The whole RustFS profile, in one reviewable place (rustfs/backlog#2751): every
            // legacy RustFS reading of a request, a credential scope and an answer, the security
            // floor's delegation and presigned widenings, and the lifted framework governor. What
            // each switch keeps, and where rustfs/backlog#2684 registers it, is the table in
            // `rustfs-gateway`'s `builder/rustfs_profile.rs` and `docs/rustfs-profile.md`; the
            // posture this assembly reports is held to the gateway's golden by
            // `service/tests/rustfs_profile_tests.rs`. Everything below the two halves is the
            // host's: its credentials, its authorizer, its sources and its settings.
            .rustfs_profile()
            .authenticator(
                SigV4Authenticator::new(Arc::new(credentials), RegionSet::new([options.region.clone()])?).rustfs_profile(),
            )
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
            // The same registry answers `x-amz-expected-bucket-owner`, so the owner id a caller
            // asserts is the very id the authorization decision was made against.
            .bucket_owner_source(Arc::clone(owners))
            // RustFS's transport gate, with TLS required for customer keys
            // (`RUSTFS_SSE_C_REQUIRE_TLS`), refuses both the target's and the copy source's key over
            // cleartext (rustfs/backlog#1677, R11); whether TLS is required at all is a deployment
            // choice the bridge takes from that variable, so it stays outside the profile. Its
            // default, TLS not required, serves both with a warning.
            .sse_config(SseConfig::strict())
            // RustFS reads virtual hosts against `RUSTFS_SERVER_DOMAINS`, ports ignored, the whole
            // prefix as the bucket and a CNAME-style fallback; none configured reads every request
            // path-style (#1136).
            .host_resolver(LegacyRustfsVirtualHosts::new(&options.server_domains)?)
            // The backend's stored CORS documents feed the gateway's CORS answers, as RustFS's do
            // behind the gateway; no cache lifetime, so a suite sees a `PutBucketCors` at once.
            .cors_source(Arc::clone(backend))
            .cors_cache(CorsCacheConfig {
                entries: 4096,
                ttl_seconds: 0,
                jitter_seconds: 0,
            })
            // No host stands in front of this launcher to hand its identifier over, so the
            // identifier is minted in RustFS's shape (ruling R10).
            .trace_source(MintedTraces::with_uuid_request_ids())
            // And the same registry decides whether a name is taken: another identity's
            // re-creation is `409 BucketAlreadyExists` before the backend is asked, and a
            // creation the backend admitted is what gets recorded.
            .op_layer::<dto::CreateBucket, _>(TakenNames::new(Arc::clone(owners), options.accounts.clone()))
            // And released once the backend deleted the bucket, so the name is free again.
            .op_layer::<dto::DeleteBucket, _>(ReleasedNames::new(Arc::clone(owners))),
    );
    // RustFS's storage refuses a key or a listing prefix with a `.` or `..` segment, `//` or a NUL,
    // in its handlers and mostly after the bucket lookup; this backend would store them, so the
    // launcher answers them as RustFS does before the backend is reached (#1145).
    let builder = crate::storage_names::refuse_where_rustfs_storage_does(builder, backend);
    // No framework deadline, as RustFS runs none; RustFS's ceiling on an upload's object, and the
    // wire ceiling widened to the framing that object may carry.
    let settings = rustfs_service_config()?.with_upload_object_ceiling(RUSTFS_MAX_SINGLE_UPLOAD_BYTES);
    let (builder, _settings) = builder.limits(rustfs_limits()).config(settings);
    let service = backend
        .register_cors(backend.register_encryption(backend.register_policy(backend.register_acl(
            backend.register_tagging(
                backend.register_lifecycle(
                    backend.register_listing(backend.register_versioning(backend.register_multipart(builder))),
                ),
            ),
        ))))
        .build()?;
    Ok(service)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
