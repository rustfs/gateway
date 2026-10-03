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
    CorsCacheConfig, Credentials, DEFAULT_MAX_BUFFERED_BODY_BYTES, HandlerDeadlineClass, HandlerDeadlineConfig,
    LegacyRustfsVirtualHosts, MintedTraces, PlaintextCustomerKeyAck, RegionMatchPolicy, RegionSet, RequestBodyDeadlineConfig,
    S3Service, SecurityFloor, ServiceBuilder, ServiceConfig, SigV4Authenticator, SlashPolicy, SseConfig, StaticCredentials, dto,
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

/// The framework governor's rates in the RustFS profile: no limit on any layer.
///
/// Legacy RustFS applies no pre-authentication limit of its own. Its optional per-client limit
/// (`RUSTFS_API_RATE_LIMIT_*`, off by default) is a host layer in front of both stacks, so the
/// framework's layers must not refuse anything legacy RustFS answers (rustfs/gateway#1067): every
/// layer is lifted with `Rate::unlimited()`, which admits without counting, keeps no address
/// entry, and is named in the start-up posture. The address table keeps its shipped bound; it is
/// memory, not a rate, and an unlimited per-client layer never fills it.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS verifies every signature it is sent, with no
/// bound on how many failed verifications or credential lookups one caller can force, and serves
/// anonymous requests with no pre-authentication bound either. That leaves forged-signature floods
/// limited only by CPU. The intended behaviour is a bounded `credential_lookup` class (a verified
/// request already returns its charge, so the bound would only count failed and in-flight work)
/// with its refill above `per_ip`'s, taken from RustFS configuration.
pub(crate) fn rustfs_governor_rates() -> rustfs_gateway::GovernorRates {
    let unlimited = rustfs_gateway::Rate::unlimited();
    rustfs_gateway::GovernorRates {
        aggregate: unlimited,
        per_ip: unlimited,
        credential_lookup: unlimited,
        cors_preflight: unlimited,
        unauthenticated: unlimited,
        tracked_clients: rustfs_gateway::GovernorRates::default().tracked_clients,
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
            // RustFS verifies a signature whatever region its scope names, an empty one included
            // (its replication client signs with one): ADR-0023's any-region grammar plus the empty
            // region, rustfs/backlog#1677.
            .authenticator(
                SigV4Authenticator::new(Arc::new(credentials), RegionSet::new([options.region.clone()])?)
                    .accept_any_signing_region()
                    .accept_empty_signing_region()
                    // And it refuses a region outside its grammar only after the signature, with
                    // `InvalidRequest` (rustfs/gateway#1075).
                    .refuse_unreadable_signing_regions_after_verification()
                    // At any length: its parser has no ceiling on the region.
                    .accept_signing_regions_of_any_length()
                    // It verifies a path's wire spelling only when the path carries an unencoded
                    // byte, such as a raw `=` (rustfs/rustfs#2593).
                    .verify_raw_paths_only_with_unencoded_bytes()
                    // It verifies an `s3`, `sts` or `s3tables` scope on every operation, and answers
                    // any other service with its `501` (rustfs/gateway#1130).
                    .accept_legacy_rustfs_signing_services()
                    // And it answers a scope date other than the signed day, and a region outside
                    // its grammar, with its own code and sentence (rustfs/gateway#1130).
                    .answer_credential_scope_refusals_as_legacy_rustfs()
                    // It reads `SignedHeaders` verbatim, and answers a list that does not cover
                    // what it must in its own words (rustfs/gateway#1130).
                    .read_signed_headers_as_legacy_rustfs(),
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
            // An anonymous request reaches the authorizer instead of being refused per operation
            // (ADR-0021): RustFS decides every request by policy, and a public bucket policy is
            // how a suite grants the public a read. The authorizer still refuses an anonymous
            // request the stored policy does not allow, and a bucket without a policy refuses
            // every one. RustFS also accepts SigV2 presigned URLs (`s3cmd signurl`) today (#913).
            .security_floor(
                SecurityFloor::new()
                    .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                    .enable_sigv2_presigned_compatibility()
                    // RustFS reads a presigned lifetime its own way: `X-Amz-Expires` as a Rust
                    // `u32` with `0` allowed, SigV2 `Expires` with no seven-day ceiling
                    // (rustfs/rustfs#5368); the posture report names the rule.
                    .with_presigned_expiry_rule(rustfs_gateway::PresignedExpiryRule::LegacyRustfs)
                    // RustFS verifies a presigned URL on every operation and authorizes it as it
                    // authorizes a header signature (rustfs/gateway#1052).
                    .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                    // And it reads a query string or a form as signed only when it carries the
                    // signature; the rest is anonymous (rustfs/gateway#1130).
                    .recognize_signatures_as_legacy_rustfs(),
            )
            // Sized as the RustFS bridge sizes it: no framework layer refuses what RustFS answers.
            .framework_governor_rates(rustfs_governor_rates())
            // The same registry answers `x-amz-expected-bucket-owner`, so the owner id a caller
            // asserts is the very id the authorization decision was made against.
            .bucket_owner_source(Arc::clone(owners))
            // RustFS requires an integrity claim on no request body: the MinIO SDKs' checksum-less
            // policy and versioning writes (#916), s3cmd's ACL writes (#912) and every other
            // write the AWS model marks checksum-required are served without one
            // (rustfs/backlog#1677, R5). A claim that is sent is still compared.
            .accept_all_checksum_omissions()
            // RustFS lowers an oversized `max-keys` to a thousand on every listing rather than
            // refusing it; Hadoop S3A pages at 5000 (rustfs/backlog#1677).
            .clamp_oversized_max_keys()
            // RustFS encodes a listing under `encoding-type=url` its own way: only exactly `url`,
            // only some members, `/` kept literal (rustfs/gateway#1059).
            .url_encode_listings_like_rustfs()
            // RustFS's transport gate, with TLS required for customer keys
            // (`RUSTFS_SSE_C_REQUIRE_TLS`), refuses the target's key over cleartext and serves a
            // copy source's (rustfs/backlog#1677, R11). Its default, TLS not required, serves both
            // with a warning; the bridge picks one of the two from that variable.
            .sse_config(SseConfig::refusing_only_target_keys_over_plaintext(
                PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
            ))
            // RustFS refuses an anonymous aws-chunked upload rather than decoding it (#1060), so
            // nothing reaches storage through the launcher that RustFS would not write.
            .leave_anonymous_streaming_payloads_undecoded()
            // RustFS signs every presigned request over `UNSIGNED-PAYLOAD` and verifies a digest the
            // request declares against the body instead (rustfs/rustfs#2379).
            .sign_presigned_payloads_as_unsigned()
            // RustFS signs a header-signed payload digest given in base64 as its hex, and holds the
            // body to the digest either way (rustfs/gateway#1130).
            .sign_base64_payload_digests_as_hex()
            // RustFS refuses a header signature before its credential lookup in its own order and
            // words, and takes the timestamp from `x-amz-date` alone (rustfs/gateway#1130).
            .answer_header_signatures_as_legacy_rustfs()
            // And a presigned URL, the same way (rustfs/gateway#1130).
            .answer_presigned_urls_as_legacy_rustfs()
            // RustFS answers an unreadable or mismatched request checksum with `BadDigest`
            // (rustfs/gateway#1057).
            .answer_checksum_failures_with_bad_digest()
            // RustFS answers a refused HEAD with no Content-Length (rustfs/gateway#1120).
            .answer_head_refusals_without_content_length()
            // RustFS answers a `304` with its object's `ETag` and `Last-Modified` on a `GET` and with
            // no header of the object on a `HEAD` (rustfs/gateway#1120).
            .answer_not_modified_with_legacy_rustfs_headers()
            // RustFS ignores a checksum header naming an algorithm it does not know, and stores the
            // body; every claim it can verify is still compared (rustfs/backlog#1677).
            .ignore_unknown_checksum_algorithms()
            // RustFS reads a request document against its shape and refuses an unknown nested
            // element, a repeated member and a value its grammar does not read, with `MalformedXML`
            // (rustfs/gateway#1078), so the launcher stores no configuration RustFS would refuse.
            .read_request_documents_as_rustfs()
            // RustFS never compares the signed digest of a request without a body: a read or delete
            // declaring another payload's digest is served (rustfs/gateway#1099).
            .accept_mismatched_payload_digests_without_a_body()
            // Nor does it read the body such a request carries: a read, delete, copy or multipart
            // creation sent a body is answered as without one, whatever the body declares, and the
            // body is never polled (rustfs/gateway#1173).
            .leave_bodies_of_bodyless_operations_unread()
            // And it refuses a buffered write it cannot size: a signed one over a chunked transfer
            // before reading it, and one decoded from aws-chunked framing or carried without a
            // length once read (rustfs/gateway#1173).
            .refuse_unsized_buffered_bodies_as_legacy_rustfs()
            // RustFS decodes aws-chunked framing with no bound on chunk count or framing share and
            // takes a chunk past 1 MiB, as a client streaming a whole buffer sends it; the profile
            // takes chunks up to this crate's 16 MiB residency bound (rustfs/gateway#1173).
            .read_aws_chunks_as_legacy_rustfs()
            // RustFS refuses a request to its admin surface declaring more than 1 MiB before its
            // access check; this launcher claims no admin route, so the switch is the profile's
            // record for the bridge (rustfs/gateway#1173).
            .bound_claimed_route_bodies_as_legacy_rustfs()
            // RustFS, built with MinIO support, reads a versioning or object-lock body that is the
            // bare word `Enabled` as the document it stands for (rustfs/backlog#1677, R6).
            .accept_minio_body_literals()
            // RustFS refuses a swapped SigV4 algorithm token, an unreadable SigV4 header and an
            // unsigned `x-amz-*` header before it routes the request, with its own answers
            // (GHSA-xm99, GHSA-g8w9; rustfs/gateway#1120).
            .refuse_unsigned_amz_headers_before_routing()
            // RustFS answers a body refusal with the fixed sentence its API layer writes for the
            // code, and an upload declared past 5 GiB with its admission's (rustfs/gateway#1099).
            .answer_body_refusals_with_legacy_rustfs_sentences()
            // RustFS words its two credential refusals itself: a signature that does not match
            // and an access key nobody issued each carry RustFS's own sentence (rustfs/gateway#1120).
            .answer_credential_refusals_with_legacy_rustfs_sentences()
            // RustFS folds the slashes of a key only when the key starts with one: `/b//x` stores
            // `x` and `/b/a//b` reaches storage as `a//b` (#1101).
            .slash_policy(SlashPolicy::RustfsLegacy)
            // RustFS stores an upload the transport ended empty without `Content-Length` as an
            // empty object instead of answering `411` (rustfs/rustfs#6849).
            .accept_empty_uploads_without_content_length()
            // RustFS reads a conditional date in one spelling and refuses the rest, minio-js's
            // `Invalid Date` included, where the core ignores it (rustfs/backlog#1677, R14).
            .refuse_unreadable_date_conditions()
            // RustFS writes a response document's members in its own declaration order, with no
            // line end after the XML declaration and no namespace on a payload root
            // (rustfs/gateway#1078), so a client reads the bytes it reads from RustFS.
            .write_responses_as_rustfs()
            // RustFS reads an HTTP/1 body its answer left unread and closes the connection behind
            // it, bounded by its 300-second body idle timeout (rustfs/rustfs#7019,
            // rustfs/gateway#1120).
            .drain_unread_request_bodies(rustfs_gateway::UnreadBodyDrain::with_idle_timeout(std::time::Duration::from_secs(300)))
            // RustFS's protocol front hands its storage every key up to 1024 bytes and its storage
            // decides; this backend hashes keys onto the disk, so no key reaches it as a path
            // (#1107).
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
            // RustFS decodes the whole path before it splits the bucket, judges the bucket by its
            // own rules before routing, and reads `GET //` as `GET /` (#1115).
            .address_paths_as_legacy_rustfs()
            // RustFS takes an `x-id` as the operation and orders two operation keys by its own
            // table (#1127).
            .select_operations_as_legacy_rustfs()
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
            // And RustFS answers CORS from them itself, in a layer in front of its S3 stack: every
            // `OPTIONS` before routing, every other answer decorated, refusals included — all but
            // the credentials legacy RustFS allows (rustfs/gateway#1120). No
            // `RUSTFS_CORS_ALLOWED_ORIGINS` fallback, as RustFS runs by default.
            .answer_cors_as_legacy_rustfs(rustfs_gateway::LegacyRustfsCors::with_fallback_origins(None))
            // RustFS reads a browser upload form with its legacy grammar, and stores from it what
            // legacy RustFS stores or refuses it (ruling R8 of rustfs/backlog#1677).
            .legacy_rustfs_post_forms()
            // RustFS answers a policy write `204`, every restore `200`, a policy read untyped, and
            // a HeadBucket without a region its handler left unnamed (rustfs/gateway#1148).
            .answer_heads_as_legacy_rustfs()
            // RustFS reads an optional header whose one line is empty as absent: an empty expected
            // owner, digest, checksum or SSE header claims nothing (rustfs/gateway#1087).
            .read_empty_headers_as_absent()
            // RustFS names an S3 answer's request with one server-owned UUID in `x-amz-request-id`
            // and `x-request-id`, writes no `x-amz-id-2`, and names no request in an error document
            // (rustfs/rustfs `e870a6d25b`, `rustfs/src/server/layer.rs:364-367`,
            // `rustfs/src/storage/request_context.rs:121-123`; ruling R10). No host stands in front
            // of this launcher to hand its identifier over, so the identifier is minted in RustFS's
            // shape.
            .identify_requests_as_legacy_rustfs()
            .trace_source(MintedTraces::with_uuid_request_ids())
            // RustFS asks a `HEAD`, tag or ACL request naming a version its unversioned action, and
            // `GetObject` and `DeleteObject` the version action (GHSA-3ppv).
            .authorize_versions_as_legacy_rustfs()
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
