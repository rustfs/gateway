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

//! PutObject decode: every known divergence between the gateway and the pinned s3s, as a named test.
//!
//! Responsible for: pinning, one test per request shape, what each stack does where they differ,
//! so none of them hides inside a generator that was narrowed around it. Each test's doc carries
//! the id of its ruling in the migration register
//! (`migration_inventory/request_divergences.rs`), and that register's guard refuses a test here
//! without one.
//! NOT responsible for: the zero-diff proofs, the property or the census (`super`), or deciding
//! a ruling (the register does).
//! Upstream: the decode harness in `super`. Downstream: the request-divergence register.

use std::sync::Arc;

use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_dialect_minio::PutObjectReplica;

use rustfs_gateway_types::compat::OracleRevision;

use super::super::SEAM_REVISION;
use super::super::seam::put_object::{input_to_s3s, replica_input_to_s3s};
use super::super::{BodyProbe, RawRequest, gateway_decode, gateway_decode_replica, oracle};
use super::{BODY, Decoded, Refusal, TARGET, body_streamed_once, convert, full_request, put, run_decode, run_decode_through};

/// A version id as a replication source writes it.
const SOURCE_VERSION: &str = "0190b7a1-6d4e-7c3a-9f00-0123456789ab";

/// The gateway half under the RustFS profile of rd-put-0007: routed with the replication dialect
/// installed, decoded by the replica codec, converted with its version id.
fn replica(request: &RawRequest, probe: &Arc<BodyProbe>) -> Result<Result<oracle::PutObjectInput, String>, String> {
    let input = gateway_decode_replica(request, probe)?;
    Ok(replica_input_to_s3s(input.object, input.version_id).map_err(|error| error.to_string()))
}

// ── decode: the known divergences, named ──────────────────────────────────────────────────────

/// The gateway answers a PUT without `Content-Length` with the dedicated 411 code
/// (`q-length-0007`); the pinned s3s back-fills the length from the body it can measure and hands
/// the request to its handler. This is a behavioral difference a migration must decide, not a
/// conversion gap: no gateway input exists for the conversion to run on.
///
/// `Transfer-Encoding: chunked` does not change that for a plain body: the transport ending the
/// body is not a length, and the operation needs one. Only an `aws-chunked` body states the
/// object's length another way — `x-amz-decoded-content-length`, mandatory in every streaming mode
/// — and rustfs/gateway#750 gives the codec that number for it, whatever framed the wire
/// (`c-chunked-0002`, `crates/gateway/tests/streaming_without_length.rs`). This decode harness runs
/// no payload mode, so what it holds is the half that must not move: no framed length, no
/// `ContentLength`.
///
/// Ruling: `rd-put-0003`
#[test]
fn a_put_without_content_length_is_refused_by_the_gateway_and_backfilled_by_s3s() {
    let request = RawRequest::put(TARGET, BODY, 5).without("content-length");
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(
        refusal,
        Refusal {
            gateway: Err("MissingContentLength".to_owned()),
            conversion: Ok(()),
            oracle: Ok(()),
        }
    );

    let chunked = request.with("transfer-encoding", "chunked");
    let probe = Arc::new(BodyProbe::default());
    assert_eq!(
        gateway_decode(&chunked, &probe).err().as_deref(),
        Some("MissingContentLength"),
        "a plain body the transport ends still states no length"
    );
    let unframed = chunked.with("x-amz-decoded-content-length", "5");
    assert_eq!(
        gateway_decode(&unframed, &probe).err().as_deref(),
        Some("MissingContentLength"),
        "a decoded length with no streaming payload mode is not a length either"
    );
}

/// An `Expires` that is not a date: the gateway keeps it opaque under every revision. The baseline
/// s3s `9c4690d8` holds the member parsed, so it refuses the request and the seam refuses the value
/// by name. `0.17.0`, the revision RustFS main links, holds the wire text: both stacks hand their
/// handler the same `never`, and the seam carries it across.
///
/// Ruling: `rd-put-0004`
#[test]
fn an_expires_that_is_not_a_date_is_kept_by_the_gateway_and_refused_only_by_the_baseline_s3s() {
    let request = full_request().replace("expires", "never");
    if SEAM_REVISION == OracleRevision::Candidate {
        let diff = run_decode(&request, &request, convert).compared();
        assert!(diff.differing.is_empty(), "0.17.0 and the seam both keep the text: {:?}", diff.differing);
        return;
    }
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(refusal.gateway, Ok(()), "the gateway keeps Expires opaque (q-timestamp-0005)");
    assert!(matches!(refusal.oracle, Err((400, _))), "{refusal:?}");
    let probe = Arc::new(BodyProbe::default());
    let error = input_to_s3s(gateway_decode(&request, &probe).expect("accepted"))
        .expect_err("an s3s input cannot hold a non-date Expires");
    assert_eq!(error.field, "expires");
}

/// Two checksum headers: two integrity claims the gateway refuses to choose between.
///
/// Ruling: `rd-put-0005`
#[test]
fn two_checksum_headers_are_refused_by_the_gateway_and_kept_by_s3s() {
    let request = full_request().with("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
    let refusal = run_decode(&request, &request, convert).refused();
    assert!(refusal.gateway.is_err(), "q-checksum-0006: more than one checksum header is a hard error");
    assert_eq!(refusal.oracle, Ok(()));
}

/// The five checksum algorithms S3 added in 2026-04 (SHA-512, MD5, XXHash64, XXHash3, XXHash128):
/// each header, carrying the true digest of `BODY`, is accepted by both stacks and handed to the
/// handler as the same member, so the RustFS app body verifies and stores it as it does today.
///
/// Ruling: `rd-put-0006`
#[test]
fn a_checksum_algorithm_added_in_2026_04_is_handed_over_by_both_stacks() {
    // base64 of each algorithm's digest of `hello`; the XXHash values are big-endian.
    const ADDED: &[(&str, &str, &str)] = &[
        (
            "x-amz-checksum-sha512",
            "checksum_sha512",
            "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==",
        ),
        ("x-amz-checksum-md5", "checksum_md5", "XUFAKrxLKna5cZ2REBfFkg=="),
        ("x-amz-checksum-xxhash64", "checksum_xxhash64", "JseCfYifbaM="),
        ("x-amz-checksum-xxhash3", "checksum_xxhash3", "lVXoVVxi3P0="),
        ("x-amz-checksum-xxhash128", "checksum_xxhash128", "tenBrQcbPn/Hec+qXlI4GA=="),
    ];
    let probe = Arc::new(BodyProbe::default());
    for (header, member, value) in ADDED {
        let request = RawRequest::put(TARGET, BODY, 5).with(header, value);
        let diff = match run_decode(&request, &request, convert) {
            Decoded::Compared(diff) => diff,
            Decoded::Refused(refusal) => panic!("{header}: both stacks must accept the added algorithm: {refusal:?}"),
        };
        assert!(diff.differing.is_empty(), "{header}: {:?}", diff.differing);
        let converted = input_to_s3s(gateway_decode(&request, &probe).expect("accepted")).expect("converts");
        let handed = match *member {
            "checksum_sha512" => converted.checksum_sha512,
            "checksum_md5" => converted.checksum_md5,
            "checksum_xxhash64" => converted.checksum_xxhash64,
            "checksum_xxhash3" => converted.checksum_xxhash3,
            _ => converted.checksum_xxhash128,
        };
        assert_eq!(handed.as_deref(), Some(*value), "{header} reaches the app body as {member}");
    }

    // The control: a SHA-512 header whose value is a SHA-256's width is still refused by the
    // gateway, so the agreement above is a checked value and not an unvalidated pass-through.
    let wrong_width =
        RawRequest::put(TARGET, BODY, 5).with("x-amz-checksum-sha512", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
    let refusal = run_decode(&wrong_width, &wrong_width, convert).refused();
    assert!(refusal.gateway.is_err(), "a value of the wrong width is not a SHA-512");
}

/// `q-content-0008`: an absent `Content-Type` decodes to no type on both stacks, so the RustFS app
/// body gets the `None` it gets today and derives a type from the key's extension. The S3 default
/// is applied on the read instead — the GetObject and HeadObject encoders answer
/// `binary/octet-stream` when a backend names no type — so every other deployment keeps the AWS
/// answer (`c-object-0017`, `c-object-0058`). It used to be filled at decode, where the conversion
/// could not undo it.
///
/// Ruling: `rd-put-0001`
#[test]
fn an_absent_content_type_is_left_absent_by_both_stacks() {
    let request = RawRequest::put(TARGET, BODY, 5);
    let diff = run_decode(&request, &request, convert).compared();
    assert!(diff.differing.is_empty(), "{:?}", diff.differing);
    let probe = Arc::new(BodyProbe::default());
    let converted = input_to_s3s(gateway_decode(&request, &probe).expect("accepted")).expect("converts");
    assert_eq!(converted.content_type, None, "the RustFS app body decides what an untyped object is");

    // The control: a type the client did send reaches the app body unchanged on both stacks.
    let typed = RawRequest::put(TARGET, BODY, 5).with("content-type", "image/png");
    let diff = run_decode(&typed, &typed, convert).compared();
    assert!(diff.differing.is_empty(), "{:?}", diff.differing);
    let converted = input_to_s3s(gateway_decode(&typed, &probe).expect("accepted")).expect("converts");
    assert_eq!(converted.content_type.as_deref(), Some("image/png"));
}

/// The gateway binds the algorithm to `x-amz-sdk-checksum-algorithm`, the header the SDKs send;
/// the pinned s3s reads `x-amz-checksum-algorithm` (or infers it from `x-amz-trailer`) and so hands
/// its handler no algorithm for the same request.
///
/// Ruling: `rd-put-0002`
#[test]
fn the_sdk_checksum_algorithm_header_is_read_by_the_gateway_and_not_by_s3s() {
    let request = put(TARGET, BODY, 5)
        .with("x-amz-sdk-checksum-algorithm", "CRC32")
        .with("x-amz-checksum-crc32", "NhCmhg==");
    let diff = run_decode(&request, &request, convert).compared();
    assert_eq!(diff.differing, ["checksum_algorithm"]);
}

/// The Object Lock event hold of the 2026-09-17 model (rustfs/gateway#815). The gateway binds the
/// header; no pinned s3s revision has the member, so s3s hands its handler an input with no hold and
/// the RustFS store applies none. The seam refuses the conversion, naming the member, so the caller
/// gets a `400` and not an object it believes is held. The duration headers are refused on their
/// own too, and a request without any of the three converts exactly as before.
///
/// Ruling: `rd-put-0009`
#[test]
fn an_object_lock_event_hold_is_refused_by_the_seam_and_unseen_by_s3s() {
    for (header, value, field) in [
        ("x-amz-object-lock-event-hold", "ON", "object_lock_event_hold"),
        ("x-amz-object-lock-event-hold-duration-days", "7", "object_lock_event_hold_duration_days"),
        (
            "x-amz-object-lock-event-hold-duration-years",
            "1",
            "object_lock_event_hold_duration_years",
        ),
    ] {
        let request = RawRequest::put(TARGET, BODY, 5).with(header, value);
        let refusal = run_decode(&request, &request, convert).refused();
        assert_eq!(refusal.gateway, Ok(()), "{header}: the gateway binds the member");
        assert_eq!(refusal.oracle, Ok(()), "{header}: s3s reaches its handler with no hold");
        let error = refusal.conversion.expect_err("the seam refuses an event hold");
        assert!(error.starts_with(field), "{header}: {error}");
    }
    let diff = run_decode(&full_request(), &full_request(), convert).compared();
    assert!(
        diff.differing.is_empty(),
        "a request without a hold converts as before: {:?}",
        diff.differing
    );
}

/// `?versionId=` on a PUT, the MinIO extension RustFS replication writes with so a replica keeps
/// its source's version id. On the default assembly it routes to `PutObject`, whose model has no
/// such member: s3s hands it to its handler and the gateway drops it, so no ordinary writer
/// chooses a version id. With the replication dialect installed
/// (`rustfs_gateway_dialect_minio::replication_dialect`, the RustFS profile) the same request
/// routes to `minio:PutObjectReplica` and converts, member for member, to the input s3s decodes,
/// with the body still crossing once and live. That operation is authorised as
/// `s3:ReplicateObject` before its body is read and as `s3:PutObject` on the key before its
/// handler runs, and is never presigned; `crates/gateway/tests/replica_put.rs` shows the `403` an
/// ordinary writer gets at the wire.
///
/// Ruling: `rd-put-0007`
#[test]
fn a_put_version_id_reaches_the_app_body_only_through_the_replica_write() {
    let request = RawRequest {
        target: format!("{TARGET}?versionId={SOURCE_VERSION}"),
        ..put(TARGET, BODY, 5)
    };

    let default = run_decode(&request, &request, convert).compared();
    assert_eq!(default.differing, ["version_id"], "the default assembly ignores the query");

    let profile = run_decode_through(&request, &request, &replica).compared();
    assert!(profile.differing.is_empty(), "{:?}", profile.differing);
    assert_eq!(body_streamed_once(&profile, &request), Ok(()));

    let auth = PutObjectReplica::spec()
        .auth
        .expect("a registered operation names its action");
    assert_eq!((auth.action, auth.resource), ("s3:ReplicateObject", ResourceShape::Object));
    assert!(!PutObjectReplica::floor().allowed_schemes().allows_presigned());
}

/// The gateway's object-key floor refuses a `..` path segment before anything is stored; the
/// pinned s3s hands its handler the key `..` unchanged. Found by the decode property, which
/// therefore never draws a dot-only segment. The RustFS store refuses the same segment on every
/// write, so the refusal strands no stored object; `c-naming-0028`..`c-naming-0032` pin it for
/// HEAD, DELETE, PUT, multipart and the MinIO profile.
///
/// Ruling: `rd-put-0008`
#[test]
fn a_dot_dot_key_segment_is_refused_by_the_gateway_and_kept_by_s3s() {
    let request = put("/photos/..", BODY, 5);
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(
        refusal,
        Refusal {
            gateway: Err("InvalidArgument".to_owned()),
            conversion: Ok(()),
            oracle: Ok(()),
        }
    );
}
