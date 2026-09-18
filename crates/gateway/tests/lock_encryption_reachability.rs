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

//! Every argument of the CORS, encryption, replication and object-lock contracts, built out of a
//! decoded request and what `Req<O>` hands a handler beside it.
//!
//! Responsible for: proving that a backend outside this workspace can *call* [`validate_cors`],
//! [`validate_encryption`] and [`refuse_blocked_encryption_type`], [`validate_replication`] and
//! [`classify_rule`], and the four object-lock contracts — and naming where each argument that is
//! *not* the decoded document comes from: the SSE proof from [`Req::sse`], the clock from the
//! backend itself, the object-write lock headers from three members of the write's own input.
//! NOT responsible for: what the rules decide (`rustfs-gateway-core`'s inline tests) or the wire
//! shapes (`conformance/cases/`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15's acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** Three contracts in this band take an argument beyond the
//! decoded document, and each is a different answer to the bar:
//!
//! - `refuse_blocked_encryption_type(config, sse)` — the proof is [`Req::sse`], the framework's
//!   own, so a backend never re-reads the SSE-C headers. Reachable.
//! - `validate_retention(retention, now)` / `validate_object_write_lock(…, now)` — `now` is **not**
//!   in `Req<O>`: `RequestContextView` carries no clock reading. This is by design (the clock is
//!   the deployment's, `ServiceBuilder::clock`, and the backend holds one too), and it is written
//!   down here as the one argument a backend supplies from outside the request, so nobody reads
//!   the signature and goes looking for a request-time accessor that does not exist.
//! - `validate_object_write_lock(mode, until, hold, now)` — three `Option` members of the
//!   write's input, borrowed as `&str`/`&Timestamp`; the bridge is four lines and is shown once.

use rustfs_gateway::{
    CorsRejection, EncryptionRejection, ErrorCode, MetaView, ObjectLockRejection, OperationCodec, ReplicationRejection, Req,
    RequestBody, RuleShape, SseConfig, SseEnforced, TargetKind, TransportSecurity, WireRequest, classify_rule, dto, enforce_sse,
    refuse_blocked_encryption_type, validate_cors, validate_encryption, validate_legal_hold, validate_lock_configuration,
    validate_object_write_lock, validate_replication, validate_retention,
};

use super::tagging_reachability::{accepted, content_md5};

/// A clock reading a backend owns; every object-lock case below is judged against it.
const NOW: i64 = 1_767_323_045;

fn integrity(body: &[u8]) -> [(&'static str, &'static str); 2] {
    let digest: &'static str = Box::leak(content_md5(body).into_boxed_str());
    [("content-type", "application/xml"), ("content-md5", digest)]
}

/// A write of `document` to `target` (bucket or object subresource), decoded as `O`.
fn decoded<O: OperationCodec>(kind: TargetKind, target: &str, document: &'static str) -> O::Input {
    let uri: &'static str = Box::leak(format!("http://host.invalid/conf-lock{target}").into_boxed_str());
    let request = accepted("PUT", uri, &integrity(document.as_bytes()));
    let view = MetaView::of(&request, kind).expect("the path has its labels");
    O::decode(&view, RequestBody::Buffered(document.as_bytes().into()))
        .expect("a well-formed document with a value outside the contract's set is not the decoder's refusal")
}

/// The SSE proof the framework attaches to a request, as a handler receives it through
/// [`Req::sse`]: with the three SSE-C headers present the proof carries a key fingerprint, and
/// without them it carries none.
fn sse_proof(customer_key: bool) -> SseEnforced {
    let mut headers: Vec<(&'static str, &'static str)> = Vec::new();
    if customer_key {
        headers.extend([
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            (
                "x-amz-server-side-encryption-customer-key",
                "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
            ),
            ("x-amz-server-side-encryption-customer-key-md5", "UhbdzFjo2t5SVgded/ZC2g=="),
        ]);
    }
    let request: WireRequest<()> = accepted("PUT", "http://host.invalid/conf-lock/key", &headers);
    let meta = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    enforce_sse(&meta, TransportSecurity::Encrypted, &SseConfig::strict()).expect("an encrypted SSE-C write passes enforcement")
}

// ---------------------------------------------------------------------------------------------
// CORS and replication: one document, one contract, plus replication's rule classifier
// ---------------------------------------------------------------------------------------------

/// Negative with its control — a rule without an `AllowedMethod` decodes (the list is empty, not
/// refused) and is the contract's refusal; a whole rule passes.
#[test]
fn n_a_cors_rule_without_a_method_is_the_contracts_refusal() {
    let whole = decoded::<dto::PutBucketCors>(
        TargetKind::Bucket,
        "?cors",
        "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>",
    );
    validate_cors(&whole.cors_configuration).expect("one origin, one method");
    let no_method = decoded::<dto::PutBucketCors>(
        TargetKind::Bucket,
        "?cors",
        "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>",
    );
    assert!(no_method.cors_configuration.cors_rules[0].allowed_methods.is_empty());
    let rejection = validate_cors(&no_method.cors_configuration).expect_err("no method");
    assert_eq!(rejection, CorsRejection::MissingAllowedMethod);
    assert_eq!(rejection.code(), ErrorCode::MALFORMED_XML);
}

/// Negative with its control — a legacy `Prefix` rule and a `Filter` rule are the two shapes
/// [`classify_rule`] names from the decoded rule alone; a rule carrying both is the contract's
/// refusal, from [`validate_replication`] over the whole document.
#[test]
fn n_a_replication_rule_with_prefix_beside_filter_is_the_contracts_refusal() {
    let legacy = decoded::<dto::PutBucketReplication>(
        TargetKind::Bucket,
        "?replication",
        "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><Prefix>a/</Prefix><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::d</Bucket></Destination></Rule></ReplicationConfiguration>",
    );
    validate_replication(&legacy.replication_configuration).expect("a legacy rule is complete");
    assert_eq!(classify_rule(&legacy.replication_configuration.rules[0]), Ok(RuleShape::LegacyPrefix));
    let both = decoded::<dto::PutBucketReplication>(
        TargetKind::Bucket,
        "?replication",
        "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><Prefix>a/</Prefix><Filter><Prefix>b/</Prefix></Filter><Priority>1</Priority><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::d</Bucket></Destination></Rule></ReplicationConfiguration>",
    );
    let rule = &both.replication_configuration.rules[0];
    assert!(rule.prefix.is_some() && rule.filter.is_some(), "both decode; neither pre-empts");
    assert_eq!(
        validate_replication(&both.replication_configuration),
        Err(ReplicationRejection::FilterBesideLegacyPrefix)
    );
}

// ---------------------------------------------------------------------------------------------
// Encryption: the document contract and the run-time rule over the framework's SSE proof
// ---------------------------------------------------------------------------------------------

/// Negative with its control — an algorithm outside the set decodes and is the contract's
/// refusal; the stored document then feeds the run-time rule, whose second argument is the proof
/// the framework already attached: a customer-keyed write into a bucket that blocks SSE-C is
/// `AccessDenied`, the same write without a customer key is not, and no header is re-read.
#[test]
fn n_a_blocked_encryption_type_is_refused_from_the_frameworks_own_sse_proof() {
    let unknown = decoded::<dto::PutBucketEncryption>(
        TargetKind::Bucket,
        "?encryption",
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>rot13</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
    );
    assert_eq!(
        validate_encryption(&unknown.server_side_encryption_configuration),
        Err(EncryptionRejection::AlgorithmUnknown)
    );

    let blocking = decoded::<dto::PutBucketEncryption>(
        TargetKind::Bucket,
        "?encryption",
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>",
    );
    validate_encryption(&blocking.server_side_encryption_configuration).expect("a blocking rule is well formed");
    let stored = Some(&blocking.server_side_encryption_configuration);

    // The write a backend judges: what it has is `Req<PutObject>`, and the proof is `req.sse()`.
    let keyed: Req<dto::PutBucketEncryption> = Req::new(blocking.clone(), sse_proof(true));
    assert!(
        keyed.sse().customer_key_fingerprint().is_some(),
        "the proof carries the key's fingerprint"
    );
    let rejection = refuse_blocked_encryption_type(stored, keyed.sse()).expect_err("SSE-C into a blocking bucket");
    assert_eq!(rejection, EncryptionRejection::EncryptionTypeBlocked);
    assert_eq!(rejection.code(), ErrorCode::ACCESS_DENIED);

    let plain: Req<dto::PutBucketEncryption> = Req::new(blocking.clone(), sse_proof(false));
    refuse_blocked_encryption_type(stored, plain.sse()).expect("no customer key, nothing blocked");
    refuse_blocked_encryption_type(None, keyed.sse()).expect("no document, nothing blocked");
}

// ---------------------------------------------------------------------------------------------
// Object lock: the bucket configuration, the two object subresources, and the write headers
// ---------------------------------------------------------------------------------------------

/// Negative with its control — a `Mode` outside the pair decodes into the lock configuration and
/// is the contract's refusal; a whole configuration passes.
#[test]
fn n_a_lock_configuration_mode_outside_the_pair_is_the_contracts_refusal() {
    let whole = decoded::<dto::PutObjectLockConfiguration>(
        TargetKind::Bucket,
        "?object-lock",
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
    );
    validate_lock_configuration(&whole.object_lock_configuration).expect("a documented mode and one period");
    let bogus = decoded::<dto::PutObjectLockConfiguration>(
        TargetKind::Bucket,
        "?object-lock",
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>FOREVER</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
    );
    assert_eq!(
        validate_lock_configuration(&bogus.object_lock_configuration),
        Err(ObjectLockRejection::ModeUnknown)
    );
}

/// Negative with its control — the retention and legal-hold documents reach their contracts
/// from the two object subresources; `now` is the backend's clock, not a request member, and a
/// `RetainUntilDate` behind it is the contract's refusal.
#[test]
fn n_a_retention_behind_the_backends_clock_is_the_contracts_refusal() {
    let future = decoded::<dto::PutObjectRetention>(
        TargetKind::Object,
        "/key?retention",
        "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>",
    );
    validate_retention(&future.retention, NOW).expect("2030 is after the clock");
    let past = decoded::<dto::PutObjectRetention>(
        TargetKind::Object,
        "/key?retention",
        "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2020-01-01T00:00:00Z</RetainUntilDate></Retention>",
    );
    assert_eq!(
        validate_retention(&past.retention, NOW),
        Err(ObjectLockRejection::RetainUntilNotInFuture),
        "the decoder keeps a past date; the contract, given the clock, refuses it"
    );

    let hold =
        decoded::<dto::PutObjectLegalHold>(TargetKind::Object, "/key?legal-hold", "<LegalHold><Status>ON</Status></LegalHold>");
    validate_legal_hold(&hold.legal_hold).expect("ON is in the pair");
    let maybe = decoded::<dto::PutObjectLegalHold>(
        TargetKind::Object,
        "/key?legal-hold",
        "<LegalHold><Status>MAYBE</Status></LegalHold>",
    );
    assert_eq!(validate_legal_hold(&maybe.legal_hold), Err(ObjectLockRejection::StatusUnknown));
}

/// Negative with its control — the object-write lock headers are three members of the write's
/// own input (`CreateMultipartUpload` here, standing in for `PutObject`), borrowed into the
/// contract with the backend's clock; a mode without its date is the contract's refusal.
#[test]
fn n_unpaired_lock_headers_on_a_write_are_the_contracts_refusal() {
    fn decoded_write(headers: &[(&'static str, &'static str)]) -> dto::CreateMultipartUploadInput {
        let request = accepted("POST", "http://host.invalid/conf-lock/key?uploads", headers);
        let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
        dto::CreateMultipartUpload::decode(&view, RequestBody::None).expect("lock headers are not the decoder's refusal")
    }
    // The bridge, once: three `Option` members to three borrowed arguments.
    fn judge(input: &dto::CreateMultipartUploadInput) -> Result<(), ObjectLockRejection> {
        validate_object_write_lock(
            input.object_lock_mode.as_ref().map(|mode| mode.as_str()),
            input.object_lock_retain_until_date.as_ref(),
            input.object_lock_legal_hold_status.as_ref().map(|status| status.as_str()),
            NOW,
        )
    }
    judge(&decoded_write(&[])).expect("no lock headers, nothing to judge");
    judge(&decoded_write(&[
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
        ("x-amz-object-lock-legal-hold", "OFF"),
    ]))
    .expect("a paired mode and date in the future, and a documented hold");
    assert_eq!(
        judge(&decoded_write(&[("x-amz-object-lock-mode", "GOVERNANCE")])),
        Err(ObjectLockRejection::WriteHeadersUnpaired)
    );
    assert_eq!(
        judge(&decoded_write(&[("x-amz-object-lock-legal-hold", "MAYBE")])),
        Err(ObjectLockRejection::WriteHeaderValueUnknown)
    );
}
