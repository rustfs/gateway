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

//! Whether the four documents `ops::shared::bucket_config` governs survive the trip out and back.
//!
//! Responsible for: the `decode ∘ encode` identity over `VersioningConfiguration`,
//! `AccelerateConfiguration`, `RequestPaymentConfiguration` and `BucketLoggingStatus` — each a
//! `Get*`/`Put*` pair sharing one nested document — together with the wire shape that identity is
//! only worth anything against. It also holds the seam between the generated decoder (syntax) and
//! `ops::shared::bucket_config`'s four `validate_*` functions (the closed value sets), so a
//! document the decoder accepts is not necessarily one a write would store.
//! NOT responsible for: `GetBucketPolicy`/`PutBucketPolicy` (JSON, not XML, and no closed set to
//! violate) or `Get/PutPublicAccessBlock` (four booleans with their own file, no shared module tie
//! to this one) — both stay outside `ops::shared::bucket_config` and outside this file's scope.
//! Upstream: the generated codecs for the four operation pairs, and `ops::shared::bucket_config`.
//! Downstream: nothing.
//!
//! # Why `BucketLoggingStatus` gets the weight of this file
//!
//! The other three documents are one open-string-enum member each — there is no wrapper to get
//! wrong and no second shape to omit. `BucketLoggingStatus` nests `LoggingEnabled`, whose
//! `TargetGrants` is a **wrapped** list (`<TargetGrants><Grant>…`) reusing `Grantee` from the ACL
//! family, and whose child element is spelled `Grant` — not `TargetGrant`, the Rust type's own
//! name. That mismatch between the wire name and the type name is exactly the shape rustfs/gateway#231
//! was filed to catch, so this file asserts it explicitly rather than trusting the identity alone.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::bucket_config::{
    BucketConfigRejection, validate_accelerate, validate_logging, validate_request_payment, validate_versioning,
};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketVersioning`, `PutBucketRequestPayment` and `PutBucketLogging` are
/// `httpChecksumRequired`; `PutBucketAccelerateConfiguration` is not, but sending the header does
/// it no harm. One constant, applied uniformly, keeps the four fixture builders identical.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// The root element's name, read out of the document rather than searched for — a
/// `contains("<Foo")` is satisfied by the shape appearing anywhere, including nested inside an
/// envelope no client expects.
fn root_element(document: &str) -> String {
    let after_declaration = document.find("?>").map_or(0, |index| index + 2);
    let rest = &document[after_declaration..];
    let open = rest.find('<').expect("a document opens an element");
    rest[open + 1..]
        .split([' ', '>', '/', '\n', '\t'])
        .next()
        .expect("the root element has a name")
        .to_owned()
}

fn body_text(response: rustfs_gateway_core::codec::response::EncodedResponse) -> String {
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

// ── VersioningConfiguration: GetBucketVersioning / PutBucketVersioning ─────────────────────────

fn encode_read_versioning(status: Option<dto::Status>, mfa_delete: Option<dto::MfaDelete>) -> String {
    let request = accepted("GET", "/photos?versioning", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketVersioningOutput { status, mfa_delete };
    body_text(dto::GetBucketVersioning::encode(output, &view, 200).expect("a configuration always encodes"))
}

fn decode_write_versioning(document: &str) -> Result<dto::VersioningConfiguration, CodecError> {
    let request = accepted("PUT", "/photos?versioning", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketVersioning::decode(&view, body).map(|input| input.versioning_configuration)
}

type VersioningProjection = (Option<String>, Option<String>);

fn versioning_projection(configuration: &dto::VersioningConfiguration) -> VersioningProjection {
    (
        configuration.status.as_ref().map(|s| s.as_str().to_owned()),
        configuration.mfa_delete.as_ref().map(|m| m.as_str().to_owned()),
    )
}

// ── AccelerateConfiguration: GetBucketAccelerateConfiguration / PutBucketAccelerateConfiguration ─

fn encode_read_accelerate(status: Option<dto::Status>) -> String {
    let request = accepted("GET", "/photos?accelerate", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketAccelerateConfigurationOutput {
        status,
        ..Default::default()
    };
    body_text(dto::GetBucketAccelerateConfiguration::encode(output, &view, 200).expect("a configuration always encodes"))
}

fn decode_write_accelerate(document: &str) -> Result<dto::AccelerateConfiguration, CodecError> {
    let request = accepted("PUT", "/photos?accelerate", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketAccelerateConfiguration::decode(&view, body).map(|input| input.accelerate_configuration)
}

// ── RequestPaymentConfiguration: GetBucketRequestPayment / PutBucketRequestPayment ─────────────

fn encode_read_request_payment(payer: Option<dto::Payer>) -> String {
    let request = accepted("GET", "/photos?requestPayment", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketRequestPaymentOutput { payer };
    body_text(dto::GetBucketRequestPayment::encode(output, &view, 200).expect("a configuration always encodes"))
}

fn decode_write_request_payment(document: &str) -> Result<dto::RequestPaymentConfiguration, CodecError> {
    let request = accepted("PUT", "/photos?requestPayment", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketRequestPayment::decode(&view, body).map(|input| input.request_payment_configuration)
}

// ── BucketLoggingStatus: GetBucketLogging / PutBucketLogging ───────────────────────────────────

const LOGGING_ROOT: &str = "BucketLoggingStatus";
const TARGET_GRANTS_OPEN: &str = "<TargetGrants>";
const TARGET_GRANTS_CLOSE: &str = "</TargetGrants>";

fn encode_read_logging(logging_enabled: Option<dto::LoggingEnabled>) -> String {
    let request = accepted("GET", "/photos?logging", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketLoggingOutput { logging_enabled };
    body_text(dto::GetBucketLogging::encode(output, &view, 200).expect("a configuration always encodes"))
}

fn decode_write_logging(document: &str) -> Result<dto::BucketLoggingStatus, CodecError> {
    let request = accepted("PUT", "/photos?logging", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketLogging::decode(&view, body).map(|input| input.bucket_logging_status)
}

/// None of these DTOs carry `PartialEq` — ADR-0004 keeps derived equality off the DTOs — so
/// equality is spelled here, over every member of every nested shape.
type GranteeProjection = (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);
type TargetGrantProjection = (Option<GranteeProjection>, Option<String>);
type KeyFormatProjection = (bool, Option<String>);
type LoggingProjection = (String, String, Vec<TargetGrantProjection>, Option<KeyFormatProjection>);

fn grantee_projection(grantee: &dto::Grantee) -> GranteeProjection {
    (
        grantee.id.clone(),
        grantee.display_name.clone(),
        grantee.email_address.clone(),
        grantee.uri.clone(),
        grantee.r#type.as_ref().map(|kind| kind.as_str().to_owned()),
    )
}

fn target_grant_projection(grant: &dto::TargetGrant) -> TargetGrantProjection {
    (
        grant.grantee.as_ref().map(grantee_projection),
        grant.permission.as_ref().map(|permission| permission.as_str().to_owned()),
    )
}

fn key_format_projection(format: &dto::TargetObjectKeyFormat) -> KeyFormatProjection {
    (
        format.simple_prefix.is_some(),
        format
            .partitioned_prefix
            .as_ref()
            .and_then(|partitioned| partitioned.partition_date_source.as_ref())
            .map(|source| source.as_str().to_owned()),
    )
}

fn logging_projection(status: &dto::BucketLoggingStatus) -> Option<LoggingProjection> {
    status.logging_enabled.as_ref().map(|enabled| {
        (
            enabled.target_bucket.clone(),
            enabled.target_prefix.clone(),
            enabled.target_grants.iter().flatten().map(target_grant_projection).collect(),
            enabled.target_object_key_format.as_ref().map(key_format_projection),
        )
    })
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// Text a writer has to escape and a reader is tempted to normalise: the five characters XML
/// escapes plus two outside ASCII, the same alphabet every sibling property in this workspace
/// samples for the identical reason.
fn awkward_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _-]{0,24}"
}

fn switch_status() -> impl Strategy<Value = dto::Status> {
    prop_oneof![Just(dto::Status::ENABLED), Just(dto::Status::SUSPENDED)]
}

fn mfa_delete() -> impl Strategy<Value = dto::MfaDelete> {
    prop_oneof![Just(dto::MfaDelete::ENABLED), Just(dto::MfaDelete::DISABLED)]
}

fn payer() -> impl Strategy<Value = dto::Payer> {
    prop_oneof![Just(dto::Payer::REQUESTER), Just(dto::Payer::BUCKETOWNER)]
}

fn permission() -> impl Strategy<Value = dto::Permission> {
    prop_oneof![
        Just(dto::Permission::FULL_CONTROL),
        Just(dto::Permission::WRITE),
        Just(dto::Permission::WRITE_ACP),
        Just(dto::Permission::READ),
        Just(dto::Permission::READ_ACP),
    ]
}

/// Unlike the ACL family, `TargetGrant`'s `Grantee` has no `canonicalize_policy` step — the
/// generated writer echoes `r#type` exactly as decoded — so the discriminator is sampled here
/// rather than left for a canonicalisation pass to fill in.
fn grantee() -> impl Strategy<Value = dto::Grantee> {
    prop_oneof![
        (awkward_text(), "[0-9a-f]{16}").prop_map(|(display_name, id)| dto::Grantee {
            id: Some(id),
            display_name: Some(display_name),
            r#type: Some(dto::Type::CANONICALUSER),
            ..dto::Grantee::default()
        }),
        "https://acs\\.amazonaws\\.com/groups/[a-z/]{1,20}".prop_map(|uri| dto::Grantee {
            uri: Some(uri),
            r#type: Some(dto::Type::GROUP),
            ..dto::Grantee::default()
        }),
        "[a-z]{1,8}@example\\.com".prop_map(|email| dto::Grantee {
            email_address: Some(email),
            r#type: Some(dto::Type::AMAZONCUSTOMERBYEMAIL),
            ..dto::Grantee::default()
        }),
    ]
}

fn target_grant() -> impl Strategy<Value = dto::TargetGrant> {
    (grantee(), permission()).prop_map(|(grantee, permission)| dto::TargetGrant {
        grantee: Some(grantee),
        permission: Some(permission),
    })
}

fn partition_date_source() -> impl Strategy<Value = dto::PartitionDateSource> {
    prop_oneof![
        Just(dto::PartitionDateSource::EVENTTIME),
        Just(dto::PartitionDateSource::DELIVERYTIME)
    ]
}

/// The codec enforces no mutual exclusion between `SimplePrefix` and `PartitionedPrefix`
/// (`ops::shared::bucket_config` names no rule for this member), so both are sampled
/// independently rather than as an either/or.
fn target_object_key_format() -> impl Strategy<Value = dto::TargetObjectKeyFormat> {
    (prop::bool::ANY, prop::option::of(partition_date_source())).prop_map(|(simple, source)| dto::TargetObjectKeyFormat {
        simple_prefix: simple.then_some(dto::SimplePrefix {}),
        partitioned_prefix: source.map(|partition_date_source| dto::PartitionedPrefix {
            partition_date_source: Some(partition_date_source),
        }),
    })
}

fn logging_enabled() -> impl Strategy<Value = dto::LoggingEnabled> {
    (
        awkward_text(),
        awkward_text(),
        prop::collection::vec(target_grant(), 0..3),
        prop::option::of(target_object_key_format()),
    )
        .prop_map(
            |(target_bucket, target_prefix, target_grants, target_object_key_format)| dto::LoggingEnabled {
                target_bucket,
                target_prefix,
                target_grants: Some(target_grants),
                target_object_key_format,
            },
        )
}

// ── the properties ──────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever a versioning document says, writing it and reading it back yields the same
    /// document, rooted at `VersioningConfiguration`.
    #[test]
    fn a_versioning_configuration_survives_encode_then_decode(status in prop::option::of(switch_status()), mfa_delete in prop::option::of(mfa_delete())) {
        let document = encode_read_versioning(status.clone(), mfa_delete.clone());
        prop_assert_eq!(root_element(&document), "VersioningConfiguration", "document: {}", document);

        let read_back = decode_write_versioning(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;
        let expected = (status.map(|s| s.as_str().to_owned()), mfa_delete.map(|m| m.as_str().to_owned()));
        prop_assert_eq!(versioning_projection(&read_back), expected, "document: {}", document);
    }

    /// Whatever an acceleration document says, writing it and reading it back yields the same
    /// document, rooted at `AccelerateConfiguration`.
    #[test]
    fn an_accelerate_configuration_survives_encode_then_decode(status in prop::option::of(switch_status())) {
        let document = encode_read_accelerate(status.clone());
        prop_assert_eq!(root_element(&document), "AccelerateConfiguration", "document: {}", document);

        let read_back = decode_write_accelerate(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;
        let expected = status.map(|s| s.as_str().to_owned());
        prop_assert_eq!(read_back.status.map(|s| s.as_str().to_owned()), expected, "document: {}", document);
    }

    /// A request-payment document survives the round trip. `Payer` is required on the write side,
    /// so the generator always supplies one — a missing `Payer` is covered as a boundary below,
    /// not as an identity input.
    #[test]
    fn a_request_payment_configuration_survives_encode_then_decode(payer in payer()) {
        let document = encode_read_request_payment(Some(payer.clone()));
        prop_assert_eq!(root_element(&document), "RequestPaymentConfiguration", "document: {}", document);

        let read_back = decode_write_request_payment(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;
        prop_assert_eq!(read_back.payer.as_str(), payer.as_str(), "document: {}", document);
    }

    /// Whatever a logging document says, writing it and reading it back yields the same
    /// document — rooted at `BucketLoggingStatus`, and carrying the `<TargetGrants>` wrapper
    /// whenever there is at least one grant to wrap.
    #[test]
    fn a_logging_configuration_survives_encode_then_decode(enabled in prop::option::of(logging_enabled())) {
        let document = encode_read_logging(enabled.clone());
        prop_assert_eq!(root_element(&document), LOGGING_ROOT, "document: {}", document);
        if enabled.as_ref().is_some_and(|e| !e.target_grants.as_deref().unwrap_or_default().is_empty()) {
            prop_assert!(
                document.contains(TARGET_GRANTS_OPEN) && document.contains(TARGET_GRANTS_CLOSE),
                "a non-empty grant list must be wrapped: {document}"
            );
            prop_assert!(!document.contains("<TargetGrant>"), "the item element is Grant, not TargetGrant: {document}");
        }

        let read_back = decode_write_logging(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;
        let expected = enabled.as_ref().map(|e| {
            (
                e.target_bucket.clone(),
                e.target_prefix.clone(),
                e.target_grants.iter().flatten().map(target_grant_projection).collect::<Vec<_>>(),
                e.target_object_key_format.as_ref().map(key_format_projection),
            )
        });
        prop_assert_eq!(logging_projection(&read_back), expected, "document: {}", document);
    }
}

// ── boundaries the properties reach only by luck ────────────────────────────────────────────

/// The empty logging document: no `<LoggingEnabled>` at all, which `q-log-0001` spells as "not
/// configured" rather than as an error.
#[test]
fn an_absent_logging_enabled_comes_back_absent() {
    let document = encode_read_logging(None);
    let read_back = decode_write_logging(&document).expect("an empty BucketLoggingStatus is still a document");
    assert!(read_back.logging_enabled.is_none(), "document: {document}");
}

/// A document this codec wrote is one a write would actually store: decode, then the family's
/// validator. A round trip that never validated would be comparing against a document no write
/// would ever have accepted.
#[test]
fn a_realistic_logging_document_this_codec_wrote_is_one_the_family_accepts() {
    let enabled = dto::LoggingEnabled {
        target_bucket: "log-bucket".to_owned(),
        target_prefix: "logs/".to_owned(),
        target_grants: Some(vec![dto::TargetGrant {
            grantee: Some(dto::Grantee {
                id: Some("abc123".to_owned()),
                r#type: Some(dto::Type::CANONICALUSER),
                ..dto::Grantee::default()
            }),
            permission: Some(dto::Permission::READ),
        }]),
        target_object_key_format: Some(dto::TargetObjectKeyFormat {
            simple_prefix: Some(dto::SimplePrefix {}),
            partitioned_prefix: None,
        }),
    };
    let document = encode_read_logging(Some(enabled.clone()));
    let read_back = decode_write_logging(&document).expect("reads");
    assert_eq!(validate_logging(&read_back), Ok(()));
    assert_eq!(
        logging_projection(&read_back),
        Some((
            enabled.target_bucket,
            enabled.target_prefix,
            enabled.target_grants.iter().flatten().map(target_grant_projection).collect(),
            enabled.target_object_key_format.as_ref().map(key_format_projection),
        ))
    );
}

/// The empty required text field: `TargetPrefix` is required by the model, but `String`'s
/// placeholder policy makes the empty string a legitimate wire value (`""` means "log
/// everything"), so it has to survive the round trip rather than be read back as absent.
#[test]
fn an_empty_target_prefix_survives_the_round_trip() {
    let enabled = dto::LoggingEnabled {
        target_bucket: "log-bucket".to_owned(),
        target_prefix: String::new(),
        target_grants: Some(vec![]),
        target_object_key_format: None,
    };
    let document = encode_read_logging(Some(enabled));
    let read_back = decode_write_logging(&document).expect("reads");
    let enabled = read_back.logging_enabled.expect("logging is still enabled");
    assert_eq!(enabled.target_prefix, "", "document: {document}");
    assert_eq!(
        validate_logging(&dto::BucketLoggingStatus {
            logging_enabled: Some(enabled)
        }),
        Ok(())
    );
}

/// A `Grant` outside the `<TargetGrants>` wrapper is not read as a grant. This is the read side
/// of the wrapper obligation the main property asserts on the write side: a document a flattening
/// writer produced would be read back with zero grants rather than the one it named — the same
/// silent-drop shape rustfs/gateway#231's CORS and notification instances took.
#[test]
fn n_a_grant_outside_the_wrapper_is_not_read_as_a_grant() {
    let document = "<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket>\
                    <TargetPrefix>p</TargetPrefix><Grant><Permission>READ</Permission></Grant>\
                    </LoggingEnabled></BucketLoggingStatus>";
    let status = decode_write_logging(document).expect("an unknown element is skipped, not refused");
    let enabled = status.logging_enabled.expect("logging_enabled is present");
    assert!(
        enabled.target_grants.as_deref().unwrap_or_default().is_empty(),
        "an unwrapped Grant must not be read as a grant: {:?}",
        enabled.target_grants
    );
}

/// A grant spelled with the Rust type's own name, `<TargetGrant>`, rather than the wire name
/// `<Grant>`, is not read as a grant either. The type name and the wire name diverge on purpose
/// (`TargetGrant` reads from `Grant` elements), and a decoder that matched on the type name would
/// read zero grants from every document AWS's own SDKs write.
#[test]
fn n_a_grant_spelled_targetgrant_is_not_read_as_a_grant() {
    let document = "<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket>\
                    <TargetPrefix>p</TargetPrefix><TargetGrants><TargetGrant>\
                    <Permission>READ</Permission></TargetGrant></TargetGrants>\
                    </LoggingEnabled></BucketLoggingStatus>";
    let status = decode_write_logging(document).expect("an unknown child element is skipped, not refused");
    let enabled = status.logging_enabled.expect("logging_enabled is present");
    assert!(
        enabled.target_grants.as_deref().unwrap_or_default().is_empty(),
        "a TargetGrant element must not be read as a Grant: {:?}",
        enabled.target_grants
    );
}

/// A document under another root is refused. This is the read side of the identity: a decoder
/// keyed to any other root would satisfy a pair that agrees with itself and speaks to no client
/// that ever wrote an S3 logging document.
#[test]
fn n_a_logging_document_under_another_root_is_refused() {
    let document = "<LoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket>\
                    <TargetPrefix>p</TargetPrefix></LoggingEnabled></LoggingStatus>";
    let error = decode_write_logging(document).expect_err("the wire root is BucketLoggingStatus, not LoggingStatus");
    assert_eq!(error.member(), Some("BucketLoggingStatus"), "{error:?}");
}

/// `validate_logging` refuses a decoded document naming an empty `TargetBucket` — the decoder
/// itself does not, because an empty string is not a placeholder for `String`. This is the seam:
/// which layer produces the refusal, and whether it exists at all.
#[test]
fn n_validate_logging_rejects_an_empty_target_bucket_after_the_decoder_accepts_it() {
    let document = "<BucketLoggingStatus><LoggingEnabled><TargetBucket></TargetBucket>\
                    <TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    let status = decode_write_logging(document).expect("the decoder does not enforce a non-empty TargetBucket");
    assert_eq!(status.logging_enabled.as_ref().map(|e| e.target_bucket.as_str()), Some(""));
    assert_eq!(validate_logging(&status), Err(BucketConfigRejection::LoggingTargetEmpty));
}

/// A `<Status>` outside the closed switch set survives the decoder (an open string enum) and is
/// refused only by `validate_versioning` — the same decoder/validator layering the sibling
/// properties in this workspace pin for their own closed sets.
#[test]
fn n_an_unknown_versioning_status_survives_the_decoder_and_is_refused_by_validate() {
    let document = "<VersioningConfiguration><Status>Archived</Status></VersioningConfiguration>";
    let configuration = decode_write_versioning(document).expect("the decoder does not close the Status set");
    assert_eq!(configuration.status.as_ref().map(|s| s.as_str()), Some("Archived"));
    assert_eq!(validate_versioning(&configuration), Err(BucketConfigRejection::StatusUnknown));
}

/// The same seam for acceleration.
#[test]
fn n_an_unknown_accelerate_status_survives_the_decoder_and_is_refused_by_validate() {
    let document = "<AccelerateConfiguration><Status>Archived</Status></AccelerateConfiguration>";
    let configuration = decode_write_accelerate(document).expect("the decoder does not close the Status set");
    assert_eq!(validate_accelerate(&configuration), Err(BucketConfigRejection::StatusUnknown));
}

/// The same seam for request payment — `Payer` is required, so the decoder still accepts an
/// unknown *value*, it just cannot accept an absent element.
#[test]
fn n_an_unknown_payer_survives_the_decoder_and_is_refused_by_validate() {
    let document = "<RequestPaymentConfiguration><Payer>Someone</Payer></RequestPaymentConfiguration>";
    let configuration = decode_write_request_payment(document).expect("the decoder does not close the Payer set");
    assert_eq!(validate_request_payment(&configuration), Err(BucketConfigRejection::PayerUnknown));
}

/// An absent `<Payer>` is refused by the decoder itself — the member is required in the pinned
/// model, so the empty document and the never-configured document must not collapse into one.
#[test]
fn n_an_empty_request_payment_document_is_refused() {
    let document = "<RequestPaymentConfiguration></RequestPaymentConfiguration>";
    let error = decode_write_request_payment(document).expect_err("Payer is required");
    assert_eq!(error.member(), Some("Payer"), "{error:?}");
}

/// An unknown top-level element inside `LoggingEnabled` is skipped rather than refused, and does
/// not survive the round trip — the DTO has nowhere to put it.
#[test]
fn n_an_unknown_element_is_skipped_and_does_not_come_back() {
    let document = "<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket>\
                    <TargetPrefix>p</TargetPrefix><HostingProvider>acme</HostingProvider>\
                    </LoggingEnabled></BucketLoggingStatus>";
    let status = decode_write_logging(document).expect("an unknown element is skipped, not refused");
    let reserialised = encode_read_logging(status.logging_enabled);
    assert!(
        !reserialised.contains("<HostingProvider>"),
        "the unknown element was echoed rather than dropped: {reserialised}"
    );
    assert_eq!(root_element(&reserialised), LOGGING_ROOT);
}
