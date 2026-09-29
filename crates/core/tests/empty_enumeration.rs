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

//! An empty element in a **required** enumeration member of a request document
//! (rustfs/gateway#1078, row 3).
//!
//! Responsible for: every required string-enumeration member a request document carries — fourteen
//! positions across seven operations — decoding `<Status></Status>` and `<Status/>` into the empty
//! value a client sent, which the handler then judges like any other value outside the model's
//! set, rather than into the member's placeholder default, which the decoder's exit check turned
//! into this side's `500 InternalError`.
//! NOT responsible for: whether an operation accepts the empty value — that is the backend's
//! question, asked with the backend's code (legacy RustFS refuses an empty lifecycle `Status` with
//! `MalformedXML` and stores an empty `Payer`), which the RustFS-profile suites pin; or a missing
//! element, which stays the schema's `MalformedXML` and is pinned below as the control.
//! Upstream: the generated codecs of the seven operations. Downstream: nothing.
//!
//! # Why the empty value has to reach the handler
//!
//! A client error is never a `5xx`: a `500` reads to every SDK as a retryable server fault, so an
//! empty `<Status/>` was retried until the client gave up, and the answer it finally reported named
//! the server. Legacy RustFS hands the empty value to its handlers, which answer `400` or store it
//! (`rustfs/src/app/bucket_usecase.rs:1220-1227` refuses an empty lifecycle status,
//! `rustfs/src/storage/ecfs.rs:1468-1477` stores an empty `Payer`, at rustfs/rustfs@5851d9eb5), so a
//! decoder that refused it itself would answer those two differently from legacy RustFS.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{ErrorCode, WirePlaceholder, dto};

/// Several of these operations are `httpChecksumRequired`; the claim's value is settled below this
/// layer, so a presence claim is all the decoder needs to read the document.
const INTEGRITY: (&str, &str) = ("x-amz-checksum-crc32", "AAAAAA==");

fn decode<O: OperationCodec>(target: &str, kind: TargetKind, document: &str) -> Result<O::Input, CodecError> {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .header(INTEGRITY.0, INTEGRITY.1)
        .body(())
        .expect("the fixture request is well formed");
    let wire = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&wire, kind).expect("view");
    O::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes())))
}

fn lifecycle(status: &str) -> Result<dto::PutBucketLifecycleConfigurationInput, CodecError> {
    decode::<dto::PutBucketLifecycleConfiguration>(
        "/photos?lifecycle",
        TargetKind::Bucket,
        &format!(
            "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>logs/</Prefix></Filter>{status}\
             <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
        ),
    )
}

/// A replication document whose one rule carries `rule` inside it and `destination` inside its
/// destination, with every other required member present.
fn replication(rule: &str, destination: &str) -> Result<dto::ReplicationConfiguration, CodecError> {
    decode::<dto::PutBucketReplication>(
        "/photos?replication",
        TargetKind::Bucket,
        &format!(
            "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Priority>1</Priority>\
             <Filter><Prefix></Prefix></Filter>{rule}<Destination><Bucket>arn:aws:s3:::dst</Bucket>{destination}</Destination>\
             </Rule></ReplicationConfiguration>"
        ),
    )
    .map(|input| input.replication_configuration)
}

fn restore(document: &str) -> Result<dto::RestoreRequest, CodecError> {
    decode::<dto::RestoreObject>("/photos/key?restore", TargetKind::Object, document).map(|input| input.restore_request)
}

/// The value a decoded required enumeration member holds must be the client's empty value, and
/// never the placeholder its type's `Default` is.
macro_rules! empty_value {
    ($value:expr, $position:expr $(,)?) => {{
        let value = $value;
        assert_eq!(value.as_str(), "", "{}", $position);
        assert!(
            !value.is_wire_placeholder(),
            "{}: the client's empty value became the placeholder",
            $position
        );
    }};
}

fn refused_as_malformed<T: std::fmt::Debug>(outcome: Result<T, CodecError>, position: &str) {
    let error = outcome.expect_err(position);
    assert_eq!(error.code(), &ErrorCode::MALFORMED_XML, "{position}: {error}");
}

// ── the empty value is decoded ────────────────────────────────────────────────────────────────

/// Positive — `LifecycleRule.Status`, paired and self-closing.
#[test]
fn an_empty_lifecycle_rule_status_is_decoded_as_the_empty_value() {
    for status in ["<Status></Status>", "<Status/>"] {
        let input = lifecycle(status).unwrap_or_else(|error| panic!("{status}: {error}"));
        let configuration = input.lifecycle_configuration.expect("a configuration");
        empty_value!(&configuration.rules[0].status, status);
    }
}

/// Positive — the seven required statuses of a replication rule and its nested members.
#[test]
fn an_empty_replication_status_is_decoded_as_the_empty_value_wherever_it_is_required() {
    let rule = replication("<Status></Status>", "").expect("rule status");
    empty_value!(&rule.rules[0].status, "ReplicationRule.Status");

    let enabled = "<Status>Enabled</Status>";
    let delete = replication(&format!("{enabled}<DeleteReplication><Status/></DeleteReplication>"), "").expect("delete");
    empty_value!(
        &delete.rules[0].delete_replication.as_ref().expect("present").status,
        "DeleteReplication.Status"
    );

    let existing = replication(
        &format!("{enabled}<ExistingObjectReplication><Status></Status></ExistingObjectReplication>"),
        "",
    )
    .expect("existing");
    empty_value!(
        &existing.rules[0]
            .existing_object_replication
            .as_ref()
            .expect("present")
            .status,
        "ExistingObjectReplication.Status",
    );

    let modifications = replication(
        &format!(
            "{enabled}<SourceSelectionCriteria><ReplicaModifications><Status/></ReplicaModifications></SourceSelectionCriteria>"
        ),
        "",
    )
    .expect("replica modifications");
    let criteria = modifications.rules[0].source_selection_criteria.as_ref().expect("criteria");
    empty_value!(
        &criteria.replica_modifications.as_ref().expect("present").status,
        "ReplicaModifications.Status",
    );

    let kms = replication(
        &format!(
            "{enabled}<SourceSelectionCriteria><SseKmsEncryptedObjects><Status></Status></SseKmsEncryptedObjects></SourceSelectionCriteria>"
        ),
        "",
    )
    .expect("sse-kms objects");
    let criteria = kms.rules[0].source_selection_criteria.as_ref().expect("criteria");
    empty_value!(
        &criteria.sse_kms_encrypted_objects.as_ref().expect("present").status,
        "SseKmsEncryptedObjects.Status",
    );

    let metrics = replication(enabled, "<Metrics><Status/></Metrics>").expect("metrics");
    empty_value!(&metrics.rules[0].destination.metrics.as_ref().expect("present").status, "Metrics.Status",);

    let time = replication(
        enabled,
        "<ReplicationTime><Status></Status><Time><Minutes>15</Minutes></Time></ReplicationTime>",
    )
    .expect("replication time");
    empty_value!(
        &time.rules[0].destination.replication_time.as_ref().expect("present").status,
        "ReplicationTime.Status",
    );
}

/// Positive — `RequestPaymentConfiguration.Payer`, which legacy RustFS stores empty.
#[test]
fn an_empty_payer_is_decoded_as_the_empty_value() {
    let input = decode::<dto::PutBucketRequestPayment>(
        "/photos?requestPayment",
        TargetKind::Bucket,
        "<RequestPaymentConfiguration><Payer></Payer></RequestPaymentConfiguration>",
    )
    .expect("payer");
    empty_value!(&input.request_payment_configuration.payer, "RequestPaymentConfiguration.Payer");
}

/// Positive — `ServerSideEncryptionByDefault.SSEAlgorithm`.
#[test]
fn an_empty_default_encryption_algorithm_is_decoded_as_the_empty_value() {
    let input = decode::<dto::PutBucketEncryption>(
        "/photos?encryption",
        TargetKind::Bucket,
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm/>\
         </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
    )
    .expect("algorithm");
    let rule = &input.server_side_encryption_configuration.rules[0];
    empty_value!(
        &rule
            .apply_server_side_encryption_by_default
            .as_ref()
            .expect("present")
            .sse_algorithm,
        "ServerSideEncryptionByDefault.SSEAlgorithm",
    );
}

/// Positive — the three required enumerations of a restore request.
#[test]
fn an_empty_restore_enumeration_is_decoded_as_the_empty_value() {
    let tier =
        restore("<RestoreRequest><Days>1</Days><GlacierJobParameters><Tier></Tier></GlacierJobParameters></RestoreRequest>")
            .expect("tier");
    empty_value!(&tier.glacier_job_parameters.as_ref().expect("present").tier, "GlacierJobParameters.Tier");

    let expression = restore(
        "<RestoreRequest><Type>SELECT</Type><SelectParameters><InputSerialization><CSV/></InputSerialization>\
         <ExpressionType/><Expression>SELECT * FROM S3Object</Expression><OutputSerialization><CSV/></OutputSerialization>\
         </SelectParameters></RestoreRequest>",
    )
    .expect("expression type");
    empty_value!(
        &expression.select_parameters.as_ref().expect("present").expression_type,
        "SelectParameters.ExpressionType",
    );

    let encryption = restore(
        "<RestoreRequest><Type>SELECT</Type><OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix>\
         <Encryption><EncryptionType></EncryptionType></Encryption></S3></OutputLocation></RestoreRequest>",
    )
    .expect("encryption type");
    let location = encryption.output_location.as_ref().expect("location");
    empty_value!(
        &location
            .s3
            .as_ref()
            .expect("s3")
            .encryption
            .as_ref()
            .expect("present")
            .encryption_type,
        "Encryption.EncryptionType",
    );
}

/// Positive — `SelectObjectContent`'s operation-level `ExpressionType`.
#[test]
fn an_empty_select_expression_type_is_decoded_as_the_empty_value() {
    let input = decode::<dto::SelectObjectContent>(
        "/photos/key?select&select-type=2",
        TargetKind::Object,
        "<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType></ExpressionType>\
         <InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization>\
         </SelectObjectContentRequest>",
    )
    .expect("expression type");
    empty_value!(&input.expression_type, "SelectObjectContent.ExpressionType");
}

// ── controls ──────────────────────────────────────────────────────────────────────────────────

/// Negative — a required status that is absent is still the schema's `MalformedXML`: the empty
/// value is a value, and no value is not.
#[test]
fn n_an_absent_required_status_is_still_malformed() {
    refused_as_malformed(lifecycle(""), "LifecycleRule.Status");
    refused_as_malformed(replication("", ""), "ReplicationRule.Status");
    refused_as_malformed(
        replication("<Status>Enabled</Status><DeleteReplication></DeleteReplication>", ""),
        "DeleteReplication.Status",
    );
    refused_as_malformed(replication("<Status>Enabled</Status>", "<Metrics></Metrics>"), "Metrics.Status");
    refused_as_malformed(
        decode::<dto::PutBucketRequestPayment>(
            "/photos?requestPayment",
            TargetKind::Bucket,
            "<RequestPaymentConfiguration></RequestPaymentConfiguration>",
        ),
        "RequestPaymentConfiguration.Payer",
    );
    refused_as_malformed(
        restore("<RestoreRequest><Days>1</Days><GlacierJobParameters></GlacierJobParameters></RestoreRequest>"),
        "GlacierJobParameters.Tier",
    );
}

/// Negative — no empty required enumeration anywhere is answered with this side's `500`.
#[test]
fn n_no_empty_required_enumeration_is_an_internal_error() {
    let outcomes: Vec<(&str, Result<(), CodecError>)> = vec![
        ("lifecycle", lifecycle("<Status/>").map(|_| ())),
        ("replication", replication("<Status/>", "").map(|_| ())),
        (
            "payer",
            decode::<dto::PutBucketRequestPayment>(
                "/photos?requestPayment",
                TargetKind::Bucket,
                "<RequestPaymentConfiguration><Payer/></RequestPaymentConfiguration>",
            )
            .map(|_| ()),
        ),
        (
            "tier",
            restore("<RestoreRequest><Days>1</Days><GlacierJobParameters><Tier/></GlacierJobParameters></RestoreRequest>")
                .map(|_| ()),
        ),
    ];
    for (position, outcome) in outcomes {
        if let Err(error) = outcome {
            assert_ne!(error.code(), &ErrorCode::INTERNAL_ERROR, "{position}: {error}");
            assert!(error.status().is_client_error(), "{position}: {error}");
        }
    }
}

/// Negative — the placeholder itself is still refused at the decode exit: the fix gives the
/// client's empty value a spelling of its own, it does not stop the guard from recognising a
/// member the decoder never filled.
#[test]
fn n_a_defaulted_required_enumeration_is_still_a_placeholder_the_exit_check_refuses() {
    let rule = dto::LifecycleRule::default();
    assert!(rule.status.is_wire_placeholder());
    let refused = rule.check_required().expect_err("the placeholder status must be refused");
    assert_eq!(refused.member(), "Status");

    let filled = dto::LifecycleRule {
        status: dto::Status::custom(""),
        ..Default::default()
    };
    assert_eq!(filled.check_required(), Ok(()), "the empty wire value is a filled member");
}

/// Negative — the empty value and the placeholder render alike but are not the same value: a
/// handler comparing against `Default::default()` must not mistake a client's empty status for a
/// member nobody filled.
#[test]
fn n_the_empty_value_is_not_equal_to_the_placeholder() {
    let empty = dto::Status::custom("");
    let placeholder = dto::Status::default();
    assert_ne!(empty, placeholder);
    assert_eq!(empty.as_str(), placeholder.as_str(), "both render as the empty string");
    assert!(!empty.is_known());
    assert!(!placeholder.is_known());
    assert_ne!(
        format!("{empty:?}"),
        format!("{placeholder:?}"),
        "a diagnostic can tell a client's empty value from a member nobody filled"
    );
    assert_eq!(empty.to_string(), placeholder.to_string(), "Display renders both as nothing");
}
