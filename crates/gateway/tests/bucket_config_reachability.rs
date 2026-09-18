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

//! Every argument of the bucket-configuration, notification and website contracts, built out of
//! a decoded request and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call*
//! [`validate_versioning`], [`validate_accelerate`], [`validate_request_payment`],
//! [`validate_logging`], [`validate_notification`] and [`validate_website`] from the one
//! document member each `Req<PutBucket…>` carries — and, the load-bearing half, that the
//! generated decoder does **not** pre-empt them: a `Status` outside the switch set, a `Payer`
//! outside its pair and a whole-site redirect beside an index document all decode, reach the
//! handler, and are the contract's refusal with the contract's code.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `ops/shared/{bucket_config,bucket_notification,bucket_website}.rs` inline tests, or the wire
//! shapes, which `conformance/cases/` pin.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the exported
//! surface open with the acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** These six contracts take one decoded document each, so
//! the constructibility half is trivially met; what was never checked is the third failure class
//! the issue names — "exported and callable, but the codec pre-empts it". The bucket-config band
//! is where that class is most likely, because its enum members (`Status`, `Payer`, `Protocol`)
//! are the ones a stricter codec would refuse before any handler saw them. The codec is lenient
//! by design (RustFS parses these documents fail-open), and this file is what pins the leniency
//! on the request side so the contracts stay reachable.

use rustfs_gateway::{
    BucketConfigRejection, ErrorCode, MetaView, NotificationRejection, OperationCodec, RequestBody, TargetKind, WebsiteRejection,
    dto, validate_accelerate, validate_logging, validate_notification, validate_request_payment, validate_versioning,
    validate_website,
};

use super::tagging_reachability::{accepted, content_md5};

/// The integrity headers the four `httpChecksumRequired` writes below need; the two that do not
/// require them (`?accelerate`, `?notification`) accept them all the same.
fn integrity(body: &[u8]) -> [(&'static str, &'static str); 2] {
    let digest: &'static str = Box::leak(content_md5(body).into_boxed_str());
    [("content-type", "application/xml"), ("content-md5", digest)]
}

/// A bucket-level write of `document` to `?{subresource}`, decoded as `O`.
fn decoded<O: OperationCodec>(subresource: &str, document: &'static str) -> O::Input {
    let uri: &'static str = Box::leak(format!("http://host.invalid/conf-config?{subresource}").into_boxed_str());
    let request = accepted("PUT", uri, &integrity(document.as_bytes()));
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has one label");
    O::decode(&view, RequestBody::Buffered(document.as_bytes().into()))
        .expect("a well-formed document with a value outside the contract's set is not the decoder's refusal")
}

// ---------------------------------------------------------------------------------------------
// The bucket-configuration band: versioning, accelerate, request payment, logging
// ---------------------------------------------------------------------------------------------

/// Positive and negative in one: `Enabled` reaches the handler and passes; `Bogus` also reaches
/// the handler — the decoder keeps the string — and is the contract's `MalformedXML`, never a
/// refusal the codec made on its own.
#[test]
fn n_a_versioning_status_outside_the_switch_set_is_the_contracts_refusal() {
    let enabled = decoded::<dto::PutBucketVersioning>(
        "versioning",
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    );
    validate_versioning(&enabled.versioning_configuration).expect("Enabled is in the set");

    let bogus = decoded::<dto::PutBucketVersioning>(
        "versioning",
        "<VersioningConfiguration><Status>Bogus</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>",
    );
    let rejection = validate_versioning(&bogus.versioning_configuration).expect_err("Bogus is not");
    assert_eq!(rejection, BucketConfigRejection::StatusUnknown);
    assert_eq!(rejection.code(), ErrorCode::MALFORMED_XML);

    let mfa = decoded::<dto::PutBucketVersioning>(
        "versioning",
        "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Maybe</MfaDelete></VersioningConfiguration>",
    );
    assert_eq!(
        validate_versioning(&mfa.versioning_configuration),
        Err(BucketConfigRejection::MfaDeleteUnknown),
        "the second member is checked after the first passes"
    );
}

/// Negative — `?accelerate` declares no integrity requirement and shares the switch set; an
/// unknown `Status` reaches the contract the same way.
#[test]
fn n_an_accelerate_status_outside_the_switch_set_is_the_contracts_refusal() {
    let suspended = decoded::<dto::PutBucketAccelerateConfiguration>(
        "accelerate",
        "<AccelerateConfiguration><Status>Suspended</Status></AccelerateConfiguration>",
    );
    validate_accelerate(&suspended.accelerate_configuration).expect("Suspended is in the set");
    let off = decoded::<dto::PutBucketAccelerateConfiguration>(
        "accelerate",
        "<AccelerateConfiguration><Status>Off</Status></AccelerateConfiguration>",
    );
    assert_eq!(
        validate_accelerate(&off.accelerate_configuration),
        Err(BucketConfigRejection::StatusUnknown)
    );
}

/// Negative — `Payer` is a required member with a two-value set; a third value decodes and is
/// the contract's `InvalidArgument`, not the codec's.
#[test]
fn n_a_payer_outside_the_pair_is_the_contracts_refusal() {
    let requester = decoded::<dto::PutBucketRequestPayment>(
        "requestPayment",
        "<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>",
    );
    validate_request_payment(&requester.request_payment_configuration).expect("Requester is in the pair");
    let nobody = decoded::<dto::PutBucketRequestPayment>(
        "requestPayment",
        "<RequestPaymentConfiguration><Payer>Nobody</Payer></RequestPaymentConfiguration>",
    );
    let rejection = validate_request_payment(&nobody.request_payment_configuration).expect_err("Nobody is not");
    assert_eq!(rejection, BucketConfigRejection::PayerUnknown);
    assert_eq!(rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// Negative — an empty `TargetBucket` decodes as an empty string, not a refusal, and the
/// contract is what refuses it; an absent `LoggingEnabled` (logging switched off) passes.
#[test]
fn n_an_empty_logging_target_is_the_contracts_refusal() {
    let off = decoded::<dto::PutBucketLogging>("logging", "<BucketLoggingStatus></BucketLoggingStatus>");
    assert!(off.bucket_logging_status.logging_enabled.is_none());
    validate_logging(&off.bucket_logging_status).expect("logging off is a valid status");
    let empty = decoded::<dto::PutBucketLogging>(
        "logging",
        "<BucketLoggingStatus><LoggingEnabled><TargetBucket></TargetBucket><TargetPrefix>p/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>",
    );
    assert_eq!(
        validate_logging(&empty.bucket_logging_status),
        Err(BucketConfigRejection::LoggingTargetEmpty)
    );
}

// ---------------------------------------------------------------------------------------------
// Notification and website
// ---------------------------------------------------------------------------------------------

/// Positive and negative — an unknown event name is *accepted* (the contract's leniency is the
/// point), while a configuration with no destination reaches the contract and is refused.
#[test]
fn n_a_notification_with_no_destination_is_the_contracts_refusal_and_an_unknown_event_is_not() {
    let unknown_event = decoded::<dto::PutBucketNotificationConfiguration>(
        "notification",
        "<NotificationConfiguration><TopicConfiguration><Topic>arn:aws:sns:us-east-1:1:t</Topic><Event>s3:SomethingNew:*</Event></TopicConfiguration></NotificationConfiguration>",
    );
    assert_eq!(unknown_event.notification_configuration.topic_configurations.len(), 1);
    validate_notification(&unknown_event.notification_configuration).expect("an unknown event name is accepted");
    let no_destination = decoded::<dto::PutBucketNotificationConfiguration>(
        "notification",
        "<NotificationConfiguration><TopicConfiguration><Topic></Topic><Event>s3:ObjectCreated:*</Event></TopicConfiguration></NotificationConfiguration>",
    );
    assert_eq!(
        validate_notification(&no_destination.notification_configuration),
        Err(NotificationRejection::DestinationEmpty)
    );
}

/// Negative — a whole-site redirect beside an index document decodes as both members present,
/// and the exclusion is the contract's `MalformedXML`; the redirect alone passes.
#[test]
fn n_a_redirect_beside_documents_is_the_contracts_refusal() {
    let redirect_only = decoded::<dto::PutBucketWebsite>(
        "website",
        "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.invalid</HostName></RedirectAllRequestsTo></WebsiteConfiguration>",
    );
    validate_website(&redirect_only.website_configuration).expect("a redirect alone is a site");
    let both = decoded::<dto::PutBucketWebsite>(
        "website",
        "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.invalid</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>",
    );
    assert!(both.website_configuration.redirect_all_requests_to.is_some());
    assert!(both.website_configuration.index_document.is_some());
    let rejection = validate_website(&both.website_configuration).expect_err("the exclusion holds");
    assert_eq!(rejection, WebsiteRejection::RedirectAllWithDocuments);
    assert_eq!(rejection.code(), ErrorCode::MALFORMED_XML);
    let ftp = decoded::<dto::PutBucketWebsite>(
        "website",
        "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.invalid</HostName><Protocol>ftp</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>",
    );
    assert_eq!(
        validate_website(&ftp.website_configuration),
        Err(WebsiteRejection::ProtocolUnknown),
        "a protocol outside the pair decodes and is the contract's"
    );
}
