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

//! Bucket-configuration read-backs written by the legacy stack's service and by the gateway's
//! encoder in the RustFS response layout, compared byte for byte (rustfs/gateway#1078, row 5).
//!
//! Responsible for: an answer RustFS built for each configuration read, carrying every member the
//! gateway carries, written by the legacy stack exactly as the gateway writes it under
//! `MetaView::with_rustfs_response_layout` — the declaration, every element's children in the
//! legacy order, every text — and written differently under the default layout, which keeps the
//! model's order and the declaration's line end.
//! NOT responsible for: the order each structure is given (the generator, `emit::codec::encode`),
//! or the request documents (`request_documents`).
//! Upstream: the harness, the generated seam. Downstream: nothing.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use rustfs_gateway_core::codec::{EncodedResponse, MetaView, OperationCodec, ResponseBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::s3s::{Body as LegacyBody, S3, S3Request, S3Response, S3Result, service::S3ServiceBuilder};
use super::seam::generated::ops::{
    get_bucket_accelerate_configuration, get_bucket_acl, get_bucket_cors, get_bucket_encryption,
    get_bucket_lifecycle_configuration, get_bucket_logging, get_bucket_replication, get_bucket_request_payment,
    get_bucket_tagging, get_bucket_versioning, get_bucket_website, get_object_acl, get_object_legal_hold,
    get_object_lock_configuration, get_object_retention, get_object_tagging, get_public_access_block,
};
use super::{HOST, block_on, oracle};

type Answer<T> = Pin<Box<dyn Future<Output = S3Result<S3Response<T>>> + Send + 'static>>;

/// The declaration the default layout opens a document with, its line end included.
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// A legacy-stack backend answering each configuration read with the output it was built with.
#[derive(Default)]
struct Answering {
    lifecycle: oracle::GetBucketLifecycleConfigurationOutput,
    replication: oracle::GetBucketReplicationOutput,
    versioning: oracle::GetBucketVersioningOutput,
    encryption: oracle::GetBucketEncryptionOutput,
    tagging: oracle::GetBucketTaggingOutput,
    cors: oracle::GetBucketCorsOutput,
    website: oracle::GetBucketWebsiteOutput,
    accelerate: oracle::GetBucketAccelerateConfigurationOutput,
    acl: oracle::GetBucketAclOutput,
    logging: oracle::GetBucketLoggingOutput,
    request_payment: oracle::GetBucketRequestPaymentOutput,
    object_lock: oracle::GetObjectLockConfigurationOutput,
    public_access_block: oracle::GetPublicAccessBlockOutput,
    object_tagging: oracle::GetObjectTaggingOutput,
    retention: oracle::GetObjectRetentionOutput,
    legal_hold: oracle::GetObjectLegalHoldOutput,
    object_acl: oracle::GetObjectAclOutput,
}

fn answer<T: Send + 'static>(output: T) -> Answer<T> {
    Box::pin(async move { Ok(S3Response::new(output)) })
}

impl S3 for Answering {
    // The pinned trait is declared with `#[async_trait]`; these are the signatures that attribute
    // expands a `&self` method to, as in the PutObject harness.
    fn get_bucket_lifecycle_configuration<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketLifecycleConfigurationInput>,
    ) -> Answer<oracle::GetBucketLifecycleConfigurationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.lifecycle.clone())
    }

    fn get_bucket_replication<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketReplicationInput>,
    ) -> Answer<oracle::GetBucketReplicationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.replication.clone())
    }

    fn get_bucket_versioning<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketVersioningInput>,
    ) -> Answer<oracle::GetBucketVersioningOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.versioning.clone())
    }

    fn get_bucket_encryption<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketEncryptionInput>,
    ) -> Answer<oracle::GetBucketEncryptionOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.encryption.clone())
    }

    fn get_bucket_tagging<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketTaggingInput>,
    ) -> Answer<oracle::GetBucketTaggingOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.tagging.clone())
    }

    fn get_bucket_cors<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketCorsInput>,
    ) -> Answer<oracle::GetBucketCorsOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.cors.clone())
    }

    fn get_bucket_website<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketWebsiteInput>,
    ) -> Answer<oracle::GetBucketWebsiteOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.website.clone())
    }

    fn get_bucket_accelerate_configuration<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketAccelerateConfigurationInput>,
    ) -> Answer<oracle::GetBucketAccelerateConfigurationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.accelerate.clone())
    }

    fn get_bucket_acl<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketAclInput>,
    ) -> Answer<oracle::GetBucketAclOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.acl.clone())
    }

    fn get_bucket_logging<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketLoggingInput>,
    ) -> Answer<oracle::GetBucketLoggingOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.logging.clone())
    }

    fn get_bucket_request_payment<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetBucketRequestPaymentInput>,
    ) -> Answer<oracle::GetBucketRequestPaymentOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.request_payment.clone())
    }

    fn get_object_lock_configuration<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetObjectLockConfigurationInput>,
    ) -> Answer<oracle::GetObjectLockConfigurationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.object_lock.clone())
    }

    fn get_public_access_block<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetPublicAccessBlockInput>,
    ) -> Answer<oracle::GetPublicAccessBlockOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.public_access_block.clone())
    }

    fn get_object_tagging<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetObjectTaggingInput>,
    ) -> Answer<oracle::GetObjectTaggingOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.object_tagging.clone())
    }

    fn get_object_retention<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetObjectRetentionInput>,
    ) -> Answer<oracle::GetObjectRetentionOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.retention.clone())
    }

    fn get_object_legal_hold<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetObjectLegalHoldInput>,
    ) -> Answer<oracle::GetObjectLegalHoldOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.legal_hold.clone())
    }

    fn get_object_acl<'life0, 'future>(
        &'life0 self,
        _request: S3Request<oracle::GetObjectAclInput>,
    ) -> Answer<oracle::GetObjectAclOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        answer(self.object_acl.clone())
    }
}

/// The body the legacy stack's service answers `GET /{target}` with.
fn legacy(target: &str, answering: Answering) -> String {
    let service = S3ServiceBuilder::new(answering).build();
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://{HOST}/{target}"))
        .header("host", HOST)
        .body(LegacyBody::from(Bytes::new()))
        .expect("a fixture request");
    let response = block_on(service.call(request)).expect("the legacy service answers");
    let (_, mut body) = response.into_parts();
    let bytes = block_on(body.store_all_limited(1 << 20)).expect("the legacy answer's body");
    String::from_utf8(bytes.to_vec()).expect("a UTF-8 document")
}

/// The body the gateway's encoder answers `GET /{target}` with, in either layout.
fn gateway<O: OperationCodec>(target: &str, output: O::Output, rustfs_layout: bool) -> String {
    let head = http::Request::builder()
        .method("GET")
        .uri(format!("http://{HOST}/{target}"))
        .header("host", HOST)
        .body(())
        .expect("a fixture head");
    let wire = WireRequest::accept(head, &Limits::default()).expect("an accepted fixture head");
    let kind = if target.split('?').next().is_some_and(|path| path.contains('/')) {
        TargetKind::Object
    } else {
        TargetKind::Bucket
    };
    let view = MetaView::of(&wire, kind).expect("request metadata");
    let view = if rustfs_layout {
        view.with_rustfs_response_layout()
    } else {
        view
    };
    let encoded: EncodedResponse = O::encode(output, &view, 200).expect("the gateway encodes the configuration");
    match encoded.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes).expect("a UTF-8 document"),
        other => panic!("a bucket configuration is a complete document, not {other:?}"),
    }
}

fn tag(key: &str, value: &str) -> oracle::Tag {
    oracle::Tag {
        key: Some(key.to_owned()),
        value: Some(value.to_owned()),
    }
}

fn lifecycle() -> oracle::GetBucketLifecycleConfigurationOutput {
    oracle::GetBucketLifecycleConfigurationOutput {
        rules: Some(vec![
            oracle::LifecycleRule {
                abort_incomplete_multipart_upload: Some(oracle::AbortIncompleteMultipartUpload {
                    days_after_initiation: Some(3),
                }),
                del_marker_expiration: Some(oracle::DelMarkerExpiration { days: Some(7) }),
                expiration: Some(oracle::LifecycleExpiration {
                    days: Some(30),
                    expired_object_all_versions: Some(true),
                    ..Default::default()
                }),
                filter: Some(oracle::LifecycleRuleFilter {
                    and: Some(oracle::LifecycleRuleAndOperator {
                        object_size_greater_than: Some(10),
                        object_size_less_than: Some(1000),
                        prefix: Some("logs/".to_owned()),
                        tags: Some(vec![tag("k", "v")]),
                    }),
                    ..Default::default()
                }),
                id: Some("rule-one".to_owned()),
                noncurrent_version_expiration: Some(oracle::NoncurrentVersionExpiration {
                    noncurrent_days: Some(9),
                    newer_noncurrent_versions: Some(2),
                }),
                noncurrent_version_transitions: Some(vec![oracle::NoncurrentVersionTransition {
                    noncurrent_days: Some(5),
                    storage_class: Some("GLACIER".to_owned().into()),
                    newer_noncurrent_versions: Some(1),
                }]),
                prefix: None,
                status: "Enabled".to_owned().into(),
                transitions: Some(vec![
                    oracle::Transition {
                        days: Some(10),
                        storage_class: Some("GLACIER".to_owned().into()),
                        date: None,
                    },
                    oracle::Transition {
                        days: Some(20),
                        storage_class: Some("DEEP_ARCHIVE".to_owned().into()),
                        date: None,
                    },
                ]),
            },
            oracle::LifecycleRule {
                expiration: Some(oracle::LifecycleExpiration {
                    expired_object_delete_marker: Some(true),
                    ..Default::default()
                }),
                filter: Some(oracle::LifecycleRuleFilter {
                    prefix: Some("tmp/".to_owned()),
                    ..Default::default()
                }),
                id: Some("rule-two".to_owned()),
                status: "Disabled".to_owned().into(),
                abort_incomplete_multipart_upload: None,
                del_marker_expiration: None,
                noncurrent_version_expiration: None,
                noncurrent_version_transitions: None,
                prefix: None,
                transitions: None,
            },
        ]),
        ..Default::default()
    }
}

fn replication() -> oracle::GetBucketReplicationOutput {
    oracle::GetBucketReplicationOutput {
        replication_configuration: Some(oracle::ReplicationConfiguration {
            role: "arn:aws:iam::1:role/replication".to_owned(),
            rules: vec![oracle::ReplicationRule {
                delete_marker_replication: Some(oracle::DeleteMarkerReplication {
                    status: Some("Enabled".to_owned().into()),
                }),
                destination: oracle::Destination {
                    bucket: "arn:aws:s3:::replica".to_owned(),
                    storage_class: Some("STANDARD".to_owned().into()),
                    ..Default::default()
                },
                filter: Some(oracle::ReplicationRuleFilter {
                    prefix: Some("docs/".to_owned()),
                    ..Default::default()
                }),
                id: Some("replicate".to_owned()),
                priority: Some(1),
                status: "Enabled".to_owned().into(),
                delete_replication: None,
                existing_object_replication: None,
                prefix: None,
                source_selection_criteria: None,
            }],
        }),
    }
}

fn encryption() -> oracle::GetBucketEncryptionOutput {
    oracle::GetBucketEncryptionOutput {
        server_side_encryption_configuration: Some(oracle::ServerSideEncryptionConfiguration {
            rules: vec![oracle::ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: Some(oracle::ServerSideEncryptionByDefault {
                    kms_master_key_id: Some("arn:aws:kms:us-east-1:1:key/k".to_owned()),
                    sse_algorithm: "aws:kms".to_owned().into(),
                }),
                bucket_key_enabled: Some(true),
                ..Default::default()
            }],
        }),
    }
}

fn cors() -> oracle::GetBucketCorsOutput {
    oracle::GetBucketCorsOutput {
        cors_rules: Some(vec![oracle::CORSRule {
            allowed_headers: Some(vec!["*".to_owned()]),
            allowed_methods: vec!["GET".to_owned(), "PUT".to_owned()],
            allowed_origins: vec!["https://example.com".to_owned()],
            expose_headers: Some(vec!["ETag".to_owned()]),
            id: Some("cors-rule".to_owned()),
            max_age_seconds: Some(300),
        }]),
    }
}

fn website() -> oracle::GetBucketWebsiteOutput {
    oracle::GetBucketWebsiteOutput {
        error_document: Some(oracle::ErrorDocument {
            key: "error.html".to_owned(),
        }),
        index_document: Some(oracle::IndexDocument {
            suffix: "index.html".to_owned(),
        }),
        routing_rules: Some(vec![oracle::RoutingRule {
            condition: Some(oracle::Condition {
                http_error_code_returned_equals: Some("404".to_owned()),
                key_prefix_equals: Some("docs/".to_owned()),
            }),
            redirect: oracle::Redirect {
                host_name: Some("example.com".to_owned()),
                http_redirect_code: Some("301".to_owned()),
                protocol: Some("https".to_owned().into()),
                replace_key_prefix_with: Some("documents/".to_owned()),
                replace_key_with: None,
            },
        }]),
        ..Default::default()
    }
}

/// One read-back: its target, the legacy stack's answer, and the gateway's in both layouts.
type ReadBack = (&'static str, String, [String; 2]);

fn read_back<O: OperationCodec>(target: &'static str, answering: Answering, converted: O::Output) -> ReadBack
where
    O::Output: Clone,
{
    (
        target,
        legacy(target, answering),
        [
            gateway::<O>(target, converted.clone(), true),
            gateway::<O>(target, converted, false),
        ],
    )
}

fn grantee(id: &str) -> oracle::Grantee {
    oracle::Grantee {
        display_name: Some("owner".to_owned()),
        email_address: None,
        id: Some(id.to_owned()),
        type_: "CanonicalUser".to_owned().into(),
        uri: None,
    }
}

/// Every read-back the differential compares.
fn read_backs() -> Vec<ReadBack> {
    let versioning = oracle::GetBucketVersioningOutput {
        mfa_delete: Some("Disabled".to_owned().into()),
        status: Some("Enabled".to_owned().into()),
    };
    let tagging = oracle::GetBucketTaggingOutput {
        tag_set: vec![tag("project", "gateway"), tag("stage", "one")],
    };
    let accelerate = oracle::GetBucketAccelerateConfigurationOutput {
        status: Some("Enabled".to_owned().into()),
        ..Default::default()
    };
    let acl = oracle::GetBucketAclOutput {
        grants: Some(vec![oracle::Grant {
            grantee: Some(grantee("owner-id")),
            permission: Some("FULL_CONTROL".to_owned().into()),
        }]),
        owner: Some(oracle::Owner {
            display_name: Some("owner".to_owned()),
            id: Some("owner-id".to_owned()),
        }),
    };
    let request_payment = oracle::GetBucketRequestPaymentOutput {
        payer: Some("BucketOwner".to_owned().into()),
    };
    let object_lock = oracle::GetObjectLockConfigurationOutput {
        object_lock_configuration: Some(oracle::ObjectLockConfiguration {
            object_lock_enabled: Some("Enabled".to_owned().into()),
            rule: Some(oracle::ObjectLockRule {
                default_retention: Some(oracle::DefaultRetention {
                    days: Some(30),
                    mode: Some("GOVERNANCE".to_owned().into()),
                    years: None,
                }),
            }),
        }),
    };
    let public_access_block = oracle::GetPublicAccessBlockOutput {
        public_access_block_configuration: Some(oracle::PublicAccessBlockConfiguration {
            block_public_acls: Some(true),
            block_public_policy: Some(false),
            ignore_public_acls: Some(true),
            restrict_public_buckets: Some(false),
        }),
    };
    let object_acl = oracle::GetObjectAclOutput {
        grants: acl.grants.clone(),
        owner: acl.owner.clone(),
        request_charged: None,
    };
    let object_tagging = oracle::GetObjectTaggingOutput {
        tag_set: vec![tag("kind", "photo")],
        version_id: None,
    };
    let retention = oracle::GetObjectRetentionOutput {
        retention: Some(oracle::ObjectLockRetention {
            mode: Some("COMPLIANCE".to_owned().into()),
            retain_until_date: Some(oracle::Timestamp::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_893_456_000_123),
            )),
        }),
    };
    let legal_hold = oracle::GetObjectLegalHoldOutput {
        legal_hold: Some(oracle::ObjectLockLegalHold {
            status: Some("ON".to_owned().into()),
        }),
    };
    vec![
        read_back::<dto::GetBucketLifecycleConfiguration>(
            "photos?lifecycle",
            Answering {
                lifecycle: lifecycle(),
                ..Default::default()
            },
            get_bucket_lifecycle_configuration::output_from_s3s(lifecycle()).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketReplication>(
            "photos?replication",
            Answering {
                replication: replication(),
                ..Default::default()
            },
            get_bucket_replication::output_from_s3s(replication()).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketVersioning>(
            "photos?versioning",
            Answering {
                versioning: versioning.clone(),
                ..Default::default()
            },
            get_bucket_versioning::output_from_s3s(versioning).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketEncryption>(
            "photos?encryption",
            Answering {
                encryption: encryption(),
                ..Default::default()
            },
            get_bucket_encryption::output_from_s3s(encryption()).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketTagging>(
            "photos?tagging",
            Answering {
                tagging: tagging.clone(),
                ..Default::default()
            },
            get_bucket_tagging::output_from_s3s(tagging).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketCors>(
            "photos?cors",
            Answering {
                cors: cors(),
                ..Default::default()
            },
            get_bucket_cors::output_from_s3s(cors()).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketWebsite>(
            "photos?website",
            Answering {
                website: website(),
                ..Default::default()
            },
            get_bucket_website::output_from_s3s(website()).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketAccelerateConfiguration>(
            "photos?accelerate",
            Answering {
                accelerate: accelerate.clone(),
                ..Default::default()
            },
            get_bucket_accelerate_configuration::output_from_s3s(accelerate).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketAcl>(
            "photos?acl",
            Answering {
                acl: acl.clone(),
                ..Default::default()
            },
            get_bucket_acl::output_from_s3s(acl).expect("the seam carries it"),
        ),
        read_back::<dto::GetBucketRequestPayment>(
            "photos?requestPayment",
            Answering {
                request_payment: request_payment.clone(),
                ..Default::default()
            },
            get_bucket_request_payment::output_from_s3s(request_payment).expect("the seam carries it"),
        ),
        read_back::<dto::GetObjectLockConfiguration>(
            "photos?object-lock",
            Answering {
                object_lock: object_lock.clone(),
                ..Default::default()
            },
            get_object_lock_configuration::output_from_s3s(object_lock).expect("the seam carries it"),
        ),
        read_back::<dto::GetPublicAccessBlock>(
            "photos?publicAccessBlock",
            Answering {
                public_access_block: public_access_block.clone(),
                ..Default::default()
            },
            get_public_access_block::output_from_s3s(public_access_block).expect("the seam carries it"),
        ),
        read_back::<dto::GetObjectTagging>(
            "photos/key?tagging",
            Answering {
                object_tagging: object_tagging.clone(),
                ..Default::default()
            },
            get_object_tagging::output_from_s3s(object_tagging).expect("the seam carries it"),
        ),
        read_back::<dto::GetObjectRetention>(
            "photos/key?retention",
            Answering {
                retention: retention.clone(),
                ..Default::default()
            },
            get_object_retention::output_from_s3s(retention).expect("the seam carries it"),
        ),
        read_back::<dto::GetObjectAcl>(
            "photos/key?acl",
            Answering {
                object_acl: object_acl.clone(),
                ..Default::default()
            },
            get_object_acl::output_from_s3s(object_acl).expect("the seam carries it"),
        ),
        read_back::<dto::GetObjectLegalHold>(
            "photos/key?legal-hold",
            Answering {
                legal_hold: legal_hold.clone(),
                ..Default::default()
            },
            get_object_legal_hold::output_from_s3s(legal_hold).expect("the seam carries it"),
        ),
    ]
}

/// Positive — every read-back written in the RustFS response layout is, byte for byte, the answer
/// the legacy stack writes for the same configuration.
#[test]
fn every_read_back_in_the_rustfs_layout_is_the_legacy_answer_byte_for_byte() {
    let mut differing = Vec::new();
    for (target, legacy, [rustfs, _]) in read_backs() {
        if rustfs != legacy {
            differing.push(format!("{target}\n  gateway {rustfs}\n  legacy  {legacy}"));
        }
    }
    assert!(differing.is_empty(), "{}", differing.join("\n"));
}

/// Negative — the default layout is not the legacy answer: it keeps the declaration's line end,
/// the model's order and the namespace on a payload root, and differs from the RustFS layout in
/// nothing but the layout — the same elements with the same text.
#[test]
fn n_the_default_layout_keeps_the_model_order_and_the_declaration_line_end() {
    for (target, legacy, [rustfs, default]) in read_backs() {
        assert_ne!(default, legacy, "{target}");
        assert!(default.starts_with(DECLARATION), "{target}: {default}");
        assert!(!rustfs.starts_with(DECLARATION), "{target}: {rustfs}");
        let namespace = " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
        let mut default_bytes: Vec<u8> = default
            .replacen(namespace, "", 1)
            .bytes()
            .filter(|byte| *byte != b'\n')
            .collect();
        let mut rustfs_bytes: Vec<u8> = rustfs.replacen(namespace, "", 1).bytes().collect();
        default_bytes.sort_unstable();
        rustfs_bytes.sort_unstable();
        assert_eq!(default_bytes, rustfs_bytes, "{target}: the layouts differ in more than order");
    }
    let lifecycle = read_backs()
        .into_iter()
        .find(|(target, ..)| *target == "photos?lifecycle")
        .expect("the lifecycle read-back");
    let [rustfs, default] = lifecycle.2;
    let rule = |document: &str| {
        let filter = document.find("<Filter>").expect("a filter");
        let id = document.find("<ID>").expect("an id");
        filter < id
    };
    assert!(rule(&rustfs), "legacy RustFS writes the rule's Filter before its ID: {rustfs}");
    assert!(!rule(&default), "the model writes the rule's ID before its Filter: {default}");
}

/// Positive — a logging configuration RustFS stored without `TargetGrants` is answered without the
/// element, and one stored with an empty list with the empty element, each byte for byte as the
/// legacy stack answers it: the gateway's list carries its presence (rustfs/gateway#1078). Outside
/// the layout both keep the empty wrapper every deployment has always written.
#[test]
fn a_logging_grant_list_is_written_as_the_legacy_stack_writes_it_set_or_not() {
    for target_grants in [None, Some(Vec::new())] {
        let logging = oracle::GetBucketLoggingOutput {
            logging_enabled: Some(oracle::LoggingEnabled {
                target_bucket: "logs".to_owned(),
                target_grants: target_grants.clone(),
                target_object_key_format: None,
                target_prefix: "access/".to_owned(),
            }),
        };
        let (_, legacy, [rustfs, default]) = read_back::<dto::GetBucketLogging>(
            "photos?logging",
            Answering {
                logging: logging.clone(),
                ..Default::default()
            },
            get_bucket_logging::output_from_s3s(logging).expect("the seam carries it"),
        );
        assert_eq!(rustfs, legacy, "{target_grants:?}");
        assert_eq!(legacy.contains("<TargetGrants></TargetGrants>"), target_grants.is_some(), "{legacy}");
        assert!(default.contains("<TargetGrants></TargetGrants>"), "{default}");
    }
}
