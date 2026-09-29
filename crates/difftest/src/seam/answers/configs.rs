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

//! Seam answer rows for the bucket configurations: every read, write and delete.
//!
//! Responsible for: rows that set every member of those operations' legacy outputs between them.
//! A read answers with the configuration the legacy stack reads from the same document the seam
//! decode rows write (`super::super::samples::configs`), which is what RustFS stores and returns.
//! NOT responsible for: judging (`tests/seam_outputs.rs`). Upstream: none. Downstream: `super`.

use crate::request::RawRequest;
use crate::s3s::dto as legacy;

use super::super::samples::configs::{
    BUCKET_ACL, CORS, ENCRYPTION, LIFECYCLE, LIFECYCLE_MINIO, LOGGING, NOTIFICATION, REPLICATION, REPLICATION_MINIO, WEBSITE,
    WEBSITE_REDIRECT, config,
};
use super::{AnswerRow, BARE, XML, answer, differs, legacy_document, named, reordered, same};

const POLICY: &str = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\
    \"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\"}]}";

/// The access control structures whose children the two stacks write in another order.
pub(super) const ACL_ORDERS: &[&str] = &[
    "AccessControlPolicy",
    "AccessControlPolicy/Owner",
    "AccessControlPolicy/AccessControlList/Grant[]/Grantee",
];

fn reads() -> Vec<AnswerRow> {
    vec![
        answer(
            "get-bucket-accelerate-every-member",
            RawRequest::get("/bucket?accelerate"),
            || legacy::GetBucketAccelerateConfigurationOutput {
                request_charged: Some(named("requester")),
                status: Some(named("Enabled")),
            },
            same(XML),
        ),
        answer(
            "get-bucket-acl-every-member",
            RawRequest::get("/bucket?acl"),
            || {
                let policy: legacy::AccessControlPolicy = legacy_document(BUCKET_ACL);
                legacy::GetBucketAclOutput {
                    grants: policy.grants,
                    owner: policy.owner,
                }
            },
            reordered(XML, ACL_ORDERS),
        ),
        answer(
            "get-bucket-cors-every-member",
            RawRequest::get("/bucket?cors"),
            || {
                let cors: legacy::CORSConfiguration = legacy_document(CORS);
                legacy::GetBucketCorsOutput {
                    cors_rules: Some(cors.cors_rules),
                }
            },
            reordered(XML, &["CORSConfiguration/CORSRule[]"]),
        ),
        answer(
            "get-bucket-encryption-every-member",
            RawRequest::get("/bucket?encryption"),
            || legacy::GetBucketEncryptionOutput {
                server_side_encryption_configuration: Some(legacy_document(ENCRYPTION)),
            },
            differs(
                XML,
                &["sa-0001"],
                &[
                    "ServerSideEncryptionConfiguration/Rule",
                    "ServerSideEncryptionConfiguration/Rule/ApplyServerSideEncryptionByDefault",
                ],
            ),
        ),
        answer(
            "get-bucket-lifecycle-every-aws-member",
            RawRequest::get("/bucket?lifecycle"),
            || {
                let lifecycle: legacy::BucketLifecycleConfiguration = legacy_document(LIFECYCLE);
                legacy::GetBucketLifecycleConfigurationOutput {
                    rules: Some(lifecycle.rules),
                    transition_default_minimum_object_size: Some(named("all_storage_classes_128K")),
                }
            },
            reordered(
                XML,
                &[
                    "LifecycleConfiguration/Rule[]",
                    "LifecycleConfiguration/Rule[]/Filter/And",
                    "LifecycleConfiguration/Rule[]/NoncurrentVersionExpiration",
                    "LifecycleConfiguration/Rule[]/NoncurrentVersionTransition",
                ],
            ),
        ),
        answer(
            "get-bucket-lifecycle-minio-members",
            RawRequest::get("/bucket?lifecycle"),
            || {
                let lifecycle: legacy::BucketLifecycleConfiguration = legacy_document(LIFECYCLE_MINIO);
                legacy::GetBucketLifecycleConfigurationOutput {
                    rules: Some(lifecycle.rules),
                    transition_default_minimum_object_size: None,
                }
            },
            reordered(XML, &["LifecycleConfiguration/Rule"]),
        ),
        answer(
            "get-bucket-logging-every-member",
            RawRequest::get("/bucket?logging"),
            || {
                let status: legacy::BucketLoggingStatus = legacy_document(LOGGING);
                legacy::GetBucketLoggingOutput {
                    logging_enabled: status.logging_enabled,
                }
            },
            reordered(
                XML,
                &[
                    "BucketLoggingStatus/LoggingEnabled",
                    "BucketLoggingStatus/LoggingEnabled/TargetGrants/Grant[]/Grantee",
                ],
            ),
        ),
        answer(
            "get-bucket-logging-simple-prefix",
            RawRequest::get("/bucket?logging"),
            || {
                let status: legacy::BucketLoggingStatus = legacy_document(
                    "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>b/</TargetPrefix>\
                     <TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>",
                );
                legacy::GetBucketLoggingOutput {
                    logging_enabled: status.logging_enabled,
                }
            },
            differs(XML, &["sa-0010"], &["BucketLoggingStatus/LoggingEnabled"]),
        ),
        answer(
            "get-bucket-notification-every-member",
            RawRequest::get("/bucket?notification"),
            || {
                let notification: legacy::NotificationConfiguration = legacy_document(NOTIFICATION);
                legacy::GetBucketNotificationConfigurationOutput {
                    event_bridge_configuration: notification.event_bridge_configuration,
                    lambda_function_configurations: notification.lambda_function_configurations,
                    queue_configurations: notification.queue_configurations,
                    topic_configurations: notification.topic_configurations,
                }
            },
            reordered(
                XML,
                &[
                    "NotificationConfiguration",
                    "NotificationConfiguration/CloudFunctionConfiguration",
                    "NotificationConfiguration/QueueConfiguration",
                    "NotificationConfiguration/TopicConfiguration",
                ],
            ),
        ),
        answer(
            "get-bucket-notification-event-bridge",
            RawRequest::get("/bucket?notification"),
            || legacy::GetBucketNotificationConfigurationOutput {
                event_bridge_configuration: Some(legacy::EventBridgeConfiguration {}),
                ..Default::default()
            },
            same(XML),
        ),
        answer(
            "get-bucket-policy-every-member",
            RawRequest::get("/bucket?policy"),
            || legacy::GetBucketPolicyOutput {
                policy: Some(POLICY.to_owned()),
            },
            differs(BARE, &["sa-0012"], &[]),
        ),
        answer(
            "get-bucket-policy-status-every-member",
            RawRequest::get("/bucket?policyStatus"),
            || legacy::GetBucketPolicyStatusOutput {
                policy_status: Some(legacy::PolicyStatus { is_public: Some(true) }),
            },
            differs(XML, &["sa-0002"], &[]),
        ),
        answer(
            "get-bucket-replication-every-aws-member",
            RawRequest::get("/bucket?replication"),
            || legacy::GetBucketReplicationOutput {
                replication_configuration: Some(legacy_document(REPLICATION)),
            },
            differs(
                XML,
                &["sa-0003"],
                &[
                    "ReplicationConfiguration/Rule[]",
                    "ReplicationConfiguration/Rule[]/Destination",
                    "ReplicationConfiguration/Rule[]/Destination/Metrics",
                    "ReplicationConfiguration/Rule[]/SourceSelectionCriteria",
                ],
            ),
        ),
        answer(
            "get-bucket-replication-minio-members",
            RawRequest::get("/bucket?replication"),
            || legacy::GetBucketReplicationOutput {
                replication_configuration: Some(legacy_document(REPLICATION_MINIO)),
            },
            differs(XML, &["sa-0003"], &["ReplicationConfiguration/Rule"]),
        ),
        answer(
            "get-bucket-request-payment-every-member",
            RawRequest::get("/bucket?requestPayment"),
            || legacy::GetBucketRequestPaymentOutput {
                payer: Some(named("Requester")),
            },
            same(XML),
        ),
        answer(
            "get-bucket-tagging-every-member",
            RawRequest::get("/bucket?tagging"),
            || legacy::GetBucketTaggingOutput {
                tag_set: vec![
                    legacy::Tag {
                        key: Some("project".to_owned()),
                        value: Some("gateway".to_owned()),
                    },
                    legacy::Tag {
                        key: Some("empty".to_owned()),
                        value: Some(String::new()),
                    },
                ],
            },
            same(XML),
        ),
        answer(
            "get-bucket-website-every-member",
            RawRequest::get("/bucket?website"),
            || {
                let website: legacy::WebsiteConfiguration = legacy_document(WEBSITE);
                legacy::GetBucketWebsiteOutput {
                    error_document: website.error_document,
                    index_document: website.index_document,
                    redirect_all_requests_to: website.redirect_all_requests_to,
                    routing_rules: website.routing_rules,
                }
            },
            reordered(XML, &["WebsiteConfiguration"]),
        ),
        answer(
            "get-bucket-website-redirect",
            RawRequest::get("/bucket?website"),
            || {
                let website: legacy::WebsiteConfiguration = legacy_document(WEBSITE_REDIRECT);
                legacy::GetBucketWebsiteOutput {
                    error_document: website.error_document,
                    index_document: website.index_document,
                    redirect_all_requests_to: website.redirect_all_requests_to,
                    routing_rules: website.routing_rules,
                }
            },
            differs(XML, &["sa-0011"], &[]),
        ),
        answer(
            "get-object-lock-configuration-days",
            RawRequest::get("/bucket?object-lock"),
            || legacy::GetObjectLockConfigurationOutput {
                object_lock_configuration: Some(legacy::ObjectLockConfiguration {
                    object_lock_enabled: Some(named("Enabled")),
                    rule: Some(legacy::ObjectLockRule {
                        default_retention: Some(legacy::DefaultRetention {
                            days: Some(1),
                            mode: Some(named("GOVERNANCE")),
                            years: None,
                        }),
                    }),
                }),
            },
            differs(XML, &["sa-0004"], &["ObjectLockConfiguration/Rule/DefaultRetention"]),
        ),
        answer(
            "get-object-lock-configuration-years",
            RawRequest::get("/bucket?object-lock"),
            || legacy::GetObjectLockConfigurationOutput {
                object_lock_configuration: Some(legacy::ObjectLockConfiguration {
                    object_lock_enabled: Some(named("Enabled")),
                    rule: Some(legacy::ObjectLockRule {
                        default_retention: Some(legacy::DefaultRetention {
                            days: None,
                            mode: Some(named("COMPLIANCE")),
                            years: Some(2),
                        }),
                    }),
                }),
            },
            differs(XML, &["sa-0004"], &[]),
        ),
        answer(
            "get-public-access-block-every-member",
            RawRequest::get("/bucket?publicAccessBlock"),
            || legacy::GetPublicAccessBlockOutput {
                public_access_block_configuration: Some(legacy::PublicAccessBlockConfiguration {
                    block_public_acls: Some(true),
                    block_public_policy: Some(false),
                    ignore_public_acls: Some(true),
                    restrict_public_buckets: Some(false),
                }),
            },
            differs(XML, &["sa-0005"], &["PublicAccessBlockConfiguration"]),
        ),
    ]
}

fn writes() -> Vec<AnswerRow> {
    vec![
        answer(
            "put-bucket-accelerate",
            config(
                "/bucket?accelerate",
                "<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>",
            ),
            || legacy::PutBucketAccelerateConfigurationOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-acl",
            config("/bucket?acl", BUCKET_ACL),
            || legacy::PutBucketAclOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-cors",
            config("/bucket?cors", CORS),
            || legacy::PutBucketCorsOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-encryption",
            config("/bucket?encryption", ENCRYPTION),
            || legacy::PutBucketEncryptionOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-lifecycle-every-member",
            config("/bucket?lifecycle", LIFECYCLE),
            || legacy::PutBucketLifecycleConfigurationOutput {
                transition_default_minimum_object_size: Some(named("varies_by_storage_class")),
            },
            same(BARE),
        ),
        answer(
            "put-bucket-logging",
            config("/bucket?logging", LOGGING),
            || legacy::PutBucketLoggingOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-notification",
            config("/bucket?notification", NOTIFICATION),
            || legacy::PutBucketNotificationConfigurationOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-policy",
            config("/bucket?policy", POLICY),
            || legacy::PutBucketPolicyOutput {},
            differs(BARE, &["sa-0013"], &[]),
        ),
        answer(
            "put-bucket-replication",
            config("/bucket?replication", REPLICATION),
            || legacy::PutBucketReplicationOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-request-payment",
            config(
                "/bucket?requestPayment",
                "<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>",
            ),
            || legacy::PutBucketRequestPaymentOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-tagging",
            config(
                "/bucket?tagging",
                "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>",
            ),
            || legacy::PutBucketTaggingOutput {},
            same(BARE),
        ),
        answer(
            "put-bucket-website",
            config("/bucket?website", WEBSITE),
            || legacy::PutBucketWebsiteOutput {},
            same(BARE),
        ),
        answer(
            "put-object-lock-configuration-every-member",
            config(
                "/bucket?object-lock",
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>",
            ),
            || legacy::PutObjectLockConfigurationOutput {
                request_charged: Some(named("requester")),
            },
            same(BARE),
        ),
        answer(
            "put-public-access-block",
            config(
                "/bucket?publicAccessBlock",
                "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>",
            ),
            || legacy::PutPublicAccessBlockOutput {},
            same(BARE),
        ),
    ]
}

fn deletes() -> Vec<AnswerRow> {
    vec![
        answer(
            "delete-bucket-cors",
            RawRequest::delete("/bucket?cors"),
            || legacy::DeleteBucketCorsOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-encryption",
            RawRequest::delete("/bucket?encryption"),
            || legacy::DeleteBucketEncryptionOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-lifecycle",
            RawRequest::delete("/bucket?lifecycle"),
            || legacy::DeleteBucketLifecycleOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-policy",
            RawRequest::delete("/bucket?policy"),
            || legacy::DeleteBucketPolicyOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-replication",
            RawRequest::delete("/bucket?replication"),
            || legacy::DeleteBucketReplicationOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-tagging",
            RawRequest::delete("/bucket?tagging"),
            || legacy::DeleteBucketTaggingOutput {},
            same(BARE),
        ),
        answer(
            "delete-bucket-website",
            RawRequest::delete("/bucket?website"),
            || legacy::DeleteBucketWebsiteOutput {},
            same(BARE),
        ),
        answer(
            "delete-public-access-block",
            RawRequest::delete("/bucket?publicAccessBlock"),
            || legacy::DeletePublicAccessBlockOutput {},
            same(BARE),
        ),
    ]
}

pub(super) fn rows() -> Vec<AnswerRow> {
    let mut rows = reads();
    rows.extend(writes());
    rows.extend(deletes());
    rows
}
