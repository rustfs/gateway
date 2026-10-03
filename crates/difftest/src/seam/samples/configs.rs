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

//! Seam rows for the bucket-configuration writes: the documents RustFS serialises into bucket
//! metadata, so an input member that differs here is stored bytes that differ.
//!
//! Responsible for: rows that set every member of each configuration family's legacy input
//! between them, the MinIO members rustfs/gateway#1062 accepts included.
//! NOT responsible for: judging (`tests/seam.rs`). Upstream: none. Downstream: `super`.

use http::Method;
use rustfs_gateway_types::ChecksumAlgorithm;

use super::{Expect, SeamRow, checked, document, row};
use crate::samples::OWNER;

/// A configuration write of `body` to `target`, with both integrity headers and the owner check.
pub(in crate::seam) fn config(target: &str, body: &str) -> crate::request::RawRequest {
    checked(document(Method::PUT, target, body), ChecksumAlgorithm::Crc32, "CRC32", body.as_bytes())
        .header("x-amz-expected-bucket-owner", OWNER)
}

pub(in crate::seam) const LIFECYCLE: &str = "<LifecycleConfiguration>\
    <Rule><ID>by-prefix</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
    <Expiration><Days>30</Days></Expiration>\
    <Transition><Days>7</Days><StorageClass>STANDARD_IA</StorageClass></Transition>\
    <Transition><Days>14</Days><StorageClass>GLACIER</StorageClass></Transition>\
    <NoncurrentVersionTransition><NoncurrentDays>5</NoncurrentDays><StorageClass>GLACIER</StorageClass><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionTransition>\
    <NoncurrentVersionExpiration><NoncurrentDays>40</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration>\
    <AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>\
    <Rule><ID>by-tag</ID><Filter><Tag><Key>class</Key><Value>tmp</Value></Tag></Filter><Status>Disabled</Status>\
    <Expiration><Date>2030-01-01T00:00:00.000Z</Date></Expiration></Rule>\
    <Rule><ID>by-and</ID><Filter><And><Prefix>a/</Prefix><Tag><Key>k1</Key><Value>v1</Value></Tag><Tag><Key>k2</Key><Value>v2</Value></Tag>\
    <ObjectSizeGreaterThan>100</ObjectSizeGreaterThan><ObjectSizeLessThan>1000</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>\
    <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>\
    <Transition><Date>2031-01-01T00:00:00.000Z</Date><StorageClass>GLACIER</StorageClass></Transition></Rule>\
    <Rule><ID>by-size</ID><Filter><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>\
    <Expiration><Days>1</Days></Expiration></Rule>\
    <Rule><ID>by-max-size</ID><Filter><ObjectSizeLessThan>10</ObjectSizeLessThan></Filter><Status>Enabled</Status>\
    <Expiration><Days>1</Days></Expiration></Rule>\
    <Rule><ID>legacy-prefix</ID><Prefix>old/</Prefix><Status>Enabled</Status><Expiration><Days>9</Days></Expiration></Rule>\
    </LifecycleConfiguration>";

pub(in crate::seam) const REPLICATION: &str = "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role>\
    <Rule><ID>everything</ID><Priority>1</Priority><Status>Enabled</Status>\
    <Filter><And><Prefix>docs/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>\
    <SourceSelectionCriteria><SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects>\
    <ReplicaModifications><Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria>\
    <ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication>\
    <Destination><Bucket>arn:aws:s3:::target</Bucket><Account>123456789012</Account><StorageClass>STANDARD</StorageClass>\
    <AccessControlTranslation><Owner>Destination</Owner></AccessControlTranslation>\
    <EncryptionConfiguration><ReplicaKmsKeyID>key-2</ReplicaKmsKeyID></EncryptionConfiguration>\
    <ReplicationTime><Status>Enabled</Status><Time><Minutes>15</Minutes></Time></ReplicationTime>\
    <Metrics><Status>Enabled</Status><EventThreshold><Minutes>15</Minutes></EventThreshold></Metrics></Destination>\
    <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication></Rule>\
    <Rule><ID>by-tag</ID><Priority>2</Priority><Status>Disabled</Status><Filter><Tag><Key>t</Key><Value>u</Value></Tag></Filter>\
    <Destination><Bucket>arn:aws:s3:::target2</Bucket></Destination><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication></Rule>\
    <Rule><ID>by-prefix-filter</ID><Priority>3</Priority><Status>Enabled</Status><Filter><Prefix>p/</Prefix></Filter>\
    <Destination><Bucket>arn:aws:s3:::target3</Bucket></Destination><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication></Rule>\
    <Rule><ID>legacy-prefix</ID><Status>Enabled</Status><Prefix>q/</Prefix><Destination><Bucket>arn:aws:s3:::target4</Bucket></Destination></Rule>\
    </ReplicationConfiguration>";

pub(in crate::seam) const NOTIFICATION: &str = "<NotificationConfiguration>\
    <TopicConfiguration><Id>t1</Id><Topic>arn:aws:sns:us-east-1:123456789012:topic</Topic><Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:Delete</Event>\
    <Filter><S3Key><FilterRule><Name>prefix</Name><Value>img/</Value></FilterRule><FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter></TopicConfiguration>\
    <QueueConfiguration><Id>q1</Id><Queue>arn:minio:sqs::1:webhook</Queue><Event>s3:ObjectCreated:Put</Event>\
    <Filter><S3Key><FilterRule><Name>suffix</Name><Value>.txt</Value></FilterRule></S3Key></Filter></QueueConfiguration>\
    <CloudFunctionConfiguration><Id>l1</Id><CloudFunction>arn:aws:lambda:us-east-1:123456789012:function:f</CloudFunction><Event>s3:ObjectRemoved:*</Event>\
    <Filter><S3Key><FilterRule><Name>prefix</Name><Value>x</Value></FilterRule></S3Key></Filter></CloudFunctionConfiguration>\
    </NotificationConfiguration>";

pub(in crate::seam) const CORS: &str = "<CORSConfiguration><CORSRule><ID>r1</ID><AllowedHeader>x-a</AllowedHeader><AllowedHeader>x-b</AllowedHeader>\
    <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://a.example</AllowedOrigin>\
    <AllowedOrigin>*</AllowedOrigin><ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-request-id</ExposeHeader>\
    <MaxAgeSeconds>3000</MaxAgeSeconds></CORSRule><CORSRule><AllowedMethod>HEAD</AllowedMethod><AllowedOrigin>https://b.example</AllowedOrigin></CORSRule>\
    </CORSConfiguration>";

pub(in crate::seam) const ENCRYPTION: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>\
    <KMSMasterKeyID>key-1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled>\
    <BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>";

pub(in crate::seam) const WEBSITE: &str = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument>\
    <RoutingRules><RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>\
    <Redirect><Protocol>https</Protocol><HostName>example.com</HostName><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith><HttpRedirectCode>301</HttpRedirectCode></Redirect></RoutingRule>\
    <RoutingRule><Redirect><ReplaceKeyWith>fixed.html</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";

pub(in crate::seam) const WEBSITE_REDIRECT: &str = "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.com</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>";

pub(in crate::seam) const LOGGING: &str = "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>b/</TargetPrefix>\
    <TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\"><EmailAddress>a@example.com</EmailAddress></Grantee><Permission>READ</Permission></Grant>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>i</ID><DisplayName>d</DisplayName></Grantee><Permission>WRITE</Permission></Grant>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI></Grantee><Permission>FULL_CONTROL</Permission></Grant></TargetGrants>\
    <TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>\
    </LoggingEnabled></BucketLoggingStatus>";

pub(in crate::seam) const BUCKET_ACL: &str = "<AccessControlPolicy><Owner><ID>owner-1</ID><DisplayName>owner</DisplayName></Owner><AccessControlList>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>owner-1</ID><DisplayName>owner</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI></Grantee><Permission>WRITE</Permission></Grant>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\"><EmailAddress>a@example.com</EmailAddress></Grantee><Permission>WRITE_ACP</Permission></Grant>\
    </AccessControlList></AccessControlPolicy>";

/// The MinIO lifecycle members RustFS reads: a document-level expiry stamp, a rule's delete-marker
/// expiry and an expiration of every version.
pub(in crate::seam) const LIFECYCLE_MINIO: &str = "<LifecycleConfiguration><ExpiryUpdatedAt>2026-01-02T03:04:05.000Z</ExpiryUpdatedAt>\
    <Rule><ID>marker-cleanup</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
    <Expiration><Days>30</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration>\
    <DelMarkerExpiration><Days>7</Days></DelMarkerExpiration></Rule></LifecycleConfiguration>";

/// The MinIO replication member RustFS reads: whether a rule replicates deletes.
pub(in crate::seam) const REPLICATION_MINIO: &str = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
    <Rule><ID>replicate-logs</ID><Priority>1</Priority><Filter><Prefix>logs/</Prefix></Filter>\
    <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status></DeleteReplication>\
    <Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule></ReplicationConfiguration>";

/// The MinIO versioning members RustFS reads: folders and prefixes kept unversioned.
const VERSIONING_MINIO: &str = "<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders>\
    <ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>cache/</Prefix></ExcludedPrefixes>\
    </VersioningConfiguration>";

pub(super) fn rows() -> Vec<SeamRow> {
    vec![
        // MinIO's bare body literal, which the RustFS profile reads as the document it stands for
        // (rustfs/backlog#1677, R6): RustFS must be handed the input the legacy stack hands it.
        row(
            "put-bucket-versioning-bare-enabled",
            document(Method::PUT, "/bucket?versioning", "Enabled"),
            Expect::Identical,
        ),
        row(
            "put-bucket-versioning-bare-enabled-padded",
            document(Method::PUT, "/bucket?versioning", " Enabled\r\n"),
            Expect::Identical,
        ),
        row(
            "put-object-lock-configuration-bare-enabled",
            document(Method::PUT, "/bucket?object-lock", "\tEnabled "),
            Expect::Identical,
        ),
        row("put-bucket-lifecycle-minio-members", config("/bucket?lifecycle", LIFECYCLE_MINIO), Expect::Identical),
        row("put-bucket-replication-minio-members", config("/bucket?replication", REPLICATION_MINIO), Expect::Identical),
        row("put-bucket-versioning-minio-members", config("/bucket?versioning", VERSIONING_MINIO), Expect::Identical),
        row(
            "put-bucket-lifecycle-every-aws-member",
            config("/bucket?lifecycle", LIFECYCLE).header("x-amz-transition-default-minimum-object-size", "all_storage_classes_128K"),
            Expect::Identical,
        ),
        row(
            "put-bucket-replication-every-aws-member",
            config("/bucket?replication", REPLICATION).header("x-amz-bucket-object-lock-token", "token-1"),
            Expect::Identical,
        ),
        row(
            "put-bucket-notification-every-member",
            config("/bucket?notification", NOTIFICATION).header("x-amz-skip-destination-validation", "true"),
            Expect::Identical,
        ),
        row(
            "put-bucket-notification-empty",
            config("/bucket?notification", "<NotificationConfiguration></NotificationConfiguration>"),
            Expect::Identical,
        ),
        // An empty element says something only by being there: both stacks hand it over and store it.
        row(
            "put-bucket-notification-event-bridge",
            config(
                "/bucket?notification",
                "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "put-bucket-logging-simple-prefix",
            config(
                "/bucket?logging",
                "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>b/</TargetPrefix>\
                 <TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>",
            ),
            Expect::Identical,
        ),
        row("put-bucket-cors-every-member", config("/bucket?cors", CORS), Expect::Identical),
        row("put-bucket-encryption-every-member", config("/bucket?encryption", ENCRYPTION), Expect::Identical),
        row(
            "put-bucket-encryption-sse-s3",
            config(
                "/bucket?encryption",
                "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "put-bucket-policy-every-member",
            config(
                "/bucket?policy",
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\"}]}",
            )
            .header("x-amz-confirm-remove-self-bucket-access", "true"),
            Expect::Identical,
        ),
        row(
            "put-bucket-tagging-every-member",
            config(
                "/bucket?tagging",
                "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>a b</Value></Tag></TagSet></Tagging>",
            ),
            Expect::Identical,
        ),
        row(
            "put-bucket-versioning-every-member",
            config(
                "/bucket?versioning",
                "<VersioningConfiguration><Status>Suspended</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>",
            )
            .header("x-amz-mfa", "SERIAL 123456"),
            Expect::Identical,
        ),
        row(
            "put-object-lock-configuration-days",
            config(
                "/bucket?object-lock",
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
            )
            .header("x-amz-bucket-object-lock-token", "token-1")
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-object-lock-configuration-years",
            config(
                "/bucket?object-lock",
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "put-public-access-block-every-member",
            config(
                "/bucket?publicAccessBlock",
                "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>\
                 <BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
            ),
            Expect::Identical,
        ),
        row("put-bucket-acl-document", config("/bucket?acl", BUCKET_ACL), Expect::Identical),
        row(
            "put-bucket-acl-headers",
            config("/bucket?acl", "")
                .header("x-amz-acl", "public-read")
                .header("x-amz-grant-full-control", "id=\"owner-1\"")
                .header("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")
                .header("x-amz-grant-read-acp", "emailAddress=\"a@example.com\"")
                .header("x-amz-grant-write", "id=\"writer\"")
                .header("x-amz-grant-write-acp", "id=\"owner-2\""),
            Expect::Identical,
        ),
        row("put-bucket-website-every-member", config("/bucket?website", WEBSITE), Expect::Identical),
        row("put-bucket-website-redirect-all", config("/bucket?website", WEBSITE_REDIRECT), Expect::Identical),
        row("put-bucket-logging-every-member", config("/bucket?logging", LOGGING), Expect::Identical),
        row(
            "put-bucket-logging-disabled",
            config("/bucket?logging", "<BucketLoggingStatus></BucketLoggingStatus>"),
            Expect::Identical,
        ),
        // A present empty list is a list of its own on both stacks, handed over and stored as legacy
        // RustFS stores it, the empty element included (rustfs/gateway#1078).
        row(
            "put-bucket-logging-empty-grants",
            config(
                "/bucket?logging",
                "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetGrants/><TargetPrefix>b/</TargetPrefix>\
                 </LoggingEnabled></BucketLoggingStatus>",
            ),
            Expect::Identical,
        ),
        row(
            "put-bucket-website-empty-routing-rules",
            config(
                "/bucket?website",
                "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><RoutingRules></RoutingRules>\
                 </WebsiteConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "put-bucket-accelerate-every-member",
            config(
                "/bucket?accelerate",
                "<AccelerateConfiguration><Status>Suspended</Status></AccelerateConfiguration>",
            )
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-bucket-request-payment-every-member",
            config(
                "/bucket?requestPayment",
                "<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>",
            ),
            Expect::Identical,
        ),
    ]
}
