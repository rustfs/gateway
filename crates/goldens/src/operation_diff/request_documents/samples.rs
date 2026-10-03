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

//! One or more complete request documents per operation, each carrying every member its structures
//! declare somewhere, so that a perturbation of every element reaches every member.
//!
//! Responsible for: the baseline documents `parity` perturbs, every one accepted by both stacks.
//! NOT responsible for: judging anything (`parity`).
//! Upstream: none. Downstream: `parity`.

use super::Op;

const XSI: &str = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";

/// `(operation, name, document)` for every baseline.
pub(super) fn samples() -> Vec<(Op, &'static str, String)> {
    let grant = |permission: &str| {
        format!(
            "<Grant><Grantee {XSI} xsi:type=\"CanonicalUser\"><ID>id-1</ID><DisplayName>name</DisplayName></Grantee><Permission>{permission}</Permission></Grant>\
             <Grant><Grantee {XSI} xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>\
             <Grant><Grantee {XSI} xsi:type=\"AmazonCustomerByEmail\"><EmailAddress>a@example.com</EmailAddress></Grantee><Permission>WRITE</Permission></Grant>"
        )
    };
    let acl = format!(
        "<AccessControlPolicy><Owner><ID>owner-id</ID><DisplayName>owner</DisplayName></Owner><AccessControlList>{}</AccessControlList></AccessControlPolicy>",
        grant("FULL_CONTROL")
    );
    vec![
        (
            Op::CompleteMultipartUpload,
            "parts",
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"d41d8cd98f00b204e9800998ecf8427e\"</ETag>\
             <ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part><Part><ETag>0cc175b9c0f1b6a831c399e269772661</ETag><PartNumber>2</PartNumber>\
             </Part></CompleteMultipartUpload>"
                .to_owned(),
        ),
        (
            Op::CreateBucket,
            "constraint",
            "<CreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>".to_owned(),
        ),
        (
            Op::CreateBucket,
            "directory-members",
            "<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint><Location><Name>usw2-az1</Name><Type>AvailabilityZone</Type></Location>\
             <Bucket><DataRedundancy>SingleAvailabilityZone</DataRedundancy><Type>Directory</Type></Bucket>\
             <Tags><Tag><Key>k</Key><Value>v</Value></Tag></Tags></CreateBucketConfiguration>"
                .to_owned(),
        ),
        (
            Op::DeleteObjects,
            "objects",
            "<Delete><Quiet>true</Quiet><Object><Key>a/b.txt</Key><VersionId>v1</VersionId><ETag>\"abc\"</ETag><Size>12</Size>\
             <LastModifiedTime>Fri, 02 Jan 2026 03:04:05 GMT</LastModifiedTime></Object><Object><Key>c</Key></Object></Delete>"
                .to_owned(),
        ),
        (
            Op::PutBucketAccelerateConfiguration,
            "status",
            "<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>".to_owned(),
        ),
        (Op::PutBucketAcl, "grants", acl.clone()),
        (Op::PutObjectAcl, "grants", acl),
        (
            Op::PutBucketCors,
            "rules",
            "<CORSConfiguration><CORSRule><ID>r1</ID><AllowedHeader>*</AllowedHeader><AllowedHeader>x-a</AllowedHeader>\
             <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://a.example</AllowedOrigin>\
             <ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>300</MaxAgeSeconds></CORSRule>\
             <CORSRule><AllowedMethod>HEAD</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketEncryption,
            "rules",
            "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>\
             <KMSMasterKeyID>key-1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled>\
             <BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketLifecycleConfiguration,
            "rules",
            "<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30T12:34:56.123Z</ExpiryUpdatedAt>\
             <Rule><ID>a</ID><Filter><And><Prefix>logs/</Prefix><Tag><Key>k1</Key><Value>v1</Value></Tag><Tag><Key>k2</Key><Value>v2</Value></Tag>\
             <ObjectSizeGreaterThan>10</ObjectSizeGreaterThan><ObjectSizeLessThan>2000</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>\
             <Expiration><Days>30</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration>\
             <DelMarkerExpiration><Days>7</Days></DelMarkerExpiration>\
             <Transition><Days>10</Days><StorageClass>GLACIER</StorageClass></Transition>\
             <NoncurrentVersionTransition><NoncurrentDays>5</NoncurrentDays><StorageClass>GLACIER</StorageClass><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionTransition>\
             <NoncurrentVersionExpiration><NoncurrentDays>40</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>\
             <Rule><ID>b</ID><Prefix>old/</Prefix><Status>Disabled</Status><Expiration><Date>2027-01-01T00:00:00Z</Date></Expiration>\
             <Transition><Date>2026-12-01T00:00:00.000Z</Date><StorageClass>STANDARD_IA</StorageClass></Transition></Rule>\
             <Rule><ID>c</ID><Filter><Tag><Key>t</Key><Value>u</Value></Tag></Filter><Status>Enabled</Status>\
             <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>\
             <Rule><ID>d</ID><Filter><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>e</ID><Filter><ObjectSizeLessThan>5</ObjectSizeLessThan></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>f</ID><Filter><Prefix>p/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             </LifecycleConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketLogging,
            "enabled",
            format!(
                "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>p/</TargetPrefix>\
                 <TargetGrants><Grant><Grantee {XSI} xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI></Grantee>\
                 <Permission>WRITE</Permission></Grant></TargetGrants>\
                 <TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>\
                 </LoggingEnabled></BucketLoggingStatus>"
            ),
        ),
        (
            Op::PutBucketLogging,
            "simple-prefix",
            "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>p/</TargetPrefix>\
             <TargetObjectKeyFormat><SimplePrefix></SimplePrefix></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>"
                .to_owned(),
        ),
        (
            Op::PutBucketNotificationConfiguration,
            "targets",
            "<NotificationConfiguration><TopicConfiguration><Id>t</Id><Topic>arn:aws:sns:us-east-1:1:t</Topic><Event>s3:ObjectCreated:*</Event>\
             <Event>s3:ObjectRemoved:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>a/</Value></FilterRule>\
             <FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter></TopicConfiguration>\
             <QueueConfiguration><Id>q</Id><Queue>arn:aws:sqs:us-east-1:1:q</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration>\
             <CloudFunctionConfiguration><Id>l</Id><CloudFunction>arn:aws:lambda:us-east-1:1:function:f</CloudFunction><Event>s3:ObjectCreated:Post</Event></CloudFunctionConfiguration>\
             <EventBridgeConfiguration></EventBridgeConfiguration></NotificationConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketReplication,
            "rules",
            "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role>\
             <Rule><ID>a</ID><Priority>1</Priority><Status>Enabled</Status><Filter><And><Prefix>logs/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>\
             <SourceSelectionCriteria><SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects><ReplicaModifications><Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria>\
             <ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication>\
             <Destination><Bucket>arn:aws:s3:::dst</Bucket><Account>2</Account><StorageClass>STANDARD</StorageClass>\
             <AccessControlTranslation><Owner>Destination</Owner></AccessControlTranslation><EncryptionConfiguration><ReplicaKmsKeyID>k</ReplicaKmsKeyID></EncryptionConfiguration>\
             <ReplicationTime><Status>Enabled</Status><Time><Minutes>15</Minutes></Time></ReplicationTime>\
             <Metrics><Status>Enabled</Status><EventThreshold><Minutes>15</Minutes></EventThreshold></Metrics></Destination>\
             <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status></DeleteReplication></Rule>\
             <Rule><ID>b</ID><Prefix>old/</Prefix><Status>Disabled</Status><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule>\
             <Rule><ID>c</ID><Status>Enabled</Status><Filter><Tag><Key>t</Key><Value>u</Value></Tag></Filter><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule>\
             <Rule><ID>d</ID><Status>Enabled</Status><Filter><Prefix>p/</Prefix></Filter><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule>\
             </ReplicationConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketRequestPayment,
            "payer",
            "<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>".to_owned(),
        ),
        (
            Op::PutBucketTagging,
            "tags",
            "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value></Value></Tag></TagSet></Tagging>".to_owned(),
        ),
        (
            Op::PutObjectTagging,
            "tags",
            "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag></TagSet></Tagging>".to_owned(),
        ),
        (
            Op::PutBucketVersioning,
            "minio-members",
            "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Disabled</MfaDelete>\
             <ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>cache/</Prefix></ExcludedPrefixes>\
             <ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketWebsite,
            "routing",
            "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument>\
             <RoutingRules><RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>\
             <Redirect><Protocol>https</Protocol><HostName>example.com</HostName><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith>\
             <HttpRedirectCode>301</HttpRedirectCode></Redirect></RoutingRule>\
             <RoutingRule><Redirect><ReplaceKeyWith>x.html</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutBucketWebsite,
            "redirect-all",
            "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.com</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutObjectLegalHold,
            "status",
            "<LegalHold><Status>ON</Status></LegalHold>".to_owned(),
        ),
        (
            Op::PutObjectLockConfiguration,
            "rule",
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days>\
             </DefaultRetention></Rule></ObjectLockConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutObjectLockConfiguration,
            "years",
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years>\
             </DefaultRetention></Rule></ObjectLockConfiguration>"
                .to_owned(),
        ),
        (
            Op::PutObjectRetention,
            "retention",
            "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-02T03:04:05.678Z</RetainUntilDate></Retention>".to_owned(),
        ),
        (
            Op::PutPublicAccessBlock,
            "switches",
            "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>\
             <BlockPublicPolicy>TRUE</BlockPublicPolicy><RestrictPublicBuckets>FALSE</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
                .to_owned(),
        ),
        (
            Op::RestoreObject,
            "days",
            "<RestoreRequest><Days>2</Days><GlacierJobParameters><Tier>Standard</Tier></GlacierJobParameters><Description>d</Description></RestoreRequest>"
                .to_owned(),
        ),
        (
            Op::RestoreObject,
            "select",
            format!(
                "<RestoreRequest><Type>SELECT</Type><Tier>Bulk</Tier><SelectParameters><InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo>\
                 <Comments>#</Comments><QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>\
                 <QuoteCharacter>\"</QuoteCharacter><AllowQuotedRecordDelimiter>false</AllowQuotedRecordDelimiter></CSV><CompressionType>GZIP</CompressionType>\
                 </InputSerialization><ExpressionType>SQL</ExpressionType><Expression>SELECT * FROM S3Object</Expression>\
                 <OutputSerialization><JSON><RecordDelimiter>\n</RecordDelimiter></JSON></OutputSerialization></SelectParameters>\
                 <OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix><Encryption><EncryptionType>aws:kms</EncryptionType>\
                 <KMSKeyId>k</KMSKeyId><KMSContext>c</KMSContext></Encryption><CannedACL>private</CannedACL>\
                 <AccessControlList>{}</AccessControlList><Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>\
                 <UserMetadata><MetadataEntry><Name>m</Name><Value>n</Value></MetadataEntry></UserMetadata><StorageClass>STANDARD</StorageClass>\
                 </S3></OutputLocation></RestoreRequest>",
                grant("READ")
            ),
        ),
        (
            Op::RestoreObject,
            "json-parquet",
            "<RestoreRequest><Type>SELECT</Type><SelectParameters><InputSerialization><JSON><Type>LINES</Type></JSON></InputSerialization>\
             <ExpressionType>SQL</ExpressionType><Expression>SELECT 1</Expression><OutputSerialization><CSV><QuoteFields>ASNEEDED</QuoteFields>\
             <QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>\
             <QuoteCharacter>\"</QuoteCharacter></CSV></OutputSerialization></SelectParameters></RestoreRequest>"
                .to_owned(),
        ),
        (
            Op::SelectObjectContent,
            "csv",
            "<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType>\
             <RequestProgress><Enabled>true</Enabled></RequestProgress><InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>\
             <CompressionType>NONE</CompressionType></InputSerialization><OutputSerialization><JSON></JSON></OutputSerialization>\
             <ScanRange><Start>0</Start><End>100</End></ScanRange></SelectObjectContentRequest>"
                .to_owned(),
        ),
        (
            Op::SelectObjectContent,
            "parquet",
            "<SelectRequest><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
             <InputSerialization><Parquet></Parquet></InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization></SelectRequest>"
                .to_owned(),
        ),
        (
            Op::UpdateObjectEncryption,
            "kms",
            "<ObjectEncryption><SSE-KMS><KMSKeyArn>arn:aws:kms:us-east-1:1:key/k</KMSKeyArn><BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption>"
                .to_owned(),
        ),
    ]
}
