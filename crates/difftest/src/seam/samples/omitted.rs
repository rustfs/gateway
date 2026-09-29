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

//! Seam rows for the checksum-required writes sent with no integrity claim at all, as legacy
//! RustFS serves them (rustfs/backlog#1677, ruling R5).
//!
//! Responsible for: one row per operation the pinned model marks `httpChecksumRequired`, with no
//! `Content-MD5`, no `x-amz-checksum-*` and no algorithm header, each of which must reach both
//! handlers with the identical input — so the configuration document, ACL, lock or key list the
//! RustFS app layer stores or acts on is the one the legacy stack hands it.
//! NOT responsible for: judging (`tests/seam.rs`), or a claim that does not match its body, which
//! the gateway refuses and the legacy stack does not (`compat/sut`'s `checksum_omission_tests.rs`).
//! Upstream: none. Downstream: `super`.

use http::Method;

use super::{Expect, SeamRow, row};
use crate::request::RawRequest;

/// The operation each row below routes to, in row order; `tests/seam.rs` holds it to the routed
/// operation of every row and to the facade's `CHECKSUM_REQUIRED_OPERATIONS`.
pub(crate) const OMITTED_OPERATIONS: [&str; 18] = [
    "DeleteObjects",
    "PutBucketAcl",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketLifecycleConfiguration",
    "PutBucketLogging",
    "PutBucketPolicy",
    "PutBucketReplication",
    "PutBucketRequestPayment",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutBucketWebsite",
    "PutObjectAcl",
    "PutObjectLegalHold",
    "PutObjectLockConfiguration",
    "PutObjectRetention",
    "PutObjectTagging",
    "PutPublicAccessBlock",
];

/// A write of `body` to `target` with its exact length and no integrity header of any kind.
fn bare(method: Method, target: &str, body: &str) -> RawRequest {
    RawRequest::with_body(method, target, body.as_bytes())
}

pub(crate) fn rows() -> Vec<SeamRow> {
    let put = || Method::PUT;
    vec![
        row(
            "omitted-delete-objects",
            bare(
                Method::POST,
                "/bucket?delete",
                "<Delete><Object><Key>a b</Key></Object><Quiet>true</Quiet></Delete>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-acl",
            bare(put(), "/bucket?acl", "").header("x-amz-acl", "public-read"),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-cors",
            bare(
                put(),
                "/bucket?cors",
                "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-encryption",
            bare(
                put(),
                "/bucket?encryption",
                "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-lifecycle",
            bare(
                put(),
                "/bucket?lifecycle",
                "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-logging",
            bare(put(), "/bucket?logging", "<BucketLoggingStatus></BucketLoggingStatus>"),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-policy",
            bare(
                put(),
                "/bucket?policy",
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\"}]}",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-replication",
            bare(
                put(),
                "/bucket?replication",
                "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><ID>r</ID><Priority>1</Priority><Status>Enabled</Status><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination></Rule></ReplicationConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-request-payment",
            bare(
                put(),
                "/bucket?requestPayment",
                "<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-tagging",
            bare(
                put(),
                "/bucket?tagging",
                "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-versioning",
            bare(
                put(),
                "/bucket?versioning",
                "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-bucket-website",
            bare(
                put(),
                "/bucket?website",
                "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-object-acl",
            bare(put(), "/bucket/k?acl", "").header("x-amz-acl", "public-read"),
            Expect::Identical,
        ),
        row(
            "omitted-put-object-legal-hold",
            bare(put(), "/bucket/k?legal-hold", "<LegalHold><Status>ON</Status></LegalHold>"),
            Expect::Identical,
        ),
        row(
            "omitted-put-object-lock-configuration",
            bare(
                put(),
                "/bucket?object-lock",
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-object-retention",
            bare(
                put(),
                "/bucket/k?retention",
                "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00.000Z</RetainUntilDate></Retention>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-object-tagging",
            bare(
                put(),
                "/bucket/k?tagging",
                "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>",
            ),
            Expect::Identical,
        ),
        row(
            "omitted-put-public-access-block",
            bare(
                put(),
                "/bucket?publicAccessBlock",
                "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>",
            ),
            Expect::Identical,
        ),
    ]
}
