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

//! Seam rows for the object writes: copies, multipart, tagging, retention, legal hold, ACLs,
//! deletes and restores — every operation whose members reach stored object state.
//!
//! Responsible for: rows that set every member of those operations' legacy inputs between them.
//! NOT responsible for: judging (`tests/seam.rs`). Upstream: none. Downstream: `super`.

use http::Method;

use rustfs_gateway_types::ChecksumAlgorithm;

use super::{Expect, SeamRow, checked, document, row};
use crate::request::RawRequest;
use crate::samples::{OWNER, UPLOAD_ID, VERSION_ID, sse};

const DATE: &str = "Wed, 21 Oct 2015 07:28:00 GMT";
/// [`DATE`] with a sign on its year, which legacy RustFS reads and RFC 9110 does not.
const SIGNED_YEAR: &str = "Wed, 21 Oct +2015 07:28:00 GMT";
const LOCK_DATE: &str = "2030-01-01T00:00:00.000Z";
const SSE_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const SSE_KEY_MD5: &str = "hRasmdxgYDKV3nvbahU1MA==";

/// The copy-source SSE-C headers, naming the same key as `sse`.
fn source_sse(request: RawRequest) -> RawRequest {
    request
        .header("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-copy-source-server-side-encryption-customer-key", SSE_KEY)
        .header("x-amz-copy-source-server-side-encryption-customer-key-md5", SSE_KEY_MD5)
}

/// Every stored-object header a write can carry, SSE-KMS for the encryption.
fn stored_headers(request: RawRequest) -> RawRequest {
    request
        .header("x-amz-meta-color", "blue")
        .header("x-amz-meta-note", "two words")
        .header("x-amz-tagging", "a=1&b=2")
        .header("x-amz-storage-class", "STANDARD_IA")
        .header("content-type", "text/plain")
        .header("cache-control", "no-cache")
        .header("content-disposition", "inline")
        .header("content-encoding", "identity")
        .header("content-language", "en")
        .header("expires", DATE)
        .header("x-amz-website-redirect-location", "/other")
        .header("x-amz-object-lock-mode", "GOVERNANCE")
        .header("x-amz-object-lock-retain-until-date", LOCK_DATE)
        .header("x-amz-object-lock-legal-hold", "ON")
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "key-1")
        .header("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
        .header("x-amz-server-side-encryption-bucket-key-enabled", "true")
        .header("x-amz-expected-bucket-owner", OWNER)
        .header("x-amz-request-payer", "requester")
}

/// The canned ACL and the four grant headers every object write takes.
fn grants(request: RawRequest) -> RawRequest {
    request
        .header("x-amz-acl", "bucket-owner-full-control")
        .header("x-amz-grant-full-control", "id=\"owner-1\"")
        .header("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")
        .header("x-amz-grant-read-acp", "emailAddress=\"a@example.com\"")
        .header("x-amz-grant-write-acp", "id=\"owner-2\"")
}

fn copies() -> Vec<SeamRow> {
    vec![
        row("put-object-plain", RawRequest::put("/bucket/dir/k.txt", b"hello"), Expect::Identical),
        row(
            "copy-object-every-stored-member",
            grants(stored_headers(
                RawRequest::new(Method::PUT, "/bucket/dest%20key")
                    .header("x-amz-copy-source", "/src-bucket/src%2Bkey?versionId=v1")
                    .header("x-amz-metadata-directive", "REPLACE")
                    .header("x-amz-tagging-directive", "REPLACE")
                    .header("x-amz-checksum-algorithm", "CRC32")
                    .header("x-amz-copy-source-if-match", "\"etag-1\"")
                    .header("x-amz-copy-source-if-none-match", "\"etag-2\"")
                    .header("x-amz-copy-source-if-modified-since", DATE)
                    .header("x-amz-copy-source-if-unmodified-since", DATE)
                    .header("x-amz-source-expected-bucket-owner", OWNER),
            )),
            Expect::Identical,
        ),
        row(
            "copy-object-customer-keys-both-sides-and-write-conditions",
            source_sse(sse(RawRequest::new(Method::PUT, "/bucket/dest")
                .header("x-amz-copy-source", "src-bucket/dir/a%2Fb%3Fc%20d")
                .header("x-amz-metadata-directive", "COPY")
                .header("x-amz-tagging-directive", "COPY")
                .header("if-match", "\"dest-etag\"")
                .header("if-none-match", "*"))),
            Expect::Identical,
        ),
        // A copy from an SSE-C source into a managed target: the source key decrypts the source,
        // the managed headers encrypt the target (rustfs/backlog#1677, R11). RustFS must be handed
        // every one of them, so the target's stored encryption is the one legacy RustFS writes.
        row(
            "copy-object-ssec-source-into-sse-s3",
            source_sse(RawRequest::new(Method::PUT, "/bucket/dest").header("x-amz-copy-source", "/src-bucket/src"))
                .header("x-amz-server-side-encryption", "AES256")
                .over_tls(),
            Expect::Identical,
        ),
        row(
            "copy-object-ssec-source-into-sse-kms",
            source_sse(RawRequest::new(Method::PUT, "/bucket/dest").header("x-amz-copy-source", "/src-bucket/src"))
                .header("x-amz-server-side-encryption", "aws:kms")
                .header("x-amz-server-side-encryption-aws-kms-key-id", "key-1")
                .header("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
                .header("x-amz-server-side-encryption-bucket-key-enabled", "true")
                .over_tls(),
            Expect::Identical,
        ),
        row(
            "copy-object-source-with-plus-unicode-and-null-version",
            RawRequest::new(Method::PUT, "/bucket/k").header("x-amz-copy-source", "/src-bucket/a+b%E2%9C%93?versionId=null"),
            Expect::Identical,
        ),
        // A year with a sign: legacy RustFS reads `+1994` as 1994, and the RFC 9110 grammar the core
        // reads by default refuses it and drops the condition. Under the RustFS profile both stacks
        // hand RustFS the same instant (rustfs/backlog#1677, R14).
        row(
            "copy-object-signed-year-conditions",
            RawRequest::new(Method::PUT, "/bucket/k")
                .header("x-amz-copy-source", "/src-bucket/src")
                .header("x-amz-copy-source-if-modified-since", SIGNED_YEAR)
                .header("x-amz-copy-source-if-unmodified-since", SIGNED_YEAR),
            Expect::Identical,
        ),
        row(
            "upload-part-copy-signed-year-conditions",
            RawRequest::new(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}"))
                .header("x-amz-copy-source", "/src-bucket/src")
                .header("x-amz-copy-source-if-modified-since", SIGNED_YEAR)
                .header("x-amz-copy-source-if-unmodified-since", SIGNED_YEAR),
            Expect::Identical,
        ),
        row(
            "upload-part-copy-every-member",
            source_sse(sse(RawRequest::new(Method::PUT, &format!("/bucket/k?partNumber=2&uploadId={UPLOAD_ID}"))
                .header("x-amz-copy-source", "/src-bucket/src?versionId=v2")
                .header("x-amz-copy-source-range", "bytes=0-9")
                .header("x-amz-copy-source-if-match", "\"etag-1\"")
                .header("x-amz-copy-source-if-none-match", "\"etag-2\"")
                .header("x-amz-copy-source-if-modified-since", DATE)
                .header("x-amz-copy-source-if-unmodified-since", DATE)
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-source-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"))),
            Expect::Identical,
        ),
    ]
}

fn multipart() -> Vec<SeamRow> {
    let part_checksums = "<ChecksumCRC32>AAAAAA==</ChecksumCRC32><ChecksumCRC32C>AAAAAA==</ChecksumCRC32C>\
        <ChecksumCRC64NVME>AAAAAAAAAAA=</ChecksumCRC64NVME><ChecksumSHA1>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ChecksumSHA1>\
        <ChecksumSHA256>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ChecksumSHA256>";
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag>{part_checksums}</Part>\
         <Part><PartNumber>2</PartNumber><ETag>\"e2\"</ETag></Part></CompleteMultipartUpload>"
    );
    vec![
        row(
            "create-multipart-upload-every-stored-member",
            grants(stored_headers(
                RawRequest::post("/bucket/k?uploads", b"")
                    .header("x-amz-checksum-algorithm", "SHA256")
                    .header("x-amz-checksum-type", "COMPOSITE"),
            )),
            Expect::Identical,
        ),
        row(
            "create-multipart-upload-customer-key",
            sse(RawRequest::post("/bucket/k?uploads", b"").header("x-amz-checksum-type", "FULL_OBJECT")),
            Expect::Identical,
        ),
        row(
            "upload-part-every-member",
            sse(RawRequest::put(&format!("/bucket/k?partNumber=3&uploadId={UPLOAD_ID}"), b"part bytes")
                .header("content-md5", &super::content_md5(b"part bytes"))
                .header("x-amz-checksum-algorithm", "SHA256")
                .header("x-amz-sdk-checksum-algorithm", "SHA256")
                .header(
                    "x-amz-checksum-sha256",
                    &super::checksum_value(rustfs_gateway_types::ChecksumAlgorithm::Sha256, b"part bytes"),
                )
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")),
            Expect::Identical,
        ),
        row(
            "complete-multipart-upload-every-member",
            sse(document(Method::POST, &format!("/bucket/k?uploadId={UPLOAD_ID}"), &complete)
                .header("x-amz-checksum-crc32", "AAAAAA==")
                .header("x-amz-checksum-type", "FULL_OBJECT")
                .header("x-amz-mp-object-size", "12")
                .header("if-match", "\"current\"")
                .header("if-none-match", "*")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")),
            Expect::Identical,
        ),
        row(
            "abort-multipart-upload-every-member",
            RawRequest::delete(&format!("/bucket/k?uploadId={UPLOAD_ID}"))
                .header("x-amz-if-match-initiated-time", DATE)
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
    ]
}

fn subresources() -> Vec<SeamRow> {
    let owner = "<Owner><ID>owner-1</ID><DisplayName>owner</DisplayName></Owner>";
    let acl = format!(
        "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{owner}<AccessControlList>\
         <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>owner-1</ID><DisplayName>owner</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>\
         <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>\
         <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\"><EmailAddress>a@example.com</EmailAddress></Grantee><Permission>READ_ACP</Permission></Grant>\
         </AccessControlList></AccessControlPolicy>"
    );
    vec![
        row(
            "put-object-tagging-every-member",
            {
                let body = "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value></Value></Tag></TagSet></Tagging>";
                checked(
                    document(Method::PUT, &format!("/bucket/k?tagging&versionId={VERSION_ID}"), body),
                    ChecksumAlgorithm::Crc32,
                    "CRC32",
                    body.as_bytes(),
                )
            }
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-object-retention-every-member",
            {
                let body = format!("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{LOCK_DATE}</RetainUntilDate></Retention>");
                checked(
                    document(Method::PUT, &format!("/bucket/k?retention&versionId={VERSION_ID}"), &body),
                    ChecksumAlgorithm::Sha256,
                    "SHA256",
                    body.as_bytes(),
                )
            }
            .header("x-amz-bypass-governance-retention", "true")
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-object-legal-hold-every-member",
            {
                let body = "<LegalHold><Status>OFF</Status></LegalHold>";
                checked(
                    document(Method::PUT, &format!("/bucket/k?legal-hold&versionId={VERSION_ID}"), body),
                    ChecksumAlgorithm::Crc32c,
                    "CRC32C",
                    body.as_bytes(),
                )
            }
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-object-acl-headers",
            grants(RawRequest::put(&format!("/bucket/k?acl&versionId={VERSION_ID}"), b""))
                .header("content-md5", &super::content_md5(b""))
                .header("x-amz-grant-write", "id=\"writer\"")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "put-object-acl-document",
            checked(document(Method::PUT, "/bucket/k?acl", &acl), ChecksumAlgorithm::Sha1, "SHA1", acl.as_bytes()),
            Expect::Identical,
        ),
    ]
}

fn deletes() -> Vec<SeamRow> {
    vec![
        row(
            "delete-object-every-member",
            RawRequest::delete(&format!("/bucket/k?versionId={VERSION_ID}"))
                .header("x-amz-mfa", "SERIAL 123456")
                .header("x-amz-bypass-governance-retention", "true")
                .header("if-match", "\"etag\"")
                .header("x-amz-if-match-last-modified-time", DATE)
                .header("x-amz-if-match-size", "12")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "delete-objects-keys-and-versions",
            {
                let body = format!(
                    "<Delete><Object><Key>a b</Key></Object><Object><Key>c/d</Key><VersionId>{VERSION_ID}</VersionId></Object><Quiet>true</Quiet></Delete>"
                );
                checked(document(Method::POST, "/bucket?delete", &body), ChecksumAlgorithm::Crc64Nvme, "CRC64NVME", body.as_bytes())
            }
            .header("x-amz-mfa", "SERIAL 123456")
            .header("x-amz-bypass-governance-retention", "true")
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "delete-object-tagging-every-member",
            RawRequest::delete(&format!("/bucket/k?tagging&versionId={VERSION_ID}")).header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
    ]
}

/// A select restore reading and writing JSON, with the grantee forms the CSV row does not use.
const SELECT_JSON: &str = "<RestoreRequest><Type>SELECT</Type><Tier>Expedited</Tier>\
    <SelectParameters><InputSerialization><JSON><Type>LINES</Type></JSON><CompressionType>NONE</CompressionType></InputSerialization>\
    <ExpressionType>SQL</ExpressionType><Expression>select * from s3object</Expression>\
    <OutputSerialization><JSON><RecordDelimiter>\n</RecordDelimiter></JSON></OutputSerialization></SelectParameters>\
    <OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix><AccessControlList>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\"><EmailAddress>a@example.com</EmailAddress></Grantee><Permission>READ</Permission></Grant>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ_ACP</Permission></Grant>\
    </AccessControlList></S3></OutputLocation></RestoreRequest>";

fn restores() -> Vec<SeamRow> {
    let select = "<RestoreRequest><Days>3</Days><Description>select</Description><Type>SELECT</Type><Tier>Standard</Tier>\
        <SelectParameters><InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo><Comments>#</Comments>\
        <QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>\
        <QuoteCharacter>\"</QuoteCharacter><AllowQuotedRecordDelimiter>true</AllowQuotedRecordDelimiter></CSV>\
        <CompressionType>GZIP</CompressionType></InputSerialization><ExpressionType>SQL</ExpressionType>\
        <Expression>select * from s3object</Expression><OutputSerialization><CSV><QuoteFields>ALWAYS</QuoteFields>\
        <QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>\
        <QuoteCharacter>\"</QuoteCharacter></CSV></OutputSerialization></SelectParameters>\
        <OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix><Encryption><EncryptionType>aws:kms</EncryptionType>\
        <KMSKeyId>k</KMSKeyId><KMSContext>c</KMSContext></Encryption><CannedACL>private</CannedACL>\
        <AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>i</ID><DisplayName>d</DisplayName></Grantee><Permission>READ</Permission></Grant></AccessControlList>\
        <Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>\
        <UserMetadata><MetadataEntry><Name>n</Name><Value>v</Value></MetadataEntry></UserMetadata>\
        <StorageClass>STANDARD</StorageClass></S3></OutputLocation></RestoreRequest>";
    vec![
        row(
            "restore-object-glacier-every-member",
            {
                let body = "<RestoreRequest><Days>2</Days><GlacierJobParameters><Tier>Bulk</Tier></GlacierJobParameters></RestoreRequest>";
                checked(
                    document(Method::POST, &format!("/bucket/k?restore&versionId={VERSION_ID}"), body),
                    ChecksumAlgorithm::Crc32,
                    "CRC32",
                    body.as_bytes(),
                )
            }
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row("restore-object-select-every-member", document(Method::POST, "/bucket/k?restore", select), Expect::Identical),
        row("restore-object-select-json", document(Method::POST, "/bucket/k?restore", SELECT_JSON), Expect::Identical),
        row(
            "restore-object-select-parquet",
            document(
                Method::POST,
                "/bucket/k?restore",
                "<RestoreRequest><Type>SELECT</Type><SelectParameters><InputSerialization><Parquet/></InputSerialization>\
                 <ExpressionType>SQL</ExpressionType><Expression>select * from s3object</Expression>\
                 <OutputSerialization><JSON/></OutputSerialization></SelectParameters>\
                 <OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix></S3></OutputLocation></RestoreRequest>",
            ),
            Expect::Identical,
        ),
    ]
}

pub(super) fn rows() -> Vec<SeamRow> {
    let mut rows = copies();
    rows.extend(multipart());
    rows.extend(subresources());
    rows.extend(deletes());
    rows.extend(restores());
    rows
}
