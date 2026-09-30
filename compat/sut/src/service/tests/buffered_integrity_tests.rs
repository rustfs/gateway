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

//! A buffered write whose integrity claim contradicts its body, as the RustFS-profile launcher
//! answers it: refused, and nothing applied (rustfs/backlog#1677, `rd-err-0011`).
//!
//! Responsible for: every buffered write the reference backend serves and legacy RustFS was
//! observed applying without comparing — PutObjectTagging, PutBucketTagging, PutBucketPolicy,
//! PutBucketCors, PutBucketLifecycleConfiguration, PutBucketVersioning, PutBucketEncryption,
//! PutPublicAccessBlock, DeleteObjects and CompleteMultipartUpload — refusing a `Content-MD5` or
//! `x-amz-checksum-*` that does not match the body or cannot be read, and two different checksums,
//! each leaving what the write would change exactly as it was; and the same write with a matching
//! `Content-MD5` being applied, so "unchanged" is a measurement.
//! NOT responsible for: the codes a RustFS deployment renders (`bad_digest_tests.rs`), or the
//! comparison itself (`rustfs_gateway_http::BodyIntegrity` and the generated decoders).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build (rustfs/rustfs `e870a6d25b`,
//! `RUSTFS_S3_STACK=legacy`): every one of these writes with a wrong or unreadable `Content-MD5`, a
//! wrong or unreadable `x-amz-checksum-crc32`, or two different checksums is `200`/`204` and
//! applied. The gateway keeps refusing them under the hard constraint of rustfs/backlog#1677:
//! storing a body that contradicts its declared checksum is data damage.

use super::*;

const XMLNS: &str = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
/// The base64 MD5 of `wrong`, which is none of the bodies below.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";
/// A well-formed CRC-32 that is none of the bodies' own.
const WRONG_CRC32: &str = "AAAAAA==";
/// A well-formed SHA-256 that is none of the bodies' own.
const WRONG_SHA256: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// One buffered write: its operation, method, target, body, the body's base64 MD5 and CRC-32, and
/// the target that reads back what it changes.
struct Write {
    operation: &'static str,
    method: http::Method,
    target: &'static str,
    body: String,
    md5: &'static str,
    crc32: &'static str,
    read_back: &'static str,
}

fn writes() -> Vec<Write> {
    let put = || http::Method::PUT;
    vec![
        Write {
            operation: "PutObjectTagging",
            method: put(),
            target: "/integrity/object?tagging",
            body: format!("<Tagging {XMLNS}><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"),
            md5: "z275X9v+yCiOgdVxBKqSYQ==",
            crc32: "Mr5yoA==",
            read_back: "/integrity/object?tagging",
        },
        Write {
            operation: "PutBucketTagging",
            method: put(),
            target: "/integrity?tagging",
            body: format!("<Tagging {XMLNS}><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"),
            md5: "z275X9v+yCiOgdVxBKqSYQ==",
            crc32: "Mr5yoA==",
            read_back: "/integrity?tagging",
        },
        Write {
            operation: "PutBucketPolicy",
            method: put(),
            target: "/integrity?policy",
            body: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::integrity/*"}]}"#
                .to_owned(),
            md5: "mc4siIQ8PA3G9q1bMJMMTg==",
            crc32: "P572uw==",
            read_back: "/integrity?policy",
        },
        Write {
            operation: "PutBucketCors",
            method: put(),
            target: "/integrity?cors",
            body: format!(
                "<CORSConfiguration {XMLNS}><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"
            ),
            md5: "xxjprZj9L5U5nysJOpDhMA==",
            crc32: "AO287g==",
            read_back: "/integrity?cors",
        },
        Write {
            operation: "PutBucketLifecycleConfiguration",
            method: put(),
            target: "/integrity?lifecycle",
            body: format!(
                "<LifecycleConfiguration {XMLNS}><Rule><ID>r</ID><Filter><Prefix>x/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
            md5: "Q16jNMnTFs03EJACxrn/uA==",
            crc32: "EiGGGg==",
            read_back: "/integrity?lifecycle",
        },
        Write {
            operation: "PutBucketVersioning",
            method: put(),
            target: "/integrity?versioning",
            body: format!("<VersioningConfiguration {XMLNS}><Status>Enabled</Status></VersioningConfiguration>"),
            md5: "QQFYoy/mRYV9PGZUfFi0Bw==",
            crc32: "C8vlPQ==",
            read_back: "/integrity?versioning",
        },
        Write {
            operation: "PutBucketEncryption",
            method: put(),
            target: "/integrity?encryption",
            body: format!(
                "<ServerSideEncryptionConfiguration {XMLNS}><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
            ),
            md5: "5bZurju84n5lUGMQ6mrGXQ==",
            crc32: "2516AQ==",
            read_back: "/integrity?encryption",
        },
        Write {
            operation: "PutPublicAccessBlock",
            method: put(),
            target: "/integrity?publicAccessBlock",
            body: format!(
                "<PublicAccessBlockConfiguration {XMLNS}><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>"
            ),
            md5: "5uDXmIGIg4k3oOj8rJ6rYw==",
            crc32: "kCyNEg==",
            read_back: "/integrity?publicAccessBlock",
        },
        Write {
            operation: "DeleteObjects",
            method: http::Method::POST,
            target: "/integrity?delete",
            body: format!("<Delete {XMLNS}><Object><Key>object</Key></Object></Delete>"),
            md5: "xT9hbiDoG/+1qv80lRPr1A==",
            crc32: "ue3gEA==",
            read_back: "/integrity/object",
        },
    ]
}

/// A launcher with the bucket, and the object the object-level writes address.
async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/integrity", ""), ("/integrity/object", "hello")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

async fn send(service: &S3Service, write: &Write, headers: &[(&str, &str)]) -> WireResponse {
    let body = Bytes::from(write.body.clone());
    exchange(service, signed(MAIN_KEY, MAIN_SECRET, write.method.clone(), write.target, body, headers)).await
}

/// What `target` reads back: its status and its body, the per-request identifiers removed.
async fn read_back(service: &S3Service, target: &str) -> (u16, String) {
    let read = exchange(service, as_main(http::Method::GET, target, Bytes::new())).await;
    let mut body = body_of(&read);
    for element in ["RequestId", "HostId"] {
        let (open, close) = (format!("<{element}>"), format!("</{element}>"));
        if let (Some(start), Some(end)) = (body.find(&open), body.find(&close)) {
            body.replace_range(start..end + close.len(), "");
        }
    }
    (read.status().as_u16(), body)
}

fn code(response: &WireResponse) -> Option<String> {
    let body = body_of(response);
    let start = body.find("<Code>")? + "<Code>".len();
    let end = body[start..].find("</Code>")? + start;
    Some(body[start..end].to_owned())
}

/// Negative — every contradicting or unreadable claim on every buffered write is refused with the
/// RustFS profile's code and changes nothing; the same write with its own `Content-MD5` is
/// applied, so the read-back sees a write when there is one.
#[tokio::test]
async fn n_a_buffered_write_that_contradicts_its_integrity_claim_changes_nothing() {
    for write in writes() {
        let root = TestRoot::new();
        let service = served(&root).await;
        let before = read_back(&service, write.read_back).await;
        let rows: [(&[(&str, &str)], &str); 5] = [
            (&[("content-md5", WRONG_MD5)], "BadDigest"),
            (&[("content-md5", "not-base64!")], "InvalidDigest"),
            (&[("x-amz-checksum-crc32", WRONG_CRC32)], "BadDigest"),
            (&[("x-amz-checksum-crc32", "not base64")], "BadDigest"),
            (
                &[("x-amz-checksum-crc32", write.crc32), ("x-amz-checksum-sha256", WRONG_SHA256)],
                "InvalidRequest",
            ),
        ];
        for (claims, expected) in rows {
            let refused = send(&service, &write, claims).await;
            assert_eq!(
                (refused.status().as_u16(), code(&refused).as_deref()),
                (400, Some(expected)),
                "{} {claims:?}: {}",
                write.operation,
                body_of(&refused)
            );
            assert_eq!(read_back(&service, write.read_back).await, before, "{} {claims:?}", write.operation);
        }
        let applied = send(&service, &write, &[("content-md5", write.md5)]).await;
        assert!(applied.status().is_success(), "{}: {}", write.operation, body_of(&applied));
        assert_ne!(read_back(&service, write.read_back).await, before, "{}", write.operation);
    }
}

/// Negative — a CompleteMultipartUpload whose `Content-MD5` contradicts or cannot read its part
/// list completes nothing: the object does not exist and the part is still listed; with its own
/// `Content-MD5` it completes.
#[tokio::test]
async fn n_a_completion_that_contradicts_its_content_md5_completes_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let created = exchange(&service, as_main(http::Method::POST, "/integrity/mpu?uploads", Bytes::new())).await;
    let created = body_of(&created);
    let start = created.find("<UploadId>").expect("an upload id") + "<UploadId>".len();
    let end = created[start..].find("</UploadId>").expect("an upload id") + start;
    let upload = created[start..end].to_owned();
    let part = format!("/integrity/mpu?partNumber=1&uploadId={upload}");
    let uploaded = exchange(&service, as_main(http::Method::PUT, &part, Bytes::from_static(b"hello"))).await;
    assert_eq!(uploaded.status(), 200, "{}", body_of(&uploaded));
    let complete = format!("/integrity/mpu?uploadId={upload}");
    let list = format!(
        "<CompleteMultipartUpload {XMLNS}><Part><PartNumber>1</PartNumber><ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part></CompleteMultipartUpload>"
    );
    for (md5, expected) in [(WRONG_MD5, "BadDigest"), ("not-base64!", "InvalidDigest")] {
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::POST,
            &complete,
            Bytes::from(list.clone()),
            &[("content-md5", md5)],
        );
        let refused = exchange(&service, request).await;
        assert_eq!(
            (refused.status().as_u16(), code(&refused).as_deref()),
            (400, Some(expected)),
            "{md5}: {}",
            body_of(&refused)
        );
        assert_eq!(read_back(&service, "/integrity/mpu").await.0, 404, "{md5}");
        let parts = body_of(&exchange(&service, as_main(http::Method::GET, &complete, Bytes::new())).await);
        assert!(parts.contains("<PartNumber>1</PartNumber>"), "{md5}: {parts}");
    }
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::POST,
        &complete,
        Bytes::from(list),
        &[("content-md5", "iSUZiBgcRi+2dSJ43aokeA==")],
    );
    let completed = exchange(&service, request).await;
    assert_eq!(completed.status(), 200, "{}", body_of(&completed));
    assert_eq!(read_back(&service, "/integrity/mpu").await, (200, "hello".to_owned()));
}
