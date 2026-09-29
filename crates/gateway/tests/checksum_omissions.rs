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

//! The checksum-omission waivers through a whole service, on every operation the AWS model marks
//! `httpChecksumRequired` (rustfs/backlog#1677, ruling R5).
//!
//! Responsible for: proving, with all eighteen operations registered, that the default assembly
//! refuses a body with no integrity claim before any handler runs; that
//! `ServiceBuilder::accept_all_checksum_omissions` hands every one of them to its handler instead;
//! that under it a `Content-MD5` or `x-amz-checksum-*` that does not match the body still reaches
//! no handler; and that the two client waivers together still leave the other fourteen required.
//! NOT responsible for: the closed sets themselves (`builder/client_quirks.rs` unit tests hold
//! them to `spec/operations`), the refusal codes a RustFS deployment renders for a mismatch
//! (`ServiceBuilder::answer_checksum_failures_with_bad_digest`), or what a RustFS backend stores
//! (`compat/sut`'s `checksum_omission_tests.rs`).
//! Upstream: `S3Service` with a counting backend for every checksum-required operation.
//! Downstream: none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::{CHECKSUM_REQUIRED_OPERATIONS, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, dto};

use super::tagging_reachability::content_md5;
use crate::support;

/// Counts the requests that reached any handler, so "no handler ran" is a measurement.
struct Counting(Arc<AtomicUsize>);

macro_rules! counting_handlers {
    ($($op:ident),* $(,)?) => {
        $(
            impl Handler<dto::$op> for Counting {
                fn call(
                    &self,
                    _request: Req<dto::$op>,
                ) -> impl core::future::Future<Output = HandlerResult<dto::$op>> + Send {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    async { Ok(Resp::new(Default::default())) }
                }
            }
        )*

        fn register_all(builder: ServiceBuilder, backend: &Arc<Counting>) -> ServiceBuilder {
            builder $(.register::<dto::$op, _>(Arc::clone(backend)))*
        }
    };
}

counting_handlers! {
    DeleteObjects,
    PutBucketAcl,
    PutBucketCors,
    PutBucketEncryption,
    PutBucketLifecycleConfiguration,
    PutBucketLogging,
    PutBucketPolicy,
    PutBucketReplication,
    PutBucketRequestPayment,
    PutBucketTagging,
    PutBucketVersioning,
    PutBucketWebsite,
    PutObjectAcl,
    PutObjectLegalHold,
    PutObjectLockConfiguration,
    PutObjectRetention,
    PutObjectTagging,
    PutPublicAccessBlock,
}

const XMLNS: &str = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";

/// One well-formed request per checksum-required operation: the operation, method, target, any
/// extra header it needs and its body. Every body is one the operation's decoder accepts, so a
/// request that is refused was refused for its integrity claim and for nothing else.
/// One checksum-required write: its operation, method, target, an extra header it needs, and body.
type Write = (&'static str, http::Method, &'static str, Option<(&'static str, &'static str)>, String);

fn writes() -> Vec<Write> {
    let put = http::Method::PUT;
    vec![
        (
            "DeleteObjects",
            http::Method::POST,
            "/bucket?delete",
            None,
            format!("<Delete {XMLNS}><Object><Key>gone</Key></Object></Delete>"),
        ),
        ("PutBucketAcl", put.clone(), "/bucket?acl", Some(("x-amz-acl", "private")), String::new()),
        (
            "PutBucketCors",
            put.clone(),
            "/bucket?cors",
            None,
            format!(
                "<CORSConfiguration {XMLNS}><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"
            ),
        ),
        (
            "PutBucketEncryption",
            put.clone(),
            "/bucket?encryption",
            None,
            format!(
                "<ServerSideEncryptionConfiguration {XMLNS}><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
            ),
        ),
        (
            "PutBucketLifecycleConfiguration",
            put.clone(),
            "/bucket?lifecycle",
            None,
            format!(
                "<LifecycleConfiguration {XMLNS}><Rule><ID>r</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
        ),
        (
            "PutBucketLogging",
            put.clone(),
            "/bucket?logging",
            None,
            format!("<BucketLoggingStatus {XMLNS}></BucketLoggingStatus>"),
        ),
        (
            "PutBucketPolicy",
            put.clone(),
            "/bucket?policy",
            None,
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}"#
                .to_owned(),
        ),
        (
            "PutBucketReplication",
            put.clone(),
            "/bucket?replication",
            None,
            format!(
                "<ReplicationConfiguration {XMLNS}><Role>arn:aws:iam::123456789012:role/r</Role><Rule><ID>r</ID><Status>Enabled</Status><Priority>1</Priority><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination></Rule></ReplicationConfiguration>"
            ),
        ),
        (
            "PutBucketRequestPayment",
            put.clone(),
            "/bucket?requestPayment",
            None,
            format!("<RequestPaymentConfiguration {XMLNS}><Payer>BucketOwner</Payer></RequestPaymentConfiguration>"),
        ),
        (
            "PutBucketTagging",
            put.clone(),
            "/bucket?tagging",
            None,
            format!("<Tagging {XMLNS}><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"),
        ),
        (
            "PutBucketVersioning",
            put.clone(),
            "/bucket?versioning",
            None,
            format!("<VersioningConfiguration {XMLNS}><Status>Enabled</Status></VersioningConfiguration>"),
        ),
        (
            "PutBucketWebsite",
            put.clone(),
            "/bucket?website",
            None,
            format!(
                "<WebsiteConfiguration {XMLNS}><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>"
            ),
        ),
        ("PutObjectAcl", put.clone(), "/bucket/key?acl", Some(("x-amz-acl", "private")), String::new()),
        (
            "PutObjectLegalHold",
            put.clone(),
            "/bucket/key?legal-hold",
            None,
            format!("<LegalHold {XMLNS}><Status>ON</Status></LegalHold>"),
        ),
        (
            "PutObjectLockConfiguration",
            put.clone(),
            "/bucket?object-lock",
            None,
            format!(
                "<ObjectLockConfiguration {XMLNS}><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>"
            ),
        ),
        (
            "PutObjectRetention",
            put.clone(),
            "/bucket/key?retention",
            None,
            format!("<Retention {XMLNS}><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>"),
        ),
        (
            "PutObjectTagging",
            put.clone(),
            "/bucket/key?tagging",
            None,
            format!("<Tagging {XMLNS}><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"),
        ),
        (
            "PutPublicAccessBlock",
            put,
            "/bucket?publicAccessBlock",
            None,
            format!(
                "<PublicAccessBlockConfiguration {XMLNS}><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>"
            ),
        ),
    ]
}

/// An assembly with every checksum-required operation registered, configured by `configure`.
fn service(configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> (S3Service, Arc<AtomicUsize>) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Counting(Arc::clone(&reached)));
    let service = register_all(configure(support::wired_at_signed_time()), &backend)
        .build()
        .expect("a complete assembly");
    (service, reached)
}

/// The base64 MD5 and CRC32 of `wrong`, which is none of the bodies above.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";
const WRONG_CRC32: &str = "J8WdGg==";

/// Sends every write with `integrity` headers, returning each operation's status and error code.
async fn send_all(service: &S3Service, integrity: &[(&str, &str)]) -> Vec<(&'static str, u16, Option<String>)> {
    let mut answers = Vec::new();
    for (operation, method, target, extra, body) in writes() {
        let mut headers: Vec<(&str, &str)> = integrity.to_vec();
        headers.extend(extra);
        let request = support::signed_target_with_body_and_headers(method, target, &headers, Bytes::from(body));
        let (status, body) = support::exchange(service, request).await;
        answers.push((operation, status.as_u16(), support::element_text(&body, "Code").map(str::to_owned)));
    }
    answers
}

#[test]
fn the_fixture_covers_every_checksum_required_operation_once() {
    let mut covered: Vec<&str> = writes().into_iter().map(|(operation, ..)| operation).collect();
    covered.sort_unstable();
    let mut listed = CHECKSUM_REQUIRED_OPERATIONS.to_vec();
    listed.sort_unstable();
    assert_eq!(covered, listed);
}

/// Negative — the default is the AWS model: every one of the eighteen writes with no integrity
/// claim is `400 InvalidRequest`, and no handler runs.
#[tokio::test]
async fn n_by_default_every_modelled_write_refuses_a_body_with_no_integrity_claim() {
    let (service, reached) = service(|builder| builder);
    for (operation, status, code) in send_all(&service, &[]).await {
        assert_eq!((status, code.as_deref()), (400, Some("InvalidRequest")), "{operation}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Positive — under the switch every one of the eighteen writes reaches its handler with no
/// integrity claim at all, as legacy RustFS serves it.
#[tokio::test]
async fn under_the_switch_every_modelled_write_reaches_its_handler_without_a_checksum() {
    let (service, reached) = service(ServiceBuilder::accept_all_checksum_omissions);
    for (operation, status, code) in send_all(&service, &[]).await {
        assert!((200..300).contains(&status), "{operation}: {status} {code:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), CHECKSUM_REQUIRED_OPERATIONS.len());
}

/// Positive — a correct `Content-MD5` is still accepted under the switch.
#[tokio::test]
async fn under_the_switch_a_matching_content_md5_is_still_accepted() {
    let (service, reached) = service(ServiceBuilder::accept_all_checksum_omissions);
    let mut sent = 0;
    for (operation, method, target, extra, body) in writes() {
        let digest = content_md5(body.as_bytes());
        let mut headers = vec![("content-md5", digest.as_str())];
        headers.extend(extra);
        let request = support::signed_target_with_body_and_headers(method, target, &headers, Bytes::from(body));
        let (status, answer) = support::exchange(&service, request).await;
        assert!(status.is_success(), "{operation}: {status} {answer}");
        sent += 1;
    }
    assert_eq!(reached.load(Ordering::SeqCst), sent);
}

/// Negative — the switch drops the requirement, not the verification: a `Content-MD5` that does
/// not match the body is `400 BadDigest` on every one of the eighteen, and no handler runs.
#[tokio::test]
async fn n_under_the_switch_a_content_md5_that_does_not_match_reaches_no_handler() {
    let (service, reached) = service(ServiceBuilder::accept_all_checksum_omissions);
    for (operation, status, code) in send_all(&service, &[("content-md5", WRONG_MD5)]).await {
        assert_eq!((status, code.as_deref()), (400, Some("BadDigest")), "{operation}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — the same for an `x-amz-checksum-*` header: refused with the core's mismatch code on
/// every one of the eighteen, and no handler runs.
#[tokio::test]
async fn n_under_the_switch_a_checksum_header_that_does_not_match_reaches_no_handler() {
    let (service, reached) = service(ServiceBuilder::accept_all_checksum_omissions);
    let claim = [
        ("x-amz-checksum-crc32", WRONG_CRC32),
        ("x-amz-sdk-checksum-algorithm", "CRC32"),
    ];
    for (operation, status, code) in send_all(&service, &claim).await {
        assert_eq!((status, code.as_deref()), (400, Some("XAmzContentChecksumMismatch")), "{operation}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — the two client waivers together still leave the other fourteen writes required:
/// only the four writes their clients omit a checksum on reach a handler.
#[tokio::test]
async fn n_the_two_client_waivers_alone_leave_every_other_write_required() {
    let (service, reached) = service(|builder| {
        builder
            .accept_minio_client_checksum_omissions()
            .accept_s3cmd_acl_checksum_omissions()
    });
    let mut served = Vec::new();
    for (operation, status, code) in send_all(&service, &[]).await {
        if (200..300).contains(&status) {
            served.push(operation);
        } else {
            assert_eq!((status, code.as_deref()), (400, Some("InvalidRequest")), "{operation}");
        }
    }
    assert_eq!(served, ["PutBucketAcl", "PutBucketPolicy", "PutBucketVersioning", "PutObjectAcl"]);
    assert_eq!(reached.load(Ordering::SeqCst), served.len());
}
