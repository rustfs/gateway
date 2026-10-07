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

//! The refusal matrix: requests both stacks refuse, and what must agree between the two answers.
//!
//! Responsible for: the contract every shared refusal holds — the same status and `<Code>`, an XML
//! document typed and framed as one, the message policy, `<Resource>` presence, the connection
//! verdict — and the auth, routing, decode, conditional and range rows that hold it.
//! NOT responsible for: the RustFS body errors crossing the adapter (`super::mapping`), or where
//! the answers differ (`super::divergences`, ruled in the register).
//! Upstream: `super`. Downstream: `super::mapping`, `super::divergences`.
//!
//! # The message policy
//!
//! A refusal the gateway makes itself, before any handler, carries one fixed sentence per cause
//! that names nothing from the request (`scripts/check_preauth_static_msg.sh`); the s3s wording is
//! its own and is not compared (rd-err-0009). A refusal the app body makes carries the body's
//! message on both stacks, byte for byte, because the adapter hands it over unchanged.
//!
//! Rows already ruled elsewhere are not repeated: an unknown access key is rd-loc-0003, the line
//! break after the XML declaration is rd-loc-0001 and holds for every error document here, and a
//! plain PUT without `Content-Length` is rd-put-0003 (its gateway document is pinned below).

use super::super::super::SEAM_REVISION;
use super::super::{ContextRequest, PATH_HOST};
use super::s3s;
use super::{Length, Pair, Reply, Scenario, both};
use http::Method;
use rustfs_gateway_types::compat::OracleRevision;
use s3s::{S3Error, S3ErrorCode};

/// The declaration both stacks open an error document with.
pub(super) const DECLARATION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

/// The gateway's sentence for a caller its policy refuses, anonymous or presigned past expiry.
pub(super) const NOT_ALLOWED: &str = "the request is not allowed";
/// The gateway's sentence for every credential rejection.
pub(super) const NOT_AUTHENTICATED: &str = "the request was not authenticated";
/// The gateway's sentence for a signing clock outside the window.
pub(super) const SKEWED: &str = "the request timestamp is outside the accepted window";
/// The gateway's sentence for a member value its type cannot hold.
pub(super) const UNREPRESENTABLE: &str = "the request carries a value this member cannot hold";

pub(super) fn location() -> ContextRequest {
    ContextRequest::get(PATH_HOST, "/photos", "location")
}

pub(super) fn object_get() -> ContextRequest {
    ContextRequest::get(PATH_HOST, "/photos/a.txt", "")
}

pub(super) fn object_head() -> ContextRequest {
    ContextRequest::head(PATH_HOST, "/photos/a.txt", "")
}

pub(super) fn object_put(body: &[u8]) -> ContextRequest {
    ContextRequest::put(PATH_HOST, "/photos/a.txt", body)
}

pub(super) fn part_put(body: &[u8]) -> ContextRequest {
    ContextRequest::new(Method::PUT, PATH_HOST, "/photos/a.txt", "partNumber=1&uploadId=missing-upload", body)
}

/// How the two `<Message>`s relate.
#[derive(Clone, Copy, Debug)]
pub(super) enum Message {
    /// The gateway writes this fixed sentence, whatever s3s writes.
    Gateway(&'static str),
    /// Both write the app body's message; an absent one reads as empty.
    Same,
}

/// What one row expects beyond the shared contract.
#[derive(Clone, Copy, Debug)]
pub(super) struct Expect {
    pub(super) status: u16,
    pub(super) code: &'static str,
    pub(super) message: Message,
    /// The gateway's `<Resource>`; s3s never writes one.
    pub(super) resource: Option<&'static str>,
    /// The gateway's connection verdict; s3s states none.
    pub(super) closes: bool,
    /// Whether the app body ran, as `(gateway, s3s)`.
    pub(super) reached: (bool, bool),
}

impl Expect {
    /// A refusal the gateway makes before its handler, keeping the connection.
    pub(super) const fn gateway_first(status: u16, code: &'static str, sentence: &'static str, s3s_reached: bool) -> Self {
        Self {
            status,
            code,
            message: Message::Gateway(sentence),
            resource: None,
            closes: false,
            reached: (false, s3s_reached),
        }
    }

    /// A refusal the app body makes on both stacks.
    pub(super) const fn app_body(status: u16, code: &'static str) -> Self {
        Self {
            status,
            code,
            message: Message::Same,
            resource: None,
            closes: false,
            reached: (true, true),
        }
    }
}

/// An answer that is an XML error document, typed as one, framed by its exact length, `<Code>` first.
pub(super) fn document_contract(reply: &Reply) {
    assert!(reply.body.starts_with(DECLARATION), "{reply:#?}");
    assert_eq!(reply.header("content-type"), Some("application/xml"), "{reply:#?}");
    assert_eq!(reply.wire_length(), Some(reply.body.len()), "{reply:#?}");
    assert_eq!(reply.elements().first().copied(), Some("Code"), "{reply:#?}");
}

/// rd-err-0001: the gateway carries one request id and one host id, the same in its head and last in
/// its document; the s3s service carries neither.
pub(super) fn identifiers(gateway: &Reply, oracle: &Reply) {
    let elements = gateway.elements();
    assert_eq!(
        elements.get(elements.len().saturating_sub(2)..),
        Some(&["RequestId", "HostId"][..]),
        "{gateway:#?}"
    );
    assert_eq!(gateway.header("x-amz-request-id"), gateway.element("RequestId"), "{gateway:#?}");
    assert_eq!(gateway.header("x-amz-id-2"), gateway.element("HostId"), "{gateway:#?}");
    assert_eq!(gateway.element("RequestId").map(str::len), Some(16), "{gateway:#?}");
    assert_eq!(
        (
            oracle.header("x-amz-request-id"),
            oracle.element("RequestId"),
            oracle.header("x-amz-id-2"),
            oracle.element("HostId")
        ),
        (None, None, None, None),
        "{oracle:#?}"
    );
}

/// Sends `scenario` through both stacks and holds the two answers to the shared contract and `expect`.
pub(super) fn refused_alike(scenario: &Scenario, expect: Expect) -> Pair {
    let pair = both(scenario).expect("both stacks answer");
    let Pair { gateway, oracle } = &pair;
    assert_eq!((gateway.status, oracle.status), (expect.status, expect.status), "{pair:#?}");
    assert_eq!((gateway.code(), oracle.code()), (Some(expect.code), Some(expect.code)), "{pair:#?}");
    assert_eq!((gateway.reached, oracle.reached), expect.reached, "{pair:#?}");
    document_contract(gateway);
    document_contract(oracle);
    identifiers(gateway, oracle);
    match expect.message {
        Message::Gateway(sentence) => assert_eq!(gateway.message(), Some(sentence), "{pair:#?}"),
        Message::Same => assert_eq!(gateway.message().unwrap_or_default(), oracle.message().unwrap_or_default(), "{pair:#?}"),
    }
    assert_eq!(gateway.element("Resource"), expect.resource, "{pair:#?}");
    assert_eq!(oracle.element("Resource"), None, "s3s never writes a Resource: {pair:#?}");
    assert_eq!((gateway.closes, oracle.closes), (Some(expect.closes), None), "{pair:#?}");
    pair
}

// ── auth ──────────────────────────────────────────────────────────────────────────────────────

/// RustFS's access hook refuses an anonymous caller on a private bucket; the gateway's authorizer
/// stands in for it, s3s's default access check for the hook.
#[test]
fn an_unsigned_request_is_access_denied_by_both_stacks() {
    refused_alike(&Scenario::new(location()), Expect::gateway_first(403, "AccessDenied", NOT_ALLOWED, false));
}

#[test]
fn a_forged_signature_is_signature_does_not_match_on_both_stacks() {
    let scenario = Scenario::new(location().signed("us-east-1").forged());
    refused_alike(&scenario, Expect::gateway_first(403, "SignatureDoesNotMatch", NOT_AUTHENTICATED, false));
}

/// Presigned an hour ago for one minute. GetObject, because the gateway admits presigning only
/// for the operations its posture lists.
#[test]
fn an_expired_presigned_url_is_access_denied_by_both_stacks() {
    let scenario = Scenario::new(object_get().signed("us-east-1"))
        .presigned(60)
        .signed_at_offset(-3600);
    let pair = refused_alike(&scenario, Expect::gateway_first(403, "AccessDenied", NOT_ALLOWED, false));
    assert_eq!(pair.oracle.message(), Some("Request has expired"));
}

/// Signed twenty minutes ago; both windows are fifteen.
#[test]
fn a_skewed_signing_clock_is_request_time_too_skewed_on_both_stacks() {
    let scenario = Scenario::new(location().signed("us-east-1")).signed_at_offset(-1200);
    refused_alike(&scenario, Expect::gateway_first(403, "RequestTimeTooSkewed", SKEWED, false));
}

// ── routing ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_missing_bucket_from_the_app_body_is_no_such_bucket_on_both_stacks() {
    for request in [location(), object_put(b"")] {
        let scenario = Scenario::new(request.signed("us-east-1"))
            .app_refuses(|| S3Error::with_message(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist"));
        let pair = refused_alike(&scenario, Expect::app_body(404, "NoSuchBucket"));
        assert_eq!(pair.gateway.message(), Some("The specified bucket does not exist"));
    }
}

/// Neither stack models `PATCH` on an object or a `POST` that is not a form upload, and both say
/// so with `501`, not AWS's `405`: the answers agree, so nothing is ruled.
#[test]
fn a_method_neither_stack_models_is_not_implemented_on_both() {
    const NOT_AN_OPERATION: &str = "This request does not name any S3 operation. If clients address buckets as virtual \
                                    hosts, check that the gateway has been configured with the domain it serves; \
                                    otherwise the method, path or query is not one this service defines.";
    for method in [Method::PATCH, Method::POST] {
        let scenario = Scenario::new(ContextRequest::new(method, PATH_HOST, "/photos/a.txt", "", b"").signed("us-east-1"));
        refused_alike(&scenario, Expect::gateway_first(501, "NotImplemented", NOT_AN_OPERATION, false));
    }
}

/// A refused `HEAD` has no document on the wire: the gateway writes none, and the one s3s leaves in
/// its in-process body is one hyper never sends for `HEAD` (RFC 9110 §9.3.2). The status and the
/// identifiers still reach the client.
#[test]
fn n_a_refused_head_has_no_document_on_the_gateway() {
    let scenario = Scenario::new(ContextRequest::new(Method::HEAD, PATH_HOST, "/photos/a.txt", "", b"").signed("us-east-1"))
        .app_refuses(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "The specified key does not exist."));
    let pair = both(&scenario).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (404, 404), "{pair:#?}");
    assert!(pair.gateway.body.is_empty(), "{pair:#?}");
    assert!(pair.gateway.header("x-amz-request-id").is_some(), "{pair:#?}");
    assert_eq!(pair.oracle.code(), Some("NoSuchKey"), "{pair:#?}");
}

// ── decode ────────────────────────────────────────────────────────────────────────────────────

/// Content-MD5 of the body, so the gateway reaches its XML decoder instead of its integrity rule.
#[test]
fn a_malformed_configuration_document_is_malformed_xml_on_both_stacks() {
    let body = b"<VersioningConfiguration><Status>Enabled";
    let request = ContextRequest::new(Method::PUT, PATH_HOST, "/photos", "versioning", body)
        .header("content-md5", b"g4/6MLSe9e+Pvs0La+MJtQ==")
        .signed("us-east-1");
    let expect = Expect {
        message: Message::Gateway("the request body is not the XML this operation accepts"),
        ..Expect::gateway_first(400, "MalformedXML", "", false)
    };
    refused_alike(&Scenario::new(request).length(Length::Declared(body.len() as u64)), expect);
}

/// Both stacks refuse the header, but not alike. The gateway refuses it before its handler with the
/// AWS code, in a document holding the shared contract. The legacy stack hands it to the RustFS
/// body, which does not answer `InvalidDigest`: it decodes the value as base64 for its storage
/// reader and maps the decoding failure to `500 InternalError`, storing nothing (rustfs/rustfs
/// `95268a3b9`, `rustfs/src/app/object/put.rs:1724-1729` and `rustfs/src/error.rs:677`; observed on
/// a legacy RustFS build, as `rd-err-0012` records). The body is scripted here as RustFS answers it,
/// so this row no longer states an answer legacy RustFS never gives; the difference is ruled in the
/// register as `rd-err-0012`.
#[test]
fn a_content_md5_that_is_not_base64_is_invalid_digest_on_the_gateway_and_a_server_error_behind_the_legacy_stack() {
    let scenario = Scenario::new(object_put(b"hello").header("content-md5", b"not-base64!").signed("us-east-1"))
        .app_refuses(|| S3Error::new(S3ErrorCode::InternalError));
    let pair = both(&scenario).expect("both stacks answer");
    let Pair { gateway, oracle } = &pair;
    assert_eq!((gateway.status, gateway.code()), (400, Some("InvalidDigest")), "{pair:#?}");
    assert_eq!((oracle.status, oracle.code()), (500, Some("InternalError")), "{pair:#?}");
    assert_eq!((gateway.reached, oracle.reached), (false, true), "{pair:#?}");
    document_contract(gateway);
    document_contract(oracle);
    identifiers(gateway, oracle);
    assert_eq!(gateway.message(), Some("The Content-MD5 you specified is not valid"), "{pair:#?}");
    assert_eq!(gateway.element("Resource"), None, "{pair:#?}");
    assert_eq!((gateway.closes, oracle.closes), (Some(false), None), "{pair:#?}");
}

/// An empty body whose Content-MD5 is that of `hello`: the gateway checks it at the gate, the RustFS
/// body behind s3s answers the same code.
#[test]
fn a_content_md5_that_does_not_match_is_bad_digest_on_both_stacks() {
    let scenario = Scenario::new(
        object_put(b"")
            .header("content-md5", b"XUFAKrxLKna5cZ2REBfFkg==")
            .signed("us-east-1"),
    )
    .app_refuses(|| {
        S3Error::with_message(S3ErrorCode::BadDigest, "The Content-Md5 you specified did not match what we received.")
    });
    refused_alike(
        &scenario,
        Expect::gateway_first(400, "BadDigest", "The Content-MD5 you specified did not match what we received", true),
    );
}

/// One byte past 5 GiB, refused from the head. The baseline s3s has no ceiling and hands it over.
#[test]
fn a_body_past_five_gibibytes_is_entity_too_large_on_the_candidate() {
    let scenario = Scenario::new(object_put(b"").signed("us-east-1")).length(Length::Declared(5 * 1024 * 1024 * 1024 + 1));
    if SEAM_REVISION == OracleRevision::Baseline {
        let pair = both(&scenario).expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (400, 200), "{pair:#?}");
        return;
    }
    let expect = Expect {
        closes: true,
        ..Expect::gateway_first(400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size.", false)
    };
    refused_alike(&scenario, expect);
}

/// rd-put-0003 rules this divergence; pinned here is the gateway document: `411`, the model member
/// as the resource, and a close, because the peer meant to send octets nobody framed.
#[test]
fn the_gateway_411_names_the_member_and_closes() {
    let scenario = Scenario::new(object_put(b"hello").signed("us-east-1")).length(Length::Omitted);
    let pair = both(&scenario).expect("both stacks answer");
    let gateway = &pair.gateway;
    assert_eq!((gateway.status, gateway.code()), (411, Some("MissingContentLength")), "{pair:#?}");
    document_contract(gateway);
    assert_eq!(gateway.element("Resource"), Some("ContentLength"), "{pair:#?}");
    assert_eq!(gateway.closes, Some(true), "{pair:#?}");
    assert_eq!((pair.oracle.status, pair.oracle.reached), (200, true), "rd-put-0003: {pair:#?}");
}

// ── conditional and range ─────────────────────────────────────────────────────────────────────

/// RustFS evaluates `If-Match` in its body and answers `PreconditionFailed`; through the adapter the
/// gateway writes the same document. 304 and 416 cross only with their facts (rd-err-0005, rd-err-0006).
#[test]
fn a_failed_precondition_from_the_app_body_is_412_on_both_stacks() {
    let scenario = Scenario::new(object_get().header("if-match", b"\"abc\"").signed("us-east-1"))
        .app_refuses(|| S3Error::new(S3ErrorCode::PreconditionFailed));
    let pair = refused_alike(&scenario, Expect::app_body(412, "PreconditionFailed"));
    assert_eq!(
        pair.gateway.element("Condition"),
        None,
        "the adapter cannot name the condition: {pair:#?}"
    );
}
