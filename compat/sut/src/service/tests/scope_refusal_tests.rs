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

//! The credential scopes the RustFS-profile launcher refuses with legacy RustFS's answers
//! (rustfs/gateway#1130): a scope date other than the signed day, and a region outside legacy
//! RustFS's grammar.
//!
//! Responsible for: pinning, through the served assembly and on every signing surface (header,
//! presigned, browser `POST`), that each is answered with legacy RustFS's status, code and sentence
//! and changes nothing in storage; that a wrong signature over a region the gateway reads is still
//! `SignatureDoesNotMatch` first, as legacy RustFS answers it; and the one order that differs from
//! legacy RustFS's (`rd-loc-0011`): a region the gateway cannot read is refused before any key is
//! derived, whatever else is wrong with the request, where legacy RustFS verifies the signature
//! first.
//! NOT responsible for: a header signature's pre-lookup refusals (`header_signature_tests.rs`),
//! which regions are verified (`signing_region_tests.rs`), or the default answers
//! (`crates/gateway/tests/scope_refusals.rs`).
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::HandSigned;
use super::*;

/// The regions legacy RustFS reads and refuses that the gateway cannot read: a space and a comma
/// (the `Authorization` header's own separators), a tab, a DEL and a non-ASCII letter.
const UNREADABLE: [&str; 5] = ["us east", "us,east", "us\teast", "us\u{7f}east", "us-\u{e9}ast"];

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/scopes", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/scopes/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

fn get() -> HandSigned {
    HandSigned::new(http::Method::GET, "/scopes/k", Bytes::new())
}

fn put(path: &'static str) -> HandSigned {
    HandSigned::new(http::Method::PUT, path, Bytes::from_static(b"replaced"))
}

fn form() -> HandSigned {
    HandSigned::new(http::Method::POST, "/scopes", Bytes::new())
}

/// Whether a header value or a form field can carry `region`: the `http` crate refuses a DEL in a
/// header value, and the form reader refuses one in a field value under both grammars (it fails
/// closed on control bytes, an open item on rustfs/backlog#1677), so only a presigned URL sends it.
fn fits_a_field(region: &str) -> bool {
    !region.contains('\u{7f}')
}

/// Whether the gateway's parsers read `region` in a presigned URL or a form: a comma, which is
/// ASCII-graphic, is read there and refused after the signature.
fn is_read_outside_a_header(region: &str) -> bool {
    region == "us,east"
}

/// Legacy RustFS's sentence for `region`, as the error document carries it.
fn region_sentence(region: &str) -> String {
    format!("invalid credential region: invalid region: {region:?}").replace('"', "&quot;")
}

fn refused(answer: &WireResponse, status: u16, code: &str, sentence: &str) {
    let body = body_of(answer);
    assert_eq!(answer.status(), status, "{sentence}: {body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{sentence}: {body}");
    assert!(body.contains(&format!("<Message>{sentence}</Message>")), "{sentence}: {body}");
}

/// Positive — the controls: a scope legacy RustFS reads, dated the signed day, in the configured
/// region or another region of its grammar, is served on each surface.
#[tokio::test]
async fn a_scope_legacy_rustfs_reads_is_still_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for region in ["us-east-1", "rustfs-local-2"] {
        for request in [get().in_region(region).request(), get().in_region(region).presigned()] {
            let answer = exchange(&service, request).await;
            assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"), "{region}");
        }
        let posted = exchange(&service, form().in_region(region).posted("posted", "form body")).await;
        assert_eq!(posted.status(), 204, "{region}: {}", body_of(&posted));
    }
    let read = exchange(&service, as_main(http::Method::GET, "/scopes/posted", Bytes::new())).await;
    assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, "form body"));
}

/// Negative — a scope dated other than the signed day is `403 SignatureDoesNotMatch` "credential
/// scope date does not match x-amz-date" on each surface, before the key is looked up and before
/// the service is judged, as legacy RustFS answers it.
#[tokio::test]
async fn n_a_scope_date_other_than_the_signed_day_is_answered_as_legacy_rustfs_answers_it() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let sentence = "credential scope date does not match x-amz-date";
    for signer in [
        get().scoped_to_day("20200101"),
        get().scoped_to_day("20200101").under_an_unknown_key(),
    ] {
        refused(&exchange(&service, signer.request()).await, 403, "SignatureDoesNotMatch", sentence);
        refused(&exchange(&service, signer.presigned()).await, 403, "SignatureDoesNotMatch", sentence);
    }
    let foreign_service = get().scoped_to_day("20200101").in_service("foo");
    refused(
        &exchange(&service, foreign_service.presigned()).await,
        403,
        "SignatureDoesNotMatch",
        sentence,
    );
    for signer in [
        form().scoped_to_day("20200101"),
        form().scoped_to_day("20200101").under_an_unknown_key(),
        form().scoped_to_day("20200101").in_service("foo"),
    ] {
        refused(
            &exchange(&service, signer.posted("dated", "form body")).await,
            403,
            "SignatureDoesNotMatch",
            sentence,
        );
    }
}

/// Negative — a region outside legacy RustFS's grammar is `400 InvalidRequest` naming it, on each
/// surface: the regions the gateway cannot read, and an uppercase one it reads and verifies first.
#[tokio::test]
async fn n_a_region_outside_the_legacy_grammar_is_answered_as_legacy_rustfs_answers_it() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for region in UNREADABLE.into_iter().chain(["US-EAST-1"]) {
        let sentence = region_sentence(region);
        if fits_a_field(region) {
            refused(
                &exchange(&service, get().in_region(region).request()).await,
                400,
                "InvalidRequest",
                &sentence,
            );
        }
        refused(
            &exchange(&service, get().in_region(region).presigned()).await,
            400,
            "InvalidRequest",
            &sentence,
        );
        if fits_a_field(region) {
            refused(
                &exchange(&service, form().in_region(region).posted("regioned", "form body")).await,
                400,
                "InvalidRequest",
                &sentence,
            );
        }
    }
}

/// Negative — a refused scope stores nothing: a new key stays absent and an overwrite leaves the
/// stored bytes, header-signed, presigned and posted.
#[tokio::test]
async fn n_a_refused_scope_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for path in ["/scopes/absent", "/scopes/k"] {
        for signer in [
            put(path).in_region("us east"),
            put(path).in_region("US-EAST-1"),
            put(path).scoped_to_day("20200101"),
        ] {
            let header = exchange(&service, signer.request()).await;
            assert!(matches!(header.status().as_u16(), 400 | 403), "{}", body_of(&header));
            let presigned = exchange(&service, signer.presigned()).await;
            assert!(matches!(presigned.status().as_u16(), 400 | 403), "{}", body_of(&presigned));
        }
    }
    for signer in [
        form().in_region("us\teast"),
        form().in_region("US-EAST-1"),
        form().scoped_to_day("20200101"),
    ] {
        let posted = exchange(&service, signer.posted("absent", "form body")).await;
        assert!(matches!(posted.status().as_u16(), 400 | 403), "{}", body_of(&posted));
    }
    let absent = exchange(&service, as_main(http::Method::GET, "/scopes/absent", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
    let kept = exchange(&service, as_main(http::Method::GET, "/scopes/k", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), body_of(&kept).as_str()), (200, "stored"));
}

/// Negative — a wrong signature over a region the gateway reads is `403 SignatureDoesNotMatch`,
/// not the region refusal: the signature is verified first, as legacy RustFS verifies it.
#[tokio::test]
async fn n_a_wrong_signature_over_a_region_the_gateway_reads_is_signature_does_not_match() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let uppercase = get().in_region("US-EAST-1").forged();
    for request in [uppercase.request(), uppercase.presigned()] {
        let answer = exchange(&service, request).await;
        assert_eq!(answer.status(), 403, "{}", body_of(&answer));
        assert!(body_of(&answer).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&answer));
    }
    for region in UNREADABLE.into_iter().filter(|region| is_read_outside_a_header(region)) {
        let forged = get().in_region(region).forged();
        let answer = exchange(&service, forged.presigned()).await;
        assert_eq!(answer.status(), 403, "{region}: {}", body_of(&answer));
        let posted = exchange(&service, form().in_region(region).forged().posted("forged", "x")).await;
        assert_eq!(posted.status(), 403, "{region}: {}", body_of(&posted));
        assert!(body_of(&posted).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&posted));
    }
}

/// Negative — the registered order (`rd-loc-0011`): a region the gateway cannot read is refused
/// before any key is derived, so a wrong signature or an unknown key over it gets the same `400
/// InvalidRequest` naming the region, where legacy RustFS answers `403 SignatureDoesNotMatch` and
/// `403 InvalidAccessKeyId`. Either way nothing is served.
#[tokio::test]
async fn n_a_region_the_gateway_cannot_read_is_refused_before_any_key_is_derived() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for region in UNREADABLE {
        let sentence = region_sentence(region);
        for signer in [
            get().in_region(region).forged(),
            get().in_region(region).under_an_unknown_key(),
        ] {
            if fits_a_field(region) {
                refused(&exchange(&service, signer.request()).await, 400, "InvalidRequest", &sentence);
            }
            if !is_read_outside_a_header(region) {
                refused(&exchange(&service, signer.presigned()).await, 400, "InvalidRequest", &sentence);
            }
        }
        if fits_a_field(region) && !is_read_outside_a_header(region) {
            let posted = exchange(&service, form().in_region(region).forged().posted("forged", "x")).await;
            refused(&posted, 400, "InvalidRequest", &sentence);
            let unknown = form().in_region(region).under_an_unknown_key();
            refused(
                &exchange(&service, unknown.posted("unknown", "x")).await,
                400,
                "InvalidRequest",
                &sentence,
            );
        }
    }
}
