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

//! `SignedHeaders` read, and its refusals answered, by the RustFS-profile launcher as legacy
//! RustFS reads and answers them (rustfs/gateway#1130).
//!
//! Responsible for: pinning, through the served assembly, that a list AWS would call malformed (a
//! name in uppercase, out of order, repeated) is verified when the string to sign spells it as
//! legacy RustFS does and is `SignatureDoesNotMatch` when it spells it as AWS does, a write storing
//! exactly what legacy RustFS stores or nothing; that a name the request did not send is answered
//! `missing signed header: <name>`; that an `x-amz-*` header the signature leaves out is `403
//! AccessDenied` "There were headers present in the request which were not signed", header-signed
//! and presigned, storing nothing; and that the one such header legacy RustFS lets a header
//! signature leave out, `x-amz-content-sha256`, stays refused in the gateway's own words
//! (`rd-loc-0010`).
//! NOT responsible for: the pre-lookup refusals of a header signature (`header_signature_tests.rs`)
//! or the credential scope (`scope_refusal_tests.rs`, `signing_service_tests.rs`).
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::HandSigned;
use super::*;

/// The three headers a request sends, named in uppercase.
const UPPERCASE: &str = "HOST;X-AMZ-CONTENT-SHA256;X-AMZ-DATE";
/// The same three out of order.
const UNSORTED: &str = "x-amz-date;host;x-amz-content-sha256";
/// The same three with `host` named twice in a row.
const REPEATED: &str = "host;host;x-amz-content-sha256;x-amz-date";

/// Legacy RustFS's sentence for an `x-amz-*` header a signature leaves out.
const UNSIGNED: &str = "There were headers present in the request which were not signed";

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/listing", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/listing/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

fn get() -> HandSigned {
    HandSigned::new(http::Method::GET, "/listing/k", Bytes::new())
}

fn put(path: &'static str) -> HandSigned {
    HandSigned::new(http::Method::PUT, path, Bytes::from_static(b"replaced"))
}

fn refused(answer: &WireResponse, status: u16, code: &str, sentence: Option<&str>) {
    let body = body_of(answer);
    assert_eq!(answer.status(), status, "{body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
    if let Some(sentence) = sentence {
        assert!(body.contains(&format!("<Message>{sentence}</Message>")), "{body}");
    }
}

async fn read(service: &S3Service, path: &str) -> (u16, String) {
    let answer = exchange(service, as_main(http::Method::GET, path, Bytes::new())).await;
    (answer.status().as_u16(), body_of(&answer))
}

/// Positive — a list in uppercase, out of order or repeated is verified when the string to sign
/// spells it as legacy RustFS does, and a write under it stores its body, as legacy RustFS stores
/// it; a header named and signed beside the three is verified too.
#[tokio::test]
async fn a_list_signed_as_legacy_rustfs_spells_it_is_verified() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for list in [UPPERCASE, UNSORTED, REPEATED] {
        let answer = exchange(&service, get().presenting(list).canonicalising_verbatim().request()).await;
        assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"), "{list}");
    }
    let signed_meta = exchange(&service, get().sending("x-amz-meta-note", "kept", true).request()).await;
    assert_eq!(signed_meta.status(), 200, "{}", body_of(&signed_meta));
    let written = put("/listing/upper")
        .presenting(UPPERCASE)
        .canonicalising_verbatim()
        .request();
    let stored = exchange(&service, written).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    assert_eq!(read(&service, "/listing/upper").await, (200, "replaced".to_owned()));
}

/// Negative — the same lists signed in AWS's canonical form are `SignatureDoesNotMatch`, as legacy
/// RustFS answers them, and a write under one stores nothing.
#[tokio::test]
async fn n_a_list_signed_as_aws_spells_it_is_signature_does_not_match() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for list in [UPPERCASE, UNSORTED, REPEATED] {
        let answer = exchange(&service, get().presenting(list).request()).await;
        refused(&answer, 403, "SignatureDoesNotMatch", None);
    }
    let written = exchange(&service, put("/listing/absent").presenting(UPPERCASE).request()).await;
    refused(&written, 403, "SignatureDoesNotMatch", None);
    assert_eq!(read(&service, "/listing/absent").await.0, 404);
}

/// Negative — a name the request did not send is `403 SignatureDoesNotMatch` naming it as written.
#[tokio::test]
async fn n_a_name_the_request_did_not_send_is_named() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (list, name) in [
        ("host;x-amz-content-sha256;x-amz-date;x-amz-meta-gone", "x-amz-meta-gone"),
        ("HOST;X-AMZ-CONTENT-SHA256;X-AMZ-DATE;X-Amz-Meta-Gone", "X-Amz-Meta-Gone"),
    ] {
        let answer = exchange(&service, get().presenting(list).canonicalising_verbatim().request()).await;
        refused(&answer, 403, "SignatureDoesNotMatch", Some(&format!("missing signed header: {name}")));
    }
}

/// Negative — an `x-amz-*` header the signature leaves out is `403 AccessDenied` with legacy
/// RustFS's sentence, header-signed and presigned, and a write carrying one stores nothing.
#[tokio::test]
async fn n_an_unsigned_amz_header_is_access_denied() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (name, value) in [("x-amz-meta-note", "unsigned"), ("x-amz-cf-id", "cdn")] {
        let header = exchange(&service, get().sending(name, value, false).request()).await;
        refused(&header, 403, "AccessDenied", Some(UNSIGNED));
        let presigned = exchange(&service, get().sending(name, value, false).presigned()).await;
        refused(&presigned, 403, "AccessDenied", Some(UNSIGNED));
    }
    let payload_hash = get().sending("x-amz-content-sha256", "UNSIGNED-PAYLOAD", false);
    refused(&exchange(&service, payload_hash.presigned()).await, 403, "AccessDenied", Some(UNSIGNED));
    for path in ["/listing/absent", "/listing/k"] {
        let header = exchange(&service, put(path).sending("x-amz-meta-note", "unsigned", false).request()).await;
        refused(&header, 403, "AccessDenied", Some(UNSIGNED));
        let presigned = exchange(&service, put(path).sending("x-amz-meta-note", "unsigned", false).presigned()).await;
        refused(&presigned, 403, "AccessDenied", Some(UNSIGNED));
    }
    assert_eq!(read(&service, "/listing/absent").await.0, 404);
    assert_eq!(read(&service, "/listing/k").await, (200, "stored".to_owned()));
}

/// Negative — the kept refusal (`rd-loc-0010`): a header signature leaving `x-amz-content-sha256`
/// out, which legacy RustFS verifies, stays `SignatureDoesNotMatch` in the gateway's own words.
#[tokio::test]
async fn n_an_unsigned_payload_hash_stays_refused_in_the_gateway_words() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let answer = exchange(&service, get().leaving_unsigned(&["x-amz-content-sha256"]).request()).await;
    refused(&answer, 403, "SignatureDoesNotMatch", None);
    assert!(!body_of(&answer).contains(UNSIGNED), "{}", body_of(&answer));
    assert!(!body_of(&answer).contains("missing signed header"), "{}", body_of(&answer));
}
