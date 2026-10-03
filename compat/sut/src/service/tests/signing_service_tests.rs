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

//! The credential-scope services the RustFS-profile launcher verifies, as legacy RustFS verifies
//! them (rustfs/gateway#1130).
//!
//! Responsible for: pinning, through the served assembly and on every signing surface (header,
//! presigned, browser `POST`), that a scope naming `s3`, `sts` or `s3tables` is verified on an S3
//! operation, and that any other service is answered `501 NotImplemented` with legacy RustFS's
//! sentence and changes nothing in storage.
//! NOT responsible for: the signing-region readings (`signing_region_tests.rs`), or how an `sts`
//! scope's absent payload hash is read.
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::HandSigned;
use super::*;

/// The services legacy RustFS verifies on every route.
const VERIFIED: [&str; 3] = ["s3", "sts", "s3tables"];

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/services", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/services/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// The legacy refusal of a scope naming `service`.
fn refused_as_legacy(answer: &WireResponse, service: &str) {
    let body = body_of(answer);
    assert_eq!(answer.status(), 501, "{service}: {body}");
    assert!(body.contains("<Code>NotImplemented</Code>"), "{service}: {body}");
    let sentence = format!(
        "<Message>unknown service &apos;{service}&apos; in credential scope; expected one of: s3, sts, s3tables</Message>"
    );
    assert!(body.contains(&sentence), "{service}: {body}");
}

/// Positive — a read scoped to each service legacy RustFS verifies is served, header-signed and
/// presigned alike.
#[tokio::test]
async fn a_read_scoped_to_every_legacy_service_is_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for scoped in VERIFIED {
        let read = HandSigned::new(http::Method::GET, "/services/k", Bytes::new()).in_service(scoped);
        for request in [read.request(), read.presigned()] {
            let answer = exchange(&service, request).await;
            assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"), "{scoped}");
        }
    }
}

/// Positive — an upload scoped to `sts` or `s3tables` is stored, header-signed, presigned and
/// posted from a browser form alike.
#[tokio::test]
async fn an_upload_scoped_to_sts_or_s3tables_is_stored() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (scoped, header, presigned, posted) in [
        ("sts", "/services/sts-header", "/services/sts-presigned", "sts-posted"),
        ("s3tables", "/services/tables-header", "/services/tables-presigned", "tables-posted"),
    ] {
        let upload = HandSigned::new(http::Method::PUT, header, Bytes::from_static(b"h")).in_service(scoped);
        assert_eq!(exchange(&service, upload.request()).await.status(), 200, "{scoped}");
        let upload = HandSigned::new(http::Method::PUT, presigned, Bytes::from_static(b"p")).in_service(scoped);
        assert_eq!(exchange(&service, upload.presigned()).await.status(), 200, "{scoped}");
        let form = HandSigned::new(http::Method::POST, "/services", Bytes::new()).in_service(scoped);
        let answer = exchange(&service, form.posted(posted, "f")).await;
        assert_eq!(answer.status(), 204, "{scoped}: {}", body_of(&answer));
        for (path, bytes) in [
            (header.to_owned(), "h"),
            (presigned.to_owned(), "p"),
            (format!("/services/{posted}"), "f"),
        ] {
            let read = exchange(&service, as_main(http::Method::GET, &path, Bytes::new())).await;
            assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, bytes), "{path}");
        }
    }
}

/// Negative — a scope naming a service legacy RustFS does not verify is answered `501
/// NotImplemented` with legacy RustFS's sentence, on every surface: an unknown name, an S3-family
/// service the gateway's own parser knows, and a known name in another case.
#[tokio::test]
async fn n_a_scope_naming_another_service_is_refused_as_legacy_refuses_it() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for scoped in ["foo", "s3express", "S3"] {
        let read = HandSigned::new(http::Method::GET, "/services/k", Bytes::new()).in_service(scoped);
        refused_as_legacy(&exchange(&service, read.request()).await, scoped);
        refused_as_legacy(&exchange(&service, read.presigned()).await, scoped);
        let form = HandSigned::new(http::Method::POST, "/services", Bytes::new()).in_service(scoped);
        refused_as_legacy(&exchange(&service, form.posted("k", "replaced")).await, scoped);
    }
}

/// Negative — an upload scoped to another service stores nothing, and an overwrite leaves the
/// stored bytes, on every surface.
#[tokio::test]
async fn n_an_upload_scoped_to_another_service_changes_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for path in ["/services/k", "/services/absent"] {
        let upload = HandSigned::new(http::Method::PUT, path, Bytes::from_static(b"replaced")).in_service("foo");
        refused_as_legacy(&exchange(&service, upload.request()).await, "foo");
        refused_as_legacy(&exchange(&service, upload.presigned()).await, "foo");
    }
    let form = HandSigned::new(http::Method::POST, "/services", Bytes::new()).in_service("foo");
    refused_as_legacy(&exchange(&service, form.posted("absent", "replaced")).await, "foo");
    let kept = exchange(&service, as_main(http::Method::GET, "/services/k", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), body_of(&kept).as_str()), (200, "stored"));
    let absent = exchange(&service, as_main(http::Method::GET, "/services/absent", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
}

/// Negative — the key is derived from the service the client named: a wrong secret under a
/// verified service is `403 SignatureDoesNotMatch` on every surface and stores nothing.
#[tokio::test]
async fn n_a_wrong_signature_under_a_legacy_service_is_signature_does_not_match() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for scoped in ["sts", "s3tables"] {
        let upload = HandSigned::new(http::Method::PUT, "/services/forged", Bytes::from_static(b"x"))
            .in_service(scoped)
            .forged();
        let form = HandSigned::new(http::Method::POST, "/services", Bytes::new())
            .in_service(scoped)
            .forged();
        for request in [upload.request(), upload.presigned(), form.posted("forged", "x")] {
            let answer = exchange(&service, request).await;
            let body = body_of(&answer);
            assert_eq!(answer.status(), 403, "{scoped}: {body}");
            assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{scoped}: {body}");
        }
    }
    let absent = exchange(&service, as_main(http::Method::GET, "/services/forged", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
}
