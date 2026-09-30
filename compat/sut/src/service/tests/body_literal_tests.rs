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

//! MinIO's bare `Enabled` versioning body as the RustFS-profile launcher serves it
//! (rustfs/backlog#1677, ruling R6).
//!
//! Responsible for: a PutBucketVersioning body that is the bare word `Enabled`, ASCII-padded or
//! not, turning versioning on and reading back exactly as the document form does; every other
//! spelling answered `400 MalformedXML` with versioning left as it was.
//! NOT responsible for: PutObjectLockConfiguration, which the reference backend does not register
//! (`crates/gateway/tests/body_literals.rs` and the seam diff cover it), or the core default
//! (`c-bucketconfig-0060`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build: `Enabled`, ` Enabled\r\n` and `\tEnabled `
//! are `200` and read back as `<Status>Enabled</Status>`, the bytes the document form stores;
//! `enabled`, `ENABLED`, `Suspended`, `EnabledX` and `Enabled\0` are `400 MalformedXML`.

use super::*;

const DOCUMENT: &[u8] = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";

async fn bucket(service: &S3Service, name: &str) {
    let made = exchange(service, as_main(http::Method::PUT, &format!("/{name}"), Bytes::new())).await;
    assert_eq!(made.status(), 200, "{}", body_of(&made));
}

async fn put_versioning(service: &S3Service, name: &str, body: &[u8]) -> WireResponse {
    exchange(
        service,
        as_main(http::Method::PUT, &format!("/{name}?versioning"), Bytes::copy_from_slice(body)),
    )
    .await
}

async fn read_versioning(service: &S3Service, name: &str) -> String {
    let read = exchange(service, as_main(http::Method::GET, &format!("/{name}?versioning"), Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    body_of(&read)
}

/// Positive — the literal turns versioning on and reads back exactly as the document does.
#[tokio::test]
async fn the_bare_literal_is_stored_as_its_document_is() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service, "by-document").await;
    let written = put_versioning(&service, "by-document", DOCUMENT).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let stored = read_versioning(&service, "by-document").await;
    assert!(stored.contains("<Status>Enabled</Status>"), "{stored}");

    for (index, literal) in [b"Enabled".as_slice(), b" Enabled\r\n", b"\tEnabled "]
        .into_iter()
        .enumerate()
    {
        let name = format!("by-literal-{index}");
        bucket(&service, &name).await;
        let written = put_versioning(&service, &name, literal).await;
        assert_eq!(written.status(), 200, "{literal:?}: {}", body_of(&written));
        assert_eq!(read_versioning(&service, &name).await, stored, "{literal:?}");
    }
}

/// Negative — every other spelling is `400 MalformedXML`, and versioning is left as it was.
#[tokio::test]
async fn n_no_other_spelling_is_read_as_the_literal() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service, "near-miss").await;
    let before = read_versioning(&service, "near-miss").await;
    for body in [b"enabled".as_slice(), b"ENABLED", b"Suspended", b"EnabledX", b"Enabled\0"] {
        let refused = put_versioning(&service, "near-miss", body).await;
        assert_eq!(refused.status(), 400, "{body:?}: {}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>MalformedXML</Code>"), "{body:?}: {}", body_of(&refused));
        assert_eq!(read_versioning(&service, "near-miss").await, before, "{body:?}");
    }
    assert!(!before.contains("Enabled"), "{before}");
}
