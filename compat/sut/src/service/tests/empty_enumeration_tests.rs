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

//! An empty required enumeration element as the RustFS-profile launcher answers it
//! (rustfs/gateway#1078, row 3).
//!
//! Responsible for: an empty lifecycle rule `Status` and an empty default-encryption
//! `SSEAlgorithm` answered `400 MalformedXML` — legacy RustFS's answer, which its handlers give
//! once its decoder has handed them the empty value (`rustfs/src/app/bucket_usecase.rs:1220-1227`
//! and `:3152-3156` at rustfs/rustfs@5851d9eb5) — where the gateway answered `500`, and the stored
//! configuration left exactly as it was.
//! NOT responsible for: the decoder itself (`crates/core/tests/empty_enumeration.rs`) or the
//! document the RustFS body is handed (`crates/goldens`, `request_documents`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const LIFECYCLE_KEPT: &str = "<LifecycleConfiguration><Rule><ID>kept</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_KEPT_MD5: &str = "s+9wqHS/8Aos1/UG8IJFIg==";
const LIFECYCLE_EMPTY: &str = "<LifecycleConfiguration><Rule><ID>empty</ID><Filter><Prefix>logs/</Prefix></Filter><Status></Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_EMPTY_MD5: &str = "xD6XiYLjxX0d+qQ2XpQstg==";
const LIFECYCLE_SELF_CLOSING: &str = "<LifecycleConfiguration><Rule><ID>empty</ID><Filter><Prefix>logs/</Prefix></Filter><Status/><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_SELF_CLOSING_MD5: &str = "RUykZtGp4KA3jr7fZjR9fw==";
const ENCRYPTION_KEPT: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const ENCRYPTION_KEPT_MD5: &str = "6vzSAkrj6gUU1ZdQlOJRWQ==";
const ENCRYPTION_EMPTY: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm></SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const ENCRYPTION_EMPTY_MD5: &str = "B1gkm7usMvekHTM+uXMboQ==";

async fn put(service: &S3Service, target: &str, document: &'static str, md5: &str) -> WireResponse {
    exchange(
        service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            target,
            Bytes::from_static(document.as_bytes()),
            &[("content-md5", md5)],
        ),
    )
    .await
}

async fn bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/configured", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn refused_as_malformed(response: &WireResponse, what: &str) {
    assert_eq!(response.status(), 400, "{what}: {}", body_of(response));
    assert!(
        body_of(response).contains("<Code>MalformedXML</Code>"),
        "{what}: {}",
        body_of(response)
    );
}

/// Negative — an empty lifecycle status, paired or self-closing, is legacy RustFS's
/// `400 MalformedXML`, and the stored configuration is the one written before it.
#[tokio::test]
async fn n_an_empty_lifecycle_status_is_refused_as_legacy_rustfs_refuses_it_and_stores_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;

    let kept = put(&service, "/configured?lifecycle", LIFECYCLE_KEPT, LIFECYCLE_KEPT_MD5).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));

    for (document, md5) in [
        (LIFECYCLE_EMPTY, LIFECYCLE_EMPTY_MD5),
        (LIFECYCLE_SELF_CLOSING, LIFECYCLE_SELF_CLOSING_MD5),
    ] {
        let refused = put(&service, "/configured?lifecycle", document, md5).await;
        refused_as_malformed(&refused, document);
    }

    let read = exchange(&service, as_main(http::Method::GET, "/configured?lifecycle", Bytes::new())).await;
    let body = body_of(&read);
    assert_eq!(read.status(), 200, "{body}");
    assert!(body.contains("<ID>kept</ID>"), "{body}");
    assert!(!body.contains("<ID>empty</ID>"), "a refused document reached storage: {body}");
}

/// Negative — an empty default-encryption algorithm is legacy RustFS's `400 MalformedXML`, and no
/// configuration is stored where none was, nor replaced where one was.
#[tokio::test]
async fn n_an_empty_encryption_algorithm_is_refused_as_legacy_rustfs_refuses_it_and_stores_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;

    let refused = put(&service, "/configured?encryption", ENCRYPTION_EMPTY, ENCRYPTION_EMPTY_MD5).await;
    refused_as_malformed(&refused, "no prior configuration");
    let absent = exchange(&service, as_main(http::Method::GET, "/configured?encryption", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));

    let kept = put(&service, "/configured?encryption", ENCRYPTION_KEPT, ENCRYPTION_KEPT_MD5).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    let refused = put(&service, "/configured?encryption", ENCRYPTION_EMPTY, ENCRYPTION_EMPTY_MD5).await;
    refused_as_malformed(&refused, "over a stored configuration");

    let read = exchange(&service, as_main(http::Method::GET, "/configured?encryption", Bytes::new())).await;
    let body = body_of(&read);
    assert_eq!(read.status(), 200, "{body}");
    assert!(body.contains("<SSEAlgorithm>AES256</SSEAlgorithm>"), "{body}");
}
