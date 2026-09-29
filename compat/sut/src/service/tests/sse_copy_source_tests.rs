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

//! A copy from an SSE-C source, and RustFS's transport gate for customer keys, as the
//! RustFS-profile launcher serves them (rustfs/backlog#1677, R11).
//!
//! Responsible for: a CopyObject carrying the copy source's customer key and a managed algorithm
//! for the target being served, with the target encrypted as the request says; the target's own
//! customer key beside a managed algorithm still being refused; and, over cleartext, a copy
//! source's customer key being served while the target's is refused, as legacy RustFS does with
//! TLS required for customer keys.
//! NOT responsible for: decrypting an SSE-C source (the reference backend stores no SSE-C object)
//! or the stored metadata a RustFS backend writes, which the seam diff proves identical
//! (`crates/difftest`, `copy-object-ssec-source-into-*` rows).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_MD5: &str = "tP/LI3N87DFaSk0aoqYgzg==";

fn source_key() -> [(&'static str, &'static str); 3] {
    [
        ("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-copy-source-server-side-encryption-customer-key", KEY),
        ("x-amz-copy-source-server-side-encryption-customer-key-md5", KEY_MD5),
    ]
}

fn target_key() -> [(&'static str, &'static str); 3] {
    [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key", KEY),
        ("x-amz-server-side-encryption-customer-key-md5", KEY_MD5),
    ]
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/ssec", ""), ("/ssec/src", "source")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

/// A copy of `/ssec/src` to `destination` with `extra` headers, over TLS or cleartext.
async fn copy(service: &S3Service, destination: &str, extra: &[(&str, &str)], tls: bool) -> WireResponse {
    let mut headers = vec![("x-amz-copy-source", "/ssec/src")];
    headers.extend_from_slice(extra);
    let mut request = signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, destination, Bytes::new(), &headers);
    if tls {
        request.extensions_mut().insert(rustfs_gateway::TransportSecurity::Encrypted);
    }
    exchange(service, request).await
}

fn code(response: &WireResponse) -> Option<String> {
    let body = body_of(response);
    let start = body.find("<Code>")? + "<Code>".len();
    let end = body[start..].find("</Code>")? + start;
    Some(body[start..end].to_owned())
}

async fn head_encryption(service: &S3Service, target: &str) -> (u16, Option<String>) {
    let head = exchange(service, as_main(http::Method::HEAD, target, Bytes::new())).await;
    let algorithm = head.header("x-amz-server-side-encryption").map(str::to_owned);
    (head.status().as_u16(), algorithm)
}

/// Positive — an SSE-C source copied into an SSE-S3 target is served, and the target is encrypted
/// as the request says.
#[tokio::test]
async fn a_copy_from_an_ssec_source_into_sse_s3_is_served() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let mut headers = source_key().to_vec();
    headers.push(("x-amz-server-side-encryption", "AES256"));
    let copied = copy(&service, "/ssec/dst", &headers, true).await;
    assert_eq!(copied.status(), 200, "{}", body_of(&copied));
    assert_eq!(head_encryption(&service, "/ssec/dst").await, (200, Some("AES256".to_owned())));
}

/// Negative — the target's own customer key beside a managed algorithm is still a contradiction,
/// whatever the source carries, and nothing is written.
#[tokio::test]
async fn n_a_managed_algorithm_beside_the_target_key_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let mut headers = source_key().to_vec();
    headers.extend(target_key());
    headers.push(("x-amz-server-side-encryption", "AES256"));
    let refused = copy(&service, "/ssec/dst", &headers, true).await;
    assert_eq!(
        (refused.status().as_u16(), code(&refused).as_deref()),
        (400, Some("InvalidArgument")),
        "{}",
        body_of(&refused)
    );
    assert_eq!(head_encryption(&service, "/ssec/dst").await.0, 404);
}

/// Positive — over cleartext, a copy source's customer key is served, as legacy RustFS serves it
/// with TLS required for customer keys.
#[tokio::test]
async fn a_copy_source_key_over_cleartext_is_served_as_legacy_rustfs_serves_it() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let copied = copy(&service, "/ssec/dst", &source_key(), false).await;
    assert_eq!(copied.status(), 200, "{}", body_of(&copied));
    assert_eq!(head_encryption(&service, "/ssec/dst").await.0, 200);
}

/// Negative — over cleartext the target's customer key is refused, alone or beside a copy
/// source's, and nothing is written.
#[tokio::test]
async fn n_a_target_key_over_cleartext_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let mut both = source_key().to_vec();
    both.extend(target_key());
    for headers in [
        target_key().to_vec(),
        both,
        vec![("x-amz-server-side-encryption-customer-key-md5", KEY_MD5)],
    ] {
        let refused = copy(&service, "/ssec/dst", &headers, false).await;
        assert_eq!(
            (refused.status().as_u16(), code(&refused).as_deref()),
            (400, Some("InvalidRequest")),
            "{headers:?}: {}",
            body_of(&refused)
        );
    }
    assert_eq!(head_encryption(&service, "/ssec/dst").await.0, 404);
}
