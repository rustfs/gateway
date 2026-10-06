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

//! RustFS path signing through the launcher's real assembly (#1314, #1315).
//!
//! Responsible for: exact stored bytes and refusals for literal percent and encoded slash paths.
//! NOT responsible for: the primitive canonicalizer or socket framing.
//! Upstream: the parent assembly and signer fixtures. Downstream: Cargo tests.

use super::*;

const PATHS: [(&str, &str); 4] = [
    ("/path-fixtures/bad%zz", "/path-fixtures/bad%25zz"),
    ("/path-fixtures/a%2Fb", "/path-fixtures/a/b"),
    ("/path-fixtures/a%2fb%zz", "/path-fixtures/a/b%25zz"),
    ("/path-fixtures/a%252Fb", "/path-fixtures/a%252Fb"),
];

fn write(raw: &str, canonical: &str, key: &str, secret: &str, body: Bytes) -> http::Request<Bytes> {
    let mut request = signed(key, secret, http::Method::PUT, canonical, body, &[]);
    *request.uri_mut() = raw.parse().expect("raw target");
    request
}

async fn create_bucket(service: &S3Service) {
    let made = exchange(service, as_main(http::Method::PUT, "/path-fixtures", Bytes::new())).await;
    assert_eq!(made.status(), 200, "{}", body_of(&made));
}

#[tokio::test]
async fn the_profile_stores_the_bytes_under_the_once_decoded_key() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    create_bucket(&service).await;
    for (index, (raw, canonical)) in PATHS.into_iter().enumerate() {
        let body = Bytes::from(format!("path-specific bytes {index}"));
        let response = exchange(&service, write(raw, canonical, MAIN_KEY, MAIN_SECRET, body.clone())).await;
        assert_eq!(response.status(), 200, "{raw}: {}", body_of(&response));
    }
    // Read after all writes: collapsing the double-encoded key onto the slash key must fail.
    for (index, (raw, canonical)) in PATHS.into_iter().enumerate() {
        let read = exchange(&service, as_main(http::Method::GET, canonical, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{raw}: {}", body_of(&read));
        assert_eq!(read.body(), format!("path-specific bytes {index}").as_bytes(), "{raw}");
    }
}

#[tokio::test]
async fn n_forged_and_unknown_paths_never_create_objects() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    create_bucket(&service).await;
    for (key, secret, code) in [
        (MAIN_KEY, "wrong", "SignatureDoesNotMatch"),
        ("UNKNOWNKEY", MAIN_SECRET, "InvalidAccessKeyId"),
    ] {
        for (raw, canonical) in PATHS {
            let response =
                exchange(&service, write(raw, canonical, key, secret, Bytes::from_static(b"must not be stored"))).await;
            assert_eq!(response.status(), 403, "{}", body_of(&response));
            assert!(body_of(&response).contains(&format!("<Code>{code}</Code>")), "{}", body_of(&response));
            let read = exchange(&service, as_main(http::Method::GET, canonical, Bytes::new())).await;
            assert_eq!(read.status(), 404, "{}", body_of(&read));
            assert!(body_of(&read).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&read));
        }
    }
}

#[tokio::test]
async fn n_encoded_separator_signatures_never_create_objects() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    create_bucket(&service).await;
    let response = exchange(
        &service,
        write(
            "/path-fixtures/a%2Fb",
            "/path-fixtures/a%2Fb",
            MAIN_KEY,
            MAIN_SECRET,
            Bytes::from_static(b"must not be stored"),
        ),
    )
    .await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("<Code>SignatureDoesNotMatch</Code>"),
        "{}",
        body_of(&response)
    );
    let read = exchange(&service, as_main(http::Method::GET, "/path-fixtures/a/b", Bytes::new())).await;
    assert_eq!(read.status(), 404, "{}", body_of(&read));
    assert!(body_of(&read).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&read));
}
