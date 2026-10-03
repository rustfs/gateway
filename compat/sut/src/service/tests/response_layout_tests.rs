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

//! Configuration read-backs as the RustFS-profile launcher writes them (rustfs/gateway#1078,
//! row 5).
//!
//! Responsible for: a stored lifecycle configuration and a versioning status read back in legacy
//! RustFS's layout — the declaration without a line end, the rule's children in the legacy stack's
//! order — byte for byte the documents the `response_order` differential in `crates/goldens`
//! proves the legacy stack writes; and an object's entity tag as legacy RustFS writes it, its
//! quotes as they are.
//! NOT responsible for: the order itself (the generator) or the default layout other deployments
//! keep (the conformance corpus).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>kept</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_MD5: &str = "s+9wqHS/8Aos1/UG8IJFIg==";
const VERSIONING: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
const VERSIONING_MD5: &str = "QQFYoy/mRYV9PGZUfFi0Bw==";

async fn put(service: &S3Service, target: &str, document: &'static str, md5: &str) {
    let response = exchange(
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
    .await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
}

async fn read(service: &S3Service, target: &str) -> String {
    let response = exchange(service, as_main(http::Method::GET, target, Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    body_of(&response)
}

/// Positive — the stored lifecycle rule is read back in legacy RustFS's layout: its `Expiration`
/// and `Filter` before its `ID`, its `Status` last, and no line end after the declaration.
#[tokio::test]
async fn a_lifecycle_configuration_is_read_back_in_legacy_rustfs_layout() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/layout", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    put(&service, "/layout?lifecycle", LIFECYCLE, LIFECYCLE_MD5).await;
    assert_eq!(
        read(&service, "/layout?lifecycle").await,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Rule><Expiration><Days>30</Days></Expiration><Filter><Prefix>logs/</Prefix></Filter><ID>kept</ID>\
         <Status>Enabled</Status></Rule></LifecycleConfiguration>"
    );
}

/// Negative — a single-member answer changes only in its declaration: the versioning status reads
/// back with no line end before the root, and nothing else moves.
#[tokio::test]
async fn n_a_versioning_status_differs_only_in_its_declaration() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/layout", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    put(&service, "/layout?versioning", VERSIONING, VERSIONING_MD5).await;
    let body = read(&service, "/layout?versioning").await;
    assert_eq!(
        body,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Status>Enabled</Status></VersioningConfiguration>"
    );
    assert!(!body.contains('\n'), "{body}");
}

/// Positive — an object's entity tag is written in a listing with its quotes as they are, as
/// legacy RustFS writes an entity tag.
#[tokio::test]
async fn an_entity_tag_is_written_as_legacy_rustfs_writes_it() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/layout", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/layout/k", Bytes::from_static(b"hello"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let listing = read(&service, "/layout?list-type=2").await;
    assert!(listing.contains("<ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag>"), "{listing}");
    assert!(!listing.contains("&quot;"), "{listing}");
}
