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

//! The four ACL operations through the production registry, answered as RustFS answers them.
//!
//! Responsible for: the owner's `FULL_CONTROL` read back for buckets and objects (current and
//! named versions), canned and grant-header writes accepted, the grant document refused as not
//! implemented with RustFS's message, the shared contract's channel refusals, and the not-found
//! answers shared with the tagging reads.
//! NOT responsible for: the grant grammar and the canned sets, which `ops/shared/acl.rs` owns,
//! or the wire shape of the document, which `conformance/cases/acl/` pins.
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

/// An empty body's `Content-MD5`: the two ACL writes require an integrity claim.
const EMPTY_MD5: &str = "1B2M2Y8AsgTpgAmY7PhCfg==";
const DOCUMENT: &str = concat!(
    "<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant>",
    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>o</ID></Grantee>",
    "<Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>"
);
const DOCUMENT_MD5: &str = "P7G/tmqKq3JaZaZpovojNg==";

fn owner_backend(root: &TestRoot) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root")
            .with_owner("acl-owner-id", "ACL <Owner>"),
    );
    service_with_backend(backend)
}

async fn put_acl(service: &S3Service, target: &str, body: &'static str, md5: &str, extra: &[(&str, &str)]) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_str(md5).expect("a header value"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(body.as_bytes()), headers),
    )
    .await
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// Positive — a bucket and an object each read back the configured owner's `FULL_CONTROL`, with
/// the grantee typed and the display name escaped; the object's version id is not an ACL member,
/// and a version-scoped read answers the same policy for a named version.
#[tokio::test]
async fn the_owner_holds_full_control_of_every_bucket_and_object() {
    let root = TestRoot::new();
    let (_, service) = owner_backend(&root);
    create_bucket(&service, "acl").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/acl/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    for target in ["/acl?acl", "/acl/key?acl"] {
        let read = exchange(&service, signed(http::Method::GET, target, Bytes::new())).await;
        let body = text(&read);
        assert_eq!(read.status(), 200, "{target}: {body}");
        assert!(
            body.contains("<Owner><ID>acl-owner-id</ID><DisplayName>ACL &lt;Owner&gt;</DisplayName></Owner>"),
            "{body}"
        );
        assert!(body.contains("xsi:type=\"CanonicalUser\""), "{body}");
        assert!(body.contains("<ID>acl-owner-id</ID>"), "{body}");
        assert!(body.contains("<Permission>FULL_CONTROL</Permission>"), "{body}");
        assert_eq!(body.matches("<Grant>").count(), 1, "one grant: {body}");
    }

    let enabled = super::versioning::set_versioning(&service, "acl", "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", text(&enabled));
    let versioned = exchange(&service, signed(http::Method::PUT, "/acl/key", Bytes::from_static(b"two"))).await;
    let version_id = header(&versioned, "x-amz-version-id")
        .expect("a minted version")
        .to_str()
        .expect("ascii")
        .to_owned();
    let named = exchange(
        &service,
        signed(http::Method::GET, &format!("/acl/key?acl&versionId={version_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(named.status(), 200, "{}", text(&named));
    assert!(text(&named).contains("<Permission>FULL_CONTROL</Permission>"));
}

/// Positive — a canned ACL and an explicit grant header are accepted on a bucket and on an object,
/// as RustFS accepts them; the read afterwards is unchanged, because nothing was stored to change it.
#[tokio::test]
async fn canned_and_grant_header_writes_are_accepted_and_not_stored() {
    let root = TestRoot::new();
    let (_, service) = owner_backend(&root);
    create_bucket(&service, "acl-write").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/acl-write/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    for (target, headers) in [
        ("/acl-write?acl", &[("x-amz-acl", "public-read")][..]),
        (
            "/acl-write?acl",
            &[("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")][..],
        ),
        ("/acl-write/key?acl", &[("x-amz-acl", "public-read-write")][..]),
        ("/acl-write/key?acl", &[("x-amz-grant-full-control", "id=\"another-account\"")][..]),
    ] {
        let written = put_acl(&service, target, "", EMPTY_MD5, headers).await;
        assert_eq!(written.status(), 200, "{target} {headers:?}: {}", text(&written));
    }
    let read = exchange(&service, signed(http::Method::GET, "/acl-write?acl", Bytes::new())).await;
    let body = text(&read);
    assert_eq!(body.matches("<Grant>").count(), 1, "the write stored nothing: {body}");
    assert!(!body.contains("AllUsers"), "{body}");
}

/// Negative — a grant document is refused as not implemented, with the message RustFS gives:
/// there is nowhere to keep it. The refusal is the handler's, after the shared contract accepted
/// the document, so a malformed document is still the contract's `400` and not this `501`.
#[tokio::test]
async fn n_an_access_control_policy_document_is_not_implemented() {
    let root = TestRoot::new();
    let (_, service) = owner_backend(&root);
    create_bucket(&service, "acl-doc").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/acl-doc/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    for target in ["/acl-doc?acl", "/acl-doc/key?acl"] {
        let refused = put_acl(&service, target, DOCUMENT, DOCUMENT_MD5, &[]).await;
        let body = text(&refused);
        assert_eq!(refused.status(), 501, "{target}: {body}");
        assert!(body.contains("<Code>NotImplemented</Code>"), "{body}");
        assert!(
            body.contains("ACL XML grants are not supported; use canned ACL headers or omit ACL"),
            "RustFS's own message: {body}"
        );
    }
}

/// Negative — the shared contract's channel rules are answered before RustFS would see the
/// request: both channels at once and neither channel are `400`, and a canned value outside the
/// bucket set is refused on a bucket while accepted on an object.
#[tokio::test]
async fn n_the_channel_rules_are_the_shared_contracts() {
    let root = TestRoot::new();
    let (_, service) = owner_backend(&root);
    create_bucket(&service, "acl-channels").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/acl-channels/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    let both = put_acl(&service, "/acl-channels?acl", DOCUMENT, DOCUMENT_MD5, &[("x-amz-acl", "private")]).await;
    assert_eq!(both.status(), 400, "both channels: {}", text(&both));
    let neither = put_acl(&service, "/acl-channels?acl", "", EMPTY_MD5, &[]).await;
    assert_eq!(neither.status(), 400, "neither channel: {}", text(&neither));
    let object_only_canned = put_acl(&service, "/acl-channels?acl", "", EMPTY_MD5, &[("x-amz-acl", "bucket-owner-read")]).await;
    assert_eq!(
        object_only_canned.status(),
        400,
        "an object canned value on a bucket: {}",
        text(&object_only_canned)
    );
    let on_object = put_acl(&service, "/acl-channels/key?acl", "", EMPTY_MD5, &[("x-amz-acl", "bucket-owner-read")]).await;
    assert_eq!(on_object.status(), 200, "{}", text(&on_object));
}

/// Negative — the not-found answers are the ones the other subresources give: a missing bucket
/// is `NoSuchBucket` on both reads and writes, a missing key `NoSuchKey`, and an unknown version
/// `NoSuchVersion`; none of them answers the owner's policy for something that is not there.
#[tokio::test]
async fn n_missing_buckets_keys_and_versions_are_not_given_a_policy() {
    let root = TestRoot::new();
    let (_, service) = owner_backend(&root);
    create_bucket(&service, "acl-present").await;
    let missing_bucket = exchange(&service, signed(http::Method::GET, "/acl-absent?acl", Bytes::new())).await;
    assert_eq!(missing_bucket.status(), 404);
    assert!(text(&missing_bucket).contains("<Code>NoSuchBucket</Code>"));
    let write_missing = put_acl(&service, "/acl-absent?acl", "", EMPTY_MD5, &[("x-amz-acl", "private")]).await;
    assert_eq!(write_missing.status(), 404, "{}", text(&write_missing));
    let missing_key = exchange(&service, signed(http::Method::GET, "/acl-present/absent?acl", Bytes::new())).await;
    assert_eq!(missing_key.status(), 404);
    assert!(text(&missing_key).contains("<Code>NoSuchKey</Code>"), "{}", text(&missing_key));
    let write_missing_key = put_acl(&service, "/acl-present/absent?acl", "", EMPTY_MD5, &[("x-amz-acl", "private")]).await;
    assert_eq!(write_missing_key.status(), 404, "{}", text(&write_missing_key));
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/acl-present/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    let unknown_version = exchange(
        &service,
        signed(http::Method::GET, "/acl-present/key?acl&versionId=not-minted", Bytes::new()),
    )
    .await;
    assert_eq!(unknown_version.status(), 404, "{}", text(&unknown_version));
    assert!(
        text(&unknown_version).contains("<Code>NoSuchVersion</Code>"),
        "{}",
        text(&unknown_version)
    );
}
