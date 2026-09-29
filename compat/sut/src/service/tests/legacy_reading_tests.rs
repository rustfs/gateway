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

//! Three RustFS fixes that lived in the legacy stack, pinned through the RustFS-profile launcher,
//! which already answers as legacy RustFS does (rustfs/gateway#1099).
//!
//! Responsible for: an ACL grantee written with its `xsi` namespace declaration and `xsi:type`
//! (rustfs/rustfs#312); an `Expires` value handed to the backend and served back as the text the
//! client sent, which is what lets RustFS's own handler refuse a value it cannot read
//! (rustfs/rustfs#6981); and a `Last-Modified` that round-trips through `If-Modified-Since`
//! (rustfs/rustfs#1627).
//! NOT responsible for: refusing a date condition legacy cannot read (the RustFS-profile date
//! switch), or the ACL document's other members.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn with_object(root: &TestRoot, key: &str, extra: &[(&str, &str)]) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/pins", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            &format!("/pins/{key}"),
            Bytes::from_static(b"pinned"),
            extra,
        ),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// The grantee start tag legacy RustFS writes: the namespace declaration on the element that uses
/// it, then the type (observed on a legacy build for `GetBucketAcl` and `GetObjectAcl`).
const LEGACY_GRANTEE: &str = "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">";

/// Positive — `GetBucketAcl` and `GetObjectAcl` write each grantee with the `xsi` namespace
/// declared on it and its `xsi:type`, as legacy RustFS writes them (rustfs/rustfs#312); a client
/// that resolves `xsi:type` by namespace reads the grantee's type.
#[tokio::test]
async fn an_acl_grantee_carries_its_namespace_and_type_as_legacy_writes_it() {
    let root = TestRoot::new();
    let service = with_object(&root, "acl", &[]).await;
    for target in ["/pins?acl", "/pins/acl?acl"] {
        let answer = exchange(&service, as_main(http::Method::GET, target, Bytes::new())).await;
        let body = body_of(&answer);
        assert_eq!(answer.status(), 200, "{target}: {body}");
        assert!(body.contains(LEGACY_GRANTEE), "{target}: {body}");
        assert!(!body.contains("<Grantee>"), "{target}: a grantee without its type: {body}");
    }
}

/// Positive — an `Expires` the client sends is handed to the backend as the text it sent and
/// served back unchanged, an HTTP-date and a value that is not one alike, as the legacy stack
/// hands RustFS the text (rustfs/rustfs#6981): RustFS's own handler, not the gateway, decides
/// whether it can read the value (`rustfs/src/app/object/shared.rs` `parse_expires_header`).
#[tokio::test]
async fn an_expires_value_reaches_the_backend_and_the_reader_as_sent() {
    for (key, sent) in [
        ("http-date", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("rfc-850", "Wednesday, 21-Oct-15 07:28:00 GMT"),
        ("not-a-date", "not a date"),
        ("zero", "0"),
    ] {
        let root = TestRoot::new();
        let service = with_object(&root, key, &[("expires", sent)]).await;
        let target = format!("/pins/{key}");
        for method in [http::Method::HEAD, http::Method::GET] {
            let read = exchange(&service, as_main(method.clone(), &target, Bytes::new())).await;
            assert_eq!(read.status(), 200, "{method} {key}");
            assert_eq!(read.header("expires"), Some(sent), "{method} {key}");
        }
    }
}

/// Positive and negative — the `Last-Modified` a read carries is the IMF-fixdate spelling, and a
/// client can send an instant in that spelling straight back: `If-Modified-Since` a second after
/// it is `304 Not Modified` with the same `Last-Modified` and `ETag`, an hour before it serves the
/// object (rustfs/rustfs#1627). The case waits two seconds first, so neither instant is in the
/// server's future; the same-second comparison is the backend's (RustFS compares whole seconds).
#[tokio::test]
async fn last_modified_round_trips_through_if_modified_since() {
    let root = TestRoot::new();
    let service = with_object(&root, "dated", &[]).await;
    let first = exchange(&service, as_main(http::Method::GET, "/pins/dated", Bytes::new())).await;
    assert_eq!(first.status(), 200);
    let last_modified = first.header("last-modified").expect("a Last-Modified").to_owned();
    let etag = first.header("etag").expect("an ETag").to_owned();
    let stamp = Timestamp::parse(&last_modified, TimestampFormat::HttpDate).expect("an HTTP-date");
    assert_eq!(
        stamp.render(TimestampFormat::HttpDate).expect("renderable"),
        last_modified,
        "the IMF-fixdate spelling, byte for byte"
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let later = Timestamp::from_secs(stamp.secs() + 1)
        .render(TimestampFormat::HttpDate)
        .expect("renderable");
    let earlier = Timestamp::from_secs(stamp.secs() - 3600)
        .render(TimestampFormat::HttpDate)
        .expect("renderable");
    for (since, status) in [(later.as_str(), 304), (earlier.as_str(), 200)] {
        let read = exchange(
            &service,
            signed(
                MAIN_KEY,
                MAIN_SECRET,
                http::Method::GET,
                "/pins/dated",
                Bytes::new(),
                &[("if-modified-since", since)],
            ),
        )
        .await;
        assert_eq!(read.status(), status, "If-Modified-Since: {since}");
        assert_eq!(read.header("last-modified"), Some(last_modified.as_str()), "{since}");
        assert_eq!(read.header("etag"), Some(etag.as_str()), "{since}");
    }
}
