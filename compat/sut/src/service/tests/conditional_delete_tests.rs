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

//! `If-Match` on `DeleteObject`, answered by the RustFS-profile launcher as legacy RustFS answers
//! it (rustfs/gateway#1191).
//!
//! Responsible for: proving the served assembly judges the header — MinIO mint's
//! `ConditionalDeleteWithIncorrectETag`: another tag is `412` and the object stays; a key holding
//! nothing is `412`; the object's own tag deletes it; a versioned bucket's key never written is
//! marked without being judged.
//! NOT responsible for: every case of the rule, which `crates/fs/tests/crud/delete_conditions.rs`
//! pins against the backend alone.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a legacy RustFS build (rustfs/rustfs `528a36814`): each answer
//! below, with the `412` body `<Code>PreconditionFailed</Code>` and legacy RustFS's sentence.

use super::*;

const VERSIONING: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";

fn delete_if(target: &str, if_match: &str) -> http::Request<Bytes> {
    signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::DELETE,
        target,
        Bytes::new(),
        &[("if-match", if_match)],
    )
}

fn header_text<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response
        .headers()
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == name).then(|| value.to_str().ok()).flatten())
}

fn assert_refused(response: &WireResponse) {
    let body = body_of(response);
    assert_eq!(response.status(), 412, "{body}");
    assert!(body.contains("<Code>PreconditionFailed</Code>"), "{body}");
    assert!(
        body.contains("<Message>At least one of the pre-conditions you specified did not hold</Message>"),
        "{body}"
    );
}

/// Negative, then the positive it differs from — another tag and a key holding nothing are
/// refused and delete nothing; the object's own tag deletes it.
#[tokio::test]
async fn n_a_delete_naming_another_tag_is_refused() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/conditional", Bytes::new()))
            .await
            .status(),
        200
    );
    let stored = exchange(&service, as_main(http::Method::PUT, "/conditional/key", Bytes::from_static(b"body"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let e_tag = header_text(&stored, "etag").expect("a stored tag").to_owned();

    assert_refused(&exchange(&service, delete_if("/conditional/key", "\"wrong-etag\"")).await);
    let kept = exchange(&service, as_main(http::Method::GET, "/conditional/key", Bytes::new())).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    assert_eq!(kept.body().as_ref(), b"body");
    assert_refused(&exchange(&service, delete_if("/conditional/never", "*")).await);

    let deleted = exchange(&service, delete_if("/conditional/key", &e_tag)).await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    let gone = exchange(&service, as_main(http::Method::GET, "/conditional/key", Bytes::new())).await;
    assert_eq!(gone.status(), 404);
}

/// Positive, legacy RustFS's quirk — a versioned bucket's key never written is not judged: the
/// delete writes a marker even though `*` names nothing.
#[tokio::test]
async fn a_versioned_key_never_written_is_marked() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/conditional-versions", Bytes::new()))
            .await
            .status(),
        200
    );
    let versioned = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/conditional-versions?versioning",
        Bytes::from_static(VERSIONING.as_bytes()),
        &[("content-md5", "QQFYoy/mRYV9PGZUfFi0Bw==")],
    );
    let configured = exchange(&service, versioned).await;
    assert_eq!(configured.status(), 200, "{}", body_of(&configured));

    let marked = exchange(&service, delete_if("/conditional-versions/never", "*")).await;
    assert_eq!(marked.status(), 204, "{}", body_of(&marked));
    assert_eq!(header_text(&marked, "x-amz-delete-marker"), Some("true"));
}
