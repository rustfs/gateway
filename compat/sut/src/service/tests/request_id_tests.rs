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

//! The request identifiers of the RustFS-profile launcher, as legacy RustFS answers with them
//! (rustfs/backlog#1677, ruling R10).
//!
//! Responsible for: one server-owned UUID in `x-amz-request-id` and `x-request-id` on a refusal and
//! on a success, no `x-amz-id-2`, the same request named in an error document's `<RequestId>` and no
//! `<HostId>`, a fresh identifier per request, a caller's own identifier never echoed, and a host's
//! identifier taken over.
//! NOT responsible for: the side-by-side comparison with the legacy stack (`crates/goldens`'s
//! error-parity diff) or the identifier types (`rustfs-gateway`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy RustFS, rustfs/rustfs `e870a6d25b`: an external S3 request is given
//! `uuid::Uuid::new_v4()` (`rustfs/src/storage/request_context.rs:121-123`), which its answer
//! carries in both headers whatever the stack wrote (`rustfs/src/server/layer.rs:364-367`); nothing
//! writes `x-amz-id-2`, and the legacy stack writes `<RequestId>` only for an error that carries
//! one, which RustFS never sets. The RustFS profile names the request in its document anyway, as
//! ruling R10 requires (`rd-err-0001`).

use super::*;

use rustfs_gateway::HostRequestId;

/// A lowercase hyphenated version-4 UUID, and nothing else.
fn is_uuid_v4(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
        && text
            .bytes()
            .all(|byte| byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && groups.get(2).is_some_and(|group| group.starts_with('4'))
        && groups
            .get(3)
            .is_some_and(|group| matches!(group.as_bytes().first(), Some(b'8' | b'9' | b'a' | b'b')))
}

/// The identifier `response` names its request with, after holding it to legacy RustFS's contract:
/// one UUID, the same in both headers, and no host identifier; an error document names the same
/// request and no host (ruling R10).
fn legacy_identifier(response: &WireResponse) -> String {
    let body = body_of(response);
    let id = response
        .header("x-amz-request-id")
        .unwrap_or_else(|| panic!("no request id: {body}"));
    assert!(is_uuid_v4(id), "{id}");
    assert_eq!(response.header_values("x-amz-request-id").count(), 1);
    assert_eq!(response.header_values("x-request-id").collect::<Vec<_>>(), [id]);
    assert_eq!(response.header("x-amz-id-2"), None, "{body}");
    assert!(!body.contains("HostId"), "{body}");
    if body.contains("<Error>") {
        assert_eq!(body.matches("<RequestId>").count(), 1, "{body}");
        assert!(body.contains(&format!("<RequestId>{id}</RequestId></Error>")), "{body}");
    } else {
        assert!(!body.contains("RequestId"), "{body}");
    }
    id.to_owned()
}

/// Negative — a refusal names its request as legacy RustFS does: in the head only, twice, with
/// RustFS's UUID, and the document names none.
#[tokio::test]
async fn n_a_refusal_names_its_request_as_legacy_rustfs() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let missing = exchange(&service, as_main(http::Method::GET, "/no-such-bucket?list-type=2", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
    assert!(body_of(&missing).contains("<Code>NoSuchBucket</Code>"), "{}", body_of(&missing));
    legacy_identifier(&missing);

    let exists = exchange(&service, as_main(http::Method::PUT, "/owned", Bytes::new())).await;
    assert_eq!(exists.status(), 200, "{}", body_of(&exists));
    let denied = exchange(&service, as_alt(http::Method::GET, "/owned?list-type=2", Bytes::new())).await;
    assert_eq!(denied.status(), 403, "{}", body_of(&denied));
    legacy_identifier(&denied);
}

/// Negative — a success is named the same way, and two requests are never named alike.
#[tokio::test]
async fn n_a_success_names_its_request_as_legacy_rustfs_and_no_two_alike() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let first = exchange(&service, as_main(http::Method::GET, "/", Bytes::new())).await;
    let second = exchange(&service, as_main(http::Method::GET, "/", Bytes::new())).await;
    assert_eq!((first.status().as_u16(), second.status().as_u16()), (200, 200));
    assert_ne!(legacy_identifier(&first), legacy_identifier(&second));
}

/// Negative — identifiers the caller sends under either name are never the answer's.
#[tokio::test]
async fn n_a_callers_identifier_is_never_echoed() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let chosen = "00000000-0000-4000-8000-00000000c0de";
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/",
        Bytes::new(),
        &[("x-request-id", chosen), ("x-amz-request-id", chosen)],
    );
    let response = exchange(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_ne!(legacy_identifier(&response), chosen);
}

/// Positive — an identifier the host hands over is the one the answer names, as RustFS's own is
/// behind its request-context layer.
#[tokio::test]
async fn a_hosts_identifier_is_the_answers() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let host = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    let mut request = as_main(http::Method::GET, "/no-such-bucket?list-type=2", Bytes::new());
    request
        .extensions_mut()
        .insert(HostRequestId::new(host).expect("RustFS's shape"));
    let response = exchange(&service, request).await;
    assert_eq!(response.status(), 404, "{}", body_of(&response));
    assert_eq!(legacy_identifier(&response), host);
}
