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

//! The gateway's CORS answers over a stored bucket document, end to end (rustfs/gateway#1004).
//!
//! Responsible for: a preflight refused without a document, allowed once `PutBucketCors` stored
//! one that admits its origin and method, refused for a method or origin no rule admits, and a
//! signed request carrying an admitted `Origin` answered with `Access-Control-Allow-Origin`.
//! NOT responsible for: matching rules or cache mechanics (`rustfs-gateway`'s own CORS tests);
//! this measures the gateway's CORS path behind the assembly RustFS uses, fed by the backend.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const RULES: &str = "<CORSConfiguration><CORSRule><AllowedOrigin>https://*.get</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule><CORSRule><AllowedOrigin>https://*.put</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>";
const RULES_MD5: &str = "ZBIPBse1Z6uzdiVcRmsTYQ==";

fn preflight(origin: &str, method: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/corsy/object")
        .header(http::header::HOST, "s3.example.com")
        .header("origin", origin)
        .header("access-control-request-method", method)
        .body(Bytes::new())
        .expect("a preflight")
}

fn allow_origin(response: &WireResponse) -> Option<String> {
    response
        .headers()
        .iter()
        .find_map(|(name, value)| {
            (name.as_str() == "access-control-allow-origin").then(|| value.to_str().ok().map(ToOwned::to_owned))
        })
        .flatten()
}

/// Negative then positive — without a document every preflight is refused; once stored, the
/// admitted origin and method are allowed and nothing else is.
#[tokio::test]
async fn preflights_follow_the_stored_document() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/corsy", Bytes::new()))
            .await
            .status(),
        200
    );

    let before = exchange(&service, preflight("https://a.put", "PUT")).await;
    assert_eq!(before.status(), 403, "{}", body_of(&before));
    assert_eq!(allow_origin(&before), None);

    let written = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/corsy?cors",
            Bytes::from_static(RULES.as_bytes()),
            &[("content-md5", RULES_MD5)],
        ),
    )
    .await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));

    let allowed = exchange(&service, preflight("https://a.put", "PUT")).await;
    assert_eq!(allowed.status(), 200, "{}", body_of(&allowed));
    assert!(allow_origin(&allowed).is_some(), "an allowed preflight names the origin");
    for (origin, method) in [
        ("https://a.put", "DELETE"),
        ("https://a.other", "PUT"),
        ("https://a.get", "PUT"),
    ] {
        let refused = exchange(&service, preflight(origin, method)).await;
        assert_eq!(refused.status(), 403, "{origin} {method}: {}", body_of(&refused));
        assert_eq!(allow_origin(&refused), None, "{origin} {method}");
    }
}

/// Positive and control — a signed request with an admitted `Origin` is answered with
/// `Access-Control-Allow-Origin`; one whose origin no rule admits carries none.
#[tokio::test]
async fn an_admitted_origin_is_named_on_an_actual_request() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/corsy", Bytes::new()))
            .await
            .status(),
        200
    );
    let written = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/corsy?cors",
            Bytes::from_static(RULES.as_bytes()),
            &[("content-md5", RULES_MD5)],
        ),
    )
    .await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));

    let admitted = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/corsy?list-type=2",
            Bytes::new(),
            &[("origin", "https://a.get")],
        ),
    )
    .await;
    assert_eq!(admitted.status(), 200, "{}", body_of(&admitted));
    assert!(allow_origin(&admitted).is_some(), "{:?}", admitted.headers());

    let other = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/corsy?list-type=2",
            Bytes::new(),
            &[("origin", "https://a.other")],
        ),
    )
    .await;
    assert_eq!(other.status(), 200, "{}", body_of(&other));
    assert_eq!(allow_origin(&other), None);
}
