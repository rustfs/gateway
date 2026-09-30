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

//! The RustFS profile's request target (rustfs/gateway#1148): the adapter hands the target's scheme
//! and authority over (`request_to_legacy`), so the request URI a RustFS body reads is the one the
//! legacy stack's transport hands its handler — over HTTP/2, where no `Host` line names the host and
//! RustFS builds a completed upload's `Location` from the URI, and for an absolute-form target.
//!
//! Responsible for: every target shape — HTTP/2 over `https` and `http`, absolute form, origin form,
//! signed and anonymous — handed over with no context member differing; the typed reading's control,
//! which loses the authority; and `request_to_legacy`'s refusals by name.
//! NOT responsible for: the typed reading's own rows and rulings (`super::put_object`, rd-ctx-0004),
//! or what RustFS builds from the URI (legacy RustFS's `Location` over HTTP/1.1 and HTTP/2 was
//! observed on a legacy build: `http://<authority>/<bucket>/<key>` on both).
//! Upstream: the harness in `super`. Downstream: nothing.

use super::super::seam::request_context::{GatewayRequestContext, RequestTarget, request_to_legacy};
use super::{ContextRequest, PATH_HOST, compare, differing_context};

const NONE: &[&str] = &[];

fn put() -> ContextRequest {
    ContextRequest::put(PATH_HOST, "/photos/dir/a%20b.jpg", b"hello")
}

/// An HTTP/2 request names its host in `:authority` alone: the gateway hands the target's scheme
/// and authority over, so both handlers see the same absolute URI and no `Host` line, and a RustFS
/// body reading the host from the URI reads the same one.
#[test]
fn an_http2_target_reaches_both_handlers_with_its_scheme_and_authority() {
    for scheme in ["https", "http"] {
        for request in [
            put().http2(scheme).legacy_target(),
            put().signed("us-east-1").http2(scheme).legacy_target(),
        ] {
            let compared = compare(&request).expect("both stacks reach their PutObject handler");
            assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE, "{scheme}");
            assert_eq!(compared.converted.uri, compared.oracle.uri, "{scheme}");
            assert_eq!(compared.converted.uri.to_string(), format!("{scheme}://{PATH_HOST}/photos/dir/a%20b.jpg"));
            // The legacy stack names the host in a `Host` line of its own, and so does the seam.
            assert_eq!(
                compared
                    .converted
                    .headers
                    .get(http::header::HOST)
                    .map(http::HeaderValue::as_bytes),
                Some(PATH_HOST.as_bytes()),
                "{scheme}"
            );
        }
    }
}

/// An absolute-form HTTP/1.1 target keeps its authority on both handlers: the difference rd-ctx-0004
/// pins for the typed reading does not occur in the RustFS profile.
#[test]
fn an_absolute_form_target_keeps_its_authority_on_both_handlers() {
    let compared = compare(&put().absolute_form().legacy_target()).expect("both stacks reach their PutObject handler");
    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri.to_string(), format!("http://{PATH_HOST}/photos/dir/a%20b.jpg"));
}

/// An origin-form target crosses as its path and query, exactly as before.
#[test]
fn an_origin_form_target_crosses_as_its_path_and_query() {
    let request = ContextRequest::get(PATH_HOST, "/photos", "location")
        .signed("us-east-1")
        .legacy_target();
    let compared = compare(&request).expect("both stacks reach their GetBucketLocation handler");
    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri.to_string(), "/photos?location");
}

// ── controls and refusals ─────────────────────────────────────────────────────────────────────

/// Negative — the typed reading hands HTTP/2's target over as its path alone and adds no `Host`
/// line, so a RustFS body finds neither a `Host` line nor an authority where the legacy stack's
/// handler finds both: the two differences this profile removes.
#[test]
fn n_the_typed_reading_loses_an_http2_authority() {
    let compared = compare(&put().signed("us-east-1").http2("https")).expect("both stacks reach their PutObject handler");
    assert_eq!(differing_context(&compared.converted, &compared.oracle), ["uri", "headers"]);
    assert_eq!(compared.converted.uri.authority(), None);
    assert_eq!(compared.converted.headers.get(http::header::HOST), None);
    assert_eq!(compared.oracle.uri.authority().map(http::uri::Authority::as_str), Some(PATH_HOST));
}

fn context() -> GatewayRequestContext {
    GatewayRequestContext {
        method: http::Method::PUT,
        raw_path: String::from("/photos/a.jpg"),
        raw_query: String::from("x-id=PutObject"),
        headers: http::HeaderMap::new(),
        principal: None,
        host_region: None,
        declares_trailers: false,
    }
}

fn target(scheme: Option<&str>, authority: Option<&str>) -> RequestTarget {
    RequestTarget {
        version: http::Version::HTTP_11,
        scheme: scheme.map(str::to_owned),
        authority: authority.map(str::to_owned),
    }
}

/// Negative — a target that carries only one of scheme and authority, or whose parts do not form a
/// URI, is refused by name rather than guessed at.
#[test]
fn n_a_target_that_is_not_a_scheme_and_an_authority_is_refused_by_name() {
    for (scheme, authority) in [
        (Some("https"), None),
        (None, Some("s3.example.test")),
        (Some("https"), Some("bad host")),
        (Some("https"), Some("")),
        (Some("h ttps"), Some("s3.example.test")),
        (Some("https"), Some("s3.example.test/extra")),
    ] {
        let error = request_to_legacy(context(), target(scheme, authority), ())
            .map(|_| ())
            .expect_err("the conversion refuses");
        assert_eq!(error.field, "uri", "{scheme:?} {authority:?}");
    }
}

/// Negative — the `Host` line the legacy stack adds is added for HTTP/2 and HTTP/3 alone, and never
/// replaces one the request sent; an absolute-form HTTP/1.1 target gets none.
#[test]
fn n_a_host_line_is_added_for_http2_and_http3_alone_and_never_replaces_one() {
    let authority = Some("s3.example.test:9000");
    for (version, expected) in [
        (http::Version::HTTP_2, Some("s3.example.test:9000")),
        (http::Version::HTTP_3, Some("s3.example.test:9000")),
        (http::Version::HTTP_11, None),
        (http::Version::HTTP_10, None),
    ] {
        let target = RequestTarget {
            version,
            ..target(Some("https"), authority)
        };
        let converted = request_to_legacy(context(), target, ()).expect("converts");
        let host = converted
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok());
        assert_eq!(host, expected, "{version:?}");
    }
    let mut sent = context();
    sent.headers
        .insert(http::header::HOST, http::HeaderValue::from_static("sent.example.test"));
    let target = RequestTarget {
        version: http::Version::HTTP_2,
        ..target(Some("https"), authority)
    };
    let converted = request_to_legacy(sent, target, ()).expect("converts");
    assert_eq!(converted.headers.get_all(http::header::HOST).iter().count(), 1);
    assert_eq!(
        converted.headers.get(http::header::HOST).map(http::HeaderValue::as_bytes),
        Some(&b"sent.example.test"[..])
    );
}

/// The rebuilt URI keeps the raw path and query exactly, percent-encoding included, behind the
/// authority; an origin-form target is the path and query alone.
#[test]
fn the_rebuilt_uri_keeps_the_raw_path_and_query() {
    let converted = request_to_legacy(context(), target(Some("https"), Some("s3.example.test:9000")), ()).expect("converts");
    assert_eq!(converted.uri.to_string(), "https://s3.example.test:9000/photos/a.jpg?x-id=PutObject");
    let converted = request_to_legacy(context(), target(None, None), ()).expect("converts");
    assert_eq!(converted.uri.to_string(), "/photos/a.jpg?x-id=PutObject");
}
