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
//! RFC 9110 conditional requests against the fs backend (rustfs/gateway#808): `If-Match`,
//! `If-None-Match`, `If-Modified-Since` and `If-Unmodified-Since` on `GetObject` and `HeadObject`,
//! and `If-Match` / `If-None-Match` on `PutObject`.
//!
//! Responsible for: the wire answers — `412`, `304` with its validators and no body, the write
//! left undone — and the one fact only a backend can prove: the write condition is judged under
//! the same lock as the publication it guards.
//! NOT responsible for: the evaluation order (`rustfs-gateway`'s precondition tests) or CopyObject's
//! copy-source conditions (`copy_object.rs`).
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use super::*;

const OLD: &[u8] = b"first";
const NEW: &[u8] = b"second";
const LONG_AGO: &str = "Thu, 01 Jan 2015 00:00:00 GMT";

fn headers(extra: &[(&'static str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_str(value).expect("an ASCII fixture header"),
        );
    }
    headers
}

async fn send(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: &'static [u8],
    extra: &[(&'static str, &str)],
) -> rustfs_gateway::WireResponse {
    exchange(service, signed_with_headers(method, target, Bytes::from_static(body), headers(extra))).await
}

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

fn code(response: &rustfs_gateway::WireResponse) -> String {
    let body = String::from_utf8_lossy(response.body()).into_owned();
    body.split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or_default()
        .to_owned()
}

/// A bucket holding `object.txt` = [`OLD`], with the entity tag and `Last-Modified` it was given.
async fn stored(root: &TestRoot, bucket: &str) -> (S3Service, String, String) {
    let (_backend, service) = service(root);
    create_bucket(&service, bucket).await;
    let put = send(&service, http::Method::PUT, &format!("/{bucket}/object.txt"), OLD, &[]).await;
    assert_eq!(put.status(), 200, "{}", String::from_utf8_lossy(put.body()));
    let e_tag = text(&put, "etag").expect("an entity tag").to_owned();
    let head = send(&service, http::Method::HEAD, &format!("/{bucket}/object.txt"), b"", &[]).await;
    let modified = text(&head, "last-modified").expect("a modification time").to_owned();
    (service, e_tag, modified)
}

/// Positive — a read whose conditions hold is served whole: the current tag in `If-Match`, another
/// tag in `If-None-Match`, an old date in `If-Modified-Since`, the object's own date in
/// `If-Unmodified-Since`.
#[tokio::test]
async fn a_read_whose_conditions_hold_is_served() {
    let root = TestRoot::new();
    let (service, e_tag, modified) = stored(&root, "cond-holds").await;
    for method in [http::Method::GET, http::Method::HEAD] {
        for condition in [
            ("if-match", e_tag.as_str()),
            ("if-none-match", "\"0123456789abcdef0123456789abcdef\""),
            ("if-modified-since", LONG_AGO),
            ("if-unmodified-since", modified.as_str()),
        ] {
            let response = send(&service, method.clone(), "/cond-holds/object.txt", b"", &[condition]).await;
            assert_eq!(response.status(), 200, "{method} {condition:?}");
            assert_eq!(text(&response, "etag"), Some(e_tag.as_str()), "{method} {condition:?}");
        }
    }
}

/// Negative — `If-Match` with another tag and `If-Unmodified-Since` with an older date are `412
/// PreconditionFailed` on `GET` and `HEAD`, and no object byte is served.
#[tokio::test]
async fn n_a_false_if_match_or_if_unmodified_since_is_412() {
    let root = TestRoot::new();
    let (service, _e_tag, _modified) = stored(&root, "cond-412").await;
    for condition in [("if-match", "\"ABCORZ\""), ("if-unmodified-since", LONG_AGO)] {
        let get = send(&service, http::Method::GET, "/cond-412/object.txt", b"", &[condition]).await;
        assert_eq!(get.status(), 412, "{condition:?}");
        assert_eq!(code(&get), "PreconditionFailed", "{condition:?}");
        assert!(!get.body().windows(OLD.len()).any(|window| window == OLD), "{condition:?}");
        let head = send(&service, http::Method::HEAD, "/cond-412/object.txt", b"", &[condition]).await;
        assert_eq!(head.status(), 412, "{condition:?}");
    }
}

/// Negative — `If-None-Match` with the current tag, `If-None-Match: *`, and `If-Modified-Since`
/// with the object's own date are `304` on `GET` and `HEAD`: the validators, and no body.
#[tokio::test]
async fn n_a_current_copy_is_answered_304_with_its_validators_and_no_body() {
    let root = TestRoot::new();
    let (service, e_tag, modified) = stored(&root, "cond-304").await;
    for method in [http::Method::GET, http::Method::HEAD] {
        for condition in [
            ("if-none-match", e_tag.as_str()),
            ("if-none-match", "*"),
            ("if-modified-since", modified.as_str()),
        ] {
            let response = send(&service, method.clone(), "/cond-304/object.txt", b"", &[condition]).await;
            assert_eq!(response.status(), 304, "{method} {condition:?}");
            assert!(response.body().is_empty(), "{method} {condition:?}");
            assert_eq!(text(&response, "last-modified"), Some(modified.as_str()), "{method} {condition:?}");
            if condition.0 == "if-none-match" {
                assert_eq!(text(&response, "etag"), Some(e_tag.as_str()), "{method} {condition:?}");
            }
        }
    }
}

/// Negative — the conditions are evaluated in RFC 9110's order: a false `If-Match` is a `412` even
/// when `If-Modified-Since` would have answered `304`; and `If-Match` sent together with
/// `If-None-Match` is refused as `400 InvalidRequest`, as the contract rules, rather than one of the
/// two being picked silently.
#[tokio::test]
async fn n_a_false_if_match_is_412_before_a_date_is_read_and_two_tag_conditions_are_refused() {
    let root = TestRoot::new();
    let (service, e_tag, modified) = stored(&root, "cond-order").await;
    let ordered = send(
        &service,
        http::Method::GET,
        "/cond-order/object.txt",
        b"",
        &[("if-match", "\"ABCORZ\""), ("if-modified-since", modified.as_str())],
    )
    .await;
    assert_eq!(ordered.status(), 412);
    let both = send(
        &service,
        http::Method::GET,
        "/cond-order/object.txt",
        b"",
        &[("if-match", e_tag.as_str()), ("if-none-match", e_tag.as_str())],
    )
    .await;
    assert_eq!((both.status().as_u16(), code(&both).as_str()), (400, "InvalidRequest"));
}

/// Negative — a condition is evaluated against absence before absence is reported: `If-Match` on a
/// key that holds nothing is a `412`, and only the unconditional miss is `404 NoSuchKey`.
#[tokio::test]
async fn n_if_match_on_a_missing_key_is_412_and_an_unconditional_miss_is_404() {
    let root = TestRoot::new();
    let (service, _e_tag, _modified) = stored(&root, "cond-missing").await;
    let conditional = send(
        &service,
        http::Method::GET,
        "/cond-missing/absent.txt",
        b"",
        &[("if-match", "\"ABCORZ\"")],
    )
    .await;
    assert_eq!(conditional.status(), 412);
    let plain = send(&service, http::Method::GET, "/cond-missing/absent.txt", b"", &[]).await;
    assert_eq!((plain.status().as_u16(), code(&plain).as_str()), (404, "NoSuchKey"));
    let other = send(
        &service,
        http::Method::GET,
        "/cond-missing/absent.txt",
        b"",
        &[("if-none-match", "\"ABCORZ\"")],
    )
    .await;
    assert_eq!(other.status(), 404, "a condition that holds leaves the miss a miss");
}

/// Negative — a conditional entity tag the contract cannot parse, such as the list form, is a
/// `400`, never read as its first member.
#[tokio::test]
async fn n_an_entity_tag_list_is_refused() {
    let root = TestRoot::new();
    let (service, e_tag, _modified) = stored(&root, "cond-list").await;
    let list = format!("{e_tag}, \"ABCORZ\"");
    let response = send(&service, http::Method::GET, "/cond-list/object.txt", b"", &[("if-match", list.as_str())]).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
}

/// Positive and negative — a conditional write replaces the object only when its condition holds:
/// `If-Match` with the current tag writes; with another tag, and `If-None-Match: *` on a key that
/// holds an object, it is a `412` and the stored bytes are unchanged; `If-None-Match: *` on an empty
/// key writes.
#[tokio::test]
async fn n_a_conditional_write_whose_condition_fails_writes_nothing() {
    let root = TestRoot::new();
    let (service, e_tag, _modified) = stored(&root, "cond-write").await;
    for condition in [("if-match", "\"ABCORZ\""), ("if-none-match", "*")] {
        let refused = send(&service, http::Method::PUT, "/cond-write/object.txt", NEW, &[condition]).await;
        assert_eq!(refused.status(), 412, "{condition:?}: {}", String::from_utf8_lossy(refused.body()));
        assert_eq!(code(&refused), "PreconditionFailed", "{condition:?}");
        let kept = send(&service, http::Method::GET, "/cond-write/object.txt", b"", &[]).await;
        assert_eq!(kept.body().as_ref(), OLD, "{condition:?}");
    }
    let missing = send(
        &service,
        http::Method::PUT,
        "/cond-write/absent.txt",
        NEW,
        &[("if-match", e_tag.as_str())],
    )
    .await;
    assert_ne!(missing.status(), 200, "If-Match on a key that holds nothing cannot hold");
    let created = send(&service, http::Method::PUT, "/cond-write/fresh.txt", NEW, &[("if-none-match", "*")]).await;
    assert_eq!(created.status(), 200, "{}", String::from_utf8_lossy(created.body()));
    let replaced = send(
        &service,
        http::Method::PUT,
        "/cond-write/object.txt",
        NEW,
        &[("if-match", e_tag.as_str())],
    )
    .await;
    assert_eq!(replaced.status(), 200, "{}", String::from_utf8_lossy(replaced.body()));
    let now = send(&service, http::Method::GET, "/cond-write/object.txt", b"", &[]).await;
    assert_eq!(now.body().as_ref(), NEW);
}

/// Negative — `If-None-Match: *` is how a client takes a lock, so the condition is judged under the
/// same lock as the publication: of sixteen writers racing for one empty key, exactly one wins and
/// every other is a `412`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_only_one_of_many_racing_create_if_absent_writes_wins() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    create_bucket(&service, "cond-race").await;
    let service = std::sync::Arc::new(service);
    let writers: Vec<_> = (0..16)
        .map(|_| {
            let service = std::sync::Arc::clone(&service);
            tokio::spawn(async move {
                send(&service, http::Method::PUT, "/cond-race/lock", NEW, &[("if-none-match", "*")])
                    .await
                    .status()
                    .as_u16()
            })
        })
        .collect();
    let mut statuses = Vec::new();
    for writer in writers {
        statuses.push(writer.await.expect("a writer finished"));
    }
    statuses.sort_unstable();
    assert_eq!(statuses.iter().filter(|status| **status == 200).count(), 1, "{statuses:?}");
    assert_eq!(statuses.iter().filter(|status| **status == 412).count(), 15, "{statuses:?}");
}
