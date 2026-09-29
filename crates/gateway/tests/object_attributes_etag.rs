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

//! `GetObjectAttributes`'s entity tag as RustFS clients read it, for the entity tags RustFS stores
//! (rustfs/gateway#1120).
//!
//! Responsible for: the scenarios of RustFS's `ObjectAttributesEtagFixLayer` tests
//! (`rustfs/src/server/layer.rs:4338-4380`, `:4541-4600`, rustfs/rustfs#2002) against the built-in
//! rendering (`q-mpu-attributes-etag-0036`): a tag RustFS hands over with its quotes — single-part
//! and multipart — is written bare in the attributes document, a bare one stays bare, the other
//! members are untouched, and the same tag on `HeadObject`'s header keeps its quotes; and a refused
//! attributes request is a plain error document.
//! NOT responsible for: the rendering contexts themselves (`rustfs-gateway-types`' `EtagRender`),
//! or the `OpLayer` demonstration (`tests/patch_layer_landings.rs`).
//! Upstream: `tests/support`. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`):
//! `<ETag>5eb63bbbe01eeed093cb22bb8f5acdc3</ETag>` in the attributes document, `"5eb6…"` in
//! `HeadObject`'s `ETag` header.

#![allow(clippy::expect_used)]

use crate::support;

use std::sync::Arc;

use rustfs_gateway::dto::{GetObjectAttributes, GetObjectAttributesOutput, HeadObject, HeadObjectOutput};
use rustfs_gateway::{ETag, Handler, HandlerError, HandlerErrorContext, HandlerResult, Req, Resp, S3Service};

const SINGLE: &str = "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"";
const MULTIPART: &str = "\"6304d8b66864869a34b0f9efd0631414-3\"";

/// Answers every object with the stored tag it was built with, as RustFS hands a stored tag over.
struct Stored(&'static str);

impl Handler<GetObjectAttributes> for Stored {
    async fn call(&self, request: Req<GetObjectAttributes>) -> HandlerResult<GetObjectAttributes> {
        if request.input().key.as_str() == "absent" {
            return Err(HandlerError::from(HandlerErrorContext::missing_bucket()));
        }
        Ok(Resp::new(GetObjectAttributesOutput {
            e_tag: Some(ETag::new(self.0).expect("a valid entity tag")),
            object_size: Some(11),
            ..GetObjectAttributesOutput::default()
        }))
    }
}

impl Handler<HeadObject> for Stored {
    async fn call(&self, _request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        Ok(Resp::new(HeadObjectOutput {
            e_tag: Some(ETag::new(self.0).expect("a valid entity tag")),
            content_length: Some(11),
            ..HeadObjectOutput::default()
        }))
    }
}

fn service(stored: &'static str) -> S3Service {
    let backend = Arc::new(Stored(stored));
    support::wired_at_signed_time()
        .register::<GetObjectAttributes, _>(Arc::clone(&backend))
        .register::<HeadObject, _>(backend)
        .build()
        .expect("an attributes assembly")
}

fn attributes(key: &str) -> http::Request<bytes::Bytes> {
    support::signed_with(
        http::Method::GET,
        &format!("/bucket/{key}?attributes"),
        &[("x-amz-object-attributes", "ETag,ObjectSize")],
    )
}

/// Positive — a stored tag handed over quoted, single-part or multipart, is written bare in the
/// attributes document, and `ObjectSize` beside it is untouched.
#[tokio::test]
async fn a_quoted_stored_tag_is_written_bare_in_the_attributes_document() {
    for (stored, bare) in [
        (SINGLE, "5eb63bbbe01eeed093cb22bb8f5acdc3"),
        (MULTIPART, "6304d8b66864869a34b0f9efd0631414-3"),
    ] {
        let (status, body) = support::exchange(&service(stored), attributes("key")).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert!(body.contains(&format!("<ETag>{bare}</ETag>")), "{body}");
        assert!(!body.contains("&quot;") && !body.contains("\"5eb6") && !body.contains("\"6304"), "{body}");
        assert!(body.contains("<ObjectSize>11</ObjectSize>"), "{body}");
    }
}

/// Negative — a tag handed over bare stays bare; nothing adds quotes.
#[tokio::test]
async fn n_a_bare_stored_tag_stays_bare() {
    let (status, body) = support::exchange(&service("5eb63bbbe01eeed093cb22bb8f5acdc3"), attributes("key")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<ETag>5eb63bbbe01eeed093cb22bb8f5acdc3</ETag>"), "{body}");
}

/// Negative — the bare spelling belongs to the attributes document only: the same stored tag on
/// `HeadObject`'s `ETag` header keeps its quotes.
#[tokio::test]
async fn n_the_same_tag_elsewhere_keeps_its_quotes() {
    let response = support::exchange_wire(&service(SINGLE), support::signed(http::Method::HEAD, "/bucket/key")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.header("etag"), Some(SINGLE));
}

/// Negative — a refused attributes request is a plain error document with no entity tag in it.
#[tokio::test]
async fn n_a_refused_attributes_request_carries_no_tag() {
    let (status, body) = support::exchange(&service(SINGLE), attributes("absent")).await;
    assert_eq!(status, http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("<Code>NoSuchBucket</Code>"), "{body}");
    assert!(!body.contains("<ETag>"), "{body}");
}
