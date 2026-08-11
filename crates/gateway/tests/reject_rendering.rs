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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! What a wire refusal actually says to a client, checked on the rendered bytes.
//!
//! `rustfs-gateway-http` has two strings per refusal, for two audiences: [`WireReject::message`]
//! is what a client reads, and [`WireReject::label`] is an operator's identifier for a log. The
//! renderer picked the wrong one — `<Message>limit-exceeded</Message>` reached clients, an
//! internal name that changes with a refactor and that a client would learn to parse.
//!
//! There used to be a third accessor, `as_str`, delegating to `message`, and a test in the `-http`
//! crate pinning that delegation. Both are gone: a name reached for out of habit that happens to
//! be right is not a guarantee, and the test could only ever assert something about an accessor.
//! What matters is the bytes, and the bytes are produced here — so the check is here, on the
//! document, where a regression has nowhere left to hide.

use crate::support;

use rustfs_gateway_http::WireReject;
use support::{exchange, plain, service};

fn labels() -> [&'static str; 2] {
    [
        WireReject::TransferEncodingMalformed.label(),
        WireReject::MalformedContentLength.label(),
    ]
}

#[tokio::test]
async fn no_operator_label_appears_in_a_rendered_refusal() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("gzip"));
    let (_status, body) = exchange(&service(), request).await;
    for label in labels() {
        assert!(
            !body.contains(label),
            "the real service response contains operator label {label:?}: {body}"
        );
    }
}

#[tokio::test]
async fn a_rendered_refusal_carries_the_client_message() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("gzip"));
    let (_status, body) = exchange(&service(), request).await;
    assert!(
        body.contains(&format!("<Message>{}</Message>", WireReject::TransferEncodingMalformed.message())),
        "the real service response does not carry its client message: {body}"
    );
}
