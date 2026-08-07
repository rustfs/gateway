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

//! `x-amz-bucket-object-lock-token` reaches the backend, and its absence reaches it too.
//!
//! Responsible for: proving that `PutBucketReplication`'s pass-through header is a value a
//! handler can read, in **both** directions — present and absent — and that the document beside
//! it decodes at the same time. `q-repl-0013` claims the header is "parsed into the input and
//! passed through untouched"; that claim is only worth its quirk id if deleting the binding
//! turns something red, and until this file existed nothing did: the conformance case observed a
//! `200`, which a gateway that discarded the header answers just as happily.
//! NOT responsible for: what the token *means*. Whether it actually permits enabling Object Lock
//! on the source bucket is the storage backend's question, and nothing here answers it — the
//! codec neither requires the header nor validates its value.
//! Upstream: the facade's `dto` and `OperationCodec`. Downstream: nothing; this is a leaf test.
//!
//! # Why both directions
//!
//! A binding stuck on `Some("…")` satisfies every test that expects the header to arrive, and a
//! binding stuck on `None` satisfies every test that expects it absent. Only the pair pins the
//! value to the request. The same rule is why the body is asserted here rather than assumed: a
//! decoder that dropped the payload while keeping the header would still pass a header-only test.

use rustfs_gateway::{Limits, MetaView, OperationCodec, RequestBody, TargetKind, WireRequest, dto};

/// The smallest legal replication document: a role and one rule that replicates everything.
const DOCUMENT: &str = concat!(
    "<ReplicationConfiguration>",
    "<Role>arn:aws:iam::111122223333:role/replication-role</Role>",
    "<Rule><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>",
    "</ReplicationConfiguration>"
);

/// The token value the present-direction case sends.
const TOKEN: &str = "lock-token-value";

/// The base64 MD5 of [`DOCUMENT`]. The write is `httpChecksumRequired` (`q-repl-0004`), so a
/// request without it never reaches the header binding this file is about — the decoder refuses
/// it first, which the conformance corpus pins separately as `c-replication-0015`.
const DOCUMENT_MD5: &str = "DIOCQC8GOqnVF/QOP0EZOg==";

/// Decodes `PUT /conf-replication?replication` with whatever header lines the case needs.
fn decoded(headers: &[(&'static str, &'static str)]) -> dto::PutBucketReplicationInput {
    let mut request = http::Request::builder()
        .method("PUT")
        .uri("http://host.invalid/conf-replication?replication")
        .header("host", "host.invalid")
        .header("content-type", "application/xml")
        .header("content-md5", DOCUMENT_MD5)
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request
            .headers_mut()
            .append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&accepted, TargetKind::Bucket).expect("the path names a bucket");
    let body = RequestBody::Buffered(DOCUMENT.as_bytes().to_vec().into());
    dto::PutBucketReplication::decode(&view, body).expect("a well-formed replication write is not a refusal")
}

/// The header the caller sent is the value the handler reads, character for character.
#[test]
fn the_object_lock_token_reaches_the_handler_as_the_caller_spelled_it() {
    let input = decoded(&[("x-amz-bucket-object-lock-token", TOKEN)]);
    assert_eq!(
        input.token.as_deref(),
        Some(TOKEN),
        "the token was parsed and dropped: a handler cannot tell it was sent"
    );
    // The document has to survive the same decode, or a binding that captured only the header
    // would satisfy the assertion above while losing the configuration it accompanies.
    assert_eq!(input.replication_configuration.rules.len(), 1);
    assert_eq!(input.replication_configuration.role, "arn:aws:iam::111122223333:role/replication-role");
}

/// The other direction — without the header the handler sees `None`, not a stale or invented one.
///
/// This is the half that makes the pair a measurement. A binding hard-coded to `Some(..)` passes
/// the case above and fails here; one hard-coded to `None` does the reverse.
#[test]
fn n_an_absent_object_lock_token_reaches_the_handler_as_none() {
    let input = decoded(&[]);
    assert_eq!(
        input.token, None,
        "a token nobody sent must not arrive: the header is optional and carries no default"
    );
    assert_eq!(input.replication_configuration.rules.len(), 1);
}

/// Negative — the token is not a requirement the codec invented.
///
/// AWS documents the header as optional, so a write without it decodes exactly as one with it.
/// The assertion is the absence of a refusal, which the two cases above already exercise; it is
/// stated separately because "optional" is the claim `q-repl-0013` makes and a decoder that
/// started demanding the header would break every client that has never enabled Object Lock.
#[test]
fn n_a_write_without_the_token_is_not_refused() {
    let without = decoded(&[]);
    assert!(without.token.is_none());
    let with_token = decoded(&[("x-amz-bucket-object-lock-token", TOKEN)]);
    // The dto deliberately derives no `PartialEq`, so the two documents are compared member by
    // member on the parts a token could plausibly disturb.
    assert_eq!(
        without.replication_configuration.role, with_token.replication_configuration.role,
        "the token must not change how the document beside it is read"
    );
    assert_eq!(
        without.replication_configuration.rules.len(),
        with_token.replication_configuration.rules.len()
    );
    assert_eq!(
        without.bucket.as_str(),
        with_token.bucket.as_str(),
        "the token must not disturb the bucket the write addresses"
    );
}
