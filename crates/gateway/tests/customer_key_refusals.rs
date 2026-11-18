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

//! A refused customer-provided key, answered through a whole assembly: the RustFS profile's words
//! (`ServiceBuilder::answer_customer_key_refusals_as_legacy_rustfs`) beside the default's.
//!
//! Responsible for: the status, code and sentence a signed `PutObject` over TLS is answered with
//! for each customer-key malformation, under the profile and under the default, and that the
//! handler is reached by neither.
//! NOT responsible for: the rules (`rustfs_gateway_core::sse`), the renderer's own table
//! (`builder/sse_refusals.rs`), or the cleartext gate (`sse_runtime.rs`).
//! Upstream: `rustfs-gateway`, `support`. Downstream: nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, TransportSecurity, dto};

use crate::support::{element_text, exchange, signed_target_with_body_and_headers, wired_at_signed_time};

const ALGORITHM: &str = "x-amz-server-side-encryption-customer-algorithm";
const KEY: &str = "x-amz-server-side-encryption-customer-key";
const KEY_MD5: &str = "x-amz-server-side-encryption-customer-key-md5";
/// `short`, as the RustFS e2e suite sends it, and its true MD5.
const SHORT_KEY: &str = "c2hvcnQ=";
const SHORT_MD5: &str = "TwnaqdlbyxZqMCQHoOC6vg==";
/// `01234567890123456789012345678901` and the MD5 of `98765432109876543210987654321098`.
const KEY_32: &str = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
const OTHER_MD5: &str = "GpnHKFGRw0Wr/Av1zW01XA==";
/// The true MD5 of `KEY_32`.
const KEY_32_MD5: &str = "KYvwGXoFFJ42a2u2GDWhwQ==";

struct Counting(Arc<AtomicUsize>);

impl Handler<dto::PutObject> for Counting {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn assembled(select: fn(ServiceBuilder) -> ServiceBuilder) -> (S3Service, Arc<AtomicUsize>) {
    let handled = Arc::new(AtomicUsize::new(0));
    let service = select(wired_at_signed_time())
        .register::<dto::PutObject, _>(Arc::new(Counting(Arc::clone(&handled))))
        .build()
        .expect("a complete assembly");
    (service, handled)
}

fn default(builder: ServiceBuilder) -> ServiceBuilder {
    builder
}

/// One signed, empty `PutObject` over TLS carrying `headers`: status, code, message and handler count.
async fn put(select: fn(ServiceBuilder) -> ServiceBuilder, headers: &[(&str, &str)]) -> (u16, String, String, usize) {
    let (service, handled) = assembled(select);
    let mut signed = vec![("content-length", "0")];
    signed.extend_from_slice(headers);
    let mut request = signed_target_with_body_and_headers(http::Method::PUT, "/bucket/object", &signed, Bytes::new());
    request.extensions_mut().insert(TransportSecurity::Encrypted);
    let (status, body) = exchange(&service, request).await;
    let code = element_text(&body, "Code").unwrap_or_default().to_owned();
    let message = element_text(&body, "Message").unwrap_or_default().to_owned();
    (status.as_u16(), code, message, handled.load(Ordering::SeqCst))
}

/// The malformations shipped RustFS distinguishes, with its sentence for each.
fn malformations() -> Vec<(Vec<(&'static str, &'static str)>, &'static str)> {
    vec![
        (
            vec![(ALGORITHM, "AES256"), (KEY, SHORT_KEY), (KEY_MD5, SHORT_MD5)],
            "SSE-C key must be 32 bytes (256 bits), got 5 bytes.",
        ),
        (
            vec![(ALGORITHM, "AES256"), (KEY, KEY_32), (KEY_MD5, OTHER_MD5)],
            "The calculated MD5 hash of the key did not match the hash that was provided.",
        ),
        (
            vec![(ALGORITHM, "AES256"), (KEY, "not!base64!!"), (KEY_MD5, KEY_32_MD5)],
            "Invalid SSE-C key: not valid Base64.",
        ),
        (
            vec![(ALGORITHM, "AES128"), (KEY, KEY_32), (KEY_MD5, KEY_32_MD5)],
            "Unsupported SSE-C algorithm. Only AES256 is supported.",
        ),
        (
            vec![(KEY, KEY_32), (KEY_MD5, KEY_32_MD5)],
            "Missing SSE-C parameters. Algorithm, customer key and customer key MD5 are all required.",
        ),
    ]
}

/// Negative — under the RustFS profile each malformation is `400 InvalidRequest` with shipped
/// RustFS's sentence for it, and the handler is never reached.
#[tokio::test]
async fn n_the_rustfs_profile_answers_each_key_fault_in_rustfs_words() {
    for (headers, sentence) in malformations() {
        let answer = put(ServiceBuilder::rustfs_profile, &headers).await;
        assert_eq!(answer, (400, "InvalidRequest".to_owned(), sentence.to_owned(), 0), "{headers:?}");
    }
}

/// Negative — the default answers the same requests as before: a key fault `400 InvalidArgument`
/// in one sentence, and the incomplete trio and the algorithm in the core's sentences.
#[tokio::test]
async fn n_the_default_keeps_its_own_answers() {
    let one_sentence = "the customer-provided encryption key and its MD5 must be base64 of 32 and 16 bytes and must agree";
    let expected = [
        one_sentence,
        one_sentence,
        one_sentence,
        "the customer-provided encryption algorithm must be AES256",
        "the customer-provided encryption algorithm, key and key MD5 headers must all be present or all be absent",
    ];
    for ((headers, _), sentence) in malformations().into_iter().zip(expected) {
        let answer = put(default, &headers).await;
        assert_eq!(answer, (400, "InvalidArgument".to_owned(), sentence.to_owned(), 0), "{headers:?}");
    }
}

/// Negative — no answer under the profile carries the key or either digest.
#[tokio::test]
async fn n_no_profile_answer_carries_the_key_or_a_digest() {
    for (headers, _) in malformations() {
        let (_, _, message, _) = put(ServiceBuilder::rustfs_profile, &headers).await;
        for secret in [
            SHORT_KEY,
            SHORT_MD5,
            KEY_32,
            KEY_32_MD5,
            OTHER_MD5,
            "short",
            "01234567890123456789012345678901",
        ] {
            assert!(!message.contains(secret), "{message:?} carries {secret:?}");
        }
    }
}

/// Positive — a well-formed trio reaches the handler under both assemblies.
#[tokio::test]
async fn a_well_formed_key_is_served_under_both() {
    let trio = [(ALGORITHM, "AES256"), (KEY, KEY_32), (KEY_MD5, KEY_32_MD5)];
    for select in [ServiceBuilder::rustfs_profile, default] {
        let (status, _, message, handled) = put(select, &trio).await;
        assert_eq!((status, handled), (200, 1), "{message}");
    }
}
