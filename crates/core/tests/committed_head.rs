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

//! Frozen operation-header contracts for responses that commit before their work completes.
//!
//! Responsible for: proving only generated response-header bindings enter a committed head and
//! that duplicate or framework-owned headers are refused before work can start.
//! NOT responsible for: driving the deferred work or writing keep-alive bytes.
//! Upstream: generated `DeferredOperation` implementations. Downstream: the gateway facade.

use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_core::{Answer, HeadPart, Resp};
use rustfs_gateway_types::dto::{CompleteMultipartUpload, CompleteMultipartUploadOutput};

fn header(name: HeaderName, value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(name, HeaderValue::from_static(value));
    headers
}

/// Negative — a backend cannot invent a response header outside the generated binding set.
#[test]
fn an_unbound_operation_header_is_rejected() {
    let headers = header(HeaderName::from_static("x-amz-unbound"), "value");
    assert!(HeadPart::<CompleteMultipartUpload>::new(headers).is_err());
}

/// Negative — framework framing and media headers do not belong to a backend-owned head.
#[test]
fn a_framework_owned_header_is_rejected() {
    let headers = header(CONTENT_TYPE, "text/plain");
    assert!(HeadPart::<CompleteMultipartUpload>::new(headers).is_err());
}

/// Negative — two values for one operation header leave an intermediary free to choose.
#[test]
fn a_duplicate_operation_header_is_rejected() {
    let name = HeaderName::from_static("x-amz-version-id");
    let mut headers = header(name.clone(), "one");
    headers.append(name, HeaderValue::from_static("two"));
    assert!(HeadPart::<CompleteMultipartUpload>::new(headers).is_err());
}

/// Positive — a generated binding enters the typed committed response unchanged.
#[test]
fn a_bound_operation_header_survives_into_the_committed_answer() {
    let name = HeaderName::from_static("x-amz-version-id");
    let head = HeadPart::<CompleteMultipartUpload>::new(header(name.clone(), "version-1")).expect("a bound header");
    let response =
        Resp::<CompleteMultipartUpload>::commit(head, Box::pin(async { Ok(CompleteMultipartUploadOutput::default()) }));
    let (Answer::Committed(committed), status, _) = response.into_parts() else {
        panic!("the committed constructor returned another answer shape");
    };
    assert_eq!(status, 200);
    assert_eq!(committed.head().headers().get(name), Some(&HeaderValue::from_static("version-1")));
}
