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

//! The body a request view hands a decoder that requires the live stream.
//!
//! Responsible for: pinning `RequestBody::into_required_stream` — the live producer handed on, an
//! absent or buffered body an internal error rather than a stream.
//! NOT responsible for: the body's bytes or framing (`rustfs-gateway-stream`).
//! Upstream: `super` (`crate::codec::view`). Downstream: nothing.

use super::*;

#[test]
fn required_stream_returns_the_live_producer() {
    let stream = ByteStream::from_bytes(Bytes::from_static(b"annotation"));
    assert!(RequestBody::Stream(stream).into_required_stream().is_ok());
}

#[test]
fn n_required_stream_refuses_an_absent_body() {
    let result = RequestBody::None.into_required_stream();
    assert!(result.is_err(), "an absent body cannot satisfy a required streaming member");
    let Err(error) = result else {
        return;
    };
    assert_eq!(*error.code(), rustfs_gateway_types::ErrorCode::INTERNAL_ERROR);
}

#[test]
fn n_required_stream_refuses_a_buffered_body() {
    let result = RequestBody::Buffered(Bytes::from_static(b"annotation")).into_required_stream();
    assert!(result.is_err(), "a buffered body cannot masquerade as the live producer");
    let Err(error) = result else {
        return;
    };
    assert_eq!(*error.code(), rustfs_gateway_types::ErrorCode::INTERNAL_ERROR);
}
