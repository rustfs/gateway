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

//! The final adapter from a codec response to the HTTP response sent downstream.
//!
//! Responsible for: preserving the codec's status, headers, and body shape in an HTTP response.
//! NOT responsible for: choosing success semantics, rendering refusals, or transport framing.
//! Upstream: `crate::service`. Downstream: `rustfs_gateway_stream::Body` and the server adapter.

use http::Response;
use rustfs_gateway_core::{EncodedResponse, ResponseBody};
use rustfs_gateway_stream::Body;

/// Turns an encoder's output into the response that goes on the wire.
pub(crate) fn into_response(encoded: EncodedResponse) -> Response<Body> {
    let body = match encoded.body {
        ResponseBody::Empty => Body::empty(),
        ResponseBody::Complete(bytes) => Body::from(bytes),
        ResponseBody::Stream(stream) => stream.into_body(),
    };
    let mut response = Response::new(body);
    *response.status_mut() = encoded.status;
    *response.headers_mut() = encoded.headers;
    response
}
