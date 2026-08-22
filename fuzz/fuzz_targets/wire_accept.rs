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

//! Responsible for: exercising request-head acceptance with arbitrary URI and header bytes.
//! NOT responsible for: reading bodies or running routing, authentication, or storage.
//! Upstream: libFuzzer and `http` request types.
//! Downstream: `rustfs-gateway-http` acceptance.

#![no_main]

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway_http::{Limits, WireRequest};

fn take<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let Some((&requested, rest)) = input.split_first() else {
        return &[];
    };
    let length = usize::from(requested).min(rest.len());
    let (value, remaining) = rest.split_at(length);
    *input = remaining;
    value
}

fn append(headers: &mut http::HeaderMap, name: HeaderName, bytes: &[u8]) {
    if let Ok(value) = HeaderValue::from_bytes(bytes) {
        headers.append(name, value);
    }
}

fuzz_target!(|input: &[u8]| {
    let mut remaining = input;
    let selector = remaining.first().copied().unwrap_or_default();
    remaining = remaining.get(1..).unwrap_or_default();

    let uri_bytes = take(&mut remaining);
    let uri = Uri::from_maybe_shared(Bytes::copy_from_slice(uri_bytes)).unwrap_or_else(|_| Uri::from_static("/"));
    let mut request = Request::new(());
    *request.uri_mut() = uri;
    *request.method_mut() = if selector & 1 == 0 { Method::GET } else { Method::PUT };
    *request.version_mut() = if selector & 2 == 0 {
        Version::HTTP_11
    } else {
        Version::HTTP_2
    };

    let host = take(&mut remaining);
    let content_length = take(&mut remaining);
    let transfer_encoding = take(&mut remaining);
    let arbitrary_name = take(&mut remaining);
    let arbitrary_value = take(&mut remaining);
    let authorization = take(&mut remaining);
    let headers = request.headers_mut();
    append(headers, HOST, host);
    append(headers, CONTENT_LENGTH, content_length);
    append(headers, TRANSFER_ENCODING, transfer_encoding);
    append(headers, AUTHORIZATION, authorization);
    if selector & 4 != 0 {
        append(headers, HOST, arbitrary_value);
    }
    if selector & 8 != 0 {
        append(headers, CONTENT_LENGTH, arbitrary_value);
    }
    if selector & 16 != 0 {
        append(headers, TRANSFER_ENCODING, arbitrary_value);
    }
    if let Ok(name) = HeaderName::from_bytes(arbitrary_name) {
        append(headers, name, arbitrary_value);
    }

    let _ = WireRequest::accept(request, &Limits::default());
});
