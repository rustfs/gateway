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

//! One raw request, exactly as both stacks receive it.
//!
//! Responsible for: the method, origin-form target, ordered header lines (any bytes a field value
//! may hold) and the body as the transport split it; building the `http::Request` head both
//! stacks are handed from it.
//! NOT responsible for: signing, normalising a recorded request (the corpus runner does that and
//! says what it changed), or deciding whether a request is well formed — that is what is measured.
//! Upstream: tests, and later the corpus runner and the shadow proxy.
//! Downstream: `gateway.rs` and `oracle.rs`, which send it.

use bytes::Bytes;
use http::Method;

/// The authority a request is addressed to when it names none. Path-style, so the bucket is in the
/// path and neither stack needs a base domain.
pub(crate) const DEFAULT_HOST: &str = "difftest.invalid";

/// One raw request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRequest {
    /// The request method.
    pub method: Method,
    /// Path and query in origin form, starting at `/`.
    pub target: String,
    /// Header lines in arrival order; a name may repeat. A `host` line is added when none is
    /// present, because both stacks refuse a request without one.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body, split the way the transport delivers it. Empty pieces are dropped when sent: a
    /// transport never delivers one.
    pub body: Vec<Bytes>,
    /// Whether the connection it arrived on is encrypted. The gateway refuses a customer-provided
    /// encryption key on a cleartext connection itself; s3s leaves that to a layer in front of it
    /// (RustFS has one), so a request carrying SSE-C members is compared as a TLS request.
    pub secure: bool,
}

impl RawRequest {
    /// A bodiless request.
    #[must_use]
    pub fn new(method: Method, target: &str) -> Self {
        Self {
            method,
            target: target.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            secure: false,
        }
    }

    /// The same request, arriving on a cleartext connection.
    #[must_use]
    pub fn plaintext(mut self) -> Self {
        self.secure = false;
        self
    }

    /// The same request, arriving on an encrypted connection.
    #[must_use]
    pub fn over_tls(mut self) -> Self {
        self.secure = true;
        self
    }

    /// A bodiless `GET`.
    #[must_use]
    pub fn get(target: &str) -> Self {
        Self::new(Method::GET, target)
    }

    /// A bodiless `HEAD`.
    #[must_use]
    pub fn head(target: &str) -> Self {
        Self::new(Method::HEAD, target)
    }

    /// A bodiless `DELETE`.
    #[must_use]
    pub fn delete(target: &str) -> Self {
        Self::new(Method::DELETE, target)
    }

    /// A request carrying `body` in one piece, with its exact `content-length`.
    #[must_use]
    pub fn with_body(method: Method, target: &str, body: &[u8]) -> Self {
        Self::new(method, target)
            .header("content-length", &body.len().to_string())
            .body_pieces(&[body])
    }

    /// A `PUT` of `body` in one piece, with its exact `content-length`.
    #[must_use]
    pub fn put(target: &str, body: &[u8]) -> Self {
        Self::with_body(Method::PUT, target, body)
    }

    /// A `POST` of `body` in one piece, with its exact `content-length`.
    #[must_use]
    pub fn post(target: &str, body: &[u8]) -> Self {
        Self::with_body(Method::POST, target, body)
    }

    /// Adds one header line.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.as_bytes().to_vec()));
        self
    }

    /// Removes every line of one header.
    #[must_use]
    pub fn without(mut self, name: &str) -> Self {
        self.headers.retain(|(present, _)| !present.eq_ignore_ascii_case(name));
        self
    }

    /// Replaces the body with these pieces, leaving the header lines alone.
    #[must_use]
    pub fn body_pieces(mut self, pieces: &[&[u8]]) -> Self {
        self.body = pieces.iter().map(|piece| Bytes::copy_from_slice(piece)).collect();
        self
    }

    /// The request head both stacks are handed, or why these bytes cannot be one.
    pub(crate) fn http_head(&self) -> Result<http::request::Builder, String> {
        let uri: http::Uri = self
            .target
            .parse()
            .map_err(|error| format!("the target is not a request target: {error}"))?;
        let mut builder = http::Request::builder().method(self.method.clone()).uri(uri);
        if !self.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            builder = builder.header(http::header::HOST, DEFAULT_HOST);
        }
        for (name, value) in &self.headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| format!("header name {name:?}: {error}"))?;
            let value = http::HeaderValue::from_bytes(value).map_err(|error| format!("header {name} value: {error}"))?;
            builder = builder.header(name, value);
        }
        Ok(builder)
    }
}
