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

//! What went back on the wire, in the order it went out.
//!
//! Responsible for: [`WireResponse`] — a status, the response headers **in emission order**, the
//! body bytes, and the trailer section — and [`collect`], which drains an
//! `http::Response<Body>` into one.
//! NOT responsible for: producing a response (`crate::service`), rendering an error document
//! (`crate::render`), or writing bytes on a socket.
//! Upstream: `rustfs-gateway-stream`, `http`. Downstream: any consumer that asserts on a response,
//! the conformance runner above all.
//!
//! # Why the header order is kept
//!
//! An `http::HeaderMap` is unordered, and for most purposes that is correct. It is not correct for
//! a suite whose job is to find differences between implementations: `Content-Type` before
//! `ETag` and the other way round are the same map and different bytes, and a client that parses
//! responses by position — several do — sees a different response. So this type stores a `Vec` of
//! pairs and its iteration order is the emission order. It is the *only* place in this workspace
//! that order is observable, deliberately: nothing in the pipeline may branch on it.
//!
//! # Why the body is `Bytes` and not a stream
//!
//! A value that can be asserted on has to be complete. A `WireResponse` is produced by draining,
//! so obtaining one is the act of reading the body to its end — which is also what makes the
//! trailer section reachable, since `rustfs-gateway-stream` hands trailers out only at
//! end-of-stream. A consumer that must not buffer works with `http::Response<Body>` directly and
//! never builds one of these.

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Response, StatusCode};
use rustfs_gateway_stream::{Body, PayloadRead, PayloadStream, StreamError, StreamMetrics, TrailingHeaders};

/// A header section in emission order.
///
/// A `Vec` of pairs rather than a `HeaderMap`, because the order is the point; see the module
/// documentation.
pub type OrderedHeaders = Vec<(HeaderName, HeaderValue)>;

/// One complete response, with its header order preserved.
#[derive(Clone, Debug)]
pub struct WireResponse {
    status: StatusCode,
    headers: OrderedHeaders,
    body: Bytes,
    trailers: OrderedHeaders,
}

impl WireResponse {
    /// The status line.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers, in the order they were emitted.
    #[must_use]
    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    /// The first value of a header, by lowercase name.
    ///
    /// `None` for a header that is absent and for one whose value is not valid UTF-8; the second
    /// case is reachable, because a header value is bytes.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.as_str() == name)
            .and_then(|(_, value)| value.to_str().ok())
    }

    /// Every value of a header, in order. A response may repeat one legitimately.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HeaderValue> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.as_str() == name)
            .map(|(_, value)| value)
    }

    /// The body bytes.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The trailer section, in the order it was emitted. Empty when there was none.
    #[must_use]
    pub fn trailers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.trailers
    }

    /// Takes the parts out.
    #[must_use]
    pub fn into_parts(self) -> (StatusCode, OrderedHeaders, Bytes, OrderedHeaders) {
        (self.status, self.headers, self.body, self.trailers)
    }
}

/// Drains a response into a [`WireResponse`].
///
/// # Errors
///
/// [`StreamError`] when the body could not be read to its end — a truncated body is an error and
/// never a short one, because a consumer cannot tell the difference after the fact.
pub async fn collect(response: Response<Body>) -> Result<WireResponse, StreamError> {
    let (parts, body) = response.into_parts();
    let (bytes, trailers) = drain(body).await?;
    Ok(WireResponse {
        status: parts.status,
        headers: ordered(&parts.headers),
        body: bytes,
        trailers: ordered(trailers.as_header_map()),
    })
}

/// A `HeaderMap` flattened into pairs.
///
/// `HeaderMap::iter` visits a repeated name once per value, which is what makes this a faithful
/// rendering of the wire rather than a rendering of the map's key set.
fn ordered(map: &HeaderMap) -> OrderedHeaders {
    map.iter().map(|(name, value)| (name.clone(), value.clone())).collect()
}

/// Reads a body to its end, in whichever shape it arrived.
async fn drain(body: Body) -> Result<(Bytes, TrailingHeaders), StreamError> {
    let payload = body.into_payload();
    // An in-memory payload needs no driver and no adaptation. Taking this branch first is what
    // keeps the ordinary case — every XML response this framework produces — free of the
    // adaptation cost the metrics below would otherwise record.
    if let Some(segments) = payload.try_as_vectored() {
        return Ok((concatenate(segments), TrailingHeaders::empty()));
    }
    let metrics = StreamMetrics::new();
    let (stream, _cost) = payload
        .try_into_stream(&metrics)
        .map_err(|(_payload, refusal)| StreamError::upstream(Box::new(refusal)))?;
    Drain {
        stream,
        collected: Vec::new(),
    }
    .await
}

/// Joins segments, avoiding the copy when there is nothing to join.
fn concatenate(segments: &[Bytes]) -> Bytes {
    match segments {
        [] => Bytes::new(),
        [only] => only.clone(),
        many => {
            let total = many.iter().map(Bytes::len).sum();
            let mut out = Vec::with_capacity(total);
            for segment in many {
                out.extend_from_slice(segment);
            }
            Bytes::from(out)
        }
    }
}

/// The future that polls a push-model body to end-of-stream.
///
/// Hand-written rather than built from a combinator because this crate forbids `unsafe` and every
/// field here is `Unpin` — `Pin<Box<dyn PayloadStream + Send>>` is `Unpin` by construction, which
/// is exactly why `rustfs-gateway-stream` boxes it pinned.
struct Drain {
    stream: rustfs_gateway_stream::BoxPayloadStream,
    collected: Vec<Bytes>,
}

impl core::future::Future for Drain {
    type Output = Result<(Bytes, TrailingHeaders), StreamError>;

    fn poll(self: core::pin::Pin<&mut Self>, context: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = self.get_mut();
        loop {
            match core::pin::Pin::new(&mut this.stream).poll_read(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(PayloadRead::Chunk(bytes))) => this.collected.push(bytes),
                Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                    let bytes = concatenate(&this.collected);
                    this.collected = Vec::new();
                    return Poll::Ready(Ok((bytes, trailers)));
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn response(body: Body) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header("x-amz-request-id", "one")
            .header("content-type", "application/xml")
            .body(body)
            .expect("a valid response")
    }

    /// Positive — the emission order survives, which is the entire reason this type exists.
    #[tokio::test]
    async fn the_header_order_is_preserved() {
        let collected = collect(response(Body::empty())).await.expect("an in-memory body");
        let names: Vec<&str> = collected.headers().iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["x-amz-request-id", "content-type"]);
    }

    /// Negative — a header that is absent is `None`, and a lookup does not fall back to a
    /// differently-cased spelling that the map would have matched.
    #[tokio::test]
    async fn a_missing_header_is_absent_rather_than_empty() {
        let collected = collect(response(Body::empty())).await.expect("an in-memory body");
        assert_eq!(collected.header("etag"), None);
        assert_eq!(collected.header("Content-Type"), None);
        assert_eq!(collected.header("content-type"), Some("application/xml"));
    }

    /// Negative — a body with no bytes drains to an empty value and never to a missing one, so a
    /// case asserting on an empty body has something to compare.
    #[tokio::test]
    async fn an_empty_body_drains_to_empty_bytes() {
        let collected = collect(response(Body::empty())).await.expect("an in-memory body");
        assert!(collected.body().is_empty());
        assert!(collected.trailers().is_empty());
    }

    /// Negative — segments are joined in order; a reversed or deduplicated join would be invisible
    /// to a length assertion alone.
    #[tokio::test]
    async fn segments_are_joined_in_order() {
        let body = Body::from_segments([Bytes::from_static(b"<Err"), Bytes::from_static(b"or/>")]);
        let collected = collect(response(body)).await.expect("an in-memory body");
        assert_eq!(collected.body().as_ref(), b"<Error/>");
    }

    /// Positive — the parts come back out, so a consumer that wants to own them does not have to
    /// clone the body.
    #[tokio::test]
    async fn the_parts_can_be_taken_out() {
        let collected = collect(response(Body::from_bytes(Bytes::from_static(b"ok"))))
            .await
            .expect("an in-memory body");
        let (status, headers, body, trailers) = collected.into_parts();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.len(), 2);
        assert_eq!(body.as_ref(), b"ok");
        assert!(trailers.is_empty());
    }
}
