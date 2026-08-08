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

//! The middle level of the three: mutable interception between the pipeline's stages.
//!
//! Responsible for: [`StageFilter`] and its three seams, the views each seam is handed
//! ([`WireHead`], [`RoutedView`], [`ResponseView`]), the closed set of head fields a filter may
//! **not** rewrite ([`FrozenHeader`]), and the three closure adapters.
//! NOT responsible for: calling them — the seams live in `crate::service`, which is the one file
//! that knows where a stage ends; deciding any protocol behaviour; or per-operation middleware,
//! which is [`crate::OpLayer`] one level in.
//! Upstream: `crate::render::S3Error`, `rustfs-gateway-core`. Downstream: `crate::builder`,
//! `crate::service`.
//!
//! # Which level absorbs which requirement
//!
//! `docs/middleware.md` is the decision tree and the table of the nine tower patch layers RustFS
//! carries today. In one sentence: a connection-level concern with no S3 semantics is a tower
//! [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) outside the whole service; a
//! rewrite of the HTTP shape or of a finished response is a [`StageFilter`]; a rewrite of one
//! operation's typed input or output is an [`crate::OpLayer`]; and pure observation is a
//! [`crate::Observer`].
//!
//! # Why every method is synchronous
//!
//! [`StageFilter::on_wire`] and [`StageFilter::on_routed`] both run **before** authentication. An
//! asynchronous seam there is an invitation to read a store — "look the bucket's configuration up
//! first" — and an unauthenticated request that drives a storage read is two things at once: an
//! amplifier, and a private-bucket enumeration oracle, because "does this bucket exist" becomes
//! answerable by timing. This is the same rule that makes [`crate::HostResolver`] synchronous, and
//! `scripts/check_stage_filter_sync.sh` enforces it over the source rather than in prose.
//!
//! [`StageFilter::on_response`] is synchronous for a different reason: it runs on the response path
//! of a request that is already finished, so awaiting there adds latency the request cannot use.
//!
//! # What a filter may do, and the four things it may not
//!
//! It may **observe**, it may **rewrite**, and it may **refuse** — an `Err` is rendered by the one
//! renderer every other refusal goes through, and the pipeline stops. What it may not do:
//!
//! 1. **It may not answer.** There is no `Ok(Response)` arm. A seam that could return a success
//!    would be able to serve object bytes from in front of the security floor, which is the
//!    structural shape of rustfs/rustfs#4845 — a route that bypassed the access check entirely.
//!    A filter can end a request, and the only way it can end one is with an error.
//! 2. **It may not affect a signature.** The material the verifier reads is snapshotted at the
//!    entry to the pipeline, before the first filter runs, so a rewrite of `Authorization`,
//!    `x-amz-date`, `x-amz-content-sha256` or any signed header changes nothing about the verdict —
//!    in *either* direction. The one exception is the `Host` header, whose effective form is
//!    derived from the head *after* this seam, and which is therefore refused outright: see
//!    [`FrozenHeader`].
//! 3. **It may not choose the target.** [`RoutedView`] hands out `&`-only accessors and no
//!    mutable one, so the bucket and the key have exactly one producer — `MetaView`'s single
//!    normalisation — and a filter has nothing to write them with.
//! 4. **It may not defeat a response invariant.** The RFC 9110 body rules and the four framework
//!    headers are applied *after* [`StageFilter::on_response`], so a filter cannot put content on
//!    a `304`, cannot leave a `Content-Length` that overstates its body, and cannot remove the
//!    request identifier from a response.
//!
//! # Order
//!
//! Registration order, at every seam, including the response seam — the first filter registered is
//! the first to see the head **and** the first to see the response. A later filter sees an earlier
//! one's rewrite, because all three seams operate on one value in sequence. The reversed
//! registration produces the reversed order, which is what makes this a contract rather than an
//! implementation detail.

use http::{HeaderName, HeaderValue, Method, Response, Version};
use rustfs_gateway_core::{OperationSpec, TargetKind};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{BucketName, ErrorCode, ObjectKey};

use crate::render::S3Error;
use crate::trace::RequestId;

/// The header fields a [`StageFilter::on_wire`] may not write, lowercase.
///
/// Exactly one, and it earns its place by a property no other header has: the effective host is
/// computed from the head **after** this seam and then feeds the canonical request, so a filter
/// that could rewrite it would be able to change a signature's input. Every other header is
/// rewritable precisely because it cannot: the verifier reads a snapshot taken before the first
/// filter ran.
///
/// A longer list would be worse, not better. Freezing `Authorization` here would suggest that
/// freezing it is what stops a forgery, and the day the snapshot moved, the list would still be
/// green.
pub const FROZEN_WIRE_HEADERS: &[&str] = &["host"];

/// A write a [`StageFilter::on_wire`] is not allowed to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenHeader {
    name: HeaderName,
}

impl FrozenHeader {
    /// The header that was refused.
    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }
}

impl core::fmt::Display for FrozenHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the {} header is frozen at the wire seam: the effective host is derived from the head after this seam and feeds \
             the canonical request, so rewriting it would change a signature's input",
            self.name
        )
    }
}

impl std::error::Error for FrozenHeader {}

impl From<FrozenHeader> for S3Error {
    /// A refused write becomes a `500`, not a `400`: the caller did nothing wrong, the deployment's
    /// filter asked for something the framework does not permit.
    fn from(_refusal: FrozenHeader) -> Self {
        // The header name stays out of the response. Nothing a caller sends reaches this path, but
        // the rule about what an error body may echo does not have exceptions for that.
        Self::new(ErrorCode::INTERNAL_ERROR, "this deployment's request filter is misconfigured").closing(
            // The refusal is about the deployment's own code and the request is otherwise fine, so
            // nothing about the connection changes.
            crate::close::ConnectionIntent::MayKeepAlive,
        )
    }
}

/// The request head, before acceptance, mutable within the rules above.
///
/// The seam sits **before** [`rustfs_gateway_http::WireRequest::accept`] on purpose: whatever a
/// filter writes is then subject to every acceptance rule — the `Content-Length`/`Transfer-Encoding`
/// conflict, the duplicate-header rules, the limits — exactly as a client's own bytes are. A seam
/// placed after acceptance would either hand out a head that is already sealed (which is the
/// boundary `WireRequest` exists to draw) or require a second acceptance pass over filter-modified
/// input, and "the front end and the back end parsed different bytes" is the whole of request
/// smuggling.
///
/// There is no accessor for the request target and no way to change the method. Both feed the
/// canonical request, and unlike the `Host` header they are not reachable from here at all, so
/// there is nothing to freeze.
#[derive(Debug)]
pub struct WireHead<'a> {
    parts: &'a mut http::request::Parts,
}

impl<'a> WireHead<'a> {
    /// Wraps a head for the duration of one seam. Crate-private: a filter is handed one, never
    /// makes one.
    pub(crate) fn new(parts: &'a mut http::request::Parts) -> Self {
        Self { parts }
    }

    /// The request method. Read-only: it is part of the canonical request.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.parts.method
    }

    /// The HTTP version the request arrived on.
    #[must_use]
    pub fn version(&self) -> Version {
        self.parts.version
    }

    /// The request path, still percent-encoded. Read-only, for the reason [`WireHead`] gives.
    #[must_use]
    pub fn path(&self) -> &str {
        self.parts.uri.path()
    }

    /// The query string, without the `?`. Read-only.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.parts.uri.query()
    }

    /// The first value of a header, when it has one.
    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.parts.headers.get(name)
    }

    /// How many times a header appears. A filter that is compensating for a client's framing needs
    /// to be able to tell "absent" from "present twice".
    #[must_use]
    pub fn header_count(&self, name: &HeaderName) -> usize {
        self.parts.headers.get_all(name).iter().count()
    }

    /// Sets a header, replacing every existing value.
    ///
    /// # Errors
    ///
    /// [`FrozenHeader`] for a name in [`FROZEN_WIRE_HEADERS`].
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<(), FrozenHeader> {
        Self::allowed(&name)?;
        self.parts.headers.insert(name, value);
        Ok(())
    }

    /// Removes every value of a header.
    ///
    /// # Errors
    ///
    /// [`FrozenHeader`] for a name in [`FROZEN_WIRE_HEADERS`].
    pub fn remove_header(&mut self, name: &HeaderName) -> Result<(), FrozenHeader> {
        Self::allowed(name)?;
        self.parts.headers.remove(name);
        Ok(())
    }

    /// The frozen check, in one place so that the two writers cannot disagree about the set.
    fn allowed(name: &HeaderName) -> Result<(), FrozenHeader> {
        if FROZEN_WIRE_HEADERS.contains(&name.as_str()) {
            return Err(FrozenHeader { name: name.clone() });
        }
        Ok(())
    }
}

/// What a routed request is, to a filter: read-only, and complete.
///
/// Every accessor returns a shared reference or a `Copy` value. There is deliberately no mutable
/// one — see rule 3 in the module documentation. The bucket and the key are the ones
/// `MetaView::addressed_with` produced, which is the single normalisation the whole pipeline shares.
#[derive(Debug)]
pub struct RoutedView<'a> {
    pub(crate) operation: &'static str,
    pub(crate) spec: &'a OperationSpec,
    pub(crate) method: &'a Method,
    pub(crate) path: &'a str,
    pub(crate) target: TargetKind,
    pub(crate) bucket: Option<&'a BucketName>,
    pub(crate) key: Option<&'a ObjectKey>,
    pub(crate) declared_body_bytes: Option<u64>,
}

impl RoutedView<'_> {
    /// The operation routing chose.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// What the operation declares about itself.
    #[must_use]
    pub const fn spec(&self) -> &OperationSpec {
        self.spec
    }

    /// The request method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        self.method
    }

    /// The request path, still percent-encoded.
    #[must_use]
    pub const fn path(&self) -> &str {
        self.path
    }

    /// What the path addresses.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// The bucket, from the one place a bucket is produced.
    #[must_use]
    pub const fn bucket(&self) -> Option<&BucketName> {
        self.bucket
    }

    /// The object key, from the one place a key is produced.
    #[must_use]
    pub const fn key(&self) -> Option<&ObjectKey> {
        self.key
    }

    /// The body length the head announced, when it announced one.
    #[must_use]
    pub const fn declared_body_bytes(&self) -> Option<u64> {
        self.declared_body_bytes
    }
}

/// What a response is about, to a filter.
///
/// The response itself arrives beside this as `&mut`; this carries the context a rewrite needs and
/// that the response cannot state — which operation produced it, and which method asked.
#[derive(Debug)]
pub struct ResponseView<'a> {
    pub(crate) request_id: &'a RequestId,
    pub(crate) operation: Option<&'static str>,
    pub(crate) method: &'a Method,
}

impl ResponseView<'_> {
    /// The identifier this request was answered with.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        self.request_id
    }

    /// The operation, when routing chose one. `None` for every request refused before routing —
    /// which is most of what a compatibility rewrite is about.
    #[must_use]
    pub const fn operation(&self) -> Option<&'static str> {
        self.operation
    }

    /// The method the request used. The RFC 9110 body rules are stated over it, and a filter that
    /// wants to know whether its rewrite will survive them needs it.
    #[must_use]
    pub const fn method(&self) -> &Method {
        self.method
    }
}

/// Mutable interception between the pipeline's stages.
///
/// Every method is synchronous and every method has a default, so an implementation states only
/// the seam it cares about. Held as `Arc<dyn StageFilter>`, so the assembled service stays
/// non-generic over it.
///
/// **This is the level for a rewrite that does not need a typed input.** If you only want to
/// observe, use [`crate::Observer`]; if you want one operation's DTO, use [`crate::OpLayer`].
pub trait StageFilter: Send + Sync + 'static {
    /// Before acceptance: the head as it arrived, mutable except for [`FROZEN_WIRE_HEADERS`].
    ///
    /// Runs before authentication, before routing, and before a single body byte is read.
    ///
    /// # Errors
    ///
    /// Any [`S3Error`]. It is rendered by the one renderer and the pipeline stops.
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), S3Error> {
        Ok(())
    }

    /// After routing and after the single normalisation, still before the governor, the security
    /// floor and the body.
    ///
    /// Read-only by design: the operation and the target are decided, and this seam exists to
    /// refuse or to record, never to redirect.
    ///
    /// # Errors
    ///
    /// Any [`S3Error`]. It is rendered by the one renderer and the pipeline stops.
    fn on_routed(&self, _routed: &RoutedView<'_>) -> Result<(), S3Error> {
        Ok(())
    }

    /// After the answer — or the refusal — has been built, and before the RFC 9110 body invariants
    /// and the four framework headers are applied.
    ///
    /// Runs for **every** response, including one refused at acceptance.
    ///
    /// # Errors
    ///
    /// Any [`S3Error`]. The response is replaced by the rendered refusal and no later filter runs.
    fn on_response(&self, _view: &ResponseView<'_>, _response: &mut Response<Body>) -> Result<(), S3Error> {
        Ok(())
    }
}

impl<T: StageFilter + ?Sized> StageFilter for std::sync::Arc<T> {
    fn on_wire(&self, head: &mut WireHead<'_>) -> Result<(), S3Error> {
        (**self).on_wire(head)
    }

    fn on_routed(&self, routed: &RoutedView<'_>) -> Result<(), S3Error> {
        (**self).on_routed(routed)
    }

    fn on_response(&self, view: &ResponseView<'_>, response: &mut Response<Body>) -> Result<(), S3Error> {
        (**self).on_response(view, response)
    }
}

/// A filter that implements only [`StageFilter::on_wire`].
///
/// ADR-0002's consequence: an extension point is not complete until a caller can supply one
/// function without declaring a struct for it.
pub fn wire_filter<F>(f: F) -> impl StageFilter
where
    F: Fn(&mut WireHead<'_>) -> Result<(), S3Error> + Send + Sync + 'static,
{
    struct WireOnly<F>(F);

    impl<F> StageFilter for WireOnly<F>
    where
        F: Fn(&mut WireHead<'_>) -> Result<(), S3Error> + Send + Sync + 'static,
    {
        fn on_wire(&self, head: &mut WireHead<'_>) -> Result<(), S3Error> {
            (self.0)(head)
        }
    }

    WireOnly(f)
}

/// A filter that implements only [`StageFilter::on_routed`].
pub fn routed_filter<F>(f: F) -> impl StageFilter
where
    F: Fn(&RoutedView<'_>) -> Result<(), S3Error> + Send + Sync + 'static,
{
    struct RoutedOnly<F>(F);

    impl<F> StageFilter for RoutedOnly<F>
    where
        F: Fn(&RoutedView<'_>) -> Result<(), S3Error> + Send + Sync + 'static,
    {
        fn on_routed(&self, routed: &RoutedView<'_>) -> Result<(), S3Error> {
            (self.0)(routed)
        }
    }

    RoutedOnly(f)
}

/// A filter that implements only [`StageFilter::on_response`].
pub fn response_filter<F>(f: F) -> impl StageFilter
where
    F: Fn(&ResponseView<'_>, &mut Response<Body>) -> Result<(), S3Error> + Send + Sync + 'static,
{
    struct ResponseOnly<F>(F);

    impl<F> StageFilter for ResponseOnly<F>
    where
        F: Fn(&ResponseView<'_>, &mut Response<Body>) -> Result<(), S3Error> + Send + Sync + 'static,
    {
        fn on_response(&self, view: &ResponseView<'_>, response: &mut Response<Body>) -> Result<(), S3Error> {
            (self.0)(view, response)
        }
    }

    ResponseOnly(f)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http::header::HOST;

    fn head() -> http::request::Parts {
        http::Request::builder()
            .method(http::Method::PUT)
            .uri("/bucket/key?versionId=7")
            .header("host", "s3.example.com")
            .header("x-amz-meta-a", "one")
            .body(())
            .expect("a valid request")
            .into_parts()
            .0
    }

    /// Negative — the `Host` header cannot be written, and the refusal names it. Every other
    /// header can, so the frozen set is a decision rather than a blanket.
    #[test]
    fn the_host_header_is_frozen_and_nothing_else_is() {
        let mut parts = head();
        let mut view = WireHead::new(&mut parts);
        let refused = view
            .set_header(HOST, HeaderValue::from_static("elsewhere"))
            .expect_err("the host is frozen");
        assert_eq!(refused.name(), &HOST);
        assert!(refused.to_string().contains("canonical request"), "{refused}");
        view.set_header(HeaderName::from_static("x-amz-meta-a"), HeaderValue::from_static("two"))
            .expect("an ordinary header");
        assert_eq!(parts.headers.get("x-amz-meta-a").map(HeaderValue::as_bytes), Some(&b"two"[..]));
        assert_eq!(parts.headers.get(HOST).map(HeaderValue::as_bytes), Some(&b"s3.example.com"[..]));
    }

    /// Negative — removal is subject to the same rule. A filter that could not *set* `Host` but
    /// could *delete* it would reach the same outcome by the other door.
    #[test]
    fn the_host_header_cannot_be_removed_either() {
        let mut parts = head();
        let mut view = WireHead::new(&mut parts);
        assert!(view.remove_header(&HOST).is_err());
        view.remove_header(&HeaderName::from_static("x-amz-meta-a"))
            .expect("an ordinary header");
        assert!(parts.headers.get(HOST).is_some());
        assert!(parts.headers.get("x-amz-meta-a").is_none());
    }

    /// Negative — the head publishes no way to change the method or the request target, both of
    /// which are canonical-request inputs. Asserted by reading what a filter can see: the values
    /// are unchanged after a filter has done everything the type allows.
    #[test]
    fn the_method_and_the_target_are_not_writable() {
        let mut parts = head();
        {
            let mut view = WireHead::new(&mut parts);
            assert_eq!(view.method(), http::Method::PUT);
            assert_eq!(view.path(), "/bucket/key");
            assert_eq!(view.query(), Some("versionId=7"));
            view.set_header(HeaderName::from_static("x-added"), HeaderValue::from_static("1"))
                .expect("an ordinary header");
        }
        assert_eq!(parts.method, http::Method::PUT);
        assert_eq!(parts.uri.path(), "/bucket/key");
        assert_eq!(parts.uri.query(), Some("versionId=7"));
    }

    /// Negative — a header that appears twice is counted twice, and a `set` collapses it to one.
    /// A filter compensating for a client's framing has to be able to tell those apart.
    #[test]
    fn a_repeated_header_is_counted_and_then_collapsed() {
        let mut parts = http::Request::builder()
            .uri("/")
            .header("x-amz-meta-a", "one")
            .header("x-amz-meta-a", "two")
            .body(())
            .expect("a valid request")
            .into_parts()
            .0;
        let name = HeaderName::from_static("x-amz-meta-a");
        let mut view = WireHead::new(&mut parts);
        assert_eq!(view.header_count(&name), 2);
        view.set_header(name.clone(), HeaderValue::from_static("three"))
            .expect("an ordinary header");
        assert_eq!(view.header_count(&name), 1);
    }

    /// Negative — every method of the trait defaults to doing nothing, so a filter that implements
    /// one seam is inert at the other two.
    #[test]
    fn the_defaults_do_nothing() {
        struct Nothing;
        impl StageFilter for Nothing {}

        let mut parts = head();
        let filter: std::sync::Arc<dyn StageFilter> = std::sync::Arc::new(Nothing);
        assert!(filter.on_wire(&mut WireHead::new(&mut parts)).is_ok());
        let mut response = Response::new(Body::empty());
        let view = ResponseView {
            request_id: &RequestId::from_bits(1),
            operation: None,
            method: &Method::GET,
        };
        assert!(filter.on_response(&view, &mut response).is_ok());
        assert!(response.body().is_empty());
    }

    /// Positive — the closure adapters produce a filter that runs at its own seam and nowhere else.
    #[test]
    fn a_closure_adapter_fills_exactly_one_seam() {
        let filter = wire_filter(|head: &mut WireHead<'_>| {
            head.set_header(HeaderName::from_static("x-seen"), HeaderValue::from_static("1"))?;
            Ok(())
        });
        let mut parts = head();
        filter.on_wire(&mut WireHead::new(&mut parts)).expect("the seam ran");
        assert!(parts.headers.get("x-seen").is_some());

        let mut response = Response::new(Body::empty());
        let view = ResponseView {
            request_id: &RequestId::from_bits(2),
            operation: Some("example:Ping"),
            method: &Method::GET,
        };
        filter.on_response(&view, &mut response).expect("the default seam");
        assert!(response.headers().is_empty());
    }
}
