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

//! The first stage of the pipeline, and the last place a raw HTTP request exists.
//!
//! Responsible for: [`WireRequest::accept`] — consuming an [`http::Request`], applying every
//! acceptance rule in a fixed order, and producing the disambiguated view everything downstream
//! reads.
//! NOT responsible for: routing, authentication, decoding, or anything that needs a body byte.
//! Acceptance never reads the body; every rule here is decidable from the head.
//! Upstream: `http`, and this crate's `framing`, `header_view`, `host`, `limits`, `query_view`.
//! Downstream: `rustfs-gateway-sig` and `rustfs-gateway-core`, which see a [`WireRequest`] and never an
//! [`http::Request`].
//!
//! # The boundary this file draws
//!
//! [`WireRequest`] owns the request head but publishes no way to get it back. There is no
//! accessor returning [`http::HeaderMap`], [`http::Uri`] or [`http::Request`]; the only way out
//! is [`WireRequest::into_body`], which yields the body alone. That is what makes "this request
//! was accepted" a fact a type carries rather than a convention a reviewer has to check: a layer
//! above cannot re-derive the host, cannot re-read the `Host` header, and cannot rediscover the
//! ambiguity that acceptance has already refused.
//!
//! # Order of checks
//!
//! Request target, then framing, then host, then headers, then query. The order is deliberate and
//! observable — a request that is malformed in two ways is reported by the first rule in this
//! list. Framing comes before everything else that can fail, because "where does this body end"
//! is the question whose wrong answer creates a second, unauthenticated request; being told that
//! a header is duplicated first would bury it.

use http::{HeaderMap, Method, Request, Uri, Version};

use crate::framing::Framing;
use crate::header_view::{self, HeaderView};
use crate::host::{EffectiveHost, effective_host_of};
use crate::limits::{LimitKind, Limits};
use crate::query_view::{QueryIndex, QueryView};
use crate::reject::WireReject;
use crate::text::contains_forbidden_control;
use crate::transport_extensions::TransportExtensions;

/// The request path exactly as it arrived, still percent-encoded.
///
/// There is no `decode` method here on purpose. A path is decoded exactly once, by the router, on
/// its way to becoming an object key; a path that can be decoded anywhere can be decoded twice,
/// and a doubly decoded `%252e%252e` is a traversal that no single-decode check would have seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPath<'a> {
    raw: &'a str,
}

impl<'a> RawPath<'a> {
    /// The undecoded path.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.raw
    }

    /// The undecoded path as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw.as_bytes()
    }

    /// Whether the path is the service root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.raw == "/"
    }
}

/// An accepted request: every wire-level ambiguity already refused.
///
/// Generic over the body so this crate stays independent of any one server implementation. The
/// head is owned and carries no lifetime — a stage that borrowed its request head would become
/// self-referential the moment it held a body across an await point.
#[derive(Debug)]
pub struct WireRequest<B> {
    method: Method,
    version: Version,
    uri: Uri,
    headers: HeaderMap,
    transport_extensions: TransportExtensions,
    host: EffectiveHost,
    framing: Framing,
    query_index: QueryIndex,
    body: B,
}

impl<B> WireRequest<B> {
    /// Accepts a request, or refuses it.
    ///
    /// Takes the request by value: after this call the raw request no longer exists, which is the
    /// point. No body byte is read, and on every error path the caller must answer
    /// [`WireReject::to_status`] and close the connection without draining.
    ///
    /// # Errors
    ///
    /// [`WireReject`], in the order documented at the top of this module.
    pub fn accept(request: Request<B>, limits: &Limits) -> Result<Self, WireReject> {
        let (parts, body) = request.into_parts();

        let path_and_query = parts.uri.path_and_query().ok_or(WireReject::MalformedRequestTarget)?;
        if path_and_query.as_str().len() > limits.max_uri_bytes {
            return Err(WireReject::LimitExceeded(LimitKind::UriBytes));
        }
        let path = path_and_query.path();
        // Origin-form and absolute-form are the two shapes this gateway serves. An asterisk-form
        // or authority-form target has no path to route on, and answering one at all would mean
        // inventing a path the client never sent.
        if !path.starts_with('/') || contains_forbidden_control(path.as_bytes()) {
            return Err(WireReject::MalformedRequestTarget);
        }

        let framing = Framing::classify(parts.version, &parts.headers, limits)?;

        let host = effective_host_of(&parts.uri, &parts.headers)?;
        if host.raw_for_signing().as_bytes().len() > limits.max_host_bytes {
            return Err(WireReject::LimitExceeded(LimitKind::HostBytes));
        }

        header_view::validate(&parts.headers, limits)?;

        let query_index = QueryIndex::parse(path_and_query.query().unwrap_or(""), limits)?;

        Ok(Self {
            method: parts.method,
            version: parts.version,
            uri: parts.uri,
            headers: parts.headers,
            transport_extensions: TransportExtensions::from_extensions(parts.extensions),
            host,
            framing,
            query_index,
            body,
        })
    }

    /// The request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The HTTP version the request arrived on.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// The undecoded path.
    #[must_use]
    pub fn raw_path(&self) -> RawPath<'_> {
        RawPath { raw: self.uri.path() }
    }

    /// The query parameters, indexed at acceptance and read without allocating.
    #[must_use]
    pub fn query(&self) -> QueryView<'_> {
        QueryView::new(self.uri.query().unwrap_or(""), &self.query_index)
    }

    /// The headers, as a borrowed view.
    ///
    /// This is the only header access layers above have. The underlying map is not reachable.
    #[must_use]
    pub fn headers(&self) -> HeaderView<'_> {
        HeaderView::new(&self.headers)
    }

    /// The transport-installed values, retained as a typed read-only view.
    #[must_use]
    pub fn transport_extensions(&self) -> &TransportExtensions {
        &self.transport_extensions
    }

    /// The one effective host, determined once at acceptance.
    #[must_use]
    pub fn host(&self) -> &EffectiveHost {
        &self.host
    }

    /// The request target's scheme, exactly as the transport handed it over: present for an
    /// absolute-form HTTP/1.1 target and for an HTTP/2 request (its `:scheme`), absent for an
    /// origin-form target.
    ///
    /// A fact for a handler that must rebuild the target it was sent (rustfs/gateway#1148); nothing
    /// in this gateway routes, signs or authorizes by it — [`Self::host`] is the host that does.
    #[must_use]
    pub fn target_scheme(&self) -> Option<&str> {
        self.uri.scheme_str()
    }

    /// The request target's authority, exactly as the transport handed it over: present for an
    /// absolute-form HTTP/1.1 target and for an HTTP/2 request with `:authority`, absent for an
    /// origin-form target. Read-only, for the reason [`Self::target_scheme`] is.
    #[must_use]
    pub fn target_authority(&self) -> Option<&str> {
        self.uri.authority().map(http::uri::Authority::as_str)
    }

    /// Where HTTP says the body ends.
    #[must_use]
    pub fn framing(&self) -> &Framing {
        &self.framing
    }

    /// The body, still unread and unverified.
    #[must_use]
    pub fn body(&self) -> &B {
        &self.body
    }

    /// The body, mutably.
    pub fn body_mut(&mut self) -> &mut B {
        &mut self.body
    }

    /// Consumes the request and yields the body.
    ///
    /// The only way out of this type, and it deliberately yields the body alone: there is no
    /// `into_parts` returning the head, because a head that can be handed back can be re-parsed
    /// by a layer that does not know what was already refused.
    #[must_use]
    pub fn into_body(self) -> B {
        self.body
    }

    /// Replaces the body, keeping the accepted head.
    ///
    /// The path from "the transport's body" to "a decoded body" without re-accepting the request.
    #[must_use]
    pub fn map_body<C, F>(self, transform: F) -> WireRequest<C>
    where
        F: FnOnce(B) -> C,
    {
        WireRequest {
            method: self.method,
            version: self.version,
            uri: self.uri,
            headers: self.headers,
            transport_extensions: self.transport_extensions,
            host: self.host,
            framing: self.framing,
            query_index: self.query_index,
            body: transform(self.body),
        }
    }
}
