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

//! The typed, read-only request context a handler reaches through [`crate::Req::context`]
//! (ADR-0022).
//!
//! Responsible for: [`RequestContextView`] — what the pipeline verified and routed about one
//! request, owned so it can cross every await into a handler — and the values it hands out: the
//! authenticated [`RequestPrincipal`] with its [`AuthenticatedScheme`] and verified scope, the
//! routed [`Addressed`] target and its [`AddressingStyle`], a read-only header view, and the
//! explicitly named [`CallerSecretKey`].
//! NOT responsible for: deciding any of those facts. The verdict is `rustfs-gateway-sig`'s and the
//! facade authenticator's; the effective host, the raw target and the accepted header lines are
//! `rustfs-gateway-http`'s; the bucket and key are the facade's single normalisation. This file
//! copies their answers and derives nothing again. Nor for any s3s shape: `rustfs-gateway-types`'
//! `compat` module turns these values into an `s3s::S3Request` context.
//! Upstream: `rustfs-gateway-http` (the accepted request), `rustfs-gateway-sig` (the verdict).
//! Downstream: [`crate::Req`], and the facade pipeline that builds one context per request.
//!
//! # Why the header lines are owned, and still not a header map anyone can reach
//!
//! `Req<O>` is pipeline stage state and must be owned and `'static`, while the accepted request
//! lives on the facade's stack and is still read after the handler returns. So the context holds
//! its own copy of every accepted line, taken with `HeaderView::iter_raw` after both
//! authorization stages allowed the request. The copy is private: the only way to it is
//! [`RequestContextView::headers`], the same borrowed [`HeaderView`] every other layer reads, whose
//! values are shared references. There is no `&mut`, no owned map and no `into_` accessor, so the
//! rustfs/backlog#1752 ruling — no raw `HeaderMap` or `Extensions` on `Req` — holds: a handler
//! can read every line and rewrite none.
//!
//! # Why a principal needs a verdict
//!
//! [`RequestContextView::from_pipeline`] is the only constructor that attaches a principal, and it
//! takes the `rustfs_gateway_sig::Verdict` itself. An authenticated verdict cannot exist without a
//! constant-time `SignatureMatch` and an anonymous one without an `AnonymousAck`, and a rejected
//! one builds no context at all. So a context that names a principal names one some signature was
//! verified for, and the scope it reports is the one `enforce_scope` produced (ADR-0020).
//!
//! # Why the secret has its own name
//!
//! s3s's `Credentials` carries the caller's secret key beside the access key, and some RustFS
//! handlers read it (the admin API decrypts request bodies with it). So a handler may need it; but
//! most never do, and a value that is merely *there* ends up in a log line. The secret therefore
//! reaches a context only when the authenticator that looked it up was explicitly told to hand it
//! over *and* the routed operation opted in (ADR-0024), only for an authenticated verdict, only
//! through
//! [`RequestPrincipal::secret_key_from_authenticator_lookup`], and only as a [`CallerSecretKey`]:
//! zeroized on drop, no `Clone`, no `PartialEq`, a `Debug` that prints `<redacted>`.

use core::fmt;

use http::{HeaderMap, Method};
use rustfs_gateway_http::{HeaderView, WireRequest};
use rustfs_gateway_sig::{Identity, SecretBytes, SigFamily, SigIdentity, SigLocation, SigService, Verdict, VerifiedScope};
use rustfs_gateway_types::{BucketName, ObjectKey};

use crate::authz::Subject;
use crate::route::PathParams;

/// How the request named its bucket, as the facade's host resolver decided it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressingStyle {
    /// The bucket, if any, was the first path segment.
    Path,
    /// The host named the bucket.
    VirtualHosted {
        /// The region label the host carried, when it carried one. Not a verified region: the
        /// verified one is [`RequestContextView::verified_scope`]'s.
        host_region: Option<Box<str>>,
    },
}

impl AddressingStyle {
    /// The region label a virtual host carried, when there was one.
    #[must_use]
    pub fn host_region(&self) -> Option<&str> {
        match self {
            Self::VirtualHosted { host_region } => host_region.as_deref(),
            Self::Path => None,
        }
    }
}

/// The routed target: the addressing style, and the bucket and key the pipeline decided.
///
/// The values are the ones both authorization stages were asked about, so a handler that reads
/// them reads the resource that was allowed rather than a second parse of the path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addressed {
    /// Where the bucket came from.
    pub style: AddressingStyle,
    /// The bucket, when the request names one.
    pub bucket: Option<BucketName>,
    /// The object key, when the request names one. For a POST Object upload, the form's key.
    pub key: Option<ObjectKey>,
}

/// How an authenticated request was signed: the parts of the verdict's scheme a handler may
/// branch on, and never the session token the scheme carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticatedScheme {
    family: SigFamily,
    location: SigLocation,
    service: SigService,
    temporary: bool,
}

impl AuthenticatedScheme {
    /// Which algorithm family signed the request.
    #[must_use]
    pub const fn family(self) -> SigFamily {
        self.family
    }

    /// Where the signature was carried: header, presigned query or POST form.
    #[must_use]
    pub const fn location(self) -> SigLocation {
        self.location
    }

    /// The credential-scope service the routed operation was checked against.
    #[must_use]
    pub const fn service(self) -> SigService {
        self.service
    }

    /// Whether the credential was a temporary (session) one. The token itself is not here.
    #[must_use]
    pub const fn is_temporary(self) -> bool {
        self.temporary
    }
}

/// The caller's secret key, exactly as the authenticator's credential lookup returned it.
///
/// Zeroized on drop; no `Clone`, no `PartialEq`, and a `Debug` that prints `<redacted>`:
///
/// ```compile_fail,E0599
/// fn copy(secret: rustfs_gateway_core::CallerSecretKey) {
///     let _ = secret.clone(); // no Clone: a second copy of a secret is not a derive
/// }
/// ```
pub struct CallerSecretKey(SecretBytes);

impl CallerSecretKey {
    /// Borrows the secret bytes.
    ///
    /// The name is the warning: every call site is a place where key material leaves its
    /// container, and should head straight into the one computation that needs it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for CallerSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallerSecretKey(<redacted>)")
    }
}

/// Who an authenticated request runs as.
///
/// Only [`RequestContextView::from_pipeline`] builds one, from an authenticated verdict:
///
/// ```compile_fail,E0451
/// use rustfs_gateway_core::RequestPrincipal;
/// fn forge() -> RequestPrincipal {
///     RequestPrincipal { identity: todo!(), scheme: todo!(), scope: None, secret: None }
/// }
/// ```
pub struct RequestPrincipal {
    identity: Identity,
    scheme: AuthenticatedScheme,
    scope: Option<VerifiedScope>,
    secret: Option<CallerSecretKey>,
}

impl RequestPrincipal {
    /// The principal the signature was verified for, including any session binding.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The access key id the signature named. A public identifier.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        self.identity.access_key_id()
    }

    /// How the request was signed.
    #[must_use]
    pub const fn scheme(&self) -> AuthenticatedScheme {
        self.scheme
    }

    /// The credential scope the signature was verified under. `None` for SigV2 and custom schemes,
    /// never a configured default (ADR-0020).
    #[must_use]
    pub const fn verified_scope(&self) -> Option<&VerifiedScope> {
        self.scope.as_ref()
    }

    /// The caller's secret key, when the authenticator that looked it up was told to hand it over.
    ///
    /// `None` by default. It is `Some` only when two opt-ins agree: the deployment called the built-in
    /// `SigV4Authenticator`'s `hand_caller_secret_to_handlers` (or a custom authenticator attached
    /// it), and the routed operation's spec called
    /// [`crate::OperationSpec::hand_caller_secret_to_handler`] (ADR-0024). A handler that needs the
    /// secret — to open a payload the client sealed with it — reads it here and nowhere else
    /// (ADR-0022).
    #[must_use]
    pub const fn secret_key_from_authenticator_lookup(&self) -> Option<&CallerSecretKey> {
        self.secret.as_ref()
    }
}

impl fmt::Debug for RequestPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestPrincipal")
            .field("identity", &self.identity)
            .field("scheme", &self.scheme)
            .field("scope", &self.scope)
            .field("secret", &self.secret.as_ref().map_or("<not handed over>", |_| "<redacted>"))
            .finish()
    }
}

/// What the pipeline verified and routed about one request, as its handler may read it.
///
/// Read-only. The header lines are reachable only as a borrowed [`HeaderView`], so a value cannot
/// be rewritten through it:
///
/// ```compile_fail,E0594
/// use http::HeaderValue;
/// use rustfs_gateway_core::RequestContextView;
/// fn rewrite(context: &RequestContextView) {
///     for (_, value) in context.headers().iter_raw() {
///         *value = HeaderValue::from_static("rewritten"); // a shared reference: does not compile
///     }
/// }
/// ```
///
/// and a handler cannot reach the context mutably, or replace it:
///
/// ```compile_fail,E0599
/// use rustfs_gateway_core::Req;
/// use rustfs_gateway_types::dto::ListBuckets;
/// fn swap(request: &mut Req<ListBuckets>) {
///     let _ = request.context_mut();
/// }
/// ```
pub struct RequestContextView {
    operation: &'static str,
    method: Method,
    raw_path: Box<str>,
    raw_query: Box<str>,
    host: Box<str>,
    addressed: Addressed,
    headers: HeaderMap,
    principal: Option<RequestPrincipal>,
    path_params: PathParams,
    subject: Option<Subject>,
}

impl RequestContextView {
    /// Builds the context of one request the pipeline has accepted, routed and authenticated.
    ///
    /// Every fact is copied from the stage that decided it: the method, raw target, effective host
    /// and every accepted header line from `wire`; the principal, its scheme and its scope from
    /// `verdict`. `caller_secret` is attached only to an authenticated principal and dropped for
    /// an anonymous request.
    ///
    /// `None` for a rejected verdict, and for any verdict variant added later: a request nobody
    /// authenticated or confirmed anonymous has no context a handler could be handed.
    #[must_use]
    pub fn from_pipeline<B>(
        operation: &'static str,
        wire: &WireRequest<B>,
        addressed: Addressed,
        verdict: &Verdict,
        caller_secret: Option<SecretBytes>,
    ) -> Option<Self> {
        let principal = match verdict {
            Verdict::Authenticated {
                identity, scheme, scope, ..
            } => Some(RequestPrincipal {
                identity: identity.clone(),
                scheme: AuthenticatedScheme {
                    family: scheme.family,
                    location: scheme.location,
                    service: scheme.service,
                    temporary: matches!(scheme.identity, SigIdentity::Session { .. }),
                },
                scope: scope.clone(),
                secret: caller_secret.map(CallerSecretKey),
            }),
            Verdict::Anonymous(_) => None,
            _ => return None,
        };
        let mut headers = HeaderMap::new();
        for (name, value) in wire.headers().iter_raw() {
            headers.append(name.clone(), value.clone());
        }
        Some(Self {
            operation,
            method: wire.method().clone(),
            raw_path: Box::from(wire.raw_path().as_str()),
            raw_query: Box::from(wire.query().as_str()),
            host: Box::from(wire.host().as_str()),
            addressed,
            headers,
            principal,
            path_params: PathParams::none(),
            subject: None,
        })
    }

    /// This context, with the values the routed claimed row's template extracted (ADR-0024).
    ///
    /// The facade calls it once, with what `PathTemplate::extract` produced for the row that
    /// accepted the request; a context outside a claim keeps [`PathParams::none`].
    #[must_use]
    pub fn with_path_params(mut self, path_params: PathParams) -> Self {
        self.path_params = path_params;
        self
    }

    /// This context, with the subject both authorizer stages judged (ADR-0025). The facade calls
    /// it once, for an operation whose requirement declares a subject rule.
    #[must_use]
    pub fn with_subject(mut self, subject: Option<Subject>) -> Self {
        self.subject = subject;
        self
    }

    /// The context of a request built outside the pipeline, by [`crate::Req::new`] or a direct
    /// registry call.
    ///
    /// Anonymous, with no header line, no bucket and no key. The method is `GET` and the target
    /// `/` only because a context has to name some; nothing about a real request is known.
    #[must_use]
    pub fn detached(operation: &'static str) -> Self {
        Self {
            operation,
            method: Method::GET,
            raw_path: Box::from("/"),
            raw_query: Box::from(""),
            host: Box::from(""),
            addressed: Addressed {
                style: AddressingStyle::Path,
                bucket: None,
                key: None,
            },
            headers: HeaderMap::new(),
            principal: None,
            path_params: PathParams::none(),
            subject: None,
        }
    }

    /// The routed operation's name.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// The request method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// The request path exactly as it arrived, still percent-encoded.
    #[must_use]
    pub fn raw_path(&self) -> &str {
        &self.raw_path
    }

    /// The query exactly as it arrived, without its `?`; empty when there is none.
    #[must_use]
    pub fn raw_query(&self) -> &str {
        &self.raw_query
    }

    /// The effective host `rustfs-gateway-http` decided once at acceptance.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// How the request named its bucket.
    #[must_use]
    pub const fn addressing(&self) -> &AddressingStyle {
        &self.addressed.style
    }

    /// The bucket the pipeline routed and authorized, when there is one.
    #[must_use]
    pub const fn bucket(&self) -> Option<&BucketName> {
        self.addressed.bucket.as_ref()
    }

    /// The object key the pipeline routed and authorized, when there is one.
    #[must_use]
    pub const fn key(&self) -> Option<&ObjectKey> {
        self.addressed.key.as_ref()
    }

    /// Every accepted header line, read-only: [`HeaderView::iter_raw`] yields each one in map
    /// order with its value exactly as it arrived, unreadable unrelated values included.
    #[must_use]
    pub fn headers(&self) -> HeaderView<'_> {
        HeaderView::new(&self.headers)
    }

    /// The authenticated principal. `None` for an anonymous request.
    #[must_use]
    pub const fn principal(&self) -> Option<&RequestPrincipal> {
        self.principal.as_ref()
    }

    /// The credential scope the signature was verified under. `None` for an anonymous request and
    /// for an authenticated scheme that has no scope; an anonymous request cannot have one.
    #[must_use]
    pub fn verified_scope(&self) -> Option<&VerifiedScope> {
        self.principal.as_ref().and_then(RequestPrincipal::verified_scope)
    }

    /// Whether the request presented no credentials and was confirmed anonymous.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.principal.is_none()
    }

    /// The path parameters of the claimed row that accepted the request, decoded once and
    /// readable as typed values through [`PathParams::parse`]. Empty outside a claim (ADR-0024).
    #[must_use]
    pub const fn path_params(&self) -> &PathParams {
        &self.path_params
    }

    /// The account the request acts on, exactly as both authorizer stages were asked about it;
    /// `None` for an operation that declares no subject rule (ADR-0025). A handler acts on this
    /// value and never parses the query for it a second time.
    #[must_use]
    pub const fn subject(&self) -> Option<&Subject> {
        self.subject.as_ref()
    }
}

/// Prints the header names only: a value may be a signature, a session token or an SSE-C key.
struct HeaderNames<'a>(&'a HeaderMap);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

impl fmt::Debug for RequestContextView {
    /// Hand-written and audit-shaped. No header value and no query is printed, because a presigned
    /// query carries a signature and a session token, and a header may carry either or an SSE-C
    /// key; the principal prints its access key id and redacts any secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestContextView")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("raw_path", &self.raw_path)
            .field("raw_query_bytes", &self.raw_query.len())
            .field("host", &self.host)
            .field("addressed", &self.addressed)
            .field("header_names", &HeaderNames(&self.headers))
            .field("principal", &self.principal)
            .field("path_params", &self.path_params)
            .field("subject", &self.subject)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests;
