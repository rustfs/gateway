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

//! Service state and read-only accessors for an assembled service.
//! Responsible for: the shared service state and its public inspection methods.
//! NOT responsible for: accepting requests or making pipeline decisions.
//! Upstream: `ServiceBuilder`. Downstream: `S3Service` and its host.

use super::*;

impl core::fmt::Debug for S3Service {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let snapshot = self.inner.config.load();
        f.debug_struct("S3Service")
            .field("operations", &snapshot.runtime().routing.dispatch.names().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl S3Service {
    /// The drain this assembly runs behind an answer that left an HTTP/1 request body unread.
    pub(crate) fn unread_body_drain(&self) -> Option<crate::UnreadBodyDrain> {
        self.inner.view_policy.unread_body_drain()
    }

    pub(crate) fn from_inner(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    /// The acceptance ceilings in force.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    /// Whether the service uses the system clock, a checked custom source, or an acknowledged one.
    #[must_use]
    pub fn clock_posture(&self) -> ClockPosture {
        self.inner.clock_posture
    }

    /// The credential-cache and pre-authentication per-client posture selected at assembly.
    #[must_use]
    pub fn security_posture(&self) -> SecurityPosture {
        self.inner.security_posture
    }

    /// Number of forbidden response bodies removed by this service's final invariant pass.
    #[must_use]
    pub fn response_body_corrections_total(&self) -> u64 {
        self.inner.response_body_corrections.load(Ordering::Relaxed)
    }

    /// Answers one request whose body is already in memory.
    ///
    /// The shape an in-process caller has, and the one the conformance runner uses: it builds a
    /// request from raw bytes and wants the response without a socket in between.
    pub async fn call_bytes(&self, request: Request<Bytes>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        self.call(Request::from_parts(parts, http_body_util::Full::new(body))).await
    }
}

pub(super) struct AuthorizedRoute {
    pub(super) policy: Arc<PolicySnapshot>,
    pub(super) config: RequestConfig<RouteAuthorized>,
    /// The index of the question that decided the route stage, which the input stage re-asks
    /// (ADR-0025, ADR-0026).
    pub(super) deciding: usize,
}

pub(super) struct ReadForDecode {
    pub(super) policy: Arc<PolicySnapshot>,
    pub(super) config: RequestConfig<Guarded>,
    pub(super) deciding: usize,
}

pub(super) struct RequestEntryContext {
    pub(super) now: RequestNow,
    pub(super) connection: TransportSecurity,
    pub(super) client_addr: Option<ClientAddr>,
}

pub(super) enum RoutedBody<B: http_body::Body> {
    Ordinary(SealedBody<B>),
    PostObject(Box<PostObjectPrelude<B>>),
}

pub(super) enum AcceptedBody<B: http_body::Body> {
    Ordinary(SealedBody<B>),
    PostObject(Box<ResolvedPostObject<B>>),
}

/// keys over HTTP.
/// What the transport said about this connection, or [`TransportSecurity::Plaintext`].
///
/// The **only** source. A transport that terminates TLS, or that is handed a connection by one
/// that did, inserts a `TransportSecurity` into the request's extensions:
///
/// ```
/// # use rustfs_gateway::TransportSecurity;
/// let mut request = http::Request::new(());
/// request.extensions_mut().insert(TransportSecurity::Encrypted);
/// ```
///
/// Extensions cannot be written from the wire, which is the property that makes this trustworthy
/// and `X-Forwarded-Proto` not. A deployment behind a TLS-terminating proxy that cannot be taught
/// to set the extension has one other option, and it is an explicit one:
/// `ServiceBuilder::sse_config` with
/// `rustfs_gateway_core::SseConfig::allowing_customer_keys_over_plaintext`, whose witness has to be
/// named in full.
///
/// Absent is cleartext. The alternative — assuming encryption when nobody said — is the failure
/// mode where a development deployment that was never given a transport quietly serves customer
/// keys over HTTP.
pub(super) fn connection_security(extensions: &http::Extensions) -> TransportSecurity {
    extensions
        .get::<TransportSecurity>()
        .copied()
        .unwrap_or(TransportSecurity::Plaintext)
}
