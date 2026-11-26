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

    /// The shared concurrency semaphore bounding background unread-body drain tasks.
    pub(crate) fn unread_body_drain_permits(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.inner.unread_body_drain_permits.as_ref().map(Arc::clone)
    }

    pub(crate) fn from_inner(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    /// Updates the preliminary body digest obligation when STS or S3 Vectors authentication
    /// verified the signature over the body's actual SHA-256 digest.
    pub(crate) fn settle_body_digest(
        &self,
        mode: RequestBodyMode,
        current: BodyDigestObligation,
        question: &crate::ext::Authentication<'_>,
    ) -> BodyDigestObligation {
        self.inner.view_policy.bodyless_digest.settle(mode, current, question)
    }

    /// Resolves an operation's versioned authorization requirement and `versionId` query value,
    /// refusing invalid UTF-8 `versionId` values before authorization runs (GHSA-3ppv).
    pub(super) fn resolve_version_requirement<'a>(
        &self,
        operation: &'static str,
        requirement: rustfs_gateway_core::AuthRequirement,
        meta: &'a MetaView<'a>,
    ) -> Result<(rustfs_gateway_core::AuthRequirement, Option<std::borrow::Cow<'a, str>>), rustfs_gateway_core::CodecError> {
        let named_version = if requirement.version_requirement().is_some() {
            meta.query("versionId").map_err(|error| error.about("VersionId"))?
        } else {
            None
        };
        let requirement = requirement
            .for_version(named_version.is_some() && self.inner.view_policy.version_actions.asks_version_action(operation));
        Ok((requirement, named_version))
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

impl<B: http_body::Body> RoutedBody<B> {
    pub(super) fn post_filename(&self) -> Option<&str> {
        match self {
            Self::PostObject(prelude) => prelude.file_name(),
            Self::Ordinary(_) => None,
        }
    }
}

pub(super) enum AcceptedBody<B: http_body::Body> {
    Ordinary(SealedBody<B>),
    PostObject(Box<ResolvedPostObject<B>>),
}

impl<B: http_body::Body> AcceptedBody<B> {
    /// Whether this is a POST Object form, whose SSE members may be form fields.
    pub(super) const fn is_post(&self) -> bool {
        matches!(self, Self::PostObject(_))
    }

    pub(super) fn post_key_constraints(
        &self,
        verdict: &rustfs_gateway_sig::Verdict,
    ) -> Option<rustfs_gateway_sig::post_policy::PostKeyConstraints> {
        let rustfs_gateway_sig::Verdict::Authenticated { scheme, .. } = verdict else {
            return None;
        };
        if scheme.location != rustfs_gateway_sig::SigLocation::FormField {
            return None;
        }
        match self {
            Self::PostObject(post) => post.key_constraints(scheme.family).cloned(),
            Self::Ordinary(_) => None,
        }
    }
}

/// What the transport said about this connection, or [`TransportSecurity::Plaintext`].
///
/// Two transport-owned extension types carry encryption facts: a host's explicit
/// [`TransportSecurity::Encrypted`] (for example when TLS was terminated upstream) and, when the
/// `server` feature is enabled, `rustfs_gateway_server::ConnectionInfo` reporting a completed TLS
/// handshake. Either marks the connection encrypted, matching [`crate::ClientFacts::observed`].
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
pub(crate) fn connection_security(extensions: &http::Extensions) -> TransportSecurity {
    if extensions.get::<TransportSecurity>().copied() == Some(TransportSecurity::Encrypted) {
        return TransportSecurity::Encrypted;
    }
    #[cfg(feature = "server")]
    if extensions
        .get::<rustfs_gateway_server::ConnectionInfo>()
        .is_some_and(|connection| connection.transport() == rustfs_gateway_server::TransportKind::Tls)
    {
        return TransportSecurity::Encrypted;
    }
    TransportSecurity::Plaintext
}
