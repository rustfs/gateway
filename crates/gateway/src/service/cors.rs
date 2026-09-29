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

//! The pipeline's CORS stage: the preflight branch and the decoration an ordinary response gets.
//!
//! Responsible for: answering a preflight from the bucket's stored document through the mandatory
//! cache (`serve_preflight`), the one refusal it can give, which bucket a preflight addresses, and
//! the headers an ordinary response carries once authorisation was granted (`actual_cors`).
//! NOT responsible for: matching or rendering a rule (`rustfs_gateway_core::cors`), reading a
//! document from anywhere (the deployment's `CorsSource`), or deciding where in the pipeline these
//! run (`super`, which calls them).
//! Upstream: `super::S3Service`'s pipeline. Downstream: `rustfs_gateway_core::cors`,
//! `crate::ext::CachedCorsSource`.

use http::{Response, StatusCode};
use rustfs_gateway_core::TargetKind;
use rustfs_gateway_core::cors::{
    CorsHeaders, PreflightOutcome, PreflightRefusalCause, PreflightRequest, answer_actual, answer_preflight,
    preflight_uses_resolved_target,
};
use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_stream::Body;

use crate::clock::MonotonicNow;
use crate::ext::{CORS_PREFLIGHT, ClassKind, ClientAddr, GovernorRequest, ResolvedHost};
use crate::request_deadline::hold_failure_floor;

use super::{Outcome, S3Service};

impl S3Service {
    /// Answers one preflight, and never anything else.
    ///
    /// The order below is the mitigation, in three steps that may not be reordered:
    ///
    /// 1. **The governor, first and unconditionally**, including for a bucket name that is not a
    ///    legal one. A limit applied after the read is a limit on nothing, and skipping it for
    ///    the illegal-name case would make that case cheaper than the others — a difference an
    ///    attacker can measure.
    /// 2. **The document, through the mandatory cache.** Every negative answer — no document, no
    ///    bucket, no legal name, source failure — is the same `None` by the time it gets here.
    /// 3. **One answer or one refusal.** The refusal has a single constructor with no arguments,
    ///    so the four ways to reach it produce identical bytes.
    pub(super) async fn serve_preflight(
        &self,
        path: &str,
        resolved: ResolvedHost,
        preflight: &PreflightRequest<'_>,
        outcome: &mut Outcome<'_>,
        now: RequestNow,
        client_addr: Option<ClientAddr>,
    ) -> Response<Body> {
        let started = self.inner.authz_clock.monotonic();
        let bucket = preflight_bucket(path, &resolved);
        if self
            .inner
            .governor
            .try_acquire(&GovernorRequest::new(
                CORS_PREFLIGHT,
                bucket.as_ref(),
                None,
                client_addr,
                ClassKind::CorsPreflight,
            ))
            .await
            .is_err()
        {
            return outcome.refuse_for_load();
        }
        let document = match bucket.as_ref() {
            Some(name) => self.inner.cors.get(name, now).await,
            // An illegal bucket name, or a path that names no bucket at all. Answered exactly as
            // a bucket that does not exist is, and without a read.
            None => {
                return self
                    .refuse_preflight(outcome, PreflightRefusalCause::InvalidTarget, started)
                    .await;
            }
        };
        let Some(document) = document else {
            return self
                .refuse_preflight(outcome, PreflightRefusalCause::MissingDocument, started)
                .await;
        };
        match answer_preflight(&self.inner.cors_policy, Some(document.as_ref()), preflight) {
            PreflightOutcome::Allowed(headers) => preflight_response(&headers),
            PreflightOutcome::Refused => {
                self.refuse_preflight(outcome, PreflightRefusalCause::RuleMismatch, started)
                    .await
            }
        }
    }

    pub(super) async fn refuse_preflight(
        &self,
        outcome: &mut Outcome<'_>,
        cause: PreflightRefusalCause,
        started: MonotonicNow,
    ) -> Response<Body> {
        hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), started).await;
        outcome.refuse_preflight(cause)
    }

    /// The CORS decoration an ordinary response should carry, if any.
    ///
    /// Called once, after authorisation. `None` for a request with no usable `Origin`, for a path
    /// that names no bucket, and for a bucket with no CORS document. An origin no rule admits gets
    /// only `Vary: Origin`: the request is served and the browser withholds the answer from the
    /// page, while shared caches still keep origin-dependent answers separate.
    pub(super) async fn actual_cors(
        &self,
        headers: &http::HeaderMap,
        bucket: Option<&rustfs_gateway_types::BucketName>,
        method: &http::Method,
        now: RequestNow,
    ) -> Option<CorsDecoration> {
        let view = rustfs_gateway_http::HeaderView::new(headers);
        // Exactly one line, and one this runtime would be willing to echo. Two `Origin` lines are
        // refused here as they are on a preflight, and for the same cache-poisoning reason.
        let origin = (view.count(&rustfs_gateway_core::cors::ORIGIN) == 1)
            .then(|| view.get_str(&rustfs_gateway_core::cors::ORIGIN))
            .flatten()
            .filter(|origin| rustfs_gateway_core::cors::is_plausible_origin(origin))?;
        let document = self.inner.cors.get(bucket?, now).await?;
        Some(CorsDecoration {
            headers: answer_actual(&self.inner.cors_policy, Some(&document), origin, method.as_str()),
            vary_origin: true,
        })
    }
}

/// The bucket a preflight addresses, from the host when the host named one and from the path
/// otherwise.
///
/// **The host wins, and it has to.** On a virtual-hosted request the whole path is the object key,
/// so reading the first path segment would answer a preflight for a bucket called `key.txt` —
/// present, absent or somebody else's, at the caller's choice. `OPTIONS https://b.s3.example.com/`
/// would be worse: the path names nothing, the derivation returns `None`, and every browser
/// preflight against a virtual-hosted bucket is refused while the same request path-style is
/// served. Both are the same one-line mistake, and [`ResolvedHost::bucket`] is the answer to it —
/// the resolver already read the host, and this is not a second place that decides.
///
/// The path branch is reached only when the resolver reports [`Addressing::Path`], and it agrees
/// with `MetaView`'s split by construction: the first segment, and the resolver's own
/// [`TargetKind`] deciding whether there is a segment to take.
///
/// A name the bucket grammar refuses answers `None`, which the caller turns into the same refusal
/// a non-existent bucket gets. Telling a caller that a name is *illegal* rather than *absent* is
/// two probes away from an enumeration oracle.
///
/// [`Addressing::Path`]: crate::Addressing::Path
pub(crate) fn preflight_bucket(path: &str, resolved: &ResolvedHost) -> Option<rustfs_gateway_types::BucketName> {
    if preflight_uses_resolved_target() {
        if let Some(bucket) = resolved.bucket() {
            return Some(bucket.clone());
        }
        if !matches!(resolved.target, TargetKind::Bucket | TargetKind::Object) {
            return None;
        }
    }
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let first = trimmed.split('/').next().unwrap_or(trimmed);
    rustfs_gateway_types::BucketName::new(first).ok()
}

/// The response an allowed preflight goes out with: `200`, the headers, and no body.
fn preflight_response(headers: &CorsHeaders) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    let map = response.headers_mut();
    for (name, value) in headers.iter() {
        map.insert(name, value.clone());
    }
    map.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    response
}

/// The CORS headers an ordinary response is decorated with, decided once authorisation was granted.
pub(super) struct CorsDecoration {
    pub(super) headers: Option<CorsHeaders>,
    pub(super) vary_origin: bool,
}
