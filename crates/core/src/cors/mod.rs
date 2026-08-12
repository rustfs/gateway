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

//! The CORS **runtime**: what a browser is told, and what it is deliberately not told.
//!
//! Responsible for: the two entry points a pipeline calls — [`answer_preflight`] for an
//! `OPTIONS` that never reaches an operation, and [`answer_actual`] for the ordinary request that
//! follows it — and [`preflight_refusal`], the single refusal every failure shares.
//! NOT responsible for: what a stored document may say (`crate::ops::shared::cors`), reading one
//! from anywhere (the deployment's `CorsSource`, in the facade), or routing.
//! Upstream: `rustfs-gateway-types`' `CorsConfiguration` dto, `rustfs-gateway-http`'s
//! `HeaderView`. Downstream: the facade's pipeline.
//!
//! # One refusal, four reasons, no oracle
//!
//! A preflight arrives with no credentials — the Fetch Standard forbids a browser from sending
//! any — so every answer here is an answer to an unauthenticated caller. Four different things
//! can go wrong, and a caller must not be able to tell which:
//!
//! | What happened | What the caller sees |
//! | --- | --- |
//! | The bucket has a document and no rule matches | [`preflight_refusal`] |
//! | The bucket exists and has no document | [`preflight_refusal`] |
//! | The bucket does not exist | [`preflight_refusal`] |
//! | The bucket name is not a legal one | [`preflight_refusal`] |
//!
//! There is one constructor, it takes no arguments, and its message is a `&'static str`, so the
//! four cannot drift apart and none of them can carry a bucket name. A `404` for the third row —
//! the answer a developer would ask for — turns this endpoint into a private-bucket enumeration
//! oracle for anyone with a browser.
//!
//! # Why `answer_actual` is not the same function
//!
//! A preflight is answered *instead of* an operation and can therefore be evaluated from the head
//! alone. An ordinary request is answered *by* an operation, so its CORS headers are a decoration
//! on somebody else's response and are computed after authorisation — which is what keeps an
//! unauthenticated `GET` carrying an `Origin` from costing a configuration read.

mod answer;
mod request;
mod rule;

use crate::contracts;

pub use self::answer::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, CorsHeaders, CorsOrigins, CorsPolicy, CorsPolicyError,
    UnrenderableRule, VARY, VARY_ORIGIN, actual_headers, preflight_headers,
};
pub use self::request::{
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, HeadersRejected, MAX_ORIGIN_BYTES, MAX_REQUESTED_HEADER_BYTES,
    MAX_REQUESTED_HEADERS, ORIGIN, PreflightClass, PreflightRequest, RequestedHeaders, classify, is_plausible_origin,
};
pub use self::rule::{AllowOrigin, RuleMatch, match_actual, match_preflight, wildcard_match};

use rustfs_gateway_types::dto::CorsConfiguration;

use crate::error::PreAuthError;

/// The status a matched preflight is answered with.
pub const PREFLIGHT_SUCCESS_STATUS: u16 = 200;

/// The message every preflight refusal carries, whatever went wrong.
///
/// The `CORSResponse:` prefix is the marker S3 puts on a refusal that came from the CORS runtime
/// rather than from an operation, and browser-side tooling greps for it; the rest is this
/// project's own wording. Nothing after the colon is derived from the request — no bucket, no
/// origin, no method — because this response is produced for an unauthenticated caller as many
/// times as they care to ask for it.
pub const PREFLIGHT_REFUSAL_MESSAGE: &str = "CORSResponse: no CORS rule allows this request";

/// The internal branch that reached a preflight refusal.
///
/// The current contract deliberately erases this value before rendering. It remains typed so the
/// refusal-profile mutation can prove that every production call site is covered without ever
/// carrying request-derived bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightRefusalCause {
    /// The preflight headers were incomplete or unreadable.
    Malformed,
    /// Host/path resolution did not produce a legal bucket target.
    InvalidTarget,
    /// The target had no readable CORS document.
    MissingDocument,
    /// A document existed but no rule admitted the request.
    RuleMismatch,
}

/// Whether a recognised preflight bypasses the ordinary operation pipeline.
#[must_use]
pub const fn preflight_bypasses_pipeline() -> bool {
    contracts::cors_preflight_bypasses_pipeline()
}

/// Whether host/path resolution supplies the bucket whose CORS document is read.
#[must_use]
pub const fn preflight_uses_resolved_target() -> bool {
    contracts::cors_preflight_uses_resolved_target()
}

/// Whether post-authorisation error responses retain their computed CORS decoration.
#[must_use]
pub const fn headers_apply_to_post_auth_errors() -> bool {
    contracts::cors_headers_apply_to_post_auth_errors()
}

/// Whether failures and absences from a CORS source are collapsed before answering.
#[must_use]
pub const fn source_absence_is_collapsed() -> bool {
    contracts::cors_source_absence_is_collapsed()
}

/// Whether an invalid bucket target receives the uniform preflight refusal.
#[must_use]
pub const fn invalid_target_is_uniform_refusal() -> bool {
    contracts::cors_invalid_target_is_uniform_refusal()
}

/// Whether a successful preflight grants no authorisation to a later request.
#[must_use]
pub const fn preflight_grants_no_authorization() -> bool {
    contracts::cors_preflight_grants_no_authorization()
}

/// The one refusal a preflight can receive.
///
/// `403 AccessForbidden`, always, with [`PREFLIGHT_REFUSAL_MESSAGE`]. Takes no arguments on
/// purpose: a constructor that could be told *why* is a constructor whose four call sites will
/// eventually say four different things, and the difference between them is the oracle.
#[must_use]
pub fn preflight_refusal() -> PreAuthError {
    PreAuthError::access_forbidden(PREFLIGHT_REFUSAL_MESSAGE)
}

/// Renders a refusal after deliberately applying the configured refusal profile.
///
/// The current profile delegates every cause to [`preflight_refusal`]. The alternative values are
/// fixed strings, never request data; they exist only so the contract mutation can demonstrate
/// that the production gateway would expose the cause if uniformity stopped being the source.
#[must_use]
pub fn preflight_refusal_for(cause: PreflightRefusalCause) -> PreAuthError {
    if contracts::cors_preflight_refusal_is_uniform() {
        return preflight_refusal();
    }
    match cause {
        PreflightRefusalCause::Malformed => PreAuthError::invalid_request("CORSResponse: malformed preflight"),
        PreflightRefusalCause::InvalidTarget => PreAuthError::invalid_argument("CORSResponse: invalid bucket target"),
        PreflightRefusalCause::MissingDocument => PreAuthError::access_forbidden("CORSResponse: no CORS configuration"),
        PreflightRefusalCause::RuleMismatch => PreAuthError::access_forbidden("CORSResponse: no matching CORS rule"),
    }
}

/// What the pipeline should do with a preflight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Answer [`PREFLIGHT_SUCCESS_STATUS`] with these headers and an empty body.
    Allowed(CorsHeaders),
    /// Answer [`preflight_refusal`].
    Refused,
}

/// Answers one preflight from the bucket's stored document, or from its absence.
///
/// `configuration` is `None` for a bucket with no document, for a bucket that does not exist, for
/// a name that is not a legal bucket name, and for a source that failed — the caller collapses
/// all four before calling, and this function could not tell them apart if it wanted to.
#[must_use]
pub fn answer_preflight(
    policy: &CorsPolicy,
    configuration: Option<&CorsConfiguration>,
    request: &PreflightRequest<'_>,
) -> PreflightOutcome {
    let Some(configuration) = configuration else {
        return PreflightOutcome::Refused;
    };
    let Some(matched) = match_preflight(configuration, request.origin, request.method, &request.headers) else {
        return PreflightOutcome::Refused;
    };
    match preflight_headers(policy, &matched, request.method, &request.headers) {
        Ok(headers) => PreflightOutcome::Allowed(headers),
        Err(UnrenderableRule) => PreflightOutcome::Refused,
    }
}

/// The CORS headers an ordinary response should carry, if any.
///
/// `None` means no header at all, which is the fail-closed answer: an unmatched origin gets an
/// ordinary S3 response and the browser refuses to hand it to the page, which is exactly what
/// "this origin was not allowed" should look like. It is never an error: the request itself was
/// legitimate and is served.
#[must_use]
pub fn answer_actual(
    policy: &CorsPolicy,
    configuration: Option<&CorsConfiguration>,
    origin: &str,
    method: &str,
) -> Option<CorsHeaders> {
    let Some(matched) = match_actual(configuration?, origin, method) else {
        return (!contracts::cors_unmatched_actual_has_no_headers())
            .then(|| answer::unmatched_actual_headers(origin).ok())
            .flatten();
    };
    actual_headers(policy, &matched).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::CorsRule;

    fn document(origins: &[&str], methods: &[&str]) -> CorsConfiguration {
        CorsConfiguration {
            cors_rules: vec![CorsRule {
                allowed_methods: methods.iter().map(|m| (*m).to_owned()).collect(),
                allowed_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
                ..CorsRule::default()
            }],
        }
    }

    fn preflight<'a>(origin: &'a str, method: &'a str) -> PreflightRequest<'a> {
        PreflightRequest {
            origin,
            method,
            headers: RequestedHeaders::empty(),
        }
    }

    /// Positive — a matching preflight is allowed and carries the origin it was granted.
    #[test]
    fn a_matching_preflight_is_allowed() {
        let stored = document(&["https://a.invalid"], &["PUT"]);
        let outcome = answer_preflight(&CorsPolicy::default(), Some(&stored), &preflight("https://a.invalid", "PUT"));
        let PreflightOutcome::Allowed(headers) = outcome else {
            panic!("expected an allowance, got {outcome:?}");
        };
        assert_eq!(
            headers.get(&ACCESS_CONTROL_ALLOW_ORIGIN).map(http::HeaderValue::as_bytes),
            Some(&b"https://a.invalid"[..])
        );
    }

    /// Positive — an ordinary request that a rule admits gets headers.
    #[test]
    fn a_matching_actual_request_gets_headers() {
        let stored = document(&["*"], &["GET"]);
        assert!(answer_actual(&CorsPolicy::default(), Some(&stored), "https://a.invalid", "GET").is_some());
    }

    /// Negative — the four ways a preflight can fail produce one value, and that value carries
    /// nothing about which of them happened. This is the enumeration oracle, closed.
    #[test]
    fn n_every_preflight_failure_is_the_same_answer() {
        let policy = CorsPolicy::default();
        let stored = document(&["https://a.invalid"], &["PUT"]);
        // No document at all — the bucket has none, does not exist, or the name was illegal; the
        // caller collapses those three into `None` before this point.
        assert_eq!(
            answer_preflight(&policy, None, &preflight("https://a.invalid", "PUT")),
            PreflightOutcome::Refused
        );
        // A document that does not admit this origin.
        assert_eq!(
            answer_preflight(&policy, Some(&stored), &preflight("https://evil.invalid", "PUT")),
            PreflightOutcome::Refused
        );
        // A document that does not admit this method.
        assert_eq!(
            answer_preflight(&policy, Some(&stored), &preflight("https://a.invalid", "DELETE")),
            PreflightOutcome::Refused
        );
        // An empty document.
        assert_eq!(
            answer_preflight(&policy, Some(&CorsConfiguration::default()), &preflight("https://a.invalid", "PUT")),
            PreflightOutcome::Refused
        );
    }

    /// Negative — the refusal is a `403` whose message is a compile-time constant, names no
    /// operation, and opens with the marker S3 uses.
    #[test]
    fn n_the_refusal_carries_nothing_from_the_request() {
        let refusal = preflight_refusal();
        assert_eq!(refusal.status().as_u16(), 403);
        // The status set the pre-authentication path is allowed to answer with. A refusal outside
        // it would be a statement about a request nobody has been authorised to look at.
        assert!(crate::error::PRE_AUTH_STATUSES.contains(&refusal.status()));
        assert_eq!(refusal.code(), &rustfs_gateway_types::ErrorCode::ACCESS_FORBIDDEN);
        assert_eq!(refusal.message(), PREFLIGHT_REFUSAL_MESSAGE);
        assert!(refusal.message().starts_with("CORSResponse:"));
        assert_eq!(refusal.operation(), None);
        // Two refusals are the same value: there is no per-call state that could differ.
        assert_eq!(preflight_refusal(), preflight_refusal());
        for cause in [
            PreflightRefusalCause::Malformed,
            PreflightRefusalCause::InvalidTarget,
            PreflightRefusalCause::MissingDocument,
            PreflightRefusalCause::RuleMismatch,
        ] {
            assert_eq!(preflight_refusal_for(cause), refusal, "the refusal exposed {cause:?}");
        }
    }

    /// Negative — an unmatched ordinary request gets no headers rather than an error. The request
    /// is served; the browser is the one that refuses to hand the answer to the page.
    #[test]
    fn n_an_unmatched_actual_request_gets_no_headers() {
        let stored = document(&["https://a.invalid"], &["GET"]);
        assert_eq!(answer_actual(&CorsPolicy::default(), Some(&stored), "https://evil.invalid", "GET"), None);
        assert_eq!(answer_actual(&CorsPolicy::default(), Some(&stored), "https://a.invalid", "PUT"), None);
        assert_eq!(answer_actual(&CorsPolicy::default(), None, "https://a.invalid", "GET"), None);
    }

    /// Negative — a stored document this runtime cannot render is a refusal, not a partial
    /// answer, on both paths.
    #[test]
    fn n_an_unrenderable_document_refuses_rather_than_partially_answers() {
        let mut stored = document(&["*"], &["GET"]);
        if let Some(rule) = stored.cors_rules.first_mut() {
            rule.expose_headers = vec!["etag\r\nx-injected: 1".to_owned()];
        }
        assert_eq!(
            answer_preflight(&CorsPolicy::default(), Some(&stored), &preflight("https://a.invalid", "GET")),
            PreflightOutcome::Refused
        );
        assert_eq!(answer_actual(&CorsPolicy::default(), Some(&stored), "https://a.invalid", "GET"), None);
    }
}
