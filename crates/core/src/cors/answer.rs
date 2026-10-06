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

//! The `Access-Control-*` headers an admitted request gets, and the one combination that is
//! unwritable.
//!
//! Responsible for: [`CorsPolicy`] — the deployment's credential posture, whose only constructor
//! refuses the reflect-plus-credentials combination — the two header sets
//! ([`preflight_headers`], [`actual_headers`]), and which header belongs to which of them.
//! NOT responsible for: matching ([`super::rule`]), classifying a request
//! ([`super::request`]), or putting anything on a wire.
//! Upstream: [`super::rule`]'s `RuleMatch`. Downstream: the facade's preflight branch and its
//! response encoder.
//!
//! # `Access-Control-Allow-Credentials` and a reflected origin cannot both be written
//!
//! `GHSA-x5xv-223c-8vm7` is one sentence: a gateway that echoes the caller's `Origin` and also
//! answers `Access-Control-Allow-Credentials: true` has told every site on the internet that it
//! may read this user's data with this user's cookies. The mitigation here is not a check.
//!
//! [`ACCESS_CONTROL_ALLOW_CREDENTIALS`] is named in exactly one function,
//! [`credentials_header`]. The generated current policy makes both wildcard arms of
//! [`credentials_for_origin`] return `None`; its mutation alternative deliberately reaches the helper
//! with the request origin, and `q-cors-0026`'s cases must turn red. The guard script separately
//! forbids folding the header write into a function that also names a wildcard `AllowOrigin`
//! variant, and forbids importing those variants unqualified, so the writer cannot bypass the
//! typed source and its mutation control.
//!
//! On top of that, [`CorsPolicy::new`] refuses `CorsOrigins::Any` with credentials outright, so a
//! deployment cannot even declare the posture, and an exact allow-list carrying a `*` is refused
//! for the same reason: a wildcard entry is `Any` wearing a list's clothes.
//!
//! # Which header goes on which response
//!
//! | Header | Preflight | Actual |
//! | --- | --- | --- |
//! | `Access-Control-Allow-Origin` | yes | yes |
//! | `Access-Control-Allow-Credentials` | when the policy permits it | when the policy permits it |
//! | `Access-Control-Allow-Methods` | yes | no |
//! | `Access-Control-Allow-Headers` | when the caller asked about any | no |
//! | `Access-Control-Max-Age` | when the rule sets one | no |
//! | `Access-Control-Expose-Headers` | when the rule sets one | when the rule sets one |
//! | `Vary: Origin` | always | always |
//!
//! The Fetch Standard has a browser read `Allow-Methods`, `Allow-Headers` and `Max-Age` only from
//! a preflight response and `Expose-Headers` only from an actual one, so the two columns are the
//! two halves of one contract rather than a subset relationship. `Expose-Headers` appears in both
//! because S3 answers it on the preflight as well; a browser ignores it there, and omitting it
//! would be a difference from the service this project is a gateway for.
//!
//! # Why `Vary: Origin` is unconditional
//!
//! The response depends on `Origin` even when it does not name one: whether any
//! `Access-Control-*` header is present at all is decided by it. A shared cache that stored one
//! origin's answer and served it to another would be handing out an allowance the second origin
//! was never granted — RFC 9110 §12.5.5 is what makes the header the fix.

use http::{HeaderName, HeaderValue};

use crate::contracts;

use super::request::RequestedHeaders;
use super::rule::{AllowOrigin, RuleMatch};

/// Which origin the answer allows.
pub const ACCESS_CONTROL_ALLOW_ORIGIN: HeaderName = HeaderName::from_static("access-control-allow-origin");
/// Whether the browser may attach credentials. See the module documentation.
pub const ACCESS_CONTROL_ALLOW_CREDENTIALS: HeaderName = HeaderName::from_static("access-control-allow-credentials");
/// Which methods the matched rule admits.
pub const ACCESS_CONTROL_ALLOW_METHODS: HeaderName = HeaderName::from_static("access-control-allow-methods");
/// Which of the requested headers are admitted — all of them, or the preflight was refused.
pub const ACCESS_CONTROL_ALLOW_HEADERS: HeaderName = HeaderName::from_static("access-control-allow-headers");
/// How long the browser may cache this preflight.
pub const ACCESS_CONTROL_MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
/// Which response headers the page's script may read.
pub const ACCESS_CONTROL_EXPOSE_HEADERS: HeaderName = HeaderName::from_static("access-control-expose-headers");
/// The cache-correctness header every answer carries.
pub const VARY: HeaderName = HeaderName::from_static("vary");
/// The one value [`VARY`] is ever given here.
pub const VARY_ORIGIN: HeaderValue = HeaderValue::from_static("origin");

/// Which origins a deployment is willing to let a browser send credentials to.
///
/// `#[non_exhaustive]` because a third posture — a matcher supplied by the deployment, say — must
/// not be addable in a way that lets an existing `match` fall through to the permissive arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorsOrigins {
    /// Any origin the bucket's own rules admit. Credentials are unavailable under this variant:
    /// the set is not enumerable, so "this exact origin was named by an operator" cannot be true
    /// of it.
    Any,
    /// An enumerated allow-list, written by an operator. The only variant that may carry
    /// credentials, and no entry of it may contain a `*`.
    Exact(Box<[String]>),
}

/// Why a [`CorsPolicy`] could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorsPolicyError {
    /// `CorsOrigins::Any` was combined with credentials. This is `GHSA-x5xv-223c-8vm7` verbatim.
    CredentialsWithAnyOrigin,
    /// An entry of an exact allow-list carried a `*`. A wildcard entry is `Any` semantics, so it
    /// is refused for the same reason and with a distinct code, because the fix differs.
    CredentialsWithWildcardOrigin,
    /// An exact allow-list with no entries was offered together with credentials. It permits
    /// nothing, so it is a configuration mistake rather than a posture.
    CredentialsWithEmptyList,
}

impl CorsPolicyError {
    /// A constant explanation. Never built from configuration text: an operator's origin list can
    /// name internal hosts, and an error that repeated one would put it in a log.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            CorsPolicyError::CredentialsWithAnyOrigin => {
                "a CORS policy that allows any origin may not allow credentials: the two together \
                 let any site read this deployment's data with the user's own session"
            }
            CorsPolicyError::CredentialsWithWildcardOrigin => {
                "an origin allow-list entry containing a wildcard may not allow credentials: a \
                 wildcard entry admits origins no operator enumerated"
            }
            CorsPolicyError::CredentialsWithEmptyList => {
                "an empty origin allow-list allows credentials to nobody; declare the origins or \
                 declare no credentials"
            }
        }
    }
}

impl core::fmt::Display for CorsPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for CorsPolicyError {}

/// A deployment's CORS posture: which origins may use credentials, and whether any may.
///
/// The bucket's stored document decides what is *allowed*; this decides whether an allowance may
/// additionally carry the user's session. The two are separate because the S3 CORS document has
/// no element for credentials — an operator who wants them has to say so here, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorsPolicy {
    origins: CorsOrigins,
    allow_credentials: bool,
}

impl Default for CorsPolicy {
    /// Any origin the bucket's rules admit, and no credentials. The fail-closed half of this is
    /// elsewhere: with no configured source, no rule matches and no header is written at all.
    fn default() -> Self {
        Self {
            origins: CorsOrigins::Any,
            allow_credentials: false,
        }
    }
}

impl CorsPolicy {
    /// The only constructor.
    ///
    /// # Errors
    ///
    /// [`CorsPolicyError`] for every combination that would reintroduce
    /// `GHSA-x5xv-223c-8vm7`. This is not a warning and not a run-time check: a policy that
    /// permits a reflected origin to carry credentials does not exist, so no code path can
    /// consult one.
    pub fn new(origins: CorsOrigins, allow_credentials: bool) -> Result<Self, CorsPolicyError> {
        if allow_credentials {
            match &origins {
                CorsOrigins::Any => return Err(CorsPolicyError::CredentialsWithAnyOrigin),
                CorsOrigins::Exact(list) if list.is_empty() => return Err(CorsPolicyError::CredentialsWithEmptyList),
                CorsOrigins::Exact(list) if list.iter().any(|origin| origin.contains('*')) => {
                    return Err(CorsPolicyError::CredentialsWithWildcardOrigin);
                }
                CorsOrigins::Exact(_) => {}
            }
        }
        Ok(Self {
            origins,
            allow_credentials,
        })
    }

    /// Whether this policy names `origin` and permits credentials for it.
    ///
    /// Reached only from [`credentials_header`]; see the module documentation.
    #[must_use]
    fn permits_credentials(&self, origin: &str) -> bool {
        match &self.origins {
            CorsOrigins::Any => false,
            CorsOrigins::Exact(list) => self.allow_credentials && list.iter().any(|allowed| allowed == origin),
        }
    }
}

/// An ordered set of response headers the CORS runtime produced.
///
/// A `Vec` of pairs rather than a `HeaderMap`, because the order is asserted by conformance cases
/// and a map does not have one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorsHeaders {
    pairs: Vec<(HeaderName, HeaderValue)>,
}

impl CorsHeaders {
    /// The pairs, in the order they are to be written.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.pairs.iter().map(|(name, value)| (name, value))
    }

    /// The value written for `name`, if any.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value)
    }

    /// How many headers there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

/// A stored rule this runtime could not turn into a header line.
///
/// Reachable: `validate_cors` bounds the *shape* of an `<ExposeHeader>` but not its bytes, and a
/// document written by an older release — or by a peer with a laxer validator — can hold a value
/// no header line may carry. The answer is to refuse the whole response rather than to drop one
/// header, because a partial CORS answer is an allowance nobody wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnrenderableRule;

/// The headers a matched preflight is answered with.
///
/// # Errors
///
/// [`UnrenderableRule`] when a value of the stored rule cannot be a header value.
pub fn preflight_headers(
    policy: &CorsPolicy,
    matched: &RuleMatch<'_>,
    requested_method: &str,
    requested: &RequestedHeaders<'_>,
) -> Result<CorsHeaders, UnrenderableRule> {
    let mut pairs = vec![(ACCESS_CONTROL_ALLOW_ORIGIN, header_value(allow_origin_value(matched))?)];
    if let Some(credentials) = credentials_for_origin(policy, matched.origin, matched.request_origin) {
        pairs.push(credentials);
    }
    let methods = if contracts::cors_preflight_uses_matched_methods() {
        join(&matched.rule.allowed_methods)
    } else {
        requested_method.to_owned()
    };
    pairs.push((ACCESS_CONTROL_ALLOW_METHODS, header_value(&methods)?));
    if !requested.is_empty() {
        let echoed = if contracts::cors_allow_headers_echoes_request() {
            requested.names().collect::<Vec<_>>().join(", ")
        } else {
            join(&matched.rule.allowed_headers)
        };
        pairs.push((ACCESS_CONTROL_ALLOW_HEADERS, header_value(&echoed)?));
    }
    if contracts::cors_preflight_includes_max_age()
        && let Some(seconds) = matched.rule.max_age_seconds
        && seconds >= 0
    {
        pairs.push((ACCESS_CONTROL_MAX_AGE, header_value(&seconds.to_string())?));
    }
    if contracts::cors_preflight_includes_expose() {
        push_expose(&mut pairs, matched)?;
    }
    if contracts::cors_preflight_varies_on_origin() {
        pairs.push((VARY, VARY_ORIGIN));
    }
    Ok(CorsHeaders { pairs })
}

/// The headers an ordinary matched request is answered with.
///
/// # Errors
///
/// [`UnrenderableRule`], for the reason [`preflight_headers`] gives.
pub fn actual_headers(policy: &CorsPolicy, matched: &RuleMatch<'_>) -> Result<CorsHeaders, UnrenderableRule> {
    let mut pairs = Vec::new();
    if contracts::cors_actual_includes_allow_origin() {
        pairs.push((ACCESS_CONTROL_ALLOW_ORIGIN, header_value(allow_origin_value(matched))?));
    }
    if let Some(credentials) = credentials_for_origin(policy, matched.origin, matched.request_origin) {
        pairs.push(credentials);
    }
    if contracts::cors_actual_includes_expose() {
        push_expose(&mut pairs, matched)?;
    }
    if !contracts::cors_actual_omits_preflight_headers() {
        pairs.push((ACCESS_CONTROL_ALLOW_METHODS, header_value(&join(&matched.rule.allowed_methods))?));
    }
    if contracts::cors_actual_varies_on_origin() {
        pairs.push((VARY, VARY_ORIGIN));
    }
    Ok(CorsHeaders { pairs })
}

pub(super) fn unmatched_actual_headers(origin: &str) -> Result<CorsHeaders, UnrenderableRule> {
    Ok(CorsHeaders {
        pairs: vec![(ACCESS_CONTROL_ALLOW_ORIGIN, header_value(origin)?), (VARY, VARY_ORIGIN)],
    })
}

/// The bytes that go into `Access-Control-Allow-Origin`.
///
/// The bare `*` answers `*`; every other match answers a concrete origin. Which of the two
/// concrete forms it is decides whether credentials are available, and that decision is
/// [`credentials_for_origin`]'s, not this function's.
fn allow_origin_value<'a>(matched: &'a RuleMatch<'a>) -> &'a str {
    match matched.origin {
        AllowOrigin::Wildcard if contracts::cors_bare_wildcard_is_literal() => "*",
        AllowOrigin::Wildcard => matched.request_origin,
        AllowOrigin::Exact(value) => value,
        AllowOrigin::Reflected(value) if contracts::cors_partial_wildcard_reflects() => value,
        AllowOrigin::Reflected(_) => "*",
    }
}

/// The credentials line, when the matched origin is one an operator enumerated.
///
/// Under the generated current policy, the two wildcard arms answer `None`. The other branch is
/// the mutation control for `q-cors-0026` and must be killed by its conformance cases.
/// Compatibility response renderers may use this alongside their own non-credential headers.
/// `origin` must describe the rule or explicit fallback entry that admitted `request_origin`;
/// a wildcard allowance must retain its wildcard variant even if the response echoes the origin.
#[must_use]
pub fn credentials_for_origin(
    policy: &CorsPolicy,
    origin: AllowOrigin<'_>,
    request_origin: &str,
) -> Option<(HeaderName, HeaderValue)> {
    match origin {
        AllowOrigin::Exact(value) => credentials_header(policy, value),
        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard if contracts::cors_wildcard_credentials_omitted() => None,
        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard => credentials_header(policy, request_origin),
    }
}

/// The one function in this workspace that names [`ACCESS_CONTROL_ALLOW_CREDENTIALS`].
///
/// Under the generated current policy, `origin` comes from the stored rule's
/// `AllowOrigin::Exact` arm. The mutation-only wildcard branch supplies the request origin so its
/// cases can prove that widening the policy changes the wire answer.
fn credentials_header(policy: &CorsPolicy, origin: &str) -> Option<(HeaderName, HeaderValue)> {
    policy
        .permits_credentials(origin)
        .then(|| (ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true")))
}

fn push_expose(pairs: &mut Vec<(HeaderName, HeaderValue)>, matched: &RuleMatch<'_>) -> Result<(), UnrenderableRule> {
    if !matched.rule.expose_headers.is_empty() {
        pairs.push((ACCESS_CONTROL_EXPOSE_HEADERS, header_value(&join(&matched.rule.expose_headers))?));
    }
    Ok(())
}

fn join(values: &[String]) -> String {
    values.join(", ")
}

fn header_value(text: &str) -> Result<HeaderValue, UnrenderableRule> {
    HeaderValue::from_str(text).map_err(|_| UnrenderableRule)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::CorsRule;

    fn rule() -> CorsRule {
        CorsRule {
            allowed_methods: vec!["GET".to_owned(), "PUT".to_owned()],
            allowed_origins: vec!["https://a.invalid".to_owned()],
            ..CorsRule::default()
        }
    }

    fn matched<'a>(rule: &'a CorsRule, origin: AllowOrigin<'a>) -> RuleMatch<'a> {
        let request_origin = match origin {
            AllowOrigin::Wildcard => "https://wildcard.invalid",
            AllowOrigin::Exact(value) | AllowOrigin::Reflected(value) => value,
        };
        RuleMatch {
            index: 0,
            rule,
            origin,
            request_origin,
        }
    }

    fn exact_policy(origins: &[&str], credentials: bool) -> CorsPolicy {
        CorsPolicy::new(CorsOrigins::Exact(origins.iter().map(|o| (*o).to_owned()).collect()), credentials)
            .expect("a policy with an enumerated list")
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    /// Positive — the smallest preflight answer: the origin, the rule's methods and the cache
    /// header, in that order.
    #[test]
    fn a_preflight_answer_names_the_origin_and_the_methods() {
        let rule = rule();
        let headers = preflight_headers(
            &CorsPolicy::default(),
            &matched(&rule, AllowOrigin::Exact("https://a.invalid")),
            "GET",
            &RequestedHeaders::empty(),
        )
        .expect("a renderable rule");
        assert_eq!(
            headers.get(&ACCESS_CONTROL_ALLOW_ORIGIN).map(HeaderValue::as_bytes),
            Some(&b"https://a.invalid"[..])
        );
        assert_eq!(
            headers.get(&ACCESS_CONTROL_ALLOW_METHODS).map(HeaderValue::as_bytes),
            Some(&b"GET, PUT"[..])
        );
        assert_eq!(headers.get(&VARY), Some(&VARY_ORIGIN));
    }

    /// Positive — the bare `*` answers `*`, and a partial wildcard answers the caller's origin.
    /// Answering `*` for the second would widen the rule to every origin there is.
    #[test]
    fn the_two_wildcard_forms_answer_differently() {
        let rule = rule();
        let star = preflight_headers(
            &CorsPolicy::default(),
            &matched(&rule, AllowOrigin::Wildcard),
            "GET",
            &RequestedHeaders::empty(),
        )
        .expect("renderable");
        assert_eq!(star.get(&ACCESS_CONTROL_ALLOW_ORIGIN).map(HeaderValue::as_bytes), Some(&b"*"[..]));
        let reflected = preflight_headers(
            &CorsPolicy::default(),
            &matched(&rule, AllowOrigin::Reflected("https://app.example.com")),
            "GET",
            &RequestedHeaders::empty(),
        )
        .expect("renderable");
        assert_eq!(
            reflected.get(&ACCESS_CONTROL_ALLOW_ORIGIN).map(HeaderValue::as_bytes),
            Some(&b"https://app.example.com"[..])
        );
    }

    /// Positive — the requested header names are echoed once every one of them has matched, and
    /// the max age and expose list come from the matched rule.
    #[test]
    fn the_optional_preflight_headers_come_from_the_matched_rule() {
        let mut rule = rule();
        rule.max_age_seconds = Some(3000);
        rule.expose_headers = vec!["etag".to_owned(), "x-amz-request-id".to_owned()];
        let requested = RequestedHeaders::parse("x-amz-acl,x-amz-meta-a").expect("a readable list");
        let headers = preflight_headers(&CorsPolicy::default(), &matched(&rule, AllowOrigin::Wildcard), "GET", &requested)
            .expect("renderable");
        assert_eq!(
            headers.get(&ACCESS_CONTROL_ALLOW_HEADERS).map(HeaderValue::as_bytes),
            Some(&b"x-amz-acl, x-amz-meta-a"[..])
        );
        assert_eq!(headers.get(&ACCESS_CONTROL_MAX_AGE).map(HeaderValue::as_bytes), Some(&b"3000"[..]));
        assert_eq!(
            headers.get(&ACCESS_CONTROL_EXPOSE_HEADERS).map(HeaderValue::as_bytes),
            Some(&b"etag, x-amz-request-id"[..])
        );
    }

    /// Positive — an enumerated origin with credentials declared gets the credentials line.
    /// Without this the exclusion below would be satisfied by a policy that never writes the
    /// header at all.
    #[test]
    fn an_enumerated_origin_may_carry_credentials() {
        let rule = rule();
        let headers = actual_headers(
            &exact_policy(&["https://a.invalid"], true),
            &matched(&rule, AllowOrigin::Exact("https://a.invalid")),
        )
        .expect("renderable");
        assert_eq!(
            headers.get(&ACCESS_CONTROL_ALLOW_CREDENTIALS).map(HeaderValue::as_bytes),
            Some(&b"true"[..])
        );
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    /// Negative — the advisory's own shape does not typecheck into a policy.
    #[test]
    fn n_any_origin_with_credentials_is_not_constructible() {
        assert_eq!(CorsPolicy::new(CorsOrigins::Any, true), Err(CorsPolicyError::CredentialsWithAnyOrigin));
        assert!(CorsPolicy::new(CorsOrigins::Any, false).is_ok());
    }

    /// Negative — a wildcard hiding inside an allow-list is refused; it is `Any` with extra
    /// steps.
    #[test]
    fn n_a_wildcard_entry_with_credentials_is_refused() {
        assert_eq!(
            CorsPolicy::new(CorsOrigins::Exact(Box::from(["https://*.example.com".to_owned()])), true),
            Err(CorsPolicyError::CredentialsWithWildcardOrigin)
        );
        assert_eq!(
            CorsPolicy::new(CorsOrigins::Exact(Box::from(["*".to_owned()])), true),
            Err(CorsPolicyError::CredentialsWithWildcardOrigin)
        );
        // Without credentials the same list is a legitimate posture, so the refusal is about the
        // combination and not about the list.
        assert!(CorsPolicy::new(CorsOrigins::Exact(Box::from(["https://*.example.com".to_owned()])), false).is_ok());
    }

    /// Negative — an empty allow-list plus credentials is a mistake, not a posture.
    #[test]
    fn n_an_empty_allow_list_with_credentials_is_refused() {
        assert_eq!(
            CorsPolicy::new(CorsOrigins::Exact(Box::from([])), true),
            Err(CorsPolicyError::CredentialsWithEmptyList)
        );
        assert!(CorsPolicy::new(CorsOrigins::Exact(Box::from([])), false).is_ok());
    }

    /// Negative — the reflected origin never carries credentials, whatever the policy says. This
    /// is the run-time half of the exclusion: even a policy that enumerates the very origin being
    /// reflected does not get the header, because the match came through a wildcard.
    #[test]
    fn n_a_reflected_origin_never_carries_credentials() {
        let rule = rule();
        let policy = exact_policy(&["https://app.example.com"], true);
        for answer in [
            preflight_headers(
                &policy,
                &matched(&rule, AllowOrigin::Reflected("https://app.example.com")),
                "GET",
                &RequestedHeaders::empty(),
            ),
            actual_headers(&policy, &matched(&rule, AllowOrigin::Reflected("https://app.example.com"))),
        ] {
            let headers = answer.expect("renderable");
            assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_CREDENTIALS), None);
        }
    }

    /// Negative — the bare `*` never carries credentials either.
    #[test]
    fn n_the_star_never_carries_credentials() {
        let rule = rule();
        let policy = exact_policy(&["*"], false);
        let headers = actual_headers(&policy, &matched(&rule, AllowOrigin::Wildcard)).expect("renderable");
        assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_CREDENTIALS), None);
    }

    /// Negative — an exact match to an origin the policy did not enumerate gets no credentials,
    /// so the allow-list is a list and not a switch.
    #[test]
    fn n_an_unenumerated_exact_origin_carries_no_credentials() {
        let rule = rule();
        let policy = exact_policy(&["https://other.invalid"], true);
        let headers = actual_headers(&policy, &matched(&rule, AllowOrigin::Exact("https://a.invalid"))).expect("renderable");
        assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_CREDENTIALS), None);
    }

    /// Negative — the preflight-only headers stay off the actual response, and the actual
    /// response's own optional header stays on it. A browser reads each from one place only.
    #[test]
    fn n_the_preflight_only_headers_are_absent_from_an_actual_response() {
        let mut rule = rule();
        rule.max_age_seconds = Some(600);
        rule.expose_headers = vec!["etag".to_owned()];
        let headers = actual_headers(&CorsPolicy::default(), &matched(&rule, AllowOrigin::Wildcard)).expect("renderable");
        assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_METHODS), None);
        assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_HEADERS), None);
        assert_eq!(headers.get(&ACCESS_CONTROL_MAX_AGE), None);
        assert_eq!(headers.get(&ACCESS_CONTROL_EXPOSE_HEADERS).map(HeaderValue::as_bytes), Some(&b"etag"[..]));
    }

    /// Negative — a preflight that asked about no header gets no `Allow-Headers` line. Writing an
    /// empty one would tell the browser the empty set was granted.
    #[test]
    fn n_no_requested_headers_means_no_allow_headers_line() {
        let rule = rule();
        let headers = preflight_headers(
            &CorsPolicy::default(),
            &matched(&rule, AllowOrigin::Wildcard),
            "GET",
            &RequestedHeaders::empty(),
        )
        .expect("renderable");
        assert_eq!(headers.get(&ACCESS_CONTROL_ALLOW_HEADERS), None);
    }

    /// Negative — a negative `MaxAgeSeconds` in a stored document writes no header rather than a
    /// negative one. `validate_cors` refuses it on write; a document from elsewhere can hold one.
    #[test]
    fn n_a_negative_max_age_writes_no_header() {
        let mut rule = rule();
        rule.max_age_seconds = Some(-1);
        let headers = preflight_headers(
            &CorsPolicy::default(),
            &matched(&rule, AllowOrigin::Wildcard),
            "GET",
            &RequestedHeaders::empty(),
        )
        .expect("renderable");
        assert_eq!(headers.get(&ACCESS_CONTROL_MAX_AGE), None);
    }

    /// Negative — a stored value that cannot be a header line refuses the whole answer rather
    /// than being dropped from it. A partial CORS answer is an allowance nobody wrote.
    #[test]
    fn n_an_unrenderable_stored_value_refuses_the_whole_answer() {
        let mut rule = rule();
        rule.expose_headers = vec!["etag\nx-injected: 1".to_owned()];
        assert_eq!(
            preflight_headers(
                &CorsPolicy::default(),
                &matched(&rule, AllowOrigin::Wildcard),
                "GET",
                &RequestedHeaders::empty()
            ),
            Err(UnrenderableRule)
        );
        assert_eq!(
            actual_headers(&CorsPolicy::default(), &matched(&rule, AllowOrigin::Wildcard)),
            Err(UnrenderableRule)
        );
    }

    /// Negative — `Vary: Origin` is on both answers, always. Without it a shared cache serves one
    /// origin's allowance to another.
    #[test]
    fn n_vary_origin_is_never_omitted() {
        let rule = rule();
        for answer in [
            preflight_headers(
                &CorsPolicy::default(),
                &matched(&rule, AllowOrigin::Wildcard),
                "GET",
                &RequestedHeaders::empty(),
            ),
            actual_headers(&CorsPolicy::default(), &matched(&rule, AllowOrigin::Exact("https://a.invalid"))),
        ] {
            assert_eq!(answer.expect("renderable").get(&VARY), Some(&VARY_ORIGIN));
        }
    }
}
