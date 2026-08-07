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

//! The CORS configuration document: what a stored one is allowed to say.
//!
//! Shares: cors
//! Members: DeleteBucketCors, GetBucketCors, PutBucketCors
//!
//! Responsible for: the semantic rules of a `CORSConfiguration` document — the closed method set,
//! the wildcard budget of each list member, the hundred-rule cap, the bounds on `ID` and
//! `MaxAgeSeconds` — held once so that every backend refuses the same documents with the same
//! codes.
//! NOT responsible for: decoding the document (the generated codec, which is deliberately lenient
//! about unknown elements — `q-cors-0007`), storing it, or **matching** it. Whether an origin, a
//! requested method or a requested header satisfies a rule is the preflight runtime's question,
//! and nothing here answers it: matching runs pre-auth on a path this crate must not own.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Why validation is here and not in the decoder
//!
//! The decoder's job is syntax, and its failure code is `MalformedXML` for everything. These
//! rules answer with three different codes — `InvalidRequest` for a value outside a closed set,
//! `InvalidArgument` for a bound violation, `MalformedXML` only for a required member that is
//! absent — and a client debugging a browser-side CORS failure branches on the difference.
//! Folding them into the generated decoder would also make them regenerate-only, when they are
//! precisely the hand-written protocol opinions the overlay cannot express.
//!
//! # The refusal messages are constant
//!
//! AWS's own message for an unsupported method echoes the method back. These reasons follow
//! [`super::copy_source`]'s stance instead — never built from request bytes — so the offending
//! value is named by position in the caller's own document, not repeated into the response.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{CorsConfiguration, CorsRule};

/// The most rules one bucket's configuration may carry: AWS's published cap.
pub const MAX_CORS_RULES: usize = 100;

/// The longest `ID` a rule may carry, in characters: AWS's published cap.
pub const MAX_CORS_ID_CHARS: usize = 255;

/// The closed set of HTTP methods a `<AllowedMethod>` element may name, upper case exactly.
///
/// `PATCH`, `OPTIONS` and lower-case spellings are all refusals: the set is AWS's, and a stored
/// value outside it would make the preflight runtime answer for a method S3 never serves.
pub const CORS_ALLOWED_METHODS: &[&str] = &["GET", "PUT", "POST", "DELETE", "HEAD"];

/// Why a decoded CORS document was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`CorsRejection::code`] and [`CorsRejection::reason`] are the
/// two halves an S3 error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsRejection {
    /// More than [`MAX_CORS_RULES`] rules.
    TooManyRules,
    /// A rule with no `<AllowedMethod>` at all. The member is required; the decoder cannot refuse
    /// it because the flattened spelling makes "absent" and "empty list" the same parse.
    MissingAllowedMethod,
    /// A rule with no `<AllowedOrigin>` at all.
    MissingAllowedOrigin,
    /// An `<AllowedMethod>` outside [`CORS_ALLOWED_METHODS`].
    UnsupportedMethod,
    /// An `<AllowedOrigin>` with more than one `*`.
    OriginWildcards,
    /// An `<AllowedHeader>` with more than one `*`.
    HeaderWildcards,
    /// An `<ExposeHeader>` with any `*`: the expose list supports no wildcard at all.
    ExposeHeaderWildcard,
    /// A negative `<MaxAgeSeconds>`.
    NegativeMaxAge,
    /// An `<ID>` longer than [`MAX_CORS_ID_CHARS`] characters.
    IdTooLong,
}

impl CorsRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A value outside a closed vocabulary, or a wildcard the grammar does not admit.
            CorsRejection::TooManyRules
            | CorsRejection::UnsupportedMethod
            | CorsRejection::OriginWildcards
            | CorsRejection::HeaderWildcards
            | CorsRejection::ExposeHeaderWildcard => ErrorCode::INVALID_REQUEST,
            // A bound violation on an otherwise well-formed member.
            CorsRejection::NegativeMaxAge | CorsRejection::IdTooLong => ErrorCode::INVALID_ARGUMENT,
            // A required member that is not there.
            CorsRejection::MissingAllowedMethod | CorsRejection::MissingAllowedOrigin => ErrorCode::MALFORMED_XML,
        }
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            CorsRejection::TooManyRules => "The CORS configuration allows a maximum of 100 CORSRules",
            CorsRejection::MissingAllowedMethod => "Each CORSRule must identify at least one AllowedMethod",
            CorsRejection::MissingAllowedOrigin => "Each CORSRule must identify at least one AllowedOrigin",
            CorsRejection::UnsupportedMethod => {
                "Found unsupported HTTP method in CORS config. Only GET, PUT, POST, DELETE and HEAD are allowed"
            }
            CorsRejection::OriginWildcards => "AllowedOrigin can not have more than one wildcard",
            CorsRejection::HeaderWildcards => "AllowedHeader can not have more than one wildcard",
            CorsRejection::ExposeHeaderWildcard => "ExposeHeader does not support wildcards",
            CorsRejection::NegativeMaxAge => "MaxAgeSeconds must be a non-negative integer",
            CorsRejection::IdTooLong => "ID must be no more than 255 characters",
        }
    }
}

/// Checks a decoded document against the family's semantic rules, first refusal wins.
///
/// Syntax only: nothing here matches an origin, a method or a header against a request — that
/// evaluation belongs to the preflight runtime and runs on a pre-auth path this crate does not
/// own. Rules are checked in document order and members in the order the wire carries them, so
/// the same document is refused for the same reason on every backend.
///
/// # Errors
///
/// [`CorsRejection`] naming the first rule the document breaks.
pub fn validate_cors(configuration: &CorsConfiguration) -> Result<(), CorsRejection> {
    if configuration.cors_rules.len() > MAX_CORS_RULES {
        return Err(CorsRejection::TooManyRules);
    }
    for rule in &configuration.cors_rules {
        validate_rule(rule)?;
    }
    Ok(())
}

fn validate_rule(rule: &CorsRule) -> Result<(), CorsRejection> {
    if rule.allowed_methods.is_empty() {
        return Err(CorsRejection::MissingAllowedMethod);
    }
    if rule.allowed_origins.is_empty() {
        return Err(CorsRejection::MissingAllowedOrigin);
    }
    if let Some(id) = rule.id.as_deref()
        && id.chars().count() > MAX_CORS_ID_CHARS
    {
        return Err(CorsRejection::IdTooLong);
    }
    for method in &rule.allowed_methods {
        // Case-sensitive on purpose: AWS stores and matches the upper-case spellings only, and a
        // stored `get` would be a rule the preflight runtime can never satisfy.
        if !CORS_ALLOWED_METHODS.contains(&method.as_str()) {
            return Err(CorsRejection::UnsupportedMethod);
        }
    }
    for origin in &rule.allowed_origins {
        if wildcards(origin) > 1 {
            return Err(CorsRejection::OriginWildcards);
        }
    }
    for header in &rule.allowed_headers {
        if wildcards(header) > 1 {
            return Err(CorsRejection::HeaderWildcards);
        }
    }
    for header in &rule.expose_headers {
        if wildcards(header) > 0 {
            return Err(CorsRejection::ExposeHeaderWildcard);
        }
    }
    if let Some(age) = rule.max_age_seconds
        && age < 0
    {
        return Err(CorsRejection::NegativeMaxAge);
    }
    Ok(())
}

/// How many `*` characters a value carries. Counted, not searched: the budget is "at most one",
/// so the second occurrence is the fact that matters.
fn wildcards(value: &str) -> usize {
    value.bytes().filter(|byte| *byte == b'*').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(methods: &[&str], origins: &[&str]) -> CorsRule {
        CorsRule {
            allowed_methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            allowed_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
            ..CorsRule::default()
        }
    }

    fn config(rules: Vec<CorsRule>) -> CorsConfiguration {
        CorsConfiguration { cors_rules: rules }
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_method_of_the_closed_set_is_accepted() {
        let document = config(vec![rule(&["GET", "PUT", "POST", "DELETE", "HEAD"], &["*"])]);
        assert_eq!(validate_cors(&document), Ok(()));
    }

    #[test]
    fn one_wildcard_is_within_budget_wherever_it_is_allowed() {
        let mut entry = rule(&["GET"], &["https://*.example.com"]);
        entry.allowed_headers = vec!["x-amz-*".to_owned()];
        assert_eq!(validate_cors(&config(vec![entry])), Ok(()));
    }

    #[test]
    fn the_rule_cap_is_inclusive() {
        let document = config((0..MAX_CORS_RULES).map(|_| rule(&["GET"], &["*"])).collect());
        assert_eq!(validate_cors(&document), Ok(()));
    }

    #[test]
    fn optional_members_at_their_bounds_are_accepted() {
        let mut entry = rule(&["GET"], &["*"]);
        entry.id = Some("i".repeat(MAX_CORS_ID_CHARS));
        entry.max_age_seconds = Some(0);
        assert_eq!(validate_cors(&config(vec![entry])), Ok(()));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_the_hundred_and_first_rule_is_refused() {
        let document = config((0..=MAX_CORS_RULES).map(|_| rule(&["GET"], &["*"])).collect());
        assert_eq!(validate_cors(&document), Err(CorsRejection::TooManyRules));
        assert_eq!(CorsRejection::TooManyRules.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_rule_without_a_method_is_malformed() {
        assert_eq!(validate_cors(&config(vec![rule(&[], &["*"])])), Err(CorsRejection::MissingAllowedMethod));
        assert_eq!(CorsRejection::MissingAllowedMethod.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_a_rule_without_an_origin_is_malformed() {
        assert_eq!(
            validate_cors(&config(vec![rule(&["GET"], &[])])),
            Err(CorsRejection::MissingAllowedOrigin)
        );
        assert_eq!(CorsRejection::MissingAllowedOrigin.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_a_method_outside_the_set_is_refused() {
        assert_eq!(
            validate_cors(&config(vec![rule(&["PATCH"], &["*"])])),
            Err(CorsRejection::UnsupportedMethod)
        );
        assert_eq!(CorsRejection::UnsupportedMethod.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_lower_case_method_is_refused() {
        assert_eq!(
            validate_cors(&config(vec![rule(&["get"], &["*"])])),
            Err(CorsRejection::UnsupportedMethod)
        );
    }

    #[test]
    fn n_options_is_not_an_allowed_method_even_though_preflight_uses_it() {
        assert_eq!(
            validate_cors(&config(vec![rule(&["OPTIONS"], &["*"])])),
            Err(CorsRejection::UnsupportedMethod)
        );
    }

    #[test]
    fn n_a_second_wildcard_in_an_origin_is_refused() {
        assert_eq!(
            validate_cors(&config(vec![rule(&["GET"], &["https://*.*.example.com"])])),
            Err(CorsRejection::OriginWildcards)
        );
        assert_eq!(CorsRejection::OriginWildcards.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_second_wildcard_in_an_allowed_header_is_refused() {
        let mut entry = rule(&["GET"], &["*"]);
        entry.allowed_headers = vec!["*-amz-*".to_owned()];
        assert_eq!(validate_cors(&config(vec![entry])), Err(CorsRejection::HeaderWildcards));
    }

    #[test]
    fn n_any_wildcard_in_an_expose_header_is_refused() {
        let mut entry = rule(&["GET"], &["*"]);
        entry.expose_headers = vec!["x-amz-*".to_owned()];
        assert_eq!(validate_cors(&config(vec![entry])), Err(CorsRejection::ExposeHeaderWildcard));
    }

    #[test]
    fn n_a_negative_max_age_is_refused_as_invalid_argument() {
        let mut entry = rule(&["GET"], &["*"]);
        entry.max_age_seconds = Some(-1);
        assert_eq!(validate_cors(&config(vec![entry])), Err(CorsRejection::NegativeMaxAge));
        assert_eq!(CorsRejection::NegativeMaxAge.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_an_id_over_the_cap_is_refused_as_invalid_argument() {
        let mut entry = rule(&["GET"], &["*"]);
        entry.id = Some("i".repeat(MAX_CORS_ID_CHARS + 1));
        assert_eq!(validate_cors(&config(vec![entry])), Err(CorsRejection::IdTooLong));
        assert_eq!(CorsRejection::IdTooLong.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_the_first_broken_rule_decides_the_refusal() {
        let document = config(vec![rule(&["GET"], &["*"]), rule(&["PATCH"], &[])]);
        // Presence is checked before values within a rule, so the missing origin of the second
        // rule wins over its unsupported method — one deterministic refusal per document.
        assert_eq!(validate_cors(&document), Err(CorsRejection::MissingAllowedOrigin));
    }

    #[test]
    fn n_the_status_side_of_each_code_is_the_one_aws_answers() {
        // The family's whole error surface, pinned to the statuses AWS answers — including the
        // 403 the preflight runtime will need, so that task inherits a mapping that already holds.
        assert_eq!(ErrorCode::NO_SUCH_CORS_CONFIGURATION.default_status().as_u16(), 404);
        assert_eq!(ErrorCode::ACCESS_FORBIDDEN.default_status().as_u16(), 403);
        assert_eq!(ErrorCode::INVALID_REQUEST.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::INVALID_ARGUMENT.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::MALFORMED_XML.default_status().as_u16(), 400);
    }
}
