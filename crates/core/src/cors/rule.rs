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

//! Whether a stored CORS document admits this request, and by which rule.
//!
//! Responsible for: the three matching dimensions — origin, method, requested headers — their
//! case rules, the one-wildcard form each list member may carry, and the first-match choice
//! between rules. [`match_preflight`] answers an `OPTIONS`; [`match_actual`] answers the
//! non-preflight request that follows it.
//! NOT responsible for: deciding what a stored document may say (`crate::ops::shared::cors`,
//! which every write already passed), recognising a request as a preflight
//! ([`super::request`]), or rendering any header ([`super::answer`]).
//! Upstream: `rustfs-gateway-types`' `CorsConfiguration` dto. Downstream: [`super::answer`], and
//! the facade's preflight branch.
//!
//! # Why the matcher does not trust the wildcard budget it is promised
//!
//! `validate_cors` refuses a stored value with two `*`, so in this process no such rule can be
//! written. It can still be *read*: a document persisted by an earlier release outlives the
//! release that refused it, and the store is not this crate's. So [`wildcard_match`] splits on
//! the **first** `*` only and compares the remainder literally — a second wildcard therefore
//! matches nothing rather than being interpreted. That is fail-closed and, more importantly,
//! linear: a matcher that backtracked over several wildcards is the shape that turns a stored
//! configuration into a CPU amplifier.
//!
//! # Which comparisons are case-sensitive, and why they differ
//!
//! An origin is compared byte for byte, because an origin's scheme and host are already
//! normalised to lower case by the browser that sends it and a case-folding comparison would let
//! `https://EXAMPLE.com` satisfy a rule naming `https://example.com` — a distinction the rule
//! author may have meant. A method is compared byte for byte for the same reason the stored set
//! is upper case only. A header **name** is case-insensitive, because RFC 9110 §5.1 makes field
//! names case-insensitive and a browser is free to send `X-Amz-Acl` for a rule that says
//! `x-amz-acl`.

use rustfs_gateway_types::dto::{CorsConfiguration, CorsRule};

use super::request::RequestedHeaders;

/// What goes into `Access-Control-Allow-Origin`, and whether credentials may join it.
///
/// The three variants exist because the answer to "which origin is allowed" is not the same
/// question as "which bytes go in the header": a rule naming one origin literally can answer that
/// origin, the bare `*` can answer `*`, and a partial wildcard can answer neither — `*` would
/// widen `https://*.example.com` to every origin on the internet, so the request's own `Origin`
/// has to be echoed back.
///
/// Only [`AllowOrigin::Exact`] may ever be paired with `Access-Control-Allow-Credentials`; see
/// the CORS answer builder, where that exclusion is a property of the code rather than a rule to
/// remember.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowOrigin<'a> {
    /// The rule's value was exactly `*`.
    ///
    /// The literal `*` is answered rather than the request's origin, and that is the safer of the
    /// two: a browser refuses `*` outright when the request was made with credentials, so
    /// answering it makes the credentialed combination unreachable at the other end too.
    Wildcard,
    /// The rule named this origin with no wildcard in it, and the request's origin equals it.
    Exact(&'a str),
    /// The rule matched through a wildcard that was not the bare `*`, so this is the request's
    /// own origin, echoed. Credentials are unavailable here.
    Reflected(&'a str),
}

/// The rule that admitted a request, and what it says about the answer.
///
/// No `PartialEq`: the generated `CorsRule` dto has none, and giving this type a comparison that
/// skipped the rule would be a comparison two different rules satisfy.
#[derive(Clone, Copy, Debug)]
pub struct RuleMatch<'a> {
    /// Where in the document the winning rule sits, counted from zero.
    pub index: usize,
    /// The rule itself, so the answer can read its methods, expose list and max age from the
    /// **matched** rule rather than from the document as a whole.
    pub rule: &'a CorsRule,
    /// What `Access-Control-Allow-Origin` will carry.
    pub origin: AllowOrigin<'a>,
}

/// The first rule of `configuration` that admits this preflight, if any.
///
/// All three dimensions must hold on the *same* rule: an origin allowed by rule one and a method
/// allowed by rule two is not a match, and treating it as one would let two unrelated rules
/// compose into an allowance neither author wrote.
#[must_use]
pub fn match_preflight<'a>(
    configuration: &'a CorsConfiguration,
    origin: &'a str,
    method: &str,
    headers: &RequestedHeaders<'_>,
) -> Option<RuleMatch<'a>> {
    first_match(configuration, origin, method, Some(headers))
}

/// The first rule of `configuration` that admits an ordinary, non-preflight request.
///
/// There is no `Access-Control-Request-Headers` on such a request — the browser sends the headers
/// themselves — so the header dimension is not evaluated at all. Evaluating it against the
/// request's actual header set would refuse every request carrying `authorization`, which is
/// every signed request there is.
#[must_use]
pub fn match_actual<'a>(configuration: &'a CorsConfiguration, origin: &'a str, method: &str) -> Option<RuleMatch<'a>> {
    first_match(configuration, origin, method, None)
}

fn first_match<'a>(
    configuration: &'a CorsConfiguration,
    origin: &'a str,
    method: &str,
    headers: Option<&RequestedHeaders<'_>>,
) -> Option<RuleMatch<'a>> {
    for (index, rule) in configuration.cors_rules.iter().enumerate() {
        if !method_allowed(rule, method) {
            continue;
        }
        if let Some(requested) = headers
            && !headers_allowed(rule, requested)
        {
            continue;
        }
        if let Some(allow) = origin_allowed(rule, origin) {
            return Some(RuleMatch {
                index,
                rule,
                origin: allow,
            });
        }
    }
    None
}

/// Which `AllowedOrigin` of this rule admits `origin`, and in what form.
///
/// First value wins within a rule, so a rule listing both `*` and `https://a.example` answers
/// `*` for a request from `https://a.example` — the document order is the author's own statement
/// of precedence and nothing here reorders it.
fn origin_allowed<'a>(rule: &'a CorsRule, origin: &'a str) -> Option<AllowOrigin<'a>> {
    for allowed in &rule.allowed_origins {
        if allowed == "*" {
            return Some(AllowOrigin::Wildcard);
        }
        if allowed.contains('*') {
            if wildcard_match(allowed, origin) {
                return Some(AllowOrigin::Reflected(origin));
            }
        } else if allowed == origin {
            return Some(AllowOrigin::Exact(allowed));
        }
    }
    None
}

/// Whether the rule names this method. Byte for byte, upper case only.
fn method_allowed(rule: &CorsRule, method: &str) -> bool {
    rule.allowed_methods.iter().any(|allowed| allowed == method)
}

/// Whether the rule admits **every** requested header name.
///
/// All or nothing on purpose. A partial allowance would answer a preflight that the browser then
/// treats as permission for the whole request, and the header the rule did not name would go out
/// anyway — so "allow the ones I recognise" is not a weaker answer, it is a wrong one.
fn headers_allowed(rule: &CorsRule, requested: &RequestedHeaders<'_>) -> bool {
    requested.names().all(|name| {
        rule.allowed_headers
            .iter()
            .any(|allowed| ascii_ci_wildcard_match(allowed, name))
    })
}

/// Whether `value` satisfies a pattern carrying at most one `*`.
///
/// A pattern with no `*` is an equality test. A pattern with one `*` is a prefix and a suffix
/// that may not overlap: `https://*.example.com` matches `https://a.example.com`, and — because
/// `*` may stand for the empty string — also `https://.example.com`. A pattern with two `*`
/// keeps the second one as a literal character of the suffix and therefore matches nothing that
/// does not contain a literal asterisk; see the module documentation for why that is deliberate.
#[must_use]
pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == value;
    };
    value.len() >= prefix.len() + suffix.len() && value.starts_with(prefix) && value.ends_with(suffix)
}

/// [`wildcard_match`] over ASCII-case-folded bytes, for header names.
fn ascii_ci_wildcard_match(pattern: &str, value: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern.eq_ignore_ascii_case(value);
    };
    if value.len() < prefix.len() + suffix.len() {
        return false;
    }
    let head = value.get(..prefix.len());
    let tail = value.get(value.len() - suffix.len()..);
    match (head, tail) {
        (Some(head), Some(tail)) => head.eq_ignore_ascii_case(prefix) && tail.eq_ignore_ascii_case(suffix),
        // Unreachable for ASCII patterns and lengths checked above; a non-ASCII boundary is
        // answered as "no match" rather than by slicing across a code point.
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cors::request::RequestedHeaders;

    fn rule(methods: &[&str], origins: &[&str]) -> CorsRule {
        CorsRule {
            allowed_methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            allowed_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
            ..CorsRule::default()
        }
    }

    fn with_headers(mut base: CorsRule, headers: &[&str]) -> CorsRule {
        base.allowed_headers = headers.iter().map(|h| (*h).to_owned()).collect();
        base
    }

    fn config(rules: Vec<CorsRule>) -> CorsConfiguration {
        CorsConfiguration { cors_rules: rules }
    }

    fn requested(value: &str) -> RequestedHeaders<'_> {
        RequestedHeaders::parse(value).expect("a readable Access-Control-Request-Headers value")
    }

    const NONE: RequestedHeaders<'static> = RequestedHeaders::empty();

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    /// Positive — the smallest rule that can admit anything does.
    #[test]
    fn an_exact_origin_and_method_match() {
        let document = config(vec![rule(&["GET"], &["https://example.com"])]);
        let found = match_preflight(&document, "https://example.com", "GET", &NONE).expect("a match");
        assert_eq!(found.index, 0);
        assert_eq!(found.origin, AllowOrigin::Exact("https://example.com"));
    }

    /// Positive — the bare `*` answers the literal `*`, not the caller's origin. Answering the
    /// caller's origin here would make the credentialed combination expressible; `*` cannot be.
    #[test]
    fn the_bare_star_answers_the_literal_star() {
        let document = config(vec![rule(&["GET"], &["*"])]);
        let found = match_preflight(&document, "https://anything.invalid", "GET", &NONE).expect("a match");
        assert_eq!(found.origin, AllowOrigin::Wildcard);
    }

    /// Positive — a partial wildcard answers the request's own origin. `*` would widen the rule
    /// from "any subdomain of example.com" to "every origin there is".
    #[test]
    fn a_partial_wildcard_reflects_the_concrete_origin() {
        let document = config(vec![rule(&["GET"], &["https://*.example.com"])]);
        let found = match_preflight(&document, "https://app.example.com", "GET", &NONE).expect("a match");
        assert_eq!(found.origin, AllowOrigin::Reflected("https://app.example.com"));
    }

    /// Positive — a trailing wildcard in an allowed header admits every requested name under it,
    /// and the comparison folds case in both directions.
    #[test]
    fn a_header_wildcard_admits_every_requested_name() {
        let document = config(vec![with_headers(rule(&["PUT"], &["*"]), &["x-amz-*"])]);
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &requested("X-Amz-Acl, x-amz-meta-a")).is_some());
    }

    /// Positive — a rule naming a header with **no** wildcard still admits the spelling a browser
    /// happens to send. RFC 9110 §5.1 makes field names case-insensitive, and this is the branch
    /// that says so: the wildcard case above folds case on its own code path, so without this
    /// assertion the plain-equality path could be case-sensitive and nothing would notice. It was
    /// exactly that, and a mutation of the fold is what found it.
    #[test]
    fn a_header_named_without_a_wildcard_is_matched_case_insensitively() {
        let document = config(vec![with_headers(rule(&["PUT"], &["*"]), &["x-amz-acl"])]);
        for spelling in ["x-amz-acl", "X-Amz-Acl", "X-AMZ-ACL"] {
            assert!(
                match_preflight(&document, "https://a.invalid", "PUT", &requested(spelling)).is_some(),
                "`{spelling}` was not admitted by a rule naming `x-amz-acl`"
            );
        }
        // And the fold is a fold, not a "matches anything": a different name is still refused.
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &requested("x-amz-acx")).is_none());
    }

    /// Positive — first match decides, and the answer reads its max age from the rule that won
    /// rather than from the first rule in the document.
    #[test]
    fn the_first_matching_rule_decides() {
        let mut second = rule(&["PUT"], &["https://b.invalid"]);
        second.max_age_seconds = Some(77);
        let document = config(vec![rule(&["GET"], &["https://a.invalid"]), second]);
        let found = match_preflight(&document, "https://b.invalid", "PUT", &NONE).expect("a match");
        assert_eq!(found.index, 1);
        assert_eq!(found.rule.max_age_seconds, Some(77));
    }

    /// Positive — an actual request is matched on origin and method alone; it carries no
    /// `Access-Control-Request-Headers` and evaluating its real header set would refuse every
    /// signed request.
    #[test]
    fn an_actual_request_ignores_the_header_dimension() {
        let document = config(vec![with_headers(rule(&["GET"], &["https://a.invalid"]), &["x-amz-acl"])]);
        assert!(match_actual(&document, "https://a.invalid", "GET").is_some());
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    /// Negative — a different origin is refused although the method matches. The origin dimension
    /// has to be able to refuse on its own.
    #[test]
    fn n_a_foreign_origin_is_refused() {
        let document = config(vec![rule(&["GET"], &["https://example.com"])]);
        assert!(match_preflight(&document, "https://evil.invalid", "GET", &NONE).is_none());
    }

    /// Negative — an origin compares byte for byte, so a case-shifted host does not match.
    #[test]
    fn n_an_origin_is_case_sensitive() {
        let document = config(vec![rule(&["GET"], &["https://example.com"])]);
        assert!(match_preflight(&document, "https://EXAMPLE.com", "GET", &NONE).is_none());
    }

    /// Negative — the wildcard's prefix and suffix are both required, so a sibling domain that
    /// merely ends the same way is refused. `https://evil.com` must not satisfy
    /// `https://*.example.com`, and neither must a host that only carries the suffix.
    #[test]
    fn n_a_wildcard_does_not_admit_a_neighbouring_domain() {
        let document = config(vec![rule(&["GET"], &["https://*.example.com"])]);
        assert!(match_preflight(&document, "https://example.com.evil.invalid", "GET", &NONE).is_none());
        assert!(match_preflight(&document, "http://app.example.com", "GET", &NONE).is_none());
    }

    /// Negative — the prefix and the suffix may not overlap, so a value shorter than the two of
    /// them together is refused. Without the length test `https://*.example.com` would match
    /// `https://.example.com`'s truncations by starting and ending on the same bytes.
    #[test]
    fn n_a_wildcard_needs_room_for_both_halves() {
        assert!(!wildcard_match("abc*abc", "abcabc".get(..5).expect("ascii")));
        assert!(wildcard_match("abc*abc", "abcabc"));
    }

    /// Negative — a second wildcard is not interpreted. A stored document from an older release
    /// cannot become a wider rule than the validator would accept today.
    #[test]
    fn n_a_second_wildcard_is_a_literal() {
        assert!(!wildcard_match("https://*.*.example.com", "https://a.b.example.com"));
        assert!(wildcard_match("https://*.*.example.com", "https://a.*.example.com"));
    }

    /// Negative — a method the rule does not name is refused although the origin matches. The
    /// method dimension has to be able to refuse on its own.
    #[test]
    fn n_an_unnamed_method_is_refused() {
        let document = config(vec![rule(&["GET"], &["*"])]);
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &NONE).is_none());
    }

    /// Negative — a method compares byte for byte, so the lower-case spelling a hand-written
    /// client might send does not match the stored upper-case value.
    #[test]
    fn n_a_method_is_case_sensitive() {
        let document = config(vec![rule(&["GET"], &["*"])]);
        assert!(match_preflight(&document, "https://a.invalid", "get", &NONE).is_none());
    }

    /// Negative — one unlisted header refuses the whole preflight. Partial allowance is the
    /// dangerous answer: the browser would send the unlisted header anyway.
    #[test]
    fn n_one_unlisted_header_refuses_the_whole_request() {
        let document = config(vec![with_headers(rule(&["PUT"], &["*"]), &["x-amz-acl"])]);
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &requested("x-amz-acl")).is_some());
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &requested("x-amz-acl, x-custom")).is_none());
    }

    /// Negative — a rule with no `AllowedHeader` admits no requested header at all, while still
    /// admitting a preflight that requests none.
    #[test]
    fn n_a_rule_without_allowed_headers_admits_no_requested_header() {
        let document = config(vec![rule(&["PUT"], &["*"])]);
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &NONE).is_some());
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &requested("x-amz-acl")).is_none());
    }

    /// Negative — the three dimensions must hold on one rule. Two rules that each satisfy part of
    /// the request compose into no allowance at all.
    #[test]
    fn n_two_rules_do_not_compose_into_one_allowance() {
        let document = config(vec![rule(&["GET"], &["https://a.invalid"]), rule(&["PUT"], &["https://b.invalid"])]);
        assert!(match_preflight(&document, "https://a.invalid", "PUT", &NONE).is_none());
    }

    /// Negative — an empty document admits nothing. `is_none` here is what makes a bucket whose
    /// configuration was deleted equivalent to one that never had one.
    #[test]
    fn n_an_empty_document_admits_nothing() {
        assert!(match_preflight(&config(vec![]), "https://a.invalid", "GET", &NONE).is_none());
        assert!(match_actual(&config(vec![]), "https://a.invalid", "GET").is_none());
    }

    /// Negative — a rule whose origin list is empty cannot be reached through the method
    /// dimension. `validate_cors` refuses such a document on write; a stored one still matches
    /// nothing.
    #[test]
    fn n_a_rule_with_no_origin_matches_nothing() {
        let document = config(vec![rule(&["GET"], &[])]);
        assert!(match_preflight(&document, "https://a.invalid", "GET", &NONE).is_none());
    }
}
