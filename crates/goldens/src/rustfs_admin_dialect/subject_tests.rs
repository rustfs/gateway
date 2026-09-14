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

//! The generated order-4 operations' subject rules through the assembled service (ADR-0025,
//! ADR-0026, ADR-0028).
//!
//! Responsible for: an absent account refused with a `400` naming the parameter where RustFS
//! refuses it, and read as the caller where RustFS reads the caller; RustFS's alias spellings
//! (`access-key`, `user-dn`) naming no account; an own-account operation about the caller whatever
//! the query names; a repeated, malformed or oversized account refused before authorisation; a
//! set naming nobody being the caller, every account needing the broader action, a malformed set
//! refused before authorisation, and a set naming several accounts failing closed at the
//! signature.
//! NOT responsible for: the questions and answers of a well-formed request (`tests`), the rule
//! functions (`rustfs-gateway-core`), or the hand-written proof (`rustfs_admin_proof`).
//! Upstream: `super`. Downstream: nothing.

use rustfs_gateway_core::{MAX_SUBJECT_BYTES, MAX_SUBJECTS, SubjectRule, WhenAbsent};
use rustfs_gateway_dialect_rustfs_admin::{ROUTES, RouteRecord};
use rustfs_gateway_sig::RequestNow;

use super::{ACCOUNT, Exchange, declared, in_lanes, paths, signed_with, subject_param, unsigned_with, wire};

const LIST_USERS: &str = "admin:ListUsers";
const LIST_SERVICE_ACCOUNTS: &str = "admin:ListServiceAccounts";

/// Every `(record, path, query)` for each row of every operation whose rule `wanted` accepts, and
/// each query `queries` spells for its subject parameter.
fn cases(
    wanted: impl Fn(SubjectRule) -> bool,
    queries: impl Fn(&str) -> Vec<String>,
) -> Vec<(&'static RouteRecord, String, String)> {
    ROUTES
        .iter()
        .filter(|record| record.subject.is_some_and(&wanted))
        .flat_map(|record| {
            let param = subject_param(record).unwrap_or("accessKey");
            paths(record)
                .into_iter()
                .flat_map(|path| queries(param).into_iter().map(move |query| (record, path.clone(), query)))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn refused_before_authorising(exchange: &Exchange, at: &str, param: &str) {
    assert_eq!(exchange.status, 400, "{at}: {}", exchange.body);
    assert!(exchange.body.contains("<Code>InvalidArgument</Code>"), "{at}: {}", exchange.body);
    assert!(exchange.body.contains(param), "{at}: the parameter is not named: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran");
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
}

/// The route-stage questions, as `(action, subject)`.
fn route_questions(exchange: &Exchange) -> Vec<(&str, Option<Option<&str>>)> {
    exchange
        .asked
        .iter()
        .filter(|asked| asked.stage == "route")
        .map(|asked| (asked.action.as_str(), asked.subject.as_ref().map(Option::as_deref)))
        .collect()
}

fn about_the_caller(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
    assert!(!exchange.asked.is_empty(), "{at}: nobody was asked");
    assert!(
        exchange.asked.iter().all(|asked| asked.subject == Some(None)),
        "{at}: {:?}",
        exchange.asked
    );
    assert_eq!(exchange.handed[0].subjects, "caller", "{at}");
}

const fn refuses_absence(rule: SubjectRule) -> bool {
    matches!(
        rule,
        SubjectRule::Query {
            when_absent: WhenAbsent::Refuse,
            ..
        }
    )
}

const fn reads_absence_as_the_caller(rule: SubjectRule) -> bool {
    matches!(
        rule,
        SubjectRule::Query {
            when_absent: WhenAbsent::Caller,
            ..
        }
    )
}

// ── one account named in the query ────────────────────────────────────────────────────────────

/// Negative — where RustFS answers `400` to an absent account (`user-info`, `add-user`, and the
/// service-account info, update and delete routes, ADR-0028 (b)), an absent or empty parameter, or
/// only RustFS's `access-key` alias spelling, is a `400 InvalidArgument` naming the parameter,
/// before the authorizer is asked or any handler runs.
#[test]
fn n_a_refused_absence_is_a_400_naming_the_parameter() {
    let cases = cases(refuses_absence, |param| {
        vec![String::new(), format!("{param}="), format!("access-key={ACCOUNT}")]
    });
    assert_eq!(cases.len(), 6 * 2 * 3);
    in_lanes(declared, &cases, |assembled, (record, path, query)| {
        let exchange = assembled.exchange(wire(&signed_with(record, path, query)));
        refused_before_authorising(&exchange, &format!("{} {path}?{query}", record.method), "accessKey");
    });
}

/// Positive — where RustFS reads an absent account as the caller (`info-access-key`,
/// `list-service-accounts`, `idp/ldap/list-access-keys`), an absent or empty parameter, RustFS's
/// alias spellings (`access-key`, `user-dn`), or the parameter in another case, is about the
/// caller: every question and the handler's context say the caller, so no spelling the facade
/// does not read names an account it did not authorise (ADR-0028 (c)).
#[test]
fn an_absence_is_the_caller_where_ruled() {
    let cases = cases(reads_absence_as_the_caller, |param| {
        vec![
            String::new(),
            format!("{param}="),
            format!("access-key={ACCOUNT}"),
            format!("user-dn={ACCOUNT}"),
            format!("{}={ACCOUNT}", param.to_ascii_uppercase()),
        ]
    });
    assert_eq!(cases.len(), 3 * 2 * 5);
    let assembled = super::assemble(declared);
    for (record, path, query) in &cases {
        let exchange = assembled.exchange(wire(&signed_with(record, path, query)));
        about_the_caller(&exchange, &format!("{} {path}?{query}", record.method));
    }
}

/// Positive — an own-account operation reads no parameter: whatever account the query names, in
/// any spelling, every question and the handler are about the caller.
#[test]
fn an_own_account_operation_is_about_the_caller_whatever_the_query_names() {
    let query = format!("accessKey={ACCOUNT}&user={ACCOUNT}&userDN={ACCOUNT}&users={ACCOUNT}&all=true");
    let cases = cases(|rule| rule == SubjectRule::Caller, |_| vec![String::new(), query.clone()]);
    assert_eq!(cases.len(), 9 * 2 * 2);
    let assembled = super::assemble(declared);
    for (record, path, query) in &cases {
        let exchange = assembled.exchange(wire(&signed_with(record, path, query)));
        let at = format!("{} {path}?{query}", record.method);
        about_the_caller(&exchange, &at);
        assert!(exchange.asked.iter().all(|asked| asked.action.starts_with("rustfs:")), "{at}");
    }
}

/// Negative — a repeated account, one that does not decode unambiguously (`+`, a malformed
/// escape, a control character) or one longer than `MAX_SUBJECT_BYTES`, is a `400` naming the
/// parameter before authentication, on every named-account row. Unsigned on purpose: the refusal
/// precedes the signature, so it cannot depend on one.
#[test]
fn n_a_repeated_or_malformed_account_is_refused_before_authorising() {
    let long = "a".repeat(MAX_SUBJECT_BYTES + 1);
    let cases = cases(
        |rule| matches!(rule, SubjectRule::Query { .. }),
        |param| {
            vec![
                format!("{param}=a&{param}=b"),
                format!("{param}=a+b"),
                format!("{param}=a%zz"),
                format!("{param}=a%01"),
                format!("{param}={long}"),
            ]
        },
    );
    assert_eq!(cases.len(), 9 * 2 * 5);
    in_lanes(declared, &cases, |assembled, (record, path, query)| {
        let param = subject_param(record).expect("a named-account operation");
        let exchange = assembled.exchange(unsigned_with(record, path, query));
        refused_before_authorising(&exchange, &format!("{} {path}", record.method), param);
    });
}

// ── a set of accounts ─────────────────────────────────────────────────────────────────────────

const fn is_set(rule: SubjectRule) -> bool {
    matches!(rule, SubjectRule::Set { .. })
}

/// Positive — a bulk listing naming nobody, or with `all=false`, is about the caller alone.
#[test]
fn a_set_naming_nobody_is_the_caller() {
    let cases = cases(is_set, |_| vec![String::new(), "all=false".to_owned()]);
    assert_eq!(cases.len(), 3 * 2 * 2);
    let assembled = super::assemble(declared);
    for (record, path, query) in &cases {
        let exchange = assembled.exchange(wire(&signed_with(record, path, query)));
        about_the_caller(&exchange, &format!("{} {path}?{query}", record.method));
        assert_eq!(route_questions(&exchange), [(LIST_SERVICE_ACCOUNTS, Some(None))]);
    }
}

/// Positive and negative — every account asks the listing action and then `admin:ListUsers`,
/// both about no account; with both allowed the handler is told every account, and with only the
/// listing action, which is all a named account needs, the request is refused before the handler.
#[test]
fn every_account_needs_the_broader_action() {
    let cases = cases(is_set, |_| vec!["all=true".to_owned()]);
    assert_eq!(cases.len(), 3 * 2);
    let broader = super::assemble(|operation, action| declared(operation, action) || action == LIST_USERS);
    let listing_only = super::assemble(declared);
    for (record, path, query) in &cases {
        let at = format!("{} {path}?{query}", record.method);
        let questions = [(LIST_SERVICE_ACCOUNTS, None), (LIST_USERS, None)];
        let allowed = broader.exchange(wire(&signed_with(record, path, query)));
        assert_eq!(allowed.status, 200, "{at}: {}", allowed.body);
        assert_eq!(route_questions(&allowed), questions, "{at}");
        assert_eq!(allowed.handed[0].subjects, "everyone", "{at}");
        assert!(!allowed.handed[0].has_one_subject, "{at}");
        let refused = listing_only.exchange(wire(&signed_with(record, path, query)));
        assert_eq!(refused.status, 403, "{at}: {}", refused.body);
        assert!(refused.reached.is_empty(), "{at}");
        assert_eq!(route_questions(&refused), questions, "{at}");
    }
}

/// Negative — a duplicated, empty, contradictory or oversized set, or a flag that is not exactly
/// `true` or `false` or appears twice, is a `400` naming the parameter at fault before
/// authentication, on every bulk row.
#[test]
fn n_a_malformed_set_is_refused_before_authorising() {
    let oversized = (0..=MAX_SUBJECTS)
        .map(|index| format!("users=u{index}"))
        .collect::<Vec<_>>()
        .join("&");
    let spelled = [
        ("users=a&users=a", "users"),
        ("users=", "users"),
        ("users=a+b", "users"),
        ("all=true&users=a", "users"),
        (oversized.as_str(), "users"),
        ("all=yes", "all"),
        ("all=true&all=true", "all"),
    ];
    let cases = cases(is_set, |_| spelled.iter().map(|(query, _)| (*query).to_owned()).collect());
    assert_eq!(cases.len(), 3 * 2 * spelled.len());
    in_lanes(declared, &cases, |assembled, (record, path, query)| {
        let named = spelled
            .iter()
            .find(|(spelling, _)| spelling == query)
            .map(|(_, param)| *param)
            .expect("a spelled query");
        let exchange = assembled.exchange(unsigned_with(record, path, query));
        refused_before_authorising(&exchange, &format!("{} {path}", record.method), named);
    });
}

/// Negative — naming several accounts fails closed today (ADR-0026 (d)): the fixture signer
/// refuses to sign a repeated `users`, and a request signed over one account that arrives naming
/// a second is refused by the verifier's canonicalisation, before the authorizer is asked about
/// either account or any handler runs.
#[test]
fn n_naming_several_accounts_fails_closed_at_the_signature() {
    let cases = cases(is_set, |_| vec![format!("users={ACCOUNT}")]);
    let assembled = super::assemble(|_, _| true);
    for (record, path, query) in &cases {
        let at = format!("{} {path}", record.method);
        let several = signed_with(record, path, &format!("{query}&users=account-2"));
        assert!(
            several.wire_headers(RequestNow::capture()).is_err(),
            "{at}: a repeated parameter was signed"
        );
        let mut smuggled = wire(&signed_with(record, path, query));
        *smuggled.uri_mut() = format!("{path}?{query}&users=account-2").parse().expect("a URI");
        let exchange = assembled.exchange(smuggled);
        assert!(matches!(exchange.status, 400 | 403), "{at}: {} {}", exchange.status, exchange.body);
        assert!(exchange.reached.is_empty(), "{at}: a handler ran");
        assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
    }
    assert_eq!(cases.len(), 3 * 2);
}
