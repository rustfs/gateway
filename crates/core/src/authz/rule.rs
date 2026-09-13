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

//! How an operation's actions combine, and whose account it acts on (ADR-0025).
//!
//! Responsible for: [`ActionRule`] and its fail-closed [`ActionRule::combine`]; [`SubjectRule`],
//! its strict [`SubjectRule::extract`], and the [`Subject`] only extraction produces.
//! NOT responsible for: asking the authorizer (the facade asks one question per action), deciding
//! whether a named subject is the caller or one of the caller's accounts (the deployment's
//! `Authorizer`, which holds the identity store), or declaring a rule (`crate::op::AuthRequirement`).
//! Upstream: `crate::op`. Downstream: `crate::registry::reject`, `crate::request_context`, the facade.
//!
//! # Why the facade combines, and the authorizer is asked one action at a time
//!
//! An authorizer handed a set of actions and asked for one verdict can read only the first, and
//! for an all-of rule that is a silent allow. Asking one question per action keeps every existing
//! `Authorizer` correct unchanged, puts every question in the audit record, and leaves the
//! combination to one pure function here, which fails closed.
//!
//! # Why a subject is decoded here, once
//!
//! A contextual admin decision ("may this caller read *this* user?") is only as good as the
//! agreement between the name the authorizer judged and the name the handler acts on. So the
//! parameter is read exactly once, strictly: a repeated parameter, a key spelled with an escape, a
//! `+` whose meaning differs between form and URI decoding, a malformed escape or a control
//! character is refused before anything is authenticated, and the handler reads the decoded value
//! from its request context rather than parsing the query again.

use core::fmt;

use super::Decision;

/// How the actions of an [`crate::AuthRequirement`] combine into one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionRule {
    /// The requirement's one action.
    One,
    /// Every listed action must be allowed.
    AllOf(&'static [&'static str]),
    /// At least one listed action must be allowed: RustFS's `evaluate_admin_actions`.
    AnyOf(&'static [&'static str]),
}

/// The combined decision, and which action decided it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Combined {
    /// The one decision the pipeline settles.
    pub decision: Decision,
    /// The index of the action the second stage re-asks: the first allowed one of an any-of rule,
    /// the first refused one of a refused rule, and the first action otherwise.
    pub deciding: usize,
}

impl ActionRule {
    /// Combines one decision per action, in declaration order, into one decision.
    ///
    /// Fails closed: a count that does not match the rule's actions, or no decision at all, is
    /// `Indeterminate`. An all-of rule keeps its first refusal. An any-of rule allows on its first
    /// `Allow`; with none it is `Indeterminate` when any answer was, and `Deny` otherwise.
    #[must_use]
    pub fn combine(self, decisions: &[Decision]) -> Combined {
        let expected = match self {
            Self::One => 1,
            Self::AllOf(actions) | Self::AnyOf(actions) => actions.len(),
        };
        if decisions.is_empty() || decisions.len() != expected {
            return Combined {
                decision: Decision::Indeterminate,
                deciding: 0,
            };
        }
        match self {
            Self::One | Self::AllOf(_) => match decisions
                .iter()
                .enumerate()
                .find(|(_, decision)| **decision != Decision::Allow)
            {
                Some((deciding, decision)) => Combined {
                    decision: *decision,
                    deciding,
                },
                None => Combined {
                    decision: Decision::Allow,
                    deciding: 0,
                },
            },
            Self::AnyOf(_) => match decisions.iter().position(|decision| *decision == Decision::Allow) {
                Some(deciding) => Combined {
                    decision: Decision::Allow,
                    deciding,
                },
                None if decisions.contains(&Decision::Indeterminate) => Combined {
                    decision: Decision::Indeterminate,
                    deciding: 0,
                },
                None => Combined {
                    decision: Decision::Deny,
                    deciding: 0,
                },
            },
        }
    }
}

/// What an absent (or empty) subject parameter means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WhenAbsent {
    /// The caller's own account, as RustFS reads `ListServiceAccounts` without `user`.
    Caller,
    /// A `400`, as RustFS answers `user-info` without `accessKey`.
    Refuse,
}

/// Whose account an operation acts on, when that is part of its authorisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubjectRule {
    /// Always the caller's own account; the request cannot name another. RustFS's
    /// `CredentialOnly` routes. The action must be in the operation's own vendor namespace.
    Caller,
    /// The account one query parameter names. RustFS's `ContextualAuthorization` routes.
    Query {
        /// The parameter, spelled in RFC 3986 unreserved characters.
        param: &'static str,
        /// What its absence means.
        when_absent: WhenAbsent,
    },
}

/// The longest decoded subject accepted, in bytes.
pub const MAX_SUBJECT_BYTES: usize = 1024;

/// The account a request names, decoded once.
///
/// Only [`SubjectRule::extract`] produces a named one:
///
/// ```compile_fail,E0423
/// let forged = rustfs_gateway_core::SubjectName(Box::from("root"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SubjectName(Box<str>);

impl SubjectName {
    /// The decoded name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SubjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

/// Whose account one request acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// The caller's own account: the operation names no other, or the parameter was absent where
    /// absence means the caller.
    Caller,
    /// The account the request names. It may still be the caller's own, or one of the caller's
    /// service accounts; deciding that is the authorizer's job, because only it can look it up.
    Named(SubjectName),
}

impl Subject {
    /// The named account, when the request named one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Caller => None,
            Self::Named(name) => Some(name.as_str()),
        }
    }
}

/// Why a subject parameter was refused. Every refusal is a `400` before authentication, naming
/// the parameter and never echoing the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectError {
    /// The parameter is absent or empty and the rule refuses that.
    Absent,
    /// The parameter appears more than once.
    Repeated,
    /// A query key or the value is not strictly decodable, or carries an ambiguous `+` or a
    /// control character.
    Malformed,
    /// The decoded value is longer than [`MAX_SUBJECT_BYTES`].
    TooLong,
}

impl SubjectError {
    /// A constant explanation.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Absent => "the request names no account for an operation that requires one",
            Self::Repeated => "the account parameter appears more than once",
            Self::Malformed => "the query cannot be decoded unambiguously",
            Self::TooLong => "the account parameter is too long",
        }
    }
}

impl SubjectRule {
    /// Why this rule cannot be registered, or `None`.
    #[must_use]
    pub fn fault(self) -> Option<&'static str> {
        match self {
            Self::Caller => None,
            Self::Query { param, .. } if param.is_empty() || !param.bytes().all(is_unreserved) => {
                Some("a subject parameter is spelled in RFC 3986 unreserved characters and is not empty")
            }
            Self::Query { .. } => None,
        }
    }

    /// The subject one request names.
    ///
    /// # Errors
    ///
    /// A [`SubjectError`]: every query key is decoded strictly, so an escaped spelling of the
    /// parameter is the parameter, and a key that cannot be decoded refuses the request.
    pub fn extract(self, raw_query: &str) -> Result<Subject, SubjectError> {
        let Self::Query { param, when_absent } = self else {
            return Ok(Subject::Caller);
        };
        let mut found = None;
        for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            if decode_component(raw_key)? != param {
                continue;
            }
            if found.replace(raw_value).is_some() {
                return Err(SubjectError::Repeated);
            }
        }
        let value = match found {
            Some(raw) => decode_component(raw)?,
            None => String::new(),
        };
        if value.is_empty() {
            return match when_absent {
                WhenAbsent::Caller => Ok(Subject::Caller),
                WhenAbsent::Refuse => Err(SubjectError::Absent),
            };
        }
        if value.len() > MAX_SUBJECT_BYTES {
            return Err(SubjectError::TooLong);
        }
        Ok(Subject::Named(SubjectName(value.into_boxed_str())))
    }
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// One percent-decode, refusing a malformed escape, invalid UTF-8, a literal `+` and a control
/// character.
fn decode_component(raw: &str) -> Result<String, SubjectError> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => return Err(SubjectError::Malformed),
            b'%' => {
                let high = bytes.next().and_then(hex_value);
                let low = bytes.next().and_then(hex_value);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(SubjectError::Malformed);
                };
                decoded.push(high << 4 | low);
            }
            byte => decoded.push(byte),
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| SubjectError::Malformed)?;
    if text.chars().any(char::is_control) {
        return Err(SubjectError::Malformed);
    }
    Ok(text)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const A: Decision = Decision::Allow;
    const D: Decision = Decision::Deny;
    const I: Decision = Decision::Indeterminate;
    const TWO: &[&str] = &["admin:A", "admin:B"];

    const USER: SubjectRule = SubjectRule::Query {
        param: "accessKey",
        when_absent: WhenAbsent::Refuse,
    };
    const LIST: SubjectRule = SubjectRule::Query {
        param: "user",
        when_absent: WhenAbsent::Caller,
    };

    fn named(value: &str) -> Subject {
        Subject::Named(SubjectName(Box::from(value)))
    }

    #[test]
    fn any_of_allows_on_any_allow_and_names_the_allowed_action() {
        assert_eq!(
            ActionRule::AnyOf(TWO).combine(&[D, A]),
            Combined {
                decision: A,
                deciding: 1
            }
        );
        assert_eq!(
            ActionRule::AnyOf(TWO).combine(&[A, D]),
            Combined {
                decision: A,
                deciding: 0
            }
        );
        assert_eq!(ActionRule::AnyOf(TWO).combine(&[I, A]).decision, A);
    }

    #[test]
    fn n_any_of_with_no_allow_refuses_and_keeps_indeterminate_visible() {
        assert_eq!(ActionRule::AnyOf(TWO).combine(&[D, D]).decision, D);
        assert_eq!(ActionRule::AnyOf(TWO).combine(&[D, I]).decision, I);
        assert_eq!(ActionRule::AnyOf(TWO).combine(&[I, D]).decision, I);
    }

    #[test]
    fn all_of_allows_only_when_every_action_is_allowed() {
        assert_eq!(
            ActionRule::AllOf(TWO).combine(&[A, A]),
            Combined {
                decision: A,
                deciding: 0
            }
        );
    }

    #[test]
    fn n_all_of_missing_one_action_is_refused_with_that_actions_decision() {
        assert_eq!(
            ActionRule::AllOf(TWO).combine(&[A, D]),
            Combined {
                decision: D,
                deciding: 1
            }
        );
        assert_eq!(
            ActionRule::AllOf(TWO).combine(&[D, A]),
            Combined {
                decision: D,
                deciding: 0
            }
        );
        assert_eq!(ActionRule::AllOf(TWO).combine(&[A, I]).decision, I);
    }

    #[test]
    fn n_a_count_that_does_not_match_the_rule_is_indeterminate() {
        assert_eq!(ActionRule::AllOf(TWO).combine(&[A]).decision, I);
        assert_eq!(ActionRule::AnyOf(TWO).combine(&[A, A, A]).decision, I);
        assert_eq!(ActionRule::One.combine(&[]).decision, I);
        assert_eq!(ActionRule::One.combine(&[A, A]).decision, I);
        assert_eq!(ActionRule::One.combine(&[A]).decision, A);
        assert_eq!(ActionRule::One.combine(&[D]).decision, D);
    }

    #[test]
    fn a_named_subject_is_decoded_once() {
        assert_eq!(USER.extract("accessKey=alice"), Ok(named("alice")));
        assert_eq!(USER.extract("x=1&accessKey=cn%3Dbob%20smith&y"), Ok(named("cn=bob smith")));
        assert_eq!(SubjectRule::Caller.extract("accessKey=alice"), Ok(Subject::Caller));
    }

    #[test]
    fn n_an_escaped_spelling_of_the_parameter_is_the_parameter() {
        assert_eq!(USER.extract("access%4Bey=mallory"), Ok(named("mallory")));
        assert_eq!(USER.extract("accessKey=alice&access%4Bey=mallory"), Err(SubjectError::Repeated));
    }

    #[test]
    fn n_a_repeated_parameter_is_refused() {
        assert_eq!(USER.extract("accessKey=alice&accessKey=mallory"), Err(SubjectError::Repeated));
        assert_eq!(LIST.extract("user=&user=mallory"), Err(SubjectError::Repeated));
    }

    #[test]
    fn absence_means_what_the_rule_says() {
        assert_eq!(USER.extract(""), Err(SubjectError::Absent));
        assert_eq!(USER.extract("accessKey="), Err(SubjectError::Absent));
        assert_eq!(USER.extract("accessKey"), Err(SubjectError::Absent));
        assert_eq!(LIST.extract(""), Ok(Subject::Caller));
        assert_eq!(LIST.extract("user="), Ok(Subject::Caller));
    }

    #[test]
    fn n_ambiguous_or_malformed_spellings_are_refused() {
        for query in [
            "accessKey=a+b",
            "accessKey=a%2",
            "accessKey=a%zz",
            "accessKey=%ff",
            "accessKey=a%0Ab",
            "acc%ZZ=1&accessKey=a",
            "access+Key=a",
        ] {
            assert_eq!(USER.extract(query), Err(SubjectError::Malformed), "{query}");
        }
        let long = format!("accessKey={}", "a".repeat(MAX_SUBJECT_BYTES + 1));
        assert_eq!(USER.extract(&long), Err(SubjectError::TooLong));
        let longest = format!("accessKey={}", "a".repeat(MAX_SUBJECT_BYTES));
        assert!(USER.extract(&longest).is_ok());
    }

    #[test]
    fn n_a_parameter_outside_the_unreserved_set_cannot_be_registered() {
        for param in ["", "access key", "a&b", "a=b", "a%41"] {
            let rule = SubjectRule::Query {
                param,
                when_absent: WhenAbsent::Refuse,
            };
            assert!(rule.fault().is_some(), "{param:?}");
        }
        assert_eq!(USER.fault(), None);
        assert_eq!(SubjectRule::Caller.fault(), None);
    }
}
