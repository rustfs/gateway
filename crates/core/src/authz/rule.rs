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

//! How an operation's actions combine, and whose accounts it acts on (ADR-0025, ADR-0026).
//!
//! Responsible for: [`ActionRule`] and its fail-closed [`ActionRule::combine`]; [`SubjectRule`],
//! its strict [`SubjectRule::extract`], and the [`Subjects`] only extraction produces.
//! NOT responsible for: asking the authorizer or settling a set of answers (`super::plan`, and
//! the facade that asks), deciding whether a named subject is the caller or one of the caller's
//! accounts (the deployment's `Authorizer`, which holds the identity store), decoding a query
//! component (`super::query`), or declaring a rule (`crate::op::AuthRequirement`).
//! Upstream: `crate::op`. Downstream: `super::plan`, `crate::registry::reject`,
//! `crate::request_context`, the facade.
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
//!
//! # Why a set of accounts is bounded, and every account is asked about (ADR-0026)
//!
//! A set rule is the one place a request chooses how many questions the authorizer is asked, so
//! [`MAX_SUBJECTS`] caps it. A name repeated in the set, or an empty one, is refused rather than
//! skipped: a handler that dropped or merged it would act on a different set from the one judged.
//! And "every account" is not a longer list: it is a flag, and it needs a broader action of its
//! own, because no answer about named accounts can imply one about accounts nobody named.

use core::fmt;

use super::Decision;
use super::query::{self, QueryParamError};

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

/// The combined decision, and which question decided it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Combined {
    /// The one decision the pipeline settles.
    pub decision: Decision,
    /// The index of the question the second stage re-asks: the first allowed one of an any-of
    /// rule, the first refused one of a refused rule, and the first question otherwise.
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

/// A set rule's every-account form (ADR-0026): the flag that asks for it, and the broader action it
/// needs on top of the operation's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Everyone {
    /// The flag parameter, whose value is exactly `true` or `false`: RustFS's `all`.
    pub param: &'static str,
    /// The broader action every account needs, distinct from the operation's own actions:
    /// RustFS's `admin:ListUsers`. Asked about no subject, so no own-account relaxation answers it.
    pub action: &'static str,
}

/// Whose account an operation acts on, when that is part of its authorisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubjectRule {
    /// Always the caller's own account; the request cannot name another. RustFS's
    /// `CredentialOnly` routes. The action must be in the operation's own vendor namespace.
    Caller,
    /// The account one query parameter names. RustFS's `ContextualAuthorization` routes.
    Query {
        /// The canonical parameter, spelled in RFC 3986 unreserved characters. A refusal names it.
        param: &'static str,
        /// Other spellings of the same parameter, each exact and unreserved, as RustFS reads
        /// `access-key` for `accessKey` (ADR-0029). At most one spelling may appear, once.
        aliases: &'static [&'static str],
        /// What its absence means.
        when_absent: WhenAbsent,
    },
    /// The accounts a repeated query parameter names, or every account (ADR-0026). RustFS's bulk
    /// access-key listings. Naming none is the caller.
    Set {
        /// The repeated parameter naming each account: RustFS's `users`.
        param: &'static str,
        /// The every-account form, or `None` when the operation never acts on every account.
        everyone: Option<Everyone>,
    },
}

/// The longest decoded subject accepted, in bytes.
pub const MAX_SUBJECT_BYTES: usize = 1024;

/// The most accounts one set-rule request may name: each is one more question per action.
pub const MAX_SUBJECTS: usize = 32;

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

/// Whose account one authorizer question is about.
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

/// Whose accounts one request acts on, as extraction decided it (ADR-0026).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subjects {
    /// One account: every [`SubjectRule::Caller`] and [`SubjectRule::Query`] request, and a set
    /// request that names nobody, which is about the caller.
    One(Subject),
    /// The accounts a set request names, each exactly once, in request order, at most
    /// [`MAX_SUBJECTS`] of them. Every one is a [`Subject::Named`], and every one is asked about.
    Each(Box<[Subject]>),
    /// Every account: a set request's flag. Asked about no subject, under the operation's actions
    /// and the rule's broader one.
    Everyone,
}

impl Subjects {
    /// The one subject of a single-subject request; `None` for a set of accounts or every account.
    #[must_use]
    pub const fn one(&self) -> Option<&Subject> {
        match self {
            Self::One(subject) => Some(subject),
            Self::Each(_) | Self::Everyone => None,
        }
    }
}

/// Why a subject parameter was refused. Every refusal is a `400` before authentication, naming
/// the parameter and never echoing the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectError {
    /// The parameter is absent or empty and the rule refuses that.
    Absent,
    /// The parameter appears more than once where one is expected: a single subject, or a set
    /// rule's every-account flag.
    Repeated,
    /// A query key or the value is not strictly decodable, carries an ambiguous `+` or a control
    /// character, or a set names an empty account.
    Malformed,
    /// The decoded value is longer than [`MAX_SUBJECT_BYTES`].
    TooLong,
    /// A set names one account twice.
    Duplicate,
    /// A set names more than [`MAX_SUBJECTS`] accounts.
    TooMany,
    /// A set names accounts and asks for every account at once.
    Contradictory,
    /// The every-account flag is neither `true` nor `false`.
    Flag,
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
            Self::Duplicate => "an account is named more than once",
            Self::TooMany => "the request names more accounts than one request may",
            Self::Contradictory => "the request names accounts and asks for every account at once",
            Self::Flag => "the every-account parameter is neither `true` nor `false`",
        }
    }
}

impl From<QueryParamError> for SubjectError {
    fn from(error: QueryParamError) -> Self {
        match error {
            QueryParamError::Repeated => Self::Repeated,
            QueryParamError::Malformed => Self::Malformed,
        }
    }
}

impl SubjectRule {
    /// Why this rule cannot be registered, or `None`. A set rule's broader action is checked
    /// against the operation's own actions by `crate::AuthRequirement::fault`.
    #[must_use]
    pub fn fault(self) -> Option<&'static str> {
        const SPELLING: &str = "a subject parameter is spelled in RFC 3986 unreserved characters and is not empty";
        match self {
            Self::Caller => None,
            Self::Query { param, aliases, .. } => {
                if !is_parameter(param) || !aliases.iter().all(|alias| is_parameter(alias)) {
                    return Some(SPELLING);
                }
                let spellings = || core::iter::once(param).chain(aliases.iter().copied());
                spellings()
                    .enumerate()
                    .any(|(index, spelling)| spellings().take(index).any(|earlier| earlier == spelling))
                    .then_some("a subject parameter's spellings are distinct from one another")
            }
            Self::Set { param, .. } if !is_parameter(param) => Some(SPELLING),
            Self::Set {
                everyone: Some(everyone),
                ..
            } if !is_parameter(everyone.param) => Some(SPELLING),
            Self::Set {
                param,
                everyone: Some(everyone),
            } if everyone.param == param => Some("a set rule's every-account flag is a parameter of its own"),
            Self::Set { .. } => None,
        }
    }

    /// The parameter a refusal is about, for the `400` that names it.
    #[must_use]
    pub const fn refused_param(self, error: SubjectError) -> Option<&'static str> {
        match (self, error) {
            (Self::Caller, _) => None,
            (Self::Query { param, .. } | Self::Set { param, everyone: None }, _) => Some(param),
            (
                Self::Set {
                    everyone: Some(everyone),
                    ..
                },
                SubjectError::Repeated | SubjectError::Flag,
            ) => Some(everyone.param),
            (Self::Set { param, .. }, _) => Some(param),
        }
    }

    /// The accounts one request names.
    ///
    /// # Errors
    ///
    /// A [`SubjectError`]: every query key is decoded strictly, so an escaped spelling of the
    /// parameter is the parameter, and a key that cannot be decoded refuses the request.
    pub fn extract(self, raw_query: &str) -> Result<Subjects, SubjectError> {
        match self {
            Self::Caller => Ok(Subjects::One(Subject::Caller)),
            Self::Query {
                param,
                aliases,
                when_absent,
            } => {
                let value = match query::single_raw_value_of(raw_query, param, aliases)? {
                    Some(raw) => query::decode_component(raw)?,
                    None => String::new(),
                };
                if value.is_empty() {
                    return match when_absent {
                        WhenAbsent::Caller => Ok(Subjects::One(Subject::Caller)),
                        WhenAbsent::Refuse => Err(SubjectError::Absent),
                    };
                }
                Ok(Subjects::One(named(value)?))
            }
            Self::Set { param, everyone } => extract_set(raw_query, param, everyone),
        }
    }
}

/// A set: each `param` value once, at most [`MAX_SUBJECTS`], never empty; the flag at most once
/// and exactly `true` or `false`; never both a name and `true`.
fn extract_set(raw_query: &str, param: &str, everyone: Option<Everyone>) -> Result<Subjects, SubjectError> {
    let mut each: Vec<Subject> = Vec::new();
    let mut flag = None;
    for (raw_key, raw_value) in query::pairs(raw_query) {
        let key = query::decode_component(raw_key)?;
        if key == param {
            let value = query::decode_component(raw_value)?;
            if value.is_empty() {
                return Err(SubjectError::Malformed);
            }
            if each.iter().any(|subject| subject.name() == Some(value.as_str())) {
                return Err(SubjectError::Duplicate);
            }
            if each.len() >= MAX_SUBJECTS {
                return Err(SubjectError::TooMany);
            }
            each.push(named(value)?);
        } else if let Some(everyone) = everyone
            && key == everyone.param
        {
            let asked = match query::decode_component(raw_value)?.as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(SubjectError::Flag),
            };
            if flag.replace(asked).is_some() {
                return Err(SubjectError::Repeated);
            }
        }
    }
    match (flag == Some(true), each.is_empty()) {
        (true, false) => Err(SubjectError::Contradictory),
        (true, true) => Ok(Subjects::Everyone),
        (false, true) => Ok(Subjects::One(Subject::Caller)),
        (false, false) => Ok(Subjects::Each(each.into_boxed_slice())),
    }
}

fn named(value: String) -> Result<Subject, SubjectError> {
    if value.len() > MAX_SUBJECT_BYTES {
        return Err(SubjectError::TooLong);
    }
    Ok(Subject::Named(SubjectName(value.into_boxed_str())))
}

fn is_parameter(param: &str) -> bool {
    !param.is_empty() && param.bytes().all(is_unreserved)
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
#[path = "rule_tests.rs"]
mod tests;
