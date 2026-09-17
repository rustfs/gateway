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

//! An operation's action rule as the generator holds it: its actions, whose account it is about,
//! and whether it admits anonymous requests; how core renders it, how the generated module spells
//! it, and why a rule outside the ADRs' shapes is refused.
//!
//! Responsible for: [`Rule`] and its shape check [`Rule::fault`] (ADR-0025, ADR-0026, ADR-0028,
//! ADR-0029, ADR-0032), and the spelling checks [`is_action`] and [`is_parameter`].
//! NOT responsible for: which rule a route gets (`super::rulings`, `super::forms`) or the bucket
//! binding (`super::Bound`).
//! Upstream: `super::rulings`. Downstream: `super::plan`, `super::render`.

use super::VENDOR;
use super::rulings::{About, Absent, Ruled};

/// The actions of a rule, owned.
pub(super) enum Actions {
    One(String),
    AnyOf(Vec<String>),
}

/// An action rule, owned, whose account it is about, and whether it admits anonymous requests.
pub(super) struct Rule {
    pub(super) actions: Actions,
    pub(super) about: Option<About>,
    /// The operation opts in to anonymous requests under its own label (ADR-0026 (f)).
    pub(super) anonymous: bool,
}

impl Rule {
    pub(super) fn plain(action: String) -> Self {
        Self {
            actions: Actions::One(action),
            about: None,
            anonymous: false,
        }
    }

    pub(super) fn ruled(ruled: Ruled, about: Option<About>, anonymous: bool) -> Self {
        let actions = match ruled {
            Ruled::One(action) => Actions::One(action.to_owned()),
            Ruled::AnyOf(actions) => Actions::AnyOf(actions.iter().map(|action| (*action).to_owned()).collect()),
        };
        Self {
            actions,
            about,
            anonymous,
        }
    }

    /// Every action asked about a named account, in order.
    pub(super) fn actions(&self) -> Vec<&str> {
        match &self.actions {
            Actions::One(action) => vec![action.as_str()],
            Actions::AnyOf(actions) => actions.iter().map(String::as_str).collect(),
        }
    }

    /// As the overlay records it, which is how `AuthRequirement::render` spells it.
    pub(super) fn render(&self) -> String {
        let mut rendered = match &self.actions {
            Actions::One(action) => action.clone(),
            Actions::AnyOf(actions) => format!("anyOf({})", actions.join(", ")),
        };
        match self.about {
            Some(About::Caller) => rendered.push_str(" about caller"),
            Some(About::Query { param, aliases, absent }) => {
                let absent = match absent {
                    Absent::Caller => "caller",
                    Absent::Refuse => "refused",
                };
                let spellings: Vec<&str> = std::iter::once(param).chain(aliases.iter().copied()).collect();
                rendered.push_str(&format!(" about query({}, absent={absent})", spellings.join("|")));
            }
            Some(About::Set {
                param,
                everyone: Some((flag, action)),
            }) => rendered.push_str(&format!(" about each({param}, everyone={flag} ⇒ {action})")),
            Some(About::Set { param, everyone: None }) => rendered.push_str(&format!(" about each({param})")),
            None => {}
        }
        rendered
    }

    /// The subject rule as a Rust expression, when there is one.
    pub(super) fn subject_expression(&self) -> Option<String> {
        self.about.map(|about| match about {
            About::Caller => "SubjectRule::Caller".to_owned(),
            About::Query { param, aliases, absent } => {
                let aliases: Vec<String> = aliases.iter().map(|alias| format!("{alias:?}")).collect();
                format!(
                    "SubjectRule::Query {{ param: {param:?}, aliases: &[{}], when_absent: WhenAbsent::{absent:?} }}",
                    aliases.join(", ")
                )
            }
            About::Set {
                param,
                everyone: Some((flag, action)),
            } => format!(
                "SubjectRule::Set {{ param: {param:?}, everyone: Some(Everyone {{ param: {flag:?}, action: {action:?} }}) }}"
            ),
            About::Set { param, everyone: None } => format!("SubjectRule::Set {{ param: {param:?}, everyone: None }}"),
        })
    }

    /// Whether the rule reads the query parameter `param` for an account, under any spelling.
    pub(super) fn reads(&self, param: &str) -> bool {
        match self.about {
            Some(About::Query {
                param: account, aliases, ..
            }) => account == param || aliases.contains(&param),
            Some(About::Set {
                param: account,
                everyone,
            }) => account == param || everyone.is_some_and(|(flag, _)| flag == param),
            Some(About::Caller) | None => false,
        }
    }

    /// As a Rust expression on `resource` (`ResourceShape::Service` or `ResourceShape::Bucket`);
    /// a subject rule is the module's `SUBJECT`.
    pub(super) fn expression(&self, resource: &str) -> String {
        let requirement = match &self.actions {
            Actions::One(action) => format!("AuthRequirement::new({action:?}, {resource})"),
            Actions::AnyOf(actions) => {
                let listed: Vec<String> = actions.iter().map(|action| format!("{action:?}")).collect();
                format!("AuthRequirement::any_of(&[{}], {resource})", listed.join(", "))
            }
        };
        match self.about {
            Some(_) => format!("{requirement}.about_subject(SUBJECT)"),
            None => requirement,
        }
    }

    /// Why this rule is outside ADR-0025's and ADR-0026's shapes, or `None`. Registration refuses
    /// most of these too; refusing them here keeps a bad ruling from ever being generated.
    pub(super) fn fault(&self, query: Option<(&str, &str)>) -> Option<&'static str> {
        let actions = self.actions();
        if !actions.iter().copied().all(is_action) {
            return Some("an action is spelled `service:Action`");
        }
        if let Actions::AnyOf(listed) = &self.actions
            && (listed.len() < 2
                || listed
                    .iter()
                    .enumerate()
                    .any(|(index, action)| listed[..index].contains(action)))
        {
            return Some("an any-of rule names at least two actions, each once");
        }
        let own = |action: &str| action.split_once(':').is_some_and(|(service, _)| service == VENDOR);
        if self.anonymous {
            return match (&self.actions, self.about) {
                (Actions::One(label), None) if own(label) => None,
                _ => Some(
                    "an anonymous operation names exactly one action, a label in the dialect's own namespace, and no account",
                ),
            };
        }
        match self.about {
            Some(About::Caller) => {
                return match &self.actions {
                    Actions::One(label) if own(label) => None,
                    _ => Some("an own-account operation names exactly one action, a label in the dialect's own namespace"),
                };
            }
            _ if actions.iter().copied().any(own) => {
                return Some("a label in the dialect's own namespace authorises only an own-account operation");
            }
            Some(About::Query { param, .. } | About::Set { param, .. }) if !is_parameter(param) => {
                return Some("a subject parameter is spelled in RFC 3986 unreserved characters");
            }
            Some(About::Query { param, .. } | About::Set { param, .. }) if query.is_some_and(|(key, _)| key == param) => {
                return Some("a subject parameter is not the query key that selects the form");
            }
            Some(About::Query { param, aliases, .. }) => {
                if !aliases.iter().copied().all(is_parameter) {
                    return Some("a subject parameter is spelled in RFC 3986 unreserved characters");
                }
                if aliases
                    .iter()
                    .enumerate()
                    .any(|(index, alias)| *alias == param || aliases[..index].contains(alias))
                {
                    return Some("a subject parameter's spellings are distinct from one another");
                }
                if query.is_some_and(|(key, _)| aliases.contains(&key)) {
                    return Some("a subject parameter is not the query key that selects the form");
                }
            }
            Some(About::Set {
                param,
                everyone: Some((flag, action)),
            }) => {
                if !is_parameter(flag) || flag == param {
                    return Some("a set rule's every-account flag is an unreserved parameter of its own");
                }
                if !is_action(action) || own(action) {
                    return Some("a set rule's every-account action is an IAM action spelled `service:Action`");
                }
                if matches!(self.actions, Actions::One(_)) && actions.contains(&action) {
                    return Some("a set rule's every-account action is one no named-account question already asks");
                }
            }
            _ => {}
        }
        None
    }
}

pub(super) fn is_action(action: &str) -> bool {
    action
        .split_once(':')
        .is_some_and(|(service, name)| !service.is_empty() && !name.is_empty() && !name.contains(':'))
}

pub(super) fn is_parameter(param: &str) -> bool {
    !param.is_empty()
        && param
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}
