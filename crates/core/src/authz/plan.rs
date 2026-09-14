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

//! Which questions a requirement asks the authorizer at the route stage, and how their answers
//! settle into one decision (ADR-0025, ADR-0026).
//!
//! Responsible for: [`Question`], and three pure methods on [`AuthRequirement`]:
//! [`AuthRequirement::question_count`], [`AuthRequirement::question`] and
//! [`AuthRequirement::decide`]. None allocates, so the one-question path costs what it did.
//! NOT responsible for: asking (the facade, which asks every question so the audit record carries
//! each), extracting the subjects (`super::rule`), or combining one subject's actions
//! ([`super::ActionRule::combine`], which this reuses per subject).
//! Upstream: `crate::op::AuthRequirement`, `super::rule`. Downstream: the facade's route and input
//! stages.
//!
//! # The questions, in order
//!
//! One group of questions per subject, each group asking every action of the rule in declaration
//! order: one group for no subject or one subject, one per named account of a set. A request for
//! every account asks one group about no subject, then the rule's broader action about no
//! subject. The groups are all-of: every named account must be allowed under the rule, and every
//! account must be allowed under the broader action as well.

use super::{ActionRule, Combined, Decision, Subject, SubjectRule, Subjects};
use crate::op::AuthRequirement;

/// One route-stage question: an action, about an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Question<'s> {
    /// The action asked about.
    pub action: &'static str,
    /// The account asked about: `None` when the operation declares no subject rule, and for every
    /// question of a request for every account, which no own-account relaxation may answer.
    pub subject: Option<&'s Subject>,
}

impl AuthRequirement {
    /// The broader action a set rule's every-account form needs, when the rule has one.
    #[must_use]
    pub const fn everyone_action(&self) -> Option<&'static str> {
        match self.subject() {
            Some(SubjectRule::Set {
                everyone: Some(everyone),
                ..
            }) => Some(everyone.action),
            _ => None,
        }
    }

    /// How many route-stage questions this requirement asks about `subjects`. Zero only for a
    /// request for every account under a rule with no every-account form, which extraction never
    /// produces and [`Self::decide`] refuses.
    #[must_use]
    pub fn question_count(&self, subjects: Option<&Subjects>) -> usize {
        let per = self.actions().len();
        match subjects {
            None | Some(Subjects::One(_)) => per,
            Some(Subjects::Each(each)) => per.saturating_mul(each.len()),
            Some(Subjects::Everyone) => match self.everyone_action() {
                Some(_) => per.saturating_add(1),
                None => 0,
            },
        }
    }

    /// The `index`th question about `subjects`, in the order asked; `None` past the last.
    #[must_use]
    pub fn question<'s>(&self, subjects: Option<&'s Subjects>, index: usize) -> Option<Question<'s>> {
        let actions = self.actions();
        let per = actions.len();
        if per == 0 || index >= self.question_count(subjects) {
            return None;
        }
        let (group, within) = (index / per, index % per);
        let subject = match subjects {
            None => None,
            Some(Subjects::One(subject)) => Some(subject),
            Some(Subjects::Each(each)) => Some(each.get(group)?),
            Some(Subjects::Everyone) if index == per => {
                return self.everyone_action().map(|action| Question { action, subject: None });
            }
            Some(Subjects::Everyone) => None,
        };
        Some(Question {
            action: actions.get(within).copied()?,
            subject,
        })
    }

    /// Settles one decision per question, in the order [`Self::question`] numbers them.
    ///
    /// Fails closed: a count that does not match, or no question at all, is `Indeterminate`. Each
    /// subject's group is combined by the action rule, and the first group that is not allowed
    /// decides; for every account, the broader action must be allowed as well. `deciding` is the
    /// index of the question the input stage re-asks.
    #[must_use]
    pub fn decide(&self, subjects: Option<&Subjects>, decisions: &[Decision]) -> Combined {
        let per = self.actions().len();
        let count = self.question_count(subjects);
        if per == 0 || count == 0 || decisions.len() != count {
            return Combined {
                decision: Decision::Indeterminate,
                deciding: 0,
            };
        }
        let (groups, broader) = match subjects {
            Some(Subjects::Everyone) => decisions.split_at_checked(per).unwrap_or((decisions, &[])),
            _ => (decisions, &[][..]),
        };
        let rule: ActionRule = self.rule();
        let mut first_allowed = None;
        for (group, answers) in groups.chunks(per).enumerate() {
            let combined = rule.combine(answers);
            let deciding = group.saturating_mul(per).saturating_add(combined.deciding);
            if combined.decision != Decision::Allow {
                return Combined {
                    decision: combined.decision,
                    deciding,
                };
            }
            first_allowed.get_or_insert(deciding);
        }
        if let Some(broader) = broader.first()
            && *broader != Decision::Allow
        {
            return Combined {
                decision: *broader,
                deciding: per,
            };
        }
        Combined {
            decision: Decision::Allow,
            deciding: first_allowed.unwrap_or(0),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
#[path = "plan_tests.rs"]
mod tests;
