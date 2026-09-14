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

//! Unit tests for `super` (`authz::plan`): the questions a requirement asks about its subjects,
//! and the fail-closed settling of their answers (ADR-0026).
//!
//! Responsible for: the order and count of questions for no subject, one subject, a set and every
//! account; one refused account refusing a set; every account refused without the broader action;
//! and a count that does not match refusing.
//! NOT responsible for: extraction (`super::super::rule`), or the facade asking.
//! Upstream: `super`. Downstream: nothing.

use super::*;
use crate::authz::{Everyone, WhenAbsent};
use crate::op::ResourceShape;

const A: Decision = Decision::Allow;
const D: Decision = Decision::Deny;
const I: Decision = Decision::Indeterminate;

const BULK_RULE: SubjectRule = SubjectRule::Set {
    param: "users",
    everyone: Some(Everyone {
        param: "all",
        action: "admin:ListUsers",
    }),
};
/// RustFS's builtin bulk listing: one action per account, `admin:ListUsers` for every account.
const BULK: AuthRequirement = AuthRequirement::new("admin:ListServiceAccounts", ResourceShape::Service).about_subject(BULK_RULE);
/// Two actions per account, any-of, with a broader action of its own.
const EITHER: AuthRequirement =
    AuthRequirement::any_of(&["admin:A", "admin:B"], ResourceShape::Service).about_subject(SubjectRule::Set {
        param: "users",
        everyone: Some(Everyone {
            param: "all",
            action: "admin:C",
        }),
    });
/// A set rule with no every-account form.
const NAMED_ONLY: AuthRequirement = AuthRequirement::new("admin:X", ResourceShape::Service).about_subject(SubjectRule::Set {
    param: "users",
    everyone: None,
});
const USER: AuthRequirement =
    AuthRequirement::any_of(&["admin:A", "admin:B"], ResourceShape::Service).about_subject(SubjectRule::Query {
        param: "accessKey",
        aliases: &[],
        when_absent: WhenAbsent::Refuse,
    });
const PLAIN: AuthRequirement = AuthRequirement::new("admin:X", ResourceShape::Service);

fn subjects(requirement: &AuthRequirement, query: &str) -> Subjects {
    requirement
        .subject()
        .expect("a subject rule")
        .extract(query)
        .expect("an acceptable query")
}

fn asked<'s>(requirement: &AuthRequirement, subjects: Option<&'s Subjects>) -> Vec<(&'static str, Option<&'s str>)> {
    (0..requirement.question_count(subjects))
        .map(|index| requirement.question(subjects, index).expect("within the count"))
        .map(|question| (question.action, question.subject.and_then(Subject::name)))
        .collect()
}

// ── the questions ───────────────────────────────────────────────────────────────────────────

/// Positive — no subject rule: one question per action, about no subject, as before ADR-0026.
#[test]
fn an_operation_without_a_subject_asks_each_action_once() {
    assert_eq!(asked(&PLAIN, None), [("admin:X", None)]);
    assert_eq!(PLAIN.question(None, 1), None);
}

/// Positive — one subject: every action about it.
#[test]
fn one_subject_is_asked_about_under_every_action() {
    let one = subjects(&USER, "accessKey=alice");
    assert_eq!(asked(&USER, Some(&one)), [("admin:A", Some("alice")), ("admin:B", Some("alice"))]);
}

/// Positive — a set: every action about every account, account by account, in request order.
#[test]
fn a_set_is_asked_about_every_account_under_every_action() {
    let set = subjects(&EITHER, "users=alice&users=bob");
    assert_eq!(
        asked(&EITHER, Some(&set)),
        [
            ("admin:A", Some("alice")),
            ("admin:B", Some("alice")),
            ("admin:A", Some("bob")),
            ("admin:B", Some("bob")),
        ]
    );
    let caller = subjects(&BULK, "");
    let questions: Vec<_> = (0..BULK.question_count(Some(&caller)))
        .filter_map(|index| BULK.question(Some(&caller), index))
        .collect();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].subject, Some(&Subject::Caller));
}

/// Positive — every account: the rule's actions, then the broader action, all about no subject.
#[test]
fn every_account_asks_the_rule_then_the_broader_action_about_no_subject() {
    let everyone = subjects(&BULK, "all=true");
    assert_eq!(
        asked(&BULK, Some(&everyone)),
        [("admin:ListServiceAccounts", None), ("admin:ListUsers", None)]
    );
    assert!((0..2).all(|index| {
        BULK.question(Some(&everyone), index)
            .is_some_and(|question| question.subject.is_none())
    }));
    assert_eq!(asked(&EITHER, Some(&everyone)), [("admin:A", None), ("admin:B", None), ("admin:C", None)]);
}

// ── the settling ────────────────────────────────────────────────────────────────────────────

/// Positive — every account of a set allowed: allowed, re-asking the first question.
#[test]
fn a_set_every_account_of_which_is_allowed_is_allowed() {
    let set = subjects(&BULK, "users=a&users=b&users=c");
    assert_eq!(
        BULK.decide(Some(&set), &[A, A, A]),
        Combined {
            decision: A,
            deciding: 0
        }
    );
}

/// Negative — one account refused refuses the whole set, naming that account's question.
#[test]
fn n_one_refused_account_refuses_the_set() {
    let set = subjects(&BULK, "users=a&users=b&users=c");
    assert_eq!(
        BULK.decide(Some(&set), &[A, A, D]),
        Combined {
            decision: D,
            deciding: 2
        }
    );
    assert_eq!(
        BULK.decide(Some(&set), &[A, I, A]),
        Combined {
            decision: I,
            deciding: 1
        }
    );
    assert_eq!(BULK.decide(Some(&set), &[D, A, A]).decision, D);
}

/// Positive and negative — the action rule applies per account: any-of needs one allowed action
/// for each account, not one across the set.
#[test]
fn the_action_rule_applies_to_each_account() {
    let set = subjects(&EITHER, "users=alice&users=bob");
    assert_eq!(
        EITHER.decide(Some(&set), &[D, A, A, D]),
        Combined {
            decision: A,
            deciding: 1
        }
    );
    assert_eq!(
        EITHER.decide(Some(&set), &[A, A, D, D]),
        Combined {
            decision: D,
            deciding: 2
        }
    );
}

/// Negative — every account without the broader action is refused, whatever the rule's own answer.
#[test]
fn n_every_account_without_the_broader_action_is_refused() {
    let everyone = subjects(&BULK, "all=true");
    assert_eq!(
        BULK.decide(Some(&everyone), &[A, D]),
        Combined {
            decision: D,
            deciding: 1
        }
    );
    assert_eq!(BULK.decide(Some(&everyone), &[A, I]).decision, I);
    assert_eq!(BULK.decide(Some(&everyone), &[D, A]).decision, D);
    assert_eq!(
        BULK.decide(Some(&everyone), &[A, A]),
        Combined {
            decision: A,
            deciding: 0
        }
    );
    assert_eq!(EITHER.decide(Some(&everyone), &[D, A, D]).decision, D);
    assert_eq!(EITHER.decide(Some(&everyone), &[D, A, A]).decision, A);
}

/// Negative — a count that does not match the questions is `Indeterminate`.
#[test]
fn n_a_count_that_does_not_match_the_questions_is_indeterminate() {
    let set = subjects(&BULK, "users=a&users=b");
    for decisions in [&[][..], &[A][..], &[A, A, A][..]] {
        assert_eq!(BULK.decide(Some(&set), decisions).decision, I, "{decisions:?}");
    }
    assert_eq!(PLAIN.decide(None, &[A]).decision, A);
    assert_eq!(PLAIN.decide(None, &[D]).decision, D);
    assert_eq!(PLAIN.decide(None, &[A, A]).decision, I);
}

/// Negative — every account under a rule with no every-account form asks nothing and is refused:
/// the one shape extraction never produces still fails closed.
#[test]
fn n_every_account_without_an_every_account_form_is_refused() {
    let everyone = Subjects::Everyone;
    assert_eq!(NAMED_ONLY.question_count(Some(&everyone)), 0);
    assert_eq!(NAMED_ONLY.question(Some(&everyone), 0), None);
    assert_eq!(NAMED_ONLY.decide(Some(&everyone), &[]).decision, I);
    assert_eq!(NAMED_ONLY.decide(Some(&everyone), &[A]).decision, I);
    assert_eq!(PLAIN.question_count(Some(&everyone)), 0);
}
