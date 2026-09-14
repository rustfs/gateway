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

//! Unit tests for `super` (`authz::rule`): combining one subject's actions, and extracting a
//! single subject or a set of them (ADR-0025, ADR-0026).
//!
//! Responsible for: every combination rule, every extraction refusal and every registration fault
//! of a subject rule.
//! NOT responsible for: the questions across subjects (`super::super::plan`), or registration as a
//! whole (`crate::registry::reject_rule_tests`).
//! Upstream: `super`. Downstream: nothing.

use super::*;

const A: Decision = Decision::Allow;
const D: Decision = Decision::Deny;
const I: Decision = Decision::Indeterminate;
const TWO: &[&str] = &["admin:A", "admin:B"];

const USER: SubjectRule = SubjectRule::Query {
    param: "accessKey",
    aliases: &[],
    when_absent: WhenAbsent::Refuse,
};
const LIST: SubjectRule = SubjectRule::Query {
    param: "user",
    aliases: &[],
    when_absent: WhenAbsent::Caller,
};
const BULK: SubjectRule = SubjectRule::Set {
    param: "users",
    everyone: Some(Everyone {
        param: "all",
        action: "admin:ListUsers",
    }),
};
const NAMED_ONLY: SubjectRule = SubjectRule::Set {
    param: "users",
    everyone: None,
};

fn one(value: &str) -> Subjects {
    Subjects::One(Subject::Named(SubjectName(Box::from(value))))
}

fn each(values: &[&str]) -> Subjects {
    Subjects::Each(
        values
            .iter()
            .map(|value| Subject::Named(SubjectName(Box::from(*value))))
            .collect(),
    )
}

const CALLER: Subjects = Subjects::One(Subject::Caller);

// ── one subject's actions ───────────────────────────────────────────────────────────────────

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

// ── one subject ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_named_subject_is_decoded_once() {
    assert_eq!(USER.extract("accessKey=alice"), Ok(one("alice")));
    assert_eq!(USER.extract("x=1&accessKey=cn%3Dbob%20smith&y"), Ok(one("cn=bob smith")));
    assert_eq!(SubjectRule::Caller.extract("accessKey=alice"), Ok(CALLER));
}

#[test]
fn n_an_escaped_spelling_of_the_parameter_is_the_parameter() {
    assert_eq!(USER.extract("access%4Bey=mallory"), Ok(one("mallory")));
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
    assert_eq!(LIST.extract(""), Ok(CALLER));
    assert_eq!(LIST.extract("user="), Ok(CALLER));
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
            aliases: &[],
            when_absent: WhenAbsent::Refuse,
        };
        assert!(rule.fault().is_some(), "{param:?}");
    }
    assert_eq!(USER.fault(), None);
    assert_eq!(SubjectRule::Caller.fault(), None);
}

// ── alias spellings (ADR-0029) ──────────────────────────────────────────────────────────────

/// RustFS's `access-key` for `accessKey`, as `AccessKeyQuery` reads it.
const ALIASED: SubjectRule = SubjectRule::Query {
    param: "accessKey",
    aliases: &["access-key"],
    when_absent: WhenAbsent::Caller,
};
/// RustFS's `user-dn` and `user` for `userDN`, as `SingleUserAccessKeysQuery` reads them.
const LDAP: SubjectRule = SubjectRule::Query {
    param: "userDN",
    aliases: &["user-dn", "user"],
    when_absent: WhenAbsent::Refuse,
};

/// Positive — each alias names the account the canonical parameter would, decoded the same way;
/// an empty alias is an absence, and another case or another rule's alias is no spelling at all.
#[test]
fn an_alias_names_the_same_account() {
    assert_eq!(ALIASED.extract("access-key=alice"), Ok(one("alice")));
    assert_eq!(ALIASED.extract("access%2Dkey=cn%3Dbob"), Ok(one("cn=bob")));
    assert_eq!(ALIASED.extract("accessKey=alice"), Ok(one("alice")));
    assert_eq!(LDAP.extract("user-dn=cn%3Dbob"), Ok(one("cn=bob")));
    assert_eq!(LDAP.extract("user=cn%3Dbob"), Ok(one("cn=bob")));
    assert_eq!(ALIASED.extract("access-key="), Ok(CALLER));
    assert_eq!(LDAP.extract("user-dn="), Err(SubjectError::Absent));
    assert_eq!(ALIASED.extract("Access-Key=alice&user-dn=bob&access_key=carol"), Ok(CALLER));
    assert_eq!(USER.extract("access-key=alice"), Err(SubjectError::Absent));
}

/// Negative — two spellings between them are one account named twice, whatever the values, and
/// an alias's value is decoded as strictly as the parameter's.
#[test]
fn n_two_spellings_of_one_account_are_refused() {
    for query in [
        "accessKey=alice&access-key=alice",
        "access-key=alice&accessKey=mallory",
        "access-key=alice&access-key=mallory",
        "access-key=&accessKey=mallory",
    ] {
        assert_eq!(ALIASED.extract(query), Err(SubjectError::Repeated), "{query}");
    }
    assert_eq!(LDAP.extract("user-dn=a&user=b"), Err(SubjectError::Repeated));
    assert_eq!(LDAP.extract("userDN=a&user=a"), Err(SubjectError::Repeated));
    assert_eq!(ALIASED.extract("access-key=a+b"), Err(SubjectError::Malformed));
    assert_eq!(ALIASED.refused_param(SubjectError::Repeated), Some("accessKey"));
}

/// Negative — an alias is spelled like a parameter and differs from every other spelling.
#[test]
fn n_an_alias_spelled_wrongly_cannot_be_registered() {
    let aliased = |aliases| SubjectRule::Query {
        param: "accessKey",
        aliases,
        when_absent: WhenAbsent::Refuse,
    };
    for aliases in [&[""][..], &["access key"], &["a%41"], &["accessKey"], &["ak", "ak"]] {
        assert!(aliased(aliases).fault().is_some(), "{aliases:?}");
    }
    assert_eq!(ALIASED.fault(), None);
    assert_eq!(LDAP.fault(), None);
}

/// Positive — the overlay spells every alias after the canonical parameter.
#[test]
fn an_alias_is_rendered_with_its_parameter() {
    let render = |rule| {
        crate::AuthRequirement::new("admin:GetUser", crate::ResourceShape::Service)
            .about_subject(rule)
            .render()
    };
    assert_eq!(render(ALIASED), "admin:GetUser about query(accessKey|access-key, absent=caller)");
    assert_eq!(render(LDAP), "admin:GetUser about query(userDN|user-dn|user, absent=refused)");
    assert_eq!(render(USER), "admin:GetUser about query(accessKey, absent=refused)");
}

// ── a set of subjects (ADR-0026) ────────────────────────────────────────────────────────────

/// Positive — each account once, in request order, decoded once; naming nobody is the caller;
/// the flag alone is every account; other parameters are not the rule's business.
#[test]
fn a_set_names_each_account_once_in_request_order() {
    assert_eq!(BULK.extract("users=alice&users=cn%3Dbob"), Ok(each(&["alice", "cn=bob"])));
    assert_eq!(BULK.extract("user%73=alice&listType=all"), Ok(each(&["alice"])));
    assert_eq!(BULK.extract("all=false&users=alice"), Ok(each(&["alice"])));
    assert_eq!(BULK.extract(""), Ok(CALLER));
    assert_eq!(BULK.extract("all=false&listType=sts-only"), Ok(CALLER));
    assert_eq!(BULK.extract("listType=all&all=true"), Ok(Subjects::Everyone));
    assert_eq!(BULK.extract("all=%74rue"), Ok(Subjects::Everyone));
}

/// Negative — an account named twice, in any spelling, and an empty member are refused, never
/// merged or skipped as RustFS's parser does.
#[test]
fn n_a_duplicated_or_empty_member_is_refused() {
    assert_eq!(BULK.extract("users=alice&users=alice"), Err(SubjectError::Duplicate));
    assert_eq!(BULK.extract("users=alice&user%73=%61lice"), Err(SubjectError::Duplicate));
    for query in ["users=", "users", "users=alice&users=", "users=&all=true"] {
        assert_eq!(BULK.extract(query), Err(SubjectError::Malformed), "{query}");
    }
}

/// Negative — a member or any key that cannot be decoded unambiguously refuses the set.
#[test]
fn n_a_malformed_member_or_key_refuses_the_set() {
    for query in [
        "users=a+b",
        "users=a%zz",
        "users=a%0A",
        "x%2=1&users=a",
        "users=alice&use+rs=bob",
    ] {
        assert_eq!(BULK.extract(query), Err(SubjectError::Malformed), "{query}");
    }
    let long = format!("users={}", "a".repeat(MAX_SUBJECT_BYTES + 1));
    assert_eq!(BULK.extract(&long), Err(SubjectError::TooLong));
}

/// Negative — the set is bounded: the bound itself is accepted, one more is refused.
#[test]
fn n_more_accounts_than_the_bound_are_refused() {
    let query = |count: usize| {
        (0..count)
            .map(|index| format!("users=u{index}"))
            .collect::<Vec<_>>()
            .join("&")
    };
    match BULK.extract(&query(MAX_SUBJECTS)) {
        Ok(Subjects::Each(each)) => assert_eq!(each.len(), MAX_SUBJECTS),
        other => panic!("the bound itself was refused: {other:?}"),
    }
    assert_eq!(BULK.extract(&query(MAX_SUBJECTS + 1)), Err(SubjectError::TooMany));
}

/// Negative — every account is a strict flag, never beside a name, and never repeated.
#[test]
fn n_every_account_is_a_strict_flag_and_never_beside_a_name() {
    assert_eq!(BULK.extract("all=true&users=alice"), Err(SubjectError::Contradictory));
    assert_eq!(BULK.extract("users=alice&all=true"), Err(SubjectError::Contradictory));
    for query in ["all=1", "all=yes", "all=on", "all=TRUE", "all=", "all", "all=true%20"] {
        assert_eq!(BULK.extract(query), Err(SubjectError::Flag), "{query}");
    }
    assert_eq!(BULK.extract("all=true&all=true"), Err(SubjectError::Repeated));
    assert_eq!(BULK.extract("all=false&%61ll=true"), Err(SubjectError::Repeated));
}

/// Negative — a set rule with no every-account form cannot be asked for every account: its flag
/// is an unrelated parameter, so the request stays about the accounts it names, or the caller.
#[test]
fn n_without_an_every_account_form_the_flag_widens_nothing() {
    assert_eq!(NAMED_ONLY.extract("all=true"), Ok(CALLER));
    assert_eq!(NAMED_ONLY.extract("all=true&users=alice"), Ok(each(&["alice"])));
}

/// Positive — each refusal names the parameter it is about.
#[test]
fn a_refusal_names_the_parameter_it_is_about() {
    assert_eq!(BULK.refused_param(SubjectError::Flag), Some("all"));
    assert_eq!(BULK.refused_param(SubjectError::Repeated), Some("all"));
    assert_eq!(BULK.refused_param(SubjectError::Duplicate), Some("users"));
    assert_eq!(BULK.refused_param(SubjectError::TooMany), Some("users"));
    assert_eq!(NAMED_ONLY.refused_param(SubjectError::Malformed), Some("users"));
    assert_eq!(USER.refused_param(SubjectError::Absent), Some("accessKey"));
    assert_eq!(SubjectRule::Caller.refused_param(SubjectError::Malformed), None);
}

/// Negative — a set rule's parameters are plain query keys, and the flag is one of its own.
#[test]
fn n_a_set_rule_spelled_wrongly_cannot_be_registered() {
    let everyone = |param| {
        Some(Everyone {
            param,
            action: "admin:ListUsers",
        })
    };
    for rule in [
        SubjectRule::Set {
            param: "user s",
            everyone: None,
        },
        SubjectRule::Set {
            param: "",
            everyone: everyone("all"),
        },
        SubjectRule::Set {
            param: "users",
            everyone: everyone("a&b"),
        },
        SubjectRule::Set {
            param: "users",
            everyone: everyone("users"),
        },
    ] {
        assert!(rule.fault().is_some(), "{rule:?}");
    }
    assert_eq!(BULK.fault(), None);
    assert_eq!(NAMED_ONLY.fault(), None);
}
