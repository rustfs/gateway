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

//! The known-diffs register refuses every malformed entry by name, and matches only what it says.
//!
//! Responsible for: a-df-0017 (an entry without `reason` or `expires` is refused) and the rest of
//! the register's refusals, and the matching rules — pinned values, one-`*` patterns, the
//! any-operation wording entry.
//! NOT responsible for: which entries exist (`rows.rs` holds them to the matrix).
//! Upstream: `known.rs`. Downstream: none.

use crate::decode::{Finding, Item, Priority};
use crate::known::{KnownDiffs, RegisterError};

const VALID: &str = r#"
[[diff]]
id = "kd-decode-0001"
kind = "decode"
operation = "GetObject"
item = "GetObjectInput.range"
gateway = "\"bytes=0-1\""
reason = "a reason"
expires = "2026-12-31"
"#;

fn refused(text: &str) -> String {
    match KnownDiffs::parse(text) {
        Ok(register) => panic!("accepted {register:?}"),
        Err(RegisterError(message)) => message,
    }
}

fn finding(operation: &str, item: Item, gateway: &str, s3s: &str) -> Finding {
    Finding {
        operation: operation.to_owned(),
        priority: if item == Item::Message {
            Priority::Info
        } else {
            Priority::Fail
        },
        item,
        gateway: gateway.to_owned(),
        s3s: s3s.to_owned(),
    }
}

/// Positive — the checked-in register and a minimal entry both parse.
#[test]
fn the_checked_in_register_and_a_minimal_entry_parse() {
    assert!(!KnownDiffs::checked_in().expect("parses").entries().is_empty());
    assert_eq!(KnownDiffs::parse(VALID).expect("parses").entries().len(), 1);
}

/// Negative (a-df-0017) — an entry without a reason is refused.
#[test]
fn an_entry_without_a_reason_is_refused() {
    assert!(refused(&VALID.replace("reason = \"a reason\"\n", "")).contains("reason"));
}

/// Negative (a-df-0017) — an entry without a review date is refused.
#[test]
fn an_entry_without_expires_is_refused() {
    assert!(refused(&VALID.replace("expires = \"2026-12-31\"\n", "")).contains("expires"));
}

/// Negative — a reason of whitespace is no reason.
#[test]
fn an_empty_reason_is_refused() {
    assert!(refused(&VALID.replace("\"a reason\"", "\"  \"")).contains("reason is empty"));
}

/// Negative — review dates are `YYYY-MM-DD` with a real month and day.
#[test]
fn a_malformed_review_date_is_refused() {
    for date in [
        "2026-13-01",
        "2026-00-10",
        "2026-01-32",
        "26-01-01",
        "2026/01/01",
        "2026-1-1",
        "someday",
    ] {
        let message = refused(&VALID.replace("2026-12-31", date));
        assert!(message.contains("YYYY-MM-DD"), "{date}: {message}");
    }
}

/// Negative — an id is `kd-<its own kind>-NNNN`.
#[test]
fn an_id_that_does_not_name_its_kind_and_four_digits_is_refused() {
    for id in [
        "kd-decode-1",
        "kd-decode-00001",
        "kd-encode-0001",
        "rd-put-0001",
        "kd-decode-00a1",
    ] {
        let message = refused(&VALID.replace("kd-decode-0001", id));
        assert!(message.contains("kd-decode-NNNN"), "{id}: {message}");
    }
}

/// Negative — one id, one entry.
#[test]
fn a_duplicate_id_is_refused() {
    assert!(refused(&format!("{VALID}{VALID}")).contains("registered twice"));
}

/// Negative — a key the register does not define is refused rather than ignored: a misspelt
/// `expire` must not read as an entry with no date.
#[test]
fn an_unknown_key_is_refused() {
    assert!(refused(&VALID.replace("reason =", "note = \"x\"\nreason =")).contains("unknown field"));
    assert!(refused(&format!("{VALID}\n[extra]\nx = 1\n")).contains("unknown field"));
}

/// Negative — an unknown kind is refused.
#[test]
fn an_unknown_kind_is_refused() {
    assert!(!refused(&VALID.replace("kind = \"decode\"", "kind = \"both\"")).is_empty());
}

/// Negative — only a wording entry that pins the gateway sentence may hold for every operation.
#[test]
fn an_any_operation_entry_must_be_a_pinned_wording_entry() {
    let any = VALID.replace("\"GetObject\"", "\"*\"");
    assert!(refused(&any).contains("every operation"));
    let unpinned = any
        .replace("GetObjectInput.range", "error.message")
        .replace("gateway = \"\\\"bytes=0-1\\\"\"\n", "");
    assert!(refused(&unpinned).contains("every operation"));
    let pinned = any.replace("GetObjectInput.range", "error.message");
    assert!(KnownDiffs::parse(&pinned).is_ok());
}

/// Negative — an entry matches its own operation, item and pinned value, and nothing next to them.
#[test]
fn an_entry_matches_only_its_operation_item_and_pinned_value() {
    let register = KnownDiffs::parse(VALID).expect("parses");
    let item = || Item::Member("GetObjectInput.range".to_owned());
    assert!(
        register
            .verdict(vec![finding("GetObject", item(), "\"bytes=0-1\"", "anything")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding("GetObject", item(), "\"bytes=0-2\"", "anything")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding("HeadObject", item(), "\"bytes=0-1\"", "anything")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding(
                "GetObject",
                Item::Member("GetObjectInput.if_range".to_owned()),
                "\"bytes=0-1\"",
                "x"
            )])
            .passed()
    );
}

/// Negative — a one-`*` pattern holds its fixed text at both ends.
#[test]
fn a_pattern_holds_its_fixed_text_at_both_ends() {
    let register = KnownDiffs::parse(&VALID.replace("\"\\\"bytes=0-1\\\"\"", "\"lead * tail\"")).expect("parses");
    let item = || Item::Member("GetObjectInput.range".to_owned());
    assert!(
        register
            .verdict(vec![finding("GetObject", item(), "lead middle tail", "x")])
            .passed()
    );
    assert!(
        register
            .verdict(vec![finding("GetObject", item(), "lead  tail", "x")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding("GetObject", item(), "lead middle", "x")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding("GetObject", item(), "middle tail", "x")])
            .passed()
    );
    assert!(
        !register
            .verdict(vec![finding("GetObject", item(), "lead tail", "x")])
            .passed()
    );
}

/// Negative — one registered finding does not carry an unregistered one beside it.
#[test]
fn a_registered_finding_does_not_excuse_its_neighbour() {
    let register = KnownDiffs::parse(VALID).expect("parses");
    let verdict = register.verdict(vec![
        finding("GetObject", Item::Member("GetObjectInput.range".to_owned()), "\"bytes=0-1\"", "x"),
        finding("GetObject", Item::RestBody, "a", "b"),
    ]);
    assert!(!verdict.passed());
    assert_eq!(verdict.known.len(), 1);
    assert_eq!(verdict.failures.len(), 1);
}

/// Negative — a pattern with two `*` is refused rather than read with its second `*` as text.
#[test]
fn a_pattern_with_two_stars_is_refused() {
    let two = VALID.replace("\"\\\"bytes=0-1\\\"\"", "\"a*b*c\"");
    assert!(refused(&two).contains("at most one *"));
    let item = VALID.replace("GetObjectInput.range", "GetObjectInput.*.*");
    assert!(refused(&item).contains("at most one *"));
}

/// Negative — a route or outcome entry that leaves a side open would accept every such
/// difference for its operation; it must pin both.
#[test]
fn an_unpinned_route_or_outcome_entry_is_refused() {
    for item in ["route", "outcome"] {
        let open = VALID.replace("GetObjectInput.range", item);
        assert!(refused(&open).contains("pins both sides"), "{item}");
        let pinned = open.replace("reason =", "s3s = \"handled\"\nreason =");
        assert!(KnownDiffs::parse(&pinned).is_ok(), "{item}");
    }
}

/// Negative — an item pattern holds its fixed text and matches members it names, not others.
#[test]
fn an_item_pattern_matches_only_the_members_it_names() {
    let register = KnownDiffs::parse(&VALID.replace("GetObjectInput.range", "GetObjectInput.if_*")).expect("parses");
    let member = |path: &str| finding("GetObject", Item::Member(path.to_owned()), "\"bytes=0-1\"", "x");
    assert!(register.verdict(vec![member("GetObjectInput.if_range")]).passed());
    assert!(register.verdict(vec![member("GetObjectInput.if_match")]).passed());
    assert!(!register.verdict(vec![member("GetObjectInput.range")]).passed());
    assert!(
        !register
            .verdict(vec![finding("GetObject", Item::Route, "\"bytes=0-1\"", "x")])
            .passed()
    );
}

/// Negative — an entry whose review date is before the day asked about is expired; one dated that
/// day is not yet.
#[test]
fn an_entry_past_its_review_date_is_expired() {
    let register = KnownDiffs::parse(VALID).expect("parses");
    assert!(register.expired_on("2026-12-31").is_empty());
    assert_eq!(register.expired_on("2027-01-01").len(), 1);
    assert!(register.expired_on("2026-06-30").is_empty());
}

/// `YYYY-MM-DD` of the current UTC day.
fn today() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    let days = i64::try_from(seconds / 86_400).expect("a day count fits");
    // Civil-from-days (proleptic Gregorian), days counted from 1970-01-01.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Negative (the expiry gate) — no checked-in entry is past its review date. On the day one
/// expires this fails every build until the entry is removed or re-argued with a new date: an
/// accepted difference is reviewed, never silently permanent.
#[test]
fn no_checked_in_entry_is_past_its_review_date() {
    let today = today();
    assert_eq!(today.len(), 10);
    let register = KnownDiffs::checked_in().expect("parses");
    let expired: Vec<&str> = register.expired_on(&today).iter().map(|entry| entry.id.as_str()).collect();
    assert!(expired.is_empty(), "past their review date on {today}: {expired:?}");
}
