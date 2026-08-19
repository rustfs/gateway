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

//! Resolving a `partNumber` selector against the part table a completed object has.
//!
//! Responsible for: the arithmetic that turns "part 2 of an object whose parts are these lengths"
//! into the byte window a `206` serves, and the four refusals that arithmetic has — three positive
//! resolutions against nine negative ones. `evaluate_range` deliberately stops at
//! `RangeDecision::Part`, because it is handed the object's total length and nothing about where
//! its parts begin; this is the other half, and it lives here rather than in a backend so that two
//! backends cannot disagree about which bytes part 2 is.
//! NOT responsible for: whether an object *has* a part table (that is storage's), the
//! `x-amz-mp-parts-count` header policy (`RangeDecision::part_count_header` owns it), or the
//! `Range`-and-`partNumber` conflict (`evaluate_range` owns it).
//! Upstream: `rustfs_gateway_core::ops::shared::part_table` and `::precondition`. Downstream: nothing.
//!
//! Evidence: <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html> documents
//! `partNumber` as selecting one part of an object uploaded in parts, answered with the part's
//! bytes and a header naming how many parts there are; the S3 error list documents
//! `InvalidPartNumber` for a part number the object cannot satisfy.

use rustfs_gateway_core::ops::shared::part_table::{PartWindow, resolve_part};
use rustfs_gateway_core::ops::shared::precondition::RangeDecision;
use rustfs_gateway_types::ErrorCode;

/// A five-mebibyte first part and a short tail, which is the smallest completable upload.
const TWO_PARTS: [u64; 2] = [5_242_880, 16];

#[test]
fn the_first_part_starts_at_the_first_byte() {
    assert_eq!(
        resolve_part(1, &TWO_PARTS),
        Ok(PartWindow {
            start: 0,
            end_inclusive: 5_242_879,
            total: 5_242_896,
        })
    );
}

/// The assertion the whole feature exists for: part 2 begins where part 1 ended, not at zero.
///
/// A resolver that ignored the preceding parts would answer `0-15`, serve the first sixteen bytes
/// of part 1, and report a `Content-Range` that says so — a download that reassembles into an
/// object of the right length and the wrong bytes, with no error anywhere.
#[test]
fn a_later_part_begins_where_the_parts_before_it_ended() {
    assert_eq!(
        resolve_part(2, &TWO_PARTS),
        Ok(PartWindow {
            start: 5_242_880,
            end_inclusive: 5_242_895,
            total: 5_242_896,
        })
    );
}

/// Three parts, so that "start of part 3" is a sum rather than a single predecessor's length.
#[test]
fn the_offset_is_the_sum_of_every_earlier_part() {
    assert_eq!(
        resolve_part(3, &[10, 20, 30]),
        Ok(PartWindow {
            start: 30,
            end_inclusive: 59,
            total: 60,
        })
    );
}

/// The window an encoder renders is the ordinary `Partial` one, so `Content-Range` comes from the
/// contract's own renderer rather than from a `format!` in a backend.
#[test]
fn the_window_renders_as_an_ordinary_partial_content_range() {
    let window = resolve_part(2, &TWO_PARTS).expect("a part inside the table resolves");
    let decision = window.as_decision();

    assert_eq!(decision.content_range().as_deref(), Some("bytes 5242880-5242895/5242896"));
    assert_eq!(decision.content_length(5_242_896), 16);
}

#[test]
fn part_number_zero_is_refused() {
    let rejection = resolve_part(0, &TWO_PARTS).expect_err("part numbers start at one");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_PART_NUMBER);
}

#[test]
fn a_part_past_the_end_of_the_table_is_refused() {
    let rejection = resolve_part(3, &TWO_PARTS).expect_err("the object has two parts");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_PART_NUMBER);
}

/// The boundary either side of the last part, in one test, because off-by-one here is the defect
/// that makes the final part of every object unreadable.
#[test]
fn the_last_part_resolves_and_the_one_after_it_does_not() {
    assert!(resolve_part(2, &TWO_PARTS).is_ok());
    assert!(resolve_part(3, &TWO_PARTS).is_err());
}

/// An object with no parts is not an object with one part.
///
/// Answering `0..len` here would let a `partNumber` read succeed against an object that was never
/// uploaded in parts, and report a part count this table cannot know.
#[test]
fn an_empty_part_table_satisfies_no_part_number() {
    let rejection = resolve_part(1, &[]).expect_err("an object with no parts has no part 1");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_PART_NUMBER);
}

/// A part carrying no bytes names no window, and `start - 1` on an empty part is exactly the
/// underflow that would otherwise answer `bytes 16-15/16`.
#[test]
fn a_part_that_carries_no_bytes_is_refused_rather_than_wrapped() {
    let rejection = resolve_part(2, &[16, 0]).expect_err("an empty part has no last byte");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_PART_NUMBER);
}

/// A table whose lengths do not fit in the address space is refused rather than wrapped into a
/// small, plausible window.
#[test]
fn a_part_table_that_overflows_the_address_space_is_refused() {
    let rejection = resolve_part(2, &[u64::MAX, 8]).expect_err("the total does not fit");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_PART_NUMBER);
}

/// The count a part read publishes is the table's length, and it is the contract's policy that
/// decides whether it is published at all — not the resolver, and not a backend.
#[test]
fn the_published_part_count_is_the_size_of_the_table() {
    assert_eq!(RangeDecision::Part { part_number: 2 }.part_count_header(TWO_PARTS.len() as u32), Some(2));
}

/// The negative half of the same rule: a decision that is not a part selection publishes no count,
/// whatever total it is offered.
#[test]
fn a_decision_that_is_not_a_part_selection_publishes_no_count() {
    assert_eq!(RangeDecision::Whole.part_count_header(2), None);
    assert_eq!(
        RangeDecision::Partial {
            start: 0,
            end_inclusive: 1,
            total: 2,
        }
        .part_count_header(2),
        None
    );
}
