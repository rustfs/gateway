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

//! How near a misspelled method name is to a real operation.
//!
//! Responsible for: [`distance`], the edit distance, and [`suggestions`], the two nearest names.
//! NOT responsible for: knowing which names exist (`crate::op_names`) or rendering the error
//! (`crate::mapping`).
//! Upstream: nothing. Downstream: `crate::mapping`.
//!
//! # Why an error needs this at all
//!
//! `get_objects` is not an operation. Without a suggestion, the message says so and the reader has
//! to go and find the list. With one, the message says `did you mean get_object?` and the fix is
//! the next keystroke. The threshold is deliberately tight — three edits — because a suggestion
//! that is not the intended name is worse than none: it sends the reader to check something
//! irrelevant.

/// How many single-character edits turn one name into the other.
///
/// Two rows rather than a full matrix; the inputs are short identifiers, and the shape is the
/// standard dynamic program.
pub(crate) fn distance(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.is_empty() {
        return right.len();
    }
    if right.is_empty() {
        return left.len();
    }

    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current: Vec<usize> = vec![0; right.len().saturating_add(1)];

    for (row, left_char) in left.iter().enumerate() {
        current[0] = row.saturating_add(1);
        for (column, right_char) in right.iter().enumerate() {
            let substitution_cost = usize::from(left_char != right_char);
            let deletion = previous[column.saturating_add(1)].saturating_add(1);
            let insertion = current[column].saturating_add(1);
            let substitution = previous[column].saturating_add(substitution_cost);
            current[column.saturating_add(1)] = deletion.min(insertion).min(substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

/// How far a suggestion may be and still be offered.
const MAX_DISTANCE: usize = 3;

/// How many suggestions are offered.
const MAX_SUGGESTIONS: usize = 2;

/// The nearest candidates to `name`, nearest first, at most two and never further than three edits.
pub(crate) fn suggestions<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut scored: Vec<(usize, &'a str)> = candidates
        .into_iter()
        .map(|candidate| (distance(name, candidate), candidate))
        .filter(|(score, _)| *score <= MAX_DISTANCE)
        .collect();
    // Sorted by distance, then by name, so the message is the same on every machine and the
    // golden `.stderr`-style assertions do not depend on iteration order.
    scored.sort_unstable();
    scored.truncate(MAX_SUGGESTIONS);
    scored.into_iter().map(|(_, candidate)| candidate).collect()
}
