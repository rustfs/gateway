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

//! Completed part lengths, their record grammar and their read window projection.
//!
//! Responsible for: validating persisted boundaries and feeding them to the shared part resolver.
//! NOT responsible for: checksum storage, range arithmetic or HEAD policy.
//! Upstream: completion, records, GET and HEAD. Downstream: the core part-table contract.

use rustfs_gateway::{ETag, ErrorCode, HandlerError, RangeDecision, resolve_part};

pub(super) fn encode(lengths: Option<&[u64]>) -> String {
    let Some(lengths) = lengths else { return String::new() };
    let mut section = format!("parts/1 {}\n", lengths.len());
    for length in lengths {
        section.push_str(&format!("{length}\n"));
    }
    section
}

pub(super) fn decode(lines: &mut std::str::Lines<'_>, count: &str) -> Result<Vec<u64>, HandlerError> {
    let count = count
        .parse::<usize>()
        .ok()
        .filter(|count| (1..=10000).contains(count))
        .ok_or_else(|| HandlerError::internal_error("the persisted part count is outside 1..10000"))?;
    (0..count)
        .map(|_| {
            lines
                .next()
                .and_then(|line| line.parse::<u64>().ok())
                .ok_or_else(|| HandlerError::internal_error("the persisted part length is missing or malformed"))
        })
        .collect()
}

pub(super) fn validate(lengths: &[u64], size: i64, tag: &str) -> Result<(), HandlerError> {
    let total = lengths.iter().try_fold(0_u64, |sum, length| sum.checked_add(*length));
    let tag = ETag::new(tag.to_owned()).map_err(|_| super::storage_error())?;
    let size = u64::try_from(size).map_err(|_| super::storage_error())?;
    if total != Some(size) || tag.part_count() != u32::try_from(lengths.len()).ok() {
        return Err(HandlerError::internal_error(
            "the persisted part table contradicts the object size or entity tag",
        ));
    }
    Ok(())
}

pub(super) fn window(number: u32, lengths: Option<&[u64]>, tag: &ETag, object_len: u64) -> Result<RangeDecision, HandlerError> {
    if !(1..=10000).contains(&number) {
        return Err(HandlerError::new(
            ErrorCode::INVALID_ARGUMENT,
            "a part number must be between 1 and 10000",
        ));
    }
    let plain = [object_len];
    let lengths = match lengths {
        Some(lengths) => lengths,
        None if tag.part_count().is_some() => {
            return Err(HandlerError::not_implemented("the stored multipart object has no part boundaries"));
        }
        None if object_len == 0 && number == 1 => return Ok(RangeDecision::Whole),
        None => &plain,
    };
    let window =
        resolve_part(number, lengths).map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    if window.total != object_len {
        return Err(HandlerError::internal_error(
            "the stored part table and object bytes have different lengths",
        ));
    }
    Ok(window.as_decision())
}

#[cfg(test)]
mod tests {
    #[test]
    fn n_two_unrepresentable_sizes_do_not_validate_each_other() {
        assert!(super::validate(&[u64::MAX, 1], -1, "00000000000000000000000000000000-2").is_err());
    }

    #[test]
    fn n_part_counts_are_bounded_before_reading_rows() {
        let rows = "0\n".repeat(10001);
        for count in ["0", "10001"] {
            assert!(super::decode(&mut rows.lines(), count).is_err(), "{count}");
        }
    }

    #[test]
    fn n_missing_or_malformed_rows_are_not_zero_lengths() {
        for rows in ["", "-1\n", "not-a-size\n", "18446744073709551616\n"] {
            assert!(super::decode(&mut rows.lines(), "1").is_err(), "{rows}");
        }
        assert!(super::decode(&mut "9\n".lines(), "not-a-count").is_err());
    }

    #[test]
    fn n_a_window_cannot_outlive_its_representation_length() {
        let tag = rustfs_gateway::ETag::new("00000000000000000000000000000000-1").expect("a fixture tag");
        assert!(super::window(1, Some(&[9]), &tag, 8).is_err());
    }
}
