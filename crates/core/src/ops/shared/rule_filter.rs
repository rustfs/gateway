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

//! The common cardinality rules of lifecycle and replication filters.
//!
//! Members: DeleteBucketLifecycle, GetBucketLifecycleConfiguration, PutBucketLifecycleConfiguration, DeleteBucketReplication, GetBucketReplication, PutBucketReplication
//!
//! Responsible for: permitting at most one direct condition and requiring two conditions in And.
//! NOT responsible for: XML decoding, family-specific fields, error rendering or rule execution.
//! Upstream: the lifecycle and replication validators count their own DTO fields. Downstream:
//! those validators map the shared refusal to their existing public error types.
//!
//! Evidence: https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRuleFilter.html and
//! https://docs.aws.amazon.com/AmazonS3/latest/API/API_ReplicationRuleFilter.html — each family
//! combines several conditions under And instead of placing them beside one another.
//! Empty filters retain the existing match-all behavior in both families.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rejection {
    FilterNotExclusive,
    AndBelowTwoConditions,
}

/// Checks counts derived from one filter; no document bytes or values are retained.
pub(super) fn validate(direct_children: usize, and_conditions: Option<usize>) -> Result<(), Rejection> {
    if direct_children > 1 {
        return Err(Rejection::FilterNotExclusive);
    }
    if and_conditions.is_some_and(|conditions| conditions < 2) {
        return Err(Rejection::AndBelowTwoConditions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Rejection, validate};

    #[test]
    fn empty_single_and_combined_filters_remain_accepted() {
        for (children, conditions) in [(0, None), (1, None), (1, Some(2)), (1, Some(3))] {
            assert_eq!(validate(children, conditions), Ok(()));
        }
    }

    #[test]
    fn direct_siblings_are_rejected_before_the_and_floor() {
        assert_eq!(validate(2, None), Err(Rejection::FilterNotExclusive));
        assert_eq!(validate(2, Some(0)), Err(Rejection::FilterNotExclusive));
    }

    #[test]
    fn an_empty_and_is_rejected() {
        assert_eq!(validate(1, Some(0)), Err(Rejection::AndBelowTwoConditions));
    }

    #[test]
    fn an_and_with_one_condition_is_rejected() {
        assert_eq!(validate(1, Some(1)), Err(Rejection::AndBelowTwoConditions));
    }
}
