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

//! The rule `<Filter>` grammar lifecycle and replication share, held once.
//!
//! Members: DeleteBucketLifecycle, GetBucketLifecycleConfiguration, PutBucketLifecycleConfiguration, DeleteBucketReplication, GetBucketReplication, PutBucketReplication
//!
//! Responsible for: the two cardinality rules of a rule filter — at most one direct child, and an
//! `<And>` that combines at least two conditions — and, per family, which members count as a
//! child or a condition. The families differ in exactly one respect, and it is spelled out below
//! rather than unified away: a lifecycle filter also carries `ObjectSizeGreaterThan` and
//! `ObjectSizeLessThan`, directly and inside `<And>`, and a replication filter has neither.
//! NOT responsible for: decoding, the rule-level scope rules around the filter (lifecycle's
//! Filter-or-Prefix requirement, replication's V1/V2 coupling), the refusal codes and reasons —
//! each family maps [`Rejection`] onto its own public rejection, whose reason names its own member
//! set — or the tag-key rules, which `shared::tagging` owns and neither family runs here.
//! Upstream: `rustfs-gateway-types`' generated filter dto. Downstream: `shared::lifecycle` and
//! `shared::replication`, the only callers, and through them the six member operations.
//!
//! Evidence: <https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRuleFilter.html> and
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ReplicationRuleFilter.html> — both types
//! take one condition directly and several only through `And`.
//!
//! # What is deliberately counted, not judged
//!
//! Presence is the whole test. An empty `<Filter/>` has no child and matches every object in both
//! families (`q-lc-0007`, `q-repl-0007`); an empty `<Prefix></Prefix>` is present and counts; and
//! every `<Tag>` inside `<And>` is one condition, two tags with the same key included — refusing a
//! duplicated key would be a tag-set rule, and a stored document stricter validation would refuse
//! turns lifecycle off and makes a replicated bucket unusable (the family modules say why).

use rustfs_gateway_types::dto::{LifecycleRuleFilter, ReplicationRuleFilter};

/// Which cardinality rule a filter broke. A family maps it onto its own public rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rejection {
    /// More than one direct child: several conditions must nest inside one `<And>`.
    FilterNotExclusive,
    /// An `<And>` with fewer than two conditions: the combinator exists only to combine.
    AndBelowTwoConditions,
}

/// Checks a lifecycle `<Filter>`: `Prefix`, `Tag`, both object-size bounds and `And` are its
/// children, and inside `And` the prefix, each tag and both bounds are conditions.
///
/// # Errors
///
/// [`Rejection`] naming the first cardinality rule the filter breaks.
pub(super) fn lifecycle(filter: &LifecycleRuleFilter) -> Result<(), Rejection> {
    let children = usize::from(filter.prefix.is_some())
        + usize::from(filter.tag.is_some())
        + usize::from(filter.object_size_greater_than.is_some())
        + usize::from(filter.object_size_less_than.is_some())
        + usize::from(filter.and.is_some());
    let conditions = filter.and.as_ref().map(|and| {
        usize::from(and.prefix.is_some())
            + and.tags.len()
            + usize::from(and.object_size_greater_than.is_some())
            + usize::from(and.object_size_less_than.is_some())
    });
    cardinality(children, conditions)
}

/// Checks a replication `<Filter>`: `Prefix`, `Tag` and `And` are its children, and inside `And`
/// the prefix and each tag are conditions. There is no object-size member in this family.
///
/// # Errors
///
/// [`Rejection`] naming the first cardinality rule the filter breaks.
pub(super) fn replication(filter: &ReplicationRuleFilter) -> Result<(), Rejection> {
    let children = usize::from(filter.prefix.is_some()) + usize::from(filter.tag.is_some()) + usize::from(filter.and.is_some());
    let conditions = filter
        .and
        .as_ref()
        .map(|and| usize::from(and.prefix.is_some()) + and.tags.len());
    cardinality(children, conditions)
}

/// The shared rule itself. Exclusivity is judged first, so a filter that breaks both rules is
/// refused for its siblings on every backend.
fn cardinality(children: usize, and_conditions: Option<usize>) -> Result<(), Rejection> {
    if children > 1 {
        return Err(Rejection::FilterNotExclusive);
    }
    if and_conditions.is_some_and(|conditions| conditions < 2) {
        return Err(Rejection::AndBelowTwoConditions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Rejection, cardinality};

    #[test]
    fn no_child_one_child_and_a_combining_and_are_accepted() {
        for (children, conditions) in [(0, None), (1, None), (1, Some(2)), (1, Some(3))] {
            assert_eq!(cardinality(children, conditions), Ok(()), "{children} children, {conditions:?}");
        }
    }

    #[test]
    fn n_siblings_are_refused_before_the_and_floor_is_looked_at() {
        assert_eq!(cardinality(2, None), Err(Rejection::FilterNotExclusive));
        assert_eq!(cardinality(2, Some(0)), Err(Rejection::FilterNotExclusive));
    }

    #[test]
    fn n_an_and_below_two_conditions_is_refused() {
        assert_eq!(cardinality(1, Some(0)), Err(Rejection::AndBelowTwoConditions));
        assert_eq!(cardinality(1, Some(1)), Err(Rejection::AndBelowTwoConditions));
    }
}
