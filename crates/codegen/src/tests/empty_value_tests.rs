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

//! Whether any member of the pinned surface drops its own empty value.
//!
//! Responsible for: the census of `omit`-on-empty members across every lowered operation.
//! NOT responsible for: what the emitter does with the policy once it has it, which is
//! `codegen_tests` and the generated goldens; or whether a document survives the trip out and
//! back, which is `crates/core/tests/*_roundtrip.rs`.
//! Upstream: [`rustfs_gateway_model::lower`]. Downstream: its callers and regression tests.
//!
//! # The class this closes
//!
//! An encoder that drops an optional member's empty text writes a document its own decoder reads
//! differently: `<Prefix></Prefix>` arrives as `Some("")` and comes back `None`. RustFS persists
//! bucket configuration by parse-then-reserialise, so one read-modify-write on an unrelated
//! member is enough to change the stored document — and in the lifecycle family to destroy it,
//! because a rule that loses its only scope is refused `ScopeMissing` on the next read
//! (rustfs/gateway#221). It reached lifecycle, replication (rustfs/gateway#248) and the ACL owner
//! and grantee members before anything asserted the two directions agreed, and each was found by
//! a round-trip property rather than by any single-direction case.
//!
//! The repair is that absence is `Option::None` and nothing else, so the encoder has no second
//! opinion to disagree with. `omit` stays available and stays meaningful — it is how a member
//! whose element AWS genuinely never writes is declared — but it is a declaration with evidence,
//! not a default nobody looked at.

use rustfs_gateway_model::ir::{EmptyValue, OperationIr};

use super::codegen_tests::artifacts;

/// Every `(operation, shape, member)` whose empty value the encoder drops.
///
/// A shared reader rather than a loop inside one test, so the negative below measures the same
/// census the positive does. A control that walks its own copy of the data proves nothing about
/// the walk that answers.
fn omit_members(operations: &[OperationIr]) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for operation in operations {
        for (member, policy) in &operation.xml.empty_value_policy {
            if *policy == EmptyValue::Omit {
                found.push((operation.operation.clone(), String::new(), member.clone()));
            }
        }
        for (shape_name, shape) in &operation.shapes {
            for (member, policy) in &shape.xml.empty_value_policy {
                if *policy == EmptyValue::Omit {
                    found.push((operation.operation.clone(), shape_name.clone(), member.clone()));
                }
            }
        }
    }
    found
}

/// No member of the pinned surface drops its own empty value.
///
/// This is the whole empty-element half of rustfs/gateway#231, asserted once over all 72
/// operations rather than three times in three families. It fails the moment the lossy default
/// returns: reverting `empty_value_policy`'s fallback to "an optional member is dropped" puts 203
/// members on this list.
///
/// It is stated as "none" rather than as an allow-list because no overlay declares an `omit`
/// today, and an allow-list with no entries is a filter that cannot filter. The day a member
/// earns one — a capture showing AWS omitting the element — this assertion has to be edited to
/// name it, which is the review step the silent default never had.
#[test]
fn no_member_drops_its_own_empty_value() {
    let operations = artifacts().operations;
    assert!(operations.len() > 60, "the census must run over the whole surface");

    let found = omit_members(&operations);
    assert!(
        found.is_empty(),
        "{} member(s) drop their own empty value; each is a value this service writes and then \
         reads back as something else, so each owes a `q-empty-*` record and a row in this \
         assertion: {found:?}",
        found.len()
    );
}

/// The census is not vacuous: it finds an `omit` that has been put there.
///
/// Without this, a lowering that stopped recording policies at all — or a census that read the
/// wrong field — would satisfy the test above forever, and the assertion above would read exactly
/// like an assertion that passed. The flip is applied to the real lowered IR and to the shape
/// position as well as the operation one, because the two are separate lists and a census that
/// walked only the first would still report zero here.
#[test]
fn n_the_census_finds_an_omit_that_was_put_there() {
    let mut operations = artifacts().operations;
    assert!(omit_members(&operations).is_empty(), "the surface starts with none");

    let operation = operations
        .iter_mut()
        .find(|ir| ir.operation == "PutBucketLifecycleConfiguration")
        .expect("the lifecycle write is in the pinned surface");
    let shape = operation
        .shapes
        .get_mut("LifecycleRule")
        .expect("the rule shape is collected for the lifecycle write");
    let policy = shape
        .xml
        .empty_value_policy
        .iter_mut()
        .find(|(name, _)| name == "Prefix")
        .expect("the legacy prefix is a member of the rule shape");
    policy.1 = EmptyValue::Omit;

    assert_eq!(
        omit_members(&operations),
        vec![(
            "PutBucketLifecycleConfiguration".to_owned(),
            "LifecycleRule".to_owned(),
            "Prefix".to_owned()
        )],
        "the census must name the member that was flipped, and only that one"
    );
}
