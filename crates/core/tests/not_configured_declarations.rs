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

//! The lowered unconfigured-subresource codes, against the error-status authority.
//!
//! Responsible for: proving that every spelling `generated/routes.rs` carries in
//! `RouteRow::not_configured` is a code `model/overlays/error-status.toml` declares, and that its
//! status there is the `404` `ErrorCode::not_configured` bakes in.
//! NOT responsible for: which operation owes which code — that is
//! `configuration_error_declarations.rs` — or what a backend answers, which the lifecycle, CORS and
//! encryption conformance cases observe.
//! Upstream: `generated/routes.rs`. Downstream: `OperationSpec::standard`.
//!
//! # Why this is not a restatement of the table
//!
//! `ErrorCode::not_configured` is a `const fn`, so it cannot consult the status table the way
//! `ErrorCode::known` does; it writes `404` in. That is sound only while every lowered spelling is
//! a declared `404`, and this file is where that stops being an assumption. Without it, changing a
//! code's row in `error-status.toml` to a non-404 would leave `OperationSpec` carrying a value that
//! renders the old status and compares unequal to the constant of the same name.

use http::StatusCode;
use rustfs_gateway_core::route::ROUTES;
use rustfs_gateway_types::ErrorCode;

/// Every lowered unconfigured code is declared, and declared as a `404`.
///
/// The loop would be satisfied by an empty table, which is exactly the regression a change to the
/// routes emitter could produce, so the anchor below it asserts a concrete row as well.
#[test]
fn every_lowered_unconfigured_code_is_a_declared_404() {
    let mut seen = 0_usize;
    for row in ROUTES {
        let Some(spelling) = row.not_configured else {
            continue;
        };
        seen += 1;
        let declared = ErrorCode::known(spelling)
            .unwrap_or_else(|| panic!("{}: `{spelling}` has no row in the error-status authority", row.operation));
        assert_eq!(
            declared.default_status(),
            StatusCode::NOT_FOUND,
            "{}: `{spelling}` is not a 404, so `ErrorCode::not_configured` may not be used for it",
            row.operation
        );
        assert_eq!(
            ErrorCode::not_configured(spelling),
            declared,
            "{}: the const constructor and the authority disagree about `{spelling}`",
            row.operation
        );
    }
    assert!(
        seen >= 12,
        "the generated table carries {seen} unconfigured codes; the overlay declares twelve, so the \
         emitter has dropped the field and the loop above proved nothing"
    );
}

/// One concrete row, so that an emitter that wrote `None` everywhere fails here rather than
/// passing the loop above with an empty set.
///
/// `GetBucketLifecycleConfiguration` is the anchor because it is the rule gateway#242 was reported
/// against: its code was lowered into a table nothing outside a `#[cfg(test)]` module included, so
/// flipping the overlay changed nothing served and `q-lc-0001` reported `INERT`.
#[test]
fn the_lifecycle_read_lowers_its_own_code_into_the_route_table() {
    let row = ROUTES
        .iter()
        .find(|row| row.operation == "GetBucketLifecycleConfiguration")
        .expect("the operation has a generated route row");
    assert_eq!(row.not_configured, Some("NoSuchLifecycleConfiguration"));

    let sibling = ROUTES
        .iter()
        .find(|row| row.operation == "PutBucketLifecycleConfiguration")
        .expect("the operation has a generated route row");
    assert_eq!(
        sibling.not_configured, None,
        "a write reads no configuration, so a 404 from it would mean `no such bucket` to a client"
    );
}
