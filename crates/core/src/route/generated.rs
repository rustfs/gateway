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

//! The row types `generated/routes.rs` is written against, and the parse into typed entries.
//!
//! Responsible for: [`RouteRow`] and [`RoutePredicate`] — the data-only shapes the emitter in
//! `rustfs-gateway-codegen` renders — mounting the generated table, and converting a row into a
//! [`RouteEntry`] with every string checked.
//! NOT responsible for: emitting the table, assigning precedence (codegen does both from the route
//! overlay), or anything about matching.
//! Upstream: `generated/routes.rs`, `selector`. Downstream: `table`, `crate::registry`.
//!
//! # Why the generated file mentions types it does not define
//!
//! A generated file that minted its own public type names would put names into the tree that
//! `grep` cannot trace back to a hand-written declaration — the rule the macro-governance section
//! of `AGENTS.md` exists to enforce. So the emitter writes data and this module owns the types.
//! The consequence is that these two declarations and
//! `crates/codegen/src/emit/rust_files.rs::predicate` are one contract in two files: a variant
//! spelled differently in either place is a compile error, which is the intended failure mode.
//!
//! The tree is mounted through `crates/core/generated`, a symlink onto the top-level `generated/`,
//! for the reason ADR-0005 gives for `rustfs-gateway-types`: an `include!` may not reach outside
//! the package directory, and the symlink is what puts the generated tree inside it.
//!
//! # A gap that used to exist here
//!
//! Until `rustfs/gateway#3`, [`RoutePredicate`] had eight variants against [`Predicate`]'s ten:
//! `HostClass` and `ArnForm` were in the frozen IR schema and in this crate, but
//! `rustfs-gateway-model`'s `Predicate` could not carry them, so codegen could not emit either one.
//! Both are now reachable end to end — `rustfs-gateway-model`'s `Predicate::HostClass`/`ArnForm`,
//! `rustfs-gateway-codegen`'s `rust_files::predicate` — but no operation's overlay entry sets
//! `host_class` or `arn_form` yet, so `ROUTES` below still carries neither spelling. The two
//! variants are proved reachable by `RouteRow::to_entry` reading them, not by a real generated row.

use http::Method;

use super::selector::{ArnForm, HostClass, Predicate, RouteEntry, RouteSelector, TargetKind};
use crate::contracts::{SELECT_TYPE_ROUTE_PREDICATE, SelectTypeRoutePredicatePolicy};

/// One row of the generated route table.
///
/// Field for field what `rustfs-gateway-codegen`'s `routes` emitter writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRow {
    /// The operation name.
    pub operation: &'static str,
    /// Whether codegen emitted the typed surfaces a backend can register a handler for.
    pub handler_registration: bool,
    /// Position in the ordered table; lower is tried first.
    pub precedence: u16,
    /// The method, as an IR spelling.
    pub method: &'static str,
    /// What the path addresses, as an IR spelling.
    pub target: &'static str,
    /// The reverse-index path shape.
    pub path_shape: &'static str,
    /// The default success status.
    pub success_status: u16,
    /// The operation-specific `404` code for a bucket subresource that was never configured, as a
    /// wire spelling, or `None` when the operation has no such condition.
    ///
    /// Not routing, and neither is `success_status` above: both are per-operation facts, and this
    /// table is the one generated per-operation table `rustfs-gateway-core` compiles. The code
    /// used to be rendered into `generated/error_codes.rs`, which nothing outside a `#[cfg(test)]`
    /// module ever included — a lowered rule with no reader, recorded as gateway#242.
    pub not_configured: Option<&'static str>,
    /// The routing conjunction.
    pub predicates: &'static [RoutePredicate],
}

/// A predicate as the emitter writes it: every operand a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePredicate {
    /// `Method("GET")`.
    Method(&'static str),
    /// `Target("Bucket")`.
    Target(&'static str),
    /// `QueryPresent("acl")`.
    QueryPresent(&'static str),
    /// `QueryEquals("list-type", "2")`.
    QueryEquals(&'static str, &'static str),
    /// `QueryAbsent("uploadId")`.
    QueryAbsent(&'static str),
    /// `HeaderPresent("x-amz-copy-source", false)` — the boolean negates the test.
    HeaderPresent(&'static str, bool),
    /// `HeaderPrefix("content-type", "multipart/form-data")`.
    HeaderPrefix(&'static str, &'static str),
    /// `PathLiteral("/WriteGetObjectResponse")`.
    PathLiteral(&'static str),
    /// `HostClass("ObjectLambda")`, the IR spelling `HostClass::as_str` produces.
    HostClass(&'static str),
    /// `ArnForm("AccessPoint")`, the IR spelling `ArnForm::as_str` produces.
    ArnForm(&'static str),
}

/// The generated table. Data only; the types above are its vocabulary.
///
/// Mounted in a module of its own so that the crate-wide `missing_docs = "deny"` can be lifted for
/// exactly one item — the generated `ROUTES` constant, which the emitter does not write a doc
/// comment for and which this task may not edit. Lifting it at the crate root would silence the
/// lint for every hand-written item too.
#[allow(missing_docs, reason = "the emitter writes data, not rustdoc; see the module docs")]
mod data {
    use super::{RoutePredicate, RouteRow};

    include!("../../generated/routes.rs");
}

pub use self::data::ROUTES;

/// A generated row this crate cannot turn into a route entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowError {
    /// The operation the row names.
    pub operation: &'static str,
    /// What could not be read.
    pub detail: String,
}

impl std::fmt::Display for RowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "generated route row for {}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for RowError {}

/// Parses a method spelling without allocating.
///
/// `Method::from_bytes` would accept any token and allocate for one it does not know; the IR's
/// method vocabulary is closed, and a row naming a method outside it is a codegen bug rather than
/// an extension point.
fn method_of(text: &str) -> Option<Method> {
    match text {
        "GET" => Some(Method::GET),
        "PUT" => Some(Method::PUT),
        "POST" => Some(Method::POST),
        "DELETE" => Some(Method::DELETE),
        "HEAD" => Some(Method::HEAD),
        "OPTIONS" => Some(Method::OPTIONS),
        _ => None,
    }
}

impl RouteRow {
    /// The typed entry this row describes.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a spelling is outside its closed vocabulary, or when the row's own
    /// `method`/`target` fields disagree with its predicates. The second check matters: the two
    /// are separate fields in the IR, a consumer may read either, and a row where they disagree
    /// would route one way and be documented another.
    pub fn to_entry(&self) -> Result<RouteEntry, RowError> {
        let error = |detail: String| RowError {
            operation: self.operation,
            detail,
        };
        let row_method = method_of(self.method).ok_or_else(|| error(format!("unknown method {:?}", self.method)))?;
        let row_target = TargetKind::parse(self.target).ok_or_else(|| error(format!("unknown target {:?}", self.target)))?;

        let mut predicates = Vec::with_capacity(self.predicates.len());
        for predicate in self.predicates {
            predicates.push(match *predicate {
                RoutePredicate::Method(text) => {
                    let method = method_of(text).ok_or_else(|| error(format!("unknown method {text:?}")))?;
                    if method != row_method {
                        return Err(error(format!("predicate Method({text}) contradicts the row's method {}", self.method)));
                    }
                    Predicate::Method(method)
                }
                RoutePredicate::Target(text) => {
                    let target = TargetKind::parse(text).ok_or_else(|| error(format!("unknown target {text:?}")))?;
                    if target != row_target {
                        return Err(error(format!("predicate Target({text}) contradicts the row's target {}", self.target)));
                    }
                    Predicate::Target(target)
                }
                RoutePredicate::QueryPresent(key) => Predicate::QueryPresent(key),
                RoutePredicate::QueryEquals("select-type", _)
                    if matches!(SELECT_TYPE_ROUTE_PREDICATE, SelectTypeRoutePredicatePolicy::PresentAnyValue) =>
                {
                    Predicate::QueryPresent("select-type")
                }
                RoutePredicate::QueryEquals(key, value) => Predicate::QueryEquals(key, value),
                RoutePredicate::QueryAbsent(key) => Predicate::QueryAbsent(key),
                RoutePredicate::HeaderPresent(header, negated) => Predicate::HeaderPresent { header, negated },
                RoutePredicate::HeaderPrefix(header, prefix) => Predicate::HeaderPrefix(header, prefix),
                RoutePredicate::PathLiteral(path) => Predicate::PathLiteral(path),
                RoutePredicate::HostClass(text) => {
                    let class = HostClass::parse(text).ok_or_else(|| error(format!("unknown host class {text:?}")))?;
                    Predicate::HostClass(class)
                }
                RoutePredicate::ArnForm(text) => {
                    let form = ArnForm::parse(text).ok_or_else(|| error(format!("unknown ARN form {text:?}")))?;
                    Predicate::ArnForm(form)
                }
            });
        }

        Ok(RouteEntry {
            precedence: self.precedence,
            selector: RouteSelector::owned(predicates),
            op_name: self.operation,
            path_shape: self.path_shape,
        })
    }
}

/// The generated row for one operation, or `None` when the table has no row for that name.
///
/// A `const fn` on purpose: [`crate::registry::OperationSpec::standard`] is how a standard
/// operation reads its own facts, and an operation's specification is a `static` built at compile
/// time. A run-time accessor would have left the hand-written literal in place, which is the
/// duplication this lookup exists to remove.
#[must_use]
// Const context only: `<[T]>::get` is not a `const fn` on this toolchain, and an out-of-range index
// here is a compile-time evaluation failure, never a panic a request can reach.
#[allow(clippy::indexing_slicing, reason = "const-evaluated bounds; see the comment above")]
pub const fn row_of(operation: &str) -> Option<&'static RouteRow> {
    let mut index = 0;
    while index < ROUTES.len() {
        let row = &ROUTES[index];
        if str_eq(row.operation, operation) {
            return Some(row);
        }
        index += 1;
    }
    None
}

/// Byte equality of two strings in const context.
///
/// `str::eq` is not `const`, and the alternative — passing the status as a literal and comparing it
/// later — is the second copy this module is removing.
// Same reason as `row_of`: every index is const-evaluated and guarded by the length check above it.
#[allow(clippy::indexing_slicing, reason = "const-evaluated bounds; see the comment above")]
const fn str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Every generated row as a typed entry.
///
/// # Errors
///
/// The first [`RowError`] encountered.
pub fn generated_entries() -> Result<Vec<RouteEntry>, RowError> {
    ROUTES.iter().map(RouteRow::to_entry).collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{ArnForm, HostClass, Predicate, RoutePredicate, RouteRow};

    const HOST_CLASS_ROW: RoutePredicate = RoutePredicate::HostClass("ObjectLambda");
    const ARN_FORM_ROW: RoutePredicate = RoutePredicate::ArnForm("AccessPoint");
    const UNKNOWN_HOST_CLASS_ROW: RoutePredicate = RoutePredicate::HostClass("Nope");
    const UNKNOWN_ARN_FORM_ROW: RoutePredicate = RoutePredicate::ArnForm("Nope");

    /// The row this test builds does not exist in `ROUTES` — no operation's overlay sets
    /// `host_class` yet (`rustfs/gateway#3`) — so this is the proof that [`RoutePredicate::HostClass`]
    /// and [`RoutePredicate::ArnForm`] are reachable the moment codegen does emit either spelling,
    /// not a claim about the current generated table.
    fn synthetic_row(predicates: &'static [RoutePredicate]) -> RouteRow {
        RouteRow {
            operation: "SyntheticProbe",
            handler_registration: true,
            precedence: 999,
            method: "POST",
            target: "Object",
            path_shape: "/{Bucket}/{Key+}",
            success_status: 200,
            not_configured: None,
            predicates,
        }
    }

    #[test]
    fn to_entry_reads_a_generated_host_class_predicate() {
        const PREDICATES: &[RoutePredicate] = &[
            RoutePredicate::Method("POST"),
            RoutePredicate::Target("Object"),
            HOST_CLASS_ROW,
        ];
        let entry = synthetic_row(PREDICATES).to_entry().expect("a known host class converts");
        assert!(
            entry
                .selector
                .predicates()
                .contains(&Predicate::HostClass(HostClass::ObjectLambda))
        );
    }

    #[test]
    fn to_entry_reads_a_generated_arn_form_predicate() {
        const PREDICATES: &[RoutePredicate] = &[RoutePredicate::Method("POST"), RoutePredicate::Target("Object"), ARN_FORM_ROW];
        let entry = synthetic_row(PREDICATES).to_entry().expect("a known ARN form converts");
        assert!(
            entry
                .selector
                .predicates()
                .contains(&Predicate::ArnForm(ArnForm::AccessPoint))
        );
    }

    #[test]
    fn n_to_entry_rejects_an_unknown_host_class_spelling() {
        const PREDICATES: &[RoutePredicate] = &[
            RoutePredicate::Method("POST"),
            RoutePredicate::Target("Object"),
            UNKNOWN_HOST_CLASS_ROW,
        ];
        let err = synthetic_row(PREDICATES)
            .to_entry()
            .expect_err("an unknown spelling must not convert");
        assert!(format!("{err}").contains("unknown host class"), "{err}");
    }

    #[test]
    fn n_to_entry_rejects_an_unknown_arn_form_spelling() {
        const PREDICATES: &[RoutePredicate] = &[
            RoutePredicate::Method("POST"),
            RoutePredicate::Target("Object"),
            UNKNOWN_ARN_FORM_ROW,
        ];
        let err = synthetic_row(PREDICATES)
            .to_entry()
            .expect_err("an unknown spelling must not convert");
        assert!(format!("{err}").contains("unknown ARN form"), "{err}");
    }
}
