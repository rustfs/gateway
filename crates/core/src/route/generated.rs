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
//! # A gap worth knowing about
//!
//! [`RoutePredicate`] has eight variants; [`Predicate`] has ten. `HostClass` and `ArnForm` are in
//! the frozen IR schema and in this crate, but `rustfs-gateway-model`'s `Predicate` does not carry
//! them yet, so codegen cannot emit them. Adding the two variants here pre-emptively would be
//! inventing a spelling that the emitter has never produced and might not match. They are
//! therefore constructible by hand and by tests, but not yet reachable from the model — recorded
//! in `MAP.md` for the maintainer rather than silently papered over.

use http::Method;

use super::selector::{Predicate, RouteEntry, RouteSelector, TargetKind};
use crate::contracts::{SELECT_TYPE_ROUTE_PREDICATE, SelectTypeRoutePredicatePolicy};

/// One row of the generated route table.
///
/// Field for field what `rustfs-gateway-codegen`'s `routes` emitter writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRow {
    /// The operation name.
    pub operation: &'static str,
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
}

/// The generated table. Data only; the types above are its vocabulary.
///
/// Mounted in a module of its own so that the crate-wide `missing_docs = "deny"` can be lifted for
/// exactly one item — the generated `ROUTES` static, which the emitter does not write a doc comment
/// for and which this task may not edit. Lifting it at the crate root would silence the lint for
/// every hand-written item too.
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

/// Every generated row as a typed entry.
///
/// # Errors
///
/// The first [`RowError`] encountered.
pub fn generated_entries() -> Result<Vec<RouteEntry>, RowError> {
    ROUTES.iter().map(RouteRow::to_entry).collect()
}
