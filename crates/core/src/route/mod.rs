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

//! Which S3 operation a request names — decided before anything is authenticated.
//!
//! Responsible for: the ordered first-match route table, the closed predicate set, the build-time
//! overlap decision, the compiled lookup form, and the explanation a human asks for.
//! NOT responsible for: whether the request's parameters are valid (`crate::registry`), whether
//! the backend implements the operation (`crate::dispatch`), or anything that reads a body.
//! Upstream: `rustfs-gateway-http`'s borrowed views. Downstream: `crate::dispatch`.
//!
//! ```text
//!   selector.rs  the closed predicate set and how one is evaluated
//!   lattice.rs   can two selectors be satisfied at once — a decision, not a comparison
//!   shape.rs     the concrete request a conflict is reported with
//!   table.rs     the ordered table, the build-time refusals, the readable matcher
//!   shadowing.rs the reviewed record of who wins across precedences
//!   mask.rs      every routing query key as one bit, derived from the table itself
//!   compiled.rs  the same table as an array index
//!   explain.rs   what the table did with one request, and what it did not do
//!   generated.rs the row types `generated/routes.rs` is written against
//! ```
//!
//! # The one invariant this module exists to hold
//!
//! Routing happens **before** the signature is verified. So nothing here is `async`, nothing here
//! takes a store, a repository, a connection or any other handle, and nothing here reads a body
//! byte. A router that could await or read storage is an unauthenticated amplifier: an attacker
//! who cannot produce a signature still gets to make the service do work. The predicate set is a
//! closed `enum` rather than a boxed callback for the same reason — the property is checkable by
//! reading one file, and `crates/core/tests/purity_guard.rs` checks it over the source.

mod compiled;
mod explain;
mod generated;
mod lattice;
mod mask;
mod selector;
mod shadowing;
mod shape;
mod table;

pub use self::compiled::{CompiledRouter, OpId, RouteBucket};
pub use self::explain::{Explained, Explanation};
pub use self::generated::{ROUTES, RoutePredicate, RouteRow, RowError, generated_entries};
pub use self::lattice::{Contradiction, OverlapError};
pub use self::mask::{CompileError, MAX_SUBRESOURCE_KEYS, SubresourceBits};
pub use self::selector::{ArnForm, HostClass, Predicate, RouteEntry, RouteRequestParts, RouteSelector, TargetKind};
pub use self::shadowing::{PROVISIONAL_SHADOWING, ShadowingDecl, ShadowingDecls, ShadowingPolicy};
pub use self::shape::RequestShape;
pub use self::table::{FALLBACK_BAND, RouteBuildError, RouteTable, SelectorReport, render_selector};
