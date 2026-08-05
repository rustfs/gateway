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

//! Operations, routing, the typed pipeline, and the extension points.
//!
//! Responsible for: `Operation`/`OperationSpec`, the ordered route table, the type-state
//! pipeline, and every extension trait (`Authorizer`, `HostResolver`, `Governor`, ...).
//! NOT responsible for: HTTP transport assembly (that is the `rustfs-gateway` facade).
//! Upstream: `rustfs-gateway-sig`. Downstream: `rustfs-gateway`.
//!
//! # What P4-01, P4-02 and P4-03 landed
//!
//! ```text
//!   route      which operation a request names — decided before anything is authenticated
//!   registry   what that operation requires of the request, and whether this backend handles it
//!   error      what may be said about a request from a caller nobody has identified yet
//!   dispatch   the three questions in order, each with its own failure
//! ```
//!
//! Three properties hold this together. Everything else here exists to serve them.
//!
//! 1. **Routing is ordered, not disjoint.** `GET /bucket?acl&tagging` names two subresources and
//!    AWS answers it, picking one by a fixed internal order. A table that refuses to start unless
//!    no two selectors overlap either rejects that request or needs quadratically many `Absent`
//!    predicates, which AWS invalidates every time it adds a subresource. So entries carry a
//!    `precedence` and the first match wins. What stays forbidden is an overlap *within* one
//!    precedence, where the winner would be decided by sort order — an accident nobody reviewed.
//! 2. **Overlap is decided, not compared.** `GET /b?acl` and `GET /b` are not equal, share no
//!    query key, and one of them is dead. The build normalises each selector into constraints over
//!    independent dimensions, meets them, and — when the meet is non-empty — materialises a
//!    concrete request and runs it back through the ordinary matcher. The decision procedure is
//!    checked by the thing it is about, so a bug in it cannot quietly report "no conflict".
//! 3. **Routing decides which operation, and nothing else.** A missing required parameter is a
//!    `400` from the operation that was already selected, never a `501`. Encoding requiredness as
//!    a routing predicate turns a client's parameter mistake into "this service does not support
//!    that operation", and clients act on that by disabling the feature rather than fixing the
//!    request.
//!
//! Everything on the pre-authentication path is non-`async`, holds no store handle, allocates
//! nothing per request, and can say nothing about the request beyond a compile-time constant.
//! `tests/purity_guard.rs` asserts each of those over the source.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

pub mod dispatch;
pub mod error;
pub mod registry;
pub mod route;

pub use crate::dispatch::{Dispatch, Router, RouterBuildError};
pub use crate::error::{DisallowedPreAuthCode, PRE_AUTH_STATUSES, PreAuthError};
pub use crate::registry::{OperationSpec, ParamKind, Registry, RegistryError, RequiredParam, check_required};
pub use crate::route::{
    ArnForm, CompileError, CompiledRouter, Explanation, HostClass, OpId, Predicate, RequestShape, RouteBuildError, RouteEntry,
    RouteRequestParts, RouteSelector, RouteTable, ShadowingDecl, ShadowingDecls, ShadowingPolicy, TargetKind,
};
