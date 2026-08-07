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

//! The extension points a deployment mounts on the assembled service.
//!
//! Responsible for: mounting one module per extension point, and stating the rule that binds all
//! of them.
//! NOT responsible for: assembling them (`crate::builder`), calling them in order
//! (`crate::service`), or any protocol behaviour.
//! Upstream: `rustfs-gateway-core`'s `BoxFuture` alias. Downstream: `crate::builder`.
//!
//! # The two rules every extension point here follows
//!
//! 1. **Asynchronous methods are hand-written `-> BoxFuture<'_, T>`** (ADR-0002). Every trait here
//!    is held as `Arc<dyn _>` by the assembled service, and RPITIT is measurably not dyn
//!    compatible. `Handler<O>` and `Operation` are the only two exceptions in the workspace, and
//!    neither of them is here.
//! 2. **A synchronous extension point must justify itself in its own module docs.** Two of them
//!    are synchronous — [`HostResolver`] and [`Observer`] — and both justifications are about
//!    where they run rather than about convenience.
//!
//! # Which of these have a default, and what the default costs
//!
//! | Extension point | Default | What the default means |
//! | --- | --- | --- |
//! | [`Authorizer`] | none — [`crate::ServiceBuilder::build`] refuses | there is no safe default: allow-all is a hole, deny-all is a service nobody can use |
//! | [`Authenticator`] | none — `build` refuses | the same asymmetry, one stage earlier |
//! | [`HostResolver`] | [`PathStyleOnly`] | a virtual-hosted request is routed by its path, so `Host: bucket.example.com` addressing `/key` is not understood |
//! | [`Governor`] | [`Unlimited`] | no request is ever refused for load, in either the per-bucket or the per-identity dimension |
//! | [`Observer`] | [`NoObserver`] | nothing is recorded; a rejection leaves no trace outside the response |
//!
//! Every default above is safe in the sense that it cannot widen access. Two of them —
//! [`Unlimited`] and [`NoObserver`] — remove a defence rather than open a door, and a deployment
//! that ships with both has no rate limit and no audit trail.

mod authenticator;
mod authorizer;
mod credentials;
mod governor;
mod host;
mod observer;

pub use self::authenticator::{Authentication, Authenticator, ChunkSink, ChunkVerification, SigV4Authenticator, Unavailable};
pub use self::authorizer::{Authorizer, AuthzRequest, Denial, allow_when};
pub use self::credentials::{CredentialProvider, Credentials, CredentialsError, StaticCredentials};
pub use self::governor::{Governor, GovernorRequest, Lease, Unlimited};
pub use self::host::{HostQuery, HostResolver, PathStyleOnly, ResolvedHost};
pub use self::observer::{NoObserver, Observer, RequestEvent};
