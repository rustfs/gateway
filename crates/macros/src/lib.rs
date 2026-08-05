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

//! `#[handlers]`: the optional sugar that writes the `impl Handler<O>` blocks nobody wants to type.
//!
//! Responsible for: the attribute macro's entry point, and nothing else. The expansion lives in
//! [`expand`], the name mapping in [`mapping`], the suggestion metric in [`levenshtein`], and the
//! operation names in [`op_names`].
//! NOT responsible for: registration semantics (that is `rustfs-gateway-core`), specs, floors,
//! or authorisation. The macro never decides anything a reader could not decide by looking at the
//! method name.
//! Upstream: `syn`, `quote`. Downstream: any backend crate that would rather not write 73
//! delegating `impl` blocks by hand.
//!
//! # What it does, in one sentence
//!
//! For each `async fn <operation_in_snake_case>` in an inherent `impl`, it writes one
//! `impl Handler<Operation>` whose body is `self.<the same method>(request)`, and one
//! `register[_<group>]` function that calls `RouterBuilder::handle` once per method.
//!
//! # The hand-written equivalent, which always works
//!
//! ```ignore
//! // With the macro:
//! #[rustfs_gateway_macros::handlers(group = objects)]
//! impl Fs {
//!     async fn put_object(&self, req: Req<PutObject>) -> HandlerResult<PutObject> { /* ... */ }
//! }
//!
//! // Without it — this is exactly what the macro emits, and it is a supported way to write a
//! // backend. Nothing in the framework requires the macro:
//! impl Fs {
//!     async fn put_object(&self, req: Req<PutObject>) -> HandlerResult<PutObject> { /* ... */ }
//!
//!     pub fn register_objects(this: &Arc<Self>, builder: RouterBuilder) -> RouterBuilder {
//!         builder.handle::<PutObject, Self>(Arc::clone(this))
//!     }
//! }
//! impl Handler<PutObject> for Fs {
//!     fn call(&self, request: Req<PutObject>) -> impl Future<Output = HandlerResult<PutObject>> + Send {
//!         self.put_object(request)
//!     }
//! }
//! ```
//!
//! `crates/macros/tests/equivalence.rs` proves the two produce the same registry, and
//! `tests/expand/*.expanded.rs` holds the expansion in the repository so that reading it never
//! requires understanding this crate.
//!
//! # The five rules this macro is held to
//!
//! 1. Declarative registration only: no function body is rewritten, and no public type name is
//!    minted. A generated type name is invisible to `grep`, and an agent that cannot find a
//!    definition cannot work.
//! 2. The expansion goldens are in the repository, refreshed with `UPDATE_GOLDEN=1`.
//! 3. A macro-free equivalent exists and is documented beside every example.
//! 4. A test proves the macro form and the hand-written form register the same operations with the
//!    same behaviour.
//! 5. Errors point at the method name, not at the `impl` block, and suggest near misses.

mod expand;
mod levenshtein;
mod mapping;
mod op_names;

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;

/// Registers each `async fn` in an inherent `impl` block as the handler for the operation its name
/// spells.
///
/// The method name is the snake_case spelling of the AWS operation name: `put_object` is
/// `PutObject`, `list_objects_v2` is `ListObjectsV2`. The mapping is mechanical and has no
/// exceptions.
///
/// # Arguments
///
/// * `group = <ident>` — emit `register_<ident>` instead of `register`, so that one backend can
///   have several `#[handlers]` blocks in several files. Nothing is generated to stitch them
///   together: the assembly point calls each one, which is a line `grep` can find.
///
/// # Per-method attributes
///
/// * `#[handlers(skip)]` — leave the method alone. Required for a helper: an unrecognised method
///   name is an error rather than a silent skip, because the failure it prevents is a handler that
///   is never called and never mentioned.
///
/// # Errors
///
/// A compile error on the method name identifier when it does not spell an operation, with the
/// nearest names as suggestions; and on the `Req<...>` type when the signature disagrees with the
/// method name.
#[proc_macro_attribute]
pub fn handlers(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
