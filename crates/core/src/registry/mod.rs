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

//! What an operation requires of a request, and which operations this backend actually handles.
//!
//! Responsible for: [`OperationSpec`], [`RequiredParam`], [`check_required`] — the parameter
//! validation that runs *after* routing — and [`Registry`], the explicit list of operations a
//! backend has registered.
//! NOT responsible for: choosing the operation (`crate::route`), decoding anything, or the
//! per-operation error codes beyond the two the spec carries.
//! Upstream: `crate::error`, `crate::route`, `rustfs-gateway-types`. Downstream: `crate::dispatch`.
//!
//! ```text
//!   mod.rs      the spec, the required-parameter check, and the registry itself
//!   reject.rs   what registration refuses, and why each refusal is a security decision
//!   handlers.rs where the backend type disappears; the only file here that awaits
//!   codecs.rs   where the operation type disappears: decode and encode, by name
//!   opset.rs    which operations a deployment insists on, and the sentence when some are missing
//!   builder.rs  assembly: routes, handlers, completeness, and one router or one error
//! ```
//!
//! # Registration is explicit, and that is the feature
//!
//! There is no `inventory`, no `linkme`, no `ctor` — banned by ADR-0003 after `error[E0117]` was
//! measured and after the only workaround turned the registry into a process-global singleton,
//! which breaks the two-backends-in-one-process arrangement RustFS already relies on. So every
//! operation this backend answers is a call somebody wrote, and `grep` finds it.
//!
//! # Routing and validation are different questions
//!
//! `PutBucketAnalyticsConfiguration` requires an `id` query parameter. There are two wrong ways to
//! model that and one right one.
//!
//! Leaving it out of the model entirely — routing on `?analytics` alone — turns a missing `id`
//! into a decode failure somewhere downstream, with whatever code that layer happens to raise.
//!
//! Putting it into the *selector* as a `QueryPresent("id")` predicate is worse. A request without
//! `id` then matches no entry at all, and no entry means `501 NotImplemented`: the gateway tells
//! the client that this service does not support the operation. A client that believes it will
//! disable the feature rather than fix its request, and an operator reading the logs goes looking
//! for a missing handler that is not missing.
//!
//! So requiredness lives here, in per-operation metadata, and is evaluated once the operation is
//! already known. That is what makes the answer a `400` naming the parameter — the operation is
//! decided, so its own error code and its own message are available.
//!
//! The one case where a query key is legitimately in a selector is when it *discriminates*:
//! `?analytics` with `id` is `GetBucketAnalyticsConfiguration` and without it is
//! `ListBucketAnalyticsConfigurations`. There `id` is a discriminator on the first and a required
//! parameter on the second — two facts about the same key, recorded separately, and the spec
//! consistency check in codegen is what stops a table from carrying only one of them.

mod builder;
mod codecs;
mod handlers;
mod opset;
mod reject;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use rustfs_gateway_types::ErrorCode;

use crate::codec::OperationCodec;
use crate::error::PreAuthError;
use crate::handler::{Handler, Req};
use crate::op::{AuthRequirement, Operation};
use crate::route::RouteRequestParts;

pub use self::builder::{BuildError, RouterBuilder};
pub use self::codecs::{ErasedCodec, ErasedDecode, ErasedEncode};
pub use self::handlers::{ErasedHandler, ErasedRequest, ErasedResponse, HandlerTable, Invocation};
pub use self::opset::{MissingHandlers, OperationSet};
pub use self::reject::RegistryError;

/// Where a required parameter is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    /// A query parameter.
    Query,
    /// A request header, by lowercase name.
    Header,
}

/// A parameter an operation cannot proceed without.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredParam {
    /// Query or header.
    pub kind: ParamKind,
    /// The wire name.
    pub name: &'static str,
    /// The code to raise when it is absent. `InvalidArgument` unless AWS says otherwise.
    pub missing_error: ErrorCode,
    /// The message to send. Static, and it must not echo anything the caller sent.
    pub message: &'static str,
}

/// The per-operation metadata this crate needs after routing.
///
/// A subset of the IR: the fields that matter between "we know which operation this is" and "the
/// decoder takes over".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    /// The operation name, matching the route entry.
    pub name: &'static str,
    /// The default success status. `204` for the delete family, `303` for a POST Object redirect.
    pub success_status: u16,
    /// Parameters checked after routing and before decoding.
    pub required_params: &'static [RequiredParam],
    /// The operation-specific `404` for a bucket subresource that was never configured.
    ///
    /// A code-to-status table cannot express this: `GetBucketLifecycleConfiguration` on an
    /// unconfigured bucket is `NoSuchLifecycleConfiguration`, not a generic not-found, and a client
    /// that branches on the specific code sees a different outcome.
    pub not_configured_error: Option<ErrorCode>,
    /// The action this operation is authorised against.
    ///
    /// `Option` so that registration can refuse the `None`: an operation nobody can authorise is
    /// an operation whose authorisation check can be forgotten, which is what happened in
    /// rustfs/rustfs#4845. Every registration path goes through
    /// [`RegistryError::MissingAuthRequirement`], so there is no way to install a handler for one.
    pub auth: Option<AuthRequirement>,
}

/// The operations this backend handles, and the erased handler for each one that has one.
///
/// Explicit and greppable: registration is a call somebody wrote, never a link-time side effect.
/// `inventory` and `linkme` are forbidden by ADR-0003 precisely so that "who registered this?" has
/// an answer `grep` can find.
///
/// A registry belongs to one [`RouterBuilder`]; it is never a process-global. That is what lets a
/// test backend and a production backend live in the same process with separate registrations,
/// which RustFS's end-to-end suite already does.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    specs: BTreeMap<&'static str, &'static OperationSpec>,
    handlers: HandlerTable,
}

impl Registry {
    /// An empty registry: every route resolves, and every one of them is `501`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one operation's spec, without a handler.
    ///
    /// Routing and parameter validation then work for it, and an invocation still finds nothing —
    /// which is the state a dispatch-only test wants and a deployment does not. Prefer
    /// [`Registry::register_handler`], which cannot leave that gap.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] for a duplicate name, an operation with no authorisation action, or a
    /// required parameter whose code could not be raised before authentication. Doing these checks
    /// here rather than per request is what lets [`check_required`] be infallible in the only way
    /// that matters.
    pub fn register(&mut self, spec: &'static OperationSpec) -> Result<(), RegistryError> {
        reject::check_spec(spec)?;
        if self.specs.contains_key(spec.name) {
            // Checked before the insert, not after: `insert` replaces, so reporting the duplicate
            // afterwards would leave the second registration installed and the error ignorable.
            return Err(RegistryError::Duplicate { name: spec.name });
        }
        self.specs.insert(spec.name, spec);
        Ok(())
    }

    /// Registers one operation, the backend that answers it, and its wire codec.
    ///
    /// This is where both types are erased. `implementation` is consumed into a closure, so
    /// nothing downstream is generic over the backend; `O`'s [`OperationCodec`] is consumed into
    /// two more, so nothing downstream is generic over the operation either. All three are stored
    /// in one entry, in one call — the only call that has the type `O` and the name `O::NAME` in
    /// scope at once, which is why the bridge from a run-time name to a compile-time codec can be
    /// built here and nowhere later.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] for any rule in [`reject`]: a name that is not namespaced, a third-party
    /// name colliding with an AWS one, a missing authorisation action, a spec or floor registered
    /// under another name, or a duplicate.
    pub fn register_handler<O, B>(&mut self, implementation: Arc<B>) -> Result<(), RegistryError>
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        self.install::<O, B>(implementation, Some(codecs::erase::<O>()))
    }

    /// Registers one operation and its backend, for an operation whose wire form this crate does
    /// not define.
    ///
    /// The escape hatch for a dialect operation that has no [`OperationCodec`] — an admin call
    /// whose transport is somebody else's, or a dispatch-only test. Routing, registration refusals
    /// and the typed [`Registry::invoke`] path all work; what does not is serving it from the
    /// wire, because nothing here can turn bytes into its input. The name says so at the call
    /// site, and [`HandlerTable::names_without_codec`] says so afterwards, which is what lets an
    /// assembly-time check refuse to start a service that would route such an operation and then
    /// have nothing able to read it.
    ///
    /// # Errors
    ///
    /// The same set as [`Registry::register_handler`].
    pub fn register_handler_without_codec<O, B>(&mut self, implementation: Arc<B>) -> Result<(), RegistryError>
    where
        O: Operation,
        B: Handler<O>,
    {
        self.install::<O, B>(implementation, None)
    }

    /// The one insertion point: spec, handler and codec, or nothing at all.
    ///
    /// Private and shared by both registration paths, so "a handler was installed without its
    /// codec being considered" is not a state any sequence of public calls can reach.
    fn install<O, B>(&mut self, implementation: Arc<B>, codec: Option<ErasedCodec>) -> Result<(), RegistryError>
    where
        O: Operation,
        B: Handler<O>,
    {
        reject::check_operation::<O>()?;
        if self.specs.contains_key(O::NAME) || self.handlers.contains(O::NAME) {
            return Err(RegistryError::Duplicate { name: O::NAME });
        }
        self.specs.insert(O::NAME, O::spec());
        self.handlers.insert(O::NAME, handlers::erase::<O, B>(implementation), codec);
        Ok(())
    }

    /// The spec for an operation, if this backend handles it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static OperationSpec> {
        self.specs.get(name).copied()
    }

    /// The erased handlers, with their codecs.
    #[must_use]
    pub const fn handlers(&self) -> &HandlerTable {
        &self.handlers
    }

    /// The erased handler registered under a name.
    #[must_use]
    pub fn handler(&self, name: &str) -> Option<&ErasedHandler> {
        self.handlers.handler(name)
    }

    /// The codec registered with that handler, when the operation has one.
    #[must_use]
    pub fn codec(&self, name: &str) -> Option<&ErasedCodec> {
        self.handlers.codec(name)
    }

    /// Everything needed to answer one request under a name: the spec, the decoder, the handler
    /// and the encoder.
    ///
    /// The pipeline's entry point. It holds an operation name from the route table and no
    /// operation type, and these four are what it needs to turn bytes into an answer — found
    /// together so that a caller cannot pair one operation's decoder with another's handler.
    ///
    /// `None` when the name is not registered, and also when it is registered without a codec: in
    /// both cases there is no way to read the request, which is the same outcome from the wire.
    /// The two are distinguishable before any request arrives — [`Registry::handler`] finds the
    /// second and [`HandlerTable::names_without_codec`] names it — so a service can refuse to
    /// start rather than discovering it under traffic.
    #[must_use]
    pub fn wire(&self, name: &str) -> Option<WireEntry<'_>> {
        let spec = self.get(name)?;
        let (handler, codec) = self.handlers.pair(name)?;
        let codec = codec?;
        Some(WireEntry {
            spec,
            handler,
            decode: codec.decoder(),
            encode: codec.encoder(),
        })
    }

    /// Calls the handler registered for `O`, if there is one.
    ///
    /// `None` is the 501: an operation with no handler is not an error condition, it is a backend
    /// that does not implement it. No default method anywhere had to be written for that.
    #[must_use]
    pub fn invoke<O: Operation>(&self, request: Req<O>) -> Option<Invocation<O>> {
        self.handlers.invoke(request)
    }

    /// How many operations are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Every registered operation name, sorted.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        self.specs.keys().copied().collect::<Vec<_>>().into_iter()
    }

    /// Every operation with a handler, sorted.
    pub fn handler_names(&self) -> impl Iterator<Item = &'static str> {
        self.handlers.names()
    }
}

/// One operation as the pipeline sees it: what it requires, how it is read, who answers it, and
/// how the answer is written.
///
/// Borrowed from the registry rather than cloned, so looking one up costs two map lookups and no
/// allocation. Every field was installed by the same `register_handler::<O, B>` call, so the
/// decoder's output is the type the handler takes and the handler's answer is the type the encoder
/// writes — a mismatch is not something a caller of this struct can assemble.
#[derive(Clone, Copy)]
pub struct WireEntry<'a> {
    /// The operation's post-routing metadata: success status, required parameters, authorisation.
    pub spec: &'static OperationSpec,
    /// The erased handler.
    pub handler: &'a ErasedHandler,
    /// The erased decoder, whose output the handler accepts.
    pub decode: &'a ErasedDecode,
    /// The erased encoder, which accepts the handler's answer.
    pub encode: &'a ErasedEncode,
}

impl fmt::Debug for WireEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireEntry").field("operation", &self.spec.name).finish()
    }
}

/// Checks an operation's required parameters against a request.
///
/// Runs after routing and before decoding. The failure is always the operation's own code — never
/// `501`, which would say the operation does not exist.
///
/// # Errors
///
/// [`PreAuthError`] carrying the parameter's declared code and its static message.
pub fn check_required(spec: &OperationSpec, request: &RouteRequestParts<'_>) -> Result<(), PreAuthError> {
    for param in spec.required_params {
        let present = match param.kind {
            ParamKind::Query => request.query.contains(param.name),
            ParamKind::Header => request.headers.iter_text().any(|(name, _)| name.as_str() == param.name),
        };
        if !present {
            // `Registry::register` has already proved this code is usable here. The fallback is
            // for a spec that reached this function without going through registration, and it
            // degrades the code rather than the message, so the caller still learns what is wrong.
            return Err(PreAuthError::with_code(param.missing_error.clone(), param.message)
                .unwrap_or_else(|_| PreAuthError::invalid_request(param.message))
                .about(spec.name));
        }
    }
    Ok(())
}
