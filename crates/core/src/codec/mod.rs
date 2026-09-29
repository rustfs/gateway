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

//! The wire codec of one operation: request bytes in, `Input` out, `Output` in, response bytes out.
//!
//! Responsible for: [`OperationCodec`], the views a codec reads and the response it produces, the
//! shared scalar conversions, and mounting the generated implementations.
//! NOT responsible for: any per-operation binding. Every one of those is generated into
//! `generated/codec/ops/` from `generated/ir/`, so a wire rule has exactly one source.
//! Upstream: `crate::op`, `rustfs-gateway-http`, `rustfs-gateway-xml`. Downstream:
//! `crate::registry`'s erasure closure, which is what turns a `WireRequest` into a response.
//!
//! # Why the implementations live in this crate
//!
//! The orphan rule decides it, and there is no second option. `OperationCodec` is declared here.
//! The operation types it is implemented for — `GetObject`, `PutObject` — are declared in
//! `rustfs-gateway-types`, because they are generated dto. An `impl Trait for Type` has to live in
//! the crate that owns the trait or the crate that owns the type, so the candidates are this crate
//! and `rustfs-gateway-types`.
//!
//! `rustfs-gateway-types` cannot host it: decoding reads a [`rustfs_gateway_http::WireRequest`],
//! and `rustfs-gateway-http` depends on `rustfs-gateway-types`. Putting the codec there would make
//! the two crates mutually dependent — the same cycle `rustfs-gateway-stream` was carved out to
//! prevent. So the codecs are generated into `generated/codec/` and mounted here, one file per
//! operation, which is also the one-operation-per-file conflict unit the rest of `crate::ops`
//! follows.
//!
//! # What a generated codec may and may not do
//!
//! It may read the IR's answer and call a function in [`value`] or [`response`]. It may not hold a
//! rule of its own: every `if` in a generated file comes from an IR field, and the three protocol
//! exceptions that would otherwise be hand-written branches are data —
//!
//! * the entity-tag rendering context is [`rustfs_gateway_types::EtagRender`], carried per field;
//! * an unwrapped body is `xml.unwrapped_output`, carried per operation;
//! * emit-or-omit for an empty member is `xml.empty_value_policy`, carried per member.

pub mod error;
pub mod extra_headers;
mod legacy_path;
pub mod response;
mod rustfs_listing;
pub mod strict_date;
pub mod value;
pub mod view;

#[cfg(test)]
mod tests;

pub use crate::codec::error::CodecError;
pub use crate::codec::extra_headers::{OWNED_RESPONSE_HEADERS, is_owned_response_header};
pub use crate::codec::legacy_path::legacy_rustfs_target;
pub use crate::codec::response::{
    BodyAllowance, EncodedResponse, ResponseBody, ResponseOverride, body_allowance, override_header_value, response_body_allowed,
    response_framing_allowed, status_code,
};
pub use crate::codec::strict_date::strict_http_date;
pub use crate::codec::value::*;
pub use crate::codec::view::{MetaView, PageSizeCeiling, RequestBody, RequestBodyMode, bucket_label};

use crate::op::Operation;

/// The generated per-operation codecs, one module per operation.
///
/// Mounted through `crates/core/generated`, the symlink onto `generated/` that this crate already
/// uses for the route table. It is the same device `rustfs-gateway-types` uses for the dto
/// (ADR-0005): a `#[path]` may not reach outside the package directory in a packaged tarball.
#[path = "../../generated/codec/ops/mod.rs"]
pub mod ops;

/// How one operation reads a request and writes a response.
///
/// Implemented once per operation, by generated code. A backend never implements it — a backend
/// implements [`crate::handler::Handler`], which sees the decoded `Input` and returns an `Output`.
///
/// It is a separate trait from [`Operation`] rather than two more methods on it, because
/// [`Operation`] is the trait a third party implements for its own admin or dialect operation.
/// Making a codec mandatory there would mean every such operation had to write one before it could
/// name itself; making it a supertrait-bounded extension means a third party opts in when it has
/// one.
pub trait OperationCodec: Operation {
    /// The generated request-body handoff mode.
    ///
    /// The buffered default keeps a third-party codec source-compatible while preventing an
    /// assembly from handing it an unbounded live producer unless it opts in explicitly.
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Full;

    /// The `response-*` overrides this operation honours, in IR order.
    ///
    /// Empty for every operation that declares none, which is most of them. It is an associated
    /// constant rather than a branch inside `encode` so that "this operation has no overrides"
    /// costs nothing at run time and is visible in the generated source.
    const RESPONSE_OVERRIDES: &'static [ResponseOverride] = &[];

    /// Reads a decoded request head and a body into the operation's input.
    ///
    /// The head has already been accepted (`rustfs-gateway-http`) and routed (`crate::route`), so
    /// every failure here is a `400`-family statement about a value, never a `501`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] naming the model member that could not be read.
    fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError>;

    /// Writes the operation's output as a status, a header set and a body.
    ///
    /// Takes the request as well as the output, because three observable S3 behaviours are
    /// functions of both: a `HEAD` carries no body, `response-*` parameters overwrite response
    /// headers, and `encoding-type` decides how body members are escaped.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`] when the output holds a value with no wire form. Nothing a caller
    /// sends can reach this path.
    fn encode(output: Self::Output, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError>;
}
