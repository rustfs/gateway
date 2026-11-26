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

//! Body-read preconditions and ordinary body handoff helpers for the request pipeline.
//!
//! Responsible for: enforcing SSE and pre-decode rules, preparing `aws-chunked` ingest,
//! computing ceilings and integrity checks before `SealedBody::handoff`, and running post-read
//! length checks and external-payload binding.
//! NOT responsible for: invoking `SealedBody::handoff` or transitioning `RequestConfig<Guarded>`
//! (both remain directly in `super::S3Service::run` for governor-position and stage-shape proofs).
//! Upstream: `super::S3Service::run`'s `read_body` closure.
//! Downstream: `crate::chunked`, `crate::gate`, `crate::integrity`, and `rustfs_gateway_core::sse`.

use http::HeaderMap;
use rustfs_gateway_core::{MetaView, RequestBody, RequestBodyMode, ResponseKind, SseConfig, SseEnforced, TransportSecurity};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::{PayloadMode, SigService};

use super::isolation;
use super::state::AcceptedBody;
use crate::builder::buffered_lengths::SignedLength;
use crate::builder::view_policy::ViewPolicy;
use crate::chunked::ChunkIngest;
use crate::close::ConnectionIntent;
use crate::config::ServiceConfig;
use crate::ext::ChunkSink;
use crate::gate::BodyCeilings;
use crate::integrity::Integrity;
use crate::render::{S3Error, from_handler};

/// Parameters computed before handing an ordinary [`crate::gate::SealedBody`] to `handoff`.
pub(super) struct OrdinaryHandoffPlan {
    pub(super) ceilings: BodyCeilings,
    pub(super) integrity: Integrity,
    pub(super) object_ceiling: Option<u64>,
}

/// Evaluates SSE enforcement, pre-decode view-policy refusals, and chunked ingest setup.
#[allow(clippy::too_many_arguments)] // Pipeline stage state passed explicitly rather than bundled into a transient carrier.
pub(super) fn enforce_body_preconditions<B>(
    signing_service: Option<SigService>,
    meta: &MetaView<'_>,
    headers: &HeaderMap,
    wire: &WireRequest<()>,
    operation: &'static str,
    connection: TransportSecurity,
    sse_config: &SseConfig,
    view_policy: ViewPolicy,
    accepted_body: &AcceptedBody<B>,
    framing_mode: Option<&PayloadMode>,
    chunk_sink: &ChunkSink,
    response_kind: ResponseKind,
) -> Result<(SseEnforced, Option<ChunkIngest>), S3Error>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let sse = rustfs_gateway_core::sse::enforce_for_service(signing_service, meta, connection, sse_config)
        .and_then(|proof| match accepted_body {
            AcceptedBody::PostObject(post) => post.sse_proof(proof, connection, sse_config),
            AcceptedBody::Ordinary(_) => Ok(proof),
        })
        .or_else(|no| view_policy.sse_refusals.settle(no, !accepted_body.is_post(), response_kind))?;
    if !isolation::is_non_s3_service(signing_service)
        && let Some(refusal) = view_policy.refusal_before_decode(operation, &wire.headers())
    {
        return Err(from_handler(refusal, response_kind, ConnectionIntent::MayKeepAlive));
    }
    let ingest = match framing_mode {
        Some(payload) => ChunkIngest::prepare(payload, headers, wire.framing(), chunk_sink, view_policy.chunk_reading.limits())?,
        None => None,
    };
    Ok((sse, ingest))
}

/// Computes body ceilings, integrity obligations, and pre-read length checks for an ordinary body.
#[allow(clippy::too_many_arguments)] // Pipeline stage inputs remain explicit to avoid hidden defaults.
pub(super) fn prepare_ordinary_handoff(
    signing_service: Option<SigService>,
    meta: &MetaView<'_>,
    wire: &WireRequest<()>,
    operation: &'static str,
    request_body_mode: RequestBodyMode,
    claimed: bool,
    config: &ServiceConfig,
    view_policy: ViewPolicy,
    framed: bool,
    signed_length: SignedLength,
    declared_length: Option<u64>,
    transport_length: Option<u64>,
) -> Result<OrdinaryHandoffPlan, S3Error> {
    let model = BodyCeilings::for_mode(request_body_mode, operation, config.max_buffered_body_bytes());
    let ceilings = view_policy
        .buffered_ceiling
        .ceilings(request_body_mode, claimed, signing_service, model);
    // The accepted head, not the pre-filter copy: it is the map the codec binds from.
    let integrity = isolation::resolve_integrity_for_service(signing_service, meta, &wire.headers(), wire.method(), operation)?;
    let object_ceiling = crate::gate::object_ceiling_for(request_body_mode, operation, config);
    if let Some(refusal) =
        view_policy
            .buffered_lengths
            .before_read(request_body_mode, framed, signed_length, declared_length, transport_length)
    {
        return Err(refusal);
    }
    Ok(OrdinaryHandoffPlan {
        ceilings,
        integrity,
        object_ceiling,
    })
}

/// Applies post-read buffered length checks and optional external-payload binding.
#[allow(clippy::too_many_arguments)] // Explicit post-read framing parameters from `read_body`.
#[cfg_attr(not(feature = "external-payload"), allow(unused_variables))]
pub(super) fn finalize_body_after_handoff(
    body: RequestBody,
    wire: &WireRequest<()>,
    request_body_mode: RequestBodyMode,
    view_policy: ViewPolicy,
    framed: bool,
    declared_length: Option<u64>,
    is_ordinary: bool,
    response_kind: ResponseKind,
) -> Result<RequestBody, S3Error> {
    if is_ordinary
        && let RequestBody::Buffered(bytes) = &body
        && let Some(refusal) = view_policy
            .buffered_lengths
            .after_read(request_body_mode, framed, declared_length, bytes)
    {
        return Err(refusal);
    }
    #[cfg(feature = "external-payload")]
    let body = crate::external_payload::bind_input(body, wire.transport_extensions())
        .map_err(|error| from_handler(error, response_kind, ConnectionIntent::MayKeepAlive))?;
    Ok(body)
}
