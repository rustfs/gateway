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

//! Pre-authentication ingress helpers for the request pipeline.
//!
//! Responsible for: pre-acceptance wire-head preparation and `on_wire` filtering, and post-routing
//! addressing and `on_routed` filtering.
//! NOT responsible for: CORS preflight (`super::cors`), authentication, authorization, routing
//! table dispatch, or stage transitions on `RequestConfig` (all owned by `super::S3Service::run`).
//! Upstream: `super::S3Service::run`. Downstream: `rustfs_gateway_http::WireRequest`,
//! `rustfs_gateway_core::MetaView`, and `super::extension_guards`.

use http::{HeaderMap, Request, Response};
use rustfs_gateway_core::{MetaView, TargetKind};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::SigService;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::BucketName;

use super::extension_guards;
use super::outcome::Outcome;
use super::{ClientFacts, RoutedView, RuntimeAssembly, S3Service};
use crate::ext::ResolvedHost;

/// A request head prepared for [`WireRequest::accept`], with its frozen pre-filter headers.
pub(super) struct PreparedWire<B> {
    pub(super) request: Request<B>,
    pub(super) headers: HeaderMap,
    pub(super) external_bound: bool,
    pub(super) reject_external: bool,
}

/// Routed targeting inputs for [`S3Service::address_meta`].
pub(super) struct AddressTarget<'a> {
    pub(super) operation: &'static str,
    pub(super) target: TargetKind,
    pub(super) bound_bucket: Option<&'a BucketName>,
    pub(super) service_level: bool,
}

impl S3Service {
    /// Applies pre-acceptance rewrites and `on_wire` filters before [`WireRequest::accept`].
    pub(super) fn prepare_wire_head<B>(
        &self,
        request: Request<B>,
        signing_service: Option<SigService>,
        outcome: &mut Outcome<'_>,
        runtime: &RuntimeAssembly,
    ) -> Result<PreparedWire<B>, Box<Response<Body>>>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if let Some(error) = crate::external_marker::rejection(request.extensions()) {
            return Err(Box::new(outcome.refuse_handler(error)));
        }
        // `WireRequest` publishes no way back to the header map — that is the boundary it exists to
        // draw — while `SecurityFloor` and the canonical request are defined over the raw map. The
        // copy is taken before acceptance and used only after it has succeeded, so what is held is
        // an accepted map. It is also the whole of "a stage filter cannot touch a signature": every
        // verifier downstream reads the head as the caller sent it.
        let (mut parts, body) = request.into_parts();
        let external_entry = crate::external_marker::explicit_entry(&parts.extensions);
        let external_bound = crate::external_marker::bound_entry(&parts.extensions);
        crate::legacy_addressing::rewrite_double_slash_root(&self.inner.names, signing_service, &mut parts);
        let headers = parts.headers.clone();
        #[cfg(feature = "external-payload")]
        crate::external_payload::apply_logical_head(&mut parts);
        // The client facts, installed where the wire seam below can correct them and acceptance
        // then freezes them for both authorization stages and the handler (rustfs/backlog#2752).
        ClientFacts::install(&mut parts.extensions);

        if let Err(error) = extension_guards::run_wire_filters(&runtime.filters, &mut parts, Some(outcome.trace)) {
            return Err(Box::new(outcome.refuse_handler(error)));
        }

        self.withhold_header_token(&mut parts.headers); // ADR-0054: nothing accepted holds a claimed header token
        let external_headers = crate::external_marker::present(&headers) || crate::external_marker::present(&parts.headers);
        let reject_external = external_entry || (external_headers && !external_bound);
        Ok(PreparedWire {
            request: Request::from_parts(parts, body),
            headers,
            external_bound,
            reject_external,
        })
    }

    /// Resolves the single normalised [`MetaView`] for a routed request and applies view policy.
    pub(super) fn address_meta<'a, B>(
        &self,
        wire: &'a WireRequest<()>,
        address: AddressTarget<'_>,
        resolved: &ResolvedHost,
        pending: Option<&B>,
        outcome: &mut Outcome<'_>,
    ) -> Result<MetaView<'a>, Box<Response<Body>>>
    where
        B: http_body::Body,
    {
        // A claimed row's bound bucket, already validated as a path-style bucket is (ADR-0025),
        // takes the host's place; `vhost_key` then reads no key for a bucket target.
        let host_bucket = match address.bound_bucket {
            Some(bucket) => Some(bucket.clone()),
            None if address.service_level => None,
            None => resolved.bucket().cloned(),
        };
        match MetaView::addressed_with(wire, address.target, host_bucket, &self.inner.names) {
            Ok(meta) => Ok(self.inner.view_policy.apply(address.operation, meta, pending)),
            Err(error) => Err(Box::new(
                outcome.refuse_addressing(error, self.inner.view_policy.nul_torrent_keys_as_missing),
            )),
        }
    }

    /// Runs the read-only `on_routed` filter seam once operation, bucket, and key are decided.
    #[allow(clippy::too_many_arguments)] // Borrowed routing facts from `S3Service::run`.
    pub(super) fn run_routed_filters(
        runtime: &RuntimeAssembly,
        operation: &'static str,
        spec: &rustfs_gateway_core::OperationSpec,
        wire: &WireRequest<()>,
        target: TargetKind,
        meta: &MetaView<'_>,
        declared_length: Option<u64>,
        outcome: &mut Outcome<'_>,
    ) -> Option<Response<Body>> {
        if runtime.filters.is_empty() {
            return None;
        }
        let view = RoutedView {
            operation,
            spec,
            method: wire.method(),
            path: wire.raw_path().as_str(),
            target,
            bucket: meta.bucket(),
            key: meta.key(),
            declared_body_bytes: declared_length,
        };
        if let Err(error) = extension_guards::run_routed_filters(&runtime.filters, &view, outcome.trace) {
            return Some(outcome.refuse_handler(error));
        }
        None
    }
}
