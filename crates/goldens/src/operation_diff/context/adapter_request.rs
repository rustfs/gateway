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

//! Responsible for: mapping accepted handler context into the pinned adapter request, and the
//! recording backend that does so for the one handler call each exchange makes.
//! NOT responsible for: authentication, protocol conversion internals, or response comparison.
//! Upstream: the context harness. Downstream: its gateway side and seam agreement tests.

use std::sync::{Arc, Mutex};

use http::HeaderName;
use rustfs_gateway::dto;
use rustfs_gateway::{CallerSecretKey, Handler, HandlerContext, HandlerResult, Req, RequestContextView, Resp};

use super::super::seam::request_context::{
    GatewayRequestContext, Principal, RequestTarget, VerifiedScope, request_to_legacy, request_to_s3s,
};
use super::{TransportMarker, s3s};

fn refused(error: rustfs_gateway_types::compat::ConversionError) -> String {
    format!("conversion refused: {error}")
}

/// The RustFS adapter's half of the seam: an `s3s::S3Request` context built from nothing but the
/// handler's request context.
pub(super) fn adapter_request(context: &RequestContextView) -> Result<s3s::S3Request<()>, String> {
    let converted = request_to_s3s(gateway_context(context)?, ()).map_err(refused)?;
    Ok(with_transport(context, converted))
}

/// The RustFS profile's adapter half (rustfs/gateway#1148): as [`adapter_request`], with the
/// request target's scheme and authority handed over, so the legacy request URI is the one the
/// legacy stack's transport would have built.
pub(super) fn legacy_adapter_request(context: &RequestContextView) -> Result<s3s::S3Request<()>, String> {
    let target = RequestTarget {
        version: context.version(),
        scheme: context.target_scheme().map(str::to_owned),
        authority: context.target_authority().map(str::to_owned),
    };
    let converted = request_to_legacy(gateway_context(context)?, target, ()).map_err(refused)?;
    Ok(with_transport(context, converted))
}

fn gateway_context(context: &RequestContextView) -> Result<GatewayRequestContext, String> {
    let principal = context
        .principal()
        .map(|principal| {
            let scope = principal.verified_scope().map(|scope| VerifiedScope {
                region: scope.region().to_owned(),
                service: scope.service().to_owned(),
            });
            let secret = principal
                .secret_key_from_authenticator_lookup()
                .map(CallerSecretKey::expose_secret);
            Principal::from_handler(principal.access_key_id(), secret, scope)
        })
        .transpose()
        .map_err(refused)?;
    Ok(GatewayRequestContext {
        method: context.method().clone(),
        raw_path: context.raw_path().to_owned(),
        raw_query: context.raw_query().to_owned(),
        headers: GatewayRequestContext::raw_headers(context.headers().iter_raw()),
        principal,
        host_region: context.addressing().host_region().map(str::to_owned),
        declares_trailers: context
            .headers()
            .get_bytes(&HeaderName::from_static("x-amz-trailer"))
            .is_some(),
    })
}

/// Ring-2 adapters name their own transport types; the protocol conversion cannot depend on them.
fn with_transport(context: &RequestContextView, mut converted: s3s::S3Request<()>) -> s3s::S3Request<()> {
    if let Some(marker) = context.transport_extensions().get::<TransportMarker>() {
        converted.extensions.insert(marker.clone());
    }
    converted
}

/// What one handler call recorded.
pub(super) struct Recorded {
    pub(super) operation: &'static str,
    pub(super) converted: Result<s3s::S3Request<()>, String>,
    pub(super) bucket: Option<String>,
    pub(super) key: Option<String>,
}

/// A gateway backend that records, for the one call it gets, what [`adapter_request`] made of the
/// handler's request context — or, for the RustFS profile's target, [`legacy_adapter_request`].
pub(super) struct AdapterBackend {
    pub(super) recorded: Arc<Mutex<Option<Recorded>>>,
    pub(super) legacy_target: bool,
}

impl AdapterBackend {
    fn record(&self, context: &RequestContextView) {
        let converted = if self.legacy_target {
            legacy_adapter_request(context)
        } else {
            adapter_request(context)
        };
        let recorded = Recorded {
            operation: context.operation(),
            converted,
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
        };
        if let Ok(mut slot) = self.recorded.lock() {
            *slot = Some(recorded);
        }
    }
}

impl Handler<dto::PutObject> for AdapterBackend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.record(request.context());
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }

    async fn call_with_context(&self, request: Req<dto::PutObject>, _context: HandlerContext) -> HandlerResult<dto::PutObject> {
        self.record(request.context());
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

impl Handler<dto::GetBucketLocation> for AdapterBackend {
    async fn call(&self, request: Req<dto::GetBucketLocation>) -> HandlerResult<dto::GetBucketLocation> {
        self.record(request.context());
        Ok(Resp::new(dto::GetBucketLocationOutput::default()))
    }

    async fn call_with_context(
        &self,
        request: Req<dto::GetBucketLocation>,
        _context: HandlerContext,
    ) -> HandlerResult<dto::GetBucketLocation> {
        self.record(request.context());
        Ok(Resp::new(dto::GetBucketLocationOutput::default()))
    }
}
