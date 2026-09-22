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

//! Responsible for: mapping accepted handler context into the pinned adapter request.
//! NOT responsible for: authentication, protocol conversion internals, or response comparison.
//! Upstream: the context harness. Downstream: its recording backend and seam agreement tests.

use http::HeaderName;
use rustfs_gateway::{CallerSecretKey, RequestContextView};

use super::super::seam::request_context::{GatewayRequestContext, Principal, VerifiedScope, request_to_s3s};
use super::{TransportMarker, s3s};

/// The RustFS adapter's half of the seam: an `s3s::S3Request` context built from nothing but the
/// handler's request context.
pub(super) fn adapter_request(context: &RequestContextView) -> Result<s3s::S3Request<()>, String> {
    let refused = |error: rustfs_gateway_types::compat::ConversionError| format!("conversion refused: {error}");
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
    let gateway = GatewayRequestContext {
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
    };
    let mut converted = request_to_s3s(gateway, ()).map_err(refused)?;
    // Ring-2 adapters name their own transport types; the protocol conversion cannot depend on them.
    if let Some(marker) = context.transport_extensions().get::<TransportMarker>() {
        converted.extensions.insert(marker.clone());
    }
    Ok(converted)
}
