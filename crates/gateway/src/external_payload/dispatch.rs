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

//! Explicit registration of handlers that verify external uploads before publication.
//!
//! Responsible for: joining the authorized request to the single prepared source and handler.
//! NOT responsible for: routing, authentication, native activation or backend storage semantics.
//! Upstream: ServiceBuilder and normal operation dispatch. Downstream: ExternalPayloadHandler.

use super::{ExternalPayloadHandler, ExternalRequest, dispatch_external_payload, upload::UploadEntry};
use futures_util::future::{Either, select};
use rustfs_gateway_core::{Handler, HandlerContext, HandlerError, HandlerResult, OperationCodec, Req};
use rustfs_gateway_sig::{SigFamily, SigLocation, SigService};
use std::{pin::pin, sync::Arc};

impl crate::ServiceBuilder {
    /// Registers the same backend for ordinary S3 and explicitly verified external uploads.
    ///
    /// Only PutObject and UploadPart are accepted by the external request entry. The backend
    /// retains its own business admission and must verify the payload before publishing bytes.
    #[must_use]
    pub fn register_external_payload<O, B>(self, backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: ExternalPayloadHandler<O>,
    {
        self.register::<O, _>(Arc::new(ExternalBackend(backend)))
            .enable_external_payload_registration(O::NAME)
    }
}
fn invalid_request(message: &'static str) -> HandlerError {
    HandlerError::new(rustfs_gateway_types::ErrorCode::INVALID_REQUEST, message)
}
struct ExternalBackend<B>(Arc<B>);
impl<O, B> Handler<O> for ExternalBackend<B>
where
    O: OperationCodec,
    B: ExternalPayloadHandler<O>,
{
    async fn call(&self, request: Req<O>) -> HandlerResult<O> {
        self.0.call(request).await
    }
    async fn call_with_context(&self, request: Req<O>, context: HandlerContext) -> HandlerResult<O> {
        let Some(entry) = request.context().transport_extensions().get::<UploadEntry>().cloned() else {
            return self.0.call_with_context(request, context).await;
        };
        let principal = request
            .context()
            .principal()
            .ok_or_else(|| invalid_request("external data requires authenticated SigV4"))?;
        let scheme = principal.scheme();
        if scheme.family() != SigFamily::V4 || scheme.location() != SigLocation::Header || scheme.service() != SigService::S3 {
            return Err(invalid_request("external data requires an S3 SigV4 header signature"));
        }
        let payload = entry.context()?;
        let external = ExternalRequest {
            context: request.context().clone_without_caller_secret(),
            binding_digest: entry.binding.digest,
            logical_length: entry.binding.length,
        };
        let cancellation = context.clone();
        let prepared = {
            let cancelled = pin!(cancellation.cancelled());
            let prepared = pin!(entry.source.prepare(external));
            match select(cancelled, prepared).await {
                Either::Left(_) => {
                    entry.source.cancel();
                    return Err(invalid_request("external request was cancelled during preparation"));
                }
                Either::Right((prepared, _)) => prepared,
            }
        };
        prepared.map_err(|error| HandlerError::internal_error(error.to_string()))?;
        if super::entry::requires_confidentiality(request.context())
            && payload.protection() != super::PayloadProtection::ConfidentialAuthenticated
        {
            payload.cancel();
            return Err(invalid_request(
                "customer-key data requires a confidential authenticated external transport",
            ));
        }
        dispatch_external_payload(self.0.as_ref(), request, context, payload).await
    }
}
