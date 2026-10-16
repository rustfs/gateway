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

//! Authorized, bounded control observations over the ordinary S3 request security pipeline.

use super::{
    ExternalPayload, ExternalPayloadBinding, ExternalPayloadError, ExternalPayloadProvider, ExternalRequest, upload::UploadEntry,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use rustfs_gateway_core::{BoxFuture, EncodedResponse, HandlerError, RequestContextView, ResponseBody, TransportSecurity};
use rustfs_gateway_sig::{SigFamily, SigLocation, SigService};
use rustfs_gateway_stream::Body;
use std::sync::{Arc, Mutex};

/// A host-owned query executed after the exact S3 request has passed both authorization stages.
/// It receives no storage handler and cannot activate an external payload.
pub trait ExternalControlQuery: Send {
    /// Consumes the authorized request once and returns a finite host control response.
    fn query(self: Box<Self>, request: ExternalRequest) -> BoxFuture<'static, Result<ExternalControlResponse, HandlerError>>;
}
/// A complete, finite response from an authorized host query.
pub struct ExternalControlResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}
impl ExternalControlResponse {
    /// Validates the host response before handing it to the ordinary response path.
    pub fn new(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Result<Self, ExternalPayloadError> {
        let bytes = headers.iter().try_fold(body.len(), |total, (name, value)| {
            total.checked_add(name.as_str().len())?.checked_add(value.as_bytes().len())
        });
        if body.len() > 65536 || headers.len() > 64 || bytes.is_none_or(|bytes| bytes > 131072) {
            return Err(ExternalPayloadError::Transport);
        }
        Ok(Self { status, headers, body })
    }
    fn encoded(self) -> EncodedResponse {
        EncodedResponse {
            status: self.status,
            headers: self.headers,
            body: ResponseBody::Complete(self.body),
        }
    }
}
#[derive(Clone)]
pub(super) struct ControlEntry {
    binding: ExternalPayloadBinding,
    query: Arc<Mutex<Option<Box<dyn ExternalControlQuery>>>>,
}
struct Dormant;
impl ExternalPayloadProvider for Dormant {
    fn prepare(self: Box<Self>, _: ExternalRequest) -> BoxFuture<'static, Result<ExternalPayload, ExternalPayloadError>> {
        Box::pin(async { Err(ExternalPayloadError::Transport) })
    }
}
impl crate::S3Service {
    /// Authorizes an exact bound S3 request and invokes a host query without executing its backend.
    /// The request retains its original method, path, query and semantic headers. Required control
    /// fields must be signed, the connection must use TLS, and the actual body must be empty.
    pub async fn call_with_external_control_bound<B>(
        &self,
        request: Request<B>,
        binding: ExternalPayloadBinding,
        query: Box<dyn ExternalControlQuery>,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let upload = request.method() == Method::PUT;
        let encrypted = crate::service::connection_security(request.extensions()) == TransportSecurity::Encrypted;
        if request.body().size_hint().exact() != Some(0)
            || !matches!(request.method(), &Method::PUT | &Method::GET)
            || binding.validate_head(request.headers(), encrypted, upload).is_err()
        {
            return self
                .external_refusal("external control request binding is invalid")
                .into_parts()
                .0;
        }
        let (mut parts, body) = request.into_parts();
        drop(body);
        parts.extensions.insert(ControlEntry {
            binding: binding.clone(),
            query: Arc::new(Mutex::new(Some(query))),
        });
        if upload {
            // The ordinary decoder receives the same logical length without polling any data.
            let entry = UploadEntry::new(binding, Box::new(Dormant));
            let body = entry.body();
            parts.extensions.insert(entry);
            self.call(Request::from_parts(parts, body)).await
        } else {
            self.call(Request::from_parts(parts, Body::empty())).await
        }
    }
}
/// This hook is called only after typed resource authorization, before handler invocation.
pub(crate) async fn dispatch_control(context: &RequestContextView) -> Option<Result<EncodedResponse, HandlerError>> {
    let entry = context.transport_extensions().get::<ControlEntry>()?;
    let invalid = || {
        HandlerError::new(
            rustfs_gateway_types::ErrorCode::INVALID_REQUEST,
            "external control requires an authenticated S3 object request",
        )
    };
    let principal = match context.principal() {
        Some(principal) => principal,
        None => return Some(Err(invalid())),
    };
    let scheme = principal.scheme();
    if !matches!(context.operation(), "PutObject" | "UploadPart" | "GetObject")
        || scheme.family() != SigFamily::V4
        || scheme.location() != SigLocation::Header
        || scheme.service() != SigService::S3
    {
        return Some(Err(invalid()));
    }
    let query = entry.query.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    let Some(query) = query else {
        return Some(Err(invalid()));
    };
    let request = ExternalRequest {
        context: context.clone_without_caller_secret(),
        binding_digest: entry.binding.digest,
        logical_length: entry.binding.length,
    };
    Some(query.query(request).await.map(ExternalControlResponse::encoded))
}
