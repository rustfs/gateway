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

//! Responsible for: running host authorization before PostObject success-control validation.
//! NOT responsible for: parsing multipart forms or writing objects.
//! Upstream: the form pipeline. Downstream: the registered PostObject backend.

use std::sync::Arc;

use rustfs_gateway_core::PostObjectSuccessCheck;

use super::OperationDispatch;
use crate::dto::PostObject;
use crate::{BoxFuture, ErrorCode, Handler, HandlerError, HandlerResult, Req};

/// A PostObject handler with a host authorization step before success-control validation.
///
/// Install it with [`crate::ServiceBuilder::register_post_object_after_authorization`].
/// The gateway retains ownership of the request and its file stream through authorization and
/// hands them to [`Self::execute`] only after the success controls pass.
pub trait PostObjectHandler: Send + Sync + 'static {
    /// Owned state produced by host authorization and passed to execution.
    type Authorization: Send + 'static;

    /// Authorize the upload using its decoded input and verified request context.
    ///
    /// Read the metadata you need from the request before constructing an async block: the
    /// request owns a file stream that can be sent but cannot be shared across threads.
    fn authorize(&self, request: &Req<PostObject>) -> BoxFuture<'_, Result<Self::Authorization, HandlerError>>;

    /// Execute the authorized upload after the gateway accepts its success controls.
    fn execute(&self, authorization: Self::Authorization, request: Req<PostObject>) -> BoxFuture<'_, HandlerResult<PostObject>>;
}

pub(crate) struct PostObjectAdapter<H>(pub(crate) Arc<H>);

impl<H: PostObjectHandler> Handler<PostObject> for PostObjectAdapter<H> {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let authorization = self.0.authorize(&request).await?;
        match request.context().post_object_success_check() {
            Some(PostObjectSuccessCheck::Valid) => {}
            Some(PostObjectSuccessCheck::InvalidStatus) => {
                return Err(HandlerError::new(
                    ErrorCode::MALFORMED_POST_REQUEST,
                    "success_action_status must be one of 200, 201, or 204",
                ));
            }
            Some(PostObjectSuccessCheck::InvalidRedirect) => {
                return Err(HandlerError::new(
                    ErrorCode::MALFORMED_POST_REQUEST,
                    "success_action_redirect must be a valid absolute URL",
                ));
            }
            None => return Err(HandlerError::internal_error("the PostObject success-control verdict is missing")),
        }
        self.0.execute(authorization, request).await
    }
}

impl OperationDispatch {
    pub(crate) fn post_object_after_authorization<H: PostObjectHandler>(adapter: Arc<PostObjectAdapter<H>>) -> Self {
        let mut entry = Self::layered::<PostObject, _>(adapter, Vec::new());
        entry.defer_post_object_success_check = true;
        entry
    }

    pub(crate) const fn defers_post_object_success_check(&self) -> bool {
        self.defer_post_object_success_check
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use bytes::Bytes;
    use rustfs_gateway_core::sse::{SseConfig, TransportSecurity, enforce_with};

    use super::*;
    use crate::dto::{PostObjectFields, PostObjectInput};
    use crate::{BucketName, ByteStream, ObjectKey};

    #[derive(Default)]
    struct Backend {
        authorized: AtomicBool,
        executed: AtomicBool,
    }

    impl PostObjectHandler for Backend {
        type Authorization = ();

        fn authorize(&self, _: &Req<PostObject>) -> BoxFuture<'_, Result<(), HandlerError>> {
            self.authorized.store(true, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }

        fn execute(&self, _: (), _: Req<PostObject>) -> BoxFuture<'_, HandlerResult<PostObject>> {
            self.executed.store(true, Ordering::Relaxed);
            Box::pin(std::future::ready(Err(HandlerError::internal_error("the test handler executed"))))
        }
    }

    #[tokio::test]
    async fn an_absent_success_control_verdict_fails_closed() {
        let input = PostObjectInput {
            bucket: BucketName::new("example-bucket").expect("bucket"),
            key: ObjectKey::new("file").expect("object key"),
            body: ByteStream::from_bytes(Bytes::from_static(b"file")),
            content_length: Some(4),
            content_type: None,
            metadata: Vec::new(),
            fields: PostObjectFields::default(),
        };
        let sse = enforce_with(|_| None, TransportSecurity::Plaintext, &SseConfig::default()).expect("no encryption");
        let handler = Arc::new(Backend::default());
        let adapter = PostObjectAdapter(Arc::clone(&handler));
        let error = adapter.call(Req::new(input, sse)).await.expect_err("missing verdict");
        assert_eq!(*error.code(), ErrorCode::INTERNAL_ERROR);
        assert!(handler.authorized.load(Ordering::Relaxed));
        assert!(!handler.executed.load(Ordering::Relaxed));
    }
}
