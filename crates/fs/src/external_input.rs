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

//! Publication admission shared by ordinary and explicitly enabled external object writes.
//!
//! Responsible for: invoking the external gate in existing business helpers before publication.
//! NOT responsible for: request authentication, data progress or storage implementation.
//! Upstream: the facade's explicit registration. Downstream: PutObject and UploadPart helpers.

use rustfs_gateway::HandlerError;

#[derive(Default)]
pub(super) struct PublicationGate {
    #[cfg(feature = "external-payload")]
    payload: Option<rustfs_gateway::external_payload::ExternalPayloadContext>,
}
impl PublicationGate {
    pub(super) fn is_external(&self) -> bool {
        #[cfg(feature = "external-payload")]
        {
            self.payload.is_some()
        }
        #[cfg(not(feature = "external-payload"))]
        {
            false
        }
    }
    pub(super) async fn accept(&self) -> Result<(), HandlerError> {
        #[cfg(feature = "external-payload")]
        if let Some(payload) = &self.payload {
            return payload.accept_after_admission().await;
        }
        Ok(())
    }
    pub(super) async fn verify(&self) -> Result<(), HandlerError> {
        #[cfg(feature = "external-payload")]
        if let Some(payload) = &self.payload {
            return payload.verify_before_publish().await;
        }
        Ok(())
    }
}
#[cfg(feature = "external-payload")]
mod enabled {
    use super::PublicationGate;
    use crate::FsBackend;
    use rustfs_gateway::dto::{PutObject, UploadPart};
    use rustfs_gateway::external_payload::{ExternalPayloadContext, ExternalPayloadHandler};
    use rustfs_gateway::{BoxFuture, HandlerContext, HandlerResult, Req};
    impl ExternalPayloadHandler<PutObject> for FsBackend {
        fn call_with_external_payload<'a>(
            &'a self,
            request: Req<PutObject>,
            _: HandlerContext,
            payload: ExternalPayloadContext,
        ) -> BoxFuture<'a, HandlerResult<PutObject>> {
            Box::pin(self.put_object_with_gate(request, PublicationGate { payload: Some(payload) }))
        }
    }
    impl ExternalPayloadHandler<UploadPart> for FsBackend {
        fn call_with_external_payload<'a>(
            &'a self,
            request: Req<UploadPart>,
            _: HandlerContext,
            payload: ExternalPayloadContext,
        ) -> BoxFuture<'a, HandlerResult<UploadPart>> {
            Box::pin(self.upload_part_with_gate(request, PublicationGate { payload: Some(payload) }))
        }
    }
}
