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

//! The body reader offered to authentication and the body resolved after its verdict.
//!
//! Responsible for: offering the STS reader only for an ordinary body, and retaining or resolving
//! the body after metadata admission. NOT responsible for: signature verification or body reads.
//! Upstream: `super::S3Service::run`. Downstream: the authenticator and `crate::post_object`.

use super::{AcceptedBody, RoutedBody, S3Service};
use crate::gate::StsBodyReader;
use crate::render::S3Error;

impl<B> RoutedBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(super) fn sts_body_reader(&self) -> Option<&dyn StsBodyReader> {
        match self {
            Self::Ordinary(body) => Some(body),
            Self::PostObject(_) => None,
        }
    }
}

impl S3Service {
    pub(super) fn resolve_routed_body<B>(
        &self,
        body: RoutedBody<B>,
        meta: &rustfs_gateway_core::MetaView<'_>,
        now: rustfs_gateway_sig::RequestNow,
    ) -> Result<AcceptedBody<B>, S3Error>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match body {
            RoutedBody::Ordinary(sealed) => Ok(AcceptedBody::Ordinary(sealed)),
            RoutedBody::PostObject(prelude) => {
                let bucket = meta.bucket().cloned().ok_or_else(|| {
                    crate::render::from_handler(
                        rustfs_gateway_core::HandlerError::internal_error("PostObject routed without a bucket"),
                        rustfs_gateway_core::ResponseKind::Other,
                        crate::close::ConnectionIntent::MayKeepAlive,
                    )
                })?;
                let resolved = (*prelude).resolve(bucket, &self.inner.names, now)?;
                Ok(AcceptedBody::PostObject(Box::new(resolved)))
            }
        }
    }
}
