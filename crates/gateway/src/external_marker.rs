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

//! Reserved external-payload detection shared by all S3 service entries.
//!
//! Responsible for: recognizing external bodies and constructing their current service refusal.
//! NOT responsible for: authenticating extension fields or enabling an external transport.
//! Upstream: accepted wire headers and trusted service entry. Downstream: the service refusal gate.

/// A trusted facade entry requested the external-data path.
#[cfg(feature = "external-payload")]
#[derive(Clone, Copy)]
pub(crate) struct ExternalEntry;

pub(crate) fn present(headers: &http::HeaderMap) -> bool {
    headers.keys().any(|name| name.as_str().starts_with("x-rustfs-rdma-"))
}

pub(crate) fn explicit_entry(extensions: &http::Extensions) -> bool {
    #[cfg(feature = "external-payload")]
    {
        extensions.get::<ExternalEntry>().is_some()
    }
    #[cfg(not(feature = "external-payload"))]
    {
        let _ = extensions;
        false
    }
}

pub(crate) fn refusal(response_kind: rustfs_gateway_core::ResponseKind) -> crate::render::S3Error {
    crate::render::from_pre_auth(
        rustfs_gateway_core::PreAuthError::not_implemented("external object payloads are not connected to this service"),
        response_kind,
    )
}
