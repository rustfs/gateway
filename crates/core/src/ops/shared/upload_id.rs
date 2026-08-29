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

//! Compatibility path for the upload-id capability and ownership exchange.
//!
//! Responsible for: preserving the established `rustfs_gateway_core::ops::shared::upload_id`
//! import path while multipart request DTOs and the exchange share the same owned capability type.
//! NOT responsible for: defining or inspecting the capability; `rustfs-gateway-types` owns both
//! the private bytes and the exchange so no downstream crate needs a raw accessor.
//! Upstream: `rustfs-gateway-types`. Downstream: the facade and existing backend implementations.

pub use rustfs_gateway_types::{RecordedUpload, ResolvedUploadId, UploadIdClaim, UploadRejection, resolve_upload};
