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

//! The decode diff's own tests.
//!
//! Responsible for: the request matrix (`rows.rs`) and its judgement (`matrix.rs`), the negative
//! controls that break the gateway side on purpose (`controls.rs`), the register's refusals
//! (`register.rs`), and the member census against the generated DTO (`census.rs`).
//! NOT responsible for: anything the library does not do.
//! Upstream: the library. Downstream: none.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]

mod census;
mod controls;
mod matrix;
mod register;
mod rows;

use crate::RawRequest;

/// The account every fixture bucket belongs to.
pub(crate) const OWNER: &str = crate::gateway::BUCKET_OWNER;
/// A 32-byte SSE-C key and its MD5, both base64.
const SSE_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const SSE_KEY_MD5: &str = "hRasmdxgYDKV3nvbahU1MA==";

/// The three SSE-C headers, on an encrypted connection (the gateway refuses them on cleartext;
/// `kd-decode-0016` pins that).
pub(crate) fn sse(request: RawRequest) -> RawRequest {
    request
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", SSE_KEY)
        .header("x-amz-server-side-encryption-customer-key-md5", SSE_KEY_MD5)
        .over_tls()
}
