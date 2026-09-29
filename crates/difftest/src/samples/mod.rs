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

//! The built-in sample matrices: requests for the decode diff (the generic matrix and the
//! RustFS-profile one) and outputs for the encode diff, each with the exact register ids it must
//! produce.
//!
//! Responsible for: exposing both matrices to the tests, the `decode-diff` and `encode-diff`
//! runners (`--builtin`) and the fuzz targets, so all of them start from the same inputs; and the
//! fixtures the matrices share.
//! NOT responsible for: judging a matrix (the tests do), or recorded traffic (`corpus.rs`).
//! Upstream: the library's request and sample types. Downstream: tests, runners, fuzzing.

mod outputs;
mod outputs_more;
mod requests;
mod rustfs;

pub use outputs::{OutputRow, UPLOAD_ID, VERSION_ID};
pub use requests::RequestRow;

use crate::RawRequest;

/// Every request row of the decode matrix.
#[must_use]
pub fn requests() -> Vec<RequestRow> {
    requests::requests()
}

/// Every request row of the RustFS-profile decode matrix, diffed under [`crate::Profile::Rustfs`].
#[must_use]
pub fn rustfs_requests() -> Vec<RequestRow> {
    rustfs::rows()
}

/// Every output row of the encode matrix.
#[must_use]
pub fn outputs() -> Vec<OutputRow> {
    let mut rows = outputs::rows();
    rows.extend(outputs_more::rows());
    rows
}

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
