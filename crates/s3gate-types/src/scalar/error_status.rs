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

//! The context an error code needs before it becomes a status line.
//!
//! Responsible for: the request facts that change an error's outcome — the method, whether the
//! caller may list the bucket, whether the bucket lives in another region — and the two functions
//! that apply them: [`status_of`] and [`mask_for_authorization`].
//! NOT responsible for: the code-to-status table itself ([`super::error_code`]), deciding which
//! code an operation raises, and rendering the body. In particular, this module *reports* that a
//! response must have no body; it does not suppress one.
//! Upstream: [`super::error_code`], `http`. Downstream: the error path of every operation, and the
//! P4/P5 tasks that consume these decisions.
//!
//! # Why a table alone is not enough
//!
//! Several S3 outcomes depend on the request rather than on the failure. Deleting a key that does
//! not exist is a success. Reading a key you are not allowed to know about is a 403 even though
//! the key is genuinely absent. A bucket in the wrong region is a redirect, not an error. Encoding
//! those as extra error codes would multiply the vocabulary; encoding them as `if`s inside
//! handlers is how they end up implemented three different ways. They are inputs to one function
//! instead.

use http::{Method, StatusCode};

use super::error_code::{CODE_TABLE, ErrorCode, FALLBACK_STATUS};

/// Request facts that change what an error looks like on the wire.
///
/// Plain struct with public fields and a `Default`: it is constructed at many call sites with
/// functional update syntax, and it is deliberately not `#[non_exhaustive]`, which would forbid
/// exactly that spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorContext {
    /// The request method, when known.
    pub method: Option<Method>,
    /// Whether the response may carry a body. `HEAD` answers carry the status and headers only,
    /// so an error body must be computed and then dropped — the code still has to be right,
    /// because it also travels in `x-amz-*` diagnostic headers.
    pub is_head: bool,
    /// Whether the caller holds `s3:ListBucket` on the bucket.
    ///
    /// This single flag decides whether a missing key is reported as missing. Without the
    /// permission, the *existence* of a key is information the caller is not entitled to, so
    /// `NoSuchKey` becomes `AccessDenied`.
    pub has_list_bucket_permission: bool,
    /// Whether the addressed bucket lives in a different region from the one that was signed.
    pub region_mismatch: bool,
    /// Whether the bucket exists but is owned by somebody else.
    pub owned_by_other_account: bool,
    /// Whether the bucket's virtual-hosted DNS name has not propagated yet.
    pub dns_not_propagated: bool,
}

impl ErrorContext {
    /// Whether the response may carry an error body at all.
    #[must_use]
    pub fn body_allowed(&self) -> bool {
        !self.is_head && self.method.as_ref() != Some(&Method::HEAD)
    }
}

/// Maps an error code to a status, taking request context into account.
///
/// The fallback for an unknown code is `400`, never a 5xx. A custom code that fell through to a
/// server error would tell the client to retry a request that cannot succeed, and clients that
/// discard 5xx bodies would never show the operator's chosen code to the user at all.
#[must_use]
pub fn status_of(code: &ErrorCode, ctx: &ErrorContext) -> StatusCode {
    // A bucket reached through the wrong region or an unpropagated DNS name is a redirect, whatever
    // the operation was about to report.
    if ctx.dns_not_propagated && code == &ErrorCode::NO_SUCH_BUCKET {
        return StatusCode::TEMPORARY_REDIRECT;
    }
    if ctx.region_mismatch && (code == &ErrorCode::NO_SUCH_BUCKET || code == &ErrorCode::PERMANENT_REDIRECT) {
        return StatusCode::MOVED_PERMANENTLY;
    }

    CODE_TABLE
        .iter()
        .find(|(name, _)| *name == code.as_str())
        .map_or(FALLBACK_STATUS, |(_, status)| *status)
}

/// Replaces a code that would leak the existence of a resource the caller cannot see.
///
/// Two rules, both of which have been the subject of published advisories elsewhere:
///
/// - without `s3:ListBucket`, a missing key must look exactly like a forbidden one;
/// - a bucket owned by another account must not be distinguishable from one that does not exist in
///   a way that confirms ownership.
///
/// Call this on the way out, after the operation has decided what happened and before the code
/// reaches [`status_of`]. It is a separate function rather than part of `status_of` because it
/// changes the code in the body too, not only the status line.
#[must_use]
pub fn mask_for_authorization(code: ErrorCode, ctx: &ErrorContext) -> ErrorCode {
    let hides_existence = code == ErrorCode::NO_SUCH_KEY || code == ErrorCode::NO_SUCH_VERSION;
    if hides_existence && !ctx.has_list_bucket_permission {
        return ErrorCode::ACCESS_DENIED;
    }
    if code == ErrorCode::NO_SUCH_BUCKET && ctx.owned_by_other_account {
        return ErrorCode::ACCESS_DENIED;
    }
    code
}
