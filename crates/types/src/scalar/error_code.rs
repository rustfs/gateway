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

//! The S3 error-code vocabulary and its HTTP status table.
//!
//! Responsible for: naming every error code this implementation can emit, keeping an escape hatch
//! for codes it does not know, and mapping a code to a status — the whole table in one place, so
//! that "which status does this code get?" has exactly one answer.
//! NOT responsible for: choosing *which* code an operation returns (that is per-operation), the
//! error body's XML shape (`rustfs-gateway-xml`), or contextual resolution, which belongs to
//! `rustfs-gateway-core` because it needs operation and authorization facts.
//! Upstream: `http`, `generated/error_status.rs`. Downstream: every operation, the error
//! serialiser, and the conformance suite.
//!
//! # A newtype, not an `enum`
//!
//! AWS adds error codes continuously, and downstream code stores codes it invented itself — one
//! migration target uses a custom code in nearly thirty places. A real `enum` would force a `_ =>`
//! arm into every consumer and would make every new AWS code a breaking change; a newtype with
//! associated constants makes it a one-line addition. Known codes cost no allocation, and an
//! unknown code is still a first-class value rather than a parse failure.
//!
//! # Where the table lives, and why there is no fallback
//!
//! The rows are not written here. `model/overlays/error-status.toml` is the single hand-written
//! authority and `generated/error_status.rs`, included below, is rendered from it — so the
//! constants and the statuses cannot drift apart, because they are one input.
//!
//! Until rustfs/backlog#1694 a code with no row silently took a 400, which reads exactly like a
//! mapped code and hid six codes that operations declare they can produce. The fallback is gone
//! rather than moved: a code has a status because a value carries one, [`ErrorCode::custom`] makes
//! its caller name that status, and there is no constructor that invents one. `is_known` still
//! reports whether the authority has a row, because a missing row usually means a missing
//! constant — but nothing about the status depends on the answer.

use std::borrow::Cow;
use std::fmt;

use http::StatusCode;

/// An S3 error code, as it appears in the `<Code>` element of an error body, with the status it
/// renders as.
///
/// Compare against the associated constants; construct codes the authority does not declare with
/// [`ErrorCode::custom`], and look one up by wire spelling with [`ErrorCode::known`].
///
/// Two values are equal when both the spelling and the status match. That is the wire identity: a
/// value that renders `AccessDenied` with a 400 is not the `AccessDenied` any client has ever
/// seen, and letting it compare equal to [`ErrorCode::ACCESS_DENIED`] would let it pass every
/// assertion written about the real one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode {
    name: Cow<'static, str>,
    status: StatusCode,
}

impl ErrorCode {
    /// Wraps a code the authority does not declare, with the status it must render as.
    ///
    /// The escape hatch is deliberate. Implementations behind this framework emit codes of their
    /// own, and forcing them through a "closest match" would put a misleading code on the wire.
    /// The status is a parameter and not a default because the default was the defect: a 5xx tells
    /// a client to retry something that will fail again and trips its circuit breaker, and a 4xx
    /// invented on the caller's behalf is a status nobody chose either.
    ///
    /// ```
    /// use http::StatusCode;
    /// use rustfs_gateway_types::ErrorCode;
    ///
    /// let code = ErrorCode::custom("RustFsTierBackendUnreachable", StatusCode::SERVICE_UNAVAILABLE);
    /// assert_eq!(code.default_status(), StatusCode::SERVICE_UNAVAILABLE);
    /// assert!(!code.is_known());
    /// ```
    #[must_use]
    pub fn custom(code: impl Into<Cow<'static, str>>, status: StatusCode) -> Self {
        Self {
            name: code.into(),
            status,
        }
    }

    /// The operation-specific `404` for an unconfigured bucket subresource, in const context.
    ///
    /// The status is not a parameter because every code this constructor is for is a `404`: the
    /// condition it names is "the document does not exist". `rustfs-gateway-core` proves that
    /// against the authority — `crates/core/tests/not_configured_declarations.rs` asserts that
    /// every spelling the IR lowers into `RouteRow::not_configured` has a `404` row in
    /// `model/overlays/error-status.toml` — so a code whose status the overlay changes fails there
    /// rather than being silently re-statused here.
    ///
    /// Why it exists at all: [`ErrorCode::known`] scans a `static` table and cannot run in a
    /// `const` initializer, and an operation's `OperationSpec` is a `static` built at compile time.
    /// Without a `const` constructor the code has to be written out a second time by hand beside
    /// the generated one, which is the divergence recorded as gateway#242.
    ///
    /// ```
    /// use rustfs_gateway_types::ErrorCode;
    ///
    /// const CODE: ErrorCode = ErrorCode::not_configured("NoSuchLifecycleConfiguration");
    /// assert_eq!(CODE, ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION);
    /// ```
    #[must_use]
    pub const fn not_configured(code: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(code),
            status: StatusCode::NOT_FOUND,
        }
    }

    /// The declared code with this wire spelling, or `None`.
    ///
    /// The replacement for the old `From<&'static str>`: a spelling with no row has no status, so
    /// it has no `ErrorCode` either. A caller that means to answer with an undeclared code says so
    /// with [`ErrorCode::custom`] and names the status.
    ///
    /// ```
    /// use rustfs_gateway_types::ErrorCode;
    ///
    /// assert_eq!(ErrorCode::known("NoSuchKey"), Some(ErrorCode::NO_SUCH_KEY));
    /// assert_eq!(ErrorCode::known("NoSuchThing"), None);
    /// ```
    #[must_use]
    pub fn known(code: &str) -> Option<Self> {
        CODE_TABLE.iter().find(|(name, _)| *name == code).map(|(name, status)| Self {
            name: Cow::Borrowed(name),
            status: *status,
        })
    }

    /// The wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Whether this code has a row in the authority.
    ///
    /// A code without one is not an error in itself — its status came from its author — but it is
    /// worth reporting, because it usually means a constant is missing.
    #[must_use]
    pub fn is_known(&self) -> bool {
        CODE_TABLE.iter().any(|(name, _)| *name == self.name)
    }

    /// The status this code renders as, ignoring request context.
    ///
    /// Contextual outcomes — a 403 masking a 404, a redirect carrying `x-amz-bucket-region` — are
    /// resolved by `rustfs-gateway-core`, which has the operation and authorization facts this
    /// crate does not.
    #[must_use]
    pub fn default_status(&self) -> StatusCode {
        self.status
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

include!("../../../../generated/error_status.rs");
