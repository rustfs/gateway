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

//! The four one-document bucket switches: what a stored versioning, acceleration, request-payment
//! or logging configuration is allowed to say.
//!
//! Shares: bucket_config
//! Members: GetBucketAccelerateConfiguration, GetBucketLogging, GetBucketRequestPayment, GetBucketVersioning, PutBucketAccelerateConfiguration, PutBucketLogging, PutBucketRequestPayment, PutBucketVersioning
//!
//! Responsible for: the semantic rules of the `VersioningConfiguration`,
//! `AccelerateConfiguration`, `RequestPaymentConfiguration` and `BucketLoggingStatus` documents —
//! which is, in every case, one closed value set and nothing else — held once so that every
//! backend refuses the same documents with the same codes.
//! NOT responsible for: decoding the documents (the generated codecs), storing them, or acting on
//! them. Nothing here suspends a version, accelerates a transfer, bills a requester or writes a
//! log line; the notification document's own grammar lives in [`super::bucket_notification`] and
//! the website document's in [`super::bucket_website`].
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Why this refuses so little
//!
//! RustFS re-parses every stored bucket configuration on every start, and its persistence layer
//! fails **open**: a document that stops parsing is downgraded to "no configuration". For most
//! subresources that is a feature quietly switching off. For versioning it is worse than that —
//! version retention switching off quietly, with the overwrites that happen in the interval
//! unrecoverable afterwards. A decoder that got stricter between two releases would do exactly
//! that, to documents this release wrote and accepted.
//!
//! So the rule is: refuse what AWS documents as a refusal, and store everything else. Unknown
//! elements are skipped by the generated decoders. Values outside a closed set are refused here
//! *only* where the member is the whole document — `<Status>` is the entire content of an
//! acceleration or versioning document, and `<Payer>` is a required member — because a stored
//! value nothing can interpret is not a configuration, it is a bucket in an undefined state.
//!
//! # The refusal messages are constant
//!
//! Every reason below is a compile-time literal. None is built from request bytes, and none
//! repeats the value that was refused: the closed sets are short enough to state outright, and a
//! reason that echoed the input would put caller-controlled text into an error body and every log
//! line that captures one.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{
    AccelerateConfiguration, BucketLoggingStatus, MfaDelete, Payer, RequestPaymentConfiguration, Status, VersioningConfiguration,
};

/// The two values a versioning or acceleration `<Status>` may carry.
///
/// Written out rather than read off `Status::VALUES`: the generated enumeration is named after the
/// *member*, so one `Status` type carries the union of every operation's set — `Disabled`, `ON` and
/// `OFF` reach it from the lifecycle and object-lock families. Accepting the union here would let a
/// versioning write store `Disabled`, which is not a versioning state at all.
const SWITCH_STATUSES: &[&str] = &["Enabled", "Suspended"];

/// The two values `<MfaDelete>` may carry. `Enabled` and `Disabled`, not the switch pair above.
const MFA_DELETE_STATES: &[&str] = &["Enabled", "Disabled"];

/// The two values `<Payer>` may carry.
const PAYERS: &[&str] = &["Requester", "BucketOwner"];

/// Why a decoded one-switch configuration was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`BucketConfigRejection::code`] and
/// [`BucketConfigRejection::reason`] are the two halves an S3 error document needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketConfigRejection {
    /// A `<Status>` outside `Enabled`/`Suspended`. The element is the whole document, so a value
    /// outside the set leaves nothing to store.
    StatusUnknown,
    /// An `<MfaDelete>` outside `Enabled`/`Disabled`.
    MfaDeleteUnknown,
    /// A `<Payer>` outside `Requester`/`BucketOwner`. The member is required, so there is no
    /// reading of the document that survives an unknown value.
    PayerUnknown,
    /// A `<LoggingEnabled>` with an empty `<TargetBucket>`. Logging to nowhere is not logging, and
    /// the member is required by the model, so the empty string is the one value the decoder lets
    /// through and this refuses.
    LoggingTargetEmpty,
}

impl BucketConfigRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A closed value set violated is a schema violation: the document is not the document.
            BucketConfigRejection::StatusUnknown | BucketConfigRejection::MfaDeleteUnknown => ErrorCode::MALFORMED_XML,
            // A present, well-formed value that this operation cannot use.
            BucketConfigRejection::PayerUnknown | BucketConfigRejection::LoggingTargetEmpty => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            BucketConfigRejection::StatusUnknown => "Status must be either Enabled or Suspended",
            BucketConfigRejection::MfaDeleteUnknown => "MfaDelete must be either Enabled or Disabled",
            BucketConfigRejection::PayerUnknown => "Payer must be either Requester or BucketOwner",
            BucketConfigRejection::LoggingTargetEmpty => "TargetBucket must name a bucket",
        }
    }
}

/// Whether a decoded string enumeration carries one of the listed values.
fn in_set(value: &str, set: &[&str]) -> bool {
    set.contains(&value)
}

/// Checks a decoded versioning document.
///
/// An absent `<Status>` passes: that is the never-configured document the read answers with, and a
/// write that carries only `<MfaDelete>` is a legitimate partial change of the same document.
///
/// # Errors
///
/// [`BucketConfigRejection`] naming the first rule the document breaks.
pub fn validate_versioning(configuration: &VersioningConfiguration) -> Result<(), BucketConfigRejection> {
    if let Some(status) = configuration.status.as_ref()
        && !in_set(status.as_str(), SWITCH_STATUSES)
    {
        return Err(BucketConfigRejection::StatusUnknown);
    }
    if let Some(mfa) = configuration.mfa_delete.as_ref()
        && !in_set(mfa.as_str(), MFA_DELETE_STATES)
    {
        return Err(BucketConfigRejection::MfaDeleteUnknown);
    }
    Ok(())
}

/// Checks a decoded acceleration document. The same closed `<Status>` set as versioning, and
/// nothing else — an empty document is "leave it alone", not an error.
///
/// # Errors
///
/// [`BucketConfigRejection::StatusUnknown`] for a `<Status>` outside the set.
pub fn validate_accelerate(configuration: &AccelerateConfiguration) -> Result<(), BucketConfigRejection> {
    match configuration.status.as_ref() {
        Some(status) if !in_set(status.as_str(), SWITCH_STATUSES) => Err(BucketConfigRejection::StatusUnknown),
        _ => Ok(()),
    }
}

/// Checks a decoded request-payment document.
///
/// # Errors
///
/// [`BucketConfigRejection::PayerUnknown`] for a `<Payer>` outside the set.
pub fn validate_request_payment(configuration: &RequestPaymentConfiguration) -> Result<(), BucketConfigRejection> {
    if in_set(configuration.payer.as_str(), PAYERS) {
        Ok(())
    } else {
        Err(BucketConfigRejection::PayerUnknown)
    }
}

/// Checks a decoded logging document.
///
/// An absent `<LoggingEnabled>` passes and means "stop logging" — there is no delete operation for
/// this subresource, so the empty document is the only way to say it.
///
/// # Errors
///
/// [`BucketConfigRejection::LoggingTargetEmpty`] when logging is enabled to no bucket at all.
pub fn validate_logging(configuration: &BucketLoggingStatus) -> Result<(), BucketConfigRejection> {
    match configuration.logging_enabled.as_ref() {
        Some(enabled) if enabled.target_bucket.is_empty() => Err(BucketConfigRejection::LoggingTargetEmpty),
        _ => Ok(()),
    }
}

/// The canonical `<Status>` values, for a backend that wants to render the set rather than repeat
/// it. The same slice the refusals above are decided against, so the two cannot disagree.
#[must_use]
pub fn switch_statuses() -> [Status; 2] {
    [Status::ENABLED, Status::SUSPENDED]
}

/// The canonical `<MfaDelete>` values, on the same footing as [`switch_statuses`].
#[must_use]
pub fn mfa_delete_states() -> [MfaDelete; 2] {
    [MfaDelete::ENABLED, MfaDelete::DISABLED]
}

/// The canonical `<Payer>` values, on the same footing as [`switch_statuses`].
#[must_use]
pub fn payers() -> [Payer; 2] {
    [Payer::REQUESTER, Payer::BUCKETOWNER]
}
