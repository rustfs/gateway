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
//! error body's XML shape (`s3gate-xml`), and the context-sensitive rules, which live next door in
//! [`super::error_status`] because they need request context this type does not have.
//! Upstream: `http`. Downstream: every operation, the error serialiser, and the conformance suite.
//!
//! # A newtype, not an `enum`
//!
//! AWS adds error codes continuously, and downstream code stores codes it invented itself — one
//! migration target uses a custom code in nearly thirty places. A real `enum` would force a `_ =>`
//! arm into every consumer and would make every new AWS code a breaking change; a newtype over
//! `Cow<'static, str>` with associated constants makes it a one-line addition. Known codes cost no
//! allocation, and an unknown code is still a first-class value rather than a parse failure.

use std::borrow::Cow;
use std::fmt;

use http::StatusCode;

/// An S3 error code, as it appears in the `<Code>` element of an error body.
///
/// Compare against the associated constants; construct unknown codes with [`ErrorCode::custom`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode(Cow<'static, str>);

impl ErrorCode {
    /// Wraps a code this implementation does not have a constant for.
    ///
    /// The escape hatch is deliberate. Implementations behind this framework emit codes of their
    /// own, and forcing them through a "closest match" would put a misleading code on the wire.
    #[must_use]
    pub fn custom(code: impl Into<Cow<'static, str>>) -> Self {
        Self(code.into())
    }

    /// The wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this code has an entry in the status table.
    ///
    /// A code without one is not an error in itself — it maps to the fallback status — but it is
    /// worth reporting, because it usually means a constant is missing.
    #[must_use]
    pub fn is_known(&self) -> bool {
        CODE_TABLE.iter().any(|(name, _)| *name == self.0)
    }

    /// The status this code maps to, ignoring request context.
    ///
    /// Unknown codes get `400 Bad Request`, never a 5xx: a server error tells the client to retry
    /// something that will fail again, and some clients discard the body of a 5xx entirely, so the
    /// code the operator carefully chose never reaches the user. See
    /// [`super::error_status::status_of`] for the context-sensitive form.
    #[must_use]
    pub fn default_status(&self) -> StatusCode {
        CODE_TABLE
            .iter()
            .find(|(name, _)| *name == self.0)
            .map_or(FALLBACK_STATUS, |(_, status)| *status)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for ErrorCode {
    fn from(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

/// The status an unrecognised code receives. Never a 5xx — see [`ErrorCode::default_status`].
pub(super) const FALLBACK_STATUS: StatusCode = StatusCode::BAD_REQUEST;

/// Declares a code constant and its table row together, so the two cannot drift apart.
macro_rules! error_codes {
    ($( $(#[doc = $note:expr])* $name:ident = $wire:literal => $status:ident; )*) => {
        impl ErrorCode {
            $(
                #[doc = concat!("`", $wire, "`, HTTP `", stringify!($status), "`.")]
                $(
                    #[doc = ""]
                    #[doc = $note]
                )*
                pub const $name: Self = Self(Cow::Borrowed($wire));
            )*
        }

        /// Every code this implementation knows, with its context-free status.
        pub(super) const CODE_TABLE: &[(&str, StatusCode)] = &[
            $( ($wire, StatusCode::$status), )*
        ];
    };
}

error_codes! {
    // ── 3xx ───────────────────────────────────────────────────────────────────────────────────
    /// Path-style request for a bucket in another region; the response also carries
    /// `x-amz-bucket-region` so the client can retry without a second lookup.
    PERMANENT_REDIRECT = "PermanentRedirect" => MOVED_PERMANENTLY;
    /// A newly created bucket whose virtual-hosted DNS name has not propagated yet. Temporary by
    /// definition, so the client must not cache it.
    TEMPORARY_REDIRECT = "TemporaryRedirect" => TEMPORARY_REDIRECT;
    /// A precondition matched on a read: the response carries an `ETag` and no body at all, not
    /// even a `Content-Length`.
    NOT_MODIFIED = "NotModified" => NOT_MODIFIED;

    // ── 400 ───────────────────────────────────────────────────────────────────────────────────
    AMBIGUOUS_GRANT_BY_EMAIL_ADDRESS = "AmbiguousGrantByEmailAddress" => BAD_REQUEST;
    /// The signing region in the credential scope does not match the bucket's region. The error
    /// body carries an extra `<Region>` element, which is why error bodies are not a fixed shape.
    AUTHORIZATION_HEADER_MALFORMED = "AuthorizationHeaderMalformed" => BAD_REQUEST;
    AUTHORIZATION_QUERY_PARAMETERS_ERROR = "AuthorizationQueryParametersError" => BAD_REQUEST;
    /// `Content-MD5` was well formed but did not match the body.
    BAD_DIGEST = "BadDigest" => BAD_REQUEST;
    CREDENTIALS_NOT_SUPPORTED = "CredentialsNotSupported" => BAD_REQUEST;
    /// An upload part below the 5 MiB minimum, in a position other than the last.
    ENTITY_TOO_SMALL = "EntityTooSmall" => BAD_REQUEST;
    /// An object beyond the size limit. Note this is a 400 and not the 413 the status name would
    /// suggest.
    ENTITY_TOO_LARGE = "EntityTooLarge" => BAD_REQUEST;
    EXPIRED_TOKEN = "ExpiredToken" => BAD_REQUEST;
    ILLEGAL_VERSIONING_CONFIGURATION = "IllegalVersioningConfigurationException" => BAD_REQUEST;
    /// Fewer body bytes arrived than `Content-Length` promised.
    INCOMPLETE_BODY = "IncompleteBody" => BAD_REQUEST;
    INCORRECT_NUMBER_OF_FILES_IN_POST_REQUEST = "IncorrectNumberOfFilesInPostRequest" => BAD_REQUEST;
    INLINE_DATA_TOO_LARGE = "InlineDataTooLarge" => BAD_REQUEST;
    INVALID_ARGUMENT = "InvalidArgument" => BAD_REQUEST;
    INVALID_BUCKET_NAME = "InvalidBucketName" => BAD_REQUEST;
    INVALID_CHUNK_SIZE = "InvalidChunkSizeError" => BAD_REQUEST;
    /// `Content-MD5` was not valid base64 of sixteen bytes.
    INVALID_DIGEST = "InvalidDigest" => BAD_REQUEST;
    INVALID_ENCRYPTION_ALGORITHM = "InvalidEncryptionAlgorithmError" => BAD_REQUEST;
    INVALID_LOCATION_CONSTRAINT = "InvalidLocationConstraint" => BAD_REQUEST;
    INVALID_PART = "InvalidPart" => BAD_REQUEST;
    INVALID_PART_NUMBER = "InvalidPartNumber" => BAD_REQUEST;
    INVALID_PART_ORDER = "InvalidPartOrder" => BAD_REQUEST;
    INVALID_POLICY_DOCUMENT = "InvalidPolicyDocument" => BAD_REQUEST;
    /// The general-purpose rejection, and the fallback for a code with no table row.
    INVALID_REQUEST = "InvalidRequest" => BAD_REQUEST;
    INVALID_RETENTION_PERIOD = "InvalidRetentionPeriod" => BAD_REQUEST;
    INVALID_SOAP_REQUEST = "InvalidSOAPRequest" => BAD_REQUEST;
    INVALID_STORAGE_CLASS = "InvalidStorageClass" => BAD_REQUEST;
    INVALID_TAG = "InvalidTag" => BAD_REQUEST;
    INVALID_TARGET_BUCKET_FOR_LOGGING = "InvalidTargetBucketForLogging" => BAD_REQUEST;
    INVALID_TOKEN = "InvalidToken" => BAD_REQUEST;
    INVALID_URI = "InvalidURI" => BAD_REQUEST;
    KEY_TOO_LONG = "KeyTooLongError" => BAD_REQUEST;
    MALFORMED_ACL = "MalformedACLError" => BAD_REQUEST;
    MALFORMED_POLICY = "MalformedPolicy" => BAD_REQUEST;
    MALFORMED_POST_REQUEST = "MalformedPOSTRequest" => BAD_REQUEST;
    MALFORMED_XML = "MalformedXML" => BAD_REQUEST;
    MAX_MESSAGE_LENGTH_EXCEEDED = "MaxMessageLengthExceeded" => BAD_REQUEST;
    MAX_POST_PRE_DATA_LENGTH_EXCEEDED = "MaxPostPreDataLengthExceededError" => BAD_REQUEST;
    METADATA_TOO_LARGE = "MetadataTooLarge" => BAD_REQUEST;
    MISSING_REQUEST_BODY = "MissingRequestBodyError" => BAD_REQUEST;
    MISSING_SECURITY_ELEMENT = "MissingSecurityElement" => BAD_REQUEST;
    MISSING_SECURITY_HEADER = "MissingSecurityHeader" => BAD_REQUEST;
    NO_LOGGING_STATUS_FOR_KEY = "NoLoggingStatusForKey" => BAD_REQUEST;
    REQUEST_IS_NOT_MULTIPART_CONTENT = "RequestIsNotMultiPartContent" => BAD_REQUEST;
    /// The client stopped sending. A 400 rather than the 408 the name suggests.
    REQUEST_TIMEOUT = "RequestTimeout" => BAD_REQUEST;
    TOKEN_REFRESH_REQUIRED = "TokenRefreshRequired" => BAD_REQUEST;
    TOO_MANY_BUCKETS = "TooManyBuckets" => BAD_REQUEST;
    UNEXPECTED_CONTENT = "UnexpectedContent" => BAD_REQUEST;
    UNRESOLVABLE_GRANT_BY_EMAIL_ADDRESS = "UnresolvableGrantByEmailAddress" => BAD_REQUEST;
    USER_KEY_MUST_BE_SPECIFIED = "UserKeyMustBeSpecified" => BAD_REQUEST;
    /// An `x-amz-checksum-*` value did not match the body. Distinct from `BadDigest`, which is the
    /// `Content-MD5` failure; SDKs branch on the difference.
    X_AMZ_CONTENT_CHECKSUM_MISMATCH = "XAmzContentChecksumMismatch" => BAD_REQUEST;
    X_AMZ_CONTENT_SHA256_MISMATCH = "XAmzContentSHA256Mismatch" => BAD_REQUEST;

    // ── 403 ───────────────────────────────────────────────────────────────────────────────────
    ACCESS_DENIED = "AccessDenied" => FORBIDDEN;
    /// `OPTIONS` against a bucket with no CORS configuration. A 403 with its own code rather than
    /// a 404, so a browser preflight fails in a way the developer can diagnose.
    ACCESS_FORBIDDEN = "AccessForbidden" => FORBIDDEN;
    ACCOUNT_PROBLEM = "AccountProblem" => FORBIDDEN;
    ALL_ACCESS_DISABLED = "AllAccessDisabled" => FORBIDDEN;
    CROSS_LOCATION_LOGGING_PROHIBITED = "CrossLocationLoggingProhibited" => FORBIDDEN;
    INVALID_ACCESS_KEY_ID = "InvalidAccessKeyId" => FORBIDDEN;
    /// The object's storage class requires a restore first. A 403, not a 409.
    INVALID_OBJECT_STATE = "InvalidObjectState" => FORBIDDEN;
    INVALID_PAYER = "InvalidPayer" => FORBIDDEN;
    INVALID_SECURITY = "InvalidSecurity" => FORBIDDEN;
    NOT_SIGNED_UP = "NotSignedUp" => FORBIDDEN;
    REQUEST_TIME_TOO_SKEWED = "RequestTimeTooSkewed" => FORBIDDEN;
    SIGNATURE_DOES_NOT_MATCH = "SignatureDoesNotMatch" => FORBIDDEN;

    // ── 404 ───────────────────────────────────────────────────────────────────────────────────
    NO_SUCH_BUCKET = "NoSuchBucket" => NOT_FOUND;
    NO_SUCH_BUCKET_POLICY = "NoSuchBucketPolicy" => NOT_FOUND;
    NO_SUCH_CORS_CONFIGURATION = "NoSuchCORSConfiguration" => NOT_FOUND;
    /// Returned only when the caller may list the bucket; without that permission the existence of
    /// the key is itself privileged and the answer is `AccessDenied`.
    NO_SUCH_KEY = "NoSuchKey" => NOT_FOUND;
    NO_SUCH_LIFECYCLE_CONFIGURATION = "NoSuchLifecycleConfiguration" => NOT_FOUND;
    NO_SUCH_OBJECT_LOCK_CONFIGURATION = "NoSuchObjectLockConfiguration" => NOT_FOUND;
    NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION = "NoSuchPublicAccessBlockConfiguration" => NOT_FOUND;
    NO_SUCH_TAG_SET = "NoSuchTagSet" => NOT_FOUND;
    NO_SUCH_UPLOAD = "NoSuchUpload" => NOT_FOUND;
    NO_SUCH_VERSION = "NoSuchVersion" => NOT_FOUND;
    NO_SUCH_WEBSITE_CONFIGURATION = "NoSuchWebsiteConfiguration" => NOT_FOUND;
    OBJECT_LOCK_CONFIGURATION_NOT_FOUND = "ObjectLockConfigurationNotFoundError" => NOT_FOUND;
    REPLICATION_CONFIGURATION_NOT_FOUND = "ReplicationConfigurationNotFoundError" => NOT_FOUND;
    SERVER_SIDE_ENCRYPTION_CONFIGURATION_NOT_FOUND = "ServerSideEncryptionConfigurationNotFoundError" => NOT_FOUND;

    // ── 405 / 409 / 411 / 412 / 416 ───────────────────────────────────────────────────────────
    /// The verb is not allowed on this resource. Distinct from `NotImplemented`, which means the
    /// operation itself is unknown; conflating them hides routing bugs. A `GET` of a delete marker
    /// by version id also lands here.
    METHOD_NOT_ALLOWED = "MethodNotAllowed" => METHOD_NOT_ALLOWED;
    BUCKET_ALREADY_EXISTS = "BucketAlreadyExists" => CONFLICT;
    /// Re-creating a bucket you already own. Historically a 200 in the original region, which is
    /// why the status is context-sensitive rather than a plain table lookup.
    BUCKET_ALREADY_OWNED_BY_YOU = "BucketAlreadyOwnedByYou" => CONFLICT;
    BUCKET_NOT_EMPTY = "BucketNotEmpty" => CONFLICT;
    INVALID_BUCKET_STATE = "InvalidBucketState" => CONFLICT;
    OPERATION_ABORTED = "OperationAborted" => CONFLICT;
    /// A `PUT` with no `Content-Length`. A 411, not a 400: the client must add the header, not fix
    /// its parameters.
    MISSING_CONTENT_LENGTH = "MissingContentLength" => LENGTH_REQUIRED;
    PRECONDITION_FAILED = "PreconditionFailed" => PRECONDITION_FAILED;
    /// The requested range cannot be satisfied at all. A range that merely runs past the end is
    /// clamped and answered with 206 instead.
    INVALID_RANGE = "InvalidRange" => RANGE_NOT_SATISFIABLE;

    // ── 5xx ───────────────────────────────────────────────────────────────────────────────────
    /// Reserved for genuine server faults. It is never a fallback: see
    /// [`ErrorCode::default_status`].
    INTERNAL_ERROR = "InternalError" => INTERNAL_SERVER_ERROR;
    /// The operation is not supported by this implementation at all.
    NOT_IMPLEMENTED = "NotImplemented" => NOT_IMPLEMENTED;
    SERVICE_UNAVAILABLE = "ServiceUnavailable" => SERVICE_UNAVAILABLE;
    /// The throttling signal SDKs treat as retryable with backoff.
    SLOW_DOWN = "SlowDown" => SERVICE_UNAVAILABLE;
}
