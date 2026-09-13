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

//! Temporary adapters to the s3s persistence oracles that migration admission is measured against.
//!
//! Responsible for: invoking the exact old persistence codecs of every pinned s3s revision,
//! selecting which revision answers, exposing family-scoped adapters over owned values, the
//! single-operation DTO conversion in [`put_object`](crate::compat::put_object), and the
//! request-context conversion in [`request_context`](crate::compat::request_context) — the only
//! two submodules whose API names s3s types.
//! NOT responsible for: production XML behavior, golden assertions, or wiring any conversion into a
//! request path.
//! Upstream: the three s3s revisions named by [`OracleRevision`]. Downstream:
//! `rustfs-gateway-goldens`; this module is deleted by P9-09.
//!
//! One adapter source, three compilations: `compat/oracle/*.rs` is compiled once per revision as
//! the `baseline`, `rollback` and `candidate` modules below, each binding its own `s3s`. The public
//! functions dispatch on the revision [`with_oracle`] selected for the current thread. The default
//! is [`OracleRevision::Baseline`], so a caller that never selects one measures exactly what it
//! measured before the other revisions existed.

use core::cell::Cell;
use core::fmt;

use crate::cors_tagging::{CorsBehaviorProjection, PersistedCorsConfiguration, PersistedTagging};
use crate::persistence::{
    NotificationBehaviorProjection, PersistedAccelerateConfiguration, PersistedBucketEncryptionConfiguration,
    PersistedBucketLoggingStatus, PersistedLifecycleConfiguration, PersistedNotificationConfiguration,
    PersistedObjectLockConfiguration, PersistedPublicAccessBlockConfiguration, PersistedReplicationConfiguration,
    PersistedRequestPaymentConfiguration, PersistedVersioningConfiguration, PersistedWebsiteConfiguration,
    ReplicationBehaviorProjection,
};

pub mod put_object;
pub mod request_context;

/// The baseline oracle crate, re-exported so a harness drives exactly the revision
/// [`put_object`] converts to. Kernel crates other than this one may not depend on s3s at all
/// (`scripts/check_ring_boundaries.sh`), so this is the one route a test takes to it. The
/// persistence adapters do not use it: each compiles against its own revision below.
pub use ::s3s_baseline as s3s;

/// One s3s revision that persistence migration is admitted against.
///
/// Each variant is the revision a real RustFS build links, read from that build's `Cargo.lock`,
/// and all three are compiled from the same adapter source. The variant names the role the
/// revision plays in admission; [`OracleRevision::rustfs_build`] names the build.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OracleRevision {
    /// The original P9-01 oracle. Every golden digest and pinned old-refusal boundary in the
    /// corpus was first measured against it.
    Baseline,
    /// The latest RustFS release: the build an operator rolls back to.
    Rollback,
    /// RustFS `main`: the production build the gateway migration is a candidate for.
    Candidate,
}

impl OracleRevision {
    /// Every admitted revision, baseline first.
    pub const ALL: [Self; 3] = [Self::Baseline, Self::Rollback, Self::Candidate];

    /// Stable report label for the role this revision plays in admission.
    #[must_use]
    pub const fn role(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Rollback => "rollback",
            Self::Candidate => "candidate",
        }
    }

    /// Git repository the revision is fetched from, exactly as this crate's manifest names it.
    #[must_use]
    pub const fn repository(self) -> &'static str {
        match self {
            Self::Baseline | Self::Rollback => "https://github.com/rustfs/s3s.git",
            Self::Candidate => "https://github.com/s3s-project/s3s.git",
        }
    }

    /// Full s3s commit, identical to the `rev` this crate's manifest pins for the revision.
    #[must_use]
    pub const fn revision(self) -> &'static str {
        match self {
            Self::Baseline => "9c4690d8e73fc8d184031a19b2c4539ebc77d180",
            Self::Rollback => "bdcb6259339c41369f9f1c60e3a42b5ab8da607b",
            Self::Candidate => "f3e17541f366696bf0cbaf380fcbd8b44c17eba4",
        }
    }

    /// The RustFS build whose `Cargo.lock` pins this revision.
    #[must_use]
    pub const fn rustfs_build(self) -> &'static str {
        match self {
            Self::Baseline => "rustfs/rustfs@436a1be899e90e67d7c4aa81def70d39fe1748d5 (1.0.0-rc.5-preview.2)",
            Self::Rollback => "rustfs/rustfs@5cd58319ed6148ed7f09f2a4d0b4e46e429f043a (1.0.0-rc.6)",
            Self::Candidate => "rustfs/rustfs@cc29b03a05e61d0c713266aa12ad6a470ecdf9f9 (main)",
        }
    }
}

impl fmt::Display for OracleRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = self.revision().get(..8).unwrap_or(self.revision());
        write!(formatter, "{} s3s@{short}", self.role())
    }
}

thread_local! {
    static SELECTED: Cell<OracleRevision> = const { Cell::new(OracleRevision::Baseline) };
}

/// The revision every adapter in this module answers from on the current thread.
#[must_use]
pub fn selected_oracle() -> OracleRevision {
    SELECTED.with(Cell::get)
}

/// Runs `measure` with every adapter in this module answering from `oracle`, then restores the
/// previous selection, also when `measure` panics.
///
/// The selection belongs to the current thread: work `measure` hands to another thread is
/// measured against the baseline. Nothing in the golden harness spawns a thread; a harness that
/// starts to must select the revision on that thread as well.
pub fn with_oracle<T>(oracle: OracleRevision, measure: impl FnOnce() -> T) -> T {
    struct Restore(OracleRevision);

    impl Drop for Restore {
        fn drop(&mut self) {
            SELECTED.with(|selected| selected.set(self.0));
        }
    }

    let _restore = Restore(SELECTED.with(|selected| selected.replace(oracle)));
    measure()
}

/// One old-codec observation before the golden harness normalizes either side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sVersioningObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedVersioningConfiguration,
    /// Whether the pinned old implementation interprets the status as enabled.
    pub versioning_enabled: bool,
    /// The exact old versioning status used by its behavior decision.
    pub versioning_status: Option<String>,
    /// The exact old MFA delete state used by its behavior decision.
    pub mfa_delete: Option<String>,
}

/// One old-codec Object Lock observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sObjectLockObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedObjectLockConfiguration,
    /// Whether the pinned old implementation interprets Object Lock as enabled.
    pub object_lock_enabled: bool,
}

/// One old-codec Bucket Encryption observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sBucketEncryptionObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedBucketEncryptionConfiguration,
    /// Runtime-relevant algorithm, KMS key, and bucket-key decisions per stored rule.
    pub behavior: Vec<(Option<String>, Option<String>, Option<bool>)>,
}

/// One old-codec Public Access Block observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sPublicAccessBlockObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedPublicAccessBlockConfiguration,
    /// The four effective access decisions in stable field order.
    pub behavior: (bool, bool, bool, bool),
}

/// One old-codec CORS observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sCorsObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedCorsConfiguration,
    /// Independently projected runtime CORS behavior.
    pub behavior: CorsBehaviorProjection,
}

/// One old-codec Tagging observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sTaggingObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedTagging,
    /// Independently projected complete tag set.
    pub tags: Vec<(Option<String>, Option<String>)>,
}

/// One old-codec Bucket Logging observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sBucketLoggingObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedBucketLoggingStatus,
    /// Runtime delivery decisions projected directly from the pinned DTO.
    pub behavior: Option<crate::persistence::PersistedLoggingEnabled>,
}

/// One old-codec Website observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sWebsiteObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedWebsiteConfiguration,
    /// Runtime routing decisions projected directly from the pinned DTO.
    pub behavior: PersistedWebsiteConfiguration,
}

/// One old-codec Accelerate observation before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sAccelerateObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedAccelerateConfiguration,
    /// Whether pinned old behavior enables acceleration.
    pub enabled: bool,
}

/// One old-codec Request Payment observation before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sRequestPaymentObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedRequestPaymentConfiguration,
    /// Whether pinned old behavior enables requester pays.
    pub requester_pays: bool,
}

/// One old-codec Lifecycle observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sLifecycleObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedLifecycleConfiguration,
    /// Enabled decisions computed directly from the pinned old rule statuses.
    pub rule_enabled: Vec<bool>,
}

/// One old-codec Notification observation before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sNotificationObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedNotificationConfiguration,
    /// Complete routing decisions projected directly from the old DTO.
    pub behavior: NotificationBehaviorProjection,
}

/// Independent old-codec Replication observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sReplicationObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedReplicationConfiguration,
    /// Runtime-relevant rule projection made from the old DTO.
    pub behavior: ReplicationBehaviorProjection,
}

/// Failure raised by an old persistence codec, or by projecting what it read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatCodecError {
    message: String,
    unrepresented_member: Option<&'static str>,
}

impl CompatCodecError {
    fn old_codec(error: impl fmt::Display) -> Self {
        Self {
            message: format!("pinned s3s persistence codec failed: {error}"),
            unrepresented_member: None,
        }
    }

    fn unrepresented(member: &'static str) -> Self {
        Self {
            message: format!("pinned s3s persistence codec read member {member}, which no persisted structure can carry"),
            unrepresented_member: Some(member),
        }
    }

    /// The member the old codec read but no persisted structure can carry, when that is why the
    /// adapter failed.
    ///
    /// `Some` reports an old *acceptance*: the selected revision read the document. It is never
    /// an old refusal, and counting it as one would hide the very divergence it names.
    #[must_use]
    pub const fn unrepresented_member(&self) -> Option<&'static str> {
        self.unrepresented_member
    }
}

impl fmt::Display for CompatCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CompatCodecError {}

/// s3s `9c4690d8`, whose `ServerSideEncryptionRule` has no `BlockedEncryptionTypes` member.
#[path = "compat/oracle"]
mod baseline {
    use ::s3s_baseline as s3s;
    use s3s::dto::{ServerSideEncryptionByDefault, ServerSideEncryptionRule};

    mod accelerate_payment;
    mod bucket_configs;
    mod lifecycle;
    mod notification;
    mod replication;

    pub(super) use self::{accelerate_payment::*, bucket_configs::*, lifecycle::*, notification::*, replication::*};

    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        bucket_key_enabled: Option<bool>,
    ) -> ServerSideEncryptionRule {
        ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            bucket_key_enabled,
        }
    }

    fn unrepresented_encryption_rule_member(_rule: &ServerSideEncryptionRule) -> Option<&'static str> {
        None
    }
}

/// s3s `bdcb6259`. Its `ServerSideEncryptionRule` gained `BlockedEncryptionTypes`, which the
/// persisted Bucket Encryption structure cannot carry.
#[path = "compat/oracle"]
#[allow(clippy::duplicate_mod)] // Deliberate: one adapter source is compiled once per pinned revision.
mod rollback {
    use ::s3s_rollback as s3s;
    use s3s::dto::{ServerSideEncryptionByDefault, ServerSideEncryptionRule};

    mod accelerate_payment;
    mod bucket_configs;
    mod lifecycle;
    mod notification;
    mod replication;

    pub(super) use self::{accelerate_payment::*, bucket_configs::*, lifecycle::*, notification::*, replication::*};

    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        bucket_key_enabled: Option<bool>,
    ) -> ServerSideEncryptionRule {
        ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            blocked_encryption_types: None,
            bucket_key_enabled,
        }
    }

    fn unrepresented_encryption_rule_member(rule: &ServerSideEncryptionRule) -> Option<&'static str> {
        rule.blocked_encryption_types.as_ref().map(|_| "BlockedEncryptionTypes")
    }
}

/// s3s `f3e17541`, with the same `BlockedEncryptionTypes` member as the rollback revision.
#[path = "compat/oracle"]
#[allow(clippy::duplicate_mod)] // Deliberate: one adapter source is compiled once per pinned revision.
mod candidate {
    use ::s3s_candidate as s3s;
    use s3s::dto::{ServerSideEncryptionByDefault, ServerSideEncryptionRule};

    mod accelerate_payment;
    mod bucket_configs;
    mod lifecycle;
    mod notification;
    mod replication;

    pub(super) use self::{accelerate_payment::*, bucket_configs::*, lifecycle::*, notification::*, replication::*};

    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        bucket_key_enabled: Option<bool>,
    ) -> ServerSideEncryptionRule {
        ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            blocked_encryption_types: None,
            bucket_key_enabled,
        }
    }

    fn unrepresented_encryption_rule_member(rule: &ServerSideEncryptionRule) -> Option<&'static str> {
        rule.blocked_encryption_types.as_ref().map(|_| "BlockedEncryptionTypes")
    }
}

/// Declares each public adapter once and routes it to the selected revision's compilation. The
/// function names stay literal here so `grep parse_s3s_versioning` still finds the definition.
macro_rules! dispatch {
    ($($(#[doc = $doc:literal])+ fn $name:ident($arg:ident: $input:ty) -> $output:ty;)+) => {$(
        $(#[doc = $doc])+
        ///
        /// # Errors
        ///
        /// Returns [`CompatCodecError`] when the selected revision refuses the input, or when it
        /// read a member no persisted structure can carry.
        pub fn $name($arg: $input) -> Result<$output, CompatCodecError> {
            match selected_oracle() {
                OracleRevision::Baseline => baseline::$name($arg),
                OracleRevision::Rollback => rollback::$name($arg),
                OracleRevision::Candidate => candidate::$name($arg),
            }
        }
    )+};
}

dispatch! {
    /// Parses Versioning bytes with the selected s3s persistence decoder.
    fn parse_s3s_versioning(input: &[u8]) -> S3sVersioningObservation;
    /// Serializes a Versioning value with the selected s3s persistence encoder.
    fn serialize_s3s_versioning(value: &PersistedVersioningConfiguration) -> Vec<u8>;
    /// Parses Object Lock bytes with the selected s3s persistence decoder.
    fn parse_s3s_object_lock(input: &[u8]) -> S3sObjectLockObservation;
    /// Serializes an Object Lock value with the selected s3s persistence encoder.
    fn serialize_s3s_object_lock(value: &PersistedObjectLockConfiguration) -> Vec<u8>;
    /// Parses Bucket Encryption bytes with the selected s3s persistence decoder.
    fn parse_s3s_bucket_encryption(input: &[u8]) -> S3sBucketEncryptionObservation;
    /// Serializes a Bucket Encryption value with the selected s3s persistence encoder.
    fn serialize_s3s_bucket_encryption(value: &PersistedBucketEncryptionConfiguration) -> Vec<u8>;
    /// Parses CORS bytes with the selected s3s persistence decoder.
    fn parse_s3s_cors(input: &[u8]) -> S3sCorsObservation;
    /// Serializes CORS with the selected s3s persistence encoder.
    fn serialize_s3s_cors(value: &PersistedCorsConfiguration) -> Vec<u8>;
    /// Parses Public Access Block bytes with the selected s3s persistence decoder.
    fn parse_s3s_public_access_block(input: &[u8]) -> S3sPublicAccessBlockObservation;
    /// Serializes a Public Access Block value with the selected s3s persistence encoder.
    fn serialize_s3s_public_access_block(value: &PersistedPublicAccessBlockConfiguration) -> Vec<u8>;
    /// Parses Tagging bytes with the selected s3s persistence decoder.
    fn parse_s3s_tagging(input: &[u8]) -> S3sTaggingObservation;
    /// Serializes Tagging with the selected s3s persistence encoder.
    fn serialize_s3s_tagging(value: &PersistedTagging) -> Vec<u8>;
    /// Parses Bucket Logging bytes with the selected s3s persistence decoder.
    fn parse_s3s_bucket_logging(input: &[u8]) -> S3sBucketLoggingObservation;
    /// Serializes a Bucket Logging value with the selected s3s persistence encoder.
    fn serialize_s3s_bucket_logging(value: &PersistedBucketLoggingStatus) -> Vec<u8>;
    /// Parses Website bytes with the selected s3s persistence decoder.
    fn parse_s3s_website(input: &[u8]) -> S3sWebsiteObservation;
    /// Serializes a Website value with the selected s3s persistence encoder.
    fn serialize_s3s_website(value: &PersistedWebsiteConfiguration) -> Vec<u8>;
    /// Parses Accelerate bytes with the selected s3s persistence decoder.
    fn parse_s3s_accelerate(input: &[u8]) -> S3sAccelerateObservation;
    /// Serializes an Accelerate value with the selected s3s persistence encoder.
    fn serialize_s3s_accelerate(value: &PersistedAccelerateConfiguration) -> Vec<u8>;
    /// Parses Request Payment bytes with the selected s3s persistence decoder.
    fn parse_s3s_request_payment(input: &[u8]) -> S3sRequestPaymentObservation;
    /// Serializes a Request Payment value with the selected s3s persistence encoder.
    fn serialize_s3s_request_payment(value: &PersistedRequestPaymentConfiguration) -> Vec<u8>;
    /// Parses Lifecycle bytes with the selected s3s persistence decoder.
    fn parse_s3s_lifecycle(input: &[u8]) -> S3sLifecycleObservation;
    /// Serializes a Lifecycle value with the selected s3s persistence encoder.
    fn serialize_s3s_lifecycle(value: &PersistedLifecycleConfiguration) -> Vec<u8>;
    /// Parses Notification bytes with the selected s3s persistence decoder.
    fn parse_s3s_notification(input: &[u8]) -> S3sNotificationObservation;
    /// Serializes a Notification value with the selected s3s persistence encoder.
    fn serialize_s3s_notification(value: &PersistedNotificationConfiguration) -> Vec<u8>;
    /// Parses Replication bytes with the selected s3s persistence decoder.
    fn parse_s3s_replication(input: &[u8]) -> S3sReplicationObservation;
    /// Serializes a Replication value with the selected s3s persistence encoder.
    fn serialize_s3s_replication(value: &PersistedReplicationConfiguration) -> Vec<u8>;
}

#[cfg(test)]
mod tests;
