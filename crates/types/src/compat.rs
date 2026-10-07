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

//! Temporary adapters to the pinned s3s revisions: the persistence oracles migration admission is
//! measured against, and the migration seam the RustFS ring-2 adapter converts through.
//!
//! Responsible for: invoking the exact old persistence codecs of every pinned s3s revision,
//! selecting which revision answers, and exposing family-scoped adapters over owned values (feature
//! `compat-s3s`); and the migration seam — the generated conversions of every covered operation
//! in both directions, the hand-written ones (`put_object`, `get_bucket_location`), the error seam
//! and the request-context conversion (`request_context`) — compiled once per seam revision:
//! `s3s_5761ddfe`, the revision RustFS main links (feature `compat-s3s-rustfs`,
//! rustfs/backlog#2759); `s3s_0_17_0`, the release it linked at 528a3681, which the goldens and
//! difftest measure (feature `compat-s3s-0-17-0`); and `s3s_9c4690d8`, the baseline oracle the
//! goldens also measure (feature `compat-s3s`). The seam modules are the only ones whose API names
//! s3s types, and each exists only under its own feature, so none of them is an intra-doc link.
//! NOT responsible for: production XML behavior, golden assertions, or the RustFS side of any
//! conversion (its extensions, its hooks, its call order).
//! Upstream: the three s3s revisions named by [`OracleRevision`](crate::compat::OracleRevision).
//! Downstream: `rustfs-gateway-goldens`; the RustFS ring-2 adapter (rustfs/backlog#1752). This
//! module is deleted by P9-09.
//!
//! # One seam source, one compilation per revision
//!
//! `compat/seam/*.rs` names s3s only as `super::s3s`, and the generated tree only as
//! `super::super::s3s`, so each seam module below binds its own revision and the same source —
//! hand-written and generated alike — compiles against it. `5761ddfe` is `0.17.0`'s DTO and error
//! tables exactly. The shapes the seam touches are identical in `9c4690d8` and `0.17.0` but for
//! one member: `PutObjectInput.expires` is a parsed `Timestamp` in `9c4690d8` and the wire text in
//! `0.17.0`. That difference is the `expires` and `expires_text` hooks each seam module defines,
//! as `encryption_rule` is for the oracles; the file is never copied.
//!
//! # One adapter source, three compilations
//!
//! Only under `compat-s3s`: `compat/oracle/*.rs` is compiled once per revision as
//! the `baseline`, `rollback` and `candidate` modules below, each binding its own `s3s`. The public
//! functions dispatch on the revision [`with_oracle`](crate::compat::with_oracle) selected for the
//! current thread. The default is
//! [`OracleRevision::Baseline`](crate::compat::OracleRevision::Baseline), so a caller that never
//! selects one measures exactly what it measured before the other revisions existed.
//!
//! These links spell the full path because rustdoc joins this inner doc with the outer `///` doc
//! on `pub mod compat` in `lib.rs` and resolves the joined text from the crate root.

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

/// The migration seam against s3s `0.17.0`, the release RustFS `main` linked at 528a3681
/// (`OracleRevision::Candidate`): what the goldens decode, encode and context diffs and the
/// difftest runners measure a second time.
#[cfg(feature = "compat-s3s-0-17-0")]
#[path = "compat/seam"]
pub mod s3s_0_17_0 {
    /// The s3s revision every signature in this module names. Kernel crates other than this one
    /// may not depend on s3s at all (`scripts/check_ring_boundaries.sh`), so this is the one route
    /// a harness takes to it.
    pub use ::s3s_candidate as s3s;

    pub mod error;
    /// Every covered operation's conversions both ways, the member and error-code census, and the
    /// test-only fixtures, generated from the IR against the s3s 0.17.0 facts (rustfs/gateway#967)
    /// and converting against this module's `s3s` and `leaf`. Not formatted by hand: the
    /// generator's output is what is reviewed. Its `#[path]` goes through the
    /// `crates/types/generated` symlink like every other generated file (ADR-0005).
    #[rustfmt::skip]
    #[path = "../../../generated/seam/mod.rs"]
    pub mod generated;
    #[cfg(test)]
    mod census_tests;
    #[cfg(test)]
    mod generated_tests;
    pub mod get_bucket_location;
    pub mod leaf;
    pub mod put_object;
    pub mod request_context;
    #[cfg(test)]
    mod reverse_tests;
    pub mod trailers;
    #[cfg(test)]
    mod trailers_tests;

    /// `0.17.0` fills a message from the code's default sentence when a body names none, so the
    /// gateway writes the sentence the s3s document would have carried.
    fn default_message(code: &s3s::S3ErrorCode) -> Option<&'static str> {
        code.default_message()
    }

    /// `0.17.0` holds `PutObjectInput.expires` as the wire text, exactly as the gateway keeps it
    /// (`q-timestamp-0005`), so every value crosses unchanged and nothing is refused.
    #[allow(clippy::unnecessary_wraps)] // The signature is the one every revision's hook shares.
    fn expires(value: &str) -> Result<s3s::dto::Expires, super::ConversionError> {
        Ok(value.to_owned())
    }

    /// The reverse of `expires`: the wire text, unchanged.
    #[allow(clippy::unnecessary_wraps)] // The signature is the one every revision's hook shares.
    fn expires_text(value: &s3s::dto::Expires) -> Result<String, super::ConversionError> {
        Ok(value.clone())
    }
}

/// The migration seam against s3s-project/s3s@5761ddfe, the revision RustFS `main` links today
/// (rustfs/rustfs@6b155400): what `impl s3s::S3 for FS` converts through while its use cases are
/// ported to gateway types (rustfs/backlog#2749), and what the RustFS ring-2 adapter converts
/// through after the flip (rustfs/backlog#2759).
///
/// Its `s3s` is the crate RustFS itself names, unified by Cargo because this crate declares it
/// with the same source and revision, so the converted values are the ones `impl s3s::S3 for FS`
/// takes. The revision is s3s `0.17.0` plus fixes outside the DTO and error tables, so the seam
/// source and the generated tree are the ones `s3s_0_17_0` compiles, compiled once more.
#[cfg(feature = "compat-s3s-rustfs")]
#[path = "compat/seam"]
#[allow(clippy::duplicate_mod)] // Deliberate: one seam source is compiled once per revision.
pub mod s3s_5761ddfe {
    /// The s3s revision every signature in this module names: RustFS main's own.
    pub use ::s3s_rustfs as s3s;

    pub mod error;
    /// As `s3s_0_17_0::generated`, compiled against this module's `s3s`.
    #[rustfmt::skip]
    #[path = "../../../generated/seam/mod.rs"]
    pub mod generated;
    #[cfg(test)]
    mod census_tests;
    #[cfg(test)]
    mod generated_tests;
    pub mod get_bucket_location;
    pub mod leaf;
    pub mod put_object;
    pub mod request_context;
    #[cfg(test)]
    mod reverse_tests;
    pub mod trailers;
    #[cfg(test)]
    mod trailers_tests;

    /// `5761ddfe` fills a message from the code's default sentence when a body names none, as
    /// `0.17.0` does.
    fn default_message(code: &s3s::S3ErrorCode) -> Option<&'static str> {
        code.default_message()
    }

    /// `5761ddfe` holds `PutObjectInput.expires` as the wire text, as `0.17.0` does.
    #[allow(clippy::unnecessary_wraps)] // The signature is the one every revision's hook shares.
    fn expires(value: &str) -> Result<s3s::dto::Expires, super::ConversionError> {
        Ok(value.to_owned())
    }

    /// The reverse of `expires`: the wire text, unchanged.
    #[allow(clippy::unnecessary_wraps)] // The signature is the one every revision's hook shares.
    fn expires_text(value: &s3s::dto::Expires) -> Result<String, super::ConversionError> {
        Ok(value.clone())
    }
}

/// The migration seam against the baseline oracle s3s `9c4690d8` (`OracleRevision::Baseline`),
/// the revision every existing golden decode, encode and context proof was first measured
/// against. Evidence only: no RustFS build that could adopt the gateway links it.
#[cfg(feature = "compat-s3s")]
#[path = "compat/seam"]
#[allow(clippy::duplicate_mod)] // Deliberate: one seam source is compiled once per revision.
pub mod s3s_9c4690d8 {
    /// The s3s revision every signature in this module names.
    pub use ::s3s_baseline as s3s;

    pub mod error;
    pub mod get_bucket_location;
    pub mod put_object;
    pub mod request_context;
    pub mod trailers;

    /// `9c4690d8` has no default sentences: a body that names no message gets a document with no
    /// `<Message>`, and the gateway writes an empty one.
    #[allow(clippy::unnecessary_wraps)] // The signature is the one both revisions' hooks share.
    const fn default_message(_code: &s3s::S3ErrorCode) -> Option<&'static str> {
        None
    }

    /// `9c4690d8` holds `PutObjectInput.expires` parsed as an HTTP-date, so the gateway's opaque
    /// text is refused by member name when it is not one (rd-put-0004).
    fn expires(value: &str) -> Result<s3s::dto::Expires, super::ConversionError> {
        s3s::dto::Timestamp::parse(s3s::dto::TimestampFormat::HttpDate, value).map_err(|_| super::ConversionError {
            field: "expires",
            reason: "not an HTTP-date, and the s3s input holds this member parsed",
        })
    }

    /// The reverse of `expires`: the parsed instant spelled as the HTTP-date the legacy decoder
    /// read, refused by member name when it has none.
    fn expires_text(value: &s3s::dto::Expires) -> Result<String, super::ConversionError> {
        let mut spelled = Vec::new();
        value
            .format(s3s::dto::TimestampFormat::HttpDate, &mut spelled)
            .map_err(|_| super::ConversionError {
                field: "expires",
                reason: "an instant that has no HTTP-date spelling",
            })?;
        String::from_utf8(spelled).map_err(|_| super::ConversionError {
            field: "expires",
            reason: "an instant spelled outside ASCII",
        })
    }
}

/// A value the target shape of a seam conversion cannot hold.
///
/// Carries the member and a fixed reason, never the value: one of the members is an SSE-C key, and
/// another the caller's secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionError {
    /// The member, named as on the side that could not represent it.
    pub field: &'static str,
    /// Why the value does not fit.
    pub reason: &'static str,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ConversionError {}

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

    /// Git repository the revision is fetched from, exactly as this crate's manifest names it, or
    /// `None` for a crates.io release.
    #[must_use]
    pub const fn repository(self) -> Option<&'static str> {
        match self {
            Self::Baseline | Self::Rollback => Some("https://github.com/rustfs/s3s.git"),
            Self::Candidate => None,
        }
    }

    /// What this crate's manifest pins for the revision: the full s3s commit (`rev`) of a git
    /// revision, or the `version` of a crates.io release.
    #[must_use]
    pub const fn revision(self) -> &'static str {
        match self {
            Self::Baseline => "9c4690d8e73fc8d184031a19b2c4539ebc77d180",
            Self::Rollback => "bdcb6259339c41369f9f1c60e3a42b5ab8da607b",
            Self::Candidate => "0.17.0",
        }
    }

    /// The RustFS build whose `Cargo.lock` pins this revision.
    #[must_use]
    pub const fn rustfs_build(self) -> &'static str {
        match self {
            Self::Baseline => "rustfs/rustfs@436a1be899e90e67d7c4aa81def70d39fe1748d5 (1.0.0-rc.5-preview.2)",
            Self::Rollback => "rustfs/rustfs@5cd58319ed6148ed7f09f2a4d0b4e46e429f043a (1.0.0-rc.6)",
            Self::Candidate => "rustfs/rustfs@528a368144a6543adccfa7ca5e6dce570f0d9a19 (main)",
        }
    }
}

impl fmt::Display for OracleRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A git commit is shortened to eight characters; a release version is already short.
        let short = match self.repository() {
            Some(_) => self.revision().get(..8).unwrap_or(self.revision()),
            None => self.revision(),
        };
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
///
/// `Debug` is written by hand so the KMS key id in `behavior` is redacted like the one in
/// `structure`; the goldens render this observation with `{:?}` when an old parse succeeds.
#[derive(Clone, Eq, PartialEq)]
pub struct S3sBucketEncryptionObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedBucketEncryptionConfiguration,
    /// Runtime-relevant algorithm, KMS key, bucket-key and blocked-type decisions per stored rule.
    pub behavior: Vec<crate::persistence::EncryptionRuleBehavior>,
}

impl fmt::Debug for S3sBucketEncryptionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let behavior: Vec<_> = self
            .behavior
            .iter()
            .map(crate::persistence::RedactedEncryptionRuleBehavior)
            .collect();
        formatter
            .debug_struct("S3sBucketEncryptionObservation")
            .field("structure", &self.structure)
            .field("behavior", &behavior)
            .finish()
    }
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
}

#[cfg(feature = "compat-s3s")]
impl CompatCodecError {
    fn old_codec(error: impl fmt::Display) -> Self {
        Self {
            message: format!("pinned s3s persistence codec failed: {error}"),
        }
    }

    /// The selected revision's DTO has no field for a persisted member the value carries, so its
    /// writer cannot produce those bytes. Refused rather than written without the member.
    fn unwritable(member: &'static str) -> Self {
        Self {
            message: format!("pinned s3s revision has no {member} member to write"),
        }
    }
}

impl fmt::Display for CompatCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CompatCodecError {}

/// s3s `9c4690d8`, whose `ServerSideEncryptionRule` has no `BlockedEncryptionTypes` member.
#[cfg(feature = "compat-s3s")]
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

    /// This revision has no `BlockedEncryptionTypes` field, so a value carrying one cannot be
    /// written by it; refusing keeps a D2/D3 measurement from passing on bytes without the block.
    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        blocked: Option<Vec<String>>,
        bucket_key_enabled: Option<bool>,
    ) -> Result<ServerSideEncryptionRule, super::CompatCodecError> {
        if blocked.is_some() {
            return Err(super::CompatCodecError::unwritable("BlockedEncryptionTypes"));
        }
        Ok(ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            bucket_key_enabled,
        })
    }

    fn split_encryption_rule(rule: ServerSideEncryptionRule) -> EncryptionRuleParts {
        let ServerSideEncryptionRule {
            apply_server_side_encryption_by_default,
            bucket_key_enabled,
        } = rule;
        (apply_server_side_encryption_by_default, None, bucket_key_enabled)
    }

    type EncryptionRuleParts = (Option<ServerSideEncryptionByDefault>, Option<Vec<String>>, Option<bool>);
}

/// s3s `bdcb6259`. Its `ServerSideEncryptionRule` gained `BlockedEncryptionTypes`, carried by the
/// persisted structure since rustfs/gateway#740.
#[cfg(feature = "compat-s3s")]
#[path = "compat/oracle"]
#[allow(clippy::duplicate_mod)] // Deliberate: one adapter source is compiled once per pinned revision.
mod rollback {
    use ::s3s_rollback as s3s;
    use s3s::dto::{BlockedEncryptionTypes, EncryptionType, ServerSideEncryptionByDefault, ServerSideEncryptionRule};

    mod accelerate_payment;
    mod bucket_configs;
    mod lifecycle;
    mod notification;
    mod replication;

    pub(super) use self::{accelerate_payment::*, bucket_configs::*, lifecycle::*, notification::*, replication::*};

    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        blocked: Option<Vec<String>>,
        bucket_key_enabled: Option<bool>,
    ) -> Result<ServerSideEncryptionRule, super::CompatCodecError> {
        Ok(ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            blocked_encryption_types: blocked.map(|entries| BlockedEncryptionTypes {
                encryption_type: (!entries.is_empty()).then(|| entries.into_iter().map(EncryptionType::from).collect()),
            }),
            bucket_key_enabled,
        })
    }

    fn split_encryption_rule(rule: ServerSideEncryptionRule) -> EncryptionRuleParts {
        let ServerSideEncryptionRule {
            apply_server_side_encryption_by_default,
            blocked_encryption_types,
            bucket_key_enabled,
        } = rule;
        let blocked = blocked_encryption_types.map(|BlockedEncryptionTypes { encryption_type }| {
            encryption_type
                .unwrap_or_default()
                .iter()
                .map(|entry| entry.as_str().to_owned())
                .collect()
        });
        (apply_server_side_encryption_by_default, blocked, bucket_key_enabled)
    }

    type EncryptionRuleParts = (Option<ServerSideEncryptionByDefault>, Option<Vec<String>>, Option<bool>);
}

/// s3s `0.17.0`, with the same `BlockedEncryptionTypes` member as the rollback revision.
#[cfg(feature = "compat-s3s")]
#[path = "compat/oracle"]
#[allow(clippy::duplicate_mod)] // Deliberate: one adapter source is compiled once per pinned revision.
mod candidate {
    use ::s3s_candidate as s3s;
    use s3s::dto::{BlockedEncryptionTypes, EncryptionType, ServerSideEncryptionByDefault, ServerSideEncryptionRule};

    mod accelerate_payment;
    mod bucket_configs;
    mod lifecycle;
    mod notification;
    mod replication;

    pub(super) use self::{accelerate_payment::*, bucket_configs::*, lifecycle::*, notification::*, replication::*};

    fn encryption_rule(
        apply: Option<ServerSideEncryptionByDefault>,
        blocked: Option<Vec<String>>,
        bucket_key_enabled: Option<bool>,
    ) -> Result<ServerSideEncryptionRule, super::CompatCodecError> {
        Ok(ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: apply,
            blocked_encryption_types: blocked.map(|entries| BlockedEncryptionTypes {
                encryption_type: (!entries.is_empty()).then(|| entries.into_iter().map(EncryptionType::from).collect()),
            }),
            bucket_key_enabled,
        })
    }

    fn split_encryption_rule(rule: ServerSideEncryptionRule) -> EncryptionRuleParts {
        let ServerSideEncryptionRule {
            apply_server_side_encryption_by_default,
            blocked_encryption_types,
            bucket_key_enabled,
        } = rule;
        let blocked = blocked_encryption_types.map(|BlockedEncryptionTypes { encryption_type }| {
            encryption_type
                .unwrap_or_default()
                .iter()
                .map(|entry| entry.as_str().to_owned())
                .collect()
        });
        (apply_server_side_encryption_by_default, blocked, bucket_key_enabled)
    }

    type EncryptionRuleParts = (Option<ServerSideEncryptionByDefault>, Option<Vec<String>>, Option<bool>);
}

/// Declares each public adapter once and routes it to the selected revision's compilation. The
/// function names stay literal here so `grep parse_s3s_versioning` still finds the definition.
#[cfg(feature = "compat-s3s")]
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

#[cfg(feature = "compat-s3s")]
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

#[cfg(all(test, feature = "compat-s3s-rustfs"))]
mod rustfs_tests;
#[cfg(all(test, feature = "compat-s3s"))]
mod tests;
