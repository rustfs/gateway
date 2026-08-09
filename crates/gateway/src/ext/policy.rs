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

//! The one reading of policy a request is judged against.
//!
//! Responsible for: [`PolicySnapshot`] and its [`SnapshotId`], the [`PolicySource`] a deployment
//! installs to produce one, the refusal it may answer with ([`PolicyError`]), the default
//! [`NoPolicy`], and the closure adapter ADR-0002 requires ([`policy_from`]).
//! NOT responsible for: what a policy *is*. The payload is `dyn Any` and this crate never looks
//! inside it — evaluating a policy language is the deployment's, and the scope fence in
//! `README.md` says so. Nor for calling the source: `crate::service` does that, once.
//! Upstream: `rustfs-gateway-sig`'s [`Identity`]. Downstream: `crate::service`,
//! `crate::ext::authorizer`, `crate::ext::authz_audit`.
//!
//! # Why the snapshot exists at all
//!
//! An authorizer that loads policy itself loads it whenever it is called. Today this service calls
//! it once per request, so the difference is invisible; the moment a second reader appears — a
//! second authorisation stage over body-derived resources, a condition evaluator, an audit trail
//! that wants to say *which* policy was applied — the two readers can disagree, and the window
//! between them is a caller's opportunity to have a request judged half under the old rules and
//! half under the new ones. The snapshot closes that by construction: the framework takes one
//! reading, before the first reader, and every reader is handed the same `Arc`.
//!
//! `scripts/check_policy_snapshot_once.sh` is what keeps it one reading. A rule written only in
//! this paragraph is a rule the next stage to need policy will not know about.
//!
//! # Why a failure to read policy is not an error the caller sees
//!
//! [`PolicySource::snapshot`] returning `Err` becomes [`crate::Decision::Indeterminate`], which the
//! framework renders as `403`. It is deliberately not a `500`: a `5xx` is the status front ends
//! retry, and some of them are configured to fail open on one. rustfs's `GHSA-j548-9grx-fh4f` is
//! the same mistake one layer down — an unreadable bucket record read as "no Object Lock here",
//! and a retained object deleted.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::Identity;

/// The default hard limit for one policy read.
pub const DEFAULT_POLICY_SNAPSHOT_TIMEOUT: Duration = Duration::from_millis(250);
/// The largest policy-read timeout this facade permits.
pub const MAX_POLICY_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

/// A non-zero, bounded policy-read timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTimeout(Duration);

impl PolicyTimeout {
    /// Validates a timeout before it reaches the request path.
    ///
    /// # Errors
    ///
    /// [`PolicyTimeoutError`] when `timeout` is zero or above
    /// [`MAX_POLICY_SNAPSHOT_TIMEOUT`].
    pub const fn new(timeout: Duration) -> Result<Self, PolicyTimeoutError> {
        if timeout.is_zero()
            || timeout.as_secs() > MAX_POLICY_SNAPSHOT_TIMEOUT.as_secs()
            || (timeout.as_secs() == MAX_POLICY_SNAPSHOT_TIMEOUT.as_secs() && timeout.subsec_nanos() > 0)
        {
            return Err(PolicyTimeoutError);
        }
        Ok(Self(timeout))
    }

    /// The validated duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// # Security
///
/// The default bounds a policy-store stall; it never turns an unavailable policy into allow.
impl Default for PolicyTimeout {
    fn default() -> Self {
        Self(DEFAULT_POLICY_SNAPSHOT_TIMEOUT)
    }
}

/// A policy timeout was zero or exceeded the hard upper bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTimeoutError;

impl core::fmt::Display for PolicyTimeoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("policy timeout must be non-zero and at most five seconds")
    }
}

impl std::error::Error for PolicyTimeoutError {}

/// Names one reading of policy.
///
/// Minted by the framework, never by a source, and never reused: two requests never share one,
/// which is what makes "these two readers saw the same policy" an assertion with content rather
/// than a comparison of two constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId(u64);

impl SnapshotId {
    /// The number this reading was given. Monotonic within a process, and meaningful only as an
    /// identity — it is not a version, a generation, or an ordering over policy content.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The counter [`SnapshotId`]s come from. One process, one sequence.
static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

/// One reading of whatever a deployment calls policy.
///
/// The payload is opaque: this crate stores it, hands it to the [`crate::Authorizer`], and never
/// reads it. [`PolicySnapshot::get`] is how the deployment gets its own type back.
///
/// Cloning is one refcount bump, so handing the same reading to several readers costs nothing and
/// — more to the point — cannot accidentally become two readings.
#[derive(Clone)]
pub struct PolicySnapshot {
    id: SnapshotId,
    payload: Option<Arc<dyn Any + Send + Sync>>,
}

impl PolicySnapshot {
    /// A reading carrying the deployment's own value.
    #[must_use]
    pub fn of(payload: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            id: SnapshotId(NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed)),
            payload: Some(payload),
        }
    }

    /// A reading carrying nothing, which is what [`NoPolicy`] answers with.
    ///
    /// An empty snapshot is still a snapshot: it has its own identifier, so a deployment that has
    /// installed no source still gets the "one reading per request" property and an audit trail
    /// that can join two events to one decision.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            id: SnapshotId(NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed)),
            payload: None,
        }
    }

    /// Which reading this is.
    #[must_use]
    pub const fn id(&self) -> SnapshotId {
        self.id
    }

    /// The deployment's own value, when the payload really is a `T`.
    ///
    /// `None` for an empty snapshot and for a payload of another type. There is no panicking
    /// variant: a downcast that fails is a misassembled deployment, and an authorizer that cannot
    /// read its own policy must answer [`crate::Decision::Indeterminate`] rather than abort the
    /// process.
    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.payload.as_ref()?.downcast_ref::<T>()
    }

    /// Whether this reading carries anything at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_none()
    }
}

impl core::fmt::Debug for PolicySnapshot {
    /// Prints the identifier and whether there is a payload, and **never the payload**.
    ///
    /// A policy document is the one value in an authorisation decision most likely to contain
    /// principal ARNs, condition keys and, in a badly designed store, credentials. This type is
    /// reachable from an audit event, and an audit event is the value most likely to be formatted
    /// straight into a log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicySnapshot")
            .field("id", &self.id)
            .field("empty", &self.payload.is_none())
            .finish()
    }
}

/// Why a [`PolicySource`] could not produce a reading.
///
/// Carries a constant label and nothing derived from the request. It never reaches a caller — the
/// framework turns it into [`crate::Decision::Indeterminate`] and answers `403 AccessDenied` — so
/// the label exists for the deployment's own logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyError {
    reason: &'static str,
}

impl PolicyError {
    /// The store could not be reached, or did not answer in time.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { reason: "unavailable" }
    }

    /// The store answered with something this deployment could not parse.
    #[must_use]
    pub const fn malformed() -> Self {
        Self { reason: "malformed" }
    }

    /// A reason of the deployment's own choosing. `&'static str` on purpose: a formatted string
    /// is where a bucket name, a key or a principal would get in.
    #[must_use]
    pub const fn because(reason: &'static str) -> Self {
        Self { reason }
    }

    /// The label, for a log line.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "policy could not be read: {}", self.reason)
    }
}

impl std::error::Error for PolicyError {}

/// Produces the one reading of policy a request is judged against.
///
/// Held as `Arc<dyn PolicySource>`, so the method is a hand-written [`BoxFuture`] (ADR-0002).
///
/// **The framework calls this exactly once per request**, after the caller's identity is known and
/// before the [`crate::Authorizer`] is asked anything. An implementation may therefore assume it is
/// not competing with a second reading of itself inside one request, and must not assume anything
/// about how many readers the resulting snapshot has.
pub trait PolicySource: Send + Sync + 'static {
    /// Reads policy for one identity. `None` is an anonymous caller, which is a caller like any
    /// other: it has a policy, and that policy is usually "almost nothing".
    fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>>;
}

impl<T: PolicySource + ?Sized> PolicySource for Arc<T> {
    fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        (**self).snapshot(identity)
    }
}

/// The default: every request is judged against an empty reading.
///
/// Safe in the only sense that matters here — it cannot widen access, because it grants nothing and
/// an [`crate::Authorizer`] that finds nothing in it has to decide without it. A deployment whose
/// authorizer loads its own policy needs no source; one whose authorizer expects a payload and
/// finds none is a misassembly its own code sees, not one this crate can detect.
pub struct NoPolicy;

impl PolicySource for NoPolicy {
    fn snapshot<'a>(&'a self, _identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        Box::pin(async { Ok(PolicySnapshot::empty()) })
    }
}

/// The closure adapter for [`PolicySource`].
///
/// ADR-0002 makes shipping one a completion condition of every `BoxFuture` extension point. The
/// closure is synchronous for the reason [`crate::allow_when`]'s is: a source that has to await is
/// a source whose caching and whose failure modes a reviewer must be able to find, and that
/// deserves a named type.
#[must_use]
pub fn policy_from<F>(read: F) -> impl PolicySource
where
    F: Fn(Option<&Identity>) -> Result<PolicySnapshot, PolicyError> + Send + Sync + 'static,
{
    struct FnSource<F>(F);

    impl<F> PolicySource for FnSource<F>
    where
        F: Fn(Option<&Identity>) -> Result<PolicySnapshot, PolicyError> + Send + Sync + 'static,
    {
        fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
            let outcome = (self.0)(identity);
            Box::pin(async move { outcome })
        }
    }

    FnSource(read)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — two readings are two identifiers, including two empty ones. Without this every
    /// "the two readers saw one snapshot" assertion in the suite would be comparing constants.
    #[test]
    fn n_no_two_snapshots_share_an_identifier() {
        let first = PolicySnapshot::empty();
        let second = PolicySnapshot::empty();
        let third = PolicySnapshot::of(Arc::new(7_u32));
        assert_ne!(first.id(), second.id());
        assert_ne!(second.id(), third.id());
    }

    /// Positive — a clone is the same reading, which is what lets one snapshot reach several
    /// readers without becoming two.
    #[test]
    fn p_a_clone_is_the_same_reading() {
        let snapshot = PolicySnapshot::of(Arc::new(String::from("document")));
        assert_eq!(snapshot.clone().id(), snapshot.id());
        assert_eq!(snapshot.get::<String>().map(String::as_str), Some("document"));
    }

    /// Negative — the payload never appears in the debug rendering, and neither does anything else
    /// about it beyond whether it is there.
    #[test]
    fn n_the_debug_rendering_holds_no_policy_text() {
        let snapshot = PolicySnapshot::of(Arc::new(String::from("Allow s3:* on arn:aws:s3:::secrets/*")));
        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains("arn:aws"), "{rendered}");
        assert!(!rendered.contains("Allow"), "{rendered}");
        assert!(rendered.contains("empty: false"), "{rendered}");
    }

    /// Negative — a payload of the wrong type is `None` rather than a panic, and an empty snapshot
    /// is `None` for every type.
    #[test]
    fn n_a_wrong_downcast_is_absence_and_not_a_panic() {
        let snapshot = PolicySnapshot::of(Arc::new(7_u32));
        assert_eq!(snapshot.get::<u32>(), Some(&7));
        assert_eq!(snapshot.get::<String>(), None);
        assert_eq!(PolicySnapshot::empty().get::<u32>(), None);
        assert!(PolicySnapshot::empty().is_empty());
        assert!(!snapshot.is_empty());
    }

    /// Negative — a policy failure renders a constant label and nothing a caller supplied.
    #[test]
    fn n_a_policy_failure_says_nothing_about_the_request() {
        let error = PolicyError::unavailable();
        assert_eq!(error.reason(), "unavailable");
        assert_eq!(error.to_string(), "policy could not be read: unavailable");
        assert_ne!(PolicyError::unavailable(), PolicyError::malformed());
        assert_eq!(PolicyError::because("throttled").reason(), "throttled");
    }

    /// Positive — the default source answers an empty reading, and the closure adapter reaches
    /// both a reading and a refusal.
    #[tokio::test]
    async fn p_the_default_and_the_adapter_both_answer() {
        assert!(NoPolicy.snapshot(None).await.expect("the default never fails").is_empty());
        let ok = policy_from(|_| Ok(PolicySnapshot::of(Arc::new(1_u8))));
        assert_eq!(ok.snapshot(None).await.expect("a reading").get::<u8>(), Some(&1));
        let bad = policy_from(|_| Err(PolicyError::malformed()));
        assert_eq!(bad.snapshot(None).await.expect_err("a refusal"), PolicyError::malformed());
    }
}
