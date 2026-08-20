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

//! Hot configuration and immutable request snapshots. Responsible for: atomic replacement and snapshot lifetime.
//! NOT responsible for: applying policy inside pipeline stages.
//! Upstream: [`crate::ServiceBuilder`]. Downstream: [`crate::S3Service`].

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rustfs_gateway_core::HandlerDeadlineClass;

/// Default deadline for ordinary handler execution.
pub const DEFAULT_STANDARD_HANDLER_DEADLINE: Duration = Duration::from_secs(30);
/// Default deadline for operations whose declared work is legitimately longer.
pub const DEFAULT_EXTENDED_HANDLER_DEADLINE: Duration = Duration::from_secs(15 * 60);
const DEFAULT_HANDLER_CLEANUP_GRACE: Duration = Duration::from_secs(1);

/// How many keep-alive intervals may pass with no outcome before a committed response is ended.
///
/// The quantum is [`crate::commit::KEEPALIVE_INTERVAL_SECONDS`] rather than a number of seconds of
/// its own, because the two are the same clock seen from either side. That interval is how often a
/// committed response says "still working" to a client that has been told `200` and cannot see
/// anything else; this is how many of those a client may be told before the framework concludes
/// that nothing is working and stops saying it. A bound expressed in seconds would let the two
/// drift, and a deployment whose keep-alive cadence was slower than its own progress bound would
/// terminate every committed response before it ever wrote a second byte.
pub const KEEPALIVE_INTERVALS_WITHOUT_PROGRESS: u64 = 12;

/// Default bound on the time a committed continuation may go without producing its outcome.
///
/// A committed response has spent its status line: `200` is already on the wire and the only thing
/// left that can carry a verdict is the body. Nothing below the framework bounds how long that
/// takes — `crates/server`'s connection-idle deadline resets while a request is in flight, and its
/// write-progress deadline arms only when a write returns `Pending`, which a continuation that
/// writes nothing never does. So without this, a continuation that stops making progress holds the
/// request until the client's own timeout, and the retry that follows starts another one.
pub const DEFAULT_COMMIT_PROGRESS_DEADLINE: Duration =
    Duration::from_secs(crate::commit::KEEPALIVE_INTERVAL_SECONDS * KEEPALIVE_INTERVALS_WITHOUT_PROGRESS);

/// Validated durations for the closed handler deadline classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandlerDeadlineConfig {
    standard: Duration,
    extended: Duration,
    cleanup_grace: Duration,
    commit_progress: Duration,
}

impl HandlerDeadlineConfig {
    /// Validates explicit non-zero durations for both handler deadline classes.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerDeadlineConfigError`] when either duration is zero. Zero is never an
    /// alias for an unlimited handler execution.
    pub const fn new(standard: Duration, extended: Duration) -> Result<Self, HandlerDeadlineConfigError> {
        if standard.is_zero() {
            return Err(HandlerDeadlineConfigError::ZeroStandard);
        }
        if extended.is_zero() {
            return Err(HandlerDeadlineConfigError::ZeroExtended);
        }
        Ok(Self {
            standard,
            extended,
            cleanup_grace: DEFAULT_HANDLER_CLEANUP_GRACE,
            commit_progress: DEFAULT_COMMIT_PROGRESS_DEADLINE,
        })
    }

    /// Replaces the bounded cleanup grace after the framework signals a handler deadline.
    ///
    /// Returns `None` when `cleanup_grace` is zero.
    #[must_use]
    pub const fn try_with_cleanup_grace(mut self, cleanup_grace: Duration) -> Option<Self> {
        if cleanup_grace.is_zero() {
            return None;
        }
        self.cleanup_grace = cleanup_grace;
        Some(self)
    }

    /// Returns the bounded cleanup grace after a handler deadline is signalled.
    #[must_use]
    pub const fn cleanup_grace(self) -> Duration {
        self.cleanup_grace
    }

    /// Replaces the bound on time between progress inside a committed continuation.
    ///
    /// Returns `None` when `commit_progress` is zero, for the same reason as the two class
    /// durations: zero is never an alias for unlimited. A deployment that wanted no bound would be
    /// asking for the behaviour this value exists to remove.
    #[must_use]
    pub const fn try_with_commit_progress(mut self, commit_progress: Duration) -> Option<Self> {
        if commit_progress.is_zero() {
            return None;
        }
        self.commit_progress = commit_progress;
        Some(self)
    }

    /// Returns the bound on time between progress inside a committed continuation.
    #[must_use]
    pub const fn commit_progress(self) -> Duration {
        self.commit_progress
    }

    /// Returns the configured duration for one closed operation class.
    #[must_use]
    pub const fn duration_for(self, class: HandlerDeadlineClass) -> Duration {
        match class {
            HandlerDeadlineClass::Standard => self.standard,
            HandlerDeadlineClass::Extended => self.extended,
        }
    }
}

impl Default for HandlerDeadlineConfig {
    fn default() -> Self {
        Self {
            standard: DEFAULT_STANDARD_HANDLER_DEADLINE,
            extended: DEFAULT_EXTENDED_HANDLER_DEADLINE,
            cleanup_grace: DEFAULT_HANDLER_CLEANUP_GRACE,
            commit_progress: DEFAULT_COMMIT_PROGRESS_DEADLINE,
        }
    }
}

/// Why handler deadline configuration was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerDeadlineConfigError {
    /// The ordinary-operation deadline was zero.
    ZeroStandard,
    /// The extended-operation deadline was zero.
    ZeroExtended,
}

impl core::fmt::Display for HandlerDeadlineConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroStandard => f.write_str("standard handler deadline must be non-zero"),
            Self::ZeroExtended => f.write_str("extended handler deadline must be non-zero"),
        }
    }
}

impl std::error::Error for HandlerDeadlineConfigError {}

/// Replaceable request settings; no `Default` leaves the memory ceiling explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    max_buffered_body_bytes: u64,
    verbose_signature_errors: bool,
    handler_deadlines: HandlerDeadlineConfig,
}

impl ServiceConfig {
    /// Creates configuration with an explicit in-memory request-body ceiling.
    #[must_use]
    pub const fn new(max_buffered_body_bytes: u64) -> Self {
        Self {
            max_buffered_body_bytes,
            verbose_signature_errors: false,
            handler_deadlines: HandlerDeadlineConfig {
                standard: DEFAULT_STANDARD_HANDLER_DEADLINE,
                extended: DEFAULT_EXTENDED_HANDLER_DEADLINE,
                cleanup_grace: DEFAULT_HANDLER_CLEANUP_GRACE,
                commit_progress: DEFAULT_COMMIT_PROGRESS_DEADLINE,
            },
        }
    }

    /// The most wire-body bytes one request may retain in memory.
    #[must_use]
    pub const fn max_buffered_body_bytes(&self) -> u64 {
        self.max_buffered_body_bytes
    }
}

/// One request's immutable configuration.
pub type ConfigSnapshot = Arc<ServiceConfig>;

pub(crate) type ConfigStore = Arc<ArcSwap<ServiceConfig>>;

/// Replaces configuration between requests; in-flight requests retain their snapshot.
#[derive(Clone)]
pub struct ConfigHandle {
    store: ConfigStore,
}

impl ConfigHandle {
    pub(crate) fn new(store: &ConfigStore) -> Self {
        Self {
            store: Arc::clone(store),
        }
    }

    /// Replaces configuration for requests that have not started.
    pub fn store(&self, config: ServiceConfig) {
        self.store.store(Arc::new(config));
    }
}

impl core::fmt::Debug for ConfigHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigHandle").finish_non_exhaustive()
    }
}

impl ServiceConfig {
    /// Permits redacted mismatch details. Default: off.
    #[must_use]
    pub const fn with_verbose_signature_errors(mut self, enabled: bool) -> Self {
        self.verbose_signature_errors = enabled;
        self
    }

    /// Whether mismatch responses may carry redacted details.
    #[must_use]
    pub const fn verbose_signature_errors(&self) -> bool {
        self.verbose_signature_errors
    }

    /// Replaces both validated handler deadline durations.
    #[must_use]
    pub const fn with_handler_deadlines(mut self, handler_deadlines: HandlerDeadlineConfig) -> Self {
        self.handler_deadlines = handler_deadlines;
        self
    }

    /// Returns the duration mapped to an operation's closed handler deadline class.
    #[must_use]
    pub const fn handler_deadline(&self, class: HandlerDeadlineClass) -> Duration {
        self.handler_deadlines.duration_for(class)
    }

    /// Returns the bounded cleanup grace after a handler deadline is signalled.
    #[must_use]
    pub const fn handler_cleanup_grace(&self) -> Duration {
        self.handler_deadlines.cleanup_grace()
    }

    /// Returns the bound on time between progress inside a committed continuation.
    #[must_use]
    pub const fn commit_progress_deadline(&self) -> Duration {
        self.handler_deadlines.commit_progress()
    }
}

#[cfg(test)]
fn load_entry(store: &ConfigStore) -> ConfigSnapshot {
    store.load_full()
}

#[cfg(test)]
fn load_replacement(store: &ConfigStore) -> ConfigSnapshot {
    // A distinct helper keeps both allowlisted test loads explicit.
    // Production still performs its sole load at request entry.
    // The allowlist tracks these calls as guard fixtures.
    // Keeping both calls visible makes a second load detectable.

    store.load_full()
}

// Explicit loads let the guard detect new hot loads; production loads once at entry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_config::RequestConfig;
    use rustfs_gateway_core::HandlerDeadlineClass;

    #[test]
    fn handler_deadline_configuration_maps_each_closed_class() {
        let defaults = HandlerDeadlineConfig::default();
        assert_eq!(defaults.duration_for(HandlerDeadlineClass::Standard), std::time::Duration::from_secs(30));
        assert_eq!(
            defaults.duration_for(HandlerDeadlineClass::Extended),
            std::time::Duration::from_secs(15 * 60)
        );

        let configured = HandlerDeadlineConfig {
            standard: std::time::Duration::from_secs(3),
            extended: std::time::Duration::from_secs(90),
            cleanup_grace: DEFAULT_HANDLER_CLEANUP_GRACE,
            commit_progress: DEFAULT_COMMIT_PROGRESS_DEADLINE,
        };
        assert_eq!(
            HandlerDeadlineConfig::new(std::time::Duration::from_secs(3), std::time::Duration::from_secs(90)),
            Ok(configured),
        );
        let service = ServiceConfig::new(8).with_handler_deadlines(configured);
        assert_eq!(
            service.handler_deadline(HandlerDeadlineClass::Standard),
            std::time::Duration::from_secs(3)
        );
        assert_eq!(
            service.handler_deadline(HandlerDeadlineClass::Extended),
            std::time::Duration::from_secs(90)
        );
    }

    #[test]
    fn zero_standard_handler_deadline_is_refused() {
        assert_eq!(
            HandlerDeadlineConfig::new(std::time::Duration::ZERO, std::time::Duration::from_secs(1)),
            Err(HandlerDeadlineConfigError::ZeroStandard),
        );
    }

    #[test]
    fn zero_extended_handler_deadline_is_refused() {
        assert_eq!(
            HandlerDeadlineConfig::new(std::time::Duration::from_secs(1), std::time::Duration::ZERO),
            Err(HandlerDeadlineConfigError::ZeroExtended),
        );
    }

    #[test]
    fn handler_cleanup_grace_is_non_zero_and_configurable() {
        let defaults = HandlerDeadlineConfig::default();
        assert_eq!(defaults.cleanup_grace(), std::time::Duration::from_secs(1));

        let configured = defaults.try_with_cleanup_grace(std::time::Duration::from_millis(75));
        assert!(configured.is_some());
        let configured = configured.unwrap_or(defaults);
        assert_eq!(configured.cleanup_grace(), std::time::Duration::from_millis(75));
        assert_eq!(configured.try_with_cleanup_grace(std::time::Duration::ZERO), None,);

        let service = ServiceConfig::new(8).with_handler_deadlines(configured);
        assert_eq!(service.handler_cleanup_grace(), std::time::Duration::from_millis(75));
    }

    /// Positive — the shipped bound is the keep-alive cadence counted, and it reaches a service.
    ///
    /// Written as the product of the two published constants rather than as `60`, so a change to
    /// either is a change to the relationship: how often a client is told "still working" and how
    /// many times it may be told are the same question read from either end.
    #[test]
    fn the_commit_progress_bound_is_the_keepalive_cadence_counted() {
        assert_eq!(
            DEFAULT_COMMIT_PROGRESS_DEADLINE,
            Duration::from_secs(crate::commit::KEEPALIVE_INTERVAL_SECONDS * KEEPALIVE_INTERVALS_WITHOUT_PROGRESS)
        );
        assert_eq!(HandlerDeadlineConfig::default().commit_progress(), DEFAULT_COMMIT_PROGRESS_DEADLINE);
        assert_eq!(
            ServiceConfig::new(8).commit_progress_deadline(),
            DEFAULT_COMMIT_PROGRESS_DEADLINE,
            "a configuration built without naming the bound did not get the default"
        );
    }

    /// Negative — a replaced bound reaches the service, and zero is refused.
    ///
    /// Zero is not an alias for unlimited here any more than it is for the two class durations: a
    /// deployment that set it would be asking for exactly the behaviour the bound removes, and
    /// would get it silently.
    #[test]
    fn a_replaced_commit_progress_bound_reaches_the_service_and_zero_is_refused() {
        let replaced = HandlerDeadlineConfig::default().try_with_commit_progress(Duration::from_millis(250));
        assert!(replaced.is_some(), "a non-zero bound was refused");
        let configured = replaced.unwrap_or_default();
        assert_eq!(configured.commit_progress(), Duration::from_millis(250));
        assert_eq!(
            ServiceConfig::new(8)
                .with_handler_deadlines(configured)
                .commit_progress_deadline(),
            Duration::from_millis(250)
        );
        assert_eq!(HandlerDeadlineConfig::default().try_with_commit_progress(Duration::ZERO), None);
        // The other three durations are untouched by naming this one. A builder that reset them
        // would silently shorten every handler in the deployment.
        assert_eq!(configured.duration_for(HandlerDeadlineClass::Standard), DEFAULT_STANDARD_HANDLER_DEADLINE);
        assert_eq!(configured.duration_for(HandlerDeadlineClass::Extended), DEFAULT_EXTENDED_HANDLER_DEADLINE);
        assert_eq!(configured.cleanup_grace(), DEFAULT_HANDLER_CLEANUP_GRACE);
    }

    // a-asm-0006: stable load anchors prove replacement cannot split the entry snapshot.
    #[test]
    fn all_eight_pipeline_stages_share_one_arc() {
        let store = Arc::new(ArcSwap::from_pointee(ServiceConfig::new(8)));
        let handle = ConfigHandle::new(&store);
        let entry = load_entry(&store);
        let mut seen = Vec::new();

        let accepted = RequestConfig::enter(Arc::clone(&entry)).accepted();
        seen.push(Arc::clone(accepted.config()));
        let routed = accepted.routed();
        seen.push(Arc::clone(routed.config()));
        let governed = routed.governed();
        seen.push(Arc::clone(governed.config()));
        handle.store(ServiceConfig::new(16));
        let replacement = load_replacement(&store);
        assert!(!Arc::ptr_eq(&entry, &replacement), "the mid-request replacement did not happen");
        let authenticated = governed.authenticated();
        seen.push(Arc::clone(authenticated.config()));
        let route_authorized = authenticated.route_authorized();
        seen.push(Arc::clone(route_authorized.config()));
        let body_read = route_authorized.body_read();
        seen.push(Arc::clone(body_read.config()));
        let decoded = body_read.decoded();
        seen.push(Arc::clone(decoded.config()));
        let input_authorized = decoded.input_authorized();
        seen.push(Arc::clone(input_authorized.config()));

        assert_eq!(seen.len(), 8);
        for snapshot in seen {
            assert!(Arc::ptr_eq(&entry, &snapshot));
        }
    }
}
