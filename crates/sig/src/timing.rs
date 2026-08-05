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

//! The side-channel register, and the primitives that close the ones this crate owns.
//!
//! Responsible for: the enumerated register of authentication side channels ([`SIDE_CHANNELS`])
//! with a disposition for every entry, the uniform failure latency floor ([`FailureFloor`]), the
//! placeholder credential that keeps the unknown-access-key path doing the same work as the known
//! one ([`placeholder_secret`]), and the credential-lookup contract ([`LookupBudget`],
//! [`CredentialLookup`]) that keeps an unauthenticated request from becoming an amplifier.
//! NOT responsible for: HMAC derivation (P2-03 owns the four-step chain and is the caller that
//! must run it for unknown keys too), rate limiting (the `Governor` extension point), policy
//! evaluation (`rustfs-gateway-core`), or sleeping — [`FailureFloor`] returns the delay to wait and never
//! blocks, because a blocking sleep inside an async server converts a timing defence into a
//! denial-of-service lever.
//! Upstream: [`crate::SecretBytes`]. Downstream: P2-03's verifier, P2-04's authentication stage,
//! and P6-08's governor.
//!
//! # Deployment note that outranks everything else in this module
//!
//! **Never run a debug build of this crate in production.** `subtle`'s invariant checks are
//! `debug_assert!`s over values derived from secrets; they exist only in debug builds, and they
//! branch on secret-dependent conditions. A debug build therefore has secret-dependent control
//! flow no amount of care in this crate can remove. `subtle`'s own barriers are `read_volatile`
//! based and documented as best-effort, so even a release build is a strong mitigation rather than
//! a proof.
//!
//! # The register
//!
//! Ten channels, each with one of three dispositions: closed here, deferred to a named task with
//! the interface constrained here, or accepted with the reason recorded. The list is data rather
//! than prose so that a test can assert every entry still has an owner.
//!
//! | # | Channel | Disposition |
//! |---|---|---|
//! | T1 | Access key lookup returns before any HMAC runs, so an unknown key answers faster than a known one — access key enumeration without ever knowing a secret, which is step one of CVE-2025-31489 | Closed by contract: the unknown-key path signs with [`placeholder_secret`] and runs the full four-step derivation and comparison, then answers `InvalidAccessKeyId`. The error codes stay distinct because S3 clients branch on them; latency parity plus rate limiting is the mitigation, error-code normalisation is not |
//! | T2 | The credential provider is a remote async call on the *unauthenticated* path: cache hit and miss differ in latency, and every forged request costs one IAM or database round trip | Closed by contract: [`LookupBudget`] fixes a hard timeout and a jittered negative-cache TTL, so a miss neither hangs nor becomes an amplifier. Per-IP quota is `Governor` (P6-08) |
//! | T3 | A derived-signing-key cache keyed on `(secret, date, region, service)` leaks, on a hit, that this access key was used recently — and keeps secret-equivalent material alive past the request | Closed by omission: this crate implements no such cache. If one is ever added it must be opt-in, TTL-bounded, and zeroized on eviction, and the trade-off documented at the type |
//! | T4 | Bucket existence: authentication that resolves the bucket before verifying answers faster for a bucket that does not exist, turning an unauthenticated probe into a namespace oracle | Deferred to P2-04 with the interface constrained here: a [`Verdict`](crate::Verdict) is computed from the request and its credentials alone. Nothing in this crate accepts a bucket, so the authentication stage cannot depend on one |
//! | T5 | Policy evaluation time varies with statement count and match position, leaking policy shape and whether a principal matched | Accepted risk, recorded: it lives in `rustfs-gateway-core`'s authorization stage, after authentication has already succeeded, so it is reachable only by a caller holding valid credentials |
//! | T6 | The rejection ladder — a malformed header fails in microseconds, a bad signature in tens of microseconds, a policy denial in milliseconds — tells an attacker how far the forgery got, which turns forging into a field-by-field binary search | Closed here: [`FailureFloor`] holds every authentication failure to one configurable minimum, non-zero by default |
//! | T7 | SigV2's HMAC-SHA1 guarantees a second signature type exists, and the second type is the one somebody gives a derived `PartialEq` | Closed by P2-01's [`Signature`](crate::Signature) enum over `CtBytes<N>`, plus `scripts/check_ct_eq.sh` so it cannot come back |
//! | T8 | `Choice` misuse: `a.ct_eq(&b).into() && other()` reintroduces a branch, because `&&` short-circuits | Closed by construction plus guard: `bool::from` appears exactly once in this crate, inside `Signature::ct_verify`, and `scripts/check_ct_eq.sh` counts it |
//! | T9 | All four SigV4 derivation steps are secret-equivalent; an intermediate left in a `Vec<u8>` or a `String` survives on the heap | Closed here: [`SigningKey`](crate::SigningKey) wraps every step in a once-allocated `Box<[u8]>` and zeroizes on drop, and the guard rejects `Vec<u8>`/`String` bindings named after key material |
//! | T10 | Lenient base64 and hex decoding maps two spellings onto one value, which is a comparison-bypass surface | Closed by P2-01's [`codec`](crate::codec): length-exact, alphabet-exact, padding-exact, canonical-bits-exact, and it rejects rather than truncates |

use core::fmt;
use core::time::Duration;

use crate::secret::SecretBytes;

/// What was done about a side channel.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// Closed by something in this crate: a type shape, a primitive, or a source guard.
    ClosedHere,
    /// Not closed here, but the interface in this crate makes the mistake unavailable to the
    /// named task. The string is the task or extension point that owns the remainder.
    DeferredTo(&'static str),
    /// Deliberately not mitigated. The string is the reason it is tolerable.
    AcceptedRisk(&'static str),
}

/// One entry in the register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SideChannel {
    /// Stable identifier, `T1` through `T10`.
    pub id: &'static str,
    /// One line on what an attacker learns.
    pub leak: &'static str,
    /// What was done about it.
    pub disposition: Disposition,
}

/// Every authentication side channel considered in P2-02, with its disposition.
///
/// Exposed as data so that a test can assert the register is complete and that nothing was
/// deferred to nowhere. Adding a channel means adding an entry; removing one without replacing the
/// mitigation makes the accompanying test fail.
pub const SIDE_CHANNELS: [SideChannel; 10] = [
    SideChannel {
        id: "T1",
        leak: "access key enumeration from the latency of an unknown-key rejection",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T2",
        leak: "credential provider cache hit/miss latency, and unauthenticated lookup amplification",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T3",
        leak: "derived signing key cache hit reveals recent use of an access key",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T4",
        leak: "bucket existence probed through an unauthenticated request",
        disposition: Disposition::DeferredTo("P2-04 authentication stage"),
    },
    SideChannel {
        id: "T5",
        leak: "policy evaluation time varies with statement count and match position",
        disposition: Disposition::AcceptedRisk("reachable only after authentication has already succeeded"),
    },
    SideChannel {
        id: "T6",
        leak: "the rejection-stage latency ladder localises which field of a forgery was wrong",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T7",
        leak: "a second signature width (SigV2, 20 bytes) invites a derived PartialEq",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T8",
        leak: "Choice converted to bool and short-circuited with && reintroduces a branch",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T9",
        leak: "the four intermediate derivation keys are secret-equivalent and can be left on the heap",
        disposition: Disposition::ClosedHere,
    },
    SideChannel {
        id: "T10",
        leak: "lenient hex/base64 decoding gives two spellings of one value",
        disposition: Disposition::ClosedHere,
    },
];

/// The uniform minimum latency of an authentication failure (T6).
///
/// Every rejection — malformed header, unknown access key, mismatched signature — is held to the
/// same floor, so the stage a forgery reached is not readable off the clock. Without it, the
/// ladder from "rejected at parse" to "rejected at signature" to "rejected at policy" is a
/// field-by-field binary search over the request.
///
/// It never sleeps. [`FailureFloor::remaining`] returns how long is left, and the caller awaits
/// that on its own runtime: a blocking sleep on a worker thread would turn this defence into a
/// denial-of-service lever, which is a worse bug than the one it fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FailureFloor {
    floor: Duration,
}

impl FailureFloor {
    /// The default floor: 25 ms.
    ///
    /// Large enough to swallow the microsecond-scale differences between rejection stages, small
    /// enough that a legitimate client typing the wrong key does not notice, and small enough that
    /// holding one connection per failure does not itself become the resource-exhaustion vector.
    pub const DEFAULT: Self = Self {
        floor: Duration::from_millis(25),
    };

    /// A floor of a chosen length.
    ///
    /// A zero floor is representable because a deployment behind an aggressive governor may prefer
    /// to spend nothing here — but it is not the default, and choosing it should be a decision in
    /// configuration rather than an accident of initialisation.
    #[must_use]
    pub const fn new(floor: Duration) -> Self {
        Self { floor }
    }

    /// The configured floor.
    #[must_use]
    pub const fn floor(&self) -> Duration {
        self.floor
    }

    /// How much longer the caller must wait before answering, given the work already done.
    ///
    /// `None` means the failure path already took at least the floor, so answering immediately is
    /// correct. Note what this does *not* do: it does not cap the latency, because capping would
    /// reintroduce a distinguishable fast path for the cheap rejections.
    #[must_use]
    pub fn remaining(&self, elapsed: Duration) -> Option<Duration> {
        self.floor.checked_sub(elapsed).filter(|left| !left.is_zero())
    }
}

impl Default for FailureFloor {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The fixed placeholder secret the unknown-access-key path signs with (T1).
///
/// An unknown access key must not short-circuit. The verifier derives a signing key from this
/// value, runs the full four-step chain, computes a signature and compares it in constant time —
/// the comparison fails, the answer is `InvalidAccessKeyId`, and the work done is the same as for
/// a key that exists. Skipping it is how an attacker enumerates valid access keys without knowing
/// a single secret, which is the reconnaissance step in front of CVE-2025-31489.
///
/// The bytes are a fixed, published constant, not a random value: it is never a credential and
/// must never be treated as one. It is 40 bytes because that is the length of an AWS secret access
/// key, so the HMAC block handling is identical to the real path.
///
/// ```
/// # use rustfs_gateway_sig::timing::placeholder_secret;
/// assert_eq!(placeholder_secret().len(), 40);
/// ```
#[must_use]
pub fn placeholder_secret() -> SecretBytes {
    // Fixed and non-secret on purpose: publishing it costs nothing, because it authenticates
    // nothing. Its only job is to make the rejection path cost the same as the success path.
    SecretBytes::new(b"placeholder-secret-not-a-real-credential")
}

/// What a credential lookup returned.
///
/// The three outcomes are kept apart at the type level so that the caller cannot collapse
/// "unknown" and "the provider is down" into one branch. They demand different answers:
/// `Unknown` is a `403` after the full parity work, `Unavailable` is a `503` and must never be
/// reported as an authentication failure, because doing so tells a client that its own credentials
/// are wrong when they are not.
///
/// There is no `Debug`: the `Found` variant carries key material.
#[non_exhaustive]
pub enum CredentialLookup {
    /// The access key is known; here is its secret.
    Found(SecretBytes),
    /// The access key is not known. The caller still runs the full derivation, against
    /// [`placeholder_secret`].
    Unknown,
    /// The provider could not answer within [`LookupBudget::timeout`], or failed.
    ///
    /// Fail closed: no verdict other than a rejection may follow, and the rejection is a service
    /// error rather than an authentication error.
    Unavailable,
}

impl CredentialLookup {
    /// Whether the caller must still run the full derivation for latency parity.
    ///
    /// True for [`CredentialLookup::Unknown`]. False for [`CredentialLookup::Unavailable`], where
    /// there is no answer to give and the request is failing for an unrelated reason.
    #[must_use]
    pub const fn requires_parity_work(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// The bounds a credential provider is held to (T2).
///
/// The provider is consulted on the *unauthenticated* path: anybody who can reach the endpoint can
/// make the gateway call it. Two consequences follow, and both are configuration rather than code:
///
/// * a hard timeout, so a slow or hostile provider cannot pin request-handling resources;
/// * a negative cache with a jittered TTL, so a flood of invented access keys does not become a
///   flood of provider round trips, and so the cache does not expire in lockstep and produce a
///   thundering herd.
///
/// The jitter is subtracted, never added, so the effective TTL is `[ttl - jitter, ttl]` and a
/// negative entry never outlives the configured maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LookupBudget {
    timeout: Duration,
    negative_ttl: Duration,
    negative_ttl_jitter: Duration,
}

impl LookupBudget {
    /// A conservative default: 250 ms timeout, 5 s negative TTL, 1 s of jitter.
    pub const DEFAULT: Self = Self {
        timeout: Duration::from_millis(250),
        negative_ttl: Duration::from_secs(5),
        negative_ttl_jitter: Duration::from_secs(1),
    };

    /// Builds a budget, clamping the jitter to the TTL.
    ///
    /// Jitter larger than the TTL would allow a zero-length negative entry, which is the same as
    /// having no negative cache at all — the failure mode this type exists to prevent.
    #[must_use]
    pub const fn new(timeout: Duration, negative_ttl: Duration, negative_ttl_jitter: Duration) -> Self {
        let negative_ttl_jitter = if negative_ttl_jitter.as_nanos() > negative_ttl.as_nanos() {
            negative_ttl
        } else {
            negative_ttl_jitter
        };
        Self {
            timeout,
            negative_ttl,
            negative_ttl_jitter,
        }
    }

    /// The hard deadline for one provider call.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// How long a "this access key does not exist" answer may be cached.
    #[must_use]
    pub const fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    /// The maximum amount subtracted from [`LookupBudget::negative_ttl`] for one entry.
    #[must_use]
    pub const fn negative_ttl_jitter(&self) -> Duration {
        self.negative_ttl_jitter
    }

    /// The effective TTL for one negative entry, given a caller-supplied fraction in `[0, 1]`.
    ///
    /// The randomness is the caller's: this crate takes no dependency on an RNG, and a
    /// deterministic function is testable. Values outside the range — including a non-finite one,
    /// which would otherwise panic inside `Duration::mul_f64` — collapse to "no jitter", because
    /// a jitter source is not attacker-controlled and a panic here would be a denial of service on
    /// the authentication path.
    #[must_use]
    pub fn jittered_negative_ttl(&self, fraction: f64) -> Duration {
        let fraction = if fraction.is_finite() { fraction.clamp(0.0, 1.0) } else { 0.0 };
        let subtract = self.negative_ttl_jitter.mul_f64(fraction);
        self.negative_ttl.saturating_sub(subtract)
    }
}

impl Default for LookupBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for SideChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.id, self.leak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_register_is_complete_and_every_entry_has_an_owner() {
        assert_eq!(SIDE_CHANNELS.len(), 10);
        for (index, channel) in SIDE_CHANNELS.iter().enumerate() {
            assert_eq!(channel.id, format!("T{}", index + 1), "the register must stay in order");
            assert!(!channel.leak.is_empty());
            match channel.disposition {
                Disposition::DeferredTo(owner) | Disposition::AcceptedRisk(owner) => {
                    assert!(!owner.is_empty(), "{} was deferred to nobody", channel.id);
                }
                Disposition::ClosedHere => {}
            }
        }
    }

    #[test]
    fn the_default_failure_floor_is_not_zero() {
        assert!(!FailureFloor::default().floor().is_zero());
    }

    #[test]
    fn the_floor_only_ever_adds_latency() {
        let floor = FailureFloor::new(Duration::from_millis(10));
        assert_eq!(floor.remaining(Duration::from_millis(4)), Some(Duration::from_millis(6)));
        // Already over the floor: nothing left to wait, and the floor never truncates.
        assert_eq!(floor.remaining(Duration::from_millis(10)), None);
        assert_eq!(floor.remaining(Duration::from_secs(1)), None);
    }

    #[test]
    fn a_zero_floor_is_representable_but_is_not_the_default() {
        let floor = FailureFloor::new(Duration::ZERO);
        assert_eq!(floor.remaining(Duration::ZERO), None);
        assert_ne!(floor, FailureFloor::default());
    }

    #[test]
    fn unknown_keys_still_owe_the_parity_work() {
        assert!(CredentialLookup::Unknown.requires_parity_work());
        assert!(!CredentialLookup::Unavailable.requires_parity_work());
        assert!(!CredentialLookup::Found(placeholder_secret()).requires_parity_work());
    }

    #[test]
    fn jitter_never_lengthens_a_negative_entry_and_never_empties_it() {
        let budget = LookupBudget::DEFAULT;
        assert_eq!(budget.jittered_negative_ttl(0.0), budget.negative_ttl());
        assert_eq!(budget.jittered_negative_ttl(1.0), Duration::from_secs(4));
        // Out-of-range fractions are clamped, never panic.
        assert_eq!(budget.jittered_negative_ttl(-5.0), budget.negative_ttl());
        assert_eq!(budget.jittered_negative_ttl(f64::NAN), budget.negative_ttl());
        assert!(budget.jittered_negative_ttl(1.0) > Duration::ZERO);
    }

    #[test]
    fn jitter_larger_than_the_ttl_is_clamped() {
        let budget = LookupBudget::new(Duration::from_millis(50), Duration::from_secs(2), Duration::from_secs(30));
        assert_eq!(budget.negative_ttl_jitter(), Duration::from_secs(2));
        assert_eq!(budget.jittered_negative_ttl(1.0), Duration::ZERO);
    }
}
