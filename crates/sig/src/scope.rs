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

//! The credential-scope cross-check, and the only public route to a [`VerifiedScope`].
//!
//! Responsible for: [`RegionSet`] (the regions this deployment serves), [`ExpectedScope`] (what
//! the routed operation expects a scope to say), and [`enforce_scope`], which compares the two and
//! is the only public producer of the [`VerifiedScope`] that [`crate::signing_key`] takes.
//! NOT responsible for: parsing the scope off the request (that is [`crate::parse`], which
//! deliberately produces an untrusted [`CredentialScope`]), the clock (that is [`crate::clock`],
//! whose receipt this module requires), or deriving the key.
//! Upstream: [`crate::clock`], [`crate::parse`], [`crate::operation`].
//! Downstream: [`crate::derive`]'s [`crate::signing_key`], through the type it hands back.
//!
//! # The replay this module exists to stop
//!
//! Derive the signing key from the scope the client sent and verification succeeds for whichever
//! scope the client chose — so a signature an ordinary SDK produced for another region or another
//! service replays here. The four HMAC steps are seeded from a type nobody outside this crate can
//! build, and this is the function that builds it.

use crate::clock::ClockChecked;
use crate::derive::VerifiedScope;
use crate::operation::FloorConfigError;
use crate::parse::CredentialScope;
use crate::scheme::SigService;

/// A bounded configured region that is safe to carry as remediation metadata.
///
/// Only [`RegionSet::new`] constructs this type. In particular, a region parsed from a request
/// cannot be converted into one.
///
/// ```compile_fail,E0423
/// use rustfs_gateway_sig::ScopeRegion;
/// let _ = ScopeRegion("attacker-region".into());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeRegion(Box<str>);

impl ScopeRegion {
    /// The largest admitted configured region.
    pub const MAX_LEN: usize = 64;

    /// The configured region spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A scope disagreement, optionally carrying the trusted configured remediation region.
///
/// ```compile_fail,E0423
/// use rustfs_gateway_sig::ScopeRejection;
/// let _ = ScopeRejection(None);
/// ```
///
/// ```compile_fail,E0532
/// use rustfs_gateway_sig::ScopeRejection;
/// fn open(rejection: ScopeRejection) {
///     let ScopeRejection(_) = rejection;
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRejection(Option<ScopeRegion>);

impl ScopeRejection {
    /// The configured remediation region for a region mismatch.
    ///
    /// Date and service mismatches deliberately return `None`.
    #[must_use]
    pub const fn expected_region(&self) -> Option<&ScopeRegion> {
        self.0.as_ref()
    }
}

/// The regions this deployment serves.
///
/// A closed set, because the region is one of the four HMAC steps: accepting whatever the client
/// wrote means deriving the signing key from attacker-chosen input, and a signature minted for
/// another region then replays here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionSet {
    regions: Box<[ScopeRegion]>,
}

impl RegionSet {
    /// Builds the set.
    ///
    /// # Errors
    ///
    /// [`FloorConfigError::InvalidRegionSet`] if the set is empty, or if a name is empty, longer
    /// than [`ScopeRegion::MAX_LEN`], or contains anything other than lowercase ASCII letters,
    /// digits or `-`.
    pub fn new<I, S>(regions: I) -> Result<Self, FloorConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut regions: Vec<ScopeRegion> = regions
            .into_iter()
            .map(|region| ScopeRegion(Box::from(region.as_ref())))
            .collect();
        if regions.is_empty() {
            return Err(FloorConfigError::InvalidRegionSet);
        }
        let ok = regions.iter().all(|region| Self::is_region_name(region.as_str()));
        if !ok {
            return Err(FloorConfigError::InvalidRegionSet);
        }
        regions.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        regions.dedup();
        Ok(Self {
            regions: regions.into_boxed_slice(),
        })
    }

    /// Whether `region` satisfies the configured-name grammar: 1..=[`ScopeRegion::MAX_LEN`] bytes
    /// of lowercase ASCII letters, digits or `-`. Legacy RustFS reads a signed region by the same
    /// grammar, and a verifier that admits other spellings for key derivation
    /// ([`ExpectedScope::accepting_any_region_spelling`]) asks this after the signature matched.
    #[must_use]
    pub fn is_region_name(region: &str) -> bool {
        !region.is_empty()
            && region.len() <= ScopeRegion::MAX_LEN
            && region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }

    /// Whether a presented region name is one this deployment serves. Byte-exact: the region is a
    /// signed string, so a case-insensitive match would accept a signature over different bytes.
    #[must_use]
    pub fn contains(&self, region: &str) -> bool {
        self.regions.iter().any(|known| known.as_str() == region)
    }

    /// The configured names, for the startup security-posture report.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.regions.iter().map(ScopeRegion::as_str)
    }
}

/// What the routed operation expects a credential scope to say.
///
/// The service comes from the operation, never from the request. That is the whole point of H5:
/// the client says which service it signed for, and the server says which service it routed to,
/// and the two must agree.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedScope<'a> {
    service: SigService,
    regions: &'a RegionSet,
    any_region: bool,
    empty_region: bool,
    any_spelling: bool,
}

impl<'a> ExpectedScope<'a> {
    /// Names the service the routed operation belongs to, and the regions this deployment serves.
    #[must_use]
    pub const fn new(service: SigService, regions: &'a RegionSet) -> Self {
        Self {
            service,
            regions,
            any_region: false,
            empty_region: false,
            any_spelling: false,
        }
    }

    /// Admits every presented region that satisfies the configured-name grammar of
    /// [`RegionSet::new`], not only the configured ones (ADR-0023, the RustFS profile of
    /// rd-loc-0004). The date and service checks are unchanged, and the key is still derived from
    /// the presented region, so a signature stays bound to the region the client named. A region
    /// outside the grammar is still refused, naming the first configured region.
    #[must_use]
    pub const fn accepting_any_region(mut self) -> Self {
        self.any_region = true;
        self
    }

    /// Admits a scope whose region field is empty, the second RustFS-profile region policy.
    ///
    /// Legacy RustFS verifies a signature whatever region its scope names, and then reads an empty
    /// region as no region at all: the request carries the virtual host's region, or none. RustFS's
    /// own replication client signs with an empty region, so a RustFS deployment that refused one
    /// could not replicate to itself. The empty region is outside
    /// [`Self::accepting_any_region`]'s grammar on purpose — it is not a region name — so it is
    /// admitted only by this, separately.
    ///
    /// Only the empty region: the key is still derived from the presented (empty) region, so the
    /// signature stays bound to it, and the date and service checks are unchanged.
    #[must_use]
    pub const fn accepting_empty_region(mut self) -> Self {
        self.empty_region = true;
        self
    }

    /// Admits every non-empty region the credential parser reads — ASCII graphic, at most
    /// [`crate::CredentialScope::MAX_REGION_LEN`] bytes, no `/` — for a verifier that refuses a
    /// region outside [`RegionSet::is_region_name`] only after the signature has been checked, as
    /// legacy RustFS does (the RustFS profile, rustfs/gateway#1075).
    ///
    /// A verifier that turns this on must make that refusal itself: the scope check no longer
    /// does. The key is still derived from the presented region, and the date and service checks
    /// are unchanged.
    #[must_use]
    pub const fn accepting_any_region_spelling(mut self) -> Self {
        self.any_spelling = true;
        self
    }

    /// Whether [`enforce_scope`] admits `region` under this expectation.
    fn admits_region(&self, region: &str) -> bool {
        self.regions.contains(region)
            || (self.any_spelling && !region.is_empty())
            || (self.any_region && RegionSet::is_region_name(region))
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS verifies a scope that names no
            // region at all, and its replication client relies on it. A scope without a region
            // is not one AWS or any SDK produces, and it skips the endpoint-routing answer; the
            // intended future behaviour is that RustFS's replication client signs with the
            // target's real region and this policy is dropped.
            || (self.empty_region && region.is_empty())
    }

    /// The service the routed operation belongs to.
    #[must_use]
    pub const fn service(&self) -> SigService {
        self.service
    }

    /// The regions this deployment serves.
    #[must_use]
    pub const fn regions(&self) -> &'a RegionSet {
        self.regions
    }
}

/// H5 — the credential-scope cross-check, and the only public producer of a [`VerifiedScope`].
///
/// Four things are checked before the signing key may be derived:
///
/// * the scope's day equals the day of the timestamp that passed the skew check;
/// * the region is one this deployment serves;
/// * the service is the one the routed operation belongs to;
/// * the terminator is `aws4_request` — already guaranteed, because [`CredentialScope::parse`]
///   refuses anything else, and this is the function that depends on it.
///
/// The timestamp arrives as a [`ClockChecked`], not as an [`crate::AmzDate`]: a scope cannot be
/// cross-checked against a timestamp that nobody compared to the clock, because the receipt is the
/// only way to name one here.
///
/// # Errors
///
/// [`ScopeRejection`] for any disagreement. Only a region mismatch carries a configured
/// remediation region; date and service mismatches carry no detail.
///
/// # Why this is the constructor
///
/// [`crate::signing_key`] takes a [`VerifiedScope`] and nothing else, and this is the only way to
/// obtain one outside the crate's own tests. So "derive the key from the scope the client sent" —
/// which makes a signature minted for another region or service replay here — is not a review
/// question. It does not compile:
///
/// ```compile_fail,E0423
/// use rustfs_gateway_sig::{CredentialScope, SecretBytes, VerifiedScope, signing_key};
/// let presented = CredentialScope::parse("AKID/20150830/us-east-1/s3/aws4_request").expect("valid");
/// let secret = SecretBytes::new(b"wJalrXUtnFEMI");
/// // No constructor, no public fields, no `From<CredentialScope>`.
/// let _ = signing_key(&secret, &VerifiedScope::from_presented(&presented));
/// ```
pub fn enforce_scope(
    presented: &CredentialScope,
    clock: ClockChecked,
    expected: &ExpectedScope<'_>,
) -> Result<VerifiedScope, ScopeRejection> {
    if presented.date() != clock.signed_at().day() {
        return Err(ScopeRejection(None));
    }
    if !expected.admits_region(presented.region()) {
        return Err(ScopeRejection(expected.regions().regions.first().cloned()));
    }
    if presented.service() != expected.service() {
        return Err(ScopeRejection(None));
    }
    Ok(VerifiedScope::from_checked_parts(
        presented.date(),
        presented.region(),
        presented.service().as_str(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{RequestNow, SkewWindow, enforce_clock_skew};
    use crate::parse::AmzDate;

    fn clock() -> ClockChecked {
        let signed_at = AmzDate::parse("20150830T123600Z").expect("a valid timestamp");
        enforce_clock_skew(&signed_at, RequestNow::from_unix_seconds(1_440_938_160), SkewWindow::DEFAULT)
            .expect("inside the window")
    }

    /// Negative — only a region mismatch carries the canonical configured remediation region.
    #[test]
    fn only_region_disagreement_carries_the_expected_region() {
        let regions = RegionSet::new(["us-east-1", "eu-west-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions);
        let bad_date = CredentialScope::parse("AKID/20150831/us-east-1/s3/aws4_request").expect("well formed");
        let bad_region = CredentialScope::parse("AKID/20150830/ap-south-1/s3/aws4_request").expect("well formed");
        let bad_service = CredentialScope::parse("AKID/20150830/us-east-1/sts/aws4_request").expect("well formed");

        assert_eq!(enforce_scope(&bad_date, clock(), &expected).unwrap_err().expected_region(), None);
        assert_eq!(
            enforce_scope(&bad_region, clock(), &expected)
                .unwrap_err()
                .expected_region()
                .map(ScopeRegion::as_str),
            Some("eu-west-1")
        );
        assert_eq!(enforce_scope(&bad_service, clock(), &expected).unwrap_err().expected_region(), None);
    }

    /// Positive — an agreeing scope keeps the wire spelling of every field it was signed with.
    #[test]
    fn a_verified_scope_keeps_the_spelling_that_was_signed() {
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions);
        let presented = CredentialScope::parse("AKID/20150830/us-east-1/s3/aws4_request").expect("well formed");
        let verified = enforce_scope(&presented, clock(), &expected).expect("agrees");
        assert_eq!(verified.date().as_str(), "20150830");
        assert_eq!(verified.region(), "us-east-1");
        assert_eq!(verified.service(), "s3");
    }

    /// Negative — a region name that could never match a parsed scope is refused where it is
    /// configured, not where it fails.
    #[test]
    fn an_unusable_region_set_is_refused_at_construction() {
        assert_eq!(RegionSet::new::<[&str; 0], &str>([]).err(), Some(FloorConfigError::InvalidRegionSet));
        assert_eq!(RegionSet::new([""]).err(), Some(FloorConfigError::InvalidRegionSet));
        assert_eq!(RegionSet::new(["us east 1"]).err(), Some(FloorConfigError::InvalidRegionSet));
        assert_eq!(RegionSet::new(["US-EAST-1"]).err(), Some(FloorConfigError::InvalidRegionSet));
        let regions = RegionSet::new(["us-east-1", "eu-west-1", "us-east-1"]).expect("valid regions");
        assert_eq!(regions.names().collect::<Vec<_>>(), ["eu-west-1", "us-east-1"]);
        let reversed = RegionSet::new(["eu-west-1", "us-east-1"]).expect("valid regions");
        assert_eq!(reversed.names().collect::<Vec<_>>(), ["eu-west-1", "us-east-1"]);
        let unordered = RegionSet::new(std::collections::HashSet::from(["us-east-1", "eu-west-1"])).expect("valid regions");
        assert_eq!(unordered.names().collect::<Vec<_>>(), ["eu-west-1", "us-east-1"]);
    }
}
