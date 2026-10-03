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
    /// of lowercase ASCII letters, digits or `-`.
    #[must_use]
    pub fn is_region_name(region: &str) -> bool {
        region.len() <= ScopeRegion::MAX_LEN && Self::is_region_name_of_any_length(region)
    }

    /// Whether `region` is one or more lowercase ASCII letters, digits or `-`, at any length: the
    /// grammar of [`Self::is_region_name`] without its ceiling. Legacy RustFS reads a signed region
    /// by this grammar, and a verifier that admits other spellings for key derivation
    /// ([`ExpectedScope::accepting_any_region_spelling`]) asks this after the signature matched.
    #[must_use]
    pub fn is_region_name_of_any_length(region: &str) -> bool {
        !region.is_empty()
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
/// and the two must agree. The one widening, [`ExpectedScope::accepting_services`], takes its set
/// from the deployment, never from the request either.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedScope<'a> {
    service: SigService,
    regions: &'a RegionSet,
    any_region: bool,
    empty_region: bool,
    any_spelling: bool,
    any_length: bool,
    services: Option<&'a [&'a str]>,
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
            any_length: false,
            services: None,
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

    /// Admits every non-empty region the credential parser reads — ASCII graphic, no `/`, at any
    /// length its [`crate::RegionRule`] reads — for a verifier that refuses a region outside
    /// [`RegionSet::is_region_name_of_any_length`] only after the signature has been checked, as
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

    /// Applies [`Self::accepting_any_region`]'s grammar at any length
    /// ([`RegionSet::is_region_name_of_any_length`]), for a verifier whose parser reads a region
    /// of any length ([`crate::RegionLength::Unbounded`]), as legacy RustFS does (the RustFS
    /// profile). On its own it admits nothing: a configured region is never that long.
    #[must_use]
    pub const fn accepting_regions_of_any_length(mut self) -> Self {
        self.any_length = true;
        self
    }

    /// Admits a scope naming any service in `names`, whatever service the routed operation belongs
    /// to, for a verifier whose deployment verifies those services on every route (the RustFS
    /// profile, rustfs/gateway#1130). Only the names listed: the key is still derived from the
    /// service the client named, so the signature stays bound to it, and the date and region
    /// checks are unchanged. A verifier that reads a service outside [`SigService`]
    /// ([`crate::ServiceReading::AnyName`]) and does not call this still refuses it here.
    #[must_use]
    pub const fn accepting_services(mut self, names: &'a [&'a str]) -> Self {
        self.services = Some(names);
        self
    }

    /// Whether [`enforce_scope`] admits a scope naming `service` under this expectation.
    fn admits_service(&self, service: &str) -> bool {
        match self.services {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS verifies an `s3`, `sts` or
            // `s3tables` scope on every operation, so a signature minted for one of those services
            // is valid for an operation of another — the cross-service replay H5 exists to stop.
            // RustFS's table-catalog clients sign `s3tables`, and the lists RustFS configures are
            // the ones it serves on every route today. The intended future behaviour is the
            // default: the scope names the routed operation's own service.
            Some(names) => names.contains(&service),
            None => SigService::parse(service) == Ok(self.service),
        }
    }

    /// Whether [`enforce_scope`] admits `region` under this expectation.
    fn admits_region(&self, region: &str) -> bool {
        let in_grammar = if self.any_length {
            RegionSet::is_region_name_of_any_length(region)
        } else {
            RegionSet::is_region_name(region)
        };
        self.regions.contains(region) || (self.any_spelling && !region.is_empty()) || (self.any_region && in_grammar)
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
/// * the service is the one the routed operation belongs to, or one of the names
///   [`ExpectedScope::accepting_services`] admits;
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
    if !expected.admits_service(presented.service_name()) {
        return Err(ScopeRejection(None));
    }
    Ok(VerifiedScope::from_checked_parts(
        presented.date(),
        presented.region(),
        presented.service_name(),
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

    /// A scope over a region of `length` bytes of `byte`, read without the ceiling.
    fn long_scope(byte: char, length: usize) -> CredentialScope {
        let rule = crate::RegionRule::STRICT.with_length(crate::RegionLength::Unbounded);
        let value = format!("AKID/20150830/{}/s3/aws4_request", String::from(byte).repeat(length));
        CredentialScope::parse_with(&value, rule).expect("read without the ceiling")
    }

    /// Positive — the grammar without its ceiling is the grammar: the same bytes, any length.
    #[test]
    fn the_grammar_of_any_length_differs_from_the_name_grammar_only_in_length() {
        let at_ceiling = "a".repeat(ScopeRegion::MAX_LEN);
        let over = "a".repeat(ScopeRegion::MAX_LEN + 1);
        assert!(RegionSet::is_region_name(&at_ceiling) && RegionSet::is_region_name_of_any_length(&at_ceiling));
        assert!(!RegionSet::is_region_name(&over) && RegionSet::is_region_name_of_any_length(&over));
        assert!(RegionSet::is_region_name_of_any_length(&"us-east-1".repeat(512)));
        for outside in ["", "US-EAST-1", "rustfs_local", "eu.west.1", &format!("{over}A")] {
            assert!(!RegionSet::is_region_name_of_any_length(outside), "{outside:?}");
            assert!(!RegionSet::is_region_name(outside), "{outside:?}");
        }
    }

    /// Positive — with ADR-0023's grammar applied at any length, a long region of the grammar is
    /// verified under the region the client named.
    #[test]
    fn any_length_policy_admits_a_long_region_of_the_grammar_verbatim() {
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions)
            .accepting_any_region()
            .accepting_regions_of_any_length();
        let presented = long_scope('a', 65);
        let verified = enforce_scope(&presented, clock(), &expected).expect("in the grammar");
        assert_eq!(verified.region(), "a".repeat(65));
    }

    /// Negative — the any-length policy admits nothing on its own, keeps the grammar, and leaves
    /// ADR-0023's ceiling in place when it is off.
    #[test]
    fn n_any_length_policy_admits_nothing_alone_and_keeps_the_grammar() {
        let regions = RegionSet::new(["us-east-1", "eu-west-1"]).expect("non-empty");
        let alone = ExpectedScope::new(SigService::S3, &regions).accepting_regions_of_any_length();
        let refused = enforce_scope(&long_scope('a', 65), clock(), &alone).expect_err("not configured");
        assert_eq!(refused.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"));

        let any_region = ExpectedScope::new(SigService::S3, &regions).accepting_any_region();
        assert!(enforce_scope(&long_scope('a', 65), clock(), &any_region).is_err());

        let both = any_region.accepting_regions_of_any_length();
        assert!(enforce_scope(&long_scope('A', 65), clock(), &both).is_err());
        let wrong_day = CredentialScope::parse_with(
            &format!("AKID/20150831/{}/s3/aws4_request", "a".repeat(65)),
            crate::RegionRule::STRICT.with_length(crate::RegionLength::Unbounded),
        )
        .expect("read without the ceiling");
        assert!(enforce_scope(&wrong_day, clock(), &both).is_err());
    }

    /// The RustFS profile's service reading: any name, the key derived from it.
    fn any_service(value: &str) -> Result<CredentialScope, crate::AuthError> {
        CredentialScope::parse_with(value, crate::RegionRule::STRICT.with_services(crate::ServiceReading::AnyName))
    }

    const LEGACY_SERVICES: [&str; 3] = ["s3", "sts", "s3tables"];

    /// Positive — a service read by any name is verified, on an operation of another service, when
    /// the expectation lists it, and the verified scope keeps the name it was signed with.
    #[test]
    fn a_listed_service_is_verified_on_an_operation_of_another_service() {
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions).accepting_services(&LEGACY_SERVICES);
        for service in LEGACY_SERVICES {
            let presented = any_service(&format!("AKID/20150830/us-east-1/{service}/aws4_request")).expect("a name");
            assert_eq!(presented.service_name(), service);
            let verified = enforce_scope(&presented, clock(), &expected).expect("listed");
            assert_eq!(verified.service(), service);
        }
        let tables = any_service("AKID/20150830/us-east-1/s3tables/aws4_request").expect("a name");
        assert_eq!(tables.service(), None);
        assert_eq!(tables.scope_string(), "20150830/us-east-1/s3tables/aws4_request");
    }

    /// Negative — the default reading refuses a name outside the S3 family, and an expectation that
    /// lists no service still verifies only the routed operation's own.
    #[test]
    fn n_without_the_list_only_the_routed_service_is_verified() {
        for value in [
            "AKID/20150830/us-east-1/s3tables/aws4_request",
            "AKID/20150830/us-east-1/foo/aws4_request",
        ] {
            assert!(CredentialScope::parse(value).is_err(), "{value}");
        }
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let routed = ExpectedScope::new(SigService::S3, &regions);
        for value in [
            "AKID/20150830/us-east-1/s3tables/aws4_request",
            "AKID/20150830/us-east-1/sts/aws4_request",
        ] {
            let presented = any_service(value).expect("a name");
            assert!(enforce_scope(&presented, clock(), &routed).is_err(), "{value}");
        }
        let s3 = any_service("AKID/20150830/us-east-1/s3/aws4_request").expect("a name");
        assert!(enforce_scope(&s3, clock(), &routed).is_ok());
    }

    /// Negative — the list admits exactly its names: another name, another case, and an empty
    /// service are refused, and the date and region checks still apply.
    #[test]
    fn n_the_list_admits_exactly_its_names() {
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions).accepting_services(&LEGACY_SERVICES);
        for service in ["foo", "S3", "s3express", "s3tables ", "sts\u{0}"] {
            let presented = any_service(&format!("AKID/20150830/us-east-1/{service}/aws4_request")).expect("a name");
            assert!(enforce_scope(&presented, clock(), &expected).is_err(), "{service:?}");
        }
        assert!(any_service("AKID/20150830/us-east-1//aws4_request").is_err());
        let wrong_day = any_service("AKID/20150831/us-east-1/s3tables/aws4_request").expect("a name");
        assert!(enforce_scope(&wrong_day, clock(), &expected).is_err());
        let wrong_region = any_service("AKID/20150830/eu-west-1/s3tables/aws4_request").expect("a name");
        assert!(enforce_scope(&wrong_region, clock(), &expected).is_err());
    }
}
