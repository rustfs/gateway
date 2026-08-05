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
use crate::verdict::AuthError;

/// The regions this deployment serves.
///
/// A closed set, because the region is one of the four HMAC steps: accepting whatever the client
/// wrote means deriving the signing key from attacker-chosen input, and a signature minted for
/// another region then replays here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionSet {
    regions: Box<[Box<str>]>,
}

impl RegionSet {
    /// Builds the set.
    ///
    /// # Errors
    ///
    /// [`FloorConfigError::InvalidRegionSet`] if the set is empty, or if a name is empty, longer
    /// than [`CredentialScope::MAX_REGION_LEN`], or not ASCII-graphic — the same rule the parser
    /// applies to the presented value, so a configured name that could never be matched is refused
    /// where it is written rather than where it fails.
    pub fn new<I, S>(regions: I) -> Result<Self, FloorConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let regions: Box<[Box<str>]> = regions.into_iter().map(|region| Box::from(region.as_ref())).collect();
        if regions.is_empty() {
            return Err(FloorConfigError::InvalidRegionSet);
        }
        let ok = regions.iter().all(|region| {
            !region.is_empty()
                && region.len() <= CredentialScope::MAX_REGION_LEN
                && region.bytes().all(|byte| byte.is_ascii_graphic())
        });
        if !ok {
            return Err(FloorConfigError::InvalidRegionSet);
        }
        Ok(Self { regions })
    }

    /// Whether a presented region name is one this deployment serves. Byte-exact: the region is a
    /// signed string, so a case-insensitive match would accept a signature over different bytes.
    #[must_use]
    pub fn contains(&self, region: &str) -> bool {
        self.regions.iter().any(|known| &**known == region)
    }

    /// The configured names, for the startup security-posture report.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.regions.iter().map(|region| &**region)
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
}

impl<'a> ExpectedScope<'a> {
    /// Names the service the routed operation belongs to, and the regions this deployment serves.
    #[must_use]
    pub const fn new(service: SigService, regions: &'a RegionSet) -> Self {
        Self { service, regions }
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
/// The timestamp arrives as a [`ClockChecked`], not as an [`AmzDate`]: a scope cannot be
/// cross-checked against a timestamp that nobody compared to the clock, because the receipt is the
/// only way to name one here.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] for any disagreement. One code for all four, and no
/// detail field: "the region is wrong; expecting eu-west-1" is a deployment-topology oracle handed
/// to an unauthenticated caller.
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
) -> Result<VerifiedScope, AuthError> {
    if presented.date() != clock.signed_at().day() {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    if !expected.regions().contains(presented.region()) {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    if presented.service() != expected.service() {
        return Err(AuthError::AuthorizationHeaderMalformed);
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

    /// Negative — the scope cross-check answers one code for all four disagreements, so the
    /// rejection is not a probe for the deployment's region or service topology.
    #[test]
    fn every_scope_disagreement_answers_the_same_code() {
        let regions = RegionSet::new(["us-east-1"]).expect("non-empty");
        let expected = ExpectedScope::new(SigService::S3, &regions);
        for bad in [
            "AKID/20150831/us-east-1/s3/aws4_request",
            "AKID/20150830/eu-west-1/s3/aws4_request",
            "AKID/20150830/us-east-1/sts/aws4_request",
        ] {
            let presented = CredentialScope::parse(bad).expect("well formed");
            assert_eq!(
                enforce_scope(&presented, clock(), &expected).err(),
                Some(AuthError::AuthorizationHeaderMalformed),
                "must refuse {bad}"
            );
        }
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
        assert!(RegionSet::new(["us-east-1", "eu-west-1"]).is_ok());
    }
}
