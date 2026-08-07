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

//! Shares: location_constraint
//! Members: CreateBucket
//!
//! Responsible for: parsing-direction `LocationConstraint` semantics — [`normalize`] (the `EU`
//! legacy alias and the empty-element-means-unspecified rule) and [`resolve`] (the us-east-1
//! omission rule and the region match against the deployment's own [`RegionSet`], under a
//! [`RegionMatchPolicy`]).
//! NOT responsible for: the *output* direction — `GetBucketLocation`'s unwrapped element and its
//! us-east-1 empty spelling belong to that operation's family — or the signature scope's region
//! check, which reads the same [`RegionSet`] in `rustfs-gateway-sig` and must keep doing so.
//! Upstream: `rustfs-gateway-sig`'s [`RegionSet`], `rustfs-gateway-types`' error codes.
//! Downstream: `CreateBucket`, and every backend that answers it.
//!
//! # The one configuration both checks read
//!
//! The deployment's region posture is a single [`RegionSet`]: the credential-scope cross-check
//! derives signing keys only for regions in it, and [`resolve`] accepts a constraint only if it
//! names a region in it. Two configurations here would let a bucket be *creatable* for a region
//! nobody can *sign* for, which is a deployment that disagrees with itself request by request.
//!
//! # Why us-east-1 is special, stated once
//!
//! us-east-1 is AWS's null region: the constraint enum has no us-east-1 value, a us-east-1
//! creation sends no constraint (or an empty one), and writing `us-east-1` out explicitly is a
//! `400 InvalidLocationConstraint` even on a us-east-1 endpoint. Nearly every S3 reimplementation
//! has tripped on this; here it is one branch of [`resolve`], covered by conformance cases in
//! both regions.

use rustfs_gateway_sig::RegionSet;
use rustfs_gateway_types::ErrorCode;

use crate::handler::HandlerError;

/// The one region whose constraint must be omitted rather than written.
pub const US_EAST_1: &str = "us-east-1";

/// The legacy alias and the modern name it denotes.
pub const EU_ALIAS: (&str, &str) = ("EU", "eu-west-1");

/// The longest constraint [`resolve`] looks at before refusing.
///
/// Applied before any comparison, so a pathological value is refused at the ceiling rather than
/// walked: the constraint is a region name, and no region name approaches this.
pub const MAX_CONSTRAINT_LEN: usize = 64;

/// How a presented constraint is matched against the deployment's regions.
///
/// **This is the configuration item.** `Strict` is the whole of what this family implements: the
/// constraint, after [`normalize`], must name a region the deployment's [`RegionSet`] contains,
/// and `us-east-1` must never be written explicitly. The lenient and multi-region postures are
/// service-assembly semantics (P7-01) and get variants here when they get semantics there; the
/// signature scope's region check must be driven by the same choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegionMatchPolicy {
    /// The constraint must name a served region exactly; us-east-1 must be omitted.
    #[default]
    Strict,
}

/// Normalises a raw constraint: the empty spelling becomes "unspecified", and `EU` becomes
/// `eu-west-1`.
///
/// An empty element (`<LocationConstraint/>`) and empty text (`<LocationConstraint></...>`) both
/// decode to an empty string, and both mean the field was not given — refusing them would break
/// clients that serialise absent fields as empty elements. Everything else passes through
/// untouched: normalisation is not validation, and an unknown name is [`resolve`]'s to refuse.
#[must_use]
pub fn normalize(raw: Option<&str>) -> Option<&str> {
    match raw {
        None | Some("") => None,
        Some(text) if text == EU_ALIAS.0 => Some(EU_ALIAS.1),
        Some(text) => Some(text),
    }
}

/// The `400 InvalidLocationConstraint` every refusal below answers with.
#[must_use]
pub fn invalid_location_constraint() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_LOCATION_CONSTRAINT, "The specified location-constraint is not valid")
}

/// Resolves a presented constraint to the region the bucket is created in.
///
/// `Ok(None)` means the request left the region unspecified — no constraint, an empty element, or
/// empty text — and the caller creates the bucket in its own region. `Ok(Some(region))` is a
/// constraint that named a served region. The bound is applied before anything else, so a
/// pathological value costs one length check.
///
/// # Errors
///
/// `400 InvalidLocationConstraint` when the constraint is longer than [`MAX_CONSTRAINT_LEN`],
/// spells `us-east-1` explicitly (it must be omitted), or names a region the deployment does not
/// serve — including every unknown or malformed name, which is deliberately the same refusal: a
/// distinct "no such region" answer would be a region-topology oracle.
pub fn resolve<'a>(
    presented: Option<&'a str>,
    regions: &RegionSet,
    policy: RegionMatchPolicy,
) -> Result<Option<&'a str>, HandlerError> {
    let RegionMatchPolicy::Strict = policy;
    if presented.is_some_and(|text| text.len() > MAX_CONSTRAINT_LEN) {
        return Err(invalid_location_constraint());
    }
    let Some(constraint) = normalize(presented) else {
        return Ok(None);
    };
    if constraint == US_EAST_1 {
        return Err(invalid_location_constraint());
    }
    if !regions.contains(constraint) {
        return Err(invalid_location_constraint());
    }
    Ok(Some(constraint))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn serving(regions: &[&str]) -> RegionSet {
        RegionSet::new(regions.iter().copied()).expect("a non-empty region set")
    }

    /// Positive — the three spellings of "unspecified" all resolve to no constraint.
    #[test]
    fn absent_empty_element_and_empty_text_all_mean_unspecified() {
        let regions = serving(&["us-east-1"]);
        assert_eq!(resolve(None, &regions, RegionMatchPolicy::Strict).expect("accepted"), None);
        assert_eq!(resolve(Some(""), &regions, RegionMatchPolicy::Strict).expect("accepted"), None);
    }

    /// Positive — a constraint naming the served region resolves to it.
    #[test]
    fn a_constraint_naming_the_served_region_is_accepted() {
        let regions = serving(&["us-west-2"]);
        let resolved = resolve(Some("us-west-2"), &regions, RegionMatchPolicy::Strict).expect("accepted");
        assert_eq!(resolved, Some("us-west-2"));
    }

    /// Positive — the legacy alias resolves to eu-west-1 and matches a deployment serving it.
    #[test]
    fn the_eu_alias_is_normalised_to_eu_west_1() {
        assert_eq!(normalize(Some("EU")), Some("eu-west-1"));
        let regions = serving(&["eu-west-1"]);
        let resolved = resolve(Some("EU"), &regions, RegionMatchPolicy::Strict).expect("accepted");
        assert_eq!(resolved, Some("eu-west-1"));
    }

    /// Negative — us-east-1 written out is refused even by a us-east-1 deployment. This is the
    /// rule the family is most often implemented without.
    #[test]
    fn n_an_explicit_us_east_1_is_refused_even_at_us_east_1() {
        let regions = serving(&["us-east-1"]);
        let error = resolve(Some("us-east-1"), &regions, RegionMatchPolicy::Strict).expect_err("refused");
        assert_eq!(*error.code(), ErrorCode::INVALID_LOCATION_CONSTRAINT);
        assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
    }

    /// Negative — a valid region the deployment does not serve is refused with the same code.
    #[test]
    fn n_a_region_the_deployment_does_not_serve_is_refused() {
        let regions = serving(&["us-west-2"]);
        let error = resolve(Some("eu-west-1"), &regions, RegionMatchPolicy::Strict).expect_err("refused");
        assert_eq!(*error.code(), ErrorCode::INVALID_LOCATION_CONSTRAINT);
    }

    /// Negative — the EU alias is refused where eu-west-1 is not served: the alias is normalised
    /// *before* matching, so it cannot be accepted anywhere its target would be refused.
    #[test]
    fn n_the_eu_alias_is_refused_where_eu_west_1_is_not_served() {
        let regions = serving(&["us-east-1"]);
        assert!(resolve(Some("EU"), &regions, RegionMatchPolicy::Strict).is_err());
    }

    /// Negative — unknown names, junk, and control characters are all the same refusal, and an
    /// oversized constraint is refused at the ceiling before any comparison.
    #[test]
    fn n_junk_is_refused_at_the_bound_with_one_code() {
        let regions = serving(&["us-west-2"]);
        for hostile in ["mars-north-1", "us_west_2", "US-WEST-2", "\u{0}", "eu"] {
            let error = resolve(Some(hostile), &regions, RegionMatchPolicy::Strict).expect_err("refused");
            assert_eq!(*error.code(), ErrorCode::INVALID_LOCATION_CONSTRAINT, "{hostile:?}");
        }
        let oversized = "a".repeat(MAX_CONSTRAINT_LEN + 1);
        assert!(resolve(Some(&oversized), &regions, RegionMatchPolicy::Strict).is_err());
    }

    /// Negative — both sides of the ceiling, so the bound is `>` and not `>=`.
    ///
    /// A name of exactly the maximum length is refused for being unserved rather than for being
    /// too long, and the pair is what says the two refusals are reached by different paths: an
    /// off-by-one here would make a legitimate region name of that length unusable, and every case
    /// asserting the shorter names would stay green through it.
    #[test]
    fn n_the_length_bound_is_exclusive_at_the_maximum() {
        let at_max = "a".repeat(MAX_CONSTRAINT_LEN);
        let regions = RegionSet::new([at_max.as_str()]).expect("a non-empty region set");
        let resolved = resolve(Some(&at_max), &regions, RegionMatchPolicy::Strict).expect("accepted at the bound");
        assert_eq!(resolved, Some(at_max.as_str()));
        let past_max = "a".repeat(MAX_CONSTRAINT_LEN + 1);
        assert!(resolve(Some(&past_max), &regions, RegionMatchPolicy::Strict).is_err());
    }

    /// Negative — case matters: the alias is `EU`, not `eu`, and a lowercased spelling is an
    /// unknown region rather than a second alias.
    #[test]
    fn n_the_alias_is_case_sensitive() {
        assert_eq!(normalize(Some("eu")), Some("eu"));
        let regions = serving(&["eu-west-1"]);
        assert!(resolve(Some("eu"), &regions, RegionMatchPolicy::Strict).is_err());
    }
}
