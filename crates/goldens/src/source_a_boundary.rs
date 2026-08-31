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

//! Source-(a) physical rule-count boundary fixtures.
//!
//! Responsible for: exact path, case-ID, digest, and rule-count bindings for four repository fixtures.
//! NOT responsible for: generating fixture XML or enforcing HTTP request limits.
//! Upstream: gateway conformance fixtures. Downstream: CORS and Lifecycle persistence corpora.

use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule};
use rustfs_gateway_types::persistence::{
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
};

use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const CORS_100: &[u8] = include_bytes!("../../../conformance/fixtures/cors/one-hundred-rules.xml");
const CORS_101: &[u8] = include_bytes!("../../../conformance/fixtures/cors/hundred-and-one-rules.xml");
const LIFECYCLE_1000: &[u8] = include_bytes!("../../../conformance/fixtures/lifecycle/one-thousand-rules.xml");
const LIFECYCLE_1001: &[u8] = include_bytes!("../../../conformance/fixtures/lifecycle/thousand-and-one-rules.xml");
const BOUNDARY_VARIANTS: &[CorpusVariant] = &[CorpusVariant::Canonical, CorpusVariant::LargeValue];

#[derive(Clone, Copy)]
pub(crate) struct FixtureBinding {
    pub(crate) kind: ConfigKind,
    pub(crate) path: &'static str,
    pub(crate) case_id: &'static str,
    pub(crate) sha256: &'static str,
    pub(crate) bytes: &'static [u8],
    pub(crate) rule_count: u16,
    pub(crate) http_accepts: bool,
}

pub(crate) fn fixture_bindings() -> [FixtureBinding; 4] {
    [
        FixtureBinding {
            kind: ConfigKind::Cors,
            path: "conformance/fixtures/cors/one-hundred-rules.xml",
            case_id: "c-cors-0010",
            sha256: "c248351230630ceec7b691fc3b627358c048ffd81d38fa1c46372a732d4fc62e",
            bytes: CORS_100,
            rule_count: 100,
            http_accepts: true,
        },
        FixtureBinding {
            kind: ConfigKind::Cors,
            path: "conformance/fixtures/cors/hundred-and-one-rules.xml",
            case_id: "c-cors-0023",
            sha256: "fac97360ccd3634249fa3480b26285dfcbc459a7f88abae55e19f30558598f6f",
            bytes: CORS_101,
            rule_count: 101,
            http_accepts: false,
        },
        FixtureBinding {
            kind: ConfigKind::Lifecycle,
            path: "conformance/fixtures/lifecycle/one-thousand-rules.xml",
            case_id: "c-lifecycle-0012",
            sha256: "8474db2e2aa4e1e1bfee638c2447e5d5bc069e412693e214969f0d2f896dc606",
            bytes: LIFECYCLE_1000,
            rule_count: 1000,
            http_accepts: true,
        },
        FixtureBinding {
            kind: ConfigKind::Lifecycle,
            path: "conformance/fixtures/lifecycle/thousand-and-one-rules.xml",
            case_id: "c-lifecycle-0026",
            sha256: "44d626c690670ab97f5182b855e9832e923832833a1b9f0b168a105bf1d1849c",
            bytes: LIFECYCLE_1001,
            rule_count: 1001,
            http_accepts: false,
        },
    ]
}

fn origin(binding: FixtureBinding) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(a) gateway physical conformance fixture".to_owned(),
        producer: binding.path.to_owned(),
        version: binding.case_id.to_owned(),
        sha256: binding.sha256.to_owned(),
    }
}

fn boundary_notes(binding: FixtureBinding) -> String {
    let verdict = if binding.http_accepts { "accepts" } else { "rejects" };
    format!(
        "{} physical fixture with {} rules; HTTP case {} the write while persistence migration remains byte-preserving",
        binding.case_id, binding.rule_count, verdict
    )
}

pub(crate) fn cors_cases() -> Vec<(GoldenSample<PersistedCorsConfiguration>, &'static [CorpusVariant])> {
    fixture_bindings()
        .into_iter()
        .filter(|binding| binding.kind == ConfigKind::Cors)
        .map(|binding| {
            let cors_rules = (0..binding.rule_count)
                .map(|index| PersistedCorsRule {
                    allowed_methods: vec!["GET".to_owned()],
                    allowed_origins: vec![format!("https://origin-{index:04}.example.com")],
                    id: Some(format!("rule-{index:04}")),
                    ..PersistedCorsRule::default()
                })
                .collect();
            (
                GoldenSample {
                    kind: ConfigKind::Cors,
                    bytes: binding.bytes.to_vec(),
                    value: PersistedCorsConfiguration { cors_rules },
                    origin: origin(binding),
                    notes: boundary_notes(binding),
                },
                BOUNDARY_VARIANTS,
            )
        })
        .collect()
}

pub(crate) fn lifecycle_cases() -> Vec<AcceptedCorpusCase<PersistedLifecycleConfiguration>> {
    fixture_bindings()
        .into_iter()
        .filter(|binding| binding.kind == ConfigKind::Lifecycle)
        .map(|binding| {
            let rules = (0..binding.rule_count)
                .map(|index| PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: None,
                    del_marker_expiration: None,
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(i32::from(index) + 1),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: Some(PersistedLifecycleFilter {
                        prefix: Some(format!("p{index:04}/")),
                        ..PersistedLifecycleFilter::default()
                    }),
                    id: Some(format!("r{index:04}")),
                    noncurrent_version_expiration: None,
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                })
                .collect();
            AcceptedCorpusCase {
                sample: GoldenSample {
                    kind: ConfigKind::Lifecycle,
                    bytes: binding.bytes.to_vec(),
                    value: PersistedLifecycleConfiguration {
                        expiry_updated_at: None,
                        rules,
                    },
                    origin: origin(binding),
                    notes: boundary_notes(binding),
                },
                variants: vec![CorpusVariant::Canonical, CorpusVariant::LargeValue],
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn all_four_physical_boundary_fixtures_are_registered() {
        let fixtures = fixture_bindings();
        assert_eq!(fixtures.len(), 4);
        for fixture in fixtures {
            assert_eq!(hex::encode(Sha256::digest(fixture.bytes)), fixture.sha256, "{}", fixture.path);
        }
        assert_eq!(
            fixtures.map(|fixture| fixture.case_id),
            ["c-cors-0010", "c-cors-0023", "c-lifecycle-0012", "c-lifecycle-0026"]
        );
        assert_eq!(fixtures.map(|fixture| fixture.rule_count), [100, 101, 1000, 1001]);
        assert_eq!(fixtures.map(|fixture| fixture.http_accepts), [true, false, true, false]);
    }

    #[test]
    fn all_four_physical_fixtures_are_registered_in_their_family_corpora() {
        assert_eq!(cors_cases().len(), 2);
        assert_eq!(lifecycle_cases().len(), 2);
    }
}
