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

//! Fail-closed tests for per-revision oracle admission.
//!
//! Responsible for: proving the real observation of all three revisions, and that every
//! validation rejection fires on a synthetic registry or a relabelled observation.
//! NOT responsible for: family D1-D5 assertions.
//! Upstream: `super`. Downstream: none; test-only.
//!
//! Since rustfs/gateway#740 no real refusal boundary moves, so every rejection that needs a moved
//! boundary is proved on one synthetic divergence added to the real observations.

use std::sync::OnceLock;

use super::*;

fn observations() -> &'static [OracleObservation] {
    static OBSERVATIONS: OnceLock<Vec<OracleObservation>> = OnceLock::new();
    OBSERVATIONS.get_or_init(|| {
        OracleRevision::ALL
            .into_iter()
            .map(observe)
            .collect::<Result<Vec<_>, _>>()
            .expect("every revision runs the whole corpus")
    })
}

/// A moved boundary under the two newer revisions, for the rejections the real corpus no longer
/// produces.
const SYNTHETIC: OracleFinding = OracleFinding {
    id: "synthetic-moved-refusal",
    revisions: &[OracleRevision::Rollback, OracleRevision::Candidate],
    kind: ConfigKind::BucketEncryption,
    sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    old: OldReading::Read,
    tracking: "https://github.com/rustfs/gateway/issues/0",
};

fn synthetic_divergence() -> OracleDivergence {
    OracleDivergence {
        kind: SYNTHETIC.kind,
        sha256: SYNTHETIC.sha256.to_owned(),
        old: OldReading::Read,
    }
}

/// The real observations with the synthetic divergence under the revisions it names.
fn moved() -> Vec<OracleObservation> {
    observations()
        .iter()
        .map(|observation| {
            let mut observation = observation.clone();
            if SYNTHETIC.revisions.contains(&observation.oracle) {
                observation.divergences.push(synthetic_divergence());
            }
            observation
        })
        .collect()
}

fn relabelled(from: OracleRevision, to: OracleRevision) -> Vec<OracleObservation> {
    let source = observations()
        .iter()
        .find(|observation| observation.oracle == from)
        .expect("every revision is observed")
        .clone();
    observations()
        .iter()
        .map(|observation| {
            if observation.oracle == to {
                OracleObservation {
                    oracle: to,
                    ..source.clone()
                }
            } else {
                observation.clone()
            }
        })
        .collect()
}

fn bucket_encryption(observation: &OracleObservation) -> &crate::FourWayFamilyReport {
    observation
        .four_way
        .families
        .iter()
        .find(|family| family.kind == ConfigKind::BucketEncryption)
        .expect("the family is executed")
}

/// rustfs/gateway#740 is closed: no revision moves a refusal boundary, the baseline widens the two
/// `BlockedEncryptionTypes` samples it predates, the two newer revisions run them through D1-D5,
/// and strict admission holds.
#[test]
fn every_revision_runs_the_whole_corpus_and_no_refusal_boundary_moves() {
    let report = validate(observations(), &FINDINGS).expect("the observations match the empty registry");
    assert_eq!(report.observations().len(), 3);
    let (baseline, later) = report.observations().split_first().expect("three observations");
    assert_eq!(baseline.oracle, OracleRevision::Baseline);
    assert_eq!(baseline.four_way.widened_count, 2);
    assert_eq!(bucket_encryption(baseline).widened, 2);
    for observation in report.observations() {
        assert_eq!(observation.four_way.families.len(), 13, "{}", observation.oracle);
        assert!(observation.rejected_reread > 100, "{}", observation.oracle);
        assert!(observation.divergences.is_empty(), "{}", observation.oracle);
    }
    for observation in later {
        assert_eq!(observation.four_way.widened_count, 0, "{}", observation.oracle);
        assert_eq!(
            observation.four_way.sample_count,
            baseline.four_way.sample_count + 2,
            "{}",
            observation.oracle
        );
    }
    assert!(report.open_findings().is_empty());
    assert_eq!(admission_verdict(report.clone()), Ok(report));
}

#[test]
fn n_open_findings_hold_strict_admission() {
    let report = validate(&moved(), &[SYNTHETIC]).expect("the synthetic finding is registered");
    assert_eq!(
        admission_verdict(report).expect_err("an open finding holds admission"),
        OracleAdmissionError::FindingsOpen(vec![
            (OracleRevision::Rollback, SYNTHETIC.id, SYNTHETIC.tracking),
            (OracleRevision::Candidate, SYNTHETIC.id, SYNTHETIC.tracking),
        ])
    );
}

#[test]
fn n_an_unregistered_moved_refusal_is_refused() {
    assert_eq!(
        validate(&moved(), &[]),
        Err(OracleAdmissionError::UnregisteredDivergence {
            oracle: OracleRevision::Rollback,
            divergence: synthetic_divergence(),
        })
    );
}

/// Both directions: a finding its revision does not reproduce is stale, and so is the #740
/// finding shape once the real corpus stopped reproducing it.
#[test]
fn n_a_finding_its_revision_does_not_reproduce_is_stale() {
    let registry = [OracleFinding {
        revisions: &[OracleRevision::Baseline, OracleRevision::Rollback, OracleRevision::Candidate],
        ..SYNTHETIC
    }];
    assert_eq!(
        validate(&moved(), &registry),
        Err(OracleAdmissionError::StaleFinding {
            oracle: OracleRevision::Baseline,
            id: SYNTHETIC.id,
        })
    );
    assert_eq!(
        validate(observations(), &[SYNTHETIC]),
        Err(OracleAdmissionError::StaleFinding {
            oracle: OracleRevision::Rollback,
            id: SYNTHETIC.id,
        })
    );
}

/// A selector stuck on the baseline would observe the baseline's widenings under a later
/// revision; the per-revision rule refuses them.
#[test]
fn n_a_selector_stuck_on_the_baseline_cannot_pass() {
    let stuck = relabelled(OracleRevision::Baseline, OracleRevision::Rollback);
    assert_eq!(
        validate(&stuck, &FINDINGS),
        Err(OracleAdmissionError::WideningDrift {
            oracle: OracleRevision::Rollback,
            kind: ConfigKind::BucketEncryption,
            expected: 0,
            found: 2,
        })
    );
}

/// A baseline that counted its widenings as D1-D5 passes keeps the same total but is refused.
#[test]
fn n_a_widening_counted_as_a_d1_to_d5_pass_is_refused() {
    let mut faked = observations().to_vec();
    let family = faked[0]
        .four_way
        .families
        .iter_mut()
        .find(|family| family.kind == ConfigKind::BucketEncryption)
        .expect("the family is executed");
    family.sample_count += family.widened;
    family.widened = 0;
    assert_eq!(
        validate(&faked, &FINDINGS),
        Err(OracleAdmissionError::WideningDrift {
            oracle: OracleRevision::Baseline,
            kind: ConfigKind::BucketEncryption,
            expected: 2,
            found: 0,
        })
    );
}

/// The registry names the exact reading; one that differs from the observation is refused.
#[test]
fn n_a_registered_reading_that_differs_is_a_mismatch() {
    let registry = [OracleFinding {
        old: OldReading::Refused,
        ..SYNTHETIC
    }];
    assert_eq!(
        validate(&moved(), &registry),
        Err(OracleAdmissionError::ReadingMismatch {
            oracle: OracleRevision::Rollback,
            id: SYNTHETIC.id,
            registered: OldReading::Refused,
            observed: OldReading::Read,
        })
    );
}

#[test]
fn n_a_revision_that_skips_samples_is_refused() {
    let mut drifted = observations().to_vec();
    drifted[2].four_way.families[0].sample_count -= 1;
    assert!(matches!(
        validate(&drifted, &FINDINGS),
        Err(OracleAdmissionError::SampleCountDrift {
            oracle: OracleRevision::Candidate,
            ..
        })
    ));
}

#[test]
fn n_a_missing_or_repeated_revision_is_refused() {
    assert_eq!(
        validate(&observations()[..2], &FINDINGS),
        Err(OracleAdmissionError::RevisionNotObservedOnce(OracleRevision::Candidate))
    );
    let repeated = relabelled(OracleRevision::Rollback, OracleRevision::Candidate)
        .into_iter()
        .map(|observation| OracleObservation {
            oracle: if observation.oracle == OracleRevision::Candidate {
                OracleRevision::Rollback
            } else {
                observation.oracle
            },
            ..observation
        })
        .collect::<Vec<_>>();
    assert_eq!(
        validate(&repeated, &FINDINGS),
        Err(OracleAdmissionError::RevisionNotObservedOnce(OracleRevision::Rollback))
    );
}

#[test]
fn render_names_every_revision_build_widening_and_finding() {
    let text = validate(observations(), &FINDINGS).expect("valid observations").render();
    assert!(text.starts_with("oracle admission: revisions=3 open-findings=0\n"), "{text}");
    for (oracle, widened) in OracleRevision::ALL.into_iter().zip([2, 0, 0]) {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("oracle {oracle} build={}: d1-d5 samples=", oracle.rustfs_build())))
            .unwrap_or_else(|| panic!("missing {oracle} in {text}"));
        assert!(line.contains(&format!(" widened={widened} families=13 ")), "{line}");
    }
    assert!(!text.contains("finding "), "{text}");

    let text = validate(&moved(), &[SYNTHETIC]).expect("registered").render();
    assert!(text.starts_with("oracle admission: revisions=3 open-findings=2\n"), "{text}");
    for oracle in ["rollback s3s@bdcb6259", "candidate s3s@f3e17541"] {
        assert!(
            text.contains(&format!(
                "finding synthetic-moved-refusal oracle={oracle} family=bucket-encryption sample={} old=reads new=refuses tracking={}\n",
                SYNTHETIC.sha256, SYNTHETIC.tracking
            )),
            "{text}"
        );
    }
}
