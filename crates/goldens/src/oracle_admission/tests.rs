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
//! validation rejection fires on a synthetic registry or a relabelled observation. NOT
//! responsible for: family D1-D5 assertions. Upstream: `super`. Downstream: none; test-only.

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

fn blocked_encryption_types() -> OracleDivergence {
    OracleDivergence {
        kind: ConfigKind::BucketEncryption,
        sha256: FINDINGS[0].sha256.to_owned(),
        old: OldReading::ReadUnrepresented("BlockedEncryptionTypes"),
    }
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

#[test]
fn every_revision_runs_the_whole_corpus_and_only_the_registered_boundary_moves() {
    let report = validate(observations(), &FINDINGS).expect("the observations match the registry");
    let baseline_count = run_four_way_all().expect("baseline D1-D5 passes").sample_count;
    assert_eq!(report.observations().len(), 3);
    for observation in report.observations() {
        assert_eq!(observation.four_way.sample_count, baseline_count, "{}", observation.oracle);
        assert_eq!(observation.four_way.families.len(), 13, "{}", observation.oracle);
        assert!(observation.rejected_reread > 100, "{}", observation.oracle);
    }
    assert_eq!(report.observations()[0].oracle, OracleRevision::Baseline);
    assert!(report.observations()[0].divergences.is_empty());
    for observation in &report.observations()[1..] {
        assert_eq!(observation.divergences, [blocked_encryption_types()], "{}", observation.oracle);
    }
    assert_eq!(
        report.open_findings(),
        [
            (OracleRevision::Rollback, FINDINGS[0]),
            (OracleRevision::Candidate, FINDINGS[0])
        ]
    );
}

#[test]
fn n_open_findings_hold_strict_admission() {
    // The CLI test drives `require_oracle_admission` end to end; this reuses the shared
    // observations so the crate stays inside its verify budget.
    let report = validate(observations(), &FINDINGS).expect("valid observations");
    let error = admission_verdict(report).expect_err("rustfs/gateway#740 is open");
    assert_eq!(
        error,
        OracleAdmissionError::FindingsOpen(vec![
            (OracleRevision::Rollback, FINDINGS[0].id, FINDINGS[0].tracking),
            (OracleRevision::Candidate, FINDINGS[0].id, FINDINGS[0].tracking),
        ])
    );
}

#[test]
fn a_report_without_open_findings_is_admitted() {
    let baseline_only = relabelled(OracleRevision::Baseline, OracleRevision::Rollback);
    let baseline_only = baseline_only
        .into_iter()
        .map(|observation| OracleObservation {
            divergences: Vec::new(),
            ..observation
        })
        .collect::<Vec<_>>();
    let report = validate(&baseline_only, &[]).expect("no revision moved a boundary");
    assert!(report.open_findings().is_empty());
    assert_eq!(admission_verdict(report.clone()), Ok(report));
}

#[test]
fn n_an_unregistered_moved_refusal_is_refused() {
    assert_eq!(
        validate(observations(), &[]),
        Err(OracleAdmissionError::UnregisteredDivergence {
            oracle: OracleRevision::Rollback,
            divergence: blocked_encryption_types(),
        })
    );
}

#[test]
fn n_a_finding_its_revision_does_not_reproduce_is_stale() {
    let registry = [OracleFinding {
        revisions: &[OracleRevision::Baseline, OracleRevision::Rollback, OracleRevision::Candidate],
        ..FINDINGS[0]
    }];
    assert_eq!(
        validate(observations(), &registry),
        Err(OracleAdmissionError::StaleFinding {
            oracle: OracleRevision::Baseline,
            id: FINDINGS[0].id,
        })
    );
}

/// A selector stuck on the baseline would observe the baseline boundary under every revision;
/// the registered finding then goes stale instead of silently passing.
#[test]
fn n_a_selector_stuck_on_the_baseline_cannot_pass() {
    let stuck = relabelled(OracleRevision::Baseline, OracleRevision::Rollback);
    assert_eq!(
        validate(&stuck, &FINDINGS),
        Err(OracleAdmissionError::StaleFinding {
            oracle: OracleRevision::Rollback,
            id: FINDINGS[0].id,
        })
    );
}

/// An adapter that dropped the member would report a plain read; the registry names the exact
/// reading, so the dropped member shows up as a mismatch.
#[test]
fn n_a_dropped_member_is_a_reading_mismatch() {
    let registry = [OracleFinding {
        old: OldReading::Read,
        ..FINDINGS[0]
    }];
    assert_eq!(
        validate(observations(), &registry),
        Err(OracleAdmissionError::ReadingMismatch {
            oracle: OracleRevision::Rollback,
            id: FINDINGS[0].id,
            registered: OldReading::Read,
            observed: OldReading::ReadUnrepresented("BlockedEncryptionTypes"),
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
fn render_names_every_revision_build_and_finding() {
    let text = validate(observations(), &FINDINGS).expect("valid observations").render();
    assert!(text.starts_with("oracle admission: revisions=3 open-findings=2\n"), "{text}");
    for oracle in OracleRevision::ALL {
        assert!(
            text.contains(&format!("oracle {oracle} build={}: d1-d5 samples=", oracle.rustfs_build())),
            "{text}"
        );
    }
    for oracle in ["rollback s3s@bdcb6259", "candidate s3s@f3e17541"] {
        assert!(
            text.contains(&format!(
                "finding bucket-encryption-blocked-encryption-types oracle={oracle} family=bucket-encryption sample={} old=reads unrepresented member BlockedEncryptionTypes new=refuses tracking=https://github.com/rustfs/gateway/issues/740\n",
                FINDINGS[0].sha256
            )),
            "{text}"
        );
    }
}
