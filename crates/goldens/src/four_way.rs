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

//! Fail-closed aggregate execution of family-owned persistence assertions.
//!
//! Responsible for: collecting observed D1-D5 executions into a machine-readable report.
//! Not responsible for: defining codecs, fixtures, or coverage variants.
//! Upstream: each configuration module's concrete sample runner.
//! Downstream: the `four-way --all` migration gate.

use core::fmt;

use crate::{
    ConfigKind, GoldenFailure, accelerate_payment, bucket_encryption, cors, lifecycle, logging, minio_migration, notification,
    object_lock, public_access_block, replication, tagging, versioning, website,
};

type FamilyRunner = fn() -> Result<usize, GoldenFailure>;

fn run_accelerate() -> Result<usize, GoldenFailure> {
    let cases = accelerate_payment::accelerate_accepted_samples();
    for (sample, _) in &cases {
        crate::assert_accelerate_four_way(sample)?;
    }
    Ok(cases.len())
}

fn run_request_payment() -> Result<usize, GoldenFailure> {
    let cases = accelerate_payment::payment_accepted_samples();
    for (sample, _) in &cases {
        crate::assert_request_payment_four_way(sample)?;
    }
    Ok(cases.len())
}

/// One configuration family's observed D1-D5 execution count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FourWayFamilyReport {
    /// Persisted XML family that was executed.
    pub kind: ConfigKind,
    /// Number of concrete accepted samples that ran through all five directions.
    pub sample_count: usize,
}

/// Aggregate observations from a fail-closed four-way run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FourWayRunReport {
    /// Family reports in stable execution order.
    pub families: Vec<FourWayFamilyReport>,
    /// Total concrete samples executed through D1-D5.
    pub sample_count: usize,
}

/// First family-scoped failure observed by an aggregate four-way run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FourWayRunError {
    /// Configuration family whose concrete sample failed.
    pub kind: ConfigKind,
    /// Underlying input or D1-D5 failure.
    pub failure: GoldenFailure,
}

impl fmt::Display for FourWayRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind.report_name(), self.failure)
    }
}

impl std::error::Error for FourWayRunError {}

/// Executes the seven core/scalar configuration families against every concrete accepted sample.
///
/// # Errors
///
/// Returns the first family-scoped input or D1-D5 failure. A missing family therefore cannot be
/// rendered as a successful report.
pub fn run_four_way_core_shard() -> Result<FourWayRunReport, FourWayRunError> {
    let runners: [(ConfigKind, FamilyRunner); 7] = [
        (ConfigKind::Accelerate, run_accelerate),
        (ConfigKind::RequestPayment, run_request_payment),
        (ConfigKind::BucketEncryption, bucket_encryption::run_bucket_encryption_corpus_four_way),
        (
            ConfigKind::PublicAccessBlock,
            public_access_block::run_public_access_block_corpus_four_way,
        ),
        (ConfigKind::Versioning, versioning::run_versioning_corpus_four_way),
        (ConfigKind::ObjectLock, object_lock::run_object_lock_corpus_four_way),
        (ConfigKind::Lifecycle, lifecycle::run_lifecycle_corpus_four_way),
    ];
    let mut families = Vec::with_capacity(runners.len());
    for (kind, runner) in runners {
        let sample_count = runner().map_err(|failure| FourWayRunError { kind, failure })?;
        families.push(FourWayFamilyReport { kind, sample_count });
    }
    let sample_count = families.iter().map(|family| family.sample_count).sum();
    Ok(FourWayRunReport { families, sample_count })
}

/// Executes all thirteen persisted XML families against every concrete accepted sample.
///
/// # Errors
///
/// Returns the first family-scoped input or D1-D5 failure. The success report is therefore an
/// observation of every real family runner, not a static completeness declaration.
pub fn run_four_way_all() -> Result<FourWayRunReport, FourWayRunError> {
    let mut report = run_four_way_core_shard()?;
    let runners: [(ConfigKind, FamilyRunner); 6] = [
        (ConfigKind::Cors, cors::run_cors_corpus_four_way),
        (ConfigKind::Tagging, tagging::run_tagging_corpus_four_way),
        (ConfigKind::Notification, notification::run_notification_corpus_four_way),
        (ConfigKind::Logging, logging::run_bucket_logging_corpus_four_way),
        (ConfigKind::Website, website::run_website_corpus_four_way),
        (ConfigKind::Replication, replication::run_replication_corpus_four_way),
    ];
    for (kind, runner) in runners {
        let sample_count = runner().map_err(|failure| FourWayRunError { kind, failure })?;
        report.sample_count += sample_count;
        report.families.push(FourWayFamilyReport { kind, sample_count });
    }
    for (kind, sample_count) in minio_migration::run().map_err(|(kind, failure)| FourWayRunError { kind, failure })? {
        let family = report
            .families
            .iter_mut()
            .find(|family| family.kind == kind)
            .ok_or_else(|| FourWayRunError {
                kind,
                failure: GoldenFailure {
                    direction: crate::Direction::Input,
                    offset: None,
                    left: "registered aggregate family".to_owned(),
                    right: format!("{kind:?}"),
                },
            })?;
        family.sample_count += sample_count;
        report.sample_count += sample_count;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{run_four_way_all, run_four_way_core_shard};

    #[test]
    fn core_shard_executes_seven_real_families() {
        let report = run_four_way_core_shard().expect("all core persistence samples pass D1-D5");
        assert_eq!(report.families.len(), 7);
        assert_eq!(report.sample_count, 82);
        assert_eq!(
            report.sample_count,
            report.families.iter().map(|family| family.sample_count).sum::<usize>()
        );
        assert!(report.families.iter().all(|family| family.sample_count > 0));
    }

    #[test]
    fn all_families_execute_real_samples_through_d1_to_d5() {
        let report = run_four_way_all().expect("all persisted XML samples pass D1-D5");
        assert_eq!(report.families.len(), 13);
        assert_eq!(
            report.sample_count,
            report.families.iter().map(|family| family.sample_count).sum::<usize>()
        );
        assert!(report.families.iter().all(|family| family.sample_count > 0));
    }
}
