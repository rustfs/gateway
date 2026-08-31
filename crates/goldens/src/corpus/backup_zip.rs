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

//! Backup-archive evidence over the exact accepted persistence corpus.
//!
//! Responsible for: proving that ZIP export/import preserves every accepted XML byte and that the
//! same samples remain readable in both migration directions. NOT responsible for: RustFS admin
//! routing, disk IO, or defining family codecs and samples. Upstream: concrete corpus evidence and
//! the D1-D5 aggregate runner. Downstream: P9 rollback and disaster-recovery acceptance cases.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read, Write},
};

use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use super::{CorpusDisposition, CorpusVariant};
use crate::{ConfigKind, all_family_corpus_evidence, run_four_way_all};

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupCase {
    path: String,
    kind: ConfigKind,
    bytes: Vec<u8>,
    variants: Vec<CorpusVariant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupCompatibilityReport {
    old_to_new_samples: usize,
    new_to_old_samples: usize,
    unknown_element_samples: usize,
    family_count: usize,
    archive_size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BackupArchiveError {
    Evidence(String),
    FourWay(String),
    MissingFamily(ConfigKind),
    DuplicatePath(String),
    Archive(String),
    MissingEntry(String),
    UnexpectedEntry(String),
    ByteMismatch(String),
    SampleCountMismatch { corpus: usize, four_way: usize },
    MissingUnknownElementSample,
}

impl fmt::Display for BackupArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => write!(formatter, "corpus evidence failed: {error}"),
            Self::FourWay(error) => write!(formatter, "D1-D5 execution failed: {error}"),
            Self::MissingFamily(kind) => write!(formatter, "{} is missing from the backup", kind.report_name()),
            Self::DuplicatePath(path) => write!(formatter, "duplicate backup path {path}"),
            Self::Archive(error) => write!(formatter, "backup archive failed: {error}"),
            Self::MissingEntry(path) => write!(formatter, "backup entry {path} is missing"),
            Self::UnexpectedEntry(path) => write!(formatter, "backup entry {path} was not exported"),
            Self::ByteMismatch(path) => write!(formatter, "backup entry {path} changed bytes"),
            Self::SampleCountMismatch { corpus, four_way } => {
                write!(formatter, "backup corpus has {corpus} samples but D1-D5 executed {four_way}")
            }
            Self::MissingUnknownElementSample => write!(formatter, "backup has no accepted unknown-element sample"),
        }
    }
}

fn collect_backup_cases() -> Result<Vec<BackupCase>, BackupArchiveError> {
    let families = all_family_corpus_evidence().map_err(|error| BackupArchiveError::Evidence(error.to_string()))?;
    let mut cases = Vec::new();
    for family in families {
        for case in family.cases {
            if case.disposition != CorpusDisposition::Accepted {
                continue;
            }
            cases.push(BackupCase {
                path: format!("{}/{}.xml", case.kind.report_name(), case.origin.sha256),
                kind: case.kind,
                bytes: case.bytes,
                variants: case.variants,
            });
        }
    }
    Ok(cases)
}

fn write_backup_archive(cases: &[BackupCase]) -> Result<Vec<u8>, BackupArchiveError> {
    for kind in ConfigKind::ALL {
        if !cases.iter().any(|case| case.kind == kind) {
            return Err(BackupArchiveError::MissingFamily(kind));
        }
    }
    let mut paths = BTreeSet::new();
    for case in cases {
        if !paths.insert(case.path.clone()) {
            return Err(BackupArchiveError::DuplicatePath(case.path.clone()));
        }
    }

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for case in cases {
        writer
            .start_file(&case.path, options)
            .map_err(|error| BackupArchiveError::Archive(error.to_string()))?;
        writer
            .write_all(&case.bytes)
            .map_err(|error| BackupArchiveError::Archive(error.to_string()))?;
    }
    writer
        .finish()
        .map(Cursor::into_inner)
        .map_err(|error| BackupArchiveError::Archive(error.to_string()))
}

fn read_backup_archive(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, BackupArchiveError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|error| BackupArchiveError::Archive(error.to_string()))?;
    let mut entries = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| BackupArchiveError::Archive(error.to_string()))?;
        if entry.is_dir() {
            return Err(BackupArchiveError::Archive(format!("{} is a directory", entry.name())));
        }
        let path = entry.name().to_owned();
        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .map_err(|error| BackupArchiveError::Archive(error.to_string()))?;
        if entries.insert(path.clone(), content).is_some() {
            return Err(BackupArchiveError::DuplicatePath(path));
        }
    }
    Ok(entries)
}

fn validate_backup_archive(bytes: &[u8], cases: &[BackupCase]) -> Result<(), BackupArchiveError> {
    let entries = read_backup_archive(bytes)?;
    let expected_paths = cases.iter().map(|case| case.path.as_str()).collect::<BTreeSet<_>>();
    for case in cases {
        let content = entries
            .get(&case.path)
            .ok_or_else(|| BackupArchiveError::MissingEntry(case.path.clone()))?;
        if content != &case.bytes {
            return Err(BackupArchiveError::ByteMismatch(case.path.clone()));
        }
    }
    if let Some(path) = entries.keys().find(|path| !expected_paths.contains(path.as_str())) {
        return Err(BackupArchiveError::UnexpectedEntry(path.clone()));
    }
    Ok(())
}

fn prove_backup_compatibility() -> Result<BackupCompatibilityReport, BackupArchiveError> {
    let four_way = run_four_way_all().map_err(|error| BackupArchiveError::FourWay(error.to_string()))?;
    let cases = collect_backup_cases()?;
    if cases.len() != four_way.sample_count {
        return Err(BackupArchiveError::SampleCountMismatch {
            corpus: cases.len(),
            four_way: four_way.sample_count,
        });
    }
    let archive = write_backup_archive(&cases)?;
    validate_backup_archive(&archive, &cases)?;
    let unknown_element_samples = cases
        .iter()
        .filter(|case| {
            case.variants.iter().any(|variant| {
                matches!(
                    variant,
                    CorpusVariant::UnknownTopLevel | CorpusVariant::UnknownNested | CorpusVariant::UnknownAttribute
                )
            })
        })
        .count();
    if unknown_element_samples == 0 {
        return Err(BackupArchiveError::MissingUnknownElementSample);
    }
    Ok(BackupCompatibilityReport {
        old_to_new_samples: cases.len(),
        new_to_old_samples: cases.len(),
        unknown_element_samples,
        family_count: four_way.families.len(),
        archive_size: archive.len(),
    })
}

#[cfg(test)]
mod tests {
    use crate::ConfigKind;

    use super::{
        BackupArchiveError, collect_backup_cases, prove_backup_compatibility, read_backup_archive, validate_backup_archive,
        write_backup_archive,
    };

    #[test]
    fn g_zip_001_old_archive_is_new_readable_and_byte_exact() {
        let report = prove_backup_compatibility().expect("old backup bytes remain new-readable");
        assert_eq!(report.old_to_new_samples, 135);
        assert_eq!(report.family_count, 13);
    }

    #[test]
    fn g_zip_002_new_archive_is_old_readable_after_rollback() {
        let report = prove_backup_compatibility().expect("new backup bytes remain old-readable");
        assert_eq!(report.new_to_old_samples, 135);
        assert!(report.archive_size > 0);
    }

    #[test]
    fn g_zip_003_unknown_elements_survive_both_import_directions() {
        let report = prove_backup_compatibility().expect("old-readable unknown elements survive the archive");
        assert!(report.unknown_element_samples > 0);
    }

    #[test]
    fn n_a_corrupt_zip_is_rejected_before_it_can_count_as_compatibility() {
        let cases = collect_backup_cases().expect("the checked-in corpus is complete");
        let mut archive = write_backup_archive(&cases).expect("the checked-in corpus archives");
        archive[0] ^= 0xff;
        assert!(read_backup_archive(&archive).is_err());
    }

    #[test]
    fn n_a_missing_family_is_not_a_thirteen_family_backup() {
        let mut cases = collect_backup_cases().expect("the checked-in corpus is complete");
        cases.retain(|case| case.kind != ConfigKind::Replication);
        let error = write_backup_archive(&cases).expect_err("a missing family must fail closed");
        assert!(error.to_string().contains("replication"));
    }

    #[test]
    fn n_a_duplicate_archive_path_is_rejected_instead_of_overwritten() {
        let mut cases = collect_backup_cases().expect("the checked-in corpus is complete");
        cases.push(cases[0].clone());
        let error = write_backup_archive(&cases).expect_err("a duplicate path must fail closed");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn n_a_valid_zip_with_changed_payload_is_rejected() {
        let cases = collect_backup_cases().expect("the checked-in corpus is complete");
        let mut changed_cases = cases.clone();
        changed_cases[0].bytes.push(b' ');
        let archive = write_backup_archive(&changed_cases).expect("changed bytes still form a valid ZIP archive");
        let error = validate_backup_archive(&archive, &cases).expect_err("changed persisted XML must fail closed");
        assert!(matches!(error, BackupArchiveError::ByteMismatch(_)));
    }
}
