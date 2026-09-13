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

//! Mutations of the historical-writer capture census.
//! Responsible for: proving missing writers, fields, bytes, and source receipts fail closed.
//! NOT responsible for: producing samples or substituting request status for persisted evidence.
//! Upstream: the capture validator. Downstream: the historical writer admission gate.

use super::*;

#[test]
fn all_observed_nonempty_exports_run_d1_to_d5() {
    let captures = captures().expect("the six stopped-writer receipts are valid");
    assert_eq!(captures.iter().map(|capture| capture.configurations.len()).sum::<usize>(), 91);
    assert_eq!(
        captures
            .iter()
            .flat_map(|capture| &capture.configurations)
            .filter(|row| row.raw_size > 0)
            .count(),
        62
    );
    let mut families = crate::base_family_corpus_evidence().expect("the existing corpus builds");
    let counts = append(&mut families).expect("every nonempty persisted observation passes D1-D5");
    assert!(counts.iter().map(|(_, count)| count).sum::<usize>() > 0);
}

#[test]
fn n_missing_writer_fails_closed() {
    let mut mutant = captures().unwrap();
    let version = mutant[0].version.clone();
    mutant.retain(|capture| capture.version != version);
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_duplicate_capture_fails_closed() {
    let mut mutant = captures().unwrap();
    mutant.push(mutant[0].clone());
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_missing_configuration_observation_fails_closed() {
    let mut mutant = captures().unwrap();
    mutant[0].configurations.pop();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_duplicate_configuration_observation_fails_closed() {
    let mut mutant = captures().unwrap();
    let duplicate = mutant[0].configurations[0].clone();
    mutant[0].configurations.push(duplicate);
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_changed_raw_digest_fails_closed() {
    let mut mutant = captures().unwrap();
    mutant[0].configurations[0].raw_sha256 = "0".repeat(64);
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_nonempty_export_cannot_be_marked_empty() {
    let mut mutant = captures().unwrap();
    let row = mutant[0].configurations.iter_mut().find(|row| row.raw_size > 0).unwrap();
    row.raw_size = 0;
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_changed_source_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].source_bytes_unchanged = false;
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_unstopped_writer_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].stop_exit_code = 1;
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_unknown_writer_version_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].version = "1.0.0-alpha.63".to_owned();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_unpinned_artifact_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].artifact = serde_json::json!({"image": "rustfs/rustfs:latest"});
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_error_response_cannot_claim_request_success() {
    let mut mutant = captures().unwrap();
    let row = mutant[0]
        .configurations
        .iter_mut()
        .find(|row| row.error_code.is_some())
        .unwrap();
    row.api_status = 200;
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_missing_source_measurements_fail_closed() {
    let mut mutant = captures().unwrap();
    mutant[0].source_files_before.clear();
    mutant[0].source_files_after.clear();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_changed_source_measurement_fails_closed() {
    let mut mutant = captures().unwrap();
    *mutant[0].source_files_after.values_mut().next().unwrap() = "0".repeat(64);
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_unpinned_runtime_commit_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].runtime_commit = "latest".to_owned();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_unpinned_exporter_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].exporter_sha256.clear();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_missing_raw_metadata_identity_is_not_admitted() {
    let mut mutant = captures().unwrap();
    mutant[0].configurations[0].metadata_sha256.clear();
    assert!(validate(&mutant).is_err());
}

#[test]
fn n_compatibility_failure_is_not_admitted() {
    let captures = captures().unwrap();
    let capture = &captures[0];
    let configuration = capture.configurations.iter().find(|row| row.kind == "versioning").unwrap();
    let sample = GoldenSample {
        kind: ConfigKind::Versioning,
        bytes: bytes(configuration).unwrap().to_vec(),
        value: (),
        origin: SampleOrigin {
            source: SOURCE.to_owned(),
            producer: capture.writer.clone(),
            version: capture.version.clone(),
            sha256: configuration.raw_sha256.clone(),
        },
        notes: "A forced codec refusal must stop admission.".to_owned(),
    };
    let mut families = crate::base_family_corpus_evidence().unwrap();
    assert!(accept(sample, |_| Err(input_failure("forced D1-D5 failure")), &mut families).is_err());
}
