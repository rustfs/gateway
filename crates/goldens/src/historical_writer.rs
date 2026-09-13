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

//! Historical writer admission and byte-exact persistence evidence.
//!
//! Responsible for: checking six stopped-writer receipts, deduplicating their raw XML, and
//! executing every nonempty observation through D1-D5, including writes that returned an error.
//! NOT responsible for: treating unsupported or empty exports as passing configuration samples.
//! Upstream: the committed capture manifest and raw exports. Downstream: corpus and source gates.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_types::compat::{
    parse_s3s_accelerate, parse_s3s_bucket_encryption, parse_s3s_bucket_logging, parse_s3s_cors, parse_s3s_lifecycle,
    parse_s3s_notification, parse_s3s_object_lock, parse_s3s_public_access_block, parse_s3s_replication,
    parse_s3s_request_payment, parse_s3s_tagging, parse_s3s_versioning, parse_s3s_website,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{ConfigKind, CorpusVariant, Direction, FamilyCorpusEvidence, GoldenFailure, GoldenSample, SampleOrigin};

mod data;
pub(crate) use data::REGISTRATIONS;

const MANIFEST: &str = include_str!("../corpus/historical-writers/manifest.json");
const MANIFEST_SHA256: &str = "96079278c47e7803a154662ec26e9907ff8e0c742fe9e89ddc80e377cf9967a9";
const SOURCE: &str = "crates/goldens/corpus/historical-writers/manifest.json";
pub(crate) const EXPECTED_WRITERS: [(&str, &str); 6] = [
    ("rustfs", "1.0.0-alpha.64"),
    ("rustfs", "1.0.0-alpha.94"),
    ("rustfs", "v1.0.0-beta.1"),
    ("rustfs", "1.0.0-beta.12"),
    ("minio", "RELEASE.2025-04-22T22-12-26Z"),
    ("minio", "RELEASE.2025-09-07T16-13-09Z"),
];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    id: String,
    writer: String,
    version: String,
    runtime_commit: String,
    runtime_version_sha256: String,
    artifact: serde_json::Value,
    exporter_sha256: String,
    capture_script_sha256: String,
    stopped_at: String,
    stop_exit_code: i32,
    source_bytes_unchanged: bool,
    source_files_before: BTreeMap<String, String>,
    source_files_after: BTreeMap<String, String>,
    configurations: Vec<Configuration>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    kind: String,
    api_status: u16,
    error_code: Option<String>,
    mc_exit_code: Option<i32>,
    raw_sha256: String,
    raw_size: usize,
    metadata_sha256: String,
}

pub(crate) fn input_failure(reason: impl ToString) -> GoldenFailure {
    GoldenFailure {
        direction: Direction::Input,
        offset: None,
        left: "historical writer matrix".to_owned(),
        right: reason.to_string(),
    }
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn kind(name: &str) -> Result<ConfigKind, GoldenFailure> {
    match name {
        "cors" => Ok(ConfigKind::Cors),
        "lifecycle" => Ok(ConfigKind::Lifecycle),
        "versioning" => Ok(ConfigKind::Versioning),
        "object-lock" => Ok(ConfigKind::ObjectLock),
        "encryption" => Ok(ConfigKind::BucketEncryption),
        "tagging" => Ok(ConfigKind::Tagging),
        "website" => Ok(ConfigKind::Website),
        "accelerate" => Ok(ConfigKind::Accelerate),
        "request-payment" => Ok(ConfigKind::RequestPayment),
        "public-access-block" => Ok(ConfigKind::PublicAccessBlock),
        "logging" => Ok(ConfigKind::Logging),
        "replication" => Ok(ConfigKind::Replication),
        "notification" => Ok(ConfigKind::Notification),
        _ => Err(input_failure(format!("unknown configuration family {name}"))),
    }
}

fn bytes(configuration: &Configuration) -> Result<&'static [u8], GoldenFailure> {
    let raw = if configuration.raw_size == 0 {
        &[][..]
    } else {
        data::BLOBS
            .iter()
            .find(|(digest, _)| *digest == configuration.raw_sha256)
            .map(|(_, raw)| *raw)
            .ok_or_else(|| input_failure(format!("missing raw export {}", configuration.raw_sha256)))?
    };
    if raw.len() != configuration.raw_size || hex::encode(Sha256::digest(raw)) != configuration.raw_sha256 {
        return Err(input_failure(format!("raw export digest/size differs for {}", configuration.kind)));
    }
    Ok(raw)
}

fn captures() -> Result<Vec<Capture>, GoldenFailure> {
    parse(MANIFEST)
}

fn parse(manifest: &str) -> Result<Vec<Capture>, GoldenFailure> {
    if hex::encode(Sha256::digest(manifest.as_bytes())) != MANIFEST_SHA256 {
        return Err(input_failure("capture manifest digest differs"));
    }
    let captures: Vec<Capture> = serde_json::from_str(manifest).map_err(input_failure)?;
    validate(&captures)?;
    Ok(captures)
}

fn validate(captures: &[Capture]) -> Result<(), GoldenFailure> {
    let mut writers = BTreeSet::new();
    let mut runs = BTreeSet::new();
    for capture in captures {
        writers.insert((capture.writer.as_str(), capture.version.as_str()));
        if !runs.insert(capture.id.as_str()) {
            return Err(input_failure("duplicate historical capture receipt"));
        }
        if capture.id.is_empty()
            || capture.stopped_at.is_empty()
            || capture.stop_exit_code != 0
            || !capture.source_bytes_unchanged
        {
            return Err(input_failure("a stopped, unchanged source was not established"));
        }
        if capture.source_files_before.is_empty()
            || capture.source_files_before != capture.source_files_after
            || capture
                .source_files_before
                .iter()
                .any(|(path, digest)| path.is_empty() || !is_hex(digest, 64))
        {
            return Err(input_failure("source file digest measurements differ or are missing"));
        }
        if !is_hex(&capture.runtime_commit, 40)
            || [
                &capture.runtime_version_sha256,
                &capture.exporter_sha256,
                &capture.capture_script_sha256,
            ]
            .into_iter()
            .any(|digest| !is_hex(digest, 64))
        {
            return Err(input_failure("writer or exporter identity is not pinned"));
        }
        let artifact_pinned = capture
            .artifact
            .get("binary_sha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| is_hex(digest, 64))
            || capture
                .artifact
                .get("image")
                .and_then(serde_json::Value::as_str)
                .and_then(|image| image.split_once("@sha256:"))
                .is_some_and(|(_, digest)| is_hex(digest, 64));
        if !artifact_pinned {
            return Err(input_failure("writer artifact is not pinned"));
        }
        let mut kinds = BTreeSet::new();
        let mut nonempty = 0;
        for configuration in &capture.configurations {
            if !kinds.insert(kind(&configuration.kind)?.report_name()) {
                return Err(input_failure("duplicate configuration observation"));
            }
            if !is_hex(&configuration.metadata_sha256, 64) {
                return Err(input_failure("raw metadata identity is missing"));
            }
            let success = (200..300).contains(&configuration.api_status);
            if !(200..600).contains(&configuration.api_status) || success == configuration.error_code.is_some() {
                return Err(input_failure("request outcome receipt is inconsistent"));
            }
            nonempty += usize::from(!bytes(configuration)?.is_empty());
        }
        if kinds != BTreeSet::from(ConfigKind::ALL.map(|kind| kind.report_name())) || nonempty == 0 {
            return Err(input_failure("writer configuration census is incomplete"));
        }
    }
    if writers != BTreeSet::from(EXPECTED_WRITERS) {
        return Err(input_failure("the six historical writer versions are not all present"));
    }
    Ok(())
}

pub(crate) fn witness_matches(writer: &str, version: &str, digest: &str, family: ConfigKind) -> Result<bool, GoldenFailure> {
    Ok(captures()?.iter().any(|capture| {
        capture.writer == writer
            && capture.version == version
            && capture.configurations.iter().any(|configuration| {
                configuration.raw_size > 0 && configuration.raw_sha256 == digest && kind(&configuration.kind).ok() == Some(family)
            })
    }))
}

pub(crate) fn witness_set_matches(writer: &str, version: &str, digests: &[&str]) -> Result<bool, GoldenFailure> {
    let captures = captures()?;
    let expected = captures
        .iter()
        .filter(|capture| capture.writer == writer && capture.version == version)
        .flat_map(|capture| &capture.configurations)
        .filter(|row| row.raw_size > 0)
        .map(|row| row.raw_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let actual = digests.iter().copied().collect::<BTreeSet<_>>();
    Ok(actual.len() == digests.len() && actual == expected)
}

fn accept<T>(
    sample: GoldenSample<T>,
    check: fn(&GoldenSample<T>) -> Result<(), GoldenFailure>,
    families: &mut [FamilyCorpusEvidence],
) -> Result<bool, GoldenFailure> {
    check(&sample)?;
    let family = families
        .iter_mut()
        .find(|family| family.kind() == sample.kind)
        .ok_or_else(|| input_failure("the observed family is absent from the corpus"))?;
    if family
        .source_a_registrations()
        .iter()
        .any(|(_, digest, accepted)| *accepted && *digest == sample.origin.sha256)
    {
        return Ok(false);
    }
    family
        .push_accepted(&sample, &[CorpusVariant::Canonical])
        .map_err(input_failure)?;
    Ok(true)
}

/// Family charged with a failure of the capture manifest itself.
///
/// Callers report failures per family, and a manifest failure (digest pin, schema, census) has no
/// single family; the failure's own text names the historical writer matrix. Failures of one
/// observed field are charged to that field's real family instead.
pub(crate) const MANIFEST_FAILURE_FAMILY: ConfigKind = ConfigKind::Lifecycle;

/// Runs every nonempty historical export through D1-D5 and admits the unseen ones to `families`.
///
/// Returns the number of samples newly admitted per family. An export whose bytes are already in
/// the family is still executed, then counted as an alias rather than a second sample.
pub(crate) fn append(families: &mut [FamilyCorpusEvidence]) -> Result<Vec<(ConfigKind, usize)>, (ConfigKind, GoldenFailure)> {
    let mut counts = ConfigKind::ALL.map(|kind| (kind, 0));
    for capture in captures().map_err(|failure| (MANIFEST_FAILURE_FAMILY, failure))? {
        for configuration in &capture.configurations {
            let kind = kind(&configuration.kind).map_err(|failure| (MANIFEST_FAILURE_FAMILY, failure))?;
            let raw = bytes(configuration).map_err(|failure| (kind, failure))?;
            if raw.is_empty() {
                continue;
            }
            let origin = SampleOrigin {
                source: format!("{SOURCE}#{}-{}", capture.id, configuration.kind),
                producer: capture.writer.clone(),
                version: capture.version.clone(),
                sha256: configuration.raw_sha256.clone(),
            };
            macro_rules! observe {
                ($parse:ident, $check:ident) => {{
                    let value = $parse(raw).map_err(|error| (kind, input_failure(error)))?.structure;
                    accept(GoldenSample { kind, bytes: raw.to_vec(), value, origin,
                        notes: format!("Historical writer raw export; API status {}, mc exit {:?}. A nonempty export is evaluated independently of request success.", configuration.api_status, configuration.mc_exit_code),
                    }, crate::$check, families).map_err(|failure| (kind, failure))?
                }};
            }
            let added = match kind {
                ConfigKind::Cors => observe!(parse_s3s_cors, assert_cors_four_way),
                ConfigKind::Lifecycle => observe!(parse_s3s_lifecycle, assert_lifecycle_four_way),
                ConfigKind::Versioning => observe!(parse_s3s_versioning, assert_versioning_four_way),
                ConfigKind::ObjectLock => observe!(parse_s3s_object_lock, assert_object_lock_four_way),
                ConfigKind::BucketEncryption => observe!(parse_s3s_bucket_encryption, assert_bucket_encryption_four_way),
                ConfigKind::Tagging => observe!(parse_s3s_tagging, assert_tagging_four_way),
                ConfigKind::Website => observe!(parse_s3s_website, assert_website_four_way),
                ConfigKind::Accelerate => observe!(parse_s3s_accelerate, assert_accelerate_four_way),
                ConfigKind::RequestPayment => observe!(parse_s3s_request_payment, assert_request_payment_four_way),
                ConfigKind::PublicAccessBlock => observe!(parse_s3s_public_access_block, assert_public_access_block_four_way),
                ConfigKind::Logging => observe!(parse_s3s_bucket_logging, assert_bucket_logging_four_way),
                ConfigKind::Replication => observe!(parse_s3s_replication, assert_replication_four_way),
                ConfigKind::Notification => observe!(parse_s3s_notification, assert_notification_four_way),
            };
            let (_, count) = counts
                .iter_mut()
                .find(|(family, _)| *family == kind)
                .ok_or_else(|| (kind, input_failure("the observed family has no execution counter")))?;
            *count += usize::from(added);
        }
    }
    Ok(counts.to_vec())
}

#[cfg(test)]
mod tests;
