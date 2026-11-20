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

//! Shared four-way execution for byte-exact XML captured from a running writer.
//!
//! Responsible for: dispatching raw bytes to their typed oracle and counting each accepted digest once.
//! NOT responsible for: extracting data from RustFS volumes or validating historical capture receipts.
//! Upstream: historical writers and release/candidate disk exports. Downstream: four-way and corpus-report.

use crate::{ConfigKind, CorpusVariant, Direction, FamilyCorpusEvidence, GoldenFailure, GoldenSample, SampleOrigin};
use rustfs_gateway_types::compat::{
    parse_s3s_accelerate, parse_s3s_bucket_encryption, parse_s3s_bucket_logging, parse_s3s_cors, parse_s3s_lifecycle,
    parse_s3s_notification, parse_s3s_object_lock, parse_s3s_public_access_block, parse_s3s_replication,
    parse_s3s_request_payment, parse_s3s_tagging, parse_s3s_versioning, parse_s3s_website,
};

fn capture_failure(reason: impl ToString) -> GoldenFailure {
    GoldenFailure {
        direction: Direction::Input,
        offset: None,
        left: "captured XML".to_owned(),
        right: reason.to_string(),
    }
}

pub(crate) fn accept<T>(
    sample: GoldenSample<T>,
    check: fn(&GoldenSample<T>) -> Result<(), GoldenFailure>,
    families: &mut [FamilyCorpusEvidence],
) -> Result<bool, GoldenFailure> {
    check(&sample)?;
    let family = families
        .iter_mut()
        .find(|family| family.kind() == sample.kind)
        .ok_or_else(|| capture_failure("the observed family is absent from the corpus"))?;
    if family
        .source_a_registrations()
        .iter()
        .any(|(_, digest, accepted)| *accepted && *digest == sample.origin.sha256)
    {
        return Ok(false);
    }
    family
        .push_accepted(&sample, &[CorpusVariant::Canonical])
        .map_err(capture_failure)?;
    Ok(true)
}

pub(crate) fn observe(
    kind: ConfigKind,
    raw: &[u8],
    origin: SampleOrigin,
    notes: String,
    families: &mut [FamilyCorpusEvidence],
) -> Result<bool, GoldenFailure> {
    macro_rules! observe {
        ($parse:ident, $check:ident) => {{
            let value = $parse(raw).map_err(capture_failure)?.structure;
            accept(
                GoldenSample {
                    kind,
                    bytes: raw.to_vec(),
                    value,
                    origin,
                    notes,
                },
                crate::$check,
                families,
            )
        }};
    }
    match kind {
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
    }
}

pub(crate) fn append(families: &mut [FamilyCorpusEvidence]) -> Result<Vec<(ConfigKind, usize)>, (ConfigKind, GoldenFailure)> {
    let counts = crate::historical_writer::append(families)?;
    counts
        .into_iter()
        .map(|(kind, count)| {
            let added = crate::persistence_parity::observe(kind, families).map_err(|error| (kind, error))?;
            Ok((kind, count + usize::from(added)))
        })
        .collect()
}
