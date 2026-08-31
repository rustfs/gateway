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

//! Real MinIO-to-RustFS migrated persisted-XML evidence.
//!
//! Responsible for: running raw MinIO-written Lifecycle, Object Lock, and Replication bytes through D1-D5.
//! NOT responsible for: synthesizing variants or decoding the source `.metadata.bin` at test time.
//! Upstream: the RustFS real-MinIO migration fixture. Downstream: the aggregate persistence rollback gate.

use rustfs_gateway_types::{
    compat::{parse_s3s_lifecycle, parse_s3s_object_lock, parse_s3s_replication},
    persistence::{PersistedLifecycleConfiguration, PersistedObjectLockConfiguration, PersistedReplicationConfiguration},
};

use crate::{
    ConfigKind, Direction, GoldenFailure, GoldenSample, SampleOrigin, assert_lifecycle_four_way, assert_object_lock_four_way,
    assert_replication_four_way,
};

const SOURCE: &str = "https://github.com/rustfs/rustfs/blob/7df0920c801998d4f5e65776767d746f362a2975/crates/ecstore/tests/fixtures/minio/bucket_metadata.blob.hex";
const PRODUCER: &str = "MinIO";
const VERSION: &str = "RELEASE.2025-07-23T15-54-02Z";
const LIFECYCLE_SHA256: &str = "18887b7a076a3429d80f1a04fed3c772d296ec968d478d382f78cba01704d0fb";
const OBJECT_LOCK_SHA256: &str = "77ddad84d9aaa703c0f621f916484c7d8833fbb4f77fbeca2c4fc16a9b07522f";
const REPLICATION_SHA256: &str = "43f149b5afcdeac67f52059b4f15b604912b1627f2c0503e85aecef5a752ccad";
const LIFECYCLE: &[u8] = b"<LifecycleConfiguration><Rule><ID>d96i4g89k8h26a95st60</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Expiration><Days>30</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration></Rule><ExpiryUpdatedAt>2026-07-07T15:58:57.337315Z</ExpiryUpdatedAt></LifecycleConfiguration>";
const OBJECT_LOCK: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>7</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
const REPLICATION: &[u8] = b"<ReplicationConfiguration><Rule><ID>d96i4m09k8h2vldifkag</ID><Status>Enabled</Status><Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status></DeleteReplication><Destination><Bucket>arn:minio:replication::ef5859af-120a-4218-94b5-be23470f3c60:interop-dr</Bucket></Destination><SourceSelectionCriteria><ReplicaModifications><Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria><Filter><Prefix></Prefix></Filter><ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication></Rule><Role></Role></ReplicationConfiguration>";

fn sample<T>(kind: ConfigKind, bytes: &[u8], sha256: &str, value: T, notes: &str) -> GoldenSample<T> {
    GoldenSample {
        kind,
        bytes: bytes.to_vec(),
        value,
        origin: SampleOrigin {
            source: SOURCE.to_owned(),
            producer: PRODUCER.to_owned(),
            version: VERSION.to_owned(),
            sha256: sha256.to_owned(),
        },
        notes: notes.to_owned(),
    }
}

fn input_failure(error: impl core::fmt::Display) -> GoldenFailure {
    GoldenFailure {
        direction: Direction::Input,
        offset: None,
        left: "real MinIO migration sample".to_owned(),
        right: error.to_string(),
    }
}

pub(crate) fn lifecycle_sample() -> Result<GoldenSample<PersistedLifecycleConfiguration>, GoldenFailure> {
    let value = parse_s3s_lifecycle(LIFECYCLE).map_err(input_failure)?.structure;
    Ok(sample(
        ConfigKind::Lifecycle,
        LIFECYCLE,
        LIFECYCLE_SHA256,
        value,
        "Source-(c) MinIO-written lifecycle bytes migrated unchanged through RustFS bucket metadata migration.",
    ))
}

pub(crate) fn object_lock_sample() -> Result<GoldenSample<PersistedObjectLockConfiguration>, GoldenFailure> {
    let value = parse_s3s_object_lock(OBJECT_LOCK).map_err(input_failure)?.structure;
    Ok(sample(
        ConfigKind::ObjectLock,
        OBJECT_LOCK,
        OBJECT_LOCK_SHA256,
        value,
        "Source-(c) MinIO-written GOVERNANCE retention bytes migrated unchanged through RustFS bucket metadata migration.",
    ))
}

pub(crate) fn replication_sample() -> Result<GoldenSample<PersistedReplicationConfiguration>, GoldenFailure> {
    let value = parse_s3s_replication(REPLICATION).map_err(input_failure)?.structure;
    Ok(sample(
        ConfigKind::Replication,
        REPLICATION,
        REPLICATION_SHA256,
        value,
        "Source-(c) MinIO-written replication bytes migrated unchanged through RustFS bucket metadata migration.",
    ))
}

pub(crate) fn run() -> Result<Vec<(ConfigKind, usize)>, (ConfigKind, GoldenFailure)> {
    let lifecycle = lifecycle_sample().and_then(|sample| assert_lifecycle_four_way(&sample));
    lifecycle.map_err(|failure| (ConfigKind::Lifecycle, failure))?;

    let object_lock = object_lock_sample().and_then(|sample| assert_object_lock_four_way(&sample));
    object_lock.map_err(|failure| (ConfigKind::ObjectLock, failure))?;

    let replication = replication_sample().and_then(|sample| assert_replication_four_way(&sample));
    replication.map_err(|failure| (ConfigKind::Replication, failure))?;

    Ok(vec![
        (ConfigKind::Lifecycle, 1),
        (ConfigKind::ObjectLock, 1),
        (ConfigKind::Replication, 1),
    ])
}

#[cfg(test)]
mod tests {
    use super::{lifecycle_sample, object_lock_sample, run};
    use crate::{ConfigKind, Direction, assert_lifecycle_four_way, assert_object_lock_four_way};

    #[test]
    fn real_minio_migration_samples_run_d1_to_d5() {
        let counts = run().expect("real MinIO migration bytes pass D1-D5");
        assert_eq!(
            counts,
            vec![
                (ConfigKind::Lifecycle, 1),
                (ConfigKind::ObjectLock, 1),
                (ConfigKind::Replication, 1),
            ]
        );
    }

    #[test]
    fn stale_minio_sample_digest_fails_before_codec_observation() {
        let mut sample = lifecycle_sample().expect("real MinIO lifecycle sample parses");
        sample.origin.sha256.replace_range(..1, "0");

        let failure = assert_lifecycle_four_way(&sample).expect_err("stale source bytes must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }

    #[test]
    fn mislabeled_minio_sample_fails_before_codec_observation() {
        let mut sample = object_lock_sample().expect("real MinIO object-lock sample parses");
        sample.kind = ConfigKind::Lifecycle;

        let failure = assert_object_lock_four_way(&sample).expect_err("wrong source registry label must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
