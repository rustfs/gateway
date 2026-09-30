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

//! An empty required enumeration element (rustfs/gateway#1078, row 3), on both stacks.
//!
//! Responsible for: every required enumeration a request document carries, emptied, handed to the
//! RustFS body as the same empty value by both stacks under both of the gateway's readings, and the
//! same members absent refused by both with the same code.
//! NOT responsible for: what RustFS does with the empty value (it refuses an empty lifecycle status
//! and stores an empty `Payer`), which its own handlers decide behind the seam.
//! Upstream: the parent harness. Downstream: nothing.

use rustfs_gateway_core::DocumentReading;

use super::{Op, gateway, legacy};

const REPLICATION_HEAD: &str = "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Priority>1</Priority><Filter><Prefix></Prefix></Filter>";
const DESTINATION: &str = "<Destination><Bucket>arn:aws:s3:::dst</Bucket>";

/// Every required enumeration a request document carries, emptied, as `(document, position, body)`.
fn empty_required_enumerations() -> Vec<(Op, &'static str, String)> {
    let replication = |rule: &str, destination: &str| {
        format!("{REPLICATION_HEAD}{rule}{DESTINATION}{destination}</Destination></Rule></ReplicationConfiguration>")
    };
    let enabled = "<Status>Enabled</Status>";
    vec![
        (
            Op::PutBucketLifecycleConfiguration,
            "LifecycleRule.Status",
            "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>logs/</Prefix></Filter><Status></Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>".to_owned(),
        ),
        (Op::PutBucketReplication, "ReplicationRule.Status", replication("<Status/>", "")),
        (
            Op::PutBucketReplication,
            "DeleteReplication.Status",
            replication(&format!("{enabled}<DeleteReplication><Status></Status></DeleteReplication>"), ""),
        ),
        (
            Op::PutBucketReplication,
            "ExistingObjectReplication.Status",
            replication(&format!("{enabled}<ExistingObjectReplication><Status/></ExistingObjectReplication>"), ""),
        ),
        (
            Op::PutBucketReplication,
            "ReplicaModifications.Status",
            replication(
                &format!("{enabled}<SourceSelectionCriteria><ReplicaModifications><Status></Status></ReplicaModifications></SourceSelectionCriteria>"),
                "",
            ),
        ),
        (
            Op::PutBucketReplication,
            "SseKmsEncryptedObjects.Status",
            replication(
                &format!("{enabled}<SourceSelectionCriteria><SseKmsEncryptedObjects><Status/></SseKmsEncryptedObjects></SourceSelectionCriteria>"),
                "",
            ),
        ),
        (Op::PutBucketReplication, "Metrics.Status", replication(enabled, "<Metrics><Status></Status></Metrics>")),
        (
            Op::PutBucketReplication,
            "ReplicationTime.Status",
            replication(enabled, "<ReplicationTime><Status/><Time><Minutes>15</Minutes></Time></ReplicationTime>"),
        ),
        (
            Op::PutBucketRequestPayment,
            "RequestPaymentConfiguration.Payer",
            "<RequestPaymentConfiguration><Payer></Payer></RequestPaymentConfiguration>".to_owned(),
        ),
        (
            Op::PutBucketEncryption,
            "ServerSideEncryptionByDefault.SSEAlgorithm",
            "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm/></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_owned(),
        ),
        (
            Op::RestoreObject,
            "GlacierJobParameters.Tier",
            "<RestoreRequest><Days>1</Days><GlacierJobParameters><Tier></Tier></GlacierJobParameters></RestoreRequest>".to_owned(),
        ),
        (
            Op::RestoreObject,
            "SelectParameters.ExpressionType",
            "<RestoreRequest><Type>SELECT</Type><SelectParameters><InputSerialization><CSV/></InputSerialization><ExpressionType/><Expression>SELECT * FROM S3Object</Expression><OutputSerialization><CSV/></OutputSerialization></SelectParameters></RestoreRequest>".to_owned(),
        ),
        (
            Op::RestoreObject,
            "Encryption.EncryptionType",
            "<RestoreRequest><Type>SELECT</Type><OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix><Encryption><EncryptionType></EncryptionType></Encryption></S3></OutputLocation></RestoreRequest>".to_owned(),
        ),
    ]
}

/// Positive — every required enumeration element sent empty reaches the RustFS body as the same
/// empty value on both stacks, whichever way the gateway reads the document. The legacy stack
/// decodes it into the value RustFS then judges; the gateway used to answer `500` before any body
/// ran.
#[test]
fn an_empty_required_enumeration_is_handed_over_alike() {
    for (op, position, body) in empty_required_enumerations() {
        let legacy = legacy(op, body.as_bytes());
        let handed = legacy
            .clone()
            .unwrap_or_else(|code| panic!("{position}: the legacy stack refused with {code}"));
        assert!(handed.contains("(\"\")"), "{position}: the legacy stack handed no empty value: {handed}");
        for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
            assert_eq!(gateway(op, reading, body.as_bytes()), legacy, "{position} {reading:?}");
        }
    }
}

/// Negative — the same members *absent* are refused by both stacks before any body runs, with the
/// same code: the empty value is a value, and no value is not.
#[test]
fn n_an_absent_required_enumeration_is_refused_alike() {
    for (op, position, body) in empty_required_enumerations() {
        let emptied = position.rsplit('.').next().expect("a member");
        let absent = body
            .replace(&format!("<{emptied}></{emptied}>"), "")
            .replace(&format!("<{emptied}/>"), "");
        assert_ne!(absent, body, "{position}: the fixture carried no empty {emptied}");
        let legacy = legacy(op, absent.as_bytes());
        assert!(legacy.is_err(), "{position}: the legacy stack handed over {legacy:?}");
        for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
            assert_eq!(gateway(op, reading, absent.as_bytes()), legacy, "{position} {reading:?}");
        }
    }
}
