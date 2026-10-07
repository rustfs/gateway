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

//! Empty required request enumerations and the HTTP-only Status refusal (rustfs/gateway#1078).
//!
//! Responsible for: the tree reading refusing empty required Status values before the backend,
//! the RustFS reading handing them over as the legacy decoder does, the remaining empty
//! enumerations handed over alike, and absent required members refused alike under both readings.
//! Also pins the persisted-reader boundary. NOT responsible for: backend validation of any value.
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

/// The later #1078 ruling changes required Status only; other empty enumerations still reach
/// the backend unchanged, including the empty Payer that RustFS stores.
#[test]
fn other_empty_required_enumerations_are_handed_over_alike() {
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| !position.ends_with(".Status"))
    {
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

/// The empty spellings of a required `Status`, a CDATA section with no text among them.
const EMPTY_STATUS: [&str; 3] = ["<Status/>", "<Status></Status>", "<Status><![CDATA[]]></Status>"];

/// Negative — the later ruling on #1078: the tree reading refuses every empty spelling with
/// `MalformedXML` before any backend runs, although the legacy decoder hands the empty string on.
#[test]
fn n_empty_required_status_is_malformed_xml() {
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| position.ends_with(".Status"))
    {
        for empty in EMPTY_STATUS {
            let body = body.replace("<Status/>", empty).replace("<Status></Status>", empty);
            assert!(legacy(op, body.as_bytes()).is_ok(), "{position}: legacy control");
            assert_eq!(
                gateway(op, DocumentReading::Tree, body.as_bytes()),
                Err("MalformedXML".to_owned()),
                "{position}: {empty}"
            );
        }
    }
}

/// Positive — the RustFS reading hands an empty required `Status` to the RustFS body exactly as
/// the legacy decoder does, so RustFS's own handler answers it with legacy RustFS's code:
/// `MalformedXML` for a lifecycle rule (`rustfs/src/app/bucket_usecase.rs:1272-1282`, `:2396-2398`)
/// and `InvalidRequest` for every replication position (`:688-704`;
/// `crates/replication/src/config.rs:235-283`), at rustfs/rustfs@95268a3b9. A decoder refusal would
/// answer a replication write `MalformedXML` instead.
#[test]
fn an_empty_required_status_is_handed_over_alike_under_the_rustfs_reading() {
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| position.ends_with(".Status"))
    {
        for empty in EMPTY_STATUS {
            let body = body.replace("<Status/>", empty).replace("<Status></Status>", empty);
            let legacy = legacy(op, body.as_bytes());
            let handed = legacy
                .clone()
                .unwrap_or_else(|code| panic!("{position}: the legacy stack refused with {code}"));
            assert!(handed.contains("(\"\")"), "{position}: the legacy stack handed no empty value: {handed}");
            assert_eq!(gateway(op, DocumentReading::RustFs, body.as_bytes()), legacy, "{position}: {empty}");
        }
    }
}

#[test]
fn nonempty_required_status_is_handed_over_alike() {
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| position.ends_with(".Status"))
    {
        for status in ["Enabled", "Disabled", "FutureStatus"] {
            let replacement = format!("<Status>{status}</Status>");
            let body = body
                .replace("<Status/>", &replacement)
                .replace("<Status></Status>", &replacement);
            let legacy = legacy(op, body.as_bytes());
            assert!(legacy.is_ok(), "{position}: {status}");
            for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
                assert_eq!(gateway(op, reading, body.as_bytes()), legacy, "{position} {reading:?}: {status}");
            }
        }
    }
}

#[test]
fn optional_empty_status_is_handed_over_alike() {
    let body = format!(
        "{REPLICATION_HEAD}<Status>Enabled</Status><DeleteMarkerReplication><Status/></DeleteMarkerReplication>{DESTINATION}</Destination></Rule></ReplicationConfiguration>"
    );
    let legacy = legacy(Op::PutBucketReplication, body.as_bytes());
    assert!(legacy.is_ok());
    for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
        assert_eq!(gateway(Op::PutBucketReplication, reading, body.as_bytes()), legacy, "{reading:?}");
    }
}

#[test]
fn stored_empty_status_remains_readable_and_round_trips() {
    use rustfs_gateway_types::compat::{
        parse_s3s_lifecycle, parse_s3s_replication, serialize_s3s_lifecycle, serialize_s3s_replication,
    };
    use rustfs_gateway_types::persistence::{parse_lifecycle, parse_replication, serialize_lifecycle, serialize_replication};
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| position.ends_with(".Status"))
    {
        let (old, new) = match op {
            Op::PutBucketLifecycleConfiguration => {
                let old = parse_s3s_lifecycle(body.as_bytes()).expect("old stored lifecycle is readable");
                let new = parse_lifecycle(body.as_bytes()).expect("stored lifecycle remains readable");
                assert_eq!(new, old.structure, "{position}: known fields survive");
                let encoded = serialize_lifecycle(&new).expect("stored lifecycle writes");
                assert_eq!(parse_lifecycle(&encoded).expect("read back"), new, "{position}");
                (serialize_s3s_lifecycle(&old.structure).expect("old writes"), encoded)
            }
            Op::PutBucketReplication => {
                let old = parse_s3s_replication(body.as_bytes()).expect("old stored replication is readable");
                let new = parse_replication(body.as_bytes()).expect("stored replication remains readable");
                assert_eq!(new, old.structure, "{position}: known fields survive");
                let encoded = serialize_replication(&new).expect("stored replication writes");
                assert_eq!(parse_replication(&encoded).expect("read back"), new, "{position}");
                (serialize_s3s_replication(&old.structure).expect("old writes"), encoded)
            }
            _ => panic!("only lifecycle and replication have required Status"),
        };
        assert_eq!(new, old, "{position}: persisted bytes remain old-readable");
    }
}

/// The RustFS reading inherits the legacy reader's CDATA omission, so a `Status` written only as
/// CDATA is the empty value there, handed over as legacy RustFS hands it; the tree reading keeps
/// its text.
#[test]
fn cdata_status_is_read_as_each_reading_reads_it() {
    for (op, position, body) in empty_required_enumerations()
        .into_iter()
        .filter(|(_, position, _)| position.ends_with(".Status"))
    {
        let plain = body
            .replace("<Status/>", "<Status>Enabled</Status>")
            .replace("<Status></Status>", "<Status>Enabled</Status>");
        let cdata = body
            .replace("<Status/>", "<Status><![CDATA[Enabled]]></Status>")
            .replace("<Status></Status>", "<Status><![CDATA[Enabled]]></Status>");
        let handed = legacy(op, cdata.as_bytes()).expect("legacy hands over an empty value");
        assert!(handed.contains("(\"\")"), "{position}");
        assert_eq!(gateway(op, DocumentReading::RustFs, cdata.as_bytes()), Ok(handed), "{position}");
        assert_eq!(
            gateway(op, DocumentReading::Tree, cdata.as_bytes()),
            gateway(op, DocumentReading::Tree, plain.as_bytes()),
            "{position}"
        );
    }
}
