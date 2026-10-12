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

//! Legacy Lifecycle date compatibility against independent bytes and the real RustFS oracle.
//!
//! Responsible for: local offsets, read precision, historical date output, and refusals.
//! NOT responsible for: HTTP policy validation, runtime extensions, or global timestamp formats.
//! Upstream: the dedicated Lifecycle persistence entry points. Downstream: RustFS migration.

use super::{
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleRule, PersistedTransition,
    parse_lifecycle_legacy_dates, serialize_lifecycle_legacy_dates,
};
use crate::persistence::PersistenceCodecError;

// https://github.com/s3s-project/s3s/blob/5761ddfe4c509fcac87e3b99fd5bd9e176b442c0/crates/s3s/src/dto/timestamp.rs
// The pinned codec retains a date's local offset and writes its local fields with three fractional digits.

#[derive(Clone, Copy, Debug)]
enum DateField {
    Expiration,
    Transition,
    ExpiryUpdatedAt,
}

fn document(field: DateField, timestamp: &str) -> String {
    match field {
        DateField::Expiration => format!(
            "<LifecycleConfiguration><Rule><Expiration><Date>{timestamp}</Date></Expiration>\
             <Status>Enabled</Status></Rule></LifecycleConfiguration>"
        ),
        DateField::Transition => format!(
            "<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Date>{timestamp}</Date>\
             <StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>"
        ),
        DateField::ExpiryUpdatedAt => format!(
            "<LifecycleConfiguration><ExpiryUpdatedAt>{timestamp}</ExpiryUpdatedAt>\
             <Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>"
        ),
    }
}

fn configuration(field: DateField, timestamp: &str) -> PersistedLifecycleConfiguration {
    let mut value = PersistedLifecycleConfiguration {
        expiry_updated_at: None,
        rules: vec![PersistedLifecycleRule {
            abort_incomplete_multipart_upload: None,
            del_marker_expiration: None,
            expiration: None,
            filter: None,
            id: None,
            noncurrent_version_expiration: None,
            noncurrent_version_transitions: None,
            prefix: None,
            status: "Enabled".to_owned(),
            transitions: None,
        }],
    };
    match field {
        DateField::Expiration => {
            value.rules[0].expiration = Some(PersistedLifecycleExpiration {
                date: Some(timestamp.to_owned()),
                ..Default::default()
            });
        }
        DateField::Transition => {
            value.rules[0].transitions = Some(vec![PersistedTransition {
                date: Some(timestamp.to_owned()),
                storage_class: Some("GLACIER".to_owned()),
                ..Default::default()
            }]);
        }
        DateField::ExpiryUpdatedAt => value.expiry_updated_at = Some(timestamp.to_owned()),
    }
    value
}

fn date(value: &PersistedLifecycleConfiguration, field: DateField) -> Option<&str> {
    match field {
        DateField::Expiration => value.rules[0].expiration.as_ref()?.date.as_deref(),
        DateField::Transition => value.rules[0].transitions.as_ref()?.first()?.date.as_deref(),
        DateField::ExpiryUpdatedAt => value.expiry_updated_at.as_deref(),
    }
}

fn old_rejects(input: &str) -> bool {
    let mut decoder = s3s_rustfs::xml::Deserializer::new(input.as_bytes());
    <s3s_rustfs::dto::BucketLifecycleConfiguration as s3s_rustfs::xml::Deserialize>::deserialize(&mut decoder).is_err()
        || decoder.expect_eof().is_err()
}

fn old_output(input: &str) -> Vec<u8> {
    let mut decoder = s3s_rustfs::xml::Deserializer::new(input.as_bytes());
    let value = <s3s_rustfs::dto::BucketLifecycleConfiguration as s3s_rustfs::xml::Deserialize>::deserialize(&mut decoder)
        .expect("the pinned real codec accepts this valid Lifecycle document");
    decoder.expect_eof().expect("the entire old document was consumed");
    let mut bytes = Vec::new();
    s3s_rustfs::xml::Serialize::serialize(&value, &mut s3s_rustfs::xml::Serializer::new(&mut bytes))
        .expect("the pinned real codec writes its decoded Lifecycle value");
    bytes
}

#[test]
fn reads_offset_midnight_without_utc_rewrite() {
    for (field, timestamp) in [
        (DateField::Expiration, "2025-01-02T00:00:00+02:00"),
        (DateField::Transition, "2025-01-02T00:00:00-05:30"),
    ] {
        let input = document(field, timestamp);
        let value = parse_lifecycle_legacy_dates(input.as_bytes()).expect("offset midnight is a valid stored date");
        assert_eq!(date(&value, field), Some(timestamp), "local midnight changed for {field:?}");
    }
}

#[test]
fn reads_submillisecond_dates_before_policy_validation() {
    let timestamp = "2025-01-02T00:00:00.000000001Z";
    for field in [DateField::Expiration, DateField::Transition] {
        let input = document(field, timestamp);
        let value = parse_lifecycle_legacy_dates(input.as_bytes()).expect("stored dates are read before policy validation");
        assert_eq!(date(&value, field), Some(timestamp), "midnight validation lost precision for {field:?}");
    }
}

#[test]
fn reads_real_minio_expiry_axis_without_truncation() {
    let input = concat!(
        "<LifecycleConfiguration><Rule><ID>d96i4g89k8h26a95st60</ID><Status>Enabled</Status>",
        "<Filter><Prefix></Prefix></Filter><Expiration><Days>30</Days></Expiration>",
        "<NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration>",
        "</Rule><ExpiryUpdatedAt>2026-07-07T15:58:57.337315Z</ExpiryUpdatedAt></LifecycleConfiguration>"
    );
    let value = parse_lifecycle_legacy_dates(input.as_bytes()).expect("the real MinIO document remains readable");
    assert_eq!(value.expiry_updated_at.as_deref(), Some("2026-07-07T15:58:57.337315Z"));
}

#[test]
fn writes_old_local_calendar_fields_with_milliseconds_and_literal_z() {
    for (field, input_date, written_date) in [
        (DateField::Expiration, "2025-01-02T00:00:00+02:00", "2025-01-02T00:00:00.000Z"),
        (DateField::Transition, "2025-01-02T00:00:00-05:30", "2025-01-02T00:00:00.000Z"),
        (
            DateField::ExpiryUpdatedAt,
            "2025-01-02T00:00:00.123456789+02:00",
            "2025-01-02T00:00:00.123Z",
        ),
    ] {
        let expected = document(field, written_date).into_bytes();
        let legacy = old_output(&document(field, input_date));
        let actual = serialize_lifecycle_legacy_dates(&configuration(field, input_date)).expect("the date writes");
        assert_eq!(
            (actual, legacy),
            (expected.clone(), expected),
            "historical date bytes changed for {field:?}"
        );
    }
}

#[test]
fn rejects_invalid_timestamp_lexemes_on_read_and_write() {
    for (field, timestamp) in [
        (DateField::Expiration, ""),
        (DateField::Transition, "2025-01-02T00:00:00"),
        (DateField::ExpiryUpdatedAt, "2025-02-30T00:00:00Z"),
        (DateField::Expiration, "2025-01-02T24:00:00Z"),
        (DateField::Transition, "2025-01-02T00:60:00Z"),
        (DateField::ExpiryUpdatedAt, "2025-01-02T00:00:61Z"),
        (DateField::Expiration, "2025-01-02T00:00:00+02:60"),
        (DateField::Transition, "2025-01-02T00:00:00+0200"),
        (DateField::ExpiryUpdatedAt, "2025-01-02T00:00:00\u{00e9}"),
    ] {
        let input = document(field, timestamp);
        let read = parse_lifecycle_legacy_dates(input.as_bytes());
        let write = serialize_lifecycle_legacy_dates(&configuration(field, timestamp));
        assert_eq!(
            (
                matches!(read, Err(PersistenceCodecError::InvalidLifecycleTimestamp)),
                matches!(write, Err(PersistenceCodecError::InvalidLifecycleTimestamp)),
                old_rejects(&input),
            ),
            (true, true, true),
            "invalid timestamp admitted for {field:?}: {timestamp:?}"
        );
    }
}

#[test]
fn rejects_malformed_documents_and_missing_known_fields() {
    for input in [
        "<LifecycleConfiguration><Rule>",
        "<Other><Rule><Status>Enabled</Status></Rule></Other>",
        "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    ] {
        assert_eq!(
            (parse_lifecycle_legacy_dates(input.as_bytes()).is_err(), old_rejects(input)),
            (true, true),
            "invalid stored document was accepted: {input}"
        );
    }
}
