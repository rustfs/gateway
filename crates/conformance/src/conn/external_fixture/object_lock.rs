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

//! External Object Lock fixture verification, preflight COMPLIANCE guard, and locked cleanup.
//!
//! Responsible for: proving Object Lock and versioning enablement after `CreateBucket`, rejecting
//! authored writes that would apply irremovable `COMPLIANCE` object retention before remote
//! contact, and cleaning locked versions under `--allow-external-writes` by bypassing GOVERNANCE
//! retention and lifting Legal Hold (`OFF`) when a version answers `403`. NOT responsible for:
//! bucket planning (`super`), setup orchestration (`super::lifecycle`), or case verdicts.
//! Upstream: `super::lifecycle` and `super::writes`; downstream: signed fixture controls and
//! `super::response_xml`.

use std::collections::BTreeSet;

use super::super::Conn;
use super::{OwnedBucket, region::FixtureRegion};
use crate::inprocess::{InProcess, Wire};
use crate::sut::SutError;
use crate::value::Value;

const LEGAL_HOLD_OFF_XML: &[u8] =
    b"<LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>OFF</Status></LegalHold>";

impl Conn {
    /// Proves that `CreateBucket` with `x-amz-bucket-object-lock-enabled: true` enabled both
    /// Object Lock and bucket versioning on the remote endpoint.
    pub(super) fn verify_fixture_object_lock(&mut self, bucket: &OwnedBucket) -> Result<(), SutError> {
        let lock_target = format!("/{}?object-lock", bucket.name);
        let lock_response = self.fixture_control_observation("GET", &lock_target, &bucket.region, &[], &[])?;
        if lock_response.status != Some(200) || !object_lock_enabled(&lock_response.body) {
            return Err(refused("object-lock readback did not prove Enabled"));
        }
        let versioning_target = format!("/{}?versioning", bucket.name);
        let versioning_response = self.fixture_control_observation("GET", &versioning_target, &bucket.region, &[], &[])?;
        if versioning_response.status != Some(200) || !super::versioned::enabled(&versioning_response.body) {
            return Err(refused("versioning readback did not prove Enabled"));
        }
        Ok(())
    }

    /// Removes one version or delete marker inside an owned Object Lock bucket when
    /// `--allow-external-writes` granted remote mutation. Sends governance bypass on `DELETE`; if
    /// an object version (not a delete marker) still answers `403`, lifts its legal hold to `OFF`
    /// and retries `DELETE` once. Fails closed on any non-204 final outcome.
    pub(super) fn delete_locked_fixture_version(
        &mut self,
        bucket: &str,
        object_target: &str,
        version_id: &str,
        region: &FixtureRegion,
        is_version: bool,
        allow_missing: bool,
    ) -> Result<(), SutError> {
        let delete_target = super::object::query_target(object_target, "versionId", version_id);
        let bypass = [("x-amz-bypass-governance-retention".to_owned(), "true".to_owned())];
        let status = self
            .fixture_control_observation("DELETE", &delete_target, region, &[], &bypass)?
            .status;
        match status {
            Some(204) => return Ok(()),
            Some(404) if allow_missing => return Ok(()),
            Some(403) if is_version => {}
            other => {
                return Err(SutError::Environment(format!(
                    "emptying Object Lock bucket `{bucket}`: DELETE of version returned status {other:?}"
                )));
            }
        }
        let hold_target = super::object::subresource_query_target(object_target, "legal-hold", "versionId", version_id);
        let hold_headers = [
            ("content-type".to_owned(), "application/xml".to_owned()),
            (
                "content-md5".to_owned(),
                crate::fixture::encode_base64(&crate::md5::digest(LEGAL_HOLD_OFF_XML)),
            ),
        ];
        let hold_status = self
            .fixture_control_observation("PUT", &hold_target, region, LEGAL_HOLD_OFF_XML, &hold_headers)?
            .status;
        if hold_status != Some(200) {
            return Err(SutError::Environment(format!(
                "emptying Object Lock bucket `{bucket}`: clearing legal hold returned status {hold_status:?}"
            )));
        }
        let retry_status = self
            .fixture_control_observation("DELETE", &delete_target, region, &[], &bypass)?
            .status;
        if retry_status == Some(204) {
            return Ok(());
        }
        Err(SutError::Environment(format!(
            "emptying Object Lock bucket `{bucket}`: DELETE after clearing legal hold returned status {retry_status:?}"
        )))
    }
}

/// Returns a preflight skip reason when a writable external case would apply irremovable
/// `COMPLIANCE` object retention that no S3 API can delete until `RetainUntilDate`.
pub(super) fn irremovable_compliance_reason(
    setup: Option<&Value>,
    decoder: &InProcess,
    requests: &[&Value],
) -> Result<Option<String>, SutError> {
    if !may_touch_object_lock(setup, requests) {
        return Ok(None);
    }
    let mut wires = Vec::with_capacity(requests.len());
    for request in requests {
        wires.push(decoder.read_wire(request)?);
    }
    let mut compliance_default_buckets = BTreeSet::new();
    for wire in &wires {
        if wire.method == "PUT"
            && has_query_param(&wire.target, "object-lock")
            && default_retention_is_compliance(&wire.body)
            && let Some(bucket) = bucket_from_target(&wire.target)
        {
            compliance_default_buckets.insert(bucket.to_owned());
        }
    }
    for wire in &wires {
        if applies_compliance_object_retention(wire, &compliance_default_buckets) {
            return Ok(Some(
                "external write applies irremovable COMPLIANCE object retention that external cleanup cannot delete until RetainUntilDate"
                    .to_owned(),
            ));
        }
    }
    Ok(None)
}

fn may_touch_object_lock(setup: Option<&Value>, requests: &[&Value]) -> bool {
    let setup_locked = setup
        .and_then(|setup| setup.read("setup.buckets"))
        .and_then(Value::as_array)
        .is_some_and(|buckets| {
            buckets
                .iter()
                .any(|bucket| bucket.read("setup.buckets[].object_lock").and_then(Value::as_bool) == Some(true))
        });
    if setup_locked {
        return true;
    }
    requests.iter().any(|request| {
        let lock_target = request
            .read("requestSpec.target")
            .and_then(Value::as_str)
            .is_some_and(|target| has_query_param(target, "object-lock"));
        let lock_header = request
            .read("requestSpec.headers")
            .and_then(|headers| match headers {
                Value::Table(entries) => Some(entries),
                _ => None,
            })
            .is_some_and(|entries| {
                entries
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-bucket-object-lock-enabled"))
            });
        lock_target || lock_header
    })
}

fn applies_compliance_object_retention(wire: &Wire, compliance_default_buckets: &BTreeSet<String>) -> bool {
    // 1. PutObject / CopyObject / CreateMultipartUpload header.
    if matches!(wire.method.as_str(), "PUT" | "POST")
        && wire
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-amz-object-lock-mode") && value.trim() == "COMPLIANCE")
    {
        return true;
    }
    // 2. PutObjectRetention XML body.
    if wire.method == "PUT" && has_query_param(&wire.target, "retention") && retention_body_is_compliance(&wire.body) {
        return true;
    }
    // 3. PostObject multipart/form-data field.
    if wire.method == "POST" && is_multipart_form(&wire.headers) && form_field_is_compliance(&wire.body) {
        return true;
    }
    // 4. Bucket COMPLIANCE DefaultRetention combined with an object write to that bucket.
    if !compliance_default_buckets.is_empty()
        && let Some(bucket) = object_write_bucket(wire)
        && compliance_default_buckets.contains(bucket)
    {
        return true;
    }
    false
}

fn object_lock_enabled(body: &[u8]) -> bool {
    let Some(items) = super::response_xml::element_texts(body, &[b"ObjectLockConfiguration"]) else {
        return false;
    };
    let [children] = items.as_slice() else { return false };
    let mut enabled = super::response_xml::texts(children, b"ObjectLockEnabled");
    children
        .iter()
        .all(|(name, text)| (name == b"ObjectLockEnabled" && text.is_some()) || (name == b"Rule" && text.is_none()))
        && matches!((enabled.next(), enabled.next()), (Some(Some("Enabled")), None))
}

fn retention_body_is_compliance(body: &[u8]) -> bool {
    let Some(items) = super::response_xml::element_texts(body, &[b"Retention"]) else {
        return false;
    };
    items
        .iter()
        .any(|children| super::response_xml::texts(children, b"Mode").any(|mode| mode == Some("COMPLIANCE")))
}

fn default_retention_is_compliance(body: &[u8]) -> bool {
    let Some(items) = super::response_xml::element_texts(body, &[b"ObjectLockConfiguration", b"Rule", b"DefaultRetention"])
    else {
        return false;
    };
    items
        .iter()
        .any(|children| super::response_xml::texts(children, b"Mode").any(|mode| mode == Some("COMPLIANCE")))
}

fn has_query_param(target: &str, wanted: &str) -> bool {
    target.split_once('?').is_some_and(|(_, query)| {
        query
            .split('&')
            .any(|part| part == wanted || part.strip_prefix(wanted).is_some_and(|rest| rest.starts_with('=')))
    })
}

fn bucket_from_target(target: &str) -> Option<&str> {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let rest = path.strip_prefix('/')?;
    let bucket = rest.split_once('/').map_or(rest, |(bucket, _)| bucket);
    (!bucket.is_empty()).then_some(bucket)
}

fn object_write_bucket(wire: &Wire) -> Option<&str> {
    let (path, query) = wire.target.split_once('?').map_or((wire.target.as_str(), ""), |pair| pair);
    let rest = path.strip_prefix('/')?;
    if wire.method == "POST" && is_multipart_form(&wire.headers) {
        let bucket = rest.trim_end_matches('/');
        return (!bucket.is_empty() && !bucket.contains('/')).then_some(bucket);
    }
    let (bucket, key) = rest.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    match wire.method.as_str() {
        "PUT" if query.is_empty() || has_query_param(&wire.target, "partNumber") => Some(bucket),
        "POST" if has_query_param(&wire.target, "uploads") || has_query_param(&wire.target, "uploadId") => Some(bucket),
        _ => None,
    }
}

fn is_multipart_form(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value.trim_start().to_ascii_lowercase().starts_with("multipart/form-data")
    })
}

fn form_field_is_compliance(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let needle = "name=\"x-amz-object-lock-mode\"";
    let mut rest = text;
    while let Some(at) = rest.find(needle) {
        rest = &rest[at + needle.len()..];
        let after_headers = rest
            .find("\r\n\r\n")
            .map(|pos| &rest[pos + 4..])
            .or_else(|| rest.find("\n\n").map(|pos| &rest[pos + 2..]));
        let Some(after_headers) = after_headers else { continue };
        let value = after_headers.lines().next().map(str::trim).unwrap_or_default();
        if value == "COMPLIANCE" {
            return true;
        }
    }
    false
}

fn refused(reason: &str) -> SutError {
    SutError::Refused(format!("external object-lock fixture: {reason}"))
}
