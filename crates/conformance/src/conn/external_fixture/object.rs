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

//! Validation and wire plans for unversioned external object fixtures.
//!
//! Responsible for: binding objects to owned bucket plans, decoding every payload source,
//! validating object headers before remote mutation, and encoding path-style control targets.
//! NOT responsible for: socket I/O, ownership transitions, cleanup, versioning, object lock, or
//! multipart uploads. Upstream: `super`; downstream: `super::lifecycle`.

use std::collections::BTreeSet;

use crate::inprocess::InProcess;
use crate::sut::SutError;
use crate::value::Value;

use super::BucketPlan;

#[derive(Debug)]
pub(super) struct ObjectPlan {
    pub(super) bucket: String,
    pub(super) key: String,
    pub(super) target: String,
    pub(super) absent: bool,
    pub(super) region: super::region::FixtureRegion,
    pub(super) body: Vec<u8>,
    pub(super) headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub(super) struct OwnedObject {
    pub(super) bucket: String,
    pub(super) key: String,
    pub(super) target: String,
    pub(super) region: super::region::FixtureRegion,
}

pub(super) fn plans(setup: &Value, buckets: &[BucketPlan], decoder: &InProcess) -> Result<Vec<ObjectPlan>, SutError> {
    let objects = setup.read("setup.objects").and_then(Value::as_array).unwrap_or_default();
    let mut seen = BTreeSet::new();
    let mut plans = Vec::with_capacity(objects.len());
    for object in objects {
        super::only_keys(
            object,
            &["bucket", "key", "body", "content_type", "storage_class", "metadata", "absent"],
            "setup.objects[]",
        )?;
        let bucket = required_string(object, "setup.objects[].bucket", "an external fixture object has no bucket")?;
        let key = required_string(object, "setup.objects[].key", "an external fixture object has no key")?;
        let Some(bucket_plan) = buckets.iter().find(|candidate| candidate.name == bucket) else {
            return Err(SutError::Environment(format!(
                "external fixture object `{bucket}/{key}` does not reference a bucket owned by this setup"
            )));
        };
        if bucket_plan.absent {
            return Err(SutError::Environment(format!(
                "external fixture object `{bucket}/{key}` cannot use absent bucket `{bucket}` because it is not owned by this setup"
            )));
        }
        if !seen.insert((bucket.to_owned(), key.to_owned())) {
            return Err(SutError::Environment(format!(
                "external fixture object `{bucket}/{key}` is declared more than once"
            )));
        }
        let absent = object
            .read("setup.objects[].absent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let payload = object.read("setup.objects[].body");
        let content_type = object.read("setup.objects[].content_type").and_then(Value::as_str);
        let storage_class = object.read("setup.objects[].storage_class").and_then(Value::as_str);
        let metadata = object.read("setup.objects[].metadata");
        if absent && (payload.is_some() || content_type.is_some() || storage_class.is_some() || metadata.is_some()) {
            return Err(SutError::Environment(format!(
                "absent external fixture object `{bucket}/{key}` cannot declare create payload or headers"
            )));
        }
        let body = match payload {
            Some(payload) => decoder.payload(payload).map_err(|error| {
                SutError::Environment(format!("external fixture object payload for `{bucket}/{key}` is invalid: {error}"))
            })?,
            None => Vec::new(),
        };
        let headers = object_headers(content_type, storage_class, metadata)?;
        plans.push(ObjectPlan {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            target: object_target(bucket, key)?,
            absent,
            region: bucket_plan.region.clone(),
            body,
            headers,
        });
    }
    Ok(plans)
}

fn required_string<'a>(value: &'a Value, path: &'static str, missing: &str) -> Result<&'a str, SutError> {
    value
        .read(path)
        .and_then(Value::as_str)
        .ok_or_else(|| SutError::Environment(missing.to_owned()))
}

fn object_headers(
    content_type: Option<&str>,
    storage_class: Option<&str>,
    metadata: Option<&Value>,
) -> Result<Vec<(String, String)>, SutError> {
    let mut headers = Vec::new();
    if let Some(value) = content_type {
        push_header(&mut headers, "content-type", value)?;
    }
    if let Some(value) = storage_class {
        push_header(&mut headers, "x-amz-storage-class", value)?;
    }
    if let Some(metadata) = metadata {
        let Value::Table(entries) = metadata else {
            return Err(SutError::Environment("external fixture object metadata is not a header map".to_owned()));
        };
        for (name, value) in entries {
            let Some(value) = value.as_str() else {
                return Err(SutError::Environment(format!(
                    "external fixture object metadata `{name}` is not a header value"
                )));
            };
            push_header(&mut headers, &format!("x-amz-meta-{name}"), value)?;
        }
    }
    Ok(headers)
}

fn push_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) -> Result<(), SutError> {
    let name = http::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| SutError::Environment(format!("external fixture object header name `{name}` is invalid")))?;
    http::HeaderValue::try_from(value)
        .map_err(|_| SutError::Environment(format!("external fixture object header `{name}` has an invalid value")))?;
    headers.push((name.as_str().to_owned(), value.to_owned()));
    Ok(())
}

fn object_target(bucket: &str, key: &str) -> Result<String, SutError> {
    if key.is_empty() {
        return Err(SutError::Environment(
            "an external fixture object key cannot be empty because it would address the bucket control path".to_owned(),
        ));
    }
    let mut target = String::with_capacity(bucket.len() + key.len() + 2);
    target.push('/');
    target.push_str(bucket);
    target.push('/');
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            target.push(char::from(byte));
        } else {
            target.push('%');
            target.push(char::from(hex_digit(byte >> 4)));
            target.push(char::from(hex_digit(byte & 0x0f)));
        }
    }
    Ok(target)
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + nibble - 10,
        _ => b'?',
    }
}
