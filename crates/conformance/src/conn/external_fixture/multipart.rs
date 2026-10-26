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

//! Plans, part uploads, and returned identities for owned external uploads.
//!
//! Responsible for: preflight payload validation, observed part ETags, initiation identities, and abort targets.
//! NOT responsible for: socket framing, cleanup ownership, or case response judgement.
//! Upstream: external fixture planning and lifecycle. Downstream: control observations and the pinned XML reader.

use std::collections::BTreeSet;

use crate::inprocess::InProcess;
use crate::sut::SutError;
use crate::value::Value;

use super::BucketPlan;

#[derive(Debug)]
pub(super) struct UploadPlan {
    pub(super) bucket: String,
    pub(super) target: String,
    pub(super) capture: Option<String>,
    pub(super) region: super::region::FixtureRegion,
    pub(super) parts: Vec<PartPlan>,
}

#[derive(Debug)]
pub(super) struct PartPlan {
    pub(super) number: i64,
    pub(super) body: Vec<u8>,
    pub(super) capture: Option<String>,
}

#[derive(Debug)]
pub(super) struct OwnedUpload {
    pub(super) bucket: String,
    pub(super) target: String,
    pub(super) region: super::region::FixtureRegion,
    // None retains unresolved ownership after a possibly successful initiation.
    pub(super) upload_id: Option<String>,
}

pub(super) fn plans(setup: &Value, buckets: &[BucketPlan], decoder: &InProcess) -> Result<Vec<UploadPlan>, SutError> {
    let Some(value) = setup.read("setup.multipart_uploads") else {
        return Ok(Vec::new());
    };
    let uploads = value
        .as_array()
        .ok_or_else(|| invalid_plan("multipart_uploads must be an array"))?;
    let mut captures = BTreeSet::new();
    let mut plans = Vec::with_capacity(uploads.len());
    for upload in uploads {
        super::only_keys(upload, &["bucket", "key", "capture_upload_id_as", "parts"], "setup.multipart_uploads[]")?;
        let bucket = upload
            .read("setup.multipart_uploads[].bucket")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_plan("upload has no bucket"))?;
        let key = upload
            .read("setup.multipart_uploads[].key")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_plan("upload has no key"))?;
        let bucket_plan = buckets
            .iter()
            .find(|candidate| candidate.name == bucket && !candidate.absent)
            .ok_or_else(|| invalid_plan("upload bucket must be owned and non-absent"))?;
        let parts = part_plans(upload, decoder)?;
        let capture = match upload.read("setup.multipart_uploads[].capture_upload_id_as") {
            Some(value) => {
                let name = value
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| invalid_plan("upload capture name must be a nonempty string"))?;
                if !captures.insert(name.to_owned()) {
                    return Err(invalid_plan("upload capture name is declared more than once"));
                }
                Some(name.to_owned())
            }
            None => None,
        };
        plans.push(UploadPlan {
            bucket: bucket.to_owned(),
            target: super::object::object_target(bucket, key)?,
            capture,
            region: bucket_plan.region.clone(),
            parts,
        });
    }
    Ok(plans)
}

fn part_plans(upload: &Value, decoder: &InProcess) -> Result<Vec<PartPlan>, SutError> {
    let Some(parts) = upload.read("setup.multipart_uploads[].parts") else {
        return Ok(Vec::new());
    };
    let parts = parts.as_array().ok_or_else(|| invalid_plan("parts must be an array"))?;
    let mut plans = Vec::with_capacity(parts.len());
    for part in parts {
        super::only_keys(part, &["part_number", "body", "capture_etag_as"], "setup.multipart_uploads[].parts[]")?;
        let number = part
            .read("setup.multipart_uploads[].parts[].part_number")
            .and_then(Value::as_integer)
            .filter(|number| (1..=10000).contains(number))
            .ok_or_else(|| invalid_plan("part_number must be an integer between 1 and 10000"))?;
        let capture = part
            .read("setup.multipart_uploads[].parts[].capture_etag_as")
            .map(|value| {
                value
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| invalid_plan("capture_etag_as must be a nonempty string"))
            })
            .transpose()?;
        let body = part
            .read("setup.multipart_uploads[].parts[].body")
            .map(|payload| {
                decoder
                    .payload(payload)
                    .map_err(|error| invalid_plan(&format!("part payload is invalid: {error}")))
            })
            .transpose()?
            .unwrap_or_default();
        plans.push(PartPlan { number, body, capture });
    }
    Ok(plans)
}

impl super::super::Conn {
    pub(super) fn put_fixture_part(
        &self,
        upload_target: &str,
        region: &super::region::FixtureRegion,
        part: &PartPlan,
    ) -> Result<Option<String>, SutError> {
        let target = format!("{upload_target}&partNumber={}", part.number);
        let observation = self
            .fixture_control_observation("PUT", &target, region, &part.body, &[])
            .map_err(|error| invalid_plan(&format!("part upload failed: {error}")))?;
        if observation.status != Some(200) {
            return Err(invalid_plan(&format!("part upload returned status {:?}", observation.status)));
        }
        if part.capture.is_none() {
            return Ok(None);
        }
        let mut etags = observation
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("etag"))
            .map(|(_, value)| value);
        let etag = etags
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_plan("part upload did not return one nonempty ETag"))?;
        if etags.next().is_some() {
            return Err(invalid_plan("part upload returned more than one ETag"));
        }
        Ok(Some(etag.clone()))
    }
}

fn invalid_plan(reason: &str) -> SutError {
    SutError::Environment(format!("external multipart fixture: {reason}"))
}

pub(super) fn unresolved_id() -> SutError {
    SutError::Environment("external initiation did not return one valid UploadId; remote ownership is unresolved".to_owned())
}

pub(super) fn upload_id(body: &[u8]) -> Result<String, SutError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut depth = 0_usize;
    let mut root_seen = false;
    let mut in_id = false;
    let mut id_seen = false;
    let mut id = String::new();
    loop {
        match reader.read_event().map_err(|_| unresolved_id())? {
            Event::Start(element) => {
                for attribute in element.attributes() {
                    attribute.map_err(|_| unresolved_id())?;
                }
                if in_id {
                    return Err(unresolved_id());
                }
                if depth == 0 {
                    if root_seen || element.local_name().as_ref() != b"InitiateMultipartUploadResult" {
                        return Err(unresolved_id());
                    }
                    root_seen = true;
                }
                if element.local_name().as_ref() == b"UploadId" {
                    if depth != 1 || id_seen {
                        return Err(unresolved_id());
                    }
                    id_seen = true;
                    in_id = true;
                }
                depth += 1;
            }
            Event::End(_) => {
                if depth == 2 && in_id {
                    in_id = false;
                }
                depth = depth.checked_sub(1).ok_or_else(unresolved_id)?;
            }
            Event::Text(text) => {
                let text = text.xml10_content().map_err(|_| unresolved_id())?;
                if in_id {
                    id.push_str(&text);
                } else if depth == 0 && !text.trim().is_empty() {
                    return Err(unresolved_id());
                }
            }
            Event::CData(text) => {
                if depth == 0 {
                    return Err(unresolved_id());
                }
                if in_id {
                    id.push_str(&text.xml10_content().map_err(|_| unresolved_id())?);
                }
            }
            Event::GeneralRef(reference) => {
                if depth == 0 {
                    return Err(unresolved_id());
                }
                if let Some(character) = reference.resolve_char_ref().map_err(|_| unresolved_id())? {
                    if in_id {
                        id.push(character);
                    }
                } else {
                    let name = reference.decode().map_err(|_| unresolved_id())?;
                    let value = quick_xml::escape::resolve_predefined_entity(&name).ok_or_else(unresolved_id)?;
                    if in_id {
                        id.push_str(value);
                    }
                }
            }
            Event::Decl(_) if root_seen => return Err(unresolved_id()),
            Event::DocType(_) => return Err(unresolved_id()),
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 || !root_seen || !id_seen || id.is_empty() {
        return Err(unresolved_id());
    }
    Ok(id)
}

pub(super) fn abort_target(target: &str, upload_id: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut target = format!("{target}?uploadId=");
    for byte in upload_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            target.push(char::from(byte));
        } else {
            target.push('%');
            target.push(char::from(HEX[usize::from(byte >> 4)]));
            target.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    target
}
