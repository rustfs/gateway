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

//! Batched multi-object cleanup (`DeleteObjects`) for owned external object fixtures.
//!
//! Responsible for: encoding S3 `POST /{bucket}?delete` batches (at most 1,000 keys per request
//! with `Content-MD5`), strictly validating every `<DeleteResult>` response so failed, unreported,
//! or malformed outcomes retain object ownership and keep bucket deletion blocked, and falling
//! back to single-object `DELETE` when the endpoint answers `501 Not Implemented` or a key cannot
//! be safely represented in XML 1.0. NOT responsible for: versioned object cleanup, multipart
//! aborts, socket reuse (`lifecycle`), or case verdicts. Upstream: `super::lifecycle`; downstream:
//! `Conn::fixture_control` and `super::response_xml`.

use std::collections::{BTreeMap, BTreeSet};

use super::super::Conn;
use super::object::OwnedObject;
use super::region::FixtureRegion;

/// Maximum keys permitted by S3 in a single `DeleteObjects` request body.
const MAX_BATCH_DELETE_KEYS: usize = 1000;

struct BucketObjects {
    bucket: String,
    region: FixtureRegion,
    objects: Vec<OwnedObject>,
}

struct ParsedDeleteResult {
    deleted_keys: BTreeSet<String>,
    error_keys: BTreeMap<String, String>,
}

impl Conn {
    /// Removes all owned non-versioned fixture objects in reverse creation order, batching
    /// multi-object buckets through `POST /{bucket}?delete` and returning any object whose
    /// deletion was not explicitly confirmed so ownership is retained and bucket deletion stays
    /// blocked.
    pub(super) fn cleanup_owned_objects(&mut self, messages: &mut Vec<String>) -> Vec<OwnedObject> {
        let owned = std::mem::take(&mut self.external_fixtures.owned_objects);
        let groups = group_objects_reverse(owned);
        let mut failed_objects = Vec::new();
        let mut batch_unsupported = false;

        for group in groups {
            let (batchable, single_only): (Vec<_>, Vec<_>) =
                group.objects.into_iter().partition(|object| is_xml10_safe_key(&object.key));

            if batch_unsupported || batchable.len() < 2 {
                self.delete_objects_individually(batchable, &mut failed_objects, messages);
            } else {
                let mut remaining = batchable.into_iter();
                loop {
                    let chunk: Vec<OwnedObject> = remaining.by_ref().take(MAX_BATCH_DELETE_KEYS).collect();
                    if chunk.is_empty() {
                        break;
                    }
                    if batch_unsupported || chunk.len() < 2 {
                        self.delete_objects_individually(chunk, &mut failed_objects, messages);
                        continue;
                    }
                    let body = encode_delete_objects_xml(&chunk);
                    let headers = [
                        ("content-type".to_owned(), "application/xml".to_owned()),
                        ("content-md5".to_owned(), crate::fixture::encode_base64(&crate::md5::digest(&body))),
                    ];
                    let target = format!("/{}?delete", group.bucket);
                    match self.fixture_control("POST", &target, &group.region, &body, &headers) {
                        Ok((200, response_body)) => match parse_delete_result(&response_body) {
                            Ok(parsed) => {
                                for object in chunk {
                                    if let Some(detail) = parsed.error_keys.get(&object.key) {
                                        messages.push(format!(
                                            "DeleteObjects for object `{}/{}` failed: {detail}",
                                            object.bucket, object.key
                                        ));
                                        failed_objects.push(object);
                                    } else if !parsed.deleted_keys.contains(&object.key) {
                                        messages.push(format!(
                                            "DeleteObjects for object `{}/{}` was not confirmed deleted",
                                            object.bucket, object.key
                                        ));
                                        failed_objects.push(object);
                                    }
                                }
                            }
                            Err(reason) => {
                                messages.push(format!("DeleteObjects for bucket `{}` {reason}", group.bucket));
                                failed_objects.extend(chunk);
                            }
                        },
                        Ok((501, _)) => {
                            batch_unsupported = true;
                            self.delete_objects_individually(chunk, &mut failed_objects, messages);
                        }
                        Ok((status, _)) => {
                            messages.push(format!("DeleteObjects for bucket `{}` returned status {status}", group.bucket));
                            failed_objects.extend(chunk);
                        }
                        Err(error) => {
                            messages.push(format!("DeleteObjects for bucket `{}` failed: {error}", group.bucket));
                            failed_objects.extend(chunk);
                        }
                    }
                }
            }

            if !single_only.is_empty() {
                self.delete_objects_individually(single_only, &mut failed_objects, messages);
            }
        }

        failed_objects.reverse();
        failed_objects
    }

    fn delete_objects_individually(
        &mut self,
        objects: Vec<OwnedObject>,
        failed_objects: &mut Vec<OwnedObject>,
        messages: &mut Vec<String>,
    ) {
        for object in objects {
            match self.fixture_control_status("DELETE", &object.target, &object.region, &[], &[]) {
                Ok(204) => {}
                Ok(status) => {
                    messages.push(format!("DELETE for object `{}/{}` returned status {status}", object.bucket, object.key));
                    failed_objects.push(object);
                }
                Err(error) => {
                    messages.push(format!("DELETE for object `{}/{}` failed: {error}", object.bucket, object.key));
                    failed_objects.push(object);
                }
            }
        }
    }
}

/// Groups owned objects by bucket in reverse creation order (both bucket order and per-bucket key
/// order).
fn group_objects_reverse(owned: Vec<OwnedObject>) -> Vec<BucketObjects> {
    let mut groups: Vec<BucketObjects> = Vec::new();
    for object in owned.into_iter().rev() {
        if let Some(group) = groups.iter_mut().find(|group| group.bucket == object.bucket) {
            group.objects.push(object);
        } else {
            let bucket = object.bucket.clone();
            let region = object.region.clone();
            groups.push(BucketObjects {
                bucket,
                region,
                objects: vec![object],
            });
        }
    }
    groups
}

/// Keys containing ASCII control characters (`< 0x20`) fall back to single-object `DELETE` to
/// avoid XML 1.0 illegal-character rejections and CR/LF normalization differences.
fn is_xml10_safe_key(key: &str) -> bool {
    key.bytes().all(|byte| byte >= 0x20)
}

fn encode_delete_objects_xml(objects: &[OwnedObject]) -> Vec<u8> {
    let mut xml = String::from("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for object in objects {
        xml.push_str("<Object><Key>");
        push_xml_escaped(&mut xml, &object.key);
        xml.push_str("</Key></Object>");
    }
    xml.push_str("</Delete>");
    xml.into_bytes()
}

fn push_xml_escaped(sink: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => sink.push_str("&amp;"),
            '<' => sink.push_str("&lt;"),
            '>' => sink.push_str("&gt;"),
            '"' => sink.push_str("&quot;"),
            '\'' => sink.push_str("&apos;"),
            _ => sink.push(ch),
        }
    }
}

fn parse_delete_result(body: &[u8]) -> Result<ParsedDeleteResult, &'static str> {
    let deleted_entries =
        super::response_xml::element_texts(body, &[b"DeleteResult", b"Deleted"]).ok_or("returned an unreadable DeleteResult")?;
    let error_entries =
        super::response_xml::element_texts(body, &[b"DeleteResult", b"Error"]).ok_or("returned an unreadable DeleteResult")?;

    let mut deleted_keys = BTreeSet::new();
    for children in &deleted_entries {
        let key = one_required_text(children, b"Key").ok_or("returned a malformed Deleted entry in DeleteResult")?;
        deleted_keys.insert(key.to_owned());
    }

    let mut error_keys = BTreeMap::new();
    for children in &error_entries {
        let key = one_required_text(children, b"Key").ok_or("returned a malformed Error entry in DeleteResult")?;
        let code = optional_single_text(children, b"Code")?;
        let message = optional_single_text(children, b"Message")?;
        let detail = match (code, message) {
            (Some(code), Some(message)) if !code.is_empty() && !message.is_empty() => format!("{code}: {message}"),
            (Some(code), _) if !code.is_empty() => code.to_owned(),
            (_, Some(message)) if !message.is_empty() => message.to_owned(),
            _ => "unspecified error".to_owned(),
        };
        error_keys.insert(key.to_owned(), detail);
    }

    Ok(ParsedDeleteResult {
        deleted_keys,
        error_keys,
    })
}

fn one_required_text<'a>(children: &'a super::response_xml::Children, name: &'a [u8]) -> Option<&'a str> {
    let mut texts = super::response_xml::texts(children, name);
    match (texts.next(), texts.next()) {
        (Some(Some(text)), None) if !text.is_empty() => Some(text),
        _ => None,
    }
}

fn optional_single_text<'a>(
    children: &'a super::response_xml::Children,
    name: &'a [u8],
) -> Result<Option<&'a str>, &'static str> {
    let mut texts = super::response_xml::texts(children, name);
    match (texts.next(), texts.next()) {
        (None, _) => Ok(None),
        (Some(Some(text)), None) => Ok(Some(text)),
        _ => Err("returned a malformed Error entry in DeleteResult"),
    }
}
