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

//! The `--allow-external-writes` gate and the bucket emptying it makes necessary.
//!
//! Responsible for: classifying an authored exchange as a write, refusing a write case before any
//! of its traffic when the flag is off, and, when it is on, emptying a declared bucket of every
//! version, delete marker and upload a listing shows so the bucket can be removed and its name
//! reused by the next case. NOT responsible for: exact version ownership (`versioned`), state a
//! case creates outside the buckets it declares, or response judgement. Upstream: `super`,
//! `lifecycle`, `crate::conn`; downstream: signed fixture controls.

use super::super::Conn;
use super::OwnedBucket;
use crate::inprocess::Wire;
use crate::sut::SutError;
use crate::value::Value;

/// How many list-and-delete rounds an emptying may take: one listing page is 1,000 entries, and a
/// case writes a handful, so a bucket still listing entries after this many is not being emptied.
const EMPTYING_ROUNDS: usize = 16;

/// The method that makes `wire` a write, or `None` when it only reads. A raw head or an
/// undecodable HTTP/2 script cannot be shown to read, so it counts as a write.
pub(super) fn write_method(wire: &Wire) -> Option<String> {
    let read_only = |method: &str| matches!(method, "GET" | "HEAD" | "OPTIONS");
    if !wire.h2_frames.is_empty() {
        // The authored header blocks are what the peer executes; `request.method` is not sent.
        return match super::super::h2::authored_methods(wire) {
            Ok(methods) => methods.into_iter().find(|method| !read_only(method)),
            Err(error) => Some(format!("an unclassified authored HTTP/2 script ({error})")),
        };
    }
    if wire.raw_head.is_some() {
        return Some("an unclassified raw request".to_owned());
    }
    (!read_only(&wire.method)).then(|| wire.method.clone())
}

pub(super) fn refused(method: &str) -> SutError {
    SutError::Environment(format!(
        "external writes are disabled: without `--allow-external-writes` only read-only GET, HEAD, and OPTIONS \
         exchanges are sent to an endpoint, not {method}"
    ))
}

impl Conn {
    /// Refuses a case with an authored write before any of its traffic, setup included, when the
    /// operator did not allow writes. A structured PUT or DELETE in a case that declares a
    /// versioning-enabled bucket is left to exact version ownership, which classifies it at
    /// exchange time; `ensure_read_only` remains the boundary for everything else.
    pub(in crate::conn) fn validate_external_requests(
        &self,
        case_id: &str,
        setup: Option<&Value>,
        requests: &[&Value],
    ) -> Result<(), SutError> {
        let fixtures = &self.external_fixtures;
        if self.external.is_none() {
            return Ok(());
        }
        // A case no endpoint can judge says so whatever the flags; `prepare` repeats this for a
        // caller that skips the runner.
        if let Some(reason) = crate::inprocess::post_object::unavailable_externally(case_id) {
            return Err(SutError::Environment(reason));
        }
        if fixtures.writes {
            return Ok(());
        }
        let versioned = fixtures.enabled
            && setup
                .and_then(|setup| setup.read("setup.buckets"))
                .and_then(Value::as_array)
                .is_some_and(|buckets| {
                    buckets
                        .iter()
                        .any(|bucket| bucket.read("setup.buckets[].versioning").and_then(Value::as_str) == Some("enabled"))
                });
        for request in requests {
            let wire = self.inner.read_wire(request)?;
            let Some(method) = write_method(&wire) else { continue };
            let exact =
                versioned && wire.raw_head.is_none() && wire.h2_frames.is_empty() && matches!(method.as_str(), "PUT" | "DELETE");
            if !exact {
                return Err(refused(&method));
            }
        }
        Ok(())
    }

    /// Empties `bucket` of every upload, version and delete marker its listings show. A bucket
    /// that does not exist (declared absent and never created, or deleted by the case) is empty.
    pub(super) fn empty_fixture_bucket(&self, bucket: &OwnedBucket) -> Result<(), SutError> {
        for _ in 0..EMPTYING_ROUNDS {
            let uploads = self.list_fixture_bucket(bucket, "uploads", &[b"Upload"], b"UploadId")?;
            let versions = self.list_fixture_bucket(bucket, "versions", &[b"Version", b"DeleteMarker"], b"VersionId")?;
            if uploads.is_empty() && versions.is_empty() {
                return Ok(());
            }
            for (entries, query) in [(uploads, "uploadId"), (versions, "versionId")] {
                for (key, id) in entries {
                    let target = super::object::query_target(&super::object::object_target(&bucket.name, &key)?, query, &id);
                    let status = self
                        .fixture_control_observation("DELETE", &target, &bucket.region, &[], &[])?
                        .status;
                    if status != Some(204) {
                        return Err(SutError::Environment(format!(
                            "emptying bucket `{}`: DELETE of a listed {query} returned status {status:?}",
                            bucket.name
                        )));
                    }
                }
            }
        }
        Err(SutError::Environment(format!(
            "bucket `{}` still lists entries after {EMPTYING_ROUNDS} emptying rounds",
            bucket.name
        )))
    }

    fn list_fixture_bucket(
        &self,
        bucket: &OwnedBucket,
        query: &str,
        items: &[&[u8]],
        id: &[u8],
    ) -> Result<Vec<(String, String)>, SutError> {
        let target = format!("/{}?{query}", bucket.name);
        let observation = self.fixture_control_observation("GET", &target, &bucket.region, &[], &[])?;
        match observation.status {
            Some(200) => listed(&observation.body, items, id).ok_or_else(|| {
                SutError::Environment(format!("emptying bucket `{}`: the {query} listing is not readable", bucket.name))
            }),
            Some(404) => Ok(Vec::new()),
            status => Err(SutError::Environment(format!(
                "emptying bucket `{}`: the {query} listing returned status {status:?}",
                bucket.name
            ))),
        }
    }
}

/// The `Key` and `id` texts of every root child named in `items`, or `None` for a body that is
/// not well-formed or an item missing either.
fn listed(body: &[u8], items: &[&[u8]], id: &[u8]) -> Option<Vec<(String, String)>> {
    use quick_xml::{Reader, escape::resolve_predefined_entity, events::Event};
    let mut reader = Reader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut entries = Vec::new();
    let (mut key, mut value) = (None::<String>, None::<String>);
    let mut text = String::new();
    loop {
        match reader.read_event().ok()? {
            Event::Start(element) => {
                path.push(element.local_name().as_ref().to_vec());
                text.clear();
            }
            Event::Text(part) => text.push_str(&part.xml10_content().ok()?),
            Event::CData(part) => text.push_str(&part.xml10_content().ok()?),
            Event::GeneralRef(reference) => match reference.resolve_char_ref().ok()? {
                Some(character) => text.push(character),
                None => text.push_str(resolve_predefined_entity(&reference.decode().ok()?)?),
            },
            Event::End(_) => {
                let name = path.pop()?;
                match path.as_slice() {
                    [_, item] if items.contains(&item.as_slice()) && name == b"Key" => key = Some(text.clone()),
                    [_, item] if items.contains(&item.as_slice()) && name == id => value = Some(text.clone()),
                    [_] if items.contains(&name.as_slice()) => entries.push((key.take()?, value.take()?)),
                    _ => {}
                }
                text.clear();
            }
            Event::Eof => return path.is_empty().then_some(entries),
            _ => {}
        }
    }
}
