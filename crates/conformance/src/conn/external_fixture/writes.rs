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

/// Headers that frame a body or rename the method behind a read's request line.
const FRAMING_OR_OVERRIDE: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// The method that makes `wire` a write, or `None` when it only reads. Classified on what the
/// bytes can carry, not on the declared method: a raw head, an undecodable HTTP/2 script, or a
/// structured read whose target or headers hold CR, LF or NUL (a second request), that carries
/// body bytes, or that frames a body or overrides its method, cannot be shown to read.
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
    if !read_only(&wire.method) {
        return Some(wire.method.clone());
    }
    let smuggles = |text: &str| text.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0));
    let unclassified = smuggles(&wire.target)
        || wire.headers.iter().any(|(name, value)| {
            smuggles(name) || smuggles(value) || FRAMING_OR_OVERRIDE.iter().any(|framing| name.eq_ignore_ascii_case(framing))
        })
        || !wire.body.is_empty()
        || !wire.steps.is_empty();
    unclassified.then(|| format!("an unclassified {} whose bytes may carry another request", wire.method))
}

pub(super) fn refused(method: &str) -> SutError {
    SutError::Environment(format!(
        "external writes are disabled: without `--allow-external-writes` only read-only GET, HEAD, and OPTIONS \
         exchanges are sent to an endpoint, not {method}"
    ))
}

impl Conn {
    /// Refuses a case with an authored write before any of its traffic, setup included, when the
    /// operator did not allow writes, and a case only the in-process target can judge always.
    /// A structured PUT or DELETE in a case that declares a versioning-enabled bucket is left to
    /// exact version ownership, which may still refuse it at exchange time, after setup; that
    /// refusal is reported at the execute phase, this one at the preflight phase.
    pub(in crate::conn) fn validate_external_requests(
        &self,
        case_id: &str,
        setup: Option<&Value>,
        requests: &[&Value],
    ) -> Result<(), SutError> {
        if self.external.is_none() {
            return Ok(());
        }
        if let Some(reason) = crate::inprocess::unavailable_externally(case_id) {
            return Err(SutError::Environment(reason));
        }
        let fixtures = &self.external_fixtures;
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

    /// Refuses a run with writes granted unless the endpoint lists no bucket: the cases assume a
    /// pristine server, and cleanup removes only what each case declares.
    pub(crate) fn ensure_endpoint_empty(&self) -> Result<(), SutError> {
        const SHOWN: usize = 5;
        let region = super::region::FixtureRegion::parse(None)?;
        let listing = self.fixture_control_observation("GET", "/", &region, &[], &[])?;
        if listing.status != Some(200) {
            return Err(SutError::Environment(format!(
                "`--allow-external-writes` needs an empty endpoint, but ListBuckets returned status {:?}",
                listing.status
            )));
        }
        let buckets = super::response_xml::element_texts(&listing.body, &[b"ListAllMyBucketsResult", b"Buckets", b"Bucket"])
            .ok_or_else(|| {
                SutError::Environment(
                    "`--allow-external-writes` needs an empty endpoint, but its ListBuckets body is not a ListAllMyBucketsResult"
                        .to_owned(),
                )
            })?;
        if buckets.is_empty() {
            return Ok(());
        }
        let names: Vec<&str> = buckets
            .iter()
            .take(SHOWN)
            .map(|children| super::response_xml::texts(children, b"Name").flatten().next().unwrap_or("?"))
            .collect();
        Err(SutError::Environment(format!(
            "`--allow-external-writes` needs an empty endpoint on a fresh data directory, but it lists {} bucket(s): {}{}",
            buckets.len(),
            names.join(", "),
            if buckets.len() > SHOWN { ", ..." } else { "" }
        )))
    }

    /// Empties `bucket` of every upload, version and delete marker its listings show. A bucket
    /// that does not exist (declared absent and never created, or deleted by the case) is empty.
    pub(super) fn empty_fixture_bucket(&self, bucket: &OwnedBucket) -> Result<(), SutError> {
        for _ in 0..EMPTYING_ROUNDS {
            let uploads =
                self.list_fixture_bucket(bucket, "uploads", b"ListMultipartUploadsResult", &[b"Upload"], b"UploadId")?;
            let versions = self.list_fixture_bucket(
                bucket,
                "versions",
                b"ListVersionsResult",
                &[b"Version", b"DeleteMarker"],
                b"VersionId",
            )?;
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

    /// The `(Key, id)` of every `items` entry a listing shows; a bucket that does not exist lists none.
    fn list_fixture_bucket(
        &self,
        bucket: &OwnedBucket,
        query: &str,
        root: &[u8],
        items: &[&[u8]],
        id: &[u8],
    ) -> Result<Vec<(String, String)>, SutError> {
        let target = format!("/{}?{query}", bucket.name);
        let observation = self.fixture_control_observation("GET", &target, &bucket.region, &[], &[])?;
        let unreadable = || {
            SutError::Environment(format!(
                "emptying bucket `{}`: the {query} listing is not a well-formed {} with a Key and an id per entry",
                bucket.name,
                String::from_utf8_lossy(root)
            ))
        };
        match observation.status {
            Some(200) => {}
            Some(404) => return Ok(Vec::new()),
            status => {
                return Err(SutError::Environment(format!(
                    "emptying bucket `{}`: the {query} listing returned status {status:?}",
                    bucket.name
                )));
            }
        }
        let mut entries = Vec::new();
        for item in items {
            for children in super::response_xml::element_texts(&observation.body, &[root, item]).ok_or_else(unreadable)? {
                let one = |name: &[u8]| {
                    let mut texts = super::response_xml::texts(&children, name);
                    match (texts.next(), texts.next()) {
                        (Some(Some(text)), None) => Some(text.to_owned()),
                        _ => None,
                    }
                };
                entries.push((one(b"Key").ok_or_else(unreadable)?, one(id).ok_or_else(unreadable)?));
            }
        }
        Ok(entries)
    }
}
