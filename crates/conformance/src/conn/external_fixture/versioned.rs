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

//! Exact version ownership for external fixtures and classified authored object writes.
//!
//! Responsible for: proving versioning enablement, journaling observed version identities, and
//! constraining writes to owned path-style objects. NOT responsible for: version-list discovery,
//! Object Lock, HTTP/2 mutation, or case verdicts. Upstream: fixture lifecycle and external exchange;
//! downstream: signed fixture controls and the existing response observer.

use super::super::{Conn, Head};
use super::{ExternalFixtures, region::FixtureRegion};
use crate::inprocess::{ChunkStep, Wire};
use crate::observation::Observation;
use crate::sut::SutError;

#[derive(Debug)]
pub(in crate::conn) struct OwnedVersion {
    pub(super) bucket: String,
    pub(super) target: String,
    pub(super) region: FixtureRegion,
    pub(super) version_id: Option<String>,
    delete_marker: bool,
}

impl ExternalFixtures {
    pub(in crate::conn) fn version_write(&self, case_id: &str, wire: &Wire) -> Result<Option<OwnedVersion>, SutError> {
        if self.active_case.is_none()
            || !self.owned_buckets.iter().any(|bucket| bucket.versioned)
            || self.active_case.as_deref() != Some(case_id)
            || wire.raw_head.is_some()
            || !wire.h2_frames.is_empty()
            || matches!(wire.method.as_str(), "GET" | "HEAD" | "OPTIONS")
        {
            self.ensure_read_only(case_id, wire)?;
            return Ok(None);
        }
        if !matches!(wire.method.as_str(), "PUT" | "DELETE") {
            return Err(unsupported("only structured object PUT and DELETE are supported"));
        }
        if self.owned_versions.iter().any(|version| version.version_id.is_none()) {
            return Err(unresolved());
        }
        let bucket = self.versioned_bucket(&wire.target)?;
        Ok(Some(OwnedVersion {
            bucket: bucket.name.clone(),
            target: wire.target.clone(),
            region: bucket.region.clone(),
            version_id: None,
            delete_marker: wire.method == "DELETE",
        }))
    }

    fn versioned_bucket(&self, target: &str) -> Result<&super::OwnedBucket, SutError> {
        let name = object_bucket(target)?;
        self.owned_buckets
            .iter()
            .find(|bucket| bucket.name == name && bucket.versioned)
            .ok_or_else(|| unsupported("the object bucket is not an owned versioning-enabled bucket"))
    }

    pub(in crate::conn) fn validate_version_head(&self, wire: &Wire, head: &Head, authority: &str) -> Result<(), SutError> {
        for (name, value) in &wire.headers {
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| unsupported("authored header name is malformed"))?;
            http::HeaderValue::from_str(value).map_err(|_| unsupported("authored header value is malformed"))?;
        }
        let bytes = std::str::from_utf8(&head.bytes).map_err(|_| unsupported("request head is not text"))?;
        let lines = bytes
            .strip_suffix("\r\n\r\n")
            .ok_or_else(|| unsupported("request head is incomplete"))?;
        let mut lines = lines.split("\r\n");
        if lines.next() != Some(format!("{} {} HTTP/1.1", wire.method, wire.target).as_str()) {
            return Err(unsupported("signing changed the classified request target"));
        }
        let mut hosts = 0;
        let mut lengths = 0;
        let mut copies = 0;
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| unsupported("request header is malformed"))?;
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| unsupported("request header name is malformed"))?;
            http::HeaderValue::from_str(value).map_err(|_| unsupported("request header value is malformed"))?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("host") {
                hosts += 1;
                if value != authority {
                    return Err(unsupported("an authored Host override is not supported"));
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(unsupported("transfer coding cannot be classified as one owned write"));
            }
            if name.eq_ignore_ascii_case("content-length") {
                lengths += 1;
                if value.parse::<usize>().ok() != Some(wire.body.len()) {
                    return Err(unsupported("authored Content-Length does not match the complete body"));
                }
            }
            if name.eq_ignore_ascii_case("x-amz-copy-source") {
                copies += 1;
                if wire.method != "PUT" {
                    return Err(unsupported("copy source is only supported on object PUT"));
                }
                let source = match value.split_once('?') {
                    Some((source, query))
                        if query
                            .strip_prefix("versionId=")
                            .is_some_and(|id| !id.is_empty() && !id.contains('&')) =>
                    {
                        source
                    }
                    Some(_) => return Err(unsupported("copy source has an unsupported query")),
                    None => value,
                };
                self.versioned_bucket(source)?;
            }
        }
        if hosts != 1 || lengths > 1 || (lengths == 0 && !wire.body.is_empty()) || copies > 1 {
            return Err(unsupported("request authority or body framing is ambiguous"));
        }
        let mut sent = Vec::new();
        for step in &wire.steps {
            match step {
                ChunkStep::Data(bytes, _) => sent.extend_from_slice(bytes),
                ChunkStep::Control { .. } => return Err(unsupported("body control actions are not supported on owned writes")),
            }
        }
        if sent != wire.body {
            return Err(unsupported("authored body steps do not match the classified body"));
        }
        Ok(())
    }

    pub(in crate::conn) fn begin_version_write(&mut self, version: OwnedVersion) -> usize {
        let index = self.owned_versions.len();
        self.owned_versions.push(version);
        index
    }

    pub(in crate::conn) fn observe_version_write(&mut self, index: usize, observation: &Observation) -> Result<(), SutError> {
        if observation.status.is_some_and(|status| (400..500).contains(&status)) {
            self.owned_versions.remove(index);
            return Ok(());
        }
        let version = &self.owned_versions[index];
        let expected = if version.delete_marker { 204 } else { 200 };
        if observation.status != Some(expected) {
            return Err(unresolved());
        }
        let id = one_header(&observation.headers, "x-amz-version-id")?;
        if id.is_empty()
            || id == "null"
            || (version.delete_marker && one_header(&observation.headers, "x-amz-delete-marker")? != "true")
        {
            return Err(unresolved());
        }
        self.owned_versions[index].version_id = Some(id.to_owned());
        Ok(())
    }
}

impl Conn {
    pub(super) fn enable_fixture_versioning(&self, bucket: &super::OwnedBucket) -> Result<(), SutError> {
        let body = b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
        let headers = [
            ("content-type".to_owned(), "application/xml".to_owned()),
            ("content-md5".to_owned(), crate::fixture::encode_base64(&crate::md5::digest(body))),
        ];
        let target = format!("/{}?versioning", bucket.name);
        let response = self.fixture_control_observation("PUT", &target, &bucket.region, body, &headers)?;
        if response.status != Some(200) {
            return Err(unsupported("versioning enablement did not succeed"));
        }
        let response = self.fixture_control_observation("GET", &target, &bucket.region, &[], &[])?;
        if response.status != Some(200) || !enabled(&response.body) {
            return Err(unsupported("versioning readback did not prove Enabled"));
        }
        Ok(())
    }

    pub(super) fn put_fixture_version(&mut self, object: &super::object::ObjectPlan) -> Result<(), SutError> {
        let index = self.external_fixtures.begin_version_write(OwnedVersion {
            bucket: object.bucket.clone(),
            target: object.target.clone(),
            region: object.region.clone(),
            version_id: None,
            delete_marker: false,
        });
        let response = self.fixture_control_observation("PUT", &object.target, &object.region, &object.body, &object.headers)?;
        self.external_fixtures.observe_version_write(index, &response)?;
        if response.status != Some(200) {
            return Err(unsupported("versioned fixture object creation was rejected"));
        }
        Ok(())
    }
}

fn one_header<'a>(headers: &'a [(String, String)], wanted: &str) -> Result<&'a str, SutError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str());
    let value = values.next().ok_or_else(unresolved)?;
    if values.next().is_some() {
        return Err(unresolved());
    }
    Ok(value)
}

pub(super) fn object_bucket(target: &str) -> Result<&str, SutError> {
    let path = target
        .strip_prefix('/')
        .ok_or_else(|| unsupported("only path-style object targets are supported"))?;
    let (bucket, key) = path
        .split_once('/')
        .ok_or_else(|| unsupported("a write needs an object key"))?;
    if bucket.is_empty()
        || key.is_empty()
        || target.contains(['?', '#', '\\'])
        || target.bytes().any(|byte| byte <= b' ' || byte >= 127)
    {
        return Err(unsupported("the object target is not an unambiguous path"));
    }
    // Proxies may normalize dot segments or encoded path separators before the S3 endpoint.
    if key.split('/').any(|part| matches!(part, "." | ".."))
        || key.to_ascii_lowercase().contains("%2e")
        || key.to_ascii_lowercase().contains("%2f")
        || key.to_ascii_lowercase().contains("%5c")
    {
        return Err(unsupported("normalized object paths are not supported"));
    }
    Ok(bucket)
}

pub(super) fn delete_target(version: &OwnedVersion, id: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut target = format!("{}?versionId=", version.target);
    for byte in id.bytes() {
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

pub(super) fn unresolved() -> SutError {
    SutError::Environment(
        "external versioned write ownership is unresolved; exact version cleanup and case reuse are blocked".to_owned(),
    )
}

fn unsupported(reason: &str) -> SutError {
    SutError::Environment(format!("external versioned fixture: {reason}"))
}

fn enabled(body: &[u8]) -> bool {
    use quick_xml::{Reader, events::Event};
    let mut reader = Reader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut stack = Vec::new();
    let mut root_seen = false;
    let mut status_seen = false;
    let mut status = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if element.attributes().any(|attribute| attribute.is_err()) {
                    return false;
                }
                let name = element.local_name().as_ref().to_vec();
                match stack.as_slice() {
                    [] if !root_seen && name == b"VersioningConfiguration" => root_seen = true,
                    [root] if root == b"VersioningConfiguration" && name == b"Status" && !status_seen => status_seen = true,
                    [root] if root == b"VersioningConfiguration" && name == b"MfaDelete" => {}
                    _ => return false,
                }
                stack.push(name);
            }
            Ok(Event::End(_)) => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            Ok(Event::Text(text)) => {
                let Ok(text) = text.xml10_content() else { return false };
                if stack.last().is_some_and(|name| name == b"Status") {
                    status.push_str(&text);
                } else if !text.trim().is_empty() && !stack.last().is_some_and(|name| name == b"MfaDelete") {
                    return false;
                }
            }
            Ok(Event::Decl(_)) if !root_seen => {}
            Ok(Event::Comment(_)) => {}
            Ok(Event::Eof) => return root_seen && stack.is_empty() && status_seen && status == "Enabled",
            _ => return false,
        }
    }
}
