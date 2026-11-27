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

//! External fixture preparation, ownership transitions, and cleanup.
//!
//! Responsible for: applying a fully validated fixture plan, retaining successful or unresolved creates,
//! and cleaning owned resources in dependency order. NOT responsible for: parsing setup values,
//! endpoint selection, or authored exchange judgement. Upstream: `super`; downstream: the signed
//! external socket control path.

use std::collections::BTreeSet;

use super::super::{Conn, Head, budget_of};
use crate::inprocess::{ChunkStep, Wire};
use crate::interpolate::Captures;
use crate::sut::{Sut, SutError};
use crate::value::Value;

impl Conn {
    pub(in crate::conn) fn finish_case(&mut self, case_id: &str) -> Result<(), SutError> {
        if self.external.is_some() {
            return self.finish_external(case_id);
        }
        self.inner.finish(case_id)
    }

    pub(in crate::conn) fn prepare_external(&mut self, case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        // Defence in depth: a `Sut` wrapper that forgets to forward `validate_requests` must not
        // run a case only the in-process target can judge and let its zero counters pass.
        if let Some(reason) = crate::inprocess::unavailable_externally(case_id) {
            return Err(SutError::Environment(reason));
        }
        self.connection = None;
        self.external_fixtures.clear_control_connection();
        let Some(setup) = setup else {
            if self.external_fixtures.holds_anything() {
                return Err(SutError::Environment(
                    "external fixture cleanup from the previous case is incomplete".to_owned(),
                ));
            }
            return self.inner.prepare(case_id, None);
        };
        let plan = self.external_fixtures.plan(setup, &self.inner)?;
        let mut captures = self.inner.prepare(case_id, None)?;
        self.external_fixtures.active_case = Some(case_id.to_owned());
        for bucket in plan.buckets {
            let target = format!("/{}", bucket.name);
            let status = match self.fixture_control_status("HEAD", &target, &bucket.region, &[], &[]) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 404 {
                let error = if (200..300).contains(&status) {
                    SutError::Environment(format!(
                        "external fixture bucket `{}` already exists; refusing to adopt or alter it",
                        bucket.name
                    ))
                } else {
                    SutError::Refused(format!(
                        "external fixture could not prove bucket `{}` absent: HEAD returned status {status}",
                        bucket.name
                    ))
                };
                return Err(self.abort_external_prepare(error));
            }
            if bucket.absent {
                // Proved absent, so with writes granted anything there at cleanup the case made.
                if self.external_fixtures.writes {
                    self.external_fixtures.owned_buckets.push(super::OwnedBucket {
                        name: bucket.name,
                        region: bucket.region,
                        versioned: false,
                        object_lock: false,
                    });
                }
                continue;
            }
            let create_body = bucket.region.create_body();
            let mut headers = Vec::new();
            if !create_body.is_empty() {
                headers.push(("content-type".to_owned(), "application/xml".to_owned()));
            }
            if bucket.object_lock {
                headers.push(("x-amz-bucket-object-lock-enabled".to_owned(), "true".to_owned()));
            }
            let status = match self.fixture_control_status("PUT", &target, &bucket.region, create_body, &headers) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 200 {
                return Err(self.abort_external_prepare(SutError::Refused(format!(
                    "external fixture PUT for bucket `{}` returned status {status}; the failed create is not owned",
                    bucket.name
                ))));
            }
            let owned = super::OwnedBucket {
                name: bucket.name,
                region: bucket.region,
                versioned: bucket.versioned,
                object_lock: bucket.object_lock,
            };
            let enablement = if owned.object_lock {
                self.verify_fixture_object_lock(&owned)
            } else if owned.versioned {
                self.enable_fixture_versioning(&owned)
            } else {
                Ok(())
            };
            self.external_fixtures.owned_buckets.push(owned);
            if let Err(error) = enablement {
                return Err(self.abort_external_prepare(error));
            }
        }
        for object in plan.objects {
            let status = match self.fixture_control_status("HEAD", &object.target, &object.region, &[], &[]) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 404 {
                let error = if (200..300).contains(&status) {
                    SutError::Environment(format!(
                        "external fixture object `{}/{}` already exists; refusing to adopt or alter it",
                        object.bucket, object.key
                    ))
                } else {
                    SutError::Refused(format!(
                        "external fixture could not prove object `{}/{}` absent: HEAD returned status {status}",
                        object.bucket, object.key
                    ))
                };
                return Err(self.abort_external_prepare(error));
            }
            if object.absent {
                continue;
            }
            if self
                .external_fixtures
                .owned_buckets
                .iter()
                .any(|bucket| bucket.name == object.bucket && (bucket.versioned || bucket.object_lock))
            {
                if let Err(error) = self.put_fixture_version(&object) {
                    return Err(self.abort_external_prepare(error));
                }
                continue;
            }
            let status = match self.fixture_control_status("PUT", &object.target, &object.region, &object.body, &object.headers) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 200 {
                return Err(self.abort_external_prepare(SutError::Refused(format!(
                    "external fixture PUT for object `{}/{}` returned status {status}; the failed create is not owned",
                    object.bucket, object.key
                ))));
            }
            self.external_fixtures.owned_objects.push(super::object::OwnedObject {
                bucket: object.bucket,
                key: object.key,
                target: object.target,
                region: object.region,
            });
        }
        for upload in plan.uploads {
            let result = self.fixture_control("POST", &format!("{}?uploads", upload.target), &upload.region, &[], &[]);
            let mut owned = super::multipart::OwnedUpload {
                bucket: upload.bucket,
                target: upload.target.clone(),
                region: upload.region.clone(),
                upload_id: None,
            };
            let body = match result {
                Ok((200, body)) => body,
                Ok((status, _)) => {
                    return Err(self.abort_external_prepare(SutError::Refused(format!(
                        "external fixture initiation returned status {status}; the failed create is not owned"
                    ))));
                }
                Err(error) => {
                    self.external_fixtures.owned_uploads.push(owned);
                    let error = if matches!(error, SutError::Unreachable(_)) {
                        error
                    } else {
                        super::multipart::unresolved_id()
                    };
                    return Err(self.abort_external_prepare(error));
                }
            };
            let upload_id = match super::multipart::upload_id(&body) {
                Ok(id) => id,
                Err(error) => {
                    self.external_fixtures.owned_uploads.push(owned);
                    return Err(self.abort_external_prepare(error));
                }
            };
            if let Some(name) = upload.capture {
                captures.insert(name, upload_id.clone());
            }
            let upload_target = super::object::query_target(&upload.target, "uploadId", &upload_id);
            owned.upload_id = Some(upload_id);
            self.external_fixtures.owned_uploads.push(owned);
            for part in upload.parts {
                let etag = match self.put_fixture_part(&upload_target, &upload.region, &part) {
                    Ok(etag) => etag,
                    Err(error) => return Err(self.abort_external_prepare(error)),
                };
                if let (Some(name), Some(etag)) = (part.capture, etag) {
                    captures.insert(name, etag);
                }
            }
        }
        self.external_fixtures.clear_control_connection();
        Ok(captures)
    }

    pub(super) fn finish_external(&mut self, case_id: &str) -> Result<(), SutError> {
        self.connection = None;
        let case_mismatch = self.external_fixtures.active_case.as_deref().and_then(|active| {
            (active != case_id).then(|| {
                SutError::Environment(format!("external fixtures owned by `{active}` cannot be finished as `{case_id}`"))
            })
        });
        let cleanup = self.cleanup_owned_external_fixtures();
        let inner = self.inner.finish(case_id);
        combine_results(case_mismatch.map_or(Ok(()), Err), combine_results(cleanup, inner))
    }

    /// Rolls back what the case created, keeping `error`'s class: a refused step or a lost endpoint
    /// whose rollback also failed is still a refused step or a lost endpoint, never a skip.
    fn abort_external_prepare(&mut self, error: SutError) -> SutError {
        match self.cleanup_owned_external_fixtures() {
            Ok(()) => error,
            Err(cleanup) => error.map_reason(|reason| format!("{reason}; rollback also failed: {cleanup}")),
        }
    }

    fn cleanup_owned_external_fixtures(&mut self) -> Result<(), SutError> {
        let mut messages = Vec::new();
        let mut failed_uploads = Vec::new();
        while let Some(upload) = self.external_fixtures.owned_uploads.pop() {
            let Some(id) = upload.upload_id.as_deref() else {
                messages.push(format!("UploadId for bucket `{}` remains unresolved", upload.bucket));
                failed_uploads.push(upload);
                continue;
            };
            let target = super::object::query_target(&upload.target, "uploadId", id);
            match self.fixture_control_status("DELETE", &target, &upload.region, &[], &[]) {
                Ok(204) => {}
                Ok(status) => {
                    messages.push(format!("upload abort for bucket `{}` returned status {status}", upload.bucket));
                    failed_uploads.push(upload);
                }
                Err(error) => {
                    messages.push(format!("upload abort for bucket `{}` failed: {error}", upload.bucket));
                    failed_uploads.push(upload);
                }
            }
        }
        failed_uploads.reverse();
        self.external_fixtures.owned_uploads = failed_uploads;
        let locked_buckets: BTreeSet<String> = self
            .external_fixtures
            .owned_buckets
            .iter()
            .filter(|bucket| bucket.object_lock)
            .map(|bucket| bucket.name.clone())
            .collect();
        let mut failed_versions = Vec::new();
        while let Some(version) = self.external_fixtures.owned_versions.pop() {
            let Some(id) = version.version_id.as_deref() else {
                messages.push(super::versioned::unresolved().to_string());
                failed_versions.push(version);
                continue;
            };
            if self.external_fixtures.writes && locked_buckets.contains(&version.bucket) {
                if let Err(error) = self.delete_locked_fixture_version(
                    &version.bucket,
                    &version.target,
                    id,
                    &version.region,
                    !version.delete_marker,
                    true,
                ) {
                    messages.push(error.to_string());
                    failed_versions.push(version);
                }
                continue;
            }
            let target = super::object::query_target(&version.target, "versionId", id);
            match self.fixture_control_status("DELETE", &target, &version.region, &[], &[]) {
                Ok(204) => {}
                Ok(status) => {
                    messages.push(format!("version DELETE for bucket `{}` returned status {status}", version.bucket));
                    failed_versions.push(version);
                }
                Err(error) => {
                    messages.push(format!("version DELETE for bucket `{}` failed: {error}", version.bucket));
                    failed_versions.push(version);
                }
            }
        }
        failed_versions.reverse();
        self.external_fixtures.owned_versions = failed_versions;
        let failed_objects = self.cleanup_owned_objects(&mut messages);
        let blocked_buckets = failed_objects
            .iter()
            .map(|object| object.bucket.clone())
            .chain(
                self.external_fixtures
                    .owned_uploads
                    .iter()
                    .map(|upload| upload.bucket.clone()),
            )
            .chain(
                self.external_fixtures
                    .owned_versions
                    .iter()
                    .map(|version| version.bucket.clone()),
            )
            .collect::<BTreeSet<_>>();
        self.external_fixtures.owned_objects = failed_objects;
        let mut failed_buckets = Vec::new();
        while let Some(bucket) = self.external_fixtures.owned_buckets.pop() {
            if blocked_buckets.contains(&bucket.name) {
                failed_buckets.push(bucket);
                continue;
            }
            if self.external_fixtures.writes
                && let Err(error) = self.empty_fixture_bucket(&bucket)
            {
                messages.push(error.to_string());
                failed_buckets.push(bucket);
                continue;
            }
            let target = format!("/{}", bucket.name);
            match self.fixture_control_status("DELETE", &target, &bucket.region, &[], &[]) {
                Ok(204) => {}
                // A granted write may have deleted the bucket, or never created a declared-absent one.
                Ok(404) if self.external_fixtures.writes => {}
                Ok(status) => {
                    messages.push(format!("DELETE for bucket `{}` returned status {status}", bucket.name));
                    failed_buckets.push(bucket);
                }
                Err(error) => {
                    messages.push(format!("DELETE for bucket `{}` failed: {error}", bucket.name));
                    failed_buckets.push(bucket);
                }
            }
        }
        failed_buckets.reverse();
        self.external_fixtures.owned_buckets = failed_buckets;
        self.external_fixtures.clear_control_connection();
        if messages.is_empty() {
            self.external_fixtures.active_case = None;
            return Ok(());
        }
        Err(SutError::Environment(format!("external fixture cleanup failed: {}", messages.join("; "))))
    }

    pub(super) fn fixture_control_status(
        &mut self,
        method: &str,
        target: &str,
        region: &super::region::FixtureRegion,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<u16, SutError> {
        self.fixture_control(method, target, region, body, extra_headers)
            .map(|(status, _)| status)
    }

    pub(super) fn fixture_control(
        &mut self,
        method: &str,
        target: &str,
        region: &super::region::FixtureRegion,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<(u16, Vec<u8>), SutError> {
        let observation = self.fixture_control_observation(method, target, region, body, extra_headers)?;
        let status = observation
            .status
            .ok_or_else(|| SutError::Environment(format!("external fixture {method} returned no status")))?;
        Ok((status, observation.body))
    }

    pub(super) fn fixture_control_observation(
        &mut self,
        method: &str,
        target: &str,
        region: &super::region::FixtureRegion,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<crate::observation::Observation, SutError> {
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external fixture control has no configured endpoint".to_owned()))?;
        let wire = Wire {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: control_headers(body.len(), extra_headers, endpoint.is_tls()),
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: body.to_vec(),
            frames: (!body.is_empty()).then(|| body.to_vec()).into_iter().collect(),
            steps: (!body.is_empty())
                .then(|| ChunkStep::Data(body.to_vec(), 0))
                .into_iter()
                .collect(),
            sign: Some(region.sign_spec()),
        };
        let request_time = self.external_now()?;
        let head: Head = self.head(&wire, &request_time)?;
        let started = std::time::Instant::now();
        let deadline = started
            .checked_add(budget_of(None))
            .ok_or_else(|| SutError::Environment("external fixture control deadline cannot be represented".to_owned()))?;
        let (mut connection, reused) = match self.external_fixtures.control_connection.take() {
            Some(connection) if !endpoint.is_tls() && connection.probe_reusable_cleartext() => (connection, true),
            _ => (endpoint.open(deadline)?, false),
        };
        match super::super::external::execute_control_exchange(&mut connection, &wire, &head, started, deadline)? {
            super::super::external::ControlExchangeOutcome::Completed { observation, torn_down } => {
                if !torn_down && !endpoint.is_tls() {
                    self.external_fixtures.control_connection = Some(connection);
                }
                Ok(observation)
            }
            super::super::external::ControlExchangeOutcome::ClosedBeforeResponse { fallback } => {
                if !reused || !may_retry_stale_control(method, target, &self.external_fixtures) {
                    return fallback;
                }
                let mut fresh = endpoint.open(deadline)?;
                match super::super::external::execute_control_exchange(&mut fresh, &wire, &head, started, deadline)? {
                    super::super::external::ControlExchangeOutcome::Completed { observation, torn_down } => {
                        if !torn_down && !endpoint.is_tls() {
                            self.external_fixtures.control_connection = Some(fresh);
                        }
                        Ok(observation)
                    }
                    super::super::external::ControlExchangeOutcome::ClosedBeforeResponse { fallback } => fallback,
                }
            }
        }
    }
}

fn may_retry_stale_control(method: &str, target: &str, fixtures: &super::ExternalFixtures) -> bool {
    matches!(method, "GET" | "HEAD" | "DELETE")
        || (method == "POST" && target.ends_with("?delete"))
        || (method == "PUT" && !fixtures.is_versioned_object_target(target))
}

fn control_headers(body_len: usize, extra: &[(String, String)], close: bool) -> Vec<(String, String)> {
    let mut headers = vec![("content-length".to_owned(), body_len.to_string())];
    if close {
        headers.push(("connection".to_owned(), "close".to_owned()));
    }
    headers.extend_from_slice(extra);
    if body_len == 0
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-content-sha256"))
    {
        headers.push(("x-amz-content-sha256".to_owned(), crate::sha256::hex_digest(&[])));
    }
    headers
}

fn combine_results(left: Result<(), SutError>, right: Result<(), SutError>) -> Result<(), SutError> {
    match (left, right) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(left), Err(right)) => Err(SutError::Environment(format!("{left}; {right}"))),
    }
}
