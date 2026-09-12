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
//! Responsible for: applying a fully validated fixture plan, recording only successful creates,
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
        self.connection = None;
        let Some(setup) = setup else {
            if self.external_fixtures.active_case.is_some()
                || !self.external_fixtures.owned_buckets.is_empty()
                || !self.external_fixtures.owned_objects.is_empty()
            {
                return Err(SutError::Environment(
                    "external fixture cleanup from the previous case is incomplete".to_owned(),
                ));
            }
            return self.inner.prepare(case_id, None);
        };
        let plan = self.external_fixtures.plan(setup, &self.inner)?;
        let captures = self.inner.prepare(case_id, None)?;
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
                    SutError::Environment(format!(
                        "external fixture could not prove bucket `{}` absent: HEAD returned status {status}",
                        bucket.name
                    ))
                };
                return Err(self.abort_external_prepare(error));
            }
            if bucket.absent {
                continue;
            }
            let create_body = bucket.region.create_body();
            let headers = (!create_body.is_empty())
                .then(|| ("content-type".to_owned(), "application/xml".to_owned()))
                .into_iter()
                .collect::<Vec<_>>();
            let status = match self.fixture_control_status("PUT", &target, &bucket.region, create_body, &headers) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 200 {
                return Err(self.abort_external_prepare(SutError::Environment(format!(
                    "external fixture PUT for bucket `{}` returned status {status}; the failed create is not owned",
                    bucket.name
                ))));
            }
            self.external_fixtures.owned_buckets.push(super::OwnedBucket {
                name: bucket.name,
                region: bucket.region,
            });
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
                    SutError::Environment(format!(
                        "external fixture could not prove object `{}/{}` absent: HEAD returned status {status}",
                        object.bucket, object.key
                    ))
                };
                return Err(self.abort_external_prepare(error));
            }
            if object.absent {
                continue;
            }
            let status = match self.fixture_control_status("PUT", &object.target, &object.region, &object.body, &object.headers) {
                Ok(status) => status,
                Err(error) => return Err(self.abort_external_prepare(error)),
            };
            if status != 200 {
                return Err(self.abort_external_prepare(SutError::Environment(format!(
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

    fn abort_external_prepare(&mut self, error: SutError) -> SutError {
        match self.cleanup_owned_external_fixtures() {
            Ok(()) => error,
            Err(cleanup) => SutError::Environment(format!("{error}; rollback also failed: {cleanup}")),
        }
    }

    fn cleanup_owned_external_fixtures(&mut self) -> Result<(), SutError> {
        let mut failed_objects = Vec::new();
        let mut messages = Vec::new();
        while let Some(object) = self.external_fixtures.owned_objects.pop() {
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
        failed_objects.reverse();
        let blocked_buckets = failed_objects
            .iter()
            .map(|object| object.bucket.clone())
            .collect::<BTreeSet<_>>();
        self.external_fixtures.owned_objects = failed_objects;
        let mut failed_buckets = Vec::new();
        while let Some(bucket) = self.external_fixtures.owned_buckets.pop() {
            if blocked_buckets.contains(&bucket.name) {
                failed_buckets.push(bucket);
                continue;
            }
            let target = format!("/{}", bucket.name);
            match self.fixture_control_status("DELETE", &target, &bucket.region, &[], &[]) {
                Ok(204) => {}
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
        if messages.is_empty() {
            self.external_fixtures.active_case = None;
            return Ok(());
        }
        Err(SutError::Environment(format!("external fixture cleanup failed: {}", messages.join("; "))))
    }

    fn fixture_control_status(
        &self,
        method: &str,
        target: &str,
        region: &super::region::FixtureRegion,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<u16, SutError> {
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external fixture control has no configured endpoint".to_owned()))?;
        let wire = Wire {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: control_headers(body.len(), extra_headers),
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
        let request_time = super::clock::current_request_time()?;
        let head: Head = self.head(&wire, &request_time)?;
        let started = std::time::Instant::now();
        let deadline = started
            .checked_add(budget_of(None))
            .ok_or_else(|| SutError::Environment("external fixture control deadline cannot be represented".to_owned()))?;
        let mut connection = endpoint.open(deadline)?;
        let result = super::super::external::execute_socket_exchange(
            &mut connection,
            &wire,
            &head,
            started,
            deadline,
            !endpoint.is_tls(),
        )?;
        result
            .observation
            .status
            .ok_or_else(|| SutError::Environment(format!("external fixture {method} returned no status")))
    }
}

fn control_headers(body_len: usize, extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut headers = vec![
        ("content-length".to_owned(), body_len.to_string()),
        ("connection".to_owned(), "close".to_owned()),
    ];
    headers.extend_from_slice(extra);
    headers
}

fn combine_results(left: Result<(), SutError>, right: Result<(), SutError>) -> Result<(), SutError> {
    match (left, right) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(left), Err(right)) => Err(SutError::Environment(format!("{left}; {right}"))),
    }
}
