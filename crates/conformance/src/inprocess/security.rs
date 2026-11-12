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

//! Deterministic security extension sources for the in-process target.
//!
//! Responsible for: fixed authorization outcomes, dispatch counts, bucket-owner metadata
//! availability, and declaring the counted cases unavailable on an external endpoint.
//! NOT responsible for: policy parsing, signing, or judging a conformance expectation.
//! Upstream: the selected case id. Downstream: `super::InProcess` service assembly.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, Decision, HandlerResult,
    InputAuthzRequest, InputDecisions, Next, Req, RequestContext, ResourceShape, ServiceBuilder, allow_when, dto, op_layer,
};

use crate::sut::SutError;

const BUCKET_OWNER_ACCOUNT_ID: &str = "123456789012";

pub(super) fn configure_version_list(builder: ServiceBuilder, case_id: &str, calls: Arc<AtomicUsize>) -> ServiceBuilder {
    let builder = if matches!(case_id, "c-authz-0008" | "c-authz-1016" | "c-authz-1017") {
        let (action, bucket) = match case_id {
            "c-authz-1016" => ("s3:ListBucket", "authz-versions"),
            "c-authz-1017" => ("s3:ListBucketVersions", "another-bucket"),
            _ => ("s3:ListBucketVersions", "authz-versions"),
        };
        builder.authorizer(allow_when(move |request| {
            request.action == action
                && request.resource == ResourceShape::Bucket
                && request.bucket.is_some_and(|name| name.as_str() == bucket)
                && request.key.is_none()
        }))
    } else {
        builder
    };
    builder.op_layer::<dto::ListObjectVersions, _>(op_layer(
        move |request: Req<dto::ListObjectVersions>, next: Next<'_, dto::ListObjectVersions>| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                next.run(request).await
            }) as BoxFuture<'_, HandlerResult<dto::ListObjectVersions>>
        },
    ))
}

/// The cases whose verdict reads a dispatch or credential counter of this target's own service,
/// each with what that counter decides. `super::InProcess::finish` judges them; the census in
/// `super::external_unavailable_tests` proves this table and that judgement name the same cases.
const COUNTED: &[(&str, &str)] = &[
    ("c-authz-0008", "that ListObjectVersions dispatch was reached exactly once"),
    (
        "c-authz-1016",
        "that ListObjectVersions dispatch was not reached after authorization refused",
    ),
    (
        "c-authz-1017",
        "that ListObjectVersions dispatch was not reached after authorization refused",
    ),
    ("c-authz-1018", "that only the ordinary copy control reached the copy backend"),
    (
        "c-authz-1001",
        "that the copy backend was not reached after authorization refused the source",
    ),
    (
        "c-authz-1011",
        "that the copy backend was not reached after authorization refused the source",
    ),
    (
        "c-authz-1012",
        "that the copy backend was not reached after authorization refused the source",
    ),
    ("c-cred-0002", "that the credential provider was not called for an anonymous request"),
    ("c-cred-0006", "how many of 100 identical misses reached the credential backend"),
    ("c-cred-0024", "that the forged key was classified as a credential lookup"),
];

/// Why an external endpoint cannot answer for `case_id`, when its verdict reads a counter only this
/// target's service increments; `None` for every other case. Against an endpoint the counter stays
/// zero, so the case would fail, or pass vacuously, for want of an observation.
pub(super) fn unavailable_externally(case_id: &str) -> Option<String> {
    COUNTED.iter().find(|(id, _)| *id == case_id).map(|(id, verdict)| {
        format!(
            "{id} judges {verdict}, a count only the in-process target's dispatch hooks can supply; it is \
             unavailable on an external endpoint, so the case is not run there"
        )
    })
}

pub(super) fn finish_version_list(case_id: &str, calls: usize) -> Result<(), SutError> {
    let violation = match case_id {
        "c-authz-1016" | "c-authz-1017" if calls != 0 => {
            format!("{case_id} reached version-list dispatch after authorization refused the request")
        }
        "c-authz-0008" if calls != 1 => "c-authz-0008 did not reach version-list dispatch exactly once".to_owned(),
        _ => return Ok(()),
    };
    Err(SutError::Environment(violation))
}

/// The case's denied source is an ARN identity with no inherited bucket.
pub(super) fn bucketless_outposts_decision(request: &AuthzRequest<'_>) -> Decision {
    if matches!(request.action, "s3:GetObject" | "s3:GetObjectVersion")
        && request.bucket.is_none()
        && request.key.is_some_and(|key| key.as_str() == "secret")
        && matches!(
            request.copy_source_identity,
            Some(rustfs_gateway::ResourceIdentity::Outposts { partition, region, account, outpost_id })
                if partition == "aws"
                    && region == "us-east-1"
                    && account == "123456789012"
                    && outpost_id == "op-denied"
        )
    {
        Decision::Deny
    } else {
        Decision::Allow
    }
}

pub(super) struct HeadObjectPolicy;

fn head_object_decision(request: &AuthzRequest<'_>) -> Decision {
    if request.operation != "HeadObject" {
        return Decision::Allow;
    }
    match request.key.map(|key| key.as_str()) {
        Some("denied/existing.txt" | "denied/missing.txt") => Decision::Deny,
        Some("uncertain/existing.txt") => Decision::Indeterminate,
        _ => Decision::Allow,
    }
}

impl Authorizer for HeadObjectPolicy {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        Box::pin(async move { head_object_decision(request) })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

pub(super) struct FixtureBucketOwner {
    pub(super) available: bool,
}

impl BucketOwnerSource for FixtureBucketOwner {
    fn owner<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        Box::pin(async move {
            if self.available {
                Ok(Arc::from(BUCKET_OWNER_ACCOUNT_ID))
            } else {
                Err(BucketOwnerError::unavailable())
            }
        })
    }
}

pub(super) struct FixedDecision(pub(super) Decision);

impl Authorizer for FixedDecision {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async move { self.0 })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(self.0, |_| self.0);
        Box::pin(async move { decisions })
    }
}
