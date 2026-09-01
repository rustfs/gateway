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
//! Responsible for: fixed authorization outcomes and bucket-owner metadata availability.
//! NOT responsible for: policy parsing, signing, or judging a conformance expectation.
//! Upstream: the selected case id. Downstream: `super::InProcess` service assembly.

use std::sync::Arc;

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, Decision, InputAuthzRequest,
    InputDecisions, RequestContext,
};

const BUCKET_OWNER_ACCOUNT_ID: &str = "123456789012";

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
