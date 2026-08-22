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

//! Faults, frozen heads, and reserved versions for committed fixture operations.
//!
//! Responsible for: arranging post-commit faults, validating their operation set, freezing
//! operation headers, and reserving version ids before detached work begins. NOT responsible for:
//! the copy or multipart assembly itself.
//! Upstream: conformance setup faults and `Fixture`. Downstream: committed fixture handlers.

use rustfs_gateway::{DeferredOperation, ErrorCode, HandlerError, HeadPart};

use super::{Fixture, StoredObject, UNVERSIONED, no_such_key};

#[derive(Debug, Clone)]
pub(super) struct CommittedFault {
    operation: String,
    effect: CommittedFaultEffect,
}

#[derive(Debug, Clone)]
enum CommittedFaultEffect {
    Reports(ErrorCode),
    StopsMakingProgress,
}

/// What a configured post-commit fault does to the detached continuation.
#[derive(Debug)]
pub(crate) enum ArmedFault {
    /// Fail the continuation with this refusal.
    Reports(HandlerError),
    /// Never resolve.
    StopsMakingProgress,
}

/// The operation names this fixture commits a head for and can fault after commitment.
pub const COMMITTED_OPERATIONS: &[&str] = &[COMPLETE_MULTIPART_UPLOAD, COPY_OBJECT];

pub(super) const COMPLETE_MULTIPART_UPLOAD: &str = "CompleteMultipartUpload";
pub(super) const COPY_OBJECT: &str = "CopyObject";

pub(super) fn head<O: DeferredOperation>(bindings: &[(&'static str, Option<&str>)]) -> Result<HeadPart<O>, HandlerError> {
    let mut headers = http::HeaderMap::new();
    for (name, value) in bindings {
        let Some(value) = value else { continue };
        let value = http::HeaderValue::try_from(*value)
            .map_err(|_| HandlerError::internal_error("a committed fixture header was not an HTTP field value"))?;
        headers.insert(http::HeaderName::from_static(name), value);
    }
    HeadPart::new(headers).map_err(|_| HandlerError::internal_error("a committed fixture header was not operation-bound"))
}

/// A fault was armed against an operation this fixture does not commit a head for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreportableFault {
    operation: String,
}

impl UnreportableFault {
    /// The operation the case named.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

const COMMITTED_FAULT_MESSAGE: &str = "The operation failed after its response head had been committed.";

impl Fixture {
    pub(super) fn put_object_with_version(&mut self, bucket: &str, key: &str, object: StoredObject, version: String) {
        let last_modified = object.last_modified;
        let versions = self.objects.entry((bucket.to_owned(), key.to_owned())).or_default();
        if version == UNVERSIONED {
            versions.clear();
        }
        versions.push(super::StoredVersion {
            version_id: version,
            object: Some(object),
            last_modified,
        });
    }

    /// Arms a reported failure after `operation` commits its response head.
    pub fn arm_committed_fault(&mut self, operation: &str, code: ErrorCode) -> Result<(), UnreportableFault> {
        self.arm(operation, CommittedFaultEffect::Reports(code))
    }

    /// Arms a continuation that never resolves after `operation` commits its response head.
    pub fn arm_committed_stall(&mut self, operation: &str) -> Result<(), UnreportableFault> {
        self.arm(operation, CommittedFaultEffect::StopsMakingProgress)
    }

    fn arm(&mut self, operation: &str, effect: CommittedFaultEffect) -> Result<(), UnreportableFault> {
        if !COMMITTED_OPERATIONS.contains(&operation) {
            return Err(UnreportableFault {
                operation: operation.to_owned(),
            });
        }
        self.committed_fault = Some(CommittedFault {
            operation: operation.to_owned(),
            effect,
        });
        Ok(())
    }

    #[must_use]
    pub(super) fn committed_fault(&self, operation: &str, subject: &str) -> Option<ArmedFault> {
        let fault = self.committed_fault.as_ref().filter(|fault| fault.operation == operation)?;
        match &fault.effect {
            CommittedFaultEffect::StopsMakingProgress => Some(ArmedFault::StopsMakingProgress),
            CommittedFaultEffect::Reports(code) if *code == ErrorCode::NO_SUCH_KEY => {
                Some(ArmedFault::Reports(no_such_key(subject)))
            }
            CommittedFaultEffect::Reports(code) => {
                Some(ArmedFault::Reports(HandlerError::new(code.clone(), COMMITTED_FAULT_MESSAGE)))
            }
        }
    }
}
