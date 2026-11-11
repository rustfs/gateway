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

//! External payload settings for a registered operation.
//!
//! Responsible for: external upload registration and the registered control query's deadline class.
//! NOT responsible for: request binding, authorization or storage publication.
//! Upstream: ServiceBuilder. Downstream: dynamic operation dispatch.

use super::OperationDispatch;
use rustfs_gateway_core::HandlerDeadlineClass;

#[derive(Clone, Copy)]
pub(super) struct Registration {
    upload: bool,
    deadline_class: Option<HandlerDeadlineClass>,
}

impl Registration {
    pub(super) fn new(deadline_class: Option<HandlerDeadlineClass>) -> Self {
        Self {
            upload: false,
            deadline_class,
        }
    }
}

impl OperationDispatch {
    pub(crate) fn with_external_payload(mut self) -> Self {
        self.external_payload.upload = true;
        self
    }

    pub(crate) fn supports_external_payload(&self) -> bool {
        self.external_payload.upload
    }

    pub(crate) fn control_deadline_class(&self) -> Option<HandlerDeadlineClass> {
        self.external_payload.deadline_class
    }
}
