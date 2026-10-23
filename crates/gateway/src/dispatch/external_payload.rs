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

//! Private capability evidence attached by explicit external upload registration.
//!
//! Responsible for: enabling and reading an operation's external-input registration evidence.
//! NOT responsible for: request binding, authorization or storage publication.
//! Upstream: ServiceBuilder. Downstream: dynamic operation dispatch.

use super::OperationDispatch;

impl OperationDispatch {
    pub(crate) fn enable_external_payload(&mut self) {
        self.external_payload = true;
    }

    pub(crate) fn supports_external_payload(&self) -> bool {
        self.external_payload
    }
}
