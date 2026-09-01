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

//! Responsible for: exposing conditional-write rendezvous controls to the socket transport.
//! Not responsible for: evaluating conditions, committing writes, or selecting race batches.
//! Upstream: `crate::conn`; downstream: `crate::fixture::ConditionalRaceCoordinator`.

use std::time::Duration;

use crate::sut::SutError;

use super::InProcess;

impl InProcess {
    /// Arms the fixture rendezvous for one batch of conditional writes to the same resource.
    pub(crate) fn begin_conditional_race(&self, participants: usize) -> Result<(), SutError> {
        let coordinator = self
            .state
            .lock()
            .map_err(|_| SutError::Environment("the fixture state was left poisoned".to_owned()))?
            .conditional_race_coordinator();
        coordinator
            .begin(participants)
            .map_err(|reason| SutError::Environment(reason.to_owned()))
    }

    /// Waits until the named prefix of a concurrent batch has reached its conditional check.
    pub(crate) fn wait_for_conditional_checks(&self, minimum: usize, timeout: Duration) -> Result<(), SutError> {
        let coordinator = self
            .state
            .lock()
            .map_err(|_| SutError::Environment("the fixture state was left poisoned".to_owned()))?
            .conditional_race_coordinator();
        coordinator
            .wait_until_checked(minimum, timeout)
            .map_err(|reason| SutError::Environment(reason.to_owned()))
    }

    /// Disarms the fixture rendezvous after every concurrent response has been observed.
    pub(crate) fn end_conditional_race(&self) {
        let coordinator = self.state.lock().ok().map(|fixture| fixture.conditional_race_coordinator());
        if let Some(coordinator) = coordinator {
            coordinator.end();
        }
    }
}
