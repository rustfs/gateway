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

//! Owns lazy listener assembly for the socket conformance target.
//!
//! Responsible for: starting the selected test or production listener with the case's clock and
//! profile. NOT responsible for: request bytes, pacing, or observations. Upstream: `super::Conn`.
//! Downstream: the sequential and concurrent socket exchange drivers.

use std::net::SocketAddr;

#[cfg(feature = "production-transports")]
use crate::production::ProductionServer;
use crate::socket::{Announce, Listener, honour_the_services_intent};
use crate::sut::{Profile, SutError};

use super::Conn;

impl Conn {
    /// Returns the test listener for this case, starting it on first use.
    pub(super) fn listener(&mut self, at_unix_seconds: i64, skew_ms: i64, profile: Profile) -> Result<&Listener, SutError> {
        if self.listener.is_none() {
            let service = self.inner.assemble(at_unix_seconds, skew_ms, profile)?;
            self.listener = Some(Listener::start(service, honour_the_services_intent(), Announce::Matching)?);
        }
        self.listener
            .as_ref()
            .ok_or_else(|| SutError::Environment("the listener vanished between starting and using it".to_owned()))
    }

    /// Returns the selected listener's kernel address, starting that listener on first use.
    pub(super) fn addr(&mut self, at_unix_seconds: i64, skew_ms: i64, profile: Profile) -> Result<SocketAddr, SutError> {
        #[cfg(feature = "production-transports")]
        if let Some(driver) = self.driver {
            if self.production.is_none() {
                let service = self.inner.assemble(at_unix_seconds, skew_ms, profile)?;
                self.production = Some(ProductionServer::start(service, driver)?);
            }
            return self
                .production
                .as_ref()
                .ok_or_else(|| SutError::Environment("the production listener vanished after starting".to_owned()))?
                .addr();
        }
        Ok(self.listener(at_unix_seconds, skew_ms, profile)?.addr())
    }
}
