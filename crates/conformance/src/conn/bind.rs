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

//! Fresh socket binding for the request-pacing rendezvous.
//!
//! Responsible for: making pacer queueing happen before a connection can be accepted.
//! NOT responsible for: pacing request bytes or choosing whether a connection is fresh.
//! Upstream: `super::Conn`. Downstream: the test and production socket listeners.

use std::sync::Arc;

use crate::socket::{Connection, Listener, Pacer};
use crate::sut::SutError;

#[cfg(feature = "production-transports")]
use crate::production::ProductionServer;

pub(super) trait PacerTarget {
    fn enqueue(&self, pacer: &Arc<Pacer>);
}

impl PacerTarget for Listener {
    fn enqueue(&self, pacer: &Arc<Pacer>) {
        self.enqueue_pacer(pacer);
    }
}

#[cfg(feature = "production-transports")]
impl PacerTarget for ProductionServer {
    fn enqueue(&self, pacer: &Arc<Pacer>) {
        self.enqueue_pacer(pacer);
    }
}

pub(super) fn connect(target: &impl PacerTarget, addr: std::net::SocketAddr, pacer: &Arc<Pacer>) -> Result<Connection, SutError> {
    connect_after_queueing(
        pacer,
        |pacer| {
            target.enqueue(pacer);
            Ok(())
        },
        || Connection::open(addr),
    )
}

pub(super) fn connect_after_queueing<T>(
    pacer: &Arc<Pacer>,
    queue: impl FnOnce(&Arc<Pacer>) -> Result<(), SutError>,
    connect: impl FnOnce() -> Result<T, SutError>,
) -> Result<T, SutError> {
    queue(pacer)?;
    connect()
}
