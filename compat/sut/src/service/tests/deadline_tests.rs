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

//! The request settings of the RustFS-profile launcher (rustfs/gateway#1070).
//!
//! Responsible for: `super::super::rustfs_service_config`, which `build_service` installs — every
//! framework deadline lifted with `Duration::MAX`, and nothing else moved from the builder's
//! defaults.
//! NOT responsible for: what `Duration::MAX` does at run time — `rustfs-gateway`'s
//! `tests/host_deadlines.rs` cancels a write mid-flight under a bounded deadline and lets the same
//! write finish whole under this one.
//! Upstream: the parent module. Downstream: nothing.

use rustfs_gateway::{DEFAULT_MAX_BUFFERED_BODY_BYTES, HandlerDeadlineClass, ServiceConfig};

use super::super::rustfs_service_config;

const NEVER: std::time::Duration = std::time::Duration::MAX;

/// Negative — no handler class, no committed continuation and no request body has a framework
/// deadline in the RustFS profile, where legacy RustFS has none.
#[test]
fn n_no_framework_deadline_is_left_in_force() {
    let settings = rustfs_service_config().expect("the RustFS profile's settings");
    for class in [HandlerDeadlineClass::Standard, HandlerDeadlineClass::Extended] {
        assert_eq!(settings.handler_deadline(class), NEVER, "{class:?}");
    }
    assert_eq!(settings.commit_progress_deadline(), NEVER);
    let body = settings.request_body_deadlines();
    assert_eq!(body.first_byte(), NEVER);
    assert_eq!(body.read_idle(), NEVER);
    assert_eq!(body.throughput_window(), NEVER);
}

/// Negative — lifting the deadlines moves nothing else: the in-memory body ceiling, the
/// signature-error detail and the cleanup grace are the builder's own defaults.
#[test]
fn n_nothing_but_the_deadlines_moves() {
    let settings = rustfs_service_config().expect("the RustFS profile's settings");
    let defaults = ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES);
    assert_eq!(settings.max_buffered_body_bytes(), defaults.max_buffered_body_bytes());
    assert_eq!(settings.verbose_signature_errors(), defaults.verbose_signature_errors());
    assert_eq!(settings.handler_cleanup_grace(), defaults.handler_cleanup_grace());
}
