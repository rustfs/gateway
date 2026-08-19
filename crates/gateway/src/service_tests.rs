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

//! The assembled pipeline's own unit suite.
//!
//! Responsible for: the two claims decidable without a request — that an `S3Service` is one
//! pointer wide, and that the transport-security reader answers both ways rather than being stuck
//! on one.
//! NOT responsible for: what a request does to the pipeline, which is `crates/gateway/tests/`.
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;

/// Positive — cloning the service is one pointer's worth of work, which is what makes cloning
/// it per connection the right thing for a server to do.
#[test]
fn the_service_is_one_pointer_wide() {
    assert_eq!(core::mem::size_of::<S3Service>(), core::mem::size_of::<usize>());
}

/// Negative — a request nobody annotated is cleartext, so the customer-key gate is closed by
/// default rather than open by default.
#[test]
fn an_unannotated_request_is_cleartext() {
    assert_eq!(connection_security(&http::Extensions::new()), TransportSecurity::Plaintext);
}

/// Negative — and the other direction, so the reader is not simply stuck on one answer. A
/// function that returned `Plaintext` unconditionally satisfies every test above.
#[test]
fn n_a_transport_that_declares_tls_is_believed_and_one_that_declares_cleartext_is_too() {
    let mut encrypted = http::Extensions::new();
    encrypted.insert(TransportSecurity::Encrypted);
    assert_eq!(connection_security(&encrypted), TransportSecurity::Encrypted);
    let mut plaintext = http::Extensions::new();
    plaintext.insert(TransportSecurity::Plaintext);
    assert_eq!(connection_security(&plaintext), TransportSecurity::Plaintext);
}
