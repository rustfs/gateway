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

//! The start-up report: every posture line an assembly writes, logged once and kept once.
//!
//! Responsible for: the posture lines in their fixed order — `SECURITY_POSTURE`, `DIALECT_POSTURE`
//! (and `FORM_CLAIM_POSTURE` when a dialect installed a form claim), `PRESIGNED_EXPIRY_POSTURE`
//! when a non-default rule is on, `NAMING_POSTURE`, `PROFILE_POSTURE` — logging every line but
//! the first, and returning all of them as the text [`S3Service::startup_posture`] hands a host;
//! and naming the router-held legacy reading in the profile line.
//! NOT responsible for: any line's text (each posture module renders its own), or logging
//! `SECURITY_POSTURE`: `ServiceBuilder::build` calls `crate::posture::log_startup_posture` itself,
//! immediately before this, because `scripts/check_sig_case_coverage.sh` anchors on that call in
//! the builder and on the live rendering inside it — which is why that one line is rendered here
//! a second time for the stored copy rather than logged from it.
//! Upstream: `crate::builder::ServiceBuilder::build`. Downstream: `crate::service::Inner`, which
//! keeps the text; `tests/tracing_events.rs` pins that it is what was logged, in order.

use std::collections::BTreeSet;

use rustfs_gateway_core::route::Selection;
use rustfs_gateway_sig::SecurityFloor;
use rustfs_gateway_types::NamePolicy;

use crate::dialect_posture::{dialect_lines, log_dialect_posture};
use crate::naming_posture::{log_naming_posture, render_naming_posture};
use crate::posture::render_startup_posture;
use crate::presigned_expiry_posture::{log_presigned_expiry_posture, render_presigned_expiry_posture};
use crate::profile_posture::{log_profile_posture, render_profile_posture};
use crate::routing::RoutingSnapshot;
use crate::service::S3Service;

/// What the report is rendered from: the assembled routing and the builder's posture-bearing state.
pub(crate) struct StartupInputs<'a> {
    pub(crate) routing: &'a RoutingSnapshot,
    pub(crate) floor: &'a SecurityFloor,
    pub(crate) custom_signature_verifier: bool,
    pub(crate) dangerously_replaced_signature_verifier: bool,
    pub(crate) caller_secret_every_operation: bool,
    pub(crate) names: &'a NamePolicy,
    /// The builder-held legacy readings (`ServiceBuilder::legacy_switches`); the router-held one
    /// is added here.
    pub(crate) legacy_switches: BTreeSet<&'static str>,
}

/// Logs every posture line but `SECURITY_POSTURE` (already logged by the builder) in order, and
/// returns all of them as one text, one line each, newline-ended.
pub(crate) fn emit(inputs: StartupInputs<'_>) -> String {
    let StartupInputs {
        routing,
        floor,
        custom_signature_verifier,
        dangerously_replaced_signature_verifier,
        caller_secret_every_operation,
        names,
        mut legacy_switches,
    } = inputs;
    let mut lines = Vec::with_capacity(6);
    lines.push(render_startup_posture(
        routing.dispatch.floors(),
        floor,
        custom_signature_verifier,
        dangerously_replaced_signature_verifier,
    ));
    log_dialect_posture(&routing.router, caller_secret_every_operation);
    lines.extend(
        dialect_lines(&routing.router, caller_secret_every_operation)
            .into_iter()
            .map(|(_, line)| line),
    );
    log_presigned_expiry_posture(floor);
    lines.extend(render_presigned_expiry_posture(floor));
    log_naming_posture(names);
    lines.push(render_naming_posture(names));
    if routing.router.selection() == Selection::RustfsLegacy {
        legacy_switches.insert("select_operations_as_legacy_rustfs");
    }
    log_profile_posture(&legacy_switches);
    lines.push(render_profile_posture(&legacy_switches));
    let mut report = String::with_capacity(lines.iter().map(|line| line.len() + 1).sum());
    for line in lines {
        report.push_str(&line);
        report.push('\n');
    }
    report
}

impl S3Service {
    /// The start-up posture report this service wrote when it was assembled: one line per posture
    /// event, in the order they were logged, each ending in a newline.
    ///
    /// The same text a `tracing` subscriber saw, kept so a host can print it through its own
    /// logger and so a deployment profile can pin it to a golden
    /// (`tests/golden/rustfs-profile-posture.txt`). It describes the assembly, not the live
    /// routing generation: a hot routing update changes what the service answers, not this text.
    #[must_use]
    pub fn startup_posture(&self) -> &str {
        &self.inner.startup_report
    }
}
