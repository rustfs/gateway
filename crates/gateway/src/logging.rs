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

//! The vocabulary of every `tracing` event this crate emits: one target, one component, the
//! subsystems and the event names, each spelled once.
//!
//! Responsible for: the constants the event sites share, so that an operator's filter or an alert
//! keyed on `event = "…"` names a value that exists, and a renamed event is a one-line diff here.
//! NOT responsible for: emitting anything (each site emits its own event), installing a subscriber
//! (the host's: RustFS installs its own, a launcher installs whatever it likes), or the catalogue
//! operators read (`docs/observability.md`, which lists every event, level and field).
//! Upstream: nothing. Downstream: the posture modules, `crate::builder`, `crate::panic_boundary`,
//! `crate::ext::authorizer`.
//!
//! # Why the field shape is RustFS's
//!
//! RustFS embeds this crate and routes its events into its own logging pipeline, where dashboards and
//! alerts select on stable fields in a fixed order: `event`, `component`, `subsystem`, then a
//! `state` or `result`, then context, and a label last (rustfs/rustfs `e870a6d25b`,
//! `.agents/skills/rustfs-logging-governance/SKILL.md`; `rustfs/src/server/layer.rs:458-561` for the
//! HTTP events). Events of this crate carry the same fields in the same order, under a target of
//! their own, so a RustFS filter written for its own events reads these unchanged and a deployment
//! can raise or lower this crate's level alone (`RUST_LOG=rustfs_gateway=debug`). The label is a
//! short sentence, except on a posture event, whose message is the start-up line itself.
//!
//! The levels are RustFS's too, including where they leave an event out: RustFS's default level is
//! `error`, and it reports a disabled security control at `warn` (`tls_verification_disabled`,
//! `rustfs/src/admin/router.rs:794`), so a dangerous assembly is a `warn` event here, visible where
//! RustFS's own is (`docs/observability.md`, "A host's subscriber").
//!
//! # What no event carries
//!
//! A header value, a query string, a body byte, a signature, a secret, a session token or a
//! customer key. The fields are identifiers this crate minted or validated, names from its own
//! vocabulary, and counts; `scripts/check_secret_hygiene.sh` refuses a logging macro that formats
//! a credential-bearing value, and `tests/tracing_events.rs` captures every event the request
//! path emits and holds it to the same rule.

/// The target of every event this crate emits.
pub(crate) const TARGET: &str = "rustfs_gateway";

/// The `component` field of every event this crate emits.
pub(crate) const COMPONENT: &str = "gateway";

/// Start-up reports of what an assembly accepts.
pub(crate) const SUBSYSTEM_POSTURE: &str = "posture";
/// Assembly choices that disable or replace a security control.
pub(crate) const SUBSYSTEM_ASSEMBLY: &str = "assembly";
/// The deployment's read-only report callbacks (observer, authorization audit sink).
pub(crate) const SUBSYSTEM_REPORT: &str = "report";

/// The `SECURITY_POSTURE` start-up line.
pub(crate) const EVENT_SECURITY_POSTURE: &str = "gateway_security_posture";
/// The `DIALECT_POSTURE` start-up line.
pub(crate) const EVENT_DIALECT_POSTURE: &str = "gateway_dialect_posture";
/// The `PRESIGNED_EXPIRY_POSTURE` start-up line.
pub(crate) const EVENT_PRESIGNED_EXPIRY_POSTURE: &str = "gateway_presigned_expiry_posture";
/// The `NAMING_POSTURE` start-up line.
pub(crate) const EVENT_NAMING_POSTURE: &str = "gateway_naming_posture";
/// An assembly that disabled or replaced a security control; `reason` says which.
pub(crate) const EVENT_DANGEROUS_ASSEMBLY: &str = "gateway_dangerous_assembly";
/// A report callback panicked; `callback` names which, and the answer went out unchanged.
pub(crate) const EVENT_REPORT_PANICKED: &str = "gateway_report_panicked";

/// Reports an assembly choice that disables or replaces a security control, as one `warn` event.
///
/// `reason` is the stable name an alert selects on; `message` is the sentence the start-up log has
/// always carried for it. Both are fixed text written at the call site, never a value read from a
/// request or a configuration file.
pub(crate) fn dangerous_assembly(reason: &'static str, message: &'static str) {
    tracing::warn!(
        target: TARGET,
        event = EVENT_DANGEROUS_ASSEMBLY,
        component = COMPONENT,
        subsystem = SUBSYSTEM_ASSEMBLY,
        reason,
        "{message}"
    );
}

/// Reports the allow-all authorizer in an assembly. Spelled once here because two assembly paths
/// report it: [`crate::ServiceBuilder::build`] and the snapshot an [`crate::AssemblyUpdate`] builds.
pub(crate) fn allow_all_authorizer_assembled() {
    dangerous_assembly(
        "allow_all_authorizer",
        "dangerous allow-all authorizer disables authorization for every request",
    );
}
