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

//! Startup-only security posture and the public assembly snapshot.
//!
//! Responsible for: rendering the security-sensitive deployment choices selected during
//! assembly and exposing the bounded runtime snapshot returned by `S3Service`.
//! NOT responsible for: HTTP diagnostics, runtime observations, or changing any security rule.
//! Upstream: `crate::builder` and `rustfs-gateway-sig`. Downstream: startup logs and operators.

use std::collections::BTreeSet;

use rustfs_gateway_sig::{OperationFloor, SecurityFloor};

// The start-up report's facade: `crate::builder` asks this module for both lines.
use crate::clock::ClockPosture;
pub(crate) use crate::dialect_posture::log_dialect_posture;
use crate::ext::{CredentialGuardConfig, GovernorRates, Rate};

/// Security-sensitive assembly configuration for a start-up report, not runtime observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityPosture {
    credential_guard: Option<CredentialGuardConfig>,
    per_ip: Rate,
    closed_layers: ClosedLayers,
    unlimited_layers: ClosedLayers,
    wall_clock: ClockPosture,
    custom_signature_verifier: bool,
    dangerously_replaced_signature_verifier: bool,
}

/// Which pre-authentication limiter layers were configured to admit nothing (c-gov-0031), or,
/// read through [`ClosedLayers::unlimited_of`], to admit everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct ClosedLayers {
    aggregate: bool,
    credential_lookup: bool,
    cors_preflight: bool,
    unauthenticated: bool,
}

impl ClosedLayers {
    const fn of(rates: &GovernorRates) -> Self {
        Self {
            aggregate: rates.aggregate.admits_nothing(),
            credential_lookup: rates.credential_lookup.admits_nothing(),
            cors_preflight: rates.cors_preflight.admits_nothing(),
            unauthenticated: rates.unauthenticated.admits_nothing(),
        }
    }

    /// The same four layers, marked where the host lifted the limit ([`Rate::unlimited`]).
    const fn unlimited_of(rates: &GovernorRates) -> Self {
        Self {
            aggregate: rates.aggregate.admits_everything(),
            credential_lookup: rates.credential_lookup.admits_everything(),
            cors_preflight: rates.cors_preflight.admits_everything(),
            unauthenticated: rates.unauthenticated.admits_everything(),
        }
    }

    fn names(self) -> impl Iterator<Item = &'static str> {
        [
            (self.aggregate, "aggregate"),
            (self.credential_lookup, "credential lookup"),
            (self.cors_preflight, "CORS preflight"),
            (self.unauthenticated, "unauthenticated"),
        ]
        .into_iter()
        .filter_map(|(closed, name)| closed.then_some(name))
    }
}

impl SecurityPosture {
    pub(crate) const fn new(
        credential_guard: Option<CredentialGuardConfig>,
        rates: &GovernorRates,
        wall_clock: ClockPosture,
        custom_signature_verifier: bool,
        dangerously_replaced_signature_verifier: bool,
    ) -> Self {
        Self {
            credential_guard,
            per_ip: rates.per_ip,
            closed_layers: ClosedLayers::of(rates),
            unlimited_layers: ClosedLayers::unlimited_of(rates),
            wall_clock,
            custom_signature_verifier,
            dangerously_replaced_signature_verifier,
        }
    }

    /// Where the wall clock that governs signature expiry comes from.
    #[must_use]
    pub const fn wall_clock(self) -> ClockPosture {
        self.wall_clock
    }

    /// The built-in credential guard settings, or `None` for an authenticator with no lookup.
    #[must_use]
    pub const fn credential_guard(self) -> Option<CredentialGuardConfig> {
        self.credential_guard
    }

    /// The mandatory framework's per-client pre-authentication rate.
    #[must_use]
    pub const fn per_ip_rate(self) -> Rate {
        self.per_ip
    }

    /// Whether the deployment installed a verifier for a registered non-AWS scheme.
    #[must_use]
    pub const fn custom_signature_verifier(self) -> bool {
        self.custom_signature_verifier
    }

    /// Whether the deployment replaced AWS signature computation after the H1..H7 floor.
    #[must_use]
    pub const fn dangerously_replaced_aws_signature_verifier(self) -> bool {
        self.dangerously_replaced_signature_verifier
    }
}

impl core::fmt::Display for SecurityPosture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.credential_guard {
            Some(config) if config.negative_entries == 0 || config.budget.negative_ttl().is_zero() => {
                f.write_str("credential negative cache: disabled")?;
            }
            Some(_) => f.write_str("credential negative cache: enabled")?,
            None => f.write_str("credential negative cache: not applicable")?,
        }
        if self.per_ip.admits_nothing() {
            f.write_str("; per-IP bucket: closed")?;
        } else if self.per_ip.admits_everything() {
            f.write_str("; per-IP bucket: unlimited")?;
        } else {
            write!(
                f,
                "; per-IP bucket: bounded ({}/s, burst {})",
                self.per_ip.per_second(),
                self.per_ip.burst()
            )?;
        }
        let mut closed = self.closed_layers.names().peekable();
        if closed.peek().is_some() {
            f.write_str("; closed pre-authentication layers: ")?;
            for (index, name) in closed.enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
            }
        }
        let mut unlimited = self.unlimited_layers.names().peekable();
        if unlimited.peek().is_some() {
            f.write_str("; unlimited pre-authentication layers: ")?;
            for (index, name) in unlimited.enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
            }
        }
        match self.wall_clock {
            ClockPosture::System => f.write_str("; wall clock: system")?,
            ClockPosture::CustomAcknowledged => {
                f.write_str("; wall clock: custom (acknowledged; signature expiry follows it)")?;
            }
        }
        if self.dangerously_replaced_signature_verifier {
            f.write_str("; AWS signature verifier: dangerously replaced")?;
        } else {
            f.write_str("; AWS signature verifier: built in")?;
        }
        if self.custom_signature_verifier {
            f.write_str("; custom signature verifier: installed")
        } else {
            f.write_str("; custom signature verifier: none")
        }
    }
}

pub(crate) fn format_names(names: &BTreeSet<&'static str>) -> String {
    names.iter().copied().collect::<Vec<_>>().join(",")
}

pub(crate) fn render_startup_posture<'a>(
    operations: impl Iterator<Item = &'a OperationFloor>,
    floor: &SecurityFloor,
    custom_signature_verifier: bool,
    dangerously_replaced_signature_verifier: bool,
) -> String {
    let operations: Vec<_> = operations.collect();
    let anonymous_reachable_ops: BTreeSet<_> = operations
        .iter()
        .copied()
        // The floor's own predicate, so the report cannot disagree with what the floor admits:
        // under delegation every non-privileged operation is listed (ADR-0021).
        .filter(|operation| floor.admits_anonymous(operation))
        .map(OperationFloor::name)
        .collect();
    let presigned_allowed_ops: BTreeSet<_> = operations
        .into_iter()
        .filter(|operation| !operation.privileged() && operation.allowed_schemes().allows_presigned())
        .map(OperationFloor::name)
        .collect();
    let custom_verifier = if custom_signature_verifier { "installed" } else { "none" };
    // The policy, not the derived presigned flag. Before P2-06's wiring, `sigv2=disabled` meant
    // "presigned SigV2 is off" while header SigV2 was refused outright, so the two readings agreed
    // by accident. Now that header SigV2 authenticates, a line reading `disabled` beside a live
    // SigV2 verifier would be a posture report that lies about which schemes are reachable.
    let sigv2_policy = floor.sigv2_policy().as_str();
    let aws_signature_verifier = if dangerously_replaced_signature_verifier {
        "dangerously-replaced"
    } else {
        "built-in"
    };
    format!(
        "SECURITY_POSTURE anonymous_reachable_ops=[{}] custom_verifier={custom_verifier} sigv2_policy={sigv2_policy} presigned_allowed_ops=[{}] aws_signature_verifier={aws_signature_verifier}",
        format_names(&anonymous_reachable_ops),
        format_names(&presigned_allowed_ops),
    )
}

pub(crate) fn log_startup_posture<'a>(
    operations: impl Iterator<Item = &'a OperationFloor>,
    floor: &SecurityFloor,
    custom_signature_verifier: bool,
    dangerously_replaced_signature_verifier: bool,
) {
    eprintln!(
        "{}",
        render_startup_posture(operations, floor, custom_signature_verifier, dangerously_replaced_signature_verifier,)
    );
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_sig::{OperationFloor, SecurityFloor, SigService};

    use super::render_startup_posture;

    #[test]
    fn the_startup_report_names_each_security_sensitive_dimension() {
        let anonymous =
            OperationFloor::builtin("PublicRead", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();
        let presigned = OperationFloor::builtin_presigned("GetObject", SigService::S3);
        let header_only = OperationFloor::builtin("PutObject", SigService::S3);
        let operations = [&header_only, &anonymous, &presigned];

        let report = render_startup_posture(operations.into_iter(), &SecurityFloor::new(), true, false);

        assert_eq!(
            report,
            "SECURITY_POSTURE anonymous_reachable_ops=[PublicRead] custom_verifier=installed sigv2_policy=HeaderOnly presigned_allowed_ops=[GetObject] aws_signature_verifier=built-in"
        );
    }

    /// Under delegation the list names every operation the floor now admits anonymously: each
    /// non-privileged one, plus a privileged one only when it opted in itself (ADR-0021).
    #[test]
    fn a_delegating_floor_lists_every_non_privileged_operation_as_anonymously_reachable() {
        let header_only = OperationFloor::builtin("PutObject", SigService::S3);
        let privileged = OperationFloor::custom("example:Admin", SigService::S3);
        let privileged_opted_in =
            OperationFloor::custom("example:PublicPing", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();
        let operations = [&header_only, &privileged, &privileged_opted_in];
        let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();

        let delegated = render_startup_posture(operations.into_iter(), &floor, false, false);
        let per_operation = render_startup_posture(operations.into_iter(), &SecurityFloor::new(), false, false);

        assert!(
            delegated.starts_with("SECURITY_POSTURE anonymous_reachable_ops=[PutObject,example:PublicPing] "),
            "{delegated}"
        );
        assert!(
            per_operation.starts_with("SECURITY_POSTURE anonymous_reachable_ops=[example:PublicPing] "),
            "{per_operation}"
        );
    }

    #[test]
    fn the_opposite_switches_and_empty_lists_render_differently() {
        let floor = SecurityFloor::new().enable_sigv2_presigned_compatibility();

        let report = render_startup_posture(core::iter::empty(), &floor, false, true);

        assert_eq!(
            report,
            "SECURITY_POSTURE anonymous_reachable_ops=[] custom_verifier=none sigv2_policy=HeaderAndPresigned presigned_allowed_ops=[] aws_signature_verifier=dangerously-replaced"
        );
    }
}
