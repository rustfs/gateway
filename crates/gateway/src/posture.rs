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

use crate::ext::{CredentialGuardConfig, Rate};

/// Security-sensitive assembly configuration for a start-up report, not runtime observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityPosture {
    credential_guard: Option<CredentialGuardConfig>,
    per_ip: Rate,
    custom_signature_verifier: bool,
    dangerously_replaced_signature_verifier: bool,
}

impl SecurityPosture {
    pub(crate) const fn new(
        credential_guard: Option<CredentialGuardConfig>,
        per_ip: Rate,
        custom_signature_verifier: bool,
        dangerously_replaced_signature_verifier: bool,
    ) -> Self {
        Self {
            credential_guard,
            per_ip,
            custom_signature_verifier,
            dangerously_replaced_signature_verifier,
        }
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
        } else {
            write!(
                f,
                "; per-IP bucket: bounded ({}/s, burst {})",
                self.per_ip.per_second(),
                self.per_ip.burst()
            )?;
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

fn format_names(names: &BTreeSet<&'static str>) -> String {
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
        .filter(|operation| operation.allows_anonymous())
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
