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

//! The `DIALECT_POSTURE` start-up line (ADR-0024).
//!
//! Responsible for: naming every path prefix a dialect claimed away from S3 routing, every
//! operation whose handler may be handed the caller's secret, and whether the assembly widened
//! that to every operation, as one tagged start-up line.
//! NOT responsible for: the `SECURITY_POSTURE` line, whose exact shape the dry-run and
//! `check_sig_case_coverage.sh` pin in `crate::posture` by once-only anchors this module keeps
//! unambiguous; installing claims, or deciding which handler receives the secret.
//! Upstream: `crate::builder` and `rustfs-gateway-core`'s router. Downstream: startup logs and
//! operators.

use std::collections::BTreeSet;

use rustfs_gateway_core::{InstalledClaim, OperationSpec, Router};

use crate::posture::format_names;

/// The dialect half of the start-up report (ADR-0024): every path prefix a dialect took away from
/// S3 routing, as `prefix@dialect`, every operation whose handler may be handed the caller's
/// secret, and whether the assembly widened that to every operation.
///
/// A line of its own rather than two more fields on `SECURITY_POSTURE`, whose exact shape the
/// dry-run and its guard pin; this one is new, and says so by its tag.
pub(crate) fn render_dialect_posture<'a>(
    claims: impl Iterator<Item = &'a InstalledClaim>,
    caller_secret_ops: impl Iterator<Item = &'static str>,
    every_operation: bool,
) -> String {
    let claims: BTreeSet<String> = claims
        .map(|installed| format!("{}@{}", installed.claim.prefix, installed.dialect))
        .collect();
    let caller_secret_ops: BTreeSet<&'static str> = caller_secret_ops.collect();
    format!(
        "DIALECT_POSTURE claimed_prefixes=[{}] caller_secret_ops=[{}] caller_secret_scope={}",
        claims.into_iter().collect::<Vec<_>>().join(","),
        format_names(&caller_secret_ops),
        if every_operation { "every-operation" } else { "opted-in" },
    )
}

/// Writes [`render_dialect_posture`] for an assembled router to the start-up log.
pub(crate) fn log_dialect_posture(router: &Router, every_operation: bool) {
    let registry = router.registry();
    let caller_secret_ops = registry
        .names()
        .filter(|name| registry.get(name).is_some_and(OperationSpec::receives_caller_secret));
    eprintln!(
        "{}",
        render_dialect_posture(router.claims().claims().iter(), caller_secret_ops, every_operation)
    );
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_core::{InstalledClaim, PathClaim};

    use super::render_dialect_posture;

    const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

    fn installed(dialect: &'static str, prefix: &'static str) -> InstalledClaim {
        InstalledClaim {
            dialect,
            claim: PathClaim {
                prefix,
                reason: "fixture",
                evidence: EVIDENCE,
            },
        }
    }

    /// Positive — every claim and every opted-in operation is named, sorted.
    #[test]
    fn the_dialect_report_names_every_claim_and_every_secret_operation() {
        let claims = [installed("rustfs", "/rustfs/admin"), installed("rustfs", "/minio/admin")];
        let report = render_dialect_posture(claims.iter(), ["rustfs:AddServiceAccount"].into_iter(), false);
        assert_eq!(
            report,
            "DIALECT_POSTURE claimed_prefixes=[/minio/admin@rustfs,/rustfs/admin@rustfs] caller_secret_ops=[rustfs:AddServiceAccount] caller_secret_scope=opted-in"
        );
    }

    /// Negative — an assembly with no claim and no opt-in says so, rather than omitting the line.
    #[test]
    fn a_dialect_report_with_nothing_installed_prints_empty_lists() {
        let report = render_dialect_posture(core::iter::empty(), core::iter::empty(), false);
        assert_eq!(
            report,
            "DIALECT_POSTURE claimed_prefixes=[] caller_secret_ops=[] caller_secret_scope=opted-in"
        );
        let widened = render_dialect_posture(core::iter::empty(), core::iter::empty(), true);
        assert_eq!(
            widened,
            "DIALECT_POSTURE claimed_prefixes=[] caller_secret_ops=[] caller_secret_scope=every-operation"
        );
    }
}
