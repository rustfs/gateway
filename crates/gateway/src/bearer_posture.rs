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

//! Startup report of operations declaring a query bearer claim.
//! Responsible for: listing declared operations and whether their host verifier is installed.
//! NOT responsible for: granting access or reporting token values.
//! Upstream: assembled routing and builder state. Downstream: startup log and posture report.

use crate::logging;
use crate::posture::format_names;
use rustfs_gateway_sig::OperationFloor;
use std::collections::BTreeSet;

pub(crate) fn log_bearer_posture<'a>(
    operations: impl Iterator<Item = &'a OperationFloor>,
    verifier_installed: bool,
) -> Option<String> {
    let claimed: BTreeSet<_> = operations
        .filter(|operation| operation.query_bearer_claim().is_some())
        .map(OperationFloor::name)
        .collect();
    if claimed.is_empty() {
        return None;
    }
    let verifier = if verifier_installed { "installed" } else { "none" };
    let line = format!(
        "BEARER_POSTURE bearer_claimed_ops=[{}] bearer_verifier={verifier}",
        format_names(&claimed)
    );
    tracing::info!(target: logging::TARGET, event = "gateway_bearer_posture", component = logging::COMPONENT, subsystem = logging::SUBSYSTEM_POSTURE, "{}", line);
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_gateway_sig::{QueryBearerClaim, SigService};

    #[test]
    fn only_declared_claims_are_reported_and_verifier_state_is_distinct() {
        let bearer = OperationFloor::custom("example:Download", SigService::S3)
            .with_query_bearer_claim(QueryBearerClaim::new("token", ".zip"));
        let other = OperationFloor::builtin("PutObject", SigService::S3);
        let absent = log_bearer_posture([&bearer, &other].into_iter(), false);
        let installed = log_bearer_posture([&bearer, &other].into_iter(), true);
        assert_eq!(
            absent.as_deref(),
            Some("BEARER_POSTURE bearer_claimed_ops=[example:Download] bearer_verifier=none")
        );
        assert_eq!(
            installed.as_deref(),
            Some("BEARER_POSTURE bearer_claimed_ops=[example:Download] bearer_verifier=installed")
        );
        assert!(log_bearer_posture([&other].into_iter(), true).is_none());
    }
}
