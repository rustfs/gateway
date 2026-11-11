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

//! Startup report of the host-verified header token claim (ADR-0050).
//! Responsible for: one `HEADER_TOKEN_POSTURE` line naming the claimed header, whether its host
//! verifier is installed, and every operation the floor admits by it; nothing without a claim.
//! NOT responsible for: granting access or reporting any token value.
//! Upstream: assembled routing and the security floor. Downstream: startup log and posture report.

use std::collections::BTreeSet;

use rustfs_gateway_sig::{OperationFloor, SecurityFloor};

use crate::logging;
use crate::posture::format_names;

pub(crate) fn log_header_token_posture<'a>(
    operations: impl Iterator<Item = &'a OperationFloor>,
    floor: &SecurityFloor,
    verifier_installed: bool,
) -> Option<String> {
    let claim = floor.header_token_claim()?;
    // The floor's own predicate, so the report cannot disagree with what the floor admits.
    let admitting: BTreeSet<_> = operations
        .filter(|operation| floor.admits_header_token(operation))
        .map(OperationFloor::name)
        .collect();
    let verifier = if verifier_installed { "installed" } else { "none" };
    let line = format!(
        "HEADER_TOKEN_POSTURE header_token={} header_token_verifier={verifier} header_token_ops=[{}]",
        claim.header(),
        format_names(&admitting)
    );
    tracing::info!(target: logging::TARGET, event = "gateway_header_token_posture", component = logging::COMPONENT, subsystem = logging::SUBSYSTEM_POSTURE, "{}", line);
    Some(line)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use rustfs_gateway_sig::{HeaderTokenClaim, QueryBearerClaim, SigService};

    use super::*;

    #[test]
    fn the_line_names_the_claim_the_verifier_state_and_only_the_admitting_operations() {
        let standard = OperationFloor::builtin("PutObject", SigService::S3);
        let privileged = OperationFloor::custom("example:Admin", SigService::S3);
        let bearer = OperationFloor::builtin("example:Download", SigService::S3)
            .with_query_bearer_claim(QueryBearerClaim::new("token", ".zip"));
        let signed_only =
            OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3).require_sigv4_under_every_policy();
        let operations = [&standard, &privileged, &bearer, &signed_only];
        let claimed = SecurityFloor::new().with_header_token_claim(HeaderTokenClaim::new("x-auth-token").expect("a legal claim"));

        assert_eq!(
            log_header_token_posture(operations.into_iter(), &claimed, true).as_deref(),
            Some("HEADER_TOKEN_POSTURE header_token=x-auth-token header_token_verifier=installed header_token_ops=[PutObject]")
        );
        assert_eq!(
            log_header_token_posture(operations.into_iter(), &claimed, false).as_deref(),
            Some("HEADER_TOKEN_POSTURE header_token=x-auth-token header_token_verifier=none header_token_ops=[PutObject]")
        );
        assert!(log_header_token_posture(operations.into_iter(), &SecurityFloor::new(), true).is_none());
    }
}
