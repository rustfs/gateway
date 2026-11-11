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

//! Startup report of the host-verified header token claim (ADR-0053).
//! Responsible for: one `HEADER_TOKEN_POSTURE` line naming the claimed header, the aliases it
//! refuses, and every operation the floor admits by it; nothing without a claim. A claim is
//! never assembled without its verifier, so the line reports none.
//! NOT responsible for: granting access or reporting any token value.
//! Upstream: assembled routing and the security floor. Downstream: startup log and posture report.

use std::collections::BTreeSet;

use rustfs_gateway_sig::{OperationFloor, SecurityFloor};

use crate::logging;
use crate::posture::format_names;

pub(crate) fn log_header_token_posture<'a>(
    operations: impl Iterator<Item = &'a OperationFloor>,
    floor: &SecurityFloor,
) -> Option<String> {
    let claim = floor.header_token_claim()?;
    // The floor's own predicate, so the report cannot disagree with what the floor admits.
    let admitting: BTreeSet<_> = operations
        .filter(|operation| floor.admits_header_token(operation))
        .map(OperationFloor::name)
        .collect();
    let line = format!(
        "HEADER_TOKEN_POSTURE header_token={} refused_aliases=[{}] header_token_ops=[{}]",
        claim.header(),
        claim.refused_aliases().join(","),
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
    fn the_line_names_the_claim_its_refused_aliases_and_only_the_admitting_operations() {
        let standard = OperationFloor::builtin("PutObject", SigService::S3);
        let privileged = OperationFloor::custom("example:Admin", SigService::S3);
        let bearer = OperationFloor::builtin("example:Download", SigService::S3)
            .with_query_bearer_claim(QueryBearerClaim::new("token", ".zip"));
        let signed_only =
            OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3).require_sigv4_under_every_policy();
        let form = OperationFloor::builtin("example:Form", SigService::S3).allow_post_policy();
        let issuing = OperationFloor::builtin("example:AssumeRole", SigService::Sts);
        let operations = [&standard, &privileged, &bearer, &signed_only, &form, &issuing];
        let claimed = SecurityFloor::new().with_header_token_claim(HeaderTokenClaim::new("x-auth-token").expect("a legal claim"));

        assert_eq!(
            log_header_token_posture(operations.into_iter(), &claimed).as_deref(),
            Some("HEADER_TOKEN_POSTURE header_token=x-auth-token refused_aliases=[] header_token_ops=[PutObject]")
        );
        let aliased = HeaderTokenClaim::new("x-auth-token")
            .and_then(|claim| claim.refusing_aliases(&["x-storage-token"]))
            .expect("a legal claim");
        let aliased = SecurityFloor::new().with_header_token_claim(aliased);
        assert_eq!(
            log_header_token_posture(operations.into_iter(), &aliased).as_deref(),
            Some("HEADER_TOKEN_POSTURE header_token=x-auth-token refused_aliases=[x-storage-token] header_token_ops=[PutObject]")
        );
        assert!(log_header_token_posture(operations.into_iter(), &SecurityFloor::new()).is_none());
    }
}
