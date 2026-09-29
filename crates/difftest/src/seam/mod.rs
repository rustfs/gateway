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

//! The seam decode diff (rustfs/gateway#1076): what the RustFS app layer is handed on each stack.
//!
//! Responsible for: sending one raw request through the assembled gateway, whose handler converts
//! its input into the pinned legacy input through the production seam exactly as the RustFS
//! adapter does, and through the pinned legacy service, whose handler records the input it was
//! handed; then comparing the two legacy inputs member by member with the generated census, and
//! the body bytes each handler drained. Every covered operation is in [`SEAM_OPERATIONS`], so a
//! member the conversion drops, flattens or synthesises shows up as a named path.
//! NOT responsible for: the gateway's own decode against the legacy one member by member in the
//! gateway's spelling (`decode.rs` does that for the operations it projects), the request
//! context (the goldens context diff), outputs, or deciding what a difference means (the seam
//! register in `samples.rs` does).
//! Upstream: `stacks.rs`, `table.rs`, the census under `compat::s3s_0_17_0::generated::census`.
//! Downstream: this crate's `tests/seam.rs`.

mod samples;
mod stacks;
mod table;

#[cfg(test)]
pub(crate) use samples::document as samples_document;
#[cfg(test)]
pub(crate) use samples::omitted::OMITTED_OPERATIONS;
pub(crate) use samples::{Expect, SEAM_FINDINGS, SeamClass, SeamFinding, UNREACHED_PATHS, seam_rows};
pub(crate) use table::{SEAM_OPERATIONS, input_paths};

use crate::decode::{Answer, BodySeen, Cmp, S3ErrorView};
use crate::request::RawRequest;
use stacks::{GatewaySeam, LegacySeam, Recorded};

/// What one side did with a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SeamVerdict {
    /// The handler was reached and, on the gateway side, the seam converted the input.
    Handed,
    /// The gateway handler was reached and the seam refused the input, naming the member.
    Unconverted {
        /// The member the conversion named.
        member: &'static str,
        /// Why the value does not fit.
        reason: &'static str,
    },
    /// The stack refused before its handler.
    Refused(S3ErrorView),
}

/// One raw request through both stacks.
#[derive(Debug)]
pub(crate) struct SeamDiff {
    /// The operation each stack routed to.
    pub(crate) routed: Cmp<Option<String>>,
    /// What each stack did with it.
    pub(crate) verdict: Cmp<SeamVerdict>,
    /// The legacy-input member paths at which the two inputs differ, when both were handed.
    pub(crate) differing: Vec<String>,
    /// The member paths the legacy input holds, when the legacy handler was reached.
    pub(crate) present: Vec<String>,
    /// The body bytes each handler drained, when either carried one.
    pub(crate) body: Cmp<Option<BodySeen>>,
}

impl SeamDiff {
    /// Whether both stacks handed the RustFS app layer the same input.
    #[must_use]
    pub(crate) fn identical(&self) -> bool {
        self.routed.same()
            && self.verdict.gateway == SeamVerdict::Handed
            && self.verdict.s3s == SeamVerdict::Handed
            && self.differing.is_empty()
            && self.body.same()
    }
}

/// The two stacks, built once and reused for every request.
pub(crate) struct SeamDiffer {
    gateway: GatewaySeam,
    legacy: LegacySeam,
}

impl SeamDiffer {
    /// Assembles both stacks, or says why the gateway assembly refused its own configuration.
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self {
            gateway: GatewaySeam::new()?,
            legacy: LegacySeam::new(),
        })
    }

    /// Sends `request` through both stacks and compares what each handler was handed.
    ///
    /// A harness failure — a request that cannot be built, or a service that answered without a
    /// verdict — is an `Err`; a refusal is a verdict, and two handlers of different operations are
    /// a routing divergence with nothing compared.
    pub(crate) fn diff(&self, request: &RawRequest) -> Result<SeamDiff, String> {
        self.diff_pair(request, request)
    }

    /// [`Self::diff`] with a different request for each stack: the negative controls send two
    /// requests that differ on purpose, to prove the difference cannot go unreported.
    pub(crate) fn diff_pair(&self, gateway_request: &RawRequest, legacy_request: &RawRequest) -> Result<SeamDiff, String> {
        let (gateway_routed, gateway) = self.gateway.send(gateway_request)?;
        let (legacy_routed, legacy) = self.legacy.send(legacy_request)?;
        let (gateway_verdict, gateway_body, gateway_input) = split(gateway);
        let (legacy_verdict, legacy_body, legacy_input) = split(legacy);
        let (present, differing) = match legacy_input {
            Some((operation, legacy_input)) => {
                // Two handlers of different operations compare nothing: the routing divergence is
                // the finding, and the decode diff owns it.
                let gateway_input = gateway_input
                    .filter(|(gateway_operation, _)| *gateway_operation == operation)
                    .map(|(_, input)| input);
                table::compare(operation, gateway_input, legacy_input)?
            }
            None => (Vec::new(), Vec::new()),
        };
        Ok(SeamDiff {
            routed: Cmp {
                gateway: gateway_routed,
                s3s: legacy_routed,
            },
            verdict: Cmp {
                gateway: gateway_verdict,
                s3s: legacy_verdict,
            },
            differing,
            present,
            body: Cmp {
                gateway: gateway_body,
                s3s: legacy_body,
            },
        })
    }
}

type Handed = (&'static str, Box<dyn std::any::Any + Send>);

fn split(answer: Answer<Recorded>) -> (SeamVerdict, Option<BodySeen>, Option<Handed>) {
    match answer {
        Answer::Refused(view) => (SeamVerdict::Refused(view), None, None),
        Answer::Handed(recorded) => match recorded.input {
            Ok(input) => (SeamVerdict::Handed, recorded.body, Some((recorded.operation, input))),
            Err(error) => (
                SeamVerdict::Unconverted {
                    member: error.field,
                    reason: error.reason,
                },
                recorded.body,
                None,
            ),
        },
    }
}
