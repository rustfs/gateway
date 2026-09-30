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

//! The seam decode diff and the seam answer diff (rustfs/gateway#1076): what the RustFS app layer
//! is handed on each stack, and what each stack writes of what it answers.
//!
//! Responsible for: sending one raw request through the assembled gateway, whose handler converts
//! its input into the pinned legacy input through the production seam exactly as the RustFS
//! adapter does, and through the pinned legacy service, whose handler records the input it was
//! handed; then comparing the two legacy inputs member by member with the generated census, and
//! the body bytes each handler drained. Every covered operation is in [`SEAM_OPERATIONS`], so a
//! member the conversion drops, flattens or synthesises shows up as a named path. And the other
//! way: handing both handlers one legacy output, the gateway's converted through the seam as the
//! RustFS adapter converts an answer, and comparing the two answers ([`AnswerDiff`]) — as the
//! encode diff compares them, and value by value, so a member the conversion drops is named even
//! where the two documents differ in their root.
//! NOT responsible for: the gateway's own decode against the legacy one member by member in the
//! gateway's spelling (`decode.rs` does that for the operations it projects), the request
//! context (the goldens context diff), or deciding what a difference means (the seam register in
//! `samples.rs` and the answer register in `answers.rs` do).
//! Upstream: `stacks.rs`, `table.rs`, the census under `compat::s3s_0_17_0::generated::census`.
//! Downstream: this crate's `tests/seam.rs`, `tests/seam_answers.rs` and `tests/seam_outputs.rs`.

mod answers;
mod samples;
mod stacks;
mod table;
mod trailers;

pub(crate) use answers::{ANSWER_FINDINGS, UNWRITTEN_PATHS, Written, answer_rows};
#[cfg(test)]
pub(crate) use samples::document as samples_document;
#[cfg(test)]
pub(crate) use samples::omitted::OMITTED_OPERATIONS;
pub(crate) use samples::{Expect, SEAM_FINDINGS, SeamClass, SeamFinding, UNREACHED_PATHS, seam_rows};
pub(crate) use table::{LegacyOutput, SEAM_OPERATIONS, STORED_OPERATIONS, input_paths, output_paths};

use crate::decode::{Answer, BodySeen, Cmp, S3ErrorView};
use crate::request::RawRequest;
use stacks::{GatewaySeam, LegacySeam, Recorded};
pub(crate) use trailers::TrailerView;

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
    /// The configuration bytes each side would store, for a configuration write: the gateway's
    /// persistence writer over its own input, and the legacy serializer RustFS stores with.
    pub(crate) stored: Cmp<table::Stored>,
    /// The trailer handle each handler was handed, as a RustFS body reads it once the body ended
    /// (rustfs/gateway#1148); [`TrailerView::Absent`] on a side whose handler was not reached.
    pub(crate) trailers: Cmp<TrailerView>,
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
            && self.stored.same()
            && self.trailers.same()
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
        let (gateway_verdict, gateway_body, gateway_stored, gateway_trailers, gateway_input) = split(gateway);
        let (legacy_verdict, legacy_body, legacy_stored, legacy_trailers, legacy_input) = split(legacy);
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
            stored: Cmp {
                gateway: gateway_stored,
                s3s: legacy_stored,
            },
            trailers: Cmp {
                gateway: gateway_trailers,
                s3s: legacy_trailers,
            },
        })
    }
}

impl SeamDiffer {
    /// Sends `request` to both stacks with one RustFS answer queued for each handler — `build`
    /// makes the legacy output and the response headers the body sets beside it, once per stack —
    /// and returns what each wrote: the gateway's `(gateway, legacy)`.
    pub(crate) fn answer<T: Send + 'static>(
        &self,
        request: &RawRequest,
        build: impl Fn() -> (T, http::HeaderMap),
    ) -> Result<(crate::encode::WireAnswer, crate::encode::WireAnswer), String> {
        let (output, headers) = build();
        let gateway = self
            .gateway
            .answer(request, Box::new(stacks::LegacyAnswer { output, headers }))?;
        let (output, headers) = build();
        let legacy = self
            .legacy
            .answer(request, Box::new(stacks::LegacyAnswer { output, headers }))?;
        Ok((gateway, legacy))
    }
}

/// One legacy output — what a RustFS app body returns — written by both stacks: by the gateway
/// after the seam converted it as the RustFS adapter does, and by the pinned legacy service as it
/// is.
#[derive(Debug)]
pub(crate) struct AnswerDiff {
    /// The operation the output answers.
    pub(crate) operation: &'static str,
    /// The member paths the legacy output holds something at.
    pub(crate) present: Vec<String>,
    /// What the seam refused to hand over, when it refused: the gateway then answers an internal
    /// error instead of writing less than the output holds.
    pub(crate) refused: Option<rustfs_gateway_types::compat::ConversionError>,
    /// The status the gateway answered with.
    pub(crate) gateway_status: u16,
    /// The two answers, compared as the encode diff compares them, when the seam handed the output
    /// over. A refused output is not written by the legacy stack: there is nothing to compare.
    pub(crate) encode: Option<crate::encode::EncodeDiff>,
    /// The gateway's and the legacy stack's answers as compared (normalised), when compared.
    pub(crate) answers: Option<(crate::encode::WireAnswer, crate::encode::WireAnswer)>,
}

impl AnswerDiff {
    /// Every value the legacy answer holds that the gateway answer does not: a header line, or a
    /// body value (`xmltree::values`: an element's text or an attribute, whatever the order, the
    /// namespace or the root's name), or a body that is not XML and not the same bytes. Empty
    /// exactly when everything the legacy stack wrote of the output reached the gateway's wire.
    ///
    /// A header named in `excused_headers`, or a body value at or below a path in `excused_paths`,
    /// is left to the register entry that already argues how the two stacks spell it.
    pub(crate) fn lost(
        &self,
        excused_headers: &std::collections::BTreeSet<String>,
        excused_paths: &std::collections::BTreeSet<String>,
    ) -> Vec<String> {
        let Some((gateway, legacy)) = &self.answers else {
            return Vec::new();
        };
        let excused = |path: &str| {
            excused_paths.iter().any(|excused| {
                path == excused
                    || path
                        .strip_prefix(excused.as_str())
                        .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('@'))
            })
        };
        let mut lost = Vec::new();
        let mut offered: Vec<&(String, Vec<u8>)> = gateway.headers.iter().collect();
        for line in &legacy.headers {
            // Framing when a body follows: each side's own length (`encode.rs` holds each to it).
            if (line.0 == "content-length" && !legacy.body.is_empty()) || excused_headers.contains(&line.0) {
                continue;
            }
            match offered.iter().position(|candidate| *candidate == line) {
                Some(index) => {
                    offered.swap_remove(index);
                }
                None => lost.push(format!("header {}: {}", line.0, String::from_utf8_lossy(&line.1))),
            }
        }
        match (document(&gateway.body), document(&legacy.body)) {
            (Some(gateway_root), Some(legacy_root)) => {
                let mut offered = crate::xmltree::values(&gateway_root);
                for value in crate::xmltree::values(&legacy_root) {
                    if excused(&value.0) {
                        continue;
                    }
                    match offered.iter().position(|candidate| *candidate == value) {
                        Some(index) => {
                            offered.swap_remove(index);
                        }
                        None => lost.push(format!("body {}: {:?}", value.0, value.1)),
                    }
                }
            }
            _ if gateway.body == legacy.body => {}
            _ => lost.push("body: not the same bytes, and not two XML documents".to_owned()),
        }
        lost
    }
}

/// The root element of an XML answer body, its declaration and the whitespace after it skipped.
fn document(body: &[u8]) -> Option<crate::xmltree::Element> {
    let text = std::str::from_utf8(body).ok()?;
    let text = match text.strip_prefix("<?xml") {
        Some(rest) => rest.split_once("?>")?.1.trim_start(),
        None => text,
    };
    crate::xmltree::parse(text)
}

impl SeamDiffer {
    /// Sends `request` to both stacks with the legacy output `build` makes as each handler's
    /// answer, and compares what each wrote: status, every header line and the body.
    pub(crate) fn answer_diff<T: LegacyOutput>(&self, request: &RawRequest, build: impl Fn() -> T) -> Result<AnswerDiff, String> {
        self.answer_diff_pair(request, &build, &build)
    }

    /// [`Self::answer_diff`] with a different output for each stack: the negative controls hand the
    /// gateway less than the legacy stack, to prove the difference cannot go unreported.
    pub(crate) fn answer_diff_pair<T: LegacyOutput>(
        &self,
        request: &RawRequest,
        gateway_build: &dyn Fn() -> T,
        legacy_build: &dyn Fn() -> T,
    ) -> Result<AnswerDiff, String> {
        let present = legacy_build().present();
        let refused = gateway_build().convert(http::HeaderMap::new()).err();
        let mut gateway = self.gateway.answer(
            request,
            Box::new(stacks::LegacyAnswer {
                output: gateway_build(),
                headers: http::HeaderMap::new(),
            }),
        )?;
        let gateway_status = gateway.status;
        let (encode, answers) = match refused {
            Some(_) => (None, None),
            None => {
                let mut legacy = self.legacy.answer(
                    request,
                    Box::new(stacks::LegacyAnswer {
                        output: legacy_build(),
                        headers: http::HeaderMap::new(),
                    }),
                )?;
                let head = request.method == http::Method::HEAD;
                let encode = crate::encode::compare(T::OPERATION.to_owned(), head, &mut gateway, &mut legacy);
                (Some(encode), Some((gateway, legacy)))
            }
        };
        Ok(AnswerDiff {
            operation: T::OPERATION,
            present,
            refused,
            gateway_status,
            encode,
            answers,
        })
    }
}

type Handed = (&'static str, Box<dyn std::any::Any + Send>);

type Split = (SeamVerdict, Option<BodySeen>, table::Stored, TrailerView, Option<Handed>);

fn split(answer: Answer<Recorded>) -> Split {
    match answer {
        Answer::Refused(view) => (SeamVerdict::Refused(view), None, None, TrailerView::Absent, None),
        Answer::Handed(recorded) => match recorded.input {
            Ok(input) => (
                SeamVerdict::Handed,
                recorded.body,
                recorded.stored,
                recorded.trailers,
                Some((recorded.operation, input)),
            ),
            Err(error) => (
                SeamVerdict::Unconverted {
                    member: error.field,
                    reason: error.reason,
                },
                recorded.body,
                recorded.stored,
                recorded.trailers,
                None,
            ),
        },
    }
}
