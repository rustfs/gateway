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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! What a wire refusal actually says to a client, checked on the rendered bytes.
//!
//! `rustfs-gateway-http` has two strings per refusal, for two audiences: [`WireReject::message`]
//! is what a client reads, and [`WireReject::label`] is an operator's identifier for a log. The
//! renderer picked the wrong one — `<Message>limit-exceeded</Message>` reached clients, an
//! internal name that changes with a refactor and that a client would learn to parse.
//!
//! There used to be a third accessor, `as_str`, delegating to `message`, and a test in the `-http`
//! crate pinning that delegation. Both are gone: a name reached for out of habit that happens to
//! be right is not a guarantee, and the test could only ever assert something about an accessor.
//! What matters is the bytes, and the bytes are produced here — so the check is here, on the
//! document, where a regression has nowhere left to hide.

use rustfs_gateway::{FixedTrace, RequestTrace, S3Error, TraceSource, document};
use rustfs_gateway_http::{HostError, LimitKind, MetadataReject, WireReject};

/// Every refusal the wire layer can reach, in one list.
///
/// Written out rather than derived: a variant added without a thought about what it tells a
/// client should fail to compile here, and an `all()` helper on the enum would remove exactly
/// that friction.
fn every_reject() -> Vec<WireReject> {
    let header = http::HeaderName::from_static("x-amz-meta-one");
    let mut all = vec![
        WireReject::ContentLengthTransferEncodingConflict,
        WireReject::TransferEncodingMalformed,
        WireReject::TransferEncodingOnHttp2,
        WireReject::DuplicateContentLength,
        WireReject::MalformedContentLength,
        WireReject::MalformedChunkFraming,
        WireReject::DuplicateSingleValuedHeader("authorization"),
        WireReject::DuplicateSingleValuedQuery("versionId"),
        WireReject::AmbiguousQueryParameterName,
        WireReject::NonUtf8SignificantHeader(header.clone()),
        WireReject::MalformedHeaderValue(header),
        WireReject::MalformedMetadata(MetadataReject::ControlCharacterAfterDecoding),
        WireReject::MalformedRequestTarget,
        WireReject::MalformedQuery,
        WireReject::Host(HostError::Duplicate),
    ];
    all.extend(LIMIT_KINDS.iter().copied().map(WireReject::LimitExceeded));
    all
}

/// Every ceiling, so that a new one cannot be added without a message being chosen for it.
const LIMIT_KINDS: &[LimitKind] = &[
    LimitKind::HeaderCount,
    LimitKind::HeaderBytes,
    LimitKind::UriBytes,
    LimitKind::QueryBytes,
    LimitKind::QueryParams,
    LimitKind::HostBytes,
    LimitKind::BodyBytes,
    LimitKind::ChunkSizeLine,
];

fn trace() -> RequestTrace {
    FixedTrace::at(0x0102_0304_0506_0708, 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10).mint()
}

/// Negative — no refusal renders an operator label into the document a client reads.
///
/// Checked across the whole product, not each label against its own message: a rendering that
/// picked the label of a *different* variant would still be a leak, and comparing pairwise is the
/// only way to say so.
#[test]
fn no_operator_label_appears_in_a_rendered_refusal() {
    let trace = trace();
    let labels: Vec<&str> = every_reject().iter().map(WireReject::label).collect();
    for reject in every_reject() {
        let rendered = document(&S3Error::from(reject.clone()), &trace);
        for label in &labels {
            assert!(
                !rendered.contains(label),
                "the document for {reject:?} contains the operator label {label:?}:\n{rendered}"
            );
        }
    }
}

/// Positive — the document says exactly what the client-facing message says.
#[test]
fn a_rendered_refusal_carries_the_client_message() {
    let trace = trace();
    for reject in every_reject() {
        let rendered = document(&S3Error::from(reject.clone()), &trace);
        assert!(
            rendered.contains(&format!("<Message>{}</Message>", reject.message())),
            "the document for {reject:?} does not carry its client message:\n{rendered}"
        );
    }
}
