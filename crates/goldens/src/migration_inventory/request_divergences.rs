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

//! Decided request divergences: every behaviour the rustfs/backlog#1762 differential pins between
//! the gateway and the pinned s3s (the stack RustFS serves today), each with its migration ruling.
//!
//! Responsible for: one entry per pinned divergence — what AWS documents, what s3s does, what the
//! gateway does, what a RustFS client would notice, the ruling, and the issue that owns any code
//! follow-up — and for refusing a register that has drifted from its tests. Every entry names a
//! test that carries its id, and every test in a named-divergence section carries an id that has an
//! entry, so a divergence cannot be pinned without a ruling or ruled without a pin.
//! NOT responsible for: observing the divergences (the named tests in `operation_diff` drive both
//! stacks), persisted-byte refusals (the parent module), or implementing a follow-up.
//! Upstream: the named tests in `operation_diff/put_object/divergences.rs` and
//! `operation_diff/context/put_object.rs`. Downstream: `corpus-report`, and the RustFS adapter work
//! of rustfs/backlog#1752.
//!
//! # The default the rulings follow
//!
//! A refusal that exists for safety stays (`..` segments, two integrity claims). A behaviour RustFS
//! clients observably depend on is aligned, or given a RustFS profile when the AWS answer should
//! stay the default for everyone else. Where AWS and s3s disagree and no RustFS client depends on
//! the difference, the gateway's AWS-derived answer stands.

use core::fmt;

/// What the migration does about one divergence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceRuling {
    /// The gateway's answer stands for every deployment.
    KeepGateway,
    /// The gateway, or the RustFS adapter in front of the RustFS handlers, gives the answer RustFS
    /// gives today.
    AlignS3s,
    /// The gateway moves to what AWS documents.
    AlignAws,
    /// The AWS answer stays the default; a RustFS dialect profile gives RustFS's answer.
    RustfsProfile,
}

impl DivergenceRuling {
    /// Every ruling, in report order.
    pub const ALL: [Self; 4] = [Self::KeepGateway, Self::AlignS3s, Self::AlignAws, Self::RustfsProfile];

    /// Stable report label.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::KeepGateway => "keep-gateway",
            Self::AlignS3s => "align-s3s",
            Self::AlignAws => "align-aws",
            Self::RustfsProfile => "rustfs-profile",
        }
    }
}

/// Where the code a ruling needs stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceFollowUp {
    /// The ruling needs no code.
    None,
    /// The code landed; this conformance case and the pinned test hold it.
    Landed(&'static str),
    /// The code is owned by this open issue.
    Open(&'static str),
}

/// One pinned divergence and its ruling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestDivergence {
    /// Stable id, `rd-<put|ctx>-NNNN`; the pinned test's doc carries it as `Ruling: `id``.
    pub id: &'static str,
    /// Operation the request addresses.
    pub operation: &'static str,
    /// The request shape that diverges.
    pub request: &'static str,
    /// What AWS documents for it.
    pub aws: &'static str,
    /// Where AWS (or the RFC S3 follows) says so.
    pub aws_evidence: &'static str,
    /// What the pinned s3s — RustFS today — does.
    pub s3s: &'static str,
    /// What the gateway does.
    pub gateway: &'static str,
    /// What a RustFS client would notice if the gateway answer shipped unchanged.
    pub client_impact: &'static str,
    /// The decision.
    pub ruling: DivergenceRuling,
    /// Where the code the decision needs stands.
    pub follow_up: DivergenceFollowUp,
    /// Pinned test source, relative to `crates/goldens/src`.
    pub test_file: &'static str,
    /// Pinned test function.
    pub test: &'static str,
}

const PUT_DECODE: &str = "operation_diff/put_object/divergences.rs";
const PUT_CONTEXT: &str = "operation_diff/context/put_object.rs";

/// The files whose named-divergence sections the register is checked against.
const PINNED_TEST_FILES: [&str; 2] = [PUT_DECODE, PUT_CONTEXT];

const API_PUT_OBJECT: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html";
const M1_ADAPTER: &str = "https://github.com/rustfs/backlog/issues/1752";
const ADAPTER_SEAM: &str = "https://github.com/rustfs/gateway/issues/753";
const DOT_KEY_INVENTORY: &str = "https://github.com/rustfs/gateway/issues/754";

/// Every decided request divergence.
pub const REQUEST_DIVERGENCES: [RequestDivergence; 14] = [
    RequestDivergence {
        id: "rd-put-0001",
        operation: "PutObject",
        request: "no Content-Type header",
        aws: "the object is stored with the S3 default media type, binary/octet-stream",
        aws_evidence: API_PUT_OBJECT,
        s3s: "content_type is None",
        gateway: "content_type is None, as on s3s; the S3 default is written on the read, by the GetObject and HeadObject encoders \
                  when the backend names no type (q-content-0008). Until rustfs/gateway#749 the decoder filled it on the write",
        client_impact: "none once the decode agrees: RustFS derives a type from the key extension when none is sent \
                        (options.rs detect_content_type_from_object_name), so a.png still reads back as image/png; \
                        a backend that stores no type still answers binary/octet-stream",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-object-0058"),
        test_file: PUT_DECODE,
        test: "an_absent_content_type_is_left_absent_by_both_stacks",
    },
    RequestDivergence {
        id: "rd-put-0002",
        operation: "PutObject",
        request: "x-amz-sdk-checksum-algorithm naming the algorithm",
        aws: "the model binds ChecksumAlgorithm to x-amz-sdk-checksum-algorithm",
        aws_evidence: API_PUT_OBJECT,
        s3s: "reads x-amz-checksum-algorithm or infers it from x-amz-trailer, so the SDK header yields no algorithm",
        gateway: "reads x-amz-sdk-checksum-algorithm, as the model says",
        client_impact: "RustFS only uses the algorithm to pick the trailer checksum to apply, and SDKs send the matching header or trailer, \
                        so a well-formed SDK upload is stored the same way",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_DECODE,
        test: "the_sdk_checksum_algorithm_header_is_read_by_the_gateway_and_not_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0003",
        operation: "PutObject",
        request: "no Content-Length",
        aws: "answers 411 MissingContentLength",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html",
        s3s: "takes the length from an exact body size hint (the in-process fixture has one); over a chunked transport it stays absent",
        gateway: "411 MissingContentLength (q-length-0007)",
        client_impact: "over a real chunked transport RustFS already refuses a PUT with no length (400 UnexpectedContent), so the client \
                        sees the AWS code rather than a new refusal; framed streaming without Content-Length is decided separately",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/750"),
        test_file: PUT_DECODE,
        test: "a_put_without_content_length_is_refused_by_the_gateway_and_backfilled_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0004",
        operation: "PutObject",
        request: "an Expires value that is not a date",
        aws: "Expires is modelled as a timestamp, and stored values that are not dates exist (q-timestamp-0005)",
        aws_evidence: API_PUT_OBJECT,
        s3s: "400 before the handler",
        gateway: "keeps the value opaque; the compat conversion refuses it by member name (expires)",
        client_impact: "RustFS stores Expires as a timestamp and cannot hold the text, so its clients already get a 400 for it",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(M1_ADAPTER),
        test_file: PUT_DECODE,
        test: "an_expires_that_is_not_a_date_is_kept_by_the_gateway_and_refused_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0005",
        operation: "PutObject",
        request: "two x-amz-checksum-* headers",
        aws: "one checksum header per request",
        aws_evidence: API_PUT_OBJECT,
        s3s: "hands every checksum member to the handler",
        gateway: "refused before the body is read (q-checksum-0006)",
        client_impact: "two integrity claims are refused instead of one being verified and the other dropped; no well-behaved client sends two",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_DECODE,
        test: "two_checksum_headers_are_refused_by_the_gateway_and_kept_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0006",
        operation: "PutObject",
        request: "an x-amz-checksum-sha512, -md5 or -xxhash* header",
        aws: "supports SHA-512, MD5, XXHash3, XXHash64 and XXHash128 checksums since 2026-04",
        aws_evidence: "https://aws.amazon.com/about-aws/whats-new/2026/04/s3-five-additional-checksum-algorithms/",
        s3s: "hands the value to the handler; RustFS verifies and stores it",
        gateway: "the pinned model predates the algorithms, so the checksum binder refuses the header as an unknown algorithm",
        client_impact: "a client configured for one of the new algorithms is refused",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/751"),
        test_file: PUT_DECODE,
        test: "a_checksum_algorithm_the_gateway_model_predates_is_refused_by_the_gateway_and_kept_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0007",
        operation: "PutObject",
        request: "?versionId= on the PUT (MinIO extension)",
        aws: "PutObject takes no versionId; the service mints version ids",
        aws_evidence: API_PUT_OBJECT,
        s3s: "reads it into version_id",
        gateway: "no member; the query is dropped",
        client_impact: "RustFS replication writes replicas with ?versionId= and a RustFS target keeps the source version id; \
                        behind the gateway every replica would get a fresh id",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/752"),
        test_file: PUT_DECODE,
        test: "the_minio_version_id_query_on_a_put_is_seen_by_s3s_only",
    },
    RequestDivergence {
        id: "rd-put-0008",
        operation: "PutObject",
        request: "a key with a .. segment",
        aws: "keys are opaque, so a .. segment is a legal key",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html",
        s3s: "hands the key to the handler unchanged",
        gateway: "the object-key floor refuses it with InvalidArgument, for every operation that names the key",
        client_impact: "the refusal protects a filesystem-backed store from traversal; an object already stored under such a key would be \
                        unreachable through the gateway, so the operator has to find those before the switch",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Open(DOT_KEY_INVENTORY),
        test_file: PUT_DECODE,
        test: "a_dot_dot_key_segment_is_refused_by_the_gateway_and_kept_by_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0001",
        operation: "PutObject",
        request: "Host photos.s3.eu-west-1.<configured domain>",
        aws: "<bucket>.s3.<region>.<domain> is the regional virtual-hosted form: bucket photos, region eu-west-1",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
        s3s: "strips only the base domain: bucket photos.s3.eu-west-1, no region",
        gateway: "bucket photos, host region eu-west-1",
        client_impact: "only clients addressing the regional form under a configured domain see a change, and they get the AWS answer; \
                        a dotted bucket literally named like that stays reachable path-style",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_a_regional_virtual_host_names_a_different_bucket_and_region",
    },
    RequestDivergence {
        id: "rd-ctx-0002",
        operation: "PutObject",
        request: "a header value that is not UTF-8",
        aws: "HTTP allows obs-text octets in a field value; S3 ignores headers it does not define",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9110#section-5.5",
        s3s: "passes the raw value to the handler",
        gateway: "the text header view skips it, so the converted request lacks it",
        client_impact: "RustFS reads raw headers directly (MIME fallback, SSE-C fallback, replication and x-rustfs-* controls); \
                        an adapter built on the text view would lose such values without a refusal",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(ADAPTER_SEAM),
        test_file: PUT_CONTEXT,
        test: "divergence_a_non_utf8_header_value_reaches_only_the_s3s_handler",
    },
    RequestDivergence {
        id: "rd-ctx-0003",
        operation: "PutObject",
        request: "an extension installed by the transport",
        aws: "no wire behaviour: an extension is in-process state",
        aws_evidence: "https://github.com/rustfs/gateway/pull/748",
        s3s: "passes it to the handler",
        gateway: "the wire request keeps no extension bag",
        client_impact: "RustFS needs RemoteAddr, RequestContext and ReqInfo from the transport and fails closed without ReqInfo",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(ADAPTER_SEAM),
        test_file: PUT_CONTEXT,
        test: "divergence_a_transport_extension_reaches_only_the_s3s_handler",
    },
    RequestDivergence {
        id: "rd-ctx-0004",
        operation: "PutObject",
        request: "an absolute-form request target",
        aws: "a server accepts absolute-form, and its authority stands in for Host",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9112#section-3.2.2",
        s3s: "the handler's URI keeps the authority",
        gateway: "the converted URI is path and query only",
        client_impact: "RustFS takes the host from the Host header and reads the URI authority only as a fallback (multipart Location), \
                        and the Host header is always present on HTTP/1.1, so handlers see the same object and host",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_an_absolute_form_target_keeps_its_authority_only_on_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0005",
        operation: "PutObject",
        request: "a bare trailing ?",
        aws: "an empty query and no query are distinct URIs, and S3 gives the empty one no meaning of its own",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc3986#section-3.4",
        s3s: "query Some(\"\")",
        gateway: "no query",
        client_impact: "RustFS looks query parameters up by name and an empty query has none, so no handler decision changes",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_an_empty_query_marker_is_kept_only_by_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0006",
        operation: "PutObject",
        request: "two lines for one x-amz-meta-* key, in any case",
        aws: "documents that same-name metadata headers are combined into one comma-separated value",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html",
        s3s: "400 InvalidRequest before the handler",
        gateway: "400 InvalidRequest at wire acceptance (DuplicateMetadataHeader); it used to keep the last line and drop the first silently",
        client_impact: "the same answer RustFS gives today; a client relying on the AWS join is refused visibly instead of losing a value",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Landed("c-object-0057"),
        test_file: PUT_CONTEXT,
        test: "divergence_repeated_metadata_lines_are_refused_by_both_stacks",
    },
];

/// A register entry that does not hold as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestDivergenceError {
    /// The id is not `rd-<put|ctx>-NNNN`.
    MalformedId(&'static str),
    /// Two entries share an id.
    DuplicateId(&'static str),
    /// A descriptive field is empty.
    MissingText {
        /// Entry.
        id: &'static str,
        /// Field.
        field: &'static str,
    },
    /// The AWS evidence is not a URL.
    EvidenceNotUrl(&'static str),
    /// A ruling that changes behaviour names no follow-up, so nothing owns the change.
    UnownedChange(&'static str),
    /// A follow-up is neither a rustfs issue URL nor a conformance case id.
    MalformedFollowUp(&'static str),
    /// The pinned test lives outside the files the register is checked against.
    UnknownTestFile(&'static str),
}

impl fmt::Display for RequestDivergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedId(id) => write!(formatter, "{id} is not an rd-<put|ctx>-NNNN id"),
            Self::DuplicateId(id) => write!(formatter, "{id} appears twice"),
            Self::MissingText { id, field } => write!(formatter, "{id} leaves {field} empty"),
            Self::EvidenceNotUrl(id) => write!(formatter, "{id} cites AWS evidence that is not a URL"),
            Self::UnownedChange(id) => write!(formatter, "{id} changes behaviour but names no follow-up"),
            Self::MalformedFollowUp(id) => write!(formatter, "{id} names a follow-up that is neither an issue nor a case"),
            Self::UnknownTestFile(id) => write!(formatter, "{id} pins a test outside the checked files"),
        }
    }
}

impl std::error::Error for RequestDivergenceError {}

/// The validated register.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestDivergenceReport {
    entries: &'static [RequestDivergence],
}

impl RequestDivergenceReport {
    /// The entries, in id order as written.
    #[must_use]
    pub const fn entries(&self) -> &'static [RequestDivergence] {
        self.entries
    }

    /// Renders the register: one summary line, then one line per ruling.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("request divergences: rulings={}", self.entries.len());
        for ruling in DivergenceRuling::ALL {
            let count = self.entries.iter().filter(|entry| entry.ruling == ruling).count();
            out.push_str(&format!(" {}={count}", ruling.slug()));
        }
        let open = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.follow_up, DivergenceFollowUp::Open(_)))
            .count();
        let landed = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.follow_up, DivergenceFollowUp::Landed(_)))
            .count();
        out.push_str(&format!(" open-follow-ups={open} landed={landed}\n"));
        for entry in self.entries {
            let follow_up = match entry.follow_up {
                DivergenceFollowUp::None => "none",
                DivergenceFollowUp::Landed(case) | DivergenceFollowUp::Open(case) => case,
            };
            out.push_str(&format!(
                "divergence {} operation={} ruling={} follow-up={follow_up} test={}::{}\n",
                entry.id,
                entry.operation,
                entry.ruling.slug(),
                entry.test_file,
                entry.test,
            ));
        }
        out
    }
}

/// Validates [`REQUEST_DIVERGENCES`].
///
/// # Errors
///
/// The first [`RequestDivergenceError`] an entry raises.
pub fn build_request_divergences() -> Result<RequestDivergenceReport, RequestDivergenceError> {
    check_register(&REQUEST_DIVERGENCES)?;
    Ok(RequestDivergenceReport {
        entries: &REQUEST_DIVERGENCES,
    })
}

fn check_register(entries: &[RequestDivergence]) -> Result<(), RequestDivergenceError> {
    for (index, entry) in entries.iter().enumerate() {
        if !well_formed_id(entry.id) {
            return Err(RequestDivergenceError::MalformedId(entry.id));
        }
        if entries[..index].iter().any(|earlier| earlier.id == entry.id) {
            return Err(RequestDivergenceError::DuplicateId(entry.id));
        }
        for (field, text) in [
            ("operation", entry.operation),
            ("request", entry.request),
            ("aws", entry.aws),
            ("s3s", entry.s3s),
            ("gateway", entry.gateway),
            ("client_impact", entry.client_impact),
            ("test", entry.test),
        ] {
            if text.trim().is_empty() {
                return Err(RequestDivergenceError::MissingText { id: entry.id, field });
            }
        }
        if !entry.aws_evidence.starts_with("https://") {
            return Err(RequestDivergenceError::EvidenceNotUrl(entry.id));
        }
        match entry.follow_up {
            DivergenceFollowUp::None if entry.ruling != DivergenceRuling::KeepGateway => {
                return Err(RequestDivergenceError::UnownedChange(entry.id));
            }
            DivergenceFollowUp::Open(url) if !is_issue_url(url) => {
                return Err(RequestDivergenceError::MalformedFollowUp(entry.id));
            }
            DivergenceFollowUp::Landed(case) if !is_case_id(case) => {
                return Err(RequestDivergenceError::MalformedFollowUp(entry.id));
            }
            _ => {}
        }
        if !PINNED_TEST_FILES.contains(&entry.test_file) {
            return Err(RequestDivergenceError::UnknownTestFile(entry.id));
        }
    }
    Ok(())
}

fn well_formed_id(id: &str) -> bool {
    let Some(number) = id.strip_prefix("rd-put-").or_else(|| id.strip_prefix("rd-ctx-")) else {
        return false;
    };
    number.len() == 4 && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_issue_url(url: &str) -> bool {
    [
        "https://github.com/rustfs/gateway/issues/",
        "https://github.com/rustfs/backlog/issues/",
    ]
    .iter()
    .any(|prefix| {
        url.strip_prefix(prefix)
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn is_case_id(case: &str) -> bool {
    case.strip_prefix("c-")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(domain, number)| {
            !domain.is_empty() && number.len() == 4 && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests;
