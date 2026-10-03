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

//! The seam answer diff's rows (rustfs/gateway#1076, item 2): legacy outputs a RustFS app body
//! returns, each with what the two stacks' answers must show.
//!
//! Responsible for: [`answer_rows`] — which, with the encode matrix's samples
//! (`crate::samples::outputs`), set every member path of every covered operation's legacy output —
//! and [`UNWRITTEN_PATHS`], every output member no row can set, with the reason.
//! NOT responsible for: writing (`mod.rs`) or judging (`tests/seam_outputs.rs`).
//! Upstream: the pinned legacy DTOs. Downstream: `tests/seam_outputs.rs`.
//!
//! # Element order
//!
//! The legacy stack writes a structure's members in its own declaration order (mostly
//! alphabetical), no line end after the XML declaration, no namespace on the root of an output
//! whose body is one structure, the attributes answer rooted at `GetObjectAttributesResponse`, and
//! an entity tag's quotes as they are; the gateway writes the S3 model's order, the order AWS
//! documents and answers with, AWS's declaration, namespace and root, and `&quot;`. The seam diff
//! runs the RustFS response layout (`write_responses_as_rustfs`, rustfs/gateway#1078), which
//! writes all of them as the legacy stack does, so no row's answers differ in any of them: the
//! register's prolog, entity-tag and order entries (`kd-encode-0005`, `kd-encode-0006`,
//! `kd-encode-0007` and the order entries after it) hold for the encode matrix's generic profile
//! alone. A row may still name structures whose children the two answers write in
//! another order (`orders`), so an order the layout does not reach is a failing row; every other
//! difference is held to the register or to [`ANSWER_FINDINGS`].

use crate::request::RawRequest;
use crate::s3s;

use super::{AnswerDiff, LegacyOutput, SeamDiffer};

mod checksums;
mod configs;
mod objects;

/// What a row's two answers must show.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Written {
    /// The seam hands the output over; the answers differ by exactly the register ids in `known`,
    /// the answer findings in `answer` and, in child order only, at exactly the element paths in
    /// `orders`.
    As {
        /// The register ids (`known-diffs.toml`) the answers' differences match, no more and no
        /// fewer.
        known: &'static [&'static str],
        /// The [`ANSWER_FINDINGS`] ids the answers' other differences match, no more and no fewer.
        answer: &'static [&'static str],
        /// The element paths (list positions as `[]`) whose children the two answers write in
        /// another order.
        orders: &'static [&'static str],
    },
    /// The seam refuses the output, naming this member: the gateway answers an internal error
    /// rather than write less than the output holds.
    Refused(&'static str),
}

/// Writes one row's output on both stacks.
pub(crate) type Run = Box<dyn Fn(&SeamDiffer) -> Result<AnswerDiff, String>>;

/// One legacy output, the request it answers and what both answers must show.
pub(crate) struct AnswerRow {
    /// A stable name for reports.
    pub(crate) name: String,
    /// Writes the output on both stacks.
    pub(crate) run: Run,
    /// What the answers must show.
    pub(crate) expect: Written,
}

/// A row answering `request` with the legacy output `build` makes, on both stacks.
pub(crate) fn answer<T: LegacyOutput>(
    name: impl Into<String>,
    request: RawRequest,
    build: impl Fn() -> T + 'static,
    expect: Written,
) -> AnswerRow {
    AnswerRow {
        name: name.into(),
        run: Box::new(move |differ| differ.answer_diff(&request, &build)),
        expect,
    }
}

/// The four headers the gateway stamps on every answer (`kd-encode-0001`..`0004`).
pub(crate) const BARE: &[&str] = &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004"];

/// An XML answer's registered differences: [`BARE`] alone. Under the RustFS response layout the
/// gateway writes the XML declaration as the legacy stack does, without the line break the generic
/// layout writes after it (`kd-encode-0005`).
pub(crate) const XML: &[&str] = BARE;

/// A written answer whose only differences are the register ids in `known`.
pub(crate) const fn same(known: &'static [&'static str]) -> Written {
    Written::As {
        known,
        answer: &[],
        orders: &[],
    }
}

/// A written answer whose differences are the register ids in `known`, the answer findings in
/// `answer` and the child order at `orders`.
pub(crate) const fn differs(
    known: &'static [&'static str],
    answer: &'static [&'static str],
    orders: &'static [&'static str],
) -> Written {
    Written::As { known, answer, orders }
}

/// A configuration document as the legacy stack reads it: the value RustFS stores and returns.
pub(crate) fn legacy_document<T>(xml: &str) -> T
where
    T: for<'xml> s3s::xml::Deserialize<'xml>,
{
    let mut deserializer = s3s::xml::Deserializer::new(xml.as_bytes());
    T::deserialize(&mut deserializer).unwrap_or_else(|error| unreachable!("a fixture document the legacy stack reads: {error:?}"))
}

/// A legacy string enumeration value.
pub(crate) fn named<T: From<String>>(value: &str) -> T {
    T::from(value.to_owned())
}

/// A version id in the shape RustFS mints.
pub(crate) const VERSION_ID: &str = crate::samples::VERSION_ID;

/// One wire difference between the two answers that no register entry (`known-diffs.toml`) holds,
/// because the encode matrix does not answer the operation: the gateway writer and the legacy writer
/// spell the same output differently. Each is presentation only — the containment check
/// (`AnswerDiff::lost`) proves no value of the output is lost with it — and each is pinned here and
/// reported for a ruling (rustfs/gateway#1076), not accepted.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnswerFinding {
    /// `sa-<nnnn>`.
    pub(crate) id: &'static str,
    /// The operation.
    pub(crate) operation: &'static str,
    /// The finding's item as the encode diff renders it (`body PolicyStatus`, `status`, …).
    pub(crate) item: &'static str,
    /// The gateway side, exactly as rendered.
    pub(crate) gateway: &'static str,
    /// The legacy side, exactly as rendered.
    pub(crate) legacy: &'static str,
    /// What differs, with the evidence for each side.
    pub(crate) reason: &'static str,
}

const fn finding(
    id: &'static str,
    operation: &'static str,
    item: &'static str,
    gateway: &'static str,
    legacy: &'static str,
    reason: &'static str,
) -> AnswerFinding {
    AnswerFinding {
        id,
        operation,
        item,
        gateway,
        legacy,
        reason,
    }
}

/// Every answer finding, by id.
pub(crate) const ANSWER_FINDINGS: &[AnswerFinding] = &[
    finding(
        "sa-0001",
        "GetBucketLogging",
        "body BucketLoggingStatus/LoggingEnabled/TargetGrants",
        "<TargetGrants>",
        "<absent>",
        "The gateway output holds the grant list as a list, empty when the legacy output has none, and its writer opens the \
         wrapper whatever it holds (generated/codec/ops/get_bucket_logging.rs); the legacy writer skips an unset list. The gateway \
         adds an empty element; nothing the legacy answer holds is missing.",
    ),
    finding(
        "sa-0002",
        "GetBucketWebsite",
        "body WebsiteConfiguration/RoutingRules",
        "<RoutingRules>",
        "<absent>",
        "As sa-0001, for the routing rules (generated/codec/ops/get_bucket_website.rs).",
    ),
    finding(
        "sa-0003",
        "ListMultipartUploads",
        "body ListMultipartUploadsResult/EncodingType",
        "<absent>",
        "<EncodingType>",
        "The RustFS listing rule (url_encode_listings_like_rustfs, #1088) echoes no EncodingType on a multipart listing, as \
         legacy RustFS answers: its multipart listing never sets the member (rustfs/rustfs e870a6d25 \
         rustfs/src/storage/s3_api/multipart.rs:165-206). Only the encode matrix's sample sets it, so no answer RustFS gives \
         loses it; a legacy output that did set it would be written without it.",
    ),
];

/// Every output member path no row can set, by operation, with the reason.
pub(crate) const UNWRITTEN_PATHS: &[(&str, &str, &str)] = &[];

/// Every row.
pub(crate) fn answer_rows() -> Vec<AnswerRow> {
    let mut rows = configs::rows();
    rows.extend(objects::rows());
    rows.extend(checksums::rows());
    rows
}
