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

//! The encode diff: one s3s output — what a RustFS handler returns — written to the wire by the
//! pinned s3s service and, converted, by the gateway service, and every way the two answers differ.
//!
//! Responsible for: [`OutputSample`], [`WireAnswer`], [`EncodeDiff`] and [`Differ::encode`] — the
//! same request and the same output through both assembled services, both answers normalised
//! (`normalize.rs`), then compared on status, every header line (name, value, order of repeated
//! lines, and presence), and the body bytes, XML in full; and each comparison as findings.
//! NOT responsible for: streaming cadence — a streaming body is a fixed placeholder, joined — or
//! deciding what is acceptable (`known.rs`).
//! Upstream: `convert/*.rs`, `normalize.rs`, both stacks. Downstream: tests, runners, fuzzing.
//!
//! # Content-Length
//!
//! On an answer with a body, `Content-Length` is framing: a side may leave it to its transport.
//! Every value a side did write is held to that side's own body length, and the two values are
//! compared only when both sides wrote one over byte-identical bodies. On a `HEAD` answer it is the
//! size of the representation not sent — content — and is compared like any other header.

use std::fmt;
use std::sync::Arc;

use crate::convert::Unconvertible;
use crate::decode::{Cmp, Differ, Fault, Finding, Item, Priority};
use crate::known::Kind;
use crate::normalize::{FormatAssertion, Normalizer, Side};
use crate::project::OracleOutput;
use crate::request::RawRequest;
use crate::xmltree;

/// One answer as a client sees it: status, header lines in order, body bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireAnswer {
    /// The status.
    pub status: u16,
    /// Lowercase name and value of every header line, in the order written.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body, joined.
    pub body: Vec<u8>,
}

impl WireAnswer {
    pub(crate) fn new(status: u16, headers: &http::HeaderMap, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body,
        }
    }

    fn lines(&self, name: &str) -> Vec<Vec<u8>> {
        self.headers
            .iter()
            .filter(|(present, _)| present == name)
            .map(|(_, value)| value.clone())
            .collect()
    }
}

/// One output to encode, and the request it answers (a `HEAD`, an `encoding-type` or a
/// `response-*` override changes what is written).
#[derive(Clone)]
pub struct OutputSample {
    /// A stable name for reports.
    pub name: String,
    /// The request both stacks answer.
    pub request: RawRequest,
    /// Builds the output; called once per stack, so a streaming body is never shared.
    pub output: Arc<dyn Fn() -> OracleOutput + Send + Sync>,
}

impl fmt::Debug for OutputSample {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputSample")
            .field("name", &self.name)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// The deterministic placeholder a streaming output carries (a-df-0005): fixed bytes in fixed
/// pieces with an exact length, so both stacks write the same stream and the joined bytes compare.
#[must_use]
pub fn placeholder_body() -> crate::s3s::dto::StreamingBlob {
    const PIECES: [&[u8]; 4] = [b"difftest ", b"placeholder ", b"streaming ", b"body"];
    let pieces: Vec<bytes::Bytes> = PIECES.iter().map(|piece| bytes::Bytes::from_static(piece)).collect();
    crate::s3s::dto::StreamingBlob::new(crate::probe::ProbeBody::new(&pieces))
}

/// The length of [`placeholder_body`].
pub const PLACEHOLDER_LENGTH: i64 = 35;

/// One header both answers wrote differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDiff {
    /// Lowercase name.
    pub name: String,
    /// The gateway's lines, in order; empty when absent.
    pub gateway: Vec<String>,
    /// The s3s lines, in order; empty when absent.
    pub s3s: Vec<String>,
}

/// Everything one output's two encodings produced, compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodeDiff {
    /// The operation the output answers.
    pub operation: String,
    /// The s3s member the gateway output could not hold; nothing else is compared then.
    pub unconvertible: Option<Unconvertible>,
    /// Both statuses.
    pub status: Cmp<u16>,
    /// Every header written differently, after normalisation.
    pub headers: Vec<HeaderDiff>,
    /// Both bodies, after normalisation.
    pub body: Cmp<Vec<u8>>,
    /// One assertion per normalised value, held or not.
    pub assertions: Vec<FormatAssertion>,
}

fn shown(lines: &[String]) -> String {
    if lines.is_empty() {
        "<absent>".to_owned()
    } else {
        lines.join(" | ")
    }
}

/// An XML body's declaration with the whitespace after it, and the rest; a body without one is all
/// rest. Reported apart so one prolog difference does not hide every element difference after it.
fn split_prolog(body: &[u8]) -> (&[u8], &[u8]) {
    if !body.starts_with(b"<?xml") {
        return (&[], body);
    }
    let Some(end) = body.windows(2).position(|pair| pair == b"?>").map(|at| at + 2) else {
        return (&[], body);
    };
    let whitespace = body[end..].iter().take_while(|byte| byte.is_ascii_whitespace()).count();
    body.split_at(end + whitespace)
}

/// The two bodies around their first differing byte, as text.
fn body_windows(gateway: &[u8], s3s: &[u8]) -> (String, String) {
    let first = gateway
        .iter()
        .zip(s3s)
        .position(|(left, right)| left != right)
        .unwrap_or(gateway.len().min(s3s.len()));
    let start = first.saturating_sub(24);
    let window = |body: &[u8]| {
        let end = (first + 40).min(body.len());
        format!(
            "@{first}: {}",
            String::from_utf8_lossy(body.get(start..end).unwrap_or_default()).escape_debug()
        )
    };
    (window(gateway), window(s3s))
}

impl EncodeDiff {
    /// Every difference, most important first. Empty exactly when the two answers agree.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        let finding = |item: Item, gateway: String, s3s: String| Finding {
            kind: Kind::Encode,
            operation: self.operation.clone(),
            item,
            priority: Priority::Fail,
            gateway,
            s3s,
        };
        if let Some(unconvertible) = &self.unconvertible {
            return vec![finding(
                Item::Unconvertible(unconvertible.member.to_owned()),
                "<cannot hold>".to_owned(),
                unconvertible.reason.to_owned(),
            )];
        }
        let mut findings = Vec::new();
        if !self.status.same() {
            findings.push(finding(
                Item::ResponseStatus,
                self.status.gateway.to_string(),
                self.status.s3s.to_string(),
            ));
        }
        for header in &self.headers {
            findings.push(finding(Item::Header(header.name.clone()), shown(&header.gateway), shown(&header.s3s)));
        }
        let (gateway_prolog, gateway_rest) = split_prolog(&self.body.gateway);
        let (s3s_prolog, s3s_rest) = split_prolog(&self.body.s3s);
        if gateway_prolog != s3s_prolog {
            findings.push(finding(
                Item::BodyProlog,
                format!("{:?}", String::from_utf8_lossy(gateway_prolog)),
                format!("{:?}", String::from_utf8_lossy(s3s_prolog)),
            ));
        }
        if gateway_rest != s3s_rest {
            let trees = std::str::from_utf8(gateway_rest)
                .ok()
                .and_then(xmltree::parse)
                .zip(std::str::from_utf8(s3s_rest).ok().and_then(xmltree::parse));
            let mut structural = Vec::new();
            if let Some((left, right)) = &trees {
                let root = String::from_utf8_lossy(gateway_rest)
                    .split(['<', '>', ' ', '/'])
                    .nth(1)
                    .unwrap_or("")
                    .to_owned();
                xmltree::differences(&root, left, right, &mut structural);
            }
            for difference in structural.iter().cloned() {
                findings.push(match difference {
                    xmltree::XmlDifference::Order { path, gateway, s3s } => finding(Item::BodyOrder(path), gateway, s3s),
                    xmltree::XmlDifference::Element { path, gateway, s3s } => finding(Item::BodyElement(path), gateway, s3s),
                });
            }
            // Bytes that differ with no structural difference — whitespace between elements, an
            // escape — are still a difference, reported where the first byte differs.
            if structural.is_empty() {
                let (gateway, s3s) = body_windows(gateway_rest, s3s_rest);
                findings.push(finding(Item::Body, gateway, s3s));
            }
        }
        for assertion in self.assertions.iter().filter(|assertion| !assertion.holds) {
            let value = format!("{:?} is not {}", assertion.value, assertion.format);
            let (gateway, s3s) = match assertion.side {
                Side::Gateway => (value, "-".to_owned()),
                Side::S3s => ("-".to_owned(), value),
            };
            findings.push(finding(Item::Format(assertion.field.clone()), gateway, s3s));
        }
        findings
    }
}

/// The gateway-side encoder defects the negative controls inject, applied to the gateway's answer.
fn break_gateway_answer(fault: &Fault, answer: &mut WireAnswer) {
    let Ok(mut text) = String::from_utf8(answer.body.clone()) else {
        return;
    };
    match fault {
        Fault::GatewayXmlElementsReordered => text = swap_first_two_children(&text),
        Fault::GatewayXmlnsDropped => {
            if let Some(start) = text.find(" xmlns=\"")
                && let Some(length) = text[start + 8..].find('"')
            {
                text.replace_range(start..start + 8 + length + 1, "");
            }
        }
        Fault::GatewayEmptyElementRespelled => text = respell_first_empty_element(&text),
        Fault::GatewayUploadIdAsHex => {
            if let Some(start) = text.find("<UploadId>")
                && let Some(length) = text[start + 10..].find("</UploadId>")
            {
                let id = text[start + 10..start + 10 + length].to_owned();
                text.replace_range(start + 10..start + 10 + length, &hex::encode(id));
            }
        }
        Fault::GatewayExtraHeader => answer.headers.push(("x-amz-difftest-extra".to_owned(), b"1".to_vec())),
        Fault::GatewayRequestIdMalformed => {
            for (name, value) in &mut answer.headers {
                if name == "x-amz-request-id" {
                    value.make_ascii_lowercase();
                }
            }
        }
        _ => {}
    }
    answer.body = text.into_bytes();
}

/// The first two child elements of the document's root, swapped.
pub(crate) fn swap_first_two_children(text: &str) -> String {
    let element_end = |from: usize| -> Option<usize> {
        let rest = &text[from..];
        let name_end = rest[1..].find(['>', ' ', '/'])? + 1;
        let name = &rest[1..name_end];
        if rest[..rest.find('>')? + 1].ends_with("/>") {
            return Some(from + rest.find('>')? + 1);
        }
        let close = format!("</{name}>");
        Some(from + rest.find(&close)? + close.len())
    };
    let root_open = text.find("?>").map_or(0, |end| end + 2);
    let Some(root_end) = text[root_open..].find('>').map(|end| root_open + end + 1) else {
        return text.to_owned();
    };
    let Some(first) = text[root_end..].find('<').map(|at| root_end + at) else {
        return text.to_owned();
    };
    let Some(first_end) = element_end(first) else {
        return text.to_owned();
    };
    if text[first_end..].starts_with("</") {
        return text.to_owned();
    }
    let Some(second_end) = element_end(first_end) else {
        return text.to_owned();
    };
    format!(
        "{}{}{}{}",
        &text[..first],
        &text[first_end..second_end],
        &text[first..first_end],
        &text[second_end..]
    )
}

/// The first empty element spelled the other way: `<X></X>` as `<X/>`, or `<X/>` as `<X></X>`.
pub(crate) fn respell_first_empty_element(text: &str) -> String {
    for (index, _) in text.match_indices('<') {
        let rest = &text[index + 1..];
        if rest.starts_with(['/', '?', '!']) {
            continue;
        }
        let Some(end) = rest.find('>') else {
            break;
        };
        let tag = &rest[..end];
        if let Some(name) = tag.strip_suffix('/') {
            let name = name.trim_end();
            return format!("{}<{name}></{name}>{}", &text[..index], &text[index + 1 + end + 1..]);
        }
        let close = format!("</{tag}>");
        let after = index + 1 + end + 1;
        if !tag.contains(' ') && text[after..].starts_with(&close) {
            return format!("{}<{tag}/>{}", &text[..index], &text[after + close.len()..]);
        }
    }
    text.to_owned()
}

impl Differ {
    /// Sends `sample.request` to both stacks with `sample.output` as each handler's answer — the
    /// s3s output as it is, and converted for the gateway — and compares the two answers.
    ///
    /// # Errors
    ///
    /// The harness failed: a stack never reached the handler the answer was queued for, or a
    /// head could not be built. Never a difference between the stacks.
    pub fn encode(&self, sample: &OutputSample) -> Result<EncodeDiff, String> {
        let oracle_output = (sample.output)();
        let operation = oracle_output.operation().to_owned();
        let empty = EncodeDiff {
            operation: operation.clone(),
            unconvertible: None,
            status: Cmp { gateway: 0, s3s: 0 },
            headers: Vec::new(),
            body: Cmp {
                gateway: Vec::new(),
                s3s: Vec::new(),
            },
            assertions: Vec::new(),
        };
        let converted = match (sample.output)().into_gateway() {
            Ok(converted) => converted,
            Err(unconvertible) => {
                return Ok(EncodeDiff {
                    unconvertible: Some(unconvertible),
                    ..empty
                });
            }
        };
        let mut gateway = self.gateway_stack().answer(&sample.request, converted)?;
        let mut oracle = self.oracle_stack().answer(&sample.request, oracle_output)?;
        break_gateway_answer(self.fault(), &mut gateway);
        Ok(compare(operation, sample.request.method == http::Method::HEAD, &mut gateway, &mut oracle))
    }
}

fn header_diff(name: &str, gateway: &[Vec<u8>], s3s: &[Vec<u8>]) -> HeaderDiff {
    let text = |lines: &[Vec<u8>]| lines.iter().map(|line| String::from_utf8_lossy(line).into_owned()).collect();
    HeaderDiff {
        name: name.to_owned(),
        gateway: text(gateway),
        s3s: text(s3s),
    }
}

pub(crate) fn compare(operation: String, head: bool, gateway: &mut WireAnswer, oracle: &mut WireAnswer) -> EncodeDiff {
    let normalizer = Normalizer;
    let mut assertions = Vec::new();
    // Content-Length is framing: a side that did not write it left it to the transport. Each side
    // that wrote it is held to its own body; the two values are compared only when both wrote one
    // and the bodies are the same bytes — otherwise the body finding already says it all.
    let mut headers = Vec::new();
    // A HEAD answer's Content-Length is the size of the representation it did not send: content,
    // not framing, so it stays a compared header like any other (the loop below compares it).
    if !head {
        for (side, answer) in [(Side::Gateway, &*gateway), (Side::S3s, &*oracle)] {
            for line in answer.lines("content-length") {
                let text = String::from_utf8_lossy(&line).into_owned();
                let holds = text.parse::<usize>().is_ok_and(|length| length == answer.body.len());
                assertions.push(FormatAssertion {
                    side,
                    field: "header content-length".to_owned(),
                    value: text,
                    format: crate::normalize::Format::BodyLength(answer.body.len()),
                    holds,
                });
            }
        }
        let (left, right) = (gateway.lines("content-length"), oracle.lines("content-length"));
        if gateway.body == oracle.body && !left.is_empty() && !right.is_empty() && left != right {
            headers.push(header_diff("content-length", &left, &right));
        }
        gateway.headers.retain(|(name, _)| name != "content-length");
        oracle.headers.retain(|(name, _)| name != "content-length");
    }
    let dropped = [
        normalizer.normalize_headers(Side::Gateway, &mut gateway.headers, &mut assertions),
        normalizer.normalize_headers(Side::S3s, &mut oracle.headers, &mut assertions),
    ];
    for name in dropped.iter().flatten() {
        gateway.headers.retain(|(present, _)| present != name);
        oracle.headers.retain(|(present, _)| present != name);
    }
    normalizer.assert_body(Side::Gateway, &gateway.body, &mut assertions);
    normalizer.assert_body(Side::S3s, &oracle.body, &mut assertions);
    let body = Cmp {
        gateway: gateway.body.clone(),
        s3s: oracle.body.clone(),
    };
    let mut names: Vec<&str> = gateway
        .headers
        .iter()
        .chain(&oracle.headers)
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let (left, right) = (gateway.lines(name), oracle.lines(name));
        if left != right {
            headers.push(header_diff(name, &left, &right));
        }
    }
    EncodeDiff {
        operation,
        unconvertible: None,
        status: Cmp {
            gateway: gateway.status,
            s3s: oracle.status,
        },
        headers,
        body,
        assertions,
    }
}
