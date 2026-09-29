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

//! The decode diff: one raw request through both stacks, and every way the two decodes differ.
//!
//! Responsible for: [`decode_diff`] and [`Differ`], which send one request to both stacks and
//! compare the four things a decode produces — the operation each routed to, every input member
//! by field path, the refusal (status, code, message) when a handler was not reached, and the
//! digest of the body bytes left for the handler — and [`DecodeDiff::findings`], which turns the
//! comparison into prioritised findings, a route mismatch first.
//! NOT responsible for: deciding whether a finding is acceptable (`known.rs`), or how a member is
//! spelled (`fields.rs`, `project/*.rs`).
//! Upstream: `gateway.rs`, `oracle.rs`. Downstream: tests, corpus runners, the shadow proxy.
//!
//! # Faults
//!
//! `Fault` breaks the gateway side on purpose, the way a real defect would: a host resolver that
//! reads every object path as a bucket path (the real route table then picks another operation), a
//! decoder that takes one body byte more than its framing said, or one member decoded wrongly.
//! They exist so the negative controls (a-df-0009, a-df-0010, a-df-0003) run against the same
//! comparison a real run uses. `Fault::None` is the only value a real run passes.

use std::cell::RefCell;
use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::fields::FieldValue;
use crate::gateway::GatewayStack;
use crate::known::Kind;
use crate::oracle::OracleStack;
use crate::request::RawRequest;

/// A defect injected into the gateway side, for the negative controls. Only the tests construct
/// one; every public entry point runs [`Fault::None`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Fault {
    /// No defect: the only value a real run uses.
    #[default]
    None,
    /// The host resolver reads every object path as a bucket path.
    GatewayMisroutesObjects,
    /// The handler sees the body with its first byte already consumed.
    GatewayDecoderEatsOneByte,
    /// The named member (a path relative to the input) is decoded as a different value.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayMemberSkewed(String),
    /// Encode: the first two children of the XML root are written in the other order.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayXmlElementsReordered,
    /// Encode: the root element loses its `xmlns`.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayXmlnsDropped,
    /// Encode: the first empty element is spelled the other way (`<X/>` and `<X></X>`).
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayEmptyElementRespelled,
    /// Encode: an upload id is written as the hex of its bytes.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayUploadIdAsHex,
    /// Encode: one header no registered difference names is added.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayExtraHeader,
    /// Encode: the request id is written in lowercase.
    #[cfg_attr(not(test), allow(dead_code, reason = "constructed by the negative controls only"))]
    GatewayRequestIdMalformed,
}

/// One thing compared, with the gateway's value and the s3s value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmp<T> {
    /// The gateway's value.
    pub gateway: T,
    /// The pinned s3s revision's value.
    pub s3s: T,
}

impl<T: PartialEq> Cmp<T> {
    /// Whether both stacks produced the same value.
    pub fn same(&self) -> bool {
        self.gateway == self.s3s
    }
}

/// A refusal as a client sees it. Code and message are `None` when the body is not an S3 error
/// document — a `HEAD` refusal has no body on either stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3ErrorView {
    /// The HTTP status.
    pub status: u16,
    /// The `<Code>` of the error document.
    pub code: Option<String>,
    /// The `<Message>` of the error document.
    pub message: Option<String>,
}

impl fmt::Display for S3ErrorView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.status, self.code.as_deref().unwrap_or("<no code>"))?;
        match &self.message {
            Some(message) => write!(formatter, ": {message}"),
            None => Ok(()),
        }
    }
}

/// What reached one stack's handler, or the refusal in its place.
pub(crate) enum Answer<T> {
    Handed(T),
    Refused(S3ErrorView),
}

impl<T> Answer<T> {
    pub(crate) fn refused(status: u16, body: &[u8]) -> Self {
        let text = std::str::from_utf8(body).ok();
        Self::Refused(S3ErrorView {
            status,
            code: text.and_then(|text| element(text, "Code")),
            message: text.and_then(|text| element(text, "Message")),
        })
    }
}

/// The text of the first `<name>` element, unescaped.
fn element(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(
        text[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// What a handler read from the body after decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BodySeen {
    /// The input carries no body.
    NoBody,
    /// The body ended normally after these bytes.
    Read(Vec<u8>),
    /// The body failed after these bytes. The error's wording is each stack's own and is not
    /// compared; that it failed is.
    Failed { read: Vec<u8> },
}

/// The body bytes left for the handler after decoding, by length and SHA-256, and whether the body
/// ended in an error instead of an end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyDigest {
    /// Bytes the handler read.
    pub len: u64,
    /// Their SHA-256, lowercase hex.
    pub sha256: String,
    /// Whether the body failed rather than ended.
    pub failed: bool,
}

impl BodyDigest {
    fn of(seen: &BodySeen) -> Option<Self> {
        let (bytes, failed) = match seen {
            BodySeen::NoBody => return None,
            BodySeen::Read(bytes) => (bytes, false),
            BodySeen::Failed { read, .. } => (read, true),
        };
        Some(Self {
            len: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            failed,
        })
    }
}

impl fmt::Display for BodyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = self.sha256.get(..16).unwrap_or(&self.sha256);
        write!(formatter, "{} bytes sha256:{prefix}", self.len)?;
        if self.failed {
            formatter.write_str(" then an error")?;
        }
        Ok(())
    }
}

/// One member path with both stacks' values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDiff {
    /// `<Operation>Input.<member path>`.
    pub path: String,
    /// The gateway's value.
    pub gateway: FieldValue,
    /// The s3s value.
    pub s3s: FieldValue,
}

/// Everything one request's two decodes produced, compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeDiff {
    /// The operation each stack routed to; `None` when it named none.
    pub operation: Cmp<Option<String>>,
    /// The refusal each stack answered with instead of reaching its handler.
    pub error: Cmp<Option<S3ErrorView>>,
    /// Every member decoded differently, when both handlers were reached for the same operation.
    pub input: Vec<FieldDiff>,
    /// The body bytes each handler was left with; `None` when it has no body or was not reached.
    pub rest_body: Cmp<Option<BodyDigest>>,
    /// Every member path compared, with both values, when both handlers were reached for the same
    /// operation: what a zero-diff row actually proved, and what a census can hold rows to.
    pub members: Vec<FieldDiff>,
    /// Every member path each handler was handed, `<Operation>Input.`-prefixed, whether or not the
    /// other stack reached its handler: what a member only one model has was seen as.
    pub handed: Cmp<Vec<(String, FieldValue)>>,
}

/// What a finding is about.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    /// The two stacks routed to different operations.
    Route,
    /// One stack reached its handler and the other refused.
    Outcome,
    /// Both refused, with different statuses.
    Status,
    /// Both refused, with different error codes.
    Code,
    /// Both refused, with different messages.
    Message,
    /// One input member, by path.
    Member(String),
    /// The body bytes left for the handler.
    RestBody,
    /// Encode: the two answers' statuses.
    ResponseStatus,
    /// Encode: one header's lines, by lowercase name.
    Header(String),
    /// Encode: the answer bodies after any XML declaration, after normalisation.
    Body,
    /// Encode: the XML declaration and the whitespace after it.
    BodyProlog,
    /// Encode: one XML element's attributes, spelling, presence or text, by element path.
    BodyElement(String),
    /// Encode: one XML element's children written in another order, by element path.
    BodyOrder(String),
    /// Encode: a normalised value that did not have its format.
    Format(String),
    /// Encode: an s3s output member the gateway output cannot hold.
    Unconvertible(String),
}

impl fmt::Display for Item {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route => formatter.write_str("route"),
            Self::Outcome => formatter.write_str("outcome"),
            Self::Status => formatter.write_str("error.status"),
            Self::Code => formatter.write_str("error.code"),
            Self::Message => formatter.write_str("error.message"),
            Self::Member(path) => formatter.write_str(path),
            Self::RestBody => formatter.write_str("rest_body"),
            Self::ResponseStatus => formatter.write_str("status"),
            Self::Header(name) => write!(formatter, "header {name}"),
            Self::Body => formatter.write_str("body"),
            Self::BodyProlog => formatter.write_str("body.prolog"),
            Self::BodyElement(path) => write!(formatter, "body {path}"),
            Self::BodyOrder(path) => write!(formatter, "body.order {path}"),
            Self::Format(field) => write!(formatter, "format {field}"),
            Self::Unconvertible(member) => write!(formatter, "unconvertible {member}"),
        }
    }
}

/// How much a finding matters. A route mismatch outranks everything: every later comparison is
/// between two different operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Different operations.
    Route,
    /// A difference in what the handler receives, or whether it receives anything.
    Fail,
    /// A message wording difference; still a failure unless registered.
    Info,
}

/// One difference, ready to be matched against the known-diffs register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Which differential found it.
    pub kind: Kind,
    /// The operation it concerns: the gateway's when it routed to one, else the s3s one.
    pub operation: String,
    /// What differs.
    pub item: Item,
    /// How much it matters.
    pub priority: Priority,
    /// The gateway side, rendered.
    pub gateway: String,
    /// The s3s side, rendered.
    pub s3s: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{:?}] {} {}: gateway={} s3s={}",
            self.priority, self.operation, self.item, self.gateway, self.s3s
        )
    }
}

fn shown<T: fmt::Display>(value: Option<&T>) -> String {
    value.map_or_else(|| "<none>".to_owned(), ToString::to_string)
}

impl DecodeDiff {
    /// Whether the two stacks routed to different operations.
    ///
    /// One stack naming no operation is a route difference, with one exception: both refused, with
    /// the same status and code. That is a refusal the two stacks reach at different stages — s3s
    /// checks a bucket name before it resolves the operation, the gateway after — and the refusal
    /// comparison already covers it.
    fn routes_differ(&self) -> bool {
        if self.operation.same() {
            return false;
        }
        let one_unnamed = self.operation.gateway.is_none() || self.operation.s3s.is_none();
        let same_refusal = match (&self.error.gateway, &self.error.s3s) {
            (Some(gateway), Some(s3s)) => gateway.status == s3s.status && gateway.code == s3s.code,
            _ => false,
        };
        !(one_unnamed && same_refusal)
    }

    /// Every difference, most important first. Empty exactly when the two decodes agree.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        let operation = self
            .operation
            .gateway
            .clone()
            .or_else(|| self.operation.s3s.clone())
            .unwrap_or_else(|| "<unrouted>".to_owned());
        let finding = |item: Item, priority: Priority, gateway: String, s3s: String| Finding {
            kind: Kind::Decode,
            operation: operation.clone(),
            item,
            priority,
            gateway,
            s3s,
        };
        let mut findings = Vec::new();
        if self.routes_differ() {
            findings.push(finding(
                Item::Route,
                Priority::Route,
                shown(self.operation.gateway.as_ref()),
                shown(self.operation.s3s.as_ref()),
            ));
        }
        match (&self.error.gateway, &self.error.s3s) {
            (None, None) => {}
            (Some(gateway), Some(s3s)) => {
                if gateway.status != s3s.status {
                    findings.push(finding(Item::Status, Priority::Fail, gateway.status.to_string(), s3s.status.to_string()));
                }
                if gateway.code != s3s.code {
                    findings.push(finding(
                        Item::Code,
                        Priority::Fail,
                        shown(gateway.code.as_ref()),
                        shown(s3s.code.as_ref()),
                    ));
                }
                if gateway.message != s3s.message {
                    findings.push(finding(
                        Item::Message,
                        Priority::Info,
                        shown(gateway.message.as_ref()),
                        shown(s3s.message.as_ref()),
                    ));
                }
            }
            (gateway, s3s) => {
                let side = |error: &Option<S3ErrorView>| error.as_ref().map_or_else(|| "handled".to_owned(), ToString::to_string);
                findings.push(finding(Item::Outcome, Priority::Fail, side(gateway), side(s3s)));
            }
        }
        for member in &self.input {
            findings.push(finding(
                Item::Member(member.path.clone()),
                Priority::Fail,
                member.gateway.to_string(),
                member.s3s.to_string(),
            ));
        }
        // Only a body both handlers were handed can be compared; when one side refused, the
        // outcome finding above already says so.
        let both_handed = self.error.gateway.is_none() && self.error.s3s.is_none();
        if both_handed && !self.rest_body.same() {
            findings.push(finding(
                Item::RestBody,
                Priority::Fail,
                shown(self.rest_body.gateway.as_ref()),
                shown(self.rest_body.s3s.as_ref()),
            ));
        }
        findings.sort_by_key(|finding| finding.priority);
        findings
    }
}

/// Which deployment the two stacks stand for.
///
/// `Generic` is the gateway's own defaults against the legacy stack's defaults: what the register
/// and the built-in matrix were written for. `Rustfs` is the gateway's RustFS profile against the
/// legacy stack configured the way RustFS main configures it (`rustfs/src/server/http.rs:166-172`,
/// `rustfs_s3_config`): the comparison that says whether a RustFS client, and RustFS's storage,
/// would see any difference once the gateway fronts RustFS (rustfs/backlog#1677).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    /// Both stacks with their defaults.
    #[default]
    Generic,
    /// The gateway's RustFS profile against the legacy stack as RustFS configures it.
    Rustfs,
}

/// Both stacks, built once and reused for every request.
pub struct Differ {
    gateway: GatewayStack,
    oracle: OracleStack,
    fault: Fault,
}

impl Differ {
    /// Builds both stacks.
    ///
    /// # Errors
    ///
    /// The gateway service does not assemble.
    pub fn new() -> Result<Self, String> {
        Self::with_fault(Fault::None)
    }

    /// Builds both stacks, the gateway side broken by `fault`: the negative controls only.
    pub(crate) fn with_fault(fault: Fault) -> Result<Self, String> {
        Ok(Self {
            gateway: GatewayStack::new(&fault)?,
            oracle: OracleStack::new(),
            fault,
        })
    }

    /// Builds both stacks for `profile`.
    ///
    /// # Errors
    ///
    /// The gateway service does not assemble.
    pub fn for_profile(profile: Profile) -> Result<Self, String> {
        Self::with_profiles(profile, profile)
    }

    /// Builds the gateway side for one profile and the legacy side for another: the negative
    /// controls use it to show that a gateway without the RustFS profile's switches is caught
    /// against the legacy stack as RustFS configures it.
    pub(crate) fn with_profiles(gateway: Profile, oracle: Profile) -> Result<Self, String> {
        Ok(Self {
            gateway: GatewayStack::with_profile(&Fault::None, gateway)?,
            oracle: OracleStack::with_profile(oracle),
            fault: Fault::None,
        })
    }

    pub(crate) const fn gateway_stack(&self) -> &GatewayStack {
        &self.gateway
    }

    pub(crate) const fn oracle_stack(&self) -> &OracleStack {
        &self.oracle
    }

    pub(crate) const fn fault(&self) -> &Fault {
        &self.fault
    }

    /// Sends `request` to both stacks and compares the two decodes.
    ///
    /// # Errors
    ///
    /// The harness itself failed — a head that cannot be built, a poisoned slot, a handler that
    /// ran for an operation the route table did not pick. Never a difference between the stacks.
    pub fn diff(&self, request: &RawRequest) -> Result<DecodeDiff, String> {
        let (gateway_op, gateway) = self.gateway.send(request)?;
        let (oracle_op, oracle) = self.oracle.send(request)?;
        let mut diff = DecodeDiff {
            operation: Cmp {
                gateway: gateway_op,
                s3s: oracle_op,
            },
            error: Cmp {
                gateway: None,
                s3s: None,
            },
            input: Vec::new(),
            rest_body: Cmp {
                gateway: None,
                s3s: None,
            },
            members: Vec::new(),
            handed: Cmp {
                gateway: Vec::new(),
                s3s: Vec::new(),
            },
        };
        let gateway_fields = match gateway {
            Answer::Handed(handed) => {
                diff.rest_body.gateway = BodyDigest::of(&handed.body);
                Some(handed.fields)
            }
            Answer::Refused(error) => {
                diff.error.gateway = Some(error);
                None
            }
        };
        let oracle_fields = match oracle {
            Answer::Handed(handed) => {
                diff.rest_body.s3s = BodyDigest::of(&handed.body);
                Some(handed.fields)
            }
            Answer::Refused(error) => {
                diff.error.s3s = Some(error);
                None
            }
        };
        let prefixed = |operation: &Option<String>, fields: &Option<crate::fields::Fields>| match (operation, fields) {
            (Some(operation), Some(fields)) => fields
                .entries()
                .map(|(path, value)| (format!("{operation}Input.{path}"), value.clone()))
                .collect(),
            _ => Vec::new(),
        };
        diff.handed = Cmp {
            gateway: prefixed(&diff.operation.gateway, &gateway_fields),
            s3s: prefixed(&diff.operation.s3s, &oracle_fields),
        };
        if let (Some(mut gateway), Some(oracle), Some(operation), true) =
            (gateway_fields, oracle_fields, diff.operation.gateway.clone(), diff.operation.same())
        {
            if let Fault::GatewayMemberSkewed(path) = &self.fault {
                gateway.set(path.as_str(), FieldValue::Present("<skewed by the harness>".to_owned()));
            }
            for path in gateway.union(&oracle) {
                let member = FieldDiff {
                    path: format!("{operation}Input.{path}"),
                    gateway: gateway.get(path),
                    s3s: oracle.get(path),
                };
                if !same_member(&member.gateway, &member.s3s) {
                    diff.input.push(member.clone());
                }
                diff.members.push(member);
            }
        }
        Ok(diff)
    }
}

/// A member one side does not have and the other leaves unset loses nothing: they agree.
fn same_member(left: &FieldValue, right: &FieldValue) -> bool {
    match (left, right) {
        (FieldValue::NoMember | FieldValue::Absent, FieldValue::NoMember | FieldValue::Absent) => true,
        _ => left == right,
    }
}

thread_local! {
    static DIFFER: RefCell<Option<Differ>> = const { RefCell::new(None) };
    static RUSTFS_DIFFER: RefCell<Option<Differ>> = const { RefCell::new(None) };
}

/// [`Differ::diff`] on a per-thread pair of stacks with no fault.
///
/// # Errors
///
/// As [`Differ::diff`], or the stacks do not build.
pub fn decode_diff(request: &RawRequest) -> Result<DecodeDiff, String> {
    DIFFER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(Differ::new()?);
        }
        match slot.as_ref() {
            Some(differ) => differ.diff(request),
            None => Err("the per-thread stacks did not build".to_owned()),
        }
    })
}

/// [`Differ::diff`] on a per-thread pair of stacks for [`Profile::Rustfs`], with no fault.
///
/// # Errors
///
/// As [`Differ::diff`], or the stacks do not build.
pub fn rustfs_decode_diff(request: &RawRequest) -> Result<DecodeDiff, String> {
    RUSTFS_DIFFER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(Differ::for_profile(Profile::Rustfs)?);
        }
        match slot.as_ref() {
            Some(differ) => differ.diff(request),
            None => Err("the per-thread RustFS-profile stacks did not build".to_owned()),
        }
    })
}
