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

//! The frozen operation IR, as Rust types.
//!
//! Responsible for: one in-memory type per construct in `spec/ir.schema.json`, so that an IR
//! document which cannot be represented cannot be emitted either.
//! NOT responsible for: how an IR is built (that is [`mod@crate::lower`]) or rendered as JSON (that is
//! [`emit`]).
//! Upstream: [`mod@crate::lower`]. Downstream: `rustfs-gateway-codegen`.
//!
//! Every closed set in the schema is a Rust enum here. That is the whole point: the schema's
//! `additionalProperties: false` catches a leak at validation time, these types catch it at
//! compile time.

pub mod emit;
pub mod types;

use std::collections::BTreeMap;

use crate::json::Value;

pub use types::{ETagRender, OmitWhen, TimestampFormat, Type};

/// The `ir_version` every document carries. A bump requires a fresh IR-FREEZE review.
pub const IR_VERSION: &str = "1";

/// One operation's complete wire contract.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationIr {
    /// AWS official operation name; equals the file stem.
    pub operation: String,
    /// Routing and status.
    pub http: Http,
    /// Authentication and authorization.
    pub auth: Auth,
    /// Request and response body handling.
    pub payload: Payload,
    /// Integrity checks.
    pub checksum: Checksum,
    /// Request fields.
    pub input: Vec<Field>,
    /// Response fields.
    pub output: Vec<Field>,
    /// Every nested shape reachable from input or output.
    pub shapes: BTreeMap<String, Shape>,
    /// XML body contract.
    pub xml: Xml,
    /// Error surface.
    pub errors: Errors,
    /// Resources needing a second authorization step.
    pub derived_resources: Vec<DerivedResource>,
    /// For HEAD operations, the GET whose headers must be mirrored.
    pub head_mirrors: Option<String>,
    /// Operation-scoped quirk ids.
    pub quirk_refs: Vec<String>,
    /// Resolved records for every quirk referenced anywhere in this document.
    pub quirks: Vec<Quirk>,
    /// Dialect extension points.
    pub ext_points: Vec<ExtPoint>,
}

/// Routing and status.
#[derive(Debug, Clone, PartialEq)]
pub struct Http {
    /// HTTP method.
    pub method: Method,
    /// What the path addresses.
    pub target: TargetKind,
    /// Position in the ordered first-match route table; lower wins.
    pub precedence: u32,
    /// Conjunction deciding which operation this is.
    pub predicates: Vec<Predicate>,
    /// Default success status.
    pub success_status: u16,
    /// Other legitimate success statuses.
    pub alt_success_statuses: Vec<u16>,
    /// Reverse-index key for `OPERATIONS.md`.
    pub path_shape: String,
}

/// HTTP methods the route table can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    /// `GET`.
    Get,
    /// `PUT`.
    Put,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
    /// `HEAD`.
    Head,
    /// `OPTIONS`.
    Options,
}

impl Method {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Post => "POST",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
        }
    }

    /// Parses a wire spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "GET" => Method::Get,
            "PUT" => Method::Put,
            "POST" => Method::Post,
            "DELETE" => Method::Delete,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            _ => return None,
        })
    }
}

/// What a request path addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// `/`.
    Service,
    /// `/{Bucket}`.
    Bucket,
    /// `/{Bucket}/{Key+}`.
    Object,
}

impl TargetKind {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Service => "Service",
            TargetKind::Bucket => "Bucket",
            TargetKind::Object => "Object",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "Service" => TargetKind::Service,
            "Bucket" => TargetKind::Bucket,
            "Object" => TargetKind::Object,
            _ => return None,
        })
    }
}

/// One route predicate. The list is closed and mirrors `rustfs-gateway-core`'s selector one for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    /// Matches the request method.
    Method(Method),
    /// Matches what the path addresses.
    Target(TargetKind),
    /// The query key is present with any value.
    QueryPresent(String),
    /// The query key is present with this exact value.
    QueryEquals(String, String),
    /// The query key is absent.
    QueryAbsent(String),
    /// The header is present, or absent when `negated`.
    HeaderPresent {
        /// Lowercase header name.
        header: String,
        /// Invert the test.
        negated: bool,
    },
    /// The header value starts with this prefix.
    HeaderPrefix {
        /// Lowercase header name.
        header: String,
        /// Non-empty value prefix.
        prefix: String,
    },
    /// The request path equals this literal.
    PathLiteral(String),
}

/// Authentication and authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// Whether a signature is required.
    pub requirement: AuthRequirement,
    /// IAM action.
    pub action: String,
    /// Whether a presigned URL may reach this operation.
    pub presigned_allowed: bool,
    /// SigV4 credential-scope service.
    pub service: String,
}

/// How much identity an operation demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequirement {
    /// A valid signature is required.
    Required,
    /// Anonymous is a legitimate identity, never a fallback after a failed signature.
    AnonymousAllowed,
    /// An administrative surface. Never reachable through a presigned URL.
    Privileged,
}

impl AuthRequirement {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthRequirement::Required => "Required",
            AuthRequirement::AnonymousAllowed => "AnonymousAllowed",
            AuthRequirement::Privileged => "Privileged",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "Required" => AuthRequirement::Required,
            "AnonymousAllowed" => AuthRequirement::AnonymousAllowed,
            "Privileged" => AuthRequirement::Privileged,
            _ => return None,
        })
    }
}

/// Request and response body handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Request side.
    pub request: PayloadSpec,
    /// Response side.
    pub response: PayloadSpec,
}

/// One direction's body handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSpec {
    /// What the body is.
    pub kind: PayloadKind,
    /// How much of it must exist before the handler runs.
    pub buffering: Buffering,
    /// Hard size cap for a buffered body.
    pub max_bytes: Option<u64>,
}

/// What a body contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// No body.
    None,
    /// An XML document.
    XmlBody,
    /// An opaque stream.
    StreamingBlob,
    /// A `multipart/form-data` POST.
    Multipart,
    /// A bare non-XML body (MinIO dialect).
    Literal,
    /// The `SelectObjectContent` framing.
    EventStream,
}

impl PayloadKind {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadKind::None => "None",
            PayloadKind::XmlBody => "XmlBody",
            PayloadKind::StreamingBlob => "StreamingBlob",
            PayloadKind::Multipart => "Multipart",
            PayloadKind::Literal => "Literal",
            PayloadKind::EventStream => "EventStream",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "None" => PayloadKind::None,
            "XmlBody" => PayloadKind::XmlBody,
            "StreamingBlob" => PayloadKind::StreamingBlob,
            "Multipart" => PayloadKind::Multipart,
            "Literal" => PayloadKind::Literal,
            "EventStream" => PayloadKind::EventStream,
            _ => return None,
        })
    }
}

/// How much of a body must be in hand before the handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Buffering {
    /// Nothing to buffer.
    None,
    /// The body must be complete first.
    Full,
    /// Handed to the handler as it arrives.
    Streaming,
    /// Headers are flushed before the outcome is known.
    Deferred,
}

impl Buffering {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Buffering::None => "None",
            Buffering::Full => "Full",
            Buffering::Streaming => "Streaming",
            Buffering::Deferred => "Deferred",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "None" => Buffering::None,
            "Full" => Buffering::Full,
            "Streaming" => Buffering::Streaming,
            "Deferred" => Buffering::Deferred,
            _ => return None,
        })
    }
}

/// Integrity checks an operation participates in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// A missing `Content-MD5` and `x-amz-checksum-*` is a 400 before the handler runs.
    pub http_checksum_required: bool,
    /// Algorithms accepted on the request.
    pub request_algorithms: Vec<ChecksumAlgo>,
    /// Algorithms produced on the response.
    pub response_algorithms: Vec<ChecksumAlgo>,
}

/// The five checksum algorithms the IR admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChecksumAlgo {
    /// CRC-32.
    Crc32,
    /// CRC-32C.
    Crc32c,
    /// CRC-64/NVME.
    Crc64Nvme,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
}

impl ChecksumAlgo {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumAlgo::Crc32 => "CRC32",
            ChecksumAlgo::Crc32c => "CRC32C",
            ChecksumAlgo::Crc64Nvme => "CRC64NVME",
            ChecksumAlgo::Sha1 => "SHA1",
            ChecksumAlgo::Sha256 => "SHA256",
        }
    }

    /// Parses an IR spelling. Returns `None` for algorithms the model knows and the IR does not.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "CRC32" => ChecksumAlgo::Crc32,
            "CRC32C" => ChecksumAlgo::Crc32c,
            "CRC64NVME" => ChecksumAlgo::Crc64Nvme,
            "SHA1" => ChecksumAlgo::Sha1,
            "SHA256" => ChecksumAlgo::Sha256,
            _ => return None,
        })
    }
}

/// One request or response field.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Member name.
    pub name: String,
    /// Name on the wire; `None` only for `Payload` and `StatusCode`.
    pub wire_name: Option<String>,
    /// Wire-level requirement.
    pub required: bool,
    /// Where the value lives on the wire.
    pub binding: Binding,
    /// Scalar or composite type.
    pub ty: Type,
    /// Whether the field stays on the hot path.
    pub hot: bool,
    /// Wire default applied when absent.
    pub default: Option<Value>,
    /// When a present value must still not be written.
    pub omit_when: Option<OmitWhen>,
    /// Error code for a missing required field.
    pub missing_error: Option<String>,
    /// Field-scoped quirk ids.
    pub quirk_refs: Vec<String>,
}

/// Where a field's value lives on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// One header.
    Header,
    /// One query key.
    Query,
    /// A URI label, greedy for `{Key+}`.
    UriLabel {
        /// Whether the label swallows slashes.
        greedy: bool,
    },
    /// Every header under a prefix; `wire_name` carries the prefix.
    PrefixHeaders,
    /// The whole body.
    Payload,
    /// An element of the XML body.
    BodyXml,
    /// The response status code.
    StatusCode,
    /// A `multipart/form-data` field.
    FormField,
}

impl Binding {
    /// The IR spelling of the discriminator.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Binding::Header => "Header",
            Binding::Query => "Query",
            Binding::UriLabel { .. } => "UriLabel",
            Binding::PrefixHeaders => "PrefixHeaders",
            Binding::Payload => "Payload",
            Binding::BodyXml => "BodyXml",
            Binding::StatusCode => "StatusCode",
            Binding::FormField => "FormField",
        }
    }
}

/// A nested structure or union shape.
#[derive(Debug, Clone, PartialEq)]
pub struct Shape {
    /// Whether it is a structure or a union.
    pub kind: ShapeKind,
    /// Members, in model order.
    pub fields: Vec<Field>,
    /// XML contract for the shape's direct children.
    pub xml: ShapeXml,
}

/// Structure or union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKind {
    /// A structure.
    Structure,
    /// A union.
    Union,
}

impl ShapeKind {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ShapeKind::Structure => "Structure",
            ShapeKind::Union => "Union",
        }
    }
}

/// XML contract for one nested shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeXml {
    /// Wire order of the shape's direct children.
    pub element_order: Vec<String>,
    /// Per member: write an empty element, or omit it.
    pub empty_value_policy: Vec<(String, EmptyValue)>,
    /// XML attributes written on child elements.
    pub attributes: Vec<XmlAttribute>,
}

/// Whether an empty member is written as an empty element or dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyValue {
    /// Write `<X></X>`.
    Emit,
    /// Write nothing.
    Omit,
}

impl EmptyValue {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            EmptyValue::Emit => "emit",
            EmptyValue::Omit => "omit",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "emit" => EmptyValue::Emit,
            "omit" => EmptyValue::Omit,
            _ => return None,
        })
    }
}

/// One XML attribute written on a child element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlAttribute {
    /// The element carrying the attribute.
    pub element: String,
    /// Attribute name, including any prefix.
    pub name: String,
    /// Where the value comes from.
    pub source: AttributeSource,
}

/// Where an XML attribute's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeSource {
    /// A field of the shape.
    Field(String),
    /// A fixed string.
    Constant(String),
}

/// The operation-level XML body contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xml {
    /// Wire root element of the request body.
    pub request_root: Option<String>,
    /// Additional root names accepted on decode.
    pub request_root_aliases: Vec<String>,
    /// Wire root element of the response body.
    pub response_root: Option<String>,
    /// Whether the 2006-03-01 namespace is written on the root.
    pub xmlns: Xmlns,
    /// Whether the single body member *is* the root element.
    pub unwrapped_output: bool,
    /// Order of the response root's direct children.
    pub element_order: Vec<String>,
    /// Per member: write an empty element, or omit it.
    pub empty_value_policy: Vec<(String, EmptyValue)>,
    /// Members percent-encoded when `encoding-type=url` was requested.
    pub url_encoded_fields: Vec<String>,
    /// XML attributes written on child elements.
    pub attributes: Vec<XmlAttribute>,
    /// Whether a bare literal body is accepted (MinIO dialect).
    pub body_literal: bool,
}

/// Whether the S3 namespace is written on a response root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Xmlns {
    /// Write it.
    Emit,
    /// Do not write it; the `Error` root must not carry it.
    Suppress,
}

impl Xmlns {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Xmlns::Emit => "emit",
            Xmlns::Suppress => "suppress",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "emit" => Xmlns::Emit,
            "suppress" => Xmlns::Suppress,
            _ => return None,
        })
    }
}

/// The error surface of one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Errors {
    /// The operation-specific 404 for an unconfigured bucket subresource.
    pub not_configured: Option<String>,
    /// Whether an `Error` body can follow an already-flushed 200.
    pub allows_error_after_200: bool,
    /// Every error code this operation can produce.
    pub codes: Vec<String>,
}

/// A resource that only becomes readable after a second authorization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedResource {
    /// Name of the derived resource.
    pub name: String,
    /// The input field it is parsed out of.
    pub source_field: String,
    /// What kind of reference it is.
    pub kind: String,
    /// IAM action guarding it.
    pub action: String,
    /// Whether it must be present.
    pub required: bool,
}

/// One hand-written protocol exception, resolved into the IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quirk {
    /// Stable id, `q-<slug>-NNNN`.
    pub id: String,
    /// Category. Not an enum: new AWS behaviour must not require a schema bump.
    pub kind: String,
    /// What it applies to.
    pub target: String,
    /// Self-written one-liner. Never upstream prose.
    pub summary: String,
    /// Where the behaviour is established.
    pub evidence: Vec<Evidence>,
    /// Conformance cases that would fail if the quirk were flipped.
    pub cases: Vec<String>,
}

/// One evidence entry behind a quirk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Source class.
    pub kind: String,
    /// URL, issue number, or repository-relative capture path.
    pub reference: String,
    /// Self-written summary of what the source establishes.
    pub summary: String,
}

/// A dialect extension point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtPoint {
    /// Stable id, `ext-<slug>`.
    pub id: String,
    /// Shape the extension hangs off.
    pub parent_shape: String,
    /// Local element name.
    pub local_name: String,
    /// Dialect that defines it.
    pub dialect: String,
    /// `ExtField` or `GeneratedVariant`.
    pub strategy: String,
    /// Always `AfterKnownFields`.
    pub position: String,
    /// Decode behaviour for unregistered elements.
    pub unknown_policy: String,
    /// Cargo feature gating a generated variant.
    pub cfg_feature: Option<String>,
}

/// Sort key for a quirk id: the four-digit counter first, the whole id as the tie-break.
///
/// Ids are allocated in discovery order, so ordering by the counter keeps a document's quirk list
/// in the order the behaviours were found — which reads far better than the lexicographic order of
/// their slugs, and is just as deterministic.
pub fn quirk_order_key(id: &str) -> (u32, &str) {
    let number = id
        .rsplit('-')
        .next()
        .and_then(|tail| tail.parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    (number, id)
}

/// Sorts and deduplicates a list of quirk ids in the canonical order.
pub fn sort_quirk_ids(mut ids: Vec<String>) -> Vec<String> {
    ids.sort_by(|a, b| quirk_order_key(a).cmp(&quirk_order_key(b)));
    ids.dedup();
    ids
}

impl OperationIr {
    /// Every quirk id referenced anywhere in the document, in canonical order, deduplicated.
    pub fn referenced_quirk_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.quirk_refs.clone();
        let push_fields = |fields: &[Field], ids: &mut Vec<String>| {
            for f in fields {
                ids.extend(f.quirk_refs.iter().cloned());
            }
        };
        push_fields(&self.input, &mut ids);
        push_fields(&self.output, &mut ids);
        for shape in self.shapes.values() {
            push_fields(&shape.fields, &mut ids);
        }
        sort_quirk_ids(ids)
    }

    /// Every query key this operation reads, whether as a route predicate or a field.
    pub fn query_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for p in &self.http.predicates {
            match p {
                Predicate::QueryPresent(k) | Predicate::QueryAbsent(k) | Predicate::QueryEquals(k, _) => {
                    keys.push(k.clone());
                }
                _ => {}
            }
        }
        for f in &self.input {
            if f.binding == Binding::Query
                && let Some(name) = &f.wire_name
            {
                keys.push(name.clone());
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    /// Every header this operation reads or writes, plus the ones it routes on.
    pub fn headers(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for p in &self.http.predicates {
            match p {
                Predicate::HeaderPresent { header, .. } | Predicate::HeaderPrefix { header, .. } => {
                    names.push(header.clone());
                }
                _ => {}
            }
        }
        for f in self.input.iter().chain(self.output.iter()) {
            if matches!(f.binding, Binding::Header | Binding::PrefixHeaders)
                && let Some(name) = &f.wire_name
            {
                names.push(name.clone());
            }
        }
        names.sort();
        names.dedup();
        names
    }
}
