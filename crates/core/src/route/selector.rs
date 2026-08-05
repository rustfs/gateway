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

//! What a route entry is, and the closed set of questions it may ask about a request.
//!
//! Responsible for: [`Predicate`] and the four vocabularies it references ([`TargetKind`],
//! [`HostClass`], [`ArnForm`], and `http::Method`), the conjunction [`RouteSelector`], the entry
//! [`RouteEntry`], and evaluating a selector against one request.
//! NOT responsible for: deciding whether two selectors can be satisfied at once (`lattice`),
//! ordering entries or reporting conflicts (`table`), classifying a host string into a
//! [`HostClass`] or a path into a [`TargetKind`] — that is the `HostResolver`'s job in P6, and
//! this module consumes the answer rather than computing it.
//! Upstream: `rustfs-gateway-http`'s borrowed views, `http`. Downstream: `lattice`, `table`,
//! `compiled`.
//!
//! # Why the predicate set is closed
//!
//! Every predicate here is decidable from the request head, in constant time, with no allocation
//! and no I/O. That is not a coincidence: routing happens *before* the signature is verified, so a
//! predicate that could read a body, await, or consult a store would turn the router into an
//! unauthenticated amplifier. Keeping the set closed — an `enum`, not a boxed `dyn Fn` — is what
//! makes that property checkable by reading one file, and it is also what makes the build-time
//! overlap decision in `lattice` possible at all: an opaque callback has no lattice.
//!
//! # Values are matched as they arrived
//!
//! [`Predicate::QueryEquals`] compares against the still-percent-encoded value, because that is
//! what [`QueryView`](rustfs_gateway_http::QueryView) hands out and because decoding here would be
//! a second decode of a value the decoder will decode again. Every routing value in the model is
//! an ASCII token (`list-type=2`), so the two spellings coincide; a client that sent `list-type=%32`
//! would not be routed to `ListObjectsV2`. That is recorded as a known limitation rather than
//! hidden: the alternative is decoding on the pre-auth path.

use std::borrow::Cow;
use std::fmt;

use http::Method;
use rustfs_gateway_http::{HeaderView, QueryView};

/// What the request path addresses.
///
/// Computed by the host/path resolver before routing, never re-derived here: two components that
/// each decide whether `/bucket` is a bucket or an object are two components that can disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    /// The service root: `/`.
    Service,
    /// A bucket and nothing more: `/bucket`.
    Bucket,
    /// A key inside a bucket: `/bucket/key`.
    Object,
}

impl TargetKind {
    /// Every variant, for exhaustive enumeration in tests and witnesses.
    pub const ALL: [Self; 3] = [Self::Service, Self::Bucket, Self::Object];

    /// The spelling used in the IR and in generated data.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "Service",
            Self::Bucket => "Bucket",
            Self::Object => "Object",
        }
    }

    /// Parses the IR spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// A path shape that addresses this kind, used when printing a conflict witness.
    #[must_use]
    pub const fn witness_path(self) -> &'static str {
        match self {
            Self::Service => "/",
            Self::Bucket => "/<bucket>",
            Self::Object => "/<bucket>/<key>",
        }
    }
}

/// Which endpoint family the request arrived on.
///
/// A host class is not decoration: S3 Express uses a different signing service and different
/// bucket names, Object Lambda serves a literal path that is not a bucket at all, and the website
/// endpoint is a second protocol whose methods and paths overlap the REST API completely. Without
/// this dimension those three are indistinguishable from an ordinary request, which is how an
/// implementation ends up routing `POST /bucket` to `WriteGetObjectResponse` because two headers
/// happened to be present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostClass {
    /// The ordinary REST endpoint, path-style or virtual-hosted.
    Standard,
    /// `<route>.s3-object-lambda.<region>.amazonaws.com`.
    ObjectLambda,
    /// The zonal endpoint of a directory bucket.
    S3Express,
    /// The static-website endpoint, a different protocol on the same shapes.
    Website,
    /// An Outposts endpoint.
    Outposts,
    /// The transfer-acceleration endpoint.
    Accelerate,
    /// The dual-stack endpoint.
    Dualstack,
}

impl HostClass {
    /// Every variant.
    pub const ALL: [Self; 7] = [
        Self::Standard,
        Self::ObjectLambda,
        Self::S3Express,
        Self::Website,
        Self::Outposts,
        Self::Accelerate,
        Self::Dualstack,
    ];

    /// The spelling used in the IR.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::ObjectLambda => "ObjectLambda",
            Self::S3Express => "S3Express",
            Self::Website => "Website",
            Self::Outposts => "Outposts",
            Self::Accelerate => "Accelerate",
            Self::Dualstack => "Dualstack",
        }
    }

    /// Parses the IR spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == text)
    }
}

/// The ARN shape occupying the bucket position of the path.
///
/// Orthogonal to [`TargetKind`]: an access-point ARN followed by a key is still an `Object`
/// target. The form changes name validation, the signing service, region resolution and the
/// resource an authorizer is asked about, so it cannot be folded into the bucket name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArnForm {
    /// `arn:aws:s3:<region>:<account>:accesspoint/<name>`.
    AccessPoint,
    /// `arn:aws:s3-outposts:...`.
    Outposts,
    /// A multi-region access point alias.
    Mrap,
}

impl ArnForm {
    /// Every variant.
    pub const ALL: [Self; 3] = [Self::AccessPoint, Self::Outposts, Self::Mrap];

    /// The spelling used in the IR.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessPoint => "AccessPoint",
            Self::Outposts => "Outposts",
            Self::Mrap => "MRAP",
        }
    }

    /// Parses the IR spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|form| form.as_str() == text)
    }
}

/// One question a route entry asks about a request.
///
/// The list is closed and mirrors `spec/ir.schema.json`'s `predicate` definition one for one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    /// The request method.
    Method(Method),
    /// What the path addresses.
    Target(TargetKind),
    /// The query key is present, whatever its value.
    QueryPresent(&'static str),
    /// The query key is present with this exact (still-encoded) value.
    QueryEquals(&'static str, &'static str),
    /// The query key is absent.
    QueryAbsent(&'static str),
    /// The endpoint family the request arrived on.
    HostClass(HostClass),
    /// The path is exactly this literal, rather than a bucket or object shape.
    PathLiteral(&'static str),
    /// The bucket position holds an ARN of this form.
    ArnForm(ArnForm),
    /// The header's first value starts with this prefix.
    ///
    /// A prefix rather than an equality because `Content-Type: multipart/form-data; boundary=…`
    /// carries a parameter that varies per request.
    HeaderPrefix(&'static str, &'static str),
    /// The header is present (or, when negated, absent), whatever its value.
    ///
    /// This is how AWS separates operations that share a method and a path shape: `PutObject` and
    /// `CopyObject` differ only by `x-amz-copy-source` existing. Spelling that as a
    /// [`Predicate::HeaderPrefix`] with an empty prefix conflates "has a value starting with" and
    /// "exists", and the frozen IR schema rejects it.
    HeaderPresent {
        /// Lowercase header name.
        header: &'static str,
        /// Invert the test: match only when the header is absent.
        negated: bool,
    },
}

impl Predicate {
    /// Whether this request satisfies the predicate.
    ///
    /// Constant time, no allocation, no I/O. See the module docs for why that is a requirement
    /// rather than an optimisation.
    #[must_use]
    pub fn matches(&self, request: &RouteRequestParts<'_>) -> bool {
        match *self {
            Self::Method(ref method) => request.method == method,
            Self::Target(target) => request.target == target,
            Self::QueryPresent(key) => request.query.contains(key),
            Self::QueryEquals(key, value) => request.query.get(key) == Some(value),
            Self::QueryAbsent(key) => !request.query.contains(key),
            Self::HostClass(class) => request.host_class == class,
            Self::PathLiteral(path) => request.path == path,
            Self::ArnForm(form) => request.arn_form == Some(form),
            Self::HeaderPrefix(name, prefix) => request.first_header(name).is_some_and(|value| value.starts_with(prefix)),
            Self::HeaderPresent { header, negated } => request.first_header(header).is_some() != negated,
        }
    }

    /// The header name this predicate reads, if any. Used to validate names once, at build time.
    #[must_use]
    pub(crate) fn header_name(&self) -> Option<&'static str> {
        match *self {
            Self::HeaderPrefix(name, _) | Self::HeaderPresent { header: name, .. } => Some(name),
            _ => None,
        }
    }

    /// The query key this predicate constrains, if any. Used to derive the subresource bit table.
    #[must_use]
    pub(crate) fn query_key(&self) -> Option<&'static str> {
        match *self {
            Self::QueryPresent(key) | Self::QueryEquals(key, _) | Self::QueryAbsent(key) => Some(key),
            _ => None,
        }
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Method(ref method) => write!(f, "Method({method})"),
            Self::Target(target) => write!(f, "Target({})", target.as_str()),
            Self::QueryPresent(key) => write!(f, "QueryPresent({key:?})"),
            Self::QueryEquals(key, value) => write!(f, "QueryEquals({key:?}, {value:?})"),
            Self::QueryAbsent(key) => write!(f, "QueryAbsent({key:?})"),
            Self::HostClass(class) => write!(f, "HostClass({})", class.as_str()),
            Self::PathLiteral(path) => write!(f, "PathLiteral({path:?})"),
            Self::ArnForm(form) => write!(f, "ArnForm({})", form.as_str()),
            Self::HeaderPrefix(name, prefix) => write!(f, "HeaderPrefix({name:?}, {prefix:?})"),
            Self::HeaderPresent { header, negated } => {
                if negated {
                    write!(f, "HeaderAbsent({header:?})")
                } else {
                    write!(f, "HeaderPresent({header:?})")
                }
            }
        }
    }
}

/// The borrowed request facts routing is allowed to see.
///
/// Every field is either `Copy` or a borrowed view, so this type is `Copy` and constructing one
/// allocates nothing. It deliberately cannot reach the body, the raw header map, or anything
/// resembling a store handle — see `crates/core/tests/purity_guard.rs`, which asserts that over
/// the source.
#[derive(Clone, Copy, Debug)]
pub struct RouteRequestParts<'a> {
    /// The request method.
    pub method: &'a Method,
    /// The undecoded path, exactly as it arrived.
    pub path: &'a str,
    /// What the path addresses, as decided by the resolver.
    pub target: TargetKind,
    /// The endpoint family, as decided by the resolver.
    pub host_class: HostClass,
    /// The ARN form in the bucket position, if any.
    pub arn_form: Option<ArnForm>,
    /// The query parameters, borrowed and already indexed.
    pub query: QueryView<'a>,
    /// The headers, borrowed.
    pub headers: HeaderView<'a>,
}

impl<'a> RouteRequestParts<'a> {
    /// The first value of a header, by lowercase name.
    ///
    /// Walks the map rather than building an [`http::HeaderName`], because constructing a name
    /// from a `&str` can allocate for a non-standard name and this is the pre-auth path. Only the
    /// two header predicates reach here, and only for entries that carry one.
    #[must_use]
    fn first_header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter_text()
            .find(|(header, _)| header.as_str() == name)
            .map(|(_, value)| value)
    }
}

/// The conjunction of predicates that selects one operation.
///
/// An empty conjunction matches every request, which is why `table` refuses one outside the
/// fallback precedence band.
///
/// Borrowed or owned: a hand-written table and a test fixture spell their predicates as a
/// `&'static [Predicate]`, while the generated table arrives as strings and is parsed into owned
/// predicates at build time. Both are the same type here, and neither allocates while matching —
/// `predicates()` is a deref either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSelector {
    predicates: Cow<'static, [Predicate]>,
}

impl RouteSelector {
    /// Wraps a static predicate list.
    #[must_use]
    pub const fn new(predicates: &'static [Predicate]) -> Self {
        Self {
            predicates: Cow::Borrowed(predicates),
        }
    }

    /// Wraps predicates parsed at build time.
    #[must_use]
    pub fn owned(predicates: Vec<Predicate>) -> Self {
        Self {
            predicates: Cow::Owned(predicates),
        }
    }

    /// The predicates, in evaluation order.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }

    /// Whether every predicate holds.
    #[must_use]
    pub fn matches(&self, request: &RouteRequestParts<'_>) -> bool {
        self.predicates.iter().all(|predicate| predicate.matches(request))
    }

    /// Whether every predicate holds, also reporting how many were evaluated.
    ///
    /// The count is what makes "the hot path is a constant number of comparisons" an assertion
    /// instead of a claim; see `crates/core/tests/hot_path.rs`.
    #[must_use]
    pub fn matches_counted(&self, request: &RouteRequestParts<'_>, evaluations: &mut usize) -> bool {
        for predicate in self.predicates.iter() {
            *evaluations = evaluations.saturating_add(1);
            if !predicate.matches(request) {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for RouteSelector {
    /// Renders the whole conjunction, which is what a conflict report has to print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.predicates.is_empty() {
            return f.write_str("<matches everything>");
        }
        for (position, predicate) in self.predicates.iter().enumerate() {
            if position > 0 {
                f.write_str(" ∧ ")?;
            }
            write!(f, "{predicate}")?;
        }
        Ok(())
    }
}

/// One row of the ordered route table.
///
/// `precedence` is assigned by codegen from the route overlay and is never written by hand in
/// Rust; `table` refuses a table whose precedences it did not receive from the generated data or
/// from an explicit test fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// Position in the ordered first-match table. Lower is tried first.
    pub precedence: u16,
    /// The conjunction that selects this operation.
    pub selector: RouteSelector,
    /// The operation name, matching `Operation::NAME` and the IR.
    pub op_name: &'static str,
    /// The path shape this operation advertises, for the reverse index and for explanations.
    pub path_shape: &'static str,
}
