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

//! A dialect's reviewed path-prefix claims and the path templates inside them (ADR-0024).
//!
//! Responsible for: [`PathClaim`] and its grammar, [`PathTemplate`] and its allocation-free
//! matcher, and [`PathParams`] — the values a matched template yields once routing is done.
//! NOT responsible for: the table that routes claimed rows and checks their overlaps (`claimed`),
//! whether a dialect may claim a prefix (the overlay review and the per-dialect rules are
//! `crate::dialect`'s), the S3 table (`table`, `compiled`), or what a handler does with a value.
//! Upstream: nothing but `std`. Downstream: `claimed`, `crate::dialect`, `crate::request_context`.
//!
//! # Why a claim is its own table rather than one more predicate
//!
//! The S3 table's lattice treats the path and the target as independent dimensions, so a row on a
//! path literal still overlaps every S3 row on the same method and target and, under
//! [`super::ShadowingPolicy::EveryOverlap`], owes one declaration per pair: ten for a `GET` and
//! eleven for a `PUT` (rustfs/backlog#1744). A claim removes its prefix from S3 routing instead.
//! The router asks the claim table first. A request inside a claim is answered by a claimed row or
//! by nothing, never by an S3 row. Disjointness from S3 is then structural, and the only overlaps
//! left to review are between two rows inside one claim.
//!
//! # What a claim covers
//!
//! A path-style request on the standard endpoint, with no ARN, whose raw path is the prefix or
//! continues it with `/`. A virtual-hosted request is never covered: its whole path is an object
//! key in the host's bucket. The prefix is compared byte for byte with the raw path, as every
//! routing value is (see `selector`'s module docs), so `/rustfs/%61dmin/…` is an ordinary S3 object
//! request for the decoded key, authorised as one.
//!
//! # Why a claim is at least two segments deep
//!
//! In a path-style request the first segment is the bucket. A one-segment claim such as `/health`
//! or `/rustfs` would take a whole bucket of that name away from S3. A two-segment claim takes only
//! the path-style spelling of the keys under its second segment, in that one bucket. That is what
//! RustFS's admin router does to a bucket named `rustfs` or `minio` today. The bucket itself, every
//! other key in it, and the same keys spelled virtual-hosted all stay S3.
//!
//! # Matching
//!
//! A template is a sequence of segments, each a literal or a `{parameter}`. Matching splits the
//! raw path on `/` and compares segment for segment, without allocating. A parameter matches one
//! non-empty raw segment that is not a dot segment in any spelling and carries no encoded `/` or
//! `\`, so a parameter can never span two segments or climb out of one. Decoding happens once,
//! after routing, in [`PathTemplate::extract`], which also refuses control bytes and invalid UTF-8.

use std::fmt;
use std::str::FromStr;

/// RFC 3986's unreserved bytes: the only ones a claim or a template literal may spell.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

// ── the claim ────────────────────────────────────────────────────────────────────────────────

/// Why a [`PathClaim`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRejection {
    /// The prefix does not start with `/`.
    NotAbsolute,
    /// The prefix ends with `/`. A claim names whole segments; matching adds the separator.
    TrailingSlash,
    /// Two adjacent separators.
    EmptySegment,
    /// A `.` or `..` segment.
    DotSegment,
    /// A byte outside RFC 3986's unreserved set: a `%`, a brace, a space.
    ForbiddenCharacter,
    /// Fewer than two segments. The first path segment is a bucket, so the claim would take a whole
    /// bucket away from S3.
    ShadowsABucket,
    /// No reason written.
    NoReason,
    /// No evidence, or a blank evidence entry.
    NoEvidence,
}

impl ClaimRejection {
    /// Why, in one sentence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "a claim is an absolute path prefix and starts with '/'",
            Self::TrailingSlash => "a claim names whole segments and does not end with '/'",
            Self::EmptySegment => "a claim has no empty segment",
            Self::DotSegment => "a claim has no '.' or '..' segment",
            Self::ForbiddenCharacter => "a claim spells only unreserved characters: letters, digits, '-', '.', '_', '~'",
            Self::ShadowsABucket => "a claim shallower than two segments names a bucket and would take it away from S3",
            Self::NoReason => "a claim says why the dialect owns this prefix",
            Self::NoEvidence => "a claim carries at least one source, and no blank one",
        }
    }
}

impl fmt::Display for ClaimRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A path prefix a dialect takes away from S3 routing, and the review that allows it.
///
/// Reviewed data, like [`super::ShadowingDecl`]: it lives in the dialect's overlay beside the
/// operations it serves, and the start-up posture report lists every installed claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathClaim {
    /// The prefix, `/segment/segment[/…]`, with no trailing `/`.
    pub prefix: &'static str,
    /// Why this dialect owns the prefix. Written by a human; read by whoever changes it.
    pub reason: &'static str,
    /// Where the claim comes from: one URL per source. Must be non-empty.
    pub evidence: &'static [&'static str],
}

impl PathClaim {
    /// Why this claim cannot be installed, or `None` when it can.
    #[must_use]
    pub fn rejection(&self) -> Option<ClaimRejection> {
        let Some(rest) = self.prefix.strip_prefix('/') else {
            return Some(ClaimRejection::NotAbsolute);
        };
        if rest.is_empty() {
            return Some(ClaimRejection::ShadowsABucket);
        }
        if rest.ends_with('/') {
            return Some(ClaimRejection::TrailingSlash);
        }
        let mut depth = 0_usize;
        for segment in rest.split('/') {
            if segment.is_empty() {
                return Some(ClaimRejection::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Some(ClaimRejection::DotSegment);
            }
            if !segment.bytes().all(is_unreserved) {
                return Some(ClaimRejection::ForbiddenCharacter);
            }
            depth = depth.saturating_add(1);
        }
        if depth < 2 {
            return Some(ClaimRejection::ShadowsABucket);
        }
        if self.reason.trim().is_empty() {
            return Some(ClaimRejection::NoReason);
        }
        if self.evidence.is_empty() || self.evidence.iter().any(|source| source.trim().is_empty()) {
            return Some(ClaimRejection::NoEvidence);
        }
        None
    }

    /// Whether a raw request path is inside this claim: the prefix itself, or the prefix
    /// continued by `/`. `/rustfs/adminx` is not inside `/rustfs/admin`.
    #[must_use]
    pub fn covers(&self, raw_path: &str) -> bool {
        raw_path
            .strip_prefix(self.prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }

    /// Whether one path could be inside both claims: they are equal, or one is nested in the other.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.covers(other.prefix) || other.covers(self.prefix)
    }

    /// The claim's segments, in order.
    pub fn segments(&self) -> impl Iterator<Item = &'static str> {
        let prefix: &'static str = self.prefix;
        prefix.strip_prefix('/').unwrap_or(prefix).split('/')
    }
}

// ── the template ─────────────────────────────────────────────────────────────────────────────

/// One template segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Segment {
    /// Matches exactly this raw segment.
    Literal(&'static str),
    /// Matches one raw segment and binds it to this name.
    Parameter(&'static str),
}

/// Why a [`PathTemplate`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateRejection {
    /// The template does not start with `/`.
    NotAbsolute,
    /// The template ends with `/`.
    TrailingSlash,
    /// Two adjacent separators, or no segment at all.
    EmptySegment,
    /// A `.` or `..` literal segment.
    DotSegment,
    /// A literal byte outside RFC 3986's unreserved set.
    ForbiddenCharacter,
    /// A parameter that is not `{name}` with a lowercase `[a-z_][a-z0-9_]*` name.
    MalformedParameter,
    /// A parameter sharing its segment with literal text, such as `{id}.zip`. Not supported yet: the
    /// one RustFS route that needs it is recorded in ADR-0024's migration plan.
    ParameterWithAffix,
    /// The same parameter name twice.
    DuplicateParameter,
}

impl TemplateRejection {
    /// Why, in one sentence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "a template is an absolute path and starts with '/'",
            Self::TrailingSlash => "a template does not end with '/'",
            Self::EmptySegment => "a template has no empty segment",
            Self::DotSegment => "a template has no '.' or '..' literal segment",
            Self::ForbiddenCharacter => "a template literal spells only unreserved characters",
            Self::MalformedParameter => "a parameter is a whole segment `{name}` with a lowercase name",
            Self::ParameterWithAffix => "a parameter is a whole segment; literal text beside it is not supported",
            Self::DuplicateParameter => "a parameter name appears once per template",
        }
    }
}

impl fmt::Display for TemplateRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn is_parameter_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Exactly one well-formed `{name}` with literal text beside it.
fn is_affixed_parameter(segment: &str) -> bool {
    let (Some(open), Some(close)) = (segment.find('{'), segment.find('}')) else {
        return false;
    };
    segment.matches('{').count() == 1
        && segment.matches('}').count() == 1
        && open < close
        && segment.get(open.saturating_add(1)..close).is_some_and(is_parameter_name)
}

/// A raw segment a parameter may bind: non-empty, not a dot segment in any spelling, and with no
/// separator, encoded or not, that would let one value stand for two segments.
fn is_one_segment_value(raw: &str) -> bool {
    !raw.is_empty() && !raw.contains('\\') && !has_encoded_separator(raw) && !is_dot_segment(raw)
}

fn has_encoded_separator(raw: &str) -> bool {
    raw.as_bytes()
        .windows(3)
        .any(|window| matches!(window, [b'%', b'2', b'f' | b'F'] | [b'%', b'5', b'c' | b'C']))
}

/// `.` or `..`, with any dot spelled `%2e` or `%2E`.
fn is_dot_segment(raw: &str) -> bool {
    let mut rest = raw.as_bytes();
    let mut dots = 0_u8;
    while !rest.is_empty() {
        rest = match rest {
            [b'.', tail @ ..] | [b'%', b'2', b'e' | b'E', tail @ ..] => tail,
            _ => return false,
        };
        dots = dots.saturating_add(1);
        if dots > 2 {
            return false;
        }
    }
    dots > 0
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes one parameter value, once, and refuses what no handler may be handed.
fn decode_parameter(raw: &str) -> Result<String, &'static str> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let [high, low, after @ ..] = tail else {
                return Err("a percent escape is cut short");
            };
            let (Some(high), Some(low)) = (hex(*high), hex(*low)) else {
                return Err("a percent escape is not two hexadecimal digits");
            };
            bytes.push((high << 4) | low);
            rest = after;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    let value = String::from_utf8(bytes).map_err(|_| "the decoded value is not UTF-8")?;
    if value.is_empty() {
        return Err("the value is empty");
    }
    if value.contains(['/', '\\']) {
        return Err("the decoded value contains a path separator");
    }
    if value == "." || value == ".." {
        return Err("the decoded value is a dot segment");
    }
    if value.chars().any(char::is_control) {
        return Err("the decoded value contains a control character");
    }
    Ok(value)
}

/// A path template inside a claim: literal segments and whole-segment `{parameters}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathTemplate {
    text: &'static str,
    segments: Box<[Segment]>,
}

impl PathTemplate {
    /// Parses a template.
    ///
    /// # Errors
    ///
    /// The [`TemplateRejection`] naming the first rule the text breaks.
    pub fn parse(text: &'static str) -> Result<Self, TemplateRejection> {
        let Some(rest) = text.strip_prefix('/') else {
            return Err(TemplateRejection::NotAbsolute);
        };
        if rest.is_empty() {
            return Err(TemplateRejection::EmptySegment);
        }
        if rest.ends_with('/') {
            return Err(TemplateRejection::TrailingSlash);
        }
        let mut segments = Vec::new();
        for segment in rest.split('/') {
            if segment.is_empty() {
                return Err(TemplateRejection::EmptySegment);
            }
            if let Some(inner) = segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}')) {
                if !is_parameter_name(inner) {
                    return Err(TemplateRejection::MalformedParameter);
                }
                if segments.contains(&Segment::Parameter(inner)) {
                    return Err(TemplateRejection::DuplicateParameter);
                }
                segments.push(Segment::Parameter(inner));
                continue;
            }
            if segment.contains(['{', '}']) {
                return Err(if is_affixed_parameter(segment) {
                    TemplateRejection::ParameterWithAffix
                } else {
                    TemplateRejection::MalformedParameter
                });
            }
            if segment == "." || segment == ".." {
                return Err(TemplateRejection::DotSegment);
            }
            if !segment.bytes().all(is_unreserved) {
                return Err(TemplateRejection::ForbiddenCharacter);
            }
            segments.push(Segment::Literal(segment));
        }
        Ok(Self {
            text,
            segments: segments.into_boxed_slice(),
        })
    }

    /// The template as written.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.text
    }

    /// The parameter names, in path order.
    pub fn parameters(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.segments.iter().filter_map(|segment| match segment {
            Segment::Parameter(name) => Some(*name),
            Segment::Literal(_) => None,
        })
    }

    /// Whether the template starts with the claim's segments as literals, so every path it matches
    /// is inside the claim.
    #[must_use]
    pub fn is_within(&self, claim: &PathClaim) -> bool {
        let mut mine = self.segments.iter();
        claim
            .segments()
            .all(|wanted| matches!(mine.next(), Some(Segment::Literal(literal)) if *literal == wanted))
    }

    /// Whether a raw request path matches, segment for segment. Allocates nothing.
    #[must_use]
    pub fn matches(&self, raw_path: &str) -> bool {
        let Some(rest) = raw_path.strip_prefix('/') else {
            return false;
        };
        let mut raw = rest.split('/');
        for segment in self.segments.iter() {
            let Some(value) = raw.next() else {
                return false;
            };
            let accepted = match segment {
                Segment::Literal(literal) => value == *literal,
                Segment::Parameter(_) => is_one_segment_value(value),
            };
            if !accepted {
                return false;
            }
        }
        raw.next().is_none()
    }

    /// The parameter values of a raw path this template matches, each decoded once.
    ///
    /// # Errors
    ///
    /// [`PathParamError::Mismatch`] when the path does not match, and
    /// [`PathParamError::Invalid`] naming the parameter whose value decodes to something no
    /// handler may be handed: a malformed escape, invalid UTF-8, a separator, a dot segment, or a
    /// control character. The value itself is never part of the error.
    pub fn extract(&self, raw_path: &str) -> Result<PathParams, PathParamError> {
        if !self.matches(raw_path) {
            return Err(PathParamError::Mismatch);
        }
        let rest = raw_path.strip_prefix('/').unwrap_or(raw_path);
        let mut values = Vec::new();
        for (segment, raw) in self.segments.iter().zip(rest.split('/')) {
            if let Segment::Parameter(name) = segment {
                let value = decode_parameter(raw).map_err(|why| PathParamError::Invalid { name, why })?;
                values.push((*name, value.into_boxed_str()));
            }
        }
        Ok(PathParams { values })
    }

    /// The raw, still-encoded segment `name` matched in `raw_path`, or `None` when the path does
    /// not match or the template has no such parameter. For a bound bucket (ADR-0025), whose
    /// label must meet the S3 rules undecoded.
    #[must_use]
    pub fn raw_value<'p>(&self, raw_path: &'p str, name: &str) -> Option<&'p str> {
        if !self.matches(raw_path) {
            return None;
        }
        let rest = raw_path.strip_prefix('/').unwrap_or(raw_path);
        self.segments
            .iter()
            .zip(rest.split('/'))
            .find_map(|(segment, raw)| matches!(segment, Segment::Parameter(parameter) if *parameter == name).then_some(raw))
    }

    /// A path both templates match, or `None` when no path does.
    pub(super) fn overlap_path(&self, other: &Self) -> Option<String> {
        if self.segments.len() != other.segments.len() {
            return None;
        }
        let mut path = String::new();
        for (mine, theirs) in self.segments.iter().zip(other.segments.iter()) {
            let segment = match (mine, theirs) {
                (Segment::Literal(a), Segment::Literal(b)) if a == b => *a,
                (Segment::Literal(_), Segment::Literal(_)) => return None,
                (Segment::Literal(literal), Segment::Parameter(_)) | (Segment::Parameter(_), Segment::Literal(literal)) => {
                    literal
                }
                (Segment::Parameter(_), Segment::Parameter(_)) => "p",
            };
            path.push('/');
            path.push_str(segment);
        }
        Some(path)
    }

    /// Whether every path this template matches is matched by `other` too.
    pub(super) fn refines(&self, other: &Self) -> bool {
        self.segments.len() == other.segments.len()
            && self.segments.iter().zip(other.segments.iter()).all(|pair| match pair {
                (_, Segment::Parameter(_)) => true,
                (Segment::Literal(a), Segment::Literal(b)) => a == b,
                (Segment::Parameter(_), Segment::Literal(_)) => false,
            })
    }
}

// ── the values ───────────────────────────────────────────────────────────────────────────────

/// Why a path parameter could not be produced or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathParamError {
    /// The path does not match the template.
    Mismatch,
    /// The value of this parameter decodes to something no handler may be handed.
    Invalid {
        /// The parameter.
        name: &'static str,
        /// Why, as a constant: the value is never echoed.
        why: &'static str,
    },
    /// The template has no parameter of this name.
    Missing {
        /// The name asked for.
        name: &'static str,
    },
    /// The value does not parse as the type asked for.
    Unparsable {
        /// The parameter.
        name: &'static str,
    },
}

impl PathParamError {
    /// The parameter the error is about, when it is about one.
    #[must_use]
    pub const fn name(&self) -> Option<&'static str> {
        match self {
            Self::Mismatch => None,
            Self::Invalid { name, .. } | Self::Missing { name } | Self::Unparsable { name } => Some(name),
        }
    }

    /// Why, as a compile-time constant that never carries the value.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Mismatch => "the path does not match the template",
            Self::Invalid { why, .. } => why,
            Self::Missing { .. } => "the template has no path parameter of this name",
            Self::Unparsable { .. } => "the path parameter does not parse as the type asked for",
        }
    }
}

impl fmt::Display for PathParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "path parameter {name}: {}", self.message()),
            None => f.write_str(self.message()),
        }
    }
}

impl std::error::Error for PathParamError {}

/// The values a matched template bound, decoded once, in path order.
///
/// Only [`PathTemplate::extract`] produces a non-empty one, so a handler cannot be handed a value
/// the template did not match:
///
/// ```compile_fail,E0451
/// use rustfs_gateway_core::route::PathParams;
/// let forged = PathParams { values: Vec::new() };
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathParams {
    values: Vec<(&'static str, Box<str>)>,
}

impl PathParams {
    /// No values: every request outside a claim, and every claimed row with no parameter.
    #[must_use]
    pub const fn none() -> Self {
        Self { values: Vec::new() }
    }

    /// The decoded value of one parameter.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| &**value)
    }

    /// The value of one parameter, parsed as `T`.
    ///
    /// # Errors
    ///
    /// [`PathParamError::Missing`] when the template has no such parameter, and
    /// [`PathParamError::Unparsable`] when the value does not parse.
    pub fn parse<T: FromStr>(&self, name: &'static str) -> Result<T, PathParamError> {
        let value = self.get(name).ok_or(PathParamError::Missing { name })?;
        value.parse().map_err(|_| PathParamError::Unparsable { name })
    }

    /// Every value, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.values.iter().map(|(name, value)| (*name, &**value))
    }

    /// How many parameters were bound.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether none was.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

    fn claim(prefix: &'static str) -> PathClaim {
        PathClaim {
            prefix,
            reason: "fixture",
            evidence: EVIDENCE,
        }
    }

    #[test]
    fn a_claim_covers_its_prefix_and_what_continues_it_with_a_separator() {
        let admin = claim("/rustfs/admin");
        for inside in ["/rustfs/admin", "/rustfs/admin/", "/rustfs/admin/v3/info"] {
            assert!(admin.covers(inside), "{inside}");
        }
        for outside in [
            "/rustfs",
            "/rustfs/",
            "/rustfs/adminx",
            "/rustfs/admi",
            "/x/rustfs/admin",
            "rustfs/admin",
        ] {
            assert!(!admin.covers(outside), "{outside}");
        }
    }

    #[test]
    fn nested_and_equal_claims_overlap_and_siblings_do_not() {
        let admin = claim("/rustfs/admin");
        assert!(admin.overlaps(&claim("/rustfs/admin/v3")));
        assert!(claim("/rustfs/admin/v3").overlaps(&admin));
        assert!(admin.overlaps(&admin));
        assert!(!admin.overlaps(&claim("/rustfs/adminx")));
        assert!(!admin.overlaps(&claim("/minio/admin")));
    }

    #[test]
    fn dot_segments_are_recognised_in_every_spelling() {
        for dot in [".", "..", "%2e", "%2E", ".%2e", "%2E%2e"] {
            assert!(is_dot_segment(dot), "{dot}");
        }
        for other in ["...", "a.", ".a", "%2e%2e%2e", "%2f", ""] {
            assert!(!is_dot_segment(other), "{other}");
        }
    }

    #[test]
    fn a_literal_refines_a_parameter_and_not_the_other_way_round() {
        let literal = PathTemplate::parse("/a/b/stats").expect("a template");
        let parameter = PathTemplate::parse("/a/b/{name}").expect("a template");
        assert!(literal.refines(&parameter));
        assert!(!parameter.refines(&literal));
        assert_eq!(literal.overlap_path(&parameter).as_deref(), Some("/a/b/stats"));
        let other = PathTemplate::parse("/a/c/{name}").expect("a template");
        assert_eq!(literal.overlap_path(&other), None);
    }
}
