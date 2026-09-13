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

//! A concrete request that two route entries both accept — the witness a conflict is reported with.
//!
//! Responsible for: [`RequestShape`], its human-readable rendering, and turning it back into the
//! borrowed [`RouteRequestParts`] the matcher consumes.
//! NOT responsible for: deciding that two selectors overlap (`lattice`), or matching (`selector`).
//! Upstream: `selector`, `rustfs-gateway-http`. Downstream: `lattice`, `table`, `explain`.
//!
//! # Why a witness and not a boolean
//!
//! "These two entries overlap" is a claim a reviewer cannot check. `GET /<bucket>?acl&tagging` is
//! a request they can send. More importantly it closes the loop on the overlap decision itself:
//! `lattice` builds a witness from the meet of two selectors and then *runs the ordinary matcher*
//! on it. If the lattice and the matcher ever disagree — a normalisation bug, a predicate added to
//! one and not the other — the witness fails to match and the build reports the inconsistency
//! instead of silently passing. The decision procedure is checked by the thing it is about.

use std::fmt;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustfs_gateway_http::{HeaderView, Limits, QueryIndex, QueryView};

use super::selector::{ArnForm, HostClass, RouteRequestParts, TargetKind};

/// A concrete request shape, owned, built at table-build time.
///
/// Not on any hot path: this type exists for error messages, explanations, and the build-time
/// self-check described in the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestShape {
    /// The method.
    pub method: Method,
    /// The path.
    pub path: String,
    /// What the path addresses.
    pub target: TargetKind,
    /// The endpoint family.
    pub host_class: HostClass,
    /// The ARN form in the bucket position, if any.
    pub arn_form: Option<ArnForm>,
    /// Query parameters, in the order they will be rendered. An empty value is a flag parameter.
    pub query: Vec<(String, String)>,
    /// Headers, by lowercase name.
    pub headers: Vec<(String, String)>,
}

impl RequestShape {
    /// The query string this shape renders to, without the leading `?`.
    #[must_use]
    pub fn query_string(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.query {
            if !out.is_empty() {
                out.push('&');
            }
            out.push_str(key);
            if !value.is_empty() {
                out.push('=');
                out.push_str(value);
            }
        }
        out
    }

    /// Materialises the borrowed views the matcher needs.
    ///
    /// Returns `None` when the shape cannot be expressed on the wire at all — a header name or a
    /// value that `http` refuses, or a query string the acceptance layer would reject. Callers
    /// treat that as "this witness cannot be verified", never as "the selectors do not overlap".
    #[must_use]
    pub(crate) fn materialise(&self) -> Option<MaterialisedShape<'_>> {
        let raw_query = self.query_string();
        let index = QueryIndex::parse(&raw_query, &Limits::default()).ok()?;
        let mut headers = HeaderMap::new();
        for (name, value) in &self.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
            let value = HeaderValue::from_str(value).ok()?;
            headers.append(name, value);
        }
        Some(MaterialisedShape {
            shape: self,
            raw_query,
            index,
            headers,
        })
    }
}

impl fmt::Display for RequestShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.path)?;
        let query = self.query_string();
        if !query.is_empty() {
            write!(f, "?{query}")?;
        }
        write!(f, "  (host_class={}, target={}", self.host_class.as_str(), self.target.as_str())?;
        if let Some(form) = self.arn_form {
            write!(f, ", arn={}", form.as_str())?;
        }
        for (name, value) in &self.headers {
            write!(f, ", {name}: {value}")?;
        }
        f.write_str(")")
    }
}

/// A [`RequestShape`] with the owned buffers the borrowed views point into.
pub(crate) struct MaterialisedShape<'a> {
    shape: &'a RequestShape,
    raw_query: String,
    index: QueryIndex,
    headers: HeaderMap,
}

impl MaterialisedShape<'_> {
    /// The borrowed view a selector is evaluated against.
    pub(crate) fn parts(&self) -> RouteRequestParts<'_> {
        RouteRequestParts {
            method: &self.shape.method,
            path: &self.shape.path,
            target: self.shape.target,
            host_class: self.shape.host_class,
            arn_form: self.shape.arn_form,
            query: QueryView::new(&self.raw_query, &self.index),
            headers: HeaderView::new(&self.headers),
            host_named_bucket: false,
        }
    }
}
