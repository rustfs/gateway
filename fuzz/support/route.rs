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

//! Shared generated-route request generation and executable routing properties.
//!
//! Responsible for: deriving requests from the generated table, falsifying accepted disjointness,
//! and comparing the readable and compiled routers over the same request alphabet.
//! NOT responsible for: choosing libFuzzer entry points, cross-precedence shadowing, deciding
//! which operation is correct, or classifying host strings into host classes.
//! Upstream: libFuzzer bytes and the generated route table. Downstream: the `route_disjoint` and
//! `route_compiled_equiv` fuzz targets.
//!
//! # Why the property is stated over a two-row table
//!
//! "No precedence in the generated table ever matches twice" is what `c-route-1011` says, and over
//! that table it is **true by construction**: all 72 rows carry pairwise-distinct precedences, so
//! no request can match two rows at one precedence whatever the lattice does. Asserting it there
//! would be a check that cannot fail — the exact shape `AGENTS.md` lists seven instances of.
//!
//! So the target puts the question where it can be answered. It takes two generated rows, places
//! them at **one** precedence, and asks `RouteTable::build` to judge them:
//!
//! - build refuses (`Conflict`) — the lattice found the overlap. Nothing to check here; the
//!   witness it reports is verified against the ordinary matcher inside `lattice` itself.
//! - build accepts — the lattice asserted these two selectors cannot both be satisfied. That is a
//!   claim about every request in existence, and this target spends its bytes trying to refute it.
//!
//! A normalisation that under-reports overlap is invisible to the build (it simply stops
//! objecting) and invisible to the golden table (nothing moved). It is visible here.
//!
//! The second property is the compiled/readable equivalence over the whole generated table, which
//! `crates/core/tests/hot_path.rs` proptests over the *fixture* table only. Both fuzz targets use
//! this module so their generated request alphabets cannot drift apart.

#![allow(dead_code)] // Each fuzz binary invokes one property from this path-shared module.

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustfs_gateway_core::route::{
    ArnForm, CompiledRouter, HostClass, Predicate, RouteEntry, RouteRequestParts, RouteTable, SHADOWING, ShadowingDecls,
    TargetKind, generated_entries,
};
use rustfs_gateway_http::{HeaderView, Limits, QueryIndex, QueryView};
use std::sync::OnceLock;

/// Methods the table can express, plus one it cannot.
const METHODS: [&str; 7] = ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH"];

/// Query values tried against every key, beside the ones the table pins itself.
const OFF_ALPHABET_VALUES: [&str; 3] = ["", "0", "zzz"];

/// Paths tried beside the literals the table pins. The target is derived from the path, never
/// drawn separately: on the wire the resolver computes one from the other, and a witness pairing
/// `/bucket/key` with `Target::Service` is a request nothing can send.
const OFF_ALPHABET_PATHS: [&str; 5] = ["/", "/bucket", "/bucket/key", "/bucket/key/deeper", "/bucket/"];

/// Header values tried against every header name the table reads.
const OFF_ALPHABET_HEADER_VALUES: [&str; 2] = ["", "/other-bucket/other-key"];

/// The precedence both rows of the probe table are given. Inside a subresource band, so the
/// fallback-band exemption for an empty selector never applies and a bare row is refused rather
/// than silently accepted.
const PROBE_PRECEDENCE: u16 = 300;

/// At most this many query parameters per request. Acceptance caps a request at 64; a much smaller
/// bound is used so that the generator does not spend a whole input on the query and leave the
/// header dimension unreached.
const MAX_QUERY_PARAMS: usize = 6;

/// At most this many headers per request.
const MAX_HEADERS: usize = 4;

struct Fixture {
    entries: Vec<RouteEntry>,
    table: RouteTable,
    router: CompiledRouter,
    query_keys: Vec<&'static str>,
    query_values: Vec<&'static str>,
    header_names: Vec<&'static str>,
    header_values: Vec<String>,
    paths: Vec<&'static str>,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

/// The generated table, built once.
///
/// A build failure is a failure of this target, not a reason to return: the property cannot be
/// evaluated against a table that does not exist, and a clean exit over one would be reporting the
/// absence of a measurement as a pass.
fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        let entries = match generated_entries() {
            Ok(entries) => entries,
            Err(error) => panic!("the generated route table does not parse: {error}"),
        };
        let table = match RouteTable::build(entries.clone(), &SHADOWING) {
            Ok(table) => table,
            Err(error) => panic!("the generated route table does not build: {error}"),
        };
        let router = match CompiledRouter::compile(&table) {
            Ok(router) => router,
            Err(error) => panic!("the generated route table does not compile: {error}"),
        };

        // The alphabet is read out of the table's own predicates. A hand-written vocabulary would
        // be a second list to keep in step, and the first route to introduce a key nobody added to
        // it would be the one route the generator could not reach.
        let mut query_keys: Vec<&'static str> = Vec::new();
        let mut query_values: Vec<&'static str> = OFF_ALPHABET_VALUES.to_vec();
        let mut header_names: Vec<&'static str> = Vec::new();
        let mut header_values: Vec<String> = OFF_ALPHABET_HEADER_VALUES.iter().map(|v| (*v).to_owned()).collect();
        let mut paths: Vec<&'static str> = OFF_ALPHABET_PATHS.to_vec();

        for entry in table.entries() {
            for predicate in entry.selector.predicates() {
                match *predicate {
                    Predicate::QueryPresent(key) | Predicate::QueryAbsent(key) => push(&mut query_keys, key),
                    Predicate::QueryEquals(key, value) => {
                        push(&mut query_keys, key);
                        push(&mut query_values, value);
                    }
                    Predicate::HeaderPresent { header, .. } => push(&mut header_names, header),
                    Predicate::HeaderPrefix(header, prefix) => {
                        push(&mut header_names, header);
                        // The prefix itself, the prefix carrying a parameter, and the prefix one
                        // character short: `multipart/form-data; boundary=…` must match and
                        // `multipart/form-dat` must not.
                        push(&mut header_values, prefix.to_owned());
                        push(&mut header_values, format!("{prefix}; boundary=----0"));
                        push(&mut header_values, truncate_one_char(prefix).to_owned());
                    }
                    Predicate::PathLiteral(path) => push(&mut paths, path),
                    Predicate::Method(_) | Predicate::Target(_) | Predicate::HostClass(_) | Predicate::ArnForm(_) => {}
                }
            }
        }
        // Off-alphabet keys explore the branch of a selector where nothing pinned the key.
        push(&mut query_keys, "x-id");
        push(&mut query_keys, "unknown-parameter");

        Fixture {
            entries,
            table,
            router,
            query_keys,
            query_values,
            header_names,
            header_values,
            paths,
        }
    })
}

fn push<T: PartialEq>(into: &mut Vec<T>, item: T) {
    if !into.contains(&item) {
        into.push(item);
    }
}

/// The string without its last character. Character, not byte: slicing a `&str` at an arbitrary
/// byte offset panics, and a panic in the generator is a crash report about the generator.
fn truncate_one_char(text: &str) -> &str {
    match text.char_indices().next_back() {
        Some((at, _)) => &text[..at],
        None => text,
    }
}

/// What a path-style resolver would say the path addresses.
fn target_of(path: &str) -> TargetKind {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        None if trimmed.is_empty() => TargetKind::Service,
        None => TargetKind::Bucket,
        Some((_, key)) if key.is_empty() => TargetKind::Bucket,
        Some(_) => TargetKind::Object,
    }
}

/// A byte-at-a-time reader over the fuzzer's input.
struct Bytes<'a> {
    input: &'a [u8],
    at: usize,
}

impl Bytes<'_> {
    fn next(&mut self) -> Option<u8> {
        let byte = self.input.get(self.at).copied()?;
        self.at = self.at.saturating_add(1);
        Some(byte)
    }

    fn choose<'c, T>(&mut self, choices: &'c [T]) -> Option<&'c T> {
        let byte = self.next()?;
        choices.get(usize::from(byte) % choices.len().max(1))
    }

    /// A count in `0..=limit`.
    fn count(&mut self, limit: usize) -> usize {
        self.next().map_or(0, |byte| usize::from(byte) % limit.saturating_add(1))
    }
}

/// One generated request, owning the buffers its borrowed views point into.
struct Request {
    method: Method,
    path: &'static str,
    target: TargetKind,
    host_class: HostClass,
    arn_form: Option<ArnForm>,
    raw_query: String,
    index: QueryIndex,
    headers: HeaderMap,
}

impl Request {
    fn parts(&self) -> RouteRequestParts<'_> {
        RouteRequestParts {
            method: &self.method,
            path: self.path,
            target: self.target,
            host_class: self.host_class,
            arn_form: self.arn_form,
            query: QueryView::new(&self.raw_query, &self.index),
            headers: HeaderView::new(&self.headers),
            host_named_bucket: false,
        }
    }

    /// The whole request, headers included.
    ///
    /// A witness a reader cannot reproduce is not a witness, and the header dimension is exactly
    /// where the interesting overlaps live: `PutObject` and `CopyObject` differ by one header and
    /// nothing else, so a report that printed only the request line would name two selectors that
    /// look disjoint on the evidence shown.
    fn line(&self) -> String {
        let mut out = format!("{} {}", self.method, self.path);
        if !self.raw_query.is_empty() {
            out.push('?');
            out.push_str(&self.raw_query);
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("  [{}: {}]", name.as_str(), value.to_str().unwrap_or("<non-ascii>")));
        }
        out
    }
}

fn generate(bytes: &mut Bytes<'_>, fixture: &Fixture) -> Option<Request> {
    let method = Method::from_bytes(bytes.choose(&METHODS)?.as_bytes()).ok()?;
    let path = *bytes.choose(&fixture.paths)?;
    let host_class = *bytes.choose(&HostClass::ALL)?;
    let arn_form = match usize::from(bytes.next()?) % (ArnForm::ALL.len() + 1) {
        0 => None,
        index => ArnForm::ALL.get(index.saturating_sub(1)).copied(),
    };

    // Acceptance refuses a repeated parameter, so a query the router could never be handed is not
    // generated: a witness the wire cannot produce is not a witness.
    let mut raw_query = String::new();
    let mut used: Vec<&str> = Vec::new();
    let wanted = bytes.count(MAX_QUERY_PARAMS);
    while used.len() < wanted {
        let key = *bytes.choose(&fixture.query_keys)?;
        let value = *bytes.choose(&fixture.query_values)?;
        if used.contains(&key) {
            continue;
        }
        used.push(key);
        if !raw_query.is_empty() {
            raw_query.push('&');
        }
        raw_query.push_str(key);
        if !value.is_empty() {
            raw_query.push('=');
            raw_query.push_str(value);
        }
    }
    let index = QueryIndex::parse(&raw_query, &Limits::default()).ok()?;

    let mut headers = HeaderMap::new();
    let wanted = bytes.count(MAX_HEADERS);
    for _ in 0..wanted {
        let name = *bytes.choose(&fixture.header_names)?;
        let value = bytes.choose(&fixture.header_values)?.clone();
        let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) else {
            continue;
        };
        if !headers.contains_key(&name) {
            headers.insert(name, value);
        }
    }

    Some(Request {
        method,
        path,
        target: target_of(path),
        host_class,
        arn_form,
        raw_query,
        index,
        headers,
    })
}

pub(crate) fn check_disjoint(input: &[u8]) {
    let fixture = fixture();
    let mut bytes = Bytes { input, at: 0 };

    // Two rows, one precedence. `ShadowingDecls::NONE` because a declaration is what makes an
    // overlap *legal across* precedences, and there is only one precedence here.
    let Some(first) = bytes.next().map(|byte| usize::from(byte) % fixture.entries.len().max(1)) else {
        return;
    };
    let Some(second) = bytes.next().map(|byte| usize::from(byte) % fixture.entries.len().max(1)) else {
        return;
    };
    let Some(request) = generate(&mut bytes, fixture) else {
        return;
    };
    let parts = request.parts();

    if first != second
        && let (Some(left), Some(right)) = (fixture.entries.get(first), fixture.entries.get(second))
    {
        let mut left = left.clone();
        let mut right = right.clone();
        left.precedence = PROBE_PRECEDENCE;
        right.precedence = PROBE_PRECEDENCE;
        let (left_name, right_name) = (left.op_name, right.op_name);
        let (left_selector, right_selector) = (left.selector.clone(), right.selector.clone());
        // A build that refuses says the lattice found the overlap, or refused the pair for a
        // reason of its own (an empty selector outside the fallback band, a contradiction). Either
        // way it made no claim this target can refute.
        if RouteTable::build(vec![left, right], &ShadowingDecls::NONE).is_ok() {
            assert!(
                !(left_selector.matches(&parts) && right_selector.matches(&parts)),
                "the route lattice called these two disjoint, and `{}` satisfies both:\n  \
                 {left_name}  {left_selector}\n  {right_name}  {right_selector}\n  \
                 (target={:?} host_class={:?} arn={:?})",
                request.line(),
                request.target,
                request.host_class,
                request.arn_form,
            );
        }
    }
}

pub(crate) fn check_compiled_equiv(input: &[u8]) {
    let fixture = fixture();
    let mut bytes = Bytes { input, at: 0 };
    let Some(request) = generate(&mut bytes, fixture) else {
        return;
    };
    let parts = request.parts();

    // The compiled table is what actually serves requests; the readable one is what the goldens,
    // the conflict reports and `route explain` are written against. They are required to be the
    // same function, and `resolve` is not a restatement of the walk above — it has its own
    // subresource-bitmap fast path.
    let readable = fixture.table.resolve(&parts).map(|entry| entry.op_name);
    let compiled = fixture.router.resolve(&parts).and_then(|op| fixture.router.op_name(op));
    assert_eq!(
        readable,
        compiled,
        "the readable and compiled tables disagree about `{}` (target={:?} host_class={:?})",
        request.line(),
        request.target,
        request.host_class,
    );
}
