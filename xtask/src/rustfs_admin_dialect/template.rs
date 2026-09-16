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

//! A route's path template as the generator reads it: its segments, its parameters and the one
//! that is its bucket, the literal-over-parameter shadowing between routes, and the operation
//! name a route gets.
//!
//! Responsible for: [`template_params`] under ADR-0027's rule and ADR-0030's bucket binding,
//! [`shadowing`] under ADR-0027 (b) and ADR-0031 (d), and [`type_name`] with its file stem [`snake`].
//! NOT responsible for: choosing or ruling the routes, or rendering anything (`super`).
//! Upstream: `super::Route` and `super::Declared`. Downstream: `super::plan`.

use super::{Declared, Route, Surface};

/// The template parameters ADR-0025 (c) binds as the authorisation bucket (ADR-0030); every other
/// parameter is service-level (ADR-0027).
const BUCKET_PARAMS: &[&str] = &["bucket", "warehouse"];

/// A later operation whose parameter meets this operation's literal segment.
pub(super) struct Shadow {
    pub(super) shadowed: String,
    pub(super) literal: String,
    pub(super) param: String,
}

/// One segment of an inventory path: literal text, or a whole-segment `{parameter}`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Segment<'a> {
    Literal(&'a str),
    Param(&'a str),
}

pub(super) fn segments(path: &str) -> impl Iterator<Item = Segment<'_>> {
    path.split('/')
        .map(|segment| match segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}')) {
            Some(name) => Segment::Param(name),
            None => Segment::Literal(segment),
        })
}

/// A route's template: its parameters in path order, and the one ADR-0025 (c) binds as the
/// authorisation bucket, if any (ADR-0030).
pub(super) struct Template {
    /// Every parameter, in path order, the bucket included: each is decoded into
    /// `RequestContextView::path_params()`.
    pub(super) params: Vec<String>,
    /// The `{bucket}` or `{warehouse}` parameter, which is the operation's bucket.
    pub(super) bucket: Option<String>,
}

/// A route's template under ADR-0027's rule: each parameter is a whole segment named by a
/// lowercase identifier, the inventory lists exactly these, none repeats, and at most one is a
/// bucket, which ADR-0030 binds. An empty segment is allowed only as a trailing `/`, which RustFS
/// registers `POST heal/` with and core matches exactly (ADR-0030).
pub(super) fn template_params(route: &Route, at: &str) -> Result<Template, String> {
    let mut params: Vec<String> = Vec::new();
    let mut bucket = None;
    let mut all: Vec<Segment<'_>> = segments(route.path.strip_prefix('/').unwrap_or(&route.path)).collect();
    if matches!(all.last(), Some(Segment::Literal(""))) && all.len() > 1 {
        all.pop();
    }
    for segment in all {
        match segment {
            Segment::Literal("") => return Err(format!("{at}: an empty segment that is not a trailing '/'")),
            Segment::Literal(text) if text.contains(['{', '}']) => {
                return Err(format!("{at}: a parameter shares its segment with literal text"));
            }
            Segment::Literal(_) => {}
            Segment::Param(name) => {
                if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_') {
                    return Err(format!("{at}: the parameter {{{name}}} is not a lowercase identifier"));
                }
                if params.iter().any(|seen| seen == name) {
                    return Err(format!("{at}: the parameter {{{name}}} appears twice"));
                }
                if BUCKET_PARAMS.contains(&name) {
                    if bucket.is_some() {
                        return Err(format!("{at}: two parameters name a bucket"));
                    }
                    bucket = Some(name.to_owned());
                }
                params.push(name.to_owned());
            }
        }
    }
    if params != route.path_params {
        return Err(format!("{at}: the template names {params:?}, the inventory {:?}", route.path_params));
    }
    Ok(Template { params, bucket })
}

/// Every pair of declared operations whose rows overlap, as `(winner, shadowed)` indices, under
/// ADR-0027's rule as ADR-0031 (d) completes it: at the first position where one route has a
/// literal segment and the other a parameter, the literal wins, as in RustFS's `matchit` router;
/// the winner must come first in inventory order, so it has the lower precedence. An overlap no
/// literal orders, or one whose literal route comes later, is refused. A trailing `/` meets no
/// parameter (ADR-0030).
pub(super) fn shadowing(declared: &[Declared]) -> Result<Vec<(usize, usize, Shadow)>, String> {
    let mut pairs = Vec::new();
    for (a, first) in declared.iter().enumerate() {
        for (b, second) in declared.iter().enumerate().skip(a + 1) {
            let queries_differ = matches!((first.query, second.query), (Some(x), Some(y)) if x != y);
            if first.method != second.method || queries_differ {
                continue;
            }
            let (x, y): (Vec<Segment<'_>>, Vec<Segment<'_>>) =
                (segments(&first.path).collect(), segments(&second.path).collect());
            if x.len() != y.len() {
                continue;
            }
            // `Some(true)` when the first route's literal decides, `Some(false)` when the second's.
            let mut decided: Option<(bool, &str, &str)> = None;
            let mut disjoint = false;
            for pair in x.iter().zip(&y) {
                match pair {
                    (Segment::Literal(l), Segment::Literal(m)) if l != m => disjoint = true,
                    (Segment::Literal(""), Segment::Param(_)) | (Segment::Param(_), Segment::Literal("")) => disjoint = true,
                    (Segment::Literal(l), Segment::Param(p)) if decided.is_none() => decided = Some((true, l, p)),
                    (Segment::Param(p), Segment::Literal(l)) if decided.is_none() => decided = Some((false, l, p)),
                    _ => {}
                }
            }
            match (disjoint, decided) {
                (true, _) => {}
                (false, Some((true, literal, param))) => pairs.push((
                    a,
                    b,
                    Shadow {
                        shadowed: second.name.clone(),
                        literal: literal.to_owned(),
                        param: param.to_owned(),
                    },
                )),
                (false, Some((false, ..))) => {
                    return Err(format!(
                        "{} is shadowed by the later {}: a literal must come before the parameter it meets",
                        first.name, second.name
                    ));
                }
                (false, None) => {
                    return Err(format!("{} and {} overlap, and no literal segment orders them", first.name, second.name));
                }
            }
        }
    }
    Ok(pairs)
}

/// `Get` for `GET`, the surface's name tag (`Iceberg` for the table catalog, nothing for the
/// admin API), and each path word after the surface's prefix capitalised (a `{parameter}` as `By`
/// and its words), then the query value.
pub(super) fn type_name(method: &str, surface: &Surface, path: &str, query: Option<(&str, &str)>) -> Option<String> {
    let rest = path.strip_prefix(surface.prefix)?;
    let mut words = vec![method, surface.tag];
    for segment in segments(rest) {
        match segment {
            Segment::Param(param) => {
                words.push("By");
                words.extend(param.split('_'));
            }
            Segment::Literal(text) => words.extend(text.split(['-', '_', '.'])),
        }
    }
    words.extend(query.map(|(_, value)| value));
    let mut name = String::new();
    for word in words.into_iter().filter(|word| !word.is_empty()) {
        let mut chars = word.chars();
        let first = chars.next()?;
        if !first.is_ascii_alphanumeric() || !chars.as_str().chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        name.push(first.to_ascii_uppercase());
        name.push_str(&chars.as_str().to_ascii_lowercase());
    }
    name.starts_with(|c: char| c.is_ascii_uppercase()).then_some(name)
}

/// The file stem `check_op_file_shape.sh` expects: an underscore before every capital but the
/// first, then lowercase.
pub(super) fn snake(name: &str) -> String {
    let mut stem = String::new();
    for (index, c) in name.chars().enumerate() {
        if index > 0 && c.is_ascii_uppercase() {
            stem.push('_');
        }
        stem.push(c.to_ascii_lowercase());
    }
    stem
}
