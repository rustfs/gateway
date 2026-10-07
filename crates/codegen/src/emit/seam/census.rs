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

//! `generated/dto/seam/census/**`: the member census of every pinned legacy structure a covered
//! operation's input or output reaches.
//!
//! Responsible for: one module per such structure, holding `PATHS` (every member path, nested
//! structures expanded, `[]` marking a list element), `differences` (the paths at which two values
//! differ) and `present` (the paths a value holds something at), all read from the fact table and
//! never from the gateway model — so a differential can name the member two stacks disagree on,
//! and prove every member was exercised, without printing a value (one of them is an SSE-C key).
//! NOT responsible for: converting anything (`super::render`), or deciding what a difference
//! means (the difftest seam diff and the classification census do).
//! Upstream: [`super::facts`] and the covered operations. Downstream: `generated/dto/seam/census/**`
//! (rustfs/gateway#1076).
//!
//! A live body or event stream has no value to compare and is left out of all three: the diff that
//! drains it compares the bytes. A runtime member with no wire value (a cache, a parsed policy) is
//! left out for the same reason. A member holding a structure with no member of its own (an empty
//! element such as `<EventBridgeConfiguration/>`) is a path itself: it says something by being
//! there, so a row must set it and a conversion that drops it must show.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use super::facts::{S3sFacts, S3sType};
use crate::emit::dto::naming;

/// Leaves the census never compares: a live body and an event stream.
const STREAMS: [&str; 2] = ["StreamingBlob", "SelectObjectContentEventStream"];

/// How deep a structure may nest before the census refuses it as a cycle.
const MAX_DEPTH: usize = 16;

fn skipped(ty: &S3sType) -> bool {
    match ty {
        S3sType::Option(inner) | S3sType::Vec(inner) => skipped(inner),
        S3sType::Opaque => true,
        S3sType::Leaf(leaf) => STREAMS.contains(&leaf.as_str()),
        _ => false,
    }
}

/// The structure a member holds, through at most one `Option` and one `Vec`.
fn nested_struct(ty: &S3sType) -> Option<&str> {
    match ty {
        S3sType::Option(inner) | S3sType::Vec(inner) => nested_struct(inner),
        S3sType::Struct(name) => Some(name),
        _ => None,
    }
}

/// Every structure reachable from `roots`, the roots included.
///
/// # Errors
///
/// A root or a member naming a structure the fact table does not declare.
pub fn reachable<'a>(facts: &'a S3sFacts, roots: &[String]) -> Result<BTreeSet<&'a str>, String> {
    let mut seen = BTreeSet::new();
    let mut pending: Vec<String> = roots.to_vec();
    while let Some(name) = pending.pop() {
        let Some((key, members)) = facts.structs.get_key_value(name.as_str()) else {
            return Err(format!("census: `{name}` is not a structure in the fact table"));
        };
        if !seen.insert(key.as_str()) {
            continue;
        }
        for (_, ty) in members {
            if let Some(nested) = nested_struct(ty) {
                pending.push(nested.to_owned());
            }
        }
    }
    Ok(seen)
}

/// Every member path of `name` under `prefix`.
///
/// # Errors
///
/// A structure nested deeper than `MAX_DEPTH` (a cycle), or one the fact table lacks.
pub fn paths(facts: &S3sFacts, name: &str, prefix: &str, depth: usize, out: &mut Vec<String>) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("census: `{name}` nests deeper than {MAX_DEPTH} levels"));
    }
    let members = facts
        .structs
        .get(name)
        .ok_or_else(|| format!("census: `{name}` is not a structure in the fact table"))?;
    for (member, ty) in members {
        if skipped(ty) {
            continue;
        }
        let (core, _) = ty.unwrap_option();
        match core {
            S3sType::Struct(nested) => nested_paths(facts, nested, &format!("{prefix}{member}"), depth, out)?,
            S3sType::Vec(element) => match element.as_ref() {
                S3sType::Struct(nested) => nested_paths(facts, nested, &format!("{prefix}{member}[]"), depth, out)?,
                _ => out.push(format!("{prefix}{member}[]")),
            },
            _ => out.push(format!("{prefix}{member}")),
        }
    }
    Ok(())
}

/// The paths of the structure `nested` a member at `path` holds. A structure with no member of
/// its own (an empty element such as `<EventBridgeConfiguration/>`) says something only by being
/// there, so the member is a path itself rather than no path at all.
fn nested_paths(facts: &S3sFacts, nested: &str, path: &str, depth: usize, out: &mut Vec<String>) -> Result<(), String> {
    let before = out.len();
    paths(facts, nested, &format!("{path}."), depth + 1, out)?;
    if out.len() == before {
        out.push(path.to_owned());
    }
    Ok(())
}

/// Whether the structure `name` has no member path of its own.
fn memberless(facts: &S3sFacts, name: &str) -> Result<bool, String> {
    let mut held = Vec::new();
    paths(facts, name, "", 0, &mut held)?;
    Ok(held.is_empty())
}

/// The function of the census module for `name`.
fn census_fn(name: &str, function: &str) -> String {
    format!("super::{}::{function}", naming::module_ident(name))
}

/// The body of `differences` for one structure.
fn differences_body(members: &[(String, S3sType)]) -> String {
    let mut body = String::new();
    for (member, ty) in members {
        if skipped(ty) {
            continue;
        }
        let path = format!("format!(\"{{prefix}}{member}\")");
        match ty {
            S3sType::Struct(nested) => {
                let _ = writeln!(
                    body,
                    "    {}(&format!(\"{{prefix}}{member}.\"), &left.{member}, &right.{member}, out);",
                    census_fn(nested, "differences")
                );
            }
            S3sType::Option(inner) if matches!(inner.as_ref(), S3sType::Struct(_)) => {
                let Some(nested) = nested_struct(inner) else { continue };
                let _ = writeln!(
                    body,
                    "    match (&left.{member}, &right.{member}) {{\n        (Some(l), Some(r)) => {}(&format!(\"{{prefix}}{member}.\"), l, r, out),\n        (None, None) => {{}}\n        _ => out.push({path}),\n    }}",
                    census_fn(nested, "differences")
                );
            }
            S3sType::Vec(element) if matches!(element.as_ref(), S3sType::Struct(_)) => {
                let Some(nested) = nested_struct(element) else { continue };
                let _ = writeln!(
                    body,
                    "    super::list(prefix, \"{member}\", &left.{member}, &right.{member}, out, {});",
                    census_fn(nested, "differences")
                );
            }
            S3sType::Option(inner) if matches!(inner.as_ref(), S3sType::Vec(element) if matches!(element.as_ref(), S3sType::Struct(_))) =>
            {
                let Some(nested) = nested_struct(inner) else { continue };
                let _ = writeln!(
                    body,
                    "    match (&left.{member}, &right.{member}) {{\n        (Some(l), Some(r)) => super::list(prefix, \"{member}\", l, r, out, {}),\n        (None, None) => {{}}\n        _ => out.push({path}),\n    }}",
                    census_fn(nested, "differences")
                );
            }
            _ => {
                let _ = writeln!(body, "    if left.{member} != right.{member} {{\n        out.push({path});\n    }}");
            }
        }
    }
    body
}

/// Pushes `path` when the container `member` holds at least one entry.
fn non_empty(member: &str, optional: bool, path: &str) -> String {
    if optional {
        format!("if value.{member}.as_ref().is_some_and(|held| !held.is_empty()) {{ out.push(format!(\"{{prefix}}{path}\")); }}")
    } else {
        format!("if !value.{member}.is_empty() {{ out.push(format!(\"{{prefix}}{path}\")); }}")
    }
}

/// The body of `present` for one structure.
fn present_body(facts: &S3sFacts, members: &[(String, S3sType)]) -> Result<String, String> {
    let mut body = String::new();
    for (member, ty) in members {
        if skipped(ty) {
            continue;
        }
        let (core, optional) = ty.unwrap_option();
        // What one held value of the member contributes, reading it as `held`.
        let contribution = match core {
            S3sType::Struct(nested) if memberless(facts, nested)? => format!("out.push(format!(\"{{prefix}}{member}\"));"),
            S3sType::Struct(nested) => format!("{}(&format!(\"{{prefix}}{member}.\"), held, out);", census_fn(nested, "present")),
            S3sType::Vec(element) => match element.as_ref() {
                S3sType::Struct(nested) if memberless(facts, nested)? => {
                    format!("for _ in held {{ out.push(format!(\"{{prefix}}{member}[]\")); }}")
                }
                S3sType::Struct(nested) => format!(
                    "for element in held {{ {}(&format!(\"{{prefix}}{member}[].\"), element, out); }}",
                    census_fn(nested, "present")
                ),
                _ => {
                    let _ = writeln!(body, "    {}", non_empty(member, optional, &format!("{member}[]")));
                    continue;
                }
            },
            S3sType::Map(..) => {
                let _ = writeln!(body, "    {}", non_empty(member, optional, member));
                continue;
            }
            _ if optional => {
                let _ = writeln!(body, "    if value.{member}.is_some() {{ out.push(format!(\"{{prefix}}{member}\")); }}");
                continue;
            }
            _ => {
                let _ = writeln!(body, "    out.push(format!(\"{{prefix}}{member}\"));");
                continue;
            }
        };
        if optional {
            let _ = writeln!(body, "    if let Some(held) = &value.{member} {{ {contribution} }}");
        } else {
            let _ = writeln!(body, "    {{ let held = &value.{member}; {contribution} }}");
        }
    }
    Ok(body)
}

/// One structure's census module.
///
/// # Errors
///
/// A structure the fact table lacks, or one nested too deep.
pub fn module(facts: &S3sFacts, name: &str) -> Result<String, String> {
    let members = facts
        .structs
        .get(name)
        .ok_or_else(|| format!("census: `{name}` is not a structure in the fact table"))?;
    let mut all = Vec::new();
    paths(facts, name, "", 0, &mut all)?;
    let mut out = String::from(super::render::HEADER);
    let _ = write!(
        out,
        "\n//! The `{name}` member census: every member path, and the paths two values differ at or one holds.\n\n\
         #[allow(unused_imports)] // A structure whose every member is skipped names no pinned type.\n\
         use super::super::s3s;\n\n\
         /// Every member path of `{name}`, nested structures expanded, `[]` marking a list element.\n\
         pub const PATHS: &[&str] = &[\n"
    );
    for path in &all {
        let _ = writeln!(out, "    \"{path}\",");
    }
    let _ = write!(
        out,
        "];\n\n\
         /// Appends, under `prefix`, every member path at which `left` and `right` differ. A list of \
         another length differs as a whole; a list of the same length differs element by element.\n\
         #[allow(unused_variables, clippy::too_many_lines, clippy::ptr_arg)]\n\
         pub fn differences(prefix: &str, left: &s3s::dto::{name}, right: &s3s::dto::{name}, out: &mut Vec<String>) {{\n{}}}\n\n\
         /// Appends, under `prefix`, every member path `value` holds something at: a required \
         member always, an optional one when set, a list element per element.\n\
         #[allow(unused_variables, clippy::too_many_lines, clippy::ptr_arg)]\n\
         pub fn present(prefix: &str, value: &s3s::dto::{name}, out: &mut Vec<String>) {{\n{}}}\n",
        differences_body(members),
        present_body(facts, members)?
    );
    Ok(out)
}

/// The census root: the list helper and one module per structure.
#[must_use]
pub fn root(modules: &[String]) -> String {
    let mut out = String::from(super::render::HEADER);
    out.push_str(
        "\n//! The member census of every pinned legacy structure a covered operation reaches \
         (rustfs/gateway#1076), one module each.\n\n\
         /// Appends, under `prefix`, `member` when the two lists differ in length, else every \
         path at which two elements at the same index differ.\n\
         pub fn list<T>(prefix: &str, member: &str, left: &[T], right: &[T], out: &mut Vec<String>, each: fn(&str, &T, &T, &mut Vec<String>)) {\n\
         \x20   if left.len() != right.len() {\n\
         \x20       out.push(format!(\"{prefix}{member}\"));\n\
         \x20       return;\n\
         \x20   }\n\
         \x20   for (index, (l, r)) in left.iter().zip(right).enumerate() {\n\
         \x20       each(&format!(\"{prefix}{member}[{index}].\"), l, r, out);\n\
         \x20   }\n\
         }\n\n",
    );
    for module in modules {
        let _ = writeln!(out, "pub mod {module};");
    }
    out
}

/// The error-code census: every `S3ErrorCode` variant the fact table lists, with the HTTP status
/// its `status_code` names, so a test can hold the error seam to every code without naming the
/// pinned revision's list by hand (rustfs/backlog#2759).
#[must_use]
pub fn error_codes(facts: &S3sFacts) -> String {
    let mut out = String::from(super::render::HEADER);
    out.push_str(
        "\n//! The error-code census: every `S3ErrorCode` variant but `Custom`, with the status it names.\n\n\
         #[allow(unused_imports)] // Named so a stale list fails to compile against the pinned crate.\n\
         use super::super::s3s;\n\n\
         /// Every pinned error code and the HTTP status its `status_code` names, `None` for a code that\n\
         /// names none, in the order the pinned enum declares them.\n\
         pub const CODES: &[(&str, Option<u16>)] = &[\n",
    );
    for (name, status) in &facts.errors {
        let _ = writeln!(out, "    (\"{name}\", {status:?}),");
    }
    out.push_str("];\n");
    out
}

/// Every census file for the covered operations, under `dir`.
///
/// # Errors
///
/// A covered operation whose input or output the fact table lacks, or a structure it reaches.
pub fn emit(facts: &S3sFacts, operations: &[&str], dir: &Path) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    let roots: Vec<String> = operations
        .iter()
        .flat_map(|operation| [format!("{operation}Input"), format!("{operation}Output")])
        .collect();
    let structures = reachable(facts, &roots)?;
    let mut files = Vec::new();
    let mut modules = Vec::new();
    for name in structures {
        files.push((dir.join(format!("{}.rs", naming::module_name(name))), module(facts, name)?));
        modules.push(naming::module_ident(name));
    }
    files.push((dir.join("error_codes.rs"), error_codes(facts)));
    modules.push("error_codes".to_owned());
    files.push((dir.join("mod.rs"), root(&modules)));
    Ok(files)
}
