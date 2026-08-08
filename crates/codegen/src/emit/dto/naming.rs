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

//! Model spelling to Rust spelling.
//!
//! Responsible for: the four name conversions the dto emitter needs — module name, type name,
//! field name and associated-constant name — and nothing else.
//! NOT responsible for: deciding *which* names exist (that is [`super::registry`]) or rendering
//! (that is [`super::render`]).
//! Upstream: [`super`]. Downstream: every generated dto identifier.
//!
//! All four conversions run off one segmenter, so `ETag` cannot become `e_tag` in one place and
//! `etag` in another. A conversion that loses information (two model names mapping to one Rust
//! name) is a hard failure at the call site rather than a silent overwrite.

/// Splits a model name into acronym-aware segments.
///
/// A boundary is inserted before an upper-case letter that follows a lower-case letter, and
/// before the last upper-case letter of a run when a lower-case letter follows it. A digit never
/// starts a segment unless a lower-case letter follows it, which is what keeps `ChecksumCRC32C`
/// in one piece while still splitting `S3KeyFilter`.
#[must_use]
pub fn segments(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for (i, c) in chars.iter().copied().enumerate() {
        let prev = if i == 0 { None } else { chars.get(i - 1).copied() };
        let next = chars.get(i + 1).copied();
        let boundary = match (prev, c) {
            (None, _) => false,
            (Some(p), c) if c.is_ascii_uppercase() => {
                p.is_ascii_lowercase() || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
            }
            (Some(p), c) if c.is_ascii_lowercase() => p.is_ascii_digit(),
            _ => false,
        };
        if boundary && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.push(c);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `PutObject` becomes `put_object`, `ListObjectsV2` becomes `list_objects_v2`.
#[must_use]
pub fn module_name(name: &str) -> String {
    segments(name).join("_").to_ascii_lowercase()
}

/// The field spelling, escaped when it collides with a Rust keyword.
///
/// `ETag` becomes `e_tag`, `ID` becomes `id`, `Type` becomes `r#type`. The four keywords that
/// cannot be raw identifiers get a trailing underscore instead.
#[must_use]
pub fn field_name(name: &str) -> String {
    escaped(module_name(name))
}

/// The module *declaration* spelling: [`module_name`] escaped the same way a field is.
///
/// The file on disk keeps the unescaped name — `mod r#type;` resolves to `type.rs` — so this is
/// only ever the identifier written into a `mod` item or a `use` path, never a path on disk. The
/// select family's `JSONInput.Type` is what first needed it: an enumeration whose model name is a
/// Rust keyword produced `mod type;`, which does not parse.
#[must_use]
pub fn module_ident(name: &str) -> String {
    escaped(module_name(name))
}

/// The one keyword-escaping rule, so the module item and the field spelling cannot disagree.
fn escaped(snake: String) -> String {
    match snake.as_str() {
        "self" | "Self" | "super" | "crate" => format!("{snake}_"),
        other if KEYWORDS.contains(&other) => format!("r#{snake}"),
        _ => snake,
    }
}

/// The Rust type spelling for a model shape or an enumeration.
///
/// Only fully upper-case segments are re-cased: `ACL` becomes `Acl` because clippy's
/// `upper_case_acronyms` refuses the original, while `ETag` and `Object` pass through unchanged.
#[must_use]
pub fn type_name(name: &str) -> String {
    segments(name)
        .into_iter()
        .map(|segment| {
            if segment.len() >= 3 && segment.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                let mut chars = segment.chars();
                match chars.next() {
                    Some(first) => format!("{first}{}", chars.as_str().to_ascii_lowercase()),
                    None => segment,
                }
            } else {
                segment
            }
        })
        .collect()
}

/// The associated-constant spelling of one enumeration value.
///
/// `public-read-write` becomes `PUBLIC_READ_WRITE` and `aws:kms:dsse` becomes `AWS_KMS_DSSE`. A
/// value that starts with a digit gets a `V` prefix, because an identifier may not.
#[must_use]
pub fn const_name(value: &str) -> String {
    let mut out = String::new();
    let mut pending_separator = false;
    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_separator && !out.is_empty() {
                out.push('_');
            }
            pending_separator = false;
            out.push(c.to_ascii_uppercase());
        } else {
            pending_separator = true;
        }
    }
    match out.chars().next() {
        Some(first) if first.is_ascii_digit() => format!("V{out}"),
        Some(_) => out,
        None => "EMPTY".to_owned(),
    }
}

/// Every Rust keyword, strict and reserved, for the 2024 edition.
const KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "do", "dyn", "else", "enum", "extern",
    "false", "final", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override",
    "priv", "pub", "ref", "return", "static", "struct", "trait", "true", "try", "type", "typeof", "unsafe", "unsized", "use",
    "virtual", "where", "while", "yield",
];
