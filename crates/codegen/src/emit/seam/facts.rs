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

//! The s3s DTO fact table the seam generator converts against.
//!
//! Responsible for: parsing `s3s_<version>.facts` — one line per s3s struct member, string
//! enumeration, union and error code (with the status it carries), with every type alias already
//! resolved by `scripts/extract_s3s_shapes.py` — into [`S3sFacts`].
//! NOT responsible for: deciding how a gateway member maps onto an s3s one (`super::expr`), or
//! extracting the facts (the script does, from the s3s release RustFS links).
//! Upstream: the checked-in fact file. Downstream: [`super`].
//!
//! The table holds names and type spellings only, never s3s code, so the generator can know the
//! exact s3s shape — wrapper, width, enumeration or plain string — without guessing and without
//! the s3s crate being a build dependency of codegen.

use std::collections::{BTreeMap, BTreeSet};

/// One resolved s3s member type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3sType {
    /// `Option<T>`.
    Option(Box<S3sType>),
    /// `Vec<T>` (s3s spells it `List<T>`).
    Vec(Box<S3sType>),
    /// `HashMap<K, V>` (s3s spells it `Map<K, V>`).
    Map(Box<S3sType>, Box<S3sType>),
    /// A string enumeration newtype, by s3s name.
    Enum(String),
    /// A structure, by s3s name.
    Struct(String),
    /// A union, by s3s name.
    Union(String),
    /// A leaf the fact file spells verbatim: `String`, `i32`, `i64`, `bool`, `Timestamp`, `ETag`,
    /// `ETagCondition`, `Range`, `CopySource`, `StreamingBlob`, `Bytes`, `()`, `Event`,
    /// `SelectObjectContentEventStream`.
    Leaf(String),
    /// An s3s runtime member with no wire value (`future`, the policy-tag cache, a parsed POST
    /// policy); it always takes its `Default`.
    Opaque,
}

impl S3sType {
    fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if let Some(inner) = text.strip_prefix("Option<").and_then(|rest| rest.strip_suffix('>')) {
            return Ok(Self::Option(Box::new(Self::parse(inner)?)));
        }
        if let Some(inner) = text.strip_prefix("Vec<").and_then(|rest| rest.strip_suffix('>')) {
            return Ok(Self::Vec(Box::new(Self::parse(inner)?)));
        }
        if let Some(inner) = text.strip_prefix("Map<").and_then(|rest| rest.strip_suffix('>')) {
            let (key, value) = split_top_level(inner).ok_or_else(|| format!("seam facts: malformed map `{text}`"))?;
            return Ok(Self::Map(Box::new(Self::parse(key)?), Box::new(Self::parse(value)?)));
        }
        if let Some(name) = text.strip_prefix("enum ") {
            return Ok(Self::Enum(name.to_owned()));
        }
        if let Some(name) = text.strip_prefix("struct ") {
            return Ok(Self::Struct(name.to_owned()));
        }
        if let Some(name) = text.strip_prefix("union ") {
            return Ok(Self::Union(name.to_owned()));
        }
        if text == "opaque" {
            return Ok(Self::Opaque);
        }
        Ok(Self::Leaf(text.to_owned()))
    }

    /// The type without its `Option`, and whether there was one.
    #[must_use]
    pub fn unwrap_option(&self) -> (&Self, bool) {
        match self {
            Self::Option(inner) => (inner, true),
            other => (other, false),
        }
    }
}

fn split_top_level(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (index, c) in text.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => return Some((&text[..index], &text[index + 1..])),
            _ => {}
        }
    }
    None
}

/// Every s3s DTO fact of one release.
#[derive(Debug, Default)]
pub struct S3sFacts {
    /// String enumerations.
    pub enums: BTreeSet<String>,
    /// Unions: variant name and payload type, in declaration order.
    pub unions: BTreeMap<String, Vec<(String, S3sType)>>,
    /// Structs: member name and type, in declaration order.
    pub structs: BTreeMap<String, Vec<(String, S3sType)>>,
    /// Every `S3ErrorCode` variant but `Custom`, in declaration order, with the HTTP status its
    /// `status_code` names, or `None` for a code that names none.
    pub errors: Vec<(String, Option<u16>)>,
}

impl S3sFacts {
    /// Parses a fact file.
    ///
    /// # Errors
    ///
    /// A line the grammar does not know, or a member before any struct.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut facts = Self::default();
        let mut current: Option<String> = None;
        for (number, line) in text.lines().enumerate() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if let Some(member) = line.strip_prefix("  ") {
                let owner = current
                    .as_ref()
                    .ok_or_else(|| format!("seam facts:{}: member outside a struct", number + 1))?;
                let (name, ty) = member
                    .split_once(": ")
                    .ok_or_else(|| format!("seam facts:{}: malformed member", number + 1))?;
                let ty = S3sType::parse(ty)?;
                facts.structs.entry(owner.clone()).or_default().push((name.to_owned(), ty));
            } else if let Some(name) = line.strip_prefix("struct ") {
                facts.structs.entry(name.to_owned()).or_default();
                current = Some(name.to_owned());
            } else if let Some(name) = line.strip_prefix("enum ") {
                facts.enums.insert(name.to_owned());
                current = None;
            } else if let Some(rest) = line.strip_prefix("error ") {
                let mut columns = rest.split(' ');
                let (Some(name), Some(status), None) = (columns.next(), columns.next(), columns.next()) else {
                    return Err(format!("seam facts:{}: an error line is `error <Code> <status|->`", number + 1));
                };
                if !is_identifier(name) {
                    return Err(format!("seam facts:{}: `{name}` is not an error code identifier", number + 1));
                }
                let status = match status {
                    "-" => None,
                    digits => Some(
                        digits
                            .parse::<u16>()
                            .map_err(|_| format!("seam facts:{}: `{digits}` is not an HTTP status", number + 1))?,
                    ),
                };
                facts.errors.push((name.to_owned(), status));
                current = None;
            } else if let Some(rest) = line.strip_prefix("union ") {
                let (name, body) = rest
                    .split_once(" { ")
                    .ok_or_else(|| format!("seam facts:{}: malformed union", number + 1))?;
                let body = body.strip_suffix(" }").unwrap_or(body);
                let mut variants = Vec::new();
                for variant in body.split(", ") {
                    let (variant, ty) = variant
                        .split_once(": ")
                        .ok_or_else(|| format!("seam facts:{}: malformed variant", number + 1))?;
                    variants.push((variant.to_owned(), S3sType::parse(ty)?));
                }
                facts.unions.insert(name.to_owned(), variants);
                current = None;
            } else {
                return Err(format!("seam facts:{}: unknown line `{line}`", number + 1));
            }
        }
        Ok(facts)
    }
}

/// Whether `name` is a Rust identifier as the s3s error enum spells its variants.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphabetic()) && chars.all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_members_wrappers_and_unions() {
        let facts = S3sFacts::parse(
            "# header\nenum StorageClass\nunion F { And: struct A, Prefix: String }\nstruct X\n  a: Option<Vec<struct Y>>\n  m: Map<String, String>\n  f: Option<opaque>\n",
        )
        .expect("parses");
        assert!(facts.enums.contains("StorageClass"));
        assert_eq!(facts.unions["F"][1], ("Prefix".to_owned(), S3sType::Leaf("String".to_owned())));
        let x = &facts.structs["X"];
        assert_eq!(x[0].1, S3sType::Option(Box::new(S3sType::Vec(Box::new(S3sType::Struct("Y".to_owned()))))));
        assert!(matches!(x[1].1, S3sType::Map(..)));
        assert_eq!(x[2].1, S3sType::Option(Box::new(S3sType::Opaque)));
    }

    #[test]
    fn refuses_an_unknown_line_and_a_member_outside_a_struct() {
        assert!(S3sFacts::parse("widget X\n").is_err());
        assert!(S3sFacts::parse("  a: String\n").is_err());
        assert!(S3sFacts::parse("union F And: struct A\n").is_err());
    }

    #[test]
    fn parses_error_codes_with_and_without_a_status() {
        let facts = S3sFacts::parse("error NoSuchKey 404\nerror MissingAttachment -\n").expect("parses");
        assert_eq!(
            facts.errors,
            [("NoSuchKey".to_owned(), Some(404)), ("MissingAttachment".to_owned(), None)]
        );
    }

    #[test]
    fn n_refuses_a_malformed_error_line() {
        assert!(S3sFacts::parse("error NoSuchKey\n").is_err(), "no status column");
        assert!(S3sFacts::parse("error NoSuchKey 4o4\n").is_err(), "a status that is not a number");
        assert!(S3sFacts::parse("error NoSuchKey 404 extra\n").is_err(), "a third column");
        assert!(
            S3sFacts::parse("error no-such-key 404\n").is_err(),
            "a name that is not a Rust identifier"
        );
    }

    #[test]
    fn the_checked_in_facts_parse() {
        let facts = S3sFacts::parse(include_str!("s3s_0_17_0.facts")).expect("the checked-in facts parse");
        assert!(facts.structs.contains_key("ListObjectsV2Input"));
        assert!(facts.enums.contains("StorageClass"));
    }
}
