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

//! Planning one mutation of a mutable quirk's lowered-IR source.
//!
//! Responsible for: choosing the single alternative value a mutation dimension admits, and
//! grouping quirk ids by the overlay family file that declares them.
//! NOT responsible for: writing the value into the IR (that is [`apply`]), regenerating, building,
//! or judging whether a case caught the mutation — the command in `xtask` owns the loop.
//! Upstream: [`crate::emit::quirk_toml::resolve_sources`], which reads the same path grammar this
//! module writes. Downstream: `xtask conformance mutate`.
//!
//! # Why the plan is separate from the application
//!
//! A mutation that resolves to the value already in the IR is a check that cannot fail: it
//! regenerates identical artefacts, the suite stays green, and the run reads as "no case catches
//! this rule" when nothing was ever changed. [`Mutation::new`] refuses to construct that shape, so
//! the failure is at planning time with a name attached rather than at reporting time as a silent
//! false negative.

pub mod apply;

use std::collections::BTreeMap;
use std::path::Path;

use rustfs_gateway_model::MutationDimension;
use rustfs_gateway_model::ir::TimestampFormat;
use rustfs_gateway_model::toml_lite::{self, Toml};

use crate::emit::quirk_toml::{ResolvedSource, SourceValue};
use crate::{Error, Result, io};

/// One planned flip of one lowered-IR mutation source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    /// The quirk whose rule this source carries.
    pub quirk: String,
    /// The lowered-IR path, in the grammar `crate::emit::quirk_toml` resolves.
    pub path: String,
    /// The value the unmutated IR carries at that path.
    pub from: SourceValue,
    /// The value to write instead.
    pub to: SourceValue,
}

impl Mutation {
    /// Builds a mutation, refusing one whose replacement equals the current value.
    ///
    /// # Errors
    ///
    /// Returns the reason when `to` equals `from`.
    pub fn new(quirk: &str, path: &str, from: SourceValue, to: SourceValue) -> std::result::Result<Self, String> {
        if from == to {
            return Err(format!(
                "quirk `{quirk}` source `{path}`: the planned mutation equals the current value, so it \
                 could not change any artefact"
            ));
        }
        Ok(Mutation {
            quirk: quirk.to_owned(),
            path: path.to_owned(),
            from,
            to,
        })
    }
}

/// The alternative spelling written in place of a renamed element, attribute or wire name.
///
/// A fixed prefix rather than a random string: the mutated artefacts are meant to be readable, and
/// a reviewer who sees `MutatedLifecycleConfiguration` in a failure message knows immediately which
/// run produced it. The prefix cannot collide with a real S3 spelling.
const RENAME_PREFIX: &str = "Mutated";

/// Plans the flip for one resolved source under one mutation dimension.
///
/// Every dimension gets the one alternative that a client would actually observe: a boolean is
/// negated, an optional value is dropped, an ordering is reversed, a name is renamed. There is no
/// "pick something random" branch, because the run has to be reproducible for the matrix to be
/// worth reading twice.
///
/// # Errors
///
/// Returns the reason when the dimension and the value shape admit no single obvious alternative.
/// An unplannable source is reported as such by the command; it never counts as a killed mutant and
/// never counts as a covered rule.
pub fn plan(quirk: &str, dimension: MutationDimension, source: &ResolvedSource) -> std::result::Result<Mutation, String> {
    let to = alternative(dimension, &source.current, &source.path)?;
    Mutation::new(quirk, &source.path, source.current.clone(), to)
}

fn alternative(dimension: MutationDimension, current: &SourceValue, path: &str) -> std::result::Result<SourceValue, String> {
    match current {
        // A boolean rule has exactly one alternative whatever the dimension calls it: a flattened
        // list becomes wrapped, a required field becomes optional, a demanded checksum becomes
        // tolerated.
        SourceValue::Bool(value) => Ok(SourceValue::Bool(!value)),
        // Absence is itself a rule here. Dropping the value is the mutation that matters: the
        // operation-specific error code becomes a generic one, the omission condition disappears.
        SourceValue::OptionalText(Some(_)) => Ok(SourceValue::OptionalText(None)),
        SourceValue::OptionalText(None) => Err(format!(
            "source `{path}` is already absent, and this planner has no evidence for which present \
             value the protocol would otherwise carry"
        )),
        SourceValue::TextList(values) => text_list_alternative(dimension, values, path),
        SourceValue::Int(value) => int_alternative(dimension, *value, path),
        SourceValue::Text(value) => text_alternative(dimension, value, path),
    }
}

fn text_list_alternative(
    dimension: MutationDimension,
    values: &[String],
    path: &str,
) -> std::result::Result<SourceValue, String> {
    match dimension {
        // Reversing is the mutation an ordering rule is about; a list of one has no other order,
        // and saying so is better than emptying it and calling the result an ordering mutation.
        MutationDimension::ElementOrder if values.len() >= 2 => {
            let mut reversed = values.to_vec();
            reversed.reverse();
            Ok(SourceValue::TextList(reversed))
        }
        MutationDimension::ElementOrder => {
            Err(format!("source `{path}` orders fewer than two elements, so it admits no second order"))
        }
        // The rule is which fields are URL-encoded, so the mutation is to encode none of them.
        MutationDimension::ElementEncoding if !values.is_empty() => Ok(SourceValue::TextList(Vec::new())),
        MutationDimension::ElementEncoding => Err(format!("source `{path}` is already the empty set")),
        other => Err(format!(
            "source `{path}` is a list and dimension `{}` has no planned list mutation",
            other.as_str()
        )),
    }
}

fn int_alternative(dimension: MutationDimension, value: i64, path: &str) -> std::result::Result<SourceValue, String> {
    match dimension {
        // The two success statuses this surface actually uses. Swapping them is observable to every
        // client; adding one would produce a status no operation is documented to return, which
        // tests the harness rather than the corpus.
        MutationDimension::StatusMapping => match value {
            200 => Ok(SourceValue::Int(204)),
            204 => Ok(SourceValue::Int(200)),
            other => Err(format!(
                "source `{path}` carries success status {other}, which has no reviewed alternative"
            )),
        },
        MutationDimension::DefaultValue => Ok(SourceValue::Int(value.saturating_add(1))),
        other => Err(format!(
            "source `{path}` is an integer and dimension `{}` has no planned integer mutation",
            other.as_str()
        )),
    }
}

fn text_alternative(dimension: MutationDimension, value: &str, path: &str) -> std::result::Result<SourceValue, String> {
    match dimension {
        MutationDimension::ElementRename | MutationDimension::AttributeRename | MutationDimension::WrapStrategy => {
            Ok(SourceValue::Text(format!("{RENAME_PREFIX}{value}")))
        }
        MutationDimension::DefaultValue => Ok(SourceValue::Text(format!("{RENAME_PREFIX}{value}"))),
        // The rendering contexts are a closed set, so the mutation names the other member rather
        // than inventing a spelling no reader implements.
        // The IR names three renderings and only one of them is bare, so "unquote it" is spelled
        // `XmlBare` even for a header position. That is the whole content of the quoting rule: a
        // client reading `ETag: abc` where it expected `ETag: "abc"` has the deviation in hand.
        MutationDimension::QuoteStrategy => match value {
            "HeaderQuoted" | "XmlQuoted" => Ok(SourceValue::Text("XmlBare".to_owned())),
            "XmlBare" => Ok(SourceValue::Text("XmlQuoted".to_owned())),
            other => Err(format!("source `{path}` renders an entity tag as `{other}`, which has no known opposite")),
        },
        MutationDimension::TimeFormat => time_format_alternative(value, path),
        MutationDimension::EmptyElementRender => match value {
            "Emit" => Ok(SourceValue::Text("Omit".to_owned())),
            "Omit" => Ok(SourceValue::Text("Emit".to_owned())),
            other => Err(format!(
                "source `{path}` renders an empty value as `{other}`, which has no known opposite"
            )),
        },
        other => Err(format!(
            "source `{path}` is a string and dimension `{}` has no planned string mutation",
            other.as_str()
        )),
    }
}

fn time_format_alternative(value: &str, path: &str) -> std::result::Result<SourceValue, String> {
    let current = TimestampFormat::parse(value)
        .ok_or_else(|| format!("source `{path}` names timestamp format `{value}`, which the IR does not define"))?;
    // HTTP date and extended ISO 8601 are the two renderings S3 actually puts on the wire, so each
    // is the other's mutation. The remaining two are reachable only from the signing surface.
    let mutant = match current {
        TimestampFormat::HttpDate => TimestampFormat::Iso8601,
        TimestampFormat::Iso8601 => TimestampFormat::HttpDate,
        TimestampFormat::Iso8601Basic => TimestampFormat::Iso8601,
        TimestampFormat::EpochSeconds => TimestampFormat::HttpDate,
    };
    Ok(SourceValue::Text(mutant.as_str().to_owned()))
}

/// Reads `model/overlays/quirks/` and returns quirk id to overlay family name.
///
/// The family is the overlay file that declares the record: `lifecycle.toml` declares the
/// `lifecycle` family. The mapping is not carried in `spec/quirks/*.toml` because the family is a
/// property of where the fact is written down, not of the fact.
///
/// # Errors
///
/// Returns an error when the directory cannot be read or a file is not parseable TOML.
pub fn quirk_families(overlays: &Path) -> Result<BTreeMap<String, String>> {
    let dir = overlays.join("quirks");
    let mut families = BTreeMap::new();
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|source| io(&dir, source))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();
    for path in paths {
        let family = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| Error::Policy(format!("quirk overlay `{}` has no readable name", path.display())))?
            .to_owned();
        let text = std::fs::read_to_string(&path).map_err(|source| io(&path, source))?;
        let doc = toml_lite::parse(&path.display().to_string(), &text).map_err(Error::Model)?;
        let Some(Toml::Array(records)) = doc.get("quirk") else {
            continue;
        };
        for record in records {
            let Some(id) = record.get("id").and_then(Toml::as_str) else {
                continue;
            };
            if let Some(previous) = families.insert(id.to_owned(), family.clone()) {
                return Err(Error::Policy(format!("quirk `{id}` is declared by both `{previous}` and `{family}`")));
            }
        }
    }
    Ok(families)
}
