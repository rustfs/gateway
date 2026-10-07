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

//! Planning one mutation of a mutable quirk's lowered-IR or runtime-contract source.
//!
//! Responsible for: choosing the single alternative value a mutation dimension admits, and
//! grouping quirk ids by the overlay family file that declares them.
//! NOT responsible for: regenerating, building, or judging whether a case caught the mutation —
//! the command in `xtask` owns the loop.
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
pub mod default_document;

use std::collections::BTreeMap;
use std::path::Path;

use rustfs_gateway_model::ir::{EmptyValue, TimestampFormat};
use rustfs_gateway_model::toml_lite::{self, Toml};
use rustfs_gateway_model::{
    AllUnknownChildrenValue, BooleanSpellingValue, CodecRule, CodecValue, ContractRule, ContractValue, HeaderToleranceValue,
    MutationDimension, UnknownElementPolicyValue, UploadIdCapabilityScopeValue,
};

use crate::emit::quirk_toml::{ResolvedSource, SourceValue};
use crate::{Error, Result, io};

/// One planned flip of one typed mutation source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    /// The quirk whose rule this source carries.
    pub quirk: String,
    /// The lowered-IR path, or an `@contract.` / `@codec.` path for a typed overlay input.
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

/// The declared error code written where a rule's whole content is that the operation owes *no*
/// operation-specific not-configured error.
///
/// A rule spelled as an absence still has a violation: the claim is "there is no 404 here", so any
/// code at all contradicts it and there is nothing to choose between them on protocol grounds. The
/// choice is made on two mechanical grounds instead. It has to be a code
/// `model/overlays/error-status.toml` declares, because `OperationSpec::standard` refuses at
/// const-evaluation time a lowered code the authority does not carry — a constant that drifted out
/// of that table would turn every one of these rows into a compile kill, which reads exactly like
/// the compiler catching the mutation. And it names a subresource that is not the one under
/// mutation in any of them, so a reviewer reading `NoSuchLifecycleConfiguration` on a bucket ACL
/// read knows immediately that it came from here and not from the overlay.
pub const ABSENT_NOT_CONFIGURED_MUTANT: &str = "NoSuchLifecycleConfiguration";

/// The lowered-IR path suffix whose absence is itself the rule.
const NOT_CONFIGURED_SUFFIX: &str = ".errors.not_configured";

/// The field property a required structure's optionality mutation is written to; see [`plan`].
pub const DEFAULT_DOCUMENT_PROPERTY: &str = "default_document";

/// Prefix for a mutation that targets a typed runtime contract instead of lowered operation IR.
const CONTRACT_PATH_PREFIX: &str = "@contract.";

/// Prefix for a mutation that targets a typed codec input instead of lowered operation IR.
const CODEC_PATH_PREFIX: &str = "@codec.";

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
///
/// # A required structure is violated by defaulting it, not by making it optional
///
/// The mechanical opposite of `required = true` is `required = false`, and for a structure member
/// that opposite is ill-formed as a *measurement*: the dto member turns from `T` into `Option<T>`,
/// so the conformance fixture, the persistence bridge and every shared validator that reads the
/// member bare stop compiling, and the row reads `KILLED_BY_COMPILE` without a case ever running
/// (`q-lock-0007`, `q-restore-0006`, `q-web-0004`; rustfs/backlog#1726). What those rules refuse
/// on the wire is not "the member is typed as optional" but "an absent document is read as a
/// defaulted one", which is the upstream defect they cite. So a required structure is planned onto
/// the sibling `default_document` property instead: the member keeps its type and only the
/// decoder's answer to absence changes. Every other `required` source keeps the boolean flip.
pub fn plan(quirk: &str, dimension: MutationDimension, source: &ResolvedSource) -> std::result::Result<Mutation, String> {
    if dimension == MutationDimension::Optionality
        && source.request_structure
        && source.current == SourceValue::Bool(true)
        && let Some(member) = source.path.strip_suffix(".required")
    {
        return Mutation::new(
            quirk,
            &format!("{member}.{DEFAULT_DOCUMENT_PROPERTY}"),
            SourceValue::Bool(false),
            SourceValue::Bool(true),
        );
    }
    let to = alternative(dimension, &source.current, &source.path)?;
    Mutation::new(quirk, &source.path, source.current.clone(), to)
}

/// Plans the boolean flip for one typed runtime contract.
///
/// # Errors
///
/// Returns the reason when the contract has no reviewed mechanical opposite.
pub fn plan_contract(quirk: &str, rule: &ContractRule) -> std::result::Result<Mutation, String> {
    let current = contract_source(&rule.current, rule.mutation_dimension)?;
    let to = alternative(rule.mutation_dimension, &current, &format!("{CONTRACT_PATH_PREFIX}{quirk}"))?;
    Mutation::new(quirk, &format!("{CONTRACT_PATH_PREFIX}{quirk}"), current, to)
}

/// Plans the mechanical opposite of one typed codec input.
///
/// # Errors
///
/// Returns the reason when the value and dimension disagree or the replacement would not differ.
pub fn plan_codec(quirk: &str, rule: &CodecRule) -> std::result::Result<Mutation, String> {
    let (path, from, to, expected_dimension) = match &rule.current {
        CodecValue::IntegerRange { min, max } => (
            format!("{CODEC_PATH_PREFIX}{quirk}"),
            SourceValue::OptionalText(Some(format!("{min}..={max}"))),
            SourceValue::OptionalText(None),
            MutationDimension::IntegerRange,
        ),
        CodecValue::NonEmptyText(value) => (
            format!("{CODEC_PATH_PREFIX}{quirk}"),
            SourceValue::Bool(*value),
            SourceValue::Bool(!value),
            MutationDimension::MemberConstraint,
        ),
        CodecValue::MediaType(value) => {
            let alternative = if value == "text/plain" {
                "application/octet-stream"
            } else {
                "text/plain"
            };
            (
                format!("{CODEC_PATH_PREFIX}{quirk}"),
                SourceValue::Text(value.clone()),
                SourceValue::Text(alternative.to_owned()),
                MutationDimension::MediaType,
            )
        }
        CodecValue::HeaderTolerance(HeaderToleranceValue::DateCondition) => (
            format!("{CODEC_PATH_PREFIX}{quirk}"),
            SourceValue::OptionalText(Some("date_condition".to_owned())),
            SourceValue::OptionalText(None),
            MutationDimension::HeaderTolerance,
        ),
        CodecValue::UnknownElementPolicy(value) => {
            let from = unknown_element_policy_source(*value);
            let to = unknown_element_policy_source(match value {
                UnknownElementPolicyValue::Skip => UnknownElementPolicyValue::Reject,
                UnknownElementPolicyValue::Reject => UnknownElementPolicyValue::Skip,
            });
            (format!("{CODEC_PATH_PREFIX}{quirk}"), from, to, MutationDimension::UnknownElementPolicy)
        }
        CodecValue::AllUnknownChildren(value) => {
            let from = all_unknown_children_source(*value);
            let to = all_unknown_children_source(match value {
                AllUnknownChildrenValue::Allow => AllUnknownChildrenValue::Reject,
                AllUnknownChildrenValue::Reject => AllUnknownChildrenValue::Allow,
            });
            (format!("{CODEC_PATH_PREFIX}{quirk}"), from, to, MutationDimension::AllUnknownChildren)
        }
        CodecValue::BooleanSpelling(value) => {
            let from = boolean_spelling_source(*value);
            let to = boolean_spelling_source(match value {
                BooleanSpellingValue::AsciiCaseInsensitive => BooleanSpellingValue::LowercaseOnly,
                BooleanSpellingValue::LowercaseOnly => BooleanSpellingValue::AsciiCaseInsensitive,
            });
            (format!("{CODEC_PATH_PREFIX}{quirk}"), from, to, MutationDimension::BooleanSpellingPolicy)
        }
    };
    if rule.mutation_dimension != expected_dimension {
        return Err(format!(
            "codec rule `{quirk}` carries `{}` but declares mutation dimension `{}`",
            codec_kind(&rule.current),
            rule.mutation_dimension.as_str()
        ));
    }
    Mutation::new(quirk, &path, from, to)
}

/// Applies a typed codec mutation, returning whether the path named that namespace.
///
/// # Errors
///
/// Returns the reason when the id is stale, the current value changed, or the replacement has the
/// wrong value shape.
pub(crate) fn apply_codec(rules: &mut BTreeMap<String, CodecRule>, mutation: &Mutation) -> std::result::Result<bool, String> {
    let Some(id) = mutation.path.strip_prefix(CODEC_PATH_PREFIX) else {
        return Ok(false);
    };
    if id != mutation.quirk {
        return Err(format!(
            "codec path `{}` names `{id}`, but the mutation belongs to `{}`",
            mutation.path, mutation.quirk
        ));
    }
    let rule = rules
        .get(id)
        .ok_or_else(|| format!("codec mutation names unknown rule `{id}`"))?;
    let found = codec_source(&rule.current);
    if found != mutation.from {
        return Err(format!(
            "codec rule `{id}` carries {found:?}, but the mutation plan replaces {:?}; the ledger and generated input disagree",
            mutation.from
        ));
    }

    if mutation.to == SourceValue::OptionalText(None) {
        rules.remove(id);
        return Ok(true);
    }

    let rule = rules
        .get_mut(id)
        .ok_or_else(|| format!("codec mutation names unknown rule `{id}`"))?;
    write_codec_value(&mut rule.current, &mutation.to)?;
    let written = codec_source(&rule.current);
    if written != mutation.to {
        return Err(format!("codec rule `{id}` does not read back as {:?}; found {written:?}", mutation.to));
    }
    Ok(true)
}

fn codec_source(value: &CodecValue) -> SourceValue {
    match value {
        CodecValue::IntegerRange { min, max } => SourceValue::OptionalText(Some(format!("{min}..={max}"))),
        CodecValue::NonEmptyText(value) => SourceValue::Bool(*value),
        CodecValue::MediaType(value) => SourceValue::Text(value.clone()),
        CodecValue::HeaderTolerance(HeaderToleranceValue::DateCondition) => {
            SourceValue::OptionalText(Some("date_condition".to_owned()))
        }
        CodecValue::UnknownElementPolicy(value) => unknown_element_policy_source(*value),
        CodecValue::AllUnknownChildren(value) => all_unknown_children_source(*value),
        CodecValue::BooleanSpelling(value) => boolean_spelling_source(*value),
    }
}

fn write_codec_value(current: &mut CodecValue, replacement: &SourceValue) -> std::result::Result<(), String> {
    match (current, replacement) {
        (CodecValue::NonEmptyText(value), SourceValue::Bool(replacement)) => *value = *replacement,
        (CodecValue::MediaType(value), SourceValue::Text(replacement)) => replacement.clone_into(value),
        (CodecValue::UnknownElementPolicy(value), SourceValue::Text(replacement)) => {
            *value = parse_unknown_element_policy(replacement)?;
        }
        (CodecValue::AllUnknownChildren(value), SourceValue::Text(replacement)) => {
            *value = parse_all_unknown_children(replacement)?;
        }
        (CodecValue::BooleanSpelling(value), SourceValue::Text(replacement)) => {
            *value = parse_boolean_spelling(replacement)?;
        }
        _ => return Err("codec mutation replacement has the wrong value shape".to_owned()),
    }
    Ok(())
}

fn unknown_element_policy_source(value: UnknownElementPolicyValue) -> SourceValue {
    SourceValue::Text(
        match value {
            UnknownElementPolicyValue::Skip => "skip",
            UnknownElementPolicyValue::Reject => "reject",
        }
        .to_owned(),
    )
}

fn parse_unknown_element_policy(value: &str) -> std::result::Result<UnknownElementPolicyValue, String> {
    match value {
        "skip" => Ok(UnknownElementPolicyValue::Skip),
        "reject" => Ok(UnknownElementPolicyValue::Reject),
        _ => Err(format!("unknown codec element policy `{value}`")),
    }
}

fn all_unknown_children_source(value: AllUnknownChildrenValue) -> SourceValue {
    SourceValue::Text(
        match value {
            AllUnknownChildrenValue::Allow => "allow",
            AllUnknownChildrenValue::Reject => "reject",
        }
        .to_owned(),
    )
}

fn parse_all_unknown_children(value: &str) -> std::result::Result<AllUnknownChildrenValue, String> {
    match value {
        "allow" => Ok(AllUnknownChildrenValue::Allow),
        "reject" => Ok(AllUnknownChildrenValue::Reject),
        _ => Err(format!("unknown codec all-unknown-children policy `{value}`")),
    }
}

fn boolean_spelling_source(value: BooleanSpellingValue) -> SourceValue {
    SourceValue::Text(
        match value {
            BooleanSpellingValue::AsciiCaseInsensitive => "ascii_case_insensitive",
            BooleanSpellingValue::LowercaseOnly => "lowercase_only",
        }
        .to_owned(),
    )
}

fn parse_boolean_spelling(value: &str) -> std::result::Result<BooleanSpellingValue, String> {
    match value {
        "ascii_case_insensitive" => Ok(BooleanSpellingValue::AsciiCaseInsensitive),
        "lowercase_only" => Ok(BooleanSpellingValue::LowercaseOnly),
        _ => Err(format!("unknown codec boolean spelling `{value}`")),
    }
}

fn codec_kind(value: &CodecValue) -> &'static str {
    match value {
        CodecValue::IntegerRange { .. } => "integer_range",
        CodecValue::NonEmptyText(_) => "member_constraint",
        CodecValue::MediaType(_) => "media_type",
        CodecValue::HeaderTolerance(_) => "header_tolerance",
        CodecValue::UnknownElementPolicy(_) => "unknown_element_policy",
        CodecValue::AllUnknownChildren(_) => "all_unknown_children",
        CodecValue::BooleanSpelling(_) => "boolean_spelling_policy",
    }
}

/// Applies a typed runtime-contract mutation, returning whether the path named that namespace.
///
/// # Errors
///
/// Returns the reason when the id is stale, the current value changed, or the replacement has the
/// wrong value shape.
pub(crate) fn apply_contract(
    rules: &mut BTreeMap<String, ContractRule>,
    mutation: &Mutation,
) -> std::result::Result<bool, String> {
    let Some(id) = mutation.path.strip_prefix(CONTRACT_PATH_PREFIX) else {
        return Ok(false);
    };
    if id != mutation.quirk {
        return Err(format!(
            "contract path `{}` names `{id}`, but the mutation belongs to `{}`",
            mutation.path, mutation.quirk
        ));
    }
    let rule = rules
        .get_mut(id)
        .ok_or_else(|| format!("contract mutation names unknown rule `{id}`"))?;
    let found = contract_source(&rule.current, rule.mutation_dimension)?;
    if found != mutation.from {
        return Err(format!(
            "contract `{id}` carries {found:?}, but the mutation plan replaces {:?}; the ledger and \
             generated input disagree",
            mutation.from
        ));
    }
    rule.current = contract_value(&mutation.to, rule.mutation_dimension)?;
    let written = contract_source(&rule.current, rule.mutation_dimension)?;
    if written != mutation.to {
        return Err(format!("contract `{id}` does not read back as {:?}; found {written:?}", mutation.to));
    }
    Ok(true)
}

fn contract_source(value: &ContractValue, dimension: MutationDimension) -> std::result::Result<SourceValue, String> {
    match (value, dimension) {
        (ContractValue::SignaturePolicy(value), dimension) if is_signature_policy(dimension) => Ok(SourceValue::Bool(*value)),
        (
            ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::BucketAndKey),
            MutationDimension::UploadIdCapabilityScope,
        ) => Ok(SourceValue::Bool(true)),
        (
            ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::UploadIdOnly),
            MutationDimension::UploadIdCapabilityScope,
        ) => Ok(SourceValue::Bool(false)),
        _ => Err(format!(
            "typed runtime contract `{}` has no matching mechanical mutation writer",
            dimension.as_str()
        )),
    }
}

fn contract_value(value: &SourceValue, dimension: MutationDimension) -> std::result::Result<ContractValue, String> {
    match (value, dimension) {
        (SourceValue::Bool(value), dimension) if is_signature_policy(dimension) => Ok(ContractValue::SignaturePolicy(*value)),
        (SourceValue::Bool(true), MutationDimension::UploadIdCapabilityScope) => {
            Ok(ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::BucketAndKey))
        }
        (SourceValue::Bool(false), MutationDimension::UploadIdCapabilityScope) => {
            Ok(ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::UploadIdOnly))
        }
        _ => Err(format!(
            "typed runtime contract `{}` requires its reviewed boolean replacement",
            dimension.as_str()
        )),
    }
}

fn is_signature_policy(dimension: MutationDimension) -> bool {
    matches!(
        dimension,
        MutationDimension::SignatureCanonicalHostPolicy
            | MutationDimension::SignaturePathFallbackPolicy
            | MutationDimension::SignaturePayloadTokenPolicy
            | MutationDimension::SigV2IncludedQueryPolicy
            | MutationDimension::SigV2DateSlotPolicy
            | MutationDimension::SigV2ExpiresAbsolutePolicy
            | MutationDimension::SigV2QueryCoveragePolicy
    )
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
        // The other direction, for the one source whose absence is a claim rather than a silence.
        SourceValue::OptionalText(None)
            if dimension == MutationDimension::Optionality && path.ends_with(NOT_CONFIGURED_SUFFIX) =>
        {
            Ok(SourceValue::OptionalText(Some(ABSENT_NOT_CONFIGURED_MUTANT.to_owned())))
        }
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
        // Spelled through the IR's own vocabulary rather than by hand: the spellings are lower case,
        // and matching them capitalised made every empty-element rule unplannable while reading like
        // a rule with no opposite.
        MutationDimension::EmptyElementRender => match EmptyValue::parse(value) {
            Some(EmptyValue::Emit) => Ok(SourceValue::Text(EmptyValue::Omit.as_str().to_owned())),
            Some(EmptyValue::Omit) => Ok(SourceValue::Text(EmptyValue::Emit.as_str().to_owned())),
            None => Err(format!(
                "source `{path}` renders an empty value as `{value}`, which the IR does not define"
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
