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

//! Parsers for codec values and lowered-IR mutation sources.
//!
//! Responsible for: turning mutable overlay fields into the closed types declared by
//! [`super::codec`]. NOT responsible for: runtime contracts or classifying a record. Upstream:
//! quirk family TOML. Downstream: the exhaustive quirk loader.

use crate::error::{Error, Result};
use crate::toml_lite::Toml;

use super::MutationDimension;
use super::codec::{
    BooleanSpellingValue, CodecRule, CodecValue, HeaderToleranceValue, SourceRule, UnknownElementPolicyValue, WireFormValue,
};
use super::{opt_str, required_str};

pub(super) fn source_rule(table: &Toml, id: &str) -> Result<Option<SourceRule>> {
    let Some(value) = table.get("mutation_sources") else {
        return Ok(None);
    };
    if ["codec_value", "codec_min", "codec_max"]
        .iter()
        .any(|key| table.get(key).is_some())
    {
        return Err(Error::Overlay(format!("quirk `{id}` mixes IR mutation sources with codec input")));
    }
    let sources = value.string_array(&format!("quirk `{id}` mutation_sources"))?;
    if sources.is_empty() {
        return Err(Error::Overlay(format!("quirk `{id}` has no mutation source")));
    }
    let spelling = required_str(table, "mutation_dimension", &format!("quirk `{id}` source rule"))?;
    let mutation_dimension = match spelling.as_str() {
        "element_order" => MutationDimension::ElementOrder,
        "element_rename" => MutationDimension::ElementRename,
        "attribute_rename" => MutationDimension::AttributeRename,
        "empty_element_render" => MutationDimension::EmptyElementRender,
        "optionality" => MutationDimension::Optionality,
        "quote_strategy" => MutationDimension::QuoteStrategy,
        "wrap_strategy" => MutationDimension::WrapStrategy,
        "element_encoding" => MutationDimension::ElementEncoding,
        "omit_strategy" => MutationDimension::OmitStrategy,
        "default_value" => MutationDimension::DefaultValue,
        "time_format" => MutationDimension::TimeFormat,
        "status_mapping" => MutationDimension::StatusMapping,
        _ => {
            return Err(Error::Overlay(format!(
                "quirk `{id}`: `{spelling}` is not an IR source mutation dimension"
            )));
        }
    };
    Ok(Some(SourceRule {
        mutation_dimension,
        sources,
    }))
}

pub(super) fn codec_rule(table: &Toml, id: &str) -> Result<Option<CodecRule>> {
    let what = format!("quirk `{id}` codec rule");
    if table.get("contract_value").is_some() {
        return Ok(None);
    }
    let has_codec_value = ["codec_value", "codec_min", "codec_max"]
        .iter()
        .any(|key| table.get(key).is_some());
    if table.get("mutation_sources").is_some() {
        return Ok(None);
    }
    let dimension = opt_str(table, "mutation_dimension");
    if !has_codec_value && dimension.is_none() {
        return Ok(None);
    }
    let spelling = dimension.ok_or_else(|| Error::Overlay(format!("{what}: missing `mutation_dimension`")))?;
    let (current, mutation_dimension) = match spelling.as_str() {
        "wire_form" => {
            reject_range_keys(table, &what)?;
            let spelling = required_str(table, "codec_value", &what)?;
            let form = match spelling.as_str() {
                "entity_tag" => WireFormValue::EntityTag,
                "opaque_token" => WireFormValue::OpaqueToken,
                _ => return Err(Error::Overlay(format!("{what}: unknown wire form `{spelling}`"))),
            };
            (CodecValue::WireForm(form), MutationDimension::WireForm)
        }
        "integer_range" => {
            reject_value_key(table, &what)?;
            let min = required_i32(table, "codec_min", &what)?;
            let max = required_i32(table, "codec_max", &what)?;
            if min > max {
                return Err(Error::Overlay(format!("{what}: `codec_min` exceeds `codec_max`")));
            }
            (CodecValue::IntegerRange { min, max }, MutationDimension::IntegerRange)
        }
        "media_type" => {
            reject_range_keys(table, &what)?;
            let media = required_str(table, "codec_value", &what)?;
            if media.is_empty() || !media.contains('/') {
                return Err(Error::Overlay(format!("{what}: `{media}` is not a media type")));
            }
            (CodecValue::MediaType(media), MutationDimension::MediaType)
        }
        "header_tolerance" => {
            reject_range_keys(table, &what)?;
            let spelling = required_str(table, "codec_value", &what)?;
            let tolerance = match spelling.as_str() {
                "date_condition" => HeaderToleranceValue::DateCondition,
                _ => return Err(Error::Overlay(format!("{what}: unknown header tolerance `{spelling}`"))),
            };
            (CodecValue::HeaderTolerance(tolerance), MutationDimension::HeaderTolerance)
        }
        "unknown_element_policy" => {
            reject_range_keys(table, &what)?;
            let spelling = required_str(table, "codec_value", &what)?;
            let policy = match spelling.as_str() {
                "skip" => UnknownElementPolicyValue::Skip,
                "reject" => UnknownElementPolicyValue::Reject,
                _ => return Err(Error::Overlay(format!("{what}: unknown element policy `{spelling}`"))),
            };
            (CodecValue::UnknownElementPolicy(policy), MutationDimension::UnknownElementPolicy)
        }
        "boolean_spelling_policy" => {
            reject_range_keys(table, &what)?;
            let spelling = required_str(table, "codec_value", &what)?;
            let policy = match spelling.as_str() {
                "ascii_case_insensitive" => BooleanSpellingValue::AsciiCaseInsensitive,
                "lowercase_only" => BooleanSpellingValue::LowercaseOnly,
                _ => return Err(Error::Overlay(format!("{what}: unknown boolean spelling `{spelling}`"))),
            };
            (CodecValue::BooleanSpelling(policy), MutationDimension::BooleanSpellingPolicy)
        }
        _ => return Err(Error::Overlay(format!("{what}: unknown mutation dimension `{spelling}`"))),
    };
    Ok(Some(CodecRule {
        current,
        mutation_dimension,
    }))
}

fn reject_range_keys(table: &Toml, what: &str) -> Result<()> {
    if table.get("codec_min").is_some() || table.get("codec_max").is_some() {
        return Err(Error::Overlay(format!("{what}: range keys do not belong to this mutation dimension")));
    }
    Ok(())
}

fn reject_value_key(table: &Toml, what: &str) -> Result<()> {
    if table.get("codec_value").is_some() {
        return Err(Error::Overlay(format!("{what}: `codec_value` does not belong to an integer range")));
    }
    Ok(())
}

fn required_i32(table: &Toml, key: &str, what: &str) -> Result<i32> {
    table
        .get(key)
        .and_then(Toml::as_int)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| Error::Overlay(format!("{what}: missing or out-of-range `{key}`")))
}
