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

//! POST-policy document shape and condition operators.
//!
//! Responsible for: parsing the three condition forms, with optional ASCII operator case folding.
//! Not responsible for: signature comparison, expiry, field values, or multipart framing.
//! Upstream: the bounded JSON reader. Downstream: the POST-policy field enforcer.

use super::PostPolicyError;
use crate::post_policy_json::JsonValue;

pub(super) enum Condition {
    Exact(String, String),
    StartsWith(String, String),
    ContentLengthRange(u64, u64),
}

pub(super) fn parse_policy(root: JsonValue, ascii_case_insensitive: bool) -> Result<(String, Vec<Condition>), PostPolicyError> {
    let JsonValue::Object(mut members) = root else {
        return Err(PostPolicyError::Malformed);
    };
    if members.len() != 2 {
        return Err(PostPolicyError::Malformed);
    }
    let expiration = take_member(&mut members, "expiration")?.into_string()?;
    let conditions = take_member(&mut members, "conditions")?.into_array()?;
    let parsed = conditions
        .into_iter()
        .map(|value| parse_condition(value, ascii_case_insensitive))
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        return Err(PostPolicyError::Malformed);
    }
    Ok((expiration, parsed))
}

fn take_member(members: &mut Vec<(String, JsonValue)>, name: &str) -> Result<JsonValue, PostPolicyError> {
    let index = members
        .iter()
        .position(|(key, _)| key == name)
        .ok_or(PostPolicyError::Malformed)?;
    Ok(members.swap_remove(index).1)
}

fn parse_condition(value: JsonValue, ascii_case_insensitive: bool) -> Result<Condition, PostPolicyError> {
    match value {
        JsonValue::Object(mut members) if members.len() == 1 => {
            let (name, value) = members.pop().ok_or(PostPolicyError::Malformed)?;
            Ok(Condition::Exact(normalize_condition_name(&name)?, value.into_string()?))
        }
        JsonValue::Array(values) if values.len() == 3 => {
            let mut values = values.into_iter();
            let mut operator = values.next().ok_or(PostPolicyError::Malformed)?.into_string()?;
            let second = values.next().ok_or(PostPolicyError::Malformed)?;
            let third = values.next().ok_or(PostPolicyError::Malformed)?;
            if ascii_case_insensitive {
                operator.make_ascii_lowercase();
            }
            match operator.as_str() {
                "eq" => Ok(Condition::Exact(normalize_variable(second.into_string()?)?, third.into_string()?)),
                "starts-with" => Ok(Condition::StartsWith(normalize_variable(second.into_string()?)?, third.into_string()?)),
                "content-length-range" => Ok(Condition::ContentLengthRange(second.into_u64()?, third.into_u64()?)),
                _ => Err(PostPolicyError::Malformed),
            }
        }
        _ => Err(PostPolicyError::Malformed),
    }
}

fn normalize_variable(value: String) -> Result<String, PostPolicyError> {
    normalize_condition_name(value.strip_prefix('$').ok_or(PostPolicyError::Malformed)?)
}

fn normalize_condition_name(name: &str) -> Result<String, PostPolicyError> {
    if name.is_empty() || !name.is_ascii() || name.eq_ignore_ascii_case("file") {
        return Err(PostPolicyError::Malformed);
    }
    Ok(name.to_ascii_lowercase())
}
