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
use std::fmt;

pub(super) enum Condition {
    Exact(String, String),
    StartsWith(String, String),
    ContentLengthRange(u64, u64),
}

/// The intersection of the key conditions parsed from a POST policy.
///
/// This is not an authorization proof. A host may use it only after the
/// gateway has verified the same form signature and enforced its routed bucket,
/// final upload key, field coverage and file-size conditions.
#[derive(Clone)]
pub struct PostKeyConstraints {
    rules: Vec<KeyRule>,
}

#[derive(Clone)]
enum KeyRule {
    Exact(String),
    StartsWith(String),
}

impl PostKeyConstraints {
    pub(super) fn from_conditions(conditions: &[Condition]) -> Self {
        let rules = conditions
            .iter()
            .filter_map(|condition| match condition {
                Condition::Exact(name, value) if name == "key" => Some(KeyRule::Exact(value.clone())),
                Condition::StartsWith(name, value) if name == "key" => Some(KeyRule::StartsWith(value.clone())),
                _ => None,
            })
            .collect();
        Self { rules }
    }

    /// Whether all recorded key conditions allow `key`.
    ///
    /// A policy without a key condition denies every derived key.
    #[must_use]
    pub fn permits(&self, key: &str) -> bool {
        !self.rules.is_empty()
            && self.rules.iter().all(|rule| match rule {
                KeyRule::Exact(expected) => key == expected,
                KeyRule::StartsWith(prefix) => key.starts_with(prefix),
            })
    }
}

impl fmt::Debug for PostKeyConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostKeyConstraints")
            .field("rule_count", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl super::PostPolicy {
    /// The parsed key conditions, not a signature or final-admission proof.
    #[must_use]
    pub fn key_constraints(&self) -> &PostKeyConstraints {
        &self.key_constraints
    }
}

impl super::SigV2PostPolicy {
    /// The parsed key conditions, not a signature or final-admission proof.
    #[must_use]
    pub fn key_constraints(&self) -> &PostKeyConstraints {
        &self.key_constraints
    }
}

/// How a policy binds the bucket its form is routed to.
///
/// A browser form names its bucket in the URL, and the `bucket` form field is optional: minio-java
/// sends none (rustfs/gateway#756). With the field, the routed bucket must equal it, and the
/// policy's `$bucket` conditions were checked against it at parse time. Without it, those
/// conditions are kept here and checked against the routed bucket. A form bound by neither is
/// refused at parse time, so a signature never authorizes an upload into whichever bucket the URL
/// happens to name.
pub(super) struct BucketBinding {
    pub(super) field: Option<String>,
    pub(super) rules: Vec<BucketRule>,
}

pub(super) enum BucketRule {
    Exact(String),
    StartsWith(String),
}

impl BucketBinding {
    pub(super) fn admits(&self, bucket: &str) -> bool {
        self.field.as_deref().is_none_or(|field| field == bucket)
            && self.rules.iter().all(|rule| match rule {
                BucketRule::Exact(expected) => bucket == expected,
                BucketRule::StartsWith(prefix) => bucket.starts_with(prefix.as_str()),
            })
    }
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
