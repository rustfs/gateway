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

//! A bucket policy read and evaluated the way RustFS reads and evaluates one.
//!
//! Responsible for: parsing a stored policy document into statements, the statement validity rules
//! RustFS's `BucketPolicy::is_valid` applies at `PutBucketPolicy`, and the evaluation order of its
//! `BucketPolicy::is_allowed` — every `Deny` first, then the owner unconditionally, then any `Allow`.
//! NOT responsible for: the document's syntax, size and depth (the shared `validate_policy`
//! contract answers those first), for storing the document (`super`), or for deciding *which*
//! request is being evaluated (`compat-sut`'s authorizer and the policy-status read build one).
//! Upstream: `serde_json`. Downstream: `super` and `compat-sut`.
//!
//! # What is and is not evaluated, and why it is written down
//!
//! RustFS's evaluator is MinIO's: principal, action, resource and a condition language of some
//! forty keys. This one matches principal, action and resource with the same `*`/`?` wildcards,
//! and evaluates `StringEquals` on `s3:x-amz-acl`: exact case-sensitive values, a string or
//! an OR-list of strings, and no match when the request header is absent. Any condition block
//! containing another key or operator remains unsupported as a whole and neither grants nor
//! denies. That preserves the existing limitation: unsupported Allow is fail-closed, unsupported
//! Deny is fail-open. This is not a complete IAM condition evaluator or validator.
//! The key spelling is deliberately canonical: RustFS passes condition-map keys directly through
//! `Key::try_from` to its exact `S3KeyName` parser, rather than applying AWS's case-insensitive rule.
//! Evidence: <https://github.com/rustfs/rustfs/blob/c95b4f08200c789168eb0e8ec4693f73012aeb1c/crates/policy/src/policy/function/key.rs>.
//! Other unsupported spellings and blocks remain stored but unevaluated here; this does not claim
//! RustFS's complete policy-validation behavior.
//!
//! Principals are matched as RustFS matches them: `*` (or `{"AWS": "*"}`) is everyone, and any
//! other `AWS` entry is compared as a whole against the caller's account name. Anonymous callers
//! have no account and match only `*`.

use std::fmt;

use serde_json::Value;

/// A parsed bucket policy: its statements, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketPolicy {
    statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Statement {
    allow: bool,
    /// `None` is `*`: every principal, anonymous included.
    principals: Option<Vec<String>>,
    actions: Vec<String>,
    not_actions: Vec<String>,
    resources: Vec<String>,
    not_resources: Vec<String>,
    condition: Condition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    None,
    AclEquals(Vec<String>),
    Unsupported,
}

impl Condition {
    fn parse(value: Option<&Value>) -> Self {
        let Some(value) = value else { return Self::None };
        let Some(operators) = value.as_object() else { return Self::Unsupported };
        if operators.is_empty() {
            return Self::None;
        }
        if operators.len() != 1 {
            return Self::Unsupported;
        }
        let Some(keys) = operators.get("StringEquals").and_then(Value::as_object) else {
            return Self::Unsupported;
        };
        if keys.len() != 1 {
            return Self::Unsupported;
        }
        let Some(value) = keys.get("s3:x-amz-acl") else {
            return Self::Unsupported;
        };
        match strings(Some(value)) {
            Ok(values) if !values.is_empty() => Self::AclEquals(values),
            _ => Self::Unsupported,
        }
    }

    fn matches(&self, acl: Option<&str>) -> bool {
        match self {
            Self::None => true,
            Self::AclEquals(values) => acl.is_some_and(|acl| values.iter().any(|value| value == acl)),
            Self::Unsupported => false,
        }
    }
}

/// Why a syntactically valid JSON object is not a bucket policy RustFS would store.
///
/// Each is `MalformedPolicy` on the wire, as RustFS answers every `is_valid` failure; the variant
/// names the rule for the log and the test, never for the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyShapeError {
    /// `Version` is present and is not `2012-10-17`.
    Version,
    /// `Statement` is missing or is not an array of objects.
    Statements,
    /// `Effect` is neither `Allow` nor `Deny`.
    Effect,
    /// `Principal` is missing, or is not `*`, `{"AWS": ...}` with strings, or a list of strings.
    Principal,
    /// Neither `Action` nor `NotAction`, or both.
    Action,
    /// Neither `Resource` nor `NotResource`, or both.
    Resource,
    /// A member that must be a string or a list of strings is something else.
    Member,
}

impl fmt::Display for PolicyShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "the policy Version is not 2012-10-17",
            Self::Statements => "the policy has no Statement array",
            Self::Effect => "a statement's Effect is neither Allow nor Deny",
            Self::Principal => "a statement names no principal",
            Self::Action => "a statement must name exactly one of Action and NotAction",
            Self::Resource => "a statement must name exactly one of Resource and NotResource",
            Self::Member => "a statement member is not a string or a list of strings",
        })
    }
}

/// What one request asks of the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRequest<'a> {
    /// The caller's account name, `None` for an anonymous request.
    pub account: Option<&'a str>,
    /// Whether the caller owns the bucket. A `Deny` still applies to the owner; nothing else does.
    pub is_owner: bool,
    /// The IAM action in its wire spelling, `s3:GetObject`.
    pub action: &'a str,
    /// The bucket the request addresses.
    pub bucket: &'a str,
    /// The object key, when the action is about one.
    pub key: Option<&'a str>,
}

impl BucketPolicy {
    /// Parses a document the shared `validate_policy` already accepted as a JSON object.
    ///
    /// # Errors
    ///
    /// [`PolicyShapeError`] for the first statement rule the document breaks, in RustFS's order.
    pub fn parse(document: &str) -> Result<Self, PolicyShapeError> {
        let root: Value = serde_json::from_str(document).map_err(|_| PolicyShapeError::Statements)?;
        let object = root.as_object().ok_or(PolicyShapeError::Statements)?;
        if let Some(version) = object.get("Version")
            && version.as_str().is_none_or(|text| !text.is_empty() && text != "2012-10-17")
        {
            return Err(PolicyShapeError::Version);
        }
        let statements = match object.get("Statement") {
            Some(Value::Array(items)) => items,
            Some(Value::Object(_)) => std::slice::from_ref(object.get("Statement").ok_or(PolicyShapeError::Statements)?),
            _ => return Err(PolicyShapeError::Statements),
        };
        let statements = statements.iter().map(Statement::parse).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { statements })
    }

    /// RustFS's verdict: any matching `Deny` refuses; the owner is otherwise allowed; anyone else
    /// needs a matching `Allow`.
    #[must_use]
    pub fn allows(&self, request: PolicyRequest<'_>) -> bool {
        self.allows_with_acl(request, None)
    }

    /// Evaluates the request with its supplied `x-amz-acl` header.
    ///
    /// Only `StringEquals` on `s3:x-amz-acl` is supported: values match exactly and case
    /// sensitively, a string array matches any member, and `None` never matches. Condition
    /// keys use RustFS's canonical spelling. A block containing any other key or operator remains
    /// unsupported as a whole. This does not store or enforce ACL grants.
    #[must_use]
    pub fn allows_with_acl(&self, request: PolicyRequest<'_>, acl: Option<&str>) -> bool {
        if self
            .statements
            .iter()
            .any(|statement| !statement.allow && statement.matches(request, acl))
        {
            return false;
        }
        if request.is_owner {
            return true;
        }
        self.statements
            .iter()
            .any(|statement| statement.allow && statement.matches(request, acl))
    }

    /// Whether any `Allow` statement names every principal, RustFS's test for a policy the
    /// public-access block may refuse to store.
    #[must_use]
    pub fn grants_everyone(&self) -> bool {
        self.statements
            .iter()
            .any(|statement| statement.allow && statement.principals.is_none())
    }
}

impl Statement {
    fn parse(value: &Value) -> Result<Self, PolicyShapeError> {
        let object = value.as_object().ok_or(PolicyShapeError::Statements)?;
        let allow = match object.get("Effect").and_then(Value::as_str) {
            Some("Allow") => true,
            Some("Deny") => false,
            _ => return Err(PolicyShapeError::Effect),
        };
        let principals = principals(object.get("Principal").ok_or(PolicyShapeError::Principal)?)?;
        let actions = strings(object.get("Action"))?;
        let not_actions = strings(object.get("NotAction"))?;
        if actions.is_empty() == not_actions.is_empty() {
            return Err(PolicyShapeError::Action);
        }
        let resources = strings(object.get("Resource"))?;
        let not_resources = strings(object.get("NotResource"))?;
        if resources.is_empty() == not_resources.is_empty() {
            return Err(PolicyShapeError::Resource);
        }
        let condition = Condition::parse(object.get("Condition"));
        Ok(Self {
            allow,
            principals,
            actions,
            not_actions,
            resources,
            not_resources,
            condition,
        })
    }

    fn matches(&self, request: PolicyRequest<'_>, acl: Option<&str>) -> bool {
        if !self.condition.matches(acl) {
            return false;
        }
        let principal_matches = match (&self.principals, request.account) {
            (None, _) => true,
            (Some(named), Some(account)) => named.iter().any(|principal| principal == account),
            (Some(_), None) => false,
        };
        if !principal_matches {
            return false;
        }
        let action_matches = if self.actions.is_empty() {
            !self.not_actions.iter().any(|pattern| glob(pattern, request.action))
        } else {
            self.actions.iter().any(|pattern| glob(pattern, request.action))
        };
        if !action_matches {
            return false;
        }
        let resource = match request.key {
            Some(key) => format!("arn:aws:s3:::{}/{key}", request.bucket),
            None => format!("arn:aws:s3:::{}", request.bucket),
        };
        if self.resources.is_empty() {
            !self.not_resources.iter().any(|pattern| glob(pattern, &resource))
        } else {
            self.resources.iter().any(|pattern| glob(pattern, &resource))
        }
    }
}

/// `*` is everyone (`None`); otherwise the `AWS` entries, or a bare list, as account names.
fn principals(value: &Value) -> Result<Option<Vec<String>>, PolicyShapeError> {
    match value {
        Value::String(star) if star == "*" => Ok(None),
        Value::Object(map) => match map.get("AWS") {
            Some(Value::String(star)) if star == "*" => Ok(None),
            Some(aws) => {
                let named = strings(Some(aws)).map_err(|_| PolicyShapeError::Principal)?;
                if named.is_empty() {
                    return Err(PolicyShapeError::Principal);
                }
                Ok(if named.iter().any(|name| name == "*") {
                    None
                } else {
                    Some(named)
                })
            }
            None => Err(PolicyShapeError::Principal),
        },
        _ => Err(PolicyShapeError::Principal),
    }
}

/// A member that is one string or a list of strings; absent is empty.
fn strings(value: Option<&Value>) -> Result<Vec<String>, PolicyShapeError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(one)) => Ok(vec![one.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(PolicyShapeError::Member))
            .collect(),
        Some(_) => Err(PolicyShapeError::Member),
    }
}

/// MinIO's wildcard match: `*` any run, `?` any one character, everything else literal.
fn glob(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    // Iterative two-pointer matching with one backtrack point: linear in the text, no recursion.
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(&literal) if literal == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod tests;
