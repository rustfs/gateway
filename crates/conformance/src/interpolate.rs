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

//! `${capture.<name>}` substitution.
//!
//! Responsible for: replacing capture references in a request before it is signed, so that an
//! interpolated value is covered by the signature, and for refusing every other `${...}` form by
//! name. Substitution is textual and deliberately has no expression language: the schema freeze
//! anticipated that computed values would eventually be wanted, and the cost of inventing a
//! syntax here — before there is a decided one — is a second, undocumented grammar inside a
//! frozen format.
//! NOT responsible for: producing captures (`crate::expect`), or signing.
//! Upstream: nothing. Downstream: `crate::runner`, `crate::lint`.

use std::collections::BTreeMap;

/// Values bound by `expect.capture` or by `setup`, addressable as `${capture.<name>}`.
pub type Captures = BTreeMap<String, String>;

/// A reference that could not be substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpolationError {
    /// `${capture.x}` where `x` was never bound.
    UnknownCapture {
        /// The name that was referenced.
        name: String,
    },
    /// `${...}` in a form other than `capture.<name>`.
    ///
    /// Computed references — a digest of a body, a length, an arithmetic expression — land here.
    /// They are a schema change, not something a runner may invent on the side.
    UnsupportedForm {
        /// The text between the braces.
        expression: String,
    },
    /// A `${` with no closing brace.
    Unterminated,
}

impl core::fmt::Display for InterpolationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InterpolationError::UnknownCapture { name } => write!(
                f,
                "`${{capture.{name}}}` is not bound; a capture must come from `expect.capture` on an \
                 earlier exchange or from `setup`"
            ),
            InterpolationError::UnsupportedForm { expression } => write!(
                f,
                "`${{{expression}}}` is not a capture reference; only `${{capture.<name>}}` exists in \
                 schema version 1, and adding a computed form is a schema change"
            ),
            InterpolationError::Unterminated => f.write_str("a `${` was never closed"),
        }
    }
}

impl std::error::Error for InterpolationError {}

/// Substitutes every `${capture.<name>}` in `text`.
///
/// # Errors
///
/// Returns [`InterpolationError`] for an unbound capture, an unterminated reference, or any
/// non-capture `${...}` form.
pub fn interpolate(text: &str, captures: &Captures) -> Result<String, InterpolationError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("${") {
        out.push_str(&rest[..position]);
        let after = &rest[position + 2..];
        let Some(end) = after.find('}') else {
            return Err(InterpolationError::Unterminated);
        };
        let expression = &after[..end];
        let Some(name) = expression.strip_prefix("capture.") else {
            return Err(InterpolationError::UnsupportedForm {
                expression: expression.to_owned(),
            });
        };
        let Some(value) = captures.get(name) else {
            return Err(InterpolationError::UnknownCapture { name: name.to_owned() });
        };
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Lists the capture names referenced by `text`, without needing them to be bound.
///
/// Used by the corpus lints to check that every reference has a producer before anything runs.
#[must_use]
pub fn referenced_captures(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find("${") {
        let after = &rest[position + 2..];
        let Some(end) = after.find('}') else { break };
        if let Some(name) = after[..end].strip_prefix("capture.") {
            names.push(name.to_owned());
        }
        rest = &after[end + 1..];
    }
    names
}

/// Lists the `${...}` expressions in `text` that are not capture references.
#[must_use]
pub fn unsupported_forms(text: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find("${") {
        let after = &rest[position + 2..];
        let Some(end) = after.find('}') else { break };
        let expression = &after[..end];
        if !expression.starts_with("capture.") {
            forms.push(expression.to_owned());
        }
        rest = &after[end + 1..];
    }
    forms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captures() -> Captures {
        let mut map = Captures::new();
        map.insert("next_token".to_owned(), "opaque-token".to_owned());
        map
    }

    #[test]
    fn a_bound_capture_is_substituted_in_place() {
        let result = interpolate("/b?continuation-token=${capture.next_token}&x=1", &captures());
        assert_eq!(result, Ok("/b?continuation-token=opaque-token&x=1".to_owned()));
    }

    #[test]
    fn text_without_a_reference_is_returned_unchanged() {
        assert_eq!(interpolate("/b/k", &captures()), Ok("/b/k".to_owned()));
    }

    #[test]
    fn an_unbound_capture_is_an_error_not_an_empty_string() {
        let error = interpolate("${capture.upload_id}", &captures()).expect_err("must fail");
        assert_eq!(
            error,
            InterpolationError::UnknownCapture {
                name: "upload_id".to_owned()
            }
        );
    }

    #[test]
    fn a_computed_form_is_refused_rather_than_guessed() {
        let error = interpolate("${md5(body)}", &captures()).expect_err("must fail");
        assert_eq!(
            error,
            InterpolationError::UnsupportedForm {
                expression: "md5(body)".to_owned()
            }
        );
    }

    #[test]
    fn an_unterminated_reference_is_refused() {
        assert_eq!(interpolate("${capture.x", &captures()), Err(InterpolationError::Unterminated));
    }

    #[test]
    fn references_are_listed_without_being_bound() {
        assert_eq!(referenced_captures("${capture.a}/${capture.b}"), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn unsupported_forms_are_listed_separately() {
        assert_eq!(unsupported_forms("${capture.a}${sha256(body)}"), vec!["sha256(body)".to_owned()]);
    }
}
