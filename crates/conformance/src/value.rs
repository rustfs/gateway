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

//! The one document model shared by the TOML corpus and the JSON schema.
//!
//! Responsible for: an order-preserving, dependency-free value tree, plus the accessors every
//! other module uses to read a case without re-implementing "is this a table, and does it have
//! this key". Order is preserved because a case file's key order is part of its diagnostics: a
//! violation is reported at the position the author wrote, not at a position a hash map chose.
//! NOT responsible for: parsing (`crate::toml`, `crate::json`), validation (`crate::schema`), or
//! any knowledge of what a conformance case means.
//! Upstream: nothing. Downstream: every other module in this crate.

use core::fmt;

/// A parsed document node.
///
/// Both the TOML corpus and the JSON schema parse into this, which is what lets the frozen
/// `case.schema.json` validate the on-disk TOML directly rather than a hand-written mirror of it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A boolean.
    Bool(bool),
    /// An integer. TOML and JSON integers both land here.
    Integer(i64),
    /// A non-integral number. Present for JSON completeness; the corpus does not use floats.
    Float(f64),
    /// A UTF-8 string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// A table (JSON object), in document order.
    Table(Vec<(String, Value)>),
}

impl Value {
    /// Returns the JSON Schema type name of this value, for diagnostics and `type` checks.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "boolean",
            Value::Integer(_) => "integer",
            Value::Float(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Table(_) => "object",
        }
    }

    /// Returns the value bound to `key`, if this is a table that has it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Table(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Follows a `/`-separated path of table keys.
    #[must_use]
    pub fn path(&self, path: &str) -> Option<&Value> {
        let mut cur = self;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            cur = cur.get(segment)?;
        }
        Some(cur)
    }

    /// Returns the string contents, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the integer contents, if this is an integer.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the boolean contents, if this is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// Returns the entries in document order, if this is a table.
    #[must_use]
    pub fn as_table(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Table(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// Returns the elements of an array of strings, or an empty vector when the key is absent.
    ///
    /// Returns `None` when the value is present but is not an array of strings, so that a caller
    /// can tell "absent" from "wrong shape" — the schema has already rejected the latter, but the
    /// lints run on documents the schema accepted and must not silently ignore a surprise.
    #[must_use]
    pub fn string_array(&self, key: &str) -> Option<Vec<&str>> {
        match self.get(key) {
            None => Some(Vec::new()),
            Some(Value::Array(items)) => items.iter().map(Value::as_str).collect(),
            Some(_) => None,
        }
    }

    /// Inserts or replaces `key` in a table, appending when the key is new.
    ///
    /// Does nothing when this value is not a table.
    pub fn insert(&mut self, key: &str, value: Value) {
        if let Value::Table(entries) = self {
            match entries.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => entries.push((key.to_owned(), value)),
            }
        }
    }

    /// Returns a mutable reference to the value bound to `key`.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Table(entries) => entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// An empty table.
    #[must_use]
    pub fn empty_table() -> Value {
        Value::Table(Vec::new())
    }
}

impl fmt::Display for Value {
    /// Renders a compact, JSON-shaped form. Used only in diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Bool(b) => write!(f, "{b}"),
            Value::Integer(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::String(s) => write!(f, "{s:?}"),
            Value::Array(items) => {
                f.write_str("[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Value::Table(entries) => {
                f.write_str("{")?;
                for (index, (key, item)) in entries.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{key:?}: {item}")?;
                }
                f.write_str("}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        Value::Table(vec![(
            "case".to_owned(),
            Value::Table(vec![
                ("id".to_owned(), Value::String("c-etag-0001".to_owned())),
                ("schema_version".to_owned(), Value::Integer(1)),
            ]),
        )])
    }

    #[test]
    fn path_walks_nested_tables() {
        assert_eq!(sample().path("case/id").and_then(Value::as_str), Some("c-etag-0001"));
    }

    #[test]
    fn path_on_a_missing_key_is_none() {
        assert!(sample().path("case/nope").is_none());
    }

    #[test]
    fn path_through_a_scalar_is_none_rather_than_a_panic() {
        assert!(sample().path("case/id/deeper").is_none());
    }

    #[test]
    fn string_array_absent_is_empty_not_missing() {
        let value = Value::empty_table();
        assert_eq!(value.string_array("tags"), Some(Vec::new()));
    }

    #[test]
    fn string_array_of_wrong_shape_is_reported_as_none() {
        let value = Value::Table(vec![("tags".to_owned(), Value::Integer(3))]);
        assert_eq!(value.string_array("tags"), None);
    }

    #[test]
    fn insert_replaces_rather_than_duplicating() {
        let mut value = Value::empty_table();
        value.insert("a", Value::Integer(1));
        value.insert("a", Value::Integer(2));
        assert_eq!(value.as_table().map(<[(String, Value)]>::len), Some(1));
        assert_eq!(value.get("a").and_then(Value::as_integer), Some(2));
    }
}
