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

//! The TOML reader for `conformance/cases/**/*.toml`.
//!
//! Responsible for: the TOML 1.0 subset the frozen case schema can express — tables, arrays of
//! tables, inline tables, arrays, integers, booleans, and all four string forms. Bare datetimes
//! are deliberately rejected: the schema requires instants to be quoted strings so that a case and
//! its JSON projection are the same value, and accepting a bare datetime here would let that
//! requirement rot silently.
//! NOT responsible for: emitting TOML, or knowing anything about conformance cases.
//! Upstream: `crate::value`. Downstream: `crate::corpus`.

use crate::value::Value;
use core::fmt;

/// A TOML syntax error, located at the line the reader gave up on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlError {
    /// One-based line number.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for TomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for TomlError {}

/// Parses a complete TOML document into a [`Value::Table`].
///
/// # Errors
///
/// Returns [`TomlError`] on any syntax error, on a duplicate key, and on a bare datetime.
pub fn parse(input: &str) -> Result<Value, TomlError> {
    let mut parser = Parser {
        chars: input.chars().collect(),
        pos: 0,
        line: 1,
    };
    parser.document()
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    line: usize,
}

impl Parser {
    fn err<T>(&self, message: impl Into<String>) -> Result<T, TomlError> {
        Err(TomlError {
            line: self.line,
            message: message.into(),
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        if ch == '\n' {
            self.line += 1;
        }
        Some(ch)
    }

    fn starts_with(&self, text: &str) -> bool {
        text.chars().enumerate().all(|(index, ch)| self.peek_at(index) == Some(ch))
    }

    fn skip_inline_space(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.pos += 1;
        }
    }

    /// Skips whitespace, newlines and comments — everything that carries no value.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r' | '\n') => {
                    self.bump();
                }
                Some('#') => {
                    while !matches!(self.peek(), None | Some('\n')) {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// Consumes the rest of a line, allowing only a comment.
    fn end_of_line(&mut self) -> Result<(), TomlError> {
        self.skip_inline_space();
        if self.peek() == Some('#') {
            while !matches!(self.peek(), None | Some('\n')) {
                self.pos += 1;
            }
        }
        match self.peek() {
            None => Ok(()),
            Some('\n' | '\r') => {
                self.bump();
                Ok(())
            }
            Some(ch) => self.err(format!("unexpected `{ch}` after a value; expected end of line")),
        }
    }

    fn document(&mut self) -> Result<Value, TomlError> {
        let mut root = Value::empty_table();
        let mut current: Vec<String> = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek().is_none() {
                return Ok(root);
            }
            if self.peek() == Some('[') {
                current = self.table_header(&mut root)?;
                continue;
            }
            let keys = self.key_path()?;
            self.skip_inline_space();
            if self.peek() != Some('=') {
                return self.err("expected `=` after a key");
            }
            self.bump();
            self.skip_inline_space();
            let value = self.value()?;
            self.end_of_line()?;
            let line = self.line;
            let table = ensure_path(&mut root, &current).map_err(|message| TomlError { line, message })?;
            assign(table, &keys, value).map_err(|message| TomlError { line, message })?;
        }
    }

    /// Parses `[a.b]` or `[[a.b]]` and returns the path that subsequent keys belong to.
    fn table_header(&mut self, root: &mut Value) -> Result<Vec<String>, TomlError> {
        let array_form = self.starts_with("[[");
        self.bump();
        if array_form {
            self.bump();
        }
        self.skip_inline_space();
        let path = self.key_path()?;
        self.skip_inline_space();
        let closing = if array_form { "]]" } else { "]" };
        if !self.starts_with(closing) {
            return self.err(format!("expected `{closing}` to close the table header"));
        }
        for _ in 0..closing.len() {
            self.bump();
        }
        self.end_of_line()?;
        if path.is_empty() {
            return self.err("empty table header");
        }
        let line = self.line;
        let (parents, last) = path.split_at(path.len() - 1);
        let parent = ensure_path(root, parents).map_err(|message| TomlError { line, message })?;
        let key = &last[0];
        if array_form {
            if parent.get(key).is_none() {
                parent.insert(key, Value::Array(Vec::new()));
            }
            match parent.get_mut(key) {
                Some(Value::Array(items)) => items.push(Value::empty_table()),
                Some(other) => {
                    return self.err(format!("`{key}` was already defined as {}, not an array of tables", other.type_name()));
                }
                None => return self.err(format!("could not define `{key}`")),
            }
        } else {
            match parent.get(key) {
                None => parent.insert(key, Value::empty_table()),
                Some(Value::Table(_)) => {}
                Some(other) => {
                    return self.err(format!("`{key}` was already defined as {}, not a table", other.type_name()));
                }
            }
        }
        Ok(path)
    }

    /// Parses a dotted key path: `a`, `a.b`, `"a b".c`.
    fn key_path(&mut self) -> Result<Vec<String>, TomlError> {
        let mut path = Vec::new();
        loop {
            self.skip_inline_space();
            path.push(self.key_segment()?);
            self.skip_inline_space();
            if self.peek() == Some('.') {
                self.bump();
            } else {
                return Ok(path);
            }
        }
    }

    fn key_segment(&mut self) -> Result<String, TomlError> {
        match self.peek() {
            Some('"') => self.basic_string(),
            Some('\'') => self.literal_string(),
            Some(ch) if is_bare_key_char(ch) => {
                let mut out = String::new();
                while let Some(ch) = self.peek() {
                    if is_bare_key_char(ch) {
                        out.push(ch);
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Ok(out)
            }
            _ => self.err("expected a key"),
        }
    }

    fn value(&mut self) -> Result<Value, TomlError> {
        match self.peek() {
            Some('"') => {
                if self.starts_with("\"\"\"") {
                    self.multiline_basic_string().map(Value::String)
                } else {
                    self.basic_string().map(Value::String)
                }
            }
            Some('\'') => {
                if self.starts_with("'''") {
                    self.multiline_literal_string().map(Value::String)
                } else {
                    self.literal_string().map(Value::String)
                }
            }
            Some('[') => self.array(),
            Some('{') => self.inline_table(),
            Some('t') if self.starts_with("true") => {
                self.pos += 4;
                Ok(Value::Bool(true))
            }
            Some('f') if self.starts_with("false") => {
                self.pos += 5;
                Ok(Value::Bool(false))
            }
            Some(_) => self.number(),
            None => self.err("expected a value"),
        }
    }

    fn basic_string(&mut self) -> Result<String, TomlError> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return self.err("unterminated string"),
                Some('"') => return Ok(out),
                Some('\\') => out.push(self.escape()?),
                Some(ch) => out.push(ch),
            }
        }
    }

    fn multiline_basic_string(&mut self) -> Result<String, TomlError> {
        for _ in 0..3 {
            self.bump();
        }
        // A newline immediately after the opening delimiter is not part of the value.
        if self.peek() == Some('\r') && self.peek_at(1) == Some('\n') {
            self.bump();
            self.bump();
        } else if self.peek() == Some('\n') {
            self.bump();
        }
        let mut out = String::new();
        loop {
            if self.starts_with("\"\"\"") {
                for _ in 0..3 {
                    self.bump();
                }
                return Ok(out);
            }
            match self.bump() {
                None => return self.err("unterminated multi-line string"),
                Some('\\') => match self.peek() {
                    // Line-ending backslash: swallow the newline and all leading whitespace after
                    // it. This is what lets a `rationale` be wrapped in the file without the wrap
                    // becoming part of the text.
                    Some('\n' | '\r' | ' ' | '\t') if self.rest_of_line_is_blank() => {
                        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
                            self.bump();
                        }
                    }
                    _ => out.push(self.escape()?),
                },
                Some(ch) => out.push(ch),
            }
        }
    }

    fn rest_of_line_is_blank(&self) -> bool {
        let mut index = 0;
        loop {
            match self.peek_at(index) {
                Some(' ' | '\t' | '\r') => index += 1,
                Some('\n') => return true,
                _ => return false,
            }
        }
    }

    fn literal_string(&mut self) -> Result<String, TomlError> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return self.err("unterminated literal string"),
                Some('\'') => return Ok(out),
                Some(ch) => out.push(ch),
            }
        }
    }

    fn multiline_literal_string(&mut self) -> Result<String, TomlError> {
        for _ in 0..3 {
            self.bump();
        }
        if self.peek() == Some('\r') && self.peek_at(1) == Some('\n') {
            self.bump();
            self.bump();
        } else if self.peek() == Some('\n') {
            self.bump();
        }
        let mut out = String::new();
        loop {
            if self.starts_with("'''") {
                for _ in 0..3 {
                    self.bump();
                }
                return Ok(out);
            }
            match self.bump() {
                None => return self.err("unterminated multi-line literal string"),
                Some(ch) => out.push(ch),
            }
        }
    }

    fn escape(&mut self) -> Result<char, TomlError> {
        match self.bump() {
            Some('"') => Ok('"'),
            Some('\\') => Ok('\\'),
            Some('b') => Ok('\u{8}'),
            Some('f') => Ok('\u{c}'),
            Some('n') => Ok('\n'),
            Some('r') => Ok('\r'),
            Some('t') => Ok('\t'),
            Some('e') => Ok('\u{1b}'),
            Some('u') => self.hex_escape(4),
            Some('U') => self.hex_escape(8),
            Some(ch) => self.err(format!("unknown escape `\\{ch}`")),
            None => self.err("unterminated escape"),
        }
    }

    fn hex_escape(&mut self, digits: usize) -> Result<char, TomlError> {
        let mut code: u32 = 0;
        for _ in 0..digits {
            let Some(ch) = self.bump() else {
                return self.err("truncated unicode escape");
            };
            let Some(digit) = ch.to_digit(16) else {
                return self.err("invalid unicode escape");
            };
            code = code * 16 + digit;
        }
        match char::from_u32(code) {
            Some(ch) => Ok(ch),
            None => self.err("unicode escape is not a scalar value"),
        }
    }

    fn array(&mut self) -> Result<Value, TomlError> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(']') {
                self.bump();
                return Ok(Value::Array(items));
            }
            if self.peek().is_none() {
                return self.err("unterminated array");
            }
            items.push(self.value()?);
            self.skip_trivia();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return self.err("expected `,` or `]` in an array"),
            }
        }
    }

    fn inline_table(&mut self) -> Result<Value, TomlError> {
        self.bump();
        let mut table = Value::empty_table();
        self.skip_trivia();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(table);
        }
        loop {
            self.skip_trivia();
            let keys = self.key_path()?;
            self.skip_inline_space();
            if self.peek() != Some('=') {
                return self.err("expected `=` in an inline table");
            }
            self.bump();
            self.skip_trivia();
            let value = self.value()?;
            let line = self.line;
            assign(&mut table, &keys, value).map_err(|message| TomlError { line, message })?;
            self.skip_trivia();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    return Ok(table);
                }
                _ => return self.err("expected `,` or `}` in an inline table"),
            }
        }
    }

    fn number(&mut self) -> Result<Value, TomlError> {
        let start = self.pos;
        if matches!(self.peek(), Some('+' | '-')) {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(ch) if ch.is_ascii_digit() || ch == '_') {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return self.err("expected a value");
        }
        // A bare datetime is a value the schema deliberately cannot represent. Rejecting it here,
        // by name, is the difference between an author seeing the rule and an author seeing
        // "expected end of line".
        if matches!(self.peek(), Some('-' | ':')) {
            return self.err(
                "bare datetimes are not accepted; the schema requires an instant to be a quoted \
                 string so the case and its JSON projection are the same value",
            );
        }
        let mut integral = true;
        if self.peek() == Some('.') {
            integral = false;
            self.pos += 1;
            while matches!(self.peek(), Some(ch) if ch.is_ascii_digit() || ch == '_') {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            integral = false;
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text: String = self.chars[start..self.pos].iter().filter(|ch| **ch != '_').collect();
        if integral {
            match text.parse::<i64>() {
                Ok(number) => Ok(Value::Integer(number)),
                Err(_) => self.err(format!("`{text}` is not an integer this runner can represent")),
            }
        } else {
            match text.parse::<f64>() {
                Ok(number) => Ok(Value::Float(number)),
                Err(_) => self.err(format!("`{text}` is not a number")),
            }
        }
    }
}

fn is_bare_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// Walks `path` from `root`, creating tables as needed and descending into the last element of an
/// array of tables. Returns the table that `path` names.
fn ensure_path<'a>(root: &'a mut Value, path: &[String]) -> Result<&'a mut Value, String> {
    let Some((head, rest)) = path.split_first() else {
        return Ok(root);
    };
    if root.get(head).is_none() {
        root.insert(head, Value::empty_table());
    }
    let kind = root.get(head).map(Value::type_name).unwrap_or("nothing");
    let child = root.get_mut(head).ok_or_else(|| format!("could not create `{head}`"))?;
    match child {
        Value::Table(_) => ensure_path(child, rest),
        Value::Array(items) => {
            let last = items
                .last_mut()
                .ok_or_else(|| format!("`{head}` is an empty array of tables"))?;
            ensure_path(last, rest)
        }
        _ => Err(format!("`{head}` is {kind}, so it cannot hold a table")),
    }
}

/// Assigns `value` at the dotted `keys` inside `table`, rejecting a redefinition.
fn assign(table: &mut Value, keys: &[String], value: Value) -> Result<(), String> {
    let Some((last, parents)) = keys.split_last() else {
        return Err("empty key".to_owned());
    };
    let target = ensure_path(table, parents)?;
    if target.get(last).is_some() {
        return Err(format!("`{last}` is defined twice; a duplicate key silently discards one of the two"));
    }
    target.insert(last, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tables_and_arrays_of_tables() {
        let doc = parse(
            "[case]\nid = \"c-etag-0001\"\n\n[[case.evidence]]\nurl = \"https://x\"\n\n[[case.evidence]]\nurl = \"https://y\"\n",
        )
        .expect("valid TOML");
        assert_eq!(doc.path("case/id").and_then(Value::as_str), Some("c-etag-0001"));
        let evidence = doc.path("case/evidence").and_then(Value::as_array).expect("array");
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[1].get("url").and_then(Value::as_str), Some("https://y"));
    }

    #[test]
    fn a_sub_table_lands_in_the_last_array_element() {
        let doc = parse("[[exchanges]]\nname = \"one\"\n[exchanges.request]\nmethod = \"GET\"\n\n[[exchanges]]\nname = \"two\"\n[exchanges.request]\nmethod = \"PUT\"\n")
            .expect("valid TOML");
        let exchanges = doc.path("exchanges").and_then(Value::as_array).expect("array");
        assert_eq!(exchanges[0].path("request/method").and_then(Value::as_str), Some("GET"));
        assert_eq!(exchanges[1].path("request/method").and_then(Value::as_str), Some("PUT"));
    }

    #[test]
    fn an_array_of_tables_nests_inside_an_array_of_tables() {
        let doc = parse("[[setup.multipart_uploads]]\nkey = \"k\"\n[[setup.multipart_uploads.parts]]\npart_number = 1\n")
            .expect("valid TOML");
        let uploads = doc.path("setup/multipart_uploads").and_then(Value::as_array).expect("array");
        let parts = uploads[0].path("parts").and_then(Value::as_array).expect("array");
        assert_eq!(parts[0].get("part_number").and_then(Value::as_integer), Some(1));
    }

    #[test]
    fn a_line_ending_backslash_joins_wrapped_prose() {
        let doc = parse("a = \"\"\"\nfirst \\\n  second\"\"\"\n").expect("valid TOML");
        assert_eq!(doc.get("a").and_then(Value::as_str), Some("first second"));
    }

    #[test]
    fn a_multi_line_literal_drops_only_the_first_newline() {
        let doc = parse("a = '''\n<?xml?>\n<Error/>'''\n").expect("valid TOML");
        assert_eq!(doc.get("a").and_then(Value::as_str), Some("<?xml?>\n<Error/>"));
    }

    #[test]
    fn inline_tables_and_nested_arrays_parse() {
        let doc = parse("a = { b = [\"x\", \"y\"], c = 3 }\n").expect("valid TOML");
        assert_eq!(doc.path("a/c").and_then(Value::as_integer), Some(3));
        assert_eq!(doc.path("a/b").and_then(Value::as_array).map(<[Value]>::len), Some(2));
    }

    #[test]
    fn escaped_quotes_survive() {
        let doc = parse("a = \"\\\"tag\\\"\"\n").expect("valid TOML");
        assert_eq!(doc.get("a").and_then(Value::as_str), Some("\"tag\""));
    }

    #[test]
    fn a_bare_datetime_is_rejected_by_name() {
        let error = parse("a = 2026-01-02T03:04:05Z\n").expect_err("must be rejected");
        assert!(error.message.contains("bare datetimes"), "{error}");
    }

    #[test]
    fn a_duplicate_key_is_rejected() {
        let error = parse("a = 1\na = 2\n").expect_err("must be rejected");
        assert!(error.message.contains("defined twice"), "{error}");
    }

    #[test]
    fn trailing_junk_after_a_value_is_rejected() {
        assert!(parse("a = 1 b = 2\n").is_err());
    }

    #[test]
    fn an_unterminated_string_is_rejected() {
        assert!(parse("a = \"abc\n").is_err());
    }

    #[test]
    fn a_comment_is_not_a_value() {
        let doc = parse("# leading\na = 1 # trailing\n# trailing block\n").expect("valid TOML");
        assert_eq!(doc.get("a").and_then(Value::as_integer), Some(1));
    }
}
