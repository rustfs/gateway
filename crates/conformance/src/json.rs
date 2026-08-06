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

//! A JSON reader for the frozen case schema and the baseline file.
//!
//! Responsible for: turning `conformance/case.schema.json` and an optional baseline document into
//! [`Value`]. It is deliberately a parser and nothing else — no serialisation, no borrowing of
//! third-party derive machinery — because this crate ships as a product other implementations run
//! and every dependency it carries is a dependency they inherit.
//! NOT responsible for: JSON output (see `crate::report`), schema semantics (`crate::schema`).
//! Upstream: `crate::value`. Downstream: `crate::schema`, `crate::report`.

use crate::value::Value;
use core::fmt;

/// A JSON syntax error, with the byte offset at which the reader gave up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    /// Byte offset into the input.
    pub offset: usize,
    /// What the reader expected to find there.
    pub message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for JsonError {}

/// Parses a complete JSON document.
///
/// # Errors
///
/// Returns [`JsonError`] when the input is not a single well-formed JSON value.
pub fn parse(input: &str) -> Result<Value, JsonError> {
    let bytes = input.as_bytes();
    let mut reader = Reader { bytes, pos: 0 };
    reader.skip_ws();
    let value = reader.value()?;
    reader.skip_ws();
    if reader.pos != bytes.len() {
        return Err(reader.err("trailing input after the top-level value"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn err(&self, message: &str) -> JsonError {
        JsonError {
            offset: self.pos,
            message: message.to_owned(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected {:?}", byte as char)))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, JsonError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.err(&format!("expected `{word}`")))
        }
    }

    fn value(&mut self) -> Result<Value, JsonError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            // `null` is accepted and modelled as an empty table so that a baseline file written by
            // another tool does not abort the run; the schema never uses it.
            Some(b'n') => self.literal("null", Value::empty_table()),
            Some(_) => self.number(),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn object(&mut self) -> Result<Value, JsonError> {
        self.expect(b'{')?;
        let mut entries: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Table(entries));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Table(entries));
                }
                _ => return Err(self.err("expected `,` or `}`")),
            }
        }
    }

    fn array(&mut self) -> Result<Value, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err("expected `,` or `]`")),
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => return Err(self.err(&format!("unknown escape `\\{}`", other as char))),
                    }
                }
                _ => {
                    // Multi-byte UTF-8 arrives here one byte at a time; collect the whole
                    // sequence from the original slice rather than re-decoding by hand.
                    let start = self.pos - 1;
                    while self.pos < self.bytes.len() && (self.bytes[self.pos] & 0xC0) == 0x80 {
                        self.pos += 1;
                    }
                    match core::str::from_utf8(&self.bytes[start..self.pos]) {
                        Ok(text) => out.push_str(text),
                        Err(_) => return Err(self.err("invalid UTF-8 in string")),
                    }
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let code = self.hex4()?;
        // Surrogate pair: the low half must follow immediately, otherwise the document is not
        // valid JSON text and silently substituting U+FFFD would corrupt a schema pattern.
        if (0xD800..0xDC00).contains(&code) {
            if !self.bytes[self.pos..].starts_with(b"\\u") {
                return Err(self.err("high surrogate without a low surrogate"));
            }
            self.pos += 2;
            let low = self.hex4()?;
            if !(0xDC00..0xE000).contains(&low) {
                return Err(self.err("expected a low surrogate"));
            }
            let combined = 0x1_0000 + ((code - 0xD800) << 10) + (low - 0xDC00);
            return char::from_u32(combined).ok_or_else(|| self.err("invalid surrogate pair"));
        }
        char::from_u32(code).ok_or_else(|| self.err("invalid \\u escape"))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let text = core::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).map_err(|_| self.err("invalid \\u escape"))?;
        let code = u32::from_str_radix(text, 16).map_err(|_| self.err("invalid \\u escape"))?;
        self.pos += 4;
        Ok(code)
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if start == self.pos {
            return Err(self.err("expected a value"));
        }
        let text = core::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| self.err("invalid number"))?;
        if integral {
            text.parse::<i64>()
                .map(Value::Integer)
                .map_err(|_| self.err("integer out of range"))
        } else {
            text.parse::<f64>().map(Value::Float).map_err(|_| self.err("invalid number"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_nested_document() {
        let value = parse(r#"{"a": [1, 2, {"b": true}], "c": "x"}"#).expect("valid JSON");
        assert_eq!(value.path("a").and_then(Value::as_array).map(<[Value]>::len), Some(3));
        assert_eq!(value.path("c").and_then(Value::as_str), Some("x"));
    }

    #[test]
    fn integers_and_floats_are_distinguished() {
        assert_eq!(parse("1"), Ok(Value::Integer(1)));
        assert_eq!(parse("1.5"), Ok(Value::Float(1.5)));
    }

    #[test]
    fn escapes_round_trip() {
        assert_eq!(parse(r#""a\"b\\cA""#), Ok(Value::String("a\"b\\cA".to_owned())));
    }

    #[test]
    fn surrogate_pairs_are_combined() {
        assert_eq!(parse(r#""😀""#), Ok(Value::String("\u{1f600}".to_owned())));
    }

    #[test]
    fn a_lone_high_surrogate_is_rejected() {
        assert!(parse(r#""\ud83d""#).is_err());
    }

    #[test]
    fn trailing_input_is_rejected() {
        assert!(parse("{} {}").is_err());
    }

    #[test]
    fn a_trailing_comma_is_rejected() {
        assert!(parse("[1,]").is_err());
    }

    #[test]
    fn an_unterminated_string_is_rejected() {
        assert!(parse("\"abc").is_err());
    }

    #[test]
    fn an_unknown_escape_is_rejected() {
        assert!(parse(r#""\q""#).is_err());
    }
}
