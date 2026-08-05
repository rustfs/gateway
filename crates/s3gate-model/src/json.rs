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

//! A dependency-free JSON reader and canonical writer.
//!
//! Responsible for: parsing the pinned Smithy model and the frozen IR samples, and writing IR
//! documents back out in one canonical, byte-stable shape.
//! NOT responsible for: knowing anything about Smithy or the IR. It sees values, not meaning.
//! Upstream: `model/*.json` and `spec/ir/samples/*.json`. Downstream: [`crate::smithy`],
//! [`crate::ir`].
//!
//! Why hand-written: the workspace dependency set is pinned and carries no serde. A reader plus a
//! writer for a format this small is cheaper than widening that set, and it lets the writer commit
//! to one deterministic layout rule instead of inheriting a library's.

use std::fmt::Write as _;

use crate::error::{Error, Result};

/// A JSON value. Objects keep insertion order, because the IR's key order is part of its
/// canonical rendering.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number that round-trips through `i64`.
    Int(i64),
    /// Any other number.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, in insertion order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Builds an object from an iterator of pairs.
    pub fn object<I: IntoIterator<Item = (String, Value)>>(pairs: I) -> Self {
        Value::Object(pairs.into_iter().collect())
    }

    /// Borrows the named member of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Borrows the value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Borrows the value as an object's pairs.
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(pairs) => Some(pairs.as_slice()),
            _ => None,
        }
    }

    /// Borrows the value as an array's items.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// A short type name, for diagnostics.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) | Value::Float(_) => "number",
            Value::Str(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

/// Parses a JSON document.
pub fn parse(input: &str) -> Result<Value> {
    let mut p = Parser {
        b: input.as_bytes(),
        i: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(Error::Json(format!("trailing input at byte {}", p.i)));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while let Some(c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn eat(&mut self, c: u8) -> Result<()> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(Error::Json(format!("expected `{}` at byte {}", c as char, self.i)))
        }
    }

    fn lit(&mut self, word: &str) -> Result<()> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(())
        } else {
            Err(Error::Json(format!("expected `{word}` at byte {}", self.i)))
        }
    }

    fn value(&mut self) -> Result<Value> {
        match self.b.get(self.i) {
            None => Err(Error::Json("unexpected end of input".into())),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => {
                self.lit("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.lit("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.lit("null")?;
                Ok(Value::Null)
            }
            Some(_) => self.number(),
        }
    }

    fn object(&mut self) -> Result<Value> {
        self.eat(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Object(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.eat(b':')?;
            self.skip_ws();
            let value = self.value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(pairs));
                }
                _ => return Err(Error::Json(format!("expected `,` or `}}` at byte {}", self.i))),
            }
        }
    }

    fn array(&mut self) -> Result<Value> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(Error::Json(format!("expected `,` or `]` at byte {}", self.i))),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or_else(|| Error::Json("unterminated string".into()))?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or_else(|| Error::Json("unterminated escape".into()))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                self.eat(b'\\')?;
                                self.eat(b'u')?;
                                let lo = self.hex4()?;
                                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                char::from_u32(cp)
                            } else {
                                char::from_u32(hi)
                            };
                            out.push(ch.ok_or_else(|| Error::Json("invalid \\u escape".into()))?);
                        }
                        other => return Err(Error::Json(format!("invalid escape `\\{}`", other as char))),
                    }
                }
                _ => {
                    // Copy the whole UTF-8 sequence; the input is known-valid UTF-8 (`&str`).
                    let start = self.i - 1;
                    let mut end = self.i;
                    while end < self.b.len() && (self.b[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    self.i = end;
                    match std::str::from_utf8(&self.b[start..end]) {
                        Ok(s) => out.push_str(s),
                        Err(_) => return Err(Error::Json("invalid utf-8 in string".into())),
                    }
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let slice = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| Error::Json("truncated \\u escape".into()))?;
        let text = std::str::from_utf8(slice).map_err(|_| Error::Json("invalid \\u escape".into()))?;
        let v = u32::from_str_radix(text, 16).map_err(|_| Error::Json("invalid \\u escape".into()))?;
        self.i += 4;
        Ok(v)
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let mut float = false;
        while let Some(c) = self.b.get(self.i) {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| Error::Json("invalid number".into()))?;
        if text.is_empty() {
            return Err(Error::Json(format!("expected a value at byte {start}")));
        }
        if float {
            text.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| Error::Json(format!("invalid number `{text}`")))
        } else {
            text.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| Error::Json(format!("invalid number `{text}`")))
        }
    }
}

/// Column budget for the canonical writer. A composite value is written on one line when it fits.
pub const PRINT_WIDTH: usize = 120;

/// Renders a value in the canonical layout: two-space indent, a composite value written flat when
/// its flat form fits inside [`PRINT_WIDTH`], and exactly one trailing newline.
///
/// The rule is a pure function of the value, so the same IR always renders to the same bytes.
pub fn write_canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out.push('\n');
    out
}

fn write_value(out: &mut String, value: &Value, indent: usize) {
    let flat = flatten(value);
    if indent + flat.len() <= PRINT_WIDTH {
        out.push_str(&flat);
        return;
    }
    match value {
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push('\n');
                pad(out, indent + 2);
                write_value(out, item, indent + 2);
            }
            out.push('\n');
            pad(out, indent);
            out.push(']');
        }
        Value::Object(pairs) => {
            out.push('{');
            for (n, (k, v)) in pairs.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push('\n');
                pad(out, indent + 2);
                write_string(out, k);
                out.push_str(": ");
                write_value(out, v, indent + 2 + k.len() + 4);
            }
            out.push('\n');
            pad(out, indent);
            out.push('}');
        }
        _ => out.push_str(&flat),
    }
}

fn pad(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

/// The one-line rendering of a value.
fn flatten(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Float(f) => {
            let _ = write!(out, "{f}");
        }
        Value::Str(s) => write_string(&mut out, s),
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                out.push_str(&flatten(item));
            }
            out.push(']');
        }
        Value::Object(pairs) => {
            if pairs.is_empty() {
                return "{}".into();
            }
            out.push_str("{ ");
            for (n, (k, v)) in pairs.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                write_string(&mut out, k);
                out.push_str(": ");
                out.push_str(&flatten(v));
            }
            out.push_str(" }");
        }
    }
    out
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
