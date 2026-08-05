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

//! A deliberately small TOML reader for the hand-written overlays.
//!
//! Responsible for: tables, arrays of tables, basic strings, integers, booleans and homogeneous
//! arrays — the whole grammar the overlays are allowed to use.
//! NOT responsible for: inline tables, multi-line strings, floats, dates, or writing TOML back.
//! Anything outside the subset is a parse error on purpose: the overlay is the one hand-written
//! protocol source in the repository, so its grammar should be boring enough to review by eye.
//! Upstream: `overlays/*.toml`. Downstream: [`crate::overlay`].

use crate::error::{Error, Result};

/// A parsed TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Toml {
    /// A basic string.
    Str(String),
    /// A signed integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// An array. Arrays of tables land here as an array of [`Toml::Table`].
    Array(Vec<Toml>),
    /// A table, in declaration order.
    Table(Vec<(String, Toml)>),
}

impl Toml {
    /// Borrows a direct child of a table.
    pub fn get(&self, key: &str) -> Option<&Toml> {
        match self {
            Toml::Table(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Borrows the value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Toml::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Borrows the value as an integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Toml::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Borrows the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Toml::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Borrows the value as an array.
    pub fn as_array(&self) -> Option<&[Toml]> {
        match self {
            Toml::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// Borrows the value as a table's entries.
    pub fn as_table(&self) -> Option<&[(String, Toml)]> {
        match self {
            Toml::Table(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// Reads an array of strings, failing when any element is not a string.
    pub fn string_array(&self, what: &str) -> Result<Vec<String>> {
        let items = self
            .as_array()
            .ok_or_else(|| Error::Overlay(format!("{what}: expected an array")))?;
        items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::Overlay(format!("{what}: expected an array of strings")))
            })
            .collect()
    }
}

/// Parses one overlay file. `path` only appears in error messages.
pub fn parse(path: &str, input: &str) -> Result<Toml> {
    let mut root = Toml::Table(Vec::new());
    let mut current: Vec<String> = Vec::new();
    let mut scanner = Scanner {
        chars: input.as_bytes(),
        pos: 0,
        line: 1,
        path: path.to_owned(),
    };

    loop {
        scanner.skip_trivia();
        if scanner.eof() {
            break;
        }
        if scanner.peek() == Some(b'[') {
            let (segments, array) = scanner.header()?;
            let line = scanner.line;
            if array {
                push_array_table(&mut root, &segments).map_err(|m| scanner.err_at(line, m))?;
            } else {
                ensure_table(&mut root, &segments).map_err(|m| scanner.err_at(line, m))?;
            }
            current = segments;
            continue;
        }
        let line = scanner.line;
        let key = scanner.key()?;
        scanner.skip_inline_ws();
        scanner.expect(b'=')?;
        scanner.skip_inline_ws();
        let value = scanner.value()?;
        let table = resolve_mut(&mut root, &current).map_err(|m| scanner.err_at(line, m))?;
        let Toml::Table(entries) = table else {
            return Err(scanner.err_at(line, format!("`{}` is not a table", current.join("."))));
        };
        if entries.iter().any(|(k, _)| *k == key) {
            return Err(scanner.err_at(line, format!("duplicate key `{key}`")));
        }
        entries.push((key, value));
    }
    Ok(root)
}

fn resolve_mut<'a>(root: &'a mut Toml, path: &[String]) -> std::result::Result<&'a mut Toml, String> {
    let mut node = root;
    for segment in path {
        node = match node {
            Toml::Table(entries) => {
                let index = entries
                    .iter()
                    .position(|(k, _)| k == segment)
                    .ok_or_else(|| format!("unknown table `{segment}`"))?;
                &mut entries[index].1
            }
            _ => return Err(format!("`{segment}` is not inside a table")),
        };
        if let Toml::Array(items) = node {
            node = items
                .last_mut()
                .ok_or_else(|| format!("`{segment}` is an empty array of tables"))?;
        }
    }
    Ok(node)
}

fn ensure_table(root: &mut Toml, path: &[String]) -> std::result::Result<(), String> {
    let mut node = root;
    for segment in path {
        let Toml::Table(entries) = node else {
            return Err(format!("`{segment}` is not inside a table"));
        };
        let index = match entries.iter().position(|(k, _)| k == segment) {
            Some(i) => i,
            None => {
                entries.push((segment.clone(), Toml::Table(Vec::new())));
                entries.len() - 1
            }
        };
        node = &mut entries[index].1;
        if let Toml::Array(items) = node {
            node = items
                .last_mut()
                .ok_or_else(|| format!("`{segment}` is an empty array of tables"))?;
        }
    }
    Ok(())
}

fn push_array_table(root: &mut Toml, path: &[String]) -> std::result::Result<(), String> {
    let (last, parents) = path.split_last().ok_or_else(|| "empty table header".to_owned())?;
    ensure_table(root, parents)?;
    let parent = resolve_mut(root, parents)?;
    let Toml::Table(entries) = parent else {
        return Err(format!("`{last}` is not inside a table"));
    };
    match entries.iter_mut().find(|(k, _)| k == last) {
        Some((_, Toml::Array(items))) => items.push(Toml::Table(Vec::new())),
        Some(_) => return Err(format!("`{last}` is already a table, not an array of tables")),
        None => entries.push((last.clone(), Toml::Array(vec![Toml::Table(Vec::new())]))),
    }
    Ok(())
}

struct Scanner<'a> {
    chars: &'a [u8],
    pos: usize,
    line: usize,
    path: String,
}

impl Scanner<'_> {
    fn eof(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> Option<u8> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn err(&self, message: impl Into<String>) -> Error {
        Error::Toml {
            path: self.path.clone(),
            line: self.line,
            message: message.into(),
        }
    }

    fn err_at(&self, line: usize, message: impl Into<String>) -> Error {
        Error::Toml {
            path: self.path.clone(),
            line,
            message: message.into(),
        }
    }

    fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.pos += 1;
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => {
                    self.bump();
                }
                Some(b'#') => {
                    while !matches!(self.peek(), None | Some(b'\n')) {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn expect(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(format!("expected `{}`", c as char)))
        }
    }

    /// Reads a `[table]` or `[[array]]` header and returns its dotted segments.
    fn header(&mut self) -> Result<(Vec<String>, bool)> {
        self.expect(b'[')?;
        let array = self.peek() == Some(b'[');
        if array {
            self.pos += 1;
        }
        let mut segments = Vec::new();
        loop {
            self.skip_inline_ws();
            segments.push(self.key()?);
            self.skip_inline_ws();
            match self.peek() {
                Some(b'.') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected `.` or `]` in a table header")),
            }
        }
        if array {
            self.expect(b']')?;
        }
        Ok((segments, array))
    }

    fn key(&mut self) -> Result<String> {
        if self.peek() == Some(b'"') {
            return self.basic_string();
        }
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.err("expected a key"));
        }
        Ok(String::from_utf8_lossy(&self.chars[start..self.pos]).into_owned())
    }

    fn basic_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.bump().ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => return Ok(out),
                b'\n' => return Err(self.err("newline inside a basic string")),
                b'\\' => {
                    let e = self.bump().ok_or_else(|| self.err("unterminated escape"))?;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        other => return Err(self.err(format!("unsupported escape `\\{}`", other as char))),
                    }
                }
                _ => {
                    let start = self.pos - 1;
                    while matches!(self.peek(), Some(b) if (b & 0xC0) == 0x80) {
                        self.pos += 1;
                    }
                    match std::str::from_utf8(&self.chars[start..self.pos]) {
                        Ok(s) => out.push_str(s),
                        Err(_) => return Err(self.err("invalid utf-8")),
                    }
                }
            }
        }
    }

    fn value(&mut self) -> Result<Toml> {
        match self.peek() {
            Some(b'"') => Ok(Toml::Str(self.basic_string()?)),
            Some(b'[') => self.array(),
            Some(b't') | Some(b'f') => {
                let start = self.pos;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphabetic()) {
                    self.pos += 1;
                }
                match &self.chars[start..self.pos] {
                    b"true" => Ok(Toml::Bool(true)),
                    b"false" => Ok(Toml::Bool(false)),
                    _ => Err(self.err("expected a value")),
                }
            }
            Some(b'{') => Err(self.err("inline tables are not part of the overlay grammar")),
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.pos;
                self.pos += 1;
                while matches!(self.peek(), Some(c) if c.is_ascii_digit() || c == b'_') {
                    self.pos += 1;
                }
                if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E') | Some(b'-') | Some(b':')) {
                    return Err(self.err("only integers are part of the overlay grammar"));
                }
                let text: String = String::from_utf8_lossy(&self.chars[start..self.pos]).replace('_', "");
                text.parse::<i64>()
                    .map(Toml::Int)
                    .map_err(|_| self.err(format!("invalid integer `{text}`")))
            }
            _ => Err(self.err("expected a value")),
        }
    }

    fn array(&mut self) -> Result<Toml> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Toml::Array(items));
            }
            items.push(self.value()?);
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Toml::Array(items));
                }
                _ => return Err(self.err("expected `,` or `]` in an array")),
            }
        }
    }
}
