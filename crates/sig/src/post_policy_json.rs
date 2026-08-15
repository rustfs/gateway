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

//! Strict bounded JSON parser for POST policies.
//!
//! Responsible for: duplicate-free JSON objects, canonical strings, unsigned integers, and parse
//! budgets. Not responsible for: policy semantics or signature proof. Upstream: decoded policy
//! bytes. Downstream: the POST-policy authority.

use std::collections::BTreeSet;

use crate::PostPolicyError;

pub(crate) enum JsonValue {
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl JsonValue {
    pub(crate) fn into_string(self) -> Result<String, PostPolicyError> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(PostPolicyError::Malformed),
        }
    }

    pub(crate) fn into_array(self) -> Result<Vec<Self>, PostPolicyError> {
        match self {
            Self::Array(value) => Ok(value),
            _ => Err(PostPolicyError::Malformed),
        }
    }

    pub(crate) fn into_u64(self) -> Result<u64, PostPolicyError> {
        match self {
            Self::Number(value) => Ok(value),
            _ => Err(PostPolicyError::Malformed),
        }
    }
}

pub(crate) struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: usize,
    elements: usize,
    max_depth: usize,
    max_elements: usize,
}

impl<'a> JsonParser<'a> {
    pub(crate) fn parse(bytes: &'a [u8], max_depth: usize, max_elements: usize) -> Result<JsonValue, PostPolicyError> {
        let mut parser = Self {
            bytes,
            position: 0,
            depth: 0,
            elements: 0,
            max_depth,
            max_elements,
        };
        let value = parser.value()?;
        parser.whitespace();
        if parser.position != bytes.len() {
            return Err(PostPolicyError::Malformed);
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<JsonValue, PostPolicyError> {
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'0'..=b'9') => self.number().map(JsonValue::Number),
            _ => Err(PostPolicyError::Malformed),
        }
    }

    fn object(&mut self) -> Result<JsonValue, PostPolicyError> {
        self.enter(b'{')?;
        let mut values = Vec::new();
        let mut names = BTreeSet::new();
        self.whitespace();
        while self.peek() != Some(b'}') {
            let name = self.string()?;
            if !names.insert(name.clone()) {
                return Err(PostPolicyError::Malformed);
            }
            self.whitespace();
            self.take(b':')?;
            self.element()?;
            values.push((name, self.value()?));
            self.whitespace();
            if self.peek() != Some(b',') {
                break;
            }
            self.position += 1;
            self.whitespace();
        }
        self.take(b'}')?;
        self.depth -= 1;
        Ok(JsonValue::Object(values))
    }

    fn array(&mut self) -> Result<JsonValue, PostPolicyError> {
        self.enter(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        while self.peek() != Some(b']') {
            self.element()?;
            values.push(self.value()?);
            self.whitespace();
            if self.peek() != Some(b',') {
                break;
            }
            self.position += 1;
            self.whitespace();
        }
        self.take(b']')?;
        self.depth -= 1;
        Ok(JsonValue::Array(values))
    }

    fn string(&mut self) -> Result<String, PostPolicyError> {
        self.take(b'"')?;
        let mut value = Vec::new();
        loop {
            match self.peek().ok_or(PostPolicyError::Malformed)? {
                b'"' => {
                    self.position += 1;
                    return String::from_utf8(value).map_err(|_| PostPolicyError::Malformed);
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = self.peek().ok_or(PostPolicyError::Malformed)?;
                    self.position += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => value.push(escaped),
                        b'b' => value.push(8),
                        b'f' => value.push(12),
                        b'n' => value.push(b'\n'),
                        b'r' => value.push(b'\r'),
                        b't' => value.push(b'\t'),
                        b'u' => self.unicode_escape(&mut value)?,
                        _ => return Err(PostPolicyError::Malformed),
                    }
                }
                0..=31 => return Err(PostPolicyError::Malformed),
                byte => {
                    value.push(byte);
                    self.position += 1;
                }
            }
        }
    }

    fn unicode_escape(&mut self, output: &mut Vec<u8>) -> Result<(), PostPolicyError> {
        let high = self.hex_quad()?;
        let code = if (0xd800..=0xdbff).contains(&high) {
            self.take(b'\\')?;
            self.take(b'u')?;
            let low = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(PostPolicyError::Malformed);
            }
            0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&high) {
            return Err(PostPolicyError::Malformed);
        } else {
            high
        };
        let scalar = char::from_u32(code).ok_or(PostPolicyError::Malformed)?;
        let mut bytes = [0; 4];
        output.extend_from_slice(scalar.encode_utf8(&mut bytes).as_bytes());
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u32, PostPolicyError> {
        let mut value = 0;
        for _ in 0..4 {
            value = value * 16 + u32::from(hex_digit(self.peek().ok_or(PostPolicyError::Malformed)?)?);
            self.position += 1;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<u64, PostPolicyError> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if self.position - start > 1 && self.bytes[start] == b'0' {
            return Err(PostPolicyError::Malformed);
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(PostPolicyError::Malformed)
    }

    fn enter(&mut self, byte: u8) -> Result<(), PostPolicyError> {
        self.take(byte)?;
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(PostPolicyError::Malformed);
        }
        Ok(())
    }

    fn element(&mut self) -> Result<(), PostPolicyError> {
        self.elements += 1;
        if self.elements > self.max_elements {
            return Err(PostPolicyError::Malformed);
        }
        Ok(())
    }

    fn take(&mut self, byte: u8) -> Result<(), PostPolicyError> {
        if self.peek() != Some(byte) {
            return Err(PostPolicyError::Malformed);
        }
        self.position += 1;
        Ok(())
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
}

fn hex_digit(byte: u8) -> Result<u8, PostPolicyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PostPolicyError::Malformed),
    }
}
