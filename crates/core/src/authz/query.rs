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

//! Reading a query parameter that authorisation depends on, once and strictly (ADR-0025,
//! ADR-0026).
//!
//! Responsible for: [`single_raw_value`], which finds one parameter's still-encoded value and
//! refuses a repeat; and the one decoder every such read shares, which refuses a literal `+`, a
//! malformed escape, invalid UTF-8 and a control character.
//! NOT responsible for: what a value means. That is a subject rule's job (`super::rule`) or a
//! bound bucket's (the facade's routed facts, which put the raw value through
//! `codec::bucket_label`).
//! Upstream: the raw query of a routed request. Downstream: `super::rule`, the facade.
//!
//! # Why every key is decoded, not only the one looked for
//!
//! A handler that parses the query itself decodes keys, so `access%4Bey=` is `accessKey=` to it.
//! A reader that compared raw keys would miss that spelling and authorise a request whose handler
//! then acts on a parameter nobody judged. So each key is decoded, and a key that cannot be decoded
//! refuses the whole request rather than being skipped.

use core::fmt;

/// Why a query parameter could not be read unambiguously. Every refusal is a `400` before
/// authentication that names the parameter and never echoes its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryParamError {
    /// The parameter appears more than once.
    Repeated,
    /// A key or the value is not strictly decodable, or carries a `+` or a control character.
    Malformed,
}

impl QueryParamError {
    /// A constant explanation.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Repeated => "the parameter appears more than once",
            Self::Malformed => "the query cannot be decoded unambiguously",
        }
    }
}

impl fmt::Display for QueryParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// The still-encoded value of `param`, or `None` when the query does not carry it. A bare key
/// (`param` with no `=`) has the empty value.
///
/// # Errors
///
/// [`QueryParamError::Repeated`] when the parameter appears twice in any spelling, and
/// [`QueryParamError::Malformed`] when any key in the query cannot be decoded strictly.
pub fn single_raw_value<'q>(raw_query: &'q str, param: &str) -> Result<Option<&'q str>, QueryParamError> {
    single_raw_value_of(raw_query, param, &[])
}

/// [`single_raw_value`] for a parameter with alias spellings (ADR-0029): the value of whichever of
/// `param` and `aliases` the query carries, each compared exactly after decoding.
///
/// # Errors
///
/// [`QueryParamError::Repeated`] when the spellings appear more than once between them, whether
/// one spelling twice or two spellings once each, with the same value or not; and
/// [`QueryParamError::Malformed`] when any key in the query cannot be decoded strictly.
pub(crate) fn single_raw_value_of<'q>(
    raw_query: &'q str,
    param: &str,
    aliases: &[&str],
) -> Result<Option<&'q str>, QueryParamError> {
    let mut found = None;
    for (raw_key, raw_value) in pairs(raw_query) {
        let key = decode_component(raw_key)?;
        if key != param && !aliases.contains(&key.as_str()) {
            continue;
        }
        if found.replace(raw_value).is_some() {
            return Err(QueryParamError::Repeated);
        }
    }
    Ok(found)
}

/// Every non-empty `key=value` pair, still encoded; a bare key has the empty value.
pub(crate) fn pairs(raw_query: &str) -> impl Iterator<Item = (&str, &str)> {
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
}

/// One percent-decode, refusing a malformed escape, invalid UTF-8, a literal `+` (a space to a form
/// decoder, a plus to a URI decoder) and a control character.
pub(crate) fn decode_component(raw: &str) -> Result<String, QueryParamError> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => return Err(QueryParamError::Malformed),
            b'%' => {
                let high = bytes.next().and_then(hex_value);
                let low = bytes.next().and_then(hex_value);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(QueryParamError::Malformed);
                };
                decoded.push(high << 4 | low);
            }
            byte => decoded.push(byte),
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| QueryParamError::Malformed)?;
    if text.chars().any(char::is_control) {
        return Err(QueryParamError::Malformed);
    }
    Ok(text)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_raw_value_of_the_one_parameter_is_found() {
        assert_eq!(single_raw_value("bucket=photos", "bucket"), Ok(Some("photos")));
        assert_eq!(single_raw_value("x=1&bucket=%70hotos&y", "bucket"), Ok(Some("%70hotos")));
        assert_eq!(single_raw_value("bucket", "bucket"), Ok(Some("")));
        assert_eq!(single_raw_value("", "bucket"), Ok(None));
        assert_eq!(single_raw_value("buckets=a&xbucket=b", "bucket"), Ok(None));
    }

    #[test]
    fn n_a_repeat_in_any_spelling_is_refused() {
        assert_eq!(single_raw_value("bucket=a&bucket=b", "bucket"), Err(QueryParamError::Repeated));
        assert_eq!(single_raw_value("bucket=a&%62ucket=b", "bucket"), Err(QueryParamError::Repeated));
        assert_eq!(single_raw_value("bucket=&bucket=a", "bucket"), Err(QueryParamError::Repeated));
    }

    /// Positive — an alias spelling is the parameter.
    #[test]
    fn an_alias_spelling_is_the_parameter() {
        let aliases = &["access-key", "ak"];
        assert_eq!(single_raw_value_of("access-key=a", "accessKey", aliases), Ok(Some("a")));
        assert_eq!(single_raw_value_of("x=1&ak=%62", "accessKey", aliases), Ok(Some("%62")));
        assert_eq!(single_raw_value_of("accessKey=c", "accessKey", aliases), Ok(Some("c")));
        assert_eq!(single_raw_value_of("AccessKey=a&access_key=b", "accessKey", aliases), Ok(None));
    }

    /// Negative — two spellings between them are a repeat, whatever their values.
    #[test]
    fn n_two_spellings_are_a_repeat() {
        let aliases = &["access-key", "ak"];
        for query in [
            "accessKey=a&access-key=a",
            "access-key=a&accessKey=b",
            "access-key=a&%61ccess-key=b",
            "ak=a&access-key=b",
            "ak=&accessKey=a",
        ] {
            assert_eq!(
                single_raw_value_of(query, "accessKey", aliases),
                Err(QueryParamError::Repeated),
                "{query}"
            );
        }
    }

    #[test]
    fn n_an_undecodable_key_anywhere_refuses_the_query() {
        for query in [
            "bu%ZZcket=a",
            "x%2=1&bucket=a",
            "a+b=1&bucket=a",
            "%ff=1&bucket=a",
            "%0A=1&bucket=a",
        ] {
            assert_eq!(single_raw_value(query, "bucket"), Err(QueryParamError::Malformed), "{query}");
        }
    }

    #[test]
    fn n_a_value_is_decoded_strictly() {
        assert_eq!(decode_component("cn%3Dbob%20smith"), Ok("cn=bob smith".to_owned()));
        for raw in ["a+b", "a%2", "a%zz", "%ff", "a%0Ab", "a%7Fb"] {
            assert_eq!(decode_component(raw), Err(QueryParamError::Malformed), "{raw}");
        }
    }
}
