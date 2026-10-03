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

//! The canonical headers of a `SignedHeaders` list read verbatim, as legacy RustFS writes them,
//! for the RustFS profile (rustfs/gateway#1130).
//!
//! Responsible for: [`write_canonical_headers`] and [`write_signed_line`] — the canonical-headers
//! block and the signed-headers line of a list [`crate::SignedHeaderSet`] read verbatim.
//! NOT responsible for: deciding that a list is read this way, or the completeness rules
//! (`crate::signed_headers`, which enforces them before anything here runs); a list AWS emits,
//! which the wire layer's writer canonicalises; the rest of the canonical request
//! (`crate::canonical`).
//! Upstream: `crate::signed_headers`. Downstream: `crate::canonical`.
//!
//! # What legacy RustFS writes
//!
//! Each name as the client wrote it, in the order written. Its values are every value of that
//! header, looked up case-insensitively, each trimmed of whitespace with every run of
//! whitespace inside it collapsed to one space (whitespace as Unicode defines it), joined by `,`;
//! a name written twice in a row continues the same line. A name spelled exactly `authorization`
//! is left out of both the block and the line, and ends a run of repeated names. A name with no
//! value is a signed header the request did not send, except `host` spelled exactly so, whose value
//! is then the request's authority. The signed-headers line is the names again, a name repeated in
//! a row written once. For a list AWS emits — lowercase, ascending, each name once — this is the
//! canonical form AWS defines.

use http::HeaderMap;
use smallvec::SmallVec;

use crate::verdict::AuthError;

/// The one name legacy RustFS leaves out of the canonical request, in this spelling only.
const SKIPPED: &str = "authorization";

/// The spelling of `host` whose absent header the request's authority stands in for.
const HOST: &str = "host";

/// Writes the canonical-headers block of the verbatim list `raw`: one line per run of a name, each
/// ending in `\n`. `host` is the request's authority, written for a `host` the headers lack.
///
/// # Errors
///
/// [`AuthError::SignatureDoesNotMatch`] for a named header the request did not send, or one with a
/// value that is not UTF-8, as legacy RustFS refuses both.
pub(crate) fn write_canonical_headers(raw: &str, headers: &HeaderMap, host: &str, out: &mut String) -> Result<(), AuthError> {
    let mut previous: Option<&str> = None;
    let mut open = false;
    for name in raw.split(';') {
        let continuing = open && previous == Some(name);
        previous = Some(name);
        if name == SKIPPED {
            if open {
                out.push('\n');
                open = false;
            }
            continue;
        }
        let values = values(name, headers, host)?;
        if !continuing {
            if open {
                out.push('\n');
            }
            out.push_str(name);
            out.push(':');
            open = true;
        }
        for (index, value) in values.iter().enumerate() {
            if continuing || index > 0 {
                out.push(',');
            }
            push_normalized(value, out);
        }
    }
    if open {
        out.push('\n');
    }
    Ok(())
}

/// Writes the signed-headers line of the verbatim list `raw`: the names in order, a name repeated
/// in a row once, `authorization` left out.
pub(crate) fn write_signed_line(raw: &str, out: &mut String) {
    let mut previous: Option<&str> = None;
    let mut first = true;
    for name in raw.split(';') {
        let repeated = previous == Some(name);
        previous = Some(name);
        if name == SKIPPED || repeated {
            continue;
        }
        if !first {
            out.push(';');
        }
        first = false;
        out.push_str(name);
    }
}

/// Every value of the header `name` names, looked up case-insensitively, as text.
fn values<'h>(name: &str, headers: &'h HeaderMap, host: &'h str) -> Result<SmallVec<[&'h str; 2]>, AuthError> {
    let mut found: SmallVec<[&'h str; 2]> = SmallVec::new();
    for value in headers.get_all(name) {
        found.push(core::str::from_utf8(value.as_bytes()).map_err(|_| AuthError::SignatureDoesNotMatch)?);
    }
    if found.is_empty() {
        if name != HOST {
            return Err(AuthError::SignatureDoesNotMatch);
        }
        found.push(host);
    }
    Ok(found)
}

/// `value` trimmed, every run of whitespace inside it collapsed to one space.
fn push_normalized(value: &str, out: &mut String) {
    let mut words = value.split_whitespace();
    if let Some(first) = words.next() {
        out.push_str(first);
        for word in words {
            out.push(' ');
            out.push_str(word);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                http::HeaderValue::from_str(value).expect("a header value"),
            );
        }
        map
    }

    fn block(raw: &str, map: &HeaderMap) -> Result<(String, String), AuthError> {
        let mut canonical = String::new();
        write_canonical_headers(raw, map, "authority.example", &mut canonical)?;
        let mut line = String::new();
        write_signed_line(raw, &mut line);
        Ok((canonical, line))
    }

    fn sent() -> HeaderMap {
        headers(&[
            ("host", "s3.example.com"),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-meta-a", "  one  two  "),
            ("x-amz-meta-a", "three"),
        ])
    }

    /// Positive — a list AWS emits is written as AWS canonicalises it.
    #[test]
    fn a_list_aws_emits_is_written_as_aws_writes_it() {
        assert_eq!(
            block("host;x-amz-date;x-amz-meta-a", &sent()),
            Ok((
                "host:s3.example.com\nx-amz-date:20150830T123600Z\nx-amz-meta-a:one two,three\n".to_owned(),
                "host;x-amz-date;x-amz-meta-a".to_owned()
            ))
        );
    }

    /// Positive — names keep their case and order, and a name repeated in a row continues one
    /// line and is signed once.
    #[test]
    fn names_are_written_as_written() {
        assert_eq!(
            block("HOST;X-Amz-Date", &sent()),
            Ok((
                "HOST:s3.example.com\nX-Amz-Date:20150830T123600Z\n".to_owned(),
                "HOST;X-Amz-Date".to_owned()
            ))
        );
        assert_eq!(
            block("x-amz-date;host", &sent()),
            Ok((
                "x-amz-date:20150830T123600Z\nhost:s3.example.com\n".to_owned(),
                "x-amz-date;host".to_owned()
            ))
        );
        assert_eq!(
            block("host;host;x-amz-date", &sent()),
            Ok((
                "host:s3.example.com,s3.example.com\nx-amz-date:20150830T123600Z\n".to_owned(),
                "host;x-amz-date".to_owned()
            ))
        );
        assert_eq!(
            block("host;x-amz-date;host", &sent()),
            Ok((
                "host:s3.example.com\nx-amz-date:20150830T123600Z\nhost:s3.example.com\n".to_owned(),
                "host;x-amz-date;host".to_owned()
            ))
        );
        assert_eq!(
            block("host;HOST", &sent()),
            Ok(("host:s3.example.com\nHOST:s3.example.com\n".to_owned(), "host;HOST".to_owned()))
        );
    }

    /// Positive — `authorization`, spelled so, is left out and ends a run; another spelling is not.
    #[test]
    fn authorization_is_left_out_only_in_its_own_spelling() {
        let mut map = sent();
        map.insert(http::header::AUTHORIZATION, http::HeaderValue::from_static("AWS4-HMAC-SHA256 x"));
        assert_eq!(
            block("host;authorization;host", &map),
            Ok(("host:s3.example.com\nhost:s3.example.com\n".to_owned(), "host;host".to_owned()))
        );
        assert_eq!(
            block("Authorization;host", &map),
            Ok((
                "Authorization:AWS4-HMAC-SHA256 x\nhost:s3.example.com\n".to_owned(),
                "Authorization;host".to_owned()
            ))
        );
    }

    /// Positive — `host` spelled so stands on the authority when no header carries it; whitespace
    /// is Unicode's.
    #[test]
    fn the_authority_and_unicode_whitespace_are_read_as_legacy_rustfs_reads_them() {
        let map = headers(&[("x-amz-meta-b", "a\u{a0}\u{a0}b\u{2003}")]);
        assert_eq!(
            block("host;x-amz-meta-b", &map),
            Ok(("host:authority.example\nx-amz-meta-b:a b\n".to_owned(), "host;x-amz-meta-b".to_owned()))
        );
    }

    /// Negative — a name the request did not send is refused, and so is `HOST` in another
    /// spelling without a header, an empty name, and a value that is not UTF-8.
    #[test]
    fn n_a_name_without_a_readable_value_is_refused() {
        let map = headers(&[("x-amz-date", "20150830T123600Z")]);
        for raw in [
            "host;x-amz-meta-gone",
            "HOST;x-amz-date",
            "host;;x-amz-date",
            "host; x-amz-date",
        ] {
            assert_eq!(block(raw, &map), Err(AuthError::SignatureDoesNotMatch), "{raw}");
        }
        let mut unreadable = HeaderMap::new();
        unreadable.insert(
            http::HeaderName::from_static("x-amz-meta-c"),
            http::HeaderValue::from_bytes(b"\xff").expect("obs-text is a header value"),
        );
        assert_eq!(block("host;x-amz-meta-c", &unreadable), Err(AuthError::SignatureDoesNotMatch));
    }
}
