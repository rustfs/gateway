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

//! The `success_action_redirect` builder for POST Object (Q7).
//!
//! Responsible for: turning an authored redirect URL into a `Location` value that carries the
//! bucket, key, and entity tag, refusing every URL a browser could not be sent to safely.
//! NOT responsible for: policy parsing, signature verification, or emitting the response.
//! Upstream: `post_policy`. Downstream: nothing; the string is handed to the caller.

use super::PostPolicyError;

/// Q7: Safe construction of `success_action_redirect`.
///
/// Rules:
/// 1. Only `http` and `https` schemes are allowed.
/// 2. Control characters (including CR, LF) are rejected.
/// 3. The authority must be present and well-formed: a non-empty RFC 3986 `reg-name` or a
///    bracketed IP literal, an optional all-digit port, and no userinfo. `https:///path` has no
///    host to redirect to, and `user@host` lets a naive port split read one host while a browser
///    goes to another, so both are refused rather than left for the caller to notice.
/// 4. `bucket`, `key`, and `etag` are appended as query parameters.
/// 5. Parameters are inserted **before** any existing fragment.
/// 6. An optional host allowlist is checked against the host alone, without its port.
/// 7. Validation failure returns 400, **never** falls back to `success_action_status`.
///
/// The result is a `Location` value the caller can emit as-is; nothing here needs re-checking.
///
/// # Errors
///
/// [`PostPolicyError::Malformed`] when the URL is invalid, has a disallowed scheme, contains
/// control characters, has a missing or malformed authority, or the host is not in the allowlist.
pub fn build_success_action_redirect(
    raw: &str,
    bucket: &str,
    key: &str,
    etag: &str,
    allowed_hosts: Option<&[&str]>,
) -> Result<String, PostPolicyError> {
    // Reject control characters (CR, LF, NUL, etc.) before URL parsing.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PostPolicyError::Malformed);
    }

    // Parse the URL. We use a simple manual parse to avoid adding a `url` crate dependency
    // for this single use case. The URL must start with http:// or https://.
    let scheme_end = raw.find("://").ok_or(PostPolicyError::Malformed)?;
    let scheme = &raw[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(PostPolicyError::Malformed);
    }

    // The authority runs from the scheme separator to the first path, query, or fragment
    // delimiter. It must be present and well-formed, and the host alone is what the allowlist
    // compares.
    let after_scheme = &raw[scheme_end + 3..];
    let authority_end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    let host = authority_host(&after_scheme[..authority_end]).ok_or(PostPolicyError::Malformed)?;

    if let Some(allowed) = allowed_hosts
        && !allowed.iter().any(|h| h.eq_ignore_ascii_case(host))
    {
        return Err(PostPolicyError::Malformed);
    }

    // Build the redirect URL with bucket, key, and etag as query parameters.
    // Parameters must be inserted before any fragment.
    let (base, fragment) = match raw.find('#') {
        Some(pos) => (&raw[..pos], Some(&raw[pos..])),
        None => (raw, None),
    };

    let separator = if base.contains('?') { '&' } else { '?' };
    let mut result = String::with_capacity(base.len() + 128);
    result.push_str(base);
    result.push(separator);
    result.push_str("bucket=");
    push_percent_encoded(&mut result, bucket.as_bytes());
    result.push_str("&key=");
    push_percent_encoded(&mut result, key.as_bytes());
    result.push_str("&etag=");
    push_percent_encoded(&mut result, etag.as_bytes());

    if let Some(frag) = fragment {
        result.push_str(frag);
    }

    Ok(result)
}

/// Splits an RFC 3986 `authority` into its host, refusing anything a redirect target cannot use.
///
/// Accepts `host` and `host:port` where the host is a non-empty `reg-name` (unreserved,
/// percent-encoded, and sub-delimiter characters) or a bracketed IP literal, and the port is any
/// run of digits, possibly empty as the grammar allows. Refuses an empty authority, userinfo, a
/// non-digit port, an unterminated or empty bracket, and any character outside the grammar.
/// Returns the host with its port removed, brackets kept, so an allowlist entry names it the way
/// the URL spells it.
fn authority_host(authority: &str) -> Option<&str> {
    // Userinfo needs no check of its own: `@` is not a `reg-name` byte, and after a bracketed
    // literal only a port may follow, so `user@host` and `[::1]@host` fail the grammar below.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let literal = &rest[..close];
        if literal.is_empty() || !literal.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.')) {
            return None;
        }
        let host = &authority[..close + 2];
        match &rest[close + 1..] {
            "" => (host, None),
            after => (host, Some(after.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    if !host.starts_with('[') && !host.bytes().all(is_reg_name_byte) {
        return None;
    }
    if port.is_some_and(|port| !port.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(host)
}

/// RFC 3986 `reg-name` characters: `unreserved`, the `%` of a percent-encoded octet, and
/// `sub-delims`.
fn is_reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'_' | b'~' | b'%' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        )
}

/// Percent-encodes bytes into the output string using RFC 3986 unreserved rules.
fn push_percent_encoded(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}
