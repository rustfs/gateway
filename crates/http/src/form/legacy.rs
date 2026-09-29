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

//! The legacy RustFS form grammar: the request's boundary, and what one part's header block says,
//! read the way the POST Object parser RustFS serves today reads them.
//!
//! Responsible for: [`FormGrammar::LegacyRustfs`](super::FormGrammar::LegacyRustfs)'s reading of
//! the `Content-Type` boundary parameter and of a located part header block — which header fields
//! are read, which `Content-Disposition` wins, how parameter values are delimited, which bytes
//! must be UTF-8, and where the part's content starts.
//! NOT responsible for: the gateway's own grammar (`super::parse_boundary` and
//! `super::parse_disposition`, unchanged), finding or bounding a header block
//! (`super::reader`), the field rules and ceilings, or what a filename means to a policy
//! (`rustfs-gateway-sig`).
//! Upstream: `super::reader`. Downstream: none.
//!
//! # The reference
//!
//! RustFS main serves POST Object through the S3 stack its `Cargo.toml` pins at `0.17.0`
//! (rustfs/rustfs `Cargo.toml:318` at `1e7065101d`), and ruling R8 of rustfs/backlog#1677 (as
//! amended on 2026-09-29) is that the RustFS profile reads a form exactly as that stack does, in
//! both directions. Each rule below is that stack's observed behaviour, written here from the
//! behaviour and checked against it by running both parsers over the same bytes; where the
//! behaviour is questionable it is marked `Legacy-compat (rustfs/backlog#2684)` with the intended
//! future behaviour.

use super::{FormReject, MAX_BOUNDARY_BYTES};
use crate::text::{is_tchar, trim_ows};

/// How many header fields of a part are read.
///
/// Legacy-compat (rustfs/backlog#2684): the legacy stack reads only a part's first three header
/// fields, so a `Content-Disposition` in fourth place is never seen and the part is refused as
/// nameless, and lines after the fourth are not even checked for well-formedness. RFC 7578 sets no
/// such limit; the intended future behaviour is to read every field of a bounded header block.
const READ_FIELDS: usize = 3;

// ── the request's Content-Type ────────────────────────────────────────────────────────────────

/// Extracts the boundary from a `Content-Type` the way the legacy stack does, or refuses it.
///
/// The media type is compared case-insensitively. Parameters follow `;` with optional spaces
/// before their name; a name is a token followed directly by `=`; a value is a token, or a quoted
/// string that runs to the next `"` with no escapes and is followed only by spaces before the
/// next `;`. The first `boundary` parameter is the boundary, and it must be one to seventy RFC 2046
/// `bchars` that do not end in a space.
///
/// Legacy-compat (rustfs/backlog#2684): the legacy header reader refuses whitespace RFC 9110
/// allows (before a `;`, a tab after it) and so never reads such a request as a form; and of two
/// `boundary` parameters it takes the first, where two readers of one header could frame the body
/// two ways. The intended future behaviour is RFC 9110's parameter grammar with a repeated
/// `boundary` refused, as [`FormGrammar::Gateway`](super::FormGrammar::Gateway) does.
pub(super) fn boundary(content_type: &str) -> Result<&str, FormReject> {
    let bytes = content_type.as_bytes();
    let mut at = 0;
    let slash = token_end(bytes, at);
    if slash == at || bytes.get(slash) != Some(&b'/') {
        return Err(FormReject::MalformedContentType);
    }
    let media_type = content_type.get(..slash).unwrap_or_default();
    at = slash.saturating_add(1);
    let subtype_end = token_end(bytes, at);
    if subtype_end == at {
        return Err(FormReject::MalformedContentType);
    }
    let subtype = content_type.get(at..subtype_end).unwrap_or_default();
    // A `+suffix` is part of the token; the legacy reader names the subtype without its last one.
    let subtype = subtype.rsplit_once('+').map_or(subtype, |(name, _)| name);
    if !media_type.eq_ignore_ascii_case("multipart") || !subtype.eq_ignore_ascii_case("form-data") {
        return Err(FormReject::MalformedContentType);
    }
    at = subtype_end;
    let mut found = None;
    while at < bytes.len() {
        if bytes.get(at) != Some(&b';') {
            return Err(FormReject::MalformedContentType);
        }
        at = at.saturating_add(1);
        while bytes.get(at) == Some(&b' ') {
            at = at.saturating_add(1);
        }
        if at == bytes.len() {
            break;
        }
        let name_end = token_end(bytes, at);
        if name_end == at || bytes.get(name_end) != Some(&b'=') {
            return Err(FormReject::MalformedContentType);
        }
        let name = content_type.get(at..name_end).unwrap_or_default();
        at = name_end.saturating_add(1);
        let value = if bytes.get(at) == Some(&b'"') {
            // The closing quote is the first one after the value's first byte: a quote right
            // after the opening one is content, so `""` never closes an empty value.
            let start = at.saturating_add(1);
            let close = bytes
                .get(start.saturating_add(1)..)
                .and_then(|rest| rest.iter().position(|&byte| byte == b'"'))
                .map(|offset| start.saturating_add(1).saturating_add(offset))
                .ok_or(FormReject::MalformedContentType)?;
            let quoted = bytes.get(start..close).unwrap_or_default();
            if quoted.iter().any(|&byte| byte < 0x20 || byte == 0x7f) {
                return Err(FormReject::MalformedContentType);
            }
            at = close.saturating_add(1);
            while bytes.get(at) == Some(&b' ') {
                at = at.saturating_add(1);
            }
            content_type.get(start..close).unwrap_or_default()
        } else {
            let end = token_end(bytes, at);
            // An empty bare value is only accepted at the very end of the header.
            if end == at && end < bytes.len() {
                return Err(FormReject::MalformedContentType);
            }
            let value = content_type.get(at..end).unwrap_or_default();
            at = end;
            value
        };
        if found.is_none() && name.eq_ignore_ascii_case("boundary") {
            found = Some(value);
        }
    }
    let boundary = found.ok_or(FormReject::MalformedContentType)?;
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_BYTES || boundary.ends_with(' ') || !boundary.bytes().all(is_bchar) {
        return Err(FormReject::MalformedContentType);
    }
    Ok(boundary)
}

/// Where the token that starts at `start` ends.
fn token_end(bytes: &[u8], start: usize) -> usize {
    let length = bytes
        .get(start..)
        .map_or(0, |rest| rest.iter().take_while(|byte| is_tchar(**byte)).count());
    start.saturating_add(length)
}

/// An RFC 2046 `bchars` byte.
fn is_bchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&byte)
}

// ── one part's header block ───────────────────────────────────────────────────────────────────

/// What a part's header block says.
#[derive(Debug)]
pub(super) struct PartHead {
    /// The part's name exactly as sent: not yet lowercased, possibly empty.
    pub(super) name: String,
    /// The `filename` parameter, when the disposition that named the part carried one.
    pub(super) filename: Option<String>,
    /// How many bytes of the block are header; the bytes after them are the part's content.
    ///
    /// Legacy-compat (rustfs/backlog#2684): header lines may end in a bare LF, and a bare-LF blank
    /// line ends the header there — before the CRLF CRLF that located the block, whose bytes then
    /// become content. RFC 2046 lines end in CRLF; the intended future behaviour is to refuse a
    /// bare LF.
    pub(super) content_start: usize,
}

/// Reads a part's header block: everything from the end of its boundary line up to and including
/// the first CRLF CRLF.
///
/// Header fields are read with the HTTP field grammar (a token name directly followed by `:`, no
/// folded lines, no control byte other than a tab in a value). When a part carries more than
/// [`READ_FIELDS`] fields, the first four are still checked that way and the first three are then
/// read line by line.
///
/// # Errors
///
/// [`FormReject::MalformedPart`] when the block is empty, a header field it checks is malformed, a
/// field name it reads is not UTF-8, a `Content-Disposition` it reads carries a `name` or a
/// `filename` that is not UTF-8, a `Content-Type` it reads is not UTF-8, or the last disposition it
/// reads names nothing.
pub(super) fn part_head(block: &[u8]) -> Result<PartHead, FormReject> {
    let mut storage = [httparse::EMPTY_HEADER; READ_FIELDS];
    let mut fields: [(&[u8], &[u8]); READ_FIELDS] = [(&[], &[]); READ_FIELDS];
    let (count, content_start) = match httparse::parse_headers(block, &mut storage) {
        Ok(httparse::Status::Complete((content_start, parsed))) => {
            for (slot, header) in fields.iter_mut().zip(parsed) {
                *slot = (header.name.as_bytes(), header.value);
            }
            (parsed.len(), content_start)
        }
        Err(httparse::Error::TooManyHeaders) => (first_lines(block, &mut fields)?, block.len()),
        Ok(httparse::Status::Partial) | Err(_) => return Err(FormReject::MalformedPart),
    };

    let mut name = None;
    let mut filename = None;
    for &(field, value) in fields.iter().take(count) {
        let field = utf8(field)?;
        if field.eq_ignore_ascii_case("content-disposition") {
            // Legacy-compat (rustfs/backlog#2684): the last disposition decides, even one that
            // names nothing and so unnames a part an earlier one named; every one read must still
            // spell its name and filename in UTF-8. The intended future behaviour is to refuse a
            // part with two dispositions.
            let disposition = content_disposition(value);
            name = disposition.and_then(|disposition| disposition.name).map(utf8).transpose()?;
            filename = disposition
                .and_then(|disposition| disposition.filename)
                .map(utf8)
                .transpose()?;
        } else if field.eq_ignore_ascii_case("content-type") {
            utf8(value)?;
        }
    }
    let Some(name) = name else {
        return Err(FormReject::MalformedPart);
    };
    Ok(PartHead {
        name: name.to_owned(),
        filename: filename.map(str::to_owned),
        content_start,
    })
}

/// Reads the first [`READ_FIELDS`] CRLF-terminated lines of a block that holds more fields than
/// that, returning how many it read: each is split at its first colon, the name before it must
/// not be empty, and the value after it is trimmed of spaces and tabs.
fn first_lines<'a>(block: &'a [u8], fields: &mut [(&'a [u8], &'a [u8]); READ_FIELDS]) -> Result<usize, FormReject> {
    let Some(mut rest) = block.strip_suffix(b"\r\n\r\n") else {
        return Err(FormReject::MalformedPart);
    };
    let mut count = 0usize;
    for slot in fields.iter_mut() {
        if rest.is_empty() {
            break;
        }
        let (line, next) = match super::find(rest, b"\r\n") {
            Some(end) => (rest.get(..end).unwrap_or_default(), rest.get(end.saturating_add(2)..).unwrap_or_default()),
            None => (rest, &[][..]),
        };
        let Some(colon) = memchr::memchr(b':', line) else {
            return Err(FormReject::MalformedPart);
        };
        let field = line.get(..colon).unwrap_or_default();
        if field.is_empty() {
            return Err(FormReject::MalformedPart);
        }
        *slot = (field, trim_ows(line.get(colon.saturating_add(1)..).unwrap_or_default()));
        count = count.saturating_add(1);
        rest = next;
    }
    Ok(count)
}

/// The two parameters of a `form-data` disposition that matter, as raw bytes.
#[derive(Clone, Copy, Debug)]
struct Disposition<'a> {
    name: Option<&'a [u8]>,
    filename: Option<&'a [u8]>,
}

/// Reads a `Content-Disposition` value, or `None` when its type is not `form-data`.
///
/// The type and the parameter names are case-insensitive, parameters come in any order, values
/// may be quoted or bare, the first `name` and the first `filename` win, and every other parameter
/// — `filename*` among them — is ignored.
///
/// Legacy-compat (rustfs/backlog#2684): the first parameter that cannot be read ends the reading
/// without failing it, so what was read before it stands and everything after it is dropped. The
/// intended future behaviour is to refuse a malformed disposition.
fn content_disposition(value: &[u8]) -> Option<Disposition<'_>> {
    let value = trim_ows(value);
    let (kind, mut rest) = match memchr::memchr(b';', value) {
        Some(semicolon) => (
            trim_ows(value.get(..semicolon).unwrap_or_default()),
            value.get(semicolon.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (value, &[][..]),
    };
    if !kind.eq_ignore_ascii_case(b"form-data") {
        return None;
    }
    let mut disposition = Disposition {
        name: None,
        filename: None,
    };
    while !trim_ows(rest).is_empty() {
        let Some((key, value, next)) = parameter(rest) else {
            break;
        };
        if key.eq_ignore_ascii_case(b"name") {
            disposition.name.get_or_insert(value);
        } else if key.eq_ignore_ascii_case(b"filename") {
            disposition.filename.get_or_insert(value);
        }
        rest = next;
    }
    Some(disposition)
}

/// Reads one `key=value` parameter from the front of `input`, returning it and what follows it:
/// `None` for an empty key or an unterminated quote.
///
/// A quoted value runs to its closing quote, and anything between that quote and the next `;` is
/// dropped; a bare value runs to the next `;` and is trimmed.
///
/// Legacy-compat (rustfs/backlog#2684): the key is everything before the first `=`, so a bare word
/// with no `=` of its own swallows the text up to the next parameter's `=` — `form-data; junk;
/// name="a"` names nothing. The intended future behaviour is to refuse the bare word.
fn parameter(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let input = trim_ows(input);
    let equals = memchr::memchr(b'=', input)?;
    let key = trim_ows(input.get(..equals).unwrap_or_default());
    if key.is_empty() {
        return None;
    }
    let raw = trim_ows(input.get(equals.saturating_add(1)..).unwrap_or_default());
    if raw.first() == Some(&b'"') {
        let (value, after) = quoted(raw)?;
        let next = match memchr::memchr(b';', after) {
            Some(semicolon) => after.get(semicolon.saturating_add(1)..).unwrap_or_default(),
            None => &[],
        };
        return Some((key, value, next));
    }
    match memchr::memchr(b';', raw) {
        Some(semicolon) => Some((
            key,
            trim_ows(raw.get(..semicolon).unwrap_or_default()),
            raw.get(semicolon.saturating_add(1)..).unwrap_or_default(),
        )),
        None => Some((key, trim_ows(raw), &[])),
    }
}

/// Splits a quoted string off `raw`, which starts with `"`, returning its content and what
/// follows the closing quote; `None` when no unescaped quote closes it.
///
/// Legacy-compat (rustfs/backlog#2684): a backslash escape ends nothing but is kept as sent, so
/// `filename="a\"b.txt"` names the file `a\"b.txt`, backslash included. RFC 2046 quoted strings
/// are decoded; the intended future behaviour is to decode the escape.
fn quoted(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut escaped = false;
    for (index, &byte) in raw.iter().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some((raw.get(1..index)?, raw.get(index.saturating_add(1)..)?));
        }
    }
    None
}

/// The bytes as UTF-8 text, or the part is malformed.
fn utf8(bytes: &[u8]) -> Result<&str, FormReject> {
    core::str::from_utf8(bytes).map_err(|_| FormReject::MalformedPart)
}

#[cfg(test)]
mod tests {
    use super::{boundary, content_disposition, parameter, trim_ows};
    use crate::FormReject;

    /// A disposition's `name` and `filename`, or `None` when it is not `form-data`.
    type Read<'a> = Option<(Option<&'a [u8]>, Option<&'a [u8]>)>;

    fn read(value: &[u8]) -> Read<'_> {
        content_disposition(value).map(|disposition| (disposition.name, disposition.filename))
    }

    /// Boundary — only a space or a tab is trimmed; CR, LF, and other controls are content.
    #[test]
    fn only_spaces_and_tabs_are_trimmed() {
        assert_eq!(trim_ows(b" \t a \t "), b"a");
        assert_eq!(trim_ows(b"\r\na\x0b"), b"\r\na\x0b");
        assert_eq!(trim_ows(b"   "), b"");
    }

    /// Boundary — an empty key or an unterminated quote is not a parameter; an empty value is.
    #[test]
    fn parameter_edges() {
        assert_eq!(parameter(b"=x"), None);
        assert_eq!(parameter(b"name=\"x"), None);
        assert_eq!(parameter(b"name="), Some((&b"name"[..], &b""[..], &b""[..])));
        assert_eq!(parameter(b"name=\"\""), Some((&b"name"[..], &b""[..], &b""[..])));
        assert_eq!(parameter(b" a b = c d ; e"), Some((&b"a b"[..], &b"c d"[..], &b" e"[..])));
    }

    /// Boundary — a parameter after a malformed one is never reached.
    #[test]
    fn reading_stops_at_the_first_malformed_parameter() {
        assert_eq!(read(b"form-data; name=\"a\"; junk; filename=\"b\""), Some((Some(&b"a"[..]), None)));
        assert_eq!(read(b"form-data; filename=\"b\"; name=\"a"), Some((None, Some(&b"b"[..]))));
    }

    /// Boundary — the media type, the parameter grammar and the boundary's characters.
    #[test]
    fn content_type_edges() {
        for (content_type, expected) in [
            ("multipart/form-data;boundary=a", Ok("a")),
            ("Multipart/Form-Data; BOUNDARY=a", Ok("a")),
            ("multipart/form-data+x; boundary=a", Ok("a")),
            ("multipart/form-data;  boundary=\"a b\" ;charset=x", Ok("a b")),
            ("multipart/form-data; boundary=a; boundary=b", Ok("a")),
            ("multipart/form-data; boundary=a;", Ok("a")),
            ("multipart/form-data", Err(FormReject::MalformedContentType)),
            ("multipart/mixed; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data ; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data;\tboundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary =a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=a ", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; x; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=\"a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=\"a\"x", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=a*b", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=\"a@b\"", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=\"a \"", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; boundary=", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; x=; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; x=\"\"; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data; x=\"\"\"; boundary=a", Ok("a")),
            ("multipart/form-data; boundary=a; x=", Ok("a")),
            ("multipart/form-data+a+b; boundary=a", Err(FormReject::MalformedContentType)),
            ("multipart/form-data+; boundary=a", Ok("a")),
            ("multipart/+form-data; boundary=a", Err(FormReject::MalformedContentType)),
        ] {
            assert_eq!(boundary(content_type), expected, "{content_type}");
        }
    }
}
