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

//! Responsible for: the credential fields of a browser-upload (`PostObject`) form — the
//! `multipart/form-data` fields that carry the POST-policy signature, its credential scope, a
//! SigV2 signature or a session token — finding a live one, rewriting its value to the
//! placeholder, and proving a claimed rewrite.
//! Not responsible for: any other body content, which stays a refusal; see `redact`.
//! Upstream: `redact::scan`, `redact::sanitize` and the redaction-claim check.
//! Downstream: nothing; this module only reads and rewrites `schema::Entry` bodies.
//!
//! A form field is spelled `name="x-amz-signature"` followed by a blank line and the value, so
//! none of the text rules sees it: there is no `Signature=` for the SigV4 rule, and a SigV2
//! signature is 28 base64 characters, far short of the 40 the secret-key rule looks for. Without
//! this module a live POST-policy signature sailed through the gate.
//!
//! The field name is found under every spelling a form reader in this workspace accepts, not only
//! the quoted one: the RustFS profile reads forms with the legacy RustFS grammar, which also takes
//! `name=x-amz-signature` bare, `name = "..."`, and `NAME=` in any case, so a recording of such a
//! form carries its credential under one of those spellings.

use crate::base64;
use crate::redact::PLACEHOLDER;
use crate::schema::{Chunk, Entry};

/// Form fields that carry credential material, matched case-insensitively. A `redacted` record
/// names one as `form:<field>`.
pub const SENSITIVE_FORM_FIELDS: &[&str] = &[
    "awsaccesskeyid",
    "signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
];

/// The prefix of a `redacted` record naming a form field.
pub const RECORD_PREFIX: &str = "form:";

/// One form field value's location in a body.
struct Field {
    /// The lowercased field name.
    name: String,
    /// Byte range of the value.
    start: usize,
    end: usize,
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() || from > haystack.len() - needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// Whether `byte` is the optional whitespace a form reader skips around a parameter's `=`.
fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// The field name a `name` parameter whose `name` ends at `at` gives, as `(start, end)`.
/// `None` when no `=` follows, and `Err` for an unterminated quoted value.
///
/// Every spelling a form reader in this workspace accepts is read, so a credential is found
/// whichever one recorded it: the quoted value, and — as the RustFS profile's legacy form grammar
/// also reads it — a bare value running to the next `;` or line end, whitespace around `=`, and
/// the parameter name in any case. The caller supplies only the current header parameter, so a
/// quote cannot close in another header or part.
fn name_value(bytes: &[u8], at: usize) -> Option<Result<(usize, usize), ()>> {
    let mut index = at;
    while bytes.get(index).copied().is_some_and(is_ows) {
        index += 1;
    }
    if bytes.get(index) != Some(&b'=') {
        return None;
    }
    index += 1;
    while bytes.get(index).copied().is_some_and(is_ows) {
        index += 1;
    }
    if bytes.get(index) == Some(&b'"') {
        let start = index + 1;
        return Some(match bytes[start..].iter().position(|byte| *byte == b'"') {
            Some(len) => Ok((start, start + len)),
            None => Err(()),
        });
    }
    let len = bytes[index..]
        .iter()
        .position(|byte| matches!(byte, b';' | b'\r' | b'\n'))
        .unwrap_or(bytes.len() - index);
    let mut end = index + len;
    while end > index && is_ows(bytes[end - 1]) {
        end -= 1;
    }
    Some(Ok((index, end)))
}

/// The end of one disposition parameter; only a value starting with a quote is quoted.
/// Bytes after its closing quote do not turn a later separator into quoted content.
fn parameter_end(line: &[u8], from: usize) -> usize {
    let end = find(line, b";", from).unwrap_or(line.len());
    let Some(equals) = line[from..end].iter().position(|byte| *byte == b'=') else {
        return end;
    };
    let mut index = from + equals + 1;
    while line.get(index).copied().is_some_and(is_ows) {
        index += 1;
    }
    if line.get(index) != Some(&b'"') {
        return end;
    }
    index += 1;
    while index < line.len() {
        match line[index] {
            b'\\' if index + 1 < line.len() => index += 1,
            b'"' => return find(line, b";", index + 1).unwrap_or(line.len()),
            _ => {}
        }
        index += 1;
    }
    line.len()
}

/// A credential-bearing `name` parameter on this Content-Disposition header line.
fn sensitive_name(line: &[u8]) -> Option<String> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    if !line[..colon].trim_ascii().eq_ignore_ascii_case(b"content-disposition") {
        return None;
    }
    let mut from = colon + 1;
    while from < line.len() {
        let end = parameter_end(line, from);
        let parameter = line[from..end].trim_ascii();
        if parameter.get(..4).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"name"))
            && let Some(Ok((start, end))) = name_value(parameter, 4)
        {
            let name = String::from_utf8_lossy(&parameter[start..end]).to_ascii_lowercase();
            if SENSITIVE_FORM_FIELDS.contains(&name.as_str()) {
                return Some(name);
            }
        }
        if end == line.len() {
            break;
        }
        from = end + 1;
    }
    None
}

/// The earliest blank line, including the bare-LF spelling accepted by the RustFS profile.
fn header_separator(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    [b"\r\n\r\n".as_slice(), b"\n\n", b"\n\r\n"]
        .into_iter()
        .filter_map(|separator| find(bytes, separator, from).map(|at| (at, at + separator.len())))
        .min_by_key(|(at, _)| *at)
}

/// Every sensitive form field in `bytes`, located structurally: a `Content-Disposition` line
/// naming the field, then the blank line that ends the part head, then the value up to the
/// CRLF that precedes the next boundary.
fn sensitive_fields(bytes: &[u8]) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut from = 0;
    while let Some((head_end, start)) = header_separator(bytes, from) {
        // An incomplete head cannot borrow the next part's header separator or body.
        if let Some(boundary) = find(bytes, b"\r\n--", from)
            && boundary < head_end
        {
            from = boundary + 2;
            continue;
        }
        let end = find(bytes, b"\r\n--", start).unwrap_or(bytes.len());
        if let Some(name) = bytes[from..head_end].split(|byte| *byte == b'\n').find_map(sensitive_name) {
            fields.push(Field { name, start, end });
        }
        if end == bytes.len() {
            break;
        }
        from = end + 2;
    }
    fields
}

/// Whether the request head declares a multipart form body.
pub fn declares_form(entry: &Entry) -> bool {
    entry
        .header_values("content-type")
        .any(|value| value.trim_start().to_ascii_lowercase().starts_with("multipart/form-data"))
}

/// Whether `text` holds a sensitive form field whose value is neither empty nor the placeholder.
///
/// Applied to every body regardless of its declared type: a live signature in a form-shaped body
/// is refused whatever the head claims.
pub fn has_live_form_credential(text: &str) -> bool {
    let bytes = text.as_bytes();
    sensitive_fields(bytes).iter().any(|field| {
        let value = &bytes[field.start..field.end];
        !value.is_empty() && value != PLACEHOLDER.as_bytes()
    })
}

/// Rewrite every sensitive form field of a declared multipart body to the placeholder, returning
/// the `redacted` record names touched.
///
/// A body whose head does not declare `multipart/form-data` is left alone: the text is then not
/// provably a form field, and the gate refuses it.
pub fn sanitize_body(entry: &mut Entry) -> Vec<String> {
    if !declares_form(entry) {
        return Vec::new();
    }
    let mut touched: Vec<String> = Vec::new();
    for chunk in entry.chunks.iter_mut().flatten() {
        let Chunk::Data { bytes_b64, .. } = chunk else {
            continue;
        };
        let Ok(mut bytes) = base64::decode(bytes_b64) else {
            continue;
        };
        let mut changed = false;
        // Back to front, so an earlier range stays valid after a later one is replaced.
        for field in sensitive_fields(&bytes).into_iter().rev() {
            if bytes[field.start..field.end] == *PLACEHOLDER.as_bytes() || field.start == field.end {
                continue;
            }
            bytes.splice(field.start..field.end, PLACEHOLDER.bytes());
            changed = true;
            let record = format!("{RECORD_PREFIX}{}", field.name);
            if !touched.contains(&record) {
                touched.push(record);
            }
        }
        if changed {
            *bytes_b64 = base64::encode(&bytes);
        }
    }
    touched
}

/// Whether a `form:<field>` record describes the entry: the head declares a form, and some data
/// chunk carries that field holding the placeholder.
pub fn claim_holds(entry: &Entry, claimed: &str) -> bool {
    let Some(field) = claimed.get(RECORD_PREFIX.len()..).filter(|_| is_form_record(claimed)) else {
        return false;
    };
    let field = field.to_ascii_lowercase();
    if !declares_form(entry) {
        return false;
    }
    entry.chunks.iter().flatten().any(|chunk| match chunk {
        Chunk::Data { bytes_b64, .. } => base64::decode(bytes_b64).is_ok_and(|bytes| {
            sensitive_fields(&bytes)
                .iter()
                .any(|found| found.name == field && bytes[found.start..found.end] == *PLACEHOLDER.as_bytes())
        }),
        Chunk::Control { .. } => false,
    })
}

/// Whether `claimed` is a `form:<field>` record.
pub fn is_form_record(claimed: &str) -> bool {
    claimed
        .get(..RECORD_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RECORD_PREFIX))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{claim_holds, has_live_form_credential, sanitize_body};
    use crate::base64;
    use crate::redact::{self, PLACEHOLDER};
    use crate::schema::{self, Capture, Chunk, Entry, Sut};

    const SIG: &str = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";

    fn form(fields: &[(&str, &str)]) -> String {
        let mut body = String::new();
        for (name, value) in fields {
            body.push_str(&format!("--xyz\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        body.push_str("--xyz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhello\r\n--xyz--\r\n");
        body
    }

    fn entry(content_type: &str, body: &str) -> Entry {
        Entry {
            v: schema::CORPUS_SCHEMA_VERSION,
            op: "PostObject".to_owned(),
            src: "handwritten:gateway".to_owned(),
            recorded: "2026-09-28".to_owned(),
            capture: Capture::HeadFull,
            sut: Sut::None,
            method: "POST".to_owned(),
            target: "/bucket".to_owned(),
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            chunks: Some(vec![Chunk::Data {
                bytes_b64: base64::encode(body.as_bytes()),
                delay_ms: None,
            }]),
            resp: None,
            redacted: Vec::new(),
        }
    }

    fn sigv4_form() -> String {
        form(&[
            ("key", "uploads/a.txt"),
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", "compatmatrixkey/20260928/us-east-1/s3/aws4_request"),
            ("X-Amz-Date", "20260928T000000Z"),
            ("Policy", "eyJleHBpcmF0aW9uIjoiMjAyNi0wOS0yOVQwMDowMDowMFoifQ=="),
            ("X-Amz-Signature", SIG),
        ])
    }

    fn body_text(entry: &Entry) -> String {
        match entry.chunks.as_deref() {
            Some([Chunk::Data { bytes_b64, .. }]) => String::from_utf8(base64::decode(bytes_b64).unwrap()).unwrap(),
            other => panic!("expected one data chunk, got {other:?}"),
        }
    }

    /// Negative — a live POST-policy signature in a form body is refused. Before this module the
    /// gate admitted it.
    #[test]
    fn a_live_post_policy_signature_is_refused() {
        let posted = entry("multipart/form-data; boundary=xyz", &sigv4_form());
        assert!(has_live_form_credential(&sigv4_form()));
        assert!(redact::admit(&posted).is_err());
    }

    /// Negative — a SigV2 form signature (28 base64 characters, too short for the secret-key
    /// rule) and its access key id are refused too.
    #[test]
    fn a_live_sigv2_form_signature_is_refused() {
        let body = form(&[
            ("AWSAccessKeyId", "compatmatrixkey"),
            ("signature", "0RavWzkygo6QX9caELEqKi9kDbU="),
        ]);
        assert!(redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err());
    }

    /// Negative — the same fields in a body whose head does not declare a form are not rewritten,
    /// and stay a refusal.
    #[test]
    fn an_undeclared_form_is_never_rewritten() {
        let mut posted = entry("application/octet-stream", &sigv4_form());
        let before = posted.clone();
        assert!(sanitize_body(&mut posted).is_empty());
        assert_eq!(posted, before);
        assert!(redact::admit(&posted).is_err());
    }

    /// Negative — a `form:` record over a live value is a laundering record and is refused.
    #[test]
    fn a_form_claim_over_a_live_value_is_refused() {
        let mut posted = entry("multipart/form-data; boundary=xyz", &sigv4_form());
        posted.redacted = vec!["form:x-amz-signature".to_owned()];
        assert!(!claim_holds(&posted, "form:x-amz-signature"));
        assert!(redact::admit(&posted).is_err());
    }

    /// Negative — a `form:` record naming a field that is not credential-bearing proves nothing.
    #[test]
    fn a_form_claim_for_an_ordinary_field_is_refused() {
        let body = form(&[("key", PLACEHOLDER)]);
        let mut posted = entry("multipart/form-data; boundary=xyz", &body);
        posted.redacted = vec!["form:key".to_owned()];
        assert!(redact::admit(&posted).is_err());
    }

    /// A form whose every field is named by `disposition`, a `Content-Disposition` header line
    /// spelled the way a client chose to, with `{name}` standing for the field name.
    fn form_spelled(disposition: &str, fields: &[(&str, &str)]) -> String {
        let mut body = String::new();
        for (name, value) in fields {
            let line = disposition.replace("{name}", name);
            body.push_str(&format!("--xyz\r\n{line}\r\n\r\n{value}\r\n"));
        }
        body.push_str("--xyz\r\nContent-Disposition: form-data; name=file; filename=a.txt\r\n\r\nhello\r\n--xyz--\r\n");
        body
    }

    #[test]
    fn n_benign_content_cannot_hide_a_later_quoted_form_credential() {
        let body = form(&[
            ("key", "hello name = \"ordinary text"),
            ("signature", "0RavWzkygo6QX9caELEqKi9kDbU="),
        ]);
        assert!(has_live_form_credential(&body));
        assert!(redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err());
    }

    const SIGV2: &str = "0RavWzkygo6QX9caELEqKi9kDbU=";

    /// Negative — unrelated or malformed parameters may not hide the next part's credential.
    #[test]
    fn n_unrelated_headers_cannot_hide_a_later_credential() {
        for head in [
            "Content-Disposition: form-data; name=\"unfinished",
            "Content-Disposition: form-data; name=\"key\"; filename=\"name = \\\"unfinished",
            "X-Note: name = \"unfinished\r\nContent-Disposition: form-data; name=key",
            "Content-Disposition: form-data; filename=\"x; name=signature\"; name=key",
        ] {
            let body = format!("--xyz\r\n{head}\r\n\r\nordinary text\r\n{}", form(&[("signature", SIGV2)]));
            assert!(has_live_form_credential(&body), "a preceding header hid the next credential");
        }
    }

    /// Negative — admission must independently refuse the credential after unrelated body text.
    #[test]
    fn n_admission_refuses_a_credential_after_unrelated_body_text() {
        let body = form(&[("key", "hello name = \"ordinary text"), ("signature", SIGV2)]);
        assert!(redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err());
    }

    /// Negative — a filename, a longer parameter name or another header is not a field name.
    #[test]
    fn n_non_name_parameters_and_headers_are_not_credential_fields() {
        for head in [
            "Content-Disposition: form-data; filename=signature",
            "Content-Disposition: form-data; x-name=signature",
            "Content-Disposition: form-data; filename=\"x; name=signature; ignored\"; name=key",
            "Content-Disposition: form-data; filename=\"x\\\"; name=signature; ignored\"; name=key",
            "X-Note: name=signature\r\nContent-Disposition: form-data; name=key",
        ] {
            let body = format!("--xyz\r\n{head}\r\n\r\nordinary value\r\n--xyz--\r\n");
            let mut posted = entry("multipart/form-data; boundary=xyz", &body);
            let detected = has_live_form_credential(&body);
            let touched = sanitize_body(&mut posted);
            assert!(
                !detected && touched.is_empty() && body_text(&posted) == body,
                "an unrelated parameter or header was treated as a credential field"
            );
        }
    }

    /// Negative — body text cannot establish a claimed rewrite, even if it looks like a header.
    #[test]
    fn n_body_text_cannot_prove_a_form_redaction_claim() {
        for text in [
            "name=signature\r\n\r\n__REDACTED__",
            "Content-Disposition: form-data; name=signature\r\n\r\n__REDACTED__",
        ] {
            let body = form(&[("key", text)]);
            let mut posted = entry("multipart/form-data; boundary=xyz", &body);
            posted.redacted = vec!["form:signature".to_owned()];
            assert!(
                !claim_holds(&posted, "form:signature") && redact::admit(&posted).is_err(),
                "body text laundered a form redaction claim"
            );
        }
    }

    /// Negative — an incomplete head cannot borrow the next part's delimiter or value.
    #[test]
    fn n_incomplete_headers_do_not_consume_the_next_part() {
        for incomplete in [
            "Content-Disposition: form-data; name=signature\r\nX-Note: ordinary",
            "Content-Disposition: form-data; name=signature",
        ] {
            let body = format!("--xyz\r\n{incomplete}\r\n{}", form(&[("key", "ordinary value")]));
            let mut posted = entry("multipart/form-data; boundary=xyz", &body);
            let detected = has_live_form_credential(&body);
            let touched = sanitize_body(&mut posted);
            assert!(
                !detected && touched.is_empty() && body_text(&posted) == body,
                "an incomplete head claimed the next part's body"
            );
        }
    }

    /// Negative — a missing closing boundary does not make a complete credential disappear.
    #[test]
    fn n_a_complete_partial_part_still_refuses_a_live_credential() {
        let body = format!("Content-Disposition: form-data; name=signature\r\n\r\n{SIGV2}");
        assert!(
            has_live_form_credential(&body) && redact::admit(&entry("application/octet-stream", &body)).is_err(),
            "a complete header and value lost the live credential"
        );
    }

    /// Positive — rewriting the later field preserves unrelated body and filename bytes.
    #[test]
    fn p_sanitize_preserves_unrelated_body_and_filename_text() {
        for head in [
            "Content-Disposition: form-data; name=key",
            "Content-Disposition: form-data; filename=\"x; name=signature\"; name=key",
            "Content-Disposition: form-data; name=\"unfinished",
        ] {
            let prefix = format!("--xyz\r\n{head}\r\n\r\nhello name = \"ordinary text\r\n");
            let body = format!("{prefix}{}", form(&[("signature", SIGV2)]));
            let expected = format!("{prefix}{}", form(&[("signature", PLACEHOLDER)]));
            let mut posted = entry("multipart/form-data; boundary=xyz", &body);
            let touched = redact::sanitize(&mut posted);
            assert!(
                touched == ["form:signature"]
                    && posted.redacted == touched
                    && body_text(&posted) == expected
                    && claim_holds(&posted, "form:signature")
                    && redact::admit(&posted).is_ok(),
                "rewriting did not preserve the non-credential bytes and prove its own record"
            );
        }
    }

    const LEGACY_HEADER_TAILS: &[&str] = &[
        "\n\n",
        "\n\r\n",
        "\r\n\n",
        "\r\nX-Note: ordinary\r\n\r\n",
        "\nX-Note: ordinary\n\n",
    ];
    const LEGACY_PARAMETERS: &[&str] = &[
        "extra=\"x\"ignored\"; name=\"signature\"",
        "extra=x\"y; name=\"signature\"",
        "filename=\"x; name=signature; ignored\"; name=\"signature\"",
        "ignored; name=\"signature\"",
    ];

    fn legacy_header_form(parameters: &str, separator: &str, value: &str) -> String {
        format!(
            "--xyz\r\nContent-Type: text/plain\nContent-Disposition: form-data; {parameters}{separator}{value}\r\n{}",
            form(&[("key", "ordinary value")])
        )
    }

    /// Negative — a bare-LF head must not be discarded before a later CRLF separator.
    #[test]
    fn n_legacy_lf_headers_still_refuse_the_credential() {
        for separator in LEGACY_HEADER_TAILS {
            let body = legacy_header_form("name=\"signature\"", separator, SIGV2);
            assert!(
                has_live_form_credential(&body) && redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err(),
                "a legacy header line ending hid the credential"
            );
        }
    }

    /// Negative — ignored parameter bytes cannot hide a later real name parameter.
    #[test]
    fn n_unknown_parameter_bytes_cannot_hide_the_credential() {
        for parameters in LEGACY_PARAMETERS {
            let body = legacy_header_form(parameters, "\r\n\r\n", SIGV2);
            assert!(
                has_live_form_credential(&body) && redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err(),
                "an ignored parameter hid the credential"
            );
        }
    }

    /// Positive — the earliest blank header line locates the exact value to rewrite.
    #[test]
    fn p_legacy_header_rewrite_preserves_every_other_byte() {
        for parameters in LEGACY_PARAMETERS {
            for separator in LEGACY_HEADER_TAILS {
                let body = legacy_header_form(parameters, separator, SIGV2);
                let expected = legacy_header_form(parameters, separator, PLACEHOLDER);
                let mut posted = entry("multipart/form-data; boundary=xyz", &body);
                let touched = redact::sanitize(&mut posted);
                assert!(
                    touched == ["form:signature"]
                        && body_text(&posted) == expected
                        && claim_holds(&posted, "form:signature")
                        && redact::admit(&posted).is_ok(),
                    "the legacy head did not locate and rewrite the credential value"
                );
            }
        }
    }

    /// Every spelling of a field's `name` parameter the RustFS-profile form reader accepts besides
    /// the quoted one (`rustfs-gateway-http`'s legacy grammar: a bare value, whitespace around
    /// `=`, any case, the parameter after another one).
    const UNQUOTED_SPELLINGS: &[&str] = &[
        "Content-Disposition: form-data; name={name}",
        "Content-Disposition: form-data; name = \"{name}\"",
        "content-disposition:form-data;NAME={name}",
        "Content-Disposition: form-data; filename=\"sig.txt\"; name={name}",
        "Content-Disposition: form-data; name=\t{name}\t",
        "Content-Disposition: form-data; name={name} ; filename=x",
    ];

    /// Negative — a live POST-policy signature whose field name is unquoted, or spelled with
    /// whitespace or case the RustFS-profile reader accepts, is refused like a quoted one. Before
    /// this, only `name="..."` was found and these sailed through the gate.
    #[test]
    fn a_live_signature_under_an_unquoted_field_name_is_refused() {
        for spelling in UNQUOTED_SPELLINGS {
            let body = form_spelled(spelling, &[("key", "uploads/a.txt"), ("X-Amz-Signature", SIG)]);
            assert!(has_live_form_credential(&body), "{spelling}");
            assert!(redact::admit(&entry("multipart/form-data; boundary=xyz", &body)).is_err(), "{spelling}");
        }
    }

    /// Negative — every credential field, not only the signature, under the bare spelling.
    #[test]
    fn each_credential_field_under_a_bare_name_is_refused() {
        for (field, value) in [
            ("AWSAccessKeyId", "compatmatrixkey"),
            ("signature", "0RavWzkygo6QX9caELEqKi9kDbU="),
            ("x-amz-credential", "compatmatrixkey/20260928/us-east-1/s3/aws4_request"),
            ("X-Amz-Security-Token", "FwoGZXIvYXdzEJr//////////wEaDOfaketoken"),
            ("x-amz-signature", SIG),
        ] {
            let body = form_spelled("Content-Disposition: form-data; name={name}", &[(field, value)]);
            assert!(has_live_form_credential(&body), "{field}");
        }
    }

    /// Negative — a `form:` record over a live value is refused under the bare spelling too.
    #[test]
    fn a_form_claim_over_a_live_unquoted_value_is_refused() {
        let body = form_spelled("Content-Disposition: form-data; name={name}", &[("x-amz-signature", SIG)]);
        let mut posted = entry("multipart/form-data; boundary=xyz", &body);
        posted.redacted = vec!["form:x-amz-signature".to_owned()];
        assert!(!claim_holds(&posted, "form:x-amz-signature"));
        assert!(redact::admit(&posted).is_err());
    }

    /// Positive — sanitizing rewrites the credential fields under every unquoted spelling, keeps
    /// every other byte, and the entry is then admitted.
    #[test]
    fn sanitize_rewrites_unquoted_credential_fields() {
        for spelling in UNQUOTED_SPELLINGS {
            let fields = [
                ("key", "uploads/a.txt"),
                ("X-Amz-Credential", "compatmatrixkey/x"),
                ("X-Amz-Signature", SIG),
            ];
            let mut posted = entry("multipart/form-data; boundary=xyz", &form_spelled(spelling, &fields));
            let touched = redact::sanitize(&mut posted);
            assert_eq!(touched, ["form:x-amz-credential", "form:x-amz-signature"], "{spelling}");
            assert_eq!(
                body_text(&posted),
                form_spelled(
                    spelling,
                    &[
                        ("key", "uploads/a.txt"),
                        ("X-Amz-Credential", PLACEHOLDER),
                        ("X-Amz-Signature", PLACEHOLDER)
                    ]
                ),
                "{spelling}"
            );
            redact::admit(&posted).expect("a sanitized form is admitted");
        }
    }

    /// Positive — sanitizing rewrites exactly the credential fields, keeps every other byte, lists
    /// each as `form:<field>`, and the entry is then admitted.
    #[test]
    fn sanitize_rewrites_only_the_credential_fields() {
        let mut posted = entry("multipart/form-data; boundary=xyz", &sigv4_form());
        let touched = redact::sanitize(&mut posted);
        assert_eq!(touched, ["form:x-amz-credential", "form:x-amz-signature"]);
        assert_eq!(posted.redacted, touched);
        assert_eq!(
            body_text(&posted),
            form(&[
                ("key", "uploads/a.txt"),
                ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
                ("X-Amz-Credential", PLACEHOLDER),
                ("X-Amz-Date", "20260928T000000Z"),
                ("Policy", "eyJleHBpcmF0aW9uIjoiMjAyNi0wOS0yOVQwMDowMDowMFoifQ=="),
                ("X-Amz-Signature", PLACEHOLDER),
            ])
        );
        redact::admit(&posted).expect("a sanitized form is admitted");
    }
}
