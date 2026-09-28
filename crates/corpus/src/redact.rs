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

//! Responsible for: proving that one corpus entry carries no credential material, and
//! refusing it when that cannot be proved.
//! Not responsible for: recording, deduplication, storage layout, or case conversion.
//! Upstream: `schema::Entry`, from ingestion or from a file already under `corpus/`.
//! Downstream: `store` (which refuses to write a rejected entry) and the `corpus` binary.
//!
//! The gate's polarity is the whole design. `scan` reports findings and `admit` turns any
//! finding into a refusal; nothing is repaired on the way past. Repair is `sanitize`, an
//! explicit opt-in that records every field it rewrote, and whose output goes back through
//! `admit` like anything else. A gate that silently fixes its input is a gate whose
//! failures are invisible, and the failure it hides here is an irreversible repository leak.

use crate::base64;
use crate::form;
use crate::framing;
use crate::schema::{Chunk, Entry};

/// The fixed value every rewritten field is replaced with.
///
/// One spelling, so that "was this field redacted?" is a string comparison rather than a
/// judgement call, and so that a grep over `corpus/` can count redactions.
pub const PLACEHOLDER: &str = "__REDACTED__";

/// Request and response header names whose value is credential material outright.
///
/// `x-amz-server-side-encryption-customer-key` is on the list because SSE-C sends the
/// **plaintext** data key in a header; the rest carry a signature, a session token, or a
/// browser credential.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-amz-copy-source-server-side-encryption-customer-key",
    "x-amz-security-token",
    "x-amz-server-side-encryption-customer-key",
];

/// Query parameter names a presigned URL uses to carry credential material.
///
/// Matched case-insensitively: SDKs disagree on the capitalisation, and a lowercase
/// `x-amz-signature` is exactly as much of a signature as the canonical spelling.
pub const SENSITIVE_QUERY_PARAMS: &[&str] = &["x-amz-credential", "x-amz-security-token", "x-amz-signature"];

/// Where in an entry a finding was located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    /// A request header, by name.
    RequestHeader(String),
    /// A response header, by name.
    ResponseHeader(String),
    /// A query parameter of `target`, by name.
    QueryParam(String),
    /// The request target as text.
    Target,
    /// A request body chunk, by index.
    RequestChunk(usize),
    /// The response body.
    ResponseBody,
    /// A name listed in the entry's own `redacted` record.
    RedactionRecord(String),
    /// A free-text scalar on the entry itself, by field name.
    Metadata(&'static str),
    /// The `action` of a request body control chunk, by index.
    ControlAction(usize),
}

impl std::fmt::Display for Site {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestHeader(name) => write!(f, "request header `{name}`"),
            Self::ResponseHeader(name) => write!(f, "response header `{name}`"),
            Self::QueryParam(name) => write!(f, "query parameter `{name}`"),
            Self::Target => write!(f, "request target"),
            Self::RequestChunk(index) => write!(f, "request body chunk {index}"),
            Self::ResponseBody => write!(f, "response body"),
            Self::RedactionRecord(name) => write!(f, "the `redacted` record for `{name}`"),
            Self::Metadata(field) => write!(f, "the `{field}` field"),
            Self::ControlAction(index) => write!(f, "the action of control chunk {index}"),
        }
    }
}

/// What was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A header or query parameter that carries credential material by definition, still
    /// holding something other than [`PLACEHOLDER`].
    LiveCredentialField,
    /// A PEM private-key header.
    PrivateKeyPem,
    /// A JSON Web Token.
    JsonWebToken,
    /// A 40-character mixed-case AWS secret access key.
    AwsSecretAccessKey,
    /// A `secret`/`password`/`token`-shaped assignment with a non-empty value.
    CredentialAssignment,
    /// A SigV4 `Signature=<64 hex>` anywhere in text.
    SigV4Signature,
    /// The entry claims a field was redacted that is not present, or is present without
    /// the placeholder. A redaction record that does not describe the entry is a
    /// laundering record.
    UnprovenRedactionClaim,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::LiveCredentialField => "a credential-bearing field still holds a live value",
            Self::PrivateKeyPem => "a PEM private key",
            Self::JsonWebToken => "a JSON Web Token",
            Self::AwsSecretAccessKey => "an AWS secret access key",
            Self::CredentialAssignment => "a credential assignment",
            Self::SigV4Signature => "a SigV4 signature",
            Self::UnprovenRedactionClaim => "a redaction claim the entry does not support",
        };
        f.write_str(text)
    }
}

/// One reason an entry cannot be proved clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Where it was found.
    pub site: Site,
    /// What was found.
    pub reason: Reason,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} in {}", self.reason, self.site)
    }
}

/// An entry that could not be proved clean, with every reason it could not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The entry's operation, for the diagnostic.
    pub op: String,
    /// Every finding, in discovery order.
    pub findings: Vec<Finding>,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused {} entry:", self.op)?;
        for finding in &self.findings {
            write!(f, "\n  - {finding}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusal {}

fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS.iter().any(|known| name.eq_ignore_ascii_case(known))
}

fn is_sensitive_query_param(name: &str) -> bool {
    SENSITIVE_QUERY_PARAMS.iter().any(|known| name.eq_ignore_ascii_case(known))
}

/// Split a query string into `(name, value)` pairs without decoding.
///
/// Percent-decoding is deliberately skipped: the question is whether a signature is
/// present, and an encoded signature is still a signature.
fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((name, value)) => (name, value),
            None => (part, ""),
        })
}

fn is_base64_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
}

/// Whether `text` contains a 40-character AWS-secret-shaped run.
///
/// The length is exact — an AWS secret access key is 40 characters — and the run must mix
/// case and contain a digit, which is what separates it from a hex digest, a base64 MD5,
/// or a long object key. Runs are maximal, so a 40-character window inside a longer
/// base64 blob does not match.
fn has_aws_secret(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !is_base64_run_byte(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_base64_run_byte(bytes[end]) {
            end += 1;
        }
        let run = &bytes[start..end];
        if run.len() == 40
            && run.iter().any(u8::is_ascii_lowercase)
            && run.iter().any(u8::is_ascii_uppercase)
            && run.iter().any(u8::is_ascii_digit)
        {
            return true;
        }
        start = end;
    }
    false
}

const CREDENTIAL_KEYS: &[&str] = &[
    "aws_secret_access_key",
    "awssecretaccesskey",
    "passwd",
    "password",
    "private_key",
    "secret_access_key",
    "secretaccesskey",
    "secretkey",
    "session_token",
    "sessiontoken",
    "x-amz-security-token",
];

/// Whether `text` assigns a non-empty value to a credential-shaped key.
///
/// Deliberately tolerant about the separator: JSON (`"key": "v"`), TOML/env (`key=v`),
/// XML (`<Key>v</Key>`) and query strings all reduce to "key token, punctuation, value".
fn has_credential_assignment(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    for key in CREDENTIAL_KEYS {
        let mut from = 0;
        while let Some(offset) = lowered[from..].find(key) {
            let after = from + offset + key.len();
            from = after;
            let tail = lowered[after..].trim_start_matches(['"', '\'', ' ', '\t', '>', '<', '/']);
            let Some(value) = tail.strip_prefix([':', '=']) else {
                continue;
            };
            let value = value.trim_start_matches(['"', '\'', ' ', '\t']);
            let value: String = value
                .chars()
                .take_while(|c| !matches!(c, '"' | '\'' | '&' | '\n' | '<'))
                .collect();
            if !value.is_empty() && value != PLACEHOLDER {
                return true;
            }
        }
    }
    false
}

/// Whether `text` contains `Signature=` followed by 64 hexadecimal characters.
fn has_sigv4_signature(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lowered[from..].find("signature=") {
        let after = from + offset + "signature=".len();
        from = after;
        let run: String = lowered[after..].chars().take_while(char::is_ascii_hexdigit).collect();
        if run.len() >= 64 {
            return true;
        }
    }
    false
}

/// Whether `text` contains a JSON Web Token: two base64url segments starting `eyJ`.
fn has_jwt(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(offset) = text[from..].find("eyJ") {
        let start = from + offset;
        from = start + 3;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'-') {
            end += 1;
        }
        if end - start >= 8 && text[end..].starts_with(".eyJ") {
            return true;
        }
    }
    false
}

/// Every secret pattern that matches `text`, in a fixed order.
fn text_findings(text: &str) -> Vec<Reason> {
    let mut reasons = Vec::new();
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
        reasons.push(Reason::PrivateKeyPem);
    }
    if has_jwt(text) {
        reasons.push(Reason::JsonWebToken);
    }
    if has_aws_secret(text) {
        reasons.push(Reason::AwsSecretAccessKey);
    }
    if has_credential_assignment(text) {
        reasons.push(Reason::CredentialAssignment);
    }
    if has_sigv4_signature(text) || framing::has_live_trailer_signature(text) {
        reasons.push(Reason::SigV4Signature);
    }
    if form::has_live_form_credential(text) {
        reasons.push(Reason::LiveCredentialField);
    }
    reasons
}

fn scan_text(site: &Site, text: &str, findings: &mut Vec<Finding>) {
    for reason in text_findings(text) {
        findings.push(Finding {
            site: site.clone(),
            reason,
        });
    }
}

/// Decode a base64 payload into scannable text.
///
/// Undecodable base64 yields no text rather than an error: an entry whose payload cannot
/// be decoded is caught by the schema, and returning an empty string here would be the
/// one place where a malformed field reads as a clean one, so the raw base64 is scanned
/// instead.
fn payload_text(encoded: &str) -> String {
    match base64::decode(encoded) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => encoded.to_owned(),
    }
}

/// Every reason this entry cannot be proved free of credential material.
///
/// An empty result is the only thing that admits an entry to the corpus.
pub fn scan(entry: &Entry) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (name, value) in &entry.headers {
        let site = Site::RequestHeader(name.to_ascii_lowercase());
        if is_sensitive_header(name) && value.as_str() != PLACEHOLDER {
            findings.push(Finding {
                site: site.clone(),
                reason: Reason::LiveCredentialField,
            });
        }
        scan_text(&site, value, &mut findings);
    }

    for (name, value) in query_pairs(entry.query()) {
        if is_sensitive_query_param(name) && value != PLACEHOLDER {
            findings.push(Finding {
                site: Site::QueryParam(name.to_ascii_lowercase()),
                reason: Reason::LiveCredentialField,
            });
        }
    }
    scan_text(&Site::Target, &entry.target, &mut findings);

    // Every free-text scalar on the entry, not only the ones a credential is *expected* in.
    // A field nobody scans is a field a secret can be parked in, and `op`, `method` and
    // `recorded` are as writable as any header. Whitelisting the scan surface is how the
    // first version of this function let a control chunk's `action` through.
    for (field, value) in [
        ("op", &entry.op),
        ("method", &entry.method),
        ("recorded", &entry.recorded),
        ("src", &entry.src),
    ] {
        scan_text(&Site::Metadata(field), value, &mut findings);
    }

    if let Some(chunks) = &entry.chunks {
        for (index, chunk) in chunks.iter().enumerate() {
            match chunk {
                Chunk::Data { bytes_b64, .. } => {
                    scan_text(&Site::RequestChunk(index), &payload_text(bytes_b64), &mut findings);
                }
                Chunk::Control { action, .. } => {
                    scan_text(&Site::ControlAction(index), action, &mut findings);
                }
            }
        }
    }

    if let Some(response) = &entry.resp {
        for (name, value) in &response.headers {
            let site = Site::ResponseHeader(name.to_ascii_lowercase());
            if is_sensitive_header(name) && value.as_str() != PLACEHOLDER {
                findings.push(Finding {
                    site: site.clone(),
                    reason: Reason::LiveCredentialField,
                });
            }
            scan_text(&site, value, &mut findings);
        }
        if let Some(body) = &response.body_b64 {
            scan_text(&Site::ResponseBody, &payload_text(body), &mut findings);
        }
    }

    for claimed in &entry.redacted {
        if !redaction_claim_holds(entry, claimed) {
            findings.push(Finding {
                site: Site::RedactionRecord(claimed.to_ascii_lowercase()),
                reason: Reason::UnprovenRedactionClaim,
            });
        }
    }

    findings
}

/// Whether `claimed` names a field that is present and holds [`PLACEHOLDER`].
fn redaction_claim_holds(entry: &Entry, claimed: &str) -> bool {
    if framing::is_body_carrier(claimed) {
        return framing::claim_holds(entry, claimed);
    }
    if form::is_form_record(claimed) {
        return form::claim_holds(entry, claimed);
    }
    let header = entry
        .headers
        .iter()
        .chain(entry.resp.iter().flat_map(|response| response.headers.iter()))
        .any(|(name, value)| name.eq_ignore_ascii_case(claimed) && value.as_str() == PLACEHOLDER);
    let param = query_pairs(entry.query()).any(|(name, value)| name.eq_ignore_ascii_case(claimed) && value == PLACEHOLDER);
    header || param
}

/// Admit the entry, or refuse it with every reason.
///
/// This is the only door into the corpus. It repairs nothing.
pub fn admit(entry: &Entry) -> Result<(), Refusal> {
    let findings = scan(entry);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(Refusal {
            op: entry.op.clone(),
            findings,
        })
    }
}

/// Rewrite every credential-bearing carrier this policy knows how to rewrite, and record
/// what was rewritten in `entry.redacted`.
///
/// Returns the field names it touched, in sorted order. It does not touch payload bytes:
/// there is no structure-independent way to replace a secret inside a payload without
/// changing what the payload proves, so a body finding stays a refusal under every mode.
/// The one exception is the signature carriers aws-chunked framing puts at fixed places in
/// the body of a request whose head declares that framing (`framing`), and the credential
/// fields of a declared `multipart/form-data` upload form (`form`); rewriting those changes no
/// data byte, no chunk-size line and no other form field.
///
/// Calling this does not admit the entry. Run [`admit`] afterwards — that is what makes
/// the sanitizer auditable rather than trusted.
pub fn sanitize(entry: &mut Entry) -> Vec<String> {
    let mut touched = Vec::new();

    for (name, value) in &mut entry.headers {
        if is_sensitive_header(name) && value.as_str() != PLACEHOLDER {
            PLACEHOLDER.clone_into(value);
            touched.push(name.to_ascii_lowercase());
        }
    }
    if let Some(response) = &mut entry.resp {
        for (name, value) in &mut response.headers {
            if is_sensitive_header(name) && value.as_str() != PLACEHOLDER {
                PLACEHOLDER.clone_into(value);
                touched.push(name.to_ascii_lowercase());
            }
        }
    }

    let target = entry.target.clone();
    if let Some((path, query)) = target.split_once('?') {
        let mut rebuilt = Vec::new();
        for part in query.split('&') {
            let (name, value) = match part.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (part, None),
            };
            if is_sensitive_query_param(name) && value != Some(PLACEHOLDER) {
                touched.push(name.to_ascii_lowercase());
                rebuilt.push(format!("{name}={PLACEHOLDER}"));
            } else {
                rebuilt.push(part.to_owned());
            }
        }
        entry.target = format!("{path}?{}", rebuilt.join("&"));
    }

    touched.extend(framing::sanitize_body(entry));
    touched.extend(form::sanitize_body(entry));

    touched.sort_unstable();
    touched.dedup();
    for name in &touched {
        if !entry.redacted.contains(name) {
            entry.redacted.push(name.clone());
        }
    }
    entry.redacted.sort_unstable();
    entry.redacted.dedup();
    touched
}
