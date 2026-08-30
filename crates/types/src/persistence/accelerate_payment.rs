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

//! Accelerate and Request Payment persistence codecs.
//!
//! Responsible for: parsing and writing the exact old XML persistence forms and exposing the two
//! runtime decisions made from them. NOT responsible for: HTTP closed-value validation or the
//! temporary s3s oracle. Upstream: bounded gateway XML. Downstream: metadata persistence and P9
//! migration goldens.

use std::borrow::Cow;

use rustfs_gateway_xml::{XmlLimits, XmlWriter, parse_with_limits};

use super::{PersistenceCodecError, optional_child};

/// Bucket Transfer Acceleration configuration persisted by the old path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedAccelerateConfiguration {
    /// Stored acceleration state, including unknown strings accepted by the old persistence DTO.
    pub status: Option<String>,
}

impl PersistedAccelerateConfiguration {
    /// Whether the stored state enables Transfer Acceleration.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.status.as_deref() == Some("Enabled")
    }
}

/// Bucket Request Payment configuration persisted by the old path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedRequestPaymentConfiguration {
    /// Stored payer value; the old DTO requires the element but accepts its string contents.
    pub payer: String,
}

impl PersistedRequestPaymentConfiguration {
    /// Whether requesters, rather than the bucket owner, pay request and data-transfer charges.
    #[must_use]
    pub fn requester_pays(&self) -> bool {
        self.payer == "Requester"
    }
}

fn parse_root(input: &[u8], expected: &str) -> Result<rustfs_gateway_xml::XmlNode, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let body = strip_inert_doctype(input, expected);
    let root = parse_with_limits(body.as_ref(), limits)?;
    if root.name != expected {
        return Err(PersistenceCodecError::WrongRoot);
    }
    Ok(root)
}

fn strip_inert_doctype<'a>(input: &'a [u8], expected: &str) -> Cow<'a, [u8]> {
    let mut cursor = usize::from(input.starts_with(b"\xef\xbb\xbf")) * 3;
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if input.get(cursor..).is_some_and(|body| body.starts_with(b"<?xml")) {
        let Some(end) = input[cursor..].windows(2).position(|window| window == b"?>") else {
            return Cow::Borrowed(input);
        };
        cursor += end + 2;
        while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
    }
    let declaration_start = cursor;
    let Some(body) = input.get(cursor..).and_then(|body| body.strip_prefix(b"<!DOCTYPE")) else {
        return Cow::Borrowed(input);
    };
    cursor = input.len() - body.len();
    if !input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        return Cow::Borrowed(input);
    }
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let Some(body) = input.get(cursor..).and_then(|body| body.strip_prefix(expected.as_bytes())) else {
        return Cow::Borrowed(input);
    };
    cursor = input.len() - body.len();
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if input.get(cursor) != Some(&b'>') {
        return Cow::Borrowed(input);
    }
    let declaration_end = cursor + 1;
    if declaration_start == 0 {
        return Cow::Borrowed(&input[declaration_end..]);
    }
    let mut without_declaration = Vec::with_capacity(input.len() - (declaration_end - declaration_start));
    without_declaration.extend_from_slice(&input[..declaration_start]);
    without_declaration.extend_from_slice(&input[declaration_end..]);
    Cow::Owned(without_declaration)
}

/// Parses persisted Transfer Acceleration XML without HTTP operation policy.
///
/// Unknown top-level children are ignored and the known scalar may occur at most once, matching
/// the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed/bounded XML, a wrong root, or duplicate status.
pub fn parse_accelerate(input: &[u8]) -> Result<PersistedAccelerateConfiguration, PersistenceCodecError> {
    let root = parse_root(input, "AccelerateConfiguration")?;
    Ok(PersistedAccelerateConfiguration {
        status: optional_scalar_text(&root, "Status")?,
    })
}

/// Serializes Transfer Acceleration into the exact old persistence element form.
#[must_use]
pub fn serialize_accelerate(value: &PersistedAccelerateConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("AccelerateConfiguration", None);
    if let Some(status) = value.status.as_deref() {
        writer.element("Status", status);
    }
    writer.close();
    writer.finish().into_bytes()
}

/// Parses persisted Request Payment XML without HTTP operation policy.
///
/// Unknown top-level children are ignored. `Payer` is required and may occur at most once, matching
/// the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed/bounded XML, a wrong root, missing payer, or a
/// duplicate payer.
pub fn parse_request_payment(input: &[u8]) -> Result<PersistedRequestPaymentConfiguration, PersistenceCodecError> {
    let root = parse_root(input, "RequestPaymentConfiguration")?;
    let payer = optional_scalar_text(&root, "Payer")?.ok_or(PersistenceCodecError::MissingRequiredField)?;
    Ok(PersistedRequestPaymentConfiguration { payer })
}

fn optional_scalar_text(parent: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
    let Some(child) = optional_child(parent, name)? else {
        return Ok(None);
    };
    if !child.children.is_empty() {
        return Err(PersistenceCodecError::UnexpectedScalarElement);
    }
    Ok(Some(child.text.clone()))
}

/// Serializes Request Payment into the exact old persistence element form.
#[must_use]
pub fn serialize_request_payment(value: &PersistedRequestPaymentConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("RequestPaymentConfiguration", None);
    writer.element("Payer", &value.payer);
    writer.close();
    writer.finish().into_bytes()
}
