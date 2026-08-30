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

//! Persisted CORS and Tagging XML codecs.
//!
//! Responsible for: lossless known-field parsing, exact old field-order serialization, and runtime
//! projections for CORS and Tagging metadata. NOT responsible for: HTTP validation or the temporary
//! s3s oracle. Upstream: `rustfs-gateway-xml`. Downstream: metadata persistence and migration goldens.

use core::fmt;

use rustfs_gateway_xml::{XmlError, XmlLimits, XmlNode, XmlWriter, parse_with_limits};

/// A persisted bucket CORS configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedCorsConfiguration {
    /// Rules in persisted evaluation order.
    pub cors_rules: Vec<PersistedCorsRule>,
}

impl PersistedCorsConfiguration {
    /// Projects every field used by runtime CORS matching and response emission.
    #[must_use]
    pub fn behavior_projection(&self) -> CorsBehaviorProjection {
        self.cors_rules
            .iter()
            .map(|rule| {
                (
                    rule.allowed_origins.clone(),
                    rule.allowed_methods.clone(),
                    rule.allowed_headers.clone(),
                    rule.expose_headers.clone(),
                    rule.max_age_seconds,
                )
            })
            .collect()
    }
}

/// Runtime-relevant CORS rules without descriptive IDs.
pub type CorsBehaviorProjection = Vec<(Vec<String>, Vec<String>, Option<Vec<String>>, Option<Vec<String>>, Option<i32>)>;

/// One persisted CORS rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedCorsRule {
    /// Optional request headers accepted by the rule.
    pub allowed_headers: Option<Vec<String>>,
    /// HTTP methods accepted by the rule.
    pub allowed_methods: Vec<String>,
    /// Origins accepted by the rule.
    pub allowed_origins: Vec<String>,
    /// Optional response headers exposed to browsers.
    pub expose_headers: Option<Vec<String>>,
    /// Optional descriptive rule identifier.
    pub id: Option<String>,
    /// Optional preflight cache duration in seconds.
    pub max_age_seconds: Option<i32>,
}

/// A persisted bucket Tagging document.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedTagging {
    /// Complete tag set in persisted order.
    pub tag_set: Vec<PersistedTag>,
}

impl PersistedTagging {
    /// Projects the complete tag set used by runtime tag decisions.
    #[must_use]
    pub fn tag_projection(&self) -> Vec<(Option<String>, Option<String>)> {
        self.tag_set.iter().map(|tag| (tag.key.clone(), tag.value.clone())).collect()
    }
}

/// One persisted tag.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedTag {
    /// Tag key.
    pub key: Option<String>,
    /// Tag value, preserved as Unicode text.
    pub value: Option<String>,
}

/// A refusal from the CORS or Tagging persistence codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorsTaggingCodecError {
    /// The document is not well-formed, bounded XML.
    Xml(XmlError),
    /// The root element names another configuration family.
    WrongRoot,
    /// A required structural wrapper or scalar field is absent.
    MissingField(&'static str),
    /// A scalar field or structural wrapper appears more than once.
    DuplicateField(&'static str),
    /// CORS max age is not a signed 32-bit integer.
    InvalidMaxAge,
    /// A nested element is not recognized by the pinned old decoder.
    UnexpectedElement,
}

impl fmt::Display for CorsTaggingCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(error) => write!(formatter, "persisted XML is unreadable: {error}"),
            Self::WrongRoot => formatter.write_str("persisted configuration XML has the wrong root"),
            Self::MissingField(field) => write!(formatter, "persisted configuration XML is missing {field}"),
            Self::DuplicateField(field) => write!(formatter, "persisted configuration XML repeats {field}"),
            Self::InvalidMaxAge => formatter.write_str("persisted CORS XML has an invalid MaxAgeSeconds"),
            Self::UnexpectedElement => formatter.write_str("persisted configuration XML has an unexpected nested element"),
        }
    }
}

impl std::error::Error for CorsTaggingCodecError {}

impl From<XmlError> for CorsTaggingCodecError {
    fn from(error: XmlError) -> Self {
        Self::Xml(error)
    }
}

fn parse_root(input: &[u8], name: &str) -> Result<XmlNode, CorsTaggingCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_with_limits(input, limits)?;
    if root.name != name {
        return Err(CorsTaggingCodecError::WrongRoot);
    }
    Ok(root)
}

fn optional_text(parent: &XmlNode, name: &'static str) -> Result<Option<String>, CorsTaggingCodecError> {
    let mut children = parent.children_named(name);
    let value = children.next().map(|child| child.text.clone());
    if children.next().is_some() {
        return Err(CorsTaggingCodecError::DuplicateField(name));
    }
    Ok(value)
}

/// Parses persisted CORS bytes with old-compatible list and scalar semantics.
///
/// # Errors
///
/// Returns [`CorsTaggingCodecError`] for malformed XML, a wrong root, a repeated scalar, a
/// missing required list member, or an invalid max-age integer.
pub fn parse_cors(input: &[u8]) -> Result<PersistedCorsConfiguration, CorsTaggingCodecError> {
    let root = parse_root(input, "CORSConfiguration")?;
    let cors_rules: Vec<_> = root
        .children_named("CORSRule")
        .map(parse_cors_rule)
        .collect::<Result<_, _>>()?;
    if cors_rules.is_empty() {
        return Err(CorsTaggingCodecError::MissingField("CORSRule"));
    }
    Ok(PersistedCorsConfiguration { cors_rules })
}

fn parse_cors_rule(rule: &XmlNode) -> Result<PersistedCorsRule, CorsTaggingCodecError> {
    const FIELDS: &[&str] = &[
        "AllowedHeader",
        "AllowedMethod",
        "AllowedOrigin",
        "ExposeHeader",
        "ID",
        "MaxAgeSeconds",
    ];
    if rule.children.iter().any(|child| !FIELDS.contains(&child.name.as_str())) {
        return Err(CorsTaggingCodecError::UnexpectedElement);
    }
    let allowed_methods: Vec<_> = rule.children_named("AllowedMethod").map(|node| node.text.clone()).collect();
    let allowed_origins: Vec<_> = rule.children_named("AllowedOrigin").map(|node| node.text.clone()).collect();
    if allowed_methods.is_empty() {
        return Err(CorsTaggingCodecError::MissingField("AllowedMethod"));
    }
    if allowed_origins.is_empty() {
        return Err(CorsTaggingCodecError::MissingField("AllowedOrigin"));
    }
    let max_age_seconds = optional_text(rule, "MaxAgeSeconds")?
        .map(|value| value.parse().map_err(|_| CorsTaggingCodecError::InvalidMaxAge))
        .transpose()?;
    let allowed_headers: Vec<_> = rule.children_named("AllowedHeader").map(|node| node.text.clone()).collect();
    let expose_headers: Vec<_> = rule.children_named("ExposeHeader").map(|node| node.text.clone()).collect();
    Ok(PersistedCorsRule {
        allowed_headers: (!allowed_headers.is_empty()).then_some(allowed_headers),
        allowed_methods,
        allowed_origins,
        expose_headers: (!expose_headers.is_empty()).then_some(expose_headers),
        id: optional_text(rule, "ID")?,
        max_age_seconds,
    })
}

/// Serializes CORS with the pinned old field order and element form.
#[must_use]
pub fn serialize_cors(value: &PersistedCorsConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("CORSConfiguration", None);
    for rule in &value.cors_rules {
        writer.open("CORSRule", None);
        if let Some(headers) = rule.allowed_headers.as_deref() {
            for header in headers {
                writer.element("AllowedHeader", header);
            }
        }
        for method in &rule.allowed_methods {
            writer.element("AllowedMethod", method);
        }
        for origin in &rule.allowed_origins {
            writer.element("AllowedOrigin", origin);
        }
        if let Some(headers) = rule.expose_headers.as_deref() {
            for header in headers {
                writer.element("ExposeHeader", header);
            }
        }
        if let Some(id) = rule.id.as_deref() {
            writer.element("ID", id);
        }
        if let Some(seconds) = rule.max_age_seconds {
            writer.element("MaxAgeSeconds", &seconds.to_string());
        }
        writer.close();
    }
    writer.close();
    writer.finish().into_bytes()
}

/// Parses persisted Tagging bytes while preserving complete Unicode tag contents.
///
/// # Errors
///
/// Returns [`CorsTaggingCodecError`] for malformed XML, a wrong root, a missing or repeated
/// `TagSet`, or a repeated tag key or value.
pub fn parse_tagging(input: &[u8]) -> Result<PersistedTagging, CorsTaggingCodecError> {
    let root = parse_root(input, "Tagging")?;
    let mut tag_sets = root.children_named("TagSet");
    let tag_set = tag_sets.next().ok_or(CorsTaggingCodecError::MissingField("TagSet"))?;
    if tag_sets.next().is_some() {
        return Err(CorsTaggingCodecError::DuplicateField("TagSet"));
    }
    let tag_set = tag_set
        .children_named("Tag")
        .map(|tag| {
            if tag
                .children
                .iter()
                .any(|child| !["Key", "Value"].contains(&child.name.as_str()))
            {
                return Err(CorsTaggingCodecError::UnexpectedElement);
            }
            Ok(PersistedTag {
                key: optional_text(tag, "Key")?,
                value: optional_text(tag, "Value")?,
            })
        })
        .collect::<Result<_, CorsTaggingCodecError>>()?;
    Ok(PersistedTagging { tag_set })
}

/// Serializes Tagging with the pinned old wrapper and field order.
#[must_use]
pub fn serialize_tagging(value: &PersistedTagging) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("Tagging", None);
    writer.open("TagSet", None);
    for tag in &value.tag_set {
        writer.open("Tag", None);
        if let Some(key) = tag.key.as_deref() {
            writer.element("Key", key);
        }
        if let Some(value) = tag.value.as_deref() {
            writer.element("Value", value);
        }
        writer.close();
    }
    writer.close();
    writer.close();
    writer.finish().into_bytes()
}
