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

//! Bucket Logging and Website persisted configuration codecs.
//!
//! Responsible for: preserving the pinned old XML structures, byte order, permissiveness, and
//! runtime decision seams for these two configuration families. NOT responsible for: log delivery,
//! website serving, or HTTP validation. Upstream: buffered persistence bytes. Downstream: migration
//! goldens and storage adapters.

use rustfs_gateway_xml::XmlWriter;

use super::{PersistenceCodecError, optional_child, optional_child_text, parse_persistence_root};

/// Complete persisted Bucket Logging state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedBucketLoggingStatus {
    /// Log-delivery configuration; absence disables logging.
    pub logging_enabled: Option<PersistedLoggingEnabled>,
}

impl PersistedBucketLoggingStatus {
    /// Runtime decisions needed to deliver one access log.
    #[must_use]
    pub fn delivery_behavior(&self) -> Option<PersistedLoggingEnabled> {
        self.logging_enabled.clone()
    }
}

/// Persisted destination and object-key policy for bucket logs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLoggingEnabled {
    /// Destination bucket.
    pub target_bucket: String,
    /// Optional delivery grants, preserving stored order.
    pub target_grants: Option<Vec<PersistedLoggingGrant>>,
    /// Optional target object-key format.
    pub target_object_key_format: Option<PersistedTargetObjectKeyFormat>,
    /// Prefix prepended to delivered log object keys.
    pub target_prefix: String,
}

/// One persisted log-delivery grant.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLoggingGrant {
    /// Optional grantee identity.
    pub grantee: Option<PersistedGrantee>,
    /// Optional granted delivery permission.
    pub permission: Option<String>,
}

/// Persisted grantee identity fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedGrantee {
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional email address.
    pub email_address: Option<String>,
    /// Optional canonical identifier.
    pub id: Option<String>,
    /// Required XML grantee type.
    pub grantee_type: String,
    /// Optional group URI.
    pub uri: Option<String>,
}

/// Persisted log object-key partitioning policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedTargetObjectKeyFormat {
    /// Present partition wrapper and its optional date source.
    pub partition_date_source: Option<Option<String>>,
    /// Whether an empty legacy simple-prefix marker is present.
    pub simple_prefix: bool,
}

/// Complete persisted Website configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedWebsiteConfiguration {
    /// Optional error-document key.
    pub error_document: Option<PersistedErrorDocument>,
    /// Optional index-document suffix.
    pub index_document: Option<PersistedIndexDocument>,
    /// Optional unconditional redirect.
    pub redirect_all_requests_to: Option<PersistedRedirectAllRequestsTo>,
    /// Optional ordered routing rules.
    pub routing_rules: Option<Vec<PersistedRoutingRule>>,
}

impl PersistedWebsiteConfiguration {
    /// Runtime decisions used by website request routing.
    #[must_use]
    pub fn routing_behavior(&self) -> Self {
        self.clone()
    }
}

/// Persisted website error-document key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedErrorDocument {
    /// Object key served for errors.
    pub key: String,
}

/// Persisted website index-document suffix.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedIndexDocument {
    /// Suffix appended for index requests.
    pub suffix: String,
}

/// Persisted unconditional website redirect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedRedirectAllRequestsTo {
    /// Redirect host name.
    pub host_name: String,
    /// Optional redirect protocol.
    pub protocol: Option<String>,
}

/// One ordered website routing rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedRoutingRule {
    /// Optional condition selecting the rule.
    pub condition: Option<PersistedRoutingRuleCondition>,
    /// Redirect applied by the rule.
    pub redirect: PersistedRedirect,
}

/// Persisted website routing condition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedRoutingRuleCondition {
    /// Optional HTTP error code selector.
    pub http_error_code_returned_equals: Option<String>,
    /// Optional object-key prefix selector.
    pub key_prefix_equals: Option<String>,
}

/// Persisted website redirect action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedRedirect {
    /// Optional redirect host name.
    pub host_name: Option<String>,
    /// Optional redirect status code.
    pub http_redirect_code: Option<String>,
    /// Optional redirect protocol.
    pub protocol: Option<String>,
    /// Optional replacement key prefix.
    pub replace_key_prefix_with: Option<String>,
    /// Optional replacement key.
    pub replace_key_with: Option<String>,
}

/// Parses persisted Bucket Logging bytes without applying HTTP policy.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, the wrong root, missing required fields,
/// duplicates, or nested content refused by the pinned old decoder.
pub fn parse_bucket_logging(input: &[u8]) -> Result<PersistedBucketLoggingStatus, PersistenceCodecError> {
    let root = parse_persistence_root(input, "BucketLoggingStatus")?;
    let logging_enabled = optional_child(&root, "LoggingEnabled")?
        .map(parse_logging_enabled)
        .transpose()?;
    Ok(PersistedBucketLoggingStatus { logging_enabled })
}

fn parse_logging_enabled(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedLoggingEnabled, PersistenceCodecError> {
    reject_unknown_logging_children(node, &["TargetBucket", "TargetGrants", "TargetObjectKeyFormat", "TargetPrefix"])?;
    let target_bucket = required_text(node, "TargetBucket")?;
    let target_grants = optional_child(node, "TargetGrants")?.map(parse_target_grants).transpose()?;
    let target_object_key_format = optional_child(node, "TargetObjectKeyFormat")?
        .map(parse_target_object_key_format)
        .transpose()?;
    let target_prefix = required_text(node, "TargetPrefix")?;
    Ok(PersistedLoggingEnabled {
        target_bucket,
        target_grants,
        target_object_key_format,
        target_prefix,
    })
}

fn parse_target_grants(node: &rustfs_gateway_xml::XmlNode) -> Result<Vec<PersistedLoggingGrant>, PersistenceCodecError> {
    node.children_named("Grant").map(parse_logging_grant).collect()
}

fn parse_logging_grant(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedLoggingGrant, PersistenceCodecError> {
    reject_unknown_logging_children(node, &["Grantee", "Permission"])?;
    let grantee = optional_child(node, "Grantee")?.map(parse_grantee).transpose()?;
    Ok(PersistedLoggingGrant {
        grantee,
        permission: optional_child_text(node, "Permission")?,
    })
}

fn parse_grantee(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedGrantee, PersistenceCodecError> {
    reject_unknown_logging_children(node, &["DisplayName", "EmailAddress", "ID", "URI"])?;
    let grantee_type = node
        .attributes
        .iter()
        .find(|attribute| {
            attribute.name == "type" && attribute.namespace.as_deref() == Some("http://www.w3.org/2001/XMLSchema-instance")
        })
        .map(|attribute| attribute.value.clone())
        .ok_or(PersistenceCodecError::MissingRequiredField)?;
    Ok(PersistedGrantee {
        display_name: optional_child_text(node, "DisplayName")?,
        email_address: optional_child_text(node, "EmailAddress")?,
        id: optional_child_text(node, "ID")?,
        grantee_type,
        uri: optional_child_text(node, "URI")?,
    })
}

fn parse_target_object_key_format(
    node: &rustfs_gateway_xml::XmlNode,
) -> Result<PersistedTargetObjectKeyFormat, PersistenceCodecError> {
    reject_unknown_logging_children(node, &["PartitionedPrefix", "SimplePrefix"])?;
    let partition_date_source = optional_child(node, "PartitionedPrefix")?
        .map(|partitioned| {
            reject_unknown_logging_children(partitioned, &["PartitionDateSource"])?;
            optional_child_text(partitioned, "PartitionDateSource")
        })
        .transpose()?;
    let simple_prefix = optional_child(node, "SimplePrefix")?
        .map(|simple| reject_unknown_logging_children(simple, &[]))
        .transpose()?
        .is_some();
    Ok(PersistedTargetObjectKeyFormat {
        partition_date_source,
        simple_prefix,
    })
}

fn reject_unknown_logging_children(node: &rustfs_gateway_xml::XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if node.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedLoggingElement);
    }
    Ok(())
}

/// Serializes Bucket Logging in the pinned old field order.
#[must_use]
pub fn serialize_bucket_logging(value: &PersistedBucketLoggingStatus) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("BucketLoggingStatus", None);
    if let Some(logging) = value.logging_enabled.as_ref() {
        writer.open("LoggingEnabled", None);
        writer.element("TargetBucket", &logging.target_bucket);
        if let Some(grants) = logging.target_grants.as_deref() {
            writer.open("TargetGrants", None);
            for grant in grants {
                writer.open("Grant", None);
                if let Some(grantee) = grant.grantee.as_ref() {
                    writer.open("Grantee", None);
                    if let Some(display_name) = grantee.display_name.as_deref() {
                        writer.element("DisplayName", display_name);
                    }
                    if let Some(email_address) = grantee.email_address.as_deref() {
                        writer.element("EmailAddress", email_address);
                    }
                    if let Some(id) = grantee.id.as_deref() {
                        writer.element("ID", id);
                    }
                    if let Some(uri) = grantee.uri.as_deref() {
                        writer.element("URI", uri);
                    }
                    writer.close();
                }
                if let Some(permission) = grant.permission.as_deref() {
                    writer.element("Permission", permission);
                }
                writer.close();
            }
            writer.close();
        }
        if let Some(format) = logging.target_object_key_format.as_ref() {
            writer.open("TargetObjectKeyFormat", None);
            if let Some(partition_date_source) = format.partition_date_source.as_ref() {
                writer.open("PartitionedPrefix", None);
                if let Some(partition_date_source) = partition_date_source.as_deref() {
                    writer.element("PartitionDateSource", partition_date_source);
                }
                writer.close();
            }
            if format.simple_prefix {
                writer.open("SimplePrefix", None);
                writer.close();
            }
            writer.close();
        }
        writer.element("TargetPrefix", &logging.target_prefix);
        writer.close();
    }
    writer.close();
    let mut output = writer.finish().into_bytes();
    // XmlWriter has no arbitrary-attribute surface. Restore the pinned DTO's required xsi:type
    // attributes after its element/text writer has performed all ordinary XML escaping.
    let grantee_types = value
        .logging_enabled
        .as_ref()
        .and_then(|logging| logging.target_grants.as_deref())
        .into_iter()
        .flatten()
        .filter_map(|grant| grant.grantee.as_ref())
        .map(|grantee| grantee.grantee_type.as_str());
    let marker = b"<Grantee>";
    let mut search_start = 0;
    for grantee_type in grantee_types {
        let Some(offset) = output[search_start..]
            .windows(marker.len())
            .position(|window| window == marker)
        else {
            break;
        };
        let start = search_start + offset;
        let replacement = format!(
            "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"{}\">",
            escape_xml_attribute(grantee_type)
        );
        output.splice(start..start + marker.len(), replacement.bytes());
        search_start = start + replacement.len();
    }
    output
}

fn escape_xml_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Parses persisted Website bytes without applying HTTP policy.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, the wrong root, missing required fields,
/// duplicates, or nested content refused by the pinned old decoder.
pub fn parse_website(input: &[u8]) -> Result<PersistedWebsiteConfiguration, PersistenceCodecError> {
    let root = parse_persistence_root(input, "WebsiteConfiguration")?;
    Ok(PersistedWebsiteConfiguration {
        error_document: optional_child(&root, "ErrorDocument")?
            .map(parse_error_document)
            .transpose()?,
        index_document: optional_child(&root, "IndexDocument")?
            .map(parse_index_document)
            .transpose()?,
        redirect_all_requests_to: optional_child(&root, "RedirectAllRequestsTo")?
            .map(parse_redirect_all)
            .transpose()?,
        routing_rules: optional_child(&root, "RoutingRules")?.map(parse_routing_rules).transpose()?,
    })
}

fn parse_error_document(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedErrorDocument, PersistenceCodecError> {
    reject_unknown_website_children(node, &["Key"])?;
    Ok(PersistedErrorDocument {
        key: required_text(node, "Key")?,
    })
}

fn parse_index_document(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedIndexDocument, PersistenceCodecError> {
    reject_unknown_website_children(node, &["Suffix"])?;
    Ok(PersistedIndexDocument {
        suffix: required_text(node, "Suffix")?,
    })
}

fn parse_redirect_all(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedRedirectAllRequestsTo, PersistenceCodecError> {
    reject_unknown_website_children(node, &["HostName", "Protocol"])?;
    Ok(PersistedRedirectAllRequestsTo {
        host_name: required_text(node, "HostName")?,
        protocol: optional_child_text(node, "Protocol")?,
    })
}

fn parse_routing_rules(node: &rustfs_gateway_xml::XmlNode) -> Result<Vec<PersistedRoutingRule>, PersistenceCodecError> {
    node.children_named("RoutingRule").map(parse_routing_rule).collect()
}

fn parse_routing_rule(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedRoutingRule, PersistenceCodecError> {
    reject_unknown_website_children(node, &["Condition", "Redirect"])?;
    let redirect = optional_child(node, "Redirect")?
        .map(parse_redirect)
        .transpose()?
        .ok_or(PersistenceCodecError::MissingRequiredField)?;
    Ok(PersistedRoutingRule {
        condition: optional_child(node, "Condition")?.map(parse_condition).transpose()?,
        redirect,
    })
}

fn parse_condition(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedRoutingRuleCondition, PersistenceCodecError> {
    reject_unknown_website_children(node, &["HttpErrorCodeReturnedEquals", "KeyPrefixEquals"])?;
    Ok(PersistedRoutingRuleCondition {
        http_error_code_returned_equals: optional_child_text(node, "HttpErrorCodeReturnedEquals")?,
        key_prefix_equals: optional_child_text(node, "KeyPrefixEquals")?,
    })
}

fn parse_redirect(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedRedirect, PersistenceCodecError> {
    reject_unknown_website_children(
        node,
        &[
            "HostName",
            "HttpRedirectCode",
            "Protocol",
            "ReplaceKeyPrefixWith",
            "ReplaceKeyWith",
        ],
    )?;
    Ok(PersistedRedirect {
        host_name: optional_child_text(node, "HostName")?,
        http_redirect_code: optional_child_text(node, "HttpRedirectCode")?,
        protocol: optional_child_text(node, "Protocol")?,
        replace_key_prefix_with: optional_child_text(node, "ReplaceKeyPrefixWith")?,
        replace_key_with: optional_child_text(node, "ReplaceKeyWith")?,
    })
}

fn reject_unknown_website_children(node: &rustfs_gateway_xml::XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if node.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedWebsiteElement);
    }
    Ok(())
}

fn required_text(node: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<String, PersistenceCodecError> {
    optional_child_text(node, name)?.ok_or(PersistenceCodecError::MissingRequiredField)
}

/// Serializes Website configuration in the pinned old field order.
#[must_use]
pub fn serialize_website(value: &PersistedWebsiteConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("WebsiteConfiguration", None);
    if let Some(error) = value.error_document.as_ref() {
        writer.open("ErrorDocument", None);
        writer.element("Key", &error.key);
        writer.close();
    }
    if let Some(index) = value.index_document.as_ref() {
        writer.open("IndexDocument", None);
        writer.element("Suffix", &index.suffix);
        writer.close();
    }
    if let Some(redirect) = value.redirect_all_requests_to.as_ref() {
        writer.open("RedirectAllRequestsTo", None);
        writer.element("HostName", &redirect.host_name);
        if let Some(protocol) = redirect.protocol.as_deref() {
            writer.element("Protocol", protocol);
        }
        writer.close();
    }
    if let Some(rules) = value.routing_rules.as_deref() {
        writer.open("RoutingRules", None);
        for rule in rules {
            writer.open("RoutingRule", None);
            if let Some(condition) = rule.condition.as_ref() {
                writer.open("Condition", None);
                if let Some(code) = condition.http_error_code_returned_equals.as_deref() {
                    writer.element("HttpErrorCodeReturnedEquals", code);
                }
                if let Some(prefix) = condition.key_prefix_equals.as_deref() {
                    writer.element("KeyPrefixEquals", prefix);
                }
                writer.close();
            }
            writer.open("Redirect", None);
            if let Some(host) = rule.redirect.host_name.as_deref() {
                writer.element("HostName", host);
            }
            if let Some(code) = rule.redirect.http_redirect_code.as_deref() {
                writer.element("HttpRedirectCode", code);
            }
            if let Some(protocol) = rule.redirect.protocol.as_deref() {
                writer.element("Protocol", protocol);
            }
            if let Some(prefix) = rule.redirect.replace_key_prefix_with.as_deref() {
                writer.element("ReplaceKeyPrefixWith", prefix);
            }
            if let Some(key) = rule.redirect.replace_key_with.as_deref() {
                writer.element("ReplaceKeyWith", key);
            }
            writer.close();
            writer.close();
        }
        writer.close();
    }
    writer.close();
    writer.finish().into_bytes()
}
