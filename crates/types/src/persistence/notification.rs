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

//! Notification persistence codec.
//!
//! Responsible for: preserving the old Notification XML shape, bytes, and destination decisions.
//! NOT responsible for: validating HTTP notification policy or delivering events. Upstream:
//! bounded gateway XML. Downstream: metadata persistence, event routing, and P9 migration goldens.

use std::borrow::Cow;

use rustfs_gateway_xml::XmlWriter;

use super::{PersistenceCodecError, optional_child, parse_persistence_root};

/// The complete bucket Notification configuration persisted by the old path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedNotificationConfiguration {
    /// Whether the configuration contains the empty EventBridge marker.
    pub event_bridge_configuration: Option<PersistedEventBridgeConfiguration>,
    /// Lambda destinations, retaining persistence order.
    pub lambda_function_configurations: Option<Vec<PersistedLambdaFunctionConfiguration>>,
    /// Queue destinations, retaining persistence order.
    pub queue_configurations: Option<Vec<PersistedQueueConfiguration>>,
    /// Topic destinations, retaining persistence order.
    pub topic_configurations: Option<Vec<PersistedTopicConfiguration>>,
}

/// The persisted EventBridge marker.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedEventBridgeConfiguration;

/// One persisted Lambda notification destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedLambdaFunctionConfiguration {
    /// Event patterns that activate the destination.
    pub events: Vec<String>,
    /// Optional object-key filter.
    pub filter: Option<PersistedNotificationConfigurationFilter>,
    /// Optional caller-defined configuration identifier.
    pub id: Option<String>,
    /// Lambda function ARN, including unknown strings accepted by the old decoder.
    pub lambda_function_arn: String,
}

/// One persisted queue notification destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedQueueConfiguration {
    /// Event patterns that activate the destination.
    pub events: Vec<String>,
    /// Optional object-key filter.
    pub filter: Option<PersistedNotificationConfigurationFilter>,
    /// Optional caller-defined configuration identifier.
    pub id: Option<String>,
    /// Queue ARN, including unknown strings accepted by the old decoder.
    pub queue_arn: String,
}

/// One persisted topic notification destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedTopicConfiguration {
    /// Event patterns that activate the destination.
    pub events: Vec<String>,
    /// Optional object-key filter.
    pub filter: Option<PersistedNotificationConfigurationFilter>,
    /// Optional caller-defined configuration identifier.
    pub id: Option<String>,
    /// Topic ARN, including unknown strings accepted by the old decoder.
    pub topic_arn: String,
}

/// The persisted notification filter wrapper.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedNotificationConfigurationFilter {
    /// Optional object-key rules.
    pub key: Option<PersistedS3KeyFilter>,
}

/// The persisted object-key filter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedS3KeyFilter {
    /// Prefix and suffix rules, retaining persistence order and missing scalar members.
    pub filter_rules: Option<Vec<PersistedFilterRule>>,
}

/// One persisted object-key filter rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedFilterRule {
    /// Rule name, normally `prefix` or `suffix` but not closed by the old decoder.
    pub name: Option<String>,
    /// Rule value, which may be omitted in old persisted bytes.
    pub value: Option<String>,
}

/// Complete runtime-relevant Notification decisions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NotificationBehaviorProjection {
    /// Whether all events are forwarded through EventBridge.
    pub event_bridge_enabled: bool,
    /// Lambda routing decisions in persistence order.
    pub lambda_routes: Vec<NotificationRouteProjection>,
    /// Queue routing decisions in persistence order.
    pub queue_routes: Vec<NotificationRouteProjection>,
    /// Topic routing decisions in persistence order.
    pub topic_routes: Vec<NotificationRouteProjection>,
}

/// One independently observable notification routing decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationRouteProjection {
    /// Optional configuration identifier.
    pub id: Option<String>,
    /// Destination ARN or old-readable destination string.
    pub destination: String,
    /// Event patterns that activate this route.
    pub events: Vec<String>,
    /// Object-key rules when a key filter is present.
    pub filter_rules: Option<Vec<(Option<String>, Option<String>)>>,
}

impl PersistedNotificationConfiguration {
    /// Projects every runtime routing decision without using the compatibility oracle.
    #[must_use]
    pub fn behavior(&self) -> NotificationBehaviorProjection {
        NotificationBehaviorProjection {
            event_bridge_enabled: self.event_bridge_configuration.is_some(),
            lambda_routes: self
                .lambda_function_configurations
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|configuration| {
                    route_projection(
                        &configuration.id,
                        &configuration.lambda_function_arn,
                        &configuration.events,
                        configuration.filter.as_ref(),
                    )
                })
                .collect(),
            queue_routes: self
                .queue_configurations
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|configuration| {
                    route_projection(
                        &configuration.id,
                        &configuration.queue_arn,
                        &configuration.events,
                        configuration.filter.as_ref(),
                    )
                })
                .collect(),
            topic_routes: self
                .topic_configurations
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|configuration| {
                    route_projection(
                        &configuration.id,
                        &configuration.topic_arn,
                        &configuration.events,
                        configuration.filter.as_ref(),
                    )
                })
                .collect(),
        }
    }
}

fn route_projection(
    id: &Option<String>,
    destination: &str,
    events: &[String],
    filter: Option<&PersistedNotificationConfigurationFilter>,
) -> NotificationRouteProjection {
    NotificationRouteProjection {
        id: id.clone(),
        destination: destination.to_owned(),
        events: events.to_vec(),
        filter_rules: filter.and_then(|filter| filter.key.as_ref()).map(|key| {
            key.filter_rules
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|rule| (rule.name.clone(), rule.value.clone()))
                .collect()
        }),
    }
}

/// Parses persisted Notification XML without applying HTTP operation policy.
///
/// Unknown root children are ignored. Destination and filter children are closed, scalar children
/// reject nested XML, and required event and destination fields fail closed like the pinned old
/// decoder.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed or bounded XML, a wrong root, missing or
/// duplicate required fields, or unexpected nested elements.
pub fn parse_notification(input: &[u8]) -> Result<PersistedNotificationConfiguration, PersistenceCodecError> {
    let body = strip_inert_doctype(input, "NotificationConfiguration");
    let root = parse_persistence_root(body.as_ref(), "NotificationConfiguration")?;
    let event_bridge_configuration = optional_child(&root, "EventBridgeConfiguration")?
        .map(parse_event_bridge)
        .transpose()?;
    let lambda_function_configurations = collect_configurations(&root, "CloudFunctionConfiguration", |node| {
        parse_destination(node, "CloudFunction").map(|destination| PersistedLambdaFunctionConfiguration {
            events: destination.events,
            filter: destination.filter,
            id: destination.id,
            lambda_function_arn: destination.destination,
        })
    })?;
    let queue_configurations = collect_configurations(&root, "QueueConfiguration", |node| {
        parse_destination(node, "Queue").map(|destination| PersistedQueueConfiguration {
            events: destination.events,
            filter: destination.filter,
            id: destination.id,
            queue_arn: destination.destination,
        })
    })?;
    let topic_configurations = collect_configurations(&root, "TopicConfiguration", |node| {
        parse_destination(node, "Topic").map(|destination| PersistedTopicConfiguration {
            events: destination.events,
            filter: destination.filter,
            id: destination.id,
            topic_arn: destination.destination,
        })
    })?;
    Ok(PersistedNotificationConfiguration {
        event_bridge_configuration,
        lambda_function_configurations,
        queue_configurations,
        topic_configurations,
    })
}

fn parse_event_bridge(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedEventBridgeConfiguration, PersistenceCodecError> {
    reject_unknown_children(node, &[])?;
    Ok(PersistedEventBridgeConfiguration)
}

fn collect_configurations<T>(
    root: &rustfs_gateway_xml::XmlNode,
    name: &str,
    parse: impl Fn(&rustfs_gateway_xml::XmlNode) -> Result<T, PersistenceCodecError>,
) -> Result<Option<Vec<T>>, PersistenceCodecError> {
    let values = root.children_named(name).map(parse).collect::<Result<Vec<_>, _>>()?;
    Ok((!values.is_empty()).then_some(values))
}

struct ParsedDestination {
    events: Vec<String>,
    filter: Option<PersistedNotificationConfigurationFilter>,
    id: Option<String>,
    destination: String,
}

fn parse_destination(
    node: &rustfs_gateway_xml::XmlNode,
    destination_name: &str,
) -> Result<ParsedDestination, PersistenceCodecError> {
    reject_unknown_children(node, &["Event", "Filter", "Id", destination_name])?;
    let events = node.children_named("Event").map(scalar_text).collect::<Result<Vec<_>, _>>()?;
    if events.is_empty() {
        return Err(PersistenceCodecError::MissingRequiredField);
    }
    let filter = optional_child(node, "Filter")?.map(parse_filter).transpose()?;
    let id = optional_scalar_text(node, "Id")?;
    let destination = optional_scalar_text(node, destination_name)?.ok_or(PersistenceCodecError::MissingRequiredField)?;
    Ok(ParsedDestination {
        events,
        filter,
        id,
        destination,
    })
}

fn parse_filter(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedNotificationConfigurationFilter, PersistenceCodecError> {
    reject_unknown_children(node, &["S3Key"])?;
    let key = optional_child(node, "S3Key")?.map(parse_key_filter).transpose()?;
    Ok(PersistedNotificationConfigurationFilter { key })
}

fn parse_key_filter(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedS3KeyFilter, PersistenceCodecError> {
    reject_unknown_children(node, &["FilterRule"])?;
    let filter_rules = collect_configurations(node, "FilterRule", parse_filter_rule)?;
    Ok(PersistedS3KeyFilter { filter_rules })
}

fn parse_filter_rule(node: &rustfs_gateway_xml::XmlNode) -> Result<PersistedFilterRule, PersistenceCodecError> {
    reject_unknown_children(node, &["Name", "Value"])?;
    Ok(PersistedFilterRule {
        name: optional_scalar_text(node, "Name")?,
        value: optional_scalar_text(node, "Value")?,
    })
}

fn reject_unknown_children(parent: &rustfs_gateway_xml::XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if parent.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedNotificationElement);
    }
    Ok(())
}

fn optional_scalar_text(parent: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
    optional_child(parent, name)?.map(scalar_text).transpose()
}

fn scalar_text(node: &rustfs_gateway_xml::XmlNode) -> Result<String, PersistenceCodecError> {
    if !node.children.is_empty() {
        return Err(PersistenceCodecError::UnexpectedScalarElement);
    }
    Ok(node.text.clone())
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

/// Serializes Notification into the exact old persistence field order and element form.
#[must_use]
pub fn serialize_notification(value: &PersistedNotificationConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("NotificationConfiguration", None);
    if value.event_bridge_configuration.is_some() {
        writer.open("EventBridgeConfiguration", None);
        writer.close();
    }
    if let Some(configurations) = value.lambda_function_configurations.as_deref() {
        for configuration in configurations {
            write_destination(
                &mut writer,
                "CloudFunctionConfiguration",
                "CloudFunction",
                &configuration.events,
                configuration.filter.as_ref(),
                configuration.id.as_deref(),
                &configuration.lambda_function_arn,
            );
        }
    }
    if let Some(configurations) = value.queue_configurations.as_deref() {
        for configuration in configurations {
            write_destination(
                &mut writer,
                "QueueConfiguration",
                "Queue",
                &configuration.events,
                configuration.filter.as_ref(),
                configuration.id.as_deref(),
                &configuration.queue_arn,
            );
        }
    }
    if let Some(configurations) = value.topic_configurations.as_deref() {
        for configuration in configurations {
            write_destination(
                &mut writer,
                "TopicConfiguration",
                "Topic",
                &configuration.events,
                configuration.filter.as_ref(),
                configuration.id.as_deref(),
                &configuration.topic_arn,
            );
        }
    }
    writer.close();
    writer.finish().into_bytes()
}

#[allow(clippy::too_many_arguments)] // The arguments are the exact old destination wire fields.
fn write_destination(
    writer: &mut XmlWriter,
    wrapper_name: &str,
    destination_name: &str,
    events: &[String],
    filter: Option<&PersistedNotificationConfigurationFilter>,
    id: Option<&str>,
    destination: &str,
) {
    writer.open(wrapper_name, None);
    for event in events {
        writer.element("Event", event);
    }
    if let Some(filter) = filter {
        writer.open("Filter", None);
        if let Some(key) = filter.key.as_ref() {
            writer.open("S3Key", None);
            if let Some(rules) = key.filter_rules.as_deref() {
                for rule in rules {
                    writer.open("FilterRule", None);
                    if let Some(name) = rule.name.as_deref() {
                        writer.element("Name", name);
                    }
                    if let Some(value) = rule.value.as_deref() {
                        writer.element("Value", value);
                    }
                    writer.close();
                }
            }
            writer.close();
        }
        writer.close();
    }
    if let Some(id) = id {
        writer.element("Id", id);
    }
    writer.element(destination_name, destination);
    writer.close();
}
