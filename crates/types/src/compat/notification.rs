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

//! Pinned-s3s observations for Notification persistence.
//!
//! Responsible for: invoking the old XML codec and independently projecting its complete structure
//! and routing decisions. NOT responsible for: production parsing or event delivery. Upstream:
//! pinned s3s. Downstream: Notification persistence goldens; deleted by P9-09.

use s3s::dto::{
    Event, EventBridgeConfiguration, FilterRule, FilterRuleName, LambdaFunctionConfiguration, NotificationConfiguration,
    NotificationConfigurationFilter, QueueConfiguration, S3KeyFilter, TopicConfiguration,
};
use s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

use crate::persistence::{
    NotificationBehaviorProjection, NotificationRouteProjection, PersistedEventBridgeConfiguration, PersistedFilterRule,
    PersistedLambdaFunctionConfiguration, PersistedNotificationConfiguration, PersistedNotificationConfigurationFilter,
    PersistedQueueConfiguration, PersistedS3KeyFilter, PersistedTopicConfiguration,
};

use super::CompatCodecError;

/// One old-codec Notification observation before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sNotificationObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedNotificationConfiguration,
    /// Complete routing decisions projected directly from the old DTO.
    pub behavior: NotificationBehaviorProjection,
}

/// Parses Notification bytes with the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old decoder rejects the document or trailing bytes.
pub fn parse_s3s_notification(input: &[u8]) -> Result<S3sNotificationObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = NotificationConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let behavior = old_behavior(&value);
    let structure = old_structure(value);
    Ok(S3sNotificationObservation { structure, behavior })
}

fn old_behavior(value: &NotificationConfiguration) -> NotificationBehaviorProjection {
    NotificationBehaviorProjection {
        event_bridge_enabled: value.event_bridge_configuration.is_some(),
        lambda_routes: value
            .lambda_function_configurations
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|configuration| {
                old_route_projection(
                    &configuration.id,
                    &configuration.lambda_function_arn,
                    &configuration.events,
                    configuration.filter.as_ref(),
                )
            })
            .collect(),
        queue_routes: value
            .queue_configurations
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|configuration| {
                old_route_projection(
                    &configuration.id,
                    &configuration.queue_arn,
                    &configuration.events,
                    configuration.filter.as_ref(),
                )
            })
            .collect(),
        topic_routes: value
            .topic_configurations
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|configuration| {
                old_route_projection(
                    &configuration.id,
                    &configuration.topic_arn,
                    &configuration.events,
                    configuration.filter.as_ref(),
                )
            })
            .collect(),
    }
}

fn old_route_projection(
    id: &Option<String>,
    destination: &str,
    events: &[Event],
    filter: Option<&NotificationConfigurationFilter>,
) -> NotificationRouteProjection {
    NotificationRouteProjection {
        id: id.clone(),
        destination: destination.to_owned(),
        events: events.iter().map(|event| event.as_ref().to_owned()).collect(),
        filter_rules: filter.as_ref().and_then(|filter| filter.key.as_ref()).map(|key| {
            key.filter_rules
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|rule| (rule.name.as_ref().map(|name| name.as_str().to_owned()), rule.value.clone()))
                .collect()
        }),
    }
}

fn old_structure(value: NotificationConfiguration) -> PersistedNotificationConfiguration {
    PersistedNotificationConfiguration {
        event_bridge_configuration: value.event_bridge_configuration.map(|_| PersistedEventBridgeConfiguration),
        lambda_function_configurations: value.lambda_function_configurations.map(|configurations| {
            configurations
                .into_iter()
                .map(|configuration| PersistedLambdaFunctionConfiguration {
                    events: event_strings(configuration.events),
                    filter: configuration.filter.map(old_filter),
                    id: configuration.id,
                    lambda_function_arn: configuration.lambda_function_arn,
                })
                .collect()
        }),
        queue_configurations: value.queue_configurations.map(|configurations| {
            configurations
                .into_iter()
                .map(|configuration| PersistedQueueConfiguration {
                    events: event_strings(configuration.events),
                    filter: configuration.filter.map(old_filter),
                    id: configuration.id,
                    queue_arn: configuration.queue_arn,
                })
                .collect()
        }),
        topic_configurations: value.topic_configurations.map(|configurations| {
            configurations
                .into_iter()
                .map(|configuration| PersistedTopicConfiguration {
                    events: event_strings(configuration.events),
                    filter: configuration.filter.map(old_filter),
                    id: configuration.id,
                    topic_arn: configuration.topic_arn,
                })
                .collect()
        }),
    }
}

fn event_strings(events: Vec<Event>) -> Vec<String> {
    events.into_iter().map(|event| event.as_ref().to_owned()).collect()
}

fn old_filter(filter: NotificationConfigurationFilter) -> PersistedNotificationConfigurationFilter {
    PersistedNotificationConfigurationFilter {
        key: filter.key.map(|key| PersistedS3KeyFilter {
            filter_rules: key.filter_rules.map(|rules| {
                rules
                    .into_iter()
                    .map(|rule| PersistedFilterRule {
                        name: rule.name.map(|name| name.as_str().to_owned()),
                        value: rule.value,
                    })
                    .collect()
            }),
        }),
    }
}

/// Serializes a Notification value with the pinned old persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old encoder refuses the value.
pub fn serialize_s3s_notification(value: &PersistedNotificationConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = NotificationConfiguration {
        event_bridge_configuration: value
            .event_bridge_configuration
            .as_ref()
            .map(|_| EventBridgeConfiguration::default()),
        lambda_function_configurations: value.lambda_function_configurations.as_ref().map(|configurations| {
            configurations
                .iter()
                .map(|configuration| LambdaFunctionConfiguration {
                    events: old_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(new_filter),
                    id: configuration.id.clone(),
                    lambda_function_arn: configuration.lambda_function_arn.clone(),
                })
                .collect()
        }),
        queue_configurations: value.queue_configurations.as_ref().map(|configurations| {
            configurations
                .iter()
                .map(|configuration| QueueConfiguration {
                    events: old_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(new_filter),
                    id: configuration.id.clone(),
                    queue_arn: configuration.queue_arn.clone(),
                })
                .collect()
        }),
        topic_configurations: value.topic_configurations.as_ref().map(|configurations| {
            configurations
                .iter()
                .map(|configuration| TopicConfiguration {
                    events: old_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(new_filter),
                    id: configuration.id.clone(),
                    topic_arn: configuration.topic_arn.clone(),
                })
                .collect()
        }),
    };
    serialize_old(&old_value)
}

fn old_events(events: &[String]) -> Vec<Event> {
    events.iter().cloned().map(Event::from).collect()
}

fn new_filter(filter: &PersistedNotificationConfigurationFilter) -> NotificationConfigurationFilter {
    NotificationConfigurationFilter {
        key: filter.key.as_ref().map(|key| S3KeyFilter {
            filter_rules: key.filter_rules.as_ref().map(|rules| {
                rules
                    .iter()
                    .map(|rule| FilterRule {
                        name: rule.name.clone().map(FilterRuleName::from),
                        value: rule.value.clone(),
                    })
                    .collect()
            }),
        }),
    }
}

fn serialize_old<T: Serialize>(value: &T) -> Result<Vec<u8>, CompatCodecError> {
    let mut output = Vec::with_capacity(1024);
    let mut serializer = Serializer::new(&mut output);
    value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}
