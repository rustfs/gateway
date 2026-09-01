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

//! Notification generated DTO persistence bridge.
//!
//! Responsible for: lossless conversion through the existing historical Notification codec.
//! NOT responsible for: XML parsing rules, HTTP validation, or delivering notification events.
//! Upstream: Notification persistence codec. Downstream: generated DTO metadata consumers.

use crate::persistence::{
    PersistedEventBridgeConfiguration, PersistedFilterRule, PersistedLambdaFunctionConfiguration,
    PersistedNotificationConfiguration, PersistedNotificationConfigurationFilter, PersistedQueueConfiguration,
    PersistedS3KeyFilter, PersistedTopicConfiguration, PersistenceCodecError, parse_notification, serialize_notification,
};

/// Parses persisted Notification bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] when the historical persistence parser rejects the bytes.
pub fn parse_notification_dto(input: &[u8]) -> Result<crate::dto::NotificationConfiguration, PersistenceCodecError> {
    let persisted = parse_notification(input)?;
    Ok(crate::dto::NotificationConfiguration {
        event_bridge_configuration: persisted
            .event_bridge_configuration
            .map(|_| crate::dto::EventBridgeConfiguration {}),
        lambda_function_configurations: persisted
            .lambda_function_configurations
            .unwrap_or_default()
            .into_iter()
            .map(|configuration| crate::dto::LambdaFunctionConfiguration {
                events: to_dto_events(configuration.events),
                filter: configuration.filter.map(to_dto_filter),
                id: configuration.id,
                lambda_function_arn: configuration.lambda_function_arn,
            })
            .collect(),
        queue_configurations: persisted
            .queue_configurations
            .unwrap_or_default()
            .into_iter()
            .map(|configuration| crate::dto::QueueConfiguration {
                events: to_dto_events(configuration.events),
                filter: configuration.filter.map(to_dto_filter),
                id: configuration.id,
                queue_arn: configuration.queue_arn,
            })
            .collect(),
        topic_configurations: persisted
            .topic_configurations
            .unwrap_or_default()
            .into_iter()
            .map(|configuration| crate::dto::TopicConfiguration {
                events: to_dto_events(configuration.events),
                filter: configuration.filter.map(to_dto_filter),
                id: configuration.id,
                topic_arn: configuration.topic_arn,
            })
            .collect(),
    })
}

fn to_dto_events(events: Vec<String>) -> Vec<crate::dto::Events> {
    events.into_iter().map(crate::dto::Events::custom).collect()
}

fn to_dto_filter(value: PersistedNotificationConfigurationFilter) -> crate::dto::NotificationConfigurationFilter {
    crate::dto::NotificationConfigurationFilter {
        key: value.key.map(|key| crate::dto::S3KeyFilter {
            filter_rules: key
                .filter_rules
                .unwrap_or_default()
                .into_iter()
                .map(|rule| crate::dto::FilterRule {
                    name: rule.name.map(crate::dto::Name::custom),
                    value: rule.value,
                })
                .collect(),
        }),
    }
}

/// Serializes the generated Notification DTO with the historical persistence writer.
#[must_use]
pub fn serialize_notification_dto(value: &crate::dto::NotificationConfiguration) -> Vec<u8> {
    serialize_notification(&PersistedNotificationConfiguration {
        event_bridge_configuration: value
            .event_bridge_configuration
            .as_ref()
            .map(|_| PersistedEventBridgeConfiguration),
        lambda_function_configurations: (!value.lambda_function_configurations.is_empty()).then(|| {
            value
                .lambda_function_configurations
                .iter()
                .map(|configuration| PersistedLambdaFunctionConfiguration {
                    events: from_dto_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(from_dto_filter),
                    id: configuration.id.clone(),
                    lambda_function_arn: configuration.lambda_function_arn.clone(),
                })
                .collect()
        }),
        queue_configurations: (!value.queue_configurations.is_empty()).then(|| {
            value
                .queue_configurations
                .iter()
                .map(|configuration| PersistedQueueConfiguration {
                    events: from_dto_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(from_dto_filter),
                    id: configuration.id.clone(),
                    queue_arn: configuration.queue_arn.clone(),
                })
                .collect()
        }),
        topic_configurations: (!value.topic_configurations.is_empty()).then(|| {
            value
                .topic_configurations
                .iter()
                .map(|configuration| PersistedTopicConfiguration {
                    events: from_dto_events(&configuration.events),
                    filter: configuration.filter.as_ref().map(from_dto_filter),
                    id: configuration.id.clone(),
                    topic_arn: configuration.topic_arn.clone(),
                })
                .collect()
        }),
    })
}

fn from_dto_events(events: &[crate::dto::Events]) -> Vec<String> {
    events.iter().map(|event| event.as_str().to_owned()).collect()
}

fn from_dto_filter(value: &crate::dto::NotificationConfigurationFilter) -> PersistedNotificationConfigurationFilter {
    PersistedNotificationConfigurationFilter {
        key: value.key.as_ref().map(|key| PersistedS3KeyFilter {
            filter_rules: (!key.filter_rules.is_empty()).then(|| {
                key.filter_rules
                    .iter()
                    .map(|rule| PersistedFilterRule {
                        name: rule.name.as_ref().map(|name| name.as_str().to_owned()),
                        value: rule.value.clone(),
                    })
                    .collect()
            }),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_notification_dto, serialize_notification_dto};
    use crate::persistence::PersistenceCodecError;

    const HISTORICAL: &[u8] = b"<NotificationConfiguration><EventBridgeConfiguration></EventBridgeConfiguration><CloudFunctionConfiguration><Event>Future:Lambda</Event><Filter><S3Key><FilterRule><Name>future</Name><Value>logs/</Value></FilterRule></S3Key></Filter><Id>lambda</Id><CloudFunction>arn:aws:lambda:us-east-1:123:function:notify</CloudFunction></CloudFunctionConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Id>queue</Id><Queue>arn:aws:sqs:us-east-1:123:events</Queue></QueueConfiguration><TopicConfiguration><Event>Future:Topic</Event><Id>topic</Id><Topic>arn:aws:sns:us-east-1:123:events</Topic></TopicConfiguration></NotificationConfiguration>";

    #[test]
    fn notification_dto_bridge_preserves_destinations_filters_unknown_enums_and_old_order() {
        let parsed = parse_notification_dto(HISTORICAL).expect("the historical document is representable");
        assert!(parsed.event_bridge_configuration.is_some());
        assert_eq!(parsed.lambda_function_configurations[0].events[0].as_str(), "Future:Lambda");
        assert_eq!(
            parsed.lambda_function_configurations[0].lambda_function_arn,
            "arn:aws:lambda:us-east-1:123:function:notify"
        );
        let rule = &parsed.lambda_function_configurations[0]
            .filter
            .as_ref()
            .and_then(|filter| filter.key.as_ref())
            .expect("the S3Key filter remains present")
            .filter_rules[0];
        assert_eq!(rule.name.as_ref().map(|name| name.as_str()), Some("future"));
        assert_eq!(rule.value.as_deref(), Some("logs/"));
        assert_eq!(parsed.queue_configurations[0].id.as_deref(), Some("queue"));
        assert_eq!(parsed.topic_configurations[0].topic_arn, "arn:aws:sns:us-east-1:123:events");
        assert_eq!(serialize_notification_dto(&parsed), HISTORICAL);
    }

    #[test]
    fn notification_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_notification_dto(b"<ReplicationConfiguration></ReplicationConfiguration>")
                .expect_err("a different family must fail"),
            PersistenceCodecError::WrongRoot
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_duplicate_event_bridge_markers() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><EventBridgeConfiguration></EventBridgeConfiguration><EventBridgeConfiguration></EventBridgeConfiguration></NotificationConfiguration>")
                .expect_err("a singleton marker cannot repeat"),
            PersistenceCodecError::DuplicateField
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_a_destination_without_an_event() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><QueueConfiguration><Queue>arn:queue</Queue></QueueConfiguration></NotificationConfiguration>")
                .expect_err("a destination requires an event"),
            PersistenceCodecError::MissingRequiredField
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_a_destination_without_its_arn() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><TopicConfiguration><Event>s3:ObjectCreated:*</Event></TopicConfiguration></NotificationConfiguration>")
                .expect_err("a destination requires its ARN"),
            PersistenceCodecError::MissingRequiredField
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_an_unknown_destination_member() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Queue>arn:queue</Queue><Future></Future></QueueConfiguration></NotificationConfiguration>")
                .expect_err("destination children are closed"),
            PersistenceCodecError::UnexpectedNotificationElement
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_an_unknown_filter_member() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Filter><Future></Future></Filter><Queue>arn:queue</Queue></QueueConfiguration></NotificationConfiguration>")
                .expect_err("filter children are closed"),
            PersistenceCodecError::UnexpectedNotificationElement
        );
    }

    #[test]
    fn notification_dto_bridge_rejects_nested_xml_in_an_event() {
        assert_eq!(
            parse_notification_dto(b"<NotificationConfiguration><QueueConfiguration><Event><Future></Future></Event><Queue>arn:queue</Queue></QueueConfiguration></NotificationConfiguration>")
                .expect_err("event values are scalar"),
            PersistenceCodecError::UnexpectedScalarElement
        );
    }
}
