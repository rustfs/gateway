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

//! The event-notification document: what a stored one is allowed to say.
//!
//! Shares: bucket_notification
//! Members: GetBucketNotificationConfiguration, PutBucketNotificationConfiguration
//!
//! Responsible for: the semantic rules of a `NotificationConfiguration` document — the floor on a
//! configuration's event list, the key-filter grammar, and the cap on how many configurations one
//! bucket may carry — held once so that every backend refuses the same documents with the same
//! codes.
//! NOT responsible for: decoding the document (the generated codec), storing it, or **delivering**
//! anything. Matching an object write against a rule, publishing to the topic, queue or function,
//! retrying a failed delivery and the destination's own existence are the notification engine's;
//! whether the destination even exists is what the caller suppresses with
//! `x-amz-skip-destination-validation`, and this file never checks it either way.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # What the wire shape is, and why it is stated here as well as in the codec
//!
//! The three configuration lists are **flattened**: `<TopicConfiguration>`, `<QueueConfiguration>`
//! and `<CloudFunctionConfiguration>` repeat directly under the root with no wrapper, and `<Event>`
//! repeats directly inside each of them. That is the opposite of the website document's wrapped
//! `<RoutingRules>`, one family over, and rendering either the other way produces a document every
//! SDK reads as empty. The codec settles it; this note is here so that a reader of the validation
//! does not have to re-derive which shape the rules are talking about.
//!
//! # Why an unknown event name is stored rather than refused
//!
//! AWS adds event types continuously — `s3:ObjectRestore:Delete`, `s3:LifecycleExpiration:*` and
//! the replication set all arrived after the original list. A gateway that refused a name it did
//! not know would reject configurations AWS accepts, and would keep rejecting them until it was
//! rebuilt. The name is stored as sent and the delivery engine decides whether it can match it,
//! which is where the knowledge actually lives.
//!
//! # The refusal messages are constant
//!
//! A notification document carries topic, queue and function ARNs, which name accounts. No reason
//! below repeats one.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{FilterRule, NotificationConfiguration, NotificationConfigurationFilter};

/// The two filter-rule names S3 defines. Unlike an event name, this set has not grown since the
/// filter was introduced and a third value has no meaning to any implementation.
const FILTER_NAMES: &[&str] = &["prefix", "suffix"];

/// The largest number of configurations one bucket may carry, across all three destination kinds.
///
/// AWS documents a hundred; the cap is here so that a document nothing can store is refused before
/// it is stored rather than after.
const MAX_CONFIGURATIONS: usize = 100;

/// Why a decoded notification document was refused, with the code AWS answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationRejection {
    /// A configuration with no `<Event>` at all. A destination that subscribes to nothing is not a
    /// subscription, and the model makes the list required.
    NoEvents,
    /// A configuration whose destination ARN is the empty string.
    DestinationEmpty,
    /// A `<FilterRule>` whose `<Name>` is neither `prefix` nor `suffix`.
    FilterNameUnknown,
    /// Two `<FilterRule>` elements with the same `<Name>` inside one `<S3Key>`. One prefix and one
    /// suffix are the whole grammar; a second prefix has no defined meaning.
    FilterNameRepeated,
    /// More configurations than one bucket may carry.
    TooManyConfigurations,
}

impl NotificationRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // Structural: the document is not the document.
            NotificationRejection::NoEvents
            | NotificationRejection::FilterNameUnknown
            | NotificationRejection::FilterNameRepeated => ErrorCode::MALFORMED_XML,
            // Present, well-formed values this operation cannot use.
            NotificationRejection::DestinationEmpty | NotificationRejection::TooManyConfigurations => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes — and never carrying an ARN.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            NotificationRejection::NoEvents => "each notification configuration must subscribe to at least one Event",
            NotificationRejection::DestinationEmpty => "each notification configuration must name a destination",
            NotificationRejection::FilterNameUnknown => "a FilterRule Name is either prefix or suffix",
            NotificationRejection::FilterNameRepeated => "an S3Key filter carries at most one prefix and one suffix rule",
            NotificationRejection::TooManyConfigurations => "a bucket carries at most 100 notification configurations",
        }
    }
}

/// Checks one destination's event list, ARN and filter — the three rules every configuration kind
/// shares, applied identically to topics, queues and functions.
fn one_configuration(
    events: usize,
    destination: &str,
    filter: Option<&NotificationConfigurationFilter>,
) -> Result<(), NotificationRejection> {
    if events == 0 {
        return Err(NotificationRejection::NoEvents);
    }
    if destination.is_empty() {
        return Err(NotificationRejection::DestinationEmpty);
    }
    match filter.and_then(|f| f.key.as_ref()) {
        Some(key) => validate_filter_rules(&key.filter_rules),
        None => Ok(()),
    }
}

/// Checks the rules inside one `<S3Key>` filter: known names, each at most once.
fn validate_filter_rules(rules: &[FilterRule]) -> Result<(), NotificationRejection> {
    let mut seen: Vec<&str> = Vec::new();
    for rule in rules {
        let Some(name) = rule.name.as_ref() else {
            // A rule with no name at all is the decoder's business, and the model makes the member
            // optional; an unnamed rule filters nothing and is stored as sent.
            continue;
        };
        let name = name.as_str();
        if !FILTER_NAMES.contains(&name) {
            return Err(NotificationRejection::FilterNameUnknown);
        }
        if seen.contains(&name) {
            return Err(NotificationRejection::FilterNameRepeated);
        }
        seen.push(name);
    }
    Ok(())
}

/// Checks a decoded notification document against the family's semantic rules, first refusal wins.
///
/// An empty `<NotificationConfiguration/>` passes: it is the documented spelling of "deliver
/// nothing", and the only spelling there is — the model declares no delete for this subresource.
///
/// # Errors
///
/// [`NotificationRejection`] naming the first rule the document breaks.
pub fn validate_notification(configuration: &NotificationConfiguration) -> Result<(), NotificationRejection> {
    let total = configuration
        .topic_configurations
        .len()
        .saturating_add(configuration.queue_configurations.len())
        .saturating_add(configuration.lambda_function_configurations.len());
    if total > MAX_CONFIGURATIONS {
        return Err(NotificationRejection::TooManyConfigurations);
    }
    for topic in &configuration.topic_configurations {
        one_configuration(topic.events.len(), &topic.topic_arn, topic.filter.as_ref())?;
    }
    for queue in &configuration.queue_configurations {
        one_configuration(queue.events.len(), &queue.queue_arn, queue.filter.as_ref())?;
    }
    for lambda in &configuration.lambda_function_configurations {
        one_configuration(lambda.events.len(), &lambda.lambda_function_arn, lambda.filter.as_ref())?;
    }
    Ok(())
}
