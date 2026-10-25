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

//! The owned producer and in-band error of a Select response.
//!
//! Responsible for: moving a live, cancellable event producer across the handler boundary.
//! NOT responsible for: framing, HTTP headers, query execution, or event-sequence policy.
//! Upstream: the Select handler. Downstream: the response codec and migration adapters.

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures_core::Stream;

use crate::dto::SelectObjectContentEventStream as Event;

/// An S3 Select failure carried inside an already-started response.
///
/// The message is resolved by the producer. Empty messages stay empty; the codec never
/// substitutes a default. Header wire-length limits are checked when the event is framed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectEventError {
    code: String,
    message: String,
}

impl SelectEventError {
    /// Creates an in-band failure from its wire code and resolved message.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// The `:error-code` header value.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The `:error-message` header value, including explicit emptiness.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A live producer of Select events and in-band failures.
///
/// The generated [`Event`] union describes one event; this carrier owns the producer.
/// Construction does not poll or buffer it. Polling and dropping the carrier reach the
/// original producer, preserving backpressure and cancellation. `End` and in-band failures
/// are values: the producer decides when the stream itself ends.
pub struct SelectEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<Event, SelectEventError>> + Send + 'static>>,
}

impl SelectEventStream {
    /// Takes ownership of a producer without polling it or requiring it to be `Sync`.
    #[must_use]
    pub fn new(stream: impl Stream<Item = Result<Event, SelectEventError>> + Send + 'static) -> Self {
        Self { inner: Box::pin(stream) }
    }
}

impl Stream for SelectEventStream {
    type Item = Result<Event, SelectEventError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for SelectEventStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectEventStream").finish_non_exhaustive()
    }
}
