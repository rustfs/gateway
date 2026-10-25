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

//! Lazy framing of an owned Select response producer.
//!
//! Responsible for: one event per poll, optional accounting values, and measured wire ordering.
//! NOT responsible for: query execution, HTTP headers, or imposing an event-sequence policy.
//! Upstream: the generated Select codec. Downstream: the shared frame encoder and transport.

use core::fmt::Write as _;
use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use rustfs_gateway_stream::{ByteStream, Payload, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use rustfs_gateway_types::dto::SelectObjectContentEventStream as Event;
use rustfs_gateway_types::{SelectEventError, SelectEventStream};

use super::{EventKind, EventStreamError, encode_message, push_string_header};
use crate::codec::CodecError;

pub(crate) fn encode_stream(events: SelectEventStream) -> Result<ByteStream, CodecError> {
    let payload = Payload::from_stream(SelectFrames { events })
        .map_err(|_| CodecError::internal("invalid Select response stream capabilities"))?;
    let Payload::Stream(stream) = payload else {
        return Err(CodecError::internal("Select response producer is not a stream"));
    };
    ByteStream::new(stream).map_err(|_| CodecError::internal("invalid Select response stream capabilities"))
}

// The enclosing ByteStream owns terminal state after EOF or a framing failure.
struct SelectFrames {
    events: SelectEventStream,
}

impl PayloadStream for SelectFrames {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        match Pin::new(&mut this.events).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            })),
            Poll::Ready(Some(event)) => Poll::Ready(frame(event).map(|bytes| PayloadRead::Chunk(bytes.into()))),
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

fn framing_error(error: EventStreamError) -> StreamError {
    StreamError::upstream(Box::new(error))
}

fn frame(event: Result<Event, SelectEventError>) -> Result<Vec<u8>, StreamError> {
    let mut headers = Vec::new();
    let payload = match event {
        Ok(event) => {
            let (kind, payload) = event_parts(event)?;
            push_string_header(&mut headers, ":event-type", kind.event_type()).map_err(framing_error)?;
            if let Some(content_type) = kind.content_type() {
                push_string_header(&mut headers, ":content-type", content_type).map_err(framing_error)?;
            }
            push_string_header(&mut headers, ":message-type", "event").map_err(framing_error)?;
            payload
        }
        Err(error) => {
            push_string_header(&mut headers, ":error-code", error.code()).map_err(framing_error)?;
            push_string_header(&mut headers, ":error-message", error.message()).map_err(framing_error)?;
            push_string_header(&mut headers, ":message-type", "error").map_err(framing_error)?;
            Bytes::new()
        }
    };
    let mut out = Vec::new();
    encode_message(&headers, &payload, &mut out).map_err(framing_error)?;
    Ok(out)
}

fn event_parts(event: Event) -> Result<(EventKind, Bytes), StreamError> {
    Ok(match event {
        Event::Records(event) => (EventKind::Records, event.payload.unwrap_or_default()),
        Event::Progress(event) => (
            EventKind::Progress,
            accounting("Progress", event.details.map(|d| [d.bytes_processed, d.bytes_returned, d.bytes_scanned])),
        ),
        Event::Stats(event) => (
            EventKind::Stats,
            accounting("Stats", event.details.map(|d| [d.bytes_processed, d.bytes_returned, d.bytes_scanned])),
        ),
        Event::Cont(_) => (EventKind::Cont, Bytes::new()),
        Event::End(_) => (EventKind::End, Bytes::new()),
        _ => return Err(StreamError::upstream(Box::new(CodecError::internal("unsupported Select event variant")))),
    })
}

fn accounting(root: &str, details: Option<[Option<i64>; 3]>) -> Bytes {
    let Some(values) = details else {
        return Bytes::new();
    };
    let mut document = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = write!(document, "<{root}>");
    for (name, value) in ["BytesProcessed", "BytesReturned", "BytesScanned"].into_iter().zip(values) {
        if let Some(value) = value {
            let _ = write!(document, "<{name}>{value}</{name}>");
        }
    }
    let _ = write!(document, "</{root}>");
    document.into()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cases;
