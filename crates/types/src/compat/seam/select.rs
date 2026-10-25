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

//! The live Select response migration seam, compiled once per legacy revision.
//!
//! Responsible for: moving optional event producers and whole-response extra headers in either
//! output direction without polling or normalizing fields.
//! NOT responsible for: nested Select inputs, query execution, HTTP policy or event framing.
//! Upstream: the owned DTO and the bound legacy revision. Downstream: RustFS migration adapters.

use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_core::Stream;

use super::s3s;
use super::s3s::dto as legacy;
use crate::{SelectEventError, SelectEventStream, dto};

/// Every owned Select output member that the response seam carries.
pub const GATEWAY_OUTPUT_MEMBERS: &[&str] = &["payload"];

/// Moves a legacy response producer into the owned response without reading it.
///
/// An unrecognized future legacy event becomes a fixed in-band InternalError; its data is not exposed.
#[must_use]
pub fn output_from_s3s(output: legacy::SelectObjectContentOutput) -> dto::SelectObjectContentOutput {
    // Exhaustive on the legacy struct so a re-pin cannot silently drop a new response member.
    let legacy::SelectObjectContentOutput { payload } = output;
    dto::SelectObjectContentOutput {
        payload: payload.map(|events| SelectEventStream::new(LegacyEvents { events })),
    }
}

/// Moves an owned response producer into the legacy response without reading it.
#[must_use]
pub fn output_to_s3s(output: dto::SelectObjectContentOutput) -> legacy::SelectObjectContentOutput {
    legacy::SelectObjectContentOutput {
        payload: output.payload.map(|events| {
            legacy::SelectObjectContentEventStream::new(GatewayEvents {
                events: Mutex::new(events),
            })
        }),
    }
}

/// Carries the legacy output and all extra response headers into the owned response path.
#[must_use]
pub fn answer_from_legacy(
    output: legacy::SelectObjectContentOutput,
    headers: http::HeaderMap,
) -> (dto::SelectObjectContentOutput, http::HeaderMap) {
    (output_from_s3s(output), headers)
}

struct LegacyEvents {
    events: legacy::SelectObjectContentEventStream,
}

impl Stream for LegacyEvents {
    type Item = Result<dto::SelectObjectContentEventStream, SelectEventError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().events)
            .poll_next(cx)
            .map(|item| item.map(|item| item.map_err(error_from_s3s).and_then(event_from_s3s)))
    }
}

/// The mutex supplies the legacy constructor's Sync bound for an owned Send-only producer.
/// Polling uses exclusive access through get_mut and never acquires a lock.
struct GatewayEvents {
    events: Mutex<SelectEventStream>,
}

impl Stream for GatewayEvents {
    type Item = s3s::S3Result<legacy::SelectObjectContentEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let events = self.get_mut().events.get_mut().unwrap_or_else(PoisonError::into_inner);
        Pin::new(events)
            .poll_next(cx)
            .map(|item| item.map(|item| item.map(event_to_s3s).map_err(error_to_s3s)))
    }
}

fn error_from_s3s(error: s3s::S3Error) -> SelectEventError {
    // The public getter already resolves newer revisions' defaults and preserves explicit emptiness.
    // The baseline has no default sentence; its event encoder writes the missing message as empty.
    SelectEventError::new(error.code().as_str().to_owned(), error.message().unwrap_or_default().to_owned())
}

fn error_to_s3s(error: SelectEventError) -> s3s::S3Error {
    let code = s3s::S3ErrorCode::from_bytes(error.code().as_bytes())
        .unwrap_or_else(|| s3s::S3ErrorCode::Custom(error.code().to_owned().into()));
    s3s::S3Error::with_message(code, error.message().to_owned())
}

fn event_from_s3s(event: legacy::SelectObjectContentEvent) -> Result<dto::SelectObjectContentEventStream, SelectEventError> {
    Ok(match event {
        legacy::SelectObjectContentEvent::Records(legacy::RecordsEvent { payload }) => {
            dto::SelectObjectContentEventStream::Records(dto::RecordsEvent { payload })
        }
        legacy::SelectObjectContentEvent::Progress(legacy::ProgressEvent { details }) => {
            dto::SelectObjectContentEventStream::Progress(dto::ProgressEvent {
                details: details.map(
                    |legacy::Progress {
                         bytes_processed,
                         bytes_returned,
                         bytes_scanned,
                     }| dto::Progress {
                        bytes_processed,
                        bytes_returned,
                        bytes_scanned,
                    },
                ),
            })
        }
        legacy::SelectObjectContentEvent::Stats(legacy::StatsEvent { details }) => {
            dto::SelectObjectContentEventStream::Stats(dto::StatsEvent {
                details: details.map(
                    |legacy::Stats {
                         bytes_processed,
                         bytes_returned,
                         bytes_scanned,
                     }| dto::Stats {
                        bytes_processed,
                        bytes_returned,
                        bytes_scanned,
                    },
                ),
            })
        }
        legacy::SelectObjectContentEvent::Cont(legacy::ContinuationEvent {}) => {
            dto::SelectObjectContentEventStream::Cont(dto::ContinuationEvent {})
        }
        legacy::SelectObjectContentEvent::End(legacy::EndEvent {}) => dto::SelectObjectContentEventStream::End(dto::EndEvent {}),
        _ => return Err(SelectEventError::new("InternalError", "Unsupported legacy Select event")),
    })
}

fn event_to_s3s(event: dto::SelectObjectContentEventStream) -> legacy::SelectObjectContentEvent {
    match event {
        dto::SelectObjectContentEventStream::Records(value) => {
            legacy::SelectObjectContentEvent::Records(legacy::RecordsEvent { payload: value.payload })
        }
        dto::SelectObjectContentEventStream::Progress(value) => {
            legacy::SelectObjectContentEvent::Progress(legacy::ProgressEvent {
                details: value.details.map(|value| legacy::Progress {
                    bytes_processed: value.bytes_processed,
                    bytes_returned: value.bytes_returned,
                    bytes_scanned: value.bytes_scanned,
                }),
            })
        }
        dto::SelectObjectContentEventStream::Stats(value) => legacy::SelectObjectContentEvent::Stats(legacy::StatsEvent {
            details: value.details.map(|value| legacy::Stats {
                bytes_processed: value.bytes_processed,
                bytes_returned: value.bytes_returned,
                bytes_scanned: value.bytes_scanned,
            }),
        }),
        dto::SelectObjectContentEventStream::Cont(_) => legacy::SelectObjectContentEvent::Cont(legacy::ContinuationEvent {}),
        dto::SelectObjectContentEventStream::End(_) => legacy::SelectObjectContentEvent::End(legacy::EndEvent {}),
    }
}
