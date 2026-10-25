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

//! Inputs for the independently measured Select wire fixtures.
//!
//! Responsible for: absent, empty, signed-boundary, and post-terminal event cases.
//! NOT responsible for: expected framing bytes or evaluating the stream.
//! Upstream: public-API measurements of pinned s3s. Downstream: the typed response parity test.

use bytes::Bytes;
use rustfs_gateway_types::SelectEventError;
use rustfs_gateway_types::dto::{ContinuationEvent, EndEvent, Progress, ProgressEvent, RecordsEvent, Stats, StatsEvent};

use super::Event;
use super::tests::Item;

fn records(payload: Option<Bytes>) -> Item {
    Ok(Event::Records(RecordsEvent { payload }))
}

fn end() -> Item {
    Ok(Event::End(EndEvent {}))
}

pub(super) fn cases() -> Vec<(&'static str, Vec<Item>)> {
    vec![
        ("records_absent", vec![records(None)]),
        ("records_empty", vec![records(Some(Bytes::new()))]),
        ("records_bytes", vec![records(Some(Bytes::from_static(b"a\0\xffz")))]),
        ("progress_absent", vec![Ok(Event::Progress(ProgressEvent { details: None }))]),
        (
            "progress_empty",
            vec![Ok(Event::Progress(ProgressEvent {
                details: Some(Progress::default()),
            }))],
        ),
        (
            "progress_partial",
            vec![Ok(Event::Progress(ProgressEvent {
                details: Some(Progress {
                    bytes_scanned: Some(-7),
                    bytes_processed: None,
                    bytes_returned: Some(0),
                }),
            }))],
        ),
        ("stats_absent", vec![Ok(Event::Stats(StatsEvent { details: None }))]),
        (
            "stats_empty",
            vec![Ok(Event::Stats(StatsEvent {
                details: Some(Stats::default()),
            }))],
        ),
        (
            "stats_partial",
            vec![Ok(Event::Stats(StatsEvent {
                details: Some(Stats {
                    bytes_scanned: Some(i64::MAX),
                    bytes_processed: Some(i64::MIN),
                    bytes_returned: None,
                }),
            }))],
        ),
        ("cont", vec![Ok(Event::Cont(ContinuationEvent {}))]),
        ("end", vec![end()]),
        ("error_default", vec![Err(SelectEventError::new("AccessDenied", "Access Denied"))]),
        ("error_empty", vec![Err(SelectEventError::new("AccessDenied", ""))]),
        ("error_message", vec![Err(SelectEventError::new("InternalError", "a<&\"\n\u{96ea}"))]),
        ("after_end", vec![end(), records(Some(Bytes::from_static(b"after")))]),
        (
            "after_error",
            vec![
                Err(SelectEventError::new("AccessDenied", "Access Denied")),
                records(Some(Bytes::from_static(b"after"))),
            ],
        ),
    ]
}
