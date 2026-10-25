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

//! Shared Select seam checks instantiated against three distinct public legacy APIs.
//!
//! Responsible for: independent wire goldens, optional values, response headers and lazy ownership.
//! NOT responsible for: request conversion or query execution.
//! Upstream: public probe receipts linked from issue #1470. Downstream: the goldens test target.

macro_rules! define_tests {
    ($name:ident, $revision_module:ident, $revision:literal, $message:literal) => {
        mod $name {
            use std::cell::Cell;
            use std::collections::VecDeque;
            use std::pin::Pin;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::task::{Context, Poll, Waker};

            use bytes::Bytes;
            use futures_core::Stream;
            use legacy_api::dto as legacy;
            use rustfs_gateway_core::codec::response::{EncodedResponse, ResponseBody};
            use rustfs_gateway_core::codec::{MetaView, OperationCodec};
            use rustfs_gateway_core::route::TargetKind;
            use rustfs_gateway_http::{Limits, WireRequest};
            use rustfs_gateway_stream::{PayloadRead, PayloadStream};
            use rustfs_gateway_types::compat::$revision_module as seam;
            use rustfs_gateway_types::{SelectEventError, SelectEventStream as OwnedStream, dto};
            use seam::s3s as legacy_api;

            const REVISION: &str = $revision;
            const DEFAULT_MESSAGE: &str = $message;
            type LegacyItem = legacy_api::S3Result<legacy::SelectObjectContentEvent>;
            type OwnedItem = Result<dto::SelectObjectContentEventStream, SelectEventError>;

            #[derive(Clone, Default)]
            struct Counts {
                polls: Arc<AtomicUsize>,
                drops: Arc<AtomicUsize>,
            }
            impl Counts {
                fn totals(&self) -> [usize; 2] {
                    [self.polls.load(Ordering::SeqCst), self.drops.load(Ordering::SeqCst)]
                }
            }
            struct Source<T, M> {
                items: VecDeque<T>,
                counts: Counts,
                pending: bool,
                _marker: M,
            }
            impl<T: Unpin, M: Unpin> Stream for Source<T, M> {
                type Item = T;
                fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
                    let this = self.get_mut();
                    this.counts.polls.fetch_add(1, Ordering::SeqCst);
                    if std::mem::take(&mut this.pending) {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        Poll::Ready(this.items.pop_front())
                    }
                }
            }
            impl<T, M> Drop for Source<T, M> {
                fn drop(&mut self) {
                    self.counts.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
            fn source<T, M>(items: Vec<T>, pending: bool, marker: M) -> (Source<T, M>, Counts) {
                let counts = Counts::default();
                (
                    Source {
                        items: items.into(),
                        counts: counts.clone(),
                        pending,
                        _marker: marker,
                    },
                    counts,
                )
            }
            fn legacy_output(items: Vec<LegacyItem>) -> legacy::SelectObjectContentOutput {
                legacy::SelectObjectContentOutput {
                    payload: Some(legacy::SelectObjectContentEventStream::new(source(items, false, ()).0)),
                }
            }
            fn owned_output(items: Vec<OwnedItem>) -> dto::SelectObjectContentOutput {
                dto::SelectObjectContentOutput {
                    payload: Some(OwnedStream::new(source(items, false, Cell::new(())).0)),
                }
            }
            fn expected(name: &str) -> Vec<u8> {
                let hex = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/select_seam/wire-golden.txt"))
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.split('\t');
                        let revision = parts.next()?;
                        let case = parts.next()?;
                        let bytes = parts.next()?;
                        (revision == REVISION && case == name).then_some(bytes)
                    })
                    .expect("the independently measured case exists");
                hex.as_bytes()
                    .chunks(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("measured hex byte"))
                    .collect()
            }
            fn encode(output: dto::SelectObjectContentOutput) -> EncodedResponse {
                let request = http::Request::builder()
                    .method("POST")
                    .uri("http://localhost/bkt/key?select&select-type=2")
                    .header("host", "localhost")
                    .body(())
                    .expect("fixture request");
                let request = WireRequest::accept(request, &Limits::default()).expect("accepted fixture");
                let view = MetaView::of(&request, TargetKind::Object).expect("fixture view");
                dto::SelectObjectContent::encode(output, &view, 200).expect("Select response")
            }
            fn gateway_bytes(output: dto::SelectObjectContentOutput) -> Vec<u8> {
                let mut stream = match encode(output).body {
                    ResponseBody::Empty => return Vec::new(),
                    ResponseBody::Stream(stream) => stream,
                    other => panic!("expected live Select response: {other:?}"),
                };
                let mut out = Vec::new();
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..100 {
                    match Pin::new(&mut stream).poll_read(&mut cx) {
                        Poll::Ready(Ok(PayloadRead::Chunk(bytes))) => out.extend_from_slice(&bytes),
                        Poll::Ready(Ok(PayloadRead::Eof { .. })) => return out,
                        other => panic!("immediate fixture did not yield a frame: {other:?}"),
                    }
                }
                panic!("fixture did not terminate")
            }
            fn legacy_bytes(output: legacy::SelectObjectContentOutput) -> Vec<u8> {
                let Some(payload) = output.payload else { return Vec::new() };
                let mut stream = payload.into_byte_stream();
                let mut out = Vec::new();
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..100 {
                    match Pin::new(&mut stream).poll_next(&mut cx) {
                        Poll::Ready(Some(Ok(bytes))) => out.extend_from_slice(&bytes),
                        Poll::Ready(None) => return out,
                        other => panic!("immediate fixture did not yield bytes: {other:?}"),
                    }
                }
                panic!("fixture did not terminate")
            }
            fn empty_kind<S: Stream + Unpin>(stream: Option<S>) -> (&'static str, bool) {
                match stream {
                    None => ("absent", true),
                    Some(mut stream) => (
                        "present",
                        matches!(
                            Pin::new(&mut stream).poll_next(&mut Context::from_waker(Waker::noop())),
                            Poll::Ready(None)
                        ),
                    ),
                }
            }
            fn observed<S: Stream + Unpin>(mut stream: Option<S>, counts: Counts) -> Vec<(&'static str, [usize; 2])> {
                let mut out = vec![("constructed", counts.totals())];
                for _ in 0..2 {
                    let kind = match stream
                        .as_mut()
                        .map(|stream| Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop())))
                    {
                        None => "missing",
                        Some(Poll::Pending) => "pending",
                        Some(Poll::Ready(Some(_))) => "item",
                        Some(Poll::Ready(None)) => "eof",
                    };
                    out.push((kind, counts.totals()));
                }
                drop(stream);
                out.push(("dropped", counts.totals()));
                out
            }

            fn legacy_cases() -> Vec<(&'static str, Vec<LegacyItem>)> {
                use legacy::*;
                use legacy_api::{S3Error, S3ErrorCode};
                fn records(payload: Option<Bytes>) -> LegacyItem {
                    Ok(legacy::SelectObjectContentEvent::Records(legacy::RecordsEvent { payload }))
                }
                fn end() -> LegacyItem {
                    Ok(legacy::SelectObjectContentEvent::End(legacy::EndEvent {}))
                }
                vec![
                    ("records_absent", vec![records(None)]),
                    ("records_empty", vec![records(Some(Bytes::new()))]),
                    ("records_bytes", vec![records(Some(Bytes::from_static(b"a\0\xffz")))]),
                    (
                        "progress_absent",
                        vec![Ok(SelectObjectContentEvent::Progress(ProgressEvent { details: None }))],
                    ),
                    (
                        "progress_empty",
                        vec![Ok(SelectObjectContentEvent::Progress(ProgressEvent {
                            details: Some(Progress::default()),
                        }))],
                    ),
                    (
                        "progress_partial",
                        vec![Ok(SelectObjectContentEvent::Progress(ProgressEvent {
                            details: Some(Progress {
                                bytes_scanned: Some(-7),
                                bytes_processed: None,
                                bytes_returned: Some(0),
                            }),
                        }))],
                    ),
                    ("stats_absent", vec![Ok(SelectObjectContentEvent::Stats(StatsEvent { details: None }))]),
                    (
                        "stats_empty",
                        vec![Ok(SelectObjectContentEvent::Stats(StatsEvent {
                            details: Some(Stats::default()),
                        }))],
                    ),
                    (
                        "stats_partial",
                        vec![Ok(SelectObjectContentEvent::Stats(StatsEvent {
                            details: Some(Stats {
                                bytes_scanned: Some(i64::MAX),
                                bytes_processed: Some(i64::MIN),
                                bytes_returned: None,
                            }),
                        }))],
                    ),
                    ("cont", vec![Ok(SelectObjectContentEvent::Cont(ContinuationEvent {}))]),
                    ("end", vec![end()]),
                    ("error_default", vec![Err(S3Error::new(S3ErrorCode::AccessDenied))]),
                    ("custom_default", vec![Err(S3Error::new(S3ErrorCode::Custom("Odd:/x".into())))]),
                    ("custom_empty", vec![Err(S3Error::with_message(S3ErrorCode::Custom("Odd:/x".into()), ""))]),
                    ("error_empty", vec![Err(S3Error::with_message(S3ErrorCode::AccessDenied, ""))]),
                    (
                        "error_message",
                        vec![Err(S3Error::with_message(
                            S3ErrorCode::InternalError,
                            "a<&\"\n\u{96ea}",
                        ))],
                    ),
                    ("after_end", vec![end(), records(Some(Bytes::from_static(b"after")))]),
                    (
                        "after_error",
                        vec![
                            Err(S3Error::new(S3ErrorCode::AccessDenied)),
                            records(Some(Bytes::from_static(b"after"))),
                        ],
                    ),
                    (
                        "custom_long",
                        vec![Err(S3Error::with_message(
                            S3ErrorCode::Custom("X".repeat(129).into()),
                            "m".repeat(1025),
                        ))],
                    ),
                ]
            }

            fn owned_cases() -> Vec<(&'static str, Vec<OwnedItem>)> {
                use dto::*;
                fn records(payload: Option<Bytes>) -> OwnedItem {
                    Ok(dto::SelectObjectContentEventStream::Records(dto::RecordsEvent { payload }))
                }
                fn end() -> OwnedItem {
                    Ok(dto::SelectObjectContentEventStream::End(dto::EndEvent {}))
                }
                vec![
                    ("records_absent", vec![records(None)]),
                    ("records_empty", vec![records(Some(Bytes::new()))]),
                    ("records_bytes", vec![records(Some(Bytes::from_static(b"a\0\xffz")))]),
                    (
                        "progress_absent",
                        vec![Ok(SelectObjectContentEventStream::Progress(ProgressEvent {
                            details: None,
                        }))],
                    ),
                    (
                        "progress_empty",
                        vec![Ok(SelectObjectContentEventStream::Progress(ProgressEvent {
                            details: Some(Progress::default()),
                        }))],
                    ),
                    (
                        "progress_partial",
                        vec![Ok(SelectObjectContentEventStream::Progress(ProgressEvent {
                            details: Some(Progress {
                                bytes_scanned: Some(-7),
                                bytes_processed: None,
                                bytes_returned: Some(0),
                            }),
                        }))],
                    ),
                    (
                        "stats_absent",
                        vec![Ok(SelectObjectContentEventStream::Stats(StatsEvent { details: None }))],
                    ),
                    (
                        "stats_empty",
                        vec![Ok(SelectObjectContentEventStream::Stats(StatsEvent {
                            details: Some(Stats::default()),
                        }))],
                    ),
                    (
                        "stats_partial",
                        vec![Ok(SelectObjectContentEventStream::Stats(StatsEvent {
                            details: Some(Stats {
                                bytes_scanned: Some(i64::MAX),
                                bytes_processed: Some(i64::MIN),
                                bytes_returned: None,
                            }),
                        }))],
                    ),
                    ("cont", vec![Ok(SelectObjectContentEventStream::Cont(ContinuationEvent {}))]),
                    ("end", vec![end()]),
                    ("error_default", vec![Err(SelectEventError::new("AccessDenied", DEFAULT_MESSAGE))]),
                    ("custom_default", vec![Err(SelectEventError::new("Odd:/x", ""))]),
                    ("custom_empty", vec![Err(SelectEventError::new("Odd:/x", ""))]),
                    ("error_empty", vec![Err(SelectEventError::new("AccessDenied", ""))]),
                    ("error_message", vec![Err(SelectEventError::new("InternalError", "a<&\"\n\u{96ea}"))]),
                    ("after_end", vec![end(), records(Some(Bytes::from_static(b"after")))]),
                    (
                        "after_error",
                        vec![
                            Err(SelectEventError::new("AccessDenied", DEFAULT_MESSAGE)),
                            records(Some(Bytes::from_static(b"after"))),
                        ],
                    ),
                    ("custom_long", vec![Err(SelectEventError::new("X".repeat(129), "m".repeat(1025)))]),
                ]
            }

            #[test]
            fn n_the_response_seam_declares_every_owned_output_member() {
                let counts =
                    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/dto/field_counts.txt"))
                        .expect("committed field-count ratchet");
                let count: usize = counts
                    .lines()
                    .find_map(|line| {
                        let (name, count) = line.split_once(' ')?;
                        (name == "SelectObjectContentOutput").then(|| count.trim().parse().expect("field count"))
                    })
                    .expect("Select output field count");
                let members = seam::select::GATEWAY_OUTPUT_MEMBERS;
                assert_eq!((members, count), (&["payload"][..], members.len()));
            }

            #[test]
            fn legacy_select_output_keeps_measured_wire() {
                for (name, items) in legacy_cases() {
                    assert_eq!(
                        gateway_bytes(seam::select::output_from_s3s(legacy_output(items))),
                        expected(name),
                        "{REVISION}/{name}"
                    );
                }
            }
            #[test]
            fn owned_select_output_keeps_measured_wire() {
                for (name, items) in owned_cases() {
                    assert_eq!(
                        legacy_bytes(seam::select::output_to_s3s(owned_output(items))),
                        expected(name),
                        "{REVISION}/{name}"
                    );
                }
            }
            #[test]
            fn n_absent_and_empty_payloads_stay_distinct() {
                let observed = [
                    empty_kind(seam::select::output_from_s3s(legacy::SelectObjectContentOutput::default()).payload),
                    empty_kind(seam::select::output_from_s3s(legacy_output(Vec::new())).payload),
                    empty_kind(seam::select::output_to_s3s(dto::SelectObjectContentOutput::default()).payload),
                    empty_kind(seam::select::output_to_s3s(owned_output(Vec::new())).payload),
                ];
                assert_eq!(observed, [("absent", true), ("present", true), ("absent", true), ("present", true)]);
            }
            #[test]
            fn n_records_payload_presence_is_not_invented() {
                let mut observed = Vec::new();
                for payload in [None, Some(Bytes::new())] {
                    let mut output = seam::select::output_from_s3s(legacy_output(vec![Ok(
                        legacy::SelectObjectContentEvent::Records(legacy::RecordsEvent {
                            payload: payload.clone(),
                        }),
                    )]));
                    let value = output.payload.as_mut().and_then(|stream| {
                        match Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop())) {
                            Poll::Ready(Some(Ok(dto::SelectObjectContentEventStream::Records(value)))) => {
                                Some(value.payload.is_some())
                            }
                            _ => None,
                        }
                    });
                    observed.push(value);
                    let mut output = seam::select::output_to_s3s(owned_output(vec![Ok(
                        dto::SelectObjectContentEventStream::Records(dto::RecordsEvent { payload }),
                    )]));
                    let value = output.payload.as_mut().and_then(|stream| {
                        match Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop())) {
                            Poll::Ready(Some(Ok(legacy::SelectObjectContentEvent::Records(value)))) => {
                                Some(value.payload.is_some())
                            }
                            _ => None,
                        }
                    });
                    observed.push(value);
                }
                assert_eq!(observed, [Some(false), Some(false), Some(true), Some(true)]);
            }
            #[test]
            fn n_extra_response_headers_are_not_lost() {
                let mut headers = http::HeaderMap::new();
                headers.insert("x-amz-server-side-encryption-customer-algorithm", "AES256".parse().unwrap());
                headers.append("x-fixture", "one".parse().unwrap());
                headers.append("x-fixture", "two".parse().unwrap());
                let (output, returned) = seam::select::answer_from_legacy(legacy_output(Vec::new()), headers.clone());
                assert_eq!((output.payload.is_some(), returned), (true, headers));
            }
            #[test]
            fn n_conversion_never_polls_or_keeps_a_cancelled_producer() {
                let (from_source, from_counts) =
                    source(vec![Ok(legacy::SelectObjectContentEvent::End(legacy::EndEvent {}))], true, ());
                let from = seam::select::output_from_s3s(legacy::SelectObjectContentOutput {
                    payload: Some(legacy::SelectObjectContentEventStream::new(from_source)),
                });
                let from_observed = observed(from.payload, from_counts);
                let (source, to_counts) =
                    source(vec![Ok(dto::SelectObjectContentEventStream::End(dto::EndEvent {}))], true, Cell::new(()));
                let to = seam::select::output_to_s3s(dto::SelectObjectContentOutput {
                    payload: Some(OwnedStream::new(source)),
                });
                let expected = vec![
                    ("constructed", [0, 0]),
                    ("pending", [1, 0]),
                    ("item", [2, 0]),
                    ("dropped", [2, 1]),
                ];
                assert_eq!([from_observed, observed(to.payload, to_counts)], [expected.clone(), expected]);
            }
        }
    };
}
pub(super) use define_tests;
