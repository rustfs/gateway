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

//! Independent Select error-frame observations and real production transport controls.
//!
//! Responsible for: the AWS error-header grammar, terminal ordering, and a failed record source
//! served over both production drivers. NOT responsible for: SQL evaluation or the corpus fault
//! schema. Upstream: `super`, the published framing API, and production listeners.
//! Downstream: no runtime code; these are permanent regression tests.

use super::{decode_event_stream, event_header};

// The appendix specifies three string headers and no error payload. Python struct/zlib generated
// these bytes independently of both the gateway encoder and this observer.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTSelectObjectAppendix.html
const ERROR_FRAME: &str = "0000006b0000005b77791149\
                          0d3a6d6573736167652d747970650700056572726f72\
                          0b3a6572726f722d636f646507000f43535650617273696e674572726f72\
                          0e3a6572726f722d6d6573736167650700154d616c666f726d656420435356207265636f72642e\
                          47d24567";
const END_FRAME: &str = "0000003800000028c1c684d4\
                        0d3a6d6573736167652d747970650700056576656e74\
                        0b3a6576656e742d74797065070003456e64cf97d392";
const ERROR_HEADERS: [(&str, &str); 3] = [
    (":message-type", "error"),
    (":error-code", "CSVParsingError"),
    (":error-message", "Malformed CSV record."),
];

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII literal"), 16).expect("hex literal"))
        .collect()
}

// The malformed-header controls keep valid CRCs so they reach the header/sequence checks.
fn frame(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (name, value) in headers {
        encoded.push(u8::try_from(name.len()).expect("a short name"));
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(7);
        encoded.extend_from_slice(&u16::try_from(value.len()).expect("a short value").to_be_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    let mut bytes = u32::try_from(16 + encoded.len() + payload.len())
        .expect("a small frame")
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&u32::try_from(encoded.len()).expect("a small header block").to_be_bytes());
    bytes.extend_from_slice(&crate::crc32::checksum(&bytes).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&crate::crc32::checksum(&bytes).to_be_bytes());
    bytes
}

#[test]
fn the_independent_select_error_golden_is_observed() {
    let events = decode_event_stream(&hex(ERROR_FRAME)).expect("the documented error frame is terminal");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "CSVParsingError");
    assert_eq!(event_header(&events[0].headers, ":error-message"), Some("Malformed CSV record."));
    assert!(events[0].payload.is_empty());
}

// Each negative names the one check that refused it. `is_err()` alone could not tell the checks
// apart: the sequence match also refuses a frame after a terminator, so deleting the dedicated
// terminator check — or any single check here — would leave an `is_err()` test green.
fn refusal(bytes: &[u8]) -> String {
    decode_event_stream(bytes).expect_err("the observer refuses this stream")
}

#[test]
fn n_the_exception_dialect_is_not_a_select_error_frame() {
    let bytes = frame(
        &[
            (":message-type", "exception"),
            (":exception-type", "CSVParsingError"),
            (":content-type", "text/xml"),
        ],
        b"<Error/>",
    );
    assert_eq!(refusal(&bytes), "an event-stream frame has an unknown :message-type");
}

#[test]
fn n_a_select_error_without_its_code_is_refused() {
    let bytes = frame(&[ERROR_HEADERS[0], ERROR_HEADERS[2]], &[]);
    assert_eq!(refusal(&bytes), "an error frame has no :error-code");
}

#[test]
fn n_a_select_error_without_its_message_is_refused() {
    let bytes = frame(&ERROR_HEADERS[..2], &[]);
    assert_eq!(refusal(&bytes), "an error frame has no :error-message");
}

#[test]
fn n_a_select_error_with_a_payload_is_refused() {
    assert_eq!(refusal(&frame(&ERROR_HEADERS, b"<Error/>")), "an error frame has a payload");
}

#[test]
fn n_end_cannot_follow_a_select_error() {
    let bytes = [hex(ERROR_FRAME), hex(END_FRAME)].concat();
    assert_eq!(refusal(&bytes), "an event-stream frame followed the terminator");
}

/// Negative — a header-only frame after the terminal error is still a frame after the terminator,
/// and so is a second error.
#[test]
fn n_no_frame_follows_a_select_error() {
    let continuation = frame(&[(":message-type", "event"), (":event-type", "Cont")], &[]);
    for trailer in [continuation, hex(ERROR_FRAME)] {
        let bytes = [hex(ERROR_FRAME), trailer].concat();
        assert_eq!(refusal(&bytes), "an event-stream frame followed the terminator");
    }
}

/// Negative — bytes too short to be a prelude after the terminal error are not ignored.
#[test]
fn n_stray_bytes_after_a_select_error_are_refused() {
    let bytes = [hex(ERROR_FRAME), vec![0, 0, 0]].concat();
    assert_eq!(refusal(&bytes), "an event-stream frame followed the terminator");
}

#[test]
fn n_a_select_error_with_a_bad_prelude_crc_is_refused() {
    let mut bytes = hex(ERROR_FRAME);
    bytes[8] ^= 1;
    let message_crc_offset = bytes.len() - 4;
    let message_crc = crate::crc32::checksum(&bytes[..message_crc_offset]);
    bytes[message_crc_offset..].copy_from_slice(&message_crc.to_be_bytes());
    assert_eq!(refusal(&bytes), "the event-stream prelude CRC does not match");
}

#[test]
fn n_a_select_error_with_a_bad_message_crc_is_refused() {
    let mut bytes = hex(ERROR_FRAME);
    *bytes.last_mut().expect("a trailing CRC") ^= 1;
    assert_eq!(refusal(&bytes), "the event-stream message CRC does not match");
}

/// Negative — error text that spells out a frame stays inside its length-prefixed header value.
///
/// A backend may put record bytes into the message. The smuggled text below is an `End` frame's
/// prelude lengths and header block; the observer must still see one terminal error carrying that
/// text verbatim, never a second frame after it.
#[test]
fn n_an_error_message_that_spells_a_frame_is_not_a_second_frame() {
    let smuggled = "\u{0}\u{0}\u{0}8\u{0}\u{0}\u{0}(\r:message-type\u{7}\u{0}\u{5}event\u{b}:event-type\u{7}\u{0}\u{3}End";
    let mut bytes = Vec::new();
    rustfs_gateway::encode_exception("CSVParsingError", smuggled, &mut bytes).expect("a short message");
    let events = decode_event_stream(&bytes).expect("one well-formed error frame");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "CSVParsingError");
    assert_eq!(event_header(&events[0].headers, ":error-message"), Some(smuggled));
}

#[cfg(feature = "production-transports")]
mod transport {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use rustfs_gateway::{
        ByteStream, Credentials, EventSequence, FixedClock, Handler, HandlerResult, Limits, RegionSet, Req, Resp, ServiceBuilder,
        SigV4Authenticator, StaticCredentials, TrailingHeaders, allow_when, dto, stats_document,
    };
    use rustfs_gateway_stream::{PayloadCaps, PayloadRead, PayloadStream, StreamError};

    use super::*;
    use crate::corpus::Corpus;
    use crate::inprocess::{InProcess, VALID_ACCESS_KEY, VALID_SECRET, sign_request};
    use crate::production::{ProductionDriver, ProductionServer};
    use crate::socket::{Connection, RawResponse};
    use crate::{time, toml};

    struct SelectBackend {
        fail: bool,
    }

    impl SelectBackend {
        fn response(&self) -> HandlerResult<dto::SelectObjectContent> {
            let mut source = vec![Ok(Bytes::from_static(b"a,b\n"))];
            if self.fail {
                source.push(Err("Malformed CSV record."));
            }
            let stream = SelectStream {
                source: source.into_iter(),
                sequence: EventSequence::new(),
                drained: false,
            };
            Ok(Resp::event_stream(
                ByteStream::new(Box::pin(stream)).expect("an unknown-length push stream"),
            ))
        }
    }

    impl Handler<dto::SelectObjectContent> for SelectBackend {
        async fn call(&self, _request: Req<dto::SelectObjectContent>) -> HandlerResult<dto::SelectObjectContent> {
            self.response()
        }

        async fn call_with_context(
            &self,
            _request: Req<dto::SelectObjectContent>,
            _context: rustfs_gateway::HandlerContext,
        ) -> HandlerResult<dto::SelectObjectContent> {
            self.response()
        }
    }

    struct SelectStream {
        source: std::vec::IntoIter<Result<Bytes, &'static str>>,
        sequence: EventSequence,
        drained: bool,
    }

    impl PayloadStream for SelectStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
            let this = self.get_mut();
            if this.drained {
                return Poll::Ready(Err(StreamError::polled_after_eof()));
            }
            if this.sequence.is_terminated() {
                this.drained = true;
                return Poll::Ready(Ok(PayloadRead::Eof {
                    trailers: TrailingHeaders::empty(),
                }));
            }
            let mut bytes = Vec::new();
            match this.source.next() {
                Some(Ok(record)) => this.sequence.records(&record, &mut bytes).expect("a small record"),
                Some(Err(message)) => this
                    .sequence
                    .exception("CSVParsingError", message, &mut bytes)
                    .expect("a small failure"),
                None => {
                    this.sequence
                        .stats(&stats_document(4, 4, 4), &mut bytes)
                        .expect("the source completed");
                    this.sequence.end(&mut bytes).expect("the success terminator");
                }
            }
            Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from(bytes))))
        }

        fn caps(&self) -> PayloadCaps {
            PayloadCaps::PUSH
        }

        fn len_hint(&self) -> Option<u64> {
            None
        }
    }

    fn response(driver: ProductionDriver, fail: bool) -> RawResponse {
        let now = time::parse_rfc3339(time::DEFAULT_FIXED).expect("the corpus clock");
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("fixture key")));
        let service = ServiceBuilder::new()
            .register::<dto::SelectObjectContent, _>(Arc::new(SelectBackend { fail }))
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("one region")))
            .authorizer(allow_when(|request| !request.is_anonymous()))
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(now.unix_seconds),
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .build()
            .expect("a signed Select service");
        let server = ProductionServer::start(service, driver).expect("a production loopback listener");
        let description = toml::parse(
            r#"
method = "POST"
target = "/conf-select/rows.csv?select&select-type=2"
host = "example.test"
headers = { "content-type" = "application/xml" }
body = { utf8 = '<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>' }
sign = { mode = "sigv4_header", service = "s3", region = "us-east-1", credential = "valid" }
"#,
        ).expect("the signed request description");
        let target = InProcess::new(Corpus::discover_root().expect("the corpus root"));
        let wire = target.read_wire(&description).expect("a wire request");
        let mut headers = wire.headers.clone();
        headers.push(("content-length".to_owned(), wire.body.len().to_string()));
        let (headers, target) = sign_request(
            wire.sign.as_ref().expect("signature description"),
            &wire,
            &headers,
            &now,
            &Limits::default(),
            wire.body.len() as u64,
        )
        .expect("the request signs");
        let mut request = format!("{} {target} HTTP/1.1\r\n", wire.method);
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&wire.body);
        let mut connection = Connection::open(server.addr().expect("the bound address")).expect("the client connects");
        connection.write(&bytes).expect("the request reaches the socket");
        let response = connection
            .read_response_classified("POST", Duration::from_secs(5))
            .expect("a complete wire response");
        assert_eq!(response.status, 200, "{driver:?}");
        assert!(super::super::has_event_stream_content_type(&response.headers), "{driver:?}");
        response
    }

    #[test]
    fn n_a_record_source_failure_is_an_in_band_error_over_both_drivers() {
        for driver in [ProductionDriver::Hyper, ProductionDriver::SelfHeld] {
            let response = response(driver, true);
            let events = decode_event_stream(&response.body).expect("the failed source ends with a valid error frame");
            let types: Vec<_> = events.iter().map(|event| event.event_type.as_str()).collect();
            assert_eq!(types, ["Records", "CSVParsingError"], "{driver:?}");
            assert_eq!(events[0].payload, b"a,b\n");
            assert!(events[1].payload.is_empty());
            assert!(
                response.body.ends_with(&hex(ERROR_FRAME)),
                "{driver:?}: the exact AWS error frame arrived"
            );
        }
    }

    #[test]
    fn a_completed_record_source_still_ends_successfully_over_both_drivers() {
        for driver in [ProductionDriver::Hyper, ProductionDriver::SelfHeld] {
            let response = response(driver, false);
            let events = decode_event_stream(&response.body).expect("a successful stream is independently readable");
            let types: Vec<_> = events.iter().map(|event| event.event_type.as_str()).collect();
            assert_eq!(types, ["Records", "Stats", "End"], "{driver:?}");
            assert_eq!(events[0].payload, b"a,b\n");
        }
    }
}
