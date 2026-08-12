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

//! Timestamp cases: the four formats, the awkward instants, and the `Expires` rule.
//!
//! Responsible for: fixed vectors for each format, cross-format agreement, negative epochs, leap
//! seconds, out-of-range years, and the round-trip property.
//! NOT responsible for: which field uses which format — that binding lives in the IR — beyond
//! proving that using the wrong one fails loudly.
//! Upstream: [`crate::scalar::timestamp`]. Downstream: nothing.

use proptest::prelude::*;

use crate::scalar::{OpaqueString, Timestamp, TimestampFormat};

fn parse(value: &str, format: TimestampFormat) -> Timestamp {
    Timestamp::parse(value, format).unwrap_or_else(|error| panic!("{value:?} must parse: {error}"))
}

#[test]
fn epoch_zero_renders_in_every_format() {
    let epoch = Timestamp::UNIX_EPOCH;
    assert_eq!(
        epoch.render(TimestampFormat::HttpDate).expect("in range"),
        "Thu, 01 Jan 1970 00:00:00 GMT"
    );
    assert_eq!(epoch.render(TimestampFormat::Iso8601).expect("in range"), "1970-01-01T00:00:00.000Z");
    assert_eq!(epoch.render(TimestampFormat::Iso8601Basic).expect("in range"), "19700101T000000Z");
    assert_eq!(epoch.render(TimestampFormat::EpochSeconds).expect("never fails"), "0");
}

#[test]
fn c_ts_0002_the_xml_form_keeps_its_milliseconds() {
    let value = "2015-10-21T07:28:00.000Z";
    let ts = parse(value, TimestampFormat::Iso8601);
    assert_eq!(ts.render(TimestampFormat::Iso8601).expect("in range"), value);

    let with_millis = parse("2015-10-21T07:28:00.123Z", TimestampFormat::Iso8601);
    assert_eq!(with_millis.subsec_millis(), 123);
    assert_eq!(
        with_millis.render(TimestampFormat::Iso8601).expect("in range"),
        "2015-10-21T07:28:00.123Z"
    );
}

#[test]
fn c_ts_0003_the_basic_form_is_the_signature_date() {
    let ts = parse("20130524T000000Z", TimestampFormat::Iso8601Basic);
    assert_eq!(ts.secs(), 1_369_353_600);
    // The same instant, spelled the two other ways, must agree — a systematic offset in the
    // calendar arithmetic would have to be identical in all three to hide here.
    assert_eq!(ts, parse("2013-05-24T00:00:00Z", TimestampFormat::Iso8601));
    assert_eq!(ts, parse("Fri, 24 May 2013 00:00:00 GMT", TimestampFormat::HttpDate));
    assert_eq!(ts.render(TimestampFormat::Iso8601Basic).expect("in range"), "20130524T000000Z");
}

#[test]
fn the_two_obsolete_http_date_formats_are_accepted_but_never_emitted() {
    let fixdate = parse("Sun, 06 Nov 1994 08:49:37 GMT", TimestampFormat::HttpDate);
    assert_eq!(parse("Sunday, 06-Nov-94 08:49:37 GMT", TimestampFormat::HttpDate), fixdate);
    assert_eq!(parse("Sun Nov  6 08:49:37 1994", TimestampFormat::HttpDate), fixdate);
    assert_eq!(
        fixdate.render(TimestampFormat::HttpDate).expect("in range"),
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "output is always IMF-fixdate"
    );
}

#[test]
fn an_iso8601_offset_is_applied_rather_than_ignored() {
    let utc = parse("2015-10-21T07:28:00Z", TimestampFormat::Iso8601);
    assert_eq!(parse("2015-10-21T15:28:00+08:00", TimestampFormat::Iso8601), utc);
    assert_eq!(parse("2015-10-21T02:28:00-05:00", TimestampFormat::Iso8601), utc);
    assert_eq!(parse("2015-10-21T15:28:00+0800", TimestampFormat::Iso8601), utc);
}

#[test]
fn c_ts_n001_expires_is_returned_verbatim() {
    // The header is user-controlled metadata and is routinely not a date. Anything that parses and
    // re-renders it either fails or silently rewrites what the caller stored.
    for value in ["not-a-date", "", "Thu, 01 Dec 1994 16:00:00 GMT", "0"] {
        let opaque = OpaqueString::new(value.to_owned());
        assert_eq!(opaque.as_str(), value);
        assert_eq!(opaque.to_string(), value);
    }
}

#[test]
fn c_ts_n003_a_format_mismatch_is_a_parse_failure() {
    // Last-Modified spelled as ISO 8601, and the object-lock header spelled as an HTTP date: each
    // must fail against the format the field is bound to, or a wrong binding goes unnoticed.
    assert!(Timestamp::parse("2015-10-21T07:28:00Z", TimestampFormat::HttpDate).is_err());
    assert!(Timestamp::parse("Sun, 06 Nov 1994 08:49:37 GMT", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2015-10-21T07:28:00Z", TimestampFormat::Iso8601Basic).is_err());
    assert!(Timestamp::parse("20130524T000000Z", TimestampFormat::Iso8601).is_err());
}

#[test]
fn c_ts_n004_a_leap_second_is_rejected() {
    let error = Timestamp::parse("2016-12-31T23:59:60Z", TimestampFormat::Iso8601)
        .expect_err("a leap second is not representable as a Unix instant");
    assert!(error.reason().contains("time of day"));
}

#[test]
fn c_ts_n005_negative_epoch_seconds_are_supported() {
    assert_eq!(parse("-1", TimestampFormat::EpochSeconds).secs(), -1);
    assert_eq!(
        parse("-1", TimestampFormat::EpochSeconds)
            .render(TimestampFormat::Iso8601)
            .expect("in range"),
        "1969-12-31T23:59:59.000Z"
    );

    // A fraction on a negative value moves further into the past, and must survive a round trip.
    let fractional = parse("-1.5", TimestampFormat::EpochSeconds);
    assert_eq!(fractional.secs(), -2);
    assert_eq!(fractional.subsec_nanos(), 500_000_000);
    assert_eq!(fractional.render(TimestampFormat::EpochSeconds).expect("never fails"), "-1.5");

    let just_before_epoch = parse("-0.5", TimestampFormat::EpochSeconds);
    assert_eq!(just_before_epoch.secs(), -1);
    assert_eq!(just_before_epoch.render(TimestampFormat::EpochSeconds).expect("never fails"), "-0.5");
}

#[test]
fn c_ts_n006_the_object_lock_header_only_accepts_iso8601() {
    // `x-amz-object-lock-retain-until-date` is the one header bound to ISO 8601. Feeding it an
    // HTTP date must fail rather than be reinterpreted.
    assert!(Timestamp::parse("Fri, 21 Dec 2012 00:00:00 GMT", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2012-12-21T00:00:00Z", TimestampFormat::Iso8601).is_ok());
}

#[test]
fn c_objectlock_0001_the_object_lock_header_only_accepts_iso8601() {
    // c-objectlock-0001 / q-timestamp-0011: this is the one header bound to ISO 8601. Feeding it an
    // HTTP date must fail rather than be reinterpreted.
    let quirk = "q-timestamp-0011";
    ::core::assert!(
        Timestamp::parse("Fri, 21 Dec 2012 00:00:00 GMT", TimestampFormat::Iso8601).is_err(),
        "{}",
        quirk
    );
    ::core::assert!(Timestamp::parse("2012-12-21T00:00:00Z", TimestampFormat::Iso8601).is_ok(), "{}", quirk);
}

#[test]
fn c_ts_n007_out_of_range_values_are_rejected_not_wrapped() {
    assert!(Timestamp::parse("99999-01-01T00:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2015-13-01T00:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2015-02-30T00:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2015-10-21T24:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("9223372036854775807", TimestampFormat::EpochSeconds).is_ok());
    assert!(
        Timestamp::parse("99999999999999999999", TimestampFormat::EpochSeconds).is_err(),
        "an epoch value beyond i64 is a parse error, not a wrap"
    );
    // Rendering an instant that no four-digit year can express fails instead of emitting nonsense.
    assert!(Timestamp::from_secs(i64::MAX).render(TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::from_secs(i64::MIN).render(TimestampFormat::HttpDate).is_err());
}

#[test]
fn leap_days_are_handled_on_both_sides_of_the_century_rule() {
    // 2000 is a leap year, 1900 and 2100 are not.
    assert!(Timestamp::parse("2000-02-29T00:00:00Z", TimestampFormat::Iso8601).is_ok());
    assert!(Timestamp::parse("1900-02-29T00:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2100-02-29T00:00:00Z", TimestampFormat::Iso8601).is_err());
    assert!(Timestamp::parse("2016-02-29T00:00:00Z", TimestampFormat::Iso8601).is_ok());
}

#[test]
fn malformed_inputs_are_rejected() {
    for value in [
        "",
        "Z",
        "2015-10-21",
        "2015-10-21T07:28:00",
        "2015/10/21T07:28:00Z",
        "2015-10-21T07:28:00+99:00",
    ] {
        assert!(
            Timestamp::parse(value, TimestampFormat::Iso8601).is_err(),
            "{value:?} is not an ISO 8601 instant"
        );
    }
    for value in [
        "",
        "Tue 15 Nov 1994 08:12:31 GMT",
        "Xyz, 15 Nov 1994 08:12:31 GMT",
        "Tue, 15 Foo 1994 08:12:31 GMT",
        "Tue, 15 Nov 1994 08:12:31 UTC",
    ] {
        assert!(
            Timestamp::parse(value, TimestampFormat::HttpDate).is_err(),
            "{value:?} is not an HTTP date"
        );
    }
    for value in ["", "1e9", "1.", "abc", "--1"] {
        assert!(
            Timestamp::parse(value, TimestampFormat::EpochSeconds).is_err(),
            "{value:?} is not an epoch value"
        );
    }
}

proptest! {
    /// Rendering and re-parsing is the identity for every whole-second instant in range, in every
    /// format that carries one.
    #[test]
    fn whole_second_round_trip(secs in -62_135_596_800i64..253_402_300_799i64) {
        let ts = Timestamp::from_secs(secs);
        for format in [
            TimestampFormat::HttpDate,
            TimestampFormat::Iso8601,
            TimestampFormat::Iso8601Basic,
            TimestampFormat::EpochSeconds,
        ] {
            let rendered = ts.render(format).expect("the range is the representable one");
            let reparsed = Timestamp::parse(&rendered, format).expect("what we render, we parse");
            prop_assert_eq!(reparsed, ts, "format {:?} rendered {}", format, rendered);
        }
    }

    /// Millisecond precision survives the ISO 8601 form, which is the only format that carries it.
    #[test]
    fn millisecond_round_trip(secs in 0i64..4_102_444_800i64, millis in 0u32..1000) {
        let ts = Timestamp::from_secs_nanos(secs, millis * 1_000_000).expect("below one second");
        let rendered = ts.render(TimestampFormat::Iso8601).expect("in range");
        prop_assert_eq!(Timestamp::parse(&rendered, TimestampFormat::Iso8601).expect("valid"), ts);
    }
}
