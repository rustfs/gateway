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

//! Responsible for: calendar and clock controls for independently checked output values.
//! NOT responsible for: comparing the two stacks or accepting other date spellings.
//! Upstream: the normalizer's format checks. Downstream: the migration acceptance gate.

use crate::normalize::{Format, Normalizer, Side};

#[test]
fn http_date_rejects_impossible_calendar_days() {
    for value in [
        "Thu, 00 Jan 2026 00:00:00 GMT",
        "Thu, 99 Jan 2026 00:00:00 GMT",
        "Thu, 31 Apr 2026 00:00:00 GMT",
        "Thu, 29 Feb 2026 00:00:00 GMT",
        "Thu, 29 Feb 2100 00:00:00 GMT",
    ] {
        assert!(!Format::HttpDate.holds(value), "{value}");
    }
}

#[test]
fn http_date_rejects_out_of_range_clock_fields() {
    for value in [
        "Thu, 01 Jan 2026 24:00:00 GMT",
        "Thu, 01 Jan 2026 00:60:00 GMT",
        "Thu, 01 Jan 2026 00:00:61 GMT",
    ] {
        assert!(!Format::HttpDate.holds(value), "{value}");
    }
}

#[test]
fn http_date_rejects_a_weekday_that_disagrees_with_the_date() {
    assert!(!Format::HttpDate.holds("Fri, 01 Jan 2026 00:00:00 GMT"));
}

#[test]
fn http_date_rejects_years_below_the_imf_date_range() {
    assert!(!Format::HttpDate.holds("Mon, 01 Jan 0001 00:00:00 GMT"));
}

#[test]
fn xml_instant_rejects_impossible_calendar_fields() {
    for value in [
        "2026-00-01T00:00:00.000Z",
        "2026-13-01T00:00:00.000Z",
        "2026-01-00T00:00:00.000Z",
        "2026-01-99T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-02-29T00:00:00.000Z",
        "2100-02-29T00:00:00.000Z",
    ] {
        assert!(!Format::XmlInstant.holds(value), "{value}");
    }
}

#[test]
fn xml_instant_rejects_out_of_range_clock_fields() {
    for value in [
        "2026-01-01T24:00:00.000Z",
        "2026-01-01T00:60:00.000Z",
        "2026-01-01T00:00:61.000Z",
    ] {
        assert!(!Format::XmlInstant.holds(value), "{value}");
    }
}

#[test]
fn a_date_placeholder_keeps_the_failed_calendar_assertion() {
    for side in [Side::Gateway, Side::S3s] {
        let mut headers = vec![("date".to_owned(), b"Thu, 31 Feb 2026 00:00:00 GMT".to_vec())];
        let mut assertions = Vec::new();
        Normalizer.normalize_headers(side, &mut headers, &mut assertions);
        assert_eq!(headers[0].1, b"<DATE>");
        assert!(assertions.iter().any(|assertion| !assertion.holds));
    }
}

#[test]
fn http_date_accepts_calendar_and_clock_boundaries() {
    for value in [
        "Thu, 01 Jan 2026 00:00:00 GMT",
        "Tue, 29 Feb 2000 23:59:59 GMT",
        "Thu, 29 Feb 2024 00:00:00 GMT",
        "Sun, 28 Feb 2100 23:59:59 GMT",
        "Sat, 31 Dec 2016 23:59:60 GMT",
    ] {
        assert!(Format::HttpDate.holds(value), "{value}");
    }
}

#[test]
fn xml_instant_accepts_calendar_and_clock_boundaries() {
    for value in [
        "2026-01-01T00:00:00.000Z",
        "2000-02-29T23:59:59.999Z",
        "2024-02-29T00:00:00.000Z",
        "2100-02-28T23:59:59.000Z",
        "2016-12-31T23:59:60.000Z",
    ] {
        assert!(Format::XmlInstant.holds(value), "{value}");
    }
}
