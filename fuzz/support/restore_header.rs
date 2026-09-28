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

//! Restore header fuzz property shared by libFuzzer and stable replay.
//! Responsible for: an independent field/token oracle and byte-preserving round trips.
//! NOT responsible for: HTTP delivery or archive scheduling. Upstream: arbitrary bytes and seeds;
//! downstream: the production restore parser and formatter, never generated codecs.
//!
//! Evidence: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
//! A running restore has a quoted boolean; a completed copy adds a quoted expiry date.
//! The repository also accepts false without expiry and does not check weekday/date agreement.
//! Those existing choices are preserved here, not expanded into claims about AWS captures.
//! Inputs over 1 KiB are bounded to a definitely oversized prefix before conversion to UTF-8.

use rustfs_gateway_core::ops::shared::restore::{
    RestoreStatus, format_optional_restore_status, format_restore_status, parse_restore_status,
};

/// Checks one arbitrary raw header; returns the actual parsed state for replay coverage.
pub(super) fn check(input: &[u8]) -> Option<RestoreStatus> {
    let input = &input[..input.len().min(1024)];
    let text = std::str::from_utf8(input).ok()?;
    let expected = reference(text);
    let actual = parse_restore_status(text);
    assert_eq!(actual, expected, "restore parser disagrees with the independent grammar");
    if let Some(status) = &actual {
        assert_eq!(format_restore_status(status), text, "canonical bytes changed");
        assert_eq!(format_optional_restore_status(Some(status)).as_deref(), Some(text));
    }
    assert_eq!(format_optional_restore_status(None), None);
    actual
}

fn reference(text: &str) -> Option<RestoreStatus> {
    // Tokenize the whole value, so duplicates, extra fields and trailing bytes cannot disappear.
    let pieces: Vec<_> = text.split('"').collect();
    match pieces.as_slice() {
        ["ongoing-request=", "true", ""] => Some(RestoreStatus::ongoing()),
        ["ongoing-request=", "false", ""] => Some(RestoreStatus {
            ongoing: false,
            expiry_date: None,
        }),
        ["ongoing-request=", "false", ", expiry-date=", date, ""] if valid_date(date) => Some(RestoreStatus::restored(*date)),
        _ => None,
    }
}

fn valid_date(date: &str) -> bool {
    // Separate tokens plus independent reconstruction verify exact widths and punctuation.
    let fields: Vec<_> = date.split(' ').collect();
    let [weekday, day, month, year, clock, "GMT"] = fields.as_slice() else { return false };
    if !["Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,", "Sun,"].contains(weekday) {
        return false;
    }
    let Some(month) = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|value| value == month) else {
        return false;
    };
    let clock: Vec<_> = clock.split(':').collect();
    let [hour, minute, second] = clock.as_slice() else { return false };
    let Some(numbers) = [*day, *year, *hour, *minute, *second]
        .into_iter()
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let [day, year, hour, minute, second] = numbers[..] else { return false };
    let leap = year % 400 == 0 || year % 4 == 0 && year % 100 != 0;
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month];
    if year > 9999 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    format!("{weekday} {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} GMT", fields[2]) == date
}
