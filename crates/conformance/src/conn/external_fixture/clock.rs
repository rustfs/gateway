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

//! Wall-clock conversion for external fixture signatures.
//!
//! Responsible for: converting the current Unix second into the UTC basic-ISO stamp SigV4 needs.
//! NOT responsible for: case clocks, signing, or fixture deadlines. Upstream: `super`; downstream:
//! `crate::inprocess::sign_request` through one control request.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::sut::SutError;

pub(super) fn current_request_time() -> Result<crate::time::Instant, SutError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SutError::Environment(format!("system clock precedes the Unix epoch: {error}")))?
        .as_secs();
    let seconds = i64::try_from(seconds)
        .map_err(|_| SutError::Environment("current Unix time does not fit the signer clock".to_owned()))?;
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = second_of_day % 3_600 / 60;
    let second = second_of_day % 60;
    Ok(crate::time::Instant {
        unix_seconds: seconds,
        amz_stamp: format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    })
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}
