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

//! The SigV4 timestamp the context fixtures are signed with.
//!
//! Responsible for: [`amz_date`], the `YYYYMMDDTHHMMSSZ` spelling of a Unix time.
//! NOT responsible for: which instant a fixture is signed at (the harness signs now), or judging a
//! timestamp (each stack's verifier).
//! Upstream: none. Downstream: `super`, which re-exports it, and the rd-loc pins.

/// `YYYYMMDDTHHMMSSZ` for a Unix time. Both verifiers compare the stamp against their own clock,
/// so the fixture is signed now rather than at a fixed instant.
pub(crate) fn amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let second_of_day = unix.rem_euclid(86_400);
    // Civil-from-days (proleptic Gregorian), days counted from 1970-01-01.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    )
}
