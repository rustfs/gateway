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

//! Strict parsing of the reference launcher's explicit fixed clock.
//!
//! Responsible for: rejecting repeated, invalid, fractional or non-UTC fixed-time declarations.
//! NOT responsible for: authentication or setting an independently managed endpoint's clock.
//! Upstream: `main::parse_options`. Downstream: `service` installs the declared Unix second.

use std::io;

use rustfs_gateway::{Timestamp, TimestampFormat};

pub(crate) fn parse_option(previous: Option<i64>, text: &str) -> io::Result<i64> {
    if previous.is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "--fixed-time may be given only once"));
    }
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--fixed-time requires a valid whole-second UTC instant YYYY-MM-DDTHH:MM:SSZ",
        )
    };
    if text.len() != 20 || !text.ends_with('Z') {
        return Err(bad());
    }
    Timestamp::parse(text, TimestampFormat::Iso8601)
        .map(|time| time.secs())
        .map_err(|_| bad())
}
