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

//! Launcher-time conversion for bounded verification.
//!
//! Responsible for: converting the launcher's Unix timestamp into the `Instant` used by the
//! verification deadline. NOT responsible for: selecting commands or enforcing the deadline.
//! Upstream: `xtask-launcher`. Downstream: crate verification.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STARTED_ENV: &str = "RUSTFS_GATEWAY_XTASK_STARTED_UNIX_NANOS";

fn elapsed(raw: Option<&str>, now: SystemTime) -> Result<Option<Duration>, &'static str> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let started = raw
        .parse::<u128>()
        .map_err(|_| "launcher timestamp is not an unsigned integer")?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_nanos();
    let elapsed = now.checked_sub(started).ok_or("launcher timestamp is in the future")?;
    let elapsed = u64::try_from(elapsed).map_err(|_| "launcher timestamp is too old")?;
    Ok(Some(Duration::from_nanos(elapsed)))
}

pub(super) fn launcher_started() -> Result<Option<Instant>, String> {
    let raw = match std::env::var(STARTED_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return Err("launcher timestamp is not Unicode".to_owned()),
    };
    let elapsed = elapsed(raw.as_deref(), SystemTime::now()).map_err(str::to_owned)?;
    elapsed
        .map(|elapsed| {
            Instant::now()
                .checked_sub(elapsed)
                .ok_or_else(|| "launcher timestamp predates this boot".to_owned())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::elapsed;

    #[test]
    fn launcher_time_is_part_of_the_crate_budget() {
        let now = UNIX_EPOCH + Duration::from_secs(10);

        assert_eq!(elapsed(Some("8000000000"), now), Ok(Some(Duration::from_secs(2))));
    }

    #[test]
    fn an_absent_launcher_timestamp_keeps_direct_invocations_working() {
        assert_eq!(elapsed(None, UNIX_EPOCH), Ok(None));
    }

    #[test]
    fn malformed_or_future_launcher_timestamps_are_rejected() {
        let now = UNIX_EPOCH + Duration::from_secs(10);

        assert!(elapsed(Some("not-a-timestamp"), now).is_err());
        assert!(elapsed(Some("10000000001"), now).is_err());
    }
}
