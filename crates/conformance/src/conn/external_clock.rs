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

//! The instant an external exchange is signed at.
//!
//! Responsible for: translating a case's `[clock]` onto the wall clock an external target runs on.
//! A case that pins nothing is signed now; a case whose `request_time` is an offset from its
//! `fixed` instant is signed at the same offset from now, so a skew case still measures the skew;
//! a case that pins `fixed` alone, or a server-side `skew_ms`, asks for an instant the wire cannot
//! give the target and is refused with that reason — before this module the external path signed
//! every case at the pinned instant and every signed request failed `RequestTimeTooSkewed`, which
//! reads exactly like a failed assertion (rustfs/backlog#2757).
//! NOT responsible for: the in-process clock (`crate::inprocess::clock_of`, which this reuses for
//! the `[clock]` reading and its refusals) or fixture signing (`super::external_fixture::clock`).
//! Upstream: `crate::inprocess`. Downstream: `super::external`.

use super::external_fixture::clock::instant_at;
use crate::inprocess::clock_of;
use crate::sut::SutError;
use crate::time::Instant;
use crate::value::Value;

/// The two instants an external exchange needs: the target's own now, and the one to sign at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExternalClock {
    /// The wall clock the target observes; what the fixture state is dated at.
    pub(super) now: Instant,
    /// The instant the request is signed at.
    pub(super) request_time: Instant,
}

/// Maps the case's `[clock]` onto `now`, the wall clock at the moment of the exchange.
///
/// # Errors
///
/// Returns [`SutError::Environment`] with the reason when the case asks for an instant the target
/// cannot be driven to: `clock.fixed` without a `request_time` offset, a non-zero `skew_ms`, or
/// the declarations `clock_of` refuses for every target.
pub(super) fn external_clock(clock: Option<&Value>, now: Instant) -> Result<ExternalClock, SutError> {
    let (fixed, request_time, skew_ms) = clock_of(clock)?;
    let pins_fixed = clock.is_some_and(|clock| clock.read("clock.fixed").is_some());
    let shifts_request = clock.is_some_and(|clock| clock.read("clock.request_time").is_some());
    if skew_ms != 0 {
        return Err(SutError::Environment(
            "`clock.skew_ms` moves the clock the target observes; an external target runs on its own \
             wall clock and cannot be driven to it, so this case is measured in process only"
                .to_owned(),
        ));
    }
    if pins_fixed && !shifts_request {
        return Err(SutError::Environment(
            "`clock.fixed` pins the instant the target observes; an external target runs on its own \
             wall clock and cannot be driven to it, so this case is measured in process only"
                .to_owned(),
        ));
    }
    // `request_time` is an offset from the case's `fixed` instant, and the offset is what the
    // case measures: keep it, from the instant the target actually observes.
    let offset = request_time.unix_seconds.saturating_sub(fixed.unix_seconds);
    let signed_at = now
        .unix_seconds
        .checked_add(offset)
        .ok_or_else(|| SutError::Environment("the case's request-time offset does not fit a signing instant".to_owned()))?;
    Ok(ExternalClock {
        now,
        request_time: instant_at(signed_at)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(text: &str) -> Value {
        crate::toml::parse(text)
            .expect("parses")
            .get("clock")
            .cloned()
            .expect("a clock table")
    }

    fn now() -> Instant {
        crate::time::parse_rfc3339("2026-10-07T12:00:00Z").expect("an instant")
    }

    /// Positive — a case that pins nothing is signed at the wall clock, and its fixture state is
    /// dated there too.
    #[test]
    fn a_case_without_a_clock_is_signed_now() {
        let mapped = external_clock(None, now()).expect("mapped");
        assert_eq!(mapped.now, now());
        assert_eq!(mapped.request_time, now());
    }

    /// Negative — `fixed` alone pins the target's instant, which the wire cannot set.
    #[test]
    fn a_pinned_instant_is_refused_with_the_reason() {
        let error = external_clock(Some(&clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\n")), now()).expect_err("refused");
        assert!(
            matches!(&error, SutError::Environment(reason) if reason.contains("clock.fixed")),
            "{error}"
        );
    }

    /// Positive — a `request_time` offset from `fixed` keeps its offset from now, so the skew the
    /// case measures is the skew the target sees.
    #[test]
    fn a_request_time_offset_is_kept_relative_to_now() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:20:05Z\"\n");
        let mapped = external_clock(Some(&declared), now()).expect("mapped");
        assert_eq!(mapped.now, now());
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds + 16 * 60);
        assert_eq!(mapped.request_time.amz_stamp, "20261007T121600Z");
        let behind = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-01T03:04:05Z\"\n");
        let mapped = external_clock(Some(&behind), now()).expect("mapped");
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds - 86_400);
    }

    /// Positive — `request_time` without `fixed` is an offset from the default pinned instant.
    #[test]
    fn a_request_time_without_fixed_is_an_offset_from_the_default_instant() {
        let declared = clock("[clock]\nrequest_time = \"2026-01-02T03:05:05Z\"\n");
        let mapped = external_clock(Some(&declared), now()).expect("mapped");
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds + 60);
    }

    /// Negative — a server-side skew is the target's clock moving, which the wire cannot do.
    #[test]
    fn a_server_skew_is_refused_with_the_reason() {
        let error = external_clock(Some(&clock("[clock]\nskew_ms = 1000\n")), now()).expect_err("refused");
        assert!(matches!(&error, SutError::Environment(reason) if reason.contains("skew_ms")), "{error}");
    }

    /// Negative — the declarations no target can honour from one pinned instant stay refused.
    #[test]
    fn the_declarations_every_target_refuses_stay_refused() {
        for text in [
            "[clock]\npresign_expires_s = 60\n",
            "[clock]\nadvance_ms_between_exchanges = 1000\n",
        ] {
            assert!(external_clock(Some(&clock(text)), now()).is_err(), "{text}");
        }
    }
}
