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
//! Responsible for: translating a case's `[clock]` onto wall time or a caller-declared endpoint
//! clock, and remapping structured `sigv2_header` `Date` / `x-amz-date` headers that explicitly
//! spell the authored `clock.request_time` so external wall-clock runs do not send stale dates.
//! Without an endpoint clock, a case that pins nothing is signed now; a `request_time` offset from
//! its `fixed` instant is signed at the same offset from now, so a skew case still measures the skew;
//! a case that pins `fixed` alone, or a server-side `skew_ms`, asks for an instant the wire cannot
//! give the target and is refused with that reason — before this module the external path signed
//! every case at the pinned instant and every signed request failed `RequestTimeTooSkewed`, which
//! reads exactly like a failed assertion (rustfs/backlog#2757).
//! An explicit endpoint clock permits matching `clock.fixed` declarations. It configures signing;
//! it neither changes a remote clock nor claims to have observed it.
//! NOT responsible for: the in-process clock (`crate::inprocess::clock_of`, reused for declarations)
//! or fixture signing. Fixture controls use the endpoint instant without authored request offsets.
//! Upstream: `crate::inprocess`. Downstream: `super::external`.

use super::external_fixture::clock::instant_at;
use crate::inprocess::{Wire, clock_of};
use crate::sut::SutError;
use crate::time::Instant;
use crate::value::Value;

impl super::Conn {
    /// Time for fixture controls; authored request offsets never affect setup or cleanup.
    pub(super) fn external_now(&self) -> Result<Instant, SutError> {
        match &self.endpoint_fixed_time {
            Some(fixed) => Ok(fixed.clone()),
            None => super::external_fixture::clock::current_request_time(),
        }
    }
}

/// The instants an external exchange needs: its time base, the one to sign at, and the authored
/// `clock.request_time` when the case explicitly declared one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExternalClock {
    /// Wall time or the caller-declared endpoint instant; not a remote clock observation.
    pub(super) now: Instant,
    /// The instant the request is signed at.
    pub(super) request_time: Instant,
    /// The authored `clock.request_time` when explicitly declared, used to detect matching dates.
    pub(super) authored_request_time: Option<Instant>,
}

/// Maps the case's `[clock]` onto the configured endpoint instant, or otherwise wall time.
///
/// # Errors
///
/// Returns [`SutError::Environment`] with the reason when the case asks for an instant the target
/// cannot be driven to: a fixed-time mismatch, an unconfigured `clock.fixed` without a request
/// offset, a non-zero `skew_ms`, or the declarations `clock_of` refuses for every target.
pub(super) fn external_clock(
    clock: Option<&Value>,
    now: Instant,
    configured: Option<&Instant>,
) -> Result<ExternalClock, SutError> {
    let (fixed, authored_request_time, skew_ms) = clock_of(clock)?;
    let pins_fixed = clock.is_some_and(|clock| clock.read("clock.fixed").is_some());
    let shifts_request = clock.is_some_and(|clock| clock.read("clock.request_time").is_some());
    if skew_ms != 0 {
        return Err(SutError::Environment(
            "`clock.skew_ms` moves the clock the target observes; an external target runs on its own \
             wall clock and cannot be driven to it, so this case is measured in process only"
                .to_owned(),
        ));
    }
    if let Some(configured) = configured {
        if let Some(text) = clock.and_then(|clock| clock.read("clock.fixed")).and_then(Value::as_str) {
            let authored = crate::time::parse_fixed_time(text).map_err(SutError::Environment)?;
            if authored != *configured {
                return Err(SutError::Environment(
                    "`clock.fixed` must equal the configured `--endpoint-fixed-time` before fixture contact".to_owned(),
                ));
            }
        }
    } else if pins_fixed && !shifts_request {
        return Err(SutError::Environment(
            "`clock.fixed` pins the instant the target observes; an external target runs on its own \
             wall clock and cannot be driven to it, so this case is measured in process only"
                .to_owned(),
        ));
    }
    let now = configured.cloned().unwrap_or(now);
    // Preserve the authored offset from the declared endpoint time, or from wall time when the
    // endpoint has no explicit clock configuration. This does not observe a remote clock.
    let offset = authored_request_time.unix_seconds.saturating_sub(fixed.unix_seconds);
    let signed_at = now
        .unix_seconds
        .checked_add(offset)
        .ok_or_else(|| SutError::Environment("the case's request-time offset does not fit a signing instant".to_owned()))?;
    let request_time = if configured.is_some() {
        Instant {
            unix_seconds: signed_at,
            amz_stamp: rustfs_gateway::Timestamp::from_secs(signed_at)
                .render(rustfs_gateway::TimestampFormat::Iso8601Basic)
                .map_err(|_| SutError::Environment("fixed-time request offset exceeds the signing date range".to_owned()))?,
        }
    } else {
        instant_at(signed_at)?
    };
    Ok(ExternalClock {
        now,
        request_time,
        authored_request_time: shifts_request.then_some(authored_request_time),
    })
}

/// Rewrites authored `Date` / `x-amz-date` headers on structured `sigv2_header` requests when
/// external execution remapped `clock.request_time` away from its authored instant.
///
/// Only header values that exactly match the authored `clock.request_time` (as HTTP-date, or as
/// basic ISO-8601 on `x-amz-date`) are updated in the same format. Intentionally skewed, malformed,
/// raw-head, unclocked, and non-`sigv2_header` requests are left untouched.
///
/// # Errors
///
/// Returns [`SutError::Environment`] if an instant cannot be formatted as an HTTP-date.
pub(super) fn remap_sigv2_authored_dates(wire: &mut Wire, clock: &ExternalClock) -> Result<(), SutError> {
    let Some(authored) = clock.authored_request_time.as_ref() else {
        return Ok(());
    };
    if authored.unix_seconds == clock.request_time.unix_seconds || wire.raw_head.is_some() {
        return Ok(());
    }
    let is_sigv2_header = wire
        .sign
        .as_ref()
        .and_then(|sign| sign.read("signSpec.mode"))
        .and_then(Value::as_str)
        == Some("sigv2_header");
    if !is_sigv2_header {
        return Ok(());
    }
    if !wire
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("date") || name.eq_ignore_ascii_case("x-amz-date"))
    {
        return Ok(());
    }
    let authored_http = rustfs_gateway::Timestamp::from_secs(authored.unix_seconds)
        .render(rustfs_gateway::TimestampFormat::HttpDate)
        .map_err(|_| SutError::Environment("authored SigV2 request time exceeds the HTTP date range".to_owned()))?;
    let remapped_http = rustfs_gateway::Timestamp::from_secs(clock.request_time.unix_seconds)
        .render(rustfs_gateway::TimestampFormat::HttpDate)
        .map_err(|_| SutError::Environment("remapped SigV2 request time exceeds the HTTP date range".to_owned()))?;
    for (name, value) in &mut wire.headers {
        if name.eq_ignore_ascii_case("date") {
            if *value == authored_http {
                *value = remapped_http.clone();
            }
        } else if name.eq_ignore_ascii_case("x-amz-date") {
            if *value == authored_http {
                *value = remapped_http.clone();
            } else if *value == authored.amz_stamp {
                *value = clock.request_time.amz_stamp.clone();
            }
        }
    }
    Ok(())
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

    fn sigv2_wire(mode: Option<&str>, headers: &[(&str, &str)]) -> Wire {
        Wire {
            method: "GET".to_owned(),
            target: "/".to_owned(),
            headers: headers.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: Vec::new(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: mode.map(|m| Value::Table(vec![("mode".to_owned(), Value::String(m.to_owned()))])),
        }
    }

    /// Positive — a case that pins nothing is signed at the wall clock, and its fixture state is
    /// dated there too.
    #[test]
    fn a_case_without_a_clock_is_signed_now() {
        let mapped = external_clock(None, now(), None).expect("mapped");
        assert_eq!(mapped.now, now());
        assert_eq!(mapped.request_time, now());
        assert_eq!(mapped.authored_request_time, None);
    }

    /// Negative — `fixed` alone pins the target's instant, which the wire cannot set.
    #[test]
    fn a_pinned_instant_is_refused_with_the_reason() {
        let error =
            external_clock(Some(&clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\n")), now(), None).expect_err("refused");
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
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        assert_eq!(mapped.now, now());
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds + 16 * 60);
        assert_eq!(mapped.request_time.amz_stamp, "20261007T121600Z");
        let behind = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-01T03:04:05Z\"\n");
        let mapped = external_clock(Some(&behind), now(), None).expect("mapped");
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds - 86_400);
    }

    /// Positive — `request_time` without `fixed` is an offset from the default pinned instant.
    #[test]
    fn a_request_time_without_fixed_is_an_offset_from_the_default_instant() {
        let declared = clock("[clock]\nrequest_time = \"2026-01-02T03:05:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        assert_eq!(mapped.request_time.unix_seconds, now().unix_seconds + 60);
    }

    /// Negative — a server-side skew is the target's clock moving, which the wire cannot do.
    #[test]
    fn a_server_skew_is_refused_with_the_reason() {
        let error = external_clock(Some(&clock("[clock]\nskew_ms = 1000\n")), now(), None).expect_err("refused");
        assert!(matches!(&error, SutError::Environment(reason) if reason.contains("skew_ms")), "{error}");
    }

    /// Negative — the declarations no target can honour from one pinned instant stay refused.
    #[test]
    fn the_declarations_every_target_refuses_stay_refused() {
        for text in [
            "[clock]\npresign_expires_s = 60\n",
            "[clock]\nadvance_ms_between_exchanges = 1000\n",
        ] {
            assert!(external_clock(Some(&clock(text)), now(), None).is_err(), "{text}");
        }
    }

    /// Positive — matching authored SigV2 `Date` and `x-amz-date` headers remap onto the external
    /// request time in the same format (including non-zero offsets and paired headers).
    #[test]
    fn remaps_sigv2_authored_date_and_amz_date_matching_request_time() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");

        let mut single = sigv2_wire(Some("sigv2_header"), &[("Date", "Fri, 02 Jan 2026 03:04:05 GMT")]);
        remap_sigv2_authored_dates(&mut single, &mapped).expect("remaps matching Date");
        assert_eq!(single.headers, vec![("Date".to_owned(), "Wed, 07 Oct 2026 12:00:00 GMT".to_owned())]);

        let mut paired = sigv2_wire(
            Some("sigv2_header"),
            &[
                ("date", "Fri, 02 Jan 2026 03:04:05 GMT"),
                ("X-Amz-Date", "Fri, 02 Jan 2026 03:04:05 GMT"),
            ],
        );
        remap_sigv2_authored_dates(&mut paired, &mapped).expect("remaps paired Date and x-amz-date");
        assert_eq!(
            paired.headers,
            vec![
                ("date".to_owned(), "Wed, 07 Oct 2026 12:00:00 GMT".to_owned()),
                ("X-Amz-Date".to_owned(), "Wed, 07 Oct 2026 12:00:00 GMT".to_owned()),
            ]
        );

        let mut iso = sigv2_wire(Some("sigv2_header"), &[("x-amz-date", "20260102T030405Z")]);
        remap_sigv2_authored_dates(&mut iso, &mapped).expect("remaps matching ISO x-amz-date");
        assert_eq!(iso.headers, vec![("x-amz-date".to_owned(), "20261007T120000Z".to_owned())]);

        let offset = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:20:05Z\"\n");
        let mapped_offset = external_clock(Some(&offset), now(), None).expect("mapped offset");
        let mut shifted = sigv2_wire(Some("sigv2_header"), &[("date", "Fri, 02 Jan 2026 03:20:05 GMT")]);
        remap_sigv2_authored_dates(&mut shifted, &mapped_offset).expect("remaps shifted Date");
        assert_eq!(shifted.headers, vec![("date".to_owned(), "Wed, 07 Oct 2026 12:16:00 GMT".to_owned())]);
    }

    /// Positive — when the endpoint clock equals the authored instant, matching headers stay exact.
    #[test]
    fn preserves_authored_sigv2_date_when_endpoint_clock_matches_authored_time() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let configured = crate::time::parse_rfc3339("2026-01-02T03:04:05Z").expect("configured instant");
        let mapped = external_clock(Some(&declared), now(), Some(&configured)).expect("mapped");
        let mut wire = sigv2_wire(Some("sigv2_header"), &[("date", "Fri, 02 Jan 2026 03:04:05 GMT")]);
        remap_sigv2_authored_dates(&mut wire, &mapped).expect("no-op remap");
        assert_eq!(wire.headers, vec![("date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned())]);
    }

    /// Negative — intentionally skewed authored timestamps are never silently rewritten.
    #[test]
    fn does_not_rewrite_intentionally_skewed_authored_sigv2_dates() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        let original = vec![
            ("date".to_owned(), "Thu, 01 Jan 2026 03:04:05 GMT".to_owned()),
            ("x-amz-date".to_owned(), "20260101T030405Z".to_owned()),
        ];
        let mut wire = sigv2_wire(
            Some("sigv2_header"),
            &[("date", "Thu, 01 Jan 2026 03:04:05 GMT"), ("x-amz-date", "20260101T030405Z")],
        );
        remap_sigv2_authored_dates(&mut wire, &mapped).expect("leaves skewed dates untouched");
        assert_eq!(wire.headers, original);
    }

    /// Negative — malformed or empty authored date values stay intact so negative cases still test them.
    #[test]
    fn does_not_rewrite_malformed_or_empty_authored_sigv2_dates() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        for (name, value) in [
            ("date", ""),
            ("date", "not-a-date"),
            ("date", "Fri, 99 Jan 2026 03:04:05 GMT"),
            ("x-amz-date", "bad-stamp"),
        ] {
            let mut wire = sigv2_wire(Some("sigv2_header"), &[(name, value)]);
            remap_sigv2_authored_dates(&mut wire, &mapped).expect("leaves malformed date untouched");
            assert_eq!(wire.headers, vec![(name.to_owned(), value.to_owned())]);
        }
    }

    /// Negative — a basic ISO-8601 stamp placed in `Date` (invalid HTTP-date) is not repaired.
    #[test]
    fn does_not_rewrite_iso8601_stamp_on_plain_date_header() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        let mut wire = sigv2_wire(Some("sigv2_header"), &[("date", "20260102T030405Z")]);
        remap_sigv2_authored_dates(&mut wire, &mapped).expect("leaves invalid Date format untouched");
        assert_eq!(wire.headers, vec![("date".to_owned(), "20260102T030405Z".to_owned())]);
    }

    /// Negative — unsigned, SigV4, presigned, and raw-head requests are never rewritten.
    #[test]
    fn does_not_rewrite_dates_for_non_sigv2_header_or_raw_head_requests() {
        let declared = clock("[clock]\nfixed = \"2026-01-02T03:04:05Z\"\nrequest_time = \"2026-01-02T03:04:05Z\"\n");
        let mapped = external_clock(Some(&declared), now(), None).expect("mapped");
        for mode in [None, Some("sigv4_header"), Some("presigned_v2"), Some("anonymous")] {
            let mut wire = sigv2_wire(mode, &[("date", "Fri, 02 Jan 2026 03:04:05 GMT")]);
            remap_sigv2_authored_dates(&mut wire, &mapped).expect("leaves non-sigv2_header untouched");
            assert_eq!(wire.headers, vec![("date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned())]);
        }
        let mut raw = sigv2_wire(Some("sigv2_header"), &[("date", "Fri, 02 Jan 2026 03:04:05 GMT")]);
        raw.raw_head = Some(b"GET / HTTP/1.1\r\nHost: s3.example.com\r\nDate: Fri, 02 Jan 2026 03:04:05 GMT\r\n\r\n".to_vec());
        remap_sigv2_authored_dates(&mut raw, &mapped).expect("leaves raw_head untouched");
        assert_eq!(raw.headers, vec![("date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned())]);
    }

    /// Negative — a request without an explicit `clock.request_time` keeps its literal `Date`.
    #[test]
    fn does_not_rewrite_authored_sigv2_date_without_declared_request_time() {
        let mapped = external_clock(None, now(), None).expect("mapped");
        let mut wire = sigv2_wire(Some("sigv2_header"), &[("date", "Fri, 02 Jan 2026 03:04:05 GMT")]);
        remap_sigv2_authored_dates(&mut wire, &mapped).expect("leaves unclocked Date untouched");
        assert_eq!(wire.headers, vec![("date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned())]);
    }
}
