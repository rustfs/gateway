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

//! The complete pinned Smithy timestamp compatibility corpus.
//!
//! Responsible for: applying every upstream parse and format vector to the matching gateway
//! timestamp format and checking the canonical instant or exact output bytes.
//! NOT responsible for: choosing a timestamp format for a protocol field or changing the corpus.
//! Upstream: the attributed JSON under `crates/types/tests/data`. Downstream: `c-ts-0001`.

use serde_json::Value;

use crate::scalar::{Timestamp, TimestampFormat};

const CORPUS: &str = include_str!("../../../tests/data/date_time_format_test_suite.json");

fn cases<'a>(suite: &'a Value, section: &str) -> &'a [Value] {
    suite[section]
        .as_array()
        .unwrap_or_else(|| panic!("{section} must be an array"))
}

fn text<'a>(case: &'a Value, field: &str, section: &str, index: usize) -> &'a str {
    case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{section}[{index}].{field} must be a string"))
}

fn canonical_nanos(case: &Value, section: &str, index: usize) -> u32 {
    case["canonical_nanos"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| panic!("{section}[{index}].canonical_nanos must fit u32"))
}

fn gateway_parts(format: TimestampFormat, seconds: i64, nanos: u32) -> (i64, u32) {
    if format == TimestampFormat::EpochSeconds && seconds < 0 && nanos > 0 {
        (seconds - 1, 1_000_000_000 - nanos)
    } else {
        (seconds, nanos)
    }
}

fn canonical(case: &Value, format: TimestampFormat, section: &str, index: usize) -> Timestamp {
    let seconds = text(case, "canonical_seconds", section, index)
        .parse::<i64>()
        .unwrap_or_else(|error| panic!("{section}[{index}] has invalid canonical seconds: {error}"));
    let nanos = canonical_nanos(case, section, index);
    let (seconds, nanos) = gateway_parts(format, seconds, nanos);
    Timestamp::from_secs_nanos(seconds, nanos)
        .unwrap_or_else(|error| panic!("{section}[{index}] has an invalid canonical instant: {error}"))
}

fn expected_error(case: &Value, section: &str, index: usize) -> bool {
    case["error"]
        .as_bool()
        .unwrap_or_else(|| panic!("{section}[{index}].error must be a boolean"))
}

fn iso8601_millis_projection(case: &Value, section: &str, index: usize) -> String {
    let upstream = text(case, "smithy_format_value", section, index);
    let without_zone = upstream
        .strip_suffix('Z')
        .unwrap_or_else(|| panic!("{section}[{index}] must be a UTC date-time"));
    let base = without_zone.split_once('.').map_or(without_zone, |(whole, _)| whole);
    format!("{base}.{:03}Z", canonical_nanos(case, section, index) / 1_000_000)
}

fn http_date_without_fraction(case: &Value, section: &str, index: usize) -> String {
    let upstream = text(case, "smithy_format_value", section, index);
    let (date_and_time, zone) = upstream
        .rsplit_once(' ')
        .unwrap_or_else(|| panic!("{section}[{index}] must have a zone"));
    let (prefix, seconds) = date_and_time
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("{section}[{index}] must have a seconds field"));
    let seconds = seconds.split_once('.').map_or(seconds, |(whole, _)| whole);
    format!("{prefix}:{seconds} {zone}")
}

fn http_date_has_fraction(value: &str) -> bool {
    value
        .split_ascii_whitespace()
        .any(|field| field.contains(':') && field.contains('.'))
}

#[test]
fn smithy_negative_canonical_parts_follow_gateway_timestamp_invariant() {
    assert_eq!(gateway_parts(TimestampFormat::EpochSeconds, -1, 1), (-2, 999_999_999));
    assert_eq!(gateway_parts(TimestampFormat::EpochSeconds, -1, 999_999_999), (-2, 1));
    assert_eq!(gateway_parts(TimestampFormat::EpochSeconds, -1, 0), (-1, 0));
    assert_eq!(gateway_parts(TimestampFormat::EpochSeconds, 0, 1), (0, 1));
    assert_eq!(gateway_parts(TimestampFormat::Iso8601, -1, 1), (-1, 1));
}

/// c-ts-0001: all 660 pinned Smithy vectors exercise the gateway timestamp codec.
#[test]
fn c_ts_0001_complete_smithy_timestamp_corpus_matches_gateway_codec() {
    let suite: Value = serde_json::from_str(CORPUS).expect("the pinned corpus must remain valid JSON");
    let format_sections = [
        ("format_date_time", TimestampFormat::Iso8601),
        ("format_epoch_seconds", TimestampFormat::EpochSeconds),
        ("format_http_date", TimestampFormat::HttpDate),
    ];
    let parse_sections = [
        ("parse_date_time", TimestampFormat::Iso8601),
        ("parse_epoch_seconds", TimestampFormat::EpochSeconds),
        ("parse_http_date", TimestampFormat::HttpDate),
    ];
    let mut observed = 0;
    let mut exact_mappings = 0;
    let mut smithy_format_rejections = 0;
    let mut smithy_parse_rejections = 0;
    let mut iso8601_millis_projections = 0;
    let mut http_date_format_projections = 0;
    let mut http_date_fraction_rejections = 0;

    for (section, format) in format_sections {
        for (index, case) in cases(&suite, section).iter().enumerate() {
            observed += 1;
            let rendered = canonical(case, format, section, index).render(format);
            if expected_error(case, section, index) {
                smithy_format_rejections += 1;
                assert!(rendered.is_err(), "{section}[{index}] must reject formatting");
            } else {
                let rendered = rendered.unwrap_or_else(|error| panic!("{section}[{index}] must format: {error}"));
                let upstream = text(case, "smithy_format_value", section, index);
                if rendered == upstream {
                    exact_mappings += 1;
                } else {
                    let projected = match section {
                        "format_date_time" => {
                            iso8601_millis_projections += 1;
                            iso8601_millis_projection(case, section, index)
                        }
                        "format_http_date" => {
                            http_date_format_projections += 1;
                            http_date_without_fraction(case, section, index)
                        }
                        _ => upstream.to_owned(),
                    };
                    assert_eq!(rendered, projected, "{section}[{index}]");
                }
            }
        }
    }

    for (section, format) in parse_sections {
        for (index, case) in cases(&suite, section).iter().enumerate() {
            observed += 1;
            let value = text(case, "smithy_format_value", section, index);
            let parsed = Timestamp::parse(value, format);
            if section == "parse_http_date" && http_date_has_fraction(value) {
                http_date_fraction_rejections += 1;
                assert!(parsed.is_err(), "{section}[{index}] must reject fractional HTTP-date seconds");
                continue;
            }
            if expected_error(case, section, index) {
                smithy_parse_rejections += 1;
                assert!(parsed.is_err(), "{section}[{index}] must reject parsing");
            } else {
                exact_mappings += 1;
                assert_eq!(
                    parsed.unwrap_or_else(|error| panic!("{section}[{index}] must parse: {error}")),
                    canonical(case, format, section, index),
                    "{section}[{index}]"
                );
            }
        }
    }

    assert_eq!(observed, 660, "every pinned vector must be observed");
    assert_eq!(exact_mappings, 442, "every byte-exact or canonical-instant mapping must be observed");
    assert_eq!(smithy_format_rejections, 72, "every Smithy-declared format rejection must be observed");
    assert_eq!(smithy_parse_rejections, 0, "the pinned Smithy corpus declares no parse rejection");
    assert_eq!(
        iso8601_millis_projections, 77,
        "every non-exact Smithy date-time format vector must be projected"
    );
    assert_eq!(
        http_date_format_projections, 0,
        "every Smithy HTTP-date format vector must already match exactly"
    );
    assert_eq!(
        http_date_fraction_rejections, 69,
        "every Smithy fractional HTTP-date parse vector must exercise the frozen rejection"
    );

    // Smithy has no basic-format section. The fourth frozen gateway format stays covered by its
    // existing dedicated case, and this control keeps that mapping explicit beside the corpus.
    let basic = Timestamp::parse("20130524T000000Z", TimestampFormat::Iso8601Basic)
        .expect("the frozen basic timestamp format remains supported");
    assert_eq!(basic.secs(), 1_369_353_600);
}
