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

//! Normalisation, not exemption: values the two stacks legitimately write differently are
//! replaced by a placeholder, and each replaced value's format is asserted on its own.
//!
//! Responsible for: [`Normalizer`] — the closed table of what is replaced (the request and host
//! identifiers, `Date` and `Server`, which the two stacks legitimately write differently), what is
//! only asserted and still compared as written (version ids, upload ids and instants, which come
//! from the one output both stacks were handed), and what is removed (hop-by-hop framing headers)
//! — and the [`FormatAssertion`] every such value leaves behind. An exemption
//! would hide a change of format (an upload id that turns from base64url into hex makes every
//! upload id a client stored unusable); a placeholder plus an exact format check does not.
//! NOT responsible for: comparing the normalised answers (`encode.rs`).
//! Upstream: the two stacks' raw answers. Downstream: `encode.rs`.

use std::fmt;

/// The formats a normalised value is held to. Each is the exact shape its producer writes, not a
/// loose family: an instant without its milliseconds is a different format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// 16 uppercase hexadecimal digits (`x-amz-request-id`).
    RequestId,
    /// 32 uppercase hexadecimal digits (`x-amz-id-2`, as the gateway writes it).
    HostId,
    /// An RFC 9110 IMF-fixdate: `Thu, 01 Jan 2026 00:00:00 GMT`.
    HttpDate,
    /// A bare product name: letters and digits only, so no version, build or platform.
    ServerName,
    /// A RustFS version id: a lowercase hyphenated UUID, or `null`.
    VersionId,
    /// A RustFS upload id: unpadded base64url of `<deployment id>.<UUID>`.
    UploadId,
    /// An S3 XML instant: `2026-01-01T00:00:00.000Z`, milliseconds always written.
    XmlInstant,
    /// A `Content-Length` equal to the body the side actually wrote.
    BodyLength(usize),
}

impl Format {
    /// Whether `value` has exactly this format.
    #[must_use]
    pub fn holds(self, value: &str) -> bool {
        match self {
            Self::RequestId => value.len() == 16 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F')),
            Self::HostId => value.len() == 32 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F')),
            Self::HttpDate => is_http_date(value),
            Self::ServerName => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            Self::VersionId => value == "null" || is_uuid(value),
            Self::UploadId => decode_base64url(value)
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .and_then(|text| {
                    text.rsplit_once('.')
                        .map(|(deployment, id)| !deployment.is_empty() && is_uuid(id))
                })
                .unwrap_or(false),
            Self::XmlInstant => is_xml_instant(value),
            Self::BodyLength(length) => value.parse::<usize>().is_ok_and(|declared| declared == length),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::RequestId => "16 uppercase hex digits",
            Self::HostId => "32 uppercase hex digits",
            Self::HttpDate => "an IMF-fixdate",
            Self::ServerName => "a bare product name",
            Self::VersionId => "a UUID or null",
            Self::UploadId => "base64url of <deployment>.<UUID>",
            Self::XmlInstant => "an ISO 8601 instant with milliseconds",
            Self::BodyLength(length) => return write!(formatter, "the body length, {length}"),
        };
        formatter.write_str(name)
    }
}

fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, length)| group.len() == length && group.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_http_date(value: &str) -> bool {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = value.split(' ').collect();
    let [day, date, month, year, time, zone] = parts.as_slice() else {
        return false;
    };
    let clock: Vec<&str> = time.split(':').collect();
    day.strip_suffix(',').is_some_and(|day| DAYS.contains(&day))
        && date.len() == 2
        && digits(date)
        && MONTHS.contains(month)
        && year.len() == 4
        && digits(year)
        && clock.len() == 3
        && clock.iter().all(|part| part.len() == 2 && digits(part))
        && *zone == "GMT"
}

fn is_xml_instant(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 24
        && [4, 7].iter().all(|&index| bytes[index] == b'-')
        && bytes[10] == b'T'
        && [13, 16].iter().all(|&index| bytes[index] == b':')
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23]
            .into_iter()
            .all(|range| value.get(range).is_some_and(digits))
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in value.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    (!value.is_empty()).then_some(out)
}

/// Which side a value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The gateway.
    Gateway,
    /// The pinned s3s revision.
    S3s,
}

/// One replaced value and whether it had its format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatAssertion {
    /// Which answer it was in.
    pub side: Side,
    /// `header <name>` or `xml <Element>`.
    pub field: String,
    /// The value before replacement.
    pub value: String,
    /// The format it is held to.
    pub format: Format,
    /// Whether it had it.
    pub holds: bool,
}

/// Where a normalised value lives.
/// A header the table names: its placeholder when the two stacks legitimately write it
/// differently (`None` when it comes from the output both stacks were handed, which is asserted
/// and still compared as written), and the format it is held to.
struct HeaderRule {
    name: &'static str,
    placeholder: Option<&'static str>,
    format: Format,
}

const HEADER_RULES: &[HeaderRule] = &[
    HeaderRule {
        name: "x-amz-request-id",
        placeholder: Some("<REQID>"),
        format: Format::RequestId,
    },
    HeaderRule {
        name: "x-amz-id-2",
        placeholder: Some("<HOSTID>"),
        format: Format::HostId,
    },
    HeaderRule {
        name: "date",
        placeholder: Some("<DATE>"),
        format: Format::HttpDate,
    },
    HeaderRule {
        name: "server",
        placeholder: Some("<SERVER>"),
        format: Format::ServerName,
    },
    HeaderRule {
        name: "x-amz-version-id",
        placeholder: None,
        format: Format::VersionId,
    },
    HeaderRule {
        name: "last-modified",
        placeholder: None,
        format: Format::HttpDate,
    },
];

/// XML elements whose values are held to a format. None is replaced: every one comes from the
/// output both stacks were handed, so a conversion that changed it within its format still shows.
const ELEMENT_RULES: &[(&str, Format)] = &[
    ("UploadId", Format::UploadId),
    ("VersionId", Format::VersionId),
    ("DeleteMarkerVersionId", Format::VersionId),
    ("LastModified", Format::XmlInstant),
    ("Initiated", Format::XmlInstant),
    ("CreationDate", Format::XmlInstant),
];

/// Framing and connection headers: a property of the transport, not of the answer.
const HOP_BY_HOP: [&str; 3] = ["connection", "keep-alive", "transfer-encoding"];

/// The normaliser. Stateless: the two tables above are the whole of its behaviour.
#[derive(Clone, Copy, Debug, Default)]
pub struct Normalizer;

impl Normalizer {
    /// Replaces every normalised header value and removes the hop-by-hop headers, recording one
    /// assertion per replaced value.
    pub fn normalize_headers(
        self,
        side: Side,
        headers: &mut [(String, Vec<u8>)],
        assertions: &mut Vec<FormatAssertion>,
    ) -> Vec<String> {
        let mut removed = Vec::new();
        for (name, value) in headers.iter_mut() {
            if HOP_BY_HOP.contains(&name.as_str()) {
                removed.push(name.clone());
                continue;
            }
            for rule in HEADER_RULES {
                if rule.name == name {
                    let text = String::from_utf8_lossy(value).into_owned();
                    assertions.push(FormatAssertion {
                        side,
                        field: format!("header {}", rule.name),
                        holds: rule.format.holds(&text),
                        value: text,
                        format: rule.format,
                    });
                    if let Some(placeholder) = rule.placeholder {
                        *value = placeholder.as_bytes().to_vec();
                    }
                }
            }
        }
        removed
    }

    /// Asserts the format of every XML element value the table names. No element value is
    /// replaced: each comes from the output both stacks were handed, so it is compared as written.
    pub fn assert_body(self, side: Side, body: &[u8], assertions: &mut Vec<FormatAssertion>) {
        let Ok(text) = std::str::from_utf8(body) else {
            return;
        };
        for &(element, format) in ELEMENT_RULES {
            let (open, close) = (format!("<{element}>"), format!("</{element}>"));
            let mut rest = text;
            while let Some(start) = rest.find(&open) {
                let value_start = start + open.len();
                let Some(length) = rest[value_start..].find(&close) else {
                    break;
                };
                let value = &rest[value_start..value_start + length];
                assertions.push(FormatAssertion {
                    side,
                    field: format!("xml {element}"),
                    value: value.to_owned(),
                    format,
                    holds: format.holds(value),
                });
                rest = &rest[value_start + length..];
            }
        }
    }
}
