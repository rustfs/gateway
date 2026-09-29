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

//! The `post_form` property: a POST Object form read by the form reader under either grammar, and
//! the fields it yields handed to both POST policy parsers.
//!
//! Responsible for: decoding an input into a grammar, a `Content-Type`, form ceilings, a framing
//! and a body; reading the body whole, in the selected framing and one byte at a time and
//! requiring the three reads to agree; holding every read that is accepted to its ceilings and
//! field rules; and handing the fields of an accepted read to `PostPolicy::parse` and
//! `SigV2PostPolicy::parse`, holding a policy either accepts to its own invariants. Any violation
//! panics, which is how libFuzzer and the stable replay both report it.
//! NOT responsible for: whether the legacy grammar reads a form as legacy RustFS does — that needs
//! the legacy stack, and `rustfs-gateway-http`'s `form_grammar.rs` pins each shape — nor the
//! signature check a policy is later held to, which needs a key this property does not have.
//! Upstream: the `post_form` fuzz target and `crates/sig/tests/post_form_replay.rs`. Downstream:
//! `rustfs-gateway-http`'s form reader and `rustfs-gateway-sig`'s POST policy parsers.
//!
//! # Input format
//!
//! Byte 0 selects: bits 0-1 the grammar (0 and 3 the gateway grammar, 1 the legacy RustFS grammar
//! with a declared length, 2 the legacy grammar without one), bits 2-4 one of [`CONTENT_TYPES`],
//! bit 5 the tight ceilings of [`tight_limits`] instead of the defaults. Byte 1 is the frame size
//! (0 reads as 1). The rest is the body.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the tables.

use rustfs_gateway_http::{FileReader, FormGrammar, FormLimits, FormReader, FormReject, FormStep};
use rustfs_gateway_sig::{PostPolicy, PostPolicyLimits, RequestNow, SigV2PostPolicy};

/// How many selector bytes precede the body.
pub(crate) const HEADER_BYTES: usize = 2;

/// The boundary every content type names; seeds frame their bodies with it.
pub(crate) const BOUNDARY: &str = "fuzzboundary";

/// The content types byte 0 selects from: the common spelling, a quoted boundary, extra
/// parameters, a quoted parameter holding `;`, whitespace the legacy header reader refuses, a
/// repeated boundary, a boundary outside RFC 2046's characters, and no boundary at all.
pub(crate) const CONTENT_TYPES: [&str; 8] = [
    "multipart/form-data; boundary=fuzzboundary",
    "multipart/form-data; boundary=\"fuzzboundary\"",
    "Multipart/Form-Data;charset=utf-8;boundary=fuzzboundary",
    "multipart/form-data; note=\"a;boundary=wrong\"; boundary=fuzzboundary",
    "multipart/form-data ; boundary=fuzzboundary",
    "multipart/form-data; boundary=fuzzboundary; boundary=other",
    "multipart/form-data; boundary=\"fuzz@boundary\"",
    "multipart/form-data",
];

/// The ceiling the file part is read under.
pub(crate) const FILE_CEILING: u64 = 1024;

/// A moment before the expiration of the policy the seeds carry.
pub(crate) const NOW: i64 = 1_440_938_160;

/// Ceilings small enough that a fuzzer reaches every one of them.
pub(crate) fn tight_limits() -> FormLimits {
    FormLimits::default()
        .with_max_field_bytes(64)
        .with_max_policy_bytes(1024)
        .with_max_field_count(4)
        .with_max_part_header_bytes(256)
        .with_max_whole_stream_bytes(4096)
}

/// What one input selected.
#[derive(Clone, Debug)]
pub(crate) struct Case<'a> {
    pub(crate) grammar: FormGrammar,
    pub(crate) content_type: &'static str,
    pub(crate) limits: FormLimits,
    pub(crate) frame: usize,
    pub(crate) body: &'a [u8],
}

impl<'a> Case<'a> {
    /// Decodes an input, or `None` when it is too short to select anything.
    pub(crate) fn parse(input: &'a [u8]) -> Option<Self> {
        let ([selector, frame], body) = input.split_first_chunk::<HEADER_BYTES>().map(|(head, body)| (*head, body))?;
        let grammar = match selector & 0b11 {
            1 => FormGrammar::LegacyRustfs { declared_length: true },
            2 => FormGrammar::LegacyRustfs { declared_length: false },
            _ => FormGrammar::Gateway,
        };
        let content_type = CONTENT_TYPES[usize::from((selector >> 2) & 0b111)];
        let limits = if selector & 0b10_0000 == 0 {
            FormLimits::default()
        } else {
            tight_limits()
        };
        Some(Self {
            grammar,
            content_type,
            limits,
            frame: usize::from(frame.max(1)),
            body,
        })
    }
}

/// What one read of a form produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The form was refused.
    Refused(FormReject),
    /// The whole form was read.
    Read {
        fields: Vec<(String, String)>,
        filename: Option<String>,
        file_name: Option<String>,
        file: Vec<u8>,
    },
}

/// What the property observed.
#[derive(Clone, Debug)]
pub(crate) struct Outcome {
    pub(crate) verdict: Verdict,
    /// Whether the SigV4 policy parser accepted the fields, when the form was read.
    pub(crate) sig_v4: Option<bool>,
    /// Whether the SigV2 policy parser accepted the fields, when the form was read.
    pub(crate) sig_v2: Option<bool>,
}

/// Reads `case.body` in `frame`-byte frames.
pub(crate) fn read(case: &Case<'_>, frame: usize) -> Verdict {
    match read_inner(case, frame) {
        Ok(verdict) => verdict,
        Err(reject) => Verdict::Refused(reject),
    }
}

/// Where one read has got to: still in the text fields, or in the file with the fields in hand.
enum Stage {
    Head(FormReader),
    File {
        reader: FileReader,
        fields: Vec<(String, String)>,
        filename: Option<String>,
        file_name: Option<String>,
    },
}

fn read_inner(case: &Case<'_>, frame: usize) -> Result<Verdict, FormReject> {
    let mut stage = Stage::Head(FormReader::with_grammar(case.content_type, case.limits, case.grammar)?);
    let mut file = Vec::new();
    for piece in case.body.chunks(frame.max(1)) {
        // What the head reader leaves of this frame belongs to the file.
        let (next, rest) = match stage {
            Stage::Head(mut reader) => match reader.push(piece)? {
                FormStep::NeedMore => (Stage::Head(reader), &[][..]),
                FormStep::FileReached { consumed } => {
                    let fields = reader
                        .fields()
                        .iter()
                        .map(|field| (field.name().to_owned(), field.value().to_owned()))
                        .collect();
                    let filename = reader.filename().map(str::to_owned);
                    let file_name = reader.file_name().map(str::to_owned);
                    let next = Stage::File {
                        reader: reader.into_file(FILE_CEILING)?,
                        fields,
                        filename,
                        file_name,
                    };
                    (next, piece.get(consumed..).unwrap_or_default())
                }
            },
            reading @ Stage::File { .. } => (reading, piece),
        };
        stage = next;
        if let Stage::File { reader, .. } = &mut stage {
            let mut sink = |bytes: &[u8]| file.extend_from_slice(bytes);
            reader.push(rest, &mut sink)?;
        }
    }
    match stage {
        Stage::Head(reader) => Err(reader.finish()),
        Stage::File {
            reader,
            fields,
            filename,
            file_name,
        } => {
            reader.finish()?;
            Ok(Verdict::Read {
                fields,
                filename,
                file_name,
                file,
            })
        }
    }
}

/// Whether two reads of one body agree.
///
/// Exactly, with one exception: a refusal for the whole-stream budget. Both readers charge that
/// budget for the bytes they have taken, and how many they have taken when a later rule fires
/// depends on the framing, so a body that breaks the budget and another rule near it may be
/// refused for either. Both are still refusals, and a read that is accepted in one framing and
/// refused in another is never excused.
fn agree(left: &Verdict, right: &Verdict) -> bool {
    match (left, right) {
        (Verdict::Refused(FormReject::WholeStreamTooLarge), Verdict::Refused(_))
        | (Verdict::Refused(_), Verdict::Refused(FormReject::WholeStreamTooLarge)) => true,
        _ => left == right,
    }
}

/// Runs the property on one input, or returns `None` when the input selects nothing.
///
/// # Panics
///
/// When a read depends on its framing, an accepted read breaks a ceiling or a field rule, or a
/// policy parser accepts fields into a policy that breaks its own invariants.
pub(crate) fn check(input: &[u8]) -> Option<Outcome> {
    let case = Case::parse(input)?;
    let whole = read(&case, case.body.len().max(1));
    let framed = read(&case, case.frame);
    assert!(
        agree(&whole, &framed),
        "a {}-byte framing read the form differently: {whole:?} against {framed:?}",
        case.frame
    );
    // One byte at a time puts a frame edge inside every delimiter; bounded so a long input does
    // not cost a quadratic replay.
    if case.body.len() <= 4096 {
        let bytewise = read(&case, 1);
        assert!(
            agree(&whole, &bytewise),
            "a one-byte framing read the form differently: {whole:?} against {bytewise:?}"
        );
    }

    let Verdict::Read {
        fields,
        filename,
        file_name,
        file,
    } = &whole
    else {
        return Some(Outcome {
            verdict: whole,
            sig_v4: None,
            sig_v2: None,
        });
    };
    assert!(fields.len() <= case.limits.max_field_count(), "{} fields were read", fields.len());
    for (index, (name, value)) in fields.iter().enumerate() {
        let ceiling = if name == "policy" {
            case.limits.max_policy_bytes()
        } else {
            case.limits.max_field_bytes()
        };
        assert!(value.len() <= ceiling, "{name} holds {} bytes", value.len());
        assert_eq!(name, &name.to_ascii_lowercase(), "a field name kept its capitals");
        assert!(
            !value
                .bytes()
                .chain(name.bytes())
                .any(|byte| byte != b'\t' && (byte < 0x20 || byte == 0x7f)),
            "{name:?} carries a control byte"
        );
        assert!(
            fields
                .get(..index)
                .is_none_or(|earlier| earlier.iter().all(|(other, _)| other != name)),
            "{name:?} was read twice"
        );
    }
    assert!(file.len() as u64 <= FILE_CEILING, "the file passed its ceiling");
    match case.grammar {
        FormGrammar::Gateway => assert_eq!(file_name, filename, "the gateway grammar invented a file name"),
        FormGrammar::LegacyRustfs { .. } => {
            assert!(file_name.is_some(), "a legacy read reached the file without a file name");
        }
    }

    let fields: Vec<(&str, &str)> = fields.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let name = file_name.as_deref().unwrap_or_default();
    let now = RequestNow::from_unix_seconds(NOW);
    let limits = PostPolicyLimits::default();
    let sig_v4 = PostPolicy::parse(&fields, name, limits, now).map(|policy| {
        assert!(!policy.final_key().contains("${"), "a SigV4 policy left a variable in the key");
        assert!(policy.read_ceiling() <= limits.max_file_bytes, "a SigV4 policy raised the file ceiling");
    });
    let sig_v2 = SigV2PostPolicy::parse(&fields, name, limits, now).map(|policy| {
        assert!(!policy.final_key().contains("${"), "a SigV2 policy left a variable in the key");
        assert!(policy.read_ceiling() <= limits.max_file_bytes, "a SigV2 policy raised the file ceiling");
    });
    Some(Outcome {
        verdict: whole,
        sig_v4: Some(sig_v4.is_ok()),
        sig_v2: Some(sig_v2.is_ok()),
    })
}
