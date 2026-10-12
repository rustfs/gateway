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

//! Real-writer and self-read comparison for the RustFS 5761 persistence contract.
//!
//! Responsible for: comparing legacy and Gateway writer bytes, typed readback, and input preservation.
//! NOT responsible for: request-body policy or persistence families outside Acceleration and Tagging.
//! Upstream: the pinned RustFS s3s oracle and Gateway codecs. Downstream: persistence migration regressions.
#![cfg(feature = "compat-s3s-rustfs")]

use rustfs_gateway_types::cors_tagging::{PersistedTag, PersistedTagging, parse_tagging, serialize_tagging};
use rustfs_gateway_types::persistence::{PersistedAccelerateConfiguration, parse_accelerate, serialize_accelerate};
use s3s_rustfs::xml::{Deserialize, Deserializer, Serialize, Serializer};

fn write_old(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Serializer::new(&mut bytes))
        .map_err(|error| format!("{error:?}"))?;
    Ok(bytes)
}

fn read_old_accelerate(bytes: &[u8]) -> Result<PersistedAccelerateConfiguration, String> {
    let mut reader = Deserializer::new(bytes);
    let value = s3s_rustfs::dto::AccelerateConfiguration::deserialize(&mut reader).map_err(|error| format!("{error:?}"))?;
    reader.expect_eof().map_err(|error| format!("{error:?}"))?;
    Ok(PersistedAccelerateConfiguration {
        status: value.status.map(|status| status.as_str().to_owned()),
    })
}

fn read_old_tagging(bytes: &[u8]) -> Result<PersistedTagging, String> {
    let mut reader = Deserializer::new(bytes);
    let value = s3s_rustfs::dto::Tagging::deserialize(&mut reader).map_err(|error| format!("{error:?}"))?;
    reader.expect_eof().map_err(|error| format!("{error:?}"))?;
    Ok(PersistedTagging {
        tag_set: value
            .tag_set
            .into_iter()
            .map(|tag| PersistedTag {
                key: tag.key,
                value: tag.value,
            })
            .collect(),
    })
}

#[test]
fn acceleration_writer_matches_real_rustfs_5761_bytes_and_preserves_typed_value() {
    let inputs = [
        ("NORMAL_STATUS", "Enabled"),
        ("CR_CRLF_STATUS", "a\rb\r\nc"),
        ("NUL_STATUS", "\0"),
        (
            "OTHER_FORBIDDEN_STATUS",
            concat!(
                "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{b}\u{c}",
                "\u{e}\u{f}\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}\u{17}\u{18}\u{19}\u{1a}\u{1b}\u{1c}\u{1d}\u{1e}\u{1f}",
                "\u{fffe}\u{ffff}&<>\"'\r"
            ),
        ),
    ];
    let mut expected_from_real_old_writer = Vec::new();
    let mut observed_gateway = Vec::new();
    let mut old_preserves_every_input = true;
    let mut gateway_preserves_every_input = true;
    for (case, text) in inputs {
        let input = PersistedAccelerateConfiguration {
            status: Some(text.to_owned()),
        };
        let old_input = s3s_rustfs::dto::AccelerateConfiguration {
            status: Some(s3s_rustfs::dto::BucketAccelerateStatus::from(text.to_owned())),
        };
        let old_bytes = write_old(&old_input);
        let old_read = match &old_bytes {
            Ok(bytes) => read_old_accelerate(bytes),
            Err(error) => Err(error.clone()),
        };
        let gateway_bytes = serialize_accelerate(&input);
        let gateway_read = parse_accelerate(&gateway_bytes).map_err(|error| format!("{error:?}"));
        let old_preserves_input = old_read.as_ref().is_ok_and(|value| value == &input);
        let gateway_preserves_input = gateway_read.as_ref().is_ok_and(|value| value == &input);
        eprintln!(
            "{case}: input={input:?}; old_input={old_input:?}; old_bytes={old_bytes:?}; gateway_bytes={gateway_bytes:?}; old_self_read={old_read:?}; gateway_self_read={gateway_read:?}; old_preserves_input={old_preserves_input}; gateway_preserves_input={gateway_preserves_input}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Serialize+Deserialize+expect_eof; gateway_writer=rustfs_gateway_types::persistence::serialize_accelerate"
        );
        old_preserves_every_input &= old_preserves_input;
        gateway_preserves_every_input &= gateway_preserves_input;
        expected_from_real_old_writer.push((case, old_bytes.map_err(|_| ()), old_read.map_err(|_| ())));
        observed_gateway.push((case, Ok::<Vec<u8>, ()>(gateway_bytes), gateway_read.map_err(|_| ())));
    }
    // The old writer supplies every expected byte and value; both readers must retain the input.
    assert_eq!(
        (observed_gateway, old_preserves_every_input, gateway_preserves_every_input),
        (expected_from_real_old_writer, true, true)
    );
}

#[test]
fn tagging_writer_matches_real_rustfs_5761_bytes_and_preserves_typed_values() {
    let inputs = [
        ("NORMAL_KEY_VALUE", "k", "v"),
        ("CR_CRLF_KEY_VALUE", "a\rb\r\nc", "d\re\r\nf"),
        ("NUL_KEY_VALUE", "\0", "\0"),
        (
            "OTHER_FORBIDDEN_KEY_VALUE",
            concat!(
                "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{b}\u{c}",
                "\u{e}\u{f}\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}\u{17}\u{18}\u{19}\u{1a}\u{1b}\u{1c}\u{1d}\u{1e}\u{1f}",
                "\u{fffe}\u{ffff}&<>\"'\r"
            ),
            concat!(
                "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{b}\u{c}",
                "\u{e}\u{f}\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}\u{17}\u{18}\u{19}\u{1a}\u{1b}\u{1c}\u{1d}\u{1e}\u{1f}",
                "\u{fffe}\u{ffff}&<>\"'\r"
            ),
        ),
    ];
    let mut expected_from_real_old_writer = Vec::new();
    let mut observed_gateway = Vec::new();
    let mut old_preserves_every_input = true;
    let mut gateway_preserves_every_input = true;
    for (case, key, value) in inputs {
        let input = PersistedTagging {
            tag_set: vec![PersistedTag {
                key: Some(key.to_owned()),
                value: Some(value.to_owned()),
            }],
        };
        let old_input = s3s_rustfs::dto::Tagging {
            tag_set: vec![s3s_rustfs::dto::Tag {
                key: Some(key.to_owned()),
                value: Some(value.to_owned()),
            }],
        };
        let old_bytes = write_old(&old_input);
        let old_read = match &old_bytes {
            Ok(bytes) => read_old_tagging(bytes),
            Err(error) => Err(error.clone()),
        };
        let gateway_bytes = serialize_tagging(&input);
        let gateway_read = parse_tagging(&gateway_bytes).map_err(|error| format!("{error:?}"));
        let old_preserves_input = old_read.as_ref().is_ok_and(|value| value == &input);
        let gateway_preserves_input = gateway_read.as_ref().is_ok_and(|value| value == &input);
        eprintln!(
            "{case}: input={input:?}; old_input={old_input:?}; old_bytes={old_bytes:?}; gateway_bytes={gateway_bytes:?}; old_self_read={old_read:?}; gateway_self_read={gateway_read:?}; old_preserves_input={old_preserves_input}; gateway_preserves_input={gateway_preserves_input}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Serialize+Deserialize+expect_eof; gateway_writer=rustfs_gateway_types::cors_tagging::serialize_tagging"
        );
        old_preserves_every_input &= old_preserves_input;
        gateway_preserves_every_input &= gateway_preserves_input;
        expected_from_real_old_writer.push((case, old_bytes.map_err(|_| ()), old_read.map_err(|_| ())));
        observed_gateway.push((case, Ok::<Vec<u8>, ()>(gateway_bytes), gateway_read.map_err(|_| ())));
    }
    assert_eq!(
        (observed_gateway, old_preserves_every_input, gateway_preserves_every_input),
        (expected_from_real_old_writer, true, true)
    );
}
